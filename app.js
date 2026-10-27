/* =========================================================
   【CipherLab】V2.4.2
   全部加解密运算均在浏览器本地完成，不发起任何网络请求。
   脚本使用经典 <script defer>，以兼容 file:// 直接打开。
   ========================================================= */

(() => {
  'use strict';

  /* ---------------------------------------------------------
     一、算法实现
     每个算法都是独立对象，统一暴露 encrypt / decrypt。
     keyType 用于界面决定显示哪种密钥输入：
     none / caesar / affine / keyword
     --------------------------------------------------------- */

  const LETTER_PATTERN = /^[A-Za-z]$/;
  const KEYWORD_PATTERN = /^[A-Za-z]+$/;

  /* 与 26 互质的 1–25 整数，仿射密码的 a 只能取这些值 */
  const AFFINE_COPRIME_A = new Set([1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]);

  /**
   * 逐字符处理文本：仅对英文字母应用映射，其余字符原样保留。
   * 使用 for...of 按 Unicode 码点遍历，避免拆散 emoji 等代理对。
   * @param {string} text 原始文本
   * @param {(char: string) => string} transformLetter 字母映射函数
   * @returns {string}
   */
  function transformLetters(text, transformLetter) {
    let result = '';
    for (const char of text) {
      result += LETTER_PATTERN.test(char) ? transformLetter(char) : char;
    }
    return result;
  }

  /**
   * 在 A–Z 或 a–z 的 26 个字母内循环位移。
   * @param {string} char 单个英文字母
   * @param {number} shift 位移量，可为负数
   * @returns {string}
   */
  function shiftLetter(char, shift) {
    const base = char >= 'a' ? 97 : 65;
    const offset = char.charCodeAt(0) - base;
    const shiftedOffset = (((offset + shift) % 26) + 26) % 26;
    return String.fromCharCode(base + shiftedOffset);
  }

  /**
   * 用字母索引映射函数处理单个字母，并自动按原大小写输出。
   * @param {string} char 单个英文字母
   * @param {(index: number) => number} transformIndex 0–25 的索引变换
   * @returns {string}
   */
  function mapLetterIndex(char, transformIndex) {
    const base = char >= 'a' ? 97 : 65;
    const offset = char.charCodeAt(0) - base;
    const nextOffset = ((transformIndex(offset) % 26) + 26) % 26;
    return String.fromCharCode(base + nextOffset);
  }

  /**
   * Atbash 镜像映射：A↔Z、B↔Y，大小写各自独立。
   * @param {string} char 单个英文字母
   * @returns {string}
   */
  function mirrorLetter(char) {
    return mapLetterIndex(char, (index) => 25 - index);
  }

  /**
   * 求 a 在模 26 下的乘法逆元。
   * @param {number} a 与 26 互质的整数
   * @returns {number}
   */
  function modularInverse(a) {
    for (let candidate = 1; candidate < 26; candidate += 1) {
      if ((a * candidate) % 26 === 1) {
        return candidate;
      }
    }
    throw new RangeError('仿射密码的 a 必须与 26 互质');
  }

  /**
   * 校验并规范化凯撒位移量。
   * 非法时抛出带明确中文说明的 RangeError，绝不静默失败。
   * @param {number|string} key 位移量
   * @returns {number} 1–25 的整数
   */
  function normalizeCaesarKey(key) {
    const raw = key === null || key === undefined ? '' : String(key).trim();

    if (raw === '') {
      throw new RangeError('请输入凯撒位移量（1–25 的整数）');
    }

    const numericKey = Number(raw);

    if (!Number.isInteger(numericKey)) {
      throw new RangeError('凯撒位移量必须是 1–25 的整数');
    }

    if (numericKey < 1 || numericKey > 25) {
      throw new RangeError('凯撒位移量需在 1–25 之间');
    }

    return numericKey;
  }

  /**
   * 校验仿射密码的 a、b 参数。
   * @param {{a: number|string, b: number|string}} key
   * @returns {{a: number, b: number}}
   */
  function normalizeAffineKey(key) {
    if (!key || typeof key !== 'object') {
      throw new RangeError('请输入仿射密码的 a 和 b（整数）');
    }

    const rawA = key.a === null || key.a === undefined ? '' : String(key.a).trim();
    const rawB = key.b === null || key.b === undefined ? '' : String(key.b).trim();

    if (rawA === '' || rawB === '') {
      throw new RangeError('请输入仿射密码的 a 和 b（整数）');
    }

    const a = Number(rawA);
    const b = Number(rawB);

    if (!Number.isInteger(a) || !Number.isInteger(b)) {
      throw new RangeError('仿射密码的 a 和 b 必须是整数');
    }

    if (!AFFINE_COPRIME_A.has(a)) {
      throw new RangeError('仿射密码的 a 必须是 1–25 中与 26 互质的整数');
    }

    if (b < 0 || b > 25) {
      throw new RangeError('仿射密码的 b 需在 0–25 之间');
    }

    return { a, b };
  }

  /**
   * 校验维吉尼亚 / 博福特的关键词密钥。
   * @param {string} key 密钥单词
   * @returns {string} 大写密钥
   */
  function normalizeKeyword(key) {
    const raw = key === null || key === undefined ? '' : String(key).trim();

    if (raw === '') {
      throw new RangeError('请输入密钥单词（仅英文字母）');
    }

    if (!KEYWORD_PATTERN.test(raw)) {
      throw new RangeError('密钥单词只能包含英文字母');
    }

    return raw.toUpperCase();
  }

  /**
   * 将关键词转换为字母位移数组。
   * @param {string} key 密钥单词
   * @returns {number[]}
   */
  function keywordShifts(key) {
    return Array.from(normalizeKeyword(key), (char) => char.charCodeAt(0) - 65);
  }

  /**
   * 维吉尼亚变换：C = P + K，解密时 C = P - K。
   * 非字母字符不消耗密钥。
   * @param {string} text 文本
   * @param {string} key 密钥单词
   * @param {'encrypt'|'decrypt'} direction 方向
   * @returns {string}
   */
  function vigenereTransform(text, key, direction) {
    const shifts = keywordShifts(key);
    let position = 0;

    return transformLetters(text, (char) => {
      const shift = shifts[position % shifts.length];
      position += 1;
      return shiftLetter(char, direction === 'decrypt' ? -shift : shift);
    });
  }

  /**
   * 标准博福特变换：C = K - P，解密与加密使用同一公式。
   * 非字母字符不消耗密钥。
   * @param {string} text 文本
   * @param {string} key 密钥单词
   * @returns {string}
   */
  function beaufortTransform(text, key) {
    const shifts = keywordShifts(key);
    let position = 0;

    return transformLetters(text, (char) => {
      const shift = shifts[position % shifts.length];
      position += 1;
      return mapLetterIndex(char, (index) => shift - index);
    });
  }

  /**
   * A1Z26 字面量转义：数字、连字符、反斜杠前加反斜杠。
   * @param {string} char 单个字符
   * @returns {string}
   */
  function escapeA1Z26Literal(char) {
    if (char === '\\' || char === '-' || (char >= '0' && char <= '9')) {
      return `\\${char}`;
    }
    return char;
  }

  /**
   * A1Z26 加密：A=1 … Z=26，数字之间用 - 分隔，其他字符保留。
   * 明文中的数字、-、\ 会被转义，保证解密可逆。
   * @param {string} text 明文
   * @returns {string}
   */
  function encodeA1Z26(text) {
    let result = '';
    let previousWasCode = false;

    for (const char of text) {
      if (LETTER_PATTERN.test(char)) {
        if (previousWasCode) {
          result += '-';
        }
        result += String(char.toUpperCase().charCodeAt(0) - 64);
        previousWasCode = true;
      } else {
        result += escapeA1Z26Literal(char);
        previousWasCode = false;
      }
    }

    return result;
  }

  /**
   * A1Z26 解密：解析 1–26 的数字编码，其他字符原样保留。
   * 由于数字编码不区分大小写，解密结果统一为大写字母。
   * @param {string} text 密文
   * @returns {string}
   */
  function decodeA1Z26(text) {
    const chars = Array.from(text);
    let result = '';
    let index = 0;

    while (index < chars.length) {
      const char = chars[index];

      if (char === '\\') {
        if (index + 1 >= chars.length) {
          throw new RangeError('A1Z26 密文中的转义符不完整');
        }
        result += chars[index + 1];
        index += 2;
      } else if (char >= '0' && char <= '9') {
        let digits = '';

        while (index < chars.length && chars[index] >= '0' && chars[index] <= '9') {
          digits += chars[index];
          index += 1;
        }

        const code = Number(digits);

        if (!Number.isInteger(code) || code < 1 || code > 26) {
          throw new RangeError('A1Z26 解密仅支持 1–26 的数字编码');
        }

        result += String.fromCharCode(64 + code);
      } else if (char === '-') {
        /* 连字符只作为数字编码之间的分隔符，输出时丢弃 */
        index += 1;
      } else {
        result += char;
        index += 1;
      }
    }

    return result;
  }

  /**
   * ASCII 码替换加密：每个字符转成十进制 ASCII 码，空格分隔。
   * @param {string} text 明文
   * @returns {string}
   */
  function encodeAscii(text) {
    const codes = [];

    for (const char of text) {
      const code = char.codePointAt(0);

      if (code > 127) {
        throw new RangeError('ASCII 码替换仅支持 ASCII 字符（码点 0–127）');
      }

      codes.push(String(code));
    }

    return codes.join(' ');
  }

  /**
   * ASCII 码替换解密：空格分隔的 0–127 整数还原为字符。
   * @param {string} text 密文
   * @returns {string}
   */
  function decodeAscii(text) {
    const trimmed = text.trim();

    if (trimmed === '') {
      return '';
    }

    return trimmed
      .split(/\s+/)
      .map((token) => {
        if (!/^\d+$/.test(token)) {
          throw new RangeError('请输入以空格分隔的 ASCII 码（0–127）');
        }

        const code = Number(token);

        if (!Number.isInteger(code) || code < 0 || code > 127) {
          throw new RangeError('ASCII 码必须在 0–127 之间');
        }

        return String.fromCharCode(code);
      })
      .join('');
  }

  /* ---------------------------------------------------------
     二、算法注册表
     --------------------------------------------------------- */

  const CIPHERS = {
    a1z26: {
      id: 'a1z26',
      keyType: 'none',

      encrypt(text) {
        return encodeA1Z26(text);
      },

      decrypt(text) {
        return decodeA1Z26(text);
      },
    },

    affine: {
      id: 'affine',
      keyType: 'affine',

      encrypt(text, key) {
        const { a, b } = normalizeAffineKey(key);
        return transformLetters(text, (char) => mapLetterIndex(char, (index) => a * index + b));
      },

      decrypt(text, key) {
        const { a, b } = normalizeAffineKey(key);
        const inverse = modularInverse(a);
        return transformLetters(text, (char) => mapLetterIndex(char, (index) => inverse * (index - b)));
      },
    },

    ascii: {
      id: 'ascii',
      keyType: 'none',

      encrypt(text) {
        return encodeAscii(text);
      },

      decrypt(text) {
        return decodeAscii(text);
      },
    },

    atbash: {
      id: 'atbash',
      keyType: 'none',

      encrypt(text) {
        return transformLetters(text, mirrorLetter);
      },

      decrypt(text) {
        return transformLetters(text, mirrorLetter);
      },
    },

    beaufort: {
      id: 'beaufort',
      keyType: 'keyword',

      encrypt(text, key) {
        return beaufortTransform(text, key);
      },

      decrypt(text, key) {
        return beaufortTransform(text, key);
      },
    },

    caesar: {
      id: 'caesar',
      keyType: 'caesar',

      encrypt(text, key) {
        const shift = normalizeCaesarKey(key);
        return transformLetters(text, (char) => shiftLetter(char, shift));
      },

      decrypt(text, key) {
        const shift = normalizeCaesarKey(key);
        return transformLetters(text, (char) => shiftLetter(char, -shift));
      },
    },

    rot13: {
      id: 'rot13',
      keyType: 'none',

      encrypt(text) {
        return transformLetters(text, (char) => shiftLetter(char, 13));
      },

      decrypt(text) {
        return transformLetters(text, (char) => shiftLetter(char, 13));
      },
    },

    vigenere: {
      id: 'vigenere',
      keyType: 'keyword',

      encrypt(text, key) {
        return vigenereTransform(text, key, 'encrypt');
      },

      decrypt(text, key) {
        return vigenereTransform(text, key, 'decrypt');
      },
    },
  };

  /* ---------------------------------------------------------
     三、V1.3 新增算法与共用数据
     --------------------------------------------------------- */

  /* 5×5 方阵字母表：I/J 合并 */
  const SQUARE_ALPHABET = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';

  const POLYBIUS_ROWS = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'K'],
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z'],
  ];

  const MORSE_ENTRIES = [
    ['A', '.-'], ['B', '-...'], ['C', '-.-.'], ['D', '-..'], ['E', '.'],
    ['F', '..-.'], ['G', '--.'], ['H', '....'], ['I', '..'], ['J', '.---'],
    ['K', '-.-'], ['L', '.-..'], ['M', '--'], ['N', '-.'], ['O', '---'],
    ['P', '.--.'], ['Q', '--.-'], ['R', '.-.'], ['S', '...'], ['T', '-'],
    ['U', '..-'], ['V', '...-'], ['W', '.--'], ['X', '-..-'], ['Y', '-.--'],
    ['Z', '--..'],
    ['0', '-----'], ['1', '.----'], ['2', '..---'], ['3', '...--'], ['4', '....-'],
    ['5', '.....'], ['6', '-....'], ['7', '--...'], ['8', '---..'], ['9', '----.'],
    ['.', '.-.-.-'], [',', '--..--'], ['?', '..--..'], ["'", '.----.'], ['!', '-.-.--'],
    ['/', '-..-.'], ['(', '-.--.'], [')', '-.--.-'], ['&', '.-...'], [':', '---...'],
    [';', '-.-.-.'], ['=', '-...-'], ['+', '.-.-.'], ['-', '-....-'], ['_', '..--.-'],
    ['"', '.-..-.'], ['$', '...-..-'], ['@', '.--.-.'],
  ];

  const MORSE_MAP = {};
  const MORSE_REVERSE = {};

  for (const [char, code] of MORSE_ENTRIES) {
    MORSE_MAP[char] = code;
    MORSE_REVERSE[code] = char;
  }

  /**
   * 只保留英文字母并转大写，J 统一为 I，供 5×5 方阵类算法使用。
   * @param {string} text
   * @returns {string}
   */
  function normalizeSquareText(text) {
    let result = '';

    for (const char of text.toUpperCase()) {
      if (char >= 'A' && char <= 'Z') {
        result += char === 'J' ? 'I' : char;
      }
    }

    return result;
  }

  /**
   * 用关键词生成 5×5 方阵，返回 25 个字母的字符串。
   * @param {string} keyword
   * @returns {string}
   */
  function buildKeyedSquare(keyword) {
    const normalized = normalizeKeyword(keyword).replace(/J/g, 'I');
    const seen = new Set();
    let square = '';

    for (const char of normalized + SQUARE_ALPHABET) {
      if (SQUARE_ALPHABET.includes(char) && !seen.has(char)) {
        seen.add(char);
        square += char;
      }
    }

    return square;
  }

  /**
   * 将 25 个字母切成 5 行。
   * @param {string} square
   * @returns {string[][]}
   */
  function squareToRows(square) {
    const rows = [];

    for (let index = 0; index < 5; index += 1) {
      rows.push(Array.from(square.slice(index * 5, index * 5 + 5)));
    }

    return rows;
  }

  /**
   * 在 5×5 方阵中查找字母坐标。
   * @param {string[][]} rows
   * @param {string} letter
   * @returns {{row: number, col: number}}
   */
  function findInRows(rows, letter) {
    const target = letter === 'J' ? 'I' : letter;

    for (let row = 0; row < rows.length; row += 1) {
      const col = rows[row].indexOf(target);

      if (col !== -1) {
        return { row, col };
      }
    }

    throw new RangeError(`方阵中找不到字母「${letter}」`);
  }

  /**
   * Playfair 明文分组：重复字母插入 X，末尾不足补 X。
   * @param {string} text
   * @returns {Array<[string, string]>}
   */
  function preparePlayfairPairs(text) {
    const letters = normalizeSquareText(text);

    if (!letters) {
      throw new RangeError('请输入至少一个英文字母');
    }

    const pairs = [];
    let index = 0;

    while (index < letters.length) {
      const first = letters[index];
      const second = letters[index + 1];

      if (second === undefined) {
        pairs.push([first, 'X']);
        index += 1;
      } else if (first === second) {
        pairs.push([first, 'X']);
        index += 1;
      } else {
        pairs.push([first, second]);
        index += 2;
      }
    }

    return pairs;
  }

  /**
   * 将文本整理成偶数长度的字母对（末尾补 X）。
   * @param {string} text
   * @returns {Array<[string, string]>}
   */
  function preparePaddedPairs(text) {
    let letters = normalizeSquareText(text);

    if (!letters) {
      throw new RangeError('请输入至少一个英文字母');
    }

    if (letters.length % 2 === 1) {
      letters += 'X';
    }

    const pairs = [];

    for (let index = 0; index < letters.length; index += 2) {
      pairs.push([letters[index], letters[index + 1]]);
    }

    return pairs;
  }

  /**
   * 将密文整理成字母对，长度必须为偶数。
   * @param {string} text
   * @returns {Array<[string, string]>}
   */
  function toCipherPairs(text) {
    const letters = normalizeSquareText(text);

    if (!letters) {
      throw new RangeError('请输入至少一个英文字母');
    }

    if (letters.length % 2 === 1) {
      throw new RangeError('密文长度必须为偶数');
    }

    const pairs = [];

    for (let index = 0; index < letters.length; index += 2) {
      pairs.push([letters[index], letters[index + 1]]);
    }

    return pairs;
  }

  function playfairEncrypt(text, key) {
    const rows = squareToRows(buildKeyedSquare(key));
    let output = '';

    for (const [first, second] of preparePlayfairPairs(text)) {
      const a = findInRows(rows, first);
      const b = findInRows(rows, second);

      if (a.row === b.row) {
        output += rows[a.row][(a.col + 1) % 5] + rows[b.row][(b.col + 1) % 5];
      } else if (a.col === b.col) {
        output += rows[(a.row + 1) % 5][a.col] + rows[(b.row + 1) % 5][b.col];
      } else {
        output += rows[a.row][b.col] + rows[b.row][a.col];
      }
    }

    return output;
  }

  function playfairDecrypt(text, key) {
    const rows = squareToRows(buildKeyedSquare(key));
    let output = '';

    for (const [first, second] of toCipherPairs(text)) {
      const a = findInRows(rows, first);
      const b = findInRows(rows, second);

      if (a.row === b.row) {
        output += rows[a.row][(a.col + 4) % 5] + rows[b.row][(b.col + 4) % 5];
      } else if (a.col === b.col) {
        output += rows[(a.row + 4) % 5][a.col] + rows[(b.row + 4) % 5][b.col];
      } else {
        output += rows[a.row][b.col] + rows[b.row][a.col];
      }
    }

    return output;
  }

  /**
   * 校验四方 / 二方密码的两个关键词。
   * @param {{key1: string, key2: string}} key
   * @returns {{key1: string, key2: string}}
   */
  function normalizeTwoKeywords(key) {
    if (!key || typeof key !== 'object') {
      throw new RangeError('请输入两个关键词（仅英文字母）');
    }

    return {
      key1: normalizeKeyword(key.key1),
      key2: normalizeKeyword(key.key2),
    };
  }

  function fourSquareEncrypt(text, key) {
    const { key1, key2 } = normalizeTwoKeywords(key);
    const keyRows1 = squareToRows(buildKeyedSquare(key1));
    const keyRows2 = squareToRows(buildKeyedSquare(key2));
    const standardRows = squareToRows(SQUARE_ALPHABET);
    let output = '';

    for (const [first, second] of preparePaddedPairs(text)) {
      const a = findInRows(standardRows, first);
      const b = findInRows(standardRows, second);
      output += keyRows1[a.row][b.col] + keyRows2[b.row][a.col];
    }

    return output;
  }

  function fourSquareDecrypt(text, key) {
    const { key1, key2 } = normalizeTwoKeywords(key);
    const keyRows1 = squareToRows(buildKeyedSquare(key1));
    const keyRows2 = squareToRows(buildKeyedSquare(key2));
    const standardRows = squareToRows(SQUARE_ALPHABET);
    let output = '';

    for (const [first, second] of toCipherPairs(text)) {
      const a = findInRows(keyRows1, first);
      const b = findInRows(keyRows2, second);
      output += standardRows[a.row][b.col] + standardRows[b.row][a.col];
    }

    return output;
  }

  function twoSquareEncrypt(text, key) {
    const { key1, key2 } = normalizeTwoKeywords(key);
    const leftRows = squareToRows(buildKeyedSquare(key1));
    const rightRows = squareToRows(buildKeyedSquare(key2));
    let output = '';

    for (const [first, second] of preparePaddedPairs(text)) {
      const a = findInRows(leftRows, first);
      const b = findInRows(rightRows, second);
      output += leftRows[a.row][b.col] + rightRows[b.row][a.col];
    }

    return output;
  }

  function twoSquareDecrypt(text, key) {
    const { key1, key2 } = normalizeTwoKeywords(key);
    const leftRows = squareToRows(buildKeyedSquare(key1));
    const rightRows = squareToRows(buildKeyedSquare(key2));
    let output = '';

    for (const [first, second] of toCipherPairs(text)) {
      const a = findInRows(leftRows, first);
      const b = findInRows(rightRows, second);
      output += leftRows[a.row][b.col] + rightRows[b.row][a.col];
    }

    return output;
  }

  function polybiusEncrypt(text) {
    const letters = normalizeSquareText(text);

    if (!letters) {
      throw new RangeError('请输入至少一个英文字母');
    }

    const parts = [];

    for (const char of letters) {
      const position = findInRows(POLYBIUS_ROWS, char);
      parts.push(`${position.row + 1}${position.col + 1}`);
    }

    return parts.join(' ');
  }

  function polybiusDecrypt(text) {
    const trimmed = text.trim();

    if (!trimmed) {
      return '';
    }

    const parts = [];

    for (const token of trimmed.split(/\s+/)) {
      if (!/^[1-5]{2}$/.test(token)) {
        throw new RangeError('波利比奥斯方阵密文应为 1–5 的两位坐标');
      }

      parts.push(POLYBIUS_ROWS[Number(token[0]) - 1][Number(token[1]) - 1]);
    }

    return parts.join('');
  }

  /**
   * 校验栅栏数。
   * @param {number|string} value
   * @returns {number}
   */
  function normalizeRailCount(value) {
    const raw = value === null || value === undefined ? '' : String(value).trim();

    if (raw === '') {
      throw new RangeError('请输入栅栏数（2–20 的整数）');
    }

    const rails = Number(raw);

    if (!Number.isInteger(rails) || rails < 2 || rails > 20) {
      throw new RangeError('栅栏数需为 2–20 的整数');
    }

    return rails;
  }

  /**
   * 构建之字形栅栏位置序列。
   * @param {number} length
   * @param {number} rails
   * @returns {number[]}
   */
  function buildRailPattern(length, rails) {
    const pattern = [];
    let rail = 0;
    let direction = 1;

    for (let index = 0; index < length; index += 1) {
      pattern.push(rail);

      if (rail === 0) {
        direction = 1;
      } else if (rail === rails - 1) {
        direction = -1;
      }

      rail += direction;
    }

    return pattern;
  }

  function railFenceEncrypt(text, key) {
    const rails = normalizeRailCount(key);
    const chars = Array.from(text);

    if (chars.length === 0) {
      return '';
    }

    const pattern = buildRailPattern(chars.length, rails);
    const rows = Array.from({ length: rails }, () => []);

    chars.forEach((char, index) => {
      rows[pattern[index]].push(char);
    });

    return rows.map((row) => row.join('')).join('');
  }

  function railFenceDecrypt(text, key) {
    const rails = normalizeRailCount(key);
    const chars = Array.from(text);

    if (chars.length === 0) {
      return '';
    }

    const pattern = buildRailPattern(chars.length, rails);
    const counts = Array.from({ length: rails }, () => 0);
    pattern.forEach((rail) => { counts[rail] += 1; });

    const rows = [];
    let cursor = 0;

    for (let rail = 0; rail < rails; rail += 1) {
      rows.push(chars.slice(cursor, cursor + counts[rail]));
      cursor += counts[rail];
    }

    const indexes = Array.from({ length: rails }, () => 0);

    return pattern.map((rail) => {
      const char = rows[rail][indexes[rail]];
      indexes[rail] += 1;
      return char;
    }).join('');
  }

  function morseEncode(text) {
    const words = text.trim().toUpperCase().split(/\s+/).filter(Boolean);

    if (words.length === 0) {
      throw new RangeError('请输入需要编码的文本');
    }

    return words.map((word) => {
      const codes = [];

      for (const char of word) {
        const code = MORSE_MAP[char];

        if (!code) {
          throw new RangeError(`摩斯密码不支持字符「${char}」`);
        }

        codes.push(code);
      }

      return codes.join(' ');
    }).join(' / ');
  }

  function morseDecode(text) {
    const trimmed = text.trim();

    if (!trimmed) {
      return '';
    }

    return trimmed.split(/\s*\/\s*/).map((word) => {
      const tokens = word.trim().split(/\s+/);

      return tokens.map((token) => {
        const char = MORSE_REVERSE[token];

        if (!char) {
          throw new RangeError(`无法识别的摩斯码「${token}」`);
        }

        return char;
      }).join('');
    }).join(' ');
  }

  /* ---------- V1.4 新增：ADFGVX ---------- */

  const ADFGVX_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const ADFGVX_LABELS = 'ADFGVX';

  function normalizePlainLetters(text) {
    let result = '';

    for (const char of text.toUpperCase()) {
      if (char >= 'A' && char <= 'Z') {
        result += char;
      }
    }

    return result;
  }

  function normalizeAdfgvxText(text) {
    let result = '';

    for (const char of text.toUpperCase()) {
      if ((char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
        result += char;
      }
    }

    return result;
  }

  function buildAdfgvxSquare(keyword) {
    const normalized = normalizeKeyword(keyword);
    const seen = new Set();
    let square = '';

    for (const char of normalized + ADFGVX_ALPHABET) {
      if (ADFGVX_ALPHABET.includes(char) && !seen.has(char)) {
        seen.add(char);
        square += char;
      }
    }

    return square;
  }

  function squareToRowsOf(square, size) {
    const rows = [];

    for (let index = 0; index < size; index += 1) {
      rows.push(Array.from(square.slice(index * size, index * size + size)));
    }

    return rows;
  }

  function columnarOrder(keyword) {
    return Array.from(keyword)
      .map((char, index) => ({ char, index }))
      .sort((first, second) => {
        if (first.char === second.char) {
          return first.index - second.index;
        }
        return first.char < second.char ? -1 : 1;
      })
      .map((item) => item.index);
  }

  function columnarEncrypt(text, keyword) {
    const columns = keyword.length;
    const rows = Math.ceil(text.length / columns);
    const order = columnarOrder(keyword);
    let output = '';

    for (const column of order) {
      for (let row = 0; row < rows; row += 1) {
        const index = row * columns + column;

        if (index < text.length) {
          output += text[index];
        }
      }
    }

    return output;
  }

  function columnarDecrypt(text, keyword) {
    const columns = keyword.length;
    const rows = Math.ceil(text.length / columns);
    const order = columnarOrder(keyword);
    const grid = Array.from({ length: rows }, () => Array(columns).fill(''));
    let cursor = 0;

    for (const column of order) {
      for (let row = 0; row < rows; row += 1) {
        if (row * columns + column < text.length) {
          grid[row][column] = text[cursor];
          cursor += 1;
        }
      }
    }

    let output = '';

    for (let row = 0; row < rows; row += 1) {
      for (let column = 0; column < columns; column += 1) {
        if (row * columns + column < text.length) {
          output += grid[row][column];
        }
      }
    }

    return output;
  }

  function adfgvxEncrypt(text, key) {
    const { key1, key2 } = normalizeTwoKeywords(key);
    const rows = squareToRowsOf(buildAdfgvxSquare(key1), 6);
    const letters = normalizeAdfgvxText(text);

    if (!letters) {
      throw new RangeError('请输入至少一个英文字母或数字');
    }

    let fractionated = '';

    for (const char of letters) {
      const position = findInRows(rows, char);
      fractionated += ADFGVX_LABELS[position.row] + ADFGVX_LABELS[position.col];
    }

    return columnarEncrypt(fractionated, key2);
  }

  function adfgvxDecrypt(text, key) {
    const { key1, key2 } = normalizeTwoKeywords(key);
    const rows = squareToRowsOf(buildAdfgvxSquare(key1), 6);
    const compact = text.toUpperCase().replace(/\s+/g, '');

    if (!compact) {
      return '';
    }

    if (compact.length % 2 === 1) {
      throw new RangeError('ADFGVX 密文长度必须为偶数');
    }

    const fractionated = columnarDecrypt(compact, key2);
    let output = '';

    for (let index = 0; index < fractionated.length; index += 2) {
      const row = ADFGVX_LABELS.indexOf(fractionated[index]);
      const column = ADFGVX_LABELS.indexOf(fractionated[index + 1]);

      if (row === -1 || column === -1) {
        throw new RangeError('ADFGVX 密文只能包含 A、D、F、G、V、X');
      }

      output += rows[row][column];
    }

    return output;
  }

  /* ---------- V1.4 新增：路径密码（顺时针螺旋） ---------- */

  function normalizeRouteColumns(value) {
    const raw = value === null || value === undefined ? '' : String(value).trim();

    if (raw === '') {
      throw new RangeError('请输入列数（2–10 的整数）');
    }

    const columns = Number(raw);

    if (!Number.isInteger(columns) || columns < 2 || columns > 10) {
      throw new RangeError('列数需为 2–10 的整数');
    }

    return columns;
  }

  function buildSpiralPath(rows, columns) {
    const path = [];
    let top = 0;
    let bottom = rows - 1;
    let left = 0;
    let right = columns - 1;

    while (top <= bottom && left <= right) {
      for (let column = left; column <= right; column += 1) {
        path.push([top, column]);
      }
      top += 1;

      for (let row = top; row <= bottom; row += 1) {
        path.push([row, right]);
      }
      right -= 1;

      if (top <= bottom) {
        for (let column = right; column >= left; column -= 1) {
          path.push([bottom, column]);
        }
        bottom -= 1;
      }

      if (left <= right) {
        for (let row = bottom; row >= top; row -= 1) {
          path.push([row, left]);
        }
        left += 1;
      }
    }

    return path;
  }

  function routeEncrypt(text, key) {
    const columns = normalizeRouteColumns(key);
    const chars = Array.from(text);

    if (chars.length === 0) {
      return '';
    }

    const rows = Math.ceil(chars.length / columns);
    const grid = Array.from({ length: rows }, () => Array(columns).fill(null));

    chars.forEach((char, index) => {
      grid[Math.floor(index / columns)][index % columns] = char;
    });

    return buildSpiralPath(rows, columns)
      .filter(([row, column]) => grid[row][column] !== null)
      .map(([row, column]) => grid[row][column])
      .join('');
  }

  function routeDecrypt(text, key) {
    const columns = normalizeRouteColumns(key);
    const chars = Array.from(text);

    if (chars.length === 0) {
      return '';
    }

    const rows = Math.ceil(chars.length / columns);
    const grid = Array.from({ length: rows }, () => Array(columns).fill(null));
    let cursor = 0;

    for (const [row, column] of buildSpiralPath(rows, columns)) {
      if (row * columns + column < chars.length) {
        grid[row][column] = chars[cursor];
        cursor += 1;
      }
    }

    let output = '';

    for (let row = 0; row < rows; row += 1) {
      for (let column = 0; column < columns; column += 1) {
        if (grid[row][column] !== null) {
          output += grid[row][column];
        }
      }
    }

    return output;
  }

  /* ---------- V1.4 新增：猪圈密码（格位编码） ---------- */

  const PIGPEN_GROUPS = [
    {
      label: '九宫格（无点）',
      columns: 3,
      cells: [
        ['A', '1a'], ['B', '1b'], ['C', '1c'],
        ['D', '1d'], ['E', '1e'], ['F', '1f'],
        ['G', '1g'], ['H', '1h'], ['I', '1i'],
      ],
    },
    {
      label: '九宫格（带点）',
      columns: 3,
      cells: [
        ['J', '2a'], ['K', '2b'], ['L', '2c'],
        ['M', '2d'], ['N', '2e'], ['O', '2f'],
        ['P', '2g'], ['Q', '2h'], ['R', '2i'],
      ],
    },
    {
      label: 'X 形区域',
      columns: 2,
      cells: [
        ['S', '3a'], ['T', '3b'],
        ['U', '3c'], ['V', '3d'],
        ['W', '3e'], ['X', '3f'],
        ['Y', '3g'], ['Z', '3h'],
      ],
    },
  ];

  const PIGPEN_MAP = {};
  const PIGPEN_REVERSE = {};

  for (const group of PIGPEN_GROUPS) {
    for (const [letter, code] of group.cells) {
      PIGPEN_MAP[letter] = code;
      PIGPEN_REVERSE[code] = letter;
    }
  }

  function pigpenEncode(text) {
    const letters = normalizePlainLetters(text);

    if (!letters) {
      throw new RangeError('请输入至少一个英文字母');
    }

    return Array.from(letters).map((char) => PIGPEN_MAP[char]).join(' ');
  }

  function pigpenDecode(text) {
    const trimmed = text.trim();

    if (!trimmed) {
      return '';
    }

    return trimmed.split(/\s+/).map((token) => {
      const letter = PIGPEN_REVERSE[token.toLowerCase()];

      if (!letter) {
        throw new RangeError(`无法识别的猪圈格位码「${token}」`);
      }

      return letter;
    }).join('');
  }

  /* ---------- V1.4 新增：旗语（左右臂位置码） ---------- */

  const SEMAPHORE_TABLE = [
    ['A', '下', '低', 'D-L'],
    ['B', '下', '外', 'D-O'],
    ['C', '下', '高', 'D-H'],
    ['D', '下', '上', 'D-U'],
    ['E', '高', '下', 'H-D'],
    ['F', '外', '下', 'O-D'],
    ['G', '低', '下', 'L-D'],
    ['H', '横低', '外', 'AL-O'],
    ['I', '横低', '上', 'AL-U'],
    ['J', '外', '上', 'O-U'],
    ['K', '上', '低', 'U-L'],
    ['L', '高', '低', 'H-L'],
    ['M', '外', '低', 'O-L'],
    ['N', '低', '低', 'L-L'],
    ['O', '横高', '外', 'AH-O'],
    ['P', '上', '外', 'U-O'],
    ['Q', '高', '外', 'H-O'],
    ['R', '外', '外', 'O-O'],
    ['S', '低', '外', 'L-O'],
    ['T', '上', '高', 'U-H'],
    ['U', '高', '高', 'H-H'],
    ['V', '低', '上', 'L-U'],
    ['W', '外', '横高', 'O-AH'],
    ['X', '低', '横高', 'L-AH'],
    ['Y', '外', '高', 'O-H'],
    ['Z', '外', '横低', 'O-AL'],
  ];

  const SEMAPHORE_LEGEND = [
    ['D', '下'], ['L', '低'], ['O', '外'], ['H', '高'],
    ['U', '上'], ['AL', '横低'], ['AH', '横高'],
  ];

  const SEMAPHORE_MAP = {};
  const SEMAPHORE_REVERSE = {};

  for (const [letter, , , code] of SEMAPHORE_TABLE) {
    SEMAPHORE_MAP[letter] = code;
    SEMAPHORE_REVERSE[code] = letter;
  }

  function semaphoreEncode(text) {
    const letters = normalizePlainLetters(text);

    if (!letters) {
      throw new RangeError('请输入至少一个英文字母');
    }

    return Array.from(letters).map((char) => SEMAPHORE_MAP[char]).join(' ');
  }

  function semaphoreDecode(text) {
    const trimmed = text.trim();

    if (!trimmed) {
      return '';
    }

    return trimmed.split(/\s+/).map((token) => {
      const letter = SEMAPHORE_REVERSE[token.toUpperCase()];

      if (!letter) {
        throw new RangeError(`无法识别的旗语位置码「${token}」`);
      }

      return letter;
    }).join('');
  }

  /* ---------- V1.4 新增：培根密码 ---------- */

  const BACON_LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const BACON_TABLE = Array.from(BACON_LETTERS).map((letter, index) => [
    letter,
    index.toString(2).padStart(5, '0').replace(/0/g, 'A').replace(/1/g, 'B'),
  ]);

  const BACON_MAP = {};
  const BACON_REVERSE = {};

  for (const [letter, code] of BACON_TABLE) {
    BACON_MAP[letter] = code;
    BACON_REVERSE[code] = letter;
  }

  function baconEncode(text) {
    const letters = normalizePlainLetters(text);

    if (!letters) {
      throw new RangeError('请输入至少一个英文字母');
    }

    return Array.from(letters).map((char) => BACON_MAP[char]).join(' ');
  }

  function baconDecode(text) {
    const tokens = text.trim().split(/\s+/).filter(Boolean);

    if (tokens.length === 0) {
      return '';
    }

    return tokens.map((token) => {
      const letter = BACON_REVERSE[token.toUpperCase()];

      if (!letter) {
        throw new RangeError(`无法识别的培根码「${token}」`);
      }

      return letter;
    }).join('');
  }

  /* ---------- V1.4 新增：盲文 ---------- */

  const BRAILLE_MASKS = {
    A: 1, B: 3, C: 9, D: 25, E: 17, F: 11, G: 27, H: 19, I: 10, J: 26,
    K: 5, L: 7, M: 13, N: 29, O: 21, P: 15, Q: 31, R: 23, S: 14, T: 30,
    U: 37, V: 39, W: 58, X: 45, Y: 61, Z: 53,
  };

  const BRAILLE_PUNCTUATION = {
    ' ': 0,
    ',': 2,
    '.': 50,
    '?': 38,
    '!': 46,
    ';': 6,
    ':': 18,
    '-': 36,
    "'": 4,
  };

  const BRAILLE_NUMBER_SIGN = String.fromCharCode(0x2800 + 60);
  const BRAILLE_SPACE = String.fromCharCode(0x2800);

  function brailleCell(mask) {
    return String.fromCharCode(0x2800 + mask);
  }

  const BRAILLE_LETTER_CELLS = {};
  const BRAILLE_LETTER_REVERSE = {};

  for (const [letter, mask] of Object.entries(BRAILLE_MASKS)) {
    const cell = brailleCell(mask);
    BRAILLE_LETTER_CELLS[letter] = cell;
    BRAILLE_LETTER_REVERSE[cell] = letter;
  }

  const BRAILLE_PUNCT_CELLS = {};
  const BRAILLE_PUNCT_REVERSE = {};

  for (const [char, mask] of Object.entries(BRAILLE_PUNCTUATION)) {
    const cell = brailleCell(mask);
    BRAILLE_PUNCT_CELLS[char] = cell;
    BRAILLE_PUNCT_REVERSE[cell] = char;
  }

  const BRAILLE_DIGITS = {
    '1': 'A', '2': 'B', '3': 'C', '4': 'D', '5': 'E',
    '6': 'F', '7': 'G', '8': 'H', '9': 'I', '0': 'J',
  };

  const BRAILLE_DIGIT_REVERSE = {};
  for (const [digit, letter] of Object.entries(BRAILLE_DIGITS)) {
    BRAILLE_DIGIT_REVERSE[BRAILLE_LETTER_CELLS[letter]] = digit;
  }

  const BRAILLE_TABLE = [];

  for (const [letter] of BACON_TABLE) {
    BRAILLE_TABLE.push([letter, BRAILLE_LETTER_CELLS[letter]]);
  }
  for (const [digit, letter] of Object.entries(BRAILLE_DIGITS)) {
    BRAILLE_TABLE.push([digit, BRAILLE_NUMBER_SIGN + BRAILLE_LETTER_CELLS[letter]]);
  }
  BRAILLE_TABLE.push(['空格', BRAILLE_SPACE]);
  for (const char of [',', '.', '?', '!', ';', ':', '-', "'"]) {
    BRAILLE_TABLE.push([char, BRAILLE_PUNCT_CELLS[char]]);
  }

  function brailleEncode(text) {
    let output = '';

    for (const char of text.toUpperCase()) {
      if (char >= 'A' && char <= 'Z') {
        output += BRAILLE_LETTER_CELLS[char];
      } else if (char >= '0' && char <= '9') {
        output += BRAILLE_NUMBER_SIGN + BRAILLE_LETTER_CELLS[BRAILLE_DIGITS[char]];
      } else if (char in BRAILLE_PUNCT_CELLS) {
        output += BRAILLE_PUNCT_CELLS[char];
      } else if (/\s/.test(char)) {
        output += BRAILLE_SPACE;
      } else {
        throw new RangeError(`盲文暂不支持字符「${char}」`);
      }
    }

    return output;
  }

  function brailleDecode(text) {
    const cells = Array.from(text.trim());

    if (cells.length === 0) {
      return '';
    }

    let output = '';
    let numeric = false;

    for (const cell of cells) {
      if (cell === BRAILLE_NUMBER_SIGN) {
        numeric = true;
        continue;
      }

      if (cell === BRAILLE_SPACE) {
        output += ' ';
        numeric = false;
        continue;
      }

      if (numeric) {
        const digit = BRAILLE_DIGIT_REVERSE[cell];

        if (!digit) {
          throw new RangeError('盲文数字符号后应为 A–J 对应的数字单元');
        }

        output += digit;
        numeric = false;
        continue;
      }

      if (BRAILLE_LETTER_REVERSE[cell]) {
        output += BRAILLE_LETTER_REVERSE[cell];
      } else if (BRAILLE_PUNCT_REVERSE[cell] !== undefined) {
        output += BRAILLE_PUNCT_REVERSE[cell];
      } else {
        throw new RangeError('无法识别的盲文单元');
      }
    }

    if (numeric) {
      throw new RangeError('盲文数字符号后缺少数字单元');
    }

    return output;
  }

  Object.assign(CIPHERS, {
    playfair: {
      id: 'playfair',
      keyType: 'keyword',
      encrypt: playfairEncrypt,
      decrypt: playfairDecrypt,
    },

    foursquare: {
      id: 'foursquare',
      keyType: 'two-keyword',
      encrypt: fourSquareEncrypt,
      decrypt: fourSquareDecrypt,
    },

    twosquare: {
      id: 'twosquare',
      keyType: 'two-keyword',
      encrypt: twoSquareEncrypt,
      decrypt: twoSquareDecrypt,
    },

    polybius: {
      id: 'polybius',
      keyType: 'none',
      encrypt: polybiusEncrypt,
      decrypt: polybiusDecrypt,
    },

    railfence: {
      id: 'railfence',
      keyType: 'rails',
      encrypt: railFenceEncrypt,
      decrypt: railFenceDecrypt,
    },

    morse: {
      id: 'morse',
      keyType: 'none',
      encrypt: morseEncode,
      decrypt: morseDecode,
    },

    adfgvx: {
      id: 'adfgvx',
      keyType: 'two-keyword',
      encrypt: adfgvxEncrypt,
      decrypt: adfgvxDecrypt,
    },

    pigpen: {
      id: 'pigpen',
      keyType: 'none',
      encrypt: pigpenEncode,
      decrypt: pigpenDecode,
    },

    semaphore: {
      id: 'semaphore',
      keyType: 'none',
      encrypt: semaphoreEncode,
      decrypt: semaphoreDecode,
    },

    bacon: {
      id: 'bacon',
      keyType: 'none',
      encrypt: baconEncode,
      decrypt: baconDecode,
    },

    braille: {
      id: 'braille',
      keyType: 'none',
      encrypt: brailleEncode,
      decrypt: brailleDecode,
    },

    route: {
      id: 'route',
      keyType: 'route',
      encrypt: routeEncrypt,
      decrypt: routeDecrypt,
    },
  });

  /* ---------------------------------------------------------
     四、说明页数据
     --------------------------------------------------------- */
  const GUIDE_ENTRIES = [
    {
      id: 'a1z26',
      name: 'A1Z26',
      english: 'A1Z26',
      type: '数字编码',
      summary: '把英文字母换成它在字母表中的序号：A=1、B=2、…、Z=26。',
      aliases: ['a1z26', '字母序号', '数字编码'],
      key: '无需密钥。',
      encrypt: '英文字母转成 1–26 的数字，数字之间用 - 分隔；其他字符原样保留。',
      decrypt: '把 1–26 的数字还原为英文字母；解密结果统一为大写。',
      example: 'Hello, World! → 8-5-12-12-15, 23-15-18-12-4!',
      notes: [
        '明文中的数字、连字符和反斜杠会用 \\ 转义，保证往返可逆。',
        '不保留大小写：解密结果统一为大写。',
        '属于数字编码，不是安全的加密算法。',
      ],
    },
    {
      id: 'affine',
      name: '仿射密码',
      english: 'Affine',
      type: '单表替换 · 仿射',
      summary: '用一次线性变换 y = (a·x + b) mod 26 完成字母替换。',
      aliases: ['affine', '仿射', '仿射密码'],
      key: '两个整数 a、b；a 必须与 26 互质（1、3、5、7、9、11、15、17、19、21、23、25），b 取 0–25。',
      encrypt: '字母索引 x 变为 (a·x + b) mod 26。',
      decrypt: '字母索引 y 变为 a⁻¹·(y − b) mod 26，其中 a⁻¹ 是 a 在模 26 下的逆元。',
      example: 'AFFINE，a=5、b=8 → IHHWVC',
      notes: [
        'a 与 26 不互质时不存在解密所需的逆元，因此密钥非法。',
        'a=1、b=0 时结果不变；a=1 时等价于凯撒位移 b。',
        '大小写保留，非字母字符不变。',
      ],
    },
    {
      id: 'ascii',
      name: 'ASCII 码替换',
      english: 'ASCII',
      type: '字符编码',
      summary: '把每个字符换成对应的十进制 ASCII 码。',
      aliases: ['ascii', 'ascii码', '字符编码'],
      key: '无需密钥。',
      encrypt: '字符转成 0–127 的十进制 ASCII 码，用空格分隔。',
      decrypt: '把空格分隔的数字还原为对应字符。',
      example: 'Hi! → 72 105 33',
      notes: [
        '只支持 ASCII 字符；中文、emoji 会提示错误。',
        '空格会被编码为 32，因此结果是纯数字串。',
        '属于字符编码，不是加密算法。',
      ],
    },
    {
      id: 'atbash',
      name: '埃特巴什码',
      english: 'Atbash',
      type: '单表替换 · 镜像',
      summary: '把字母表首尾镜像：A↔Z、B↔Y、C↔X。',
      aliases: ['atbash', '埃特巴什', '埃特巴什码', '镜像'],
      key: '无需密钥。',
      encrypt: '每个字母替换为距字母表中心对称的字母，大小写各自镜像。',
      decrypt: '与加密相同，再执行一次即可还原。',
      example: 'Hello, World! → Svool, Dliow!',
      notes: [
        '自反算法：加密和解密使用同一规则。',
        '非字母字符不变。',
        '只有一种固定映射，安全性很低。',
      ],
    },
    {
      id: 'beaufort',
      name: '博福特密码',
      english: 'Beaufort',
      type: '多表替换',
      summary: '以关键词为密钥的多表替换，使用 C = K − P。',
      aliases: ['beaufort', '博福特', '博福特密码'],
      key: '英文字母关键词，例如 KEY；只含字母，大小写不敏感；非字母不消耗密钥位置。',
      encrypt: '每个明文字母 P 与循环使用的密钥字母 K 计算 (K − P) mod 26。',
      decrypt: '对密文字母 C 计算 (K − C) mod 26；与加密公式相同，算法自反。',
      example: 'HELLO，密钥 KEY → DANZQ',
      notes: [
        '这里实现的是标准博福特，不是变体博福特（P − K）。',
        '关键词只使用英文字母；遇到非字母字符时密钥不前进。',
        '大小写保留。',
      ],
    },
    {
      id: 'caesar',
      name: '凯撒密码',
      english: 'Caesar',
      type: '单表替换 · 移位',
      summary: '把每个字母沿字母表固定移动若干位。',
      aliases: ['caesar', '凯撒', '凯撒密码', '移位'],
      key: '1–25 的整数位移量。',
      encrypt: '每个字母向后移动 k 位；超过 Z 后回到 A。',
      decrypt: '每个字母向前移动 k 位。',
      example: 'Hello, World!，k=3 → Khoor, Zruog!',
      notes: [
        '密钥空间只有 25 种，容易被穷举。',
        '只变换英文字母，其他字符不变。',
        '大小写保持。',
      ],
    },
    {
      id: 'rot13',
      name: 'ROT13',
      english: 'ROT13',
      type: '单表替换 · 固定移位',
      summary: '固定位移 13 位的凯撒密码特例。',
      aliases: ['rot13', 'rot', '凯撒13', '固定移位'],
      key: '无需密钥。',
      encrypt: '每个英文字母移动 13 位。',
      decrypt: '再次移动 13 位；与加密相同，算法自反。',
      example: 'Hello, World! → Uryyb, Jbeyq!',
      notes: [
        '因为 13×2=26，加密两次回到原文。',
        '不提供真正的保密性，常用于隐藏剧透或弱混淆。',
        '非字母字符不变。',
      ],
    },
    {
      id: 'vigenere',
      name: '维吉尼亚密码',
      english: 'Vigenère',
      type: '多表替换',
      summary: '用关键词循环移位，每个字母使用不同的凯撒位移。',
      aliases: ['vigenere', 'vigenère', '维吉尼亚', '维吉尼亚密码', '弗吉尼亚'],
      key: '英文字母关键词，例如 LEMON；只含字母，大小写不敏感；非字母不消耗密钥位置。',
      encrypt: '每个明文字母 P 加上当前密钥字母 K，得到 (P + K) mod 26。',
      decrypt: '每个密文字母 C 减去当前密钥字母 K，得到 (C − K) mod 26。',
      example: 'ATTACKATDAWN，密钥 LEMON → LXFOPVEFRNHR',
      notes: [
        '关键词循环使用；空格、标点和数字不消耗密钥。',
        '比单表替换更强，但仍可能被频率分析或已知明文攻击破解。',
        '关键词只使用英文字母。',
      ],
    },
    {
      id: 'foursquare',
      name: '四方密码',
      english: 'Four-square',
      type: '四个 5×5 方阵 · 双字母替换',
      summary: '用四个 5×5 方阵，把一对明文字母替换成另一对字母。',
      aliases: ['foursquare', 'four-square', '四方', '四方密码'],
      key: '两个英文字母关键词（两个密钥方阵）；只含字母，I/J 合并。',
      encrypt: '明文整理为大写字母（J→I，非字母去掉），两两分组，末尾补 X；按两个标准方阵定位，再从两个密钥方阵取交叉字母。',
      decrypt: '在密钥方阵中定位密文字母，回到两个标准方阵取交叉字母。',
      example: 'THEPRISONERSHAVEESCAPED，密钥 HACK / SAFE → SHBOTDTMPFSQDFZSCUHFPBCY',
      notes: [
        '只处理英文字母，输出大写、无空格；末尾补齐的 X 会保留。',
        'I/J 合并，J 会当成 I 处理。',
        '两个关键词可以不同，推荐使用两个独立关键词。',
      ],
      matrix: { cipher: 'foursquare', key1: 'HACK', key2: 'SAFE' },
    },
    {
      id: 'morse',
      name: '摩斯密码',
      english: 'Morse',
      type: '点划码',
      summary: '用点（.）和划（-）表示字母、数字与常用标点。',
      aliases: ['morse', '摩斯', '摩斯密码', '摩尔斯', '点划'],
      key: '无需密钥。',
      encrypt: '字母、数字和常用标点转成摩斯码；字母之间用空格，单词之间用 / 分隔。',
      decrypt: '按 / 分词、按空格分字母，再逐码还原。',
      example: 'SOS → ... --- ...；HELLO WORLD → .... . .-.. .-.. --- / .-- --- .-. .-.. -..',
      notes: [
        '不保留大小写，解密结果为大写。',
        '连续空格和换行会规范为一个空格。',
        '不支持的字符（如中文、emoji）会明确报错。',
        '下方给出本工具支持的完整字符对照表。',
      ],
      morseTable: MORSE_ENTRIES,
    },
    {
      id: 'playfair',
      name: '普莱费尔密码',
      english: 'Playfair',
      type: '5×5 方阵 · 双字母替换',
      summary: '用关键词方阵把成对字母替换成另外两个字母。',
      aliases: ['playfair', '普莱费尔', '普莱费尔密码'],
      key: '英文字母关键词；只含字母，I/J 合并，重复字母忽略。',
      encrypt: '明文整理为大写字母（J→I，非字母去掉），两两分组；同组重复插入 X，末尾不足补 X。同行右移、同列下移，其余交换列。',
      decrypt: '按相反方向移动：同行左移、同列上移，其余交换列。',
      example: 'SUPERSECRETMESSAGE，密钥 safety → YSQFNTFDQTGRTAAFDT',
      notes: [
        '只处理英文字母，输出大写、无空格；插入或补齐的 X 会保留在解密结果中。',
        'I/J 合并；关键词中的重复字母只保留一次。',
        '属于双字母替换，比单表替换更能抵抗简单频率分析。',
      ],
      matrix: { cipher: 'playfair', key1: 'SAFETY' },
    },
    {
      id: 'polybius',
      name: '波利比奥斯方阵',
      english: 'Polybius',
      type: '5×5 坐标替换',
      summary: '把字母放进 5×5 方阵，用行列坐标表示。',
      aliases: ['polybius', 'polybius square', '波利比奥斯', '波利比奥斯方阵', '棋盘密码'],
      key: '无需密钥；固定 5×5 方阵，I/J 合并。',
      encrypt: '字母转成两位行列坐标（1–5），坐标对之间用空格分隔；非字母去掉。',
      decrypt: '把 1–5 的两位坐标还原为字母。',
      example: 'HELLO → 23 15 31 31 34',
      notes: [
        '只处理英文字母，输出大写；J 会还原为 I。',
        '方阵固定，不支持自定义字母表。',
        '下方给出完整 5×5 方阵。',
      ],
      matrix: { cipher: 'polybius' },
    },
    {
      id: 'railfence',
      name: '栅栏密码',
      english: 'Rail Fence',
      type: '换位密码 · 之字形',
      summary: '把文本按之字形写到多条栅栏上，再按行读出。',
      aliases: ['railfence', 'rail fence', '栅栏', '栅栏密码', '之字形'],
      key: '2–20 的整数栅栏数。',
      encrypt: '按之字形把每个字符分配到 0…n−1 号栅栏，再按栅栏顺序拼接。',
      decrypt: '重建之字形位置，按各行长度切分密文，再按原路径读回。',
      example: 'WEAREDISCOVEREDFLEEATONCE，3 栏 → WECRLTEERDSOEEFEAOCAIVDEN',
      notes: [
        '空格和标点也参与换位，因此解密可以完整还原。',
        '输出中的空格位置会改变，这是换位密码的正常现象。',
        '栅栏数越大，文本被打散得越明显。',
      ],
    },
    {
      id: 'twosquare',
      name: '二方密码',
      english: 'Two-square',
      type: '左右 5×5 方阵 · 双字母替换',
      summary: '用左右两个 5×5 密钥方阵，把一对字母替换成矩形对角位置的字母。',
      aliases: ['twosquare', 'two-square', '二方', '二方密码', '双方阵'],
      key: '两个英文字母关键词；只含字母，I/J 合并。',
      encrypt: '明文整理为大写字母（J→I，非字母去掉），两两分组，末尾补 X；第一个字母查左方阵，第二个查右方阵，取矩形另外两个角。',
      decrypt: '在左右方阵中定位密文字母，再按矩形规则还原。',
      example: 'IOEX，密钥 EXAMPLE / KEYWORD → NYMT',
      notes: [
        '这里实现的是横向二方密码（左右两个方阵）。',
        '只处理英文字母，输出大写、无空格；J→I，末尾补齐的 X 会保留。',
        '解密 NYMT 会得到 IOEX，而不是原始 JOE，因为 J 已合并为 I 且补了 X。',
      ],
      matrix: { cipher: 'twosquare', key1: 'EXAMPLE', key2: 'KEYWORD' },
    },
    {
      id: 'adfgvx',
      name: 'ADFGVX 密码',
      english: 'ADFGVX',
      type: '6×6 方阵 + 列换位',
      summary: '先用 6×6 方阵把字符变成 ADFGVX 坐标，再进行列换位。',
      aliases: ['adfgvx', 'adfgvx密码', '坐标换位'],
      key: '两个英文字母关键词：关键词 1 生成 6×6 方阵，关键词 2 用于列换位。',
      encrypt: '字符先转成两个 ADFGVX 坐标字母，再按第二个关键词做列换位。',
      decrypt: '先逆向列换位，再把坐标对还原为字符。',
      example: 'ATTACKATDAWN，密钥 CARGO / SECRET → GAGGDDDDGFDFDADVAAAADAAG',
      notes: [
        '支持 A–Z 和 0–9；其他字符会被去掉。',
        '关键词只使用英文字母；两个关键词分别负责方阵和换位。',
        '下方给出示例 6×6 方阵。',
      ],
      adfgvxKey: 'CARGO',
    },
    {
      id: 'bacon',
      name: '培根密码',
      english: 'Bacon',
      type: '5 位 A/B 编码',
      summary: '每个字母用 5 个 A/B 符号表示。',
      aliases: ['bacon', '培根', '培根密码', 'ab码'],
      key: '无需密钥；26 字母各对应一个 5 位 A/B 码。',
      encrypt: '字母转成 5 位 A/B 码，每个字母之间用空格分隔。',
      decrypt: '把每组 5 位 A/B 码还原为字母。',
      example: 'HELLO → AABBB AABAA ABABB ABABB ABBBA',
      notes: [
        '只处理英文字母，输出大写。',
        '使用 26 字母版本，I/J、U/V 不合并。',
        '下方给出完整 26 字母对照表。',
      ],
      baconTable: BACON_TABLE,
    },
    {
      id: 'braille',
      name: '盲文',
      english: 'Braille',
      type: '六点盲文单元',
      summary: '用 2×3 的六个凸点组合表示字母、数字和标点。',
      aliases: ['braille', '盲文', '点字'],
      key: '无需密钥。',
      encrypt: '字母转成 Unicode 盲文单元；数字前加数字符号；支持空格和常用标点。',
      decrypt: '逐个盲文单元还原；数字符号后的单元按数字读取。',
      example: 'HI → ⠓⠊',
      notes: [
        '字母不区分大小写，解密结果为大写。',
        '数字使用数字符号加 A–J 单元表示；标点使用标准盲文单元。',
        '下方给出本工具支持的完整盲文对照表。',
      ],
      brailleTable: BRAILLE_TABLE,
    },
    {
      id: 'pigpen',
      name: '猪圈密码',
      english: 'Pigpen',
      type: '九宫格 / X 形格位',
      summary: '用九宫格和 X 形区域的位置表示字母。',
      aliases: ['pigpen', '猪圈', '猪圈密码', '共济会密码'],
      key: '无需密钥；使用“区域 + 格位”码，如 1a、2b、3c。',
      encrypt: '字母转成格位码：1/2 为九宫格，3 为 X 形区域；码之间用空格分隔。',
      decrypt: '把格位码还原为字母。',
      example: 'HELLO → 1h 1e 2c 2c 2f',
      notes: [
        '只处理英文字母，输出大写。',
        '本工具用可复制的格位码表示猪圈符号，说明栏给出完整格位图。',
        '下方给出 26 个字母的完整对照表。',
      ],
      pigpenGroups: PIGPEN_GROUPS,
    },
    {
      id: 'route',
      name: '路径密码',
      english: 'Route',
      type: '换位密码 · 顺时针螺旋',
      summary: '把文本按行填入矩阵，再从左上角顺时针螺旋读出。',
      aliases: ['route', '路径', '路径密码', '螺旋密码'],
      key: '2–10 的整数矩阵列数。',
      encrypt: '按行填入 rows × columns 矩阵，从左上角顺时针向内螺旋读取。',
      decrypt: '按螺旋路径填回矩阵，再按行读出。',
      example: 'ABCDEFGHI，4 列 → ABCDHIEFG',
      notes: [
        '空格和标点也参与换位，因此解密可以完整还原。',
        '列数决定矩阵形状；最后一行不足时跳过空位。',
        '属于换位密码，不改变字符本身。',
      ],
    },
    {
      id: 'semaphore',
      name: '旗语',
      english: 'Semaphore',
      type: '左右臂位置码',
      summary: '用左右两臂的八个方向位置表示字母。',
      aliases: ['semaphore', '旗语', '旗语密码', '手旗'],
      key: '无需密钥；使用左右臂位置码，如 D-L。',
      encrypt: '字母转成左右臂位置码；码之间用空格分隔。',
      decrypt: '把位置码还原为字母。',
      example: 'HELLO → AL-O H-D H-L H-L AH-O',
      notes: [
        '只处理英文字母，输出大写。',
        '本工具以可复制的位置码表示旗语，说明栏给出完整左右臂对照表。',
        '下方给出 26 个字母的完整对照表。',
      ],
      semaphoreTable: SEMAPHORE_TABLE,
    },
  ];

  const GUIDE_CATEGORY_BY_ID = {
    a1z26: 'single',
    adfgvx: 'other',
    affine: 'single',
    ascii: 'single',
    atbash: 'single',
    bacon: 'other',
    beaufort: 'poly',
    braille: 'other',
    caesar: 'single',
    foursquare: 'matrix',
    morse: 'other',
    pigpen: 'other',
    playfair: 'matrix',
    polybius: 'matrix',
    railfence: 'transposition',
    rot13: 'single',
    route: 'transposition',
    semaphore: 'other',
    twosquare: 'matrix',
    vigenere: 'poly',
  };

  const CATEGORY_LABELS = {
    all: '全部',
    single: '单表替换',
    poly: '多表替换',
    matrix: '矩阵替换',
    transposition: '换位密码',
    other: '其他加密',
  };

  const CATEGORY_NOTES = {
    all: '按单表、多表、矩阵、换位、其他五类浏览，也可以直接搜索算法。',
    single: '一个明文字符固定对应一个密文字符，如凯撒、Atbash、仿射。',
    poly: '同一明文字符在不同位置可能对应不同密文字符，如维吉尼亚、博福特。',
    matrix: '使用 5×5 方阵进行单字母或双字母替换，如普莱费尔、四方、二方、波利比奥斯。',
    transposition: '只改变字符顺序，不改变字符本身，如栅栏、路径。',
    other: '用符号、图形、点划、坐标或编码表示字符；每种算法都附完整字符对照表。',
  };

  GUIDE_ENTRIES.forEach((entry) => {
    entry.category = GUIDE_CATEGORY_BY_ID[entry.id];
  });

  GUIDE_ENTRIES.sort((first, second) => first.english.localeCompare(second.english));

  /* ---------------------------------------------------------
     五、DOM 引用与界面状态
     --------------------------------------------------------- */

  const dom = {
    siteMain: document.getElementById('site-main'),
    navLinks: Array.from(document.querySelectorAll('.site-nav a[data-route]')),
    views: Array.from(document.querySelectorAll('[data-view]')),

    toolTitle: document.getElementById('tool-title'),
    toolDescription: document.getElementById('tool-description'),
    inputLabel: document.getElementById('input-label'),
    outputLabel: document.getElementById('output-label'),
    starfield: document.getElementById('starfield'),

    algorithm: document.getElementById('algorithm'),
    caesarKeyField: document.getElementById('caesar-key-field'),
    affineKeyField: document.getElementById('affine-key-field'),
    keywordField: document.getElementById('keyword-field'),
    twoKeywordField: document.getElementById('two-keyword-field'),
    railField: document.getElementById('rail-field'),
    routeField: document.getElementById('route-field'),
    noKeyNote: document.getElementById('no-key-note'),
    caesarKey: document.getElementById('caesar-key'),
    affineA: document.getElementById('affine-a'),
    affineB: document.getElementById('affine-b'),
    keyword: document.getElementById('keyword'),
    keywordHint: document.getElementById('keyword-hint'),
    keyword1: document.getElementById('keyword-1'),
    keyword2: document.getElementById('keyword-2'),
    twoKeywordHint: document.getElementById('two-keyword-hint'),
    railCount: document.getElementById('rail-count'),
    routeColumns: document.getElementById('route-columns'),
    inputText: document.getElementById('input-text'),
    clearInput: document.getElementById('clear-input'),
    errorRegion: document.getElementById('error-region'),
    outputText: document.getElementById('output-text'),
    copyButton: document.getElementById('copy-btn'),
    matrixPanel: document.getElementById('matrix-panel'),
    historyList: document.getElementById('history-list'),
    historyEmpty: document.getElementById('history-empty'),
    historyClear: document.getElementById('history-clear'),

    gameCard: document.getElementById('game-card'),
    gameLobby: document.getElementById('game-lobby'),
    gameProgress: document.getElementById('game-progress'),
    gameTimer: document.getElementById('game-timer'),
    gameScore: document.getElementById('game-score'),
    gameDifficultyLabel: document.getElementById('game-difficulty-label'),
    gameState: document.getElementById('game-state'),
    gameHint: document.getElementById('game-hint'),
    gameHintButton: document.getElementById('game-hint-btn'),
    gameHintDetail: document.getElementById('game-hint-detail'),
    gameCipher: document.getElementById('game-cipher'),
    gameAnswer: document.getElementById('game-answer'),
    gameFeedback: document.getElementById('game-feedback'),
    gameSubmit: document.getElementById('game-submit'),
    gameGiveup: document.getElementById('game-giveup'),
    gameNext: document.getElementById('game-next'),
    gameResult: document.getElementById('game-result'),
    gameExplanation: document.getElementById('game-explanation'),
    gameScratch: document.getElementById('game-scratch'),
    gameScratchAlgorithm: document.getElementById('game-scratch-algorithm'),
    gameScratchKey: document.getElementById('game-scratch-key'),
    gameScratchHint: document.getElementById('game-scratch-hint'),
    gameScratchRun: document.getElementById('game-scratch-run'),
    gameScratchError: document.getElementById('game-scratch-error'),
    gameScratchResult: document.getElementById('game-scratch-result'),
    comboPop: document.getElementById('combo-pop'),

    gameSummary: document.getElementById('game-summary'),
    gameSummaryKicker: document.getElementById('game-summary-kicker'),
    gameSummaryScore: document.getElementById('game-summary-score'),
    gameSummaryDetail: document.getElementById('game-summary-detail'),
    gameSummaryLeave: document.getElementById('game-summary-leave'),
    gamePerfectBadge: document.getElementById('game-perfect-badge'),
    gameRestart: document.getElementById('game-restart'),
    gameChangeDifficulty: document.getElementById('game-change-difficulty'),

    gameStartDifficulties: document.getElementById('game-start-difficulties'),
    gameStartButton: document.getElementById('game-start-btn'),
    gameLobbyStory: document.getElementById('game-lobby-story'),
    gameRecords: {
      easy: document.getElementById('game-record-easy'),
      medium: document.getElementById('game-record-medium'),
      hard: document.getElementById('game-record-hard'),
    },

    gameLeaveModal: document.getElementById('game-leave-modal'),
    gameLeaveMessage: document.getElementById('game-leave-message'),
    gameLeaveCancel: document.getElementById('game-leave-cancel'),
    gameLeaveConfirm: document.getElementById('game-leave-confirm'),

    guideSearch: document.getElementById('guide-search'),
    guideStatus: document.getElementById('guide-status'),
    guideCategories: document.getElementById('guide-categories'),
    guideCategoryNote: document.getElementById('guide-category-note'),
    guideCategoryButtons: Array.from(document.querySelectorAll('.guide-category')),
    guideList: document.getElementById('guide-list'),
    guideDetail: document.getElementById('guide-detail'),
  };

  const COPY_FEEDBACK_DURATION = 1500;
  const LIVE_TRANSFORM_DELAY = 90;
  const HISTORY_DELAY = 700;
  const HISTORY_LIMIT = 5;

  const ROUTES = {
    home: { documentTitle: '【CipherLab】· 破译未知密文，洞悉隐秘真相。' },
    encrypt: { documentTitle: '加密 · 【CipherLab】' },
    decrypt: { documentTitle: '解密 · 【CipherLab】' },
    game: { documentTitle: '破译 · 【CipherLab】' },
    guide: { documentTitle: '说明 · 【CipherLab】' },
  };

  let copyResetTimer = null;
  let liveTimer = null;
  let historyTimer = null;
  let historyRecords = [];
  let toolMode = 'encrypt';
  let currentRoute = null;
  let selectedGuideId = 'caesar';
  let activeCategory = 'all';

  /**
   * 读取当前选中的算法，异常时回退到凯撒。
   * @returns {{id: string, keyType: string, encrypt: Function, decrypt: Function}}
   */
  function getCurrentCipher() {
    return CIPHERS[dom.algorithm.value] || CIPHERS.caesar;
  }

  /* 需要展示加密方阵的算法 */
  const MATRIX_CIPHER_IDS = new Set(['playfair', 'foursquare', 'twosquare', 'polybius']);

  /**
   * 生成矩阵密码的方阵配置。
   * @param {string} cipherId
   * @param {{key1?: string, key2?: string}|null} key
   * @returns {{note: string, squares: Array}|null}
   */
  function buildMatrixConfig(cipherId, key) {
    if (cipherId === 'playfair') {
      return {
        note: `关键词：${key.key1}；I/J 合并，重复字母只保留一次。`,
        squares: [
          { label: `密钥方阵（${key.key1}）`, rows: squareToRows(buildKeyedSquare(key.key1)) },
        ],
      };
    }

    if (cipherId === 'foursquare') {
      const standardRows = squareToRows(SQUARE_ALPHABET);

      return {
        note: `关键词：${key.key1} / ${key.key2}；I/J 合并。`,
        squares: [
          { label: `密钥方阵 1（${key.key1}）`, rows: squareToRows(buildKeyedSquare(key.key1)) },
          { label: '标准方阵', rows: standardRows },
          { label: '标准方阵', rows: standardRows },
          { label: `密钥方阵 2（${key.key2}）`, rows: squareToRows(buildKeyedSquare(key.key2)) },
        ],
      };
    }

    if (cipherId === 'twosquare') {
      return {
        note: `关键词：${key.key1} / ${key.key2}；I/J 合并。`,
        squares: [
          { label: `左方阵（${key.key1}）`, rows: squareToRows(buildKeyedSquare(key.key1)) },
          { label: `右方阵（${key.key2}）`, rows: squareToRows(buildKeyedSquare(key.key2)) },
        ],
      };
    }

    if (cipherId === 'polybius') {
      return {
        note: '固定 5×5 方阵；I/J 合并，坐标从 1 开始。',
        squares: [
          { label: '固定方阵', rows: POLYBIUS_ROWS },
        ],
      };
    }

    return null;
  }

  /**
   * 读取当前加密参数并生成方阵配置。
   * @returns {{note: string, squares: Array}|null}
   */
  function buildCurrentMatrixConfig() {
    const cipher = getCurrentCipher();

    if (!MATRIX_CIPHER_IDS.has(cipher.id)) {
      return null;
    }

    try {
      if (cipher.id === 'playfair') {
        return buildMatrixConfig('playfair', {
          key1: normalizeKeyword(dom.keyword.value),
        });
      }

      if (cipher.id === 'foursquare' || cipher.id === 'twosquare') {
        return buildMatrixConfig(cipher.id, normalizeTwoKeywords({
          key1: dom.keyword1.value,
          key2: dom.keyword2.value,
        }));
      }

      if (cipher.id === 'polybius') {
        return buildMatrixConfig('polybius', null);
      }
    } catch (error) {
      return null;
    }

    return null;
  }

  /**
   * 在容器中渲染方阵卡片。
   * @param {HTMLElement} container
   * @param {{note: string, squares: Array}} config
   * @param {string} title
   * @param {'h2'|'h3'} headingTag
   */
  function fillMatrixPanel(container, config, title, headingTag) {
    clearElement(container);

    const header = createElement('div', 'matrix-panel__head');
    header.append(createElement(headingTag, 'matrix-panel__title', title));
    header.append(createElement('p', 'matrix-panel__note', config.note));
    container.append(header);

    const grid = createElement('div', 'matrix-grid');
    grid.dataset.count = String(config.squares.length);

    for (const square of config.squares) {
      const card = createElement('div', 'matrix-card');
      card.append(createElement('p', 'matrix-card__label', square.label));

      const table = createElement('table', 'matrix-table');
      const thead = document.createElement('thead');
      const headRow = document.createElement('tr');
      const corner = createElement('th', 'matrix-corner', '');
      corner.scope = 'col';
      headRow.append(corner);

      ['1', '2', '3', '4', '5'].forEach((col) => {
        const th = createElement('th', '', col);
        th.scope = 'col';
        headRow.append(th);
      });

      thead.append(headRow);
      const tbody = document.createElement('tbody');

      square.rows.forEach((row, rowIndex) => {
        const tr = document.createElement('tr');
        const rowHead = createElement('th', '', String(rowIndex + 1));
        rowHead.scope = 'row';
        tr.append(rowHead);

        row.forEach((letter) => {
          tr.append(createElement('td', '', letter === 'I' ? 'I/J' : letter));
        });

        tbody.append(tr);
      });

      table.append(thead, tbody);
      card.append(table);
      grid.append(card);
    }

    container.append(grid);
  }

  /**
   * 更新“加密”栏中的加密方阵：仅加密模式、矩阵密码、密钥合法时显示。
   */
  function updateMatrixPanel() {
    if (!dom.matrixPanel) {
      return;
    }

    if (toolMode !== 'encrypt') {
      dom.matrixPanel.hidden = true;
      clearElement(dom.matrixPanel);
      return;
    }

    const config = buildCurrentMatrixConfig();

    if (!config) {
      dom.matrixPanel.hidden = true;
      clearElement(dom.matrixPanel);
      return;
    }

    dom.matrixPanel.hidden = false;
    fillMatrixPanel(dom.matrixPanel, config, '加密方阵', 'h2');
  }

  /**
   * 盲文只在真正承载盲文的一侧放大字号：
   * 加密时放大输出，解密时放大输入。
   */
  function updateBrailleTextStyles() {
    const isBraille = getCurrentCipher().id === 'braille';

    dom.inputText.classList.toggle('is-braille', isBraille && toolMode === 'decrypt');
    dom.outputText.classList.toggle('is-braille', isBraille && toolMode === 'encrypt');
  }

  /**
   * 根据当前算法显示对应的密钥输入区或“无需密钥”提示。
   */
  function updateKeyVisibility() {
    const cipher = getCurrentCipher();

    dom.caesarKeyField.hidden = cipher.keyType !== 'caesar';
    dom.affineKeyField.hidden = cipher.keyType !== 'affine';
    dom.keywordField.hidden = cipher.keyType !== 'keyword';
    dom.twoKeywordField.hidden = cipher.keyType !== 'two-keyword';
    dom.railField.hidden = cipher.keyType !== 'rails';
    dom.routeField.hidden = cipher.keyType !== 'route';
    dom.noKeyNote.hidden = cipher.keyType !== 'none';

    if (cipher.keyType === 'keyword') {
      dom.keywordHint.textContent = cipher.id === 'playfair'
        ? '仅英文字母；I/J 合并，重复字母会忽略。'
        : '仅英文字母；非字母字符不消耗密钥位置。';
    }

    if (cipher.keyType === 'two-keyword') {
      dom.twoKeywordHint.textContent = cipher.id === 'adfgvx'
        ? '关键词 1 生成 6×6 方阵，关键词 2 用于列换位；仅英文字母。'
        : '两个关键词仅英文字母；I/J 合并，重复字母忽略。';
    }

    if (cipher.keyType === 'none') {
      const notes = {
        a1z26: 'A1Z26 无需密钥；字母转为 1–26，解密为大写。',
        ascii: 'ASCII 码替换无需密钥；字符会转为十进制 ASCII 码（仅支持 ASCII）。',
        atbash: 'Atbash 无需密钥，直接输入文本即可。',
        rot13: 'ROT13 无需密钥，直接输入文本即可。',
        polybius: '无需密钥；字母转为行列坐标。',
        morse: '摩斯密码无需密钥；字母用空格分隔，单词用 / 分隔。',
        pigpen: '猪圈密码无需密钥；使用“区域 + 格位”码，如 1a、2b。',
        semaphore: '旗语无需密钥；使用左右臂位置码，如 D-L。',
        bacon: '培根密码无需密钥；每个字母对应 5 位 A/B 码。',
        braille: '盲文无需密钥；字母转为 Unicode 盲文单元。',
      };
      dom.noKeyNote.textContent = notes[cipher.id] || '该算法无需密钥，直接输入文本即可。';
    }
  }

  /* ---------------------------------------------------------
     六、错误与结果状态
     --------------------------------------------------------- */

  /**
   * 清除错误提示与所有输入框的非法状态。
   */
  function clearError() {
    dom.errorRegion.hidden = true;
    dom.errorRegion.textContent = '';
    dom.inputText.removeAttribute('aria-invalid');
    dom.caesarKey.removeAttribute('aria-invalid');
    dom.affineA.removeAttribute('aria-invalid');
    dom.affineB.removeAttribute('aria-invalid');
    dom.keyword.removeAttribute('aria-invalid');
    dom.keyword1.removeAttribute('aria-invalid');
    dom.keyword2.removeAttribute('aria-invalid');
    dom.railCount.removeAttribute('aria-invalid');
    dom.routeColumns.removeAttribute('aria-invalid');
  }

  /**
   * 展示错误提示，并可选择是否把焦点移到出错控件上。
   * 实时输入时不抢焦点，避免打断用户打字。
   * @param {string} message 错误文案
   * @param {HTMLElement|null} targetField 需要标记的控件
   * @param {{focus?: boolean}} [options]
   */
  function showError(message, targetField, options = {}) {
    dom.errorRegion.hidden = false;
    dom.errorRegion.textContent = message;

    if (targetField) {
      targetField.setAttribute('aria-invalid', 'true');

      if (options.focus !== false) {
        targetField.focus();
      }
    }
  }

  /**
   * 将复制按钮恢复为初始文案，并清理计时器。
   */
  function resetCopyButton() {
    if (copyResetTimer !== null) {
      clearTimeout(copyResetTimer);
      copyResetTimer = null;
    }

    dom.copyButton.textContent = '复制结果';
    dom.copyButton.classList.remove('is-copied');
  }

  /**
   * 清空输出区，并重置复制按钮。
   */
  function clearOutput() {
    dom.outputText.value = '';
    dom.outputText.classList.remove('is-fresh');
    dom.copyButton.disabled = true;
    resetCopyButton();
  }

  /**
   * 复制成功后的短暂反馈：文案变为“已复制”，约 1.5 秒后恢复。
   */
  function showCopiedState() {
    if (copyResetTimer !== null) {
      clearTimeout(copyResetTimer);
    }

    dom.copyButton.textContent = '已复制';
    dom.copyButton.classList.add('is-copied');

    copyResetTimer = setTimeout(() => {
      dom.copyButton.textContent = '复制结果';
      dom.copyButton.classList.remove('is-copied');
      copyResetTimer = null;
    }, COPY_FEEDBACK_DURATION);
  }

  /**
   * 重新播放结果淡入动画（先移除类并强制重排，确保可重复触发）。
   */
  function playResultAnimation() {
    dom.outputText.classList.remove('is-fresh');
    void dom.outputText.offsetWidth;
    dom.outputText.classList.add('is-fresh');
  }

  /**
   * 动画结束后移除标记类。
   * @param {AnimationEvent} event
   */
  function handleResultAnimationEnd(event) {
    if (event.animationName === 'result-glow') {
      dom.outputText.classList.remove('is-fresh');
    }
  }

  /* ---------------------------------------------------------
     七、密钥解析与加解密流程
     --------------------------------------------------------- */

  /**
   * 解析凯撒密钥，返回统一结果对象。
   * @param {string} rawValue 输入框原始值
   * @returns {{ok: true, value: number} | {ok: false, message: string}}
   */
  function parseCaesarKey(rawValue) {
    try {
      return { ok: true, value: normalizeCaesarKey(rawValue) };
    } catch (error) {
      const message = error instanceof Error ? error.message : '凯撒位移量必须是 1–25 的整数';
      return { ok: false, message };
    }
  }

  /**
   * 解析仿射密码的 a、b 输入，并定位到具体出错的字段。
   * @returns {{ok: true, value: {a: number, b: number}} | {ok: false, message: string, field: HTMLElement}}
   */
  function parseAffineInput() {
    const rawA = dom.affineA.value.trim();
    const rawB = dom.affineB.value.trim();

    if (rawA === '' || rawB === '') {
      return {
        ok: false,
        message: '请输入仿射密码的 a 和 b（整数）',
        field: rawA === '' ? dom.affineA : dom.affineB,
      };
    }

    const a = Number(rawA);
    const b = Number(rawB);

    if (!Number.isInteger(a) || !Number.isInteger(b)) {
      return {
        ok: false,
        message: '仿射密码的 a 和 b 必须是整数',
        field: Number.isInteger(a) ? dom.affineB : dom.affineA,
      };
    }

    if (!AFFINE_COPRIME_A.has(a)) {
      return {
        ok: false,
        message: '仿射密码的 a 必须是 1–25 中与 26 互质的整数',
        field: dom.affineA,
      };
    }

    if (b < 0 || b > 25) {
      return {
        ok: false,
        message: '仿射密码的 b 需在 0–25 之间',
        field: dom.affineB,
      };
    }

    return { ok: true, value: { a, b } };
  }

  /**
   * 解析关键词密钥。
   * @returns {{ok: true, value: string} | {ok: false, message: string, field: HTMLElement}}
   */
  function parseKeywordInput() {
    const raw = dom.keyword.value.trim();

    if (raw === '') {
      return { ok: false, message: '请输入密钥单词（仅英文字母）', field: dom.keyword };
    }

    if (!KEYWORD_PATTERN.test(raw)) {
      return { ok: false, message: '密钥单词只能包含英文字母', field: dom.keyword };
    }

    return { ok: true, value: raw.toUpperCase() };
  }

  /**
   * 解析四方 / 二方密码的两个关键词。
   * @returns {{ok: true, value: {key1: string, key2: string}} | {ok: false, message: string, field: HTMLElement}}
   */
  function parseTwoKeywordInput() {
    const raw1 = dom.keyword1.value.trim();
    const raw2 = dom.keyword2.value.trim();

    if (raw1 === '' || raw2 === '') {
      return {
        ok: false,
        message: '请输入两个关键词（仅英文字母）',
        field: raw1 === '' ? dom.keyword1 : dom.keyword2,
      };
    }

    if (!KEYWORD_PATTERN.test(raw1) || !KEYWORD_PATTERN.test(raw2)) {
      return {
        ok: false,
        message: '关键词只能包含英文字母',
        field: !KEYWORD_PATTERN.test(raw1) ? dom.keyword1 : dom.keyword2,
      };
    }

    return {
      ok: true,
      value: { key1: raw1.toUpperCase(), key2: raw2.toUpperCase() },
    };
  }

  /**
   * 解析栅栏数。
   * @returns {{ok: true, value: number} | {ok: false, message: string, field: HTMLElement}}
   */
  function parseRailInput() {
    try {
      return { ok: true, value: normalizeRailCount(dom.railCount.value) };
    } catch (error) {
      return {
        ok: false,
        message: error instanceof Error ? error.message : '栅栏数需为 2–20 的整数',
        field: dom.railCount,
      };
    }
  }

  /**
   * 解析路径密码列数。
   * @returns {{ok: true, value: number} | {ok: false, message: string, field: HTMLElement}}
   */
  function parseRouteInput() {
    try {
      return { ok: true, value: normalizeRouteColumns(dom.routeColumns.value) };
    } catch (error) {
      return {
        ok: false,
        message: error instanceof Error ? error.message : '列数需为 2–10 的整数',
        field: dom.routeColumns,
      };
    }
  }

  /**
   * 根据算法类型读取并校验密钥。
   * @param {{keyType: string}} cipher 当前算法
   * @returns {{ok: true, value: any} | {ok: false, message: string, field: HTMLElement}}
   */
  function readTransformKey(cipher) {
    if (cipher.keyType === 'caesar') {
      const result = parseCaesarKey(dom.caesarKey.value);
      return result.ok ? result : { ...result, field: dom.caesarKey };
    }

    if (cipher.keyType === 'affine') {
      return parseAffineInput();
    }

    if (cipher.keyType === 'keyword') {
      return parseKeywordInput();
    }

    if (cipher.keyType === 'two-keyword') {
      return parseTwoKeywordInput();
    }

    if (cipher.keyType === 'rails') {
      return parseRailInput();
    }

    if (cipher.keyType === 'route') {
      return parseRouteInput();
    }

    return { ok: true, value: null };
  }

  /**
   * 安排一次实时转换：输入、算法或密钥变化后短暂防抖执行。
   */
  function scheduleLiveTransform() {
    if (liveTimer !== null) {
      clearTimeout(liveTimer);
    }

    liveTimer = setTimeout(() => {
      liveTimer = null;
      handleTransform({ live: true });
    }, LIVE_TRANSFORM_DELAY);
  }

  /**
   * 清空输入框与结果，方便快速开始下一次输入。
   */
  function clearInputText() {
    if (liveTimer !== null) {
      clearTimeout(liveTimer);
      liveTimer = null;
    }

    dom.inputText.value = '';
    clearError();
    clearOutput();
    cancelHistoryRecord();
    updateMatrixPanel();
    dom.inputText.focus();
  }

  /**
   * 执行当前子栏目的操作（加密页只加密，解密页只解密）。
   * 实时模式下输入为空不报错，密钥错误也不抢焦点。
   * @param {{live?: boolean}} [options]
   */
  function handleTransform(options = {}) {
    const live = options.live === true;
    clearError();

    const action = toolMode;
    const cipher = getCurrentCipher();
    const rawText = dom.inputText.value;

    if (rawText.trim() === '') {
      clearOutput();
      cancelHistoryRecord();
      updateMatrixPanel();
      return;
    }

    const keyResult = readTransformKey(cipher);

    if (!keyResult.ok) {
      clearOutput();
      cancelHistoryRecord();
      showError(keyResult.message, keyResult.field, { focus: !live });
      updateMatrixPanel();
      return;
    }

    try {
      dom.outputText.value = cipher[action](rawText, keyResult.value);
    } catch (error) {
      clearOutput();
      cancelHistoryRecord();
      const message = error instanceof Error ? error.message : '处理失败，请检查输入后重试';
      showError(message, dom.inputText, { focus: !live });
      return;
    }

    dom.copyButton.disabled = false;
    resetCopyButton();

    if (!live) {
      playResultAnimation();
    }

    updateMatrixPanel();
    scheduleHistoryRecord();
  }

  /**
   * 获取当前算法的中文显示名。
   * @param {{id: string}} cipher
   * @returns {string}
   */
  function getCipherDisplayName(cipher) {
    const entry = GUIDE_ENTRIES.find((item) => item.id === cipher.id);

    if (entry) {
      return entry.name;
    }

    const option = dom.algorithm.options[dom.algorithm.selectedIndex];
    return option ? option.textContent : cipher.id;
  }

  /**
   * 安排写入历史记录：停止输入约 0.7 秒后记录，避免每按一个键都生成记录。
   */
  function scheduleHistoryRecord() {
    cancelHistoryRecord();
    historyTimer = setTimeout(() => {
      historyTimer = null;
      recordHistory();
    }, HISTORY_DELAY);
  }

  /**
   * 取消尚未写入的历史记录。
   */
  function cancelHistoryRecord() {
    if (historyTimer !== null) {
      clearTimeout(historyTimer);
      historyTimer = null;
    }
  }

  /**
   * 记录最近一次成功的加密 / 解密。
   */
  function recordHistory() {
    const input = dom.inputText.value;
    const output = dom.outputText.value;

    if (!input || !output) {
      return;
    }

    const cipher = getCurrentCipher();
    const key = `${toolMode}|${cipher.id}|${input}|${output}`;

    if (historyRecords[0] && historyRecords[0].key === key) {
      return;
    }

    const now = new Date();
    const time = [now.getHours(), now.getMinutes(), now.getSeconds()]
      .map((value) => String(value).padStart(2, '0'))
      .join(':');

    historyRecords.unshift({
      key,
      mode: toolMode,
      algorithm: getCipherDisplayName(cipher),
      algorithmId: cipher.id,
      input,
      output,
      time,
    });
    historyRecords = historyRecords.slice(0, HISTORY_LIMIT);
    renderHistory();
  }

  /**
   * 渲染最近记录列表。
   */
  function renderHistory() {
    clearElement(dom.historyList);
    dom.historyList.hidden = historyRecords.length === 0;
    dom.historyEmpty.hidden = historyRecords.length > 0;
    dom.historyClear.disabled = historyRecords.length === 0;

    for (const record of historyRecords) {
      const item = createElement('li', 'history-item');
      const meta = createElement('div', 'history-item__meta');
      const badge = createElement(
        'span',
        `history-badge ${record.mode === 'encrypt' ? 'is-encrypt' : 'is-decrypt'}`,
        record.mode === 'encrypt' ? '加密' : '解密',
      );
      const algorithm = createElement('span', 'history-item__algorithm', record.algorithm);
      algorithm.title = record.algorithm;
      const time = createElement('span', 'history-item__time', record.time);

      meta.append(badge, algorithm, time);

      const inputRow = createElement('div', 'history-item__row');
      inputRow.append(createElement('span', '', '输入'));
      const inputText = createElement('span', 'history-item__text', record.input);
      inputText.title = record.input;
      inputRow.append(inputText);

      const outputRow = createElement('div', 'history-item__row');
      outputRow.append(createElement('span', '', '输出'));
      const outputText = createElement('span', 'history-item__text is-output', record.output);
      outputText.title = record.output;
      outputRow.append(outputText);

      if (record.algorithmId === 'braille') {
        if (record.mode === 'encrypt') {
          outputText.classList.add('is-braille-sm');
        } else {
          inputText.classList.add('is-braille-sm');
        }
      }

      item.append(meta, inputRow, outputRow);
      dom.historyList.append(item);
    }
  }

  /**
   * 清空历史记录。
   */
  function clearHistory() {
    cancelHistoryRecord();
    historyRecords = [];
    renderHistory();
  }

  /* ---------------------------------------------------------
     八、复制到剪贴板（含降级方案）
     --------------------------------------------------------- */

  /**
   * 使用隐藏的 textarea + execCommand 作为旧浏览器或权限受限时的降级方案。
   * @param {string} text 待复制文本
   * @returns {boolean} 是否复制成功
   */
  function copyWithFallback(text) {
    const helper = document.createElement('textarea');
    helper.value = text;
    helper.setAttribute('readonly', '');
    helper.style.position = 'fixed';
    helper.style.top = '-9999px';
    helper.style.left = '-9999px';
    helper.style.opacity = '0';
    document.body.appendChild(helper);

    const previousFocus = document.activeElement;
    let succeeded = false;

    try {
      helper.focus();
      helper.select();
      helper.setSelectionRange(0, helper.value.length);
      succeeded = document.execCommand('copy');
    } catch (error) {
      succeeded = false;
    } finally {
      helper.remove();

      if (previousFocus && typeof previousFocus.focus === 'function') {
        try {
          previousFocus.focus({ preventScroll: true });
        } catch (error) {
          // 焦点恢复失败不影响复制结果
        }
      }
    }

    return succeeded;
  }

  /**
   * 复制结果：优先 Clipboard API，失败后自动降级。
   */
  async function copyResult() {
    const text = dom.outputText.value;

    if (!text) {
      return;
    }

    let copied = false;

    if (window.isSecureContext && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      try {
        await navigator.clipboard.writeText(text);
        copied = true;
      } catch (error) {
        copied = false;
      }
    }

    if (!copied) {
      copied = copyWithFallback(text);
    }

    if (copied) {
      clearError();
      showCopiedState();
    } else {
      resetCopyButton();
      showError('复制失败，请手动选中结果后复制', null);
    }
  }

  /* ---------------------------------------------------------
     九、路由、加密/解密模式与说明页
     --------------------------------------------------------- */

  /**
   * 切换到加密或解密模式，更新该子栏目的标题、标签与提示。
   * @param {'encrypt'|'decrypt'} mode
   */
  function setToolMode(mode) {
    toolMode = mode;
    const isEncrypt = mode === 'encrypt';

    dom.toolTitle.textContent = isEncrypt ? '加密' : '解密';
    dom.toolDescription.textContent = isEncrypt
      ? '输入即实时加密，明文与密文并排对照。'
      : '输入即实时解密，密文与明文并排对照。';
    dom.inputLabel.textContent = isEncrypt ? '输入明文' : '输入密文';
    dom.inputText.placeholder = isEncrypt
      ? '在此输入要加密的明文…'
      : '在此输入要解密的密文…';
    dom.outputLabel.textContent = isEncrypt ? '密文结果' : '明文结果';
    dom.outputText.placeholder = isEncrypt
      ? '加密结果将显示在这里'
      : '解密结果将显示在这里';
    cancelHistoryRecord();
    updateBrailleTextStyles();
    updateMatrixPanel();
    scheduleLiveTransform();
  }

  /**
   * 从 hash 解析当前栏目。
   * @returns {'home'|'encrypt'|'decrypt'|'guide'}
   */
  function getRoute() {
    const raw = window.location.hash.replace(/^#\/?/, '').replace(/\/+$/, '').trim();
    return Object.prototype.hasOwnProperty.call(ROUTES, raw) ? raw : 'home';
  }

  /**
   * 显示当前栏目、同步导航高亮与浏览器标题。
   * @param {string} [routeOverride] 直接指定栏目，供链接点击时立即切换
   */
  function renderRoute(routeOverride) {
    const route = typeof routeOverride === 'string'
      && Object.prototype.hasOwnProperty.call(ROUTES, routeOverride)
      ? routeOverride
      : getRoute();
    const isTool = route === 'encrypt' || route === 'decrypt';

    dom.views.forEach((view) => {
      const viewName = view.dataset.view;
      view.hidden = !(viewName === route || (viewName === 'tool' && isTool));
    });

    dom.navLinks.forEach((link) => {
      const active = link.dataset.route === route;
      link.classList.toggle('is-active', active);

      if (active) {
        link.setAttribute('aria-current', 'page');
      } else {
        link.removeAttribute('aria-current');
      }
    });

    if (isTool && toolMode !== route) {
      setToolMode(route);
      clearError();
      clearOutput();
    }

    if (isTool) {
      updateBrailleTextStyles();
      updateMatrixPanel();
      scheduleLiveTransform();
    } else {
      if (liveTimer !== null) {
        clearTimeout(liveTimer);
        liveTimer = null;
      }
      cancelHistoryRecord();
    }

    if (route === 'game') {
      GameModule.onEnter();
    }

    document.title = ROUTES[route].documentTitle;

    if (currentRoute !== null) {
      window.scrollTo({ top: 0, behavior: 'auto' });

      if (dom.siteMain && typeof dom.siteMain.focus === 'function') {
        dom.siteMain.focus({ preventScroll: true });
      }
    }

    currentRoute = route;
  }

  /**
   * 清空一个容器的所有子节点（兼容不支持 replaceChildren 的浏览器）。
   * @param {HTMLElement} element
   */
  function clearElement(element) {
    while (element.firstChild) {
      element.removeChild(element.firstChild);
    }
  }

  /**
   * 创建带类名和文本的元素，避免使用 innerHTML。
   * @param {string} tagName
   * @param {string} className
   * @param {string} [text]
   * @returns {HTMLElement}
   */
  function createElement(tagName, className, text) {
    const element = document.createElement(tagName);

    if (className) {
      element.className = className;
    }

    if (text !== undefined) {
      element.textContent = text;
    }

    return element;
  }

  /**
   * 统一搜索文本：转小写并去掉空白。
   * @param {string} value
   * @returns {string}
   */
  function normalizeGuideSearch(value) {
    return String(value).trim().toLocaleLowerCase().replace(/\s+/g, '');
  }

  /**
   * 根据搜索框内容筛选算法。
   * @returns {Array}
   */
  function filterGuideEntries() {
    const query = normalizeGuideSearch(dom.guideSearch.value);
    const byCategory = activeCategory === 'all'
      ? GUIDE_ENTRIES
      : GUIDE_ENTRIES.filter((entry) => entry.category === activeCategory);

    if (!query) {
      return byCategory;
    }

    return byCategory.filter((entry) => {
      const haystack = normalizeGuideSearch([
        entry.name,
        entry.english,
        entry.type,
        CATEGORY_LABELS[entry.category] || '',
        ...entry.aliases,
      ].join(' '));
      return haystack.includes(query);
    });
  }

  /**
   * 按 id 取说明数据。
   * @param {string} id
   * @returns {object|null}
   */
  function getGuideEntry(id) {
    return GUIDE_ENTRIES.find((entry) => entry.id === id) || null;
  }

  /**
   * 创建一个说明页算法列表项。
   * @param {object} entry
   * @returns {HTMLLIElement}
   */
  function createGuideListItem(entry) {
    const item = document.createElement('li');
    const button = createElement('button', 'guide-item');
    const secondary = entry.english !== entry.name ? entry.english : entry.type;

    button.type = 'button';
    button.dataset.guideId = entry.id;
    button.setAttribute('aria-controls', 'guide-detail');
    button.setAttribute('aria-pressed', 'false');
    button.append(createElement('span', 'guide-item__name', entry.name));
    button.append(createElement('span', 'guide-item__english', secondary));
    item.append(button);

    return item;
  }

  /**
   * 同步列表按钮的选中状态。
   */
  function updateGuideSelection() {
    const buttons = dom.guideList.querySelectorAll('button[data-guide-id]');

    buttons.forEach((button) => {
      const active = button.dataset.guideId === selectedGuideId;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    });
  }

  /**
   * 渲染算法列表。
   * @param {Array} entries
   */
  function renderGuideList(entries) {
    clearElement(dom.guideList);

    for (const entry of entries) {
      dom.guideList.append(createGuideListItem(entry));
    }

    updateGuideSelection();
  }

  /**
   * 创建 Polybius 5×5 完整方阵表。
   * @param {string[][]} rows
   * @returns {HTMLElement}
   */
  function createPolybiusTable(rows) {
    const section = createElement('section', 'guide-table');
    section.append(createElement('h3', '', '完整 5×5 方阵'));

    const table = createElement('table', 'polybius-table');
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    headRow.append(createElement('th', 'polybius-corner', ''));
    ['1', '2', '3', '4', '5'].forEach((col) => {
      const th = createElement('th', '', col);
      th.scope = 'col';
      headRow.append(th);
    });
    thead.append(headRow);

    const tbody = document.createElement('tbody');
    rows.forEach((row, rowIndex) => {
      const tr = document.createElement('tr');
      const rowHead = createElement('th', '', String(rowIndex + 1));
      rowHead.scope = 'row';
      tr.append(rowHead);
      row.forEach((char) => {
        tr.append(createElement('td', '', char === 'I' ? 'I/J' : char));
      });
      tbody.append(tr);
    });

    table.append(thead, tbody);
    section.append(table);

    return section;
  }

  /**
   * 创建摩斯密码完整字符对照表。
   * @param {Array<[string, string]>} items
   * @returns {HTMLElement}
   */
  function createMorseTable(items) {
    const section = createElement('section', 'guide-table');
    section.append(createElement('h3', '', `完整字符对照表（${items.length} 个字符）`));

    const table = createElement('table', 'morse-table');
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');

    ['字符', '电码', '字符', '电码'].forEach((label) => {
      const th = createElement('th', '', label);
      th.scope = 'col';
      headRow.append(th);
    });

    thead.append(headRow);
    const tbody = document.createElement('tbody');

    for (let index = 0; index < items.length; index += 2) {
      const tr = document.createElement('tr');

      for (let offset = 0; offset < 2; offset += 1) {
        const item = items[index + offset];

        if (item) {
          tr.append(createElement('td', '', item[0]));
          const codeCell = document.createElement('td');
          codeCell.append(createElement('code', '', item[1]));
          tr.append(codeCell);
        } else {
          tr.append(createElement('td', '', ''));
          tr.append(createElement('td', '', ''));
        }
      }

      tbody.append(tr);
    }

    table.append(thead, tbody);
    section.append(table);

    return section;
  }

  /**
   * 通用两列对字符表，每行放两组“字符 / 编码”。
   * @param {string} title
   * @param {Array<[string, string]>} items
   * @returns {HTMLElement}
   */
  function createPairTable(title, items, options = {}) {
    const section = createElement('section', options.braille ? 'guide-table braille-table' : 'guide-table');
    section.append(createElement('h3', '', title));

    const table = createElement('table', 'morse-table');
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');

    ['字符', '编码', '字符', '编码'].forEach((label) => {
      const th = createElement('th', '', label);
      th.scope = 'col';
      headRow.append(th);
    });

    thead.append(headRow);
    const tbody = document.createElement('tbody');

    for (let index = 0; index < items.length; index += 2) {
      const tr = document.createElement('tr');

      for (let offset = 0; offset < 2; offset += 1) {
        const item = items[index + offset];

        if (item) {
          tr.append(createElement('td', '', item[0]));
          const codeCell = document.createElement('td');
          codeCell.append(createElement('code', '', item[1]));
          tr.append(codeCell);
        } else {
          tr.append(createElement('td', '', ''));
          tr.append(createElement('td', '', ''));
        }
      }

      tbody.append(tr);
    }

    table.append(thead, tbody);
    section.append(table);

    return section;
  }

  function createAdfgvxTable(keyword) {
    const section = createElement('section', 'guide-table');
    section.append(createElement('h3', '', `完整 6×6 方阵（关键词 ${keyword}）`));

    const rows = squareToRowsOf(buildAdfgvxSquare(keyword), 6);
    const table = createElement('table', 'adfgvx-table');
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');
    const corner = createElement('th', 'matrix-corner', '');
    corner.scope = 'col';
    headRow.append(corner);

    for (const label of ADFGVX_LABELS) {
      const th = createElement('th', '', label);
      th.scope = 'col';
      headRow.append(th);
    }

    thead.append(headRow);
    const tbody = document.createElement('tbody');

    rows.forEach((row, rowIndex) => {
      const tr = document.createElement('tr');
      const rowHead = createElement('th', '', ADFGVX_LABELS[rowIndex]);
      rowHead.scope = 'row';
      tr.append(rowHead);
      row.forEach((char) => tr.append(createElement('td', '', char)));
      tbody.append(tr);
    });

    table.append(thead, tbody);
    section.append(table);

    return section;
  }

  function createPigpenTable(groups) {
    const section = createElement('section', 'guide-table');
    section.append(createElement('h3', '', '完整 26 字母格位对照表'));

    const wrapper = createElement('div', 'pigpen-groups');

    for (const group of groups) {
      const card = createElement('div', 'pigpen-group');
      card.append(createElement('h4', 'pigpen-group__title', group.label));

      const grid = createElement('div', 'pigpen-grid');
      grid.style.gridTemplateColumns = `repeat(${group.columns}, minmax(0, 1fr))`;

      for (const [letter, code] of group.cells) {
        const cell = createElement('div', 'pigpen-cell');
        cell.append(createElement('span', 'pigpen-cell__letter', letter));
        cell.append(createElement('span', 'pigpen-cell__code', code));
        grid.append(cell);
      }

      card.append(grid);
      wrapper.append(card);
    }

    section.append(wrapper);
    return section;
  }

  function createSemaphoreTable() {
    const section = createElement('section', 'guide-table');
    section.append(createElement('h3', '', '完整 26 字母旗语对照表'));

    const legend = createElement('div', 'semaphore-legend');
    for (const [code, label] of SEMAPHORE_LEGEND) {
      legend.append(createElement('span', 'semaphore-legend__item', `${code}=${label}`));
    }
    section.append(legend);

    const table = createElement('table', 'semaphore-table');
    const thead = document.createElement('thead');
    const headRow = document.createElement('tr');

    ['字母', '左臂', '右臂', '位置码'].forEach((label) => {
      const th = createElement('th', '', label);
      th.scope = 'col';
      headRow.append(th);
    });

    thead.append(headRow);
    const tbody = document.createElement('tbody');

    for (const row of SEMAPHORE_TABLE) {
      const tr = document.createElement('tr');
      row.forEach((value) => tr.append(createElement('td', '', value)));
      tbody.append(tr);
    }

    table.append(thead, tbody);
    section.append(table);

    return section;
  }

  /**
   * 创建说明详情内容。
   * @param {object} entry
   * @returns {HTMLElement}
   */
  function createGuideDetail(entry) {
    const article = createElement('article', 'guide-detail edge-glow');
    const header = createElement('header', 'guide-detail__header');

    header.append(createElement('p', 'guide-kicker', '算法详情'));

    const title = createElement('h2', 'guide-detail__title');
    title.id = 'guide-detail-title';
    title.append(createElement('span', 'guide-detail__name', entry.name));

    if (entry.english !== entry.name) {
      title.append(createElement('span', 'guide-detail__english', entry.english));
    }

    header.append(title);
    header.append(createElement('p', 'guide-summary', entry.summary));

    const badges = createElement('div', 'guide-badges');
    badges.append(createElement('span', 'guide-category-badge', CATEGORY_LABELS[entry.category] || ''));
    badges.append(createElement('span', 'guide-type', entry.type));
    header.append(badges);

    const facts = createElement('dl', 'guide-facts');

    const addFact = (label, value, withCode = false) => {
      const row = createElement('div', 'guide-fact');
      const term = createElement('dt', '', label);
      const description = createElement('dd', withCode ? 'guide-example' : '');

      if (withCode) {
        const code = createElement('code', entry.id === 'braille' ? 'braille-example' : '', value);
        description.append(code);
      } else {
        description.textContent = value;
      }

      row.append(term, description);
      facts.append(row);
    };

    addFact('密钥', entry.key);
    addFact('加密', entry.encrypt);
    addFact('解密', entry.decrypt);
    addFact('示例', entry.example, true);

    const notes = createElement('div', 'guide-notes');
    notes.append(createElement('h3', '', '注意'));

    const noteList = document.createElement('ul');

    for (const note of entry.notes) {
      noteList.append(createElement('li', '', note));
    }

    notes.append(noteList);
    article.append(header, facts);

    if (entry.matrix) {
      const config = buildMatrixConfig(entry.matrix.cipher, entry.matrix);

      if (config) {
        const panel = createElement('section', 'matrix-panel');
        panel.setAttribute('aria-label', '示例加密方阵');
        fillMatrixPanel(panel, config, '示例加密方阵', 'h3');
        article.append(panel);
      }
    }

    if (entry.adfgvxKey) {
      article.append(createAdfgvxTable(entry.adfgvxKey));
    }

    if (entry.pigpenGroups) {
      article.append(createPigpenTable(entry.pigpenGroups));
    }

    if (entry.baconTable) {
      article.append(createPairTable('完整 26 字母对照表', entry.baconTable));
    }

    if (entry.brailleTable) {
      article.append(createPairTable('完整盲文对照表', entry.brailleTable, { braille: true }));
    }

    if (entry.semaphoreTable) {
      article.append(createSemaphoreTable());
    }

    if (entry.morseTable) {
      article.append(createMorseTable(entry.morseTable));
    }

    article.append(notes);

    return article;
  }

  /**
   * 渲染说明详情或空状态。
   * @param {object|null} entry
   * @param {string} query
   */
  function renderGuideDetail(entry, query) {
    clearElement(dom.guideDetail);

    if (!entry) {
      const empty = createElement('div', 'guide-empty');
      empty.append(createElement('h2', '', '没有找到匹配的算法'));

      if (query) {
        const message = createElement('p', '');
        message.append(document.createTextNode(`没有与「${query}」匹配的算法。试试`));

        ['凯撒密码', 'Vigenère', 'A1Z26'].forEach((name, index) => {
          message.append(createElement('span', 'no-wrap', `「${name}」`));

          if (index < 2) {
            message.append(document.createTextNode('、'));
          }
        });

        message.append(document.createTextNode('。'));
        empty.append(message);
      } else {
        empty.append(createElement('p', '', '没有可显示的算法。'));
      }

      dom.guideDetail.append(empty);
      return;
    }

    dom.guideDetail.append(createGuideDetail(entry));
  }

  /**
   * 根据搜索框与当前选中项，重新渲染说明页。
   */
  function renderGuide() {
    const entries = filterGuideEntries();
    const query = dom.guideSearch.value.trim();
    const hasQuery = normalizeGuideSearch(query) !== '';
    const scope = CATEGORY_LABELS[activeCategory] || '全部';

    if (entries.length === 0) {
      selectedGuideId = null;
      dom.guideStatus.textContent = '未找到匹配算法';
      renderGuideList([]);
      renderGuideDetail(null, query);
      return;
    }

    if (!entries.some((entry) => entry.id === selectedGuideId)) {
      selectedGuideId = entries.some((entry) => entry.id === 'caesar')
        ? 'caesar'
        : entries[0].id;
    }

    dom.guideStatus.textContent = hasQuery
      ? `${scope} · 找到 ${entries.length} 个算法`
      : `${scope} · 共 ${entries.length} 个算法`;

    renderGuideList(entries);
    renderGuideDetail(getGuideEntry(selectedGuideId), query);
  }

  /**
   * 同步分类按钮与说明文字。
   */
  function updateCategoryFilter() {
    dom.guideCategoryButtons.forEach((button) => {
      const active = button.dataset.category === activeCategory;
      button.classList.toggle('is-active', active);
      button.setAttribute('aria-pressed', String(active));
    });

    dom.guideCategoryNote.textContent = CATEGORY_NOTES[activeCategory] || CATEGORY_NOTES.all;
  }

  /**
   * 点击分类按钮。
   * @param {MouseEvent} event
   */
  function handleCategoryClick(event) {
    if (!(event.target instanceof Element)) {
      return;
    }

    const button = event.target.closest('button[data-category]');

    if (!button) {
      return;
    }

    activeCategory = button.dataset.category;
    updateCategoryFilter();
    renderGuide();
  }

  /**
   * 点击算法列表项：切换详情，不重建列表，保留键盘焦点。
   * @param {MouseEvent} event
   */
  function handleGuideListClick(event) {
    if (!(event.target instanceof Element)) {
      return;
    }

    const button = event.target.closest('button[data-guide-id]');

    if (!button) {
      return;
    }

    selectedGuideId = button.dataset.guideId;
    updateGuideSelection();
    renderGuideDetail(getGuideEntry(selectedGuideId), dom.guideSearch.value.trim());

    if (
      window.matchMedia('(max-width: 900px)').matches
      && typeof dom.guideDetail.scrollIntoView === 'function'
    ) {
      const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      dom.guideDetail.scrollIntoView({
        behavior: reduceMotion ? 'auto' : 'smooth',
        block: 'start',
      });
    }
  }

  /**
   * 点击任意 #/ 链接时立即切换栏目。
   * 这样即使某些预览环境不触发 hashchange，导航也能工作。
   * @param {MouseEvent} event
   */
  function handleRouteLinkClick(event) {
    if (
      event.defaultPrevented
      || event.button !== 0
      || event.metaKey
      || event.ctrlKey
      || event.shiftKey
      || event.altKey
    ) {
      return;
    }

    if (!(event.target instanceof Element)) {
      return;
    }

    const link = event.target.closest('a[href^="#/"]');

    if (!link) {
      return;
    }

    const route = link.getAttribute('href').replace(/^#\/?/, '').replace(/\/+$/, '');

    if (!Object.prototype.hasOwnProperty.call(ROUTES, route)) {
      return;
    }

    event.preventDefault();

    if (route !== 'game' && GameModule.isChallengeActive()) {
      GameModule.requestLeave(() => navigateToRoute(route));
      return;
    }

    navigateToRoute(route);

    if (route === 'encrypt' && link.dataset.algorithm) {
      const algorithmSelect = document.getElementById('algorithm');
      const algorithmId = link.dataset.algorithm;
      const hasOption = algorithmSelect
        && Array.from(algorithmSelect.options).some((option) => option.value === algorithmId);

      if (hasOption) {
        algorithmSelect.value = algorithmId;
        algorithmSelect.dispatchEvent(new Event('change', { bubbles: true }));
      }
    }
  }

  /**
   * 执行栏目切换：立即渲染，并尽力同步 hash。
   * @param {string} route
   */
  function navigateToRoute(route) {
    renderRoute(route);

    try {
      if (window.location.hash !== `#/${route}`) {
        window.location.hash = `#/${route}`;
      }
    } catch (error) {
      // 某些预览沙箱会阻止修改 hash；此时已经完成本地渲染。
    }
  }

  /* ---------------------------------------------------------
     十、事件绑定与初始化
     --------------------------------------------------------- */

  /**
   * 切换算法：更新密钥区显隐，清空上一次的错误与结果，保留输入文本和密钥。
   */
  function handleAlgorithmChange() {
    updateKeyVisibility();
    updateBrailleTextStyles();
    clearError();
    clearOutput();
    cancelHistoryRecord();
    updateMatrixPanel();
    scheduleLiveTransform();
  }

  function bindEvents() {
    dom.algorithm.addEventListener('change', handleAlgorithmChange);

    [dom.inputText, dom.caesarKey, dom.affineA, dom.affineB, dom.keyword, dom.keyword1, dom.keyword2, dom.railCount, dom.routeColumns].forEach((field) => {
      field.addEventListener('input', () => {
        clearError();
        cancelHistoryRecord();
        scheduleLiveTransform();
      });
    });

    [dom.keyword, dom.keyword1, dom.keyword2].forEach((field) => {
      field.addEventListener('input', updateMatrixPanel);
    });

    dom.copyButton.addEventListener('click', copyResult);
    dom.outputText.addEventListener('animationend', handleResultAnimationEnd);
    dom.historyClear.addEventListener('click', clearHistory);
    dom.clearInput.addEventListener('click', clearInputText);

    dom.guideSearch.addEventListener('input', renderGuide);
    dom.guideCategories.addEventListener('click', handleCategoryClick);
    dom.guideList.addEventListener('click', handleGuideListClick);

    document.addEventListener('click', handleRouteLinkClick);
    window.addEventListener('hashchange', renderRoute);
  }

  /**
   * 初始化背景星空粒子。只在留白背景绘制，不影响页面交互。
   */
  function initStarfield() {
    const canvas = dom.starfield;

    if (!canvas || typeof canvas.getContext !== 'function') {
      return;
    }

    const context = canvas.getContext('2d');

    if (!context) {
      return;
    }

    const reduceMotion = typeof window.matchMedia === 'function'
      && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let stars = [];
    let width = 0;
    let height = 0;
    let frameId = null;
    let resizeTimer = null;

    const random = (min, max) => min + Math.random() * (max - min);

    function buildStars() {
      const count = Math.min(110, Math.max(36, Math.round((width * height) / 18000)));
      stars = Array.from({ length: count }, () => ({
        x: random(0, width),
        y: random(0, height),
        radius: random(0.45, 1.55),
        alpha: random(0.22, 0.82),
        speed: random(0.018, 0.065),
        twinkle: random(0.00035, 0.0011),
        phase: random(0, Math.PI * 2),
        warm: Math.random() < 0.14,
      }));
    }

    function draw(time) {
      context.clearRect(0, 0, width, height);

      for (const star of stars) {
        if (!reduceMotion) {
          star.y -= star.speed;

          if (star.y < -2) {
            star.y = height + 2;
            star.x = random(0, width);
          }
        }

        const twinkle = Math.sin(time * star.twinkle + star.phase) * 0.18;
        const alpha = Math.max(0.06, Math.min(0.9, star.alpha + twinkle));
        context.beginPath();
        context.fillStyle = star.warm
          ? `rgba(255, 236, 205, ${alpha})`
          : `rgba(190, 217, 255, ${alpha})`;
        context.arc(star.x, star.y, star.radius, 0, Math.PI * 2);
        context.fill();
      }
    }

    function animate(time) {
      draw(time);
      frameId = window.requestAnimationFrame(animate);
    }

    function resize() {
      const ratio = Math.min(window.devicePixelRatio || 1, 2);
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = Math.round(width * ratio);
      canvas.height = Math.round(height * ratio);
      canvas.style.width = `${width}px`;
      canvas.style.height = `${height}px`;
      context.setTransform(ratio, 0, 0, ratio, 0, 0);
      buildStars();

      if (reduceMotion) {
        draw(0);
      }
    }

    resize();

    if (!reduceMotion) {
      frameId = window.requestAnimationFrame(animate);
    }

    window.addEventListener('resize', () => {
      if (resizeTimer !== null) {
        clearTimeout(resizeTimer);
      }

      resizeTimer = setTimeout(() => {
        resizeTimer = null;
        resize();
      }, 120);
    });

    document.addEventListener('visibilitychange', () => {
      if (reduceMotion) {
        return;
      }

      if (document.hidden && frameId !== null) {
        window.cancelAnimationFrame(frameId);
        frameId = null;
      } else if (!document.hidden && frameId === null) {
        frameId = window.requestAnimationFrame(animate);
      }
    });
  }

  /**
   * V2.3 破译游戏模块：十题挑战、独立结算与离场守护。
   * 只负责出题、展示和判定，加解密全部调用现有 CIPHERS。
   */
  const GameModule = (() => {
    const DIFFICULTIES = {
      easy: {
        label: '简单',
        hint: '无密钥算法（本难度禁用提示）',
        algorithms: [
          'a1z26', 'ascii', 'atbash', 'rot13',
          'bacon', 'braille', 'morse', 'pigpen', 'polybius',
        ],
        maxHints: 0,
      },
      medium: {
        label: '中等',
        hint: '单表替换（密钥未知）',
        algorithms: ['affine', 'caesar'],
        maxHints: 2,
      },
      hard: {
        label: '困难',
        hint: '多表 / 矩阵 / 其他密钥算法（密钥未知）',
        algorithms: ['adfgvx', 'beaufort', 'foursquare', 'playfair', 'twosquare', 'vigenere'],
        maxHints: 2,
      },
    };

    const WORD_BANK = [
      'CRYPTO',
      'HELLO WORLD',
      'SECRET',
      'CYBER',
      'FIREWALL',
      'PASSWORD',
      'CIPHER',
      'ENIGMA',
      'MYSTERY',
      'CODE',
      'TREASURE',
      'SHADOW',
      'PUZZLE',
      'NETWORK',
      'SIGNAL',
      'HIDDEN',
      'KEYBOARD',
      'GALAXY',
      'ORBIT',
      'DETECTIVE',
    ];

    const KEYWORD_POOL = [
      'LEMON',
      'CIPHER',
      'SECRET',
      'GALAXY',
      'ORBIT',
      'SHADOW',
      'PUZZLE',
      'SIGNAL',
      'TREASURE',
      'DETECTIVE',
    ];

    const AFFINE_A_VALUES = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
    const QUESTIONS_PER_CHALLENGE = 10;
    const HIGH_SCORE_KEY = 'cipher-game-high-scores-v1';
    const LOBBY_STORY_INTRO = '我们截获了一段密信，但在破译时出现了问题，其中的单词尚不明晰……';
    const LOBBY_STORY_THANKS = '感谢您的协助，侦探。';
    const STORY_TYPE_DELAY = 34;
    const STORY_PAUSE_DELAY = 1000;
    const SCRATCH_DEFAULT_ALGORITHM = {
      easy: 'ascii',
      medium: 'caesar',
      hard: 'vigenere',
    };

    const state = {
      mode: 'idle',
      difficulty: 'easy',
      startDifficulty: 'easy',
      challenge: null,
      puzzle: null,
      ended: false,
      hintStage: 0,
      lastAlgorithmId: null,
      leaveCallback: null,
      timerId: null,
      autoNextId: null,
      comboHideId: null,
      storyTypeId: null,
      startPauseId: null,
      transitioning: false,
    };

    let audioContext = null;

    let highScores = {
      easy: null,
      medium: null,
      hard: null,
    };

    const randomItem = (items) => items[Math.floor(Math.random() * items.length)];
    const normalizeAnswer = (value) => String(value).toUpperCase().replace(/[^A-Z]/g, '');

    function shuffle(items) {
      const copy = items.slice();

      for (let index = copy.length - 1; index > 0; index -= 1) {
        const swapIndex = Math.floor(Math.random() * (index + 1));
        [copy[index], copy[swapIndex]] = [copy[swapIndex], copy[index]];
      }

      return copy;
    }

    function formatDuration(milliseconds) {
      const totalSeconds = Math.max(0, Math.floor(milliseconds / 1000));
      const minutes = Math.floor(totalSeconds / 60);
      const seconds = totalSeconds % 60;
      return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
    }

    function loadHighScores() {
      try {
        const raw = window.localStorage.getItem(HIGH_SCORE_KEY);

        if (!raw) {
          return;
        }

        const parsed = JSON.parse(raw);

        for (const difficulty of ['easy', 'medium', 'hard']) {
          const record = parsed && parsed[difficulty];

          if (record
            && Number.isFinite(record.score)
            && Number.isFinite(record.timeMs)
            && record.score >= 0
            && record.timeMs >= 0) {
            highScores[difficulty] = {
              score: Math.round(record.score),
              timeMs: Math.round(record.timeMs),
            };
          }
        }
      } catch (error) {
        // localStorage 不可用时只保留当前会话的内存纪录。
      }
    }

    function saveHighScores() {
      try {
        window.localStorage.setItem(HIGH_SCORE_KEY, JSON.stringify(highScores));
      } catch (error) {
        // 隐私模式或沙箱禁止存储时忽略。
      }
    }

    function renderHighScores() {
      for (const difficulty of ['easy', 'medium', 'hard']) {
        const element = dom.gameRecords[difficulty];

        if (!element) {
          continue;
        }

        const record = highScores[difficulty];
        element.textContent = record
          ? `最高分：${record.score} 分 · ${formatDuration(record.timeMs)}`
          : '最高分：暂无纪录';
      }
    }

    function updateHighScore(difficulty, score, timeMs) {
      const current = highScores[difficulty];

      if (current
        && (score < current.score || (score === current.score && timeMs >= current.timeMs))) {
        return false;
      }

      highScores[difficulty] = { score, timeMs };
      saveHighScores();
      renderHighScores();
      return true;
    }

    function getElapsedMs() {
      const challenge = state.challenge;

      if (!challenge) {
        return 0;
      }

      return (challenge.elapsedMs || 0) + (challenge.startedAt ? Date.now() - challenge.startedAt : 0);
    }

    function updateTimer() {
      dom.gameTimer.textContent = `用时 ${formatDuration(getElapsedMs())}`;
    }

    function clearTimerInterval() {
      if (state.timerId !== null) {
        window.clearInterval(state.timerId);
        state.timerId = null;
      }
    }

    function startTimer() {
      clearTimerInterval();

      if (!state.challenge) {
        return;
      }

      state.challenge.elapsedMs = 0;
      state.challenge.startedAt = Date.now();
      updateTimer();
      state.timerId = window.setInterval(updateTimer, 1000);
    }

    function pauseTimer() {
      const challenge = state.challenge;

      if (challenge && challenge.startedAt) {
        challenge.elapsedMs = (challenge.elapsedMs || 0) + (Date.now() - challenge.startedAt);
        challenge.startedAt = 0;
      }

      clearTimerInterval();
      updateTimer();
    }

    function resumeTimer() {
      const challenge = state.challenge;

      if (!challenge || state.mode !== 'challenge' || state.ended || challenge.startedAt) {
        return;
      }

      challenge.startedAt = Date.now();
      updateTimer();
      state.timerId = window.setInterval(updateTimer, 1000);
    }

    function stopTimer() {
      pauseTimer();
    }

    function getAudioContext() {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;

      if (!AudioContextClass) {
        return null;
      }

      if (!audioContext) {
        try {
          audioContext = new AudioContextClass();
        } catch (error) {
          return null;
        }
      }

      if (audioContext.state === 'suspended') {
        audioContext.resume().catch(() => {});
      }

      return audioContext;
    }

    function playTone(frequency, start, duration, type, volume) {
      const context = getAudioContext();

      if (!context) {
        return;
      }

      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.type = type;
      oscillator.frequency.setValueAtTime(frequency, start);
      gain.gain.setValueAtTime(0.0001, start);
      gain.gain.exponentialRampToValueAtTime(volume, start + 0.015);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + duration);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start(start);
      oscillator.stop(start + duration + 0.02);
    }

    function playCorrectSound() {
      const context = getAudioContext();

      if (!context) {
        return;
      }

      const now = context.currentTime;
      [523.25, 659.25, 783.99].forEach((frequency, index) => {
        playTone(frequency, now + index * 0.025, 0.24, 'sine', 0.045);
      });
    }

    function playWrongSound() {
      const context = getAudioContext();

      if (!context) {
        return;
      }

      const now = context.currentTime;
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.type = 'sawtooth';
      oscillator.frequency.setValueAtTime(190, now);
      oscillator.frequency.exponentialRampToValueAtTime(105, now + 0.24);
      gain.gain.setValueAtTime(0.0001, now);
      gain.gain.exponentialRampToValueAtTime(0.045, now + 0.015);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + 0.24);
      oscillator.connect(gain);
      gain.connect(context.destination);
      oscillator.start(now);
      oscillator.stop(now + 0.26);
    }

    function playHintSound() {
      const context = getAudioContext();

      if (!context) {
        return;
      }

      const now = context.currentTime;
      playTone(880, now, 0.12, 'triangle', 0.035);
      playTone(1320, now + 0.07, 0.12, 'sine', 0.025);
    }

    function cancelAutoNext() {
      if (state.autoNextId !== null) {
        window.clearTimeout(state.autoNextId);
        state.autoNextId = null;
      }
    }

    function scheduleAutoNext() {
      cancelAutoNext();
      state.autoNextId = window.setTimeout(() => {
        state.autoNextId = null;

        if (state.mode === 'challenge'
          && state.ended
          && state.puzzle
          && state.puzzle.result === 'correct') {
          nextPuzzle();
        }
      }, 1500);
    }

    function showCombo(text) {
      dom.comboPop.textContent = text;
      dom.comboPop.hidden = false;
      dom.comboPop.classList.remove('is-visible');
      void dom.comboPop.offsetWidth;
      dom.comboPop.classList.add('is-visible');

      if (state.comboHideId !== null) {
        window.clearTimeout(state.comboHideId);
      }

      state.comboHideId = window.setTimeout(() => {
        dom.comboPop.hidden = true;
        dom.comboPop.classList.remove('is-visible');
        state.comboHideId = null;
      }, 1400);
    }

    function clearTransientEffects() {
      dom.gameAnswer.classList.remove('is-correct-flash', 'is-shaking');
      dom.gameCipher.classList.remove('is-correct-flash');
    }

    function flashCorrect() {
      dom.gameAnswer.classList.remove('is-correct-flash');
      dom.gameCipher.classList.remove('is-correct-flash');
      void dom.gameAnswer.offsetWidth;
      dom.gameAnswer.classList.add('is-correct-flash');
      dom.gameCipher.classList.add('is-correct-flash');
    }

    function shakeAnswerInput() {
      dom.gameAnswer.classList.remove('is-shaking');
      void dom.gameAnswer.offsetWidth;
      dom.gameAnswer.classList.add('is-shaking');
      window.setTimeout(() => {
        dom.gameAnswer.classList.remove('is-shaking');
      }, 420);
    }

    function parseScratchKey(algorithmId) {
      const cipher = CIPHERS[algorithmId];
      const type = cipher ? cipher.keyType : 'none';
      const raw = dom.gameScratchKey.value.trim();

      if (type === 'none') {
        return null;
      }

      if (type === 'caesar') {
        const shift = Number(raw);

        if (!Number.isInteger(shift) || shift < 1 || shift > 25) {
          throw new RangeError('凯撒位移量需为 1–25 的整数');
        }

        return shift;
      }

      if (type === 'affine') {
        const parts = raw.split(/[,，\s]+/).filter(Boolean);

        if (parts.length !== 2) {
          throw new RangeError('仿射密钥格式为 a,b，例如 5,8');
        }

        return normalizeAffineKey({
          a: Number(parts[0]),
          b: Number(parts[1]),
        });
      }

      if (type === 'keyword') {
        return normalizeKeyword(raw);
      }

      if (type === 'two-keyword') {
        const parts = raw.split(/[,，/／\s]+/).filter(Boolean);

        if (parts.length !== 2) {
          throw new RangeError('请输入两个关键词，例如 HACK / SAFE');
        }

        return normalizeTwoKeywords({ key1: parts[0], key2: parts[1] });
      }

      throw new RangeError('当前算法暂不支持草稿试算');
    }

    function updateScratchKeyHelp() {
      const algorithmId = dom.gameScratchAlgorithm.value;
      const cipher = CIPHERS[algorithmId];
      const keyType = cipher ? cipher.keyType : 'none';
      const keyHelp = {
        none: '该算法无需密钥，直接试算即可。',
        caesar: '输入 1–25 的位移量。',
        affine: '格式：a,b，例如 5,8。',
        keyword: '输入英文关键词。',
        'two-keyword': '格式：关键词1 / 关键词2。',
      };

      dom.gameScratchKey.disabled = keyType === 'none';
      dom.gameScratchKey.placeholder = keyType === 'none' ? '无需密钥' : '输入你猜想的密钥';
      dom.gameScratchHint.textContent = keyHelp[keyType] || '当前算法暂不支持草稿试算。';
    }

    function handleScratchAlgorithmChange() {
      dom.gameScratchKey.value = '';
      dom.gameScratchResult.value = '';
      dom.gameScratchError.hidden = true;
      dom.gameScratchError.textContent = '';
      updateScratchKeyHelp();
    }

    function resetScratchpad(puzzle) {
      dom.gameScratch.open = false;
      dom.gameScratch.removeAttribute('open');
      dom.gameScratchResult.value = '';
      dom.gameScratchError.hidden = true;
      dom.gameScratchError.textContent = '';
      dom.gameScratchKey.value = '';

      const pool = DIFFICULTIES[state.difficulty].algorithms;
      const options = pool.map((algorithmId) => {
        const option = document.createElement('option');
        option.value = algorithmId;
        option.textContent = getAlgorithmName(algorithmId);
        return option;
      });

      dom.gameScratchAlgorithm.replaceChildren(...options);
      dom.gameScratchAlgorithm.value = SCRATCH_DEFAULT_ALGORITHM[state.difficulty] || pool[0];
      updateScratchKeyHelp();
    }

    function runScratchpad() {
      const puzzle = state.puzzle;

      if (!puzzle || state.mode !== 'challenge') {
        return;
      }

      dom.gameScratchError.hidden = true;
      dom.gameScratchError.textContent = '';
      dom.gameScratchResult.value = '';

      try {
        const algorithmId = dom.gameScratchAlgorithm.value;
        const cipher = CIPHERS[algorithmId];

        if (!cipher) {
          throw new RangeError('请选择当前难度中的算法');
        }

        const key = parseScratchKey(algorithmId);
        dom.gameScratchResult.value = cipher.decrypt(puzzle.ciphertext, key);
      } catch (error) {
        dom.gameScratchError.textContent = error instanceof Error ? error.message : '试算失败，请检查密钥。';
        dom.gameScratchError.hidden = false;
      }
    }

    function getAlgorithmName(algorithmId) {
      const entry = GUIDE_ENTRIES.find((item) => item.id === algorithmId);
      return entry ? entry.name : algorithmId;
    }

    function getKeyLabel(puzzle) {
      const key = puzzle.key;

      if (key === null || key === undefined) {
        return '无';
      }

      if (puzzle.algorithmId === 'caesar') {
        return `移动量为 ${key}`;
      }

      if (puzzle.algorithmId === 'affine') {
        return `a=${key.a}，b=${key.b}`;
      }

      if (puzzle.algorithmId === 'adfgvx'
        || puzzle.algorithmId === 'foursquare'
        || puzzle.algorithmId === 'twosquare') {
        return `${key.key1} / ${key.key2}`;
      }

      return String(key);
    }

    function getHintKeyLine(puzzle) {
      if (puzzle.key === null || puzzle.key === undefined) {
        return '密钥：无';
      }

      if (puzzle.algorithmId === 'caesar' || puzzle.algorithmId === 'affine') {
        return `密钥：${getKeyLabel(puzzle)}`;
      }

      return `密钥词：${getKeyLabel(puzzle)}`;
    }

    function formatAnswerDisplay(value) {
      return String(value).split(/\s+/).filter(Boolean).map((word) => {
        const lower = word.toLowerCase();
        return lower.charAt(0).toUpperCase() + lower.slice(1);
      }).join(' ');
    }

    function generateKey(algorithmId) {
      if (algorithmId === 'caesar') {
        return 1 + Math.floor(Math.random() * 25);
      }

      if (algorithmId === 'affine') {
        return {
          a: randomItem(AFFINE_A_VALUES),
          b: Math.floor(Math.random() * 26),
        };
      }

      if (algorithmId === 'adfgvx'
        || algorithmId === 'foursquare'
        || algorithmId === 'twosquare') {
        const key1 = randomItem(KEYWORD_POOL);
        let key2 = randomItem(KEYWORD_POOL);

        while (key2 === key1 && KEYWORD_POOL.length > 1) {
          key2 = randomItem(KEYWORD_POOL);
        }

        return { key1, key2 };
      }

      if (algorithmId === 'playfair'
        || algorithmId === 'beaufort'
        || algorithmId === 'vigenere') {
        return randomItem(KEYWORD_POOL);
      }

      return null;
    }

    function pickAlgorithm(pool) {
      let candidates = pool;

      if (state.lastAlgorithmId && pool.length > 1) {
        const filtered = pool.filter((id) => id !== state.lastAlgorithmId);

        if (filtered.length > 0) {
          candidates = filtered;
        }
      }

      const algorithmId = randomItem(candidates);
      state.lastAlgorithmId = algorithmId;
      return algorithmId;
    }

    function createPuzzle(plaintext) {
      const config = DIFFICULTIES[state.difficulty];
      const algorithmId = pickAlgorithm(config.algorithms);
      const key = generateKey(algorithmId);
      const cipher = CIPHERS[algorithmId];

      if (!cipher) {
        throw new Error(`找不到游戏算法：${algorithmId}`);
      }

      return {
        algorithmId,
        algorithmName: getAlgorithmName(algorithmId),
        plaintext,
        ciphertext: cipher.encrypt(plaintext, key),
        key,
        result: null,
        score: 0,
        hintsUsed: 0,
      };
    }

    function getQuestionScore(puzzle) {
      if (!puzzle || puzzle.result !== 'correct') {
        return 0;
      }

      const hints = puzzle.hintsUsed || 0;

      if (state.difficulty === 'hard') {
        if (hints >= 2) {
          return 7;
        }

        if (hints === 1) {
          return 9;
        }

        return 10;
      }

      return hints > 0 ? 8 : 10;
    }

    function clearLobbyTimers() {
      if (state.storyTypeId !== null) {
        window.clearTimeout(state.storyTypeId);
        state.storyTypeId = null;
      }

      if (state.startPauseId !== null) {
        window.clearTimeout(state.startPauseId);
        state.startPauseId = null;
      }
    }

    function typeLobbyStory(text, onDone) {
      clearLobbyTimers();

      const story = dom.gameLobbyStory;
      story.textContent = '';
      story.classList.remove('is-typing');

      if (!text) {
        if (typeof onDone === 'function') {
          onDone();
        }
        return;
      }

      if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        story.textContent = text;

        if (typeof onDone === 'function') {
          onDone();
        }
        return;
      }

      story.classList.add('is-typing');
      let index = 0;

      const tick = () => {
        index += 1;
        story.textContent = text.slice(0, index);

        if (index < text.length) {
          state.storyTypeId = window.setTimeout(tick, STORY_TYPE_DELAY);
          return;
        }

        state.storyTypeId = null;
        story.classList.remove('is-typing');

        if (typeof onDone === 'function') {
          onDone();
        }
      };

      state.storyTypeId = window.setTimeout(tick, 120);
    }

    function setLobbyStartState(busy) {
      dom.gameStartButton.disabled = busy;
      dom.gameStartButton.textContent = busy ? '准备中…' : '开始挑战';
      dom.gameLobby.setAttribute('aria-busy', String(busy));
      dom.gameStartDifficulties.querySelectorAll('[data-difficulty]').forEach((button) => {
        button.disabled = busy;
      });
    }

    function beginChallenge(difficulty) {
      if (!DIFFICULTIES[difficulty] || state.transitioning) {
        return;
      }

      state.transitioning = true;
      state.startDifficulty = difficulty;
      setLobbyStartState(true);

      typeLobbyStory(LOBBY_STORY_THANKS, () => {
        state.startPauseId = window.setTimeout(() => {
          state.startPauseId = null;
          const gameView = document.querySelector('.view-game');
          const stillInLobby = !dom.gameLobby.hidden && gameView && !gameView.hidden;

          if (!stillInLobby) {
            state.transitioning = false;
            return;
          }

          state.transitioning = false;
          launchChallenge(difficulty);
        }, STORY_PAUSE_DELAY);
      });
    }

    function setStartDifficultyButtons() {
      dom.gameStartDifficulties.querySelectorAll('[data-difficulty]').forEach((button) => {
        const active = button.dataset.difficulty === state.startDifficulty;
        button.classList.toggle('is-active', active);
        button.setAttribute('aria-pressed', String(active));
      });
    }

    function setFeedback(message, type) {
      dom.gameFeedback.hidden = false;
      dom.gameFeedback.className = `game-feedback is-${type}`;
      dom.gameFeedback.textContent = message;
    }

    function clearFeedback() {
      dom.gameFeedback.hidden = true;
      dom.gameFeedback.className = 'game-feedback';
      dom.gameFeedback.textContent = '';
    }

    function setStateLabel(label, tone) {
      dom.gameState.textContent = label;
      dom.gameState.className = 'game-state';

      if (tone) {
        dom.gameState.classList.add(tone);
      }
    }

    function resetHint() {
      const disabled = DIFFICULTIES[state.difficulty].maxHints === 0;
      state.hintStage = 0;
      dom.gameHintDetail.hidden = true;
      dom.gameHintDetail.textContent = '';
      dom.gameHintButton.disabled = disabled;
      dom.gameHintButton.textContent = disabled ? '提示不可用' : '提示';
    }

    function hideExplanation() {
      dom.gameExplanation.hidden = true;
      clearElement(dom.gameExplanation);
    }

    function showExplanation(puzzle) {
      const entry = GUIDE_ENTRIES.find((item) => item.id === puzzle.algorithmId);

      if (!entry) {
        return;
      }

      clearElement(dom.gameExplanation);
      dom.gameExplanation.append(createElement('p', 'game-explanation__kicker', '算法说明'));

      const title = createElement('h2', 'game-explanation__title', entry.name);
      title.id = 'game-explanation-title';
      dom.gameExplanation.append(title);
      dom.gameExplanation.append(createElement('span', 'game-explanation__type', entry.type));
      dom.gameExplanation.append(createElement('p', 'game-explanation__summary', entry.summary));

      const facts = createElement('dl', 'game-explanation__facts');
      const addFact = (label, value) => {
        const row = createElement('div', 'game-explanation__fact');
        row.append(createElement('dt', '', label));
        row.append(createElement('dd', '', value));
        facts.append(row);
      };

      addFact('密钥', entry.key);
      addFact('加密', entry.encrypt);
      addFact('解密', entry.decrypt);
      dom.gameExplanation.append(facts);
      dom.gameExplanation.hidden = false;
    }

    function revealHint() {
      const puzzle = state.puzzle;

      if (!puzzle || state.mode !== 'challenge' || state.ended) {
        return;
      }

      const config = DIFFICULTIES[state.difficulty];

      if (state.hintStage >= config.maxHints) {
        return;
      }

      state.hintStage += 1;
      puzzle.hintsUsed = state.hintStage;
      state.challenge.combo = 0;
      state.challenge.perfect = false;
      playHintSound();

      const lines = [`加密算法：${puzzle.algorithmName}`];

      if (state.hintStage >= 2) {
        lines.push(getHintKeyLine(puzzle));
      }

      dom.gameHintDetail.textContent = lines.join('\n');
      dom.gameHintDetail.hidden = false;

      if (typeof dom.gameHintDetail.scrollIntoView === 'function') {
        dom.gameHintDetail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      }

      if (state.hintStage === 1) {
        showExplanation(puzzle);
      }

      if (state.hintStage >= config.maxHints) {
        dom.gameHintButton.disabled = true;
        dom.gameHintButton.textContent = '已提示';
      } else {
        dom.gameHintButton.textContent = '再提示';
      }
    }

    function revealResult() {
      const puzzle = state.puzzle;

      if (!puzzle) {
        return;
      }

      clearElement(dom.gameResult);
      dom.gameResult.hidden = false;
      dom.gameResult.append(createElement('p', 'game-result__label', '正确答案'));
      dom.gameResult.append(createElement('p', 'game-result__answer', formatAnswerDisplay(puzzle.plaintext)));
      dom.gameResult.append(createElement(
        'p',
        'game-result__meta',
        `算法：${puzzle.algorithmName} · 密钥：${getKeyLabel(puzzle)} · 本题得分：${puzzle.score || 0}`,
      ));
    }

    function launchChallenge(difficulty) {
      if (!DIFFICULTIES[difficulty]) {
        difficulty = 'easy';
      }

      state.difficulty = difficulty;
      state.startDifficulty = difficulty;
      state.leaveCallback = null;

      try {
        const plaintexts = shuffle(WORD_BANK).slice(0, QUESTIONS_PER_CHALLENGE);
        const puzzles = plaintexts.map((plaintext) => createPuzzle(plaintext));

        state.challenge = {
          puzzles,
          index: 0,
          correct: 0,
          score: 0,
          combo: 0,
          perfect: true,
          elapsedMs: 0,
          startedAt: 0,
        };
        state.puzzle = puzzles[0];
        state.ended = false;
        state.hintStage = 0;
        state.mode = 'challenge';

        dom.gameLobby.hidden = true;
        dom.gameLeaveModal.hidden = true;
        dom.gameSummary.hidden = true;
        dom.gameSummaryLeave.hidden = true;
        dom.gameCard.hidden = false;
        dom.gameExplanation.hidden = true;
        renderPuzzle();
        startTimer();
      } catch (error) {
        console.error(error);
        state.transitioning = false;
        setLobbyStartState(false);
        dom.gameLobbyStory.textContent = '题目生成失败，请重新选择难度。';
        dom.gameLobbyStory.classList.remove('is-typing');
      }
    }

    function openLobby(difficulty = state.startDifficulty) {
      if (!DIFFICULTIES[difficulty]) {
        difficulty = 'easy';
      }

      state.mode = 'idle';
      state.startDifficulty = difficulty;
      state.transitioning = false;
      clearLobbyTimers();
      stopTimer();
      cancelAutoNext();
      state.challenge = null;
      state.puzzle = null;
      state.ended = false;
      state.hintStage = 0;
      state.leaveCallback = null;

      dom.gameLobby.hidden = false;
      dom.gameLeaveModal.hidden = true;
      dom.gameSummary.hidden = true;
      dom.gameSummaryLeave.hidden = true;
      dom.gameCard.hidden = true;
      dom.gameExplanation.hidden = true;
      setLobbyStartState(false);
      setStartDifficultyButtons();
      renderHighScores();
      typeLobbyStory(LOBBY_STORY_INTRO);
    }

    function renderPuzzle() {
      const puzzle = state.puzzle;
      const challenge = state.challenge;

      if (!puzzle || !challenge) {
        return;
      }

      const config = DIFFICULTIES[state.difficulty];

      dom.gameLobby.hidden = true;
      dom.gameCard.hidden = false;
      dom.gameLeaveModal.hidden = true;
      dom.gameSummary.hidden = true;
      dom.gameSummaryLeave.hidden = true;
      dom.gamePerfectBadge.hidden = true;

      dom.gameDifficultyLabel.textContent = config.label;
      dom.gameProgress.textContent = `第 ${challenge.index + 1} / ${QUESTIONS_PER_CHALLENGE} 题`;
      dom.gameTimer.textContent = `用时 ${formatDuration(getElapsedMs())}`;
      dom.gameScore.textContent = `得分 ${challenge.score}`;
      setStateLabel('推理中');
      dom.gameHint.textContent = `提示：${config.hint}`;
      dom.gameCipher.textContent = puzzle.ciphertext;
      dom.gameAnswer.value = '';
      dom.gameAnswer.disabled = false;
      dom.gameSubmit.disabled = false;
      dom.gameGiveup.disabled = false;
      dom.gameHintButton.disabled = false;
      dom.gameNext.disabled = true;
      dom.gameNext.textContent = challenge.index === QUESTIONS_PER_CHALLENGE - 1 ? '查看结果' : '下一题';
      dom.gameResult.hidden = true;
      clearElement(dom.gameResult);
      clearFeedback();
      resetHint();
      hideExplanation();
      resetScratchpad(puzzle);
      clearTransientEffects();
      cancelAutoNext();
      dom.comboPop.hidden = true;
      dom.comboPop.classList.remove('is-visible');
    }

    function submitAnswer() {
      const puzzle = state.puzzle;

      if (!puzzle || state.mode !== 'challenge' || state.ended) {
        return;
      }

      const guess = normalizeAnswer(dom.gameAnswer.value);

      if (!guess) {
        setFeedback('请输入答案后再提交。', 'error');
        dom.gameAnswer.focus();
        return;
      }

      if (guess === normalizeAnswer(puzzle.plaintext)) {
        state.ended = true;
        puzzle.result = 'correct';
        let points = getQuestionScore(puzzle);
        let comboBonus = 0;

        if ((puzzle.hintsUsed || 0) === 0) {
          state.challenge.combo += 1;

          if (state.challenge.combo % 3 === 0) {
            comboBonus = 5;
            points += comboBonus;
            showCombo(`Combo x${state.challenge.combo}！+5分`);
          }
        } else {
          state.challenge.combo = 0;
          state.challenge.perfect = false;
        }

        puzzle.score = points;
        state.challenge.correct += 1;
        state.challenge.score += points;
        dom.gameScore.textContent = `得分 ${state.challenge.score}`;
        pauseTimer();
        playCorrectSound();
        flashCorrect();
        setFeedback(
          comboBonus > 0
            ? `正确！Combo x${state.challenge.combo}，本题得 ${points} 分。`
            : `正确！本题得 ${points} 分。`,
          'success',
        );
        setStateLabel('已解开', 'is-solved');
        revealResult();
        dom.gameAnswer.disabled = true;
        dom.gameSubmit.disabled = true;
        dom.gameGiveup.disabled = true;
        dom.gameHintButton.disabled = true;
        dom.gameNext.disabled = false;
        dom.gameNext.focus();
        scheduleAutoNext();
        return;
      }

      playWrongSound();
      shakeAnswerInput();
      dom.gameAnswer.value = '';
      setFeedback('答案不对，再试一次。', 'error');
      dom.gameAnswer.focus();
    }

    function giveUp() {
      if (!state.puzzle || state.mode !== 'challenge' || state.ended) {
        return;
      }

      state.ended = true;
      state.puzzle.result = 'wrong';
      state.puzzle.score = 0;
      state.challenge.combo = 0;
      state.challenge.perfect = false;
      pauseTimer();
      cancelAutoNext();
      setFeedback('已放弃，本题不得分。', 'info');
      setStateLabel('已放弃', 'is-given-up');
      revealResult();
      dom.gameAnswer.disabled = true;
      dom.gameSubmit.disabled = true;
      dom.gameGiveup.disabled = true;
      dom.gameHintButton.disabled = true;
      dom.gameNext.disabled = false;
      dom.gameNext.focus();
    }

    function finishChallenge(terminated = false) {
      const challenge = state.challenge;

      if (!challenge) {
        return;
      }

      cancelAutoNext();
      stopTimer();
      const elapsedMs = challenge.elapsedMs;
      state.mode = 'summary';
      state.ended = true;

      dom.gameSummaryKicker.textContent = terminated ? '挑战已终止' : '挑战完成';
      dom.gameSummaryScore.textContent = String(challenge.score);
      dom.gamePerfectBadge.hidden = terminated
        || challenge.correct !== QUESTIONS_PER_CHALLENGE
        || !challenge.perfect;
      let detail = `答对 ${challenge.correct} / ${QUESTIONS_PER_CHALLENGE} 题 · 用时 ${formatDuration(elapsedMs)}`;

      if (!terminated) {
        state.leaveCallback = null;
        const isNewRecord = updateHighScore(state.difficulty, challenge.score, elapsedMs);

        if (isNewRecord) {
          detail += ' · 新纪录！';
        }
      }

      dom.gameSummaryDetail.textContent = detail;
      dom.gameSummaryLeave.hidden = !terminated;
      dom.gameLobby.hidden = true;
      dom.gameCard.hidden = true;
      dom.gameExplanation.hidden = true;
      dom.gameLeaveModal.hidden = true;
      dom.gameSummary.hidden = false;
    }

    function nextPuzzle() {
      const challenge = state.challenge;

      if (!challenge || state.mode !== 'challenge' || !state.ended) {
        return;
      }

      cancelAutoNext();

      if (challenge.index >= QUESTIONS_PER_CHALLENGE - 1) {
        finishChallenge();
        return;
      }

      challenge.index += 1;
      state.puzzle = challenge.puzzles[challenge.index];
      state.ended = false;
      state.hintStage = 0;
      renderPuzzle();
      resumeTimer();
    }

    function isChallengeActive() {
      return state.mode === 'challenge' && state.challenge !== null;
    }

    function requestLeave(callback) {
      if (!isChallengeActive()) {
        if (typeof callback === 'function') {
          callback();
        }
        return;
      }

      state.leaveCallback = callback;
      cancelAutoNext();
      const challenge = state.challenge;
      dom.gameLeaveMessage.textContent = `当前进度：第 ${challenge.index + 1} / ${QUESTIONS_PER_CHALLENGE} 题，已答对 ${challenge.correct} 题。终止后将结算本组挑战。`;
      dom.gameLeaveModal.hidden = false;
    }

    function cancelLeave() {
      state.leaveCallback = null;
      dom.gameLeaveModal.hidden = true;
    }

    function confirmLeave() {
      if (!isChallengeActive()) {
        dom.gameLeaveModal.hidden = true;
        return;
      }

      dom.gameLeaveModal.hidden = true;
      finishChallenge(true);
    }

    function leaveToPendingRoute() {
      const callback = state.leaveCallback;
      state.leaveCallback = null;
      cancelAutoNext();
      state.mode = 'idle';
      state.challenge = null;
      state.puzzle = null;
      state.ended = false;
      state.hintStage = 0;
      dom.gameSummary.hidden = true;
      dom.gameSummaryLeave.hidden = true;
      dom.gameLobby.hidden = true;
      dom.gameCard.hidden = true;
      dom.gameExplanation.hidden = true;

      if (typeof callback === 'function') {
        callback();
      } else {
        navigateToRoute('home');
      }
    }

    function onEnter() {
      if (state.mode === 'challenge' && state.challenge) {
        dom.gameLobby.hidden = true;
        dom.gameLeaveModal.hidden = true;
        dom.gameSummary.hidden = true;
        dom.gameSummaryLeave.hidden = true;
        dom.gameCard.hidden = false;
        return;
      }

      if (state.mode === 'summary') {
        openLobby(state.difficulty);
        return;
      }

      openLobby(state.startDifficulty);
    }

    function bind() {
      dom.gameStartDifficulties.addEventListener('click', (event) => {
        if (state.transitioning) {
          return;
        }

        const button = event.target.closest('[data-difficulty]');

        if (!button) {
          return;
        }

        state.startDifficulty = button.dataset.difficulty;
        setStartDifficultyButtons();
      });

      dom.gameStartButton.addEventListener('click', () => beginChallenge(state.startDifficulty));

      dom.gameSubmit.addEventListener('click', submitAnswer);
      dom.gameGiveup.addEventListener('click', giveUp);
      dom.gameNext.addEventListener('click', nextPuzzle);
      dom.gameHintButton.addEventListener('click', revealHint);
      dom.gameScratchRun.addEventListener('click', runScratchpad);
      dom.gameScratchAlgorithm.addEventListener('change', handleScratchAlgorithmChange);

      dom.gameRestart.addEventListener('click', () => {
        state.leaveCallback = null;
        launchChallenge(state.difficulty);
      });
      dom.gameChangeDifficulty.addEventListener('click', () => {
        state.leaveCallback = null;
        openLobby(state.difficulty);
      });
      dom.gameSummaryLeave.addEventListener('click', leaveToPendingRoute);

      dom.gameLeaveCancel.addEventListener('click', cancelLeave);
      dom.gameLeaveConfirm.addEventListener('click', confirmLeave);

      dom.gameAnswer.addEventListener('input', () => {
        if (state.mode === 'challenge' && !state.ended) {
          clearFeedback();
        }
      });

      dom.gameAnswer.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
          event.preventDefault();
          submitAnswer();
        }
      });
    }

    function init() {
      loadHighScores();
      bind();
      setStartDifficultyButtons();
      renderHighScores();
    }

    return { init, onEnter, isChallengeActive, requestLeave };
  })();


  function init() {
    updateKeyVisibility();
    bindEvents();
    updateCategoryFilter();
    renderGuide();
    renderHistory();
    GameModule.init();
    renderRoute();
    updateBrailleTextStyles();
    updateMatrixPanel();
    initStarfield();
  }

  try {
    init();
  } catch (error) {
    console.error(error);

    const region = document.getElementById('app-error');

    if (region) {
      region.hidden = false;
      region.textContent = `页面初始化失败：${error instanceof Error ? error.message : '未知错误'}。请使用最新版 Chrome / Edge / Firefox 打开，并按 Ctrl+F5 强制刷新。`;
    }
  }
})();
