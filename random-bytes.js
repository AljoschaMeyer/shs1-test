module.exports = (rnd, size) => {
  const buf = Buffer.alloc(size);
  for (let i = 0; i < size; i++) {
    buf.writeUInt8(rnd.intBetween(0, 255), i);
  }
  return buf;
};
