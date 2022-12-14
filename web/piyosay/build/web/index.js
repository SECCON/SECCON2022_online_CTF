const fastify = require("fastify")();
const fs = require("node:fs/promises");

const PORT = process.env.PORT ?? "3000";

fastify.register(require("@fastify/formbody"));
fastify.register(require("./report"), { prefix: "/report" });

fastify.get("/", async (req, reply) => {
  const html = await fs.readFile("views/index.html");
  return reply.type("text/html; charset=utf-8").send(html);
});

fastify.get("/result", async (req, reply) => {
  const html = await fs.readFile("views/result.html");
  return reply.type("text/html; charset=utf-8").send(html);
});

fastify.get("/api/emojis", async (req, reply) => {
  const emojis =
    "๐/๐/๐/๐/๐/๐/๐/๐คฃ/๐ฅฒ/โบ๏ธ/๐/๐/๐/๐/๐/๐/๐/๐ฅฐ/๐/๐/๐/๐/๐/๐/๐/๐/๐คช/๐คจ/๐ง/๐ค/๐/๐ฅธ/๐คฉ/๐ฅณ/๐/๐/๐/๐/๐/๐/๐/โน๏ธ/๐ฃ/๐/๐ซ/๐ฉ/๐ฅบ/๐ข/๐ญ/๐ค/๐ /๐ก/๐คฌ/๐คฏ/๐ณ/๐ฅต/๐ฅถ/๐ฑ/๐จ/๐ฐ/๐ฅ/๐/๐ค/๐ค/๐คญ/๐คซ/๐คฅ/๐ถ/๐/๐/๐ฌ/๐/๐ฏ/๐ฆ/๐ง/๐ฎ/๐ฒ/๐ฅฑ/๐ด/๐คค/๐ช/๐ต/๐ค/๐ฅด/๐คข/๐คฎ/๐คง/๐ท/๐ค/๐ค/๐ค/๐ค /๐/๐ฟ/๐น/๐บ/๐คก/๐ฉ/๐ป/๐/โ ๏ธ/๐ฝ/๐พ/๐ค/๐/๐บ/๐ธ/๐น/๐ป/๐ผ/๐ฝ/๐/๐ฟ/๐พ/๐ถ/๐ฑ/๐ญ/๐น/๐ฐ/๐ฆ/๐ป/๐ผ/๐ปโโ๏ธ/๐จ/๐ฏ/๐ฆ/๐ฎ/๐ท/๐ฝ/๐ธ/๐ต/๐/๐/๐/๐/๐/๐ง/๐ฆ/๐ค/๐ฃ/๐ฅ/๐ฆ/๐ฆ/๐ฆ/๐ฆ/๐บ/๐/๐ด/๐ฆ/๐/๐ชฑ/๐/๐ฆ/๐/๐/๐/๐ชฐ/๐ชฒ/๐ชณ/๐ฆ/๐ฆ/๐ท/๐ธ/๐ฆ/๐ข/๐/๐ฆ/๐ฆ/๐ฆ/๐/๐ฆ/๐ฆ/๐ฆ/๐ฆ/๐ก/๐ /๐/๐ฌ/๐ณ/๐/๐ฆ/๐/๐/๐/๐ฆ/๐ฆ/๐ฆง/๐ฆฃ/๐/๐ฆ/๐ฆ/๐ช/๐ซ/๐ฆ/๐ฆ/๐ฆฌ/๐/๐/๐/๐/๐/๐/๐/๐ฆ/๐/๐ฆ/๐/๐ฉ/๐ฆฎ/๐โ๐ฆบ/๐/๐โโฌ/๐ชถ/๐/๐ฆ/๐ฆค/๐ฆ/๐ฆ/๐ฆข/๐ฆฉ/๐/๐/๐ฆ/๐ฆจ/๐ฆก/๐ฆซ/๐ฆฆ/๐ฆฅ/๐/๐/๐ฟ/๐ฆ/๐พ/๐/๐ฒ".split(
      "/"
    );
  return reply.send(emojis);
});

fastify.listen({ port: PORT, host: "0.0.0.0" }, (err, address) => {
  if (err) {
    fastify.log.error(err);
    process.exit(1);
  }
  console.log(`Server listening at "${address}"`);
});
