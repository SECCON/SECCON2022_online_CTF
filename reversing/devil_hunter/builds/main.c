/* SECCON{byT3c0d3_1nT3rpr3T3r_1s_4_L0T_0f_fun} */
VIRUSNAME_PREFIX("Seccon.Reversing")
VIRUSNAMES("FLAG")
TARGET(0)

SIGNATURES_DECL_BEGIN
DECLARE_SIGNATURE(prefix)
SIGNATURES_DECL_END

SIGNATURES_DEF_BEGIN
DEFINE_SIGNATURE(prefix, "0:534543434f4e7b")
SIGNATURES_END

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

const uint16_t __clambc_kind = BC_LOGICAL;

bool logical_trigger(void)
{
  return matches(Signatures.prefix);
}

unsigned int my_hash(unsigned int v)
{
  unsigned int h = 0xacab3c0;
  for (unsigned int i = 0; i < 4; i++) {
    h = ROTL(h ^ ((v >> (i*8)) & 0xff), 8);
  }
  return h;
}

bool check_contents()
{
  unsigned int i;
  unsigned char c;
  unsigned char flag[36];
  unsigned int conv[36 / 4];
  bool res = true;

  /* Skip "SECCON{" prefix */
  seek(7, SEEK_SET);

  /* Contents length must be 36 */
  for (i = 0; i < 36U; i++) {
    if (read(flag + i, 1) <= 0)
      return 0;
  }

  /* Must end with "}" */
  if (read(&c, 1) <= 0 || c != '}' || read(&c, 1) > 0)
    return 0;

  /* Check contents */
  for (i = 0; i < 36; i += 4) {
    conv[i/4] = my_hash(*(unsigned int*)(flag + i));
  }

  res &= (conv[0] == 1939767458);
  res &= (conv[1] == 984514723);
  res &= (conv[2] == 1000662943);
  res &= (conv[3] == 2025505267);
  res &= (conv[4] == 1593426419);
  res &= (conv[5] == 1002040479);
  res &= (conv[6] == 1434878964);
  res &= (conv[7] == 1442502036);
  res &= (conv[8] == 1824513439);

  return res;
}

int entrypoint(void)
{
  if (check_contents())
    foundVirus("FLAG");

  return 0;
}
