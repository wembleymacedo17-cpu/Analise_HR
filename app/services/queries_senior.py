QUERY_ESTRUTURA_COLABORADORES = """
SELECT
    fil.codfil                          AS codigo_unidade,
    fil.nomfil                          AS nome_unidade,
    ccu.codccu                          AS codigo_cc,
    ccu.nomccu                          AS nome_cc,
    car.codcar                          AS codigo_cargo,
    car.titred                          AS titulo_cargo,
    fun.numcad                          AS cracha,
    fun.nomfun                          AS nome,
    LPAD(TO_CHAR(fun.numcpf), 11, '0')  AS cpf,
    fun.datnas                          AS data_nascimento,
    cpl.emacom                          AS email
FROM R034FUN fun
INNER JOIN R030FIL fil ON fil.numemp = fun.numemp AND fil.codfil = fun.codfil
INNER JOIN R018CCU ccu ON ccu.numemp = fun.numemp AND ccu.codccu = fun.codccu
INNER JOIN R024CAR car ON car.estcar = fun.estcar AND car.codcar = fun.codcar
LEFT JOIN R034CPL cpl  ON cpl.numemp = fun.numemp AND cpl.tipcol = fun.tipcol AND cpl.numcad = fun.numcad
WHERE fun.tipcol = 1
  AND fun.numemp = 1
  AND fun.sitafa NOT IN (7, 17, 427, 16, 422)
"""


def montar_query_faltas(dias_retroativos: int = 15) -> str:
    dias = int(dias_retroativos)
    return f"""
    SELECT
        f.numcad                            AS cracha,
        LPAD(TO_CHAR(f.numcpf), 11, '0')    AS cpf,
        f.codccu                            AS codigo_cc,
        s.datapu                            AS data_ocorrencia
    FROM R066SIT s
    INNER JOIN R034FUN f ON f.numemp = s.numemp AND f.tipcol = s.tipcol AND f.numcad = s.numcad
    WHERE f.tipcol = 1
      AND f.numemp = 1
      AND s.codsit IN (15, 65, 135)
      AND s.datapu >= TRUNC(SYSDATE) - {dias}
      AND s.datapu < TRUNC(SYSDATE)
    GROUP BY f.numcad, f.numcpf, f.codccu, s.datapu
    """

