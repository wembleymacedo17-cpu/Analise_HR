CARGOS_REJEITADOS_LEGADO = {
    '1013', '11', '1159', '1161', '12', '125', '135', '137', '156', '157',
    '158', '161', '162', '171', '172', '173', '174', '175', '176', '177',
    '178', '179', '180', '181', '182', '184', '194', '20', '244', '245',
    '246', '247', '248', '249', '251', '257', '258', '259', '260', '261',
    '262', '263', '264', '265', '267', '269', '270', '271', '273', '274',
    '279', '280', '282', '283', '286', '287', '288', '291', '294', '295',
    '297', '298', '300', '301', '307', '308', '309', '310', '311', '312',
    '313', '314', '316', '317', '319', '322', '323', '326', '348', '349',
    '359', '400', '453', '48', '49', '497', '499', '50', '51', '518',
    '519', '52', '520', '53', '530', '54', '55', '56', '57', '600',
    '601', '602', '66', '666', '789', '799', '8020', '8026', '807', '808',
    '809', '823', '837', '840', '857', '858', '875', '9000', '9042', '910',
    '921', '933', '934', '935', '936', '940', '943', '944', '945', '948',
    '953', '954', '955', '956', '957', '958', '959', '960', '961', '962',
    '963', '964', '965', '968', '975', '976', '977', '978', '979', '980',
    '981', '982', '983', '984', '985', '987', '988', '989', '993', '994',
    '995', '996', '997', '998', '5001'
}

_CARGOS_REJEITADOS_SQL = ", ".join(f"'{c}'" for c in sorted(CARGOS_REJEITADOS_LEGADO))

QUERY_ESTRUTURA_COLABORADORES = f"""
SELECT
    fil.codfil                          AS codigo_unidade,
    fil.nomfil                          AS nome_unidade,
    ccu.codccu                          AS codigo_cc,
    ccu.nomccu                          AS nome_cc,
    car.codcar                          AS codigo_cargo,
    car.titred                          AS titulo_cargo,
    fun.numcad                          AS cracha,
    fun.nomfun                          AS nome,
    fun.tipsex                          AS sexo,
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
  AND TRIM(TO_CHAR(car.codcar)) NOT IN ({_CARGOS_REJEITADOS_SQL})
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
      AND TRIM(TO_CHAR(f.codcar)) NOT IN ({_CARGOS_REJEITADOS_SQL})
      AND s.datapu >= TRUNC(SYSDATE) - {dias}
      AND s.datapu < TRUNC(SYSDATE)
    GROUP BY f.numcad, f.numcpf, f.codccu, s.datapu
    """