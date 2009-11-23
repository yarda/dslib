# encoding: utf-8

MESSAGE_STATUS = dict( [(1, u"zpráva byla podána"),
			(2, u"hash datové zprávy včetně písemností označen časovým razítkem"),
			(3, u"zpráva NEprošla AV kontrolou; nakažená písemnost je smazána; konečný stav zprávy"),
			(4, u"zpráva dodána do ISDS (zapsán čas dodání)"),
			(5, u"zpráva byla doručena fikcí (vypršením 10 dnů od dodání) - (zapsán čas doručení)"),
			(6, u"zpráva byla doručena přihlášením (zapsán čas doručení)"),
			(7, u"zpráva byla přečtena (na portále nebo akcí ESS)"),
			(8, u"zpráva byla označena jako nedoručitelná (DS byla zpětně znepřístupněna)"),
			(9, u"obsah zprávy byl smazán (v současné verzi takovouto DZ nelze získat pomocí jakékoliv WS)")
			]
		       )

