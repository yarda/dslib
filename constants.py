# encoding: utf-8

#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2010  CZ.NIC, z.s.p.o. (http://www.nic.cz)
#*
#*    This library is free software; you can redistribute it and/or
#*    modify it under the terms of the GNU Library General Public
#*    License as published by the Free Software Foundation; either
#*    version 2 of the License, or (at your option) any later version.
#*
#*    This library is distributed in the hope that it will be useful,
#*    but WITHOUT ANY WARRANTY; without even the implied warranty of
#*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#*    Library General Public License for more details.
#*
#*    You should have received a copy of the GNU Library General Public
#*    License along with this library; if not, write to the Free
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#*


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

