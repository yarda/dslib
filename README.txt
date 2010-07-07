=====
dslib
=====

dslib je svobodná (licence LGPL) knihovna pro přístup k Datovým schránkám.
Knihovna je napsaná v jazyce Python a ve svém základě jde v podstatě o tenkou
vrstvu nad SOAP rozhraním, které systém datových schránek poskytuje.

V současné verzi jsou implementovány následující funkce:

 * GetListOfSentMessages
 * GetListOfReceivedMessages
 * MessageEnvelopeDownload
 * MessageDownload
 * SignedMessageDownload
 * SignedSentMessageDownload
 * GetDeliveryInfo
 * GetSignedDeliveryInfo
 * GetOwnerInfoFromLogin
 * GetUserInfoFromLogin
 * GetPasswordInfo
 * ChangeISDSPassword
 * FindDataBox
 * CreateMessage
 * DummyOperation
 
Autentizace je implementovaná v plném rozsahu a lze tedy využít kombinaci jména
a heslo, či autentizaci pomocí klientského certifikátu.

Ukázkový kód pro knihovnu je k disposici v souboru tests.py


SOAP knihovna
==============

Knihovna používá knihovnu "suds" (https://fedorahosted.org/suds) pro SOAP
komunikaci. Protože bylo třeba tuto knihovnu upravit pro potřeby našeho
projektu, distribuujeme upravenou verzi jako součást našeho balíčku 
(suds i dslib jsou vydávány pod licencí LGPL) pod názvem sudsds. Pokud bude 
v budoucnosti možné použít oficiální verzi "suds", bude naše upravená
verze z balíčku odstraněna.


Autoři
=======

Knihovna dslib byla vytvořená ve vývojových laboratořích CZ.NIC, z.s.p.o.- 
CZ.NIC Labs (http://labs.nic.cz/) 
