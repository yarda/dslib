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
 * MarkMessageAsDownloaded
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


Knihovna pyasn1
================

dslib verze 1.4.1 a nižší obsahovaly přibalenou upravenou knihovnu pyasn1
založenou na upstreamové verzi 0.0.9a. V rámci usnadnění balíčkování byla v
dslib odstraněna nutnost používat modifikovanou knihovnu pyasn1 a je možné
využít upstreamovou verzi. Je však nutno použít verzi minimálně 0.0.13b.
Protože tato verze není ve většině distribucí k disposici, obsahuje knihovna
dslib stále interní kopii pyasn1, která odpovídá verzi 0.0.13b. V budoucnosti
bude tato knihovna pravděpodobně odstraněna z balíčku dslib.


Autoři
=======

Knihovna dslib byla vytvořená ve vývojových laboratořích CZ.NIC, z.s.p.o.- 
CZ.NIC Labs (http://labs.nic.cz/) 

