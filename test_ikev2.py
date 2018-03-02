# -*- coding: utf-8 -*-

import ikev2.ikev2_class as ikev2

#ike_instance = ikev2.epdg_ikev2('188.21.252.88', 51234, 500)
ike_instance = ikev2.epdg_ikev2('192.168.0.1', 51234, 500)
#ike_instance.sa_init(True)
ike_instance.sa_auth("232019876543210")
