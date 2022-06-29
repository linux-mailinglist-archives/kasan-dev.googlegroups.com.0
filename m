Return-Path: <kasan-dev+bncBDDO3ANQ5EKBBSWE6GKQMGQE6T3YWDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1008E5602BB
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 16:31:39 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id az28-20020adfe19c000000b0021bc8df3721sf1803796wrb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 07:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656513098; cv=pass;
        d=google.com; s=arc-20160816;
        b=eJzLrgn/4wKNCVidoJpklL9l2iyUiQ5l1odCpPk5XwoYfcLvzfnkwRRBQhN50OE4ON
         ELcFcL5BieQor0VWo77/YAN53IdRoFX48zcWouVqKno5IKJej1hwwJYwDFRFcntTZFcR
         KVOCyWncLHIA9XkDB7wAGyRzJxVBcLUXv8btqWPl+WwqpFUHhzv5jG5N9KOg2IUYYprt
         PSn+tF8sH2QllAoZRioCBp0U2prSE25CRrNQta59y0myohw5poFfdGyL/8DWvx8xRHiy
         Va5xVD1ia40ptg5i1owH3K/a41u0PGKVlhUK7wd9LHRbgl9dMATs/WyG10UMgH2MXa34
         bLqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:user-agent:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=H8GD4wxIuwcotLUEOHYRadOgirkl4LUHQbhQHB0Kt/A=;
        b=OIBk9mKCiChPPAtB55QPA8uwxHEfsBhblvj+rXITXGjgA5QhC1lUnUVBnxE7kFPYKM
         FP73/rGMQ+7W7HOOVkN0MnAzAnOspHCkNNaLo2lqdHKu82nLZvcAKik9SHSpxEJUuIjX
         wEs4GHNISTV4gPyYSvcZsW9fKsB7OI1Blw/7hw7PclF9KBLmxDz9x183G2bkGBoN+Exn
         XfPcRXR5KXaPYyjnK2hinZQQiLVlhNfDlYUJ0ZRkWy+iM2GL3shVapoyfey0yiL14FfN
         qRMG2MjhRIOrJJ9T/MDqGDyUkAqPdxOMfs/KMPaCAVx744ExzD2ksISU0/o9hIbIfO/l
         nUXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=i0npVKk7;
       spf=pass (google.com: best guess record for domain of srinivas.pandruvada@linux.intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=srinivas.pandruvada@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :user-agent:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H8GD4wxIuwcotLUEOHYRadOgirkl4LUHQbhQHB0Kt/A=;
        b=pYTsFZhEMThbE/mI5Fc0PDw27/fLRMiRHfw2MbUbYdfAPxRrhw4Xz6XRU7aKeAnOeN
         vPuCYC+FfyYMjciHK9UF+YSIuUsHLX5+D8UgA94pyE8ptjDaX+lO0Y4iNRey/ok8Kjky
         qRcL9AKvVrhHGnd+WaTz+QQiTIYJ81nC1tmzLfSS4AZm2J3l9uUddioQ908ITYRVHVZ8
         oIv4iJypQg0kPdvTo3ExgFpyxDCfP+3+ht8TE8SKZRKKEp0ESTxPJ3lvF7ct9dOpwMau
         b1fpkXUj1kElCQP90RbPuuJqaGM89vblER3i12GFxnAMV0QRIzF+iH7ezcbR7J2kCztZ
         Ft3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:user-agent:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H8GD4wxIuwcotLUEOHYRadOgirkl4LUHQbhQHB0Kt/A=;
        b=2KrqS6/umJaVLv/dPohxmBJQDW6PQKeshLTX8VUDDE85vQyFBT8jhE7DtvUSnEj6m/
         CuPkv97OtQwhLmK8LvI+EHi2PEnzWpb9Awuze16XCkwJk/pDlWGiojz5EqLJZd60RXFF
         CBOOIzGQ31vYSoQNOrzftrM6cfXhzoTh1le4U2Jxg5r/B9JIx4IIDRcGifgbADkqTkxR
         wNMbBhctDYx8+XzWxbDDUwN+9M0IS0/mI/gV0oNi3meUzZITMIRBaMSbYd6m1IXg6RQk
         GFVyQcHUpWwbJ+MKqGnONvQB3YKUFNh1TVQwyboub6S8HWTZB9vKJBIJkCLsMd07Swf3
         jNfg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/5PSmOSjFZ+s0+G/DS4afnfmHCcsBt9SAFXgLSs6kS34B05+IC
	ORDZ6CulwU0NqAnV/X6LACM=
X-Google-Smtp-Source: AGRyM1sXbeQnqfWYjAqgWF/GcLBQH1ISStrPPjXGhdZBozBNNKV4ktYnwWnyhjvBw3DqsyRpO/s6sw==
X-Received: by 2002:a5d:4892:0:b0:20c:d4eb:1886 with SMTP id g18-20020a5d4892000000b0020cd4eb1886mr3575288wrq.96.1656513098434;
        Wed, 29 Jun 2022 07:31:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1887:b0:218:5c3b:1a23 with SMTP id
 a7-20020a056000188700b002185c3b1a23ls1159459wri.0.gmail; Wed, 29 Jun 2022
 07:31:37 -0700 (PDT)
X-Received: by 2002:a05:6000:80e:b0:21b:9fb8:1b65 with SMTP id bt14-20020a056000080e00b0021b9fb81b65mr3480090wrb.592.1656513097017;
        Wed, 29 Jun 2022 07:31:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656513097; cv=none;
        d=google.com; s=arc-20160816;
        b=Sm0QKuFsyX1MdTDbcpMu2VKFlGFOldfLmJ7eNcbDESVxukBUSpmbHLm//G0YbXtw1K
         g22Hh/vpOmgTetjFseUMd26u3lPtMVAzZZGJJzGkTn5MGLOJ1Q3JGWWRB+tj3X3tV/bJ
         WIkIs5sEJTFYnpigY7jVXh4W99ctkb6HmxR52gkyr5XFORsxRHVpq0W3F6J/HTuSmIYf
         B5DjSsZNZYVzA4PRuaam57bU81ocd4OXWJq9zAZ7lK/M6w+AwqFpOqCcPSo1itQ1LDUa
         pqcuNQrZRMk1ToWDU3OzMaEgNdXvWAnAoeFUrdaV0xKaIJX2bjrVePRDrTtFm1isTZDf
         BHCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=pJXpdvH9MEQ8HqGK7OiRzl2ik/5lsUWV9t2eLvcSr04=;
        b=YJRNS9ncW3ustnMiE4qGNfuNltciKB3ez5Ggmu3vFelk5/kkcRK/xr2SG4W5lJU4ya
         Mofg/MZBJImTAjXsb67lnB3mszfWcwSRMYGLKsixmc+UNof1WXPbnQqa8SXJ0W8xBD9Y
         YY5KO80AlTndG/0988DcuIQpgJ7TFfDYAyWvoRWUBNsFsr+qhdvNb72+3oJrurZk+mUd
         +WBkW/pnXhgeCjrTN5SeY4yCG8NbUCLggiMBO7icOsCZewXx/6gYrCURHPQeH1vS3rgJ
         XOf/oJ4SiuyyzRmm/XgPS3R9t882Vt3UYV86QMUilrmf1Of07NOXPq42EItIfuESw8Kq
         LfmA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=i0npVKk7;
       spf=pass (google.com: best guess record for domain of srinivas.pandruvada@linux.intel.com designates 192.55.52.88 as permitted sender) smtp.mailfrom=srinivas.pandruvada@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga01.intel.com (mga01.intel.com. [192.55.52.88])
        by gmr-mx.google.com with ESMTPS id w15-20020adff9cf000000b0021b95bcfb2asi648035wrr.0.2022.06.29.07.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jun 2022 07:31:36 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of srinivas.pandruvada@linux.intel.com designates 192.55.52.88 as permitted sender) client-ip=192.55.52.88;
X-IronPort-AV: E=McAfee;i="6400,9594,10392"; a="307540984"
X-IronPort-AV: E=Sophos;i="5.92,231,1650956400"; 
   d="scan'208";a="307540984"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by fmsmga101.fm.intel.com with ESMTP; 29 Jun 2022 07:31:23 -0700
X-IronPort-AV: E=Sophos;i="5.92,231,1650956400"; 
   d="scan'208";a="647415537"
Received: from egolubev-mobl.amr.corp.intel.com (HELO spandruv-desk1.amr.corp.intel.com) ([10.209.68.9])
  by fmsmga008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Jun 2022 07:31:09 -0700
Message-ID: <bc3ddfb53df76885ca9714a6502d7d0bb367584b.camel@linux.intel.com>
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
From: srinivas pandruvada <srinivas.pandruvada@linux.intel.com>
To: Uwe =?ISO-8859-1?Q?Kleine-K=F6nig?= <u.kleine-koenig@pengutronix.de>, 
	Wolfram Sang <wsa@kernel.org>
Cc: Uwe =?ISO-8859-1?Q?Kleine-K=F6nig?= <uwe@kleine-koenig.org>, Sekhar Nori
 <nsekhar@ti.com>, Bartosz Golaszewski <brgl@bgdev.pl>, Russell King
 <linux@armlinux.org.uk>, Scott Wood <oss@buserror.net>, Michael Ellerman
 <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
 Paul Mackerras <paulus@samba.org>, Robin van der Gracht
 <robin@protonic.nl>, Miguel Ojeda <ojeda@kernel.org>,  Corey Minyard
 <minyard@acm.org>, Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen
 <jarkko@kernel.org>, Jason Gunthorpe <jgg@ziepe.ca>, Nicolas Ferre
 <nicolas.ferre@microchip.com>, Alexandre Belloni
 <alexandre.belloni@bootlin.com>, Claudiu Beznea
 <claudiu.beznea@microchip.com>,  Max Filippov <jcmvbkbc@gmail.com>, Michael
 Turquette <mturquette@baylibre.com>, Stephen Boyd <sboyd@kernel.org>, Luca
 Ceresoli <luca@lucaceresoli.net>, Tudor Ambarus
 <tudor.ambarus@microchip.com>, Herbert Xu <herbert@gondor.apana.org.au>, 
 "David S. Miller" <davem@davemloft.net>, MyungJoo Ham
 <myungjoo.ham@samsung.com>, Chanwoo Choi <cw00.choi@samsung.com>,  Michael
 Hennerich <michael.hennerich@analog.com>, Linus Walleij
 <linus.walleij@linaro.org>, Andrzej Hajda <andrzej.hajda@intel.com>, Neil
 Armstrong <narmstrong@baylibre.com>, Robert Foss <robert.foss@linaro.org>,
 Laurent Pinchart <Laurent.pinchart@ideasonboard.com>,  Jonas Karlman
 <jonas@kwiboo.se>, Jernej Skrabec <jernej.skrabec@gmail.com>, David Airlie
 <airlied@linux.ie>,  Daniel Vetter <daniel@ffwll.ch>, Benson Leung
 <bleung@chromium.org>, Guenter Roeck <groeck@chromium.org>,  Phong LE
 <ple@baylibre.com>, Adrien Grassein <adrien.grassein@gmail.com>, Peter
 Senna Tschudin <peter.senna@gmail.com>, Martin Donnelly
 <martin.donnelly@ge.com>, Martyn Welch <martyn.welch@collabora.co.uk>,
 Douglas Anderson <dianders@chromium.org>,  Stefan Mavrodiev
 <stefan@olimex.com>, Thierry Reding <thierry.reding@gmail.com>, Sam
 Ravnborg <sam@ravnborg.org>, Florian Fainelli <f.fainelli@gmail.com>,
 Broadcom internal kernel review list
 <bcm-kernel-feedback-list@broadcom.com>, Javier Martinez Canillas
 <javierm@redhat.com>, Jiri Kosina <jikos@kernel.org>, Benjamin Tissoires
 <benjamin.tissoires@redhat.com>, Jean Delvare <jdelvare@suse.com>, George
 Joseph <george.joseph@fairview5.com>, Juerg Haefliger <juergh@gmail.com>,
 Riku Voipio <riku.voipio@iki.fi>, Robert Marko <robert.marko@sartura.hr>,
 Luka Perkov <luka.perkov@sartura.hr>, Marc Hulsman <m.hulsman@tudelft.nl>,
 Rudolf Marek <r.marek@assembler.cz>, Peter Rosin <peda@axentia.se>,
 Jonathan Cameron <jic23@kernel.org>, Lars-Peter Clausen <lars@metafoo.de>,
 Dan Robertson <dan@dlrobertson.com>, Rui Miguel Silva <rmfrfs@gmail.com>,
 Tomasz Duszynski <tduszyns@gmail.com>, Kevin Tsai <ktsai@capellamicro.com>,
 Crt Mori <cmo@melexis.com>, Dmitry Torokhov <dmitry.torokhov@gmail.com>,
 Nick Dyer <nick@shmanahar.org>, Bastien Nocera <hadess@hadess.net>, Hans de
 Goede <hdegoede@redhat.com>, Maxime Coquelin <mcoquelin.stm32@gmail.com>,
 Alexandre Torgue <alexandre.torgue@foss.st.com>,  Sakari Ailus
 <sakari.ailus@linux.intel.com>, Pavel Machek <pavel@ucw.cz>, Jan-Simon
 Moeller <jansimon.moeller@gmx.de>, Marek =?ISO-8859-1?Q?Beh=FAn?=
 <kabel@kernel.org>,  Colin Leroy <colin@colino.net>, Joe Tessler
 <jrt@google.com>, Hans Verkuil <hverkuil-cisco@xs4all.nl>,  Mauro Carvalho
 Chehab <mchehab@kernel.org>, Antti Palosaari <crope@iki.fi>, Jasmin Jessich
 <jasmin@anw.at>, Matthias Schwarzott <zzam@gentoo.org>, Olli Salonen
 <olli.salonen@iki.fi>, Akihiro Tsukada <tskd08@gmail.com>, Kieran Bingham
 <kieran.bingham@ideasonboard.com>, Tianshu Qiu <tian.shu.qiu@intel.com>, 
 Dongchun Zhu <dongchun.zhu@mediatek.com>, Shawn Tu <shawnx.tu@intel.com>,
 Martin Kepplinger <martink@posteo.de>, Ricardo Ribalda
 <ribalda@kernel.org>, Dave Stevenson <dave.stevenson@raspberrypi.com>, Leon
 Luo <leonl@leopardimaging.com>,  Manivannan Sadhasivam <mani@kernel.org>,
 Bingbu Cao <bingbu.cao@intel.com>, "Paul J. Murphy"
 <paul.j.murphy@intel.com>, Daniele Alessandrelli
 <daniele.alessandrelli@intel.com>, Michael Tretter
 <m.tretter@pengutronix.de>,  Pengutronix Kernel Team
 <kernel@pengutronix.de>, Kyungmin Park <kyungmin.park@samsung.com>,
 Heungjun Kim <riverful.kim@samsung.com>, Ramesh Shanmugasundaram
 <rashanmu@gmail.com>, Jacopo Mondi <jacopo+renesas@jmondi.org>, Niklas
 =?ISO-8859-1?Q?S=F6derlund?= <niklas.soderlund+renesas@ragnatech.se>, Jimmy
 Su <jimmy.su@intel.com>, Arec Kao <arec.kao@intel.com>, "Lad, Prabhakar"
 <prabhakar.csengg@gmail.com>, Shunqian Zheng <zhengsq@rock-chips.com>,
 Steve Longerbeam <slongerbeam@gmail.com>,  Chiranjeevi Rapolu
 <chiranjeevi.rapolu@intel.com>, Daniel Scally <djrscally@gmail.com>, Wenyou
 Yang <wenyou.yang@microchip.com>, Petr Cvek <petrcvekcz@gmail.com>, Akinobu
 Mita <akinobu.mita@gmail.com>, Sylwester Nawrocki <s.nawrocki@samsung.com>,
  Benjamin Mugnier <benjamin.mugnier@foss.st.com>, Sylvain Petinot
 <sylvain.petinot@foss.st.com>, Mats Randgaard <matrandg@cisco.com>, Tim
 Harvey <tharvey@gateworks.com>, Matt Ranostay <matt.ranostay@konsulko.com>,
 Eduardo Valentin <edubezval@gmail.com>,  "Daniel W. S. Almeida"
 <dwlsalmeida@gmail.com>, Lee Jones <lee.jones@linaro.org>, Chen-Yu Tsai
 <wens@csie.org>, Support Opensource <support.opensource@diasemi.com>,
 Robert Jones <rjones@gateworks.com>, Andy Shevchenko <andy@kernel.org>,
 Charles Keepax <ckeepax@opensource.cirrus.com>, Richard Fitzgerald
 <rf@opensource.cirrus.com>,  Krzysztof Kozlowski
 <krzysztof.kozlowski@linaro.org>, Bartlomiej Zolnierkiewicz
 <b.zolnierkie@samsung.com>, Tony Lindgren <tony@atomide.com>, Jonathan
 =?ISO-8859-1?Q?Neusch=E4fer?= <j.neuschaefer@gmx.net>, Arnd Bergmann
 <arnd@arndb.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Eric Piel
 <eric.piel@tremplin-utc.net>, Miquel Raynal <miquel.raynal@bootlin.com>,
 Richard Weinberger <richard@nod.at>, Vignesh Raghavendra <vigneshr@ti.com>,
 Andrew Lunn <andrew@lunn.ch>, Vivien Didelot <vivien.didelot@gmail.com>,
 Vladimir Oltean <olteanv@gmail.com>, Eric Dumazet <edumazet@google.com>,
 Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, Woojung
 Huh <woojung.huh@microchip.com>,  UNGLinuxDriver@microchip.com, George
 McCollister <george.mccollister@gmail.com>,  Ido Schimmel
 <idosch@nvidia.com>, Petr Machata <petrm@nvidia.com>, Jeremy Kerr
 <jk@codeconstruct.com.au>,  Matt Johnston <matt@codeconstruct.com.au>,
 Charles Gorand <charles.gorand@effinnov.com>, Krzysztof Opasiak
 <k.opasiak@samsung.com>, Rob Herring <robh+dt@kernel.org>, Frank Rowand
 <frowand.list@gmail.com>, Mark Gross <markgross@kernel.org>, Maximilian Luz
 <luzmaximilian@gmail.com>, Corentin Chary <corentin.chary@gmail.com>, Pali
 =?ISO-8859-1?Q?Roh=E1r?= <pali@kernel.org>, Sebastian Reichel
 <sre@kernel.org>, Tobias Schrammm <t.schramm@manjaro.org>, Liam Girdwood
 <lgirdwood@gmail.com>, Mark Brown <broonie@kernel.org>, Alessandro Zummo
 <a.zummo@towertech.it>, Jens Frederich <jfrederich@gmail.com>, Jon
 Nettleton <jon.nettleton@gmail.com>, Jiri Slaby <jirislaby@kernel.org>,
 Felipe Balbi <balbi@kernel.org>, Heikki Krogerus
 <heikki.krogerus@linux.intel.com>, Daniel Thompson
 <daniel.thompson@linaro.org>,  Jingoo Han <jingoohan1@gmail.com>, Helge
 Deller <deller@gmx.de>, Evgeniy Polyakov <zbr@ioremap.net>,  Wim Van
 Sebroeck <wim@linux-watchdog.org>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,  Johannes Berg
 <johannes@sipsolutions.net>, Jaroslav Kysela <perex@perex.cz>, Takashi Iwai
 <tiwai@suse.com>,  James Schulman <james.schulman@cirrus.com>, David Rhodes
 <david.rhodes@cirrus.com>, Lucas Tanure <tanureal@opensource.cirrus.com>,
 Nuno =?ISO-8859-1?Q?S=E1?= <nuno.sa@analog.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, Oder Chiou <oder_chiou@realtek.com>, Fabio
 Estevam <festevam@gmail.com>, Kevin Cernekee <cernekee@chromium.org>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,  Maxime Ripard
 <maxime@cerno.tech>, Alvin =?UTF-8?Q?=C5=A0ipraga?= <alsi@bang-olufsen.dk>,
 Lucas Stach <l.stach@pengutronix.de>, Jagan Teki
 <jagan@amarulasolutions.com>, Biju Das <biju.das.jz@bp.renesas.com>, Thomas
 Zimmermann <tzimmermann@suse.de>, Alex Deucher <alexander.deucher@amd.com>,
 Lyude Paul <lyude@redhat.com>, Xin Ji <xji@analogixsemi.com>,  Hsin-Yi Wang
 <hsinyi@chromium.org>, =?ISO-8859-1?Q?Jos=E9_Exp=F3sito?=
 <jose.exposito89@gmail.com>, Yang Li <yang.lee@linux.alibaba.com>, Angela
 Czubak <acz@semihalf.com>, Alistair Francis <alistair@alistair23.me>, Eddie
 James <eajames@linux.ibm.com>, Joel Stanley <joel@jms.id.au>,  Nathan
 Chancellor <nathan@kernel.org>, Antoniu Miclaus
 <antoniu.miclaus@analog.com>, Alexandru Ardelean <ardeleanalex@gmail.com>,
 Dmitry Rokosov <DDRokosov@sberdevices.ru>, Stephan Gerhold
 <stephan@gerhold.net>, Miaoqian Lin <linmq006@gmail.com>, Gwendal Grignou
 <gwendal@chromium.org>, Yang Yingliang <yangyingliang@huawei.com>, Paul
 Cercueil <paul@crapouillou.net>, Daniel Palmer <daniel@0x0f.com>, Haibo
 Chen <haibo.chen@nxp.com>,  Cai Huoqing <cai.huoqing@linux.dev>, Marek
 Vasut <marex@denx.de>, Jose Cazarin <joseespiriki@gmail.com>,  Dan
 Carpenter <dan.carpenter@oracle.com>, Jean-Baptiste Maneyrol
 <jean-baptiste.maneyrol@tdk.com>, Michael Srba <Michael.Srba@seznam.cz>,
 Nikita Travkin <nikita@trvn.ru>, Maslov Dmitry <maslovdmitry@seeed.cc>,
 Jiri Valek - 2N <valek@2n.cz>, Arnaud Ferraris
 <arnaud.ferraris@collabora.com>, Zheyu Ma <zheyuma97@gmail.com>, Marco
 Felsch <m.felsch@pengutronix.de>, Oliver Graute
 <oliver.graute@kococonnector.com>,  Zheng Yongjun
 <zhengyongjun3@huawei.com>, CGEL ZTE <cgel.zte@gmail.com>, Minghao Chi
 <chi.minghao@zte.com.cn>,  Evgeny Novikov <novikov@ispras.ru>, Sean Young
 <sean@mess.org>, Kirill Shilimanov <kirill.shilimanov@huawei.com>,  Moses
 Christopher Bollavarapu <mosescb.dev@gmail.com>, Paul Kocialkowski
 <paul.kocialkowski@bootlin.com>,  Janusz Krzysztofik <jmkrzyszt@gmail.com>,
 Dongliang Mu <mudongliangabcd@gmail.com>, Colin Ian King
 <colin.king@intel.com>, lijian <lijian@yulong.com>, Kees Cook
 <keescook@chromium.org>, Yan Lei <yan_lei@dahuatech.com>, Heiner Kallweit
 <hkallweit1@gmail.com>, Jonas Malaco <jonas@protocubo.io>, wengjianfeng
 <wengjianfeng@yulong.com>, Rikard Falkeborn <rikard.falkeborn@gmail.com>, 
 Wei Yongjun <weiyongjun1@huawei.com>, Tom Rix <trix@redhat.com>, Yizhuo
 <yzhai003@ucr.edu>, Martiros Shakhzadyan <vrzh@vrzh.net>, Bjorn Andersson
 <bjorn.andersson@linaro.org>, Sven Peter <sven@svenpeter.dev>,  Alyssa
 Rosenzweig <alyssa@rosenzweig.io>, Hector Martin <marcan@marcan.st>,
 Saranya Gopal <saranya.gopal@intel.com>,  Guido =?ISO-8859-1?Q?G=FCnther?=
 <agx@sigxcpu.org>, Sing-Han Chen <singhanc@nvidia.com>, Wayne Chang
 <waynec@nvidia.com>, Geert Uytterhoeven <geert@linux-m68k.org>, Alexey
 Dobriyan <adobriyan@gmail.com>, Masahiro Yamada <masahiroy@kernel.org>,
 Vincent Knecht <vincent.knecht@mailoo.org>, Stephen Kitt <steve@sk2.org>,
 Pierre-Louis Bossart <pierre-louis.bossart@linux.intel.com>, Alexey
 Khoroshilov <khoroshilov@ispras.ru>, Randy Dunlap <rdunlap@infradead.org>,
 Alejandro Tafalla <atafalla@dnyon.com>, Vijendar Mukunda
 <Vijendar.Mukunda@amd.com>, Seven Lee <wtli@nuvoton.com>, Mac Chiang
 <mac.chiang@intel.com>, David Lin <CTLIN0@nuvoton.com>, Daniel Beer
 <daniel.beer@igorinstitute.com>, Ricard Wanderlof <ricardw@axis.com>, Simon
 Trimmer <simont@opensource.cirrus.com>, Shengjiu Wang
 <shengjiu.wang@nxp.com>, Viorel Suman <viorel.suman@nxp.com>, Nicola Lunghi
 <nick83ola@gmail.com>, Adam Ford <aford173@gmail.com>, 
 linux-i2c@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
 linuxppc-dev@lists.ozlabs.org, openipmi-developer@lists.sourceforge.net, 
 linux-integrity@vger.kernel.org, linux-clk@vger.kernel.org, 
 linux-crypto@vger.kernel.org, linux-gpio@vger.kernel.org, 
 dri-devel@lists.freedesktop.org, chrome-platform@lists.linux.dev, 
 linux-rpi-kernel@lists.infradead.org, linux-input@vger.kernel.org, 
 linux-hwmon@vger.kernel.org, linux-iio@vger.kernel.org, 
 linux-stm32@st-md-mailman.stormreply.com, linux-leds@vger.kernel.org, 
 linux-media@vger.kernel.org, patches@opensource.cirrus.com, 
 alsa-devel@alsa-project.org, linux-omap@vger.kernel.org, 
 linux-mtd@lists.infradead.org, netdev@vger.kernel.org, 
 devicetree@vger.kernel.org, platform-driver-x86@vger.kernel.org, 
 acpi4asus-user@lists.sourceforge.net, linux-pm@vger.kernel.org, 
 linux-pwm@vger.kernel.org, linux-rtc@vger.kernel.org, 
 linux-staging@lists.linux.dev, linux-serial@vger.kernel.org, 
 linux-usb@vger.kernel.org, linux-fbdev@vger.kernel.org, 
 linux-watchdog@vger.kernel.org, kasan-dev@googlegroups.com, 
 linux-mediatek@lists.infradead.org
Date: Wed, 29 Jun 2022 07:31:08 -0700
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
	 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.42.4 (3.42.4-2.fc35)
MIME-Version: 1.0
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: srinivas.pandruvada@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=i0npVKk7;       spf=pass
 (google.com: best guess record for domain of srinivas.pandruvada@linux.intel.com
 designates 192.55.52.88 as permitted sender) smtp.mailfrom=srinivas.pandruvada@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On Tue, 2022-06-28 at 16:03 +0200, Uwe Kleine-K=C3=B6nig wrote:
> From: Uwe Kleine-K=C3=B6nig <uwe@kleine-koenig.org>
>=20
> The value returned by an i2c driver's remove function is mostly
> ignored.
> (Only an error message is printed if the value is non-zero that the
> error is ignored.)
>=20
> So change the prototype of the remove function to return no value.
> This
> way driver authors are not tempted to assume that passing an error to
> the upper layer is a good idea. All drivers are adapted accordingly.
> There is no intended change of behaviour, all callbacks were prepared
> to
> return 0 before.
>=20
> Signed-off-by: Uwe Kleine-K=C3=B6nig <u.kleine-koenig@pengutronix.de>

For
 drivers/iio/accel/bmc150-accel-i2c.c                      | 4 +---
 drivers/iio/accel/kxcjk-1013.c                            | 4 +---

Acked-by: Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>

Thanks,
Srinivas

> ---
> =C2=A0Documentation/i2c/writing-clients.rst=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 2 +-
> =C2=A0arch/arm/mach-davinci/board-dm644x-evm.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0arch/arm/mach-davinci/board-dm646x-evm.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0arch/powerpc/platforms/83xx/mcu_mpc8349emitx.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/auxdisplay/ht16k33.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/auxdisplay/lcd2s.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/char/ipmi/ipmb_dev_int.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/char/ipmi/ipmi_ipmb.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/char/ipmi/ipmi_ssif.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/char/tpm/st33zp24/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/char/tpm/tpm_i2c_atmel.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/char/tpm/tpm_i2c_infineon.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/char/tpm/tpm_i2c_nuvoton.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/char/tpm/tpm_tis_i2c_cr50.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/clk/clk-cdce706.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0drivers/clk/clk-cs2000-cp.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/clk/clk-si514.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/clk/clk-si5341.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/clk/clk-si5351.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/clk/clk-si570.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/clk/clk-versaclock5.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/crypto/atmel-ecc.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
6 ++----
> =C2=A0drivers/crypto/atmel-sha204a.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/extcon/extcon-rt8973a.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpio/gpio-adp5588.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpio/gpio-max7300.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpio/gpio-pca953x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpio/gpio-pcf857x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpio/gpio-tpic2810.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/adv7511/adv7511_drv.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/analogix/analogix-anx6345.c=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/analogix/analogix-anx78xx.c=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/analogix/anx7625.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/gpu/drm/bridge/chrontel-ch7033.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/cros-ec-anx7688.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/ite-it6505.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/ite-it66121.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/lontium-lt8912b.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0drivers/gpu/drm/bridge/lontium-lt9211.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/lontium-lt9611.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/lontium-lt9611uxc.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c=C2=A0 | 8 =
++----
> --
> =C2=A0drivers/gpu/drm/bridge/nxp-ptn3460.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/parade-ps8622.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/parade-ps8640.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/sii902x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/sii9234.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/sil-sii8620.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/tc358767.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/tc358768.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/tc358775.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/ti-sn65dsi83.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/bridge/ti-tfp410.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/i2c/ch7006_drv.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/i2c/tda9950.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/i2c/tda998x_drv.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/gpu/drm/panel/panel-olimex-lcd-olinuxino.c=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/panel/panel-raspberrypi-touchscreen.c=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/gpu/drm/solomon/ssd130x-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/hid/i2c-hid/i2c-hid-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/hid/i2c-hid/i2c-hid.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 2 +-
> =C2=A0drivers/hwmon/adc128d818.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/hwmon/adt7470.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/hwmon/asb100.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/hwmon/asc7621.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/hwmon/dme1737.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/hwmon/f75375s.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 5 ++---
> =C2=A0drivers/hwmon/fschmd.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/hwmon/ftsteutates.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/hwmon/ina209.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/hwmon/ina3221.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/hwmon/jc42.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/hwmon/mcp3021.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/hwmon/occ/p8_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/hwmon/pcf8591.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/hwmon/smm665.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/hwmon/tps23861.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/hwmon/w83781d.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/hwmon/w83791d.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/hwmon/w83792d.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/hwmon/w83793.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/hwmon/w83795.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/hwmon/w83l785ts.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 6 ++----
> =C2=A0drivers/i2c/i2c-core-base.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 6 +---=
--
> =C2=A0drivers/i2c/i2c-slave-eeprom.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/i2c/i2c-slave-testunit.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/i2c/i2c-smbus.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/i2c/muxes/i2c-mux-ltc4306.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/i2c/muxes/i2c-mux-pca9541.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/i2c/muxes/i2c-mux-pca954x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/iio/accel/bma180.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/iio/accel/bma400_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/bmc150-accel-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/kxcjk-1013.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/kxsd9-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/mc3230.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/iio/accel/mma7455_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/mma7660.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/mma8452.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/mma9551.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/mma9553.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/stk8312.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/accel/stk8ba50.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/adc/ad799x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/iio/adc/ina2xx-adc.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/adc/ltc2497.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/iio/adc/ti-ads1015.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/chemical/atlas-sensor.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/chemical/ccs811.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/chemical/sgp30.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/dac/ad5380.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/iio/dac/ad5446.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/iio/dac/ad5593r.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/iio/dac/ad5696-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/dac/ds4424.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/iio/dac/m62332.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/iio/dac/mcp4725.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/iio/dac/ti-dac5571.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/gyro/bmg160_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/gyro/fxas21002c_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/gyro/itg3200_core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/gyro/mpu3050-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/health/afe4404.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/health/max30100.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/health/max30102.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/humidity/hdc2010.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/imu/inv_mpu6050/inv_mpu_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/iio/imu/kmx61.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/apds9300.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/apds9960.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/bh1750.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/iio/light/bh1780.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/iio/light/cm3232.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/iio/light/cm36651.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/gp2ap002.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/gp2ap020a00f.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/isl29028.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/isl29125.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/jsa1212.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/ltr501.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/iio/light/opt3001.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 6 ++--=
--
> =C2=A0drivers/iio/light/pa12203001.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/rpr0521.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/stk3310.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/tcs3472.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/tsl2563.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/tsl2583.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/tsl4531.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/us5182d.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/vcnl4000.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/vcnl4035.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/light/veml6070.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/magnetometer/ak8974.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/magnetometer/ak8975.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/magnetometer/bmc150_magn_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/magnetometer/hmc5843_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/magnetometer/mag3110.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/magnetometer/yamaha-yas530.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/iio/potentiostat/lmp91000.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/pressure/mpl3115.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/pressure/ms5611_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/pressure/zpa2326_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/proximity/pulsedlight-lidar-lite-v2.c=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/proximity/sx9500.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/temperature/mlx90614.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/iio/temperature/mlx90632.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/joystick/as5011.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/keyboard/adp5588-keys.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/keyboard/lm8323.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/keyboard/lm8333.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/keyboard/mcs_touchkey.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/keyboard/qt1070.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/keyboard/qt2160.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/keyboard/tca6416-keypad.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/input/misc/adxl34x-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/misc/bma150.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/misc/cma3000_d0x_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/misc/pcf8574_keypad.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/mouse/synaptics_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/rmi4/rmi_smbus.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/touchscreen/atmel_mxt_ts.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/input/touchscreen/bu21013_ts.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/touchscreen/cyttsp4_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/input/touchscreen/edt-ft5x06.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/touchscreen/goodix.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/touchscreen/migor_ts.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/touchscreen/s6sy761.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/touchscreen/stmfts.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/input/touchscreen/tsc2004.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/leds/flash/leds-as3645a.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/leds/flash/leds-lm3601x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/leds/flash/leds-rt4505.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/leds/leds-an30259a.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/leds/leds-aw2013.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-bd2802.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-blinkm.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/leds/leds-is31fl319x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/leds/leds-is31fl32xx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/leds/leds-lm3530.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/leds/leds-lm3532.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lm355x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lm3642.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/leds/leds-lm3692x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/leds/leds-lm3697.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lp3944.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lp3952.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lp50xx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lp5521.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lp5523.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lp5562.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lp8501.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-lp8860.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/leds/leds-pca9532.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 6 ++--=
--
> =C2=A0drivers/leds/leds-tca6507.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/leds/leds-turris-omnia.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/macintosh/ams/ams-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/macintosh/therm_adt746x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/macintosh/therm_windtunnel.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/macintosh/windfarm_ad7417_sensor.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/macintosh/windfarm_fcu_controls.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/macintosh/windfarm_lm75_sensor.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/macintosh/windfarm_lm87_sensor.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/macintosh/windfarm_max6690_sensor.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/macintosh/windfarm_smu_sat.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/cec/i2c/ch7322.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/a8293.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/af9013.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/af9033.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/au8522_decoder.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/cxd2099.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/cxd2820r_core.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/dvb-pll.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/lgdt3306a.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/lgdt330x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/m88ds3103.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/mn88443x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/mn88472.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/mn88473.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/mxl692.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/rtl2830.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/rtl2832.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/si2165.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/si2168.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/dvb-frontends/sp2.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/stv090x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/stv6110x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/tc90522.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/tda10071.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/dvb-frontends/ts2020.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/ad5820.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/ad9389b.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/adp1653.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/adv7170.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/adv7175.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/adv7180.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/adv7183.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/adv7343.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/adv7393.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/adv748x/adv748x-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/media/i2c/adv7511-v4l2.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/adv7604.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/adv7842.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/ak7375.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ak881x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/bt819.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0drivers/media/i2c/bt856.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0drivers/media/i2c/bt866.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0drivers/media/i2c/ccs/ccs-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/cs3308.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/cs5345.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/cs53l32a.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/cx25840/cx25840-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0drivers/media/i2c/dw9714.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/dw9768.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/dw9807-vcm.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/et8ek8/et8ek8_driver.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/media/i2c/hi556.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/media/i2c/hi846.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/media/i2c/hi847.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/media/i2c/imx208.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/imx214.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/imx219.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/imx258.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/imx274.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/imx290.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/imx319.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/imx334.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/imx335.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/imx355.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/imx412.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ir-kbd-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/isl7998x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/ks0127.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/lm3560.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/lm3646.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/m52790.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/m5mols/m5mols_core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/max2175.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/max9286.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/ml86v7667.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/msp3400-driver.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/mt9m001.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/mt9m032.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/mt9m111.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/mt9p031.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/mt9t001.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/mt9t112.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/mt9v011.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/mt9v032.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/mt9v111.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/noon010pc30.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/og01a1b.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/ov02a10.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/ov08d10.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/ov13858.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/ov13b10.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/ov2640.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/ov2659.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov2680.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov2685.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov2740.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov5640.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov5645.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov5647.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov5648.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov5670.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov5675.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov5693.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov5695.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov6650.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/ov7251.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov7640.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov7670.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/ov772x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov7740.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/ov8856.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov8865.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov9282.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov9640.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov9650.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/ov9734.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/rdacm20.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/rdacm21.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/rj54n1cb0c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/s5c73m3/s5c73m3-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/media/i2c/s5k4ecgx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/s5k5baf.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/s5k6a3.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/s5k6aa.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/saa6588.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/saa6752hs.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/saa7110.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/saa7115.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/saa7127.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/saa717x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/saa7185.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/sony-btf-mpx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/sr030pc30.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/st-mipid02.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/tc358743.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/tda1997x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/tda7432.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/tda9840.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/tea6415c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/tea6420.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/ths7303.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/ths8200.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/tlv320aic23b.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/tvaudio.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/tvp514x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/tvp5150.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/tvp7002.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/tw2804.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/tw9903.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/tw9906.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/tw9910.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/media/i2c/uda1342.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/upd64031a.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/upd64083.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/video-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/vp27smpx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/i2c/vpx3220.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/i2c/vs6624.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/wm8739.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/i2c/wm8775.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/media/radio/radio-tea5764.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/radio/saa7706h.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/radio/si470x/radio-si470x-i2c.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/radio/si4713/si4713.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/radio/tef6862.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/test-drivers/vidtv/vidtv_demod.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/test-drivers/vidtv/vidtv_tuner.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/tuners/e4000.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/tuners/fc2580.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/tuners/m88rs6000t.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/tuners/mt2060.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/tuners/mxl301rf.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/tuners/qm1d1b0004.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/tuners/qm1d1c0042.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/tuners/si2157.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/tuners/tda18212.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/tuners/tda18250.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/media/tuners/tua9001.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/usb/go7007/s2250-board.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/media/v4l2-core/tuner-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/mfd/88pm800.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/88pm805.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/88pm860x-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/mfd/acer-ec-a500.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/mfd/arizona-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/mfd/axp20x-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/mfd/da903x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/mfd/da9052-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 3 +--
> =C2=A0drivers/mfd/da9055-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/mfd/da9062-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/mfd/da9150-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/mfd/dm355evm_msp.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/mfd/ene-kb3930.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/mfd/gateworks-gsc.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/intel_soc_pmic_core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/iqs62x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/lm3533-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/mfd/lp8788.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/mfd/madera-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/mfd/max14577.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/max77693.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/max8907.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/max8925-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0drivers/mfd/mc13xxx-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0drivers/mfd/menelaus.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/mfd/ntxec.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/palmas.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/pcf50633-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/retu-mfd.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/rk808.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/rn5t618.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/rsmu_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/rt4831.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/si476x-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/mfd/stmfx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/stmpe-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/tc3589x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/tps6105x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/tps65010.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/mfd/tps65086.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/tps65217.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/tps6586x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/mfd/tps65912-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/mfd/twl-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/mfd/twl6040.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mfd/wm8994-core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/misc/ad525x_dpot-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/misc/apds9802als.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/misc/apds990x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/misc/bh1770glc.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/misc/ds1682.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/misc/eeprom/at24.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/misc/eeprom/ee1004.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/misc/eeprom/eeprom.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/misc/eeprom/idt_89hpesx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/misc/eeprom/max6875.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/misc/hmc6352.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/misc/ics932s401.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 5 ++---
> =C2=A0drivers/misc/isl29003.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/misc/isl29020.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/misc/lis3lv02d/lis3lv02d_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/misc/tsl2550.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/mtd/maps/pismo.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/net/dsa/lan9303_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/net/dsa/microchip/ksz9477_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/net/dsa/xrs700x/xrs700x_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/net/ethernet/mellanox/mlxsw/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/net/mctp/mctp-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/nfc/fdp/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/nfc/microread/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/nfc/nfcmrvl/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/nfc/nxp-nci/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/nfc/pn533/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/nfc/pn544/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/nfc/s3fwrn5/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/nfc/st-nci/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/nfc/st21nfca/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/of/unittest.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0drivers/platform/chrome/cros_ec_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/platform/surface/surface3_power.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/platform/x86/asus-tf103c-dock.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/platform/x86/intel/int3472/tps68470.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/bq2415x_charger.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/bq24190_charger.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/bq24257_charger.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/bq25890_charger.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/bq27xxx_battery_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/cw2015_battery.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/power/supply/ds2782_battery.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/lp8727_charger.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/power/supply/rt5033_battery.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/rt9455_charger.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/smb347-charger.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/power/supply/z2_battery.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/pwm/pwm-pca9685.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0drivers/regulator/da9121-regulator.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/regulator/lp8755.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/regulator/rpi-panel-attiny-regulator.c=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/rtc/rtc-bq32k.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/rtc/rtc-ds1374.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/rtc/rtc-isl12026.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0drivers/rtc/rtc-m41t80.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0drivers/rtc/rtc-rs5c372.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0drivers/rtc/rtc-x1205.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/staging/media/atomisp/i2c/atomisp-gc0310.c=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/staging/media/atomisp/i2c/atomisp-gc2235.c=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/staging/media/atomisp/i2c/atomisp-lm3554.c=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/staging/media/atomisp/i2c/atomisp-mt9m114.c=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/staging/media/atomisp/i2c/atomisp-ov2680.c=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/staging/media/atomisp/i2c/atomisp-ov2722.c=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/staging/media/atomisp/i2c/ov5693/atomisp-ov5693.c | 4 +---
> =C2=A0drivers/staging/media/max96712/max96712.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/staging/most/i2c/i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/staging/olpc_dcon/olpc_dcon.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/tty/serial/sc16is7xx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/misc/usb3503.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/usb/phy/phy-isp1301-omap.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/phy/phy-isp1301.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/typec/hd3ss3220.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/typec/mux/fsa4480.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/typec/mux/pi3usb30532.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/usb/typec/rt1719.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0drivers/usb/typec/stusb160x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/typec/tcpm/fusb302.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/typec/tcpm/tcpci.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/typec/tcpm/tcpci_maxim.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/typec/tcpm/tcpci_rt1711h.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/usb/typec/tipd/core.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/typec/ucsi/ucsi_ccg.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/usb/typec/wusb3801.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/video/backlight/adp8860_bl.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/video/backlight/adp8870_bl.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/video/backlight/arcxcnn_bl.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/video/backlight/bd6107.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/video/backlight/lm3630a_bl.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/video/backlight/lm3639_bl.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/video/backlight/lp855x_bl.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/video/backlight/lv5207lp.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/video/backlight/tosa_bl.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/video/fbdev/matrox/matroxfb_maven.c=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/video/fbdev/ssd1307fb.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0drivers/w1/masters/ds2482.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0drivers/watchdog/ziirave_wdt.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0include/linux/i2c.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 2 +-
> =C2=A0lib/Kconfig.kasan=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 1 +
> =C2=A0sound/aoa/codecs/onyx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0 | 3 +--
> =C2=A0sound/aoa/codecs/tas.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0sound/pci/hda/cs35l41_hda_i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/ppc/keywest.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 6 ++----
> =C2=A0sound/soc/codecs/adau1761-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0sound/soc/codecs/adau1781-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0sound/soc/codecs/ak4375.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/ak4458.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/ak4641.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/ak5558.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/cs35l32.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/cs35l33.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/cs35l34.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/cs35l35.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/cs35l36.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/cs35l41-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/cs35l45-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/cs4234.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/cs4265.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/cs4270.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/cs42l42.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/cs42l51-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/cs42l56.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0sound/soc/codecs/cs42xx8-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/cs43130.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/cs4349.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/cs53l30.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/cx2072x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0sound/soc/codecs/max98090.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/max9860.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0sound/soc/codecs/max98927.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/mt6660.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0sound/soc/codecs/nau8821.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/nau8825.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
6 ++----
> =C2=A0sound/soc/codecs/pcm1789-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/pcm3168a-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/pcm512x-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0sound/soc/codecs/rt274.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/rt286.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/rt298.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/rt5616.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 6 ++----
> =C2=A0sound/soc/codecs/rt5631.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 6 ++----
> =C2=A0sound/soc/codecs/rt5645.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/rt5663.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/rt5670.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/rt5677.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/rt5682-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/rt5682s.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/rt9120.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0sound/soc/codecs/sgtl5000.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/sta350.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 6 ++----
> =C2=A0sound/soc/codecs/tas2552.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
3 +--
> =C2=A0sound/soc/codecs/tas5086.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
6 ++----
> =C2=A0sound/soc/codecs/tas571x.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/tas5805m.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0sound/soc/codecs/tas6424.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | =
4 +---
> =C2=A0sound/soc/codecs/tlv320adc3xxx.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0sound/soc/codecs/tlv320aic32x4-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/tlv320aic3x-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/tlv320dac33.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/wm1250-ev1.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 4 +---
> =C2=A0sound/soc/codecs/wm2200.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/wm5100.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/wm8804-i2c.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 3 +--
> =C2=A0sound/soc/codecs/wm8900.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 6 ++----
> =C2=A0sound/soc/codecs/wm8903.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/wm8960.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 6 ++----
> =C2=A0sound/soc/codecs/wm8962.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 3 +--
> =C2=A0sound/soc/codecs/wm8993.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/wm8996.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 4 +---
> =C2=A0sound/soc/codecs/wm9081.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 6 ++----
> =C2=A0621 files changed, 648 insertions(+), 1735 deletions(-)
>=20
> diff --git a/Documentation/i2c/writing-clients.rst
> b/Documentation/i2c/writing-clients.rst
> index e3b126cf4a3b..c1b46844b0fb 100644
> --- a/Documentation/i2c/writing-clients.rst
> +++ b/Documentation/i2c/writing-clients.rst
> @@ -156,7 +156,7 @@ those devices, and a remove() method to unbind.
> =C2=A0::
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0static int foo_probe(stru=
ct i2c_client *client);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0static int foo_remove(struct i=
2c_client *client);
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0static void foo_remove(struct =
i2c_client *client);
> =C2=A0
> =C2=A0Remember that the i2c_driver does not create those client handles.=
=C2=A0
> The
> =C2=A0handle may be used during foo_probe().=C2=A0 If foo_probe() reports
> success
> diff --git a/arch/arm/mach-davinci/board-dm644x-evm.c
> b/arch/arm/mach-davinci/board-dm644x-evm.c
> index 9f405af36a6f..9055da325a3f 100644
> --- a/arch/arm/mach-davinci/board-dm644x-evm.c
> +++ b/arch/arm/mach-davinci/board-dm644x-evm.c
> @@ -554,10 +554,9 @@ static int dm6446evm_msp_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int dm6446evm_msp_remove(struct i2c_client *client)
> +static void dm6446evm_msp_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dm6446evm_msp =3D NULL;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id dm6446evm_msp_ids[] =3D {
> diff --git a/arch/arm/mach-davinci/board-dm646x-evm.c
> b/arch/arm/mach-davinci/board-dm646x-evm.c
> index 84ad065e98c2..287bb5833ec0 100644
> --- a/arch/arm/mach-davinci/board-dm646x-evm.c
> +++ b/arch/arm/mach-davinci/board-dm646x-evm.c
> @@ -403,10 +403,9 @@ static int cpld_video_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int cpld_video_remove(struct i2c_client *client)
> +static void cpld_video_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cpld_client =3D NULL;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cpld_video_id[] =3D {
> diff --git a/arch/powerpc/platforms/83xx/mcu_mpc8349emitx.c
> b/arch/powerpc/platforms/83xx/mcu_mpc8349emitx.c
> index abb62fa630ef..77ed61306a73 100644
> --- a/arch/powerpc/platforms/83xx/mcu_mpc8349emitx.c
> +++ b/arch/powerpc/platforms/83xx/mcu_mpc8349emitx.c
> @@ -178,7 +178,7 @@ static int mcu_probe(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mcu_remove(struct i2c_client *client)
> +static void mcu_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mcu *mcu =3D i2c_g=
et_clientdata(client);
> =C2=A0
> @@ -193,7 +193,6 @@ static int mcu_remove(struct i2c_client *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mcu_gpiochip_remove(mcu);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(mcu);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mcu_ids[] =3D {
> diff --git a/drivers/auxdisplay/ht16k33.c
> b/drivers/auxdisplay/ht16k33.c
> index 4fab3b2c7023..02425991c159 100644
> --- a/drivers/auxdisplay/ht16k33.c
> +++ b/drivers/auxdisplay/ht16k33.c
> @@ -775,7 +775,7 @@ static int ht16k33_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int ht16k33_remove(struct i2c_client *client)
> +static void ht16k33_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ht16k33_priv *priv=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ht16k33_fbdev *fbd=
ev =3D &priv->fbdev;
> @@ -796,8 +796,6 @@ static int ht16k33_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0device_remove_file(&client->dev,
> &dev_attr_map_seg14);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0break;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ht16k33_i2c_match[] =3D {
> diff --git a/drivers/auxdisplay/lcd2s.c b/drivers/auxdisplay/lcd2s.c
> index e465108d9998..135831a16514 100644
> --- a/drivers/auxdisplay/lcd2s.c
> +++ b/drivers/auxdisplay/lcd2s.c
> @@ -340,13 +340,12 @@ static int lcd2s_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int lcd2s_i2c_remove(struct i2c_client *i2c)
> +static void lcd2s_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lcd2s_data *lcd2s =
=3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0charlcd_unregister(lcd2s-=
>charlcd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0charlcd_free(lcd2s->charl=
cd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lcd2s_i2c_id[] =3D {
> diff --git a/drivers/char/ipmi/ipmb_dev_int.c
> b/drivers/char/ipmi/ipmb_dev_int.c
> index db40037eb347..a0e9e80d92ee 100644
> --- a/drivers/char/ipmi/ipmb_dev_int.c
> +++ b/drivers/char/ipmi/ipmb_dev_int.c
> @@ -341,14 +341,12 @@ static int ipmb_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ipmb_remove(struct i2c_client *client)
> +static void ipmb_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ipmb_dev *ipmb_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_slave_unregister(clie=
nt);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0misc_deregister(&ipmb_dev=
->miscdev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ipmb_id[] =3D {
> diff --git a/drivers/char/ipmi/ipmi_ipmb.c
> b/drivers/char/ipmi/ipmi_ipmb.c
> index ab19b4b3317e..25c010c9ec25 100644
> --- a/drivers/char/ipmi/ipmi_ipmb.c
> +++ b/drivers/char/ipmi/ipmi_ipmb.c
> @@ -424,7 +424,7 @@ static void ipmi_ipmb_request_events(void
> *send_info)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* We don't fetch events =
here. */
> =C2=A0}
> =C2=A0
> -static int ipmi_ipmb_remove(struct i2c_client *client)
> +static void ipmi_ipmb_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ipmi_ipmb_dev *iid=
ev =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -438,8 +438,6 @@ static int ipmi_ipmb_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ipmi_ipmb_stop_thread(iid=
ev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ipmi_unregister_smi(iidev=
->intf);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ipmi_ipmb_probe(struct i2c_client *client)
> diff --git a/drivers/char/ipmi/ipmi_ssif.c
> b/drivers/char/ipmi/ipmi_ssif.c
> index fc742ee9c046..13da021e7c6b 100644
> --- a/drivers/char/ipmi/ipmi_ssif.c
> +++ b/drivers/char/ipmi/ipmi_ssif.c
> @@ -1281,13 +1281,13 @@ static void shutdown_ssif(void *send_info)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0}
> =C2=A0
> -static int ssif_remove(struct i2c_client *client)
> +static void ssif_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ssif_info *ssif_in=
fo =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ssif_addr_info *ad=
dr_info;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!ssif_info)
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/*
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * After this point, we w=
on't deliver anything asychronously
> @@ -1303,8 +1303,6 @@ static int ssif_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(ssif_info);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int read_response(struct i2c_client *client, unsigned char
> *resp)
> diff --git a/drivers/char/tpm/st33zp24/i2c.c
> b/drivers/char/tpm/st33zp24/i2c.c
> index 3170d59d660c..a3aa411389e7 100644
> --- a/drivers/char/tpm/st33zp24/i2c.c
> +++ b/drivers/char/tpm/st33zp24/i2c.c
> @@ -264,13 +264,11 @@ static int st33zp24_i2c_probe(struct i2c_client
> *client,
> =C2=A0 * @param: client, the i2c_client description (TPM I2C description)=
.
> =C2=A0 * @return: 0 in case of success.
> =C2=A0 */
> -static int st33zp24_i2c_remove(struct i2c_client *client)
> +static void st33zp24_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tpm_chip *chip =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0st33zp24_remove(chip);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id st33zp24_i2c_id[] =3D {
> diff --git a/drivers/char/tpm/tpm_i2c_atmel.c
> b/drivers/char/tpm/tpm_i2c_atmel.c
> index d5ac85558214..4be3677c1463 100644
> --- a/drivers/char/tpm/tpm_i2c_atmel.c
> +++ b/drivers/char/tpm/tpm_i2c_atmel.c
> @@ -179,12 +179,11 @@ static int i2c_atmel_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return tpm_chip_register(=
chip);
> =C2=A0}
> =C2=A0
> -static int i2c_atmel_remove(struct i2c_client *client)
> +static void i2c_atmel_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &(=
client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tpm_chip *chip =3D=
 dev_get_drvdata(dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tpm_chip_unregister(chip)=
;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id i2c_atmel_id[] =3D {
> diff --git a/drivers/char/tpm/tpm_i2c_infineon.c
> b/drivers/char/tpm/tpm_i2c_infineon.c
> index a19d32cb4e94..fd3c3661e646 100644
> --- a/drivers/char/tpm/tpm_i2c_infineon.c
> +++ b/drivers/char/tpm/tpm_i2c_infineon.c
> @@ -706,15 +706,13 @@ static int tpm_tis_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rc;
> =C2=A0}
> =C2=A0
> -static int tpm_tis_i2c_remove(struct i2c_client *client)
> +static void tpm_tis_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tpm_chip *chip =3D=
 tpm_dev.chip;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tpm_chip_unregister(chip)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0release_locality(chip, tp=
m_dev.locality, 1);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tpm_dev.client =3D NULL;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver tpm_tis_i2c_driver =3D {
> diff --git a/drivers/char/tpm/tpm_i2c_nuvoton.c
> b/drivers/char/tpm/tpm_i2c_nuvoton.c
> index b77c18e38662..95c37350cc8e 100644
> --- a/drivers/char/tpm/tpm_i2c_nuvoton.c
> +++ b/drivers/char/tpm/tpm_i2c_nuvoton.c
> @@ -622,12 +622,11 @@ static int i2c_nuvoton_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return tpm_chip_register(=
chip);
> =C2=A0}
> =C2=A0
> -static int i2c_nuvoton_remove(struct i2c_client *client)
> +static void i2c_nuvoton_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tpm_chip *chip =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tpm_chip_unregister(chip)=
;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id i2c_nuvoton_id[] =3D {
> diff --git a/drivers/char/tpm/tpm_tis_i2c_cr50.c
> b/drivers/char/tpm/tpm_tis_i2c_cr50.c
> index 974479a1ec5a..77cea5b31c6e 100644
> --- a/drivers/char/tpm/tpm_tis_i2c_cr50.c
> +++ b/drivers/char/tpm/tpm_tis_i2c_cr50.c
> @@ -763,20 +763,18 @@ static int tpm_cr50_i2c_probe(struct i2c_client
> *client)
> =C2=A0 * - 0:=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0Success.
> =C2=A0 * - -errno:=C2=A0=C2=A0=C2=A0A POSIX error code.
> =C2=A0 */
> -static int tpm_cr50_i2c_remove(struct i2c_client *client)
> +static void tpm_cr50_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tpm_chip *chip =3D=
 i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &c=
lient->dev;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!chip) {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_crit(dev, "Could not get client data at remove,
> memory corruption ahead\n");
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tpm_chip_unregister(chip)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tpm_cr50_release_locality=
(chip, true);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static SIMPLE_DEV_PM_OPS(cr50_i2c_pm, tpm_pm_suspend,
> tpm_pm_resume);
> diff --git a/drivers/clk/clk-cdce706.c b/drivers/clk/clk-cdce706.c
> index 5467d941ddfd..1449d0537674 100644
> --- a/drivers/clk/clk-cdce706.c
> +++ b/drivers/clk/clk-cdce706.c
> @@ -665,10 +665,9 @@ static int cdce706_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 cdce);
> =C2=A0}
> =C2=A0
> -static int cdce706_remove(struct i2c_client *client)
> +static void cdce706_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_clk_del_provider(clien=
t->dev.of_node);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/clk/clk-cs2000-cp.c b/drivers/clk/clk-cs2000-
> cp.c
> index aa5c72bab83e..320d39922206 100644
> --- a/drivers/clk/clk-cs2000-cp.c
> +++ b/drivers/clk/clk-cs2000-cp.c
> @@ -557,7 +557,7 @@ static int cs2000_version_print(struct
> cs2000_priv *priv)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int cs2000_remove(struct i2c_client *client)
> +static void cs2000_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs2000_priv *priv =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D pr=
iv_to_dev(priv);
> @@ -566,8 +566,6 @@ static int cs2000_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_clk_del_provider(np);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0clk_hw_unregister(&priv->=
hw);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int cs2000_probe(struct i2c_client *client)
> diff --git a/drivers/clk/clk-si514.c b/drivers/clk/clk-si514.c
> index 4481c4303534..c028fa103bed 100644
> --- a/drivers/clk/clk-si514.c
> +++ b/drivers/clk/clk-si514.c
> @@ -370,10 +370,9 @@ static int si514_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int si514_remove(struct i2c_client *client)
> +static void si514_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_clk_del_provider(clien=
t->dev.of_node);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id si514_id[] =3D {
> diff --git a/drivers/clk/clk-si5341.c b/drivers/clk/clk-si5341.c
> index 4bca73212662..0e528d7ba656 100644
> --- a/drivers/clk/clk-si5341.c
> +++ b/drivers/clk/clk-si5341.c
> @@ -1796,7 +1796,7 @@ static int si5341_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int si5341_remove(struct i2c_client *client)
> +static void si5341_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct clk_si5341 *data =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -1807,8 +1807,6 @@ static int si5341_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0if (data->clk[i].vddo_reg)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0reg=
ulator_disable(data->clk[i].vddo_reg);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id si5341_id[] =3D {
> diff --git a/drivers/clk/clk-si5351.c b/drivers/clk/clk-si5351.c
> index b9f088c4ba2f..9e939c98a455 100644
> --- a/drivers/clk/clk-si5351.c
> +++ b/drivers/clk/clk-si5351.c
> @@ -1651,11 +1651,9 @@ static int si5351_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int si5351_i2c_remove(struct i2c_client *client)
> +static void si5351_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_clk_del_provider(clien=
t->dev.of_node);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver si5351_driver =3D {
> diff --git a/drivers/clk/clk-si570.c b/drivers/clk/clk-si570.c
> index 1ff8f32f734d..0a6d70c49726 100644
> --- a/drivers/clk/clk-si570.c
> +++ b/drivers/clk/clk-si570.c
> @@ -498,10 +498,9 @@ static int si570_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int si570_remove(struct i2c_client *client)
> +static void si570_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_clk_del_provider(clien=
t->dev.of_node);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id clk_si570_of_match[] =3D {
> diff --git a/drivers/clk/clk-versaclock5.c b/drivers/clk/clk-
> versaclock5.c
> index e7be3e54b9be..657493ecce4c 100644
> --- a/drivers/clk/clk-versaclock5.c
> +++ b/drivers/clk/clk-versaclock5.c
> @@ -1138,7 +1138,7 @@ static int vc5_probe(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int vc5_remove(struct i2c_client *client)
> +static void vc5_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct vc5_driver_data *v=
c5 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1146,8 +1146,6 @@ static int vc5_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (vc5->chip_info->flags=
 & VC5_HAS_INTERNAL_XTAL)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0clk_unregister_fixed_rate(vc5->pin_xin);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused vc5_suspend(struct device *dev)
> diff --git a/drivers/crypto/atmel-ecc.c b/drivers/crypto/atmel-ecc.c
> index a4b13d326cfc..82bf15d49561 100644
> --- a/drivers/crypto/atmel-ecc.c
> +++ b/drivers/crypto/atmel-ecc.c
> @@ -343,7 +343,7 @@ static int atmel_ecc_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int atmel_ecc_remove(struct i2c_client *client)
> +static void atmel_ecc_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct atmel_i2c_client_p=
riv *i2c_priv =3D
> i2c_get_clientdata(client);
> =C2=A0
> @@ -358,7 +358,7 @@ static int atmel_ecc_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 * accessing the freed memory.
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0 */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_emerg(&client->dev, "Device is busy, expect
> memory corruption.\n");
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0crypto_unregister_kpp(&at=
mel_ecdh_nist_p256);
> @@ -366,8 +366,6 @@ static int atmel_ecc_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0spin_lock(&driver_data.i2=
c_list_lock);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0list_del(&i2c_priv->i2c_c=
lient_list_node);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0spin_unlock(&driver_data.=
i2c_list_lock);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_OF
> diff --git a/drivers/crypto/atmel-sha204a.c b/drivers/crypto/atmel-
> sha204a.c
> index e4087bdd2475..a84b657598c6 100644
> --- a/drivers/crypto/atmel-sha204a.c
> +++ b/drivers/crypto/atmel-sha204a.c
> @@ -116,18 +116,16 @@ static int atmel_sha204a_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int atmel_sha204a_remove(struct i2c_client *client)
> +static void atmel_sha204a_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct atmel_i2c_client_p=
riv *i2c_priv =3D
> i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (atomic_read(&i2c_priv=
->tfm_count)) {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_emerg(&client->dev, "Device is busy, will remov=
e
> it anyhow\n");
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree((void *)i2c_priv->h=
wrng.priv);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id atmel_sha204a_dt_ids[] =3D {
> diff --git a/drivers/extcon/extcon-rt8973a.c b/drivers/extcon/extcon-
> rt8973a.c
> index 40c07f4d656e..d1c674f3f2b9 100644
> --- a/drivers/extcon/extcon-rt8973a.c
> +++ b/drivers/extcon/extcon-rt8973a.c
> @@ -647,13 +647,11 @@ static int rt8973a_muic_i2c_probe(struct
> i2c_client *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int rt8973a_muic_i2c_remove(struct i2c_client *i2c)
> +static void rt8973a_muic_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt8973a_muic_info =
*info =3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_del_irq_chip(info-=
>irq, info->irq_data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id rt8973a_dt_match[] =3D {
> diff --git a/drivers/gpio/gpio-adp5588.c b/drivers/gpio/gpio-
> adp5588.c
> index e388e75103f4..acb673dc9005 100644
> --- a/drivers/gpio/gpio-adp5588.c
> +++ b/drivers/gpio/gpio-adp5588.c
> @@ -411,14 +411,12 @@ static int adp5588_gpio_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int adp5588_gpio_remove(struct i2c_client *client)
> +static void adp5588_gpio_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adp5588_gpio *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (dev->client->irq)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(dev->client->irq, dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adp5588_gpio_id[] =3D {
> diff --git a/drivers/gpio/gpio-max7300.c b/drivers/gpio/gpio-
> max7300.c
> index b2b547dd6e84..43da381a4d7e 100644
> --- a/drivers/gpio/gpio-max7300.c
> +++ b/drivers/gpio/gpio-max7300.c
> @@ -48,11 +48,9 @@ static int max7300_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return __max730x_probe(ts=
);
> =C2=A0}
> =C2=A0
> -static int max7300_remove(struct i2c_client *client)
> +static void max7300_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0__max730x_remove(&client-=
>dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max7300_id[] =3D {
> diff --git a/drivers/gpio/gpio-pca953x.c b/drivers/gpio/gpio-
> pca953x.c
> index 3eedeac9ec8d..fc5f037aaf64 100644
> --- a/drivers/gpio/gpio-pca953x.c
> +++ b/drivers/gpio/gpio-pca953x.c
> @@ -1095,7 +1095,7 @@ static int pca953x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int pca953x_remove(struct i2c_client *client)
> +static void pca953x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pca953x_platform_d=
ata *pdata =3D
> dev_get_platdata(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pca953x_chip *chip=
 =3D i2c_get_clientdata(client);
> @@ -1106,8 +1106,6 @@ static int pca953x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(chip->r=
egulator);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/gpio/gpio-pcf857x.c b/drivers/gpio/gpio-
> pcf857x.c
> index 59cc27e4de51..e98ea47d7237 100644
> --- a/drivers/gpio/gpio-pcf857x.c
> +++ b/drivers/gpio/gpio-pcf857x.c
> @@ -399,7 +399,7 @@ static int pcf857x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return status;
> =C2=A0}
> =C2=A0
> -static int pcf857x_remove(struct i2c_client *client)
> +static void pcf857x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pcf857x_platform_d=
ata=C2=A0=C2=A0=C2=A0=C2=A0*pdata =3D
> dev_get_platdata(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pcf857x=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0*gpio =3D
> i2c_get_clientdata(client);
> @@ -407,8 +407,6 @@ static int pcf857x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (pdata && pdata->teard=
own)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0pdata->teardown(client, gpio->chip.base, gpio-
> >chip.ngpio,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pdata->context);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void pcf857x_shutdown(struct i2c_client *client)
> diff --git a/drivers/gpio/gpio-tpic2810.c b/drivers/gpio/gpio-
> tpic2810.c
> index 99d5a84a9129..8d8290f36c8a 100644
> --- a/drivers/gpio/gpio-tpic2810.c
> +++ b/drivers/gpio/gpio-tpic2810.c
> @@ -134,13 +134,11 @@ static int tpic2810_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tpic2810_remove(struct i2c_client *client)
> +static void tpic2810_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tpic2810 *gpio =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiochip_remove(&gpio->ch=
ip);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tpic2810_id_table[] =3D {
> diff --git a/drivers/gpu/drm/bridge/adv7511/adv7511_drv.c
> b/drivers/gpu/drm/bridge/adv7511/adv7511_drv.c
> index 5bb9300040dd..06107b01e169 100644
> --- a/drivers/gpu/drm/bridge/adv7511/adv7511_drv.c
> +++ b/drivers/gpu/drm/bridge/adv7511/adv7511_drv.c
> @@ -1335,7 +1335,7 @@ static int adv7511_probe(struct i2c_client
> *i2c, const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int adv7511_remove(struct i2c_client *i2c)
> +static void adv7511_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adv7511 *adv7511 =
=3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -1352,8 +1352,6 @@ static int adv7511_remove(struct i2c_client
> *i2c)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(adv=
7511->i2c_packet);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(adv=
7511->i2c_edid);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adv7511_i2c_ids[] =3D {
> diff --git a/drivers/gpu/drm/bridge/analogix/analogix-anx6345.c
> b/drivers/gpu/drm/bridge/analogix/analogix-anx6345.c
> index ae3d6e9a606c..660a54857929 100644
> --- a/drivers/gpu/drm/bridge/analogix/analogix-anx6345.c
> +++ b/drivers/gpu/drm/bridge/analogix/analogix-anx6345.c
> @@ -787,7 +787,7 @@ static int anx6345_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int anx6345_i2c_remove(struct i2c_client *client)
> +static void anx6345_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct anx6345 *anx6345 =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -798,8 +798,6 @@ static int anx6345_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(anx6345->edid);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&anx6345->l=
ock);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id anx6345_id[] =3D {
> diff --git a/drivers/gpu/drm/bridge/analogix/analogix-anx78xx.c
> b/drivers/gpu/drm/bridge/analogix/analogix-anx78xx.c
> index d2fc8676fab6..5997049fde5b 100644
> --- a/drivers/gpu/drm/bridge/analogix/analogix-anx78xx.c
> +++ b/drivers/gpu/drm/bridge/analogix/analogix-anx78xx.c
> @@ -1357,7 +1357,7 @@ static int anx78xx_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int anx78xx_i2c_remove(struct i2c_client *client)
> +static void anx78xx_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct anx78xx *anx78xx =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1366,8 +1366,6 @@ static int anx78xx_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unregister_i2c_dummy_clie=
nts(anx78xx);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(anx78xx->edid);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id anx78xx_id[] =3D {
> diff --git a/drivers/gpu/drm/bridge/analogix/anx7625.c
> b/drivers/gpu/drm/bridge/analogix/anx7625.c
> index 53a5da6c49dd..73f1d3338c81 100644
> --- a/drivers/gpu/drm/bridge/analogix/anx7625.c
> +++ b/drivers/gpu/drm/bridge/analogix/anx7625.c
> @@ -2733,7 +2733,7 @@ static int anx7625_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int anx7625_i2c_remove(struct i2c_client *client)
> +static void anx7625_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct anx7625_data *plat=
form =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -2755,8 +2755,6 @@ static int anx7625_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (platform->pdata.audio=
_en)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0anx7625_unregister_audio(platform);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id anx7625_id[] =3D {
> diff --git a/drivers/gpu/drm/bridge/chrontel-ch7033.c
> b/drivers/gpu/drm/bridge/chrontel-ch7033.c
> index 486f405c2e16..efd587d2075f 100644
> --- a/drivers/gpu/drm/bridge/chrontel-ch7033.c
> +++ b/drivers/gpu/drm/bridge/chrontel-ch7033.c
> @@ -582,14 +582,12 @@ static int ch7033_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ch7033_remove(struct i2c_client *client)
> +static void ch7033_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &c=
lient->dev;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ch7033_priv *priv =
=3D dev_get_drvdata(dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&priv->=
bridge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id ch7033_dt_ids[] =3D {
> diff --git a/drivers/gpu/drm/bridge/cros-ec-anx7688.c
> b/drivers/gpu/drm/bridge/cros-ec-anx7688.c
> index 0f6d907432e3..fa91bdeddef0 100644
> --- a/drivers/gpu/drm/bridge/cros-ec-anx7688.c
> +++ b/drivers/gpu/drm/bridge/cros-ec-anx7688.c
> @@ -159,13 +159,11 @@ static int cros_ec_anx7688_bridge_probe(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int cros_ec_anx7688_bridge_remove(struct i2c_client *client)
> +static void cros_ec_anx7688_bridge_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cros_ec_anx7688 *a=
nx7688 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&anx768=
8->bridge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id
> cros_ec_anx7688_bridge_match_table[] =3D {
> diff --git a/drivers/gpu/drm/bridge/ite-it6505.c
> b/drivers/gpu/drm/bridge/ite-it6505.c
> index 4b673c4792d7..547e0c9d3bdc 100644
> --- a/drivers/gpu/drm/bridge/ite-it6505.c
> +++ b/drivers/gpu/drm/bridge/ite-it6505.c
> @@ -3316,7 +3316,7 @@ static int it6505_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int it6505_i2c_remove(struct i2c_client *client)
> +static void it6505_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct it6505 *it6505 =3D=
 i2c_get_clientdata(client);
> =C2=A0
> @@ -3324,8 +3324,6 @@ static int it6505_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_dp_aux_unregister(&it=
6505->aux);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0it6505_debugfs_remove(it6=
505);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0it6505_poweroff(it6505);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id it6505_id[] =3D {
> diff --git a/drivers/gpu/drm/bridge/ite-it66121.c
> b/drivers/gpu/drm/bridge/ite-it66121.c
> index 448c58e60c11..8d05ac2192f2 100644
> --- a/drivers/gpu/drm/bridge/ite-it66121.c
> +++ b/drivers/gpu/drm/bridge/ite-it66121.c
> @@ -1622,15 +1622,13 @@ static int it66121_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int it66121_remove(struct i2c_client *client)
> +static void it66121_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct it66121_ctx *ctx =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ite66121_power_off(ctx);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&ctx->b=
ridge);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ctx->lock)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id it66121_dt_match[] =3D {
> diff --git a/drivers/gpu/drm/bridge/lontium-lt8912b.c
> b/drivers/gpu/drm/bridge/lontium-lt8912b.c
> index c642d1e02b2f..2f5c9ea46e93 100644
> --- a/drivers/gpu/drm/bridge/lontium-lt8912b.c
> +++ b/drivers/gpu/drm/bridge/lontium-lt8912b.c
> @@ -717,7 +717,7 @@ static int lt8912_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lt8912_remove(struct i2c_client *client)
> +static void lt8912_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lt8912 *lt =3D i2c=
_get_clientdata(client);
> =C2=A0
> @@ -725,7 +725,6 @@ static int lt8912_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&lt->br=
idge);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lt8912_free_i2c(lt);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lt8912_put_dt(lt);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id lt8912_dt_match[] =3D {
> diff --git a/drivers/gpu/drm/bridge/lontium-lt9211.c
> b/drivers/gpu/drm/bridge/lontium-lt9211.c
> index e92821fbc639..0646ec28ad17 100644
> --- a/drivers/gpu/drm/bridge/lontium-lt9211.c
> +++ b/drivers/gpu/drm/bridge/lontium-lt9211.c
> @@ -765,13 +765,11 @@ static int lt9211_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lt9211_remove(struct i2c_client *client)
> +static void lt9211_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lt9211 *ctx =3D i2=
c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&ctx->b=
ridge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_device_id lt9211_id[] =3D {
> diff --git a/drivers/gpu/drm/bridge/lontium-lt9611.c
> b/drivers/gpu/drm/bridge/lontium-lt9611.c
> index 7ef8fe5abc12..492e948d624f 100644
> --- a/drivers/gpu/drm/bridge/lontium-lt9611.c
> +++ b/drivers/gpu/drm/bridge/lontium-lt9611.c
> @@ -1220,7 +1220,7 @@ static int lt9611_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lt9611_remove(struct i2c_client *client)
> +static void lt9611_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lt9611 *lt9611 =3D=
 i2c_get_clientdata(client);
> =C2=A0
> @@ -1232,8 +1232,6 @@ static int lt9611_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_node_put(lt9611->dsi1_=
node);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_node_put(lt9611->dsi0_=
node);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_device_id lt9611_id[] =3D {
> diff --git a/drivers/gpu/drm/bridge/lontium-lt9611uxc.c
> b/drivers/gpu/drm/bridge/lontium-lt9611uxc.c
> index 3d62e6bf6892..b5a58106c328 100644
> --- a/drivers/gpu/drm/bridge/lontium-lt9611uxc.c
> +++ b/drivers/gpu/drm/bridge/lontium-lt9611uxc.c
> @@ -977,7 +977,7 @@ static int lt9611uxc_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lt9611uxc_remove(struct i2c_client *client)
> +static void lt9611uxc_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lt9611uxc *lt9611u=
xc =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -992,8 +992,6 @@ static int lt9611uxc_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_node_put(lt9611uxc->ds=
i1_node);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_node_put(lt9611uxc->ds=
i0_node);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_device_id lt9611uxc_id[] =3D {
> diff --git a/drivers/gpu/drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c
> b/drivers/gpu/drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c
> index cce98bf2a4e7..9f175df11581 100644
> --- a/drivers/gpu/drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c
> +++ b/drivers/gpu/drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c
> @@ -355,11 +355,9 @@ static int stdp4028_ge_b850v3_fw_probe(struct
> i2c_client *stdp4028_i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ge_b850v3_register=
();
> =C2=A0}
> =C2=A0
> -static int stdp4028_ge_b850v3_fw_remove(struct i2c_client
> *stdp4028_i2c)
> +static void stdp4028_ge_b850v3_fw_remove(struct i2c_client
> *stdp4028_i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ge_b850v3_lvds_remove();
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id stdp4028_ge_b850v3_fw_i2c_table[]
> =3D {
> @@ -405,11 +403,9 @@ static int stdp2690_ge_b850v3_fw_probe(struct
> i2c_client *stdp2690_i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ge_b850v3_register=
();
> =C2=A0}
> =C2=A0
> -static int stdp2690_ge_b850v3_fw_remove(struct i2c_client
> *stdp2690_i2c)
> +static void stdp2690_ge_b850v3_fw_remove(struct i2c_client
> *stdp2690_i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ge_b850v3_lvds_remove();
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id stdp2690_ge_b850v3_fw_i2c_table[]
> =3D {
> diff --git a/drivers/gpu/drm/bridge/nxp-ptn3460.c
> b/drivers/gpu/drm/bridge/nxp-ptn3460.c
> index 1ab91f4e057b..0851101a8c72 100644
> --- a/drivers/gpu/drm/bridge/nxp-ptn3460.c
> +++ b/drivers/gpu/drm/bridge/nxp-ptn3460.c
> @@ -315,13 +315,11 @@ static int ptn3460_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ptn3460_remove(struct i2c_client *client)
> +static void ptn3460_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ptn3460_bridge *pt=
n_bridge =3D
> i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&ptn_br=
idge->bridge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ptn3460_i2c_table[] =3D {
> diff --git a/drivers/gpu/drm/bridge/parade-ps8622.c
> b/drivers/gpu/drm/bridge/parade-ps8622.c
> index 37b308850b4e..b54f418d2b7b 100644
> --- a/drivers/gpu/drm/bridge/parade-ps8622.c
> +++ b/drivers/gpu/drm/bridge/parade-ps8622.c
> @@ -524,14 +524,12 @@ static int ps8622_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ps8622_remove(struct i2c_client *client)
> +static void ps8622_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ps8622_bridge *ps8=
622 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0backlight_device_unregist=
er(ps8622->bl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&ps8622=
->bridge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ps8622_i2c_table[] =3D {
> diff --git a/drivers/gpu/drm/bridge/parade-ps8640.c
> b/drivers/gpu/drm/bridge/parade-ps8640.c
> index edb939b14c04..a09d1828d8e1 100644
> --- a/drivers/gpu/drm/bridge/parade-ps8640.c
> +++ b/drivers/gpu/drm/bridge/parade-ps8640.c
> @@ -690,13 +690,11 @@ static int ps8640_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ps8640_remove(struct i2c_client *client)
> +static void ps8640_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ps8640 *ps_bridge =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&ps_bri=
dge->bridge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id ps8640_match[] =3D {
> diff --git a/drivers/gpu/drm/bridge/sii902x.c
> b/drivers/gpu/drm/bridge/sii902x.c
> index 65549fbfdc87..c5e5f83b97ce 100644
> --- a/drivers/gpu/drm/bridge/sii902x.c
> +++ b/drivers/gpu/drm/bridge/sii902x.c
> @@ -1143,7 +1143,7 @@ static int sii902x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int sii902x_remove(struct i2c_client *client)
> +static void sii902x_remove(struct i2c_client *client)
> =C2=A0
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct sii902x *sii902x =
=3D i2c_get_clientdata(client);
> @@ -1152,8 +1152,6 @@ static int sii902x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&sii902=
x->bridge);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(sii902x->supplies),
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 sii902x->supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id sii902x_dt_ids[] =3D {
> diff --git a/drivers/gpu/drm/bridge/sii9234.c
> b/drivers/gpu/drm/bridge/sii9234.c
> index 15c98a7bd81c..5b3061d4b5c3 100644
> --- a/drivers/gpu/drm/bridge/sii9234.c
> +++ b/drivers/gpu/drm/bridge/sii9234.c
> @@ -936,14 +936,12 @@ static int sii9234_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int sii9234_remove(struct i2c_client *client)
> +static void sii9234_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct sii9234 *ctx =3D i=
2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sii9234_cable_out(ctx);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&ctx->b=
ridge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id sii9234_dt_match[] =3D {
> diff --git a/drivers/gpu/drm/bridge/sil-sii8620.c
> b/drivers/gpu/drm/bridge/sil-sii8620.c
> index ec7745c31da0..eabd3e09adfa 100644
> --- a/drivers/gpu/drm/bridge/sil-sii8620.c
> +++ b/drivers/gpu/drm/bridge/sil-sii8620.c
> @@ -2346,7 +2346,7 @@ static int sii8620_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int sii8620_remove(struct i2c_client *client)
> +static void sii8620_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct sii8620 *ctx =3D i=
2c_get_clientdata(client);
> =C2=A0
> @@ -2360,8 +2360,6 @@ static int sii8620_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0sii8620_cable_out(ctx);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&ctx->b=
ridge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id sii8620_dt_match[] =3D {
> diff --git a/drivers/gpu/drm/bridge/tc358767.c
> b/drivers/gpu/drm/bridge/tc358767.c
> index 485717c8f0b4..a50316538a9b 100644
> --- a/drivers/gpu/drm/bridge/tc358767.c
> +++ b/drivers/gpu/drm/bridge/tc358767.c
> @@ -2148,13 +2148,11 @@ static int tc_probe(struct i2c_client
> *client, const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tc_remove(struct i2c_client *client)
> +static void tc_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tc_data *tc =3D i2=
c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&tc->br=
idge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tc358767_i2c_ids[] =3D {
> diff --git a/drivers/gpu/drm/bridge/tc358768.c
> b/drivers/gpu/drm/bridge/tc358768.c
> index fd585bf925fe..4c4b77ce8aba 100644
> --- a/drivers/gpu/drm/bridge/tc358768.c
> +++ b/drivers/gpu/drm/bridge/tc358768.c
> @@ -1072,13 +1072,11 @@ static int tc358768_i2c_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return mipi_dsi_host_regi=
ster(&priv->dsi_host);
> =C2=A0}
> =C2=A0
> -static int tc358768_i2c_remove(struct i2c_client *client)
> +static void tc358768_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tc358768_priv *pri=
v =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mipi_dsi_host_unregister(=
&priv->dsi_host);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver tc358768_driver =3D {
> diff --git a/drivers/gpu/drm/bridge/tc358775.c
> b/drivers/gpu/drm/bridge/tc358775.c
> index 62a7ef352daa..1d097717b47b 100644
> --- a/drivers/gpu/drm/bridge/tc358775.c
> +++ b/drivers/gpu/drm/bridge/tc358775.c
> @@ -713,13 +713,11 @@ static int tc_probe(struct i2c_client *client,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tc_remove(struct i2c_client *client)
> +static void tc_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tc_data *tc =3D i2=
c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&tc->br=
idge);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tc358775_i2c_ids[] =3D {
> diff --git a/drivers/gpu/drm/bridge/ti-sn65dsi83.c
> b/drivers/gpu/drm/bridge/ti-sn65dsi83.c
> index ac66f408b40c..8f93e374848c 100644
> --- a/drivers/gpu/drm/bridge/ti-sn65dsi83.c
> +++ b/drivers/gpu/drm/bridge/ti-sn65dsi83.c
> @@ -726,14 +726,12 @@ static int sn65dsi83_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int sn65dsi83_remove(struct i2c_client *client)
> +static void sn65dsi83_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct sn65dsi83 *ctx =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_bridge_remove(&ctx->b=
ridge);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_node_put(ctx->host_nod=
e);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_device_id sn65dsi83_id[] =3D {
> diff --git a/drivers/gpu/drm/bridge/ti-tfp410.c
> b/drivers/gpu/drm/bridge/ti-tfp410.c
> index 756b3e6e776b..281ceb7b9840 100644
> --- a/drivers/gpu/drm/bridge/ti-tfp410.c
> +++ b/drivers/gpu/drm/bridge/ti-tfp410.c
> @@ -392,11 +392,9 @@ static int tfp410_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return tfp410_init(&clien=
t->dev, true);
> =C2=A0}
> =C2=A0
> -static int tfp410_i2c_remove(struct i2c_client *client)
> +static void tfp410_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tfp410_fini(&client->dev)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tfp410_i2c_ids[] =3D {
> diff --git a/drivers/gpu/drm/i2c/ch7006_drv.c
> b/drivers/gpu/drm/i2c/ch7006_drv.c
> index b91e48d2190d..578b738859b9 100644
> --- a/drivers/gpu/drm/i2c/ch7006_drv.c
> +++ b/drivers/gpu/drm/i2c/ch7006_drv.c
> @@ -417,11 +417,9 @@ static int ch7006_probe(struct i2c_client
> *client, const struct i2c_device_id *i
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return -ENODEV;
> =C2=A0}
> =C2=A0
> -static int ch7006_remove(struct i2c_client *client)
> +static void ch7006_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ch7006_dbg(client, "\n");
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ch7006_resume(struct device *dev)
> diff --git a/drivers/gpu/drm/i2c/tda9950.c
> b/drivers/gpu/drm/i2c/tda9950.c
> index 5b03fdd1eaa4..9ed54e7ccff2 100644
> --- a/drivers/gpu/drm/i2c/tda9950.c
> +++ b/drivers/gpu/drm/i2c/tda9950.c
> @@ -478,14 +478,12 @@ static int tda9950_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tda9950_remove(struct i2c_client *client)
> +static void tda9950_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tda9950_priv *priv=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cec_notifier_cec_adap_unr=
egister(priv->notify, priv->adap);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cec_unregister_adapter(pr=
iv->adap);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_device_id tda9950_ids[] =3D {
> diff --git a/drivers/gpu/drm/i2c/tda998x_drv.c
> b/drivers/gpu/drm/i2c/tda998x_drv.c
> index b7ec6c374fbd..1f5ce292f5b1 100644
> --- a/drivers/gpu/drm/i2c/tda998x_drv.c
> +++ b/drivers/gpu/drm/i2c/tda998x_drv.c
> @@ -2075,11 +2075,10 @@ tda998x_probe(struct i2c_client *client,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tda998x_remove(struct i2c_client *client)
> +static void tda998x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0component_del(&client->de=
v, &tda998x_ops);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tda998x_destroy(&client->=
dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_OF
> diff --git a/drivers/gpu/drm/panel/panel-olimex-lcd-olinuxino.c
> b/drivers/gpu/drm/panel/panel-olimex-lcd-olinuxino.c
> index cb5cb27462df..36a46cb7fe1c 100644
> --- a/drivers/gpu/drm/panel/panel-olimex-lcd-olinuxino.c
> +++ b/drivers/gpu/drm/panel/panel-olimex-lcd-olinuxino.c
> @@ -288,7 +288,7 @@ static int lcd_olinuxino_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lcd_olinuxino_remove(struct i2c_client *client)
> +static void lcd_olinuxino_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lcd_olinuxino *pan=
el =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -296,8 +296,6 @@ static int lcd_olinuxino_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_panel_disable(&panel-=
>panel);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_panel_unprepare(&pane=
l->panel);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id lcd_olinuxino_of_ids[] =3D {
> diff --git a/drivers/gpu/drm/panel/panel-raspberrypi-touchscreen.c
> b/drivers/gpu/drm/panel/panel-raspberrypi-touchscreen.c
> index 145047e19394..6dc67b609873 100644
> --- a/drivers/gpu/drm/panel/panel-raspberrypi-touchscreen.c
> +++ b/drivers/gpu/drm/panel/panel-raspberrypi-touchscreen.c
> @@ -445,7 +445,7 @@ static int rpi_touchscreen_probe(struct
> i2c_client *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return -ENODEV;
> =C2=A0}
> =C2=A0
> -static int rpi_touchscreen_remove(struct i2c_client *i2c)
> +static void rpi_touchscreen_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rpi_touchscreen *t=
s =3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -454,8 +454,6 @@ static int rpi_touchscreen_remove(struct
> i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0drm_panel_remove(&ts->bas=
e);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mipi_dsi_device_unregiste=
r(ts->dsi);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int rpi_touchscreen_dsi_probe(struct mipi_dsi_device *dsi)
> diff --git a/drivers/gpu/drm/solomon/ssd130x-i2c.c
> b/drivers/gpu/drm/solomon/ssd130x-i2c.c
> index 1e0fcec7be47..ddfa0bb5d9c9 100644
> --- a/drivers/gpu/drm/solomon/ssd130x-i2c.c
> +++ b/drivers/gpu/drm/solomon/ssd130x-i2c.c
> @@ -39,13 +39,11 @@ static int ssd130x_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ssd130x_i2c_remove(struct i2c_client *client)
> +static void ssd130x_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ssd130x_device *ss=
d130x =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ssd130x_remove(ssd130x);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void ssd130x_i2c_shutdown(struct i2c_client *client)
> diff --git a/drivers/hid/i2c-hid/i2c-hid-core.c b/drivers/hid/i2c-
> hid/i2c-hid-core.c
> index c078f09a2318..95cefae47adf 100644
> --- a/drivers/hid/i2c-hid/i2c-hid-core.c
> +++ b/drivers/hid/i2c-hid/i2c-hid-core.c
> @@ -1064,7 +1064,7 @@ int i2c_hid_core_probe(struct i2c_client
> *client, struct i2chid_ops *ops,
> =C2=A0}
> =C2=A0EXPORT_SYMBOL_GPL(i2c_hid_core_probe);
> =C2=A0
> -int i2c_hid_core_remove(struct i2c_client *client)
> +void i2c_hid_core_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct i2c_hid *ihid =3D =
i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct hid_device *hid;
> @@ -1078,8 +1078,6 @@ int i2c_hid_core_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0i2c_hid_free_buffers(ihid);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_hid_core_power_down(i=
hid);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0EXPORT_SYMBOL_GPL(i2c_hid_core_remove);
> =C2=A0
> diff --git a/drivers/hid/i2c-hid/i2c-hid.h b/drivers/hid/i2c-hid/i2c-
> hid.h
> index 236cc062d5ef..96c75510ad3f 100644
> --- a/drivers/hid/i2c-hid/i2c-hid.h
> +++ b/drivers/hid/i2c-hid/i2c-hid.h
> @@ -33,7 +33,7 @@ struct i2chid_ops {
> =C2=A0
> =C2=A0int i2c_hid_core_probe(struct i2c_client *client, struct i2chid_ops
> *ops,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u16 hid_descri=
ptor_address, u32 quirks);
> -int i2c_hid_core_remove(struct i2c_client *client);
> +void i2c_hid_core_remove(struct i2c_client *client);
> =C2=A0
> =C2=A0void i2c_hid_core_shutdown(struct i2c_client *client);
> =C2=A0
> diff --git a/drivers/hwmon/adc128d818.c b/drivers/hwmon/adc128d818.c
> index fd938c70293f..299160543b35 100644
> --- a/drivers/hwmon/adc128d818.c
> +++ b/drivers/hwmon/adc128d818.c
> @@ -495,14 +495,12 @@ static int adc128_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int adc128_remove(struct i2c_client *client)
> +static void adc128_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adc128_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (data->regulator)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->regulator);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adc128_id[] =3D {
> diff --git a/drivers/hwmon/adt7470.c b/drivers/hwmon/adt7470.c
> index c67cd037a93f..927f8df05b7c 100644
> --- a/drivers/hwmon/adt7470.c
> +++ b/drivers/hwmon/adt7470.c
> @@ -1296,12 +1296,11 @@ static int adt7470_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int adt7470_remove(struct i2c_client *client)
> +static void adt7470_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adt7470_data *data=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kthread_stop(data->auto_u=
pdate);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adt7470_id[] =3D {
> diff --git a/drivers/hwmon/asb100.c b/drivers/hwmon/asb100.c
> index 8cf0bcb85eb4..a9166c8555c5 100644
> --- a/drivers/hwmon/asb100.c
> +++ b/drivers/hwmon/asb100.c
> @@ -208,7 +208,7 @@ static void asb100_write_value(struct i2c_client
> *client, u16 reg, u16 val);
> =C2=A0static int asb100_probe(struct i2c_client *client);
> =C2=A0static int asb100_detect(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 st=
ruct i2c_board_info *info);
> -static int asb100_remove(struct i2c_client *client);
> +static void asb100_remove(struct i2c_client *client);
> =C2=A0static struct asb100_data *asb100_update_device(struct device *dev)=
;
> =C2=A0static void asb100_init_client(struct i2c_client *client);
> =C2=A0
> @@ -822,7 +822,7 @@ static int asb100_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int asb100_remove(struct i2c_client *client)
> +static void asb100_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct asb100_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -831,8 +831,6 @@ static int asb100_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(dat=
a->lm75[1]);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(dat=
a->lm75[0]);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/hwmon/asc7621.c b/drivers/hwmon/asc7621.c
> index e835605a7456..4f90fdee9cc7 100644
> --- a/drivers/hwmon/asc7621.c
> +++ b/drivers/hwmon/asc7621.c
> @@ -1165,7 +1165,7 @@ static int asc7621_detect(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return -ENODEV;
> =C2=A0}
> =C2=A0
> -static int asc7621_remove(struct i2c_client *client)
> +static void asc7621_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct asc7621_data *data=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -1176,8 +1176,6 @@ static int asc7621_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0device_remove_file(&client->dev,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0
> &(asc7621_params[i].sda.dev_attr));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id asc7621_id[] =3D {
> diff --git a/drivers/hwmon/dme1737.c b/drivers/hwmon/dme1737.c
> index e3ad4c2d0038..b1cd028c8277 100644
> --- a/drivers/hwmon/dme1737.c
> +++ b/drivers/hwmon/dme1737.c
> @@ -2508,14 +2508,12 @@ static int dme1737_i2c_probe(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int dme1737_i2c_remove(struct i2c_client *client)
> +static void dme1737_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dme1737_data *data=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0hwmon_device_unregister(d=
ata->hwmon_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dme1737_remove_files(&cli=
ent->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id dme1737_id[] =3D {
> diff --git a/drivers/hwmon/f75375s.c b/drivers/hwmon/f75375s.c
> index 57c8a473698d..ffeed6c1e20b 100644
> --- a/drivers/hwmon/f75375s.c
> +++ b/drivers/hwmon/f75375s.c
> @@ -114,7 +114,7 @@ struct f75375_data {
> =C2=A0static int f75375_detect(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 st=
ruct i2c_board_info *info);
> =C2=A0static int f75375_probe(struct i2c_client *client);
> -static int f75375_remove(struct i2c_client *client);
> +static void f75375_remove(struct i2c_client *client);
> =C2=A0
> =C2=A0static const struct i2c_device_id f75375_id[] =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0{ "f75373", f75373 },
> @@ -864,12 +864,11 @@ static int f75375_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int f75375_remove(struct i2c_client *client)
> +static void f75375_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct f75375_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0hwmon_device_unregister(d=
ata->hwmon_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &f75375_group);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* Return 0 if detection is successful, -ENODEV otherwise */
> diff --git a/drivers/hwmon/fschmd.c b/drivers/hwmon/fschmd.c
> index c26195e3aad7..343e227ca38a 100644
> --- a/drivers/hwmon/fschmd.c
> +++ b/drivers/hwmon/fschmd.c
> @@ -217,7 +217,7 @@ static const int FSCHMD_NO_TEMP_SENSORS[7] =3D { 3,
> 3, 4, 3, 5, 5, 11 };
> =C2=A0static int fschmd_probe(struct i2c_client *client);
> =C2=A0static int fschmd_detect(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 st=
ruct i2c_board_info *info);
> -static int fschmd_remove(struct i2c_client *client);
> +static void fschmd_remove(struct i2c_client *client);
> =C2=A0static struct fschmd_data *fschmd_update_device(struct device *dev)=
;
> =C2=A0
> =C2=A0/*
> @@ -1248,7 +1248,7 @@ static int fschmd_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int fschmd_remove(struct i2c_client *client)
> +static void fschmd_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct fschmd_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -1291,8 +1291,6 @@ static int fschmd_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&watchdog_data=
_mutex);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kref_put(&data->kref, fsc=
hmd_release_resources);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&watchdog_da=
ta_mutex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct fschmd_data *fschmd_update_device(struct device *dev)
> diff --git a/drivers/hwmon/ftsteutates.c
> b/drivers/hwmon/ftsteutates.c
> index ceffc76a0c51..918763832432 100644
> --- a/drivers/hwmon/ftsteutates.c
> +++ b/drivers/hwmon/ftsteutates.c
> @@ -744,12 +744,11 @@ static int fts_detect(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int fts_remove(struct i2c_client *client)
> +static void fts_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct fts_data *data =3D=
 dev_get_drvdata(&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0watchdog_unregister_devic=
e(&data->wdd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int fts_probe(struct i2c_client *client)
> diff --git a/drivers/hwmon/ina209.c b/drivers/hwmon/ina209.c
> index fc3007c3e85c..9b58655d2de4 100644
> --- a/drivers/hwmon/ina209.c
> +++ b/drivers/hwmon/ina209.c
> @@ -568,13 +568,11 @@ static int ina209_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ina209_remove(struct i2c_client *client)
> +static void ina209_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ina209_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ina209_restore_conf(clien=
t, data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ina209_id[] =3D {
> diff --git a/drivers/hwmon/ina3221.c b/drivers/hwmon/ina3221.c
> index 58d3828e2ec0..f89bac19bd73 100644
> --- a/drivers/hwmon/ina3221.c
> +++ b/drivers/hwmon/ina3221.c
> @@ -913,7 +913,7 @@ static int ina3221_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ina3221_remove(struct i2c_client *client)
> +static void ina3221_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ina3221_data *ina =
=3D dev_get_drvdata(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -926,8 +926,6 @@ static int ina3221_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_put_noidle(ina->pm_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ina->lock)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused ina3221_suspend(struct device *dev)
> diff --git a/drivers/hwmon/jc42.c b/drivers/hwmon/jc42.c
> index 07f7f8b5b73d..7b3c190959d3 100644
> --- a/drivers/hwmon/jc42.c
> +++ b/drivers/hwmon/jc42.c
> @@ -524,7 +524,7 @@ static int jc42_probe(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return PTR_ERR_OR_ZERO(hw=
mon_dev);
> =C2=A0}
> =C2=A0
> -static int jc42_remove(struct i2c_client *client)
> +static void jc42_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct jc42_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -537,7 +537,6 @@ static int jc42_remove(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | (data->config & JC42_CFG_HYST_MASK);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0i2c_smbus_write_word_swapped(client, JC42_REG_CONFI=
G,
> config);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/hwmon/mcp3021.c b/drivers/hwmon/mcp3021.c
> index ce2780768074..99c29ced084c 100644
> --- a/drivers/hwmon/mcp3021.c
> +++ b/drivers/hwmon/mcp3021.c
> @@ -167,14 +167,12 @@ static int mcp3021_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int mcp3021_remove(struct i2c_client *client)
> +static void mcp3021_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mcp3021_data *data=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0hwmon_device_unregister(d=
ata->hwmon_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_file(&client=
->dev.kobj,
> &dev_attr_in0_input.attr);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mcp3021_id[] =3D {
> diff --git a/drivers/hwmon/occ/p8_i2c.c b/drivers/hwmon/occ/p8_i2c.c
> index da39ea28df31..d82a4873a0c6 100644
> --- a/drivers/hwmon/occ/p8_i2c.c
> +++ b/drivers/hwmon/occ/p8_i2c.c
> @@ -226,13 +226,11 @@ static int p8_i2c_occ_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return occ_setup(occ);
> =C2=A0}
> =C2=A0
> -static int p8_i2c_occ_remove(struct i2c_client *client)
> +static void p8_i2c_occ_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct occ *occ =3D dev_g=
et_drvdata(&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0occ_shutdown(occ);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id p8_i2c_occ_of_match[] =3D {
> diff --git a/drivers/hwmon/pcf8591.c b/drivers/hwmon/pcf8591.c
> index a97a51005c61..af9614e918a4 100644
> --- a/drivers/hwmon/pcf8591.c
> +++ b/drivers/hwmon/pcf8591.c
> @@ -228,14 +228,13 @@ static int pcf8591_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int pcf8591_remove(struct i2c_client *client)
> +static void pcf8591_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pcf8591_data *data=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0hwmon_device_unregister(d=
ata->hwmon_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj,
> &pcf8591_attr_group_opt);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &pcf8591_attr_group);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* Called when we have found a new PCF8591. */
> diff --git a/drivers/hwmon/smm665.c b/drivers/hwmon/smm665.c
> index 8c4ed72e5d68..c36bdbe423de 100644
> --- a/drivers/hwmon/smm665.c
> +++ b/drivers/hwmon/smm665.c
> @@ -671,12 +671,11 @@ static int smm665_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int smm665_remove(struct i2c_client *client)
> +static void smm665_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct smm665_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(dat=
a->cmdreg);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id smm665_id[] =3D {
> diff --git a/drivers/hwmon/tps23861.c b/drivers/hwmon/tps23861.c
> index 8bd6435c13e8..9cf693287235 100644
> --- a/drivers/hwmon/tps23861.c
> +++ b/drivers/hwmon/tps23861.c
> @@ -584,13 +584,11 @@ static int tps23861_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tps23861_remove(struct i2c_client *client)
> +static void tps23861_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tps23861_data *dat=
a =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0debugfs_remove_recursive(=
data->debugfs_dir);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id __maybe_unused tps23861_of_match[]
> =3D {
> diff --git a/drivers/hwmon/w83781d.c b/drivers/hwmon/w83781d.c
> index b3579721265f..55c78e12bbbe 100644
> --- a/drivers/hwmon/w83781d.c
> +++ b/drivers/hwmon/w83781d.c
> @@ -1239,7 +1239,7 @@ static int w83781d_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int
> +static void
> =C2=A0w83781d_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct w83781d_data *data=
 =3D i2c_get_clientdata(client);
> @@ -1250,8 +1250,6 @@ w83781d_remove(struct i2c_client *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(dat=
a->lm75[0]);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(dat=
a->lm75[1]);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int
> diff --git a/drivers/hwmon/w83791d.c b/drivers/hwmon/w83791d.c
> index 80a9a78d7ce9..5fe5c93856af 100644
> --- a/drivers/hwmon/w83791d.c
> +++ b/drivers/hwmon/w83791d.c
> @@ -315,7 +315,7 @@ struct w83791d_data {
> =C2=A0static int w83791d_probe(struct i2c_client *client);
> =C2=A0static int w83791d_detect(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 struct i2c_board_info *info);
> -static int w83791d_remove(struct i2c_client *client);
> +static void w83791d_remove(struct i2c_client *client);
> =C2=A0
> =C2=A0static int w83791d_read(struct i2c_client *client, u8 reg);
> =C2=A0static int w83791d_write(struct i2c_client *client, u8 reg, u8
> value);
> @@ -1405,14 +1405,12 @@ static int w83791d_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int w83791d_remove(struct i2c_client *client)
> +static void w83791d_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct w83791d_data *data=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0hwmon_device_unregister(d=
ata->hwmon_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &w83791d_group);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void w83791d_init_client(struct i2c_client *client)
> diff --git a/drivers/hwmon/w83792d.c b/drivers/hwmon/w83792d.c
> index 31a1cdc30877..2ee8ee4f0f1c 100644
> --- a/drivers/hwmon/w83792d.c
> +++ b/drivers/hwmon/w83792d.c
> @@ -286,7 +286,7 @@ struct w83792d_data {
> =C2=A0static int w83792d_probe(struct i2c_client *client);
> =C2=A0static int w83792d_detect(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 struct i2c_board_info *info);
> -static int w83792d_remove(struct i2c_client *client);
> +static void w83792d_remove(struct i2c_client *client);
> =C2=A0static struct w83792d_data *w83792d_update_device(struct device
> *dev);
> =C2=A0
> =C2=A0#ifdef DEBUG
> @@ -1429,7 +1429,7 @@ w83792d_probe(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int
> +static void
> =C2=A0w83792d_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct w83792d_data *data=
 =3D i2c_get_clientdata(client);
> @@ -1440,8 +1440,6 @@ w83792d_remove(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0for (i =3D 0; i < ARRAY_S=
IZE(w83792d_group_fan); i++)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&client->dev.kobj,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 &w83792d_group_fa=
n[i]);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void
> diff --git a/drivers/hwmon/w83793.c b/drivers/hwmon/w83793.c
> index 0a65d164c8f0..daeaaded6b76 100644
> --- a/drivers/hwmon/w83793.c
> +++ b/drivers/hwmon/w83793.c
> @@ -285,7 +285,7 @@ static int w83793_write_value(struct i2c_client
> *client, u16 reg, u8 value);
> =C2=A0static int w83793_probe(struct i2c_client *client);
> =C2=A0static int w83793_detect(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 st=
ruct i2c_board_info *info);
> -static int w83793_remove(struct i2c_client *client);
> +static void w83793_remove(struct i2c_client *client);
> =C2=A0static void w83793_init_client(struct i2c_client *client);
> =C2=A0static void w83793_update_nonvolatile(struct device *dev);
> =C2=A0static struct w83793_data *w83793_update_device(struct device *dev)=
;
> @@ -1495,7 +1495,7 @@ static struct notifier_block watchdog_notifier
> =3D {
> =C2=A0 * Init / remove routines
> =C2=A0 */
> =C2=A0
> -static int w83793_remove(struct i2c_client *client)
> +static void w83793_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct w83793_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &c=
lient->dev;
> @@ -1554,8 +1554,6 @@ static int w83793_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&watchdog_data=
_mutex);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kref_put(&data->kref, w83=
793_release_resources);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&watchdog_da=
ta_mutex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int
> diff --git a/drivers/hwmon/w83795.c b/drivers/hwmon/w83795.c
> index 45b12c4287df..b170cdf3c2be 100644
> --- a/drivers/hwmon/w83795.c
> +++ b/drivers/hwmon/w83795.c
> @@ -2235,14 +2235,12 @@ static int w83795_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int w83795_remove(struct i2c_client *client)
> +static void w83795_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct w83795_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0hwmon_device_unregister(d=
ata->hwmon_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0w83795_handle_files(&clie=
nt->dev,
> device_remove_file_wrapper);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/hwmon/w83l785ts.c b/drivers/hwmon/w83l785ts.c
> index a41f989d66e2..99f68358378b 100644
> --- a/drivers/hwmon/w83l785ts.c
> +++ b/drivers/hwmon/w83l785ts.c
> @@ -65,7 +65,7 @@ static const unsigned short normal_i2c[] =3D { 0x2e,
> I2C_CLIENT_END };
> =C2=A0static int w83l785ts_probe(struct i2c_client *client);
> =C2=A0static int w83l785ts_detect(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 struct i2c_board_info *info);
> -static int w83l785ts_remove(struct i2c_client *client);
> +static void w83l785ts_remove(struct i2c_client *client);
> =C2=A0static u8 w83l785ts_read_value(struct i2c_client *client, u8 reg, u=
8
> defval);
> =C2=A0static struct w83l785ts_data *w83l785ts_update_device(struct device
> *dev);
> =C2=A0
> @@ -203,7 +203,7 @@ static int w83l785ts_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int w83l785ts_remove(struct i2c_client *client)
> +static void w83l785ts_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct w83l785ts_data *da=
ta =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -212,8 +212,6 @@ static int w83l785ts_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 &sensor_dev_attr_temp1_input.dev_attr);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0device_remove_file(&clien=
t->dev,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0 &sensor_dev_attr_temp1_max.dev_attr);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static u8 w83l785ts_read_value(struct i2c_client *client, u8 reg, u=
8
> defval)
> diff --git a/drivers/i2c/i2c-core-base.c b/drivers/i2c/i2c-core-
> base.c
> index 8ae47e0bbd67..68fc66a424ef 100644
> --- a/drivers/i2c/i2c-core-base.c
> +++ b/drivers/i2c/i2c-core-base.c
> @@ -599,13 +599,9 @@ static void i2c_device_remove(struct device
> *dev)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0driver =3D to_i2c_driver(=
dev->driver);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (driver->remove) {
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0int status;
> -
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(dev, "remove\n");
> =C2=A0
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0status =3D driver->remove(client);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0if (status)
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(=
dev, "remove failed (%pe), will be
> ignored\n", ERR_PTR(status));
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0driver->remove(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0devres_release_group(&cli=
ent->dev, client->devres_group_id);
> diff --git a/drivers/i2c/i2c-slave-eeprom.c b/drivers/i2c/i2c-slave-
> eeprom.c
> index 5c7ae421cacf..4abc2d919881 100644
> --- a/drivers/i2c/i2c-slave-eeprom.c
> +++ b/drivers/i2c/i2c-slave-eeprom.c
> @@ -181,14 +181,12 @@ static int i2c_slave_eeprom_probe(struct
> i2c_client *client, const struct i2c_de
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0};
> =C2=A0
> -static int i2c_slave_eeprom_remove(struct i2c_client *client)
> +static void i2c_slave_eeprom_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct eeprom_data *eepro=
m =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_slave_unregister(clie=
nt);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_bin_file(&cl=
ient->dev.kobj, &eeprom->bin);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id i2c_slave_eeprom_id[] =3D {
> diff --git a/drivers/i2c/i2c-slave-testunit.c b/drivers/i2c/i2c-
> slave-testunit.c
> index 56dae08dfd48..75ee7ebdb614 100644
> --- a/drivers/i2c/i2c-slave-testunit.c
> +++ b/drivers/i2c/i2c-slave-testunit.c
> @@ -153,13 +153,12 @@ static int i2c_slave_testunit_probe(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return i2c_slave_register=
(client,
> i2c_slave_testunit_slave_cb);
> =C2=A0};
> =C2=A0
> -static int i2c_slave_testunit_remove(struct i2c_client *client)
> +static void i2c_slave_testunit_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct testunit_data *tu =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_delayed_work_sync(=
&tu->worker);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_slave_unregister(clie=
nt);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id i2c_slave_testunit_id[] =3D {
> diff --git a/drivers/i2c/i2c-smbus.c b/drivers/i2c/i2c-smbus.c
> index 775332945ad0..b0f1da7ec0f2 100644
> --- a/drivers/i2c/i2c-smbus.c
> +++ b/drivers/i2c/i2c-smbus.c
> @@ -153,12 +153,11 @@ static int smbalert_probe(struct i2c_client
> *ara,
> =C2=A0}
> =C2=A0
> =C2=A0/* IRQ and memory resources are managed so they are freed
> automatically */
> -static int smbalert_remove(struct i2c_client *ara)
> +static void smbalert_remove(struct i2c_client *ara)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct i2c_smbus_alert *a=
lert =3D i2c_get_clientdata(ara);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_work_sync(&alert->=
alert);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id smbalert_ids[] =3D {
> diff --git a/drivers/i2c/muxes/i2c-mux-ltc4306.c
> b/drivers/i2c/muxes/i2c-mux-ltc4306.c
> index 704f1e50f6f4..70835825083f 100644
> --- a/drivers/i2c/muxes/i2c-mux-ltc4306.c
> +++ b/drivers/i2c/muxes/i2c-mux-ltc4306.c
> @@ -294,13 +294,11 @@ static int ltc4306_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ltc4306_remove(struct i2c_client *client)
> +static void ltc4306_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct i2c_mux_core *muxc=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_mux_del_adapters(muxc=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver ltc4306_driver =3D {
> diff --git a/drivers/i2c/muxes/i2c-mux-pca9541.c
> b/drivers/i2c/muxes/i2c-mux-pca9541.c
> index 6daec8d3d331..ea83de78f52d 100644
> --- a/drivers/i2c/muxes/i2c-mux-pca9541.c
> +++ b/drivers/i2c/muxes/i2c-mux-pca9541.c
> @@ -325,12 +325,11 @@ static int pca9541_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int pca9541_remove(struct i2c_client *client)
> +static void pca9541_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct i2c_mux_core *muxc=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_mux_del_adapters(muxc=
);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver pca9541_driver =3D {
> diff --git a/drivers/i2c/muxes/i2c-mux-pca954x.c
> b/drivers/i2c/muxes/i2c-mux-pca954x.c
> index 4ad665757dd8..a5f458b635df 100644
> --- a/drivers/i2c/muxes/i2c-mux-pca954x.c
> +++ b/drivers/i2c/muxes/i2c-mux-pca954x.c
> @@ -521,14 +521,13 @@ static int pca954x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int pca954x_remove(struct i2c_client *client)
> +static void pca954x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct i2c_mux_core *muxc=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0device_remove_file(&clien=
t->dev, &dev_attr_idle_state);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pca954x_cleanup(muxc);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/iio/accel/bma180.c b/drivers/iio/accel/bma180.c
> index 9c9e98578667..d03fc3400f94 100644
> --- a/drivers/iio/accel/bma180.c
> +++ b/drivers/iio/accel/bma180.c
> @@ -1045,7 +1045,7 @@ static int bma180_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int bma180_remove(struct i2c_client *client)
> +static void bma180_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bma180_data *data =
=3D iio_priv(indio_dev);
> @@ -1062,8 +1062,6 @@ static int bma180_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&data->mutex=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
ddio_supply);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
dd_supply);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int bma180_suspend(struct device *dev)
> diff --git a/drivers/iio/accel/bma400_i2c.c
> b/drivers/iio/accel/bma400_i2c.c
> index da104ffd3fe0..90c99ab8c8f2 100644
> --- a/drivers/iio/accel/bma400_i2c.c
> +++ b/drivers/iio/accel/bma400_i2c.c
> @@ -27,11 +27,9 @@ static int bma400_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return bma400_probe(&clie=
nt->dev, regmap, id->name);
> =C2=A0}
> =C2=A0
> -static int bma400_i2c_remove(struct i2c_client *client)
> +static void bma400_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0bma400_remove(&client->de=
v);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id bma400_i2c_ids[] =3D {
> diff --git a/drivers/iio/accel/bmc150-accel-i2c.c
> b/drivers/iio/accel/bmc150-accel-i2c.c
> index dff4d7dd101c..be8cc598b88e 100644
> --- a/drivers/iio/accel/bmc150-accel-i2c.c
> +++ b/drivers/iio/accel/bmc150-accel-i2c.c
> @@ -209,13 +209,11 @@ static int bmc150_accel_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int bmc150_accel_remove(struct i2c_client *client)
> +static void bmc150_accel_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0bmc150_acpi_dual_accel_re=
move(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0bmc150_accel_core_remove(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct acpi_device_id bmc150_accel_acpi_match[] =3D {
> diff --git a/drivers/iio/accel/kxcjk-1013.c
> b/drivers/iio/accel/kxcjk-1013.c
> index 748b35c2f0c3..94f7b6ac5c87 100644
> --- a/drivers/iio/accel/kxcjk-1013.c
> +++ b/drivers/iio/accel/kxcjk-1013.c
> @@ -1611,7 +1611,7 @@ static int kxcjk1013_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int kxcjk1013_remove(struct i2c_client *client)
> +static void kxcjk1013_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct kxcjk1013_data *da=
ta =3D iio_priv(indio_dev);
> @@ -1630,8 +1630,6 @@ static int kxcjk1013_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&data->mutex);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kxcjk1013_set_mode(data, =
STANDBY);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&data->mutex=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/iio/accel/kxsd9-i2c.c b/drivers/iio/accel/kxsd9-
> i2c.c
> index c8dc52f11037..86c0d70d0da7 100644
> --- a/drivers/iio/accel/kxsd9-i2c.c
> +++ b/drivers/iio/accel/kxsd9-i2c.c
> @@ -32,11 +32,9 @@ static int kxsd9_i2c_probe(struct i2c_client *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 i2c->name);
> =C2=A0}
> =C2=A0
> -static int kxsd9_i2c_remove(struct i2c_client *client)
> +static void kxsd9_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kxsd9_common_remove(&clie=
nt->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id kxsd9_of_match[] =3D {
> diff --git a/drivers/iio/accel/mc3230.c b/drivers/iio/accel/mc3230.c
> index c15d16e7f1da..2462000e0519 100644
> --- a/drivers/iio/accel/mc3230.c
> +++ b/drivers/iio/accel/mc3230.c
> @@ -151,15 +151,13 @@ static int mc3230_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mc3230_remove(struct i2c_client *client)
> +static void mc3230_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mc3230_set_opcon(iio_priv=
(indio_dev),
> MC3230_MODE_OPCON_STANDBY);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int mc3230_suspend(struct device *dev)
> diff --git a/drivers/iio/accel/mma7455_i2c.c
> b/drivers/iio/accel/mma7455_i2c.c
> index a3b84e8a3ea8..c63b321b01cd 100644
> --- a/drivers/iio/accel/mma7455_i2c.c
> +++ b/drivers/iio/accel/mma7455_i2c.c
> @@ -26,11 +26,9 @@ static int mma7455_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return mma7455_core_probe=
(&i2c->dev, regmap, name);
> =C2=A0}
> =C2=A0
> -static int mma7455_i2c_remove(struct i2c_client *i2c)
> +static void mma7455_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mma7455_core_remove(&i2c-=
>dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mma7455_i2c_ids[] =3D {
> diff --git a/drivers/iio/accel/mma7660.c
> b/drivers/iio/accel/mma7660.c
> index 112a5a33c29f..ad2aac0ec1d4 100644
> --- a/drivers/iio/accel/mma7660.c
> +++ b/drivers/iio/accel/mma7660.c
> @@ -207,7 +207,7 @@ static int mma7660_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mma7660_remove(struct i2c_client *client)
> +static void mma7660_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> @@ -218,8 +218,6 @@ static int mma7660_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to put device in
> stand-by mode (%pe), ignoring\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ER=
R_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int mma7660_suspend(struct device *dev)
> diff --git a/drivers/iio/accel/mma8452.c
> b/drivers/iio/accel/mma8452.c
> index c7d9ca96dbaa..3ba28c2ff68a 100644
> --- a/drivers/iio/accel/mma8452.c
> +++ b/drivers/iio/accel/mma8452.c
> @@ -1735,7 +1735,7 @@ static int mma8452_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mma8452_remove(struct i2c_client *client)
> +static void mma8452_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mma8452_data *data=
 =3D iio_priv(indio_dev);
> @@ -1751,8 +1751,6 @@ static int mma8452_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
ddio_reg);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
dd_reg);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/iio/accel/mma9551.c
> b/drivers/iio/accel/mma9551.c
> index 123cdbbb265c..f7a793f4a8e3 100644
> --- a/drivers/iio/accel/mma9551.c
> +++ b/drivers/iio/accel/mma9551.c
> @@ -509,7 +509,7 @@ static int mma9551_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mma9551_remove(struct i2c_client *client)
> +static void mma9551_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mma9551_data *data=
 =3D iio_priv(indio_dev);
> @@ -522,8 +522,6 @@ static int mma9551_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&data->mutex);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mma9551_set_device_state(=
data->client, false);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&data->mutex=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int mma9551_runtime_suspend(struct device *dev)
> diff --git a/drivers/iio/accel/mma9553.c
> b/drivers/iio/accel/mma9553.c
> index 09df58d4be33..2da0e005b13e 100644
> --- a/drivers/iio/accel/mma9553.c
> +++ b/drivers/iio/accel/mma9553.c
> @@ -1148,7 +1148,7 @@ static int mma9553_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mma9553_remove(struct i2c_client *client)
> +static void mma9553_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mma9553_data *data=
 =3D iio_priv(indio_dev);
> @@ -1161,8 +1161,6 @@ static int mma9553_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&data->mutex);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mma9551_set_device_state(=
data->client, false);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&data->mutex=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int mma9553_runtime_suspend(struct device *dev)
> diff --git a/drivers/iio/accel/stk8312.c
> b/drivers/iio/accel/stk8312.c
> index ceca28913355..7b1d6fb692b3 100644
> --- a/drivers/iio/accel/stk8312.c
> +++ b/drivers/iio/accel/stk8312.c
> @@ -597,7 +597,7 @@ static int stk8312_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int stk8312_remove(struct i2c_client *client)
> +static void stk8312_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct stk8312_data *data=
 =3D iio_priv(indio_dev);
> @@ -609,8 +609,6 @@ static int stk8312_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0iio_trigger_unregister(data->dready_trig);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0stk8312_set_mode(data, ST=
K8312_MODE_STANDBY);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int stk8312_suspend(struct device *dev)
> diff --git a/drivers/iio/accel/stk8ba50.c
> b/drivers/iio/accel/stk8ba50.c
> index 7d59efb41e22..2f5e4ab2a6e7 100644
> --- a/drivers/iio/accel/stk8ba50.c
> +++ b/drivers/iio/accel/stk8ba50.c
> @@ -490,7 +490,7 @@ static int stk8ba50_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int stk8ba50_remove(struct i2c_client *client)
> +static void stk8ba50_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct stk8ba50_data *dat=
a =3D iio_priv(indio_dev);
> @@ -502,8 +502,6 @@ static int stk8ba50_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0iio_trigger_unregister(data->dready_trig);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0stk8ba50_set_power(data, =
STK8BA50_MODE_SUSPEND);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int stk8ba50_suspend(struct device *dev)
> diff --git a/drivers/iio/adc/ad799x.c b/drivers/iio/adc/ad799x.c
> index 220228c375d3..746bf9a01c25 100644
> --- a/drivers/iio/adc/ad799x.c
> +++ b/drivers/iio/adc/ad799x.c
> @@ -880,7 +880,7 @@ static int ad799x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ad799x_remove(struct i2c_client *client)
> +static void ad799x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ad799x_state *st =
=3D iio_priv(indio_dev);
> @@ -892,8 +892,6 @@ static int ad799x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(st->vref);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(st->reg=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(st->rx_buf);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused ad799x_suspend(struct device *dev)
> diff --git a/drivers/iio/adc/ina2xx-adc.c b/drivers/iio/adc/ina2xx-
> adc.c
> index 240e6c420701..910e7e965fc4 100644
> --- a/drivers/iio/adc/ina2xx-adc.c
> +++ b/drivers/iio/adc/ina2xx-adc.c
> @@ -1034,7 +1034,7 @@ static int ina2xx_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return iio_device_registe=
r(indio_dev);
> =C2=A0}
> =C2=A0
> -static int ina2xx_remove(struct i2c_client *client)
> +static void ina2xx_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ina2xx_chip_info *=
chip =3D iio_priv(indio_dev);
> @@ -1048,8 +1048,6 @@ static int ina2xx_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to power down device
> (%pe)\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ER=
R_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ina2xx_id[] =3D {
> diff --git a/drivers/iio/adc/ltc2497.c b/drivers/iio/adc/ltc2497.c
> index 1adddf5a88a9..be57f1157796 100644
> --- a/drivers/iio/adc/ltc2497.c
> +++ b/drivers/iio/adc/ltc2497.c
> @@ -74,13 +74,11 @@ static int ltc2497_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ltc2497core_probe(=
dev, indio_dev);
> =C2=A0}
> =C2=A0
> -static int ltc2497_remove(struct i2c_client *client)
> +static void ltc2497_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ltc2497core_remove(indio_=
dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ltc2497_id[] =3D {
> diff --git a/drivers/iio/adc/ti-ads1015.c b/drivers/iio/adc/ti-
> ads1015.c
> index e3dfc155fbe2..8bceba694026 100644
> --- a/drivers/iio/adc/ti-ads1015.c
> +++ b/drivers/iio/adc/ti-ads1015.c
> @@ -1094,7 +1094,7 @@ static int ads1015_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ads1015_remove(struct i2c_client *client)
> +static void ads1015_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ads1015_data *data=
 =3D iio_priv(indio_dev);
> @@ -1110,8 +1110,6 @@ static int ads1015_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to power down
> (%pe)\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ER=
R_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/iio/chemical/atlas-sensor.c
> b/drivers/iio/chemical/atlas-sensor.c
> index 8378c00fa2ff..7cac77a931c7 100644
> --- a/drivers/iio/chemical/atlas-sensor.c
> +++ b/drivers/iio/chemical/atlas-sensor.c
> @@ -722,7 +722,7 @@ static int atlas_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int atlas_remove(struct i2c_client *client)
> +static void atlas_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct atlas_data *data =
=3D iio_priv(indio_dev);
> @@ -739,8 +739,6 @@ static int atlas_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_err(&client->dev, "Failed to power down device
> (%pe)\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ERR=
_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int atlas_runtime_suspend(struct device *dev)
> diff --git a/drivers/iio/chemical/ccs811.c
> b/drivers/iio/chemical/ccs811.c
> index 560183efb36f..ba4045e20303 100644
> --- a/drivers/iio/chemical/ccs811.c
> +++ b/drivers/iio/chemical/ccs811.c
> @@ -532,7 +532,7 @@ static int ccs811_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ccs811_remove(struct i2c_client *client)
> +static void ccs811_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ccs811_data *data =
=3D iio_priv(indio_dev);
> @@ -548,8 +548,6 @@ static int ccs811_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to power down device
> (%pe)\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ER=
R_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ccs811_id[] =3D {
> diff --git a/drivers/iio/chemical/sgp30.c
> b/drivers/iio/chemical/sgp30.c
> index 2343d444604d..e2c13c78c7e0 100644
> --- a/drivers/iio/chemical/sgp30.c
> +++ b/drivers/iio/chemical/sgp30.c
> @@ -552,15 +552,13 @@ static int sgp_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int sgp_remove(struct i2c_client *client)
> +static void sgp_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct sgp_data *data =3D=
 iio_priv(indio_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (data->iaq_thread)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0kthread_stop(data->iaq_thread);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id sgp_id[] =3D {
> diff --git a/drivers/iio/dac/ad5380.c b/drivers/iio/dac/ad5380.c
> index a44c83242fb1..62d7fc53c7f4 100644
> --- a/drivers/iio/dac/ad5380.c
> +++ b/drivers/iio/dac/ad5380.c
> @@ -561,11 +561,9 @@ static int ad5380_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ad5380_probe(&i2c-=
>dev, regmap, id->driver_data, id-
> >name);
> =C2=A0}
> =C2=A0
> -static int ad5380_i2c_remove(struct i2c_client *i2c)
> +static void ad5380_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ad5380_remove(&i2c->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ad5380_i2c_ids[] =3D {
> diff --git a/drivers/iio/dac/ad5446.c b/drivers/iio/dac/ad5446.c
> index 09e242949cd0..7324065d3782 100644
> --- a/drivers/iio/dac/ad5446.c
> +++ b/drivers/iio/dac/ad5446.c
> @@ -575,11 +575,9 @@ static int ad5446_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0&ad5446_i2c_chip_info[id->driver_data]);
> =C2=A0}
> =C2=A0
> -static int ad5446_i2c_remove(struct i2c_client *i2c)
> +static void ad5446_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ad5446_remove(&i2c->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ad5446_i2c_ids[] =3D {
> diff --git a/drivers/iio/dac/ad5593r.c b/drivers/iio/dac/ad5593r.c
> index 34e1319a9712..92be661034a6 100644
> --- a/drivers/iio/dac/ad5593r.c
> +++ b/drivers/iio/dac/ad5593r.c
> @@ -97,11 +97,9 @@ static int ad5593r_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ad5592r_probe(&i2c=
->dev, id->name, &ad5593r_rw_ops);
> =C2=A0}
> =C2=A0
> -static int ad5593r_i2c_remove(struct i2c_client *i2c)
> +static void ad5593r_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ad5592r_remove(&i2c->dev)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ad5593r_i2c_ids[] =3D {
> diff --git a/drivers/iio/dac/ad5696-i2c.c b/drivers/iio/dac/ad5696-
> i2c.c
> index 762503c1901b..aa36cbf0137c 100644
> --- a/drivers/iio/dac/ad5696-i2c.c
> +++ b/drivers/iio/dac/ad5696-i2c.c
> @@ -65,11 +65,9 @@ static int ad5686_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 ad5686_i2c_write, ad5686_i2c_read);
> =C2=A0}
> =C2=A0
> -static int ad5686_i2c_remove(struct i2c_client *i2c)
> +static void ad5686_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ad5686_remove(&i2c->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ad5686_i2c_id[] =3D {
> diff --git a/drivers/iio/dac/ds4424.c b/drivers/iio/dac/ds4424.c
> index 5a5e967b0be4..e3dcf1efb7fa 100644
> --- a/drivers/iio/dac/ds4424.c
> +++ b/drivers/iio/dac/ds4424.c
> @@ -281,15 +281,13 @@ static int ds4424_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ds4424_remove(struct i2c_client *client)
> +static void ds4424_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ds4424_data *data =
=3D iio_priv(indio_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
cc_reg);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ds4424_id[] =3D {
> diff --git a/drivers/iio/dac/m62332.c b/drivers/iio/dac/m62332.c
> index 22b02f50fe41..5a812f87970c 100644
> --- a/drivers/iio/dac/m62332.c
> +++ b/drivers/iio/dac/m62332.c
> @@ -218,7 +218,7 @@ static int m62332_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int m62332_remove(struct i2c_client *client)
> +static void m62332_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -226,8 +226,6 @@ static int m62332_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_map_array_unregister(=
indio_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0m62332_set_value(indio_de=
v, 0, 0);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0m62332_set_value(indio_de=
v, 0, 1);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id m62332_id[] =3D {
> diff --git a/drivers/iio/dac/mcp4725.c b/drivers/iio/dac/mcp4725.c
> index 7fcb86288823..29ab21904aca 100644
> --- a/drivers/iio/dac/mcp4725.c
> +++ b/drivers/iio/dac/mcp4725.c
> @@ -485,7 +485,7 @@ static int mcp4725_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int mcp4725_remove(struct i2c_client *client)
> +static void mcp4725_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mcp4725_data *data=
 =3D iio_priv(indio_dev);
> @@ -495,8 +495,6 @@ static int mcp4725_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (data->vref_reg)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->vref_reg);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
dd_reg);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mcp4725_id[] =3D {
> diff --git a/drivers/iio/dac/ti-dac5571.c b/drivers/iio/dac/ti-
> dac5571.c
> index 4b6b04038e94..96b8d80b72a0 100644
> --- a/drivers/iio/dac/ti-dac5571.c
> +++ b/drivers/iio/dac/ti-dac5571.c
> @@ -381,15 +381,13 @@ static int dac5571_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int dac5571_remove(struct i2c_client *i2c)
> +static void dac5571_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(i2c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dac5571_data *data=
 =3D iio_priv(indio_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
ref);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id dac5571_of_id[] =3D {
> diff --git a/drivers/iio/gyro/bmg160_i2c.c
> b/drivers/iio/gyro/bmg160_i2c.c
> index b3fa46bd02cb..908ccc385254 100644
> --- a/drivers/iio/gyro/bmg160_i2c.c
> +++ b/drivers/iio/gyro/bmg160_i2c.c
> @@ -32,11 +32,9 @@ static int bmg160_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return bmg160_core_probe(=
&client->dev, regmap, client->irq,
> name);
> =C2=A0}
> =C2=A0
> -static int bmg160_i2c_remove(struct i2c_client *client)
> +static void bmg160_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0bmg160_core_remove(&clien=
t->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct acpi_device_id bmg160_acpi_match[] =3D {
> diff --git a/drivers/iio/gyro/fxas21002c_i2c.c
> b/drivers/iio/gyro/fxas21002c_i2c.c
> index a7807fd97483..13bb52c594d1 100644
> --- a/drivers/iio/gyro/fxas21002c_i2c.c
> +++ b/drivers/iio/gyro/fxas21002c_i2c.c
> @@ -33,11 +33,9 @@ static int fxas21002c_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return fxas21002c_core_pr=
obe(&i2c->dev, regmap, i2c->irq,
> i2c->name);
> =C2=A0}
> =C2=A0
> -static int fxas21002c_i2c_remove(struct i2c_client *i2c)
> +static void fxas21002c_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fxas21002c_core_remove(&i=
2c->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id fxas21002c_i2c_id[] =3D {
> diff --git a/drivers/iio/gyro/itg3200_core.c
> b/drivers/iio/gyro/itg3200_core.c
> index a7f1bbb5f289..8b3758e3b9e8 100644
> --- a/drivers/iio/gyro/itg3200_core.c
> +++ b/drivers/iio/gyro/itg3200_core.c
> @@ -350,7 +350,7 @@ static int itg3200_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int itg3200_remove(struct i2c_client *client)
> +static void itg3200_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -360,8 +360,6 @@ static int itg3200_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0itg3200_remove_trigger(indio_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0itg3200_buffer_unconfigur=
e(indio_dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused itg3200_suspend(struct device *dev)
> diff --git a/drivers/iio/gyro/mpu3050-i2c.c
> b/drivers/iio/gyro/mpu3050-i2c.c
> index 5b5f58baaf7f..4d5e4b04745d 100644
> --- a/drivers/iio/gyro/mpu3050-i2c.c
> +++ b/drivers/iio/gyro/mpu3050-i2c.c
> @@ -78,7 +78,7 @@ static int mpu3050_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int mpu3050_i2c_remove(struct i2c_client *client)
> +static void mpu3050_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D dev_get_drvdata(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mpu3050 *mpu3050 =
=3D iio_priv(indio_dev);
> @@ -87,8 +87,6 @@ static int mpu3050_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0i2c_mux_del_adapters(mpu3050->i2cmux);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mpu3050_common_remove(&cl=
ient->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/iio/health/afe4404.c
> b/drivers/iio/health/afe4404.c
> index 1bb7de60f8ca..a87337453824 100644
> --- a/drivers/iio/health/afe4404.c
> +++ b/drivers/iio/health/afe4404.c
> @@ -577,7 +577,7 @@ static int afe4404_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int afe4404_remove(struct i2c_client *client)
> +static void afe4404_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct afe4404_data *afe =
=3D iio_priv(indio_dev);
> @@ -593,8 +593,6 @@ static int afe4404_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ret =3D regulator_disable=
(afe->regulator);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_err(afe->dev, "Unable to disable regulator\n");
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id afe4404_ids[] =3D {
> diff --git a/drivers/iio/health/max30100.c
> b/drivers/iio/health/max30100.c
> index ad5717965223..2cca5e0519f8 100644
> --- a/drivers/iio/health/max30100.c
> +++ b/drivers/iio/health/max30100.c
> @@ -471,15 +471,13 @@ static int max30100_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return iio_device_registe=
r(indio_dev);
> =C2=A0}
> =C2=A0
> -static int max30100_remove(struct i2c_client *client)
> +static void max30100_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max30100_data *dat=
a =3D iio_priv(indio_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0max30100_set_powermode(da=
ta, false);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max30100_id[] =3D {
> diff --git a/drivers/iio/health/max30102.c
> b/drivers/iio/health/max30102.c
> index abbcef563807..437298a29f2d 100644
> --- a/drivers/iio/health/max30102.c
> +++ b/drivers/iio/health/max30102.c
> @@ -592,15 +592,13 @@ static int max30102_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return iio_device_registe=
r(indio_dev);
> =C2=A0}
> =C2=A0
> -static int max30102_remove(struct i2c_client *client)
> +static void max30102_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max30102_data *dat=
a =3D iio_priv(indio_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0max30102_set_power(data, =
false);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max30102_id[] =3D {
> diff --git a/drivers/iio/humidity/hdc2010.c
> b/drivers/iio/humidity/hdc2010.c
> index 1381df46187c..d6858ccb056e 100644
> --- a/drivers/iio/humidity/hdc2010.c
> +++ b/drivers/iio/humidity/hdc2010.c
> @@ -308,7 +308,7 @@ static int hdc2010_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return iio_device_registe=
r(indio_dev);
> =C2=A0}
> =C2=A0
> -static int hdc2010_remove(struct i2c_client *client)
> +static void hdc2010_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct hdc2010_data *data=
 =3D iio_priv(indio_dev);
> @@ -318,8 +318,6 @@ static int hdc2010_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Disable Automatic Meas=
urement Mode */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (hdc2010_update_drdy_c=
onfig(data, HDC2010_AMM, 0))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Unable to restore default
> AMM\n");
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id hdc2010_id[] =3D {
> diff --git a/drivers/iio/imu/inv_mpu6050/inv_mpu_i2c.c
> b/drivers/iio/imu/inv_mpu6050/inv_mpu_i2c.c
> index 2aa647704a79..14255a918eb1 100644
> --- a/drivers/iio/imu/inv_mpu6050/inv_mpu_i2c.c
> +++ b/drivers/iio/imu/inv_mpu6050/inv_mpu_i2c.c
> @@ -157,7 +157,7 @@ static int inv_mpu_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return result;
> =C2=A0}
> =C2=A0
> -static int inv_mpu_remove(struct i2c_client *client)
> +static void inv_mpu_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct inv_mpu6050_state =
*st =3D iio_priv(indio_dev);
> @@ -166,8 +166,6 @@ static int inv_mpu_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0inv_mpu_acpi_delete_mux_client(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0i2c_mux_del_adapters(st->muxc);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/iio/imu/kmx61.c b/drivers/iio/imu/kmx61.c
> index ec23b1ee472b..b10c0dcac0bb 100644
> --- a/drivers/iio/imu/kmx61.c
> +++ b/drivers/iio/imu/kmx61.c
> @@ -1418,7 +1418,7 @@ static int kmx61_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int kmx61_remove(struct i2c_client *client)
> +static void kmx61_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct kmx61_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1439,8 +1439,6 @@ static int kmx61_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&data->lock);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kmx61_set_mode(data, KMX6=
1_ALL_STBY, KMX61_ACC | KMX61_MAG,
> true);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&data->lock)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int kmx61_suspend(struct device *dev)
> diff --git a/drivers/iio/light/apds9300.c
> b/drivers/iio/light/apds9300.c
> index 0f9d77598997..b70f2681bcb3 100644
> --- a/drivers/iio/light/apds9300.c
> +++ b/drivers/iio/light/apds9300.c
> @@ -452,7 +452,7 @@ static int apds9300_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int apds9300_remove(struct i2c_client *client)
> +static void apds9300_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct apds9300_data *dat=
a =3D iio_priv(indio_dev);
> @@ -462,8 +462,6 @@ static int apds9300_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Ensure that power off =
and interrupts are disabled */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0apds9300_set_intr_state(d=
ata, 0);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0apds9300_set_power_state(=
data, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int apds9300_suspend(struct device *dev)
> diff --git a/drivers/iio/light/apds9960.c
> b/drivers/iio/light/apds9960.c
> index 09b831f9f40b..b62c139baf41 100644
> --- a/drivers/iio/light/apds9960.c
> +++ b/drivers/iio/light/apds9960.c
> @@ -1067,7 +1067,7 @@ static int apds9960_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int apds9960_remove(struct i2c_client *client)
> +static void apds9960_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct apds9960_data *dat=
a =3D iio_priv(indio_dev);
> @@ -1076,8 +1076,6 @@ static int apds9960_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0apds9960_set_powermode(da=
ta, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/iio/light/bh1750.c b/drivers/iio/light/bh1750.c
> index 48484b9401b9..034c47ef6e33 100644
> --- a/drivers/iio/light/bh1750.c
> +++ b/drivers/iio/light/bh1750.c
> @@ -263,7 +263,7 @@ static int bh1750_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return iio_device_registe=
r(indio_dev);
> =C2=A0}
> =C2=A0
> -static int bh1750_remove(struct i2c_client *client)
> +static void bh1750_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bh1750_data *data =
=3D iio_priv(indio_dev);
> @@ -273,8 +273,6 @@ static int bh1750_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&data->lock);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_smbus_write_byte(clie=
nt, BH1750_POWER_DOWN);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&data->lock)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused bh1750_suspend(struct device *dev)
> diff --git a/drivers/iio/light/bh1780.c b/drivers/iio/light/bh1780.c
> index fc7141390117..90bca392b262 100644
> --- a/drivers/iio/light/bh1780.c
> +++ b/drivers/iio/light/bh1780.c
> @@ -202,7 +202,7 @@ static int bh1780_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int bh1780_remove(struct i2c_client *client)
> +static void bh1780_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bh1780_data *bh178=
0 =3D iio_priv(indio_dev);
> @@ -216,8 +216,6 @@ static int bh1780_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret < 0)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_err(&client->dev, "failed to power off (%pe)\n"=
,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ERR=
_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int bh1780_runtime_suspend(struct device *dev)
> diff --git a/drivers/iio/light/cm3232.c b/drivers/iio/light/cm3232.c
> index 2c80a0535d2c..5214cd014cf8 100644
> --- a/drivers/iio/light/cm3232.c
> +++ b/drivers/iio/light/cm3232.c
> @@ -357,7 +357,7 @@ static int cm3232_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return iio_device_registe=
r(indio_dev);
> =C2=A0}
> =C2=A0
> -static int cm3232_remove(struct i2c_client *client)
> +static void cm3232_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -365,8 +365,6 @@ static int cm3232_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0CM3232_CMD_ALS_DISABLE);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cm3232_id[] =3D {
> diff --git a/drivers/iio/light/cm36651.c
> b/drivers/iio/light/cm36651.c
> index 89f5e48a6642..6615c98b601c 100644
> --- a/drivers/iio/light/cm36651.c
> +++ b/drivers/iio/light/cm36651.c
> @@ -700,7 +700,7 @@ static int cm36651_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cm36651_remove(struct i2c_client *client)
> +static void cm36651_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cm36651_data *cm36=
651 =3D iio_priv(indio_dev);
> @@ -710,8 +710,6 @@ static int cm36651_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0free_irq(client->irq, ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(cm3=
6651->ps_client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(cm3=
6651->ara_client);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cm36651_id[] =3D {
> diff --git a/drivers/iio/light/gp2ap002.c
> b/drivers/iio/light/gp2ap002.c
> index c6d1d88d3775..855dc63fb0a5 100644
> --- a/drivers/iio/light/gp2ap002.c
> +++ b/drivers/iio/light/gp2ap002.c
> @@ -619,7 +619,7 @@ static int gp2ap002_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int gp2ap002_remove(struct i2c_client *client)
> +static void gp2ap002_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct gp2ap002 *gp2ap002=
 =3D iio_priv(indio_dev);
> @@ -631,8 +631,6 @@ static int gp2ap002_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(gp2ap00=
2->vio);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(gp2ap00=
2->vdd);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused gp2ap002_runtime_suspend(struct device
> *dev)
> diff --git a/drivers/iio/light/gp2ap020a00f.c
> b/drivers/iio/light/gp2ap020a00f.c
> index b820041159f7..826439299e8b 100644
> --- a/drivers/iio/light/gp2ap020a00f.c
> +++ b/drivers/iio/light/gp2ap020a00f.c
> @@ -1573,7 +1573,7 @@ static int gp2ap020a00f_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int gp2ap020a00f_remove(struct i2c_client *client)
> +static void gp2ap020a00f_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct gp2ap020a00f_data =
*data =3D iio_priv(indio_dev);
> @@ -1589,8 +1589,6 @@ static int gp2ap020a00f_remove(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0free_irq(client->irq, ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_triggered_buffer_clea=
nup(indio_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
led_reg);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id gp2ap020a00f_id[] =3D {
> diff --git a/drivers/iio/light/isl29028.c
> b/drivers/iio/light/isl29028.c
> index 720fa83d44e0..6c344875c791 100644
> --- a/drivers/iio/light/isl29028.c
> +++ b/drivers/iio/light/isl29028.c
> @@ -636,7 +636,7 @@ static int isl29028_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int isl29028_remove(struct i2c_client *client)
> +static void isl29028_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct isl29028_chip *chi=
p =3D iio_priv(indio_dev);
> @@ -647,8 +647,6 @@ static int isl29028_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0isl29028_clear_configure_=
reg(chip);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused isl29028_suspend(struct device *dev)
> diff --git a/drivers/iio/light/isl29125.c
> b/drivers/iio/light/isl29125.c
> index eb68a52aab82..c199e63cce82 100644
> --- a/drivers/iio/light/isl29125.c
> +++ b/drivers/iio/light/isl29125.c
> @@ -300,15 +300,13 @@ static int isl29125_powerdown(struct
> isl29125_data *data)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0(data->conf1 & ~ISL29125_MODE_MASK) |
> ISL29125_MODE_PD);
> =C2=A0}
> =C2=A0
> -static int isl29125_remove(struct i2c_client *client)
> +static void isl29125_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_triggered_buffer_clea=
nup(indio_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0isl29125_powerdown(iio_pr=
iv(indio_dev));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int isl29125_suspend(struct device *dev)
> diff --git a/drivers/iio/light/jsa1212.c
> b/drivers/iio/light/jsa1212.c
> index 5387c12231cf..57ce6d75966c 100644
> --- a/drivers/iio/light/jsa1212.c
> +++ b/drivers/iio/light/jsa1212.c
> @@ -373,7 +373,7 @@ static int jsa1212_power_off(struct jsa1212_data
> *data)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int jsa1212_remove(struct i2c_client *client)
> +static void jsa1212_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct jsa1212_data *data=
 =3D iio_priv(indio_dev);
> @@ -381,8 +381,6 @@ static int jsa1212_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0jsa1212_power_off(data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int jsa1212_suspend(struct device *dev)
> diff --git a/drivers/iio/light/ltr501.c b/drivers/iio/light/ltr501.c
> index 679a1e1086ae..74a1ccda8b9c 100644
> --- a/drivers/iio/light/ltr501.c
> +++ b/drivers/iio/light/ltr501.c
> @@ -1600,15 +1600,13 @@ static int ltr501_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ltr501_remove(struct i2c_client *client)
> +static void ltr501_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_triggered_buffer_clea=
nup(indio_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ltr501_powerdown(iio_priv=
(indio_dev));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ltr501_suspend(struct device *dev)
> diff --git a/drivers/iio/light/opt3001.c
> b/drivers/iio/light/opt3001.c
> index a326d47afc9b..a26d1c3f9543 100644
> --- a/drivers/iio/light/opt3001.c
> +++ b/drivers/iio/light/opt3001.c
> @@ -794,7 +794,7 @@ static int opt3001_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int opt3001_remove(struct i2c_client *client)
> +static void opt3001_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *iio =3D i=
2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct opt3001 *opt =3D i=
io_priv(iio);
> @@ -808,7 +808,7 @@ static int opt3001_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret < 0) {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_err(opt->dev, "failed to read register %02x\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0OPT3001_CONFIGURATION);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0reg =3D ret;
> @@ -820,8 +820,6 @@ static int opt3001_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_err(opt->dev, "failed to write register %02x\n"=
,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0OPT3001_CONFIGURATION);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id opt3001_id[] =3D {
> diff --git a/drivers/iio/light/pa12203001.c
> b/drivers/iio/light/pa12203001.c
> index 772874e707ae..3cb2de51f4aa 100644
> --- a/drivers/iio/light/pa12203001.c
> +++ b/drivers/iio/light/pa12203001.c
> @@ -394,7 +394,7 @@ static int pa12203001_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int pa12203001_remove(struct i2c_client *client)
> +static void pa12203001_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> @@ -408,8 +408,6 @@ static int pa12203001_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to power down
> (%pe)\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ER=
R_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#if defined(CONFIG_PM_SLEEP) || defined(CONFIG_PM)
> diff --git a/drivers/iio/light/rpr0521.c
> b/drivers/iio/light/rpr0521.c
> index dabdd05f0e2c..d1c16dd76058 100644
> --- a/drivers/iio/light/rpr0521.c
> +++ b/drivers/iio/light/rpr0521.c
> @@ -1041,7 +1041,7 @@ static int rpr0521_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rpr0521_remove(struct i2c_client *client)
> +static void rpr0521_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1051,8 +1051,6 @@ static int rpr0521_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rpr0521_poweroff(iio_priv=
(indio_dev));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int rpr0521_runtime_suspend(struct device *dev)
> diff --git a/drivers/iio/light/stk3310.c
> b/drivers/iio/light/stk3310.c
> index f7cc7a6c0c8d..7b8e0da6aabc 100644
> --- a/drivers/iio/light/stk3310.c
> +++ b/drivers/iio/light/stk3310.c
> @@ -649,14 +649,12 @@ static int stk3310_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int stk3310_remove(struct i2c_client *client)
> +static void stk3310_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0stk3310_set_state(iio_pri=
v(indio_dev),
> STK3310_STATE_STANDBY);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int stk3310_suspend(struct device *dev)
> diff --git a/drivers/iio/light/tcs3472.c
> b/drivers/iio/light/tcs3472.c
> index 823435f59bb6..db17fec634be 100644
> --- a/drivers/iio/light/tcs3472.c
> +++ b/drivers/iio/light/tcs3472.c
> @@ -559,7 +559,7 @@ static int tcs3472_powerdown(struct tcs3472_data
> *data)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tcs3472_remove(struct i2c_client *client)
> +static void tcs3472_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -568,8 +568,6 @@ static int tcs3472_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(client->irq, indio_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_triggered_buffer_clea=
nup(indio_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tcs3472_powerdown(iio_pri=
v(indio_dev));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int tcs3472_suspend(struct device *dev)
> diff --git a/drivers/iio/light/tsl2563.c
> b/drivers/iio/light/tsl2563.c
> index 0a278eea36ca..1fa189fe6eb6 100644
> --- a/drivers/iio/light/tsl2563.c
> +++ b/drivers/iio/light/tsl2563.c
> @@ -796,7 +796,7 @@ static int tsl2563_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int tsl2563_remove(struct i2c_client *client)
> +static void tsl2563_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tsl2563_chip *chip=
 =3D iio_priv(indio_dev);
> @@ -810,8 +810,6 @@ static int tsl2563_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 chip->intr);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0flush_scheduled_work();
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tsl2563_set_power(chip, 0=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int tsl2563_suspend(struct device *dev)
> diff --git a/drivers/iio/light/tsl2583.c
> b/drivers/iio/light/tsl2583.c
> index efb3c13cfc87..59e7ef624283 100644
> --- a/drivers/iio/light/tsl2583.c
> +++ b/drivers/iio/light/tsl2583.c
> @@ -873,7 +873,7 @@ static int tsl2583_probe(struct i2c_client
> *clientp,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tsl2583_remove(struct i2c_client *client)
> +static void tsl2583_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tsl2583_chip *chip=
 =3D iio_priv(indio_dev);
> @@ -884,8 +884,6 @@ static int tsl2583_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tsl2583_set_power_state(c=
hip, TSL2583_CNTL_PWR_OFF);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused tsl2583_suspend(struct device *dev)
> diff --git a/drivers/iio/light/tsl4531.c
> b/drivers/iio/light/tsl4531.c
> index 6ae1b27e50b6..090038fed889 100644
> --- a/drivers/iio/light/tsl4531.c
> +++ b/drivers/iio/light/tsl4531.c
> @@ -207,12 +207,10 @@ static int tsl4531_powerdown(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0TSL4531_MODE_POWERDOWN);
> =C2=A0}
> =C2=A0
> -static int tsl4531_remove(struct i2c_client *client)
> +static void tsl4531_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(i2c=
_get_clientdata(client));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tsl4531_powerdown(client)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int tsl4531_suspend(struct device *dev)
> diff --git a/drivers/iio/light/us5182d.c
> b/drivers/iio/light/us5182d.c
> index cbd9978540fa..ca6a03933e2e 100644
> --- a/drivers/iio/light/us5182d.c
> +++ b/drivers/iio/light/us5182d.c
> @@ -904,7 +904,7 @@ static int us5182d_probe(struct i2c_client
> *client,
> =C2=A0
> =C2=A0}
> =C2=A0
> -static int us5182d_remove(struct i2c_client *client)
> +static void us5182d_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct us5182d_data *data=
 =3D
> iio_priv(i2c_get_clientdata(client));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> @@ -918,8 +918,6 @@ static int us5182d_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to shut down (%pe)\n=
",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ER=
R_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#if defined(CONFIG_PM_SLEEP) || defined(CONFIG_PM)
> diff --git a/drivers/iio/light/vcnl4000.c
> b/drivers/iio/light/vcnl4000.c
> index 947a41b86173..9c492f9024e2 100644
> --- a/drivers/iio/light/vcnl4000.c
> +++ b/drivers/iio/light/vcnl4000.c
> @@ -1111,7 +1111,7 @@ static const struct of_device_id
> vcnl_4000_of_match[] =3D {
> =C2=A0};
> =C2=A0MODULE_DEVICE_TABLE(of, vcnl_4000_of_match);
> =C2=A0
> -static int vcnl4000_remove(struct i2c_client *client)
> +static void vcnl4000_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct vcnl4000_data *dat=
a =3D iio_priv(indio_dev);
> @@ -1126,8 +1126,6 @@ static int vcnl4000_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to power down
> (%pe)\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ER=
R_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused vcnl4000_runtime_suspend(struct device
> *dev)
> diff --git a/drivers/iio/light/vcnl4035.c
> b/drivers/iio/light/vcnl4035.c
> index 2aaec6bef64c..8282f19c9de7 100644
> --- a/drivers/iio/light/vcnl4035.c
> +++ b/drivers/iio/light/vcnl4035.c
> @@ -601,7 +601,7 @@ static int vcnl4035_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int vcnl4035_remove(struct i2c_client *client)
> +static void vcnl4035_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> @@ -616,8 +616,6 @@ static int vcnl4035_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to put device into
> standby (%pe)\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ER=
R_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused vcnl4035_runtime_suspend(struct device
> *dev)
> diff --git a/drivers/iio/light/veml6070.c
> b/drivers/iio/light/veml6070.c
> index 1e55e09a8d16..cfa4e9e7c803 100644
> --- a/drivers/iio/light/veml6070.c
> +++ b/drivers/iio/light/veml6070.c
> @@ -180,15 +180,13 @@ static int veml6070_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int veml6070_remove(struct i2c_client *client)
> +static void veml6070_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct veml6070_data *dat=
a =3D iio_priv(indio_dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(dat=
a->client2);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id veml6070_id[] =3D {
> diff --git a/drivers/iio/magnetometer/ak8974.c
> b/drivers/iio/magnetometer/ak8974.c
> index e54feacfb980..1064859fbf83 100644
> --- a/drivers/iio/magnetometer/ak8974.c
> +++ b/drivers/iio/magnetometer/ak8974.c
> @@ -969,7 +969,7 @@ static int ak8974_probe(struct i2c_client *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ak8974_remove(struct i2c_client *i2c)
> +static void ak8974_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(i2c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ak8974 *ak8974 =3D=
 iio_priv(indio_dev);
> @@ -981,8 +981,6 @@ static int ak8974_remove(struct i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&i2c->=
dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ak8974_set_power(ak8974, =
AK8974_PWR_OFF);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(ak8974->regs), ak8974-
> >regs);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused ak8974_runtime_suspend(struct device *dev=
)
> diff --git a/drivers/iio/magnetometer/ak8975.c
> b/drivers/iio/magnetometer/ak8975.c
> index 2432e697150c..caf03a2a98a5 100644
> --- a/drivers/iio/magnetometer/ak8975.c
> +++ b/drivers/iio/magnetometer/ak8975.c
> @@ -1018,7 +1018,7 @@ static int ak8975_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int ak8975_remove(struct i2c_client *client)
> +static void ak8975_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ak8975_data *data =
=3D iio_priv(indio_dev);
> @@ -1030,8 +1030,6 @@ static int ak8975_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_triggered_buffer_clea=
nup(indio_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ak8975_set_mode(data, POW=
ER_DOWN);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ak8975_power_off(data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ak8975_runtime_suspend(struct device *dev)
> diff --git a/drivers/iio/magnetometer/bmc150_magn_i2c.c
> b/drivers/iio/magnetometer/bmc150_magn_i2c.c
> index 65c004411d0f..570deaa87836 100644
> --- a/drivers/iio/magnetometer/bmc150_magn_i2c.c
> +++ b/drivers/iio/magnetometer/bmc150_magn_i2c.c
> @@ -34,11 +34,9 @@ static int bmc150_magn_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return bmc150_magn_probe(=
&client->dev, regmap, client->irq,
> name);
> =C2=A0}
> =C2=A0
> -static int bmc150_magn_i2c_remove(struct i2c_client *client)
> +static void bmc150_magn_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0bmc150_magn_remove(&clien=
t->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct acpi_device_id bmc150_magn_acpi_match[] =3D {
> diff --git a/drivers/iio/magnetometer/hmc5843_i2c.c
> b/drivers/iio/magnetometer/hmc5843_i2c.c
> index 8d2ff8fc204d..fe5e8415b2f2 100644
> --- a/drivers/iio/magnetometer/hmc5843_i2c.c
> +++ b/drivers/iio/magnetometer/hmc5843_i2c.c
> @@ -65,11 +65,9 @@ static int hmc5843_i2c_probe(struct i2c_client
> *cli,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0id-=
>driver_data, id->name);
> =C2=A0}
> =C2=A0
> -static int hmc5843_i2c_remove(struct i2c_client *client)
> +static void hmc5843_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0hmc5843_common_remove(&cl=
ient->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id hmc5843_id[] =3D {
> diff --git a/drivers/iio/magnetometer/mag3110.c
> b/drivers/iio/magnetometer/mag3110.c
> index 226439d0bfb5..b870ad803862 100644
> --- a/drivers/iio/magnetometer/mag3110.c
> +++ b/drivers/iio/magnetometer/mag3110.c
> @@ -559,7 +559,7 @@ static int mag3110_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mag3110_remove(struct i2c_client *client)
> +static void mag3110_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mag3110_data *data=
 =3D iio_priv(indio_dev);
> @@ -569,8 +569,6 @@ static int mag3110_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mag3110_standby(iio_priv(=
indio_dev));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
ddio_reg);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(data->v=
dd_reg);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int mag3110_suspend(struct device *dev)
> diff --git a/drivers/iio/magnetometer/yamaha-yas530.c
> b/drivers/iio/magnetometer/yamaha-yas530.c
> index b2bc637150bf..8c16178d4820 100644
> --- a/drivers/iio/magnetometer/yamaha-yas530.c
> +++ b/drivers/iio/magnetometer/yamaha-yas530.c
> @@ -943,7 +943,7 @@ static int yas5xx_probe(struct i2c_client *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int yas5xx_remove(struct i2c_client *i2c)
> +static void yas5xx_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(i2c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct yas5xx *yas5xx =3D=
 iio_priv(indio_dev);
> @@ -961,8 +961,6 @@ static int yas5xx_remove(struct i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(=
yas5xx->reset, 1);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(yas5xx->regs), yas5xx-
> >regs);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused yas5xx_runtime_suspend(struct device *dev=
)
> diff --git a/drivers/iio/potentiostat/lmp91000.c
> b/drivers/iio/potentiostat/lmp91000.c
> index fe514f0b5506..5ec7060d31d9 100644
> --- a/drivers/iio/potentiostat/lmp91000.c
> +++ b/drivers/iio/potentiostat/lmp91000.c
> @@ -384,7 +384,7 @@ static int lmp91000_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lmp91000_remove(struct i2c_client *client)
> +static void lmp91000_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lmp91000_data *dat=
a =3D iio_priv(indio_dev);
> @@ -396,8 +396,6 @@ static int lmp91000_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_triggered_buffer_clea=
nup(indio_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_trigger_unregister(da=
ta->trig);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id lmp91000_of_match[] =3D {
> diff --git a/drivers/iio/pressure/mpl3115.c
> b/drivers/iio/pressure/mpl3115.c
> index d4f89e4babed..2f22aba61e4d 100644
> --- a/drivers/iio/pressure/mpl3115.c
> +++ b/drivers/iio/pressure/mpl3115.c
> @@ -290,15 +290,13 @@ static int mpl3115_standby(struct mpl3115_data
> *data)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0data->ctrl_reg1 & ~MPL3115_CTRL_ACTIVE);
> =C2=A0}
> =C2=A0
> -static int mpl3115_remove(struct i2c_client *client)
> +static void mpl3115_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_device_unregister(ind=
io_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0iio_triggered_buffer_clea=
nup(indio_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mpl3115_standby(iio_priv(=
indio_dev));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int mpl3115_suspend(struct device *dev)
> diff --git a/drivers/iio/pressure/ms5611_i2c.c
> b/drivers/iio/pressure/ms5611_i2c.c
> index 3b1de71e0d15..b681a4183909 100644
> --- a/drivers/iio/pressure/ms5611_i2c.c
> +++ b/drivers/iio/pressure/ms5611_i2c.c
> @@ -105,11 +105,9 @@ static int ms5611_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ms5611_probe(indio=
_dev, &client->dev, id->name, id-
> >driver_data);
> =C2=A0}
> =C2=A0
> -static int ms5611_i2c_remove(struct i2c_client *client)
> +static void ms5611_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ms5611_remove(i2c_get_cli=
entdata(client));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id ms5611_i2c_matches[] =3D {
> diff --git a/drivers/iio/pressure/zpa2326_i2c.c
> b/drivers/iio/pressure/zpa2326_i2c.c
> index 0db0860d386b..f26dd8cbb387 100644
> --- a/drivers/iio/pressure/zpa2326_i2c.c
> +++ b/drivers/iio/pressure/zpa2326_i2c.c
> @@ -53,11 +53,9 @@ static int zpa2326_probe_i2c(struct
> i2c_client=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 zpa2326_i2c_hwid(client), regmap);
> =C2=A0}
> =C2=A0
> -static int zpa2326_remove_i2c(struct i2c_client *client)
> +static void zpa2326_remove_i2c(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0zpa2326_remove(&client->d=
ev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id zpa2326_i2c_ids[] =3D {
> diff --git a/drivers/iio/proximity/pulsedlight-lidar-lite-v2.c
> b/drivers/iio/proximity/pulsedlight-lidar-lite-v2.c
> index 648ae576d6fa..791a33d5286c 100644
> --- a/drivers/iio/proximity/pulsedlight-lidar-lite-v2.c
> +++ b/drivers/iio/proximity/pulsedlight-lidar-lite-v2.c
> @@ -311,7 +311,7 @@ static int lidar_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lidar_remove(struct i2c_client *client)
> +static void lidar_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -320,8 +320,6 @@ static int lidar_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lidar_id[] =3D {
> diff --git a/drivers/iio/proximity/sx9500.c
> b/drivers/iio/proximity/sx9500.c
> index 42589d6200ad..d4670864ddc7 100644
> --- a/drivers/iio/proximity/sx9500.c
> +++ b/drivers/iio/proximity/sx9500.c
> @@ -979,7 +979,7 @@ static int sx9500_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int sx9500_remove(struct i2c_client *client)
> +static void sx9500_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct sx9500_data *data =
=3D iio_priv(indio_dev);
> @@ -989,8 +989,6 @@ static int sx9500_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (client->irq > 0)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0iio_trigger_unregister(data->trig);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(data->buffer);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int sx9500_suspend(struct device *dev)
> diff --git a/drivers/iio/temperature/mlx90614.c
> b/drivers/iio/temperature/mlx90614.c
> index c253a5315988..0808bb865928 100644
> --- a/drivers/iio/temperature/mlx90614.c
> +++ b/drivers/iio/temperature/mlx90614.c
> @@ -571,7 +571,7 @@ static int mlx90614_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return iio_device_registe=
r(indio_dev);
> =C2=A0}
> =C2=A0
> -static int mlx90614_remove(struct i2c_client *client)
> +static void mlx90614_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mlx90614_data *dat=
a =3D iio_priv(indio_dev);
> @@ -584,8 +584,6 @@ static int mlx90614_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mlx=
90614_sleep(data);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mlx90614_id[] =3D {
> diff --git a/drivers/iio/temperature/mlx90632.c
> b/drivers/iio/temperature/mlx90632.c
> index 7ee7ff8047a4..e8ef47147e2b 100644
> --- a/drivers/iio/temperature/mlx90632.c
> +++ b/drivers/iio/temperature/mlx90632.c
> @@ -924,7 +924,7 @@ static int mlx90632_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return iio_device_registe=
r(indio_dev);
> =C2=A0}
> =C2=A0
> -static int mlx90632_remove(struct i2c_client *client)
> +static void mlx90632_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iio_dev *indio_dev=
 =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mlx90632_data *dat=
a =3D iio_priv(indio_dev);
> @@ -936,8 +936,6 @@ static int mlx90632_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_put_noidle(&cl=
ient->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mlx90632_sleep(data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mlx90632_id[] =3D {
> diff --git a/drivers/input/joystick/as5011.c
> b/drivers/input/joystick/as5011.c
> index 34bcd99a46f5..2beda29021a3 100644
> --- a/drivers/input/joystick/as5011.c
> +++ b/drivers/input/joystick/as5011.c
> @@ -327,7 +327,7 @@ static int as5011_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return error;
> =C2=A0}
> =C2=A0
> -static int as5011_remove(struct i2c_client *client)
> +static void as5011_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct as5011_device *as5=
011 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -337,8 +337,6 @@ static int as5011_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0input_unregister_device(a=
s5011->input_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(as5011);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id as5011_id[] =3D {
> diff --git a/drivers/input/keyboard/adp5588-keys.c
> b/drivers/input/keyboard/adp5588-keys.c
> index 1592da4de336..b5666d650994 100644
> --- a/drivers/input/keyboard/adp5588-keys.c
> +++ b/drivers/input/keyboard/adp5588-keys.c
> @@ -598,7 +598,7 @@ static int adp5588_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return error;
> =C2=A0}
> =C2=A0
> -static int adp5588_remove(struct i2c_client *client)
> +static void adp5588_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adp5588_kpad *kpad=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -608,8 +608,6 @@ static int adp5588_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0input_unregister_device(k=
pad->input);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adp5588_gpio_remove(kpad)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(kpad);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/input/keyboard/lm8323.c
> b/drivers/input/keyboard/lm8323.c
> index 6c38d034ec6e..407dd2ad6302 100644
> --- a/drivers/input/keyboard/lm8323.c
> +++ b/drivers/input/keyboard/lm8323.c
> @@ -752,7 +752,7 @@ static int lm8323_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int lm8323_remove(struct i2c_client *client)
> +static void lm8323_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm8323_chip *lm =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -769,8 +769,6 @@ static int lm8323_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0led=
_classdev_unregister(&lm->pwm[i].cdev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(lm);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/input/keyboard/lm8333.c
> b/drivers/input/keyboard/lm8333.c
> index 7c5f8c6bb957..9dac22c14125 100644
> --- a/drivers/input/keyboard/lm8333.c
> +++ b/drivers/input/keyboard/lm8333.c
> @@ -200,15 +200,13 @@ static int lm8333_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int lm8333_remove(struct i2c_client *client)
> +static void lm8333_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm8333 *lm8333 =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0free_irq(client->irq, lm8=
333);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0input_unregister_device(l=
m8333->input);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(lm8333);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm8333_id[] =3D {
> diff --git a/drivers/input/keyboard/mcs_touchkey.c
> b/drivers/input/keyboard/mcs_touchkey.c
> index 8cb0062b98e4..ac1637a3389e 100644
> --- a/drivers/input/keyboard/mcs_touchkey.c
> +++ b/drivers/input/keyboard/mcs_touchkey.c
> @@ -194,7 +194,7 @@ static int mcs_touchkey_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return error;
> =C2=A0}
> =C2=A0
> -static int mcs_touchkey_remove(struct i2c_client *client)
> +static void mcs_touchkey_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mcs_touchkey_data =
*data =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -203,8 +203,6 @@ static int mcs_touchkey_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0data->poweron(false);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0input_unregister_device(d=
ata->input_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void mcs_touchkey_shutdown(struct i2c_client *client)
> diff --git a/drivers/input/keyboard/qt1070.c
> b/drivers/input/keyboard/qt1070.c
> index 7174e1df1ee3..9fcce18b1d65 100644
> --- a/drivers/input/keyboard/qt1070.c
> +++ b/drivers/input/keyboard/qt1070.c
> @@ -216,7 +216,7 @@ static int qt1070_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int qt1070_remove(struct i2c_client *client)
> +static void qt1070_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct qt1070_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -225,8 +225,6 @@ static int qt1070_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0input_unregister_device(d=
ata->input);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/input/keyboard/qt2160.c
> b/drivers/input/keyboard/qt2160.c
> index 32d4a076eaa3..382b1519218c 100644
> --- a/drivers/input/keyboard/qt2160.c
> +++ b/drivers/input/keyboard/qt2160.c
> @@ -432,7 +432,7 @@ static int qt2160_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return error;
> =C2=A0}
> =C2=A0
> -static int qt2160_remove(struct i2c_client *client)
> +static void qt2160_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct qt2160_data *qt216=
0 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -446,8 +446,6 @@ static int qt2160_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0input_unregister_device(q=
t2160->input);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(qt2160);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id qt2160_idtable[] =3D {
> diff --git a/drivers/input/keyboard/tca6416-keypad.c
> b/drivers/input/keyboard/tca6416-keypad.c
> index 2a9755910065..afcdfbb002ff 100644
> --- a/drivers/input/keyboard/tca6416-keypad.c
> +++ b/drivers/input/keyboard/tca6416-keypad.c
> @@ -307,7 +307,7 @@ static int tca6416_keypad_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return error;
> =C2=A0}
> =C2=A0
> -static int tca6416_keypad_remove(struct i2c_client *client)
> +static void tca6416_keypad_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tca6416_keypad_chi=
p *chip =3D
> i2c_get_clientdata(client);
> =C2=A0
> @@ -318,8 +318,6 @@ static int tca6416_keypad_remove(struct
> i2c_client *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0input_unregister_device(c=
hip->input);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(chip);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/input/misc/adxl34x-i2c.c
> b/drivers/input/misc/adxl34x-i2c.c
> index a3b5f88d2bd1..5be636aaa94f 100644
> --- a/drivers/input/misc/adxl34x-i2c.c
> +++ b/drivers/input/misc/adxl34x-i2c.c
> @@ -99,13 +99,11 @@ static int adxl34x_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int adxl34x_i2c_remove(struct i2c_client *client)
> +static void adxl34x_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adxl34x *ac =3D i2=
c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adxl34x_remove(ac);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused adxl34x_i2c_suspend(struct device *dev)
> diff --git a/drivers/input/misc/bma150.c
> b/drivers/input/misc/bma150.c
> index a9d984da95f3..84fe394da7a6 100644
> --- a/drivers/input/misc/bma150.c
> +++ b/drivers/input/misc/bma150.c
> @@ -513,11 +513,9 @@ static int bma150_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int bma150_remove(struct i2c_client *client)
> +static void bma150_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused bma150_suspend(struct device *dev)
> diff --git a/drivers/input/misc/cma3000_d0x_i2c.c
> b/drivers/input/misc/cma3000_d0x_i2c.c
> index 03fb49127c3a..3b23210c46b7 100644
> --- a/drivers/input/misc/cma3000_d0x_i2c.c
> +++ b/drivers/input/misc/cma3000_d0x_i2c.c
> @@ -58,13 +58,11 @@ static int cma3000_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int cma3000_i2c_remove(struct i2c_client *client)
> +static void cma3000_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cma3000_accl_data =
*data =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cma3000_exit(data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/input/misc/pcf8574_keypad.c
> b/drivers/input/misc/pcf8574_keypad.c
> index abc423165522..cfd6640e4f82 100644
> --- a/drivers/input/misc/pcf8574_keypad.c
> +++ b/drivers/input/misc/pcf8574_keypad.c
> @@ -157,7 +157,7 @@ static int pcf8574_kp_probe(struct i2c_client
> *client, const struct i2c_device_i
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int pcf8574_kp_remove(struct i2c_client *client)
> +static void pcf8574_kp_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct kp_data *lp =3D i2=
c_get_clientdata(client);
> =C2=A0
> @@ -165,8 +165,6 @@ static int pcf8574_kp_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0input_unregister_device(l=
p->idev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(lp);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/input/mouse/synaptics_i2c.c
> b/drivers/input/mouse/synaptics_i2c.c
> index fa304648d611..987ee67a1045 100644
> --- a/drivers/input/mouse/synaptics_i2c.c
> +++ b/drivers/input/mouse/synaptics_i2c.c
> @@ -587,7 +587,7 @@ static int synaptics_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int synaptics_i2c_remove(struct i2c_client *client)
> +static void synaptics_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct synaptics_i2c *tou=
ch =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -596,8 +596,6 @@ static int synaptics_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0input_unregister_device(t=
ouch->input);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(touch);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused synaptics_i2c_suspend(struct device *dev)
> diff --git a/drivers/input/rmi4/rmi_smbus.c
> b/drivers/input/rmi4/rmi_smbus.c
> index 2407ea43de59..c130468541b7 100644
> --- a/drivers/input/rmi4/rmi_smbus.c
> +++ b/drivers/input/rmi4/rmi_smbus.c
> @@ -338,13 +338,11 @@ static int rmi_smb_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int rmi_smb_remove(struct i2c_client *client)
> +static void rmi_smb_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rmi_smb_xport *rmi=
_smb =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rmi_unregister_transport_=
device(&rmi_smb->xport);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused rmi_smb_suspend(struct device *dev)
> diff --git a/drivers/input/touchscreen/atmel_mxt_ts.c
> b/drivers/input/touchscreen/atmel_mxt_ts.c
> index eb66cd2689b7..4eedea08b0b5 100644
> --- a/drivers/input/touchscreen/atmel_mxt_ts.c
> +++ b/drivers/input/touchscreen/atmel_mxt_ts.c
> @@ -3284,7 +3284,7 @@ static int mxt_probe(struct i2c_client *client,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return error;
> =C2=A0}
> =C2=A0
> -static int mxt_remove(struct i2c_client *client)
> +static void mxt_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mxt_data *data =3D=
 i2c_get_clientdata(client);
> =C2=A0
> @@ -3294,8 +3294,6 @@ static int mxt_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mxt_free_object_table(dat=
a);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(data->regulators),
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 data->regulators);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused mxt_suspend(struct device *dev)
> diff --git a/drivers/input/touchscreen/bu21013_ts.c
> b/drivers/input/touchscreen/bu21013_ts.c
> index 2f1f0d7607f8..34f422e246ef 100644
> --- a/drivers/input/touchscreen/bu21013_ts.c
> +++ b/drivers/input/touchscreen/bu21013_ts.c
> @@ -552,15 +552,13 @@ static int bu21013_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int bu21013_remove(struct i2c_client *client)
> +static void bu21013_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bu21013_ts *ts =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Make sure IRQ will exi=
t quickly even if there is contact
> */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ts->touch_stopped =3D tru=
e;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* The resources will be =
freed by devm */
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused bu21013_suspend(struct device *dev)
> diff --git a/drivers/input/touchscreen/cyttsp4_i2c.c
> b/drivers/input/touchscreen/cyttsp4_i2c.c
> index c65ccb2f4716..28ae7c15397a 100644
> --- a/drivers/input/touchscreen/cyttsp4_i2c.c
> +++ b/drivers/input/touchscreen/cyttsp4_i2c.c
> @@ -43,13 +43,11 @@ static int cyttsp4_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return PTR_ERR_OR_ZERO(ts=
);
> =C2=A0}
> =C2=A0
> -static int cyttsp4_i2c_remove(struct i2c_client *client)
> +static void cyttsp4_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cyttsp4 *ts =3D i2=
c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cyttsp4_remove(ts);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cyttsp4_i2c_id[] =3D {
> diff --git a/drivers/input/touchscreen/edt-ft5x06.c
> b/drivers/input/touchscreen/edt-ft5x06.c
> index bb2e1cbffba7..0c325132a955 100644
> --- a/drivers/input/touchscreen/edt-ft5x06.c
> +++ b/drivers/input/touchscreen/edt-ft5x06.c
> @@ -1266,13 +1266,11 @@ static int edt_ft5x06_ts_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int edt_ft5x06_ts_remove(struct i2c_client *client)
> +static void edt_ft5x06_ts_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct edt_ft5x06_ts_data=
 *tsdata =3D
> i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0edt_ft5x06_ts_teardown_de=
bugfs(tsdata);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused edt_ft5x06_ts_suspend(struct device *dev)
> diff --git a/drivers/input/touchscreen/goodix.c
> b/drivers/input/touchscreen/goodix.c
> index 3ad9870db108..1617dd931876 100644
> --- a/drivers/input/touchscreen/goodix.c
> +++ b/drivers/input/touchscreen/goodix.c
> @@ -1383,14 +1383,12 @@ static int goodix_ts_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int goodix_ts_remove(struct i2c_client *client)
> +static void goodix_ts_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct goodix_ts_data *ts=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ts->load_cfg_from_dis=
k)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0wait_for_completion(&ts->firmware_loading_complete)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused goodix_suspend(struct device *dev)
> diff --git a/drivers/input/touchscreen/migor_ts.c
> b/drivers/input/touchscreen/migor_ts.c
> index 42d3fd7e04d7..79cd660d879e 100644
> --- a/drivers/input/touchscreen/migor_ts.c
> +++ b/drivers/input/touchscreen/migor_ts.c
> @@ -176,7 +176,7 @@ static int migor_ts_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return error;
> =C2=A0}
> =C2=A0
> -static int migor_ts_remove(struct i2c_client *client)
> +static void migor_ts_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct migor_ts_priv *pri=
v =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -185,8 +185,6 @@ static int migor_ts_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(priv);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_set_drvdata(&client->=
dev, NULL);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused migor_ts_suspend(struct device *dev)
> diff --git a/drivers/input/touchscreen/s6sy761.c
> b/drivers/input/touchscreen/s6sy761.c
> index 85a1f465c097..1a7d00289b4c 100644
> --- a/drivers/input/touchscreen/s6sy761.c
> +++ b/drivers/input/touchscreen/s6sy761.c
> @@ -475,11 +475,9 @@ static int s6sy761_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int s6sy761_remove(struct i2c_client *client)
> +static void s6sy761_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused s6sy761_runtime_suspend(struct device
> *dev)
> diff --git a/drivers/input/touchscreen/stmfts.c
> b/drivers/input/touchscreen/stmfts.c
> index c175d44c52f3..d5bd170808fb 100644
> --- a/drivers/input/touchscreen/stmfts.c
> +++ b/drivers/input/touchscreen/stmfts.c
> @@ -738,11 +738,9 @@ static int stmfts_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int stmfts_remove(struct i2c_client *client)
> +static void stmfts_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused stmfts_runtime_suspend(struct device *dev=
)
> diff --git a/drivers/input/touchscreen/tsc2004.c
> b/drivers/input/touchscreen/tsc2004.c
> index 9fdd870c4c0b..a9565353ee98 100644
> --- a/drivers/input/touchscreen/tsc2004.c
> +++ b/drivers/input/touchscreen/tsc2004.c
> @@ -43,11 +43,9 @@ static int tsc2004_probe(struct i2c_client *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 tsc2004_cmd);
> =C2=A0}
> =C2=A0
> -static int tsc2004_remove(struct i2c_client *i2c)
> +static void tsc2004_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tsc200x_remove(&i2c->dev)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tsc2004_idtable[] =3D {
> diff --git a/drivers/leds/flash/leds-as3645a.c
> b/drivers/leds/flash/leds-as3645a.c
> index aa3f82be0a9c..bb2249771acb 100644
> --- a/drivers/leds/flash/leds-as3645a.c
> +++ b/drivers/leds/flash/leds-as3645a.c
> @@ -724,7 +724,7 @@ static int as3645a_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rval;
> =C2=A0}
> =C2=A0
> -static int as3645a_remove(struct i2c_client *client)
> +static void as3645a_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct as3645a *flash =3D=
 i2c_get_clientdata(client);
> =C2=A0
> @@ -740,8 +740,6 @@ static int as3645a_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fwnode_handle_put(flash->=
flash_node);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fwnode_handle_put(flash->=
indicator_node);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id as3645a_id_table[] =3D {
> diff --git a/drivers/leds/flash/leds-lm3601x.c
> b/drivers/leds/flash/leds-lm3601x.c
> index 37e1d6e68687..78730e066a73 100644
> --- a/drivers/leds/flash/leds-lm3601x.c
> +++ b/drivers/leds/flash/leds-lm3601x.c
> @@ -440,7 +440,7 @@ static int lm3601x_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return lm3601x_register_l=
eds(led, fwnode);
> =C2=A0}
> =C2=A0
> -static int lm3601x_remove(struct i2c_client *client)
> +static void lm3601x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3601x_led *led =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> @@ -450,8 +450,6 @@ static int lm3601x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 "F=
ailed to put into standby (%pe)\n",
> ERR_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3601x_id[] =3D {
> diff --git a/drivers/leds/flash/leds-rt4505.c
> b/drivers/leds/flash/leds-rt4505.c
> index ee129ab7255d..e404fe8b0314 100644
> --- a/drivers/leds/flash/leds-rt4505.c
> +++ b/drivers/leds/flash/leds-rt4505.c
> @@ -393,12 +393,11 @@ static int rt4505_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int rt4505_remove(struct i2c_client *client)
> +static void rt4505_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt4505_priv *priv =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_flash_release(priv->=
v4l2_flash);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void rt4505_shutdown(struct i2c_client *client)
> diff --git a/drivers/leds/leds-an30259a.c b/drivers/leds/leds-
> an30259a.c
> index a0df1fb28774..e072ee5409f7 100644
> --- a/drivers/leds/leds-an30259a.c
> +++ b/drivers/leds/leds-an30259a.c
> @@ -334,13 +334,11 @@ static int an30259a_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int an30259a_remove(struct i2c_client *client)
> +static void an30259a_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct an30259a *chip =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&chip->mute=
x);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id an30259a_match_table[] =3D {
> diff --git a/drivers/leds/leds-aw2013.c b/drivers/leds/leds-aw2013.c
> index 80d937454aee..0b52fc9097c6 100644
> --- a/drivers/leds/leds-aw2013.c
> +++ b/drivers/leds/leds-aw2013.c
> @@ -401,15 +401,13 @@ static int aw2013_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int aw2013_remove(struct i2c_client *client)
> +static void aw2013_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct aw2013 *chip =3D i=
2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0aw2013_chip_disable(chip)=
;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&chip->mute=
x);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id aw2013_match_table[] =3D {
> diff --git a/drivers/leds/leds-bd2802.c b/drivers/leds/leds-bd2802.c
> index 8bbaef5a2986..2b6678f6bd56 100644
> --- a/drivers/leds/leds-bd2802.c
> +++ b/drivers/leds/leds-bd2802.c
> @@ -722,7 +722,7 @@ static int bd2802_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int bd2802_remove(struct i2c_client *client)
> +static void bd2802_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bd2802_led *led =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -733,8 +733,6 @@ static int bd2802_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0bd2802_disable_adv_conf(led);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0for (i =3D 0; i < ARRAY_S=
IZE(bd2802_attributes); i++)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0device_remove_file(&led->client->dev,
> bd2802_attributes[i]);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/leds/leds-blinkm.c b/drivers/leds/leds-blinkm.c
> index bd7d0d5cf3b6..3fb6a2fdaefa 100644
> --- a/drivers/leds/leds-blinkm.c
> +++ b/drivers/leds/leds-blinkm.c
> @@ -677,7 +677,7 @@ static int blinkm_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int blinkm_remove(struct i2c_client *client)
> +static void blinkm_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct blinkm_data *data =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret =3D 0;
> @@ -716,7 +716,6 @@ static int blinkm_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_err(&client->dev, "Failure in blinkm_remove
> ignored. Continuing.\n");
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &blinkm_group);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id blinkm_id[] =3D {
> diff --git a/drivers/leds/leds-is31fl319x.c b/drivers/leds/leds-
> is31fl319x.c
> index 4161b9dd7e48..7aee62211750 100644
> --- a/drivers/leds/leds-is31fl319x.c
> +++ b/drivers/leds/leds-is31fl319x.c
> @@ -414,12 +414,11 @@ static int is31fl319x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int is31fl319x_remove(struct i2c_client *client)
> +static void is31fl319x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct is31fl319x_chip *i=
s31 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&is31->lock=
);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/leds/leds-is31fl32xx.c b/drivers/leds/leds-
> is31fl32xx.c
> index fc63fce38c19..0d219c1ac3b5 100644
> --- a/drivers/leds/leds-is31fl32xx.c
> +++ b/drivers/leds/leds-is31fl32xx.c
> @@ -457,7 +457,7 @@ static int is31fl32xx_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int is31fl32xx_remove(struct i2c_client *client)
> +static void is31fl32xx_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct is31fl32xx_priv *p=
riv =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> @@ -466,8 +466,6 @@ static int is31fl32xx_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_err(&client->dev, "Failed to reset registers on
> removal (%pe)\n",
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ERR=
_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/leds/leds-lm3530.c b/drivers/leds/leds-lm3530.c
> index e72393534b72..ba906c253c7f 100644
> --- a/drivers/leds/leds-lm3530.c
> +++ b/drivers/leds/leds-lm3530.c
> @@ -470,13 +470,12 @@ static int lm3530_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lm3530_remove(struct i2c_client *client)
> +static void lm3530_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3530_data *drvda=
ta =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lm3530_led_disable(drvdat=
a);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0led_classdev_unregister(&=
drvdata->led_dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3530_id[] =3D {
> diff --git a/drivers/leds/leds-lm3532.c b/drivers/leds/leds-lm3532.c
> index beb53040e09e..db64d44bcbbf 100644
> --- a/drivers/leds/leds-lm3532.c
> +++ b/drivers/leds/leds-lm3532.c
> @@ -704,7 +704,7 @@ static int lm3532_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lm3532_remove(struct i2c_client *client)
> +static void lm3532_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3532_data *drvda=
ta =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -712,8 +712,6 @@ static int lm3532_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (drvdata->enable_gpio)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpiod_direction_output(drvdata->enable_gpio, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id of_lm3532_leds_match[] =3D {
> diff --git a/drivers/leds/leds-lm355x.c b/drivers/leds/leds-lm355x.c
> index 2d3e11845ba5..daa35927b301 100644
> --- a/drivers/leds/leds-lm355x.c
> +++ b/drivers/leds/leds-lm355x.c
> @@ -491,7 +491,7 @@ static int lm355x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int lm355x_remove(struct i2c_client *client)
> +static void lm355x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm355x_chip_data *=
chip =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm355x_reg_data *p=
reg =3D chip->regs;
> @@ -501,8 +501,6 @@ static int lm355x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0led_classdev_unregister(&=
chip->cdev_torch);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0led_classdev_unregister(&=
chip->cdev_flash);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_info(&client->dev, "%=
s is removed\n", lm355x_name[chip-
> >type]);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm355x_id[] =3D {
> diff --git a/drivers/leds/leds-lm3642.c b/drivers/leds/leds-lm3642.c
> index 435309154e6b..428a5d928150 100644
> --- a/drivers/leds/leds-lm3642.c
> +++ b/drivers/leds/leds-lm3642.c
> @@ -380,7 +380,7 @@ static int lm3642_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int lm3642_remove(struct i2c_client *client)
> +static void lm3642_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3642_chip_data *=
chip =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -388,7 +388,6 @@ static int lm3642_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0led_classdev_unregister(&=
chip->cdev_torch);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0led_classdev_unregister(&=
chip->cdev_flash);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_write(chip->regmap=
, REG_ENABLE, 0);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3642_id[] =3D {
> diff --git a/drivers/leds/leds-lm3692x.c b/drivers/leds/leds-
> lm3692x.c
> index 87cd24ce3f95..54b4662bff41 100644
> --- a/drivers/leds/leds-lm3692x.c
> +++ b/drivers/leds/leds-lm3692x.c
> @@ -491,14 +491,12 @@ static int lm3692x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lm3692x_remove(struct i2c_client *client)
> +static void lm3692x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3692x_led *led =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lm3692x_leds_disable(led)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&led->lock)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3692x_id[] =3D {
> diff --git a/drivers/leds/leds-lm3697.c b/drivers/leds/leds-lm3697.c
> index 3ecf90fbc06c..71231a60eebc 100644
> --- a/drivers/leds/leds-lm3697.c
> +++ b/drivers/leds/leds-lm3697.c
> @@ -337,7 +337,7 @@ static int lm3697_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return lm3697_init(led);
> =C2=A0}
> =C2=A0
> -static int lm3697_remove(struct i2c_client *client)
> +static void lm3697_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3697 *led =3D i2=
c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &l=
ed->client->dev;
> @@ -358,8 +358,6 @@ static int lm3697_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&led->lock)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3697_id[] =3D {
> diff --git a/drivers/leds/leds-lp3944.c b/drivers/leds/leds-lp3944.c
> index 437c711b2a27..673ad8c04f41 100644
> --- a/drivers/leds/leds-lp3944.c
> +++ b/drivers/leds/leds-lp3944.c
> @@ -397,7 +397,7 @@ static int lp3944_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lp3944_remove(struct i2c_client *client)
> +static void lp3944_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp3944_platform_da=
ta *pdata =3D
> dev_get_platdata(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp3944_data *data =
=3D i2c_get_clientdata(client);
> @@ -414,8 +414,6 @@ static int lp3944_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0default:
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0bre=
ak;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* lp3944 i2c driver struct */
> diff --git a/drivers/leds/leds-lp3952.c b/drivers/leds/leds-lp3952.c
> index 6ee9131fbf25..bf0ad1b5ce24 100644
> --- a/drivers/leds/leds-lp3952.c
> +++ b/drivers/leds/leds-lp3952.c
> @@ -255,15 +255,13 @@ static int lp3952_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lp3952_remove(struct i2c_client *client)
> +static void lp3952_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp3952_led_array *=
priv;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0priv =3D i2c_get_clientda=
ta(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp3952_on_off(priv, LP395=
2_LED_ALL, false);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value(priv->ena=
ble_gpio, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lp3952_id[] =3D {
> diff --git a/drivers/leds/leds-lp50xx.c b/drivers/leds/leds-lp50xx.c
> index e129dcc656b8..28d6b39fa72d 100644
> --- a/drivers/leds/leds-lp50xx.c
> +++ b/drivers/leds/leds-lp50xx.c
> @@ -563,7 +563,7 @@ static int lp50xx_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return lp50xx_probe_dt(le=
d);
> =C2=A0}
> =C2=A0
> -static int lp50xx_remove(struct i2c_client *client)
> +static void lp50xx_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp50xx *led =3D i2=
c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> @@ -579,8 +579,6 @@ static int lp50xx_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&led->lock)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lp50xx_id[] =3D {
> diff --git a/drivers/leds/leds-lp5521.c b/drivers/leds/leds-lp5521.c
> index a9e7507c998c..7ff20c260504 100644
> --- a/drivers/leds/leds-lp5521.c
> +++ b/drivers/leds/leds-lp5521.c
> @@ -579,7 +579,7 @@ static int lp5521_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lp5521_remove(struct i2c_client *client)
> +static void lp5521_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp55xx_led *led =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp55xx_chip *chip =
=3D led->chip;
> @@ -587,8 +587,6 @@ static int lp5521_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp5521_stop_all_engines(c=
hip);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp55xx_unregister_sysfs(c=
hip);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp55xx_deinit_device(chip=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lp5521_id[] =3D {
> diff --git a/drivers/leds/leds-lp5523.c b/drivers/leds/leds-lp5523.c
> index b1590cb4a188..369d40b0b65b 100644
> --- a/drivers/leds/leds-lp5523.c
> +++ b/drivers/leds/leds-lp5523.c
> @@ -947,7 +947,7 @@ static int lp5523_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lp5523_remove(struct i2c_client *client)
> +static void lp5523_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp55xx_led *led =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp55xx_chip *chip =
=3D led->chip;
> @@ -955,8 +955,6 @@ static int lp5523_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp5523_stop_all_engines(c=
hip);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp55xx_unregister_sysfs(c=
hip);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp55xx_deinit_device(chip=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lp5523_id[] =3D {
> diff --git a/drivers/leds/leds-lp5562.c b/drivers/leds/leds-lp5562.c
> index 31c14016d289..0e490085ff35 100644
> --- a/drivers/leds/leds-lp5562.c
> +++ b/drivers/leds/leds-lp5562.c
> @@ -573,7 +573,7 @@ static int lp5562_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lp5562_remove(struct i2c_client *client)
> +static void lp5562_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp55xx_led *led =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp55xx_chip *chip =
=3D led->chip;
> @@ -582,8 +582,6 @@ static int lp5562_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp55xx_unregister_sysfs(c=
hip);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp55xx_deinit_device(chip=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lp5562_id[] =3D {
> diff --git a/drivers/leds/leds-lp8501.c b/drivers/leds/leds-lp8501.c
> index 2d2fda2ab104..ae11a02c0ab2 100644
> --- a/drivers/leds/leds-lp8501.c
> +++ b/drivers/leds/leds-lp8501.c
> @@ -362,7 +362,7 @@ static int lp8501_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lp8501_remove(struct i2c_client *client)
> +static void lp8501_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp55xx_led *led =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp55xx_chip *chip =
=3D led->chip;
> @@ -370,8 +370,6 @@ static int lp8501_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp8501_stop_engine(chip);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp55xx_unregister_sysfs(c=
hip);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp55xx_deinit_device(chip=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lp8501_id[] =3D {
> diff --git a/drivers/leds/leds-lp8860.c b/drivers/leds/leds-lp8860.c
> index 3c693d5e3b44..e2b36d3187eb 100644
> --- a/drivers/leds/leds-lp8860.c
> +++ b/drivers/leds/leds-lp8860.c
> @@ -445,7 +445,7 @@ static int lp8860_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lp8860_remove(struct i2c_client *client)
> +static void lp8860_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp8860_led *led =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> @@ -461,8 +461,6 @@ static int lp8860_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&led->lock)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lp8860_id[] =3D {
> diff --git a/drivers/leds/leds-pca9532.c b/drivers/leds/leds-
> pca9532.c
> index f72b5d1be3a6..df83d97cb479 100644
> --- a/drivers/leds/leds-pca9532.c
> +++ b/drivers/leds/leds-pca9532.c
> @@ -52,7 +52,7 @@ struct pca9532_data {
> =C2=A0
> =C2=A0static int pca9532_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0const struct i2c_device_i=
d *id);
> -static int pca9532_remove(struct i2c_client *client);
> +static void pca9532_remove(struct i2c_client *client);
> =C2=A0
> =C2=A0enum {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pca9530,
> @@ -546,13 +546,11 @@ static int pca9532_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return pca9532_configure(=
client, data, pca9532_pdata);
> =C2=A0}
> =C2=A0
> -static int pca9532_remove(struct i2c_client *client)
> +static void pca9532_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pca9532_data *data=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pca9532_destroy_devices(d=
ata, data->chip_info->num_leds);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0module_i2c_driver(pca9532_driver);
> diff --git a/drivers/leds/leds-tca6507.c b/drivers/leds/leds-
> tca6507.c
> index 1473ced8664c..161bef65c6b7 100644
> --- a/drivers/leds/leds-tca6507.c
> +++ b/drivers/leds/leds-tca6507.c
> @@ -790,7 +790,7 @@ static int tca6507_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int tca6507_remove(struct i2c_client *client)
> +static void tca6507_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tca6507_chip *tca =
=3D i2c_get_clientdata(client);
> @@ -802,8 +802,6 @@ static int tca6507_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tca6507_remove_gpio(tca);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_work_sync(&tca->wo=
rk);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver tca6507_driver =3D {
> diff --git a/drivers/leds/leds-turris-omnia.c b/drivers/leds/leds-
> turris-omnia.c
> index 1adfed1c0619..66040e8621af 100644
> --- a/drivers/leds/leds-turris-omnia.c
> +++ b/drivers/leds/leds-turris-omnia.c
> @@ -245,7 +245,7 @@ static int omnia_leds_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int omnia_leds_remove(struct i2c_client *client)
> +static void omnia_leds_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0u8 buf[5];
> =C2=A0
> @@ -261,8 +261,6 @@ static int omnia_leds_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0buf[4] =3D 255;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_master_send(client, b=
uf, 5);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id of_omnia_leds_match[] =3D {
> diff --git a/drivers/macintosh/ams/ams-i2c.c
> b/drivers/macintosh/ams/ams-i2c.c
> index d2f0cde6f9c7..362fc56b69dc 100644
> --- a/drivers/macintosh/ams/ams-i2c.c
> +++ b/drivers/macintosh/ams/ams-i2c.c
> @@ -230,7 +230,7 @@ static int ams_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ams_i2c_remove(struct i2c_client *client)
> +static void ams_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ams_info.has_device) =
{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0ams_sensor_detach();
> @@ -245,8 +245,6 @@ static int ams_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0ams_info.has_device =3D 0;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void ams_i2c_exit(void)
> diff --git a/drivers/macintosh/therm_adt746x.c
> b/drivers/macintosh/therm_adt746x.c
> index e604cbc91763..b004ea2a1102 100644
> --- a/drivers/macintosh/therm_adt746x.c
> +++ b/drivers/macintosh/therm_adt746x.c
> @@ -563,7 +563,7 @@ static int probe_thermostat(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int remove_thermostat(struct i2c_client *client)
> +static void remove_thermostat(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct thermostat *th =3D=
 i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -585,8 +585,6 @@ static int remove_thermostat(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0write_both_fan_speed(th, =
-1);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(th);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id therm_adt746x_id[] =3D {
> diff --git a/drivers/macintosh/therm_windtunnel.c
> b/drivers/macintosh/therm_windtunnel.c
> index 9226b74fa08f..61fe2ab910b8 100644
> --- a/drivers/macintosh/therm_windtunnel.c
> +++ b/drivers/macintosh/therm_windtunnel.c
> @@ -334,7 +334,7 @@ static void do_attach(struct i2c_adapter
> *adapter)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0}
> =C2=A0
> -static int
> +static void
> =C2=A0do_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (x.running) {
> @@ -348,8 +348,6 @@ do_remove(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0x.fan =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0else
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0printk(KERN_ERR "g4fan: bad client\n");
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int
> diff --git a/drivers/macintosh/windfarm_ad7417_sensor.c
> b/drivers/macintosh/windfarm_ad7417_sensor.c
> index 6ad6441abcbc..c5c54a4ce91f 100644
> --- a/drivers/macintosh/windfarm_ad7417_sensor.c
> +++ b/drivers/macintosh/windfarm_ad7417_sensor.c
> @@ -289,7 +289,7 @@ static int wf_ad7417_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int wf_ad7417_remove(struct i2c_client *client)
> +static void wf_ad7417_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wf_ad7417_priv *pv=
 =3D dev_get_drvdata(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -302,8 +302,6 @@ static int wf_ad7417_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0wf_unregister_sensor(&pv->sensors[i]);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kref_put(&pv->ref, wf_ad7=
417_release);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wf_ad7417_id[] =3D {
> diff --git a/drivers/macintosh/windfarm_fcu_controls.c
> b/drivers/macintosh/windfarm_fcu_controls.c
> index 82e7b2005ae7..c5b1ca5bcd73 100644
> --- a/drivers/macintosh/windfarm_fcu_controls.c
> +++ b/drivers/macintosh/windfarm_fcu_controls.c
> @@ -560,7 +560,7 @@ static int wf_fcu_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int wf_fcu_remove(struct i2c_client *client)
> +static void wf_fcu_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wf_fcu_priv *pv =
=3D dev_get_drvdata(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wf_fcu_fan *fan;
> @@ -571,7 +571,6 @@ static int wf_fcu_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0wf_unregister_control(&fan->ctrl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kref_put(&pv->ref, wf_fcu=
_release);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wf_fcu_id[] =3D {
> diff --git a/drivers/macintosh/windfarm_lm75_sensor.c
> b/drivers/macintosh/windfarm_lm75_sensor.c
> index eb7e7f0bd219..204661c8e918 100644
> --- a/drivers/macintosh/windfarm_lm75_sensor.c
> +++ b/drivers/macintosh/windfarm_lm75_sensor.c
> @@ -147,7 +147,7 @@ static int wf_lm75_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rc;
> =C2=A0}
> =C2=A0
> -static int wf_lm75_remove(struct i2c_client *client)
> +static void wf_lm75_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wf_lm75_sensor *lm=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -156,8 +156,6 @@ static int wf_lm75_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* release sensor */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0wf_unregister_sensor(&lm-=
>sens);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wf_lm75_id[] =3D {
> diff --git a/drivers/macintosh/windfarm_lm87_sensor.c
> b/drivers/macintosh/windfarm_lm87_sensor.c
> index 807efdde86bc..40d25463346e 100644
> --- a/drivers/macintosh/windfarm_lm87_sensor.c
> +++ b/drivers/macintosh/windfarm_lm87_sensor.c
> @@ -145,7 +145,7 @@ static int wf_lm87_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rc;
> =C2=A0}
> =C2=A0
> -static int wf_lm87_remove(struct i2c_client *client)
> +static void wf_lm87_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wf_lm87_sensor *lm=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -154,8 +154,6 @@ static int wf_lm87_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* release sensor */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0wf_unregister_sensor(&lm-=
>sens);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wf_lm87_id[] =3D {
> diff --git a/drivers/macintosh/windfarm_max6690_sensor.c
> b/drivers/macintosh/windfarm_max6690_sensor.c
> index 55ee417fb878..c0d404ebc792 100644
> --- a/drivers/macintosh/windfarm_max6690_sensor.c
> +++ b/drivers/macintosh/windfarm_max6690_sensor.c
> @@ -104,14 +104,12 @@ static int wf_max6690_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rc;
> =C2=A0}
> =C2=A0
> -static int wf_max6690_remove(struct i2c_client *client)
> +static void wf_max6690_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wf_6690_sensor *ma=
x =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0max->i2c =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0wf_unregister_sensor(&max=
->sens);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wf_max6690_id[] =3D {
> diff --git a/drivers/macintosh/windfarm_smu_sat.c
> b/drivers/macintosh/windfarm_smu_sat.c
> index 5ade627eaa78..be5d4593db93 100644
> --- a/drivers/macintosh/windfarm_smu_sat.c
> +++ b/drivers/macintosh/windfarm_smu_sat.c
> @@ -316,7 +316,7 @@ static int wf_sat_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int wf_sat_remove(struct i2c_client *client)
> +static void wf_sat_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wf_sat *sat =3D i2=
c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wf_sat_sensor *sen=
s;
> @@ -330,8 +330,6 @@ static int wf_sat_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sat->i2c =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kref_put(&sat->ref, wf_sa=
t_release);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wf_sat_id[] =3D {
> diff --git a/drivers/media/cec/i2c/ch7322.c
> b/drivers/media/cec/i2c/ch7322.c
> index 0814338c43e4..34fad7123704 100644
> --- a/drivers/media/cec/i2c/ch7322.c
> +++ b/drivers/media/cec/i2c/ch7322.c
> @@ -565,7 +565,7 @@ static int ch7322_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ch7322_remove(struct i2c_client *client)
> +static void ch7322_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ch7322 *ch7322 =3D=
 i2c_get_clientdata(client);
> =C2=A0
> @@ -578,8 +578,6 @@ static int ch7322_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ch7322->mu=
tex);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_info(&client->dev, "d=
evice unregistered\n");
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id ch7322_of_match[] =3D {
> diff --git a/drivers/media/dvb-frontends/a8293.c b/drivers/media/dvb-
> frontends/a8293.c
> index 57f52c004a23..ba38783b2b4f 100644
> --- a/drivers/media/dvb-frontends/a8293.c
> +++ b/drivers/media/dvb-frontends/a8293.c
> @@ -98,14 +98,13 @@ static int a8293_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int a8293_remove(struct i2c_client *client)
> +static void a8293_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct a8293_dev *dev =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(&client->dev, "\n=
");
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id a8293_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/af9013.c
> b/drivers/media/dvb-frontends/af9013.c
> index 7d7c341b2bd8..d85929582c3f 100644
> --- a/drivers/media/dvb-frontends/af9013.c
> +++ b/drivers/media/dvb-frontends/af9013.c
> @@ -1540,7 +1540,7 @@ static int af9013_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int af9013_remove(struct i2c_client *client)
> +static void af9013_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct af9013_state *stat=
e =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1551,8 +1551,6 @@ static int af9013_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(state->regmap=
);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id af9013_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/af9033.c
> b/drivers/media/dvb-frontends/af9033.c
> index 785c49b3d307..808da7a9ffe7 100644
> --- a/drivers/media/dvb-frontends/af9033.c
> +++ b/drivers/media/dvb-frontends/af9033.c
> @@ -1163,7 +1163,7 @@ static int af9033_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int af9033_remove(struct i2c_client *client)
> +static void af9033_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct af9033_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1171,8 +1171,6 @@ static int af9033_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(dev->regmap);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id af9033_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/au8522_decoder.c
> b/drivers/media/dvb-frontends/au8522_decoder.c
> index 8cdca051e51b..e4f99bd468cb 100644
> --- a/drivers/media/dvb-frontends/au8522_decoder.c
> +++ b/drivers/media/dvb-frontends/au8522_decoder.c
> @@ -758,13 +758,12 @@ static int au8522_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int au8522_remove(struct i2c_client *client)
> +static void au8522_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0au8522_release_state(to_s=
tate(sd));
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id au8522_id[] =3D {
> diff --git a/drivers/media/dvb-frontends/cxd2099.c
> b/drivers/media/dvb-frontends/cxd2099.c
> index 1c8207ab8988..fbc666fa04ec 100644
> --- a/drivers/media/dvb-frontends/cxd2099.c
> +++ b/drivers/media/dvb-frontends/cxd2099.c
> @@ -664,14 +664,12 @@ static int cxd2099_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cxd2099_remove(struct i2c_client *client)
> +static void cxd2099_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cxd *ci =3D i2c_ge=
t_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(ci->regmap);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(ci);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cxd2099_id[] =3D {
> diff --git a/drivers/media/dvb-frontends/cxd2820r_core.c
> b/drivers/media/dvb-frontends/cxd2820r_core.c
> index b1618339eec0..5d98222f9df0 100644
> --- a/drivers/media/dvb-frontends/cxd2820r_core.c
> +++ b/drivers/media/dvb-frontends/cxd2820r_core.c
> @@ -705,7 +705,7 @@ static int cxd2820r_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cxd2820r_remove(struct i2c_client *client)
> +static void cxd2820r_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cxd2820r_priv *pri=
v =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -721,8 +721,6 @@ static int cxd2820r_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(priv->regmap[=
0]);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(priv);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cxd2820r_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/dvb-pll.c
> b/drivers/media/dvb-frontends/dvb-pll.c
> index d45b4ddc8f91..baf2a378e565 100644
> --- a/drivers/media/dvb-frontends/dvb-pll.c
> +++ b/drivers/media/dvb-frontends/dvb-pll.c
> @@ -899,14 +899,13 @@ dvb_pll_probe(struct i2c_client *client, const
> struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int dvb_pll_remove(struct i2c_client *client)
> +static void dvb_pll_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dvb_frontend *fe =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dvb_pll_priv *priv=
 =3D fe->tuner_priv;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ida_simple_remove(&pll_id=
a, priv->nr);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dvb_pll_release(fe);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/media/dvb-frontends/lgdt3306a.c
> b/drivers/media/dvb-frontends/lgdt3306a.c
> index 136b76cb4807..424311afb2bf 100644
> --- a/drivers/media/dvb-frontends/lgdt3306a.c
> +++ b/drivers/media/dvb-frontends/lgdt3306a.c
> @@ -2226,7 +2226,7 @@ static int lgdt3306a_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lgdt3306a_remove(struct i2c_client *client)
> +static void lgdt3306a_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lgdt3306a_state *s=
tate =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -2237,8 +2237,6 @@ static int lgdt3306a_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state->cfg);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lgdt3306a_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/lgdt330x.c
> b/drivers/media/dvb-frontends/lgdt330x.c
> index da3a8c5e18d8..ea9ae22fd201 100644
> --- a/drivers/media/dvb-frontends/lgdt330x.c
> +++ b/drivers/media/dvb-frontends/lgdt330x.c
> @@ -974,15 +974,13 @@ static const struct dvb_frontend_ops
> lgdt3303_ops =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0.release=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 =3D lgdt330=
x_release,
> =C2=A0};
> =C2=A0
> -static int lgdt330x_remove(struct i2c_client *client)
> +static void lgdt330x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lgdt330x_state *st=
ate =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(&client->dev, "\n=
");
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lgdt330x_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/m88ds3103.c
> b/drivers/media/dvb-frontends/m88ds3103.c
> index bce0f42f3d19..4e844b2ef597 100644
> --- a/drivers/media/dvb-frontends/m88ds3103.c
> +++ b/drivers/media/dvb-frontends/m88ds3103.c
> @@ -1914,7 +1914,7 @@ static int m88ds3103_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int m88ds3103_remove(struct i2c_client *client)
> +static void m88ds3103_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct m88ds3103_dev *dev=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1926,7 +1926,6 @@ static int m88ds3103_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_mux_del_adapters(dev-=
>muxc);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id m88ds3103_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/mn88443x.c
> b/drivers/media/dvb-frontends/mn88443x.c
> index fff212c0bf3b..452571b380b7 100644
> --- a/drivers/media/dvb-frontends/mn88443x.c
> +++ b/drivers/media/dvb-frontends/mn88443x.c
> @@ -762,15 +762,13 @@ static int mn88443x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mn88443x_remove(struct i2c_client *client)
> +static void mn88443x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mn88443x_priv *chi=
p =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mn88443x_cmn_power_off(ch=
ip);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(chi=
p->client_t);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct mn88443x_spec mn88443x_spec_pri =3D {
> diff --git a/drivers/media/dvb-frontends/mn88472.c
> b/drivers/media/dvb-frontends/mn88472.c
> index 73922fc8f39c..2b01cc678f7e 100644
> --- a/drivers/media/dvb-frontends/mn88472.c
> +++ b/drivers/media/dvb-frontends/mn88472.c
> @@ -691,7 +691,7 @@ static int mn88472_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mn88472_remove(struct i2c_client *client)
> +static void mn88472_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mn88472_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -706,8 +706,6 @@ static int mn88472_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(dev->regmap[0=
]);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mn88472_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/mn88473.c
> b/drivers/media/dvb-frontends/mn88473.c
> index 4838969ef735..f0ecf5910c02 100644
> --- a/drivers/media/dvb-frontends/mn88473.c
> +++ b/drivers/media/dvb-frontends/mn88473.c
> @@ -726,7 +726,7 @@ static int mn88473_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mn88473_remove(struct i2c_client *client)
> +static void mn88473_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mn88473_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -741,8 +741,6 @@ static int mn88473_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(dev->regmap[0=
]);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mn88473_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/mxl692.c
> b/drivers/media/dvb-frontends/mxl692.c
> index dd7954e8f553..129630cbffff 100644
> --- a/drivers/media/dvb-frontends/mxl692.c
> +++ b/drivers/media/dvb-frontends/mxl692.c
> @@ -1337,15 +1337,13 @@ static int mxl692_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return -ENODEV;
> =C2=A0}
> =C2=A0
> -static int mxl692_remove(struct i2c_client *client)
> +static void mxl692_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mxl692_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev->fe.demodulator_priv =
=3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_set_clientdata(client=
, NULL);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mxl692_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/rtl2830.c
> b/drivers/media/dvb-frontends/rtl2830.c
> index e6b8367c8cce..e0fbf41316ae 100644
> --- a/drivers/media/dvb-frontends/rtl2830.c
> +++ b/drivers/media/dvb-frontends/rtl2830.c
> @@ -865,7 +865,7 @@ static int rtl2830_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rtl2830_remove(struct i2c_client *client)
> +static void rtl2830_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rtl2830_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -874,8 +874,6 @@ static int rtl2830_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_mux_del_adapters(dev-=
>muxc);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(dev->regmap);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id rtl2830_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/rtl2832.c
> b/drivers/media/dvb-frontends/rtl2832.c
> index dcbeb9f5e12a..4fa884eda5d5 100644
> --- a/drivers/media/dvb-frontends/rtl2832.c
> +++ b/drivers/media/dvb-frontends/rtl2832.c
> @@ -1110,7 +1110,7 @@ static int rtl2832_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rtl2832_remove(struct i2c_client *client)
> +static void rtl2832_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rtl2832_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1123,8 +1123,6 @@ static int rtl2832_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(dev->regmap);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id rtl2832_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/si2165.c
> b/drivers/media/dvb-frontends/si2165.c
> index ebee230afb7b..86b0d59169dd 100644
> --- a/drivers/media/dvb-frontends/si2165.c
> +++ b/drivers/media/dvb-frontends/si2165.c
> @@ -1274,14 +1274,13 @@ static int si2165_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int si2165_remove(struct i2c_client *client)
> +static void si2165_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct si2165_state *stat=
e =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(&client->dev, "\n=
");
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id si2165_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/si2168.c
> b/drivers/media/dvb-frontends/si2168.c
> index 196e028a6617..8157df4570d1 100644
> --- a/drivers/media/dvb-frontends/si2168.c
> +++ b/drivers/media/dvb-frontends/si2168.c
> @@ -774,7 +774,7 @@ static int si2168_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int si2168_remove(struct i2c_client *client)
> +static void si2168_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct si2168_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -786,8 +786,6 @@ static int si2168_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev->fe.demodulator_priv =
=3D NULL;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id si2168_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/sp2.c b/drivers/media/dvb-
> frontends/sp2.c
> index 992f22167fbe..27e7037e130e 100644
> --- a/drivers/media/dvb-frontends/sp2.c
> +++ b/drivers/media/dvb-frontends/sp2.c
> @@ -398,14 +398,13 @@ static int sp2_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int sp2_remove(struct i2c_client *client)
> +static void sp2_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct sp2 *s =3D i2c_get=
_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(&client->dev, "\n=
");
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sp2_exit(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(s);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id sp2_id[] =3D {
> diff --git a/drivers/media/dvb-frontends/stv090x.c
> b/drivers/media/dvb-frontends/stv090x.c
> index 90d24131d335..0a600c1d7d1b 100644
> --- a/drivers/media/dvb-frontends/stv090x.c
> +++ b/drivers/media/dvb-frontends/stv090x.c
> @@ -5032,12 +5032,11 @@ static int stv090x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int stv090x_remove(struct i2c_client *client)
> +static void stv090x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct stv090x_state *sta=
te =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0stv090x_release(&state->f=
rontend);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0struct dvb_frontend *stv090x_attach(struct stv090x_config *config,
> diff --git a/drivers/media/dvb-frontends/stv6110x.c
> b/drivers/media/dvb-frontends/stv6110x.c
> index 5012d0231652..fbc4dbd62151 100644
> --- a/drivers/media/dvb-frontends/stv6110x.c
> +++ b/drivers/media/dvb-frontends/stv6110x.c
> @@ -436,12 +436,11 @@ static int stv6110x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int stv6110x_remove(struct i2c_client *client)
> +static void stv6110x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct stv6110x_state *st=
v6110x =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0stv6110x_release(stv6110x=
->frontend);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0const struct stv6110x_devctl *stv6110x_attach(struct dvb_frontend
> *fe,
> diff --git a/drivers/media/dvb-frontends/tc90522.c
> b/drivers/media/dvb-frontends/tc90522.c
> index e83836b29715..c22d2a2b2a45 100644
> --- a/drivers/media/dvb-frontends/tc90522.c
> +++ b/drivers/media/dvb-frontends/tc90522.c
> @@ -819,14 +819,13 @@ static int tc90522_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tc90522_remove(struct i2c_client *client)
> +static void tc90522_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tc90522_state *sta=
te;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0state =3D cfg_to_state(i2=
c_get_clientdata(client));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_del_adapter(&state->t=
uner_i2c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/media/dvb-frontends/tda10071.c
> b/drivers/media/dvb-frontends/tda10071.c
> index 685c0ac71819..d1098ef20a8b 100644
> --- a/drivers/media/dvb-frontends/tda10071.c
> +++ b/drivers/media/dvb-frontends/tda10071.c
> @@ -1221,14 +1221,13 @@ static int tda10071_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tda10071_remove(struct i2c_client *client)
> +static void tda10071_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tda10071_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(&client->dev, "\n=
");
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tda10071_id_table[] =3D {
> diff --git a/drivers/media/dvb-frontends/ts2020.c
> b/drivers/media/dvb-frontends/ts2020.c
> index 3e383912bcfd..02338256b974 100644
> --- a/drivers/media/dvb-frontends/ts2020.c
> +++ b/drivers/media/dvb-frontends/ts2020.c
> @@ -696,7 +696,7 @@ static int ts2020_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ts2020_remove(struct i2c_client *client)
> +static void ts2020_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ts2020_priv *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -708,7 +708,6 @@ static int ts2020_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(dev->regmap);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ts2020_id_table[] =3D {
> diff --git a/drivers/media/i2c/ad5820.c b/drivers/media/i2c/ad5820.c
> index 2958a4694461..516de278cc49 100644
> --- a/drivers/media/i2c/ad5820.c
> +++ b/drivers/media/i2c/ad5820.c
> @@ -342,7 +342,7 @@ static int ad5820_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ad5820_remove(struct i2c_client *client)
> +static void ad5820_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ad5820_device *coi=
l =3D to_ad5820_device(subdev);
> @@ -351,7 +351,6 @@ static int ad5820_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&c=
oil->ctrls);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&coi=
l->subdev.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&coil->powe=
r_lock);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ad5820_id_table[] =3D {
> diff --git a/drivers/media/i2c/ad9389b.c
> b/drivers/media/i2c/ad9389b.c
> index 8679a44e6413..4a255a492918 100644
> --- a/drivers/media/i2c/ad9389b.c
> +++ b/drivers/media/i2c/ad9389b.c
> @@ -1174,7 +1174,7 @@ static int ad9389b_probe(struct i2c_client
> *client, const struct i2c_device_id *
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> =C2=A0
> -static int ad9389b_remove(struct i2c_client *client)
> +static void ad9389b_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ad9389b_state *sta=
te =3D get_ad9389b_state(sd);
> @@ -1192,7 +1192,6 @@ static int ad9389b_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/adp1653.c
> b/drivers/media/i2c/adp1653.c
> index 522a0b10e415..1f353157df07 100644
> --- a/drivers/media/i2c/adp1653.c
> +++ b/drivers/media/i2c/adp1653.c
> @@ -510,7 +510,7 @@ static int adp1653_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int adp1653_remove(struct i2c_client *client)
> +static void adp1653_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adp1653_flash *fla=
sh =3D to_adp1653_flash(subdev);
> @@ -518,8 +518,6 @@ static int adp1653_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(&flash->subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&f=
lash->ctrls);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&fla=
sh->subdev.entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adp1653_id_table[] =3D {
> diff --git a/drivers/media/i2c/adv7170.c
> b/drivers/media/i2c/adv7170.c
> index 714e31f993e1..61a2f87d3c62 100644
> --- a/drivers/media/i2c/adv7170.c
> +++ b/drivers/media/i2c/adv7170.c
> @@ -368,12 +368,11 @@ static int adv7170_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int adv7170_remove(struct i2c_client *client)
> +static void adv7170_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/adv7175.c
> b/drivers/media/i2c/adv7175.c
> index 1813f67f0fe1..b58689728243 100644
> --- a/drivers/media/i2c/adv7175.c
> +++ b/drivers/media/i2c/adv7175.c
> @@ -423,12 +423,11 @@ static int adv7175_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int adv7175_remove(struct i2c_client *client)
> +static void adv7175_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/adv7180.c
> b/drivers/media/i2c/adv7180.c
> index e3a57c178c6b..f85e5bf228f1 100644
> --- a/drivers/media/i2c/adv7180.c
> +++ b/drivers/media/i2c/adv7180.c
> @@ -1511,7 +1511,7 @@ static int adv7180_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int adv7180_remove(struct i2c_client *client)
> +static void adv7180_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adv7180_state *sta=
te =3D to_state(sd);
> @@ -1531,8 +1531,6 @@ static int adv7180_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adv7180_set_power_pin(sta=
te, false);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&state->mut=
ex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adv7180_id[] =3D {
> diff --git a/drivers/media/i2c/adv7183.c
> b/drivers/media/i2c/adv7183.c
> index ba746a19fd39..313c706e8335 100644
> --- a/drivers/media/i2c/adv7183.c
> +++ b/drivers/media/i2c/adv7183.c
> @@ -613,13 +613,12 @@ static int adv7183_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int adv7183_remove(struct i2c_client *client)
> +static void adv7183_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adv7183_id[] =3D {
> diff --git a/drivers/media/i2c/adv7343.c
> b/drivers/media/i2c/adv7343.c
> index 63e94dfcb5d3..7e84869d2434 100644
> --- a/drivers/media/i2c/adv7343.c
> +++ b/drivers/media/i2c/adv7343.c
> @@ -492,15 +492,13 @@ static int adv7343_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int adv7343_remove(struct i2c_client *client)
> +static void adv7343_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adv7343_state *sta=
te =3D to_state(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&state->sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adv7343_id[] =3D {
> diff --git a/drivers/media/i2c/adv7393.c
> b/drivers/media/i2c/adv7393.c
> index b6234c8231c9..fb5fefa83b18 100644
> --- a/drivers/media/i2c/adv7393.c
> +++ b/drivers/media/i2c/adv7393.c
> @@ -437,15 +437,13 @@ static int adv7393_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int adv7393_remove(struct i2c_client *client)
> +static void adv7393_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adv7393_state *sta=
te =3D to_state(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adv7393_id[] =3D {
> diff --git a/drivers/media/i2c/adv748x/adv748x-core.c
> b/drivers/media/i2c/adv748x/adv748x-core.c
> index 4e54148147b9..4498d78a2357 100644
> --- a/drivers/media/i2c/adv748x/adv748x-core.c
> +++ b/drivers/media/i2c/adv748x/adv748x-core.c
> @@ -815,7 +815,7 @@ static int adv748x_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int adv748x_remove(struct i2c_client *client)
> +static void adv748x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adv748x_state *sta=
te =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -828,8 +828,6 @@ static int adv748x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adv748x_unregister_client=
s(state);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adv748x_dt_cleanup(state)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&state->mut=
ex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id adv748x_of_table[] =3D {
> diff --git a/drivers/media/i2c/adv7511-v4l2.c
> b/drivers/media/i2c/adv7511-v4l2.c
> index 202e0cd83f90..49aca579576a 100644
> --- a/drivers/media/i2c/adv7511-v4l2.c
> +++ b/drivers/media/i2c/adv7511-v4l2.c
> @@ -1923,7 +1923,7 @@ static int adv7511_probe(struct i2c_client
> *client, const struct i2c_device_id *
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> =C2=A0
> -static int adv7511_remove(struct i2c_client *client)
> +static void adv7511_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adv7511_state *sta=
te =3D get_adv7511_state(sd);
> @@ -1943,7 +1943,6 @@ static int adv7511_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/adv7604.c
> b/drivers/media/i2c/adv7604.c
> index bb0c8fc6d383..e63abf93ccac 100644
> --- a/drivers/media/i2c/adv7604.c
> +++ b/drivers/media/i2c/adv7604.c
> @@ -3661,7 +3661,7 @@ static int adv76xx_probe(struct i2c_client
> *client,
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> =C2=A0
> -static int adv76xx_remove(struct i2c_client *client)
> +static void adv76xx_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adv76xx_state *sta=
te =3D to_state(sd);
> @@ -3678,7 +3678,6 @@ static int adv76xx_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adv76xx_unregister_client=
s(to_state(sd));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/adv7842.c
> b/drivers/media/i2c/adv7842.c
> index 22caa070273b..a8dd92948df0 100644
> --- a/drivers/media/i2c/adv7842.c
> +++ b/drivers/media/i2c/adv7842.c
> @@ -3593,7 +3593,7 @@ static int adv7842_probe(struct i2c_client
> *client,
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> =C2=A0
> -static int adv7842_remove(struct i2c_client *client)
> +static void adv7842_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adv7842_state *sta=
te =3D to_state(sd);
> @@ -3604,7 +3604,6 @@ static int adv7842_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adv7842_unregister_client=
s(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/ak7375.c b/drivers/media/i2c/ak7375.c
> index 40b1a4aa846c..1af9f698eecf 100644
> --- a/drivers/media/i2c/ak7375.c
> +++ b/drivers/media/i2c/ak7375.c
> @@ -169,7 +169,7 @@ static int ak7375_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ak7375_remove(struct i2c_client *client)
> +static void ak7375_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ak7375_device *ak7=
375_dev =3D sd_to_ak7375_vcm(sd);
> @@ -177,8 +177,6 @@ static int ak7375_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ak7375_subdev_cleanup(ak7=
375_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/media/i2c/ak881x.c b/drivers/media/i2c/ak881x.c
> index dc569d5a4d9d..0370ad6b6811 100644
> --- a/drivers/media/i2c/ak881x.c
> +++ b/drivers/media/i2c/ak881x.c
> @@ -297,13 +297,11 @@ static int ak881x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ak881x_remove(struct i2c_client *client)
> +static void ak881x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ak881x *ak881x =3D=
 to_ak881x(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(&ak881x->subdev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ak881x_id[] =3D {
> diff --git a/drivers/media/i2c/bt819.c b/drivers/media/i2c/bt819.c
> index 73bc50c919d7..4d9bb6eb7d65 100644
> --- a/drivers/media/i2c/bt819.c
> +++ b/drivers/media/i2c/bt819.c
> @@ -446,14 +446,13 @@ static int bt819_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int bt819_remove(struct i2c_client *client)
> +static void bt819_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bt819 *decoder =3D=
 to_bt819(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ecoder->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/bt856.c b/drivers/media/i2c/bt856.c
> index c134fda270a1..70443ef1ac46 100644
> --- a/drivers/media/i2c/bt856.c
> +++ b/drivers/media/i2c/bt856.c
> @@ -223,12 +223,11 @@ static int bt856_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int bt856_remove(struct i2c_client *client)
> +static void bt856_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id bt856_id[] =3D {
> diff --git a/drivers/media/i2c/bt866.c b/drivers/media/i2c/bt866.c
> index 1a8df9f18ffb..c2508cbafd02 100644
> --- a/drivers/media/i2c/bt866.c
> +++ b/drivers/media/i2c/bt866.c
> @@ -190,12 +190,11 @@ static int bt866_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int bt866_remove(struct i2c_client *client)
> +static void bt866_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id bt866_id[] =3D {
> diff --git a/drivers/media/i2c/ccs/ccs-core.c
> b/drivers/media/i2c/ccs/ccs-core.c
> index 7609add2aff4..4a14d7e5d9f2 100644
> --- a/drivers/media/i2c/ccs/ccs-core.c
> +++ b/drivers/media/i2c/ccs/ccs-core.c
> @@ -3665,7 +3665,7 @@ static int ccs_probe(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rval;
> =C2=A0}
> =C2=A0
> -static int ccs_remove(struct i2c_client *client)
> +static void ccs_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ccs_sensor *sensor=
 =3D to_ccs_sensor(subdev);
> @@ -3687,8 +3687,6 @@ static int ccs_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(sensor->ccs_limits)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kvfree(sensor->sdata.back=
ing);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kvfree(sensor->mdata.back=
ing);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct ccs_device smia_device =3D {
> diff --git a/drivers/media/i2c/cs3308.c b/drivers/media/i2c/cs3308.c
> index ebe55e261bff..d901a59883a9 100644
> --- a/drivers/media/i2c/cs3308.c
> +++ b/drivers/media/i2c/cs3308.c
> @@ -99,13 +99,12 @@ static int cs3308_probe(struct i2c_client
> *client,
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> =C2=A0
> -static int cs3308_remove(struct i2c_client *client)
> +static void cs3308_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/cs5345.c b/drivers/media/i2c/cs5345.c
> index f6dd5edf77dd..591b1e7b24ee 100644
> --- a/drivers/media/i2c/cs5345.c
> +++ b/drivers/media/i2c/cs5345.c
> @@ -178,14 +178,13 @@ static int cs5345_probe(struct i2c_client
> *client,
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> =C2=A0
> -static int cs5345_remove(struct i2c_client *client)
> +static void cs5345_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs5345_state *stat=
e =3D to_state(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/cs53l32a.c
> b/drivers/media/i2c/cs53l32a.c
> index 9a411106cfb3..9461589aea30 100644
> --- a/drivers/media/i2c/cs53l32a.c
> +++ b/drivers/media/i2c/cs53l32a.c
> @@ -190,14 +190,13 @@ static int cs53l32a_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int cs53l32a_remove(struct i2c_client *client)
> +static void cs53l32a_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs53l32a_state *st=
ate =3D to_state(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cs53l32a_id[] =3D {
> diff --git a/drivers/media/i2c/cx25840/cx25840-core.c
> b/drivers/media/i2c/cx25840/cx25840-core.c
> index dc31944c7d5b..f1a978af82ef 100644
> --- a/drivers/media/i2c/cx25840/cx25840-core.c
> +++ b/drivers/media/i2c/cx25840/cx25840-core.c
> @@ -6026,7 +6026,7 @@ static int cx25840_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int cx25840_remove(struct i2c_client *client)
> +static void cx25840_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cx25840_state *sta=
te =3D to_state(sd);
> @@ -6034,7 +6034,6 @@ static int cx25840_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cx25840_ir_remove(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cx25840_id[] =3D {
> diff --git a/drivers/media/i2c/dw9714.c b/drivers/media/i2c/dw9714.c
> index 206d74338b9c..af59687383aa 100644
> --- a/drivers/media/i2c/dw9714.c
> +++ b/drivers/media/i2c/dw9714.c
> @@ -190,7 +190,7 @@ static int dw9714_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rval;
> =C2=A0}
> =C2=A0
> -static int dw9714_remove(struct i2c_client *client)
> +static void dw9714_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dw9714_device *dw9=
714_dev =3D sd_to_dw9714_vcm(sd);
> @@ -206,8 +206,6 @@ static int dw9714_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dw9714_subdev_cleanup(dw9=
714_dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/media/i2c/dw9768.c b/drivers/media/i2c/dw9768.c
> index c086580efac7..0f47ef015a1d 100644
> --- a/drivers/media/i2c/dw9768.c
> +++ b/drivers/media/i2c/dw9768.c
> @@ -499,7 +499,7 @@ static int dw9768_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int dw9768_remove(struct i2c_client *client)
> +static void dw9768_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dw9768 *dw9768 =3D=
 sd_to_dw9768(sd);
> @@ -511,8 +511,6 @@ static int dw9768_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!pm_runtime_status_su=
spended(&client->dev))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dw9768_runtime_suspend(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id dw9768_of_table[] =3D {
> diff --git a/drivers/media/i2c/dw9807-vcm.c
> b/drivers/media/i2c/dw9807-vcm.c
> index 01c372925a80..3599720db7e9 100644
> --- a/drivers/media/i2c/dw9807-vcm.c
> +++ b/drivers/media/i2c/dw9807-vcm.c
> @@ -216,7 +216,7 @@ static int dw9807_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rval;
> =C2=A0}
> =C2=A0
> -static int dw9807_remove(struct i2c_client *client)
> +static void dw9807_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dw9807_device *dw9=
807_dev =3D sd_to_dw9807_vcm(sd);
> @@ -224,8 +224,6 @@ static int dw9807_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dw9807_subdev_cleanup(dw9=
807_dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/media/i2c/et8ek8/et8ek8_driver.c
> b/drivers/media/i2c/et8ek8/et8ek8_driver.c
> index 873d614339bb..ff9bb9fc97dd 100644
> --- a/drivers/media/i2c/et8ek8/et8ek8_driver.c
> +++ b/drivers/media/i2c/et8ek8/et8ek8_driver.c
> @@ -1460,7 +1460,7 @@ static int et8ek8_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int __exit et8ek8_remove(struct i2c_client *client)
> +static void __exit et8ek8_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct et8ek8_sensor *sen=
sor =3D to_et8ek8_sensor(subdev);
> @@ -1477,8 +1477,6 @@ static int __exit et8ek8_remove(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&sensor->subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sen=
sor->subdev.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&sensor->po=
wer_lock);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id et8ek8_of_table[] =3D {
> diff --git a/drivers/media/i2c/hi556.c b/drivers/media/i2c/hi556.c
> index 055d1aa8410e..e422ac7609b5 100644
> --- a/drivers/media/i2c/hi556.c
> +++ b/drivers/media/i2c/hi556.c
> @@ -1101,7 +1101,7 @@ static int hi556_check_hwcfg(struct device
> *dev)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int hi556_remove(struct i2c_client *client)
> +static void hi556_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct hi556 *hi556 =3D t=
o_hi556(sd);
> @@ -1111,8 +1111,6 @@ static int hi556_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&hi556->mut=
ex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int hi556_probe(struct i2c_client *client)
> diff --git a/drivers/media/i2c/hi846.c b/drivers/media/i2c/hi846.c
> index ad35c3ff3611..c5b69823f257 100644
> --- a/drivers/media/i2c/hi846.c
> +++ b/drivers/media/i2c/hi846.c
> @@ -2143,7 +2143,7 @@ static int hi846_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int hi846_remove(struct i2c_client *client)
> +static void hi846_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct hi846 *hi846 =3D t=
o_hi846(sd);
> @@ -2158,8 +2158,6 @@ static int hi846_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&hi846->mut=
ex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops hi846_pm_ops =3D {
> diff --git a/drivers/media/i2c/hi847.c b/drivers/media/i2c/hi847.c
> index 7e85349e1852..5a82b15a9513 100644
> --- a/drivers/media/i2c/hi847.c
> +++ b/drivers/media/i2c/hi847.c
> @@ -2903,7 +2903,7 @@ static int hi847_check_hwcfg(struct device
> *dev)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int hi847_remove(struct i2c_client *client)
> +static void hi847_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct hi847 *hi847 =3D t=
o_hi847(sd);
> @@ -2913,8 +2913,6 @@ static int hi847_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&hi847->mut=
ex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int hi847_probe(struct i2c_client *client)
> diff --git a/drivers/media/i2c/imx208.c b/drivers/media/i2c/imx208.c
> index b9516b2f1c15..a0e17bb9d4ca 100644
> --- a/drivers/media/i2c/imx208.c
> +++ b/drivers/media/i2c/imx208.c
> @@ -1061,7 +1061,7 @@ static int imx208_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int imx208_remove(struct i2c_client *client)
> +static void imx208_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx208 *imx208 =3D=
 to_imx208(sd);
> @@ -1075,8 +1075,6 @@ static int imx208_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&imx208->im=
x208_mx);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops imx208_pm_ops =3D {
> diff --git a/drivers/media/i2c/imx214.c b/drivers/media/i2c/imx214.c
> index 83c1737abeec..710c9fb515fd 100644
> --- a/drivers/media/i2c/imx214.c
> +++ b/drivers/media/i2c/imx214.c
> @@ -1080,7 +1080,7 @@ static int imx214_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int imx214_remove(struct i2c_client *client)
> +static void imx214_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx214 *imx214 =3D=
 to_imx214(sd);
> @@ -1093,8 +1093,6 @@ static int imx214_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&imx214->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id imx214_of_match[] =3D {
> diff --git a/drivers/media/i2c/imx219.c b/drivers/media/i2c/imx219.c
> index e10af3f74b38..77bd79a5954e 100644
> --- a/drivers/media/i2c/imx219.c
> +++ b/drivers/media/i2c/imx219.c
> @@ -1562,7 +1562,7 @@ static int imx219_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int imx219_remove(struct i2c_client *client)
> +static void imx219_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx219 *imx219 =3D=
 to_imx219(sd);
> @@ -1575,8 +1575,6 @@ static int imx219_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!pm_runtime_status_su=
spended(&client->dev))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0imx219_power_off(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id imx219_dt_ids[] =3D {
> diff --git a/drivers/media/i2c/imx258.c b/drivers/media/i2c/imx258.c
> index c249507aa2db..eab5fc1ee2f7 100644
> --- a/drivers/media/i2c/imx258.c
> +++ b/drivers/media/i2c/imx258.c
> @@ -1338,7 +1338,7 @@ static int imx258_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int imx258_remove(struct i2c_client *client)
> +static void imx258_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx258 *imx258 =3D=
 to_imx258(sd);
> @@ -1351,8 +1351,6 @@ static int imx258_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!pm_runtime_status_su=
spended(&client->dev))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0imx258_power_off(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops imx258_pm_ops =3D {
> diff --git a/drivers/media/i2c/imx274.c b/drivers/media/i2c/imx274.c
> index 7de1f2948e53..a00761b1e18c 100644
> --- a/drivers/media/i2c/imx274.c
> +++ b/drivers/media/i2c/imx274.c
> @@ -2142,7 +2142,7 @@ static int imx274_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int imx274_remove(struct i2c_client *client)
> +static void imx274_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct stimx274 *imx274 =
=3D to_imx274(sd);
> @@ -2157,7 +2157,6 @@ static int imx274_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&imx274->lo=
ck);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops imx274_pm_ops =3D {
> diff --git a/drivers/media/i2c/imx290.c b/drivers/media/i2c/imx290.c
> index 99f2a50d39a4..1ce64dcdf7f0 100644
> --- a/drivers/media/i2c/imx290.c
> +++ b/drivers/media/i2c/imx290.c
> @@ -1119,7 +1119,7 @@ static int imx290_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int imx290_remove(struct i2c_client *client)
> +static void imx290_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx290 *imx290 =3D=
 to_imx290(sd);
> @@ -1134,8 +1134,6 @@ static int imx290_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!pm_runtime_status_su=
spended(imx290->dev))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0imx290_power_off(imx290->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
imx290->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id imx290_of_match[] =3D {
> diff --git a/drivers/media/i2c/imx319.c b/drivers/media/i2c/imx319.c
> index a2b5a34de76b..245a18fb40ad 100644
> --- a/drivers/media/i2c/imx319.c
> +++ b/drivers/media/i2c/imx319.c
> @@ -2523,7 +2523,7 @@ static int imx319_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int imx319_remove(struct i2c_client *client)
> +static void imx319_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx319 *imx319 =3D=
 to_imx319(sd);
> @@ -2536,8 +2536,6 @@ static int imx319_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&imx319->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops imx319_pm_ops =3D {
> diff --git a/drivers/media/i2c/imx334.c b/drivers/media/i2c/imx334.c
> index 062125501788..7b0a9086447d 100644
> --- a/drivers/media/i2c/imx334.c
> +++ b/drivers/media/i2c/imx334.c
> @@ -1089,7 +1089,7 @@ static int imx334_probe(struct i2c_client
> *client)
> =C2=A0 *
> =C2=A0 * Return: 0 if successful, error code otherwise.
> =C2=A0 */
> -static int imx334_remove(struct i2c_client *client)
> +static void imx334_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx334 *imx334 =3D=
 to_imx334(sd);
> @@ -1102,8 +1102,6 @@ static int imx334_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_suspended(&cli=
ent->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&imx334->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops imx334_pm_ops =3D {
> diff --git a/drivers/media/i2c/imx335.c b/drivers/media/i2c/imx335.c
> index 410d6b86feb5..078ede2b7a00 100644
> --- a/drivers/media/i2c/imx335.c
> +++ b/drivers/media/i2c/imx335.c
> @@ -1083,7 +1083,7 @@ static int imx335_probe(struct i2c_client
> *client)
> =C2=A0 *
> =C2=A0 * Return: 0 if successful, error code otherwise.
> =C2=A0 */
> -static int imx335_remove(struct i2c_client *client)
> +static void imx335_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx335 *imx335 =3D=
 to_imx335(sd);
> @@ -1098,8 +1098,6 @@ static int imx335_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&imx335->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops imx335_pm_ops =3D {
> diff --git a/drivers/media/i2c/imx355.c b/drivers/media/i2c/imx355.c
> index 3922b9305978..b46178681c05 100644
> --- a/drivers/media/i2c/imx355.c
> +++ b/drivers/media/i2c/imx355.c
> @@ -1810,7 +1810,7 @@ static int imx355_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int imx355_remove(struct i2c_client *client)
> +static void imx355_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx355 *imx355 =3D=
 to_imx355(sd);
> @@ -1823,8 +1823,6 @@ static int imx355_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&imx355->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops imx355_pm_ops =3D {
> diff --git a/drivers/media/i2c/imx412.c b/drivers/media/i2c/imx412.c
> index a1394d6c1432..7f6d29e0e7c4 100644
> --- a/drivers/media/i2c/imx412.c
> +++ b/drivers/media/i2c/imx412.c
> @@ -1257,7 +1257,7 @@ static int imx412_probe(struct i2c_client
> *client)
> =C2=A0 *
> =C2=A0 * Return: 0 if successful, error code otherwise.
> =C2=A0 */
> -static int imx412_remove(struct i2c_client *client)
> +static void imx412_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct imx412 *imx412 =3D=
 to_imx412(sd);
> @@ -1272,8 +1272,6 @@ static int imx412_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&imx412->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops imx412_pm_ops =3D {
> diff --git a/drivers/media/i2c/ir-kbd-i2c.c b/drivers/media/i2c/ir-
> kbd-i2c.c
> index 56674173524f..ee6bbbb977f7 100644
> --- a/drivers/media/i2c/ir-kbd-i2c.c
> +++ b/drivers/media/i2c/ir-kbd-i2c.c
> @@ -915,7 +915,7 @@ static int ir_probe(struct i2c_client *client,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int ir_remove(struct i2c_client *client)
> +static void ir_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct IR_i2c *ir =3D i2c=
_get_clientdata(client);
> =C2=A0
> @@ -924,8 +924,6 @@ static int ir_remove(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(ir-=
>tx_c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rc_unregister_device(ir->=
rc);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ir_kbd_id[] =3D {
> diff --git a/drivers/media/i2c/isl7998x.c
> b/drivers/media/i2c/isl7998x.c
> index dc3068549dfa..246d8d182a8e 100644
> --- a/drivers/media/i2c/isl7998x.c
> +++ b/drivers/media/i2c/isl7998x.c
> @@ -1544,7 +1544,7 @@ static int isl7998x_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int isl7998x_remove(struct i2c_client *client)
> +static void isl7998x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct isl7998x *isl7998x=
 =3D i2c_to_isl7998x(client);
> =C2=A0
> @@ -1552,8 +1552,6 @@ static int isl7998x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&isl7998x->subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0isl7998x_remove_controls(=
isl7998x);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&isl=
7998x->subdev.entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id isl7998x_of_match[] =3D {
> diff --git a/drivers/media/i2c/ks0127.c b/drivers/media/i2c/ks0127.c
> index c077f53b9c30..215d9a43b0b9 100644
> --- a/drivers/media/i2c/ks0127.c
> +++ b/drivers/media/i2c/ks0127.c
> @@ -675,14 +675,13 @@ static int ks0127_probe(struct i2c_client
> *client, const struct i2c_device_id *i
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ks0127_remove(struct i2c_client *client)
> +static void ks0127_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ks0127_write(sd, KS_OFMTA=
, 0x20); /* tristate */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ks0127_write(sd, KS_CMDA,=
 0x2c | 0x80); /* power down */
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ks0127_id[] =3D {
> diff --git a/drivers/media/i2c/lm3560.c b/drivers/media/i2c/lm3560.c
> index 9e34ccce4fc3..edad3138cb07 100644
> --- a/drivers/media/i2c/lm3560.c
> +++ b/drivers/media/i2c/lm3560.c
> @@ -443,7 +443,7 @@ static int lm3560_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lm3560_remove(struct i2c_client *client)
> +static void lm3560_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3560_flash *flas=
h =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unsigned int i;
> @@ -453,8 +453,6 @@ static int lm3560_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&flash->ctrls_led[i]);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&flash->subdev_led[i].entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3560_id_table[] =3D {
> diff --git a/drivers/media/i2c/lm3646.c b/drivers/media/i2c/lm3646.c
> index c76ccf67a909..0aaa963917d8 100644
> --- a/drivers/media/i2c/lm3646.c
> +++ b/drivers/media/i2c/lm3646.c
> @@ -377,15 +377,13 @@ static int lm3646_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lm3646_remove(struct i2c_client *client)
> +static void lm3646_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3646_flash *flas=
h =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(&flash->subdev_led);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&f=
lash->ctrls_led);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&fla=
sh->subdev_led.entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3646_id_table[] =3D {
> diff --git a/drivers/media/i2c/m52790.c b/drivers/media/i2c/m52790.c
> index 0a1efc1417bc..2ab91b993c33 100644
> --- a/drivers/media/i2c/m52790.c
> +++ b/drivers/media/i2c/m52790.c
> @@ -154,12 +154,11 @@ static int m52790_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int m52790_remove(struct i2c_client *client)
> +static void m52790_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/m5mols/m5mols_core.c
> b/drivers/media/i2c/m5mols/m5mols_core.c
> index c19590389bfe..2201d2a26353 100644
> --- a/drivers/media/i2c/m5mols/m5mols_core.c
> +++ b/drivers/media/i2c/m5mols/m5mols_core.c
> @@ -1020,15 +1020,13 @@ static int m5mols_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int m5mols_remove(struct i2c_client *client)
> +static void m5mols_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id m5mols_id[] =3D {
> diff --git a/drivers/media/i2c/max2175.c
> b/drivers/media/i2c/max2175.c
> index 0eea200124d2..1019020f3a37 100644
> --- a/drivers/media/i2c/max2175.c
> +++ b/drivers/media/i2c/max2175.c
> @@ -1403,15 +1403,13 @@ static int max2175_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int max2175_remove(struct i2c_client *client)
> +static void max2175_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max2175 *ctx =3D m=
ax2175_from_sd(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&c=
tx->ctrl_hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(sd);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max2175_id[] =3D {
> diff --git a/drivers/media/i2c/max9286.c
> b/drivers/media/i2c/max9286.c
> index 3684faa72253..9c083cf14231 100644
> --- a/drivers/media/i2c/max9286.c
> +++ b/drivers/media/i2c/max9286.c
> @@ -1378,7 +1378,7 @@ static int max9286_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int max9286_remove(struct i2c_client *client)
> +static void max9286_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max9286_priv *priv=
 =3D
> sd_to_max9286(i2c_get_clientdata(client));
> =C2=A0
> @@ -1391,8 +1391,6 @@ static int max9286_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(=
priv->gpiod_pwdn, 0);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0max9286_cleanup_dt(priv);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id max9286_dt_ids[] =3D {
> diff --git a/drivers/media/i2c/ml86v7667.c
> b/drivers/media/i2c/ml86v7667.c
> index 48cc0b0922f4..49ec59b0ca43 100644
> --- a/drivers/media/i2c/ml86v7667.c
> +++ b/drivers/media/i2c/ml86v7667.c
> @@ -415,15 +415,13 @@ static int ml86v7667_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ml86v7667_remove(struct i2c_client *client)
> +static void ml86v7667_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ml86v7667_priv *pr=
iv =3D to_ml86v7667(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&p=
riv->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(&priv->sd);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ml86v7667_id[] =3D {
> diff --git a/drivers/media/i2c/msp3400-driver.c
> b/drivers/media/i2c/msp3400-driver.c
> index 39530d43590e..4ce7a15a9884 100644
> --- a/drivers/media/i2c/msp3400-driver.c
> +++ b/drivers/media/i2c/msp3400-driver.c
> @@ -859,7 +859,7 @@ static int msp_probe(struct i2c_client *client,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int msp_remove(struct i2c_client *client)
> +static void msp_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct msp_state *state =
=3D
> to_state(i2c_get_clientdata(client));
> =C2=A0
> @@ -872,7 +872,6 @@ static int msp_remove(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0msp_reset(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/mt9m001.c
> b/drivers/media/i2c/mt9m001.c
> index ad13b0c890c0..ebf9cf1e1bce 100644
> --- a/drivers/media/i2c/mt9m001.c
> +++ b/drivers/media/i2c/mt9m001.c
> @@ -833,7 +833,7 @@ static int mt9m001_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mt9m001_remove(struct i2c_client *client)
> +static void mt9m001_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9m001 *mt9m001 =
=3D to_mt9m001(client);
> =C2=A0
> @@ -853,8 +853,6 @@ static int mt9m001_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&m=
t9m001->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&mt9m001->m=
utex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mt9m001_id[] =3D {
> diff --git a/drivers/media/i2c/mt9m032.c
> b/drivers/media/i2c/mt9m032.c
> index ba0c0ea91c95..76b8c9c08c82 100644
> --- a/drivers/media/i2c/mt9m032.c
> +++ b/drivers/media/i2c/mt9m032.c
> @@ -858,7 +858,7 @@ static int mt9m032_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mt9m032_remove(struct i2c_client *client)
> +static void mt9m032_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9m032 *sensor =
=3D to_mt9m032(subdev);
> @@ -867,7 +867,6 @@ static int mt9m032_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
ensor->ctrls);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sub=
dev->entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&sensor->lo=
ck);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mt9m032_id_table[] =3D {
> diff --git a/drivers/media/i2c/mt9m111.c
> b/drivers/media/i2c/mt9m111.c
> index afc86efa9e3e..f5fe272d1205 100644
> --- a/drivers/media/i2c/mt9m111.c
> +++ b/drivers/media/i2c/mt9m111.c
> @@ -1359,15 +1359,13 @@ static int mt9m111_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mt9m111_remove(struct i2c_client *client)
> +static void mt9m111_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9m111 *mt9m111 =
=3D to_mt9m111(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&mt9m111->subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&mt9=
m111->subdev.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&m=
t9m111->hdl);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0static const struct of_device_id mt9m111_of_match[] =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0{ .compatible =3D "micron=
,mt9m111", },
> diff --git a/drivers/media/i2c/mt9p031.c
> b/drivers/media/i2c/mt9p031.c
> index cbce8b88dbcf..00da584a47b7 100644
> --- a/drivers/media/i2c/mt9p031.c
> +++ b/drivers/media/i2c/mt9p031.c
> @@ -1200,7 +1200,7 @@ static int mt9p031_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mt9p031_remove(struct i2c_client *client)
> +static void mt9p031_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9p031 *mt9p031 =
=3D to_mt9p031(subdev);
> @@ -1209,8 +1209,6 @@ static int mt9p031_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sub=
dev->entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&mt9p031->p=
ower_lock);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mt9p031_id[] =3D {
> diff --git a/drivers/media/i2c/mt9t001.c
> b/drivers/media/i2c/mt9t001.c
> index b651ee4a26e8..d5abe4a7ef07 100644
> --- a/drivers/media/i2c/mt9t001.c
> +++ b/drivers/media/i2c/mt9t001.c
> @@ -961,7 +961,7 @@ static int mt9t001_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mt9t001_remove(struct i2c_client *client)
> +static void mt9t001_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9t001 *mt9t001 =
=3D to_mt9t001(subdev);
> @@ -969,7 +969,6 @@ static int mt9t001_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&m=
t9t001->ctrls);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sub=
dev->entity);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mt9t001_id[] =3D {
> diff --git a/drivers/media/i2c/mt9t112.c
> b/drivers/media/i2c/mt9t112.c
> index 8d2e3caa9b28..ad564095d0cf 100644
> --- a/drivers/media/i2c/mt9t112.c
> +++ b/drivers/media/i2c/mt9t112.c
> @@ -1102,14 +1102,12 @@ static int mt9t112_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return v4l2_async_registe=
r_subdev(&priv->subdev);
> =C2=A0}
> =C2=A0
> -static int mt9t112_remove(struct i2c_client *client)
> +static void mt9t112_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9t112_priv *priv=
 =3D to_mt9t112(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0clk_disable_unprepare(pri=
v->clk);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&priv->subdev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mt9t112_id[] =3D {
> diff --git a/drivers/media/i2c/mt9v011.c
> b/drivers/media/i2c/mt9v011.c
> index 7699e64e1127..9952ce06ebb2 100644
> --- a/drivers/media/i2c/mt9v011.c
> +++ b/drivers/media/i2c/mt9v011.c
> @@ -561,7 +561,7 @@ static int mt9v011_probe(struct i2c_client *c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int mt9v011_remove(struct i2c_client *c)
> +static void mt9v011_remove(struct i2c_client *c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9v011 *core =3D =
to_mt9v011(sd);
> @@ -572,8 +572,6 @@ static int mt9v011_remove(struct i2c_client *c)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&c=
ore->ctrls);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/mt9v032.c
> b/drivers/media/i2c/mt9v032.c
> index 4cfdd3dfbd42..bc4388ccc2a8 100644
> --- a/drivers/media/i2c/mt9v032.c
> +++ b/drivers/media/i2c/mt9v032.c
> @@ -1192,7 +1192,7 @@ static int mt9v032_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mt9v032_remove(struct i2c_client *client)
> +static void mt9v032_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9v032 *mt9v032 =
=3D to_mt9v032(subdev);
> @@ -1200,8 +1200,6 @@ static int mt9v032_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&m=
t9v032->ctrls);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sub=
dev->entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct mt9v032_model_data mt9v032_model_data[] =3D {
> diff --git a/drivers/media/i2c/mt9v111.c
> b/drivers/media/i2c/mt9v111.c
> index 2dc4a0f24ce8..fe18e5258d7a 100644
> --- a/drivers/media/i2c/mt9v111.c
> +++ b/drivers/media/i2c/mt9v111.c
> @@ -1238,7 +1238,7 @@ static int mt9v111_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mt9v111_remove(struct i2c_client *client)
> +static void mt9v111_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9v111_dev *mt9v1=
11 =3D sd_to_mt9v111(sd);
> @@ -1253,8 +1253,6 @@ static int mt9v111_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&mt9v111->p=
wr_mutex);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&mt9v111->s=
tream_mutex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id mt9v111_of_match[] =3D {
> diff --git a/drivers/media/i2c/noon010pc30.c
> b/drivers/media/i2c/noon010pc30.c
> index bc5187f46365..ecaf5e9057f1 100644
> --- a/drivers/media/i2c/noon010pc30.c
> +++ b/drivers/media/i2c/noon010pc30.c
> @@ -789,7 +789,7 @@ static int noon010_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int noon010_remove(struct i2c_client *client)
> +static void noon010_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct noon010_info *info=
 =3D to_noon010(sd);
> @@ -797,8 +797,6 @@ static int noon010_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&i=
nfo->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id noon010_id[] =3D {
> diff --git a/drivers/media/i2c/og01a1b.c
> b/drivers/media/i2c/og01a1b.c
> index 87179fc04e00..35663c10fcd9 100644
> --- a/drivers/media/i2c/og01a1b.c
> +++ b/drivers/media/i2c/og01a1b.c
> @@ -1015,7 +1015,7 @@ static int og01a1b_check_hwcfg(struct device
> *dev)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int og01a1b_remove(struct i2c_client *client)
> +static void og01a1b_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct og01a1b *og01a1b =
=3D to_og01a1b(sd);
> @@ -1025,8 +1025,6 @@ static int og01a1b_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&og01a1b->m=
utex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int og01a1b_probe(struct i2c_client *client)
> diff --git a/drivers/media/i2c/ov02a10.c
> b/drivers/media/i2c/ov02a10.c
> index 0f08c05333ea..2c1eb724d8e5 100644
> --- a/drivers/media/i2c/ov02a10.c
> +++ b/drivers/media/i2c/ov02a10.c
> @@ -975,7 +975,7 @@ static int ov02a10_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov02a10_remove(struct i2c_client *client)
> +static void ov02a10_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov02a10 *ov02a10 =
=3D to_ov02a10(sd);
> @@ -988,8 +988,6 @@ static int ov02a10_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0ov02a10_power_off(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov02a10->m=
utex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id ov02a10_of_match[] =3D {
> diff --git a/drivers/media/i2c/ov08d10.c
> b/drivers/media/i2c/ov08d10.c
> index e5ef6466a3ec..c1703596c3dc 100644
> --- a/drivers/media/i2c/ov08d10.c
> +++ b/drivers/media/i2c/ov08d10.c
> @@ -1415,7 +1415,7 @@ static int ov08d10_get_hwcfg(struct ov08d10
> *ov08d10, struct device *dev)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov08d10_remove(struct i2c_client *client)
> +static void ov08d10_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov08d10 *ov08d10 =
=3D to_ov08d10(sd);
> @@ -1425,8 +1425,6 @@ static int ov08d10_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov08d10->m=
utex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ov08d10_probe(struct i2c_client *client)
> diff --git a/drivers/media/i2c/ov13858.c
> b/drivers/media/i2c/ov13858.c
> index d5fe67c763f7..e618b613e078 100644
> --- a/drivers/media/i2c/ov13858.c
> +++ b/drivers/media/i2c/ov13858.c
> @@ -1769,7 +1769,7 @@ static int ov13858_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov13858_remove(struct i2c_client *client)
> +static void ov13858_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov13858 *ov13858 =
=3D to_ov13858(sd);
> @@ -1779,8 +1779,6 @@ static int ov13858_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ov13858_free_controls(ov1=
3858);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov13858_id_table[] =3D {
> diff --git a/drivers/media/i2c/ov13b10.c
> b/drivers/media/i2c/ov13b10.c
> index 7caeae641051..549e5d93e568 100644
> --- a/drivers/media/i2c/ov13b10.c
> +++ b/drivers/media/i2c/ov13b10.c
> @@ -1447,7 +1447,7 @@ static int ov13b10_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov13b10_remove(struct i2c_client *client)
> +static void ov13b10_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov13b10 *ov13b =3D=
 to_ov13b10(sd);
> @@ -1457,8 +1457,6 @@ static int ov13b10_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ov13b10_free_controls(ov1=
3b);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops ov13b10_pm_ops =3D {
> diff --git a/drivers/media/i2c/ov2640.c b/drivers/media/i2c/ov2640.c
> index 4b75da55b260..29ed0ef8c033 100644
> --- a/drivers/media/i2c/ov2640.c
> +++ b/drivers/media/i2c/ov2640.c
> @@ -1271,7 +1271,7 @@ static int ov2640_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov2640_remove(struct i2c_client *client)
> +static void ov2640_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov2640_priv=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 *priv =3D to_ov2640(client);
> =C2=A0
> @@ -1281,7 +1281,6 @@ static int ov2640_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&pri=
v->subdev.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(&priv->subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0clk_disable_unprepare(pri=
v->clk);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov2640_id[] =3D {
> diff --git a/drivers/media/i2c/ov2659.c b/drivers/media/i2c/ov2659.c
> index 13ded5b2aa66..42fc64ada08c 100644
> --- a/drivers/media/i2c/ov2659.c
> +++ b/drivers/media/i2c/ov2659.c
> @@ -1544,7 +1544,7 @@ static int ov2659_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov2659_remove(struct i2c_client *client)
> +static void ov2659_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov2659 *ov2659 =3D=
 to_ov2659(sd);
> @@ -1558,8 +1558,6 @@ static int ov2659_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!pm_runtime_status_su=
spended(&client->dev))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0ov2659_power_off(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops ov2659_pm_ops =3D {
> diff --git a/drivers/media/i2c/ov2680.c b/drivers/media/i2c/ov2680.c
> index 906c711f6821..de66d3395a4d 100644
> --- a/drivers/media/i2c/ov2680.c
> +++ b/drivers/media/i2c/ov2680.c
> @@ -1097,7 +1097,7 @@ static int ov2680_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov2680_remove(struct i2c_client *client)
> +static void ov2680_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov2680_dev *sensor=
 =3D to_ov2680_dev(sd);
> @@ -1106,8 +1106,6 @@ static int ov2680_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&sensor->lo=
ck);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sen=
sor->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
ensor->ctrls.handler);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused ov2680_suspend(struct device *dev)
> diff --git a/drivers/media/i2c/ov2685.c b/drivers/media/i2c/ov2685.c
> index b6e010ea3249..a3b524f15d89 100644
> --- a/drivers/media/i2c/ov2685.c
> +++ b/drivers/media/i2c/ov2685.c
> @@ -798,7 +798,7 @@ static int ov2685_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov2685_remove(struct i2c_client *client)
> +static void ov2685_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov2685 *ov2685 =3D=
 to_ov2685(sd);
> @@ -814,8 +814,6 @@ static int ov2685_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!pm_runtime_status_su=
spended(&client->dev))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0__ov2685_power_off(ov2685);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#if IS_ENABLED(CONFIG_OF)
> diff --git a/drivers/media/i2c/ov2740.c b/drivers/media/i2c/ov2740.c
> index d5f0eabf20c6..5d74ad479214 100644
> --- a/drivers/media/i2c/ov2740.c
> +++ b/drivers/media/i2c/ov2740.c
> @@ -1053,7 +1053,7 @@ static int ov2740_check_hwcfg(struct device
> *dev)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov2740_remove(struct i2c_client *client)
> +static void ov2740_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov2740 *ov2740 =3D=
 to_ov2740(sd);
> @@ -1063,8 +1063,6 @@ static int ov2740_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov2740->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ov2740_nvmem_read(void *priv, unsigned int off, void
> *val,
> diff --git a/drivers/media/i2c/ov5640.c b/drivers/media/i2c/ov5640.c
> index db5a19babe67..7bcfdfdd1248 100644
> --- a/drivers/media/i2c/ov5640.c
> +++ b/drivers/media/i2c/ov5640.c
> @@ -3180,7 +3180,7 @@ static int ov5640_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov5640_remove(struct i2c_client *client)
> +static void ov5640_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov5640_dev *sensor=
 =3D to_ov5640_dev(sd);
> @@ -3189,8 +3189,6 @@ static int ov5640_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sen=
sor->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
ensor->ctrls.handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&sensor->lo=
ck);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov5640_id[] =3D {
> diff --git a/drivers/media/i2c/ov5645.c b/drivers/media/i2c/ov5645.c
> index 562c62f192c4..81e4e87e1821 100644
> --- a/drivers/media/i2c/ov5645.c
> +++ b/drivers/media/i2c/ov5645.c
> @@ -1256,7 +1256,7 @@ static int ov5645_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov5645_remove(struct i2c_client *client)
> +static void ov5645_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov5645 *ov5645 =3D=
 to_ov5645(sd);
> @@ -1265,8 +1265,6 @@ static int ov5645_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&ov5=
645->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&o=
v5645->ctrls);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov5645->po=
wer_lock);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov5645_id[] =3D {
> diff --git a/drivers/media/i2c/ov5647.c b/drivers/media/i2c/ov5647.c
> index d346d18ce629..847a7bbb69c5 100644
> --- a/drivers/media/i2c/ov5647.c
> +++ b/drivers/media/i2c/ov5647.c
> @@ -1448,7 +1448,7 @@ static int ov5647_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov5647_remove(struct i2c_client *client)
> +static void ov5647_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov5647 *sensor =3D=
 to_sensor(sd);
> @@ -1459,8 +1459,6 @@ static int ov5647_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&sensor->lo=
ck);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops ov5647_pm_ops =3D {
> diff --git a/drivers/media/i2c/ov5648.c b/drivers/media/i2c/ov5648.c
> index dfcd33e9ee13..84604ea7bdf9 100644
> --- a/drivers/media/i2c/ov5648.c
> +++ b/drivers/media/i2c/ov5648.c
> @@ -2587,7 +2587,7 @@ static int ov5648_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov5648_remove(struct i2c_client *client)
> +static void ov5648_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov5648_sensor *sen=
sor =3D ov5648_subdev_sensor(subdev);
> @@ -2597,8 +2597,6 @@ static int ov5648_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
ensor->ctrls.handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&sensor->mu=
tex);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sub=
dev->entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops ov5648_pm_ops =3D {
> diff --git a/drivers/media/i2c/ov5670.c b/drivers/media/i2c/ov5670.c
> index 02f75c18e480..bc9fc3bc90c2 100644
> --- a/drivers/media/i2c/ov5670.c
> +++ b/drivers/media/i2c/ov5670.c
> @@ -2557,7 +2557,7 @@ static int ov5670_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov5670_remove(struct i2c_client *client)
> +static void ov5670_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov5670 *ov5670 =3D=
 to_ov5670(sd);
> @@ -2568,8 +2568,6 @@ static int ov5670_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov5670->mu=
tex);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops ov5670_pm_ops =3D {
> diff --git a/drivers/media/i2c/ov5675.c b/drivers/media/i2c/ov5675.c
> index 82ba9f56baec..94dc8cb7a7c0 100644
> --- a/drivers/media/i2c/ov5675.c
> +++ b/drivers/media/i2c/ov5675.c
> @@ -1175,7 +1175,7 @@ static int ov5675_check_hwcfg(struct device
> *dev)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov5675_remove(struct i2c_client *client)
> +static void ov5675_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov5675 *ov5675 =3D=
 to_ov5675(sd);
> @@ -1185,8 +1185,6 @@ static int ov5675_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov5675->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ov5675_probe(struct i2c_client *client)
> diff --git a/drivers/media/i2c/ov5693.c b/drivers/media/i2c/ov5693.c
> index 117ff5403312..5a05356bcfb6 100644
> --- a/drivers/media/i2c/ov5693.c
> +++ b/drivers/media/i2c/ov5693.c
> @@ -1489,7 +1489,7 @@ static int ov5693_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov5693_remove(struct i2c_client *client)
> +static void ov5693_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov5693_device *ov5=
693 =3D to_ov5693_sensor(sd);
> @@ -1507,8 +1507,6 @@ static int ov5693_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!pm_runtime_status_su=
spended(&client->dev))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0ov5693_sensor_powerdown(ov5693);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops ov5693_pm_ops =3D {
> diff --git a/drivers/media/i2c/ov5695.c b/drivers/media/i2c/ov5695.c
> index 910309783885..61906fc54e37 100644
> --- a/drivers/media/i2c/ov5695.c
> +++ b/drivers/media/i2c/ov5695.c
> @@ -1361,7 +1361,7 @@ static int ov5695_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov5695_remove(struct i2c_client *client)
> +static void ov5695_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov5695 *ov5695 =3D=
 to_ov5695(sd);
> @@ -1377,8 +1377,6 @@ static int ov5695_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!pm_runtime_status_su=
spended(&client->dev))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0__ov5695_power_off(ov5695);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#if IS_ENABLED(CONFIG_OF)
> diff --git a/drivers/media/i2c/ov6650.c b/drivers/media/i2c/ov6650.c
> index 6458e96d9091..18f041e985b7 100644
> --- a/drivers/media/i2c/ov6650.c
> +++ b/drivers/media/i2c/ov6650.c
> @@ -1096,13 +1096,12 @@ static int ov6650_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov6650_remove(struct i2c_client *client)
> +static void ov6650_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov6650 *priv =3D t=
o_ov6650(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&priv->subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&p=
riv->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov6650_id[] =3D {
> diff --git a/drivers/media/i2c/ov7251.c b/drivers/media/i2c/ov7251.c
> index 0e7be15bc20a..5d837a782ac8 100644
> --- a/drivers/media/i2c/ov7251.c
> +++ b/drivers/media/i2c/ov7251.c
> @@ -1766,7 +1766,7 @@ static int ov7251_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov7251_remove(struct i2c_client *client)
> +static void ov7251_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov7251 *ov7251 =3D=
 to_ov7251(sd);
> @@ -1780,8 +1780,6 @@ static int ov7251_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!pm_runtime_status_su=
spended(ov7251->dev))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0ov7251_set_power_off(ov7251->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
ov7251->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops ov7251_pm_ops =3D {
> diff --git a/drivers/media/i2c/ov7640.c b/drivers/media/i2c/ov7640.c
> index 977cd2d8ad33..5e2d67f0f9f2 100644
> --- a/drivers/media/i2c/ov7640.c
> +++ b/drivers/media/i2c/ov7640.c
> @@ -70,13 +70,11 @@ static int ov7640_probe(struct i2c_client
> *client,
> =C2=A0}
> =C2=A0
> =C2=A0
> -static int ov7640_remove(struct i2c_client *client)
> +static void ov7640_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov7640_id[] =3D {
> diff --git a/drivers/media/i2c/ov7670.c b/drivers/media/i2c/ov7670.c
> index 1be2c0e5bdc1..4b9b156b53c7 100644
> --- a/drivers/media/i2c/ov7670.c
> +++ b/drivers/media/i2c/ov7670.c
> @@ -2009,7 +2009,7 @@ static int ov7670_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov7670_remove(struct i2c_client *client)
> +static void ov7670_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov7670_info *info =
=3D to_state(sd);
> @@ -2017,7 +2017,6 @@ static int ov7670_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&i=
nfo->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&inf=
o->sd.entity);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov7670_id[] =3D {
> diff --git a/drivers/media/i2c/ov772x.c b/drivers/media/i2c/ov772x.c
> index 78602a2f70b0..4189e3fc3d53 100644
> --- a/drivers/media/i2c/ov772x.c
> +++ b/drivers/media/i2c/ov772x.c
> @@ -1521,7 +1521,7 @@ static int ov772x_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov772x_remove(struct i2c_client *client)
> +static void ov772x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov772x_priv *priv =
=3D
> to_ov772x(i2c_get_clientdata(client));
> =C2=A0
> @@ -1532,8 +1532,6 @@ static int ov772x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&priv->subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&p=
riv->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&priv->lock=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov772x_id[] =3D {
> diff --git a/drivers/media/i2c/ov7740.c b/drivers/media/i2c/ov7740.c
> index 2539cfee85c8..c9fd9b0bc54a 100644
> --- a/drivers/media/i2c/ov7740.c
> +++ b/drivers/media/i2c/ov7740.c
> @@ -1153,7 +1153,7 @@ static int ov7740_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov7740_remove(struct i2c_client *client)
> +static void ov7740_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov7740 *ov7740 =3D=
 container_of(sd, struct ov7740,
> subdev);
> @@ -1170,7 +1170,6 @@ static int ov7740_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_put_noidle(&cl=
ient->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ov7740_set_power(ov7740, =
0);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused ov7740_runtime_suspend(struct device *dev=
)
> diff --git a/drivers/media/i2c/ov8856.c b/drivers/media/i2c/ov8856.c
> index a9728afc81d4..efa18d026ac3 100644
> --- a/drivers/media/i2c/ov8856.c
> +++ b/drivers/media/i2c/ov8856.c
> @@ -2440,7 +2440,7 @@ static int ov8856_get_hwcfg(struct ov8856
> *ov8856, struct device *dev)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov8856_remove(struct i2c_client *client)
> +static void ov8856_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov8856 *ov8856 =3D=
 to_ov8856(sd);
> @@ -2452,8 +2452,6 @@ static int ov8856_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov8856->mu=
tex);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0__ov8856_power_off(ov8856=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ov8856_probe(struct i2c_client *client)
> diff --git a/drivers/media/i2c/ov8865.c b/drivers/media/i2c/ov8865.c
> index b8f4f0d3e33d..a233c34b168e 100644
> --- a/drivers/media/i2c/ov8865.c
> +++ b/drivers/media/i2c/ov8865.c
> @@ -3119,7 +3119,7 @@ static int ov8865_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov8865_remove(struct i2c_client *client)
> +static void ov8865_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *subde=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov8865_sensor *sen=
sor =3D ov8865_subdev_sensor(subdev);
> @@ -3131,8 +3131,6 @@ static int ov8865_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sub=
dev->entity);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_fwnode_endpoint_free=
(&sensor->endpoint);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops ov8865_pm_ops =3D {
> diff --git a/drivers/media/i2c/ov9282.c b/drivers/media/i2c/ov9282.c
> index 2e0b315801e5..df144a2f6eda 100644
> --- a/drivers/media/i2c/ov9282.c
> +++ b/drivers/media/i2c/ov9282.c
> @@ -1091,7 +1091,7 @@ static int ov9282_probe(struct i2c_client
> *client)
> =C2=A0 *
> =C2=A0 * Return: 0 if successful, error code otherwise.
> =C2=A0 */
> -static int ov9282_remove(struct i2c_client *client)
> +static void ov9282_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov9282 *ov9282 =3D=
 to_ov9282(sd);
> @@ -1106,8 +1106,6 @@ static int ov9282_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov9282->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops ov9282_pm_ops =3D {
> diff --git a/drivers/media/i2c/ov9640.c b/drivers/media/i2c/ov9640.c
> index 9f44ed52d164..8b80be33c5f4 100644
> --- a/drivers/media/i2c/ov9640.c
> +++ b/drivers/media/i2c/ov9640.c
> @@ -744,15 +744,13 @@ static int ov9640_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov9640_remove(struct i2c_client *client)
> +static void ov9640_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov9640_priv *priv =
=3D to_ov9640_sensor(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&priv->subdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&p=
riv->hdl);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov9640_id[] =3D {
> diff --git a/drivers/media/i2c/ov9650.c b/drivers/media/i2c/ov9650.c
> index c313e11a9754..4d458993e6d6 100644
> --- a/drivers/media/i2c/ov9650.c
> +++ b/drivers/media/i2c/ov9650.c
> @@ -1584,7 +1584,7 @@ static int ov965x_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov965x_remove(struct i2c_client *client)
> +static void ov965x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov965x *ov965x =3D=
 to_ov965x(sd);
> @@ -1593,8 +1593,6 @@ static int ov965x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov965x->lo=
ck);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ov965x_id[] =3D {
> diff --git a/drivers/media/i2c/ov9734.c b/drivers/media/i2c/ov9734.c
> index df538ceb71c3..8b0a158cb297 100644
> --- a/drivers/media/i2c/ov9734.c
> +++ b/drivers/media/i2c/ov9734.c
> @@ -930,7 +930,7 @@ static int ov9734_check_hwcfg(struct device *dev)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ov9734_remove(struct i2c_client *client)
> +static void ov9734_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov9734 *ov9734 =3D=
 to_ov9734(sd);
> @@ -940,8 +940,6 @@ static int ov9734_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&ov9734->mu=
tex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ov9734_probe(struct i2c_client *client)
> diff --git a/drivers/media/i2c/rdacm20.c
> b/drivers/media/i2c/rdacm20.c
> index 2615ad154f49..a2263fa825b5 100644
> --- a/drivers/media/i2c/rdacm20.c
> +++ b/drivers/media/i2c/rdacm20.c
> @@ -646,7 +646,7 @@ static int rdacm20_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rdacm20_remove(struct i2c_client *client)
> +static void rdacm20_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rdacm20_device *de=
v =3D i2c_to_rdacm20(client);
> =C2=A0
> @@ -655,8 +655,6 @@ static int rdacm20_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ev->ctrls);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&dev=
->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(dev=
->sensor);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void rdacm20_shutdown(struct i2c_client *client)
> diff --git a/drivers/media/i2c/rdacm21.c
> b/drivers/media/i2c/rdacm21.c
> index ef31cf5f23ca..9ccc56c30d3b 100644
> --- a/drivers/media/i2c/rdacm21.c
> +++ b/drivers/media/i2c/rdacm21.c
> @@ -614,7 +614,7 @@ static int rdacm21_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rdacm21_remove(struct i2c_client *client)
> +static void rdacm21_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rdacm21_device *de=
v =3D
> sd_to_rdacm21(i2c_get_clientdata(client));
> =C2=A0
> @@ -622,8 +622,6 @@ static int rdacm21_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ev->ctrls);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(dev=
->isp);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fwnode_handle_put(dev->sd=
.fwnode);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id rdacm21_of_ids[] =3D {
> diff --git a/drivers/media/i2c/rj54n1cb0c.c
> b/drivers/media/i2c/rj54n1cb0c.c
> index 2e4018c26912..1c3502f34cd3 100644
> --- a/drivers/media/i2c/rj54n1cb0c.c
> +++ b/drivers/media/i2c/rj54n1cb0c.c
> @@ -1398,7 +1398,7 @@ static int rj54n1_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rj54n1_remove(struct i2c_client *client)
> +static void rj54n1_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rj54n1 *rj54n1 =3D=
 to_rj54n1(client);
> =C2=A0
> @@ -1410,8 +1410,6 @@ static int rj54n1_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0clk_put(rj54n1->clk);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&r=
j54n1->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&rj54n1->subdev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id rj54n1_id[] =3D {
> diff --git a/drivers/media/i2c/s5c73m3/s5c73m3-core.c
> b/drivers/media/i2c/s5c73m3/s5c73m3-core.c
> index e2b88c5e4f98..d96ba58ce1e5 100644
> --- a/drivers/media/i2c/s5c73m3/s5c73m3-core.c
> +++ b/drivers/media/i2c/s5c73m3/s5c73m3-core.c
> @@ -1770,7 +1770,7 @@ static int s5c73m3_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int s5c73m3_remove(struct i2c_client *client)
> +static void s5c73m3_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *oif_s=
d =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct s5c73m3 *state =3D=
 oif_sd_to_s5c73m3(oif_sd);
> @@ -1785,8 +1785,6 @@ static int s5c73m3_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sen=
sor_sd->entity);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0s5c73m3_unregister_spi_dr=
iver(state);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id s5c73m3_id[] =3D {
> diff --git a/drivers/media/i2c/s5k4ecgx.c
> b/drivers/media/i2c/s5k4ecgx.c
> index af9a305242cd..3dddcd9dd351 100644
> --- a/drivers/media/i2c/s5k4ecgx.c
> +++ b/drivers/media/i2c/s5k4ecgx.c
> @@ -996,7 +996,7 @@ static int s5k4ecgx_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int s5k4ecgx_remove(struct i2c_client *client)
> +static void s5k4ecgx_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct s5k4ecgx *priv =3D=
 to_s5k4ecgx(sd);
> @@ -1006,8 +1006,6 @@ static int s5k4ecgx_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&p=
riv->handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id s5k4ecgx_id[] =3D {
> diff --git a/drivers/media/i2c/s5k5baf.c
> b/drivers/media/i2c/s5k5baf.c
> index 6a5dceb699a8..5c2253ab3b6f 100644
> --- a/drivers/media/i2c/s5k5baf.c
> +++ b/drivers/media/i2c/s5k5baf.c
> @@ -2018,7 +2018,7 @@ static int s5k5baf_probe(struct i2c_client *c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int s5k5baf_remove(struct i2c_client *c)
> +static void s5k5baf_remove(struct i2c_client *c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct s5k5baf *state =3D=
 to_s5k5baf(sd);
> @@ -2030,8 +2030,6 @@ static int s5k5baf_remove(struct i2c_client *c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sd =3D &state->cis_sd;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id s5k5baf_id[] =3D {
> diff --git a/drivers/media/i2c/s5k6a3.c b/drivers/media/i2c/s5k6a3.c
> index f6ecf6f92bb2..a4efd6d10b43 100644
> --- a/drivers/media/i2c/s5k6a3.c
> +++ b/drivers/media/i2c/s5k6a3.c
> @@ -354,14 +354,13 @@ static int s5k6a3_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int s5k6a3_remove(struct i2c_client *client)
> +static void s5k6a3_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id s5k6a3_ids[] =3D {
> diff --git a/drivers/media/i2c/s5k6aa.c b/drivers/media/i2c/s5k6aa.c
> index 105a4b7d8354..059211788a65 100644
> --- a/drivers/media/i2c/s5k6aa.c
> +++ b/drivers/media/i2c/s5k6aa.c
> @@ -1621,15 +1621,13 @@ static int s5k6aa_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int s5k6aa_remove(struct i2c_client *client)
> +static void s5k6aa_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id s5k6aa_id[] =3D {
> diff --git a/drivers/media/i2c/saa6588.c
> b/drivers/media/i2c/saa6588.c
> index d1e0716bdfff..d6a51beabd02 100644
> --- a/drivers/media/i2c/saa6588.c
> +++ b/drivers/media/i2c/saa6588.c
> @@ -484,7 +484,7 @@ static int saa6588_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int saa6588_remove(struct i2c_client *client)
> +static void saa6588_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct saa6588 *s =3D to_=
saa6588(sd);
> @@ -492,8 +492,6 @@ static int saa6588_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_delayed_work_sync(=
&s->work);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/saa6752hs.c
> b/drivers/media/i2c/saa6752hs.c
> index a7f043cad149..5928cc6f4595 100644
> --- a/drivers/media/i2c/saa6752hs.c
> +++ b/drivers/media/i2c/saa6752hs.c
> @@ -764,13 +764,12 @@ static int saa6752hs_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int saa6752hs_remove(struct i2c_client *client)
> +static void saa6752hs_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&t=
o_state(sd)->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id saa6752hs_id[] =3D {
> diff --git a/drivers/media/i2c/saa7110.c
> b/drivers/media/i2c/saa7110.c
> index 0c7a9ce0a693..5067525d8b11 100644
> --- a/drivers/media/i2c/saa7110.c
> +++ b/drivers/media/i2c/saa7110.c
> @@ -428,14 +428,13 @@ static int saa7110_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int saa7110_remove(struct i2c_client *client)
> +static void saa7110_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct saa7110 *decoder =
=3D to_saa7110(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ecoder->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/saa7115.c
> b/drivers/media/i2c/saa7115.c
> index 15ff80e6301e..86e70a980218 100644
> --- a/drivers/media/i2c/saa7115.c
> +++ b/drivers/media/i2c/saa7115.c
> @@ -1927,13 +1927,12 @@ static int saa711x_probe(struct i2c_client
> *client,
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> =C2=A0
> -static int saa711x_remove(struct i2c_client *client)
> +static void saa711x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id saa711x_id[] =3D {
> diff --git a/drivers/media/i2c/saa7127.c
> b/drivers/media/i2c/saa7127.c
> index 891192f6412a..78c9388c2ea1 100644
> --- a/drivers/media/i2c/saa7127.c
> +++ b/drivers/media/i2c/saa7127.c
> @@ -785,14 +785,13 @@ static int saa7127_probe(struct i2c_client
> *client,
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> =C2=A0
> -static int saa7127_remove(struct i2c_client *client)
> +static void saa7127_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Turn off TV output */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0saa7127_set_video_enable(=
sd, 0);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/saa717x.c
> b/drivers/media/i2c/saa717x.c
> index adf905360171..4f3d1b432a4e 100644
> --- a/drivers/media/i2c/saa717x.c
> +++ b/drivers/media/i2c/saa717x.c
> @@ -1324,13 +1324,12 @@ static int saa717x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int saa717x_remove(struct i2c_client *client)
> +static void saa717x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/saa7185.c
> b/drivers/media/i2c/saa7185.c
> index 7a04422df8c8..266462325d30 100644
> --- a/drivers/media/i2c/saa7185.c
> +++ b/drivers/media/i2c/saa7185.c
> @@ -322,7 +322,7 @@ static int saa7185_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int saa7185_remove(struct i2c_client *client)
> +static void saa7185_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct saa7185 *encoder =
=3D to_saa7185(sd);
> @@ -330,7 +330,6 @@ static int saa7185_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* SW: output off is acti=
ve */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0saa7185_write(sd, 0x61, (=
encoder->reg[0x61]) | 0x40);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/sony-btf-mpx.c
> b/drivers/media/i2c/sony-btf-mpx.c
> index ad239280c42e..927a9ec41463 100644
> --- a/drivers/media/i2c/sony-btf-mpx.c
> +++ b/drivers/media/i2c/sony-btf-mpx.c
> @@ -357,13 +357,11 @@ static int sony_btf_mpx_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int sony_btf_mpx_remove(struct i2c_client *client)
> +static void sony_btf_mpx_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/sr030pc30.c
> b/drivers/media/i2c/sr030pc30.c
> index 19c0252df2f1..ff18693beb5c 100644
> --- a/drivers/media/i2c/sr030pc30.c
> +++ b/drivers/media/i2c/sr030pc30.c
> @@ -732,13 +732,12 @@ static int sr030pc30_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int sr030pc30_remove(struct i2c_client *client)
> +static void sr030pc30_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id sr030pc30_id[] =3D {
> diff --git a/drivers/media/i2c/st-mipid02.c b/drivers/media/i2c/st-
> mipid02.c
> index ef976d085d72..0389223a61f7 100644
> --- a/drivers/media/i2c/st-mipid02.c
> +++ b/drivers/media/i2c/st-mipid02.c
> @@ -1041,7 +1041,7 @@ static int mipid02_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mipid02_remove(struct i2c_client *client)
> +static void mipid02_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mipid02_dev *bridg=
e =3D to_mipid02_dev(sd);
> @@ -1052,8 +1052,6 @@ static int mipid02_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mipid02_set_power_off(bri=
dge);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&bri=
dge->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&bridge->lo=
ck);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id mipid02_dt_ids[] =3D {
> diff --git a/drivers/media/i2c/tc358743.c
> b/drivers/media/i2c/tc358743.c
> index e18b8947ad7e..d99eedbdf011 100644
> --- a/drivers/media/i2c/tc358743.c
> +++ b/drivers/media/i2c/tc358743.c
> @@ -2169,7 +2169,7 @@ static int tc358743_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int tc358743_remove(struct i2c_client *client)
> +static void tc358743_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tc358743_state *st=
ate =3D to_state(sd);
> @@ -2185,8 +2185,6 @@ static int tc358743_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&state->con=
fctl_mutex);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&sd-=
>entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tc358743_id[] =3D {
> diff --git a/drivers/media/i2c/tda1997x.c
> b/drivers/media/i2c/tda1997x.c
> index 8fafce26d62f..47d60f9a656f 100644
> --- a/drivers/media/i2c/tda1997x.c
> +++ b/drivers/media/i2c/tda1997x.c
> @@ -2805,7 +2805,7 @@ static int tda1997x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tda1997x_remove(struct i2c_client *client)
> +static void tda1997x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tda1997x_state *st=
ate =3D to_state(sd);
> @@ -2827,8 +2827,6 @@ static int tda1997x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&state->loc=
k);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver tda1997x_i2c_driver =3D {
> diff --git a/drivers/media/i2c/tda7432.c
> b/drivers/media/i2c/tda7432.c
> index cbdc9be0a597..11e918311b13 100644
> --- a/drivers/media/i2c/tda7432.c
> +++ b/drivers/media/i2c/tda7432.c
> @@ -390,7 +390,7 @@ static int tda7432_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tda7432_remove(struct i2c_client *client)
> +static void tda7432_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tda7432 *t =3D to_=
state(sd);
> @@ -398,7 +398,6 @@ static int tda7432_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tda7432_set(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&t=
->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tda7432_id[] =3D {
> diff --git a/drivers/media/i2c/tda9840.c
> b/drivers/media/i2c/tda9840.c
> index 8c6dfe746b20..aaa74944fc7c 100644
> --- a/drivers/media/i2c/tda9840.c
> +++ b/drivers/media/i2c/tda9840.c
> @@ -175,12 +175,11 @@ static int tda9840_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tda9840_remove(struct i2c_client *client)
> +static void tda9840_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tda9840_id[] =3D {
> diff --git a/drivers/media/i2c/tea6415c.c
> b/drivers/media/i2c/tea6415c.c
> index 67378dbcc74b..50e74314f315 100644
> --- a/drivers/media/i2c/tea6415c.c
> +++ b/drivers/media/i2c/tea6415c.c
> @@ -134,12 +134,11 @@ static int tea6415c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tea6415c_remove(struct i2c_client *client)
> +static void tea6415c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tea6415c_id[] =3D {
> diff --git a/drivers/media/i2c/tea6420.c
> b/drivers/media/i2c/tea6420.c
> index 712141b261ed..246f2b10ccc7 100644
> --- a/drivers/media/i2c/tea6420.c
> +++ b/drivers/media/i2c/tea6420.c
> @@ -116,12 +116,11 @@ static int tea6420_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tea6420_remove(struct i2c_client *client)
> +static void tea6420_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tea6420_id[] =3D {
> diff --git a/drivers/media/i2c/ths7303.c
> b/drivers/media/i2c/ths7303.c
> index 8206bf7a5a8f..2a0f9a3d1a66 100644
> --- a/drivers/media/i2c/ths7303.c
> +++ b/drivers/media/i2c/ths7303.c
> @@ -358,13 +358,11 @@ static int ths7303_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ths7303_remove(struct i2c_client *client)
> +static void ths7303_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ths7303_id[] =3D {
> diff --git a/drivers/media/i2c/ths8200.c
> b/drivers/media/i2c/ths8200.c
> index c52fe84cba1b..081ef5a4b950 100644
> --- a/drivers/media/i2c/ths8200.c
> +++ b/drivers/media/i2c/ths8200.c
> @@ -468,7 +468,7 @@ static int ths8200_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ths8200_remove(struct i2c_client *client)
> +static void ths8200_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ths8200_state *dec=
oder =3D to_state(sd);
> @@ -478,8 +478,6 @@ static int ths8200_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ths8200_s_power(sd, false=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&decoder->sd);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ths8200_id[] =3D {
> diff --git a/drivers/media/i2c/tlv320aic23b.c
> b/drivers/media/i2c/tlv320aic23b.c
> index e4c21990fea9..937fa1dbaecb 100644
> --- a/drivers/media/i2c/tlv320aic23b.c
> +++ b/drivers/media/i2c/tlv320aic23b.c
> @@ -177,14 +177,13 @@ static int tlv320aic23b_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tlv320aic23b_remove(struct i2c_client *client)
> +static void tlv320aic23b_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tlv320aic23b_state=
 *state =3D to_state(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/tvaudio.c
> b/drivers/media/i2c/tvaudio.c
> index e6796e94dadf..9f1ed078b661 100644
> --- a/drivers/media/i2c/tvaudio.c
> +++ b/drivers/media/i2c/tvaudio.c
> @@ -2065,7 +2065,7 @@ static int tvaudio_probe(struct i2c_client
> *client, const struct i2c_device_id *
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tvaudio_remove(struct i2c_client *client)
> +static void tvaudio_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct CHIPSTATE *chip =
=3D to_state(sd);
> @@ -2079,7 +2079,6 @@ static int tvaudio_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&c=
hip->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* This driver supports many devices and the idea is to let the
> driver
> diff --git a/drivers/media/i2c/tvp514x.c
> b/drivers/media/i2c/tvp514x.c
> index cee60f945036..a746d96875f9 100644
> --- a/drivers/media/i2c/tvp514x.c
> +++ b/drivers/media/i2c/tvp514x.c
> @@ -1121,7 +1121,7 @@ tvp514x_probe(struct i2c_client *client, const
> struct i2c_device_id *id)
> =C2=A0 * Unregister decoder as an i2c client device and V4L2
> =C2=A0 * device. Complement of tvp514x_probe().
> =C2=A0 */
> -static int tvp514x_remove(struct i2c_client *client)
> +static void tvp514x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tvp514x_decoder *d=
ecoder =3D to_decoder(sd);
> @@ -1129,7 +1129,6 @@ static int tvp514x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&decoder->sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&dec=
oder->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ecoder->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0/* TVP5146 Init/Power on Sequence */
> =C2=A0static const struct tvp514x_reg tvp5146_init_reg_seq[] =3D {
> diff --git a/drivers/media/i2c/tvp5150.c
> b/drivers/media/i2c/tvp5150.c
> index 65472438444b..de21e67c0709 100644
> --- a/drivers/media/i2c/tvp5150.c
> +++ b/drivers/media/i2c/tvp5150.c
> @@ -2230,7 +2230,7 @@ static int tvp5150_probe(struct i2c_client *c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return res;
> =C2=A0}
> =C2=A0
> -static int tvp5150_remove(struct i2c_client *c)
> +static void tvp5150_remove(struct i2c_client *c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tvp5150 *decoder =
=3D to_tvp5150(sd);
> @@ -2250,8 +2250,6 @@ static int tvp5150_remove(struct i2c_client *c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ecoder->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&c->de=
v);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&c->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/tvp7002.c
> b/drivers/media/i2c/tvp7002.c
> index 2de18833b07b..4ccd218f5584 100644
> --- a/drivers/media/i2c/tvp7002.c
> +++ b/drivers/media/i2c/tvp7002.c
> @@ -1044,7 +1044,7 @@ static int tvp7002_probe(struct i2c_client *c)
> =C2=A0 * Reset the TVP7002 device
> =C2=A0 * Returns zero.
> =C2=A0 */
> -static int tvp7002_remove(struct i2c_client *c)
> +static void tvp7002_remove(struct i2c_client *c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tvp7002 *device =
=3D to_tvp7002(sd);
> @@ -1056,7 +1056,6 @@ static int tvp7002_remove(struct i2c_client *c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&dev=
ice->sd.entity);
> =C2=A0#endif
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
evice->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* I2C Device ID table */
> diff --git a/drivers/media/i2c/tw2804.c b/drivers/media/i2c/tw2804.c
> index cd05f1ff504d..c7c8dfe8a8a8 100644
> --- a/drivers/media/i2c/tw2804.c
> +++ b/drivers/media/i2c/tw2804.c
> @@ -405,14 +405,13 @@ static int tw2804_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tw2804_remove(struct i2c_client *client)
> +static void tw2804_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tw2804 *state =3D =
to_state(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tw2804_id[] =3D {
> diff --git a/drivers/media/i2c/tw9903.c b/drivers/media/i2c/tw9903.c
> index f8e3ab4909d8..d7eef7986b75 100644
> --- a/drivers/media/i2c/tw9903.c
> +++ b/drivers/media/i2c/tw9903.c
> @@ -235,13 +235,12 @@ static int tw9903_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tw9903_remove(struct i2c_client *client)
> +static void tw9903_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&t=
o_state(sd)->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/tw9906.c b/drivers/media/i2c/tw9906.c
> index c528eb01fed0..549ad8f72f12 100644
> --- a/drivers/media/i2c/tw9906.c
> +++ b/drivers/media/i2c/tw9906.c
> @@ -203,13 +203,12 @@ static int tw9906_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tw9906_remove(struct i2c_client *client)
> +static void tw9906_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&t=
o_state(sd)->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/tw9910.c b/drivers/media/i2c/tw9910.c
> index 09f5b3986928..853b5acead32 100644
> --- a/drivers/media/i2c/tw9910.c
> +++ b/drivers/media/i2c/tw9910.c
> @@ -993,7 +993,7 @@ static int tw9910_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tw9910_remove(struct i2c_client *client)
> +static void tw9910_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tw9910_priv *priv =
=3D to_tw9910(client);
> =C2=A0
> @@ -1001,8 +1001,6 @@ static int tw9910_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpiod_put(priv->pdn_gpio);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0clk_put(priv->clk);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&priv->subdev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tw9910_id[] =3D {
> diff --git a/drivers/media/i2c/uda1342.c
> b/drivers/media/i2c/uda1342.c
> index b0a9c6d7163f..d0659c4392f2 100644
> --- a/drivers/media/i2c/uda1342.c
> +++ b/drivers/media/i2c/uda1342.c
> @@ -72,12 +72,11 @@ static int uda1342_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int uda1342_remove(struct i2c_client *client)
> +static void uda1342_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id uda1342_id[] =3D {
> diff --git a/drivers/media/i2c/upd64031a.c
> b/drivers/media/i2c/upd64031a.c
> index ef35c6574785..4de26ed2ba00 100644
> --- a/drivers/media/i2c/upd64031a.c
> +++ b/drivers/media/i2c/upd64031a.c
> @@ -210,12 +210,11 @@ static int upd64031a_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int upd64031a_remove(struct i2c_client *client)
> +static void upd64031a_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/upd64083.c
> b/drivers/media/i2c/upd64083.c
> index d6a1698caa2a..2bfd5443d406 100644
> --- a/drivers/media/i2c/upd64083.c
> +++ b/drivers/media/i2c/upd64083.c
> @@ -181,12 +181,11 @@ static int upd64083_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int upd64083_remove(struct i2c_client *client)
> +static void upd64083_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/video-i2c.c b/drivers/media/i2c/video-
> i2c.c
> index e08e3579c0a1..f15ef2d13059 100644
> --- a/drivers/media/i2c/video-i2c.c
> +++ b/drivers/media/i2c/video-i2c.c
> @@ -895,7 +895,7 @@ static int video_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int video_i2c_remove(struct i2c_client *client)
> +static void video_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct video_i2c_data *da=
ta =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -908,8 +908,6 @@ static int video_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0data->chip->set_power(data, false);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0video_unregister_device(&=
data->vdev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/media/i2c/vp27smpx.c
> b/drivers/media/i2c/vp27smpx.c
> index 492af8749fca..c832edad5fa7 100644
> --- a/drivers/media/i2c/vp27smpx.c
> +++ b/drivers/media/i2c/vp27smpx.c
> @@ -163,12 +163,11 @@ static int vp27smpx_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int vp27smpx_remove(struct i2c_client *client)
> +static void vp27smpx_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* ----------------------------------------------------------------=
-
> ------ */
> diff --git a/drivers/media/i2c/vpx3220.c
> b/drivers/media/i2c/vpx3220.c
> index 8be03fe5928c..b481ec196b88 100644
> --- a/drivers/media/i2c/vpx3220.c
> +++ b/drivers/media/i2c/vpx3220.c
> @@ -526,15 +526,13 @@ static int vpx3220_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int vpx3220_remove(struct i2c_client *client)
> +static void vpx3220_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct vpx3220 *decoder =
=3D to_vpx3220(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ecoder->hdl);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id vpx3220_id[] =3D {
> diff --git a/drivers/media/i2c/vs6624.c b/drivers/media/i2c/vs6624.c
> index 29003dec6f2d..d496bb45f201 100644
> --- a/drivers/media/i2c/vs6624.c
> +++ b/drivers/media/i2c/vs6624.c
> @@ -824,13 +824,12 @@ static int vs6624_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int vs6624_remove(struct i2c_client *client)
> +static void vs6624_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id vs6624_id[] =3D {
> diff --git a/drivers/media/i2c/wm8739.c b/drivers/media/i2c/wm8739.c
> index ed533834db54..180b35347521 100644
> --- a/drivers/media/i2c/wm8739.c
> +++ b/drivers/media/i2c/wm8739.c
> @@ -234,14 +234,13 @@ static int wm8739_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int wm8739_remove(struct i2c_client *client)
> +static void wm8739_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wm8739_state *stat=
e =3D to_state(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm8739_id[] =3D {
> diff --git a/drivers/media/i2c/wm8775.c b/drivers/media/i2c/wm8775.c
> index d4c83c39892a..8ff97867d3cd 100644
> --- a/drivers/media/i2c/wm8775.c
> +++ b/drivers/media/i2c/wm8775.c
> @@ -280,14 +280,13 @@ static int wm8775_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int wm8775_remove(struct i2c_client *client)
> +static void wm8775_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wm8775_state *stat=
e =3D to_state(sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm8775_id[] =3D {
> diff --git a/drivers/media/radio/radio-tea5764.c
> b/drivers/media/radio/radio-tea5764.c
> index 877a24e5c577..abda40e81612 100644
> --- a/drivers/media/radio/radio-tea5764.c
> +++ b/drivers/media/radio/radio-tea5764.c
> @@ -487,7 +487,7 @@ static int tea5764_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tea5764_i2c_remove(struct i2c_client *client)
> +static void tea5764_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tea5764_device *ra=
dio =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -499,7 +499,6 @@ static int tea5764_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister(&radio->v4l2_dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0kfree(radio);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* I2C subsystem interface */
> diff --git a/drivers/media/radio/saa7706h.c
> b/drivers/media/radio/saa7706h.c
> index adb66f869dd2..f9e990a9c3ef 100644
> --- a/drivers/media/radio/saa7706h.c
> +++ b/drivers/media/radio/saa7706h.c
> @@ -384,7 +384,7 @@ static int saa7706h_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int saa7706h_remove(struct i2c_client *client)
> +static void saa7706h_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct saa7706h_state *st=
ate =3D to_state(sd);
> @@ -393,7 +393,6 @@ static int saa7706h_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(to_state(sd));
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id saa7706h_id[] =3D {
> diff --git a/drivers/media/radio/si470x/radio-si470x-i2c.c
> b/drivers/media/radio/si470x/radio-si470x-i2c.c
> index 59b3d77e282d..a6ad926c2b4e 100644
> --- a/drivers/media/radio/si470x/radio-si470x-i2c.c
> +++ b/drivers/media/radio/si470x/radio-si470x-i2c.c
> @@ -461,7 +461,7 @@ static int si470x_i2c_probe(struct i2c_client
> *client)
> =C2=A0/*
> =C2=A0 * si470x_i2c_remove - remove the device
> =C2=A0 */
> -static int si470x_i2c_remove(struct i2c_client *client)
> +static void si470x_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct si470x_device *rad=
io =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -472,7 +472,6 @@ static int si470x_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&r=
adio->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister(&r=
adio->v4l2_dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/media/radio/si4713/si4713.c
> b/drivers/media/radio/si4713/si4713.c
> index adbf43ff6a21..2aec642133a1 100644
> --- a/drivers/media/radio/si4713/si4713.c
> +++ b/drivers/media/radio/si4713/si4713.c
> @@ -1623,7 +1623,7 @@ static int si4713_probe(struct i2c_client
> *client)
> =C2=A0}
> =C2=A0
> =C2=A0/* si4713_remove - remove the device */
> -static int si4713_remove(struct i2c_client *client)
> +static void si4713_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct si4713_device *sde=
v =3D to_si4713_device(sd);
> @@ -1635,8 +1635,6 @@ static int si4713_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(sd=
->ctrl_handler);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* si4713_i2c_driver - i2c driver interface */
> diff --git a/drivers/media/radio/tef6862.c
> b/drivers/media/radio/tef6862.c
> index d8810492db4f..7b0870a9785b 100644
> --- a/drivers/media/radio/tef6862.c
> +++ b/drivers/media/radio/tef6862.c
> @@ -165,13 +165,12 @@ static int tef6862_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tef6862_remove(struct i2c_client *client)
> +static void tef6862_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(to_state(sd));
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tef6862_id[] =3D {
> diff --git a/drivers/media/test-drivers/vidtv/vidtv_demod.c
> b/drivers/media/test-drivers/vidtv/vidtv_demod.c
> index b7823d97b30d..e7959ab1add8 100644
> --- a/drivers/media/test-drivers/vidtv/vidtv_demod.c
> +++ b/drivers/media/test-drivers/vidtv/vidtv_demod.c
> @@ -438,13 +438,11 @@ static int vidtv_demod_i2c_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int vidtv_demod_i2c_remove(struct i2c_client *client)
> +static void vidtv_demod_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct vidtv_demod_state =
*state =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver vidtv_demod_i2c_driver =3D {
> diff --git a/drivers/media/test-drivers/vidtv/vidtv_tuner.c
> b/drivers/media/test-drivers/vidtv/vidtv_tuner.c
> index 14b6bc902ee1..aabc97ed736b 100644
> --- a/drivers/media/test-drivers/vidtv/vidtv_tuner.c
> +++ b/drivers/media/test-drivers/vidtv/vidtv_tuner.c
> @@ -414,13 +414,11 @@ static int vidtv_tuner_i2c_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int vidtv_tuner_i2c_remove(struct i2c_client *client)
> +static void vidtv_tuner_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct vidtv_tuner_dev *t=
uner_dev =3D
> i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(tuner_dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver vidtv_tuner_i2c_driver =3D {
> diff --git a/drivers/media/tuners/e4000.c
> b/drivers/media/tuners/e4000.c
> index a3a8d051dc6c..61ae884ea59a 100644
> --- a/drivers/media/tuners/e4000.c
> +++ b/drivers/media/tuners/e4000.c
> @@ -706,7 +706,7 @@ static int e4000_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int e4000_remove(struct i2c_client *client)
> +static void e4000_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct e4000_dev *dev =3D=
 container_of(sd, struct e4000_dev,
> sd);
> @@ -717,8 +717,6 @@ static int e4000_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ev->hdl);
> =C2=A0#endif
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id e4000_id_table[] =3D {
> diff --git a/drivers/media/tuners/fc2580.c
> b/drivers/media/tuners/fc2580.c
> index 1b5961bdf2d5..f30932e1a0f3 100644
> --- a/drivers/media/tuners/fc2580.c
> +++ b/drivers/media/tuners/fc2580.c
> @@ -588,7 +588,7 @@ static int fc2580_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int fc2580_remove(struct i2c_client *client)
> +static void fc2580_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct fc2580_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -598,7 +598,6 @@ static int fc2580_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ev->hdl);
> =C2=A0#endif
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id fc2580_id_table[] =3D {
> diff --git a/drivers/media/tuners/m88rs6000t.c
> b/drivers/media/tuners/m88rs6000t.c
> index 8647c50b66e5..e32e3e9daa15 100644
> --- a/drivers/media/tuners/m88rs6000t.c
> +++ b/drivers/media/tuners/m88rs6000t.c
> @@ -697,7 +697,7 @@ static int m88rs6000t_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int m88rs6000t_remove(struct i2c_client *client)
> +static void m88rs6000t_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct m88rs6000t_dev *de=
v =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dvb_frontend *fe =
=3D dev->cfg.fe;
> @@ -707,8 +707,6 @@ static int m88rs6000t_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0memset(&fe->ops.tuner_ops=
, 0, sizeof(struct dvb_tuner_ops));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fe->tuner_priv =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id m88rs6000t_id[] =3D {
> diff --git a/drivers/media/tuners/mt2060.c
> b/drivers/media/tuners/mt2060.c
> index 204e6186bf71..322c806228a5 100644
> --- a/drivers/media/tuners/mt2060.c
> +++ b/drivers/media/tuners/mt2060.c
> @@ -509,11 +509,9 @@ static int mt2060_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mt2060_remove(struct i2c_client *client)
> +static void mt2060_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(&client->dev, "\n=
");
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id mt2060_id_table[] =3D {
> diff --git a/drivers/media/tuners/mxl301rf.c
> b/drivers/media/tuners/mxl301rf.c
> index c628435a1b06..6422056185a9 100644
> --- a/drivers/media/tuners/mxl301rf.c
> +++ b/drivers/media/tuners/mxl301rf.c
> @@ -307,14 +307,13 @@ static int mxl301rf_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int mxl301rf_remove(struct i2c_client *client)
> +static void mxl301rf_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mxl301rf_state *st=
ate;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0state =3D cfg_to_state(i2=
c_get_clientdata(client));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0state->cfg.fe->tuner_priv=
 =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/media/tuners/qm1d1b0004.c
> b/drivers/media/tuners/qm1d1b0004.c
> index 008ad870c00f..9cba0893207c 100644
> --- a/drivers/media/tuners/qm1d1b0004.c
> +++ b/drivers/media/tuners/qm1d1b0004.c
> @@ -232,14 +232,13 @@ qm1d1b0004_probe(struct i2c_client *client,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int qm1d1b0004_remove(struct i2c_client *client)
> +static void qm1d1b0004_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dvb_frontend *fe;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fe =3D i2c_get_clientdata=
(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(fe->tuner_priv);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fe->tuner_priv =3D NULL;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/media/tuners/qm1d1c0042.c
> b/drivers/media/tuners/qm1d1c0042.c
> index 53aa2558f71e..2d60bf501fb5 100644
> --- a/drivers/media/tuners/qm1d1c0042.c
> +++ b/drivers/media/tuners/qm1d1c0042.c
> @@ -424,14 +424,13 @@ static int qm1d1c0042_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int qm1d1c0042_remove(struct i2c_client *client)
> +static void qm1d1c0042_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct qm1d1c0042_state *=
state;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0state =3D cfg_to_state(i2=
c_get_clientdata(client));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0state->cfg.fe->tuner_priv=
 =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/media/tuners/si2157.c
> b/drivers/media/tuners/si2157.c
> index 0de587b412d4..476b32c04c20 100644
> --- a/drivers/media/tuners/si2157.c
> +++ b/drivers/media/tuners/si2157.c
> @@ -951,7 +951,7 @@ static int si2157_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int si2157_remove(struct i2c_client *client)
> +static void si2157_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct si2157_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dvb_frontend *fe =
=3D dev->fe;
> @@ -969,8 +969,6 @@ static int si2157_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0memset(&fe->ops.tuner_ops=
, 0, sizeof(struct dvb_tuner_ops));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fe->tuner_priv =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/media/tuners/tda18212.c
> b/drivers/media/tuners/tda18212.c
> index bf48f1cd83d2..eb97711c9c68 100644
> --- a/drivers/media/tuners/tda18212.c
> +++ b/drivers/media/tuners/tda18212.c
> @@ -242,7 +242,7 @@ static int tda18212_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tda18212_remove(struct i2c_client *client)
> +static void tda18212_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tda18212_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dvb_frontend *fe =
=3D dev->cfg.fe;
> @@ -252,8 +252,6 @@ static int tda18212_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0memset(&fe->ops.tuner_ops=
, 0, sizeof(struct dvb_tuner_ops));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fe->tuner_priv =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tda18212_id[] =3D {
> diff --git a/drivers/media/tuners/tda18250.c
> b/drivers/media/tuners/tda18250.c
> index 8a5781b966ee..e404a5afad4c 100644
> --- a/drivers/media/tuners/tda18250.c
> +++ b/drivers/media/tuners/tda18250.c
> @@ -856,7 +856,7 @@ static int tda18250_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tda18250_remove(struct i2c_client *client)
> +static void tda18250_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tda18250_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dvb_frontend *fe =
=3D dev->fe;
> @@ -866,8 +866,6 @@ static int tda18250_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0memset(&fe->ops.tuner_ops=
, 0, sizeof(struct dvb_tuner_ops));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fe->tuner_priv =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tda18250_id_table[] =3D {
> diff --git a/drivers/media/tuners/tua9001.c
> b/drivers/media/tuners/tua9001.c
> index af7d5ea1f77e..d141d000b819 100644
> --- a/drivers/media/tuners/tua9001.c
> +++ b/drivers/media/tuners/tua9001.c
> @@ -227,7 +227,7 @@ static int tua9001_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tua9001_remove(struct i2c_client *client)
> +static void tua9001_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tua9001_dev *dev =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dvb_frontend *fe =
=3D dev->fe;
> @@ -243,7 +243,6 @@ static int tua9001_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev=
_err(&client->dev, "Tuner disable failed
> (%pe)\n", ERR_PTR(ret));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tua9001_id_table[] =3D {
> diff --git a/drivers/media/usb/go7007/s2250-board.c
> b/drivers/media/usb/go7007/s2250-board.c
> index 1fa6f10ee157..2f45188bf9d4 100644
> --- a/drivers/media/usb/go7007/s2250-board.c
> +++ b/drivers/media/usb/go7007/s2250-board.c
> @@ -601,7 +601,7 @@ static int s2250_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int s2250_remove(struct i2c_client *client)
> +static void s2250_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct s2250 *state =3D t=
o_state(i2c_get_clientdata(client));
> =C2=A0
> @@ -609,7 +609,6 @@ static int s2250_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_device_unregister_su=
bdev(&state->sd);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&s=
tate->hdl);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(state);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id s2250_id[] =3D {
> diff --git a/drivers/media/v4l2-core/tuner-core.c
> b/drivers/media/v4l2-core/tuner-core.c
> index 2d47c10de062..33162dc1daf6 100644
> --- a/drivers/media/v4l2-core/tuner-core.c
> +++ b/drivers/media/v4l2-core/tuner-core.c
> @@ -779,7 +779,7 @@ static int tuner_probe(struct i2c_client *client,
> =C2=A0 * @client:=C2=A0=C2=A0=C2=A0=C2=A0i2c_client descriptor
> =C2=A0 */
> =C2=A0
> -static int tuner_remove(struct i2c_client *client)
> +static void tuner_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tuner *t =3D to_tu=
ner(i2c_get_clientdata(client));
> =C2=A0
> @@ -789,7 +789,6 @@ static int tuner_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0list_del(&t->list);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(t);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/mfd/88pm800.c b/drivers/mfd/88pm800.c
> index eaf9845633b4..a30e47b74327 100644
> --- a/drivers/mfd/88pm800.c
> +++ b/drivers/mfd/88pm800.c
> @@ -583,7 +583,7 @@ static int pm800_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int pm800_remove(struct i2c_client *client)
> +static void pm800_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pm80x_chip *chip =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -592,8 +592,6 @@ static int pm800_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm800_pages_exit(chip);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm80x_deinit();
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver pm800_driver =3D {
> diff --git a/drivers/mfd/88pm805.c b/drivers/mfd/88pm805.c
> index ada6c513302b..10d3637840c8 100644
> --- a/drivers/mfd/88pm805.c
> +++ b/drivers/mfd/88pm805.c
> @@ -239,7 +239,7 @@ static int pm805_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int pm805_remove(struct i2c_client *client)
> +static void pm805_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pm80x_chip *chip =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -247,8 +247,6 @@ static int pm805_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0device_irq_exit_805(chip)=
;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm80x_deinit();
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver pm805_driver =3D {
> diff --git a/drivers/mfd/88pm860x-core.c b/drivers/mfd/88pm860x-
> core.c
> index b1e829ea909b..5dc86dd66202 100644
> --- a/drivers/mfd/88pm860x-core.c
> +++ b/drivers/mfd/88pm860x-core.c
> @@ -1201,7 +1201,7 @@ static int pm860x_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int pm860x_remove(struct i2c_client *client)
> +static void pm860x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pm860x_chip *chip =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1210,7 +1210,6 @@ static int pm860x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0regmap_exit(chip->regmap_companion);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(chip->companion);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/mfd/acer-ec-a500.c b/drivers/mfd/acer-ec-a500.c
> index 80c2fdd14fc4..7fd8b9988075 100644
> --- a/drivers/mfd/acer-ec-a500.c
> +++ b/drivers/mfd/acer-ec-a500.c
> @@ -169,7 +169,7 @@ static int a500_ec_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int a500_ec_remove(struct i2c_client *client)
> +static void a500_ec_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (of_device_is_system_p=
ower_controller(client-
> >dev.of_node)) {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0if (pm_power_off =3D=3D a500_ec_poweroff)
> @@ -177,8 +177,6 @@ static int a500_ec_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0unregister_restart_handler(&a500_ec_restart_handler=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id a500_ec_match[] =3D {
> diff --git a/drivers/mfd/arizona-i2c.c b/drivers/mfd/arizona-i2c.c
> index 6d83e6b9a692..bfc7cf56ff2c 100644
> --- a/drivers/mfd/arizona-i2c.c
> +++ b/drivers/mfd/arizona-i2c.c
> @@ -84,13 +84,11 @@ static int arizona_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return arizona_dev_init(a=
rizona);
> =C2=A0}
> =C2=A0
> -static int arizona_i2c_remove(struct i2c_client *i2c)
> +static void arizona_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct arizona *arizona =
=3D dev_get_drvdata(&i2c->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0arizona_dev_exit(arizona)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id arizona_i2c_id[] =3D {
> diff --git a/drivers/mfd/axp20x-i2c.c b/drivers/mfd/axp20x-i2c.c
> index 00ab48018d8d..8fd6727dc30a 100644
> --- a/drivers/mfd/axp20x-i2c.c
> +++ b/drivers/mfd/axp20x-i2c.c
> @@ -50,13 +50,11 @@ static int axp20x_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return axp20x_device_prob=
e(axp20x);
> =C2=A0}
> =C2=A0
> -static int axp20x_i2c_remove(struct i2c_client *i2c)
> +static void axp20x_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct axp20x_dev *axp20x=
 =3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0axp20x_device_remove(axp2=
0x);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_OF
> diff --git a/drivers/mfd/da903x.c b/drivers/mfd/da903x.c
> index a818fbb55988..3f8f6ad3a98c 100644
> --- a/drivers/mfd/da903x.c
> +++ b/drivers/mfd/da903x.c
> @@ -532,12 +532,11 @@ static int da903x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return da903x_add_subdevs=
(chip, pdata);
> =C2=A0}
> =C2=A0
> -static int da903x_remove(struct i2c_client *client)
> +static void da903x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct da903x_chip *chip =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0da903x_remove_subdevs(chi=
p);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver da903x_driver =3D {
> diff --git a/drivers/mfd/da9052-i2c.c b/drivers/mfd/da9052-i2c.c
> index 8de93db35f3a..5a74696c8704 100644
> --- a/drivers/mfd/da9052-i2c.c
> +++ b/drivers/mfd/da9052-i2c.c
> @@ -168,12 +168,11 @@ static int da9052_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return da9052_device_init=
(da9052, id->driver_data);
> =C2=A0}
> =C2=A0
> -static int da9052_i2c_remove(struct i2c_client *client)
> +static void da9052_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct da9052 *da9052 =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0da9052_device_exit(da9052=
);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver da9052_i2c_driver =3D {
> diff --git a/drivers/mfd/da9055-i2c.c b/drivers/mfd/da9055-i2c.c
> index bc60433b68db..276c7d1c509e 100644
> --- a/drivers/mfd/da9055-i2c.c
> +++ b/drivers/mfd/da9055-i2c.c
> @@ -41,13 +41,11 @@ static int da9055_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return da9055_device_init=
(da9055);
> =C2=A0}
> =C2=A0
> -static int da9055_i2c_remove(struct i2c_client *i2c)
> +static void da9055_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct da9055 *da9055 =3D=
 i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0da9055_device_exit(da9055=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/mfd/da9062-core.c b/drivers/mfd/da9062-core.c
> index 2774b2cbaea6..0a80d82c6858 100644
> --- a/drivers/mfd/da9062-core.c
> +++ b/drivers/mfd/da9062-core.c
> @@ -723,14 +723,12 @@ static int da9062_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int da9062_i2c_remove(struct i2c_client *i2c)
> +static void da9062_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct da9062 *chip =3D i=
2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mfd_remove_devices(chip->=
dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_del_irq_chip(i2c->=
irq, chip->regmap_irq);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id da9062_i2c_id[] =3D {
> diff --git a/drivers/mfd/da9150-core.c b/drivers/mfd/da9150-core.c
> index 58009c8cb870..6ae56e46d24e 100644
> --- a/drivers/mfd/da9150-core.c
> +++ b/drivers/mfd/da9150-core.c
> @@ -471,15 +471,13 @@ static int da9150_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int da9150_remove(struct i2c_client *client)
> +static void da9150_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct da9150 *da9150 =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_del_irq_chip(da915=
0->irq, da9150->regmap_irq_data);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mfd_remove_devices(da9150=
->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(da9=
150->core_qif);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void da9150_shutdown(struct i2c_client *client)
> diff --git a/drivers/mfd/dm355evm_msp.c b/drivers/mfd/dm355evm_msp.c
> index 54fb6cbd2aa0..759c59690680 100644
> --- a/drivers/mfd/dm355evm_msp.c
> +++ b/drivers/mfd/dm355evm_msp.c
> @@ -375,11 +375,10 @@ static void dm355evm_power_off(void)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dm355evm_command(MSP_COMM=
AND_POWEROFF);
> =C2=A0}
> =C2=A0
> -static int dm355evm_msp_remove(struct i2c_client *client)
> +static void dm355evm_msp_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_power_off =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0msp430 =3D NULL;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int
> diff --git a/drivers/mfd/ene-kb3930.c b/drivers/mfd/ene-kb3930.c
> index 1b73318d1f1f..3eff98e26bea 100644
> --- a/drivers/mfd/ene-kb3930.c
> +++ b/drivers/mfd/ene-kb3930.c
> @@ -177,7 +177,7 @@ static int kb3930_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int kb3930_remove(struct i2c_client *client)
> +static void kb3930_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct kb3930 *ddata =3D =
i2c_get_clientdata(client);
> =C2=A0
> @@ -187,8 +187,6 @@ static int kb3930_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0unregister_restart_handler(&kb3930_restart_nb);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kb3930_power_off =3D NULL=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id kb3930_dt_ids[] =3D {
> diff --git a/drivers/mfd/gateworks-gsc.c b/drivers/mfd/gateworks-
> gsc.c
> index d87876747b91..9d7d870c44a8 100644
> --- a/drivers/mfd/gateworks-gsc.c
> +++ b/drivers/mfd/gateworks-gsc.c
> @@ -255,11 +255,9 @@ static int gsc_probe(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int gsc_remove(struct i2c_client *client)
> +static void gsc_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &attr_group);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver gsc_driver =3D {
> diff --git a/drivers/mfd/intel_soc_pmic_core.c
> b/drivers/mfd/intel_soc_pmic_core.c
> index 5e8c94e008ed..b824e15f4d22 100644
> --- a/drivers/mfd/intel_soc_pmic_core.c
> +++ b/drivers/mfd/intel_soc_pmic_core.c
> @@ -81,7 +81,7 @@ static int intel_soc_pmic_i2c_probe(struct
> i2c_client *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int intel_soc_pmic_i2c_remove(struct i2c_client *i2c)
> +static void intel_soc_pmic_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct intel_soc_pmic *pm=
ic =3D dev_get_drvdata(&i2c->dev);
> =C2=A0
> @@ -91,8 +91,6 @@ static int intel_soc_pmic_i2c_remove(struct
> i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pwm_remove_table(crc_pwm_=
lookup, ARRAY_SIZE(crc_pwm_lookup));
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mfd_remove_devices(&i2c->=
dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void intel_soc_pmic_shutdown(struct i2c_client *i2c)
> diff --git a/drivers/mfd/iqs62x.c b/drivers/mfd/iqs62x.c
> index 575ab67e243d..1895fce25b06 100644
> --- a/drivers/mfd/iqs62x.c
> +++ b/drivers/mfd/iqs62x.c
> @@ -1008,13 +1008,11 @@ static int iqs62x_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int iqs62x_remove(struct i2c_client *client)
> +static void iqs62x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct iqs62x_core *iqs62=
x =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0wait_for_completion(&iqs6=
2x->fw_done);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused iqs62x_suspend(struct device *dev)
> diff --git a/drivers/mfd/lm3533-core.c b/drivers/mfd/lm3533-core.c
> index 5690768f3e63..be32ffc5af38 100644
> --- a/drivers/mfd/lm3533-core.c
> +++ b/drivers/mfd/lm3533-core.c
> @@ -607,15 +607,13 @@ static int lm3533_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return lm3533_device_init=
(lm3533);
> =C2=A0}
> =C2=A0
> -static int lm3533_i2c_remove(struct i2c_client *i2c)
> +static void lm3533_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3533 *lm3533 =3D=
 i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(&i2c->dev, "%s\n"=
, __func__);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lm3533_device_exit(lm3533=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3533_i2c_ids[] =3D {
> diff --git a/drivers/mfd/lp8788.c b/drivers/mfd/lp8788.c
> index c223d2c6a363..e7c601bca9ef 100644
> --- a/drivers/mfd/lp8788.c
> +++ b/drivers/mfd/lp8788.c
> @@ -199,13 +199,12 @@ static int lp8788_probe(struct i2c_client *cl,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ARRAY_SIZE(lp8788_devs), NULL, 0,
> NULL);
> =C2=A0}
> =C2=A0
> -static int lp8788_remove(struct i2c_client *cl)
> +static void lp8788_remove(struct i2c_client *cl)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp8788 *lp =3D i2c=
_get_clientdata(cl);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mfd_remove_devices(lp->de=
v);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp8788_irq_exit(lp);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lp8788_ids[] =3D {
> diff --git a/drivers/mfd/madera-i2c.c b/drivers/mfd/madera-i2c.c
> index 7df5b9ba5855..915d2f95bad3 100644
> --- a/drivers/mfd/madera-i2c.c
> +++ b/drivers/mfd/madera-i2c.c
> @@ -112,13 +112,11 @@ static int madera_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return madera_dev_init(ma=
dera);
> =C2=A0}
> =C2=A0
> -static int madera_i2c_remove(struct i2c_client *i2c)
> +static void madera_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct madera *madera =3D=
 dev_get_drvdata(&i2c->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0madera_dev_exit(madera);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id madera_i2c_id[] =3D {
> diff --git a/drivers/mfd/max14577.c b/drivers/mfd/max14577.c
> index 6c487fa14e9c..d44ad6f33742 100644
> --- a/drivers/mfd/max14577.c
> +++ b/drivers/mfd/max14577.c
> @@ -463,7 +463,7 @@ static int max14577_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int max14577_i2c_remove(struct i2c_client *i2c)
> +static void max14577_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max14577 *max14577=
 =3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -471,8 +471,6 @@ static int max14577_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_del_irq_chip(max14=
577->irq, max14577->irq_data);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (max14577->dev_type =
=3D=3D MAXIM_DEVICE_TYPE_MAX77836)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0max77836_remove(max14577);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max14577_i2c_id[] =3D {
> diff --git a/drivers/mfd/max77693.c b/drivers/mfd/max77693.c
> index 4e6244e17559..7088cb6f9174 100644
> --- a/drivers/mfd/max77693.c
> +++ b/drivers/mfd/max77693.c
> @@ -294,7 +294,7 @@ static int max77693_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int max77693_i2c_remove(struct i2c_client *i2c)
> +static void max77693_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max77693_dev *max7=
7693 =3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -307,8 +307,6 @@ static int max77693_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(max=
77693->i2c_muic);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(max=
77693->i2c_haptic);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max77693_i2c_id[] =3D {
> diff --git a/drivers/mfd/max8907.c b/drivers/mfd/max8907.c
> index 41f566e6a096..c340080971ce 100644
> --- a/drivers/mfd/max8907.c
> +++ b/drivers/mfd/max8907.c
> @@ -282,7 +282,7 @@ static int max8907_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int max8907_i2c_remove(struct i2c_client *i2c)
> +static void max8907_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max8907 *max8907 =
=3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -293,8 +293,6 @@ static int max8907_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_del_irq_chip(max89=
07->i2c_gen->irq, max8907-
> >irqc_chg);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(max=
8907->i2c_rtc);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_OF
> diff --git a/drivers/mfd/max8925-i2c.c b/drivers/mfd/max8925-i2c.c
> index 114e905bef25..04101da42bd3 100644
> --- a/drivers/mfd/max8925-i2c.c
> +++ b/drivers/mfd/max8925-i2c.c
> @@ -198,14 +198,13 @@ static int max8925_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int max8925_remove(struct i2c_client *client)
> +static void max8925_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max8925_chip *chip=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0max8925_device_exit(chip)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(chi=
p->adc);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(chi=
p->rtc);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/mfd/mc13xxx-i2c.c b/drivers/mfd/mc13xxx-i2c.c
> index fb937f66277e..eb94f3004cf3 100644
> --- a/drivers/mfd/mc13xxx-i2c.c
> +++ b/drivers/mfd/mc13xxx-i2c.c
> @@ -85,10 +85,9 @@ static int mc13xxx_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return mc13xxx_common_ini=
t(&client->dev);
> =C2=A0}
> =C2=A0
> -static int mc13xxx_i2c_remove(struct i2c_client *client)
> +static void mc13xxx_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mc13xxx_common_exit(&clie=
nt->dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver mc13xxx_i2c_driver =3D {
> diff --git a/drivers/mfd/menelaus.c b/drivers/mfd/menelaus.c
> index 07e0ca2e467c..eb08f69001f9 100644
> --- a/drivers/mfd/menelaus.c
> +++ b/drivers/mfd/menelaus.c
> @@ -1222,14 +1222,13 @@ static int menelaus_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int menelaus_remove(struct i2c_client *client)
> +static void menelaus_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct menelaus_chip=C2=
=A0=C2=A0=C2=A0=C2=A0*menelaus =3D
> i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0free_irq(client->irq, men=
elaus);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0flush_work(&menelaus->wor=
k);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0the_menelaus =3D NULL;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id menelaus_id[] =3D {
> diff --git a/drivers/mfd/ntxec.c b/drivers/mfd/ntxec.c
> index b711e73eedcb..e16a7a82a929 100644
> --- a/drivers/mfd/ntxec.c
> +++ b/drivers/mfd/ntxec.c
> @@ -239,15 +239,13 @@ static int ntxec_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return res;
> =C2=A0}
> =C2=A0
> -static int ntxec_remove(struct i2c_client *client)
> +static void ntxec_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (client =3D=3D powerof=
f_restart_client) {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0poweroff_restart_client =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0pm_power_off =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0unregister_restart_handler(&ntxec_restart_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id of_ntxec_match_table[] =3D {
> diff --git a/drivers/mfd/palmas.c b/drivers/mfd/palmas.c
> index f5b3fa973b13..8b7429bd2e3e 100644
> --- a/drivers/mfd/palmas.c
> +++ b/drivers/mfd/palmas.c
> @@ -700,7 +700,7 @@ static int palmas_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int palmas_i2c_remove(struct i2c_client *i2c)
> +static void palmas_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct palmas *palmas =3D=
 i2c_get_clientdata(i2c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -716,8 +716,6 @@ static int palmas_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0pm_power_off =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0palmas_dev =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id palmas_i2c_id[] =3D {
> diff --git a/drivers/mfd/pcf50633-core.c b/drivers/mfd/pcf50633-
> core.c
> index e9c565cf0f54..4ccc2c3e7681 100644
> --- a/drivers/mfd/pcf50633-core.c
> +++ b/drivers/mfd/pcf50633-core.c
> @@ -273,7 +273,7 @@ static int pcf50633_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int pcf50633_remove(struct i2c_client *client)
> +static void pcf50633_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pcf50633 *pcf =3D =
i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -289,8 +289,6 @@ static int pcf50633_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0for (i =3D 0; i < PCF5063=
3_NUM_REGULATORS; i++)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0platform_device_unregister(pcf->regulator_pdev[i]);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id pcf50633_id_table[] =3D {
> diff --git a/drivers/mfd/retu-mfd.c b/drivers/mfd/retu-mfd.c
> index c748fd29a220..3b5acf7ca39c 100644
> --- a/drivers/mfd/retu-mfd.c
> +++ b/drivers/mfd/retu-mfd.c
> @@ -287,7 +287,7 @@ static int retu_probe(struct i2c_client *i2c,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int retu_remove(struct i2c_client *i2c)
> +static void retu_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct retu_dev *rdev =3D=
 i2c_get_clientdata(i2c);
> =C2=A0
> @@ -297,8 +297,6 @@ static int retu_remove(struct i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mfd_remove_devices(rdev->=
dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_del_irq_chip(i2c->=
irq, rdev->irq_data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id retu_id[] =3D {
> diff --git a/drivers/mfd/rk808.c b/drivers/mfd/rk808.c
> index 4142b638e5fa..d5d641efa077 100644
> --- a/drivers/mfd/rk808.c
> +++ b/drivers/mfd/rk808.c
> @@ -778,7 +778,7 @@ static int rk808_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rk808_remove(struct i2c_client *client)
> +static void rk808_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rk808 *rk808 =3D i=
2c_get_clientdata(client);
> =C2=A0
> @@ -792,8 +792,6 @@ static int rk808_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0pm_power_off =3D NULL;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unregister_restart_handle=
r(&rk808_restart_handler);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused rk8xx_suspend(struct device *dev)
> diff --git a/drivers/mfd/rn5t618.c b/drivers/mfd/rn5t618.c
> index 384acb459427..eb8005b4e58d 100644
> --- a/drivers/mfd/rn5t618.c
> +++ b/drivers/mfd/rn5t618.c
> @@ -241,7 +241,7 @@ static int rn5t618_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rn5t618_irq_init(p=
riv);
> =C2=A0}
> =C2=A0
> -static int rn5t618_i2c_remove(struct i2c_client *i2c)
> +static void rn5t618_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (i2c =3D=3D rn5t618_pm=
_power_off) {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0rn5t618_pm_power_off =3D NULL;
> @@ -249,8 +249,6 @@ static int rn5t618_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unregister_restart_handle=
r(&rn5t618_restart_handler);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused rn5t618_i2c_suspend(struct device *dev)
> diff --git a/drivers/mfd/rsmu_i2c.c b/drivers/mfd/rsmu_i2c.c
> index dc001c9791c1..f716ab8039a0 100644
> --- a/drivers/mfd/rsmu_i2c.c
> +++ b/drivers/mfd/rsmu_i2c.c
> @@ -146,13 +146,11 @@ static int rsmu_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rsmu_core_init(rsm=
u);
> =C2=A0}
> =C2=A0
> -static int rsmu_i2c_remove(struct i2c_client *client)
> +static void rsmu_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rsmu_ddata *rsmu =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rsmu_core_exit(rsmu);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id rsmu_i2c_id[] =3D {
> diff --git a/drivers/mfd/rt4831.c b/drivers/mfd/rt4831.c
> index fb3bd788a3eb..c6d34dc2b520 100644
> --- a/drivers/mfd/rt4831.c
> +++ b/drivers/mfd/rt4831.c
> @@ -87,7 +87,7 @@ static int rt4831_probe(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 ARRAY_SIZE(=
rt4831_subdevs), NULL,
> 0, NULL);
> =C2=A0}
> =C2=A0
> -static int rt4831_remove(struct i2c_client *client)
> +static void rt4831_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct regmap *regmap =3D=
 dev_get_regmap(&client->dev, NULL);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> @@ -96,8 +96,6 @@ static int rt4831_remove(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ret =3D regmap_update_bit=
s(regmap, RT4831_REG_ENABLE,
> RT4831_RESET_MASK, RT4831_RESET_MASK);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to disable outputs
> (%pe)\n", ERR_PTR(ret));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id __maybe_unused rt4831_of_match[] =
=3D
> {
> diff --git a/drivers/mfd/si476x-i2c.c b/drivers/mfd/si476x-i2c.c
> index a2635c2d9d1a..8166949b725c 100644
> --- a/drivers/mfd/si476x-i2c.c
> +++ b/drivers/mfd/si476x-i2c.c
> @@ -835,7 +835,7 @@ static int si476x_core_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rval;
> =C2=A0}
> =C2=A0
> -static int si476x_core_remove(struct i2c_client *client)
> +static void si476x_core_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct si476x_core *core =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -851,8 +851,6 @@ static int si476x_core_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (gpio_is_valid(core->g=
pio_reset))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpio_free(core->gpio_reset);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/mfd/stmfx.c b/drivers/mfd/stmfx.c
> index 122f96094410..5dd7d9688459 100644
> --- a/drivers/mfd/stmfx.c
> +++ b/drivers/mfd/stmfx.c
> @@ -467,13 +467,11 @@ static int stmfx_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int stmfx_remove(struct i2c_client *client)
> +static void stmfx_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0stmfx_irq_exit(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0stmfx_chip_exit(client);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/mfd/stmpe-i2c.c b/drivers/mfd/stmpe-i2c.c
> index d3eedf3d607e..4d55494a97c4 100644
> --- a/drivers/mfd/stmpe-i2c.c
> +++ b/drivers/mfd/stmpe-i2c.c
> @@ -91,13 +91,11 @@ stmpe_i2c_probe(struct i2c_client *i2c, const
> struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return stmpe_probe(&i2c_c=
i, partnum);
> =C2=A0}
> =C2=A0
> -static int stmpe_i2c_remove(struct i2c_client *i2c)
> +static void stmpe_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct stmpe *stmpe =3D d=
ev_get_drvdata(&i2c->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0stmpe_remove(stmpe);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id stmpe_i2c_id[] =3D {
> diff --git a/drivers/mfd/tc3589x.c b/drivers/mfd/tc3589x.c
> index 13583cdb93b6..d5d0ec117acb 100644
> --- a/drivers/mfd/tc3589x.c
> +++ b/drivers/mfd/tc3589x.c
> @@ -429,13 +429,11 @@ static int tc3589x_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tc3589x_remove(struct i2c_client *client)
> +static void tc3589x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tc3589x *tc3589x =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mfd_remove_devices(tc3589=
x->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/mfd/tps6105x.c b/drivers/mfd/tps6105x.c
> index c906324d293e..b360568ea675 100644
> --- a/drivers/mfd/tps6105x.c
> +++ b/drivers/mfd/tps6105x.c
> @@ -179,7 +179,7 @@ static int tps6105x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tps6105x_remove(struct i2c_client *client)
> +static void tps6105x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tps6105x *tps6105x=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -189,8 +189,6 @@ static int tps6105x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regmap_update_bits(tps610=
5x->regmap, TPS6105X_REG_0,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0TPS6105X_REG0_MODE_MASK,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0TPS6105X_MODE_SHUTDOWN << TPS6105X_REG0_MODE_SHIFT)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tps6105x_id[] =3D {
> diff --git a/drivers/mfd/tps65010.c b/drivers/mfd/tps65010.c
> index 7e7dbee58ca9..c2afa2e69f42 100644
> --- a/drivers/mfd/tps65010.c
> +++ b/drivers/mfd/tps65010.c
> @@ -501,7 +501,7 @@ static int tps65010_gpio_get(struct gpio_chip
> *chip, unsigned offset)
> =C2=A0
> =C2=A0static struct tps65010 *the_tps;
> =C2=A0
> -static int tps65010_remove(struct i2c_client *client)
> +static void tps65010_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tps65010=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0*tps =3D i2c_get_clientdata(cl=
ient);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tps65010_board=C2=
=A0=C2=A0=C2=A0*board =3D dev_get_platdata(&client-
> >dev);
> @@ -517,7 +517,6 @@ static int tps65010_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_delayed_work_sync(=
&tps->work);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0debugfs_remove(tps->file)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0the_tps =3D NULL;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int tps65010_probe(struct i2c_client *client,
> diff --git a/drivers/mfd/tps65086.c b/drivers/mfd/tps65086.c
> index 3bd5728844a0..eb5afbeb0e91 100644
> --- a/drivers/mfd/tps65086.c
> +++ b/drivers/mfd/tps65086.c
> @@ -119,14 +119,12 @@ static int tps65086_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tps65086_remove(struct i2c_client *client)
> +static void tps65086_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tps65086 *tps =3D =
i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (tps->irq > 0)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0regmap_del_irq_chip(tps->irq, tps->irq_data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tps65086_id_table[] =3D {
> diff --git a/drivers/mfd/tps65217.c b/drivers/mfd/tps65217.c
> index 8027b0a9e14f..a7200ddd85e6 100644
> --- a/drivers/mfd/tps65217.c
> +++ b/drivers/mfd/tps65217.c
> @@ -382,7 +382,7 @@ static int tps65217_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tps65217_remove(struct i2c_client *client)
> +static void tps65217_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tps65217 *tps =3D =
i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unsigned int virq;
> @@ -396,8 +396,6 @@ static int tps65217_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0irq_domain_remove(tps->ir=
q_domain);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tps->irq_domain =3D NULL;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tps65217_id_table[] =3D {
> diff --git a/drivers/mfd/tps6586x.c b/drivers/mfd/tps6586x.c
> index c9303d3d6602..fb340da64bbc 100644
> --- a/drivers/mfd/tps6586x.c
> +++ b/drivers/mfd/tps6586x.c
> @@ -579,7 +579,7 @@ static int tps6586x_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tps6586x_i2c_remove(struct i2c_client *client)
> +static void tps6586x_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tps6586x *tps6586x=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -587,7 +587,6 @@ static int tps6586x_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mfd_remove_devices(tps658=
6x->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (client->irq)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(client->irq, tps6586x);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused tps6586x_i2c_suspend(struct device *dev)
> diff --git a/drivers/mfd/tps65912-i2c.c b/drivers/mfd/tps65912-i2c.c
> index 06eb2784d322..cbbac1567eaa 100644
> --- a/drivers/mfd/tps65912-i2c.c
> +++ b/drivers/mfd/tps65912-i2c.c
> @@ -51,13 +51,11 @@ static int tps65912_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return tps65912_device_in=
it(tps);
> =C2=A0}
> =C2=A0
> -static int tps65912_i2c_remove(struct i2c_client *client)
> +static void tps65912_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tps65912 *tps =3D =
i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tps65912_device_exit(tps)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tps65912_i2c_id_table[] =3D {
> diff --git a/drivers/mfd/twl-core.c b/drivers/mfd/twl-core.c
> index bd6659cf3bc0..89a96db15b33 100644
> --- a/drivers/mfd/twl-core.c
> +++ b/drivers/mfd/twl-core.c
> @@ -1033,7 +1033,7 @@ static void clocks_init(struct device *dev,
> =C2=A0/*-----------------------------------------------------------------=
-
> ----*/
> =C2=A0
> =C2=A0
> -static int twl_remove(struct i2c_client *client)
> +static void twl_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unsigned i, num_slaves;
> =C2=A0
> @@ -1051,7 +1051,6 @@ static int twl_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0twl->client =3D NULL;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0twl_priv->ready =3D false=
;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct of_dev_auxdata twl_auxdata_lookup[] =3D {
> diff --git a/drivers/mfd/twl6040.c b/drivers/mfd/twl6040.c
> index b9c6d94b4002..f429b8f00db6 100644
> --- a/drivers/mfd/twl6040.c
> +++ b/drivers/mfd/twl6040.c
> @@ -808,7 +808,7 @@ static int twl6040_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int twl6040_remove(struct i2c_client *client)
> +static void twl6040_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct twl6040 *twl6040 =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -820,8 +820,6 @@ static int twl6040_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mfd_remove_devices(&clien=
t->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(TW=
L6040_NUM_SUPPLIES, twl6040-
> >supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id twl6040_i2c_id[] =3D {
> diff --git a/drivers/mfd/wm8994-core.c b/drivers/mfd/wm8994-core.c
> index 7b1d270722ba..7e88f5b0abe6 100644
> --- a/drivers/mfd/wm8994-core.c
> +++ b/drivers/mfd/wm8994-core.c
> @@ -657,13 +657,11 @@ static int wm8994_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return wm8994_device_init=
(wm8994, i2c->irq);
> =C2=A0}
> =C2=A0
> -static int wm8994_i2c_remove(struct i2c_client *i2c)
> +static void wm8994_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wm8994 *wm8994 =3D=
 i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0wm8994_device_exit(wm8994=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm8994_i2c_id[] =3D {
> diff --git a/drivers/misc/ad525x_dpot-i2c.c
> b/drivers/misc/ad525x_dpot-i2c.c
> index 0ee0c6d808c3..28ffb4377d98 100644
> --- a/drivers/misc/ad525x_dpot-i2c.c
> +++ b/drivers/misc/ad525x_dpot-i2c.c
> @@ -67,10 +67,9 @@ static int ad_dpot_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ad_dpot_probe(&cli=
ent->dev, &bdata, id->driver_data,
> id->name);
> =C2=A0}
> =C2=A0
> -static int ad_dpot_i2c_remove(struct i2c_client *client)
> +static void ad_dpot_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ad_dpot_remove(&client->d=
ev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ad_dpot_id[] =3D {
> diff --git a/drivers/misc/apds9802als.c b/drivers/misc/apds9802als.c
> index 6fff44b952bd..a32431f4b370 100644
> --- a/drivers/misc/apds9802als.c
> +++ b/drivers/misc/apds9802als.c
> @@ -242,7 +242,7 @@ static int apds9802als_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return res;
> =C2=A0}
> =C2=A0
> -static int apds9802als_remove(struct i2c_client *client)
> +static void apds9802als_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct als_data *data =3D=
 i2c_get_clientdata(client);
> =C2=A0
> @@ -256,7 +256,6 @@ static int apds9802als_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_put_noidle(&cl=
ient->dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(data);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/misc/apds990x.c b/drivers/misc/apds990x.c
> index 45f5b997a0e1..e2100cc42ce8 100644
> --- a/drivers/misc/apds990x.c
> +++ b/drivers/misc/apds990x.c
> @@ -1185,7 +1185,7 @@ static int apds990x_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int apds990x_remove(struct i2c_client *client)
> +static void apds990x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct apds990x_chip *chi=
p =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1205,7 +1205,6 @@ static int apds990x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_free(ARRAY=
_SIZE(chip->regs), chip->regs);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(chip);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/misc/bh1770glc.c b/drivers/misc/bh1770glc.c
> index 0581bb9cef2e..d0dfa674414c 100644
> --- a/drivers/misc/bh1770glc.c
> +++ b/drivers/misc/bh1770glc.c
> @@ -1280,7 +1280,7 @@ static int bh1770_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int bh1770_remove(struct i2c_client *client)
> +static void bh1770_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bh1770_chip *chip =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1299,8 +1299,6 @@ static int bh1770_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&client->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/misc/ds1682.c b/drivers/misc/ds1682.c
> index 42f316c2d719..0698ddc5f4d5 100644
> --- a/drivers/misc/ds1682.c
> +++ b/drivers/misc/ds1682.c
> @@ -228,11 +228,10 @@ static int ds1682_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rc;
> =C2=A0}
> =C2=A0
> -static int ds1682_remove(struct i2c_client *client)
> +static void ds1682_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_bin_file(&cl=
ient->dev.kobj,
> &ds1682_eeprom_attr);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &ds1682_group);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ds1682_id[] =3D {
> diff --git a/drivers/misc/eeprom/at24.c b/drivers/misc/eeprom/at24.c
> index 633e1cf08d6e..938c4f41b98c 100644
> --- a/drivers/misc/eeprom/at24.c
> +++ b/drivers/misc/eeprom/at24.c
> @@ -791,7 +791,7 @@ static int at24_probe(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int at24_remove(struct i2c_client *client)
> +static void at24_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct at24_data *at24 =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -801,8 +801,6 @@ static int at24_remove(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0reg=
ulator_disable(at24->vcc_reg);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(&client->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused at24_suspend(struct device *dev)
> diff --git a/drivers/misc/eeprom/ee1004.c
> b/drivers/misc/eeprom/ee1004.c
> index 9fbfe784d710..c8c6deb7ed89 100644
> --- a/drivers/misc/eeprom/ee1004.c
> +++ b/drivers/misc/eeprom/ee1004.c
> @@ -219,14 +219,12 @@ static int ee1004_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int ee1004_remove(struct i2c_client *client)
> +static void ee1004_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Remove page select cli=
ents if this is the last device */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&ee1004_bus_lo=
ck);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ee1004_cleanup(EE1004_NUM=
_PAGES);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&ee1004_bus_=
lock);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*-----------------------------------------------------------------=
-
> -------*/
> diff --git a/drivers/misc/eeprom/eeprom.c
> b/drivers/misc/eeprom/eeprom.c
> index 34fa385dfd4b..4a9445fea93d 100644
> --- a/drivers/misc/eeprom/eeprom.c
> +++ b/drivers/misc/eeprom/eeprom.c
> @@ -183,11 +183,9 @@ static int eeprom_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return sysfs_create_bin_f=
ile(&client->dev.kobj,
> &eeprom_attr);
> =C2=A0}
> =C2=A0
> -static int eeprom_remove(struct i2c_client *client)
> +static void eeprom_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_bin_file(&cl=
ient->dev.kobj, &eeprom_attr);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id eeprom_id[] =3D {
> diff --git a/drivers/misc/eeprom/idt_89hpesx.c
> b/drivers/misc/eeprom/idt_89hpesx.c
> index b0cff4b152da..0c23e909bc3e 100644
> --- a/drivers/misc/eeprom/idt_89hpesx.c
> +++ b/drivers/misc/eeprom/idt_89hpesx.c
> @@ -1401,7 +1401,7 @@ static int idt_probe(struct i2c_client *client,
> const struct i2c_device_id *id)
> =C2=A0/*
> =C2=A0 * idt_remove() - IDT 89HPESx driver remove() callback method
> =C2=A0 */
> -static int idt_remove(struct i2c_client *client)
> +static void idt_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct idt_89hpesx_dev *p=
dev =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1413,8 +1413,6 @@ static int idt_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Discard driver data st=
ructure */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0idt_free_pdev(pdev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/misc/eeprom/max6875.c
> b/drivers/misc/eeprom/max6875.c
> index 9da81f6d4a1c..6bd4f4339af4 100644
> --- a/drivers/misc/eeprom/max6875.c
> +++ b/drivers/misc/eeprom/max6875.c
> @@ -173,7 +173,7 @@ static int max6875_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int max6875_remove(struct i2c_client *client)
> +static void max6875_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max6875_data *data=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -181,8 +181,6 @@ static int max6875_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_bin_file(&cl=
ient->dev.kobj, &user_eeprom_attr);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(data);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max6875_id[] =3D {
> diff --git a/drivers/misc/hmc6352.c b/drivers/misc/hmc6352.c
> index 572a2ff10f00..42b9adef28a3 100644
> --- a/drivers/misc/hmc6352.c
> +++ b/drivers/misc/hmc6352.c
> @@ -116,10 +116,9 @@ static int hmc6352_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int hmc6352_remove(struct i2c_client *client)
> +static void hmc6352_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &m_compass_gr);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id hmc6352_id[] =3D {
> diff --git a/drivers/misc/ics932s401.c b/drivers/misc/ics932s401.c
> index 0f9ea75b0b18..2c4bb6d6e1a0 100644
> --- a/drivers/misc/ics932s401.c
> +++ b/drivers/misc/ics932s401.c
> @@ -93,7 +93,7 @@ static int ics932s401_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 co=
nst struct i2c_device_id *id);
> =C2=A0static int ics932s401_detect(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 struct i2c_board_info *info);
> -static int ics932s401_remove(struct i2c_client *client);
> +static void ics932s401_remove(struct i2c_client *client);
> =C2=A0
> =C2=A0static const struct i2c_device_id ics932s401_id[] =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0{ "ics932s401", 0 },
> @@ -460,13 +460,12 @@ static int ics932s401_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int ics932s401_remove(struct i2c_client *client)
> +static void ics932s401_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ics932s401_data *d=
ata =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &data->attrs);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(data);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0module_i2c_driver(ics932s401_driver);
> diff --git a/drivers/misc/isl29003.c b/drivers/misc/isl29003.c
> index 703d20e83ebd..8ab61be79c76 100644
> --- a/drivers/misc/isl29003.c
> +++ b/drivers/misc/isl29003.c
> @@ -410,12 +410,11 @@ static int isl29003_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int isl29003_remove(struct i2c_client *client)
> +static void isl29003_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &isl29003_attr_group);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0isl29003_set_power_state(=
client, 0);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(i2c_get_clientdata(=
client));
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/misc/isl29020.c b/drivers/misc/isl29020.c
> index fc5ff2805b94..c6f2a94f501a 100644
> --- a/drivers/misc/isl29020.c
> +++ b/drivers/misc/isl29020.c
> @@ -171,11 +171,10 @@ static int=C2=A0 isl29020_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return res;
> =C2=A0}
> =C2=A0
> -static int isl29020_remove(struct i2c_client *client)
> +static void isl29020_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &m_als_gr);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id isl29020_id[] =3D {
> diff --git a/drivers/misc/lis3lv02d/lis3lv02d_i2c.c
> b/drivers/misc/lis3lv02d/lis3lv02d_i2c.c
> index 52555d2e824b..d7daa01fe7ca 100644
> --- a/drivers/misc/lis3lv02d/lis3lv02d_i2c.c
> +++ b/drivers/misc/lis3lv02d/lis3lv02d_i2c.c
> @@ -177,7 +177,7 @@ static int lis3lv02d_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lis3lv02d_i2c_remove(struct i2c_client *client)
> +static void lis3lv02d_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lis3lv02d *lis3 =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lis3lv02d_platform=
_data *pdata =3D client-
> >dev.platform_data;
> @@ -190,7 +190,6 @@ static int lis3lv02d_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_free(ARRAY=
_SIZE(lis3->regulators),
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 lis3_dev.regulators);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/misc/tsl2550.c b/drivers/misc/tsl2550.c
> index 6d71865c8042..1652fb9b3856 100644
> --- a/drivers/misc/tsl2550.c
> +++ b/drivers/misc/tsl2550.c
> @@ -389,7 +389,7 @@ static int tsl2550_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int tsl2550_remove(struct i2c_client *client)
> +static void tsl2550_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&clien=
t->dev.kobj, &tsl2550_attr_group);
> =C2=A0
> @@ -397,8 +397,6 @@ static int tsl2550_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tsl2550_set_power_state(c=
lient, 0);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(i2c_get_clientdata(=
client));
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/mtd/maps/pismo.c b/drivers/mtd/maps/pismo.c
> index 946ba80f9758..5fcefcd0baca 100644
> --- a/drivers/mtd/maps/pismo.c
> +++ b/drivers/mtd/maps/pismo.c
> @@ -195,7 +195,7 @@ static void pismo_add_one(struct pismo_data
> *pismo, int i,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0}
> =C2=A0
> -static int pismo_remove(struct i2c_client *client)
> +static void pismo_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pismo_data *pismo =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int i;
> @@ -204,8 +204,6 @@ static int pismo_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0platform_device_unregister(pismo->dev[i]);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(pismo);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int pismo_probe(struct i2c_client *client,
> diff --git a/drivers/net/dsa/lan9303_i2c.c
> b/drivers/net/dsa/lan9303_i2c.c
> index 8ca4713310fa..b25e91b26d99 100644
> --- a/drivers/net/dsa/lan9303_i2c.c
> +++ b/drivers/net/dsa/lan9303_i2c.c
> @@ -65,18 +65,16 @@ static int lan9303_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lan9303_i2c_remove(struct i2c_client *client)
> +static void lan9303_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lan9303_i2c *sw_de=
v =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!sw_dev)
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lan9303_remove(&sw_dev->c=
hip);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_set_clientdata(client=
, NULL);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void lan9303_i2c_shutdown(struct i2c_client *client)
> diff --git a/drivers/net/dsa/microchip/ksz9477_i2c.c
> b/drivers/net/dsa/microchip/ksz9477_i2c.c
> index faa3163c86b0..ef9d3cc4b15a 100644
> --- a/drivers/net/dsa/microchip/ksz9477_i2c.c
> +++ b/drivers/net/dsa/microchip/ksz9477_i2c.c
> @@ -52,7 +52,7 @@ static int ksz9477_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ksz9477_i2c_remove(struct i2c_client *i2c)
> +static void ksz9477_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ksz_device *dev =
=3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -60,8 +60,6 @@ static int ksz9477_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0ksz_switch_remove(dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_set_clientdata(i2c, N=
ULL);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void ksz9477_i2c_shutdown(struct i2c_client *i2c)
> diff --git a/drivers/net/dsa/xrs700x/xrs700x_i2c.c
> b/drivers/net/dsa/xrs700x/xrs700x_i2c.c
> index 6deae388a0d6..bbaf5a3fbf00 100644
> --- a/drivers/net/dsa/xrs700x/xrs700x_i2c.c
> +++ b/drivers/net/dsa/xrs700x/xrs700x_i2c.c
> @@ -105,18 +105,16 @@ static int xrs700x_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int xrs700x_i2c_remove(struct i2c_client *i2c)
> +static void xrs700x_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct xrs700x *priv =3D =
i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!priv)
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0xrs700x_switch_remove(pri=
v);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_set_clientdata(i2c, N=
ULL);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void xrs700x_i2c_shutdown(struct i2c_client *i2c)
> diff --git a/drivers/net/ethernet/mellanox/mlxsw/i2c.c
> b/drivers/net/ethernet/mellanox/mlxsw/i2c.c
> index ce843ea91464..50b7121a5e3c 100644
> --- a/drivers/net/ethernet/mellanox/mlxsw/i2c.c
> +++ b/drivers/net/ethernet/mellanox/mlxsw/i2c.c
> @@ -656,14 +656,12 @@ static int mlxsw_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int mlxsw_i2c_remove(struct i2c_client *client)
> +static void mlxsw_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mlxsw_i2c *mlxsw_i=
2c =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mlxsw_core_bus_device_unr=
egister(mlxsw_i2c->core, false);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&mlxsw_i2c-=
>cmd.lock);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0int mlxsw_i2c_driver_register(struct i2c_driver *i2c_driver)
> diff --git a/drivers/net/mctp/mctp-i2c.c b/drivers/net/mctp/mctp-
> i2c.c
> index 53846c6b56ca..670ad9b306fe 100644
> --- a/drivers/net/mctp/mctp-i2c.c
> +++ b/drivers/net/mctp/mctp-i2c.c
> @@ -986,7 +986,7 @@ static int mctp_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rc;
> =C2=A0}
> =C2=A0
> -static int mctp_i2c_remove(struct i2c_client *client)
> +static void mctp_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mctp_i2c_client *m=
cli =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mctp_i2c_dev *mide=
v =3D NULL, *tmp =3D NULL;
> @@ -1000,7 +1000,6 @@ static int mctp_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mctp_i2c_free_client(mcli=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&driver_clie=
nts_lock);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Callers ignore return =
code */
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/* We look for a 'mctp-controller' property on I2C busses as they
> are
> diff --git a/drivers/nfc/fdp/i2c.c b/drivers/nfc/fdp/i2c.c
> index 28a9e1eb9bcf..2d53e0f88d2f 100644
> --- a/drivers/nfc/fdp/i2c.c
> +++ b/drivers/nfc/fdp/i2c.c
> @@ -336,14 +336,12 @@ static int fdp_nci_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int fdp_nci_i2c_remove(struct i2c_client *client)
> +static void fdp_nci_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct fdp_i2c_phy *phy =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fdp_nci_remove(phy->ndev)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fdp_nci_i2c_disable(phy);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct acpi_device_id fdp_nci_i2c_acpi_match[] =3D {
> diff --git a/drivers/nfc/microread/i2c.c
> b/drivers/nfc/microread/i2c.c
> index 067295124eb9..5eaa18f81355 100644
> --- a/drivers/nfc/microread/i2c.c
> +++ b/drivers/nfc/microread/i2c.c
> @@ -268,15 +268,13 @@ static int microread_i2c_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return r;
> =C2=A0}
> =C2=A0
> -static int microread_i2c_remove(struct i2c_client *client)
> +static void microread_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct microread_i2c_phy =
*phy =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0microread_remove(phy->hde=
v);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0free_irq(client->irq, phy=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id microread_i2c_id[] =3D {
> diff --git a/drivers/nfc/nfcmrvl/i2c.c b/drivers/nfc/nfcmrvl/i2c.c
> index ceef81d93ac9..61f1e2019c0a 100644
> --- a/drivers/nfc/nfcmrvl/i2c.c
> +++ b/drivers/nfc/nfcmrvl/i2c.c
> @@ -231,13 +231,11 @@ static int nfcmrvl_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int nfcmrvl_i2c_remove(struct i2c_client *client)
> +static void nfcmrvl_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct nfcmrvl_i2c_drv_da=
ta *drv_data =3D
> i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0nfcmrvl_nci_unregister_de=
v(drv_data->priv);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/drivers/nfc/nxp-nci/i2c.c b/drivers/nfc/nxp-nci/i2c.c
> index 7e451c10985d..82a2e2fb1472 100644
> --- a/drivers/nfc/nxp-nci/i2c.c
> +++ b/drivers/nfc/nxp-nci/i2c.c
> @@ -307,14 +307,12 @@ static int nxp_nci_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return r;
> =C2=A0}
> =C2=A0
> -static int nxp_nci_i2c_remove(struct i2c_client *client)
> +static void nxp_nci_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct nxp_nci_i2c_phy *p=
hy =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0nxp_nci_remove(phy->ndev)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0free_irq(client->irq, phy=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id nxp_nci_i2c_id_table[] =3D {
> diff --git a/drivers/nfc/pn533/i2c.c b/drivers/nfc/pn533/i2c.c
> index 673eb5e9b887..ddf3db286bad 100644
> --- a/drivers/nfc/pn533/i2c.c
> +++ b/drivers/nfc/pn533/i2c.c
> @@ -227,7 +227,7 @@ static int pn533_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return r;
> =C2=A0}
> =C2=A0
> -static int pn533_i2c_remove(struct i2c_client *client)
> +static void pn533_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pn533_i2c_phy *phy=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -235,8 +235,6 @@ static int pn533_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pn53x_unregister_nfc(phy-=
>priv);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pn53x_common_clean(phy->p=
riv);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id of_pn533_i2c_match[] __maybe_unuse=
d
> =3D {
> diff --git a/drivers/nfc/pn544/i2c.c b/drivers/nfc/pn544/i2c.c
> index 62a0f1a010cb..9e754abcfa2a 100644
> --- a/drivers/nfc/pn544/i2c.c
> +++ b/drivers/nfc/pn544/i2c.c
> @@ -928,7 +928,7 @@ static int pn544_hci_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int pn544_hci_i2c_remove(struct i2c_client *client)
> +static void pn544_hci_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pn544_i2c_phy *phy=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -940,8 +940,6 @@ static int pn544_hci_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (phy->powered)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0pn544_hci_i2c_disable(phy);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id of_pn544_i2c_match[] __maybe_unuse=
d
> =3D {
> diff --git a/drivers/nfc/s3fwrn5/i2c.c b/drivers/nfc/s3fwrn5/i2c.c
> index 4d1cf1bb55b0..f824dc7099ce 100644
> --- a/drivers/nfc/s3fwrn5/i2c.c
> +++ b/drivers/nfc/s3fwrn5/i2c.c
> @@ -246,14 +246,12 @@ static int s3fwrn5_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int s3fwrn5_i2c_remove(struct i2c_client *client)
> +static void s3fwrn5_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct s3fwrn5_i2c_phy *p=
hy =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0s3fwrn5_remove(phy->commo=
n.ndev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0clk_disable_unprepare(phy=
->clk);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id s3fwrn5_i2c_id_table[] =3D {
> diff --git a/drivers/nfc/st-nci/i2c.c b/drivers/nfc/st-nci/i2c.c
> index cbd968f013c7..89fa24d71bef 100644
> --- a/drivers/nfc/st-nci/i2c.c
> +++ b/drivers/nfc/st-nci/i2c.c
> @@ -250,13 +250,11 @@ static int st_nci_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return r;
> =C2=A0}
> =C2=A0
> -static int st_nci_i2c_remove(struct i2c_client *client)
> +static void st_nci_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct st_nci_i2c_phy *ph=
y =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ndlc_remove(phy->ndlc);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id st_nci_i2c_id_table[] =3D {
> diff --git a/drivers/nfc/st21nfca/i2c.c b/drivers/nfc/st21nfca/i2c.c
> index 42dc0e5eb161..76b55986bcf8 100644
> --- a/drivers/nfc/st21nfca/i2c.c
> +++ b/drivers/nfc/st21nfca/i2c.c
> @@ -562,7 +562,7 @@ static int st21nfca_hci_i2c_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return r;
> =C2=A0}
> =C2=A0
> -static int st21nfca_hci_i2c_remove(struct i2c_client *client)
> +static void st21nfca_hci_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct st21nfca_i2c_phy *=
phy =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -571,8 +571,6 @@ static int st21nfca_hci_i2c_remove(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (phy->powered)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0st21nfca_hci_i2c_disable(phy);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree_skb(phy->pending_sk=
b);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id st21nfca_hci_i2c_id_table[] =3D {
> diff --git a/drivers/of/unittest.c b/drivers/of/unittest.c
> index 7f6bba18c515..e0b98ce9c5e8 100644
> --- a/drivers/of/unittest.c
> +++ b/drivers/of/unittest.c
> @@ -2525,13 +2525,12 @@ static int unittest_i2c_dev_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0};
> =C2=A0
> -static int unittest_i2c_dev_remove(struct i2c_client *client)
> +static void unittest_i2c_dev_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &c=
lient->dev;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device_node *np =
=3D client->dev.of_node;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(dev, "%s for node=
 @%pOF\n", __func__, np);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id unittest_i2c_dev_id[] =3D {
> @@ -2602,7 +2601,7 @@ static int unittest_i2c_mux_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0};
> =C2=A0
> -static int unittest_i2c_mux_remove(struct i2c_client *client)
> +static void unittest_i2c_mux_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &c=
lient->dev;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device_node *np =
=3D client->dev.of_node;
> @@ -2610,7 +2609,6 @@ static int unittest_i2c_mux_remove(struct
> i2c_client *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_dbg(dev, "%s for node=
 @%pOF\n", __func__, np);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_mux_del_adapters(muxc=
);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id unittest_i2c_mux_id[] =3D {
> diff --git a/drivers/platform/chrome/cros_ec_i2c.c
> b/drivers/platform/chrome/cros_ec_i2c.c
> index 9f5b95763173..b6823c654c3f 100644
> --- a/drivers/platform/chrome/cros_ec_i2c.c
> +++ b/drivers/platform/chrome/cros_ec_i2c.c
> @@ -317,13 +317,11 @@ static int cros_ec_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int cros_ec_i2c_remove(struct i2c_client *client)
> +static void cros_ec_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cros_ec_device *ec=
_dev =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cros_ec_unregister(ec_dev=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/platform/surface/surface3_power.c
> b/drivers/platform/surface/surface3_power.c
> index 444ec81ba02d..3b20dddeb815 100644
> --- a/drivers/platform/surface/surface3_power.c
> +++ b/drivers/platform/surface/surface3_power.c
> @@ -554,7 +554,7 @@ static int mshw0011_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return error;
> =C2=A0}
> =C2=A0
> -static int mshw0011_remove(struct i2c_client *client)
> +static void mshw0011_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mshw0011_data *cda=
ta =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -564,8 +564,6 @@ static int mshw0011_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0kthread_stop(cdata->poll_task);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(cda=
ta->bat0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct acpi_device_id mshw0011_acpi_match[] =3D {
> diff --git a/drivers/platform/x86/asus-tf103c-dock.c
> b/drivers/platform/x86/asus-tf103c-dock.c
> index 6fd0c9fea82d..62310e06282b 100644
> --- a/drivers/platform/x86/asus-tf103c-dock.c
> +++ b/drivers/platform/x86/asus-tf103c-dock.c
> @@ -878,14 +878,12 @@ static int tf103c_dock_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tf103c_dock_remove(struct i2c_client *client)
> +static void tf103c_dock_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tf103c_dock_data *=
dock =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tf103c_dock_stop_hpd(dock=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tf103c_dock_disable(dock)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused tf103c_dock_suspend(struct device *dev)
> diff --git a/drivers/platform/x86/intel/int3472/tps68470.c
> b/drivers/platform/x86/intel/int3472/tps68470.c
> index 22f61b47f9e5..5dd81bb05255 100644
> --- a/drivers/platform/x86/intel/int3472/tps68470.c
> +++ b/drivers/platform/x86/intel/int3472/tps68470.c
> @@ -178,15 +178,13 @@ static int skl_int3472_tps68470_probe(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int skl_int3472_tps68470_remove(struct i2c_client *client)
> +static void skl_int3472_tps68470_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0const struct int3472_tps6=
8470_board_data *board_data;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0board_data =3D
> int3472_tps68470_get_board_data(dev_name(&client->dev));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (board_data)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpiod_remove_lookup_table(board_data-
> >tps68470_gpio_lookup_table);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct acpi_device_id int3472_device_id[] =3D {
> diff --git a/drivers/power/supply/bq2415x_charger.c
> b/drivers/power/supply/bq2415x_charger.c
> index 5724001e66b9..6b99e1c675b8 100644
> --- a/drivers/power/supply/bq2415x_charger.c
> +++ b/drivers/power/supply/bq2415x_charger.c
> @@ -1696,7 +1696,7 @@ static int bq2415x_probe(struct i2c_client
> *client,
> =C2=A0
> =C2=A0/* main bq2415x remove function */
> =C2=A0
> -static int bq2415x_remove(struct i2c_client *client)
> +static void bq2415x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bq2415x_device *bq=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1715,8 +1715,6 @@ static int bq2415x_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0dev_info(bq->dev, "driver=
 unregistered\n");
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(bq->name);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id bq2415x_i2c_id_table[] =3D {
> diff --git a/drivers/power/supply/bq24190_charger.c
> b/drivers/power/supply/bq24190_charger.c
> index 27f5c7648617..2274679c5ddd 100644
> --- a/drivers/power/supply/bq24190_charger.c
> +++ b/drivers/power/supply/bq24190_charger.c
> @@ -1901,7 +1901,7 @@ static int bq24190_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int bq24190_remove(struct i2c_client *client)
> +static void bq24190_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bq24190_dev_info *=
bdi =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int error;
> @@ -1918,8 +1918,6 @@ static int bq24190_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_put_sync(bdi->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_dont_use_autos=
uspend(bdi->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(bdi->d=
ev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void bq24190_shutdown(struct i2c_client *client)
> diff --git a/drivers/power/supply/bq24257_charger.c
> b/drivers/power/supply/bq24257_charger.c
> index 96cb3290bcaa..dafb64b32cef 100644
> --- a/drivers/power/supply/bq24257_charger.c
> +++ b/drivers/power/supply/bq24257_charger.c
> @@ -1077,7 +1077,7 @@ static int bq24257_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int bq24257_remove(struct i2c_client *client)
> +static void bq24257_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bq24257_device *bq=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1085,8 +1085,6 @@ static int bq24257_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0cancel_delayed_work_sync(&bq->iilimit_setup_work);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0bq24257_field_write(bq, F=
_RESET, 1); /* reset to defaults */
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/power/supply/bq25890_charger.c
> b/drivers/power/supply/bq25890_charger.c
> index 852a6fec4339..06ea7399d151 100644
> --- a/drivers/power/supply/bq25890_charger.c
> +++ b/drivers/power/supply/bq25890_charger.c
> @@ -1258,7 +1258,7 @@ static int bq25890_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int bq25890_remove(struct i2c_client *client)
> +static void bq25890_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bq25890_device *bq=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1269,8 +1269,6 @@ static int bq25890_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0/* reset all registers to default values */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0bq25890_chip_reset(bq);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void bq25890_shutdown(struct i2c_client *client)
> diff --git a/drivers/power/supply/bq27xxx_battery_i2c.c
> b/drivers/power/supply/bq27xxx_battery_i2c.c
> index cf38cbfe13e9..94b00bb89c17 100644
> --- a/drivers/power/supply/bq27xxx_battery_i2c.c
> +++ b/drivers/power/supply/bq27xxx_battery_i2c.c
> @@ -205,7 +205,7 @@ static int bq27xxx_battery_i2c_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int bq27xxx_battery_i2c_remove(struct i2c_client *client)
> +static void bq27xxx_battery_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct bq27xxx_device_inf=
o *di =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -214,8 +214,6 @@ static int bq27xxx_battery_i2c_remove(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&battery_mutex=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0idr_remove(&battery_id, d=
i->id);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&battery_mut=
ex);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id bq27xxx_i2c_id_table[] =3D {
> diff --git a/drivers/power/supply/cw2015_battery.c
> b/drivers/power/supply/cw2015_battery.c
> index 728e2a6cc9c3..81e17ad80163 100644
> --- a/drivers/power/supply/cw2015_battery.c
> +++ b/drivers/power/supply/cw2015_battery.c
> @@ -725,13 +725,12 @@ static int __maybe_unused cw_bat_resume(struct
> device *dev)
> =C2=A0
> =C2=A0static SIMPLE_DEV_PM_OPS(cw_bat_pm_ops, cw_bat_suspend,
> cw_bat_resume);
> =C2=A0
> -static int cw_bat_remove(struct i2c_client *client)
> +static void cw_bat_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cw_battery *cw_bat=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_delayed_work_sync(=
&cw_bat->battery_delay_work);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0power_supply_put_battery_=
info(cw_bat->rk_bat, cw_bat-
> >battery);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cw_bat_id_table[] =3D {
> diff --git a/drivers/power/supply/ds2782_battery.c
> b/drivers/power/supply/ds2782_battery.c
> index 9ae273fde7a2..d78cd05402f6 100644
> --- a/drivers/power/supply/ds2782_battery.c
> +++ b/drivers/power/supply/ds2782_battery.c
> @@ -312,7 +312,7 @@ static void ds278x_power_supply_init(struct
> power_supply_desc *battery)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0battery->external_power_c=
hanged=C2=A0=3D NULL;
> =C2=A0}
> =C2=A0
> -static int ds278x_battery_remove(struct i2c_client *client)
> +static void ds278x_battery_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ds278x_info *info =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int id =3D info->id;
> @@ -325,8 +325,6 @@ static int ds278x_battery_remove(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_lock(&battery_lock)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0idr_remove(&battery_id, i=
d);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&battery_loc=
k);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/power/supply/lp8727_charger.c
> b/drivers/power/supply/lp8727_charger.c
> index 9ee54e397754..384a374b52c1 100644
> --- a/drivers/power/supply/lp8727_charger.c
> +++ b/drivers/power/supply/lp8727_charger.c
> @@ -590,13 +590,12 @@ static int lp8727_probe(struct i2c_client *cl,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lp8727_remove(struct i2c_client *cl)
> +static void lp8727_remove(struct i2c_client *cl)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp8727_chg *pchg =
=3D i2c_get_clientdata(cl);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp8727_release_irq(pchg);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp8727_unregister_psy(pch=
g);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id lp8727_dt_ids[] =3D {
> diff --git a/drivers/power/supply/rt5033_battery.c
> b/drivers/power/supply/rt5033_battery.c
> index 7a23c70f4879..736dec608ff6 100644
> --- a/drivers/power/supply/rt5033_battery.c
> +++ b/drivers/power/supply/rt5033_battery.c
> @@ -149,13 +149,11 @@ static int rt5033_battery_probe(struct
> i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int rt5033_battery_remove(struct i2c_client *client)
> +static void rt5033_battery_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt5033_battery *ba=
ttery =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0power_supply_unregister(b=
attery->psy);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id rt5033_battery_id[] =3D {
> diff --git a/drivers/power/supply/rt9455_charger.c
> b/drivers/power/supply/rt9455_charger.c
> index 74ee54320e6a..72962286d704 100644
> --- a/drivers/power/supply/rt9455_charger.c
> +++ b/drivers/power/supply/rt9455_charger.c
> @@ -1698,7 +1698,7 @@ static int rt9455_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rt9455_remove(struct i2c_client *client)
> +static void rt9455_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int ret;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt9455_info *info =
=3D i2c_get_clientdata(client);
> @@ -1715,8 +1715,6 @@ static int rt9455_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_delayed_work_sync(=
&info->pwr_rdy_work);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_delayed_work_sync(=
&info->max_charging_time_work);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_delayed_work_sync(=
&info->batt_presence_work);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id rt9455_i2c_id_table[] =3D {
> diff --git a/drivers/power/supply/smb347-charger.c
> b/drivers/power/supply/smb347-charger.c
> index 1511f71f937c..996a82f8a2a1 100644
> --- a/drivers/power/supply/smb347-charger.c
> +++ b/drivers/power/supply/smb347-charger.c
> @@ -1595,14 +1595,12 @@ static int smb347_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int smb347_remove(struct i2c_client *client)
> +static void smb347_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct smb347_charger *sm=
b =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0smb347_usb_vbus_regulator=
_disable(smb->usb_rdev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0smb347_irq_disable(smb);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void smb347_shutdown(struct i2c_client *client)
> diff --git a/drivers/power/supply/z2_battery.c
> b/drivers/power/supply/z2_battery.c
> index 7ed4e4bb26ec..1897c2984860 100644
> --- a/drivers/power/supply/z2_battery.c
> +++ b/drivers/power/supply/z2_battery.c
> @@ -251,7 +251,7 @@ static int z2_batt_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int z2_batt_remove(struct i2c_client *client)
> +static void z2_batt_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct z2_charger *charge=
r =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -263,8 +263,6 @@ static int z2_batt_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(gpiod_to_irq(charger->charge_gpiod),
> charger);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(charger);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/pwm/pwm-pca9685.c b/drivers/pwm/pwm-pca9685.c
> index c91fa7f9e33d..f230c10d28bb 100644
> --- a/drivers/pwm/pwm-pca9685.c
> +++ b/drivers/pwm/pwm-pca9685.c
> @@ -598,7 +598,7 @@ static int pca9685_pwm_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int pca9685_pwm_remove(struct i2c_client *client)
> +static void pca9685_pwm_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pca9685 *pca =3D i=
2c_get_clientdata(client);
> =C2=A0
> @@ -610,8 +610,6 @@ static int pca9685_pwm_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused pca9685_pwm_runtime_suspend(struct device
> *dev)
> diff --git a/drivers/regulator/da9121-regulator.c
> b/drivers/regulator/da9121-regulator.c
> index 76e0e23bf598..e4c753b83088 100644
> --- a/drivers/regulator/da9121-regulator.c
> +++ b/drivers/regulator/da9121-regulator.c
> @@ -1164,7 +1164,7 @@ static int da9121_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int da9121_i2c_remove(struct i2c_client *i2c)
> +static void da9121_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct da9121 *chip =3D i=
2c_get_clientdata(i2c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0const int mask_all[4] =3D=
 { 0xFF, 0xFF, 0xFF, 0xFF };
> @@ -1176,7 +1176,6 @@ static int da9121_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ret =3D regmap_bulk_write=
(chip->regmap, DA9121_REG_SYS_MASK_0,
> mask_all, 4);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret !=3D 0)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_err(chip->dev, "Failed to set IRQ masks: %d\n",
> ret);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id da9121_i2c_id[] =3D {
> diff --git a/drivers/regulator/lp8755.c b/drivers/regulator/lp8755.c
> index 321bec6e3f8d..31b43426d47c 100644
> --- a/drivers/regulator/lp8755.c
> +++ b/drivers/regulator/lp8755.c
> @@ -422,15 +422,13 @@ static int lp8755_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lp8755_remove(struct i2c_client *client)
> +static void lp8755_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int icnt;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp8755_chip *pchip=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0for (icnt =3D 0; icnt < L=
P8755_BUCK_MAX; icnt++)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0regmap_write(pchip->regmap, icnt, 0x00);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lp8755_id[] =3D {
> diff --git a/drivers/regulator/rpi-panel-attiny-regulator.c
> b/drivers/regulator/rpi-panel-attiny-regulator.c
> index fa8706a352ce..04b4ab131985 100644
> --- a/drivers/regulator/rpi-panel-attiny-regulator.c
> +++ b/drivers/regulator/rpi-panel-attiny-regulator.c
> @@ -385,13 +385,11 @@ static int attiny_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int attiny_i2c_remove(struct i2c_client *client)
> +static void attiny_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct attiny_lcd *state =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&state->loc=
k);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id attiny_dt_ids[] =3D {
> diff --git a/drivers/rtc/rtc-bq32k.c b/drivers/rtc/rtc-bq32k.c
> index 2235c968842d..f198663f20c7 100644
> --- a/drivers/rtc/rtc-bq32k.c
> +++ b/drivers/rtc/rtc-bq32k.c
> @@ -298,11 +298,9 @@ static int bq32k_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int bq32k_remove(struct i2c_client *client)
> +static void bq32k_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0bq32k_sysfs_unregister(&c=
lient->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id bq32k_id[] =3D {
> diff --git a/drivers/rtc/rtc-ds1374.c b/drivers/rtc/rtc-ds1374.c
> index 8db5a631bca8..44148802b1a5 100644
> --- a/drivers/rtc/rtc-ds1374.c
> +++ b/drivers/rtc/rtc-ds1374.c
> @@ -531,7 +531,7 @@ static int ds1374_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ds1374_remove(struct i2c_client *client)
> +static void ds1374_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ds1374 *ds1374 =3D=
 i2c_get_clientdata(client);
> =C2=A0
> @@ -543,8 +543,6 @@ static int ds1374_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0devm_free_irq(&client->dev, client->irq, client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0cancel_work_sync(&ds1374->work);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/rtc/rtc-isl12026.c b/drivers/rtc/rtc-isl12026.c
> index 1fc6627d854d..1bfca39079d4 100644
> --- a/drivers/rtc/rtc-isl12026.c
> +++ b/drivers/rtc/rtc-isl12026.c
> @@ -472,12 +472,11 @@ static int isl12026_probe_new(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return devm_rtc_register_=
device(priv->rtc);
> =C2=A0}
> =C2=A0
> -static int isl12026_remove(struct i2c_client *client)
> +static void isl12026_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct isl12026 *priv =3D=
 i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0i2c_unregister_device(pri=
v->nvm_client);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id isl12026_dt_match[] =3D {
> diff --git a/drivers/rtc/rtc-m41t80.c b/drivers/rtc/rtc-m41t80.c
> index d868458cd40e..e0b4d3794320 100644
> --- a/drivers/rtc/rtc-m41t80.c
> +++ b/drivers/rtc/rtc-m41t80.c
> @@ -989,7 +989,7 @@ static int m41t80_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int m41t80_remove(struct i2c_client *client)
> +static void m41t80_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0#ifdef CONFIG_RTC_DRV_M41T80_WDT
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct m41t80_data *clien=
tdata =3D i2c_get_clientdata(client);
> @@ -999,8 +999,6 @@ static int m41t80_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0unregister_reboot_notifier(&wdt_notifier);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> =C2=A0#endif
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver m41t80_driver =3D {
> diff --git a/drivers/rtc/rtc-rs5c372.c b/drivers/rtc/rtc-rs5c372.c
> index cb15983383f5..9562c477e1c9 100644
> --- a/drivers/rtc/rtc-rs5c372.c
> +++ b/drivers/rtc/rtc-rs5c372.c
> @@ -910,10 +910,9 @@ static int rs5c372_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int rs5c372_remove(struct i2c_client *client)
> +static void rs5c372_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rs5c_sysfs_unregister(&cl=
ient->dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver rs5c372_driver =3D {
> diff --git a/drivers/rtc/rtc-x1205.c b/drivers/rtc/rtc-x1205.c
> index d1d5a44d9122..7792e22de805 100644
> --- a/drivers/rtc/rtc-x1205.c
> +++ b/drivers/rtc/rtc-x1205.c
> @@ -658,10 +658,9 @@ static int x1205_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int x1205_remove(struct i2c_client *client)
> +static void x1205_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0x1205_sysfs_unregister(&c=
lient->dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id x1205_id[] =3D {
> diff --git a/drivers/staging/media/atomisp/i2c/atomisp-gc0310.c
> b/drivers/staging/media/atomisp/i2c/atomisp-gc0310.c
> index cbc8b1d91995..783f1b88ebf2 100644
> --- a/drivers/staging/media/atomisp/i2c/atomisp-gc0310.c
> +++ b/drivers/staging/media/atomisp/i2c/atomisp-gc0310.c
> @@ -1194,7 +1194,7 @@ static const struct v4l2_subdev_ops gc0310_ops
> =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0.sensor =3D &gc0310_senso=
r_ops,
> =C2=A0};
> =C2=A0
> -static int gc0310_remove(struct i2c_client *client)
> +static void gc0310_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct gc0310_device *dev=
 =3D to_gc0310_sensor(sd);
> @@ -1207,8 +1207,6 @@ static int gc0310_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&dev=
->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ev->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int gc0310_probe(struct i2c_client *client)
> diff --git a/drivers/staging/media/atomisp/i2c/atomisp-gc2235.c
> b/drivers/staging/media/atomisp/i2c/atomisp-gc2235.c
> index 0e6b2e6100d1..4d5a7e335f85 100644
> --- a/drivers/staging/media/atomisp/i2c/atomisp-gc2235.c
> +++ b/drivers/staging/media/atomisp/i2c/atomisp-gc2235.c
> @@ -952,7 +952,7 @@ static const struct v4l2_subdev_ops gc2235_ops =3D
> {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0.sensor =3D &gc2235_senso=
r_ops,
> =C2=A0};
> =C2=A0
> -static int gc2235_remove(struct i2c_client *client)
> +static void gc2235_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct gc2235_device *dev=
 =3D to_gc2235_sensor(sd);
> @@ -965,8 +965,6 @@ static int gc2235_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&dev=
->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ev->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int gc2235_probe(struct i2c_client *client)
> diff --git a/drivers/staging/media/atomisp/i2c/atomisp-lm3554.c
> b/drivers/staging/media/atomisp/i2c/atomisp-lm3554.c
> index e046489cd253..75d16b525294 100644
> --- a/drivers/staging/media/atomisp/i2c/atomisp-lm3554.c
> +++ b/drivers/staging/media/atomisp/i2c/atomisp-lm3554.c
> @@ -910,7 +910,7 @@ static int lm3554_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int lm3554_remove(struct i2c_client *client)
> +static void lm3554_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3554 *flash =3D =
to_lm3554(sd);
> @@ -926,8 +926,6 @@ static int lm3554_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lm3554_gpio_uninit(client=
);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(flash);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops lm3554_pm_ops =3D {
> diff --git a/drivers/staging/media/atomisp/i2c/atomisp-mt9m114.c
> b/drivers/staging/media/atomisp/i2c/atomisp-mt9m114.c
> index 00d6842c07d6..4601a238cb89 100644
> --- a/drivers/staging/media/atomisp/i2c/atomisp-mt9m114.c
> +++ b/drivers/staging/media/atomisp/i2c/atomisp-mt9m114.c
> @@ -1711,7 +1711,7 @@ static const struct v4l2_subdev_ops mt9m114_ops
> =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0.sensor =3D &mt9m114_sens=
or_ops,
> =C2=A0};
> =C2=A0
> -static int mt9m114_remove(struct i2c_client *client)
> +static void mt9m114_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt9m114_device *de=
v;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> @@ -1722,7 +1722,6 @@ static int mt9m114_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&dev=
->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ev->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int mt9m114_probe(struct i2c_client *client)
> diff --git a/drivers/staging/media/atomisp/i2c/atomisp-ov2680.c
> b/drivers/staging/media/atomisp/i2c/atomisp-ov2680.c
> index 4ba99c660681..8f48b23be3aa 100644
> --- a/drivers/staging/media/atomisp/i2c/atomisp-ov2680.c
> +++ b/drivers/staging/media/atomisp/i2c/atomisp-ov2680.c
> @@ -1135,7 +1135,7 @@ static const struct v4l2_subdev_ops ov2680_ops
> =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0.sensor =3D &ov2680_senso=
r_ops,
> =C2=A0};
> =C2=A0
> -static int ov2680_remove(struct i2c_client *client)
> +static void ov2680_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov2680_device *dev=
 =3D to_ov2680_sensor(sd);
> @@ -1148,8 +1148,6 @@ static int ov2680_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&dev=
->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ev->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ov2680_probe(struct i2c_client *client)
> diff --git a/drivers/staging/media/atomisp/i2c/atomisp-ov2722.c
> b/drivers/staging/media/atomisp/i2c/atomisp-ov2722.c
> index da98094d7094..715a7aeeda18 100644
> --- a/drivers/staging/media/atomisp/i2c/atomisp-ov2722.c
> +++ b/drivers/staging/media/atomisp/i2c/atomisp-ov2722.c
> @@ -1094,7 +1094,7 @@ static const struct v4l2_subdev_ops ov2722_ops
> =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0.sensor =3D &ov2722_senso=
r_ops,
> =C2=A0};
> =C2=A0
> -static int ov2722_remove(struct i2c_client *client)
> +static void ov2722_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov2722_device *dev=
 =3D to_ov2722_sensor(sd);
> @@ -1107,8 +1107,6 @@ static int ov2722_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&dev=
->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __ov2722_init_ctrl_handler(struct ov2722_device *dev)
> diff --git a/drivers/staging/media/atomisp/i2c/ov5693/atomisp-
> ov5693.c b/drivers/staging/media/atomisp/i2c/ov5693/atomisp-ov5693.c
> index 6c95f57a52e9..c1cd631455e6 100644
> --- a/drivers/staging/media/atomisp/i2c/ov5693/atomisp-ov5693.c
> +++ b/drivers/staging/media/atomisp/i2c/ov5693/atomisp-ov5693.c
> @@ -1877,7 +1877,7 @@ static const struct v4l2_subdev_ops ov5693_ops
> =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0.pad =3D &ov5693_pad_ops,
> =C2=A0};
> =C2=A0
> -static int ov5693_remove(struct i2c_client *client)
> +static void ov5693_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct v4l2_subdev *sd =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ov5693_device *dev=
 =3D to_ov5693_sensor(sd);
> @@ -1893,8 +1893,6 @@ static int ov5693_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0media_entity_cleanup(&dev=
->sd.entity);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_ctrl_handler_free(&d=
ev->ctrl_handler);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int ov5693_probe(struct i2c_client *client)
> diff --git a/drivers/staging/media/max96712/max96712.c
> b/drivers/staging/media/max96712/max96712.c
> index 6b5abd958bff..99b333b68198 100644
> --- a/drivers/staging/media/max96712/max96712.c
> +++ b/drivers/staging/media/max96712/max96712.c
> @@ -407,15 +407,13 @@ static int max96712_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return max96712_v4l2_regi=
ster(priv);
> =C2=A0}
> =C2=A0
> -static int max96712_remove(struct i2c_client *client)
> +static void max96712_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max96712_priv *pri=
v =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0v4l2_async_unregister_sub=
dev(&priv->sd);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(=
priv->gpiod_pwdn, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id max96712_of_table[] =3D {
> diff --git a/drivers/staging/most/i2c/i2c.c
> b/drivers/staging/most/i2c/i2c.c
> index 7042f10887bb..285a071f02be 100644
> --- a/drivers/staging/most/i2c/i2c.c
> +++ b/drivers/staging/most/i2c/i2c.c
> @@ -340,14 +340,12 @@ static int i2c_probe(struct i2c_client *client,
> const struct i2c_device_id *id)
> =C2=A0 *
> =C2=A0 * Unregister the i2c client device as a MOST interface
> =C2=A0 */
> -static int i2c_remove(struct i2c_client *client)
> +static void i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct hdm_i2c *dev =3D i=
2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0most_deregister_interface=
(&dev->most_iface);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id i2c_id[] =3D {
> diff --git a/drivers/staging/olpc_dcon/olpc_dcon.c
> b/drivers/staging/olpc_dcon/olpc_dcon.c
> index 7284cb4ac395..aea2841f7598 100644
> --- a/drivers/staging/olpc_dcon/olpc_dcon.c
> +++ b/drivers/staging/olpc_dcon/olpc_dcon.c
> @@ -671,7 +671,7 @@ static int dcon_probe(struct i2c_client *client,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return rc;
> =C2=A0}
> =C2=A0
> -static int dcon_remove(struct i2c_client *client)
> +static void dcon_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct dcon_priv *dcon =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -687,8 +687,6 @@ static int dcon_remove(struct i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_work_sync(&dcon->s=
witch_source);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(dcon);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/drivers/tty/serial/sc16is7xx.c
> b/drivers/tty/serial/sc16is7xx.c
> index 8472bf70477c..cc3b22cbda9b 100644
> --- a/drivers/tty/serial/sc16is7xx.c
> +++ b/drivers/tty/serial/sc16is7xx.c
> @@ -1683,11 +1683,9 @@ static int sc16is7xx_i2c_probe(struct
> i2c_client *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return sc16is7xx_probe(&i=
2c->dev, devtype, regmap, i2c->irq);
> =C2=A0}
> =C2=A0
> -static int sc16is7xx_i2c_remove(struct i2c_client *client)
> +static void sc16is7xx_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sc16is7xx_remove(&client-=
>dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id sc16is7xx_i2c_id_table[] =3D {
> diff --git a/drivers/usb/misc/usb3503.c b/drivers/usb/misc/usb3503.c
> index 330f494cd158..3c9fa663475f 100644
> --- a/drivers/usb/misc/usb3503.c
> +++ b/drivers/usb/misc/usb3503.c
> @@ -289,14 +289,12 @@ static int usb3503_i2c_probe(struct i2c_client
> *i2c,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return usb3503_probe(hub)=
;
> =C2=A0}
> =C2=A0
> -static int usb3503_i2c_remove(struct i2c_client *i2c)
> +static void usb3503_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct usb3503 *hub;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0hub =3D i2c_get_clientdat=
a(i2c);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0clk_disable_unprepare(hub=
->clk);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int usb3503_platform_probe(struct platform_device *pdev)
> diff --git a/drivers/usb/phy/phy-isp1301-omap.c
> b/drivers/usb/phy/phy-isp1301-omap.c
> index f8bd93fe69cd..e5d3f206097c 100644
> --- a/drivers/usb/phy/phy-isp1301-omap.c
> +++ b/drivers/usb/phy/phy-isp1301-omap.c
> @@ -1196,7 +1196,7 @@ static void isp1301_release(struct device *dev)
> =C2=A0
> =C2=A0static struct isp1301 *the_transceiver;
> =C2=A0
> -static int isp1301_remove(struct i2c_client *i2c)
> +static void isp1301_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct isp1301=C2=A0=C2=
=A0*isp;
> =C2=A0
> @@ -1214,8 +1214,6 @@ static int isp1301_remove(struct i2c_client
> *i2c)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0put_device(&i2c->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0the_transceiver =3D NULL;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*-----------------------------------------------------------------=
-
> -------*/
> diff --git a/drivers/usb/phy/phy-isp1301.c b/drivers/usb/phy/phy-
> isp1301.c
> index ad3d57f1c273..c2777a5c1f4e 100644
> --- a/drivers/usb/phy/phy-isp1301.c
> +++ b/drivers/usb/phy/phy-isp1301.c
> @@ -120,14 +120,12 @@ static int isp1301_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int isp1301_remove(struct i2c_client *client)
> +static void isp1301_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct isp1301 *isp =3D i=
2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0usb_remove_phy(&isp->phy)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0isp1301_i2c_client =3D NU=
LL;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver isp1301_driver =3D {
> diff --git a/drivers/usb/typec/hd3ss3220.c
> b/drivers/usb/typec/hd3ss3220.c
> index cd47c3597e19..2a58185fb14c 100644
> --- a/drivers/usb/typec/hd3ss3220.c
> +++ b/drivers/usb/typec/hd3ss3220.c
> @@ -245,14 +245,12 @@ static int hd3ss3220_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int hd3ss3220_remove(struct i2c_client *client)
> +static void hd3ss3220_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct hd3ss3220 *hd3ss32=
20 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0typec_unregister_port(hd3=
ss3220->port);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0usb_role_switch_put(hd3ss=
3220->role_sw);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id dev_ids[] =3D {
> diff --git a/drivers/usb/typec/mux/fsa4480.c
> b/drivers/usb/typec/mux/fsa4480.c
> index 6184f5367190..d6495e533e58 100644
> --- a/drivers/usb/typec/mux/fsa4480.c
> +++ b/drivers/usb/typec/mux/fsa4480.c
> @@ -181,14 +181,12 @@ static int fsa4480_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int fsa4480_remove(struct i2c_client *client)
> +static void fsa4480_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct fsa4480 *fsa =3D i=
2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0typec_mux_unregister(fsa-=
>mux);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0typec_switch_unregister(f=
sa->sw);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id fsa4480_table[] =3D {
> diff --git a/drivers/usb/typec/mux/pi3usb30532.c
> b/drivers/usb/typec/mux/pi3usb30532.c
> index 6ce9f282594e..1cd388b55c30 100644
> --- a/drivers/usb/typec/mux/pi3usb30532.c
> +++ b/drivers/usb/typec/mux/pi3usb30532.c
> @@ -160,13 +160,12 @@ static int pi3usb30532_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int pi3usb30532_remove(struct i2c_client *client)
> +static void pi3usb30532_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct pi3usb30532 *pi =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0typec_mux_unregister(pi->=
mux);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0typec_switch_unregister(p=
i->sw);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id pi3usb30532_table[] =3D {
> diff --git a/drivers/usb/typec/rt1719.c b/drivers/usb/typec/rt1719.c
> index f1b698edd7eb..ea8b700b0ceb 100644
> --- a/drivers/usb/typec/rt1719.c
> +++ b/drivers/usb/typec/rt1719.c
> @@ -930,14 +930,12 @@ static int rt1719_probe(struct i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rt1719_remove(struct i2c_client *i2c)
> +static void rt1719_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt1719_data *data =
=3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0typec_unregister_port(dat=
a->port);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0usb_role_switch_put(data-=
>role_sw);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id __maybe_unused
> rt1719_device_table[] =3D {
> diff --git a/drivers/usb/typec/stusb160x.c
> b/drivers/usb/typec/stusb160x.c
> index e7745d1c2a5c..8638f1d39896 100644
> --- a/drivers/usb/typec/stusb160x.c
> +++ b/drivers/usb/typec/stusb160x.c
> @@ -801,7 +801,7 @@ static int stusb160x_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int stusb160x_remove(struct i2c_client *client)
> +static void stusb160x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct stusb160x *chip =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -823,8 +823,6 @@ static int stusb160x_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (chip->main_supply)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(chip->main_supply);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused stusb160x_suspend(struct device *dev)
> diff --git a/drivers/usb/typec/tcpm/fusb302.c
> b/drivers/usb/typec/tcpm/fusb302.c
> index 96c55eaf3f80..5e9348f28d50 100644
> --- a/drivers/usb/typec/tcpm/fusb302.c
> +++ b/drivers/usb/typec/tcpm/fusb302.c
> @@ -1771,7 +1771,7 @@ static int fusb302_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int fusb302_remove(struct i2c_client *client)
> +static void fusb302_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct fusb302_chip *chip=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1783,8 +1783,6 @@ static int fusb302_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fwnode_handle_put(chip->t=
cpc_dev.fwnode);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0destroy_workqueue(chip->w=
q);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fusb302_debugfs_exit(chip=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int fusb302_pm_suspend(struct device *dev)
> diff --git a/drivers/usb/typec/tcpm/tcpci.c
> b/drivers/usb/typec/tcpm/tcpci.c
> index f33e08eb7670..c48fca60bb06 100644
> --- a/drivers/usb/typec/tcpm/tcpci.c
> +++ b/drivers/usb/typec/tcpm/tcpci.c
> @@ -869,7 +869,7 @@ static int tcpci_probe(struct i2c_client *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tcpci_remove(struct i2c_client *client)
> +static void tcpci_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tcpci_chip *chip =
=3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int err;
> @@ -880,8 +880,6 @@ static int tcpci_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_warn(&client->dev, "Failed to disable irqs
> (%pe)\n", ERR_PTR(err));
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tcpci_unregister_port(chi=
p->tcpci);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tcpci_id[] =3D {
> diff --git a/drivers/usb/typec/tcpm/tcpci_maxim.c
> b/drivers/usb/typec/tcpm/tcpci_maxim.c
> index df2505570f07..a11be5754128 100644
> --- a/drivers/usb/typec/tcpm/tcpci_maxim.c
> +++ b/drivers/usb/typec/tcpm/tcpci_maxim.c
> @@ -493,14 +493,12 @@ static int max_tcpci_probe(struct i2c_client
> *client, const struct i2c_device_id
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int max_tcpci_remove(struct i2c_client *client)
> +static void max_tcpci_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max_tcpci_chip *ch=
ip =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (!IS_ERR_OR_NULL(chip-=
>tcpci))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0tcpci_unregister_port(chip->tcpci);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max_tcpci_id[] =3D {
> diff --git a/drivers/usb/typec/tcpm/tcpci_rt1711h.c
> b/drivers/usb/typec/tcpm/tcpci_rt1711h.c
> index b56a0880a044..9ad4924b4ba7 100644
> --- a/drivers/usb/typec/tcpm/tcpci_rt1711h.c
> +++ b/drivers/usb/typec/tcpm/tcpci_rt1711h.c
> @@ -263,12 +263,11 @@ static int rt1711h_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int rt1711h_remove(struct i2c_client *client)
> +static void rt1711h_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt1711h_chip *chip=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tcpci_unregister_port(chi=
p->tcpci);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id rt1711h_id[] =3D {
> diff --git a/drivers/usb/typec/tipd/core.c
> b/drivers/usb/typec/tipd/core.c
> index dfbba5ae9487..b637e8b378b3 100644
> --- a/drivers/usb/typec/tipd/core.c
> +++ b/drivers/usb/typec/tipd/core.c
> @@ -857,15 +857,13 @@ static int tps6598x_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tps6598x_remove(struct i2c_client *client)
> +static void tps6598x_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tps6598x *tps =3D =
i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0tps6598x_disconnect(tps, =
0);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0typec_unregister_port(tps=
->port);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0usb_role_switch_put(tps->=
role_sw);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id tps6598x_of_match[] =3D {
> diff --git a/drivers/usb/typec/ucsi/ucsi_ccg.c
> b/drivers/usb/typec/ucsi/ucsi_ccg.c
> index 6db7c8ddd51c..920b7e743f56 100644
> --- a/drivers/usb/typec/ucsi/ucsi_ccg.c
> +++ b/drivers/usb/typec/ucsi/ucsi_ccg.c
> @@ -1398,7 +1398,7 @@ static int ucsi_ccg_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return status;
> =C2=A0}
> =C2=A0
> -static int ucsi_ccg_remove(struct i2c_client *client)
> +static void ucsi_ccg_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ucsi_ccg *uc =3D i=
2c_get_clientdata(client);
> =C2=A0
> @@ -1408,8 +1408,6 @@ static int ucsi_ccg_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ucsi_unregister(uc->ucsi)=
;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ucsi_destroy(uc->ucsi);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0free_irq(uc->irq, uc);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ucsi_ccg_device_id[] =3D {
> diff --git a/drivers/usb/typec/wusb3801.c
> b/drivers/usb/typec/wusb3801.c
> index e63509f8b01e..3cc7a15ecbd3 100644
> --- a/drivers/usb/typec/wusb3801.c
> +++ b/drivers/usb/typec/wusb3801.c
> @@ -399,7 +399,7 @@ static int wusb3801_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int wusb3801_remove(struct i2c_client *client)
> +static void wusb3801_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wusb3801 *wusb3801=
 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -411,8 +411,6 @@ static int wusb3801_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (wusb3801->vbus_on)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(wusb3801->vbus_supply);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id wusb3801_of_match[] =3D {
> diff --git a/drivers/video/backlight/adp8860_bl.c
> b/drivers/video/backlight/adp8860_bl.c
> index 8ec19425671f..b0fe02273e87 100644
> --- a/drivers/video/backlight/adp8860_bl.c
> +++ b/drivers/video/backlight/adp8860_bl.c
> @@ -753,7 +753,7 @@ static int adp8860_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int adp8860_remove(struct i2c_client *client)
> +static void adp8860_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adp8860_bl *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -765,8 +765,6 @@ static int adp8860_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (data->en_ambl_sens)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&data->bl->dev.kobj,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0&ad=
p8860_bl_attr_group);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/video/backlight/adp8870_bl.c
> b/drivers/video/backlight/adp8870_bl.c
> index 8b5213a39527..5becace3fd0f 100644
> --- a/drivers/video/backlight/adp8870_bl.c
> +++ b/drivers/video/backlight/adp8870_bl.c
> @@ -925,7 +925,7 @@ static int adp8870_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int adp8870_remove(struct i2c_client *client)
> +static void adp8870_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adp8870_bl *data =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -937,8 +937,6 @@ static int adp8870_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (data->pdata->en_ambl_=
sens)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&data->bl->dev.kobj,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0&ad=
p8870_bl_attr_group);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/video/backlight/arcxcnn_bl.c
> b/drivers/video/backlight/arcxcnn_bl.c
> index 7b1c0a0e6cad..060c0eef6a52 100644
> --- a/drivers/video/backlight/arcxcnn_bl.c
> +++ b/drivers/video/backlight/arcxcnn_bl.c
> @@ -362,7 +362,7 @@ static int arcxcnn_probe(struct i2c_client *cl,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int arcxcnn_remove(struct i2c_client *cl)
> +static void arcxcnn_remove(struct i2c_client *cl)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct arcxcnn *lp =3D i2=
c_get_clientdata(cl);
> =C2=A0
> @@ -376,8 +376,6 @@ static int arcxcnn_remove(struct i2c_client *cl)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0lp->bl->props.brightness =
=3D 0;
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0backlight_update_status(l=
p->bl);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id arcxcnn_dt_ids[] =3D {
> diff --git a/drivers/video/backlight/bd6107.c
> b/drivers/video/backlight/bd6107.c
> index 515184fbe33a..a506872d4396 100644
> --- a/drivers/video/backlight/bd6107.c
> +++ b/drivers/video/backlight/bd6107.c
> @@ -175,14 +175,12 @@ static int bd6107_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int bd6107_remove(struct i2c_client *client)
> +static void bd6107_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct backlight_device *=
backlight =3D
> i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0backlight->props.brightne=
ss =3D 0;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0backlight_update_status(b=
acklight);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id bd6107_ids[] =3D {
> diff --git a/drivers/video/backlight/lm3630a_bl.c
> b/drivers/video/backlight/lm3630a_bl.c
> index 1d17c439430e..475f35635bf6 100644
> --- a/drivers/video/backlight/lm3630a_bl.c
> +++ b/drivers/video/backlight/lm3630a_bl.c
> @@ -579,7 +579,7 @@ static int lm3630a_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lm3630a_remove(struct i2c_client *client)
> +static void lm3630a_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int rval;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3630a_chip *pchi=
p =3D i2c_get_clientdata(client);
> @@ -596,7 +596,6 @@ static int lm3630a_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(pchip->irq, pchip);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0destroy_workqueue(pchip->irqthread);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3630a_id[] =3D {
> diff --git a/drivers/video/backlight/lm3639_bl.c
> b/drivers/video/backlight/lm3639_bl.c
> index 48c04155a5f9..6580911671a3 100644
> --- a/drivers/video/backlight/lm3639_bl.c
> +++ b/drivers/video/backlight/lm3639_bl.c
> @@ -390,7 +390,7 @@ static int lm3639_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lm3639_remove(struct i2c_client *client)
> +static void lm3639_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lm3639_chip_data *=
pchip =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -400,7 +400,6 @@ static int lm3639_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0led_classdev_unregister(&=
pchip->cdev_flash);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (pchip->bled)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0device_remove_file(&(pchip->bled->dev),
> &dev_attr_bled_mode);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lm3639_id[] =3D {
> diff --git a/drivers/video/backlight/lp855x_bl.c
> b/drivers/video/backlight/lp855x_bl.c
> index 2b9e2bbbb03e..43b39cf68b04 100644
> --- a/drivers/video/backlight/lp855x_bl.c
> +++ b/drivers/video/backlight/lp855x_bl.c
> @@ -537,7 +537,7 @@ static int lp855x_probe(struct i2c_client *cl,
> const struct i2c_device_id *id)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int lp855x_remove(struct i2c_client *cl)
> +static void lp855x_remove(struct i2c_client *cl)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct lp855x *lp =3D i2c=
_get_clientdata(cl);
> =C2=A0
> @@ -548,8 +548,6 @@ static int lp855x_remove(struct i2c_client *cl)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (lp->supply)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(lp->supply);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0sysfs_remove_group(&lp->d=
ev->kobj, &lp855x_attr_group);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id lp855x_dt_ids[] =3D {
> diff --git a/drivers/video/backlight/lv5207lp.c
> b/drivers/video/backlight/lv5207lp.c
> index 1842ae9a55f8..767b800d79fa 100644
> --- a/drivers/video/backlight/lv5207lp.c
> +++ b/drivers/video/backlight/lv5207lp.c
> @@ -124,14 +124,12 @@ static int lv5207lp_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int lv5207lp_remove(struct i2c_client *client)
> +static void lv5207lp_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct backlight_device *=
backlight =3D
> i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0backlight->props.brightne=
ss =3D 0;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0backlight_update_status(b=
acklight);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id lv5207lp_ids[] =3D {
> diff --git a/drivers/video/backlight/tosa_bl.c
> b/drivers/video/backlight/tosa_bl.c
> index 6df6fcd132e3..f55b3d616a87 100644
> --- a/drivers/video/backlight/tosa_bl.c
> +++ b/drivers/video/backlight/tosa_bl.c
> @@ -121,12 +121,11 @@ static int tosa_bl_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tosa_bl_remove(struct i2c_client *client)
> +static void tosa_bl_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tosa_bl_data *data=
 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0data->bl =3D NULL;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM_SLEEP
> diff --git a/drivers/video/fbdev/matrox/matroxfb_maven.c
> b/drivers/video/fbdev/matrox/matroxfb_maven.c
> index 9a98c4a6ba33..f2e02958673d 100644
> --- a/drivers/video/fbdev/matrox/matroxfb_maven.c
> +++ b/drivers/video/fbdev/matrox/matroxfb_maven.c
> @@ -1276,11 +1276,10 @@ ERROR0:;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int maven_remove(struct i2c_client *client)
> +static void maven_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0maven_shutdown_client(cli=
ent);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(i2c_get_clientdata(=
client));
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id maven_id[] =3D {
> diff --git a/drivers/video/fbdev/ssd1307fb.c
> b/drivers/video/fbdev/ssd1307fb.c
> index 5c765655d000..fbf26cdfb1c0 100644
> --- a/drivers/video/fbdev/ssd1307fb.c
> +++ b/drivers/video/fbdev/ssd1307fb.c
> @@ -817,7 +817,7 @@ static int ssd1307fb_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ssd1307fb_remove(struct i2c_client *client)
> +static void ssd1307fb_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct fb_info *info =3D =
i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ssd1307fb_par *par=
 =3D info->par;
> @@ -836,8 +836,6 @@ static int ssd1307fb_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0fb_deferred_io_cleanup(in=
fo);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0__free_pages(__va(info->f=
ix.smem_start), get_order(info-
> >fix.smem_len));
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0framebuffer_release(info)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ssd1307fb_i2c_id[] =3D {
> diff --git a/drivers/w1/masters/ds2482.c
> b/drivers/w1/masters/ds2482.c
> index 6c962e88501c..62c44616d8a9 100644
> --- a/drivers/w1/masters/ds2482.c
> +++ b/drivers/w1/masters/ds2482.c
> @@ -525,7 +525,7 @@ static int ds2482_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return err;
> =C2=A0}
> =C2=A0
> -static int ds2482_remove(struct i2c_client *client)
> +static void ds2482_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ds2482_data=C2=A0=
=C2=A0 *data =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int idx;
> @@ -538,7 +538,6 @@ static int ds2482_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Free the memory */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(data);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/*
> diff --git a/drivers/watchdog/ziirave_wdt.c
> b/drivers/watchdog/ziirave_wdt.c
> index c5a9b820d43a..d0e88875443a 100644
> --- a/drivers/watchdog/ziirave_wdt.c
> +++ b/drivers/watchdog/ziirave_wdt.c
> @@ -708,13 +708,11 @@ static int ziirave_wdt_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ziirave_wdt_remove(struct i2c_client *client)
> +static void ziirave_wdt_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ziirave_wdt_data *=
w_priv =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0watchdog_unregister_devic=
e(&w_priv->wdd);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ziirave_wdt_id[] =3D {
> diff --git a/include/linux/i2c.h b/include/linux/i2c.h
> index fbda5ada2afc..066b541a0d5d 100644
> --- a/include/linux/i2c.h
> +++ b/include/linux/i2c.h
> @@ -273,7 +273,7 @@ struct i2c_driver {
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Standard driver model =
interfaces */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int (*probe)(struct i2c_c=
lient *client, const struct
> i2c_device_id *id);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0int (*remove)(struct i2c_clien=
t *client);
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0void (*remove)(struct i2c_clie=
nt *client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* New driver model inter=
face to aid the seamless removal of
> the
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * current probe()'s, mor=
e commonly unused than used second
> parameter.
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index f0973da583e0..366e61639cb2 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -149,6 +149,7 @@ config KASAN_STACK
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0depends on KASAN_GENERIC =
|| KASAN_SW_TAGS
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0depends on !ARCH_DISABLE_=
KASAN_INLINE
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0default y if CC_IS_GCC
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0depends on !ARM
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0help
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 Disables stack ins=
trumentation and thus KASAN's ability to
> detect
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 out-of-bounds bugs=
 in stack variables.
> diff --git a/sound/aoa/codecs/onyx.c b/sound/aoa/codecs/onyx.c
> index 1abee841cc45..2d0f904aba00 100644
> --- a/sound/aoa/codecs/onyx.c
> +++ b/sound/aoa/codecs/onyx.c
> @@ -1029,7 +1029,7 @@ static int onyx_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return -ENODEV;
> =C2=A0}
> =C2=A0
> -static int onyx_i2c_remove(struct i2c_client *client)
> +static void onyx_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct onyx *onyx =3D i2c=
_get_clientdata(client);
> =C2=A0
> @@ -1037,7 +1037,6 @@ static int onyx_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0of_node_put(onyx->codec.n=
ode);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(onyx->codec_info);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(onyx);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id onyx_i2c_id[] =3D {
> diff --git a/sound/aoa/codecs/tas.c b/sound/aoa/codecs/tas.c
> index ab19a37e2a68..ab89475b7715 100644
> --- a/sound/aoa/codecs/tas.c
> +++ b/sound/aoa/codecs/tas.c
> @@ -912,7 +912,7 @@ static int tas_i2c_probe(struct i2c_client
> *client,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return -EINVAL;
> =C2=A0}
> =C2=A0
> -static int tas_i2c_remove(struct i2c_client *client)
> +static void tas_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tas *tas =3D i2c_g=
et_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0u8 tmp =3D TAS_ACR_ANALOG=
_PDOWN;
> @@ -925,7 +925,6 @@ static int tas_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&tas->mtx);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0kfree(tas);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tas_i2c_id[] =3D {
> diff --git a/sound/pci/hda/cs35l41_hda_i2c.c
> b/sound/pci/hda/cs35l41_hda_i2c.c
> index e810b278fb91..acab8c058e66 100644
> --- a/sound/pci/hda/cs35l41_hda_i2c.c
> +++ b/sound/pci/hda/cs35l41_hda_i2c.c
> @@ -30,11 +30,9 @@ static int cs35l41_hda_i2c_probe(struct i2c_client
> *clt, const struct i2c_device
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 devm_regmap_init_i2c(clt,
> &cs35l41_regmap_i2c));
> =C2=A0}
> =C2=A0
> -static int cs35l41_hda_i2c_remove(struct i2c_client *clt)
> +static void cs35l41_hda_i2c_remove(struct i2c_client *clt)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cs35l41_hda_remove(&clt->=
dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cs35l41_hda_i2c_id[] =3D {
> diff --git a/sound/ppc/keywest.c b/sound/ppc/keywest.c
> index 6e5daae18f9d..80e5108157ef 100644
> --- a/sound/ppc/keywest.c
> +++ b/sound/ppc/keywest.c
> @@ -71,14 +71,12 @@ static int keywest_attach_adapter(struct
> i2c_adapter *adapter)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int keywest_remove(struct i2c_client *client)
> +static void keywest_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (! keywest_ctx)
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return 0;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0return;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (client =3D=3D keywest=
_ctx->client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0keywest_ctx->client =3D NULL;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/sound/soc/codecs/adau1761-i2c.c
> b/sound/soc/codecs/adau1761-i2c.c
> index 0683caf86aea..0cefff49569c 100644
> --- a/sound/soc/codecs/adau1761-i2c.c
> +++ b/sound/soc/codecs/adau1761-i2c.c
> @@ -30,10 +30,9 @@ static int adau1761_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0id->driver_data, NULL);
> =C2=A0}
> =C2=A0
> -static int adau1761_i2c_remove(struct i2c_client *client)
> +static void adau1761_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adau17x1_remove(&client->=
dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adau1761_i2c_ids[] =3D {
> diff --git a/sound/soc/codecs/adau1781-i2c.c
> b/sound/soc/codecs/adau1781-i2c.c
> index e046de0ebcc7..39021b8cfb62 100644
> --- a/sound/soc/codecs/adau1781-i2c.c
> +++ b/sound/soc/codecs/adau1781-i2c.c
> @@ -30,10 +30,9 @@ static int adau1781_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0id->driver_data, NULL);
> =C2=A0}
> =C2=A0
> -static int adau1781_i2c_remove(struct i2c_client *client)
> +static void adau1781_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adau17x1_remove(&client->=
dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id adau1781_i2c_ids[] =3D {
> diff --git a/sound/soc/codecs/ak4375.c b/sound/soc/codecs/ak4375.c
> index 9a7b662016b9..bfed08fe4b9e 100644
> --- a/sound/soc/codecs/ak4375.c
> +++ b/sound/soc/codecs/ak4375.c
> @@ -581,11 +581,9 @@ static int ak4375_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ak4375_i2c_remove(struct i2c_client *i2c)
> +static void ak4375_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&i2c->=
dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id ak4375_of_match[] =3D {
> diff --git a/sound/soc/codecs/ak4458.c b/sound/soc/codecs/ak4458.c
> index baa9ff5d0ce5..919aa0973050 100644
> --- a/sound/soc/codecs/ak4458.c
> +++ b/sound/soc/codecs/ak4458.c
> @@ -826,11 +826,9 @@ static int ak4458_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ak4458_i2c_remove(struct i2c_client *i2c)
> +static void ak4458_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&i2c->=
dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id ak4458_of_match[] =3D {
> diff --git a/sound/soc/codecs/ak4641.c b/sound/soc/codecs/ak4641.c
> index d8d9cc712d67..65a11cd39a43 100644
> --- a/sound/soc/codecs/ak4641.c
> +++ b/sound/soc/codecs/ak4641.c
> @@ -605,7 +605,7 @@ static int ak4641_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int ak4641_i2c_remove(struct i2c_client *i2c)
> +static void ak4641_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct ak4641_platform_da=
ta *pdata =3D i2c->dev.platform_data;
> =C2=A0
> @@ -617,8 +617,6 @@ static int ak4641_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0if (gpio_is_valid(pdata->gpio_npdn))
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpi=
o_free(pdata->gpio_npdn);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id ak4641_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/ak5558.c b/sound/soc/codecs/ak5558.c
> index c94cfde3e4a8..df8140907ac5 100644
> --- a/sound/soc/codecs/ak5558.c
> +++ b/sound/soc/codecs/ak5558.c
> @@ -481,11 +481,9 @@ static int ak5558_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int ak5558_i2c_remove(struct i2c_client *i2c)
> +static void ak5558_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&i2c->=
dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id ak5558_i2c_dt_ids[] __maybe_unused
> =3D {
> diff --git a/sound/soc/codecs/cs35l32.c b/sound/soc/codecs/cs35l32.c
> index badfc55bc5fa..7aec12688da9 100644
> --- a/sound/soc/codecs/cs35l32.c
> +++ b/sound/soc/codecs/cs35l32.c
> @@ -498,14 +498,12 @@ static int cs35l32_i2c_probe(struct i2c_client
> *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs35l32_i2c_remove(struct i2c_client *i2c_client)
> +static void cs35l32_i2c_remove(struct i2c_client *i2c_client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs35l32_private *c=
s35l32 =3D
> i2c_get_clientdata(i2c_client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Hold down reset */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(=
cs35l32->reset_gpio, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/sound/soc/codecs/cs35l33.c b/sound/soc/codecs/cs35l33.c
> index 47dc0f6d90a2..46972c86fd88 100644
> --- a/sound/soc/codecs/cs35l33.c
> +++ b/sound/soc/codecs/cs35l33.c
> @@ -1251,7 +1251,7 @@ static int cs35l33_i2c_probe(struct i2c_client
> *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs35l33_i2c_remove(struct i2c_client *client)
> +static void cs35l33_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs35l33_private *c=
s35l33 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1260,8 +1260,6 @@ static int cs35l33_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(cs=
35l33->num_core_supplies,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0cs35l33->core_supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id cs35l33_of_match[] =3D {
> diff --git a/sound/soc/codecs/cs35l34.c b/sound/soc/codecs/cs35l34.c
> index 50d509a06071..c36b824b66e6 100644
> --- a/sound/soc/codecs/cs35l34.c
> +++ b/sound/soc/codecs/cs35l34.c
> @@ -1129,7 +1129,7 @@ static int cs35l34_i2c_probe(struct i2c_client
> *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs35l34_i2c_remove(struct i2c_client *client)
> +static void cs35l34_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs35l34_private *c=
s35l34 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1138,8 +1138,6 @@ static int cs35l34_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(cs=
35l34->num_core_supplies,
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0cs35l34->core_supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused cs35l34_runtime_resume(struct device *dev=
)
> diff --git a/sound/soc/codecs/cs35l35.c b/sound/soc/codecs/cs35l35.c
> index 6b70afb70a67..0f6968a29ace 100644
> --- a/sound/soc/codecs/cs35l35.c
> +++ b/sound/soc/codecs/cs35l35.c
> @@ -1628,14 +1628,12 @@ static int cs35l35_i2c_probe(struct
> i2c_client *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs35l35_i2c_remove(struct i2c_client *i2c_client)
> +static void cs35l35_i2c_remove(struct i2c_client *i2c_client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs35l35_private *c=
s35l35 =3D
> i2c_get_clientdata(i2c_client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(cs=
35l35->num_supplies, cs35l35-
> >supplies);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(=
cs35l35->reset_gpio, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id cs35l35_of_match[] =3D {
> diff --git a/sound/soc/codecs/cs35l36.c b/sound/soc/codecs/cs35l36.c
> index dfe85dc2cd20..80844471309d 100644
> --- a/sound/soc/codecs/cs35l36.c
> +++ b/sound/soc/codecs/cs35l36.c
> @@ -1911,7 +1911,7 @@ static int cs35l36_i2c_probe(struct i2c_client
> *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs35l36_i2c_remove(struct i2c_client *client)
> +static void cs35l36_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs35l36_private *c=
s35l36 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1925,8 +1925,6 @@ static int cs35l36_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(cs35l36->reset_gpio, 0);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(cs=
35l36->num_supplies, cs35l36-
> >supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0static const struct of_device_id cs35l36_of_match[] =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0{.compatible =3D "cirrus,=
cs35l36"},
> diff --git a/sound/soc/codecs/cs35l41-i2c.c
> b/sound/soc/codecs/cs35l41-i2c.c
> index 37c703c08fd5..3676b596f60b 100644
> --- a/sound/soc/codecs/cs35l41-i2c.c
> +++ b/sound/soc/codecs/cs35l41-i2c.c
> @@ -56,13 +56,11 @@ static int cs35l41_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return cs35l41_probe(cs35=
l41, hw_cfg);
> =C2=A0}
> =C2=A0
> -static int cs35l41_i2c_remove(struct i2c_client *client)
> +static void cs35l41_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs35l41_private *c=
s35l41 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cs35l41_remove(cs35l41);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_OF
> diff --git a/sound/soc/codecs/cs35l45-i2c.c
> b/sound/soc/codecs/cs35l45-i2c.c
> index 06c2ddffb9c5..39d28641429e 100644
> --- a/sound/soc/codecs/cs35l45-i2c.c
> +++ b/sound/soc/codecs/cs35l45-i2c.c
> @@ -36,13 +36,11 @@ static int cs35l45_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return cs35l45_probe(cs35=
l45);
> =C2=A0}
> =C2=A0
> -static int cs35l45_i2c_remove(struct i2c_client *client)
> +static void cs35l45_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs35l45_private *c=
s35l45 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cs35l45_remove(cs35l45);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id cs35l45_of_match[] =3D {
> diff --git a/sound/soc/codecs/cs4234.c b/sound/soc/codecs/cs4234.c
> index 881c5ba70c0e..18bddeb63762 100644
> --- a/sound/soc/codecs/cs4234.c
> +++ b/sound/soc/codecs/cs4234.c
> @@ -851,7 +851,7 @@ static int cs4234_i2c_probe(struct i2c_client
> *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs4234_i2c_remove(struct i2c_client *i2c_client)
> +static void cs4234_i2c_remove(struct i2c_client *i2c_client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs4234 *cs4234 =3D=
 i2c_get_clientdata(i2c_client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &i=
2c_client->dev;
> @@ -859,8 +859,6 @@ static int cs4234_i2c_remove(struct i2c_client
> *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0snd_soc_unregister_compon=
ent(dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cs4234_shutdown(cs4234);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused cs4234_runtime_resume(struct device *dev)
> diff --git a/sound/soc/codecs/cs4265.c b/sound/soc/codecs/cs4265.c
> index 86bfa8d5ec78..c16c0a0d3b56 100644
> --- a/sound/soc/codecs/cs4265.c
> +++ b/sound/soc/codecs/cs4265.c
> @@ -624,14 +624,12 @@ static int cs4265_i2c_probe(struct i2c_client
> *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0ARR=
AY_SIZE(cs4265_dai));
> =C2=A0}
> =C2=A0
> -static int cs4265_i2c_remove(struct i2c_client *i2c)
> +static void cs4265_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs4265_private *cs=
4265 =3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (cs4265->reset_gpio)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(cs4265->reset_gpio, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id cs4265_of_match[] =3D {
> diff --git a/sound/soc/codecs/cs4270.c b/sound/soc/codecs/cs4270.c
> index 531f63b01554..6bfddb1b9968 100644
> --- a/sound/soc/codecs/cs4270.c
> +++ b/sound/soc/codecs/cs4270.c
> @@ -651,13 +651,11 @@ static const struct regmap_config cs4270_regmap
> =3D {
> =C2=A0 * This function puts the chip into low power mode when the i2c
> device
> =C2=A0 * is removed.
> =C2=A0 */
> -static int cs4270_i2c_remove(struct i2c_client *i2c_client)
> +static void cs4270_i2c_remove(struct i2c_client *i2c_client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs4270_private *cs=
4270 =3D
> i2c_get_clientdata(i2c_client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(=
cs4270->reset_gpio, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0/**
> diff --git a/sound/soc/codecs/cs42l42.c b/sound/soc/codecs/cs42l42.c
> index 4fade2388797..ab848fe5f721 100644
> --- a/sound/soc/codecs/cs42l42.c
> +++ b/sound/soc/codecs/cs42l42.c
> @@ -2342,7 +2342,7 @@ static int cs42l42_i2c_probe(struct i2c_client
> *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs42l42_i2c_remove(struct i2c_client *i2c_client)
> +static void cs42l42_i2c_remove(struct i2c_client *i2c_client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs42l42_private *c=
s42l42 =3D
> i2c_get_clientdata(i2c_client);
> =C2=A0
> @@ -2359,8 +2359,6 @@ static int cs42l42_i2c_remove(struct i2c_client
> *i2c_client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(=
cs42l42->reset_gpio, 0);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(cs42l42->supplies),
> cs42l42->supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops cs42l42_pm_ops =3D {
> diff --git a/sound/soc/codecs/cs42l51-i2c.c
> b/sound/soc/codecs/cs42l51-i2c.c
> index 3613fb12d623..85238339fbca 100644
> --- a/sound/soc/codecs/cs42l51-i2c.c
> +++ b/sound/soc/codecs/cs42l51-i2c.c
> @@ -28,11 +28,9 @@ static int cs42l51_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return cs42l51_probe(&i2c=
->dev, devm_regmap_init_i2c(i2c,
> &config));
> =C2=A0}
> =C2=A0
> -static int cs42l51_i2c_remove(struct i2c_client *i2c)
> +static void cs42l51_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cs42l51_remove(&i2c->dev)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct dev_pm_ops cs42l51_pm_ops =3D {
> diff --git a/sound/soc/codecs/cs42l56.c b/sound/soc/codecs/cs42l56.c
> index 510c94265b1f..d1cae24d015f 100644
> --- a/sound/soc/codecs/cs42l56.c
> +++ b/sound/soc/codecs/cs42l56.c
> @@ -1321,13 +1321,12 @@ static int cs42l56_i2c_probe(struct
> i2c_client *i2c_client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs42l56_i2c_remove(struct i2c_client *client)
> +static void cs42l56_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs42l56_private *c=
s42l56 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(cs42l56->supplies),
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 cs42l56->supplies);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id cs42l56_of_match[] =3D {
> diff --git a/sound/soc/codecs/cs42xx8-i2c.c
> b/sound/soc/codecs/cs42xx8-i2c.c
> index cb06a06d48b0..bd80e9fc907f 100644
> --- a/sound/soc/codecs/cs42xx8-i2c.c
> +++ b/sound/soc/codecs/cs42xx8-i2c.c
> @@ -30,11 +30,9 @@ static int cs42xx8_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int cs42xx8_i2c_remove(struct i2c_client *i2c)
> +static void cs42xx8_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&i2c->=
dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_device_id cs42xx8_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/cs43130.c b/sound/soc/codecs/cs43130.c
> index a2bce0f9f247..944bb9a26ca9 100644
> --- a/sound/soc/codecs/cs43130.c
> +++ b/sound/soc/codecs/cs43130.c
> @@ -2584,7 +2584,7 @@ static int cs43130_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs43130_i2c_remove(struct i2c_client *client)
> +static void cs43130_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs43130_private *c=
s43130 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -2611,8 +2611,6 @@ static int cs43130_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(CS=
43130_NUM_SUPPLIES, cs43130-
> >supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused cs43130_runtime_suspend(struct device
> *dev)
> diff --git a/sound/soc/codecs/cs4349.c b/sound/soc/codecs/cs4349.c
> index 7069e9b54857..41472ed22209 100644
> --- a/sound/soc/codecs/cs4349.c
> +++ b/sound/soc/codecs/cs4349.c
> @@ -306,14 +306,12 @@ static int cs4349_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0&cs4349_dai, 1);
> =C2=A0}
> =C2=A0
> -static int cs4349_i2c_remove(struct i2c_client *client)
> +static void cs4349_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs4349_private *cs=
4349 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Hold down reset */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(=
cs4349->reset_gpio, 0);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/sound/soc/codecs/cs53l30.c b/sound/soc/codecs/cs53l30.c
> index 360ca2ffd506..71298a18ee1a 100644
> --- a/sound/soc/codecs/cs53l30.c
> +++ b/sound/soc/codecs/cs53l30.c
> @@ -1044,7 +1044,7 @@ static int cs53l30_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int cs53l30_i2c_remove(struct i2c_client *client)
> +static void cs53l30_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct cs53l30_private *c=
s53l30 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1053,8 +1053,6 @@ static int cs53l30_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(cs53l30->supplies),
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 cs53l30->supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/sound/soc/codecs/cx2072x.c b/sound/soc/codecs/cx2072x.c
> index b35debb5818d..c24915f7dec3 100644
> --- a/sound/soc/codecs/cx2072x.c
> +++ b/sound/soc/codecs/cx2072x.c
> @@ -1676,10 +1676,9 @@ static int cx2072x_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int cx2072x_i2c_remove(struct i2c_client *i2c)
> +static void cx2072x_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&i2c->=
dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id cx2072x_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/max98090.c
> b/sound/soc/codecs/max98090.c
> index 576277a82d41..416e6f660541 100644
> --- a/sound/soc/codecs/max98090.c
> +++ b/sound/soc/codecs/max98090.c
> @@ -2618,11 +2618,9 @@ static void max98090_i2c_shutdown(struct
> i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0msleep(40);
> =C2=A0}
> =C2=A0
> -static int max98090_i2c_remove(struct i2c_client *client)
> +static void max98090_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0max98090_i2c_shutdown(cli=
ent);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/sound/soc/codecs/max9860.c b/sound/soc/codecs/max9860.c
> index 82f20a8e27ad..2b0d0298da83 100644
> --- a/sound/soc/codecs/max9860.c
> +++ b/sound/soc/codecs/max9860.c
> @@ -702,14 +702,13 @@ static int max9860_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int max9860_remove(struct i2c_client *i2c)
> +static void max9860_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &i=
2c->dev;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max9860_priv *max9=
860 =3D dev_get_drvdata(dev);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(max9860=
->dvddio);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max9860_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/max98927.c
> b/sound/soc/codecs/max98927.c
> index b7cff76d7b5b..c9694ba9c341 100644
> --- a/sound/soc/codecs/max98927.c
> +++ b/sound/soc/codecs/max98927.c
> @@ -935,15 +935,13 @@ static int max98927_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int max98927_i2c_remove(struct i2c_client *i2c)
> +static void max98927_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct max98927_priv *max=
98927 =3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (max98927->reset_gpio)=
 {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value_cansleep(max98927->reset_gpio, 1);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id max98927_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/mt6660.c b/sound/soc/codecs/mt6660.c
> index ba11555796ad..4971cd0b90f8 100644
> --- a/sound/soc/codecs/mt6660.c
> +++ b/sound/soc/codecs/mt6660.c
> @@ -516,14 +516,13 @@ static int mt6660_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int mt6660_i2c_remove(struct i2c_client *client)
> +static void mt6660_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mt6660_chip *chip =
=3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(chip->=
dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
chip->dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_destroy(&chip->io_l=
ock);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused mt6660_i2c_runtime_suspend(struct device
> *dev)
> diff --git a/sound/soc/codecs/nau8821.c b/sound/soc/codecs/nau8821.c
> index ce4e7f46bb06..dcae41ba2e02 100644
> --- a/sound/soc/codecs/nau8821.c
> +++ b/sound/soc/codecs/nau8821.c
> @@ -1665,13 +1665,11 @@ static int nau8821_i2c_probe(struct
> i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int nau8821_i2c_remove(struct i2c_client *i2c_client)
> +static void nau8821_i2c_remove(struct i2c_client *i2c_client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct nau8821 *nau8821 =
=3D i2c_get_clientdata(i2c_client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0devm_free_irq(nau8821->de=
v, nau8821->irq, nau8821);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id nau8821_i2c_ids[] =3D {
> diff --git a/sound/soc/codecs/nau8825.c b/sound/soc/codecs/nau8825.c
> index 20e45a337b8f..bd34c84507da 100644
> --- a/sound/soc/codecs/nau8825.c
> +++ b/sound/soc/codecs/nau8825.c
> @@ -2669,10 +2669,8 @@ static int nau8825_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0&nau8825_dai, 1);
> =C2=A0}
> =C2=A0
> -static int nau8825_i2c_remove(struct i2c_client *client)
> -{
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> -}
> +static void nau8825_i2c_remove(struct i2c_client *client)
> +{}
> =C2=A0
> =C2=A0static const struct i2c_device_id nau8825_i2c_ids[] =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0{ "nau8825", 0 },
> diff --git a/sound/soc/codecs/pcm1789-i2c.c
> b/sound/soc/codecs/pcm1789-i2c.c
> index 1d2f7480a6e4..fafe0dcbe4ea 100644
> --- a/sound/soc/codecs/pcm1789-i2c.c
> +++ b/sound/soc/codecs/pcm1789-i2c.c
> @@ -27,11 +27,9 @@ static int pcm1789_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return pcm1789_common_ini=
t(&client->dev, regmap);
> =C2=A0}
> =C2=A0
> -static int pcm1789_i2c_remove(struct i2c_client *client)
> +static void pcm1789_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pcm1789_common_exit(&clie=
nt->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_OF
> diff --git a/sound/soc/codecs/pcm3168a-i2c.c
> b/sound/soc/codecs/pcm3168a-i2c.c
> index c0fa0dc80e8f..a0eec82e9872 100644
> --- a/sound/soc/codecs/pcm3168a-i2c.c
> +++ b/sound/soc/codecs/pcm3168a-i2c.c
> @@ -26,11 +26,9 @@ static int pcm3168a_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return pcm3168a_probe(&i2=
c->dev, regmap);
> =C2=A0}
> =C2=A0
> -static int pcm3168a_i2c_remove(struct i2c_client *i2c)
> +static void pcm3168a_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pcm3168a_remove(&i2c->dev=
);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id pcm3168a_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/pcm512x-i2c.c
> b/sound/soc/codecs/pcm512x-i2c.c
> index 81754e141a55..9dfbbe8f4a0b 100644
> --- a/sound/soc/codecs/pcm512x-i2c.c
> +++ b/sound/soc/codecs/pcm512x-i2c.c
> @@ -29,10 +29,9 @@ static int pcm512x_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return pcm512x_probe(&i2c=
->dev, regmap);
> =C2=A0}
> =C2=A0
> -static int pcm512x_i2c_remove(struct i2c_client *i2c)
> +static void pcm512x_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pcm512x_remove(&i2c->dev)=
;
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id pcm512x_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/rt274.c b/sound/soc/codecs/rt274.c
> index ab093bdb5552..cb2147f86818 100644
> --- a/sound/soc/codecs/rt274.c
> +++ b/sound/soc/codecs/rt274.c
> @@ -1207,14 +1207,12 @@ static int rt274_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rt274_i2c_remove(struct i2c_client *i2c)
> +static void rt274_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt274_priv *rt274 =
=3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (i2c->irq)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(i2c->irq, rt274);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/sound/soc/codecs/rt286.c b/sound/soc/codecs/rt286.c
> index ad8ea1fa7c23..c66db0760a0f 100644
> --- a/sound/soc/codecs/rt286.c
> +++ b/sound/soc/codecs/rt286.c
> @@ -1254,14 +1254,12 @@ static int rt286_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rt286_i2c_remove(struct i2c_client *i2c)
> +static void rt286_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt286_priv *rt286 =
=3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (i2c->irq)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(i2c->irq, rt286);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/sound/soc/codecs/rt298.c b/sound/soc/codecs/rt298.c
> index c291786dc82d..9f44eabfdbdb 100644
> --- a/sound/soc/codecs/rt298.c
> +++ b/sound/soc/codecs/rt298.c
> @@ -1297,14 +1297,12 @@ static int rt298_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rt298_i2c_remove(struct i2c_client *i2c)
> +static void rt298_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt298_priv *rt298 =
=3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (i2c->irq)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(i2c->irq, rt298);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0
> diff --git a/sound/soc/codecs/rt5616.c b/sound/soc/codecs/rt5616.c
> index 37f1bf552eff..7a994abeedb0 100644
> --- a/sound/soc/codecs/rt5616.c
> +++ b/sound/soc/codecs/rt5616.c
> @@ -1389,10 +1389,8 @@ static int rt5616_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 rt5616_dai,
> ARRAY_SIZE(rt5616_dai));
> =C2=A0}
> =C2=A0
> -static int rt5616_i2c_remove(struct i2c_client *i2c)
> -{
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> -}
> +static void rt5616_i2c_remove(struct i2c_client *i2c)
> +{}
> =C2=A0
> =C2=A0static void rt5616_i2c_shutdown(struct i2c_client *client)
> =C2=A0{
> diff --git a/sound/soc/codecs/rt5631.c b/sound/soc/codecs/rt5631.c
> index c941e878471c..d82264edd25c 100644
> --- a/sound/soc/codecs/rt5631.c
> +++ b/sound/soc/codecs/rt5631.c
> @@ -1721,10 +1721,8 @@ static int rt5631_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rt5631_i2c_remove(struct i2c_client *client)
> -{
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> -}
> +static void rt5631_i2c_remove(struct i2c_client *client)
> +{}
> =C2=A0
> =C2=A0static struct i2c_driver rt5631_i2c_driver =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0.driver =3D {
> diff --git a/sound/soc/codecs/rt5645.c b/sound/soc/codecs/rt5645.c
> index 507aba8de3cc..e77bdbc1a098 100644
> --- a/sound/soc/codecs/rt5645.c
> +++ b/sound/soc/codecs/rt5645.c
> @@ -4146,7 +4146,7 @@ static int rt5645_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rt5645_i2c_remove(struct i2c_client *i2c)
> +static void rt5645_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt5645_priv *rt564=
5 =3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -4163,8 +4163,6 @@ static int rt5645_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0cancel_delayed_work_sync(=
&rt5645->rcclock_work);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(rt5645->supplies), rt5645-
> >supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void rt5645_i2c_shutdown(struct i2c_client *i2c)
> diff --git a/sound/soc/codecs/rt5663.c b/sound/soc/codecs/rt5663.c
> index e51eed8a79ab..15296e0fa545 100644
> --- a/sound/soc/codecs/rt5663.c
> +++ b/sound/soc/codecs/rt5663.c
> @@ -3711,7 +3711,7 @@ static int rt5663_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rt5663_i2c_remove(struct i2c_client *i2c)
> +static void rt5663_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct rt5663_priv *rt566=
3 =3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -3719,8 +3719,6 @@ static int rt5663_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(i2c->irq, rt5663);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(rt5663->supplies), rt5663-
> >supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static void rt5663_i2c_shutdown(struct i2c_client *client)
> diff --git a/sound/soc/codecs/rt5670.c b/sound/soc/codecs/rt5670.c
> index 8a97f6db04d5..eb73e262457c 100644
> --- a/sound/soc/codecs/rt5670.c
> +++ b/sound/soc/codecs/rt5670.c
> @@ -3321,11 +3321,9 @@ static int rt5670_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int rt5670_i2c_remove(struct i2c_client *i2c)
> +static void rt5670_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&i2c->=
dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver rt5670_i2c_driver =3D {
> diff --git a/sound/soc/codecs/rt5677.c b/sound/soc/codecs/rt5677.c
> index 4a8c267d4fbc..3161022f0757 100644
> --- a/sound/soc/codecs/rt5677.c
> +++ b/sound/soc/codecs/rt5677.c
> @@ -5694,11 +5694,9 @@ static int rt5677_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 rt5677_dai,
> ARRAY_SIZE(rt5677_dai));
> =C2=A0}
> =C2=A0
> -static int rt5677_i2c_remove(struct i2c_client *i2c)
> +static void rt5677_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rt5677_free_gpio(i2c);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static struct i2c_driver rt5677_i2c_driver =3D {
> diff --git a/sound/soc/codecs/rt5682-i2c.c b/sound/soc/codecs/rt5682-
> i2c.c
> index 3f72f6093436..2935c1bb81f3 100644
> --- a/sound/soc/codecs/rt5682-i2c.c
> +++ b/sound/soc/codecs/rt5682-i2c.c
> @@ -302,11 +302,9 @@ static void rt5682_i2c_shutdown(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rt5682_reset(rt5682);
> =C2=A0}
> =C2=A0
> -static int rt5682_i2c_remove(struct i2c_client *client)
> +static void rt5682_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rt5682_i2c_shutdown(clien=
t);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id rt5682_of_match[] =3D {
> diff --git a/sound/soc/codecs/rt5682s.c b/sound/soc/codecs/rt5682s.c
> index 4d44eddee901..a80c686613f4 100644
> --- a/sound/soc/codecs/rt5682s.c
> +++ b/sound/soc/codecs/rt5682s.c
> @@ -3195,11 +3195,9 @@ static void rt5682s_i2c_shutdown(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rt5682s_reset(rt5682s);
> =C2=A0}
> =C2=A0
> -static int rt5682s_i2c_remove(struct i2c_client *client)
> +static void rt5682s_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0rt5682s_i2c_shutdown(clie=
nt);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id rt5682s_of_match[] =3D {
> diff --git a/sound/soc/codecs/rt9120.c b/sound/soc/codecs/rt9120.c
> index da495bdc8415..644300e88b4c 100644
> --- a/sound/soc/codecs/rt9120.c
> +++ b/sound/soc/codecs/rt9120.c
> @@ -572,11 +572,10 @@ static int rt9120_probe(struct i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 &rt9120_dai, 1);
> =C2=A0}
> =C2=A0
> -static int rt9120_remove(struct i2c_client *i2c)
> +static void rt9120_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&i2c->=
dev);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_set_suspended(=
&i2c->dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static int __maybe_unused rt9120_runtime_suspend(struct device *dev=
)
> diff --git a/sound/soc/codecs/sgtl5000.c
> b/sound/soc/codecs/sgtl5000.c
> index 2aa48aef6a97..f29bd50fe4cd 100644
> --- a/sound/soc/codecs/sgtl5000.c
> +++ b/sound/soc/codecs/sgtl5000.c
> @@ -1791,15 +1791,13 @@ static int sgtl5000_i2c_probe(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int sgtl5000_i2c_remove(struct i2c_client *client)
> +static void sgtl5000_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct sgtl5000_priv *sgt=
l5000 =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0clk_disable_unprepare(sgt=
l5000->mclk);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(sg=
tl5000->num_supplies, sgtl5000-
> >supplies);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_free(sgtl5=
000->num_supplies, sgtl5000-
> >supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id sgtl5000_id[] =3D {
> diff --git a/sound/soc/codecs/sta350.c b/sound/soc/codecs/sta350.c
> index 9189fb3648f7..0676c822458f 100644
> --- a/sound/soc/codecs/sta350.c
> +++ b/sound/soc/codecs/sta350.c
> @@ -1243,10 +1243,8 @@ static int sta350_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int sta350_i2c_remove(struct i2c_client *client)
> -{
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> -}
> +static void sta350_i2c_remove(struct i2c_client *client)
> +{}
> =C2=A0
> =C2=A0static const struct i2c_device_id sta350_i2c_id[] =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0{ "sta350", 0 },
> diff --git a/sound/soc/codecs/tas2552.c b/sound/soc/codecs/tas2552.c
> index b5c9c61ff5a8..0259ae96d97e 100644
> --- a/sound/soc/codecs/tas2552.c
> +++ b/sound/soc/codecs/tas2552.c
> @@ -737,10 +737,9 @@ static int tas2552_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tas2552_i2c_remove(struct i2c_client *client)
> +static void tas2552_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tas2552_id[] =3D {
> diff --git a/sound/soc/codecs/tas5086.c b/sound/soc/codecs/tas5086.c
> index 5c0df3cd4832..b0a73244ee31 100644
> --- a/sound/soc/codecs/tas5086.c
> +++ b/sound/soc/codecs/tas5086.c
> @@ -982,10 +982,8 @@ static int tas5086_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tas5086_i2c_remove(struct i2c_client *i2c)
> -{
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> -}
> +static void tas5086_i2c_remove(struct i2c_client *i2c)
> +{}
> =C2=A0
> =C2=A0static struct i2c_driver tas5086_i2c_driver =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0.driver =3D {
> diff --git a/sound/soc/codecs/tas571x.c b/sound/soc/codecs/tas571x.c
> index 7b599664db20..1a060e85621f 100644
> --- a/sound/soc/codecs/tas571x.c
> +++ b/sound/soc/codecs/tas571x.c
> @@ -885,13 +885,11 @@ static int tas571x_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tas571x_i2c_remove(struct i2c_client *client)
> +static void tas571x_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tas571x_private *p=
riv =3D i2c_get_clientdata(client);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(pr=
iv->chip->num_supply_names, priv-
> >supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id tas571x_of_match[] __maybe_unused =
=3D
> {
> diff --git a/sound/soc/codecs/tas5805m.c
> b/sound/soc/codecs/tas5805m.c
> index fa0e81ec875a..4782d9c47992 100644
> --- a/sound/soc/codecs/tas5805m.c
> +++ b/sound/soc/codecs/tas5805m.c
> @@ -523,7 +523,7 @@ static int tas5805m_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int tas5805m_i2c_remove(struct i2c_client *i2c)
> +static void tas5805m_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &i=
2c->dev;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tas5805m_priv *tas=
5805m =3D dev_get_drvdata(dev);
> @@ -532,7 +532,6 @@ static int tas5805m_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0gpiod_set_value(tas5805m-=
>gpio_pdn_n, 0);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0usleep_range(10000, 15000=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_disable(tas5805=
m->pvdd);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tas5805m_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/tas6424.c b/sound/soc/codecs/tas6424.c
> index 22b53856e691..fd1f37d48982 100644
> --- a/sound/soc/codecs/tas6424.c
> +++ b/sound/soc/codecs/tas6424.c
> @@ -775,7 +775,7 @@ static int tas6424_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int tas6424_i2c_remove(struct i2c_client *client)
> +static void tas6424_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct device *dev =3D &c=
lient->dev;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tas6424_data *tas6=
424 =3D dev_get_drvdata(dev);
> @@ -791,8 +791,6 @@ static int tas6424_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 tas64=
24->supplies);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (ret < 0)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0dev_err(dev, "unable to disable supplies: %d\n",
> ret);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tas6424_i2c_ids[] =3D {
> diff --git a/sound/soc/codecs/tlv320adc3xxx.c
> b/sound/soc/codecs/tlv320adc3xxx.c
> index 82532ad00c3c..82d78e7c610e 100644
> --- a/sound/soc/codecs/tlv320adc3xxx.c
> +++ b/sound/soc/codecs/tlv320adc3xxx.c
> @@ -1427,7 +1427,7 @@ static int adc3xxx_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int __exit adc3xxx_i2c_remove(struct i2c_client *client)
> +static void __exit adc3xxx_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct adc3xxx *adc3xxx =
=3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1435,7 +1435,6 @@ static int __exit adc3xxx_i2c_remove(struct
> i2c_client *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0clk_disable_unprepare(adc3xxx->mclk);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0adc3xxx_free_gpio(adc3xxx=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0snd_soc_unregister_compon=
ent(&client->dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id tlv320adc3xxx_of_match[] =3D {
> diff --git a/sound/soc/codecs/tlv320aic32x4-i2c.c
> b/sound/soc/codecs/tlv320aic32x4-i2c.c
> index 0645239901b1..d1e543ca3521 100644
> --- a/sound/soc/codecs/tlv320aic32x4-i2c.c
> +++ b/sound/soc/codecs/tlv320aic32x4-i2c.c
> @@ -45,11 +45,9 @@ static int aic32x4_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return aic32x4_probe(&i2c=
->dev, regmap);
> =C2=A0}
> =C2=A0
> -static int aic32x4_i2c_remove(struct i2c_client *i2c)
> +static void aic32x4_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0aic32x4_remove(&i2c->dev)=
;
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id aic32x4_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/tlv320aic3x-i2c.c
> b/sound/soc/codecs/tlv320aic3x-i2c.c
> index 7bd9ce08bb7b..d7e94d564dbf 100644
> --- a/sound/soc/codecs/tlv320aic3x-i2c.c
> +++ b/sound/soc/codecs/tlv320aic3x-i2c.c
> @@ -41,11 +41,9 @@ static int aic3x_i2c_probe(struct i2c_client *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return aic3x_probe(&i2c->=
dev, regmap, id->driver_data);
> =C2=A0}
> =C2=A0
> -static int aic3x_i2c_remove(struct i2c_client *i2c)
> +static void aic3x_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0aic3x_remove(&i2c->dev);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id aic3x_of_id[] =3D {
> diff --git a/sound/soc/codecs/tlv320dac33.c
> b/sound/soc/codecs/tlv320dac33.c
> index 66f1d1cd6cf0..8a86bfe8266c 100644
> --- a/sound/soc/codecs/tlv320dac33.c
> +++ b/sound/soc/codecs/tlv320dac33.c
> @@ -1539,7 +1539,7 @@ static int dac33_i2c_probe(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int dac33_i2c_remove(struct i2c_client *client)
> +static void dac33_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct tlv320dac33_priv *=
dac33 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -1548,8 +1548,6 @@ static int dac33_i2c_remove(struct i2c_client
> *client)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (dac33->power_gpio >=
=3D 0)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpio_free(dac33->power_gpio);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id tlv320dac33_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/wm1250-ev1.c b/sound/soc/codecs/wm1250-
> ev1.c
> index b6366dea15a6..49dbd19d26cc 100644
> --- a/sound/soc/codecs/wm1250-ev1.c
> +++ b/sound/soc/codecs/wm1250-ev1.c
> @@ -229,11 +229,9 @@ static int wm1250_ev1_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int wm1250_ev1_remove(struct i2c_client *i2c)
> +static void wm1250_ev1_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0wm1250_ev1_free(i2c);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm1250_ev1_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/wm2200.c b/sound/soc/codecs/wm2200.c
> index 1cd544580c83..8557c33eeee7 100644
> --- a/sound/soc/codecs/wm2200.c
> +++ b/sound/soc/codecs/wm2200.c
> @@ -2415,7 +2415,7 @@ static int wm2200_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int wm2200_i2c_remove(struct i2c_client *i2c)
> +static void wm2200_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wm2200_priv *wm220=
0 =3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -2428,8 +2428,6 @@ static int wm2200_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpio_set_value_cansleep(wm2200->pdata.ldo_ena, 0);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(wm2200->core_supplies),
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 wm2200->core_supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/sound/soc/codecs/wm5100.c b/sound/soc/codecs/wm5100.c
> index a89870918174..211ef8190c61 100644
> --- a/sound/soc/codecs/wm5100.c
> +++ b/sound/soc/codecs/wm5100.c
> @@ -2636,7 +2636,7 @@ static int wm5100_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int wm5100_i2c_remove(struct i2c_client *i2c)
> +static void wm5100_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wm5100_priv *wm510=
0 =3D i2c_get_clientdata(i2c);
> =C2=A0
> @@ -2652,8 +2652,6 @@ static int wm5100_i2c_remove(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpio_set_value_cansleep(wm5100->pdata.ldo_ena, 0);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpio_free(wm5100->pdata.ldo_ena);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/sound/soc/codecs/wm8804-i2c.c b/sound/soc/codecs/wm8804-
> i2c.c
> index 04dc9fb5afb4..3ce1a39d76eb 100644
> --- a/sound/soc/codecs/wm8804-i2c.c
> +++ b/sound/soc/codecs/wm8804-i2c.c
> @@ -25,10 +25,9 @@ static int wm8804_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return wm8804_probe(&i2c-=
>dev, regmap);
> =C2=A0}
> =C2=A0
> -static int wm8804_i2c_remove(struct i2c_client *i2c)
> +static void wm8804_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0wm8804_remove(&i2c->dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm8804_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/wm8900.c b/sound/soc/codecs/wm8900.c
> index 84a3daf0c11e..28e296f2f969 100644
> --- a/sound/soc/codecs/wm8900.c
> +++ b/sound/soc/codecs/wm8900.c
> @@ -1283,10 +1283,8 @@ static int wm8900_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int wm8900_i2c_remove(struct i2c_client *client)
> -{
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> -}
> +static void wm8900_i2c_remove(struct i2c_client *client)
> +{}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm8900_i2c_id[] =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0{ "wm8900", 0 },
> diff --git a/sound/soc/codecs/wm8903.c b/sound/soc/codecs/wm8903.c
> index 3c95c2aea515..967be629b846 100644
> --- a/sound/soc/codecs/wm8903.c
> +++ b/sound/soc/codecs/wm8903.c
> @@ -2183,7 +2183,7 @@ static int wm8903_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int wm8903_i2c_remove(struct i2c_client *client)
> +static void wm8903_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wm8903_priv *wm890=
3 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -2192,8 +2192,6 @@ static int wm8903_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (client->irq)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(client->irq, wm8903);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0wm8903_free_gpio(wm8903);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct of_device_id wm8903_of_match[] =3D {
> diff --git a/sound/soc/codecs/wm8960.c b/sound/soc/codecs/wm8960.c
> index 8c8f32b23083..3c4cd47f5ad9 100644
> --- a/sound/soc/codecs/wm8960.c
> +++ b/sound/soc/codecs/wm8960.c
> @@ -1487,10 +1487,8 @@ static int wm8960_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int wm8960_i2c_remove(struct i2c_client *client)
> -{
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> -}
> +static void wm8960_i2c_remove(struct i2c_client *client)
> +{}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm8960_i2c_id[] =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0{ "wm8960", 0 },
> diff --git a/sound/soc/codecs/wm8962.c b/sound/soc/codecs/wm8962.c
> index 5cca89364280..85089304f5e7 100644
> --- a/sound/soc/codecs/wm8962.c
> +++ b/sound/soc/codecs/wm8962.c
> @@ -3779,10 +3779,9 @@ static int wm8962_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int wm8962_i2c_remove(struct i2c_client *client)
> +static void wm8962_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0pm_runtime_disable(&clien=
t->dev);
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0#ifdef CONFIG_PM
> diff --git a/sound/soc/codecs/wm8993.c b/sound/soc/codecs/wm8993.c
> index f4da77ec9d6c..fe1c5aab0ab6 100644
> --- a/sound/soc/codecs/wm8993.c
> +++ b/sound/soc/codecs/wm8993.c
> @@ -1723,15 +1723,13 @@ static int wm8993_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int wm8993_i2c_remove(struct i2c_client *i2c)
> +static void wm8993_i2c_remove(struct i2c_client *i2c)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wm8993_priv *wm899=
3 =3D i2c_get_clientdata(i2c);
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0if (i2c->irq)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0free_irq(i2c->irq, wm8993);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0regulator_bulk_disable(AR=
RAY_SIZE(wm8993->supplies), wm8993-
> >supplies);
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm8993_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/wm8996.c b/sound/soc/codecs/wm8996.c
> index f7bb27d1c76d..5f2b3af47c12 100644
> --- a/sound/soc/codecs/wm8996.c
> +++ b/sound/soc/codecs/wm8996.c
> @@ -3067,7 +3067,7 @@ static int wm8996_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return ret;
> =C2=A0}
> =C2=A0
> -static int wm8996_i2c_remove(struct i2c_client *client)
> +static void wm8996_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct wm8996_priv *wm899=
6 =3D i2c_get_clientdata(client);
> =C2=A0
> @@ -3076,8 +3076,6 @@ static int wm8996_i2c_remove(struct i2c_client
> *client)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpio_set_value_cansleep(wm8996->pdata.ldo_ena, 0);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0gpio_free(wm8996->pdata.ldo_ena);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0}
> -
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm8996_i2c_id[] =3D {
> diff --git a/sound/soc/codecs/wm9081.c b/sound/soc/codecs/wm9081.c
> index 87b58448cea7..6184d8c06564 100644
> --- a/sound/soc/codecs/wm9081.c
> +++ b/sound/soc/codecs/wm9081.c
> @@ -1357,10 +1357,8 @@ static int wm9081_i2c_probe(struct i2c_client
> *i2c)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}
> =C2=A0
> -static int wm9081_i2c_remove(struct i2c_client *client)
> -{
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> -}
> +static void wm9081_i2c_remove(struct i2c_client *client)
> +{}
> =C2=A0
> =C2=A0static const struct i2c_device_id wm9081_i2c_id[] =3D {
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0{ "wm9081", 0 },

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bc3ddfb53df76885ca9714a6502d7d0bb367584b.camel%40linux.intel.com.
