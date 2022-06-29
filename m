Return-Path: <kasan-dev+bncBC6252EEVYIRBLFT6CKQMGQEKZHBOXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 9537355FBBA
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 11:21:50 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id w82-20020acadf55000000b003358f467974sf2864533oig.7
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 02:21:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656494508; cv=pass;
        d=google.com; s=arc-20160816;
        b=BKjSoH+0yl2PBJpy3xNNmlcU4yC2EOFA7KtmlEVJjpaGiYbgY2OSZW8HNFLCzYGfG0
         Xz2bK6v4L1p0LNfCG80ePiopQSoblnjSWslILw642QrmY2tN26VItRk3DDl2X5re6HBg
         PsJwEIv+DSsRNByglvRDCsWEp5XB/CWIFHosHZWLf08LDc0rNKmgBQbG5T/ubhYIcxUd
         hxxGVkvlvz2VwsCvtU41bLsH/1Ul7OVnxvncX2it42npVYLJBh20U4DtuhvHXDHn6SMS
         s+ghOogSQ/T8+j63lDHob3qXqhbGRNU6+qsxt1EQXP8SbNSWvXMRCeS6CznhTgAXgJ5L
         CMzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:in-reply-to:message-id:subject:cc:to:from
         :date:sender:dkim-signature;
        bh=uCZ4si7puMSEUT5cz4941hUufwatr8UMoE5fwCuZ5mc=;
        b=b9+WNINP2VA8SGRkx/XrTSqgrRKQT4Ee6cp+KJ7hEmuyBtqiSkclD7gMHvbliZaRID
         vWUJc9U8+AZj2J3iKm2p3BMW84VqS/7Tv3ZQ8LzX4kznoaZkQQs8g/AvgHz45uBunp6X
         xfISb0pV7yjO1tPvKzi9RpJp1F8yIqFUUvYkLBIFBD3O4mGd6y6UCVZGatyd3LrcCc1+
         gi8QeqoqtKVgrxaVe60pLcD7piLBRt8iHobjj74GXZOp0z4wwRffxQ17KLZs9JjrHTCq
         c+oRBkN6yvL47yZ0jKFUnV2SsgDGrbILJJgzROVp+zPIiRAY8hDgLR1GpL691n3u5ksf
         gm9Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KDGJ+ZX0;
       spf=pass (google.com: domain of kabel@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kabel@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=uCZ4si7puMSEUT5cz4941hUufwatr8UMoE5fwCuZ5mc=;
        b=SMPbHD9FAx4Y5839xP9HZXsSAVEGy0R8dyqRlsN5NxGJ+paG19kSlRU792DKsAuYrj
         wm/fLi5UKttG4PneyujZ9xZfgiG3gd3xqjQYTFCxPhDwbLFlLtIvt5BU5D1cBhRnrTlI
         iCwDGGBPFXndwSsmsp1f0rDGioqaprnE0CNw6DQVqt/arB3cUoEkBVq91nQnZNPax1jN
         m0wJWwH92a3jBZ4gzUrcfKQveZl8jHBYsDX3xxmNLG2wSoJukaZES1sYj4mQrckrEnew
         rhbSZiRlXP7fdxPn86BSkCAaITtHfUPTwx37qQDgLJ/PU+UdMiOaFMVapfqr+AALeMSL
         eKuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=uCZ4si7puMSEUT5cz4941hUufwatr8UMoE5fwCuZ5mc=;
        b=SKC9NMSyCReAzdSIgHL6RvxX2dxSCU4l3EQezhP2XEqcQGvfwmJ/HHc0rPxtoiHKUe
         18BCT9Z1vmFaMfjCFtvxGVFDUFEPbfRV+N1h3/JQMTcXyHUDGU9+rdVDyGL75NLXX5Sp
         vqFEZaTKO8ElhtIthmH4bqfhPbtdWcSYFiMWrbL40pmTB2iXCu/zaVKuPYXiOGo4Ieqv
         4CAi2tfqTWyqnbqS8TgvZqdGAxLT92blB2EROE/je3YwPC18tgeqLA5LgbIqj4KbVIuT
         LiS2xnMNtdh1u0g8l9IdDwpnmu7++E3/+jAShzVIa+IjvxHK8jp87js73dsXenioS4sE
         XKkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/hWvn2fane+0awHb0j2d+bxGcD5ig24M7f/c09wXSVpO59itO2
	Wa8ihuFa4JIMoC1+SMI0MEw=
X-Google-Smtp-Source: AGRyM1v3eAE14uSPsF9WrObS2J7PIKyc/RPkNKbR46q44yx/nX3K/bjJ67hGQltd7aYRKUgYUhwNXw==
X-Received: by 2002:a05:6870:51ce:b0:101:c7e3:d7a5 with SMTP id b14-20020a05687051ce00b00101c7e3d7a5mr2328761oaj.176.1656494508181;
        Wed, 29 Jun 2022 02:21:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:60b:b0:101:a6a7:72cf with SMTP id
 w11-20020a056871060b00b00101a6a772cfls12223177oan.4.gmail; Wed, 29 Jun 2022
 02:21:47 -0700 (PDT)
X-Received: by 2002:a05:6870:a2d1:b0:101:ce47:e1e6 with SMTP id w17-20020a056870a2d100b00101ce47e1e6mr1234931oak.80.1656494507762;
        Wed, 29 Jun 2022 02:21:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656494507; cv=none;
        d=google.com; s=arc-20160816;
        b=f6SIpLOux0uVYewQPNP/eIdpL5JkqKQvzlYpT5IAzn9MfLZXNB9ON8EZtRYmnRGO+y
         KKNZUs1i58CiIJpzrrk5CpsmffQfy/I3PRqQXuw+tlOF271szXoMEfwt5pvvA+ksgBaR
         CyJJrzX4f9XXCbLxYcXlPFe04hgWCDZb9rzttHEy5Aue4bDXAySrc82G+6qZm1csFWKE
         CyFzuPXr5zt72/cSoMyLMskG9pZV/QXtwudhQWv23TC4ODAnVMs2+SK/kQlcCTHWuwXc
         iET2TKrW7T+EFTWJXnFI+Njs/0BiLyLBkF8/Gyg6yzSecBAdXCbKI99ygX3f3IIKDLY4
         LM9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=qP4bV8z27UvwcYy45jdJWDX6JPzpOY0v1rrPabA8vGI=;
        b=eBbqtUjaIQ4PYMJHJ2r64QTphBmSO6AAJDMkNYec3TeVTGEMnI5TEfZrR+DXhVObvL
         i2sP7W7vNlVyAF8jyzzds2Xga7OuvpQiAzFokyNYiH8FGykD30LfRG1zw8k35zNjXNdZ
         CxKT4XT97bg3wJ6lhsYwz7M+VUNDgDkBlai67yW48t0qUAmFKR0T0P4E1I6LgN6W/UWL
         llTHqpI+FCpeV6otCZZVxGvUnKhcsM2YVRx0k7xIwCwzucz75OHY4jkm9v/fM6ZhHmVe
         GdCVI49SQeS+kBEy+g6nTe2gDabOYQuLj4F4Sh1M4IdAmMXKOk/w4uvu+vNrJDaLRmtY
         laGA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KDGJ+ZX0;
       spf=pass (google.com: domain of kabel@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=kabel@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id a32-20020a056870a1a000b000ddac42441esi2198939oaf.0.2022.06.29.02.21.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jun 2022 02:21:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of kabel@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id DDCCF61E2F;
	Wed, 29 Jun 2022 09:21:46 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 9A6A5C34114;
	Wed, 29 Jun 2022 09:20:45 +0000 (UTC)
Date: Wed, 29 Jun 2022 11:20:42 +0200
From: Marek =?UTF-8?B?QmVow7pu?= <kabel@kernel.org>
To: Uwe =?UTF-8?B?S2xlaW5lLUvDtm5pZw==?= <u.kleine-koenig@pengutronix.de>
Cc: Wolfram Sang <wsa@kernel.org>, Uwe =?UTF-8?B?S2xlaW5lLUvDtm5pZw==?=
 <uwe@kleine-koenig.org>, Sekhar Nori <nsekhar@ti.com>, Bartosz Golaszewski
 <brgl@bgdev.pl>, Russell King <linux@armlinux.org.uk>, Scott Wood
 <oss@buserror.net>, Michael Ellerman <mpe@ellerman.id.au>, Benjamin
 Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras
 <paulus@samba.org>, Robin van der Gracht <robin@protonic.nl>, Miguel Ojeda
 <ojeda@kernel.org>, Corey Minyard <minyard@acm.org>, Peter Huewe
 <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, Jason Gunthorpe
 <jgg@ziepe.ca>, Nicolas Ferre <nicolas.ferre@microchip.com>, Alexandre
 Belloni <alexandre.belloni@bootlin.com>, Claudiu Beznea
 <claudiu.beznea@microchip.com>, Max Filippov <jcmvbkbc@gmail.com>, Michael
 Turquette <mturquette@baylibre.com>, Stephen Boyd <sboyd@kernel.org>, Luca
 Ceresoli <luca@lucaceresoli.net>, Tudor Ambarus
 <tudor.ambarus@microchip.com>, Herbert Xu <herbert@gondor.apana.org.au>,
 "David S. Miller" <davem@davemloft.net>, MyungJoo Ham
 <myungjoo.ham@samsung.com>, Chanwoo Choi <cw00.choi@samsung.com>, Michael
 Hennerich <michael.hennerich@analog.com>, Linus Walleij
 <linus.walleij@linaro.org>, Andrzej Hajda <andrzej.hajda@intel.com>, Neil
 Armstrong <narmstrong@baylibre.com>, Robert Foss <robert.foss@linaro.org>,
 Laurent Pinchart <Laurent.pinchart@ideasonboard.com>, Jonas Karlman
 <jonas@kwiboo.se>, Jernej Skrabec <jernej.skrabec@gmail.com>, David Airlie
 <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>, Benson Leung
 <bleung@chromium.org>, Guenter Roeck <groeck@chromium.org>, Phong LE
 <ple@baylibre.com>, Adrien Grassein <adrien.grassein@gmail.com>, Peter
 Senna Tschudin <peter.senna@gmail.com>, Martin Donnelly
 <martin.donnelly@ge.com>, Martyn Welch <martyn.welch@collabora.co.uk>,
 Douglas Anderson <dianders@chromium.org>, Stefan Mavrodiev
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
 Alexandre Torgue <alexandre.torgue@foss.st.com>, Sakari Ailus
 <sakari.ailus@linux.intel.com>, Pavel Machek <pavel@ucw.cz>, Jan-Simon
 Moeller <jansimon.moeller@gmx.de>, Colin Leroy <colin@colino.net>, Joe
 Tessler <jrt@google.com>, Hans Verkuil <hverkuil-cisco@xs4all.nl>, Mauro
 Carvalho Chehab <mchehab@kernel.org>, Antti Palosaari <crope@iki.fi>,
 Jasmin Jessich <jasmin@anw.at>, Matthias Schwarzott <zzam@gentoo.org>, Olli
 Salonen <olli.salonen@iki.fi>, Akihiro Tsukada <tskd08@gmail.com>, Kieran
 Bingham <kieran.bingham@ideasonboard.com>, Tianshu Qiu
 <tian.shu.qiu@intel.com>, Dongchun Zhu <dongchun.zhu@mediatek.com>, Shawn
 Tu <shawnx.tu@intel.com>, Martin Kepplinger <martink@posteo.de>, Ricardo
 Ribalda <ribalda@kernel.org>, Dave Stevenson
 <dave.stevenson@raspberrypi.com>, Leon Luo <leonl@leopardimaging.com>,
 Manivannan Sadhasivam <mani@kernel.org>, Bingbu Cao <bingbu.cao@intel.com>,
 "Paul J. Murphy" <paul.j.murphy@intel.com>, Daniele Alessandrelli
 <daniele.alessandrelli@intel.com>, Michael Tretter
 <m.tretter@pengutronix.de>, Pengutronix Kernel Team
 <kernel@pengutronix.de>, Kyungmin Park <kyungmin.park@samsung.com>,
 Heungjun Kim <riverful.kim@samsung.com>, Ramesh Shanmugasundaram
 <rashanmu@gmail.com>, Jacopo Mondi <jacopo+renesas@jmondi.org>, Niklas
 =?UTF-8?B?U8O2ZGVybHVuZA==?= <niklas.soderlund+renesas@ragnatech.se>, Jimmy
 Su <jimmy.su@intel.com>, Arec Kao <arec.kao@intel.com>, "Lad, Prabhakar"
 <prabhakar.csengg@gmail.com>, Shunqian Zheng <zhengsq@rock-chips.com>,
 Steve Longerbeam <slongerbeam@gmail.com>, Chiranjeevi Rapolu
 <chiranjeevi.rapolu@intel.com>, Daniel Scally <djrscally@gmail.com>, Wenyou
 Yang <wenyou.yang@microchip.com>, Petr Cvek <petrcvekcz@gmail.com>, Akinobu
 Mita <akinobu.mita@gmail.com>, Sylwester Nawrocki <s.nawrocki@samsung.com>,
 Benjamin Mugnier <benjamin.mugnier@foss.st.com>, Sylvain Petinot
 <sylvain.petinot@foss.st.com>, Mats Randgaard <matrandg@cisco.com>, Tim
 Harvey <tharvey@gateworks.com>, Matt Ranostay <matt.ranostay@konsulko.com>,
 Eduardo Valentin <edubezval@gmail.com>, "Daniel W. S. Almeida"
 <dwlsalmeida@gmail.com>, Lee Jones <lee.jones@linaro.org>, Chen-Yu Tsai
 <wens@csie.org>, Support Opensource <support.opensource@diasemi.com>,
 Robert Jones <rjones@gateworks.com>, Andy Shevchenko <andy@kernel.org>,
 Charles Keepax <ckeepax@opensource.cirrus.com>, Richard Fitzgerald
 <rf@opensource.cirrus.com>, Krzysztof Kozlowski
 <krzysztof.kozlowski@linaro.org>, Bartlomiej Zolnierkiewicz
 <b.zolnierkie@samsung.com>, Tony Lindgren <tony@atomide.com>, Jonathan
 =?UTF-8?B?TmV1c2Now6RmZXI=?= <j.neuschaefer@gmx.net>, Arnd Bergmann
 <arnd@arndb.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Eric Piel
 <eric.piel@tremplin-utc.net>, Miquel Raynal <miquel.raynal@bootlin.com>,
 Richard Weinberger <richard@nod.at>, Vignesh Raghavendra <vigneshr@ti.com>,
 Andrew Lunn <andrew@lunn.ch>, Vivien Didelot <vivien.didelot@gmail.com>,
 Vladimir Oltean <olteanv@gmail.com>, Eric Dumazet <edumazet@google.com>,
 Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, Woojung
 Huh <woojung.huh@microchip.com>, UNGLinuxDriver@microchip.com, George
 McCollister <george.mccollister@gmail.com>, Ido Schimmel
 <idosch@nvidia.com>, Petr Machata <petrm@nvidia.com>, Jeremy Kerr
 <jk@codeconstruct.com.au>, Matt Johnston <matt@codeconstruct.com.au>,
 Charles Gorand <charles.gorand@effinnov.com>, Krzysztof Opasiak
 <k.opasiak@samsung.com>, Rob Herring <robh+dt@kernel.org>, Frank Rowand
 <frowand.list@gmail.com>, Mark Gross <markgross@kernel.org>, Maximilian Luz
 <luzmaximilian@gmail.com>, Corentin Chary <corentin.chary@gmail.com>, Pali
 =?UTF-8?B?Um9ow6Fy?= <pali@kernel.org>, Sebastian Reichel <sre@kernel.org>,
 Tobias Schrammm <t.schramm@manjaro.org>, Liam Girdwood
 <lgirdwood@gmail.com>, Mark Brown <broonie@kernel.org>, Alessandro Zummo
 <a.zummo@towertech.it>, Jens Frederich <jfrederich@gmail.com>, Jon
 Nettleton <jon.nettleton@gmail.com>, Jiri Slaby <jirislaby@kernel.org>,
 Felipe Balbi <balbi@kernel.org>, Heikki Krogerus
 <heikki.krogerus@linux.intel.com>, Daniel Thompson
 <daniel.thompson@linaro.org>, Jingoo Han <jingoohan1@gmail.com>, Helge
 Deller <deller@gmx.de>, Evgeniy Polyakov <zbr@ioremap.net>, Wim Van
 Sebroeck <wim@linux-watchdog.org>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Johannes Berg
 <johannes@sipsolutions.net>, Jaroslav Kysela <perex@perex.cz>, Takashi Iwai
 <tiwai@suse.com>, James Schulman <james.schulman@cirrus.com>, David Rhodes
 <david.rhodes@cirrus.com>, Lucas Tanure <tanureal@opensource.cirrus.com>,
 Nuno =?UTF-8?B?U8Oh?= <nuno.sa@analog.com>, Matthias Brugger
 <matthias.bgg@gmail.com>, Oder Chiou <oder_chiou@realtek.com>, Fabio
 Estevam <festevam@gmail.com>, Kevin Cernekee <cernekee@chromium.org>,
 Christophe Leroy <christophe.leroy@csgroup.eu>, Maxime Ripard
 <maxime@cerno.tech>, Alvin =?UTF-8?B?xaBpcHJhZ2E=?= <alsi@bang-olufsen.dk>,
 Lucas Stach <l.stach@pengutronix.de>, Jagan Teki
 <jagan@amarulasolutions.com>, Biju Das <biju.das.jz@bp.renesas.com>, Thomas
 Zimmermann <tzimmermann@suse.de>, Alex Deucher <alexander.deucher@amd.com>,
 Lyude Paul <lyude@redhat.com>, Xin Ji <xji@analogixsemi.com>, Hsin-Yi Wang
 <hsinyi@chromium.org>, =?UTF-8?B?Sm9zw6kgRXhww7NzaXRv?=
 <jose.exposito89@gmail.com>, Yang Li <yang.lee@linux.alibaba.com>, Angela
 Czubak <acz@semihalf.com>, Alistair Francis <alistair@alistair23.me>, Eddie
 James <eajames@linux.ibm.com>, Joel Stanley <joel@jms.id.au>, Nathan
 Chancellor <nathan@kernel.org>, Antoniu Miclaus
 <antoniu.miclaus@analog.com>, Alexandru Ardelean <ardeleanalex@gmail.com>,
 Dmitry Rokosov <DDRokosov@sberdevices.ru>, Srinivas Pandruvada
 <srinivas.pandruvada@linux.intel.com>, Stephan Gerhold
 <stephan@gerhold.net>, Miaoqian Lin <linmq006@gmail.com>, Gwendal Grignou
 <gwendal@chromium.org>, Yang Yingliang <yangyingliang@huawei.com>, Paul
 Cercueil <paul@crapouillou.net>, Daniel Palmer <daniel@0x0f.com>, Haibo
 Chen <haibo.chen@nxp.com>, Cai Huoqing <cai.huoqing@linux.dev>, Marek Vasut
 <marex@denx.de>, Jose Cazarin <joseespiriki@gmail.com>, Dan Carpenter
 <dan.carpenter@oracle.com>, Jean-Baptiste Maneyrol
 <jean-baptiste.maneyrol@tdk.com>, Michael Srba <Michael.Srba@seznam.cz>,
 Nikita Travkin <nikita@trvn.ru>, Maslov Dmitry <maslovdmitry@seeed.cc>,
 Jiri Valek - 2N <valek@2n.cz>, Arnaud Ferraris
 <arnaud.ferraris@collabora.com>, Zheyu Ma <zheyuma97@gmail.com>, Marco
 Felsch <m.felsch@pengutronix.de>, Oliver Graute
 <oliver.graute@kococonnector.com>, Zheng Yongjun
 <zhengyongjun3@huawei.com>, CGEL ZTE <cgel.zte@gmail.com>, Minghao Chi
 <chi.minghao@zte.com.cn>, Evgeny Novikov <novikov@ispras.ru>, Sean Young
 <sean@mess.org>, Kirill Shilimanov <kirill.shilimanov@huawei.com>, Moses
 Christopher Bollavarapu <mosescb.dev@gmail.com>, Paul Kocialkowski
 <paul.kocialkowski@bootlin.com>, Janusz Krzysztofik <jmkrzyszt@gmail.com>,
 Dongliang Mu <mudongliangabcd@gmail.com>, Colin Ian King
 <colin.king@intel.com>, lijian <lijian@yulong.com>, Kees Cook
 <keescook@chromium.org>, Yan Lei <yan_lei@dahuatech.com>, Heiner Kallweit
 <hkallweit1@gmail.com>, Jonas Malaco <jonas@protocubo.io>, wengjianfeng
 <wengjianfeng@yulong.com>, Rikard Falkeborn <rikard.falkeborn@gmail.com>,
 Wei Yongjun <weiyongjun1@huawei.com>, Tom Rix <trix@redhat.com>, Yizhuo
 <yzhai003@ucr.edu>, Martiros Shakhzadyan <vrzh@vrzh.net>, Bjorn Andersson
 <bjorn.andersson@linaro.org>, Sven Peter <sven@svenpeter.dev>, Alyssa
 Rosenzweig <alyssa@rosenzweig.io>, Hector Martin <marcan@marcan.st>,
 Saranya Gopal <saranya.gopal@intel.com>, Guido =?UTF-8?B?R8O8bnRoZXI=?=
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
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Message-ID: <20220629112042.221af80b@thinkpad>
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
	<20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
X-Mailer: Claws Mail 3.18.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kabel@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KDGJ+ZX0;       spf=pass
 (google.com: domain of kabel@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=kabel@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, 28 Jun 2022 16:03:12 +0200
Uwe Kleine-K=C3=B6nig <u.kleine-koenig@pengutronix.de> wrote:

> From: Uwe Kleine-K=C3=B6nig <uwe@kleine-koenig.org>
>=20
> The value returned by an i2c driver's remove function is mostly ignored.
> (Only an error message is printed if the value is non-zero that the
> error is ignored.)
>=20
> So change the prototype of the remove function to return no value. This
> way driver authors are not tempted to assume that passing an error to
> the upper layer is a good idea. All drivers are adapted accordingly.
> There is no intended change of behaviour, all callbacks were prepared to
> return 0 before.
>=20
> Signed-off-by: Uwe Kleine-K=C3=B6nig <u.kleine-koenig@pengutronix.de>

For

>  drivers/leds/leds-turris-omnia.c                          | 4 +---

Acked-by: Marek Beh=C3=BAn <kabel@kernel.org>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220629112042.221af80b%40thinkpad.
