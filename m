Return-Path: <kasan-dev+bncBCX3TTWUQMPRBUMU5SKQMGQEEFSEEWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BF8855E52B
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 16:04:02 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id n8-20020a05640205c800b00434fb0c150csf9555258edx.19
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 07:04:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656425041; cv=pass;
        d=google.com; s=arc-20160816;
        b=EpI6TQnaoufrohA7YsnjJnZr70eEw0bc4L9dERkdHtJJ6C4GRm4VIA6HZiBtAvw21M
         oKVMN2OjpLVNaoA6rxs/MT2cRmHbheySBzZPKsY8RSsbNuEb2wpIzOpFBiRdtUEO5iY6
         hqjX98uN5XYBArZdwxczsXXVfT8CyDnGboX8Bgii8brGjo2XxFF3bjlSJAuq3jdsMzQm
         O4i0XARMwNzPDq9beEp9kfeu4eVlI99bwy731LAhuC+MwRZZa7T/FwlWJM8+8kQu0Y5m
         dRHauMFrTfmjFN33mnFastnbEunspUpagmPJCsC/NRvq/8vv9QUgiohRfA87nv9VFPGH
         /3rA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=sYJF5pKg2YbMqGgog5wLb10gENBKCzbVUhSqNWyUQJk=;
        b=bkpiUeT/VL7AeH4TupbdgnJJqW09oWVG4mV3AXH5GQHG+R0uZzOO4DA5wlDybBE7s/
         36RbGNJSGDHQ91IRJvA7CcvZ9VJykRxXhnWIXLgRQtOb5wdyk/SfZuhRGOfEOgaCGq72
         U3pO/omARaZyKOfizhBihpdACq8gdCVLrv0rK9o7QiSDS+ai6QAqibSIz9enIbyeZUnm
         T8+E5Pfp13l6oLHIsAmbqtE1F/+o8BjR7YpL+06SM7tzGZQT7Fu/ISeQmzI1XHs1xcrL
         u/D+mh4gTWgT31dFTCMGx5znm1zM0Db3/1e7k6l0t6Gbwg6Q2Akxtw8gJGFhDtLN8fe5
         PWPg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=sYJF5pKg2YbMqGgog5wLb10gENBKCzbVUhSqNWyUQJk=;
        b=pT3vJYc1M7jix46pgtxF5nCLTqHDaUj6uGiJwJjxfbA+O2HkY5ZL1f3v+XelPNkJW/
         +8WjtHawNihFBHAxWardyJtcFvcwFmeGzCKBpbcDwCQMLIRLOtEYNfKfS3NlrNIbJvFm
         VhWbSuZIqkmU2STUxtfvTmEOiuh01uFB6/vNRNkg9CuA/wTOZjvlqybd1PnUZ4K6lwr7
         9jxiI9UL5BfGM0kxXVRwJXus1NlwkeB1sWmFMpzZJK7QIFHgFU65P68lK+fi7lKrj9DA
         lvqZInQvA9+FxclLDOHbFaVVzdztvzhGu0ENDwsc8mfgO0L2zcit++YZXBloZ+BYb1Rf
         fOrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sYJF5pKg2YbMqGgog5wLb10gENBKCzbVUhSqNWyUQJk=;
        b=Inx8Aw2NwWmajNPCgfia2nYkZf/XbRTsUlUTecX7ai9cR/ST9+yM202F4vj30hJ+4p
         haS73wsba7vtThgGHol07+vmCb9qw77V6kIsg1FpB6cYGUqvOXSO9mZjfhDX5sE2v0o5
         YBoDusGCJ9Rqh+dQxaaF8JxZUkdl/0i6ICLTG9kBxYvXERbsIZQ9tQPiQVVh5visXGbh
         CbPLWrczNq9bflI6j5nXitIz1GU/MM/vG9wTI4Bo1tKegfLU0HRLMcsl6fYOhs43Oah6
         a0jr2D/46l45QVIcG7lRnGv3WghyAYu7nZo8zbJiAITE2EbwfmLMWzxv/3Ipa2QVwvVj
         2vig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9o+gC9MIVPg6lEIC0qZNKe9cDzjV9s0b4V13lZaHrL9GIiq3ad
	/sfVa3HLXQHV+XSMId4XbNo=
X-Google-Smtp-Source: AGRyM1tLps6inwAIzm+9ZzRLQltUGq52ocsSjljNlre4jmXS7+MAum+pZ2VQ1sCnoQnsW30xugHJHA==
X-Received: by 2002:a05:6402:528d:b0:435:89c6:e16b with SMTP id en13-20020a056402528d00b0043589c6e16bmr23721154edb.292.1656425041462;
        Tue, 28 Jun 2022 07:04:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:a42b:b0:726:cbdd:466d with SMTP id
 sg43-20020a170907a42b00b00726cbdd466dls1475488ejc.9.gmail; Tue, 28 Jun 2022
 07:04:00 -0700 (PDT)
X-Received: by 2002:a17:907:1b0c:b0:6fe:25bf:b3e5 with SMTP id mp12-20020a1709071b0c00b006fe25bfb3e5mr17106138ejc.689.1656425040120;
        Tue, 28 Jun 2022 07:04:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656425040; cv=none;
        d=google.com; s=arc-20160816;
        b=uSqOKnsqbTPYD0YKsxbuB7pVmPVWalWg7GaV3c+uY37rEjQwhILOUP2vcUTcJRqtXA
         Mc4ITtwXWR3Q6t3A8HSXJ6mJJ6kiR1Boy29rajsarmjmShQ39Z/YlbWzG0TD1nlzmPKQ
         jhJ7/Y4JgED7NhEqJTH6kQ1bIuji6UPIoXlx/pAlMWgn1ZMxCtApC+K4oG2a+bYSIxC8
         1uSYLpxmXijvp2wGGhpOucigzGinFRzYIJ4b099U3amZnTiPDCjLg8wgS/pUCTGK/6W0
         YUQaw58VFUvjFP/lIfBgfwXga9pvaNZnuhMPvoH+LC+Iua2ivcSVSqRleBw7XZOFKstm
         FCxA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=i9IffEpWdRzBHoFuviGYj1SQ7Dc6Z9mNxJRm2BF+D6Y=;
        b=U8fxsmZJ0buG9cCaDvbuX7CleZH7JzJ09andXqxy6h5wsS8EJZ24FS3lYzreQFqwfT
         2gZkCbIKHAvQ+aJ3RuhGq3kXST8XX5a7miBypZ48M8WuQ8ap7a/qvVmdFW1zWFdYmBSE
         aGyEtN6mqrb6RJTVp7pKA2F9PcLhw9lJyoR7EIM9+Evsm0pha4cWa4pg3GihxSZAH97V
         8EeocidReRwvzxvpyhqOWak88QIpMSgFG6V4nTmt9yu68HCYEYcHeomB/NqrHF3hSukR
         EVEyiJ1qiJJ3BuFPqZtFSQ+gWN7uYf66a/SVfNWT/t3lc528wp8c8ob69m1QhTaSOLKA
         5iOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
Received: from metis.ext.pengutronix.de (metis.ext.pengutronix.de. [2001:67c:670:201:290:27ff:fe1d:cc33])
        by gmr-mx.google.com with ESMTPS id q31-20020a056402249f00b0043780485814si334374eda.2.2022.06.28.07.04.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Jun 2022 07:04:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33 as permitted sender) client-ip=2001:67c:670:201:290:27ff:fe1d:cc33;
Received: from drehscheibe.grey.stw.pengutronix.de ([2a0a:edc0:0:c01:1d::a2])
	by metis.ext.pengutronix.de with esmtps (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <ukl@pengutronix.de>)
	id 1o6BoH-0008LH-O8; Tue, 28 Jun 2022 16:03:21 +0200
Received: from [2a0a:edc0:0:900:1d::77] (helo=ptz.office.stw.pengutronix.de)
	by drehscheibe.grey.stw.pengutronix.de with esmtp (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o6BoD-003DTI-AD; Tue, 28 Jun 2022 16:03:20 +0200
Received: from ukl by ptz.office.stw.pengutronix.de with local (Exim 4.94.2)
	(envelope-from <ukl@pengutronix.de>)
	id 1o6BoD-001gz7-Uf; Tue, 28 Jun 2022 16:03:17 +0200
From: =?UTF-8?q?Uwe=20Kleine-K=C3=B6nig?= <u.kleine-koenig@pengutronix.de>
To: David Airlie <airlied@linux.ie>,
	Daniel Vetter <daniel@ffwll.ch>,
	Pavel Machek <pavel@ucw.cz>,
	Linus Walleij <linus.walleij@linaro.org>,
	Dan Murphy <dmurphy@ti.com>,
	Sekhar Nori <nsekhar@ti.com>,
	Bartosz Golaszewski <brgl@bgdev.pl>,
	Russell King <linux@armlinux.org.uk>,
	Wolfram Sang <wsa@kernel.org>
Cc: dri-devel@lists.freedesktop.org,
	linux-leds@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-gpio@vger.kernel.org,
	Scott Wood <oss@buserror.net>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Robin van der Gracht <robin@protonic.nl>,
	Miguel Ojeda <ojeda@kernel.org>,
	Corey Minyard <minyard@acm.org>,
	Peter Huewe <peterhuewe@gmx.de>,
	Jarkko Sakkinen <jarkko@kernel.org>,
	Jason Gunthorpe <jgg@ziepe.ca>,
	Nicolas Ferre <nicolas.ferre@microchip.com>,
	Alexandre Belloni <alexandre.belloni@bootlin.com>,
	Claudiu Beznea <claudiu.beznea@microchip.com>,
	Max Filippov <jcmvbkbc@gmail.com>,
	Michael Turquette <mturquette@baylibre.com>,
	Stephen Boyd <sboyd@kernel.org>,
	Luca Ceresoli <luca@lucaceresoli.net>,
	Tudor Ambarus <tudor.ambarus@microchip.com>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	"David S. Miller" <davem@davemloft.net>,
	MyungJoo Ham <myungjoo.ham@samsung.com>,
	Chanwoo Choi <cw00.choi@samsung.com>,
	Michael Hennerich <michael.hennerich@analog.com>,
	Andrzej Hajda <andrzej.hajda@intel.com>,
	Neil Armstrong <narmstrong@baylibre.com>,
	Robert Foss <robert.foss@linaro.org>,
	Laurent Pinchart <Laurent.pinchart@ideasonboard.com>,
	Jonas Karlman <jonas@kwiboo.se>,
	Jernej Skrabec <jernej.skrabec@gmail.com>,
	Benson Leung <bleung@chromium.org>,
	Guenter Roeck <groeck@chromium.org>,
	Phong LE <ple@baylibre.com>,
	Adrien Grassein <adrien.grassein@gmail.com>,
	Peter Senna Tschudin <peter.senna@gmail.com>,
	Martin Donnelly <martin.donnelly@ge.com>,
	Martyn Welch <martyn.welch@collabora.co.uk>,
	Douglas Anderson <dianders@chromium.org>,
	Stefan Mavrodiev <stefan@olimex.com>,
	Thierry Reding <thierry.reding@gmail.com>,
	Sam Ravnborg <sam@ravnborg.org>,
	Florian Fainelli <f.fainelli@gmail.com>,
	Broadcom internal kernel review list <bcm-kernel-feedback-list@broadcom.com>,
	Javier Martinez Canillas <javierm@redhat.com>,
	Jiri Kosina <jikos@kernel.org>,
	Benjamin Tissoires <benjamin.tissoires@redhat.com>,
	Jean Delvare <jdelvare@suse.com>,
	George Joseph <george.joseph@fairview5.com>,
	Juerg Haefliger <juergh@gmail.com>,
	Riku Voipio <riku.voipio@iki.fi>,
	Robert Marko <robert.marko@sartura.hr>,
	Luka Perkov <luka.perkov@sartura.hr>,
	Marc Hulsman <m.hulsman@tudelft.nl>,
	Rudolf Marek <r.marek@assembler.cz>,
	Peter Rosin <peda@axentia.se>,
	Jonathan Cameron <jic23@kernel.org>,
	Lars-Peter Clausen <lars@metafoo.de>,
	Dan Robertson <dan@dlrobertson.com>,
	Rui Miguel Silva <rmfrfs@gmail.com>,
	Tomasz Duszynski <tduszyns@gmail.com>,
	Kevin Tsai <ktsai@capellamicro.com>,
	Crt Mori <cmo@melexis.com>,
	Dmitry Torokhov <dmitry.torokhov@gmail.com>,
	Nick Dyer <nick@shmanahar.org>,
	Bastien Nocera <hadess@hadess.net>,
	Hans de Goede <hdegoede@redhat.com>,
	Maxime Coquelin <mcoquelin.stm32@gmail.com>,
	Alexandre Torgue <alexandre.torgue@foss.st.com>,
	Sakari Ailus <sakari.ailus@linux.intel.com>,
	Jan-Simon Moeller <jansimon.moeller@gmx.de>,
	=?utf-8?q?Marek_Beh=C3=BAn?= <kabel@kernel.org>,
	Colin Leroy <colin@colino.net>,
	Joe Tessler <jrt@google.com>,
	Hans Verkuil <hverkuil-cisco@xs4all.nl>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Antti Palosaari <crope@iki.fi>,
	Jasmin Jessich <jasmin@anw.at>,
	Matthias Schwarzott <zzam@gentoo.org>,
	Olli Salonen <olli.salonen@iki.fi>,
	Akihiro Tsukada <tskd08@gmail.com>,
	Kieran Bingham <kieran.bingham@ideasonboard.com>,
	Tianshu Qiu <tian.shu.qiu@intel.com>,
	Dongchun Zhu <dongchun.zhu@mediatek.com>,
	Shawn Tu <shawnx.tu@intel.com>,
	Martin Kepplinger <martink@posteo.de>,
	Ricardo Ribalda <ribalda@kernel.org>,
	Dave Stevenson <dave.stevenson@raspberrypi.com>,
	Leon Luo <leonl@leopardimaging.com>,
	Manivannan Sadhasivam <mani@kernel.org>,
	Bingbu Cao <bingbu.cao@intel.com>,
	"Paul J. Murphy" <paul.j.murphy@intel.com>,
	Daniele Alessandrelli <daniele.alessandrelli@intel.com>,
	Michael Tretter <m.tretter@pengutronix.de>,
	Pengutronix Kernel Team <kernel@pengutronix.de>,
	Kyungmin Park <kyungmin.park@samsung.com>,
	Heungjun Kim <riverful.kim@samsung.com>,
	Ramesh Shanmugasundaram <rashanmu@gmail.com>,
	Jacopo Mondi <jacopo+renesas@jmondi.org>,
	=?utf-8?q?Niklas_S=C3=B6derlund?= <niklas.soderlund+renesas@ragnatech.se>,
	Jimmy Su <jimmy.su@intel.com>,
	Arec Kao <arec.kao@intel.com>,
	"Lad, Prabhakar" <prabhakar.csengg@gmail.com>,
	Shunqian Zheng <zhengsq@rock-chips.com>,
	Steve Longerbeam <slongerbeam@gmail.com>,
	Chiranjeevi Rapolu <chiranjeevi.rapolu@intel.com>,
	Daniel Scally <djrscally@gmail.com>,
	Wenyou Yang <wenyou.yang@microchip.com>,
	Petr Cvek <petrcvekcz@gmail.com>,
	Akinobu Mita <akinobu.mita@gmail.com>,
	Sylwester Nawrocki <s.nawrocki@samsung.com>,
	Benjamin Mugnier <benjamin.mugnier@foss.st.com>,
	Sylvain Petinot <sylvain.petinot@foss.st.com>,
	Mats Randgaard <matrandg@cisco.com>,
	Tim Harvey <tharvey@gateworks.com>,
	Matt Ranostay <matt.ranostay@konsulko.com>,
	Eduardo Valentin <edubezval@gmail.com>,
	"Daniel W. S. Almeida" <dwlsalmeida@gmail.com>,
	Lee Jones <lee.jones@linaro.org>,
	Chen-Yu Tsai <wens@csie.org>,
	Support Opensource <support.opensource@diasemi.com>,
	Robert Jones <rjones@gateworks.com>,
	Andy Shevchenko <andy@kernel.org>,
	Charles Keepax <ckeepax@opensource.cirrus.com>,
	Richard Fitzgerald <rf@opensource.cirrus.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>,
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
	Tony Lindgren <tony@atomide.com>,
	=?utf-8?q?Jonathan_Neusch=C3=A4fer?= <j.neuschaefer@gmx.net>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Eric Piel <eric.piel@tremplin-utc.net>,
	Miquel Raynal <miquel.raynal@bootlin.com>,
	Richard Weinberger <richard@nod.at>,
	Vignesh Raghavendra <vigneshr@ti.com>,
	Andrew Lunn <andrew@lunn.ch>,
	Vivien Didelot <vivien.didelot@gmail.com>,
	Vladimir Oltean <olteanv@gmail.com>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>,
	Paolo Abeni <pabeni@redhat.com>,
	Woojung Huh <woojung.huh@microchip.com>,
	UNGLinuxDriver@microchip.com,
	George McCollister <george.mccollister@gmail.com>,
	Ido Schimmel <idosch@nvidia.com>,
	Petr Machata <petrm@nvidia.com>,
	Jeremy Kerr <jk@codeconstruct.com.au>,
	Matt Johnston <matt@codeconstruct.com.au>,
	Charles Gorand <charles.gorand@effinnov.com>,
	Krzysztof Opasiak <k.opasiak@samsung.com>,
	Rob Herring <robh+dt@kernel.org>,
	Frank Rowand <frowand.list@gmail.com>,
	Mark Gross <markgross@kernel.org>,
	Maximilian Luz <luzmaximilian@gmail.com>,
	Corentin Chary <corentin.chary@gmail.com>,
	=?utf-8?q?Pali_Roh=C3=A1r?= <pali@kernel.org>,
	Sebastian Reichel <sre@kernel.org>,
	Tobias Schrammm <t.schramm@manjaro.org>,
	Liam Girdwood <lgirdwood@gmail.com>,
	Mark Brown <broonie@kernel.org>,
	Alessandro Zummo <a.zummo@towertech.it>,
	Jens Frederich <jfrederich@gmail.com>,
	Jon Nettleton <jon.nettleton@gmail.com>,
	Jiri Slaby <jirislaby@kernel.org>,
	Felipe Balbi <balbi@kernel.org>,
	Heikki Krogerus <heikki.krogerus@linux.intel.com>,
	Daniel Thompson <daniel.thompson@linaro.org>,
	Jingoo Han <jingoohan1@gmail.com>,
	Helge Deller <deller@gmx.de>,
	Evgeniy Polyakov <zbr@ioremap.net>,
	Wim Van Sebroeck <wim@linux-watchdog.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jaroslav Kysela <perex@perex.cz>,
	Takashi Iwai <tiwai@suse.com>,
	James Schulman <james.schulman@cirrus.com>,
	David Rhodes <david.rhodes@cirrus.com>,
	Lucas Tanure <tanureal@opensource.cirrus.com>,
	=?utf-8?q?Nuno_S=C3=A1?= <nuno.sa@analog.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Oder Chiou <oder_chiou@realtek.com>,
	Fabio Estevam <festevam@gmail.com>,
	Kevin Cernekee <cernekee@chromium.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Maxime Ripard <maxime@cerno.tech>,
	=?utf-8?q?Alvin_=C5=A0ipraga?= <alsi@bang-olufsen.dk>,
	Lucas Stach <l.stach@pengutronix.de>,
	Jagan Teki <jagan@amarulasolutions.com>,
	Biju Das <biju.das.jz@bp.renesas.com>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Alex Deucher <alexander.deucher@amd.com>,
	Lyude Paul <lyude@redhat.com>,
	Xin Ji <xji@analogixsemi.com>,
	Hsin-Yi Wang <hsinyi@chromium.org>,
	=?utf-8?b?Sm9zw6kgRXhww7NzaXRv?= <jose.exposito89@gmail.com>,
	Yang Li <yang.lee@linux.alibaba.com>,
	Angela Czubak <acz@semihalf.com>,
	Alistair Francis <alistair@alistair23.me>,
	Eddie James <eajames@linux.ibm.com>,
	Joel Stanley <joel@jms.id.au>,
	Nathan Chancellor <nathan@kernel.org>,
	Antoniu Miclaus <antoniu.miclaus@analog.com>,
	Alexandru Ardelean <ardeleanalex@gmail.com>,
	Dmitry Rokosov <DDRokosov@sberdevices.ru>,
	Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>,
	Stephan Gerhold <stephan@gerhold.net>,
	Miaoqian Lin <linmq006@gmail.com>,
	Gwendal Grignou <gwendal@chromium.org>,
	Yang Yingliang <yangyingliang@huawei.com>,
	Paul Cercueil <paul@crapouillou.net>,
	Daniel Palmer <daniel@0x0f.com>,
	Haibo Chen <haibo.chen@nxp.com>,
	Cai Huoqing <cai.huoqing@linux.dev>,
	Marek Vasut <marex@denx.de>,
	Jose Cazarin <joseespiriki@gmail.com>,
	Dan Carpenter <dan.carpenter@oracle.com>,
	Jean-Baptiste Maneyrol <jean-baptiste.maneyrol@tdk.com>,
	Michael Srba <Michael.Srba@seznam.cz>,
	Nikita Travkin <nikita@trvn.ru>,
	Maslov Dmitry <maslovdmitry@seeed.cc>,
	Jiri Valek - 2N <valek@2n.cz>,
	Arnaud Ferraris <arnaud.ferraris@collabora.com>,
	Zheyu Ma <zheyuma97@gmail.com>,
	Marco Felsch <m.felsch@pengutronix.de>,
	Oliver Graute <oliver.graute@kococonnector.com>,
	Zheng Yongjun <zhengyongjun3@huawei.com>,
	CGEL ZTE <cgel.zte@gmail.com>,
	Minghao Chi <chi.minghao@zte.com.cn>,
	Evgeny Novikov <novikov@ispras.ru>,
	Sean Young <sean@mess.org>,
	Kirill Shilimanov <kirill.shilimanov@huawei.com>,
	Moses Christopher Bollavarapu <mosescb.dev@gmail.com>,
	Paul Kocialkowski <paul.kocialkowski@bootlin.com>,
	Janusz Krzysztofik <jmkrzyszt@gmail.com>,
	Dongliang Mu <mudongliangabcd@gmail.com>,
	Colin Ian King <colin.king@intel.com>,
	lijian <lijian@yulong.com>,
	Kees Cook <keescook@chromium.org>,
	Yan Lei <yan_lei@dahuatech.com>,
	Heiner Kallweit <hkallweit1@gmail.com>,
	Jonas Malaco <jonas@protocubo.io>,
	wengjianfeng <wengjianfeng@yulong.com>,
	Rikard Falkeborn <rikard.falkeborn@gmail.com>,
	Wei Yongjun <weiyongjun1@huawei.com>,
	Tom Rix <trix@redhat.com>,
	Yizhuo <yzhai003@ucr.edu>,
	Martiros Shakhzadyan <vrzh@vrzh.net>,
	Bjorn Andersson <bjorn.andersson@linaro.org>,
	Sven Peter <sven@svenpeter.dev>,
	Alyssa Rosenzweig <alyssa@rosenzweig.io>,
	Hector Martin <marcan@marcan.st>,
	Saranya Gopal <saranya.gopal@intel.com>,
	=?utf-8?q?Guido_G=C3=BCnther?= <agx@sigxcpu.org>,
	Sing-Han Chen <singhanc@nvidia.com>,
	Wayne Chang <waynec@nvidia.com>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Alexey Dobriyan <adobriyan@gmail.com>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Vincent Knecht <vincent.knecht@mailoo.org>,
	Stephen Kitt <steve@sk2.org>,
	Pierre-Louis Bossart <pierre-louis.bossart@linux.intel.com>,
	Alexey Khoroshilov <khoroshilov@ispras.ru>,
	Randy Dunlap <rdunlap@infradead.org>,
	Alejandro Tafalla <atafalla@dnyon.com>,
	Vijendar Mukunda <Vijendar.Mukunda@amd.com>,
	Seven Lee <wtli@nuvoton.com>,
	Mac Chiang <mac.chiang@intel.com>,
	David Lin <CTLIN0@nuvoton.com>,
	Daniel Beer <daniel.beer@igorinstitute.com>,
	Ricard Wanderlof <ricardw@axis.com>,
	Simon Trimmer <simont@opensource.cirrus.com>,
	Shengjiu Wang <shengjiu.wang@nxp.com>,
	Viorel Suman <viorel.suman@nxp.com>,
	Nicola Lunghi <nick83ola@gmail.com>,
	Adam Ford <aford173@gmail.com>,
	linux-i2c@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org,
	openipmi-developer@lists.sourceforge.net,
	linux-integrity@vger.kernel.org,
	linux-clk@vger.kernel.org,
	linux-crypto@vger.kernel.org,
	chrome-platform@lists.linux.dev,
	linux-rpi-kernel@lists.infradead.org,
	linux-input@vger.kernel.org,
	linux-hwmon@vger.kernel.org,
	linux-iio@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-media@vger.kernel.org,
	patches@opensource.cirrus.com,
	alsa-devel@alsa-project.org,
	linux-omap@vger.kernel.org,
	linux-mtd@lists.infradead.org,
	netdev@vger.kernel.org,
	devicetree@vger.kernel.org,
	platform-driver-x86@vger.kernel.org,
	acpi4asus-user@lists.sourceforge.net,
	linux-pm@vger.kernel.org,
	linux-pwm@vger.kernel.org,
	linux-rtc@vger.kernel.org,
	linux-staging@lists.linux.dev,
	linux-serial@vger.kernel.org,
	linux-usb@vger.kernel.org,
	linux-fbdev@vger.kernel.org,
	linux-watchdog@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mediatek@lists.infradead.org
Subject: [PATCH 0/6] i2c: Make remove callback return void
Date: Tue, 28 Jun 2022 16:03:06 +0200
Message-Id: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
X-Mailer: git-send-email 2.36.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Developer-Signature: v=1; a=openpgp-sha256; l=45210; h=from:subject; bh=Mwqu26eJogiyHT1G06+iH7kc6AvAvJ/k+k7QYHMiS/4=; b=owEBbQGS/pANAwAKAcH8FHityuwJAcsmYgBiuwoBTegoPUfWaoKv11qTIxYAi2918Y1SFHiCCxmx UDgraCGJATMEAAEKAB0WIQR+cioWkBis/z50pAvB/BR4rcrsCQUCYrsKAQAKCRDB/BR4rcrsCYTNB/ oD1/VbWcD5xJMRw85oWihLWBUY1Ph8KeiyekvVCz581WqmtY7xcxEDdj6aJ8e48HbDGG0qSWjQzv0C obbaR+pqnXQFVWo7Hw0xrmj3T8KVwYI+ErqyDtyW8kSaaZU5ecL6U/SBkrNJEpmaMIzdSWWqTZFK2k F07FOq0WAuksxkEX6Z06jqcNxqoAC/e0NRlVHLanLDk0O/eYod1AYpU8PNpzc82TF2z89VmbXINhvq kupYHdM+cl6n6CdzWi9UDP47Vc6LkScQ4XhaIWlwgiD2mhZnXrYQqQnQzOb7i8xFcNpV7X6A9wHuAI AP5Zjf4n2zMi9/zRUc8zViC3LL4bqB
X-Developer-Key: i=u.kleine-koenig@pengutronix.de; a=openpgp; fpr=0D2511F322BFAB1C1580266BE2DCDD9132669BD6
Content-Transfer-Encoding: quoted-printable
X-SA-Exim-Connect-IP: 2a0a:edc0:0:c01:1d::a2
X-SA-Exim-Mail-From: ukl@pengutronix.de
X-SA-Exim-Scanned: No (on metis.ext.pengutronix.de); SAEximRunCond expanded to false
X-PTX-Original-Recipient: kasan-dev@googlegroups.com
X-Original-Sender: u.kleine-koenig@pengutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ukl@pengutronix.de designates 2001:67c:670:201:290:27ff:fe1d:cc33
 as permitted sender) smtp.mailfrom=ukl@pengutronix.de
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

Hello,

as announced in
https://lore.kernel.org/linux-i2c/20220609091018.q52fhowlsdbdkct5@pengutron=
ix.de
I intend to change the remove prototype for i2c drivers to remove void.

As this touches quite some drivers, the plan is to submit this change
for inclusion after the next merge window and get it quickly into next
that other subsystems have enough time to adapt.

Still to give the opportunity to comment I send the patch set out based
on v5.19-rc4. There are still a few patches in next that are required,
namely:

	d04d46dd82ad iio:magnetometer:mbc150: Make bmc150_magn_remove() return voi=
d
	7576bc05b360 iio:light:vcnl4035: Improve error reporting for problems duri=
ng .remove()
	ab91da2f2574 iio:light:vcnl4000: Improve error reporting for problems duri=
ng .remove()
	5049646718d7 iio:light:us5182d: Improve error reporting for problems durin=
g .remove()
	be9f6004be88 iio:light:pa12203001: Improve error reporting for problems du=
ring .remove()
	730cd2f54eba iio:chemical:ccs811: Improve error reporting for problems dur=
ing .remove()
	a76209246d9f iio:chemical:atlas: Improve error reporting for problems duri=
ng .remove()
	8f760ce7affd iio:adc:ti-ads1015: Improve error reporting for problems duri=
ng .remove()
	ffa952e95d8c iio:adc:ina2xx: Improve error reporting for problems during .=
remove()
	48d1ae774099 iio: health: afe4404: Remove duplicated error reporting in .r=
emove()
	8dc0a72795e4 iio:light:tsl2583: Remove duplicated error reporting in .remo=
ve()
	58a6df5580bb iio:light:stk3310: Remove duplicated error reporting in .remo=
ve()
	44ceb791182a iio:light:opt3001: Remove duplicated error reporting in .remo=
ve()
	f0e34d262567 iio:light:jsa1212: Remove duplicated error reporting in .remo=
ve()
	8d3d6baa4990 iio:light:isl29028: Remove duplicated error reporting in .rem=
ove()
	5004e24a466c iio:light:bh1780: Remove duplicated error reporting in .remov=
e()
	1db6926d611d iio:accel:stk8ba50: Remove duplicated error reporting in .rem=
ove()
	1aec857d50ce iio:accel:stk8312: Remove duplicated error reporting in .remo=
ve()
	aae59bdf2585 iio:accel:mc3230: Remove duplicated error reporting in .remov=
e()
	7df7563b16aa crypto: atmel-ecc - Remove duplicated error reporting in .rem=
ove()
	99ad11e06be8 i2c: dummy: Drop no-op remove function
	84965cc60e64 ASoC: cs35l45: Make cs35l45_remove() return void
	fb68cb963bb7 ASoC: da732x: Drop no-op remove function
	3cce931a5e44 ASoC: lm49453: Drop no-op remove function
	8a291eebeb63 ASoC: da7219: Drop no-op remove function
	60391d788a22 ASoC: ak4642: Drop no-op remove function
	51bd0abd873d extcon: fsa9480: Drop no-op remove function

I hope and assume they will all be included in v5.20-rc1. There are 5
more patches required that didn't made it into next yet (i.e. patches #1
- #5 of this series).

There are also two drivers in next that need adaption:

	drivers/gpu/drm/bridge/ti-dlpc3433.c
	drivers/tty/serial/max310x.c

The respective changes are not included here, the requrired changes are
the typical three-line adaption (i.e. s/int/void/ and drop "return 0").

Best regards
Uwe

Uwe Kleine-K=C3=B6nig (6):
  drm/i2c/sil164: Drop no-op remove function
  leds: lm3697: Remove duplicated error reporting in .remove()
  leds: lm3601x: Don't use mutex after it was destroyed
  leds: lm3601x: Improve error reporting for problems during .remove()
  gpio: pca953x: Make platform teardown callback return void
  i2c: Make remove callback return void

 Documentation/i2c/writing-clients.rst               |  2 +-
 arch/arm/mach-davinci/board-da850-evm.c             | 12 ++++--------
 arch/arm/mach-davinci/board-dm644x-evm.c            |  3 +--
 arch/arm/mach-davinci/board-dm646x-evm.c            |  3 +--
 arch/powerpc/platforms/83xx/mcu_mpc8349emitx.c      |  3 +--
 drivers/auxdisplay/ht16k33.c                        |  4 +---
 drivers/auxdisplay/lcd2s.c                          |  3 +--
 drivers/char/ipmi/ipmb_dev_int.c                    |  4 +---
 drivers/char/ipmi/ipmi_ipmb.c                       |  4 +---
 drivers/char/ipmi/ipmi_ssif.c                       |  6 ++----
 drivers/char/tpm/st33zp24/i2c.c                     |  4 +---
 drivers/char/tpm/tpm_i2c_atmel.c                    |  3 +--
 drivers/char/tpm/tpm_i2c_infineon.c                 |  4 +---
 drivers/char/tpm/tpm_i2c_nuvoton.c                  |  3 +--
 drivers/char/tpm/tpm_tis_i2c_cr50.c                 |  6 ++----
 drivers/clk/clk-cdce706.c                           |  3 +--
 drivers/clk/clk-cs2000-cp.c                         |  4 +---
 drivers/clk/clk-si514.c                             |  3 +--
 drivers/clk/clk-si5341.c                            |  4 +---
 drivers/clk/clk-si5351.c                            |  4 +---
 drivers/clk/clk-si570.c                             |  3 +--
 drivers/clk/clk-versaclock5.c                       |  4 +---
 drivers/crypto/atmel-ecc.c                          |  6 ++----
 drivers/crypto/atmel-sha204a.c                      |  6 ++----
 drivers/extcon/extcon-rt8973a.c                     |  4 +---
 drivers/gpio/gpio-adp5588.c                         |  4 +---
 drivers/gpio/gpio-max7300.c                         |  4 +---
 drivers/gpio/gpio-pca953x.c                         | 13 +++----------
 drivers/gpio/gpio-pcf857x.c                         |  4 +---
 drivers/gpio/gpio-tpic2810.c                        |  4 +---
 drivers/gpu/drm/bridge/adv7511/adv7511_drv.c        |  4 +---
 drivers/gpu/drm/bridge/analogix/analogix-anx6345.c  |  4 +---
 drivers/gpu/drm/bridge/analogix/analogix-anx78xx.c  |  4 +---
 drivers/gpu/drm/bridge/analogix/anx7625.c           |  4 +---
 drivers/gpu/drm/bridge/chrontel-ch7033.c            |  4 +---
 drivers/gpu/drm/bridge/cros-ec-anx7688.c            |  4 +---
 drivers/gpu/drm/bridge/ite-it6505.c                 |  4 +---
 drivers/gpu/drm/bridge/ite-it66121.c                |  4 +---
 drivers/gpu/drm/bridge/lontium-lt8912b.c            |  3 +--
 drivers/gpu/drm/bridge/lontium-lt9211.c             |  4 +---
 drivers/gpu/drm/bridge/lontium-lt9611.c             |  4 +---
 drivers/gpu/drm/bridge/lontium-lt9611uxc.c          |  4 +---
 .../drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c    |  8 ++------
 drivers/gpu/drm/bridge/nxp-ptn3460.c                |  4 +---
 drivers/gpu/drm/bridge/parade-ps8622.c              |  4 +---
 drivers/gpu/drm/bridge/parade-ps8640.c              |  4 +---
 drivers/gpu/drm/bridge/sii902x.c                    |  4 +---
 drivers/gpu/drm/bridge/sii9234.c                    |  4 +---
 drivers/gpu/drm/bridge/sil-sii8620.c                |  4 +---
 drivers/gpu/drm/bridge/tc358767.c                   |  4 +---
 drivers/gpu/drm/bridge/tc358768.c                   |  4 +---
 drivers/gpu/drm/bridge/tc358775.c                   |  4 +---
 drivers/gpu/drm/bridge/ti-sn65dsi83.c               |  4 +---
 drivers/gpu/drm/bridge/ti-tfp410.c                  |  4 +---
 drivers/gpu/drm/i2c/ch7006_drv.c                    |  4 +---
 drivers/gpu/drm/i2c/sil164_drv.c                    |  7 -------
 drivers/gpu/drm/i2c/tda9950.c                       |  4 +---
 drivers/gpu/drm/i2c/tda998x_drv.c                   |  3 +--
 drivers/gpu/drm/panel/panel-olimex-lcd-olinuxino.c  |  4 +---
 .../gpu/drm/panel/panel-raspberrypi-touchscreen.c   |  4 +---
 drivers/gpu/drm/solomon/ssd130x-i2c.c               |  4 +---
 drivers/hid/i2c-hid/i2c-hid-core.c                  |  4 +---
 drivers/hid/i2c-hid/i2c-hid.h                       |  2 +-
 drivers/hwmon/adc128d818.c                          |  4 +---
 drivers/hwmon/adt7470.c                             |  3 +--
 drivers/hwmon/asb100.c                              |  6 ++----
 drivers/hwmon/asc7621.c                             |  4 +---
 drivers/hwmon/dme1737.c                             |  4 +---
 drivers/hwmon/f75375s.c                             |  5 ++---
 drivers/hwmon/fschmd.c                              |  6 ++----
 drivers/hwmon/ftsteutates.c                         |  3 +--
 drivers/hwmon/ina209.c                              |  4 +---
 drivers/hwmon/ina3221.c                             |  4 +---
 drivers/hwmon/jc42.c                                |  3 +--
 drivers/hwmon/mcp3021.c                             |  4 +---
 drivers/hwmon/occ/p8_i2c.c                          |  4 +---
 drivers/hwmon/pcf8591.c                             |  3 +--
 drivers/hwmon/smm665.c                              |  3 +--
 drivers/hwmon/tps23861.c                            |  4 +---
 drivers/hwmon/w83781d.c                             |  4 +---
 drivers/hwmon/w83791d.c                             |  6 ++----
 drivers/hwmon/w83792d.c                             |  6 ++----
 drivers/hwmon/w83793.c                              |  6 ++----
 drivers/hwmon/w83795.c                              |  4 +---
 drivers/hwmon/w83l785ts.c                           |  6 ++----
 drivers/i2c/i2c-core-base.c                         |  6 +-----
 drivers/i2c/i2c-slave-eeprom.c                      |  4 +---
 drivers/i2c/i2c-slave-testunit.c                    |  3 +--
 drivers/i2c/i2c-smbus.c                             |  3 +--
 drivers/i2c/muxes/i2c-mux-ltc4306.c                 |  4 +---
 drivers/i2c/muxes/i2c-mux-pca9541.c                 |  3 +--
 drivers/i2c/muxes/i2c-mux-pca954x.c                 |  3 +--
 drivers/iio/accel/bma180.c                          |  4 +---
 drivers/iio/accel/bma400_i2c.c                      |  4 +---
 drivers/iio/accel/bmc150-accel-i2c.c                |  4 +---
 drivers/iio/accel/kxcjk-1013.c                      |  4 +---
 drivers/iio/accel/kxsd9-i2c.c                       |  4 +---
 drivers/iio/accel/mc3230.c                          |  4 +---
 drivers/iio/accel/mma7455_i2c.c                     |  4 +---
 drivers/iio/accel/mma7660.c                         |  4 +---
 drivers/iio/accel/mma8452.c                         |  4 +---
 drivers/iio/accel/mma9551.c                         |  4 +---
 drivers/iio/accel/mma9553.c                         |  4 +---
 drivers/iio/accel/stk8312.c                         |  4 +---
 drivers/iio/accel/stk8ba50.c                        |  4 +---
 drivers/iio/adc/ad799x.c                            |  4 +---
 drivers/iio/adc/ina2xx-adc.c                        |  4 +---
 drivers/iio/adc/ltc2497.c                           |  4 +---
 drivers/iio/adc/ti-ads1015.c                        |  4 +---
 drivers/iio/chemical/atlas-sensor.c                 |  4 +---
 drivers/iio/chemical/ccs811.c                       |  4 +---
 drivers/iio/chemical/sgp30.c                        |  4 +---
 drivers/iio/dac/ad5380.c                            |  4 +---
 drivers/iio/dac/ad5446.c                            |  4 +---
 drivers/iio/dac/ad5593r.c                           |  4 +---
 drivers/iio/dac/ad5696-i2c.c                        |  4 +---
 drivers/iio/dac/ds4424.c                            |  4 +---
 drivers/iio/dac/m62332.c                            |  4 +---
 drivers/iio/dac/mcp4725.c                           |  4 +---
 drivers/iio/dac/ti-dac5571.c                        |  4 +---
 drivers/iio/gyro/bmg160_i2c.c                       |  4 +---
 drivers/iio/gyro/fxas21002c_i2c.c                   |  4 +---
 drivers/iio/gyro/itg3200_core.c                     |  4 +---
 drivers/iio/gyro/mpu3050-i2c.c                      |  4 +---
 drivers/iio/health/afe4404.c                        |  4 +---
 drivers/iio/health/max30100.c                       |  4 +---
 drivers/iio/health/max30102.c                       |  4 +---
 drivers/iio/humidity/hdc2010.c                      |  4 +---
 drivers/iio/imu/inv_mpu6050/inv_mpu_i2c.c           |  4 +---
 drivers/iio/imu/kmx61.c                             |  4 +---
 drivers/iio/light/apds9300.c                        |  4 +---
 drivers/iio/light/apds9960.c                        |  4 +---
 drivers/iio/light/bh1750.c                          |  4 +---
 drivers/iio/light/bh1780.c                          |  4 +---
 drivers/iio/light/cm3232.c                          |  4 +---
 drivers/iio/light/cm36651.c                         |  4 +---
 drivers/iio/light/gp2ap002.c                        |  4 +---
 drivers/iio/light/gp2ap020a00f.c                    |  4 +---
 drivers/iio/light/isl29028.c                        |  4 +---
 drivers/iio/light/isl29125.c                        |  4 +---
 drivers/iio/light/jsa1212.c                         |  4 +---
 drivers/iio/light/ltr501.c                          |  4 +---
 drivers/iio/light/opt3001.c                         |  6 ++----
 drivers/iio/light/pa12203001.c                      |  4 +---
 drivers/iio/light/rpr0521.c                         |  4 +---
 drivers/iio/light/stk3310.c                         |  4 +---
 drivers/iio/light/tcs3472.c                         |  4 +---
 drivers/iio/light/tsl2563.c                         |  4 +---
 drivers/iio/light/tsl2583.c                         |  4 +---
 drivers/iio/light/tsl4531.c                         |  4 +---
 drivers/iio/light/us5182d.c                         |  4 +---
 drivers/iio/light/vcnl4000.c                        |  4 +---
 drivers/iio/light/vcnl4035.c                        |  4 +---
 drivers/iio/light/veml6070.c                        |  4 +---
 drivers/iio/magnetometer/ak8974.c                   |  4 +---
 drivers/iio/magnetometer/ak8975.c                   |  4 +---
 drivers/iio/magnetometer/bmc150_magn_i2c.c          |  4 +---
 drivers/iio/magnetometer/hmc5843_i2c.c              |  4 +---
 drivers/iio/magnetometer/mag3110.c                  |  4 +---
 drivers/iio/magnetometer/yamaha-yas530.c            |  4 +---
 drivers/iio/potentiostat/lmp91000.c                 |  4 +---
 drivers/iio/pressure/mpl3115.c                      |  4 +---
 drivers/iio/pressure/ms5611_i2c.c                   |  4 +---
 drivers/iio/pressure/zpa2326_i2c.c                  |  4 +---
 drivers/iio/proximity/pulsedlight-lidar-lite-v2.c   |  4 +---
 drivers/iio/proximity/sx9500.c                      |  4 +---
 drivers/iio/temperature/mlx90614.c                  |  4 +---
 drivers/iio/temperature/mlx90632.c                  |  4 +---
 drivers/input/joystick/as5011.c                     |  4 +---
 drivers/input/keyboard/adp5588-keys.c               |  4 +---
 drivers/input/keyboard/lm8323.c                     |  4 +---
 drivers/input/keyboard/lm8333.c                     |  4 +---
 drivers/input/keyboard/mcs_touchkey.c               |  4 +---
 drivers/input/keyboard/qt1070.c                     |  4 +---
 drivers/input/keyboard/qt2160.c                     |  4 +---
 drivers/input/keyboard/tca6416-keypad.c             |  4 +---
 drivers/input/misc/adxl34x-i2c.c                    |  4 +---
 drivers/input/misc/bma150.c                         |  4 +---
 drivers/input/misc/cma3000_d0x_i2c.c                |  4 +---
 drivers/input/misc/pcf8574_keypad.c                 |  4 +---
 drivers/input/mouse/synaptics_i2c.c                 |  4 +---
 drivers/input/rmi4/rmi_smbus.c                      |  4 +---
 drivers/input/touchscreen/atmel_mxt_ts.c            |  4 +---
 drivers/input/touchscreen/bu21013_ts.c              |  4 +---
 drivers/input/touchscreen/cyttsp4_i2c.c             |  4 +---
 drivers/input/touchscreen/edt-ft5x06.c              |  4 +---
 drivers/input/touchscreen/goodix.c                  |  4 +---
 drivers/input/touchscreen/migor_ts.c                |  4 +---
 drivers/input/touchscreen/s6sy761.c                 |  4 +---
 drivers/input/touchscreen/stmfts.c                  |  4 +---
 drivers/input/touchscreen/tsc2004.c                 |  4 +---
 drivers/leds/flash/leds-as3645a.c                   |  4 +---
 drivers/leds/flash/leds-lm3601x.c                   | 13 +++++++------
 drivers/leds/flash/leds-rt4505.c                    |  3 +--
 drivers/leds/leds-an30259a.c                        |  4 +---
 drivers/leds/leds-aw2013.c                          |  4 +---
 drivers/leds/leds-bd2802.c                          |  4 +---
 drivers/leds/leds-blinkm.c                          |  3 +--
 drivers/leds/leds-is31fl319x.c                      |  3 +--
 drivers/leds/leds-is31fl32xx.c                      |  4 +---
 drivers/leds/leds-lm3530.c                          |  3 +--
 drivers/leds/leds-lm3532.c                          |  4 +---
 drivers/leds/leds-lm355x.c                          |  4 +---
 drivers/leds/leds-lm3642.c                          |  3 +--
 drivers/leds/leds-lm3692x.c                         |  4 +---
 drivers/leds/leds-lm3697.c                          |  8 ++------
 drivers/leds/leds-lp3944.c                          |  4 +---
 drivers/leds/leds-lp3952.c                          |  4 +---
 drivers/leds/leds-lp50xx.c                          |  4 +---
 drivers/leds/leds-lp5521.c                          |  4 +---
 drivers/leds/leds-lp5523.c                          |  4 +---
 drivers/leds/leds-lp5562.c                          |  4 +---
 drivers/leds/leds-lp8501.c                          |  4 +---
 drivers/leds/leds-lp8860.c                          |  4 +---
 drivers/leds/leds-pca9532.c                         |  6 ++----
 drivers/leds/leds-tca6507.c                         |  4 +---
 drivers/leds/leds-turris-omnia.c                    |  4 +---
 drivers/macintosh/ams/ams-i2c.c                     |  4 +---
 drivers/macintosh/therm_adt746x.c                   |  4 +---
 drivers/macintosh/therm_windtunnel.c                |  4 +---
 drivers/macintosh/windfarm_ad7417_sensor.c          |  4 +---
 drivers/macintosh/windfarm_fcu_controls.c           |  3 +--
 drivers/macintosh/windfarm_lm75_sensor.c            |  4 +---
 drivers/macintosh/windfarm_lm87_sensor.c            |  4 +---
 drivers/macintosh/windfarm_max6690_sensor.c         |  4 +---
 drivers/macintosh/windfarm_smu_sat.c                |  4 +---
 drivers/media/cec/i2c/ch7322.c                      |  4 +---
 drivers/media/dvb-frontends/a8293.c                 |  3 +--
 drivers/media/dvb-frontends/af9013.c                |  4 +---
 drivers/media/dvb-frontends/af9033.c                |  4 +---
 drivers/media/dvb-frontends/au8522_decoder.c        |  3 +--
 drivers/media/dvb-frontends/cxd2099.c               |  4 +---
 drivers/media/dvb-frontends/cxd2820r_core.c         |  4 +---
 drivers/media/dvb-frontends/dvb-pll.c               |  3 +--
 drivers/media/dvb-frontends/lgdt3306a.c             |  4 +---
 drivers/media/dvb-frontends/lgdt330x.c              |  4 +---
 drivers/media/dvb-frontends/m88ds3103.c             |  3 +--
 drivers/media/dvb-frontends/mn88443x.c              |  4 +---
 drivers/media/dvb-frontends/mn88472.c               |  4 +---
 drivers/media/dvb-frontends/mn88473.c               |  4 +---
 drivers/media/dvb-frontends/mxl692.c                |  4 +---
 drivers/media/dvb-frontends/rtl2830.c               |  4 +---
 drivers/media/dvb-frontends/rtl2832.c               |  4 +---
 drivers/media/dvb-frontends/si2165.c                |  3 +--
 drivers/media/dvb-frontends/si2168.c                |  4 +---
 drivers/media/dvb-frontends/sp2.c                   |  3 +--
 drivers/media/dvb-frontends/stv090x.c               |  3 +--
 drivers/media/dvb-frontends/stv6110x.c              |  3 +--
 drivers/media/dvb-frontends/tc90522.c               |  3 +--
 drivers/media/dvb-frontends/tda10071.c              |  3 +--
 drivers/media/dvb-frontends/ts2020.c                |  3 +--
 drivers/media/i2c/ad5820.c                          |  3 +--
 drivers/media/i2c/ad9389b.c                         |  3 +--
 drivers/media/i2c/adp1653.c                         |  4 +---
 drivers/media/i2c/adv7170.c                         |  3 +--
 drivers/media/i2c/adv7175.c                         |  3 +--
 drivers/media/i2c/adv7180.c                         |  4 +---
 drivers/media/i2c/adv7183.c                         |  3 +--
 drivers/media/i2c/adv7343.c                         |  4 +---
 drivers/media/i2c/adv7393.c                         |  4 +---
 drivers/media/i2c/adv748x/adv748x-core.c            |  4 +---
 drivers/media/i2c/adv7511-v4l2.c                    |  3 +--
 drivers/media/i2c/adv7604.c                         |  3 +--
 drivers/media/i2c/adv7842.c                         |  3 +--
 drivers/media/i2c/ak7375.c                          |  4 +---
 drivers/media/i2c/ak881x.c                          |  4 +---
 drivers/media/i2c/bt819.c                           |  3 +--
 drivers/media/i2c/bt856.c                           |  3 +--
 drivers/media/i2c/bt866.c                           |  3 +--
 drivers/media/i2c/ccs/ccs-core.c                    |  4 +---
 drivers/media/i2c/cs3308.c                          |  3 +--
 drivers/media/i2c/cs5345.c                          |  3 +--
 drivers/media/i2c/cs53l32a.c                        |  3 +--
 drivers/media/i2c/cx25840/cx25840-core.c            |  3 +--
 drivers/media/i2c/dw9714.c                          |  4 +---
 drivers/media/i2c/dw9768.c                          |  4 +---
 drivers/media/i2c/dw9807-vcm.c                      |  4 +---
 drivers/media/i2c/et8ek8/et8ek8_driver.c            |  4 +---
 drivers/media/i2c/hi556.c                           |  4 +---
 drivers/media/i2c/hi846.c                           |  4 +---
 drivers/media/i2c/hi847.c                           |  4 +---
 drivers/media/i2c/imx208.c                          |  4 +---
 drivers/media/i2c/imx214.c                          |  4 +---
 drivers/media/i2c/imx219.c                          |  4 +---
 drivers/media/i2c/imx258.c                          |  4 +---
 drivers/media/i2c/imx274.c                          |  3 +--
 drivers/media/i2c/imx290.c                          |  4 +---
 drivers/media/i2c/imx319.c                          |  4 +---
 drivers/media/i2c/imx334.c                          |  4 +---
 drivers/media/i2c/imx335.c                          |  4 +---
 drivers/media/i2c/imx355.c                          |  4 +---
 drivers/media/i2c/imx412.c                          |  4 +---
 drivers/media/i2c/ir-kbd-i2c.c                      |  4 +---
 drivers/media/i2c/isl7998x.c                        |  4 +---
 drivers/media/i2c/ks0127.c                          |  3 +--
 drivers/media/i2c/lm3560.c                          |  4 +---
 drivers/media/i2c/lm3646.c                          |  4 +---
 drivers/media/i2c/m52790.c                          |  3 +--
 drivers/media/i2c/m5mols/m5mols_core.c              |  4 +---
 drivers/media/i2c/max2175.c                         |  4 +---
 drivers/media/i2c/max9286.c                         |  4 +---
 drivers/media/i2c/ml86v7667.c                       |  4 +---
 drivers/media/i2c/msp3400-driver.c                  |  3 +--
 drivers/media/i2c/mt9m001.c                         |  4 +---
 drivers/media/i2c/mt9m032.c                         |  3 +--
 drivers/media/i2c/mt9m111.c                         |  4 +---
 drivers/media/i2c/mt9p031.c                         |  4 +---
 drivers/media/i2c/mt9t001.c                         |  3 +--
 drivers/media/i2c/mt9t112.c                         |  4 +---
 drivers/media/i2c/mt9v011.c                         |  4 +---
 drivers/media/i2c/mt9v032.c                         |  4 +---
 drivers/media/i2c/mt9v111.c                         |  4 +---
 drivers/media/i2c/noon010pc30.c                     |  4 +---
 drivers/media/i2c/og01a1b.c                         |  4 +---
 drivers/media/i2c/ov02a10.c                         |  4 +---
 drivers/media/i2c/ov08d10.c                         |  4 +---
 drivers/media/i2c/ov13858.c                         |  4 +---
 drivers/media/i2c/ov13b10.c                         |  4 +---
 drivers/media/i2c/ov2640.c                          |  3 +--
 drivers/media/i2c/ov2659.c                          |  4 +---
 drivers/media/i2c/ov2680.c                          |  4 +---
 drivers/media/i2c/ov2685.c                          |  4 +---
 drivers/media/i2c/ov2740.c                          |  4 +---
 drivers/media/i2c/ov5640.c                          |  4 +---
 drivers/media/i2c/ov5645.c                          |  4 +---
 drivers/media/i2c/ov5647.c                          |  4 +---
 drivers/media/i2c/ov5648.c                          |  4 +---
 drivers/media/i2c/ov5670.c                          |  4 +---
 drivers/media/i2c/ov5675.c                          |  4 +---
 drivers/media/i2c/ov5693.c                          |  4 +---
 drivers/media/i2c/ov5695.c                          |  4 +---
 drivers/media/i2c/ov6650.c                          |  3 +--
 drivers/media/i2c/ov7251.c                          |  4 +---
 drivers/media/i2c/ov7640.c                          |  4 +---
 drivers/media/i2c/ov7670.c                          |  3 +--
 drivers/media/i2c/ov772x.c                          |  4 +---
 drivers/media/i2c/ov7740.c                          |  3 +--
 drivers/media/i2c/ov8856.c                          |  4 +---
 drivers/media/i2c/ov8865.c                          |  4 +---
 drivers/media/i2c/ov9282.c                          |  4 +---
 drivers/media/i2c/ov9640.c                          |  4 +---
 drivers/media/i2c/ov9650.c                          |  4 +---
 drivers/media/i2c/ov9734.c                          |  4 +---
 drivers/media/i2c/rdacm20.c                         |  4 +---
 drivers/media/i2c/rdacm21.c                         |  4 +---
 drivers/media/i2c/rj54n1cb0c.c                      |  4 +---
 drivers/media/i2c/s5c73m3/s5c73m3-core.c            |  4 +---
 drivers/media/i2c/s5k4ecgx.c                        |  4 +---
 drivers/media/i2c/s5k5baf.c                         |  4 +---
 drivers/media/i2c/s5k6a3.c                          |  3 +--
 drivers/media/i2c/s5k6aa.c                          |  4 +---
 drivers/media/i2c/saa6588.c                         |  4 +---
 drivers/media/i2c/saa6752hs.c                       |  3 +--
 drivers/media/i2c/saa7110.c                         |  3 +--
 drivers/media/i2c/saa7115.c                         |  3 +--
 drivers/media/i2c/saa7127.c                         |  3 +--
 drivers/media/i2c/saa717x.c                         |  3 +--
 drivers/media/i2c/saa7185.c                         |  3 +--
 drivers/media/i2c/sony-btf-mpx.c                    |  4 +---
 drivers/media/i2c/sr030pc30.c                       |  3 +--
 drivers/media/i2c/st-mipid02.c                      |  4 +---
 drivers/media/i2c/tc358743.c                        |  4 +---
 drivers/media/i2c/tda1997x.c                        |  4 +---
 drivers/media/i2c/tda7432.c                         |  3 +--
 drivers/media/i2c/tda9840.c                         |  3 +--
 drivers/media/i2c/tea6415c.c                        |  3 +--
 drivers/media/i2c/tea6420.c                         |  3 +--
 drivers/media/i2c/ths7303.c                         |  4 +---
 drivers/media/i2c/ths8200.c                         |  4 +---
 drivers/media/i2c/tlv320aic23b.c                    |  3 +--
 drivers/media/i2c/tvaudio.c                         |  3 +--
 drivers/media/i2c/tvp514x.c                         |  3 +--
 drivers/media/i2c/tvp5150.c                         |  4 +---
 drivers/media/i2c/tvp7002.c                         |  3 +--
 drivers/media/i2c/tw2804.c                          |  3 +--
 drivers/media/i2c/tw9903.c                          |  3 +--
 drivers/media/i2c/tw9906.c                          |  3 +--
 drivers/media/i2c/tw9910.c                          |  4 +---
 drivers/media/i2c/uda1342.c                         |  3 +--
 drivers/media/i2c/upd64031a.c                       |  3 +--
 drivers/media/i2c/upd64083.c                        |  3 +--
 drivers/media/i2c/video-i2c.c                       |  4 +---
 drivers/media/i2c/vp27smpx.c                        |  3 +--
 drivers/media/i2c/vpx3220.c                         |  4 +---
 drivers/media/i2c/vs6624.c                          |  3 +--
 drivers/media/i2c/wm8739.c                          |  3 +--
 drivers/media/i2c/wm8775.c                          |  3 +--
 drivers/media/radio/radio-tea5764.c                 |  3 +--
 drivers/media/radio/saa7706h.c                      |  3 +--
 drivers/media/radio/si470x/radio-si470x-i2c.c       |  3 +--
 drivers/media/radio/si4713/si4713.c                 |  4 +---
 drivers/media/radio/tef6862.c                       |  3 +--
 drivers/media/test-drivers/vidtv/vidtv_demod.c      |  4 +---
 drivers/media/test-drivers/vidtv/vidtv_tuner.c      |  4 +---
 drivers/media/tuners/e4000.c                        |  4 +---
 drivers/media/tuners/fc2580.c                       |  3 +--
 drivers/media/tuners/m88rs6000t.c                   |  4 +---
 drivers/media/tuners/mt2060.c                       |  4 +---
 drivers/media/tuners/mxl301rf.c                     |  3 +--
 drivers/media/tuners/qm1d1b0004.c                   |  3 +--
 drivers/media/tuners/qm1d1c0042.c                   |  3 +--
 drivers/media/tuners/si2157.c                       |  4 +---
 drivers/media/tuners/tda18212.c                     |  4 +---
 drivers/media/tuners/tda18250.c                     |  4 +---
 drivers/media/tuners/tua9001.c                      |  3 +--
 drivers/media/usb/go7007/s2250-board.c              |  3 +--
 drivers/media/v4l2-core/tuner-core.c                |  3 +--
 drivers/mfd/88pm800.c                               |  4 +---
 drivers/mfd/88pm805.c                               |  4 +---
 drivers/mfd/88pm860x-core.c                         |  3 +--
 drivers/mfd/acer-ec-a500.c                          |  4 +---
 drivers/mfd/arizona-i2c.c                           |  4 +---
 drivers/mfd/axp20x-i2c.c                            |  4 +---
 drivers/mfd/da903x.c                                |  3 +--
 drivers/mfd/da9052-i2c.c                            |  3 +--
 drivers/mfd/da9055-i2c.c                            |  4 +---
 drivers/mfd/da9062-core.c                           |  4 +---
 drivers/mfd/da9150-core.c                           |  4 +---
 drivers/mfd/dm355evm_msp.c                          |  3 +--
 drivers/mfd/ene-kb3930.c                            |  4 +---
 drivers/mfd/gateworks-gsc.c                         |  4 +---
 drivers/mfd/intel_soc_pmic_core.c                   |  4 +---
 drivers/mfd/iqs62x.c                                |  4 +---
 drivers/mfd/lm3533-core.c                           |  4 +---
 drivers/mfd/lp8788.c                                |  3 +--
 drivers/mfd/madera-i2c.c                            |  4 +---
 drivers/mfd/max14577.c                              |  4 +---
 drivers/mfd/max77693.c                              |  4 +---
 drivers/mfd/max8907.c                               |  4 +---
 drivers/mfd/max8925-i2c.c                           |  3 +--
 drivers/mfd/mc13xxx-i2c.c                           |  3 +--
 drivers/mfd/menelaus.c                              |  3 +--
 drivers/mfd/ntxec.c                                 |  4 +---
 drivers/mfd/palmas.c                                |  4 +---
 drivers/mfd/pcf50633-core.c                         |  4 +---
 drivers/mfd/retu-mfd.c                              |  4 +---
 drivers/mfd/rk808.c                                 |  4 +---
 drivers/mfd/rn5t618.c                               |  4 +---
 drivers/mfd/rsmu_i2c.c                              |  4 +---
 drivers/mfd/rt4831.c                                |  4 +---
 drivers/mfd/si476x-i2c.c                            |  4 +---
 drivers/mfd/stmfx.c                                 |  4 +---
 drivers/mfd/stmpe-i2c.c                             |  4 +---
 drivers/mfd/tc3589x.c                               |  4 +---
 drivers/mfd/tps6105x.c                              |  4 +---
 drivers/mfd/tps65010.c                              |  3 +--
 drivers/mfd/tps65086.c                              |  4 +---
 drivers/mfd/tps65217.c                              |  4 +---
 drivers/mfd/tps6586x.c                              |  3 +--
 drivers/mfd/tps65912-i2c.c                          |  4 +---
 drivers/mfd/twl-core.c                              |  3 +--
 drivers/mfd/twl6040.c                               |  4 +---
 drivers/mfd/wm8994-core.c                           |  4 +---
 drivers/misc/ad525x_dpot-i2c.c                      |  3 +--
 drivers/misc/apds9802als.c                          |  3 +--
 drivers/misc/apds990x.c                             |  3 +--
 drivers/misc/bh1770glc.c                            |  4 +---
 drivers/misc/ds1682.c                               |  3 +--
 drivers/misc/eeprom/at24.c                          |  4 +---
 drivers/misc/eeprom/ee1004.c                        |  4 +---
 drivers/misc/eeprom/eeprom.c                        |  4 +---
 drivers/misc/eeprom/idt_89hpesx.c                   |  4 +---
 drivers/misc/eeprom/max6875.c                       |  4 +---
 drivers/misc/hmc6352.c                              |  3 +--
 drivers/misc/ics932s401.c                           |  5 ++---
 drivers/misc/isl29003.c                             |  3 +--
 drivers/misc/isl29020.c                             |  3 +--
 drivers/misc/lis3lv02d/lis3lv02d_i2c.c              |  3 +--
 drivers/misc/tsl2550.c                              |  4 +---
 drivers/mtd/maps/pismo.c                            |  4 +---
 drivers/net/dsa/lan9303_i2c.c                       |  6 ++----
 drivers/net/dsa/microchip/ksz9477_i2c.c             |  4 +---
 drivers/net/dsa/xrs700x/xrs700x_i2c.c               |  6 ++----
 drivers/net/ethernet/mellanox/mlxsw/i2c.c           |  4 +---
 drivers/net/mctp/mctp-i2c.c                         |  3 +--
 drivers/nfc/fdp/i2c.c                               |  4 +---
 drivers/nfc/microread/i2c.c                         |  4 +---
 drivers/nfc/nfcmrvl/i2c.c                           |  4 +---
 drivers/nfc/nxp-nci/i2c.c                           |  4 +---
 drivers/nfc/pn533/i2c.c                             |  4 +---
 drivers/nfc/pn544/i2c.c                             |  4 +---
 drivers/nfc/s3fwrn5/i2c.c                           |  4 +---
 drivers/nfc/st-nci/i2c.c                            |  4 +---
 drivers/nfc/st21nfca/i2c.c                          |  4 +---
 drivers/of/unittest.c                               |  6 ++----
 drivers/platform/chrome/cros_ec_i2c.c               |  4 +---
 drivers/platform/surface/surface3_power.c           |  4 +---
 drivers/platform/x86/asus-tf103c-dock.c             |  4 +---
 drivers/platform/x86/intel/int3472/tps68470.c       |  4 +---
 drivers/power/supply/bq2415x_charger.c              |  4 +---
 drivers/power/supply/bq24190_charger.c              |  4 +---
 drivers/power/supply/bq24257_charger.c              |  4 +---
 drivers/power/supply/bq25890_charger.c              |  4 +---
 drivers/power/supply/bq27xxx_battery_i2c.c          |  4 +---
 drivers/power/supply/cw2015_battery.c               |  3 +--
 drivers/power/supply/ds2782_battery.c               |  4 +---
 drivers/power/supply/lp8727_charger.c               |  3 +--
 drivers/power/supply/rt5033_battery.c               |  4 +---
 drivers/power/supply/rt9455_charger.c               |  4 +---
 drivers/power/supply/smb347-charger.c               |  4 +---
 drivers/power/supply/z2_battery.c                   |  4 +---
 drivers/pwm/pwm-pca9685.c                           |  4 +---
 drivers/regulator/da9121-regulator.c                |  3 +--
 drivers/regulator/lp8755.c                          |  4 +---
 drivers/regulator/rpi-panel-attiny-regulator.c      |  4 +---
 drivers/rtc/rtc-bq32k.c                             |  4 +---
 drivers/rtc/rtc-ds1374.c                            |  4 +---
 drivers/rtc/rtc-isl12026.c                          |  3 +--
 drivers/rtc/rtc-m41t80.c                            |  4 +---
 drivers/rtc/rtc-rs5c372.c                           |  3 +--
 drivers/rtc/rtc-x1205.c                             |  3 +--
 drivers/staging/media/atomisp/i2c/atomisp-gc0310.c  |  4 +---
 drivers/staging/media/atomisp/i2c/atomisp-gc2235.c  |  4 +---
 drivers/staging/media/atomisp/i2c/atomisp-lm3554.c  |  4 +---
 drivers/staging/media/atomisp/i2c/atomisp-mt9m114.c |  3 +--
 drivers/staging/media/atomisp/i2c/atomisp-ov2680.c  |  4 +---
 drivers/staging/media/atomisp/i2c/atomisp-ov2722.c  |  4 +---
 .../media/atomisp/i2c/ov5693/atomisp-ov5693.c       |  4 +---
 drivers/staging/media/max96712/max96712.c           |  4 +---
 drivers/staging/most/i2c/i2c.c                      |  4 +---
 drivers/staging/olpc_dcon/olpc_dcon.c               |  4 +---
 drivers/tty/serial/sc16is7xx.c                      |  4 +---
 drivers/usb/misc/usb3503.c                          |  4 +---
 drivers/usb/phy/phy-isp1301-omap.c                  |  4 +---
 drivers/usb/phy/phy-isp1301.c                       |  4 +---
 drivers/usb/typec/hd3ss3220.c                       |  4 +---
 drivers/usb/typec/mux/fsa4480.c                     |  4 +---
 drivers/usb/typec/mux/pi3usb30532.c                 |  3 +--
 drivers/usb/typec/rt1719.c                          |  4 +---
 drivers/usb/typec/stusb160x.c                       |  4 +---
 drivers/usb/typec/tcpm/fusb302.c                    |  4 +---
 drivers/usb/typec/tcpm/tcpci.c                      |  4 +---
 drivers/usb/typec/tcpm/tcpci_maxim.c                |  4 +---
 drivers/usb/typec/tcpm/tcpci_rt1711h.c              |  3 +--
 drivers/usb/typec/tipd/core.c                       |  4 +---
 drivers/usb/typec/ucsi/ucsi_ccg.c                   |  4 +---
 drivers/usb/typec/wusb3801.c                        |  4 +---
 drivers/video/backlight/adp8860_bl.c                |  4 +---
 drivers/video/backlight/adp8870_bl.c                |  4 +---
 drivers/video/backlight/arcxcnn_bl.c                |  4 +---
 drivers/video/backlight/bd6107.c                    |  4 +---
 drivers/video/backlight/lm3630a_bl.c                |  3 +--
 drivers/video/backlight/lm3639_bl.c                 |  3 +--
 drivers/video/backlight/lp855x_bl.c                 |  4 +---
 drivers/video/backlight/lv5207lp.c                  |  4 +---
 drivers/video/backlight/tosa_bl.c                   |  3 +--
 drivers/video/fbdev/matrox/matroxfb_maven.c         |  3 +--
 drivers/video/fbdev/ssd1307fb.c                     |  4 +---
 drivers/w1/masters/ds2482.c                         |  3 +--
 drivers/watchdog/ziirave_wdt.c                      |  4 +---
 include/linux/i2c.h                                 |  2 +-
 include/linux/platform_data/pca953x.h               |  2 +-
 lib/Kconfig.kasan                                   |  1 +
 sound/aoa/codecs/onyx.c                             |  3 +--
 sound/aoa/codecs/tas.c                              |  3 +--
 sound/pci/hda/cs35l41_hda_i2c.c                     |  4 +---
 sound/ppc/keywest.c                                 |  6 ++----
 sound/soc/codecs/adau1761-i2c.c                     |  3 +--
 sound/soc/codecs/adau1781-i2c.c                     |  3 +--
 sound/soc/codecs/ak4375.c                           |  4 +---
 sound/soc/codecs/ak4458.c                           |  4 +---
 sound/soc/codecs/ak4641.c                           |  4 +---
 sound/soc/codecs/ak5558.c                           |  4 +---
 sound/soc/codecs/cs35l32.c                          |  4 +---
 sound/soc/codecs/cs35l33.c                          |  4 +---
 sound/soc/codecs/cs35l34.c                          |  4 +---
 sound/soc/codecs/cs35l35.c                          |  4 +---
 sound/soc/codecs/cs35l36.c                          |  4 +---
 sound/soc/codecs/cs35l41-i2c.c                      |  4 +---
 sound/soc/codecs/cs35l45-i2c.c                      |  4 +---
 sound/soc/codecs/cs4234.c                           |  4 +---
 sound/soc/codecs/cs4265.c                           |  4 +---
 sound/soc/codecs/cs4270.c                           |  4 +---
 sound/soc/codecs/cs42l42.c                          |  4 +---
 sound/soc/codecs/cs42l51-i2c.c                      |  4 +---
 sound/soc/codecs/cs42l56.c                          |  3 +--
 sound/soc/codecs/cs42xx8-i2c.c                      |  4 +---
 sound/soc/codecs/cs43130.c                          |  4 +---
 sound/soc/codecs/cs4349.c                           |  4 +---
 sound/soc/codecs/cs53l30.c                          |  4 +---
 sound/soc/codecs/cx2072x.c                          |  3 +--
 sound/soc/codecs/max98090.c                         |  4 +---
 sound/soc/codecs/max9860.c                          |  3 +--
 sound/soc/codecs/max98927.c                         |  4 +---
 sound/soc/codecs/mt6660.c                           |  3 +--
 sound/soc/codecs/nau8821.c                          |  4 +---
 sound/soc/codecs/nau8825.c                          |  6 ++----
 sound/soc/codecs/pcm1789-i2c.c                      |  4 +---
 sound/soc/codecs/pcm3168a-i2c.c                     |  4 +---
 sound/soc/codecs/pcm512x-i2c.c                      |  3 +--
 sound/soc/codecs/rt274.c                            |  4 +---
 sound/soc/codecs/rt286.c                            |  4 +---
 sound/soc/codecs/rt298.c                            |  4 +---
 sound/soc/codecs/rt5616.c                           |  6 ++----
 sound/soc/codecs/rt5631.c                           |  6 ++----
 sound/soc/codecs/rt5645.c                           |  4 +---
 sound/soc/codecs/rt5663.c                           |  4 +---
 sound/soc/codecs/rt5670.c                           |  4 +---
 sound/soc/codecs/rt5677.c                           |  4 +---
 sound/soc/codecs/rt5682-i2c.c                       |  4 +---
 sound/soc/codecs/rt5682s.c                          |  4 +---
 sound/soc/codecs/rt9120.c                           |  3 +--
 sound/soc/codecs/sgtl5000.c                         |  4 +---
 sound/soc/codecs/sta350.c                           |  6 ++----
 sound/soc/codecs/tas2552.c                          |  3 +--
 sound/soc/codecs/tas5086.c                          |  6 ++----
 sound/soc/codecs/tas571x.c                          |  4 +---
 sound/soc/codecs/tas5805m.c                         |  3 +--
 sound/soc/codecs/tas6424.c                          |  4 +---
 sound/soc/codecs/tlv320adc3xxx.c                    |  3 +--
 sound/soc/codecs/tlv320aic32x4-i2c.c                |  4 +---
 sound/soc/codecs/tlv320aic3x-i2c.c                  |  4 +---
 sound/soc/codecs/tlv320dac33.c                      |  4 +---
 sound/soc/codecs/wm1250-ev1.c                       |  4 +---
 sound/soc/codecs/wm2200.c                           |  4 +---
 sound/soc/codecs/wm5100.c                           |  4 +---
 sound/soc/codecs/wm8804-i2c.c                       |  3 +--
 sound/soc/codecs/wm8900.c                           |  6 ++----
 sound/soc/codecs/wm8903.c                           |  4 +---
 sound/soc/codecs/wm8960.c                           |  6 ++----
 sound/soc/codecs/wm8962.c                           |  3 +--
 sound/soc/codecs/wm8993.c                           |  4 +---
 sound/soc/codecs/wm8996.c                           |  4 +---
 sound/soc/codecs/wm9081.c                           |  6 ++----
 624 files changed, 662 insertions(+), 1764 deletions(-)


base-commit: 03c765b0e3b4cb5063276b086c76f7a612856a9a
prerequisite-patch-id: 441efa55b1b8230c552efc4bda33e3396ee51c79
prerequisite-patch-id: af9b2b7b60700ec19ca5eb9c8b5e3f4358501210
prerequisite-patch-id: a55a1a6c4568e0182a0a7fe320e4a8f735301101
prerequisite-patch-id: 85f3fc8ebc4e16b05cd395cfc5a19d32d2d4635b
prerequisite-patch-id: 7dba4240ecd10883304b34f90a00a0b5c6a43c17
prerequisite-patch-id: ab8eebafb243d59ce09c227189e0063b4c6230af
prerequisite-patch-id: 93db70696e2b6583615d43e4d0c811f2cbd29d00
prerequisite-patch-id: c1480501d2d1293d9d408af55b39d0eda16c44b9
prerequisite-patch-id: 78607708b16be1a9fcd55d77f8f127c2a930dd9b
prerequisite-patch-id: eceb3900b5d3b49b8e452b35ddcc1f828bab49d4
prerequisite-patch-id: b33dc54db77e35a534fe652d8ef45ca8b870f96d
prerequisite-patch-id: c0d93663e6e6f0f41a5d922b487b8f73484d3da9
prerequisite-patch-id: e2fc96e9529de1148f201ee5f766ccd9f3babd4f
prerequisite-patch-id: 9c6006ce194cc70e021879f277956ddd5b323975
prerequisite-patch-id: daa3f3aa42ceb43ab883f91e27a0ed8f5dd4a933
prerequisite-patch-id: 455cc9ed7155200d373914595bb39bbf45001323
prerequisite-patch-id: bf0a83aede1f9734bab42ed176af12b580a40d20
prerequisite-patch-id: 6f986e2c0e136da0f61271d243fa4819aa6230b6
prerequisite-patch-id: fba66e092eea3888a716e5a5cbaa5df3b32cc747
prerequisite-patch-id: d4c49fe9869ecc8b4c2641c2ed5aaa49284bc119
prerequisite-patch-id: 4b8174029075c67f12c67e39888116403dfc6c36
prerequisite-patch-id: 96ac612cae066721ff375fffb64e0b029aa01690
prerequisite-patch-id: 8b77dd639267f5171d64834642b629703c5d934f
prerequisite-patch-id: d997bdc1d48a1e349b553acc1f94363e933196bd
prerequisite-patch-id: e061803cc7bee5f562cae9665b01be4294779925
prerequisite-patch-id: e2c3d2b439ac949e153a3a92fbc260f50304cb2c
prerequisite-patch-id: 65ef9c57b41612854f57c1e671c6eb7e5c2a0b3f
--=20
2.36.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220628140313.74984-1-u.kleine-koenig%40pengutronix.de.
