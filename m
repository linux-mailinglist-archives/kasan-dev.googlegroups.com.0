Return-Path: <kasan-dev+bncBDZKLXNI4ACBBKME2CLAMGQEOB2WDFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C305B57762D
	for <lists+kasan-dev@lfdr.de>; Sun, 17 Jul 2022 14:35:54 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id h65-20020a1c2144000000b003a30cae106csf3754710wmh.8
        for <lists+kasan-dev@lfdr.de>; Sun, 17 Jul 2022 05:35:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658061354; cv=pass;
        d=google.com; s=arc-20160816;
        b=fJA4g4PNtJwoA8O3l7cgpZNa+SKOR51CMi2TC/43FTxAYAR6w21mBD0PPm1jVVPx1b
         wvuJSQ5V8z5SrhmuR0NayWtstxpYU/MuLawZD2TBqBZcNUwBA3owFKeFhMCtKHNHGXUt
         m5/wyso76ySfSOmwQkPAnw7KTFgnrzbacXp1Y85uErow83Aiypqr7dbQgWfk2cphovLZ
         +YCrj0SNHjeuduMkczxK11HUzp45m9gpnKlwF4eKwxN0pLgnG79fQMgD2OuJ5jUhfgrC
         Eps/QxpN63O6S3XDUgJaWfDwS2vTqGYBk8a0cugU1UVMJeiwjKKHtnZRxqsPTff4ZtGl
         M7LA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=OjtbNWXS9YG3AUuqd5lfrs3G15pmzOGvM0dnSKOhYeE=;
        b=QID/O5ccXIXFS6NTFnrf+IlSOvo/H+nPBUN0ahnCXNAt40aK2qQ4KvW2kJOmYeXTAC
         Q2VBl32Uvs7/f1qxnwBwAMsroZNLC1EhuG1r+HSMolIywqPIwA0eLWLw57oUoXTrxDjZ
         TzuXCegvqXm1RCzh3bNseII/KEWA2SzBI04NjcK/49ElKL4t6eCmN+iq78DpTdUPXr/2
         AVeTM00dt2cNopTLnqU004IUiJ2NipN0OFC6B8fn2op5T69NZiu/18HSumNlEZjX33rC
         C1SZrjs+os1tjAn6W57eD59ZCPyoqQo7dXOwcKIQlNFARzEfNFJ/0UgtJvqdHYiELmx3
         FUkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ucw.cz header.s=gen1 header.b="DbT/eKOB";
       spf=pass (google.com: best guess record for domain of pavel@ucw.cz designates 46.255.230.98 as permitted sender) smtp.mailfrom=pavel@ucw.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ucw.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OjtbNWXS9YG3AUuqd5lfrs3G15pmzOGvM0dnSKOhYeE=;
        b=j0zYAjNduuVmpMOZj7IHVAVjvyKBzn5JFpRuqgQytcfxptyiZuMGxnJpAOlcb7rpEk
         l2E+3rcEVLfWD5gGefSpfqlXevn1RBC9NHGZteiwlxS0oUuAeMPPI47iY+/Q8EHeuDRl
         hhSD/E6tRDry9KY8Qaa4pLpIw8DUHc1iOoTUwPcO7uwbGTVTPvCxBiF0uxZnbkJZxSfC
         qQT3VgBluXa1GxwRSYS2Kc5OraPTL9mLMXFEMF2OPSrXiWyDJccrDgnFr6ZYXL88XNER
         6yJ7xd9+ngN7nXYhadTFg0HkSnN2onayXporurt/BzupCrPmYB+OQsKCqALsM33iztmB
         QK8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=OjtbNWXS9YG3AUuqd5lfrs3G15pmzOGvM0dnSKOhYeE=;
        b=A8CN9XSNlAvZMLoGkh9Dr1YzlJgHf5JZFPyQucUCTS3FcMA1murnMqfFNK6D4wQrPT
         ntP0BNX0/J3ZgkgjhPL9dhDfrHCBkj+ySVJ90wVwm6cIyPGx4i4BMR6EL+c7JtZpMyqT
         oDqU7Gyqra2frenUB66AIZzzgRpK2QScainDAasMXRdimSId//FRSfUHoAqVKzYOaoYH
         f31maF+sGW08REbTrDKKOkPm3CJRBIq8EsSeBoxKHwLLaXeengewNc7SjiEKl+8KydiS
         YvTosCOtczV7p8U9QMuC+LzVImExehJo2f235wirCg1YDVD51oteXDKalDrRYZEiCHjZ
         7n8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8hsCG9pvdVINeMJBSDd+EAb1BTh1wJyhMq2LuOds3sg1SifKlT
	oqdCJWuN4povyT50+fgVCbo=
X-Google-Smtp-Source: AGRyM1u8e5OpA1qXqPkRt8eNA75FO82S6cDaDnxtfPLGoGW/fBvRLvF1WeQSOPUgJW8nU291vmDISg==
X-Received: by 2002:a7b:c7d1:0:b0:3a3:1890:3495 with SMTP id z17-20020a7bc7d1000000b003a318903495mr2845052wmk.18.1658061354176;
        Sun, 17 Jul 2022 05:35:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e88:b0:3a2:f0cc:bc47 with SMTP id
 be8-20020a05600c1e8800b003a2f0ccbc47ls7167939wmb.2.canary-gmail; Sun, 17 Jul
 2022 05:35:53 -0700 (PDT)
X-Received: by 2002:a05:600c:35ca:b0:3a2:aee3:a8eb with SMTP id r10-20020a05600c35ca00b003a2aee3a8ebmr29033344wmq.86.1658061353083;
        Sun, 17 Jul 2022 05:35:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658061353; cv=none;
        d=google.com; s=arc-20160816;
        b=oZ/XF0+YdG0QxJMNzvaV04q5iOn0KKZWlZLZvxcTYZgihkWsRVQJHK5qHLDD5ZJmi4
         inui/uieAvO+9JqrVm0NB+G7SG6PTu8Hfc/rXQcq5h4uKmgKCvzgfsV12n2g4H2itBsv
         ae5ZzQF0Z7EKLvXWYLNQA8TgHz2kYvAazVXU66CV9Msb3vGso1zlXRaJc96Ar8ZlavH/
         F0rmfcHcfN2/5nre6V+GrQEDMxHHUI5OZUsp/I3vQfhW59Y/Fbzzrjucb3peDVM7D0yu
         D0I510Ma9s5eRAP6U9sMb5Ucl4wZgQEvfSq77IBiziSOKjzDx0AbFAESEA0QMovXxtPE
         WKTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=cBf+jWRDoNQnkPa+e9dAEb6sr2FGwNq/30S0BQ1Xqz8=;
        b=sHjc8Iq1OJmfjC78ZRtDocTLBeEVuhJCJL+u7E75tVBMu9Yhlms/8ryhTNBtFxYR8l
         1tqZkSjAGy+rQB0iOye0soC9hlZAfpPqnLP8txw8IWwzBQQ7XkZR1UEnmIQIjJdd9Psb
         JPy5jCI9aame3nAr61fqZxeOnW5bK/ngkm9HrsBcGtSibDeT4iw2uTQ58Q9p+CFZ0UzH
         F86mMrGSWcLQEAckoEf7x53OjSpwK4bHV/9fcwmia5BTzdF8n/3zGFIMpH6Lc5WM/u89
         c5IwsiQZGMSzu0c52MR1BYdU8T+IjpBXx91aCsy95+41t9Xg5mI9YIPHePAChP4s0WS4
         dlqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ucw.cz header.s=gen1 header.b="DbT/eKOB";
       spf=pass (google.com: best guess record for domain of pavel@ucw.cz designates 46.255.230.98 as permitted sender) smtp.mailfrom=pavel@ucw.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ucw.cz
Received: from jabberwock.ucw.cz (jabberwock.ucw.cz. [46.255.230.98])
        by gmr-mx.google.com with ESMTPS id bv20-20020a0560001f1400b0021d835e888fsi258456wrb.0.2022.07.17.05.35.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 17 Jul 2022 05:35:53 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of pavel@ucw.cz designates 46.255.230.98 as permitted sender) client-ip=46.255.230.98;
Received: by jabberwock.ucw.cz (Postfix, from userid 1017)
	id 7F4CB1C0003; Sun, 17 Jul 2022 14:35:51 +0200 (CEST)
Date: Sun, 17 Jul 2022 14:35:51 +0200
From: Pavel Machek <pavel@ucw.cz>
To: Uwe =?iso-8859-1?Q?Kleine-K=F6nig?= <u.kleine-koenig@pengutronix.de>
Cc: Wolfram Sang <wsa@kernel.org>,
	Uwe =?iso-8859-1?Q?Kleine-K=F6nig?= <uwe@kleine-koenig.org>,
	Sekhar Nori <nsekhar@ti.com>, Bartosz Golaszewski <brgl@bgdev.pl>,
	Russell King <linux@armlinux.org.uk>, Scott Wood <oss@buserror.net>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Robin van der Gracht <robin@protonic.nl>,
	Miguel Ojeda <ojeda@kernel.org>, Corey Minyard <minyard@acm.org>,
	Peter Huewe <peterhuewe@gmx.de>,
	Jarkko Sakkinen <jarkko@kernel.org>, Jason Gunthorpe <jgg@ziepe.ca>,
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
	Linus Walleij <linus.walleij@linaro.org>,
	Andrzej Hajda <andrzej.hajda@intel.com>,
	Neil Armstrong <narmstrong@baylibre.com>,
	Robert Foss <robert.foss@linaro.org>,
	Laurent Pinchart <Laurent.pinchart@ideasonboard.com>,
	Jonas Karlman <jonas@kwiboo.se>,
	Jernej Skrabec <jernej.skrabec@gmail.com>,
	David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
	Benson Leung <bleung@chromium.org>,
	Guenter Roeck <groeck@chromium.org>, Phong LE <ple@baylibre.com>,
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
	Rudolf Marek <r.marek@assembler.cz>, Peter Rosin <peda@axentia.se>,
	Jonathan Cameron <jic23@kernel.org>,
	Lars-Peter Clausen <lars@metafoo.de>,
	Dan Robertson <dan@dlrobertson.com>,
	Rui Miguel Silva <rmfrfs@gmail.com>,
	Tomasz Duszynski <tduszyns@gmail.com>,
	Kevin Tsai <ktsai@capellamicro.com>, Crt Mori <cmo@melexis.com>,
	Dmitry Torokhov <dmitry.torokhov@gmail.com>,
	Nick Dyer <nick@shmanahar.org>, Bastien Nocera <hadess@hadess.net>,
	Hans de Goede <hdegoede@redhat.com>,
	Maxime Coquelin <mcoquelin.stm32@gmail.com>,
	Alexandre Torgue <alexandre.torgue@foss.st.com>,
	Sakari Ailus <sakari.ailus@linux.intel.com>,
	Jan-Simon Moeller <jansimon.moeller@gmx.de>,
	Marek =?iso-8859-1?Q?Beh=FAn?= <kabel@kernel.org>,
	Colin Leroy <colin@colino.net>, Joe Tessler <jrt@google.com>,
	Hans Verkuil <hverkuil-cisco@xs4all.nl>,
	Mauro Carvalho Chehab <mchehab@kernel.org>,
	Antti Palosaari <crope@iki.fi>, Jasmin Jessich <jasmin@anw.at>,
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
	Niklas =?iso-8859-1?Q?S=F6derlund?= <niklas.soderlund+renesas@ragnatech.se>,
	Jimmy Su <jimmy.su@intel.com>, Arec Kao <arec.kao@intel.com>,
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
	Lee Jones <lee.jones@linaro.org>, Chen-Yu Tsai <wens@csie.org>,
	Support Opensource <support.opensource@diasemi.com>,
	Robert Jones <rjones@gateworks.com>,
	Andy Shevchenko <andy@kernel.org>,
	Charles Keepax <ckeepax@opensource.cirrus.com>,
	Richard Fitzgerald <rf@opensource.cirrus.com>,
	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>,
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
	Tony Lindgren <tony@atomide.com>,
	Jonathan =?iso-8859-1?Q?Neusch=E4fer?= <j.neuschaefer@gmx.net>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Eric Piel <eric.piel@tremplin-utc.net>,
	Miquel Raynal <miquel.raynal@bootlin.com>,
	Richard Weinberger <richard@nod.at>,
	Vignesh Raghavendra <vigneshr@ti.com>, Andrew Lunn <andrew@lunn.ch>,
	Vivien Didelot <vivien.didelot@gmail.com>,
	Vladimir Oltean <olteanv@gmail.com>,
	Eric Dumazet <edumazet@google.com>,
	Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
	Woojung Huh <woojung.huh@microchip.com>,
	UNGLinuxDriver@microchip.com,
	George McCollister <george.mccollister@gmail.com>,
	Ido Schimmel <idosch@nvidia.com>, Petr Machata <petrm@nvidia.com>,
	Jeremy Kerr <jk@codeconstruct.com.au>,
	Matt Johnston <matt@codeconstruct.com.au>,
	Charles Gorand <charles.gorand@effinnov.com>,
	Krzysztof Opasiak <k.opasiak@samsung.com>,
	Rob Herring <robh+dt@kernel.org>,
	Frank Rowand <frowand.list@gmail.com>,
	Mark Gross <markgross@kernel.org>,
	Maximilian Luz <luzmaximilian@gmail.com>,
	Corentin Chary <corentin.chary@gmail.com>,
	Pali =?iso-8859-1?Q?Roh=E1r?= <pali@kernel.org>,
	Sebastian Reichel <sre@kernel.org>,
	Tobias Schrammm <t.schramm@manjaro.org>,
	Liam Girdwood <lgirdwood@gmail.com>,
	Mark Brown <broonie@kernel.org>,
	Alessandro Zummo <a.zummo@towertech.it>,
	Jens Frederich <jfrederich@gmail.com>,
	Jon Nettleton <jon.nettleton@gmail.com>,
	Jiri Slaby <jirislaby@kernel.org>, Felipe Balbi <balbi@kernel.org>,
	Heikki Krogerus <heikki.krogerus@linux.intel.com>,
	Daniel Thompson <daniel.thompson@linaro.org>,
	Jingoo Han <jingoohan1@gmail.com>, Helge Deller <deller@gmx.de>,
	Evgeniy Polyakov <zbr@ioremap.net>,
	Wim Van Sebroeck <wim@linux-watchdog.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Johannes Berg <johannes@sipsolutions.net>,
	Jaroslav Kysela <perex@perex.cz>, Takashi Iwai <tiwai@suse.com>,
	James Schulman <james.schulman@cirrus.com>,
	David Rhodes <david.rhodes@cirrus.com>,
	Lucas Tanure <tanureal@opensource.cirrus.com>,
	Nuno =?iso-8859-1?Q?S=E1?= <nuno.sa@analog.com>,
	Matthias Brugger <matthias.bgg@gmail.com>,
	Oder Chiou <oder_chiou@realtek.com>,
	Fabio Estevam <festevam@gmail.com>,
	Kevin Cernekee <cernekee@chromium.org>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Maxime Ripard <maxime@cerno.tech>,
	Alvin =?utf-8?Q?=C5=A0ipraga?= <alsi@bang-olufsen.dk>,
	Lucas Stach <l.stach@pengutronix.de>,
	Jagan Teki <jagan@amarulasolutions.com>,
	Biju Das <biju.das.jz@bp.renesas.com>,
	Thomas Zimmermann <tzimmermann@suse.de>,
	Alex Deucher <alexander.deucher@amd.com>,
	Lyude Paul <lyude@redhat.com>, Xin Ji <xji@analogixsemi.com>,
	Hsin-Yi Wang <hsinyi@chromium.org>,
	=?iso-8859-1?Q?Jos=E9_Exp=F3sito?= <jose.exposito89@gmail.com>,
	Yang Li <yang.lee@linux.alibaba.com>,
	Angela Czubak <acz@semihalf.com>,
	Alistair Francis <alistair@alistair23.me>,
	Eddie James <eajames@linux.ibm.com>, Joel Stanley <joel@jms.id.au>,
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
	Daniel Palmer <daniel@0x0f.com>, Haibo Chen <haibo.chen@nxp.com>,
	Cai Huoqing <cai.huoqing@linux.dev>, Marek Vasut <marex@denx.de>,
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
	CGEL ZTE <cgel.zte@gmail.com>, Minghao Chi <chi.minghao@zte.com.cn>,
	Evgeny Novikov <novikov@ispras.ru>, Sean Young <sean@mess.org>,
	Kirill Shilimanov <kirill.shilimanov@huawei.com>,
	Moses Christopher Bollavarapu <mosescb.dev@gmail.com>,
	Paul Kocialkowski <paul.kocialkowski@bootlin.com>,
	Janusz Krzysztofik <jmkrzyszt@gmail.com>,
	Dongliang Mu <mudongliangabcd@gmail.com>,
	Colin Ian King <colin.king@intel.com>, lijian <lijian@yulong.com>,
	Kees Cook <keescook@chromium.org>, Yan Lei <yan_lei@dahuatech.com>,
	Heiner Kallweit <hkallweit1@gmail.com>,
	Jonas Malaco <jonas@protocubo.io>,
	wengjianfeng <wengjianfeng@yulong.com>,
	Rikard Falkeborn <rikard.falkeborn@gmail.com>,
	Wei Yongjun <weiyongjun1@huawei.com>, Tom Rix <trix@redhat.com>,
	Yizhuo <yzhai003@ucr.edu>, Martiros Shakhzadyan <vrzh@vrzh.net>,
	Bjorn Andersson <bjorn.andersson@linaro.org>,
	Sven Peter <sven@svenpeter.dev>,
	Alyssa Rosenzweig <alyssa@rosenzweig.io>,
	Hector Martin <marcan@marcan.st>,
	Saranya Gopal <saranya.gopal@intel.com>,
	Guido =?iso-8859-1?Q?G=FCnther?= <agx@sigxcpu.org>,
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
	Seven Lee <wtli@nuvoton.com>, Mac Chiang <mac.chiang@intel.com>,
	David Lin <CTLIN0@nuvoton.com>,
	Daniel Beer <daniel.beer@igorinstitute.com>,
	Ricard Wanderlof <ricardw@axis.com>,
	Simon Trimmer <simont@opensource.cirrus.com>,
	Shengjiu Wang <shengjiu.wang@nxp.com>,
	Viorel Suman <viorel.suman@nxp.com>,
	Nicola Lunghi <nick83ola@gmail.com>, Adam Ford <aford173@gmail.com>,
	linux-i2c@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org,
	openipmi-developer@lists.sourceforge.net,
	linux-integrity@vger.kernel.org, linux-clk@vger.kernel.org,
	linux-crypto@vger.kernel.org, linux-gpio@vger.kernel.org,
	dri-devel@lists.freedesktop.org, chrome-platform@lists.linux.dev,
	linux-rpi-kernel@lists.infradead.org, linux-input@vger.kernel.org,
	linux-hwmon@vger.kernel.org, linux-iio@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-leds@vger.kernel.org, linux-media@vger.kernel.org,
	patches@opensource.cirrus.com, alsa-devel@alsa-project.org,
	linux-omap@vger.kernel.org, linux-mtd@lists.infradead.org,
	netdev@vger.kernel.org, devicetree@vger.kernel.org,
	platform-driver-x86@vger.kernel.org,
	acpi4asus-user@lists.sourceforge.net, linux-pm@vger.kernel.org,
	linux-pwm@vger.kernel.org, linux-rtc@vger.kernel.org,
	linux-staging@lists.linux.dev, linux-serial@vger.kernel.org,
	linux-usb@vger.kernel.org, linux-fbdev@vger.kernel.org,
	linux-watchdog@vger.kernel.org, kasan-dev@googlegroups.com,
	linux-mediatek@lists.infradead.org
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Message-ID: <20220717123551.GJ14285@duo.ucw.cz>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha1;
	protocol="application/pgp-signature"; boundary="T4IYkFBVPN84tP7K"
Content-Disposition: inline
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: pavel@ucw.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ucw.cz header.s=gen1 header.b="DbT/eKOB";       spf=pass
 (google.com: best guess record for domain of pavel@ucw.cz designates
 46.255.230.98 as permitted sender) smtp.mailfrom=pavel@ucw.cz;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=ucw.cz
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


--T4IYkFBVPN84tP7K
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable

Hi!

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

2-4: Acked-by: Pavel Machek <pavel@ucw.cz>

Best regards,
							Pavel

--=20
People of Russia, stop Putin before his war on Ukraine escalates.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220717123551.GJ14285%40duo.ucw.cz.

--T4IYkFBVPN84tP7K
Content-Type: application/pgp-signature; name="signature.asc"

-----BEGIN PGP SIGNATURE-----

iF0EABECAB0WIQRPfPO7r0eAhk010v0w5/Bqldv68gUCYtQCJwAKCRAw5/Bqldv6
8uLoAKCbwzuCGlS9LKQcrBTMJXgap3//dQCfasApR6kyXVLFz8BcHxrPzA1L43I=
=dhr2
-----END PGP SIGNATURE-----

--T4IYkFBVPN84tP7K--
