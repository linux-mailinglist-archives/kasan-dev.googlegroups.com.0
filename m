Return-Path: <kasan-dev+bncBCNLTYGKMIIJHNUSSYDBUBEQC46XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x938.google.com (mail-ua1-x938.google.com [IPv6:2607:f8b0:4864:20::938])
	by mail.lfdr.de (Postfix) with ESMTPS id 0BADE567834
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jul 2022 22:12:05 +0200 (CEST)
Received: by mail-ua1-x938.google.com with SMTP id k36-20020ab04327000000b00382d2589eb2sf400590uak.8
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jul 2022 13:12:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657051924; cv=pass;
        d=google.com; s=arc-20160816;
        b=UPd3UCp/g/MAR2nqvQL57VeZQxT5h73hWVo7fEaMPPVyemNHMYOxWftUbkuZNbx7dC
         etnwxoI32wXw10IYjvRvEymRqBzOraJKEV7wUeF8SW1jlB/Xj7pgnZL2Q5LSp9hOECSP
         eJKnYYoafZiYKxs8wv3wdPaGZ99Amx2c4jtZ7TTXtq+LqA5huE6BzSaqZ4B6r6VTbgY+
         cqk7fc/jUlU8lZNyV8buzo++HG4h3LYgcCOiYVSINTR4Yv6q3jCG6c/bkKwXSU2s89hs
         Kyxl9UEEd0fjm/4EtxtvQpGQxXYEUoimq6tzd7LfhArhMPEtajADd1fwkTZz1PODt2v0
         T4aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Q+rR+WTNzwEbUHNojrtLC3zZ/T523vVWjCj+JdFgNOg=;
        b=nX+lMyPdZ0ibah3oxpA9+ShkX1u42Z40/Hdhl/B3J3a1WC19Jw3Zr0gm1NCNpc/jQN
         aMdc4A57GmlOSCcjBwk9IC2J+bsq3dNVsZYMdOaubfjTqxMiSlRP9eCScxLj7CaljQeq
         m7oNMD28y3BE4p/r+69TfCmnRXZhRjawYOAPkdbdSTU2Dkj01ks6lZ8Pk+k8+a2jaDVA
         +AbOfQCp0Vr0uLADubd4ILXZzjkiOvWk3HlXjIiLv07rejmyPYQb/l9xhHqmv2tavyBE
         Q9Dxfvgyr0gM1n7kovK4nEZzKMyHOmhK0kJEerug77j7rU5iOLLoozo+9Hd+lu20u9Y/
         pFBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jzyDqqOs;
       spf=pass (google.com: domain of tcminyard@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=tcminyard@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=acm.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+rR+WTNzwEbUHNojrtLC3zZ/T523vVWjCj+JdFgNOg=;
        b=GbaIkPwU+KlnBR/UZlGCCqUvHBgiKVV/1HYOBbm5DqgWcpwhcDPPMRSbJIsV3v6jXa
         WFPpyQ+pgYDl9ov33zxiPaEM4me9l1UqNgkjN1v7sB01UaKl7nVgMFe7JnYpY478hgti
         TUmMimKzu9UkHBNIjG6kK4GpJirY6oso33lO+/rk3ky9FK7WQBL4i7DCLKEtB87qFfTx
         LVPO2X3RrcTCyE1lw1/DhMxFc5YxPyV98eI4dbCpgCNbMUQ4B37Rhi5nWf4h+OpNUYA4
         eHw58SS4J6vWaG8HnNaWKw9yHlwwFE3vtVNDzoVy/eJnmz1gYzhCo5ZlDa+5uEjBvqNY
         DvWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:sender:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Q+rR+WTNzwEbUHNojrtLC3zZ/T523vVWjCj+JdFgNOg=;
        b=GSzfLkN+xB2lfImVdosGNObmO5LdWhtXd5dPpZLF+Q+gqVrVNyvYC37Ei5l/aUByHj
         Xi6kLIVPvn+j/CWjRM2+/bzaD8+dtDrKgExwkoFgCJIaLstHWHHI0WR3Iwd3zd5pIiBd
         KG8BtyzNPVvRLnWQSv/altq1K1AcY+jv9f7mdVaVhwLCZKuOaF9LRHzvZNyIAv97m+B8
         6Rl9lPXzqsDQo3VtpTYX/1MLN1poBNcDhfw+gKHBgqQbrbihIPnONujLeZjevZEG2Aro
         3ZowcV9nvOJN0MxiCwN9nzdov+wuE4YOXIO17fBKigSi+4EjHNSPkBIr3GLI/VyTQlwI
         sadQ==
X-Gm-Message-State: AJIora8u3l15CFXgbGhg38KedodfoF6s8QMt0astwTqDYPmz7ruabPY6
	wtVjTz9eSr8tAbHr9PMBzlA=
X-Google-Smtp-Source: AGRyM1vpHJ2+qMFaC8NnWCNmWIJZ047YXcXmgHcMzcfYqhCF/TQ9yUjipY2kxf4ULqJlv3Rq6Efxwg==
X-Received: by 2002:a05:6122:9a9:b0:370:ea7:109a with SMTP id g41-20020a05612209a900b003700ea7109amr22196258vkd.11.1657051923751;
        Tue, 05 Jul 2022 13:12:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:cb0b:0:b0:354:31d7:3b5e with SMTP id b11-20020a67cb0b000000b0035431d73b5els8059703vsl.6.gmail;
 Tue, 05 Jul 2022 13:12:03 -0700 (PDT)
X-Received: by 2002:a67:a64a:0:b0:356:1e89:ef40 with SMTP id r10-20020a67a64a000000b003561e89ef40mr22416074vsh.80.1657051923168;
        Tue, 05 Jul 2022 13:12:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657051923; cv=none;
        d=google.com; s=arc-20160816;
        b=mwaQ/G7XQRnPd74aMds5FBFs5km8H0wQT2UgPe/IGix0r8xDo/vGXaqGtl/eAEjLLK
         rN3ks7LbzaAvVx77rcVv6a7k6nr2s9gRMSSP70ywFwgVsYPtzr/6PmhAqW107DfKpNqC
         1C6SpPxzIaybCSkz8z5wp/kAONeKg0JDzKTmNp5Vibq5YbSGOO2VmOyGjxGaUd5nop6h
         mExHUJ5DPG2OqwQrrn0fvJjWTGeV0lwfH8D7H2yGCCf8tlpGle6pGtPq58SySXiIose/
         WvInz5c2Bc/VVJgLLbWPcdXp93BHs0bRl26vtQKDUriX2bn72u39fx6FpCYpNwdsx45T
         xyOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=OTC6txqtQct8PJfU00O4zbYgNzmzFUtn37nCnhn8x1k=;
        b=sDl+pSDOf8+fLDEVJBc/zDs9fRptkmvFXZtf80G+CZizJO/Dcr8gOyrgM3SRcuLkSM
         m59JgvvSoDLzRvku5kAlhWolo5ksEESy7VVcyBZ7HqbuRlFwe2wn3EM2M+2mZ0nwCyXy
         G+S/PqpDv9ivrAr2vBhhc4Mp6rr6UeD0uxblDwfDP4+sMtxlcoduB99Z9NV0CqSzA0NS
         qzSCcWgmggILuOMBI072PmvUsAQU2Sl2TGOEPYycswVFUsU98mmKUQznQbEJKHFRLsfK
         ywtWxXED2No+Omgt8n3Y4O3SMjk4auCAnddqU7sUEG1HHVoWnNpBQGwKf2hWyEe6Srst
         MbyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=jzyDqqOs;
       spf=pass (google.com: domain of tcminyard@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=tcminyard@gmail.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=acm.org
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id f193-20020a1f38ca000000b0036c2d9d2237si1286007vka.4.2022.07.05.13.12.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jul 2022 13:12:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of tcminyard@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id i11so15403377qtr.4
        for <kasan-dev@googlegroups.com>; Tue, 05 Jul 2022 13:12:03 -0700 (PDT)
X-Received: by 2002:ac8:7dc9:0:b0:31a:c81b:9eca with SMTP id c9-20020ac87dc9000000b0031ac81b9ecamr29457670qte.133.1657051922698;
        Tue, 05 Jul 2022 13:12:02 -0700 (PDT)
Received: from serve.minyard.net ([47.184.144.75])
        by smtp.gmail.com with ESMTPSA id he18-20020a05622a601200b00317c38c8606sm17167061qtb.20.2022.07.05.13.12.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Jul 2022 13:12:01 -0700 (PDT)
Sender: Corey Minyard <tcminyard@gmail.com>
Received: from minyard.net (unknown [IPv6:2001:470:b8f6:1b:1895:1b49:2a68:29f7])
	by serve.minyard.net (Postfix) with ESMTPSA id B3B861800BD;
	Tue,  5 Jul 2022 20:11:57 +0000 (UTC)
Date: Tue, 5 Jul 2022 15:11:56 -0500
From: Corey Minyard <minyard@acm.org>
To: Uwe =?utf-8?Q?Kleine-K=C3=B6nig?= <u.kleine-koenig@pengutronix.de>
Cc: Wolfram Sang <wsa@kernel.org>,
	Uwe =?utf-8?Q?Kleine-K=C3=B6nig?= <uwe@kleine-koenig.org>,
	Sekhar Nori <nsekhar@ti.com>, Bartosz Golaszewski <brgl@bgdev.pl>,
	Russell King <linux@armlinux.org.uk>, Scott Wood <oss@buserror.net>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Robin van der Gracht <robin@protonic.nl>,
	Miguel Ojeda <ojeda@kernel.org>, Peter Huewe <peterhuewe@gmx.de>,
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
	Pavel Machek <pavel@ucw.cz>,
	Jan-Simon Moeller <jansimon.moeller@gmx.de>,
	Marek =?utf-8?B?QmVow7pu?= <kabel@kernel.org>,
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
	Niklas =?utf-8?Q?S=C3=B6derlund?= <niklas.soderlund+renesas@ragnatech.se>,
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
	Jonathan =?utf-8?Q?Neusch=C3=A4fer?= <j.neuschaefer@gmx.net>,
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
	Pali =?utf-8?B?Um9ow6Fy?= <pali@kernel.org>,
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
	Nuno =?utf-8?B?U8Oh?= <nuno.sa@analog.com>,
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
	=?utf-8?B?Sm9zw6kgRXhww7NzaXRv?= <jose.exposito89@gmail.com>,
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
	Guido =?utf-8?Q?G=C3=BCnther?= <agx@sigxcpu.org>,
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
Message-ID: <20220705201156.GL908082@minyard.net>
Reply-To: minyard@acm.org
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
X-Original-Sender: minyard@acm.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=jzyDqqOs;       spf=pass
 (google.com: domain of tcminyard@gmail.com designates 2607:f8b0:4864:20::832
 as permitted sender) smtp.mailfrom=tcminyard@gmail.com;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=acm.org
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

On Tue, Jun 28, 2022 at 04:03:12PM +0200, Uwe Kleine-K=C3=B6nig wrote:
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

For IPMI portions below:

Acked-by: Corey Minyard <cninyard@mvista.com>

> =20
>  static const struct i2c_device_id lcd2s_i2c_id[] =3D {
> diff --git a/drivers/char/ipmi/ipmb_dev_int.c b/drivers/char/ipmi/ipmb_de=
v_int.c
> index db40037eb347..a0e9e80d92ee 100644
> --- a/drivers/char/ipmi/ipmb_dev_int.c
> +++ b/drivers/char/ipmi/ipmb_dev_int.c
> @@ -341,14 +341,12 @@ static int ipmb_probe(struct i2c_client *client)
>  	return 0;
>  }
> =20
> -static int ipmb_remove(struct i2c_client *client)
> +static void ipmb_remove(struct i2c_client *client)
>  {
>  	struct ipmb_dev *ipmb_dev =3D i2c_get_clientdata(client);
> =20
>  	i2c_slave_unregister(client);
>  	misc_deregister(&ipmb_dev->miscdev);
> -
> -	return 0;
>  }
> =20
>  static const struct i2c_device_id ipmb_id[] =3D {
> diff --git a/drivers/char/ipmi/ipmi_ipmb.c b/drivers/char/ipmi/ipmi_ipmb.=
c
> index ab19b4b3317e..25c010c9ec25 100644
> --- a/drivers/char/ipmi/ipmi_ipmb.c
> +++ b/drivers/char/ipmi/ipmi_ipmb.c
> @@ -424,7 +424,7 @@ static void ipmi_ipmb_request_events(void *send_info)
>  	/* We don't fetch events here. */
>  }
> =20
> -static int ipmi_ipmb_remove(struct i2c_client *client)
> +static void ipmi_ipmb_remove(struct i2c_client *client)
>  {
>  	struct ipmi_ipmb_dev *iidev =3D i2c_get_clientdata(client);
> =20
> @@ -438,8 +438,6 @@ static int ipmi_ipmb_remove(struct i2c_client *client=
)
>  	ipmi_ipmb_stop_thread(iidev);
> =20
>  	ipmi_unregister_smi(iidev->intf);
> -
> -	return 0;
>  }
> =20
>  static int ipmi_ipmb_probe(struct i2c_client *client)
> diff --git a/drivers/char/ipmi/ipmi_ssif.c b/drivers/char/ipmi/ipmi_ssif.=
c
> index fc742ee9c046..13da021e7c6b 100644
> --- a/drivers/char/ipmi/ipmi_ssif.c
> +++ b/drivers/char/ipmi/ipmi_ssif.c
> @@ -1281,13 +1281,13 @@ static void shutdown_ssif(void *send_info)
>  	}
>  }
> =20
> -static int ssif_remove(struct i2c_client *client)
> +static void ssif_remove(struct i2c_client *client)
>  {
>  	struct ssif_info *ssif_info =3D i2c_get_clientdata(client);
>  	struct ssif_addr_info *addr_info;
> =20
>  	if (!ssif_info)
> -		return 0;
> +		return;
> =20
>  	/*
>  	 * After this point, we won't deliver anything asychronously
> @@ -1303,8 +1303,6 @@ static int ssif_remove(struct i2c_client *client)
>  	}
> =20
>  	kfree(ssif_info);
> -
> -	return 0;
>  }
> =20
>  static int read_response(struct i2c_client *client, unsigned char *resp)

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220705201156.GL908082%40minyard.net.
