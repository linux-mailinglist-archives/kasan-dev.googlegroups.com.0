Return-Path: <kasan-dev+bncBCQYH5M5XMLRBCPV7SKQMGQENJZNKIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id BAD33563905
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Jul 2022 20:18:50 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id j13-20020ac2550d000000b00481622c87ddsf830802lfk.8
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Jul 2022 11:18:50 -0700 (PDT)
ARC-Seal: i=3; a=rsa-sha256; t=1656699530; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lw7q8T50fRlVZKgD3JyK6v9JOYXBAAGmlpU2jBWFslwrraVpgI1ChOl4BcHBWkMPLP
         p0qmDzCA1RW0Z+FYcsfkrTv5f+v4orudoOm9fE0APBSFvXIPKzOj7WzDvg2+GJva33pe
         NOTVHk8sG3tN5cTnuTDuPY6GQoKiWdnOz3p1Lk5KjtgWB7Kzs+/4T1WmRRpkb0ikJIXk
         wXYWP7twLB3MswRBvfqZG7aZc2k5DlnSv2hIAkTqNyQ7obBEicQuJN24Jo4tXCvESIb7
         blRwdVL/isMm6BFCQzAitAlyVFUkceeLl6gSYyTOnxHGOqTCD83EM9dzq/3R67c0hs+F
         qwyQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version
         :content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:date:message-id:sender
         :dkim-signature;
        bh=LeIFNQV7QitpTKQpK9T819uHctrmlz9Wqq5OUbu75Xw=;
        b=nX9fQ72PmH+qcGzrYJfYucXg2MPYCrmQ80MqOAuj8vgPDkIf6w2XcyIfgz4CBXP08R
         F9Gg4hJl2SCQ0QrDw405k0ThMEPlo2zccdYHIrFHGIObSfU3FVgrt5/FREWZ713WdVll
         p0NjmWvI2FQ9j8QHUkYu4JdNJMhTPU3LN/Bpxb9vXBUgz3SxkZghHFbBLhiADdjZ+5tk
         CaGho8Suo4wm4um/g1kOU/z820suAeLV1YVYWB1PtFPOh8PhNG702tgD/ns4ioEGOJxN
         y99C/DntAQarekr3dSVOZrG7Bid5q63Z6ihqDaN1IwEQSKzRi/Iqyd8bxH7VV2qc7Pyk
         /O4Q==
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@axentia.se header.s=selector2 header.b=A+2TT0uR;
       arc=pass (i=1 spf=pass spfdomain=axentia.se dkim=pass dkdomain=axentia.se dmarc=pass fromdomain=axentia.se);
       spf=pass (google.com: domain of peda@axentia.se designates 40.107.21.126 as permitted sender) smtp.mailfrom=peda@axentia.se
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:user-agent:subject:content-language:to:cc
         :references:from:in-reply-to:content-transfer-encoding:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LeIFNQV7QitpTKQpK9T819uHctrmlz9Wqq5OUbu75Xw=;
        b=KzTgyHlFsYgCr2WQtmj7K7UGwnLnOgdjRXaNJ5HzJZCpU9gp3wij0WouUK/u8jWFAg
         cgvvRThAMZrUfMzEpbV2C6TWPg+YYycFE0L9Xffe6zPI07rK1sOrIbxhcifmsVGhRU9Z
         586zBBl3FYh/wwuWh4HAgwk0Iwy98p3JY2vUE3NlY1VYBWDdqr/dZy3t4B10PlUJ1JhB
         FUFA8ZxqdN14hkRyOnuTYiTOZmhTXACfR8GfG5PPQT7RQRMmLd+QS1UD5FyHZr0bZtw4
         KZHI79cbhFZUCzwzOXKXwmT1aoEEejqBbXm4sp3swQSu6n2a7K6b9SzZlZzB7dpkP3gB
         NDmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LeIFNQV7QitpTKQpK9T819uHctrmlz9Wqq5OUbu75Xw=;
        b=uuSQJZIFNaCoNh3AUDbDtcU2YEicflc16n2DPeaxHZGL7iVQQfCVKPvUKjXBrWgL5v
         Ma2/utG6QNaLbVtOOia/1fsQRAE2cBD04+riUdshqm5e2UbduWK+znpugBGnQGZVt9Fw
         wwzwPdLqX71UWNRI243hLVPv1TCIczq9i2l1y3wARVRP2D4ZS/6cxvHhZiwjF7jPfaKC
         wIG25t5hUp6S4+ACnaci9yTwZrpMylyMWqiLy4qsDO0h59tJ0kUQ2BvTXamqQzZmGjRW
         HYo3Lv4UQEvmg0XDIt6g31QO6Ia6OIELtlNHXd69DGQD20cHTL2H1hTNZeePFfb+j3Kb
         8NVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8QeNYIjmabpCTfTSNccSPfNeqdFUWobe1kQki5nKyqX0bBVS5M
	7a/uMMX5Q1dY/Nf+Fqn+/3c=
X-Google-Smtp-Source: AGRyM1sljCryZ10FW4Nn0kgtkuYheou6GP9VNU1iZKwmUWXEe1fttf2BMFQpCoII7hlby66cgnmlhQ==
X-Received: by 2002:a2e:a58c:0:b0:25a:89da:cb88 with SMTP id m12-20020a2ea58c000000b0025a89dacb88mr9521812ljp.485.1656699529964;
        Fri, 01 Jul 2022 11:18:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9948:0:b0:25b:c0c2:7dec with SMTP id r8-20020a2e9948000000b0025bc0c27decls2921660ljj.11.gmail;
 Fri, 01 Jul 2022 11:18:48 -0700 (PDT)
X-Received: by 2002:a2e:a16e:0:b0:25a:9202:9a80 with SMTP id u14-20020a2ea16e000000b0025a92029a80mr8641744ljl.105.1656699528791;
        Fri, 01 Jul 2022 11:18:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656699528; cv=pass;
        d=google.com; s=arc-20160816;
        b=iWLuab1M2nmj5aSj9QI0WO0esr+sp0cLxDzbVI6ILD6sXBSlSJTPA5m1aTUDy/kp3m
         Bkna0F9DOt/9JqGYj1SiVoSamkr8MqdllUo27RTHJ+nd50J5OLyWRoo/lRYLhaceyT1n
         5hBndsgdLq8ZLg1uHhAgVE9FJ4c725Rn9HFAwG7aLeegMscDePYcOt04hXEqs1LL134E
         QAG6PCmI2MwsZRRLBbN+eqWof/S8ODKleRd0E2APUhn9TNJyzMNvLlWFlzn0eqYlnsUl
         DGamclJ+nfT2jXYitkjtSdRqOdPC+GtJfzIryOV4OWMs7+PEz8NcPiS9sxJ4wiNkfHug
         fcUQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:content-transfer-encoding:in-reply-to:from:references
         :cc:to:content-language:subject:user-agent:date:message-id
         :dkim-signature;
        bh=d9xpzPqVYAgwPLCnJG7IfZSJEh9UMzLzMOjw4DnB994=;
        b=CgWLnudzeEX2VKaJSLHP+TpoFbY43gbf0ydTj9qDM3b4TRzrCGsDqI99TODlLrlF4c
         LKAjZgWO+Sc0HqLGGGzEHCxHFP3CV0DI5RjdSvAaoN63vvoCaJUdc01IPfjuIKrl6L/p
         f+pHsRa2Gf83miZYFuNdD9QtJcOsYpXs7zs+uurGSLcNHxZQVpcHJjbzvCVhHpwUFOds
         iA0+fX+kDjD13OMJbSNijUw/faMS+0kIIuC/HqsTbXHXuLB8MQBnjFLUz7OT+5xFrk7j
         icFFNrUv7zkckaHdOvK24/YNKa4KDd8gwFoUy50FlLY9LE60fGgg0zTAf0nooUsZRPCC
         9Aug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axentia.se header.s=selector2 header.b=A+2TT0uR;
       arc=pass (i=1 spf=pass spfdomain=axentia.se dkim=pass dkdomain=axentia.se dmarc=pass fromdomain=axentia.se);
       spf=pass (google.com: domain of peda@axentia.se designates 40.107.21.126 as permitted sender) smtp.mailfrom=peda@axentia.se
Received: from EUR05-VI1-obe.outbound.protection.outlook.com (mail-vi1eur05on2126.outbound.protection.outlook.com. [40.107.21.126])
        by gmr-mx.google.com with ESMTPS id c7-20020ac25f67000000b0047faa025f65si76716lfc.12.2022.07.01.11.18.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 01 Jul 2022 11:18:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of peda@axentia.se designates 40.107.21.126 as permitted sender) client-ip=40.107.21.126;
ARC-Seal: i=1; a=rsa-sha256; s=arcselector9901; d=microsoft.com; cv=none;
 b=i5xaZNS9YkQAA4IRbpfFSdJ7ihM1u6gpHb9gUle52f4uYsNnBl2Y1HC7C+Gwv1+gOkzgt+SrM1go65jeeGlPuxZ+oSUGYHxk6VURQWBJyVb2Ghx+bK9jsBb4OyqEPMk7285/IeB44OPDJ8nAVIhte8Gcet8ziAXk2HbfNnJhW6mK5gkONb19nv44g5MpRRQi4yI/QJlm4HJttBZRzT2/efbIzP8ZK7bnfGfD2BJqYRJBfiubi40oVqHzeQntXlbqgXdnS+U7pEuXsPnfZ6asWfwgHl4rw0p3hC1Rv0/CXAkVgbhQtq2WbDzJg9Mj9VsuLRaRRsHlEpZkc2B9gTdIiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=microsoft.com;
 s=arcselector9901;
 h=From:Date:Subject:Message-ID:Content-Type:MIME-Version:X-MS-Exchange-AntiSpam-MessageData-ChunkCount:X-MS-Exchange-AntiSpam-MessageData-0:X-MS-Exchange-AntiSpam-MessageData-1;
 bh=d9xpzPqVYAgwPLCnJG7IfZSJEh9UMzLzMOjw4DnB994=;
 b=GOwfaoBzhhzjoX6z0r2dQLynJ4LDMPPaXEbZr0b2sfqDh6/H0xjQIVJP2Wp1ByngqIFANVAWAYrU+8GquJBDhmqNSJPXP+AAm+gNHN2X33Qq4cBvhaqtUaj6fTjY64bNnamyDPiBzTdaBldwyah6vdaCmnFz0gWXF7UXf4WF4v+c1kLo/NMMV12Fe3KIPr0Dhssgsc7JkmHCGFXKruUgTjNjQ2t3GYdcmOv26HsJCreUp2N3dg2BH4bdLvDVwOKLMi80lEnAymPWV4WXgn3PYSJz2zjPjIL0dWAQPPZgyxM7mslDlP84dSrsHqLY8kgsKmgwnWaNBHgF5ygt8+kDeA==
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass
 smtp.mailfrom=axentia.se; dmarc=pass action=none header.from=axentia.se;
 dkim=pass header.d=axentia.se; arc=none
Received: from AM0PR02MB4436.eurprd02.prod.outlook.com (2603:10a6:208:ed::15)
 by AM7PR02MB6484.eurprd02.prod.outlook.com (2603:10a6:20b:1b1::16) with
 Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.5395.17; Fri, 1 Jul
 2022 18:18:46 +0000
Received: from AM0PR02MB4436.eurprd02.prod.outlook.com
 ([fe80::11f2:df70:b231:2b45]) by AM0PR02MB4436.eurprd02.prod.outlook.com
 ([fe80::11f2:df70:b231:2b45%4]) with mapi id 15.20.5395.015; Fri, 1 Jul 2022
 18:18:46 +0000
Message-ID: <23b70c51-4bd7-84f9-e72c-ba6547eedf7d@axentia.se>
Date: Fri, 1 Jul 2022 20:18:26 +0200
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101
 Thunderbird/91.10.0
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Content-Language: en-US
To: =?UTF-8?Q?Uwe_Kleine-K=c3=b6nig?= <u.kleine-koenig@pengutronix.de>,
 Wolfram Sang <wsa@kernel.org>
Cc: =?UTF-8?Q?Uwe_Kleine-K=c3=b6nig?= <uwe@kleine-koenig.org>,
 Sekhar Nori <nsekhar@ti.com>, Bartosz Golaszewski <brgl@bgdev.pl>,
 Russell King <linux@armlinux.org.uk>, Scott Wood <oss@buserror.net>,
 Michael Ellerman <mpe@ellerman.id.au>,
 Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 Paul Mackerras <paulus@samba.org>, Robin van der Gracht <robin@protonic.nl>,
 Miguel Ojeda <ojeda@kernel.org>, Corey Minyard <minyard@acm.org>,
 Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>,
 Jason Gunthorpe <jgg@ziepe.ca>, Nicolas Ferre <nicolas.ferre@microchip.com>,
 Alexandre Belloni <alexandre.belloni@bootlin.com>,
 Claudiu Beznea <claudiu.beznea@microchip.com>,
 Max Filippov <jcmvbkbc@gmail.com>,
 Michael Turquette <mturquette@baylibre.com>, Stephen Boyd
 <sboyd@kernel.org>, Luca Ceresoli <luca@lucaceresoli.net>,
 Tudor Ambarus <tudor.ambarus@microchip.com>,
 Herbert Xu <herbert@gondor.apana.org.au>,
 "David S. Miller" <davem@davemloft.net>,
 MyungJoo Ham <myungjoo.ham@samsung.com>, Chanwoo Choi
 <cw00.choi@samsung.com>, Michael Hennerich <michael.hennerich@analog.com>,
 Linus Walleij <linus.walleij@linaro.org>,
 Andrzej Hajda <andrzej.hajda@intel.com>,
 Neil Armstrong <narmstrong@baylibre.com>,
 Robert Foss <robert.foss@linaro.org>,
 Laurent Pinchart <Laurent.pinchart@ideasonboard.com>,
 Jonas Karlman <jonas@kwiboo.se>, Jernej Skrabec <jernej.skrabec@gmail.com>,
 David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
 Benson Leung <bleung@chromium.org>, Guenter Roeck <groeck@chromium.org>,
 Phong LE <ple@baylibre.com>, Adrien Grassein <adrien.grassein@gmail.com>,
 Peter Senna Tschudin <peter.senna@gmail.com>,
 Martin Donnelly <martin.donnelly@ge.com>,
 Martyn Welch <martyn.welch@collabora.co.uk>,
 Douglas Anderson <dianders@chromium.org>,
 Stefan Mavrodiev <stefan@olimex.com>,
 Thierry Reding <thierry.reding@gmail.com>, Sam Ravnborg <sam@ravnborg.org>,
 Florian Fainelli <f.fainelli@gmail.com>,
 Broadcom internal kernel review list
 <bcm-kernel-feedback-list@broadcom.com>,
 Javier Martinez Canillas <javierm@redhat.com>, Jiri Kosina
 <jikos@kernel.org>, Benjamin Tissoires <benjamin.tissoires@redhat.com>,
 Jean Delvare <jdelvare@suse.com>, George Joseph
 <george.joseph@fairview5.com>, Juerg Haefliger <juergh@gmail.com>,
 Riku Voipio <riku.voipio@iki.fi>, Robert Marko <robert.marko@sartura.hr>,
 Luka Perkov <luka.perkov@sartura.hr>, Marc Hulsman <m.hulsman@tudelft.nl>,
 Rudolf Marek <r.marek@assembler.cz>, Jonathan Cameron <jic23@kernel.org>,
 Lars-Peter Clausen <lars@metafoo.de>, Dan Robertson <dan@dlrobertson.com>,
 Rui Miguel Silva <rmfrfs@gmail.com>, Tomasz Duszynski <tduszyns@gmail.com>,
 Kevin Tsai <ktsai@capellamicro.com>, Crt Mori <cmo@melexis.com>,
 Dmitry Torokhov <dmitry.torokhov@gmail.com>, Nick Dyer <nick@shmanahar.org>,
 Bastien Nocera <hadess@hadess.net>, Hans de Goede <hdegoede@redhat.com>,
 Maxime Coquelin <mcoquelin.stm32@gmail.com>,
 Alexandre Torgue <alexandre.torgue@foss.st.com>,
 Sakari Ailus <sakari.ailus@linux.intel.com>, Pavel Machek <pavel@ucw.cz>,
 Jan-Simon Moeller <jansimon.moeller@gmx.de>, =?UTF-8?Q?Marek_Beh=c3=ban?=
 <kabel@kernel.org>, Colin Leroy <colin@colino.net>,
 Joe Tessler <jrt@google.com>, Hans Verkuil <hverkuil-cisco@xs4all.nl>,
 Mauro Carvalho Chehab <mchehab@kernel.org>, Antti Palosaari <crope@iki.fi>,
 Jasmin Jessich <jasmin@anw.at>, Matthias Schwarzott <zzam@gentoo.org>,
 Olli Salonen <olli.salonen@iki.fi>, Akihiro Tsukada <tskd08@gmail.com>,
 Kieran Bingham <kieran.bingham@ideasonboard.com>,
 Tianshu Qiu <tian.shu.qiu@intel.com>,
 Dongchun Zhu <dongchun.zhu@mediatek.com>, Shawn Tu <shawnx.tu@intel.com>,
 Martin Kepplinger <martink@posteo.de>, Ricardo Ribalda <ribalda@kernel.org>,
 Dave Stevenson <dave.stevenson@raspberrypi.com>,
 Leon Luo <leonl@leopardimaging.com>, Manivannan Sadhasivam
 <mani@kernel.org>, Bingbu Cao <bingbu.cao@intel.com>,
 "Paul J. Murphy" <paul.j.murphy@intel.com>,
 Daniele Alessandrelli <daniele.alessandrelli@intel.com>,
 Michael Tretter <m.tretter@pengutronix.de>,
 Pengutronix Kernel Team <kernel@pengutronix.de>,
 Kyungmin Park <kyungmin.park@samsung.com>,
 Heungjun Kim <riverful.kim@samsung.com>,
 Ramesh Shanmugasundaram <rashanmu@gmail.com>,
 Jacopo Mondi <jacopo+renesas@jmondi.org>,
 =?UTF-8?Q?Niklas_S=c3=b6derlund?= <niklas.soderlund+renesas@ragnatech.se>,
 Jimmy Su <jimmy.su@intel.com>, Arec Kao <arec.kao@intel.com>,
 "Lad, Prabhakar" <prabhakar.csengg@gmail.com>,
 Shunqian Zheng <zhengsq@rock-chips.com>,
 Steve Longerbeam <slongerbeam@gmail.com>,
 Chiranjeevi Rapolu <chiranjeevi.rapolu@intel.com>,
 Daniel Scally <djrscally@gmail.com>, Wenyou Yang
 <wenyou.yang@microchip.com>, Petr Cvek <petrcvekcz@gmail.com>,
 Akinobu Mita <akinobu.mita@gmail.com>,
 Sylwester Nawrocki <s.nawrocki@samsung.com>,
 Benjamin Mugnier <benjamin.mugnier@foss.st.com>,
 Sylvain Petinot <sylvain.petinot@foss.st.com>,
 Mats Randgaard <matrandg@cisco.com>, Tim Harvey <tharvey@gateworks.com>,
 Matt Ranostay <matt.ranostay@konsulko.com>,
 Eduardo Valentin <edubezval@gmail.com>,
 "Daniel W. S. Almeida" <dwlsalmeida@gmail.com>,
 Lee Jones <lee.jones@linaro.org>, Chen-Yu Tsai <wens@csie.org>,
 Support Opensource <support.opensource@diasemi.com>,
 Robert Jones <rjones@gateworks.com>, Andy Shevchenko <andy@kernel.org>,
 Charles Keepax <ckeepax@opensource.cirrus.com>,
 Richard Fitzgerald <rf@opensource.cirrus.com>,
 Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>,
 Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>,
 Tony Lindgren <tony@atomide.com>, =?UTF-8?Q?Jonathan_Neusch=c3=a4fer?=
 <j.neuschaefer@gmx.net>, Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Eric Piel <eric.piel@tremplin-utc.net>,
 Miquel Raynal <miquel.raynal@bootlin.com>,
 Richard Weinberger <richard@nod.at>, Vignesh Raghavendra <vigneshr@ti.com>,
 Andrew Lunn <andrew@lunn.ch>, Vivien Didelot <vivien.didelot@gmail.com>,
 Vladimir Oltean <olteanv@gmail.com>, Eric Dumazet <edumazet@google.com>,
 Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>,
 Woojung Huh <woojung.huh@microchip.com>, UNGLinuxDriver@microchip.com,
 George McCollister <george.mccollister@gmail.com>,
 Ido Schimmel <idosch@nvidia.com>, Petr Machata <petrm@nvidia.com>,
 Jeremy Kerr <jk@codeconstruct.com.au>,
 Matt Johnston <matt@codeconstruct.com.au>,
 Charles Gorand <charles.gorand@effinnov.com>,
 Krzysztof Opasiak <k.opasiak@samsung.com>, Rob Herring <robh+dt@kernel.org>,
 Frank Rowand <frowand.list@gmail.com>, Mark Gross <markgross@kernel.org>,
 Maximilian Luz <luzmaximilian@gmail.com>,
 Corentin Chary <corentin.chary@gmail.com>, =?UTF-8?Q?Pali_Roh=c3=a1r?=
 <pali@kernel.org>, Sebastian Reichel <sre@kernel.org>,
 Tobias Schrammm <t.schramm@manjaro.org>, Liam Girdwood
 <lgirdwood@gmail.com>, Mark Brown <broonie@kernel.org>,
 Alessandro Zummo <a.zummo@towertech.it>,
 Jens Frederich <jfrederich@gmail.com>,
 Jon Nettleton <jon.nettleton@gmail.com>, Jiri Slaby <jirislaby@kernel.org>,
 Felipe Balbi <balbi@kernel.org>,
 Heikki Krogerus <heikki.krogerus@linux.intel.com>,
 Daniel Thompson <daniel.thompson@linaro.org>,
 Jingoo Han <jingoohan1@gmail.com>, Helge Deller <deller@gmx.de>,
 Evgeniy Polyakov <zbr@ioremap.net>, Wim Van Sebroeck
 <wim@linux-watchdog.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Johannes Berg <johannes@sipsolutions.net>, Jaroslav Kysela <perex@perex.cz>,
 Takashi Iwai <tiwai@suse.com>, James Schulman <james.schulman@cirrus.com>,
 David Rhodes <david.rhodes@cirrus.com>,
 Lucas Tanure <tanureal@opensource.cirrus.com>, =?UTF-8?Q?Nuno_S=c3=a1?=
 <nuno.sa@analog.com>, Matthias Brugger <matthias.bgg@gmail.com>,
 Oder Chiou <oder_chiou@realtek.com>, Fabio Estevam <festevam@gmail.com>,
 Kevin Cernekee <cernekee@chromium.org>,
 Christophe Leroy <christophe.leroy@csgroup.eu>,
 Maxime Ripard <maxime@cerno.tech>, =?UTF-8?Q?Alvin_=c5=a0ipraga?=
 <alsi@bang-olufsen.dk>, Lucas Stach <l.stach@pengutronix.de>,
 Jagan Teki <jagan@amarulasolutions.com>,
 Biju Das <biju.das.jz@bp.renesas.com>,
 Thomas Zimmermann <tzimmermann@suse.de>,
 Alex Deucher <alexander.deucher@amd.com>, Lyude Paul <lyude@redhat.com>,
 Xin Ji <xji@analogixsemi.com>, Hsin-Yi Wang <hsinyi@chromium.org>,
 =?UTF-8?B?Sm9zw6kgRXhww7NzaXRv?= <jose.exposito89@gmail.com>,
 Yang Li <yang.lee@linux.alibaba.com>, Angela Czubak <acz@semihalf.com>,
 Alistair Francis <alistair@alistair23.me>,
 Eddie James <eajames@linux.ibm.com>, Joel Stanley <joel@jms.id.au>,
 Nathan Chancellor <nathan@kernel.org>,
 Antoniu Miclaus <antoniu.miclaus@analog.com>,
 Alexandru Ardelean <ardeleanalex@gmail.com>,
 Dmitry Rokosov <DDRokosov@sberdevices.ru>,
 Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>,
 Stephan Gerhold <stephan@gerhold.net>, Miaoqian Lin <linmq006@gmail.com>,
 Gwendal Grignou <gwendal@chromium.org>,
 Yang Yingliang <yangyingliang@huawei.com>,
 Paul Cercueil <paul@crapouillou.net>, Daniel Palmer <daniel@0x0f.com>,
 Haibo Chen <haibo.chen@nxp.com>, Cai Huoqing <cai.huoqing@linux.dev>,
 Marek Vasut <marex@denx.de>, Jose Cazarin <joseespiriki@gmail.com>,
 Dan Carpenter <dan.carpenter@oracle.com>,
 Jean-Baptiste Maneyrol <jean-baptiste.maneyrol@tdk.com>,
 Michael Srba <Michael.Srba@seznam.cz>, Nikita Travkin <nikita@trvn.ru>,
 Maslov Dmitry <maslovdmitry@seeed.cc>, Jiri Valek - 2N <valek@2n.cz>,
 Arnaud Ferraris <arnaud.ferraris@collabora.com>,
 Zheyu Ma <zheyuma97@gmail.com>, Marco Felsch <m.felsch@pengutronix.de>,
 Oliver Graute <oliver.graute@kococonnector.com>,
 Zheng Yongjun <zhengyongjun3@huawei.com>, CGEL ZTE <cgel.zte@gmail.com>,
 Minghao Chi <chi.minghao@zte.com.cn>, Evgeny Novikov <novikov@ispras.ru>,
 Sean Young <sean@mess.org>, Kirill Shilimanov
 <kirill.shilimanov@huawei.com>,
 Moses Christopher Bollavarapu <mosescb.dev@gmail.com>,
 Paul Kocialkowski <paul.kocialkowski@bootlin.com>,
 Janusz Krzysztofik <jmkrzyszt@gmail.com>,
 Dongliang Mu <mudongliangabcd@gmail.com>,
 Colin Ian King <colin.king@intel.com>, lijian <lijian@yulong.com>,
 Kees Cook <keescook@chromium.org>, Yan Lei <yan_lei@dahuatech.com>,
 Heiner Kallweit <hkallweit1@gmail.com>, Jonas Malaco <jonas@protocubo.io>,
 wengjianfeng <wengjianfeng@yulong.com>,
 Rikard Falkeborn <rikard.falkeborn@gmail.com>,
 Wei Yongjun <weiyongjun1@huawei.com>, Tom Rix <trix@redhat.com>,
 Yizhuo <yzhai003@ucr.edu>, Martiros Shakhzadyan <vrzh@vrzh.net>,
 Bjorn Andersson <bjorn.andersson@linaro.org>, Sven Peter
 <sven@svenpeter.dev>, Alyssa Rosenzweig <alyssa@rosenzweig.io>,
 Hector Martin <marcan@marcan.st>, Saranya Gopal <saranya.gopal@intel.com>,
 =?UTF-8?Q?Guido_G=c3=bcnther?= <agx@sigxcpu.org>,
 Sing-Han Chen <singhanc@nvidia.com>, Wayne Chang <waynec@nvidia.com>,
 Geert Uytterhoeven <geert@linux-m68k.org>,
 Alexey Dobriyan <adobriyan@gmail.com>, Masahiro Yamada
 <masahiroy@kernel.org>, Vincent Knecht <vincent.knecht@mailoo.org>,
 Stephen Kitt <steve@sk2.org>,
 Pierre-Louis Bossart <pierre-louis.bossart@linux.intel.com>,
 Alexey Khoroshilov <khoroshilov@ispras.ru>,
 Randy Dunlap <rdunlap@infradead.org>, Alejandro Tafalla
 <atafalla@dnyon.com>, Vijendar Mukunda <Vijendar.Mukunda@amd.com>,
 Seven Lee <wtli@nuvoton.com>, Mac Chiang <mac.chiang@intel.com>,
 David Lin <CTLIN0@nuvoton.com>, Daniel Beer <daniel.beer@igorinstitute.com>,
 Ricard Wanderlof <ricardw@axis.com>,
 Simon Trimmer <simont@opensource.cirrus.com>,
 Shengjiu Wang <shengjiu.wang@nxp.com>, Viorel Suman <viorel.suman@nxp.com>,
 Nicola Lunghi <nick83ola@gmail.com>, Adam Ford <aford173@gmail.com>,
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
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
From: Peter Rosin <peda@axentia.se>
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-ClientProxiedBy: GV3P280CA0069.SWEP280.PROD.OUTLOOK.COM
 (2603:10a6:150:a::30) To AM0PR02MB4436.eurprd02.prod.outlook.com
 (2603:10a6:208:ed::15)
MIME-Version: 1.0
X-MS-PublicTrafficType: Email
X-MS-Office365-Filtering-Correlation-Id: 35b97d70-9d53-435a-bdda-08da5b8e22b6
X-MS-TrafficTypeDiagnostic: AM7PR02MB6484:EE_
X-MS-Exchange-SenderADCheck: 1
X-MS-Exchange-AntiSpam-Relay: 0
X-Microsoft-Antispam: BCL:0;
X-Microsoft-Antispam-Message-Info: vzChXohioRsHMfghJ5DgMO1CzBWBEheYRx7EtN0uNy9oOHWXqIk0jDSm9a5jy6/z7EHDKaikwrcKQY92OExj1jew9G991gwN8YUn7QKOQosVGv3Z6CJOsWZ+c30sDCljKLMIiJvgiDSoQKT+8JMuDWCPfFO3YmELn33KHn0OrSjiYC3ot39ejoiYmeGTqv54qpaoRXu+jpPjgNagufDxiT/B7AXF5HaimcBdY/FDoukGbZcNJOQqGv/EuxOe+OYjvjVL4/SbLTasuOdiQrYtXmijyp6x3DizUWKLPQSVVcyzzthRilHeDhat8Lwu2isx4HYmAK6buRwpD8+JQbNzlhuByD/RaaL85bxr93FaKdywfidBucgKS/GCX9i6D69Xt5n5v40Yfndm3W2Yej/+dOnOJtalv9yagNACQ8998v9ZfKcRh0D+br1uRMRH6TPCgKwvAaT8dpWCaJhfxhgzlBDywh+GHHqztfFaLVSvBdsZaoGi4GzhfjMNdal6ncuR4PEARpk1ey0OhNAqQHnhL2YzbISzuJWoOv+iExDoYP3j2AOZoMGiPGzCTGbd+Atreod9SRVCbZv/4suBGv+LEP5XrcravOI2sQ/qd21KF0jrHhV9LEsYGDVGwNkSEi29cx3khF9PmqsUVSL01AMa24iQzvOK9+67Plf0BPrwfw7MoeKHubjHYwcdtYMZDzrUsWGlMoccLnVxpaQlbtT1gB5SQ6M4v7r6laeOzyVcJU2rFMKEAhBP3lEyrEsDhHfe2sZXL3R14Bv94Evh4fr4nsbnZIyvwYmOsx3kEjVNVgQdk1XPlSo7u9A96QehSVTwxwWYRUXTWiW+fXyt9utdJA==
X-Forefront-Antispam-Report: CIP:255.255.255.255;CTRY:;LANG:en;SCL:1;SRV:;IPV:NLI;SFV:NSPM;H:AM0PR02MB4436.eurprd02.prod.outlook.com;PTR:;CAT:NONE;SFS:(13230016)(39830400003)(396003)(366004)(346002)(136003)(376002)(7416002)(7366002)(2616005)(7336002)(7276002)(7406005)(8936002)(86362001)(478600001)(5660300002)(6506007)(6666004)(4744005)(6512007)(41300700001)(2906002)(26005)(38100700002)(31696002)(83380400001)(186003)(31686004)(110136005)(316002)(36756003)(6486002)(76576003)(66556008)(8676002)(88732003)(66946007)(4326008)(54906003)(66476007)(43740500002)(45980500001);DIR:OUT;SFP:1102;
X-MS-Exchange-AntiSpam-MessageData-ChunkCount: 1
X-MS-Exchange-AntiSpam-MessageData-0: =?utf-8?B?bjVtdjdXeHdlMUZNZGR2Z2lTeHRadllpMEQ5SHo1ZGFHSlI3OW96YnZDOUlL?=
 =?utf-8?B?S3lMZW1JeTFVQ3dsTDUraHd6U2krQUNOWVpob0hvcVNvN0FZZkpId2RWUFZh?=
 =?utf-8?B?c2oxZ0wzcGxQRy9RTlhLTmc4VElDWXZTUkJTWFNDNWdBMHFWUUpVcEZSK2JF?=
 =?utf-8?B?Z2NtSFZRZGt0ZGwwVXQ5WlREem5oamRUUzU0Z29OOHQ3Sk5mOUI4S0ZONEJT?=
 =?utf-8?B?TjZ0TjBjcDJVNW1sMHowSko2RkFLZklzNUlVUVFJVkFoZFVodDVlcWZYWThJ?=
 =?utf-8?B?WUMvVzNJa2F4OFN4dTAwT1BGY3dWOXVPQjB0WDBmU3BXWDdVNzhtTG5wZFJG?=
 =?utf-8?B?S2xUZ2hlWFRVS1NjaDVLUm9TamFoQXV5WW5hcjBjamtPOVJSM3NINGtvMmpN?=
 =?utf-8?B?Vjg4eFdDU0VGWXA2R2plbDlJT1BxeHBYVDI0Yk9uNmFrMk5pWGROUEk5OHd4?=
 =?utf-8?B?RDB2S01xY1lxUUhML3dWeWF4YVBhT3lTRmN6emkyVmFYRW9mWmptQjJqNlBW?=
 =?utf-8?B?VjhmeHF5ZVloVjI5REpiakY5Mi9zVU1qZU8yTzlKTGltbWpNbFZNSnhNWmZQ?=
 =?utf-8?B?dEVja2ROUmxxVjhoUWJNai9ZMDNjY3NSYmF2SXFCZUNNcHJZWiszTmM3TUhj?=
 =?utf-8?B?YTN0MXFBcldYN0F1eGVzSkJpNDBPVTNLTTNKOGZ3NldnVmo1VXdsNGV5RVVN?=
 =?utf-8?B?ayt2L2dtYlAwUDVvRk9aak1ScmVTY01EK01jRWlBSUtUeEdQWFl1L29jUnlp?=
 =?utf-8?B?c2xNSFhlZU1FTHhaYVp2dXN4QXU3bU5YczBHdVZSbFFVakxZNmp5VHBMTXlu?=
 =?utf-8?B?Wk40VXBETkJ2bVpzV2ZGTitBL0tyUFcyVmFNZGhuak40S0ZlZkxpV1VwQkUx?=
 =?utf-8?B?ZlE4OHNWTlQzc2hxL3Z5Q0ZoTGQyZ0V6dUE2RnF3VzhnSkd1eHFlNWx4R25m?=
 =?utf-8?B?VmRWMzVHbFpBR0FmZk9tbWNmWEVRdXZVb3lxWFdvSTVFTUQ4RllGQmo0UVNI?=
 =?utf-8?B?UmVIcGpWMFM2QzZnWEU4TTZEVG1qVE1oVmRrcStsK2JWTytvRjJ6UU9CZ0w2?=
 =?utf-8?B?Z05ZdEhGZU1kREIwQSttcUlFY2M2OVJhaXM5L0ErNi85SG5QSFJtbTNTVTly?=
 =?utf-8?B?RldPSXdUbjZPVXNGa01xTUhpdGV0OWFGN3oyQnMrcGE3RFVYRGRPWWtVQWhT?=
 =?utf-8?B?UFVCSzJJa2ZTTllKR21wb1R6WkRzdSt4dkRjZ0tIZnpXaUIvOHZvbE0wWlVr?=
 =?utf-8?B?NS9wZmxuZzZBZC9zeUhWd0VLVXI3K2VyV3lIOWNUUXlkdm81YUNCY0ZPZFVJ?=
 =?utf-8?B?T1gxVThnREZBcU5ZTUJaRnNEd0FzVGhvWTZaLzRkNnRJR3FxQTE2UU5kcTJa?=
 =?utf-8?B?YktXS1g1Z2VqVEVRYnJRM2lvcFNIY0NjS3JsOWRTMDlzZGMxa0pKcXRYWmU3?=
 =?utf-8?B?VDVrWUFYRVRIN0NUTjRLTEtPU0cyN3dvbFV0amFBTWtQV0hOTklCb2U4aWFp?=
 =?utf-8?B?TEI3ckt2akdiajRUdEp1eGZ3SkZYVDB6YjVUZWV4MHJKYmx3bVFPS1VlTzBH?=
 =?utf-8?B?bUE3QlVCL2hMTlhENU5KR1J5N0crUHVvcWJDMlRnNUV5T3NSLzRXU3E0YXJR?=
 =?utf-8?B?ZStWbnI5RTYzUE5kd3VCMzEweGlCV0hEN1VocUhJbkRab3lWODl0S1QzOUxj?=
 =?utf-8?B?bGVsWWl1djk4a21SL09TRnd4WDQrK1B4WnpNcm94ZXVkOEFjK2wwSkNsd2JV?=
 =?utf-8?B?VTkvVlV1amV0QjhwNlEwUVRxL3lGR0xzQmRDb2ZhcUw5eWEzU2RCRmRZa3Er?=
 =?utf-8?B?c0diOC9pdTR3V0ExL1hpWS9CUG44R2RQci93UUNDUG5BMDVvSkowZkV6ZlE4?=
 =?utf-8?B?VHNCYTZMSjhtVk9pemFINHU4dURrNGlLbjY1Z3g5b1R6aElCMkRvdTFTdnFl?=
 =?utf-8?B?RnJqMUNJYURHeGU2RnhlV014ODl2dTYrS2lPR21qMmhaZWU3UG5KQ3ZUeXJt?=
 =?utf-8?B?TDhmY0dFeHpTNnp1TjcybHpzR1JSczFhQVpuQTRJNUFnL2RmNi9NTDhHN2FU?=
 =?utf-8?B?dDBhUGcxQS9JTVpZQ2cyR05WdGR2bGtGeTZOR0poVmtVSDg3KzRsZXU5end5?=
 =?utf-8?Q?PS8vfUp9/wumobatJ4oqkDV4f?=
X-OriginatorOrg: axentia.se
X-MS-Exchange-CrossTenant-Network-Message-Id: 35b97d70-9d53-435a-bdda-08da5b8e22b6
X-MS-Exchange-CrossTenant-AuthSource: AM0PR02MB4436.eurprd02.prod.outlook.com
X-MS-Exchange-CrossTenant-AuthAs: Internal
X-MS-Exchange-CrossTenant-OriginalArrivalTime: 01 Jul 2022 18:18:45.9418
 (UTC)
X-MS-Exchange-CrossTenant-FromEntityHeader: Hosted
X-MS-Exchange-CrossTenant-Id: 4ee68585-03e1-4785-942a-df9c1871a234
X-MS-Exchange-CrossTenant-MailboxType: HOSTED
X-MS-Exchange-CrossTenant-UserPrincipalName: 7nFh0/44uvyj3javqv3b8IjXK7y15J32AjB08PgER4p7+h3bXau7gVVrkFFI7qx3
X-MS-Exchange-Transport-CrossTenantHeadersStamped: AM7PR02MB6484
X-Original-Sender: peda@axentia.se
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axentia.se header.s=selector2 header.b=A+2TT0uR;       arc=pass
 (i=1 spf=pass spfdomain=axentia.se dkim=pass dkdomain=axentia.se dmarc=pass
 fromdomain=axentia.se);       spf=pass (google.com: domain of peda@axentia.se
 designates 40.107.21.126 as permitted sender) smtp.mailfrom=peda@axentia.se
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

2022-06-28 at 16:03, Uwe Kleine-K=C3=B6nig wrote:
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

For drivers I'm involved in, namely:

>  drivers/i2c/muxes/i2c-mux-ltc4306.c                       | 4 +---
>  drivers/i2c/muxes/i2c-mux-pca9541.c                       | 3 +--
>  drivers/i2c/muxes/i2c-mux-pca954x.c                       | 3 +--
>  sound/soc/codecs/max9860.c                                | 3 +--

Acked-by: Peter Rosin <peda@axentia.se>

Cheers,
Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/23b70c51-4bd7-84f9-e72c-ba6547eedf7d%40axentia.se.
