Return-Path: <kasan-dev+bncBAABBS7656KQMGQEC3S73IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AC1655F8EE
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 09:29:16 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id i5-20020a1c3b05000000b003a02b027e53sf10123451wma.7
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 00:29:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656487756; cv=pass;
        d=google.com; s=arc-20160816;
        b=eLWCtqnE3uClB80Oh+BpTKQcImbP4DpFgOLyIUZlxh3b1T69JDvyTx7zJmedMq5O7D
         2S7v9VuDhoU77Cj20UsRyjCA4AP/2ykDpbaU/p8jQcKewYAz2QEUEsZhHW+50lPAT45u
         6odX0Ssiihl/hUzW6yqfnBTB9X94NjKoRs7DEg3XS1PQFG8s4ALguyT5QgzzxXB5zHQI
         Nr5rIC6/mZEOso3Ht1KYOyVE6DUTGVJ8CugAJIuNxEF2jmyeYjgVVZQ67fQy1vL6veqa
         93+LUknwt88X1opRERIVJJPfdtha7AnzT0//Q50DwPqXExTyAHS6L4/ZwMzufUbNKzn6
         TX+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=74xwhZeFxOa20w14URR4PQ1dLE+ryYrZtqusYiz10Vs=;
        b=JxRECmsUDnMJishTYFAw7qvZRM611E6rqoxZMCrjaLqpZGY3bkgnrnpv9ecEZLz0Ku
         33csLG/ANyKWUtxjnyyC3ukD8SY+CRexsZ+UtttaqmGFFLq08Db09VWjD9txU3RRn4fY
         JZGq9Wce7ACNAqZ/CKFBwJb/3mxErHSnlCDg63ZMKRJMNxPUgn/tzPsYagpB/KPDLHh9
         yzHJB5zClvidqxrkqG8VgcSNL0VO9sY6f1ac+hcY4eRep15HbSa/BTZJSN+3KVmY50cI
         TeY23NPLgoTOXQJ8lmTX6lRTcynm3Q8KYrDiMrlOhWPX/fl7Phyn4A3Ke9ojipw9DvF/
         USpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@foss.st.com header.s=selector1 header.b=Hmn6FvPV;
       spf=pass (google.com: domain of prvs=3179ce0c97=benjamin.mugnier@foss.st.com designates 185.132.182.106 as permitted sender) smtp.mailfrom="prvs=3179ce0c97=benjamin.mugnier@foss.st.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foss.st.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=74xwhZeFxOa20w14URR4PQ1dLE+ryYrZtqusYiz10Vs=;
        b=HJAlsMCXLe+NlEZvYBKq8yPgo0wKQIbMuNZlmckb7LGOwmpYDy3H8yHKs2t752JI1o
         H6KZzXx0aJsrsRCKhb3gU4p43E+y/NLrZRTvxLQbj/a0DAn7BiV215VCq0CcycV/EhkZ
         gGbD8d3+64dTIOmCflPXCz7nJOQWvPszpXneeqgu7aUVlwhLAsaLrjPxGosDoQHiQZs+
         Wiml4rvOCryc6qo7FQ71/e2G8bUHIY85WUbIQzCiptidgtfFosXDi9RKxj/BEp3LjbFD
         O2WAV3xPONLv9vf6lCIw7MMsr2mUpVjDcUvujJQrjREwipu420hkxBKlYLvC9LgVl1eq
         CmCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=74xwhZeFxOa20w14URR4PQ1dLE+ryYrZtqusYiz10Vs=;
        b=6GraZfyz/1S61GSPzeJZIEguVs/C1oootHWNZpMP8ddY+REt453k6r7Ukyo7vV6fUe
         UDRstgJABz0H2wv351fQfTeeLSrAEI3cxgWFWlj1hgP2LLtunxYkgWZox4OVXuFE56iX
         jds6OROhTYMHPcX7zmBZCCmvuzAWiA2EYzagr89DpOTljHZMI3B49uKTlBYSJFC7N6J/
         ybkvg/X0r+jOAoayOHl5nB5VtuxstRcI3l0GPZxsYaeN8WUg7VAfqMUHST5AWvj9lXe0
         +3vQNMz2+UAbDk/elmJNg24ZEJ4I+J/Rdh4qxPxvDdLKk+IoMTSIOBxXwMZn8F3c6YmJ
         ycvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9zDQE1IaefCG26MkrnoMbSghBfFgKnbXy/76lyKXSwQkfiRDge
	JiQpADCKGVOpPOk3Qef5iL4=
X-Google-Smtp-Source: AGRyM1ueFu/W5qdmcjT4xNCL2NsOvagexWxGGi0y/EuBpwg+qcgJXtXrNIkiXUWJBr0Nqqwb/N7fRQ==
X-Received: by 2002:a5d:470c:0:b0:21b:812e:1b70 with SMTP id y12-20020a5d470c000000b0021b812e1b70mr1523902wrq.147.1656487755842;
        Wed, 29 Jun 2022 00:29:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:34c6:b0:3a0:4f27:977f with SMTP id
 d6-20020a05600c34c600b003a04f27977fls1142448wmq.2.gmail; Wed, 29 Jun 2022
 00:29:15 -0700 (PDT)
X-Received: by 2002:a05:600c:4ecc:b0:3a1:68bf:d17a with SMTP id g12-20020a05600c4ecc00b003a168bfd17amr1585278wmq.154.1656487754991;
        Wed, 29 Jun 2022 00:29:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656487754; cv=none;
        d=google.com; s=arc-20160816;
        b=isS7k9e7XnseztGdkdavDUn07z7pIDZNIRA17CC6XRYNpt3qcUPLc6SFciDh4CgvE3
         /vlKDJOG6e3CDqtdBgfveFk0OoJOwVaCucUl3dguwaigfx5FQklW0wqcBuvGu0FcO8fX
         efHmxPhraUMdh1S8vVFThAg0S40rJ49BmuJHrd8feMQaPHBFsNkwebCSECklPxsMOFPZ
         y6s4orI+X0qINz7rhWCAHgNUBl9lZebSdaYC+tsRKb3tzCOm91j/DZiHYGJLkGMnLZcm
         xNV6OulJ5GWf8sh4wSII2/GSB0/xpoJhOzUJYZSIR9UloiPKwT1A2fBrk59K3X+vuVE8
         29ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject
         :dkim-signature;
        bh=UD4IN9gRHJreA7opqpLKSzn8bQhDjxY56nGlMezzYAU=;
        b=Eca/55m2p22Gk4IdY1ip0y/BR+6qNBfrvveK1E3QPRi8g7jFa+NtuMFcx2cchPiK1V
         pf7fXd4d+6V0NUPeDitvQXYgTpmcn2/73fbKptV2e4dOv16iqTC79tc9g6FzVJlou+tE
         fcuX4BqaiNLY5DsUzDcV4b+QRFgfDVyc7/T55GNkkDBTPHMhV1Xu35f5HkwyNKPcJm6W
         loBL/xfRWgdB0M41jSjNoviQotjI68Cfv6EzCaiWkke6fEhzJNEodRID0Y9Zc86Pn6nD
         ASMgxqlDB3SMQe7Tpe1WvkJ2rIRufV+BaN750+qrroHiDZIhfhwNQo5uau+SvGqdNJtR
         30XA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@foss.st.com header.s=selector1 header.b=Hmn6FvPV;
       spf=pass (google.com: domain of prvs=3179ce0c97=benjamin.mugnier@foss.st.com designates 185.132.182.106 as permitted sender) smtp.mailfrom="prvs=3179ce0c97=benjamin.mugnier@foss.st.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foss.st.com
Received: from mx07-00178001.pphosted.com (mx07-00178001.pphosted.com. [185.132.182.106])
        by gmr-mx.google.com with ESMTPS id a8-20020a05600c348800b003a03ade6826si74778wmq.0.2022.06.29.00.29.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jun 2022 00:29:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of prvs=3179ce0c97=benjamin.mugnier@foss.st.com designates 185.132.182.106 as permitted sender) client-ip=185.132.182.106;
Received: from pps.filterd (m0288072.ppops.net [127.0.0.1])
	by mx07-00178001.pphosted.com (8.17.1.5/8.17.1.5) with ESMTP id 25T7JJUH004271;
	Wed, 29 Jun 2022 09:28:00 +0200
Received: from beta.dmz-eu.st.com (beta.dmz-eu.st.com [164.129.1.35])
	by mx07-00178001.pphosted.com (PPS) with ESMTPS id 3gydcub6vk-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Wed, 29 Jun 2022 09:28:00 +0200
Received: from euls16034.sgp.st.com (euls16034.sgp.st.com [10.75.44.20])
	by beta.dmz-eu.st.com (STMicroelectronics) with ESMTP id D5F1C100038;
	Wed, 29 Jun 2022 09:27:58 +0200 (CEST)
Received: from Webmail-eu.st.com (eqndag1node4.st.com [10.75.129.133])
	by euls16034.sgp.st.com (STMicroelectronics) with ESMTP id A24252128A8;
	Wed, 29 Jun 2022 09:27:58 +0200 (CEST)
Received: from [10.0.2.15] (10.75.127.45) by EQNDAG1NODE4.st.com
 (10.75.129.133) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256) id 15.1.2308.20; Wed, 29 Jun
 2022 09:27:52 +0200
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
To: =?UTF-8?Q?Uwe_Kleine-K=c3=b6nig?= <u.kleine-koenig@pengutronix.de>,
        Wolfram Sang <wsa@kernel.org>
CC: =?UTF-8?Q?Uwe_Kleine-K=c3=b6nig?= <uwe@kleine-koenig.org>,
        Sekhar Nori
	<nsekhar@ti.com>, Bartosz Golaszewski <brgl@bgdev.pl>,
        Russell King
	<linux@armlinux.org.uk>, Scott Wood <oss@buserror.net>,
        Michael Ellerman
	<mpe@ellerman.id.au>,
        Benjamin Herrenschmidt <benh@kernel.crashing.org>,
        Paul
 Mackerras <paulus@samba.org>,
        Robin van der Gracht <robin@protonic.nl>,
        Miguel Ojeda <ojeda@kernel.org>, Corey Minyard <minyard@acm.org>,
        Peter Huewe
	<peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>,
        Jason Gunthorpe
	<jgg@ziepe.ca>,
        Nicolas Ferre <nicolas.ferre@microchip.com>,
        Alexandre
 Belloni <alexandre.belloni@bootlin.com>,
        Claudiu Beznea
	<claudiu.beznea@microchip.com>,
        Max Filippov <jcmvbkbc@gmail.com>,
        Michael
 Turquette <mturquette@baylibre.com>,
        Stephen Boyd <sboyd@kernel.org>,
        Luca
 Ceresoli <luca@lucaceresoli.net>,
        Tudor Ambarus
	<tudor.ambarus@microchip.com>,
        Herbert Xu <herbert@gondor.apana.org.au>,
        "David S. Miller" <davem@davemloft.net>,
        MyungJoo Ham
	<myungjoo.ham@samsung.com>,
        Chanwoo Choi <cw00.choi@samsung.com>,
        Michael
 Hennerich <michael.hennerich@analog.com>,
        Linus Walleij
	<linus.walleij@linaro.org>,
        Andrzej Hajda <andrzej.hajda@intel.com>,
        Neil
 Armstrong <narmstrong@baylibre.com>,
        Robert Foss <robert.foss@linaro.org>,
        Laurent Pinchart <Laurent.pinchart@ideasonboard.com>,
        Jonas Karlman
	<jonas@kwiboo.se>,
        Jernej Skrabec <jernej.skrabec@gmail.com>,
        David Airlie
	<airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>,
        Benson Leung
	<bleung@chromium.org>,
        Guenter Roeck <groeck@chromium.org>, Phong LE
	<ple@baylibre.com>,
        Adrien Grassein <adrien.grassein@gmail.com>,
        Peter Senna
 Tschudin <peter.senna@gmail.com>,
        Martin Donnelly <martin.donnelly@ge.com>,
        Martyn Welch <martyn.welch@collabora.co.uk>,
        Douglas Anderson
	<dianders@chromium.org>,
        Stefan Mavrodiev <stefan@olimex.com>,
        Thierry Reding
	<thierry.reding@gmail.com>,
        Sam Ravnborg <sam@ravnborg.org>,
        Florian Fainelli
	<f.fainelli@gmail.com>,
        Broadcom internal kernel review list
	<bcm-kernel-feedback-list@broadcom.com>,
        Javier Martinez Canillas
	<javierm@redhat.com>,
        Jiri Kosina <jikos@kernel.org>,
        Benjamin Tissoires
	<benjamin.tissoires@redhat.com>,
        Jean Delvare <jdelvare@suse.com>,
        George
 Joseph <george.joseph@fairview5.com>,
        Juerg Haefliger <juergh@gmail.com>, Riku Voipio <riku.voipio@iki.fi>,
        Robert Marko <robert.marko@sartura.hr>,
        Luka Perkov <luka.perkov@sartura.hr>,
        Marc Hulsman <m.hulsman@tudelft.nl>,
        Rudolf Marek <r.marek@assembler.cz>, Peter Rosin <peda@axentia.se>,
        Jonathan
 Cameron <jic23@kernel.org>,
        Lars-Peter Clausen <lars@metafoo.de>,
        Dan
 Robertson <dan@dlrobertson.com>,
        Rui Miguel Silva <rmfrfs@gmail.com>,
        Tomasz
 Duszynski <tduszyns@gmail.com>,
        Kevin Tsai <ktsai@capellamicro.com>, Crt Mori
	<cmo@melexis.com>,
        Dmitry Torokhov <dmitry.torokhov@gmail.com>,
        Nick Dyer
	<nick@shmanahar.org>, Bastien Nocera <hadess@hadess.net>,
        Hans de Goede
	<hdegoede@redhat.com>,
        Maxime Coquelin <mcoquelin.stm32@gmail.com>,
        Alexandre
 Torgue <alexandre.torgue@foss.st.com>,
        Sakari Ailus
	<sakari.ailus@linux.intel.com>,
        Pavel Machek <pavel@ucw.cz>,
        Jan-Simon
 Moeller <jansimon.moeller@gmx.de>,
        =?UTF-8?Q?Marek_Beh=c3=ban?=
	<kabel@kernel.org>,
        Colin Leroy <colin@colino.net>, Joe Tessler
	<jrt@google.com>,
        Hans Verkuil <hverkuil-cisco@xs4all.nl>,
        Mauro Carvalho
 Chehab <mchehab@kernel.org>,
        Antti Palosaari <crope@iki.fi>, Jasmin Jessich
	<jasmin@anw.at>,
        Matthias Schwarzott <zzam@gentoo.org>,
        Olli Salonen
	<olli.salonen@iki.fi>,
        Akihiro Tsukada <tskd08@gmail.com>,
        Kieran Bingham
	<kieran.bingham@ideasonboard.com>,
        Tianshu Qiu <tian.shu.qiu@intel.com>,
        Dongchun Zhu <dongchun.zhu@mediatek.com>,
        Shawn Tu <shawnx.tu@intel.com>, Martin Kepplinger <martink@posteo.de>,
        Ricardo Ribalda <ribalda@kernel.org>,
        Dave Stevenson <dave.stevenson@raspberrypi.com>,
        Leon Luo
	<leonl@leopardimaging.com>,
        Manivannan Sadhasivam <mani@kernel.org>,
        Bingbu
 Cao <bingbu.cao@intel.com>,
        "Paul J. Murphy" <paul.j.murphy@intel.com>,
        Daniele Alessandrelli <daniele.alessandrelli@intel.com>,
        Michael Tretter
	<m.tretter@pengutronix.de>,
        Pengutronix Kernel Team <kernel@pengutronix.de>,
        Kyungmin Park <kyungmin.park@samsung.com>,
        Heungjun Kim
	<riverful.kim@samsung.com>,
        Ramesh Shanmugasundaram <rashanmu@gmail.com>,
        Jacopo Mondi <jacopo+renesas@jmondi.org>,
        =?UTF-8?Q?Niklas_S=c3=b6derlund?=
	<niklas.soderlund+renesas@ragnatech.se>,
        Jimmy Su <jimmy.su@intel.com>, Arec
 Kao <arec.kao@intel.com>,
        "Lad, Prabhakar" <prabhakar.csengg@gmail.com>,
        Shunqian Zheng <zhengsq@rock-chips.com>,
        Steve Longerbeam
	<slongerbeam@gmail.com>,
        Chiranjeevi Rapolu <chiranjeevi.rapolu@intel.com>,
        Daniel Scally <djrscally@gmail.com>,
        Wenyou Yang <wenyou.yang@microchip.com>,
        Petr Cvek <petrcvekcz@gmail.com>,
        Akinobu Mita <akinobu.mita@gmail.com>,
        Sylwester Nawrocki <s.nawrocki@samsung.com>,
        Sylvain Petinot
	<sylvain.petinot@foss.st.com>,
        Mats Randgaard <matrandg@cisco.com>,
        Tim
 Harvey <tharvey@gateworks.com>,
        Matt Ranostay <matt.ranostay@konsulko.com>,
        Eduardo Valentin <edubezval@gmail.com>,
        "Daniel W. S. Almeida"
	<dwlsalmeida@gmail.com>,
        Lee Jones <lee.jones@linaro.org>, Chen-Yu Tsai
	<wens@csie.org>,
        Support Opensource <support.opensource@diasemi.com>,
        Robert
 Jones <rjones@gateworks.com>,
        Andy Shevchenko <andy@kernel.org>,
        Charles
 Keepax <ckeepax@opensource.cirrus.com>,
        Richard Fitzgerald
	<rf@opensource.cirrus.com>,
        Krzysztof Kozlowski
	<krzysztof.kozlowski@linaro.org>,
        Bartlomiej Zolnierkiewicz
	<b.zolnierkie@samsung.com>,
        Tony Lindgren <tony@atomide.com>,
        =?UTF-8?Q?Jonathan_Neusch=c3=a4fer?= <j.neuschaefer@gmx.net>,
        Arnd Bergmann
	<arnd@arndb.de>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Eric Piel
	<eric.piel@tremplin-utc.net>,
        Miquel Raynal <miquel.raynal@bootlin.com>,
        Richard Weinberger <richard@nod.at>,
        Vignesh Raghavendra <vigneshr@ti.com>, Andrew Lunn <andrew@lunn.ch>,
        Vivien Didelot <vivien.didelot@gmail.com>,
        Vladimir Oltean <olteanv@gmail.com>,
        Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>,
        Paolo Abeni <pabeni@redhat.com>,
        Woojung
 Huh <woojung.huh@microchip.com>,
        <UNGLinuxDriver@microchip.com>,
        George
 McCollister <george.mccollister@gmail.com>,
        Ido Schimmel <idosch@nvidia.com>, Petr Machata <petrm@nvidia.com>,
        Jeremy Kerr <jk@codeconstruct.com.au>,
        Matt
 Johnston <matt@codeconstruct.com.au>,
        Charles Gorand
	<charles.gorand@effinnov.com>,
        Krzysztof Opasiak <k.opasiak@samsung.com>,
        Rob
 Herring <robh+dt@kernel.org>,
        Frank Rowand <frowand.list@gmail.com>,
        Mark
 Gross <markgross@kernel.org>,
        Maximilian Luz <luzmaximilian@gmail.com>,
        Corentin Chary <corentin.chary@gmail.com>,
        =?UTF-8?Q?Pali_Roh=c3=a1r?=
	<pali@kernel.org>,
        Sebastian Reichel <sre@kernel.org>,
        Tobias Schrammm
	<t.schramm@manjaro.org>,
        Liam Girdwood <lgirdwood@gmail.com>, Mark Brown
	<broonie@kernel.org>,
        Alessandro Zummo <a.zummo@towertech.it>,
        Jens Frederich
	<jfrederich@gmail.com>,
        Jon Nettleton <jon.nettleton@gmail.com>,
        Jiri Slaby
	<jirislaby@kernel.org>, Felipe Balbi <balbi@kernel.org>,
        Heikki Krogerus
	<heikki.krogerus@linux.intel.com>,
        Daniel Thompson
	<daniel.thompson@linaro.org>,
        Jingoo Han <jingoohan1@gmail.com>, Helge Deller
	<deller@gmx.de>,
        Evgeniy Polyakov <zbr@ioremap.net>,
        Wim Van Sebroeck
	<wim@linux-watchdog.org>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander
 Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino
	<vincenzo.frascino@arm.com>,
        Johannes Berg <johannes@sipsolutions.net>,
        Jaroslav Kysela <perex@perex.cz>, Takashi Iwai <tiwai@suse.com>,
        James
 Schulman <james.schulman@cirrus.com>,
        David Rhodes <david.rhodes@cirrus.com>,
        Lucas Tanure <tanureal@opensource.cirrus.com>,
        =?UTF-8?Q?Nuno_S=c3=a1?=
	<nuno.sa@analog.com>,
        Matthias Brugger <matthias.bgg@gmail.com>,
        Oder Chiou
	<oder_chiou@realtek.com>,
        Fabio Estevam <festevam@gmail.com>,
        Kevin Cernekee
	<cernekee@chromium.org>,
        Christophe Leroy <christophe.leroy@csgroup.eu>,
        Maxime Ripard <maxime@cerno.tech>,
        =?UTF-8?Q?Alvin_=c5=a0ipraga?=
	<alsi@bang-olufsen.dk>,
        Lucas Stach <l.stach@pengutronix.de>,
        Jagan Teki
	<jagan@amarulasolutions.com>,
        Biju Das <biju.das.jz@bp.renesas.com>,
        Thomas
 Zimmermann <tzimmermann@suse.de>,
        Alex Deucher <alexander.deucher@amd.com>,
        Lyude Paul <lyude@redhat.com>, Xin Ji <xji@analogixsemi.com>,
        Hsin-Yi Wang
	<hsinyi@chromium.org>,
        =?UTF-8?B?Sm9zw6kgRXhww7NzaXRv?=
	<jose.exposito89@gmail.com>,
        Yang Li <yang.lee@linux.alibaba.com>,
        Angela
 Czubak <acz@semihalf.com>,
        Alistair Francis <alistair@alistair23.me>,
        Eddie
 James <eajames@linux.ibm.com>, Joel Stanley <joel@jms.id.au>,
        Nathan
 Chancellor <nathan@kernel.org>,
        Antoniu Miclaus <antoniu.miclaus@analog.com>,
        Alexandru Ardelean <ardeleanalex@gmail.com>,
        Dmitry Rokosov
	<DDRokosov@sberdevices.ru>,
        Srinivas Pandruvada
	<srinivas.pandruvada@linux.intel.com>,
        Stephan Gerhold <stephan@gerhold.net>,
        Miaoqian Lin <linmq006@gmail.com>,
        Gwendal Grignou <gwendal@chromium.org>,
        Yang Yingliang <yangyingliang@huawei.com>,
        Paul Cercueil
	<paul@crapouillou.net>, Daniel Palmer <daniel@0x0f.com>,
        Haibo Chen
	<haibo.chen@nxp.com>, Cai Huoqing <cai.huoqing@linux.dev>,
        Marek Vasut
	<marex@denx.de>, Jose Cazarin <joseespiriki@gmail.com>,
        Dan Carpenter
	<dan.carpenter@oracle.com>,
        Jean-Baptiste Maneyrol
	<jean-baptiste.maneyrol@tdk.com>,
        Michael Srba <Michael.Srba@seznam.cz>, Nikita Travkin <nikita@trvn.ru>,
        Maslov Dmitry <maslovdmitry@seeed.cc>, Jiri
 Valek - 2N <valek@2n.cz>,
        Arnaud Ferraris <arnaud.ferraris@collabora.com>,
        Zheyu Ma <zheyuma97@gmail.com>, Marco Felsch <m.felsch@pengutronix.de>,
        Oliver Graute <oliver.graute@kococonnector.com>,
        Zheng Yongjun
	<zhengyongjun3@huawei.com>,
        CGEL ZTE <cgel.zte@gmail.com>, Minghao Chi
	<chi.minghao@zte.com.cn>,
        Evgeny Novikov <novikov@ispras.ru>, Sean Young
	<sean@mess.org>,
        Kirill Shilimanov <kirill.shilimanov@huawei.com>,
        Moses
 Christopher Bollavarapu <mosescb.dev@gmail.com>,
        Paul Kocialkowski
	<paul.kocialkowski@bootlin.com>,
        Janusz Krzysztofik <jmkrzyszt@gmail.com>,
        Dongliang Mu <mudongliangabcd@gmail.com>,
        Colin Ian King
	<colin.king@intel.com>, lijian <lijian@yulong.com>,
        Kees Cook
	<keescook@chromium.org>, Yan Lei <yan_lei@dahuatech.com>,
        Heiner Kallweit
	<hkallweit1@gmail.com>,
        Jonas Malaco <jonas@protocubo.io>,
        wengjianfeng
	<wengjianfeng@yulong.com>,
        Rikard Falkeborn <rikard.falkeborn@gmail.com>,
        Wei
 Yongjun <weiyongjun1@huawei.com>, Tom Rix <trix@redhat.com>,
        Yizhuo
	<yzhai003@ucr.edu>, Martiros Shakhzadyan <vrzh@vrzh.net>,
        Bjorn Andersson
	<bjorn.andersson@linaro.org>,
        Sven Peter <sven@svenpeter.dev>,
        Alyssa
 Rosenzweig <alyssa@rosenzweig.io>,
        Hector Martin <marcan@marcan.st>,
        Saranya
 Gopal <saranya.gopal@intel.com>,
        =?UTF-8?Q?Guido_G=c3=bcnther?=
	<agx@sigxcpu.org>,
        Sing-Han Chen <singhanc@nvidia.com>, Wayne Chang
	<waynec@nvidia.com>,
        Geert Uytterhoeven <geert@linux-m68k.org>,
        Alexey
 Dobriyan <adobriyan@gmail.com>,
        Masahiro Yamada <masahiroy@kernel.org>,
        Vincent Knecht <vincent.knecht@mailoo.org>,
        Stephen Kitt <steve@sk2.org>,
        Pierre-Louis Bossart <pierre-louis.bossart@linux.intel.com>,
        Alexey
 Khoroshilov <khoroshilov@ispras.ru>,
        Randy Dunlap <rdunlap@infradead.org>,
        Alejandro Tafalla <atafalla@dnyon.com>,
        Vijendar Mukunda
	<Vijendar.Mukunda@amd.com>,
        Seven Lee <wtli@nuvoton.com>, Mac Chiang
	<mac.chiang@intel.com>,
        David Lin <CTLIN0@nuvoton.com>,
        Daniel Beer
	<daniel.beer@igorinstitute.com>,
        Ricard Wanderlof <ricardw@axis.com>,
        Simon
 Trimmer <simont@opensource.cirrus.com>,
        Shengjiu Wang
	<shengjiu.wang@nxp.com>,
        Viorel Suman <viorel.suman@nxp.com>,
        Nicola Lunghi
	<nick83ola@gmail.com>, Adam Ford <aford173@gmail.com>,
        <linux-i2c@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
        <linuxppc-dev@lists.ozlabs.org>,
        <openipmi-developer@lists.sourceforge.net>,
        <linux-integrity@vger.kernel.org>, <linux-clk@vger.kernel.org>,
        <linux-crypto@vger.kernel.org>, <linux-gpio@vger.kernel.org>,
        <dri-devel@lists.freedesktop.org>, <chrome-platform@lists.linux.dev>,
        <linux-rpi-kernel@lists.infradead.org>, <linux-input@vger.kernel.org>,
        <linux-hwmon@vger.kernel.org>, <linux-iio@vger.kernel.org>,
        <linux-stm32@st-md-mailman.stormreply.com>,
        <linux-leds@vger.kernel.org>, <linux-media@vger.kernel.org>,
        <patches@opensource.cirrus.com>, <alsa-devel@alsa-project.org>,
        <linux-omap@vger.kernel.org>, <linux-mtd@lists.infradead.org>,
        <netdev@vger.kernel.org>, <devicetree@vger.kernel.org>,
        <platform-driver-x86@vger.kernel.org>,
        <acpi4asus-user@lists.sourceforge.net>, <linux-pm@vger.kernel.org>,
        <linux-pwm@vger.kernel.org>, <linux-rtc@vger.kernel.org>,
        <linux-staging@lists.linux.dev>, <linux-serial@vger.kernel.org>,
        <linux-usb@vger.kernel.org>, <linux-fbdev@vger.kernel.org>,
        <linux-watchdog@vger.kernel.org>, <kasan-dev@googlegroups.com>,
        <linux-mediatek@lists.infradead.org>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
From: Benjamin Mugnier <benjamin.mugnier@foss.st.com>
Message-ID: <b3cab1de-a1eb-e669-0900-cf1833415f2c@foss.st.com>
Date: Wed, 29 Jun 2022 09:27:47 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.13.0
MIME-Version: 1.0
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Originating-IP: [10.75.127.45]
X-ClientProxiedBy: SFHDAG2NODE3.st.com (10.75.127.6) To EQNDAG1NODE4.st.com
 (10.75.129.133)
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.205,Aquarius:18.0.883,Hydra:6.0.517,FMLib:17.11.122.1
 definitions=2022-06-28_11,2022-06-28_01,2022-06-22_01
X-Original-Sender: benjamin.mugnier@foss.st.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@foss.st.com header.s=selector1 header.b=Hmn6FvPV;       spf=pass
 (google.com: domain of prvs=3179ce0c97=benjamin.mugnier@foss.st.com
 designates 185.132.182.106 as permitted sender) smtp.mailfrom="prvs=3179ce0c97=benjamin.mugnier@foss.st.com";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=foss.st.com
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

Hi Uwe,

> diff --git a/drivers/media/i2c/st-mipid02.c b/drivers/media/i2c/st-mipid02.c
> index ef976d085d72..0389223a61f7 100644
> --- a/drivers/media/i2c/st-mipid02.c
> +++ b/drivers/media/i2c/st-mipid02.c
> @@ -1041,7 +1041,7 @@ static int mipid02_probe(struct i2c_client *client)
>  	return ret;
>  }
>  
> -static int mipid02_remove(struct i2c_client *client)
> +static void mipid02_remove(struct i2c_client *client)
>  {
>  	struct v4l2_subdev *sd = i2c_get_clientdata(client);
>  	struct mipid02_dev *bridge = to_mipid02_dev(sd);
> @@ -1052,8 +1052,6 @@ static int mipid02_remove(struct i2c_client *client)
>  	mipid02_set_power_off(bridge);
>  	media_entity_cleanup(&bridge->sd.entity);
>  	mutex_destroy(&bridge->lock);
> -
> -	return 0;
>  }
>  
>  static const struct of_device_id mipid02_dt_ids[] = {

Thank you. All good for me.

Reviewed-by: Benjamin Mugnier <benjamin.mugnier@foss.st.com>

Cheers,


Benjamin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b3cab1de-a1eb-e669-0900-cf1833415f2c%40foss.st.com.
