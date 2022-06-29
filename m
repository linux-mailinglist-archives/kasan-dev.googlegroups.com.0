Return-Path: <kasan-dev+bncBD3NLIPGWIOBBQ7P56KQMGQEZIACU4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id DC4E055F737
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 08:57:08 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 10-20020a0562140cca00b004702e8ce21bsf14618037qvx.22
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 23:57:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656485827; cv=pass;
        d=google.com; s=arc-20160816;
        b=a+VZtVbYd0wap76s8nszhCQISZukrfyB1UUop4w6Hq0OtPNCafkOW1StQH/bQ+FTSJ
         ROkDi/yO0jShK6WIqpxsuqfhFyfwdcoW7VTHtMkUCYgTbqu6l4MwE92tBdC4L6DDCYYm
         blu946M2sCzEcM+t9MgJLquJZE7GHYa9Ok9qXrMuxTkey9MvSMRK+dB5YQHs1NFlWIDn
         IXbLSJY1J0OC2Ww1VA0/q8nAGQ+13UjBFJYvGgL8mYt1wJrMSPFRBXJr0dnYgJ/tXJgs
         CEMY3n8dJweG0ms5jGpa/C59cejlTzbeClYQubMp1TvFXa4oNG2ybptKjTFn8vGgZ9H4
         kWaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=85R9JxV3n/KuH16F5HZXOfS7wMwJ57Pyp+9kUiC6y2A=;
        b=d2gAVsuGsVCFbnAYdWbMaW9RAzZnZD/PStF/Pd5C6Hx+keMEhzEFAYaOqyFN+AvSVq
         9R8f3t5i23ZZZRTPJl6vGNhOuQwa0AYEQbzYCI9HEhtpB+8YN9xD0Xe48rxvwbJlN8W4
         tpHYm2tGKlC5JkAXmZ/1jk1oShOTNyjkTtF7+lOcp4Le/w7q15ICNwpAx4E/193oeZjr
         JIbxixkZYtyPPHEvB+K+NYx3Uv6HsMmQq36KcCG92CMxwAmtXGsA8JRYmwBBW3HfI12b
         i54+78VJKl/2kX0hj0lcSvRlpSEOHbBP/jcEZKHrTeLB6zxBrj7Pv+fjfGYEX7emnwrn
         TxPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=nsSF081B;
       spf=pass (google.com: domain of peter.senna@gmail.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=peter.senna@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=85R9JxV3n/KuH16F5HZXOfS7wMwJ57Pyp+9kUiC6y2A=;
        b=bPVOGnNJFzAzhSAOQ0y4Qjjq0PdTxj12q2N/6s1g/ONehMuaSXzL2irzHGCj6xfSZ5
         4UNF1IGid2Z1Q6rIocbDvyMPoFult7ZoldKuQUHI7dXHCIO38SjFy3DPY8eqoB5VND4G
         RhaAULt6NMFVswMCKBCRlOic+fUUT7AOarz2+yu3fYn3TaoUrfTci09rkf66a+b+Pycj
         XBgQEpv4ENI1uzEw0e4to0l7X3T2IhAPz0sQN8rLaNfW403ywlomTHW5Nk6fzLKBZFnl
         sg59pj5JPDZpxd6rP0Hjo6hlJ9QjT96YaC5WgNEClSB+flZ7pF0r/mHAZavdfDmLtwH9
         WT3Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=85R9JxV3n/KuH16F5HZXOfS7wMwJ57Pyp+9kUiC6y2A=;
        b=Hi3NGKM8dMSIKVZUp0wXDVWNg9q+NJFBXrwZmGN8/YYaK8HKpyJB8EvhuAZSiO9WY4
         p4o7nO6Gid3aIh6mmDO08IClDw+mPH3R6QPkj6CqQl/mt9nGRUq3jTOM2zPStgOpm18Q
         81yJnAkd7eTdZgCKmn8l7jfF/1H38Pi1TbbEYi2yU5GmZ/QJTw0O37EHQZcuHbffA12Q
         aB6xOh19u8c8K3QHGsiy8HOIOEbPTCcff54uBsz5kCdd2Y+XpvuHKO07iysTxGRy8rm3
         BHHU8eQnbOT2T2gNlpSgugXqXpz5WJFeaHOwgdFEbyHQe+0/LJcUOhvgx4GA466Yjw4L
         qR7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=85R9JxV3n/KuH16F5HZXOfS7wMwJ57Pyp+9kUiC6y2A=;
        b=6059P1OUf3lpBwBGRSTA7KYxawca83bq2xyzOsS3U4TMXTXm3fRuCKj9fX1lr4OLSB
         NPBHkbsuR6du6hu3P0DR2a7VUr5ESL2afAD0TR+UlOY6p+hY4oeTAhEbaZAnLA98hDun
         icmTLK4EGErj1s8bBOuylFty5BpokT5/RQP1rYKKmNthxR/pqHObJ5YovjQAWS4WY+Qx
         ICn/xsbYTBuhTHzbICCzXe86EGoj16PsVNgWLXlqPVgYL61CsSvF3IZhxXRQCy92MjPr
         aYYcCzEwC5/g1zScvd0o+CVUckNLflrzCevA68a30OcDECwT18K00al3iLo2/1o6K2eR
         MUnw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora984rzPoA3z1HOOReP8gOntj0yRIbl9EsYGMqCYqzgwSpKanEuc
	vXFv8Cf8vYHCqkbPDwglayE=
X-Google-Smtp-Source: AGRyM1sj+S44P/lQ4qOymK5HurUZ+q4Zg20+ouXiwrm65jf3ey7Ukvm0JnFQkR86ZncCaXJ3+5r4Rw==
X-Received: by 2002:a05:6214:f0f:b0:472:99fc:e34a with SMTP id gw15-20020a0562140f0f00b0047299fce34amr1725097qvb.108.1656485827658;
        Tue, 28 Jun 2022 23:57:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7c6:0:b0:316:1f24:eac8 with SMTP id m6-20020ac807c6000000b003161f24eac8ls11654762qth.6.gmail;
 Tue, 28 Jun 2022 23:57:07 -0700 (PDT)
X-Received: by 2002:a05:622a:5d3:b0:305:27d8:cb15 with SMTP id d19-20020a05622a05d300b0030527d8cb15mr1229010qtb.298.1656485827207;
        Tue, 28 Jun 2022 23:57:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656485827; cv=none;
        d=google.com; s=arc-20160816;
        b=QJE9qzkX74PTA0Xa5lc5vrOWmL0JrAUYoeYrgRh6QeCnrDztqXstbaoSIrBH9NOWjG
         dcJM2E5J2AYapnwOng05jvSqy1sK+uzWjSjSyF0e2jVHXo+zxB8dhfOfX0aVCTJIMfe8
         nN/Llo1uEOeE7mCOFcWcxe9JyVfljhsPtbRMmx8iNXDQ+U3780MeggPzJ9XFE6y4OLu5
         yaeQcXdYvjgeB3OG93bFhteBIXBAI4lvvIc5mf5E+LF5kh9TV4CpvcqdZmVZogVZkx+9
         7251zpAeMAHBeAjnqKCXrBpUsrdjInCixNHRXxGoSAtmMne7lP/ThjXdZ5+SFAgfPkfM
         PDdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EEF0s3kbEcxLFpcibr8V8xDuFD7v13Z6e3FjeyphC7I=;
        b=ea+aCib9Ah+z8V73yLa8dBHjN+CBZNx/pPsGbVC3NZNG17YsMiPQ+Lrb2KVfG5cED8
         gJYMf3b7fRqRO9UBiQbCDr+V+2qW7zWf5mIULGrL79NSvlnG8MWEtiSVJzId5pbBXTUa
         JoaY5hVEirGdP7tw6l5qwtB7nejUsSg9V/HLdWNCUXVzUCT9qpzANzG6jk8i5DaTE82x
         ecdQH8f5OsHrZQ5lYWhJz450S4kAUj7e554MloXfGXZ/0Q3p5/FFCRw9Dvw59FCwQG/k
         qD7VNPjDd0XWUZ/cqAPmiHz6ZpqeZ4nGl5UtSXd+AD1KXZIgr2sVhlp+nQdyiz6VsW7c
         CQpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=nsSF081B;
       spf=pass (google.com: domain of peter.senna@gmail.com designates 2607:f8b0:4864:20::1132 as permitted sender) smtp.mailfrom=peter.senna@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-yw1-x1132.google.com (mail-yw1-x1132.google.com. [2607:f8b0:4864:20::1132])
        by gmr-mx.google.com with ESMTPS id a14-20020ac844ae000000b00307ca319443si72748qto.0.2022.06.28.23.57.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 23:57:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of peter.senna@gmail.com designates 2607:f8b0:4864:20::1132 as permitted sender) client-ip=2607:f8b0:4864:20::1132;
Received: by mail-yw1-x1132.google.com with SMTP id 00721157ae682-31c1d580e4bso6853137b3.3
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 23:57:07 -0700 (PDT)
X-Received: by 2002:a81:d91:0:b0:317:9176:56fe with SMTP id
 139-20020a810d91000000b00317917656femr2208847ywn.381.1656485826739; Tue, 28
 Jun 2022 23:57:06 -0700 (PDT)
MIME-Version: 1.0
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de> <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
From: Peter Senna Tschudin <peter.senna@gmail.com>
Date: Wed, 29 Jun 2022 08:56:55 +0200
Message-ID: <CA+MoWDrJKP1YHcBwb8AKBr59eymHEZH9QEKEwOWL2pVK1LFDEQ@mail.gmail.com>
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
To: =?UTF-8?Q?Uwe_Kleine=2DK=C3=B6nig?= <u.kleine-koenig@pengutronix.de>
Cc: Wolfram Sang <wsa@kernel.org>, =?UTF-8?Q?Uwe_Kleine=2DK=C3=B6nig?= <uwe@kleine-koenig.org>, 
	Sekhar Nori <nsekhar@ti.com>, Bartosz Golaszewski <brgl@bgdev.pl>, Russell King <linux@armlinux.org.uk>, 
	Scott Wood <oss@buserror.net>, Michael Ellerman <mpe@ellerman.id.au>, 
	Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, 
	Robin van der Gracht <robin@protonic.nl>, Miguel Ojeda <ojeda@kernel.org>, Corey Minyard <minyard@acm.org>, 
	Peter Huewe <peterhuewe@gmx.de>, Jarkko Sakkinen <jarkko@kernel.org>, Jason Gunthorpe <jgg@ziepe.ca>, 
	Nicolas Ferre <nicolas.ferre@microchip.com>, 
	Alexandre Belloni <alexandre.belloni@bootlin.com>, 
	Claudiu Beznea <claudiu.beznea@microchip.com>, Max Filippov <jcmvbkbc@gmail.com>, 
	Michael Turquette <mturquette@baylibre.com>, Stephen Boyd <sboyd@kernel.org>, 
	Luca Ceresoli <luca@lucaceresoli.net>, Tudor Ambarus <tudor.ambarus@microchip.com>, 
	Herbert Xu <herbert@gondor.apana.org.au>, "David S. Miller" <davem@davemloft.net>, 
	MyungJoo Ham <myungjoo.ham@samsung.com>, Chanwoo Choi <cw00.choi@samsung.com>, 
	Michael Hennerich <michael.hennerich@analog.com>, Linus Walleij <linus.walleij@linaro.org>, 
	Andrzej Hajda <andrzej.hajda@intel.com>, Neil Armstrong <narmstrong@baylibre.com>, 
	Robert Foss <robert.foss@linaro.org>, 
	Laurent Pinchart <Laurent.pinchart@ideasonboard.com>, Jonas Karlman <jonas@kwiboo.se>, 
	Jernej Skrabec <jernej.skrabec@gmail.com>, David Airlie <airlied@linux.ie>, 
	Daniel Vetter <daniel@ffwll.ch>, Benson Leung <bleung@chromium.org>, 
	Guenter Roeck <groeck@chromium.org>, Phong LE <ple@baylibre.com>, 
	Adrien Grassein <adrien.grassein@gmail.com>, Martin Donnelly <martin.donnelly@ge.com>, 
	Martyn Welch <martyn.welch@collabora.co.uk>, Douglas Anderson <dianders@chromium.org>, 
	Stefan Mavrodiev <stefan@olimex.com>, Thierry Reding <thierry.reding@gmail.com>, 
	Sam Ravnborg <sam@ravnborg.org>, Florian Fainelli <f.fainelli@gmail.com>, 
	Broadcom internal kernel review list <bcm-kernel-feedback-list@broadcom.com>, 
	Javier Martinez Canillas <javierm@redhat.com>, Jiri Kosina <jikos@kernel.org>, 
	Benjamin Tissoires <benjamin.tissoires@redhat.com>, Jean Delvare <jdelvare@suse.com>, 
	George Joseph <george.joseph@fairview5.com>, Juerg Haefliger <juergh@gmail.com>, 
	Riku Voipio <riku.voipio@iki.fi>, Robert Marko <robert.marko@sartura.hr>, 
	Luka Perkov <luka.perkov@sartura.hr>, Marc Hulsman <m.hulsman@tudelft.nl>, 
	Rudolf Marek <r.marek@assembler.cz>, Peter Rosin <peda@axentia.se>, 
	Jonathan Cameron <jic23@kernel.org>, Lars-Peter Clausen <lars@metafoo.de>, Dan Robertson <dan@dlrobertson.com>, 
	Rui Miguel Silva <rmfrfs@gmail.com>, Tomasz Duszynski <tduszyns@gmail.com>, 
	Kevin Tsai <ktsai@capellamicro.com>, Crt Mori <cmo@melexis.com>, 
	Dmitry Torokhov <dmitry.torokhov@gmail.com>, Nick Dyer <nick@shmanahar.org>, 
	Bastien Nocera <hadess@hadess.net>, Hans de Goede <hdegoede@redhat.com>, 
	Maxime Coquelin <mcoquelin.stm32@gmail.com>, Alexandre Torgue <alexandre.torgue@foss.st.com>, 
	Sakari Ailus <sakari.ailus@linux.intel.com>, Pavel Machek <pavel@ucw.cz>, 
	Jan-Simon Moeller <jansimon.moeller@gmx.de>, =?UTF-8?B?TWFyZWsgQmVow7pu?= <kabel@kernel.org>, 
	Colin Leroy <colin@colino.net>, Joe Tessler <jrt@google.com>, 
	Hans Verkuil <hverkuil-cisco@xs4all.nl>, Mauro Carvalho Chehab <mchehab@kernel.org>, 
	Antti Palosaari <crope@iki.fi>, Jasmin Jessich <jasmin@anw.at>, Matthias Schwarzott <zzam@gentoo.org>, 
	Olli Salonen <olli.salonen@iki.fi>, Akihiro Tsukada <tskd08@gmail.com>, 
	Kieran Bingham <kieran.bingham@ideasonboard.com>, Tianshu Qiu <tian.shu.qiu@intel.com>, 
	Dongchun Zhu <dongchun.zhu@mediatek.com>, Shawn Tu <shawnx.tu@intel.com>, 
	Martin Kepplinger <martink@posteo.de>, Ricardo Ribalda <ribalda@kernel.org>, 
	Dave Stevenson <dave.stevenson@raspberrypi.com>, Leon Luo <leonl@leopardimaging.com>, 
	Manivannan Sadhasivam <mani@kernel.org>, Bingbu Cao <bingbu.cao@intel.com>, 
	"Paul J. Murphy" <paul.j.murphy@intel.com>, 
	Daniele Alessandrelli <daniele.alessandrelli@intel.com>, 
	Michael Tretter <m.tretter@pengutronix.de>, Pengutronix Kernel Team <kernel@pengutronix.de>, 
	Kyungmin Park <kyungmin.park@samsung.com>, Heungjun Kim <riverful.kim@samsung.com>, 
	Ramesh Shanmugasundaram <rashanmu@gmail.com>, Jacopo Mondi <jacopo+renesas@jmondi.org>, 
	=?UTF-8?Q?Niklas_S=C3=B6derlund?= <niklas.soderlund+renesas@ragnatech.se>, 
	Jimmy Su <jimmy.su@intel.com>, Arec Kao <arec.kao@intel.com>, 
	"Lad, Prabhakar" <prabhakar.csengg@gmail.com>, Shunqian Zheng <zhengsq@rock-chips.com>, 
	Steve Longerbeam <slongerbeam@gmail.com>, Chiranjeevi Rapolu <chiranjeevi.rapolu@intel.com>, 
	Daniel Scally <djrscally@gmail.com>, Wenyou Yang <wenyou.yang@microchip.com>, 
	Petr Cvek <petrcvekcz@gmail.com>, Akinobu Mita <akinobu.mita@gmail.com>, 
	Sylwester Nawrocki <s.nawrocki@samsung.com>, Benjamin Mugnier <benjamin.mugnier@foss.st.com>, 
	Sylvain Petinot <sylvain.petinot@foss.st.com>, Mats Randgaard <matrandg@cisco.com>, 
	Tim Harvey <tharvey@gateworks.com>, Matt Ranostay <matt.ranostay@konsulko.com>, 
	Eduardo Valentin <edubezval@gmail.com>, "Daniel W. S. Almeida" <dwlsalmeida@gmail.com>, 
	Lee Jones <lee.jones@linaro.org>, Chen-Yu Tsai <wens@csie.org>, 
	Support Opensource <support.opensource@diasemi.com>, Robert Jones <rjones@gateworks.com>, 
	Andy Shevchenko <andy@kernel.org>, Charles Keepax <ckeepax@opensource.cirrus.com>, 
	Richard Fitzgerald <rf@opensource.cirrus.com>, 
	Krzysztof Kozlowski <krzysztof.kozlowski@linaro.org>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Tony Lindgren <tony@atomide.com>, 
	=?UTF-8?Q?Jonathan_Neusch=C3=A4fer?= <j.neuschaefer@gmx.net>, 
	Arnd Bergmann <arnd@arndb.de>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Eric Piel <eric.piel@tremplin-utc.net>, Miquel Raynal <miquel.raynal@bootlin.com>, 
	Richard Weinberger <richard@nod.at>, Vignesh Raghavendra <vigneshr@ti.com>, Andrew Lunn <andrew@lunn.ch>, 
	Vivien Didelot <vivien.didelot@gmail.com>, Vladimir Oltean <olteanv@gmail.com>, 
	Eric Dumazet <edumazet@google.com>, Jakub Kicinski <kuba@kernel.org>, Paolo Abeni <pabeni@redhat.com>, 
	Woojung Huh <woojung.huh@microchip.com>, UNGLinuxDriver@microchip.com, 
	George McCollister <george.mccollister@gmail.com>, Ido Schimmel <idosch@nvidia.com>, 
	Petr Machata <petrm@nvidia.com>, Jeremy Kerr <jk@codeconstruct.com.au>, 
	Matt Johnston <matt@codeconstruct.com.au>, Charles Gorand <charles.gorand@effinnov.com>, 
	Krzysztof Opasiak <k.opasiak@samsung.com>, Rob Herring <robh+dt@kernel.org>, 
	Frank Rowand <frowand.list@gmail.com>, Mark Gross <markgross@kernel.org>, 
	Maximilian Luz <luzmaximilian@gmail.com>, Corentin Chary <corentin.chary@gmail.com>, 
	=?UTF-8?Q?Pali_Roh=C3=A1r?= <pali@kernel.org>, 
	Sebastian Reichel <sre@kernel.org>, Tobias Schrammm <t.schramm@manjaro.org>, 
	Liam Girdwood <lgirdwood@gmail.com>, Mark Brown <broonie@kernel.org>, 
	Alessandro Zummo <a.zummo@towertech.it>, Jens Frederich <jfrederich@gmail.com>, 
	Jon Nettleton <jon.nettleton@gmail.com>, Jiri Slaby <jirislaby@kernel.org>, 
	Felipe Balbi <balbi@kernel.org>, Heikki Krogerus <heikki.krogerus@linux.intel.com>, 
	Daniel Thompson <daniel.thompson@linaro.org>, Jingoo Han <jingoohan1@gmail.com>, 
	Helge Deller <deller@gmx.de>, Evgeniy Polyakov <zbr@ioremap.net>, 
	Wim Van Sebroeck <wim@linux-watchdog.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Johannes Berg <johannes@sipsolutions.net>, Jaroslav Kysela <perex@perex.cz>, 
	Takashi Iwai <tiwai@suse.com>, James Schulman <james.schulman@cirrus.com>, 
	David Rhodes <david.rhodes@cirrus.com>, Lucas Tanure <tanureal@opensource.cirrus.com>, 
	=?UTF-8?B?TnVubyBTw6E=?= <nuno.sa@analog.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, Oder Chiou <oder_chiou@realtek.com>, 
	Fabio Estevam <festevam@gmail.com>, Kevin Cernekee <cernekee@chromium.org>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Maxime Ripard <maxime@cerno.tech>, 
	=?UTF-8?Q?Alvin_=C5=A0ipraga?= <alsi@bang-olufsen.dk>, 
	Lucas Stach <l.stach@pengutronix.de>, Jagan Teki <jagan@amarulasolutions.com>, 
	Biju Das <biju.das.jz@bp.renesas.com>, Thomas Zimmermann <tzimmermann@suse.de>, 
	Alex Deucher <alexander.deucher@amd.com>, Lyude Paul <lyude@redhat.com>, 
	Xin Ji <xji@analogixsemi.com>, Hsin-Yi Wang <hsinyi@chromium.org>, 
	=?UTF-8?B?Sm9zw6kgRXhww7NzaXRv?= <jose.exposito89@gmail.com>, 
	Yang Li <yang.lee@linux.alibaba.com>, Angela Czubak <acz@semihalf.com>, 
	Alistair Francis <alistair@alistair23.me>, Eddie James <eajames@linux.ibm.com>, 
	Joel Stanley <joel@jms.id.au>, Nathan Chancellor <nathan@kernel.org>, 
	Antoniu Miclaus <antoniu.miclaus@analog.com>, Alexandru Ardelean <ardeleanalex@gmail.com>, 
	Dmitry Rokosov <DDRokosov@sberdevices.ru>, 
	Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>, Stephan Gerhold <stephan@gerhold.net>, 
	Miaoqian Lin <linmq006@gmail.com>, Gwendal Grignou <gwendal@chromium.org>, 
	Yang Yingliang <yangyingliang@huawei.com>, Paul Cercueil <paul@crapouillou.net>, 
	Daniel Palmer <daniel@0x0f.com>, Haibo Chen <haibo.chen@nxp.com>, 
	Cai Huoqing <cai.huoqing@linux.dev>, Marek Vasut <marex@denx.de>, 
	Jose Cazarin <joseespiriki@gmail.com>, Dan Carpenter <dan.carpenter@oracle.com>, 
	Jean-Baptiste Maneyrol <jean-baptiste.maneyrol@tdk.com>, Michael Srba <Michael.Srba@seznam.cz>, 
	Nikita Travkin <nikita@trvn.ru>, Maslov Dmitry <maslovdmitry@seeed.cc>, Jiri Valek - 2N <valek@2n.cz>, 
	Arnaud Ferraris <arnaud.ferraris@collabora.com>, Zheyu Ma <zheyuma97@gmail.com>, 
	Marco Felsch <m.felsch@pengutronix.de>, Oliver Graute <oliver.graute@kococonnector.com>, 
	Zheng Yongjun <zhengyongjun3@huawei.com>, CGEL ZTE <cgel.zte@gmail.com>, 
	Minghao Chi <chi.minghao@zte.com.cn>, Evgeny Novikov <novikov@ispras.ru>, Sean Young <sean@mess.org>, 
	Kirill Shilimanov <kirill.shilimanov@huawei.com>, 
	Moses Christopher Bollavarapu <mosescb.dev@gmail.com>, Paul Kocialkowski <paul.kocialkowski@bootlin.com>, 
	Janusz Krzysztofik <jmkrzyszt@gmail.com>, Dongliang Mu <mudongliangabcd@gmail.com>, 
	Colin Ian King <colin.king@intel.com>, lijian <lijian@yulong.com>, 
	Kees Cook <keescook@chromium.org>, Yan Lei <yan_lei@dahuatech.com>, 
	Heiner Kallweit <hkallweit1@gmail.com>, Jonas Malaco <jonas@protocubo.io>, 
	wengjianfeng <wengjianfeng@yulong.com>, Rikard Falkeborn <rikard.falkeborn@gmail.com>, 
	Wei Yongjun <weiyongjun1@huawei.com>, Tom Rix <trix@redhat.com>, Yizhuo <yzhai003@ucr.edu>, 
	Martiros Shakhzadyan <vrzh@vrzh.net>, Bjorn Andersson <bjorn.andersson@linaro.org>, 
	Sven Peter <sven@svenpeter.dev>, Alyssa Rosenzweig <alyssa@rosenzweig.io>, 
	Hector Martin <marcan@marcan.st>, Saranya Gopal <saranya.gopal@intel.com>, 
	=?UTF-8?Q?Guido_G=C3=BCnther?= <agx@sigxcpu.org>, 
	Sing-Han Chen <singhanc@nvidia.com>, Wayne Chang <waynec@nvidia.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Alexey Dobriyan <adobriyan@gmail.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Vincent Knecht <vincent.knecht@mailoo.org>, 
	Stephen Kitt <steve@sk2.org>, Pierre-Louis Bossart <pierre-louis.bossart@linux.intel.com>, 
	Alexey Khoroshilov <khoroshilov@ispras.ru>, Randy Dunlap <rdunlap@infradead.org>, 
	Alejandro Tafalla <atafalla@dnyon.com>, Vijendar Mukunda <Vijendar.Mukunda@amd.com>, 
	Seven Lee <wtli@nuvoton.com>, Mac Chiang <mac.chiang@intel.com>, David Lin <CTLIN0@nuvoton.com>, 
	Daniel Beer <daniel.beer@igorinstitute.com>, Ricard Wanderlof <ricardw@axis.com>, 
	Simon Trimmer <simont@opensource.cirrus.com>, Shengjiu Wang <shengjiu.wang@nxp.com>, 
	Viorel Suman <viorel.suman@nxp.com>, Nicola Lunghi <nick83ola@gmail.com>, 
	Adam Ford <aford173@gmail.com>, linux-i2c@vger.kernel.org, 
	linux-arm-kernel@lists.infradead.org, linuxppc-dev@lists.ozlabs.org, 
	openipmi-developer@lists.sourceforge.net, linux-integrity@vger.kernel.org, 
	linux-clk@vger.kernel.org, linux-crypto@vger.kernel.org, 
	linux-gpio@vger.kernel.org, dri-devel@lists.freedesktop.org, 
	chrome-platform@lists.linux.dev, linux-rpi-kernel@lists.infradead.org, 
	linux-input@vger.kernel.org, linux-hwmon@vger.kernel.org, 
	linux-iio@vger.kernel.org, linux-stm32@st-md-mailman.stormreply.com, 
	linux-leds@vger.kernel.org, linux-media@vger.kernel.org, 
	patches@opensource.cirrus.com, alsa-devel@alsa-project.org, 
	linux-omap@vger.kernel.org, linux-mtd@lists.infradead.org, 
	netdev@vger.kernel.org, devicetree@vger.kernel.org, 
	platform-driver-x86@vger.kernel.org, acpi4asus-user@lists.sourceforge.net, 
	linux-pm@vger.kernel.org, linux-pwm@vger.kernel.org, 
	linux-rtc@vger.kernel.org, linux-staging@lists.linux.dev, 
	linux-serial@vger.kernel.org, linux-usb@vger.kernel.org, 
	linux-fbdev@vger.kernel.org, linux-watchdog@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Peter.Senna@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=nsSF081B;       spf=pass
 (google.com: domain of peter.senna@gmail.com designates 2607:f8b0:4864:20::1132
 as permitted sender) smtp.mailfrom=peter.senna@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Jun 28, 2022 at 4:05 PM Uwe Kleine-K=C3=B6nig
<u.kleine-koenig@pengutronix.de> wrote:
>
> From: Uwe Kleine-K=C3=B6nig <uwe@kleine-koenig.org>
>
> The value returned by an i2c driver's remove function is mostly ignored.
> (Only an error message is printed if the value is non-zero that the
> error is ignored.)
>
> So change the prototype of the remove function to return no value. This
> way driver authors are not tempted to assume that passing an error to
> the upper layer is a good idea. All drivers are adapted accordingly.
> There is no intended change of behaviour, all callbacks were prepared to
> return 0 before.
>
> Signed-off-by: Uwe Kleine-K=C3=B6nig <u.kleine-koenig@pengutronix.de>
> ---

[...]

>  static struct i2c_device_id lt9611uxc_id[] =3D {
> diff --git a/drivers/gpu/drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c b/d=
rivers/gpu/drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c
> index cce98bf2a4e7..9f175df11581 100644
> --- a/drivers/gpu/drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c
> +++ b/drivers/gpu/drm/bridge/megachips-stdpxxxx-ge-b850v3-fw.c
> @@ -355,11 +355,9 @@ static int stdp4028_ge_b850v3_fw_probe(struct i2c_cl=
ient *stdp4028_i2c,
>         return ge_b850v3_register();
>  }
>
> -static int stdp4028_ge_b850v3_fw_remove(struct i2c_client *stdp4028_i2c)
> +static void stdp4028_ge_b850v3_fw_remove(struct i2c_client *stdp4028_i2c=
)
>  {
>         ge_b850v3_lvds_remove();
> -
> -       return 0;
>  }
>
>  static const struct i2c_device_id stdp4028_ge_b850v3_fw_i2c_table[] =3D =
{
> @@ -405,11 +403,9 @@ static int stdp2690_ge_b850v3_fw_probe(struct i2c_cl=
ient *stdp2690_i2c,
>         return ge_b850v3_register();
>  }
>
> -static int stdp2690_ge_b850v3_fw_remove(struct i2c_client *stdp2690_i2c)
> +static void stdp2690_ge_b850v3_fw_remove(struct i2c_client *stdp2690_i2c=
)
>  {
>         ge_b850v3_lvds_remove();
> -
> -       return 0;
>  }
>
>  static const struct i2c_device_id stdp2690_ge_b850v3_fw_i2c_table[] =3D =
{
Reviewed-by: Peter Senna Tschudin <peter.senna@gmail.com>

[...]

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BMoWDrJKP1YHcBwb8AKBr59eymHEZH9QEKEwOWL2pVK1LFDEQ%40mail.gmai=
l.com.
