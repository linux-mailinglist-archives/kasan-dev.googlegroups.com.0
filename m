Return-Path: <kasan-dev+bncBD2MPO4QTIPBBHHT56KQMGQE353M6DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id D9D3D55F775
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 09:05:01 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id 5-20020a620605000000b00527ca01f8a3sf1775012pfg.19
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 00:05:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656486300; cv=pass;
        d=google.com; s=arc-20160816;
        b=HaFaReUxcMD85qZ8cIt6mLzfZ9xozfkjwgOigcATR5toq8qx9xa2P9urH1P/uSH//H
         EmG2XV0xeCHzDYD/XCD/kCIbuXwRotMgqV4QUrN2myurrck0kyNbBpnWdL5X61/gz2Fh
         UgtFbxtZDGbFT5MkbguffoONhtcsdx8hLmjN/OWcWkWq5Qn0HBoQRbp8XlMnF36dnI/S
         zv4mBDlsKbGE7tKi1ZpVmarkw0mhjX6xiP/NRxiR3XbMgNOaQSkwZVRH7kTdkD0AjZhG
         vYnmwvJ+ZFrBSZNf9gVazEt0vAIBa+fi0AYa8WzXMveaQmKqHtueAD/C2odomHB6Lb1X
         DkMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:sender:dkim-signature;
        bh=VH3YLKWfbe4zk0ptCZWYC1Hnb42QDhhTlnbOeaG0SFM=;
        b=jXnfxgjMyaG4n80ZE+iD0YuwCwm+4eh8eD05YkyI4pr+fJHU12D/iUDKmPeGM2tZCf
         HFY/e48x8BYo3KP7n+wpQiUQncChuiSyvwQFhgnpEgyRWBUyAnR6AlAHbKLStjxFsrlM
         PRXUINM02j+kxh8bngfzQMf0BbyJ5ZX+b43lJEz5wcjz+DjcqgCFo8xDbAhMLlDshRq4
         FottMW7nkXuhBarcpU8rJhdpGYWCB2lKH92FYTp8fzllQuUCw5Lo/O6kRrvZqMDoiHNj
         aAJK+4JNyX+qPtrcXCau65NKtGOtGZqByqKiUuTA2EL545Y4uNnRz6tVMc57BbszX27i
         qdDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@codeconstruct.com.au header.s=2022a header.b=X7tGIzHu;
       spf=pass (google.com: domain of jk@codeconstruct.com.au designates 203.29.241.158 as permitted sender) smtp.mailfrom=jk@codeconstruct.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codeconstruct.com.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :content-transfer-encoding:user-agent:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VH3YLKWfbe4zk0ptCZWYC1Hnb42QDhhTlnbOeaG0SFM=;
        b=c9+nzMRJP7QQKOLjOlpQWmoUuq5kiOomV6Y4MeXOTPvcFNXgKNC5j+nFWsLbFoQKqv
         vSaT/zgUhWFiCkniNQ6IH/kpk8PaZRsbj8uV9eeaUU1vYy0sR4MUJG0ZrL/bl5yBSD+H
         e7dbVnGA4LLhPcJCKyQytNgmtZZTuT6RUQS2gtwx3iTIy3FQKUFBx257jz/14DSkQmZ9
         lYGgXBWnHswG++x1lW2p8zCybu+Ay8F54Tth0kxSwwmlV5lDAp4xiMfqd4YjUgJ/qVxs
         H6lX9ubS4QtDoGBuNOQYWIKnL+gQ/v5gZSrezwx+Kgx0cHhRUOIBGG2e2E4zFZjRpaTY
         8uMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:content-transfer-encoding:user-agent
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VH3YLKWfbe4zk0ptCZWYC1Hnb42QDhhTlnbOeaG0SFM=;
        b=YCoX+KS0uO4dfMD8cC6SbzaA2aJxTQT7cUH/fOUj8JjU0Mu/kC3rExeUvBVuUAWt9p
         DD2XFkrFGJskeTA8XSMksI7497wScFAwms5RW/DeY9x2UoTJ3t7yH9wMyUa8LIDeqwqw
         l9fok7bJkqOZFMvMnRV/FjWZdXF76ptJGnacjtuiHW9MripVELARBb5SU+xPOzAqm4t4
         FRCocEauX+0CEN5liVnLxJzhVJha8xqmjhL9AaryxCGj6P5dMPvF2KkLxKSoNySSThfn
         PJ0wT+pHVvcpnKfMXy8PQDqEMGDQxuAVdow3MHfO8+HQUe3wzxwUWVBXP80B20eszVmj
         NEmw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/ksXmQJDQO/y4My0sGIvzsW2p2iMgd+Eq6xRzHU8b3F5V7QdfI
	9dQ+qKwT9GMUeFRqksxr94k=
X-Google-Smtp-Source: AGRyM1uZRhPEQ7gPM5d+J1iYVMcpmH3mcnWo5nBRVdqQf78JyZVQbI4rUpY9MV0eolIZGHwWqaNBSA==
X-Received: by 2002:a05:6a00:1a15:b0:527:d02b:29c6 with SMTP id g21-20020a056a001a1500b00527d02b29c6mr6145467pfv.23.1656486300166;
        Wed, 29 Jun 2022 00:05:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1a0b:0:b0:3fd:9834:5d21 with SMTP id a11-20020a631a0b000000b003fd98345d21ls13676029pga.9.gmail;
 Wed, 29 Jun 2022 00:04:59 -0700 (PDT)
X-Received: by 2002:a63:8c47:0:b0:40d:2d4:e3a2 with SMTP id q7-20020a638c47000000b0040d02d4e3a2mr1845981pgn.2.1656486299464;
        Wed, 29 Jun 2022 00:04:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656486299; cv=none;
        d=google.com; s=arc-20160816;
        b=DNg2Pkvl/w5/9+ln79NsADRzSyusWJP8yFcIH04X709XGQDlsTgbi/AhuPbr0fiNe/
         0fl+JhJVpzZmJnx7IHYdCdBCfL95LyWVObRZmLtXrwjUtjFCEDyZnQ2xloEi6AI7IRLL
         2n1wDk71XA4Tpp7Rp9WdLUH/pvB6btGG3venKBbpT2+WQFErUgeWRTjCX4oE9PH/VBha
         RnyS1DO81bcMnldphI1ST7DEa0xmqg7oxsXd/8tLiUZPMCQ+9UCYpi9UmEkW/VnZYEPZ
         qAH8SJ7WiODYAF2wEXVxs1QoeZ2frZluILE5KhhIXxN0XB/KJ5WZSzn5zyQGg132yu0e
         ymtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=eOkMn4BdLyYJIY7WVcJ+BSTGLOGnPlIkZql9k18jmoA=;
        b=pfsluj+P0nPVgY6M3MdV27chEEP4/ZgBv6865XYMrwUR8xl/kpfhCWwK4MOGQkNQHY
         3EUcv1ZOcPrh9QUYwab3sJDPOoK6q8kU5wn2uZ5xwb2UCg26YausezEwiZu7gz5LAgx4
         q/Zn8rAIn8396vcFsEVCyjILAo0kTLpJ94eOB64LCpr4Hl2+17R4lAiKRtz35DtuvhLZ
         F9jtItOhOigU2Kkxfq2f6N3VMkw2WvKuiKz4Gn4xUohTFJdBs+0yAdcbmemMCZhF/oOe
         uEg0MfttSvTrsLPQyfAkj5oddOYGQw66oEeue0jfgx6OTOXKfx1S+L2oJv/oxpsIBX4p
         hkuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@codeconstruct.com.au header.s=2022a header.b=X7tGIzHu;
       spf=pass (google.com: domain of jk@codeconstruct.com.au designates 203.29.241.158 as permitted sender) smtp.mailfrom=jk@codeconstruct.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codeconstruct.com.au
Received: from codeconstruct.com.au (pi.codeconstruct.com.au. [203.29.241.158])
        by gmr-mx.google.com with ESMTPS id ca10-20020a056a00418a00b0051c55b05eaesi366795pfb.5.2022.06.29.00.04.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Jun 2022 00:04:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of jk@codeconstruct.com.au designates 203.29.241.158 as permitted sender) client-ip=203.29.241.158;
Received: from pecola.lan (unknown [159.196.93.152])
	by mail.codeconstruct.com.au (Postfix) with ESMTPSA id A134D2003E;
	Wed, 29 Jun 2022 15:03:54 +0800 (AWST)
Message-ID: <60cc6796236f23c028a9ae76dbe00d1917df82a5.camel@codeconstruct.com.au>
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
From: Jeremy Kerr <jk@codeconstruct.com.au>
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
 <idosch@nvidia.com>, Petr Machata <petrm@nvidia.com>, Matt Johnston
 <matt@codeconstruct.com.au>,  Charles Gorand <charles.gorand@effinnov.com>,
 Krzysztof Opasiak <k.opasiak@samsung.com>, Rob Herring
 <robh+dt@kernel.org>, Frank Rowand <frowand.list@gmail.com>, Mark Gross
 <markgross@kernel.org>, Maximilian Luz <luzmaximilian@gmail.com>, Corentin
 Chary <corentin.chary@gmail.com>, Pali =?ISO-8859-1?Q?Roh=E1r?=
 <pali@kernel.org>,  Sebastian Reichel <sre@kernel.org>, Tobias Schrammm
 <t.schramm@manjaro.org>, Liam Girdwood <lgirdwood@gmail.com>, Mark Brown
 <broonie@kernel.org>, Alessandro Zummo <a.zummo@towertech.it>, Jens
 Frederich <jfrederich@gmail.com>, Jon Nettleton <jon.nettleton@gmail.com>,
 Jiri Slaby <jirislaby@kernel.org>, Felipe Balbi <balbi@kernel.org>, Heikki
 Krogerus <heikki.krogerus@linux.intel.com>,  Daniel Thompson
 <daniel.thompson@linaro.org>, Jingoo Han <jingoohan1@gmail.com>, Helge
 Deller <deller@gmx.de>,  Evgeniy Polyakov <zbr@ioremap.net>, Wim Van
 Sebroeck <wim@linux-watchdog.org>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>, Johannes Berg
 <johannes@sipsolutions.net>,  Jaroslav Kysela <perex@perex.cz>, Takashi
 Iwai <tiwai@suse.com>, James Schulman <james.schulman@cirrus.com>, David
 Rhodes <david.rhodes@cirrus.com>, Lucas Tanure
 <tanureal@opensource.cirrus.com>, Nuno =?ISO-8859-1?Q?S=E1?=
 <nuno.sa@analog.com>,  Matthias Brugger <matthias.bgg@gmail.com>, Oder
 Chiou <oder_chiou@realtek.com>, Fabio Estevam <festevam@gmail.com>,  Kevin
 Cernekee <cernekee@chromium.org>, Christophe Leroy
 <christophe.leroy@csgroup.eu>, Maxime Ripard <maxime@cerno.tech>, Alvin
 =?UTF-8?Q?=C5=A0ipraga?= <alsi@bang-olufsen.dk>,  Lucas Stach
 <l.stach@pengutronix.de>, Jagan Teki <jagan@amarulasolutions.com>, Biju Das
 <biju.das.jz@bp.renesas.com>, Thomas Zimmermann <tzimmermann@suse.de>, Alex
 Deucher <alexander.deucher@amd.com>, Lyude Paul <lyude@redhat.com>, Xin Ji
 <xji@analogixsemi.com>,  Hsin-Yi Wang <hsinyi@chromium.org>,
 =?ISO-8859-1?Q?Jos=E9_Exp=F3sito?= <jose.exposito89@gmail.com>, Yang Li
 <yang.lee@linux.alibaba.com>, Angela Czubak <acz@semihalf.com>, Alistair
 Francis <alistair@alistair23.me>, Eddie James <eajames@linux.ibm.com>, Joel
 Stanley <joel@jms.id.au>,  Nathan Chancellor <nathan@kernel.org>, Antoniu
 Miclaus <antoniu.miclaus@analog.com>, Alexandru Ardelean
 <ardeleanalex@gmail.com>, Dmitry Rokosov <DDRokosov@sberdevices.ru>,
 Srinivas Pandruvada <srinivas.pandruvada@linux.intel.com>, Stephan Gerhold
 <stephan@gerhold.net>,  Miaoqian Lin <linmq006@gmail.com>, Gwendal Grignou
 <gwendal@chromium.org>, Yang Yingliang <yangyingliang@huawei.com>, Paul
 Cercueil <paul@crapouillou.net>, Daniel Palmer <daniel@0x0f.com>, Haibo
 Chen <haibo.chen@nxp.com>, Cai Huoqing <cai.huoqing@linux.dev>, Marek Vasut
 <marex@denx.de>, Jose Cazarin <joseespiriki@gmail.com>, Dan Carpenter
 <dan.carpenter@oracle.com>,  Jean-Baptiste Maneyrol
 <jean-baptiste.maneyrol@tdk.com>, Michael Srba <Michael.Srba@seznam.cz>,
 Nikita Travkin <nikita@trvn.ru>,  Maslov Dmitry <maslovdmitry@seeed.cc>,
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
Date: Wed, 29 Jun 2022 15:03:54 +0800
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
	 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.44.0-2
MIME-Version: 1.0
X-Original-Sender: jk@codeconstruct.com.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@codeconstruct.com.au header.s=2022a header.b=X7tGIzHu;
       spf=pass (google.com: domain of jk@codeconstruct.com.au designates
 203.29.241.158 as permitted sender) smtp.mailfrom=jk@codeconstruct.com.au;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=codeconstruct.com.au
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

Looks good - just one minor change for the mctp-i2c driver, but only
worthwhile if you end up re-rolling this series for other reasons:

> -static int mctp_i2c_remove(struct i2c_client *client)
> +static void mctp_i2c_remove(struct i2c_client *client)
> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mctp_i2c_client *m=
cli =3D i2c_get_clientdata(client);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0struct mctp_i2c_dev *mide=
v =3D NULL, *tmp =3D NULL;
> @@ -1000,7 +1000,6 @@ static int mctp_i2c_remove(struct i2c_client *clien=
t)
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mctp_i2c_free_client(mcli=
);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0mutex_unlock(&driver_clie=
nts_lock);
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0/* Callers ignore return =
code */
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return 0;
> =C2=A0}

The comment there no longer makes much sense, I'd suggest removing that
too. Either way:

Reviewed-by: Jeremy Kerr <jk@codeconstruct.com.au>

Cheers,


Jeremy

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/60cc6796236f23c028a9ae76dbe00d1917df82a5.camel%40codeconstruct.co=
m.au.
