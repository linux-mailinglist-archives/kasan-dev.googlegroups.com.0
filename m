Return-Path: <kasan-dev+bncBDNLPI4ESUMBBMME6CKQMGQE3BF7BIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 690C655F94A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 09:41:38 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id w12-20020adf8bcc000000b0021d20a5b24fsf733574wra.22
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 00:41:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656488498; cv=pass;
        d=google.com; s=arc-20160816;
        b=q9C+JkXQY+LGFiuXCBq/ZNF6htCtdS/g3xfTbCsB8tzUBZpAnz+It8iTbl4Z1kU+Ia
         3lI7su0RjQEDeYMwV84rBPCsh4w1Z2sVh59gXvwgVIvJ/sf38qlw6Ph8fnEuVCcUiroJ
         cmcv+j9+yUO8l4Xv7E5Q0RJFiWq05vBezCjp82IeACiqnuN/kyG8w8h5mxPNEt0eXc3C
         lWjlkXNx8ijlnFXg6Uk042DdAXZmBZ1LxzymBsYs0yTYp3ZoCXWsCHaadbulzR5KLW5Z
         PdubnM6J3wCpNa2g08NvpYCL2Up1vO19xokqb/90dv9zdrUr/u9KVMilNTBEDhLL6+cM
         dTGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=dVgHAgr2L70jiENNVRYcAHISSmAsGDrPshd42R+KTVI=;
        b=Ec2TYwGg8ui6xTeuATbggFLiFN9t736wn2PUxz4unIfMWYPlCrhg26ShJOIRV9G4Lk
         F+YfcfFcTJfi5sMD2EMz0N1TOfoTV4jWj9IbHi+9znl6ZiHC46K0XIA2VhuAd3WzBFHS
         L5nUkyS1kB0Igx/K/Wcz7RwRtOypVZsUm2b7AIhOu/FqFpQhAdSZWkJrrYl3FBo9S9hm
         XR/fDzwzC634T6YzaEG9i5HJwqHJUr92OYA83xw0LnHlNCer+GUkO6ZiE/DfWkdEvu47
         vHS4Pq7ZbES/MevqXNgBVzlBOXHNQrROqhaq/muUYyJ3ovF6wHoz9DqKllpbwbWKvFvB
         AbHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=TWA3luX9;
       spf=pass (google.com: best guess record for domain of heikki.krogerus@linux.intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=heikki.krogerus@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dVgHAgr2L70jiENNVRYcAHISSmAsGDrPshd42R+KTVI=;
        b=p62lBuCpZ8dKwDh0pwDBLD4t+nYrg19Bfw+PZKH7Qcd6JfxnqMivPTkiJBQGj+piM9
         nwDLACH/921hmVHiiRv8nYH4UTCU9fCnJpNiade1KHMx2WKdlXcoAov3/xleGShiFuOA
         UHq3T3ib45WiNRAAuCDrB//2t/kU4sznasDvYz1ZPq/ChZOzQNDgsGnmv3AD8fjbSxaW
         nlOa1UGwESUw8HRHPa0v4H+LCKphBPS1cOtUtRtsK49pnA34Fu55HLdwMwPlAX9SHb9I
         pT0pDHnnYh1k31aUG4q9R4OiiaK2UgDzO26zSKFApgequKtrYzr6StZj7TvJggYNtOCn
         oclw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dVgHAgr2L70jiENNVRYcAHISSmAsGDrPshd42R+KTVI=;
        b=v6V+LFeU8fV1kiCJzCao8QWjZbWHmWNX88y9qqoSRGpN0thn1pYuqgZ5tqX24mNH/F
         8+Uw6l43mMJWkOCaZEZ3imTxucZU0UI4jitU363N/2RC1BIdjL1eYWZERSfBG8dp9CZT
         R1W9vZYsZPWjDyz+wuqfzgJlsrw4nTKMvnwhHM6EOcrmHePZyrUuWYk4dAUXG9TwYBsl
         3jw0tUfUMUR8y87cJBzyQ9NWH8+rAFhtk9xUxRpJgcFMlkof+zhjhbnXj1H2p8+SbWVQ
         tpZDFsHdekIGzF1lNjWVJ4zFdHWLisQdyuYyEyySK3bUdSMx8JIv/sSGWYoay40/gK1S
         Zvrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+OSvZufIoKrqOMln23UjMRPFc4+khLbIii4FfKxHD2Mhc28GDI
	PKgG0iK+q+21fHRzBpwL8Mg=
X-Google-Smtp-Source: AGRyM1svOjUdHsfhe2fvGzu15cUao1pTrmV73+sLkYQPjq2iOTE4dmpBW+nbJxhfTxOskIiLJmBAtg==
X-Received: by 2002:a05:600c:210d:b0:3a0:2eea:bf4b with SMTP id u13-20020a05600c210d00b003a02eeabf4bmr2122551wml.28.1656488497979;
        Wed, 29 Jun 2022 00:41:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:156e:b0:21d:2eb7:c707 with SMTP id
 14-20020a056000156e00b0021d2eb7c707ls322483wrz.3.gmail; Wed, 29 Jun 2022
 00:41:36 -0700 (PDT)
X-Received: by 2002:a05:6000:102:b0:21b:9219:b28e with SMTP id o2-20020a056000010200b0021b9219b28emr1673413wrx.236.1656488496338;
        Wed, 29 Jun 2022 00:41:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656488496; cv=none;
        d=google.com; s=arc-20160816;
        b=UIp5e1dNovlw+6wZsvwPHnQ2Sgf/g6O68RZghmTjqvvvIPVOQ67TZp425oAmXHr9uF
         5EQt/1kvWgJRSrvwFqUTf9/iiOcpW0HV04SLdf7xbp8CA8+dcyH0p++9/NB4JEBrbLhi
         iEtCc8L5ILUUMbBdr6Tr41P1Il2LJRw4tRhVxXnbUxXCDK53sHxx0NRaIOT+eJq6DGjh
         P9tJT5YqSF/RyUQj7lql4UeL+9Ircy400GsIhkYmorij17tNcJVdPCuMh2e3zO2VmfA5
         i+6GV+PnF7mVryhukKsNMDZTne6C1bCLXpn7rT7oeCwN3dbwMYVDX1HRUBbj+qHgHhqW
         FF1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=YVrXwuTPggf1EtX7JJxI+g99eW9Kzw38LCP67CQulG4=;
        b=xjLmL7+wnHwJvoNXu5fKu8+hM3u8yMekCUHETGe9M0ZNDaE79yIASZo8eI3+HNGRa+
         FLzplRvp+tdFDPuVgrBQi6ZAFKkb3seUX0OUmd9L/NouL03pupXNg/guBq3HQP5gFEb4
         +kcyndxtXXvWyXWMxJPSBcMEodT6wUR+yZkLWF19Y/v5L/Jq3SrUr6dFozHdBV5QzdLi
         XWOkJstVx2OyV1677VuiCxvpZ5iyN+UQJSps8Ppy//7/plyMPiOs7JZF2WcnUPwqmgMO
         CVV8mX9EgjvytYH5lCBbrReX6K5q7RsX8VkvEg0sZA97feTDhvvUpdHP7+39uqnk+7uL
         5vMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=TWA3luX9;
       spf=pass (google.com: best guess record for domain of heikki.krogerus@linux.intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=heikki.krogerus@linux.intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id x11-20020adfdccb000000b0021bbdc3209asi463940wrm.1.2022.06.29.00.41.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jun 2022 00:41:36 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of heikki.krogerus@linux.intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6400,9594,10392"; a="270717166"
X-IronPort-AV: E=Sophos;i="5.92,230,1650956400"; 
   d="scan'208";a="270717166"
Received: from fmsmga001.fm.intel.com ([10.253.24.23])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 29 Jun 2022 00:41:34 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.92,230,1650956400"; 
   d="scan'208";a="733074160"
Received: from kuha.fi.intel.com ([10.237.72.185])
  by fmsmga001.fm.intel.com with SMTP; 29 Jun 2022 00:40:24 -0700
Received: by kuha.fi.intel.com (sSMTP sendmail emulation); Wed, 29 Jun 2022 10:40:23 +0300
Date: Wed, 29 Jun 2022 10:40:23 +0300
From: Heikki Krogerus <heikki.krogerus@linux.intel.com>
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
	Broad
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Message-ID: <YrwB5xPKZmHlXzrC@kuha.fi.intel.com>
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
X-Original-Sender: heikki.krogerus@linux.intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=TWA3luX9;       spf=pass
 (google.com: best guess record for domain of heikki.krogerus@linux.intel.com
 designates 134.134.136.20 as permitted sender) smtp.mailfrom=heikki.krogerus@linux.intel.com;
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

On Tue, Jun 28, 2022 at 04:03:12PM +0200, Uwe Kleine-K=C3=B6nig wrote:
> diff --git a/drivers/usb/typec/hd3ss3220.c b/drivers/usb/typec/hd3ss3220.=
c
> index cd47c3597e19..2a58185fb14c 100644
> --- a/drivers/usb/typec/hd3ss3220.c
> +++ b/drivers/usb/typec/hd3ss3220.c
> @@ -245,14 +245,12 @@ static int hd3ss3220_probe(struct i2c_client *clien=
t,
>  	return ret;
>  }
> =20
> -static int hd3ss3220_remove(struct i2c_client *client)
> +static void hd3ss3220_remove(struct i2c_client *client)
>  {
>  	struct hd3ss3220 *hd3ss3220 =3D i2c_get_clientdata(client);
> =20
>  	typec_unregister_port(hd3ss3220->port);
>  	usb_role_switch_put(hd3ss3220->role_sw);
> -
> -	return 0;
>  }
> =20
>  static const struct of_device_id dev_ids[] =3D {
> diff --git a/drivers/usb/typec/mux/fsa4480.c b/drivers/usb/typec/mux/fsa4=
480.c
> index 6184f5367190..d6495e533e58 100644
> --- a/drivers/usb/typec/mux/fsa4480.c
> +++ b/drivers/usb/typec/mux/fsa4480.c
> @@ -181,14 +181,12 @@ static int fsa4480_probe(struct i2c_client *client)
>  	return 0;
>  }
> =20
> -static int fsa4480_remove(struct i2c_client *client)
> +static void fsa4480_remove(struct i2c_client *client)
>  {
>  	struct fsa4480 *fsa =3D i2c_get_clientdata(client);
> =20
>  	typec_mux_unregister(fsa->mux);
>  	typec_switch_unregister(fsa->sw);
> -
> -	return 0;
>  }
> =20
>  static const struct i2c_device_id fsa4480_table[] =3D {
> diff --git a/drivers/usb/typec/mux/pi3usb30532.c b/drivers/usb/typec/mux/=
pi3usb30532.c
> index 6ce9f282594e..1cd388b55c30 100644
> --- a/drivers/usb/typec/mux/pi3usb30532.c
> +++ b/drivers/usb/typec/mux/pi3usb30532.c
> @@ -160,13 +160,12 @@ static int pi3usb30532_probe(struct i2c_client *cli=
ent)
>  	return 0;
>  }
> =20
> -static int pi3usb30532_remove(struct i2c_client *client)
> +static void pi3usb30532_remove(struct i2c_client *client)
>  {
>  	struct pi3usb30532 *pi =3D i2c_get_clientdata(client);
> =20
>  	typec_mux_unregister(pi->mux);
>  	typec_switch_unregister(pi->sw);
> -	return 0;
>  }
> =20
>  static const struct i2c_device_id pi3usb30532_table[] =3D {
> diff --git a/drivers/usb/typec/rt1719.c b/drivers/usb/typec/rt1719.c
> index f1b698edd7eb..ea8b700b0ceb 100644
> --- a/drivers/usb/typec/rt1719.c
> +++ b/drivers/usb/typec/rt1719.c
> @@ -930,14 +930,12 @@ static int rt1719_probe(struct i2c_client *i2c)
>  	return ret;
>  }
> =20
> -static int rt1719_remove(struct i2c_client *i2c)
> +static void rt1719_remove(struct i2c_client *i2c)
>  {
>  	struct rt1719_data *data =3D i2c_get_clientdata(i2c);
> =20
>  	typec_unregister_port(data->port);
>  	usb_role_switch_put(data->role_sw);
> -
> -	return 0;
>  }
> =20
>  static const struct of_device_id __maybe_unused rt1719_device_table[] =
=3D {
> diff --git a/drivers/usb/typec/stusb160x.c b/drivers/usb/typec/stusb160x.=
c
> index e7745d1c2a5c..8638f1d39896 100644
> --- a/drivers/usb/typec/stusb160x.c
> +++ b/drivers/usb/typec/stusb160x.c
> @@ -801,7 +801,7 @@ static int stusb160x_probe(struct i2c_client *client)
>  	return ret;
>  }
> =20
> -static int stusb160x_remove(struct i2c_client *client)
> +static void stusb160x_remove(struct i2c_client *client)
>  {
>  	struct stusb160x *chip =3D i2c_get_clientdata(client);
> =20
> @@ -823,8 +823,6 @@ static int stusb160x_remove(struct i2c_client *client=
)
> =20
>  	if (chip->main_supply)
>  		regulator_disable(chip->main_supply);
> -
> -	return 0;
>  }
> =20
>  static int __maybe_unused stusb160x_suspend(struct device *dev)
> diff --git a/drivers/usb/typec/tcpm/fusb302.c b/drivers/usb/typec/tcpm/fu=
sb302.c
> index 96c55eaf3f80..5e9348f28d50 100644
> --- a/drivers/usb/typec/tcpm/fusb302.c
> +++ b/drivers/usb/typec/tcpm/fusb302.c
> @@ -1771,7 +1771,7 @@ static int fusb302_probe(struct i2c_client *client,
>  	return ret;
>  }
> =20
> -static int fusb302_remove(struct i2c_client *client)
> +static void fusb302_remove(struct i2c_client *client)
>  {
>  	struct fusb302_chip *chip =3D i2c_get_clientdata(client);
> =20
> @@ -1783,8 +1783,6 @@ static int fusb302_remove(struct i2c_client *client=
)
>  	fwnode_handle_put(chip->tcpc_dev.fwnode);
>  	destroy_workqueue(chip->wq);
>  	fusb302_debugfs_exit(chip);
> -
> -	return 0;
>  }
> =20
>  static int fusb302_pm_suspend(struct device *dev)
> diff --git a/drivers/usb/typec/tcpm/tcpci.c b/drivers/usb/typec/tcpm/tcpc=
i.c
> index f33e08eb7670..c48fca60bb06 100644
> --- a/drivers/usb/typec/tcpm/tcpci.c
> +++ b/drivers/usb/typec/tcpm/tcpci.c
> @@ -869,7 +869,7 @@ static int tcpci_probe(struct i2c_client *client,
>  	return 0;
>  }
> =20
> -static int tcpci_remove(struct i2c_client *client)
> +static void tcpci_remove(struct i2c_client *client)
>  {
>  	struct tcpci_chip *chip =3D i2c_get_clientdata(client);
>  	int err;
> @@ -880,8 +880,6 @@ static int tcpci_remove(struct i2c_client *client)
>  		dev_warn(&client->dev, "Failed to disable irqs (%pe)\n", ERR_PTR(err))=
;
> =20
>  	tcpci_unregister_port(chip->tcpci);
> -
> -	return 0;
>  }
> =20
>  static const struct i2c_device_id tcpci_id[] =3D {
> diff --git a/drivers/usb/typec/tcpm/tcpci_maxim.c b/drivers/usb/typec/tcp=
m/tcpci_maxim.c
> index df2505570f07..a11be5754128 100644
> --- a/drivers/usb/typec/tcpm/tcpci_maxim.c
> +++ b/drivers/usb/typec/tcpm/tcpci_maxim.c
> @@ -493,14 +493,12 @@ static int max_tcpci_probe(struct i2c_client *clien=
t, const struct i2c_device_id
>  	return ret;
>  }
> =20
> -static int max_tcpci_remove(struct i2c_client *client)
> +static void max_tcpci_remove(struct i2c_client *client)
>  {
>  	struct max_tcpci_chip *chip =3D i2c_get_clientdata(client);
> =20
>  	if (!IS_ERR_OR_NULL(chip->tcpci))
>  		tcpci_unregister_port(chip->tcpci);
> -
> -	return 0;
>  }
> =20
>  static const struct i2c_device_id max_tcpci_id[] =3D {
> diff --git a/drivers/usb/typec/tcpm/tcpci_rt1711h.c b/drivers/usb/typec/t=
cpm/tcpci_rt1711h.c
> index b56a0880a044..9ad4924b4ba7 100644
> --- a/drivers/usb/typec/tcpm/tcpci_rt1711h.c
> +++ b/drivers/usb/typec/tcpm/tcpci_rt1711h.c
> @@ -263,12 +263,11 @@ static int rt1711h_probe(struct i2c_client *client,
>  	return 0;
>  }
> =20
> -static int rt1711h_remove(struct i2c_client *client)
> +static void rt1711h_remove(struct i2c_client *client)
>  {
>  	struct rt1711h_chip *chip =3D i2c_get_clientdata(client);
> =20
>  	tcpci_unregister_port(chip->tcpci);
> -	return 0;
>  }
> =20
>  static const struct i2c_device_id rt1711h_id[] =3D {
> diff --git a/drivers/usb/typec/tipd/core.c b/drivers/usb/typec/tipd/core.=
c
> index dfbba5ae9487..b637e8b378b3 100644
> --- a/drivers/usb/typec/tipd/core.c
> +++ b/drivers/usb/typec/tipd/core.c
> @@ -857,15 +857,13 @@ static int tps6598x_probe(struct i2c_client *client=
)
>  	return ret;
>  }
> =20
> -static int tps6598x_remove(struct i2c_client *client)
> +static void tps6598x_remove(struct i2c_client *client)
>  {
>  	struct tps6598x *tps =3D i2c_get_clientdata(client);
> =20
>  	tps6598x_disconnect(tps, 0);
>  	typec_unregister_port(tps->port);
>  	usb_role_switch_put(tps->role_sw);
> -
> -	return 0;
>  }
> =20
>  static const struct of_device_id tps6598x_of_match[] =3D {
> diff --git a/drivers/usb/typec/ucsi/ucsi_ccg.c b/drivers/usb/typec/ucsi/u=
csi_ccg.c
> index 6db7c8ddd51c..920b7e743f56 100644
> --- a/drivers/usb/typec/ucsi/ucsi_ccg.c
> +++ b/drivers/usb/typec/ucsi/ucsi_ccg.c
> @@ -1398,7 +1398,7 @@ static int ucsi_ccg_probe(struct i2c_client *client=
,
>  	return status;
>  }
> =20
> -static int ucsi_ccg_remove(struct i2c_client *client)
> +static void ucsi_ccg_remove(struct i2c_client *client)
>  {
>  	struct ucsi_ccg *uc =3D i2c_get_clientdata(client);
> =20
> @@ -1408,8 +1408,6 @@ static int ucsi_ccg_remove(struct i2c_client *clien=
t)
>  	ucsi_unregister(uc->ucsi);
>  	ucsi_destroy(uc->ucsi);
>  	free_irq(uc->irq, uc);
> -
> -	return 0;
>  }
> =20
>  static const struct i2c_device_id ucsi_ccg_device_id[] =3D {
> diff --git a/drivers/usb/typec/wusb3801.c b/drivers/usb/typec/wusb3801.c
> index e63509f8b01e..3cc7a15ecbd3 100644
> --- a/drivers/usb/typec/wusb3801.c
> +++ b/drivers/usb/typec/wusb3801.c
> @@ -399,7 +399,7 @@ static int wusb3801_probe(struct i2c_client *client)
>  	return ret;
>  }
> =20
> -static int wusb3801_remove(struct i2c_client *client)
> +static void wusb3801_remove(struct i2c_client *client)
>  {
>  	struct wusb3801 *wusb3801 =3D i2c_get_clientdata(client);
> =20
> @@ -411,8 +411,6 @@ static int wusb3801_remove(struct i2c_client *client)
> =20
>  	if (wusb3801->vbus_on)
>  		regulator_disable(wusb3801->vbus_supply);
> -
> -	return 0;
>  }

Reviewed-by: Heikki Krogerus <heikki.krogerus@linux.intel.com>

--=20
heikki

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/YrwB5xPKZmHlXzrC%40kuha.fi.intel.com.
