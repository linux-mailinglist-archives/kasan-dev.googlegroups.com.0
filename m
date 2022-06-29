Return-Path: <kasan-dev+bncBDUIPVEV74KRB56B6GKQMGQEFCS2HOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DBA156028D
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 16:26:00 +0200 (CEST)
Received: by mail-ej1-x63a.google.com with SMTP id hq41-20020a1709073f2900b00722e5ad076csf5103538ejc.20
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 07:26:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656512759; cv=pass;
        d=google.com; s=arc-20160816;
        b=EPT7ARmBPJS7da0U7rxzacS8Y9XugQT3kPorYaRs154f6HPh5zC5UAu7Ue7ayJmN9D
         Zc2yLyAKVMpeliq1fu58GemArduaU4osRAsxFSRbUiOxY58BbSYqphA8pYLAJOs6LOz9
         vc4jQqe4MHHpEjyRQmyuO+WDrXJNyR0wfMnK25InNIVDYHQzRzzUFN9u/9XE63+0nQnz
         ulbUruLRxyPq4t0516iMzDwJ8So+xAYC8pPEUmVxktR3VtQL26IffCp20PAa3DoZPuIq
         8ruyhOYmevCdcgUS6IeTUMVvw6f8igooLqUl7Fjpu6hgOoW0fScs382Cqt8Ad5FCEOE0
         iIqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:references:cc:to:content-language:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=7kgHq855BJwZTSNiyL8CPd3svhPhROro2UxLrcJJVQk=;
        b=ouFnAq/LnynoAnJxbkupLkQnaLgrBGVVhkexQLTq/WFjyYYCvm50rcERK26U7DvfHb
         FQrBByaZ1ujCqOYX8f9mUZruf0X6V/Gp0NGwzxqOs1QFDW8c4snU2EMIu8VXqnSsOgKG
         pz5HsYfKJbu9HAHU0C+TuPrf1Ej9WV5qOMfvS2qUYOoxh49rxRe1PPk8GaSNfc9d6wkv
         yQofWpuOSCPPkVFPiczrv9WWcJRB25C/I+CL3cFoCtyPicwz5ThAxbGkkNh00m5K5sdV
         FkFLeMqvcmAyRAytV+2P8p+VgcsAs9hEVcxOejqtDm7dYEr1ujk7DGM+Z2Q7pfJoqWVW
         GkFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="S2dVib/e";
       spf=pass (google.com: domain of luzmaximilian@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=luzmaximilian@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7kgHq855BJwZTSNiyL8CPd3svhPhROro2UxLrcJJVQk=;
        b=VjWu4eHQaO31tpBPRgJLkHFsOg8GgHBnLNo4vWbWVcjdnXhX/aDkmiDRS91gdOKuJG
         PK9zwaGGfAXo4qBLmkyqjeTe0oSJOgAiWJsK9IEvQUOIsMmHoIfoU7/zGYJleGgYUifA
         L13ALJ2ceKjVdbH7CjY7qMpiX7lXfAgowyd+T9xD9uC71NuZC8clPApoVa2iwm3Ryn59
         pEdVdg4rKbeUbAMIJSH0E4kwm9IbRDFkit8DGRsq5plmW7zkwp7nWVa578OV+6VR/h8z
         VLe16TouifJxNtMQVpjOEUqnaWKMY3KU9PMBcYPriLA3h2O84sWx7c4REsr8gYiT+lUe
         w2qg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=message-id:date:mime-version:user-agent:subject:content-language:to
         :cc:references:from:in-reply-to:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kgHq855BJwZTSNiyL8CPd3svhPhROro2UxLrcJJVQk=;
        b=ezqW2BP3zhBb1gL+e2YWtFmh+kgIX2mLeWNziBeFNzSV7G5PisW0FqPRVOWHnK8JgT
         cDqYDvHW6Xg0NmrFlHmQUVF69+Lg43UoE/8aDNqORFk3cV9CDM1Efzz0neGcY0L65hR7
         kcd8StHLlCSNUJULGdYvjReqWKmTooNdjhIKKoDYmxn1D4Jw86/bu8fbsM5KPbzHZSCZ
         kv+0eGOgAL3bq8PYcS4DrX8Z5CE51jBJv8iBZ3HJwAX/4Wtg0q9iOn2bmgtwjSDP3yS5
         R2q/Locf7T/FyADWEv9VbTxA+vGufoO2XbCK9sR330dWq/yqFIoO3NFposPf3uapWijs
         b/6w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7kgHq855BJwZTSNiyL8CPd3svhPhROro2UxLrcJJVQk=;
        b=NpiGBTYNPtJ7llntka34xhu4wBVt1tBE80k3wtoGnlB3HtnIBuOJbyJRXbvel35asU
         IzLfDSQ2PYnhV3R90JwdUFso83UaLuq4j6843tt7YlqmEMrV2AZ1k9cJwWhtRtgXMO1/
         YF01romZ2epG9awP5pYtcwMw556SpEm/PBC3f4R2p26VO8Yh+L0E6pNvcU7lwE4pLTAw
         7uN988GzDuFjqsy4o8Y1QlrL1MmZdn7jsi0VcRXwUSPJkd87JGLq36z5ES1ebAuU6pKs
         aPi8ocfHBqPRzpohoJ4QCL8vDzqWC72USfcPmyhnfhceJSlyUmj12ZRGbZBYYEdAagU5
         QFSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/W2PCfbvtn9G5Ak9pbeXQWk/ol1+uDolFUJhxIaCB3aX4gmG6W
	6Uyk8gXw3/tDxniNOGBqJHo=
X-Google-Smtp-Source: AGRyM1voaik0lQn4PnfW3G8qQ1eBgX1fZBq0hyZh99oewYZ/G86gbTUgT7xDc6kc2d0ZoYwijicp5g==
X-Received: by 2002:a17:907:7ba1:b0:726:4522:d368 with SMTP id ne33-20020a1709077ba100b007264522d368mr3701396ejc.662.1656512759632;
        Wed, 29 Jun 2022 07:25:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:4245:b0:435:dc4b:1bad with SMTP id
 g5-20020a056402424500b00435dc4b1badls597334edb.1.gmail; Wed, 29 Jun 2022
 07:25:58 -0700 (PDT)
X-Received: by 2002:a05:6402:5412:b0:435:5997:ccb5 with SMTP id ev18-20020a056402541200b004355997ccb5mr4499507edb.167.1656512758531;
        Wed, 29 Jun 2022 07:25:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656512758; cv=none;
        d=google.com; s=arc-20160816;
        b=dT1ZIjyJLtuJ8qFZXCRTNt/iFozx8Twz72f+OzfZCbfUD+AiEIEAEGarBMIHstBoyB
         0AN7T3heHdBX9sMn8ol/x9lT1gBdc3Fy5KWAZRwCsqOUEJUuL65cYfqADGPVmXA8CvC0
         dl4ZVskOR8FmBIEdahk9nltlafLzzvdMgpzT4YN/YuRLNI57GMXUFQwEBjyLnuBXWT+m
         F/uGXUV9o4+AL3/BjRSVZcoNFrwLB/d5fSXR5gszVvzyrhjG4BrX7PeBpeLNRsEtX8M+
         6nIDbgDeVuaUhV1rkQvuq1X+Q8jiyIEir6duAtNaYLmQOG+XST7eMiRZ7l2G0HWYjqO4
         bZlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=nzVAkjUIXnSmifmZO/KNuTW33GCGTCzsi9aX026XXeg=;
        b=VOqMwyJgslwixWOP8ss2yyajdE9/OF+CmOygFpwcacKiyv2BNEdg+MhhxztWgVpcAy
         MjTrS/MEXSkqDAxanJjUMiAL2qfdsDDrhD6YK3tfK542hnw71lXFR1KTdU4c4BRPmI1m
         jy4NT5XfkLMw8R3Y+BY7qTWvD0JCRtqHPt2BX2idBMLZbeEouQDpCr2J5qIAzAPUxu19
         fiXUdHUS2GMI0SWPpvzmV91CASD79eJBO1uHABMAnFLZNMAKOslKb42XxAvlAQTMWv5Z
         SkwS7+mucibtpVWcc8XjGdlP0akjuhaa8HHkZ+SsUWcbMW8Zuj/4xNUay1VoElzGzS40
         d7lA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b="S2dVib/e";
       spf=pass (google.com: domain of luzmaximilian@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) smtp.mailfrom=luzmaximilian@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62a.google.com (mail-ej1-x62a.google.com. [2a00:1450:4864:20::62a])
        by gmr-mx.google.com with ESMTPS id p11-20020a056402500b00b004359bd2b6c9si788469eda.3.2022.06.29.07.25.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Jun 2022 07:25:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of luzmaximilian@gmail.com designates 2a00:1450:4864:20::62a as permitted sender) client-ip=2a00:1450:4864:20::62a;
Received: by mail-ej1-x62a.google.com with SMTP id sb34so32873047ejc.11
        for <kasan-dev@googlegroups.com>; Wed, 29 Jun 2022 07:25:58 -0700 (PDT)
X-Received: by 2002:a17:906:58cf:b0:722:e4e1:c174 with SMTP id e15-20020a17090658cf00b00722e4e1c174mr3593366ejs.85.1656512758310;
        Wed, 29 Jun 2022 07:25:58 -0700 (PDT)
Received: from [10.29.0.16] ([37.120.217.82])
        by smtp.gmail.com with ESMTPSA id jy19-20020a170907763300b007263713cfe9sm7220580ejc.169.2022.06.29.07.25.55
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Jun 2022 07:25:57 -0700 (PDT)
Message-ID: <80117936-6869-19b2-45a6-96a4562c6cd2@gmail.com>
Date: Wed, 29 Jun 2022 16:25:54 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.10.0
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
Content-Language: en-US
To: =?UTF-8?Q?Uwe_Kleine-K=c3=b6nig?= <u.kleine-koenig@pengutronix.de>,
 Wolfram Sang <wsa@kernel.org>
Cc: =?UTF-8?Q?Uwe_Kleine-K=c3=b6nig?= <uwe@kleine-koenig.org>,
 Miguel Ojeda <ojeda@kernel.org>, Jarkko Sakkinen <jarkko@kernel.org>,
 Stephen Boyd <sboyd@kernel.org>, "David S. Miller" <davem@davemloft.net>,
 Jiri Kosina <jikos@kernel.org>,
 Benjamin Tissoires <benjamin.tissoires@redhat.com>,
 Luka Perkov <luka.perkov@sartura.hr>,
 Dmitry Torokhov <dmitry.torokhov@gmail.com>,
 Bastien Nocera <hadess@hadess.net>, Hans de Goede <hdegoede@redhat.com>,
 Mauro Carvalho Chehab <mchehab@kernel.org>, Shawn Tu <shawnx.tu@intel.com>,
 Manivannan Sadhasivam <mani@kernel.org>,
 Pengutronix Kernel Team <kernel@pengutronix.de>,
 Kyungmin Park <kyungmin.park@samsung.com>, Andy Shevchenko
 <andy@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
 Jakub Kicinski <kuba@kernel.org>, Rob Herring <robh+dt@kernel.org>,
 Mark Gross <markgross@kernel.org>, =?UTF-8?Q?Pali_Roh=c3=a1r?=
 <pali@kernel.org>, Mark Brown <broonie@kernel.org>,
 Nathan Chancellor <nathan@kernel.org>,
 Bjorn Andersson <bjorn.andersson@linaro.org>, linux-i2c@vger.kernel.org,
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
References: <20220628140313.74984-1-u.kleine-koenig@pengutronix.de>
 <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
From: Maximilian Luz <luzmaximilian@gmail.com>
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: luzmaximilian@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b="S2dVib/e";       spf=pass
 (google.com: domain of luzmaximilian@gmail.com designates 2a00:1450:4864:20::62a
 as permitted sender) smtp.mailfrom=luzmaximilian@gmail.com;       dmarc=pass
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

On 6/28/22 16:03, Uwe Kleine-K=C3=B6nig wrote:
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

[...]
>   drivers/platform/surface/surface3_power.c                 | 4 +---

[...]

> diff --git a/drivers/platform/surface/surface3_power.c b/drivers/platform=
/surface/surface3_power.c
> index 444ec81ba02d..3b20dddeb815 100644
> --- a/drivers/platform/surface/surface3_power.c
> +++ b/drivers/platform/surface/surface3_power.c
> @@ -554,7 +554,7 @@ static int mshw0011_probe(struct i2c_client *client)
>   	return error;
>   }
>  =20
> -static int mshw0011_remove(struct i2c_client *client)
> +static void mshw0011_remove(struct i2c_client *client)
>   {
>   	struct mshw0011_data *cdata =3D i2c_get_clientdata(client);
>  =20
> @@ -564,8 +564,6 @@ static int mshw0011_remove(struct i2c_client *client)
>   		kthread_stop(cdata->poll_task);
>  =20
>   	i2c_unregister_device(cdata->bat0);
> -
> -	return 0;
>   }
>  =20
>   static const struct acpi_device_id mshw0011_acpi_match[] =3D {

For the quoted above:

Reviewed-by: Maximilian Luz <luzmaximilian@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/80117936-6869-19b2-45a6-96a4562c6cd2%40gmail.com.
