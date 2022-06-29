Return-Path: <kasan-dev+bncBCVJF6GBUAARBHME6OKQMGQEU2AF5EQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C9FA1560B92
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 23:20:30 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id e8-20020ac24e08000000b0047fad5770d2sf8223860lfr.17
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Jun 2022 14:20:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656537630; cv=pass;
        d=google.com; s=arc-20160816;
        b=Igj7xsG2L1z8bH8VsEK9fgyVeFLx/iP63zY79GnV8wTXxpUPIT1qXgZNeu+T/yOuBy
         p7IZ+hTr2LKVGqW3oARS2MhGv91iGNGQF3fQF6u2VmS8TXsn1t7QTvXvawUkjQQP2bUv
         FbYIIhgCFTRG8Q7PYC4VIzrtFth00HW8pPpHnD41/I/xm2prFm+R2KtI5af3HfaWUEJO
         JwhYPHm77imcPHW5yWJsODRCrPW6iYWW0cSTfcI9Rr5kFz1aclaw8WKs36dCwdQ7yfNU
         Irpe6esa1mLKy1TEOK7CgwTdibVHCzMSwVTM3w1aMg/3Sexf0ZWmIe+e/fDTWmfEFGmh
         6K2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-language:references:cc:to:subject:from
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=WApYBOhm65lASQnQJ15e81V0oYa6W0dhm/BtIiF1Ujg=;
        b=Wd2r8KGt+rMx2adJiWtParTjxoJXwr2Vyacz1XU9v1Yn070m9kF4mFZBsQf4JXK57f
         IOUJzXGr/eBO0SUe/UDY6flP721Iyu2XJEMP/S1X+QIiim2pxm24msbXnNMUkEyFVFeV
         OpQJNLG0cB6+taSIJulbvjs49t+i3kEKv1ArkTLJ2xYbL6LP1wfnIUpYoNP6Nk9UcWgu
         6V2Vtrw9rztnTam6UA9Vs3oD35AuM9XjLJsebA5ee2wE2xkBhVXIWdqhuI8EBLZBDRcv
         hhLlvum5arnB/uUQ2UqbfNkgILeMNPPNpEnCCPk6KBp8yldWyveHt6K4YvDb0B+J2Obl
         zmRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of luca@lucaceresoli.net designates 89.40.174.40 as permitted sender) smtp.mailfrom=luca@lucaceresoli.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:from:subject:to:cc
         :references:content-language:in-reply-to:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WApYBOhm65lASQnQJ15e81V0oYa6W0dhm/BtIiF1Ujg=;
        b=WuPp8j1T68wnEiL2mL4QtPTRPYXHCVdDXLscgYqXCdZv5/sVSqC+/ThXzA/0TRP8Dv
         EeFPI9rSdTeQqHbtHFL3s3pze1bWsRiZzth35TDF2j18F6cHAxSBFSUqU3TZaox1KKuj
         t9LAasswo3YGNQ8iqVqggtbdh6M3KGa82PkR7IhzGHG/nKTRv1XbGxR8/TT/otyNR7AR
         VI3gKUKIGEScpQOSGWU0XqhRC0SWQ3cuxwxN5fhyJrNcHaLRusyvL8nnsmRJaEnNtpks
         F494VndGRwM/xK/aGrXgd5X9FYy1yiwgo36Pf+X7YQJmnFucap3PJYPA/z3WjFebkTCX
         L/FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :from:subject:to:cc:references:content-language:in-reply-to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WApYBOhm65lASQnQJ15e81V0oYa6W0dhm/BtIiF1Ujg=;
        b=sMgR2n7kEdtF6n2LQjhQKv/ii+YUEVxHV/nLiRrWo2VsfDjBe3o4hBJw/65PzJ4acw
         OQUoM5a6YLCPlUeaAjXj4w2nE4VXSJNY5sJk1Dynu/jOx4BboF5UOOI7PzrSusoX21Q9
         GwnVec7/k+mgPVktCf5emtOp/o6wFdM96Xr6leG4fx2FR2Zl5HHbI4dsMILnvte9r8Qy
         p2YZpKf9YY8hOVAauMjfv/JjUJXmV3CMXJhWj3IUWP2hov+MKvbZajXlT9ReW3rpLRD/
         ybTgLN46B/1rUyneWnf6KFoNDBhUylEUSa4+/tk/hfybl22zLkPqKpuMR8uDvRbCxmw9
         Tdsg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9K3gbyx/jd5NPzl+M7tDldAMBn0gkjTUibWnNgi+0eUoi0evKV
	co/Iq1UwNo6C3KETB95Hb7k=
X-Google-Smtp-Source: AGRyM1v4yfTu5fzqVO5qA9WxjYmLAtDiHAVRgQtiEmz8dY4XkPjX1V/hmhaL4pn+JnEnXHnyptGikA==
X-Received: by 2002:a2e:a793:0:b0:25a:74f4:b377 with SMTP id c19-20020a2ea793000000b0025a74f4b377mr3057755ljf.177.1656537629852;
        Wed, 29 Jun 2022 14:20:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b0c:b0:47f:9907:2b50 with SMTP id
 f12-20020a0565123b0c00b0047f99072b50ls318827lfv.3.gmail; Wed, 29 Jun 2022
 14:20:28 -0700 (PDT)
X-Received: by 2002:a05:6512:31d1:b0:47f:5d39:1d9d with SMTP id j17-20020a05651231d100b0047f5d391d9dmr3405937lfe.140.1656537628351;
        Wed, 29 Jun 2022 14:20:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656537628; cv=none;
        d=google.com; s=arc-20160816;
        b=vnvDGf1W3qBk9Nv3XN4+aRWYJWRT+ySbFQzYKsVmrCOR2iG7UDGS3U2EcL5+NPUA+c
         XK//oMHME7IdsJCFrTaETRCGSxt9dduGX8MXXQ6Jpng728sRiUrRyHBGVrGbD1bbb3iD
         rGMwXYuyezMoGDpN9cryHefjrzno9w3yU/q3Dkdm28SACTVlwLwd+Cn+0K0YeXCvJK66
         k0F9Ks1VlJrz9LCH7U2eLUO5cf7YDlIagK11BaOuu/tfZXvfqIfmsJnrsmro2LWVgKaf
         GSN1qPcHD2Jgij22wI9+XS/hDpV5LK+dt4RG/vFExierRUloKSBt2NWs4+mzt0e2UtRM
         KBLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:subject:from:user-agent:mime-version:date:message-id;
        bh=oz6GKw8BpKrDIGgvnV9242qGIiYTvSr9/fjEazC9jI8=;
        b=lwCGMOYggEiYJsqX1UrAbU035xzNOKOM98Yy1bPAqZnUQiauHG5/8rW7PCZKat0f7a
         HAR9ocHS5BeGwKizUYhNRv75uXS7fQqAlt6hYWx96rcifdaWrJ6pc50YLoThZrmCvkC4
         vfoMMhkZhmhQV1tb4yVIkqa7p+DbW+NMjISIhkbWOiu8x2KclQpeaoZ6MbhLjahVuSyL
         2cSdpcFXARsU/B2pcZ8EtgkeK2YT9ozgAIYYWFAEQdXrOwTWVsXBejDSMdOZgGOzbqye
         TKtIg0A/BkTLErib/bpeIcUngBZM6+plvhhcmrOvN9kw69/qsxVy/82DQM63jYhv892s
         RVkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of luca@lucaceresoli.net designates 89.40.174.40 as permitted sender) smtp.mailfrom=luca@lucaceresoli.net
Received: from hostingweb31-40.netsons.net (hostingweb31-40.netsons.net. [89.40.174.40])
        by gmr-mx.google.com with ESMTPS id o9-20020ac25e29000000b0047f8e0add59si827070lfg.10.2022.06.29.14.20.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 Jun 2022 14:20:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of luca@lucaceresoli.net designates 89.40.174.40 as permitted sender) client-ip=89.40.174.40;
Received: from [37.161.29.0] (port=43545 helo=[192.168.131.30])
	by hostingweb31.netsons.net with esmtpsa  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.95)
	(envelope-from <luca@lucaceresoli.net>)
	id 1o6f6m-000BzC-Qd;
	Wed, 29 Jun 2022 23:20:25 +0200
Message-ID: <d682fb60-c254-f89e-5d6d-cdf7aa752939@lucaceresoli.net>
Date: Wed, 29 Jun 2022 23:20:04 +0200
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.9.1
From: Luca Ceresoli <luca@lucaceresoli.net>
Subject: Re: [PATCH 6/6] i2c: Make remove callback return void
To: =?UTF-8?Q?Uwe_Kleine-K=c3=b6nig?= <u.kleine-koenig@pengutronix.de>,
 Wolfram Sang <wsa@kernel.org>
Cc: linux-i2c@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
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
Content-Language: en-US
In-Reply-To: <20220628140313.74984-7-u.kleine-koenig@pengutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-AntiAbuse: This header was added to track abuse, please include it with any abuse report
X-AntiAbuse: Primary Hostname - hostingweb31.netsons.net
X-AntiAbuse: Original Domain - googlegroups.com
X-AntiAbuse: Originator/Caller UID/GID - [47 12] / [47 12]
X-AntiAbuse: Sender Address Domain - lucaceresoli.net
X-Get-Message-Sender-Via: hostingweb31.netsons.net: authenticated_id: luca@lucaceresoli.net
X-Authenticated-Sender: hostingweb31.netsons.net: luca@lucaceresoli.net
X-Source: 
X-Source-Args: 
X-Source-Dir: 
X-Original-Sender: luca@lucaceresoli.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of luca@lucaceresoli.net designates 89.40.174.40 as
 permitted sender) smtp.mailfrom=luca@lucaceresoli.net
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

Hi,

[keeping only individuals and lists in Cc to avoid bounces]

On 28/06/22 16:03, Uwe Kleine-K=C3=B6nig wrote:
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

For versaclock:

> diff --git a/drivers/clk/clk-versaclock5.c b/drivers/clk/clk-versaclock5.=
c
> index e7be3e54b9be..657493ecce4c 100644
> --- a/drivers/clk/clk-versaclock5.c
> +++ b/drivers/clk/clk-versaclock5.c
> @@ -1138,7 +1138,7 @@ static int vc5_probe(struct i2c_client *client)
>  	return ret;
>  }
> =20
> -static int vc5_remove(struct i2c_client *client)
> +static void vc5_remove(struct i2c_client *client)
>  {
>  	struct vc5_driver_data *vc5 =3D i2c_get_clientdata(client);
> =20
> @@ -1146,8 +1146,6 @@ static int vc5_remove(struct i2c_client *client)
> =20
>  	if (vc5->chip_info->flags & VC5_HAS_INTERNAL_XTAL)
>  		clk_unregister_fixed_rate(vc5->pin_xin);
> -
> -	return 0;
>  }
> =20
>  static int __maybe_unused vc5_suspend(struct device *dev)

Reviewed-by: Luca Ceresoli <luca@lucaceresoli.net>
Reviewed-by: Luca Ceresoli <luca.ceresoli@bootlin.com>

--=20
Luca

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d682fb60-c254-f89e-5d6d-cdf7aa752939%40lucaceresoli.net.
