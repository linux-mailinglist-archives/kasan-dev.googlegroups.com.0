Return-Path: <kasan-dev+bncBDW2JDUY5AORBRVOWLCAMGQE5UNAAJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B6FEB18020
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Aug 2025 12:30:33 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id 2adb3069b0e04-55b6fe3ea4bsf899736e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Aug 2025 03:30:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754044232; cv=pass;
        d=google.com; s=arc-20240605;
        b=cY0lBcsxvS1T/60o2BEsVLoz71zq4dQMLwNLiAoMfF4mNjF5B5zVmRzBSpJ5jtoncP
         faGsMy7IDgI3ePCTMCpFOu0NQ7O6HuKIyQvE5IGojTADUoqaKoT7cguENM/AFmWXTIOL
         U8GxPFkZAdMw7bU+uS+YHiPEAlinj/06XNOQBqhzB3lXhE7pqEn2ofhzwlB0qsQ/H5yR
         C8hpeu39XSR/YpxSVVcJ5aXjqMUd0+gZVu17qnv7rrwvCnq4jK/jHttPGIOvvLSVDOjn
         L6kEmLeULd5wFUIbXYJC4zqbUkCkDJTLYoGdDTeKa9w7HfP6kk5Xo27NaD4ylhlbbBgK
         R4hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=to3rERJsG9BcvyU2C/uWtTkJH0gTvbtSvXv3ANpq0ck=;
        fh=Es0ZHP4a474giHPWigceD5u54U31WQkmsCx7FhxwdBY=;
        b=O9foRA9Z9/EdWGmiBT3CGfSa/3iNJ9SirHtggSE48dYg0e1NoYULB4KxSeZuNg650b
         Lt9n072hJhPRplQVbg92wfxH1NJaB27PKB3iUg6sGoHwnLzzdwNj0MF9eoPDqCeEN/tP
         uPCdyinPbz1O6LMxfbF/KsBpFeS/9v0+FQBD2GVsdhj86BXUqIaJLovql8GgoF2SIInW
         N3KrljftbN/BWDooMmruBlO5O01y8Yoi3a7U5tm28XPes+WCZ5mH47tUO3FmrHbIxFn7
         nPyK8JXesMfcHTO5ztAO+iM+vfrIH4AcjVzMmeIXJGN//Y2DHlA5w+WLQWJg4fgClKO9
         bpQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Qzo/6ouC";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754044232; x=1754649032; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=to3rERJsG9BcvyU2C/uWtTkJH0gTvbtSvXv3ANpq0ck=;
        b=fKk8T5EV67nXAiL+vgTp3viYd7yOdcmYOMYav2ZfCXrvlAI3VhbL8FHybkOvarJkaC
         HtrFnAebaZ27hLsc3ad5sYDdG9X9b5+6tcq0B8sh0lJPLzcqQN+FbitdJASPdpqZdGrn
         XhWIXDrHRlF8zP+eDShpraaTRuDCtGzCC1L7839Rc7ZkGf/I1OP5Ni1UmeWlYkjmZB5/
         uNUk7FWJhdjPscKsM8066w13wweuz3jvOFCucDPlOmCQ4yXH/soTNQGrGtcZwKbdzDQz
         K4oolzYdmH6+02Q5awDKUrZM+HYd2QWEutpN4aMI4vP0RutRT/qqD9hPZT7eWSZBMbSV
         ow/Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754044232; x=1754649032; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=to3rERJsG9BcvyU2C/uWtTkJH0gTvbtSvXv3ANpq0ck=;
        b=C0QkYTuWiWJ9thuyesJSArYTwYc2VgxvEVfelSwGcP8luQi82f3yl4w6d60/SW+syW
         k0tPCgZkws5KTffMHi+Qwp0gPkjIAaQjKbZpiR0CdOaxwTrAv6lBydEznm4HjpXdvQhr
         ObpiLPEXVNGlXhFo2sy88mhYn6w+YU2Gj+WVtYjPcFWzcuEn/Dny6XaJMyOr0dpsESO2
         hDt8XWMW97z65p52H3yeTVte0YWn1ZRC7lNxMc8FNzzXeDWDEMxIokFvnEvx/1Cvkp1y
         Ad0kVACgH8yxvC+muU1baDM0EbbRuixyvz6IGFeguGXor0PPfLsPYc3sgjrErHr0lmmj
         RBtQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754044232; x=1754649032;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=to3rERJsG9BcvyU2C/uWtTkJH0gTvbtSvXv3ANpq0ck=;
        b=gb4KxxI1xTQEHW5K+pHfkII9NuvlV2CUX5m37S2++qf8oy+c8ix0esq4cn67YuR3bk
         fUByrx3mZLe3VdVEJKRw/UeYkqFOeJyv8Uhn+5diNhDWwawEu8ye77TEsmOz7H7Mm6MF
         OFnO8brwlf+4yhvgDVukbQiXmLPEm00wI57Cw6GPJf56xSp3FDtQb9XxRhiClM11nhRA
         zWEeD2AbdynqnJSkiNFwD17u7xX0us3OKeMnCJFjrPvHcl1SYnUNTPCk76gkAgeNmMyI
         XuF469P8k8cwsS7ArfGkGyJBzxH34kvS0trDZ3HMEDtSXUIMvXa9S2GX3phpm8fx/aLo
         WWZA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXiOAbPNyHqHw4LKOCGwG25qkj94XqTdyNYq1NCecexkA70EqKK+3maLSWot0g5sKTsCZUFIQ==@lfdr.de
X-Gm-Message-State: AOJu0YziwJT5hgrEhHv6MRh7Q+BPCH4cZlKgrf+kLfH30djJXG1iQfdI
	LNrUKKIbZEfJnmfse4ZCGcU755OFgm8toidr+ciJadxDWMipJmXB74Qo
X-Google-Smtp-Source: AGHT+IECxa/KfeF7dCMgoc0HruAcH3KDtcjW0HhJ3J0v8SrtToQjNVu7tIVf3qUkLhEFxVZaZ8IRmg==
X-Received: by 2002:a05:6512:1106:b0:553:ab9a:c94 with SMTP id 2adb3069b0e04-55b7bffc383mr3522804e87.6.1754044231745;
        Fri, 01 Aug 2025 03:30:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc+6Xl3sqvCLsVcsyw+dCyhIhRMdb0otEg9QdmyMO26xA==
Received: by 2002:a05:6512:6719:b0:553:66c0:cc33 with SMTP id
 2adb3069b0e04-55b87adbc43ls420768e87.1.-pod-prod-01-eu; Fri, 01 Aug 2025
 03:30:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX1n9+PXjbLqp/Xm6N61Hbrjjzw9DZwWUfYXG/9R0cqu3tv0zJ2KI6Mrh989Rg3ykTxJdDkF1acDo4=@googlegroups.com
X-Received: by 2002:a05:6512:3d22:b0:55b:8f9d:f78c with SMTP id 2adb3069b0e04-55b8f9e4368mr756945e87.44.1754044228111;
        Fri, 01 Aug 2025 03:30:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754044228; cv=none;
        d=google.com; s=arc-20240605;
        b=eAnvcN9J0iOFN/DQRgYvWmFiI9bNtOzdq/qmtW/oknDv7WTWF9YxJhk6sSK6l5F8/I
         rbSh7X46qQUvpk9sWiUysndy99VIdQe3zEkVd28ge0n3oUHhFPoYAiHedo5nU00u4G/L
         DF6MZjZm4Bp6mMmpSY9gg5Ux5IT9j4FSO+gpltZu5EYX7en4n6+S7cqqL/e3xkj3niBG
         NXGNu+Xa2otBq5x69iHMI5o/eMAr4GijUklc0B0B/2Zs8VGPEcqyv3cLpZvcGHAALX7b
         r4TaSfcMp+015Rj8wF9z+BXfuboSK4jICkC//NJB4pn88U/b+TgimddzBVsmLWqJZLov
         T4Tg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2R+MqrgO5Yl0URvHmsHiXNr06EO/8hBJAf8Kunyd3Fk=;
        fh=FFx3LbxOSijcP4+D5+/QDNxTYV9TtYsaibD24fl5XAs=;
        b=SBMewx0Dstv+nTB1BFTkC7nMSjMFUruXdUFcAzLHeJhbSTH9I1XU+mme/ELaAIHGQ1
         TrlllHB9b/wxTZPNujSW6Vo3fdmunOUtaIg2sZrKkQoZ3q4xTyEioPdQJPV3eKQAoGhV
         QM9/54OgaMmfseks43nQAldKnJn3IrnzbwSTvnGwAZ0YI/6M6rdsM2IEyGe4xHaMvJ+X
         oXHe0ppM5Dt+sgZ29HflQ8ORpGvu+xKm3SmS+4jyyURcTBYh/T7B3201QyynRuXW1bAh
         7ieyd2f3vZCR/6tEvXlUnGI5T5h22CssRv7GQjIkFLxcOSfd1krO8bpIR3P18PDY7BAM
         IZKw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Qzo/6ouC";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55b88970321si110484e87.8.2025.08.01.03.30.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Aug 2025 03:30:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id ffacd0b85a97d-3b78310b296so1191382f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 01 Aug 2025 03:30:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWkDuJ6WRL/tSZVbHQYNTx40qrdVRAI4q7o74TheTlX9nGcPMekaU1odwU6gJFUcpcqtlx7x4TkzpM=@googlegroups.com
X-Gm-Gg: ASbGncv24Filv8MeYrRWNcgsUdTvTKJCPn9elugdW24RJC/u65IbaAS8+XHoqkSXerE
	uz2MoqOCLR/XlJQrcvqDzeqeX/l2Ei2Eh1aIhn3jK06fErujcOYducWPdvPLktXEGe/zWeN/Mrp
	8FrE4dWwSxs2IrLEy4XOX9E6Gs2AKpLHZpIVwOzVZ66UoGwkyGcJ54b8U6JxMUtXrw46zTzt77h
	3hgmOO4Eg==
X-Received: by 2002:a05:6000:3101:b0:3a4:cfbf:51a0 with SMTP id
 ffacd0b85a97d-3b794fed8bfmr8236846f8f.21.1754044227142; Fri, 01 Aug 2025
 03:30:27 -0700 (PDT)
MIME-Version: 1.0
References: <20250801092805.2602490-1-yeoreum.yun@arm.com>
In-Reply-To: <20250801092805.2602490-1-yeoreum.yun@arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 1 Aug 2025 12:30:15 +0200
X-Gm-Features: Ac12FXwpbti9uxZkALv_-SQcxyY8JUp4abK1P5ZF80uVJbXi5SM7UT7UOWr81Jc
Message-ID: <CA+fCnZdiwXXYmW9a0WVOm3dRGmNBT6J5Xjs8uvRtp7zdTBKPLA@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: disable kasan_strings() kunit test when
 CONFIG_FORTIFY_SOURCE enabled
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: thomas.weissschuh@linutronix.de, ryabinin.a.a@gmail.com, glider@google.com, 
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Qzo/6ouC";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::432
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Aug 1, 2025 at 11:28=E2=80=AFAM Yeoreum Yun <yeoreum.yun@arm.com> w=
rote:
>
> When CONFIG_FORTIFY_SOURCE is enabled, invalid access from source
> triggers __fortify_panic() which kills running task.
>
> This makes failured of kasan_strings() kunit testcase since the
> kunit-try-cacth kthread running kasan_string() dies before checking the
> fault.
>
> To address this, add define for __NO_FORTIFY for kasan kunit test.
>
> Signed-off-by: Yeoreum Yun <yeoreum.yun@arm.com>
> ---
>  mm/kasan/Makefile | 4 ++++
>  1 file changed, 4 insertions(+)
>
> diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
> index dd93ae8a6beb..b70d76c167ca 100644
> --- a/mm/kasan/Makefile
> +++ b/mm/kasan/Makefile
> @@ -44,6 +44,10 @@ ifndef CONFIG_CC_HAS_KASAN_MEMINTRINSIC_PREFIX
>  CFLAGS_KASAN_TEST +=3D -fno-builtin
>  endif
>
> +ifdef CONFIG_FORTIFY_SOURCE
> +CFLAGS_KASAN_TEST +=3D -D__NO_FORTIFY
> +endif

We should be able to use OPTIMIZER_HIDE_VAR() to deal with this
instead; see commits b2325bf860fa and 09c6304e38e4.

> +
>  CFLAGS_REMOVE_kasan_test_c.o +=3D $(call cc-option, -Wvla-larger-than=3D=
1)
>  CFLAGS_kasan_test_c.o :=3D $(CFLAGS_KASAN_TEST)
>  RUSTFLAGS_kasan_test_rust.o :=3D $(RUSTFLAGS_KASAN)
> --
> LEVI:{C3F47F37-75D8-414A-A8BA-3980EC8A46D7}
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZdiwXXYmW9a0WVOm3dRGmNBT6J5Xjs8uvRtp7zdTBKPLA%40mail.gmail.com.
