Return-Path: <kasan-dev+bncBCT4VV5O2QKBB4GPVSXAMGQEXDMQQYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 677D4852B17
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 09:27:29 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2d0a4fbc9e4sf37519051fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 00:27:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707812848; cv=pass;
        d=google.com; s=arc-20160816;
        b=R9hkbA8G8JoUVdi7Ze474P98iqYffKLdIMV9GziLm5LOQi52U1GHJ07YhBNF7CN452
         PsJlQRJCuEBmXTkswBlU2H2EUpxfD20qwnHWIceLLltXM0tRwap1blmWItn+CVSFkbTw
         vUCB2dn/3PO2eC3KSvCzFCG625Zgc8RZkl08x+lpjDfYDTJRJ3+kehIT1bQA7b2sRBK7
         +q4/qLz3BkpYGzshs4TqjiDI0iTW9lgisesZl3KHsYHEgXkLTLIZqQ5xEmvn7g5HviT+
         I73tYJ4opR5arGFQMrQwNS6HSQqUvF3ytjL58K+qGsk+gzbuIf8VBF1Rgd2L7ephiT3o
         z54w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=CEQFsmP7C/g9nPl44pICTDOCXYawTMu5L9I/uq3x2DY=;
        fh=VVpJU8WZsA0BOgNa6Q3Fw3RX+fMc/dWWmUddCyn/Tl0=;
        b=eWQx/CkNT7xHjOv060eHccrfziVsrYkVSY3iYKNqLjczG0/sTgeUSIz7uu8fjnMTbB
         G+sQL9cM18BkzHDJvTzw1KbYcWmPNuVs7dONQnEJYyjsbnrNGX3JjAV3x7YlciRr82xL
         qR/ZLFb4M85+eklQA2Y04Ebkq/8HD1JnJiZbOIDlFNwFnRq1vnGLaZfqOA+6JwiGzNSc
         nj1NyQlDhBMqcBf5I2KIsJi7LGjxo7FoOavG/iNw+j6nMSNP2Orsdm8mjYfyBC4J4J+w
         kxpBUCYizNf+F8X3VVxE8BGS+Bk1prwI2Hhmn0//XtoKtvTpQXWMQX+tTGO/MWUtqf9R
         Gt+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="FG/++D3d";
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707812848; x=1708417648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=CEQFsmP7C/g9nPl44pICTDOCXYawTMu5L9I/uq3x2DY=;
        b=SWl82HMlJ6BgjdTxqkp1tfBFVWoc1Lvr42C+gzaouaXH7egLm+uRI2bYHbVVypf7WV
         INuGlHoQVg8c5oZYgDnBG8u9lEV5At1ytObVWzFf4FrLlDWvvREvbLYM4Ufzu6nvpiVK
         sVTrBNvPmfJRtAnDgBd9xsdA6wCPMr7Pp8PIo1yPGyyJNPLRJk9QU5oKvnuzjRFw6ppl
         i/i4u8Ew6jl0+hMJNYZdt/SWg4iLUaL9UV9A2M8ONMi8zyzTYRildYsr1rKfQpixVTxz
         bit0GTMN+OcSCJj60FGTr7g7hGLKpUINDOVVIQcgfz5g0NwUhmsfFogGbP2oWmiYLCgZ
         eMyQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707812848; x=1708417648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CEQFsmP7C/g9nPl44pICTDOCXYawTMu5L9I/uq3x2DY=;
        b=kuPmhDuPhomvsGrM/s0bvOOGSjAap3NRlKXDvDwB6gJqiTYXgivoe1gqJhpW/h+jRA
         0Qx6pizuIZag/53yYjp3PaRyGFRbwxUtiTBxeviOUx3c3PdJ505AdTk41+eicLs96+Jb
         mZ4a8L8sJ1c/JKIHHpuoLtn8tqRm162fbR1MCJwL2Mb23oMeejOsqPJS3jHJDyxPD+cR
         Dp711qy8OyhYmNrUOEWPokgODyc/tH6QsmMuQJtD/T3ijebTRgZwQhewjhXT/rpGSrn5
         2dRZwuiGVYTPQgA20OBaBQuBSiHVUP5vzciNM2oPhyFKa7Ydi4rWtRSk3KoFrBdrgKnj
         X1Gw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707812848; x=1708417648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=CEQFsmP7C/g9nPl44pICTDOCXYawTMu5L9I/uq3x2DY=;
        b=ooiN0zAhMRJQPcm54ikO6PJHeRm9QhEvrRpQ+TmVduaaO08w9DOmLJhd9Cb1ZYbask
         JfCjs+ppXuLe/NftlSJczIU9Rt9P9u52LQD7SRFcXzfIzyHPv9dzqPRXZU5JvsW/tdKn
         1wv7ZPIUuXdyz91iY2Xgp41APrg4UQ4AOHAeOtP8jaMf6b5lO7At3CiZnn9GuLhPM2iv
         NKJh4y5JzyEisdE9fDG4+Z16k8XL+O6MIFow3pTcW00tvg83MqGR4o8YI8zl6Rs/jykE
         GB5BEDwakuvdQj3icM6KRkNaKfg19ju2pJy46ZUkaOuDBC23yHPRLFBfUwYWilX82NgK
         1pew==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2dBpioWUKnq12DufYSarqFq79O26OjIFIg8x5B+4aBu7rSt4lpVMxH3HciEa+qv/3rNjOJsA3X7ENgsJ37glhHvmmJmlSQg==
X-Gm-Message-State: AOJu0Yw+ouVtUgQBHwD0H9O5ADchJM96h6s1HtY85NxdS2Par7iv2u0e
	Q8fm47Dg2bJ1qPYnztsc3zVaIid44ujOnWwnnmFCMXJs6YxeW7z5
X-Google-Smtp-Source: AGHT+IE+CyufQZwkOofgIlKiuxaIsI9XLaxqvwOfvLVAk99L5T4mbn+7sLk+Zs6ff1D+8NPAO5rJBg==
X-Received: by 2002:a2e:9090:0:b0:2d0:9a29:f849 with SMTP id l16-20020a2e9090000000b002d09a29f849mr5561589ljg.29.1707812848318;
        Tue, 13 Feb 2024 00:27:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a497:0:b0:2d0:a7cd:36ff with SMTP id h23-20020a2ea497000000b002d0a7cd36ffls835111lji.2.-pod-prod-06-eu;
 Tue, 13 Feb 2024 00:27:26 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWS+i/iTRsWPBmIRQ6hCMMZWZLuk9ktxTW4IPyoJQC4/UByagcn41zsAPFnwrCDPcQ3GUrgwmoYc2DnPt7EXET7Jj8IjOe5cfrdtw==
X-Received: by 2002:a2e:804f:0:b0:2d0:99e5:84b with SMTP id p15-20020a2e804f000000b002d099e5084bmr5537585ljg.9.1707812846218;
        Tue, 13 Feb 2024 00:27:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707812846; cv=none;
        d=google.com; s=arc-20160816;
        b=LK55dKeDgaWtnAVCvuvbc5G7v7JL+MqMfcQf7r3+BVlIbLL02uyy6A66gDtp6pdVKY
         T7UQbrIOgaSo4WB9eZIZPv+DpsJwnS/adsMSKgrxrJfw1sj303SkVnq9oK6i2EuhoE/s
         fYKw9+jjMNdwvTLPHaFbms3s0fROlWTD6KLjK95TDYi2vSJNFJD7x10hWhQG3Dn+HEnx
         KB8Z3KiT8C2vxlz/n+dh4+Z+Jxxv81ob1fjfT/Ozg8tCsVrQTpKk39lg6Sn429uEqZ1B
         2mDKWReveXC30D+9hzpJZ6YLMwG+KezeN4bquLqwPTQa/4+5snSt61FlbQiiV1/Jd2TI
         ViEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=iNGA8ZHGAdrm/kUeu0sTwlf3VcWW6Pp9gwsOjSJOS+s=;
        fh=tW/S6EFtaf3CQOcmDZ4an0+RWJOVHncXZhdK0e8wub0=;
        b=kTxBvXNIsnKHP55vfDafWRqNUuqaP2nHK1M3IHOPWLUI5IL4MQCxsld9XsnDCta06l
         +1Z7SAk5aozjnmop4VVLgLzLRb6oVdmcnsc4Qm0N2rkBTvzzE1lnoM/uc9v+yfERNFRH
         qDbZpXUeuYJmTTfp92mkizflwx4zZAR3P3bL+o9D91nnOdF2xbIGqwmp3l1GV//R/liU
         e2RwNCJgpezVAraMXUocIOxq4yUKtawiufFcYc9YM/yc2EXsJFFbz0p1B5jsn4P+6nOX
         LTbA+2dg/fz1praXPup0vOs6FtkCIPJ5YY1SJQx/aTYeV7BqOJbPqqP0lfyxpgPneauM
         lZAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="FG/++D3d";
       spf=pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=1; AJvYcCX0qc79NJmndBTTXBjDjiTH20TP2o7/eVtRFoKS7Zczvm7nyvWNT/YQtCRlVHeOBnBchenIABwt3PBBrGBQKJhlV0bHSjZ4UivVhw==
Received: from mail-ej1-x630.google.com (mail-ej1-x630.google.com. [2a00:1450:4864:20::630])
        by gmr-mx.google.com with ESMTPS id r18-20020a2e9952000000b002d0cff10145si156040ljj.6.2024.02.13.00.27.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 00:27:26 -0800 (PST)
Received-SPF: pass (google.com: domain of andy.shevchenko@gmail.com designates 2a00:1450:4864:20::630 as permitted sender) client-ip=2a00:1450:4864:20::630;
Received: by mail-ej1-x630.google.com with SMTP id a640c23a62f3a-a3c309236c1so340115066b.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 00:27:26 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVtsTfwSHDt2c6DsLZ3ivVbfcbFJu8mogo02Cs9W+JmFcETTddn/uMyyV9usfFD7PNfK0+63Yji8vhKsIXoJMDdMeaGOtkbdaVX2Q==
X-Received: by 2002:a17:906:ceca:b0:a38:3db5:a846 with SMTP id
 si10-20020a170906ceca00b00a383db5a846mr5777021ejb.67.1707812845309; Tue, 13
 Feb 2024 00:27:25 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-2-surenb@google.com>
In-Reply-To: <20240212213922.783301-2-surenb@google.com>
From: Andy Shevchenko <andy.shevchenko@gmail.com>
Date: Tue, 13 Feb 2024 10:26:48 +0200
Message-ID: <CAHp75Vek3DEYLHnpUDBo_bYSd-ksN_66=LQ5s0Z+EhnNvhybpw@mail.gmail.com>
Subject: Re: [PATCH v3 01/35] lib/string_helpers: Add flags param to string_get_size()
To: Suren Baghdasaryan <surenb@google.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org, Andy Shevchenko <andy@kernel.org>, 
	Michael Ellerman <mpe@ellerman.id.au>, Benjamin Herrenschmidt <benh@kernel.crashing.org>, 
	Paul Mackerras <paulus@samba.org>, "Michael S. Tsirkin" <mst@redhat.com>, Jason Wang <jasowang@redhat.com>, 
	=?UTF-8?Q?Noralf_Tr=C3=B8nnes?= <noralf@tronnes.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andy.shevchenko@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="FG/++D3d";       spf=pass
 (google.com: domain of andy.shevchenko@gmail.com designates
 2a00:1450:4864:20::630 as permitted sender) smtp.mailfrom=andy.shevchenko@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Feb 12, 2024 at 11:39=E2=80=AFPM Suren Baghdasaryan <surenb@google.=
com> wrote:
>
> From: Kent Overstreet <kent.overstreet@linux.dev>
>
> The new flags parameter allows controlling
>  - Whether or not the units suffix is separated by a space, for
>    compatibility with sort -h
>  - Whether or not to append a B suffix - we're not always printing
>    bytes.
>
> Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Suren Baghdasaryan <surenb@google.com>

It seems most of my points from the previous review were refused...

...

You can move the below under --- cutter, so it won't pollute the git histor=
y.

> Cc: Andy Shevchenko <andy@kernel.org>
> Cc: Michael Ellerman <mpe@ellerman.id.au>
> Cc: Benjamin Herrenschmidt <benh@kernel.crashing.org>
> Cc: Paul Mackerras <paulus@samba.org>
> Cc: "Michael S. Tsirkin" <mst@redhat.com>
> Cc: Jason Wang <jasowang@redhat.com>
> Cc: "Noralf Tr=C3=B8nnes" <noralf@tronnes.org>
> Cc: Jens Axboe <axboe@kernel.dk>
> ---

...

> --- a/include/linux/string_helpers.h
> +++ b/include/linux/string_helpers.h
> @@ -17,14 +17,13 @@ static inline bool string_is_terminated(const char *s=
, int len)

...

> -/* Descriptions of the types of units to
> - * print in */
> -enum string_size_units {
> -       STRING_UNITS_10,        /* use powers of 10^3 (standard SI) */
> -       STRING_UNITS_2,         /* use binary powers of 2^10 */
> +enum string_size_flags {
> +       STRING_SIZE_BASE2       =3D (1 << 0),
> +       STRING_SIZE_NOSPACE     =3D (1 << 1),
> +       STRING_SIZE_NOBYTES     =3D (1 << 2),
>  };

Do not kill documentation, I already said that. Or i.o.w. document this.
Also the _SIZE is ambigous (if you don't want UNITS, use SIZE_FORMAT.

Also why did you kill BASE10 here? (see below as well)

...

> --- a/lib/string_helpers.c
> +++ b/lib/string_helpers.c
> @@ -19,11 +19,17 @@
>  #include <linux/string.h>
>  #include <linux/string_helpers.h>
>
> +enum string_size_units {
> +       STRING_UNITS_10,        /* use powers of 10^3 (standard SI) */
> +       STRING_UNITS_2,         /* use binary powers of 2^10 */
> +};

Why do we need this duplication?

...

> +       enum string_size_units units =3D flags & flags & STRING_SIZE_BASE=
2
> +               ? STRING_UNITS_2 : STRING_UNITS_10;

Double flags check is redundant.

--=20
With Best Regards,
Andy Shevchenko

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAHp75Vek3DEYLHnpUDBo_bYSd-ksN_66%3DLQ5s0Z%2BEhnNvhybpw%40mail.gm=
ail.com.
