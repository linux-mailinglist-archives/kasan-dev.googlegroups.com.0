Return-Path: <kasan-dev+bncBDW2JDUY5AORBP7QWSXAMGQEI22SZRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 51452855571
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 23:01:37 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-51147e15397sf136735e87.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 14:01:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707948096; cv=pass;
        d=google.com; s=arc-20160816;
        b=kusgOmuWvVlLZzFx+k/tqYVrEkVDEiapv4QHOxOn5RP9dbPTmd/tBkCIIQc+C+rPvs
         Rww9yeGi3+LXycI8rcRcum5DBCwKdVqAQxGytwTRYJZ5Rcr2PZfsgyYeqSZoQRXz49/U
         VUQDwdplbGYLJVcLzbky3dEP9ZYl0fXif8ap1xKIKOAGgofo150EJ2z8NNii8Ob6rPqg
         pzMBzJ3haHMR4UutX32pZ5tEUN+w5jEgoFtQL6scF55LCWULsvilPUSC9cRFeaGs8ILs
         tzwaU/B5Xa4T8o+6bvqIEk6DlLGtrwTIcL821ChoxA4FFOseeq7D6N9sruRjO5ZBP0gL
         oHWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=pfxei3zOk/JcVK1hrVgI40DW8kStpJivgSyLAAdmhns=;
        fh=DdxKDhkvJsUx42mrSAgYrLWf7qiITd2MzbDkzwancCY=;
        b=C8YT9ij9A1/Qnwz3TcOsQqwsM9GOX8OGKQyEVAvfnDJfMIYP+ZAt+3S26GNuMhSEYU
         l+nhT5Ra/Jfc3T98hsF3+3WWSl8T22ZsBq9rdof6BSZexFS2NbbZyfPRSdrvcdR/u8/B
         3uoI90RHDC5NtAdwa2SeQMFlUgrk9cyw928yGAwFwcYAVKysKTWGf38qToXVoQscpxhP
         eykvd8PpJzUxOQQSL7pBkDhQzhgqH0INUPeTh1TK7UoP0CuUdQejU86YTSHiPaKfTj/w
         jvEFxQOjX7KuVnoerEZzYvpKSP4uHuVk2VcwoZ7FRatPejYMMxzwmqJAZDG6AEk9LlW3
         gP+Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=joiLFVJh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707948096; x=1708552896; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=pfxei3zOk/JcVK1hrVgI40DW8kStpJivgSyLAAdmhns=;
        b=eTFznGOkJWafg1BAFgNVgNLqXJ3RcdfC2jpKWsh1NV1JkNJVJIKuZFNus7hyrloGmi
         HG+uU8sNWlbJz8NLAWnzFmSjzeY9QFg/M9cK9F3/hV7lVorroOMkRGEysSqfXT615O+c
         0V4zzkDaLn5E91sLYjm36aC4U0GpFrnNYSoOchPg3nocnYVswYey7jckBoDgDAf0+0HA
         vd/7nh6cmaiFuQj4Ao1QMNABWxgKME4Vw8HFYCjPLt+NeH3Eh16pI3kOo322NGjb9RjW
         hvRs/L/cO8nXMTZlpHjlSKZ73YQRd5cwaZ9y8wh3bOs6pa0ZMPYINHAWhD1DY9gqORX9
         RaVQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1707948096; x=1708552896; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pfxei3zOk/JcVK1hrVgI40DW8kStpJivgSyLAAdmhns=;
        b=V1wS/p2ZZwinoOItYOSdAIAI42XLx/UEyb4R6fec9ISJqNxjcLZ0f5HA3FSOEJaAYa
         sme2zJYVGHzSbJvG4hJr6H8TzwdZE9RVDjedIPN6yf//qzaVPGqXR8usEX5kpbsdBOzr
         GIr+JO8/KZalD1WpB2AGaZLPFqPRytyMwCQp9qsqeAeULM1SkOc6isO/3RnAV9P/8b3W
         0BRL3x4Wrwh4iUpLvTwfx53IgSyjGv1P9WbczeDmLPetFLAqxVqKcXZpX/edQQnle3l/
         DZPEUgPd5WLTm1HCV8ajfUu/mCTOVm7RI3qjY/20i6KA8QVAVhEh30Dn9w8vh0BecOLE
         8pSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707948096; x=1708552896;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pfxei3zOk/JcVK1hrVgI40DW8kStpJivgSyLAAdmhns=;
        b=eBDRljZLpFrPyyLt0EwO6cb81pLfIHzxyrPV8pM4aIb7S4n+2pR+Cp/PkW/JOXrW3x
         NqnAFD4yCh6sKhaL9zBpEIXmmutf1nSD4bRCjHHQP1M6FeQCHKehOC7YKBc1bmLsBJbS
         cm5PuRqift+KMtbfHYQfRHK3gPg1//zAfydTjclLGUamD0Gpn85f3k1Jr67swWeaBRrf
         VJkjwb4d4N88oednNAD+1mnYHMZx6tykFz6LAIcDZ5fxW+QttD1z+DoOtiPgdCb8Yw3d
         ptYJ+VPST43xnbomBJz7jLi/LVS5xP0hrbwW2vwjjNOMnKacVW+qv1/3oDCeI0rY+d4i
         a0Pw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWXQZ/SfrXs6/9AHLlThKD/BlgohUP2tAd/4XG43EULAR726FDFfB6axxfWHgRpzqoqOX6rpSJ8iVsnPYgwB20lLjE+i4ak3Q==
X-Gm-Message-State: AOJu0Yw6vgm9djF3zIZNsP9XmWhLrxRxiFiqi0fdmxvJs8U4CS2SXTa9
	kORJwZIQgpUYH6XEHQeI3EIvMaiNrqsMupzhbBnyaAC1KxcEQqaT
X-Google-Smtp-Source: AGHT+IGsFM0SDBRX3yghY8+BHExNiVxo3hp7Rjr0BajtwUK4BhLNLUgXWWwrn4jLHuVgn/tfD3/o3w==
X-Received: by 2002:a19:5e15:0:b0:511:5756:f54d with SMTP id s21-20020a195e15000000b005115756f54dmr50225lfb.60.1707948095949;
        Wed, 14 Feb 2024 14:01:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:402a:b0:511:46b8:40b4 with SMTP id
 br42-20020a056512402a00b0051146b840b4ls484670lfb.2.-pod-prod-03-eu; Wed, 14
 Feb 2024 14:01:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWhK0849xUFSTx4b3/TSMsQ7LDgdlsgbavNzQxiEKuxaFYmdfVUQIb2OSlR0YacLwFSAF6G77JDIAXMfryhCsQMVycWgTUfRCOmxA==
X-Received: by 2002:a05:6512:1d2:b0:511:5405:7bc9 with SMTP id f18-20020a05651201d200b0051154057bc9mr46480lfp.59.1707948093951;
        Wed, 14 Feb 2024 14:01:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707948093; cv=none;
        d=google.com; s=arc-20160816;
        b=ar7upBATVc6sXbptC61aG/n3//bpZ8Vl+nFCs/MY6Ey4y9fymxhEgJTht9zJ9YUrW+
         l3H+X7SdU2tiTEjtDaYND7NKH7igZ5Trkm8AYY0zB/gK3DjzECC/r52i/7C86xyqxaDp
         OJUiHK3jOLZZUqI5Fy2wK2pw8rfYMEd4V9/7OYQjvGVf5D4sHKwHVawuB4j9uFaB/hOf
         gwbRTbkOHjBIYZYboYAy4L0VHIP5NaNvINO8ZOSiAR1xb6VS5iBN6KUFfhAPzjI/F7Si
         F6ZGaTkFU6BjTabSRA+/Ai87JgS5yZ/pJrr4cWlhcUhoDj7JAZJri5dFEBBU1lNgHBze
         4hOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=n0ESyyBcqjsDVYShCT0eHRNmp20GSZgnSy4/io1Ynu0=;
        fh=qSuwyNvETtG7uCU8AJHrDWSTOGWO+BcvtWuII1F5hvU=;
        b=e7S0XajQT1QiXS12QGzFx5meP0Snxdc55BhYxVFUp6NSLQ40jbi95c+737fyhqhSA0
         RGZZeeUKU/xAIz9z8XYNUE5gzpGM06NQ3E5nfXmxHzsm2YnBrySv2M0P1xoj6aHPaqUD
         4l8uHyeU1i7c8R6V7k+scp2vxMR1CJuFNDkLVNi/tZpvsorCmuF5GLz5jXIXX8vSl9Ro
         q30faNYkg7uSEu1hd1s2DYSDw72lyUGSiv4ssiHXzIsjpSqFihzuYyOwMM/wvlWEL3wG
         2xlXz51LblhKU/mnUJ8ZXt2NWcU3VKjqHRGnYgmNGZ87kYjSB8kDCp3a4CQy75koiz4s
         pb6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=joiLFVJh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=1; AJvYcCWewHARkAYx16xDu41xpj/g2qWcW+/FpfZFWHUwYOVASJuaFHUnvNmNLnbMDJs27CqrOkj1R54K234X+Fu+zZY3LTgCNkZXPsLY8A==
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id o16-20020ac24bd0000000b00511a71805a8si105931lfq.8.2024.02.14.14.01.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Feb 2024 14:01:33 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-33cf91fc9easo92506f8f.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Feb 2024 14:01:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVa1smpGphgmOLcnmxgkz2MG/xXqSC9yd5K0xEbayRJIlHuxrYlnKORZrJo/wK1vuAnoIfTwnFPPaIHxc8lpPl1y2T1ucI+dlGwtA==
X-Received: by 2002:a5d:4a8b:0:b0:33b:1577:a2d1 with SMTP id
 o11-20020a5d4a8b000000b0033b1577a2d1mr2765986wrq.1.1707948093094; Wed, 14 Feb
 2024 14:01:33 -0800 (PST)
MIME-Version: 1.0
References: <20240212111609.869266-1-arnd@kernel.org>
In-Reply-To: <20240212111609.869266-1-arnd@kernel.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 14 Feb 2024 23:01:22 +0100
Message-ID: <CA+fCnZe4Tr4FXruNgOzaXHR-u+M8h2MkZCOQMH0B8mwUy=wVig@mail.gmail.com>
Subject: Re: [PATCH] kasan/test: avoid gcc warning for intentional overflow
To: Arnd Bergmann <arnd@kernel.org>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <adech.fo@gmail.com>, Arnd Bergmann <arnd@arndb.de>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Marco Elver <elver@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=joiLFVJh;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42f
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Mon, Feb 12, 2024 at 12:16=E2=80=AFPM Arnd Bergmann <arnd@kernel.org> wr=
ote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> The out-of-bounds test allocates an object that is three bytes too
> short in order to validate the bounds checking. Starting with gcc-14,
> this causes a compile-time warning as gcc has grown smart enough to
> understand the sizeof() logic:
>
> mm/kasan/kasan_test.c: In function 'kmalloc_oob_16':
> mm/kasan/kasan_test.c:443:14: error: allocation of insufficient size '13'=
 for type 'struct <anonymous>' with size '16' [-Werror=3Dalloc-size]
>   443 |         ptr1 =3D kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
>       |              ^
>
> Hide the actual computation behind a RELOC_HIDE() that ensures
> the compiler misses the intentional bug.
>
> Fixes: 3f15801cdc23 ("lib: add kasan test module")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  mm/kasan/kasan_test.c | 3 ++-
>  1 file changed, 2 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
> index 318d9cec111a..2d8ae4fbe63b 100644
> --- a/mm/kasan/kasan_test.c
> +++ b/mm/kasan/kasan_test.c
> @@ -440,7 +440,8 @@ static void kmalloc_oob_16(struct kunit *test)
>         /* This test is specifically crafted for the generic mode. */
>         KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
>
> -       ptr1 =3D kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
> +       /* RELOC_HIDE to prevent gcc from warning about short alloc */
> +       ptr1 =3D RELOC_HIDE(kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL), 0);
>         KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
>
>         ptr2 =3D kmalloc(sizeof(*ptr2), GFP_KERNEL);
> --
> 2.39.2
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZe4Tr4FXruNgOzaXHR-u%2BM8h2MkZCOQMH0B8mwUy%3DwVig%40mail.=
gmail.com.
