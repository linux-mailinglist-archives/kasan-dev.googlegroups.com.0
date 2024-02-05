Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHFMQOXAMGQEHYJA2KY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 00F3E849A68
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Feb 2024 13:35:43 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-6e02aaa5a15sf1319800b3a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Feb 2024 04:35:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707136541; cv=pass;
        d=google.com; s=arc-20160816;
        b=FnYSYYXf2pbEI8et+Un6rRPic/ZNxg4KjtJSiQ+SRJq9RoVJ5gpbCX0zei4BAlN/j9
         Ro+DMTwPrpStYH+6Jjg35Qlf2M7BRiLSP+wD+xphbXp79GMCLrakRYhRgyw/M9D9JtOD
         OSGFVs8ZFkIPfVFXd0adww2igYqziOe1K76RPXWX2FamQfOT8ba35JCX1AYbJwd67qc+
         E0iHryJQM6erdhQW+MRBhqjkOeeQ/dLGgsksBcFsF0FzksaVolfyoh7ULRcdN/1ATdG2
         6vhZl1gHSHep7wouT6p37xDzzDD/GR0omo/P+hPEPQClTjOhALGJaRwpllZD0REy6XUk
         oXKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=LiNyJmX2anMHXVkMewAShMoTd8Y+BB8+X7Vq/iuSjvg=;
        fh=WXURkvoPuD+ds6ayj9OE4rbeaFVGoAQpuKbJuBHYKB4=;
        b=F5MKBj1ZQhrcVlVx4eNiswAVi3VTGBS9+OI0MeldBFs1jhVLHtPeKZBqIdb3SY1uFk
         pN71/ARRWYVu+ITWdui7ZryRca6QJP3VBovpYyteba1elNx72/zsK6tB1NdSXrB+/CSD
         QBF3uQZwtxX/su2jHyJ7mXhVS6uyM3lN6rebDT9hmx/Xz7PRa4ouszcfXW+LZqbd73f+
         Jauikvf0m6EtzDQ7GHChjj6xcj+tuTf/OzJbeRocAqvncQIptydWLc41hh52nS0pLt9/
         cwhqnIxLkSJ29XDynU3w8yQRfcC01l0NRsCzKnI85zSFg55bRBWNPt3YjqKKKf+dZm3a
         kymg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WJGj86fk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707136541; x=1707741341; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LiNyJmX2anMHXVkMewAShMoTd8Y+BB8+X7Vq/iuSjvg=;
        b=pZQpWdqlfY9btsEB6YzvsF/hBXVZoNtU2EuQIg0g+kTghqJoi7+CShaIud7M+PAmjJ
         2SznTcUwaFqrq2UV06A27OEvswyiF8B+IDwM5O0LK8NUoktoMbwSveGAiOlFxZHePAjP
         34tzZXf15GiuZTeDj3IQD/ydFNyMlaJBKvnxi7DffkkiLAxRaNzgrhGvZpuUhufwm2Vp
         GF6WKzbg4sqN8Ew445n70tKotHKipY31SCtYTEHfmICZHS/k64VXiuRgRXcXQh6GYJe4
         7zS8IcePz5WPkQB/8PpGF0smKcaP7t2RGAuNsOOQbxrg/oWV0Iv/RUQY2tOPKoiVtacM
         W9ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707136541; x=1707741341;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LiNyJmX2anMHXVkMewAShMoTd8Y+BB8+X7Vq/iuSjvg=;
        b=gwwaO5AmATwB+X4gILbHNaxSP+6D5cOtDTe2hrcn99zYKJhDDXOycMLmV12irUbz95
         RgMjD1yrZj6jnCDwNhtdCHU0lTWip6czSKq9uPcDlJv8n0f6fcfbYuoAhAy8l3Jv++4N
         EWaZLM/pORIcYCvuov2wCgk2HF6Jhq+pAKGqWL797p8jyNuWl15piSEUzxFYNsjA8zy8
         Rq5iDjFdRKzF/DYQ3eqZns8dTiH7fQfdbx/gKaEPe6bT1V6xcpjSMr2GKpx8OaaaNxQ3
         1A1ydMkiG47iVT/aLnpH2a3VYVEXvwVuszqobwgVWXdLQVntEHIwPw3IPbcsig4Q1IvF
         AslA==
X-Gm-Message-State: AOJu0Yzw7cO16dvlQ8z3DqqbLTHqi3/2AZHMeevqiLcVupOEzjH5uWNm
	Z51QOv4rXa8e0zhyQQKMIoElSrw613CkR5D90ROr5YqZPkcnZpb2
X-Google-Smtp-Source: AGHT+IG9pWBNbbGhAF9ckQuIAShQK/rp1b1A6tUgJEBPl5qt+M4kJiN5uMsnNeGonLIu58PhNqcs/Q==
X-Received: by 2002:a05:6a20:6f88:b0:19e:4c29:d305 with SMTP id gv8-20020a056a206f8800b0019e4c29d305mr10372693pzb.54.1707136541159;
        Mon, 05 Feb 2024 04:35:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:9082:b0:6df:ede3:f6bf with SMTP id
 jo2-20020a056a00908200b006dfede3f6bfls2475595pfb.1.-pod-prod-04-us; Mon, 05
 Feb 2024 04:35:40 -0800 (PST)
X-Received: by 2002:a05:6a20:7611:b0:19e:4ebd:92c8 with SMTP id m17-20020a056a20761100b0019e4ebd92c8mr5683269pze.0.1707136539797;
        Mon, 05 Feb 2024 04:35:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707136539; cv=none;
        d=google.com; s=arc-20160816;
        b=c5RlZQLSkjs0If65+ykoKDj5TNe4h9AbZxln8sHjSUvZm4z5ZBo7djcKX7wYW1pfFj
         qWX5VjEBfjMo3W/vVpIeNvHgitIq0tGbipdxHlejJvIMZ3dVcHwz2SGKdGlyghhtwELy
         eu6DI4+ZfU/Y65TErulsmm9EQ/tRp2rCpI/Aqy+eMxlzZvQZDxXnktShakvhdyBWB9PX
         uhROhgKCN5uQZlQxpkW0mv0d3+/TNpD1pKJ5JiADn0BKER+oSCuu56YOwsZjAS4WLTY1
         8QJFHhQ6ybzMfLVCWf4lKsDpzHffRmRwc4fLN/3/A2B588HTL5Qnj/M0ArCzno8ROAcn
         n8ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=pqINmvXfIdTyRxv3LEyPIo0XoyRMgoEvWKIchHbThYU=;
        fh=WXURkvoPuD+ds6ayj9OE4rbeaFVGoAQpuKbJuBHYKB4=;
        b=N4H2kqQ6jgtmWsjSIg2PLtzLX0brTAOLnm9uYeIxKn8x8w7u0PR8MmJsJhEMsJDgr2
         WH00aIzAbJADQFHHA4xWtRkaI8elPWKlRPUeEeSUBJfHYGThdLHgBBrzLxAL5g7uGtMz
         VZnaBKCwibrHv12XsJ77OTNqHHsYp3RaNB9YRy06Vm59yvG2CdzycQVo7ya7+AntV29Q
         qv+WIsDYGvTnYbOUJhidF+0+HSIn+e89s2MZFG6UWi7cWQbvxhVFmZB+oMvK744m+I6V
         56GFaPw6rxlIbyvfYCtfElyTYeCcreY67cTewMDkuqlNTSb3JBfAPNzBVwqjwG9Oc1pZ
         lVRQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=WJGj86fk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=0; AJvYcCXl0S4OHl9FriYwajKC4fShtkOKqROmDDj37m8ai1qxxsNqQkUBqSl8qcppBFp2P3/BW6c4aOtfBMEWGalJwUK3kdJeGexo+vhXWw==
Received: from mail-ua1-x930.google.com (mail-ua1-x930.google.com. [2607:f8b0:4864:20::930])
        by gmr-mx.google.com with ESMTPS id w1-20020a17090a8a0100b00296a25fd756si102924pjn.0.2024.02.05.04.35.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Feb 2024 04:35:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as permitted sender) client-ip=2607:f8b0:4864:20::930;
Received: by mail-ua1-x930.google.com with SMTP id a1e0cc1a2514c-7d5c2502ea2so1640676241.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Feb 2024 04:35:39 -0800 (PST)
X-Received: by 2002:a67:cd87:0:b0:46d:2fb2:337c with SMTP id
 r7-20020a67cd87000000b0046d2fb2337cmr1824167vsl.8.1707136538764; Mon, 05 Feb
 2024 04:35:38 -0800 (PST)
MIME-Version: 1.0
References: <20240205060925.15594-1-yangtiezhu@loongson.cn> <20240205060925.15594-3-yangtiezhu@loongson.cn>
In-Reply-To: <20240205060925.15594-3-yangtiezhu@loongson.cn>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Feb 2024 13:35:02 +0100
Message-ID: <CANpmjNP4gp0k-VpqJferxUAV7Z9M4ROYdq7+mQS57qiYDccw7A@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: Rename test_kasan_module_init to kasan_test_module_init
To: Tiezhu Yang <yangtiezhu@loongson.cn>
Cc: Andrew Morton <akpm@linux-foundation.org>, Jonathan Corbet <corbet@lwn.net>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=WJGj86fk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::930 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Mon, 5 Feb 2024 at 07:09, Tiezhu Yang <yangtiezhu@loongson.cn> wrote:
>
> After commit f7e01ab828fd ("kasan: move tests to mm/kasan/"),
> the test module file is renamed from lib/test_kasan_module.c
> to mm/kasan/kasan_test_module.c, in order to keep consistent,
> rename test_kasan_module_init to kasan_test_module_init.
>
> Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>

Seems reasonable:

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kasan/kasan_test_module.c | 4 ++--
>  1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/mm/kasan/kasan_test_module.c b/mm/kasan/kasan_test_module.c
> index 8b7b3ea2c74e..27ec22767e42 100644
> --- a/mm/kasan/kasan_test_module.c
> +++ b/mm/kasan/kasan_test_module.c
> @@ -62,7 +62,7 @@ static noinline void __init copy_user_test(void)
>         kfree(kmem);
>  }
>
> -static int __init test_kasan_module_init(void)
> +static int __init kasan_test_module_init(void)
>  {
>         /*
>          * Temporarily enable multi-shot mode. Otherwise, KASAN would only
> @@ -77,5 +77,5 @@ static int __init test_kasan_module_init(void)
>         return -EAGAIN;
>  }
>
> -module_init(test_kasan_module_init);
> +module_init(kasan_test_module_init);
>  MODULE_LICENSE("GPL");
> --
> 2.42.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240205060925.15594-3-yangtiezhu%40loongson.cn.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP4gp0k-VpqJferxUAV7Z9M4ROYdq7%2BmQS57qiYDccw7A%40mail.gmail.com.
