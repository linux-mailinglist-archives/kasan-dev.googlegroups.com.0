Return-Path: <kasan-dev+bncBDW2JDUY5AORBCONSW4QMGQEMQUZWZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id C4F039B9B3C
	for <lists+kasan-dev@lfdr.de>; Sat,  2 Nov 2024 00:38:51 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-2fb652f40f1sf14822511fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Nov 2024 16:38:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730504331; cv=pass;
        d=google.com; s=arc-20240605;
        b=MGLn3Vifg7BqNdLPlBuUqpVAdmmrcqWwZFe2r+6F13cV+bzvFEZeQjhtgKdm9le3+a
         4YDH7VYW5GqnLH88K7OSrem6GeFnEaU7TFrHzSQA794ijxWyC/GRznAZRhXWpvinUhEs
         BRmkpEdRSKCryIUgLN1rErp7u/ESxEM5TjA7lgliT7a2Omd/c4BfEoaH7bqhzU+9USUd
         wfkJr2+X/4cC23D4va1LIBLvse9N7oGbU8HpFkkJuRJAa3jXWChC6ngnFpqpBaHY8B1S
         19QdxAz50JCjSW1p4rVepTMSSRNms5noo7j/Q/M4CxxwdzgF1cHUZDtw4SjLPMUeU2rE
         pg7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=DUq3mGOpoUaUZQFwYBR6yCTWMXYr5tniGqv151++NpE=;
        fh=3nPVOt3FWbXzGcy9e/MfRHV97DXHgzaCMDWZaiCYGvQ=;
        b=XzCVjnGYl87wA2Cpvzqy4YaYTIa//N8j7AQUs3ajR00BMRP4qI/plZkPqdXqoftsd3
         6Tnf3ZfQx6mKug5XvR/YgEmJa1KOn3VF8rVV2Alv6dr8cJeLQgZOFfjUfzsCrpVgE14s
         Sv6q6QDnmsN3nQ3ETfCtBUCksaaFpIp/sSudzv1HT6E4lIolxQvWZAnEyCKw2Xnr++ze
         K6QBMxu5xihbnVP5f2muXkRzqMCweSVVvhl04C8jjWwSa364Uesta7JhQhpNbbCQF7Pn
         dq8hB+supL5Ydrlrv0CG41FpYYG1YILPqv1mU8smZ0eEEBC0jbJwHftyhyw4JBwmpJjI
         wWkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YovL6+Ej;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730504331; x=1731109131; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DUq3mGOpoUaUZQFwYBR6yCTWMXYr5tniGqv151++NpE=;
        b=UoLv00SIwNeuQ7/rgqLbUmckajyhM5Kjhn5+BUqUu216hMsyNmzu5AaEEcVk8DBNGh
         DMEkWl9voU33jMWaIsK/iQhRS4zXJHMGVqcMTdrZaca4gPF1SFGzVTDZ1blLQkkJrOxa
         kMVTIV+II5dBa3rnCa5+wfYD7k+0YzJlHDXJ2GB8AHFh3Q05DgLJqpzdSuqFpnJGDNzm
         LWfwpySN+yzW721Ljqqht50lCAfPRDuS3vAm+fxxrrh3QlSgfrw9WB7m9/hjWyhuPkHO
         zK1uppzu+VlajidofvTGSOOzB8ViDghSJMCgiDRCW+9di+AQ43t+aCD0d+UL92n0Z8nX
         ZT7w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1730504331; x=1731109131; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=DUq3mGOpoUaUZQFwYBR6yCTWMXYr5tniGqv151++NpE=;
        b=LFvM2qPzx3qPpxH1ATyhTuRfPbe0hS89+qgebnv0yFWyuij12eXvnqyWDb2R7qvxgp
         fCQoAbidAKzULLNshDeGg2aJux8K7EHLVEURzI3A07huTJaOYwpALgLF84JPsMxDqEuc
         DNuyddaCpJgfGIyUPUXoK+8fE33Z0mK1XvnFKeGbccXDnqARaGJXxUt88f0+58EjRj3M
         fj9IyVMrykdsNoH3hEYrELwsk2YzoSlb/3wRTMDmrvgJOH75BE2L68APnPLyg0XmjtzS
         F7uKoB+pxcMlwImKzVgs2RzywibIsbPXZ97O5M2QjGiTgt4QZfc5GbB3VyEY/KlM8jl7
         TXjw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730504331; x=1731109131;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DUq3mGOpoUaUZQFwYBR6yCTWMXYr5tniGqv151++NpE=;
        b=uhpEvc7ymqHaNaoZzaOj8n74Lw8mUdmp0XKVjN+AMABRN3O+qW859GGO8LaHN+M1KG
         c+0Vkn7Xu/Eoi5FSB1wu3LHc2LG/tVJ2LgAstU1Mz8Q2HbtRcjPgdBU3gw7r6rUJUmse
         5UUIx4nrzrCJt3q7CoCHnPwUai1NLfNbK3HcArnpFJXAVMXRsbtdPgnngAwsNLHdK+zY
         kY1+kzvDsTQhzh+5dTqLreza8JFFUbIsTF2jPEhT9OeQAHHhUXes+SBHZokYgfujDZ9t
         DsGw4GrqgM2ltuQ0n1G+tpGgQwFy8KOtCG0OmYF3HKDcn1sxmrdF8l3MkAPTLAp4eNf6
         Y4HA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX/rK9W5mxmYZeXjnYfiM4urkaX5+MU1t9ryCd4oR+2cwkr5mbCePycd8RzyWUryU1ZX1ud5w==@lfdr.de
X-Gm-Message-State: AOJu0YwGAJ9V6c/7oLojV6/3PO9sKeltG4jY7+R1FUK1u50ZikbTzxSE
	N8q+nAqi2W7HgytcfdDQg+H/im/mxr1pSLwd6fC25DONpLrqgMR8
X-Google-Smtp-Source: AGHT+IEupcctTQ1Wj4neA+jAJhLTA6qr5DjYTuyy0Nd/yKPiJlAvEczsnKuSJO5Dwd1MBc8tC4A87A==
X-Received: by 2002:a2e:9fc2:0:b0:2fb:4ca9:8f4 with SMTP id 38308e7fff4ca-2fedb796712mr28393341fa.23.1730504330123;
        Fri, 01 Nov 2024 16:38:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a46:0:b0:2fb:358c:f76b with SMTP id 38308e7fff4ca-2fdeb66db52ls4568251fa.2.-pod-prod-06-eu;
 Fri, 01 Nov 2024 16:38:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUBZIKc6f1NVOFyfXHvkKf/07pZjUDph0rn0n54+xgnNKFqbq6uORfeB4LQi//wtAbIolEeGCb2OzU=@googlegroups.com
X-Received: by 2002:a05:651c:1541:b0:2fa:fc98:8235 with SMTP id 38308e7fff4ca-2fedb7ec78amr25827141fa.42.1730504328121;
        Fri, 01 Nov 2024 16:38:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730504328; cv=none;
        d=google.com; s=arc-20240605;
        b=JFtD5romc5oEAny+xWvjQwR+fHskoAX5GGR29L0kK42x2qZ+C5pufM+jYya2KDzoer
         yRRNmJIsIo9is8CgeR3a8NUwBQ/rLJkx65UARDW5AbTjdq0vXQot3/2r6j78z5ukx/HE
         cT3rGXVVIfcnevoTkq6s0Z9jeZi9OZYNYJmr4XnWbV3nS9oIHPEfgR41np9XfvKECpga
         7FtAP6m2IaWA+DZmvrTiZ8AKseXPQAGFjxTcIdJV0fI6iH4hE3lPgIht72sP1VIxa/fc
         e/xyaV2fFcNqBl7PnUqWHp5I7ZAgj25KNKv133+87NKtV8d259ZfeJEO3POrxd8rLB0E
         2iGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=G7fKD6F8/BWM/aqkIjVZ9Hrc4vMUOZTXgZCF9mCVBq8=;
        fh=TQTM7C8ZLUO3cvvfBvaaq6MtOkn0oCPDeRya1Dr+yzA=;
        b=j5SdtqlygSTpBIpaZfZELK17zvCF8I4nwIOyyfeMR8u8VunLG/IVU/6W7jxYQa1fbp
         6HJLl2P8iz3lgCJmQb3w8jCVbynZjo6r4jP4QUpY+aY7EYzqoVYknjyHik2Dx/X71MqI
         +y7hFeYSl3DgBF3hj6DijOwQDAPodrOQOzc9PBN2OZrOVKiN460E6UXbPMs3ftYFElcq
         n8mJx20ig0pFZCZQIJs8g+sz/r5p+B6hsnwqLwjQNEi/ZaFwlOt9Yk2/5Gvbfl0jE1RS
         gmnwTjFUJyjhCzINT+9TzHzOwWc5zISluJ+6j0DtdXlOtjaOJcjcScbW/r3JDey7tcck
         a/ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=YovL6+Ej;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x436.google.com (mail-wr1-x436.google.com. [2a00:1450:4864:20::436])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fdef8dcbafsi1267231fa.8.2024.11.01.16.38.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Nov 2024 16:38:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436 as permitted sender) client-ip=2a00:1450:4864:20::436;
Received: by mail-wr1-x436.google.com with SMTP id ffacd0b85a97d-37ed3bd6114so1385984f8f.2
        for <kasan-dev@googlegroups.com>; Fri, 01 Nov 2024 16:38:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWoxzdCbhTFM9YFc02Fvk2mDWqW8jafCkBRchApr2P3UwZkVzz9t+D9RZcMMEAg0z28zEi/PoUpqWo=@googlegroups.com
X-Received: by 2002:a05:6000:156e:b0:37d:33ab:de30 with SMTP id
 ffacd0b85a97d-381c7a3a535mr4042932f8f.8.1730504327558; Fri, 01 Nov 2024
 16:38:47 -0700 (PDT)
MIME-Version: 1.0
References: <20241101184011.3369247-1-snovitoll@gmail.com> <20241101184011.3369247-3-snovitoll@gmail.com>
In-Reply-To: <20241101184011.3369247-3-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 2 Nov 2024 00:38:36 +0100
Message-ID: <CA+fCnZd9V8okaozn-LBA3w=TsuVbTR=4Hey+w1+_CRDVQV_XEA@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: change kasan_atomics kunit test as KUNIT_CASE_SLOW
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, elver@google.com, arnd@kernel.org, 
	glider@google.com, dvyukov@google.com, vincenzo.frascino@arm.com, 
	akpm@linux-foundation.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=YovL6+Ej;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::436
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

On Fri, Nov 1, 2024 at 7:40=E2=80=AFPM Sabyrzhan Tasbolatov <snovitoll@gmai=
l.com> wrote:
>
> During running KASAN Kunit tests with CONFIG_KASAN enabled, the
> following "warning" is reported by kunit framework:
>
>         # kasan_atomics: Test should be marked slow (runtime: 2.604703115=
s)
>
> It took 2.6 seconds on my PC (Intel(R) Core(TM) i7-7700K CPU @ 4.20GHz),
> apparently, due to multiple atomic checks in kasan_atomics_helper().
>
> Let's mark it with KUNIT_CASE_SLOW which reports now as:
>
>         # kasan_atomics.speed: slow
>
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  mm/kasan/kasan_test_c.c | 2 +-
>  1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/mm/kasan/kasan_test_c.c b/mm/kasan/kasan_test_c.c
> index 3e495c09342e..3946fc89a979 100644
> --- a/mm/kasan/kasan_test_c.c
> +++ b/mm/kasan/kasan_test_c.c
> @@ -2020,7 +2020,7 @@ static struct kunit_case kasan_kunit_test_cases[] =
=3D {
>         KUNIT_CASE(kasan_strings),
>         KUNIT_CASE(kasan_bitops_generic),
>         KUNIT_CASE(kasan_bitops_tags),
> -       KUNIT_CASE(kasan_atomics),
> +       KUNIT_CASE_SLOW(kasan_atomics),
>         KUNIT_CASE(vmalloc_helpers_tags),
>         KUNIT_CASE(vmalloc_oob),
>         KUNIT_CASE(vmap_tags),
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd9V8okaozn-LBA3w%3DTsuVbTR%3D4Hey%2Bw1%2B_CRDVQV_XEA%40mail.gmail.c=
om.
