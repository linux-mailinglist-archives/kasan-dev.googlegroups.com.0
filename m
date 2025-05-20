Return-Path: <kasan-dev+bncBCMIZB7QWENRBSVQWLAQMGQE2YTWTPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C9EFABDDF0
	for <lists+kasan-dev@lfdr.de>; Tue, 20 May 2025 16:57:16 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-551fc32ff06sf600610e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 20 May 2025 07:57:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1747753036; cv=pass;
        d=google.com; s=arc-20240605;
        b=MMiDxhOofIYT3nWwei8b+KoNTpxpZwBOGvWZ10pmRWHhZBqFN1YPVbM62MCC8mXyuH
         QWHXYCss4HrGnk3p2xnnw2G6uXjP9Fj1SuK7mcG2PJtIIbhXm017RDjkKoIp4mmg3MQO
         y4a30zK0bhmON42KOKb/X66KteQ6j6Jj3RAVswHaH6tiM9BXSxItG4lphxb6slML+ktp
         Sl1MMobIE9WV97L7MTiD2GQp4TJDgOkyNbjShEotmtIF3paH2yAMOjDKIBnf2ATOYoNp
         izuMlvHJVfBytPY96jutfpaGvv7OCDdpRP1qguLfbUVdR06d8vJQaIQPbHCK+ED1cRq4
         bz1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nIwXLa//IuWgIlSod0Ck5JS6ft1x30WUbPm9lu33+zc=;
        fh=xJw9kbFZc0nKk6iqPpuR+pemo8lkXuc8ifsQ0z7d0vI=;
        b=i+5zcWnw4AyDNyzZABBMYxk3MsYDRPfmBQT/QaKdL75+ZZrmokj1V+bpdNnCF+aGXm
         qK1h80zhEUtMLKnF3NC1mMTQi74NiYJnhVJKCDs32n4zCNU0cydcTsD96rjNbKXrALUr
         q/z80DK3orVny40zRLLWrvWwBfUR7ahoz9JeeDfrq46trltz4Nw+xMMytofP6FtPkoG8
         z7ncFcusm9sLtiy0NC1gMl8tfB4CVon2rmOdRYml7OCgqZAUEJVk76+bCH3j8Ng1Woet
         vc8Ci0FmZcNNSUPxLqUVRL0md6zkPRo/qaonafXu/tr39aquI5kWuQnEvfmfNV8neBBd
         q5Rw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R14F7Akq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1747753036; x=1748357836; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nIwXLa//IuWgIlSod0Ck5JS6ft1x30WUbPm9lu33+zc=;
        b=FhAQx8YeL0uPX0/oYaYLbczdxOIAQPDqU9jRfJoGHz69fqUIBygtEGtzHb+I9321nf
         +01O/ngy5zTV4guRmE61oRaLSOeHPaYg+nmzZ9D7LvKInjmCSHe3hx5JDlYXpIjFwynR
         ioiF2AD/Wcu2/GyzzsmXhtvgim2OqKKpMmzL+/x9/hFnBLql9xGBSgbqFoSeI7ZzO7d8
         9JRw0rw3YQJCOQNA8vIIprc+7OoUtGRjRTKMTWHMp8OQhE6f7hSYYppKHHChK/sj3kIO
         CEuy5TNoOLNbcgshMJE7my01MorXJtOaW0230U5xT/6VfdnMwqDV2qp+QD6RoTLKrUP+
         Ad/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1747753036; x=1748357836;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=nIwXLa//IuWgIlSod0Ck5JS6ft1x30WUbPm9lu33+zc=;
        b=V5Vd5xULlz5DksYT297IzCi7lzCITTNxcqQZPxHHdhc4OZ1K3b4e68WptvAnjI9V3O
         pNVNzoceituFzCFgbh8gwNsGrG6N0QHsJLK0xZvbTySIcuVHHLuSu8Da11B7d0Ps8yaC
         O6FoFqV7Cg4Z07Zx0nbKmgpYhKB7nT40wF07+PuSryi4oYKasj34FJ079fSOIo5T3Non
         v6Fnq4wQlZLFDdx3TcaQ8VXcUOuM56Xu18v0kNJBvmg+GuEvqDMclLh53i7aQaXFT69F
         MuxDcFMWH+ZnAX8yxFig1Zq9aQQnfGQXCWUBajg2rPmSFbyioHM990l0VccosGGLU5Nz
         AA8Q==
X-Forwarded-Encrypted: i=2; AJvYcCVaNhkG2uOB+Zr+04x3wQPpzmtU0C4d5QFFWrfCp/Ihy0VHziiYpGxXzHJOTgLHLx/SxGix1A==@lfdr.de
X-Gm-Message-State: AOJu0Yy/NjaZYqx7mcdE1sxdIFH+RmHu4/Be8vED0DBWZybS62Evhe89
	a3ga1TPPGn8jG1bwec0W8axB8CEcSNe8hJOYY+HFCQAcSxtAadT4cs5H
X-Google-Smtp-Source: AGHT+IFWw5PAMIB+JQfaENOTSRVRepTqZVVjzMtK07hjuhqG7zkaO3TIv3goGsXRYypycEEJyMAJRg==
X-Received: by 2002:ac2:4e05:0:b0:54f:c1cc:1241 with SMTP id 2adb3069b0e04-550e75147c4mr5805759e87.25.1747753035317;
        Tue, 20 May 2025 07:57:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBG5vEU3ZWiZkP9uR4MDEaJgqe07IVjMte7HfiMGX7tFLQ==
Received: by 2002:ac2:5924:0:b0:551:ee0c:ec5 with SMTP id 2adb3069b0e04-551ee0c118als74661e87.2.-pod-prod-00-eu;
 Tue, 20 May 2025 07:57:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUlbO9fibPM75ETtiYwImJ+gFEdNs4ogrgv83QXDSNHhBcJDPQT6GmPtw3E0WyDGqGazHYZC0OFkXw=@googlegroups.com
X-Received: by 2002:a05:6512:3e28:b0:549:8999:8bc6 with SMTP id 2adb3069b0e04-550e746f0b0mr4340211e87.6.1747753032707;
        Tue, 20 May 2025 07:57:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1747753032; cv=none;
        d=google.com; s=arc-20240605;
        b=XiXvAWucnXgOqSZuNphd5a50wQwAkQhKNHiOcTmjfjjLmnecBwtWVWmamTxgyIVPOA
         Rxiy1aKIN95mOFWYxeYjii6W76R9UO7OxiWXIknx3kn7eJpb+a+Yd4ORmGAtvfdpoC49
         X3DNmk0RVg1HYnCQT1pYUlIZKZr5eU0g4IibC27hN60Prl4sW3cmKKW8tmaD8GiQ+yeW
         ph4oeYOtSePZaH+dDPGypXgtJFtUWcfkHeJKer7UbiMlLAvtvX+/bhxp0zH3H+2AEmLm
         U02YBCQ1KArGbFCvbIhSU738YZr7/1e4V92jRF+nWHDJns1MrU9GOUgn3NA7zV/lo3WN
         dJfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OirvPWyIXir2GaJImkb/fUid8xpI91V6lGP/kVK2Qzk=;
        fh=rTReEQqpHQseyw3WRAXOTO/TY0Wa0P9oPeCdcGLjYxw=;
        b=OoZ3+L5nwsbBACtL0g61xqWxDL1ZkNRV8DQUgkSoFZPnEEjHkzkqMzwEw5cfvJqA0A
         qEIR7hyKU6+8zQ28Za4ygoIk5EdM+GiTFoaihZ7ZA7+rdQKtilJaMq7IWH96eUNnYP46
         ELts+lFyLZEWxkNBGwjV34dXixAkxhtzECbnAuoc9YZ7dOCzr/rb71L9mPijOEH8mH6x
         xwyEb5FxGz1t/YYIYN7hKJj9p4Hbi7aUifVFNiNNk7dgAXa/fxaQwnmDnVaFE7Rniaax
         M1E64KDbf/BiZdA/2eaDh/c2TMY7zAD0qtSRKX7zSREsPQrHeuHZP+QmMh1ZxmAN1l4C
         oqnw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R14F7Akq;
       spf=pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x22c.google.com (mail-lj1-x22c.google.com. [2a00:1450:4864:20::22c])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-550e6f78de8si162041e87.7.2025.05.20.07.57.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 May 2025 07:57:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c as permitted sender) client-ip=2a00:1450:4864:20::22c;
Received: by mail-lj1-x22c.google.com with SMTP id 38308e7fff4ca-32805a565e6so55866731fa.1
        for <kasan-dev@googlegroups.com>; Tue, 20 May 2025 07:57:12 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXtFeK0ddWEG7Tkm0w28RwB79n2BezrI0LwSD1gulvYfkCvSHxQVAMHFmDMwPnRbYmVi4YW/h0eJEg=@googlegroups.com
X-Gm-Gg: ASbGncsd9JUSxcDDIyMo74JL66q8HwAReQL0GgvwaqMjIvqZsTRZO+MtmV4vC5Tw2RJ
	9JsjI2O0d9AXH4gzJ2yw+YYwMqgpulMklFLyO/3Nrm1g5pKE0WxPgcbCApjdc+EiszNQtJbG48j
	z8jnUygXCyHgOPxKp17WumBhAEZtvs/OIJS+0bvb7LooHnNmu/i0hVpWhzwlzzhhnakRRNtz3Ou
	1lkBCRBs+1y
X-Received: by 2002:a2e:bcca:0:b0:30b:f0dd:9096 with SMTP id
 38308e7fff4ca-327f8484885mr66095551fa.12.1747753032039; Tue, 20 May 2025
 07:57:12 -0700 (PDT)
MIME-Version: 1.0
References: <20250507133043.61905-1-lukas.bulwahn@redhat.com> <20250508164425.GD834338@ax162>
In-Reply-To: <20250508164425.GD834338@ax162>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 20 May 2025 16:56:59 +0200
X-Gm-Features: AX0GCFvIRljugCIcQbtSXjz8NxSFlDDJZ4BA92IeoXfPnXvtaGyqWo21owy367U
Message-ID: <CACT4Y+a=FLk--rrN0TQiKcQ+NjND_vnSRnwrrg1XzAYaUmKxhw@mail.gmail.com>
Subject: Re: [PATCH] Makefile.kcov: apply needed compiler option
 unconditionally in CFLAGS_KCOV
To: Nathan Chancellor <nathan@kernel.org>
Cc: Lukas Bulwahn <lbulwahn@redhat.com>, Masahiro Yamada <masahiroy@kernel.org>, 
	Nicolas Schier <nicolas.schier@linux.dev>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Arnd Bergmann <arnd@arndb.de>, linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com, 
	kernel-janitors@vger.kernel.org, linux-kernel@vger.kernel.org, 
	Lukas Bulwahn <lukas.bulwahn@redhat.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=R14F7Akq;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2a00:1450:4864:20::22c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, 8 May 2025 at 18:44, Nathan Chancellor <nathan@kernel.org> wrote:
>
> On Wed, May 07, 2025 at 03:30:43PM +0200, Lukas Bulwahn wrote:
> > From: Lukas Bulwahn <lukas.bulwahn@redhat.com>
> >
> > Commit 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin") removes the
> > config CC_HAS_SANCOV_TRACE_PC, as all supported compilers include the
> > compiler option '-fsanitize-coverage=trace-pc' by now.
> >
> > The commit however misses the important use of this config option in
> > Makefile.kcov to add '-fsanitize-coverage=trace-pc' to CFLAGS_KCOV.
> > Include the compiler option '-fsanitize-coverage=trace-pc' unconditionally
> > to CFLAGS_KCOV, as all compilers provide that option now.
> >
> > Fixes: 852faf805539 ("gcc-plugins: remove SANCOV gcc plugin")
> > Signed-off-by: Lukas Bulwahn <lukas.bulwahn@redhat.com>
>
> Good catch.
>
> Reviewed-by: Nathan Chancellor <nathan@kernel.org>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

Thanks for fixing this!

> > ---
> >  scripts/Makefile.kcov | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/scripts/Makefile.kcov b/scripts/Makefile.kcov
> > index 67de7942b3e7..01616472f43e 100644
> > --- a/scripts/Makefile.kcov
> > +++ b/scripts/Makefile.kcov
> > @@ -1,5 +1,5 @@
> >  # SPDX-License-Identifier: GPL-2.0-only
> > -kcov-flags-$(CONFIG_CC_HAS_SANCOV_TRACE_PC)  += -fsanitize-coverage=trace-pc
> > +kcov-flags-y                                 += -fsanitize-coverage=trace-pc
> >  kcov-flags-$(CONFIG_KCOV_ENABLE_COMPARISONS) += -fsanitize-coverage=trace-cmp
> >
> >  export CFLAGS_KCOV := $(kcov-flags-y)
> > --
> > 2.49.0
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba%3DFLk--rrN0TQiKcQ%2BNjND_vnSRnwrrg1XzAYaUmKxhw%40mail.gmail.com.
