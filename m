Return-Path: <kasan-dev+bncBCCMH5WKTMGRBJMUWD6QKGQELDDETDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id B57472AF596
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:58:30 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id 190sf1698328pfz.16
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 07:58:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605110309; cv=pass;
        d=google.com; s=arc-20160816;
        b=dPfhRZkZ5xsGFcu1bXa/M5cNakgI2ByCxV/QGwyC/A09OeXjI60GyanqM7xwvmgpzI
         cDroNO5tSh5c1Jvlp4XqH8+ELsKp5BJd6WiReBKvWDCzL87LmehVq3OA/YevrgkIBxtS
         oGg6TAXFEyw6pZg9Ww4RHob9Awuz+DE4BCJPj+YwdxTHPStDah7Nc+ezabFzK8ucC0oB
         rKClYhzPWnx5u+p6DAIO1xaejNfl847yBIzaXRRLJ+67mp3LixgUc+Zfk2qpg6cwuc+D
         3r9qrDFyo+BmMotO8lfIFQxCCRM09OjqxUzqOGiLcrli1SUCBqxdQ029n01f97T3lLS2
         vbuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=I3zU0uyeK1+TjGZMH+L229+sYUIPo7JlHHFm+Qxs7XA=;
        b=T15QGt8wEAE0maWo+dHNISuT6MKi3gD6FBVSPEuSDG7u1s7m4QMgLmptHDFYNLTUDq
         ApfC4sBwvaL/HDWsVUX/AJ0bny54fGuim2uWs8wjFzWowTXPWTNO6SYlcm+VV6MKXkU/
         8N/fD3JSrHV1H2tqkO7XKzE32LXPR12I1IXB6NyhjmaTVHmSgh7k3aC2t26IT019uCow
         xtNwPzhRxYuCmlSLh7RULwsE0Yll6VSBOP6Ok+3zT7huNRu+z10SwDiEklEKdpc3gYjg
         7dBqC50EGD3l74RQv0wXqfRSx1h3i3VzCDz0guBZZo7XmkqAnCSS5SC51KT0tEkoW9Tq
         a2JQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=COznLUbd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3zU0uyeK1+TjGZMH+L229+sYUIPo7JlHHFm+Qxs7XA=;
        b=raSxWmCkvMmzr1xRnf6gBmIDsRQTEZ8hcg/OfeZnlVdBMAhWyETkCt9puUoW7Ln98r
         4pwunSpvv2dPJAlLzVOdVeMCFh5xOPKG5Wilo+L9HgIx9O7cam8FN6j8ihZ2THjORG1x
         gD+Dn4P6q+2gCTv3Dt3JsDKVyYng1AGtC9ywToQ/BJ6DkWJubMmsMkyXlXXlP5VahLeq
         y2S9D4rTBoTPSztUf8NgiAFLnJTrfkdn98FDagr08+GIyvLGjRl+HRGY9GT8EPHlkNnh
         92riRA0WbnhJE9a39OjglpIlk5xEUdRfqgeBN6srAmIG8tjTQA787PE6ll3C/zJ3ajyK
         G/Rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3zU0uyeK1+TjGZMH+L229+sYUIPo7JlHHFm+Qxs7XA=;
        b=Ls+iXTWqViUSzCFZa3tn2duLyF2Eaa4PfPffMOJbVfi2yGrUdLkyeoXzVJrH8wW/IC
         TxJxoilTsgVYQn63XdH3Tj6yKm0j1OR6LT8eAN5SYqTevwgZ6FljvJWHnEZGN4/jy8vm
         xVxg9txZ2WTHxzcNCf40RdqJ1wVUesLP0AHr5tGfTp6Sb6hOzylx/ImZ2kiSqjo8a0Nt
         B5EXmLvpdinOo3lnzu2cFAR7LiF3+KjgYnbD1xvCN8fRiJ5VMil5dfOm3fxbCN4preaJ
         CE62sPDzmvbKIBukWrUuUBb/6Xbya2ZLq9hQ8fQ6QpeewQVFRuPv5iW2Eovk3PWKi+ka
         Ycow==
X-Gm-Message-State: AOAM5307aGrGdUALWONkFFGB8i+NWBpPxn5eh5u7aGodA21DANwsFoDV
	EmQfxuYSKaKmhYyHZS6hzSM=
X-Google-Smtp-Source: ABdhPJwd/eQ7I3prsfKC34aRD5IVZPAm7sNSslCUTwcdpPCJMeb8pCtk6QRrcTuBUK8BUsHr1Kb8GA==
X-Received: by 2002:a63:f146:: with SMTP id o6mr22340394pgk.107.1605110309393;
        Wed, 11 Nov 2020 07:58:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b086:: with SMTP id p6ls71151plr.7.gmail; Wed, 11
 Nov 2020 07:58:28 -0800 (PST)
X-Received: by 2002:a17:90a:d301:: with SMTP id p1mr4582803pju.49.1605110308887;
        Wed, 11 Nov 2020 07:58:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605110308; cv=none;
        d=google.com; s=arc-20160816;
        b=XLcWKQgjzL7DkpwjVacNIPmsGjx4RUFs0y1mqRTaAxjI3mdM32Nv3NevOlGNHh54Y8
         dkvmhagjijgbhaJORVesxzCWsc3pADe4RegUC3goJK6OQS7oygk+qDq6OutonkxFMvxg
         EXwqNZvLMe13HQ2EO0TDbCiKWesp/vhLgybttZa+3m9NYZRWw+0BOp6BH/utUCMg7ioC
         TRw68i83EZV3cxiOew6EO8shSD5P+k6tM/dgVtGm2oXb7udNjjSim4d+Ig2j4tr8JFSc
         yMZnjJ/BW++6LeEDDu4bN290SQ+F8Rmk2gtpMLB5mdkyF5+kUGJKgmnUD/84owAjvErb
         jImw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DPphamhndc5tA5oV0qBp8MU+hvUN5gz++nbj/D+WAKU=;
        b=VJSTLYDI0Uz7H/WEW0tQEuTwSB1B3fOYXztohZOIJb+HKI0ZjmWYGeEtMCoarli0+P
         VPInOGvLDK0wCmAtRQOwRcAI/Yw3p0E9vRIXxFtyZ53NjbTLS2EbSGim0HIrTjJoZm4t
         bBZLDX7nhYeG44lPmtuH5PCu5KrdK2/B9x6DJP7VRzm2b+45woy+JGIbQ+lE/KVGQWMO
         R52rXhKIHs98KAj8SD1A2FkEhkPjS9p+BDYzNTWiCCLEhOPwpZoJ/MtyQPGx20HtZi8d
         VnZWJ7Ssd/TEOxcng26XC/byb2QFXsK15/6ll7bXRcukLdMRc0clSr2W04BMBvEyV7pM
         U7gA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=COznLUbd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id 80si179143pga.5.2020.11.11.07.58.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 07:58:28 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id n63so1604955qte.4
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 07:58:28 -0800 (PST)
X-Received: by 2002:ac8:364d:: with SMTP id n13mr3306339qtb.369.1605110307801;
 Wed, 11 Nov 2020 07:58:27 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com> <55d90be0a5815917f0e1bd468ea0a257f72e7e46.1605046192.git.andreyknvl@google.com>
In-Reply-To: <55d90be0a5815917f0e1bd468ea0a257f72e7e46.1605046192.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 11 Nov 2020 16:58:16 +0100
Message-ID: <CAG_fn=V1Pu1NED5K6rJJZ5ufeQwrjN_JShO4m_V=gbLwry7cyg@mail.gmail.com>
Subject: Re: [PATCH v9 25/44] kasan: introduce CONFIG_KASAN_HW_TAGS
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=COznLUbd;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::841 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 10, 2020 at 11:12 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> This patch adds a configuration option for a new KASAN mode called
> hardware tag-based KASAN. This mode uses the memory tagging approach
> like the software tag-based mode, but relies on arm64 Memory Tagging
> Extension feature for tag management and access checking.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Reviewed-by: Marco Elver <elver@google.com>
> ---
> Change-Id: I246c2def9fffa6563278db1bddfbe742ca7bdefe
> ---
>  lib/Kconfig.kasan | 58 +++++++++++++++++++++++++++++++++--------------
>  1 file changed, 41 insertions(+), 17 deletions(-)
>
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index ec59a0e26d09..e5f27ec8b254 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -6,7 +6,10 @@ config HAVE_ARCH_KASAN
>  config HAVE_ARCH_KASAN_SW_TAGS
>         bool
>
> -config HAVE_ARCH_KASAN_VMALLOC
> +config HAVE_ARCH_KASAN_HW_TAGS
> +       bool
> +
> +config HAVE_ARCH_KASAN_VMALLOC
>         bool
>
>  config CC_HAS_KASAN_GENERIC
> @@ -20,11 +23,11 @@ config CC_HAS_WORKING_NOSANITIZE_ADDRESS
It might make sense to add a comment to
CC_HAS_WORKING_NOSANITIZE_ADDRESS describing which modes need it (and
why).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DV1Pu1NED5K6rJJZ5ufeQwrjN_JShO4m_V%3DgbLwry7cyg%40mail.gmail.com.
