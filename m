Return-Path: <kasan-dev+bncBDX4HWEMTEBRB77N3T7QKGQEVRZ3PWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 201E62ED451
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Jan 2021 17:29:52 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id n17sf4790135oof.5
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Jan 2021 08:29:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610036991; cv=pass;
        d=google.com; s=arc-20160816;
        b=O/bR9pyER+4Pjh7g7c/6oPNecEuaNaiLzusI7Q89DYlhBxV6wcs+1/9zk7w3reD4dQ
         8VgNJKw/AE807ImaturyHmRs5KC0QhLOPpd+diDB1R2Lofsn6sNi+7NsGYfOond9DTeb
         sdujjJz0/xkrBW5iz13LPbm4SBy7gp97RDnVTSeFBMMMgIjMby71q75rZcXucZSge3ho
         yV06C7ZAAFJm3Rz3MfHVInnoBot/FecljJCr5XxCEaOvKLVsWTTYgrIti8IBzohq2p18
         nxfYEDbfYq8nHtmHn9lB/eM3p9LC7OD66bmVzxCfiSLw8Mqrd1B9wpyCMzffXJZf3KDA
         HKYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=3rpfKOLhb4/9W9i19s4sB7ZLAMexXmqtop0/voPqrnk=;
        b=w0Ke0QvRxIrFy+yhzZiuaQSS3sYAAkvjjBRyqjRG5rqz95cSZEgP2peHeRNfQu+7U/
         dQzRpVYAF7+fIFomjhItIPA6kTy1MpwWz9RsvUD7aTxIXJDHBYyrJjZJST2dDqXRtz6d
         p6Oz+tmEalT2zX1Oa6CG9LPPP/IIHgkjyaRnBNSmAaxLzW9h2pBrGkD59JEbbnGxEh2g
         R0ppWTCWXP36AoLamC5ZgRcPOMjkVDvBBofMkHk14ond5aKacfCKgkK+FpyXjZOvQuxm
         zryTa06WGFj/1ij6W8NKt2ctyf5wm73C6Dr5THdcUmdZ9M/NK3h/11DvlW8+ESvP5Vt8
         ZNFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MNQpruws;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3rpfKOLhb4/9W9i19s4sB7ZLAMexXmqtop0/voPqrnk=;
        b=ErY27qHdisNpf/WAfT/zGwdcAXcxCw+o4k3t8+3GL8Rek6OPpyO4waQ9SVZQUyJDRs
         CF5/L1XHOy5ud9WJdqRyeF/3v2LFrbtZVNS81rPZhOUWNR3fMe24JilOzwQCpO72rzTp
         YQ9miYA+cvJVcNvEJnshlTAaQN420sf5+14/L73Y1brOVtNi8oel6e+d7abh6A0TziOb
         dDB6huxskfzqqxA7R16bIVpmBVk7EzdpfP19/3rO7TiiLUzJXmKBFVKVqhZqMq+ZTWmA
         Aj2H2M7bbEmxYjb9vvUWIAMvjfE5skK+nDDKSVJFUEwq/lhZCa8xg4lHZ1E8bWww8HvW
         WD8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3rpfKOLhb4/9W9i19s4sB7ZLAMexXmqtop0/voPqrnk=;
        b=VGvf0abF36fo1w2yfvDsJG0FO2F9/9ue4Tre2TcdhqLpr1ZAOBEQlm0ExhgHRhjDeg
         cd1FoRttHhWJxUsLgfT6YwBlEbinahVkflRec8y1l4Z5DkS1dB9w+LbvjVRPE6nRI0Qm
         yR/nFlio1UoUGfXOMNiNoAu50KY8o8ReGD9zXjSQNZ8ChEIUIUhqbRXKTW41nYq/RvJl
         cF0cNaWPGDVZTj748ES6h3/q4Z8oeEmaf8RvDDvPhZ+S8q+zkoajE60HaAz7rRDHMrKh
         j5vmK5U4OvalSMmcPaRHhSzcMLaTj92JXrWAeaRQBVyKzwEVtvRPYG8NRry+Bj4f2mcY
         SYtg==
X-Gm-Message-State: AOAM533S7EYOW/hsc/iX6H6310zjrgqYF4WAoVXJdkGgD/mq8EqT17am
	4HB4PDR2TyVcdVDkCUeRTao=
X-Google-Smtp-Source: ABdhPJyDprZdnsbuJlnVJRW1zUv67jsaYNSvC1VP9lyW0fj7PC3LZ5dSPbqygLtQfdKSFX69drFS8Q==
X-Received: by 2002:a4a:bc8d:: with SMTP id m13mr1619224oop.63.1610036991126;
        Thu, 07 Jan 2021 08:29:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2413:: with SMTP id n19ls1991223oic.7.gmail; Thu, 07 Jan
 2021 08:29:50 -0800 (PST)
X-Received: by 2002:aca:d06:: with SMTP id 6mr7100449oin.13.1610036990833;
        Thu, 07 Jan 2021 08:29:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610036990; cv=none;
        d=google.com; s=arc-20160816;
        b=ztjQpg9eTF4OnPjA0Uu/u7g1mV45sAr6CayskEJ6UmMyPUhCM9y4MiIBf4L/Cza1Qk
         5Qbe2ghzpFCBGhZQp5JLvVW96CqQhTNBy7exFr+dCFWIgB/V9i7sQV5ZTdYvSkz11dbl
         EV/SSIqfwaQpxpvYcRUBdOkfyzlJ6+4urAZQLf++aHz+9CtVt3rvPA7slEPs+OMPkS6j
         Q09bhjwIpICFqwWKahnopu/AcvDu/7py5VqGS2CV7vFBUw52WAgPq3sCN+WFwflRVuB5
         SHtWwDHM39ivgjKNMzdIVaAUJVXLOUGbR5/pTyA6CbliPxiOfZuZfYg6x2WRr8yjQEfw
         IY/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=FpXEjxjV8OA24pUWXj8gzsn1GWb+lIIbFcLAwI2yW6M=;
        b=oHwLb94AsMZfgbK0UFe/7YKEImsnUqhCr8Mtl0AnHh/pXuA2T1qMZJYDp9Uofg3a7a
         PA2A8P2avDwQxDJ1Lz8uwq9W500d96734Fhz5uRV195FVcOiBKs9JElGTHJ+uhF0FuCZ
         sblQ7XuadPNPcYnHQhgQjeGYqbvGqnAxlnXxTopiqmUCGoPDXChsLfesz3EY4ixOmNem
         H1U+hvhc5U4hrpIHVuP3JwXmorP3fhjffHZFIvfgb6Qk5OJfWRjXJh0fNlciymxDfly6
         w0FZQ563Txcn83oxirZ/cMWftUGFZK3Nnskxk77oEUNrMwTT8HnizpPFplrzv8M2NS5S
         YOBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MNQpruws;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x430.google.com (mail-pf1-x430.google.com. [2607:f8b0:4864:20::430])
        by gmr-mx.google.com with ESMTPS id s126si507540ooa.0.2021.01.07.08.29.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Jan 2021 08:29:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430 as permitted sender) client-ip=2607:f8b0:4864:20::430;
Received: by mail-pf1-x430.google.com with SMTP id 11so4181440pfu.4
        for <kasan-dev@googlegroups.com>; Thu, 07 Jan 2021 08:29:50 -0800 (PST)
X-Received: by 2002:a62:2585:0:b029:1ab:7fb7:b965 with SMTP id
 l127-20020a6225850000b02901ab7fb7b965mr9501125pfl.2.1610036989989; Thu, 07
 Jan 2021 08:29:49 -0800 (PST)
MIME-Version: 1.0
References: <20210106115519.32222-1-vincenzo.frascino@arm.com> <20210106115519.32222-3-vincenzo.frascino@arm.com>
In-Reply-To: <20210106115519.32222-3-vincenzo.frascino@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Jan 2021 17:29:39 +0100
Message-ID: <CAAeHK+xuGRzkLdrfGZVo-RVfkH31qUrNdBaPd4k5ffMKHWGfTQ@mail.gmail.com>
Subject: Re: [PATCH 2/4] arm64: mte: Add asynchronous mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=MNQpruws;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Wed, Jan 6, 2021 at 12:56 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> MTE provides an asynchronous mode for detecting tag exceptions. In
> particular instead of triggering a fault the arm64 core updates a
> register which is checked by the kernel at the first entry after the tag
> exception has occurred.
>
> Add support for MTE asynchronous mode.
>
> The exception handling mechanism will be added with a future patch.
>
> Note: KASAN HW activates async mode via kasan.mode kernel parameter.
> The default mode is set to synchronous.
>
> Cc: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will.deacon@arm.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/kernel/mte.c | 31 +++++++++++++++++++++++++++++--
>  1 file changed, 29 insertions(+), 2 deletions(-)
>
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 24a273d47df1..5d992e16b420 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -153,8 +153,35 @@ void mte_init_tags(u64 max_tag)
>
>  void mte_enable_kernel(enum kasan_arg_mode mode)
>  {
> -       /* Enable MTE Sync Mode for EL1. */
> -       sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +       const char *m;
> +
> +       /* Preset parameter values based on the mode. */
> +       switch (mode) {
> +       case KASAN_ARG_MODE_OFF:
> +               return;
> +       case KASAN_ARG_MODE_LIGHT:
> +               /* Enable MTE Async Mode for EL1. */
> +               sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_ASYNC);
> +               m = "asynchronous";
> +               break;
> +       case KASAN_ARG_MODE_DEFAULT:
> +       case KASAN_ARG_MODE_PROD:
> +       case KASAN_ARG_MODE_FULL:
> +               /* Enable MTE Sync Mode for EL1. */
> +               sysreg_clear_set(sctlr_el1, SCTLR_ELx_TCF_MASK, SCTLR_ELx_TCF_SYNC);
> +               m = "synchronous";
> +               break;
> +       default:
> +               /*
> +                * kasan mode should be always set hence we should
> +                * not reach this condition.
> +                */
> +               WARN_ON_ONCE(1);
> +               return;
> +       }
> +
> +       pr_info_once("MTE: enabled in %s mode at EL1\n", m);
> +
>         isb();
>  }
>
> --
> 2.29.2
>

Hi Vincenzo,

It would be cleaner to pass a bool to mte_enable_kernel() and have it
indicate sync/async mode. This way you don't have to pull all these
KASAN constants into the arm64 code.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxuGRzkLdrfGZVo-RVfkH31qUrNdBaPd4k5ffMKHWGfTQ%40mail.gmail.com.
