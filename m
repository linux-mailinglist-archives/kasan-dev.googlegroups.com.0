Return-Path: <kasan-dev+bncBC7OBJGL2MHBBX6E7T7QKGQEHQYV3BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 92CD62F5025
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:40:01 +0100 (CET)
Received: by mail-pl1-x63f.google.com with SMTP id p19sf1554619plr.22
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:40:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610556000; cv=pass;
        d=google.com; s=arc-20160816;
        b=iYP65MQ202Uh44K8IRCc3Ao7GPFV3cVezUlMWXrCzv7EUyvN7pmoJNqa7hrCGemJFA
         qN94RkIJ84nZmZp0qsZEBRHA+s+RAyXL5N7zxYWUtV5jPZphXoOSATBfx/j7qcPUAYG4
         FqjjmXaDAGovgs3JImgnssHDmLf3AUBQF2qe7HtzDfG0ya4RtiPykO9BnolLJkh3Rtgl
         NZOqq0fAUieVeP6iWcI1skcpJDvgRik2VDmtmruTBnkltb8d2P+/5uJlHY700M4vDSYw
         MFTEgV0dLzwWTXAe5ne2fGgkJEsJDNWbqhsyBmK4QAf75uwuu0n33fzfNtuRdTB0cpoS
         5c8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=r9q2j6fRXaHoPkDdg9rF7HOzt4/dXN5xywlFi6tNaHU=;
        b=PdUo/jgKwXV/52oxS2whl7Cu8it8gwrfXh4Obo/C92Th5pAUVrKZwQHHdflnsNQkqM
         POJELSvBXmePtxzM/+cEcbjNSGUy94bStR4Jk8RO18+LFd8aZ8bA7BO+6sldVpoPjW6X
         XnYiaDjxhd/l7BYdvrXU5bbkOpW8lYxh7E+p4KLZ558zVk9XixII5oiWlHQc24eBXgqt
         6Px1+ofOo88l5PLKl51TZs66alQJlwwTEJMZ9kprlsFMD7rdQ8YSF254AR0CgoAaToOI
         Fwv3qgjmBiIzURnAaB7Pbfk84DQU51OIfVkvQDlRSfRp5/3AjZKP/Se8PEAjRcSBGqu1
         ysIw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SWJj7egF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r9q2j6fRXaHoPkDdg9rF7HOzt4/dXN5xywlFi6tNaHU=;
        b=EVUkzjuxk6Xsa98bneM36TKSZJXk9QduS/5hI58vEc2edgL6ctBHQYtnKL93pRHbkX
         LL4eY6o7CUjGGwERBVXIS0xdQF4sKuchWWtotpzE8XVmzmBUyFtXnXylDFYOilYzrvKC
         tAypY8OvBictNlBBhbsb4nAyapQVC65PbqToHWKA5YnD/kQewsr8QiEtKjGfV3U28gsT
         THT2t2fXtMpAJb8FmwN61MYGB2bC2RDRQkljDYXcvdtYu6TnPGaqfHqtEsN5dzHqItTL
         LAbApzmq2uiSf3ZDVQS9KtUjkxoiqzEZ7B0Zpw82knu7I+ztrYpaFuTUtLin8mthWmQz
         Ae0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r9q2j6fRXaHoPkDdg9rF7HOzt4/dXN5xywlFi6tNaHU=;
        b=gLZnYOpghONLEOkZDnJna98hi8Ne6Od9YpvlgGHLI2GNSaGfwXPOtpGpCy7uIItGNX
         8JSK0TYi1hpFrefsklxBhHJDT8/dG+mQDjoMb21v7DuCsIqDPv1XRwoNieGSpkTC7SiS
         QokU1B4ZGhbV8hcMzoXePCGsAdwdXV/z5/slo0ZRMTfPjsSUgVnmSUdIbivBOUoWzpel
         6Yw+4sYQ0iWER1imVLbWltT0QrHWtCtRKyc7wRrrrHyhFlJGEmq7GiFlHCDlqRmRHQuX
         i7V8rW6+Gso6EpnRz+FDwsPFaOxHLHEv6XKcapJ1S0tdP9XiF4/FBYDmL8jX7UJ+PZ4I
         542A==
X-Gm-Message-State: AOAM533QY4ws2gtyfFTPgJdd1/mWcFiTsUxQ8JzSAQuYPBYOq4CqIJb2
	FVGUbNdQEvhkMh2nsiUI9sA=
X-Google-Smtp-Source: ABdhPJya8S5vvSM4OWNSNmXemrNDtU5H682w3wI+hvDgAVR+zfOvw2IGF6PneE1MKOMuRDc/YDGUig==
X-Received: by 2002:a17:902:a5c5:b029:de:30b0:f1d with SMTP id t5-20020a170902a5c5b02900de30b00f1dmr3230459plq.1.1610556000087;
        Wed, 13 Jan 2021 08:40:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:959d:: with SMTP id z29ls1076900pfj.2.gmail; Wed, 13 Jan
 2021 08:39:59 -0800 (PST)
X-Received: by 2002:a63:1110:: with SMTP id g16mr2818233pgl.357.1610555999325;
        Wed, 13 Jan 2021 08:39:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610555999; cv=none;
        d=google.com; s=arc-20160816;
        b=AbBfoCirEKNjQSmOc4f2w3yhITXNTHZK+GCGaUJ+HlWF7HXzndljisdyZ4dROxWgbG
         TwXH4R2416423r2EA8X4xTFZOemgcobCoP+FN0vjx6KWHcgRZAJiiMnotBFochmGesoN
         FPIboNcR1vwsQeDQO7NwGcwwFTHZ9ZI1nDWqG9qVHrocxuEmgBMhNI2Ub2bVFiJ7hQwo
         PGF7DbMFlwZLjiWi5PwcEnpvtpytdrhwO702sytXmERIwv/q2TVcX8frMILAy7WtYlha
         pV5bZ+EsOZ8JkiaFkbpZD/ztFrvLssoNMrJZ4QqbspOAAFqKfy86C4ff5CxwcX4WZVW0
         rhKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=718zcsFUzGW3JK8wqJnAiFUqkREV/jlMJotq/sE7w4Q=;
        b=VIqnUtFDjS6NLCWpEhI6LQV5QEFgnfQkCdfuWKsxbW8Aeiwm0OEx9wl4dfj042SfRc
         A+8n27jS6q1bVWtJF0HS8vQjLczwPkAo+wtoFJj1OZ314gxHMFBHKA8+ps5dHNJO5NTe
         8viHnl/vPMpZO45vanmI28K1hAETmxstr191byHy8HfQKPWJ8IZeZcm21JZEY7KtM5ay
         1GxtOHu2A0zoDUrVymt4L06KH/OIKZ7FbN9IDgD2t20EcivfhykXB7+hfDS+WJQle3kL
         ausxshB/UOGDHjKn0/WXyV0KkFA2oz/cbWfF8yMfHd6TOTxF8P1vakvr1+vUvbeXXnhT
         YluA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SWJj7egF;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32e.google.com (mail-ot1-x32e.google.com. [2607:f8b0:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id j11si161566pgm.4.2021.01.13.08.39.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:39:59 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as permitted sender) client-ip=2607:f8b0:4864:20::32e;
Received: by mail-ot1-x32e.google.com with SMTP id b24so2505181otj.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:39:59 -0800 (PST)
X-Received: by 2002:a05:6830:2413:: with SMTP id j19mr1862383ots.251.1610555998526;
 Wed, 13 Jan 2021 08:39:58 -0800 (PST)
MIME-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com> <654bdeedde54e9e8d5d6250469966b0bdf288010.1610554432.git.andreyknvl@google.com>
In-Reply-To: <654bdeedde54e9e8d5d6250469966b0bdf288010.1610554432.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 13 Jan 2021 17:39:47 +0100
Message-ID: <CANpmjNPOtohFy800icx1LU_hzuQZNMQqqTBUSDXZ_9wWO_vHWw@mail.gmail.com>
Subject: Re: [PATCH v2 14/14] kasan: don't run tests when KASAN is not enabled
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SWJj7egF;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32e as
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

On Wed, 13 Jan 2021 at 17:22, Andrey Konovalov <andreyknvl@google.com> wrote:
>
> Don't run KASAN tests when it's disabled with kasan.mode=off to avoid
> corrupting kernel memory.
>
> Link: https://linux-review.googlesource.com/id/I6447af436a69a94bfc35477f6bf4e2122948355e
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  lib/test_kasan.c | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/lib/test_kasan.c b/lib/test_kasan.c
> index d9f9a93922d5..0c8279d9907e 100644
> --- a/lib/test_kasan.c
> +++ b/lib/test_kasan.c
> @@ -47,6 +47,9 @@ static bool multishot;
>   */
>  static int kasan_test_init(struct kunit *test)
>  {
> +       if (!kasan_enabled())
> +               return -1;

This should WARN_ON() or pr_err(). Otherwise it's impossible to say
why the test couldn't initialize.

>         multishot = kasan_save_enable_multi_shot();
>         hw_set_tagging_report_once(false);
>         return 0;
> --
> 2.30.0.284.gd98b1dd5eaa7-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPOtohFy800icx1LU_hzuQZNMQqqTBUSDXZ_9wWO_vHWw%40mail.gmail.com.
