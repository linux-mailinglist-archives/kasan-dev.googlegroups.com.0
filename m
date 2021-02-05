Return-Path: <kasan-dev+bncBDX4HWEMTEBRBFHD6WAAMGQEV4N23BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id EF71A310DD6
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 17:25:57 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id f7sf5631638qtd.9
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 08:25:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612542356; cv=pass;
        d=google.com; s=arc-20160816;
        b=rYZnkjj5OHiHs8nOEE9ayD8qqTi1HiW1xMiAl9P1rBAdx3r8Q7GtZ5e3tcWzG8xdof
         ErPxsZxOyMghNwkLxVHZH3S/hbmmoKIdTLVytZfum5EOLe2JgrHLhX25YgKf+lVOiKpm
         atn0xM0y2SG/J14iTfKmisbRgTwkiWpx26OhYsyexRPrgAauRkhq8Au9uh1lsaVWDX04
         WTG2NJk1F+omFhkakn4ar7iSvuokHL6/vzSarimhx6C5dGwG11sI2P+AIDVlPzozTT2j
         LYGQfUSjys60hch38HxuvyY+ADY+VgAs9HknzBu1r7F9NMtF/x2UAat6bnDxh4Wc8tN9
         mZ3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5VGHuiqgdU3isGoKR1KNaoby5Tfv3jDR8aTfI2XQPyI=;
        b=zHpK1AJPDmthzRRcC+8YUE/OE5Chefax6lJfqa+B63DO9ClY6yV2vKX8J7wUzUwq8k
         XXp3rwId7vG+taijQ87W6bUZduN/eYgtGyIhBUH9XVOAtMtFtvpwPDwGdu70cUmnPHwt
         qeSRjOHYtv6yo4ZLxMOmHvaTi2c/ulTEFHQBob2NvhqaKbnO8NkFZ/qLXmFVk/TNTrBn
         w8LvfWTviC+e4+GFHLo75XHTEobzx5rqYY58CPTMSK6LT0D8gFKuVbbu1/Ljh22i7q6z
         MXYc012aTPQxBfkjU+DdkhL8w0VeNDrtV++DLZwBHDPekm2BMR1VqDLiuhIKQEKKIGes
         WN3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YWfA2TQ5;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5VGHuiqgdU3isGoKR1KNaoby5Tfv3jDR8aTfI2XQPyI=;
        b=Jcl4/WzkSaYFqOeYSMtVVkzO3NOeOjIRJLSmYnurxPVpiuBxRlu1JaopEJyISEeUTK
         avdUp8sa5yriUN3xD4Ou1F5ZysMVmUiYw8jVwKys5b7TMPtTxahfDVhQ4mYYZ11NQOA9
         xdHbfhoDr2xapw47bFKdnWt1lb0YzLr69O1fQDeLBMhj1CGnjackXIJD46LCvwerU1KK
         9V+eJpZJS8wgREVWtwilXBRAKMXuT0zKIaZR4z/7G4eagjzTdYCE6jWwouP9C1uPkJVu
         qUc2F9jDH2hWnYiyvTbrFTiMzj31O0Iswx+cr567Jjq0h1UV0GvPRx2CAE2JAHqnhB+M
         14LA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5VGHuiqgdU3isGoKR1KNaoby5Tfv3jDR8aTfI2XQPyI=;
        b=V4T3QOuYi8GAbnWVR1ReNPi3gxe9uJGWY+Ou8nSmVyleV+UitOgL2xHwf8egfeJDdr
         1EXAEyiuzJVCQ0pSja1V01tP8lXvHumrSet9iBLiOYu9WGj1pfi6RxtdqfufTgyJdcGN
         LD9ajo4tjdjhz1D+2Y1qua2Zn4EqHqOgVBIiN+zgsFs3xbe3puwq4HvlKbzvxxs24SSu
         XRmotHXkVtZBHjdr1dQTRXHX6vJYLSJmS2DevJnYkci/+zY0sfq8OH57CeiJQmOgqT8U
         qn3m08bYEXq3nYa0WiQPQBQjo2+hZEVmk7Q1kg683bqLLokaRIUFJuHX2h19Z4OKEGoi
         l2nw==
X-Gm-Message-State: AOAM532VPsbOTXYPRdF2ld2+aZ+mpEPC1It1eLT/irIARdHbkbQrhhlx
	WWolf3sqzvTFMkb3V5IAGUw=
X-Google-Smtp-Source: ABdhPJz08faskTVRha7/rl7w+55lVxI86QVp8GbfGRUHzmgOcHYSmG0WVdJ/m6uRWVOy7uvrcQbADw==
X-Received: by 2002:a37:618f:: with SMTP id v137mr4908096qkb.461.1612542356784;
        Fri, 05 Feb 2021 08:25:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:fa4f:: with SMTP id k15ls2317881qvo.7.gmail; Fri, 05 Feb
 2021 08:25:56 -0800 (PST)
X-Received: by 2002:ad4:4b2c:: with SMTP id s12mr5092064qvw.21.1612542356420;
        Fri, 05 Feb 2021 08:25:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612542356; cv=none;
        d=google.com; s=arc-20160816;
        b=p9HSbLXnZjJYjdmyE+mHvJ6oMS6aYsvCINIExXL+j3uEfWrpH4RvHUJZVDjsluWzBY
         YiqX2kuZ6SyFtyU2qGmcHWJpe0/WYdnhoWpjtKgs/3LCyaJ1xonEg7cj2EZGDwiMNcWj
         2/HzO4M1XQ+mOp9fUs83SAxKLnvKnitSIdsui6nqvgTLNF6adt6fHZ2QW1UW95H0RJVt
         Jcl2D0/4gkwf9NiZ04ZC/Jtoq8BLNZMp6sGsxFr/seTUeIQxkZasm7NjCEZZMOducfZG
         Al6FjQ4sXa7nyvliFgnr7CAxTogzY/E5hTTVvGOMzyvvhRNeSrc6nk40DGsCnqP6Jwhd
         dEyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RAV6woYg0kfqY+8ibsodS4//9eDsxI9wZiwPSoFnDsw=;
        b=BlXk6bBhIQLMjRmRAU3OVC8JQK77jPfykb4/X9NEIJABr5oFXCB7rU435hN5DJ64HT
         g7EoF0z3anoJhCOLyfY4PobWs5USuBveXFr+DaizMpWVgsoP8+FesFekeISBwaUiLtSO
         eHJe2pI9gmV2NaLvFO4OX1AlX8MFSJJRuZVXQGVKbBMuhnJW/wRoEL+XGft4IkTsz1ax
         oyriQeSAcUBRDGr4vMuYiBbJecDjKc6G8kxuJ4ZCNxC/JwMvMgY/Nexdge6+CdO0OKxj
         HBwtLQxJeHXJWqRJg+sYO+WBbZql5OKIyjNzZ/V9zT7GB/Tx0uS9voLX87kO8l566p60
         Bt4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YWfA2TQ5;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id u4si486685qtd.3.2021.02.05.08.25.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 08:25:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id u11so3793802plg.13
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 08:25:56 -0800 (PST)
X-Received: by 2002:a17:90b:350b:: with SMTP id ls11mr4812469pjb.166.1612542355340;
 Fri, 05 Feb 2021 08:25:55 -0800 (PST)
MIME-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 5 Feb 2021 17:25:44 +0100
Message-ID: <CAAeHK+zv7U_oN1WVqQNhorL4Gf9G-hFb120o3XFO9RDtY7TEpQ@mail.gmail.com>
Subject: Re: [PATCH v2 00/12] kasan: optimizations and fixes for HW_TAGS
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YWfA2TQ5;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::633
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

On Fri, Feb 5, 2021 at 4:39 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> This patchset goes on top of:
>
> 1. Vincenzo's async support patches [1], and
> 2. "kasan: untag addresses for KFENCE" fix [2] (already in mm).
>
> [1] https://lore.kernel.org/linux-arm-kernel/20210130165225.54047-1-vincenzo.frascino@arm.com/
> [2] https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/commit/?h=akpm&id=dec4728fab910da0c86cf9a97e980f4244ebae9f
>
> This patchset makes the HW_TAGS mode more efficient, mostly by reworking
> poisoning approaches and simplifying/inlining some internal helpers.
>
> With this change, the overhead of HW_TAGS annotations excluding setting
> and checking memory tags is ~3%. The performance impact caused by tags
> will be unknown until we have hardware that supports MTE.
>
> As a side-effect, this patchset speeds up generic KASAN by ~15%.

Forgot to include changes v1->v2:

- Use EXPORT_SYMBOL_GPL() for arm64 symbols.
- Rename kmalloc bool flag argument to is_kmalloc.
- Make empty mte_set_mem_tag_range() return void.
- Fix build warning in 32-bit systems by using unsigned long instead
of u64 in WARN_ON() checks.
- Minor changes in comments and commit descriptions.
- Use kfence_ksize() before __ksize() to avoid crashes with KFENCE.
- Use inline instead of __always_inline.

>
> Andrey Konovalov (12):
>   kasan, mm: don't save alloc stacks twice
>   kasan, mm: optimize kmalloc poisoning
>   kasan: optimize large kmalloc poisoning
>   kasan: clean up setting free info in kasan_slab_free
>   kasan: unify large kfree checks
>   kasan: rework krealloc tests
>   kasan, mm: fail krealloc on freed objects
>   kasan, mm: optimize krealloc poisoning
>   kasan: ensure poisoning size alignment
>   arm64: kasan: simplify and inline MTE functions
>   kasan: inline HW_TAGS helper functions
>   arm64: kasan: export MTE symbols for KASAN tests
>
>  arch/arm64/include/asm/cache.h     |   1 -
>  arch/arm64/include/asm/kasan.h     |   1 +
>  arch/arm64/include/asm/mte-def.h   |   2 +
>  arch/arm64/include/asm/mte-kasan.h |  65 ++++++++--
>  arch/arm64/include/asm/mte.h       |   2 -
>  arch/arm64/kernel/mte.c            |  48 +-------
>  arch/arm64/lib/mte.S               |  16 ---
>  include/linux/kasan.h              |  25 ++--
>  lib/test_kasan.c                   | 111 +++++++++++++++--
>  mm/kasan/common.c                  | 187 ++++++++++++++++++++---------
>  mm/kasan/kasan.h                   |  72 +++++++++--
>  mm/kasan/shadow.c                  |  53 ++++----
>  mm/slab_common.c                   |  18 ++-
>  mm/slub.c                          |   3 +-
>  14 files changed, 418 insertions(+), 186 deletions(-)
>
> --
> 2.30.0.365.g02bc693789-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bzv7U_oN1WVqQNhorL4Gf9G-hFb120o3XFO9RDtY7TEpQ%40mail.gmail.com.
