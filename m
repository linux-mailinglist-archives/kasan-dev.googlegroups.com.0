Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5GWXOHQMGQEZAMKNVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 159884987E9
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:09:58 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id q21-20020a170902edd500b0014ae79cc6d5sf3750425plk.18
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:09:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047796; cv=pass;
        d=google.com; s=arc-20160816;
        b=YPo75Q/5l06ncFEhHZC73rVyt9hnFC0SiseQKuskLV1Dq55oiOsG7W7+eTFOTRKGR8
         pz9L77pxUe2OAMPLzAi+aV8UNNk3qBHvhrkml2UePXj9kYgdnAb+EU5AAH3KxG6XKvSq
         QcghHK8wz2rwY63CE4fwNLkwt+nl2Y9evVUhUgJuuO7gW4CsmNA84n/Julr2EbJhIUAW
         t8U5h1ovFO6EKOfCymFg1UB4ARBeXipYecwKj+O7Vv0vRik79BIwOV7owF0NhVvKEq5N
         siJlSm93lP2pYNQRFV7Deq9KWfiVyJq2LXOkYslYM5NvZRkPEIZlvOu2jXRCLLsCmLmD
         p+jQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5xQg99H8OKZVXILGjhW2KOvokImVA4M5OtXykMLHoZQ=;
        b=HCFEt/n9DuzxQtU292y9i8LBmRK1s1I0/sCJyOVMIvFq+sMKyj2/oiOE4igy87rrv8
         ztzpxGgDM40RsrHebJ59vE9UI0hPXcLT4/rMAKeyetpKaY/P78gKDjK5fsCj1reXDq9t
         bureOU7idrlmBELnXQrc1kvO+pvN5d1PvL8ix+piLzGFnd5Q5MWimfaTKHT/FgDc5PLB
         6gSFbgpa+supUMoO/ioxfwMWRr1yM3PYPfLEGZ3VzPTPuAo0yZABMT2mkVPzyqsGdnYE
         +Cr62zQAE7mzUhn4BoOsJltWEmzyJ87eNUirQC4QaNlZA7NnqzgdQQbw5XDOHtMLK4rT
         DnNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YkS6CDPg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5xQg99H8OKZVXILGjhW2KOvokImVA4M5OtXykMLHoZQ=;
        b=lELCWxXiSudpkxK3xYpvH5T8LpwuTJqpGLfiel+OJyplGyYQu2z6AgkpaVg0isT5ee
         rbZhXJUMQ0tzVEPU6eeCj6GSXKlwrv5YXfbDrJ/28i6+v5E/78yBrH5gxKWVTW3GzMLN
         it+X4Kc6ImTqZ4PFjk0ultxwDaQf0/9actzKoMq0h7YAa3WsYsN/7V5yp9X9tHf4dU4M
         8gkdX2p8wvErOvs66nSExrvkzzKhC+wOxXzA0na/BafXUvpcb/ur/ZjS0HVY15kUuKSe
         AA7aHtJ57F65fes6hUTm9ZiUFnauo1XrTWlXaTvkhgnEzvvx1EBKXpZRSOIEx+3mqK7t
         tpLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5xQg99H8OKZVXILGjhW2KOvokImVA4M5OtXykMLHoZQ=;
        b=trt85mmInm2sXYUfoNZ6l46oKg8lqRcyhVmPV7fm2RdqV5STPFmwqamVRLQ6ArWnbH
         KuwM5xG19J1Q1LZg9E4ycRIGPvukpVNLedEq5TLMmS6bCnmAmIjmiivi3vuyddbLtC7B
         n1VdZLO5/xq+hr9pk9P8fCboZzAhGuhTXe/vUwSaIvSc15O9JpvzID/6IRovCWNfKYCN
         Rkp98twMPEyogH28aYyPAniqlOXHTW9f+5wcAA+9w4KCO4yh9gJV2tqK0WR38zLGvoPA
         bLm2XwxH9Iktg16zRBm01ofyBujhb4lLD5DTqD1NgGk0ufv/whQX4Tn4LzbKajwGjPuM
         DikA==
X-Gm-Message-State: AOAM532X2xBw0ac02/GlvzROU+FgsjzVN+YR6R0jBCXhj73bdghWcamP
	+W0R8Mm8+mJSI9fyyMWHtSU=
X-Google-Smtp-Source: ABdhPJwH+tnLLclvmJ3/c+lxKQ3Q0+lJK9VBmamjlp9ybNG/T3wAeg0avKPR7z/fYq65qdQM7CLCpA==
X-Received: by 2002:a17:90a:1c1:: with SMTP id 1mr3056204pjd.151.1643047796669;
        Mon, 24 Jan 2022 10:09:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ecc6:: with SMTP id a6ls733863plh.5.gmail; Mon, 24
 Jan 2022 10:09:56 -0800 (PST)
X-Received: by 2002:a17:902:be08:b0:14b:7036:3573 with SMTP id r8-20020a170902be0800b0014b70363573mr427983pls.155.1643047795996;
        Mon, 24 Jan 2022 10:09:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047795; cv=none;
        d=google.com; s=arc-20160816;
        b=mHPQ1bA9pRkg+kBvKiUzO7DAquuqibLVkRuGMtvXL+rDJY5GFxe8aJVLGG+bKUHmMF
         2XIMp8GdsvPdXKm2cmt0QJd1W54+tPMKqouUlQe0WGpj1STpcQ4G8EGc70S/W2JbTP8m
         0FoPS5mc97O3ZowDq94YGcWuXRV38fHURxosoHJ5AhLBJy8wtKiUosqrHRmGG+GbX9rU
         TIFsCEkgF02gQbiW31WE16qv9vgWXjmpoYH9Xm3aupYV/tk2KNbiVm4TeQ+2uvw2ylf+
         +v2szzRpEJ8gZEk78QetaELcaL/M0OKqtQ3e9UhtsFoMJZFe8yB/8zIcYEIvdp5uoZbt
         eORw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=v6jRI9epvX7ZG9JJREEDqZFqkweKboDzqXireE4QkNA=;
        b=bIHRqJdJ8vDR3bLUL11vWqWO5gJdqQNHu4QznaUEqD1ylv8ebn5ShylsGCAtl3hr0P
         p5zXmXZfn3IEadWD9LB2gozgunLhZEo9+yW1IcDDRtM9q5NmPN0A/dziAXm1wHWzgwdL
         pz69AB9VAn6WqMes/QXfFSfI8KM2f2hyjAMfEAvnrGHZQQn4WY92XgS2iu60b7OodAWV
         7hoKsKoOq3fI0iiHP8DSctQ+wMnDrwO4iasgEtErcGI2xBJFJgbBdkgRDbSVyXa7AO29
         n9ZI62rDEc3ZaWm+xfvN01iosDMbrPWY86VscAwU3iiDmKPdealW5Gy5FXpRFUYDQN3J
         3B6w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YkS6CDPg;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22f.google.com (mail-oi1-x22f.google.com. [2607:f8b0:4864:20::22f])
        by gmr-mx.google.com with ESMTPS id q3si704083plx.3.2022.01.24.10.09.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 24 Jan 2022 10:09:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as permitted sender) client-ip=2607:f8b0:4864:20::22f;
Received: by mail-oi1-x22f.google.com with SMTP id q186so26765620oih.8
        for <kasan-dev@googlegroups.com>; Mon, 24 Jan 2022 10:09:55 -0800 (PST)
X-Received: by 2002:a05:6808:15a6:: with SMTP id t38mr2513927oiw.154.1643047795220;
 Mon, 24 Jan 2022 10:09:55 -0800 (PST)
MIME-Version: 1.0
References: <cover.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 24 Jan 2022 19:09:43 +0100
Message-ID: <CANpmjNO2Lwq5+zy3pGj=cetMdB7qLmP0WWjbSCYucPVjEt4kWw@mail.gmail.com>
Subject: Re: [PATCH v6 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
To: andrey.konovalov@linux.dev
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YkS6CDPg;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22f as
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

On Mon, 24 Jan 2022 at 19:02, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Hi,
>
> This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
> KASAN modes.
[...]
>
> Acked-by: Marco Elver <elver@google.com>

FYI, my Ack may get lost here - on rebase you could apply it to all
patches to carry it forward. As-is, Andrew would still have to apply
it manually.

An Ack to the cover letter saves replying to each patch and thus
generating less emails, which I think is preferred.

My Ack is still valid, given v6 is mainly a rebase and I don't see any
major changes.

Thanks,
-- Marco

> Andrey Konovalov (39):
>   kasan, page_alloc: deduplicate should_skip_kasan_poison
>   kasan, page_alloc: move tag_clear_highpage out of
>     kernel_init_free_pages
>   kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
>   kasan, page_alloc: simplify kasan_poison_pages call site
>   kasan, page_alloc: init memory of skipped pages on free
>   kasan: drop skip_kasan_poison variable in free_pages_prepare
>   mm: clarify __GFP_ZEROTAGS comment
>   kasan: only apply __GFP_ZEROTAGS when memory is zeroed
>   kasan, page_alloc: refactor init checks in post_alloc_hook
>   kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
>   kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
>   kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
>   kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
>   kasan, page_alloc: rework kasan_unpoison_pages call site
>   kasan: clean up metadata byte definitions
>   kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
>   kasan, x86, arm64, s390: rename functions for modules shadow
>   kasan, vmalloc: drop outdated VM_KASAN comment
>   kasan: reorder vmalloc hooks
>   kasan: add wrappers for vmalloc hooks
>   kasan, vmalloc: reset tags in vmalloc functions
>   kasan, fork: reset pointer tags of vmapped stacks
>   kasan, arm64: reset pointer tags of vmapped stacks
>   kasan, vmalloc: add vmalloc tagging for SW_TAGS
>   kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
>   kasan, vmalloc: unpoison VM_ALLOC pages after mapping
>   kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS
>   kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
>   kasan, page_alloc: allow skipping memory init for HW_TAGS
>   kasan, vmalloc: add vmalloc tagging for HW_TAGS
>   kasan, vmalloc: only tag normal vmalloc allocations
>   kasan, arm64: don't tag executable vmalloc allocations
>   kasan: mark kasan_arg_stacktrace as __initdata
>   kasan: clean up feature flags for HW_TAGS mode
>   kasan: add kasan.vmalloc command line flag
>   kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS
>   arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
>   kasan: documentation updates
>   kasan: improve vmalloc tests
>
>  Documentation/dev-tools/kasan.rst   |  17 ++-
>  arch/arm64/Kconfig                  |   2 +-
>  arch/arm64/include/asm/vmalloc.h    |   6 +
>  arch/arm64/include/asm/vmap_stack.h |   5 +-
>  arch/arm64/kernel/module.c          |   5 +-
>  arch/arm64/mm/pageattr.c            |   2 +-
>  arch/arm64/net/bpf_jit_comp.c       |   3 +-
>  arch/s390/kernel/module.c           |   2 +-
>  arch/x86/kernel/module.c            |   2 +-
>  include/linux/gfp.h                 |  35 +++--
>  include/linux/kasan.h               |  97 +++++++++-----
>  include/linux/vmalloc.h             |  18 +--
>  include/trace/events/mmflags.h      |  14 +-
>  kernel/fork.c                       |   1 +
>  kernel/scs.c                        |   4 +-
>  lib/Kconfig.kasan                   |  20 +--
>  lib/test_kasan.c                    | 189 ++++++++++++++++++++++++++-
>  mm/kasan/common.c                   |   4 +-
>  mm/kasan/hw_tags.c                  | 193 ++++++++++++++++++++++------
>  mm/kasan/kasan.h                    |  18 ++-
>  mm/kasan/shadow.c                   |  63 +++++----
>  mm/page_alloc.c                     | 152 +++++++++++++++-------
>  mm/vmalloc.c                        |  99 +++++++++++---
>  23 files changed, 731 insertions(+), 220 deletions(-)
>
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO2Lwq5%2Bzy3pGj%3DcetMdB7qLmP0WWjbSCYucPVjEt4kWw%40mail.gmail.com.
