Return-Path: <kasan-dev+bncBC7OBJGL2MHBBP42ROHAMGQENMR7MZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E58047CD37
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Dec 2021 08:01:21 +0100 (CET)
Received: by mail-ua1-x937.google.com with SMTP id y5-20020ab05b85000000b002fa1b6d2430sf871815uae.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Dec 2021 23:01:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640156479; cv=pass;
        d=google.com; s=arc-20160816;
        b=wiNzTk7boRM3SdOeUfQKHfUs1P7X/GnMeiMXZze1ZkYbT3cftCqR9xA4b+UOfNl25F
         8B9GkWxtCruxqKtdNqLBJZqdloIP+heOlkmGxMKxt1nWm7d6r1XTAO4ADxZEIXGryusT
         43nXfN6/nKBx98glvuzCwNU/wSzwsUIjwFq0iLIZ/kczLaClJZrVrMgz+AATsij2YQ/l
         +7fVJFwj9aklD0pGBCPqt48AkOwrfBoVU2l3i4jk/aK8yOGlrfR7f4fH0jG96ZJwOzBh
         ZsSPy5Rm9jfWcewKge/vod6AqLmGo7+ZF3N/pbc5+foClTQ4Qs/p12BLrCLae57uW/CA
         nCcw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=S8CVYWr5Fpx6b8IzauAnWe3vWxmCBmEJIAVmZ6Xd8nI=;
        b=VInz37vZ10Pom/UO9SNzqzQmyTb3C76bROWmYalkFhj5sa8iRLIwM8awfSuiq1KHU1
         GV8agUwdzGgCqA5qr5i6jn2DttfGNk4+KGsVd/k1BPe5ws8T2POhLbHtTKKfejmA/gyA
         /ZjFF/rIFHzrm1pr9udNkTM8DRDxsNXdjM57kCBmn+pkQiw6pbjQzDPNDHSLhjg+ypRK
         XOjPKC5xyTjRYS2DH6eScHJeXU+/i368t285CZYMxnfFHZiFVEDNUqCBIzSISs5J0BZ+
         7xQvl3bFLBwNDxbCA4acy8MVygzlJ1+TK6LPBspiGg1aHqGVyh/Z8JIqeGYeTWEi3c5W
         cwdA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mtHkqAut;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S8CVYWr5Fpx6b8IzauAnWe3vWxmCBmEJIAVmZ6Xd8nI=;
        b=REA88qFv8zrX51S8CG91CJXlNXlVz5EhruapU3L/it/aWLUMNpwGqtqqc9wl7ydKOD
         ZyDO5T6lpfbaKq4DAwz8vr2BNYYx4WlHpDWeMuVj4a1IWnSM1XIUCfSfNS2/47Ekpnq8
         Rlk7BxYNutxoKKeNWD+2rcYZG9Sjcu+mIgZjjNNTWUU74wBPPkUDOsuDmv/pykqEFV4k
         4BtrVnOVc3r38FlC/Qu9CYo4nx6evZZiJHiP18NIYQJPTpirrzqR9XkbcLckWkPg9usD
         j2YoZtt5WtWXZsJX5IVaA6hhyIBDk31pTdGsNCWdsku2fVNmOmk6h8TVOxuLtZ9Y+VdE
         FHiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S8CVYWr5Fpx6b8IzauAnWe3vWxmCBmEJIAVmZ6Xd8nI=;
        b=xhgpM7+15hjjV6FTzHDvROE4Njl7P22QpUu39GtUWXvnR5Ey/JcV9AcwNrsjBB6MmZ
         HcIqTtZqn9i1ZmtmmFbG8ZM6Q7/yZC5Lf1sJczIAx54TWTaeqVh8xSHKaEpPluHtacoh
         W8mKDaz0boye1E1sYP65eHz0kiwJVfvo1BXUWnCeGyeUx9sEO7mjuk3jeEYPuSuiphw7
         g9ug48MW5OeIe/m25o65jKBMq1QOmy+mWGX36+RgGtBZYBB7aSGDI15JQ8p3YvuWQ+vO
         bAKdYZ4lC0At15gYb8GjaAt1Faf0+J1X5KWDZrjc7dLUZc8ZjzjLnGP/PneePlZYndwM
         MP2g==
X-Gm-Message-State: AOAM530HksCHmzxuUgDwF9NRyT87EoJlk46Hh6gxnbMgxRWNTLXSP/aX
	3OTXli0+f4TMu4g73+dW9dg=
X-Google-Smtp-Source: ABdhPJyZ8XInfMzzH+sVDX+eqFd/TtK08E/A1mczQ2wLJb/yKu/zcJf6dd/YpTHw+Ne258ksOUdvIw==
X-Received: by 2002:a9f:25f8:: with SMTP id 111mr523282uaf.44.1640156479763;
        Tue, 21 Dec 2021 23:01:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d58b:: with SMTP id m11ls179768vsj.9.gmail; Tue, 21 Dec
 2021 23:01:19 -0800 (PST)
X-Received: by 2002:a67:eb8b:: with SMTP id e11mr517763vso.35.1640156479266;
        Tue, 21 Dec 2021 23:01:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640156479; cv=none;
        d=google.com; s=arc-20160816;
        b=KnTFw00hBxbUNqrCBaMiSHRoDOIg0qPRnvQVqeUC2+aTfT6PY8BfOto+Wzc9rnJjLZ
         TTRuYoWVg1GY4v9+h08FYNeft6WsLn25Gc1jMIOHxBmjlspMQqO3lbacmq4ReTvjlgs5
         h3DXEqOGAuaxd43sb1kcs3drC8O3fjIH+u1q4/GhMBtvZ+Wgc6ZriPjOGQJ48wy5isl0
         Z42mQ4f2606QQUOoZQTRUD59ySAtMSpBqpVbegdyWNDLa2heEmxKfByZtqovpDVAqFGT
         PRyjXJEaqnKb2QC0XQeRjif8Z+ftks/eenL7MMnbmde36zeJnn4W9l75VGHVUrbOxCgz
         akLg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=K+fEElkxyh17SJxyQvhZhzCYL3bEc/oln0enLIlPr7s=;
        b=tRTtXEvUTBmw8CeSfQrBew0ZegJgluMS3eYF3e+68zYxBER22JAqjoOpLt/mwAmgEZ
         oXVSSm6vGldsjAjZUjHNy3/E8OIrDEFKq0nYUl/MjGnq1XeeMF+Bo8akV31qChBesCjr
         uqK9GApYgnHM35nEi50hw/3djKLgMQ671cxN8nKg6NOPO+UWSM8NZEISqLhVpRpp0djQ
         cjw4fBmRaDwHpPr+O5AUcwv1JgeeKGN1M1YR9n7T7mZ7u8pCu7Rrl1ivPHXI54z6S/sz
         JRAZDngyNnqevFmlVhBNAByuCUEysqtlkEkErCoK23/s/4pyJHIGQa59Zqasj+Bc9iYs
         YEJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=mtHkqAut;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id r20si99125vsk.1.2021.12.21.23.01.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Dec 2021 23:01:19 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id bj13so2630573oib.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Dec 2021 23:01:19 -0800 (PST)
X-Received: by 2002:a05:6808:118c:: with SMTP id j12mr1181782oil.65.1640156478612;
 Tue, 21 Dec 2021 23:01:18 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 Dec 2021 08:00:00 +0100
Message-ID: <CANpmjNOj-jYo=yaffBi5w=esyHYo=CEqDJce7cb-KmQ1P6BEMQ@mail.gmail.com>
Subject: Re: [PATCH mm v4 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=mtHkqAut;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::236 as
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

On Mon, 20 Dec 2021 at 22:58, <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Hi,
>
> This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
> KASAN modes.
>
> The tree with patches is available here:
>
> https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v4-akpm
>
> About half of patches are cleanups I went for along the way. None of
> them seem to be important enough to go through stable, so I decided
> not to split them out into separate patches/series.
>
> The patchset is partially based on an early version of the HW_TAGS
> patchset by Vincenzo that had vmalloc support. Thus, I added a
> Co-developed-by tag into a few patches.
>
> SW_TAGS vmalloc tagging support is straightforward. It reuses all of
> the generic KASAN machinery, but uses shadow memory to store tags
> instead of magic values. Naturally, vmalloc tagging requires adding
> a few kasan_reset_tag() annotations to the vmalloc code.
>
> HW_TAGS vmalloc tagging support stands out. HW_TAGS KASAN is based on
> Arm MTE, which can only assigns tags to physical memory. As a result,
> HW_TAGS KASAN only tags vmalloc() allocations, which are backed by
> page_alloc memory. It ignores vmap() and others.
>
> Changes in v3->v4:
[...]
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
>   kasan: simplify kasan_init_hw_tags
>   kasan: add kasan.vmalloc command line flag
>   kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS
>   arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
>   kasan: documentation updates
>   kasan: improve vmalloc tests

Functionally it all looks good. So rather than acking every patch, for
the whole series:

Acked-by: Marco Elver <elver@google.com>

... and in case you do a v5, I've left some minor comments.

Happy holidays!

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOj-jYo%3DyaffBi5w%3DesyHYo%3DCEqDJce7cb-KmQ1P6BEMQ%40mail.gmail.com.
