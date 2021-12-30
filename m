Return-Path: <kasan-dev+bncBDW2JDUY5AORB7MIXCHAMGQE3KAKROY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id A2C94481F74
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:11:58 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d26-20020ac800da000000b002c43d2f6c7fsf16651843qtg.14
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:11:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891517; cv=pass;
        d=google.com; s=arc-20160816;
        b=oOBhQWp14lReNPF42fUNjpW8opIz2pHO7zHgeDv37Pn/7GnsGz9/ed5/JpPTcMCTZV
         J60ugTayynP6+N8wbaIfcBZHTpKlgF6692CqnZh9IpUs6MfXKCTTBbi6ydsoSc4cqvi5
         EUrgrWz2vF5upc1Q8sy7+HV9vz8T7bV3W1glNjV0Ots8lCpJHJCpCVdnpGny9WNG+ZsE
         KxOWQxJrWPo7GVt3u6ify8cp8fgeNi3mhRnBI8eRXShlKm5e/sxUyBxI6iXunOP5LBwR
         jIdnMXmSh7L+YDbjSrtbuitjLlB8rWW+07SFVyhrl89ri5gltBxHbZYcexLEgJXGZ1TB
         lOYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=vq/jXZttXZ7q7lwNLzjTMG68ZtKdw7djOonOkxZkuCs=;
        b=ABSE9+48tE63psC5OCQWs/OQBqt65rilJxcDddXr7zPYYerXjQwlHWo6IGe8OSmlQ/
         RGaAUuLQ/QCmF0ItLJ9rPq475haz7ZA9zCsMPyPkPI7a4P5o9h5PPeysStlH+kSRgjYt
         neNVAh4Gb+DWjFuQmzeFb58VEZAJmnkriZ10bo5+Cf46d2WaJe1Dl6XvUsz9Hg8xXTlV
         10QSYiF7ARRe3OQJq4YJdMGEDv84W9vXkQU5GF7awVqZSffUQNQMkkXweQfonKqcek0J
         dugCAPrZIxYcfjfnpmdJ+OBtvtN4W7Gg3pLRyiRQ/jiuq1Kvrus+KmaQCWz3mrhLlrRm
         oDCw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I5w21MLC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vq/jXZttXZ7q7lwNLzjTMG68ZtKdw7djOonOkxZkuCs=;
        b=Zxt5bcmLmOKwKcgiNA8EHbquwCpw9adU0kcLFmdMj3WBWQLdq2iizEjlRPA7LON6Jf
         bcCs/W1wu5FqmGoZ5lQJ1coi92FHMH4BUa07HJpD/zPTPZYzTwsViPAfvP3TIZv46/+3
         cQ+NEpZ/obalo+jQRL2eRXr1yePuH6yG0DjRQO1iu9Vl5K8idg/1p/4guMLN0EwC7YbK
         pJHmNhcCgAfDUFlVvIs0TBE5xQZZX3xK/3jqf6tvYOONdvI8sBL7cl+cjO5sn6ErtGz3
         vnv3X+bcobQ7aiunGL2csQU2mhNpxiU8LtdejVdrBTb3MfS+bf87BS2Hryv3pwud36fs
         q8rA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vq/jXZttXZ7q7lwNLzjTMG68ZtKdw7djOonOkxZkuCs=;
        b=OlhzKJLpD0zxTVxmbzN7ODP6sojwk9VPn3QEifxVhRwK+K24vG/XrnSI3nz60MZ0QS
         an69gQXQm8UaTVuoDvwrCePMS46HUy8MtDk6lk/3X+s7G+NXZgtdnEWLW5J3keoY/12j
         6xgKdd8leHMFiRT6ljc0no5kc+1GrfYFgRhb0PEhdlo1qFmUGa0I/mm3PEum1nwZUya5
         4JCeeltzvTR8cbXH+kzv6xqUo647MhtkG1j/IzuYZDrNUBtwd4Jx7D86GOoun+vB6LKN
         o0hylsucjkFsz81DANRoTSZrGHIqZztmec38qdLbyPb+cwEr8n/8/xwKYPjySVfBL5O0
         tYxw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vq/jXZttXZ7q7lwNLzjTMG68ZtKdw7djOonOkxZkuCs=;
        b=r8E/cnyGgR77UhfqYM5nGqrpiYQOaigrWFSaHTBBQGoiBSKn6L8AHdvOhMkPrg9BIF
         3pLW0HKigHLmR8VIavH8bU9IOQzLvXD0fj63egzlbMwHse4acr1E5LI/VYsaek6x2FAR
         sZ64fuztAverSS42O5sA2fW1QOCCQx6XZQDj+p6L3xhw4EVOZWW4i7/2yqJOlyE6nPhd
         mT8OlENTklcvX76wsiGpAxixlq+qYt8MuemO4tzNCN3NDtbBRJkuhP4egjA4otO3wMkz
         8Z1uAlDRNgOJ/bSuHlXGUBfcwq4FEmMnm7DHHZD/A5z8Xl1U4LLVKHAn5D0AUo+NXbwa
         v2GA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OzMhhCLuBjG1SfhFIAgCtj6y9zLyLvQtJ9SbAR5KOGwkbNbn4
	fdCTp3lF9dCceEEbaF1WqmQ=
X-Google-Smtp-Source: ABdhPJxV+LmjcrnKCkTGdr22LmOPnv2/3KJhslHvjjAw1ynxsAhAxqN2RGEzEb+oiCDwW30hZXV0tQ==
X-Received: by 2002:a05:622a:1908:: with SMTP id w8mr27909129qtc.564.1640891517781;
        Thu, 30 Dec 2021 11:11:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e206:: with SMTP id q6ls10862764qvl.0.gmail; Thu, 30 Dec
 2021 11:11:57 -0800 (PST)
X-Received: by 2002:ad4:5aaa:: with SMTP id u10mr28644301qvg.51.1640891517439;
        Thu, 30 Dec 2021 11:11:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891517; cv=none;
        d=google.com; s=arc-20160816;
        b=xnQwVjNBtvNgC/yQyhXGAzWF99WmzQ/SHLu5uC1oVtd07UVL3VwRIVFKhmsOiVe78b
         H27EaFYfApf1Lmd9EkLUGCZR04BQUmMEl62RvbFZlv0hhr591mdSVGl2yOH0bFOpwzm+
         StjNlF6TH8Nxhz/gA5kd3A+CEXC8l2QDans02gMV2tH/THedXU3LmYskKGfHeCn+Cb/u
         f/X/tVKl93ZSky4VUBj0RSvf7Qn1ur3ycf1VrscCV1e90amWDaJRkMhBE8FcDcssWHex
         RNCFacnPWGSlRQJFSwfMVXvRtBLypC2nich9oKZvkvxRhpXxkUSCS3BEDLyK3nGOw61G
         vvmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=0B1QA/OwI2lHBTPwaGSFFWLygKR3T0IMOccEPyW54+I=;
        b=mZXBlm7uh5mYXO+VsNDWIjgpvoDw/QD/8q4F4ODWYmR3Udu6AsSnURKXD+4Fgr7vB+
         cSOQ08OJp+ufybAFCGieHvoc9qnkWLShTzyMpHYoTdzMiTWDfE088NlKvUHTf+frXbW8
         nKs6ps2ploXg8VdM4Ui9xmbD1wHmSTs9d3o1SMzlcabBhGTJ5vahh/zTf0OSyjEkXoJe
         xn0UmAod93efrOR6VeJx4vYpiVDoJZ8MWPE0T0ilMTlvxtH23xONiTDMhHQ/Jkfeq3gE
         Dwc6eXJwj0rTi8h4+JXVuCRDnTVeuYS3WHaVor7DlspXaofCZXsIcSv5gjVzoyQdtUln
         kfaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I5w21MLC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x135.google.com (mail-il1-x135.google.com. [2607:f8b0:4864:20::135])
        by gmr-mx.google.com with ESMTPS id 22si3504688qty.4.2021.12.30.11.11.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Dec 2021 11:11:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135 as permitted sender) client-ip=2607:f8b0:4864:20::135;
Received: by mail-il1-x135.google.com with SMTP id g5so19521383ilj.12
        for <kasan-dev@googlegroups.com>; Thu, 30 Dec 2021 11:11:57 -0800 (PST)
X-Received: by 2002:a05:6e02:178f:: with SMTP id y15mr14604983ilu.235.1640891516954;
 Thu, 30 Dec 2021 11:11:56 -0800 (PST)
MIME-Version: 1.0
References: <cover.1640036051.git.andreyknvl@google.com> <CANpmjNOj-jYo=yaffBi5w=esyHYo=CEqDJce7cb-KmQ1P6BEMQ@mail.gmail.com>
In-Reply-To: <CANpmjNOj-jYo=yaffBi5w=esyHYo=CEqDJce7cb-KmQ1P6BEMQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 30 Dec 2021 20:11:46 +0100
Message-ID: <CA+fCnZeDdgiCZbmJZY7Ep-W8XpEmCzs+1B2QcaEMQhJMrFyPEw@mail.gmail.com>
Subject: Re: [PATCH mm v4 00/39] kasan, vmalloc, arm64: add vmalloc tagging
 support for SW/HW_TAGS
To: Marco Elver <elver@google.com>
Cc: andrey.konovalov@linux.dev, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=I5w21MLC;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::135
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

On Wed, Dec 22, 2021 at 8:01 AM Marco Elver <elver@google.com> wrote:
>
> On Mon, 20 Dec 2021 at 22:58, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Hi,
> >
> > This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
> > KASAN modes.
> >
> > The tree with patches is available here:
> >
> > https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v4-akpm
> >
> > About half of patches are cleanups I went for along the way. None of
> > them seem to be important enough to go through stable, so I decided
> > not to split them out into separate patches/series.
> >
> > The patchset is partially based on an early version of the HW_TAGS
> > patchset by Vincenzo that had vmalloc support. Thus, I added a
> > Co-developed-by tag into a few patches.
> >
> > SW_TAGS vmalloc tagging support is straightforward. It reuses all of
> > the generic KASAN machinery, but uses shadow memory to store tags
> > instead of magic values. Naturally, vmalloc tagging requires adding
> > a few kasan_reset_tag() annotations to the vmalloc code.
> >
> > HW_TAGS vmalloc tagging support stands out. HW_TAGS KASAN is based on
> > Arm MTE, which can only assigns tags to physical memory. As a result,
> > HW_TAGS KASAN only tags vmalloc() allocations, which are backed by
> > page_alloc memory. It ignores vmap() and others.
> >
> > Changes in v3->v4:
> [...]
> > Andrey Konovalov (39):
> >   kasan, page_alloc: deduplicate should_skip_kasan_poison
> >   kasan, page_alloc: move tag_clear_highpage out of
> >     kernel_init_free_pages
> >   kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
> >   kasan, page_alloc: simplify kasan_poison_pages call site
> >   kasan, page_alloc: init memory of skipped pages on free
> >   kasan: drop skip_kasan_poison variable in free_pages_prepare
> >   mm: clarify __GFP_ZEROTAGS comment
> >   kasan: only apply __GFP_ZEROTAGS when memory is zeroed
> >   kasan, page_alloc: refactor init checks in post_alloc_hook
> >   kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
> >   kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
> >   kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
> >   kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
> >   kasan, page_alloc: rework kasan_unpoison_pages call site
> >   kasan: clean up metadata byte definitions
> >   kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
> >   kasan, x86, arm64, s390: rename functions for modules shadow
> >   kasan, vmalloc: drop outdated VM_KASAN comment
> >   kasan: reorder vmalloc hooks
> >   kasan: add wrappers for vmalloc hooks
> >   kasan, vmalloc: reset tags in vmalloc functions
> >   kasan, fork: reset pointer tags of vmapped stacks
> >   kasan, arm64: reset pointer tags of vmapped stacks
> >   kasan, vmalloc: add vmalloc tagging for SW_TAGS
> >   kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
> >   kasan, vmalloc: unpoison VM_ALLOC pages after mapping
> >   kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS
> >   kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
> >   kasan, page_alloc: allow skipping memory init for HW_TAGS
> >   kasan, vmalloc: add vmalloc tagging for HW_TAGS
> >   kasan, vmalloc: only tag normal vmalloc allocations
> >   kasan, arm64: don't tag executable vmalloc allocations
> >   kasan: mark kasan_arg_stacktrace as __initdata
> >   kasan: simplify kasan_init_hw_tags
> >   kasan: add kasan.vmalloc command line flag
> >   kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS
> >   arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
> >   kasan: documentation updates
> >   kasan: improve vmalloc tests
>
> Functionally it all looks good. So rather than acking every patch, for
> the whole series:
>
> Acked-by: Marco Elver <elver@google.com>
>
> ... and in case you do a v5, I've left some minor comments.

I will, thanks!

> Happy holidays!

Happy holidays to you too!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZeDdgiCZbmJZY7Ep-W8XpEmCzs%2B1B2QcaEMQhJMrFyPEw%40mail.gmail.com.
