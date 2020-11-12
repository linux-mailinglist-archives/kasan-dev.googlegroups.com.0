Return-Path: <kasan-dev+bncBDX4HWEMTEBRBA4OWL6QKGQEQ3YUYAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id CED7F2AFBD7
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Nov 2020 01:51:16 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id v134sf3066027qka.19
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Nov 2020 16:51:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605142275; cv=pass;
        d=google.com; s=arc-20160816;
        b=kfhcXtHff+mKOIj/v0H8gQUhT/kr+5YnZUqf34FYYP5qqV25hIVZzeSTJvlsLRDWEP
         hYPp5GLU6G8iC8j55/SXRt6ZoJwPKrqm6KlrTGiElknfHBd+ozSIl9CEWIiIEPbVBCub
         6Tu9Hvhv8ycUaDibiThi2MQkl9MfhB8wK5pK8Qn4y5Z7Q+a6L5XX1jgWOblM1vGzleYL
         cJzsWptJArUbaE00xKUte575xrCMJZ1f+BP0+C0yl2gX4XJBAKZuDo0FJK7D/RDRZ6Dq
         0CJrUHLQ/Q0wWEx2LCwWvSGeUvzqsGX5AGpWbLSfOx2ydGMbjDB1eGmYwGudopyh3xVq
         FBMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4z8rFtV2flxGY2todwdzMx+OsRG44gIqDltQo0rvPt8=;
        b=MY2ceUnq8qCTCFbMziCAkBqXk+V8vh719YRCtbTNAV/wHRZLW9syUkioAIGXBxvumz
         TT1caqdb/bZSzJUZ6eZdk54D+9miASlro7LA3YJwdwLo3jpQpvDE5MI3K9AYH1dxOb6a
         Kelk91t8szgib3pn/rDVGZOr2ZUUhdZuESQF3dMpG7EXyN/GWPbN3lwqBuiSas6fdMpp
         lfZhRovo5uCnfoKbZd1JoMdYnjwawKQg9Gi/xc65WrnI17I4NjNpY+OmCaC2mI73XflK
         YKGUNryMyae2TrqnQixseI6jiG6lNGhHKW1cWqpa3JB6p/HXj/rceCbMq++02g1RPJ47
         q8xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CRNOrmU+;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4z8rFtV2flxGY2todwdzMx+OsRG44gIqDltQo0rvPt8=;
        b=ssqMBNIKhJYn/0moukcsSZtdYFdIJCqEKnoYhVp8OEmmH1RUHUjLFiDbmMoiDD2/o0
         QiT+XD3VSKNCTdNKT3lhI3U+RLI1GPWgsWSW2wMIKv+UsXQTJFE0qJLYfC1pd/Sy0op8
         mZgXKLEko67P/Cvd8htysm06g4S6Blj8oJVU5Az8k6C6l0Ls+yVMTodPd6Ndb4nEO143
         rVTIgA+1xx7XvWelW9FMBWJw4mriy0JziivYlDF+a08VhBl3672T2ih4/YbZhDoMvDYN
         80VzxAszPxkFQX9YZtr0GJFY52TAQdqv0OE5k2Zn9sjtO0wkH/5oBarDram7OnT11+Yp
         0Vlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4z8rFtV2flxGY2todwdzMx+OsRG44gIqDltQo0rvPt8=;
        b=Et9UdU+Wv9RtmU4anVIsxnHejrhZSf5J5TENUqJbWtbdVZjpC7mQJDpzMd7lBlxelX
         OMujxT3+kkCNlvZcizZpQew1n1xSJBVUuCkwjdPqNR21SdSrgKYWasPQui1XMHV6yy0o
         8x8M0NSxDanqSMYvf0laDo83ii7NMgzjsEtZJeHg57qrelKrXaSdvaIVLK6e7ccIplZ1
         hVKhUaHVkWz8pmesRXXgF2ykSE1d9XuqmZOnBiw4qjCHXM6QGhdsxbjo3ZCFeiQrnoP7
         bRoOlZ7YyI3G5veL+8upna4Lss+ratNZakXWY2NI1elgoNYMJ8j5Mt3tdRQOHufN4fzA
         VNrQ==
X-Gm-Message-State: AOAM532nQQvWGFmrtjzBieGGRfwxCo6JZAbVEQ6oYrstczu76SjBPdTY
	sMmwJt4UP46WEYSLlCa4etI=
X-Google-Smtp-Source: ABdhPJz3jNDqz7UGpcnInIm/h1PqD2csxA22iQsqoO8+vnhXR8cZ+2yXHe1AJm1he50ub9On8rVGDQ==
X-Received: by 2002:a37:b85:: with SMTP id 127mr26116527qkl.109.1605142275722;
        Wed, 11 Nov 2020 16:51:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:152:: with SMTP id x18ls281879qvs.10.gmail; Wed, 11
 Nov 2020 16:51:15 -0800 (PST)
X-Received: by 2002:a0c:fc52:: with SMTP id w18mr15047800qvp.48.1605142275217;
        Wed, 11 Nov 2020 16:51:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605142275; cv=none;
        d=google.com; s=arc-20160816;
        b=qekybot+hHe3IWiQcZsBdLqlDsAekw5/dSg46SkxY8Hd/n/8jWJQ5yJV/MuwQb4hWr
         JFQcvkVpyVd+LPhpXBpcfLgDng09jYxA6lrRu9LywfCcfNStMx0SmjlJYMtXTtJfIawn
         8Ey2z7E2aTcOL9MS40J0ORyAwSG9s5dyReCI5DV2IJK9vIWOnNTsxyaZ3qfS9xCvVkiG
         Wp9zh8z3t2MefzGmgaHswD6UGPkYFWdqR7bq15/0EeWc+8+mHQ9F/c1nXfixkiyLRciM
         ABGu9JqUi6ZbYEu992dom16BT5j6d3P1d9zE3pideVTshCW/TBoXLKtRRiAV3Ivd+Q2T
         R5pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=8rS3LSGNvGpE3/HRnihmkueblCSGMw78UyqxkdR2g20=;
        b=l0KBURIDtjmlgl+yE3mhrrCFpyQczFx1mWcjB2mHWTgb2g669sGRF+qErN5axROs1a
         4oKMQliLrcshQ2m3IRHq3nz4E6J+z/qLj8aT70LJZSbeunoW+hO95QuDXRcIsKbb/OUL
         iGfgt3QqOV5f9Php9AzGwDcnOXQyQ72/g9uGPXCywIAiOyFN+VgXrcme0tYOG/amfzHJ
         YsadlM8uEi7nlbAItQOwai1RV8zJ3tGjPj6+EAnsJsqjewhBpo3Tp+rG/mtPg3MHUDXD
         i1sWi24ErHCxTzGCiWWmHyTniNFXRWGcAQpgSbVraJWI9DAb1lAHv6kG90hIhvqwu0aQ
         EDlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CRNOrmU+;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id r3si234624qtn.0.2020.11.11.16.51.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Nov 2020 16:51:15 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id 62so2664692pgg.12
        for <kasan-dev@googlegroups.com>; Wed, 11 Nov 2020 16:51:15 -0800 (PST)
X-Received: by 2002:a63:4c10:: with SMTP id z16mr24030555pga.440.1605142273809;
 Wed, 11 Nov 2020 16:51:13 -0800 (PST)
MIME-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com> <6103d1aaacea96a94ca4632f78bcd801e4fbc9c4.1605046662.git.andreyknvl@google.com>
 <20201111160311.GB517454@elver.google.com>
In-Reply-To: <20201111160311.GB517454@elver.google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 12 Nov 2020 01:51:02 +0100
Message-ID: <CAAeHK+xWvHK2SH3ZEqnJ97ArjkuAB4Hrpu34AhQiruUyo1h6dw@mail.gmail.com>
Subject: Re: [PATCH v2 20/20] kasan: update documentation
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CRNOrmU+;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541
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

On Wed, Nov 11, 2020 at 5:03 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, Nov 10, 2020 at 11:20PM +0100, Andrey Konovalov wrote:
> > This change updates KASAN documentation to reflect the addition of boot
> > parameters and also reworks and clarifies some of the existing sections,
> > in particular: defines what a memory granule is, mentions quarantine,
> > makes Kunit section more readable.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > ---
> >  Documentation/dev-tools/kasan.rst | 180 +++++++++++++++++++-----------
> >  1 file changed, 113 insertions(+), 67 deletions(-)
> >
> > diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> > index 422f8ee1bb17..f2da2b09e5c7 100644
> > --- a/Documentation/dev-tools/kasan.rst
> > +++ b/Documentation/dev-tools/kasan.rst
> > @@ -6,6 +6,7 @@ Overview
> >
> >  KernelAddressSANitizer (KASAN) is a dynamic memory error detector designed to
>
> s/memory error/memory safety error/
>
> to be precise and consistent with various other docs and literature we
> have, if you deem it appropriate to change in this patch.
>
> >  find out-of-bound and use-after-free bugs. KASAN has three modes:
> > +
> >  1. generic KASAN (similar to userspace ASan),
> >  2. software tag-based KASAN (similar to userspace HWASan),
> >  3. hardware tag-based KASAN (based on hardware memory tagging).
> > @@ -39,23 +40,13 @@ CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
> >  The former produces smaller binary while the latter is 1.1 - 2 times faster.
> >
> >  Both software KASAN modes work with both SLUB and SLAB memory allocators,
> > -hardware tag-based KASAN currently only support SLUB.
> > -For better bug detection and nicer reporting, enable CONFIG_STACKTRACE.
> > +while the hardware tag-based KASAN currently only support SLUB.
> > +
> > +For better error reports that include stack traces, enable CONFIG_STACKTRACE.
> >
> >  To augment reports with last allocation and freeing stack of the physical page,
> >  it is recommended to enable also CONFIG_PAGE_OWNER and boot with page_owner=on.
> >
> > -To disable instrumentation for specific files or directories, add a line
> > -similar to the following to the respective kernel Makefile:
> > -
> > -- For a single file (e.g. main.o)::
> > -
> > -    KASAN_SANITIZE_main.o := n
> > -
> > -- For all files in one directory::
> > -
> > -    KASAN_SANITIZE := n
> > -
> >  Error reports
> >  ~~~~~~~~~~~~~
> >
> > @@ -140,16 +131,20 @@ freed (in case of a use-after-free bug report). Next comes a description of
> >  the accessed slab object and information about the accessed memory page.
> >
> >  In the last section the report shows memory state around the accessed address.
> > -Reading this part requires some understanding of how KASAN works.
> > -
> > -The state of each 8 aligned bytes of memory is encoded in one shadow byte.
> > -Those 8 bytes can be accessible, partially accessible, freed or be a redzone.
> > -We use the following encoding for each shadow byte: 0 means that all 8 bytes
> > -of the corresponding memory region are accessible; number N (1 <= N <= 7) means
> > -that the first N bytes are accessible, and other (8 - N) bytes are not;
> > -any negative value indicates that the entire 8-byte word is inaccessible.
> > -We use different negative values to distinguish between different kinds of
> > -inaccessible memory like redzones or freed memory (see mm/kasan/kasan.h).
> > +Internally KASAN tracks memory state separately for each memory granule, which
> > +is either 8 or 16 aligned bytes depending on KASAN mode. Each number in the
> > +memory state section of the report shows the state of one of the memory
> > +granules that surround the accessed address.
> > +
> > +For generic KASAN the size of each memory granule is 8. The state of each
> > +granule is encoded in one shadow byte. Those 8 bytes can be accessible,
> > +partially accessible, freed or be a part of a redzone. KASAN uses the following
> > +encoding for each shadow byte: 0 means that all 8 bytes of the corresponding
> > +memory region are accessible; number N (1 <= N <= 7) means that the first N
> > +bytes are accessible, and other (8 - N) bytes are not; any negative value
> > +indicates that the entire 8-byte word is inaccessible. KASAN uses different
> > +negative values to distinguish between different kinds of inaccessible memory
> > +like redzones or freed memory (see mm/kasan/kasan.h).
> >
> >  In the report above the arrows point to the shadow byte 03, which means that
> >  the accessed address is partially accessible.
> > @@ -157,6 +152,55 @@ the accessed address is partially accessible.
> >  For tag-based KASAN this last report section shows the memory tags around the
> >  accessed address (see Implementation details section).
>
> I think ReST automatically creates a link if you write it as
>
>         ... (see `Implementation details`_ section).
>
> >
> > +Boot parameters
> > +~~~~~~~~~~~~~~~
> > +
> > +Hardware tag-based KASAN mode (see the section about different mode below) is
> > +intended for use in production as a security mitigation. Therefore it supports
> > +boot parameters that allow to disable KASAN competely or otherwise control
> > +particular KASAN features.
> > +
> > +The things that can be controlled are:
> > +
> > +1. Whether KASAN is enabled at all.
> > +2. Whether KASAN collects and saves alloc/free stacks.
> > +3. Whether KASAN panics on a detected bug or not.
> > +
> > +The ``kasam.mode`` boot parameter allows to choose one of three main modes:
>
> s/kasam/kasan/
>
> > +- ``kasan.mode=off`` - KASAN is disabled, no tag checks are performed
> > +- ``kasan.mode=prod`` - only essential production features are enabled
> > +- ``kasan.mode=full`` - all KASAN features are enabled
> > +
> > +The chosen mode provides default control values for the features mentioned
> > +above. However it's also possible to override the default values by providing:
> > +
> > +- ``kasan.stacktrace=off`` or ``=on`` - enable alloc/free stack collection
> > +                                        (default: ``on`` for ``mode=full``,
> > +                                         otherwise ``off``)
> > +- ``kasan.fault=report`` or ``=panic`` - only print KASAN report or also panic
> > +                                      (default: ``report``)
>
> This is indented with tabs instead of spaces.
>
> > +
> > +If ``kasan.mode parameter`` is not provided, it defaults to ``full`` when
>
> s/``kasan.mode parameter``/``kasan.mode`` parameter/  ?
>
> > +``CONFIG_DEBUG_KERNEL`` is enabled, and to ``prod`` otherwise.
> > +
> > +For developers
> > +~~~~~~~~~~~~~~
> > +
> > +Software KASAN modes use compiler instrumentation to insert validity checks.
> > +Such instrumentation might be incompatible with some part of the kernel, and
> > +therefore needs to be disabled. To disable instrumentation for specific files
> > +or directories, add a line similar to the following to the respective kernel
> > +Makefile:
> > +
> > +- For a single file (e.g. main.o)::
> > +
> > +    KASAN_SANITIZE_main.o := n
> > +
> > +- For all files in one directory::
> > +
> > +    KASAN_SANITIZE := n
> > +
> >
> >  Implementation details
> >  ----------------------
> > @@ -164,10 +208,10 @@ Implementation details
> >  Generic KASAN
> >  ~~~~~~~~~~~~~
> >
> > -From a high level, our approach to memory error detection is similar to that
> > -of kmemcheck: use shadow memory to record whether each byte of memory is safe
> > -to access, and use compile-time instrumentation to insert checks of shadow
> > -memory on each memory access.
> > +From a high level perspective, KASAN's approach to memory error detection is
> > +similar to that of kmemcheck: use shadow memory to record whether each byte of
> > +memory is safe to access, and use compile-time instrumentation to insert checks
> > +of shadow memory on each memory access.
> >
> >  Generic KASAN dedicates 1/8th of kernel memory to its shadow memory (e.g. 16TB
> >  to cover 128TB on x86_64) and uses direct mapping with a scale and offset to
> > @@ -194,7 +238,10 @@ function calls GCC directly inserts the code to check the shadow memory.
> >  This option significantly enlarges kernel but it gives x1.1-x2 performance
> >  boost over outline instrumented kernel.
> >
> > -Generic KASAN prints up to 2 call_rcu() call stacks in reports, the last one
> > +Generic KASAN is the only mode that delays the reuse of freed object via
> > +quarantine (see mm/kasan/quarantine.c for implementation).
> > +
> > +Generic KASAN prints up to two call_rcu() call stacks in reports, the last one
> >  and the second to last.
> >
> >  Software tag-based KASAN
> > @@ -302,15 +349,15 @@ therefore be wasteful. Furthermore, to ensure that different mappings
> >  use different shadow pages, mappings would have to be aligned to
> >  ``KASAN_GRANULE_SIZE * PAGE_SIZE``.
> >
> > -Instead, we share backing space across multiple mappings. We allocate
> > +Instead, KASAN shares backing space across multiple mappings. It allocates
> >  a backing page when a mapping in vmalloc space uses a particular page
> >  of the shadow region. This page can be shared by other vmalloc
> >  mappings later on.
> >
> > -We hook in to the vmap infrastructure to lazily clean up unused shadow
> > +KASAN hooks in to the vmap infrastructure to lazily clean up unused shadow
>
> s/in to/into/
>
> >  memory.
> >
> > -To avoid the difficulties around swapping mappings around, we expect
> > +To avoid the difficulties around swapping mappings around, KASAN expects
> >  that the part of the shadow region that covers the vmalloc space will
> >  not be covered by the early shadow page, but will be left
> >  unmapped. This will require changes in arch-specific code.
> > @@ -321,24 +368,31 @@ architectures that do not have a fixed module region.
> >  CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
> >  --------------------------------------------------
> >
> > -``CONFIG_KASAN_KUNIT_TEST`` utilizes the KUnit Test Framework for testing.
> > -This means each test focuses on a small unit of functionality and
> > -there are a few ways these tests can be run.
> > +KASAN tests consist on two parts:
> > +
> > +1. Tests that are integrated with the KUnit Test Framework. Enabled with
> > +``CONFIG_KASAN_KUNIT_TEST``. These tests can be run and partially verified
> > +automatically in a few different ways, see the instructions below.
> >
> > -Each test will print the KASAN report if an error is detected and then
> > -print the number of the test and the status of the test:
> > +2. Tests that are currently incompatible with Kunit. Enabled with
>
> s/Kunit/KUnit/
>
> > +``CONFIG_TEST_KASAN_MODULE`` and can only be run as a module. These tests can
> > +only be verified manually, by loading the kernel module and inspecting the
> > +kernel log for KASAN reports.
> >
> > -pass::
> > +Each KUNIT-compatible KASAN test prints a KASAN report if an error is detected.
>
> s/KUNIT/KUnit/  like elsewhere.
>
> > +Then the test prints its number and status.
> > +
> > +When a test passes::
> >
> >          ok 28 - kmalloc_double_kzfree
> >
> > -or, if kmalloc failed::
> > +When a test fails due to a failed ``kmalloc``::
> >
> >          # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
> >          Expected ptr is not null, but is
> >          not ok 4 - kmalloc_large_oob_right
> >
> > -or, if a KASAN report was expected, but not found::
> > +When a test fails due to a missing KASAN report::
> >
> >          # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
> >          Expected kasan_data->report_expected == kasan_data->report_found, but
> > @@ -346,46 +400,38 @@ or, if a KASAN report was expected, but not found::
> >          kasan_data->report_found == 0
> >          not ok 28 - kmalloc_double_kzfree
> >
> > -All test statuses are tracked as they run and an overall status will
> > -be printed at the end::
> > +At the end the cumulative status of all KASAN tests is printed. On success::
> >
> >          ok 1 - kasan
> >
> > -or::
> > +Or, if one of the tests failed::
> >
> >          not ok 1 - kasan
> >
> > -(1) Loadable Module
> > -~~~~~~~~~~~~~~~~~~~~
> > +
> > +There are a few ways to run Kunit-compatible KASAN tests.
>
> s/Kunit/KUnit/

Will fix all in v10/v3.

>
> > +
> > +1. Loadable module
> > +~~~~~~~~~~~~~~~~~~
> >
> >  With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
> > -a loadable module and run on any architecture that supports KASAN
> > -using something like insmod or modprobe. The module is called ``test_kasan``.
> > +a loadable module and run on any architecture that supports KASAN by loading
> > +the module with insmod or modprobe. The module is called ``test_kasan``.
> >
> > -(2) Built-In
> > -~~~~~~~~~~~~~
> > +2. Built-In
> > +~~~~~~~~~~~
> >
> >  With ``CONFIG_KUNIT`` built-in, ``CONFIG_KASAN_KUNIT_TEST`` can be built-in
> > -on any architecure that supports KASAN. These and any other KUnit
> > -tests enabled will run and print the results at boot as a late-init
> > -call.
> > +on any architecure that supports KASAN. These and any other KUnit tests enabled
> > +will run and print the results at boot as a late-init call.
> >
> > -(3) Using kunit_tool
> > -~~~~~~~~~~~~~~~~~~~~~
> > +3. Using kunit_tool
> > +~~~~~~~~~~~~~~~~~~~
> >
> > -With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, we can also
> > -use kunit_tool to see the results of these along with other KUnit
> > -tests in a more readable way. This will not print the KASAN reports
> > -of tests that passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_ for more up-to-date
> > -information on kunit_tool.
> > +With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it's also
> > +possible use ``kunit_tool`` to see the results of these and other KUnit tests
> > +in a more readable way. This will not print the KASAN reports of the tests that
> > +passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
> > +for more up-to-date information on ``kunit_tool``.
> >
> >  .. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
> > -
> > -``CONFIG_TEST_KASAN_MODULE`` is a set of KASAN tests that could not be
> > -converted to KUnit. These tests can be run only as a module with
> > -``CONFIG_TEST_KASAN_MODULE`` built as a loadable module and
> > -``CONFIG_KASAN`` built-in. The type of error expected and the
> > -function being run is printed before the expression expected to give
> > -an error. Then the error is printed, if found, and that test
> > -should be interpretted to pass only if the error was the one expected
> > -by the test.
> > --
> > 2.29.2.222.g5d2a92d10f8-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxWvHK2SH3ZEqnJ97ArjkuAB4Hrpu34AhQiruUyo1h6dw%40mail.gmail.com.
