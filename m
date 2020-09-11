Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRWW5T5AKGQEMSQR2MA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D794265ABB
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 09:46:16 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id o184sf6379808pfb.12
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 00:46:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599810374; cv=pass;
        d=google.com; s=arc-20160816;
        b=jb/Jqwpa5uhvoxWPK0nO5EXlcC51NlJ0DHgjE6uUHNesuoTXFd1ICibITPaSV4Mjp5
         BMypSBcWnY8PUCVLPHIuafLTpPDTFSqW1lJ6EvxrH2AqTaoabzmNV1l/fp2qCgoJEXrT
         LdqoNaQOvO8eCMQ1vfPat8dumH6wuMirzyVddNxD4/AVVxAbSg9TN9EChGcMBFL0e8/y
         l4IA035W+IR+jsWmFPmQRRBQsmpxW6JSuNJSVClTrzy4mxtSzg1ofQ1CgLYtiKGYIQg4
         EeDy2WwEqEApS7uxtx+oFQt/Iv93C9Sx/alyS6dOFmPlakVDywmNhjO5lsKxlbWaaMdj
         ffdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=G57uxx120emaOkbyWGBzsuiWBHXrD+QmMg0PhKlkPCA=;
        b=aDeY0XqupRYCi8+KooBb7p3WGNTeNfFL3q58OmD6T5qcG/rbsJlX0adiJGbAobUD6L
         U5wFep63Mm0QkWmIdOCUbXFTfpbCFUYFYFlXeHBFgwkKf9szTbpurwVvRkhYBrW+ZD+V
         0fWLaWAhD4pKuGZdRDUa0DmrqfrIIZ7nOrBwvGVeDHGkZzbUaN1XYclBPKEAXkCw7rxe
         JccatkDKA02jxS670E29T+OKL6yVdAAxr0g6y/O6QJQnE1DUyGLrdw8N9nO4C8RJEOtv
         RvmVhUTYSsNS46lpZbPQn34oEe1vr2C/vaKRjgf7YcU23uW2J9UftsuHMAmXNN4MWLdl
         Zr9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A5Thz3ng;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G57uxx120emaOkbyWGBzsuiWBHXrD+QmMg0PhKlkPCA=;
        b=FzVwZnBGP/tRc7xpoNNFA3bswYhFoVyunizP3iKyrT0Pd8BUIOZhhHdJ5moyKkMlDx
         0ZLyg2icUadaCCAtMoDsZRtXjXYmDr/5OQR+08j2M98N4sUIIPuuapquuxv5iNFK5gok
         Pj+96n/7BAuXJE38X0KF2gsKQAKeEpSDqAe+pEQw+5AraclNDRSG9pjUEyGlXuZFpguB
         rRqQJUlQLpuL+IP1jih+nh5xrALZFgGxV8IAwzrvRCtA1flEgvHUNLRI3qPPGzutcjf8
         SCxy9Rn8yOd7+V+kPL3d7AoG7w5hI55N16LdBAt3lPHmHJdcpjc0kjpOxyI4M7jTYgKx
         AwLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=G57uxx120emaOkbyWGBzsuiWBHXrD+QmMg0PhKlkPCA=;
        b=Q2MXgwwcSDa6ZQsW1rx2rqVa79oed3Z6IYXftlNf1WxLAYO9OLDkWxlMEFfoSz22us
         EU822gdUkMxbGaZZW5wNJncl513joJhUMjHrVnfDs2a+rxDSEwibpAatdhQkLS81o3fn
         pa4uVmVTBAWQr5JZZzFdWhRu3A5v+S4crLlBO91jntIxjyCNcKFhp4ADWY8bilhb6IJl
         YOYl1xtcfw6eez5GfNv9M81ES20pGMS8c2xz2teMutSgdkpTA9LrKicrvSrreCTUpPvT
         Cav2b81UL4ocfnZWrCQ4ZIvp+bbyEvYXk/ASttcO3SZ7Jzp16CgVEiuPY6IgVRHoyRuX
         fQSw==
X-Gm-Message-State: AOAM530Knj7iSLoUoVPxj+N2SlQWne99JqMK1aDRL07Rjg6YARRJ9sPu
	9jyKJxqe0tkBlmtrxAI7Wzg=
X-Google-Smtp-Source: ABdhPJzkIBYYPW1H0WczZsQv+CUG4OWIIds8qmtlr7e6h1yaD2QMt5u6fHi9hdUo2r3TBqQa7hxi9w==
X-Received: by 2002:a17:902:8605:b029:d0:cbe1:e773 with SMTP id f5-20020a1709028605b02900d0cbe1e773mr1198717plo.26.1599810374727;
        Fri, 11 Sep 2020 00:46:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:96cd:: with SMTP id h13ls659859pfq.0.gmail; Fri, 11 Sep
 2020 00:46:14 -0700 (PDT)
X-Received: by 2002:a63:410:: with SMTP id 16mr790950pge.189.1599810374019;
        Fri, 11 Sep 2020 00:46:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599810374; cv=none;
        d=google.com; s=arc-20160816;
        b=qlwyUy/XgXlE8yF6EneAl7i/e5TTHg5PvQ3Tak/HMfwYPqbimyBKudogvJnR74fBhG
         9FkV0LDP8wzOAINlzjQmF9eyK2awdJ1MB19Sk/p/FKSjrhoubh3VnspssNWA/zgLYWKr
         LSx4v8xVsL5qipCv1Yn1t82JwMV7f+UF4lahrnkCqIid0yfixJPLXUu2vo51UBd54++X
         EXjVKeRUCnbGtJXscRl0MnHAV3i9Vwnfmp20Iof7RRi1hAv2rRtZhz9Z6FX9IeZW63BJ
         Ckj7bilP8JInGd7dwwiILKEroUkt1sqv4YN2cnwOg2j8bwzKfZYP6PpDwNK4ql+ENZ4U
         VRAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xAMAwKSgCkhLU1+HorKufuFkvoMc/AqgwnyXt9BkPkw=;
        b=cX13h6WrGhaZ7Rbd6QrbcqiLUFMJ42HcepRTeSOSMJ9/KlYf8TX7BPxYNf4/qS5PWW
         v0076uz+keNK9ev6pYJWez2ygIiND7TTtc23c5BgQ9FRGBe/EuQS/Qm1Clv0PG7u0mSZ
         ur3eXNIllfmUSugFqd+zHM0FATVprAbLmWvtI47e8uEwaNyKJcm0jn/GPzXlUMc9AYBt
         IwNdjVOt0cQEWKImhfTBJKEbflw59W+GT12TKIAwnlArqqFnq6Xa7j4Mwv0qFjmB6O1B
         pQkP0KsGfsOR3amkHrx6Tre0m3N3++ma2BLmPqsVcKRM6RbX0T1MS0wrOWilXZK42lcR
         rRWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=A5Thz3ng;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id w15si92091pfu.6.2020.09.11.00.46.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 00:46:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id g10so7596052otq.9
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 00:46:13 -0700 (PDT)
X-Received: by 2002:a9d:3da1:: with SMTP id l30mr459810otc.233.1599810372977;
 Fri, 11 Sep 2020 00:46:12 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-10-elver@google.com>
 <CACT4Y+b-RPYpqErLVPh+qtiuv_LhCyxLE_DJqbM0jegFd_nOKQ@mail.gmail.com>
In-Reply-To: <CACT4Y+b-RPYpqErLVPh+qtiuv_LhCyxLE_DJqbM0jegFd_nOKQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 09:46:01 +0200
Message-ID: <CANpmjNOkGChKcav-zRLUTS1tsobXNkounFGSVp0srEk5BDGweg@mail.gmail.com>
Subject: Re: [PATCH RFC 09/10] kfence, Documentation: add KFENCE documentation
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=A5Thz3ng;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Fri, 11 Sep 2020 at 09:14, Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
> >
> > Add KFENCE documentation in dev-tools/kfence.rst, and add to index.
> >
> > Co-developed-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  Documentation/dev-tools/index.rst  |   1 +
> >  Documentation/dev-tools/kfence.rst | 285 +++++++++++++++++++++++++++++
> >  2 files changed, 286 insertions(+)
> >  create mode 100644 Documentation/dev-tools/kfence.rst
> >
> > diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
> > index f7809c7b1ba9..1b1cf4f5c9d9 100644
> > --- a/Documentation/dev-tools/index.rst
> > +++ b/Documentation/dev-tools/index.rst
> > @@ -22,6 +22,7 @@ whole; patches welcome!
> >     ubsan
> >     kmemleak
> >     kcsan
> > +   kfence
> >     gdb-kernel-debugging
> >     kgdb
> >     kselftest
> > diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
> > new file mode 100644
> > index 000000000000..254f4f089104
> > --- /dev/null
> > +++ b/Documentation/dev-tools/kfence.rst
> > @@ -0,0 +1,285 @@
> > +.. SPDX-License-Identifier: GPL-2.0
> > +
> > +Kernel Electric-Fence (KFENCE)
> > +==============================
> > +
> > +Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory safety
> > +error detector. KFENCE detects heap out-of-bounds access, use-after-free, and
> > +invalid-free errors.
> > +
> > +KFENCE is designed to be enabled in production kernels, and has near zero
> > +performance overhead. Compared to KASAN, KFENCE trades performance for
> > +precision. The main motivation behind KFENCE's design, is that with enough
> > +total uptime KFENCE will detect bugs in code paths not typically exercised by
> > +non-production test workloads. One way to quickly achieve a large enough total
> > +uptime is when the tool is deployed across a large fleet of machines.
> > +
> > +Usage
> > +-----
> > +
> > +To enable KFENCE, configure the kernel with::
> > +
> > +    CONFIG_KFENCE=y
> > +
> > +KFENCE provides several other configuration options to customize behaviour (see
> > +the respective help text in ``lib/Kconfig.kfence`` for more info).
> > +
> > +Tuning performance
> > +~~~~~~~~~~~~~~~~~~
> > +
> > +The most important parameter is KFENCE's sample interval, which can be set via
> > +the kernel boot parameter ``kfence.sample_interval`` in milliseconds. The
> > +sample interval determines the frequency with which heap allocations will be
> > +guarded by KFENCE. The default is configurable via the Kconfig option
> > +``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=0``
> > +disables KFENCE.
> > +
> > +With the Kconfig option ``CONFIG_KFENCE_NUM_OBJECTS`` (default 255), the number
> > +of available guarded objects can be controlled. Each object requires 2 pages,
> > +one for the object itself and the other one used as a guard page; object pages
> > +are interleaved with guard pages, and every object page is therefore surrounded
> > +by two guard pages.
> > +
> > +The total memory dedicated to the KFENCE memory pool can be computed as::
> > +
> > +    ( #objects + 1 ) * 2 * PAGE_SIZE
> > +
> > +Using the default config, and assuming a page size of 4 KiB, results in
> > +dedicating 2 MiB to the KFENCE memory pool.
> > +
> > +Error reports
> > +~~~~~~~~~~~~~
> > +
> > +A typical out-of-bounds access looks like this::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: out-of-bounds in test_out_of_bounds_read+0xa3/0x22b
> > +
> > +    Out-of-bounds access at 0xffffffffb672efff (left of kfence-#17):
> > +     test_out_of_bounds_read+0xa3/0x22b
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=32, cache=kmalloc-32] allocated in:
> > +     __kfence_alloc+0x42d/0x4c0
> > +     __kmalloc+0x133/0x200
> > +     test_alloc+0xf3/0x25b
> > +     test_out_of_bounds_read+0x98/0x22b
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 107 Comm: kunit_try_catch Not tainted 5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +The header of the report provides a short summary of the function involved in
> > +the access. It is followed by more detailed information about the access and
> > +its origin.
> > +
> > +Use-after-free accesses are reported as::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: use-after-free in test_use_after_free_read+0xb3/0x143
> > +
> > +    Use-after-free access at 0xffffffffb673dfe0:
> > +     test_use_after_free_read+0xb3/0x143
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=32, cache=kmalloc-32] allocated in:
> > +     __kfence_alloc+0x277/0x4c0
> > +     __kmalloc+0x133/0x200
> > +     test_alloc+0xf3/0x25b
> > +     test_use_after_free_read+0x76/0x143
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
>
> Empty line between stacks for consistency and readability.

Done for v2.

> > +    freed in:
> > +     kfence_guarded_free+0x158/0x380
> > +     __kfence_free+0x38/0xc0
> > +     test_use_after_free_read+0xa8/0x143
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 109 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +KFENCE also reports on invalid frees, such as double-frees::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: invalid free in test_double_free+0xdc/0x171
> > +
> > +    Invalid free of 0xffffffffb6741000:
> > +     test_double_free+0xdc/0x171
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    kfence-#26 [0xffffffffb6741000-0xffffffffb674101f, size=32, cache=kmalloc-32] allocated in:
> > +     __kfence_alloc+0x42d/0x4c0
> > +     __kmalloc+0x133/0x200
> > +     test_alloc+0xf3/0x25b
> > +     test_double_free+0x76/0x171
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +    freed in:
> > +     kfence_guarded_free+0x158/0x380
> > +     __kfence_free+0x38/0xc0
> > +     test_double_free+0xa8/0x171
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 111 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +KFENCE also uses pattern-based redzones on the other side of an object's guard
> > +page, to detect out-of-bounds writes on the unprotected side of the object.
> > +These are reported on frees::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_write+0xef/0x184
> > +
> > +    Detected corrupted memory at 0xffffffffb6797ff9 [ 0xac . . . . . . ]:
> > +     test_kmalloc_aligned_oob_write+0xef/0x184
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=73, cache=kmalloc-96] allocated in:
> > +     __kfence_alloc+0x277/0x4c0
> > +     __kmalloc+0x133/0x200
> > +     test_alloc+0xf3/0x25b
> > +     test_kmalloc_aligned_oob_write+0x57/0x184
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 120 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +For such errors, the address where the corruption as well as the corrupt bytes
> > +are shown.
> > +
> > +And finally, KFENCE may also report on invalid accesses to any protected page
> > +where it was not possible to determine an associated object, e.g. if adjacent
> > +object pages had not yet been allocated::
> > +
> > +    ==================================================================
> > +    BUG: KFENCE: invalid access in test_invalid_access+0x26/0xe0
> > +
> > +    Invalid access at 0xffffffffb670b00a:
> > +     test_invalid_access+0x26/0xe0
> > +     kunit_try_run_case+0x51/0x85
> > +     kunit_generic_run_threadfn_adapter+0x16/0x30
> > +     kthread+0x137/0x160
> > +     ret_from_fork+0x22/0x30
> > +
> > +    CPU: 4 PID: 124 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> > +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> > +    ==================================================================
> > +
> > +DebugFS interface
> > +~~~~~~~~~~~~~~~~~
> > +
> > +Some debugging information is exposed via debugfs:
> > +
> > +* The file ``/sys/kernel/debug/kfence/stats`` provides runtime statistics.
> > +
> > +* The file ``/sys/kernel/debug/kfence/objects`` provides a list of objects
> > +  allocated via KFENCE, including those already freed but protected.
> > +
> > +Implementation Details
> > +----------------------
> > +
> > +Guarded allocations are set up based on the sample interval. After expiration
> > +of the sample interval, a guarded allocation from the KFENCE object pool is
> > +returned to the main allocator (SLAB or SLUB). At this point, the timer is
> > +reset, and the next allocation is set up after the expiration of the interval.
> > +To "gate" a KFENCE allocation through the main allocator's fast-path without
> > +overhead, KFENCE relies on static branches via the static keys infrastructure.
> > +The static branch is toggled to redirect the allocation to KFENCE.
> > +
> > +KFENCE objects each reside on a dedicated page, at either the left or right
>
> Do we mention anywhere explicitly that KFENCE currently only supports
> allocations <=page_size?
> May be worth mentioning. It kinda follows from implementation but
> quite implicitly. One may also be confused assuming KFENCE handles
> larger allocations, but then not being able to figure out.

We can add a note that "allocation sizes up to PAGE_SIZE are supported".

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOkGChKcav-zRLUTS1tsobXNkounFGSVp0srEk5BDGweg%40mail.gmail.com.
