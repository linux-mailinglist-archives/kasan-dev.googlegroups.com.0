Return-Path: <kasan-dev+bncBCMIZB7QWENRBT6H5T5AKGQESJQP5JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id EBF9B265A2F
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 09:14:25 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id f76sf6369324pfa.5
        for <lists+kasan-dev@lfdr.de>; Fri, 11 Sep 2020 00:14:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599808464; cv=pass;
        d=google.com; s=arc-20160816;
        b=KIFke96TQRSFYifKTpmQnpfRaLj1dwRuR2HwTtCCCHYAXcg/Lw6NATQMfgRtJLCFju
         rkZfUScfSs+BFZVc6g1PSFNSECoyjYbVn/lrqYHyMLMOlouxdpaqdeWdiypADvfqyxdO
         SVoQzLQTVJknAZ2uEmO12vORFM+mbdX4VaPplAGN0IEgvtv1PGrKWuaLqxISvUhaJYqq
         qThgwGS757KsCtVexIHdAbTkQdxTAVwjgyCSbTT12dTagKBtjqjNV+CJ5jjcABjYWxKQ
         V5iFd6sW8z88qVG2yFj+IOuqNVgnukijreKXz/2yfSwHsjS4Nfuse+Tn5T3S8ix9A+RI
         d22Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JBzTR3WyhQPnRDxMZM+JIKjOfYh0Aw94QkSwpr5KhPg=;
        b=NdKoKBVXFQ/aQD0D/xCJ9wzWqKIhMb7/gdlbDC/rqnDtoX0IaGzQb6XmpJgADjmr0a
         Kv2CNr1IufkC7zA4mitLtx0N+NI1MJOX7MjhYWANCq5no/OaADWcOIIuwXmnLcjbSO2S
         VC2oQamL+azQ8rcVzgCzG8QXQ5QsJmT8I+aF/DpRi8iwkeD0ZF+gekjIr9Fa5VRP3tzD
         MuezJSLNMWatqSNLHvZWzabpUPbY8kN0iz2szZY62LPbp4N0Li+Zmqs4QV6mmV5gJZih
         JkyAGYc+7GtCnJ0nCEP2cpURMbWSnIyz2yq9GSd1ZWMnp7EbOqu/g3NkZdvTZUCQ8m/I
         SMTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cGD6EZ5G;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JBzTR3WyhQPnRDxMZM+JIKjOfYh0Aw94QkSwpr5KhPg=;
        b=TN1yTc1CCu8twX0YYdo4k8lqqeb74TG91yHvo5xVmON+4iqu+h1quHUK8FT20uO7GZ
         GLNbMfGOl2+P2ZZhk/uVZYBqexput8XJPkl1inY8rFenXdx5pDX7mmXgTRyzLlBeAUkE
         96gOlk7260wR32e1RoYN+hOHdGkB/42TbSjP5hX2JN1Ba4dnE+mQqbUwqH3UQJ0QHKMS
         4J4F6HCPwlweXMtWqtcGaoiHKrxRo6IK07VLrH1LyK6BlKuAJGdVOrAIGi4C01Pq9oOC
         gbUgl/oFbvon0qh7CvoZt4NLc+EySpkrrOJoE72Cc7mDnYVJbWByulXXFjl/ZSZ/H7CT
         8l6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JBzTR3WyhQPnRDxMZM+JIKjOfYh0Aw94QkSwpr5KhPg=;
        b=YZlEvNNMQi5dN4hDuLuNh6+Sf9drd7Xzq+39FHuU/b504TZwd5z9On1vz2e4To4Y1w
         DlHihiq/fnYlBzOe8jd70FsKnbORPHklEgSVVTYxD8tmfBj0XduAgkk8gVcOAbQMUXor
         KyRbP/agI3VfY0tdj2XKIYvY8UCluWQt0tMI+ENpDs9IU0ZS8hdDcGQHtU5vD5vfVzaz
         WKyCENxq+dadxxP1/tdd7StpfL/9Yl+aVoDFLy31H89a3hwcf4SBmmq6fnqGlID8Lx9k
         WHKLNzfsrhV4pBE+xZCJBOk1JFsmLBr0SrD44n220rUTNc7IoIx7fQWdPub6EczwEOe/
         tAzw==
X-Gm-Message-State: AOAM530wuTUeZ4oirI28IU5yojq+PHLzp9AF8cSPvpJdkKxx5QNJsYh+
	28mglmLmm7ejZ/FrRNuYIyw=
X-Google-Smtp-Source: ABdhPJx/wvBqXNnfLhtVsPtcP52kPPfuJRYIpa2BI2qyP2i2MJIY8dauFkHHRENptjyON5SBxf9sDg==
X-Received: by 2002:a17:902:70c8:b029:d0:cbe1:e7ac with SMTP id l8-20020a17090270c8b02900d0cbe1e7acmr1023543plt.29.1599808464037;
        Fri, 11 Sep 2020 00:14:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7b90:: with SMTP id w16ls746193pll.5.gmail; Fri, 11
 Sep 2020 00:14:23 -0700 (PDT)
X-Received: by 2002:a17:90b:4b82:: with SMTP id lr2mr999187pjb.184.1599808463387;
        Fri, 11 Sep 2020 00:14:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599808463; cv=none;
        d=google.com; s=arc-20160816;
        b=psSfTAROG6R4jK8v/51rvqit9NlSoG+tWdasrVCB6RXH2XzL+K6tr+dJ2sRZbz50fJ
         JYIvpK8j6E70T/0pLmA/QyWheh/AcWt+1z7Q7ytM12ZSbSJSwXxQa4rhgHHrl/c//r2A
         sQF39wSCaSG/+HCUuKzYUbuD7ciGUtWHHDIo/O2swpYby1ETOL/+V30mLM1sHSaBa/Cq
         4G25XUA2E1HmD3KDIXgLoP1deaB5WjNcsum7IEVQ44ovLiCvaZ0Urm9Ktujk0Yh2XIA/
         0+y4GFfoM21cINB0GGw/R73iDsfRsTAdwJ+q865yaTW7ZAIZYYqyTe7LB2Xv1tamUxYz
         e0hQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Iq7jn4E6GwevsaQr+w+3QyCKnTOOBmHy/jKNim9F3x0=;
        b=T9U2Xm3fAIErdqbNYfh9qpcVFkC/QF8RNbL8Q5gK7sZOU7Ot5F0js8d6ud4fhSQcOH
         eKzVvu33XIvmGClLeY7JAm/JbApLuqJ3f9qHmIFneYAWPwyox9HsVxXZ+aPl7zCp2s9R
         aaQX+v3MQ8sY6HDZXlyAh9jgucER2DjS/m9BEZoVpizGHvIgydDHISMTYR1E5QW2B8gu
         yiOHXvXEkVYkcICmLl+oVkwX75PitcG6CE3G1gkt7r7kEymje84c1xWT+5oW730Ljg1j
         Xz2JUN/pU+ge7mm3IzTELLH6JkiBvegfYumZDVTiGu/xqys9O/8/Fhj+pmzrdwVRgNni
         pXCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cGD6EZ5G;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id k5si74628pjl.1.2020.09.11.00.14.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 11 Sep 2020 00:14:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id q63so8197378qkf.3
        for <kasan-dev@googlegroups.com>; Fri, 11 Sep 2020 00:14:23 -0700 (PDT)
X-Received: by 2002:a37:5684:: with SMTP id k126mr355198qkb.43.1599808462092;
 Fri, 11 Sep 2020 00:14:22 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-10-elver@google.com>
In-Reply-To: <20200907134055.2878499-10-elver@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 11 Sep 2020 09:14:10 +0200
Message-ID: <CACT4Y+b-RPYpqErLVPh+qtiuv_LhCyxLE_DJqbM0jegFd_nOKQ@mail.gmail.com>
Subject: Re: [PATCH RFC 09/10] kfence, Documentation: add KFENCE documentation
To: Marco Elver <elver@google.com>
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
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cGD6EZ5G;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Mon, Sep 7, 2020 at 3:41 PM Marco Elver <elver@google.com> wrote:
>
> Add KFENCE documentation in dev-tools/kfence.rst, and add to index.
>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  Documentation/dev-tools/index.rst  |   1 +
>  Documentation/dev-tools/kfence.rst | 285 +++++++++++++++++++++++++++++
>  2 files changed, 286 insertions(+)
>  create mode 100644 Documentation/dev-tools/kfence.rst
>
> diff --git a/Documentation/dev-tools/index.rst b/Documentation/dev-tools/index.rst
> index f7809c7b1ba9..1b1cf4f5c9d9 100644
> --- a/Documentation/dev-tools/index.rst
> +++ b/Documentation/dev-tools/index.rst
> @@ -22,6 +22,7 @@ whole; patches welcome!
>     ubsan
>     kmemleak
>     kcsan
> +   kfence
>     gdb-kernel-debugging
>     kgdb
>     kselftest
> diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
> new file mode 100644
> index 000000000000..254f4f089104
> --- /dev/null
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -0,0 +1,285 @@
> +.. SPDX-License-Identifier: GPL-2.0
> +
> +Kernel Electric-Fence (KFENCE)
> +==============================
> +
> +Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory safety
> +error detector. KFENCE detects heap out-of-bounds access, use-after-free, and
> +invalid-free errors.
> +
> +KFENCE is designed to be enabled in production kernels, and has near zero
> +performance overhead. Compared to KASAN, KFENCE trades performance for
> +precision. The main motivation behind KFENCE's design, is that with enough
> +total uptime KFENCE will detect bugs in code paths not typically exercised by
> +non-production test workloads. One way to quickly achieve a large enough total
> +uptime is when the tool is deployed across a large fleet of machines.
> +
> +Usage
> +-----
> +
> +To enable KFENCE, configure the kernel with::
> +
> +    CONFIG_KFENCE=y
> +
> +KFENCE provides several other configuration options to customize behaviour (see
> +the respective help text in ``lib/Kconfig.kfence`` for more info).
> +
> +Tuning performance
> +~~~~~~~~~~~~~~~~~~
> +
> +The most important parameter is KFENCE's sample interval, which can be set via
> +the kernel boot parameter ``kfence.sample_interval`` in milliseconds. The
> +sample interval determines the frequency with which heap allocations will be
> +guarded by KFENCE. The default is configurable via the Kconfig option
> +``CONFIG_KFENCE_SAMPLE_INTERVAL``. Setting ``kfence.sample_interval=0``
> +disables KFENCE.
> +
> +With the Kconfig option ``CONFIG_KFENCE_NUM_OBJECTS`` (default 255), the number
> +of available guarded objects can be controlled. Each object requires 2 pages,
> +one for the object itself and the other one used as a guard page; object pages
> +are interleaved with guard pages, and every object page is therefore surrounded
> +by two guard pages.
> +
> +The total memory dedicated to the KFENCE memory pool can be computed as::
> +
> +    ( #objects + 1 ) * 2 * PAGE_SIZE
> +
> +Using the default config, and assuming a page size of 4 KiB, results in
> +dedicating 2 MiB to the KFENCE memory pool.
> +
> +Error reports
> +~~~~~~~~~~~~~
> +
> +A typical out-of-bounds access looks like this::
> +
> +    ==================================================================
> +    BUG: KFENCE: out-of-bounds in test_out_of_bounds_read+0xa3/0x22b
> +
> +    Out-of-bounds access at 0xffffffffb672efff (left of kfence-#17):
> +     test_out_of_bounds_read+0xa3/0x22b
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +
> +    kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=32, cache=kmalloc-32] allocated in:
> +     __kfence_alloc+0x42d/0x4c0
> +     __kmalloc+0x133/0x200
> +     test_alloc+0xf3/0x25b
> +     test_out_of_bounds_read+0x98/0x22b
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +
> +    CPU: 4 PID: 107 Comm: kunit_try_catch Not tainted 5.8.0-rc6+ #7
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> +    ==================================================================
> +
> +The header of the report provides a short summary of the function involved in
> +the access. It is followed by more detailed information about the access and
> +its origin.
> +
> +Use-after-free accesses are reported as::
> +
> +    ==================================================================
> +    BUG: KFENCE: use-after-free in test_use_after_free_read+0xb3/0x143
> +
> +    Use-after-free access at 0xffffffffb673dfe0:
> +     test_use_after_free_read+0xb3/0x143
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +
> +    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=32, cache=kmalloc-32] allocated in:
> +     __kfence_alloc+0x277/0x4c0
> +     __kmalloc+0x133/0x200
> +     test_alloc+0xf3/0x25b
> +     test_use_after_free_read+0x76/0x143
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30

Empty line between stacks for consistency and readability.

> +    freed in:
> +     kfence_guarded_free+0x158/0x380
> +     __kfence_free+0x38/0xc0
> +     test_use_after_free_read+0xa8/0x143
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +
> +    CPU: 4 PID: 109 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> +    ==================================================================
> +
> +KFENCE also reports on invalid frees, such as double-frees::
> +
> +    ==================================================================
> +    BUG: KFENCE: invalid free in test_double_free+0xdc/0x171
> +
> +    Invalid free of 0xffffffffb6741000:
> +     test_double_free+0xdc/0x171
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +
> +    kfence-#26 [0xffffffffb6741000-0xffffffffb674101f, size=32, cache=kmalloc-32] allocated in:
> +     __kfence_alloc+0x42d/0x4c0
> +     __kmalloc+0x133/0x200
> +     test_alloc+0xf3/0x25b
> +     test_double_free+0x76/0x171
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +    freed in:
> +     kfence_guarded_free+0x158/0x380
> +     __kfence_free+0x38/0xc0
> +     test_double_free+0xa8/0x171
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +
> +    CPU: 4 PID: 111 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> +    ==================================================================
> +
> +KFENCE also uses pattern-based redzones on the other side of an object's guard
> +page, to detect out-of-bounds writes on the unprotected side of the object.
> +These are reported on frees::
> +
> +    ==================================================================
> +    BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_write+0xef/0x184
> +
> +    Detected corrupted memory at 0xffffffffb6797ff9 [ 0xac . . . . . . ]:
> +     test_kmalloc_aligned_oob_write+0xef/0x184
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +
> +    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=73, cache=kmalloc-96] allocated in:
> +     __kfence_alloc+0x277/0x4c0
> +     __kmalloc+0x133/0x200
> +     test_alloc+0xf3/0x25b
> +     test_kmalloc_aligned_oob_write+0x57/0x184
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +
> +    CPU: 4 PID: 120 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> +    ==================================================================
> +
> +For such errors, the address where the corruption as well as the corrupt bytes
> +are shown.
> +
> +And finally, KFENCE may also report on invalid accesses to any protected page
> +where it was not possible to determine an associated object, e.g. if adjacent
> +object pages had not yet been allocated::
> +
> +    ==================================================================
> +    BUG: KFENCE: invalid access in test_invalid_access+0x26/0xe0
> +
> +    Invalid access at 0xffffffffb670b00a:
> +     test_invalid_access+0x26/0xe0
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
> +
> +    CPU: 4 PID: 124 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
> +    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
> +    ==================================================================
> +
> +DebugFS interface
> +~~~~~~~~~~~~~~~~~
> +
> +Some debugging information is exposed via debugfs:
> +
> +* The file ``/sys/kernel/debug/kfence/stats`` provides runtime statistics.
> +
> +* The file ``/sys/kernel/debug/kfence/objects`` provides a list of objects
> +  allocated via KFENCE, including those already freed but protected.
> +
> +Implementation Details
> +----------------------
> +
> +Guarded allocations are set up based on the sample interval. After expiration
> +of the sample interval, a guarded allocation from the KFENCE object pool is
> +returned to the main allocator (SLAB or SLUB). At this point, the timer is
> +reset, and the next allocation is set up after the expiration of the interval.
> +To "gate" a KFENCE allocation through the main allocator's fast-path without
> +overhead, KFENCE relies on static branches via the static keys infrastructure.
> +The static branch is toggled to redirect the allocation to KFENCE.
> +
> +KFENCE objects each reside on a dedicated page, at either the left or right

Do we mention anywhere explicitly that KFENCE currently only supports
allocations <=page_size?
May be worth mentioning. It kinda follows from implementation but
quite implicitly. One may also be confused assuming KFENCE handles
larger allocations, but then not being able to figure out.

> +page boundaries selected at random. The pages to the left and right of the
> +object page are "guard pages", whose attributes are changed to a protected
> +state, and cause page faults on any attempted access. Such page faults are then
> +intercepted by KFENCE, which handles the fault gracefully by reporting an
> +out-of-bounds access. The side opposite of an object's guard page is used as a
> +pattern-based redzone, to detect out-of-bounds writes on the unprotected sed of
> +the object on frees (for special alignment and size combinations, both sides of
> +the object are redzoned).
> +
> +KFENCE also uses pattern-based redzones on the other side of an object's guard
> +page, to detect out-of-bounds writes on the unprotected side of the object;
> +these are reported on frees.
> +
> +The following figure illustrates the page layout::
> +
> +    ---+-----------+-----------+-----------+-----------+-----------+---
> +       | xxxxxxxxx | O :       | xxxxxxxxx |       : O | xxxxxxxxx |
> +       | xxxxxxxxx | B :       | xxxxxxxxx |       : B | xxxxxxxxx |
> +       | x GUARD x | J : RED-  | x GUARD x | RED-  : J | x GUARD x |
> +       | xxxxxxxxx | E :  ZONE | xxxxxxxxx |  ZONE : E | xxxxxxxxx |
> +       | xxxxxxxxx | C :       | xxxxxxxxx |       : C | xxxxxxxxx |
> +       | xxxxxxxxx | T :       | xxxxxxxxx |       : T | xxxxxxxxx |
> +    ---+-----------+-----------+-----------+-----------+-----------+---
> +
> +Upon deallocation of a KFENCE object, the object's page is again protected and
> +the object is marked as freed. Any further access to the object causes a fault
> +and KFENCE reports a use-after-free access. Freed objects are inserted at the
> +tail of KFENCE's freelist, so that the least recently freed objects are reused
> +first, and the chances of detecting use-after-frees of recently freed objects
> +is increased.
> +
> +Interface
> +---------
> +
> +The following describes the functions which are used by allocators as well page
> +handling code to set up and deal with KFENCE allocations.
> +
> +.. kernel-doc:: include/linux/kfence.h
> +   :functions: is_kfence_address
> +               kfence_shutdown_cache
> +               kfence_alloc kfence_free
> +               kfence_ksize kfence_object_start
> +               kfence_handle_page_fault
> +
> +Related Tools
> +-------------
> +
> +In userspace, a similar approach is taken by `GWP-ASan
> +<http://llvm.org/docs/GwpAsan.html>`_. GWP-ASan also relies on guard pages and
> +a sampling strategy to detect memory unsafety bugs at scale. KFENCE's design is
> +directly influenced by GWP-ASan, and can be seen as its kernel sibling. Another
> +similar but non-sampling approach, that also inspired the name "KFENCE", can be
> +found in the userspace `Electric Fence Malloc Debugger
> +<https://linux.die.net/man/3/efence>`_.
> +
> +In the kernel, several tools exist to debug memory access errors, and in
> +particular KASAN can detect all bug classes that KFENCE can detect. While KASAN
> +is more precise, relying on compiler instrumentation, this comes at a
> +performance cost. We want to highlight that KASAN and KFENCE are complementary,
> +with different target environments. For instance, KASAN is the better
> +debugging-aid, where a simple reproducer exists: due to the lower chance to
> +detect the error, it would require more effort using KFENCE to debug.
> +Deployments at scale, however, would benefit from using KFENCE to discover bugs
> +due to code paths not exercised by test cases or fuzzers.
> --
> 2.28.0.526.ge36021eeef-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb-RPYpqErLVPh%2Bqtiuv_LhCyxLE_DJqbM0jegFd_nOKQ%40mail.gmail.com.
