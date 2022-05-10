Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLFK5GJQMGQE4IKFKHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DAA05214CD
	for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 14:06:05 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id l26-20020a2e99da000000b0024f02d881cdsf5081900ljj.6
        for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 05:06:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652184364; cv=pass;
        d=google.com; s=arc-20160816;
        b=eZM4oxxVvR2ro1fWc6WnF/GSgw/rETxkc/+BSJX8bl9WXkVSj2BX1c+xhh9zy4DbaS
         73FbCTBsFqk/9ztMYDWODlp1ntKWRWtn21F0VSsLC8CixuFicparRmvaFqq2wugvzeOV
         etOdFmYL04PZhMxigbArTlhlnWXc3e/m1ZOW0PM7czJhOSvAfRrnssKNtBjB104GFfVl
         Bi9XFK25IgbLk36QMd+SwOqUQmq+tw6FrtE6CaPuy5+qfSuRb6kxA78ZWMvB/LOpSoiV
         lg3c3xAzVPwxj/pKyRuvy2EjGzgLBoOIfZkiBGcQ/7tQqRZG7NfIRBqndBTkO9ttNdqr
         26hw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=imG/2elSzrHOdgNsfcFLNRZGQ+/jUjwR+gwTuMQyU54=;
        b=zRyJrRwwwGRZJ3/j4cAOLMT4lu8++wqB/vxh7t7EnQs5zbKnBgtuUK+sfRyQOCeTzy
         DzoStP79BwRk/zuvXOI0MriL2gbYmM7JinbFHk3ta9fodpSiAzGb2e207CpJqTfzrlj6
         QpbKt4ttV9nQ1HXBJCCZdBN0Ymd1po5UuLRmzdtMhlPnEsp9nOd/xhYX8jIHkgYF5iZD
         veoMBs/bCZlttHxKC4eyvgg8C4HCWfadljq7LjXWrYr7oI6vMZQ0DN9FmRZhEtAlVv6T
         HNC12AqQd+a67UlWHYng8wHZb40+HdW6GLZCwUYydAdouCOvBx0TOPHn7pfhyihT4qfl
         r7UA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PMx3kpP5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=imG/2elSzrHOdgNsfcFLNRZGQ+/jUjwR+gwTuMQyU54=;
        b=S9wC1BYOAHFfzFU6fgrUsWg/k4Dx6N2bV/H76erpYZnvfwDPLEgPsjdDBFr7AJgfem
         fN1hpcjwxzOIG3Jt9gBW6NpXnwXfM+7AIva38NRNb/jPKPm+0TZTeKt5DN62zKBc/NJH
         DlEf7iP90PYOreaeD4bEUN506c3SLM3IBb3SaGGIYDbGuul5SBiDZlUuIXVjm2qQIdbe
         JFyVT20v1LLkeI5My99CECy9CBWW7qesrIoY2JajPI3prAZEOd+0BaSu3hHHJ+MpscX1
         y1raAXkZDQOFK7LBWIQosgkq1gmzs8/fXPGy+qoNaR3Apidp96vRXWCwANoeTe8ru8rt
         CXDQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=imG/2elSzrHOdgNsfcFLNRZGQ+/jUjwR+gwTuMQyU54=;
        b=zAnaf6KYKXYAVIemG++fG6pyUeM3j21DUDnYuN608ZhhJX64bonXYQxLZWCJQKuJGO
         Ylo8MTHvNPnF/4lB6b+WEtG9+V+0YPOwXL6EikCfRtoWvq37TftixQB7g6F/P/q5ofBy
         CZ2g6+8vjA2I07ZZZ8pGPXljurPCKNi+mSYl+U0XakLm6yXmzolLQcMUvqDIXsc4ze1R
         UmxH/32xKLLlKaBmE5PWlrtG6fMzza172k5/UmHNqNGe0E8Qon4748LBxoCiGLq+GYs1
         6lW851ISZF6bzbDpiDS2djFRhTAPLxovnwoDvcB5RLk6EK3UyhT/8LfVhcfT0cti/Nqy
         GDEg==
X-Gm-Message-State: AOAM531OZiZVdmt0m9/2YeVNsxfm1J2CyU7TU1A3pBGdhW8QxSMftY4b
	kGivhTd2CwWJ43YzRxfuo48=
X-Google-Smtp-Source: ABdhPJzX4sm/0AHQSR3vMtXjnsWwDwA7JqzQI+9bVaSgbAuRrz6pIdIIEwC/Wg5tX+FR/0e6wM2HFQ==
X-Received: by 2002:a05:6512:3d87:b0:473:a178:690f with SMTP id k7-20020a0565123d8700b00473a178690fmr16690686lfv.353.1652184364806;
        Tue, 10 May 2022 05:06:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:553:b0:250:615f:dbd1 with SMTP id
 q19-20020a05651c055300b00250615fdbd1ls3511983ljp.7.gmail; Tue, 10 May 2022
 05:06:03 -0700 (PDT)
X-Received: by 2002:a2e:88ce:0:b0:24f:fff:603c with SMTP id a14-20020a2e88ce000000b0024f0fff603cmr13855247ljk.527.1652184363357;
        Tue, 10 May 2022 05:06:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652184363; cv=none;
        d=google.com; s=arc-20160816;
        b=m92PL0Tw9XJc5WMqCmgqwStv10eET60CKDhdP3w/VX9bmqu6uLOSiuHhev/KiBK0gk
         i4L9BvUp99qm58FtzK1xG/vCRda1LBofra+G4mtO6gsukoUkV0AVEwNTltY9TYREyROr
         x0wQk5/EsHCN8D+wOyfWINzceZgi9t1uO/FOARMOpBsz5CgQWJJxRDiRT8lcRbwk9asp
         0VlwHtBDXzLMjPRAXzG4NvA6MTYvCewq0e84+l5epynuJgl4D1uyA1/eEQD1Wxb5XC87
         lbuCYqf3bVe/W0KZjnYpU6QsT9uIdoOyOeqrUNmYj0W0jJCAEeM4epRk+MNge4KyGvH+
         PNmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=oWkJBDkeq4gmtzRx6NRpFA5vku8/WyRK30dRLyQT1IE=;
        b=S7O4ZSoqLWlx9g5Z59WgTzdCqQH1bl/TTfZycncXNfcYZBtYq63826tWbrpLTuuxGr
         9NrQAK06Ae/Rt7/FJdXDPj0GnWxn2RSufYQStFL/bcQ9NdVDxW+ytE12X7bHwm+HGMd4
         kavJVFJb6LXL3zu+eUVp8rIV70Xg7ervQRxiNmpaevqF3AfqpuLJUkk2viDiqDVFGTYz
         yPebKp4KSfgSgzIQQPiIW4iH1opmnKHCqTcQCdMoGE/MkGRUOjVz+6G0Ad7/DKPqbUWp
         Z9ohWbjl3TQUgB5rUihFMr+XAFFWECfRnlbK0wqrh8itMUeqSVpFoLIwGSAt71LSSRxZ
         mmXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=PMx3kpP5;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x333.google.com (mail-wm1-x333.google.com. [2a00:1450:4864:20::333])
        by gmr-mx.google.com with ESMTPS id b7-20020a056512070700b004720a623d80si787847lfs.7.2022.05.10.05.06.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 May 2022 05:06:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as permitted sender) client-ip=2a00:1450:4864:20::333;
Received: by mail-wm1-x333.google.com with SMTP id r1-20020a1c2b01000000b00394398c5d51so1278670wmr.2
        for <kasan-dev@googlegroups.com>; Tue, 10 May 2022 05:06:03 -0700 (PDT)
X-Received: by 2002:a05:600c:4ed1:b0:394:8352:3ea1 with SMTP id g17-20020a05600c4ed100b0039483523ea1mr15503780wmq.153.1652184362787;
        Tue, 10 May 2022 05:06:02 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:15:13:640f:aa66:3ec8:cbb6])
        by smtp.gmail.com with ESMTPSA id d3-20020a05600c3ac300b00394586f696dsm2361872wms.11.2022.05.10.05.06.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 10 May 2022 05:06:02 -0700 (PDT)
Date: Tue, 10 May 2022 14:05:56 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 1/3] kasan: update documentation
Message-ID: <YnpVJJz9IKyvBfFI@elver.google.com>
References: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=PMx3kpP5;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::333 as
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

On Mon, May 09, 2022 at 09:07PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Do assorted clean-ups and improvements to KASAN documentation, including:
> 
> - Describe each mode in a dedicated paragraph.
> - Split out a Support section that describes in details which compilers,
>   architectures and memory types each mode requires/supports.
> - Capitalize the first letter in the names of each KASAN mode.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Marco Elver <elver@google.com>

But see comment below.

> ---
>  Documentation/dev-tools/kasan.rst | 143 ++++++++++++++++++------------
>  1 file changed, 87 insertions(+), 56 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
> index 7614a1fc30fa..aca219ed1198 100644
> --- a/Documentation/dev-tools/kasan.rst
> +++ b/Documentation/dev-tools/kasan.rst
> @@ -4,39 +4,76 @@ The Kernel Address Sanitizer (KASAN)
>  Overview
>  --------
>  
> -KernelAddressSANitizer (KASAN) is a dynamic memory safety error detector
> -designed to find out-of-bound and use-after-free bugs. KASAN has three modes:
> +Kernel Address Sanitizer (KASAN) is a dynamic memory safety error detector
> +designed to find out-of-bounds and use-after-free bugs.
>  
> -1. generic KASAN (similar to userspace ASan),
> -2. software tag-based KASAN (similar to userspace HWASan),
> -3. hardware tag-based KASAN (based on hardware memory tagging).
> +KASAN has three modes:
>  
> -Generic KASAN is mainly used for debugging due to a large memory overhead.
> -Software tag-based KASAN can be used for dogfood testing as it has a lower
> -memory overhead that allows using it with real workloads. Hardware tag-based
> -KASAN comes with low memory and performance overheads and, therefore, can be
> -used in production. Either as an in-field memory bug detector or as a security
> -mitigation.
> +1. Generic KASAN
> +2. Software Tag-Based KASAN
> +3. Hardware Tag-Based KASAN
>  
> -Software KASAN modes (#1 and #2) use compile-time instrumentation to insert
> -validity checks before every memory access and, therefore, require a compiler
> -version that supports that.
> +Generic KASAN, enabled with CONFIG_KASAN_GENERIC, is the mode intended for
> +debugging, similar to userspace ASan. This mode is supported on many CPU
> +architectures, but it has significant performance and memory overheads.
>  
> -Generic KASAN is supported in GCC and Clang. With GCC, it requires version
> -8.3.0 or later. Any supported Clang version is compatible, but detection of
> -out-of-bounds accesses for global variables is only supported since Clang 11.
> +Software Tag-Based KASAN or SW_TAGS KASAN, enabled with CONFIG_KASAN_SW_TAGS,
> +can be used for both debugging and dogfood testing, similar to userspace HWASan.
> +This mode is only supported for arm64, but its moderate memory overhead allows
> +using it for testing on memory-restricted devices with real workloads.
>  
> -Software tag-based KASAN mode is only supported in Clang.
> +Hardware Tag-Based KASAN or HW_TAGS KASAN, enabled with CONFIG_KASAN_HW_TAGS,
> +is the mode intended to be used as an in-field memory bug detector or as a
> +security mitigation. This mode only works on arm64 CPUs that support MTE
> +(Memory Tagging Extension), but it has low memory and performance overheads and
> +thus can be used in production.
>  
> -The hardware KASAN mode (#3) relies on hardware to perform the checks but
> -still requires a compiler version that supports memory tagging instructions.
> -This mode is supported in GCC 10+ and Clang 12+.
> +For details about the memory and performance impact of each KASAN mode, see the
> +descriptions of the corresponding Kconfig options.
>  
> -Both software KASAN modes work with SLUB and SLAB memory allocators,
> -while the hardware tag-based KASAN currently only supports SLUB.
> +The Generic and the Software Tag-Based modes are commonly referred to as the
> +software modes. The Software Tag-Based and the Hardware Tag-Based modes are
> +referred to as the tag-based modes.
>  
> -Currently, generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390,
> -and riscv architectures, and tag-based KASAN modes are supported only for arm64.
> +Support
> +-------
> +
> +Architectures
> +~~~~~~~~~~~~~
> +
> +Generic KASAN is supported on x86_64, arm, arm64, powerpc, riscv, s390, and
> +xtensa, and the tag-based KASAN modes are supported only on arm64.
> +
> +Compilers
> +~~~~~~~~~
> +
> +Software KASAN modes use compile-time instrumentation to insert validity checks
> +before every memory access and thus require a compiler version that provides
> +support for that. The Hardware Tag-Based mode relies on hardware to perform
> +these checks but still requires a compiler version that supports the memory
> +tagging instructions.
> +
> +Generic KASAN requires GCC version 8.3.0 or later
> +or any Clang version supported by the kernel.
> +
> +Software Tag-Based KASAN requires GCC 11+
> +or any Clang version supported by the kernel.
> +
> +Hardware Tag-Based KASAN requires GCC 10+ or Clang 12+.
> +
> +Memory types
> +~~~~~~~~~~~~
> +
> +Generic KASAN supports finding bugs in all of slab, page_alloc, vmap, vmalloc,
> +stack, and global memory.
> +
> +Software Tag-Based KASAN supports slab, page_alloc, vmalloc, and stack memory.
> +
> +Hardware Tag-Based KASAN supports slab, page_alloc, and non-executable vmalloc
> +memory.
> +
> +For slab, both software KASAN modes support SLUB and SLAB allocators, while
> +Hardware Tag-Based KASAN only supports SLUB.
>  
>  Usage
>  -----
> @@ -45,13 +82,13 @@ To enable KASAN, configure the kernel with::
>  
>  	  CONFIG_KASAN=y
>  
> -and choose between ``CONFIG_KASAN_GENERIC`` (to enable generic KASAN),
> -``CONFIG_KASAN_SW_TAGS`` (to enable software tag-based KASAN), and
> -``CONFIG_KASAN_HW_TAGS`` (to enable hardware tag-based KASAN).
> +and choose between ``CONFIG_KASAN_GENERIC`` (to enable Generic KASAN),
> +``CONFIG_KASAN_SW_TAGS`` (to enable Software Tag-Based KASAN), and
> +``CONFIG_KASAN_HW_TAGS`` (to enable Hardware Tag-Based KASAN).
>  
> -For software modes, also choose between ``CONFIG_KASAN_OUTLINE`` and
> +For the software modes, also choose between ``CONFIG_KASAN_OUTLINE`` and
>  ``CONFIG_KASAN_INLINE``. Outline and inline are compiler instrumentation types.
> -The former produces a smaller binary while the latter is 1.1-2 times faster.
> +The former produces a smaller binary while the latter is up to 2 times faster.
>  
>  To include alloc and free stack traces of affected slab objects into reports,
>  enable ``CONFIG_STACKTRACE``. To include alloc and free stack traces of affected
> @@ -146,7 +183,7 @@ is either 8 or 16 aligned bytes depending on KASAN mode. Each number in the
>  memory state section of the report shows the state of one of the memory
>  granules that surround the accessed address.
>  
> -For generic KASAN, the size of each memory granule is 8. The state of each
> +For Generic KASAN, the size of each memory granule is 8. The state of each
>  granule is encoded in one shadow byte. Those 8 bytes can be accessible,
>  partially accessible, freed, or be a part of a redzone. KASAN uses the following
>  encoding for each shadow byte: 00 means that all 8 bytes of the corresponding
> @@ -181,14 +218,14 @@ By default, KASAN prints a bug report only for the first invalid memory access.
>  With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
>  effectively disables ``panic_on_warn`` for KASAN reports.
>  
> -Alternatively, independent of ``panic_on_warn`` the ``kasan.fault=`` boot
> +Alternatively, independent of ``panic_on_warn``, the ``kasan.fault=`` boot
>  parameter can be used to control panic and reporting behaviour:
>  
>  - ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
>    report or also panic the kernel (default: ``report``). The panic happens even
>    if ``kasan_multi_shot`` is enabled.
>  
> -Hardware tag-based KASAN mode (see the section about various modes below) is
> +Hardware Tag-Based KASAN mode (see the section about various modes below) is
>  intended for use in production as a security mitigation. Therefore, it supports
>  additional boot parameters that allow disabling KASAN or controlling features:
>  
> @@ -250,49 +287,46 @@ outline-instrumented kernel.
>  Generic KASAN is the only mode that delays the reuse of freed objects via
>  quarantine (see mm/kasan/quarantine.c for implementation).
>  
> -Software tag-based KASAN
> +Software Tag-Based KASAN
>  ~~~~~~~~~~~~~~~~~~~~~~~~
>  
> -Software tag-based KASAN uses a software memory tagging approach to checking
> +Software Tag-Based KASAN uses a software memory tagging approach to checking
>  access validity. It is currently only implemented for the arm64 architecture.
>  
> -Software tag-based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
> +Software Tag-Based KASAN uses the Top Byte Ignore (TBI) feature of arm64 CPUs
>  to store a pointer tag in the top byte of kernel pointers. It uses shadow memory
>  to store memory tags associated with each 16-byte memory cell (therefore, it
>  dedicates 1/16th of the kernel memory for shadow memory).
>  
> -On each memory allocation, software tag-based KASAN generates a random tag, tags
> +On each memory allocation, Software Tag-Based KASAN generates a random tag, tags
>  the allocated memory with this tag, and embeds the same tag into the returned
>  pointer.
>  
> -Software tag-based KASAN uses compile-time instrumentation to insert checks
> +Software Tag-Based KASAN uses compile-time instrumentation to insert checks
>  before each memory access. These checks make sure that the tag of the memory
>  that is being accessed is equal to the tag of the pointer that is used to access
> -this memory. In case of a tag mismatch, software tag-based KASAN prints a bug
> +this memory. In case of a tag mismatch, Software Tag-Based KASAN prints a bug
>  report.
>  
> -Software tag-based KASAN also has two instrumentation modes (outline, which
> +Software Tag-Based KASAN also has two instrumentation modes (outline, which
>  emits callbacks to check memory accesses; and inline, which performs the shadow
>  memory checks inline). With outline instrumentation mode, a bug report is
>  printed from the function that performs the access check. With inline
>  instrumentation, a ``brk`` instruction is emitted by the compiler, and a
>  dedicated ``brk`` handler is used to print bug reports.
>  
> -Software tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
> +Software Tag-Based KASAN uses 0xFF as a match-all pointer tag (accesses through
>  pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
>  reserved to tag freed memory regions.
>  
> -Software tag-based KASAN currently only supports tagging of slab, page_alloc,
> -and vmalloc memory.
> -
> -Hardware tag-based KASAN
> +Hardware Tag-Based KASAN
>  ~~~~~~~~~~~~~~~~~~~~~~~~
>  
> -Hardware tag-based KASAN is similar to the software mode in concept but uses
> +Hardware Tag-Based KASAN is similar to the software mode in concept but uses
>  hardware memory tagging support instead of compiler instrumentation and
>  shadow memory.
>  
> -Hardware tag-based KASAN is currently only implemented for arm64 architecture
> +Hardware Tag-Based KASAN is currently only implemented for arm64 architecture
>  and based on both arm64 Memory Tagging Extension (MTE) introduced in ARMv8.5
>  Instruction Set Architecture and Top Byte Ignore (TBI).
>  
> @@ -302,21 +336,18 @@ access, hardware makes sure that the tag of the memory that is being accessed is
>  equal to the tag of the pointer that is used to access this memory. In case of a
>  tag mismatch, a fault is generated, and a report is printed.
>  
> -Hardware tag-based KASAN uses 0xFF as a match-all pointer tag (accesses through
> +Hardware Tag-Based KASAN uses 0xFF as a match-all pointer tag (accesses through
>  pointers with the 0xFF pointer tag are not checked). The value 0xFE is currently
>  reserved to tag freed memory regions.
>  
> -Hardware tag-based KASAN currently only supports tagging of slab, page_alloc,
> -and VM_ALLOC-based vmalloc memory.
> -
> -If the hardware does not support MTE (pre ARMv8.5), hardware tag-based KASAN
> +If the hardware does not support MTE (pre ARMv8.5), Hardware Tag-Based KASAN
>  will not be enabled. In this case, all KASAN boot parameters are ignored.
>  
>  Note that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
>  enabled. Even when ``kasan.mode=off`` is provided or when the hardware does not
>  support MTE (but supports TBI).
>  
> -Hardware tag-based KASAN only reports the first found bug. After that, MTE tag
> +Hardware Tag-Based KASAN only reports the first found bug. After that, MTE tag
>  checking gets disabled.
>  
>  Shadow memory
> @@ -414,15 +445,15 @@ generic ``noinstr`` one.
>  Note that disabling compiler instrumentation (either on a per-file or a
>  per-function basis) makes KASAN ignore the accesses that happen directly in
>  that code for software KASAN modes. It does not help when the accesses happen
> -indirectly (through calls to instrumented functions) or with the hardware
> -tag-based mode that does not use compiler instrumentation.
> +indirectly (through calls to instrumented functions) or with Hardware
> +Tag-Based KASAN, which does not use compiler instrumentation.
>  
>  For software KASAN modes, to disable KASAN reports in a part of the kernel code
>  for the current task, annotate this part of the code with a
>  ``kasan_disable_current()``/``kasan_enable_current()`` section. This also
>  disables the reports for indirect accesses that happen through function calls.
>  
> -For tag-based KASAN modes (include the hardware one), to disable access
> +For tag-based KASAN modes (include the Hardware one), to disable access

The changes related to capitalization appear weird here. At least in
this case, it starts with "tag-based" (lower case) and then in braces
".. the Hardware one". This does not look like correct English.

The "hardware" here is not part of a name, so no need for
capitalization. And "tag-based" can also stay lower case, since it is
not part of a name either, but an adjective to "KASAN".

Or you rewrite the sentence.

>  checking, use ``kasan_reset_tag()`` or ``page_kasan_tag_reset()``. Note that
>  temporarily disabling access checking via ``page_kasan_tag_reset()`` requires
>  saving and restoring the per-page KASAN tag via
> -- 
> 2.25.1
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YnpVJJz9IKyvBfFI%40elver.google.com.
