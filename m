Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7NF3H5AKGQEK2PKRGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id D75B325FD39
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Sep 2020 17:34:22 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id u6sf3991372plq.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Sep 2020 08:34:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599492861; cv=pass;
        d=google.com; s=arc-20160816;
        b=l9ERdnW0nmB8QAK00HYdIPykyIVi29q/SLD4hR5HA382fX2iaifVLfQkBBYg9rAPcx
         c7MV2f8y55fX4IXdHeQlpxLSBWa/UQ1P/Ds7o4osPEj9kckFoxu9AYyKE0fD9apwcU9D
         SJfWm2yiN5XWBwawMe4mwuSiZByD8Mz0eDyu4PZ4rOE/OnFKp+z0JLGpk7sL1gemfimz
         5FerVFf6+SusVLmoekIyw+8zeogn/rdPvpNp5Tn3g31mRIRRV7fOed6vhubKoX1RmMFr
         Kno9nh97oXhqKuAy2SIX3xQWcXZDHwFG3Y0UL4vJRiL8vULFoCScLKzcc+cqD38EQhUM
         BG8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zkMfR85D57b17J0owW0Owpj5T0eQJkQ3UALYW8ilJWw=;
        b=b4dWHO6q/InPmyIRavjt3g2BTyKcGbg2EARHWgHjPjz0aGTR0SaizbWMjPvJdETbI/
         tHknDrG2r7yeL5bIYsSEFQbDxuBIKQkTE6iIJN8W0Ph6SFKOfDyNfhT6HaJO1mKA2ac/
         XTb0icXcfX5/mHHReohIFDPCd4khwFoR4JCb1aSgqk3t8dIRFRCbNpsVrC/r2kSn0cNf
         DhMEXtYC8N49aCvcS01AIDX8o4WAFvvRReuIbyW456siqmapze8YQKNmmdbfyRJZCzps
         LS70p9bFwX4vnm8jo0C4Ij3M7R9j0Briuqo0oKzxdPRX2njs3UK6M/Z6gbF+iJ9arIWL
         yk/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C77BjO4d;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zkMfR85D57b17J0owW0Owpj5T0eQJkQ3UALYW8ilJWw=;
        b=Bekmb17ENoXYeWlsl5iQQfTmz2Neffpl5vd/WUsfUYpoyv0ASC6qCWGlWOtjHIKSO4
         hQur6VSKFZn4VrYOtc4QuLwoWW8nhzcKeZ4p0rI7Vmbf1vE8yNRqdx1Y8DZOS40tGWVW
         hztaCg9m4whlARg+oWBiMDSkcnEsRgWKF2/8gRUxuw6pafISzS15gOd1QF1993BXeaSY
         vyp+UsH2ISA3cvVrm0At0tJ1heQYYUaWwAGiCPk2Ma6cQELOcG1m444MkRW40ff6iPjZ
         j9hh8mujaClwW9hzkAxfNO0KAXaQnNihaVJwW6gRkkrW+F/uar7avo3DNWp+EWPQ8O9q
         1NEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zkMfR85D57b17J0owW0Owpj5T0eQJkQ3UALYW8ilJWw=;
        b=aJY8RPKSOyCZh9AlPAhkJl/QD54wixt0gB0TIfk9mhTM2p5M/W06836VDy/YLX6dM5
         taR4SoR1w8+5x7QGNlF8r2zLLAvOap2jwuvdkmlQFCMAL/YPt46srDrqYMvy97qy37UM
         HOou2c0ZB5vSWTJccFhz5l3oOmJEh/476x2wu+l7Nw1AMUIfxp4Wnd0mYSBECadzGtPp
         6ARMOgB2zgiew5vK2DfAOW6wFced+ZfQTXPOJsj0b2L/AE2LtFx4qrlnNKWhvGL1ZMHy
         zHnt7JTaPdLzVf76lbOopU1Ow9B/VPBGk+T/apwxNQtVA4fvkTvOd5S7wX82uUJECXiJ
         htCA==
X-Gm-Message-State: AOAM531uXL94RvHbB1GoDO4Rd7RdESYH08syU8gbHirFE5hnAeElmB1b
	HzMvAHXmgLv4yTpG3gSBxkc=
X-Google-Smtp-Source: ABdhPJxF/GMmYltD71Ov2P9OlbALPDkcsDdKrScnD49/xoq9c5OnrT7lGZdaerq9brtYncgcSgxFjw==
X-Received: by 2002:a63:5043:: with SMTP id q3mr16759992pgl.293.1599492861502;
        Mon, 07 Sep 2020 08:34:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3590:: with SMTP id mm16ls7426238pjb.3.canary-gmail;
 Mon, 07 Sep 2020 08:34:21 -0700 (PDT)
X-Received: by 2002:a17:902:7b83:: with SMTP id w3mr20451823pll.28.1599492860983;
        Mon, 07 Sep 2020 08:34:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599492860; cv=none;
        d=google.com; s=arc-20160816;
        b=zm15xQKfb4/ltq3uIpsJqGRkF2cwo3qGMJmPb2a43ERiUm4/G6ra5N5vR2yupVdimn
         ZUX9DZjYTEsAE4BZMgk2UY8ri1+9H8juJMgFt/oftOx+sHm26FnJUg2kUQmqiMc0W1A3
         MBMA9wgePx+ylnPR/pxR4zzDf2IAvqW2ocIbAErIeJDIITVzb7qJ68M+/f7oPTK6Lqf3
         /OTtBtbdQANMZrYLLQN7yOtKZQP3vfEN3+ze/QbC84ACmMSSN1NiY4LuarYehjYOYvoi
         4Cf8JrD1ixMOFlfCZrd8g4kbPZqtpnE3jo4GJ+jhn0UslgyAjNdIq8XgCj3FD3wN8u9R
         Fmug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sRGlK8jjy1/wDdSe4iD14HDBzDdtA2CSB57wVBddJ3M=;
        b=HOFGx3NSwDZ1dK4QkcLtU4wba9HKVlMlkJrnGIuYWhiyuZAuuEZaRMFO+9lQrPmulm
         9QOVskzkjrRoJvLYJTRROMdFVAhoR8W7cUeOx2285eSGurl/qIcR1E6xxQFmehdl3X2+
         tPHDeBuoA4llareecxmcLfwPvkV4aGPlphGQkC3olBZ9Wo1q9V1IkVrw/kVj/vWJgQlV
         hN5W+7CRpd00EeCsV70cmNK+EFp8nXv4PxrvALs7tUL3M19x9lsdM36Hnya+fL1KPc6H
         zHKQ9Xtbh7AnAXIoJTX+P9gby5zGQ3/ce8LmN9bjmEWOFIkuJMqALL29W0C0MTYCNHhE
         Hxhg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=C77BjO4d;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x541.google.com (mail-pg1-x541.google.com. [2607:f8b0:4864:20::541])
        by gmr-mx.google.com with ESMTPS id o98si781548pjo.1.2020.09.07.08.34.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Sep 2020 08:34:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::541 as permitted sender) client-ip=2607:f8b0:4864:20::541;
Received: by mail-pg1-x541.google.com with SMTP id t14so2737438pgl.10
        for <kasan-dev@googlegroups.com>; Mon, 07 Sep 2020 08:34:20 -0700 (PDT)
X-Received: by 2002:a62:343:: with SMTP id 64mr1933040pfd.136.1599492860070;
 Mon, 07 Sep 2020 08:34:20 -0700 (PDT)
MIME-Version: 1.0
References: <20200907134055.2878499-1-elver@google.com> <20200907134055.2878499-10-elver@google.com>
In-Reply-To: <20200907134055.2878499-10-elver@google.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Sep 2020 17:33:48 +0200
Message-ID: <CAAeHK+zGpJd6szPounYz6wogO9TMT18TmQu_mfXUWQd65QTf0w@mail.gmail.com>
Subject: Re: [PATCH RFC 09/10] kfence, Documentation: add KFENCE documentation
To: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Mark Rutland <mark.rutland@arm.com>, Pekka Enberg <penberg@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, dave.hansen@linux.intel.com, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@redhat.com>, 
	Jann Horn <jannh@google.com>, Jonathan Corbet <corbet@lwn.net>, Kees Cook <keescook@chromium.org>, 
	Peter Zijlstra <peterz@infradead.org>, Qian Cai <cai@lca.pw>, Thomas Gleixner <tglx@linutronix.de>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=C77BjO4d;       spf=pass
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

Does the user need to know that this is object #17? This doesn't seem
like something that can be useful for anything.

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

Same here.

Also, this says object #24, but the stack trace above doesn't mention
which object it is. Is it the same one?

> +     __kfence_alloc+0x277/0x4c0
> +     __kmalloc+0x133/0x200
> +     test_alloc+0xf3/0x25b
> +     test_use_after_free_read+0x76/0x143
> +     kunit_try_run_case+0x51/0x85
> +     kunit_generic_run_threadfn_adapter+0x16/0x30
> +     kthread+0x137/0x160
> +     ret_from_fork+0x22/0x30
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

It's not really clear what is 0xac here. Value of the corrupted byte?
What does '.' stand for?

Also, if this is to be used in production, printing kernel memory
bytes might lead to info-leaks.

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
> +returned to the main allocator (SLAB or SLUB).

Only for freed allocations, right?

> At this point, the timer is
> +reset, and the next allocation is set up after the expiration of the interval.
> +To "gate" a KFENCE allocation through the main allocator's fast-path without
> +overhead, KFENCE relies on static branches via the static keys infrastructure.
> +The static branch is toggled to redirect the allocation to KFENCE.
> +
> +KFENCE objects each reside on a dedicated page, at either the left or right
> +page boundaries selected at random. The pages to the left and right of the
> +object page are "guard pages", whose attributes are changed to a protected
> +state, and cause page faults on any attempted access. Such page faults are then
> +intercepted by KFENCE, which handles the fault gracefully by reporting an
> +out-of-bounds access.

I'd start a new paragraph here:

> The side opposite of an object's guard page is used as a

Not a native speaker, but "The side opposite _to_" sounds better. Or
"The opposite side of".

> +pattern-based redzone, to detect out-of-bounds writes on the unprotected sed of

"sed"?

> +the object on frees (for special alignment and size combinations, both sides of
> +the object are redzoned).
> +
> +KFENCE also uses pattern-based redzones on the other side of an object's guard
> +page, to detect out-of-bounds writes on the unprotected side of the object;
> +these are reported on frees.

Not really clear, what is "other side" and how it's different from the
"opposite side" mentioned above. The figure doesn't really help.

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

Seems really similar to KASAN's quarantine? Is the implementation much
different?

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzGpJd6szPounYz6wogO9TMT18TmQu_mfXUWQd65QTf0w%40mail.gmail.com.
