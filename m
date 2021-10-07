Return-Path: <kasan-dev+bncBCMIZB7QWENRBJVH7OFAMGQEQC2VVSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 7829D42519F
	for <lists+kasan-dev@lfdr.de>; Thu,  7 Oct 2021 13:02:01 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id o4-20020ab05944000000b002c9c4d839d1sf2836587uad.13
        for <lists+kasan-dev@lfdr.de>; Thu, 07 Oct 2021 04:02:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633604520; cv=pass;
        d=google.com; s=arc-20160816;
        b=BUekQu8iY5Bk17nrVgIUBFoMjJ+4c25S5KwvyqRN8x9DsnCdLMkTj0q/xYSmBcnH+J
         wes6CR4Kxu5hmggiePOoH60+vcl7NULr0cNw85iq+mQa0HaXMXMeBSOABNn89YlOMJfX
         cJ8yCDQfC8OjOoEzhMw7q0yjZ7F7OPLcBgPOQcrg9DcOJIPuVt16AoEubEn9RQEamDMd
         vaC5Nbm4cy/RKwojB3ujBaYysi2YadJ2ybya5izPbgI9GfoWZQCOdTp+uFdqMK4G5qwP
         9Sn7LUPIPVo1fGhRUebzFy5b5IHUDcscia1FFuRmu2nJUr1SRRCe0LnBojDSzTGgvHKQ
         vBjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TntmgT+12YmP+PPJsAHeIjIKdgQ0D8dJneDSdWZ9t68=;
        b=CAie9x/acsWmD4QgOBRVATTQPmdGFYRXvVlk0VMX6sfpHlQunW19gascvY2VGUd1ny
         hACbFfioJTX4DYkgfSOFi+aGvBIQMq7Vfr22i7ZHfXEtmA110FT0nYBODafj4MBAz2Eq
         yVY46uw5Eft81z4FczpmCRnVrbtnxzzayLXpHPQvcRrdTJP7yLo3C/B4Du4uc4gJYVeS
         BR6gLwjvJd+AydsBR8+Cg84UeqQLTpQEyKgLH7yQGeIl44o2YK2J1td9hWD9+x3RMEHU
         ylq5aB10C6Gutld/b0MrSOxXjvb2r5td4EVS1H8NRb+xkQojHIeJprFmAt1g0w73Ig7O
         Ds2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CWIileFS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TntmgT+12YmP+PPJsAHeIjIKdgQ0D8dJneDSdWZ9t68=;
        b=Irpc1rMnPmXenVhrvRm76ssyuI5ViReh5BiwTFXhpuREgMrlkBHHzU4GuSCIdVhLu2
         p3B7+gYzPAMW3I6y4ufiVG8ZaSm488XGaOKOkWkWw+Z9CxFtP9+Vvh93QYtpkNoV214H
         goC6wYxnrdnM+41wMnOUGYneVK+qvx5A01ts8ukSWUSsYFlPyQu5Il/YDAb7PFzlqSo2
         P1OtE4A0SMXQhoW425aZ0ccvWF9f4is85rFhX08NiQ1ILMPIqKAidaVKZL1DSXDrVEhk
         Yg4uuQknBJXwVcqoETqxAYNj8gkyZlriWQNOvZkyWGcfwqzIMlBkDW1ogL4HLbZuHQTK
         qp9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TntmgT+12YmP+PPJsAHeIjIKdgQ0D8dJneDSdWZ9t68=;
        b=7+3OIyYJA7HhBIJtLhrVPM9BLKrOCFamRZR0mYomsiztzjXA16GzyBxviLcnAxPBFC
         vp4pLNIk9MFh21tYwyswidWWm2+/psGytR8LMZwrgrnWfBDnLMXHwzsrQURafsAv+o4F
         WVAWpT1Lt5q6RPAE83uvRaUZ/0TG2FQvyR95U0tD7IF/5509ybHhClCvDDpCe2iR8RsR
         NdiWpR08+0Z/c7/nOVKQxvNu8OorxKIn27WUvowD+vRSHIYMRHzIA+g7K/4qx5rFLyt3
         QmN67U0m0BSnf82SToD6gG/O34JuUPef6R4+Z75BDewpwXMkQ91nTkMiIf+8Dslbx44w
         fBOw==
X-Gm-Message-State: AOAM532ggapm79Q84VZEbqz+E5Fra5DaTd/FHPgZklPAp2qEHilnUT3Q
	U7hk+o5pThsHmpnLE+Er6Ic=
X-Google-Smtp-Source: ABdhPJxoSvIl8WGIjN7xF/BkD60nIAcoghCViQG+elxUu3F0H5fokNM+LTudFyjpQpzAdz05p0yXtQ==
X-Received: by 2002:ab0:3b59:: with SMTP id o25mr3408877uaw.100.1633604518990;
        Thu, 07 Oct 2021 04:01:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:edd7:: with SMTP id e23ls785078vsp.5.gmail; Thu, 07 Oct
 2021 04:01:58 -0700 (PDT)
X-Received: by 2002:a67:2285:: with SMTP id i127mr2948810vsi.57.1633604518068;
        Thu, 07 Oct 2021 04:01:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633604518; cv=none;
        d=google.com; s=arc-20160816;
        b=iLdRJG2XU+vUl4Yo1rZ9c7JLJETKdKFjc0jUTrJLoYxIgGXUlsXiYex4YyhC6NU+uE
         WhmRRtZ0pMoCxmb9vUg2p+b535hTAA8L8JFNoa5r4YTGl/csXF+vugMawwzt5VBRP0CA
         mXHg2cYB2p+MPa2dOpaTZiRuzVoM7r2rIGP4pKbBPNpBXkXCsy8HUPXcHWjdIdwdWbMy
         5VvqRhLswKmVyoUE9c22ZLJ0+FKFN+hDeLAL2N7Y3Tr32Af601uVIq64k/BLdwBZwDun
         8slpQqSWOzZuMWNRokDk/9K7HnLkNvYk34dzbCZqoO6CSqgRZY0pBC4bewqxxqhNPGtK
         GyZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MFLTJIiHDCdoWGozrgcXT8vP3XOP5pGhvQd0Nr+SVb4=;
        b=fGeGfW07rmaedwoj1MtVGt/P0Xrq+YcbnJFx2udG7eVbLndOI+3BPLGyhvMcbAuuT6
         mz82+KZjPXWtBhLfSURm9OreWAQ++RSsNkDO+Hc31L18xWT/ZfnDQdHE4SAfW2Nxv0uL
         CokCOrQO+Ju4RdDp4W3L/f2Bv2pQB//0OmV4MBks0KEGrJnr4HByQP8ZxWZHCsmDi8DF
         FiG3wNoTDUIFAQ0fCxiuzP4CcpX6q++WRGLHO9rfBqJJsjKeIpu5Ub0CEntQqJLu8yHP
         P5qoLpOcAym/O1YwhztoqK2JeABiUY2HBmXpqtKZtnP8WhuadgmwSy4oG907GVHC4/D2
         2rvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=CWIileFS;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x236.google.com (mail-oi1-x236.google.com. [2607:f8b0:4864:20::236])
        by gmr-mx.google.com with ESMTPS id x75si1766873vsx.1.2021.10.07.04.01.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 07 Oct 2021 04:01:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236 as permitted sender) client-ip=2607:f8b0:4864:20::236;
Received: by mail-oi1-x236.google.com with SMTP id y201so8503576oie.3
        for <kasan-dev@googlegroups.com>; Thu, 07 Oct 2021 04:01:58 -0700 (PDT)
X-Received: by 2002:a05:6808:1991:: with SMTP id bj17mr11056054oib.160.1633604517467;
 Thu, 07 Oct 2021 04:01:57 -0700 (PDT)
MIME-Version: 1.0
References: <20211007095815.3563-1-vbabka@suse.cz>
In-Reply-To: <20211007095815.3563-1-vbabka@suse.cz>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 7 Oct 2021 13:01:45 +0200
Message-ID: <CACT4Y+bigoRHKxPG6G-E1OwfCBE+JFCq_Y1FbL78t368-sX+hg@mail.gmail.com>
Subject: Re: [PATCH] lib/stackdepot: allow optional init and stack_table
 allocation by kvmalloc()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, dri-devel@lists.freedesktop.org, 
	intel-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com, 
	Marco Elver <elver@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Maxime Ripard <mripard@kernel.org>, 
	Thomas Zimmermann <tzimmermann@suse.de>, David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Oliver Glitta <glittao@gmail.com>, Imran Khan <imran.f.khan@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=CWIileFS;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::236
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

On Thu, 7 Oct 2021 at 11:58, Vlastimil Babka <vbabka@suse.cz> wrote:
>
> Currently, enabling CONFIG_STACKDEPOT means its stack_table will be allocated
> from memblock, even if stack depot ends up not actually used. The default size
> of stack_table is 4MB on 32-bit, 8MB on 64-bit.
>
> This is fine for use-cases such as KASAN which is also a config option and
> has overhead on its own. But it's an issue for functionality that has to be
> actually enabled on boot (page_owner) or depends on hardware (GPU drivers)
> and thus the memory might be wasted. This was raised as an issue when trying
> to add stackdepot support for SLUB's debug object tracking functionality. It's
> common to build kernels with CONFIG_SLUB_DEBUG and enable slub_debug on boot
> only when needed, or create specific kmem caches with debugging for testing
> purposes.
>
> It would thus be more efficient if stackdepot's table was allocated only when
> actually going to be used. This patch thus makes the allocation (and whole
> stack_depot_init() call) optional:
>
> - Add a CONFIG_STACKDEPOT_ALWAYS_INIT flag to keep using the current
>   well-defined point of allocation as part of mem_init(). Make CONFIG_KASAN
>   select this flag.
> - Other users have to call stack_depot_init() as part of their own init when
>   it's determined that stack depot will actually be used. This may depend on
>   both config and runtime conditions. Convert current users which are
>   page_owner and several in the DRM subsystem. Same will be done for SLUB
>   later.
> - Because the init might now be called after the boot-time memblock allocation
>   has given all memory to the buddy allocator, change stack_depot_init() to
>   allocate stack_table with kvmalloc() when memblock is no longer available.
>   Also handle allocation failure by disabling stackdepot (could have
>   theoretically happened even with memblock allocation previously), and don't
>   unnecessarily align the memblock allocation to its own size anymore.
>
> [1] https://lore.kernel.org/all/CAMuHMdW=eoVzM1Re5FVoEN87nKfiLmM2+Ah7eNu2KXEhCvbZyA@mail.gmail.com/
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> Cc: Marco Elver <elver@google.com>
> Cc: Vijayanand Jitta <vjitta@codeaurora.org>
> Cc: Maarten Lankhorst <maarten.lankhorst@linux.intel.com>
> Cc: Maxime Ripard <mripard@kernel.org>
> Cc: Thomas Zimmermann <tzimmermann@suse.de>
> Cc: David Airlie <airlied@linux.ie>
> Cc: Daniel Vetter <daniel@ffwll.ch>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Geert Uytterhoeven <geert@linux-m68k.org>
> Cc: Oliver Glitta <glittao@gmail.com>
> Cc: Imran Khan <imran.f.khan@oracle.com>

Acked-by: Dmitry Vyukov <dvyukov@google.com>

> ---
> Hi, I'd appreciate review of the DRM parts - namely that I've got correctly
> that stack_depot_init() is called from the proper init functions and iff
> stack_depot_save() is going to be used later. Thanks!
>
>  drivers/gpu/drm/drm_dp_mst_topology.c   |  1 +
>  drivers/gpu/drm/drm_mm.c                |  4 ++++
>  drivers/gpu/drm/i915/intel_runtime_pm.c |  3 +++
>  include/linux/stackdepot.h              | 19 ++++++++-------
>  init/main.c                             |  3 ++-
>  lib/Kconfig                             |  3 +++
>  lib/Kconfig.kasan                       |  1 +
>  lib/stackdepot.c                        | 32 +++++++++++++++++++++----
>  mm/page_owner.c                         |  2 ++
>  9 files changed, 53 insertions(+), 15 deletions(-)
>
> diff --git a/drivers/gpu/drm/drm_dp_mst_topology.c b/drivers/gpu/drm/drm_dp_mst_topology.c
> index 2d1adab9e360..bbe972d59dae 100644
> --- a/drivers/gpu/drm/drm_dp_mst_topology.c
> +++ b/drivers/gpu/drm/drm_dp_mst_topology.c
> @@ -5490,6 +5490,7 @@ int drm_dp_mst_topology_mgr_init(struct drm_dp_mst_topology_mgr *mgr,
>         mutex_init(&mgr->probe_lock);
>  #if IS_ENABLED(CONFIG_DRM_DEBUG_DP_MST_TOPOLOGY_REFS)
>         mutex_init(&mgr->topology_ref_history_lock);
> +       stack_depot_init();
>  #endif
>         INIT_LIST_HEAD(&mgr->tx_msg_downq);
>         INIT_LIST_HEAD(&mgr->destroy_port_list);
> diff --git a/drivers/gpu/drm/drm_mm.c b/drivers/gpu/drm/drm_mm.c
> index 7d1c578388d3..8257f9d4f619 100644
> --- a/drivers/gpu/drm/drm_mm.c
> +++ b/drivers/gpu/drm/drm_mm.c
> @@ -980,6 +980,10 @@ void drm_mm_init(struct drm_mm *mm, u64 start, u64 size)
>         add_hole(&mm->head_node);
>
>         mm->scan_active = 0;
> +
> +#ifdef CONFIG_DRM_DEBUG_MM
> +       stack_depot_init();
> +#endif
>  }
>  EXPORT_SYMBOL(drm_mm_init);
>
> diff --git a/drivers/gpu/drm/i915/intel_runtime_pm.c b/drivers/gpu/drm/i915/intel_runtime_pm.c
> index 0d85f3c5c526..806c32ab410b 100644
> --- a/drivers/gpu/drm/i915/intel_runtime_pm.c
> +++ b/drivers/gpu/drm/i915/intel_runtime_pm.c
> @@ -68,6 +68,9 @@ static noinline depot_stack_handle_t __save_depot_stack(void)
>  static void init_intel_runtime_pm_wakeref(struct intel_runtime_pm *rpm)
>  {
>         spin_lock_init(&rpm->debug.lock);
> +
> +       if (rpm->available)
> +               stack_depot_init();
>  }
>
>  static noinline depot_stack_handle_t
> diff --git a/include/linux/stackdepot.h b/include/linux/stackdepot.h
> index c34b55a6e554..60ba99a43745 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -15,6 +15,16 @@
>
>  typedef u32 depot_stack_handle_t;
>
> +/*
> + * Every user of stack depot has to call this during its own init when it's
> + * decided that it will be calling stack_depot_save() later.
> + *
> + * The alternative is to select STACKDEPOT_ALWAYS_INIT to have stack depot
> + * enabled as part of mm_init(), for subsystems where it's known at compile time
> + * that stack depot will be used.
> + */
> +int stack_depot_init(void);
> +
>  depot_stack_handle_t __stack_depot_save(unsigned long *entries,
>                                         unsigned int nr_entries,
>                                         gfp_t gfp_flags, bool can_alloc);
> @@ -30,13 +40,4 @@ int stack_depot_snprint(depot_stack_handle_t handle, char *buf, size_t size,
>
>  void stack_depot_print(depot_stack_handle_t stack);
>
> -#ifdef CONFIG_STACKDEPOT
> -int stack_depot_init(void);
> -#else
> -static inline int stack_depot_init(void)
> -{
> -       return 0;
> -}
> -#endif /* CONFIG_STACKDEPOT */
> -
>  #endif
> diff --git a/init/main.c b/init/main.c
> index ee4d3e1b3eb9..b6a5833d98f5 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -844,7 +844,8 @@ static void __init mm_init(void)
>         init_mem_debugging_and_hardening();
>         kfence_alloc_pool();
>         report_meminit();
> -       stack_depot_init();
> +       if (IS_ENABLED(CONFIG_STACKDEPOT_ALWAYS_INIT))
> +               stack_depot_init();
>         mem_init();
>         mem_init_print_info();
>         /* page_owner must be initialized after buddy is ready */
> diff --git a/lib/Kconfig b/lib/Kconfig
> index 5e7165e6a346..df6bcf0a4cc3 100644
> --- a/lib/Kconfig
> +++ b/lib/Kconfig
> @@ -671,6 +671,9 @@ config STACKDEPOT
>         bool
>         select STACKTRACE
>
> +config STACKDEPOT_ALWAYS_INIT
> +       bool
> +
>  config STACK_HASH_ORDER
>         int "stack depot hash size (12 => 4KB, 20 => 1024KB)"
>         range 12 20
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cdc842d090db..695deb603c66 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -39,6 +39,7 @@ menuconfig KASAN
>                    HAVE_ARCH_KASAN_HW_TAGS
>         depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
>         select STACKDEPOT
> +       select STACKDEPOT_ALWAYS_INIT
>         help
>           Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
>           designed to find out-of-bounds accesses and use-after-free bugs.
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index b437ae79aca1..a4f449ccd0dc 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -23,6 +23,7 @@
>  #include <linux/jhash.h>
>  #include <linux/kernel.h>
>  #include <linux/mm.h>
> +#include <linux/mutex.h>
>  #include <linux/percpu.h>
>  #include <linux/printk.h>
>  #include <linux/slab.h>
> @@ -145,6 +146,7 @@ depot_alloc_stack(unsigned long *entries, int size, u32 hash, void **prealloc)
>  #define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
>  #define STACK_HASH_SEED 0x9747b28c
>
> +DEFINE_MUTEX(stack_depot_init_mutex);
>  static bool stack_depot_disable;
>  static struct stack_record **stack_table;
>
> @@ -161,18 +163,38 @@ static int __init is_stack_depot_disabled(char *str)
>  }
>  early_param("stack_depot_disable", is_stack_depot_disabled);
>
> -int __init stack_depot_init(void)
> +/*
> + * __ref because of memblock_alloc(), which will not be actually called after
> + * the __init code is gone
> + */
> +__ref int stack_depot_init(void)
>  {
> -       if (!stack_depot_disable) {
> +       mutex_lock(&stack_depot_init_mutex);
> +       if (!stack_depot_disable && stack_table == NULL) {
>                 size_t size = (STACK_HASH_SIZE * sizeof(struct stack_record *));
>                 int i;
>
> -               stack_table = memblock_alloc(size, size);
> -               for (i = 0; i < STACK_HASH_SIZE;  i++)
> -                       stack_table[i] = NULL;
> +               if (slab_is_available()) {
> +                       pr_info("Stack Depot allocating hash table with kvmalloc\n");
> +                       stack_table = kvmalloc(size, GFP_KERNEL);
> +               } else {
> +                       pr_info("Stack Depot allocating hash table with memblock_alloc\n");
> +                       stack_table = memblock_alloc(size, SMP_CACHE_BYTES);
> +               }
> +               if (stack_table) {
> +                       for (i = 0; i < STACK_HASH_SIZE;  i++)
> +                               stack_table[i] = NULL;
> +               } else {
> +                       pr_err("Stack Depot failed hash table allocationg, disabling\n");
> +                       stack_depot_disable = true;
> +                       mutex_unlock(&stack_depot_init_mutex);
> +                       return -ENOMEM;
> +               }
>         }
> +       mutex_unlock(&stack_depot_init_mutex);
>         return 0;
>  }
> +EXPORT_SYMBOL_GPL(stack_depot_init);
>
>  /* Calculate hash for a stack */
>  static inline u32 hash_stack(unsigned long *entries, unsigned int size)
> diff --git a/mm/page_owner.c b/mm/page_owner.c
> index a83f546c06b5..a48607b51a97 100644
> --- a/mm/page_owner.c
> +++ b/mm/page_owner.c
> @@ -80,6 +80,8 @@ static void init_page_owner(void)
>         if (!page_owner_enabled)
>                 return;
>
> +       stack_depot_init();
> +
>         register_dummy_stack();
>         register_failure_stack();
>         register_early_stack();
> --
> 2.33.0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211007095815.3563-1-vbabka%40suse.cz.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbigoRHKxPG6G-E1OwfCBE%2BJFCq_Y1FbL78t368-sX%2Bhg%40mail.gmail.com.
