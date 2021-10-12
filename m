Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK5YSWFQMGQE5KXH5HQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CA9442A172
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 11:58:05 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 124-20020a251182000000b005a027223ed9sf26476229ybr.13
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Oct 2021 02:58:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634032684; cv=pass;
        d=google.com; s=arc-20160816;
        b=jiTc+F6lo+5qlyLr1iVKd2zKxRVMa9rM9rpkha1cemP4iil1eLZgmVONuAfCHqsrbM
         xQHKekSl8ICr2zDuAF30jzNjrZY9YVtLLYvcx6Dh71qIL7ToKVTVDdw3XG0ytZWlagOi
         OYg9TvlDifkLHHZXmTQlbQejqJtKPU7Ap+ccOFdAdCwWpD841cYu3Ln5KLaftXfhG4O1
         eMKf8E66aERg0HO8MIQfGp/svFZYM3HvEzkuCctoR0JWzIJjwqBiYDkjWSzwRuOPtSwj
         zwW/irlSmMUzv+MreE/h9ty/6aj0NVNbYR8h84GinbBIn+YrNLrmZXil4cFYrU2NMV33
         X5Qw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pBSzxNJ4P0a+xii26+Y2HzYhEqm2CfSGGgyXDkupMWY=;
        b=Lgl8TdroJ6f+VxwJgWBRFmX40VqVdmyqE+9NFQBnPnSNoapZDKe8bfMQPB1WpN6DT6
         Ak0/RFTHuQkNXZfs4195W2queEfZ3A7Lr8zz/YzDswjEyzU3cvvYaJF2Hg3+c+wA62dA
         PhLRA1H5sDZnAYCwMoxaGE8wff7KGPD8S84Wb6bRbxCPVLP+FOEoF4O/6OSTB2epyN5E
         8TqXZyrkUEPexTC6pWdP9TJ2KLYh6mdypUhDrJYVLin6jdZ5qBewDXFX7DgdyoItKEjJ
         dkU7+s+sbe92FFtfzt0udgppfsv+lTVuDDqABySKIi6ZJgrrjvfz2OvJ4qjX5i93WScL
         b9Pw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W3fE3wAs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pBSzxNJ4P0a+xii26+Y2HzYhEqm2CfSGGgyXDkupMWY=;
        b=imM3TH5r6Q5qcViTWvU0wRGzijSqscg6wQdkZZw0KBSRHWcw12ysP8lG5OazMarxCl
         NDt2q101cHuqFnJAG87mExFREB7H/K6DNWJQE6IGbXDLp+AZOHogn/83EHNGRG+qQiVa
         smbdj+d9qgAwfq+hkwGDSiZmcUxQdaJOaeUIQ4aSvLsDAkexFwH3SEzigRdIZQ9Bbw/q
         57pffGMDlEL+n8HffF9REjCDm+P91EgRkAIgQhZmnExpm+Brys2D7az2BqW9pxPuQ2XY
         UVwojv6zShl1DwAa92QiEk2b3f1CKO/dMZYlS2RFXeCY5l7HWHOntrd+MvCh1VhxdY9k
         nbTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pBSzxNJ4P0a+xii26+Y2HzYhEqm2CfSGGgyXDkupMWY=;
        b=UoEaJoRZlyN9B/xM+eRY39jhJ6epiOGU1/L0qyO/qNEU9oquiKtFjz/C2Q6sCvlXnu
         bh8mWvYYQok9+wyRHA8UMtwpHz67OQZKL4IIyS/0JwY7IVsZU+TzWdp3NibRtv+RDbjt
         7JuR7d8zmIVobN0jxAVBBU1u2/pHfTvbjxYhQRGP2Ex4E+jydahjmBvPijTrzkTLJ0ez
         /loqjbKiLvjdtk1sW47F+Xfh8r62fFhOIZ8onDrSZmvjmhS61UkU59zhLjOxpfKp6WzC
         WOegjoAi/QXMyu5b3FIqBMJuSMZSmS3uvKhNiZwbXVzZdVx9uRbqQHnS818VlUAo9vtw
         s75A==
X-Gm-Message-State: AOAM533JnbraHWPdrP1DcWSrKODEZx1o/c+fvLjBVelnoJ9f0w39Uubi
	nU40WQpQCXU5A2xh/G4y1Xg=
X-Google-Smtp-Source: ABdhPJza7TTTJULNdPgW2HR7CwdOjfZuI4X8QWgOieLcGmDXT8TfkwJNGHAMXg1YgA1cqA+B5PGsBg==
X-Received: by 2002:a25:47c6:: with SMTP id u189mr30241071yba.232.1634032683830;
        Tue, 12 Oct 2021 02:58:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:4e57:: with SMTP id c84ls3072344ybb.10.gmail; Tue, 12
 Oct 2021 02:58:03 -0700 (PDT)
X-Received: by 2002:a25:54c5:: with SMTP id i188mr26761303ybb.304.1634032683138;
        Tue, 12 Oct 2021 02:58:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634032683; cv=none;
        d=google.com; s=arc-20160816;
        b=WS7fqBCV6cX6gzoLPYLk7fRZgUMwqX3OV69cezNftXFNLTi36aK9OUKIu+mJvqNyIx
         eY/sb4aKB+1gyjSxkgCuJO41dJPT+J734WbrbcEUp4YoEFu+zs02F5aqPmtxpOqswps2
         N4sPnbKTi60l2WBEfZc0RQeWC5MDt3S0lIUzt7xpkrBaf+OlndUromdE0Yv5opPgnl4c
         jytC73NXXdC3qGosNCZ7ACD6M2t71DbfA23E0eSJiHf4T5rQW1lj7Nd17EhyjjRWBvOb
         QDEoBx0op/TxnY7pIKZknGrKqENA2Vnmtw2tqBYHhimw8ggwCEZWoIfFsgohXuKjlGZT
         Am4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=exw8d3KuGhElvzTHGBSpGdBnH3FvQOLQqakhYUKFBwo=;
        b=M1xcsORy7mLLw4cY69D+in+y8Numg8SWllg4eTkpZpJDfnobzWUAEIpTzIxVVjwGQq
         w/RsO90E+jkt0RU769oUd8dZJpfIK3n1fkb8+eO2P6BN8VtkmC+SUkkftSXN0iN89TPf
         CYxGiSF2AAexjcEkiBjINzJ3XwHIz5eHokksDoJSFdfJmhP6b1uEcWLcpJqb5jHNkOOm
         swxKjGuqATj3M1OmeI+uYzpP/8dcUC90q1HhjLHYCKKMe1jtn4d13tTyrZg/vPcDSZY7
         mIc2KE3eK29n9iIYESP0OA1F/0T4NOZmdtBcumlGGPd89dfEK/ME5rWgt2AciPCTUcLk
         oo1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=W3fE3wAs;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x332.google.com (mail-ot1-x332.google.com. [2607:f8b0:4864:20::332])
        by gmr-mx.google.com with ESMTPS id v16si718548ybq.5.2021.10.12.02.58.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Oct 2021 02:58:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as permitted sender) client-ip=2607:f8b0:4864:20::332;
Received: by mail-ot1-x332.google.com with SMTP id g62-20020a9d2dc4000000b0054752cfbc59so25302409otb.1
        for <kasan-dev@googlegroups.com>; Tue, 12 Oct 2021 02:58:03 -0700 (PDT)
X-Received: by 2002:a05:6830:24a7:: with SMTP id v7mr1618845ots.329.1634032682395;
 Tue, 12 Oct 2021 02:58:02 -0700 (PDT)
MIME-Version: 1.0
References: <20211012090621.1357-1-vbabka@suse.cz>
In-Reply-To: <20211012090621.1357-1-vbabka@suse.cz>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Oct 2021 11:57:50 +0200
Message-ID: <CANpmjNOLEvY9zuBRMe-P_8jUzK6=rS06bQC4r0+=_6YP-UfeSA@mail.gmail.com>
Subject: Re: [PATCH v2] lib/stackdepot: allow optional init and stack_table
 allocation by kvmalloc()
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, dri-devel@lists.freedesktop.org, 
	intel-gfx@lists.freedesktop.org, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Vijayanand Jitta <vjitta@codeaurora.org>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Maxime Ripard <mripard@kernel.org>, 
	Thomas Zimmermann <tzimmermann@suse.de>, David Airlie <airlied@linux.ie>, Daniel Vetter <daniel@ffwll.ch>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Geert Uytterhoeven <geert@linux-m68k.org>, 
	Oliver Glitta <glittao@gmail.com>, Imran Khan <imran.f.khan@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=W3fE3wAs;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::332 as
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

On Tue, 12 Oct 2021 at 11:06, Vlastimil Babka <vbabka@suse.cz> wrote:
> Currently, enabling CONFIG_STACKDEPOT means its stack_table will be allocated
> from memblock, even if stack depot ends up not actually used. The default size
> of stack_table is 4MB on 32-bit, 8MB on 64-bit.
>
> This is fine for use-cases such as KASAN which is also a config option and
> has overhead on its own. But it's an issue for functionality that has to be
> actually enabled on boot (page_owner) or depends on hardware (GPU drivers)
> and thus the memory might be wasted. This was raised as an issue [1] when
> attempting to add stackdepot support for SLUB's debug object tracking
> functionality. It's common to build kernels with CONFIG_SLUB_DEBUG and enable
> slub_debug on boot only when needed, or create only specific kmem caches with
> debugging for testing purposes.
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
> Acked-by: Dmitry Vyukov <dvyukov@google.com>
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

Reviewed-by: Marco Elver <elver@google.com> # stackdepot

Thanks!

> ---
> Changes in v2:
> - Rebase to v5.15-rc5.
> - Stylistic changes suggested by Marco Elver.
>  drivers/gpu/drm/drm_dp_mst_topology.c   |  1 +
>  drivers/gpu/drm/drm_mm.c                |  4 ++++
>  drivers/gpu/drm/i915/intel_runtime_pm.c |  3 +++
>  include/linux/stackdepot.h              | 25 ++++++++++++-------
>  init/main.c                             |  2 +-
>  lib/Kconfig                             |  4 ++++
>  lib/Kconfig.kasan                       |  2 +-
>  lib/stackdepot.c                        | 32 +++++++++++++++++++++----
>  mm/page_owner.c                         |  2 ++
>  9 files changed, 59 insertions(+), 16 deletions(-)
>
> diff --git a/drivers/gpu/drm/drm_dp_mst_topology.c b/drivers/gpu/drm/drm_dp_mst_topology.c
> index 86d13d6bc463..b0ebdc843a00 100644
> --- a/drivers/gpu/drm/drm_dp_mst_topology.c
> +++ b/drivers/gpu/drm/drm_dp_mst_topology.c
> @@ -5493,6 +5493,7 @@ int drm_dp_mst_topology_mgr_init(struct drm_dp_mst_topology_mgr *mgr,
>         mutex_init(&mgr->probe_lock);
>  #if IS_ENABLED(CONFIG_DRM_DEBUG_DP_MST_TOPOLOGY_REFS)
>         mutex_init(&mgr->topology_ref_history_lock);
> +       stack_depot_init();
>  #endif
>         INIT_LIST_HEAD(&mgr->tx_msg_downq);
>         INIT_LIST_HEAD(&mgr->destroy_port_list);
> diff --git a/drivers/gpu/drm/drm_mm.c b/drivers/gpu/drm/drm_mm.c
> index 93d48a6f04ab..5916228ea0c9 100644
> --- a/drivers/gpu/drm/drm_mm.c
> +++ b/drivers/gpu/drm/drm_mm.c
> @@ -983,6 +983,10 @@ void drm_mm_init(struct drm_mm *mm, u64 start, u64 size)
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
> index eaf7688f517d..d083506986e1 100644
> --- a/drivers/gpu/drm/i915/intel_runtime_pm.c
> +++ b/drivers/gpu/drm/i915/intel_runtime_pm.c
> @@ -78,6 +78,9 @@ static void __print_depot_stack(depot_stack_handle_t stack,
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
> index 6bb4bc1a5f54..40fc5e92194f 100644
> --- a/include/linux/stackdepot.h
> +++ b/include/linux/stackdepot.h
> @@ -13,6 +13,22 @@
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
> +#ifdef CONFIG_STACKDEPOT_ALWAYS_INIT
> +static inline int stack_depot_early_init(void) { return stack_depot_init(); }
> +#else
> +static inline int stack_depot_early_init(void) { return 0; }
> +#endif
> +
>  depot_stack_handle_t stack_depot_save(unsigned long *entries,
>                                       unsigned int nr_entries, gfp_t gfp_flags);
>
> @@ -21,13 +37,4 @@ unsigned int stack_depot_fetch(depot_stack_handle_t handle,
>
>  unsigned int filter_irq_stacks(unsigned long *entries, unsigned int nr_entries);
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
> index 81a79a77db46..ca2765c8e45c 100644
> --- a/init/main.c
> +++ b/init/main.c
> @@ -842,7 +842,7 @@ static void __init mm_init(void)
>         init_mem_debugging_and_hardening();
>         kfence_alloc_pool();
>         report_meminit();
> -       stack_depot_init();
> +       stack_depot_early_init();
>         mem_init();
>         mem_init_print_info();
>         /* page_owner must be initialized after buddy is ready */
> diff --git a/lib/Kconfig b/lib/Kconfig
> index 5e7165e6a346..9d0569084152 100644
> --- a/lib/Kconfig
> +++ b/lib/Kconfig
> @@ -671,6 +671,10 @@ config STACKDEPOT
>         bool
>         select STACKTRACE
>
> +config STACKDEPOT_ALWAYS_INIT
> +       bool
> +       select STACKDEPOT
> +
>  config STACK_HASH_ORDER
>         int "stack depot hash size (12 => 4KB, 20 => 1024KB)"
>         range 12 20
> diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
> index cdc842d090db..879757b6dd14 100644
> --- a/lib/Kconfig.kasan
> +++ b/lib/Kconfig.kasan
> @@ -38,7 +38,7 @@ menuconfig KASAN
>                     CC_HAS_WORKING_NOSANITIZE_ADDRESS) || \
>                    HAVE_ARCH_KASAN_HW_TAGS
>         depends on (SLUB && SYSFS) || (SLAB && !DEBUG_SLAB)
> -       select STACKDEPOT
> +       select STACKDEPOT_ALWAYS_INIT
>         help
>           Enables KASAN (KernelAddressSANitizer) - runtime memory debugger,
>           designed to find out-of-bounds accesses and use-after-free bugs.
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 0a2e417f83cb..9bb5333bf02f 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -24,6 +24,7 @@
>  #include <linux/jhash.h>
>  #include <linux/kernel.h>
>  #include <linux/mm.h>
> +#include <linux/mutex.h>
>  #include <linux/percpu.h>
>  #include <linux/printk.h>
>  #include <linux/slab.h>
> @@ -146,6 +147,7 @@ static struct stack_record *depot_alloc_stack(unsigned long *entries, int size,
>  #define STACK_HASH_MASK (STACK_HASH_SIZE - 1)
>  #define STACK_HASH_SEED 0x9747b28c
>
> +DEFINE_MUTEX(stack_depot_init_mutex);
>  static bool stack_depot_disable;
>  static struct stack_record **stack_table;
>
> @@ -162,18 +164,38 @@ static int __init is_stack_depot_disabled(char *str)
>  }
>  early_param("stack_depot_disable", is_stack_depot_disabled);
>
> -int __init stack_depot_init(void)
> +/*
> + * __ref because of memblock_alloc(), which will not be actually called after
> + * the __init code is gone, because at that point slab_is_available() is true
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
> index 62402d22539b..16a0ef903384 100644
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
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211012090621.1357-1-vbabka%40suse.cz.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOLEvY9zuBRMe-P_8jUzK6%3DrS06bQC4r0%2B%3D_6YP-UfeSA%40mail.gmail.com.
