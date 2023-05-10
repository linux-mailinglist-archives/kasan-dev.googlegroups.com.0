Return-Path: <kasan-dev+bncBCKJJ7XLVUBBB6WL56RAMGQEMZU7VVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 016136FE426
	for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 20:44:12 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-19297b852cfsf50684265fac.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 May 2023 11:44:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683744250; cv=pass;
        d=google.com; s=arc-20160816;
        b=B1sCRt1F9BQWIQR23aa1Xn5guDpDoP1eWUmlk59yDYcseH7yju2lvxEzE+gowO4i7t
         tB1+fX1b+fj0Q6raXYBooZVVw413uEXaxntiksdmERrNBIf1RmUOYbdfZAfqM+S5Ky8z
         qUsuopeGDZAMgUtARBCI/WulU0FClqp63VsKpiC37AgT+Zf6BSLlUDql5O0JCW+dmggM
         oKHE1N0ZO5mJ1q98r3TG5zBcwOEkxwVBIm/2mVgYs1CC4L8JjixHCmOloqo89bOF9gaT
         Ipshcch0NrWqfc6WDQENLyk4H6Bjwg2tuzlpkjRBYPJCEmrSnTqruFOsGK7g4mvFyYBh
         PckA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8zEXx7UKB01MlTAgGhq0ZK6FCufddZ+G8cDqoUx2NFg=;
        b=q7GVWQKRa61mxCHsQCBzbvm32aT6pevEoUEaDS1mmERrZzEqCkQT+n9Nh/f3N3LjjK
         Uf+awO6GMppYughr/xU294I9AXuJ+dyW9Qgg8qD7AVmUW3+KrEyAd/I27aWEIlRCggBT
         eI7JOLEHdUa16z/dqSJlD5Bt0YVw5myQWevQlCfz8/U+JUQav1VFrYpAtr4cmdvf2jeC
         7+p/++DWH7oRBU0GJSd/UE+MnbaU+P2i0KBfb0vBdT9clYJdC4BbPYMCnT4t0RB1Yu5m
         w8wcXwGOhoBZ+50ZxGfSUzR8gRKQ75nCkjOfthptLgEv6ujYKgeand/yZezRr4AKjg0A
         mq3w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=HkyxGzdl;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683744250; x=1686336250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8zEXx7UKB01MlTAgGhq0ZK6FCufddZ+G8cDqoUx2NFg=;
        b=m2waCoz0bjsbOlOasBJd7W7OoM0+KE0Ph0IOmtGe9d9uKaUc/6izMg2A9ZMqnon94n
         SXvmkwNFWB8xgzzeQlPGC6YNzNhPfT9ipaYvJFpHc5vRsBrcqQcgoG2Tz8oLBrpqtrv3
         2kd5WfzV1J/ohLjfaVPG5HM5jXKkZ0rRwD7iwX8+hX58j5KsT/HTeznQskTEtJ1Gk3lO
         Ku+lQKkHxdmLIozmBCRM+ELYbHR6b9EVpz1PPKm4SVW93nEh06T6dXvG4f60hLfx63uO
         lYWyOmu8tdw9kIc/VOJl3S0SwvqwztkWuBB9sPtKC0ZlSzZ/AVpegQo2tDhzjuzUX7Ro
         E+IQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1683744250; x=1686336250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8zEXx7UKB01MlTAgGhq0ZK6FCufddZ+G8cDqoUx2NFg=;
        b=lbSBUa0LETIQ654F8KqB9I94f3JvPgJ5YFXz9PpDWqsXUgsBnvV7lMemP2C0YNuHDZ
         0korSGWOQfGkKa67hoSX6aVU9Rx2bLDNrg6X3kVYwzwlCXSONoOOGx2342BunWdoK086
         kgXG4ZXSVhdb0XRBs8Rw/LgmHOFNze3ce9FDGywv5lQSv/Nc0ookMp17vUUpvXD/4+Sw
         VpgTXQJpNjFJRTk/buxG/K0jCFKcrDTGcFktqfEQEdKkglQ59xso4ygaNKzG8MnGYVSt
         90eoksXd9uw44lQJXqdHgGcJAo2hsRta4e68FRPLQAJ6SokUWBFXvbbLtswJUWr4A5zK
         Zb9A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683744250; x=1686336250;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8zEXx7UKB01MlTAgGhq0ZK6FCufddZ+G8cDqoUx2NFg=;
        b=OOk9Iyjud7CH5/vGxrhByDpaPZ6U+TXZMGlMm0Xc9t6V12XrAHgK2gUBZs2aRMNaZu
         p9ArZiNmaxO8zb6ne7FHRz+gMqVCin9E80K+PAN9lgBUti2UzHuGpzFcB4QCH86Di64P
         /5DvoMd/VwyreiK3iu0JtVpF0llezhI+TLqC1BxTnw19a187iGQxJXRPILlDiSrqRzO3
         eKLSaFCLziFS7vjULEwmA1ZLVRQizSh7CnS8Ttjg3PAcwzPMeW/Hx4vdEH1lHIYrNsMF
         1UL1BjBb1YJTVHihmcKVrMh9c2K+ZVhcV2iDn8PKQFwu3R6I3RXBhKIW2Wy7fbsVMxc6
         ZowA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDzwoc72cTSVploCm8M7K4hfV3ey2O8SKztpMAjlO4BrxqUAp+EI
	LBvfDIFFTD1x+oSQkO3ggtE=
X-Google-Smtp-Source: ACHHUZ4sAwLt8Vl/vghWE0JQlEo08L3seD/DXTbPFl0U4Kb/16nayK8/LLGbkocK7dcYAiTqsV3ccw==
X-Received: by 2002:a05:6808:1383:b0:38e:96b5:5b73 with SMTP id c3-20020a056808138300b0038e96b55b73mr2842536oiw.1.1683744250552;
        Wed, 10 May 2023 11:44:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:4994:b0:192:7463:c900 with SMTP id
 ho20-20020a056870499400b001927463c900ls7745307oab.1.-pod-prod-gmail; Wed, 10
 May 2023 11:44:10 -0700 (PDT)
X-Received: by 2002:a05:6870:a8ac:b0:184:5395:4e44 with SMTP id eb44-20020a056870a8ac00b0018453954e44mr7459699oab.28.1683744249959;
        Wed, 10 May 2023 11:44:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683744249; cv=none;
        d=google.com; s=arc-20160816;
        b=zIHDHh8v4h5MESSZZSMroJGKt0hHbD947Y3glx5VxVnC/6mjkCrq69qStr9uKBQnXi
         KJBOHMAiVtYO6CsOKs8EU4614MZFqx1PzCP1bYtlgiU595iMAD5vRcoJxFir3soW2i83
         jqJmkBSSW+Ljf2APsVjs1ZZuOcHXePKkRrQEHL26HtDvZ/JgQ2qMQr3dKUhZJMsiuJxT
         ter/pgW83ZP9KVj4EGawL40BhM83e4pSoQ46cDPizNnYQ72PmhBZTuwGVB9SgtP92BFR
         BIC9nGlxX0WIhQVlYY8fF4FeUzvR6MRVPlpAH1DqXSRw8B5Tjxu3If82TZLoIRSr14YM
         BkXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Zz2gG5x1uuzDHd7UBtUGSEWxhXGgpajKQUUrCpUNvM8=;
        b=wiDSDMy+4vtLoaGNrb/jKGfy/s1uS6fQpq/0nzigBtD8UM7hcBxW3OPQem+HrwNy+X
         eG8mpD01OsP83vvXTcvkrAp46qFu8kDn7sc16mte93KupyUZLj4OxoK/zWPFDT5xDrb6
         qiGpJLiNoUbT1v+x8U2m2qbgFbGyPzmeur3TsxpM87tH6WWrZKo7fyAqTQbdglDrO/mw
         WZtRXRJ3moq+SrNz8YAjRYQb/5VvyIK7n6sKkNqvpY87EOr11c4fu6d/VS9CSJe7oR/L
         hwy/PMEJq8ttTfavemsNTtmE7SiEKYwUpzoZcX33yco7PmEDWOU7sjwUReQXpLU9viwu
         E19g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=HkyxGzdl;
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a29 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-vk1-xa29.google.com (mail-vk1-xa29.google.com. [2607:f8b0:4864:20::a29])
        by gmr-mx.google.com with ESMTPS id k5-20020a4ad985000000b0054f1917acd1si1341618oou.0.2023.05.10.11.44.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 10 May 2023 11:44:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a29 as permitted sender) client-ip=2607:f8b0:4864:20::a29;
Received: by mail-vk1-xa29.google.com with SMTP id 71dfb90a1353d-4501f454581so3418983e0c.3
        for <kasan-dev@googlegroups.com>; Wed, 10 May 2023 11:44:09 -0700 (PDT)
X-Received: by 2002:a1f:5205:0:b0:44f:e6ff:f30e with SMTP id
 g5-20020a1f5205000000b0044fe6fff30emr5850656vkb.10.1683744249025; Wed, 10 May
 2023 11:44:09 -0700 (PDT)
MIME-Version: 1.0
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
In-Reply-To: <20230508075507.1720950-1-gongruiqi1@huawei.com>
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
Date: Wed, 10 May 2023 11:43:58 -0700
Message-ID: <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
To: "GONG, Ruiqi" <gongruiqi1@huawei.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-hardening@vger.kernel.org, 
	Alexander Lobakin <aleksander.lobakin@intel.com>, kasan-dev@googlegroups.com, 
	Wang Weiyang <wangweiyang2@huawei.com>, Xiu Jianfeng <xiujianfeng@huawei.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Pekka Enberg <penberg@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=HkyxGzdl;       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::a29
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
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

On Mon, May 8, 2023 at 12:53=E2=80=AFAM GONG, Ruiqi <gongruiqi1@huawei.com>=
 wrote:
>
> When exploiting memory vulnerabilities, "heap spraying" is a common
> technique targeting those related to dynamic memory allocation (i.e. the
> "heap"), and it plays an important role in a successful exploitation.
> Basically, it is to overwrite the memory area of vulnerable object by
> triggering allocation in other subsystems or modules and therefore
> getting a reference to the targeted memory location. It's usable on
> various types of vulnerablity including use after free (UAF), heap out-
> of-bound write and etc.
>
> There are (at least) two reasons why the heap can be sprayed: 1) generic
> slab caches are shared among different subsystems and modules, and
> 2) dedicated slab caches could be merged with the generic ones.
> Currently these two factors cannot be prevented at a low cost: the first
> one is a widely used memory allocation mechanism, and shutting down slab
> merging completely via `slub_nomerge` would be overkill.
>
> To efficiently prevent heap spraying, we propose the following approach:
> to create multiple copies of generic slab caches that will never be
> merged, and random one of them will be used at allocation. The random
> selection is based on the address of code that calls `kmalloc()`, which
> means it is static at runtime (rather than dynamically determined at
> each time of allocation, which could be bypassed by repeatedly spraying
> in brute force). In this way, the vulnerable object and memory allocated
> in other subsystems and modules will (most probably) be on different
> slab caches, which prevents the object from being sprayed.
>
> The overhead of performance has been tested on a 40-core x86 server by
> comparing the results of `perf bench all` between the kernels with and
> without this patch based on the latest linux-next kernel, which shows
> minor difference. A subset of benchmarks are listed below:
>

Please Cc maintainers/reviewers of corresponding subsystem in MAINTAINERS f=
ile.

I dont think adding a hardening feature by sacrificing one digit
percent performance
(and additional complexity) is worth. Heap spraying can only occur
when the kernel contains
security vulnerabilities, and if there is no known ways of performing
such an attack,
then we would simply be paying a consistent cost.

Any opinions from hardening folks?

>                         control         experiment (avg of 3 samples)
> sched/messaging (sec)   0.019           0.019
> sched/pipe (sec)        5.253           5.340
> syscall/basic (sec)     0.741           0.742
> mem/memcpy (GB/sec)     15.258789       14.860495
> mem/memset (GB/sec)     48.828125       50.431069
>
> The overhead of memory usage was measured by executing `free` after boot
> on a QEMU VM with 1GB total memory, and as expected, it's positively
> correlated with # of cache copies:
>
>                 control         4 copies        8 copies        16 copies
> total           969.8M          968.2M          968.2M          968.2M
> used            20.0M           21.9M           24.1M           26.7M
> free            936.9M          933.6M          931.4M          928.6M
> available       932.2M          928.8M          926.6M          923.9M
>
> Signed-off-by: GONG, Ruiqi <gongruiqi1@huawei.com>
> ---
>
> v2:
>   - Use hash_64() and a per-boot random seed to select kmalloc() caches.
>   - Change acceptable # of caches from [4,16] to {2,4,8,16}, which is
> more compatible with hashing.
>   - Supplement results of performance and memory overhead tests.
>
>  include/linux/percpu.h  | 12 ++++++---
>  include/linux/slab.h    | 25 +++++++++++++++---
>  mm/Kconfig              | 49 ++++++++++++++++++++++++++++++++++++
>  mm/kfence/kfence_test.c |  4 +--
>  mm/slab.c               |  2 +-
>  mm/slab.h               |  3 ++-
>  mm/slab_common.c        | 56 +++++++++++++++++++++++++++++++++++++----
>  7 files changed, 135 insertions(+), 16 deletions(-)
>
> diff --git a/include/linux/percpu.h b/include/linux/percpu.h
> index 1338ea2aa720..6cee6425951f 100644
> --- a/include/linux/percpu.h
> +++ b/include/linux/percpu.h
> @@ -34,6 +34,12 @@
>  #define PCPU_BITMAP_BLOCK_BITS         (PCPU_BITMAP_BLOCK_SIZE >>      \
>                                          PCPU_MIN_ALLOC_SHIFT)
>
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +#define PERCPU_DYNAMIC_SIZE_SHIFT      13
> +#else
> +#define PERCPU_DYNAMIC_SIZE_SHIFT      10
> +#endif
> +
>  /*
>   * Percpu allocator can serve percpu allocations before slab is
>   * initialized which allows slab to depend on the percpu allocator.
> @@ -41,7 +47,7 @@
>   * for this.  Keep PERCPU_DYNAMIC_RESERVE equal to or larger than
>   * PERCPU_DYNAMIC_EARLY_SIZE.
>   */
> -#define PERCPU_DYNAMIC_EARLY_SIZE      (20 << 10)
> +#define PERCPU_DYNAMIC_EARLY_SIZE      (20 << PERCPU_DYNAMIC_SIZE_SHIFT)
>
>  /*
>   * PERCPU_DYNAMIC_RESERVE indicates the amount of free area to piggy
> @@ -55,9 +61,9 @@
>   * intelligent way to determine this would be nice.
>   */
>  #if BITS_PER_LONG > 32
> -#define PERCPU_DYNAMIC_RESERVE         (28 << 10)
> +#define PERCPU_DYNAMIC_RESERVE         (28 << PERCPU_DYNAMIC_SIZE_SHIFT)
>  #else
> -#define PERCPU_DYNAMIC_RESERVE         (20 << 10)
> +#define PERCPU_DYNAMIC_RESERVE         (20 << PERCPU_DYNAMIC_SIZE_SHIFT)
>  #endif
>
>  extern void *pcpu_base_addr;
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 6b3e155b70bf..939c41c20600 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -18,6 +18,9 @@
>  #include <linux/workqueue.h>
>  #include <linux/percpu-refcount.h>
>
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +#include <linux/hash.h>
> +#endif
>
>  /*
>   * Flags to pass to kmem_cache_create().
> @@ -106,6 +109,12 @@
>  /* Avoid kmemleak tracing */
>  #define SLAB_NOLEAKTRACE       ((slab_flags_t __force)0x00800000U)
>
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +# define SLAB_RANDOMSLAB       ((slab_flags_t __force)0x01000000U)
> +#else
> +# define SLAB_RANDOMSLAB       0
> +#endif
> +
>  /* Fault injection mark */
>  #ifdef CONFIG_FAILSLAB
>  # define SLAB_FAILSLAB         ((slab_flags_t __force)0x02000000U)
> @@ -331,7 +340,9 @@ static inline unsigned int arch_slab_minalign(void)
>   * kmem caches can have both accounted and unaccounted objects.
>   */
>  enum kmalloc_cache_type {
> -       KMALLOC_NORMAL =3D 0,
> +       KMALLOC_RANDOM_START =3D 0,
> +       KMALLOC_RANDOM_END =3D KMALLOC_RANDOM_START + CONFIG_RANDOM_KMALL=
OC_CACHES_NR - 1,
> +       KMALLOC_NORMAL =3D KMALLOC_RANDOM_END,
>  #ifndef CONFIG_ZONE_DMA
>         KMALLOC_DMA =3D KMALLOC_NORMAL,
>  #endif
> @@ -363,14 +374,20 @@ kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH=
 + 1];
>         (IS_ENABLED(CONFIG_ZONE_DMA)   ? __GFP_DMA : 0) |       \
>         (IS_ENABLED(CONFIG_MEMCG_KMEM) ? __GFP_ACCOUNT : 0))
>
> -static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags)
> +extern unsigned long random_kmalloc_seed;
> +
> +static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags,=
 unsigned long caller)
>  {
>         /*
>          * The most common case is KMALLOC_NORMAL, so test for it
>          * with a single branch for all the relevant flags.
>          */
>         if (likely((flags & KMALLOC_NOT_NORMAL_BITS) =3D=3D 0))
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +               return KMALLOC_RANDOM_START + hash_64(caller ^ random_kma=
lloc_seed, CONFIG_RANDOM_KMALLOC_CACHES_BITS);
> +#else
>                 return KMALLOC_NORMAL;
> +#endif
>
>         /*
>          * At least one of the flags has to be set. Their priorities in
> @@ -557,7 +574,7 @@ static __always_inline __alloc_size(1) void *kmalloc(=
size_t size, gfp_t flags)
>
>                 index =3D kmalloc_index(size);
>                 return kmalloc_trace(
> -                               kmalloc_caches[kmalloc_type(flags)][index=
],
> +                               kmalloc_caches[kmalloc_type(flags, _RET_I=
P_)][index],
>                                 flags, size);
>         }
>         return __kmalloc(size, flags);
> @@ -573,7 +590,7 @@ static __always_inline __alloc_size(1) void *kmalloc_=
node(size_t size, gfp_t fla
>
>                 index =3D kmalloc_index(size);
>                 return kmalloc_node_trace(
> -                               kmalloc_caches[kmalloc_type(flags)][index=
],
> +                               kmalloc_caches[kmalloc_type(flags, _RET_I=
P_)][index],
>                                 flags, node, size);
>         }
>         return __kmalloc_node(size, flags, node);
> diff --git a/mm/Kconfig b/mm/Kconfig
> index 7672a22647b4..e868da87d9cd 100644
> --- a/mm/Kconfig
> +++ b/mm/Kconfig
> @@ -311,6 +311,55 @@ config SLUB_CPU_PARTIAL
>           which requires the taking of locks that may cause latency spike=
s.
>           Typically one would choose no for a realtime system.
>
> +config RANDOM_KMALLOC_CACHES
> +       default n
> +       depends on SLUB
> +       bool "Random slab caches for normal kmalloc"
> +       help
> +         A hardening feature that creates multiple copies of slab caches=
 for
> +         normal kmalloc allocation and makes kmalloc randomly pick one b=
ased
> +         on code address, which makes the attackers unable to spray vuln=
erable
> +         memory objects on the heap for exploiting memory vulnerabilitie=
s.
> +
> +choice
> +       prompt "Number of random slab caches copies"
> +       depends on RANDOM_KMALLOC_CACHES
> +       default RANDOM_KMALLOC_CACHES_16
> +       help
> +         The number of copies of random slab caches. Bigger value makes =
the
> +         potentially vulnerable memory object less likely to collide wit=
h
> +         objects allocated from other subsystems or modules.
> +
> +config RANDOM_KMALLOC_CACHES_2
> +       bool "2"
> +
> +config RANDOM_KMALLOC_CACHES_4
> +       bool "4"
> +
> +config RANDOM_KMALLOC_CACHES_8
> +       bool "8"
> +
> +config RANDOM_KMALLOC_CACHES_16
> +       bool "16"
> +
> +endchoice
> +
> +config RANDOM_KMALLOC_CACHES_BITS
> +       int
> +       default 0 if !RANDOM_KMALLOC_CACHES
> +       default 1 if RANDOM_KMALLOC_CACHES_2
> +       default 2 if RANDOM_KMALLOC_CACHES_4
> +       default 3 if RANDOM_KMALLOC_CACHES_8
> +       default 4 if RANDOM_KMALLOC_CACHES_16
> +
> +config RANDOM_KMALLOC_CACHES_NR
> +       int
> +       default 1 if !RANDOM_KMALLOC_CACHES
> +       default 2 if RANDOM_KMALLOC_CACHES_2
> +       default 4 if RANDOM_KMALLOC_CACHES_4
> +       default 8 if RANDOM_KMALLOC_CACHES_8
> +       default 16 if RANDOM_KMALLOC_CACHES_16
> +
>  endmenu # SLAB allocator options
>
>  config SHUFFLE_PAGE_ALLOCATOR
> diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
> index 6aee19a79236..8a95ef649d5e 100644
> --- a/mm/kfence/kfence_test.c
> +++ b/mm/kfence/kfence_test.c
> @@ -213,7 +213,7 @@ static void test_cache_destroy(void)
>
>  static inline size_t kmalloc_cache_alignment(size_t size)
>  {
> -       return kmalloc_caches[kmalloc_type(GFP_KERNEL)][__kmalloc_index(s=
ize, false)]->align;
> +       return kmalloc_caches[kmalloc_type(GFP_KERNEL, _RET_IP_)][__kmall=
oc_index(size, false)]->align;
>  }
>
>  /* Must always inline to match stack trace against caller. */
> @@ -284,7 +284,7 @@ static void *test_alloc(struct kunit *test, size_t si=
ze, gfp_t gfp, enum allocat
>                 if (is_kfence_address(alloc)) {
>                         struct slab *slab =3D virt_to_slab(alloc);
>                         struct kmem_cache *s =3D test_cache ?:
> -                                       kmalloc_caches[kmalloc_type(GFP_K=
ERNEL)][__kmalloc_index(size, false)];
> +                                       kmalloc_caches[kmalloc_type(GFP_K=
ERNEL, _RET_IP_)][__kmalloc_index(size, false)];
>
>                         /*
>                          * Verify that various helpers return the right v=
alues
> diff --git a/mm/slab.c b/mm/slab.c
> index bb57f7fdbae1..82e2a8d4cd9d 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -1674,7 +1674,7 @@ static size_t calculate_slab_order(struct kmem_cach=
e *cachep,
>                         if (freelist_size > KMALLOC_MAX_CACHE_SIZE) {
>                                 freelist_cache_size =3D PAGE_SIZE << get_=
order(freelist_size);
>                         } else {
> -                               freelist_cache =3D kmalloc_slab(freelist_=
size, 0u);
> +                               freelist_cache =3D kmalloc_slab(freelist_=
size, 0u, _RET_IP_);
>                                 if (!freelist_cache)
>                                         continue;
>                                 freelist_cache_size =3D freelist_cache->s=
ize;
> diff --git a/mm/slab.h b/mm/slab.h
> index f01ac256a8f5..1e484af71c52 100644
> --- a/mm/slab.h
> +++ b/mm/slab.h
> @@ -243,7 +243,7 @@ void setup_kmalloc_cache_index_table(void);
>  void create_kmalloc_caches(slab_flags_t);
>
>  /* Find the kmalloc slab corresponding for a certain size */
> -struct kmem_cache *kmalloc_slab(size_t, gfp_t);
> +struct kmem_cache *kmalloc_slab(size_t, gfp_t, unsigned long);
>
>  void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
>                               int node, size_t orig_size,
> @@ -319,6 +319,7 @@ static inline bool is_kmalloc_cache(struct kmem_cache=
 *s)
>                               SLAB_TEMPORARY | \
>                               SLAB_ACCOUNT | \
>                               SLAB_KMALLOC | \
> +                             SLAB_RANDOMSLAB | \
>                               SLAB_NO_USER_FLAGS)
>
>  bool __kmem_cache_empty(struct kmem_cache *);
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 607249785c07..70899b20a9a7 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -47,6 +47,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>   */
>  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER =
| \
>                 SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> +               SLAB_RANDOMSLAB | \
>                 SLAB_FAILSLAB | kasan_never_merge())
>
>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
> @@ -679,6 +680,11 @@ kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH =
+ 1] __ro_after_init =3D
>  { /* initialization for https://bugs.llvm.org/show_bug.cgi?id=3D42570 */=
 };
>  EXPORT_SYMBOL(kmalloc_caches);
>
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +unsigned long random_kmalloc_seed __ro_after_init;
> +EXPORT_SYMBOL(random_kmalloc_seed);
> +#endif
> +
>  /*
>   * Conversion table for small slabs sizes / 8 to the index in the
>   * kmalloc array. This is necessary for slabs < 192 since we have non po=
wer
> @@ -721,7 +727,7 @@ static inline unsigned int size_index_elem(unsigned i=
nt bytes)
>   * Find the kmem_cache structure that serves a given size of
>   * allocation
>   */
> -struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
> +struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long =
caller)
>  {
>         unsigned int index;
>
> @@ -736,7 +742,7 @@ struct kmem_cache *kmalloc_slab(size_t size, gfp_t fl=
ags)
>                 index =3D fls(size - 1);
>         }
>
> -       return kmalloc_caches[kmalloc_type(flags)][index];
> +       return kmalloc_caches[kmalloc_type(flags, caller)][index];
>  }
>
>  size_t kmalloc_size_roundup(size_t size)
> @@ -754,7 +760,7 @@ size_t kmalloc_size_roundup(size_t size)
>                 return PAGE_SIZE << get_order(size);
>
>         /* The flags don't matter since size_index is common to all. */
> -       c =3D kmalloc_slab(size, GFP_KERNEL);
> +       c =3D kmalloc_slab(size, GFP_KERNEL, _RET_IP_);
>         return c ? c->object_size : 0;
>  }
>  EXPORT_SYMBOL(kmalloc_size_roundup);
> @@ -777,12 +783,44 @@ EXPORT_SYMBOL(kmalloc_size_roundup);
>  #define KMALLOC_RCL_NAME(sz)
>  #endif
>
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +#define __KMALLOC_RANDOM_CONCAT(a, b, c) a ## b ## c
> +#define KMALLOC_RANDOM_NAME(N, sz) __KMALLOC_RANDOM_CONCAT(KMALLOC_RANDO=
M_, N, _NAME)(sz)
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >=3D 1
> +#define KMALLOC_RANDOM_1_NAME(sz)                             .name[KMAL=
LOC_RANDOM_START +  0] =3D "kmalloc-random-01-" #sz,
> +#define KMALLOC_RANDOM_2_NAME(sz)  KMALLOC_RANDOM_1_NAME(sz)  .name[KMAL=
LOC_RANDOM_START +  1] =3D "kmalloc-random-02-" #sz,
> +#endif
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >=3D 2
> +#define KMALLOC_RANDOM_3_NAME(sz)  KMALLOC_RANDOM_2_NAME(sz)  .name[KMAL=
LOC_RANDOM_START +  2] =3D "kmalloc-random-03-" #sz,
> +#define KMALLOC_RANDOM_4_NAME(sz)  KMALLOC_RANDOM_3_NAME(sz)  .name[KMAL=
LOC_RANDOM_START +  3] =3D "kmalloc-random-04-" #sz,
> +#endif
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >=3D 3
> +#define KMALLOC_RANDOM_5_NAME(sz)  KMALLOC_RANDOM_4_NAME(sz)  .name[KMAL=
LOC_RANDOM_START +  4] =3D "kmalloc-random-05-" #sz,
> +#define KMALLOC_RANDOM_6_NAME(sz)  KMALLOC_RANDOM_5_NAME(sz)  .name[KMAL=
LOC_RANDOM_START +  5] =3D "kmalloc-random-06-" #sz,
> +#define KMALLOC_RANDOM_7_NAME(sz)  KMALLOC_RANDOM_6_NAME(sz)  .name[KMAL=
LOC_RANDOM_START +  6] =3D "kmalloc-random-07-" #sz,
> +#define KMALLOC_RANDOM_8_NAME(sz)  KMALLOC_RANDOM_7_NAME(sz)  .name[KMAL=
LOC_RANDOM_START +  7] =3D "kmalloc-random-08-" #sz,
> +#endif
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >=3D 4
> +#define KMALLOC_RANDOM_9_NAME(sz)  KMALLOC_RANDOM_8_NAME(sz)  .name[KMAL=
LOC_RANDOM_START +  8] =3D "kmalloc-random-09-" #sz,
> +#define KMALLOC_RANDOM_10_NAME(sz) KMALLOC_RANDOM_9_NAME(sz)  .name[KMAL=
LOC_RANDOM_START +  9] =3D "kmalloc-random-10-" #sz,
> +#define KMALLOC_RANDOM_11_NAME(sz) KMALLOC_RANDOM_10_NAME(sz) .name[KMAL=
LOC_RANDOM_START + 10] =3D "kmalloc-random-11-" #sz,
> +#define KMALLOC_RANDOM_12_NAME(sz) KMALLOC_RANDOM_11_NAME(sz) .name[KMAL=
LOC_RANDOM_START + 11] =3D "kmalloc-random-12-" #sz,
> +#define KMALLOC_RANDOM_13_NAME(sz) KMALLOC_RANDOM_12_NAME(sz) .name[KMAL=
LOC_RANDOM_START + 12] =3D "kmalloc-random-13-" #sz,
> +#define KMALLOC_RANDOM_14_NAME(sz) KMALLOC_RANDOM_13_NAME(sz) .name[KMAL=
LOC_RANDOM_START + 13] =3D "kmalloc-random-14-" #sz,
> +#define KMALLOC_RANDOM_15_NAME(sz) KMALLOC_RANDOM_14_NAME(sz) .name[KMAL=
LOC_RANDOM_START + 14] =3D "kmalloc-random-15-" #sz,
> +#define KMALLOC_RANDOM_16_NAME(sz) KMALLOC_RANDOM_15_NAME(sz) .name[KMAL=
LOC_RANDOM_START + 15] =3D "kmalloc-random-16-" #sz,
> +#endif
> +#else // CONFIG_RANDOM_KMALLOC_CACHES
> +#define KMALLOC_RANDOM_NAME(N, sz)
> +#endif
> +
>  #define INIT_KMALLOC_INFO(__size, __short_size)                        \
>  {                                                              \
>         .name[KMALLOC_NORMAL]  =3D "kmalloc-" #__short_size,      \
>         KMALLOC_RCL_NAME(__short_size)                          \
>         KMALLOC_CGROUP_NAME(__short_size)                       \
>         KMALLOC_DMA_NAME(__short_size)                          \
> +       KMALLOC_RANDOM_NAME(CONFIG_RANDOM_KMALLOC_CACHES_NR, __short_size=
)      \
>         .size =3D __size,                                         \
>  }
>
> @@ -878,6 +916,11 @@ new_kmalloc_cache(int idx, enum kmalloc_cache_type t=
ype, slab_flags_t flags)
>                 flags |=3D SLAB_CACHE_DMA;
>         }
>
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +       if (type >=3D KMALLOC_RANDOM_START && type <=3D KMALLOC_RANDOM_EN=
D)
> +               flags |=3D SLAB_RANDOMSLAB;
> +#endif
> +
>         kmalloc_caches[type][idx] =3D create_kmalloc_cache(
>                                         kmalloc_info[idx].name[type],
>                                         kmalloc_info[idx].size, flags, 0,
> @@ -904,7 +947,7 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>         /*
>          * Including KMALLOC_CGROUP if CONFIG_MEMCG_KMEM defined
>          */
> -       for (type =3D KMALLOC_NORMAL; type < NR_KMALLOC_TYPES; type++) {
> +       for (type =3D KMALLOC_RANDOM_START; type < NR_KMALLOC_TYPES; type=
++) {
>                 for (i =3D KMALLOC_SHIFT_LOW; i <=3D KMALLOC_SHIFT_HIGH; =
i++) {
>                         if (!kmalloc_caches[type][i])
>                                 new_kmalloc_cache(i, type, flags);
> @@ -922,6 +965,9 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>                                 new_kmalloc_cache(2, type, flags);
>                 }
>         }
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +       random_kmalloc_seed =3D get_random_u64();
> +#endif
>
>         /* Kmalloc array is now usable */
>         slab_state =3D UP;
> @@ -957,7 +1003,7 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, in=
t node, unsigned long caller
>                 return ret;
>         }
>
> -       s =3D kmalloc_slab(size, flags);
> +       s =3D kmalloc_slab(size, flags, caller);
>
>         if (unlikely(ZERO_OR_NULL_PTR(s)))
>                 return s;
> --
> 2.25.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAB%3D%2Bi9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ%40mail.gm=
ail.com.
