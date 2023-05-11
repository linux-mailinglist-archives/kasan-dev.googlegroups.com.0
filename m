Return-Path: <kasan-dev+bncBAABBAOA6ORAMGQERG6ZDEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 22EBA6FF181
	for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 14:30:59 +0200 (CEST)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-559e55b8766sf139320127b3.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 May 2023 05:30:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683808258; cv=pass;
        d=google.com; s=arc-20160816;
        b=HBomNXBNiixYFCAxwFs5Ii62ehTuBxXDQxpcyvGuL5kimst80BMgmH7j1h2tq46nHt
         mkYEMYrugdKoFHOifvmujc60ev4DZhKYU91cKrgxKvEq8TwGnMJiXfmqW/7PypmjwTED
         osUWZ6j2uqKAXAIvgGis5WsbUABCC4uydkR5cvNtra15f5E4c9kpKZ7WXUDp+Kcq25aD
         MqzhGQE3+dgGJbg4cpSWxyqFO0jycdK3qr/SPzjWralD90irZ9IYd9xOPY9ZAQchiqb4
         J6urcUh2wHZ6fUqmY3+Z2P57ROiX7F28P0pyvAJQ7ExKsNo7hZOBgzkOrU3tK40trwQm
         189g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:dkim-signature;
        bh=RkiARLf5kLWnUFxzX/ykbOiM7U9scXrQv4OyxRvNUWk=;
        b=us7yMQm3O81N2rH/EaL5aS5JNNl+1KzU4TSCh24F7ufCBLoFuvV/Fr/Ta8u0U9W1Q+
         S0znZxK6IGAICJcHqDDNsna90oCC3WPLckS87tfHbr2i7E37vAdknCSDVRlNwTZBPkbQ
         WquxcziABMciOv+n4Nj1nu1ey5IwyQuvs8ptYcRPnVIYAZgQ2iHtMG5u/3zruzzpB+Jr
         14BVFZDNzUqz7fuXzBwSdylzCfkGQnXhMg+oPFCajATAbhlzXC+1mSEV/PzVzgk9tern
         Cz1/wDwOdy85Og5mJCJpNR5XZ0XdF3JLJ7/TmR1fotIptxlRoMHTmLKDlkIKzCISBzxg
         Jy8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of xiujianfeng@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=xiujianfeng@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683808258; x=1686400258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RkiARLf5kLWnUFxzX/ykbOiM7U9scXrQv4OyxRvNUWk=;
        b=lg8JPc6lobt0UES7sRyPYAEcbtvGspeEPLg6mvEdOzVYJ1fzSP1u1QFsM1WD+510k4
         h/tGIgVqt0yB0Z+VN0uuUdd5YssezDDaDuDyUOmiaH+PCVcbwAY4ecHbjZCdfS1NTJrw
         DuQ7EmWTMJJMjHf3DygSuoNLVzekhnLUh5APyJI0Z7f25hQgYr+lGWj4yK8LdB+MML3E
         M+7wbVhPnsdw1AZ7VUv3qchp95r5C8DNMYJji3UWqiHKTA8bY+fPSYbYHqDw5/xy3+sL
         W1avSE2RoHtNDE3/4RufZhZ/0NJPHXGaGiQOmT6w7j4mhJJUjUPqx+8d+sAWylH8/40g
         JHLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683808258; x=1686400258;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RkiARLf5kLWnUFxzX/ykbOiM7U9scXrQv4OyxRvNUWk=;
        b=CZgCsRjdbQpheQBDA6wSReWUURJrlXDWTQwWaPPLFe0/lVQNMKOoBTFkJeUye/QfkW
         Xi/PMw+d3gTJjzNEJfSrSyu/GZTTKReLXFeWEZSC5y2oII7rSkEI8mo0/WtfeNqDTICF
         HIHsQOZGdrRURh2DtvxRbl8VYTAcE11Y3GFrJOlKf1SFJXknCLHXL0xdeBu7qZQKo5X9
         AoLCDCBoZe+auom67/5D2joNUn4y11VM2QyElsiRT16ek+gcpXyHHnlx65lYKKZAgOXU
         pTjOkmMBVgebJ4Ylk5nJcH8ILBXfsVKGx38pebGwjIAvWhkPTqzbclwcKZOqRXlQC9fQ
         wt8g==
X-Gm-Message-State: AC+VfDwGnCRP6eWx6WqUQk5ftAdjSOXPeky9wzHBTqjRIcUtUFcrzXTZ
	3qi6kVpSaiHruGMIZWDYpzo=
X-Google-Smtp-Source: ACHHUZ6hfoeU1dl51jCMoqtEEPkW1dxb86uY8twcflzzNGdK1I27Yaaduvm09mxyzE5ge9oH6fULIw==
X-Received: by 2002:a81:b2c7:0:b0:559:e97a:cb21 with SMTP id q190-20020a81b2c7000000b00559e97acb21mr12429401ywh.9.1683808257796;
        Thu, 11 May 2023 05:30:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:690c:2e8e:b0:560:eb68:ab45 with SMTP id
 eu14-20020a05690c2e8e00b00560eb68ab45ls1968126ywb.9.-pod-prod-gmail; Thu, 11
 May 2023 05:30:57 -0700 (PDT)
X-Received: by 2002:a81:c24c:0:b0:55a:6e23:1a82 with SMTP id t12-20020a81c24c000000b0055a6e231a82mr20148875ywg.52.1683808257289;
        Thu, 11 May 2023 05:30:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683808257; cv=none;
        d=google.com; s=arc-20160816;
        b=t55wrvbtkRn9VGkrwVSG7yUGeX7M36RvXZlS3c+udwsoeokM0locht1xbG490hhx5W
         qsaPFpLnopSouaU7nlgxFT+ARZ2LIN95SE79wFpFE1ZwnPTBEk7+1/op6DA9ed8p7vmY
         dEx4ccoF63ipfP+bi1Ev7e/v7tdgl2XDMXJqb5FXL65VE19YVUR1IABObkTygCyzXfe+
         gE2+4WPAsyboP3p9ktHgrYUYsOc9BF1bXla424uqWBSBR4kLmSP7xP4FTTr6uK1ISgw1
         j6oRgIxBGrPIjHnAocZve4PSxUPznXQNHi+7gEqkdm+r7ml48PwIMOR1ltEGgy5NKK/R
         vOcA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=gk0/bf5Km+xGX9S4/V+Y+ni7xCYAD/RE0zXrRDM2lG8=;
        b=nioH5XahllIr6FkwKmynruePoY2JILh2yk75r17R1LMvB05OEhjATcBD+sgpCeEAcw
         nD8lAOmgVOdwFbr+PdBU87mdOI+gxS6vLWst6rdz08Q9VTvstdXCm6xgV/aXjayaBjNg
         2/Z36Gx8cYYF6ye23ryhuVTGnYSDNe3s+SHOZMEPiDzFPJP8FLyJXECFyVZyXNG7l9QG
         /r4cEwzdjVnbDKhqXfhXlo0Tf4pReIJUJ7SeyCSRPPQbBtn8bETjuzZ3YS9BCbD4zqc9
         7qKmTaz3xwgXscTtfEwV/46CEgAzrPLESKzPyzusd502t/GjY7+aQjxYoa8JfNoUafHT
         ln2g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of xiujianfeng@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=xiujianfeng@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id db20-20020a05690c0dd400b0055a5a7bcedcsi755761ywb.3.2023.05.11.05.30.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 11 May 2023 05:30:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of xiujianfeng@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpeml500023.china.huawei.com (unknown [172.30.72.56])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4QHB334zv1zpVH6;
	Thu, 11 May 2023 20:26:39 +0800 (CST)
Received: from [10.67.110.112] (10.67.110.112) by
 dggpeml500023.china.huawei.com (7.185.36.114) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.23; Thu, 11 May 2023 20:30:52 +0800
Message-ID: <1b270263-f457-e23b-e744-322a010d2a66@huawei.com>
Date: Thu, 11 May 2023 20:30:52 +0800
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101
 Thunderbird/102.5.1
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Content-Language: en-US
To: "GONG, Ruiqi" <gongruiqi1@huawei.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-hardening@vger.kernel.org>
CC: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Lobakin
	<aleksander.lobakin@intel.com>, <kasan-dev@googlegroups.com>, Wang Weiyang
	<wangweiyang2@huawei.com>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
From: "'xiujianfeng' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <20230508075507.1720950-1-gongruiqi1@huawei.com>
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.110.112]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpeml500023.china.huawei.com (7.185.36.114)
X-CFilter-Loop: Reflected
X-Original-Sender: xiujianfeng@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of xiujianfeng@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=xiujianfeng@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: xiujianfeng <xiujianfeng@huawei.com>
Reply-To: xiujianfeng <xiujianfeng@huawei.com>
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



On 2023/5/8 15:55, GONG, Ruiqi wrote:
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
> 			control		experiment (avg of 3 samples)
> sched/messaging (sec)	0.019		0.019
> sched/pipe (sec)	5.253		5.340
> syscall/basic (sec)	0.741		0.742
> mem/memcpy (GB/sec)	15.258789	14.860495
> mem/memset (GB/sec)	48.828125	50.431069
> 

Could this be a measurement error? otherwise it doesn't look reasonable
to just improve memcpy and worsen memset.


> The overhead of memory usage was measured by executing `free` after boot
> on a QEMU VM with 1GB total memory, and as expected, it's positively
> correlated with # of cache copies:
> 
> 		control		4 copies	8 copies	16 copies
> total		969.8M		968.2M		968.2M		968.2M
> used		20.0M		21.9M		24.1M		26.7M
> free		936.9M		933.6M		931.4M		928.6M
> available	932.2M		928.8M		926.6M		923.9M
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
>  #define PCPU_BITMAP_BLOCK_BITS		(PCPU_BITMAP_BLOCK_SIZE >>	\
>  					 PCPU_MIN_ALLOC_SHIFT)
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
> -#define PERCPU_DYNAMIC_EARLY_SIZE	(20 << 10)
> +#define PERCPU_DYNAMIC_EARLY_SIZE	(20 << PERCPU_DYNAMIC_SIZE_SHIFT)
>  
>  /*
>   * PERCPU_DYNAMIC_RESERVE indicates the amount of free area to piggy
> @@ -55,9 +61,9 @@
>   * intelligent way to determine this would be nice.
>   */
>  #if BITS_PER_LONG > 32
> -#define PERCPU_DYNAMIC_RESERVE		(28 << 10)
> +#define PERCPU_DYNAMIC_RESERVE		(28 << PERCPU_DYNAMIC_SIZE_SHIFT)
>  #else
> -#define PERCPU_DYNAMIC_RESERVE		(20 << 10)
> +#define PERCPU_DYNAMIC_RESERVE		(20 << PERCPU_DYNAMIC_SIZE_SHIFT)
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
>  #define SLAB_NOLEAKTRACE	((slab_flags_t __force)0x00800000U)
>  
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +# define SLAB_RANDOMSLAB	((slab_flags_t __force)0x01000000U)
> +#else
> +# define SLAB_RANDOMSLAB	0
> +#endif
> +
>  /* Fault injection mark */
>  #ifdef CONFIG_FAILSLAB
>  # define SLAB_FAILSLAB		((slab_flags_t __force)0x02000000U)
> @@ -331,7 +340,9 @@ static inline unsigned int arch_slab_minalign(void)
>   * kmem caches can have both accounted and unaccounted objects.
>   */
>  enum kmalloc_cache_type {
> -	KMALLOC_NORMAL = 0,
> +	KMALLOC_RANDOM_START = 0,
> +	KMALLOC_RANDOM_END = KMALLOC_RANDOM_START + CONFIG_RANDOM_KMALLOC_CACHES_NR - 1,
> +	KMALLOC_NORMAL = KMALLOC_RANDOM_END,
>  #ifndef CONFIG_ZONE_DMA
>  	KMALLOC_DMA = KMALLOC_NORMAL,
>  #endif
> @@ -363,14 +374,20 @@ kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1];
>  	(IS_ENABLED(CONFIG_ZONE_DMA)   ? __GFP_DMA : 0) |	\
>  	(IS_ENABLED(CONFIG_MEMCG_KMEM) ? __GFP_ACCOUNT : 0))
>  
> -static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags)
> +extern unsigned long random_kmalloc_seed;
> +
> +static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags, unsigned long caller)
>  {
>  	/*
>  	 * The most common case is KMALLOC_NORMAL, so test for it
>  	 * with a single branch for all the relevant flags.
>  	 */
>  	if (likely((flags & KMALLOC_NOT_NORMAL_BITS) == 0))
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +		return KMALLOC_RANDOM_START + hash_64(caller ^ random_kmalloc_seed, CONFIG_RANDOM_KMALLOC_CACHES_BITS);
> +#else
>  		return KMALLOC_NORMAL;
> +#endif
>  
>  	/*
>  	 * At least one of the flags has to be set. Their priorities in
> @@ -557,7 +574,7 @@ static __always_inline __alloc_size(1) void *kmalloc(size_t size, gfp_t flags)
>  
>  		index = kmalloc_index(size);
>  		return kmalloc_trace(
> -				kmalloc_caches[kmalloc_type(flags)][index],
> +				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
>  				flags, size);
>  	}
>  	return __kmalloc(size, flags);
> @@ -573,7 +590,7 @@ static __always_inline __alloc_size(1) void *kmalloc_node(size_t size, gfp_t fla
>  
>  		index = kmalloc_index(size);
>  		return kmalloc_node_trace(
> -				kmalloc_caches[kmalloc_type(flags)][index],
> +				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
>  				flags, node, size);
>  	}
>  	return __kmalloc_node(size, flags, node);
> diff --git a/mm/Kconfig b/mm/Kconfig
> index 7672a22647b4..e868da87d9cd 100644
> --- a/mm/Kconfig
> +++ b/mm/Kconfig
> @@ -311,6 +311,55 @@ config SLUB_CPU_PARTIAL
>  	  which requires the taking of locks that may cause latency spikes.
>  	  Typically one would choose no for a realtime system.
>  
> +config RANDOM_KMALLOC_CACHES
> +	default n
> +	depends on SLUB
> +	bool "Random slab caches for normal kmalloc"
> +	help
> +	  A hardening feature that creates multiple copies of slab caches for
> +	  normal kmalloc allocation and makes kmalloc randomly pick one based
> +	  on code address, which makes the attackers unable to spray vulnerable
> +	  memory objects on the heap for exploiting memory vulnerabilities.
> +
> +choice
> +	prompt "Number of random slab caches copies"
> +	depends on RANDOM_KMALLOC_CACHES
> +	default RANDOM_KMALLOC_CACHES_16
> +	help
> +	  The number of copies of random slab caches. Bigger value makes the
> +	  potentially vulnerable memory object less likely to collide with
> +	  objects allocated from other subsystems or modules.
> +
> +config RANDOM_KMALLOC_CACHES_2
> +	bool "2"
> +
> +config RANDOM_KMALLOC_CACHES_4
> +	bool "4"
> +
> +config RANDOM_KMALLOC_CACHES_8
> +	bool "8"
> +
> +config RANDOM_KMALLOC_CACHES_16
> +	bool "16"
> +
> +endchoice
> +
> +config RANDOM_KMALLOC_CACHES_BITS
> +	int
> +	default 0 if !RANDOM_KMALLOC_CACHES
> +	default 1 if RANDOM_KMALLOC_CACHES_2
> +	default 2 if RANDOM_KMALLOC_CACHES_4
> +	default 3 if RANDOM_KMALLOC_CACHES_8
> +	default 4 if RANDOM_KMALLOC_CACHES_16
> +
> +config RANDOM_KMALLOC_CACHES_NR
> +	int
> +	default 1 if !RANDOM_KMALLOC_CACHES
> +	default 2 if RANDOM_KMALLOC_CACHES_2
> +	default 4 if RANDOM_KMALLOC_CACHES_4
> +	default 8 if RANDOM_KMALLOC_CACHES_8
> +	default 16 if RANDOM_KMALLOC_CACHES_16
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
> -	return kmalloc_caches[kmalloc_type(GFP_KERNEL)][__kmalloc_index(size, false)]->align;
> +	return kmalloc_caches[kmalloc_type(GFP_KERNEL, _RET_IP_)][__kmalloc_index(size, false)]->align;
>  }
>  
>  /* Must always inline to match stack trace against caller. */
> @@ -284,7 +284,7 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
>  		if (is_kfence_address(alloc)) {
>  			struct slab *slab = virt_to_slab(alloc);
>  			struct kmem_cache *s = test_cache ?:
> -					kmalloc_caches[kmalloc_type(GFP_KERNEL)][__kmalloc_index(size, false)];
> +					kmalloc_caches[kmalloc_type(GFP_KERNEL, _RET_IP_)][__kmalloc_index(size, false)];
>  
>  			/*
>  			 * Verify that various helpers return the right values
> diff --git a/mm/slab.c b/mm/slab.c
> index bb57f7fdbae1..82e2a8d4cd9d 100644
> --- a/mm/slab.c
> +++ b/mm/slab.c
> @@ -1674,7 +1674,7 @@ static size_t calculate_slab_order(struct kmem_cache *cachep,
>  			if (freelist_size > KMALLOC_MAX_CACHE_SIZE) {
>  				freelist_cache_size = PAGE_SIZE << get_order(freelist_size);
>  			} else {
> -				freelist_cache = kmalloc_slab(freelist_size, 0u);
> +				freelist_cache = kmalloc_slab(freelist_size, 0u, _RET_IP_);
>  				if (!freelist_cache)
>  					continue;
>  				freelist_cache_size = freelist_cache->size;
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
>  			      int node, size_t orig_size,
> @@ -319,6 +319,7 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
>  			      SLAB_TEMPORARY | \
>  			      SLAB_ACCOUNT | \
>  			      SLAB_KMALLOC | \
> +			      SLAB_RANDOMSLAB | \
>  			      SLAB_NO_USER_FLAGS)
>  
>  bool __kmem_cache_empty(struct kmem_cache *);
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 607249785c07..70899b20a9a7 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -47,6 +47,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
>   */
>  #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
>  		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
> +		SLAB_RANDOMSLAB | \
>  		SLAB_FAILSLAB | kasan_never_merge())
>  
>  #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
> @@ -679,6 +680,11 @@ kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1] __ro_after_init =
>  { /* initialization for https://bugs.llvm.org/show_bug.cgi?id=42570 */ };
>  EXPORT_SYMBOL(kmalloc_caches);
>  
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +unsigned long random_kmalloc_seed __ro_after_init;
> +EXPORT_SYMBOL(random_kmalloc_seed);
> +#endif
> +
>  /*
>   * Conversion table for small slabs sizes / 8 to the index in the
>   * kmalloc array. This is necessary for slabs < 192 since we have non power
> @@ -721,7 +727,7 @@ static inline unsigned int size_index_elem(unsigned int bytes)
>   * Find the kmem_cache structure that serves a given size of
>   * allocation
>   */
> -struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
> +struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
>  {
>  	unsigned int index;
>  
> @@ -736,7 +742,7 @@ struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
>  		index = fls(size - 1);
>  	}
>  
> -	return kmalloc_caches[kmalloc_type(flags)][index];
> +	return kmalloc_caches[kmalloc_type(flags, caller)][index];
>  }
>  
>  size_t kmalloc_size_roundup(size_t size)
> @@ -754,7 +760,7 @@ size_t kmalloc_size_roundup(size_t size)
>  		return PAGE_SIZE << get_order(size);
>  
>  	/* The flags don't matter since size_index is common to all. */
> -	c = kmalloc_slab(size, GFP_KERNEL);
> +	c = kmalloc_slab(size, GFP_KERNEL, _RET_IP_);
>  	return c ? c->object_size : 0;
>  }
>  EXPORT_SYMBOL(kmalloc_size_roundup);
> @@ -777,12 +783,44 @@ EXPORT_SYMBOL(kmalloc_size_roundup);
>  #define KMALLOC_RCL_NAME(sz)
>  #endif
>  
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +#define __KMALLOC_RANDOM_CONCAT(a, b, c) a ## b ## c
> +#define KMALLOC_RANDOM_NAME(N, sz) __KMALLOC_RANDOM_CONCAT(KMALLOC_RANDOM_, N, _NAME)(sz)
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 1
> +#define KMALLOC_RANDOM_1_NAME(sz)                             .name[KMALLOC_RANDOM_START +  0] = "kmalloc-random-01-" #sz,
> +#define KMALLOC_RANDOM_2_NAME(sz)  KMALLOC_RANDOM_1_NAME(sz)  .name[KMALLOC_RANDOM_START +  1] = "kmalloc-random-02-" #sz,
> +#endif
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 2
> +#define KMALLOC_RANDOM_3_NAME(sz)  KMALLOC_RANDOM_2_NAME(sz)  .name[KMALLOC_RANDOM_START +  2] = "kmalloc-random-03-" #sz,
> +#define KMALLOC_RANDOM_4_NAME(sz)  KMALLOC_RANDOM_3_NAME(sz)  .name[KMALLOC_RANDOM_START +  3] = "kmalloc-random-04-" #sz,
> +#endif
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 3
> +#define KMALLOC_RANDOM_5_NAME(sz)  KMALLOC_RANDOM_4_NAME(sz)  .name[KMALLOC_RANDOM_START +  4] = "kmalloc-random-05-" #sz,
> +#define KMALLOC_RANDOM_6_NAME(sz)  KMALLOC_RANDOM_5_NAME(sz)  .name[KMALLOC_RANDOM_START +  5] = "kmalloc-random-06-" #sz,
> +#define KMALLOC_RANDOM_7_NAME(sz)  KMALLOC_RANDOM_6_NAME(sz)  .name[KMALLOC_RANDOM_START +  6] = "kmalloc-random-07-" #sz,
> +#define KMALLOC_RANDOM_8_NAME(sz)  KMALLOC_RANDOM_7_NAME(sz)  .name[KMALLOC_RANDOM_START +  7] = "kmalloc-random-08-" #sz,
> +#endif
> +#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 4
> +#define KMALLOC_RANDOM_9_NAME(sz)  KMALLOC_RANDOM_8_NAME(sz)  .name[KMALLOC_RANDOM_START +  8] = "kmalloc-random-09-" #sz,
> +#define KMALLOC_RANDOM_10_NAME(sz) KMALLOC_RANDOM_9_NAME(sz)  .name[KMALLOC_RANDOM_START +  9] = "kmalloc-random-10-" #sz,
> +#define KMALLOC_RANDOM_11_NAME(sz) KMALLOC_RANDOM_10_NAME(sz) .name[KMALLOC_RANDOM_START + 10] = "kmalloc-random-11-" #sz,
> +#define KMALLOC_RANDOM_12_NAME(sz) KMALLOC_RANDOM_11_NAME(sz) .name[KMALLOC_RANDOM_START + 11] = "kmalloc-random-12-" #sz,
> +#define KMALLOC_RANDOM_13_NAME(sz) KMALLOC_RANDOM_12_NAME(sz) .name[KMALLOC_RANDOM_START + 12] = "kmalloc-random-13-" #sz,
> +#define KMALLOC_RANDOM_14_NAME(sz) KMALLOC_RANDOM_13_NAME(sz) .name[KMALLOC_RANDOM_START + 13] = "kmalloc-random-14-" #sz,
> +#define KMALLOC_RANDOM_15_NAME(sz) KMALLOC_RANDOM_14_NAME(sz) .name[KMALLOC_RANDOM_START + 14] = "kmalloc-random-15-" #sz,
> +#define KMALLOC_RANDOM_16_NAME(sz) KMALLOC_RANDOM_15_NAME(sz) .name[KMALLOC_RANDOM_START + 15] = "kmalloc-random-16-" #sz,
> +#endif
> +#else // CONFIG_RANDOM_KMALLOC_CACHES
> +#define KMALLOC_RANDOM_NAME(N, sz)
> +#endif
> +
>  #define INIT_KMALLOC_INFO(__size, __short_size)			\
>  {								\
>  	.name[KMALLOC_NORMAL]  = "kmalloc-" #__short_size,	\
>  	KMALLOC_RCL_NAME(__short_size)				\
>  	KMALLOC_CGROUP_NAME(__short_size)			\
>  	KMALLOC_DMA_NAME(__short_size)				\
> +	KMALLOC_RANDOM_NAME(CONFIG_RANDOM_KMALLOC_CACHES_NR, __short_size)	\
>  	.size = __size,						\
>  }
>  
> @@ -878,6 +916,11 @@ new_kmalloc_cache(int idx, enum kmalloc_cache_type type, slab_flags_t flags)
>  		flags |= SLAB_CACHE_DMA;
>  	}
>  
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +	if (type >= KMALLOC_RANDOM_START && type <= KMALLOC_RANDOM_END)
> +		flags |= SLAB_RANDOMSLAB;
> +#endif
> +
>  	kmalloc_caches[type][idx] = create_kmalloc_cache(
>  					kmalloc_info[idx].name[type],
>  					kmalloc_info[idx].size, flags, 0,
> @@ -904,7 +947,7 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>  	/*
>  	 * Including KMALLOC_CGROUP if CONFIG_MEMCG_KMEM defined
>  	 */
> -	for (type = KMALLOC_NORMAL; type < NR_KMALLOC_TYPES; type++) {
> +	for (type = KMALLOC_RANDOM_START; type < NR_KMALLOC_TYPES; type++) {
>  		for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++) {
>  			if (!kmalloc_caches[type][i])
>  				new_kmalloc_cache(i, type, flags);
> @@ -922,6 +965,9 @@ void __init create_kmalloc_caches(slab_flags_t flags)
>  				new_kmalloc_cache(2, type, flags);
>  		}
>  	}
> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> +	random_kmalloc_seed = get_random_u64();
> +#endif
>  
>  	/* Kmalloc array is now usable */
>  	slab_state = UP;
> @@ -957,7 +1003,7 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller
>  		return ret;
>  	}
>  
> -	s = kmalloc_slab(size, flags);
> +	s = kmalloc_slab(size, flags, caller);
>  
>  	if (unlikely(ZERO_OR_NULL_PTR(s)))
>  		return s;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1b270263-f457-e23b-e744-322a010d2a66%40huawei.com.
