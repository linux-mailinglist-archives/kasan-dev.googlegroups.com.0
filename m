Return-Path: <kasan-dev+bncBAABB7WU4KRAMGQE3KBCDLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id B89916FA19A
	for <lists+kasan-dev@lfdr.de>; Mon,  8 May 2023 09:53:35 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id a1e0cc1a2514c-77ab850888bsf1284344241.3
        for <lists+kasan-dev@lfdr.de>; Mon, 08 May 2023 00:53:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683532414; cv=pass;
        d=google.com; s=arc-20160816;
        b=iEhY3Yzlc5aqD6/kDLCcGnqnUzr/YTOCR4tAUH2LBlLVrrg2kHqmtPiSUfWZL7PcO8
         p1NBbiyQwj3y6BUh3cuQ5/CAO3A5PwxxtCMpwtonk1OvbFKpnJFNsuEJOPxVLxpQnmVz
         GMMbLiSaLrEW13gHron5y350Z7/3lZVyVK4LTtQ3laYYqZelFqj/cJiHITINw8Zo3QEZ
         UIuaYZ4SMmNMZgG/eusYJ7VBekdQ5fwR3jZcJanDK0CN/NJmFIk/BzHAzvgALGA483tA
         e7q1hfmGDBNKJTDnXRBapde+7xOV78EDMLGKJHxItPTj1jwpXWMNZcdMymiq6LtSUyJ7
         QjGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=LmOdVHYfLYtx7nvvEp5odBo4Sd8vhATB19yBLldahZg=;
        b=wxlijd1bxuZz4tCoSPc7v6ZUucQ4H6Pau0vE70p0z880dcKpb3t5k4OI9ZOKvVI0JL
         6Wqj8eoPSXIuK39tl+smMiJgaFwYXKr0YOo+AklfxX9f8DJm9CL5h/NzV4QpVLsMi6kV
         XNdCWOcHNBJrgdgU1arhA2/KMFdJoFGYDhdyhUuLrosxHzKmhqXXoU0XdA8YhogCroYi
         f3po2HryPU//wa33/acFxqInHDaWeLJlYjjMvLhyZqRBjxMh7uftSdQ3VB+5kH9cMdoZ
         YNV3Jp/X7vsmvJ1sGlu1sDjSRvwyXb//Abcep29mDc6Vb2oBUhFzsl/NWNmkxBslnUD3
         iUWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683532414; x=1686124414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LmOdVHYfLYtx7nvvEp5odBo4Sd8vhATB19yBLldahZg=;
        b=HGn3TLpBg5t9wRH8E6U2TfSnCkIrxFX0oNLeQvIAwJvOdIUISuUFqSGDXsZFCgTXal
         HtC+Lm1PCdv1Mw7gUlpvlr0XnuHfVophqzc++FqKw1sFrIqyNGYjidKMnsNF03V9G2CY
         S7PDNqrQjK2cCMwlfNVmuWDz/4Fx2S7vUt9O1vOyyaDDWwiLxw6PkanNBRecxpMQTVSO
         r/OetdGeoboR/wbrcKgr9PblOxE1b0IMF7b3pm0BjESqICHzNwDIhW7mJzYRJbna/3vQ
         M+b4kDE+PW4Bi+mFHoncOtd6feO/KyuMejATara1iouly3WcNMLWcWTjq7HccVmYgZzT
         HR0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683532414; x=1686124414;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LmOdVHYfLYtx7nvvEp5odBo4Sd8vhATB19yBLldahZg=;
        b=QGJf4QCSxknEP5LkiS004ywF0BKqWb45jUb8Lbt5NFRNGosni0MP8fZxPbg9TpauIO
         4jhxNF8/eiFXmi+ftQEohbgr+TU7U1aR+Hl4NC/DPTdM8zXSHoy8l7FWnrr5jJzd9Mv0
         KS5SeuwbbwDb459EzrpzfU2cANkH8Kt0aG0Nf7A7KVPgIAbo49kwxM8/0DGBHbTGLd9X
         Sjf6cpjnPnUAQNdFYQOBjpBZlcXzc6bb0+cHRzsoDFmXL9OLV75BM+gz9Kq+dAKdrff8
         BacYR0ssZKn0gPriur7+0MW25XmBMjGfWcTg77UJ/u+7YAXsl6wHiHVRckwDjJKIoCJY
         3uZA==
X-Gm-Message-State: AC+VfDyRv3qtpZPP3gtA2q+iFfSB4Z+qOmc7gBQJQOLsYXG5kYlfHyB2
	OWPN3nd2FvsIScfjrywM8/Q=
X-Google-Smtp-Source: ACHHUZ4+MLy5rXcET1jUPoD5VZQMBHDQVr3SRBHeIx1PFlu1fB82DiEAWuF3pZCnZphBpK0LawtPlQ==
X-Received: by 2002:a9f:3319:0:b0:772:5:5398 with SMTP id o25-20020a9f3319000000b0077200055398mr4858709uab.2.1683532414375;
        Mon, 08 May 2023 00:53:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:b0f:b0:432:7210:88cd with SMTP id
 b15-20020a0561020b0f00b00432721088cdls6628719vst.7.-pod-prod-gmail; Mon, 08
 May 2023 00:53:33 -0700 (PDT)
X-Received: by 2002:a67:f6c5:0:b0:434:7238:995c with SMTP id v5-20020a67f6c5000000b004347238995cmr2898536vso.16.1683532413713;
        Mon, 08 May 2023 00:53:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683532413; cv=none;
        d=google.com; s=arc-20160816;
        b=N6rfSmsWuBpRQvjtVO/JkXNywyN4IslqyJ1ncfvKUuuq+pRyF+WrWQMgPQTVBIqqJ9
         E3UM48nS3sbWGLsKS9JwB5SPW+AT0oZ2D2hFqxuHLmVsidA2eM+DA+6imwH0fTbNoooY
         +Hbz//pidqYQpe6CXj1iBkn4HMIvNjGkrQUSeitQczvu4BbVOoae6XzuSsi6B2YpuubE
         Ni/7DPvy3FPWsKFXaviLGVdwtcMM7coE6o2cZ1jvfjjl44EVvtTYMmfdpiu8yO+JmL0d
         ubEpF4EJH/9Vo6qSanzUNoLIc1RAmkKpcgDCJNTc13yjIp/MOmwg8L9kvCF3FCsLkYs0
         HflQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=KBB5vrcaY3TtwnchNCw5D74eakZOATrEFtun0MVW1NE=;
        b=JZ3jVteltoXbKO0nQaK5LViWPhsiBacLINnpvt6DyBiFvAfElphiLu74Avp4cvzTQl
         J4KZqNoAK4jzqSGYGw1oCLtO+EAwm2PbJ68HwwX+yv+P2kbQd3CpFVukKBegG3K3htJe
         IppJq3ZQGu2/McVJYIcwtyMcHlGfsJLIJ+BCYk3QpN6l01rTIEXlbY8s5cKJX5MC8vdY
         xJ1w7wZ09su+JC9+JZfA4KW6Mo5pXbI4xO/gkXOs52nVpHPxESVWT5U/AuAWzOfQS57v
         VDS28bGY5elF5v/+F+rGjN+tyvrouN7MjRFHDbZRzEYX+kFfOgfOmhdiOT8TanGa5pCz
         YYOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga01-in.huawei.com (szxga01-in.huawei.com. [45.249.212.187])
        by gmr-mx.google.com with ESMTPS id e13-20020a0561020f8d00b00434547639dasi510743vsv.0.2023.05.08.00.53.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 May 2023 00:53:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as permitted sender) client-ip=45.249.212.187;
Received: from dggpemm500016.china.huawei.com (unknown [172.30.72.53])
	by szxga01-in.huawei.com (SkyGuard) with ESMTP id 4QFD1t5KvFzpT0j;
	Mon,  8 May 2023 15:48:50 +0800 (CST)
Received: from huawei.com (10.67.174.33) by dggpemm500016.china.huawei.com
 (7.185.36.25) with Microsoft SMTP Server (version=TLS1_2,
 cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id 15.1.2507.23; Mon, 8 May
 2023 15:52:59 +0800
From: "'GONG, Ruiqi' via kasan-dev" <kasan-dev@googlegroups.com>
To: <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
	<linux-hardening@vger.kernel.org>
CC: Hyeonggon Yoo <42.hyeyoo@gmail.com>, Alexander Lobakin
	<aleksander.lobakin@intel.com>, <kasan-dev@googlegroups.com>, Wang Weiyang
	<wangweiyang2@huawei.com>, Xiu Jianfeng <xiujianfeng@huawei.com>
Subject: [PATCH RFC v2] Randomized slab caches for kmalloc()
Date: Mon, 8 May 2023 15:55:07 +0800
Message-ID: <20230508075507.1720950-1-gongruiqi1@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.67.174.33]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
 dggpemm500016.china.huawei.com (7.185.36.25)
X-CFilter-Loop: Reflected
X-Original-Sender: gongruiqi1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of gongruiqi1@huawei.com designates 45.249.212.187 as
 permitted sender) smtp.mailfrom=gongruiqi1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: "GONG, Ruiqi" <gongruiqi1@huawei.com>
Reply-To: "GONG, Ruiqi" <gongruiqi1@huawei.com>
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

When exploiting memory vulnerabilities, "heap spraying" is a common
technique targeting those related to dynamic memory allocation (i.e. the
"heap"), and it plays an important role in a successful exploitation.
Basically, it is to overwrite the memory area of vulnerable object by
triggering allocation in other subsystems or modules and therefore
getting a reference to the targeted memory location. It's usable on
various types of vulnerablity including use after free (UAF), heap out-
of-bound write and etc.

There are (at least) two reasons why the heap can be sprayed: 1) generic
slab caches are shared among different subsystems and modules, and
2) dedicated slab caches could be merged with the generic ones.
Currently these two factors cannot be prevented at a low cost: the first
one is a widely used memory allocation mechanism, and shutting down slab
merging completely via `slub_nomerge` would be overkill.

To efficiently prevent heap spraying, we propose the following approach:
to create multiple copies of generic slab caches that will never be
merged, and random one of them will be used at allocation. The random
selection is based on the address of code that calls `kmalloc()`, which
means it is static at runtime (rather than dynamically determined at
each time of allocation, which could be bypassed by repeatedly spraying
in brute force). In this way, the vulnerable object and memory allocated
in other subsystems and modules will (most probably) be on different
slab caches, which prevents the object from being sprayed.

The overhead of performance has been tested on a 40-core x86 server by
comparing the results of `perf bench all` between the kernels with and
without this patch based on the latest linux-next kernel, which shows
minor difference. A subset of benchmarks are listed below:

			control		experiment (avg of 3 samples)
sched/messaging (sec)	0.019		0.019
sched/pipe (sec)	5.253		5.340
syscall/basic (sec)	0.741		0.742
mem/memcpy (GB/sec)	15.258789	14.860495
mem/memset (GB/sec)	48.828125	50.431069

The overhead of memory usage was measured by executing `free` after boot
on a QEMU VM with 1GB total memory, and as expected, it's positively
correlated with # of cache copies:

		control		4 copies	8 copies	16 copies
total		969.8M		968.2M		968.2M		968.2M
used		20.0M		21.9M		24.1M		26.7M
free		936.9M		933.6M		931.4M		928.6M
available	932.2M		928.8M		926.6M		923.9M

Signed-off-by: GONG, Ruiqi <gongruiqi1@huawei.com>
---

v2:
  - Use hash_64() and a per-boot random seed to select kmalloc() caches.
  - Change acceptable # of caches from [4,16] to {2,4,8,16}, which is
more compatible with hashing.
  - Supplement results of performance and memory overhead tests.

 include/linux/percpu.h  | 12 ++++++---
 include/linux/slab.h    | 25 +++++++++++++++---
 mm/Kconfig              | 49 ++++++++++++++++++++++++++++++++++++
 mm/kfence/kfence_test.c |  4 +--
 mm/slab.c               |  2 +-
 mm/slab.h               |  3 ++-
 mm/slab_common.c        | 56 +++++++++++++++++++++++++++++++++++++----
 7 files changed, 135 insertions(+), 16 deletions(-)

diff --git a/include/linux/percpu.h b/include/linux/percpu.h
index 1338ea2aa720..6cee6425951f 100644
--- a/include/linux/percpu.h
+++ b/include/linux/percpu.h
@@ -34,6 +34,12 @@
 #define PCPU_BITMAP_BLOCK_BITS		(PCPU_BITMAP_BLOCK_SIZE >>	\
 					 PCPU_MIN_ALLOC_SHIFT)
 
+#ifdef CONFIG_RANDOM_KMALLOC_CACHES
+#define PERCPU_DYNAMIC_SIZE_SHIFT      13
+#else
+#define PERCPU_DYNAMIC_SIZE_SHIFT      10
+#endif
+
 /*
  * Percpu allocator can serve percpu allocations before slab is
  * initialized which allows slab to depend on the percpu allocator.
@@ -41,7 +47,7 @@
  * for this.  Keep PERCPU_DYNAMIC_RESERVE equal to or larger than
  * PERCPU_DYNAMIC_EARLY_SIZE.
  */
-#define PERCPU_DYNAMIC_EARLY_SIZE	(20 << 10)
+#define PERCPU_DYNAMIC_EARLY_SIZE	(20 << PERCPU_DYNAMIC_SIZE_SHIFT)
 
 /*
  * PERCPU_DYNAMIC_RESERVE indicates the amount of free area to piggy
@@ -55,9 +61,9 @@
  * intelligent way to determine this would be nice.
  */
 #if BITS_PER_LONG > 32
-#define PERCPU_DYNAMIC_RESERVE		(28 << 10)
+#define PERCPU_DYNAMIC_RESERVE		(28 << PERCPU_DYNAMIC_SIZE_SHIFT)
 #else
-#define PERCPU_DYNAMIC_RESERVE		(20 << 10)
+#define PERCPU_DYNAMIC_RESERVE		(20 << PERCPU_DYNAMIC_SIZE_SHIFT)
 #endif
 
 extern void *pcpu_base_addr;
diff --git a/include/linux/slab.h b/include/linux/slab.h
index 6b3e155b70bf..939c41c20600 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -18,6 +18,9 @@
 #include <linux/workqueue.h>
 #include <linux/percpu-refcount.h>
 
+#ifdef CONFIG_RANDOM_KMALLOC_CACHES
+#include <linux/hash.h>
+#endif
 
 /*
  * Flags to pass to kmem_cache_create().
@@ -106,6 +109,12 @@
 /* Avoid kmemleak tracing */
 #define SLAB_NOLEAKTRACE	((slab_flags_t __force)0x00800000U)
 
+#ifdef CONFIG_RANDOM_KMALLOC_CACHES
+# define SLAB_RANDOMSLAB	((slab_flags_t __force)0x01000000U)
+#else
+# define SLAB_RANDOMSLAB	0
+#endif
+
 /* Fault injection mark */
 #ifdef CONFIG_FAILSLAB
 # define SLAB_FAILSLAB		((slab_flags_t __force)0x02000000U)
@@ -331,7 +340,9 @@ static inline unsigned int arch_slab_minalign(void)
  * kmem caches can have both accounted and unaccounted objects.
  */
 enum kmalloc_cache_type {
-	KMALLOC_NORMAL = 0,
+	KMALLOC_RANDOM_START = 0,
+	KMALLOC_RANDOM_END = KMALLOC_RANDOM_START + CONFIG_RANDOM_KMALLOC_CACHES_NR - 1,
+	KMALLOC_NORMAL = KMALLOC_RANDOM_END,
 #ifndef CONFIG_ZONE_DMA
 	KMALLOC_DMA = KMALLOC_NORMAL,
 #endif
@@ -363,14 +374,20 @@ kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1];
 	(IS_ENABLED(CONFIG_ZONE_DMA)   ? __GFP_DMA : 0) |	\
 	(IS_ENABLED(CONFIG_MEMCG_KMEM) ? __GFP_ACCOUNT : 0))
 
-static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags)
+extern unsigned long random_kmalloc_seed;
+
+static __always_inline enum kmalloc_cache_type kmalloc_type(gfp_t flags, unsigned long caller)
 {
 	/*
 	 * The most common case is KMALLOC_NORMAL, so test for it
 	 * with a single branch for all the relevant flags.
 	 */
 	if (likely((flags & KMALLOC_NOT_NORMAL_BITS) == 0))
+#ifdef CONFIG_RANDOM_KMALLOC_CACHES
+		return KMALLOC_RANDOM_START + hash_64(caller ^ random_kmalloc_seed, CONFIG_RANDOM_KMALLOC_CACHES_BITS);
+#else
 		return KMALLOC_NORMAL;
+#endif
 
 	/*
 	 * At least one of the flags has to be set. Their priorities in
@@ -557,7 +574,7 @@ static __always_inline __alloc_size(1) void *kmalloc(size_t size, gfp_t flags)
 
 		index = kmalloc_index(size);
 		return kmalloc_trace(
-				kmalloc_caches[kmalloc_type(flags)][index],
+				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
 				flags, size);
 	}
 	return __kmalloc(size, flags);
@@ -573,7 +590,7 @@ static __always_inline __alloc_size(1) void *kmalloc_node(size_t size, gfp_t fla
 
 		index = kmalloc_index(size);
 		return kmalloc_node_trace(
-				kmalloc_caches[kmalloc_type(flags)][index],
+				kmalloc_caches[kmalloc_type(flags, _RET_IP_)][index],
 				flags, node, size);
 	}
 	return __kmalloc_node(size, flags, node);
diff --git a/mm/Kconfig b/mm/Kconfig
index 7672a22647b4..e868da87d9cd 100644
--- a/mm/Kconfig
+++ b/mm/Kconfig
@@ -311,6 +311,55 @@ config SLUB_CPU_PARTIAL
 	  which requires the taking of locks that may cause latency spikes.
 	  Typically one would choose no for a realtime system.
 
+config RANDOM_KMALLOC_CACHES
+	default n
+	depends on SLUB
+	bool "Random slab caches for normal kmalloc"
+	help
+	  A hardening feature that creates multiple copies of slab caches for
+	  normal kmalloc allocation and makes kmalloc randomly pick one based
+	  on code address, which makes the attackers unable to spray vulnerable
+	  memory objects on the heap for exploiting memory vulnerabilities.
+
+choice
+	prompt "Number of random slab caches copies"
+	depends on RANDOM_KMALLOC_CACHES
+	default RANDOM_KMALLOC_CACHES_16
+	help
+	  The number of copies of random slab caches. Bigger value makes the
+	  potentially vulnerable memory object less likely to collide with
+	  objects allocated from other subsystems or modules.
+
+config RANDOM_KMALLOC_CACHES_2
+	bool "2"
+
+config RANDOM_KMALLOC_CACHES_4
+	bool "4"
+
+config RANDOM_KMALLOC_CACHES_8
+	bool "8"
+
+config RANDOM_KMALLOC_CACHES_16
+	bool "16"
+
+endchoice
+
+config RANDOM_KMALLOC_CACHES_BITS
+	int
+	default 0 if !RANDOM_KMALLOC_CACHES
+	default 1 if RANDOM_KMALLOC_CACHES_2
+	default 2 if RANDOM_KMALLOC_CACHES_4
+	default 3 if RANDOM_KMALLOC_CACHES_8
+	default 4 if RANDOM_KMALLOC_CACHES_16
+
+config RANDOM_KMALLOC_CACHES_NR
+	int
+	default 1 if !RANDOM_KMALLOC_CACHES
+	default 2 if RANDOM_KMALLOC_CACHES_2
+	default 4 if RANDOM_KMALLOC_CACHES_4
+	default 8 if RANDOM_KMALLOC_CACHES_8
+	default 16 if RANDOM_KMALLOC_CACHES_16
+
 endmenu # SLAB allocator options
 
 config SHUFFLE_PAGE_ALLOCATOR
diff --git a/mm/kfence/kfence_test.c b/mm/kfence/kfence_test.c
index 6aee19a79236..8a95ef649d5e 100644
--- a/mm/kfence/kfence_test.c
+++ b/mm/kfence/kfence_test.c
@@ -213,7 +213,7 @@ static void test_cache_destroy(void)
 
 static inline size_t kmalloc_cache_alignment(size_t size)
 {
-	return kmalloc_caches[kmalloc_type(GFP_KERNEL)][__kmalloc_index(size, false)]->align;
+	return kmalloc_caches[kmalloc_type(GFP_KERNEL, _RET_IP_)][__kmalloc_index(size, false)]->align;
 }
 
 /* Must always inline to match stack trace against caller. */
@@ -284,7 +284,7 @@ static void *test_alloc(struct kunit *test, size_t size, gfp_t gfp, enum allocat
 		if (is_kfence_address(alloc)) {
 			struct slab *slab = virt_to_slab(alloc);
 			struct kmem_cache *s = test_cache ?:
-					kmalloc_caches[kmalloc_type(GFP_KERNEL)][__kmalloc_index(size, false)];
+					kmalloc_caches[kmalloc_type(GFP_KERNEL, _RET_IP_)][__kmalloc_index(size, false)];
 
 			/*
 			 * Verify that various helpers return the right values
diff --git a/mm/slab.c b/mm/slab.c
index bb57f7fdbae1..82e2a8d4cd9d 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -1674,7 +1674,7 @@ static size_t calculate_slab_order(struct kmem_cache *cachep,
 			if (freelist_size > KMALLOC_MAX_CACHE_SIZE) {
 				freelist_cache_size = PAGE_SIZE << get_order(freelist_size);
 			} else {
-				freelist_cache = kmalloc_slab(freelist_size, 0u);
+				freelist_cache = kmalloc_slab(freelist_size, 0u, _RET_IP_);
 				if (!freelist_cache)
 					continue;
 				freelist_cache_size = freelist_cache->size;
diff --git a/mm/slab.h b/mm/slab.h
index f01ac256a8f5..1e484af71c52 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -243,7 +243,7 @@ void setup_kmalloc_cache_index_table(void);
 void create_kmalloc_caches(slab_flags_t);
 
 /* Find the kmalloc slab corresponding for a certain size */
-struct kmem_cache *kmalloc_slab(size_t, gfp_t);
+struct kmem_cache *kmalloc_slab(size_t, gfp_t, unsigned long);
 
 void *__kmem_cache_alloc_node(struct kmem_cache *s, gfp_t gfpflags,
 			      int node, size_t orig_size,
@@ -319,6 +319,7 @@ static inline bool is_kmalloc_cache(struct kmem_cache *s)
 			      SLAB_TEMPORARY | \
 			      SLAB_ACCOUNT | \
 			      SLAB_KMALLOC | \
+			      SLAB_RANDOMSLAB | \
 			      SLAB_NO_USER_FLAGS)
 
 bool __kmem_cache_empty(struct kmem_cache *);
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 607249785c07..70899b20a9a7 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -47,6 +47,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
  */
 #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
 		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
+		SLAB_RANDOMSLAB | \
 		SLAB_FAILSLAB | kasan_never_merge())
 
 #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
@@ -679,6 +680,11 @@ kmalloc_caches[NR_KMALLOC_TYPES][KMALLOC_SHIFT_HIGH + 1] __ro_after_init =
 { /* initialization for https://bugs.llvm.org/show_bug.cgi?id=42570 */ };
 EXPORT_SYMBOL(kmalloc_caches);
 
+#ifdef CONFIG_RANDOM_KMALLOC_CACHES
+unsigned long random_kmalloc_seed __ro_after_init;
+EXPORT_SYMBOL(random_kmalloc_seed);
+#endif
+
 /*
  * Conversion table for small slabs sizes / 8 to the index in the
  * kmalloc array. This is necessary for slabs < 192 since we have non power
@@ -721,7 +727,7 @@ static inline unsigned int size_index_elem(unsigned int bytes)
  * Find the kmem_cache structure that serves a given size of
  * allocation
  */
-struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
+struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags, unsigned long caller)
 {
 	unsigned int index;
 
@@ -736,7 +742,7 @@ struct kmem_cache *kmalloc_slab(size_t size, gfp_t flags)
 		index = fls(size - 1);
 	}
 
-	return kmalloc_caches[kmalloc_type(flags)][index];
+	return kmalloc_caches[kmalloc_type(flags, caller)][index];
 }
 
 size_t kmalloc_size_roundup(size_t size)
@@ -754,7 +760,7 @@ size_t kmalloc_size_roundup(size_t size)
 		return PAGE_SIZE << get_order(size);
 
 	/* The flags don't matter since size_index is common to all. */
-	c = kmalloc_slab(size, GFP_KERNEL);
+	c = kmalloc_slab(size, GFP_KERNEL, _RET_IP_);
 	return c ? c->object_size : 0;
 }
 EXPORT_SYMBOL(kmalloc_size_roundup);
@@ -777,12 +783,44 @@ EXPORT_SYMBOL(kmalloc_size_roundup);
 #define KMALLOC_RCL_NAME(sz)
 #endif
 
+#ifdef CONFIG_RANDOM_KMALLOC_CACHES
+#define __KMALLOC_RANDOM_CONCAT(a, b, c) a ## b ## c
+#define KMALLOC_RANDOM_NAME(N, sz) __KMALLOC_RANDOM_CONCAT(KMALLOC_RANDOM_, N, _NAME)(sz)
+#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 1
+#define KMALLOC_RANDOM_1_NAME(sz)                             .name[KMALLOC_RANDOM_START +  0] = "kmalloc-random-01-" #sz,
+#define KMALLOC_RANDOM_2_NAME(sz)  KMALLOC_RANDOM_1_NAME(sz)  .name[KMALLOC_RANDOM_START +  1] = "kmalloc-random-02-" #sz,
+#endif
+#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 2
+#define KMALLOC_RANDOM_3_NAME(sz)  KMALLOC_RANDOM_2_NAME(sz)  .name[KMALLOC_RANDOM_START +  2] = "kmalloc-random-03-" #sz,
+#define KMALLOC_RANDOM_4_NAME(sz)  KMALLOC_RANDOM_3_NAME(sz)  .name[KMALLOC_RANDOM_START +  3] = "kmalloc-random-04-" #sz,
+#endif
+#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 3
+#define KMALLOC_RANDOM_5_NAME(sz)  KMALLOC_RANDOM_4_NAME(sz)  .name[KMALLOC_RANDOM_START +  4] = "kmalloc-random-05-" #sz,
+#define KMALLOC_RANDOM_6_NAME(sz)  KMALLOC_RANDOM_5_NAME(sz)  .name[KMALLOC_RANDOM_START +  5] = "kmalloc-random-06-" #sz,
+#define KMALLOC_RANDOM_7_NAME(sz)  KMALLOC_RANDOM_6_NAME(sz)  .name[KMALLOC_RANDOM_START +  6] = "kmalloc-random-07-" #sz,
+#define KMALLOC_RANDOM_8_NAME(sz)  KMALLOC_RANDOM_7_NAME(sz)  .name[KMALLOC_RANDOM_START +  7] = "kmalloc-random-08-" #sz,
+#endif
+#if CONFIG_RANDOM_KMALLOC_CACHES_BITS >= 4
+#define KMALLOC_RANDOM_9_NAME(sz)  KMALLOC_RANDOM_8_NAME(sz)  .name[KMALLOC_RANDOM_START +  8] = "kmalloc-random-09-" #sz,
+#define KMALLOC_RANDOM_10_NAME(sz) KMALLOC_RANDOM_9_NAME(sz)  .name[KMALLOC_RANDOM_START +  9] = "kmalloc-random-10-" #sz,
+#define KMALLOC_RANDOM_11_NAME(sz) KMALLOC_RANDOM_10_NAME(sz) .name[KMALLOC_RANDOM_START + 10] = "kmalloc-random-11-" #sz,
+#define KMALLOC_RANDOM_12_NAME(sz) KMALLOC_RANDOM_11_NAME(sz) .name[KMALLOC_RANDOM_START + 11] = "kmalloc-random-12-" #sz,
+#define KMALLOC_RANDOM_13_NAME(sz) KMALLOC_RANDOM_12_NAME(sz) .name[KMALLOC_RANDOM_START + 12] = "kmalloc-random-13-" #sz,
+#define KMALLOC_RANDOM_14_NAME(sz) KMALLOC_RANDOM_13_NAME(sz) .name[KMALLOC_RANDOM_START + 13] = "kmalloc-random-14-" #sz,
+#define KMALLOC_RANDOM_15_NAME(sz) KMALLOC_RANDOM_14_NAME(sz) .name[KMALLOC_RANDOM_START + 14] = "kmalloc-random-15-" #sz,
+#define KMALLOC_RANDOM_16_NAME(sz) KMALLOC_RANDOM_15_NAME(sz) .name[KMALLOC_RANDOM_START + 15] = "kmalloc-random-16-" #sz,
+#endif
+#else // CONFIG_RANDOM_KMALLOC_CACHES
+#define KMALLOC_RANDOM_NAME(N, sz)
+#endif
+
 #define INIT_KMALLOC_INFO(__size, __short_size)			\
 {								\
 	.name[KMALLOC_NORMAL]  = "kmalloc-" #__short_size,	\
 	KMALLOC_RCL_NAME(__short_size)				\
 	KMALLOC_CGROUP_NAME(__short_size)			\
 	KMALLOC_DMA_NAME(__short_size)				\
+	KMALLOC_RANDOM_NAME(CONFIG_RANDOM_KMALLOC_CACHES_NR, __short_size)	\
 	.size = __size,						\
 }
 
@@ -878,6 +916,11 @@ new_kmalloc_cache(int idx, enum kmalloc_cache_type type, slab_flags_t flags)
 		flags |= SLAB_CACHE_DMA;
 	}
 
+#ifdef CONFIG_RANDOM_KMALLOC_CACHES
+	if (type >= KMALLOC_RANDOM_START && type <= KMALLOC_RANDOM_END)
+		flags |= SLAB_RANDOMSLAB;
+#endif
+
 	kmalloc_caches[type][idx] = create_kmalloc_cache(
 					kmalloc_info[idx].name[type],
 					kmalloc_info[idx].size, flags, 0,
@@ -904,7 +947,7 @@ void __init create_kmalloc_caches(slab_flags_t flags)
 	/*
 	 * Including KMALLOC_CGROUP if CONFIG_MEMCG_KMEM defined
 	 */
-	for (type = KMALLOC_NORMAL; type < NR_KMALLOC_TYPES; type++) {
+	for (type = KMALLOC_RANDOM_START; type < NR_KMALLOC_TYPES; type++) {
 		for (i = KMALLOC_SHIFT_LOW; i <= KMALLOC_SHIFT_HIGH; i++) {
 			if (!kmalloc_caches[type][i])
 				new_kmalloc_cache(i, type, flags);
@@ -922,6 +965,9 @@ void __init create_kmalloc_caches(slab_flags_t flags)
 				new_kmalloc_cache(2, type, flags);
 		}
 	}
+#ifdef CONFIG_RANDOM_KMALLOC_CACHES
+	random_kmalloc_seed = get_random_u64();
+#endif
 
 	/* Kmalloc array is now usable */
 	slab_state = UP;
@@ -957,7 +1003,7 @@ void *__do_kmalloc_node(size_t size, gfp_t flags, int node, unsigned long caller
 		return ret;
 	}
 
-	s = kmalloc_slab(size, flags);
+	s = kmalloc_slab(size, flags, caller);
 
 	if (unlikely(ZERO_OR_NULL_PTR(s)))
 		return s;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230508075507.1720950-1-gongruiqi1%40huawei.com.
