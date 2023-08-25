Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBWFTUSTQMGQEOTKJS6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F8C5789041
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Aug 2023 23:15:06 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-51dd0857366sf6239a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Aug 2023 14:15:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1692998106; cv=pass;
        d=google.com; s=arc-20160816;
        b=wRBw2WvN20KmdlV7wRBaZi7RgeMqyPW37GMSColZslMYWL96ep0WYvC01JfVNO61Ae
         +cO89fDgRxUi90ggGJQqwDq3k/p6NplxXOV83ZmV18QXv/aYUPpPG8Hy2Us5QBw92Fgo
         tSW/vkzkNofomkXRXVsvEECJj+dtpD68WSU9hEtUyzW1tWynU9rP3NLbz018rYQUIS9r
         RRP0VGsbK0e3nyEbIqVLT35Sa2n9M1Rh3c95pevixFI7tDLsNFZYHCS4zXsUjnbgyGKC
         vOpFFGupFRPgpgCrZo9lina6kQbzAAdzg5Ly7H0V1mC3CP/bQHHqJ/kkEZSfAKPMiMe8
         d14A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=uZ/dMIjnZxyPfCT6x/+O6e3DGNv4C5SIohnol5F3eL8=;
        fh=YCwm8ypGo7+l3Q4v2+fQcrI1Tsl2uKPQMHTrOPFZgnI=;
        b=KEQvlhKaft8hwpimo4FpJoqx5MDFrUVtVDGi10FGsYagLPBT7XoX1hoNXTVqEQRug4
         vbnjqghfO+Y8oj8TLEveEq12VdrTV/6sZbkTbDFc+QXfFlWrZYrD3ERsQdVCHec62PLS
         aBS7LXdSYmSV0nkAldvZFs7tjvmpzFUU4bNumZTY5SEiideCDm6VOV+2hVjZRj9HnYQX
         7VDyFsiYUV0DPuE+1mO8AEnOgrVQTXWv0wVo+aNYzTfF4Km84jF5m7gbyl3HgObfkpab
         HQFhxM0LlbMsxXd91v22JX02GgVNvhe/hXeBDuu8nJmtrZk8imfluokX1t7flwlZBrC6
         Nkqw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=NJAmiIu4;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1692998106; x=1693602906; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:from:to:cc:subject:date
         :message-id:reply-to;
        bh=uZ/dMIjnZxyPfCT6x/+O6e3DGNv4C5SIohnol5F3eL8=;
        b=BQA1VXRRTAkDMCzAyIGLPi/bDgFBO050s//01+gBmXUCUZCBCXkLWy4jNQd9aURU3y
         aJNF1ZCwDRABQUDtYOhd6r/Zoz/a9NGZsbHqGRxqOTAhtSmRd3t9F0ZAoee/pbJZSAqw
         vopu3ts9SafTuqr5mzooU+Se0PWJGHaCRymrJq0bIti6+TiCYf6QAgic4RUWefrbYk5O
         0c/kHqTtP+PsUbeD2ENTHLrMWJOuB9T0mn2ToTmF7IUoePuoZoSqZMZCB/eZI0lET+5C
         vgBRwHn9tzIaNExRDz9DX3iWy7WDaPwm55/eNsKA58F7MvWm/R7pC9OUk8UZRo5qlhGi
         FxMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1692998106; x=1693602906;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=uZ/dMIjnZxyPfCT6x/+O6e3DGNv4C5SIohnol5F3eL8=;
        b=ANRFdKX8++OSQ7gpzkj3JScQoJIFNSqDgbP4a7IDKPDNu9zaw63Xjw+OJFSfGL8xvP
         k/SSwGC1m/lFTN88ONfAuwUWzaqbyGHVsz7I/d9S1+y7qbsISsyA14V2RHjy8rvEgQ+A
         B5n890/4nXLsA5D9Gvjq4zyrpnQyr7IF7Tay5yvMD0+g5KM6C5Aphn/abOVGylirMsOt
         Y40nslQNmmv/V2pCNaE7WaMf14KjKuzSylZC3/QRTh646hQ84TZQMngnN7ZTIu4Gvz/2
         uYfqHH9Szz6Z1ZOk6I8NSxx22dUWcZUcHJ/P8uyV1QwZPSmGYrw+yWlKiEKTNstkEHWk
         3sHw==
X-Gm-Message-State: AOJu0YzECyBoHV97IxBM89OBKIHK6gyNQnwo2e5XEBx82/8+rERthUV4
	eC3i7oRYk9T50bnMXXdoOtU=
X-Google-Smtp-Source: AGHT+IFqXLO/5BewAOcqC+l597RuSlsHznjunA1FcBPQwbkyf/5aKNw/qGfudX//nQDS5DFc6XaIag==
X-Received: by 2002:a50:d742:0:b0:522:4741:d992 with SMTP id i2-20020a50d742000000b005224741d992mr80365edj.4.1692998105034;
        Fri, 25 Aug 2023 14:15:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:ba8:b0:2bc:da88:b686 with SMTP id
 bg40-20020a05651c0ba800b002bcda88b686ls411571ljb.0.-pod-prod-01-eu; Fri, 25
 Aug 2023 14:15:02 -0700 (PDT)
X-Received: by 2002:a2e:8717:0:b0:2bc:c11c:4471 with SMTP id m23-20020a2e8717000000b002bcc11c4471mr12590267lji.21.1692998102824;
        Fri, 25 Aug 2023 14:15:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1692998102; cv=none;
        d=google.com; s=arc-20160816;
        b=sxbYUHItP5xHISxG+toWW+m08C1qritctFjI63YJxl1S2B4DvR/VfbQNOcOoR4qeG8
         T8z2jF1NkAUsZ0wlLlXHF8nkRh0nc/VuFQYAAvZa1YOxyPzSQbgvoqNLHnLGo4vnWAez
         x6hB1b0LEWCMKx/aeRmwL4KqZRmMWwYass+LecrlW/tzi556H8/T1Om4MskyYyiva5oz
         yBYQTsLk4kaHtU3DaJZevZCj+CI3aoCuSUE35Cf7vEkwvp6yPSx9+w6WkKZO/RSCyt23
         0Bb2OD8btlmYgqUnzsTgl5gkJiB4VI1nCoaCQd/HwQBPjl37JLTl4t4TgNTXpil0lOJr
         LqLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=aPiiwNs7Vv+AACjowQ9IHJzrj9oQRfhXdiPEG1HBSek=;
        fh=YCwm8ypGo7+l3Q4v2+fQcrI1Tsl2uKPQMHTrOPFZgnI=;
        b=XyYrFmjhVnUKP2jVMYnqzI5PAhms7NAUAxXQcDSZ0VE4NxCoRn5ZpPVc/6OUkGooNZ
         zavCEcAhx/5YreK4XRwbhB/GmyeC2zfjjNywqcHHpLg9I9qUyWHgCIysXhT6OCeY3vre
         fydKgdliVOTCxau64JpAJdF2hB6DmSs3hFHpe9/L2P7fWcxuFNGf0MxQQjpjf7UrEGLr
         zkP+jNQV7PqtG+cAlTe/r5gxHtQICESgbB5QNBCK78a7mYOGNUe08ySkOMqikk7h4wMQ
         IuueQ25n096f1SjPML/9lQXz8bCEaflcXtC07Fi5eWB0FnTv7tN8fxa4Vizk/avHDqOD
         bPlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=NJAmiIu4;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id i25-20020a2ea379000000b002bcc064ac3asi169849ljn.7.2023.08.25.14.15.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Aug 2023 14:15:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id 4fb4d7f45d1cf-529fa243739so3857a12.0
        for <kasan-dev@googlegroups.com>; Fri, 25 Aug 2023 14:15:02 -0700 (PDT)
X-Received: by 2002:a50:d55c:0:b0:523:d5bc:8424 with SMTP id f28-20020a50d55c000000b00523d5bc8424mr27062edj.5.1692998101863;
        Fri, 25 Aug 2023 14:15:01 -0700 (PDT)
Received: from localhost ([2a00:79e0:9d:4:7803:f309:e9d9:478])
        by smtp.gmail.com with ESMTPSA id d7-20020adffd87000000b00317a04131c5sm3177620wrr.57.2023.08.25.14.15.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 25 Aug 2023 14:15:00 -0700 (PDT)
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Vlastimil Babka <vbabka@suse.cz>
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linux-hardening@vger.kernel.org,
	kernel-hardening@lists.openwall.com
Subject: [PATCH] slub: Introduce CONFIG_SLUB_RCU_DEBUG
Date: Fri, 25 Aug 2023 23:14:26 +0200
Message-ID: <20230825211426.3798691-1-jannh@google.com>
X-Mailer: git-send-email 2.42.0.rc1.204.g551eb34607-goog
MIME-Version: 1.0
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=NJAmiIu4;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::52e as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
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

Currently, KASAN is unable to catch use-after-free in SLAB_TYPESAFE_BY_RCU
slabs because use-after-free is allowed within the RCU grace period by
design.

Add a SLUB debugging feature which RCU-delays every individual
kmem_cache_free() before either actually freeing the object or handing it
off to KASAN, and change KASAN to poison freed objects as normal when this
option is enabled.

Note that this creates a 16-byte unpoisoned area in the middle of the
slab metadata area, which kinda sucks but seems to be necessary in order
to be able to store an rcu_head in there without triggering an ASAN
splat during RCU callback processing.

For now I've configured Kconfig.kasan to always enable this feature in the
GENERIC and SW_TAGS modes; I'm not forcibly enabling it in HW_TAGS mode
because I'm not sure if it might have unwanted performance degradation
effects there.

Signed-off-by: Jann Horn <jannh@google.com>
---
can I get a review from the KASAN folks of this?
I have been running it on my laptop for a bit and it seems to be working
fine.

Notes:
    With this patch, a UAF on a TYPESAFE_BY_RCU will splat with an error
    like this (tested by reverting a security bugfix).
    Note that, in the ASAN memory state dump, we can see the little
    unpoisoned 16-byte areas storing the rcu_head.
    
    BUG: KASAN: slab-use-after-free in folio_lock_anon_vma_read+0x129/0x4c0
    Read of size 8 at addr ffff888004e85b00 by task forkforkfork/592
    
    CPU: 0 PID: 592 Comm: forkforkfork Not tainted 6.5.0-rc7-00105-gae70c1e1f6f5-dirty #334
    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014
    Call Trace:
     <TASK>
     dump_stack_lvl+0x4a/0x80
     print_report+0xcf/0x660
     kasan_report+0xd4/0x110
     folio_lock_anon_vma_read+0x129/0x4c0
     rmap_walk_anon+0x1cc/0x290
     folio_referenced+0x277/0x2a0
     shrink_folio_list+0xb8c/0x1680
     reclaim_folio_list+0xdc/0x1f0
     reclaim_pages+0x211/0x280
     madvise_cold_or_pageout_pte_range+0x812/0xb70
     walk_pgd_range+0x70b/0xce0
     __walk_page_range+0x343/0x360
     walk_page_range+0x227/0x280
     madvise_pageout+0x1cd/0x2d0
     do_madvise+0x552/0x15a0
     __x64_sys_madvise+0x62/0x70
     do_syscall_64+0x3b/0x90
     entry_SYSCALL_64_after_hwframe+0x6e/0xd8
    [...]
     </TASK>
    
    Allocated by task 574:
     kasan_save_stack+0x33/0x60
     kasan_set_track+0x25/0x30
     __kasan_slab_alloc+0x6e/0x70
     kmem_cache_alloc+0xfd/0x2b0
     anon_vma_fork+0x88/0x270
     dup_mmap+0x87c/0xc10
     copy_process+0x3399/0x3590
     kernel_clone+0x10e/0x480
     __do_sys_clone+0xa1/0xe0
     do_syscall_64+0x3b/0x90
     entry_SYSCALL_64_after_hwframe+0x6e/0xd8
    
    Freed by task 0:
     kasan_save_stack+0x33/0x60
     kasan_set_track+0x25/0x30
     kasan_save_free_info+0x2b/0x50
     __kasan_slab_free+0xfe/0x180
     slab_free_after_rcu_debug+0xad/0x200
     rcu_core+0x638/0x1620
     __do_softirq+0x14c/0x581
    
    Last potentially related work creation:
     kasan_save_stack+0x33/0x60
     __kasan_record_aux_stack+0x94/0xa0
     __call_rcu_common.constprop.0+0x47/0x730
     __put_anon_vma+0x6e/0x150
     unlink_anon_vmas+0x277/0x2e0
     vma_complete+0x341/0x580
     vma_merge+0x613/0xff0
     mprotect_fixup+0x1c0/0x510
     do_mprotect_pkey+0x5a7/0x710
     __x64_sys_mprotect+0x47/0x60
     do_syscall_64+0x3b/0x90
     entry_SYSCALL_64_after_hwframe+0x6e/0xd8
    
    Second to last potentially related work creation:
    [...]
    
    The buggy address belongs to the object at ffff888004e85b00
     which belongs to the cache anon_vma of size 192
    The buggy address is located 0 bytes inside of
     freed 192-byte region [ffff888004e85b00, ffff888004e85bc0)
    
    The buggy address belongs to the physical page:
    [...]
    
    Memory state around the buggy address:
     ffff888004e85a00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
     ffff888004e85a80: 00 00 00 00 00 00 00 00 fc 00 00 fc fc fc fc fc
    >ffff888004e85b00: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                       ^
     ffff888004e85b80: fb fb fb fb fb fb fb fb fc 00 00 fc fc fc fc fc
     ffff888004e85c00: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb

 include/linux/kasan.h    |  6 ++++
 include/linux/slub_def.h |  3 ++
 lib/Kconfig.kasan        |  2 ++
 mm/Kconfig.debug         | 21 +++++++++++++
 mm/kasan/common.c        | 15 ++++++++-
 mm/slub.c                | 66 +++++++++++++++++++++++++++++++++++++---
 6 files changed, 107 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 819b6bc8ac08..45e07caf4704 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -229,6 +229,8 @@ static __always_inline bool kasan_check_byte(const void *addr)
 	return true;
 }
 
+size_t kasan_align(size_t size);
+
 #else /* CONFIG_KASAN */
 
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
@@ -278,6 +280,10 @@ static inline bool kasan_check_byte(const void *address)
 {
 	return true;
 }
+static inline size_t kasan_align(size_t size)
+{
+	return size;
+}
 
 #endif /* CONFIG_KASAN */
 
diff --git a/include/linux/slub_def.h b/include/linux/slub_def.h
index deb90cf4bffb..b87be8fce64a 100644
--- a/include/linux/slub_def.h
+++ b/include/linux/slub_def.h
@@ -120,6 +120,9 @@ struct kmem_cache {
 	int refcount;		/* Refcount for slab cache destroy */
 	void (*ctor)(void *);
 	unsigned int inuse;		/* Offset to metadata */
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	unsigned int debug_rcu_head_offset;
+#endif
 	unsigned int align;		/* Alignment */
 	unsigned int red_left_pad;	/* Left redzone padding size */
 	const char *name;	/* Name (only for display!) */
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index fdca89c05745..7ff7de96c6e4 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -79,6 +79,7 @@ config KASAN_GENERIC
 	depends on HAVE_ARCH_KASAN && CC_HAS_KASAN_GENERIC
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	select SLUB_DEBUG if SLUB
+	select SLUB_RCU_DEBUG if SLUB_DEBUG
 	select CONSTRUCTORS
 	help
 	  Enables Generic KASAN.
@@ -96,6 +97,7 @@ config KASAN_SW_TAGS
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
 	depends on CC_HAS_WORKING_NOSANITIZE_ADDRESS
 	select SLUB_DEBUG if SLUB
+	select SLUB_RCU_DEBUG if SLUB_DEBUG
 	select CONSTRUCTORS
 	help
 	  Enables Software Tag-Based KASAN.
diff --git a/mm/Kconfig.debug b/mm/Kconfig.debug
index 018a5bd2f576..99cce7f0fbef 100644
--- a/mm/Kconfig.debug
+++ b/mm/Kconfig.debug
@@ -78,6 +78,27 @@ config SLUB_DEBUG_ON
 	  off in a kernel built with CONFIG_SLUB_DEBUG_ON by specifying
 	  "slub_debug=-".
 
+config SLUB_RCU_DEBUG
+	bool "Make use-after-free detection possible in TYPESAFE_BY_RCU caches"
+	depends on SLUB && SLUB_DEBUG
+	default n
+	help
+	  Make SLAB_TYPESAFE_BY_RCU caches behave approximately as if the cache
+	  was not marked as SLAB_TYPESAFE_BY_RCU and every caller used
+	  kfree_rcu() instead.
+
+	  This is intended for use in combination with KASAN, to enable KASAN to
+	  detect use-after-free accesses in such caches.
+	  (KFENCE is able to do that independent of this flag.)
+
+	  This might degrade performance.
+
+	  If you're using this for testing bugs / fuzzing and care about
+	  catching all the bugs WAY more than performance, you might want to
+	  also turn on CONFIG_RCU_STRICT_GRACE_PERIOD.
+
+	  If unsure, say N.
+
 config PAGE_OWNER
 	bool "Track page owner"
 	depends on DEBUG_KERNEL && STACKTRACE_SUPPORT
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 256930da578a..b4a3504f9f5e 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -191,6 +191,13 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	if (kasan_requires_meta())
 		kasan_init_object_meta(cache, object);
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	if (cache->flags & SLAB_TYPESAFE_BY_RCU) {
+		kasan_unpoison(object + cache->debug_rcu_head_offset,
+			       sizeof(struct rcu_head), false);
+	}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 	/* Tag is ignored in set_tag() without CONFIG_KASAN_SW/HW_TAGS */
 	object = set_tag(object, assign_tag(cache, object, true));
 
@@ -218,7 +225,8 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
 	}
 
 	/* RCU slabs could be legally used after free within the RCU period */
-	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
+	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU) &&
+	    !IS_ENABLED(CONFIG_SLUB_RCU_DEBUG))
 		return false;
 
 	if (!kasan_byte_accessible(tagged_object)) {
@@ -450,3 +458,8 @@ bool __kasan_check_byte(const void *address, unsigned long ip)
 	}
 	return true;
 }
+
+size_t kasan_align(size_t size)
+{
+	return round_up(size, KASAN_GRANULE_SIZE);
+}
diff --git a/mm/slub.c b/mm/slub.c
index e3b5d5c0eb3a..bae6c2bc1e5f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1108,7 +1108,8 @@ static int check_bytes_and_report(struct kmem_cache *s, struct slab *slab,
  * 	A. Free pointer (if we cannot overwrite object on free)
  * 	B. Tracking data for SLAB_STORE_USER
  *	C. Original request size for kmalloc object (SLAB_STORE_USER enabled)
- *	D. Padding to reach required alignment boundary or at minimum
+ *	D. RCU head for CONFIG_SLUB_RCU_DEBUG (with padding around it)
+ *	E. Padding to reach required alignment boundary or at minimum
  * 		one word if debugging is on to be able to detect writes
  * 		before the word boundary.
  *
@@ -1134,6 +1135,11 @@ static int check_pad_bytes(struct kmem_cache *s, struct slab *slab, u8 *p)
 			off += sizeof(unsigned int);
 	}
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	if (s->flags & SLAB_TYPESAFE_BY_RCU)
+		off = kasan_align(s->debug_rcu_head_offset + sizeof(struct rcu_head));
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 	off += kasan_metadata_size(s, false);
 
 	if (size_from_object(s) == off)
@@ -1751,12 +1757,17 @@ static bool freelist_corrupted(struct kmem_cache *s, struct slab *slab,
 #endif
 #endif /* CONFIG_SLUB_DEBUG */
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+static void slab_free_after_rcu_debug(struct rcu_head *rcu_head);
+#endif
+
 /*
  * Hooks for other subsystems that check memory allocations. In a typical
  * production configuration these hooks all should produce no code at all.
  */
 static __always_inline bool slab_free_hook(struct kmem_cache *s,
-						void *x, bool init)
+						void *x, bool init,
+						bool after_rcu_delay)
 {
 	kmemleak_free_recursive(x, s->flags);
 	kmsan_slab_free(s, x);
@@ -1766,8 +1777,18 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s,
 	if (!(s->flags & SLAB_DEBUG_OBJECTS))
 		debug_check_no_obj_freed(x, s->object_size);
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	/* kfence does its own RCU delay */
+	if ((s->flags & SLAB_TYPESAFE_BY_RCU) && !after_rcu_delay &&
+	    !is_kfence_address(x)) {
+		call_rcu(kasan_reset_tag(x) + s->debug_rcu_head_offset,
+			 slab_free_after_rcu_debug);
+		return true;
+	}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 	/* Use KCSAN to help debug racy use-after-free. */
-	if (!(s->flags & SLAB_TYPESAFE_BY_RCU))
+	if (!(s->flags & SLAB_TYPESAFE_BY_RCU) || after_rcu_delay)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
@@ -1802,7 +1823,7 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 	void *old_tail = *tail ? *tail : *head;
 
 	if (is_kfence_address(next)) {
-		slab_free_hook(s, next, false);
+		slab_free_hook(s, next, false, false);
 		return true;
 	}
 
@@ -1815,7 +1836,7 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 		next = get_freepointer(s, object);
 
 		/* If object's reuse doesn't have to be delayed */
-		if (!slab_free_hook(s, object, slab_want_init_on_free(s))) {
+		if (!slab_free_hook(s, object, slab_want_init_on_free(s), false)) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -3802,6 +3823,31 @@ static __fastpath_inline void slab_free(struct kmem_cache *s, struct slab *slab,
 		do_slab_free(s, slab, head, tail, cnt, addr);
 }
 
+#ifdef CONFIG_SLUB_RCU_DEBUG
+static void slab_free_after_rcu_debug(struct rcu_head *rcu_head)
+{
+	struct slab *slab = virt_to_slab(rcu_head);
+	struct kmem_cache *s;
+	void *object;
+
+	if (WARN_ON(is_kfence_address(rcu_head)))
+		return;
+
+	/* find the object and the cache again */
+	if (WARN_ON(!slab))
+		return;
+	s = slab->slab_cache;
+	if (WARN_ON(!(s->flags & SLAB_TYPESAFE_BY_RCU)))
+		return;
+	object = (void *)rcu_head - s->debug_rcu_head_offset;
+
+	/* resume freeing */
+	if (slab_free_hook(s, object, slab_want_init_on_free(s), true))
+		return;
+	do_slab_free(s, slab, object, NULL, 1, _THIS_IP_);
+}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
+
 #ifdef CONFIG_KASAN_GENERIC
 void ___cache_free(struct kmem_cache *cache, void *x, unsigned long addr)
 {
@@ -4443,6 +4489,16 @@ static int calculate_sizes(struct kmem_cache *s)
 		if (flags & SLAB_KMALLOC)
 			size += sizeof(unsigned int);
 	}
+
+#ifdef CONFIG_SLUB_RCU_DEBUG
+	if (flags & SLAB_TYPESAFE_BY_RCU) {
+		size = kasan_align(size);
+		size = ALIGN(size, __alignof__(struct rcu_head));
+		s->debug_rcu_head_offset = size;
+		size += sizeof(struct rcu_head);
+		size = kasan_align(size);
+	}
+#endif /* CONFIG_SLUB_RCU_DEBUG */
 #endif
 
 	kasan_cache_create(s, &size, &s->flags);

base-commit: 4f9e7fabf8643003afefc172e62dd276686f016e
-- 
2.42.0.rc1.204.g551eb34607-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230825211426.3798691-1-jannh%40google.com.
