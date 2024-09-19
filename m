Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBC5GV23QMGQEUEGKDPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 05FA997C2F5
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 04:57:17 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6c3580b7cf5sf6031936d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 19:57:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726714635; cv=pass;
        d=google.com; s=arc-20240605;
        b=SvzjTA5CQSQBj8IG5Meiy+1JChSvxgMLEBsINkQJJO4ZWLmQ/HR9pUGzu/E4Vy5bkO
         /BeDE9P2Y2t9UxtaTn1QzXECdxoI6pwtYxLtW7QcCQLURyyqxbgVmhXxscfMmcHe+kLA
         5Gi7f9LiulNc7uklpT6Sf6ytZLdxtVC2xtE1zTEEY86N1ZXArVIfsuqaxMmFkwUL+aFz
         0ZaHAypXoBbt0CZGJGnAdlmGzai5B76rertMvg79lNwKAPcvUVhA1M+97ASd/kXiRNUe
         hReCxslT3rbXFnngDlt8+5pViZptmFvF4t08cvEIcFhGAhmFlzwm9f5TvkNfOiETnirK
         tH+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=1k09kE4qrPcsBIt5m2/Nc9Xt08TTr1MQFi3cw4NhyRs=;
        fh=DHeqXjcOcElOC3WGmzPuq9mjRh7w+r16nqoImu491Ow=;
        b=jz4GtF8bDvi4o+YaW7jImPlNk7rGFY1dAr1rlMnjbiZUBgvm/IZFK3FV0b4iOXVQVE
         yVbYMz6iURjB00D+VO2eDF5Ni4X9wz7WWabOu44v+eIXDUZxNWDvZ2RwqiWOg8QXGR0/
         sQPmDrDNoQJEnr5tsMUvi72V6qygXOV+GjrZ4G4HXL1lMMfKLrNPriAF1Cu6vBit1ZOb
         stwWtj6VCc/eqRxi93hqmrudxKgyjcat+RrGsSpdCUGB97ZvaVO1QnD+cjaJ8zNvJu9A
         gV/P40ARQUbuDtLODHvhr6gOHvfozOTffBRkzSDDvxeIZBQZwaSdGdH+nvdi7OmEZj54
         UDng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FUXPsuiQ;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726714635; x=1727319435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1k09kE4qrPcsBIt5m2/Nc9Xt08TTr1MQFi3cw4NhyRs=;
        b=wpckDqJb25kYaprq7hNqB0zQde9R6AboaooynHt8xinZbQFZul+npAwun4IYv+Ygrr
         ebX3eJrA09wOMgx9BusxzBJleiT+n0Gs0vXttmsViy75szeM2D9ue9wQ+KZJjr1FyFKD
         9rnfRSSbS/z/iVldeJ2yb7cJ+F1QGMycLLqM1g3i+R9HFJnLCSQQGkhSZcqqgZ0hVt5I
         n0KcSU//PC1LAPAUbwIn3GV/OF4AFaVYdDRBbglBW6l7F3Os1XQ2GzVBLnfJgZmk+WCV
         JIRyMEOU+tKZn3cmWPnJCmcRZutRDsDWXzSyFET1ggje2c8VmLnSTLl36sVCY3393f7l
         mz9Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726714635; x=1727319435; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=1k09kE4qrPcsBIt5m2/Nc9Xt08TTr1MQFi3cw4NhyRs=;
        b=WSSFB/+ZGW2fN419nED5y5/tBYbqyXRjnLvveHE8/M+YOiOqSBXyO9HpF0Hs5B9g7I
         4gg2in9mvvq/ndxM+BNUmdld6365x3iYd+OATO4n7BTDPrCXIiysff7oM16IfKvKgOj+
         NVHrKFf0fXz57d3hc8lYphDEAIayhq0V506LJArWlMsHyW4/Derqxz1O5zKbEGYCqy1e
         efpXyPE2s1GycQqC00OHFQ8+1dO2BRthlvsxcwGLrqLGRIUzA9DebcY6s74AhJ6C3awo
         lz+LDXJj58sGCn9MjUDrFVqDRnU6iOJ/sok7VRL/rADrgSwtNxkI4+Yvz8H05uGe7Rui
         cukA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726714635; x=1727319435;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1k09kE4qrPcsBIt5m2/Nc9Xt08TTr1MQFi3cw4NhyRs=;
        b=vcaFXzBz4QncY3yh7Gm0kTqq2YJNVcOXaMvS61Opu+seq5snoI5V1l94eCLSc2TD4k
         gNrUzbIVtF36V9ymSmoia4rRIQyuGo+vHI4sRtL7PC1B4JyoZW51RlTSWpLPBt3R8Wmt
         xWivCZUIcG2gcZ03hCFTgpnth+W7qtbzs61ByNHUv2K6df2NY5FNR3KwEJXAOAT2O3YV
         eUvpIE5LN8fOkOYxeQERNPuESNEjJYIMD6CoxJJghNXqPbvM1GXPoNXnv5Zm3cpcQvmZ
         669Td7WkBI1kTXhYHGzKKHdBkJWiMpsqIhG95FLLqIaYnnMYsJBrVm94Tf0T497ZPZb0
         9Ffw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWH09dwBcQuxlK/U2rNpcFUTlT++XxNF53D0CdylV33gA4Zfno7Z3JhTrcPxl9C3gM3g+XvmA==@lfdr.de
X-Gm-Message-State: AOJu0YyrDTMn8/eP88ERxbky4cwPmh0ZvWgFGG+jTgcfHSvp3nk2RMg5
	6FTg70hi3u/3McJF8Nlv9SyJXNcpyW54azkyFMuKopgVojdtS41G
X-Google-Smtp-Source: AGHT+IFWcKf++LGWbsu/FdHFK3aboMovB1gbZZrOyxTqfdbTwtFXJyrEV0zM6rEZYXanrSbbMTkwhA==
X-Received: by 2002:a05:6214:3d8a:b0:6c5:a69a:aa68 with SMTP id 6a1803df08f44-6c5a69aaac3mr184302746d6.47.1726714635628;
        Wed, 18 Sep 2024 19:57:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5b88:0:b0:6bf:60fd:c203 with SMTP id 6a1803df08f44-6c69bbce690ls8488866d6.1.-pod-prod-05-us;
 Wed, 18 Sep 2024 19:57:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVcgIOYc7Hp3D9j6ovR1A37riM8zcbBECZeosNGxnWGVKfSkTh1PXKKkk0Xif2SQPGJME9K8Ru/+1s=@googlegroups.com
X-Received: by 2002:a05:620a:2907:b0:7a9:b928:41ba with SMTP id af79cd13be357-7ab30dad854mr3370843685a.40.1726714634889;
        Wed, 18 Sep 2024 19:57:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726714634; cv=none;
        d=google.com; s=arc-20240605;
        b=DOtmj4X23lTdsgW+0Y4KUs/3xLzKD0jT7lfHtRDjh1UvcAyCpzuPM7DRKp5rbLv2Un
         8N1cXok6ud1rntXkL1IE6JwQeN1e37rcKL0jEgIIG+sO6N7ZvbpN/ObBjdTYWioNxfjH
         H0onuNRAORUS5ejdf+Q5fH6JWJbZJbfwv4CATogv4fig9Ld5T3bLREkbnFFoOv1jb49i
         ELfTqi1Hv0jn63p31kMnFY+fgn+Askf1q78CW259oS+iIDf8w/2eV8xL+VSu6m5cGsKG
         +koTAIxalM2DgYOrs0viY67RRH3nXkdCICRWHMkFh72NQHbFSG7OlWg1bjI3aqobaQX1
         +ZIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OpMDq1IEGMMPwRojJ8i4AsUukx9XqidcnS2hx9BDF5Q=;
        fh=KDJ1orczYhnVgpCCnI+U5FTQ3KRDm4ArBo2AgMG0GPw=;
        b=VIoTLVRdv8hRj0Rc9to2mG9oGKYKsdnadQfIcoYfSgngFfbDl/vaYjSZHpZPjQcUYP
         uVYyy5bYbg/dkL537kOPQA+0AsJeIre6wCFC4ZxxWAuII3lLv7C9DNM8xU/HbG0ifd7B
         iwpKBnXVCb+cAzuNNK0CXuKb4okmbJFztb373wGpq9zYtGBERGl3uXsXk1fyCgS19/TV
         7MWF1DTUxhG0np8Wsw8EQ3tsm6RH+1Pk3tnAWERIqpG/MI4yta9lqsT10kmogK5bSZuW
         pCw0vdsyI5B0gaRcrJqm8VI5/rfx0QI7ZT2Mwwxa2XSk+hY+dun7xHBmoAhL8BCQqeQJ
         zCEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=FUXPsuiQ;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7acb07ea45esi5297085a.1.2024.09.18.19.57.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 19:57:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-206bd1c6ccdso4156265ad.3
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 19:57:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWkgVztz24d7K77sld6sTwxJF/lnz3N1zCNPG8nUWWyN9xRETLYiCeg+MdK5y6RysCTl1hjsBk4UzA=@googlegroups.com
X-Received: by 2002:a17:902:e80a:b0:202:190e:2adb with SMTP id d9443c01a7336-2078253791bmr316942145ad.36.1726714633762;
        Wed, 18 Sep 2024 19:57:13 -0700 (PDT)
Received: from dw-tp.. ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946d2823sm71389105ad.148.2024.09.18.19.57.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 19:57:13 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	Nirjhar Roy <nirjhar@linux.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	kasan-dev@googlegroups.com,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC v2 10/13] book3s64/hash: Add kfence functionality
Date: Thu, 19 Sep 2024 08:26:08 +0530
Message-ID: <449e751d8c64538076079a8fcb19749260817e62.1726571179.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1726571179.git.ritesh.list@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=FUXPsuiQ;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::62e
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Now that linear map functionality of debug_pagealloc is made generic,
enable kfence to use this generic infrastructure.

1. Define kfence related linear map variables.
   - u8 *linear_map_kf_hash_slots;
   - unsigned long linear_map_kf_hash_count;
   - DEFINE_RAW_SPINLOCK(linear_map_kf_hash_lock);
2. The linear map size allocated in RMA region is quite small
   (KFENCE_POOL_SIZE >> PAGE_SHIFT) which is 512 bytes by default.
3. kfence pool memory is reserved using memblock_phys_alloc() which has
   can come from anywhere.
   (default 255 objects => ((1+255) * 2) << PAGE_SHIFT = 32MB)
4. The hash slot information for kfence memory gets added in linear map
   in hash_linear_map_add_slot() (which also adds for debug_pagealloc).

Reported-by: Pavithra Prakash <pavrampu@linux.vnet.ibm.com>
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/include/asm/kfence.h     |   5 -
 arch/powerpc/mm/book3s64/hash_utils.c | 162 +++++++++++++++++++++++---
 2 files changed, 149 insertions(+), 18 deletions(-)

diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
index f3a9476a71b3..fab124ada1c7 100644
--- a/arch/powerpc/include/asm/kfence.h
+++ b/arch/powerpc/include/asm/kfence.h
@@ -10,7 +10,6 @@
 
 #include <linux/mm.h>
 #include <asm/pgtable.h>
-#include <asm/mmu.h>
 
 #ifdef CONFIG_PPC64_ELF_ABI_V1
 #define ARCH_FUNC_PREFIX "."
@@ -26,10 +25,6 @@ static inline void disable_kfence(void)
 
 static inline bool arch_kfence_init_pool(void)
 {
-#ifdef CONFIG_PPC64
-	if (!radix_enabled())
-		return false;
-#endif
 	return !kfence_disabled;
 }
 #endif
diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index cffbb6499ac4..53e6f3a524eb 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -40,6 +40,7 @@
 #include <linux/random.h>
 #include <linux/elf-randomize.h>
 #include <linux/of_fdt.h>
+#include <linux/kfence.h>
 
 #include <asm/interrupt.h>
 #include <asm/processor.h>
@@ -66,6 +67,7 @@
 #include <asm/pte-walk.h>
 #include <asm/asm-prototypes.h>
 #include <asm/ultravisor.h>
+#include <asm/kfence.h>
 
 #include <mm/mmu_decl.h>
 
@@ -271,7 +273,7 @@ void hash__tlbiel_all(unsigned int action)
 		WARN(1, "%s called on pre-POWER7 CPU\n", __func__);
 }
 
-#ifdef CONFIG_DEBUG_PAGEALLOC
+#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)
 static void kernel_map_linear_page(unsigned long vaddr, unsigned long idx,
 				   u8 *slots, raw_spinlock_t *lock)
 {
@@ -325,11 +327,13 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long idx,
 				     mmu_linear_psize,
 				     mmu_kernel_ssize, 0);
 }
+#endif
 
+#ifdef CONFIG_DEBUG_PAGEALLOC
 static u8 *linear_map_hash_slots;
 static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
-static inline void hash_debug_pagealloc_alloc_slots(void)
+static void hash_debug_pagealloc_alloc_slots(void)
 {
 	unsigned long max_hash_count = ppc64_rma_size / 4;
 
@@ -352,7 +356,8 @@ static inline void hash_debug_pagealloc_alloc_slots(void)
 		      __func__, linear_map_hash_count, &ppc64_rma_size);
 }
 
-static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr,
+							int slot)
 {
 	if (!debug_pagealloc_enabled() || !linear_map_hash_count)
 		return;
@@ -386,20 +391,148 @@ static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
 	return 0;
 }
 
-int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+#else /* CONFIG_DEBUG_PAGEALLOC */
+static inline void hash_debug_pagealloc_alloc_slots(void) {}
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot) {}
+static int __maybe_unused
+hash_debug_pagealloc_map_pages(struct page *page, int numpages, int enable)
 {
-	return hash_debug_pagealloc_map_pages(page, numpages, enable);
+	return 0;
 }
+#endif /* CONFIG_DEBUG_PAGEALLOC */
 
-#else /* CONFIG_DEBUG_PAGEALLOC */
-int hash__kernel_map_pages(struct page *page, int numpages,
-					 int enable)
+#ifdef CONFIG_KFENCE
+static u8 *linear_map_kf_hash_slots;
+static unsigned long linear_map_kf_hash_count;
+static DEFINE_RAW_SPINLOCK(linear_map_kf_hash_lock);
+
+static phys_addr_t kfence_pool;
+
+static inline void hash_kfence_alloc_pool(void)
+{
+
+	// allocate linear map for kfence within RMA region
+	linear_map_kf_hash_count = KFENCE_POOL_SIZE >> PAGE_SHIFT;
+	linear_map_kf_hash_slots = memblock_alloc_try_nid(
+					linear_map_kf_hash_count, 1,
+					MEMBLOCK_LOW_LIMIT, ppc64_rma_size,
+					NUMA_NO_NODE);
+	if (!linear_map_kf_hash_slots) {
+		pr_err("%s: memblock for linear map (%lu) failed\n", __func__,
+				linear_map_kf_hash_count);
+		goto err;
+	}
+
+	// allocate kfence pool early
+	kfence_pool = memblock_phys_alloc_range(KFENCE_POOL_SIZE, PAGE_SIZE,
+				MEMBLOCK_LOW_LIMIT, MEMBLOCK_ALLOC_ANYWHERE);
+	if (!kfence_pool) {
+		pr_err("%s: memblock for kfence pool (%lu) failed\n", __func__,
+				KFENCE_POOL_SIZE);
+		memblock_free(linear_map_kf_hash_slots,
+				linear_map_kf_hash_count);
+		linear_map_kf_hash_count = 0;
+		goto err;
+	}
+	memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
+
+	return;
+err:
+	pr_info("Disabling kfence\n");
+	disable_kfence();
+}
+
+static inline void hash_kfence_map_pool(void)
+{
+	unsigned long kfence_pool_start, kfence_pool_end;
+	unsigned long prot = pgprot_val(PAGE_KERNEL);
+
+	if (!kfence_pool)
+		return;
+
+	kfence_pool_start = (unsigned long) __va(kfence_pool);
+	kfence_pool_end = kfence_pool_start + KFENCE_POOL_SIZE;
+	__kfence_pool = (char *) kfence_pool_start;
+	BUG_ON(htab_bolt_mapping(kfence_pool_start, kfence_pool_end,
+				    kfence_pool, prot, mmu_linear_psize,
+				    mmu_kernel_ssize));
+	memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
+}
+
+static inline void hash_kfence_add_slot(phys_addr_t paddr, int slot)
 {
+	unsigned long vaddr = (unsigned long) __va(paddr);
+	unsigned long lmi = (vaddr - (unsigned long)__kfence_pool)
+					>> PAGE_SHIFT;
+
+	if (!kfence_pool)
+		return;
+	BUG_ON(!is_kfence_address((void *)vaddr));
+	BUG_ON(lmi >= linear_map_kf_hash_count);
+	linear_map_kf_hash_slots[lmi] = slot | 0x80;
+}
+
+static int hash_kfence_map_pages(struct page *page, int numpages, int enable)
+{
+	unsigned long flags, vaddr, lmi;
+	int i;
+
+	WARN_ON_ONCE(!linear_map_kf_hash_count);
+	local_irq_save(flags);
+	for (i = 0; i < numpages; i++, page++) {
+		vaddr = (unsigned long)page_address(page);
+		lmi = (vaddr - (unsigned long)__kfence_pool) >> PAGE_SHIFT;
+
+		/* Ideally this should never happen */
+		if (lmi >= linear_map_kf_hash_count) {
+			WARN_ON_ONCE(1);
+			continue;
+		}
+
+		if (enable)
+			kernel_map_linear_page(vaddr, lmi,
+					       linear_map_kf_hash_slots,
+					       &linear_map_kf_hash_lock);
+		else
+			kernel_unmap_linear_page(vaddr, lmi,
+						 linear_map_kf_hash_slots,
+						 &linear_map_kf_hash_lock);
+	}
+	local_irq_restore(flags);
 	return 0;
 }
-static inline void hash_debug_pagealloc_alloc_slots(void) {}
-static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot) {}
-#endif /* CONFIG_DEBUG_PAGEALLOC */
+#else
+static inline void hash_kfence_alloc_pool(void) {}
+static inline void hash_kfence_map_pool(void) {}
+static inline void hash_kfence_add_slot(phys_addr_t paddr, int slot) {}
+static int __maybe_unused
+hash_kfence_map_pages(struct page *page, int numpages, int enable)
+{
+	return 0;
+}
+#endif
+
+#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)
+int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+{
+	void *vaddr = page_address(page);
+
+	if (is_kfence_address(vaddr))
+		return hash_kfence_map_pages(page, numpages, enable);
+	else
+		return hash_debug_pagealloc_map_pages(page, numpages, enable);
+}
+
+static void hash_linear_map_add_slot(phys_addr_t paddr, int slot)
+{
+	if (is_kfence_address(__va(paddr)))
+		hash_kfence_add_slot(paddr, slot);
+	else
+		hash_debug_pagealloc_add_slot(paddr, slot);
+}
+#else
+static void hash_linear_map_add_slot(phys_addr_t paddr, int slot) {}
+#endif
 
 /*
  * 'R' and 'C' update notes:
@@ -559,7 +692,8 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;
 
 		cond_resched();
-		hash_debug_pagealloc_add_slot(paddr, ret);
+		// add slot info in debug_pagealloc / kfence linear map
+		hash_linear_map_add_slot(paddr, ret);
 	}
 	return ret < 0 ? ret : 0;
 }
@@ -940,7 +1074,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();
 
-	if (!debug_pagealloc_enabled()) {
+	if (!debug_pagealloc_enabled_or_kfence()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
@@ -1261,6 +1395,7 @@ static void __init htab_initialize(void)
 	prot = pgprot_val(PAGE_KERNEL);
 
 	hash_debug_pagealloc_alloc_slots();
+	hash_kfence_alloc_pool();
 	/* create bolted the linear mapping in the hash table */
 	for_each_mem_range(i, &base, &end) {
 		size = end - base;
@@ -1277,6 +1412,7 @@ static void __init htab_initialize(void)
 		BUG_ON(htab_bolt_mapping(base, base + size, __pa(base),
 				prot, mmu_linear_psize, mmu_kernel_ssize));
 	}
+	hash_kfence_map_pool();
 	memblock_set_current_limit(MEMBLOCK_ALLOC_ANYWHERE);
 
 	/*
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/449e751d8c64538076079a8fcb19749260817e62.1726571179.git.ritesh.list%40gmail.com.
