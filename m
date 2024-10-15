Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBLMNW64AMGQESFCJRII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id C2E6A99DB9C
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:38 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2e18b6cd304sf4419771a91.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956077; cv=pass;
        d=google.com; s=arc-20240605;
        b=k8f50pgZPZme+8odoF+QnGO/E8B1E6l1BK5jmlQNFHJZsRw1YnZrkt5qm7HaQNnKTu
         EYFGOpN4R+Fr01FdG11HHmI0GtzR5NA45zTcoYAf2ItcLjvd8aa4ZTxvsxzwgM80ykEE
         apcMlI5GA6V4JGrO224edNo4JDNFChGHIJlQCs5rEu7qTblRQHxl887OadluoCrAirsO
         qwHRSC4dWBm5FcQdLlyKsTrZ90hBe3HXJEHyctUop1BwPUHn1Y3GLZPPqsWO1fHWwZWa
         VQOWGyFavbsANY7fOsVJlbLhzS+N3/zALBvKHXe+om8t8v2GYQtA1fOdmG5Wb2u2bIhg
         uI8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=lv4HlSOoW3cZpAGFGStKUpGE1EI+lL8Brr+kYWFoX7Y=;
        fh=c2RPQaqb0rfeeKvldJvDqIrlhH/qAK0XxLQBx5x333I=;
        b=Z9FTP7PpObYr1WjJxwAt0pvZ4oX3i+xH/IEK325CWqkinCNafoz0vp6b7vP2Xei4rt
         pNTKotGfWAxv+8AWurlrGPy2gxJtyvtv9GbOEu8B6Sxof3bIeJ4PWHgw5mC6Pr12kVa+
         YIF4/6T6qCf4p1aabKSih/NYeensSLgzxOGH/rQuuaYbQFxDV/3xdIdnSW6aXYCSLH8j
         c0HmBV5vROOsZ9zXsdMgRDbVisGgvkzDoScKaWeGrKmNtMQYqf/lz+1/5g4ndFlaNS6u
         3YkrSueS+eVaGxBe2oEnplyTctVfi7S0LmbePnT4Iy3XTLy4kR7olQuN3yEf0NWrMcMt
         +lug==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=We5UDm88;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956077; x=1729560877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lv4HlSOoW3cZpAGFGStKUpGE1EI+lL8Brr+kYWFoX7Y=;
        b=J+cjv/GKAoVuWRA2lr5PZuAV5hDfFPM+hDWb2FZQ1xOq8cjzMEJpQXjDQVaHImXwRB
         GXcDrIjSjxFKyPvPBa4pmIFtvNYcREutbilHAUZZg9i4D2lkq+fUkvnrWK6fFYBD9T3Y
         k1Ju50x+87VfTktSqHaXKlvnvd9AnE0GmI0QabgKY3ZEmnjNPde+OMvl4IObnmirJ1uU
         nWQ+W5fhzJ1xYWI4/0gUHK5eq6Q6Eg3o16pxdJXjnpv2JC88xweOEy4NBzqKBkZONBvP
         TU/PhJzJwH4C1mLPluFkMTRzT65/pio3b3GcKf54eRXO5mDQU9RN1uyRnw7zBqbLc0mc
         +SqQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956077; x=1729560877; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=lv4HlSOoW3cZpAGFGStKUpGE1EI+lL8Brr+kYWFoX7Y=;
        b=J7969/ZFfwCd9DZo4nbyPv31inaCP1nVP/9KBD2tUEYfExavV7ybtO/DRdhNQe11W4
         1e7w/oeN1aIKtE620Af7ovF2AoXrxP872+9B2xz5aZNeK4WUhZ6065+oocBAAeGhQGYN
         PG57nwNgDATbOQSODUtLF9wN7LNAHv7/M+EtlH8ud4Jz/eDkdwCQoKdGnOSWZStzV+kj
         XRtYMAZRbfwNbk4BHsMUuf1xnYRnCaJJKdi0TTyHBdjHWvgmUQBZB6VcCKGhFP63GXqx
         G/3Z/pYg5fo1IieMQOKIDzGf9L5Whs+nhd6xLVtC+yjP8LM17mdQdpgnh0Dy9osuB0Z8
         qM5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956077; x=1729560877;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lv4HlSOoW3cZpAGFGStKUpGE1EI+lL8Brr+kYWFoX7Y=;
        b=dj+t+VD3PM/4qe7UFXTKexMNw3foCvRufzAbC4wGpyFepJtyIwhlvnIGx+W9qXNR9x
         I9Vk+KytPC5dliahwnBt9r3mux3dD5H+FLaX0O7A0sZbvpgsJVmPrP4yyTtkz554vC5l
         m67BM281d+58dMocE/O9NsX1DL69zUp/3ajS1bnvPpIE1Jf4niZaRoHYwd+YXvH1V7V2
         N27tKLwBzHin2wNZ322SEDK8Pp9ZHCTfMcpx3sA+eTl5DIbAu0pUGQ2vpFhPNvpnBA8j
         Y6S1XsQOkdmrfpTfLm3er52G0PXItHuKTjwJd3iiDDw5QticfaB6lWykb8kg6/3IsPVg
         4PNQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXkX7+gVxbL8PuZBY31IZG9Hbo7zFdGv9jrm26AXcQffrv45y4kCTs8DaJTWJY37BABFcldhw==@lfdr.de
X-Gm-Message-State: AOJu0Yz9zyvx3wf0+oM3o9rZJAZlsu1EeVGBXI5/wKa7NZ4oCnb7ru/0
	5jJ5WmCO5Jy7lnPpX4zs0izUujaFl2aN9NT+Yzmr2NPivNqwAOco
X-Google-Smtp-Source: AGHT+IFO42Hn0ohvfHw0UnyVpA7ZgeX9kGJGHIygWzMMqoTA5WjJha2ojXB663pI1YDKm6Ccg8EOeg==
X-Received: by 2002:a17:90a:bf0c:b0:2e2:b45f:53b4 with SMTP id 98e67ed59e1d1-2e31536de0dmr11784918a91.25.1728956077333;
        Mon, 14 Oct 2024 18:34:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:c7c9:b0:2e1:1d4a:962a with SMTP id
 98e67ed59e1d1-2e2c833665fls1106019a91.1.-pod-prod-04-us; Mon, 14 Oct 2024
 18:34:36 -0700 (PDT)
X-Received: by 2002:a17:90b:1495:b0:2e2:e6c8:36a7 with SMTP id 98e67ed59e1d1-2e31536e312mr12852411a91.31.1728956076048;
        Mon, 14 Oct 2024 18:34:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956076; cv=none;
        d=google.com; s=arc-20240605;
        b=MsGwbRIqNaQe9ejehFQoS4JpGr2BlFue/TTTSIl2c5uTsWXzc/DgfQz/F+Aezkz/Jh
         tjF9T3i6mGxyiRPG9yWg3mF4jO2SZe6/W0Wy2huYgKqUu51CScKSkThy36QL1Vvkh7uz
         bZ/TSQfVFKqkHJUUc8DQgJy75GONxGt3NSaqzgP9kCqLEq5flPhFanzPqAbMPKw8b/Nn
         tXm8WN8/etXjSM0BuVhF6UJ4SSLbGPuUJKWtCaF4VbRSC9RNaD2Yr8VF+PXgjr6YNhIW
         YNmmDBqx2iHqUxjyyIDc/L7Jy/NzqDEJIinQKc8q8v2kLbdGjb1h7W3ibjqd8iLezoRD
         eiJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=OpMDq1IEGMMPwRojJ8i4AsUukx9XqidcnS2hx9BDF5Q=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=O69YsratmDcPKxZUQpVfIIiiC0roGqkTYmQnnjVifa/vuOD+tp+cuOya94E4XtY/5n
         Oe/Vwfisj2d4emuIuLBc0eYw8LkeSHNnpdL8pv2pAx3rMVN7P8d8gjMmTojYso8Fw6YW
         LRnhYkTB1tGZFL2R3cTz5+EgV0LpDWvSdB0SkbrWFt+JT1Vnamq8/K38FYxU0qcXP72L
         ADh524Mvw6Q7d91RhLydWa2ilT+2JALkJ40VRtw5jr9VO2b5Ga5edbDHOtXSk/d94Aeb
         +wWMkUhIaVMjq4ggfc+uzWQAiDKTUOKdkXMVaMX/JINiWy3a2PFah/r1HRdBvef8nNzM
         SfCQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=We5UDm88;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x531.google.com (mail-pg1-x531.google.com. [2607:f8b0:4864:20::531])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e37f1cfcc2si143314a91.0.2024.10.14.18.34.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::531 as permitted sender) client-ip=2607:f8b0:4864:20::531;
Received: by mail-pg1-x531.google.com with SMTP id 41be03b00d2f7-7ea6a4f287bso1543155a12.3
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:36 -0700 (PDT)
X-Received: by 2002:a05:6a21:168e:b0:1cf:3677:1c63 with SMTP id adf61e73a8af0-1d8c95d56c3mr14328100637.25.1728956075539;
        Mon, 14 Oct 2024 18:34:35 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.34.30
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:34 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC RESEND v2 10/13] book3s64/hash: Add kfence functionality
Date: Tue, 15 Oct 2024 07:03:33 +0530
Message-ID: <52f01906734ece9d4f9292c252cf02e7cd267f99.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=We5UDm88;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::531
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/52f01906734ece9d4f9292c252cf02e7cd267f99.1728954719.git.ritesh.list%40gmail.com.
