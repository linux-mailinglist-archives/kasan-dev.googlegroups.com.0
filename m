Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBN5WZK4AMGQERKUSJMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 7F12F9A449F
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:30:33 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id 98e67ed59e1d1-2e2a6f9438esf2626119a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:30:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272632; cv=pass;
        d=google.com; s=arc-20240605;
        b=cd6Ddb+ZJkYx4lmICazIbMY3KzXvOeKj/2rL9A+Rv4mBrQTgaLAl/wcWnLebSUujH2
         yva9Sk+NjWqx3ge10+RehSX1QCzYKBUR/8A45HHwFhyfIUKDA8fFiWboNDsQuP8L8vna
         O8mI4gru+7247IcRgMhDBtQzH1VqktZuLHGwb4mBkhKqtXoeM/kkq+zknVVzdgAZBV3v
         M9pdbzrV8QMBa4h7eOUrEELSNIVWtHKzPLAmUmXauZuS2WgnfEsKIMlDUTpP6BCA/shi
         jAIIeTs6PpK2irBAHodhCfJc3p6LMD5epDr7RBb4ooAvPNyYxiEgX2ycIGJS2h5ZmUcP
         qifw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=pIwxbRZVrfFzp4u66A2R0qkaAAbBsBlPHQdtBQ96TSk=;
        fh=xOWxlIyd00d2U10kP5a3mNB+c7VQ7QDv7gaqhakb8FU=;
        b=BoWkjkj0GTRBWtN4IR74uQLt6axKVPJjiNmLqlmbYFhP5NfUt70GXUZ7CpU2FFFevl
         NRo6mC5SOme41Y9yYHpUjA+OBCYmeNLylcgON85qaFbQb7vLkX/KzM9mXqs0T7UZReBF
         SbpncIRQuu5sKLULfaULU86e9gj46Px6tJmuCBFunp8RKVGuqmprCbeZsWlt0vEvj0F1
         0ehjGXAUNhs9JkyhqaGnxunlId40K0AUt8v9XjChWE85Z3Co0G7aXzcGoLJt89OLBAaO
         SESjHjHX4N7Q/3FJVkMaBTNB2uUmr1b9KzevW8sxZFsjytHZMohM8HhfReeSLOrIep0R
         SmGA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="f30jA/+F";
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272632; x=1729877432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pIwxbRZVrfFzp4u66A2R0qkaAAbBsBlPHQdtBQ96TSk=;
        b=kNpfPnnQb37rWBpVER03XWTKefGKDxMbWrFa0+59a4iRam1hZlftxKnYgbCMn1ttwH
         CarVomRwSbuBFxeA3Sv5R5rPGhTNgJeS2qHkY2yngn/sjnk1VFvy/Cgv4zP34Pq2qZyL
         D1ZJCBJkS5voGMFHDyKmQXReooKqplutIArY6tbtvEYzYewfyIcKLqB4Fko133IaDfOD
         YAsm+emFulst59dnrjOzYZSXirOOBCTW0QlBBsHpFP/ByidXiXv0+EwlmNLW817gKZEW
         0RJVpIePlU+5RiJx/4ImFAOjCWAKklwHj6J8cQqy8r5np5cc4JpeA6ly6buhle7Wg5Vs
         m0Og==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272632; x=1729877432; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=pIwxbRZVrfFzp4u66A2R0qkaAAbBsBlPHQdtBQ96TSk=;
        b=U0ekQkGO2fB1LFI2UTdgX4Z9wauQB75oqhsMPYTQ2hb80dpm0Sm+9oxYlFeV8mt484
         Bg+GI+djo2MdZCWJ0QgeGzxlJ8TJlbyIlj9Z0cSQ7uswoaYCQJ8Y+A7Ox3A4T46TUh8x
         IxuMO4Y+i5AOXrUUsgsK04FAK7ZsBHHruJTbFeXPrwyPESPu4mMGUJLu4RzTTXjygAsh
         TBHGq7V6FuRRMlgd1FgzYhlAkPmysWbh768q/jNGlxF2QHMP20lNhYflmYUg2zOl6ACS
         xddRPwOKC6bruYnSMpyYG+Jw0jugsxrRoEetqBagDRaE0fwhziOkqyTsCxi+mtiRAkLs
         RrFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272632; x=1729877432;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pIwxbRZVrfFzp4u66A2R0qkaAAbBsBlPHQdtBQ96TSk=;
        b=wq2LDGrivwPGk7WepEDA5N8rHRbELViPbstWJc6wRCL8OTBrWQaHGgn2Agg7BLN0su
         +NXfW2WUcy3tiuxppUO286ztAJICDDqQNi8nfpwt21FwqINwCtvW7ypRXhAI/un1tpr/
         s3To+rYQqCJvQkKEPRPf6kWskoXiU0ByvtyQg932PCdlkux5ApJx26gkOKOMAG1dII+s
         u4UJi0jXXA7sHCCr0dcPktEv4C/tiOj3+BVg59dEvFD5iCICmHMqxgUQN05YgktVVKTW
         OCjVve4EK7HK29eLiUxvTAucIyeOEnsToJ0EQ3hSyyAT2YXrf2yb/w4iRWQSinuX6Fiw
         ATTA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVbs5rkAf2yCsu2K3aqSxBleYnixr+iDhT/w4j/otPWGDG1djGN0GiYnYz+QkGEUB6htROgfg==@lfdr.de
X-Gm-Message-State: AOJu0YwX5K+RHViTWgjxsZ3ctsRlC+9y7zQjr2tA61Ijo3acVZ2ZcdI5
	ynjYhPXdGJPM8oLfAjTDE6xahczMKoHQFhNikTkSqeE8OEaGi9W/
X-Google-Smtp-Source: AGHT+IFWMQvHmXxjH3RdDlukpfntdj08fvOGkOg+6sj8El9V6FCwei/7sHODAE8/xmJl6mQqDyVHUg==
X-Received: by 2002:a17:90b:4b0d:b0:2e2:de95:34eb with SMTP id 98e67ed59e1d1-2e5616eba4emr3945163a91.10.1729272631966;
        Fri, 18 Oct 2024 10:30:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:dc16:b0:2e2:840e:d4a7 with SMTP id
 98e67ed59e1d1-2e3dc179dbcls1373629a91.1.-pod-prod-06-us; Fri, 18 Oct 2024
 10:30:30 -0700 (PDT)
X-Received: by 2002:a17:90b:3852:b0:2e2:c7f8:8ba8 with SMTP id 98e67ed59e1d1-2e561a4ce67mr3124938a91.40.1729272629850;
        Fri, 18 Oct 2024 10:30:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272629; cv=none;
        d=google.com; s=arc-20240605;
        b=SRHHy9oBb8f1o1qDLUtekFuIjzdoE7utNp23pEM1mo8T2zxgbmnuTXA9tV5BFwRsP6
         t2ciVMTpyzrTi+gZfkI1xBfUugGTjp6WGTFhthw5rSVzfnBhB4kIVIaKMuW+wLrHpVtc
         txfdONJf97HfrIxyhiguK+uglww2EIAOQ9jHQKwyVhFqNpMOL3mn10Ro6PPEhCA97JFq
         /YoSYwq3/KFVEKQJTOTbYtbRx6kYe7mmfKRSDxOnw1LZpPF0vgIVTnyQKloK4f9G2Wa6
         tCYqN2ZXi7Kc45ZeYPHxcR2T9k6RFBAsWfHoyr+3Kc/H9eGvGqUnxqg99OQoQzXALyYA
         1O1A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Y7m6nw0SlLNWzWwVTYubL573BHmMjcLP6yP7O1snSbI=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=asuINwZp6uzXbRc8KJceE4/jjlKicjua5JMt5WSfiKqpuTUHrxK5hXWbwT4/NY9AT/
         E9tQgutSQnXTNVSXpsXVdlt7baQMRRmLJPQ31omqrvtqAgkv7L8iVCmZyr2AQu1sTk3M
         SkG/TEie15z5Nj90U/0qixc5cHNvRQadfV0CVijeAucHju1Ovlb/wIOQX0qboGrYCYFF
         iPq6tPSVpzxby9AfBgrXZGrIWECLazWIEDSyOpSmtRO2kXD7pv8rbHWjYx0YDq95ZTMH
         t3e/Zw5BTiW82lDVC7YB1infNneOmxQ2S7QDkuuU7yEABPdp1iUdeJmyymywq2FoAVID
         U5Fw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="f30jA/+F";
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x435.google.com (mail-pf1-x435.google.com. [2607:f8b0:4864:20::435])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2e55d248267si134883a91.0.2024.10.18.10.30.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:30:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435 as permitted sender) client-ip=2607:f8b0:4864:20::435;
Received: by mail-pf1-x435.google.com with SMTP id d2e1a72fcca58-71e4e481692so2056444b3a.1
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:30:29 -0700 (PDT)
X-Received: by 2002:a05:6a00:3e0f:b0:71e:4a1b:2204 with SMTP id d2e1a72fcca58-71ea331b398mr4152501b3a.25.1729272629392;
        Fri, 18 Oct 2024 10:30:29 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.30.24
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:30:28 -0700 (PDT)
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
Subject: [PATCH v3 02/12] book3s64/hash: Remove kfence support temporarily
Date: Fri, 18 Oct 2024 22:59:43 +0530
Message-ID: <1761bc39674473c8878dedca15e0d9a0d3a1b528.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="f30jA/+F";       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::435
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

Kfence on book3s Hash on pseries is anyways broken. It fails to boot
due to RMA size limitation. That is because, kfence with Hash uses
debug_pagealloc infrastructure. debug_pagealloc allocates linear map
for entire dram size instead of just kfence relevant objects.
This means for 16TB of DRAM it will require (16TB >> PAGE_SHIFT)
which is 256MB which is half of RMA region on P8.
crash kernel reserves 256MB and we also need 2048 * 16KB * 3 for
emergency stack and some more for paca allocations.
That means there is not enough memory for reserving the full linear map
in the RMA region, if the DRAM size is too big (>=16TB)
(The issue is seen above 8TB with crash kernel 256 MB reservation).

Now Kfence does not require linear memory map for entire DRAM.
It only needs for kfence objects. So this patch temporarily removes the
kfence functionality since debug_pagealloc code needs some refactoring.
We will bring in kfence on Hash support in later patches.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/include/asm/kfence.h     |  5 +++++
 arch/powerpc/mm/book3s64/hash_utils.c | 16 +++++++++++-----
 2 files changed, 16 insertions(+), 5 deletions(-)

diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
index fab124ada1c7..f3a9476a71b3 100644
--- a/arch/powerpc/include/asm/kfence.h
+++ b/arch/powerpc/include/asm/kfence.h
@@ -10,6 +10,7 @@
 
 #include <linux/mm.h>
 #include <asm/pgtable.h>
+#include <asm/mmu.h>
 
 #ifdef CONFIG_PPC64_ELF_ABI_V1
 #define ARCH_FUNC_PREFIX "."
@@ -25,6 +26,10 @@ static inline void disable_kfence(void)
 
 static inline bool arch_kfence_init_pool(void)
 {
+#ifdef CONFIG_PPC64
+	if (!radix_enabled())
+		return false;
+#endif
 	return !kfence_disabled;
 }
 #endif
diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index a408ef7d850e..e22a8f540193 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -431,7 +431,7 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;
 
 		cond_resched();
-		if (debug_pagealloc_enabled_or_kfence() &&
+		if (debug_pagealloc_enabled() &&
 			(paddr >> PAGE_SHIFT) < linear_map_hash_count)
 			linear_map_hash_slots[paddr >> PAGE_SHIFT] = ret | 0x80;
 	}
@@ -814,7 +814,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();
 
-	if (!debug_pagealloc_enabled_or_kfence()) {
+	if (!debug_pagealloc_enabled()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
@@ -1134,7 +1134,7 @@ static void __init htab_initialize(void)
 
 	prot = pgprot_val(PAGE_KERNEL);
 
-	if (debug_pagealloc_enabled_or_kfence()) {
+	if (debug_pagealloc_enabled()) {
 		linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
 		linear_map_hash_slots = memblock_alloc_try_nid(
 				linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
@@ -2120,7 +2120,7 @@ void hpt_do_stress(unsigned long ea, unsigned long hpte_group)
 	}
 }
 
-#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)
+#ifdef CONFIG_DEBUG_PAGEALLOC
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
 
 static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
@@ -2194,7 +2194,13 @@ int hash__kernel_map_pages(struct page *page, int numpages, int enable)
 	local_irq_restore(flags);
 	return 0;
 }
-#endif /* CONFIG_DEBUG_PAGEALLOC || CONFIG_KFENCE */
+#else /* CONFIG_DEBUG_PAGEALLOC */
+int hash__kernel_map_pages(struct page *page, int numpages,
+					 int enable)
+{
+	return 0;
+}
+#endif /* CONFIG_DEBUG_PAGEALLOC */
 
 void hash__setup_initial_memory_limit(phys_addr_t first_memblock_base,
 				phys_addr_t first_memblock_size)
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1761bc39674473c8878dedca15e0d9a0d3a1b528.1729271995.git.ritesh.list%40gmail.com.
