Return-Path: <kasan-dev+bncBAABB4EB36GQMGQEJDSVSRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 96C4C4736E0
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:53:53 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id c40-20020a05651223a800b004018e2f2512sf8077215lfv.11
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:53:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432433; cv=pass;
        d=google.com; s=arc-20160816;
        b=adD/5NkVfmWsFarOSrbPSHEpjKYCoXOyppxdbKRtDja0lEaSGZCxj37M+jTU5luEKy
         PYkIrlNRtOghcYTwWFJeM8dBpOWTW6Vcks+2VBMKIrxmbCEIzPwAgFu52yrUe8p0fUYx
         B9Mou3n76pcs829D3Jr0ELObZlKZz7b/QNr9GhuFcV04OhatK5bqsYBVDyPqhnhXArVy
         0tL9IbtA1c/NraM+HBENeejgoMDVZn6sJgzDvLtcakL7zOxJ12Smlx8O8FyIVG/pv5Na
         drjgt/CeDwwwRlxDc7TTB+2i6JNIIa119D5dDkV/HnD0MP9YhbGTLQ+hyoeMULs+psM5
         TDXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OFhcW2+KenjJ8a0OQgE22lIqbiSPfs3chSNqKmmu1Bo=;
        b=f0pTR2cMFtR+PcZfLuAWr3HxuX2Nehh6NH/6QfGNyiu9HP2XFArLujqPobLfHrtuE5
         0DxF9t5/0tTjuJa6HFvjOHbtNbopXyUxpLNZMaGn46mDxsa3R9GXKDCaolYekyvnDlhD
         CwcqC8nXiMyYXJJVeJjRVv9mJJW/GZygOyF9UMxiqS+8ZmAr9XywjhM7ulwwqP7BfUbL
         /b/KZWfiPsGsYLO7PS9BQa5fiYIBVG7nr+GvjEJn5O/AZmdFddWiBc8ndnuhtjMs/d/s
         9Arnv/RvH7RSAPmK4MrzxYKHQgONUT/4WJIVYCJ+q1wvaOW9mfisGA3j62GKi9f7UWqh
         f0SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=l9cgcG2b;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OFhcW2+KenjJ8a0OQgE22lIqbiSPfs3chSNqKmmu1Bo=;
        b=rmafMpuPL2FZW4mX6dNyqRMjyfRBrSZInNJsz5oT+rfHboss5+20aiHJ+QSsvS9AqU
         STzMVUZ1eVCxiMiIqi21yNKe4wqGyveWvQwixapF5w4ZR3C2J2o44YkmpqzbUODylHz2
         5oUjMu8n2hBtL4E9VojAY0rbta/sfvnU0CJ9fLCda/v1S7moBHRSf+59oL6/l0eX31B9
         XyftsjnJjUmPWssViV220Um67376WQtmAXZ6cPgrO82IWD5Me/zzHK3ebioVkQoieeV1
         vSgHe3E02BzesNFpUJdulGxIsA9w7hWiD3UTHSldAX1HQ8Zp4joljL6pW6+S5ZAWZ5Jz
         LZlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OFhcW2+KenjJ8a0OQgE22lIqbiSPfs3chSNqKmmu1Bo=;
        b=iPde1IiD4Mk9HcyFs8rbYnmL7a83Q04cvN3YAhGUcOXEUghNBvLB6pTxa+3LWXrdnS
         RCk2T2AtxP1nuUPWGHHMXDWIXPlCbht5AkAcEQXdOnVLT24mG2dSo4wvTZzDw0D7+zPh
         hOoqBTtLeAfWUj8ZK3iNL3xiO2n8pOwe+0tsqNIhpAiuH3y9GcdPlLbXtUsD1rUmQjwi
         ip0qEk72d29jAWecfsnaAd2Z208LqF5KuePiiH0PnXw5D1bPY7IwBnqE4Yo/2rAt04p1
         LkaRg3uUS4qYR8wFoiLEIXj4cGaSLQpVvsmKGuJMuGljkHToxs+ufzGbERzexiNDJnf4
         ECkA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533oT2AdhTAqQ2U5TMpCx0+dUlR42rAFR1jGByMB8d9vX0zTV/2H
	GugYBn+IiWOgShbv4j+9KO0=
X-Google-Smtp-Source: ABdhPJylYPj8EXZqynel/JVzPkaL2Gn/g2gmK/7ocOHInzKZv3fy0EykdNaS0/pIAGgqA/AnjkrBbA==
X-Received: by 2002:a05:6512:1304:: with SMTP id x4mr956848lfu.484.1639432433165;
        Mon, 13 Dec 2021 13:53:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:234c:: with SMTP id p12ls1551762lfu.0.gmail; Mon,
 13 Dec 2021 13:53:52 -0800 (PST)
X-Received: by 2002:a19:48d8:: with SMTP id v207mr909896lfa.217.1639432432423;
        Mon, 13 Dec 2021 13:53:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432432; cv=none;
        d=google.com; s=arc-20160816;
        b=Uqv7Ywp9ZrejyQRLaWJea0l4Md4e4LbBPaoxzSQs1Cp+A18kdapvHTGCvLuOq0HAGk
         e7AtXj8dVStAQ33cdVwShiilHPFI4KKZkfpCTjt0pkeqDFTK3DzxXlzWoM/9E2EuOQWa
         2fSyCXHPfIvaHOXAptEkIc9eVtWq9y+0JU5jUePPlCTaNuHLN1xI84DrgI2SIgNcfGoz
         72H4eCGpO5TYoS5nqfPPB8FVSBe+qVVuMnJorrnO5KmgdUNTigQfuanTkNgOtRam8t0k
         ul9mTj1jP2CZPPPpbDRcMYr8A0Fklsj4iW/p7Q4rRVYqIv05hDokQHgNgfH0+Il+rQO7
         PPBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9dVngw7BBBYIM7SwVKtk6s7/OcNf3Aanlkh6omsgm0k=;
        b=qfLJJUa1L2s9cQ9Dm2/gNBQekH3GwdxnYWF/oY9zGx2laTtqYZlftXjUKiocFRWZ25
         CT9b7fj9mUvG3QaB9GAH/jyW4HxdbvUM6fZ4MOyvCuSDK857F7689OLBxho+Yl7g2DNn
         p6yLLqEEb44huHrFBb+8TEfKxEqsJSRgPg/kYwfmF/fUrjJOwjE4sRMXwm5pHtpeMSum
         kGyRdL2qS4wA46sJAqZ687l1sTr2nsDGzaFTZroBah3aJ6PqeDyUQC70FY7Q6zjkx+Sn
         76d41eNEK+p/RRLxv4h7nc+sANAbn+Exh8FRE6myZ7UTF56iwa7BWdaDGlOZp34AVJFc
         xNdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=l9cgcG2b;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id f11si646240lfv.6.2021.12.13.13.53.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:53:52 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 17/38] kasan, x86, arm64, s390: rename functions for modules shadow
Date: Mon, 13 Dec 2021 22:53:07 +0100
Message-Id: <0277a361e807ca199fbc3022a9438491a6cc816d.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=l9cgcG2b;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Rename kasan_free_shadow to kasan_free_module_shadow and
kasan_module_alloc to kasan_alloc_module_shadow.

These functions are used to allocate/free shadow memory for kernel
modules when KASAN_VMALLOC is not enabled. The new names better
reflect their purpose.

Also reword the comment next to their declaration to improve clarity.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
 arch/arm64/kernel/module.c |  2 +-
 arch/s390/kernel/module.c  |  2 +-
 arch/x86/kernel/module.c   |  2 +-
 include/linux/kasan.h      | 14 +++++++-------
 mm/kasan/shadow.c          |  4 ++--
 mm/vmalloc.c               |  2 +-
 6 files changed, 13 insertions(+), 13 deletions(-)

diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index 309a27553c87..d3a1fa818348 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -58,7 +58,7 @@ void *module_alloc(unsigned long size)
 				PAGE_KERNEL, 0, NUMA_NO_NODE,
 				__builtin_return_address(0));
 
-	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/s390/kernel/module.c b/arch/s390/kernel/module.c
index d52d85367bf7..b16bebd9a8b9 100644
--- a/arch/s390/kernel/module.c
+++ b/arch/s390/kernel/module.c
@@ -45,7 +45,7 @@ void *module_alloc(unsigned long size)
 	p = __vmalloc_node_range(size, MODULE_ALIGN, MODULES_VADDR, MODULES_END,
 				 gfp_mask, PAGE_KERNEL_EXEC, VM_DEFER_KMEMLEAK, NUMA_NO_NODE,
 				 __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
index 95fa745e310a..c9eb8aa3b7b8 100644
--- a/arch/x86/kernel/module.c
+++ b/arch/x86/kernel/module.c
@@ -78,7 +78,7 @@ void *module_alloc(unsigned long size)
 				    MODULES_END, gfp_mask,
 				    PAGE_KERNEL, VM_DEFER_KMEMLEAK, NUMA_NO_NODE,
 				    __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b88ca6b97ba3..55f1d4edf6b5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -454,17 +454,17 @@ static inline void kasan_populate_early_vm_area_shadow(void *start,
 		!defined(CONFIG_KASAN_VMALLOC)
 
 /*
- * These functions provide a special case to support backing module
- * allocations with real shadow memory. With KASAN vmalloc, the special
- * case is unnecessary, as the work is handled in the generic case.
+ * These functions allocate and free shadow memory for kernel modules.
+ * They are only required when KASAN_VMALLOC is not supported, as otherwise
+ * shadow memory is allocated by the generic vmalloc handlers.
  */
-int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask);
-void kasan_free_shadow(const struct vm_struct *vm);
+int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask);
+void kasan_free_module_shadow(const struct vm_struct *vm);
 
 #else /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
-static inline int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
+static inline int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask) { return 0; }
+static inline void kasan_free_module_shadow(const struct vm_struct *vm) {}
 
 #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 94136f84b449..e5c4393eb861 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 
 #else /* CONFIG_KASAN_VMALLOC */
 
-int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask)
+int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 {
 	void *ret;
 	size_t scaled_size;
@@ -534,7 +534,7 @@ int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask)
 	return -ENOMEM;
 }
 
-void kasan_free_shadow(const struct vm_struct *vm)
+void kasan_free_module_shadow(const struct vm_struct *vm)
 {
 	if (vm->flags & VM_KASAN)
 		vfree(kasan_mem_to_shadow(vm->addr));
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 841158aa9ca7..a6b61e24a703 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2524,7 +2524,7 @@ struct vm_struct *remove_vm_area(const void *addr)
 		va->vm = NULL;
 		spin_unlock(&vmap_area_lock);
 
-		kasan_free_shadow(vm);
+		kasan_free_module_shadow(vm);
 		free_unmap_vmap_area(va);
 
 		return vm;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0277a361e807ca199fbc3022a9438491a6cc816d.1639432170.git.andreyknvl%40google.com.
