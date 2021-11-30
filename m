Return-Path: <kasan-dev+bncBAABB66ATKGQMGQEGTKWHXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43b.google.com (mail-wr1-x43b.google.com [IPv6:2a00:1450:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 19C1C4640F2
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:06:52 +0100 (CET)
Received: by mail-wr1-x43b.google.com with SMTP id d7-20020a5d6447000000b00186a113463dsf3864586wrw.10
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:06:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310012; cv=pass;
        d=google.com; s=arc-20160816;
        b=aDj4ld34F4j0QYKvW0nhMULir53kB+nURSKZuquj72KAhdMkPDCsNZJK3uoIzx1Jnu
         OvTCchp4poQsNzXwSIscJ68QK6UEBncCcKBYJiQ16q69KoYbW/2NpUJvEAHsC7zc3MTJ
         lc6a2P53z2A8PCri49kiFusBxWZharQyOelcEWrIZSwc6lQ6fB7TypbiuDn21i6ZCiR7
         A5SjJp+seTuqkkodCTJO3j2TR5O6KiNUGWUtYjq0xvb2Du3Y7FmSykxKCHMDfb6alhGl
         TH2xjsfgcMVFll9k68MpO85xtk4DpVkflkNORiXVHTGFJvinpGih9/KmuOyz2geNzYQ3
         aUbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3FZLUINOQg2Cxcw9uq9z6JEEepqkjmNzeBIz8Ci7OMM=;
        b=kwRPew8bqibacy9tA+euj24RZkXNyRQQ/eGiXxkYw7+6Pf3MNdX8UJ8XiDHDdoYDFE
         k5OvcoSICGh2a5G5gnLC0VeudySBWN86FUt/3ewcot6LaT/bCi/7TxlrSglK0WfePqwK
         JU8o5cZ39eRpkY44DpH6LjM3PiVkOd2EKIpTMS/At/ciGzYdiuKKhxnxj6wb2ldgqsWe
         vAs30BLj3gPj/lL8xnuS2r84tPw/oSXspnd5ggwpYJ270BWsCdQ+rhSJwdh65FabUiTT
         R+TwhK/Ku2GUltOpTuZO/Lx1v1LzDeHvuYuxx9hQmEkTo9zOBCsb6EA4MHkuZ1Ws2awK
         0xwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jdcRHqIG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3FZLUINOQg2Cxcw9uq9z6JEEepqkjmNzeBIz8Ci7OMM=;
        b=KqZC719fpZr+yDw89uk0MMzgQ/LOIPih7c678rYpOtIN3JLrtn1o+tw5R94wIYUiP+
         rBRZGSHKDr9DYxBofjp7uSOzmAoqrn/2UlN6w1USZ1D6z3yx4K+/faQFhTAc1LrLryOO
         r2bhYBedJQmCZM0Nv+Xyy6Gmq8n/3xR2Ye+626rfPiFuSij1YQiXMDDz4Izvlm8RJ3wO
         xOxLSG640Yf3GJCr2R67yjZOuNQhw//cuvgzjSKBuIy+RIh1Chkxzzkal6CBcUK/1Qf5
         D9zNOVjQqxxatytO8dVaBvO135bvo+MCBeToAr6OoO3TAjhQsI2nyWCkY7Eq8JuBwCjg
         rPyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3FZLUINOQg2Cxcw9uq9z6JEEepqkjmNzeBIz8Ci7OMM=;
        b=eU5Ww3SK6vnlvFb3PkMcXHPXIenHvDli0Ae5PEsREZNmzFAWoBRu+5Z76SiCLOfeZx
         lqh0eUeiMTF/mwZxI8FCaEB1D2wuJusYN3NhmfQuFyWqtwP2y4LsPydFA4wjF+HLTGnu
         XxFDRzOiTkwvRjsAf3ibd0fswEWY3oZ+lmHmmhaaFLS9fMdVFZi94g2YklGGwB78xk4m
         8qKyS0rXQsCOwZT2/4215qXsm8Dm6y4G+j8wmLEzBIkoKbx+vl1QhnX/ZFAEyXi12ATq
         oNtddAJ/rzd6ImQF4Il2NAUgngg+KCvtaKTSq896mMLtW0UYlvuWIBv6mEVgaX5EKWzk
         jIQg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532q+py+EVr0Peuz+PDuW3DAulVFGvC0VzIUb0rbRjaN+1nhtohW
	7+soPdObURrH3bofCRP4NPA=
X-Google-Smtp-Source: ABdhPJz6L0c8R34EEJINdpBLC9WlyipzPIy1sjbwxPGtYSRvEUw0lXsS58bFIIO2NSgwbLZZrdo7UA==
X-Received: by 2002:adf:8bd8:: with SMTP id w24mr1914468wra.540.1638310011940;
        Tue, 30 Nov 2021 14:06:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4092:: with SMTP id o18ls196690wrp.1.gmail; Tue, 30 Nov
 2021 14:06:51 -0800 (PST)
X-Received: by 2002:adf:db47:: with SMTP id f7mr1937467wrj.113.1638310011286;
        Tue, 30 Nov 2021 14:06:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310011; cv=none;
        d=google.com; s=arc-20160816;
        b=ZV/LiFMVrjam9BEzVoxpYYTY8/2Mh6IV9XUP+gODxopd04S9yB4yDUcXf96F88Xw2Q
         x1eWQdWUsjA04TFsYcqzR8FwdSb/sfxOd6kiFPjb7Qh3ucqw2wLCSrzQXOgTlIJYonMJ
         4NKs51oJ+6ocUfwHaUBHPKUBIouSwYDHTVFAIH59EKQ9JLlqG5kUF2SQFUVfljrtuuuR
         WlbsoFrY6Slvf8mr8KQOCvrNGxXHZ6b0G19HzKZn9OpWkycZNJydG+2pJtO6oHZl1gCq
         +cQyFDeHZ01TeL7lM3lO0feHvsThkfEu1XjVqCBxRR3M1FOdZyRGJgFHVT0S2SRwdNgY
         E3Jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5vrmXGtyQkXmrhoONS3mEv98+EJ5a6iWSXEuOfvldi8=;
        b=d9PoZdGi/n1dTjdk96ozpHtNvN6zJvHkwySKz5je7kOYvjctHqg4JvAoXobzUFEoSX
         PaqAgduo5j4PWtbKzzc9qRUGAS3/scT2rDhsMoJfkFjBZK3kRo+r/efOhc1hLxrEQFLr
         f7JqcmA/nanzxVUQ0qd5wLY9l7Vr/CNmKNQGaI9c/0FYG2KpjzQoj3IJsJigPNMYJpV+
         8kxsyZdjOlZm1hJnAVzmGt4Ta/kcPShFIyyKKQH61IZTy5EL1miuRv+WV7EcIgANtK2d
         buE05e6+IgH7uDpTJh0ODAbrYu7FY8bjtjTm/Q3KYpCLqmaJaPNwscprVMWGRGQWNAmW
         XCRQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=jdcRHqIG;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id o19si698924wme.2.2021.11.30.14.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:06:51 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 16/31] kasan, x86, arm64, s390: rename functions for modules shadow
Date: Tue, 30 Nov 2021 23:06:49 +0100
Message-Id: <21d500c89d8ba7ea0399553b4ef9cd393ecd1c00.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=jdcRHqIG;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
---
 arch/arm64/kernel/module.c |  2 +-
 arch/s390/kernel/module.c  |  2 +-
 arch/x86/kernel/module.c   |  2 +-
 include/linux/kasan.h      | 14 +++++++-------
 mm/kasan/shadow.c          |  4 ++--
 mm/vmalloc.c               |  2 +-
 6 files changed, 13 insertions(+), 13 deletions(-)

diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index b5ec010c481f..f8bd5100efb5 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -58,7 +58,7 @@ void *module_alloc(unsigned long size)
 				PAGE_KERNEL, 0, NUMA_NO_NODE,
 				__builtin_return_address(0));
 
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/s390/kernel/module.c b/arch/s390/kernel/module.c
index b01ba460b7ca..a753cebedda9 100644
--- a/arch/s390/kernel/module.c
+++ b/arch/s390/kernel/module.c
@@ -44,7 +44,7 @@ void *module_alloc(unsigned long size)
 	p = __vmalloc_node_range(size, MODULE_ALIGN, MODULES_VADDR, MODULES_END,
 				 GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
 				 __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
index 169fb6f4cd2e..dec41d9ba337 100644
--- a/arch/x86/kernel/module.c
+++ b/arch/x86/kernel/module.c
@@ -77,7 +77,7 @@ void *module_alloc(unsigned long size)
 				    MODULES_END, GFP_KERNEL,
 				    PAGE_KERNEL, 0, NUMA_NO_NODE,
 				    __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1031070be3f3..4eec58e6ef82 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -453,17 +453,17 @@ static inline void kasan_populate_early_vm_area_shadow(void *start,
 		!defined(CONFIG_KASAN_VMALLOC)
 
 /*
- * These functions provide a special case to support backing module
- * allocations with real shadow memory. With KASAN vmalloc, the special
- * case is unnecessary, as the work is handled in the generic case.
+ * These functions allocate and free shadow memory for kernel modules.
+ * They are only required when KASAN_VMALLOC is not supported, as otherwise
+ * shadow memory is allocated by the generic vmalloc handlers.
  */
-int kasan_module_alloc(void *addr, size_t size);
-void kasan_free_shadow(const struct vm_struct *vm);
+int kasan_alloc_module_shadow(void *addr, size_t size);
+void kasan_free_module_shadow(const struct vm_struct *vm);
 
 #else /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
-static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
+static inline int kasan_alloc_module_shadow(void *addr, size_t size) { return 0; }
+static inline void kasan_free_module_shadow(const struct vm_struct *vm) {}
 
 #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 4a4929b29a23..585c2bf1073b 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 
 #else /* CONFIG_KASAN_VMALLOC */
 
-int kasan_module_alloc(void *addr, size_t size)
+int kasan_alloc_module_shadow(void *addr, size_t size)
 {
 	void *ret;
 	size_t scaled_size;
@@ -529,7 +529,7 @@ int kasan_module_alloc(void *addr, size_t size)
 	return -ENOMEM;
 }
 
-void kasan_free_shadow(const struct vm_struct *vm)
+void kasan_free_module_shadow(const struct vm_struct *vm)
 {
 	if (vm->flags & VM_KASAN)
 		vfree(kasan_mem_to_shadow(vm->addr));
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d2a00ad4e1dd..c5235e3e5857 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/21d500c89d8ba7ea0399553b4ef9cd393ecd1c00.1638308023.git.andreyknvl%40google.com.
