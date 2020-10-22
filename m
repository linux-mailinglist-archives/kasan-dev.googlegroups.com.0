Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6UNY36AKGQEFBSLYHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A43E295FB5
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:55 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id a73sf658151edf.16
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372795; cv=pass;
        d=google.com; s=arc-20160816;
        b=bgX2PVBp5QN3MafVhSikX4cLOGZcuYnh5UL09u2qx5Kdff5+5ZfneKZ78HpXvWjC8h
         J0Ze7liSdjBv/RwQZQbYo4+f79KjhgxTLeQlp/1LXpWypWmuOPFxxxcNFJsifMW8M3GO
         3EiEe9i210tW06tyepZbhn7dw48SzHTRjTgzp8iAFvl5XXN5bY9xduhwof65TtVgLDR1
         KLuZaNMQWzYAObgSCNuxinxgs9UBpJr2Og/Jk9kqTmp7d7oHNReWCzNxPJpB14fMDMlO
         hAB1CwS9QLowY9DSNsxk0A86fWDen99O5YNw9vNTQN9UU03H6mrT4ETBgqVsFhmFcS/a
         /20w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=Fo5Ap3KYI3gYC5Zxf1m0nTb+XWW9lcnZq0asIkOi0/c=;
        b=dCqVg0QVWPQiMfET61B3H9IKgZv1b+SM14C/dTfh/nGarAktx7O88pJ3lrwmhZdPGT
         /lLwD1SmA+tekWhS7HyReYH2BgXe7dGS6KGfTnzCSTap6X9XRbAPUnv8heY5zlapoJ4l
         fMIPgjXR1Sq6rjeELyyZkoljNIe7r5wpelHExOfRZ3KxLRpN/IrBVo1UiebVfipxJUv7
         +IdIqHAjpeqA+eVwlLKTjRy9VHLEufD/+kztSLB3SLh/p7lNwWxUGJfZJo1w7uqrIQll
         zTZb9zL5WOOYr5YIdzm9CbbDnjblzv9XEb+ACMqOVXKCY+GQh75Z9VTR0vCobqk6i7DT
         em0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JUPSUQCu;
       spf=pass (google.com: domain of 3-yarxwokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3-YaRXwoKCVAs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Fo5Ap3KYI3gYC5Zxf1m0nTb+XWW9lcnZq0asIkOi0/c=;
        b=MWKmqWF/seZ++fajhZQ98uBRExHDvZW8GncKWk87B7vmEtJspETQwHDP1Oq5kwrIWc
         GSAEAt5BoyjLYcVDQDVGorArZWoe4LuLtf12YCVF1WFvcWFTNkeKTBo7vhccVW/Nl26L
         YzZnEVWG1uc6rYOd0pN4CK+uMjBb+XVVgZ7srD2jkMBF+lfYki3WvPWFf+RfigYuOrBN
         6qDej3aIYcIv0YsIiyQCG+CZI9uD4adVZ44ILDp7oTJyngUflBVSuj3zPpR28CzVyJES
         az8DCV18zeIc5oei31dqbVFhdZNMW3UrnfIiZ5kdFw3A//lKgWShy3wkaQat0xhQfdGa
         s37A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Fo5Ap3KYI3gYC5Zxf1m0nTb+XWW9lcnZq0asIkOi0/c=;
        b=gPEE2LlHOgA5pER5sT6igDp1B2qr9POM6RYArpnI9oTbqEVQECJPf2bAg7+02PCnn0
         EaIuM/RKz/stTaoJc9Gk1PIGUuo3VQCPBprc3FjBeJ/w3BIexRdDQdDDV9gh7r/0mTbW
         W2HPD6gCr5VzEwcag09nOQOSg/ltNxmJFeehW8JDPx6xdrnnQnfdkXOXj3lRhhmorZrV
         sEv2hByTwDvyev+OPE+YliziSXrQtUlWwLxRQEy9sUuLFQnzp63f37pEhu9GFYTnxSri
         bqF2dPrvq53KN4G1ManHByeAmcY6XTkr6P8DrN0idXrEW/PZfYe0GoUZSSoV0KuJowb1
         tMBQ==
X-Gm-Message-State: AOAM531gOxT/fdY6nRj8HjICrDNdLewAGEARrQrCAto7pQzUDk18SrFX
	ny4qMAoNePXJXFZW7vDXzzw=
X-Google-Smtp-Source: ABdhPJyZKnKHec/hn4iHQJ+jRj8kAS+ygvrLGT/VoBRKOkiIyJXRoUykyU2ALr7+yqUQrOOb3wuscg==
X-Received: by 2002:a50:ee19:: with SMTP id g25mr2286487eds.160.1603372794991;
        Thu, 22 Oct 2020 06:19:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cc8b:: with SMTP id p11ls337976edt.3.gmail; Thu, 22 Oct
 2020 06:19:54 -0700 (PDT)
X-Received: by 2002:a50:8acf:: with SMTP id k15mr2158409edk.351.1603372794056;
        Thu, 22 Oct 2020 06:19:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372794; cv=none;
        d=google.com; s=arc-20160816;
        b=MlHzF8r9fpEZZwh9R5f5Cc5x6U34bLxz/3l+t41alNjsyqTkCZfE++z7gSJ8gGCQKE
         O6zyNG9JY3kqKyDq/VkIEBWURMN7VCdjT8sHVI8SMMNveJKU88+JODP3uJztBdY0jTEF
         hnhGJF9heVO5X/t9Vl3PTN5Z9BfZn/m01h7CFpUyoQgNdnaECYTWdgqWUoKVesBciI3z
         J8TFYHqEKICOuZ0NIdF2iqttR9jGAoB3qBePruV17zFuyrjITHnKdYVCVzTNgBHaVW1z
         Ptv0MS+1Ph/izR/h0mYt5u8uhx23AdyNJ25j+CdeD6HoI0Trv3id+8NgGRHx9GqceoQP
         EzKg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=IcAE4Jyu1jclhjsbbav79rrFgX1+75/awDcEqCY54u8=;
        b=hHRvUS7n0TLNEn/TRQo+2oystW0axKx2jZlyYMErHnFbHGRLDpgUCHE9IcPdrykg9H
         mPUb54/bNbv4NUb4gpyHmyPIpnttaSk9kEgA6jw9Qwu6Vtzfzlu1V/170+1zh/VE0q0Z
         QfPYfFA6T9R8TVZXl+zrPiMJgqXGHZ4oZEHrGPOK44WEc0BzS/9pyioQHkdXNNvWHuLe
         bJKgSLtuZOoi2zF08eflHlZHN7QaDTPdqOiliHOn/iZWEEfEmydXEabkYJ7h0UmVySBU
         JmUxiOX2l4sTo9k9GOr1IiHy4zjjsIHM1zI5tv+Ygr0xW+cHkZDL8rObuMPyT41Mf2ss
         NI1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JUPSUQCu;
       spf=pass (google.com: domain of 3-yarxwokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3-YaRXwoKCVAs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x249.google.com (mail-lj1-x249.google.com. [2a00:1450:4864:20::249])
        by gmr-mx.google.com with ESMTPS id u2si62699edp.5.2020.10.22.06.19.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-yarxwokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::249 as permitted sender) client-ip=2a00:1450:4864:20::249;
Received: by mail-lj1-x249.google.com with SMTP id z8so706952lji.0
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:54 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a19:8a88:: with SMTP id
 m130mr896681lfd.503.1603372793217; Thu, 22 Oct 2020 06:19:53 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:04 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <6f87cb86aeeca9f4148d435ff01ad7d21af4bdfc.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 12/21] kasan: inline and rename kasan_unpoison_memory
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JUPSUQCu;       spf=pass
 (google.com: domain of 3-yarxwokcvas5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::249 as permitted sender) smtp.mailfrom=3-YaRXwoKCVAs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Currently kasan_unpoison_memory() is used as both an external annotation
and as internal memory poisoning helper. Rename external annotation to
kasan_unpoison_data() and inline the internal helper for for hardware
tag-based mode to avoid undeeded function calls.

There's the external annotation kasan_unpoison_slab() that is currently
defined as static inline and uses kasan_unpoison_memory(). With this
change it's turned into a function call. Overall, this results in the
same number of calls for hardware tag-based mode as
kasan_unpoison_memory() is now inlined.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Ia7c8b659f79209935cbaab3913bf7f082cc43a0e
---
 include/linux/kasan.h | 16 ++++++----------
 kernel/fork.c         |  2 +-
 mm/kasan/common.c     | 10 ++++++++++
 mm/kasan/hw_tags.c    |  6 ------
 mm/kasan/kasan.h      |  7 +++++++
 mm/slab_common.c      |  2 +-
 6 files changed, 25 insertions(+), 18 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6377d7d3a951..2b9023224474 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -66,14 +66,15 @@ static inline void kasan_disable_current(void) {}
 
 #ifdef CONFIG_KASAN
 
-void kasan_unpoison_memory(const void *address, size_t size);
-
 void kasan_alloc_pages(struct page *page, unsigned int order);
 void kasan_free_pages(struct page *page, unsigned int order);
 
 void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 			slab_flags_t *flags);
 
+void kasan_unpoison_data(const void *address, size_t size);
+void kasan_unpoison_slab(const void *ptr);
+
 void kasan_poison_slab(struct page *page);
 void kasan_unpoison_object_data(struct kmem_cache *cache, void *object);
 void kasan_poison_object_data(struct kmem_cache *cache, void *object);
@@ -98,11 +99,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-size_t __ksize(const void *);
-static inline void kasan_unpoison_slab(const void *ptr)
-{
-	kasan_unpoison_memory(ptr, __ksize(ptr));
-}
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
 bool kasan_save_enable_multi_shot(void);
@@ -110,8 +106,6 @@ void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
-static inline void kasan_unpoison_memory(const void *address, size_t size) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
@@ -119,6 +113,9 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
 
+static inline void kasan_unpoison_data(const void *address, size_t size) { }
+static inline void kasan_unpoison_slab(const void *ptr) { }
+
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -158,7 +155,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #endif /* CONFIG_KASAN */
diff --git a/kernel/fork.c b/kernel/fork.c
index b41fecca59d7..858d78eee6ec 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -225,7 +225,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 			continue;
 
 		/* Mark stack accessible for KASAN. */
-		kasan_unpoison_memory(s->addr, THREAD_SIZE);
+		kasan_unpoison_data(s->addr, THREAD_SIZE);
 
 		/* Clear stale pointers from reused stack. */
 		memset(s->addr, 0, THREAD_SIZE);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 9008fc6b0810..1a5e6c279a72 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -184,6 +184,16 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
+void kasan_unpoison_data(const void *address, size_t size)
+{
+	kasan_unpoison_memory(address, size);
+}
+
+void kasan_unpoison_slab(const void *ptr)
+{
+	kasan_unpoison_memory(ptr, __ksize(ptr));
+}
+
 void kasan_poison_slab(struct page *page)
 {
 	unsigned long i;
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index f03161f3da19..915142da6b57 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -24,12 +24,6 @@ void __init kasan_init_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void kasan_unpoison_memory(const void *address, size_t size)
-{
-	set_mem_tag_range(reset_tag(address),
-			  round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
-}
-
 void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8d84ae6f58f1..da08b2533d73 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -280,6 +280,12 @@ static inline void kasan_poison_memory(const void *address, size_t size, u8 valu
 			  round_up(size, KASAN_GRANULE_SIZE), value);
 }
 
+static inline void kasan_unpoison_memory(const void *address, size_t size)
+{
+	set_mem_tag_range(reset_tag(address),
+			  round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
+}
+
 static inline bool check_invalid_free(void *addr)
 {
 	u8 ptr_tag = get_tag(addr);
@@ -292,6 +298,7 @@ static inline bool check_invalid_free(void *addr)
 #else /* CONFIG_KASAN_HW_TAGS */
 
 void kasan_poison_memory(const void *address, size_t size, u8 value);
+void kasan_unpoison_memory(const void *address, size_t size);
 bool check_invalid_free(void *addr);
 
 #endif /* CONFIG_KASAN_HW_TAGS */
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 53d0f8bb57ea..f1b0c4a22f08 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1176,7 +1176,7 @@ size_t ksize(const void *objp)
 	 * We assume that ksize callers could use whole allocated area,
 	 * so we need to unpoison this area.
 	 */
-	kasan_unpoison_memory(objp, size);
+	kasan_unpoison_data(objp, size);
 	return size;
 }
 EXPORT_SYMBOL(ksize);
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6f87cb86aeeca9f4148d435ff01ad7d21af4bdfc.1603372719.git.andreyknvl%40google.com.
