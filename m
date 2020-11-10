Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRVEVT6QKGQEPJO72XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id DF70B2AE32F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:54 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id 64sf78906lfk.15
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046854; cv=pass;
        d=google.com; s=arc-20160816;
        b=b9dKfOAW2MTcNaca60rHcGxI6ZZj8f111Rq9Gh09pBkezeCgTwcIi+9PdPleXOGdTN
         JClrXYPfHGCXdLc9qmy8ny0gZQy/LxaoyH6VMrnqitP3K/uuRbMF/ZJ9IHpcQGNRTBqC
         c3hXoCwG7lxiDftrYkB9tDiVxrMrlvzKpn3XwcNeUQ2XwKDxoRiHFbYBFtd5rX5dJup1
         6RVgdM0hrGb6A81OahmW1fba3KbVsPWMI+sCSOjwoUJKEqen2FkeNomM8T6u6h/tErMb
         AkLc0nxBiBOL3Do7MvbDsJxx0NbBg9KpL3GerGk5pMYPj+CvWDyvBYoGjTQ2B1qp4EUq
         uEyQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sygUpVquksVj1dC/Ryfmx6SEp8YRoPHeQpAWU7W2tsI=;
        b=h+pmpQocPjkYWZ+LF2urH59oYMmyXQTLb5Telibj5rXtc47NQDtGre/A7ZEi24qRm0
         3vvOGIbSTq9wQ/WTQF6/sI/gb7RlXLWaiRAk1V7FBz76us/+hmFFHXBvz5h20+R9+JwI
         tX5S3uEt3otBolPWbiUzK/epVIq4+9P3kJjPNJHsKmnk4v6E0+G3duqJjM5H+gY0pfOV
         HaBR46ziTc7R0KrBhaUuAQQ2RJTnQTd9JmLjdDHDAKbJB56wwS+qmX+UePaQM5bPA2DB
         7HTupDMZ0jTVmFG6hUKTUK8UoPDNGoV2NAObneGo35NLqYrsx5elsuJNyPwZ6wI2BeK+
         k2vQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tjOoGMIf;
       spf=pass (google.com: domain of 3rbkrxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RBKrXwoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sygUpVquksVj1dC/Ryfmx6SEp8YRoPHeQpAWU7W2tsI=;
        b=aws8k6iBBqmpWhxZoub4ifUdCHrxVE+8GswODe4LU/82KH+ofT6a7yykPo0tvyGNCf
         1OLqt+xC7UAOgTtp/X5Q7u1QtLWVC2yTDwHbppwwK9238lOQvrgcYptUDntwsG0e4hmU
         tfZBNnPRBFD4o/zpKn8yt7ITUALC3x/Ajh1q7bmdiJEB/FVNGp3WWUKBqG1v5xpptBTo
         Pe9mw+L+paI+ECe8NAkZb0Xadhz0KpL4LRsv3UkaV/diXYimeKsBgb/8S31pLYFv6Sik
         49KhwY8EZeovpN7VGm/Pg9XdH88O/cI7d73kvuotE03C1KYgNraXQ4rp0KrRMxJWvwuU
         x1Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sygUpVquksVj1dC/Ryfmx6SEp8YRoPHeQpAWU7W2tsI=;
        b=BTvH5U71CdA5jtW94by6wIJKo6zBnJlKHoaQd+Cl49YjeOeb1tZL4GF8vJklkLLnw1
         rr9rCX0w9iNjmdaV9mm3PlvV/6IHh/qy799K9uiiqaY01VKLoa0Td4i8FFmWRdkeNP3v
         nqa9mmJgrFPeg6FAVSVVgCBgAYUWJM0Vg+rIb3VHdQsQaik/fbhP0o8FadRSAAOktSCK
         2b5uWE5kIjsieyPyeetEPZF5gXgpKva0QKeSM9WwzwKQ1L4BHRKswQghG0lZ9OaAPX9M
         AHoEl/CD48sTlCWSVPCxvhXklPWUK6zZnHpCIfw1PjytPuN64INaiR3ZD3VsgalyZaPG
         4qKQ==
X-Gm-Message-State: AOAM531ZE+b6V1xDnx11e4LxrbzhB/am4Oo8T0dXtEcX+frnjhlgNhs2
	1hbiznRhCs+aF25lNz6CLGc=
X-Google-Smtp-Source: ABdhPJweGpDLhCWJSMfVx0XRbPvzLcPF2pYPihEBxQcklCWr19vkAY9rbgiTfhGhTyS9KM4oRmvMJg==
X-Received: by 2002:a2e:914d:: with SMTP id q13mr9486305ljg.299.1605046854479;
        Tue, 10 Nov 2020 14:20:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b016:: with SMTP id y22ls2398754ljk.3.gmail; Tue, 10 Nov
 2020 14:20:53 -0800 (PST)
X-Received: by 2002:a05:651c:336:: with SMTP id b22mr9594348ljp.75.1605046853390;
        Tue, 10 Nov 2020 14:20:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046853; cv=none;
        d=google.com; s=arc-20160816;
        b=BCBIJe4BnGZ3l6PsIVeReulbD9C55eUoipXV+SdCZuQ96yj8ZmIWf7P/9ZS3F0RqGW
         ZYctePXTqsPTtCPmHvmd+fh9zKu+aF3o07oDRui2MFAEeXrEDqG/8jmv73PothK3rsD+
         aVwIZv53iXpjvmIAov5dxQorxKG8AjDVe3AgEPcrnqxZPLHjaHhRxQ3rJSw4Yot2gksa
         Cow0u5YKPN/pGuuhI6BmBDYgVyrOmgHQKuprfOkbe1qIGE81/LTuseo+080n6EG1796E
         T2PtzMlfZy1f7vGNFf677CcP2piUtryTgvAIwQBG6IiuhKH4EW0yNguCEGJNV2aY7s//
         F48w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=tuOEp1iVth583MBjSMMuaXP+cup9Jpeadd/jLYbzv5o=;
        b=TX3KOVjx69IcznTR/z9NlpySv2ExJSSl06c0mDCU/jm2UouoPlOs6dKfNH3WNDrGN4
         aOBvteu8DZpyiDYaHXxs51d36HuzL+g+fU9ApvVEZ1zzVthyWXmCWXif9umZ6r0CuKZa
         S4OeI+7kE2Y7weLJm3xu6cpfq7yHex77RmPZec25A/TU9JB8g8zi4KXg0dkwjynwpiE2
         J4cUwDvfom75eVRpDxhwi0IAxbOLUKaNWpO1q7Mk35jSPY6myC1JqaDaAffvLlphJ/T6
         xQv23pPCE17Q07+LIAQSK2pkDDNvj/6hT9OoBSk1evc+RaJ/gh9/HI3AJIAZuzjk7cqk
         +P7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=tjOoGMIf;
       spf=pass (google.com: domain of 3rbkrxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RBKrXwoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id h4si8367ljl.1.2020.11.10.14.20.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rbkrxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id u207so1866524wmu.4
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c458:: with SMTP id
 l24mr281240wmi.136.1605046852883; Tue, 10 Nov 2020 14:20:52 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:14 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <0a9b63bff116734ab63d99ebd09c244332d71958.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 10/20] kasan: inline and rename kasan_unpoison_memory
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=tjOoGMIf;       spf=pass
 (google.com: domain of 3rbkrxwokcrkzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RBKrXwoKCRkzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
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
and as an internal memory poisoning helper. Rename external annotation to
kasan_unpoison_data() and inline the internal helper for hardware
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
index 53c8e8b12fbc..f1a5042ae4fc 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -74,14 +74,15 @@ static inline void kasan_disable_current(void) {}
 
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
@@ -106,11 +107,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-size_t __ksize(const void *);
-static inline void kasan_unpoison_slab(const void *ptr)
-{
-	kasan_unpoison_memory(ptr, __ksize(ptr));
-}
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
 bool kasan_save_enable_multi_shot(void);
@@ -118,8 +114,6 @@ void kasan_restore_multi_shot(bool enabled);
 
 #else /* CONFIG_KASAN */
 
-static inline void kasan_unpoison_memory(const void *address, size_t size) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
@@ -127,6 +121,9 @@ static inline void kasan_cache_create(struct kmem_cache *cache,
 				      unsigned int *size,
 				      slab_flags_t *flags) {}
 
+static inline void kasan_unpoison_data(const void *address, size_t size) { }
+static inline void kasan_unpoison_slab(const void *ptr) { }
+
 static inline void kasan_poison_slab(struct page *page) {}
 static inline void kasan_unpoison_object_data(struct kmem_cache *cache,
 					void *object) {}
@@ -166,7 +163,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #endif /* CONFIG_KASAN */
diff --git a/kernel/fork.c b/kernel/fork.c
index 1c905e4290ab..883898487b3f 100644
--- a/kernel/fork.c
+++ b/kernel/fork.c
@@ -226,7 +226,7 @@ static unsigned long *alloc_thread_stack_node(struct task_struct *tsk, int node)
 			continue;
 
 		/* Mark stack accessible for KASAN. */
-		kasan_unpoison_memory(s->addr, THREAD_SIZE);
+		kasan_unpoison_data(s->addr, THREAD_SIZE);
 
 		/* Clear stale pointers from reused stack. */
 		memset(s->addr, 0, THREAD_SIZE);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index a266b90636a1..4598c1364f19 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -184,6 +184,16 @@ struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
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
index 0303e49904b4..838b29e44e32 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -30,12 +30,6 @@ void kasan_init_hw_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void kasan_unpoison_memory(const void *address, size_t size)
-{
-	hw_set_mem_tag_range(kasan_reset_tag(address),
-			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
-}
-
 void kasan_set_free_info(struct kmem_cache *cache,
 				void *object, u8 tag)
 {
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index ab7314418604..2d3c99125996 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -283,6 +283,12 @@ static inline void kasan_poison_memory(const void *address, size_t size, u8 valu
 			round_up(size, KASAN_GRANULE_SIZE), value);
 }
 
+static inline void kasan_unpoison_memory(const void *address, size_t size)
+{
+	hw_set_mem_tag_range(kasan_reset_tag(address),
+			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
+}
+
 static inline bool check_invalid_free(void *addr)
 {
 	u8 ptr_tag = get_tag(addr);
@@ -295,6 +301,7 @@ static inline bool check_invalid_free(void *addr)
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0a9b63bff116734ab63d99ebd09c244332d71958.1605046662.git.andreyknvl%40google.com.
