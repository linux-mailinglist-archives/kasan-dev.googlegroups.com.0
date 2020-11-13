Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMENXT6QKGQEK6VY7EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id DC5FF2B283E
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:33 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id t17sf3056169vsl.18
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306032; cv=pass;
        d=google.com; s=arc-20160816;
        b=SKunR+UoAZX6gzdzDvJ1Vbzo3dEn7yuFDeuB6mwIgmaYtI4fXadQMTrULiCRr59ZRC
         tWCv7YGLw0z+QMrF0NgasQzbMeFcqBq8AVhrwcbDfJVjamtXKrXqPEL5QLGk27ZRXfL8
         lbsDz7MO6k7/PkNM33WojemEZkIH09hhndXC6ujxWNod+SBf80ecB/+P+FHIE8nH23W2
         Bqpivf8wGm6ChzVrFrVuhLXQmqCJE7MAGsBeARkzgoCaFaXkuojjtrbHalvh4Jb3zs2U
         Q9kKlObBDj8SeojjyWuOIaCb+Vjurf8s8uTfbZ3PY/faACbyZt4gaJtwKJ5rafJeDVIx
         HwMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=3Cn54E/9B9nwDuVu2CS73RFV3UasraAXk11uw6Gq6QY=;
        b=nL7rGB30BdW6ZRjroEUko3sDDZpMd1gCFI43TcLs46IUcwvrsbLBxba1rHsBkuSdfo
         gHkui/FurZ1XOwm0tIz8BZIQdooMWA7Bb/f7rmySFUM0GJI0r9F+SvmqE5Lnh833XKaJ
         57RJwOlXLCqOP9kSsYAvkKrKPqg2jdgo950+gjOhwf2golW4H/Hk/+sHjzUTHWAT1BU4
         9vq3XNh6YQCarSjLJmBnbW0hVANR3E/1XfxuITrXQ+M06X3XGWywgqcFq+CYZHJRxxb9
         yV6P4GGjI9J10kroo7RIrglTpRzs/qkr1ykz7BuyvLlGLwAQGXj0B+KY5WdbxlaoI5Bq
         LQbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FZDE1cHf;
       spf=pass (google.com: domain of 3rwavxwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rwavXwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3Cn54E/9B9nwDuVu2CS73RFV3UasraAXk11uw6Gq6QY=;
        b=ltT36BdtDQ9SgQy8DuktAbGpgW9oNzUuog0VaSpjRhfONxiWu0M5C2daA+AMs3z6Tg
         bkqM1gDm89UeUKiJVh/K9wea9Of6TcKNi+Kndj9s3rDaHGUXHN2JX3RnOhd6ldAw2rKw
         EcEf1FtW/ERH9xGOH8vCDKTsEF7WT5lCiIlQjXDaLs24JE6ruZef/3P225gnRwgqONuN
         lNgVF71CttzX63UwQGpPDuZXbtvQhKiOiBOKGadG2DqyN6PfrafL+wtYmFOgpCKCKVCx
         zgO7YAZ0Q8ZUZKSK/JxF9JQ/ViPr8ouMR/llb8GLVQnmgzDQp7wRGx+G4Gpe6Bguq7zK
         DdoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Cn54E/9B9nwDuVu2CS73RFV3UasraAXk11uw6Gq6QY=;
        b=algOQu1ArYFcREwW60JS9ZGBFN7r2w6MMSa68siSu3URNqCY3rh95O/u0OtOAdZWFv
         L/RnMi4QQwT57VtU7GMOwXB+X3JylD4Kst2Go+lvlWQdKNfIB8pG+FaP+IsJzeAE2gxk
         bFUuj4j1HEKor/ILB+/4GDcxOSMqFv9HxxIwJcgFQVfyUVCBN/vbWxQ7/5m8PLy3c6rT
         haTGh5/WWpcFGoUIh0EFDbQB484p3y9scUJ+tvbI/oIzT5d7uxxdxC0rabWMsdSqQltQ
         0JaqfD/NDIkeAzNyi0bpNHAzt0SH6IZuU0LMwYAVBuTrznn316vTcBgjG+9i1lXsP47i
         i9YA==
X-Gm-Message-State: AOAM532i8gsijXdV9+LCBIAUycIU5IMZnbjhqX9Pu6X7q/FcxD8TAzmj
	Z4R60kT5QBrAIeD9FwQkR6M=
X-Google-Smtp-Source: ABdhPJwPT+CSM18qXCnSjJ/ci2CCsXFqWHfmZU7+AfpGIliQRkE454UlpSIGfyARSimugAgqGXXarg==
X-Received: by 2002:ac5:c96c:: with SMTP id t12mr3063531vkm.19.1605306032845;
        Fri, 13 Nov 2020 14:20:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3b19:: with SMTP id i25ls588809uah.5.gmail; Fri, 13 Nov
 2020 14:20:32 -0800 (PST)
X-Received: by 2002:ab0:15a4:: with SMTP id i33mr2834087uae.79.1605306032320;
        Fri, 13 Nov 2020 14:20:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306032; cv=none;
        d=google.com; s=arc-20160816;
        b=UQ+y0MY++N9av24OIJk4WpPLYABgmcyR1SaqF7GXVxAqN1+qSYhMz5D5iwpEtib2eM
         msQNDOHq7Iu8y5btGIeuXBtbHlsBSZu3B5jgJe6PWDD4lUajZUVQrBYDt7KsC7E4hh5j
         5AGib1cZezsSGTM/vFr0oJGMjtqGU+y9l2llQtayNRswNBCFaQOkPOldD3vSRaDcbqHs
         VABS2ZV1qMWm8QNEM7/KnJbAGCKjo0tv8S1VG7EH6Q6VCsrwa6Hy+rpXEWRKU+fT1U3P
         PBHJtrztKMiWPYFXE8x6M1tpeYH8soN7J42Osb9rezEZDLEyWXR+wVY54JzHZKgSueWT
         Sr5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=0OoqMffsjTTjhNupRd8vITAFnXjp5GgZqecD32hcplM=;
        b=Pl3khjelQvI9Pei6en8z/Ak4hCnQQrFnn0uUIEC7ar4A0f+VS7Ml76rEV0zHrViURx
         asL5DH9SoADUXZa8sCjxhZgqwF9I2WpO4B94u4bVSWgo+rHXGb2yj7jmYr8JYSlOpnnC
         OTC0BFdnxBE+uLuVrZNPHmpquZD3yFWi+DDpTX4P3+LcqWq+p8/Xux5PhngtRPWF1yg8
         wCbnjN+zj5kJNlmJzS2t4vEbVVOTtZAumrdXqCpBUbSWfvDQjytto5mmfAr1FTCLBMtL
         odjoogLOcJlH4a8niRb6j8fjQbFaptZ8Xnw19gFYjDQBBtXgrw6OK9kTNlql4iriAj05
         BboQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FZDE1cHf;
       spf=pass (google.com: domain of 3rwavxwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rwavXwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id k3si978779vkg.3.2020.11.13.14.20.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rwavxwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id 74so6237420qki.12
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:32 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b418:: with SMTP id
 u24mr4838113qve.4.1605306031906; Fri, 13 Nov 2020 14:20:31 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:57 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <4c2a23ccb3572459da7585a776d2d45f6e8b8580.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 07/19] kasan: inline kasan_reset_tag for tag-based modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FZDE1cHf;       spf=pass
 (google.com: domain of 3rwavxwokcxwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rwavXwoKCXwfsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

Using kasan_reset_tag() currently results in a function call. As it's
called quite often from the allocator code, this leads to a noticeable
slowdown. Move it to include/linux/kasan.h and turn it into a static
inline function. Also remove the now unneeded reset_tag() internal KASAN
macro and use kasan_reset_tag() instead.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/I4d2061acfe91d480a75df00b07c22d8494ef14b5
---
 include/linux/kasan.h     | 5 ++++-
 mm/kasan/common.c         | 6 +++---
 mm/kasan/hw_tags.c        | 9 ++-------
 mm/kasan/kasan.h          | 4 ----
 mm/kasan/report.c         | 4 ++--
 mm/kasan/report_hw_tags.c | 2 +-
 mm/kasan/report_sw_tags.c | 4 ++--
 mm/kasan/shadow.c         | 4 ++--
 mm/kasan/sw_tags.c        | 9 ++-------
 9 files changed, 18 insertions(+), 29 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index f2109bf0c5f9..1594177f86bb 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -193,7 +193,10 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
-void *kasan_reset_tag(const void *addr);
+static inline void *kasan_reset_tag(const void *addr)
+{
+	return (void *)arch_kasan_reset_tag(addr);
+}
 
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index fabd843eff3d..1ac4f435c679 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -180,14 +180,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
 					      const void *object)
 {
-	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
+	return kasan_reset_tag(object) + cache->kasan_info.alloc_meta_offset;
 }
 
 struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
 					    const void *object)
 {
 	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
-	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
+	return kasan_reset_tag(object) + cache->kasan_info.free_meta_offset;
 }
 
 void kasan_poison_slab(struct page *page)
@@ -284,7 +284,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	tag = get_tag(object);
 	tagged_object = object;
-	object = reset_tag(object);
+	object = kasan_reset_tag(object);
 
 	if (is_kfence_address(object))
 		return false;
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 68e77363e58b..a34476764f1d 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -31,18 +31,13 @@ void __init kasan_init_hw_tags(void)
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void *kasan_reset_tag(const void *addr)
-{
-	return reset_tag(addr);
-}
-
 void poison_range(const void *address, size_t size, u8 value)
 {
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(address))
 		return;
 
-	hw_set_mem_tag_range(reset_tag(address),
+	hw_set_mem_tag_range(kasan_reset_tag(address),
 			round_up(size, KASAN_GRANULE_SIZE), value);
 }
 
@@ -52,7 +47,7 @@ void unpoison_range(const void *address, size_t size)
 	if (is_kfence_address(address))
 		return;
 
-	hw_set_mem_tag_range(reset_tag(address),
+	hw_set_mem_tag_range(kasan_reset_tag(address),
 			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 0eab7e4cecb8..5e8cd2080369 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -248,15 +248,11 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 	return addr;
 }
 #endif
-#ifndef arch_kasan_reset_tag
-#define arch_kasan_reset_tag(addr)	((void *)(addr))
-#endif
 #ifndef arch_kasan_get_tag
 #define arch_kasan_get_tag(addr)	0
 #endif
 
 #define set_tag(addr, tag)	((void *)arch_kasan_set_tag((addr), (tag)))
-#define reset_tag(addr)		((void *)arch_kasan_reset_tag(addr))
 #define get_tag(addr)		arch_kasan_get_tag(addr)
 
 #ifdef CONFIG_KASAN_HW_TAGS
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index df16bef0d810..76a0e3ae2049 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -328,7 +328,7 @@ void kasan_report_invalid_free(void *object, unsigned long ip)
 	unsigned long flags;
 	u8 tag = get_tag(object);
 
-	object = reset_tag(object);
+	object = kasan_reset_tag(object);
 
 #if IS_ENABLED(CONFIG_KUNIT)
 	if (current->kunit_test)
@@ -361,7 +361,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	disable_trace_on_warning();
 
 	tagged_addr = (void *)addr;
-	untagged_addr = reset_tag(tagged_addr);
+	untagged_addr = kasan_reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
 	if (addr_has_metadata(untagged_addr))
diff --git a/mm/kasan/report_hw_tags.c b/mm/kasan/report_hw_tags.c
index da543eb832cd..57114f0e14d1 100644
--- a/mm/kasan/report_hw_tags.c
+++ b/mm/kasan/report_hw_tags.c
@@ -22,7 +22,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 
 void *find_first_bad_addr(void *addr, size_t size)
 {
-	return reset_tag(addr);
+	return kasan_reset_tag(addr);
 }
 
 void metadata_fetch_row(char *buffer, void *row)
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 317100fd95b9..7604b46239d4 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -41,7 +41,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	int i;
 
 	tag = get_tag(info->access_addr);
-	addr = reset_tag(info->access_addr);
+	addr = kasan_reset_tag(info->access_addr);
 	page = kasan_addr_to_page(addr);
 	if (page && PageSlab(page)) {
 		cache = page->slab_cache;
@@ -72,7 +72,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 void *find_first_bad_addr(void *addr, size_t size)
 {
 	u8 tag = get_tag(addr);
-	void *p = reset_tag(addr);
+	void *p = kasan_reset_tag(addr);
 	void *end = p + size;
 
 	while (p < end && tag == *(u8 *)kasan_mem_to_shadow(p))
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index d8a122f887a0..37153bd1c126 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -82,7 +82,7 @@ void poison_range(const void *address, size_t size, u8 value)
 	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
 	 * addresses to this function.
 	 */
-	address = reset_tag(address);
+	address = kasan_reset_tag(address);
 
 	/* Skip KFENCE memory if called explicitly outside of sl*b. */
 	if (is_kfence_address(address))
@@ -103,7 +103,7 @@ void unpoison_range(const void *address, size_t size)
 	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
 	 * addresses to this function.
 	 */
-	address = reset_tag(address);
+	address = kasan_reset_tag(address);
 
 	/*
 	 * Skip KFENCE memory if called explicitly outside of sl*b. Also note
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 6d7648cc3b98..e17de2619bbf 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -67,11 +67,6 @@ u8 random_tag(void)
 	return (u8)(state % (KASAN_TAG_MAX + 1));
 }
 
-void *kasan_reset_tag(const void *addr)
-{
-	return reset_tag(addr);
-}
-
 bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip)
 {
@@ -107,7 +102,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 	if (tag == KASAN_TAG_KERNEL)
 		return true;
 
-	untagged_addr = reset_tag((const void *)addr);
+	untagged_addr = kasan_reset_tag((const void *)addr);
 	if (unlikely(untagged_addr <
 			kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
 		return !kasan_report(addr, size, write, ret_ip);
@@ -126,7 +121,7 @@ bool check_memory_region(unsigned long addr, size_t size, bool write,
 bool check_invalid_free(void *addr)
 {
 	u8 tag = get_tag(addr);
-	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(reset_tag(addr)));
+	u8 shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(kasan_reset_tag(addr)));
 
 	return (shadow_byte == KASAN_TAG_INVALID) ||
 		(tag != KASAN_TAG_KERNEL && tag != shadow_byte);
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4c2a23ccb3572459da7585a776d2d45f6e8b8580.1605305978.git.andreyknvl%40google.com.
