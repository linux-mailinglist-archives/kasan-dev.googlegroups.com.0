Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLMCRX6QKGQEXAOOYAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id AA8562A7374
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:54 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id c9sf25472pgk.10
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534573; cv=pass;
        d=google.com; s=arc-20160816;
        b=QdkPnGJoTwvGy6bVgrGZyNeeAbtTiIwxk8Xnuyrdvak4qrUzJ45xOBnSegqskvCENE
         b00MKGtmH+BG6Xw4Cst5Mtf57D74D2TZqROZ2sY6jw8CcOGwo01HLcAr1IH+eRowZcJc
         KpjjkLHHdmTC48BKVeq39EsteZ/dS+rCQ77J7nxr+P3Sy52IJmu/L/A/cadrpoN66ed2
         P14LVppuxZaZ5LA2KDRrdNG4dRDyCyQy37lvDSuiL6KSMkqX0AgCqZyymWjIzva4qKIB
         fijizdszI7oEBOy6MhEc0lKGpweVXnJPvICRvl1peGupGdI05Q+9ATaYh+WA4+HfbqqF
         9wKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1+QK9A93UExla25tVIk4tl2OSEa87Lrb+03hJZ2UNRk=;
        b=bP7zRNs4jdzkfG6GL0CXe051EI0Ui/uwPt3vJ7s4gjopyU/N1H2D0C2BTDDAiaZeXO
         mNwtwmGPyKqI8UMsVY/EzPyLwP6BvW8EPIUKS0UUJv9QcRWuON56jfGHwyIuX7tMWbQp
         z8NrT7wxZ0OqB0zHATXhk2pBIbEVqg8SdqLWyI805sx7m3ERYHw/uBeAUIImN1/g9/3m
         krj6zHLTTFFsBiUOphn6aUXG8UbEYwLN7WqDN3jYSiqiG6G3IcE4qI5mi2i3mTGi0guZ
         WDjWYCWGqA5vafk1MwAScFFYq+7e+ewdvFrCxPZ+wKgvnybSEEPIchjoQBdqk072PwaH
         Li5Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DwhOeulf;
       spf=pass (google.com: domain of 3k0gjxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3K0GjXwoKCT4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1+QK9A93UExla25tVIk4tl2OSEa87Lrb+03hJZ2UNRk=;
        b=Xe5+fe4lVlhSMXJBpvYFa+GT2rjSXyvv7ZhYiqOriHSTIoiYRQ5tNZZrIIMrs/pIwN
         12cM/1qczjopIOcElupNEYDpfzHNOWUTsjcnCGFhRP2rUHnRAaO8VNgLre1O1PAq5Jlj
         ZmmMsMLFl4RzjjVntAvyBqFq7fh9lOa61xgBa1BVfHP5LcaKNhGZRMhUOYZGopNB1KAa
         0U965iVfTB/mtCa/+mIz/xCjxRSKG+Lan4i8dN/+Jkp5HRneEHGx54OOu6abhZEPwkYm
         VTDZMLgA4cFG5/SFxJ1H8AO6/dwHwpggiugTkSqNMzdyjmUD5+sZUdeNBixW+fpZwA0Y
         lLIA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1+QK9A93UExla25tVIk4tl2OSEa87Lrb+03hJZ2UNRk=;
        b=PhbKx/R7T+5c8tZMccLFgli8k0gIIhrBdsLBRquOzvVMIXR2vVXZbvFkh03YPiGfNm
         YYcHMYyN+12afHy1t6Kv/XQWtsezUqbQGtGY25yI/nxW22T4sYRvNzHniGdp4AwRDXPH
         N+9xz1NbFiOTTxVWI+5LKEjTg6NTtJXX8QSrR7l8LRLMjbgdSDBsobhYR/ugnWNJ/28H
         i/DQFgNKyq/MVn34openD35j1C4ozNMU1UNvyEx279UN7k+AduxlC0VHoduuYz3tN3d5
         XSvb+2zRLAw3KljoJOc6bODVHKFmugkWbN2H6vhvmgWQYVWY/2bsZc9xVkjGHzG0dnUI
         2rYA==
X-Gm-Message-State: AOAM532uzVT/ktTfHjk26CKEWiuHwr++zmxA4aVYKx9MIWiCAbvv6Off
	e3L6gxEgmjpVs6KO+OYJCEA=
X-Google-Smtp-Source: ABdhPJzuLuoEZ6wJWtFpHBhnH6gN0u+vrKReykSlAGgHaqnX4UtWCV6MxI7UtqSWDDMrwHcc51uCNg==
X-Received: by 2002:a63:6386:: with SMTP id x128mr422966pgb.148.1604534573469;
        Wed, 04 Nov 2020 16:02:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7f13:: with SMTP id a19ls1393716pfd.9.gmail; Wed, 04 Nov
 2020 16:02:52 -0800 (PST)
X-Received: by 2002:a63:ea0f:: with SMTP id c15mr392113pgi.367.1604534572877;
        Wed, 04 Nov 2020 16:02:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534572; cv=none;
        d=google.com; s=arc-20160816;
        b=ExOMtDR9sW9veeAMZw8gMsmz0ShlkQTHmCe3ZSfYFOikE2DRN2SNvGM108UCFBieaf
         1UM1600Ndlpq5Ad33EWSHVCee+KTIg2LM5JoMBAwXaNABw8/0/J0Y72zvaFwFq2BZ7YT
         6Oyx+vFu0tPNriN62qv6MBWXBvbL6XW3QBTfmD5bM+8V1DnAa0jjVND2+4VX/n84QUar
         Ah+kf/cJEjm/l1gnG0CUhvN5raxECjG4fzI7t70OoRo61jBlrQhy2QbBgTSLTwZ8Ct76
         iwN0F938EbprHzNYEggDEHioRIctLwqsEa3nlqCZUlu9ClmJp41aFm9aDKU9cjAHPCMD
         B6Fw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=/zD7WZPyOqitLWvnpsu4/VKPhFmibJDXB/9ojacn4YU=;
        b=lSCTKkvEiZnYakKsF8f73+RBA2mvJhtOns2SpheF2syZEj4ydkgM9lKkujt7XroKGT
         MPdlMoLmAhAAqav2NvSwFbBO86HwFSpLXffDtzKnkEzyZNJvCF8xAWeL0wmYUy/uQkDI
         7zeW4Xi1b7GUWGT4CGaDwRIiU/paLvfhv2roJQ+Bmm5pLbXzAMXPjt6KwdOfvape/EFz
         XjJIkIcUwYNb86d/SFIyOU8Oe2zBw5FOUaH7HqJRQ3VEWdOX9xbCokYx/pJlIRrePNNy
         dvhKRav46Vl+vBgWpzZXzJHU/YS+iwszuEbDUBvOTnYRSR+SKdjrjDLmS3BNASOQgyUu
         MGeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DwhOeulf;
       spf=pass (google.com: domain of 3k0gjxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3K0GjXwoKCT4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id t40si249231pfg.2.2020.11.04.16.02.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:52 -0800 (PST)
Received-SPF: pass (google.com: domain of 3k0gjxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id j5so123672qtj.11
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:52 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:45ca:: with SMTP id
 v10mr546432qvt.36.1604534571983; Wed, 04 Nov 2020 16:02:51 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:17 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <a34436af3e3383001fa6232834bd6d46687bda22.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 07/20] kasan: inline kasan_reset_tag for tag-based modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DwhOeulf;       spf=pass
 (google.com: domain of 3k0gjxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3K0GjXwoKCT4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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
index 2c37a39b76ed..0211a4ec5d87 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -191,7 +191,10 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
-void *kasan_reset_tag(const void *addr);
+static inline void *kasan_reset_tag(const void *addr)
+{
+	return (void *)arch_kasan_reset_tag(addr);
+}
 
 bool kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 9008fc6b0810..a266b90636a1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -174,14 +174,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
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
@@ -278,7 +278,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 
 	tag = get_tag(object);
 	tagged_object = object;
-	object = reset_tag(object);
+	object = kasan_reset_tag(object);
 
 	if (unlikely(nearest_obj(cache, virt_to_head_page(object), object) !=
 	    object)) {
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index d858aeb7387f..fe8e6c8e6319 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -26,20 +26,15 @@ void kasan_init_hw_tags(void)
 		pr_info("KernelAddressSanitizer initialized\n");
 }
 
-void *kasan_reset_tag(const void *addr)
-{
-	return reset_tag(addr);
-}
-
 void kasan_poison_memory(const void *address, size_t size, u8 value)
 {
-	hw_set_mem_tag_range(reset_tag(address),
+	hw_set_mem_tag_range(kasan_reset_tag(address),
 			round_up(size, KASAN_GRANULE_SIZE), value);
 }
 
 void kasan_unpoison_memory(const void *address, size_t size)
 {
-	hw_set_mem_tag_range(reset_tag(address),
+	hw_set_mem_tag_range(kasan_reset_tag(address),
 			round_up(size, KASAN_GRANULE_SIZE), get_tag(address));
 }
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 5513b4685007..e9c7d061fbe5 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -246,15 +246,11 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
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
index 0cac53a57c14..25ca66c99e48 100644
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
index 616ac64c4a21..8e4fa9157a0b 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -81,7 +81,7 @@ void kasan_poison_memory(const void *address, size_t size, u8 value)
 	 * some of the callers (e.g. kasan_poison_object_data) pass tagged
 	 * addresses to this function.
 	 */
-	address = reset_tag(address);
+	address = kasan_reset_tag(address);
 
 	shadow_start = kasan_mem_to_shadow(address);
 	shadow_end = kasan_mem_to_shadow(address + size);
@@ -98,7 +98,7 @@ void kasan_unpoison_memory(const void *address, size_t size)
 	 * some of the callers (e.g. kasan_unpoison_object_data) pass tagged
 	 * addresses to this function.
 	 */
-	address = reset_tag(address);
+	address = kasan_reset_tag(address);
 
 	kasan_poison_memory(address, size, tag);
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 3bffb489b144..d1af6f6c6d12 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a34436af3e3383001fa6232834bd6d46687bda22.1604534322.git.andreyknvl%40google.com.
