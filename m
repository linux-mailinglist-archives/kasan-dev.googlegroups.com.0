Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPVEVT6QKGQETAS7DEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B2A12AE327
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:47 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id r6sf87993lfc.4
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046847; cv=pass;
        d=google.com; s=arc-20160816;
        b=XKb4Wj7I6ON1Wut5QK6/c0OqZfP4xFLSfL30ux1CgRD6Wyes+Z69N1XpgBWESMjOW2
         v2viGTKs1FMLnhXpfwxooHDPsvm1pcQFjgdph4EFJbF+yXQyV2kVloYouKkmv/tRkH+i
         Q0otzXyh1hH1e1jHMBFONL/ONta6a5nfyuIFEJayrggHI9WRdTGCb4vW1JYg9i3tgfd8
         QRMQHhkYMo++PeBnT0U4Z6xOaYqoGPt4FeQ8raquU2rVS1lCST+d5Na/LmMWnQ5xI6UG
         /dWCETB76/vQ9TT5uI9mauAvg2aTyi9os8FOObsKjJxYpeAM3ZzDNm/i3KFA4oAJo5Ny
         WFQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=xA3HRQFAFLjgsZ6XNHdimZ3dr+1b/+h8Jc2NgeXx3Eg=;
        b=Yz5WSUlBqA/W7J8mXkEYqEG6jnVYQdB04/6CXSdZ4N8e6fD6Ope2dAhm1KWUdRE7m7
         BqL380zWZLZxcQMlWiKUWvZo0ZDliHc4ebA0pvLuz813p56SRJv+X7Pwmar76pDEkEsn
         VCfH5pYzJ57dOJoDj+UqDb1woGvRADdOO7eq+PmknXgE5jlGUawUu8+1Iaaiv7DMev2h
         bR7KqI51xXuU2lUXJQONp3OuDhM0i6SpHMtvwGP7EeZUQlhUhOJJPS2IHOirgI9WRb6W
         F5sAbzkL3v2FT97hoMCAL6hUtP7aC4hU7W9KxWU3QA+yrQhmwba7Js4TyQe/DTxFbDkI
         OwEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=blIC1ANB;
       spf=pass (google.com: domain of 3prkrxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PRKrXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xA3HRQFAFLjgsZ6XNHdimZ3dr+1b/+h8Jc2NgeXx3Eg=;
        b=XhuAU2M7VWl59IIxQnEUK05Hy26k8gMPihuexUGMtz6lU80Ut0usqdUYy8qGtNRjzc
         5RzzFh5C3PW5gJnl6778yOUsyI0IWMWJcyf3b04dcahAVUFBr4adfdJvtOAJO9nAIHco
         a9PLzPv2vFNDhVI+aA3uw6OI6254yi6WnLw46JnquVYY8rDcX/GsFyFlVJ6mrzIwaBEF
         IXp2AeC3AMzjYKzYzEwOIVMjd3H9PwDVENOOS0hyivrmFugyuEyt7OkhbMwhG+mw/7DM
         rATFrXHdHfGD6vAU9gsyqcAuEEohp2hdUKPOQB/1YouNqXAePQhIfqna388nYqOLOF0Z
         68XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xA3HRQFAFLjgsZ6XNHdimZ3dr+1b/+h8Jc2NgeXx3Eg=;
        b=Y3vCvi62ZSkt9zZ263Dp8+OhOCrsKYBj0g8bHwkm5PX52oGYft8qjqDLwMFn8n6Fmd
         BSLd+kcTUkegKLmkTPIyoIEGMXkdX33OP/kwpQuQD8OMpnKCeR+4GTLmJzCOCc7N7P/a
         +1UbFYJUGIIWC7MqJwiovH8BYuZ3SyMiF3wy+YxFhbmXiBAsVz1au7hi1Q+KTalq6wIR
         puKStnuRHA4WM1mEMTDSfhT71PCuJFnerc/OAnuQenKvnvKvmToFLz+d1turz+6ppMTE
         FLIIl8PbrFC9tZeBp9RgUkQrN3R4/SOy/XUOgpg1MMrBxHtdKp5mvlsbkeXBHpxz1WLj
         fzFw==
X-Gm-Message-State: AOAM530ngn39b9lXYdgZ3d+W000s9LwxbYE9mG7sXs+HgvWmf0cai2ZH
	xz9A0GGUdG6Za7qi4SKdFmc=
X-Google-Smtp-Source: ABdhPJycf5F2pT45q0T9uSqLSMMwLeQ3f5Leyn08lntgVipZJjJt+FbyKk7bZG+R3NvbGPLqwIbsqQ==
X-Received: by 2002:a2e:8e79:: with SMTP id t25mr4971295ljk.133.1605046847139;
        Tue, 10 Nov 2020 14:20:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:818d:: with SMTP id e13ls2410677ljg.5.gmail; Tue, 10 Nov
 2020 14:20:46 -0800 (PST)
X-Received: by 2002:a2e:97ce:: with SMTP id m14mr9126453ljj.49.1605046846228;
        Tue, 10 Nov 2020 14:20:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046846; cv=none;
        d=google.com; s=arc-20160816;
        b=LeNHTWwy8etrOr0R0IN1EsqZzAQyLTNStmZIDVwPXuCdIPMb1s801SME8Vb3FHm2eL
         q36ypglz9zInXtW8C5RH6u6jEzolt/9SsjO3TbRvAuxPXlGGSAzV2NJMDFRunSTS+nxl
         sUAhmskz5MRwz1WChCsxiabkaSamSQd4mx+Uh372wzHBF3CFdL7q6Ai3IAcrUaxXyO3o
         iC1s5ZF5n5uIe0yUi30WEE0XZkzC0OvOG/V7UeudDWSaxYSAIuATt1P7hsNbvBKSQglN
         ziaSITZmGD4rzUYKzMqCVCEm+BhYn14oFxTvP7Y5SX+uroCt8BjKlNE42XubpIarObVo
         IsZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=syFMy85hNfCVsv9zzw9k8mLn//1pQqq/P081Jgl6REI=;
        b=JR0Jn5XV3MAgIyEiKfKZ5awD9TmHNlXpRwq/ZYjYP5mQm0UKeVnxwNt4XGxYbFFZdA
         EMH2SEvDPE+cZsiJQWn4Ynz4di62Q039vdPpf3OstkaOq5WcnGVvUPPwbzANrYstO+1M
         Rbic3TR72z2C3S4ccWmIpsI+jxlAWqM9qoTUrBhyLnlZLcJG6yMCG0gLp00IySQBaiGy
         smUQWEjkYUIwDoLiyRFuTQ9fhVRj+fDikjD5Edd4na7XcXpAaNzYvqstvqAK+Iujo04T
         exZYzocFkbErAxk0Ax48YLyJ3Xmly7p4GtcwH23OPpPgSHbkGHxHScdS+eW52KCulrKi
         Aj0A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=blIC1ANB;
       spf=pass (google.com: domain of 3prkrxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PRKrXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id h19si10770ljh.7.2020.11.10.14.20.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3prkrxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id b6so6159819wrn.17
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:46 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a5d:4ac1:: with SMTP id
 y1mr26982536wrs.27.1605046845650; Tue, 10 Nov 2020 14:20:45 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:11 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <ceba8fba477518e5dc26b77bc395c264cd1e593a.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 07/20] kasan: inline kasan_reset_tag for tag-based modes
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
 header.i=@google.com header.s=20161025 header.b=blIC1ANB;       spf=pass
 (google.com: domain of 3prkrxwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3PRKrXwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
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
index b9b9db335d87..53c8e8b12fbc 100644
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
index 70b88dd40cd8..49ea5f5c5643 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -30,20 +30,15 @@ void kasan_init_hw_tags(void)
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
index db8a7a508121..8a5501ef2339 100644
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ceba8fba477518e5dc26b77bc395c264cd1e593a.1605046662.git.andreyknvl%40google.com.
