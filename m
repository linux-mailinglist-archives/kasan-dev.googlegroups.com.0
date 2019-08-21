Return-Path: <kasan-dev+bncBC5L5P75YUERB4EO63VAKGQEMQZ53NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4AFA89823E
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Aug 2019 20:03:29 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id h13sf553303lfm.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Aug 2019 11:03:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566410608; cv=pass;
        d=google.com; s=arc-20160816;
        b=ITYxh7yVoM9IqrO4dOstlUKMaeHzes5WPkjSSWmx7o4vNU8cfNPfVWiao7ba0oHIyr
         QSc3jQaickBxR4FFqavo9+kdJj6QxbEIb3Ct438hqSiW+ZREXVU4aJen/cXDjgOK3uiQ
         H18o2TnlzZdClVGQdy5MggCvJ6Aw7IHPFC5p0A3Np0EoSUi0xw+qYPw0Q0L2ZIT/5oPf
         ZG06oBxWooUN4VaCdiK1CyasKBlio5JwvNBxh/S2WtzTbRdywXh3uG6ydEJY7ifUmGWN
         XmA9iMTTEzDOwBX7uFSBdNhHTaAgprOuRAJVyI7yIK05Bbo1j37KDFStg3k72zPMW0mu
         1sEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=UlFZ3Kad8PvDaU4agL3KUbkwC6ijZvpfInKijCF+OPg=;
        b=OBedrZXq7nV0ZE/ILQy8U5Mf9o6hEDPTq34E7bhRVB93UBUvBrOPRZnG9fKDj9Y2JP
         tDUPEJI26yTTt9ytO2RuxHSkU/0gzyJ9jMGFtmgonVB86h0sAciskolSoSZz+dOH5Bk0
         gJQVembPffmmag4KLkbzVq1jGDAnDNvbBBqCy+H/GMk7VsJqK36kfPXMkLM+qb+x77P1
         TK1m/V3iAgYmTjV8o2BlMudkIpGfZthNZUN52E3+4BctcSP25hS6BZ8qU5RD/3rYLcyZ
         h2DXQ8C/3Qd/kmKoxkz2sDXIjBn3bTAQCf56wPwUVSPKolk6u8cOr2pHB5cPFWGJrAim
         CEdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UlFZ3Kad8PvDaU4agL3KUbkwC6ijZvpfInKijCF+OPg=;
        b=KEm0anjRAQvOn5hC0zZ027/oDYcRKY9Db52kV6REByx2QM6jgr7ADGSrPNdtzyOQMu
         yddMAv9I++MEfZ/hed25TLQsA57bcrjFR+th9ozwrmrOB6AHbpc8iQNMI8JfYyyv3oYm
         XgLvK6pMTSQjBdw4viGSsekUF8DJ29Y1eScfkaKVDxgm/E/2PWEzGk0y+vYtdzeIK5N+
         wqmsFacenjYTI+fvrFEZi2+nyrPL6NsWJlnm9dGWYlQ2De9au3IkGPckKFtLXsotcXX+
         7VKwHmq/0X/xWy4V5Fbpcrq+Jbcoq7ty1N35JnEXDl7fkD1n9wkF+CL25uI0NXnAgZ8h
         F5QQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UlFZ3Kad8PvDaU4agL3KUbkwC6ijZvpfInKijCF+OPg=;
        b=c52wHM0IBrcwUIdtjiOSsXdA0HBuiSI1/PVZgmXMT/v8H/mFgWC87n0YhKRiinTXf5
         X5tnjgKwXRAyYYcQfUhVwEfF1ifgTNg1aceoQZxjdHJxGYUiAUu36xvamnxW0TUMn+tG
         oBsn60MYx0IXWrEglOHrcmgtXwrg0Rh5ccQedmDkbhwqhAj20t3NU2Z8ZOv9MHSFR0qF
         qtdA7V93XxQCJW3GG2fYuCc0RymHIxp3XvxyKKBr50wrUDMG/GVMfcBsttKeMCjfsh7D
         qPqcRM4XGLN7wG4fRgB0I+APMSLptPm5yN8W5VOE0W/tvkzucP5saFP9gG6RcOF082s2
         RYlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVZSuP5dUf360JCViyoPqtlt83O2J7nFI1Ela/e/Y9mIvE9MFCZ
	totffflUMMfiQcfwSAQoGcY=
X-Google-Smtp-Source: APXvYqySkOzRFCE3HEiNOysgY1tNBJ6l3ckr1RTacqeK2giIfKOoNJfhKSCgYxYdgAbee3DM50eh8g==
X-Received: by 2002:a19:ca4b:: with SMTP id h11mr18435252lfj.162.1566410608778;
        Wed, 21 Aug 2019 11:03:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b4ef:: with SMTP id s15ls385615ljm.14.gmail; Wed, 21 Aug
 2019 11:03:28 -0700 (PDT)
X-Received: by 2002:a2e:9889:: with SMTP id b9mr20043182ljj.230.1566410608000;
        Wed, 21 Aug 2019 11:03:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566410607; cv=none;
        d=google.com; s=arc-20160816;
        b=VqHCX9lzFvMRFJ/Bpdt0x0nf2W/KvrytKwH4VlAT24q5z0Cirg9GJ6S1z5yzdboLff
         TC0u8C5SOKocWDKHsAXpRdtH7MRk4NrHJjsE1KeiP/Hxl6Op3EnPEnOM+frEwyLxWjBy
         7hZF0WUGrfqQR0lgFhhfcylVkuF2ETSJIVbZ/NrpQCv/Qvy/FY81sINJbvwj/cf3XRZ1
         foOs8HGkolx+HL9GGizX+3QZ3L261afeBfnlZEm3+lFUWuC+QtQNaZpUE5UiqwIDJiKx
         lk101WdMYWqLIyZITfxXrN5kBGLPVmMhYcOUimiI5Oq/loSgWRQuPmfl1woejO2yVFlR
         LmaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=i0P+tsgTlNjgXt3p7+gz/sRItTPBN6orllDLg+y3Fa0=;
        b=p3tLBlvdfA03NQz43LxLCxlFMqLs8jPN76rCGNQFW9ssSaaf1u6UUetW5A0dwMXp8j
         F/zIvj4qUlY3VzePQcFrFgtSJGAiHCDkHRE2B0hYmFQ8smU4TfBXAlhow0ErPz/6AvlD
         GpiIPPa06pPV/vucrYZwN3NcKuDhgtzsrrTURbEYed0I5xZGgm55/+AXoPkOgwssSs5m
         gQmduY/7UH5Cqf/PjSMEIG7sxmGZecEioTq1bex82jSDSgqvGONchVvBG2wzw9A0zh+f
         rBslQ84JuT0LpZt9ItLSY1xANrnZ4S73ZXGsVEaRuBZtLIeblEHd9EkATFP1ECliTSZj
         wN4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id d23si414812ljo.5.2019.08.21.11.03.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Aug 2019 11:03:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from [172.16.25.5] (helo=i7.sw.ru)
	by relay.sw.ru with esmtp (Exim 4.92)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1i0UxB-0003dx-8Y; Wed, 21 Aug 2019 21:03:25 +0300
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Walter Wu <walter-zh.wu@mediatek.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: [PATCH v5] kasan: add memory corruption identification for software tag-based mode
Date: Wed, 21 Aug 2019 21:03:32 +0300
Message-Id: <20190821180332.11450-1-aryabinin@virtuozzo.com>
X-Mailer: git-send-email 2.21.0
MIME-Version: 1.0
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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

From: Walter Wu <walter-zh.wu@mediatek.com>

This patch adds memory corruption identification at bug report for
software tag-based mode, the report show whether it is "use-after-free"
or "out-of-bound" error instead of "invalid-access" error. This will make
it easier for programmers to see the memory corruption problem.

We extend the slab to store five old free pointer tag and free backtrace,
we can check if the tagged address is in the slab record and make a
good guess if the object is more like "use-after-free" or "out-of-bound".
therefore every slab memory corruption can be identified whether it's
"use-after-free" or "out-of-bound".

[aryabinin@virtuozzo.com: simplify & clenup code:
  https://lkml.kernel.org/r/3318f9d7-a760-3cc8-b700-f06108ae745f@virtuozzo.com]
Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
Signed-off-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
---

====== Changes
Change since v1:
- add feature option CONFIG_KASAN_SW_TAGS_IDENTIFY.
- change QUARANTINE_FRACTION to reduce quarantine size.
- change the qlist order in order to find the newest object in quarantine
- reduce the number of calling kmalloc() from 2 to 1 time.
- remove global variable to use argument to pass it.
- correct the amount of qobject cache->size into the byes of qlist_head.
- only use kasan_cache_shrink() to shink memory.

Change since v2:
- remove the shinking memory function kasan_cache_shrink()
- modify the description of the CONFIG_KASAN_SW_TAGS_IDENTIFY
- optimize the quarantine_find_object() and qobject_free()
- fix the duplicating function name 3 times in the header.
- modify the function name set_track() to kasan_set_track()

Change since v3:
- change tag-based quarantine to extend slab to identify memory corruption

Changes since v4:
 - Simplify and cleanup code.

 lib/Kconfig.kasan      |  8 ++++++++
 mm/kasan/common.c      | 22 +++++++++++++++++++--
 mm/kasan/kasan.h       | 14 +++++++++++++-
 mm/kasan/report.c      | 44 ++++++++++++++++++++++++++++++++----------
 mm/kasan/tags_report.c | 24 +++++++++++++++++++++++
 5 files changed, 99 insertions(+), 13 deletions(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 7fa97a8b5717..6c9682ce0254 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -134,6 +134,14 @@ config KASAN_S390_4_LEVEL_PAGING
 	  to 3TB of RAM with KASan enabled). This options allows to force
 	  4-level paging instead.
 
+config KASAN_SW_TAGS_IDENTIFY
+	bool "Enable memory corruption identification"
+	depends on KASAN_SW_TAGS
+	help
+	  This option enables best-effort identification of bug type
+	  (use-after-free or out-of-bounds) at the cost of increased
+	  memory consumption.
+
 config TEST_KASAN
 	tristate "Module for testing KASAN for bug detection"
 	depends on m && KASAN
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 3b8cde0cb5b2..6814d6d6a023 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -304,7 +304,6 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
 struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
 					const void *object)
 {
-	BUILD_BUG_ON(sizeof(struct kasan_alloc_meta) > 32);
 	return (void *)object + cache->kasan_info.alloc_meta_offset;
 }
 
@@ -315,6 +314,24 @@ struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
 	return (void *)object + cache->kasan_info.free_meta_offset;
 }
 
+
+static void kasan_set_free_info(struct kmem_cache *cache,
+		void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+	u8 idx = 0;
+
+	alloc_meta = get_alloc_info(cache, object);
+
+#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+	idx = alloc_meta->free_track_idx;
+	alloc_meta->free_pointer_tag[idx] = tag;
+	alloc_meta->free_track_idx = (idx + 1) % KASAN_NR_FREE_STACKS;
+#endif
+
+	set_track(&alloc_meta->free_track[idx], GFP_NOWAIT);
+}
+
 void kasan_poison_slab(struct page *page)
 {
 	unsigned long i;
@@ -451,7 +468,8 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 			unlikely(!(cache->flags & SLAB_KASAN)))
 		return false;
 
-	set_track(&get_alloc_info(cache, object)->free_track, GFP_NOWAIT);
+	kasan_set_free_info(cache, object, tag);
+
 	quarantine_put(get_free_info(cache, object), cache);
 
 	return IS_ENABLED(CONFIG_KASAN_GENERIC);
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 014f19e76247..35cff6bbb716 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -95,9 +95,19 @@ struct kasan_track {
 	depot_stack_handle_t stack;
 };
 
+#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+#define KASAN_NR_FREE_STACKS 5
+#else
+#define KASAN_NR_FREE_STACKS 1
+#endif
+
 struct kasan_alloc_meta {
 	struct kasan_track alloc_track;
-	struct kasan_track free_track;
+	struct kasan_track free_track[KASAN_NR_FREE_STACKS];
+#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+	u8 free_pointer_tag[KASAN_NR_FREE_STACKS];
+	u8 free_track_idx;
+#endif
 };
 
 struct qlist_node {
@@ -146,6 +156,8 @@ void kasan_report(unsigned long addr, size_t size,
 		bool is_write, unsigned long ip);
 void kasan_report_invalid_free(void *object, unsigned long ip);
 
+struct page *kasan_addr_to_page(const void *addr);
+
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
 void quarantine_put(struct kasan_free_meta *info, struct kmem_cache *cache);
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 0e5f965f1882..621782100eaa 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -111,7 +111,7 @@ static void print_track(struct kasan_track *track, const char *prefix)
 	}
 }
 
-static struct page *addr_to_page(const void *addr)
+struct page *kasan_addr_to_page(const void *addr)
 {
 	if ((addr >= (void *)PAGE_OFFSET) &&
 			(addr < high_memory))
@@ -151,15 +151,38 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 		(void *)(object_addr + cache->object_size));
 }
 
+static struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
+		void *object, u8 tag)
+{
+	struct kasan_alloc_meta *alloc_meta;
+	int i = 0;
+
+	alloc_meta = get_alloc_info(cache, object);
+
+#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
+		if (alloc_meta->free_pointer_tag[i] == tag)
+			break;
+	}
+	if (i == KASAN_NR_FREE_STACKS)
+		i = alloc_meta->free_track_idx;
+#endif
+
+	return &alloc_meta->free_track[i];
+}
+
 static void describe_object(struct kmem_cache *cache, void *object,
-				const void *addr)
+				const void *addr, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_info = get_alloc_info(cache, object);
 
 	if (cache->flags & SLAB_KASAN) {
+		struct kasan_track *free_track;
+
 		print_track(&alloc_info->alloc_track, "Allocated");
 		pr_err("\n");
-		print_track(&alloc_info->free_track, "Freed");
+		free_track = kasan_get_free_track(cache, object, tag);
+		print_track(free_track, "Freed");
 		pr_err("\n");
 	}
 
@@ -344,9 +367,9 @@ static void print_address_stack_frame(const void *addr)
 	print_decoded_frame_descr(frame_descr);
 }
 
-static void print_address_description(void *addr)
+static void print_address_description(void *addr, u8 tag)
 {
-	struct page *page = addr_to_page(addr);
+	struct page *page = kasan_addr_to_page(addr);
 
 	dump_stack();
 	pr_err("\n");
@@ -355,7 +378,7 @@ static void print_address_description(void *addr)
 		struct kmem_cache *cache = page->slab_cache;
 		void *object = nearest_obj(cache, page,	addr);
 
-		describe_object(cache, object, addr);
+		describe_object(cache, object, addr, tag);
 	}
 
 	if (kernel_or_module_addr(addr) && !init_task_stack_addr(addr)) {
@@ -435,13 +458,14 @@ static bool report_enabled(void)
 void kasan_report_invalid_free(void *object, unsigned long ip)
 {
 	unsigned long flags;
+	u8 tag = get_tag(object);
 
+	object = reset_tag(object);
 	start_report(&flags);
 	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
-	print_tags(get_tag(object), reset_tag(object));
-	object = reset_tag(object);
+	print_tags(tag, object);
 	pr_err("\n");
-	print_address_description(object);
+	print_address_description(object, tag);
 	pr_err("\n");
 	print_shadow_for_address(object);
 	end_report(&flags);
@@ -479,7 +503,7 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 	pr_err("\n");
 
 	if (addr_has_shadow(untagged_addr)) {
-		print_address_description(untagged_addr);
+		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
 		print_shadow_for_address(info.first_bad_addr);
 	} else {
diff --git a/mm/kasan/tags_report.c b/mm/kasan/tags_report.c
index 8eaf5f722271..969ae08f59d7 100644
--- a/mm/kasan/tags_report.c
+++ b/mm/kasan/tags_report.c
@@ -36,6 +36,30 @@
 
 const char *get_bug_type(struct kasan_access_info *info)
 {
+#ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
+	struct kasan_alloc_meta *alloc_meta;
+	struct kmem_cache *cache;
+	struct page *page;
+	const void *addr;
+	void *object;
+	u8 tag;
+	int i;
+
+	tag = get_tag(info->access_addr);
+	addr = reset_tag(info->access_addr);
+	page = kasan_addr_to_page(addr);
+	if (page && PageSlab(page)) {
+		cache = page->slab_cache;
+		object = nearest_obj(cache, page, (void *)addr);
+		alloc_meta = get_alloc_info(cache, object);
+
+		for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
+			if (alloc_meta->free_pointer_tag[i] == tag)
+				return "use-after-free";
+		return "out-of-bounds";
+	}
+
+#endif
 	return "invalid-access";
 }
 
-- 
2.21.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190821180332.11450-1-aryabinin%40virtuozzo.com.
