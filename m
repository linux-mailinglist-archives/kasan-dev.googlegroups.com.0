Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT5Q6D6QKGQEBHCY5ZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id A5CB42C1570
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:12 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id b4sf11964042plr.15
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162511; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xv6bkrLgnIn6VIJnc9yEZXsUHUbJX8L7dbpBiydih+ik9mnqjS5ncROCDf4vMiBys+
         aVDqu66pvUcZPZfp36JL1P4VNhmkNy9Jcq1opyH2T/6VfVkT0JFOlj0j00v35fMchqqz
         47KqxvJ2CFAPTnaJ8XO8jL4hNhWaYKiERDkR4FQDKZsxvg1K48k7kmQYHxGYhDgfoqsA
         Y53jQKboBY4dSYwh8VGfaKrb/P0gKaVeP5J19waiz351mZGQaLniwYLjdqOEuqTHJKpz
         oW5KFsppBp+9yxuwMXZFH00P3hmmFGN851jHPX/L0MDkhuSRx1UpSrFUv8t5HMrIt6zP
         MayA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1+3zYEVNT6yvXeYII6ryZF8s4xoLeKWpAnZ+db4elMY=;
        b=bKSuA0ir85wXbuewda6hAPUFZy2FXnCw8/O1tmP0l6+U8ihc5WsNaC3koCCJvadLN9
         zUkMlGt5ARIvRMyyKfBKQO2qs3M1eCvkgj00pKEwHWVoxo8ILQMGz4sqROHGH4CNaFz+
         I46CAfT18A6G0btI7ZK/s+WJLdzrsrt+Wo/58xaw3oNXkJTs6rW5AGY7MJpSHXUZzZKC
         TOE4GIhCEcXI2YgzOtyYRD8S/2C1sNltBu8Xg6z9UO0A3+M3V28sKYn3vwF+jC4i4Dzh
         x1M8ihJa3j2tvUU6T8VuVe76cV+ZYIdLLuZidIpEbiW3Tqt3qWLm8S+q04YTWf8hXTUF
         lVRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ToUXDya0;
       spf=pass (google.com: domain of 3thi8xwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Thi8XwoKCXMReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1+3zYEVNT6yvXeYII6ryZF8s4xoLeKWpAnZ+db4elMY=;
        b=tifyhE0vEmxe3mMpBDPDfdbjCSjiXicwkTOrcp8zHESj7tSXv7XDegn3qq4Nw5i62n
         tjPFabW/mf/K9F8ggEsIl9SzXo6zX0Ymg+tA3bniaJPj0jacqvzm201C5OmZW/jVoBMf
         fep6PIoIe3nXB/q/IUMWpG3YMBY9XGI4YYdq5xCgBhrsmkn5ibqvOM+OQA+PO1ZedD0V
         lCULbG6zQ948eJfViMMetCm9YVdz5Ef5DZrzstsvTMREzaFjIlRZaKn3/HQz2BsOdrO3
         1sLzrcM6vD1Xr5DyZK2BFjKlKvVNoLU+WAwNDdi7kr971g8C+4xFKhDOLK/wti2uwPZv
         WUHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1+3zYEVNT6yvXeYII6ryZF8s4xoLeKWpAnZ+db4elMY=;
        b=I/+k9P3gkIBm2mpJfEbaIU3U4tcQL9QmNcTCE8xr46iteOjyMcvQjFxTB4HWG4yXjb
         tZq2sb2Lj8JcZHeilA2IcNzeFI4SU9Q0EvGbZ98qLyAfPk2PqA8pJBdQfz5Kd/okRhPK
         //j7s/c8lewK9n1zAwuFXP90wMyRsIREN7/ad9NIki/x47kC9aSphaprvSz6vbIiFwdC
         sx/Sml3e75P12MyPDliKy4nhkNxLmAjTDaWBFIWQfOzxDKt+7cwWlErECj5WhrIO4sdK
         iR9fsAkpMPb7vjctDgRXwBaC0aM+bJrD19PdcPkrfLlw91Fm1+bvzvP5nia2ExT66mM1
         HVuw==
X-Gm-Message-State: AOAM5310jehFT7sQDDJHU8rlFzv5tqu01IgxUfDQ2YjXffiyM4QbwtU1
	sjDDxKkhxmJBFn7QIhU8MrU=
X-Google-Smtp-Source: ABdhPJwOVtJt//24BHy898QzVor4LpvSUnKyyfAjtSfTZolaYe/5F4fX+/eSh5Z8r0nzrSOpCsi14Q==
X-Received: by 2002:a17:90a:5d93:: with SMTP id t19mr666136pji.220.1606162511460;
        Mon, 23 Nov 2020 12:15:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:524:: with SMTP id 33ls6693044plf.6.gmail; Mon, 23
 Nov 2020 12:15:10 -0800 (PST)
X-Received: by 2002:a17:90a:a50b:: with SMTP id a11mr720263pjq.170.1606162510904;
        Mon, 23 Nov 2020 12:15:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162510; cv=none;
        d=google.com; s=arc-20160816;
        b=H/azLvy3QYEmu7hKpXm35tHARLh173kmBpcUxVu6q3bJMT1/EMLVZTyhBMMZL/OKsV
         Kuv6CYtk/674ASH4NorBsMSX8sBR27chk1Y5nVYYijXZDce+XaYILi3bK91ahPzLwDXt
         1gyk6DxeAlPPy12dwAeKenON31MMeTaDFbJMOOqdyj+NgAAyn8GyFFWlHQmuBubNyRLN
         2yh8OXkw2xex+NBF39Jj+q8ZVwJtdt24ob/IH1ZmAJQneFnF0HWMtBzeeEw/N+8Y0ebl
         vOmoZAFOH3DE/MpEPMHT+yR4fspTahQ+0iLPcKhYp+FmFdqJFtWkm9RyMB8wrJ+ZdzYv
         z//w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=DkuzKfuS0My7aCtgOtfSEaKr7eC5T05KZFHiwPwDzrY=;
        b=nl5wl47fWacrV6Q6abEOzVbhxFRORDDYGP6rXp2RfO2y1lOcxmpyjnRLa8wX7Nh+3y
         wvwK14eW3DpFVlxPQawHG8YT5W2guQlIHf6r722iyzZOushf1M6u5bMvPuzjgJmTYx2d
         bzFaJEW/cXtbBVZSV5TCU4gK6nLfV7WgrFS5Kx+H9daMz5rw94q0zYZr/ZAlR2yKTz0k
         JCtrh7Uoc5Qc3IGLX1AS4AXQ1ohOdRrJFB9ZkJbnIzKHNmH4yAWmrf9YcC6BCbzO4Jtx
         9WLKtcT6d6MHi0jswgO08MtqsQ5+cITjtj2bZ/fyVEZj8EBsyP24UYde4/4PO4b9TN4S
         kjgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ToUXDya0;
       spf=pass (google.com: domain of 3thi8xwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Thi8XwoKCXMReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id o2si29936pjq.0.2020.11.23.12.15.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3thi8xwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id f49so6564459qta.11
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:10 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:450e:: with SMTP id
 k14mr1203920qvu.28.1606162510024; Mon, 23 Nov 2020 12:15:10 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:37 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <6940383a3a9dfb416134d338d8fac97a9ebb8686.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 07/19] kasan: inline kasan_reset_tag for tag-based modes
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
 header.i=@google.com header.s=20161025 header.b=ToUXDya0;       spf=pass
 (google.com: domain of 3thi8xwokcxmreuivpbemcxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3Thi8XwoKCXMReUiVpbemcXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6940383a3a9dfb416134d338d8fac97a9ebb8686.1606162397.git.andreyknvl%40google.com.
