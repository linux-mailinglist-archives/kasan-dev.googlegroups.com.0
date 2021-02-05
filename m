Return-Path: <kasan-dev+bncBDX4HWEMTEBRBR4D62AAMGQELVA5S6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe38.google.com (mail-vs1-xe38.google.com [IPv6:2607:f8b0:4864:20::e38])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B5F8310EC2
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:04 +0100 (CET)
Received: by mail-vs1-xe38.google.com with SMTP id a63sf945823vsc.10
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546503; cv=pass;
        d=google.com; s=arc-20160816;
        b=QPNnXMqX02Ut5Sy3njtfdN1+ws+UZDcl1KBQ8/2ebdViBna0JqPcFG2QJpgaoHWMhx
         lUBuDTC6xpe7cNetkcstfESMhBtIPfo3dSkWOoAb8i4aNxFp3P5f+dBR//YXVadN9Mw/
         KPFw5vbJeaK5B7ND1/5BjhTCtg+EBrVLzeQOc+iAx0Gvd8IGehlzMz9C0VNUGwe5StGl
         WZpSZs3UXsmHsEfN1LS3xXXhKcn6CqeGM1UsDxfCf6h20u7z7ZRl+BdK6Rcif0pKJkIk
         3dMyQ/Bohpg8VKGf1qCP28+1tOu6UKZRYusNAayUAxzpVh7x3sZ4BSm6QHqQveQzqIcK
         pcUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=VXvLkXnRj9Kb21V4Xgs/fY+T6WQoSQgtBu+QC9Gh+ic=;
        b=VoLHmu4T/3pH17idDaaXC2IfjMmeqVwTyDUTzXBrDoP2xCWBlFV43qrf0+Ghl1VWUq
         pFu5vM4RGmQr38K6eWGcZxkIPHXmK+lN/zUFDGY59GjkI6yLocirZFoPEFo7VXjNXTXf
         Jt+ICSEZ/QaROlBDnSYRgVlJ2oSX9rjaC+X8GgEe0SK+0/PVX59IZTFlz3YMPpHjJCZY
         22O2v5gPWqR/cOdThxJA3x5QCzYHSbeEYaiUl7RirCQHd5SvebycxY606Eq2w1VQzzmf
         XZ6WkecGsuRT58Fhf5oeNLePOUdl5svAaszndFwSZNE678NVw1MPS9xeBfPyJH9ydD1h
         7zVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="r27Shr/X";
       spf=pass (google.com: domain of 3xoedyaokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3xoEdYAoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VXvLkXnRj9Kb21V4Xgs/fY+T6WQoSQgtBu+QC9Gh+ic=;
        b=qMK3gXnRl/HJOwXM38hl24nH7+9+kpcEvO5Cutq3G+r4zPDjFsKpIx9yaHqK0z1PZu
         lzEPAjeI7iq48UhV1GO7SHo+ZgsN9Ab1gRMGEkKSTQHBphQN845tU00BhIAyvB8GX8/K
         nubS4orRORmfty34wLbLJ3b+zc7IdhwlX8GO79CP1reWXMJ6YyaYz8o2us+GZi0+txSo
         ZCskWb/h7PfcITCDKyhpBgRHZHk1CsgddOcJuFF19MoTRoDr+2J1Xi1oNIaHS8hn9cEd
         EeAjJOGI6StBZ8gvKbNe2urD/3HNiZuFsUjhkXbw9tONxkjZiLRB5sEGbF0pRzNfir4I
         uS9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VXvLkXnRj9Kb21V4Xgs/fY+T6WQoSQgtBu+QC9Gh+ic=;
        b=XB4tjjD9sZ7Ij3ohbW0yhyCKH2CuDkMp3qzCaKUI9i8fU4XtBlGR0ayePSds/K2rKk
         wqfNsQAqoVnI9I+u2/kxw9iqILeP58BB5BpINRY3zWCwiphXUgDi2HiKltXzFA16g4+o
         5xYRu8tmME8vv/IVemPltCNNxg/wNlIzIkG1zr8nZAgT8gAio9ih02cfkclsR2WaXmHl
         BzLfkEYXngttqbPD6xny/gdbhD+8uxsxgyh360x+Efkh8aCxaiJCIEqRXwvXp/HnqBiC
         yzmNDTQsLS7ZUJUFPXLxlnDUHzbQQA61ud63wD1SDFTcMKIxtihfK14Rk5b5zam+E8+U
         ThEw==
X-Gm-Message-State: AOAM533KKoVAHGh86Z/RWKNEaZHB9n0juwARBGVV7kbQkuMptwMN2LI5
	PD2IuNgiHDgxPv3OBQ/FuQ4=
X-Google-Smtp-Source: ABdhPJwIeYnXqEydU2TwKe6O8UxnlQjts+u8/TOmmqdZPTl7yxyNvRz5chw+lZKrxhGdlMuVGcx8mQ==
X-Received: by 2002:ab0:13c5:: with SMTP id n5mr3992056uae.16.1612546503288;
        Fri, 05 Feb 2021 09:35:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3641:: with SMTP id s1ls803956uad.10.gmail; Fri, 05 Feb
 2021 09:35:02 -0800 (PST)
X-Received: by 2002:ab0:2a01:: with SMTP id o1mr3984056uar.32.1612546502834;
        Fri, 05 Feb 2021 09:35:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546502; cv=none;
        d=google.com; s=arc-20160816;
        b=P7m6iKAEKT6CA7S0evl7Rq9gVPs/Z795ZMp7hS7Vs19xM88V7XOCqEietiN3mAVCPG
         xybg/MGbMoGhZsVyz6MEEakzbxOxLoEG7WXaA9ybHAymyPa/pq+7i50rDM+509kW6OyX
         GpXlr+C28ZdfwDv29jDY1hur/cTs5xvanOiijlq0pr9VP90L8j9Q8PkgF4T98qTIOhwX
         jMK/nQdiXGQ5h0LMzILozhsBfAvl1j+psvDffGUHPXFdHjJAE6Pp1vuk90HkSg5Pc1xi
         a+K5mxK3CkL6FfFGuC4dWkg0lWvg/l+e5zcyqVM3O1oouWmeWbUEkkfvHJ16baJxAS2H
         1dwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=nFFQgpju2Q7ah9cWGUiX1xDaTa8Y8GPfAWjtc31c0z0=;
        b=AagZhGmeNoh+fQ9PT99W0qRvAs9B19S6LEcB/ti0KTEK4O7K1WowSS36UDjThAlYEy
         BKQua5RfanBvUb2ECxb+nweS2guI0rvEtKgSRh5RTKmgrTDhxNv1gjRFrQM26ww4sWst
         E/I+bDbWqaLPP5BfzR4Pm5cNp/MkJ7SanEmzM0GEx39PCkd9fwqrdU2QDgFxl/oG/9Lq
         u14/3x2NuJqLEp945bq4JOUW0YkLDPx1QgTIhViTYZ4Pjj/uSoSNEIAInytSbNLwl9uU
         DKGhQfXe5leGTqY2ZUXvJ7QoYWaPEi2NMx6vBXW0F+IZD7VJZCAOHyALepuozwXnepse
         9MyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="r27Shr/X";
       spf=pass (google.com: domain of 3xoedyaokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3xoEdYAoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id l11si398346vkr.5.2021.02.05.09.35.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xoedyaokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id g80so6418453qke.17
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:02 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:613:: with SMTP id
 z19mr5363210qvw.2.1612546502427; Fri, 05 Feb 2021 09:35:02 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:39 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <14ffc4cd867e0b1ed58f7527e3b748a1b4ad08aa.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 05/13] kasan: unify large kfree checks
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="r27Shr/X";       spf=pass
 (google.com: domain of 3xoedyaokcucjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3xoEdYAoKCUcjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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

Unify checks in kasan_kfree_large() and in kasan_slab_free_mempool()
for large allocations as it's done for small kfree() allocations.

With this change, kasan_slab_free_mempool() starts checking that the
first byte of the memory that's being freed is accessible.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 16 ++++++++--------
 mm/kasan/common.c     | 36 ++++++++++++++++++++++++++----------
 2 files changed, 34 insertions(+), 18 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index e6ed969e74b3..14f72ec96492 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -200,6 +200,13 @@ static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object)
 	return false;
 }
 
+void __kasan_kfree_large(void *ptr, unsigned long ip);
+static __always_inline void kasan_kfree_large(void *ptr)
+{
+	if (kasan_enabled())
+		__kasan_kfree_large(ptr, _RET_IP_);
+}
+
 void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
 static __always_inline void kasan_slab_free_mempool(void *ptr)
 {
@@ -247,13 +254,6 @@ static __always_inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
-void __kasan_kfree_large(void *ptr, unsigned long ip);
-static __always_inline void kasan_kfree_large(void *ptr)
-{
-	if (kasan_enabled())
-		__kasan_kfree_large(ptr, _RET_IP_);
-}
-
 /*
  * Unlike kasan_check_read/write(), kasan_check_byte() is performed even for
  * the hardware tag-based mode that doesn't rely on compiler instrumentation.
@@ -302,6 +302,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
 {
 	return false;
 }
+static inline void kasan_kfree_large(void *ptr) {}
 static inline void kasan_slab_free_mempool(void *ptr) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags)
@@ -322,7 +323,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
-static inline void kasan_kfree_large(void *ptr) {}
 static inline bool kasan_check_byte(const void *address)
 {
 	return true;
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index da24b144d46c..7ea643f7e69c 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -364,6 +364,31 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
+static bool ____kasan_kfree_large(void *ptr, unsigned long ip)
+{
+	if (ptr != page_address(virt_to_head_page(ptr))) {
+		kasan_report_invalid_free(ptr, ip);
+		return true;
+	}
+
+	if (!kasan_byte_accessible(ptr)) {
+		kasan_report_invalid_free(ptr, ip);
+		return true;
+	}
+
+	/*
+	 * The object will be poisoned by kasan_free_pages() or
+	 * kasan_slab_free_mempool().
+	 */
+
+	return false;
+}
+
+void __kasan_kfree_large(void *ptr, unsigned long ip)
+{
+	____kasan_kfree_large(ptr, ip);
+}
+
 void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 {
 	struct page *page;
@@ -377,10 +402,8 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 	 * KMALLOC_MAX_SIZE, and kmalloc falls back onto page_alloc.
 	 */
 	if (unlikely(!PageSlab(page))) {
-		if (ptr != page_address(page)) {
-			kasan_report_invalid_free(ptr, ip);
+		if (____kasan_kfree_large(ptr, ip))
 			return;
-		}
 		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE);
 	} else {
 		____kasan_slab_free(page->slab_cache, ptr, ip, false);
@@ -539,13 +562,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 		return ____kasan_kmalloc(page->slab_cache, object, size, flags);
 }
 
-void __kasan_kfree_large(void *ptr, unsigned long ip)
-{
-	if (ptr != page_address(virt_to_head_page(ptr)))
-		kasan_report_invalid_free(ptr, ip);
-	/* The object will be poisoned by kasan_free_pages(). */
-}
-
 bool __kasan_check_byte(const void *address, unsigned long ip)
 {
 	if (!kasan_byte_accessible(address)) {
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/14ffc4cd867e0b1ed58f7527e3b748a1b4ad08aa.1612546384.git.andreyknvl%40google.com.
