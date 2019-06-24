Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF65YLUAKGQEVKTA2OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id E59B050966
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 13:06:00 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id g30sf16533755qtm.17
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jun 2019 04:06:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561374359; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wtd9BE8nNMd7EFZr60xhrxj4IbitGKyRASX4rfluIngxwjRos5VOXEivXjiVISmfMK
         Ke/UqXU5qq90EqfGjeEDswSypOdUDcj53d6GnHsG9behUIwPtUBX3ejI2jEpy4ZGmF13
         Ni3c8gT6kc7rNfaI1eFFCqtt6tEPCbFpSJuDWffbuVUrAxfJ9AIMSVlJRfoOdZ/yNIld
         aZ18FbZ6HLnnrbBwXhVRxIo3ll7ws6YQGI6rAdj6XU5RwMuGAyoXQ0MzT60Liq+dXZUB
         O4wjW8Gjqc/rOIuJauZJJcc8qmpuiH+5Bug7j5mqmJu3aGTN9CUzWLNlFgQCFS/jPVfx
         goYQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=+6RBIKOgXu4Qs9VaprZy4XAbW8OkDk3cV0N0dnWg8UI=;
        b=OUlKc1KI0kyvt0DRZurp3my68j9eszrqpIUDvxrYi7g1svq1rs60pYGkweRJTaYmik
         8HNRtQLNQ7D5mmPF3ADT4KlkeIyy9gKiBdVBVFxLtAR9dy2hdjW+6fy7htBGAmwRuTvL
         RqhHA486Y1CpilJUry85rn9w+wu+aJsERM5wigziotXme2P1xhGRPC9M2ZOBhRGQc5Q+
         AwN91Zuovu0XmCZ+MyQsQH58foI1hLKuETB5DshR0CjP8FXtdq0EMJ6rc3DDiEFz6C+r
         PAB5iMlR2jvz7A4IMnRUvEpzUjrdk/nFQ99Q9PE7Re1g9B5FpHUwSwcnPV/SKmx79O0N
         5WlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vosRPmYO;
       spf=pass (google.com: domain of 3l64qxqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3l64QXQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=+6RBIKOgXu4Qs9VaprZy4XAbW8OkDk3cV0N0dnWg8UI=;
        b=CYXkunBYoOxaBQfODlnnK/2KAPI/jKe32vjjTmSC7eWMWPPWbEBWmpfbyBqcGmYV6h
         QMNuDxaWS2gxMhh/sPtRgJ66yYELMAYGkbt7GGBUNwDfZxQakwiwr14AoO33LXR8aCQm
         cAsG1Nl/nce2It5P/NIyBwlQ27Qyxfi3iuFTj4XN+TcWehC9qd8lFVZ9jH5LZGo//rXt
         1z8LkAamDHxM+iTDepYNp4W5VclnrCRUzUm+MyY3UeDin47qUqRxnscCX6ZiQXLPvrgn
         YDBFeRy73sq6wdG9KHYFzENXL6qNxGO60F8OS3hEnWEZOZMzwBWyd5obcEPIUXqzso0F
         IYGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+6RBIKOgXu4Qs9VaprZy4XAbW8OkDk3cV0N0dnWg8UI=;
        b=rfJPuEsB//8f4YX9tfghjF5ynTyFmMsXtu/fqC+JwfinDK21xDvVsJfEp534LK3yti
         SSF9PqlyoRKa/us8Uue2kS6UZzK0YPassluqeEUrFyk9aqQ1fjGhy2ARY+1WxpwzPS25
         cKFuh2NGgv9rCULb2mrMf8Et4YyVVBR/E1DnV9mVqoQyfB+Snz5tsYzoA6Hk9TLcSTQN
         7/NG/irgdxaaaZTewW8P1XvleO9ZjENfVrQ47XO53rZe1STZ3iCP0onDMwldcpL2e76Q
         L3ywcaM4QdO8ysOcLAkoL0Zmkk4KH+PPrIo3GqQ2L20NYaaAI8kR6gfDrMkOOwxpthIn
         XW+Q==
X-Gm-Message-State: APjAAAWhAyMYqM9isIjJG50C28TadDDx6y1eEYzMTEjzgo0AXUye3sMc
	8bq5+/NM+Qa80aKThxKvCx0=
X-Google-Smtp-Source: APXvYqx7XFzLACW+ufrvudoI4NSh0Zlrjs9Mv7Xq21tWHna9O8rcQo6U1PVs5OSssycArJaHGzVMZw==
X-Received: by 2002:a37:a5d5:: with SMTP id o204mr46504347qke.155.1561374359812;
        Mon, 24 Jun 2019 04:05:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9741:: with SMTP id z62ls640543qkd.12.gmail; Mon, 24 Jun
 2019 04:05:59 -0700 (PDT)
X-Received: by 2002:a37:a5c3:: with SMTP id o186mr61462014qke.108.1561374359540;
        Mon, 24 Jun 2019 04:05:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561374359; cv=none;
        d=google.com; s=arc-20160816;
        b=C4MuUp/vl0C3bsDUqYYdcYeTLuZqIDemxd7Krdt4qsv17SCB0Jl8WVyd15gMoLeFjt
         f/9fYkRmeW/B0cwsqLwXBb0xbiSWV+yNc1ie2bzvu8HYn99TGLPa1mSIR+lJCPdCLgA9
         i3Ho3TgqKJAkQmSJHl33ZnJAzAMGjbsPNVvbj6bnG7jXIYxghfRCbeZFuUbXKxwtTP7c
         4NPlFRWtMKBcu6zca/UOwLhorLwTZuV5CA/JTpiweQzaYfXEi0EUJHe5PYu/qhy2YqPD
         tw+3Hd2UtcCyedfYwCeAcdCSwkW9MEKpnu0WpeRdgOGy/ee1IwWJjj1KhiuOOmemdZF+
         DmAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=PHd5TU1tSErJuln8CLwgi6IjxpHufjIY0VZFaXkHGNk=;
        b=hMIPIIn4eEOgy00RI11JbESBkXlZfTkiyJB+egpEi4LvoLtOt24CLgFon4ehYepA2t
         p7Nc5qhMvtRrXyGNF6ubhd0LVV0zKDM2LMFlgUwfVErpfJPSvQJSZqgYdjA7Xhpb0U09
         mGHz3AlwZFV2FvmsqUnt5KY/6ARGKcBSWaR1FuHz5mo7ZjkLq/tFcroAfn2QVHqUlIhA
         aTjgqoVINhMKYz44/H8SDmknpzUmyglhd5CUkXIXDDDgGx9cFZ48sFbIk6n5g1wCsqH2
         6HCr040b+pS/vGjgVTQp/lQ4i7TxEH+fDfyAUzdpnPcbvi0NG44iECSq32/iOVja6MnV
         oWPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vosRPmYO;
       spf=pass (google.com: domain of 3l64qxqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3l64QXQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id u204si687335qka.6.2019.06.24.04.05.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 24 Jun 2019 04:05:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3l64qxqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id 5so15774848qki.2
        for <kasan-dev@googlegroups.com>; Mon, 24 Jun 2019 04:05:59 -0700 (PDT)
X-Received: by 2002:a37:805:: with SMTP id 5mr15123706qki.385.1561374359272;
 Mon, 24 Jun 2019 04:05:59 -0700 (PDT)
Date: Mon, 24 Jun 2019 13:05:32 +0200
Message-Id: <20190624110532.41065-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH] mm/kasan: Add shadow memory validation in ksize()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: aryabinin@virtuozzo.com, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com
Cc: linux-kernel@vger.kernel.org, Marco Elver <elver@google.com>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vosRPmYO;       spf=pass
 (google.com: domain of 3l64qxqukcsygnxgtiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3l64QXQUKCSYGNXGTIQQING.EQOMCUCP-FGXIQQINGITQWRU.EQO@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

ksize() has been unconditionally unpoisoning the whole shadow memory region
associated with an allocation. This can lead to various undetected bugs,
for example, double-kzfree().

kzfree() uses ksize() to determine the actual allocation size, and
subsequently zeroes the memory. Since ksize() used to just unpoison the
whole shadow memory region, no invalid free was detected.

This patch addresses this as follows:

1. For each SLAB and SLUB allocators: add a check in ksize() that the
   pointed to object's shadow memory is valid, and only then unpoison
   the memory region.

2. Update kasan_unpoison_slab() to explicitly unpoison the shadow memory
   region using the size obtained from ksize(); it is possible that
   double-unpoison can occur if the shadow was already valid, however,
   this should not be the general case.

Tested:
1. With SLAB allocator: a) normal boot without warnings; b) verified the
   added double-kzfree() is detected.
2. With SLUB allocator: a) normal boot without warnings; b) verified the
   added double-kzfree() is detected.

Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=199359
Signed-off-by: Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>
Cc: Christoph Lameter <cl@linux.com>
Cc: Pekka Enberg <penberg@kernel.org>
Cc: David Rientjes <rientjes@google.com>
Cc: Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
 include/linux/kasan.h | 20 +++++++++++++++++++-
 lib/test_kasan.c      | 17 +++++++++++++++++
 mm/kasan/common.c     | 15 ++++++++++++---
 mm/slab.c             | 12 ++++++++----
 mm/slub.c             | 11 +++++++----
 5 files changed, 63 insertions(+), 12 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b40ea104dd36..9778a68fb5cf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -63,6 +63,14 @@ void * __must_check kasan_krealloc(const void *object, size_t new_size,
 
 void * __must_check kasan_slab_alloc(struct kmem_cache *s, void *object,
 					gfp_t flags);
+
+/**
+ * kasan_shadow_invalid - Check if shadow memory of object is invalid.
+ * @object: The pointed to object; the object pointer may be tagged.
+ * @return: true if shadow is invalid, false if valid.
+ */
+bool kasan_shadow_invalid(const void *object);
+
 bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
 
 struct kasan_cache {
@@ -77,7 +85,11 @@ int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
 size_t ksize(const void *);
-static inline void kasan_unpoison_slab(const void *ptr) { ksize(ptr); }
+static inline void kasan_unpoison_slab(const void *ptr)
+{
+	/* Force unpoison: ksize() only unpoisons if shadow of ptr is valid. */
+	kasan_unpoison_shadow(ptr, ksize(ptr));
+}
 size_t kasan_metadata_size(struct kmem_cache *cache);
 
 bool kasan_save_enable_multi_shot(void);
@@ -133,6 +145,12 @@ static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 {
 	return object;
 }
+
+static inline bool kasan_shadow_invalid(const void *object)
+{
+	return false;
+}
+
 static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 				   unsigned long ip)
 {
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7de2702621dc..9b710bfa84da 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -623,6 +623,22 @@ static noinline void __init kasan_strings(void)
 	strnlen(ptr, 1);
 }
 
+static noinline void __init kmalloc_pagealloc_double_kzfree(void)
+{
+	char *ptr;
+	size_t size = 16;
+
+	pr_info("kmalloc pagealloc allocation: double-free (kzfree)\n");
+	ptr = kmalloc(size, GFP_KERNEL);
+	if (!ptr) {
+		pr_err("Allocation failed\n");
+		return;
+	}
+
+	kzfree(ptr);
+	kzfree(ptr);
+}
+
 static int __init kmalloc_tests_init(void)
 {
 	/*
@@ -664,6 +680,7 @@ static int __init kmalloc_tests_init(void)
 	kasan_memchr();
 	kasan_memcmp();
 	kasan_strings();
+	kmalloc_pagealloc_double_kzfree();
 
 	kasan_restore_multi_shot(multishot);
 
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 242fdc01aaa9..357e02e73163 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -413,10 +413,20 @@ static inline bool shadow_invalid(u8 tag, s8 shadow_byte)
 		return tag != (u8)shadow_byte;
 }
 
+bool kasan_shadow_invalid(const void *object)
+{
+	u8 tag = get_tag(object);
+	s8 shadow_byte;
+
+	object = reset_tag(object);
+
+	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
+	return shadow_invalid(tag, shadow_byte);
+}
+
 static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 			      unsigned long ip, bool quarantine)
 {
-	s8 shadow_byte;
 	u8 tag;
 	void *tagged_object;
 	unsigned long rounded_up_size;
@@ -435,8 +445,7 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	if (unlikely(cache->flags & SLAB_TYPESAFE_BY_RCU))
 		return false;
 
-	shadow_byte = READ_ONCE(*(s8 *)kasan_mem_to_shadow(object));
-	if (shadow_invalid(tag, shadow_byte)) {
+	if (kasan_shadow_invalid(tagged_object)) {
 		kasan_report_invalid_free(tagged_object, ip);
 		return true;
 	}
diff --git a/mm/slab.c b/mm/slab.c
index f7117ad9b3a3..3595348c401b 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -4226,10 +4226,14 @@ size_t ksize(const void *objp)
 		return 0;
 
 	size = virt_to_cache(objp)->object_size;
-	/* We assume that ksize callers could use the whole allocated area,
-	 * so we need to unpoison this area.
-	 */
-	kasan_unpoison_shadow(objp, size);
+
+	if (!kasan_shadow_invalid(objp)) {
+		/*
+		 * We assume that ksize callers could use the whole allocated
+		 * area, so we need to unpoison this area.
+		 */
+		kasan_unpoison_shadow(objp, size);
+	}
 
 	return size;
 }
diff --git a/mm/slub.c b/mm/slub.c
index cd04dbd2b5d0..28231d30358e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -3921,10 +3921,13 @@ static size_t __ksize(const void *object)
 size_t ksize(const void *object)
 {
 	size_t size = __ksize(object);
-	/* We assume that ksize callers could use whole allocated area,
-	 * so we need to unpoison this area.
-	 */
-	kasan_unpoison_shadow(object, size);
+	if (!kasan_shadow_invalid(object)) {
+		/*
+		 * We assume that ksize callers could use whole allocated area,
+		 * so we need to unpoison this area.
+		 */
+		kasan_unpoison_shadow(object, size);
+	}
 	return size;
 }
 EXPORT_SYMBOL(ksize);
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190624110532.41065-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
