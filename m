Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJVA2LUAKGQER76ZOBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93e.google.com (mail-ua1-x93e.google.com [IPv6:2607:f8b0:4864:20::93e])
	by mail.lfdr.de (Postfix) with ESMTPS id B2C4B57F81
	for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 11:45:11 +0200 (CEST)
Received: by mail-ua1-x93e.google.com with SMTP id o46sf248889uad.4
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Jun 2019 02:45:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561628710; cv=pass;
        d=google.com; s=arc-20160816;
        b=PmWLwtjl5e+tlRlC6n8Pm4QsZ4JhQ4lAAT3paLDu5QBblkYEBfVYus4erc9xODXiXW
         NiEzBbxLh3PzT4d07WpOqaw9amvJZFORlFwa2WG25Nd0uUV07tcRdi3bshi+F2gPNpOj
         TXtMD1qAKBJgGt2uAhUkuldrGuWxGagi4YV/ZyKHjHDIbptYuyh8kjAsyWPNsgeD9VLb
         4R0r61kE+1FGUyXjdPHFkWJnM852214qzOvxkk41dHPBApLBKzizTobqMQ5RsAWeue6c
         Au8U4sVTDEA7PklUiki+4w3MKksd+PcHL58QmUv09m3mqpUEaa7tD/YVlHfQuDGrmouW
         48ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=DdXujlBiVLk/GZY0o1QAmvnap4CdIuq/oSJILVTi4NY=;
        b=c0NOG/8onR1h46KNHu/YRRxt6gus6NOwOgK3lxroQAVwJBKn29EAe6n5lvWpkH4g86
         BxV8PkXk5DZoRM2l9KHs7x8OuF4CDygF/qfeKX4QttEixI9C819n0YM1xOYOJiSsfn5/
         0P9zm0Tj23x4nXM1LE8DrznWmyRulmiAsA7J1NT7qPnxzA1FUbDDspvo7Y0XSz3nkRRl
         D/mBGduhNT99GIPngRqGl1ULyy0aCll6LsfHShtXLGixWIXIWYevB3Njk5Gzkd3+qjrT
         GR4jb9gI0atflEj6HuZOQoOPlefcsEh38NuFpUv5nEEaT1C6pwgZuhSFfknYhjQCapSq
         SZ8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dkNaHYpO;
       spf=pass (google.com: domain of 3jpauxqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3JpAUXQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DdXujlBiVLk/GZY0o1QAmvnap4CdIuq/oSJILVTi4NY=;
        b=k+a6NMPyKw8Cplcj+94scGj6SsA2JRBC23mhIZmxHQ8tLTb6mzSOIX2v/X6AhyNygf
         kmHJo/pI1n4ptdrWzSF86j+kv8lnYyHyxVQ9jYm4erCJTMlurEQjAbi3POxVl2pDmPy7
         PclxXmDbpOLpa2h9tL0ZHESpjsTxVp92QfXHnC810rjc5lI2wRCeZF7hL/wPhQ7Omxd9
         ef3A3TCDlSVtktRucQQX+C/PcBjnAp72Q5wylqW5tnNEIcf5MpwYBonA5gckNtLHG88w
         kjTyk25iTeoV9kiXasBGANyJz3MndPFZd++yH9Sr2JE8AMz5nwTslvji6iG0g7CGmRFT
         WKUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DdXujlBiVLk/GZY0o1QAmvnap4CdIuq/oSJILVTi4NY=;
        b=CbEgk1b52T5djvp9FX/8EWtcEUvJDLV1EJh3aUqgm3DNVe00P6OcteGjaeK+9qJ6o0
         BSCVCkUhHfEcOBOtBjGT/Hb4JOqY+Vwl8sEXvO/MihuFNzzEeoqMzuDhjFmMIZTbooeE
         gYDMbnkyz1YijkdvpOJdT2bFT/DAlVgY09R2QXZUVrSNfH7K4Q7IetQdCpCCvU+qJvPE
         6cn7trKb2HXRaCkhep+K/3N6BClhRcriYr99SQKFHVlzncUdnBMD87RbkhKF+Bs8PiA2
         Vxxh3hxjCOlUnpXqDb6pvkKlCoBQKeoGDrKAq+DDdzKEW4gAx7kjZ9KZC6PG+ZIg0N0s
         msRg==
X-Gm-Message-State: APjAAAUwGf0E8/RpmJbzp8LMzVrLYH6SqifzRqslXEv44jwyncNmGIJg
	b2TmSC/nA9FbZ+FU79JlUOc=
X-Google-Smtp-Source: APXvYqyxtOVXmaJkUH9IoG9sHOjp0Q+zPY4dsdQ0pF2idB16jA0IckP+ndIF9dLoeA7ZBiE9VS4Bog==
X-Received: by 2002:a67:eada:: with SMTP id s26mr1922913vso.163.1561628710789;
        Thu, 27 Jun 2019 02:45:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:eec4:: with SMTP id o4ls491147vsp.11.gmail; Thu, 27 Jun
 2019 02:45:10 -0700 (PDT)
X-Received: by 2002:a67:ad07:: with SMTP id t7mr1959109vsl.214.1561628710474;
        Thu, 27 Jun 2019 02:45:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561628710; cv=none;
        d=google.com; s=arc-20160816;
        b=hZzxr/zBcMgyKuz1S9NVKkO/3bpEcDzMmy6WkgDfvQHqdFY4q+QSbOlUazgEYnd3Eu
         bdUu7Sk6s5kTtl0qmQWd1lWqwfe8kghN6GYoj4tU424hcAyLs1zeviJfpVMeeSHfocVn
         RwVZyH79HmEVtYTKLVgNjZ5JTLuTG6UPZ7piJGdGY2eXz0WaB7ecJTk0UQXPWhF2FHTL
         4N/8KTg2OwObG7ayrbGreka7DnnA1pXkDm6hQgyJUr5IEXC525XAqobV7K+xJc/idhUt
         yFx1+TrHhBDM5+OjxuUyv+YNmjCsC8c7f9oPgd3k47Vi8HCZxPDr865hd6LpPkwFr1jb
         Vgzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Rln2FP6BOxdiVf8wORphr5UbX/lGN9PNgnvsQm0pxfA=;
        b=M8YYck6mM2FNi55BtvBrgJdd9pPyqm9vMMKOs5Sb+75gFuUH5OYlxc7DimUJrReN3L
         y12D/B89dJMdIi8yN7ORktsPwpxxl3v+ga3TLj7NBqKtzYsvzLyQ04l8rJPd1MnaWgPF
         W6lEI9nv6nvD0+yB1bkwj9/EAGfF9r6vU6oJazLlTJ4Wci/kIvhyg8Ghj/tKo1o0Zlt8
         hLq4Wt7bgipOC0faCyBwe4P7rCKku7FZoQXygiIsGInrtCHTLCiDs9/Rg+keR+7spBmf
         okQzHGMLLIxQsq9lId/FcFjYWngCtRHFL5eRzuHopXNi1zwBuV2o0NM8A62MFMw70OMo
         GNyQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dkNaHYpO;
       spf=pass (google.com: domain of 3jpauxqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3JpAUXQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa4a.google.com (mail-vk1-xa4a.google.com. [2607:f8b0:4864:20::a4a])
        by gmr-mx.google.com with ESMTPS id b5si43042vsd.2.2019.06.27.02.45.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 27 Jun 2019 02:45:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jpauxqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::a4a as permitted sender) client-ip=2607:f8b0:4864:20::a4a;
Received: by mail-vk1-xa4a.google.com with SMTP id j5so527856vkj.1
        for <kasan-dev@googlegroups.com>; Thu, 27 Jun 2019 02:45:10 -0700 (PDT)
X-Received: by 2002:a1f:3c82:: with SMTP id j124mr982314vka.47.1561628710024;
 Thu, 27 Jun 2019 02:45:10 -0700 (PDT)
Date: Thu, 27 Jun 2019 11:44:42 +0200
In-Reply-To: <20190627094445.216365-1-elver@google.com>
Message-Id: <20190627094445.216365-3-elver@google.com>
Mime-Version: 1.0
References: <20190627094445.216365-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v4 2/5] mm/kasan: Change kasan_check_{read,write} to return boolean
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dkNaHYpO;       spf=pass
 (google.com: domain of 3jpauxqukcycpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::a4a as permitted sender) smtp.mailfrom=3JpAUXQUKCYcpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
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

This changes {,__}kasan_check_{read,write} functions to return a boolean
denoting if the access was valid or not.

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
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
v3:
* Fix Formatting and split introduction of __kasan_check_* and returning
  bool into 2 patches.
---
 include/linux/kasan-checks.h | 36 ++++++++++++++++++++++--------------
 mm/kasan/common.c            |  8 ++++----
 mm/kasan/generic.c           | 13 +++++++------
 mm/kasan/kasan.h             | 10 +++++++++-
 mm/kasan/tags.c              | 12 +++++++-----
 5 files changed, 49 insertions(+), 30 deletions(-)

diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index 19a0175d2452..2c7f0b6307b2 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -8,13 +8,17 @@
  * to validate access to an address.   Never use these in header files!
  */
 #ifdef CONFIG_KASAN
-void __kasan_check_read(const volatile void *p, unsigned int size);
-void __kasan_check_write(const volatile void *p, unsigned int size);
+bool __kasan_check_read(const volatile void *p, unsigned int size);
+bool __kasan_check_write(const volatile void *p, unsigned int size);
 #else
-static inline void __kasan_check_read(const volatile void *p, unsigned int size)
-{ }
-static inline void __kasan_check_write(const volatile void *p, unsigned int size)
-{ }
+static inline bool __kasan_check_read(const volatile void *p, unsigned int size)
+{
+	return true;
+}
+static inline bool __kasan_check_write(const volatile void *p, unsigned int size)
+{
+	return true;
+}
 #endif
 
 /*
@@ -22,19 +26,23 @@ static inline void __kasan_check_write(const volatile void *p, unsigned int size
  * instrumentation enabled. May be used in header files.
  */
 #ifdef __SANITIZE_ADDRESS__
-static inline void kasan_check_read(const volatile void *p, unsigned int size)
+static inline bool kasan_check_read(const volatile void *p, unsigned int size)
 {
-	__kasan_check_read(p, size);
+	return __kasan_check_read(p, size);
 }
-static inline void kasan_check_write(const volatile void *p, unsigned int size)
+static inline bool kasan_check_write(const volatile void *p, unsigned int size)
 {
-	__kasan_check_read(p, size);
+	return __kasan_check_read(p, size);
 }
 #else
-static inline void kasan_check_read(const volatile void *p, unsigned int size)
-{ }
-static inline void kasan_check_write(const volatile void *p, unsigned int size)
-{ }
+static inline bool kasan_check_read(const volatile void *p, unsigned int size)
+{
+	return true;
+}
+static inline bool kasan_check_write(const volatile void *p, unsigned int size)
+{
+	return true;
+}
 #endif
 
 #endif
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 6bada42cc152..2277b82902d8 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -87,15 +87,15 @@ void kasan_disable_current(void)
 	current->kasan_depth--;
 }
 
-void __kasan_check_read(const volatile void *p, unsigned int size)
+bool __kasan_check_read(const volatile void *p, unsigned int size)
 {
-	check_memory_region((unsigned long)p, size, false, _RET_IP_);
+	return check_memory_region((unsigned long)p, size, false, _RET_IP_);
 }
 EXPORT_SYMBOL(__kasan_check_read);
 
-void __kasan_check_write(const volatile void *p, unsigned int size)
+bool __kasan_check_write(const volatile void *p, unsigned int size)
 {
-	check_memory_region((unsigned long)p, size, true, _RET_IP_);
+	return check_memory_region((unsigned long)p, size, true, _RET_IP_);
 }
 EXPORT_SYMBOL(__kasan_check_write);
 
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 504c79363a34..616f9dd82d12 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -166,29 +166,30 @@ static __always_inline bool memory_is_poisoned(unsigned long addr, size_t size)
 	return memory_is_poisoned_n(addr, size);
 }
 
-static __always_inline void check_memory_region_inline(unsigned long addr,
+static __always_inline bool check_memory_region_inline(unsigned long addr,
 						size_t size, bool write,
 						unsigned long ret_ip)
 {
 	if (unlikely(size == 0))
-		return;
+		return true;
 
 	if (unlikely((void *)addr <
 		kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
 		kasan_report(addr, size, write, ret_ip);
-		return;
+		return false;
 	}
 
 	if (likely(!memory_is_poisoned(addr, size)))
-		return;
+		return true;
 
 	kasan_report(addr, size, write, ret_ip);
+	return false;
 }
 
-void check_memory_region(unsigned long addr, size_t size, bool write,
+bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip)
 {
-	check_memory_region_inline(addr, size, write, ret_ip);
+	return check_memory_region_inline(addr, size, write, ret_ip);
 }
 
 void kasan_cache_shrink(struct kmem_cache *cache)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 3ce956efa0cb..e62ea45d02e3 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -123,7 +123,15 @@ static inline bool addr_has_shadow(const void *addr)
 
 void kasan_poison_shadow(const void *address, size_t size, u8 value);
 
-void check_memory_region(unsigned long addr, size_t size, bool write,
+/**
+ * check_memory_region - Check memory region, and report if invalid access.
+ * @addr: the accessed address
+ * @size: the accessed size
+ * @write: true if access is a write access
+ * @ret_ip: return address
+ * @return: true if access was valid, false if invalid
+ */
+bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip);
 
 void *find_first_bad_addr(void *addr, size_t size);
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index 63fca3172659..0e987c9ca052 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -76,7 +76,7 @@ void *kasan_reset_tag(const void *addr)
 	return reset_tag(addr);
 }
 
-void check_memory_region(unsigned long addr, size_t size, bool write,
+bool check_memory_region(unsigned long addr, size_t size, bool write,
 				unsigned long ret_ip)
 {
 	u8 tag;
@@ -84,7 +84,7 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
 	void *untagged_addr;
 
 	if (unlikely(size == 0))
-		return;
+		return true;
 
 	tag = get_tag((const void *)addr);
 
@@ -106,22 +106,24 @@ void check_memory_region(unsigned long addr, size_t size, bool write,
 	 * set to KASAN_TAG_KERNEL (0xFF)).
 	 */
 	if (tag == KASAN_TAG_KERNEL)
-		return;
+		return true;
 
 	untagged_addr = reset_tag((const void *)addr);
 	if (unlikely(untagged_addr <
 			kasan_shadow_to_mem((void *)KASAN_SHADOW_START))) {
 		kasan_report(addr, size, write, ret_ip);
-		return;
+		return false;
 	}
 	shadow_first = kasan_mem_to_shadow(untagged_addr);
 	shadow_last = kasan_mem_to_shadow(untagged_addr + size - 1);
 	for (shadow = shadow_first; shadow <= shadow_last; shadow++) {
 		if (*shadow != tag) {
 			kasan_report(addr, size, write, ret_ip);
-			return;
+			return false;
 		}
 	}
+
+	return true;
 }
 
 #define DEFINE_HWASAN_LOAD_STORE(size)					\
-- 
2.22.0.410.gd8fdbe21b5-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190627094445.216365-3-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
