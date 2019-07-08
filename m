Return-Path: <kasan-dev+bncBC7OBJGL2MHBBLPRRXUQKGQERBEMICI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id 67587626D7
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Jul 2019 19:09:02 +0200 (CEST)
Received: by mail-qk1-x73d.google.com with SMTP id e18sf10864907qkl.17
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Jul 2019 10:09:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562605741; cv=pass;
        d=google.com; s=arc-20160816;
        b=JDcS3fBMygYNENoogSsKA5KKu+ZNCRHtBx4e/Ksv4zlglV043lo0wF0o2am6u/LF3k
         15PXL+3rOoC08wvC1dCN4ftnz+w1DKAJkQKuuv+G9wKRfB9CymvX6RnMBPDxuBmxo7RP
         C/zivk8WwskYfoLP7Fl8alTbdP27cK21Tk/zLffcL52jWf/fsTKMziuFLnW897QeRJ22
         VhdG634ZOT5PwZUfouRJAzGve51r/f0/Y0z9smCRil/4ha/9Z3CG2yfGQ8WwT3AH73Rk
         r/MP07haVuF3WKeVRDQZF+KD36oinP8kev4d9aIZpF20USwdahY2i5szSg+YrHWaPVbz
         ESoA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=EQkMQaIDrrg4m/OVvGx3TNHmevPvdmOGIljy0yutNtc=;
        b=iXWt3e29Z8JuZf6ZcCYmY5mzVQPjZ2Yw7p4c/wS4qt60GvhvuvDsLNSnPxiqGhT25P
         N+xcYNrquM9ppNHprP3dKhuQl3ofercgF2udDEBqXQkZNH+sgij5L0Omvci02IMViuEZ
         wMtGr46nYGteo8ISdpba/0tGLYPWhh/GvaPeuytMUfXDr6yHlu0dbhwyCoFBDcwrBV43
         6kRudk30w9DJ905rmGxp0nedg8amfAHESg0H5dwmJtEwcuYDHzFEAmR6Loxcy34cOwQX
         +Upa1AFFl1XLkfKDSwFuMX20D2YrvoBaUyEvzlKG/J0YzBvVBkwKWglLhBmIk/Si7f1K
         PCrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XOe4Irkl;
       spf=pass (google.com: domain of 3rhgjxqukcrs5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rHgjXQUKCRs5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EQkMQaIDrrg4m/OVvGx3TNHmevPvdmOGIljy0yutNtc=;
        b=Q6RFZ4GQfywp81K52ePrY+J0AU4lfN3JZnHk+Ai3AyaKGWpJA7Foh6GHkdpMPVTwcl
         i6livEfdSI3Zp44WXWxXLZfEs+v43YEuJEykan7zkrqXqrI9VYSkeDZn0vK78US2D6tV
         UcnvmXHRCR2DmrCLdr0IxNgyWTnvk/bygP5qWhwQiVFWA6jb+atgB8aAeFQanUeCD8KI
         3zhIfqmFsVLkqMLY1Pm7I8zdRmgn4z6rHd3Dd08WugsbQ7GzT0mvra8IRHqGaMxDQ4bH
         yucT7i55a5OCiyYa3Ilsz+Yb+hc/v2GDfDBcMPM43HFMSwShvd5wJgPJEImARe+eqBzU
         bMag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EQkMQaIDrrg4m/OVvGx3TNHmevPvdmOGIljy0yutNtc=;
        b=q9cwtTl3xh6nGMgUgb9TfUyOD0myv+F8QwsnygdIUekrnpZgStx/tDE6aTYI78Usjz
         oJNV5GWlEyJjoe79j4TFsfRDUJ5LRzO9x3W6ujKfzNgetQ57YrJJqHyhMF5fO2SGbMfe
         ld6r3aE4vcZp2ylBOUUh66TNZGnAfUDgMauLzuiCRI8or9K+1Ivj4pSlU2RpdWLcXLyz
         jLUMTFIsr9LrAyYUgkqTCGJYW0FFdyFrjd+bbbPnScHvD3FnW3RjmdjighBnogZ5/3tL
         hu1sc++KnlhxBRVSpDBkWx6TrKrPy81QJaxct5fS8AL8oDay4K0G7ewoqxXYeIS7hAg5
         8vtg==
X-Gm-Message-State: APjAAAVT8fs9wjzmtdPjKhg9+7RvaaNDPXhY/ZuufALPlraat3WFxYjD
	usPxK0IIBF3fI+jWXWedWnA=
X-Google-Smtp-Source: APXvYqxpqCvO7Jn2ZmtcKDQZlnw4GfIr+j0Ht8uI+ctz0kpzExDKVkfwmbR9hkMpIgjYKyKwo8SaLg==
X-Received: by 2002:a37:8341:: with SMTP id f62mr15128250qkd.312.1562605741503;
        Mon, 08 Jul 2019 10:09:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f392:: with SMTP id i18ls2933676qvk.7.gmail; Mon, 08 Jul
 2019 10:09:01 -0700 (PDT)
X-Received: by 2002:a0c:b12b:: with SMTP id q40mr16306894qvc.0.1562605741191;
        Mon, 08 Jul 2019 10:09:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562605741; cv=none;
        d=google.com; s=arc-20160816;
        b=dbnbCmj0h889kREFinQ7+ux80C2JPgSV31w63cqUt4aSTouPJM/9QUkGR5ct6SOXHO
         kN2SIw8UcQTVTv3hTkkzIRBYWcwJZYx7tJhDnDNenk2M59JBYvZYmwytDQgdXOjklnOM
         SIQ5HshgtADN6dch/If7oSG9dXfpnoV8ay9KwwDpLq+CsM9tR502AHUrkvTqmIj2RWx7
         U0w2CPlxonwDSL/XE2pee+siqfF3aPGfYXsGj7X6bm58sC8bk/WWLkVBzPuT/Uh5rLY9
         bUXycnwPE+ZF/5y8tejsxTKEKex91jI6pV8yBylSVB6J1YGksKb8gjSC/4DkxHrEFK7s
         rl5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=RtWDjGUPs90JyASI41SwauSsXqiA2S8BXOwsZQtnu1I=;
        b=z2uwHPu+b8gMAJC2k3l1X7aNcngvm3afmyFsG9qK81/Avgbjy4l35GVfDA/FYfXFAb
         B00MvJDvzY8cCf1Q7qM/7lFoO9hE1aDfCqE3m+4r3RWtEuzXQq1wHXSLDiAV37fGEoym
         fjlO7Dsa//dmrxaGRTctxD24jJ3zA8AFGaUSFblMzInubRntTCyRi+7CLIRVIwnVSXcp
         ACQD67kkuBmvryeZRUCJ02Tu5xymGIgbe7WhgxhikxxowJyq4uPFcy3hQkKEaWqfHRIu
         3wXnymoXhaf9js/AAOVLVyaPqjPz7G2LHsAFVbxOBW/4QLWuMcf5298yaN0MniKU7XfW
         pZFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XOe4Irkl;
       spf=pass (google.com: domain of 3rhgjxqukcrs5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rHgjXQUKCRs5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id c39si926706qta.5.2019.07.08.10.09.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Mon, 08 Jul 2019 10:09:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rhgjxqukcrs5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id r200so6963693qke.19
        for <kasan-dev@googlegroups.com>; Mon, 08 Jul 2019 10:09:01 -0700 (PDT)
X-Received: by 2002:a05:620a:1106:: with SMTP id o6mr14619312qkk.272.1562605740816;
 Mon, 08 Jul 2019 10:09:00 -0700 (PDT)
Date: Mon,  8 Jul 2019 19:07:04 +0200
In-Reply-To: <20190708170706.174189-1-elver@google.com>
Message-Id: <20190708170706.174189-3-elver@google.com>
Mime-Version: 1.0
References: <20190708170706.174189-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v5 2/5] mm/kasan: Change kasan_check_{read,write} to return boolean
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Mark Rutland <mark.rutland@arm.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XOe4Irkl;       spf=pass
 (google.com: domain of 3rhgjxqukcrs5cm5i7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3rHgjXQUKCRs5CM5I7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--elver.bounces.google.com;
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
Cc: Stephen Rothwell <sfr@canb.auug.org.au>
Cc: kasan-dev@googlegroups.com
Cc: linux-kernel@vger.kernel.org
Cc: linux-mm@kvack.org
---
v5:
* Rebase on top of v5 of preceding patch.
* Include types.h for bool.

v3:
* Fix Formatting and split introduction of __kasan_check_* and returning
  bool into 2 patches.
---
 include/linux/kasan-checks.h | 30 ++++++++++++++++++++----------
 mm/kasan/common.c            |  8 ++++----
 mm/kasan/generic.c           | 13 +++++++------
 mm/kasan/kasan.h             | 10 +++++++++-
 mm/kasan/tags.c              | 12 +++++++-----
 5 files changed, 47 insertions(+), 26 deletions(-)

diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index 221f05fbddd7..ac6aba632f2d 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -2,19 +2,25 @@
 #ifndef _LINUX_KASAN_CHECKS_H
 #define _LINUX_KASAN_CHECKS_H
 
+#include <linux/types.h>
+
 /*
  * __kasan_check_*: Always available when KASAN is enabled. This may be used
  * even in compilation units that selectively disable KASAN, but must use KASAN
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
@@ -25,10 +31,14 @@ static inline void __kasan_check_write(const volatile void *p, unsigned int size
 #define kasan_check_read __kasan_check_read
 #define kasan_check_write __kasan_check_write
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190708170706.174189-3-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
