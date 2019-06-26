Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4EBZ3UAKGQENDFRSFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 5389D56BDA
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 16:28:02 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id h26sf1070936otr.21
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 07:28:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561559281; cv=pass;
        d=google.com; s=arc-20160816;
        b=XXqzilwrC4e2x9kAD104dJei8HNH61PRLZg60WpsxYuzTJDpkauL546+01jzPPW1hj
         2whrzdJYJTUEYbJcBCQw1Q71ob0Us5nGRHx1fENoWmrk4yJ7/aLvTRpZjiXbW+MU+7dL
         UNw9l7PIwL5/QeFNkPwckTIygE60DEOtZ6IVZ08iGNt8XkE29/FWPJrmLaiu3kJCo6fs
         qF9p1HEYpJj1iL1N4nRlcC1+40afn8F5SZDwXjvsYkFqBWiq3EaQGrAVn6c4jQ3bjtia
         VummYAYUEOaqWYqGH1Sc0QmJS6fd8+h5kZhf5aLL8/U98tge/laqCfJ4zwKtjnwV8YM0
         1G9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ndwMRSLij1LJwk7xoXp1vO1duPzWZcWhcR6NHgYnI6k=;
        b=1J71LxIz1HCSUaCDhqIR+KdCeSRX9KJqY+NN2WpSw5hYkutmG6RxKHXeGoxKxdaFxc
         eq538o1bTk48lM6LUDYhSD8Xg1Tf/V7hiGKTh70bKwMZLnZe7e4sSpIYPYHYpRXMHu9g
         StTo50bcHRmA07SJia4DcP6NBr0+wsYDLteT6P1cP3j2PBT54eG2gUki46vRzwkh/xE4
         E8V+mfla9ED7Eqx2XQBKdfpNePCzeSuCniruY8IVCTvlf2x3cDB4FN5MtZAp08egpeI8
         3jbHSPw2BLMKlv24v5aCQvcA8YjdQ42i0JWt8x/EFD3gZMsaavgswaW13QwG1uYdnbtQ
         gayQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b1IaFK1m;
       spf=pass (google.com: domain of 374atxqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=374ATXQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ndwMRSLij1LJwk7xoXp1vO1duPzWZcWhcR6NHgYnI6k=;
        b=d2C7s6MK2MGxDEwAAGsRiQ2DBu02zHbZeN0nxEnVannaW+8vUVUtc9eoORbWw1kdyP
         N57UljM3JgSJj4VjzkldyPfUhNiELgMAF6vSaCZmjkqcpIxRDwUFyUh0DvWTT8Sjo2rv
         Ri5ZNdpWLalohuzuPo2T5CMaTrYCEh8OhE5s4y9f/2Coz7FmRnHY3MH9AJf21CQjey58
         bK0hIPSMKqnoCT3bOmrvU3FiWljwh6mgEGhr+OVEmF1mcLLKvEkNiGJyaU0GeNudsGOW
         3aDtQmQWCCBTzyDMEZeNBvtSLizeDQs5gZlTsI/yC9D+/RiR4EfA8gu/v+3LFMem3uDd
         fb4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ndwMRSLij1LJwk7xoXp1vO1duPzWZcWhcR6NHgYnI6k=;
        b=X6mwntlGD9fhjLGiBr7ivOFlbYJrRSMEtJJtnMSrTYZT9cdyDJv0ef6ZNQta1iR/wo
         GMjuAHV4feRMfeW6to/NzvHFQQcvC5VENCNHKd3edZcd7swh43ZenV3fjitKZWQlpxlf
         Jssg+RAiavldlSZP9hu/Gtc8eOXIV12y2iKKKcD6p63YgwCwAdOH5atCO3H/+bjKuvV4
         q8CAxLlsScp10vqVzb+9SB5PLCvPnnAJcL1u94OGeljUzWo2KFVmhIsZSpAdBEUtF4a8
         43gyGkKWU4IvtJxi21vM+0LBrmXQ17T0q8ENDCBeaNA/A63gtKiyxN7zQruO5aKZXavu
         lRTw==
X-Gm-Message-State: APjAAAXtkn/4q6x3GnYMMUvQKF7sQBYjFYCexNMIpXNpGqusVuLmbl3A
	IDqpwDOC4WjrLYLWFZLLQwM=
X-Google-Smtp-Source: APXvYqy/NRxXd9BD3Ii5CWg3JtKN2uQT0+USIwaTv9EF4WMy5LzJvlJUckHyLcNHda+P+Gq9xS+pSQ==
X-Received: by 2002:aca:494c:: with SMTP id w73mr1883339oia.31.1561559280753;
        Wed, 26 Jun 2019 07:28:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6d09:: with SMTP id o9ls440066otp.7.gmail; Wed, 26 Jun
 2019 07:28:00 -0700 (PDT)
X-Received: by 2002:a9d:6e01:: with SMTP id e1mr3527470otr.220.1561559280461;
        Wed, 26 Jun 2019 07:28:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561559280; cv=none;
        d=google.com; s=arc-20160816;
        b=WHmnSDipJMvHWKl9SZGuPIoSH3n2VkKIa3NnmpTLF6AwoM+JRHEGburiUP6U1T68wT
         ZEEZ3TlPilaWgC6kunoGic2S9P9fH43IqMAz5oadQf37kRxi1WuuFHur1Rd4ti0oEoTp
         b9tIQWigG7oOX6RnGixGswPQGyi2vJuOyPI5kM0ot4Pdx+y94PkrQZth92ikKZ4z0Plx
         NQtTnXng0MoB/hpUeQygluSShNBRiLptCtcK/QfPlvEJlHxJim6AnrJjgdZp7VmD4Jl4
         7Qd7qvZo9a47KhTZqYQOPbx2zuCUpigb0NFwDaO3AfU7hxHkup6Sn415hgnyXYI2/jRU
         wqGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Rln2FP6BOxdiVf8wORphr5UbX/lGN9PNgnvsQm0pxfA=;
        b=qUTVYVlrMUSuiiPX8F95Zp9csEUTPi4OxkRsHHmwjkBdmteSdoM06XFfUxWkBl+382
         FNr8xZz81w+fnxZZ9SKmvCZROxSgngAiigVKlQ+55onhQnwDxgGMYY8MfiDGH629kYxr
         P+ttAYzjdmifITLfnPOus+IeLPT0CAjd8SNRUlFBnqugLsdiF3jNeiDZI6GL2WgI5hLP
         MnYxciizP9dugMw9pDjwwlTNhSUB6CTOVMWqpC2MXfv6KMlfrfIhTSCPflULmUT0hK47
         8AYP3nvhvnxDPPNQtJkoY14Rv+T3kq3L9EKfCd4PzE0XyAFVG/ijTYzQPYliLUTl0cAA
         Wo5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b1IaFK1m;
       spf=pass (google.com: domain of 374atxqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=374ATXQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x54a.google.com (mail-pg1-x54a.google.com. [2607:f8b0:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id r129si948553oib.4.2019.06.26.07.28.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 07:28:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 374atxqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::54a as permitted sender) client-ip=2607:f8b0:4864:20::54a;
Received: by mail-pg1-x54a.google.com with SMTP id e16so1705885pga.4
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 07:28:00 -0700 (PDT)
X-Received: by 2002:a65:4387:: with SMTP id m7mr3168635pgp.287.1561559279316;
 Wed, 26 Jun 2019 07:27:59 -0700 (PDT)
Date: Wed, 26 Jun 2019 16:20:11 +0200
In-Reply-To: <20190626142014.141844-1-elver@google.com>
Message-Id: <20190626142014.141844-3-elver@google.com>
Mime-Version: 1.0
References: <20190626142014.141844-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v3 2/5] mm/kasan: Change kasan_check_{read,write} to return boolean
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
 header.i=@google.com header.s=20161025 header.b=b1IaFK1m;       spf=pass
 (google.com: domain of 374atxqukcs4ovfobqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::54a as permitted sender) smtp.mailfrom=374ATXQUKCS4OVfObQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--elver.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626142014.141844-3-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
