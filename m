Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMGHZXUAKGQE3NZD7QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9D98E5689A
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 14:23:14 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id i33sf1351069pld.15
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Jun 2019 05:23:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561551793; cv=pass;
        d=google.com; s=arc-20160816;
        b=yQR6Up6rsmcqFaRss54/ZkZ81nB/w/GyNuefyZKAjm5wEsfy81F52AIPg+nA8l1VwT
         eAnHc+qrA+sAUNJ7eeqcBGPeqdZUrJ3kEY7v1T4KisYAEQCi8+bsgZNJCpWRYp+VZqZS
         NRkQLY93JS4GjMW3p5lDG2MVpO3VEq6cdVmVM8OaygcfpdetRy0fE2GqRIWfr0IcTSVD
         ty+BJsGgpp/DE4PMME/MicCLt5HMPpoK8DLeK/ni9RzRqU3W8A1T1LVEvZUQ/swbVDL8
         0zWrT4zQmfdbf/EquihnDjS8xdc4+XBjzwLsP2SWSdKXpXKdYm6SZQazn3YB1SiRDgaB
         3Vcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3f6kdCWcdBzBwdpxKnXD6V7JRnY9a1y09c4skRb7+EY=;
        b=KNMjuSlp0vtcjBizIylTEhpPo9tSTHCYtIrUfhb+g9jmGUTt2hl0flkYTrjkntHiyO
         okRxgb4GDAdeR47L2EAufKCg5Qkod5qC2jyMx9EmvY9l/tHP8zy6DSovl/sb8Sk+/lhr
         EToXOnPCApoqS9Pne724e+bWZ4HqYVVkvNwAN6HS+m6BQrK4FoCSHBvsAV7ebxYhcWzF
         8mjCGlc0mNYSYTImHtzGoXTdpVUPm9AUpFQeFJGWIomoSJSaiImMajEYGj9jCBEewnj1
         q5Sr+sDpaO1MNneTn1O0cLLrm7G14JsgJdzC1BF7YlV7IWv/7wwQKwZEqw9ND1eQokAf
         vvag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dr+4yvWO;
       spf=pass (google.com: domain of 3r2mtxqukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3r2MTXQUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3f6kdCWcdBzBwdpxKnXD6V7JRnY9a1y09c4skRb7+EY=;
        b=A7NpV0BqonI9jfxgoyd9T6Xa4PdKNIKztfpLktp8OnGX+NmAIeHK7nEpz287YZbIrg
         hzaguHcg2fcvxJSI6D0tuzLOPZFEC80q/mdB7t4omTlvL5Y+XdW7fo1s3uZrWT4H4rYQ
         WwAY5+MB7LeU/ofCxMQT1udHjO/Fxg9WrYMyjbTapdsAhDpe4hCWARj0/b9kVcqUBvdI
         uhbi+hd1G5T4QYrx6SeXZQbwHIbQ6FXdlzFagBYcHqlrxEbmrfWg7VGgjrEr2XB8sBig
         k5+UbGDApZAii6n/JlFFg7TZEU6AWQA2pIV6gzzg6oQT9zMu+KBaHjBtP/qDhSstjMU+
         RwHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3f6kdCWcdBzBwdpxKnXD6V7JRnY9a1y09c4skRb7+EY=;
        b=WrDx4ZNiTvNZDReZxR7ofd2g7R0wO5rW+CDCVpi0IqP6BUaMcITv2C+t2Tcvh8at9f
         RpLI45+VLNm4xKkriqG093dxlj6ELELZlZSjK4ppE7gSEOGzdAF3aGPN7GzRer5R7a/g
         rADdybCB620+6EmKBjP2OzPwDogB/Kku89u9cxPCMhrRgcbWwDq5S6KGoSE+66OwOocR
         U58XZ/rSPQ93WgCd+9GOLMUF/983aorR20JEvZnzA1VH+0GRGmNXzslUkmciSLlWZVpa
         ihvPg8BXU6K/G9u4Rjy9PBqCdCwnOamkNc1MogU+WbGt5sD//nX+EudxChl9BmsvfsLV
         uCQA==
X-Gm-Message-State: APjAAAUDLBS7G26rwJjH72UaZrExExn9ElkLT70sCNp7Fbgs/lB+pGV+
	nDKnani0CQvt1uO3US4A9SY=
X-Google-Smtp-Source: APXvYqyQdmoeW1b589sB2gU/5CgDeGroPAYTrDUMStIUQh3Nbv1pkBTsNm1fZFJJYXyV532aiYuHHA==
X-Received: by 2002:a17:902:d891:: with SMTP id b17mr5151779plz.48.1561551793070;
        Wed, 26 Jun 2019 05:23:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b90b:: with SMTP id bf11ls673302plb.14.gmail; Wed,
 26 Jun 2019 05:23:12 -0700 (PDT)
X-Received: by 2002:a17:90a:1951:: with SMTP id 17mr4441705pjh.79.1561551792608;
        Wed, 26 Jun 2019 05:23:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561551792; cv=none;
        d=google.com; s=arc-20160816;
        b=Olt6l/9tJX9R89EKx3/gIH3Yrbeb9Qi2UKIsNRVgTFps3kKoVZPjKdha+2YNs13GN2
         OyMCMFot4IEtm3aYlM7hxL25hj1SfnyD/vC88IxOvyS61lPK2BBlz+wx8bYdFroI3YMB
         BkiFCeZNT1SGspKTj0v7zZpEcyTKNYvpC4qsMwOtLfv+bHodCmSFGtIpUD/3h1TdJK6r
         1n+NFURDM9fbRzOK4S1/PruKBUCidFEArxuEAAjMvP2UhGA2GQOM160G5BQ/U4g4dJR+
         G3AZZ/CrVe0DCUNXzHU8GThk63Zj/GOaRASAZX0HydBx6rITz4tEQIsyCm+gRYntKvnx
         +CwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=aEBIaaWYace9y+Mt2DPGrWS6yavzA5TNBst3S/YiRr8=;
        b=by4jXrkdwyaaySWqSPOfku5hkwikKvW5QD7yKhEtVbgiUc2E68VWCDOL4V25QsNpAE
         uOwEt77Bqwki9E7vkazSBk9DsQ6E3kQGIj92ox/hyRzeBUvTcYBhpeuCF6tzf4UG4m/A
         Xb3/Gi/0nnX6227Qu5ndB9TY7cTSJ8sKYQpeZ+lWTvYNNzm3ifE6HLiZEFDBUt/YZSrm
         GYTe5XXXIxi+Blx3gCWaEdPIJSr4H9oWnU6/GGqwI+sjafjztIW0zOhZJdotGcIp9sUH
         YWg01FxgfIPRndgEvfYajidt0Cty5ZJW/7tDVTXBxflWvzFEsW2SCQoAj+hgaczLhSP/
         afFg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dr+4yvWO;
       spf=pass (google.com: domain of 3r2mtxqukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3r2MTXQUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id s20si47897pjp.1.2019.06.26.05.23.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 26 Jun 2019 05:23:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r2mtxqukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d26so2595942qte.19
        for <kasan-dev@googlegroups.com>; Wed, 26 Jun 2019 05:23:12 -0700 (PDT)
X-Received: by 2002:ac8:25d9:: with SMTP id f25mr3394375qtf.256.1561551791675;
 Wed, 26 Jun 2019 05:23:11 -0700 (PDT)
Date: Wed, 26 Jun 2019 14:20:16 +0200
In-Reply-To: <20190626122018.171606-1-elver@google.com>
Message-Id: <20190626122018.171606-2-elver@google.com>
Mime-Version: 1.0
References: <20190626122018.171606-1-elver@google.com>
X-Mailer: git-send-email 2.22.0.410.gd8fdbe21b5-goog
Subject: [PATCH v2 1/4] mm/kasan: Introduce __kasan_check_{read,write}
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
 header.i=@google.com header.s=20161025 header.b=dr+4yvWO;       spf=pass
 (google.com: domain of 3r2mtxqukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3r2MTXQUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
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

This introduces __kasan_check_{read,write} which return a bool if the
access was valid or not. __kasan_check functions may be used from
anywhere, even compilation units that disable instrumentation
selectively. For consistency, kasan_check_{read,write} have been changed
to also return a bool.

This change eliminates the need for the __KASAN_INTERNAL definition.

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
 include/linux/kasan-checks.h | 35 ++++++++++++++++++++++++++++-------
 mm/kasan/common.c            | 14 ++++++--------
 mm/kasan/generic.c           | 13 +++++++------
 mm/kasan/kasan.h             | 10 +++++++++-
 mm/kasan/tags.c              | 12 +++++++-----
 5 files changed, 57 insertions(+), 27 deletions(-)

diff --git a/include/linux/kasan-checks.h b/include/linux/kasan-checks.h
index a61dc075e2ce..b8cf8a7cad34 100644
--- a/include/linux/kasan-checks.h
+++ b/include/linux/kasan-checks.h
@@ -2,14 +2,35 @@
 #ifndef _LINUX_KASAN_CHECKS_H
 #define _LINUX_KASAN_CHECKS_H
 
-#if defined(__SANITIZE_ADDRESS__) || defined(__KASAN_INTERNAL)
-void kasan_check_read(const volatile void *p, unsigned int size);
-void kasan_check_write(const volatile void *p, unsigned int size);
+/*
+ * __kasan_check_*: Always available when KASAN is enabled. This may be used
+ * even in compilation units that selectively disable KASAN, but must use KASAN
+ * to validate access to an address.   Never use these in header files!
+ */
+#ifdef CONFIG_KASAN
+bool __kasan_check_read(const volatile void *p, unsigned int size);
+bool __kasan_check_write(const volatile void *p, unsigned int size);
 #else
-static inline void kasan_check_read(const volatile void *p, unsigned int size)
-{ }
-static inline void kasan_check_write(const volatile void *p, unsigned int size)
-{ }
+static inline bool __kasan_check_read(const volatile void *p, unsigned int size)
+{ return true; }
+static inline bool __kasan_check_write(const volatile void *p, unsigned int size)
+{ return true; }
+#endif
+
+/*
+ * kasan_check_*: Only available when the particular compilation unit has KASAN
+ * instrumentation enabled. May be used in header files.
+ */
+#ifdef __SANITIZE_ADDRESS__
+static inline bool kasan_check_read(const volatile void *p, unsigned int size)
+{ return __kasan_check_read(p, size); }
+static inline bool kasan_check_write(const volatile void *p, unsigned int size)
+{ return __kasan_check_read(p, size); }
+#else
+static inline bool kasan_check_read(const volatile void *p, unsigned int size)
+{ return true; }
+static inline bool kasan_check_write(const volatile void *p, unsigned int size)
+{ return true; }
 #endif
 
 #endif
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 242fdc01aaa9..2277b82902d8 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -14,8 +14,6 @@
  *
  */
 
-#define __KASAN_INTERNAL
-
 #include <linux/export.h>
 #include <linux/interrupt.h>
 #include <linux/init.h>
@@ -89,17 +87,17 @@ void kasan_disable_current(void)
 	current->kasan_depth--;
 }
 
-void kasan_check_read(const volatile void *p, unsigned int size)
+bool __kasan_check_read(const volatile void *p, unsigned int size)
 {
-	check_memory_region((unsigned long)p, size, false, _RET_IP_);
+	return check_memory_region((unsigned long)p, size, false, _RET_IP_);
 }
-EXPORT_SYMBOL(kasan_check_read);
+EXPORT_SYMBOL(__kasan_check_read);
 
-void kasan_check_write(const volatile void *p, unsigned int size)
+bool __kasan_check_write(const volatile void *p, unsigned int size)
 {
-	check_memory_region((unsigned long)p, size, true, _RET_IP_);
+	return check_memory_region((unsigned long)p, size, true, _RET_IP_);
 }
-EXPORT_SYMBOL(kasan_check_write);
+EXPORT_SYMBOL(__kasan_check_write);
 
 #undef memset
 void *memset(void *addr, int c, size_t len)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190626122018.171606-2-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
