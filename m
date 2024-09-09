Return-Path: <kasan-dev+bncBDN7L7O25EIBBKE77G3AMGQEFIZGAFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1DFD0970B35
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2024 03:30:18 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id af79cd13be357-7a9bb56da15sf15580085a.1
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Sep 2024 18:30:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725845417; cv=pass;
        d=google.com; s=arc-20240605;
        b=NHvkut0McXhQX1atyristkWQtjaL6Mu8KCONUhtLejIuULXWNmG5tGxzETgVsD3CoH
         BMEpMpA2r0cjaZWGLmYzk0eC69Pms8e4WxWM1IpGZnT+PZQnCmk5EfkeIVvSAzRpDI6c
         b6EkJVoMzKTQmJcQhiyeTpU74MwfKpUIM5lf6dwzOYiRtXNR1ZePkwEnLz7xeKYwAYjv
         jV4d0bWikirJ3LKarJtqgzS42Tx6hxlPUw7Zts6lc9Pr3OYRGYpr1mTqUQaIZ1o1sUCd
         RKHajgRZw9Se3P2kRRoi8fcgXLwqkQYBMRAoaKdCKtt4uz7yQMnBjebOEqEk5haSGNcO
         Mdxw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=yfGu1T7SaOtBh/YwwJylzMZqDPR7bXjTJqcUpDCAIto=;
        fh=hrvGaI1bMT+SbN1Sgud/27LxDMJo0UU5bDvH5M0h15I=;
        b=aB3YBmU4vCW5lBom29otcNOkyG8FhyEsQPHyunK/N1j6ZDN16ntwQIZCnMWTRS7LX3
         bDot08/7elAqUVL2I0+GebFxzCxbZ8fL9jxEX9vXR6+ceBMnaoa/TkyYf3Ku4+QFSWtz
         dWdW+5YeUjYWb9KUxnSHD3LVpSM3p9/R4YtH/hEVw66heI8AQBVbwqFnj4FljatpZigy
         TCw65UQS5NtzwS/7R8JlDQbp/vyQuJqC5uQ0O17hv9gRhJTdhPGLAXJKG6cqIUSWV/fb
         LovW4ggFsHT4hFD0nYa4wYthpdJlHcvnsGfevclo/aki/rb7fZhn/tsv7WvsCKzW2u/I
         /fMQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UO0zbAn1;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725845417; x=1726450217; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yfGu1T7SaOtBh/YwwJylzMZqDPR7bXjTJqcUpDCAIto=;
        b=T8P6oZUHc7MUbQXHT3b3cie77/njRfiDjqi9AJg/HU5D82HhEgWLLUST+HwkTXeDyA
         o7RkQB+gzw4FnBkcI2GM/22xBYXH2XEMlRLk4Sz7vZJGLyvK3BOH0CGWmPjSIrbwgjFN
         /+lQwMw5UvfD1Uo1iBJDbc/z1eiHSItsD4FyA16tlr1OWUT/0txYxgb3ni50aVpw6Thf
         Xemr6oPnYUc/d7wEGelGwgJfJkndF0FA+T9fj0o4IRsDDHtwRd3HQbo5KWUHYlK6eMav
         +HzNzkjD0bSrjuwpq4xoLN/1LWw3exHl7uNu5AYirEZrcTZVzh4B/eJ/KJX03RInBB0W
         zpzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725845417; x=1726450217;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=yfGu1T7SaOtBh/YwwJylzMZqDPR7bXjTJqcUpDCAIto=;
        b=gcA8JoSVblqLqfBHzsBrO8dXLlZDAYnNYtFYrXGCvsDiS+watMwJeUh223BpyBFRmd
         ujTOuiOaIpNhIqcCed2p3/sjtce0Kz2+p3RKnBpLoQRbjCahF4H/UxVAo3mwGXRipj5x
         1JB3YYXstjl85A5rKmv9d1PU11PYg0nRsaLwYrqwmYV9y7ogyqJO7qJtdrFA3N7TYRlA
         3QWgQtZr3L4T5S5ghmpYGpSdqv5sk0pZtfOdPn2Bw/6fIS8iFSV87G4oD738YFZbQJK2
         NfciWX1320Fd1kaUMz9iLudwfpWKqjFYE3NO+ENlXxCa3/SoNyQo/hBFLZH9pKr2L6Sq
         W38Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWKNk/yiweIXnHvC6G2KO5mkP6uB49Anr8nMeXiRFBPm/X8jVzEEs76QPgoTGUmMinlhOpFSA==@lfdr.de
X-Gm-Message-State: AOJu0YyXYiiV7Xl1KDT0S5ngEWXdBnKtBTwmwwmh/ZudhSNk0bRf0lL/
	PZALk7U15fA/MUBZmUAOI2Qt5mpf76E6hbDWarNOyjJ1mi/Hw5XT
X-Google-Smtp-Source: AGHT+IEHlMwk/rEziN7aiFiFe6dcVZ4tdQCd1R/btZFTXI5BOV1imPir+aIZX28sveG4I7MXZ51OJg==
X-Received: by 2002:a05:6214:3910:b0:6bd:80f0:42c7 with SMTP id 6a1803df08f44-6c52850bb74mr139151986d6.42.1725845416855;
        Sun, 08 Sep 2024 18:30:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5dea:0:b0:6b7:96a6:c5e7 with SMTP id 6a1803df08f44-6c5279cbde2ls46690846d6.0.-pod-prod-08-us;
 Sun, 08 Sep 2024 18:30:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVgufRL9cS49D/s3rQ46bj3zI4NzeFQNEmn6IoJTi5E3hSlPPRaebbDYgtcK4h7NRBHNZhzyE9gYIM=@googlegroups.com
X-Received: by 2002:a05:620a:2596:b0:79e:ff38:5806 with SMTP id af79cd13be357-7a99737c439mr1605858085a.46.1725845416270;
        Sun, 08 Sep 2024 18:30:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725845416; cv=none;
        d=google.com; s=arc-20240605;
        b=Uw4ri10wDXzoMjTK7Jxbi5ShmR6Nl8cus4jWWh1BqjMvPVXQppcVqMSie7yeGakKIB
         lgmo2viOyvLVL8+STPnTbbj+Ek25BSX9gPPlAR7rkWEjkB8isev5887AKO0bEL5KRSHg
         DGMKtl0scrTL6E3crRNF6y1vZjG2f981dmoFWYAIFHOMZbmiAgfNmiTBm0r48NNEflsC
         T3fzSdzIlVHTxwNFVZlLSPeP7dG/iOb3Wu0XDN2pQeTIAefETfyipIr/RdJh5cnI3r0T
         UCAvxiD8tWcdlcSMxxXqP+4ijacHbGXgq8zHrLKXA303rfwVtngYiplXwuzjBFc8fVLC
         G9uA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5SIq2Al2KKMR6KlWBzxeKlCo6AeeNgLC3rgQdDAQ+Bw=;
        fh=DOrQZqwZ3gYiN8TxsTSOKms3YTEHds3R/56bZbzlpuk=;
        b=YyvN2ZGyWisnodGagUU0vXCg7focrqrXDDXl0MSW4WAkIRYRxs5O7vQPkzs8GHSkPq
         pg8tQPX79mA6Cqqyy/swvxeMCioA78kXEZlCUXgSHgDU8/o3YvIT+SlJjJuMq/IkVuA7
         6BsEWG+/j8BFjCbW11ffZ9WuZ2L3t5RvymorPfDwk4T5nac8w/3LR6Hrn6wn4b3MAT6Z
         L4cg+nc2N0qcr5Ec7pIKvyg97vksJliYISi04cG3/1O3J8k/jM2HI6vmObKnGokdz94j
         nCVAROTkm+yQgOMbNdZH246hndM+ZlEdvAieM8jUP9l5XlmrL1Hwm0VCmhOmoLCU7RNF
         I4/g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UO0zbAn1;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a9a7a07571si13098485a.4.2024.09.08.18.30.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 08 Sep 2024 18:30:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: vd6peuhORpeKizvLsR3e9A==
X-CSE-MsgGUID: oT3SdejXQ2OcJ4f7D5rMwQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11189"; a="28258127"
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="28258127"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2024 18:30:16 -0700
X-CSE-ConnectionGUID: cx70BTLlS3CxDDTgPHNKyA==
X-CSE-MsgGUID: E/DBYOyRSA6Yo9pun0F7fg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="66486467"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa009.jf.intel.com with ESMTP; 08 Sep 2024 18:30:11 -0700
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>,
	Danilo Krummrich <dakr@kernel.org>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH 3/5] mm/slub: Improve redzone check and zeroing for krealloc()
Date: Mon,  9 Sep 2024 09:29:56 +0800
Message-Id: <20240909012958.913438-4-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240909012958.913438-1-feng.tang@intel.com>
References: <20240909012958.913438-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=UO0zbAn1;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

For current krealloc(), one problem is its caller doesn't know what's
the actual request size, say the object is 64 bytes kmalloc one, but
the original caller may only requested 48 bytes. And when krealloc()
shrinks or grows in the same object, or allocate a new bigger object,
it lacks this 'original size' information to do accurate data preserving
or zeroing (when __GFP_ZERO is set).

And when some slub debug option is enabled, kmalloc caches do have this
'orig_size' feature. So utilize it to do more accurate data handling,
as well as enforce the kmalloc-redzone sanity check.

The krealloc() related code is moved from slab_common.c to slub.c for
more efficient function calling.

Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slab_common.c |  84 -------------------------------------
 mm/slub.c        | 106 +++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 106 insertions(+), 84 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index ad438ba62485..e59942fb7970 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1297,90 +1297,6 @@ module_init(slab_proc_init);
 
 #endif /* CONFIG_SLUB_DEBUG */
 
-static __always_inline __realloc_size(2) void *
-__do_krealloc(const void *p, size_t new_size, gfp_t flags)
-{
-	void *ret;
-	size_t ks;
-
-	/* Check for double-free before calling ksize. */
-	if (likely(!ZERO_OR_NULL_PTR(p))) {
-		if (!kasan_check_byte(p))
-			return NULL;
-		ks = ksize(p);
-	} else
-		ks = 0;
-
-	/* If the object still fits, repoison it precisely. */
-	if (ks >= new_size) {
-		/* Zero out spare memory. */
-		if (want_init_on_alloc(flags)) {
-			kasan_disable_current();
-			memset((void *)p + new_size, 0, ks - new_size);
-			kasan_enable_current();
-		}
-
-		p = kasan_krealloc((void *)p, new_size, flags);
-		return (void *)p;
-	}
-
-	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
-	if (ret && p) {
-		/* Disable KASAN checks as the object's redzone is accessed. */
-		kasan_disable_current();
-		memcpy(ret, kasan_reset_tag(p), ks);
-		kasan_enable_current();
-	}
-
-	return ret;
-}
-
-/**
- * krealloc - reallocate memory. The contents will remain unchanged.
- * @p: object to reallocate memory for.
- * @new_size: how many bytes of memory are required.
- * @flags: the type of memory to allocate.
- *
- * If @p is %NULL, krealloc() behaves exactly like kmalloc().  If @new_size
- * is 0 and @p is not a %NULL pointer, the object pointed to is freed.
- *
- * If __GFP_ZERO logic is requested, callers must ensure that, starting with the
- * initial memory allocation, every subsequent call to this API for the same
- * memory allocation is flagged with __GFP_ZERO. Otherwise, it is possible that
- * __GFP_ZERO is not fully honored by this API.
- *
- * This is the case, since krealloc() only knows about the bucket size of an
- * allocation (but not the exact size it was allocated with) and hence
- * implements the following semantics for shrinking and growing buffers with
- * __GFP_ZERO.
- *
- *         new             bucket
- * 0       size             size
- * |--------|----------------|
- * |  keep  |      zero      |
- *
- * In any case, the contents of the object pointed to are preserved up to the
- * lesser of the new and old sizes.
- *
- * Return: pointer to the allocated memory or %NULL in case of error
- */
-void *krealloc_noprof(const void *p, size_t new_size, gfp_t flags)
-{
-	void *ret;
-
-	if (unlikely(!new_size)) {
-		kfree(p);
-		return ZERO_SIZE_PTR;
-	}
-
-	ret = __do_krealloc(p, new_size, flags);
-	if (ret && kasan_reset_tag(p) != kasan_reset_tag(ret))
-		kfree(p);
-
-	return ret;
-}
-EXPORT_SYMBOL(krealloc_noprof);
-
 /**
  * kfree_sensitive - Clear sensitive information in memory before freeing
  * @p: object to free memory of
diff --git a/mm/slub.c b/mm/slub.c
index 4cb3822dba08..d4c938dfb89e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4709,6 +4709,112 @@ void kfree(const void *object)
 }
 EXPORT_SYMBOL(kfree);
 
+static __always_inline __realloc_size(2) void *
+__do_krealloc(const void *p, size_t new_size, gfp_t flags)
+{
+	void *ret;
+	size_t ks;
+	int orig_size = 0;
+	struct kmem_cache *s;
+
+	/* Check for double-free before calling ksize. */
+	if (likely(!ZERO_OR_NULL_PTR(p))) {
+		if (!kasan_check_byte(p))
+			return NULL;
+
+		s = virt_to_cache(p);
+		orig_size = get_orig_size(s, (void *)p);
+		ks = s->object_size;
+	} else
+		ks = 0;
+
+	/* If the object doesn't fit, allocate a bigger one */
+	if (new_size > ks)
+		goto alloc_new;
+
+	/* Zero out spare memory. */
+	if (want_init_on_alloc(flags)) {
+		kasan_disable_current();
+		if (orig_size < new_size)
+			memset((void *)p + orig_size, 0, new_size - orig_size);
+		else
+			memset((void *)p + new_size, 0, ks - new_size);
+		kasan_enable_current();
+	}
+
+	if (slub_debug_orig_size(s) && !is_kfence_address(p)) {
+		set_orig_size(s, (void *)p, new_size);
+		if (s->flags & SLAB_RED_ZONE && new_size < ks)
+			memset_no_sanitize_memory((void *)p + new_size,
+						SLUB_RED_ACTIVE, ks - new_size);
+	}
+
+	p = kasan_krealloc((void *)p, new_size, flags);
+	return (void *)p;
+
+alloc_new:
+	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
+	if (ret && p) {
+		/* Disable KASAN checks as the object's redzone is accessed. */
+		kasan_disable_current();
+		if (orig_size)
+			memcpy(ret, kasan_reset_tag(p), orig_size);
+		kasan_enable_current();
+	}
+
+	return ret;
+}
+
+/**
+ * krealloc - reallocate memory. The contents will remain unchanged.
+ * @p: object to reallocate memory for.
+ * @new_size: how many bytes of memory are required.
+ * @flags: the type of memory to allocate.
+ *
+ * If @p is %NULL, krealloc() behaves exactly like kmalloc().  If @new_size
+ * is 0 and @p is not a %NULL pointer, the object pointed to is freed.
+ *
+ * If __GFP_ZERO logic is requested, callers must ensure that, starting with the
+ * initial memory allocation, every subsequent call to this API for the same
+ * memory allocation is flagged with __GFP_ZERO. Otherwise, it is possible that
+ * __GFP_ZERO is not fully honored by this API.
+ *
+ * When slub_debug_orig_size() is off,  since krealloc() only knows about the
+ * bucket size of an allocation (but not the exact size it was allocated with)
+ * and hence implements the following semantics for shrinking and growing
+ * buffers with __GFP_ZERO.
+ *
+ *         new             bucket
+ * 0       size             size
+ * |--------|----------------|
+ * |  keep  |      zero      |
+ *
+ * Otherwize, the original allocation size 'orig_size' could be used to
+ * precisely clear the requested size, and the new size will also be stored as
+ * the new 'orig_size'.
+ *
+ * In any case, the contents of the object pointed to are preserved up to the
+ * lesser of the new and old sizes.
+ *
+ * Return: pointer to the allocated memory or %NULL in case of error
+ */
+void *krealloc_noprof(const void *p, size_t new_size, gfp_t flags)
+{
+	void *ret;
+
+	if (unlikely(!new_size)) {
+		kfree(p);
+		return ZERO_SIZE_PTR;
+	}
+
+	ret = __do_krealloc(p, new_size, flags);
+	if (ret && kasan_reset_tag(p) != kasan_reset_tag(ret))
+		kfree(p);
+
+	return ret;
+}
+EXPORT_SYMBOL(krealloc_noprof);
+
 struct detached_freelist {
 	struct slab *slab;
 	void *tail;
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240909012958.913438-4-feng.tang%40intel.com.
