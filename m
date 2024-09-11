Return-Path: <kasan-dev+bncBDN7L7O25EIBBNXZQS3QMGQEOCUWRXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id BA5C8974A8C
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2024 08:46:15 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4582a894843sf32125901cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 23:46:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726037174; cv=pass;
        d=google.com; s=arc-20240605;
        b=O7flMNYju0jDrv0iDw5VK5qpsCCbegdPrYN3XZXfvZ41ZrJNXHomxFULzyfyRWl8g+
         zZ37RG+JHUTva1GtxpE6ez9TR1Ovm8mUpYuKsRWERCSv7QniUbxGWNeUxI1a6ab5IM+C
         JX79z2JQ3cRJqpxOVluO2a529OQrHelXAX2C30QmfSLG+SrLU2uieSHqAOrulZFLR0bR
         5JN7W3fBlZwfxV+3tW1vT/HlaGJrxS/+ILPLj7mAtKB9vDRWMEKVdPSiFTKjsq9dNYAL
         9NULakZi/M09G2VyJnXCaxvPcmJa9/xnKdCBjd2t0AND6Pnzax/csE5NN9OuspPOd0k5
         oquQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+Rma3RIj1+dKve6phuGNHnPPi3A3TJpC5wqyPycni4Y=;
        fh=xtmApayvLmCDGrolmww6rbNokNjSq1pWeFKTnC+5Two=;
        b=An/io2Qqjbh52AQJcGwHkGD9gi1Ut76VFY+vkTcxgk0OQIOML9D9ST33tRbzZ1TvJX
         IhDp4E7vhxrBuvlNOa6GnndA4SS/abKr9/wTyIW1oYokTW50QlycLxcBtvnIoFZEnWzN
         N3u9PMNL6lLbtBl3cT3I9WG2V2OwtCH9ZSnSheYLASS3ttWXFhhBL+UOUspVrtAuNr2g
         4CzE2ZSSLYLJxbjlklDfiFJVRXtONbjVmF+acw4Dz/NE+6UPhO5uTMu1xfwrGcP41pX6
         TSRlYkIFrR786LQkuGZICRI2t7ZoaKqln7mvzbiRb4XtjKYnONgfOHKYi6M8P5WH7tna
         elnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BYT44DQz;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726037174; x=1726641974; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+Rma3RIj1+dKve6phuGNHnPPi3A3TJpC5wqyPycni4Y=;
        b=SkW/ncLI/Ac/WbrWs3PMD2bXV9u/rUIxIJiP5/Qycr8IV+EjhURV4Jg2tVSaFo9LU1
         ouE1wT7VfrwH5887e/ukJmeRp3mQT5lO43Or4FOugw6aVS0ot+k/SqDPcO+lXP4WQzLT
         KoEWKMNOq/sDGaHr8jCIQZol4phE4VFo+VeRd26ipgeo7z5FluOxFY2HGRgIafJNEezC
         ge7kDoY5+6dC1X+UWHOZtO9bk3U4W/jhPVDVU2e9uqKdTnen3yfeOAJVynan/RhDKv2c
         uytIPwFRGZGdZt5vnWVhB+MorT7l5YNx2meNiCL2crQzKP2QnbsbiilcembCzYfk3vMs
         rHCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726037174; x=1726641974;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+Rma3RIj1+dKve6phuGNHnPPi3A3TJpC5wqyPycni4Y=;
        b=ejPMWbczM80MID7dC4NzJa2Zs3l7FVi6P+vfCRAANmByz7rifBj70+WYJ9i3Sxb4WR
         JHGK9JKnBCgXieJuObKNNo5ZP0t9e0+wTLLj9FyYSOag7jok8yUwX6elEqcUNGm5An3a
         EmaR8+UKMU6sqhQ7grznTgIg54dVifH4Nh+msMX3Rxd0jdNSUGIbqFcxJAx3UOeylhUk
         D9mfdNTeo8O90Zq037qI1c+q5swnHS4Yy6d+E/gjDWR2yPXwhTEUwOVqtCFULorMLNm2
         JwBOFdu0PgFsdmrkHXgxszppxjXZKc2cQEKHH6sRFHpjqw4O/IFfxwhtGR7XENywhq8R
         4efA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUUPk+wyU5RuJkc9tKI38nvcqTB6IjWA4ZVZzYdXobHh/gm6KFd10tFvLJTqsSjQmVtO2wDUQ==@lfdr.de
X-Gm-Message-State: AOJu0YwMeWaR6FWAwZQwHGbpVFD/MFgQJEeyGz/BVWA+ztK9cG8DgYy8
	See/KougEhi1XJlleQmjzTzySy3YHi/GeFxt6TdaaWBcgbpYloyM
X-Google-Smtp-Source: AGHT+IHeWX0gzXF5+SToi2Fg0aBA8QlfPDgvDVUsume8P3QHa8OWfL4rwcDrDPf1zU0PVnuATSdaWw==
X-Received: by 2002:ac8:7dcc:0:b0:455:a05:b477 with SMTP id d75a77b69052e-4584e8fd151mr28692891cf.12.1726037174497;
        Tue, 10 Sep 2024 23:46:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:58e:b0:458:2e21:e409 with SMTP id
 d75a77b69052e-4583c7d7295ls28870581cf.0.-pod-prod-03-us; Tue, 10 Sep 2024
 23:46:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBsxGgyhBIQOBXMyZ98pDEeQY81ma31Q522J03dnMmuf3qDX7QlYUceGUBDstcVrKgW+v8s3uiL3M=@googlegroups.com
X-Received: by 2002:ac8:5a53:0:b0:44f:5e2c:1600 with SMTP id d75a77b69052e-4584e91cdaamr30110021cf.28.1726037173833;
        Tue, 10 Sep 2024 23:46:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726037173; cv=none;
        d=google.com; s=arc-20240605;
        b=K2IEMuDXcr7yCEUVitNdtpj/FOk0vihDqxIZyCZMdOEu1PtVt9tsjUpCLqUJpoqufo
         s7riu3snHbeAxNdcGvqscP+gfW3jZvRe72pL5rDqxb0yg0Ef8x/39skQ/6xXVr7NU2Sc
         1Qj/nvucosLKlwbbK4S9xnPw5+2MphEV3MoS6Y+icJpqeX6WwzCC72kyoZtdVTlekF36
         U7hM41dgI/3Ji2bcLvrnRorOeZIGtSyUlKhu4qGvLCQxVXxRBdMgOlA1DuSB8gKjaI9x
         4QGa7P2a5flYONr7jyCwUpuU64e2wBSVyB9sTFuNZtkA6l5u8XqHu08sIcMZm08V+BZf
         L+Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=/S8vF7imCQy4zA2SHeFyV8/wC75Gy306lr1UXEKj3dY=;
        fh=Xs830Dl/dg7cBD7Cjxi4zgG6B28PocXmmZIfDH/IGEM=;
        b=PiTxQLy2WhJ3yp+T26qiSkZtRsSQ087267QBzFEUoIYTOUB2YwuexjVCJjgj+od0K6
         tnYkdGRuqhrNgdeHf6FY0CInhbD7m2vh2jslJKmaGxb4DINp+UcGUVnrl1zMwFKm4g8A
         9MxhNRGZ+QBK9aj/zHEl8zaWhmEjL0gQIqBCxOl5kOQCNOLB0ltyZSryv6wSUH5hc4ps
         r3bJArZnP9NpAdVMAtsdwn9nBUtBh91B6Rb+MerX7ezQ9iq2vQyx3jm4A2JKh2wh94St
         TJUuxjyfBgZQErlHSMBugQ0/2f/LR94hkL7N4zEHCDO43fmJFOWh4C8qGtrQSfVI/MO9
         rgBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=BYT44DQz;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-458230c72d5si3632121cf.5.2024.09.10.23.46.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Sep 2024 23:46:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: RMjJ4cZ4Tsyo4J0FGxXUIg==
X-CSE-MsgGUID: Eo6+jFD7RJ+6hbP8UMYC8w==
X-IronPort-AV: E=McAfee;i="6700,10204,11191"; a="36173017"
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="36173017"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2024 23:46:11 -0700
X-CSE-ConnectionGUID: IgyzjmIvSCmBHDIIIAmEIw==
X-CSE-MsgGUID: u/rfH00VRWC+1lv/88CKcQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="67771497"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa007.jf.intel.com with ESMTP; 10 Sep 2024 23:45:55 -0700
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
	Danilo Krummrich <dakr@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v2 3/5] mm/slub: Move krealloc() and related code to slub.c
Date: Wed, 11 Sep 2024 14:45:33 +0800
Message-Id: <20240911064535.557650-4-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240911064535.557650-1-feng.tang@intel.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=BYT44DQz;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as
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

This is a preparation for the following refactoring of krealloc(),
for more efficient function calling as it will call some internal
functions defined in slub.c.

Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slab_common.c | 84 ------------------------------------------------
 mm/slub.c        | 84 ++++++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 84 insertions(+), 84 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index af6b14769fbd..5734b61a106f 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1185,90 +1185,6 @@ module_init(slab_proc_init);
 
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
index 021991e17287..c1796f9dd30f 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4712,6 +4712,90 @@ void kfree(const void *object)
 }
 EXPORT_SYMBOL(kfree);
 
+static __always_inline __realloc_size(2) void *
+__do_krealloc(const void *p, size_t new_size, gfp_t flags)
+{
+	void *ret;
+	size_t ks;
+
+	/* Check for double-free before calling ksize. */
+	if (likely(!ZERO_OR_NULL_PTR(p))) {
+		if (!kasan_check_byte(p))
+			return NULL;
+		ks = ksize(p);
+	} else
+		ks = 0;
+
+	/* If the object still fits, repoison it precisely. */
+	if (ks >= new_size) {
+		/* Zero out spare memory. */
+		if (want_init_on_alloc(flags)) {
+			kasan_disable_current();
+			memset((void *)p + new_size, 0, ks - new_size);
+			kasan_enable_current();
+		}
+
+		p = kasan_krealloc((void *)p, new_size, flags);
+		return (void *)p;
+	}
+
+	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
+	if (ret && p) {
+		/* Disable KASAN checks as the object's redzone is accessed. */
+		kasan_disable_current();
+		memcpy(ret, kasan_reset_tag(p), ks);
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
+ * This is the case, since krealloc() only knows about the bucket size of an
+ * allocation (but not the exact size it was allocated with) and hence
+ * implements the following semantics for shrinking and growing buffers with
+ * __GFP_ZERO.
+ *
+ *         new             bucket
+ * 0       size             size
+ * |--------|----------------|
+ * |  keep  |      zero      |
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240911064535.557650-4-feng.tang%40intel.com.
