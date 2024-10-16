Return-Path: <kasan-dev+bncBDN7L7O25EIBBTV5X64AMGQECY3BLCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id A0B549A0EB6
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 17:42:07 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-6cbec7fbf1csf97895336d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2024 08:42:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729093326; cv=pass;
        d=google.com; s=arc-20240605;
        b=OuOsPP+Y3CH4b5mrBtQLe1pvKq4Je0iTPvTOkk6O7xbWCjYCX1rfaVds0V1UQ0MV6i
         ITfS9mnSSXQRcLqSbU4Y4Wn6zxClESf7XOmSIPcIlAIgZPsBuGtrBZ7Tb785ihR+OXMM
         4FrMZRtP/nXeKEFzu9GLr5gnzQE3HUyhJO1oT3rQE2m5vw8LmGquDMYAOkXHDsGZiaBb
         WbJYxwqyQhXeAslueNxCeBoPTKpPL/VzsVNnV9dGOFQrvMhvm8z6I5SyZRZUkHFssKlv
         TXPLKkpfqp+ogW35UtFMv51JZ1n3Lia1E/c9qD3J/5qtggI9Dp5NHN0yaPLsFs6FJbB+
         rJhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=c8Kd57ZFo0etAPPvyVBFE3toUpg2sIrup1xOoD4z0BA=;
        fh=JBdFCwVMCiKYIA7gUVfzynp0nKj1wi5WfixCA4oW0S8=;
        b=XtdrG4VWA46xDrjAmYEm0h3g9hSBYP8oiDUVi1Ho4pqQCnoOUgurxrK+S1riLZLKMn
         yS3mwt9HFwicuPDdJlIVMDq0v145cJJKsqJNUBKlz4XiBz1piEURjWMVF/2rPYfjtaSf
         Ftt3ilhoXYbugtfaH4Af8iRv/6J8kT4FVCV3yMh99m8y8XfAana6D8FNuMDxVh68V/Uq
         /25tb9GV0UKJo+2artS+55auC6h/07ZuzzFYiwq+xZ4wFF2w3w5Ys2GOm9IUtz6F79GY
         8QXzjfE5/M7N2/6eQgQAoybpHBE2dzOmQJRwoBe8C2Kelh/Xx5OwC2I6UX8llbvbIBmw
         i1tA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PcxNTrAX;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729093326; x=1729698126; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=c8Kd57ZFo0etAPPvyVBFE3toUpg2sIrup1xOoD4z0BA=;
        b=bx4i5SG2YKNYAhfP6qFQ1JqY1mE9xxvF+YrgLdlyebdjmxmcLoz2Z93czSt9Sud1re
         8RNnV0I3R5qZ3UguKbMma0S05fNbwzzBTSN0EJlTbMsCBEGhRr912QRJQSMmylRWC4sr
         Wv6RhWM8m/Kv00LWfy2YtwVAIrDr5MJt6TkGD4UpBRpI37SRE8PbZEA3k+QDONThJZeG
         oX5EirmubrK+RfpsH0+eG53pX2wJseIL7hfiRHOLSsiijZFmvvModSu1W96Sqpa8lK7K
         9h+KPQbFB2tLDY/XN/i7qjSVgwQbpqmVpAZmAxnpwnmRvmElEW48059P9eY2wzHoaDJ6
         uD4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729093326; x=1729698126;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=c8Kd57ZFo0etAPPvyVBFE3toUpg2sIrup1xOoD4z0BA=;
        b=oGNZoWGc0AQP/dcRlretGLuKmITHwtsCTs7uARte2pDqdwmXZw31JganoufpW/vuqi
         GEpNhneSpELgZb+N0H9gPSjl75QCKQGhg/TaKFqOBrm/grtR9ccL5ikNzjVuRALnk4nG
         d8aIuC4N34Vd1BLaMvNZJ5qcKw+485VboUX7fTnNyZJWl3zTlFRbsVNoOr0B94qftSq4
         GgTKy82IzFEYQEA0pbIHnPGBq96kNqsEyNu4KCVRnkSmULK06y3qC/hxfC4snIXhsNo1
         ayhzG3EbAjhLz+lfANQy2yauMDh28JbkxD+GgZ0FBH16YE4KL2Xnrpn68trHTKKAR2F1
         TeCg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWrRZOBkN77kj36Ap1ZXHTWcaWoaBIKOhhhMqUNBPABcnxJbqtWynm8GArfJ3DxrznL8KyepQ==@lfdr.de
X-Gm-Message-State: AOJu0YxDcsvcrc4yfRFs5SbV4zydkxtnZgVQhcE82Iz+5E/G+0smZ1zG
	o+4cFqiDU2SnYH+iIfKeg36ebmC5KKpJ9d3p/Ixe2vWjhUf/Lmn2
X-Google-Smtp-Source: AGHT+IEe5Ba+U0wyDLB5rod+rRSMqwhFBjnD7Z+xOKA7lEC5M7ezTS9Cas3TSlStb75BXOvYN+w4Zg==
X-Received: by 2002:a05:6214:311e:b0:6cb:ef1c:743d with SMTP id 6a1803df08f44-6cbf007f5c2mr279961846d6.27.1729093326465;
        Wed, 16 Oct 2024 08:42:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5c44:0:b0:6cb:d0a5:f12 with SMTP id 6a1803df08f44-6cc36f68b8bls826666d6.0.-pod-prod-01-us;
 Wed, 16 Oct 2024 08:42:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuy6mg72raxToFyFRr4HXQTWlBn+m6/jOMkpBxin2WLcTBaCcXeukBlZlJc7OmUnZoFaFOsw0uhNA=@googlegroups.com
X-Received: by 2002:a05:6102:2ac6:b0:4a4:8fc3:9b7 with SMTP id ada2fe7eead31-4a48fc318eamr8886369137.14.1729093325757;
        Wed, 16 Oct 2024 08:42:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729093325; cv=none;
        d=google.com; s=arc-20240605;
        b=aaxq2tVqjsmOOP4JnqFTZJZkb8i9ShT/uk2fH+d5YOAiqlIHrV6JED1Aj9GQYkt7gB
         jNUdHEL43nYgqudM/mUK7GUqOZyYMrKQLFCqTM6QUJpy0sTcnJBvB85CicEbe+dfMZc5
         /9gG36Csg5PL9uKPjZGu8hIGgG/9cGrLTkACvKkkLjH5gH+EQcnvAhuvL3bnQohBiIXi
         TDhl+VBqG85XiAwFeecNZndO6eaU/xoeZbyIM6kBXz3zHcOt+SxQV1NynSt5Bc3QZuM9
         6xQG7bnPRWJ2Udl9aCM/eIOpVLThUUYsRqTbHvumPmsjvUP2xq3+J8Ynmr71d0wr87RH
         v/wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SAsqbT7F8ZH/bzSMugdy64lPBN/0mAPzdY7m+7h1gzw=;
        fh=7lbPjXPBrR8dSgG7ysvKWnMIE29dr8yWrocKYwe0ENg=;
        b=f5uIYUdIvAVeqtZQ/P8kr49BygoXNL0ILXEfKsF9/NtrKc25SLHFgrLybVMRanJ0OT
         0ax4y37U1YpUkKz/Gc5fHsStu2wWEc8rYBrq2C2SAxGqOU/2TQy12DOTlnEDSL28o8iJ
         HB0Vb8O/az+AN3CKqw5L1n+wS1IUzOJ/pwFWWtHWnObt6upT0buDB3nme6DgZTiB/r76
         p6zn62qZ9M0xH1XMLdPgYTTQl+h4D76n4aA8wqu/lQ1/Q40w0PPFq/RrsbPFCPitBU0y
         2FlmRAZiidQqdnOxQ1seBIJzi87lmfD8Vvn7JMVL5BPErO0sGLN06wUQ6c8DLAsj7nCP
         CarQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=PcxNTrAX;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.10])
        by gmr-mx.google.com with ESMTPS id ada2fe7eead31-4a5acc321fbsi175313137.2.2024.10.16.08.42.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 16 Oct 2024 08:42:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as permitted sender) client-ip=198.175.65.10;
X-CSE-ConnectionGUID: CsFavTpYQRWiKcuYAMurvA==
X-CSE-MsgGUID: OvgWxzxISh+DFtX7t0NltA==
X-IronPort-AV: E=McAfee;i="6700,10204,11222"; a="46021361"
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="46021361"
Received: from fmviesa001.fm.intel.com ([10.60.135.141])
  by orvoesa102.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 16 Oct 2024 08:42:05 -0700
X-CSE-ConnectionGUID: UUGX2kglTD2IGECAAw+E6g==
X-CSE-MsgGUID: 51KYtXJaTQ6dVWcB49DHcg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,208,1725346800"; 
   d="scan'208";a="109018920"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by fmviesa001.fm.intel.com with ESMTP; 16 Oct 2024 08:42:01 -0700
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
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Narasimhan.V@amd.com
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v3 2/3] mm/slub: Improve redzone check and zeroing for krealloc()
Date: Wed, 16 Oct 2024 23:41:51 +0800
Message-Id: <20241016154152.1376492-3-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20241016154152.1376492-1-feng.tang@intel.com>
References: <20241016154152.1376492-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=PcxNTrAX;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.10 as
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

For current krealloc(), one problem is its caller doesn't pass the old
request size, say the object is 64 bytes kmalloc one, but caller may
only requested 48 bytes. Then when krealloc() shrinks or grows in the
same object, or allocate a new bigger object, it lacks this 'original
size' information to do accurate data preserving or zeroing (when
__GFP_ZERO is set).

Thus with slub debug redzone and object tracking enabled, parts of the
object after krealloc() might contain redzone data instead of zeroes,
which is violating the __GFP_ZERO guarantees. Good thing is in this
case, kmalloc caches do have this 'orig_size' feature. So solve the
problem by utilize 'org_size' to do accurate data zeroing and preserving.

[Thanks to syzbot and V, Narasimhan for discovering kfence and big
 kmalloc related issues in early patch version]

Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slub.c | 84 +++++++++++++++++++++++++++++++++++++++----------------
 1 file changed, 60 insertions(+), 24 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 1d348899f7a3..958f7af79fad 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4718,34 +4718,66 @@ static __always_inline __realloc_size(2) void *
 __do_krealloc(const void *p, size_t new_size, gfp_t flags)
 {
 	void *ret;
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
+	size_t ks = 0;
+	int orig_size = 0;
+	struct kmem_cache *s = NULL;
+
+	/* Check for double-free. */
+	if (unlikely(ZERO_OR_NULL_PTR(p)))
+		goto alloc_new;
+
+	if (!kasan_check_byte(p))
+		return NULL;
+
+	if (is_kfence_address(p)) {
+		ks = orig_size = kfence_ksize(p);
+	} else {
+		struct folio *folio;
+
+		folio = virt_to_folio(p);
+		if (unlikely(!folio_test_slab(folio))) {
+			/* Big kmalloc object */
+			WARN_ON(folio_size(folio) <= KMALLOC_MAX_CACHE_SIZE);
+			WARN_ON(p != folio_address(folio));
+			ks = folio_size(folio);
+		} else {
+			s = folio_slab(folio)->slab_cache;
+			orig_size = get_orig_size(s, (void *)p);
+			ks = s->object_size;
+		}
+	}
+
+	/* If the old object doesn't fit, allocate a bigger one */
+	if (new_size > ks)
+		goto alloc_new;
+
+	/* Zero out spare memory. */
+	if (want_init_on_alloc(flags)) {
+		kasan_disable_current();
+		if (orig_size && orig_size < new_size)
+			memset((void *)p + orig_size, 0, new_size - orig_size);
+		else
 			memset((void *)p + new_size, 0, ks - new_size);
-			kasan_enable_current();
-		}
+		kasan_enable_current();
+	}
 
-		p = kasan_krealloc((void *)p, new_size, flags);
-		return (void *)p;
+	/* Setup kmalloc redzone when needed */
+	if (s && slub_debug_orig_size(s)) {
+		set_orig_size(s, (void *)p, new_size);
+		if (s->flags & SLAB_RED_ZONE && new_size < ks)
+			memset_no_sanitize_memory((void *)p + new_size,
+						SLUB_RED_ACTIVE, ks - new_size);
 	}
 
+	p = kasan_krealloc((void *)p, new_size, flags);
+	return (void *)p;
+
+alloc_new:
 	ret = kmalloc_node_track_caller_noprof(new_size, flags, NUMA_NO_NODE, _RET_IP_);
 	if (ret && p) {
 		/* Disable KASAN checks as the object's redzone is accessed. */
 		kasan_disable_current();
-		memcpy(ret, kasan_reset_tag(p), ks);
+		memcpy(ret, kasan_reset_tag(p), orig_size ?: ks);
 		kasan_enable_current();
 	}
 
@@ -4766,16 +4798,20 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
  * memory allocation is flagged with __GFP_ZERO. Otherwise, it is possible that
  * __GFP_ZERO is not fully honored by this API.
  *
- * This is the case, since krealloc() only knows about the bucket size of an
- * allocation (but not the exact size it was allocated with) and hence
- * implements the following semantics for shrinking and growing buffers with
- * __GFP_ZERO.
+ * When slub_debug_orig_size() is off, krealloc() only knows about the bucket
+ * size of an allocation (but not the exact size it was allocated with) and
+ * hence implements the following semantics for shrinking and growing buffers
+ * with __GFP_ZERO.
  *
  *         new             bucket
  * 0       size             size
  * |--------|----------------|
  * |  keep  |      zero      |
  *
+ * Otherwise, the original allocation size 'orig_size' could be used to
+ * precisely clear the requested size, and the new size will also be stored
+ * as the new 'orig_size'.
+ *
  * In any case, the contents of the object pointed to are preserved up to the
  * lesser of the new and old sizes.
  *
-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241016154152.1376492-3-feng.tang%40intel.com.
