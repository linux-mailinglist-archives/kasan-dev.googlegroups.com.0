Return-Path: <kasan-dev+bncBDN7L7O25EIBBN7ZQS3QMGQECN7Q7AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 591E3974A8D
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2024 08:46:16 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4585419487asf4457151cf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 23:46:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726037175; cv=pass;
        d=google.com; s=arc-20240605;
        b=lodzhJIaqMYSqaLtKyT/E9zMWTZyxbr0n85Q6cmsOonQXmoNYxiuridQnonrYxIVgv
         2RvcH7OpkhOQkaPN+NGVFrtYDlh9kL5oGtH/EP/IYG337nNMYVIjnJsXh1p4LfvUoKhr
         rMCGbpBpdbOKgSjphbpyoQnargMvlLOjXPwdXhLb4Bs2NoA6fiSpxc5nNQpBFmkV0kRK
         na3REN8NHxWqg3Lh+gsA3KS2SxOve1zQHs8/xk3USwVrXb+oQjb0kcyOM9h2RKv2m/hN
         MRQrzyjIBxgkLVCSzo2hdCPE//ZaCXCGd8vXMHKGxEYflab0pHB3LC903HriGPa4SSbc
         8RMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=P8Fa2YqTBTfLHeNu3LiOuY9NAvmATFFAjNFHnvNjvLs=;
        fh=qDiC75aP/z1Ky65g7NfiTIs8s03egkRPucj8Ot7GG4Q=;
        b=ah2H4gHUnVA5qdOpfplSvfl6inNRIQEbhiuST/EqyN4rq4jhoa76/yNJguZ50VBuCb
         v6zhY1grQti20kCMdHH1P3/s0ENgg680t1B+Iv8A/tQcu7GTZjhtXtnTbf86XQ3jgAzg
         fcdGHCnLrBZcBb0JDn7trpxG9rKKpoNjF59ElPQWwP9zhhlr/h0HBAtzC/K5a4B1MLKZ
         ia8cCNl0DSyX12UYH3EBcBQvu/9YeoBlh1OEtypddK7Cf0sGGcyZJPx0//zKaT50FzP5
         iHbZPUSh2kREKSyB1K3fRZFO5Tdry5CU7n4iEpNLssQlECC1cWaUEbWWo32R8/319TxW
         mx/Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=n9yclDSe;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726037175; x=1726641975; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P8Fa2YqTBTfLHeNu3LiOuY9NAvmATFFAjNFHnvNjvLs=;
        b=RO1LjkxWBO8ze5RzzFIavSe/jWez4lyRft6EU5iiiDS+ghqEx8C8pWMjUyJTddG5Lo
         N0Gz+lCTYXTbXv79nx26wadZT2eyvi68wbYKWhJp+v09XIjneUi/LPC1m43VpmrJedE0
         Dmr2UGX43EA9/97kt97+vjXtHR1UxGlcHvDcYJI0NAYyVtsO2fx1lZKswnz/jQxPkYm4
         lMeUMbjfhEgd5uzaaaDINxuW0D5X0Pvrz032xEEtOjpku+/AE4uyT4MDFFtRVxxPa9K8
         Kz/mHjyMiukVreBIVWu8oVzhBnIt7hVk7Ys29V86MOTrTYH1we62YycwnvEK3v1kUI+m
         mrtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726037175; x=1726641975;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=P8Fa2YqTBTfLHeNu3LiOuY9NAvmATFFAjNFHnvNjvLs=;
        b=AT9Bs1BTTjK4bui8s5dOESU4Y6G/n1NvTnvyYuGMG8ZHv1fHyOiSvlUE2EFZ0P/0kx
         iL9c/HisPcEmotJ03Utb6xOcxWN5u9N9DrdIBCTw4Y1MvHjQvPKc3Fqw49yKsxMo7OmB
         v0r9ds6QUpfzGUArJuAeXSHegNtxHasbUK9yI7wZVy89oYfX/V/9gzCATB+P+jtQu2DE
         vqj80Ilg3Y5m45/5gQyTZDaIR14qFq5h5x9v8h2FS6otOHqZiVJoTxbcxxWPFi4QxMLU
         oYE2bOE9OVYtC0VumtiCmvjdGrdZal3MLylAHtG87qvGwzBqPUcHXmwYsBN4UkIdpOvD
         GPGQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQJLLpQqjXlWWiiUficIgKIxJ7QWBOFoWWwFSvDr8exeNo8w3GuGePZt8eAPdTLgfgRb4a4Q==@lfdr.de
X-Gm-Message-State: AOJu0YwhM6PJygHX/q9uh5q+d1bc23xXCCXwNvS4a/0yGJKjxuvpbkrG
	2JCqH1S2DwiRdJdjyhiyHw+bMu8BInpix/Dg3po26LpNRQ629ZEp
X-Google-Smtp-Source: AGHT+IEcLY6BTmEQb35hnbFv01CpxdPuW0m7Qv4f4mGPNGCIc1dxRyJROifbvHEd+BRE0PptcBw7Eg==
X-Received: by 2002:a05:622a:34c:b0:455:b00:f02d with SMTP id d75a77b69052e-4584e967593mr46958641cf.49.1726037175164;
        Tue, 10 Sep 2024 23:46:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:10a:b0:458:2dcf:c764 with SMTP id
 d75a77b69052e-4583c937112ls30013461cf.2.-pod-prod-03-us; Tue, 10 Sep 2024
 23:46:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWoMBsLtDDv5i0AJcHWj1RMoYCnsJjCa2ZrIEJqoiCSdj98I3ttfatkA5CJGKQwzZZ33108b+aMN9k=@googlegroups.com
X-Received: by 2002:a05:622a:1815:b0:457:f8b1:a042 with SMTP id d75a77b69052e-4584e91da18mr30488621cf.33.1726037174472;
        Tue, 10 Sep 2024 23:46:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726037174; cv=none;
        d=google.com; s=arc-20240605;
        b=HDhzA7SK32068kSTHybDDfSubzBceeeHmImbk/uJE+2BJzdDiP3xOULz0c6vdgPY3A
         cfwQgAsbKkkv/tmXB2w5fsi7PQ9oV+uH5y33IEMgr2U0+QUkULlEhA5SeI39LmCCsyBz
         kQB2GYUiTxWvKTsXcy/rRVmHpI1INn4SmCqqHTDqmQC4hT+xlsUeqjNkH5UKABxtZq+H
         u3NKARIqCKJLAEjxVah3hHEtiLShwHXaSwLdKvjcEAtLSRDVmTtj78z20kBxqVG5nJ6S
         V6Upq+RYHUjd+bVWHX0s3FMuycwzGnzNdPqLLCtF71rYaIvx9wYGPOqa3uJox5GzydLC
         Y/4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sQnDdI6wKIFdlJ+Rjok4zmD0BtF30gqRHIfs4m6lyC4=;
        fh=Xs830Dl/dg7cBD7Cjxi4zgG6B28PocXmmZIfDH/IGEM=;
        b=NmMvAyMBjgnrlI7KSZ3ZQvAdenYLEahKUz/KWMzJInlYTSTQURJoyQbSCtZg28Fe2Q
         EhoP7+JDJMyLue53IGyhCrSkYR/Rok6gQPY2Q/xbnh8++xp+oVdiLzyR+PfbM/mZrUJx
         /bLC8G9cTmJvkcn1yGgXTCrZt41bYSMVf2+mTrL2H0V09gX2gQ92VVI25cX5WFo8IJ7Y
         kHVWlzaGQx7co1yCtlyOie1sgKaf4PGGI/Lbi6p0JXizFK1ZPwxV8SORMoWTAKwgS9Ri
         FZ3Wmnd54uvUm40yjhMBdmMPVmzIUIZc5bU5Vvx8/NZi+DrqqbqO/oS/8DSDf8q2aJkm
         S+Rw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=n9yclDSe;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-458230c72d5si3632121cf.5.2024.09.10.23.46.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Sep 2024 23:46:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: DZKKtBMCT1uGNhM0Y74EkQ==
X-CSE-MsgGUID: b0vwKxpaQoK97ySYSY5GyA==
X-IronPort-AV: E=McAfee;i="6700,10204,11191"; a="36173028"
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="36173028"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2024 23:46:11 -0700
X-CSE-ConnectionGUID: v543qwycT2WvE2geGxwVvA==
X-CSE-MsgGUID: Ll8xYtUdRRW3q2YxBIkspA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="67771506"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa007.jf.intel.com with ESMTP; 10 Sep 2024 23:46:00 -0700
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
Subject: [PATCH v2 4/5] mm/slub: Improve redzone check and zeroing for krealloc()
Date: Wed, 11 Sep 2024 14:45:34 +0800
Message-Id: <20240911064535.557650-5-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240911064535.557650-1-feng.tang@intel.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=n9yclDSe;       spf=pass
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

Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slub.c | 54 ++++++++++++++++++++++++++++++++++++++----------------
 1 file changed, 38 insertions(+), 16 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index c1796f9dd30f..e0fb0a26c796 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4717,33 +4717,51 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
 {
 	void *ret;
 	size_t ks;
+	int orig_size = 0;
+	struct kmem_cache *s;
 
-	/* Check for double-free before calling ksize. */
+	/* Check for double-free. */
 	if (likely(!ZERO_OR_NULL_PTR(p))) {
 		if (!kasan_check_byte(p))
 			return NULL;
-		ks = ksize(p);
+
+		s = virt_to_cache(p);
+		orig_size = get_orig_size(s, (void *)p);
+		ks = s->object_size;
 	} else
 		ks = 0;
 
-	/* If the object still fits, repoison it precisely. */
-	if (ks >= new_size) {
-		/* Zero out spare memory. */
-		if (want_init_on_alloc(flags)) {
-			kasan_disable_current();
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
 			memset((void *)p + new_size, 0, ks - new_size);
-			kasan_enable_current();
-		}
+		kasan_enable_current();
+	}
 
-		p = kasan_krealloc((void *)p, new_size, flags);
-		return (void *)p;
+	if (slub_debug_orig_size(s) && !is_kfence_address(p)) {
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
+		if (orig_size)
+			memcpy(ret, kasan_reset_tag(p), orig_size);
 		kasan_enable_current();
 	}
 
@@ -4764,16 +4782,20 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
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
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240911064535.557650-5-feng.tang%40intel.com.
