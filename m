Return-Path: <kasan-dev+bncBDN7L7O25EIBB2FBZCNAMGQE26MQBUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EF01606E49
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Oct 2022 05:24:25 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id l7-20020a19c207000000b004a471b5cbabsf471678lfc.18
        for <lists+kasan-dev@lfdr.de>; Thu, 20 Oct 2022 20:24:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1666322664; cv=pass;
        d=google.com; s=arc-20160816;
        b=pGSCHb48WXl1jhrrV18QVTV8kr/hxI4yTd7N/saTrN3OCoUmeMUb8ky/Cje3bADXXg
         aODdvwzbTUSmKzBX4RIh3B3jlDYmW7c/ba1l5bh/jx/to6f9b/qR8anB7Ux6UkffkncO
         fn4Ajp1yMwEsx1B1YmcdOBmYGiLLRQlj5M6jqZ//EBuC7kPXsUnDpcKx9VFemVgbNLlh
         R0+F0ZqnTq7NumZhJnOkYMghUA6P0xsyeX+N0kBOf49sawKvYuej7PIEejIj2pxY7FbX
         ZS4SQexPt8ZcS1bZa4VtiPjilG7bS0ycfx3OleXjvti7wwRElO1GhT1WT8CCSBuw+gnL
         d4Hg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=bvVQIJSCXnlJBfkPX68sHnZlsoMpaX/Z++f8ZK/KOx4=;
        b=yEn5bkER+LTm0U5wZX/S7lsbWuRC8ycR7SeOq4jd9vgh0aYq4qeJ20oc+SKW0wo9sM
         r/TIpek9M/k/V5ED2z1rZ1zXyXWbQ5GEuBUib2MRHu0IZrtKJzV/Ok9KTQNlBV6ApegH
         JO1cinTELyXK3usvud/Xrd4jwNlm2hYcAc2gp1BeJ1HDqT7U3n5hwrBbL/0WOSfRgShT
         UU/oIZvnh1klPq8mBc9ipOGYTWMBglc6RPOHGAs2bwF4jkKKcYxdVSBeH1BUVAFTgLiS
         r3FQj6EWEEeTsPEgBu1j00N2dzFfidW1iRp2Cyvv6o3YyO+M7QRxS78NQVPm96w2OgQO
         S3SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=katAm9rP;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bvVQIJSCXnlJBfkPX68sHnZlsoMpaX/Z++f8ZK/KOx4=;
        b=Zhz88YnF8rHqXVhGxQ9yzptNvlfBWwxr/IY0/I3+k4ZsNO54yV34Pz4SKtxACiKeM8
         c3h8OSHuhMuPzNA/6pn/vTfK7fRgeXeriTr5ueis5ZCtb0JmaiJDksGf8ZHEURiwLtIF
         Yj6V5f3ItLXTcI0B8oaIV929o3XcfTuuWVM3E1C7eYztOsER7mhBd7tuMIh66C5SWfmY
         hKb8/uBKRd7ctcwVfQsHFBpiahDwAMwkbjjk2HlN8niZ9NP40arTQx6EPcPyx2llKnjU
         aMy1G8IcdHvFGc74xW9z+tMTdrU/ou9iv7YTYQsywKQiYncpK20JWSngZTALf4qNpACJ
         3gZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bvVQIJSCXnlJBfkPX68sHnZlsoMpaX/Z++f8ZK/KOx4=;
        b=f+/5gEDbI6kacl/wVX7T6UZAEw64Sq01rVzvt9sk1SKI727G1fvm7LTkuHPqgUlG8v
         25B8dCjXbgQ/DKseoAVTucJRB0uh5I/3cLas59+knSFDCdS7xKoXL+FnvlkXNRWo1RAI
         nAuje1O+3VWH5lZJE/dO6IOFmYFmgF11wFvkOnBy6yzSO7NIzDMUgP3izVtgb2nW4QeB
         11FCX3KlypYMYVB/vvSZLKgCnalf0lYcEiKEj2MmhLPdWa2bkLHFat3kBX5VzCwQwO8/
         vm1WXPPsrdvjEArJuAzBA66WUYUkJEA8Bu9GO29SGstQWtkd9lMLbDMlifp9CvZQVntq
         WHtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2Z//erQIeWwZFpyB+fHFtYJHf/BkXusz96j5PeZOmLNdtvWxZp
	xqH07C65YblgAF3jW0ClHBk=
X-Google-Smtp-Source: AMsMyM5p3NFLFUkHe4Z2asggZVFM80gs5DN1MpaTCW9nx3s7qtE/7GMjmUhNz9yUOAMlx+VKwCqyMg==
X-Received: by 2002:a2e:84ca:0:b0:25d:77e0:2566 with SMTP id q10-20020a2e84ca000000b0025d77e02566mr6355293ljh.78.1666322664759;
        Thu, 20 Oct 2022 20:24:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1c7:b0:26d:cef8:8887 with SMTP id
 d7-20020a05651c01c700b0026dcef88887ls280717ljn.7.-pod-prod-gmail; Thu, 20 Oct
 2022 20:24:23 -0700 (PDT)
X-Received: by 2002:a2e:8ecc:0:b0:26f:dd45:e50f with SMTP id e12-20020a2e8ecc000000b0026fdd45e50fmr6332950ljl.48.1666322663610;
        Thu, 20 Oct 2022 20:24:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1666322663; cv=none;
        d=google.com; s=arc-20160816;
        b=EWDlo+HqQuN5KnVpznGD4slZsd6OzCLXwoWoqf31slADMe1E1mUBb5rMUoR9LG/Mu1
         BqjeEVQK3vxQmbn/6Ae2LDlycg0WWYi6N3keNVzcLf1hmZzdp5IRGwBkw8IuuRuo9XCc
         w4B9UE53X1z3qmY0AnAq+GuiRkZo1TQ6jrzhvw0BZpPwIxLki0ekX/X9odi/uZNbzmtJ
         LQ/Vy6hUcqgOEY586EWtULf1VNf4rTQje4qy7l12N/oOPGfBxn8COcw5/056TbFTJ9Hs
         XSn/p47epkPC9f8xzbHvxrJdcJV05HxIjy5MDpkSfoS4M/XJFva00t94nieYhcOJwPT1
         DgeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ms3Ytik3W/RJebwRdrY+iMC5yNLhiRgPO9DIkBKR5Fk=;
        b=FehDaELnhZIX8nwoboS3sJyFqJ92FTS7aHivASmWnCvR3nz08SusbfVWauVxIQpU/2
         20SI8NOan4KNre91sC1rTJ5mmhnkghnF+oQWGjr03aR7dJS1R6EOnDFkk5XC27NAMWnR
         wp5EZyDg9oZAJ+It4JfrvQgaEf2nr3PcvhW2VV1fRvndnvSt8KJta50jX6tlr3J8UgKM
         ALloVDo3n6TvJVl9xgcaFU0npk8b8dU9AfxR893TXcTs2YT2gAkMoB1M3und+YbXvn+1
         Pl1O8YkecZPsy+AUL70lD22inPUCpfemxP8CMVyRoT1P9xQvxAOhNqFmn+dMK6X60Hbk
         nFdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=katAm9rP;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga07.intel.com (mga07.intel.com. [134.134.136.100])
        by gmr-mx.google.com with ESMTPS id k20-20020a2eb754000000b0026fb09d81bbsi595748ljo.1.2022.10.20.20.24.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 20 Oct 2022 20:24:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as permitted sender) client-ip=134.134.136.100;
X-IronPort-AV: E=McAfee;i="6500,9779,10506"; a="371114077"
X-IronPort-AV: E=Sophos;i="5.95,200,1661842800"; 
   d="scan'208";a="371114077"
Received: from fmsmga003.fm.intel.com ([10.253.24.29])
  by orsmga105.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 20 Oct 2022 20:24:22 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=McAfee;i="6500,9779,10506"; a="719459612"
X-IronPort-AV: E=Sophos;i="5.95,200,1661842800"; 
   d="scan'208";a="719459612"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by FMSMGA003.fm.intel.com with ESMTP; 20 Oct 2022 20:24:19 -0700
From: Feng Tang <feng.tang@intel.com>
To: Andrew Morton <akpm@linux-foundation.org>,
	Vlastimil Babka <vbabka@suse.cz>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Kees Cook <keescook@chromium.org>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v7 3/3] mm/slub: extend redzone check to extra allocated kmalloc space than requested
Date: Fri, 21 Oct 2022 11:24:05 +0800
Message-Id: <20221021032405.1825078-4-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20221021032405.1825078-1-feng.tang@intel.com>
References: <20221021032405.1825078-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=katAm9rP;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.100 as
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

kmalloc will round up the request size to a fixed size (mostly power
of 2), so there could be a extra space than what is requested, whose
size is the actual buffer size minus original request size.

To better detect out of bound access or abuse of this space, add
redzone sanity check for it.

In current kernel, some kmalloc user already knows the existence of
the space and utilizes it after calling 'ksize()' to know the real
size of the allocated buffer. So we skip the sanity check for objects
which have been called with ksize(), as treating them as legitimate
users.

In some cases, the free pointer could be saved inside the latter
part of object data area, which may overlap the redzone part(for
small sizes of kmalloc objects). As suggested by Hyeonggon Yoo,
force the free pointer to be in meta data area when kmalloc redzone
debug is enabled, to make all kmalloc objects covered by redzone
check.

Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Feng Tang <feng.tang@intel.com>
Acked-by: Hyeonggon Yoo <42.hyeyoo@gmail.com>
---
 mm/slab.h        |  4 ++++
 mm/slab_common.c |  4 ++++
 mm/slub.c        | 51 ++++++++++++++++++++++++++++++++++++++++++++----
 3 files changed, 55 insertions(+), 4 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 8b4ee02fc14a..1dd773afd0c4 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -885,4 +885,8 @@ void __check_heap_object(const void *ptr, unsigned long n,
 }
 #endif
 
+#ifdef CONFIG_SLUB_DEBUG
+void skip_orig_size_check(struct kmem_cache *s, const void *object);
+#endif
+
 #endif /* MM_SLAB_H */
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 33b1886b06eb..0bb4625f10a2 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1037,6 +1037,10 @@ size_t __ksize(const void *object)
 		return folio_size(folio);
 	}
 
+#ifdef CONFIG_SLUB_DEBUG
+	skip_orig_size_check(folio_slab(folio)->slab_cache, object);
+#endif
+
 	return slab_ksize(folio_slab(folio)->slab_cache);
 }
 
diff --git a/mm/slub.c b/mm/slub.c
index adff7553b54e..76581da6b9df 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -829,6 +829,17 @@ static inline void set_orig_size(struct kmem_cache *s,
 	if (!slub_debug_orig_size(s))
 		return;
 
+#ifdef CONFIG_KASAN_GENERIC
+	/*
+	 * KASAN could save its free meta data in object's data area at
+	 * offset 0, if the size is larger than 'orig_size', it will
+	 * overlap the data redzone in [orig_size+1, object_size], and
+	 * the check should be skipped.
+	 */
+	if (kasan_metadata_size(s, true) > orig_size)
+		orig_size = s->object_size;
+#endif
+
 	p += get_info_end(s);
 	p += sizeof(struct track) * 2;
 
@@ -848,6 +859,11 @@ static inline unsigned int get_orig_size(struct kmem_cache *s, void *object)
 	return *(unsigned int *)p;
 }
 
+void skip_orig_size_check(struct kmem_cache *s, const void *object)
+{
+	set_orig_size(s, (void *)object, s->object_size);
+}
+
 static void slab_bug(struct kmem_cache *s, char *fmt, ...)
 {
 	struct va_format vaf;
@@ -966,13 +982,27 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
 static void init_object(struct kmem_cache *s, void *object, u8 val)
 {
 	u8 *p = kasan_reset_tag(object);
+	unsigned int orig_size = s->object_size;
 
-	if (s->flags & SLAB_RED_ZONE)
+	if (s->flags & SLAB_RED_ZONE) {
 		memset(p - s->red_left_pad, val, s->red_left_pad);
 
+		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
+			orig_size = get_orig_size(s, object);
+
+			/*
+			 * Redzone the extra allocated space by kmalloc
+			 * than requested.
+			 */
+			if (orig_size < s->object_size)
+				memset(p + orig_size, val,
+				       s->object_size - orig_size);
+		}
+	}
+
 	if (s->flags & __OBJECT_POISON) {
-		memset(p, POISON_FREE, s->object_size - 1);
-		p[s->object_size - 1] = POISON_END;
+		memset(p, POISON_FREE, orig_size - 1);
+		p[orig_size - 1] = POISON_END;
 	}
 
 	if (s->flags & SLAB_RED_ZONE)
@@ -1120,6 +1150,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 {
 	u8 *p = object;
 	u8 *endobject = object + s->object_size;
+	unsigned int orig_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
 		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
@@ -1129,6 +1160,17 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 		if (!check_bytes_and_report(s, slab, object, "Right Redzone",
 			endobject, val, s->inuse - s->object_size))
 			return 0;
+
+		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
+			orig_size = get_orig_size(s, object);
+
+			if (s->object_size > orig_size  &&
+				!check_bytes_and_report(s, slab, object,
+					"kmalloc Redzone", p + orig_size,
+					val, s->object_size - orig_size)) {
+				return 0;
+			}
+		}
 	} else {
 		if ((s->flags & SLAB_POISON) && s->object_size < s->inuse) {
 			check_bytes_and_report(s, slab, p, "Alignment padding",
@@ -4206,7 +4248,8 @@ static int calculate_sizes(struct kmem_cache *s)
 	 */
 	s->inuse = size;
 
-	if ((flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
+	if (slub_debug_orig_size(s) ||
+	    (flags & (SLAB_TYPESAFE_BY_RCU | SLAB_POISON)) ||
 	    ((flags & SLAB_RED_ZONE) && s->object_size < sizeof(void *)) ||
 	    s->ctor) {
 		/*
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221021032405.1825078-4-feng.tang%40intel.com.
