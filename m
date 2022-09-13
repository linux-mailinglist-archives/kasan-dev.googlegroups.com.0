Return-Path: <kasan-dev+bncBDN7L7O25EIBBSGSQCMQMGQECK24UXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id B15245B6834
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Sep 2022 08:55:04 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id d30-20020adfa41e000000b00228c0e80c49sf2807746wra.21
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 23:55:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663052104; cv=pass;
        d=google.com; s=arc-20160816;
        b=z3VnHQrHYE9xjoK4D/If+Hi+6aQcTQOj5u2/I2NXn1FqrNHRx/OBXkM7COSDV85Lj1
         COnnCjXxYTC1r4lskfJ+zS9C58s233D9Ns9fFe0gt4DqGhGBLzviPFvMz9Qf08vJ0joX
         P0ZfpFhtkz3AFysT5qvXDskmz+icGYNmZz/veMKHbg6k2ssjllsIAwkRZtqYrRu9CX33
         rFZWAIBLhrXMeaHYppUsZXLwzA+xQajsTHrLIC2EVZMUkM2KJG+25Tka/jbpfC5ynbHP
         DHZnekTX6jOPrr4Od6jgqIkR1p2ojk2d++Cj2VS2gOTmj+reYZ91oQrrQWg+woQaAOyV
         FWBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=MlB8zyeeZpFjnpgk82srI4x6ADG1gmCsDxOVqm+MCT4=;
        b=iRlCtsKK6gOriwBmKdbuHMgCOndPyXafQKmcgnpApClSsFG2I1lOK3fvTY56SI1ieD
         dFV6VrEBu4EfSCggm+Hw1yqmil2RN1636MoR5RjV8GmHxhvic6TeqsIkN5KT43I0QvgI
         ncg/uM7cluielolgf2GsfEPiKrdB/nvFeZHGpD3e+Vh0DBqfsALWmVfGgisP3rR5BhsH
         Y5TsCy6hTObsKcAcLvFg4v66lnO8o8h8gSRCQqGMSOPdsH6LE6GdXxS3n78K3DMWsTIz
         ZoRuvUfromwubti/+z0gbSmsyW6OX6Jx0b2hioAgEC8JrBD7ZP49dzZwS62iCmkovlrq
         CKig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=XrvVyepK;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=MlB8zyeeZpFjnpgk82srI4x6ADG1gmCsDxOVqm+MCT4=;
        b=pgPbHvx2cnAFSrXlsaw7nDVUHLEoTud4Ma6/QTC6t1x5CtJPu6ZGKYP59n6jhpL67Q
         wrQH66+pCMHW7LEcjvLEH6G5LW8PVLbGoS8mD4n0Zn+xvURCMPINLfIgupa/y8z+LBO7
         IU279qB8mDbm3R/r+wouQ+go/J0pjvO7DCPyFkkBRa370qZBpoVDkrSB9Ms1H0GAW9rg
         XfT4diHdcRfof41dygholMShY1udnhPVDzfV2hzW/OnXxsJuCltAuroH1FA39YyF/BR+
         Q06JHNBoN3JXE+H746OdvJ4WbAhqPFcrjoP7whvfKDTT4lGT17QKf8ynyfko9Dl0iENF
         JQ0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=MlB8zyeeZpFjnpgk82srI4x6ADG1gmCsDxOVqm+MCT4=;
        b=arDqZ2UrYoAaKVcLzktPAtMjgbdPCHpGi+HAVM5wpr5Cqi8DqDaBJLXY2Gx5TIb2LX
         Q6pegPftC3+ObBjaihhjOPVqykLt/cjzREfeJEHDlj2lGtDdQusNOifv8+mQTN0NTYtb
         jmKFaogJEHyxOqg9DMs0SrbJy7hY2h1L77uVrBb1NxuSv0XeywVtwQaJsi7avzQ3M/Rv
         +9qA7NzlH05MtzSJVWluCe2uAo8nJhDkopb5woxVpntZFRcQRfBKLWx7o8WUAUFb97LY
         ElaFO4DxB45XCaOEQDS6xOWFiOtv0RufYoeZagmd2p6odCiUgMPx4f8Yt2wSoG66XYBr
         nl1Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1q1Tq1c52GfVqcugevdbs1OGomli0HP0pgP+EgE5KwgHKzV4KH
	aqUecz8xTSLaMlrpb7bj5bg=
X-Google-Smtp-Source: AA6agR4msl05G7vIP+SBjyipub2SsqTvDa2I9dT9F7PRSVAYHwBTPIMrna54wV6xGBtujn8E4jFrpA==
X-Received: by 2002:a05:6000:144f:b0:22a:7098:6472 with SMTP id v15-20020a056000144f00b0022a70986472mr6369860wrx.685.1663052104299;
        Mon, 12 Sep 2022 23:55:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:256:b0:228:a25b:134a with SMTP id
 m22-20020a056000025600b00228a25b134als1505550wrz.0.-pod-prod-gmail; Mon, 12
 Sep 2022 23:55:03 -0700 (PDT)
X-Received: by 2002:a5d:64c2:0:b0:228:cb3e:1ce with SMTP id f2-20020a5d64c2000000b00228cb3e01cemr17213854wri.392.1663052103351;
        Mon, 12 Sep 2022 23:55:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663052103; cv=none;
        d=google.com; s=arc-20160816;
        b=PFxnDEGcIIsArQdBkWIaiTKpSgg2uezlCzNfrCdXqGs7sBw0JYHoVFWPHf/D/qmqdN
         vFWlzkvWv3Fv65Ada0aF9tOOuLsUVYfY/fmBnz6eg54PFL0dNLkKNQcl3uaPGxD38+3c
         2F8F5d3m+Dvf75bWEraEsJuWLLc5/pTDkr6FpVvZNw491gBAH7DI8hdcFn2mBkCbZEb2
         p/8Dlxm2ZDRk2T9CMRTzWu/Wa1eCq7PTpPgdrbZgLGEXvCpMgdiY4QDh9mry/YGTUrxZ
         yEZKRxnqMaC585RPniOTo8/07xua5EUVqMRSobNRQfk6vmC5b/a+YeyhEtikFQE/r1pY
         iIjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=17ru2aScMcm/B0OnyQ31ceHqJ7mFMov0F/bGaFPOtys=;
        b=dRss1PZkay1kDe3uwNbkCe9YUNZbgFDEmmtwAFNEbJESScL48JcE60mKvAsGqqvYgK
         Fzipt8R1yJplpoWvbhxy90ezAzRnQNa2IAV/LRO5Br4DIt5clciHIm8ExkFb8hYaxGnK
         fQBB/3gKkIwnpSBTD3kuGJWEv7CMgJXrLQFgnLJr54mKAVawEB8mwxLcydd8XV8I/zq/
         aabFIUA29EKfQ+IWKWDzEEoRSN4lB9qrtgw29ybF33p3ePYN1aOE/PCcD792U7ozbSxc
         bujQEn3YG5jdJ9NRj8wFQm7LSZKwToKhjaCN4nGJLMq6h5iJCrUSvStXuHRP/uZrzEkG
         pq1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=XrvVyepK;
       spf=pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga02.intel.com (mga02.intel.com. [134.134.136.20])
        by gmr-mx.google.com with ESMTPS id f62-20020a1c3841000000b003b211d11291si13124wma.1.2022.09.12.23.55.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 12 Sep 2022 23:55:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as permitted sender) client-ip=134.134.136.20;
X-IronPort-AV: E=McAfee;i="6500,9779,10468"; a="285079434"
X-IronPort-AV: E=Sophos;i="5.93,312,1654585200"; 
   d="scan'208";a="285079434"
Received: from fmsmga006.fm.intel.com ([10.253.24.20])
  by orsmga101.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Sep 2022 23:55:02 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,312,1654585200"; 
   d="scan'208";a="861440749"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga006.fm.intel.com with ESMTP; 12 Sep 2022 23:54:58 -0700
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
	Jonathan Corbet <corbet@lwn.net>,
	Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v6 4/4] mm/slub: extend redzone check to extra allocated kmalloc space than requested
Date: Tue, 13 Sep 2022 14:54:23 +0800
Message-Id: <20220913065423.520159-5-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220913065423.520159-1-feng.tang@intel.com>
References: <20220913065423.520159-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=XrvVyepK;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 134.134.136.20 as
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

And in current kernel, some kmalloc user already knows the existence
of the space and utilizes it after calling 'ksize()' to know the real
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
---
 mm/slab.h        |  4 ++++
 mm/slab_common.c |  4 ++++
 mm/slub.c        | 51 ++++++++++++++++++++++++++++++++++++++++++++----
 3 files changed, 55 insertions(+), 4 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 3cf5adf63f48..5ca04d9c8bf5 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -881,4 +881,8 @@ void __check_heap_object(const void *ptr, unsigned long n,
 }
 #endif
 
+#ifdef CONFIG_SLUB_DEBUG
+void skip_orig_size_check(struct kmem_cache *s, const void *object);
+#endif
+
 #endif /* MM_SLAB_H */
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 8e13e3aac53f..5106667d6adb 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -1001,6 +1001,10 @@ size_t __ksize(const void *object)
 		return folio_size(folio);
 	}
 
+#ifdef CONFIG_SLUB_DEBUG
+	skip_orig_size_check(folio_slab(folio)->slab_cache, object);
+#endif
+
 	return slab_ksize(folio_slab(folio)->slab_cache);
 }
 
diff --git a/mm/slub.c b/mm/slub.c
index 6f823e99d8b4..546b30ed5afd 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -812,12 +812,28 @@ static inline void set_orig_size(struct kmem_cache *s,
 	if (!slub_debug_orig_size(s))
 		return;
 
+#ifdef CONFIG_KASAN_GENERIC
+	/*
+	 * KASAN could save its free meta data in object's data area at
+	 * offset 0, if the size is larger than 'orig_size', it could
+	 * overlap the data redzone(from 'orig_size+1' to 'object_size'),
+	 * where the check should be skipped.
+	 */
+	if (s->kasan_info.free_meta_size > orig_size)
+		orig_size = s->object_size;
+#endif
+
 	p += get_info_end(s);
 	p += sizeof(struct track) * 2;
 
 	*(unsigned int *)p = orig_size;
 }
 
+void skip_orig_size_check(struct kmem_cache *s, const void *object)
+{
+	set_orig_size(s, (void *)object, s->object_size);
+}
+
 static unsigned int get_orig_size(struct kmem_cache *s, void *object)
 {
 	void *p = kasan_reset_tag(object);
@@ -949,13 +965,27 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
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
@@ -1103,6 +1133,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 {
 	u8 *p = object;
 	u8 *endobject = object + s->object_size;
+	unsigned int orig_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
 		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
@@ -1112,6 +1143,17 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
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
@@ -4187,7 +4229,8 @@ static int calculate_sizes(struct kmem_cache *s)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220913065423.520159-5-feng.tang%40intel.com.
