Return-Path: <kasan-dev+bncBDN7L7O25EIBBCUI4GMAMGQEYFREZAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C2DB5AFD22
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Sep 2022 09:11:06 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id ay21-20020a05600c1e1500b003a6271a9718sf7039930wmb.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Sep 2022 00:11:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662534666; cv=pass;
        d=google.com; s=arc-20160816;
        b=HUs6I7s7iszAHnObSeWFbLUdns2XuZYtNRQX7ZcVAZVfkbzor3VjNSwP65rlrhKwDZ
         LJhhq/VJtHco8Bd/WVaxCwmMo3YNgDvZF7dDUAT5TdwOx+oeP+FTVMNrTNSzmuDpXfJL
         Nk2QR61oIVlBxtGNzysNYTar0Crv2yi/1kL+bWzmrf90jBLZKZr4F1QZe7Gc4ZgsWTl3
         NHLZYxpdOKt6fhhQFuV0W3gLCLcRf6aA89CSgZ3GjORBAv0O58BpQdqbQQkzg+T7pMWn
         qeLU7cHjW1JFKkXX11AwVlEh2Sy0ZWOV4e8txNaYbjW2HLYi8/izl0J8pdMSozJ4VWzJ
         ZCFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=GtMr5ESxVtls2L37bjnc7cT82of7To9bxJ+L1KDPD1k=;
        b=zBhI4o085BybjsGx6e3wpANW++POdbcJ0mwwCPbutRSmrDbHr1pMKP8nDLMVYkfoob
         G18v0/NdiZXOFLRbpSM9sQZ1WxrqZBE+ZnckZgcG2GraNFQVPMaRz86EP+a4KInf8A/s
         CC4zpJ+r7AsQ8Ykh7VGsww0l/My9oo9YismKehacow5QjIpb8Twjr4kuSmC4V57A96ky
         dzSmogUTJvFch3Ege5rtsXEWUBh/EFZ2tPSSZqPK0YvjDMOqqxWzotLpGkoZ/Gzhdm5K
         o7beYYPBcfI5chXJtl8Mn32+THnciUHGBHW9KPfDNfX8dhKfE9/j9lf1YshCF3ZAMGrW
         qtqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jVJ+CmaE;
       spf=softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=GtMr5ESxVtls2L37bjnc7cT82of7To9bxJ+L1KDPD1k=;
        b=NDpIMDTibuG+VcXQKJ38HefOQ1gBR+9puGAC4z4QgVOqG5r0YMh13OY9FifF8Zo7CL
         Vw33Njw4khMaS9oD9Emwqn4RJWhOzUfkvCDFrEkoMJ2yjRFnn+OpP452JTDUrhPjQ6kf
         +zoVkDI4GTQ/f1nsMLy0X/iO5H93ZOb6qVyOAQWXNh4XgisM4umxJmlB0Uah89PScyCi
         Z43dUvr6GR8GLVWrdHJE/FXcI4aTbRSmR5oQEUwXqNDxZwyk3G1C0Cvf2WZkixD2yIBn
         It9cgiJBv97rVjDB4OE7b1nqKFueI1P9ZQ4FSdzygzqRVXPiaedz/apkje1P3jTeisVL
         nGwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=GtMr5ESxVtls2L37bjnc7cT82of7To9bxJ+L1KDPD1k=;
        b=44I/Ccjnw5nUm0aqBkUw5YQBPBNWJWFjj+mR5JP4yDYBpX9AN4nMwv2uCaRPrWLcrQ
         p5XsapJVev6qMTRU6Xkyck0mc4wpfiraSvESVljgQnVLuL2gFtNOBZBsoIxvNBlyvGXG
         wX0ThzOi6x4KOX2YO8ierf6u3IiebZT1Ho1xNejeaGUH9n7j4WdRJAwrvSTfBq9dBSTm
         PCR7kU8FlbSpXmB/JeZ/UOM+Ba+xgxDFlyeeHTsYxYXsmRf+25RwWkxG07msB/nLK92W
         NrWeq1GubCxKAnhZE+GqzTCKd2Q0S8k84TXyzqmjN+S75YrPqgwmYZgjVHv+xB4cmgDe
         TOAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1mgFlATlw1fn98MTEg4P1C6o7Ox5XgVPqrFxpk/rua1t7zXUPO
	asZhJ6Q/dWev+NYhHmcK7qA=
X-Google-Smtp-Source: AA6agR6gfIbv3cyKY5oZYiqQhaV+73AX+V8z5UC6j0TEhsdHuD1c7HSlDQhOwZYttyMQRlVngKWiIA==
X-Received: by 2002:a05:6000:1882:b0:226:ef64:55c8 with SMTP id a2-20020a056000188200b00226ef6455c8mr1059351wri.183.1662534666316;
        Wed, 07 Sep 2022 00:11:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d213:0:b0:228:ddd7:f40e with SMTP id j19-20020adfd213000000b00228ddd7f40els548367wrh.3.-pod-prod-gmail;
 Wed, 07 Sep 2022 00:11:05 -0700 (PDT)
X-Received: by 2002:adf:df82:0:b0:228:e2cf:d20f with SMTP id z2-20020adfdf82000000b00228e2cfd20fmr787937wrl.356.1662534665482;
        Wed, 07 Sep 2022 00:11:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662534665; cv=none;
        d=google.com; s=arc-20160816;
        b=ZvADjV09MyIHqKtxlkCQew7wDynmkOkX5tVlvQfbJYpS7GXU8Ej1GwHykHASJ36bt/
         dSzA1VE6ACZM+Ig3ZzHE3MAkjtoVuIPdYb4AYqlLo8DufYMpryFU14Rf8MId+DkBq1hC
         I6NAe+ZLocnR1VUs+HJo+EzyTMgJ/XBsyzp/NxR7N4e3qOPehcizC7aUn/Fg+PYVft4A
         NYbFw6H5og0hh5cSCLQmzIrjU0IcW4LwxaDgdhP2HboU4adJPDkcOPMhjEbDLu012czd
         UVkT8QoZZlVPsNZhSEekEcFQogwmyj5tndBMyNPg1BfOzk4DExvyDKQJHqpB7gjfn4qp
         zA3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=A7VbBWQ1FaID1ZOWc911qvZ0dgLNnXtOgQ9HgLyFnzo=;
        b=sJrQBNeulTa0YBGeimrTACsgjt+zy/XwxL9nYLh8vvNpKL3GX1lHXS/PvKrPv/E/Ui
         3jjsvlnLD8cfmwS1f2Y8+dwAXios8bTURZLUB3m2EvO1sUq/yEIpZ0l2dB1reqWh6z4a
         5nkmhiZR1MDbNsKoVEtf3OP4VjGEXqR/VRojOqM3OHfhImmcq6xwt/iFK8HxjW0YljDL
         5u8bdKeYsza7j6jU18tyRTqkrcEz9fg7Uy7aUJGqvN7LAcfo2/DJ/p1FqboD/SyvqoGR
         6O1Y3mbyJyriFthIfaDnwF6Xj/xDPTKjk/OnAbLXWx/KNXH0fpKIqqIMHzO8bejuO/PG
         G4fg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=jVJ+CmaE;
       spf=softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mga03.intel.com (mga03.intel.com. [134.134.136.65])
        by gmr-mx.google.com with ESMTPS id y18-20020a05600c365200b003a5ce2af2c7si724421wmq.1.2022.09.07.00.11.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 07 Sep 2022 00:11:05 -0700 (PDT)
Received-SPF: softfail (google.com: domain of transitioning feng.tang@intel.com does not designate 134.134.136.65 as permitted sender) client-ip=134.134.136.65;
X-IronPort-AV: E=McAfee;i="6500,9779,10462"; a="298115328"
X-IronPort-AV: E=Sophos;i="5.93,296,1654585200"; 
   d="scan'208";a="298115328"
Received: from fmsmga008.fm.intel.com ([10.253.24.58])
  by orsmga103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 07 Sep 2022 00:11:04 -0700
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="5.93,296,1654585200"; 
   d="scan'208";a="676053530"
Received: from feng-clx.sh.intel.com ([10.238.200.228])
  by fmsmga008.fm.intel.com with ESMTP; 07 Sep 2022 00:11:00 -0700
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
	Jonathan Corbet <corbet@lwn.net>
Cc: Dave Hansen <dave.hansen@intel.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v5 4/4] mm/slub: extend redzone check to extra allocated kmalloc space than requested
Date: Wed,  7 Sep 2022 15:10:23 +0800
Message-Id: <20220907071023.3838692-5-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220907071023.3838692-1-feng.tang@intel.com>
References: <20220907071023.3838692-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=jVJ+CmaE;       spf=softfail
 (google.com: domain of transitioning feng.tang@intel.com does not designate
 134.134.136.65 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

Suggested-by: Vlastimil Babka <vbabka@suse.cz>
Signed-off-by: Feng Tang <feng.tang@intel.com>
---
 mm/slab.h        |  4 ++++
 mm/slab_common.c |  4 ++++
 mm/slub.c        | 57 +++++++++++++++++++++++++++++++++++++++++++++---
 3 files changed, 62 insertions(+), 3 deletions(-)

diff --git a/mm/slab.h b/mm/slab.h
index 20f9e2a9814f..0bc91b30b031 100644
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
index f523601d3fcf..2f0302136604 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -812,12 +812,27 @@ static inline void set_orig_size(struct kmem_cache *s,
 	if (!slub_debug_orig_size(s))
 		return;
 
+#ifdef CONFIG_KASAN_GENERIC
+	/*
+	 * KASAN could save its free meta data in the start part of object
+	 * area, so skip the redzone check if kasan's meta data size is
+	 * bigger enough to possibly overlap with kmalloc redzone
+	 */
+	if (s->kasan_info.free_meta_size_in_object * 2 >= s->object_size)
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
@@ -949,13 +964,34 @@ static __printf(3, 4) void slab_err(struct kmem_cache *s, struct slab *slab,
 static void init_object(struct kmem_cache *s, void *object, u8 val)
 {
 	u8 *p = kasan_reset_tag(object);
+	unsigned int orig_size = s->object_size;
 
-	if (s->flags & SLAB_RED_ZONE)
+	if (s->flags & SLAB_RED_ZONE) {
 		memset(p - s->red_left_pad, val, s->red_left_pad);
 
+		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
+			unsigned int zone_start;
+
+			orig_size = get_orig_size(s, object);
+			zone_start = orig_size;
+
+			if (!freeptr_outside_object(s))
+				zone_start = max_t(unsigned int, orig_size,
+						s->offset + sizeof(void *));
+
+			/*
+			 * Redzone the extra allocated space by kmalloc
+			 * than requested.
+			 */
+			if (zone_start < s->object_size)
+				memset(p + zone_start, val,
+					s->object_size - zone_start);
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
@@ -1103,6 +1139,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 {
 	u8 *p = object;
 	u8 *endobject = object + s->object_size;
+	unsigned int orig_size;
 
 	if (s->flags & SLAB_RED_ZONE) {
 		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
@@ -1112,6 +1149,20 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
 		if (!check_bytes_and_report(s, slab, object, "Right Redzone",
 			endobject, val, s->inuse - s->object_size))
 			return 0;
+
+		if (slub_debug_orig_size(s) && val == SLUB_RED_ACTIVE) {
+			orig_size = get_orig_size(s, object);
+
+			if (!freeptr_outside_object(s))
+				orig_size = max_t(unsigned int, orig_size,
+						s->offset + sizeof(void *));
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
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220907071023.3838692-5-feng.tang%40intel.com.
