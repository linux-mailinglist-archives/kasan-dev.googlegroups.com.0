Return-Path: <kasan-dev+bncBAABBWNXR3GAMGQEES3IWMY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6CbvLtubg2nppwMAu9opvQ
	(envelope-from <kasan-dev+bncBAABBWNXR3GAMGQEES3IWMY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:19:55 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1ACA7EC061
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:19:55 +0100 (CET)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-8887c0d3074sf6711276d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 11:19:55 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770232794; cv=pass;
        d=google.com; s=arc-20240605;
        b=LvMKlIq6XkrpSoBOVXVuiyFDJRuB2A2UGrkLG81p4/09KpAcN5j5jk//8k9lACzBpy
         L1cfrpK9qsyQndf4w5eUNiErmx02PZfxN1JR2S5aatdETiT+7cgI/4zSzUosf48MGvOs
         YGSU5qzCQxA1n+W4t/wUF2zI9MJYyY8QzSeohR9JmkjcCegayw0qrZ7uZ6dy3KNvpGTJ
         xWtJ2F0UZhMtpH9W7xK/29+0RWIOzingsYDVIwgxrvLhiDzQBgiRBk2dHtxgmhxNPBYH
         68CyAJGD2BNmdpYrAVPvVIaklVXlZ2srDkejllnwKNWFqWNCt+Y06bRBseqPaygRYg3O
         rktw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=o52VwqgMunQKeT+mh45rBk4cyKFp9J4hkLY54PM2hyo=;
        fh=l1AM7O5goxdlBTWmVwOIvYgClEBt2fkshijbRtn17Jw=;
        b=BynTdrdytm0M421XBzUqXIrwvQiNY51yYzmskzLR/gDpqWwcDr/RGEoiVYPnbG6BWn
         qyvt2o1YEQmd8XG+nn7OhmUCprqbIhXfEZJhu7CwlZcje8xhjLCyUnOzIOy3u83vXjCG
         0RFVMdQ9LL5xItloRMv9UZ9HNfSfr8G7Fv3F86de2D2ImPXM+uKrjpQxrIt6o4ogLDR+
         1TGG9Bv2/L+00UwJsizRWIsCzienRWQFazYmFPHFex61cb8zw9dWKOuiBNNd5bPYnBXs
         NGVcpywG0OOOCqMLiP+6HkY/06zvIeVPy4RDX60a3rx68hxXYKD2zHs+sdovf/bU03sk
         YMPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=PGOowp5R;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770232794; x=1770837594; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=o52VwqgMunQKeT+mh45rBk4cyKFp9J4hkLY54PM2hyo=;
        b=fqJ18aJx8qEe2z+A2lkAQ/avAForYrsItrTJhlbayhVrY6qPc8yPanDaN3L7cLn5GF
         rt0njkNzUH622IntN9BXtLgKczYZwTDPdqfqh4HiApblWFiqrJFT8jO6q8h2a7FQOqUC
         +bqZj6szDDOmspS4QG4KgFV6eBmR/bOjsZfYmkyXe5f5vA2gLr7Efkp+vrtDLZ6xAwjY
         W5XP/rH3iiwhOLa2fE+QeMIX3H6L7WImssQVwsVsE9h1sAtUlAIfI1tWaDoQasDAqyOk
         QxJtZ1eWOsnUPmRnPWDUdF6ZH2Sn9guXEAJjcCu2y7YsuUP3bz6jyV8IFJHQu1Qjy9sV
         GZcQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770232794; x=1770837594;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=o52VwqgMunQKeT+mh45rBk4cyKFp9J4hkLY54PM2hyo=;
        b=wm7SF6y01jGNgR69rirqWjpMj6PahTHjSgGwCbmKVkz7PQBXn23F6Yj3wBoG/jbEdV
         HRbQxmnZ8R8EdAL6l6ASagSZYSlDKehKcBq271klBjXEfwQg5vTUReLf3fEntVW/xvnQ
         1sD+0Z8BLDUtlQrpZHegdolXx1gIZNNVlQM2QoT5A+gcwrSdKo0d8f9Qc8NCFduizQoD
         5kuI/e01WXL9sa4IOTtOsqGC0jLo3VzRBO4/Mo8GDpeBOBK1iEOnNtDdwhjkyiTmebuC
         dDKh758qLYUTinJFMUAvuYmL9QOi0foIZQfdP52A84CxMTChFaBt+PpWbeZiQoFJ8aS8
         HN4w==
X-Forwarded-Encrypted: i=2; AJvYcCXyVbtXCNhGi+V9mPJ7YAotOJrBRX4C+hdwd6+GVgwUWltqvDtWIcXAvSN8NqCTpfSaRZWghA==@lfdr.de
X-Gm-Message-State: AOJu0YwcmbXG0rcEzq4dhEDlVJVL+eCN9Z6jgGM0e7ChqPYJl6cWjFve
	AgsG4rmGtqeQExnSSMwIz3q3Kg3GlWX04x+8ZWZrRtT602Rz+6oU03vb
X-Received: by 2002:ad4:5ba2:0:b0:880:5867:45b4 with SMTP id 6a1803df08f44-895220fd0femr57364896d6.13.1770232793386;
        Wed, 04 Feb 2026 11:19:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HJvj5is7O+xU2diL0YttN8fu7L8SCDUDhbMDnBc3IdgQ=="
Received: by 2002:a05:6214:1bca:b0:894:6e57:51d9 with SMTP id
 6a1803df08f44-8952facd1b9ls3494616d6.2.-pod-prod-09-us; Wed, 04 Feb 2026
 11:19:52 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUl6I3Ireoo7TCK+bNE4AgmlyCQ4lbM/uM6sF9ewMzWCcpxpHJGwe6oKNuY8PCAjrkbWg8n7dyeEwU=@googlegroups.com
X-Received: by 2002:a05:620a:c4d:b0:8b2:2066:ffca with SMTP id af79cd13be357-8ca2fa5f10cmr533930385a.82.1770232792419;
        Wed, 04 Feb 2026 11:19:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770232792; cv=none;
        d=google.com; s=arc-20240605;
        b=fb0c1asBjtnKI/x09TYWo1zv1v6umPgmwLYA0hhIwSuro/EhYRn446UXHnorDfxX2u
         F2B+XVFFsrrhx2OaNVmN0D9Z10DJ679+BmK26xFnzApjB3XBMPamSnlT7tprMrOZ+9Wh
         9niCioClXuNBQyztzjZjSf/jCgXG7PGDgeB6m25DxxIJ9YdBJVaDG1aLodENTdANS1r9
         NaKR6bkTX/qL0rP9fchR2P8f37f4fD6Rhgvweg/h9FGKljHpdnB5TabBw2KISOhoTar0
         Bi0IHjNmqkB4qOXU26sF23/wJBFWinaQ7d3Ypk72TM3VKATeFwCd4HddLgU0/E9T1E9E
         LUwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=8q4FTnyJKL7VL66Fr0/i2+AcAlsSlxe0w17bfcxDbBw=;
        fh=cJXmhCP8DC+WrXzvw1naa+LNCCILCB3dr6HhvGsMiuM=;
        b=AbeboM25st/oAlHoXi5Lh8W9wikjLHYK+CHxPM0tjwXMY36ytm2FfgOQ6gR3UCxe6I
         vtezxd+a01srkKHZtZvutEg7iN5d13hkmuR5ElfdFDbU2sMpbK6a64WrM0CWBUUhCFo+
         WA+ky2zlBmSRsN52e5/gtw9SjWLkp48ncRL0qtKaaUDIpKCnhk9zTJ5T8KRpMCduOilN
         iDoSEBoxdTRckf+mppa4njbC8a1IaS7VZJTEYTjHDiy59+cpzCdDZiTVs7YK0u4a3FLW
         CUq+MkID4fL89T+MQFicKWrVghzu6vwUvhT5tAW49IBesY/CKq14KJyknblAhmIZCDga
         4Ulw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=PGOowp5R;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.121 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-244121.protonmail.ch (mail-244121.protonmail.ch. [109.224.244.121])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-89521d49d76si1190996d6.7.2026.02.04.11.19.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Feb 2026 11:19:52 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.121 as permitted sender) client-ip=109.224.244.121;
Date: Wed, 04 Feb 2026 19:19:45 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Axel Rasmussen <axelrasmussen@google.com>, Yuanchu Xie <yuanchu@google.com>, Wei Xu <weixugc@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v10 04/13] x86/kasan: Add arch specific kasan functions
Message-ID: <d58968c27836adbd0b4a067fe39edc4b973d4b4c.1770232424.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1770232424.git.m.wieczorretman@pm.me>
References: <cover.1770232424.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 144eb06d27a67966df17bfcfb2a55167d1a539cb
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=PGOowp5R;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 109.224.244.121 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBWNXR3GAMGQEES3IWMY];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_TO(0.00)[gmail.com,google.com,arm.com,kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com,linux-foundation.org,oracle.com,suse.cz,suse.com];
	RCPT_COUNT_TWELVE(0.00)[27];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[pm.me:mid,pm.me:replyto,googlegroups.com:email,googlegroups.com:dkim,intel.com:email]
X-Rspamd-Queue-Id: 1ACA7EC061
X-Rspamd-Action: no action

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

KASAN's software tag-based mode needs multiple macros/functions to
handle tag and pointer interactions - to set, retrieve and reset tags
from the top bits of a pointer.

Mimic functions currently used by arm64 but change the tag's position to
bits [60:57] in the pointer.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Reviewed-by: Andrey Ryabinin <ryabinin.a.a@gmail.com>
---
Changelog v9:
- Rename KASAN_TAG_BYTE_MASK to KASAN_TAG_BITS_MASK.
- Add Andrey Ryabinin's Reviewed-by tag.

Changelog v7:
- Add KASAN_TAG_BYTE_MASK to avoid circular includes and avoid removing
  KASAN_TAG_MASK from mmzone.h.
- Remove Andrey's Acked-by tag.

Changelog v6:
- Remove empty line after ifdef CONFIG_KASAN_SW_TAGS
- Add ifdef 64 bit to avoid problems in vdso32.
- Add Andrey's Acked-by tag.

Changelog v4:
- Rewrite __tag_set() without pointless casts and make it more readable.

Changelog v3:
- Reorder functions so that __tag_*() etc are above the
  arch_kasan_*() ones.
- Remove CONFIG_KASAN condition from __tag_set()

 arch/x86/include/asm/kasan.h | 42 ++++++++++++++++++++++++++++++++++--
 include/linux/kasan-tags.h   |  2 ++
 include/linux/mmzone.h       |  2 +-
 3 files changed, 43 insertions(+), 3 deletions(-)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index d7e33c7f096b..c868ae734f68 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -3,6 +3,8 @@
 #define _ASM_X86_KASAN_H
 
 #include <linux/const.h>
+#include <linux/kasan-tags.h>
+#include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #define KASAN_SHADOW_SCALE_SHIFT 3
 
@@ -24,8 +26,43 @@
 						  KASAN_SHADOW_SCALE_SHIFT)))
 
 #ifndef __ASSEMBLER__
+#include <linux/bitops.h>
+#include <linux/bitfield.h>
+#include <linux/bits.h>
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
+#define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
+#define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
+#else
+#define __tag_shifted(tag)		0UL
+#define __tag_reset(addr)		(addr)
+#define __tag_get(addr)			0
+#endif /* CONFIG_KASAN_SW_TAGS */
+
+#ifdef CONFIG_64BIT
+static inline void *__tag_set(const void *__addr, u8 tag)
+{
+	u64 addr = (u64)__addr;
+
+	addr &= ~__tag_shifted(KASAN_TAG_BITS_MASK);
+	addr |= __tag_shifted(tag & KASAN_TAG_BITS_MASK);
+
+	return (void *)addr;
+}
+#else
+static inline void *__tag_set(void *__addr, u8 tag)
+{
+	return __addr;
+}
+#endif
+
+#define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
+#define arch_kasan_reset_tag(addr)	__tag_reset(addr)
+#define arch_kasan_get_tag(addr)	__tag_get(addr)
 
 #ifdef CONFIG_KASAN
+
 void __init kasan_early_init(void);
 void __init kasan_init(void);
 void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid);
@@ -34,8 +71,9 @@ static inline void kasan_early_init(void) { }
 static inline void kasan_init(void) { }
 static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size,
 						   int nid) { }
-#endif
 
-#endif
+#endif /* CONFIG_KASAN */
+
+#endif /* __ASSEMBLER__ */
 
 #endif
diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
index ad5c11950233..36cc4f70674a 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -10,6 +10,8 @@
 #define KASAN_TAG_WIDTH		0
 #endif
 
+#define KASAN_TAG_BITS_MASK	((1UL << KASAN_TAG_WIDTH) - 1)
+
 #ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #endif
diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
index fc5d6c88d2f0..72c958cb6f3b 100644
--- a/include/linux/mmzone.h
+++ b/include/linux/mmzone.h
@@ -1177,7 +1177,7 @@ static inline bool zone_is_empty(const struct zone *zone)
 #define NODES_MASK		((1UL << NODES_WIDTH) - 1)
 #define SECTIONS_MASK		((1UL << SECTIONS_WIDTH) - 1)
 #define LAST_CPUPID_MASK	((1UL << LAST_CPUPID_SHIFT) - 1)
-#define KASAN_TAG_MASK		((1UL << KASAN_TAG_WIDTH) - 1)
+#define KASAN_TAG_MASK		KASAN_TAG_BITS_MASK
 #define ZONEID_MASK		((1UL << ZONEID_SHIFT) - 1)
 
 static inline enum zone_type memdesc_zonenum(memdesc_flags_t flags)
-- 
2.53.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d58968c27836adbd0b4a067fe39edc4b973d4b4c.1770232424.git.m.wieczorretman%40pm.me.
