Return-Path: <kasan-dev+bncBAABBI5IX3FQMGQEBU3MUXI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id WLW0OCqjb2l7DgAAu9opvQ
	(envelope-from <kasan-dev+bncBAABBI5IX3FQMGQEBU3MUXI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:45:46 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 862B646962
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 16:45:46 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-382fcf9cb7dsf30088531fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 07:45:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768923946; cv=pass;
        d=google.com; s=arc-20240605;
        b=iY44RWZ72Vw9MO9VXhXpkZVt/Fj1hljt82DUFL/YtKAsGILaGkVhhbBKlbORMszUAI
         DbOgoFyPSkkADwTx61GeJqUea5iBvhqdw+Gr0A6JwGV+fBibooCuio8TvrxWPO+T7F1N
         tPqhQcfycdUyUP4Iz69iId/ymwooPSsSkivWW/fc2I7fDA7mPpsJDevSDrmVrcWcdJvL
         sx/wmA42p4g/5yKhcxPK4/LdC3AtOnmI2xv2Mzrs1D5RErTlbi08e2nk4Rk//xLshB4x
         wtByqLO66ZtzfsTGLoqJOPmIWrMnf6S7226z77101yvvx/iWHZnbIfvUPFTd83Qbxqo8
         FwdQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=wPRjhT8pzMvjcBIq9lFbbbXeey7C8S8X+N968kD0eQY=;
        fh=4hUee9iK6Mk2YJX21oA+Deucdwc2RCvx3DN8GHd28LI=;
        b=J6gyULUfaI+kO4aSdPj5SrIaYz7FZWaHAQZNORSzNTtPuRtjbufWrtNseGa8oIK3Pd
         +q9W3ECmJotyqQidCX4NDut/YXM2CtHjRjt+8xaXQsxHoyAEo6ozNB6e2pGyeGFOf4L6
         ZZqsW3z90j9c26rC0PM/dRVGg3X+yyuH9gbpzXH2Yux1F+MYOLyK7VIHe7TEMTH2dCbv
         H9pmoAhV9T7X8l+FyM/wa+bWxOtmwVadO1bSeNwdikPYW3sJxER8yvtSxjJSc9Uu/KOY
         ZsIFU+y4e38nBhWbUfHIjXfwngF/loNd4Eg/NHjuAsclpyzHW6SUQp7LQPMCYzIGEk8A
         rsPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=IEOg9iUY;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768923946; x=1769528746; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=wPRjhT8pzMvjcBIq9lFbbbXeey7C8S8X+N968kD0eQY=;
        b=hdclBcs4HBWRCw10lwLleIxuS1VTLX6fD+FW0Sc1XtD2goNBYLqZfxre1mYoXpuVzh
         V4eGesrQTG/DZp2VHSfdZ9iWRfhPPkdIj8g6EIE9Ye+1qh29KjmzU46auzMzcfyCNtSM
         /0CzufFaQCSJSTIl1OWr2SmLm1cAmQc/yn9asvnwBFTuCLyZbmzoBI0qH1BT5ml+yLrb
         V3ZblQRxhzM03e4Qkg1NBcuvPIuxJwAb04g7YgfazVAXOhNwufXBr0uOn4RpnDHU1Qfu
         oR3qXAA7uB/4c4rDTtzigX7YOWA30qr3GOdaazZFhkSq3AAOeG9Q94SrPC3if0+o0Lqw
         q1AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768923946; x=1769528746;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wPRjhT8pzMvjcBIq9lFbbbXeey7C8S8X+N968kD0eQY=;
        b=buko9BmNrN2EcTNKvz+YQ33uYEuodrj/U5lPJaRA3VAEbHUvwvtUwuir2TepsBVhqV
         aAuX/HpO4XI/njmEC3xJcPiHtmgjwedT43/J+URdatI/dGePzYxWF5n3zYQeBS3oPNm3
         XV2W3FM1C/N70CQoAyiLWwAX0guJqBqNcx+itdRoAb9P2vQ03pzFy+dVgV/QTHmm7E4p
         Qxh4TIJgwSjBtsF9CrX0XYaD4fu+W7uo3Dndo63C4+XTFqS7a8h8cwpbyqcIWm9xCr52
         9BkcpW/L7VjtinNrvpWyueQFK26bCQUQrSbHXTgmiiJWV3XYsc7DlXFgVd+evpZOYsAH
         nmMQ==
X-Forwarded-Encrypted: i=2; AJvYcCVhePUjT45RU6/l0NB06DE+PjKur7qXERfxZRI67G45pEg5F/BJP5B4uKCkMCdZAquOJ4+nkQ==@lfdr.de
X-Gm-Message-State: AOJu0YxiCKnjirlmOkvSjc71fXi29fIaQl9B6bwlNFMKDjAfGEKqi0e2
	9ebXZehSwpzLjLaO/qA4DEMBcQUzsulweUtCIKhfcxUEfEss3Yz4MR46
X-Received: by 2002:a05:6402:35c4:b0:64d:65d:2315 with SMTP id 4fb4d7f45d1cf-654bb61b317mr11452220a12.30.1768920099647;
        Tue, 20 Jan 2026 06:41:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FbLqUVbiojnlJ3YFF3nfwlVl1fP0YtUzkp8+5gdl+jbw=="
Received: by 2002:a50:9e82:0:b0:64b:aa45:7bf6 with SMTP id 4fb4d7f45d1cf-6541be912c6ls4609659a12.0.-pod-prod-06-eu;
 Tue, 20 Jan 2026 06:41:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVUfFlP0X/iTpkRudM5R+mY8M3MQeho7FJgx7k09WDOs/VKbyaya80iu8PVdwxFHwA7fbgC4tyIGYU=@googlegroups.com
X-Received: by 2002:a05:6402:5193:b0:641:78b7:d326 with SMTP id 4fb4d7f45d1cf-654bb61b16fmr11361463a12.28.1768920097945;
        Tue, 20 Jan 2026 06:41:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768920097; cv=none;
        d=google.com; s=arc-20240605;
        b=WmYGK6RFmJfbm4bJM4NmbbRcVRxMmtoqCjGzqZpYsVzXBjaeU4yPxTdlLWGHic0eY9
         nJAcURvl6sPPRsuuTMmxuad56rq8ihPWREj+6ClZfkiDgxPMPGUQcLJKZrMq7esIcZVV
         nehuk5Bq+0MwNyGocIaBQfpksEHDp5cEr44mykB12KLNMnrkopMNg5VEDoiT8GXQt7G8
         TDoYuAn3a/OL00/n1tJMIZv3ren4KdiWGhz4jQCxuWXCtBXkYsDWK6efnxlJ+SBg4I4K
         oYzt3bkx/yJbx4Cm4tm4SpcWK1RbOCsNt5o374GrwNTMNn1F4u0ElSgdVTuS1W+qVBrC
         vAGA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=eIIDTGQyCgm26nLjZu4KEA9Oyj/JLFsBgq7aIkvXEts=;
        fh=TJq0SnTd+NxFIQrv63buUvzimLnJvGq6kZKkVOp+d9E=;
        b=fkBe2zfsfjIjYVzw2MGPn2XTJuA9b+bbF9xLh1ZiZtuvcj+cU2U0EtsdTHQK/lPn84
         XtsQpFIY07J50RV0Xsr7D+JzMRYdn4L+8HIGaczzHogfCwriEXmNZduk1VgoL9pFPL4Q
         e9YFtLSbuOiVxFA2mNSVGmB3ZpC++DCLc2zzCoCH5HyTFLdIzFETHXRjaRtzeG+vZQ8X
         DqPnW/ImBxWA6Y7H8FQyJH4B/GqZOfRrMvjdA7NpiLujsXWnazps/acIknSvSAHgz24p
         DPXml7CFc+ok75ErKnHtt8Mjz4xAWUIgd0FMx6/pySPeRkLJFfqBhCZMh6L4eCEPYDX8
         X+uA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=IEOg9iUY;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43103.protonmail.ch (mail-43103.protonmail.ch. [185.70.43.103])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532d768bsi280198a12.7.2026.01.20.06.41.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 20 Jan 2026 06:41:37 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as permitted sender) client-ip=185.70.43.103;
Date: Tue, 20 Jan 2026 14:41:32 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, Axel Rasmussen <axelrasmussen@google.com>, Yuanchu Xie <yuanchu@google.com>, Wei Xu <weixugc@google.com>, David Hildenbrand <david@kernel.org>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v9 04/13] x86/kasan: Add arch specific kasan functions
Message-ID: <764ec564b29372fa7e8cd6cf3ba1f4cfac6ea1d0.1768845098.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768845098.git.m.wieczorretman@pm.me>
References: <cover.1768845098.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 9d53fc9017bfe54371bdd75ce3f16f0f911acc40
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=IEOg9iUY;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.103 as
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com,google.com,arm.com,kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com,linux-foundation.org,oracle.com,suse.cz,suse.com];
	RCPT_COUNT_TWELVE(0.00)[27];
	TAGGED_FROM(0.00)[bncBAABBI5IX3FQMGQEBU3MUXI];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,pm.me:mid,pm.me:replyto,googlegroups.com:email,googlegroups.com:dkim,mail-lj1-x23c.google.com:rdns,mail-lj1-x23c.google.com:helo]
X-Rspamd-Queue-Id: 862B646962
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

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
index 75ef7c9f9307..631200332c45 100644
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
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/764ec564b29372fa7e8cd6cf3ba1f4cfac6ea1d0.1768845098.git.m.wieczorretman%40pm.me.
