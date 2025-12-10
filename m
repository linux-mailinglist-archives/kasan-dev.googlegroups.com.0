Return-Path: <kasan-dev+bncBAABB2W343EQMGQEOFHVMGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id A81E1CB3A03
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 18:29:15 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-597c376d9a9sf7659905e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Dec 2025 09:29:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765387755; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q+k4FXvnmsDEQxDtJDQ1qld1T4iEX8GXTXShTwiwQ0d2DvfcQ2dYUBuI54lHcTwQJh
         oUigrRK5Yk7frpVE0PXV3uvSiHjizFEP4X0CsPjuNwWQabdLY/XI2LOA+yoIOjKCw/CF
         M6wjoVt0kFwYYzjJLKAsKvZbvQLE38vN4w8syfG5+xNgKefj1Ve3oOvBMzAZOBCWS/Nu
         JoLYdi7LscjcsgL2+F6DE6616MPaq4A6TuipBAzoQ1UXWT+HUVqFJ4D8Iz75dDH31XJq
         HrWRhIZmevxEMUH87noFVjm7/yy2f4xWuJJxE4ThfmkFrxF9cz8zppX2RZH8gPI12EH2
         /mcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=nBDR617EahDkzoDr9QthNcRRgzH2BU0x2xCDlQZKA8k=;
        fh=GlYygEeNB5yAXcQcl1icR7lmmUqsMKgmo1fB80iG8pw=;
        b=VBDj6nqOq3ZhsZK0AcIWjSTYGimjCT+pQzDINBiKJmVamqg6sgDRtSkObPtbkr5avW
         KoJ11Twbra3QqBuMNw5oKntxv3cFrsH1XtQqcHqn5QbI7jA5wbwlG5N8gXL4yyZzzpDD
         6kBUycAwhziLLlQ7hOaLk5zhzWCQKwAcjtxZwF9fWRhie/LJgTAnZp745eBsjsr0B40R
         h01xHzr7qaLhSOmE2DYwk6tSBZ3NgfO0YaJNe3Em6qUD+uzwF1b92Zzer7RcrBN6+Ege
         CYXiPwD5PCsrCj09vfNmHMWafdR+PkuUgzifDnMYNVp6sAoDSL6YAKWjZOaFtM+osfCL
         geFw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=ekLjSZAu;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765387755; x=1765992555; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=nBDR617EahDkzoDr9QthNcRRgzH2BU0x2xCDlQZKA8k=;
        b=IVLxfO95AyzKJHyP9VOkViHP+pXGtT5fc3xBn2FQqiMUChO0Jbgb2R89V5RUJCDQEn
         smtjRKI2RqGG+2TlMRjbRe7R0j5aUNNXXwN3UYrJONOrqyC3sGnPYUqoXaUrUzfaiIWa
         Xzv1oLmLm4jPC1ACUOYEfJe7w5q8LFAUmG959vOQLGwqLb8Zv8PosS+z8eKd94oQ1y7v
         cnvzcawXwWg6XaAco+G25AOnG3Jito6BBQWA6Jori9/1lRwmoa2kp5w/y+deQpjuW6bR
         NziFvBld7go3EGB0aalGBa2pNYrnx1e+W4h5gHDUD2oGrLVONTLWFvqF/b+Y0LLFQ5Kg
         huzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765387755; x=1765992555;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nBDR617EahDkzoDr9QthNcRRgzH2BU0x2xCDlQZKA8k=;
        b=hZTfmzrLlp6Ke9RYifzsOdnQVzQa5vtDqqzAkCYDs20bEJo+4oUK0SJ802N/QhF8nO
         PquYPQm/3S3tZIZmP3yx5MIICJGjlnBssLZS3TaK1Cx0nqsmwWn5ASWjefOdXCNSPc7v
         gGWfJHjRJrxHf0NH5UcUFmFSh0ZKJ6bRzmGzdwUdqWb6YdG/hjHHSjYn3Oi37hqCxWd1
         d5h25kZyxiu22S2+9a3AMsIwtBCToEIYVVOxgjoLSXL56KU7/StassEcoxUtuV9nxltd
         2bXYWP+GKvM/CJYLvEto5/kFQvQl/CBnfYQqpksokSUaX3iqvkS327Vtxh3Ih7f2cXmP
         9Whg==
X-Forwarded-Encrypted: i=2; AJvYcCW3P7+r9YMkqBdMS7kHaBtcBcb+z00wzhGi6JBtHYhx0y0TZf6waueIgR4wkhwoqEn/nalVQQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw5/kObeRjSJ3M7C8PGKPR31IWA7ambCDvFmEvOIWO4Pq7c6wZx
	455OwliJdKMTZOs/stvX+L0laaHlVf1zkiYWBFqq5laQb9wLz7yHMSrg
X-Google-Smtp-Source: AGHT+IF/TA9Sbw6j+xSirFC6/1LcwmhDfg5zM42DOFowKbofMwEcJQWkiwhSdS0LTK5W5ct/dwoTzw==
X-Received: by 2002:ac2:51c5:0:b0:598:f283:e12f with SMTP id 2adb3069b0e04-598f283e1a8mr97239e87.11.1765387754809;
        Wed, 10 Dec 2025 09:29:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaPUePxX9HWW7dliOSVogBM8lPf/nUPFNUPgERK1dxUOA=="
Received: by 2002:ac2:4f16:0:b0:598:f1b3:ed7a with SMTP id 2adb3069b0e04-598f1b3edc0ls171729e87.0.-pod-prod-02-eu;
 Wed, 10 Dec 2025 09:29:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVLk7bRu8gc2Ye3RQojf4m29sWML/2zYfr0q0t/Wd5nRU6Of0zAnQFGLNdZe0XnrOZG2oVG1IP2XfE=@googlegroups.com
X-Received: by 2002:a05:6512:3ca2:b0:598:958b:f3d2 with SMTP id 2adb3069b0e04-598ee5318a3mr1123306e87.34.1765387752642;
        Wed, 10 Dec 2025 09:29:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765387752; cv=none;
        d=google.com; s=arc-20240605;
        b=NnBm3dcGM/ds6Yt4qrDsI2u56mUOArinbYmMcXlSLKF2AjECz2WfK14ZlFNiy+R0N9
         /IKVwUBrFInxE8L6dRjb8mkT/M+wI0+g5wfS8TcUvWca0W8jAG+OI0J1NQ95fLq4aFlo
         DfGzeI4Jh5nK2kcVoC6oAbJ4IYV7QAmCJjw3Yq2L1J6QDJYj/ocsSgmWyHps9qimnV/y
         xiuFLV+AYB0NM2+ZO70/Xi8wihUm+a4cPENbD1fhDbTtetsykDb/JGboiT60VKRTGCBp
         U2JNjdZS23olaTeJ8ieGBzPD0uXLvni6ikljIcb3YXzCUCRkYeQ2Bw9xKEdbSWrWF/B9
         g0zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=FfChR2RkA9EYwmqKbBDmes/ZKIT7Eu4BfGwYt0WPyRQ=;
        fh=RwCnRiznNGq/qqtqgWpciw1BZAN/kd4qwH7ssBFA3Cw=;
        b=AudBAnjOlANOm19NI+kJLRiGEgD2w0NCM1PrBVMPMEO97zRlYmGWyl5kMrCncRH9k5
         UH//URI77Ly7fnHwB4cPZ6kHhqVRyeJx+nra/tfI0xXJDFXPiODvkJX5yxZ17UGBgTAR
         eyTH7n4LL81GrpH5NYh4KGZqD1p6e6q5qictdn6pcX7AkIQjmkUegWUfzVHalRq4Qj+f
         DkoJELv6u+RWQOTt1O4RJfiG7w+0UcnuRNgk91MRael0D5J39GcawUE1U6fXwndP5uNE
         Xdn8/fYcTz79OFb/Y6m+wg2JcdWb2k0LFxPdh0/9pGxL3rhZDBwIUl1RE2jwx+zKSV/4
         VOEg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=ekLjSZAu;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10630.protonmail.ch (mail-10630.protonmail.ch. [79.135.106.30])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-598f2f37c4dsi500e87.1.2025.12.10.09.29.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Dec 2025 09:29:12 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as permitted sender) client-ip=79.135.106.30;
Date: Wed, 10 Dec 2025 17:29:03 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>, Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, Michal Hocko <mhocko@suse.com>, Axel Rasmussen <axelrasmussen@google.com>, Yuanchu Xie <yuanchu@google.com>, Wei Xu <weixugc@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v7 04/15] x86/kasan: Add arch specific kasan functions
Message-ID: <406416dea492be82578c2cf4ee70e45d98200081.1765386422.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1765386422.git.m.wieczorretman@pm.me>
References: <cover.1765386422.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 5a34045bd28f1283c14c644ca9f08dc44d52c0f8
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=ekLjSZAu;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.30 as
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

KASAN's software tag-based mode needs multiple macros/functions to
handle tag and pointer interactions - to set, retrieve and reset tags
from the top bits of a pointer.

Mimic functions currently used by arm64 but change the tag's position to
bits [60:57] in the pointer.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
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
index d7e33c7f096b..eab12527ed7f 100644
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
+	addr &= ~__tag_shifted(KASAN_TAG_BYTE_MASK);
+	addr |= __tag_shifted(tag & KASAN_TAG_BYTE_MASK);
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
index ad5c11950233..e4f26bec3673 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -10,6 +10,8 @@
 #define KASAN_TAG_WIDTH		0
 #endif
 
+#define KASAN_TAG_BYTE_MASK	((1UL << KASAN_TAG_WIDTH) - 1)
+
 #ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
 #endif
diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
index 7fb7331c5725..aa35f8331a4b 100644
--- a/include/linux/mmzone.h
+++ b/include/linux/mmzone.h
@@ -1181,7 +1181,7 @@ static inline bool zone_is_empty(const struct zone *zone)
 #define NODES_MASK		((1UL << NODES_WIDTH) - 1)
 #define SECTIONS_MASK		((1UL << SECTIONS_WIDTH) - 1)
 #define LAST_CPUPID_MASK	((1UL << LAST_CPUPID_SHIFT) - 1)
-#define KASAN_TAG_MASK		((1UL << KASAN_TAG_WIDTH) - 1)
+#define KASAN_TAG_MASK		KASAN_TAG_BYTE_MASK
 #define ZONEID_MASK		((1UL << ZONEID_SHIFT) - 1)
 
 static inline enum zone_type memdesc_zonenum(memdesc_flags_t flags)
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/406416dea492be82578c2cf4ee70e45d98200081.1765386422.git.m.wieczorretman%40pm.me.
