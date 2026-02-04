Return-Path: <kasan-dev+bncBAABBCNYR3GAMGQEDH3HXKY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id OGu0Kgucg2nppwMAu9opvQ
	(envelope-from <kasan-dev+bncBAABBCNYR3GAMGQEDH3HXKY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:20:43 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 4778EEC08E
	for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 20:20:43 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-42fd46385c0sf100433f8f.0
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Feb 2026 11:20:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770232842; cv=pass;
        d=google.com; s=arc-20240605;
        b=dc8ImDkXkyosix4Mmhe9scMgp3kV7UT6hacrCIhqNBXmojeht0MrIabP/RQQ+WAywY
         JF12Ynw+EW4/nwzkQiRSAPp9J0n3EwS284s7k5NTJyMlkIuwhVsB31vFj9/peDBVAV7p
         P4/IwzzEqnq8BhAe+QAAcqYnQmLamdHbT6Lsc7t037s6ueIiinu7neOWtHbiaJV4Gkv7
         MtGjNT9NSaBazLUSWvzNuJJJELSHllFDR3YTTV0HDuVXtJP6rHSYxi3MLN+2bgZG70NA
         NXQ47sFL0+F5vsAS9ICoKaTWunnjnrRN+d6R4gKYOYqpIz/lZfmrPHpAoxwaE4wQs6zm
         pbQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=f6vpx0VUqqX25TImipwbC7JKJVlfu3pqs9bMwlrTi3w=;
        fh=Pue/HI2D44XSDZR7JpEg9BkAqYjUlWW4Gp+sUNYN8Po=;
        b=hRUdMxpPktN4hZvUA5Gp35XnTXLV8x/TjP/iBqzMkg+oI/LEPSf3Zp7wqilKH/modq
         t3ZnBKvRT8DtVwNmyBbGCKn0/5nIY/+7+kCFu9VsX18p6ohfAqDjtZ0MoZiErgyurEXo
         UL3OB5vHDmb6Z1jsfGt69viXHMRvnfa505erpJTrlxpXAif6wK1NMQLJsEL4ErAdmFDP
         kp3E9KI6wS3sqCWqUwk33CgBf1u7+kYkiVA7IqMh9oe4VkO1WUax4tlxbhJNNaK76YtV
         emvtydG9ZetktdGy2m8sYJxJrQLz+Oin7tY9Br/IgwAbXIMxSgmOHp4Lr5wlDOMB3d+f
         AhZg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=BI+nHvXj;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770232842; x=1770837642; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=f6vpx0VUqqX25TImipwbC7JKJVlfu3pqs9bMwlrTi3w=;
        b=CjOV1r1TzJlBbwQKD1TuB2VN+Oc/dfCrxGDVRRcgu4jX9warLdDZ/wa6u5chTU7RkB
         HfZlECuszDM0UwObUJiyGIUVnOLhtxQVM7e7bdUYY/xlgJrhHp4EJ94juxEi/xhwTACn
         d0V6xqV5JpSQX0pAaex6KlMAgxewSjUuhrIyZSlOJgE8qIjIlGln1wQHjmVekSS6a9rd
         j3FP74+mfuct4xyrFJn7Q9Ff8+kRQRtacZNPcZ76ZFuLkEL1a4w+yBLV4ZdmpElT1FO3
         uKIjXsMUkIzS2eF4AIRMPht+mWpjGPT3nK4eQay8kWLYx1hA9/b4S9FofqecZZIIJJQm
         wMEA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770232842; x=1770837642;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=f6vpx0VUqqX25TImipwbC7JKJVlfu3pqs9bMwlrTi3w=;
        b=tWA7IgmMBYxZm+8ze4B00+9wQBja8UY5GcuLvktM1C0lICzfgR7Zub8zwR45shQXlC
         vy5CKsu+Om5TE6XIOGAW3EX9oQKTIdd2qeLQaXberexCAy/9OU4W6m+xBTE+4VG8jnR8
         K9/NHBC8l2V5lkYoUQzG90Sl1IxvJo9z2Xz417LYoEDD1opyjhtjiyrQmdfXJ4DhszK7
         g6CPec+Glke6RtxZS8+QdcSdlZsxvGFTLXuqLLm7egnVCd0oYjEXdJbUjLJ463mHzrD+
         dz+M7ujZFkkzlT2E2BciPBM9epAv2n6zVYk75eHLJ7fKheHYOhpw3X+4rAt63U5hlaVZ
         Nlsg==
X-Forwarded-Encrypted: i=2; AJvYcCULdCf4Gg/kOPro92AgSzFUtiPEVUrWgmYQMEpUSrH7R8gGrYldvTSX8oyOjpF8xsOC/wlrog==@lfdr.de
X-Gm-Message-State: AOJu0YwDysGDZ1MjfHVe0Fkk7AroTPrcTNWdCWCxKexeTJkArNCSb4H1
	6YCguVw8rmmRN8ES2+Lp/gTXPIBoJ1+QuZBDfPcO2IJF5sUtVn7LupWU
X-Received: by 2002:a5d:5f51:0:b0:431:266:d13a with SMTP id ffacd0b85a97d-43618059565mr5686743f8f.48.1770232842371;
        Wed, 04 Feb 2026 11:20:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FhxZvyxpZgD2mtrIhCvMg7p2ZT9RDuqAZsNPpe4zsPSw=="
Received: by 2002:a05:6000:40e0:b0:432:84f4:e9d3 with SMTP id
 ffacd0b85a97d-436207263abls86107f8f.1.-pod-prod-01-eu; Wed, 04 Feb 2026
 11:20:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWM4ptwnEMrp6rsWl9i843a0A+eLRQLWg4iuqMh94knkgUuUEWHYN9i08iZhLAJcm1+9AhJ4RMx4fk=@googlegroups.com
X-Received: by 2002:a5d:5f51:0:b0:431:266:d13a with SMTP id ffacd0b85a97d-43618059565mr5686606f8f.48.1770232840585;
        Wed, 04 Feb 2026 11:20:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770232840; cv=none;
        d=google.com; s=arc-20240605;
        b=NzC+sgqSDtnvFHTdMdwqrrpPRESaOzZrlVtYRp6PPWIy2B0a7LkhpIzyltWYjjDBSz
         QEAJAbsmqTL661ErKlkPMKcRiuURb85vL3PHhtPQUsTHdHCsEi1GWoQs64dx+F08wmz8
         hpuKK0mDydjjDewdtP4X+qKz9W/bpEJ8B1oAj3k3bNNJXc5XPfPRO81uKC8VlSTV5w69
         yS+xJSthirb90Kj/7zwBz+vLcq7qh7smDh4obZ0VWlikD5tcVhEo1GE0nsxVLePdJAHi
         nXSG6ZMeSQ7+LxpXYP+VOzLxd9JXT8uUJ2JvoKRcDeqzAxRw0rdlooSZI0x6d9UFg94o
         tSrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=pCJsmVtyGsdKKIuPYKpRm9fUYAKTYyOUZBJDn3h7tqU=;
        fh=1M1spAKXRL1ft3V52YDxcSPLLmwT2TtGJN4YN+QkeXw=;
        b=GTXfsTKvX0+H67A5Zaxefd8yaQNDkrn3WqrKrbLUHHmHF7TWdmkciRVgYdFthEkBMm
         GtR/cSgK3tv26xYrAB58hxCZzM4FYULVrR8bgpQNtfgdcRxp5GE7aOzWFtm7ywXvrHPC
         yuebLjSOmvsyh42yfscVmz05eZyOcAPBo13nOjc4N5OSK/wSN+TEBsIpuV5BPfFkmo2H
         PozbKl9PZxf/gy/ooZOyiwBk1PphGbE6B7GUsfWlyRw4Fkv0zRAy8heJGnrtTVuKmMf4
         I+KPjBq525fibIBGVk5Ib3Pd0/sA4Awaf73ypdtsvtbS5mkQsifAp3uMfPVhiQ33pQ7j
         Ai+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=BI+nHvXj;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-43101.protonmail.ch (mail-43101.protonmail.ch. [185.70.43.101])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-43617e3c546si69683f8f.3.2026.02.04.11.20.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Feb 2026 11:20:40 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as permitted sender) client-ip=185.70.43.101;
Date: Wed, 04 Feb 2026 19:20:35 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Thomas Gleixner <tglx@kernel.org>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, "H. Peter Anvin" <hpa@zytor.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Subject: [PATCH v10 12/13] x86/kasan: Use a logical bit shift for kasan_mem_to_shadow
Message-ID: <0f4fe40cd9a481e64a3337c69b4e5e925a30ac7e.1770232424.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1770232424.git.m.wieczorretman@pm.me>
References: <cover.1770232424.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 84f78230333589d3ec7afed7dc5dcd1a51c62275
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=BI+nHvXj;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.101 as
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBAABBCNYR3GAMGQEDH3HXKY];
	MIME_TRACE(0.00)[0:+];
	RCVD_TLS_LAST(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_THREE(0.00)[3];
	FREEMAIL_TO(0.00)[gmail.com,google.com,arm.com,kernel.org,redhat.com,alien8.de,linux.intel.com,zytor.com];
	RCPT_COUNT_TWELVE(0.00)[15];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[m.wieczorretman@pm.me];
	TAGGED_RCPT(0.00)[kasan-dev];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	MISSING_XM_UA(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[intel.com:email,pm.me:mid,pm.me:replyto,googlegroups.com:email,googlegroups.com:dkim,mail-wr1-x437.google.com:helo,mail-wr1-x437.google.com:rdns]
X-Rspamd-Queue-Id: 4778EEC08E
X-Rspamd-Action: no action

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

The tag-based KASAN adopts an arithemitc bit shift to convert a memory
address to a shadow memory address. While it makes a lot of sense on
arm64, it doesn't work well for all cases on x86 - either the
non-canonical hook becomes quite complex for different paging levels, or
the inline mode would need a lot more adjustments. Thus the best working
scheme is the logical bit shift and non-canonical shadow offset that x86
uses for generic KASAN, of course adjusted for the increased granularity
from 8 to 16 bytes.

Add an arch specific implementation of kasan_mem_to_shadow() that uses
the logical bit shift.

The non-canonical hook tries to calculate whether an address came from
kasan_mem_to_shadow(). First it checks whether this address fits into
the legal set of values possible to output from the mem to shadow
function.

Duplicate the generic mode check from kasan_non_canonical_hook() into
the arch specific function as the calculation follows the same logic due
to the same logical bit shift.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v9:
- Rename patch title so it fits the tip standards.
- Take out the x86 part from mm/kasan/report.c and put it in the arch
  specific function. Adjust the patch message.

Changelog v7:
- Redo the patch message and add a comment to __kasan_mem_to_shadow() to
  provide better explanation on why x86 doesn't work well with the
  arithemitc bit shift approach (Marco).

Changelog v4:
- Add this patch to the series.

 arch/x86/include/asm/kasan.h | 32 ++++++++++++++++++++++++++++++++
 1 file changed, 32 insertions(+)

diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index c868ae734f68..90c18e30848f 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -31,6 +31,38 @@
 #include <linux/bits.h>
 
 #ifdef CONFIG_KASAN_SW_TAGS
+/*
+ * Using the non-arch specific implementation of __kasan_mem_to_shadow() with a
+ * arithmetic bit shift can cause high code complexity in KASAN's non-canonical
+ * hook for x86 or might not work for some paging level and KASAN mode
+ * combinations. The inline mode compiler support could also suffer from higher
+ * complexity for no specific benefit. Therefore the generic mode's logical
+ * shift implementation is used.
+ */
+static inline void *__kasan_mem_to_shadow(const void *addr)
+{
+	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
+		+ KASAN_SHADOW_OFFSET;
+}
+#define kasan_mem_to_shadow(addr)	__kasan_mem_to_shadow(addr)
+
+static __always_inline bool __arch_kasan_non_canonical_hook(unsigned long addr)
+{
+	/*
+	 * For Generic KASAN and Software Tag-Based mode on the x86
+	 * architecture, kasan_mem_to_shadow() uses the logical right shift
+	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values (on
+	 * both x86 and arm64). Thus, the possible shadow addresses (even for
+	 * bogus pointers) belong to a single contiguous region that is the
+	 * result of kasan_mem_to_shadow() applied to the whole address space.
+	 */
+	if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
+	    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
+		return true;
+	return false;
+}
+#define arch_kasan_non_canonical_hook(addr) __arch_kasan_non_canonical_hook(addr)
+
 #define __tag_shifted(tag)		FIELD_PREP(GENMASK_ULL(60, 57), tag)
 #define __tag_reset(addr)		(sign_extend64((u64)(addr), 56))
 #define __tag_get(addr)			((u8)FIELD_GET(GENMASK_ULL(60, 57), (u64)addr))
-- 
2.53.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/0f4fe40cd9a481e64a3337c69b4e5e925a30ac7e.1770232424.git.m.wieczorretman%40pm.me.
