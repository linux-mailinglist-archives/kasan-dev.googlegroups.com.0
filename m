Return-Path: <kasan-dev+bncBDGZVRMH6UCRB4H6VG7AMGQEGLH4AEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3173CA55FC8
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Mar 2025 06:09:06 +0100 (CET)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e583e274095sf1682715276.3
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Mar 2025 21:09:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1741324145; cv=pass;
        d=google.com; s=arc-20240605;
        b=lSlaVWNeYCpvlEIZNGuCZp+2U4w9GWB4Np06HDgF/KbKGW6fZnTgQl222Pr/2Xl0s7
         aoZ87bPJ38tWfj9e7+dgZzwBWQv9CJRAulecea32/KREiYPEBZl19W5egTJ40bRObvJQ
         FcJNoHGBaTBwxi2/xQdAbWIi4FbjOd43MFNxySXbPiUQkbtZPb9huSFGoG2B8FFJeGPS
         SEzvYKJulFEtTSpogbZwt7TjOl8M+g8V2CFoiG6h/VIuWF7yhbyHQNxg9ykz93BDDzJB
         uwyr21WAvlO+xWbtOqY1JFi1kAChhcDjhQOkQKinCEP6RklVvXQBFZFY4bGgUWU9RxBb
         ijYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=uNClzC/qM2U5WMosJ1mrQUeWpTId7LGpS9hs/55/img=;
        fh=ykALzUAOSzHb0IzyuJRJ/lce0I0OUbH9VZpxPIQM6D4=;
        b=lzqyCj9zW8/JhdeB1WYltiJ95Y0VqaEmksGt8wKVMAvqq+VXNl7s3fftcJUXpJd1Zc
         Beu9GZSXBn93YpjDyDiTMpxGTsW8ma+k6Hxpw6cY2V3tutsiipv82U/RzibLCeuq6Nxx
         KaQc3iMMe9qSzeNEi0pLuTReks2uaZ8MzKddTEBfEtz23HSqf+NT3BoaG1PnSBxQuoOz
         2CfnNpIo01B7avc3AI6l26zPE1f22rJ+X6O82E8q3PprIgn9jLbxiavdyxrBBNjyGsUW
         J8mNETQmiBl6g048BMMPD41gKkAMAMPCXSMxKARcdSSpHKDM4QQMlkKO6opwvO/vwMhE
         l81w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741324145; x=1741928945; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uNClzC/qM2U5WMosJ1mrQUeWpTId7LGpS9hs/55/img=;
        b=w39awha0a1NyoB3firwJP+uFiFf44Rjad29npNY1aZV9G6rODw6v2T56G/KVIfjTqZ
         6ISOJ4uep1Mr1fp0TQtPjLBK3uXhpIORdo8P1B88i6oDxMxbQFo9ci51Npdj2aC7CMa6
         r2cFcaE5tMLB3ShOqE0L/+/9W2DImlNzC6Gc4nOSr3kJR7syw/WEjwWNTH3S6Erhikhf
         p5q1s2hbdPs6xtGWy69ZlAz+yvvj3M83map/fRRToseAL+4kS2ciuLVftwY+0tMPLBKE
         5+bO1ScnZe1wVORCRGtPXBz8Og2Slk0KAR+lKDE2qBUVUnXM7t81sV9dQIrtqQTH8LUr
         WNCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741324145; x=1741928945;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=uNClzC/qM2U5WMosJ1mrQUeWpTId7LGpS9hs/55/img=;
        b=AOD3ClMXEZMIOvK26U2PlMWFFswML2YDedbiobB0Tb1DVlPbwv+Rwq05urixSb/ppt
         WSpdE6lOugFnjBo8c7pD1wnrFSFCPsro2C6YMW9y3DsiuvuHKmg1WUCToU3qFE7kz8zG
         DUWHj0qhnc0WbV0NN2dHNYFm0no8byX8nxlVA9R5SrhtuqGluJxENUq0aRKQVviyLAok
         dMuByNf+W4KXrWPF73I35NA7VBAVKiMCkPcDds3aOgGFapxAjxQUb3lvxCYmvupdOAwF
         mf8yzR/etTuJgTEdJJ4NPfQBVCOfx2J7r2+eT8hQAIR+QjVLEHkEFBg+5mpwfjaWBCJO
         zCwQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUccl3KunKLgDKp8w9LwR5Bvdvf7NIczGqx83enJrHEOcBRrAqQeme37gYd3zyjiJjPE0ZtxQ==@lfdr.de
X-Gm-Message-State: AOJu0YwIjUfxYTl9SSjtcA1BbjdYBlP7XoUDMO7DQw2kM/9VGLF83r9t
	A0uYzESiATZigdSWwLOpvi76wx0R/LeLA7hJv+1qoeDeyX1o4OXC
X-Google-Smtp-Source: AGHT+IHNYAEQZUhfvoxrd7q22t+0tMrK5yfvUWqhYwiaox/mQynsmOjBnche/Y5OWKtcFyeRuOWl0Q==
X-Received: by 2002:a05:6902:154d:b0:e5d:dd0a:7fdb with SMTP id 3f1490d57ef6-e635c19566dmr2464697276.28.1741324144864;
        Thu, 06 Mar 2025 21:09:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGr9RVMPZ3TPhQODG18FpUZM8Ennyr3mFm/YQtKbhWIVA==
Received: by 2002:a25:aa89:0:b0:e60:8901:aead with SMTP id 3f1490d57ef6-e634856926cls1258228276.2.-pod-prod-07-us;
 Thu, 06 Mar 2025 21:09:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUYQnSHjrcfaeDpNFAtlU5psmlRJI5IMbSs8X0v8J1Hw9MfSsnWCDnOlXA85pn+JoD81LCCUvTQrhI=@googlegroups.com
X-Received: by 2002:a05:6902:1701:b0:e58:33aa:3ac7 with SMTP id 3f1490d57ef6-e635c1ed2eemr2619249276.44.1741324143862;
        Thu, 06 Mar 2025 21:09:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1741324143; cv=none;
        d=google.com; s=arc-20240605;
        b=flhvDz/T8rj0wBzi2xhSolTjjp2AjHxUs1rAODmo+qfnuSP1GSdxvLMWhIMDUAYI7T
         r5RKqDjEUHAtyDTUId9avXTZiLIprmUHKots/SQAf2SOtZXje+K4PUOjDVH5giYtpi1z
         Rx0IR5s8N2WQ8PzEbqJ8gJh94Mg5b8ytH+Kqze1VeJmW2pn7KLdx8c1sO0rrouodq7Jd
         QRkJ8nT76/y1VM4QnRCAwhoCzIrfd4fF+/FgRxAFple0+0bHyRG9m9B74aFsTV+/nhS1
         9vA4vVSt5Wgug39Ob7+EdlYGgsXhj3iYQ6nXT26oZui8ZYSIquwJ9IUCgdhxHf0jY3cr
         Qs2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=gZfaWFrnyRTRlDZleXMbzRz2449564iW/nkLH7vcD3I=;
        fh=5l/eLuwIniyMnBhDRDkXj2Fw1cfPUNtNnjRj2PJcfaw=;
        b=ay1YlwFwzmb1tV7z/KY/0D+qHONNhocBH9LaRy/V6ZQISbaoyEPRsAJKr/NjyU60AS
         CWQ5qPSRSZzK77DSW+WCP3jaSS8qgE0mNE6iBlHtKFlEj6TSsBzVIv7IrtlrUYMLXJmq
         WrJjmOPnuy2mdgQbhokOk+4hiXIzv+MS1ZlHp/NJxSjyrhg/6TVlTPmV/+zscsFIYGjd
         0fV3FqcEOsRf5AAWb/Ge5zD1Jicw6ePNAtQHDPpwi2qIvj2qz89NLfTvhiMTLpFgCull
         CWU7JaG7HBZaAZmnKbXTqQub1nVj1Xy/2gUmcgriib5ImqUIPpluvcXbj0j0tKA2lm36
         zkgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 3f1490d57ef6-e635fa2d448si34294276.0.2025.03.06.21.09.03
        for <kasan-dev@googlegroups.com>;
        Thu, 06 Mar 2025 21:09:03 -0800 (PST)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 1F939150C;
	Thu,  6 Mar 2025 21:09:16 -0800 (PST)
Received: from a077893.blr.arm.com (a077893.blr.arm.com [10.162.42.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 054D83F66E;
	Thu,  6 Mar 2025 21:08:58 -0800 (PST)
From: Anshuman Khandual <anshuman.khandual@arm.com>
To: linux-arm-kernel@lists.infradead.org
Cc: Anshuman Khandual <anshuman.khandual@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Ard Biesheuvel <ardb@kernel.org>,
	Ryan Roberts <ryan.roberts@arm.com>,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH] arm64/mm: Define PTE_SHIFT
Date: Fri,  7 Mar 2025 10:38:51 +0530
Message-Id: <20250307050851.4034393-1-anshuman.khandual@arm.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-Original-Sender: anshuman.khandual@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Address bytes shifted with a single 64 bit page table entry (any page table
level) has been always hard coded as 3 (aka 2^3 = 8). Although intuitive it
is not very readable or easy to reason about. Besides it is going to change
with D128, where each 128 bit page table entry will shift address bytes by
4 (aka 2^4 = 16) instead.

Let's just formalise this address bytes shift value into a new macro called
PTE_SHIFT establishing a logical abstraction, thus improving readability as
well. This does not cause any functional change.

Cc: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will@kernel.org>
Cc: Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Ard Biesheuvel <ardb@kernel.org>
Cc: Ryan Roberts <ryan.roberts@arm.com>
Cc: linux-arm-kernel@lists.infradead.org
Cc: linux-kernel@vger.kernel.org
Cc: kasan-dev@googlegroups.com
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
This patch applies on v6.14-rc5

 arch/arm64/Kconfig                      |  2 +-
 arch/arm64/include/asm/kernel-pgtable.h |  3 ++-
 arch/arm64/include/asm/pgtable-hwdef.h  | 26 +++++++++++++------------
 arch/arm64/kernel/pi/map_range.c        |  2 +-
 arch/arm64/mm/kasan_init.c              |  6 +++---
 5 files changed, 21 insertions(+), 18 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 940343beb3d4..fd3303f2ccda 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -323,7 +323,7 @@ config ARCH_MMAP_RND_BITS_MIN
 	default 18
 
 # max bits determined by the following formula:
-#  VA_BITS - PAGE_SHIFT - 3
+#  VA_BITS - PAGE_SHIFT - PTE_SHIFT
 config ARCH_MMAP_RND_BITS_MAX
 	default 19 if ARM64_VA_BITS=36
 	default 24 if ARM64_VA_BITS=39
diff --git a/arch/arm64/include/asm/kernel-pgtable.h b/arch/arm64/include/asm/kernel-pgtable.h
index fd5a08450b12..7150a7a10f00 100644
--- a/arch/arm64/include/asm/kernel-pgtable.h
+++ b/arch/arm64/include/asm/kernel-pgtable.h
@@ -49,7 +49,8 @@
 	(SPAN_NR_ENTRIES(vstart, vend, shift) + (add))
 
 #define EARLY_LEVEL(lvl, lvls, vstart, vend, add)	\
-	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
+	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + \
+	lvl * (PAGE_SHIFT - PTE_SHIFT), add) : 0)
 
 #define EARLY_PAGES(lvls, vstart, vend, add) (1 	/* PGDIR page */				\
 	+ EARLY_LEVEL(3, (lvls), (vstart), (vend), add) /* each entry needs a next level page table */	\
diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
index a9136cc551cc..43f98eac7653 100644
--- a/arch/arm64/include/asm/pgtable-hwdef.h
+++ b/arch/arm64/include/asm/pgtable-hwdef.h
@@ -7,40 +7,42 @@
 
 #include <asm/memory.h>
 
+#define PTE_SHIFT 3
+
 /*
  * Number of page-table levels required to address 'va_bits' wide
  * address, without section mapping. We resolve the top (va_bits - PAGE_SHIFT)
- * bits with (PAGE_SHIFT - 3) bits at each page table level. Hence:
+ * bits with (PAGE_SHIFT - PTE_SHIFT) bits at each page table level. Hence:
  *
- *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - 3))
+ *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - PTE_SHIFT))
  *
  * where DIV_ROUND_UP(n, d) => (((n) + (d) - 1) / (d))
  *
  * We cannot include linux/kernel.h which defines DIV_ROUND_UP here
  * due to build issues. So we open code DIV_ROUND_UP here:
  *
- *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - 3) - 1) / (PAGE_SHIFT - 3))
+ *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - PTE_SHIFT) - 1) / (PAGE_SHIFT - PTE_SHIFT))
  *
  * which gets simplified as :
  */
-#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
+#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - PTE_SHIFT - 1) / (PAGE_SHIFT - PTE_SHIFT))
 
 /*
  * Size mapped by an entry at level n ( -1 <= n <= 3)
- * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
+ * We map (PAGE_SHIFT - PTE_SHIFT) at all translation levels and PAGE_SHIFT bits
  * in the final page. The maximum number of translation levels supported by
  * the architecture is 5. Hence, starting at level n, we have further
  * ((4 - n) - 1) levels of translation excluding the offset within the page.
  * So, the total number of bits mapped by an entry at level n is :
  *
- *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
+ *  ((4 - n) - 1) * (PAGE_SHIFT - PTE_SHIFT) + PAGE_SHIFT
  *
  * Rearranging it a bit we get :
- *   (4 - n) * (PAGE_SHIFT - 3) + 3
+ *   (4 - n) * (PAGE_SHIFT - PTE_SHIFT) + PTE_SHIFT
  */
-#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
+#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - PTE_SHIFT) * (4 - (n)) + PTE_SHIFT)
 
-#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - PTE_SHIFT))
 
 /*
  * PMD_SHIFT determines the size a level 2 page table entry can map.
@@ -49,7 +51,7 @@
 #define PMD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
 #define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
 #define PMD_MASK		(~(PMD_SIZE-1))
-#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - PTE_SHIFT))
 #endif
 
 /*
@@ -59,14 +61,14 @@
 #define PUD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
 #define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
 #define PUD_MASK		(~(PUD_SIZE-1))
-#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - PTE_SHIFT))
 #endif
 
 #if CONFIG_PGTABLE_LEVELS > 4
 #define P4D_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(0)
 #define P4D_SIZE		(_AC(1, UL) << P4D_SHIFT)
 #define P4D_MASK		(~(P4D_SIZE-1))
-#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - PTE_SHIFT))
 #endif
 
 /*
diff --git a/arch/arm64/kernel/pi/map_range.c b/arch/arm64/kernel/pi/map_range.c
index 2b69e3beeef8..3530a5427f57 100644
--- a/arch/arm64/kernel/pi/map_range.c
+++ b/arch/arm64/kernel/pi/map_range.c
@@ -31,7 +31,7 @@ void __init map_range(u64 *pte, u64 start, u64 end, u64 pa, pgprot_t prot,
 {
 	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
 	pteval_t protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
-	int lshift = (3 - level) * (PAGE_SHIFT - 3);
+	int lshift = (3 - level) * (PAGE_SHIFT - PTE_SHIFT);
 	u64 lmask = (PAGE_SIZE << lshift) - 1;
 
 	start	&= PAGE_MASK;
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b65a29440a0c..90548079b42e 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -190,7 +190,7 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
  */
 static bool __init root_level_aligned(u64 addr)
 {
-	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - 3);
+	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - PTE_SHIFT);
 
 	return (addr % (PAGE_SIZE << shift)) == 0;
 }
@@ -245,7 +245,7 @@ static int __init root_level_idx(u64 addr)
 	 */
 	u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
 							: vabits_actual;
-	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
+	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - PTE_SHIFT);
 
 	return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
 }
@@ -269,7 +269,7 @@ static void __init clone_next_level(u64 addr, pgd_t *tmp_pg_dir, pud_t *pud)
  */
 static int __init next_level_idx(u64 addr)
 {
-	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - 3);
+	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - PTE_SHIFT);
 
 	return (addr >> (shift + PAGE_SHIFT)) % PTRS_PER_PTE;
 }
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250307050851.4034393-1-anshuman.khandual%40arm.com.
