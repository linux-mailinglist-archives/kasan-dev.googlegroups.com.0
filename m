Return-Path: <kasan-dev+bncBDGZVRMH6UCRBMUFX67AMGQETQHDSCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 49794A5B820
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Mar 2025 05:57:25 +0100 (CET)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2ff798e8c3bsf7331941a91.2
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Mar 2025 21:57:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741669043; cv=pass;
        d=google.com; s=arc-20240605;
        b=TXDIJ1S1eSAjqH3dQJKzeJj6uss9i4dE+nTqDnmBlNlOsBef54ImgSWJanZoUp0CsP
         zx0uSzAQvMuaV8U1ILK4RhFdpqKkTaXawrWM2RcN0OMjL23WhFsFW1CW5WDU5c24JRO8
         X40zQZ81m64U6iiw1XDM5296zWMDHtJxalduy+RlXfkZ2lhl84cVNCx+Wl02O/ySobmY
         Pr9o4kmiMwEnwYfbW02YQig6jLImsHkW0yAEfUv1akGDINr0sSMF709pxYHS9ts8fKBz
         7EuLfHt/jU5zMvG/wp+aWkNfEsMUbNI5VmM8wPa0G4TukKUcNWQLwcqrYlc2p+YpIjr9
         9W0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=kmztOErHfrTdUka6lxZB7tuO1dm86hlJA/NE3UchD8o=;
        fh=sn6+6VL4/LrKBYqII9yUs3nFKiHJSClrmTQRlWUTHQ0=;
        b=RcjHzdzF3PKer1H5u0XSmd8AxiGe3Iqkw3IhyL2j4Sk9Z9m3ds7DgUlaJ3JhwrGOes
         LjpAzolPjukG+f6+g99SIld7PwLdacaULnwlzUNvExz/2QXx0E6tMETfKDzZL+QHlnwB
         UU+tK9xofA+laeSKO8Js5FIT0Em6jEmmJGEl6EL4L34BH9uz9AC29YKRfc3//Vkm7dD/
         MShD3twcJssoi0YEDGsredL60XK4zxGwDelhNpgk3Si/0YxBbj0Cqfb72SeXMX9KqNJv
         5WPE6f9ATXsFHoTbms3k/wNfvw3aviGsTKz6CXjkm8GyakXnDqDTLwkTvCNgLJ4rOK21
         M4dQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741669043; x=1742273843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kmztOErHfrTdUka6lxZB7tuO1dm86hlJA/NE3UchD8o=;
        b=XoqCex04qh7EUUEeNMp3vS7u7ZqqDoZZB5WduEXItkTXXz2UnUlqERq+gO14UHUbLX
         IwvUsgKBc1ihJGme1t63AnJq7RLGGCJX1ddFwo7BLE8wkfG/R0XiT3aTElafO6exDPIS
         Dd4NfEhgCFfSceZrz9sJNcexxaBQbjfGKQMwv1ShTRKJmQaL0KJ0C+e5iAheyLBU+ncO
         wRDaATgKAiW/eZDBViZq1kxeStv4EVojMMh50+4tA8ssmub3Cz4LSAvFv1QAIjAaxgAq
         xBxsY4Aq3FneFTyHyb4UahTcAUES4uzeXbP6lSav7xXIXtbvWxJxmfuRZm/Qcnl1mgl/
         A/Cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741669043; x=1742273843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=kmztOErHfrTdUka6lxZB7tuO1dm86hlJA/NE3UchD8o=;
        b=HTqRFqKk6IZTwvTDXM7Yg5S/ls6x/hka22xCiuUtaQJX4kJviO6TJ/sSSIDqDIpVB0
         BlpON5skTgfe6NFaUDC3SQ/IPiVjOTsQ20XJ8Fq3wAhxP//x3YHKe3ERHI3D7sVnyppe
         Gi/DskkfKP/noNBGdoRxNNRWqOfLVfDPsVIBFRZ+5fukX3+1anl8J+EE5bCQMJ5o387N
         YAkd5OBPNk79FRc8/RM7yRQgL7y+CP61u1cK3FoqTvsxJZuIz9vJ3KSYbUzX9p49IUzT
         zrbhuuWBjn0cGcwdtUuy4u4b/h0JgCfHdResatqN32Ix6Y725fxAHM5KVaAcAQnX7m0t
         QTfA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUlRvbpTMYrO8ai46xwJqP0X4tkrm2Oxgy19VIOY9n7bOEcqqmogVC8UCxCtRbegVQqY1caKw==@lfdr.de
X-Gm-Message-State: AOJu0YwycT5irUt0sSV0i7x+OcGMPUQf8NefQWvxIJNK+Uqj9FDjrvy5
	rfpU8nvEXJKE1tzG+mdxo+zRmBeTDgxWxfO0FoBKuddKGeBVRxy+
X-Google-Smtp-Source: AGHT+IHkMFEjUmNps+kNxQrMmkWrVyLPwg3W1Qxb5SXo6o4pwY6vDGqGMRvi7SynvoNq7W68RkeAsQ==
X-Received: by 2002:a17:90b:38cd:b0:2ee:741c:e9f4 with SMTP id 98e67ed59e1d1-2ff7ce8e5dfmr25068073a91.11.1741669043258;
        Mon, 10 Mar 2025 21:57:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVEWPb1cTdBs+BLUEhi4K/H/ul3o3xuy7j6tqiy6Kz39Hw==
Received: by 2002:a17:90a:c917:b0:2fa:1e46:bfa with SMTP id
 98e67ed59e1d1-2ff628a8466ls4849362a91.1.-pod-prod-07-us; Mon, 10 Mar 2025
 21:57:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWjqRhd6GSddMmfXOPjhDdG5p77JWeyKCo2TBTdvyFIrq/v7rx9lZFrzKQVhogDprCoxrDesngYq68=@googlegroups.com
X-Received: by 2002:a17:90b:4f8f:b0:2fe:b937:2a51 with SMTP id 98e67ed59e1d1-2ff7cf3e3f7mr28239428a91.33.1741669041629;
        Mon, 10 Mar 2025 21:57:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1741669041; cv=none;
        d=google.com; s=arc-20240605;
        b=DOsRjU6bwY+tPYWlUbDR48a2RI8NwZfhVqvZK75uqio2vnDq3Cn6NOsBtac+zZrGcU
         6UUt98bHan25bT3pBGMA4inp00jab5P99W8KFlUIFt39yE0V82Do8CIcfIkf8SeiXy6e
         nynBqP3FSQimv/ZWsn5MOAsxE/YEA3KbV4mr8InMHytN6TTwBgzYFyU8fDU67GAtAj2M
         PqrSkdWTt2jP07P4nwNlxJh4Ysh7rMj4bUohdckRUJEAltrN25zTmKjUq777lANjh5xT
         ZxXJ9prRh4gD8GWs2Bqj81GCD+kOBlQtW2W0WBMz6TgLcbC01ksyuh1+OkiHxa2RV+76
         nCGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=XabsgAyp04zCDh9YJQMj9X1lo3AVdIElty7Tk8zI+lo=;
        fh=5l/eLuwIniyMnBhDRDkXj2Fw1cfPUNtNnjRj2PJcfaw=;
        b=OZSz6HVi4gGc/CGS6DZtqR5cvuPhfRE6k8y2roKwggB5cjv2OOzXmyFEDVxUcJ4fL3
         ZH95JDC5784ZTJtdEfY8YFWF1bFOwLIVaUsmTYO6yglMRhgLjKiV0tp2bnnHb1TA9lPI
         EpGecZrxEayCiv484egeiTCA053+dML+DPAeC2Due0r+fBUecB2yJFt3wSCPFwFy3K+x
         VLaTTV7PRLNTXpd8sHW6ZUAQolgtopvFOvC0M6HdCX2VKqa7RonHLKMry9eui+9+hxv3
         fYg9ZNXlcM6LwcFDJvPDXqQQ2wliFV5MIDMlUz/+KYyaN8QsSXdyY+6kBNssbMUXXIAQ
         dgJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-30102708526si110607a91.0.2025.03.10.21.57.21
        for <kasan-dev@googlegroups.com>;
        Mon, 10 Mar 2025 21:57:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 027B01516;
	Mon, 10 Mar 2025 21:57:32 -0700 (PDT)
Received: from a077893.blr.arm.com (a077893.blr.arm.com [10.162.40.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 624C13F694;
	Mon, 10 Mar 2025 21:57:16 -0700 (PDT)
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
Subject: [PATCH V3] arm64/mm: Define PTDESC_ORDER
Date: Tue, 11 Mar 2025 10:27:10 +0530
Message-Id: <20250311045710.550625-1-anshuman.khandual@arm.com>
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
PTDESC_ORDER establishing a logical abstraction, thus improving readability
as well. While here re-organize EARLY_LEVEL macro along with its dependents
for better clarity. This does not cause any functional change. Also replace
all (PAGE_SHIFT - PTDESC_ORDER) instances with PTDESC_TABLE_SHIFT.

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
Acked-by: Ard Biesheuvel <ardb@kernel.org>
Reviewed-by: Ryan Roberts <ryan.roberts@arm.com>
Signed-off-by: Anshuman Khandual <anshuman.khandual@arm.com>
---
This patch applies on v6.14-rc6

Changes in V3:

- Moved PTDESC_TABLE_SHIFT definition inside asm/pgtable-hwdef.h
- Replaced all (PAGE_SHIFT - PTDESC_ORDER) instances with PTDESC_TABLE_SHIFT

Changes in V2:

https://lore.kernel.org/all/20250310040115.91298-1-anshuman.khandual@arm.com/

- Replaced PTE_SHIFT with PTDESC_ORDER per Ard
- Re-organized EARLY_LEVEL macro per Mark

Changes in V1:

https://lore.kernel.org/all/20250307050851.4034393-1-anshuman.khandual@arm.com/

 arch/arm64/Kconfig                      |  2 +-
 arch/arm64/include/asm/kernel-pgtable.h |  8 +++----
 arch/arm64/include/asm/pgtable-hwdef.h  | 30 +++++++++++++++----------
 arch/arm64/kernel/pi/map_range.c        |  2 +-
 arch/arm64/mm/kasan_init.c              |  6 ++---
 5 files changed, 27 insertions(+), 21 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 940343beb3d4..c8f48945cc09 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -323,7 +323,7 @@ config ARCH_MMAP_RND_BITS_MIN
 	default 18
 
 # max bits determined by the following formula:
-#  VA_BITS - PAGE_SHIFT - 3
+#  VA_BITS - PTDESC_TABLE_SHIFT
 config ARCH_MMAP_RND_BITS_MAX
 	default 19 if ARM64_VA_BITS=36
 	default 24 if ARM64_VA_BITS=39
diff --git a/arch/arm64/include/asm/kernel-pgtable.h b/arch/arm64/include/asm/kernel-pgtable.h
index fd5a08450b12..9e93733523f6 100644
--- a/arch/arm64/include/asm/kernel-pgtable.h
+++ b/arch/arm64/include/asm/kernel-pgtable.h
@@ -45,11 +45,11 @@
 #define SPAN_NR_ENTRIES(vstart, vend, shift) \
 	((((vend) - 1) >> (shift)) - ((vstart) >> (shift)) + 1)
 
-#define EARLY_ENTRIES(vstart, vend, shift, add) \
-	(SPAN_NR_ENTRIES(vstart, vend, shift) + (add))
+#define EARLY_ENTRIES(lvl, vstart, vend) \
+	SPAN_NR_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * PTDESC_TABLE_SHIFT)
 
-#define EARLY_LEVEL(lvl, lvls, vstart, vend, add)	\
-	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
+#define EARLY_LEVEL(lvl, lvls, vstart, vend, add) \
+	((lvls) > (lvl) ? EARLY_ENTRIES(lvl, vstart, vend) + (add) : 0)
 
 #define EARLY_PAGES(lvls, vstart, vend, add) (1 	/* PGDIR page */				\
 	+ EARLY_LEVEL(3, (lvls), (vstart), (vend), add) /* each entry needs a next level page table */	\
diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
index a9136cc551cc..288964341404 100644
--- a/arch/arm64/include/asm/pgtable-hwdef.h
+++ b/arch/arm64/include/asm/pgtable-hwdef.h
@@ -7,40 +7,46 @@
 
 #include <asm/memory.h>
 
+#define PTDESC_ORDER 3
+
+/* Number of VA bits resolved by a single translation table level */
+#define PTDESC_TABLE_SHIFT	(PAGE_SHIFT - PTDESC_ORDER)
+
 /*
  * Number of page-table levels required to address 'va_bits' wide
  * address, without section mapping. We resolve the top (va_bits - PAGE_SHIFT)
- * bits with (PAGE_SHIFT - 3) bits at each page table level. Hence:
+ * bits with PTDESC_TABLE_SHIFT bits at each page table level. Hence:
  *
- *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - 3))
+ *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), PTDESC_TABLE_SHIFT)
  *
  * where DIV_ROUND_UP(n, d) => (((n) + (d) - 1) / (d))
  *
  * We cannot include linux/kernel.h which defines DIV_ROUND_UP here
  * due to build issues. So we open code DIV_ROUND_UP here:
  *
- *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - 3) - 1) / (PAGE_SHIFT - 3))
+ *	((((va_bits) - PAGE_SHIFT) + PTDESC_TABLE_SHIFT - 1) / PTDESC_TABLE_SHIFT)
  *
  * which gets simplified as :
  */
-#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
+#define ARM64_HW_PGTABLE_LEVELS(va_bits) \
+	(((va_bits) - PTDESC_ORDER - 1) / PTDESC_TABLE_SHIFT)
 
 /*
  * Size mapped by an entry at level n ( -1 <= n <= 3)
- * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
+ * We map PTDESC_TABLE_SHIFT at all translation levels and PAGE_SHIFT bits
  * in the final page. The maximum number of translation levels supported by
  * the architecture is 5. Hence, starting at level n, we have further
  * ((4 - n) - 1) levels of translation excluding the offset within the page.
  * So, the total number of bits mapped by an entry at level n is :
  *
- *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
+ *  ((4 - n) - 1) * PTDESC_TABLE_SHIFT + PAGE_SHIFT
  *
  * Rearranging it a bit we get :
- *   (4 - n) * (PAGE_SHIFT - 3) + 3
+ *   (4 - n) * PTDESC_TABLE_SHIFT + PTDESC_ORDER
  */
-#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
+#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	(PTDESC_TABLE_SHIFT * (4 - (n)) + PTDESC_ORDER)
 
-#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_PTE		(1 << PTDESC_TABLE_SHIFT)
 
 /*
  * PMD_SHIFT determines the size a level 2 page table entry can map.
@@ -49,7 +55,7 @@
 #define PMD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
 #define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
 #define PMD_MASK		(~(PMD_SIZE-1))
-#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_PMD		(1 << PTDESC_TABLE_SHIFT)
 #endif
 
 /*
@@ -59,14 +65,14 @@
 #define PUD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
 #define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
 #define PUD_MASK		(~(PUD_SIZE-1))
-#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_PUD		(1 << PTDESC_TABLE_SHIFT)
 #endif
 
 #if CONFIG_PGTABLE_LEVELS > 4
 #define P4D_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(0)
 #define P4D_SIZE		(_AC(1, UL) << P4D_SHIFT)
 #define P4D_MASK		(~(P4D_SIZE-1))
-#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_P4D		(1 << PTDESC_TABLE_SHIFT)
 #endif
 
 /*
diff --git a/arch/arm64/kernel/pi/map_range.c b/arch/arm64/kernel/pi/map_range.c
index 2b69e3beeef8..dc68d09555b9 100644
--- a/arch/arm64/kernel/pi/map_range.c
+++ b/arch/arm64/kernel/pi/map_range.c
@@ -31,7 +31,7 @@ void __init map_range(u64 *pte, u64 start, u64 end, u64 pa, pgprot_t prot,
 {
 	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
 	pteval_t protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
-	int lshift = (3 - level) * (PAGE_SHIFT - 3);
+	int lshift = (3 - level) * PTDESC_TABLE_SHIFT;
 	u64 lmask = (PAGE_SIZE << lshift) - 1;
 
 	start	&= PAGE_MASK;
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b65a29440a0c..d541ce45daeb 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -190,7 +190,7 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
  */
 static bool __init root_level_aligned(u64 addr)
 {
-	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - 3);
+	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * PTDESC_TABLE_SHIFT;
 
 	return (addr % (PAGE_SIZE << shift)) == 0;
 }
@@ -245,7 +245,7 @@ static int __init root_level_idx(u64 addr)
 	 */
 	u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
 							: vabits_actual;
-	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
+	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * PTDESC_TABLE_SHIFT;
 
 	return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
 }
@@ -269,7 +269,7 @@ static void __init clone_next_level(u64 addr, pgd_t *tmp_pg_dir, pud_t *pud)
  */
 static int __init next_level_idx(u64 addr)
 {
-	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - 3);
+	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * PTDESC_TABLE_SHIFT;
 
 	return (addr >> (shift + PAGE_SHIFT)) % PTRS_PER_PTE;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250311045710.550625-1-anshuman.khandual%40arm.com.
