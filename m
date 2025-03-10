Return-Path: <kasan-dev+bncBDGZVRMH6UCRBFWIXG7AMGQEBRR4Z4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 32AAFA58B04
	for <lists+kasan-dev@lfdr.de>; Mon, 10 Mar 2025 05:01:29 +0100 (CET)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-2254bdd4982sf39644865ad.1
        for <lists+kasan-dev@lfdr.de>; Sun, 09 Mar 2025 21:01:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1741579287; cv=pass;
        d=google.com; s=arc-20240605;
        b=atsp5M0/7AkKj2KcHojR3TXhZuehK7gz5qVlLFr5MXPqCEQwTBNrIzUnl9IhxslXJt
         LZAJVJktJEXm8PzrBBLaYP/tmFLZzAuTJErLpwfBbEBqQIR+y/S7e88Xrhh4LLZmQptq
         bLailZ3bKdvS62EhTsbYAUX1BOhe2054ayb/EBJwo67AYc+dSKj7Uy48+xcK6IHuMskX
         +g8IzYgFpuHcoh13uhD05Bb9K+ymI61Dr9revR47sWCUnT9AugnOB2PIuBntgNx6lp3/
         p1/V6Covh8Um3rGJnuo3ivdsH7xBqOPrsHBo3b6NegtinnnJ2dar7eGnEw+EJc/CoW4z
         jyWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=1zDJ93ffeR1B8ZxQ21e1lVt0qU66Q3KCemkVt6xkKz4=;
        fh=SfLTOiPJE6h+95kW5/DGRymU73XInwHckS5Exl/kdY8=;
        b=TJgLvA+8zhSkT+OYz81zCs1o/cZyqkohvnAN342Q9Pi8p9M4R4+XUgCuqn3NRuydE2
         5O0HedEqZ/sA36ocIGPTeuCwmn6NIoDCE+pOVQ77ETx7RfxyXvoSyBux+pfhrwAe2atW
         htW8UXhBQcoC02un5JOTtvSxPEnkFfVz0acIJABne9IAI063qgScH4Qk8SlAwTSSzQN3
         SpfGRd/dBHLlEJnqZQBnTXpo0tg22fFWigIxT/b4ADdSiZ398+UvTxkmGuuwucJc60Yn
         KmvzhSsQZ37r/drKPDZRsWR40YoXQyD+9FVm78W2M1NUGr08BnfWlZTYkMd+KGAnbBUv
         I6Bw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1741579287; x=1742184087; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1zDJ93ffeR1B8ZxQ21e1lVt0qU66Q3KCemkVt6xkKz4=;
        b=s9jmTc99gximmR3mmXZGUvtklXf7rEU4uhPJSM1UmO1qawFcCRD3XvdhgmVUf/KI0C
         PT025paYKJoUXMrqoyJ8Dpkjz4jptfNWCYIM71PjEtUIjvpZuQsn1uNbcKn59f4HsyQk
         R7Eq62Nm+uM+eGmq8F5A/DAkeIm7lLf11fDuUPwm2v+4Rurme1E9xwWWYq4AV86DICo7
         piWOoDrkbFqwXJp1Vg8NQPvy/rpi45X37aPiNJifTwWNCDRoZXVU7KOpIQOaNVZwN6cj
         o/FfAT8aTuJh1PfE0Le88PqPYWM/8sd4DHeLiYcMae5Vi4z5Sq1QRMxfT3WLspyY/Vsq
         I0Sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1741579287; x=1742184087;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1zDJ93ffeR1B8ZxQ21e1lVt0qU66Q3KCemkVt6xkKz4=;
        b=KFwZCgdHjXFl0P1rPfCVrivF8l3Ng2ZRg+3N8/kAyjDzExmm1co/r3umwDQm2NARUM
         yaxPGq9dUX4PwMndKvdimkYJuBI05VAr+QMzP8Wzq01r4eUoDAIyG582Qvn4gH/G/glB
         NBWw2j/XGQBB7KiWDPt+eSb2np10LQR1HT4bB6TsuCxIRoSiLKe7y9M3osZ4uLNVVRGj
         O4R842ij76CGWRMmFyQZSS46s9bTOrPKEiHZErLpTt/1ybs7oGAw2RON3ng+JBHzYQ2m
         rdw5UUdgi0qbJCKxY6UfNvQo8WNI+MG3R7pe+O3eqS4tvPQrLD7Todh6483NVpAeU5Bv
         bndg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXzLB4zbmQ6SJXUDB144Me0AQYw1KnWo+D/e6p7Gbk3KPil2P1B9QhyLr4ZCvWbnwPr+buXgA==@lfdr.de
X-Gm-Message-State: AOJu0YwZ1Sm+sDyksDsKw4ak3IgLMB6XFyh0/9uvXCRBGwXjY8HVnkDa
	mDlAbWRtE4We46147zvdgDJ6qBzAhpFF4SYSbgus8unkzpkdoqaq
X-Google-Smtp-Source: AGHT+IF0po2rqBkMZtkWMe+4BzZLF4+3V3Zql30W6Naxq74X6ev619+KU57slPz0RU/qErlJRaPa0A==
X-Received: by 2002:a17:902:e5d2:b0:21f:1549:a55a with SMTP id d9443c01a7336-2242887b30dmr204350075ad.1.1741579287194;
        Sun, 09 Mar 2025 21:01:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGLYEsArLoYrk65Ke+PERIrtdd1yeGNRSJmf2LNUrv6/Q==
Received: by 2002:a17:902:fc8e:b0:223:f930:6e87 with SMTP id
 d9443c01a7336-224091b301bls17675055ad.1.-pod-prod-03-us; Sun, 09 Mar 2025
 21:01:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXjNaRYi3ZcbMpYBJSbE4U2Vsuz22gaq3NEBQMYCOnIHvv3kzNwk0Lqz9IngOShwW4EncCGP+BLiMk=@googlegroups.com
X-Received: by 2002:a17:903:98b:b0:223:397f:46be with SMTP id d9443c01a7336-22428ad4a09mr196096625ad.47.1741579284078;
        Sun, 09 Mar 2025 21:01:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1741579284; cv=none;
        d=google.com; s=arc-20240605;
        b=dsFkx/4+7TDCy18HGkaqY1CvFhMeVg7jkzsNBARTI3Qbd8nD6tZEv3Gx51vnr6ICGm
         jmysoCrrUaLLSBvtIN7+3CM6BrhtWq5zrLsM6O0cNFJcI4HZ7/B2aQ74z9vy75CMJ0g7
         +sQbco2HgIs2YvS8NUuFTdN0DSnZC4yMdEoAMGQFL6sdswR4BOgZpmO9xVfO9rZld61b
         RweQxj1nHBz+prQCjLM4a6cQXEsT2enrKwMSF/R+k5fEd2TWEtajY1pHrjl9pz3osvbf
         J/nbeFtn2+JY62WUaQxCeLuhjn7g6Fh86YJ+hHjjf8pY/H0a3/9xzmHmKeb7OJNUqOWC
         TCjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=y/WkbbSgGnY9T7hMavgR3DToVbrZtJqmk4830aygPEE=;
        fh=5l/eLuwIniyMnBhDRDkXj2Fw1cfPUNtNnjRj2PJcfaw=;
        b=QhYMr+zBsrdaYDqNsPxfISFqH1QqOxDoBaf3iY+ZJs+0OMJmIGArEQzWQEfpJwZRSU
         L84PK7Wh4CO6zamgMs/b9TaGRFPOTYCo1vRw3cGyf4gn+rbegC3O/QJqqOvSlt64xmTC
         hEDahqkY/cJZVE4ITi6amA5NccGuU45pC5muTV8oTXQnXzU+aNFl3OQyLZA/6VLCDe+N
         jhhOJMXiXekPaPDwwOymBuUmsIhQhPSlgcv66reEDN+lrKovgvOdMTbXW+RHVA6FX455
         9Mc5rXzNWPh54YAI6kiVMpoQc64DqNIh5WybxV/TI2PsBWmPnm6jsfmMBUXaNe2cNSaR
         9gwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=anshuman.khandual@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d9443c01a7336-224191d9babsi3007725ad.8.2025.03.09.21.01.23
        for <kasan-dev@googlegroups.com>;
        Sun, 09 Mar 2025 21:01:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of anshuman.khandual@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B477D15A1;
	Sun,  9 Mar 2025 21:01:34 -0700 (PDT)
Received: from a077893.arm.com (unknown [10.163.42.69])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 99DCC3F673;
	Sun,  9 Mar 2025 21:01:18 -0700 (PDT)
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
Subject: [PATCH V2] arm64/mm: Define PTDESC_ORDER
Date: Mon, 10 Mar 2025 09:31:15 +0530
Message-Id: <20250310040115.91298-1-anshuman.khandual@arm.com>
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
for better clarity. This does not cause any functional change.

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

Changes in V2:

- Replaced PTE_SHIFT with PTDESC_ORDER per Ard
- Re-organized EARLY_LEVEL macro per Mark

Changes in V1:

https://lore.kernel.org/all/20250307050851.4034393-1-anshuman.khandual@arm.com/

 arch/arm64/Kconfig                      |  2 +-
 arch/arm64/include/asm/kernel-pgtable.h | 11 ++++++----
 arch/arm64/include/asm/pgtable-hwdef.h  | 27 ++++++++++++++-----------
 arch/arm64/kernel/pi/map_range.c        |  2 +-
 arch/arm64/mm/kasan_init.c              |  6 +++---
 5 files changed, 27 insertions(+), 21 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index 940343beb3d4..657baf59fdbe 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -323,7 +323,7 @@ config ARCH_MMAP_RND_BITS_MIN
 	default 18
 
 # max bits determined by the following formula:
-#  VA_BITS - PAGE_SHIFT - 3
+#  VA_BITS - PAGE_SHIFT - PTDESC_ORDER
 config ARCH_MMAP_RND_BITS_MAX
 	default 19 if ARM64_VA_BITS=36
 	default 24 if ARM64_VA_BITS=39
diff --git a/arch/arm64/include/asm/kernel-pgtable.h b/arch/arm64/include/asm/kernel-pgtable.h
index fd5a08450b12..78c7e03a0e35 100644
--- a/arch/arm64/include/asm/kernel-pgtable.h
+++ b/arch/arm64/include/asm/kernel-pgtable.h
@@ -45,11 +45,14 @@
 #define SPAN_NR_ENTRIES(vstart, vend, shift) \
 	((((vend) - 1) >> (shift)) - ((vstart) >> (shift)) + 1)
 
-#define EARLY_ENTRIES(vstart, vend, shift, add) \
-	(SPAN_NR_ENTRIES(vstart, vend, shift) + (add))
+/* Number of VA bits resolved by a single translation table level */
+#define PTDESC_TABLE_SHIFT	(PAGE_SHIFT - PTDESC_ORDER)
 
-#define EARLY_LEVEL(lvl, lvls, vstart, vend, add)	\
-	(lvls > lvl ? EARLY_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * (PAGE_SHIFT - 3), add) : 0)
+#define EARLY_ENTRIES(lvl, vstart, vend) \
+	SPAN_NR_ENTRIES(vstart, vend, SWAPPER_BLOCK_SHIFT + lvl * PTDESC_TABLE_SHIFT)
+
+#define EARLY_LEVEL(lvl, lvls, vstart, vend, add) \
+	((lvls) > (lvl) ? EARLY_ENTRIES(lvl, vstart, vend) + (add) : 0)
 
 #define EARLY_PAGES(lvls, vstart, vend, add) (1 	/* PGDIR page */				\
 	+ EARLY_LEVEL(3, (lvls), (vstart), (vend), add) /* each entry needs a next level page table */	\
diff --git a/arch/arm64/include/asm/pgtable-hwdef.h b/arch/arm64/include/asm/pgtable-hwdef.h
index a9136cc551cc..3c544edc3968 100644
--- a/arch/arm64/include/asm/pgtable-hwdef.h
+++ b/arch/arm64/include/asm/pgtable-hwdef.h
@@ -7,40 +7,43 @@
 
 #include <asm/memory.h>
 
+#define PTDESC_ORDER 3
+
 /*
  * Number of page-table levels required to address 'va_bits' wide
  * address, without section mapping. We resolve the top (va_bits - PAGE_SHIFT)
- * bits with (PAGE_SHIFT - 3) bits at each page table level. Hence:
+ * bits with (PAGE_SHIFT - PTDESC_ORDER) bits at each page table level. Hence:
  *
- *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - 3))
+ *  levels = DIV_ROUND_UP((va_bits - PAGE_SHIFT), (PAGE_SHIFT - PTDESC_ORDER))
  *
  * where DIV_ROUND_UP(n, d) => (((n) + (d) - 1) / (d))
  *
  * We cannot include linux/kernel.h which defines DIV_ROUND_UP here
  * due to build issues. So we open code DIV_ROUND_UP here:
  *
- *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - 3) - 1) / (PAGE_SHIFT - 3))
+ *	((((va_bits) - PAGE_SHIFT) + (PAGE_SHIFT - PTDESC_ORDER) - 1) / (PAGE_SHIFT - PTDESC_ORDER))
  *
  * which gets simplified as :
  */
-#define ARM64_HW_PGTABLE_LEVELS(va_bits) (((va_bits) - 4) / (PAGE_SHIFT - 3))
+#define ARM64_HW_PGTABLE_LEVELS(va_bits) \
+	(((va_bits) - PTDESC_ORDER - 1) / (PAGE_SHIFT - PTDESC_ORDER))
 
 /*
  * Size mapped by an entry at level n ( -1 <= n <= 3)
- * We map (PAGE_SHIFT - 3) at all translation levels and PAGE_SHIFT bits
+ * We map (PAGE_SHIFT - PTDESC_ORDER) at all translation levels and PAGE_SHIFT bits
  * in the final page. The maximum number of translation levels supported by
  * the architecture is 5. Hence, starting at level n, we have further
  * ((4 - n) - 1) levels of translation excluding the offset within the page.
  * So, the total number of bits mapped by an entry at level n is :
  *
- *  ((4 - n) - 1) * (PAGE_SHIFT - 3) + PAGE_SHIFT
+ *  ((4 - n) - 1) * (PAGE_SHIFT - PTDESC_ORDER) + PAGE_SHIFT
  *
  * Rearranging it a bit we get :
- *   (4 - n) * (PAGE_SHIFT - 3) + 3
+ *   (4 - n) * (PAGE_SHIFT - PTDESC_ORDER) + PTDESC_ORDER
  */
-#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - 3) * (4 - (n)) + 3)
+#define ARM64_HW_PGTABLE_LEVEL_SHIFT(n)	((PAGE_SHIFT - PTDESC_ORDER) * (4 - (n)) + PTDESC_ORDER)
 
-#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_PTE		(1 << (PAGE_SHIFT - PTDESC_ORDER))
 
 /*
  * PMD_SHIFT determines the size a level 2 page table entry can map.
@@ -49,7 +52,7 @@
 #define PMD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(2)
 #define PMD_SIZE		(_AC(1, UL) << PMD_SHIFT)
 #define PMD_MASK		(~(PMD_SIZE-1))
-#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_PMD		(1 << (PAGE_SHIFT - PTDESC_ORDER))
 #endif
 
 /*
@@ -59,14 +62,14 @@
 #define PUD_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(1)
 #define PUD_SIZE		(_AC(1, UL) << PUD_SHIFT)
 #define PUD_MASK		(~(PUD_SIZE-1))
-#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_PUD		(1 << (PAGE_SHIFT - PTDESC_ORDER))
 #endif
 
 #if CONFIG_PGTABLE_LEVELS > 4
 #define P4D_SHIFT		ARM64_HW_PGTABLE_LEVEL_SHIFT(0)
 #define P4D_SIZE		(_AC(1, UL) << P4D_SHIFT)
 #define P4D_MASK		(~(P4D_SIZE-1))
-#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - 3))
+#define PTRS_PER_P4D		(1 << (PAGE_SHIFT - PTDESC_ORDER))
 #endif
 
 /*
diff --git a/arch/arm64/kernel/pi/map_range.c b/arch/arm64/kernel/pi/map_range.c
index 2b69e3beeef8..f74335e13929 100644
--- a/arch/arm64/kernel/pi/map_range.c
+++ b/arch/arm64/kernel/pi/map_range.c
@@ -31,7 +31,7 @@ void __init map_range(u64 *pte, u64 start, u64 end, u64 pa, pgprot_t prot,
 {
 	u64 cmask = (level == 3) ? CONT_PTE_SIZE - 1 : U64_MAX;
 	pteval_t protval = pgprot_val(prot) & ~PTE_TYPE_MASK;
-	int lshift = (3 - level) * (PAGE_SHIFT - 3);
+	int lshift = (3 - level) * (PAGE_SHIFT - PTDESC_ORDER);
 	u64 lmask = (PAGE_SIZE << lshift) - 1;
 
 	start	&= PAGE_MASK;
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index b65a29440a0c..211821f80571 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -190,7 +190,7 @@ static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
  */
 static bool __init root_level_aligned(u64 addr)
 {
-	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - 3);
+	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 1) * (PAGE_SHIFT - PTDESC_ORDER);
 
 	return (addr % (PAGE_SIZE << shift)) == 0;
 }
@@ -245,7 +245,7 @@ static int __init root_level_idx(u64 addr)
 	 */
 	u64 vabits = IS_ENABLED(CONFIG_ARM64_64K_PAGES) ? VA_BITS
 							: vabits_actual;
-	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - 3);
+	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits) - 1) * (PAGE_SHIFT - PTDESC_ORDER);
 
 	return (addr & ~_PAGE_OFFSET(vabits)) >> (shift + PAGE_SHIFT);
 }
@@ -269,7 +269,7 @@ static void __init clone_next_level(u64 addr, pgd_t *tmp_pg_dir, pud_t *pud)
  */
 static int __init next_level_idx(u64 addr)
 {
-	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - 3);
+	int shift = (ARM64_HW_PGTABLE_LEVELS(vabits_actual) - 2) * (PAGE_SHIFT - PTDESC_ORDER);
 
 	return (addr >> (shift + PAGE_SHIFT)) % PTRS_PER_PTE;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250310040115.91298-1-anshuman.khandual%40arm.com.
