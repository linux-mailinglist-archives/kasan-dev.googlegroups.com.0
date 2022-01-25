Return-Path: <kasan-dev+bncBAABBL6YYCHQMGQER4AYSWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id F3DE349B963
	for <lists+kasan-dev@lfdr.de>; Tue, 25 Jan 2022 17:58:23 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id a11-20020adffb8b000000b001a0b0f4afe9sf3326023wrr.13
        for <lists+kasan-dev@lfdr.de>; Tue, 25 Jan 2022 08:58:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643129903; cv=pass;
        d=google.com; s=arc-20160816;
        b=gKRiynA5WBVVjlIoZY3bgvA7PkU9mcsm2hjufZZbzq+quQzP5pBBzK9ezZ5fiuc7hT
         CH0mH45Visqfnm0e0bnFZie+J7W3DiDNntWaTNWCFYjyfYQwtDEwVK/BuqDRb3QiZr++
         VMUBzx5SysNiw/S+kTfWqFOKmqrCb/1uKBtfbh49/0Mp8zu9H9GGPRSi3vCn/nTsoZTP
         a5/0kP5ThL6TcC5rF7/RrORR6RcqWPDNmQcyLHfpDHyWqgZoShHnIYmLOwarvKVz3+Jc
         UHPbPD7nH0Mq0DSPPXFpY888ktyDSs+LMZGNRpUx1nxSYqj5mUSJ3F4BbcwMQqy+MzWu
         AA9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=esNPwAB6dZC0KVtIWhT4El8Qmu2+xdXVDdQx2YTJMBI=;
        b=UXbug/za0OBbk5zaYGSDWRzT8Oi7dR0HoWTSOdwEkoT3vaP2GD18squjR0jKilsiEM
         l31RUTPECnuK4dr11KJEgb2hotBqT2qcey5Tj1lc01EBc4NDtaldooyVPCSTNAVI2Hs+
         +AXLlwk3uVRhZbksaIEikta0s8SRYF6BIvkpFPw/0m+TfKdfE0QXs3qEbGqSyX8khQxs
         +Q79GiryyxHqyP3pp4tIcAS5PRnXivrffGYJpSTKhBKXJTIvZUizMvyAzDnO2sfC3Llf
         laD2a459HtKbC4e8IUBKKLXBeOZNrTWyCo5+YlyQNu2Wm2iTfnhI6E/8gPusHSQcZqQ7
         PTbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H2CXBtZx;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=esNPwAB6dZC0KVtIWhT4El8Qmu2+xdXVDdQx2YTJMBI=;
        b=Ydf7eqzTXhhDHB6Teod62QtKrQH52Vf/Br8dPB2CckTvXgK6WYzfFx6Tgpb8ug78c0
         2TKIP2i8QRV4djjbWWkVxDK2swYhGKytS6A7ov67Gv2ONueHgIBkPCQi5L1xjovJUHIO
         OMBKgC4BGbwrMOurOtruaWFAYmPH23M4xCnnH07OV5z7wu2x+FJnQUHnj3QWpYYyxgRo
         83rALfpL0E0GsVi3hCkgCq2e0rUBdYEFNFj6SWmBZ+fDjfBAidRf/vAVaU65Cx9V/weH
         TCmXwkhV4V0yGOQWiwzMvrTOKe03iq/zhN5vIQXI6/oz1LRogchF6jPlZHTyT/VGv1gh
         QVYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=esNPwAB6dZC0KVtIWhT4El8Qmu2+xdXVDdQx2YTJMBI=;
        b=QWf0s7JnOAsjslXJkvf6P/RIWeYIXYO66KzbL8SmXsOE549SmGqGm3/d81GKpWWPcJ
         qUvmN8gawgRcq75QtjcPlTAxbCKt7gAxCTx2gw8rc5hTf4zv1GG1JyB0iTNtQTbczuZX
         u64nJLSmN937UXq1o4QCwEG4Ja8zS7kcO5oCvJ6GcCcLTOVzDWUrrlb4hbO+y2QCMI4b
         a1TdgeOGP2sDKVq93WQNeAvDDVYFnUvjWN7SeSS+JZ78v5PdXwyrE+Fod+yTwwKfUKtY
         SrfMslnhZv4E8pl6x8Wjznce3mvIUwya9AEaehbKrNB2vqiPG/fcp1mpg6x62Q7dFPlf
         pJNw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531aLWMuCtuWZaXs4xR4v1ANDPqfNJPwX5SotAB7dFeMzJPnoX+U
	6ULWp+B8o+Otkx3QtMX6reg=
X-Google-Smtp-Source: ABdhPJwPgR3jiBDkpVWumXDbF9s9Qu+sQ6ubtNueQeaPhfZQDC3CeWwVYjef5dCjHLhqvs9ziJyujA==
X-Received: by 2002:adf:a159:: with SMTP id r25mr19235909wrr.204.1643129903663;
        Tue, 25 Jan 2022 08:58:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f04f:: with SMTP id t15ls52310wro.1.gmail; Tue, 25 Jan
 2022 08:58:23 -0800 (PST)
X-Received: by 2002:a05:6000:2c7:: with SMTP id o7mr3913716wry.621.1643129902973;
        Tue, 25 Jan 2022 08:58:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643129902; cv=none;
        d=google.com; s=arc-20160816;
        b=xFwBjhQjiw33gXm6h/gEgQ9Zr+JbwvQqZggYd/aIRMxp1ittXF0WFJf9HzQ2QhoF1X
         Vr1bYwmizs+isLx0I12d8cqys0AVUKRqY/Oaqci8JSSXnq1xlI79V2e6xTb2dvoYlwgo
         Q+Y12sOFlOuF8Bi0GGd4TSTJ4KDPPmyaB7XjN5uyYWFsj82TWN5E38D4Ozl+MfAWkSFX
         YSs2PFuzqhY4Jxf9ej+rHr5A/jEiAFgi2sP04/NL16hVC+kM9PzP4XIYptIeoU8yBtEt
         cKqSX9hBg3VzSHWlOP4JoGyUUM62qAq8pH7YJOlSlUPodbY7+RG9bUjy8DVVUFRtbMwq
         VEfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zANbQJ7VZ+su24P4cK47hXzZgKvUxgI3/B1NRm/BvoQ=;
        b=qgVvpg63Pj676S+BJTiJi2kD5ZcukmSfDcyudmeLvK6of1KJScX3kCKor2JyppMgYW
         DYAMXUMQ6kZDKiGSw4BLmUGr60uW0mjrWx4sPvyD+vsR+n2nCLMfOWcxUpKQUZnV/251
         MY2i0/ZqnbMSuTVj7WHGoQsM9btmCHcAcMXW7YwIrezUmWXxeQx4QpdQmErCVS2D/DwD
         f+SVJJ2DdvbCra9n2fKhfhxqjTNLOunNrfUFOshEiIYgeqLmGb9CILCSfCn6IZqk+shH
         cC8eaY5fbi13LQd1cs4BKUBzb9WZhyKuK+Bqao0W6RqnpgKDIIX62UyPzSXA5QSapwtq
         5KXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=H2CXBtZx;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id p6si596291wrx.3.2022.01.25.08.58.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 25 Jan 2022 08:58:22 -0800 (PST)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 7D9C7B81912;
	Tue, 25 Jan 2022 16:58:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7B036C340E0;
	Tue, 25 Jan 2022 16:58:18 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH 3/3] riscv: convert pgtable_l4_enabled to static key
Date: Wed, 26 Jan 2022 00:50:36 +0800
Message-Id: <20220125165036.987-4-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220125165036.987-1-jszhang@kernel.org>
References: <20220125165036.987-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=H2CXBtZx;       spf=pass
 (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as
 permitted sender) smtp.mailfrom=jszhang@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

On a specific HW platform, pgtable_l4_enabled won't change after
boot, and the check sits at hot code path, this characteristic make it
suitable for optimization with static key.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/include/asm/cpufeature.h |  6 ++++++
 arch/riscv/include/asm/pgalloc.h    |  8 ++++----
 arch/riscv/include/asm/pgtable-64.h | 21 ++++++++++-----------
 arch/riscv/include/asm/pgtable.h    |  3 +--
 arch/riscv/kernel/cpu.c             |  2 +-
 arch/riscv/mm/init.c                | 23 ++++++++++-------------
 arch/riscv/mm/kasan_init.c          |  6 +++---
 arch/riscv/tools/cpucaps            |  1 +
 8 files changed, 36 insertions(+), 34 deletions(-)

diff --git a/arch/riscv/include/asm/cpufeature.h b/arch/riscv/include/asm/cpufeature.h
index 634a653c7fa2..10af83d6fb2a 100644
--- a/arch/riscv/include/asm/cpufeature.h
+++ b/arch/riscv/include/asm/cpufeature.h
@@ -96,4 +96,10 @@ static inline bool system_supports_fpu(void)
 	return IS_ENABLED(CONFIG_FPU) && !cpus_have_final_cap(RISCV_HAS_NO_FPU);
 }
 
+static inline bool system_supports_sv48(void)
+{
+	return IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL) &&
+		!cpus_have_const_cap(RISCV_HAS_NO_SV48);
+}
+
 #endif
diff --git a/arch/riscv/include/asm/pgalloc.h b/arch/riscv/include/asm/pgalloc.h
index 11823004b87a..cd37f3777ff1 100644
--- a/arch/riscv/include/asm/pgalloc.h
+++ b/arch/riscv/include/asm/pgalloc.h
@@ -41,7 +41,7 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
 
 static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
 {
-	if (pgtable_l4_enabled) {
+	if (system_supports_sv48()) {
 		unsigned long pfn = virt_to_pfn(pud);
 
 		set_p4d(p4d, __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
@@ -51,7 +51,7 @@ static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
 static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
 				     pud_t *pud)
 {
-	if (pgtable_l4_enabled) {
+	if (system_supports_sv48()) {
 		unsigned long pfn = virt_to_pfn(pud);
 
 		set_p4d_safe(p4d,
@@ -62,7 +62,7 @@ static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
 #define pud_alloc_one pud_alloc_one
 static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		return __pud_alloc_one(mm, addr);
 
 	return NULL;
@@ -71,7 +71,7 @@ static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
 #define pud_free pud_free
 static inline void pud_free(struct mm_struct *mm, pud_t *pud)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		__pud_free(mm, pud);
 }
 
diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
index bbbdd66e5e2f..5ad4311f9c6e 100644
--- a/arch/riscv/include/asm/pgtable-64.h
+++ b/arch/riscv/include/asm/pgtable-64.h
@@ -7,14 +7,13 @@
 #define _ASM_RISCV_PGTABLE_64_H
 
 #include <linux/const.h>
-
-extern bool pgtable_l4_enabled;
+#include <asm/cpufeature.h>
 
 #define PGDIR_SHIFT_L3  30
 #define PGDIR_SHIFT_L4  39
 #define PGDIR_SIZE_L3   (_AC(1, UL) << PGDIR_SHIFT_L3)
 
-#define PGDIR_SHIFT     (pgtable_l4_enabled ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3)
+#define PGDIR_SHIFT     (system_supports_sv48() ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3)
 /* Size of region mapped by a page global directory */
 #define PGDIR_SIZE      (_AC(1, UL) << PGDIR_SHIFT)
 #define PGDIR_MASK      (~(PGDIR_SIZE - 1))
@@ -102,7 +101,7 @@ static inline struct page *pud_page(pud_t pud)
 #define mm_pud_folded  mm_pud_folded
 static inline bool mm_pud_folded(struct mm_struct *mm)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		return false;
 
 	return true;
@@ -130,7 +129,7 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
 
 static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		*p4dp = p4d;
 	else
 		set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
@@ -138,7 +137,7 @@ static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
 
 static inline int p4d_none(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		return (p4d_val(p4d) == 0);
 
 	return 0;
@@ -146,7 +145,7 @@ static inline int p4d_none(p4d_t p4d)
 
 static inline int p4d_present(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		return (p4d_val(p4d) & _PAGE_PRESENT);
 
 	return 1;
@@ -154,7 +153,7 @@ static inline int p4d_present(p4d_t p4d)
 
 static inline int p4d_bad(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		return !p4d_present(p4d);
 
 	return 0;
@@ -162,13 +161,13 @@ static inline int p4d_bad(p4d_t p4d)
 
 static inline void p4d_clear(p4d_t *p4d)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		set_p4d(p4d, __p4d(0));
 }
 
 static inline pud_t *p4d_pgtable(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		return (pud_t *)pfn_to_virt(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
 
 	return (pud_t *)pud_pgtable((pud_t) { p4d_val(p4d) });
@@ -184,7 +183,7 @@ static inline struct page *p4d_page(p4d_t p4d)
 #define pud_offset pud_offset
 static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
 {
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		return p4d_pgtable(*p4d) + pud_index(address);
 
 	return (pud_t *)p4d;
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 7e949f25c933..40d999950e5b 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -62,7 +62,7 @@
  * position vmemmap directly below the VMALLOC region.
  */
 #ifdef CONFIG_64BIT
-#define VA_BITS		(pgtable_l4_enabled ? 48 : 39)
+#define VA_BITS		(system_supports_sv48() ? 48 : 39)
 #else
 #define VA_BITS		32
 #endif
@@ -735,7 +735,6 @@ extern uintptr_t _dtb_early_pa;
 #define dtb_early_pa	_dtb_early_pa
 #endif /* CONFIG_XIP_KERNEL */
 extern u64 satp_mode;
-extern bool pgtable_l4_enabled;
 
 void paging_init(void);
 void misc_mem_init(void);
diff --git a/arch/riscv/kernel/cpu.c b/arch/riscv/kernel/cpu.c
index ad0a7e9f828b..ce38319232ec 100644
--- a/arch/riscv/kernel/cpu.c
+++ b/arch/riscv/kernel/cpu.c
@@ -79,7 +79,7 @@ static void print_mmu(struct seq_file *f)
 #if defined(CONFIG_32BIT)
 	strncpy(sv_type, "sv32", 5);
 #elif defined(CONFIG_64BIT)
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		strncpy(sv_type, "sv48", 5);
 	else
 		strncpy(sv_type, "sv39", 5);
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 35586688a1b6..8a84606f99f0 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -44,9 +44,6 @@ u64 satp_mode __ro_after_init = SATP_MODE_32;
 #endif
 EXPORT_SYMBOL(satp_mode);
 
-bool pgtable_l4_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
-EXPORT_SYMBOL(pgtable_l4_enabled);
-
 phys_addr_t phys_ram_base __ro_after_init;
 EXPORT_SYMBOL(phys_ram_base);
 
@@ -459,19 +456,19 @@ static void __init create_pud_mapping(pud_t *pudp,
 }
 
 #define pgd_next_t		pud_t
-#define alloc_pgd_next(__va)	(pgtable_l4_enabled ?			\
+#define alloc_pgd_next(__va)	(system_supports_sv48() ?			\
 		pt_ops.alloc_pud(__va) : pt_ops.alloc_pmd(__va))
-#define get_pgd_next_virt(__pa)	(pgtable_l4_enabled ?			\
+#define get_pgd_next_virt(__pa)	(system_supports_sv48() ?			\
 		pt_ops.get_pud_virt(__pa) : (pgd_next_t *)pt_ops.get_pmd_virt(__pa))
 #define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot)	\
-				(pgtable_l4_enabled ?			\
+				(system_supports_sv48() ?			\
 		create_pud_mapping(__nextp, __va, __pa, __sz, __prot) :	\
 		create_pmd_mapping((pmd_t *)__nextp, __va, __pa, __sz, __prot))
-#define fixmap_pgd_next		(pgtable_l4_enabled ?			\
+#define fixmap_pgd_next		(system_supports_sv48() ?			\
 		(uintptr_t)fixmap_pud : (uintptr_t)fixmap_pmd)
-#define trampoline_pgd_next	(pgtable_l4_enabled ?			\
+#define trampoline_pgd_next	(system_supports_sv48() ?			\
 		(uintptr_t)trampoline_pud : (uintptr_t)trampoline_pmd)
-#define early_dtb_pgd_next	(pgtable_l4_enabled ?			\
+#define early_dtb_pgd_next	(system_supports_sv48() ?			\
 		(uintptr_t)early_dtb_pud : (uintptr_t)early_dtb_pmd)
 #else
 #define pgd_next_t		pte_t
@@ -575,7 +572,7 @@ static __init pgprot_t pgprot_from_va(uintptr_t va)
 #ifdef CONFIG_64BIT
 static void __init disable_pgtable_l4(void)
 {
-	pgtable_l4_enabled = false;
+	cpus_set_cap(RISCV_HAS_NO_SV48);
 	kernel_map.page_offset = PAGE_OFFSET_L3;
 	satp_mode = SATP_MODE_39;
 }
@@ -691,7 +688,7 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
 			   PGDIR_SIZE,
 			   IS_ENABLED(CONFIG_64BIT) ? PAGE_TABLE : PAGE_KERNEL);
 
-	if (pgtable_l4_enabled) {
+	if (system_supports_sv48()) {
 		create_pud_mapping(early_dtb_pud, DTB_EARLY_BASE_VA,
 				   (uintptr_t)early_dtb_pmd, PUD_SIZE, PAGE_TABLE);
 	}
@@ -819,7 +816,7 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 
 #ifndef __PAGETABLE_PMD_FOLDED
 	/* Setup fixmap PUD and PMD */
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		create_pud_mapping(fixmap_pud, FIXADDR_START,
 				   (uintptr_t)fixmap_pmd, PUD_SIZE, PAGE_TABLE);
 	create_pmd_mapping(fixmap_pmd, FIXADDR_START,
@@ -827,7 +824,7 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 	/* Setup trampoline PGD and PMD */
 	create_pgd_mapping(trampoline_pg_dir, kernel_map.virt_addr,
 			   trampoline_pgd_next, PGDIR_SIZE, PAGE_TABLE);
-	if (pgtable_l4_enabled)
+	if (system_supports_sv48())
 		create_pud_mapping(trampoline_pud, kernel_map.virt_addr,
 				   (uintptr_t)trampoline_pmd, PUD_SIZE, PAGE_TABLE);
 #ifdef CONFIG_XIP_KERNEL
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index f61f7ca6fe0f..3d456c5b55c8 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -149,11 +149,11 @@ static void __init kasan_populate_pud(pgd_t *pgd,
 		set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_pud)), PAGE_TABLE));
 }
 
-#define kasan_early_shadow_pgd_next			(pgtable_l4_enabled ?	\
+#define kasan_early_shadow_pgd_next		(system_supports_sv48() ?	\
 				(uintptr_t)kasan_early_shadow_pud :		\
 				(uintptr_t)kasan_early_shadow_pmd)
 #define kasan_populate_pgd_next(pgdp, vaddr, next, early)			\
-		(pgtable_l4_enabled ?						\
+		(system_supports_sv48() ?					\
 			kasan_populate_pud(pgdp, vaddr, next, early) :		\
 			kasan_populate_pmd((pud_t *)pgdp, vaddr, next))
 
@@ -211,7 +211,7 @@ asmlinkage void __init kasan_early_init(void)
 				(__pa((uintptr_t)kasan_early_shadow_pte)),
 				PAGE_TABLE));
 
-	if (pgtable_l4_enabled) {
+	if (system_supports_sv48()) {
 		for (i = 0; i < PTRS_PER_PUD; ++i)
 			set_pud(kasan_early_shadow_pud + i,
 				pfn_pud(PFN_DOWN
diff --git a/arch/riscv/tools/cpucaps b/arch/riscv/tools/cpucaps
index cb1ff2747859..1aea959f225d 100644
--- a/arch/riscv/tools/cpucaps
+++ b/arch/riscv/tools/cpucaps
@@ -3,3 +3,4 @@
 # Internal CPU capabilities constants, keep this list sorted
 
 HAS_NO_FPU
+HAS_NO_SV48
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220125165036.987-4-jszhang%40kernel.org.
