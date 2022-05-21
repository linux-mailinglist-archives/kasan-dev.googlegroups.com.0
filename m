Return-Path: <kasan-dev+bncBAABBKHVUOKAMGQEVV75WMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 14C4B52FD6F
	for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 16:43:53 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id bq17-20020a056512151100b0047867d569d8sf174271lfb.12
        for <lists+kasan-dev@lfdr.de>; Sat, 21 May 2022 07:43:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1653144232; cv=pass;
        d=google.com; s=arc-20160816;
        b=yJibKW3T0VpVzWosBfJ7nTAMWkOaj97bFt7tLIwg6QHgt1FNmwBakeNBI2mh8fXBpE
         etR6srznA3AhMBKUFJGxxbimuYDc6A2NhLMNSSQdmIPX11cwFp6J7EEhC7VfRwiAZOQ4
         jyaTTUrM9WCKwAOfXnCUII8nKAQSw9bL7W+w4FCHQV4zqzWZDUFCTIr0/WwaSoOa4Jr9
         khd/wQyawqmJdfaYRwK2Vw0XhiKFBnfGHcOxeREHOfP9uI/fKxIVFZNAykLWEOiBDNAi
         nwqXfOKARVqAyl+l+OwQj4qFvTsu+WQbccR1ULRLZ3oUJscmpsCOe0YpAax41QVr0OSr
         Ve8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=tA6erS3hCoPqizJAl06Xlyzv3aKV2J4G4ytLBKxtTVk=;
        b=hbUkDKQigBpgldju3ltyDJwkIPYppuzRL2cMwkoHvOoT1Qscj0xGb1ow1u6N87+/bf
         JClEAActrQYdqnrz3AwTzKd8qPC591mkIi/ZR1PEmwj0QEYXlhSiDgtfAZKGLHRpao46
         FyK/pcj8yqMfr6JAL7WOQoT+J5ujjpHUM7Rls1NR8cmbkNlXAqDLS5IOuT+JPloZlYza
         69niHlqcTHAVUUYP8fEKcVyP9EpvXVsr5Pn0AzUGLBtHNtkw0hii5ZBQ12cglPr5lIln
         euU0ZJ+h/ZWNh8VJUJAVVtlPVPt/3O4uQaXiWjhcMpDe29H7affWMkwzudOH8jVKqKyN
         TLxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sSGkZ0uR;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tA6erS3hCoPqizJAl06Xlyzv3aKV2J4G4ytLBKxtTVk=;
        b=BFsbxofipN5uwSrCIEUgz+dBZeS/MzO0gZNUJB3/EZmvgUb/jwVoUCYxYDkT4rzhLB
         JKIUzFCLpi5+tVMVqtCvOxn/jUKFyHvC2y6j4EjgnEeIW81EO/uha9fVqYb/nSlt+AZv
         VGd62yy+g5W7UmCLAB+0AMpaUbejY+GOTbwQ5GErYg+me74kC+GN2j5wprgEXrgG9iri
         cDasX3g37bmUkLV0HeY2JeP17g/+oSbRSUVmzajb7lbCG1epP8apXqNlMxNkbANc24wI
         vUX8lxClpCptEM7e2ySnx9QWM/HijeNIFydEEkHm0nK6Bf/O2hAhueLGDJzGbkSslP2Q
         HJvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tA6erS3hCoPqizJAl06Xlyzv3aKV2J4G4ytLBKxtTVk=;
        b=gLGX+UTsT1ouf3VcvgSQDGxtAIfCmaOSi913tk6VPHzZmMgAqvGy9rtIwH20EVgWuc
         MCzsdBmhmd2M+cTd70qsSE7Yc3XuJM1PSdTpCZp8SQDpSWyOLdXsANi93BDhIW+p6Cml
         nWFWPKNH5NASo+CD+TPYz9dT9d+KsdWYe4gQVB8K+Dfdvgj4Iby2pMNm6aHaTkYHPJZW
         TsgSlHSHUm5szBK/JOqqIjv9qwZ92Ss0eDgV84tzBmWSvip2N9D4bLo+qSgrBm7aUc91
         QlwV7M2cbpXY/ACg0wmWXa2RHVVkxfiGYt0ED2M6T4JXwIVUPjVi6TKfx3ngYq3d1R/Q
         GDsQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328ULQ4/YVJ0t8gETpsnDqmB6kkdW0TXuPq+kN/Zd0fpPrsS0uI
	J5x7bmrnG26eWa9Tiok5wek=
X-Google-Smtp-Source: ABdhPJztTPTTyMdxFxQ/4oPEu2B579OvTNd9NjNaDtsTR1WTb3nNkPLRmGeS6/+vVAzXKrlMaAKldA==
X-Received: by 2002:a05:6512:104a:b0:473:d38b:cdf with SMTP id c10-20020a056512104a00b00473d38b0cdfmr10840960lfb.554.1653144232511;
        Sat, 21 May 2022 07:43:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1693:b0:448:3742:2320 with SMTP id
 bu19-20020a056512169300b0044837422320ls3580309lfb.1.gmail; Sat, 21 May 2022
 07:43:51 -0700 (PDT)
X-Received: by 2002:a05:6512:22d4:b0:477:be45:3667 with SMTP id g20-20020a05651222d400b00477be453667mr10593121lfu.659.1653144231590;
        Sat, 21 May 2022 07:43:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1653144231; cv=none;
        d=google.com; s=arc-20160816;
        b=pH/EdBr9JCGQtBHcqmtnf9iShPeoKUaqFXKWbKIr8k9hhNMeqhD7hJEa94ozNykdL1
         inU9PJGb/Khe9rpDeeE3fNHYv9D2je6oeqeGbPrM7RlDxUrVfhkLdi8nqju7X5OVjMvZ
         43zWDpQ+Ap3FFwtKsctC3g3U7QV4aD6Z1tSq3xDl8V/iwasjj9DYkWIaZ2gT8WNm92iP
         AbHSxnzUNkeiLdYte5KnTDnt0fN2CdrbDjW/M5Nx+pDsAy05Hqgvmk+rpiwaiUE9Vc7S
         WVz+avfJ5MT4ErWRIqSvcMkkpsHB0jyIGpqRPUYj5O7Wku8bLxr9J420h65lGoK2EBQz
         5tEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FkxSMoK0aEYVGqUQnurxmyolFzsDfI3IUEMUEw5al5Y=;
        b=AHhzSCnlkELaOnoqx6C3gnt2ZhxMCfiTTKG13lCDhtRGPqc/5UCuo3tp4rfhkMUbiN
         gHHhUyB1B9JClNJVSzdyjZmLC1eE9QYzJs9rEb2eKQ+MGOS7tr3oGLk3dcEWRVr9c7hL
         ms8O5nnFqVrZs81+KcoI6cVKqnvn3BczFK+Wo+ges9N+TS4qeKt3LA2AhdOu8JTUNJ8T
         xRs/FdwtkGHSZiwq77JP33SDv+a0N+WsfOJ4mmuRxPGGt2myhXenXqFNnyT1M7Z+i1Nl
         1IHILkOdYqVRcy0iFyY+NmZjuynHee3KL+8tMVfK3dp0Wfcc3X7JTamGQIYu6oTLq08N
         Wjyg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sSGkZ0uR;
       spf=pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id k38-20020a0565123da600b0047866dddb47si21203lfv.2.2022.05.21.07.43.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 21 May 2022 07:43:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id C1FC8B80687;
	Sat, 21 May 2022 14:43:50 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8880DC385AA;
	Sat, 21 May 2022 14:43:43 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>,
	Anup Patel <anup@brainfault.org>,
	Atish Patra <atishp@rivosinc.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: [PATCH v4 2/2] riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
Date: Sat, 21 May 2022 22:34:56 +0800
Message-Id: <20220521143456.2759-3-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220521143456.2759-1-jszhang@kernel.org>
References: <20220521143456.2759-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sSGkZ0uR;       spf=pass
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

On a specific HW platform, pgtable_l4|[l5]_enabled won't change after
boot, and the check sits at hot code path, this characteristic makes it
suitable for optimization with static key.

_pgtable_l4|[l5]_enabled is used very early during boot, even is used
with MMU off, so the static key mechanism isn't ready. For this case,
we use another static key _pgtable_lx_ready to indicate whether we
have finalised pgtable_l4|[l5]_enabled or not, then fall back to
_pgtable_l4|[l5]_enabled_early bool.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/include/asm/pgalloc.h    | 16 ++++----
 arch/riscv/include/asm/pgtable-32.h |  3 ++
 arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
 arch/riscv/include/asm/pgtable.h    |  5 +--
 arch/riscv/kernel/cpu.c             |  4 +-
 arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
 arch/riscv/mm/kasan_init.c          | 16 ++++----
 7 files changed, 103 insertions(+), 65 deletions(-)

diff --git a/arch/riscv/include/asm/pgalloc.h b/arch/riscv/include/asm/pgalloc.h
index 947f23d7b6af..0280eeb4756f 100644
--- a/arch/riscv/include/asm/pgalloc.h
+++ b/arch/riscv/include/asm/pgalloc.h
@@ -41,7 +41,7 @@ static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
 
 static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
 {
-	if (pgtable_l4_enabled) {
+	if (pgtable_l4_enabled()) {
 		unsigned long pfn = virt_to_pfn(pud);
 
 		set_p4d(p4d, __p4d((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
@@ -51,7 +51,7 @@ static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
 static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
 				     pud_t *pud)
 {
-	if (pgtable_l4_enabled) {
+	if (pgtable_l4_enabled()) {
 		unsigned long pfn = virt_to_pfn(pud);
 
 		set_p4d_safe(p4d,
@@ -61,7 +61,7 @@ static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d,
 
 static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
 {
-	if (pgtable_l5_enabled) {
+	if (pgtable_l5_enabled()) {
 		unsigned long pfn = virt_to_pfn(p4d);
 
 		set_pgd(pgd, __pgd((pfn << _PAGE_PFN_SHIFT) | _PAGE_TABLE));
@@ -71,7 +71,7 @@ static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
 static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd,
 				     p4d_t *p4d)
 {
-	if (pgtable_l5_enabled) {
+	if (pgtable_l5_enabled()) {
 		unsigned long pfn = virt_to_pfn(p4d);
 
 		set_pgd_safe(pgd,
@@ -82,7 +82,7 @@ static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd,
 #define pud_alloc_one pud_alloc_one
 static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return __pud_alloc_one(mm, addr);
 
 	return NULL;
@@ -91,7 +91,7 @@ static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
 #define pud_free pud_free
 static inline void pud_free(struct mm_struct *mm, pud_t *pud)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		__pud_free(mm, pud);
 }
 
@@ -100,7 +100,7 @@ static inline void pud_free(struct mm_struct *mm, pud_t *pud)
 #define p4d_alloc_one p4d_alloc_one
 static inline p4d_t *p4d_alloc_one(struct mm_struct *mm, unsigned long addr)
 {
-	if (pgtable_l5_enabled) {
+	if (pgtable_l5_enabled()) {
 		gfp_t gfp = GFP_PGTABLE_USER;
 
 		if (mm == &init_mm)
@@ -120,7 +120,7 @@ static inline void __p4d_free(struct mm_struct *mm, p4d_t *p4d)
 #define p4d_free p4d_free
 static inline void p4d_free(struct mm_struct *mm, p4d_t *p4d)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		__p4d_free(mm, p4d);
 }
 
diff --git a/arch/riscv/include/asm/pgtable-32.h b/arch/riscv/include/asm/pgtable-32.h
index 5b2e79e5bfa5..8af36d76b70d 100644
--- a/arch/riscv/include/asm/pgtable-32.h
+++ b/arch/riscv/include/asm/pgtable-32.h
@@ -16,4 +16,7 @@
 
 #define MAX_POSSIBLE_PHYSMEM_BITS 34
 
+#define pgtable_l5_enabled() 0
+#define pgtable_l4_enabled() 0
+
 #endif /* _ASM_RISCV_PGTABLE_32_H */
diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
index 7e246e9f8d70..d14a3a8f1f4b 100644
--- a/arch/riscv/include/asm/pgtable-64.h
+++ b/arch/riscv/include/asm/pgtable-64.h
@@ -7,17 +7,37 @@
 #define _ASM_RISCV_PGTABLE_64_H
 
 #include <linux/const.h>
+#include <linux/jump_label.h>
 
-extern bool pgtable_l4_enabled;
-extern bool pgtable_l5_enabled;
+extern bool _pgtable_l5_enabled_early;
+extern bool _pgtable_l4_enabled_early;
+extern struct static_key_false _pgtable_l5_enabled;
+extern struct static_key_false _pgtable_l4_enabled;
+extern struct static_key_false _pgtable_lx_ready;
+
+static __always_inline bool pgtable_l5_enabled(void)
+{
+	if (static_branch_likely(&_pgtable_lx_ready))
+		return static_branch_likely(&_pgtable_l5_enabled);
+	else
+		return _pgtable_l5_enabled_early;
+}
+
+static __always_inline bool pgtable_l4_enabled(void)
+{
+	if (static_branch_likely(&_pgtable_lx_ready))
+		return static_branch_likely(&_pgtable_l4_enabled);
+	else
+		return _pgtable_l4_enabled_early;
+}
 
 #define PGDIR_SHIFT_L3  30
 #define PGDIR_SHIFT_L4  39
 #define PGDIR_SHIFT_L5  48
 #define PGDIR_SIZE_L3   (_AC(1, UL) << PGDIR_SHIFT_L3)
 
-#define PGDIR_SHIFT     (pgtable_l5_enabled ? PGDIR_SHIFT_L5 : \
-		(pgtable_l4_enabled ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3))
+#define PGDIR_SHIFT     (pgtable_l5_enabled() ? PGDIR_SHIFT_L5 : \
+		(pgtable_l4_enabled() ? PGDIR_SHIFT_L4 : PGDIR_SHIFT_L3))
 /* Size of region mapped by a page global directory */
 #define PGDIR_SIZE      (_AC(1, UL) << PGDIR_SHIFT)
 #define PGDIR_MASK      (~(PGDIR_SIZE - 1))
@@ -119,7 +139,7 @@ static inline struct page *pud_page(pud_t pud)
 #define mm_p4d_folded  mm_p4d_folded
 static inline bool mm_p4d_folded(struct mm_struct *mm)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return false;
 
 	return true;
@@ -128,7 +148,7 @@ static inline bool mm_p4d_folded(struct mm_struct *mm)
 #define mm_pud_folded  mm_pud_folded
 static inline bool mm_pud_folded(struct mm_struct *mm)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return false;
 
 	return true;
@@ -159,7 +179,7 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
 
 static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		*p4dp = p4d;
 	else
 		set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
@@ -167,7 +187,7 @@ static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
 
 static inline int p4d_none(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return (p4d_val(p4d) == 0);
 
 	return 0;
@@ -175,7 +195,7 @@ static inline int p4d_none(p4d_t p4d)
 
 static inline int p4d_present(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return (p4d_val(p4d) & _PAGE_PRESENT);
 
 	return 1;
@@ -183,7 +203,7 @@ static inline int p4d_present(p4d_t p4d)
 
 static inline int p4d_bad(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return !p4d_present(p4d);
 
 	return 0;
@@ -191,7 +211,7 @@ static inline int p4d_bad(p4d_t p4d)
 
 static inline void p4d_clear(p4d_t *p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		set_p4d(p4d, __p4d(0));
 }
 
@@ -207,7 +227,7 @@ static inline unsigned long _p4d_pfn(p4d_t p4d)
 
 static inline pud_t *p4d_pgtable(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return (pud_t *)pfn_to_virt(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
 
 	return (pud_t *)pud_pgtable((pud_t) { p4d_val(p4d) });
@@ -224,7 +244,7 @@ static inline struct page *p4d_page(p4d_t p4d)
 #define pud_offset pud_offset
 static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return p4d_pgtable(*p4d) + pud_index(address);
 
 	return (pud_t *)p4d;
@@ -232,7 +252,7 @@ static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
 
 static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		*pgdp = pgd;
 	else
 		set_p4d((p4d_t *)pgdp, (p4d_t){ pgd_val(pgd) });
@@ -240,7 +260,7 @@ static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
 
 static inline int pgd_none(pgd_t pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return (pgd_val(pgd) == 0);
 
 	return 0;
@@ -248,7 +268,7 @@ static inline int pgd_none(pgd_t pgd)
 
 static inline int pgd_present(pgd_t pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return (pgd_val(pgd) & _PAGE_PRESENT);
 
 	return 1;
@@ -256,7 +276,7 @@ static inline int pgd_present(pgd_t pgd)
 
 static inline int pgd_bad(pgd_t pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return !pgd_present(pgd);
 
 	return 0;
@@ -264,13 +284,13 @@ static inline int pgd_bad(pgd_t pgd)
 
 static inline void pgd_clear(pgd_t *pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		set_pgd(pgd, __pgd(0));
 }
 
 static inline p4d_t *pgd_pgtable(pgd_t pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return (p4d_t *)pfn_to_virt(pgd_val(pgd) >> _PAGE_PFN_SHIFT);
 
 	return (p4d_t *)p4d_pgtable((p4d_t) { pgd_val(pgd) });
@@ -288,7 +308,7 @@ static inline struct page *pgd_page(pgd_t pgd)
 #define p4d_offset p4d_offset
 static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return pgd_pgtable(*pgd) + p4d_index(address);
 
 	return (p4d_t *)pgd;
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 046b44225623..ae01a9b83ac4 100644
--- a/arch/riscv/include/asm/pgtable.h
+++ b/arch/riscv/include/asm/pgtable.h
@@ -63,8 +63,8 @@
  * position vmemmap directly below the VMALLOC region.
  */
 #ifdef CONFIG_64BIT
-#define VA_BITS		(pgtable_l5_enabled ? \
-				57 : (pgtable_l4_enabled ? 48 : 39))
+#define VA_BITS		(pgtable_l5_enabled() ? \
+				57 : (pgtable_l4_enabled() ? 48 : 39))
 #else
 #define VA_BITS		32
 #endif
@@ -738,7 +738,6 @@ extern uintptr_t _dtb_early_pa;
 #define dtb_early_pa	_dtb_early_pa
 #endif /* CONFIG_XIP_KERNEL */
 extern u64 satp_mode;
-extern bool pgtable_l4_enabled;
 
 void paging_init(void);
 void misc_mem_init(void);
diff --git a/arch/riscv/kernel/cpu.c b/arch/riscv/kernel/cpu.c
index ccb617791e56..29bb0ef75248 100644
--- a/arch/riscv/kernel/cpu.c
+++ b/arch/riscv/kernel/cpu.c
@@ -141,9 +141,9 @@ static void print_mmu(struct seq_file *f)
 #if defined(CONFIG_32BIT)
 	strncpy(sv_type, "sv32", 5);
 #elif defined(CONFIG_64BIT)
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		strncpy(sv_type, "sv57", 5);
-	else if (pgtable_l4_enabled)
+	else if (pgtable_l4_enabled())
 		strncpy(sv_type, "sv48", 5);
 	else
 		strncpy(sv_type, "sv39", 5);
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 05ed641a1134..42c79388e6fd 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -44,10 +44,16 @@ u64 satp_mode __ro_after_init = SATP_MODE_32;
 #endif
 EXPORT_SYMBOL(satp_mode);
 
-bool pgtable_l4_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
-bool pgtable_l5_enabled = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
-EXPORT_SYMBOL(pgtable_l4_enabled);
-EXPORT_SYMBOL(pgtable_l5_enabled);
+DEFINE_STATIC_KEY_FALSE(_pgtable_l4_enabled);
+DEFINE_STATIC_KEY_FALSE(_pgtable_l5_enabled);
+DEFINE_STATIC_KEY_FALSE(_pgtable_lx_ready);
+EXPORT_SYMBOL(_pgtable_l4_enabled);
+EXPORT_SYMBOL(_pgtable_l5_enabled);
+EXPORT_SYMBOL(_pgtable_lx_ready);
+bool _pgtable_l4_enabled_early = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
+bool _pgtable_l5_enabled_early = IS_ENABLED(CONFIG_64BIT) && !IS_ENABLED(CONFIG_XIP_KERNEL);
+EXPORT_SYMBOL(_pgtable_l4_enabled_early);
+EXPORT_SYMBOL(_pgtable_l5_enabled_early);
 
 phys_addr_t phys_ram_base __ro_after_init;
 EXPORT_SYMBOL(phys_ram_base);
@@ -555,26 +561,26 @@ static void __init create_p4d_mapping(p4d_t *p4dp,
 }
 
 #define pgd_next_t		p4d_t
-#define alloc_pgd_next(__va)	(pgtable_l5_enabled ?			\
-		pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled ?		\
+#define alloc_pgd_next(__va)	(pgtable_l5_enabled() ?			\
+		pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled() ?	\
 		pt_ops.alloc_pud(__va) : pt_ops.alloc_pmd(__va)))
-#define get_pgd_next_virt(__pa)	(pgtable_l5_enabled ?			\
-		pt_ops.get_p4d_virt(__pa) : (pgd_next_t *)(pgtable_l4_enabled ?	\
+#define get_pgd_next_virt(__pa)	(pgtable_l5_enabled() ?			\
+		pt_ops.get_p4d_virt(__pa) : (pgd_next_t *)(pgtable_l4_enabled() ?	\
 		pt_ops.get_pud_virt(__pa) : (pud_t *)pt_ops.get_pmd_virt(__pa)))
 #define create_pgd_next_mapping(__nextp, __va, __pa, __sz, __prot)	\
-				(pgtable_l5_enabled ?			\
+				(pgtable_l5_enabled() ?			\
 		create_p4d_mapping(__nextp, __va, __pa, __sz, __prot) : \
-				(pgtable_l4_enabled ?			\
+				(pgtable_l4_enabled() ?			\
 		create_pud_mapping((pud_t *)__nextp, __va, __pa, __sz, __prot) :	\
 		create_pmd_mapping((pmd_t *)__nextp, __va, __pa, __sz, __prot)))
-#define fixmap_pgd_next		(pgtable_l5_enabled ?			\
-		(uintptr_t)fixmap_p4d : (pgtable_l4_enabled ?		\
+#define fixmap_pgd_next		(pgtable_l5_enabled() ?			\
+		(uintptr_t)fixmap_p4d : (pgtable_l4_enabled() ?		\
 		(uintptr_t)fixmap_pud : (uintptr_t)fixmap_pmd))
-#define trampoline_pgd_next	(pgtable_l5_enabled ?			\
-		(uintptr_t)trampoline_p4d : (pgtable_l4_enabled ?	\
+#define trampoline_pgd_next	(pgtable_l5_enabled() ?			\
+		(uintptr_t)trampoline_p4d : (pgtable_l4_enabled() ?	\
 		(uintptr_t)trampoline_pud : (uintptr_t)trampoline_pmd))
-#define early_dtb_pgd_next	(pgtable_l5_enabled ?			\
-		(uintptr_t)early_dtb_p4d : (pgtable_l4_enabled ?	\
+#define early_dtb_pgd_next	(pgtable_l5_enabled() ?			\
+		(uintptr_t)early_dtb_p4d : (pgtable_l4_enabled() ?	\
 		(uintptr_t)early_dtb_pud : (uintptr_t)early_dtb_pmd))
 #else
 #define pgd_next_t		pte_t
@@ -680,14 +686,14 @@ static __init pgprot_t pgprot_from_va(uintptr_t va)
 #ifdef CONFIG_64BIT
 static void __init disable_pgtable_l5(void)
 {
-	pgtable_l5_enabled = false;
+	_pgtable_l5_enabled_early = false;
 	kernel_map.page_offset = PAGE_OFFSET_L4;
 	satp_mode = SATP_MODE_48;
 }
 
 static void __init disable_pgtable_l4(void)
 {
-	pgtable_l4_enabled = false;
+	_pgtable_l4_enabled_early = false;
 	kernel_map.page_offset = PAGE_OFFSET_L3;
 	satp_mode = SATP_MODE_39;
 }
@@ -816,11 +822,11 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
 			   PGDIR_SIZE,
 			   IS_ENABLED(CONFIG_64BIT) ? PAGE_TABLE : PAGE_KERNEL);
 
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		create_p4d_mapping(early_dtb_p4d, DTB_EARLY_BASE_VA,
 				   (uintptr_t)early_dtb_pud, P4D_SIZE, PAGE_TABLE);
 
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		create_pud_mapping(early_dtb_pud, DTB_EARLY_BASE_VA,
 				   (uintptr_t)early_dtb_pmd, PUD_SIZE, PAGE_TABLE);
 
@@ -961,11 +967,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 
 #ifndef __PAGETABLE_PMD_FOLDED
 	/* Setup fixmap P4D and PUD */
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		create_p4d_mapping(fixmap_p4d, FIXADDR_START,
 				   (uintptr_t)fixmap_pud, P4D_SIZE, PAGE_TABLE);
 	/* Setup fixmap PUD and PMD */
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		create_pud_mapping(fixmap_pud, FIXADDR_START,
 				   (uintptr_t)fixmap_pmd, PUD_SIZE, PAGE_TABLE);
 	create_pmd_mapping(fixmap_pmd, FIXADDR_START,
@@ -973,10 +979,10 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 	/* Setup trampoline PGD and PMD */
 	create_pgd_mapping(trampoline_pg_dir, kernel_map.virt_addr,
 			   trampoline_pgd_next, PGDIR_SIZE, PAGE_TABLE);
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		create_p4d_mapping(trampoline_p4d, kernel_map.virt_addr,
 				   (uintptr_t)trampoline_pud, P4D_SIZE, PAGE_TABLE);
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		create_pud_mapping(trampoline_pud, kernel_map.virt_addr,
 				   (uintptr_t)trampoline_pmd, PUD_SIZE, PAGE_TABLE);
 #ifdef CONFIG_XIP_KERNEL
@@ -1165,8 +1171,18 @@ static void __init reserve_crashkernel(void)
 	crashk_res.end = crash_base + crash_size - 1;
 }
 
+static void __init riscv_finalise_pgtable_lx(void)
+{
+	if (_pgtable_l5_enabled_early)
+		static_branch_enable(&_pgtable_l5_enabled);
+	if (_pgtable_l4_enabled_early)
+		static_branch_enable(&_pgtable_l4_enabled);
+	static_branch_enable(&_pgtable_lx_ready);
+}
+
 void __init paging_init(void)
 {
+	riscv_finalise_pgtable_lx();
 	setup_bootmem();
 	setup_vm_final();
 }
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index a22e418dbd82..356044498e8a 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -209,15 +209,15 @@ static void __init kasan_populate_p4d(pgd_t *pgd,
 		set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_p4d)), PAGE_TABLE));
 }
 
-#define kasan_early_shadow_pgd_next			(pgtable_l5_enabled ?	\
+#define kasan_early_shadow_pgd_next			(pgtable_l5_enabled() ?	\
 				(uintptr_t)kasan_early_shadow_p4d :		\
-							(pgtable_l4_enabled ?	\
+							(pgtable_l4_enabled() ?	\
 				(uintptr_t)kasan_early_shadow_pud :		\
 				(uintptr_t)kasan_early_shadow_pmd))
 #define kasan_populate_pgd_next(pgdp, vaddr, next, early)			\
-		(pgtable_l5_enabled ?						\
+		(pgtable_l5_enabled() ?						\
 		kasan_populate_p4d(pgdp, vaddr, next, early) :			\
-		(pgtable_l4_enabled ?						\
+		(pgtable_l4_enabled() ?						\
 			kasan_populate_pud(pgdp, vaddr, next, early) :		\
 			kasan_populate_pmd((pud_t *)pgdp, vaddr, next)))
 
@@ -274,7 +274,7 @@ asmlinkage void __init kasan_early_init(void)
 				(__pa((uintptr_t)kasan_early_shadow_pte)),
 				PAGE_TABLE));
 
-	if (pgtable_l4_enabled) {
+	if (pgtable_l4_enabled()) {
 		for (i = 0; i < PTRS_PER_PUD; ++i)
 			set_pud(kasan_early_shadow_pud + i,
 				pfn_pud(PFN_DOWN
@@ -282,7 +282,7 @@ asmlinkage void __init kasan_early_init(void)
 					PAGE_TABLE));
 	}
 
-	if (pgtable_l5_enabled) {
+	if (pgtable_l5_enabled()) {
 		for (i = 0; i < PTRS_PER_P4D; ++i)
 			set_p4d(kasan_early_shadow_p4d + i,
 				pfn_p4d(PFN_DOWN
@@ -393,9 +393,9 @@ static void __init kasan_shallow_populate_p4d(pgd_t *pgdp,
 }
 
 #define kasan_shallow_populate_pgd_next(pgdp, vaddr, next)			\
-		(pgtable_l5_enabled ?						\
+		(pgtable_l5_enabled() ?						\
 		kasan_shallow_populate_p4d(pgdp, vaddr, next) :			\
-		(pgtable_l4_enabled ?						\
+		(pgtable_l4_enabled() ?						\
 		kasan_shallow_populate_pud(pgdp, vaddr, next) :			\
 		kasan_shallow_populate_pmd(pgdp, vaddr, next)))
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220521143456.2759-3-jszhang%40kernel.org.
