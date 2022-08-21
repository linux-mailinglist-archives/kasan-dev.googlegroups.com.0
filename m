Return-Path: <kasan-dev+bncBAABBP75RCMAMGQEGK5CAYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F93B59B45D
	for <lists+kasan-dev@lfdr.de>; Sun, 21 Aug 2022 16:18:41 +0200 (CEST)
Received: by mail-ua1-x93d.google.com with SMTP id j30-20020ab015e1000000b0038779c4c218sf1524672uae.22
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Aug 2022 07:18:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1661091520; cv=pass;
        d=google.com; s=arc-20160816;
        b=zi2bAL++Et2mwowOrwK+dsntjVwvdPX6A3yUPsJHDVetfl/4ig9SEBqvGWWmxn9ahP
         UhDWp96xhR6lc+X+m0RUpKYsLHxKaoHT84hMMbK2Yc51zjZbx1WQLpZDa261zQsUg2Og
         GwCFEMrDmmlnflVq/BN1wGS/GW8foiRDinj2JgjDeYGOm/ZmCJQjUjcyjK5vi8zOFO8N
         7m02mCosDKym4wZzomqbs5hqj6XI0PnvPxx9PBXg+W4N/HJ7Yg3imGGjmK1HPRQo+s6a
         V1CZ6s0M6KVb3WTMgM7nKmQE2Kurhvk17coe6EbrrVGYWh7Cx1yMDYObHzg5Lj1/vb32
         cH6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vUmok/haK3/4rwd+qej4O7i5wGg+HzMj9oefbA8Ps8s=;
        b=QlV3C3bdbz9bbPACHyU1eBy+2ZF/+JLqjKiw571YI4bRumf5P5uCGV+vUDEqpSGLbv
         +d772ramyw8DJRcZc84cVTIvC9WUQ/X7uTrT+IX0PFVAExbKW8oWpItZTZlKp/FkoK5B
         yMWHcS3Ih9dif0LjioYjS5owvb88vtUfkpm7g+hulPmV3voFMaIMvuzlgqkitPP+3+oN
         LkKXPWjwm68UKldNjOKWM/USps2pjalzkDhvMyV/+wcUvCHG3vw0XMe7GNktG5hOeNyd
         eqZ9GZmAAj8tVsJt0C4/XuJLfJEZ0soK5TBjXcz8bb0+wESYfGIMocsq2OkKhL9yF2mM
         aUNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="SJ42r/xT";
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=vUmok/haK3/4rwd+qej4O7i5wGg+HzMj9oefbA8Ps8s=;
        b=cIoNCN5K5D/R4rJU74KxxuPar5NzchnITbDKupESEJlFFk3cTGwqIZ/DisxG5I9hZk
         +lBfwFrfND1L+TyneRRQWWUJ8l0QBBm2/jmuXA9l2ALokBgFRLQmcS4dJhT9a6CjRrzm
         zTPPbJZGRchlo5fwJRsH5QLX36DwdPChD7E9qKpkOvLzNxzq45GViQMB8Hbu7w9Ik1oo
         DESXZ3OjnFEfFmaAs+Tod7I0Hhyu2KUKZrQnTOK7MMHNCybj54cjJ7UN3RoUZpnDlJ9k
         DvsugnedWrsNiO6kRPV1zq4jHFrUMdIZV2ypFQmmeg9VTHIaqGh3ortXeKz6EMB6UcDj
         Q+iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=vUmok/haK3/4rwd+qej4O7i5wGg+HzMj9oefbA8Ps8s=;
        b=j009Xb/+TD3Ilg+R7KXPF+AWGeiat1cVRodXkTwwE9o7/kFbn9lu2iIQfO6TibY2fH
         i4D6mfLyg7T4/drEe/zBBmkDGD3fWR756zsSv4Qe3xhaYMMyMjd8/oyEZLlo2/HtURNJ
         dj2wyZRIN2KCooAHvRGXVKe0aPKKM5jqC2v3FdwsIoIOee3HRWaijBawsYQ2G/Q9YEMM
         TDcaeA34EYtvw2pAK+jrAU5wmidHFZ6u50n8PauzRAfi7pG/CRX7A0H45qQAHN4BL19Y
         clJF+bl7Ug6vpO8KojQUavnjKohM40nooQygPlFGBeepCNYT44GKGHY3vJM+HFlWvQcf
         gUiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2hBzXOxvJb+5iDNcbgK2+g0oEsCAXkq/QrwF38Zsma4doEdpyg
	CKN9fjZPPfZZYYQtTxLitF8=
X-Google-Smtp-Source: AA6agR7vplt7ApC/3pt6LhXaQaAsjtw2TmYt8hyXJQ6QWRpIsS/uPEGgtduVAWKt4pWiCLcmUeIGzw==
X-Received: by 2002:ab0:7417:0:b0:39e:e3eb:95c0 with SMTP id r23-20020ab07417000000b0039ee3eb95c0mr1963201uap.1.1661091519899;
        Sun, 21 Aug 2022 07:18:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:ab0b:0:b0:38c:e94f:3b4e with SMTP id u11-20020a67ab0b000000b0038ce94f3b4els1869257vse.5.-pod-prod-gmail;
 Sun, 21 Aug 2022 07:18:39 -0700 (PDT)
X-Received: by 2002:a67:c48e:0:b0:390:62b3:20f1 with SMTP id d14-20020a67c48e000000b0039062b320f1mr266152vsk.7.1661091519349;
        Sun, 21 Aug 2022 07:18:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1661091519; cv=none;
        d=google.com; s=arc-20160816;
        b=CDy1LK+IZIORhmr8B3WnRxhqKO/hZeewzTO05lRUNl0CEm8kXxlaIYn+KgYEKYL2k5
         IvH2Amos3WF+L47V7Yi+JaOXal/oye8wcVOeTltpWgK0Htpii3sWDrLlLxKF4M9fNuuM
         RSNfRF1Q3LWN9UruEsI3YDU9HDEHjvgxn/Q9HLNpyqJDYReY4K5qB6n8QDcdSTUV7hVB
         oTh8ZCr7z3mYy3hiI0Gh9YI5sb5yNHGLiinDI9rVm5qBhxTC1VZ/3HBHfoctOvBSr5Qr
         qg5zLpACu5IfssrbdNJpQW5upAn4T+rDOSIJp8xmc66NPeaBYs3ic0jz+5AEhdND/Rzl
         Zu6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lhIOza/oslo7qDrEvLVHqb4S1Sum3a9yOZuLyu7Bric=;
        b=DPARnWYe9r5mXjHicQ+nZaBubUxaiB7HMvdCe6mbF3PrdzJ8cilNlIXXUD7LGyaQSa
         0Zc8Duh7rBQI9NIvSuetr5+/Ex5ZN81Ihe7J0ZYxCwatcWL8rlq04geuzltgTuWR2Spp
         8c8eT8fD3O+IANhb90LDKWyhrBpU12hW3+X3Dx3oqE3ewRPt7BlvyFgBpfV58Kk7M8UH
         3etS8J8fHWzb408O1higvkh8SlBfkGUtoCn6VERMbm3Z9VMLtlR+W9tN6J3i0uhWjfxS
         fTULb/YVyB7GS/pPklsROrhU+LKjW1zK0aGymijnc5CilK2SvQA3dFhi6gCh1sd04nnF
         jewg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="SJ42r/xT";
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id n25-20020a67e459000000b003839d28013bsi312009vsm.2.2022.08.21.07.18.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 21 Aug 2022 07:18:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id C93BE60E77;
	Sun, 21 Aug 2022 14:18:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 7B879C433D6;
	Sun, 21 Aug 2022 14:18:35 +0000 (UTC)
From: Jisheng Zhang <jszhang@kernel.org>
To: Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexandre Ghiti <alexandre.ghiti@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Anup Patel <anup@brainfault.org>
Subject: [PATCH v6 RESEND 2/2] riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
Date: Sun, 21 Aug 2022 22:09:18 +0800
Message-Id: <20220821140918.3613-3-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220821140918.3613-1-jszhang@kernel.org>
References: <20220821140918.3613-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="SJ42r/xT";       spf=pass
 (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as
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
Reviewed-by: Anup Patel <anup@brainfault.org>
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
index 59ba1fbaf784..1ef52079179a 100644
--- a/arch/riscv/include/asm/pgtable-32.h
+++ b/arch/riscv/include/asm/pgtable-32.h
@@ -17,6 +17,9 @@
 
 #define MAX_POSSIBLE_PHYSMEM_BITS 34
 
+#define pgtable_l5_enabled() 0
+#define pgtable_l4_enabled() 0
+
 /*
  * rv32 PTE format:
  * | XLEN-1  10 | 9             8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0
diff --git a/arch/riscv/include/asm/pgtable-64.h b/arch/riscv/include/asm/pgtable-64.h
index dc42375c2357..ef182aa785d5 100644
--- a/arch/riscv/include/asm/pgtable-64.h
+++ b/arch/riscv/include/asm/pgtable-64.h
@@ -8,18 +8,38 @@
 
 #include <linux/bits.h>
 #include <linux/const.h>
+#include <linux/jump_label.h>
 #include <asm/errata_list.h>
 
-extern bool pgtable_l4_enabled;
-extern bool pgtable_l5_enabled;
+extern bool _pgtable_l5_enabled_early;
+extern bool _pgtable_l4_enabled_early;
+DECLARE_STATIC_KEY_FALSE(_pgtable_l5_enabled);
+DECLARE_STATIC_KEY_FALSE(_pgtable_l4_enabled);
+DECLARE_STATIC_KEY_FALSE(_pgtable_lx_ready);
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
@@ -191,7 +211,7 @@ static inline struct page *pud_page(pud_t pud)
 #define mm_p4d_folded  mm_p4d_folded
 static inline bool mm_p4d_folded(struct mm_struct *mm)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return false;
 
 	return true;
@@ -200,7 +220,7 @@ static inline bool mm_p4d_folded(struct mm_struct *mm)
 #define mm_pud_folded  mm_pud_folded
 static inline bool mm_pud_folded(struct mm_struct *mm)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return false;
 
 	return true;
@@ -235,7 +255,7 @@ static inline unsigned long _pmd_pfn(pmd_t pmd)
 
 static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		*p4dp = p4d;
 	else
 		set_pud((pud_t *)p4dp, (pud_t){ p4d_val(p4d) });
@@ -243,7 +263,7 @@ static inline void set_p4d(p4d_t *p4dp, p4d_t p4d)
 
 static inline int p4d_none(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return (p4d_val(p4d) == 0);
 
 	return 0;
@@ -251,7 +271,7 @@ static inline int p4d_none(p4d_t p4d)
 
 static inline int p4d_present(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return (p4d_val(p4d) & _PAGE_PRESENT);
 
 	return 1;
@@ -259,7 +279,7 @@ static inline int p4d_present(p4d_t p4d)
 
 static inline int p4d_bad(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return !p4d_present(p4d);
 
 	return 0;
@@ -267,7 +287,7 @@ static inline int p4d_bad(p4d_t p4d)
 
 static inline void p4d_clear(p4d_t *p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		set_p4d(p4d, __p4d(0));
 }
 
@@ -283,7 +303,7 @@ static inline unsigned long _p4d_pfn(p4d_t p4d)
 
 static inline pud_t *p4d_pgtable(p4d_t p4d)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return (pud_t *)pfn_to_virt(__page_val_to_pfn(p4d_val(p4d)));
 
 	return (pud_t *)pud_pgtable((pud_t) { p4d_val(p4d) });
@@ -300,7 +320,7 @@ static inline struct page *p4d_page(p4d_t p4d)
 #define pud_offset pud_offset
 static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
 {
-	if (pgtable_l4_enabled)
+	if (pgtable_l4_enabled())
 		return p4d_pgtable(*p4d) + pud_index(address);
 
 	return (pud_t *)p4d;
@@ -308,7 +328,7 @@ static inline pud_t *pud_offset(p4d_t *p4d, unsigned long address)
 
 static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		*pgdp = pgd;
 	else
 		set_p4d((p4d_t *)pgdp, (p4d_t){ pgd_val(pgd) });
@@ -316,7 +336,7 @@ static inline void set_pgd(pgd_t *pgdp, pgd_t pgd)
 
 static inline int pgd_none(pgd_t pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return (pgd_val(pgd) == 0);
 
 	return 0;
@@ -324,7 +344,7 @@ static inline int pgd_none(pgd_t pgd)
 
 static inline int pgd_present(pgd_t pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return (pgd_val(pgd) & _PAGE_PRESENT);
 
 	return 1;
@@ -332,7 +352,7 @@ static inline int pgd_present(pgd_t pgd)
 
 static inline int pgd_bad(pgd_t pgd)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return !pgd_present(pgd);
 
 	return 0;
@@ -340,13 +360,13 @@ static inline int pgd_bad(pgd_t pgd)
 
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
 		return (p4d_t *)pfn_to_virt(__page_val_to_pfn(pgd_val(pgd)));
 
 	return (p4d_t *)p4d_pgtable((p4d_t) { pgd_val(pgd) });
@@ -364,7 +384,7 @@ static inline struct page *pgd_page(pgd_t pgd)
 #define p4d_offset p4d_offset
 static inline p4d_t *p4d_offset(pgd_t *pgd, unsigned long address)
 {
-	if (pgtable_l5_enabled)
+	if (pgtable_l5_enabled())
 		return pgd_pgtable(*pgd) + p4d_index(address);
 
 	return (p4d_t *)pgd;
diff --git a/arch/riscv/include/asm/pgtable.h b/arch/riscv/include/asm/pgtable.h
index 7ec936910a96..daf2475b6f43 100644
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
@@ -814,7 +814,6 @@ extern uintptr_t _dtb_early_pa;
 #define dtb_early_pa	_dtb_early_pa
 #endif /* CONFIG_XIP_KERNEL */
 extern u64 satp_mode;
-extern bool pgtable_l4_enabled;
 
 void paging_init(void);
 void misc_mem_init(void);
diff --git a/arch/riscv/kernel/cpu.c b/arch/riscv/kernel/cpu.c
index 0be8a2403212..8e2fae6cad34 100644
--- a/arch/riscv/kernel/cpu.c
+++ b/arch/riscv/kernel/cpu.c
@@ -150,9 +150,9 @@ static void print_mmu(struct seq_file *f)
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
index b56a0a75533f..713831f12fe2 100644
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
@@ -609,26 +615,26 @@ static void __init create_p4d_mapping(p4d_t *p4dp,
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
@@ -734,14 +740,14 @@ static __init pgprot_t pgprot_from_va(uintptr_t va)
 #if defined(CONFIG_64BIT) && !defined(CONFIG_XIP_KERNEL)
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
@@ -870,11 +876,11 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
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
 
@@ -1016,11 +1022,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 
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
@@ -1028,10 +1034,10 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
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
@@ -1220,6 +1226,15 @@ static void __init reserve_crashkernel(void)
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
 	setup_bootmem();
@@ -1231,6 +1246,7 @@ void __init misc_mem_init(void)
 	early_memtest(min_low_pfn << PAGE_SHIFT, max_low_pfn << PAGE_SHIFT);
 	arch_numa_init();
 	sparse_init();
+	riscv_finalise_pgtable_lx();
 	zone_sizes_init();
 	reserve_crashkernel();
 	memblock_dump_all();
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220821140918.3613-3-jszhang%40kernel.org.
