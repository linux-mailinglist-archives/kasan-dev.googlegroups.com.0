Return-Path: <kasan-dev+bncBAABBR6QZKLAMGQETLKYWDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7696A576DAE
	for <lists+kasan-dev@lfdr.de>; Sat, 16 Jul 2022 14:00:09 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id w5-20020a170902e88500b0016ce31d1d79sf166692plg.4
        for <lists+kasan-dev@lfdr.de>; Sat, 16 Jul 2022 05:00:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1657972808; cv=pass;
        d=google.com; s=arc-20160816;
        b=SxD4rAq+eQZ8KxbzkLAh/mm6dmlU1XhfLXM5WhOthn9KWcZOTTvrszB8aJxyAL0pIw
         Ky51+TpTi5mGbTdkdHtVOj1QEI7Mwjd6o5R292FQWEs8Z2TTlB/OCkF2sllPEJU2xY5K
         TIG8er+Vfb/6njALln7a6nMwUuIgbCjLKz4g5RpKQ8YA6fFbu+izeSEkN2u4W+e9QPTs
         dSnieZ3Y6jBT3K+WFtUcWEAl9LuepzIXvIS9vTibNWvz2PyLguP7Is/CnJb/UYWteFby
         Tb8BHAaitrniii15NHxR4l3bu8/9fum+kgYOhZV+QM0+8cBBY9q3gNI0/dUYCEjuMAeO
         JcaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=IBJ/aDPLewpyaGcJyqNncjJuVATjn//sZZaSYOdw9zw=;
        b=wsA4a9Pa36fvGou7cBb5bRKOT6vL+TUtF5QGQtuYXWxCwCxMxtz2g2PHD3TOomA5Vk
         nIBYtd5WMh6EVSrIG756Jq4BITdDmauJkfBx+H/NflVHOT0Ynrm43y+OgZvit2IvpxRh
         8LnYRGUrf3nAbIpc0HGGKcGFbnG4IzKO2lgD7XRfMtgEmAc1HU8rFdTfeWbdRzl36m79
         Mh162JJzOk+Gpi9Fl+E2T7cxmI+kLC6HbSMlglM/LL4UMwygyu9WGNrlDS01xkJzElyn
         wzR69AFOF2vwn9CZ3TBfjz5oWf1ir7k6twPVyH996YZVQdMeq4i5ZsD7uEXf7ruF+W14
         agBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FoMhIQGn;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IBJ/aDPLewpyaGcJyqNncjJuVATjn//sZZaSYOdw9zw=;
        b=gxnxg75f252JWFlc5rcAlqu66UFNOLKV6vN3UuChTj07mXVsQ6urB0snFvROSjUfJ0
         /ZaNnI6q/qSIXc30MQvxk3jk7Lta7GxLw1WkB/xZjSjXJ6PR+numcDQ0Xg6V1ssW4Z6V
         uuWZ0pQZGqFcfOs9mtANWqwa1AU4oBtw9f0n0aKXzxj+WxHSwryRhL2FpX457IVog5Sl
         aKLUTPpMdlsnDOug+TPg6Pu8yOx/3qZbRRkp8Lzeb/EQ/IAYNBgAVzdk1k9Q0lZLlchW
         NWpb5LQpYzVqT4txxzBMEHWiZkm3aFJ1nB6YETYaln8KG9AkhPtEcpoJ/4tXPxJNnjYi
         ErMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IBJ/aDPLewpyaGcJyqNncjJuVATjn//sZZaSYOdw9zw=;
        b=qQUpl/AXL1sxECnJCInf4Blaift/uqlNlnwuWL4Yyj5WPyipno8kz1tqwcc9R0rUfP
         K+ps0F3tLYlVt7csqxRpaLX8/x74N/vgezwsYExHectjWgMdUaI5Ip82WQLsZB4a/TJp
         yBtpstaQ0UDDHrPYmpeqiFAkYowWTSehFxuQ8wr/NcLSScGfZ61flssolg6bQEhNVQxg
         vlWeAJHHvRq43D/gmH1/OgoRfeReIsE9Y88aQWlbwOHlE3E8q7wlDDC2u0CabQLQx6dg
         A6CMitK8kkQ/hPaTHPinx8tehecgqH5s55Zrt/X/nvpV/LS0OFZ4O5kotTrNHmHXMPoO
         +nnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/z/34d51BmBHSMKevAsNdGaKuQc4D0NOgGp20ENFDOAgSDTY4G
	Mqwhf9JPSD6e4wHM3Gfz4Bg=
X-Google-Smtp-Source: AGRyM1tQIEKUCRMxEsERHGIC8uteWlUHmGeKAXMgB4tevUS7h1VmlyrLWSdnWqLALkRTNqr4rW4ucA==
X-Received: by 2002:a65:5a42:0:b0:411:bf36:eeec with SMTP id z2-20020a655a42000000b00411bf36eeecmr16033441pgs.522.1657972807641;
        Sat, 16 Jul 2022 05:00:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e80b:b0:16b:f798:37b2 with SMTP id
 u11-20020a170902e80b00b0016bf79837b2ls8572681plg.8.gmail; Sat, 16 Jul 2022
 05:00:07 -0700 (PDT)
X-Received: by 2002:a17:903:191:b0:16c:3d49:b0c8 with SMTP id z17-20020a170903019100b0016c3d49b0c8mr18492915plg.95.1657972806993;
        Sat, 16 Jul 2022 05:00:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1657972806; cv=none;
        d=google.com; s=arc-20160816;
        b=UIQXGT4/DXx+S17jiywYxIyUVe57RRwn6yKRH9bSeQx362QNHGXhcLdEfBYg9Rz72L
         q/EOTe5Rodo1sGjM3uEFITXZBUhzc/EYNeG/0XOY0xBvsbhBFdysp0yYwMuDlK/ENEGf
         8caH3Z+3DT8i2wp29acvp0SpMTzqPR5D3CaXkBncFICW1uKYWLMC8FMY3LGzxVExjToN
         3OAUORuv1oAhGV/ym9600zKqPvfV+sMVZOQGEiIezBun6IgBjCtztvZi5RKJH+lCnxLG
         KH6hqG6v78uS/439SNIi4smd4d332cm4hR7Vr5LR7D0d/VRWZhrlDlUT9oqyHAFC1r5Q
         jNAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XXA+QuXrzA+a6WAEFjQzjtl/UtmyoN5TeXspnwncu28=;
        b=hzpBxu9QOUjIX0kaPVZFymFLSUbIJPbncTGaA6nAyBQDHMeniI1ovYFAT0lz4wroeY
         S7iVUM6EfVMDQdelD25BFw/8ryC/iAQCFUtJOJk9OjiSOssRZG7PgPk7Y2bc4OEXQ1XM
         pLtaUdV8/7RRR0GoF+qmHJ2sVdDWc2vm7atSiz5eBKtRJ06Q00mmlMEYyKmybs+MNgMV
         pXLIZ++QGEdxc50gBglmu3xptG55/IZtXA2jTNzuBV7Nx/PrUlsyzn3BITT70NvMAWh/
         F96LFhNrQg6H6DqLYnUBwAxYP401F8J/3pjH5PVEkWkXgWitQcHSN/kX7cx5btmYQlUO
         In+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FoMhIQGn;
       spf=pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=jszhang@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id lt2-20020a17090b354200b001ef8b809176si379633pjb.2.2022.07.16.05.00.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 16 Jul 2022 05:00:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 532B260FCF;
	Sat, 16 Jul 2022 12:00:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 94BCDC34114;
	Sat, 16 Jul 2022 12:00:02 +0000 (UTC)
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
	Emil Renner Berthing <emil.renner.berthing@canonical.com>
Cc: linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Anup Patel <anup@brainfault.org>
Subject: [PATCH v6 2/2] riscv: turn pgtable_l4|[l5]_enabled to static key for RV64
Date: Sat, 16 Jul 2022 19:50:59 +0800
Message-Id: <20220716115059.3509-3-jszhang@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20220716115059.3509-1-jszhang@kernel.org>
References: <20220716115059.3509-1-jszhang@kernel.org>
MIME-Version: 1.0
X-Original-Sender: jszhang@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FoMhIQGn;       spf=pass
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
index 5c2aba5efbd0..baab8e6bec01 100644
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
 		return (pud_t *)pfn_to_virt(p4d_val(p4d) >> _PAGE_PFN_SHIFT);
 
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
 		return (p4d_t *)pfn_to_virt(pgd_val(pgd) >> _PAGE_PFN_SHIFT);
 
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
index 1d1be9d9419c..3eaa01d880b9 100644
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
@@ -834,7 +834,6 @@ extern uintptr_t _dtb_early_pa;
 #define dtb_early_pa	_dtb_early_pa
 #endif /* CONFIG_XIP_KERNEL */
 extern u64 satp_mode;
-extern bool pgtable_l4_enabled;
 
 void paging_init(void);
 void misc_mem_init(void);
diff --git a/arch/riscv/kernel/cpu.c b/arch/riscv/kernel/cpu.c
index fba9e9f46a8c..9b3697a97e41 100644
--- a/arch/riscv/kernel/cpu.c
+++ b/arch/riscv/kernel/cpu.c
@@ -143,9 +143,9 @@ static void print_mmu(struct seq_file *f)
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
index d466ec670e1f..11708cdb7094 100644
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
@@ -585,26 +591,26 @@ static void __init create_p4d_mapping(p4d_t *p4dp,
 }
 
 #define pgd_next_t		p4d_t
-#define alloc_pgd_next(__va)	(pgtable_l5_enabled ?			\
-		pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled ?		\
+#define alloc_pgd_next(__va)	(pgtable_l5_enabled() ?			\
+		pt_ops.alloc_p4d(__va) : (pgtable_l4_enabled() ?		\
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
@@ -710,14 +716,14 @@ static __init pgprot_t pgprot_from_va(uintptr_t va)
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
@@ -846,11 +852,11 @@ static void __init create_fdt_early_page_table(pgd_t *pgdir, uintptr_t dtb_pa)
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
 
@@ -992,11 +998,11 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
 
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
@@ -1004,10 +1010,10 @@ asmlinkage void __init setup_vm(uintptr_t dtb_pa)
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
@@ -1196,6 +1202,15 @@ static void __init reserve_crashkernel(void)
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
@@ -1207,6 +1222,7 @@ void __init misc_mem_init(void)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220716115059.3509-3-jszhang%40kernel.org.
