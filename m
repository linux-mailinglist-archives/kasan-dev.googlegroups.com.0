Return-Path: <kasan-dev+bncBC447XVYUEMRBT5EQ2AQMGQEGPJX3VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 2DC70313F15
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Feb 2021 20:34:40 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id w16sf13189716ejk.7
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Feb 2021 11:34:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612812879; cv=pass;
        d=google.com; s=arc-20160816;
        b=fjtSq4z/FZhMoSjwHXgG8eDHWRD8tywTBFo4hzIOf3ZaqggXeyZYmRpfLkliyB7pWB
         Nfei4yCSctJdh5aYx/H43tNDJ8RWsJyzj1uDXDM+AFe02F3og242/tZk20Bbnag3upXG
         6SppilJYT5eEQxHMOkQVW3ho/fxfpRagjzfOo9z6iWZBo1wznJY14CAMQHSJ4PdLQTPg
         ibjbaoG6FJS6BEa2TQLm4b3CpK9JXNBigiPzHF0RJpYx4wUvhYth4L6Qy8XnL0g0NJMi
         RV3f/Ave4XjebOpz6Lxi1bU2XIilT1ahS9Iepk/sWgvgsyx12W2jTjgXsddaBo4Pxci3
         MVcA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2GkeIqZ1DyZGEvbOxdnG+f9VnqJjqbXv8+hnyT+lf8g=;
        b=iiJl+fcpTSQmetQQiJjKytF2ENRgCSkvfBsnZMK0USdovkVzk3WtZO/lIGhp04g30g
         puGCtzvMJ4H312/zVET2sMC90/S5CcPyBvaymuVFzhZs38hxKjsddN2wqfovvJMvbMyV
         7PIJ8SS/xDEOaP4MNsMXafi0b8jVpya01JEsZQWCueZGID7hUH2TzRKVmtZAOLfbRJIn
         TzPpzjvnVELh19+kPgS8auMFUpxYb3d5nUlTdF4si/0TFGU5Jm1S6bIFgJuUCvXYjzn+
         uOO0UfqDL8ap0CQjUTpR0mISFGaXniHiHekMxv1eNnxWRYuSB9xkz3ziuxfpm0lPhLYx
         sFdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2GkeIqZ1DyZGEvbOxdnG+f9VnqJjqbXv8+hnyT+lf8g=;
        b=oiEkpPjMMY7NXHzjC4BtpQz2oS8Q6GTiWZJ7oQY19us1YnUjzqvcAbJKldsUQtPZSO
         GNPB0EyU01R62zGvLXdfgpl+Tm9oKLf9mOHwrIgwCCYFfpCqvKfoPxpZa+ZN+3x/MSKS
         M4cvvBjRD76oHUaMbQ17F7J/QdQxeoCwtyBCbeTVdcI2WunL8n7dRCbw1118AD6eaIF5
         wDGBYUhAROWBipNQ6IdVGMQb7+YAj9vUi/l4bYmpQnTIyYTk0gz6eDVEtk5hsVlPqSNp
         Q/ZE630dWGxTAdUmJXf6+cXhpWAH+CLpj+un+TL1vDVHXqucbz6YwO8RMtcSefVOHNO+
         jZVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2GkeIqZ1DyZGEvbOxdnG+f9VnqJjqbXv8+hnyT+lf8g=;
        b=flfGSB9cvdWLPgTPlY+nFdbvnxevNfVou/einZ8Ap1SFm0xjVbgL50uYvqVHRsciZr
         4e8TwGqxqqgD40jXsFlda8eeZ+NcTrTYu5pnozCB5RVHVwdgIWgwJGjfP1QDNigEIOyp
         ZUEi3O/sz/3bolhh6crHFEk3z/fb1YcqRvgUHZo9R7QZr2BiIdi77w//nhmtWvppAHXA
         fXFodkJsX/m04wpypfFTbQSINKOPmv9X2UffzNKEjL/lj4Yw5nkEaGYXDenUeU6R52GX
         tRvcueaJmmtBQr3x5ge+3EPurbCp+qa78XxUq0ai7erjcDySZREvZByyiZsw66QN1LP9
         F1OA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5328LKt9UB+l3Ku+I1nji4Ps86482GpRoAxBkHcv4Ak6EXuWeJ5O
	VP9q/6hibubJP3iGQO5blL0=
X-Google-Smtp-Source: ABdhPJyZkKh+qBfR67LVMGdQirHgpGQzhrUgsg3DMT6dqKMvKDZC+PYGJcxeIzXswLUi7Cc21GRieg==
X-Received: by 2002:a17:906:5e59:: with SMTP id b25mr18564395eju.536.1612812879892;
        Mon, 08 Feb 2021 11:34:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520e:: with SMTP id s14ls8205332edd.3.gmail; Mon,
 08 Feb 2021 11:34:39 -0800 (PST)
X-Received: by 2002:a50:bb47:: with SMTP id y65mr9784951ede.33.1612812879144;
        Mon, 08 Feb 2021 11:34:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612812879; cv=none;
        d=google.com; s=arc-20160816;
        b=qTrCF8cp6BVHQUMYwPOYY51oyQplKYR52MUH0I3dWyXyiOFhVFfsgX7dUs8paQ488h
         4p4hjoJq2wlAXts0yzw7TuVDlYGVUPPsJWqbI/WMhNI8nA6zRq9CVuG/rZqXJ5OurY4e
         cH3CrO0J+fxlGCUhZ15eLnUKrneLmoNjORiW4lVaEYYtkg7lTPqltiwLYDJ21+29e9Ew
         nT7T6Cq460rIWcBiOptE0quttLpJHQjx7oeJ/YhXV+RNco93WbTPdgsisB5bPHT9N6nU
         SwN8jItFI86Le0f22wEhxyjoflOS0jhiOG89LCSoLKRK2alkKgjFvceh7owqq4jgsFpA
         ryMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=0A+o//LrYgYgbZiXith201cPHPBQpFD9Rvam+3jXqNs=;
        b=OsXkwHSblZETY1hVTQQ6Nvcl/csoXEI3Mf2FEOdR4t6PLSl1FioMRGdSKeW3P1NPUO
         8WXgLpCAofGJ7SD9R4/sfi9kBIi6tp2WdxyZ2OwYNRi1ClD3+etXieLVYfYDke7lDT8t
         qSBM9oKwth+2Z0Bnf53HOBuAh5fABFvh9gm06AVpI5DKTSAor9C2wzPW6eud9hCoaBDd
         eetLi9MPf1nv90892vkQprjKoQKUXbCP2tdlov71cMrIcIn8Z3OXZjqXDKYsctWDTmQK
         jYsfX/833lhbHO7EdG5Fm9nSBQZMQg4wuy+hdJZXEiQuezjAe1urtspw8FzltjjSAiQM
         OmXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
Received: from relay12.mail.gandi.net (relay12.mail.gandi.net. [217.70.178.232])
        by gmr-mx.google.com with ESMTPS id ce26si991984edb.2.2021.02.08.11.34.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 08 Feb 2021 11:34:39 -0800 (PST)
Received-SPF: neutral (google.com: 217.70.178.232 is neither permitted nor denied by best guess record for domain of alex@ghiti.fr) client-ip=217.70.178.232;
Received: from debian.home (lfbn-lyo-1-457-219.w2-7.abo.wanadoo.fr [2.7.49.219])
	(Authenticated sender: alex@ghiti.fr)
	by relay12.mail.gandi.net (Postfix) with ESMTPSA id 863E5200008;
	Mon,  8 Feb 2021 19:34:35 +0000 (UTC)
From: Alexandre Ghiti <alex@ghiti.fr>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Paul Walmsley <paul.walmsley@sifive.com>,
	Palmer Dabbelt <palmer@dabbelt.com>,
	Albert Ou <aou@eecs.berkeley.edu>,
	kasan-dev@googlegroups.com,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org
Cc: Alexandre Ghiti <alex@ghiti.fr>
Subject: [PATCH 4/4] riscv: Improve kasan population by using hugepages when possible
Date: Mon,  8 Feb 2021 14:30:17 -0500
Message-Id: <20210208193017.30904-5-alex@ghiti.fr>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20210208193017.30904-1-alex@ghiti.fr>
References: <20210208193017.30904-1-alex@ghiti.fr>
MIME-Version: 1.0
X-Original-Sender: alex@ghiti.fr
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.70.178.232 is neither permitted nor denied by best guess
 record for domain of alex@ghiti.fr) smtp.mailfrom=alex@ghiti.fr
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

The kasan functions that populates the shadow regions used to allocate them
page by page and did not take advantage of hugepages, so fix this by
trying to allocate hugepages of 1GB and fallback to 2MB hugepages or 4K
pages in case it fails.

This reduces the page table memory consumption and improves TLB usage,
as shown below:

Before this patch:

---[ Kasan shadow start ]---
0xffffffc000000000-0xffffffc400000000    0x00000000818ef000        16G PTE     . A . . . . R V
0xffffffc400000000-0xffffffc447fc0000    0x00000002b7f4f000   1179392K PTE     D A . . . W R V
0xffffffc480000000-0xffffffc800000000    0x00000000818ef000        14G PTE     . A . . . . R V
---[ Kasan shadow end ]---

After this patch:

---[ Kasan shadow start ]---
0xffffffc000000000-0xffffffc400000000    0x00000000818ef000        16G PTE     . A . . . . R V
0xffffffc400000000-0xffffffc440000000    0x0000000240000000         1G PGD     D A . . . W R V
0xffffffc440000000-0xffffffc447e00000    0x00000002b7e00000       126M PMD     D A . . . W R V
0xffffffc447e00000-0xffffffc447fc0000    0x00000002b818f000      1792K PTE     D A . . . W R V
0xffffffc480000000-0xffffffc800000000    0x00000000818ef000        14G PTE     . A . . . . R V
---[ Kasan shadow end ]---

Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
---
 arch/riscv/mm/kasan_init.c | 24 ++++++++++++++++++++++++
 1 file changed, 24 insertions(+)

diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index b7d4d9abd144..2b196f512f07 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -83,6 +83,15 @@ static void kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned long en
 
 	do {
 		next = pmd_addr_end(vaddr, end);
+
+		if (pmd_none(*pmdp) && IS_ALIGNED(vaddr, PMD_SIZE) && (next - vaddr) >= PMD_SIZE) {
+			phys_addr = memblock_phys_alloc(PMD_SIZE, PMD_SIZE);
+			if (phys_addr) {
+				set_pmd(pmdp, pfn_pmd(PFN_DOWN(phys_addr), PAGE_KERNEL));
+				continue;
+			}
+		}
+
 		kasan_populate_pte(pmdp, vaddr, next);
 	} while (pmdp++, vaddr = next, vaddr != end);
 
@@ -103,6 +112,21 @@ static void kasan_populate_pgd(unsigned long vaddr, unsigned long end)
 
 	do {
 		next = pgd_addr_end(vaddr, end);
+
+		/*
+		 * pgdp can't be none since kasan_early_init initialized all KASAN
+		 * shadow region with kasan_early_shadow_pmd: if this is stillthe case,
+		 * that means we can try to allocate a hugepage as a replacement.
+		 */
+		if (pgd_page_vaddr(*pgdp) == (unsigned long)lm_alias(kasan_early_shadow_pmd) &&
+		    IS_ALIGNED(vaddr, PGDIR_SIZE) && (next - vaddr) >= PGDIR_SIZE) {
+			phys_addr = memblock_phys_alloc(PGDIR_SIZE, PGDIR_SIZE);
+			if (phys_addr) {
+				set_pgd(pgdp, pfn_pgd(PFN_DOWN(phys_addr), PAGE_KERNEL));
+				continue;
+			}
+		}
+
 		kasan_populate_pmd(pgdp, vaddr, next);
 	} while (pgdp++, vaddr = next, vaddr != end);
 }
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210208193017.30904-5-alex%40ghiti.fr.
