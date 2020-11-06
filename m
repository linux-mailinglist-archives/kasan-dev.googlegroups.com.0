Return-Path: <kasan-dev+bncBDE6RCFOWIARBNM5ST6QKGQE5ZC66TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id F36012A91CD
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Nov 2020 09:52:05 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id 2sf227031ejv.4
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Nov 2020 00:52:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604652725; cv=pass;
        d=google.com; s=arc-20160816;
        b=sPWiCm8gQ6t4VRnZqAHFCjYnIgeUR3YggnB03mkTrOfhlWv0JihOCBE6+HLnotIluj
         P6SECeIozBwWgnE9aclcYXxJcdIPMgl6vVS/MEzMD3/0rOHGMFWZfor/8yJFqr0EJnBW
         Hv4FbxZnLiR/N0Ydb9wNAbgbZgi1ZnP9dXOmDB0YQNA9Kp9ZjwH2G4pdXjJlOdglTdvh
         hQ1625zszFTa2CLcx1s8+03MxumNjQaf/+WdhLmvyM8jkIUlEbqns6SvjZqzgXfno6TC
         yNGxcvU/t0jbQGGNnyBiQqCw4dCLqlzFCm0W/7KdFSjWlqfq3PwWMlHdhfgFPiDd5w5c
         8Q2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=qXPl9Z7vJ1Pj6t8ii8KUXPyWnnKHJgXi2uIcvi+7/7o=;
        b=ofO4MTf6R8BUEBy0gFnYf0J2mTC/FlOyppKlpUconMe1s7nmMQYT4rppKTEYoG+fnP
         PoSyK7e0LErclwBEl4rBbDHAkB0Us+3+KBrKgHv4QQeqixjzdKHYckBl2XPXiwGxZ1CT
         aNZSMWXNCyCTYHTKTF+SXQ6/UGBSCqbWqWVJSzMRsIQOxX0I8d51I6cWQEsRA8WEaSsY
         6Raq1P2kYPitnoQypctAB/UpqmEi01IxE9X8mY/yblY/9IKIInmZvDy+KuiceERLsweX
         Gsx0GQO+Zr5Kqt6D81kOiMwUZwKaMpqR1Xv3Eoi921oldXMOlqdm4uvgRzID6HlI19dQ
         HGow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=VtslIGpi;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qXPl9Z7vJ1Pj6t8ii8KUXPyWnnKHJgXi2uIcvi+7/7o=;
        b=T3fPxUS6TLxJdetmLXJFR4gWK4cI7erJojxa1O8AwDB8vZZgFmCNUFn3PkLuN/cVfE
         zrw3HbiMjraPypAp+KU952TrmFN0TvcF2nV0dZZgKO7NjaThRBT2yPjiQQcYxXg9sPBu
         iV9ksIBO/s2Zm3KODSn5czXk8xKy9jXpgiDy+53P24qRML6SJ4YwZJ4FT7MksbiK/HR3
         JnuZWbyR0WZhgb2Zlz+cy15eM1D9sBo4cOUq/NmziikyWL+YtT6cnyskYfE/mhxRHcpC
         lAXmqW3fLNB2s9W8NK1UZSGBWnpNxF6c09Nj7l8x9o8M1EueKuP+N/at4WXEZqqbmTsy
         615g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qXPl9Z7vJ1Pj6t8ii8KUXPyWnnKHJgXi2uIcvi+7/7o=;
        b=QmcjCWmm4mbzX7TTT1fkkUVqr1vFTDSIaUOQ9KSUgY8bvn24jZmhHZVVcrCWKdybl8
         yBPzSKvnSei8zRzli6j3Chpuze+CWypiZBwD/5OIA26QT2SBjPHgx1gJlCRLrz+nquLB
         lwq5mwBCRRri37bocYs6GL09yUy7X5cY9gxls+/ZAE4R/uhJqw5eGo/A8FEwznqWkSVa
         TI4g/VA6e7SfYanZQWf3Ti1JvTVO0X2OD/VugcfcggHPCETpzz92RvX3V+7wsk2uaW5n
         ODj5BLFK/Y3PFuGjgTFXBbnxB7sRjQDk8TUvyzyn2kq9PX2dhvGp1ziuSL9UBuNffw+Y
         dTlg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533A7y3o+lAuak6PVjsz2566TUKpDz8BEPiUecDGtMdDsnNRa+QF
	BsTMmnaYj/pW+3dkCr9bYz0=
X-Google-Smtp-Source: ABdhPJwqeVyI+sJxu8XKWSLHtWJ997TyieiwGY9rKbSr48sJHZlv8ta0CKkxX+RLodOdBjpslgTRjw==
X-Received: by 2002:a17:906:c193:: with SMTP id g19mr1045204ejz.393.1604652725690;
        Fri, 06 Nov 2020 00:52:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:d981:: with SMTP id w1ls875374edj.2.gmail; Fri, 06 Nov
 2020 00:52:04 -0800 (PST)
X-Received: by 2002:a50:e442:: with SMTP id e2mr989544edm.186.1604652724757;
        Fri, 06 Nov 2020 00:52:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604652724; cv=none;
        d=google.com; s=arc-20160816;
        b=C025uzdQ/1XpRAiYYnphf3uNpH9wXo3ZS4y3Ur0E3Nkaq9AZTnaCx33A10nsorye6G
         QtRvZYwrOF8/F0MvB1PQai8w7wYClKT3NFpBdpLfN3B2QWsuj21bo8WABh9Or9gg0JF5
         9cEi7u1PrZOFwUJVjNt65+bLyPaChTT0sJ+4c506OrzURPNXETaunIEyO92MKcN/5SPk
         dzl2TCesB4DQJA8sYny8yp20TrOm6R0kkOdg0WUThZVdzIHRI9kZtYHpTLPH9ELEfDSk
         V92KN59iz26CZuYVKwbgji0sH2CCUxyFZvj45bhzoOSATWePfcEwjinRQzTJEnc45CKU
         qp5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=5/pXTcy5u/7G3oKv3kb10Umqape2ZIGHbYKgIyHnWys=;
        b=gkLL8dSYLUUQW1rdAR4Oti9bNQ3imnFi95pah1dR1jXSKV642q2ozuzSqUYy3xWrqd
         k/fZ/ZAypCSJXbDHIknLxGByAOaA5lz9tgtGuz4NkwOrhSV9DB4OapsK52n1FZtYlD0g
         0eEYlzxx4Hstdk8eK436pAb+omL50eUw5lS4L5Uhje003nDfAMfGDWsS44v9mMP0f2NC
         TrSn52VRfoTC3YD2veM2DvF98UN8bq24JM14JQQIeE7YQZZBg2/ZZcfgx3X2pVL3FVkJ
         xBOAm2aXX7awscGfHbhVBYkHgyPFijJSFTE/G0vCQoC8UqAaOflgbwXGnKHg7gS8Z/0C
         iyuQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=VtslIGpi;
       spf=pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id c11si18326edn.0.2020.11.06.00.52.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Nov 2020 00:52:04 -0800 (PST)
Received-SPF: pass (google.com: domain of linus.walleij@linaro.org designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id d24so548995ljg.10
        for <kasan-dev@googlegroups.com>; Fri, 06 Nov 2020 00:52:04 -0800 (PST)
X-Received: by 2002:a2e:2414:: with SMTP id k20mr364863ljk.257.1604652724318;
        Fri, 06 Nov 2020 00:52:04 -0800 (PST)
Received: from genomnajs.ideon.se ([85.235.10.227])
        by smtp.gmail.com with ESMTPSA id o21sm81201lff.265.2020.11.06.00.52.02
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Nov 2020 00:52:03 -0800 (PST)
From: Linus Walleij <linus.walleij@linaro.org>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com
Cc: linux-arm-kernel@lists.infradead.org,
	Arnd Bergmann <arnd@arndb.de>,
	Ard Biesheuvel <ardb@kernel.org>,
	Mike Rapoport <rppt@linux.ibm.com>,
	Linus Walleij <linus.walleij@linaro.org>,
	kernel test robot <lkp@intel.com>
Subject: [PATCH] mm: kasan: Index page hierarchy as an array
Date: Fri,  6 Nov 2020 09:51:57 +0100
Message-Id: <20201106085157.11211-1-linus.walleij@linaro.org>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
X-Original-Sender: linus.walleij@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=VtslIGpi;       spf=pass
 (google.com: domain of linus.walleij@linaro.org designates
 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=linus.walleij@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

When freeing page directories, KASan was consistently
indexing through the page hierarchy like this:

  static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d) {
    pud_t *pud;
    int i;

    for (i = 0; i < PTRS_PER_PUD; i++) {
      pud = pud_start + i;
      if (!pud_none(*pud))
        if (!pud_none(pud_start[i]))
          return;
    }
  }

That is: implicitly add i sizeof(put_t) idices to
the variable pud.

On ARM32 arch/arm/include/asm/pgtable-2level.h has folded
the PMDs into the PUDs and thus has this definition of
pud_none():

  #define pud_none(pud)           (0)

This will make the above construction emit this harmless
build warning on ARM32:

  mm/kasan/init.c: In function 'kasan_free_pud':
  >> mm/kasan/init.c:318:9: warning: variable 'pud' set but not used [-Wunused-but-set-variable]
     318 |  pud_t *pud;
         |         ^~~

Using an explicit array removes this problem and also makes
the build warning go away. Arguably the code also gets
easier to read.

So I fixed all the kasan_free_p??() to use explicit
array inidices instead.

Fixes: 421015713b30 ("ARM: 9017/2: Enable KASan for ARM")
Reported-by: kernel test robot <lkp@intel.com>
Suggested-by: Ard Biesheuvel <ardb@kernel.org>
Signed-off-by: Linus Walleij <linus.walleij@linaro.org>
---
 mm/kasan/init.c | 16 ++++------------
 1 file changed, 4 insertions(+), 12 deletions(-)

diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index fe6be0be1f76..3c74c30996ef 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -285,12 +285,10 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
 
 static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
 {
-	pte_t *pte;
 	int i;
 
 	for (i = 0; i < PTRS_PER_PTE; i++) {
-		pte = pte_start + i;
-		if (!pte_none(*pte))
+		if (!pte_none(pte_start[i]))
 			return;
 	}
 
@@ -300,12 +298,10 @@ static void kasan_free_pte(pte_t *pte_start, pmd_t *pmd)
 
 static void kasan_free_pmd(pmd_t *pmd_start, pud_t *pud)
 {
-	pmd_t *pmd;
 	int i;
 
 	for (i = 0; i < PTRS_PER_PMD; i++) {
-		pmd = pmd_start + i;
-		if (!pmd_none(*pmd))
+		if (!pmd_none(pmd_start[i]))
 			return;
 	}
 
@@ -315,12 +311,10 @@ static void kasan_free_pmd(pmd_t *pmd_start, pud_t *pud)
 
 static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d)
 {
-	pud_t *pud;
 	int i;
 
 	for (i = 0; i < PTRS_PER_PUD; i++) {
-		pud = pud_start + i;
-		if (!pud_none(*pud))
+		if (!pud_none(pud_start[i]))
 			return;
 	}
 
@@ -330,12 +324,10 @@ static void kasan_free_pud(pud_t *pud_start, p4d_t *p4d)
 
 static void kasan_free_p4d(p4d_t *p4d_start, pgd_t *pgd)
 {
-	p4d_t *p4d;
 	int i;
 
 	for (i = 0; i < PTRS_PER_P4D; i++) {
-		p4d = p4d_start + i;
-		if (!p4d_none(*p4d))
+		if (!p4d_none(p4d_start[i]))
 			return;
 	}
 
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201106085157.11211-1-linus.walleij%40linaro.org.
