Return-Path: <kasan-dev+bncBC5JXFXXVEGRBCW32WEQMGQEHKUD5GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B9A240130F
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Sep 2021 03:23:23 +0200 (CEST)
Received: by mail-vs1-xe3c.google.com with SMTP id i2-20020a67e2c20000b02902bae9a0967fsf1587702vsm.0
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Sep 2021 18:23:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630891402; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xeyo0faEOInhj0VGs6245vjuVeLJ0vazbSN52zCnPDd8BuEKFX/4gNaOwXrp3ZFE4x
         TQGJyRnSn35/mprJup1rKKFkkbWvqOOk5hPEvtaLwo/cIg0lC43eG0CQagITPFdMmVv2
         Mrae9GAWrKIZFf1XEtaiej1SzOfNmH0Cd9XX1whJNgoGKF/lBQ9D1Q2IX+l6D50bXplD
         FrDAv/pAasATq18yegTmWtKyIp6lwmk82YPEPFGDW2VCoVzSBRGyDkwQfctsRwUiOaWc
         vufG+/zSEtu2xNshc63OyFTX3BrQ+1zGRxBJM5UnZWcKTUzj2dd9VlCvEJx5oL1wgFor
         iGgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=U9YoEB4XS1er3E9DfutDg+RQYhs6EgUu1CIcKH5ec+M=;
        b=ut1uKqgg/pOrvwPim5kBtWQFFABgKi2NDAa0E9UGYAmjqdWvM2e9jX1fyJXkHdFKv7
         kG3crlTfl3ysYBtcEmDtzIgQiJXoQCJFd9KN0Ti0BjELedg8DVAd8vOQqQuMv5i6L9rL
         M4+EeJI9uMK6FJAUAK/btAkZroY03+qqiA/Mo91G31gOueUjYAywAkfvea70A3EikcVT
         IKzDW4sh3OCtX0l/htECYu0Kd3Ja8V95AblsazsZA9i/XflhK+o5o4Y2AnUHinALgGwz
         i0fKemuOLapiZ+GpvPOGG6XHUfYo0UGwoJkTM5EOAj1Ph+uNRNXVAYofBMbacFEZ3eV4
         2FcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M8gkruqE;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U9YoEB4XS1er3E9DfutDg+RQYhs6EgUu1CIcKH5ec+M=;
        b=lEEvBH9nRRg6WceH1nW8XaXNfBKcD6rNwn2/JM+Q1cnls2qKz8s1TxcSv7ZqmgH8hz
         1hMRMvcr4jYfRcvRkwGGNeTrXoKBHznI9N1wkFNew63oJiAJ4BXxrH02UtV35TQSOFe9
         xIi9ap/RkoGO6vcqyzNPLruSTgHPK8GoX/ZIsQNRkyy0uPeMWohis50fwjby0JA86AH/
         bVfxwaWUghtK3b8DgOe9qbr6mxhxxWMOn7oHn1ohN/kDqb96GW4zXsVjHXtFPUFx3GAE
         mmZr7mj+8xtjYUJiM0IKYmcEdAEoAvN4kO3FMsgbjQvgQ+cNouUZ1V5vPxEsc7lLNgtU
         Lz1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U9YoEB4XS1er3E9DfutDg+RQYhs6EgUu1CIcKH5ec+M=;
        b=DWoU9a4kJjfzdchZptNNvv61nYDSnXLFVMsdCRGvDsCm2s80lGfgIi5mrQ3xAgb4lO
         ryw0bZgbr9GXNumg4j0alaBe3ZbeOIfR6RwtCWwtKbFLNGl5STXUZ1Z8vAokGK0e+Crh
         Oe8kLW8QZWf+y908Nt3TR/e5mNEQKYlFTrQTu0zJ1yZeqmyGazqb8MKG1jyErZioOksZ
         tprsOWC0Fq/5zZWuMAtoiFj9awyPOvCSiradVywcTg5cM0o7sLXlwPyr8FK/gHyBg/e6
         w6ttlkDnJim3chwQCrpfekLAXYVQh2cIAex9lqrPyiopblz3YZxVenspG4UOwCNd6Q3M
         1ZNA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533TOHjfhq5Em5y351uFfbqHuv0nAS2bAJZoCsuYrgfRrwx1Rynd
	NiSZl7ADf14dD65xjneCdWc=
X-Google-Smtp-Source: ABdhPJzkD0eYaqd4t2PnAZItgHnPC/kLLvcq15bjkZ+pLTSbDJ1Ey6lPCV+xFMQTK7qVrJMaaexjQA==
X-Received: by 2002:a67:6bc6:: with SMTP id g189mr3129021vsc.28.1630891402385;
        Sun, 05 Sep 2021 18:23:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:7e8c:: with SMTP id j12ls379897uax.7.gmail; Sun, 05 Sep
 2021 18:23:21 -0700 (PDT)
X-Received: by 2002:ab0:3255:: with SMTP id r21mr4507244uan.46.1630891401781;
        Sun, 05 Sep 2021 18:23:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630891401; cv=none;
        d=google.com; s=arc-20160816;
        b=CJiuhMrbDA25x1SMxph+Rvp2yi+I7uHASzuXnL2hJ9xnJkwpqK5tXrnpq/gXQIqPDI
         FBc8Q78uakxHIwEUgiaqsSd3WnZppuHOCnCxesBLsohMVucuF2MpZFSuduVVqgVgyj/W
         ekgvGmXh4CKxgv6cB1r0U3yGqikDLZ4ubrUTkci8ESj0ZAxgV3xF+IRPtMBkiqJ/zEGh
         cu5/qAp0Uivm1AO4RQJLpDDutmzj88X2W0M35j4wluuncRY99KkiOgcGtMBsqB2NRmzE
         MNRgRuxH34VOidyqG4BC2yGnj10t2p60efOSJcf9fI/Y2/K6sgFKNnKP9Cty2poUdHmk
         /gMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JAEa4Lg7jrj4DHAGLY3MFK6muTGUA0pZYgn/g8Yyod8=;
        b=DN6L8JcyCkQsDdUmEos7b43raxo+IQZXsJ8cGGzNeo3xz/inGmauC6BE03qGDYAy43
         4F6PddGJuJaep+Jgo1j6EesAYyLpHcZ73Q3FvOtRCc/c9WrjSLSu/UrkkK4WFci8um6G
         QERC1fchebD59+5t4h2FcEqJuTor/6WLEUq4CRM+KqX2HGmPlE2h9vJnSaX+l3RpOKFv
         y0WpHzNJOO3izw/6PepkJ7WQQe3npa1wgVdzKr+UT4XDUgsg7Sv7XZtEHOa+ejhgTYqs
         p5+0Hhn5EO0k8Bg9Vf8NyhJfOdXXYInFA3uK9iCCeiPYyZbjdAIEWdCCxrDIX+GlCrAE
         aBeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=M8gkruqE;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f23si322194vkf.0.2021.09.05.18.23.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 05 Sep 2021 18:23:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DC16D610CF;
	Mon,  6 Sep 2021 01:23:19 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-s390@vger.kernel.org
Subject: [PATCH AUTOSEL 5.4 29/30] s390/kasan: fix large PMD pages address alignment check
Date: Sun,  5 Sep 2021 21:22:42 -0400
Message-Id: <20210906012244.930338-29-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210906012244.930338-1-sashal@kernel.org>
References: <20210906012244.930338-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=M8gkruqE;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
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

From: Alexander Gordeev <agordeev@linux.ibm.com>

[ Upstream commit ddd63c85ef67ea9ea7282ad35eafb6568047126e ]

It is currently possible to initialize a large PMD page when
the address is not aligned on page boundary.

Signed-off-by: Alexander Gordeev <agordeev@linux.ibm.com>
Reviewed-by: Vasily Gorbik <gor@linux.ibm.com>
Signed-off-by: Vasily Gorbik <gor@linux.ibm.com>
Signed-off-by: Heiko Carstens <hca@linux.ibm.com>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 arch/s390/mm/kasan_init.c | 41 +++++++++++++++++++--------------------
 1 file changed, 20 insertions(+), 21 deletions(-)

diff --git a/arch/s390/mm/kasan_init.c b/arch/s390/mm/kasan_init.c
index 460f25572940..5182e0836ca7 100644
--- a/arch/s390/mm/kasan_init.c
+++ b/arch/s390/mm/kasan_init.c
@@ -101,6 +101,9 @@ static void __init kasan_early_vmemmap_populate(unsigned long address,
 	pgt_prot = pgprot_val(PAGE_KERNEL_EXEC);
 	sgt_prot = pgprot_val(SEGMENT_KERNEL_EXEC);
 
+	/*
+	 * The first 1MB of 1:1 mapping is mapped with 4KB pages
+	 */
 	while (address < end) {
 		pg_dir = pgd_offset_k(address);
 		if (pgd_none(*pg_dir)) {
@@ -146,30 +149,26 @@ static void __init kasan_early_vmemmap_populate(unsigned long address,
 
 		pm_dir = pmd_offset(pu_dir, address);
 		if (pmd_none(*pm_dir)) {
-			if (mode == POPULATE_ZERO_SHADOW &&
-			    IS_ALIGNED(address, PMD_SIZE) &&
+			if (IS_ALIGNED(address, PMD_SIZE) &&
 			    end - address >= PMD_SIZE) {
-				pmd_populate(&init_mm, pm_dir,
-						kasan_early_shadow_pte);
-				address = (address + PMD_SIZE) & PMD_MASK;
-				continue;
-			}
-			/* the first megabyte of 1:1 is mapped with 4k pages */
-			if (has_edat && address && end - address >= PMD_SIZE &&
-			    mode != POPULATE_ZERO_SHADOW) {
-				void *page;
-
-				if (mode == POPULATE_ONE2ONE) {
-					page = (void *)address;
-				} else {
-					page = kasan_early_alloc_segment();
-					memset(page, 0, _SEGMENT_SIZE);
+				if (mode == POPULATE_ZERO_SHADOW) {
+					pmd_populate(&init_mm, pm_dir, kasan_early_shadow_pte);
+					address = (address + PMD_SIZE) & PMD_MASK;
+					continue;
+				} else if (has_edat && address) {
+					void *page;
+
+					if (mode == POPULATE_ONE2ONE) {
+						page = (void *)address;
+					} else {
+						page = kasan_early_alloc_segment();
+						memset(page, 0, _SEGMENT_SIZE);
+					}
+					pmd_val(*pm_dir) = __pa(page) | sgt_prot;
+					address = (address + PMD_SIZE) & PMD_MASK;
+					continue;
 				}
-				pmd_val(*pm_dir) = __pa(page) | sgt_prot;
-				address = (address + PMD_SIZE) & PMD_MASK;
-				continue;
 			}
-
 			pt_dir = kasan_early_pte_alloc();
 			pmd_populate(&init_mm, pm_dir, pt_dir);
 		} else if (pmd_large(*pm_dir)) {
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210906012244.930338-29-sashal%40kernel.org.
