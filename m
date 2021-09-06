Return-Path: <kasan-dev+bncBC5JXFXXVEGRB3OZ2WEQMGQEQBLUSFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id DE469401298
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Sep 2021 03:20:46 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id o32-20020a4a95a3000000b0029018f4f7c3sf3556515ooi.22
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Sep 2021 18:20:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630891245; cv=pass;
        d=google.com; s=arc-20160816;
        b=I6H/g5Y8ybdH7SeezthMFfpUOnJgIbRc1OslyXz4Yai1WhRc8al1JKVz896w1biUEj
         T7T5oRqeJDZQVHd93F8pd+LfdbNMnFZJKajisJOpIMXg+sJpesgTQ/CGe9Ijpc/XuSIw
         63pZHtheg5+87qp/nkwjglvlbJ7Ebwlq9jyWGhAvZMfD0R5cnfazbPtN4/eQnd4Evw53
         5JGqgYOnaDKaiy8IMuHYaXUkDQn3Yg7VDhi2/sRzFybilJ9HAty+7ve/70W45c50s4ua
         6fBy2VRgfGJSm5mhQz4TwTuYearHa7OtgyhpjKsGh/oSOPBlAkkKthMm3EpTvUXXFgfC
         vanA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hr5i54RjReYhlW+cHiU4FeA1yQw2RQUT1DsuQeh9GEE=;
        b=kdFxxQ1cwlyhfgMsdeNBPswPv4Q/rIa5MJpHC1WJmxTUj+ueCIsTu7GMNRc9Wwms+7
         bwR+qfohdG2h+IYOaSKQfANfXhWXEEKyRPbsRqor9CP3xImXfRJZ0kfj3SL/MgroGACr
         sQG8hjyBQCGcZnk4hHJqc8ZPEBZgSz7unK3B9v+n6ngYYBBj2i7sF1u4m8bupYYdEFES
         drNww95s8hSTXgE+K7xIO4iZ8vQXN953cL2Q7a+8dvRGpyufR1lXIqE3xefLC/wQUcn1
         7bCuMti+i6Z3FOGgRUXK84V0QiD6TBGkzOrpzhLoiVTM3mcEjLZmOWIGmrsg+HpYNsPP
         xjAA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Icy1ps6G;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hr5i54RjReYhlW+cHiU4FeA1yQw2RQUT1DsuQeh9GEE=;
        b=A5YxtX8HEt3RxpMANYynL1MImhDj30i5JtNJ5V7jz2ruKg0VYRVB4QdRJ7gftzkVyp
         WpNAz7zpqNblYB/azyYoRrI/15Gg1dmqYOZWPyY7Bgqcji/F/rGa3M0l8P+br/TTFKJe
         fuQCSj/fubc2Ck28EeOaE+adEwq5IW1tdYcxGMgAorLb6aazBwj9qeJZ7cPAadpYTvsR
         uZlL1fQ2TTSCNSX27TMvIUcFahaxfhsMXsF5aZgd+oJh7FKVn2dmKggyb5HZEPO2OFLE
         fQrHkKWm3tu14zypbhQ3kVcIf3sGZyX2KEDRTjqSctpiqgx6IZ536PYCJ2qyc0zCNxur
         h3+w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hr5i54RjReYhlW+cHiU4FeA1yQw2RQUT1DsuQeh9GEE=;
        b=BGFP3TPzD/1PHlDGlgnbOjCRTAAINloJuhotuWqMii+AgTAlAJp/WLMc/72NAnJPiI
         WRyrBqETCAQYfw3nUX8Ve7eMELhSxS31nfON00SUjNY0NTDaxzngiQoNwTsLqd7vlOau
         UIHN8L2ILNONJjGul7TeLcKUKGb2809D+adfhUMpDfYjciYXV/e9wTAzdOEXBkfgIUZo
         /d7vscI7CjYGquEhBAjpnQLK1qepLeQwUKT1wmU8FzWzkeylOQvHySA9/mkw9gU40XW8
         NiSEfieOYbBjf65AKNoND/3uF7UObP0trG10g6l/il7rNt3n4FE/QYcjyNMwLcgy2P3Q
         JzSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5311jvglV/cuEIloneZ0uzJ+k7ZpN2/ZLcD0uU8dCmKPtHq4RHdf
	4/RDNcrnKiQK6KEf7wJJXrM=
X-Google-Smtp-Source: ABdhPJyVFRJaSqgWddplqA+Ph6FEJEImIG+Ys3lH9iqwh5FhFLOhwSBIyhwXjLdgu8DxTGS7/WRXfg==
X-Received: by 2002:a05:6808:2204:: with SMTP id bd4mr7059573oib.108.1630891245493;
        Sun, 05 Sep 2021 18:20:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:66c4:: with SMTP id t4ls1330877otm.5.gmail; Sun, 05 Sep
 2021 18:20:45 -0700 (PDT)
X-Received: by 2002:a05:6830:4b6:: with SMTP id l22mr9131233otd.129.1630891245054;
        Sun, 05 Sep 2021 18:20:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630891245; cv=none;
        d=google.com; s=arc-20160816;
        b=W+p3JfysmmAD+WUFgD/yU945eEQeD9amHWU8vbiWvkIOHGWgtWpIjwvmLZlhEO6Kao
         aSWCqDnSptftMV77OQeUCRNPhsUhoExTmjy/ZzOops7MUG1EyTsp8OD8gNtni3rjvdwa
         ZdDb+K1IVMU+shtIoUg8LGosGb5l9htN3NSpddoYoGzLQzM2FyruYn8jBjWFeB683gkm
         BypAN2GJutZuoLSe0taUOANxkD+fxSl4voBsS5gi0wpyksPY3ST/+sdmB4YjTX9rKACQ
         7V01HfN8QuU3W/kVmHLfjASOe6rZy5FwHQCh85hXZxfQRLToet0y3zTg0tHETcAa2Ehl
         Bpzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XOnEGtTtmqHaMTLHwq2UKO3CWF4vA/SmI4KDyIeemgE=;
        b=NSY7EPj+fbl/xD4e5PW6tE0BkZKC9lU9jumtBmxoajFfPar+2WOcbKbCttd93/w+L8
         WanePmKq/d6x3Ml+BJdvfmqeu687TqawyDf9OyGLviTmK/gqzjVeUDIfBX/AgURD2tXd
         bcxe4uNWDpzhdbVFc099/G6baLF2ROB4HAl7eE55hYVtokeTOpOLt1Cb+fKUrKrEIR33
         FbU/J/8JPz9WtUEui4Adm3wf/AIpXRMh17jxnHREQnzYoKTJaiCRcRPIadxKihU8YVo+
         JS7sY9ctc+EUyHgE3jnpWOWDdDk5IsoDAwqPBt9GFh55yeMQODOFPa0ERueWOhtddzkj
         omkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Icy1ps6G;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id bf14si269860oib.0.2021.09.05.18.20.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 05 Sep 2021 18:20:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8719861054;
	Mon,  6 Sep 2021 01:20:43 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-s390@vger.kernel.org
Subject: [PATCH AUTOSEL 5.14 42/47] s390/kasan: fix large PMD pages address alignment check
Date: Sun,  5 Sep 2021 21:19:46 -0400
Message-Id: <20210906011951.928679-42-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210906011951.928679-1-sashal@kernel.org>
References: <20210906011951.928679-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Icy1ps6G;       spf=pass
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
index a0fdc6dc5f9d..cc3af046c14e 100644
--- a/arch/s390/mm/kasan_init.c
+++ b/arch/s390/mm/kasan_init.c
@@ -107,6 +107,9 @@ static void __init kasan_early_pgtable_populate(unsigned long address,
 		sgt_prot &= ~_SEGMENT_ENTRY_NOEXEC;
 	}
 
+	/*
+	 * The first 1MB of 1:1 mapping is mapped with 4KB pages
+	 */
 	while (address < end) {
 		pg_dir = pgd_offset_k(address);
 		if (pgd_none(*pg_dir)) {
@@ -157,30 +160,26 @@ static void __init kasan_early_pgtable_populate(unsigned long address,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210906011951.928679-42-sashal%40kernel.org.
