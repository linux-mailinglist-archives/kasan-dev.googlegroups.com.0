Return-Path: <kasan-dev+bncBC5JXFXXVEGRBK622WEQMGQESKLIMPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 006444012BA
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Sep 2021 03:21:48 +0200 (CEST)
Received: by mail-oo1-xc3c.google.com with SMTP id k6-20020a4ae286000000b00290b373626dsf3588814oot.6
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Sep 2021 18:21:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630891308; cv=pass;
        d=google.com; s=arc-20160816;
        b=0TveJ9oNMY8D0aYP9G7aaZhFuHS8CrlkL9AfXfJkoOhJVxz6PTMeB+Jt2xjP+EMcOp
         CIf1T5CQoKBMRuJ41NXb669iSfEpw7KjrY/bPr86KzInYx7MwEL2Etch2SIjaft7Q+IG
         S6q09hOSvmKwOrasots256ntwf9pfPM30xptSNyCfYU9LG8r78iEJ8LvCLZoqKiygwsm
         Cw62p2S1SJG5BeCkwKx0oLCZNq+r+6UixtWtv4Z4RN/w8D+KiRB8Y46UzCV+LaEJ3v8h
         uWdDACfl0786nyUt+mml+0LigsNiBm1Oo9Po1WWS0q11PahspPsVPd1jdFpwpYHwJ60/
         ZO1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=jIcZV0UF1WWlhuypvtcnmFyIUdDRcQjG66U5vBtPyuM=;
        b=QNb9BJ49pMtPebueYn8XMZ5f4PxGaZl9/NNdJs9ug/88yNHQ6No/0ItHHl8VXxnsYQ
         2aTdrpFbBpx7qqMBU0DjuUsgSERZQW5n9X7BT1F/YWwWQpAVihCa3QLTAuNZkblag0mv
         782UtO1YDBWKr5LOy7SrNrundXjsT/l3qiel0mPFEAgRqi+r3X/lKyTdiw/+GwphSoDG
         a+LTO3nRRDruvD7WbC6/dNHPBQ3bE00FN3DcWRD+294iJhqq1B6ccNf24jb8uD+y56aA
         j2WDp0+Bft8wcRS5z5LvlmKL3eNTLWZqiyt9op/51xCA/AfeasUqW8Lt0KvkDfMn1Rgn
         nNGA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BgbDl2mQ;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIcZV0UF1WWlhuypvtcnmFyIUdDRcQjG66U5vBtPyuM=;
        b=EJvTP7K8L7O+lEeR7Db0dJd6rBA0CpI61BRKo+cyQuYvYsFrA6y4kcLkuui5mq7ax6
         dTNgA8fVj7KU6WM2u4RE3NgOIXDWkRvoi+r8Tns8lIScSDZZJDwpgVJuCb0hDB+3yDGL
         b14OQPViyu6MikrEUV0ZZ50h8pePd2REE+eOKKrNR7MtEoicsTzMKee5PB0f9cAw1X4/
         EIYMSKC+9AvOfY8yTtGUZEVvVrAUPxJBvEv6yVkRUq8/Sc0Axpo1Corzc3l+PtaCd9Ty
         0VIxXZp28TbiGcnMn8gHTwc1jSAt9qASUpG3gWisLrGXWiJTgR7MegZrG2cuUticV9w6
         fmzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jIcZV0UF1WWlhuypvtcnmFyIUdDRcQjG66U5vBtPyuM=;
        b=EFl8VobJCrXRSuRBcQruQLRGtwdlBYldw5WlJlLT6/iJhN6W4jyD3SJY2t4kGmU24M
         n4Sh5fuJY4CKFaRhe+ZV/+2vszO2I+Lt2b6UYgyVcAY267hF5gMJLV9d1mvCOEpn3Spw
         dTKzBfpv2JHeiK3ir8pS7hz1JRM2a0qoUiyOW2Y8y4mnXjDjHJs9xXY05MyX6OACrrER
         MkXzDbTv7EGQy8mVjv9Uncve5YbNSWs4FE0fD4vdFojk70ZznZ1XuUcfALELXmTCEuHp
         aFZA5eFs3jzOdKsUplA21FT9apb9eie6GcPsgykzPe/QSk7NW6j3knjLLOJv7ap1uvxt
         rBKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532hsqOabbo7ZUnTWaIx9YeOA7QPH7/sXdMBx8AX1tEwZQJEJd/g
	gHsatzKe/VH8sCfiTqs6Fpw=
X-Google-Smtp-Source: ABdhPJzC1XzFcEwL0d0Uf8Q3sYHcAsQp8K8eC6sH6SnJSVZ0UhJnifsfgyreHYEMLqZ8X4LKoxnvZQ==
X-Received: by 2002:a05:6808:1414:: with SMTP id w20mr6689833oiv.17.1630891308032;
        Sun, 05 Sep 2021 18:21:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:11d7:: with SMTP id v23ls1335776otq.2.gmail; Sun,
 05 Sep 2021 18:21:47 -0700 (PDT)
X-Received: by 2002:a05:6830:1f0a:: with SMTP id u10mr9152956otg.53.1630891307685;
        Sun, 05 Sep 2021 18:21:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630891307; cv=none;
        d=google.com; s=arc-20160816;
        b=zopzar2VC7wxGWrPvCEaYVHBfJhbN7FrY5ODksXOC/Aod3xp8IZGNNJv/IKMqSacer
         8Gy3ONnd/+rTERaZpjKX/vnvv3eGfBoEXdKpfEWz31+mJwibB1a4c8KUW/Q19vyHn22W
         960cVtNdUvDqefIkn3PIY+CAchzXTj9rCY5hguOvm3mO0zP1/DTKS2l/Rh8U3UPygvl7
         Lq05WNclzLdgXHskyGZW42CCJJFdkd1SEK+ylayUZOqMYL1sLf/C+LPiJuyaYFm0pqBu
         SVIWpDsQvdbkLRFLVxnB61LZak1egJ976odlkAnt77+edLmKN9E1swBgqPIHb0JqWysw
         xy+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=XqZb+6GeX5ehpKRdeODgZJspNBNVG93TkKFbXFGMq1Q=;
        b=nZwQk/c3AxMjy0B2hYpInzaF8AdLTRYMyx6tIJju4HN7+7xhuZieGhTJpDc8VaIf+q
         W0vUnxw+F3sy17sLv9PEM39l2ROchSf87eP84gFtg39e7eY1GzlY/4pkJradjxHzJi12
         zJWBJnNWLxG+990MHVWCYoRch2z8bmRUjFbGIrdnGuluy+Tkc/evrj3y/CwfD/jySkbD
         zi1lRKKy57eTFT29mIH5AMlyX6859k4LwsKB0YC3pw0Vk2HkZ/wlbmklhRQ8qM53EhiK
         z0c0OjiIqSn+XPdla2s5x9Pg5Ls5waewv/X6Zg2iXcOaLIoj6tXGmL1zXtXU0HyRQRZy
         /+tw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BgbDl2mQ;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h24si379609otk.1.2021.09.05.18.21.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 05 Sep 2021 18:21:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 22186610A1;
	Mon,  6 Sep 2021 01:21:46 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-s390@vger.kernel.org
Subject: [PATCH AUTOSEL 5.13 42/46] s390/kasan: fix large PMD pages address alignment check
Date: Sun,  5 Sep 2021 21:20:47 -0400
Message-Id: <20210906012052.929174-42-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210906012052.929174-1-sashal@kernel.org>
References: <20210906012052.929174-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BgbDl2mQ;       spf=pass
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
index db4d303aaaa9..d7fcfe97d168 100644
--- a/arch/s390/mm/kasan_init.c
+++ b/arch/s390/mm/kasan_init.c
@@ -108,6 +108,9 @@ static void __init kasan_early_pgtable_populate(unsigned long address,
 		sgt_prot &= ~_SEGMENT_ENTRY_NOEXEC;
 	}
 
+	/*
+	 * The first 1MB of 1:1 mapping is mapped with 4KB pages
+	 */
 	while (address < end) {
 		pg_dir = pgd_offset_k(address);
 		if (pgd_none(*pg_dir)) {
@@ -158,30 +161,26 @@ static void __init kasan_early_pgtable_populate(unsigned long address,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210906012052.929174-42-sashal%40kernel.org.
