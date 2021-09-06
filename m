Return-Path: <kasan-dev+bncBC5JXFXXVEGRBXW22WEQMGQECMJBZLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id EB8614012E8
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Sep 2021 03:22:39 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id c27-20020a05620a165b00b003d3817c7c23sf9287716qko.16
        for <lists+kasan-dev@lfdr.de>; Sun, 05 Sep 2021 18:22:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1630891359; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zk9b2XuubYhA9yWD/yzDwTjahNBimVExz7bXbj86W4mVpJyjXQch1YvMEQUXDmrFoZ
         xL7a/2KvgL3extIX+7+9X7rMjJeKEJDSt/aKhg8lbkHDxMDzstAPhXrOEbTWijU3ZqPe
         8ZZ1xc3G5k/CveLTUmpga5/c4pYJ9cU26I2AGF7bT9tpVqwsyBil55dPoNHXDWLK/yby
         rbGnmKokycss6okrqzgU4ij3w3LgC7I717CsY+9+0uqyjTxM1j/yrsV4sREtrLWpNoHV
         rz1ja7l9IRA0TELa2Jlb42FyoiE5ibPQt2S7E1djLl1NQE/qcSmf5ofprGA2cIsRc7cN
         yvmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gyI0Mvpb+iDWLSoauPTy72oKqdeljTOV/y2BbcB75dU=;
        b=FeewjPISUVnC4fUL71S6l4W30oslojgRtHOPB91gf7PDa7z9OcKUYmYfjoKta+V9hb
         tvS2hqgH6/WroRWKkHEirbeluNrdzrI790ltcaW9WQ6PLPcB5GhGT+oOutcyGBJgduQs
         uLDRBjwora06xOM3Gl/g8N/qWTq2M3oWnI89cycDh6zoo72Kps1+jdWQihw/fbJvkXDw
         +0IzRd5m1JnKwPnQmyl9PtzGbiIF26mqWtFaBX84U7Hz0tTN9FiBRlQnOO9O/yR2G8Wa
         Nx+qH7k4BwMJaWQK8cnf/uXnXf3fIAsyzkxza2NK9pDUOA9sQk/qjZTpCgij/r6q65KI
         YpIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DonMKGc0;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gyI0Mvpb+iDWLSoauPTy72oKqdeljTOV/y2BbcB75dU=;
        b=YwcUrM4g19tqVx0UzLllWlQKTvfO6MFuzvKigZZs5vstSfBloZCWK5dCcW7EZ0rkgW
         eyF+AuskPDw0J3mKh9VD/ZPA3aLRz2851mM9vdlodV+EQntpNtzOGlts8XdgbbmAaGHt
         s7NWIFjfr1YZLFXsZjrdBOdSmB5VDHqtERNn2K74QEaeRK92jJTJ4wcvO7dQFhTBDVbF
         diSqe8HKGChuXYQbzY8213NS3fOWvy1W1pszNwkepqyPe5Y1MQZvIoVLubfi+pYVFT0d
         1fgRs8lCzIJ5k3/yn6q2eegZ3aBm9AtRga5PaI1ldsyttJ5OGVupQX9N6CyBV4eSyiU6
         Rqww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gyI0Mvpb+iDWLSoauPTy72oKqdeljTOV/y2BbcB75dU=;
        b=Dg/7GlD21cZs+Z1g7gT+TV2HV+zE/XljI7j5cJK9h0dt2qb9tAZoz0GgvRv8XRTlS8
         gicp29mXISmxsQRZrf+tfNssXLiVTouWbb8T0Lt+n1PnFjSCpLNr38iw+dDUf3s0TKBW
         81bukwhbVhdlWLCjokVr0nmAwt3YdLUCFOISaunRekk64yVp9wqUg/fvMj6Uwo+7v0O4
         Xer1byFy14cZaQpgaryUGKjiCQAMU4P4tKEXBKvPkY7YxMMUsbs2MEnW/Ka4Ru+jZYpG
         JmA8O+LwisIbCcEzGtO00PjZTrtO7XgXxRpHBMdp7kvnCnaGer1of39f/3G5YKUvQ5cU
         mr3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531V+2+gm1iCHDTe0Ms3eTbId5E5cWjlBgCKMV+Ym1Xq8uOgpCKx
	vxATI4q8kuoMu0+eLEJ1ocM=
X-Google-Smtp-Source: ABdhPJyASgSa+xT+LDBBdxXJQiH988Sm3DKV4KZjwt9KfZ3keZwt5cQj9lnWVQfuCuNEGaFYiI3Khg==
X-Received: by 2002:a0c:aa8d:: with SMTP id f13mr9855726qvb.31.1630891359049;
        Sun, 05 Sep 2021 18:22:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:478c:: with SMTP id k12ls2532000qtq.6.gmail; Sun, 05 Sep
 2021 18:22:38 -0700 (PDT)
X-Received: by 2002:ac8:6e88:: with SMTP id c8mr9126497qtv.241.1630891358556;
        Sun, 05 Sep 2021 18:22:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1630891358; cv=none;
        d=google.com; s=arc-20160816;
        b=Jdxyuux1C0eTqceVi+PycMVJUqAxoWhYrUBdYl25eg/1X9URXt/NHB6yg3psUdCxr1
         paZkREdpY08N3JCsB0ThhnWRRzMtO+PZc99k0fHUmByDbqPMq8dYHTQBqAXChfejgRXP
         8uen1365KkNPeewGTG0Wcc/VuFCPeIebTt6sevVcqv96PNcA/xgu5jIq3U0RnAdnDHgU
         xaOnMNi6z+Lndhh5m68K7IMn51Ibr4BTp8WdcLLeSQuyXeSJkSfStKiUbTzH5MBxSYaj
         IMs7Y/6WOQdYhsO3YOv0Li9Dvr0alEszQiqDRDS6wAoDL/S3hVzExig5HKp/1KOs+nkz
         xq4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Zy1/cQfwZH0UIKCGkdmpVNS4AU2XB2z7iCrUzAOHj4A=;
        b=wAWezlR1PpVKBIX0ca/yGbiiNWk2N/EngPslLsMMzBhJH1ZB67ucLTKnIQ7PxKIWsy
         dOR77yBwj8Bs682EAVC9sgz4UcTnVSqHCApZrip4pDgel4xO4Nak6RmA0rDBplCpwDWR
         9YJWBl93PigQsVhiZW5z+uZwfsLn2k46FxE1VPktgxmBXOnQLiULKwYptZI5VRcmwuRy
         UEWJbfxyTQ9Ps/ob31ihNwUToAWht03EqZSfXjei9HFM5Uqetn6kjGpq2duNWcGhjsnX
         Vq9Ew5p3wyOFTuvQ7y60fvCPGXKp+w6oafsP6cD/f8wNZHYrJ6A3qYuHQY7diCB+x6rj
         MDdw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DonMKGc0;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i4si541723qkg.7.2021.09.05.18.22.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 05 Sep 2021 18:22:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A911D610F9;
	Mon,  6 Sep 2021 01:22:36 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Alexander Gordeev <agordeev@linux.ibm.com>,
	Vasily Gorbik <gor@linux.ibm.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com,
	linux-s390@vger.kernel.org
Subject: [PATCH AUTOSEL 5.10 35/39] s390/kasan: fix large PMD pages address alignment check
Date: Sun,  5 Sep 2021 21:21:49 -0400
Message-Id: <20210906012153.929962-35-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210906012153.929962-1-sashal@kernel.org>
References: <20210906012153.929962-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DonMKGc0;       spf=pass
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
index 5646b39c728a..e9a9b7b616bc 100644
--- a/arch/s390/mm/kasan_init.c
+++ b/arch/s390/mm/kasan_init.c
@@ -108,6 +108,9 @@ static void __init kasan_early_vmemmap_populate(unsigned long address,
 		sgt_prot &= ~_SEGMENT_ENTRY_NOEXEC;
 	}
 
+	/*
+	 * The first 1MB of 1:1 mapping is mapped with 4KB pages
+	 */
 	while (address < end) {
 		pg_dir = pgd_offset_k(address);
 		if (pgd_none(*pg_dir)) {
@@ -165,30 +168,26 @@ static void __init kasan_early_vmemmap_populate(unsigned long address,
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210906012153.929962-35-sashal%40kernel.org.
