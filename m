Return-Path: <kasan-dev+bncBCN7B3VUS4CRBEPV5KBAMGQEYM3DVGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 27D0634705B
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Mar 2021 05:05:39 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id c199sf597593oob.18
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 21:05:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616558738; cv=pass;
        d=google.com; s=arc-20160816;
        b=MXdi2ZfpsKzwaoL54zXku0cLdsnjAocbdIrZ8HjVLuW3Srmgf+ohT6PN1EZqrV65Vo
         bfehAN5Q/14dzAgNX7FDPkVRXdhPDSD6vlmbOKRCB/d7UZQkZP81bOs0u1ouxtTUZACb
         cI0sCmeBvOhPuPmo3XD96UZYi7b5NxnUZay4b0imtnyAM1QyesKYbQ3SVSX9EnuDfxj4
         470P/auK18XJegJgpHkSh6NQLnaH2ru/THyuFeeMfarfr5t06zqejWkx+QrozyWdSapp
         v8t8kOICGDsWr8P058cGDBRqDl8iHdZUqSp8vHo2dnoK1H1TtdK7Kx0zJts0W8lnEYMP
         O+lg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=YI2NNAaUkLG3PQZsT8VkxIusrwKvXquMzNLB1WwDXnE=;
        b=Eowj6XSnLPb7C/q8h1nUe42o5qSRKS5o00UK9AVB56JlyzAX1L0HnawmFpZ+0reqrf
         dSJnjmxamm+edImNi67kmj4Ozyv5ojrSI9W/XPjUnRacv03drgqyQq/0vJVTPnm3xUf6
         i7C+HqdJk7GqQ4C0ukFwqCIO3Oe9Utpk/Ul3zkebYA6znGzBvJEA9ARovK2brkEPfzAB
         a8OYxJs2fyqmvxIicCJTfK9aTdRfJRZfMbHF3pibUy/D/fpgvN+JLXw0Fs16VdnSuI7c
         TKGi4z87wYzM7lwQbXBB19iukheBG6gIIin4FtfmajHd/sV0YKeEneItYGE6ONGYZpJ7
         v29w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YI2NNAaUkLG3PQZsT8VkxIusrwKvXquMzNLB1WwDXnE=;
        b=p2SPYzALtUYPG78HAScHUDhBNvdHubPP1e1U4BkTirqVx2ksUErI8bAFH+XCO4XjAJ
         GcwLvxn+wbCZxiMuII31cSOK9jTq9TgigAC1p2UvOEKRuv9RLFZinow9c/jxBpxLBU6E
         Pok78VMwKiTQgL/rJX8T62SnOFjwCvhtKEw+a3nS0OKOdcpB8++NBaq1pPU/ySyUg0xD
         nWPvaTmpscw6T0Le10rRXG0IG6ywDKKhgoyS/0kszQUecoVTraO2nxR31fWu9QZK+qLM
         ZWQ/WA5N2o2DTMrLg/cskRwuMcTGA09/EhgOyHz9TJtkAHlP786pjPNpObulDWW+lKna
         yXDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YI2NNAaUkLG3PQZsT8VkxIusrwKvXquMzNLB1WwDXnE=;
        b=AM6+/Ef7QExLRMYA2qbsQ/zI1r1J8KB0P1kdDdfWWrkuSwcu1khkSJ8QeVeH6W06+t
         3okZ0zf/ZACgsHFt9yWZw/kyJ78CQHh9oXoIvMCMVVcZaOa7/jLA32dtb6QjaxkJxU/F
         L4BCY73jmAwWegKX0BbBqotL5PtmuG+N/gTnfDqFZcjLmDtd2vpUg6Ul+57H6UWFFKIY
         6pHrbUbUb0mQOq5VhdHZrJ0PZJd3DEHMyicGZiQJBP2KQyMsmOWw8qqTgkDSi8S3E+nS
         nhpGVL5nXz+xvZ8Mis3PiouDy8G1YQXotbtFYW6ZNQ9ffV2cmNZ9WBJkXAuNcfkU9xz5
         RR7g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531v1Ln+8yy+ATIb1zz3SorzLOfaya+rheiqdMKIKJEAaOaklK38
	lVjN+lq+CGrfFqDwj40oGbM=
X-Google-Smtp-Source: ABdhPJzPkCQeW7LRPFWCzqIhXt6DPIi83EP+j6RjkBoxOf357LNng4UDMCl061ffjSBjCRRnUfkebQ==
X-Received: by 2002:aca:f5c4:: with SMTP id t187mr952803oih.127.1616558738025;
        Tue, 23 Mar 2021 21:05:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:dfb8:: with SMTP id k24ls51864ook.1.gmail; Tue, 23 Mar
 2021 21:05:37 -0700 (PDT)
X-Received: by 2002:a4a:424c:: with SMTP id i12mr1048959ooj.85.1616558737644;
        Tue, 23 Mar 2021 21:05:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616558737; cv=none;
        d=google.com; s=arc-20160816;
        b=IZHupsgZWxegctLVKAu9OBcXyLTGXNUVt7OlTQVgfDn5WsgCqjmX49grSDH7Oysv7x
         0N5vUppz7rYoYfQXTq/MWWsPljVufyysMcGqPzwqQzZ4AmNHFIyuZagIp2qyLU7WuCVT
         5h2f+bVJ89nOOJuPLIFPGVhYCUQon1f3G3thVSp/1O9nc86zEsRgJo8NTzcN4WcYydIF
         Whd32zrjsG8cwYYvKwWepTaeu/HWfc9bQg4nC/aWjRILfVKYXFsoJc9G4s4iBSR2Mh2M
         iURGb4TasCckBwu8Mnq64Q/13vJLrjG7C/I2yU17bo0hov2ijXHqDB/JLQoLjPeKZeFa
         NV5g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=7Tb/S1Sf/lHO0ziJCv8F1F+gdlDcazL0uFWPVhsOLoU=;
        b=M2YiXo76gJdIQnAYcTScdpfGRV4WKN83rF2kKa1elRoXJyLv07Bzee07NTnAx+7rzY
         N1psTNR3Fv1gzhxVVfFPBcxQ8B6LW8DJqwqZfPU63pFBBv0EyypFbS8xJ4popg6hBfT8
         uL9dVbdjwWTsKPc9lZt25il0YJkGSHKSu5h1sonau570vF4MgzFCZJ4SanWlrWmER53V
         W96enwwDZfvgbjhBNpNjLGfTDxUeMdDzhib5RzC6knxfV9MPFXulOgeBBjkw9gp9T8oI
         VAYiuVVsAjrt7rDP5LEb1/L8PI5TT91YuGM/j/hkgJR1Xu0C13d/5M5/Q02g+h+wOmPf
         6qng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id x143si72794oif.2.2021.03.23.21.05.37
        for <kasan-dev@googlegroups.com>;
        Tue, 23 Mar 2021 21:05:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 4f555892369f483ca5cd0ed9efb7ceed-20210324
X-UUID: 4f555892369f483ca5cd0ed9efb7ceed-20210324
Received: from mtkcas11.mediatek.inc [(172.21.101.40)] by mailgw02.mediatek.com
	(envelope-from <lecopzer.chen@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 110564171; Wed, 24 Mar 2021 12:05:34 +0800
Received: from mtkcas11.mediatek.inc (172.21.101.40) by
 mtkmbs05n1.mediatek.inc (172.21.101.15) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Wed, 24 Mar 2021 12:05:32 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by mtkcas11.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Wed, 24 Mar 2021 12:05:32 +0800
From: Lecopzer Chen <lecopzer.chen@mediatek.com>
To: <linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, <catalin.marinas@arm.com>, <will@kernel.org>
CC: <ryabinin.a.a@gmail.com>, <glider@google.com>, <andreyknvl@gmail.com>,
	<dvyukov@google.com>, <akpm@linux-foundation.org>,
	<tyhicks@linux.microsoft.com>, <maz@kernel.org>, <rppt@kernel.org>,
	<linux@roeck-us.net>, <gustavoars@kernel.org>, <yj.chiang@mediatek.com>,
	Lecopzer Chen <lecopzer.chen@mediatek.com>
Subject: [PATCH v4 4/5] arm64: kaslr: support randomized module area with KASAN_VMALLOC
Date: Wed, 24 Mar 2021 12:05:21 +0800
Message-ID: <20210324040522.15548-5-lecopzer.chen@mediatek.com>
X-Mailer: git-send-email 2.18.0
In-Reply-To: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
References: <20210324040522.15548-1-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-MTK: N
X-Original-Sender: lecopzer.chen@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lecopzer.chen@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=lecopzer.chen@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

After KASAN_VMALLOC works in arm64, we can randomize module region
into vmalloc area now.

Test:
	VMALLOC area ffffffc010000000 fffffffdf0000000

	before the patch:
		module_alloc_base/end ffffffc008b80000 ffffffc010000000
	after the patch:
		module_alloc_base/end ffffffdcf4bed000 ffffffc010000000

	And the function that insmod some modules is fine.

Suggested-by: Ard Biesheuvel <ardb@kernel.org>
Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
---
 arch/arm64/kernel/kaslr.c  | 18 ++++++++++--------
 arch/arm64/kernel/module.c | 16 +++++++++-------
 2 files changed, 19 insertions(+), 15 deletions(-)

diff --git a/arch/arm64/kernel/kaslr.c b/arch/arm64/kernel/kaslr.c
index 27f8939deb1b..341342b207f6 100644
--- a/arch/arm64/kernel/kaslr.c
+++ b/arch/arm64/kernel/kaslr.c
@@ -128,15 +128,17 @@ u64 __init kaslr_early_init(void)
 	/* use the top 16 bits to randomize the linear region */
 	memstart_offset_seed = seed >> 48;
 
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
-	    IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	if (!IS_ENABLED(CONFIG_KASAN_VMALLOC) &&
+	    (IS_ENABLED(CONFIG_KASAN_GENERIC) ||
+	     IS_ENABLED(CONFIG_KASAN_SW_TAGS)))
 		/*
-		 * KASAN does not expect the module region to intersect the
-		 * vmalloc region, since shadow memory is allocated for each
-		 * module at load time, whereas the vmalloc region is shadowed
-		 * by KASAN zero pages. So keep modules out of the vmalloc
-		 * region if KASAN is enabled, and put the kernel well within
-		 * 4 GB of the module region.
+		 * KASAN without KASAN_VMALLOC does not expect the module region
+		 * to intersect the vmalloc region, since shadow memory is
+		 * allocated for each module at load time, whereas the vmalloc
+		 * region is shadowed by KASAN zero pages. So keep modules
+		 * out of the vmalloc region if KASAN is enabled without
+		 * KASAN_VMALLOC, and put the kernel well within 4 GB of the
+		 * module region.
 		 */
 		return offset % SZ_2G;
 
diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index fe21e0f06492..b5ec010c481f 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -40,14 +40,16 @@ void *module_alloc(unsigned long size)
 				NUMA_NO_NODE, __builtin_return_address(0));
 
 	if (!p && IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
-	    !IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-	    !IS_ENABLED(CONFIG_KASAN_SW_TAGS))
+	    (IS_ENABLED(CONFIG_KASAN_VMALLOC) ||
+	     (!IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+	      !IS_ENABLED(CONFIG_KASAN_SW_TAGS))))
 		/*
-		 * KASAN can only deal with module allocations being served
-		 * from the reserved module region, since the remainder of
-		 * the vmalloc region is already backed by zero shadow pages,
-		 * and punching holes into it is non-trivial. Since the module
-		 * region is not randomized when KASAN is enabled, it is even
+		 * KASAN without KASAN_VMALLOC can only deal with module
+		 * allocations being served from the reserved module region,
+		 * since the remainder of the vmalloc region is already
+		 * backed by zero shadow pages, and punching holes into it
+		 * is non-trivial. Since the module region is not randomized
+		 * when KASAN is enabled without KASAN_VMALLOC, it is even
 		 * less likely that the module region gets exhausted, so we
 		 * can simply omit this fallback in that case.
 		 */
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210324040522.15548-5-lecopzer.chen%40mediatek.com.
