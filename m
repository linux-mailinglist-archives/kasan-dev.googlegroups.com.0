Return-Path: <kasan-dev+bncBC5JXFXXVEGRBEWQYGLQMGQEBSH7WJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C59558BEEC
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 03:34:12 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-10e7cc69a90sf1280457fac.6
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 18:34:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659922451; cv=pass;
        d=google.com; s=arc-20160816;
        b=uWUS/WHm62ovQNhHhfWhXH/ZWL6Mfsw4P427OXyg9OfCn9vKm2afB/rwgJGleeQNIz
         /59JX/V8WNZ3uNMkg5F5+c+zvHcywFELuR+DQjJ6xX9W9x/IxyA8IKDaNbHuM7/WXwgi
         TIOxfvuxstcTNLXGH886SoN8XHAlEEKfJfjcJyD4cdTris4OFMs0KmfU8taSNMcKxYsk
         c4Gx+Qlf7NXtKG+CYNwU03c4gzxZfzvx9OLxKodFKCEUVk6z8QrmkeMS847cTvC5O2AN
         23q5AeSDbcnJhj/EPOSgRktwGPUB02QecxTqcIC4FgZTcDgNF5xMwZ7r7bmdUyf6xuit
         2+gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=hQJFLif66kmLSC5lBcPcPK80y4AN5BMq+SizNHZEdf0=;
        b=krGfTQB2Pvq9rJMa5n1hpeGOGdT8h0m1qeL7V/pSY4cJu2sW2R1FKiGXs/Fth973BD
         sYon1CDgG5wXATEKUMHJPTDaZzUIS80TZNx7aCwbp2VTc5fkDBqE8XEvQ4ECeNez8CWI
         Nllg7BUZbuvbjQV0HQDmpJc4NYIuDPSjaD0ub04fDdpdEmeo/kklL3Uef3s7mEDOJd7E
         uOlMiwje5FyfrUSlZNobBviCgIFAzF5mHN54sSh1B4z1vIBjEqPHawBzyDoR7YHg5xVo
         VX5C0qp0UgN17GilaYlUtgjQqSuwvBx2mpFSmsNdoQUfCJfAGPAncPPH6jqVQ5jlSFvc
         p5vA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oX9hgytE;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=hQJFLif66kmLSC5lBcPcPK80y4AN5BMq+SizNHZEdf0=;
        b=CKqmbgeb18clf2LSZ2szi+0WWUn6AIw59XQTNYaHd/soyxsN9vD/bMzwXb5YzzmjSJ
         xz1agQ9U00ErDbXPqurs9z22k89LuN6SMfRHmEYcZiVxE7HSGd7yR2OB4egDsmFgOjkQ
         cY2gETQSLWAno424d300s+nmxEzccn6MlB70JOSzOvs2x2IbZ/iOf0GkvrevyZR9QR/x
         Fp/2BQYH4pRmCxbux3NR2A5ZNdIbPm+Bjmhhe+lFGU4KNOup01Yx1IRiHOJ+VbAU+XDd
         kasRlH07+AjiuiTCbBtAX+0I3CqnBdaUouQz+pEP8XkHhqfskNyc4y5YzhAv8WaPuxrs
         zEXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=hQJFLif66kmLSC5lBcPcPK80y4AN5BMq+SizNHZEdf0=;
        b=fict2wkWnoViKH85dnGIvawJfvDoHhncEwsoYYMh/cQUfb57oLQKW1JZYEHyqbeGVf
         TrmshtsKN6J96OybGWff8PIbIiCldnd6LnrhYcml0rX0Qotg2hS/rSRCXfVeo6HJ8jRx
         1LC5uwn5JSo1wMGzGGO5+/7qXWMTzSb5z1fwRwiyHADzB2y+2/a+UA6PWK7jjb582GKA
         8YeFYtSYGLmXM1RNEbLspfUgdLiuscxpsy9SiTCVHUT678E26CWUbeuYmrt17vmRf5l8
         FJXq+FX4SnlLcDYklVwhF/gWMk6fhBT1jaHB3f+L1HtbFMYeljB+/NCXVfsH1F064qmf
         Ia8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1IWuUZzygEpEM/SJrMLBt79kD6Cn5gh05RbWC/uGsiqAnXf1ul
	2lgZKKBW6neZ1KwPwHR54lU=
X-Google-Smtp-Source: AA6agR4EHl2gcixwPBWOHiIOc+enUKwZ3JSea9DplW99HkLU9SXILBuqmU/V8U8qzisDGa3Jqj8Zyw==
X-Received: by 2002:a05:6808:1408:b0:343:1ae:87cb with SMTP id w8-20020a056808140800b0034301ae87cbmr34586oiv.201.1659922451022;
        Sun, 07 Aug 2022 18:34:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:786:0:b0:33a:8505:22b5 with SMTP id 128-20020aca0786000000b0033a850522b5ls2807569oih.7.-pod-prod-gmail;
 Sun, 07 Aug 2022 18:34:10 -0700 (PDT)
X-Received: by 2002:a05:6808:1495:b0:33a:ad84:1dc7 with SMTP id e21-20020a056808149500b0033aad841dc7mr9647503oiw.177.1659922450501;
        Sun, 07 Aug 2022 18:34:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659922450; cv=none;
        d=google.com; s=arc-20160816;
        b=X+i6j3few00CS6Tu/cGJ5uze1Y4sCA7q7L2T+fUIUfElweEHhLt99JQYzFOV56ywb2
         AFnbGq8LgmGD+P0mGR7mfCtxe2DfC8cBdY4s2gJ4PdMg29+myntq78oacvm4i+Ab8apm
         c0uVvRPmFTxhIdwx406eTUwh/eaayqkZMyChNH3/72X1xVYiEq7Qt2pXEfh+Iz3MRdcr
         4PENrVcJ6dsSWwmdHrWwbUnMFA36nm7SVldbcIP5fGladNyBCBSbQFVMGYWGAwnPdhu/
         R3NGP/6Rl+3u4xsFb/NRs8+GzTQ/5jMZXn6KrLpPbao6CHSxmaieEDo3g6FA4cV4/xZJ
         aVhQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rX0AtKDvuIWz3Tmemb9rsnlVXuio1xX8EylBFHY4Fkw=;
        b=wdVqDIy5+xY4M2F9Osr4LveE4KtKP0wnYAl5EsFr2nYgJz8t6ZiznbZ+FZVcKxPQW+
         IM8Lyptmo/0TuoMI1U926cYi6WbUxoIz7LFb7AnboyeUkVrOcgFdlY3hvwFgxshNBxES
         B6PEyEIeCchsOi50XUzNvdX++J7kAe7ZAIHxTO9/KuBmaaA0SGxmKxOROkg/ZVWPPcAh
         kKrqvDFyiZvJveFk18ndsRt/XLdGPbNU7mLm85syryUR/aMWVf0g2lCEQYZJj5HBaqTS
         NLZgXFrdAeOlILQDpnvPyBH2yVzTIG3vd/IkUW7vnI1qlzIUMBo8SBEhNj+hIE4x+OV1
         64Ug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=oX9hgytE;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 38-20020a9d0829000000b00636e490f364si74265oty.2.2022.08.07.18.34.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Aug 2022 18:34:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4798060DE1;
	Mon,  8 Aug 2022 01:34:10 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CB9E3C433D7;
	Mon,  8 Aug 2022 01:34:07 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Ard Biesheuvel <ardb@kernel.org>,
	Will Deacon <will@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	anshuman.khandual@arm.com,
	pasha.tatashin@soleen.com,
	broonie@kernel.org,
	maz@kernel.org,
	suzuki.poulose@arm.com,
	vladimir.murzin@arm.com,
	james.morse@arm.com,
	Julia.Lawall@inria.fr,
	akpm@linux-foundation.org,
	david@redhat.com,
	jianyong.wu@arm.com,
	quic_sudaraja@quicinc.com,
	vijayb@linux.microsoft.com,
	rppt@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.18 04/53] arm64: mm: provide idmap pointer to cpu_replace_ttbr1()
Date: Sun,  7 Aug 2022 21:32:59 -0400
Message-Id: <20220808013350.314757-4-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220808013350.314757-1-sashal@kernel.org>
References: <20220808013350.314757-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=oX9hgytE;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as
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

From: Ard Biesheuvel <ardb@kernel.org>

[ Upstream commit 1682c45b920643cbde31d8a5b7ca7c2be92d6928 ]

In preparation for changing the way we initialize the permanent ID map,
update cpu_replace_ttbr1() so we can use it with the initial ID map as
well.

Signed-off-by: Ard Biesheuvel <ardb@kernel.org>
Link: https://lore.kernel.org/r/20220624150651.1358849-11-ardb@kernel.org
Signed-off-by: Will Deacon <will@kernel.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 arch/arm64/include/asm/mmu_context.h | 13 +++++++++----
 arch/arm64/kernel/cpufeature.c       |  2 +-
 arch/arm64/kernel/suspend.c          |  2 +-
 arch/arm64/mm/kasan_init.c           |  4 ++--
 arch/arm64/mm/mmu.c                  |  2 +-
 5 files changed, 14 insertions(+), 9 deletions(-)

diff --git a/arch/arm64/include/asm/mmu_context.h b/arch/arm64/include/asm/mmu_context.h
index 6770667b34a3..f47e7ced3ff9 100644
--- a/arch/arm64/include/asm/mmu_context.h
+++ b/arch/arm64/include/asm/mmu_context.h
@@ -106,13 +106,18 @@ static inline void cpu_uninstall_idmap(void)
 		cpu_switch_mm(mm->pgd, mm);
 }
 
-static inline void cpu_install_idmap(void)
+static inline void __cpu_install_idmap(pgd_t *idmap)
 {
 	cpu_set_reserved_ttbr0();
 	local_flush_tlb_all();
 	cpu_set_idmap_tcr_t0sz();
 
-	cpu_switch_mm(lm_alias(idmap_pg_dir), &init_mm);
+	cpu_switch_mm(lm_alias(idmap), &init_mm);
+}
+
+static inline void cpu_install_idmap(void)
+{
+	__cpu_install_idmap(idmap_pg_dir);
 }
 
 /*
@@ -143,7 +148,7 @@ static inline void cpu_install_ttbr0(phys_addr_t ttbr0, unsigned long t0sz)
  * Atomically replaces the active TTBR1_EL1 PGD with a new VA-compatible PGD,
  * avoiding the possibility of conflicting TLB entries being allocated.
  */
-static inline void __nocfi cpu_replace_ttbr1(pgd_t *pgdp)
+static inline void __nocfi cpu_replace_ttbr1(pgd_t *pgdp, pgd_t *idmap)
 {
 	typedef void (ttbr_replace_func)(phys_addr_t);
 	extern ttbr_replace_func idmap_cpu_replace_ttbr1;
@@ -166,7 +171,7 @@ static inline void __nocfi cpu_replace_ttbr1(pgd_t *pgdp)
 
 	replace_phys = (void *)__pa_symbol(function_nocfi(idmap_cpu_replace_ttbr1));
 
-	cpu_install_idmap();
+	__cpu_install_idmap(idmap);
 	replace_phys(ttbr1);
 	cpu_uninstall_idmap();
 }
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index 2cb9cc9e0eff..859e9b635ba0 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -3107,7 +3107,7 @@ subsys_initcall_sync(init_32bit_el0_mask);
 
 static void __maybe_unused cpu_enable_cnp(struct arm64_cpu_capabilities const *cap)
 {
-	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+	cpu_replace_ttbr1(lm_alias(swapper_pg_dir), idmap_pg_dir);
 }
 
 /*
diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
index 2b0887e58a7c..9135fe0f3df5 100644
--- a/arch/arm64/kernel/suspend.c
+++ b/arch/arm64/kernel/suspend.c
@@ -52,7 +52,7 @@ void notrace __cpu_suspend_exit(void)
 
 	/* Restore CnP bit in TTBR1_EL1 */
 	if (system_supports_cnp())
-		cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+		cpu_replace_ttbr1(lm_alias(swapper_pg_dir), idmap_pg_dir);
 
 	/*
 	 * PSTATE was not saved over suspend/resume, re-enable any detected
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index c12cd700598f..e969e68de005 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -236,7 +236,7 @@ static void __init kasan_init_shadow(void)
 	 */
 	memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(tmp_pg_dir));
 	dsb(ishst);
-	cpu_replace_ttbr1(lm_alias(tmp_pg_dir));
+	cpu_replace_ttbr1(lm_alias(tmp_pg_dir), idmap_pg_dir);
 
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
@@ -280,7 +280,7 @@ static void __init kasan_init_shadow(void)
 				PAGE_KERNEL_RO));
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
-	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+	cpu_replace_ttbr1(lm_alias(swapper_pg_dir), idmap_pg_dir);
 }
 
 static void __init kasan_init_depth(void)
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 626ec32873c6..903745ea801a 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -771,7 +771,7 @@ void __init paging_init(void)
 
 	pgd_clear_fixmap();
 
-	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+	cpu_replace_ttbr1(lm_alias(swapper_pg_dir), idmap_pg_dir);
 	init_mm.pgd = swapper_pg_dir;
 
 	memblock_phys_free(__pa_symbol(init_pg_dir),
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220808013350.314757-4-sashal%40kernel.org.
