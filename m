Return-Path: <kasan-dev+bncBC5JXFXXVEGRBDORYGLQMGQEM7EG2PA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 243F058BF20
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 03:36:15 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-10e46ccc8f9sf1273727fac.18
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 18:36:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659922574; cv=pass;
        d=google.com; s=arc-20160816;
        b=QzeMjJf774nocBqGe99uJn6gvpBPpigobAYDNEmt87pRRO+SRuv6ZaWyG+BLsHvCx7
         rJQ40zvfEYjveaJs0tv1yEeTySsMmFa9G2EyboVHPu8QlwsuiQABKnSrO+1qFAQmsbT4
         geKIgPvEOFve/yW/Pz1bfUnbAM1LuO0X/wZQE9ZN7L+nVonWTMYijXCNCx+39l3Hyjw4
         w1dzE0hI2q3Ho6JVksHqJ0hVoWieERoz8FlWqY0qyVkQ8a2fpZe0mkjT7IG/PQa1g8Nu
         kKwQx0ydzkqvwEseOZniOqIcXFv5srZzyFOfwJCmu3/g+UKK9RIBRG1LN0jb7r12ZCLO
         HINw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=3wwjRJoSZVF775pitXcxI8PE6z7bTy/Usn9oLSEtwhU=;
        b=wKht5hmyNXl3IZg/tHQG/Tx1jX/m3llltdMMt+R19PPDR7MhKmdgjX2wnwEuZWBWbY
         kleOfHtJ2zVG3yZ1k1DKCrVKCzxjuu0favo3+VgahS3+hDDCa/M94ZJP9Xj+CnlzCxJZ
         KUKhshj+c8+5oKE/SEinm/1agBGZlP/2RTRvOUohoutCITXFTYRk+HkKMO6y8hW72sLT
         SEgsTeLErITnUA/A1dWYGZT8kvTRhUhecr6a3SB9v62riyjqQ2pov2xZt/LqjTCk7lTp
         1UFYTh8ChTImtyKylR3+zuzsB42lD9mTAkydnKNH1HKiYDsZfYSwBRIJRWKhlCppwA+u
         INyg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G1D4aNPF;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=3wwjRJoSZVF775pitXcxI8PE6z7bTy/Usn9oLSEtwhU=;
        b=BCc8gGRmVFfvzZeFmnD3mTNhn95DzH4TlBudYEzkSnUlZ2mfPrNpZYfD9xx9HVx9s6
         qtGGLdc/hJ8P5LzrdXIHYM6QRk+uhV4Jecvorfx5aDqQMAAxj8M2FhbTnQSmxIy8QzQC
         qfazyiAjVk+DTSzjaBPe0fjcliRj0Ca61ZhGqO9xhYFEMQGIwaL0bGegeBFU6MkVVu0s
         eeiIm9LwvpRn4+Er6GuNdWjsRukmhszZEP1O5otp4GwAONr5TMLK+Qzl1sI+AQxCioVH
         Uf3x9BFB78FUPfwKCm52G76vmXU7clMAnCCXKCl0Cf55ule2xM4NKBSSMsvdjWbiUAtr
         qfnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=3wwjRJoSZVF775pitXcxI8PE6z7bTy/Usn9oLSEtwhU=;
        b=6u7gkSUt+18tsVkznV8xczAC0ONTNttnvNivpj81d2PETeDbAiKb5EQodgUEjsjAJC
         e2vDMt+/i9vHUV/LHw4LPBFbQdvknigrLfj9EHkp8CuryB0uUBU1le+afFeoeFPtXL8n
         ipZ0vpQg5GltObJU36ebJjhDdNCPKi+bQMTq+8Xit4wIYWoJ+DQh5lywGtToATIm/9ys
         i9K+8pXqDvJqagSEQUMAL391/J6LYB0D6jRtHiCNDbnn/wvQSmJPooAvMXSSy1RueEY9
         crQ4wyumOEf7A0hV1n7DxtnjYJDBkh/Fj+4v9n+k2VYXCxdyWota/60d0JshwBoMOdG5
         qNww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo0YQIBMaUWx7DZkROx/WLHw+qVdLj80wj/awBjmspT/VOrHgbAh
	FYRYtCOQJS+hydi94N2fE2g=
X-Google-Smtp-Source: AA6agR4CBZ7/kuXjGh45Y8eGjTPBBL9sBlVJkjHkNdFuCzF+Sixvj1qjeSkfkoulVelQYlFHwwRB8w==
X-Received: by 2002:a05:6870:b609:b0:f2:74e7:9bf1 with SMTP id cm9-20020a056870b60900b000f274e79bf1mr10454702oab.141.1659922573879;
        Sun, 07 Aug 2022 18:36:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:4c7:b0:10c:2137:38ad with SMTP id
 n7-20020a05687104c700b0010c213738adls1624815oai.1.-pod-prod-gmail; Sun, 07
 Aug 2022 18:36:13 -0700 (PDT)
X-Received: by 2002:a05:6870:e612:b0:109:d5fb:144c with SMTP id q18-20020a056870e61200b00109d5fb144cmr7409350oag.195.1659922573486;
        Sun, 07 Aug 2022 18:36:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659922573; cv=none;
        d=google.com; s=arc-20160816;
        b=ISv2FAv3tFcNL9XRLI5youZE334a9S0nMyaBB8iw1+8op3qi1DGIvHt6QyJRkGKHMg
         FldIztccdZ8jRQVNCVaLneR9bitqcZUEaPyV9z89lk47iLLZGUKZe44qfsoZsiDr3kKn
         VyZWFccSJx7cOG9b/tPLLtR2zi1V5EhLIMqCGEkHND6sZH7xV5ocqFy8yJcwqJVKuu9a
         oDog9sE5NAdT3IkPfVnn2/Z3A9LHAglgnEhJY/0VHbxxFpOHpG/M0TTsX722TrDQr6J9
         PpiFlrw2BZYxuMReYzEbFmnPEoOuLMWNH5kty++bnkqW5uYeJ+1ojgM84OcneCyxSwj/
         8ydA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=bduAGRoIkG+o823tApBWLDjrswTFlqZ1Ry9Ikj5MxBA=;
        b=uYfpjpWjedWRaWERVNgSND+QRYp8eoImr+gq2W/amxLceMrN58nWQ+DCzFgulyq+HN
         XfP4yrhMuGSueNDz62h6/0FJFraBcF2gbhKcN/eW9583+aFf1iFFnmAMABzIxKM4OZLM
         UMK+lzNSUDB1v/XFy0UYhgRxTDLO+NfBeDgeRAfovB7osBAaRg0bqXiUbVGP8gYkvTkf
         6fsiQbplSuF0t6KNCevh8JjmJLagjJ1rfY6KqkZdXqX0z2BGDtuCjOhLddf/o6VrK40M
         eMrI24quNESvhQngExtEuL4PlWdNOPNcKEpbYPSxI+b1DnvQQS4eNtxYD0gVFA2daVaN
         D6FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=G1D4aNPF;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e184-20020acab5c1000000b0033a8986c20csi543002oif.2.2022.08.07.18.36.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Aug 2022 18:36:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4DEE960C94;
	Mon,  8 Aug 2022 01:36:13 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 20228C433D6;
	Mon,  8 Aug 2022 01:36:10 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Ard Biesheuvel <ardb@kernel.org>,
	Will Deacon <will@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	pasha.tatashin@soleen.com,
	anshuman.khandual@arm.com,
	broonie@kernel.org,
	maz@kernel.org,
	suzuki.poulose@arm.com,
	james.morse@arm.com,
	vladimir.murzin@arm.com,
	Julia.Lawall@inria.fr,
	akpm@linux-foundation.org,
	david@redhat.com,
	vijayb@linux.microsoft.com,
	quic_sudaraja@quicinc.com,
	jianyong.wu@arm.com,
	rppt@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.15 04/45] arm64: mm: provide idmap pointer to cpu_replace_ttbr1()
Date: Sun,  7 Aug 2022 21:35:08 -0400
Message-Id: <20220808013551.315446-4-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220808013551.315446-1-sashal@kernel.org>
References: <20220808013551.315446-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=G1D4aNPF;       spf=pass
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
index f4ba93d4ffeb..24ed534bb417 100644
--- a/arch/arm64/include/asm/mmu_context.h
+++ b/arch/arm64/include/asm/mmu_context.h
@@ -106,20 +106,25 @@ static inline void cpu_uninstall_idmap(void)
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
  * Atomically replaces the active TTBR1_EL1 PGD with a new VA-compatible PGD,
  * avoiding the possibility of conflicting TLB entries being allocated.
  */
-static inline void __nocfi cpu_replace_ttbr1(pgd_t *pgdp)
+static inline void __nocfi cpu_replace_ttbr1(pgd_t *pgdp, pgd_t *idmap)
 {
 	typedef void (ttbr_replace_func)(phys_addr_t);
 	extern ttbr_replace_func idmap_cpu_replace_ttbr1;
@@ -142,7 +147,7 @@ static inline void __nocfi cpu_replace_ttbr1(pgd_t *pgdp)
 
 	replace_phys = (void *)__pa_symbol(function_nocfi(idmap_cpu_replace_ttbr1));
 
-	cpu_install_idmap();
+	__cpu_install_idmap(idmap);
 	replace_phys(ttbr1);
 	cpu_uninstall_idmap();
 }
diff --git a/arch/arm64/kernel/cpufeature.c b/arch/arm64/kernel/cpufeature.c
index e71c9cfb46e8..e826509823a6 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -3013,7 +3013,7 @@ subsys_initcall_sync(init_32bit_el0_mask);
 
 static void __maybe_unused cpu_enable_cnp(struct arm64_cpu_capabilities const *cap)
 {
-	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+	cpu_replace_ttbr1(lm_alias(swapper_pg_dir), idmap_pg_dir);
 }
 
 /*
diff --git a/arch/arm64/kernel/suspend.c b/arch/arm64/kernel/suspend.c
index 19ee7c33769d..40bf1551d1ad 100644
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
index 61b52a92b8b6..674863348f67 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -235,7 +235,7 @@ static void __init kasan_init_shadow(void)
 	 */
 	memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(tmp_pg_dir));
 	dsb(ishst);
-	cpu_replace_ttbr1(lm_alias(tmp_pg_dir));
+	cpu_replace_ttbr1(lm_alias(tmp_pg_dir), idmap_pg_dir);
 
 	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);
 
@@ -279,7 +279,7 @@ static void __init kasan_init_shadow(void)
 				PAGE_KERNEL_RO));
 
 	memset(kasan_early_shadow_page, KASAN_SHADOW_INIT, PAGE_SIZE);
-	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+	cpu_replace_ttbr1(lm_alias(swapper_pg_dir), idmap_pg_dir);
 }
 
 static void __init kasan_init_depth(void)
diff --git a/arch/arm64/mm/mmu.c b/arch/arm64/mm/mmu.c
index 6680689242df..984f1f503328 100644
--- a/arch/arm64/mm/mmu.c
+++ b/arch/arm64/mm/mmu.c
@@ -780,7 +780,7 @@ void __init paging_init(void)
 
 	pgd_clear_fixmap();
 
-	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
+	cpu_replace_ttbr1(lm_alias(swapper_pg_dir), idmap_pg_dir);
 	init_mm.pgd = swapper_pg_dir;
 
 	memblock_free(__pa_symbol(init_pg_dir),
-- 
2.35.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220808013551.315446-4-sashal%40kernel.org.
