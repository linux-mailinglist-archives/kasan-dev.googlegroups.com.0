Return-Path: <kasan-dev+bncBC5JXFXXVEGRBCWPYGLQMGQEZ63ML4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 2264158BEBD
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Aug 2022 03:31:56 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id y7-20020a056a00180700b0052d90ab2314sf3151008pfa.10
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Aug 2022 18:31:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1659922314; cv=pass;
        d=google.com; s=arc-20160816;
        b=n5r4hz5dwxVxnEJSNpY8x71tarY73x0oIA0+NZxADdGvKbDpqi1gyfDSjTK0CySHZI
         vpLmxRLbIKZ3H7CCuV5ijsMjl/KgoKZ8rI8lBK2kMhmEc7c6N1d8enpjnbSrlLr34B0M
         IW2Ee9YH6AtCCm98lUzUTP1+OV4yiseuqVktyzwib8lF18P08Hd7qUjTW62L7fwmknCf
         M1kPXTAVecF26xVBNlaOLAqUPROGvCj4Tr3h2pnh+hzp5DpjjOujvHcn4CrnkXUryGSk
         7lq4BRXwEBmmiHymzt4Lv48nUd1J7WPAnDnfsCIin8ThkQDG9cvNb1taME0U3B5mnFv4
         dF0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qWIxg52N5Tmo/93mz2/soOAuV37vEwPRqpVwtgmUgUI=;
        b=NvCzFfP8SWOUkTnU+kQ2tUz86EepF1rDaf5hO3Co/wiUtB1pF3OOm/73RsQABYmStR
         RwNksUuowgb5ayONjZzwAGMnNB+jYKfxQFjrkDHby0MwyOiduk6NtEpGfe3sed1sU0ye
         LFuO0LIK5xHFcZcbDvpWJ/Rw93Q36Bgx5Dujism+kiXa2kcu/Yx8ETm5OEW/MdGW/BFY
         OkXGN8GNBtrv4NerkUr8LEEICHZ28eX6Mad7L4JPUgHwoDLjQwxM1vp6AcFtz8C28QJQ
         moaw/X1fr3za6HAXF3iXHM6xWYHZEi1S4fPdzaPK+RtUv360jl+jfVmfwmMi5Rs4Fq2D
         PQLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fhFWLbzO;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc;
        bh=qWIxg52N5Tmo/93mz2/soOAuV37vEwPRqpVwtgmUgUI=;
        b=QsVeLDUUkQj0+zhzNOYc4vhQzfYwyTyuC5RZJUVP/ohhHGixW2qWB9JLxzlHm0TBIg
         PbSTZwxSr271nZ1HZJN4wDB+SlHuETUiTcspGP4ewn8RS7o9UvHVFrSPd42iMGFjusF7
         BWqSQckXKv+xYy1BwqchokXyNqXn7XtrbsiMjeEv20h9gvczsp+B2nPTP0ohl5kxuNa5
         CaS14p41g5l8SBT4tAvYVpPMW2a/TPO/NLogH1gAWzQFiZBZufRT3VPTWEHZVD4N+E1X
         Xf0AucP7maAyg4SM8hw3A1YW8f6PMl0mR4Vzn82HI5emlWDxzPg9ra4JYGv8KnaaKiZh
         5U/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc;
        bh=qWIxg52N5Tmo/93mz2/soOAuV37vEwPRqpVwtgmUgUI=;
        b=Mn03QtZvmiMbpjmbkoRWU5plCNPA14mJjhEb3X4NBNa+ow4wM0GmaR4V+cvyy3OUfU
         /MT2S4xNnAlL4u3eRmNgE81fM68wt6H+aZoQVTLDIeDMPZ0WaRG6ZLSEKdcXAEIoPnbD
         6hcmplvLUMUqedZv51l1tPMLa6DCGOdsJu4N9Fb0b96NSkLEhKXQL5suvr6UOLGUV3KQ
         OSeoHPVcinntBuhD5ReL5UdKCI0RAKcrLgZ8s98JuQq6l/eJJw+ea53rcw4jEd0kF5kP
         Gvd7+Mz0LZQrAlxty0GBKQszfwFoHZ5MxO6FjcgX0hHC7+Q/+zV2JmjXk8hoG1QRmnqp
         5BpQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo3YnCp8hqF3z7hYY+5uflHtEdFZJog1x3/YG8cFrxe4ygLUZOFa
	eqE8OUiRbcAIXdEvsjKZGpg=
X-Google-Smtp-Source: AA6agR79CJ2Bp+RkpsS78giI0l9+xblr+owIvMyNf33M0j41GbxDl7yc9yzIDvgqxPOQ6lREwLPp7Q==
X-Received: by 2002:a17:902:ed44:b0:16d:b1a2:f24 with SMTP id y4-20020a170902ed4400b0016db1a20f24mr16159433plb.145.1659922314243;
        Sun, 07 Aug 2022 18:31:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bcc6:b0:16c:2ae8:5b94 with SMTP id
 o6-20020a170902bcc600b0016c2ae85b94ls6194663pls.0.-pod-prod-gmail; Sun, 07
 Aug 2022 18:31:53 -0700 (PDT)
X-Received: by 2002:a17:90a:7aca:b0:1f1:ff59:fe7e with SMTP id b10-20020a17090a7aca00b001f1ff59fe7emr18744820pjl.11.1659922313291;
        Sun, 07 Aug 2022 18:31:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1659922313; cv=none;
        d=google.com; s=arc-20160816;
        b=FEwSGJa1xBsLUEvlTZbTvSDITaHsCXz7A5J08FGcsXKLIG1pIx+sW0UWcL1EA1zeLQ
         Tk8h1jCwu6Wsm6HfdehhcuDgRWW1/AJsJEd9qZLwt9x5s/8zPo9yymDBvjW1dqO+rg/u
         18WgDnoXnZxY1YTPSUpWST+fAUozM/un/XXo67D+NXYTzeax+zanjXZK25aYoPSi1yQ/
         DnszxHl52qDEiYJDws8GwZU7jEWjvidM1Hm8oZQ+v3iA6vZTnNql6rK6M1MRt5cQ5wOJ
         Xfzko2SdcH3SkoZ3DKfAnSdMPp+r/dcqgmjQZkvRdVdbhpRpJvNsGB913QvGJKo2+9RR
         9flg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KnA3Fv8EhXMbYpK6B+azrQkT3rTPd4z8B+rz+Yb1ghs=;
        b=gu81l2XgWZCxbrL+7ajl7s2VBPQr0aGLztFJyE7K8ZbVbs35AKnXrky0sgSi7UACxJ
         vsx8KElH5YbX+mQeAv/M0CQaknetEaimUcCirlx8+WM96ZDMZUqWMHiFImqNR96lWWBr
         8cYN67gGLKb7osPvtZM7RklYEJZ/gEXqIGLKW2kzgB8H8a5KiRKycp46ywf8dN4x1RUL
         2GKitYXyLQdQm+F1AqtZohF5E+8S0S/r93lb/7lQumjuPCajBxXZdSUSaoVh1cl9PG9x
         tC63vG/T+ZFNqba7RzCWcaVUKbDTMUkp32/4Z1kxMR5vNapo8Hk3cakDHjSwXHZJ5uYB
         NSZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fhFWLbzO;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id mt16-20020a17090b231000b001f25c992249si612320pjb.0.2022.08.07.18.31.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 07 Aug 2022 18:31:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 6BC4DCE0FDD;
	Mon,  8 Aug 2022 01:31:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 06567C433D6;
	Mon,  8 Aug 2022 01:31:46 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Ard Biesheuvel <ardb@kernel.org>,
	Will Deacon <will@kernel.org>,
	Sasha Levin <sashal@kernel.org>,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	pasha.tatashin@soleen.com,
	peterz@infradead.org,
	broonie@kernel.org,
	maz@kernel.org,
	suzuki.poulose@arm.com,
	james.morse@arm.com,
	vladimir.murzin@arm.com,
	Julia.Lawall@inria.fr,
	anshuman.khandual@arm.com,
	akpm@linux-foundation.org,
	vijayb@linux.microsoft.com,
	quic_sudaraja@quicinc.com,
	jianyong.wu@arm.com,
	rppt@kernel.org,
	david@redhat.com,
	linux-arm-kernel@lists.infradead.org,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.19 06/58] arm64: mm: provide idmap pointer to cpu_replace_ttbr1()
Date: Sun,  7 Aug 2022 21:30:24 -0400
Message-Id: <20220808013118.313965-6-sashal@kernel.org>
X-Mailer: git-send-email 2.35.1
In-Reply-To: <20220808013118.313965-1-sashal@kernel.org>
References: <20220808013118.313965-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fhFWLbzO;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:40e1:4800::1 as
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
index 8d88433de81d..a97913d19709 100644
--- a/arch/arm64/kernel/cpufeature.c
+++ b/arch/arm64/kernel/cpufeature.c
@@ -3218,7 +3218,7 @@ subsys_initcall_sync(init_32bit_el0_mask);
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220808013118.313965-6-sashal%40kernel.org.
