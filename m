Return-Path: <kasan-dev+bncBDAOJ6534YNBBDUO57BAMGQEOGYZBIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 26822AE7E10
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 11:53:27 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-450d50eacafsf10065805e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Jun 2025 02:53:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750845199; cv=pass;
        d=google.com; s=arc-20240605;
        b=OMhoo0rT8JrCaoiZxgfAvNXSXLXBR/cJemfgETA+krPiHQyz3NbX3AYnDCWEFRfZqJ
         3UOiH5N3OeD74MofZQy38CcyXIOMV8A8V1NNilRDuT28HmMvL4j1ZLRJNRxSks2jIOuj
         krKRdpDskYJh1eoDK9/g0N/T8pfI7iGNF3CwO/KVQfgIlLI0PQLNWUk7PH0cBGRn2WeT
         HMBDao1OM6ovjVqhUZdEfX08WLrQyWlfrK/1OmkI65Y4+/oxZiclDRScbcZAKHQlsp5m
         x3rHbMGd30vJbG4iBuYgWptOu/DuPpvVMzMRzCCqtC7ySWEI6DBuAx2ILiEURnLynqgM
         MPIw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=jeUJ8T5VYf/6YCgkFQ3lfVjWJC0per1ChQTckSCpqww=;
        fh=MDDacB/BF+7YDEcXe/jWD+U7v/KeID1nvXAGHPcholY=;
        b=U6KHL3klnv6WVtXvBAo3Wi7INgHMkSjtKif+qqdNVgywtLfMrohHbl+TTv/aOLFf9z
         Hefn1lbLYvAxNm1E/MY6WbCMYHIuk8/8ZDuhQDu7Wk/64lj1Z9h5YCczTJO2bgY5VqrU
         OLE6HYzZyplt2f9DRhwrZV8D9wSyo6nYLJeFR2wU1ppaJsngQ0jKvQ9arOH9t2u2YaRi
         1PkRaO/YGdioXE1aM9F3v+J3RIDw5iFPve3aBdTPtJizDQGL0EcXNvobzX2IWUcQhjZb
         IgUemjd/dRBhJT2DHMEMIbUvS7CgiyQ8mumKCv28gLXn7GiZyX5f7pl8ptxhcoDNGoJ0
         VoAw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CM73VGbz;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750845199; x=1751449999; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=jeUJ8T5VYf/6YCgkFQ3lfVjWJC0per1ChQTckSCpqww=;
        b=IbgxeObnI7XkP7tXlRZvE6AdqDsfVI2M1pltJd1iFZWxB22xJGhTc1tel2HtHFseev
         aDbuyNtn99+Lu6uGTo4pAVUXWzyMSQpAsBFRkSkw2dRHdwbMol0ebninA2GvWkq+Ra/5
         22Al6YVC5vobg4FfZ2CzrSF3x4n3gx/a8/hrBMwDjTIfcLzJ+b5JKItD8cSYC9Judy8D
         iueeivIPp8sARPdS0wGf7n46UpvN+cxGp/+cqpKf4AxJ9rT4UgxIsDablTZHilCYmuai
         doCIfw0RIObbZ17ONwpFrB+L+K41Xd5kaISEHy5NqYwm7M74h+vEfDzAG8ToGQB9BO1O
         AaGA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1750845199; x=1751449999; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=jeUJ8T5VYf/6YCgkFQ3lfVjWJC0per1ChQTckSCpqww=;
        b=Y4TLbeV3iFw+ibYqbzzuPv5VY0b54cEAe58h1X91xFGkfJahAEb6h060946FfCGKOZ
         pEAMPvLFD55kqBeWRO5Jo35VSKaAlFAyg5BO3BZM92sH5PwEGFhCDK+ETVSZt+XkyoXd
         CZj58ElTAvmdUXKgRWS7vIzu+8uyhtzn/Ahplipodov1GoSHBbMsFmI1dfpJlyAW+NXI
         LzW7InqovVu+R9iJ16xrxpJwm8MH2mySIfbSCXgXeViTkt1TMW1kzNTFSqNo0hbJbWf3
         3wTF3fQGt4Tiz4ENTBH4PV/F5akbodVM6078TITAymu//0sdIBh9n6rLmv79ajoZ7eTq
         IrMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750845199; x=1751449999;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=jeUJ8T5VYf/6YCgkFQ3lfVjWJC0per1ChQTckSCpqww=;
        b=f9MAZkGNEaNlo5XDJCACf9zGfvdDfQzBMPLhvkANWEwTATh40M+4F8m7wXHPstlHrS
         N1pg+em3QwCCqDsFhK1+NRw6kiK2KRMtVwHZHCPbNf+wpCCB6CdnaEZ/xuC/7OsXLQf4
         ZEqbLJZmRvCowTGkPegnehu5CVKH/rWehKkV68Q0w7Iv/2GgEaUYNvj7WXPhwTpfHY9u
         p2RwqMGJdxrbIyovir4eI6cgp86ydBfu0Zt692vzSdnMra1IxaLVsMPAjbwkJW6RFIBG
         Ynx5I2cUyKqMd+e4PDoiNnc/NHZxJ143cZZaooRWZBnl2szPdPK3H3puhLuJVZZS0VRJ
         GnYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUtsvIreW6giWPFC+QMS5ucTI764bYG5ftC+lsBoMDooeJ/Gd2FtKIzr3gn3wjeWtPVA2FPdw==@lfdr.de
X-Gm-Message-State: AOJu0YyWBH3agDeITq6pzLnWpMqqqMh+xx+cxQq3jkSDliQMPwktBJuq
	Tlcnu/uu0c0wNh6icRGT3OTv6hs6pSU1p2IlLSCavTtWp84CyEDKmBeV
X-Google-Smtp-Source: AGHT+IGEz163RjB7qvvoBCYqgp9BO1kDOSsCsJlIx05B52x4t64i2l54tdys1Kpuej2SaRLNTfOsBg==
X-Received: by 2002:a05:600c:8714:b0:43c:efed:733e with SMTP id 5b1f17b1804b1-45381af6270mr22956955e9.14.1750845199137;
        Wed, 25 Jun 2025 02:53:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdz+NGl5U5Q6nbXbm4ygE4ZHdTA1pPa8hinNOI62p5MkQ==
Received: by 2002:a05:600c:8209:b0:43c:e3ef:1646 with SMTP id
 5b1f17b1804b1-45360ed2d12ls32069835e9.0.-pod-prod-02-eu; Wed, 25 Jun 2025
 02:53:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUknHd60U+4jLfAQ7bs31kPPbGgJP7jlUCRFpDYUCuEdgiEv6aPrKwBhlEWoSs8Fz+qvpniHaJNsqA=@googlegroups.com
X-Received: by 2002:a05:6000:310a:b0:3a5:8cc2:10aa with SMTP id ffacd0b85a97d-3a6ed638631mr1412607f8f.32.1750845196675;
        Wed, 25 Jun 2025 02:53:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750845196; cv=none;
        d=google.com; s=arc-20240605;
        b=NeiXPRoJ9WJTQp3lSuhbaGgLm7eFER+P0LbrvKNE8C5g8CXM8P0SId82iOWnwv3yAY
         fIuB2asjRuYqW9u0EyxPKBFA08JC2YMKFsk8Pgscxr/O/9H05h8d+g0u7dQOO6j4MKo7
         qF/ulKpuFmOrmc+3ACkuGTDpYt+17UXtKMvNYfRCFuNRtA8KinIeBCksiJakQKN1bV8Q
         LyRnAjUYu94sIibJT1OC4PBwMHCIPXiPY/9w0SKCoFmKOzx30arP8uUWpBZP5cLs+bAl
         MkThy8aUFNefJixDR7XWcAXGkcfymgVm/AXS/Qw0UW4hWF17glVsG9U9s9NEDY7D1ZXi
         abtQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aOegpAuvdkFcZey7AJnC2ppf18uuNZebWg0aRe4Uqy0=;
        fh=K1XUhIOhi0Q96FLue/V5LyeiKQKlZd7PEQVweVq4hsY=;
        b=JSgr/FEI5KJC4fnuGjBZUAfyKLI71IKw3n/MKwJq1GD9ezk/qv6N/TryuPnXyaCJhR
         FIBG6WUEvALTNqhT/q+cOC6uF1d67NhkEgDBt4IXT4KZHtagr/h8W2Qje9bA7Gf81sDM
         m27sVZmOTcxbeuivdEZPik58ec3PDrRqaG6DvyR1AtuP01ZdTmISFOTRUdhoJ222GRGI
         XkMq0RrxEeghgezlC58lfiY8c3319VMBg372oPfunUStw8PZaWBSKBSTxfsPCwQ7quX4
         KarX8Diu0+EwRQLu2SA7zKw0fZVgj0e0llJqqVWhWuCG4RgFHMkEykoC9dQGPdk0SC1O
         wCWw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=CM73VGbz;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12a.google.com (mail-lf1-x12a.google.com. [2a00:1450:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-453822d391csi282525e9.0.2025.06.25.02.53.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Jun 2025 02:53:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12a as permitted sender) client-ip=2a00:1450:4864:20::12a;
Received: by mail-lf1-x12a.google.com with SMTP id 2adb3069b0e04-553bcf41440so1448444e87.3
        for <kasan-dev@googlegroups.com>; Wed, 25 Jun 2025 02:53:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWDIagdMh7OSXQSroLjubVcVZMAAjk2fwdsqEGcNaW4ljEj4Apwi/WseImZ8Cww4xfzW4iplDuZnms=@googlegroups.com
X-Gm-Gg: ASbGnctZbDxWXJftzfSl4dkmcOZMHIrWLKbGVc34ipbD/KwRuLZ4neqwOs8jaEs2YS0
	tdgEwQ5Ui81ROhDMZwJvfI4Xqoz6IpuiKsaEMyIJCt5NYoosJTUGbT2aPjOjzdXb48X9hHcLvQS
	RbpCPkHMSg3urq+laVGDD1ZFoQfVrphSiooUD8lCUOT2oEyn0gUjGCFb9yAv5KRXY+r7qVF2CvD
	Fh/V08iSYZEHGfWgWJEyctuwt0JreGoUjZ3gurAUGw4NFdh7px/Oxe4marRchVN+RK1g9O17eyW
	ya7H7pLmOmuxwuac4ct7MlKDnpbHBvLShiNRIePMDkIKci8sY/yBWWcIwj6LPE5+8TJwB4hu1ft
	bwwpGBXy+62rNn/W5qIuvgfjr+gHD5g==
X-Received: by 2002:a05:6512:b1d:b0:553:ccef:e31f with SMTP id 2adb3069b0e04-554fdd428c7mr668464e87.13.1750845195630;
        Wed, 25 Jun 2025 02:53:15 -0700 (PDT)
Received: from localhost.localdomain (2.135.54.165.dynamic.telecom.kz. [2.135.54.165])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-32b980a36c0sm19311851fa.62.2025.06.25.02.53.09
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Jun 2025 02:53:15 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	catalin.marinas@arm.com,
	will@kernel.org,
	chenhuacai@kernel.org,
	kernel@xen0n.name,
	maddy@linux.ibm.com,
	mpe@ellerman.id.au,
	npiggin@gmail.com,
	christophe.leroy@csgroup.eu,
	hca@linux.ibm.com,
	gor@linux.ibm.com,
	agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com,
	svens@linux.ibm.com,
	richard@nod.at,
	anton.ivanov@cambridgegreys.com,
	johannes@sipsolutions.net,
	dave.hansen@linux.intel.com,
	luto@kernel.org,
	peterz@infradead.org,
	tglx@linutronix.de,
	mingo@redhat.com,
	bp@alien8.de,
	x86@kernel.org,
	hpa@zytor.com,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	akpm@linux-foundation.org
Cc: guoweikang.kernel@gmail.com,
	geert@linux-m68k.org,
	rppt@kernel.org,
	tiwei.btw@antgroup.com,
	richard.weiyang@gmail.com,
	benjamin.berg@intel.com,
	kevin.brodsky@arm.com,
	kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH 5/9] kasan/loongarch: call kasan_init_generic in kasan_init
Date: Wed, 25 Jun 2025 14:52:20 +0500
Message-Id: <20250625095224.118679-6-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250625095224.118679-1-snovitoll@gmail.com>
References: <20250625095224.118679-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=CM73VGbz;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12a
 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Call kasan_init_generic() which enables the static flag
to mark generic KASAN initialized, otherwise it's an inline stub.

Replace `kasan_arch_is_ready` with `kasan_enabled`.
Delete the flag `kasan_early_stage` in favor of the global static key
enabled via kasan_enabled().

printk banner is printed earlier right where `kasan_early_stage`
was flipped, just to keep the same flow.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
 arch/loongarch/include/asm/kasan.h | 7 -------
 arch/loongarch/mm/kasan_init.c     | 7 ++-----
 2 files changed, 2 insertions(+), 12 deletions(-)

diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
index 7f52bd31b9d..b0b74871257 100644
--- a/arch/loongarch/include/asm/kasan.h
+++ b/arch/loongarch/include/asm/kasan.h
@@ -66,7 +66,6 @@
 #define XKPRANGE_WC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_WC_KASAN_OFFSET)
 #define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KASAN_OFFSET)
 
-extern bool kasan_early_stage;
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 
 #define kasan_mem_to_shadow kasan_mem_to_shadow
@@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
 #define kasan_shadow_to_mem kasan_shadow_to_mem
 const void *kasan_shadow_to_mem(const void *shadow_addr);
 
-#define kasan_arch_is_ready kasan_arch_is_ready
-static __always_inline bool kasan_arch_is_ready(void)
-{
-	return !kasan_early_stage;
-}
-
 #define addr_has_metadata addr_has_metadata
 static __always_inline bool addr_has_metadata(const void *addr)
 {
diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
index d2681272d8f..cf8315f9119 100644
--- a/arch/loongarch/mm/kasan_init.c
+++ b/arch/loongarch/mm/kasan_init.c
@@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
 #define __pte_none(early, pte) (early ? pte_none(pte) : \
 ((pte_val(pte) & _PFN_MASK) == (unsigned long)__pa(kasan_early_shadow_page)))
 
-bool kasan_early_stage = true;
-
 void *kasan_mem_to_shadow(const void *addr)
 {
-	if (!kasan_arch_is_ready()) {
+	if (!kasan_enabled()) {
 		return (void *)(kasan_early_shadow_page);
 	} else {
 		unsigned long maddr = (unsigned long)addr;
@@ -298,7 +296,7 @@ void __init kasan_init(void)
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
 					kasan_mem_to_shadow((void *)KFENCE_AREA_END));
 
-	kasan_early_stage = false;
+	kasan_init_generic();
 
 	/* Populate the linear mapping */
 	for_each_mem_range(i, &pa_start, &pa_end) {
@@ -329,5 +327,4 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized.\n");
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250625095224.118679-6-snovitoll%40gmail.com.
