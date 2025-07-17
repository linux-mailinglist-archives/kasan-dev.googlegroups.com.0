Return-Path: <kasan-dev+bncBDAOJ6534YNBB54Q4TBQMGQE4RRBYVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 99B1AB08F41
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 16:28:08 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-451d2037f1esf6250615e9.0
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jul 2025 07:28:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752762488; cv=pass;
        d=google.com; s=arc-20240605;
        b=faJ8wrFNlWveFkxc5YCU2w/ygZ26v1fBesvC9pZmHNA8TXi3CaYSws2kVFqMi/cBiR
         +usdE/iQD73CiO0Lhcb3qiNEhOhmTMgDzY13dg/EGT3Y5QSkm3o/DDctq5/jVl7dwQPn
         B3zLnBRORF3paZxReQrzJgWtHZMm8dDyF+SvxUS8v6lWUCx7MPTMg4S6d4Ep9SJXNJAk
         FEaxgR17NadOJHU2oNDuWQT/BphIPGV4awLH6I1+FNGlc7mdvW22oeMu9L36jPej6jN8
         p79IxsVfCEEWXrPwnRwPl7nKJh7W81oItTlA9UMdghiWd3RVEw8MoKe71l5mYwL0/AuV
         O6Rw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=ax8F2GTPOBO7wJPYbjhrtaV4rdO/ktsWNxUgDgmizjg=;
        fh=3RnrahySU4YWDh2F1NbU2POqtfW1rUDtSSogQWbZ7rg=;
        b=kJ353GuSgjyegWLAuFnq1ACYkk89ggCuaEOx4o+IeuFJYTeq19QKV9m73c79NhF2eI
         zWAnx4/YmZgpTJh51vekm4xEl78o4HN3pfGJQ/EssPAhEz78l7BwgD6ZVflJqpANPppY
         sbt5afFvs8nybYElCtKEKUQenK5p//2VwvaMptb/Hem7buo8rNBlkTMPtLVcCK94I9ut
         Btsqwua2X/SqdiXvCQeLUpo56UI2vqBOpYveKMMF0yuZOFBMGsToAeNddy66+HcRQ6S0
         tzRE1+LeNgMGrnCAxhy0XUZuD4X5T+OtfOTU/SiUh47ybcZvuYSPOfVjJBXg25jOy6vh
         Zj+g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jIwqmINS;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752762488; x=1753367288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ax8F2GTPOBO7wJPYbjhrtaV4rdO/ktsWNxUgDgmizjg=;
        b=wgXl8sEo8UejXYkvf4hPV82575xrjOMWNtmg5euONABLbhGMZlwlPEj9oGS8uV/aQ/
         RdrfF8jgQTJujt39Az+2Gi+aeRyYlNESGc8spr0QklALgK5SFLpJmtThPY+4freoPCzH
         FkKnuErqGkruEfC6o5PSLQuG9RW7ZXW4as/T6/0haTamdBFjKg7rarbp0IJPTGORNCLi
         zZ7uDJU1pvCdMms4aGQzhuNnCocwVRHPtAektWSuqibSMqqQq6eAYabJwqbsBlVtw0eV
         fV/j2BLluHxJ4G1Fp+RxfEne0Q0Hi0iuXFALGMAulUMHBLPxpW5QxXC7fn3NwL3HnO/Z
         OmCA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752762488; x=1753367288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=ax8F2GTPOBO7wJPYbjhrtaV4rdO/ktsWNxUgDgmizjg=;
        b=Y05tbrAznlkT37IHB659OJxVRHGDkgT5uBZ5dOV4VI/EZwx9UkuCP2PhTGAimooJMR
         fSYLaRD5722AZ0SFlw8q4OqKsSASUbn0/Uj1bc1cehKfBUMNcJuCTgO3e097s3r0xOtA
         WaPzezjAlwHrAdO9X+w9S9LlHLy+LlFATQ3qULVRp6Fv55mMBQqWB711vrCBYUIgSxgK
         NPNtfkfDp1ZbYr2sDwFhfnAR7q37Zsh18JBYszB9vQlJ7hZpzdSWIBnQuAJ2kWpKVS61
         sT3/y493RS0RZpIZ3ZG+/oKwvhWTavTYSbdrDYegwJwivTjDkdvbCozFVVLOFw7q/h8F
         gxvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752762488; x=1753367288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ax8F2GTPOBO7wJPYbjhrtaV4rdO/ktsWNxUgDgmizjg=;
        b=EbxVs1TLSD097j73MQdyHj/fYlUb30ewY3l7ujAsfWLrqvWvwrcoS3VWD3xmxfNgdu
         V14v1qnDt6Z2swCe13RtMxrPTlBTgoagcvAk9LXHcPWKxdrKIjuUD33C6lFyNjMabGIq
         PF29ZCwAnAVJYlxKLVIRlhb+VXF5YwFnhpAuwFVYUk/S6EABjJw24tz+3LxqVKYTc2BU
         3meoYXkNMlPgyaO/qBthf6YYCPYicoIxEvkBYnfvFkOY5dq7JDG1JKALTMV6wod8JaKY
         N1vCWaxsa0fOwtqZF1U24egTyX5rTdyDo3W129iQsRQTvu9fX1/lzBqV+uGD3Ked/Rgj
         Kikg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOk2gNskW7HejwUHmJgDKQIBGmQBkZzmCjddmzU06V2JlPKYgi/krwvza9A9DbccUAyj4dCg==@lfdr.de
X-Gm-Message-State: AOJu0Yx5KT3GBHeNqwBvIVSrm9lk9H7BqEPF46NKu7Mg7aqSg5rmdvU1
	39ZCTIvaHuCbQZmAHng+6hGf/fjqMEKMgxFwbkcq8KAg/mu1pUvQnWGg
X-Google-Smtp-Source: AGHT+IFB3Gq8hxcnR/bfAHRzCCJ66Ft+fcwIO4wWCcVQU4fWeR3mKSjoISvasGM4hglSaP6cxQhmrg==
X-Received: by 2002:a05:600c:a088:b0:456:43d:118d with SMTP id 5b1f17b1804b1-4562e38afacmr75058685e9.17.1752762487698;
        Thu, 17 Jul 2025 07:28:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcoDy45AlTfiDCaQW8SuvTb8KF3K9YMitYZomFwZ2/xEg==
Received: by 2002:a05:600c:871b:b0:456:241d:50c3 with SMTP id
 5b1f17b1804b1-45634190503ls5569935e9.1.-pod-prod-08-eu; Thu, 17 Jul 2025
 07:28:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUBpIDhWpYrSl5hGX+xR80BAhKa3ebtAhsI4VUXHHecpZYBV2iarcZj156hmqF0bPFd93ltuHAYIZQ=@googlegroups.com
X-Received: by 2002:a05:600c:6097:b0:456:26ac:517a with SMTP id 5b1f17b1804b1-4562e3914b3mr66031635e9.24.1752762485172;
        Thu, 17 Jul 2025 07:28:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752762485; cv=none;
        d=google.com; s=arc-20240605;
        b=iuyvExvQ/m3IrFGvOv082Wc3rah4/GLqnf1kT81SUmZunB6VVPibyboctreeW330f6
         yMiyFZRFS5A+x6yRT+Uy5GVywyRZJP/YcOj0OTDj/f+JncrHmycxoYj7JvGkQPeT2vvL
         chZAcxAAtPw5TKnZaX5V/qK+hQJmIRSUnGII6X1/FW0b71tfhH57E2q688+EW4IGOn2N
         QqafPsIRZgUgswT9inboeAeWnqEAnubWPEcUsAR7j0xuss181l+vADEw3GJfplb5GXVJ
         w8O4+xX5hMSS3WMtywUEl/HtRRqhaJC/Vl3ib7PsiVaDoRsKuByJ+TBzDH9PvbCWgRWT
         2pCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VQlEQnJy2HJRDhHnfkaTRfud2Lma6wEowy/1dG9z9wI=;
        fh=wM3ZUTsIPPsgXb5nJbvhigdTlLNA8iKatdndrrzhtQs=;
        b=HZPiaaKo9xAkzazJ7MiNTEoTLMvKxrpXNMCmrSuqHklQ24uRzXwnDsS0EgopmwCQgL
         L6sNVt6z0hCoaWQVUiKHbGaZCTAoLaOIgUvYLeSD7jd7EkMI4EV1RboZIOKJS9a0e4al
         Bpy31/dXC+MmgeTuSqeZOjQav40DYMHl1+zXZAJYrHfcvvQNfMouBhjGjj9Zjg3HDNKM
         RCBIUrE1HSRD4ZO8bOGtRAaAuAY+s67PrSAbsI8GHAysqWejFxC2eGREBBIy56zcOEQF
         cx/2SwrHWY87LvLAhrf4aeq/iNRaga7t+yOr0qPhOqEJuf5HhfDMFH6LMZgAhBeUQ6x9
         Oy6g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=jIwqmINS;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12c.google.com (mail-lf1-x12c.google.com. [2a00:1450:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-456278a0118si1070455e9.1.2025.07.17.07.28.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jul 2025 07:28:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c as permitted sender) client-ip=2a00:1450:4864:20::12c;
Received: by mail-lf1-x12c.google.com with SMTP id 2adb3069b0e04-556fd896c99so957790e87.3
        for <kasan-dev@googlegroups.com>; Thu, 17 Jul 2025 07:28:05 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWz0TSQlFp2GxrL9jSIr0rIwGKLSgg/Dlc71yxSPZzoY/sa/OK1x+HNkMuot1mRK2/X27BoTM6NA8I=@googlegroups.com
X-Gm-Gg: ASbGncsq8zW5y10ozEtC8mPPSfhraNTVBLO4MGexV4n3qTZdl7SDKLsyUtFGRFvVyAM
	ANx+ytZfl9jQVMYRMn1kzOJcHcO0VZKC6T3PpC+1hLJBQzGBvJWgUk5N00IspmCiO48WKtIesNs
	bvJRd5ctYqA+WoVS/k4mH16jyE6sqg+koPXvVki0kS9gUEl3qlMIYnOUA6B+YBL9/fCISXSW/m6
	C5riK4Zfs+XxFgFZNc+8qvBMGXXkJX+vbec3TBZYoHEbEIaJEnwVcotY1M/fgE6+pi91FQngKVY
	7VPE4N+JbyYJpkFymntUnP0URuUBLOKxArPRzaf6NWQuee+X10XUXSFOUwBAVJmayi9voX4ZdNH
	FMJ8TXtYppVpsTirWaSWiW0rFXbuYKxj/dj73+wtYN4ZPMkm3uifuNo6tWoTWDx/VdP/W
X-Received: by 2002:a05:6512:2310:b0:55a:271e:965c with SMTP id 2adb3069b0e04-55a271e97f2mr1332318e87.55.1752762484050;
        Thu, 17 Jul 2025 07:28:04 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55989825fe3sm3022975e87.223.2025.07.17.07.28.00
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jul 2025 07:28:02 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-mm@kvack.org,
	snovitoll@gmail.com
Subject: [PATCH v3 07/12] kasan/loongarch: select ARCH_DEFER_KASAN and call kasan_init_generic
Date: Thu, 17 Jul 2025 19:27:27 +0500
Message-Id: <20250717142732.292822-8-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250717142732.292822-1-snovitoll@gmail.com>
References: <20250717142732.292822-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=jIwqmINS;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::12c
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

LoongArch needs deferred KASAN initialization as it has a custom
kasan_arch_is_ready() implementation that tracks shadow memory
readiness via the kasan_early_stage flag.

Select ARCH_DEFER_KASAN to enable the unified static key mechanism
for runtime KASAN control. Call kasan_init_generic() which handles
Generic KASAN initialization and enables the static key.

Replace kasan_arch_is_ready() with kasan_enabled() and delete the
flag kasan_early_stage in favor of the unified kasan_enabled()
interface.

Note that init_task.kasan_depth = 0 is called after kasan_init_generic(),
which is different than in other arch kasan_init(). This is left
unchanged as it cannot be tested.

Closes: https://bugzilla.kernel.org/show_bug.cgi?id=217049
Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
---
Changes in v3:
- Added CONFIG_ARCH_DEFER_KASAN selection to enable proper runtime control
---
 arch/loongarch/Kconfig             | 1 +
 arch/loongarch/include/asm/kasan.h | 7 -------
 arch/loongarch/mm/kasan_init.c     | 7 ++-----
 3 files changed, 3 insertions(+), 12 deletions(-)

diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index 4b19f93379a..07130809a35 100644
--- a/arch/loongarch/Kconfig
+++ b/arch/loongarch/Kconfig
@@ -9,6 +9,7 @@ config LOONGARCH
 	select ACPI_PPTT if ACPI
 	select ACPI_SYSTEM_POWER_STATES_SUPPORT	if ACPI
 	select ARCH_BINFMT_ELF_STATE
+	select ARCH_DEFER_KASAN
 	select ARCH_DISABLE_KASAN_INLINE
 	select ARCH_ENABLE_MEMORY_HOTPLUG
 	select ARCH_ENABLE_MEMORY_HOTREMOVE
diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
index 62f139a9c87..0e50e5b5e05 100644
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250717142732.292822-8-snovitoll%40gmail.com.
