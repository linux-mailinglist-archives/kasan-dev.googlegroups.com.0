Return-Path: <kasan-dev+bncBDAOJ6534YNBBIVJZDCAMGQELGXPDNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id B9950B1B661
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Aug 2025 16:26:48 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-459d7da3647sf14885335e9.0
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Aug 2025 07:26:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754404003; cv=pass;
        d=google.com; s=arc-20240605;
        b=h8dwkpiQreQOWVFLyTvscCHSJZhmgui3JLAK8wAYKf0SEcKOozgMDU96fOmYnD5Z56
         Dui2FqenRDjtiZadvVIm39nCGjXI5n0WzW1h+TXfyyvzIqffTpKJTXKz7Jn+xcuXHYIF
         tXb3NHSNb9Pty8035/73eZwefnGpXM7DATOh2oPI3bpSZM7z+P3+iVptGcT3lX0vgLu3
         Lkh2SVVxSN+Qvv7K+F/6O+dTgqNYLj2pxi6o8t17flpbmX9C6bVLoCg1H9XchhHZZKTG
         6Iiln5nReKqPJOUpnpC/p/MxPPPdWFCLbsbUozoozz4vVqZuLGc5OKIfaaJ6rzsdIcez
         1JAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=RxO34AVkLocxpdq5N6UaR29ZGssyjDqopQzR1Qy6Hbo=;
        fh=5xopGmH54ZzYMb8v/FfP6cbe4rwKBmNXBFMCQS+sj0o=;
        b=bvGEU1/pHtfdIIpJbEE0kMGPpeC/Ia9w3xN6TQSg0JJCYCsRki0ZF/syK6oCecAB3u
         VZjf1u5VRLyHGzXxUSa8Wwbd8We5FvW9tuup/ggzDeWRywGw8ntL34elYvdfgeDPT18J
         06CoMu3KJZTgG+1A/xMnP/CYGSm8wbwW08zk5lIUqXHy0oMzPR3eJtBC5MomRcLd+OuO
         8I/aQRTuHUPl077warvPAzh3mcLGVCupy+8YgW31XC5kc26vFKyn3ft5KxJDAKkJpMTA
         XDuxmSvJGxtdg5bteNCHFBFxonBR4ucDgyUffoLs0N+Qt60euS3LFVAgSuffXNcdCRpa
         mdSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Povp77ys;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754404003; x=1755008803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RxO34AVkLocxpdq5N6UaR29ZGssyjDqopQzR1Qy6Hbo=;
        b=v9m8GvlAuhSEUNW4x2a1d5nJGvbgfdshmysKjQJIbMEa7Y3M8/d60Pm4tyZDEx2rsU
         Xku4UQI9wTlJMQ7xjx0jjFKiqG4+fdQQmr6Ye6KpMyE2bHw4qQ4WwKf1hKpYg+OiSaw4
         b9mHV2KqtBOFlwOl/GGoWtgU0fxBWxOsmeszGqnn2lNA/cbucYHPTF2pK0o1bTER/XEw
         BRnbyJ/eSgtHjvZv2hDF0hyLURjXqbm0clPT6WoX4uxKVQm1s2RDx8G0qGafxHICYspC
         GbQGUXUAGuqxk1DJ9p+EjoiP362sRZKaPE6O0Kh0nfT713MeGSWVDaWKczYNhR1qkt/c
         98WQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754404003; x=1755008803; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=RxO34AVkLocxpdq5N6UaR29ZGssyjDqopQzR1Qy6Hbo=;
        b=X/sz2m6uLQHoNsVtZ8gRucVCIG6OrY0c4AKc51k8WRoW32+NVZsR5GDhx4+coOlOy/
         N47nlqINfRDhxF/gpNkJqQmRgm8arQPd8NQHPE1fQXxGoBJztrRTICkUFHvKtgkWEBhg
         +JCT+k2vy7Oomb08NyiLf27lWDmGYXPjJB/cje22t3l88Ysz9stxG8+/BQiwoGSaKeEO
         Yu7+MH2TY0D7AQDXSLBRkI6FnxPQ9moJCrdNk3TYMpiZlJZUp7iYI/md7SYUwfqDZCU8
         yw2dmXM/Ps8B2K1+lS8WXsWPucbjPblQmdzFe2mpJ/EgmtD+Rkq0rv3JpL9YoHeSmsJp
         qRmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754404003; x=1755008803;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RxO34AVkLocxpdq5N6UaR29ZGssyjDqopQzR1Qy6Hbo=;
        b=UV/JaXxLcETJ0rODSy4QxtzN/Vpc2SfxpAZ+8or9nNJ4/Um4K/2JQVfv0Obsszqwvi
         K2LLZdnfFJKoNJ4DaPnj+jEFnek0I7hRQZ8G4jA1BjdmHSbvmExPqAqLJ4ImMdtYBWrq
         eSjL4Le/z1yvDSOCevx9XHUWqNYtzwKLQ3rXneaL5foEkSYl40mr7vMw42sFdOyb4ph3
         7pBWzP1ocdzz7IjnESSY4NDdTKd/x48ltA0vQS9LkgFNSdHy9hR95MRkAn/MEpTlR7ky
         bWilAlsnTo2YI4kRTjIxQkh3fjNj2xL2trH50a2JZv04hZHGh+9VFw2KIwANBXqH+Z4L
         6jkg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWgi1OrpmNuJRHfXJSCon94I8oyvEFnkN8EyNcCvQ/7KGW/G+psR/P4FlL+LeeP3xGG0hkFpg==@lfdr.de
X-Gm-Message-State: AOJu0YxRp7nHLwZXJDEprPEZau43bobYJv80KDeyEEsrCk2jzGu1CfkA
	Hx3z0VcszmhaLiVjjBQKW5PPb5rCXTKz+oc4178OvP3pYVh2j3SCWBmh
X-Google-Smtp-Source: AGHT+IEb8z5VaZO9M1HOoBkuru/oV/s2zzHkHeFbGQXCF5GsCfNoOG/SM8u5vC/6a0Da4o5wJli76w==
X-Received: by 2002:a05:6000:288b:b0:3b7:87be:d9d8 with SMTP id ffacd0b85a97d-3b8d94c473amr10395606f8f.43.1754404003503;
        Tue, 05 Aug 2025 07:26:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfeHtg+iKCXMKy1BhE+UL+dFhLaf89rvGsE27vx9XDNVw==
Received: by 2002:a05:6000:400d:b0:3b7:868d:435f with SMTP id
 ffacd0b85a97d-3b79c3dfddfls2611261f8f.1.-pod-prod-09-eu; Tue, 05 Aug 2025
 07:26:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXbVkWRfzsu7YEmdZBpgRvmfcbnDu8ZLVK57ALhRsJ1zfLspDFNilGcxhLB8SP2Ky30Pv3/E/lyp6I=@googlegroups.com
X-Received: by 2002:a5d:5888:0:b0:3b8:d2d1:5c02 with SMTP id ffacd0b85a97d-3b8d94c4c29mr10224729f8f.49.1754404001019;
        Tue, 05 Aug 2025 07:26:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754404001; cv=none;
        d=google.com; s=arc-20240605;
        b=INj88hg6PrQrp5oUxHcnxw0kwueC8cS9j+HtYGwIBPa5spEMBn9y39XTH3GNGt4JVQ
         i2La2cqh7WUZ8wAG53c4WIV5RkA5IeRwhQmviCJuefrZneRMB4tpXF4AM7Lc35MV6HvN
         Oo96RmeZwovYNYV4E+6SuOE3EcMim2WBlBFciEe8Fupypc9HPBskWhw+mZNTn54ObbK7
         qhkF6BbMzBUgXNB4YWuR2cw09RBBBJ2JYQxcZmBgj45rWnItZQ69oRTTmx3vxVkSrmbA
         ik1BvHthndAgEKFeF89ZJxVHHOCBcrKe9QoRLuIzJDTPVjUNtOX+NxuTZGaIsfTYzNDY
         R3xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DndoJEoEU+djai/jF18bii/cwZvYONRQ0C6xs3DhJyU=;
        fh=eAnyuu32RKvJ6JmMkrLf2P33XkP4Tv0DYbbt+GFot5c=;
        b=C10+O+FDoUXKusxkq09xeMalNSxxsh625j39GD5NToJ9xNgwu4QuxDuNgruNNFd9eE
         k75sdQ/uus6SBQ0Oo3aOx2+x+toyWYDfJdh/0+pun6kMvqw5CH7oY5gmfL1i6aq8x/8Q
         P35TanTdYMfIRg/MDWabm4Li0rEP9/heTNGCfsPE5wLYYNizI88BFZBbzseVwqdH+M4v
         BdFfu6JFFZOWoxCKk5yb79rXJJBmO9eid9sGHF08TcwXfPUPmVs8fqGmVV3vs/gbbOzg
         C00lt1Y5c43LeND8GmAdunjyqdWWTdBdWV0BYwzMAA7CGMdpxfwT9S93LjB88sTSC2s1
         Ldpg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Povp77ys;
       spf=pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=snovitoll@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b79d191681si298821f8f.4.2025.08.05.07.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Aug 2025 07:26:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-55b797ad392so5690513e87.3
        for <kasan-dev@googlegroups.com>; Tue, 05 Aug 2025 07:26:40 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWffSXj7GnweDiXhOzrJMmYWD0kIF7tSGcF3+ZAU5aP8xBy2WDMp1DRkzWKHYeJ4Bmyac0e4Apf/ZE=@googlegroups.com
X-Gm-Gg: ASbGnctMIeRElhYz90XL4Ln4t5d+uHvPatwWgold3ILfuFJUfeviaUKVBuANvPluY9t
	J+fitvJKktGMn44Q4tWu7ZxA5zR1ll+xiJIlt3urWiLURhXod+x0jXmTC88MpxaRPsLPhXv7Zdh
	4CGWfINw8PmDsymA/r7dik2DL+TxgZzl81v9RSjzfVQUVYRZGmsSw9R42jEQ1hJ90s2LrotSTI4
	IFN72jzsYqg1XKMxXCg4YKJOtenUPZP5el8QSL2moAWZvsCk12DOjnymQoMmsY/EoRYdVm2/T2+
	gwcnNch0dwTwgMgevNwG2xg9do5DnbgVzXK8KrFZL5wPxUCpxQq0w0QBc33HvYaBpoG0fLPizKu
	zlWKV100CmC+by3ZJS49U7ELw+QWgALS8Abedi88nMiMfd4ulrjpS5zwT1vo4J+WRcrz5TA==
X-Received: by 2002:a05:6512:1387:b0:553:25f4:695c with SMTP id 2adb3069b0e04-55b97bc54b1mr4200362e87.50.1754404000307;
        Tue, 05 Aug 2025 07:26:40 -0700 (PDT)
Received: from localhost.localdomain (178.90.89.143.dynamic.telecom.kz. [178.90.89.143])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55b889a290fsm1976379e87.54.2025.08.05.07.26.38
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 05 Aug 2025 07:26:39 -0700 (PDT)
From: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
To: ryabinin.a.a@gmail.com,
	hca@linux.ibm.com,
	christophe.leroy@csgroup.eu,
	andreyknvl@gmail.com,
	agordeev@linux.ibm.com,
	akpm@linux-foundation.org,
	zhangqing@loongson.cn,
	chenhuacai@loongson.cn,
	trishalfonso@google.com,
	davidgow@google.com
Cc: glider@google.com,
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
Subject: [PATCH v4 5/9] kasan/loongarch: select ARCH_DEFER_KASAN and call kasan_init_generic
Date: Tue,  5 Aug 2025 19:26:18 +0500
Message-Id: <20250805142622.560992-6-snovitoll@gmail.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20250805142622.560992-1-snovitoll@gmail.com>
References: <20250805142622.560992-1-snovitoll@gmail.com>
MIME-Version: 1.0
X-Original-Sender: snovitoll@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Povp77ys;       spf=pass
 (google.com: domain of snovitoll@gmail.com designates 2a00:1450:4864:20::132
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
Changes in v4:
- Replaced !kasan_enabled() with !kasan_shadow_initialized() in
  loongarch which selects ARCH_DEFER_KASAN (Andrey Ryabinin)
---
 arch/loongarch/Kconfig             | 1 +
 arch/loongarch/include/asm/kasan.h | 7 -------
 arch/loongarch/mm/kasan_init.c     | 8 ++------
 3 files changed, 3 insertions(+), 13 deletions(-)

diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index f0abc38c40a..f6304c073ec 100644
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
index d2681272d8f..57fb6e98376 100644
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
+	if (!kasan_shadow_initialized()) {
 		return (void *)(kasan_early_shadow_page);
 	} else {
 		unsigned long maddr = (unsigned long)addr;
@@ -298,8 +296,6 @@ void __init kasan_init(void)
 	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
 					kasan_mem_to_shadow((void *)KFENCE_AREA_END));
 
-	kasan_early_stage = false;
-
 	/* Populate the linear mapping */
 	for_each_mem_range(i, &pa_start, &pa_end) {
 		void *start = (void *)phys_to_virt(pa_start);
@@ -329,5 +325,5 @@ void __init kasan_init(void)
 
 	/* At this point kasan is fully initialized. Enable error messages */
 	init_task.kasan_depth = 0;
-	pr_info("KernelAddressSanitizer initialized.\n");
+	kasan_init_generic();
 }
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250805142622.560992-6-snovitoll%40gmail.com.
