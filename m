Return-Path: <kasan-dev+bncBDQ27FVWWUFRBVO4VODAMGQE64ELP3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F3823AAC94
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 08:40:23 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id f4-20020a17090a9b04b029016e9e101f9bsf3049387pjp.1
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 23:40:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623912022; cv=pass;
        d=google.com; s=arc-20160816;
        b=dAWgc3egU0NhxgScGDhZTXeX9KQ4tsg9G4EZtKOTJHqptRkBEu0aSAos6a/l+4XczL
         EwBiQHWfwE/RAV211gS4xAx4c6EUR7JlK8PdlfYYJali9ewrDu2COhi41l/ZUst9OjXX
         mgWiI0ClAlNfU798s+vhTmB3Xw4CJO4fwPcBCBf+fq2FEZjp+VIW/OCbq2sKBKJzXXL6
         5l6FRp0MhBO1aWQM8Dxr+I33036/XG8CXYajHgcma04ZMHMypJxPOXWZmspLM0a8M/fh
         6FUGnzbK1Lwxh8IPb1kcn2HTi9A54ej1kt4drIA4qcv9lpems2YucVYtVDXWw6Wsgdsy
         ZFpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=j7iMIr6HZmClhsMJitd4X9GSHzWvntNV8CCGv8jJUVg=;
        b=yJQdNE+0Zz/H3nuSBa8flxlpasLf0ZFXyOZrec0Pf6H2zfpfj2CV/oenqUMMu/A7lK
         00FBSeVnJP88GtqG10rFv2FBBD9YYyNTUSgDamILK10vMEHlzU2wpexDNiVLCHAyXUrH
         XCyHfdvm9dZA2stxsdrSNIrefx6Q7DhL95QeZgv92KzpZugSO6VJh51ShFuNxLtGSlzm
         SnTQNMmgNJlxP5rirCp24N5VXlzkKkJ0drCUXFAHR4TuS3u36czfie45lJzvkTvzLtmq
         BTclBXNctJ8w80Ktq7NyuQqyuunOUw43p6gxNFR1gZmkGuQQN8vf2y5fDx+KQfhV3O3v
         atlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=LW8mQ1aU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j7iMIr6HZmClhsMJitd4X9GSHzWvntNV8CCGv8jJUVg=;
        b=LZ2tQD5zWioiTe+PmS8X2dtqRT8IN+rqjnp26AnBCLxtbmBAS18SU5gLe/45Jb4Nqx
         Mm+xMAZCiCnZXMSd+UipvuHvUVspxYH0BN/m5BFSTv1JqYhIMGTSOkSXM1+blfJoasxv
         ulz2SklH5PHxDnAU4l8uUrnZ7XvL9/KgY48MMQZuV8BeN5WukA0ySlqkZ85m4Vr1ymfE
         tlNAC5qOAtNRbIUGautj/692fo995XGgHJbmOShoJgPdqk/jj6vLgXev2gTliMg7n/PB
         H/cL9I6n3SDEM3nNZ3NHjaUUVvZihDpPr3hoSeMjpaZPlDY1dkpdXcEYeeIAkhjVH2vb
         PqPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j7iMIr6HZmClhsMJitd4X9GSHzWvntNV8CCGv8jJUVg=;
        b=SRnACVSWx/ub8KfckKrS1IIQyKDoPlkFl7kkOYPnkGJDwDLBx7M+YahB+dhXQ+FMqH
         LrLgQ9tu8KJzAbJZ6uJ2vRMo6Gr7+Q5+6d8tK1IjcAyURdb/FpE95/Bo4yK06aU+tQ3w
         K2aRSPphqCiMRqAiDgUA08Dlhr04WcZpPWbm47ke/L/SKCSjZXMh5lzgt/93XuAt2hoT
         kj05Sk3VK2cUsTOlbSTaNOYPQt1JVBiVNdmtiE5OgpgDahSwZFOE5D8ASOE146SLyTCS
         Kqv/f07pDYgURvYF+oxB1TYqTMBcO8RuCh+qpFwvbB/4baHpSUGKUvKqW00kRf0I8Xrr
         uQ9Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5323dqHFMJ5RNiy3T+ZGWizlvm0UzDUw00Xl4Qinhinf11ZVBTBF
	3TUhmcxj0YxYdwzPwvPCxNw=
X-Google-Smtp-Source: ABdhPJxr/vsqhhZ4LQwgGDihm0C9+wnJmmQf++9O5EQJs8Z9bi1PBotAvsLFutecgTJ8yUqGeaHwVw==
X-Received: by 2002:a65:63d2:: with SMTP id n18mr3527056pgv.447.1623912021990;
        Wed, 16 Jun 2021 23:40:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e802:: with SMTP id u2ls2479801plg.9.gmail; Wed, 16
 Jun 2021 23:40:21 -0700 (PDT)
X-Received: by 2002:a17:90a:5d83:: with SMTP id t3mr15107867pji.195.1623912021515;
        Wed, 16 Jun 2021 23:40:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623912021; cv=none;
        d=google.com; s=arc-20160816;
        b=ULo9p2QJM488JAuwpvI0HPRbAYP2LLKUQbtDv92ZNNmrMOYBIixwsJxkdIVSbHaNSv
         cIcfV/E+wo/J0dp0fPekRY4UGIsvrY7OhfqIjIt+RFQgYIHyD7p7eShIqVTN+ZdS+Xct
         ZMw8dS+BQAcYmOVFBgKUBUpn5pGV+QTzt046vnnnQoMM93eFIpLtMQuBK76Vp3XAY0YX
         2mYS+PCLtr+4ypjIS9362NTk44ooEqISweIwfE4ZvoJx7d40p6703hjVxtDtZ6mlTpU9
         JWSI6nLk3tk+cG8g3wU3mlT29iOanID4KsFldcbSOQ9Hmb5K6xhFQ3WQbkuL+SMnjEZX
         R+0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=eRdt/wFzvgUcAph19a7+La8R0pqDnXPYkPybGzP3TFs=;
        b=BYFYBqPq097VlGDieNkU7i2SChh5VlcQ0VTXUO6Pd9vIRaIm7sY103CDhTBJ4bOuQJ
         NA6Kuo2z5go0VV34GydKIaIMyshztZIPJ8+22OFgrT2WAPFb4GZu0dRiqkbxiJmNA627
         rAcW5ncYY0bHDWMM6Hy6O1z+H6OloG9cDbiLR3T62E30jUpEZwcuVOpfCoKu27KBFbZg
         fpC+U0VcSujNeckajO34AJc5GDWggR46V2dPEKoAQDJbTzNqgFmQ0SpZwCQRMpV4uD0V
         oPQwMJk3B8S2c5dF0KcmMN4hotJpse3VeB9Cf1YzBZJxmGV4UDxaApT+x0x2YwgUXdzI
         kmlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=LW8mQ1aU;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42a.google.com (mail-pf1-x42a.google.com. [2607:f8b0:4864:20::42a])
        by gmr-mx.google.com with ESMTPS id y205si561292pfc.6.2021.06.16.23.40.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 23:40:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as permitted sender) client-ip=2607:f8b0:4864:20::42a;
Received: by mail-pf1-x42a.google.com with SMTP id k6so4162990pfk.12
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 23:40:21 -0700 (PDT)
X-Received: by 2002:a63:64a:: with SMTP id 71mr3578146pgg.360.1623912021307;
        Wed, 16 Jun 2021 23:40:21 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id o34sm717337pgm.6.2021.06.16.23.40.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 23:40:21 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	elver@google.com,
	akpm@linux-foundation.org,
	andreyknvl@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v14 4/4] kasan: use MAX_PTRS_PER_* for early shadow tables
Date: Thu, 17 Jun 2021 16:39:56 +1000
Message-Id: <20210617063956.94061-5-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210617063956.94061-1-dja@axtens.net>
References: <20210617063956.94061-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=LW8mQ1aU;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42a as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

powerpc has a variable number of PTRS_PER_*, set at runtime based
on the MMU that the kernel is booted under.

This means the PTRS_PER_* are no longer constants, and therefore
breaks the build. Switch to using MAX_PTRS_PER_*, which are constant.

Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Suggested-by: Balbir Singh <bsingharora@gmail.com>
Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Reviewed-by: Balbir Singh <bsingharora@gmail.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h | 6 +++---
 mm/kasan/init.c       | 6 +++---
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 768d7d342757..5310e217bd74 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -41,9 +41,9 @@ struct kunit_kasan_expectation {
 #endif
 
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
-extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS];
-extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
-extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
+extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS];
+extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
+extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 
 int kasan_populate_early_shadow(const void *shadow_start,
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index 348f31d15a97..cc64ed6858c6 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -41,7 +41,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 3
-pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
+pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
 static inline bool kasan_pud_table(p4d_t p4d)
 {
 	return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
@@ -53,7 +53,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 2
-pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
+pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
 static inline bool kasan_pmd_table(pud_t pud)
 {
 	return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
@@ -64,7 +64,7 @@ static inline bool kasan_pmd_table(pud_t pud)
 	return false;
 }
 #endif
-pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS]
+pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS]
 	__page_aligned_bss;
 
 static inline bool kasan_pte_table(pmd_t pmd)
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617063956.94061-5-dja%40axtens.net.
