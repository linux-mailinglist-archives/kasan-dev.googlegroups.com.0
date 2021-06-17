Return-Path: <kasan-dev+bncBDQ27FVWWUFRBUFMVSDAMGQE2DJH4QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id D8B073AAFBC
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 11:30:58 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id i15-20020a056e020ecfb02901ede9c9d267sf3428677ilk.18
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Jun 2021 02:30:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623922256; cv=pass;
        d=google.com; s=arc-20160816;
        b=fqdd5pHICiF/EChIsLw9JSRmJmmVEabJ4JvoL4vzEqLQY9kjT9EogqKY0zSBpLPzue
         KSpAc/AQtOAlDKXcJ1bHdKef7TxSGJMozKtT2rtSwjTNMd/WkJ7WlXnGYRBjqHDujdke
         P2ogUbqqGuHrsMG9+5hSkzprqgC6gyl0k3k1yimZptuK97X1hyvYRXIlP3xgquna3mih
         Ivvz6A2TUjkwjlDoHmNk2cWk6NWocQ+ebhzizAlTI4A06A4sFd3q3YsnN/MZv28v8Oza
         dr6RciYUcwspRCbtJl+cIs58trvHBxZwahGUKan/2axBtLhQhReHf8PplmMphRU2XTaw
         8j4w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=LbjfPQSzIaTfUl0euw3q01deqbrSuto/foHLqExLr98=;
        b=fVjpfmw6gRA8+SOECYgF5kkeWPLyMJ2BMyAnoXib42d7vI7EKLFtYhLUpPtB2ZCWlx
         2eGBBy0X3UYFvNDBrxsbbOHZGALsJS+64MwB+ZQBDsC4dzva7EYuM+doT3/ccOlpVtNA
         bSKUNlEvrx2TSZYgo3FiXe+lgJs99/BTugXpVJTG8cob6qqW2z9DlF3KIZW95ZdFRxA7
         Y3JtRpBso5N7QptsVtz9oqteMR0zwPqcGGZh8pOS4r22nCt27vafLrSL/W40zNq/A0hp
         MG9gXKK5g7eqEmG/fGsLdzGJjxZ1hMxmDxUo6oaHvNgF7kiT3wWqrxQfTX6IPnBb/6Yu
         h9Xg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ApqW+b4w;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LbjfPQSzIaTfUl0euw3q01deqbrSuto/foHLqExLr98=;
        b=oYTU179leu+r4e9wGULacYqHM1lQlP61r6q3ieVo07ZDxi/CkgHt1m+bTHmfyVCvjA
         1cQc8WWa/ujGBYm4tTBEG1dh/pJlcARfuGaQFqcoSR1X8ZH+jNDP2ZrUCcg80WLmBRRg
         U94oz2OeWCTrevmYxszzrI0QvnGUyQuNFx2dDzzdGwaFZrd/2+RrXeqItTWUOl00zADV
         7G3HhTQTrpAASHGNqprpg0CpFrI8UQe/szF9UjpC9AtmfN23hlwp2guC97QpFn8JEh9O
         jwq6trRkktJ9zrCqvppl3igjdenn5LCKXeqPmhuFCjsPP33Lm35GC8WhGbGhWADShGaN
         rqLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LbjfPQSzIaTfUl0euw3q01deqbrSuto/foHLqExLr98=;
        b=tjb0KGGwRfDJyX3ojFhiVQYf47RW9oJOwMz0Z0Nn2eGxNGUGrq2+U4TQZ361M1Kejj
         Gll+3i/vFlGGSShUamj6e/0wsdTeMPN19JQrMFccJrqnMgIeffGzmKgwKx0Pjzjhwuk/
         o69uloSEqR++FI4e1YwaLw5WA034beEIGWulIiB7ZisznXX+OTRswsLMgi7vdEypxog+
         CUjiibvjt9l9SYn4y3FVDchPLQVbMtKRQ+Rch8XFAyd88GcG3qY6xT6oLoBbDEXUhTs6
         2E9cKHDILwz4wZxsnIcbdoIhZQmdo+G6T8keFPFPNhRjBTMoeDynULKVTuKjgILh3XHi
         DEeQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531RrVna1GgQ5gA4T4aLWTWUUxVTQUiSndcDCEVI+V99OkwVRloI
	+0d0UfANf5/kSUEPk91Fr/U=
X-Google-Smtp-Source: ABdhPJwl1r8pn6CF7r93Y0T0t6V40fBpJd2FbP9uPvu850klTa9r3r614VsrO9mbQNLkohzbowmImA==
X-Received: by 2002:a05:6e02:13ad:: with SMTP id h13mr2878693ilo.128.1623922256493;
        Thu, 17 Jun 2021 02:30:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:8d50:: with SMTP id p77ls852199iod.4.gmail; Thu, 17 Jun
 2021 02:30:56 -0700 (PDT)
X-Received: by 2002:a5d:8254:: with SMTP id n20mr3079130ioo.85.1623922256189;
        Thu, 17 Jun 2021 02:30:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623922256; cv=none;
        d=google.com; s=arc-20160816;
        b=Rcnwx2KH0gDbxrKBbYbZ4EQ7dC280sJHYcNSpnFTHv6aRP068VbVrR7qYrZnKH2Bvb
         eLefn0ztZPr8CnZeezY+mvF+TzcfKQmaaHID6mWLKnoR2CgZ3L5lfopG19nECWbyy8qP
         F8r4pheY1ZZm0hX0Q3FcaCK+oQiTyd4BbsNlA6YMz8aoxjLaSLlOwtV2vHx6ChXT6XIC
         aIdxf5bFO91Z05S+y/2S18CKMGxdWXQmkpxPl4q00kFSqXqXCqSzVvpWYXCVQUobXrnJ
         SGgY/ZFJQtP4x9lLlzPBsUaoEuHgU3oez/6hbRK8ZLYmpwDJ8Y+FKFgatVer2Yz9Gx9K
         X6jA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=lssK+06OrqYXMI/RYJk+NygLCQ6hQhXYMHdalKVel+U=;
        b=opkfJhANNR4G6enBuYPwj9qKtr2xG4LjxLKguFGM6GQlBCjv5IZsXfBEmsGc+HWqCa
         k8aQ8jwng9hNPt7+QPvZZ28ViV0aEV/4ToKUPl5S+sN4JMi7eLZOJpnGnnFwhS9xFMhj
         el0Ej47j2Z+AolqQ4HqnYZoS8mTCkfJo1kaCoiBc4IEzZsUNSnhbRARclCtjjH1cyOKH
         atVDZkki5ouhJjkKnRQnCTabhRHYrAV/uFXgsBqpwuhgtt0gv55leBZzJDQEuH0t28dm
         AespKeajqheymJPAXgWxee5HqCBK9GfIn9tblpl+ub34lGH8mMmmkr8S+NVzL55bDLN+
         KJPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=ApqW+b4w;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id g16si406301ion.0.2021.06.17.02.30.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Jun 2021 02:30:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id t13so4459270pgu.11
        for <kasan-dev@googlegroups.com>; Thu, 17 Jun 2021 02:30:56 -0700 (PDT)
X-Received: by 2002:a63:db01:: with SMTP id e1mr4204540pgg.38.1623922255699;
        Thu, 17 Jun 2021 02:30:55 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id o14sm4847028pgk.82.2021.06.17.02.30.54
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 17 Jun 2021 02:30:55 -0700 (PDT)
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
Subject: [PATCH v15 4/4] kasan: use MAX_PTRS_PER_* for early shadow tables
Date: Thu, 17 Jun 2021 19:30:32 +1000
Message-Id: <20210617093032.103097-5-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210617093032.103097-1-dja@axtens.net>
References: <20210617093032.103097-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=ApqW+b4w;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as
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
Reviewed-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210617093032.103097-5-dja%40axtens.net.
