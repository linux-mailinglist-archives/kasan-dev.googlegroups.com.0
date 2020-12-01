Return-Path: <kasan-dev+bncBDQ27FVWWUFRB4WYTH7AKGQEHIHO6NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 05D242CA7EF
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Dec 2020 17:16:52 +0100 (CET)
Received: by mail-pj1-x103a.google.com with SMTP id cm17sf1385611pjb.2
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Dec 2020 08:16:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606839410; cv=pass;
        d=google.com; s=arc-20160816;
        b=qDchLwAC/13qMdKlVNTySEoz20qUvaZd5F9jsvwq2OHp6WJ37rBr0pzuzkRaPEozw2
         N6+xECJEnBw+d2YCeOWM2IqHR2qY/Q4SKlheeCJJl/GUygL14TSmVJQxm+tR2uVGxlW2
         iZGbaqhcnjAZoSz9m7Fodnx9oOa7NlCV8Zbd/LaXhDLIg5WizN7tsIxEqPazOrSViVYn
         9/f4cUjkSx1+ZfC/A+2n/WqiDSvA0yU1IT4AnocqSV7X9viDn6WkKk7VvjzwTRIYLNAt
         ihwb9t12ujaLprPOw3Rvnl4I6YjWL1xcmJLy4XbeqOiU1XfWajUjQdy0e4Tw8ra6IuFB
         HYOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=W132VYwls0zYPGirakZ/eU0zUVSTkuLUp4gV4+815ok=;
        b=OuxTZ2kVVP8V4kR8cYbjojq1hFa61rAwOBn6fgkK6Kp5ggYOWDCnPm/Ogy66gz2GKW
         Xudl3WIdcVFk/mgv2OjF98M2TUfusSScyztfhrY2SVMYjjDrP+LtcYISJO5oPHy+cDwo
         K87otgo3huOX1+JW5lA7FIw9/NypDnBWz/KM6dqr/LLmf6RLEEY2Wdp2aaxOA46myoRX
         2PMNKkO/rQTLuZEeGVUoUgEbNjn1xyhR93/6QsibGFqxFywQmuQqL3ZHP0y6I9h1Xd+B
         JHQVaEroLoU7uEenaJzM44I18i/jGz1KHeHjS9mjqkdipqT5KD8s2BS+pQZSXmRno8R2
         RPrA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=o7pY89Eh;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W132VYwls0zYPGirakZ/eU0zUVSTkuLUp4gV4+815ok=;
        b=bl/rJiwsanUNOdITVLouhHffbeSLi7HRkwhbi+3mpzHgS2ng40nGqPCAYseE4/6LwU
         8SSt8iYA/4zOOqCVMN8kxq/WnjK1jzaAsqfU+qqPN2HbrUizDfgkzvAQnJdOIN3u8RyK
         6ghgn34NMv0/oJXGhxSddURtzsmdoAxUp0H28OHgoB5dxEG7VJfbVoy77pfxvKDKhTEt
         mZFRJejv8ox8d3aycqRYSr4Bs4ejgD3g6DQY7TmVZ11+n1FumXKT2VSfCES9niy+stvH
         2g78H6W9GyeXO7ariK5DKZu5xXJuwe69kEE1wxnS/7BSAUTP4W1AlhDVligyh2wN8bmX
         utoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W132VYwls0zYPGirakZ/eU0zUVSTkuLUp4gV4+815ok=;
        b=HaGB54s9ZLwRTz2yNj84bLINldDXw+jD0TqxraT6GcdLxWbZWuz1mkxRDt9//7e3Ay
         /v2hoNgCLvHfLpOnKWb5oPdtTBhVlMhvFQ+QH0JDN0s5NIY7vloM85/+Y4V4J01brhME
         K7MnZQZO9SbT2Wkk7XZM5D5k7Rcf4aOlPL/igZG1qOlmjtiUcLKk76lJS6KTIQpeH/2c
         m8Xt9t2K5qdvfHu4efbAkXMC3oyfHUUti9okt1IXijX3xQ74kTLg3nsCHEPDtjDuitQR
         1XX5gY0yfDBF/uTZMih1SNvsgSIW5d+Xi5PUuA+NizXHu+CsPSAERAGpsDHJWjzHgfPR
         oN2w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533hPY6AA6iSP1dlEL/EA0ilHOa3C0vpGF8sqjadAk+RyB1GAEqj
	tWCkKybyb5BagN8AQ64+d1M=
X-Google-Smtp-Source: ABdhPJygEGbxLT0KYjXDW2sFHMKtOg/IFk0a0xXxylTYg1N3Q1BcvpmZADaWj2z5ztLJWRSy+rYxBQ==
X-Received: by 2002:a63:124a:: with SMTP id 10mr2891595pgs.180.1606839410753;
        Tue, 01 Dec 2020 08:16:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d04c:: with SMTP id s12ls916644pgi.2.gmail; Tue, 01 Dec
 2020 08:16:50 -0800 (PST)
X-Received: by 2002:a65:67d0:: with SMTP id b16mr2096063pgs.397.1606839410204;
        Tue, 01 Dec 2020 08:16:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606839410; cv=none;
        d=google.com; s=arc-20160816;
        b=IIsnjPLzpYIdijt5iS5tQ09I54UY+I7CHcs6mJHmpTlCRzLqv4gmp8dvsiXB4U2SS0
         0hXXJO/R4O1aKOAUfCz8lmeUYhD3c3ooyZLfMonL72m64QMUWWulHS42uLdqDiNB/Yh6
         h4CgTrYU5RwXRPB8IEYuZ57KBmto+Iru6xtnq3Li4t1V29jJrhUMnLhw9EuwiDEo06TY
         R+lVDw8SU0fWb71B2eBX5fvAJFxsDy+2bZzDA5HqTqxdcGJYZrMtfbYyulnG7MaoDE92
         rgSOpNapRhKk/Qh7JdWj5k4tTO+7JpR9CyoZiOoi4guxXrQvdiWgQcnAq3OYXxeDuK/u
         DYHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TxkOT8OtKTLEt+0Y1UXvfZzv0Ces9ugsvAtyOyjKCDs=;
        b=qGsTzjzDKHa0wExMEzm7r9JbmN70I6NLQ0dZsvVfi3z4ZzXnpxijVhDCF9/9P+RTdY
         1SXNTwjq3rG6oRuxFl8oqaWNTHEDvivSKunHHtxM5bcYhKwmA6JfyJdIM4XgmZgfGpbv
         Pbr7oeq9V1YW9RwA1C47TVJVd47EbSt3N41sRzXKipqL+drbniTXsTslwZI6cCGb4aDw
         4crGVtclJNlzJKD98Bfe+2sp4MkVcnkY8PALdzVLT1DhfPivZvjMOM3/Z+uPRyyY4udl
         Quefg20IVV34T5vC4pj+5eRRvMR8qA405ExRoVq2lEbN92RDlIyEX/sleZmHB6h7u0Q8
         UahQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=o7pY89Eh;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1044.google.com (mail-pj1-x1044.google.com. [2607:f8b0:4864:20::1044])
        by gmr-mx.google.com with ESMTPS id mt17si158573pjb.0.2020.12.01.08.16.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Dec 2020 08:16:50 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as permitted sender) client-ip=2607:f8b0:4864:20::1044;
Received: by mail-pj1-x1044.google.com with SMTP id o7so390610pjj.2
        for <kasan-dev@googlegroups.com>; Tue, 01 Dec 2020 08:16:50 -0800 (PST)
X-Received: by 2002:a17:90a:d3cf:: with SMTP id d15mr3291039pjw.132.1606839409910;
        Tue, 01 Dec 2020 08:16:49 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-f932-2db6-916f-25e2.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:f932:2db6:916f:25e2])
        by smtp.gmail.com with ESMTPSA id s5sm194359pfh.164.2020.12.01.08.16.48
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 01 Dec 2020 08:16:49 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v9 3/6] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Wed,  2 Dec 2020 03:16:29 +1100
Message-Id: <20201201161632.1234753-4-dja@axtens.net>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20201201161632.1234753-1-dja@axtens.net>
References: <20201201161632.1234753-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=o7pY89Eh;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1044 as
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
breaks the build.

Define default MAX_PTRS_PER_*s in the same style as MAX_PTRS_PER_P4D.
As KASAN is the only user at the moment, just define them in the kasan
header, and have them default to PTRS_PER_* unless overridden in arch
code.

Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
Suggested-by: Balbir Singh <bsingharora@gmail.com>
Reviewed-by: Christophe Leroy <christophe.leroy@c-s.fr>
Reviewed-by: Balbir Singh <bsingharora@gmail.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h | 18 +++++++++++++++---
 mm/kasan/init.c       |  6 +++---
 2 files changed, 18 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 3df66fdf6662..893d054aad6f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -24,10 +24,22 @@ struct kunit_kasan_expectation {
 static inline bool kasan_arch_is_ready(void)	{ return true; }
 #endif
 
+#ifndef MAX_PTRS_PER_PTE
+#define MAX_PTRS_PER_PTE PTRS_PER_PTE
+#endif
+
+#ifndef MAX_PTRS_PER_PMD
+#define MAX_PTRS_PER_PMD PTRS_PER_PMD
+#endif
+
+#ifndef MAX_PTRS_PER_PUD
+#define MAX_PTRS_PER_PUD PTRS_PER_PUD
+#endif
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
-extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
-extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
-extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
+extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE];
+extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
+extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 
 int kasan_populate_early_shadow(const void *shadow_start,
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index fe6be0be1f76..42bca3d27db8 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -46,7 +46,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 3
-pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
+pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
 static inline bool kasan_pud_table(p4d_t p4d)
 {
 	return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
@@ -58,7 +58,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 2
-pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
+pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
 static inline bool kasan_pmd_table(pud_t pud)
 {
 	return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
@@ -69,7 +69,7 @@ static inline bool kasan_pmd_table(pud_t pud)
 	return false;
 }
 #endif
-pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
+pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE] __page_aligned_bss;
 
 static inline bool kasan_pte_table(pmd_t pmd)
 {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201201161632.1234753-4-dja%40axtens.net.
