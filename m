Return-Path: <kasan-dev+bncBDQ27FVWWUFRBZVC3PYAKGQECPKAHVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73d.google.com (mail-qk1-x73d.google.com [IPv6:2607:f8b0:4864:20::73d])
	by mail.lfdr.de (Postfix) with ESMTPS id ECF0713537F
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 08:08:23 +0100 (CET)
Received: by mail-qk1-x73d.google.com with SMTP id 12sf3550397qkf.20
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Jan 2020 23:08:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578553703; cv=pass;
        d=google.com; s=arc-20160816;
        b=MDULjnmLah68OoIyfytEkA2wlcVKcAdVYOznMyjhUp/+YU8fGDNAQzPb8K0hVWhjke
         WJtEIWbfsa6DDLXBqrbUzOxOjsQPBftCTyPAYE89d3LIMZp0PX6Uc9vIQA8q0b811qBI
         RQWBwaBtItznCBJew542ucCYgVtXxDDOmuzbifPXtoZWzQCbxwcrtsOIYUB1W91QrfWa
         oDg8oHoX1MHa4rfi65JW3xsjxKC5Wjt7PXnGOx1y20B5CRn70BW4wRawp5ERtLwSIgvx
         +nVRI9VOZdCs9e68/tEX/RjAlT3wsEtB+LDBCrAnpp4L7rSqJIDypu4XLYaUH0Hsn03z
         quaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6cchPZ9P+wLMCvqBzlout7NFdcQH2o0jwPyk+CFmwyY=;
        b=0ZooqTrnDotasklpP06+lGlZ8nTJx8cbafkyk+isvrUg8/lUNvE8G0umoYuLoTSCft
         ZwR0KlOU9IbBZrTnQpvWppFQws2pX9u4lHriAuNihRZ0STDKNrkjrxdqWyfo4Kv/ikYt
         mQoYmo8elKTDRBSnxk31KTdvIiJsBDWi8bKkVf2dob7lBBmbpnIyhNganiGSYLweDwCi
         F/XZhh4Ygi1dYa8cXA1sQF3eNMjp/AdGQV2fImWEKfCJxJFhxg7gE0+FKvjnIHpDD6kv
         YpOAFzDrkvCPwRla5oMwVDbVRhsSjYV9qKzWtWiDl60+YkeusBt4oQimO7e1KnghgEp9
         h9Ug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jjaxrqgt;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6cchPZ9P+wLMCvqBzlout7NFdcQH2o0jwPyk+CFmwyY=;
        b=aKOSfuDKe7qDkCI53UdbyGEJDlTophT85grBRtWkGRPj5Px33YagL/uVnUR02wYxwo
         NZ2Hj+HpBYEt8Ff5QuyHOS/66iQeDuxHzbLRu2JNIqEjKtUTTzXEtAAwE2uCEvSe8IxF
         vzk6HCZQk9oM3jrMth1DrJNIXmgk6mul4FljJNJM158XoGpkHP9cjJGMJ9MPv9VcwUP5
         F+LpzUMDWL31M86pWbHZvgIlP8Q693PVSs48oMjAel5vPE54bAIE532Cgfdlw67K7UAN
         TTCgvmx3kUS+hunQxmQSUhHbcy8O2peGb1j9AxDvYxYjcAJa7B8MUuX1gvtSUA6DKNek
         A+rg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6cchPZ9P+wLMCvqBzlout7NFdcQH2o0jwPyk+CFmwyY=;
        b=D5eOA78gHhcGJ1oqDkrT8OGLhYMT6dl6SqFL1DgR0vtpAOPHMWfiS4krhZsta8QJWz
         FvVcJnkNQ7pM1FbkRYtwlUAAjibtWXOgarmJLYiDqp3J9GsHNLfcdkaRyTETGRNlF0AT
         Ught0meW+9AjYMbRcEzfGe3/b5jA1W6BGJHyPP+Ys3ZApISTMTKYFtDef+PpiQRpVg8Y
         zL8sSn5n4Zv+zKPZEsVoSSDCK7XjAza0C+ONmDt1wA7ItTxucTX6KU7ZARvk2tg4e5B0
         UXe4H2KqHbxjhp687UMFrARhZxptCgp6M03bJUN4jCR4bbrQ7xVfhp82kSfMehn0MvjD
         /RgA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX8/nHtWhY8ncMoOW5mbK5lpamumYnQKlLaALCvn5xBJMDJo6aK
	7tdyxim8JlZCxexxysESZuQ=
X-Google-Smtp-Source: APXvYqxHJnoAPtHrBjwHBlB9RRaN55Y7Y55K/6yM200WuqcnLpAhmVhchSXPwFKNJdamvIEv/P/0cQ==
X-Received: by 2002:ae9:c316:: with SMTP id n22mr7929510qkg.72.1578553702994;
        Wed, 08 Jan 2020 23:08:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7b94:: with SMTP id p20ls336634qtu.13.gmail; Wed, 08 Jan
 2020 23:08:22 -0800 (PST)
X-Received: by 2002:ac8:7699:: with SMTP id g25mr6658562qtr.75.1578553702733;
        Wed, 08 Jan 2020 23:08:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578553702; cv=none;
        d=google.com; s=arc-20160816;
        b=YKBYOF6zobRxMvn4hlq3tr7Q44z/VGy4Xv4TOYxTt2SvpvluMJD8NqbAvIotWNQIvp
         0ccV0Ncfn+GzV6rBHSYLA6gkT5Qo4feXjn+QhHdmSfmL0lPDdnTscmYuCRcclknRZXMX
         V6MBhggpTrZcswnZHt9S2rECxGRJNsMvuc89gMd4hKISiYgZkq66YXWG4J+vxS2I3Wvt
         CluTBemOND/DvpFyy6f8h2DJsUVTW66jrFofrUnBYUmWweNc49vDIfSl0yyZP5ZlKz4Y
         wai0CiCmCQMAcQoT5Preh/a+PyC8yssjC1ZRSjhOKXJiX6AtebsLp3Xo9i+EV6GhKeyj
         XMbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=+Qbs6Z3rqfBFwWIlrYI64jfvYzlaBBfAFpq17iRyZdo=;
        b=tra8tK0fmxEAqaBlo5MNtnu0fQWTuEkcc4IWN7wyb2MnnXhh0QBCmRNDpGsdH+rYRc
         d4Kx0vx2M/4jJTesFKo6XclcC7aBD2RihusfX0ugnaquNKPdBVLH8btSnf0L6iG4OGpQ
         7OxomKJuu6Dz9FbRaVCxtZIGhAaX9kR8mZzmI5xYZppRvUzpIhjboPDMlVrr5Ko4OM8l
         P+4Ir0mh+sgGDK612W8F/okB+9C1mlzCXRjRRbcraOlbZq/Qc8yIr4vRODXmm8d+k8ac
         DzFNMIzPP6d1TkJMq81xyjuAYVzK+EMd28YXJlze3amNfs9HRdsxez+rGtVjl/jgHJXi
         xciA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=jjaxrqgt;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id h17si205859qtm.0.2020.01.08.23.08.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Jan 2020 23:08:22 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id a6so2186104plm.3
        for <kasan-dev@googlegroups.com>; Wed, 08 Jan 2020 23:08:22 -0800 (PST)
X-Received: by 2002:a17:90a:6587:: with SMTP id k7mr3432299pjj.40.1578553701900;
        Wed, 08 Jan 2020 23:08:21 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-5cb3-ebc3-7dc6-a17b.static.ipv6.internode.on.net. [2001:44b8:1113:6700:5cb3:ebc3:7dc6:a17b])
        by smtp.gmail.com with ESMTPSA id 199sm6721622pfv.81.2020.01.08.23.08.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 08 Jan 2020 23:08:20 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v5 1/4] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Thu,  9 Jan 2020 18:08:08 +1100
Message-Id: <20200109070811.31169-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200109070811.31169-1-dja@axtens.net>
References: <20200109070811.31169-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=jjaxrqgt;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
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
index e18fe54969e9..70865810d0e7 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -14,10 +14,22 @@ struct task_struct;
 #include <asm/kasan.h>
 #include <asm/pgtable.h>
 
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
index ce45c491ebcd..8b54a96d3b3e 100644
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
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200109070811.31169-2-dja%40axtens.net.
