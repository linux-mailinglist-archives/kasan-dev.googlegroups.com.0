Return-Path: <kasan-dev+bncBDQ27FVWWUFRBR5A5KAAMGQEAFOUBVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id B69E030D95D
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Feb 2021 13:00:08 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id l3sf17609445qvz.12
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Feb 2021 04:00:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612353608; cv=pass;
        d=google.com; s=arc-20160816;
        b=f4PBTm+P8zYe5/6jy8Hnr7TQXnryisMcxMEyDSTL+W4nvv1snnOzcheu/uklgDg1CG
         fHWLyty7FAg2on7n/d5UnsY8C8wSNyJ6d6K7YDd4UgZaBvx0NUkOvppC8PG8Sug+Rc2M
         iDyaiksWxba0l11K+dserOan3Y7dkfx3zSPnb48dpierXSw89GhKbfnngZmkea8ZG5l2
         ETL9qDAh1dCecVZok5X1HMp0i5aVmuJt3UiTDeoF2aizzgdny0aFqwKTnjwfQB9rN2l7
         UJ6hGObXLEeNz5zn4mximfz5UGLextm9vxIbDnneGLx2bfFdgmttQ5r6v6PY2+xMp4S3
         zN9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=rz7vapNnDv3bI2odqVay6bFu2e5rfTw/qGIoMxwvmS4=;
        b=vzVSRA+k0sExi0gcfIJCYbXkHgIK6lY+3vacXnHdDf4vP1nDzNyJpkTwyOZbldINcf
         vnS25DZ2jA3KydaR0Z+qmLZ+dvwlGjeg4aeqtvSil603km+ZaPVVZTetfUCkSqKHyLIi
         60KiOgMQ8C+TcXAWH6GFY0PKX89gEdL6ZNp1iIi72VLk4QH0cDou+vr5FieHLilGX0pL
         05xeLBi8HSE/GgBQ5WaY8Da3j1WP5hmqhA/ecO+FonAu3TXcOkOQbIELoP1XHM8TU0TO
         E0CdVR7gMqPRelDq0pWKLIg/Gv8ybiVr9XTjAda9aPtA9V1gvPWDbp3BgG3Vjy/DOEo5
         O43g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=NU7X5sik;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rz7vapNnDv3bI2odqVay6bFu2e5rfTw/qGIoMxwvmS4=;
        b=straGG+ySiRsmSXu3IedEYf/jtnVnOpb02en+MA5StLWb3YY0FpV/VbSg29haPBS6W
         yJTTQ6pLSZFEXWlVMo8ZCIqP/ABKIIVJOpqDCh79IzWZF8qWkgbXC9HZDVcEqJacKTHE
         n9/2bwhfYv1H3pF3CxmmhS1PCOR3b2jueWKqy3NlGimZsYNTXgERV6r8G7Ni6XFAFlGP
         9SPJMOxS7czIIO288unBcpshw6rKEqWjsA180lBIEGO7EYUWjYqXQ1NOabPamoQfhmeA
         cZepieP6CJHln3Pwn2h8IXBK1ymebhnEUC42sqa+GQGQcSm59wjWFbX3E8azR7053YjH
         TAuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rz7vapNnDv3bI2odqVay6bFu2e5rfTw/qGIoMxwvmS4=;
        b=Mqr4KBwOTMXqAJ15tYdlw0VAW+vVXx1TwqRsQnb6MXZO4SJVNuKd9w2Oul9xRQHkCR
         hgv5k62RRjUlIqFBozzeDAtIFO+PEXh/q7sm/ujrSSdxpBk943VpgRWTRRFOsikPl2Ad
         binQIgKKttrmNAUWxA6ux/9gr6e4gDlaYTnxeKA40lAPAXGw6lvZ+JaVz6nwKySNnEbt
         S3403CrR01t8BrZ1MSbEV1kl9YnxqAAiOP1Z5bAPJSsfgWJ4J21BW2DvWg5equiIjoq+
         8L5QdGJk3xaj2M0JZdPdGpxZbUkRaYqYFPbPtT+vzkNA5uoyZue2neVJFIxwRBjMjYBI
         sNkw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ykQusm+Y7+Dqf4FvV90MVs/I0P3XolRiuVEAMZB50Lm2x9CqU
	Aj37aOl5IucDxzkcdVy2Fog=
X-Google-Smtp-Source: ABdhPJxBeqYf6z0kOV2j3tiRZa4MKnn7frZgcoa1diiJWEXkc3idYQMHrYZ8fSoeqK/vmckT4Z/K5Q==
X-Received: by 2002:a05:620a:406:: with SMTP id 6mr2184013qkp.318.1612353607875;
        Wed, 03 Feb 2021 04:00:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4b0c:: with SMTP id r12ls392118qvw.8.gmail; Wed, 03 Feb
 2021 04:00:07 -0800 (PST)
X-Received: by 2002:a0c:c78c:: with SMTP id k12mr2151225qvj.47.1612353607539;
        Wed, 03 Feb 2021 04:00:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612353607; cv=none;
        d=google.com; s=arc-20160816;
        b=YxTAyYGCFpREeuW5MdOHWP7JzTcH6+1Y3XCfIcJLll1N1nAhscmdae7K9byX0h5O5i
         iXBnuBaJMqhETfNRoSB9maD86Gg58F9ZdhPGdoc8S7A1hNfE8K3fFK1NdXBXOaUNXSu1
         Mo3+2IJMVzFgmeo+zTA2ID3T2gEmnhZ+drd70UH0wnAEiH6D7qD/e9NWVS88WZakZ2jz
         tXnb3UCOlXO3bF+Exf39EBhyEp6g4Ofwcc2U/GpebKqVOusoeNZ6e/0ooJBILIBXQVQ0
         PwVvfDobY/WIjfV4/XshKM1U9jVnfcEqQRMPZmEwh2uh9tvalvC1DL4LBzv3fC91DIOr
         iWYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4yeRRS+YoQcAmvPlaj8okeosVtMgEWoUxf3CV/ngv8E=;
        b=r8Y/MrIZnlMDf3P8JtaUMVsGwk1n/JisfnlzkgfQ3Ar3KjUv/4mQmf66G/VQuBLZXl
         r/iWVCwVHQuekjtdrRot83zy5RsZss/fBq0uksqO74g+7Q0xs5cn4tnsJzczW7t2cldM
         f7qjlphI3K9IPSY/5QegsvCV70bocQ1komubbzbB1TPVvMfUWd7EQQI066DlmO99qx0G
         4CWyBP75/T1ae9VpYiONMYGFnNnC2xXY+GMvbyWRVO9MXhvzzY9/vkE8kHu3GwU92i3J
         WS/8B+lSfsMkezwWn/FkhWjs4451flKyssucany9F8UY8KSd4M2uXO/DjdWgPLufABNY
         rw6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=NU7X5sik;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id f10si75455qko.5.2021.02.03.04.00.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Feb 2021 04:00:07 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id j2so15561590pgl.0
        for <kasan-dev@googlegroups.com>; Wed, 03 Feb 2021 04:00:07 -0800 (PST)
X-Received: by 2002:a65:648c:: with SMTP id e12mr3246745pgv.123.1612353606752;
        Wed, 03 Feb 2021 04:00:06 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-1c59-4eca-f876-fd51.static.ipv6.internode.on.net. [2001:44b8:1113:6700:1c59:4eca:f876:fd51])
        by smtp.gmail.com with ESMTPSA id 32sm2747368pgq.80.2021.02.03.04.00.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Feb 2021 04:00:06 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v10 3/6] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Wed,  3 Feb 2021 22:59:43 +1100
Message-Id: <20210203115946.663273-4-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210203115946.663273-1-dja@axtens.net>
References: <20210203115946.663273-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=NU7X5sik;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52c as
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

Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Suggested-by: Balbir Singh <bsingharora@gmail.com>
Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Reviewed-by: Balbir Singh <bsingharora@gmail.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h | 18 +++++++++++++++---
 mm/kasan/init.c       |  6 +++---
 2 files changed, 18 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d314c0fa5804..84bea59d01b3 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -43,10 +43,22 @@ static inline bool kasan_arch_is_ready(void)	{ return true; }
 #define PTE_HWTABLE_PTRS 0
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
-extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE + PTE_HWTABLE_PTRS];
-extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
-extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
+extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE + PTE_HWTABLE_PTRS];
+extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
+extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 
 int kasan_populate_early_shadow(const void *shadow_start,
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index c4605ac9837b..b4d822dff1fb 100644
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
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210203115946.663273-4-dja%40axtens.net.
