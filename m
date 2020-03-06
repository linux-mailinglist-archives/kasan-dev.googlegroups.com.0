Return-Path: <kasan-dev+bncBDQ27FVWWUFRBR5CRHZQKGQE46ZGRMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F77017BED8
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Mar 2020 14:34:01 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id m1sf1379518pll.23
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Mar 2020 05:34:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583501640; cv=pass;
        d=google.com; s=arc-20160816;
        b=BcEZ4tiWDIhZNmcZGIAGuKW1VuJknngS9z3pIRSn8zm1Q7zNyx+LAMVFZruL9WNLrK
         CBiIzdJOloj3TV/7gJky8fM7A+ynWEN5jJ2o3nlVLqdaHughENfHLATkbqIzbsNK1CAp
         6kJjx4hvZKrtbFZhVQ/zi1EPWW30CDuyEKw4p2QXblcXRUEBHpzpLjiQr4KQUeHWwxuf
         X30H+EhDf+DIAVkhaUPgvKG9qYX5PVIGT8d4nrwM0k0/Gys63HuJ/3kg8i2WBbSD5tQi
         0Z9y/dJB4KOlhe1eKmRVPiYAnY8JRuKblOs4GaaFnLNAWv2tnjrnLve4PsOlGegtT07O
         ovEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gBZwEKDDwzhxowRT7pf0U9Y68x4/kLjEy3ub00uwTc8=;
        b=e+y8he72aDl72EtQGIJRfmZeysuwuTdoBqo4BzBnIztPi19l5JwIkWw3E7pb4Y80J8
         zAkDYaUvFclg/grleZb1t5Sn/fDTzTEln+X42jrbnBWz7q/R01ObM5E95if5jFXkYYpG
         n9h6XS1tZ6FS2m7KhahogepjeZLxOD8L0uNsASbMz1h0E0ePSQUge1ol0PpBjAvmvMYE
         rMbx1I/OB3Bh2vogdFIlGC1/fQcqr6FN+8GxaIsE3MUBSLEH4Q5Rj+DrLLvKSmDevdlK
         PLZmslBDgOfljTbZ52WUmGFrWXHwG2WP4J3AUEqMWQ3Biwg7tezGdkMNLZjoQ596VO46
         CwHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=aYql5mJg;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gBZwEKDDwzhxowRT7pf0U9Y68x4/kLjEy3ub00uwTc8=;
        b=ZsNpBu1+KaYxyaWhQOwSuYe70K0lCxB86M8C4OLV+008EwD6g9fdzAxyILNcD2PM5u
         3yRivKAIIM9lGtkNMl2VNnaGdzAGyDX8wnHnN1GSuOh0jLJuEUUf3rbZnQiqc+ddzz65
         /h5Nlv8s/PeEDXLpjNbu5fRQTaLnR8gppOHag/chm8SCfPIl1o4ORyFx0GJEWLB19HNd
         unEIn/BSfmZg1Bw9l82CcJMhtzxAmL8wtef2fcQQOPftSLQ62cPyw+XOaG1p4IAXznzM
         UbRBk4CbMWByx1i4u2K5l4DQeXY9L/yPrDnQGdmZEzDfRTbFub/RcVZIlBAO18tLptOz
         I2fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gBZwEKDDwzhxowRT7pf0U9Y68x4/kLjEy3ub00uwTc8=;
        b=KiwtNFhQYaS3+HvV6TIvgPVjAmMIeRwMcehmagBzsKK9Xl89oCsJVHM9EUHLB/H55t
         8SWFXozEdOzkmkEMoIUS6BxHVJ8tDrYYG1rTvYWI/dmBf3JGZg4ws3n7oxc2OZbSkjZE
         Rj2eBmAhFTcaikdUxmQFyXwHStTu6Ghr3+w1KQF0xJDTD8q+6Sgrmmdyp3Z1GO2IVM4Q
         565EMrAr1Z/XQ2kVg+yOL5Ui/0DpwPnuShM3SiEDBOBALqt3QaGJXa4b3mwkUnNkRz9j
         Y3RlwZqqSnw6+VlRRxcNrQ3ifkDMjiYnt9w99hqV/zhU2IXS3RLeEsPKHQJMsjdry6EK
         eeRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0ouH8Un9xrOi+4Ynny7vk3TrkTA1tYILZRp2j0mtvhRaeup2m7
	3OChYSE4v+GQc5/WHSh0nKg=
X-Google-Smtp-Source: ADFU+vu/mW+LS7ANQYE9+Oa0Zh7eaT60DCLREGqhpq1senWRzW+p6jr3tkNRsXwVh/BieC+8B30WYA==
X-Received: by 2002:a65:5905:: with SMTP id f5mr3155103pgu.87.1583501639759;
        Fri, 06 Mar 2020 05:33:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1bd1:: with SMTP id b200ls829583pfb.9.gmail; Fri, 06 Mar
 2020 05:33:59 -0800 (PST)
X-Received: by 2002:aa7:86cd:: with SMTP id h13mr3752724pfo.252.1583501639303;
        Fri, 06 Mar 2020 05:33:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583501639; cv=none;
        d=google.com; s=arc-20160816;
        b=Jy0YqqGNTugiR7Fsoxg6vNEumuM9jsbmNp8pM8sUMo1v8QZcdId5BTVSwdfvUki72s
         uMtuQID/NMGjaKD6638UiQEH9q+dC8kj59MwXCf2GrVxB3mK6e+GUh/ZUwsNL6HiLxr3
         UrkpDnpoqW2e5Bx3tAMI4Ff39vqEkbUsER5CzwKdkj53otdXY8ZFlXTgRBHl4+hp1UuI
         UJmzxtKQIVyhrvmjmiT6ZvPh+wf5VJqGcQa0W6yVA45ww5csZ/wSTtmkzlAszbHbv3GP
         AzFu1VJ88N6PwF+EC+8JypUAoWrMTyTY0PFq2qW67r/H2b9lUiq9TncOR1OmZw5b2ceP
         pf1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0eDFn39gIg7xtZfHp4ELa6UyXk2yfoJL9wFZ1T547PE=;
        b=Ul+vVk7Gk2I2QjxfAT2mjmp4hKxZ89Te9pSGPQhJDk7fdQtikdLhcZA51XLLXyngzV
         REW/DzMd+rGrVVRMhHMIBh/B6U3QVVqb0M9T31IrokozTsXIi7npxnocrwqOBk6loYLD
         S1s9kIZsItUeDxw0/Hoiv4Xlb4RdKE/ruE2miJ9pxuCPY4WlR83ZOHvoJOmXw4KRKkob
         0WVzUGnfXNEammZ/G0gqkEQESxxSgYwmEms0Lb65tvrZ6ichH6fygnZx9vbEY0O/6r4h
         v3qcLUTZDE+8NnyZC7YThskpsdq9eAhAeFIcV9Hos/abIzrkw/7S1RrW5ysPTc5WfVFS
         cxuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=aYql5mJg;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x1043.google.com (mail-pj1-x1043.google.com. [2607:f8b0:4864:20::1043])
        by gmr-mx.google.com with ESMTPS id hg11si453950pjb.2.2020.03.06.05.33.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Mar 2020 05:33:59 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as permitted sender) client-ip=2607:f8b0:4864:20::1043;
Received: by mail-pj1-x1043.google.com with SMTP id o21so3498356pjs.0
        for <kasan-dev@googlegroups.com>; Fri, 06 Mar 2020 05:33:59 -0800 (PST)
X-Received: by 2002:a17:902:222:: with SMTP id 31mr3128704plc.108.1583501638997;
        Fri, 06 Mar 2020 05:33:58 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-b120-f113-a8cb-35fd.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:b120:f113:a8cb:35fd])
        by smtp.gmail.com with ESMTPSA id o71sm9880171pjo.35.2020.03.06.05.33.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Mar 2020 05:33:57 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v8 1/4] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Sat,  7 Mar 2020 00:33:37 +1100
Message-Id: <20200306133340.9181-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200306133340.9181-1-dja@axtens.net>
References: <20200306133340.9181-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=aYql5mJg;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::1043 as
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
index 5cde9e7c2664..b3a4500633f5 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200306133340.9181-2-dja%40axtens.net.
