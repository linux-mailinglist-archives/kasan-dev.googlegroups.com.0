Return-Path: <kasan-dev+bncBDQ27FVWWUFRB45TZHXQKGQE6R2M3JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F6D111D0B7
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 16:17:09 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id i8sf1805051ioi.0
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 07:17:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576163828; cv=pass;
        d=google.com; s=arc-20160816;
        b=AskLzwFrDzVQeZBCuyD8M/mNuiCkc8e2daia9K9zL7zg4usgw2mrbD8yOzh3ztf9Bt
         JoD+IawtUm20BnM5VLJxOUM0v5kcOpTGPDICtqp/JOnYpMTYX8nJqeKUHpePcGXvy3UH
         7115h4HtCJZVi43Ug/3uD2+MI5Al2qcs/ZrRj+YDlrwBk8Ds3RuyIQTmuK2zYWQHHs2/
         XTsrNh7NiclSJPYcGDGDC93qvtGEtEqQJPztdlpt0UuuhrDBLvdnxT19QG3xzIVAvcYA
         kLvo/WhxpxQP0RoVp0NTT3Bb1oNbBvIHI+30ehgr0fJ4QsJYeplQn+SkIYxNdyJjXLLX
         GIbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=FOy+shyKUQsVFquSbyWzyffd7Jq5GV7J82tqsDuixY0=;
        b=wpJqMPooZs6gIV3PIHqBSPvgBpp9OAOx05D6vRRbj8uGNNz4TPFojUVi1PvKDqkzo/
         B6f1do8R3wuoWpAszQnNGV7129CPCipk8mcqcwBjU+elNDonOWe/Iw9Wx8pSz8jdIbhD
         c/wzQKaZZe5BLZ2t6Nc+gR7szRHurSANbpgOaRvqrxVQgC0j6aSweOCRlFUksAsZ7UG8
         q7ED8MXnVyTB8llbgwltdcS3AYIKrDxtV8y0IVMsSftXQv89jx9aSPfQkC+FMZcCDwta
         Wxxe7/argVZcHuJE1CfqI4iolHF3PTT9sB+sua2H1DdtpHxg0hFq0gaJSOzHcrf4L1nI
         rQbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=S2vM1eFB;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FOy+shyKUQsVFquSbyWzyffd7Jq5GV7J82tqsDuixY0=;
        b=blDTBm7a51t4nqK3qWdWDsnp2hQ+xY0t4HAnBxNrmbfRMhSDbXKvGeh2rdiktU1sdO
         7pRQaN+hkTqosOCOzM5+fgCnj8RvaxtAadMDpkgi6Dd2rwdJQcDHokrP5ZUGHRMuRMfD
         XIxeXSW+jyvo42vDD27akZazvNNRjYC+kX7ZACOm6UD8qGywlV3PvZY60X4BvcYRVi0G
         kjztgNQO0ttVvXLJlYmF/4DcMTSGQZbZyTc16Gz7dO1sJr59n/eKGhXqqKPHiSaSBLFu
         xOC/GA3xIedrGN3Hp2HghoKLmll9pbgaY6j5AcDXbvKQq5Mxw4Yk4clzLA9QtrrYDbVC
         gWcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FOy+shyKUQsVFquSbyWzyffd7Jq5GV7J82tqsDuixY0=;
        b=hIKYKo1J9PQat+jCdAQduAiFmNGAWlOBiq/pjZrcDTbb7e/nHwsYA83hG441RpgjMV
         iU6Vks3IF7rHvqVQ8/dbSs+p1KirjgZS0rNhpYKiBRFYq13v2a5GBJTtYOxF4TxjM4ul
         cXltmca0BtgoDW+ptIQmsdLykQRzJzXuNzEVV3lbfRXYBSogMQzrx7Ym200Gr/bUlIxF
         1dymSBz9gOcOJQG/yoJk9SH6G+Ra6Bp5nTrhVZDMf+A+5gCbK5qQDWBPdZZCBf1ZTPaR
         xhcLRMzZ0kasUx4YB7gnA4aI/mQanFzStUkZqCg17iZtituVZZww1YTLb+NjGzFk0q0T
         hmIQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXKvtzbzwM/aAD4XwlIOwHX5D5xMS/6VdU7A1+isC8AptJQbTUU
	112jBVMbRy8aGdT0oQW9jZE=
X-Google-Smtp-Source: APXvYqzKPbMgCOQaYV3ta/k28yr/Ty96U7j3UGa5QrdOZ4KPwIWzL9JJwwgKV/vF50sFdxfKE3yU8w==
X-Received: by 2002:a5e:941a:: with SMTP id q26mr3231086ioj.135.1576163827659;
        Thu, 12 Dec 2019 07:17:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8789:: with SMTP id f9ls772919ion.9.gmail; Thu, 12 Dec
 2019 07:17:07 -0800 (PST)
X-Received: by 2002:a5e:8505:: with SMTP id i5mr3293208ioj.158.1576163827228;
        Thu, 12 Dec 2019 07:17:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576163827; cv=none;
        d=google.com; s=arc-20160816;
        b=RPUXF++VEJwY/UdasgoPf4MHRbE/1voGQw4YMmUbuVbHoePfzKCGUsThMC62EyNCnH
         kXKjX+MuaaoaEaynJj+X4GZJCUYFIqATkL5nlToaXTxZuuSyFhhk0Mn4LBoVA9xCcwUp
         dbixxUx3yl4t+lFgQoZqDu4C1jry71UWEJQW4qg8SOPJA+rp0x/ojWsd3GKoirKT9h+8
         65Lkxg+kFxj/qZAugkY6JFXYF1xsw0O/D8szlpjKVZE0xqFqXh8k1GviWQpzaRb8Jxs1
         freyw04jIoHj5aSRbZDgZCEcjlFGJAjCdXckTcLHA4q3re4n+3CUhr/AtK1EpqzMo1xI
         /pOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=hw7pbm5ZSn/YgWBhazKTeiCLvFMpKrZ3mbIvcxopwH8=;
        b=eqM3Z9K51tyI3tl5oLtx0pkwi1f1Nua8XmNYTaKExE/Yt3Y5Z1NgKJ0oOkky4X/flK
         UTT4Rp+lexf7Dx2sAhaDCxad9rItt0r1Qctm6eWiFUOKda2enz02XndF6QsKCRCKBv2L
         R+pjoHvHW0pLY9JFC/ARAxNtmkgoMmChC51O8JlLttJtUBpHScHjrpPtr+i2uTu0pu/S
         I1KeLsKWNMM56ws9JNOR2bdzRKLEDTgc4zZlodwxhGz/O7hGjhL96EOk3Ny02aAXaEFY
         iprbLiREZiugh4jrPYKSdXu45FaAGb4Pqk5mBYpjWTs6FDF0vGz94Z2BycNFAZV55UIT
         PbNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=S2vM1eFB;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id g12si188816iok.4.2019.12.12.07.17.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 12 Dec 2019 07:17:07 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id l127so924232pfl.1
        for <kasan-dev@googlegroups.com>; Thu, 12 Dec 2019 07:17:07 -0800 (PST)
X-Received: by 2002:a63:1106:: with SMTP id g6mr10842363pgl.13.1576163826623;
        Thu, 12 Dec 2019 07:17:06 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-b116-2689-a4a9-76f8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:b116:2689:a4a9:76f8])
        by smtp.gmail.com with ESMTPSA id d24sm7941034pfq.75.2019.12.12.07.17.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 12 Dec 2019 07:17:05 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v3 1/3] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Fri, 13 Dec 2019 02:16:54 +1100
Message-Id: <20191212151656.26151-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20191212151656.26151-1-dja@axtens.net>
References: <20191212151656.26151-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=S2vM1eFB;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191212151656.26151-2-dja%40axtens.net.
