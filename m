Return-Path: <kasan-dev+bncBDQ27FVWWUFRBLENUCDAMGQEI2ZLDWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 91BB13A7374
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 03:47:25 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id x4-20020a5eda040000b02904a91aa10037sf24504851ioj.17
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Jun 2021 18:47:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623721644; cv=pass;
        d=google.com; s=arc-20160816;
        b=zIZalFDlWQYKpzvJb7NwNr27S1Ma4oeuSc99RYJy9Q+uZqDyY81HwjZU/L/B78dInM
         Y/SXp4ZkVyM5yqM5e1nG+OzD6Is+cnafzHKL15Xq+P6af6pHfX3JGRViXfMRKhQJb2DI
         Zr/UbE1m0lye4nGkAgqV/ZzpCnJrrIzS8HoRyEwnBHfYpgKZ+1h7LunsAOV3oZ4lzmAJ
         02zu8Vr47s4XcazGLOcfY37cSX6JSLo/NbZ9FKRp1EwnKEPcWsx3kFKG9zjKSFht5x6d
         Wh6xKQpGeWY1gC2oUy4hjl1SOEgoBXhJF55OamX2H2g7ZAhfcwkSOAMQ6qzVgR5DSgQG
         EPZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=UIIsXg/JqfUAaVuIWs9X4Mb6T405O8zMUHfdaYwGDdM=;
        b=HtfUEC/VlLNPne/AIPJLg+4qonNl/ajwRz8uDIFORHez74XjvVZpaLhMOfcovsXM/F
         abO4O7YWbDlIl5HNpmBRljOlbjGV6OTb2+nCkqYBJa8euuE1ohDO0LV/9A7vCbR0Cj54
         u/pYcBfX/HZPJLdRQ5DsDoHxeuFh/s1406Ks//oklYJqxdBshYIUlD6OwSS9jRZxftDw
         BTRecZ+EXxHNsk4Xl9dC8PQ/vfmb/GlFC/NBDuX14VGNMGPylVqbBThVuqrVtRbm4Mqe
         QLzzWa5EulOMMp2U0bu+r5K+sUjfEgdwZOVbpN/Z+lWyNMJi060loIw02PFjt2R8LVQk
         e61g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YYXooO3C;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UIIsXg/JqfUAaVuIWs9X4Mb6T405O8zMUHfdaYwGDdM=;
        b=PxXRKp6XK5imPemSVLaA5SrUVeqaOCsZr+jxxQeV3TRbbgody0Dw1f1BaN001a8H/z
         dfFrheLi0yo6e7mZrpu7iNzBogGAT7oTOasiGoWppKTzg+xL0uBR+sCqnMLGGb5dKLXv
         VNcr2slGPkOSUfXlJlBqgu1tfu6rX2bb5XBXPuszKa2WtWjf+WsTCLmEqyogao5FSIGj
         hAko6RxggLiWR5zz7fASfqmouB7jEEQrM4SyvhHQYeO+1W3C+8V1RCo3UBKcRPmX4cQI
         TI3VLma3GCMUhsb5i11K0DlrdG4oBujX4aTLTrgyG3cTcA2k5BnS4XX5k4GqO+8J/3sU
         Ehpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UIIsXg/JqfUAaVuIWs9X4Mb6T405O8zMUHfdaYwGDdM=;
        b=d5fKV8xkckJiqFrEy78Rq4WuRb1S8ISMQJLhtXp5VeVTlJqMlZiVNlQj4mfD0uindi
         14kYOneSZl7a5SvI0qTCuq3znoZzzMs/Wd9kRWYaT7sh6tEniJPAOT/DrGrzILHdpmw4
         uk8t7pI+1u+9n9ofLensfzdYFpNdxvqPZ+c8EFQXycmN7qs+nTJZoZ+o4/IkNGXxuGTK
         pBWKlQOh7A+kA4PHat3pC/oSfffxVkeazj/hz3aX19277kD2BumUvf+62oTMDY2SIEJi
         oYlju1wEurnGOzII1BF7DD6zhXXw8OZUjuz/j4NtSh9hOF8V712yhXt7HIhC+rcjI84r
         rTfQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5306v6D57k49FUQIC5/mDUDhc5VpWGosxjZUP1ABAoNQU1EKXc9V
	/OaSpb3CmGTpqMgBnVX0hJk=
X-Google-Smtp-Source: ABdhPJxNf36gvKvx76+68MwrvUi1j9lkG6M31Xw5prJXzWIPp14BN7alt4CW30kDR4igR8cyKllvqg==
X-Received: by 2002:a92:b111:: with SMTP id t17mr16171914ilh.208.1623721644508;
        Mon, 14 Jun 2021 18:47:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:16cc:: with SMTP id g12ls2762747jat.8.gmail; Mon,
 14 Jun 2021 18:47:24 -0700 (PDT)
X-Received: by 2002:a02:c76d:: with SMTP id k13mr19262760jao.82.1623721644087;
        Mon, 14 Jun 2021 18:47:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623721644; cv=none;
        d=google.com; s=arc-20160816;
        b=ZeXu1pOQOiwYVTAGzdbYqU/qkRWx18wi+tXP0ik6NmULiQL+2Ht8r09ciircNHo9W2
         bPjjIjKvx/nex4er9sZsAcusKSNhMIJKbZnOJt/kvxeqtLrZ3vfvE+x/JoArLLW8gyAp
         EKuBt3k2U7GudDdRLIkVpaekKoQgMLgtvGdlT6s3eSQMDjUMNT/iLjFZJTLwGffnuzXH
         PtJ7HabZMQYKkyJfewX7lb4G1t7HIYgRbR8vEDGHj3vq6nq3UuxiHIGjYUANRXqgoChi
         IRKRDwMjB+hXXkTKG7wQVhN1lFl6VRX+2YiuGxSBtksHo98hXT7O6guZEzYwa8NXMVMV
         p0/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=a1pNfOTnuu9q0yP3UcKWGmSF0bOy6BujGvnQzOBamsE=;
        b=doU51OORMX6RqQCboRi14IZhl+dbDjrc5k6OZ6qefcKJFOf+W0VBWKvxC1IBH0fbHW
         MNx+v3vwUCjVZu3YKc9s2OF4sMqlUhUqSYSKiGUZLed0TyprzfQFC1VRCCJJl1alo/G0
         kWbLcEXAySzYAwBG39F6sFyK59H3KrlQjWfiphCkoJfKRhyuT2x2lR/Ml+qDOO1SfE/I
         Qe+xQVOqfHppOX/XA3PC+P0F7RUISDy4vw45ioEvqjn+VO0KuUj3U36hMaoh0rDtPLEM
         c9XMhdciDW3X7qH9oPYtTBpa+6u/NyXjm+GBO1wTw4FOdnM08c2KEDncMpyCMG5QmBKe
         Sc2Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YYXooO3C;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x530.google.com (mail-pg1-x530.google.com. [2607:f8b0:4864:20::530])
        by gmr-mx.google.com with ESMTPS id h15si78535ili.5.2021.06.14.18.47.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Jun 2021 18:47:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::530 as permitted sender) client-ip=2607:f8b0:4864:20::530;
Received: by mail-pg1-x530.google.com with SMTP id v7so1396509pgl.2
        for <kasan-dev@googlegroups.com>; Mon, 14 Jun 2021 18:47:23 -0700 (PDT)
X-Received: by 2002:a05:6a00:82:b029:2e9:c6db:e16d with SMTP id c2-20020a056a000082b02902e9c6dbe16dmr1937093pfj.78.1623721643469;
        Mon, 14 Jun 2021 18:47:23 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id n6sm5768289pgt.7.2021.06.14.18.47.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Jun 2021 18:47:23 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@csgroup.eu,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: elver@google.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v12 3/6] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Tue, 15 Jun 2021 11:47:02 +1000
Message-Id: <20210615014705.2234866-4-dja@axtens.net>
X-Mailer: git-send-email 2.27.0
In-Reply-To: <20210615014705.2234866-1-dja@axtens.net>
References: <20210615014705.2234866-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=YYXooO3C;       spf=pass
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
index 768d7d342757..fd65f477ac92 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -40,10 +40,22 @@ struct kunit_kasan_expectation {
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
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210615014705.2234866-4-dja%40axtens.net.
