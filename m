Return-Path: <kasan-dev+bncBDQ27FVWWUFRB3O3TDTQKGQE4AXTE4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 7369E2756A
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 07:21:50 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id j1sf3368987pff.1
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 22:21:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558588909; cv=pass;
        d=google.com; s=arc-20160816;
        b=F21c7ax952nprmO4eW2xVwImsTDWr4/DniLTspW6iwD7rM7rbUNUPEq/1B0M2fNQwz
         rlZvPKcFGgeow9hbGZJqYy9Ws80GgVZ0dumsNUhU4Lh6PDsp/bxSGNjKhAYKZ6kiJsIX
         HKw5oGoG+DN/huG4ZqR0wUHZINL1CLfW/d5lIRcOCnfdnhbWJ1IfMnmYzqET/ioOO4XM
         qi7xMGzNHUEssDVEVGq/dsUNUYAZYPQLjX9Ak1fwaLGoWkjJzPKWJcdX66MFPWhcP2CJ
         vTo4f2UrqQbIIZyD+hliGTrvpVrIKZiK5d4u2Kel9jP6PePuDNshW+IlQcCMNNiZFJ3+
         Ff9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=JEbZG/lDcTWxKKktEUp+ti+i//jiYekdlUVWZJXJr6Y=;
        b=kAEgR7jnKb/aISXkmzQHpPl7Avih30c8onn+yjCbVjc4lYz+BFRUJBc2HJvp2iNL/q
         5fQipQ13mGycF4a7SuxmmPZf1p1IbQUgz5RQ6SgB5MS8/pj40ScGC6YXfNHvEMXh6tNM
         lnR/kh+p+cir1tAcQ3AJly9FDsHJI/TyqMDXskcrAecoex6m3hq97NLQSkj5GVYFNfP4
         rCqezv6E8e9Nh5YbSZin3G1OTkLDF333lrrtplpSKAmbkMLEfHAq3KUwnZyef0JEBdCn
         yLLtrpR/lvxFyXWO+0/eFEiECpNWteK9+Dbv1pwrZkbC85lV1pOJDK7qiW3RL8Nhq95G
         lwfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=grfUhkoC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JEbZG/lDcTWxKKktEUp+ti+i//jiYekdlUVWZJXJr6Y=;
        b=gLvYM3MvwGr2isyaTIoT9uHeyiMq00lhRvPG7k0lYHkclW7c2tv9pOnTDFatbrqBmw
         ascs8+bnlhNu6z0mcXoubRdSU1pZxXg55OzK20dHxQZks6ZGRsPUnTTK5CG+XW0v2jGL
         6jtcQAaq4s6MMP1uArLohQ58GsSonYqZgouj+r0e50+m62hzXpstVIOhhHKFY4j2feDd
         Xt5z4f4rxM346/LuDuHRIxGmnNHI2yZXZpVmbsqO3fJ2W1rgmvzJcwEgdSzH0WlG2qEq
         0X9iDx7usmvscoNIMG+tCIh4yTZiKYVMt8p9c7RIjqDaJt/LtZocVd2gfudCfzAHX3Ql
         zlyw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=JEbZG/lDcTWxKKktEUp+ti+i//jiYekdlUVWZJXJr6Y=;
        b=MSh0djGfYaTOXegjGW+OVOU/HB5jP9oiDgJmDh/EjleHFRHc9K9oqWPnjGbO5Wb8zN
         gXGrI0Y7DP+IppNV8M5fh0H/EbGslbSk3SFIxNEattAnw0YU2derNeLXSYL7/T1iubvc
         OEtl66DZVu2GbV3896p3W5MEjdXisodcMw2nedzg+9BfnWgpJWstXll300SzZvcPMVcl
         CNQ44IDQTP/5Yk9GBhI1q+eQkVjN6AdjcmLzKaqOqbz7RTIejxtUZt8b2qI8WiI34KRx
         4N7NE7ridMvQ3aUq6x1FuncztGYEXTGgWTRx3oV3UrHFvGYiJ4TKdS/l/W+CeHW2VddT
         /sEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXupUDFSqeQ2tsVnYwTqYDdNx8hhoBNNVFxufmEx58R3mmcBeDe
	z0orv1rFKPGzYEjh3gJzSKU=
X-Google-Smtp-Source: APXvYqzOarEtbfRwWdaOphXjnyoS4hYLEomg89nfXXQslJQhrqFLlP7Vv1tVjMQgvLRuCJBdc3UITA==
X-Received: by 2002:aa7:881a:: with SMTP id c26mr94850098pfo.254.1558588909235;
        Wed, 22 May 2019 22:21:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5c4a:: with SMTP id v10ls1193405pgr.1.gmail; Wed, 22 May
 2019 22:21:49 -0700 (PDT)
X-Received: by 2002:a62:1d0d:: with SMTP id d13mr27376455pfd.200.1558588909028;
        Wed, 22 May 2019 22:21:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558588909; cv=none;
        d=google.com; s=arc-20160816;
        b=Gl9OJmaaVs0UyuWSVaIuDd2W+aLHdefJoTaLoEVa7vZYsMWdR8sP2Ppc+49ZH+YJLp
         3m2kWG8KtzAFbUocVmgPMcjrkFZWUtWDdtZN0qguiA/TGbFfct8Fa3qUpTSymeA2mWhc
         WisfvchO99XZ/7IycjWZVaUe3KekP/gL0U3CaeiztVekuLHbUiyKZQKDxUHhndeZZODg
         Cy+ddgeZukNkvLsFqW1CuXwF0ekXFQDAdtO1Yu7p13Sh2DoHq+2+GmbU2ljhxgOECNzL
         gxo6psVfrE6EvGfQmpkWxcciz4b3lgOvyciv0Srdd67eaHRBqJJKqjl3ALoT1BS01u1d
         G7pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=HfBrEV1CyylZ9vuMNT9zujYn+Hw36buoRy8FUC7k2rk=;
        b=J0PFGY7RUM7a/p3EE6ejmYA2PCmtIVL6Rk1nysitHqiOrCP31Cv4ui0AVs1MMadqF6
         apvrrSitWV0l/eEiBeWZEnxlNJH1Oyh+ayUmW6Pq3T6SnxEQUZOzqXzPiYOGRXl4ezW5
         rF827NAezQc85fGTeGX13DVhIFW1U51pq3kahIUXlfzZvATyZPpgdDc+3NnfPNmmmtOQ
         IiKLOrwFyJZigkUYdbDITpeCbRwKpp/k9jarsPyWNy5SybMUI62+oTOd1x/Ug6hIHA7d
         ck0IQwhAlJqgxh1NzZNA+kutt5bd//Wtst1iUiBGuf15h4w0Lmo82jubI1AFAtpGmKxD
         l4fw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=grfUhkoC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42c as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42c.google.com (mail-pf1-x42c.google.com. [2607:f8b0:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id f185si631324pgc.5.2019.05.22.22.21.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 22:21:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42c as permitted sender) client-ip=2607:f8b0:4864:20::42c;
Received: by mail-pf1-x42c.google.com with SMTP id n19so2579119pfa.1
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 22:21:48 -0700 (PDT)
X-Received: by 2002:a63:2d0:: with SMTP id 199mr37549705pgc.188.1558588908836;
        Wed, 22 May 2019 22:21:48 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id y10sm40609648pff.4.2019.05.22.22.21.47
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 22:21:48 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [RFC PATCH 5/7] kasan: allow arches to provide their own early shadow setup
Date: Thu, 23 May 2019 15:21:18 +1000
Message-Id: <20190523052120.18459-6-dja@axtens.net>
X-Mailer: git-send-email 2.19.1
In-Reply-To: <20190523052120.18459-1-dja@axtens.net>
References: <20190523052120.18459-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=grfUhkoC;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42c as
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

powerpc supports several different MMUs. In particular, book3s
machines support both a hash-table based MMU and a radix MMU.
These MMUs support different numbers of entries per directory
level: PTES_PER_* reference variables. This leads to complier
errors as global variables must have constant sizes.

Allow architectures to manage their own early shadow variables
so we can work around this on powerpc.

Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h |  2 ++
 mm/kasan/init.c       | 10 ++++++++++
 2 files changed, 12 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index a630d53f1a36..dfee2b42d799 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -18,11 +18,13 @@ struct task_struct;
 static inline bool kasan_arch_is_ready(void)	{ return true; }
 #endif
 
+#ifndef ARCH_HAS_KASAN_EARLY_SHADOW
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
 extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
+#endif
 
 int kasan_populate_early_shadow(const void *shadow_start,
 				const void *shadow_end);
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ce45c491ebcd..2522382bf374 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -31,10 +31,14 @@
  *   - Latter it reused it as zero shadow to cover large ranges of memory
  *     that allowed to access, but not handled by kasan (vmalloc/vmemmap ...).
  */
+#ifndef ARCH_HAS_KASAN_EARLY_SHADOW
 unsigned char kasan_early_shadow_page[PAGE_SIZE] __page_aligned_bss;
+#endif
 
 #if CONFIG_PGTABLE_LEVELS > 4
+#ifndef ARCH_HAS_KASAN_EARLY_SHADOW
 p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D] __page_aligned_bss;
+#endif
 static inline bool kasan_p4d_table(pgd_t pgd)
 {
 	return pgd_page(pgd) == virt_to_page(lm_alias(kasan_early_shadow_p4d));
@@ -46,7 +50,9 @@ static inline bool kasan_p4d_table(pgd_t pgd)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 3
+#ifndef ARCH_HAS_KASAN_EARLY_SHADOW
 pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
+#endif
 static inline bool kasan_pud_table(p4d_t p4d)
 {
 	return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
@@ -58,7 +64,9 @@ static inline bool kasan_pud_table(p4d_t p4d)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 2
+#ifndef ARCH_HAS_KASAN_EARLY_SHADOW
 pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
+#endif
 static inline bool kasan_pmd_table(pud_t pud)
 {
 	return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
@@ -69,7 +77,9 @@ static inline bool kasan_pmd_table(pud_t pud)
 	return false;
 }
 #endif
+#ifndef ARCH_HAS_KASAN_EARLY_SHADOW
 pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
+#endif
 
 static inline bool kasan_pte_table(pmd_t pmd)
 {
-- 
2.19.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190523052120.18459-6-dja%40axtens.net.
For more options, visit https://groups.google.com/d/optout.
