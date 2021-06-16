Return-Path: <kasan-dev+bncBDQ27FVWWUFRBN7AU2DAMGQEWCUJUEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 59CBA3A94A6
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 10:03:04 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id d194-20020a3768cb0000b02903ad9d001bb6sf368782qkc.7
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 01:03:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623830583; cv=pass;
        d=google.com; s=arc-20160816;
        b=kUgM3NBkqwVXf9Xu1RZy/gSRW3fnbCahqsfXXI4lfqmjUH3Net2yyH+ZQ1EhVVVK4F
         IWB+G1D2xHREVKTYEl9IKFxb4xhSxHBgQYQny7A1BKbfYd53he0zW3qBvRpqMJ1NGjok
         oSf4uSuwcEnfpWI7u6w33zpMMOPkcOGtwi6I+1hnsvi8JgJ4HfMeiuSvfRZD1OLGHAt0
         hEm7KjPCGZynkd1RaLufnmwICmVq6N3xtM2xcBLTJEGkcAaIUqNE5BIn+Fb1f9kTaYl1
         ze88oH4qIJIFNvDekl6+4kqUolvSMCw0SOotbkPcENKQcac/0Ic8HnZipkqgwW44O3yi
         upsQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=uFOLSBBmuqrIl1+2PX78npJw9SlCveJQxijTRj7Fq/E=;
        b=bmQz25l2/Wy0kAhNyc/NlGagmOcr1fm2hLI5sOf+bOrze7Ya/wxc5uE/yFHMuKn4q+
         zi+XQLAPllOZnXjrrQDwZqJZZQTo5SXJDUUGGZZESMc3/DpA9TgtMJSeXea4detZGn6o
         17G5E2cJwwp3HKS1OZIRHTdorD+uvhpTmoROIxB5RMBd1F3eAkKOk4J3ES8wxrlewRNT
         dAZLbMRFZ5YUXD/DoqZI9STQ0rolv6VGXgF6Y2MlM8p6B8ONtosMfZMB8M95Fw7i/Il0
         9p6wRfskx3MjGKSy5NZqDZpoXSW9+V0M3fKcDF3VlsBsRWuCdbFMzu504yK/E5Pgjw3s
         2vZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=rVBqDrHD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uFOLSBBmuqrIl1+2PX78npJw9SlCveJQxijTRj7Fq/E=;
        b=PHydmUPQRTjqjhvUGnRcBvmcq/RtbJi+w6HSD9OPiIh9qctJw3JuHLsAMQOPju6SIJ
         tktb1owfvLhZggwPeiopjK0agiQ6h9pP8y+O7tDwj1nbasiuwq35hO6ECB9Nq04e2n/j
         uPXdV43sEKW7Y0BiSjMaVER8WWHcNRtyfN/80gwAO0ytr9qKny3wa0gk2XGvyo/WKK9+
         DfIvV3Ru8bTA90J7MSQVDc2/3TiqadCoPyHH0DYrWGNZt26Ls7is6QFRs65wwckS98in
         rFU2jeXxlWC6raX1CV6XO4261nzQo4cc0Y9VE7689wBeadCm5b39IIXe1toz3bDHvDj8
         okxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uFOLSBBmuqrIl1+2PX78npJw9SlCveJQxijTRj7Fq/E=;
        b=KaCIN/dFe/XExKfjdlQz2gvd8xAN/q31fjB7L5l0iniGr7XNmzZ3VCH91GGsKs1ipR
         ZD2tENfTX1KhynIoLnNkvPCkt/ywBzUceOFh2qG6yq059hZf3RKcjynHAHwhtQHUEj7a
         XPWlP+qOhI3b0JmQBa4y5xAVXjkLQ8C0eGd0QMV8t/Zjjg9lJe03vZOCcJj7WhC1sy0k
         vzzxjn2+jDhVnAK5MxCGSzRLk5VZD22VvZzYhb8Bo3m+8iypBm4JOpvT3eNvDGlKcCK6
         5CnGx5f79G4aeNqv3gWYvICV8vnV9pOcY01mlygBfAdF5eIvZuEm8zGSNeJm+6jBLJcu
         73AA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533uilBDJaA6ZiP+2gOzYjYhhz96VM7DhEBjrnP8S1xQ2dqkzyLX
	2Rt63oUEgwvJP6ENb1ltKeA=
X-Google-Smtp-Source: ABdhPJyCTrxevP+o7lfLBCqDyVJXazNRDoa4hT5l2qlRGFWQf7/9Ydxau0Q5oGPmpz29fHWi+HV2rw==
X-Received: by 2002:a05:622a:44b:: with SMTP id o11mr3938110qtx.157.1623830583489;
        Wed, 16 Jun 2021 01:03:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5f4e:: with SMTP id y14ls936126qta.5.gmail; Wed, 16 Jun
 2021 01:03:03 -0700 (PDT)
X-Received: by 2002:ac8:6682:: with SMTP id d2mr3976811qtp.230.1623830583069;
        Wed, 16 Jun 2021 01:03:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623830583; cv=none;
        d=google.com; s=arc-20160816;
        b=PGtMDszvNzD3wC8FUxc3QAMvtEf3RS+Ahgoox01SDz1HvPZHZK1Hqb5qtX5gZ2P9lX
         lxq5ZpPuR2HNpgn3OFxu4XrQ6ho0TkWWFhq3pmkUnxm7C895I2wnlFO6THc6JRTWvWb8
         Brgl2Tg5xhjYK+lbJtBTSpaJNHUnWQ0CXIntA2c/Nhv4sPZ3kjBR3eSr4un63IKIuT5P
         bc8UbO3Gp/zbXHNc3m2iStYrZqoRYbTzgP/YLMtlXUAuXkIjEL/CwQl614B2uCMzYdpa
         5EAQgf5y1GZQbwsoKrW5oA8xCROiSHqbo0BSCT1OzAd6OYymrM6AOqIsrdduSo+mTv6V
         fvNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=j1YLXpeuYLLATMRsuPzyJcK3SDVQ5TMCmimmfEEEFlM=;
        b=bmLPb1MPrdWP4wkhM4XGzhiKR/GGZyGR5PMqiIbRezqHVWvKl/z53qozTTuiw2aazg
         wVw4wwAilX//il78KjKGPceW1jos+tgBvpOrtyjBXZDum0A3Ti0n91BnlguxHkgIqXHg
         +dtZXJl3IIAw0lU9rPmxP+9UpCffemZnFdb7Am3KILReuriekClkT2X3rokhf0YYg/8o
         YUJ7e39KLqkNRskYRsAQLkbvW8/s29425BRfsAdLj/Xe4YaP7c8KRB6+FLHMlavd1Df4
         LXwOlWyB0yT5CBpDEUsaV16PViiAMcSBikRIXVMrtKgtTTnRB+0XdUj6Bo1TfzHgx9A+
         9VwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=rVBqDrHD;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::529 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x529.google.com (mail-pg1-x529.google.com. [2607:f8b0:4864:20::529])
        by gmr-mx.google.com with ESMTPS id c24si130548qtw.1.2021.06.16.01.03.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jun 2021 01:03:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::529 as permitted sender) client-ip=2607:f8b0:4864:20::529;
Received: by mail-pg1-x529.google.com with SMTP id e33so1328219pgm.3
        for <kasan-dev@googlegroups.com>; Wed, 16 Jun 2021 01:03:02 -0700 (PDT)
X-Received: by 2002:a62:e307:0:b029:2f8:d49:7b65 with SMTP id g7-20020a62e3070000b02902f80d497b65mr8326880pfh.48.1623830582233;
        Wed, 16 Jun 2021 01:03:02 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id g17sm1466688pgh.61.2021.06.16.01.03.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jun 2021 01:03:01 -0700 (PDT)
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
Subject: [PATCH v13 3/3] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Wed, 16 Jun 2021 18:02:44 +1000
Message-Id: <20210616080244.51236-4-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210616080244.51236-1-dja@axtens.net>
References: <20210616080244.51236-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=rVBqDrHD;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::529 as
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
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210616080244.51236-4-dja%40axtens.net.
