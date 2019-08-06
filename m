Return-Path: <kasan-dev+bncBDQ27FVWWUFRBAU7VDVAKGQEWWZ5Y6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0590B83DDF
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2019 01:38:44 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id i33sf49250498pld.15
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Aug 2019 16:38:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565134722; cv=pass;
        d=google.com; s=arc-20160816;
        b=0D4zUKR0Z/D+nNuttkyXBxiyIX8svqzv8xGGcnKNJy5nC6fkii7xyq+gwo12DiUFoI
         vVvqF3IKyKKYlI/UYuEQ9S7cDe4E2Gyi5XwT5ZoAhDrSsFJSBDknw2xjfLGuUAiVomgj
         ZTHXcUmCEb2x+NDDXTHu4GsO76o15yLVitvfCCgcWsb2mgG5dGQrAD6R1hxJLnBoL5/n
         E1RJdoIf9EfZv68BBiHgbzxZiDyr4LYF7GYPwmAm7k8e3uK/kVGeRLN6eUUyXz48NQSw
         wFh98AFYtx9WVzIWZ7aRWHT1Tei5T9JDyi3uQ/xJLrfhax8Qza+uZCejouic54uyWEVl
         e/iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=h6QmHem1EqQKW36HRuoLLIAH4cipqZwMu1XZ3uy68CY=;
        b=e4THz0P4l++5pF1T7LGSiDxGprewMwH0suzG/NBRSq0PvExlQ+uf4lEGQCPNIRPBb6
         W79TmKInsdmVPhvKSVjnSRErqTrUFumXb6aVFsGZ8gYEJzfQQNKoZFO+RBHS6KZwgFaJ
         xZsFnaWLdrbPBWK9lg8A7JsFrKaa/LOGK5Ahj1T1FZV2i8u931RpU9N/0DWouhP8OCj1
         yNcWfcElcm7iprPWKPJtIU4xTOfqYnONiGi2fEPSmh4wFw6Ck67uaAxwuYnwFI1GYuf5
         +59b/2CrsKh08+xXc1BLPh6JPc3yORI43AgTEl51YxiEBh12fVab2I3Hvyyzjb10UHp+
         IQ1w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lgsrE8jK;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h6QmHem1EqQKW36HRuoLLIAH4cipqZwMu1XZ3uy68CY=;
        b=Rr/I1apSLUO4+JeN1o3G6oUYk5rgW6hRPE3o5aZONlmzqlbpMjA6NBBU/sj5VmukFa
         3fQVuZdl/qWqE4z11VCDB1Tc3OXbW/H6BBehnxjz/E4VBziDLkhAdnNeMMxgoVJtTwHj
         lzfzg7SsE1mpq4RdepjY8O+cx90NZ6ccpp+xs6E1hF8Zvh3uultlnPTd0O2U9y4HZ3IS
         oXxP64sQ/AI0wbTBqj7b1L9i3zN+AOSSFDUjqCHNogOJbyfWbGOih/FiXzRsWCNdKbz9
         ucJ0F5dNqd0EFTkQe+d3HKODNhqQluy25TS4kNJHTSmJrsRZZi0dVGMkmJ+M94yXgcWM
         1/9w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h6QmHem1EqQKW36HRuoLLIAH4cipqZwMu1XZ3uy68CY=;
        b=SIPdOQfIzNcfPOlly/sLkDSRPI0ZwsBsRofi37zdsoFpHR7uRUpxD0K2oJT5i4h873
         bCkwbXXS7ZwqGaJKKXqCFQln3j93QxeFv6E55TceVnky+5cfgrcfoX3/AQoBFzPtorVN
         YdufQ+EAqcBVapVoVuAss6bwmudWwF7RUgwkJyIJmvKjvBi953e05AqcBnwoV3feMt1z
         5EwGQN7qkQOAAON6xWb/bKFNgRTMaIBSmlM6RKQoxDREdUNcaM0fFxAZPIlzoZccq/8G
         gLeb97eUlPnyMaKONLRupyTEMaQkbnHk4v9Jdtz39V7PDYTsovWzKjUuYyMsvKsHL9w2
         48oQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVY+RaT8pgyMp8c/avfRsz2tURMr2XQdkTvIN6hjpOpTSRPYwaj
	3sBlChpPnbCvUcD8Cdu2ou0=
X-Google-Smtp-Source: APXvYqzorPVk/ZKZX4KM0uPrIgy7Mj6wvxqEIetRRHjcHZNuRXcR5F43VdIIWwb+fcBFjPO7GJdAJg==
X-Received: by 2002:a63:7245:: with SMTP id c5mr5280197pgn.11.1565134722637;
        Tue, 06 Aug 2019 16:38:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b08e:: with SMTP id p14ls24774285plr.16.gmail; Tue,
 06 Aug 2019 16:38:42 -0700 (PDT)
X-Received: by 2002:a17:902:7791:: with SMTP id o17mr5549387pll.27.1565134722328;
        Tue, 06 Aug 2019 16:38:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565134722; cv=none;
        d=google.com; s=arc-20160816;
        b=oqxUMlPSn6vRFPJLScNk1F1Jw8oHOsOZHT1flPN6wkUbaHmWyHBuWBrr5AmISThkkR
         CvaY1IOs9Wxvr0mcoek0EMQg6MmFzqdzSSrctWDrIIZMUnm1eSJn8Nnh0/qn+eKnnNoq
         ISjZanG9lD8wmx3cFCCWjFVsYUeH1hwDV3aetCsAyxtZ43miDDHEdsUGrQUtgj84pne2
         YNLy5Sv0jI2UznH/rrYMBqvnBoGP2c2fUu73zI1q4/znLZYKi34MwiGNWbczaSjWw8xB
         kJFxy3Ymyy/3VuZgseRezUXl3PBAWQ9IETz1hcqkbWnzwuXHII5w5rtvx2cP8NRrExI3
         zF+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=tEsxmPhUS4bT5wWGzUtfPaeJrqiErpfsRL+tuJYXGZE=;
        b=GluQyNqIVtK26iNLfY1o1QjtdRCzAQtxjt5HDaKytwuuhwiXon5CbZ2YC4n4OHCyQS
         RyDkDpHwd2gG55Uwm0T1uf6YYBEfW1C2zjR+eDFYO4GoU0McjT/Oe7jrb7AKnowxcQoc
         VGBz0wXIdkOdTe7+auA4WiO4rZs0fx+7cuS4XnyOi5SZGJAGIidmmH+sBwKeHKgoxOH4
         4hZbqIpkVQd5ftddXud7QF8Ou1JPRVg5UrR1jku6HHPi6WAUv+k0DZLcqyuoOBGOQesm
         X1UunjAckf6wIi3wvpb9i6HalWMb5G1s/zaOeu5WaUw4M5ZJPj+vsOd+JXX0bEyZPCtK
         NmkQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lgsrE8jK;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id w72si3765125pfd.2.2019.08.06.16.38.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Aug 2019 16:38:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id r1so42351500pfq.12
        for <kasan-dev@googlegroups.com>; Tue, 06 Aug 2019 16:38:42 -0700 (PDT)
X-Received: by 2002:a17:90a:b104:: with SMTP id z4mr5662095pjq.102.1565134721898;
        Tue, 06 Aug 2019 16:38:41 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id j6sm36104084pjd.19.2019.08.06.16.38.40
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Tue, 06 Aug 2019 16:38:41 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH 1/4] kasan: allow arches to provide their own early shadow setup
Date: Wed,  7 Aug 2019 09:38:24 +1000
Message-Id: <20190806233827.16454-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20190806233827.16454-1-dja@axtens.net>
References: <20190806233827.16454-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=lgsrE8jK;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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
level: the PTES_PER_* defines evaluate to variables, not constants.
This leads to complier errors as global variables must have constant
sizes.

Allow architectures to manage their own early shadow variables so we
can work around this on powerpc.

Signed-off-by: Daniel Axtens <dja@axtens.net>

---
Changes from RFC:

 - To make checkpatch happy, move ARCH_HAS_KASAN_EARLY_SHADOW from
   a random #define to a config option selected when building for
   ppc64 book3s
---
 include/linux/kasan.h |  2 ++
 lib/Kconfig.kasan     |  3 +++
 mm/kasan/init.c       | 10 ++++++++++
 3 files changed, 15 insertions(+)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index ec81113fcee4..15933da52a3e 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -14,11 +14,13 @@ struct task_struct;
 #include <asm/kasan.h>
 #include <asm/pgtable.h>
 
+#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
 extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
 extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
+#endif
 
 int kasan_populate_early_shadow(const void *shadow_start,
 				const void *shadow_end);
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index a320dc2e9317..0621a0129c04 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -9,6 +9,9 @@ config HAVE_ARCH_KASAN_SW_TAGS
 config	HAVE_ARCH_KASAN_VMALLOC
 	bool
 
+config ARCH_HAS_KASAN_EARLY_SHADOW
+	bool
+
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
diff --git a/mm/kasan/init.c b/mm/kasan/init.c
index ce45c491ebcd..7ef2b87a7988 100644
--- a/mm/kasan/init.c
+++ b/mm/kasan/init.c
@@ -31,10 +31,14 @@
  *   - Latter it reused it as zero shadow to cover large ranges of memory
  *     that allowed to access, but not handled by kasan (vmalloc/vmemmap ...).
  */
+#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
 unsigned char kasan_early_shadow_page[PAGE_SIZE] __page_aligned_bss;
+#endif
 
 #if CONFIG_PGTABLE_LEVELS > 4
+#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
 p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D] __page_aligned_bss;
+#endif
 static inline bool kasan_p4d_table(pgd_t pgd)
 {
 	return pgd_page(pgd) == virt_to_page(lm_alias(kasan_early_shadow_p4d));
@@ -46,7 +50,9 @@ static inline bool kasan_p4d_table(pgd_t pgd)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 3
+#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
 pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
+#endif
 static inline bool kasan_pud_table(p4d_t p4d)
 {
 	return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
@@ -58,7 +64,9 @@ static inline bool kasan_pud_table(p4d_t p4d)
 }
 #endif
 #if CONFIG_PGTABLE_LEVELS > 2
+#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
 pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
+#endif
 static inline bool kasan_pmd_table(pud_t pud)
 {
 	return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
@@ -69,7 +77,9 @@ static inline bool kasan_pmd_table(pud_t pud)
 	return false;
 }
 #endif
+#ifndef CONFIG_ARCH_HAS_KASAN_EARLY_SHADOW
 pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
+#endif
 
 static inline bool kasan_pte_table(pmd_t pmd)
 {
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190806233827.16454-2-dja%40axtens.net.
