Return-Path: <kasan-dev+bncBDQ27FVWWUFRBRFZSLZAKGQEP6YQMCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id CCBDD15B614
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 01:48:05 +0100 (CET)
Received: by mail-qk1-x73e.google.com with SMTP id c77sf2628512qke.7
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2020 16:48:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581554884; cv=pass;
        d=google.com; s=arc-20160816;
        b=0uaVvA3O/yEG4hKwdI0lhQJ0C4jLVbj+qoMKUHN4BwTQ9nFjt/b8BObm3N1jS4gxSV
         5cXsqOJ392RQ5wie2XLSB/IAve60n1kqvZGAvXQCTJNbNF/kM0Zj56RM0gmxOBn+eQZK
         3gAGtLz9ifw8wXSblOa77V6zRBCjK9+Vagl3HhZLGl+H1Gw1Yu42QW957oRLzrejKmIA
         xd3PZSUy7usr+k7AMGIEQSKrPUQIZZHEMTACrmKj+RxXUdFRQkCa+cxwhfSBWACmgztK
         ETY04SD8dTdTTZyBYhkVPZ3o2NbHHMqiChZ4Fe633eHtDJF1+GEsU75n8GlK9JytD3U3
         3D2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=qbV8h++Jtab2tGTdWjm9d/FdjtwP5K/Rgx1U3kws5TE=;
        b=Cf5tFl+5U+95v7kS7djKvj7w/hViG1w1ts15r8lAnKtZNa5PU3YXjaYTfgXJXXwq/Q
         F9mJlK0DXgDH1Cjy/JrdSILOWsLkCSF8XDGtKF+PfRjQp11nMStFA1PTL0KVHWaXFdXc
         CKVxvy25c+PnEuEOygp7FypUqm3voE6tA2zACroS2OD+nibheX0juvb5fo9aMBWGrVwc
         BFWi2hBB4ipsPj69tZPR8ZhfG1EJDO8vWm0FL+TQC8QDXhpLGGE7blR9Hc7gQIAAjfVy
         LGk74Sy+ADo7hXaiaxt0HATl2jUPv8FxKItNSWWLPLUIZlxBvMamwkWScH24eIWkj0ZR
         E1JA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gfQ7jmAP;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qbV8h++Jtab2tGTdWjm9d/FdjtwP5K/Rgx1U3kws5TE=;
        b=ZodpyZfo44PqEOUflCUfbH4GgdML+kp25YOeynyNHkmeMwPetpaDuDStUoRndHh+hf
         Wnpi6IRm/8KyCSpHHLKxgIUs5nhApxqDakNB0jUNeWeL2p7dF1AZNUcxDq6dWr5FYUGJ
         ZW8xpMES3YI0gQSiQ6OcK86RjhPTOwqiEC8Ju8Vrd+PMXXNeZzT45y0fR7wD0ZOtZp3w
         Up0OHXgF68eg5uH5pR7xn8DL6y+FMAkkVeHsNXvfV8boWZZdeWww37uTPWMI7dqDWVtU
         GMZmix2Y5olHbPXTFDOXfQx5NyQEPrTo1dU9+iFiyGtptW4gbXwy+v2lgbWhDm/LOwLE
         epnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qbV8h++Jtab2tGTdWjm9d/FdjtwP5K/Rgx1U3kws5TE=;
        b=Dq8zvP7/iazn2EN1BQ5TaSCzJ+E88MfLPiZo42ksK9Xq/sxjoHb/fVbv0BXWRH31T7
         IzDjUz2TMubb6jafAdtql70hKcTVX0c1dkcsj06ev1l+ArLVt/8Z0fTAiSAp5Etcjuct
         MIr2bnhf6vdU4Qln2aoSoKa2LwIGeuBVNMu5JUqmo/GIlRvjl+cR5gtkNAiHfaLpyNzu
         EMSdlCxLMCK/TG9afvXdVJJvvG/yxn4EB7LOT/tSAUSJHk64DKVQBoIx7Rgq+2kPqQFm
         WT9ZbZ+zJJmUlrtLQmr3sWqLIr+/Joj5OQHEStBkW0YMUAsH6RQdLjZ5rM0n41hfZ2K6
         4MXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXGe/ge35zrarzAHOdWkNvCbR/iBhGjl1xdUj+JIOWhdJBzdUXk
	F8qj996bXN5ZW4EOJVbUBLk=
X-Google-Smtp-Source: APXvYqyEUqP+uz8A1KA51o45138O0F0sY365BjVc2OrgXsta1OeUbL3fsy0ilN/YYfkAHko9Kb9V4A==
X-Received: by 2002:a37:680b:: with SMTP id d11mr13814125qkc.471.1581554884597;
        Wed, 12 Feb 2020 16:48:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:52b:: with SMTP id h11ls2867030qkh.5.gmail; Wed, 12
 Feb 2020 16:48:04 -0800 (PST)
X-Received: by 2002:a37:9407:: with SMTP id w7mr8143186qkd.55.1581554884285;
        Wed, 12 Feb 2020 16:48:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581554884; cv=none;
        d=google.com; s=arc-20160816;
        b=YyKkLJk+rNUDjjlnfudA6zePoDUDt46Q7uMtwQ8XrKk1qWxNkgPAb6XftAQRYXxV43
         JcNXp7QU9jtgOg+08B4a1hf4ufFg9xyeZfAhAYegCNIKiw6c3A02tI/zZWq84hvXsGFA
         R549SSpKnBkImh43I5/di2Oab72sDSwqc9EbYJJmxe7yAQFzn4fxGuYzJQ46HsQH645k
         2i0Fjy94ftcL7t4E8fQ8j4vT5sfRbARVVHe6siTjvwDQEdpnQ6PLbogCc5p26bCrvSCL
         ohaIjRdrl3KZohbjpDORENwlrq+xDc1C5JZXthf7fg8dIHyz4Z+i/SyS2kaDksvFRLNh
         SV4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=0eDFn39gIg7xtZfHp4ELa6UyXk2yfoJL9wFZ1T547PE=;
        b=e4tBaIay/ql3YLOuswDfXfuGetYQReMYkR1wyf02Vir0yo3AomzYU4KgQjlTje9jT/
         JePPs29wSOnbFAKA1lx2G2Jk1MIUV2FJpoNN3UlprQa4cRPTCysMm536FFZxkRsxQS/Y
         vwfUGLEK7ntJXyqG1OciWGpu4HEWoM8ZF15IvFXaPocV0ykLOgmor5fpJP1pGbA9Peqe
         hhZ2Gh/eBvJFAXhGXvv4R8TAseqLp/u2cM/H6f72q526JL0qqz0ZrzVtIj7BtzU8gGxR
         aeEYdj/HRktyc/zZPn/p0DhBPGfXgqxxCmvJbvuP1eXLY2acV6vCP6xmDCYB4bzzbmg9
         5oyA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=gfQ7jmAP;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id e26si53638qka.2.2020.02.12.16.48.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2020 16:48:04 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id ay11so1623729plb.0
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2020 16:48:04 -0800 (PST)
X-Received: by 2002:a17:902:9f98:: with SMTP id g24mr11134599plq.325.1581554883272;
        Wed, 12 Feb 2020 16:48:03 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-f1ea-0ab5-027b-8841.static.ipv6.internode.on.net. [2001:44b8:1113:6700:f1ea:ab5:27b:8841])
        by smtp.gmail.com with ESMTPSA id l29sm297624pgb.86.2020.02.12.16.48.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 12 Feb 2020 16:48:02 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	christophe.leroy@c-s.fr,
	aneesh.kumar@linux.ibm.com,
	bsingharora@gmail.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v7 1/4] kasan: define and use MAX_PTRS_PER_* for early shadow tables
Date: Thu, 13 Feb 2020 11:47:49 +1100
Message-Id: <20200213004752.11019-2-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
In-Reply-To: <20200213004752.11019-1-dja@axtens.net>
References: <20200213004752.11019-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=gfQ7jmAP;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200213004752.11019-2-dja%40axtens.net.
