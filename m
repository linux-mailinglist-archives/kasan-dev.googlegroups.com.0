Return-Path: <kasan-dev+bncBDQ27FVWWUFRBWX5Z6DAMGQEBNJDZDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id D18433B2592
	for <lists+kasan-dev@lfdr.de>; Thu, 24 Jun 2021 05:41:15 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id o11-20020a17090a420bb029016eed2aa304sf2636192pjg.2
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 20:41:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624506074; cv=pass;
        d=google.com; s=arc-20160816;
        b=BubGXqcGXEit6lZwle3GKd+F74Jc8MezdFRFmtNgwn2P7rZzlzx4ywY2p3LW9kGRS6
         3EQwxSV0A4pjByiANPkXANj7ZgtsRSsGLH/ohDRzd3oyUmqUGdmOd1RAhQ/BUQtMRqEU
         ZF08qpKjj7F2RKtBbtCoRi8sYKOrNwYToZUzYA3PztSm7zTvFXQLdkM4m8769coKBaEU
         1gTUfOv/z4L0pswua+84zURXLCp+WEzaoAyEaRiiErV6pr9oBKEvbqwoVnqs/tuD55FK
         rlzFZRDCziWhgHYae1gTFzLmqRZ4II8i6QvXe6FfPgJZ10Ari4vZC3RU/thPkP6OMU9M
         iWqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZNuXO57dqXJRfguZ7SxJ5JvXBZRKojWSu60fZwwQZRc=;
        b=a6tfFAcjGvdDQltiZ8DZqGWBharikj5KZZ32uHcuH5V8tge/tnrbGQfwN0+ZYxd9ZP
         Ey4tFebNOzSdG32nZ8EYs9cTZvP4M9YtI7PQWIjyYPFoYHjXZ1TKFJjXP3qjnnc0uV59
         V6TJ6as2VRMA+kBlWNYIL6rI1hC1z92gi9ZEYY8kdXrOMe3TiE+CSoAIULtKZ34UhLZ4
         I74zYqtx8OXZ4TBvtcVbvB1YUjGVEkGkqwE92emVKK1czYzVJTJa3a2IIfKxfLVHk2CK
         Rg4YIhaIo2Nj1MrTGG9dhVPMHNX4+1sylK02k2HyOhL8tYBbr3q+HEiqHYuVMlb+Jo2Y
         hPZw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=FooYSsrf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZNuXO57dqXJRfguZ7SxJ5JvXBZRKojWSu60fZwwQZRc=;
        b=KhEOC8nczgpVBGuWLjJGEBgmpMNQvHmvHQzf+oaI7Jm9jA3AumIJqxt9KgkfkkJG3W
         ZSup0WNkPcrFCYTAn9qxuc4PcJb8xhWnnMu+INTte+FZeAzZMLFwv3tnGePYn7yabw+q
         uRM8TkzrigrNhayuAEMD9ay8Y3Cwc5jphVdOtw+O4TPsu5hkxfQskuc7EFI//T7xwf3J
         1TFhnIT/kTg5k8RaZtMJKGZyjCzh6iQ98YMV6faFEysDPd/cGyLMG6REaOI7imO9xPv9
         5khHv7gwDgURZzLyQ/ZnIRe44zooC9bh/xw/2/Mg6mKD2tD2995K+G9lDitx24Jxl/2W
         YphQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZNuXO57dqXJRfguZ7SxJ5JvXBZRKojWSu60fZwwQZRc=;
        b=JosdtprrVY4CZSIFD0tkxdSlwzFXWnhODKbQAexX/UkpLimHX302ogF8oAIzHqn7Kj
         M7TMRfDMN1pF4duF9OWpKyeu9pEnMPzCszdbY10q+cBnzjzjO8/q7GQo3JXOR/fI6gtd
         tBbNotczt88Wqff4Cnl1UgITbQGuEEoyV4+BAzaapK/9kBhKLIHyNOx76D07l3ytz7+b
         07LY3Sz22V7lPE1n/0xHJJ/vDVgHBKx7rvcUqSifZg5m4C5Y61cNgB4vvYV3kgWxmSV2
         tZJak1rZ/v5GH5O67pz5elda7ZpZSRh6SUlKd3OW0qx1D//IZWU6wGhcfFj+ZH+SHkbt
         gnVw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530a6Sh8UjgrYPfWxuaR7DLOwMpFY1NjuW71Zzfjut67G9OrOwxT
	0SwSRKxsVs48uu/hT7JKpwo=
X-Google-Smtp-Source: ABdhPJyCYZ7HVo6jyu1XlAJ2pRtrq5f8wPdYeimbhJ9YZDpM6GM4KL4ry3kWrzlRTdtpgKmGsmd0qQ==
X-Received: by 2002:a17:902:c18d:b029:127:9c3d:6e93 with SMTP id d13-20020a170902c18db02901279c3d6e93mr549217pld.73.1624506074387;
        Wed, 23 Jun 2021 20:41:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1dd4:: with SMTP id d203ls2076662pfd.2.gmail; Wed, 23
 Jun 2021 20:41:14 -0700 (PDT)
X-Received: by 2002:a65:618b:: with SMTP id c11mr2810970pgv.292.1624506073911;
        Wed, 23 Jun 2021 20:41:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624506073; cv=none;
        d=google.com; s=arc-20160816;
        b=qQYsx7O5wEqf6yhQ3mPhMzisBC601c9XLAYR6Cvy/hp1PqafuMNPWbQuhsNrajEKso
         gDH1FcO+/3u/1E/62sltjEqDapY1WPnQ1flII96Qeyt6k7zPbcZt7lZ/XQJc1KMOxNA4
         LtAmEr3iywUKB2OZnkLXdlyAi8Ktgh9zGL44HI3Hc2HQSFMUVUYJdmsICQ4y7lJ9SZ1T
         5bYyR7ZWxkXAWmlxOX0/3Ku3V7ixdwyr7AZhky7WTfE6lHGGvJ1zCGsLWqP4S7O10Q+P
         HDiXFPBTm8zn3rmMBPqV0WDN793y416pCokpZ+SfYTHiwPF0KRYs3O87aaTrGHQQS5i6
         VthA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Ctu6eGIgdooF8iPxRHw2B5UaQhrklgx8o8kc13VGL+0=;
        b=DaGKymWk+58oNS65fl7kxG6VeEYS4EEVOOP771Qpybo4wDIAVbDrg3Sp8lXZd4YtQO
         EVsyECzAlaJx2MFbSPJoXmp8iDJ8NobgqiH/21FvxNE/AgMCo5JBh9EgF0EVZhttPl/8
         K5vbK2DYhUK7gODkThFXKASCVIc6KBvrKBn7XwBeEXY7NUj/kT5v5kAlbQj9iDw8IHPg
         eqnKIJ2bQEf9hgJJnhGKxOpIH8KqkqIX82ZKhUibhGWwRaSc22Po5871uYo5cGjgfcrk
         Ww+8IeH1PQztgQgvfvahp5hNKlkRxjbGB8Dya20NuZvTL5F8NE2RDp2ytjOVjkiRBWQL
         bMiw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=FooYSsrf;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x42f.google.com (mail-pf1-x42f.google.com. [2607:f8b0:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id m14si592122pjq.1.2021.06.23.20.41.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jun 2021 20:41:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as permitted sender) client-ip=2607:f8b0:4864:20::42f;
Received: by mail-pf1-x42f.google.com with SMTP id a127so3997816pfa.10
        for <kasan-dev@googlegroups.com>; Wed, 23 Jun 2021 20:41:13 -0700 (PDT)
X-Received: by 2002:a62:1657:0:b029:301:af69:5ae3 with SMTP id 84-20020a6216570000b0290301af695ae3mr2929381pfw.57.1624506073704;
        Wed, 23 Jun 2021 20:41:13 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id n69sm1160501pfd.132.2021.06.23.20.41.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jun 2021 20:41:13 -0700 (PDT)
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
Subject: [PATCH v16 4/4] kasan: use MAX_PTRS_PER_* for early shadow tables
Date: Thu, 24 Jun 2021 13:40:50 +1000
Message-Id: <20210624034050.511391-5-dja@axtens.net>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210624034050.511391-1-dja@axtens.net>
References: <20210624034050.511391-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=FooYSsrf;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::42f as
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
breaks the build. Switch to using MAX_PTRS_PER_*, which are constant.

Suggested-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Suggested-by: Balbir Singh <bsingharora@gmail.com>
Reviewed-by: Christophe Leroy <christophe.leroy@csgroup.eu>
Reviewed-by: Balbir Singh <bsingharora@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
---
 include/linux/kasan.h | 6 +++---
 mm/kasan/init.c       | 6 +++---
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 768d7d342757..5310e217bd74 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -41,9 +41,9 @@ struct kunit_kasan_expectation {
 #endif
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210624034050.511391-5-dja%40axtens.net.
