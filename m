Return-Path: <kasan-dev+bncBDX4HWEMTEBRBU4LXT6QKGQEXVQKVSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 313DE2B280B
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:16:52 +0100 (CET)
Received: by mail-wr1-x439.google.com with SMTP id g5sf3269337wrp.5
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:16:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305812; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xd6X+5HOqOTUVYeO8ZqR/Tr6CNnRT44ix75tqXDjcaV5swonRZFItRuKjnNCgqNh1R
         XAAziKHoAr2IcZmEHANUH7nsnhINyTk7PjYtZ+DNGuzK+wcmRDQue1NCLqbUcp/kiaMV
         80PkEbdIjFj9yy7t5SBiK12PLxAgLtqwDG/EwGdR3I7TrJ/tZNRQdIaH1V6qOt812lV6
         32A4oY0WmNw6UQ7OkRl4br5GlfysPOOI690A13gbcZQ7E1y9NayMxzdbJDBDiRpfpfUw
         IAiBJr5WGRX6blHuVessl9ctAZCCohbNpAarvNxmUUfCtlq54tXyIdXgze4ZTivjDGBS
         1ycQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nTx0eNVowQXmlN2v6Ut41I/yU+sVBBrmsJUQ+q6vN4Q=;
        b=t7GikzLaImVt++ix1RvxzP1kZ/KHP1oAKqLwwjMaNPtY7zMproD3h5W3ssVqWUEyof
         bfQ12a109LZ9W6VZG566vUJEZ8JkVQImY8k3x724HLB08sBLk23rwO0dyP8QXLXJT0M9
         CpyHJnfDCsogNdIhdd4NeDE2nsLingOVcP2c+HmNx4UHmP2v5h8glqTGB80lFWLFiLaG
         IcuCZvjsE5QrBQ7IkaPQgPAK2Tv6jExltfcbdVYkPtjU3C4qSZx5V04cWcW3VjtopkE0
         HOS89bcx8Xviv1rTIMyq4ZFOJbLZ07/mhr7SSlI7AUpCKTquLoIwBHEzC2dYD1L/8tsD
         i0XA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nVndJlcF;
       spf=pass (google.com: domain of 30gwvxwokcz07kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=30gWvXwoKCZ07KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nTx0eNVowQXmlN2v6Ut41I/yU+sVBBrmsJUQ+q6vN4Q=;
        b=WIIMsQW8LVU0jcwVxYdiKyeLzbAaFsVfIliAF85/e9ReS5MpUuiTnNvk58NhV8hFbK
         Hlaf+L0/wSRirkOUxPxXKcgZXWybHxf2bBfuqVwY2CRzBAbzlH1YsEIxvszqwY4pOQko
         U/pGKmw6Qb9z1zdlPRvp1jkelCy9D8g2S/dicQEtlaL16LH906jL+eQ+hl7sxZIpCRVY
         zSvn2wdcnmVpCjn3q6ZbrIHSqFIUOwl28+NZmCUgtl3X82GXHSkhJHbRSXRURzJjAXSj
         gopbdzeiukHoVyYtsw1744hyQnBZskTyq9eMSPmsJoDm5+vk5iXYi0pt8XR2o0Sc6VnQ
         N/CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nTx0eNVowQXmlN2v6Ut41I/yU+sVBBrmsJUQ+q6vN4Q=;
        b=b72RlxXKf/UExhxXSvsLYCjdpbPJTwCbLIuOYl8t80aTWmLXgpuRLSVQNv7dOeysjm
         rlzNhOsEWoJ4rqhZwZgMhS2T8BElAnNg+2YOhmQAmJo844KNdCD1sMdfM5JlH/zV8P7i
         mUrrrFH0furtSYnEFS+/kS/Z11/DaMZRSbDEjLSt1VbnaKwBKgZ3qhwiVyLCwFHc0jfP
         hagdbH6/qsuVDiqw58+FXh/Z/CH8ls5cAmp4FtgNGZKRkbbwlNfIhs0cNJeAMAUzKSD8
         0urIcAEqo7YwNCYlmHH9axXDVV+8kTBupcqp66BYeE0SIQB4O5WggV4VHJfO9ogCrRKE
         n21w==
X-Gm-Message-State: AOAM533K/FLwmy1Ebe1tRhkKEpBtylKEP9IJSV3M+1CLPPXJoo0OAku0
	OzcPeH82htfqMpK4RTfMKQM=
X-Google-Smtp-Source: ABdhPJyBqUNycpn619H0VuK6SDgrfigDvegq4czRLjnMljUaIm1qbITU3GAwMmYOAjPqGilYFsjmVA==
X-Received: by 2002:a5d:4f90:: with SMTP id d16mr225853wru.292.1605305811969;
        Fri, 13 Nov 2020 14:16:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls7240338wrp.1.gmail; Fri, 13 Nov
 2020 14:16:51 -0800 (PST)
X-Received: by 2002:adf:e5c4:: with SMTP id a4mr6494410wrn.56.1605305811211;
        Fri, 13 Nov 2020 14:16:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305811; cv=none;
        d=google.com; s=arc-20160816;
        b=bCIw2g/E6lMfqppbQCPSIoiT/UiNgdM2tLvcwMuE4XFaBUk6j0hHcOhTl4bjlwjn9J
         RV42xzGp1xRhJdMNaMBWKcGEkfwzOSfAwVz94EPRQb2lMSQsnCEKbWEwE4jExiLfrN47
         02QDCar8UjLCcTIRhLWpTxqLonf13odIV9z6SeixQC8NlX3nZMZKIRvrAj+rS8uMFs6l
         5wAkbllY8vEXKyZwCOhy6BNuv4wnGUQVll/zIxaFYRDkoYPjI3yGj9+tHsEw/gHQ58pg
         H7sO3NwsZTqClqELcPpQPylXbfdRnPXTA+sIvIuAjn9/gfAXPmwA4zR9PAu4BnDM+RAd
         oMCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ntObSH5Wts69G9iVeYOB8VW5d6k5gPFIMEcmSrRrEtM=;
        b=NxYyFIUuVlTzv7+Te2Y0vH0o8iwC1ES2NYfqTrinWfxc4MYRkfGhDKUSYOGe2LvH9J
         fPTrOa8yu8RRUVkioiuMdLbmMvG8nQHppeG95WonKLZiMWPIfQEaiqC2ajgus4RKwuhI
         dgQbWDSIyVgUdGAfZFvj6rqKFIAwJPfEl69AFtEhPxbk/6yDdKNO6wjB75shMzc0c0Pj
         V847vEJSmn2fYImfMXA+7KlMcp3vVfzfe62bkEq3e8pQ4E12zlyfpyNMco21Ai6D3mv9
         M7WGiGrJdaE14ZJ4Bj7WjiXxGre2B6DcbtNkUUw3EJAcvUA2n3ddn1UjxbY9mTBr9Ywl
         BO6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nVndJlcF;
       spf=pass (google.com: domain of 30gwvxwokcz07kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=30gWvXwoKCZ07KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 94si244908wrl.2.2020.11.13.14.16.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 30gwvxwokcz07kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id h2so4727173wmm.0
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:51 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f246:: with SMTP id
 b6mr5787412wrp.238.1605305810568; Fri, 13 Nov 2020 14:16:50 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:43 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <98764bf6acb71bd93f344bcd7441e4ae6091d023.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 15/42] kasan, arm64: only use kasan_depth for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nVndJlcF;       spf=pass
 (google.com: domain of 30gwvxwokcz07kaobvhksidlldib.9ljh7p7k-absdlldibdolrmp.9lj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=30gWvXwoKCZ07KAOBVHKSIDLLDIB.9LJH7P7K-ABSDLLDIBDOLRMP.9LJ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't use kasan_depth. Only define and use it
when one of the software KASAN modes are enabled.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I6109ea96c8df41ef6d75ad71bf22c1c8fa234a9a
---
 arch/arm64/mm/kasan_init.c | 11 ++++++++---
 include/linux/kasan.h      | 18 +++++++++---------
 include/linux/sched.h      |  2 +-
 init/init_task.c           |  2 +-
 mm/kasan/common.c          |  2 ++
 mm/kasan/report.c          |  2 ++
 6 files changed, 23 insertions(+), 14 deletions(-)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index ffeb80d5aa8d..5172799f831f 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -273,17 +273,22 @@ static void __init kasan_init_shadow(void)
 	cpu_replace_ttbr1(lm_alias(swapper_pg_dir));
 }
 
+static void __init kasan_init_depth(void)
+{
+	init_task.kasan_depth = 0;
+}
+
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) */
 
 static inline void __init kasan_init_shadow(void) { }
 
+static inline void __init kasan_init_depth(void) { }
+
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 void __init kasan_init(void)
 {
 	kasan_init_shadow();
-
-	/* At this point kasan is fully initialized. Enable error messages */
-	init_task.kasan_depth = 0;
+	kasan_init_depth();
 	pr_info("KernelAddressSanitizer initialized\n");
 }
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d237051dca58..58567a672c5c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -51,6 +51,12 @@ static inline void *kasan_mem_to_shadow(const void *addr)
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
+/* Enable reporting bugs after kasan_disable_current() */
+extern void kasan_enable_current(void);
+
+/* Disable reporting bugs for current task */
+extern void kasan_disable_current(void);
+
 #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 static inline int kasan_add_zero_shadow(void *start, unsigned long size)
@@ -61,16 +67,13 @@ static inline void kasan_remove_zero_shadow(void *start,
 					unsigned long size)
 {}
 
+static inline void kasan_enable_current(void) {}
+static inline void kasan_disable_current(void) {}
+
 #endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 #ifdef CONFIG_KASAN
 
-/* Enable reporting bugs after kasan_disable_current() */
-extern void kasan_enable_current(void);
-
-/* Disable reporting bugs for current task */
-extern void kasan_disable_current(void);
-
 void kasan_unpoison_range(const void *address, size_t size);
 
 void kasan_unpoison_task_stack(struct task_struct *task);
@@ -121,9 +124,6 @@ static inline void kasan_unpoison_range(const void *address, size_t size) {}
 
 static inline void kasan_unpoison_task_stack(struct task_struct *task) {}
 
-static inline void kasan_enable_current(void) {}
-static inline void kasan_disable_current(void) {}
-
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
 
diff --git a/include/linux/sched.h b/include/linux/sched.h
index 8682df0050bf..96f6e581e7eb 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1203,7 +1203,7 @@ struct task_struct {
 	u64				timer_slack_ns;
 	u64				default_timer_slack_ns;
 
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	unsigned int			kasan_depth;
 #endif
 
diff --git a/init/init_task.c b/init/init_task.c
index a56f0abb63e9..39703b4ef1f1 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -176,7 +176,7 @@ struct task_struct init_task
 	.numa_group	= NULL,
 	.numa_faults	= NULL,
 #endif
-#ifdef CONFIG_KASAN
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	.kasan_depth	= 1,
 #endif
 #ifdef CONFIG_KCSAN
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index ae55570b4d32..52fa763d2169 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -47,6 +47,7 @@ void kasan_set_track(struct kasan_track *track, gfp_t flags)
 	track->stack = kasan_save_stack(flags);
 }
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 void kasan_enable_current(void)
 {
 	current->kasan_depth++;
@@ -56,6 +57,7 @@ void kasan_disable_current(void)
 {
 	current->kasan_depth--;
 }
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
 
 void kasan_unpoison_range(const void *address, size_t size)
 {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b18d193f7f58..af9138ea54ad 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -292,8 +292,10 @@ static void print_shadow_for_address(const void *addr)
 
 static bool report_enabled(void)
 {
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 	if (current->kasan_depth)
 		return false;
+#endif
 	if (test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
 		return true;
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/98764bf6acb71bd93f344bcd7441e4ae6091d023.1605305705.git.andreyknvl%40google.com.
