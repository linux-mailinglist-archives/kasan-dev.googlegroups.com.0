Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBVAVT6QKGQEBFIFXXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 266202AE2AB
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:19 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id w17sf5432432wrp.11
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046279; cv=pass;
        d=google.com; s=arc-20160816;
        b=vxq1mGffA5NLwWib7EJ7rviVHzFZmai2M0kEOUbtxiVOTgFxUJE47ms8bFAN33cybx
         ts/t3kTX9snUNfEVlfqeErAQjOdlk4TpgXqmOcpJH4/RZyydPVHq7PjJBG8wuAdxN6L2
         JUY6GYXs4jjVz1lSgPe6kk/BwWwbutujTwohguPh5aMJPfeaqxqDdD7w+werbAMpm5hR
         5q+XwKON3mLwUnIe9o99L0Tw9HgTk30CMlPml1uWaQ/THrUC7vTiVX8fmarmZstUfLTY
         0Tn0MZKynauR1edGnJpCKaxUOm5OsaV+f1KRSR19mkknpT5IT/sv5qPkZ0u4zxZTAalg
         pPmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ZE8S8OQ2RcJks4Z7jBCi0MY+qNgQp3vjPyR4W+3JMRo=;
        b=IfpKF/oN4lGuMvcV0xwzr7QGkhVDNgJIsBUjJWHemjoL8wd3YSQ37tKXTly4wXM0vK
         b3d1oqE77prvIMnovoURjaXV6aVo95hDcNSp6reTNnwcyNR+x8xLrM7+lk5qyxWe1pg+
         3yL0nLVYi0obnVPFDtEC3OinqWHlAe5U0mWkOvvzEloA5uG9APIYPe0bCKOOrNw2mUi7
         /tge5Zezi3999MM9QCX455xUmgNuXgV7MNNmHNfZUTyTcaAIg2kveaxoDu+BHQ10njRP
         SIi2b7y4xeZ0RPMnhf6ZiMwrDIld2OTXTxI1eJp4+jTAllajK69osO2zA9eBVjAmF7aK
         qwhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dcDLFYUo;
       spf=pass (google.com: domain of 3brcrxwokcdq0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3BRCrXwoKCdQ0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ZE8S8OQ2RcJks4Z7jBCi0MY+qNgQp3vjPyR4W+3JMRo=;
        b=oUvCwVW95y1W7UAcsHfYWtN5BPMlUmmdSwrHZRnrh9E7Akc93EPCK0xlzfqAfTNVkm
         AyxTB6y2oJYZC6b5oq/PO5aTg+sQroK8XNpdmqD79GUxKKcPZ71VDKFX5BiRmJR7HHko
         +JbWe+QqFQ+5z62YtqSNJ2YctrNClcenn8bUrsbdOv2P2S0Yq5HG8MeelWxBuDy+dXAs
         qEmeTcWKSqeYaCcDWxbeahP9VSyTfhoTWmTIjP8xjM4yuM0C1jIGxQMWb3E6FqYPOkiw
         Om6VWDkLuFfUGrpWLPcSoDh0bfFAFurbTTJfqCNe99XZOvwiNfZuCaEeNq4lu0cptUZD
         REkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZE8S8OQ2RcJks4Z7jBCi0MY+qNgQp3vjPyR4W+3JMRo=;
        b=LxaQjtAaAwjI1VVgeqUIy6z0PH3EwZIS7no59XM0Uz5w3lYrW9hxBqD8bVpEHJnOFp
         IIrhfm1i9ZX5D7sPZYBGNiMMvNsHG+GhDdmvqYZfhv5eawU5bsy+b4uQuQN0eQ61aeEv
         zsoZE+UhFpb5eEU3hWV604DhrJt6cXt4GyJxhqnOa1ZEU05WonpfT1vla6C+d/vDf6qM
         dX+EwzsGtBEgrcv0991xLT3qOUX8CyfruoSLwETtyU+E4zQ94MmP+OyitrR5rdExgLrm
         AQ2nOFoOj75vqUGQ8457kJbL3X6xgIcH7N90AwV9zZTL0oPcHUJ4kIKfUOfz6SCRdbP4
         2h8g==
X-Gm-Message-State: AOAM533Vr9fEyxTfPqzuS7FJkXx0/NBzUnypBjYjt8aNcUuwGFClcnL+
	JRUcIVZTP7RCRtZ84QFP8Ao=
X-Google-Smtp-Source: ABdhPJwAZdN3srzqnSU43TcsfgFTqxux8Qwo1xDyDA4Dd+E/9sZDCD80w3tCVWtHXceSiFftyxKS4g==
X-Received: by 2002:adf:8362:: with SMTP id 89mr26985227wrd.280.1605046278860;
        Tue, 10 Nov 2020 14:11:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f70d:: with SMTP id r13ls459276wrp.1.gmail; Tue, 10 Nov
 2020 14:11:18 -0800 (PST)
X-Received: by 2002:adf:e5d0:: with SMTP id a16mr28021511wrn.340.1605046278035;
        Tue, 10 Nov 2020 14:11:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046278; cv=none;
        d=google.com; s=arc-20160816;
        b=G8xgUcNqfLMoltSju8jRG/C7ilPhIHhGG88FQJ25ZGQL2m2/lIDwb2Notr7FnPcXSZ
         qJ0EKc8UjOeT/rMSCLXwmo8whUNqgau8f/tG1Mm7mkXom7cxBW2TAa+oyvvnsolOt6Bj
         Qzp7GpHZTIi0ajit3STrVGjaIWSpG1j/9S9u15ohwDrN7PX8cq3wqv8ktc+QcrigHedW
         +QQVFI0hZH+aSdZ/RLzXwMd5cpN+9fOmLpQ7r46rJ8V/jCx2ynCn5WaHQrTl//gP74cG
         zNTgXK/OkB6aM7Pt0MigDfB4pw2sEb7503Ic6bzJHbWfCAjtWCHnLEkI7bmO6+34dUN3
         7UZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=1eB/cLd20VDMIOf5D2uQuwyV0kwdvml7t6htObswIuI=;
        b=cLumOQB45neRFdo7yF0ucE/yEpESDfQtr7nzMnDlRoASSZXvt87/4Ip8wCr8zedjXF
         nBxR9OpkOPNUulq7U9XxybG5UTpwqpn7NHpkT4gt1XSxpuG7f3YwBbPnGVmMTf28QOIU
         fYcssQcErJe/ovRFcVcMMZLYx194MPltPUhyFfZtAHFRCMN0IdpAwU7pX2tPfmG6QfLN
         mpZsv5bpw9FeF6uCemXWgVj1hdXwATcpIVLfcQ/iN4LVwu2bu/7YG19ahwLhAf/B+8z+
         tABwJ5ZcCyqkXCNByKQ0VmKgPe3khL4lAVaDaZvHth8lpFXt7sQ8dW5/95Tqx/dn1fdy
         kY4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dcDLFYUo;
       spf=pass (google.com: domain of 3brcrxwokcdq0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3BRCrXwoKCdQ0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id h1si1231wrp.1.2020.11.10.14.11.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:18 -0800 (PST)
Received-SPF: pass (google.com: domain of 3brcrxwokcdq0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id w17so5432417wrp.11
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:18 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:7303:: with SMTP id
 d3mr275192wmb.152.1605046277660; Tue, 10 Nov 2020 14:11:17 -0800 (PST)
Date: Tue, 10 Nov 2020 23:10:02 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <81fbf12c3455448b2bb4162dd9888d405ee0c00a.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 05/44] kasan: shadow declarations only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dcDLFYUo;       spf=pass
 (google.com: domain of 3brcrxwokcdq0d3h4oadlb6ee6b4.2eca0i0d-34l6ee6b46hekfi.2ec@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3BRCrXwoKCdQ0D3H4OADLB6EE6B4.2ECA0I0D-34L6EE6B46HEKFI.2EC@flex--andreyknvl.bounces.google.com;
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

Group shadow-related KASAN function declarations and only define them
for the two existing software modes.

No functional changes for software modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
---
 include/linux/kasan.h | 47 ++++++++++++++++++++++++++++---------------
 1 file changed, 31 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 59538e795df4..26f2ab92e7ca 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -11,7 +11,6 @@ struct task_struct;
 
 #ifdef CONFIG_KASAN
 
-#include <linux/pgtable.h>
 #include <asm/kasan.h>
 
 /* kasan_data struct is used in KUnit tests for KASAN expected failures */
@@ -20,6 +19,20 @@ struct kunit_kasan_expectation {
 	bool report_found;
 };
 
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
+
+#include <linux/pgtable.h>
+
+/* Software KASAN implementations use shadow memory. */
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_INIT 0xFF
+#else
+#define KASAN_SHADOW_INIT 0
+#endif
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
@@ -35,6 +48,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
 		+ KASAN_SHADOW_OFFSET;
 }
 
+int kasan_add_zero_shadow(void *start, unsigned long size);
+void kasan_remove_zero_shadow(void *start, unsigned long size);
+
+#else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+static inline int kasan_add_zero_shadow(void *start, unsigned long size)
+{
+	return 0;
+}
+static inline void kasan_remove_zero_shadow(void *start,
+					unsigned long size)
+{}
+
+#endif /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
+
+#ifdef CONFIG_KASAN
+
 /* Enable reporting bugs after kasan_disable_current() */
 extern void kasan_enable_current(void);
 
@@ -75,9 +105,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-int kasan_add_zero_shadow(void *start, unsigned long size);
-void kasan_remove_zero_shadow(void *start, unsigned long size);
-
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
@@ -143,14 +170,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 	return false;
 }
 
-static inline int kasan_add_zero_shadow(void *start, unsigned long size)
-{
-	return 0;
-}
-static inline void kasan_remove_zero_shadow(void *start,
-					unsigned long size)
-{}
-
 static inline void kasan_unpoison_slab(const void *ptr) { }
 static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
@@ -158,8 +177,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SHADOW_INIT 0
-
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -174,8 +191,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-#define KASAN_SHADOW_INIT 0xFF
-
 void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/81fbf12c3455448b2bb4162dd9888d405ee0c00a.1605046192.git.andreyknvl%40google.com.
