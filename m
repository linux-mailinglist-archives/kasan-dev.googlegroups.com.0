Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7WD3H5QKGQEWMI2IRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id B2CF0280AF0
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:10:55 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id d195sf207052oig.9
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:10:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593854; cv=pass;
        d=google.com; s=arc-20160816;
        b=lJlRLEJgOY1hbH7gAfY8OUV82VWmh+99O18asfzS2aHrGe8Q8aeDBVqVsa48BIhRZ0
         yZhIfm4pfF5lTVQbeD7cDjfxSkmnGfw7a84kpwN+AJto564B0hK3c9zZc+R1XzvO2jq5
         UcsTiokyUF5O5d8QsmDHuDB8W7yQpl+SRn1As8BOsFRQIB0OpDbgiqFP+JsBpaWGjZtM
         CwamysphUXWCgROL39Z78KjRMjvehpShzN/ITSljc4Je2ZiWjNKX2Pf3YagUqAUOka6G
         ZyW6mqcgNHr0VLM4JExd67eoJGHyKhc4RW+kyu+ME2LPMQ0iBjsElYBUhgyjKOCuyWIs
         odvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=McKBvZ4nZhynBz8ikGxcJB3MqCr/4hYLuM9NKfJFXYo=;
        b=LmyhRn9H+RmW6oTOtAKT+8fSCUxkVOf/Z9MzG3KutZDN+AebglR6znJ09NmOP67ng9
         SUcO8PfvTtztcOi6nHC86K8fe5x0gD5IsFxB9botF8lLSLMUzLp8BihkIv0kjbleAybL
         DpCQ319A86oJnMyQV5ktFRUS02hnAMX7lDRDp2DbSW3zUcoHJIOWQ55HXz19xtZa/zSk
         Js5gUiabqG2GqkC6Hq5PKXX/kDO9W/p+e5c0AxUsISRhUWjvs5JfORLH2JyyPWcmQy9C
         SRaNPdFr5K3psTFPClvF9M+W8CshsMhQfJ2hstBybQ2lGo/MC37X+3WeRMVPeOc1Y6Mp
         r1Wg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m1YEkqOP;
       spf=pass (google.com: domain of 3_wf2xwokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3_WF2XwoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=McKBvZ4nZhynBz8ikGxcJB3MqCr/4hYLuM9NKfJFXYo=;
        b=AzMrgmJ/UB/DyAkzBOdcljkdo8TeesO3hXbo14jriwy6ZclxmGH4Gyj8WIZ9IQZzBB
         rJdpGf15wc4BqHyO/ssZqKzE7YtDX8vNFgA9YMVjhoiFeQhA6631NQn8uoIV96UZsoqY
         8LQxcMKnTiP2iGY+IlMwcKeD9C88GA206jI++D/D9+gg0iwl091sip8A2qzauq5TuVwe
         O4HY06pC+k6SU+JkaQ2Ym9STyZ0j97SJ/9IRDLDysjwTtpEpS+oXtyjZUiLkZaddeogY
         QTgoYJfnLDu+QXKY2jQmi386W2sXjbwID3cdFCn8RUT0ovvznBKbcfhUgA8Wxq5K9ztA
         ONQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=McKBvZ4nZhynBz8ikGxcJB3MqCr/4hYLuM9NKfJFXYo=;
        b=jYbZpCPYIkCHLzu4rV00s3AflgLdj19q0+1T+6G4/0l1HIuyymGOFBzOwYvrw86FD+
         bQB6YZOTi3Gn0C7irDa8OGqxT/QufZS2DI+p0vWrAdAz+z5A7rEYGV1lwlsQueN4Mk6H
         DZS+sweXwErs6nMGZriNJNdkIAZ6GszLJJ0od29V9SZZw1Ygu8EXEc1E49jkZoY8Y0q7
         1EOOh95rcCVmP2Rk58uk+hUtqIDkPJ4lVXSY3IbL0nJRgi4DGE3+CH3bFwwYUfQ+jsRm
         vS5RepJfxc0Bp/BK74my43SVR28aNFPkENVedBCr5tu6lkQlFvW1LjiaMIOvAQ7hbC7C
         q74A==
X-Gm-Message-State: AOAM532kdfGkS31Ce9VOkTDf/pOUk6kR9DIh6ke6sSh/pLMkTtDWqH0a
	thihftmMDFbpcgYjiZWiayc=
X-Google-Smtp-Source: ABdhPJyrW35Tjvtyngz8GAKVce8tbfmqBTOdEJvunLaGnO2Pwn4GRMADrV1JwqnnjJGYWtWNpHefbg==
X-Received: by 2002:aca:c6c8:: with SMTP id w191mr1502244oif.24.1601593854656;
        Thu, 01 Oct 2020 16:10:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:40e:: with SMTP id 14ls1818360otc.4.gmail; Thu, 01 Oct
 2020 16:10:54 -0700 (PDT)
X-Received: by 2002:a9d:2274:: with SMTP id o107mr6938639ota.323.1601593854306;
        Thu, 01 Oct 2020 16:10:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593854; cv=none;
        d=google.com; s=arc-20160816;
        b=bhUeZC35RMuK+dPLMiKJcrJLfv/KA/t8vm2qOlbZJqusYpTQO4dNnKmfJozUXO1OSp
         /Wu6wXLzlR2OZ5BJ7bZXQ3Nv6SeYAIk2q0tsChlxV1t8Wglak0juZ71mUv1R122eeRIg
         BBlO6YFk5E1ldh4EKCWv27M2LadLPYGbJhlz8KeTbacBHOwiCoOE58h+AFK4JpC7bnDU
         X/X410rnAaYg/aLRsYHDr2p1CwMWldOg8zmzyq1ghHNJ5mPMeeIuH8Nrwq+4DRwos+un
         U5NI3Las7CQfx0iuglGpEtPYLoIIojrF3VroqQd00FmKsCycHxFmOXmKpMowGdQfBVl7
         dk1g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LrSFyHjUGw2UiTx9NykDJbmC1IL+xpnwwfDCTvI2cF8=;
        b=0M6Hy5XszUzJ49mYFeUJuQTj0qD7/n06qGjpXXFKL70dFXXkqo+XVznHSF8G+UcYKC
         HzVRhc4dfoLwC3adxkRmwoYO/OSVfZzCDdJke0sOk87hhD7PFNqTaXB7vka7z1PgFcBB
         3cf9X8vImCcOJ7Hnov4O6xRNCo083xpfFyQKUTLRzb7mbejo9xikGhYNevazjb798MDL
         S6SoUhRgoTR4Ico2EYQkTj35hFkZAGJh7t/b0D7/w12Ha0FxpXmb6+cb3Gkksh+hwkPa
         LmcP7k7OE7AK9VtdoT4WHio2aHUN3CD99dmQre7bH3Rl1qy/yFmWPWptw4i3cWPFABm0
         K+9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=m1YEkqOP;
       spf=pass (google.com: domain of 3_wf2xwokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3_WF2XwoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id b12si50398ots.3.2020.10.01.16.10.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:10:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_wf2xwokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id y53so99873qth.2
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:10:54 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9e0e:: with SMTP id
 p14mr9650649qve.25.1601593853704; Thu, 01 Oct 2020 16:10:53 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:05 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <443425c7e907f0a3b5bece8e4315cd70b93170c0.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 04/39] kasan: shadow declarations only for software modes
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=m1YEkqOP;       spf=pass
 (google.com: domain of 3_wf2xwokczw6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3_WF2XwoKCZw6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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
 include/linux/kasan.h | 45 ++++++++++++++++++++++++++++---------------
 1 file changed, 29 insertions(+), 16 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bd5b4965a269..1ff2717a8547 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -10,9 +10,20 @@ struct vm_struct;
 struct task_struct;
 
 #ifdef CONFIG_KASAN
+#include <asm/kasan.h>
+#endif
+
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 
 #include <linux/pgtable.h>
-#include <asm/kasan.h>
+
+/* Software KASAN implementations use shadow memory. */
+
+#ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_INIT 0xFF
+#else
+#define KASAN_SHADOW_INIT 0
+#endif
 
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
@@ -29,6 +40,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
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
 
@@ -69,9 +97,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-int kasan_add_zero_shadow(void *start, unsigned long size);
-void kasan_remove_zero_shadow(void *start, unsigned long size);
-
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
@@ -137,14 +162,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
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
 
@@ -152,8 +169,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SHADOW_INIT 0
-
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -168,8 +183,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-#define KASAN_SHADOW_INIT 0xFF
-
 void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/443425c7e907f0a3b5bece8e4315cd70b93170c0.1601593784.git.andreyknvl%40google.com.
