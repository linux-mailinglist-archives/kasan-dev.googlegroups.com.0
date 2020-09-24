Return-Path: <kasan-dev+bncBDX4HWEMTEBRBVWFWT5QKGQEOPP2D6A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 55150277BC2
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:51:03 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id i9sf322182ljc.12
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:51:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987863; cv=pass;
        d=google.com; s=arc-20160816;
        b=rgzeyfXq7DCWpkDuerqN6EjV3e/XRQy0Av9FbwS3HXPwv6JYeDoI8flCa/dEA/VMn1
         mo1mBCWf/lz0f4uZQqCzSQ2YW3C1ZcpGn//jqTVGslLK0MnNGdkwBeGyfFeFI0GujmrL
         AxtZn3oiXVzAzb/51XkAunF+rOHegfcMqhYRTCxYf825Tl9InyyOqN2zS9xuun7HJONE
         fPkEx8wUjuVAneRzX2hkWHcZiNggffC3rYt5TIIX0tlWwYk22ry5BYV62vOvLRSn2XYa
         zQ+sqYkzlWiIZAevbPHIfZk/oBdF3LLCz/YXUtTyNVYOvig9lyKbmcBr87nxSQ4BuYRq
         ggRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=U/UOUmZclnUvX4L2/vsaUfHW72qiP3brGXEuHhbQVq0=;
        b=LbqcmmsSeMOmcGmKvMQbye1MEXeJW29C0lsuH7lNYozaDNCvvX7HsNJEBk1L0DOusV
         f4MYkRnjRk369cf6pbncwcyqFZBY5f7HkypitqWe8M25ff0NGL9DFUFXn+7pCT98QpqL
         aKdnWjnX50JhciR6E4upaLY3RZOnh5i0VhR01/fatkqXDdp7LFRqBkyClwEN4Axbsycu
         rO2iCV2l+bhKKA2b/AD7IG1SM2GNZhB0F+o/+jFDeTBoWopCX8otDbmnXS/a17RAI2jR
         KVTFMSiVXF/SGisO9bkhO8WDxn+ug1cvXB5MM3axvWHqNfHPna5hhqIadW8SoEoLlm4e
         wgRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kXKqNW8E;
       spf=pass (google.com: domain of 31sjtxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=31SJtXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=U/UOUmZclnUvX4L2/vsaUfHW72qiP3brGXEuHhbQVq0=;
        b=WxooAaDbq1AR5CS5SWY3g57FpHchc9k33Vy1xU838dHGHR5PINJf9rur1krJ8QF153
         Uk/lUlOjR0NL2B5XPnJDJbfhO6YFpAEAo8dq5REBrW8sFE6q29+qsaoQ3wIp3yNcYPoi
         UXfijXKyFAxN7NCon5GIMWOaF2tJxPU547cFMo4FdtuxarBcNwo6fs2zsNMOInKSjRTi
         jGc+jbDDJhfGQjGsqOvX9evRicoix1PJOcJpk/SjE0OoPN1BNHUhPC+yGAbYGwMochVA
         PslLMGDNn7SWQr8yB40ISb8BSsE2igRfFVigAiTov+SttYCtAgsOCrU/TunUjyMuR4aO
         eHpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U/UOUmZclnUvX4L2/vsaUfHW72qiP3brGXEuHhbQVq0=;
        b=RQRHHEAlRMPCCbr8061cbTIrLZxDgtaMo/DbYNvyHBfJ9UUy8FM+s2GG6tXOPUFnWp
         Jri7xQrSjnvkQ1y9QaypMsSABxQhG8C/KqI1qkDW49DFqlDV0O/reWOJLF4EbCfFmG2g
         V/ZfXan5brr0XGkA1cQ2WxbtFoaaSWtnH4S3z77RuWIqiOg1dHj1r//85KIqpNhDIqLc
         k6f9QZw6MUsqhYon7Efvx7eRLtQfws57RtWdjnAPwjIL07DFSY9cXz4h2fqdLi6zusBt
         SHkryfmvIvj9wxkbNivtU6QFowR3Bi+ZE27S2PFKcBfPnsCy2JwE9ntlKhkyqz1t+ylr
         +NfA==
X-Gm-Message-State: AOAM533WNEYKrx3d991jrLu+OnLJg7N8Px0uYgntnKEcM3+T9YlVSfJT
	nyseouds08gZKkTD1GIhx98=
X-Google-Smtp-Source: ABdhPJy32UQEE0RTboWrvvBmD7dm6ZWrUyDp3fnDeTHVhBxMF6i4DSYtxKP3ayusVwGBsdzqMl8U8w==
X-Received: by 2002:a2e:964b:: with SMTP id z11mr417973ljh.364.1600987862870;
        Thu, 24 Sep 2020 15:51:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:554:: with SMTP id 81ls253241lff.1.gmail; Thu, 24 Sep
 2020 15:51:01 -0700 (PDT)
X-Received: by 2002:a05:6512:110a:: with SMTP id l10mr378942lfg.552.1600987861877;
        Thu, 24 Sep 2020 15:51:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987861; cv=none;
        d=google.com; s=arc-20160816;
        b=DIbHYPR8Mk/qXN5aGRdvBRYeYwQiROvF7IJJm7nfQm5i7i1JxiXXwNZpdCwTJzKZEO
         zzZcbri727WD8pLVeZTf7+iFmlIKksKAsptotXmB6oRiaBS3XNWB56iXy7Fmpd66bBna
         wonaJXUAhbW/V3kiSyvXz4OWdpk4sPEMdmWLBQA+zC0EFWV32pyD2D9Gqtd7CQLB9Gxi
         mWYVfesnU38bIR1vQvLOCdg9Pterje6D05fHReo6fBTD2KCBzWxKvsI6ZBq0K1ybgmJ4
         bwFwN5DpNcblNeERF6hhlSA8Tvfde2aWYGZZAakxWchMngndWrx1B7ybw+RbIH9GwJJ/
         nDKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=o+5muahIyzBsCSQYTa2yEzLZS8Az5j3CfnIGZXwP7nI=;
        b=JXeAmQe1t24eQNQNR0Wr4AHbsHvcvvINGUUiNkDIe/yA95gyL7+Qdj/PSbq075TdDC
         JkDKuwLc0qQKyGQVPVRZSxuEAv95C8juk4ngnk/Go9Xakbj758Vx8yUJOyf1+GFaDuas
         DOIzVgmrBhu43e+rQfl8xF1zZr3PejGZrkJLpWjsX37br8XWsW2gOagUWO6n+Gny/2KY
         W/0M3Fzi1DhCClTY6d8IyWUfB3ujHKCDkYESwlfaQmGGBcl52R6pIKuoQmE+0hvu1VQi
         7ytmxXFKtC0zKXisT3aIWU3uuUdtuNgvx1M/1cMaFon2KTOYmwhbXI6wZJXeMjShJdtW
         6sOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kXKqNW8E;
       spf=pass (google.com: domain of 31sjtxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=31SJtXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id q20si19316lji.2.2020.09.24.15.51.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:51:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31sjtxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id l17so286095wrw.11
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:51:01 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:750d:: with SMTP id
 o13mr918934wmc.54.1600987861205; Thu, 24 Sep 2020 15:51:01 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:11 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <9de4c3b360444c66fcf454e0880fc655c5d80395.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 04/39] kasan: shadow declarations only for software modes
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
 header.i=@google.com header.s=20161025 header.b=kXKqNW8E;       spf=pass
 (google.com: domain of 31sjtxwokcdaw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=31SJtXwoKCdAw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I864be75a88b91b443c55e9c2042865e15703e164
---
 include/linux/kasan.h | 44 ++++++++++++++++++++++++++-----------------
 1 file changed, 27 insertions(+), 17 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index bd5b4965a269..44a9aae44138 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -3,16 +3,24 @@
 #define _LINUX_KASAN_H
 
 #include <linux/types.h>
+#include <asm/kasan.h>
 
 struct kmem_cache;
 struct page;
 struct vm_struct;
 struct task_struct;
 
-#ifdef CONFIG_KASAN
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
@@ -29,6 +37,23 @@ static inline void *kasan_mem_to_shadow(const void *addr)
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
 
@@ -69,9 +94,6 @@ struct kasan_cache {
 	int free_meta_offset;
 };
 
-int kasan_add_zero_shadow(void *start, unsigned long size);
-void kasan_remove_zero_shadow(void *start, unsigned long size);
-
 size_t __ksize(const void *);
 static inline void kasan_unpoison_slab(const void *ptr)
 {
@@ -137,14 +159,6 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
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
 
@@ -152,8 +166,6 @@ static inline size_t kasan_metadata_size(struct kmem_cache *cache) { return 0; }
 
 #ifdef CONFIG_KASAN_GENERIC
 
-#define KASAN_SHADOW_INIT 0
-
 void kasan_cache_shrink(struct kmem_cache *cache);
 void kasan_cache_shutdown(struct kmem_cache *cache);
 void kasan_record_aux_stack(void *ptr);
@@ -168,8 +180,6 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #ifdef CONFIG_KASAN_SW_TAGS
 
-#define KASAN_SHADOW_INIT 0xFF
-
 void kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9de4c3b360444c66fcf454e0880fc655c5d80395.1600987622.git.andreyknvl%40google.com.
