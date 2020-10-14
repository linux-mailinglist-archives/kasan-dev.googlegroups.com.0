Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSGGTX6AKGQEXWBENBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 17E0128E7FD
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 22:44:58 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id z22sf514546qtn.15
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:44:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602708297; cv=pass;
        d=google.com; s=arc-20160816;
        b=lDy2jbJ4ltUJPHWd+ScoWOr55PR0QZVjDD2ufCKjlbGp6H559zfmIy6VQJMJlUHrOQ
         02K93E7TCcCrGtLFcF8rhxp0qGiXkyivPXM9jAfUvF0l1nnr083V3vmRZoH5QlKr2ixa
         L0Mq7RBBAct9u+pKv1M1i2azty5uI52MM8W283JWLhkIrlAUYMHmTtkSMgHX5ilEEXQ/
         0ZVBZ7RLyM5pqUplpF7qCWCT0ZnQjqb24R4ww78YMLsgD3Gs6yiXou/TX34Onoq9Ai85
         2+jkK1JQFhDE4dYI3NegS9H9+kNeJGg2bsENGCc1Kg9IvbmUcZcqcaHRJldhY+fEFmmn
         v7cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=3Lb9v4lLAoKoknhvLXexoQhdRGY3cdq3Ejr3V62whVU=;
        b=Vjgm3PVmKqEG+BOfSdAdTe/UMJdT7c4yICUulT9bjCk7bHyefJVqlVlDDjBfUl80wj
         Ck4Dzng/4HTNki37bZPhz/CseiPcuWkxdrvACIqgwEDYgLcIetIFQyvJeBoBypLFckqM
         g9WMnXZpZyw20DArwrVxYy0ZVqDBZKugwF3Yf43XZxpvCbCZ2dYywLJk6YldbH/4ZFqf
         tFRW1qoRxjLX9rINod4RYw4Y3xuWMju3niPlqWWCFOSaIBC1qGZHtbn0erO+EG8O8Amz
         cqZbGVXgreysumO5TiA13+6O+KnSL7dlzX/oG+fWknzJ5ZoUVYHf4SVayTOrQ6hF9DhI
         eoRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bzlkU+ha;
       spf=pass (google.com: domain of 3sgohxwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3SGOHXwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3Lb9v4lLAoKoknhvLXexoQhdRGY3cdq3Ejr3V62whVU=;
        b=Ssf3gZogniUyEry3gNOWkiD0DL4O+JXJoDnV6bR2ZOBYDXjB9DPGGH5tHLfOCxayxS
         Y84MYuBUPyCjE0pwLSFh4hJH30JnUDAc48YUK7P7nPFNwrx/N0X1g+G44WrVbixW0r86
         xpQ/7+3T+n64fpWx6wRD3tU+RFS95xT449K/GZ3Ain8cM/YPQaXzXYh8LWf72WQ+Cfud
         5XVhdmQ2a1E/Vs4CGUz3wDv/c6slM6hDyQoGgjWwi7cl7cSyQMsHXI6gl6wWuTC8l055
         OhvGYos+HQxz90YdzBneHk4O+rRV46E4JX9vSheUvhL+cPpYNWv863QHans4XEzyZqew
         i6MA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Lb9v4lLAoKoknhvLXexoQhdRGY3cdq3Ejr3V62whVU=;
        b=lKD0OwfrQMMkLXPJUFM9w8iMQE4JSLHh1n87G/oQq9OhDql27+AknNE6T1N9FN4LEr
         G6zJNVIUXSW25NW0HcbJItrtDhfEWkSpOQhgfMUy0GReIzdaBnYrFS87i2NQgJyXArav
         LFB8gWQr5BSs3nxtkYzCqkhCqgSlAuUYQ5oZPVtNictpujROLhyhwqloGS+FipoHzxnV
         DgRn7ceLqNwZN8aNWiGrWihO0Nipl2HJrYaxOWME8IqHBy0zL5JDZb9keDAy9WsqwoHj
         n2Tm5IOfyWE7DH2gD/DaLv7L9006YB8bpbKJhxhwG78QynKqC6W46Obbg0gV8iIVQb9V
         oW5Q==
X-Gm-Message-State: AOAM533Rs5I52mHQxT5X7d8FMuMRo3TRqDlM2FWpmC28qOGBkcDuhP2y
	b2Vb5ZvefGBVrk5uB5UBVdQ=
X-Google-Smtp-Source: ABdhPJyVRLxvS3ZExWnfaakgfsWIXDbqg+e+TtHMHg/TCZtIY4AvCfj35/23zZY9M+B3q6dDZnJU+g==
X-Received: by 2002:a05:620a:849:: with SMTP id u9mr864618qku.419.1602708296867;
        Wed, 14 Oct 2020 13:44:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9b89:: with SMTP id d131ls192953qke.2.gmail; Wed, 14 Oct
 2020 13:44:56 -0700 (PDT)
X-Received: by 2002:a05:620a:1024:: with SMTP id a4mr926971qkk.390.1602708296446;
        Wed, 14 Oct 2020 13:44:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602708296; cv=none;
        d=google.com; s=arc-20160816;
        b=lM1Srl2hBcr3SmsmZ+8AHOFkowYMRJ99CYetj0bwxlqx1vyyvOz6n3RgBMG7IpiPRT
         0X9jA7UMucDwJApq0alveRCfgLolglQQ0i/QCL6Zm/vbpf/iTRNzDKqFRzdoO61lnnL0
         wMsIttYLyjjy7Uw7jqFqB7Nk92wc7wSn7jKZxfgTLdapvOboFVg/FtCBmFUsglLk1d/3
         C9E8GfGfX2vGGVLSW5vIgq4y8KyYNpZ7iU+daZ9CKParSZZz6DzXZJIpYUg9OTRBn8iu
         wUq1E5z7NWPTo4vtUWX7Lw2k/Qddx611nRRTAR54kM0ss7aoQGjEdcTgL5Uj8YjVu4vh
         9n8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=qyL7M+3Aw1Hsa4EXSDAwQDJZSRSVnrXpMPSsUVjsP1o=;
        b=TlDHFfzALTS/hyvnTpbX91lPboLBGuDMfw2+54ugRKhzssie/nz83shVKV6B1hqcka
         /W4iH7/r44wAoz0s0l2sJhIBQFI4R9t3e7QHSHVMMU4QqV5LC/u2RGckah8cplt8WSyc
         He4mQSOYgfwuv6Vpg3J8Q8/JcM64q6rmDz4CiTYBKnwOZCkVH42ug1piLPv9G4TChYI9
         FMyeiMEdWFbpOwAy2uliCu2oBoa8v+1VMb1ZgvVQkB/2TjLCsEfYLbYLnkzBL/nR0NOd
         M/IVWzHf/MF7MAk/gYHWDjCbH5fYJaVRrA/qHZvZeRwqZOMFu4TWvjcvfQNYIW6oVqh5
         uupQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bzlkU+ha;
       spf=pass (google.com: domain of 3sgohxwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3SGOHXwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id r40si21536qte.5.2020.10.14.13.44.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 13:44:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3sgohxwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id s8so290523qvv.18
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 13:44:56 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5547:: with SMTP id
 v7mr1394691qvy.9.1602708296087; Wed, 14 Oct 2020 13:44:56 -0700 (PDT)
Date: Wed, 14 Oct 2020 22:44:33 +0200
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
Message-Id: <8fe7b641027ea3151bc84e0d7c81d2d8104d50d7.1602708025.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH RFC 5/8] kasan: mark kasan_init_tags as __init
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bzlkU+ha;       spf=pass
 (google.com: domain of 3sgohxwokcs8lyocpjvygwrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3SGOHXwoKCS8LYOcPjVYgWRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--andreyknvl.bounces.google.com;
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

Similarly to kasan_init() mark kasan_init_tags() as __init.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I8792e22f1ca5a703c5e979969147968a99312558
---
 include/linux/kasan.h | 4 ++--
 mm/kasan/hw_tags.c    | 2 +-
 mm/kasan/sw_tags.c    | 2 +-
 3 files changed, 4 insertions(+), 4 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 7be9fb9146ac..af8317b416a8 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -185,7 +185,7 @@ static inline void kasan_record_aux_stack(void *ptr) {}
 
 #if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
 
-void kasan_init_tags(void);
+void __init kasan_init_tags(void);
 
 void *kasan_reset_tag(const void *addr);
 
@@ -194,7 +194,7 @@ bool kasan_report(unsigned long addr, size_t size,
 
 #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
 
-static inline void kasan_init_tags(void) { }
+static inline void __init kasan_init_tags(void) { }
 
 static inline void *kasan_reset_tag(const void *addr)
 {
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 2a38885014e3..0128062320d5 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -15,7 +15,7 @@
 
 #include "kasan.h"
 
-void kasan_init_tags(void)
+void __init kasan_init_tags(void)
 {
 	init_tags(KASAN_TAG_MAX);
 }
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index c10863a45775..bf1422282bb5 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -35,7 +35,7 @@
 
 static DEFINE_PER_CPU(u32, prng_state);
 
-void kasan_init_tags(void)
+void __init kasan_init_tags(void)
 {
 	int cpu;
 
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8fe7b641027ea3151bc84e0d7c81d2d8104d50d7.1602708025.git.andreyknvl%40google.com.
