Return-Path: <kasan-dev+bncBDX4HWEMTEBRBSUD5P2QKGQE65Z5FEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id BDBE11CF93D
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 17:33:31 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id p15sf14092462qkk.15
        for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 08:33:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589297610; cv=pass;
        d=google.com; s=arc-20160816;
        b=iGmsm01/+zZloyY7hunj0FvMybQ3zTOLVWBiCfG2q1Wob611bRGgHCRY1GYv8p7uWJ
         WrpQm+UmNmavPDzR9Dvw64Dyc4aI/uMqiWEKpXw+AIg9HRIl6v84aEfgJObbe0y4usdP
         hxhid5oRplr4BDva28J6pOxqMqSDz12mdPeXrc+D3rsKnVNS1/07VLaquTUWf7GBmNIv
         a/YZck8cypZGw0dFApIILOJ/+cIRKkCr61IE1aLhFyF5jNIa2GsMbqJwB/u7WGlIpCIY
         iw8rSOW3LPPTuOlCvPzoYQ7Af9zuw9q76052+BvlqEyDxH9a/04yIbYMRBasp073tWTp
         fLNw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=rUxchAEDjkrRreFSmxE0da0Ne0yQVB7kCofZECM9PV4=;
        b=OqjQTdp5Jnz+MsrbwBZlcxZFezc0a61vrfKpHmGL4DF5JhtH4Rl4d+WjItQyTt/D2V
         +LuxoOzZ4PI5i4izu7LjVVvvX10QaQ9r7YF2SnQqsL5fwS4StCAgP+TMPgB8RE/ExqST
         tgvU/BFlksHL0LTUMYEAul61/pe6pegGcYeq9funRwFlsypXU5Gd/Zi8N+x9wLssmYJJ
         ggFYV4tawrS/0V9G80gN/pTyWVSfDmePKPBvKicydwar9dtDg4EAVDRjvGoPyyBqq3Zn
         ce3Pdy8eSQErBh9HPmH42yC2hd2dxsErp5EGZa0ETtFBkB5soUWDAjw1UEEZqHU++aEV
         o24Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OiYty1LL;
       spf=pass (google.com: domain of 3ycg6xgokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ycG6XgoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rUxchAEDjkrRreFSmxE0da0Ne0yQVB7kCofZECM9PV4=;
        b=KbGZgMGdT6sLqtSgmqcOvyHdjps4gTZOFwrIcHWUKZsIuRNP1J8glKAs5jnBIkK4yK
         uhQluSoaV0cEuPxbnP50TnxvxUHVd3ic6ipKsp5RzOT59On5L4dnBuYNiolGNim2CI+1
         nYJCSv/FhCwCYM0gaetKh9ZuFrxS01vcmsrR4pkGpfyQyiSJKsv5yU9hkF1YqyE1a08j
         cXCKKiQ8G88N6SgLaVXUKsLQlZVzDg4Dj0yEwG26zA2p8wwdKrBWoCBCsEh6l0l9rUfN
         RWr5cXU1VXqs9qSObMXu9OqxZes0Q2W07w1LXdeaxIlOT1ozZ1a6lFoKOCuUVczJQhgM
         YdlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rUxchAEDjkrRreFSmxE0da0Ne0yQVB7kCofZECM9PV4=;
        b=L1vjzD59T6WsAJFOQM2u9ryExJw/EVfvRxruSF37gostisvufzKtmiHzL+UBH3l/PB
         TjdKNtQydi3rL2foRcE4WebeO1GR/o7cBHzvW66UdAZOj25CZqlgxW+59Bu1uGKvTJQP
         c9em107wreUiTyy78X+eFWTWGRg0NsAloA9l4lOpB/msmwKZ33sOIPeKAoED5QxP6xnv
         T901q8q7PjoQPF8x/+awArGjmGCxWiE0DuXbYAzb428yDG3U5WMvJxFYBtR9SjSVRO1q
         5KJ+rYV1fMmHBikQjszoV9U6ym7CgS5fjWJEUvG2XXAO0DlVKWG/E8YOH/FLQmltz4tI
         VESw==
X-Gm-Message-State: AGi0PuaVl8gRr2WPhIqoWsG0qB3fbmSXUokLThjCsh2eSAbtkorT87N3
	REgCPSk9ei+ONRLKngi272E=
X-Google-Smtp-Source: APiQypIJwgjqCsr3qM4WClMSbkwx5crQAPz+ljHU9oBsJTj9EWKZww/usfbbFqGRo8DdIjcFCnzo1g==
X-Received: by 2002:a37:c08:: with SMTP id 8mr21364188qkm.47.1589297610680;
        Tue, 12 May 2020 08:33:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:24dd:: with SMTP id u29ls6138690qtc.3.gmail; Tue, 12 May
 2020 08:33:30 -0700 (PDT)
X-Received: by 2002:aed:3907:: with SMTP id l7mr20988167qte.198.1589297610006;
        Tue, 12 May 2020 08:33:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589297610; cv=none;
        d=google.com; s=arc-20160816;
        b=0Ak49Y3n+AC442s+rCZcZDEl7SChphfnj0trt2J9P5S2uEDsjRChHKg08DepKlslCz
         U3ZeYRhQeZ6Fj/PCRTjwbBnGvBWINWZMLvbyReucM4emGZmIyBNoh7lk3+0rs51osr8+
         t6XnkcQzxjm+jvAzYw/+9/Hyn59o6AqpE1W2z6jLjyRZf/RV/vAluUNPqSrB7PJKWwWx
         OU+2GvhheXjvt7eFjtEVYDBpueungvkx7n1L4OH5P/sVxdHKPk1xW5nlWlio36url4g/
         Ih96HHoyEZUj9mIYIsWrckxUhvw7Rs08CZieQzuA2+dGnzSsg/U/grLIb95lv/jO7Fzr
         YJOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=A/fbgfde0XyUO2F69Y6u/rjH6iJE5L1jOqri/XRSNJ0=;
        b=Temsk46e980LS9yVdoy86XpFRFxE8/htK4PYVawKt6yvo1Doufb+cICKNvDDbNvps6
         CfGwzuy8g/wHJSIYQHzIhTu2PX/g/SZfwXcr5yllhIhvH17MXaH0cQ1Wp781zCorIvZj
         o/Chx2cOpQGwsRPc/mZDXI40xmH0vYjX+dinGA1+JwFktJLt8cd9EsK5a5UNda5XUkh1
         M1L7Z4htvvAa+dn73U+kSwuIt+bwBxkvRpWn9ZoL9FEfjctPO3F/tWw7m/+ettjujt67
         HHP8todUqGYTykYH1keyAysNnoqBkE0eL3osz+NNY70tZX0yIf/w65Sl85jI67fIJKvX
         YA4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=OiYty1LL;
       spf=pass (google.com: domain of 3ycg6xgokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ycG6XgoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id q4si611993qtn.5.2020.05.12.08.33.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 May 2020 08:33:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ycg6xgokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id f56so14476243qte.18
        for <kasan-dev@googlegroups.com>; Tue, 12 May 2020 08:33:29 -0700 (PDT)
X-Received: by 2002:a05:6214:1812:: with SMTP id o18mr21635775qvw.64.1589297609674;
 Tue, 12 May 2020 08:33:29 -0700 (PDT)
Date: Tue, 12 May 2020 17:33:21 +0200
In-Reply-To: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
Message-Id: <45b445a76a79208918f0cc44bfabebaea909b54d.1589297433.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <29bd753d5ff5596425905b0b07f51153e2345cc1.1589297433.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.26.2.645.ge9eca65c58-goog
Subject: [PATCH 3/3] kasan: add missing functions declarations to kasan.h
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Leon Romanovsky <leonro@mellanox.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Leon Romanovsky <leon@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=OiYty1LL;       spf=pass
 (google.com: domain of 3ycg6xgokctqqdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3ycG6XgoKCTQQdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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

KASAN is currently missing declarations for __asan_report* and
__hwasan* functions. This can lead to compiler warnings.

Reported-by: Leon Romanovsky <leon@kernel.org>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 34 ++++++++++++++++++++++++++++++++--
 1 file changed, 32 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e8f37199d885..cfade6413528 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -212,8 +212,6 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 asmlinkage void kasan_unpoison_task_stack_below(const void *watermark);
 void __asan_register_globals(struct kasan_global *globals, size_t size);
 void __asan_unregister_globals(struct kasan_global *globals, size_t size);
-void __asan_loadN(unsigned long addr, size_t size);
-void __asan_storeN(unsigned long addr, size_t size);
 void __asan_handle_no_return(void);
 void __asan_alloca_poison(unsigned long addr, size_t size);
 void __asan_allocas_unpoison(const void *stack_top, const void *stack_bottom);
@@ -228,6 +226,8 @@ void __asan_load8(unsigned long addr);
 void __asan_store8(unsigned long addr);
 void __asan_load16(unsigned long addr);
 void __asan_store16(unsigned long addr);
+void __asan_loadN(unsigned long addr, size_t size);
+void __asan_storeN(unsigned long addr, size_t size);
 
 void __asan_load1_noabort(unsigned long addr);
 void __asan_store1_noabort(unsigned long addr);
@@ -239,6 +239,21 @@ void __asan_load8_noabort(unsigned long addr);
 void __asan_store8_noabort(unsigned long addr);
 void __asan_load16_noabort(unsigned long addr);
 void __asan_store16_noabort(unsigned long addr);
+void __asan_loadN_noabort(unsigned long addr, size_t size);
+void __asan_storeN_noabort(unsigned long addr, size_t size);
+
+void __asan_report_load1_noabort(unsigned long addr);
+void __asan_report_store1_noabort(unsigned long addr);
+void __asan_report_load2_noabort(unsigned long addr);
+void __asan_report_store2_noabort(unsigned long addr);
+void __asan_report_load4_noabort(unsigned long addr);
+void __asan_report_store4_noabort(unsigned long addr);
+void __asan_report_load8_noabort(unsigned long addr);
+void __asan_report_store8_noabort(unsigned long addr);
+void __asan_report_load16_noabort(unsigned long addr);
+void __asan_report_store16_noabort(unsigned long addr);
+void __asan_report_load_n_noabort(unsigned long addr, size_t size);
+void __asan_report_store_n_noabort(unsigned long addr, size_t size);
 
 void __asan_set_shadow_00(const void *addr, size_t size);
 void __asan_set_shadow_f1(const void *addr, size_t size);
@@ -247,4 +262,19 @@ void __asan_set_shadow_f3(const void *addr, size_t size);
 void __asan_set_shadow_f5(const void *addr, size_t size);
 void __asan_set_shadow_f8(const void *addr, size_t size);
 
+void __hwasan_load1_noabort(unsigned long addr);
+void __hwasan_store1_noabort(unsigned long addr);
+void __hwasan_load2_noabort(unsigned long addr);
+void __hwasan_store2_noabort(unsigned long addr);
+void __hwasan_load4_noabort(unsigned long addr);
+void __hwasan_store4_noabort(unsigned long addr);
+void __hwasan_load8_noabort(unsigned long addr);
+void __hwasan_store8_noabort(unsigned long addr);
+void __hwasan_load16_noabort(unsigned long addr);
+void __hwasan_store16_noabort(unsigned long addr);
+void __hwasan_loadN_noabort(unsigned long addr, size_t size);
+void __hwasan_storeN_noabort(unsigned long addr, size_t size);
+
+void __hwasan_tag_memory(unsigned long addr, u8 tag, unsigned long size);
+
 #endif
-- 
2.26.2.645.ge9eca65c58-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/45b445a76a79208918f0cc44bfabebaea909b54d.1589297433.git.andreyknvl%40google.com.
