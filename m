Return-Path: <kasan-dev+bncBC7OBJGL2MHBBF4K5SDAMGQEI6RDSII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id EF3DA3B7157
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jun 2021 13:33:43 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id b15-20020a2e988f0000b029017a27402ce9sf2316714ljj.5
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jun 2021 04:33:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624966423; cv=pass;
        d=google.com; s=arc-20160816;
        b=YI+VPg29/6oiP2N3LEHtO8VkygfmlejI2bVLEnnLugcKX76eqrAzg9AtfcfoiQEf4O
         rLJmueZ1rp120WL0hEkA6enYcAwAvnmSK1VViWfoKqQRUg9UYNarBv+yCbIP9IQX0ruN
         7gpF6sfTIBMMdBtVLPwXq6VTpQ+hYris6eHHAwvPO/lyb+0uGoszCS6eHhiG887hPeSz
         eKteeUAPnx25FgnyTwSKMXeoZyVT2DQZ7iGDCalM/VApz6twuGsgpPsWH4TdKVO1EKPu
         9J5l/AAm0yP/ix5MlhO79UeBp4gq8SkfooNQky6nk0EeraDGDkRK4uf9fbGokfdM21+3
         WVgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=3HQWdCTTLQP6p7y7Fsj9m3mwPaHOPh6Vusa6BSlT7VI=;
        b=KRipY9NTenoTYxzG5H2K8rIjQenatHPHq5Qt+1LFnqZdz3nkOluUsPolrrYrM1krE4
         trNOxNuoX5/0uimjhmcydChi+62QcoutrDGsMdUFara3LfoD7otVRmR97Put7VD68ZIT
         UvqVMSfrGBG5cXVNYYyb8um06TJDpmvmd04JhHTlVYMORHHn/lFlKPZcQvePDYeWgcQD
         AQX5K0U0RytusWaZ4nyfGuY7ibrbEjTzTpPOO4SM2xjRQiUVvW4iK24MnG8HD9dN5008
         0Yh7TKSMDOlI2yJBSz111iHsrfq9R2rk8XSooHsHunZr4Xqxrd1njp54lpiydluTS8QD
         98Iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ED88Uury;
       spf=pass (google.com: domain of 3fqxbyaukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3FQXbYAUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3HQWdCTTLQP6p7y7Fsj9m3mwPaHOPh6Vusa6BSlT7VI=;
        b=kGjNjNNqmYZX0q239meWUxB5Ak0lho2UaZD2Gb3kpBMIfwZ0OPd6ao8RMK+P+yTf5D
         L5mQAKTEP1VBsZat1PU1SuXG3b4NnryBUid8MZAOGhxLwx64UJcoPizfY5ar2UySAvMB
         FwhVUgWN+Nx0Drj4cO+G2lJwrczixrU5Ndfu9EU7VCzl2Oq4WgJOjYfWQEuBv4wGJ+O+
         mgFAyGiiyqTzEtDkIEhAMDrsQA/Vgbt5Nu5opRSG4Uh1//I6dm8FoApNWU5ISKBgM2tf
         nsxg6nbO+wbXrHjuqhZCOOaKDClQLfSLkXvNXEpkG7ozei6fdDnjOEAX/ag8En1OHSvV
         obJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3HQWdCTTLQP6p7y7Fsj9m3mwPaHOPh6Vusa6BSlT7VI=;
        b=WIG8fd47rM71AmsXRa3DFgxj1y3kOJC24rhn0SKOaP6sx96WaZcFKOy3/qtu/1dzBs
         NQ2s3FKGnbSx5MdaPmD6/yl/c+wdFXF2obNHhs1QqAWDFtvLLagXwFPlazSCheYI2VPu
         gWeZD+OleS/zFQwkYq0s5/qeP/CMYve65zetPnYvZ99eRMBjHCTqTlLX9fBJwFXuLbps
         oq5nfmcOAZXsbNzEI/UmPssxM0aSdS2NiZ7JRctiVd6RN3yjqpUvwCUFT+DcAI9mgvNa
         dCglM9G/ZsQVXrUYW/xxgL1QASj0C1fqEU4VyaXN2L3OnwxvG/8Y6gRElqKcZCb1oS8c
         vDVA==
X-Gm-Message-State: AOAM530CXrXWCSZ9GuBgfxeRN4J9d58mTDEa642u7lwwXJTpYwOlrR1m
	4/0WrThMIwDRaUG/waJbWNw=
X-Google-Smtp-Source: ABdhPJy4rNZ74SzJ6L11RQKIB1nuoqm1+1H7zsu54IN4ALF8wv0c7MbCU1FIRP9E7SSzG2k1KSgveQ==
X-Received: by 2002:ac2:54a4:: with SMTP id w4mr22623345lfk.518.1624966423311;
        Tue, 29 Jun 2021 04:33:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:508b:: with SMTP id f11ls1952989lfm.2.gmail; Tue, 29 Jun
 2021 04:33:42 -0700 (PDT)
X-Received: by 2002:a05:6512:44b:: with SMTP id y11mr22786874lfk.84.1624966422132;
        Tue, 29 Jun 2021 04:33:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624966422; cv=none;
        d=google.com; s=arc-20160816;
        b=w2gh+Euj3F036ny2+ROklZoTduGEpbbcE25yYd3VTUJ/uTUo95q/LET/91xwmC8ZwZ
         /O4NqpvRV3h/HJEMqAwxcQyEHuwsai2XH398n3Sjz5CwB0/jlJCHyQhKodiZVTsG9x16
         qFtfoa5IGMTlX2Fuovg6HT5LRZDuNVP0lqTmgOtc3v/mFCTHAmhb8ig2jtEQJmsCY2mp
         9sM3NjxNpdF9L2IF3+rb6fcSv7qXsP2FKGO77YXqDplejGpDOm/VSnFIZ7c7N/PE0P1i
         O56k87OPSQGiPioh+UIBCCypm4pP3k7z3cvOd+iiBWzvCk8l9/l/c4M6AEtDzdReajuv
         PIwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=Z9L5cfcK7pl5yBJJm5vz6LAfMKO1p/6M+h4xx7hIK+4=;
        b=g5jGAkmOwk1rXzVQj3BHBjaW2LGEw71b5sOSLueI7c6A56P+n6r9NtrM9euSEfTQYD
         NNBV+TE4iLFMo8xtsOtTKaLncAOL8RIbNCy1lrVqXU6zDX9Gufr7GP/TWa/gaXvPZjwd
         RQra3x7v1B8et+HRFj2nqJF3qFE1hlVgW/WEXLfHIJxXVQzVIZ51GgFU2+FMWExajOLK
         CUoQYwohCZmFpv7CqNmgoh8gMxGVJsKhkkJAmVrsllcrC+Tq35Ot2JSNJXSTBK86wAZd
         Xssaj+5e2ToEOSxVBy2ulJg8ZERx3/wh88YbDntzRukhVHsFLjq4QeKSyMu7Kz9ylo2B
         i7tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ED88Uury;
       spf=pass (google.com: domain of 3fqxbyaukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3FQXbYAUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id z16si750165lfq.13.2021.06.29.04.33.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jun 2021 04:33:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3fqxbyaukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id ho42-20020a1709070eaab02904a77ea3380eso5593958ejc.4
        for <kasan-dev@googlegroups.com>; Tue, 29 Jun 2021 04:33:42 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:6136:a356:cc5c:f9ac])
 (user=elver job=sendgmr) by 2002:a50:ff01:: with SMTP id a1mr39190604edu.253.1624966421205;
 Tue, 29 Jun 2021 04:33:41 -0700 (PDT)
Date: Tue, 29 Jun 2021 13:33:23 +0200
Message-Id: <20210629113323.2354571-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH] kfence: show cpu and timestamp in alloc/free info
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, linux-doc@vger.kernel.org, 
	Joern Engel <joern@purestorage.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ED88Uury;       spf=pass
 (google.com: domain of 3fqxbyaukczg6dn6j8gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3FQXbYAUKCZg6DN6J8GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Record cpu and timestamp on allocations and frees, and show them in
reports. Upon an error, this can help correlate earlier messages in the
kernel log via allocation and free timestamps.

Suggested-by: Joern Engel <joern@purestorage.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kfence.rst | 98 ++++++++++++++++--------------
 mm/kfence/core.c                   |  3 +
 mm/kfence/kfence.h                 |  2 +
 mm/kfence/report.c                 | 19 ++++--
 4 files changed, 71 insertions(+), 51 deletions(-)

diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
index fdf04e741ea5..0fbe3308bf37 100644
--- a/Documentation/dev-tools/kfence.rst
+++ b/Documentation/dev-tools/kfence.rst
@@ -65,25 +65,27 @@ Error reports
 A typical out-of-bounds access looks like this::
 
     ==================================================================
-    BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa3/0x22b
+    BUG: KFENCE: out-of-bounds read in test_out_of_bounds_read+0xa6/0x234
 
-    Out-of-bounds read at 0xffffffffb672efff (1B left of kfence-#17):
-     test_out_of_bounds_read+0xa3/0x22b
-     kunit_try_run_case+0x51/0x85
+    Out-of-bounds read at 0xffff8c3f2e291fff (1B left of kfence-#72):
+     test_out_of_bounds_read+0xa6/0x234
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    kfence-#17 [0xffffffffb672f000-0xffffffffb672f01f, size=32, cache=kmalloc-32] allocated by task 507:
-     test_alloc+0xf3/0x25b
-     test_out_of_bounds_read+0x98/0x22b
-     kunit_try_run_case+0x51/0x85
+    kfence-#72: 0xffff8c3f2e292000-0xffff8c3f2e29201f, size=32, cache=kmalloc-32
+
+    allocated by task 484 on cpu 0 at 32.919330s:
+     test_alloc+0xfe/0x738
+     test_out_of_bounds_read+0x9b/0x234
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    CPU: 4 PID: 107 Comm: kunit_try_catch Not tainted 5.8.0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    CPU: 0 PID: 484 Comm: kunit_try_catch Not tainted 5.13.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 The header of the report provides a short summary of the function involved in
@@ -96,30 +98,32 @@ Use-after-free accesses are reported as::
     ==================================================================
     BUG: KFENCE: use-after-free read in test_use_after_free_read+0xb3/0x143
 
-    Use-after-free read at 0xffffffffb673dfe0 (in kfence-#24):
+    Use-after-free read at 0xffff8c3f2e2a0000 (in kfence-#79):
      test_use_after_free_read+0xb3/0x143
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    kfence-#24 [0xffffffffb673dfe0-0xffffffffb673dfff, size=32, cache=kmalloc-32] allocated by task 507:
-     test_alloc+0xf3/0x25b
+    kfence-#79: 0xffff8c3f2e2a0000-0xffff8c3f2e2a001f, size=32, cache=kmalloc-32
+
+    allocated by task 488 on cpu 2 at 33.871326s:
+     test_alloc+0xfe/0x738
      test_use_after_free_read+0x76/0x143
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    freed by task 507:
+    freed by task 488 on cpu 2 at 33.871358s:
      test_use_after_free_read+0xa8/0x143
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    CPU: 4 PID: 109 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    CPU: 2 PID: 488 Comm: kunit_try_catch Tainted: G    B             5.13.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 KFENCE also reports on invalid frees, such as double-frees::
@@ -127,30 +131,32 @@ KFENCE also reports on invalid frees, such as double-frees::
     ==================================================================
     BUG: KFENCE: invalid free in test_double_free+0xdc/0x171
 
-    Invalid free of 0xffffffffb6741000:
+    Invalid free of 0xffff8c3f2e2a4000 (in kfence-#81):
      test_double_free+0xdc/0x171
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    kfence-#26 [0xffffffffb6741000-0xffffffffb674101f, size=32, cache=kmalloc-32] allocated by task 507:
-     test_alloc+0xf3/0x25b
+    kfence-#81: 0xffff8c3f2e2a4000-0xffff8c3f2e2a401f, size=32, cache=kmalloc-32
+
+    allocated by task 490 on cpu 1 at 34.175321s:
+     test_alloc+0xfe/0x738
      test_double_free+0x76/0x171
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    freed by task 507:
+    freed by task 490 on cpu 1 at 34.175348s:
      test_double_free+0xa8/0x171
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    CPU: 4 PID: 111 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    CPU: 1 PID: 490 Comm: kunit_try_catch Tainted: G    B             5.13.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 KFENCE also uses pattern-based redzones on the other side of an object's guard
@@ -160,23 +166,25 @@ These are reported on frees::
     ==================================================================
     BUG: KFENCE: memory corruption in test_kmalloc_aligned_oob_write+0xef/0x184
 
-    Corrupted memory at 0xffffffffb6797ff9 [ 0xac . . . . . . ] (in kfence-#69):
+    Corrupted memory at 0xffff8c3f2e33aff9 [ 0xac . . . . . . ] (in kfence-#156):
      test_kmalloc_aligned_oob_write+0xef/0x184
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    kfence-#69 [0xffffffffb6797fb0-0xffffffffb6797ff8, size=73, cache=kmalloc-96] allocated by task 507:
-     test_alloc+0xf3/0x25b
+    kfence-#156: 0xffff8c3f2e33afb0-0xffff8c3f2e33aff8, size=73, cache=kmalloc-96
+
+    allocated by task 502 on cpu 7 at 42.159302s:
+     test_alloc+0xfe/0x738
      test_kmalloc_aligned_oob_write+0x57/0x184
-     kunit_try_run_case+0x51/0x85
+     kunit_try_run_case+0x61/0xa0
      kunit_generic_run_threadfn_adapter+0x16/0x30
-     kthread+0x137/0x160
+     kthread+0x176/0x1b0
      ret_from_fork+0x22/0x30
 
-    CPU: 4 PID: 120 Comm: kunit_try_catch Tainted: G        W         5.8.0-rc6+ #7
-    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1 04/01/2014
+    CPU: 7 PID: 502 Comm: kunit_try_catch Tainted: G    B             5.13.0-rc3+ #7
+    Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
     ==================================================================
 
 For such errors, the address where the corruption occurred as well as the
diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index d7666ace9d2e..0fd7a122e1a1 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -20,6 +20,7 @@
 #include <linux/moduleparam.h>
 #include <linux/random.h>
 #include <linux/rcupdate.h>
+#include <linux/sched/clock.h>
 #include <linux/sched/sysctl.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
@@ -196,6 +197,8 @@ static noinline void metadata_update_state(struct kfence_metadata *meta,
 	 */
 	track->num_stack_entries = stack_trace_save(track->stack_entries, KFENCE_STACK_DEPTH, 1);
 	track->pid = task_pid_nr(current);
+	track->cpu = raw_smp_processor_id();
+	track->ts_nsec = local_clock(); /* Same source as printk timestamps. */
 
 	/*
 	 * Pairs with READ_ONCE() in
diff --git a/mm/kfence/kfence.h b/mm/kfence/kfence.h
index 24065321ff8a..c1f23c61e5f9 100644
--- a/mm/kfence/kfence.h
+++ b/mm/kfence/kfence.h
@@ -36,6 +36,8 @@ enum kfence_object_state {
 /* Alloc/free tracking information. */
 struct kfence_track {
 	pid_t pid;
+	int cpu;
+	u64 ts_nsec;
 	int num_stack_entries;
 	unsigned long stack_entries[KFENCE_STACK_DEPTH];
 };
diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index 2a319c21c939..d1daabdc9188 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -9,6 +9,7 @@
 
 #include <linux/kernel.h>
 #include <linux/lockdep.h>
+#include <linux/math.h>
 #include <linux/printk.h>
 #include <linux/sched/debug.h>
 #include <linux/seq_file.h>
@@ -100,6 +101,13 @@ static void kfence_print_stack(struct seq_file *seq, const struct kfence_metadat
 			       bool show_alloc)
 {
 	const struct kfence_track *track = show_alloc ? &meta->alloc_track : &meta->free_track;
+	u64 ts_sec = track->ts_nsec;
+	unsigned long rem_nsec = do_div(ts_sec, NSEC_PER_SEC);
+
+	/* Timestamp matches printk timestamp format. */
+	seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
+		       show_alloc ? "allocated" : "freed", meta->alloc_track.pid,
+		       meta->alloc_track.cpu, (unsigned long)ts_sec, rem_nsec / 1000);
 
 	if (track->num_stack_entries) {
 		/* Skip allocation/free internals stack. */
@@ -126,15 +134,14 @@ void kfence_print_object(struct seq_file *seq, const struct kfence_metadata *met
 		return;
 	}
 
-	seq_con_printf(seq,
-		       "kfence-#%td [0x%p-0x%p"
-		       ", size=%d, cache=%s] allocated by task %d:\n",
-		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1), size,
-		       (cache && cache->name) ? cache->name : "<destroyed>", meta->alloc_track.pid);
+	seq_con_printf(seq, "kfence-#%td: 0x%p-0x%p, size=%d, cache=%s\n\n",
+		       meta - kfence_metadata, (void *)start, (void *)(start + size - 1),
+		       size, (cache && cache->name) ? cache->name : "<destroyed>");
+
 	kfence_print_stack(seq, meta, true);
 
 	if (meta->state == KFENCE_OBJECT_FREED) {
-		seq_con_printf(seq, "\nfreed by task %d:\n", meta->free_track.pid);
+		seq_con_printf(seq, "\n");
 		kfence_print_stack(seq, meta, false);
 	}
 }
-- 
2.32.0.93.g670b81a890-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210629113323.2354571-1-elver%40google.com.
