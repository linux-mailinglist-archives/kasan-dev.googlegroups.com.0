Return-Path: <kasan-dev+bncBC7OBJGL2MHBBMN5XKDQMGQESLAQC3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id E772B3C7FF1
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 10:22:10 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id x9-20020a6541490000b0290222fe6234d6sf967938pgp.14
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Jul 2021 01:22:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626250929; cv=pass;
        d=google.com; s=arc-20160816;
        b=vpxBLFQrY9f16LzyujthZvWYt2cGMpliuisZLl9RXMzQXFA/bqMs/2rCYmJsn2k/tj
         HvzWOTXPpnhdIVha7MIRmhrVNlRXHkGPhOYxgXVlqmDUl1m1jx1MFbOirgDi66fuSOcm
         IfU/Zk2Yw58OIP1HoboXdrl1Kb0Nue3ub4zjX1sR9kiuns4a1QZjIanrAkj3pIXFeTo5
         xYjA4SaojKoXkLfPxWP6loU0JhFV4rGqpG7U1OiDvbbeakTOrL4BBV2N+n3LE3TaRFr/
         5zMq1AJUH8UG5vK7GNWYOTsdpxiXyL4dhbuxJyaO9+u7I/kSX9N2WvyutjIZPpbq4pHC
         /LFw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=9AZ46Xq6rhvbLsfEn02pAAU0N3lFOzqqSnDYdCjnydo=;
        b=oCMW+lxl6EZaxJeQ39oKZ/x6Dl6DZllTHOsWK+Xan5GvtcrfquSf5Ho16cgc29uo8i
         29HRswb6Cmk20wgfvE3f8PL0rmmCuGI481lr1V7+mjK95tY3aPEBJxhlZcYh+mn9q9Fl
         VAKwiRaIHulNOXa5JWkBlHYiKZr/v2yShqWKpG1VYnZJ92be2o0bdoI32NHMZOaEe0Xr
         raCWD6lb6ZSypIyOCGbDF3NCBeXQYHMabTgMAQB7LSZtD18ffJWc3kcpQRohP6U4iGdb
         WG28GxmK5b3UiMtc+2FznvsB9UNZEb60UO+bPdu4yE6mvuyK4NR571TbetwAMR+K6i5g
         TJAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="K/k4GmUt";
       spf=pass (google.com: domain of 3r57uyaukcbqyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3r57uYAUKCbQYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9AZ46Xq6rhvbLsfEn02pAAU0N3lFOzqqSnDYdCjnydo=;
        b=jMX6EqHIEVm+1uxw4cvipmS/ry1mM2PNaw1187Y6+RjSNxVLYOw0BpWBgqN1Bu4u0B
         pwcXhOFd712uTWYt+d5KhY8h72I6/SevS1k2U7y4hcSCrZ7IOGGOIlgTPpu2tXcXWklN
         uyL+XqwUClL37/5WhxqyotyBAmOy42G06PUyq6soHLJTX03jKKBy3/iAvqo7gWKiQPKs
         rRQz1/PvzTSch8mYYP1Zo/+0dL2Dbvd+iRSXPHjxRWKsbqnRyaw+/w0x0JOSWAarkzXG
         A7DWODFlBKFrap51cHkFYUGNuu9fXt9vLouGqGQsILQYwynMPVS/iS2gKm7NxmBMFmbF
         8Bqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9AZ46Xq6rhvbLsfEn02pAAU0N3lFOzqqSnDYdCjnydo=;
        b=fGe60UNE34iOARy3FA3LSTiqTDyf54tvlTy31HhZ1UKPo9ZsvT6evDY1SQ/F2lktKW
         z4MQzYSShnMXeOaDVEX/itdHx4jdG/LM2VMfhmUqMC+N/P3WaGghB4cVUtQKUwFugP88
         C0qAHsQaiV24K4l95wj3r4xsWQxffiGzqM3+Z4cTJvp1HYlwNFb1D1Sme9tyMROEiMQ7
         SfXFbL4nFYjq3H7iVM5EojGOx2VxDIv2MlCxpgj3um1/T3ByLL5ycHS8GuvKaQ0m3oi5
         ioEsgaXN6NdmHyC7ZB6iJEDnjl4+nJdeIa76NAZFFVfOj7fcwQ8TcsY6S+vPBmhI7CjR
         fnYw==
X-Gm-Message-State: AOAM533TCmhT3i8tfxDv7NW5N8IQZzBeW2fuPGBNRyhI+hC0EJnOjlgU
	xl0DqsAIVMlQrhii4OYK9L0=
X-Google-Smtp-Source: ABdhPJwQjXCBmeVajpD2TW3N1kC6+BRPAzdIuH+Lplm+RbsaJPgZx2qY4evEDsLZuS2H6XTKlBXqGQ==
X-Received: by 2002:a62:92d7:0:b029:32c:8c46:9491 with SMTP id o206-20020a6292d70000b029032c8c469491mr8970524pfd.2.1626250929248;
        Wed, 14 Jul 2021 01:22:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5348:: with SMTP id w8ls905395pgr.10.gmail; Wed, 14 Jul
 2021 01:22:08 -0700 (PDT)
X-Received: by 2002:a63:807:: with SMTP id 7mr8287945pgi.122.1626250928600;
        Wed, 14 Jul 2021 01:22:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626250928; cv=none;
        d=google.com; s=arc-20160816;
        b=hay6YYYUdNlS1b6xOUmHQDEuWskXjA+TadAvkPz+6paGZ5CKX6U3pQtr9c7bOnEkjZ
         zRmWDF5VmEHhJesj3aJQJ7rLpAqy88DOD7B6TMTvWVzgcYvBQJ3oGPl15kgGBRK7TZDH
         DolXIGF4+JcgqrgqDwMQkPoc73XkyXSExj6SlZTEKR0LE6Xqb6yxJbLyD8pGYy4Oy/wF
         S7XtX+75pXqq/eLSg3B1qW8UExh272qr+otnco2r0GTcAH46sQYkAwwJFLfIlZn/NswT
         Z3fXuFYenxbzPMtKYfXssBeSwFQcu//PaOY7E2kNZ8wLqglwm6ceS0IZcuRAjDTNOCGW
         7eXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=KdvbL+Jep13ELIaiRdmi7CMJ1jwkrxNTodiW13l5s0s=;
        b=yDWN0I9BNZCOohRyfUuljOJuupE7sJiJN9Bqrf2GwBrUrmdaCtGqTiRGvneFZ+7UJM
         Lkpfdd1W5P6WIHtHqN3+tm7bZQd+40zRVbXTI5cDse7Q3HBlNj7oBrnV6I1qmXKo1yaW
         muZhxTabGEOOmchg0sMbVms10UT8GBmY+ZQsfRbeoax+AsDLRkvpRQGjvwYSSO1Hxb0R
         R68z0NqtaIcoZaAgJHylGtPLw8FEdiRdalw3f/ie0thCqbfz5h8IqeI+KbZtTcQ3dWid
         2xGWiNkZMtmrLInVxAPabWi/Jty1iJ6oHozO88CuOnxVqoUAsnqY+YcxMWn+NIf+jIBq
         52eQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="K/k4GmUt";
       spf=pass (google.com: domain of 3r57uyaukcbqyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3r57uYAUKCbQYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id c9si214681pfr.5.2021.07.14.01.22.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Jul 2021 01:22:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3r57uyaukcbqyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id y35-20020a0cb8a30000b0290270c2da88e8so1079455qvf.13
        for <kasan-dev@googlegroups.com>; Wed, 14 Jul 2021 01:22:08 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:16e4:4f77:5c18:936])
 (user=elver job=sendgmr) by 2002:a05:6214:6a1:: with SMTP id
 s1mr9343148qvz.54.1626250927652; Wed, 14 Jul 2021 01:22:07 -0700 (PDT)
Date: Wed, 14 Jul 2021 10:21:45 +0200
Message-Id: <20210714082145.2709233-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.93.g670b81a890-goog
Subject: [PATCH mm v2] kfence: show cpu and timestamp in alloc/free info
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, corbet@lwn.net, 
	linux-doc@vger.kernel.org, Joern Engel <joern@purestorage.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="K/k4GmUt";       spf=pass
 (google.com: domain of 3r57uyaukcbqyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3r57uYAUKCbQYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
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
Acked-by: Alexander Potapenko <glider@google.com>
Acked-by: Joern Engel <joern@purestorage.com>
---
v2:
* Rebase to v5.14-rc1 and pick up Acks.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210714082145.2709233-1-elver%40google.com.
