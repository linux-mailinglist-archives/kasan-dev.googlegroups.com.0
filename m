Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH43VKBAMGQEJWHCLKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 874B4337FB3
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:36 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id m19sf10325024oiw.19
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498655; cv=pass;
        d=google.com; s=arc-20160816;
        b=ca1FJciDzg1Yn4RJaEDVpULrKqF2+3GRoQVUv4rZLl7g3pidRwCc8p5E8kEnPoPzB5
         qEOEHo4MELGAp+JcCF5iQelfMMZAhuESwgcIUCXFfBcb8TPKPmyzNQZiAvcCYy0+0QCU
         eXP3U52iif/jRrR/Y1DTbSW5KpBqwyRFAZGqSjRU2offRGye/R5oEJ/taV6+Qm7WGncQ
         2gHbNpDI/JUDx89nTWeLEBPyckIlrcKtpJ6HDpWM/wIcAgSJ8uT1Mp8fcHgKQw4zlYr4
         rbhuGt4LhHlvcSXnfBvl+qqT1a3OfIJg43QFOmenw6xAJlG2SYbIDGUpgKB+8fW4pREQ
         FtPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Su1tzUMBNdvWdQKXOaaj6U4UevS5Lna0ruD9hqGvGvc=;
        b=xysCHNtGzHJOvcGajP0UdGinBDhu7thoZ3t5iGKR3gvcD34zyC8bkfywqmeUPMkELR
         Sk0a07lXSwUeXKaiu8ZF6K3dl5cgGjozN1SKNrco1rQA4ploDFkzdmg4YjHMtZy0q2PJ
         0ECW3Gvjr62uEqBJjG1c9PBtZefVhJF9UUQI+0a0ueipx6pypbX+3FDvPv1WULCSNmHf
         /F+BOBQWwc2K86ovkklnriuWLClLrEFlfMSNxpfHGZbxvqiZSc9G/dSWd1uvr0ZU9UIx
         XTzXB1yZUPfqJpKXTLQiHDDkMOgxOAqkIQsHvx0MCw6+gMu3OXwwhdxdqx/N7qyA6Rtr
         SqxQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ss9oJe0p;
       spf=pass (google.com: domain of 3no1kyaokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3no1KYAoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Su1tzUMBNdvWdQKXOaaj6U4UevS5Lna0ruD9hqGvGvc=;
        b=V0qFD1aejP4a7a2XBrYzWFh9Zbty968aTFWLxQfe8CmJ31NQ7EHE+nAd8G64Fz7qIu
         Hrdkg9NQfj9bls1SAB3fT/8Afz/rpkyLNPgC8fPfpnCgE26JG4LJ0IMJDib1Qs6uyB+E
         bTKQ4YKERGnxHQURZZoZVqEfVmepYRmpVm09LymrsbGOjroS5d7rZw//kNyQXPPkOC2j
         /gTwRXQzNZVD8J4wy4TgfFfGcVkQpBl7WHReLfHKvOifk/pEiSG7gRPY0ruNNfBQqil8
         AZDS/iTBm50HfgqD/LUZGbRMF9wyeZuSSu9tsroc0K0lQaNyOcVX3geHf26/bhSbUgcT
         D1uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Su1tzUMBNdvWdQKXOaaj6U4UevS5Lna0ruD9hqGvGvc=;
        b=Vp8dK7UkvPS2zMPbF829xzFaF4XQ8stxdbkHIqbDJpm381n7h3HPcnynRPCzbpVRQj
         N3DOuwcQ1ITS21S1OCMCX11qYn9D0uN9+OfG9QjqzpDzS2se7iZoGnWtNQ4JTe6En2TO
         yVyD44zzLRNWWB5ancbcKxUIhwMEmKzar2SbADGlf07vUMBMdlOWK8KAuSTmgU3J6AtQ
         NEgbTbg//iCWwE+B1/QqlEIFYRfkZ46MqtIL+dUEhjpg+LWDfxUC+nKN/lw4wiaIbP51
         CgEN8Ek+6NrqEIoXjWZJFrRvez/q/oI83izEY1DzLq9B+82WTgm1hVhhj7QnMxpzbvSt
         MA7A==
X-Gm-Message-State: AOAM532kTUkA62UAjHqS1hCnAMv89WZY4HapLI+TxMIUWHb1Ck2HQnEA
	8xCBo8I9bMB5hK+44gcXUo0=
X-Google-Smtp-Source: ABdhPJz56rMv8DxZPZUp+mYbAaaFYtVY1dmp/YJThv+DAjvFySlHm5lo/ZzCtBYFYiDOdFmr5NW8JA==
X-Received: by 2002:aca:db85:: with SMTP id s127mr7616402oig.142.1615498655379;
        Thu, 11 Mar 2021 13:37:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:578a:: with SMTP id q10ls1799246oth.7.gmail; Thu, 11 Mar
 2021 13:37:35 -0800 (PST)
X-Received: by 2002:a9d:7f8a:: with SMTP id t10mr741907otp.239.1615498655061;
        Thu, 11 Mar 2021 13:37:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498655; cv=none;
        d=google.com; s=arc-20160816;
        b=G8Q3U0sb06+mbe9HaYKcxmsB3/EtekdU3ARM7rhFuJfW0gUHcfHn/ASGwGd5hJ/b7d
         G0s8HCZtgiYdEGSyTSvco2dUWut6Zigt24eXzcMO6LujPULsaithiMKimTdp+6aoGqej
         Lk5qmUFVYUev19RKvR6odXd2faKoiIoJ6uKIpvgfmwpaL1js8va4f2TkJjLuSf0oCjR8
         uGZc4oPc2sxRSzzTjOP/3xlfLUKOSeGvIcw4Rg+ABsyIQVQjYOHIygXmmO/KZkv0rM91
         VKNJWAAmmwZKT6OOceJgaoS7gGEXyjFnyIXMPt6sHR9CA5mNtCUWG3dyzsmMlAzn78fG
         dzag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Z5eOirVQs3kFMVVYLPwNbYTFfp7Ms1nJ3eBbZNg7oSE=;
        b=BRSUViXLwGuoYwRLpRvg8Bh1FycnAgYymdGqefkywiLNRlia/TslrjNkq52Ln2IK3V
         dwELyIA87Ml7VIPfSNq32+qbFtTw8keUmiNojylYfm6wBKksaEoj8r4YTT8GOt2Dc8dI
         1rV0jLTpe2G/BHQiFuuluXAvCxIYdXUCr7UN9+q+xbDkIQKj3YXVDPUIhBKAYAhiVBtT
         ov8duQdXDx4bhteTBgk9Th8JYpSZTU7IJ3Ja+Ae0arW0UkbUJj8/T8NEPevt4q65uhZG
         t1W3Ko2kQ94p/fpnaXX6VcSocc3J3HdizwuBkSzwgomCr5dEFtUII763RiKsETz5Dk5S
         f7RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ss9oJe0p;
       spf=pass (google.com: domain of 3no1kyaokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3no1KYAoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id l7si270137oih.0.2021.03.11.13.37.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:35 -0800 (PST)
Received-SPF: pass (google.com: domain of 3no1kyaokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id c184so1170144qkb.17
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:35 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c248:: with SMTP id
 w8mr9669098qvh.58.1615498654537; Thu, 11 Mar 2021 13:37:34 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:16 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <fb4c4c963a8f35df5d42706cf3384a1a1e36554b.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 04/11] kasan: docs: update error reports section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ss9oJe0p;       spf=pass
 (google.com: domain of 3no1kyaokcesnaqerlxaiytbbtyr.pbzxnfna-qritbbtyrtebhcf.pbz@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3no1KYAoKCesNaQeRlXaiYTbbTYR.PbZXNfNa-QRiTbbTYRTebhcf.PbZ@flex--andreyknvl.bounces.google.com;
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

Update the "Error reports" section in KASAN documentation:

- Mention that bug titles are best-effort.
- Move and reword the part about auxiliary stacks from
  "Implementation details".
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 46 +++++++++++++++++--------------
 1 file changed, 26 insertions(+), 20 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index f21c0cbebcb3..5fe43489e94e 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -60,7 +60,7 @@ physical pages, enable ``CONFIG_PAGE_OWNER`` and boot with ``page_owner=on``.
 Error reports
 ~~~~~~~~~~~~~
 
-A typical out-of-bounds access generic KASAN report looks like this::
+A typical KASAN report looks like this::
 
     ==================================================================
     BUG: KASAN: slab-out-of-bounds in kmalloc_oob_right+0xa8/0xbc [test_kasan]
@@ -133,33 +133,43 @@ A typical out-of-bounds access generic KASAN report looks like this::
      ffff8801f44ec400: fb fb fb fb fb fb fb fb fc fc fc fc fc fc fc fc
     ==================================================================
 
-The header of the report provides a short summary of what kind of bug happened
-and what kind of access caused it. It's followed by a stack trace of the bad
-access, a stack trace of where the accessed memory was allocated (in case bad
-access happens on a slab object), and a stack trace of where the object was
-freed (in case of a use-after-free bug report). Next comes a description of
-the accessed slab object and information about the accessed memory page.
+The report header summarizes what kind of bug happened and what kind of access
+caused it. It is followed by a stack trace of the bad access, a stack trace of
+where the accessed memory was allocated (in case a slab object was accessed),
+and a stack trace of where the object was freed (in case of a use-after-free
+bug report). Next comes a description of the accessed slab object and the
+information about the accessed memory page.
 
-In the last section the report shows memory state around the accessed address.
-Internally KASAN tracks memory state separately for each memory granule, which
+In the end, the report shows the memory state around the accessed address.
+Internally, KASAN tracks memory state separately for each memory granule, which
 is either 8 or 16 aligned bytes depending on KASAN mode. Each number in the
 memory state section of the report shows the state of one of the memory
 granules that surround the accessed address.
 
-For generic KASAN the size of each memory granule is 8. The state of each
+For generic KASAN, the size of each memory granule is 8. The state of each
 granule is encoded in one shadow byte. Those 8 bytes can be accessible,
-partially accessible, freed or be a part of a redzone. KASAN uses the following
-encoding for each shadow byte: 0 means that all 8 bytes of the corresponding
+partially accessible, freed, or be a part of a redzone. KASAN uses the following
+encoding for each shadow byte: 00 means that all 8 bytes of the corresponding
 memory region are accessible; number N (1 <= N <= 7) means that the first N
 bytes are accessible, and other (8 - N) bytes are not; any negative value
 indicates that the entire 8-byte word is inaccessible. KASAN uses different
 negative values to distinguish between different kinds of inaccessible memory
 like redzones or freed memory (see mm/kasan/kasan.h).
 
-In the report above the arrows point to the shadow byte 03, which means that
-the accessed address is partially accessible. For tag-based KASAN modes this
-last report section shows the memory tags around the accessed address
-(see the `Implementation details`_ section).
+In the report above, the arrow points to the shadow byte ``03``, which means
+that the accessed address is partially accessible.
+
+For tag-based KASAN modes, this last report section shows the memory tags around
+the accessed address (see the `Implementation details`_ section).
+
+Note that KASAN bug titles (like ``slab-out-of-bounds`` or ``use-after-free``)
+are best-effort: KASAN prints the most probable bug type based on the limited
+information it has. The actual type of the bug might be different.
+
+Generic KASAN also reports up to two auxiliary call stack traces. These stack
+traces point to places in code that interacted with the object but that are not
+directly present in the bad access stack trace. Currently, this includes
+call_rcu() and workqueue queuing.
 
 Boot parameters
 ~~~~~~~~~~~~~~~
@@ -214,10 +224,6 @@ function calls GCC directly inserts the code to check the shadow memory.
 This option significantly enlarges kernel but it gives x1.1-x2 performance
 boost over outline instrumented kernel.
 
-Generic KASAN also reports the last 2 call stacks to creation of work that
-potentially has access to an object. Call stacks for the following are shown:
-call_rcu() and workqueue queuing.
-
 Generic KASAN is the only mode that delays the reuse of freed object via
 quarantine (see mm/kasan/quarantine.c for implementation).
 
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fb4c4c963a8f35df5d42706cf3384a1a1e36554b.1615498565.git.andreyknvl%40google.com.
