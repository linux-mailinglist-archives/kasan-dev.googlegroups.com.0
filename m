Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJ7TVWBAMGQE4LGBZGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 95515338FDE
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:24:40 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id t18sf13329100plr.15
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:24:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559079; cv=pass;
        d=google.com; s=arc-20160816;
        b=nj96COEgwkDpuWFdm5pj42RSqd1J5YXxSVQLc1SSa9L/ksKPNEm8j34GWMFN1DT3LT
         xF/JU/diZ7uDfqXfp2c0OjtBtvK5bwVy4QLy4AwAnipReEeToTI3KQICVeAwzDF3aUeM
         OgQmJv4suSGb6zigwilqrrIrLlU9+JCw2OKCgXHMor1HB5FeTEXUn8afMrJf0A7Ujk13
         Jo7MOku8LfZDNzKeUH8BQbMnx2NMT6Hd/azu7OniBUzhuBoL+moSo7z18Upfbn2JKRHC
         zlRtkOaZDeTlHtNIc7IfN3cspENTs9HDlmD/5tfdnLBwnP4eH1FoQ/tHhAlPJT56iyvA
         SEWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=UViitEcTTcTrerc+vRaiXqxn5JckljrNfmIV/aP8A90=;
        b=VZq0EXFwOZ+oyT3zVhZFIMLIJ+CWLIAKK6D6VTFz/67cQi+Lm3dBJwfY450qhOphhW
         WOjoznjSWL6xg/ossFnZCeYeAWwpBdsgi3RLvRcD7fRC9lZoGeJsM73K0WGtIWSDImhp
         tFVGAuMJ8u9B//ixdRuL34mZSTQewP/NyNgyGANY01rWTcLAlPIAgV3IBiWdtLFNAtxC
         MiwrR3Go38zGfN9pCTdfMlsv0kZ1BbK8SBa+Tl20Z8OcZnXr38Pu0xkxEODXLU0hzKgY
         DXyAf/2GCyhkbFwuDXp8DTMqMTKTizfdTtL4mo7BCZh2ipd94hHepKpUkbkdwlw4WvvB
         UcVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nXGX3uu1;
       spf=pass (google.com: domain of 3pnllyaokcc8v8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3pnlLYAoKCc8v8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=UViitEcTTcTrerc+vRaiXqxn5JckljrNfmIV/aP8A90=;
        b=b5OGikJ2ctzJcxrSsizvhgR7umpz6aGpd7jMFxlxhBOCQ9kKXFvG9Ww3L3dVdqkJ2B
         ihLJsbSFNcKHe3lwydPV3qZpNzJivX/1rx3/KcAFXHJOIBrGX9zJvxvAEjesKJwvMA67
         A65Q6wVIa4/9rOYj6MxmCrjVuPDKIW8Aj4dyltBzfOTQds3/HpypTQn8Sdx1EQn1gQ0z
         i84R/WS35YIlYczMnuekt++HfKxbVDG3G/+lM1c5zoS/slQNBCi4TXfgXFU69Krl2ju7
         by0pw6OrOJPJ+PpVeIJQx7j+yPbMDG7bV4pnV3/EsGpCtSTA+Dfi2SRjS+SIGpMUZlse
         B23g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UViitEcTTcTrerc+vRaiXqxn5JckljrNfmIV/aP8A90=;
        b=ddHma7WGCNniWo8nLVbG2362hbvsYb2z0zYz1lm0MKgurFUlCa6Ik0CSftAUYbVOlG
         N+ZelwzJ5ZMSJDgfywM1DQfSMRVbYtp2wmy6uC7a0MxKoy3kQDh/MCA3jRtiwAKCa3nu
         PeDqk2FAscgelX6RiT4h0mHEPIQ1sHP0pP85Rc3fQFqGqw22n0lhgJqsok8SJOaZgh0l
         cw6UWAFPt9Ix0eqFW5A6JDlx2rTiSmzwURF5VqyU98qzOYN23mgWJ3XNjMpxrEFu1Tvj
         3RfuXtowOBMl1rw2fI1kgzbs5jQfMAFMILVLa6QxjhQFcnEyqozDUsSUX9nx1YsvAPBr
         wIuw==
X-Gm-Message-State: AOAM531IswQUbtHwY5bH3DMYy9gJacTD1K+IpZCCbolunORSoJlAUVpQ
	yLYxj7bgbEdJFD/yKUoTb3k=
X-Google-Smtp-Source: ABdhPJw6KoheRXHjBwXzbPICwrKTxaLhZf0HGYI11Wli3zqPdQ+nEa5da1eAXR3VlGzep1bFneEJvQ==
X-Received: by 2002:a63:4761:: with SMTP id w33mr12137430pgk.118.1615559079362;
        Fri, 12 Mar 2021 06:24:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:ef0b:: with SMTP id u11ls3640486pgh.4.gmail; Fri, 12 Mar
 2021 06:24:38 -0800 (PST)
X-Received: by 2002:a63:d144:: with SMTP id c4mr11645768pgj.196.1615559078896;
        Fri, 12 Mar 2021 06:24:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559078; cv=none;
        d=google.com; s=arc-20160816;
        b=mrgVBuIeGZLlq9htYzgNwTf3qe+9+0LiSlbrMu2sjQg6gs2xOYeg0Qp7ikTIqOpYkq
         jj+q2jrExUyPDdVE6Uj6SG0kG1KCyr5+650HDtyvyZ4yekvyYxuFP0/eTXnaILCPd1Ca
         IHzHUbwZYmC2zWA0XY6E6XIO6MMpY37QIW6A8hKxtlVRBLUKeT0N2sptvQmj7UrlH0za
         /Y0sLtgcKoD1GZiEyZPFDaO69cyBfYA30Qw5pNyg86rBFoVPzaFcitVzfU0Zlcx9o+6j
         hDiKXA5K55VBsB/r+1f7ZxgNCgs3loCvSR2q5x1g21Cy36rTfbGR4rtqaQ5Te0fkWYFc
         QR8w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=iXUBccT1s/Tpz0xpM0wAfa/pMQuz7eoXMXGou1E4nY8=;
        b=f1E0hBIONO2O3XoE3TdffRwnivmDX6ayEjSm7Zlo2czLCkguUbo9T7pFfiPXHKfVig
         eTIs4cofnPIDNOjh3glixZkIKCLtuDDR4HkZAB1Fvb+DEKuLyAiOR4AhfkSXb0vPFRAi
         U+9+LZ/2/DO0G0a9bmxK9EOm1C/7lIcyU00Z2Ct6SfIekocZJ5rA6/ciJVTbQfa7GcXU
         wX79AOauED31rvgJZTzIi34XDAUZ7AqkWlFNrnJEVYs5voP+rg15cNz+EksauBz9EOx+
         AkKnLQSLMQNY349djn4wlFKPiVwQT2EY0oKNRvLPJWpLEkip/A0zxJDOySndMUfofT0s
         8kHg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nXGX3uu1;
       spf=pass (google.com: domain of 3pnllyaokcc8v8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3pnlLYAoKCc8v8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id md20si924158pjb.1.2021.03.12.06.24.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:24:38 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pnllyaokcc8v8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d11so17970085qth.3
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:24:38 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a0c:8f1a:: with SMTP id
 z26mr11991825qvd.51.1615559078072; Fri, 12 Mar 2021 06:24:38 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:24 +0100
Message-Id: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 01/11] kasan: docs: clean up sections
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nXGX3uu1;       spf=pass
 (google.com: domain of 3pnllyaokcc8v8yczj58g619916z.x975vdv8-yzg19916z1c9fad.x97@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3pnlLYAoKCc8v8yCzJ58G619916z.x975vDv8-yzG19916z1C9FAD.x97@flex--andreyknvl.bounces.google.com;
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

Update KASAN documentation:

- Give some sections clearer names.
- Remove unneeded subsections in the "Tests" section.
- Move the "For developers" section and split into subsections.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- Rename "By default" section to "Default behaviour".
---
 Documentation/dev-tools/kasan.rst | 54 +++++++++++++++----------------
 1 file changed, 27 insertions(+), 27 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index ddf4239a5890..b3b2c517db55 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -168,24 +168,6 @@ particular KASAN features.
   report or also panic the kernel (default: ``report``). Note, that tag
   checking gets disabled after the first reported bug.
 
-For developers
-~~~~~~~~~~~~~~
-
-Software KASAN modes use compiler instrumentation to insert validity checks.
-Such instrumentation might be incompatible with some part of the kernel, and
-therefore needs to be disabled. To disable instrumentation for specific files
-or directories, add a line similar to the following to the respective kernel
-Makefile:
-
-- For a single file (e.g. main.o)::
-
-    KASAN_SANITIZE_main.o := n
-
-- For all files in one directory::
-
-    KASAN_SANITIZE := n
-
-
 Implementation details
 ----------------------
 
@@ -299,8 +281,8 @@ support MTE (but supports TBI).
 Hardware tag-based KASAN only reports the first found bug. After that MTE tag
 checking gets disabled.
 
-What memory accesses are sanitised by KASAN?
---------------------------------------------
+Shadow memory
+-------------
 
 The kernel maps memory in a number of different parts of the address
 space. This poses something of a problem for KASAN, which requires
@@ -311,8 +293,8 @@ The range of kernel virtual addresses is large: there is not enough
 real memory to support a real shadow region for every address that
 could be accessed by the kernel.
 
-By default
-~~~~~~~~~~
+Default behaviour
+~~~~~~~~~~~~~~~~~
 
 By default, architectures only map real memory over the shadow region
 for the linear mapping (and potentially other small areas). For all
@@ -362,8 +344,29 @@ unmapped. This will require changes in arch-specific code.
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
 
-CONFIG_KASAN_KUNIT_TEST and CONFIG_KASAN_MODULE_TEST
-----------------------------------------------------
+For developers
+--------------
+
+Ignoring accesses
+~~~~~~~~~~~~~~~~~
+
+Software KASAN modes use compiler instrumentation to insert validity checks.
+Such instrumentation might be incompatible with some part of the kernel, and
+therefore needs to be disabled. To disable instrumentation for specific files
+or directories, add a line similar to the following to the respective kernel
+Makefile:
+
+- For a single file (e.g. main.o)::
+
+    KASAN_SANITIZE_main.o := n
+
+- For all files in one directory::
+
+    KASAN_SANITIZE := n
+
+
+Tests
+~~~~~
 
 KASAN tests consist of two parts:
 
@@ -409,21 +412,18 @@ Or, if one of the tests failed::
 There are a few ways to run KUnit-compatible KASAN tests.
 
 1. Loadable module
-~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
 a loadable module and run on any architecture that supports KASAN by loading
 the module with insmod or modprobe. The module is called ``test_kasan``.
 
 2. Built-In
-~~~~~~~~~~~
 
 With ``CONFIG_KUNIT`` built-in, ``CONFIG_KASAN_KUNIT_TEST`` can be built-in
 on any architecure that supports KASAN. These and any other KUnit tests enabled
 will run and print the results at boot as a late-init call.
 
 3. Using kunit_tool
-~~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it's also
 possible use ``kunit_tool`` to see the results of these and other KUnit tests
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl%40google.com.
