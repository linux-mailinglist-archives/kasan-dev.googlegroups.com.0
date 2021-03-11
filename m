Return-Path: <kasan-dev+bncBDX4HWEMTEBRBGE3VKBAMGQECQDWBPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id C88D1337FB0
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:28 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id n25sf4577253wmk.1
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498648; cv=pass;
        d=google.com; s=arc-20160816;
        b=WIjr8ZO0riK2j+9YgDap/IRTBzQb5kl5pS/Ar3pgLIOD6r1meyEIF7bVCLouUTStRf
         kwgqx1wz71Z4eksaky5SojMbPLArLUH05d3FCuyjhViZquPJJJ6BRhvP+sfeV0BzyuZs
         90gsxg7p5fSJz8VgV54qK7pVclgLKYSglLQqourgPsSFPQmDzT14+Xw50Ivebh2Jnw2M
         bCp0S4b6yPmPrI2iiuhUrxbSplaaLgJ7aNLw9EDoa0TgPO4C+gBdiIlh9SRW+eSfpsoK
         eomrOH3IZaDbuLs23BVgGE6oJxaUpGT1wESI40EJyGVfFryCtBxRwnuAflqvlKVD/FkX
         tG/g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=YUek+8cAX1C6kSkgov5g1dg+ydXQjsuQ3RHeTLqXPYo=;
        b=yvIlkjVsFDm8itZehlmdDoIDOWHYYDZe7AovS8f9H5hqdsr23sKOs76rv323t6ygtG
         Dj7JrGvKBm1h6uKnm0YwST//6/rA83FYA2jOOfkWOBIAbdfmZKoOEiE+Wx48QeHMPcyD
         MLT4gyAOYHz2AJc2Ko2PuhnX1mBbE6B4/rdYTvyZ7/lQd4+oq3qaU/AEmhj/JM83VEuB
         BbvbQcoOlXii+OFFX+Zl+r1kofJWMJld6ZQsBVNVHHHbtYPZnegTzpMcD3fP4uL6r2hB
         2BCErz8vB9h3Xd9WP50F+NdrcU+Aof+ROE1lLn+ywim+ggbEjlrtIB3dqZF7KRJv1GB+
         PjMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nG+j8ZjK;
       spf=pass (google.com: domain of 3l41kyaokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3l41KYAoKCeQGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YUek+8cAX1C6kSkgov5g1dg+ydXQjsuQ3RHeTLqXPYo=;
        b=NanAdHI6Z+gWqkJ1UkbeFF57g9K6FbtLkXYSnVPNDnCXJgd9TZ0Q6t7qCdW4FmSLsh
         +NwLmoMjz6MT98CpGZBxMI/42VRUMRewI7cusgoNlRiMuAucw89Q2JI9jXY3Yabg89SU
         zpY4CQnrjuGitoMPGY589kOE5vu9wW9dF6IentrMpwqoFaBZXyzPPYZeLClpFJiLBmL0
         12JxvyvldM1coQ3XkyeRWTl9EHbs1zKJekk92rCs36SxMH5Cm9e+DonSbddDIj01LFeP
         NNFOU9aAo7/vkEuSxxPjbo3A6PvZJ//+aq/SldrLep70/fJIUkxYuU21+/fVxwb/mcuD
         UA/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YUek+8cAX1C6kSkgov5g1dg+ydXQjsuQ3RHeTLqXPYo=;
        b=G1sGQu2ztjXkRyl6CWK9pWJaIrpxZ2y/26sYFmOD3/3jtfaH90OozwcTnKo4Ym2DDs
         24qwh4if0tM2yOCJjp3t3nsopL8hD/bKEPClbdc51q8Hqc90Y8xypeI2YiifJqDuaj7T
         BpYYQEzNbFXx7kYwil7wfiCNNEbsqoqaSUlboY7+I3T5cW2vhoOHowNwFE5Mk7fSUjJQ
         oFmUT1qDY6qalX1JGFX2+IqhingnedJ1lhbyYbwzaGJsGHxWFeO+n7n6EeXcS5Fq+/VF
         6jSN+qyn90S3R4cW8oLS053fzL7CIe6YfJ7SNJeFQlQgxIIZv/d6R+xVqyQX/mj/jzvw
         YyYw==
X-Gm-Message-State: AOAM533jPZXq0uvSEHBTSl3/a6sT1q95BhpqA+uHX0Uxf0T3dMIBq8Hw
	0QWMIM+GncSwnT8EofXWRV4=
X-Google-Smtp-Source: ABdhPJw5HUNeUu/NOM0H7U460wtnC04QxyZAASEJlMaaAHADRt69lSHnCq3mnVbGGHsl4+rcbaEjsQ==
X-Received: by 2002:a05:6000:1547:: with SMTP id 7mr10796290wry.301.1615498648496;
        Thu, 11 Mar 2021 13:37:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cc94:: with SMTP id p20ls3509620wma.0.gmail; Thu, 11 Mar
 2021 13:37:27 -0800 (PST)
X-Received: by 2002:a1c:e4d4:: with SMTP id b203mr9680412wmh.105.1615498647712;
        Thu, 11 Mar 2021 13:37:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498647; cv=none;
        d=google.com; s=arc-20160816;
        b=JoX1YeMEcIYwpwHsIiase71hcAn273tAsod8/SKnXnroYltJthArqk6brdujZi7FMC
         n3oaiH+JkcUcFzX4ITfGqEztEQ7/X8E0E+OR9WVofM1uNsjNy7v2jiCo3dNDyZT4fZ1F
         3qHzY4KWGPZ6H1i1q0fjFr1eqEh+X1RL4m4JbL6CAsbKPveGXIfT0vS2XMCWShCTJzOD
         q6wVXgYCX4dbrioh26yehxHyYRDzRw3qWVsBJFuRjLRTwaGKowgR6eXSqbDCjtfcisCP
         x1ouDF17ttIqg2gVIVugZr3+KXCriySZ1IgwwSxazOqKZsJz6Y2sJyH0TQfOrxqtSthC
         oN4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=+0bSxqm3N16pi4DLzYVkzAZIIL0GOgjjdGwFbbf/d6g=;
        b=jQlIL86yH6loNaQKDhJ3NUHEpDvzWWkVuiKtfNxrhcfowTLTyYTwNjBcaGgjTp/Smy
         6eu7Oja77rdzKhFa36CJ9msYR3lqwXcafXblJ+OGBZOTPXdUXUT6mCpjzosMKmYSxSnY
         yox851GxCaQ36o77hZ7cesUPGE+P8UOKX0ogFvE+syM9yqXRZO4lACr0UAgNwMt2Vc17
         kogSc1woYZrJ11bkstdy46CiSaHwTuewVQOSQwr7GQIEvfDh/0EAYOju+Un1QvpX47eX
         AYX4Xj8TmoCukDTy/RRNqDSI30Yo4cisf3Rj4dTV43tL90wB5bQJiG6dlqGC2+LdvNBb
         QGSw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nG+j8ZjK;
       spf=pass (google.com: domain of 3l41kyaokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3l41KYAoKCeQGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r11si150805wrm.1.2021.03.11.13.37.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:27 -0800 (PST)
Received-SPF: pass (google.com: domain of 3l41kyaokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h21so10040279wrc.19
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:27 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a5d:638f:: with SMTP id
 p15mr10637565wru.220.1615498647343; Thu, 11 Mar 2021 13:37:27 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:13 +0100
Message-Id: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 01/11] kasan: docs: clean up sections
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nG+j8ZjK;       spf=pass
 (google.com: domain of 3l41kyaokceqgtjxkeqtbrmuumrk.iusqgygt-jkbmuumrkmxuavy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3l41KYAoKCeQGTJXKeQTbRMUUMRK.IUSQGYGT-JKbMUUMRKMXUaVY.IUS@flex--andreyknvl.bounces.google.com;
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
 Documentation/dev-tools/kasan.rst | 50 +++++++++++++++----------------
 1 file changed, 25 insertions(+), 25 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index ddf4239a5890..c9484f34da2a 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl%40google.com.
