Return-Path: <kasan-dev+bncBAABBMF65KJQMGQE4EURWAQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 91C4452224F
	for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 19:21:53 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id e8-20020ac24e08000000b00473b1bae573sf7517322lfr.3
        for <lists+kasan-dev@lfdr.de>; Tue, 10 May 2022 10:21:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652203313; cv=pass;
        d=google.com; s=arc-20160816;
        b=DKpzS2Kihmfk4O/IQd7ZwNjeABXRxiUeo7B56Y2uuWinWdvJ46uTAM9fWfrIWzgms4
         cGO17BNY7hA9zKA5gy//nO1cENAppjhPJ9GkuqkaJN60SSb/5fGkGN5n7sieFnf/RloF
         BPPJoVuLrfrcvlpH0KaHork/hHm9p6PhrjpOfCW9zGXZiBxaSr2iaDB5hQp1XB04mYqo
         EOjSuboB0xYxWTpvqO6V+PDk66UehoVmivsIZBDOZBi954QpA4wVCZ0gBaNE0BMs/8E2
         3/sHsYu0P31m3WB/zYEL4tUs42XuQZ6bkIMSYsOIxbNoypSSZhHnEiJfhlVrQwTl49qX
         vd1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lb7FmDeX+HhXI60z6OT9bZiUXm6LHwu93SN5UEgjhq8=;
        b=fI7Kdw5g773j5CiJsUY2Fat0GlkpJnX34zOTD1eWAuUHF0I4GSiXsAMkeoQCbRs8li
         q0FBEnXXv1nWaoI6w7mRjyNA+KXEQatyBBwUzg4bOCCiNnfQh8/v9yIl8NCzJTp2isZU
         V6vBxppaBbKQGNUY2GLqD5Lv1z6Xi5DAN/1u2izbmIMLwy4kC+VNwWdNGYfB8vZ0FA1y
         pHaTKE0R9nTNEYJBYklbEat01JDlSTTfic/Mvk7YByZLKXFfmgGo/n1zxOxsSgpy+w9r
         Thm4D0xDD4mZJN55uyj5Lnnk1FE09RFNhkqDeN/DjopO2yMfHQNDBI4XE7zkBoXDoFo7
         qxPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FdizoY0L;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lb7FmDeX+HhXI60z6OT9bZiUXm6LHwu93SN5UEgjhq8=;
        b=Pn5x6zRV7rm2E2Whkt7kUD6IDeiZPr5qd11IqB1MjryZAAgdbDZMHjujHmz3WI92bI
         IyDprOxwvNmNy3HN7DpM3Tgm2wdneZni+9m5/WKm8kOUHjK6sKaNeUaXSX8Nr1Hfkkio
         m0yJ/9841Vavc3d4Hr601N8H7bJYVE0zDxCKtc3vwGEwkX8qRduxylnB+KH+1jKnUW79
         tioexyE8y4UAIR6b6lFR632F+EmMd04fh8cKj8R/mN896DTGPbTER/wPyznFq8crEYo4
         j88LYw9bGO9pAesgJwYnP5Nj5sk6Vq2yzPVIZMpoiZK//gUgkznslE/DT23dsPEC+pcw
         FNpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lb7FmDeX+HhXI60z6OT9bZiUXm6LHwu93SN5UEgjhq8=;
        b=EqohHeNe+lPQC8sgo3MNfMSgW8E6q8jYxnGPLkfmbJFPwy7CzFXvlnAeGBRTRtxXj2
         /eMtZ6vFypFa6kgiIPb88930x+VlpyCG2NTEr4G8UfNTrEg/yRwFqRO8PTKvvmNTVW3A
         Sd9JFulZxagogXvN/0vvHjvVfJ8PLxP333xCg87xmrHPK1HrDReDkrK4F2RcwsLwod25
         RcUmLuRbb78X2eullLoxClI3V3HZODOw6TlvBoayJ56O9J4O5us9TDEymVZGFuZcoKxO
         6BnCAczGX2kVF3oVux0tnODIdqaDF6V8Djuyg7/TC8Ukkg+kBbG3DEiZsIRqDLtEdBq2
         Sfcg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533jt5Dij1ZHNsTHwuReIbtLS2hdzTEOH6wdL9Ueg6MxgCYpmrhU
	eNX7+SZHW/0VH1I1rzBpYt0=
X-Google-Smtp-Source: ABdhPJxoR+j9itim2mILgqWbFn7YXFyL1x+FfsNxH1knS+k2ieCv4eA4TnnlrP3lmXNJFjF/ggTFPg==
X-Received: by 2002:a19:a418:0:b0:473:c1af:fc9f with SMTP id q24-20020a19a418000000b00473c1affc9fmr17028799lfc.575.1652203313014;
        Tue, 10 May 2022 10:21:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:b1c:b0:472:38f0:bc75 with SMTP id
 w28-20020a0565120b1c00b0047238f0bc75ls1615303lfu.0.gmail; Tue, 10 May 2022
 10:21:52 -0700 (PDT)
X-Received: by 2002:a05:6512:20cc:b0:471:f6fb:dac9 with SMTP id u12-20020a05651220cc00b00471f6fbdac9mr17033546lfr.475.1652203312172;
        Tue, 10 May 2022 10:21:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652203312; cv=none;
        d=google.com; s=arc-20160816;
        b=hvjZRHf/sLF6UOwM5Y2BE4DPCsUTqWXZq3Pf6J7d494IngaSNjdppL7m8rDp75AYQc
         TDfNBF8QQA3KT8TusfZYOMKtNkcU5NEGe2R4t8Tw4Os+a38nkD+sB23FTg+H5wxdzeF/
         LxUb4jct/5l/+TNlsnizxTRC0Sw5bmBzYXJbYTbGMROngWM0TvAj9GMntxVsNwG6c4Qn
         pin4ehsZKn2zfLgOUHW6cWLXpHf0vU7oUZKq+OF/sD8t2rEdBZdFq2pQSs+gujNjBvr2
         JFkrJG5ihnrR46hCYajtr7YSQDoFZ6nMLAztWbXKSv1GuBiw6BnzVu8tpl5YOloDO5i+
         eaJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=nXXfBfocIvVCxUKFufjfWD4rJkOLYYU+cQFGctoe54A=;
        b=wpDXrwZjyGh2UyvtsdSpBU4eNZYrmVHBji/hIjHkKTBrOXH2Cy8t3xXaj7XHvL9/GP
         bpWRbV/Dz8EkJsxEZD2tAhauYdJsGT7Ch/IqM7bVOPEY0cdIcxlgk+HnPBwNd4ehHA9t
         VaBhsos5ChAS535Z5eHoc88Fv/GNtvepgMlk/Yc2XvNfpiqYVVmzaWjeBWNqM2Mk7iSn
         MdmZ+btgGmXoqOko9hwH3PJVwUDJrt/tRFtjOtkIDNaZJgP1mQK0ccGVLRLVXDVGIDLU
         ujzn8JBNsTT6tODTW7uYLMcfKdagcToiOMA4D9AI1CjIr3PMXLJYtKE+IKyMtJK1UqSJ
         3AnA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=FdizoY0L;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id v8-20020a056512348800b0047238f0bc72si859832lfr.12.2022.05.10.10.21.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 May 2022 10:21:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 2/3] kasan: move boot parameters section in documentation
Date: Tue, 10 May 2022 19:21:47 +0200
Message-Id: <870628e1293b4f44edf7cbcb92374ff9eb7503d7.1652203271.git.andreyknvl@google.com>
In-Reply-To: <896b2d914d6b50d677fd7b38f76967cc705c01ba.1652203271.git.andreyknvl@google.com>
References: <896b2d914d6b50d677fd7b38f76967cc705c01ba.1652203271.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=FdizoY0L;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Move the "Boot parameters" section in KASAN documentation next to the
section that describes KASAN build options.

No content changes.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 82 +++++++++++++++----------------
 1 file changed, 41 insertions(+), 41 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 2ed0b77d1db6..1772fd457fed 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -94,6 +94,47 @@ To include alloc and free stack traces of affected slab objects into reports,
 enable ``CONFIG_STACKTRACE``. To include alloc and free stack traces of affected
 physical pages, enable ``CONFIG_PAGE_OWNER`` and boot with ``page_owner=on``.
 
+Boot parameters
+~~~~~~~~~~~~~~~
+
+KASAN is affected by the generic ``panic_on_warn`` command line parameter.
+When it is enabled, KASAN panics the kernel after printing a bug report.
+
+By default, KASAN prints a bug report only for the first invalid memory access.
+With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
+effectively disables ``panic_on_warn`` for KASAN reports.
+
+Alternatively, independent of ``panic_on_warn``, the ``kasan.fault=`` boot
+parameter can be used to control panic and reporting behaviour:
+
+- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
+  report or also panic the kernel (default: ``report``). The panic happens even
+  if ``kasan_multi_shot`` is enabled.
+
+Hardware Tag-Based KASAN mode (see the section about various modes below) is
+intended for use in production as a security mitigation. Therefore, it supports
+additional boot parameters that allow disabling KASAN or controlling features:
+
+- ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
+
+- ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
+  is configured in synchronous, asynchronous or asymmetric mode of
+  execution (default: ``sync``).
+  Synchronous mode: a bad access is detected immediately when a tag
+  check fault occurs.
+  Asynchronous mode: a bad access detection is delayed. When a tag check
+  fault occurs, the information is stored in hardware (in the TFSR_EL1
+  register for arm64). The kernel periodically checks the hardware and
+  only reports tag faults during these checks.
+  Asymmetric mode: a bad access is detected synchronously on reads and
+  asynchronously on writes.
+
+- ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
+  allocations (default: ``on``).
+
+- ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
+  traces collection (default: ``on``).
+
 Error reports
 ~~~~~~~~~~~~~
 
@@ -208,47 +249,6 @@ traces point to places in code that interacted with the object but that are not
 directly present in the bad access stack trace. Currently, this includes
 call_rcu() and workqueue queuing.
 
-Boot parameters
-~~~~~~~~~~~~~~~
-
-KASAN is affected by the generic ``panic_on_warn`` command line parameter.
-When it is enabled, KASAN panics the kernel after printing a bug report.
-
-By default, KASAN prints a bug report only for the first invalid memory access.
-With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
-effectively disables ``panic_on_warn`` for KASAN reports.
-
-Alternatively, independent of ``panic_on_warn``, the ``kasan.fault=`` boot
-parameter can be used to control panic and reporting behaviour:
-
-- ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
-  report or also panic the kernel (default: ``report``). The panic happens even
-  if ``kasan_multi_shot`` is enabled.
-
-Hardware Tag-Based KASAN mode (see the section about various modes below) is
-intended for use in production as a security mitigation. Therefore, it supports
-additional boot parameters that allow disabling KASAN or controlling features:
-
-- ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
-
-- ``kasan.mode=sync``, ``=async`` or ``=asymm`` controls whether KASAN
-  is configured in synchronous, asynchronous or asymmetric mode of
-  execution (default: ``sync``).
-  Synchronous mode: a bad access is detected immediately when a tag
-  check fault occurs.
-  Asynchronous mode: a bad access detection is delayed. When a tag check
-  fault occurs, the information is stored in hardware (in the TFSR_EL1
-  register for arm64). The kernel periodically checks the hardware and
-  only reports tag faults during these checks.
-  Asymmetric mode: a bad access is detected synchronously on reads and
-  asynchronously on writes.
-
-- ``kasan.vmalloc=off`` or ``=on`` disables or enables tagging of vmalloc
-  allocations (default: ``on``).
-
-- ``kasan.stacktrace=off`` or ``=on`` disables or enables alloc and free stack
-  traces collection (default: ``on``).
-
 Implementation details
 ----------------------
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/870628e1293b4f44edf7cbcb92374ff9eb7503d7.1652203271.git.andreyknvl%40google.com.
