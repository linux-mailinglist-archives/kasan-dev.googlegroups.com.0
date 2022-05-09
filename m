Return-Path: <kasan-dev+bncBAABB3GM4WJQMGQEETH2RYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 69A705204F1
	for <lists+kasan-dev@lfdr.de>; Mon,  9 May 2022 21:07:25 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id j27-20020adfb31b000000b0020c4ca11566sf6115890wrd.14
        for <lists+kasan-dev@lfdr.de>; Mon, 09 May 2022 12:07:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1652123245; cv=pass;
        d=google.com; s=arc-20160816;
        b=XS3UcYylVCrranYFxDfR4ERlG6gFRgTuP07vhXDrzZlmiMeSIPhEb0QG0AIy0MhEGm
         2KFVc2GgAWs/CCaElEB2aNwr2/ReaNg8oSd1zRvyAmLetoFSkvmZuQvjSLYY45rARlJq
         12hRajNNfeuyg7YF6BvV4MfOoHqRPRtVM6m2ov4KqdcxB8u03DXVkyHUyvqPzHTB2xMK
         S5GWaw7dT7BtsffuyJMzVImC60Pcq5B6+MTS7b3VunNLxwDFhQmKL/kadqT0KjBH+Ipu
         gxuPiR2K0+SRAWbZKr23NDk9Rp0WMiwzRh4p/Kejp65ixLBmIr/g6PhVmgQViZVL6wa/
         ZNBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=w+IQm+ij37/YHy668zf7OMFgR3FTQ09YXolYb+FCT1E=;
        b=bBbWxaMqP17LYzQYEweRIJVqWsG+boy3tEeFTGtXsgS6l5CGy+Lzb8xbPC2dMNWFVi
         plPBK9TeyiMRe73pkwehr9nMiNKV3IhqK+NONB2LrBI2t9hLboye3TZ5OgUN8bYLGDjD
         vUrC81cxutJXUaXMEVa7SQpj4alVngiksvT6L9yFviLRhcdCq8yvZVxBMZ3mcG/Wrc9/
         ayMqEvrm4rSEW7yVMjvVoQyDeI/eawXOu6ysDuNcJuOol+cf1YtyGmb0Mmc+VLO2Bw3E
         478IAGKS59k8z3TjkVYs9mC1SXOCp8g3cv9S3uy5FZQvdTREKcI6yT/GoExX/BbgoGCV
         LL3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bSVeJpsx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+IQm+ij37/YHy668zf7OMFgR3FTQ09YXolYb+FCT1E=;
        b=ONQBYCOa4WzqI5BNif+1r8UlsfICBWG9yU96y5G9Gh9y3W5mk+lkO/Y7jUJf3Sd16R
         IbZ54YHkHX5gryndmdopSp/03vjE9OQs3QCdc/slYfG+2WjdeOnfyv7BMJGAQbJ5w/6K
         VV5trkLWx6WU2HD9NX18tvxWXo/rH9vNDJd4KRENIUyZbVHfRoeDe5qS/eZRT5jLcbqp
         29wra6a2P31gTNzzmD9f32bA4ffDNHQIg7qFD+JZT0trObhe3UdRMGjKItHXkA/i7wPN
         +DEeFQQkNNTat5WVDR2D7i2Psbe0GCNOZzJEItnKM3eB/VCCoTUBDNm/O1uAGn7Fjbly
         2DbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w+IQm+ij37/YHy668zf7OMFgR3FTQ09YXolYb+FCT1E=;
        b=mf2v8xDdTsHZbTBNdgsdzTzBftditKtqqeWJJPKT3ly8uY0ukRdrzsEdTgBosC0+Q/
         2X5lTYnnOIP4JPfkFu0Yj5IOVE27DCqpQ38TNHfstBW75FQujDIRqOcvU0/F9AFJnZdR
         8NnlDxlCyxSo58itdREwvTubWw/BhGL2FJIDD85/56G9BMvgFiDPuw6hY6oj1MES3qpv
         t51eAbcmHyxiom7Dg/ysjLMpQlnvQZeEu3bqmAeKp9qvvJo7Kw3DPwWzNUnXa05AhL6e
         U5j1Mzb3m5qNF6AZr2iIsfj1qzEjCgdYqgUhKjCuvQ8aYCbnvsdI3pGlT+BpK+KGNajq
         EaXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Y54RxKF29s+qJDlFRdSyGBatxwAP6NSS/oO1bYOsg9734PqiJ
	L4uuXqKSQ+4UXSgW2RKVwks=
X-Google-Smtp-Source: ABdhPJz/SUMIghxBQWjEzXgYf7n2XGwY/3IJngLWMcO8ixM085hAY4QdgS13hzMT3JTwsBtOBesHGg==
X-Received: by 2002:a5d:6391:0:b0:20a:e4c5:c247 with SMTP id p17-20020a5d6391000000b0020ae4c5c247mr15474098wru.516.1652123245065;
        Mon, 09 May 2022 12:07:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:64ca:0:b0:20c:bb44:bd7 with SMTP id f10-20020a5d64ca000000b0020cbb440bd7ls1970315wri.0.gmail;
 Mon, 09 May 2022 12:07:24 -0700 (PDT)
X-Received: by 2002:a05:6000:707:b0:20c:4fd8:1d61 with SMTP id bs7-20020a056000070700b0020c4fd81d61mr15692444wrb.407.1652123244312;
        Mon, 09 May 2022 12:07:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1652123244; cv=none;
        d=google.com; s=arc-20160816;
        b=q5+EkQW6LRAmo1/419pRauEl1RNXgGGSIY33udMhrWCwdBAyICCeoKCIroniJ0eoxl
         d3DtR2E3ZPKO1TkLLB1TgxPSQNAIhpnH2YfdrExeF6KCpzjrEpm+21y+K7sFthuxs1s2
         yBL8RVmSa4lut4mIHnLIDnkT7nnhxDT56hb9+2wkR6eFNrCL8vHVpiaw1mKfqyVfr+I0
         UpsrahZeKPp5+Meh97t11ruJwTYVcEzAdR6MYDojJtodY+LSj1avedfdptrofm1K+/P5
         jSBvM1WGzR7BxvEDxSd3APTH/1bxC3jj8efj+4V/bXQzs/JlQurBDrHFou7mitpm8X9q
         rQpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EkFD1fi2DMJyDMqe6JC23GNJMEwl8KxQZeJUIWsDFSE=;
        b=Ly82Snede+0/OFXDkWDLxdnMgd1pH+LetpaflmveL7aUIfRbkv6gS5tJ0YTVIkdoPs
         AonUaZw2/UJkoeVpzZ/fGhI8YfCFDKdnx77jqQtVBUO7sgcb5ovoMYAl/ZhbOVMKpEHo
         pkiv+UWPhQHhqZbkOG0V24I7eVdg/EbWU1q2pWJBXoSZW93CgGnDm+K4IpG3QJJDgJqe
         AubfBVZQMiW7OPbvqVDBH+fNxO5072MzzNTM8p5EjFZ2Ppci2KWHy04HM3HDM40Qvj7d
         Pl579WTYngQ4CtdPI/RwiA0LMIH11oJb8ktzIWlxFkbcmML8ybtmSgCGlYUdqFs3aZeQ
         TFCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=bSVeJpsx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id bg5-20020a05600c3c8500b00393e98f67a1si8156wmb.1.2022.05.09.12.07.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 09 May 2022 12:07:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 2/3] kasan: move boot parameters section in documentation
Date: Mon,  9 May 2022 21:07:18 +0200
Message-Id: <ec9c923f35e7c5312836c4624a7f317dc1ee2c1c.1652123204.git.andreyknvl@google.com>
In-Reply-To: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
References: <5bd58ebebf066593ce0e1d265d60278b5f5a1874.1652123204.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=bSVeJpsx;       spf=pass
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 82 +++++++++++++++----------------
 1 file changed, 41 insertions(+), 41 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index aca219ed1198..7f103e975ac2 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ec9c923f35e7c5312836c4624a7f317dc1ee2c1c.1652123204.git.andreyknvl%40google.com.
