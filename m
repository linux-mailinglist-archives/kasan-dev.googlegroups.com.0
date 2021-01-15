Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2UYQ6AAMGQEYHIGXBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3c.google.com (mail-io1-xd3c.google.com [IPv6:2607:f8b0:4864:20::d3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A3262F81AA
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:10:04 +0100 (CET)
Received: by mail-io1-xd3c.google.com with SMTP id a1sf15994071ios.2
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:10:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610730603; cv=pass;
        d=google.com; s=arc-20160816;
        b=FlORPuWegDjsgLLdpMxStHeBms680vFomYpmMCBkzmSuyzi6XljzdiScwfbPbZkart
         IOfQIAWMHKOctBARuKTYJ2YDMgKB+xPIi3IoyxcQh0uktbqYi8//9qk6wCC6uRarsTMd
         80Z2kSd9Nc0UU0wSXpRIsbV4oeyZxHmq7NsBsYuoMbNyIwjVG73MwKGsjJ5V/F4BgJQ3
         cKydDaUkAA7pn5vG0Um83Ju1sUpiWKrJ2aHDIZpdRWcO/+jZA34nIdChx6DkZ6ap/662
         D6wHNO/igg3kFDFnVzJLpKdY0hqgr79IRJw0mwhhDjxB0zyp+m1Xx9VnKtRRvh7sjSsw
         o8cw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=V6PKkrJ6kD5OhvmVybPOut2LhcpirEU8HZa1FQjgsiw=;
        b=dQF9GfTC7qtDfFDkXT63JcHhZSGpWDYrnqmdMzGcm+2T1vSJmNe6ak0ZFrTdlff6US
         PxFpM+mkEMoZOS8+WlRNwgFupkBCcmtr30q07ZlPBkWWMq4Ysb3alT5gjrryBZKhydyN
         rsQ29AiBrLu0XE6xHgF9U0hM4iCGp3noTpTupKcd4NlchCwkDiW+hu/ZvVqKuRj0B8po
         7ij47kD0rBbdRbLOWfT9M/jd/sAFN54IflR+IXIenkcevZxtXcyLj+wZ+cmVxbiZm0IU
         oopxXNZNLfqNIayXoFxu49Hn6XYcNNX4BmMlI1gKB6F7Ej2U2SzJ8UPzp2VE2eDsEwMy
         /sDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cscuEghJ;
       spf=pass (google.com: domain of 3aswbyaukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3aswBYAUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=V6PKkrJ6kD5OhvmVybPOut2LhcpirEU8HZa1FQjgsiw=;
        b=iir0S5RaPvGgjvG3fxpG1OLEcCp2U94EdC0GSkMRPRhXurjCXFD3FymMoKoraEkdod
         gu1I/0ikE9aXKLhcb0oLKRoLTkJb/md9QsMUgndjIu55/CcnvkgOTmmWVYvXvLR+Bcw4
         1Ng8NnfVFb2dIQnAs4gJfM/H2X9j/LrZ/pQZ+4Ey42WvcAGBbIgHBLYudtIVMzOimdg3
         fWwS2e33w1Sx4trm+TTzoJGFmgZ7Cz6/Ncli0XQ1Nr3ObIGUglnHTwsEl6xXbbGt8UN5
         syaAfe6av4VmZfD6/Lazs1ynxWyfNiCaq3A2fORtZjBWE+L7WDbqTI1DoxNILIA6ueOr
         p9wA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V6PKkrJ6kD5OhvmVybPOut2LhcpirEU8HZa1FQjgsiw=;
        b=JlpqU9yfErGpFudWn1ZyJmEb4/gmr2ndnrWyiSAF5JR2YWb67x7SC6qpqBpFfVdlgT
         Z9dU1PNIf9sPKNkYtSuGOdjuyBe9egAtoy+oOki2qt94Ux5aE6iLhjcb03KZmzIMPKHS
         la8v2pLtF9wUUJaSMxNfZbgHi6t6FpD4Amu6fSqcc1BH1KqXmtNKmNddKG9OB+ExL8H9
         c5yibBDfJbBcSwxTWXomuC/mwtmFGSDl+tq2L0PJHGYzaMVxLfgoDb7TmIdwdE9YvWZk
         z7sNrdqOLTUWyBRpk95RphM76z9/MZajNPuzGcZn5I6WvjMWEaotzqyJ/Easd6FbsrQz
         zCNg==
X-Gm-Message-State: AOAM532QOSyrb/GiuQ1xi0E7tBd/nKaavWIGXji0u3D9n4cNvOz+7Ewm
	A0tkQ5UPuy1Z6JINgHD6kfI=
X-Google-Smtp-Source: ABdhPJzeiGBwxis8NoUsczWd6MemGjjaGWs2qnAWn805QC1069Vo31tnboW3iGuiqDPX47EdPiICTg==
X-Received: by 2002:a05:6638:2192:: with SMTP id s18mr5755612jaj.18.1610730603062;
        Fri, 15 Jan 2021 09:10:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:5a03:: with SMTP id v3ls1199546jaa.0.gmail; Fri, 15 Jan
 2021 09:10:02 -0800 (PST)
X-Received: by 2002:a02:5ec1:: with SMTP id h184mr1486494jab.133.1610730602684;
        Fri, 15 Jan 2021 09:10:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610730602; cv=none;
        d=google.com; s=arc-20160816;
        b=bpI1KRwi+zjlls1kCP8aiObR26b3ORypMjZayPGAIA+jsi3Obmt8U+pUdJX/f8X/8d
         VEMmg/uLinvh5HzPKtdfuZhDt2PeW8/EnEWC3LE0hNdi7i8J6OJ1NGiZKraVaNp/W2PN
         IyCBowmYcAOahvgM/wqXiL1URX4z1d3NNf6GQjK1rvLcXTPyIfPnJA9R6QtxUcUDdMsG
         Y/xZWnNziIPHDA3mYp4dQEFeNaKyLzXSPPVQszOyZhxsopAxfegIx4voJeCJaFODOZk2
         jB1iJCOsP+5hLuo4hs1YmpiRFiUxk7LrZ5vLQ/0SDXbhRvN8q4FnaOWwCvz2q4FAFS4a
         rHkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=1EfdZrGF6ccrmWfpU+pLhGkociDM7fhd/S74GNWvRSA=;
        b=bR8OV9ISv0XUf0hSLBaJ6AbKDfawJ72OdYP5l2dvb+6dRwpSuwqR5WUmk1kzhAYEtS
         UiivuYx3hrwBHcbswP1/+2qhQiyBhI1Yt0kfY55lwuikbiR2evEq9mSUwWLlM8q3dnXg
         wlR66/5Feho1qxo5ayu6XjejdK3jIfT0aVqUD9yK5/LYvlca5bm7LaTcME2AKHcoTv5B
         TZJPbq5B5lawcTEg5upFjixvFf+vgZ3tiIcD14n7KTNyxhYDGd3dnwj64rw23p3t7v/j
         gi+maiT9tYa0lljSTAh4Wv4rpe4qIrnV15JeeOyjDI6CbuuoFR5DOqVdCvDW0u9TDbJ/
         w9lQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cscuEghJ;
       spf=pass (google.com: domain of 3aswbyaukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3aswBYAUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id l3si486299iol.1.2021.01.15.09.10.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:10:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3aswbyaukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id b11so7871618qtj.11
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:10:02 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:ec85:: with SMTP id u5mr13036504qvo.32.1610730602049;
 Fri, 15 Jan 2021 09:10:02 -0800 (PST)
Date: Fri, 15 Jan 2021 18:09:53 +0100
Message-Id: <20210115170953.3035153-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH] kcsan: Add missing license and copyright headers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cscuEghJ;       spf=pass
 (google.com: domain of 3aswbyaukcrev2cv8x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3aswBYAUKCREv2Cv8x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--elver.bounces.google.com;
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

Adds missing license and/or copyright headers for KCSAN source files.

Signed-off-by: Marco Elver <elver@google.com>
---
 Documentation/dev-tools/kcsan.rst | 3 +++
 include/linux/kcsan-checks.h      | 6 ++++++
 include/linux/kcsan.h             | 7 +++++++
 kernel/kcsan/atomic.h             | 5 +++++
 kernel/kcsan/core.c               | 5 +++++
 kernel/kcsan/debugfs.c            | 5 +++++
 kernel/kcsan/encoding.h           | 5 +++++
 kernel/kcsan/kcsan.h              | 3 ++-
 kernel/kcsan/report.c             | 5 +++++
 kernel/kcsan/selftest.c           | 5 +++++
 10 files changed, 48 insertions(+), 1 deletion(-)

diff --git a/Documentation/dev-tools/kcsan.rst b/Documentation/dev-tools/kcsan.rst
index be7a0b0e1f28..d85ce238ace7 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -1,3 +1,6 @@
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright (C) 2019, Google LLC.
+
 The Kernel Concurrency Sanitizer (KCSAN)
 ========================================
 
diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index cf14840609ce..9fd0ad80fef6 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -1,4 +1,10 @@
 /* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * KCSAN access checks and modifiers. These can be used to explicitly check
+ * uninstrumented accesses, or change KCSAN checking behaviour of accesses.
+ *
+ * Copyright (C) 2019, Google LLC.
+ */
 
 #ifndef _LINUX_KCSAN_CHECKS_H
 #define _LINUX_KCSAN_CHECKS_H
diff --git a/include/linux/kcsan.h b/include/linux/kcsan.h
index 53340d8789f9..fc266ecb2a4d 100644
--- a/include/linux/kcsan.h
+++ b/include/linux/kcsan.h
@@ -1,4 +1,11 @@
 /* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. Public interface and
+ * data structures to set up runtime. See kcsan-checks.h for explicit checks and
+ * modifiers. For more info please see Documentation/dev-tools/kcsan.rst.
+ *
+ * Copyright (C) 2019, Google LLC.
+ */
 
 #ifndef _LINUX_KCSAN_H
 #define _LINUX_KCSAN_H
diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index 75fe701f4127..530ae1bda8e7 100644
--- a/kernel/kcsan/atomic.h
+++ b/kernel/kcsan/atomic.h
@@ -1,4 +1,9 @@
 /* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * Rules for implicitly atomic memory accesses.
+ *
+ * Copyright (C) 2019, Google LLC.
+ */
 
 #ifndef _KERNEL_KCSAN_ATOMIC_H
 #define _KERNEL_KCSAN_ATOMIC_H
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3bf98db9c702..8c3867640c21 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -1,4 +1,9 @@
 // SPDX-License-Identifier: GPL-2.0
+/*
+ * KCSAN core runtime.
+ *
+ * Copyright (C) 2019, Google LLC.
+ */
 
 #define pr_fmt(fmt) "kcsan: " fmt
 
diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 3c8093a371b1..c837ce6c52e6 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -1,4 +1,9 @@
 // SPDX-License-Identifier: GPL-2.0
+/*
+ * KCSAN debugfs interface.
+ *
+ * Copyright (C) 2019, Google LLC.
+ */
 
 #define pr_fmt(fmt) "kcsan: " fmt
 
diff --git a/kernel/kcsan/encoding.h b/kernel/kcsan/encoding.h
index 7ee405524904..170a2bb22f53 100644
--- a/kernel/kcsan/encoding.h
+++ b/kernel/kcsan/encoding.h
@@ -1,4 +1,9 @@
 /* SPDX-License-Identifier: GPL-2.0 */
+/*
+ * KCSAN watchpoint encoding.
+ *
+ * Copyright (C) 2019, Google LLC.
+ */
 
 #ifndef _KERNEL_KCSAN_ENCODING_H
 #define _KERNEL_KCSAN_ENCODING_H
diff --git a/kernel/kcsan/kcsan.h b/kernel/kcsan/kcsan.h
index 8d4bf3431b3c..594a5dd4842a 100644
--- a/kernel/kcsan/kcsan.h
+++ b/kernel/kcsan/kcsan.h
@@ -1,8 +1,9 @@
 /* SPDX-License-Identifier: GPL-2.0 */
-
 /*
  * The Kernel Concurrency Sanitizer (KCSAN) infrastructure. For more info please
  * see Documentation/dev-tools/kcsan.rst.
+ *
+ * Copyright (C) 2019, Google LLC.
  */
 
 #ifndef _KERNEL_KCSAN_KCSAN_H
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index d3bf87e6007c..13dce3c664d6 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -1,4 +1,9 @@
 // SPDX-License-Identifier: GPL-2.0
+/*
+ * KCSAN reporting.
+ *
+ * Copyright (C) 2019, Google LLC.
+ */
 
 #include <linux/debug_locks.h>
 #include <linux/delay.h>
diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index 9014a3a82cf9..7f29cb0f5e63 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -1,4 +1,9 @@
 // SPDX-License-Identifier: GPL-2.0
+/*
+ * KCSAN short boot-time selftests.
+ *
+ * Copyright (C) 2019, Google LLC.
+ */
 
 #define pr_fmt(fmt) "kcsan: " fmt
 
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115170953.3035153-1-elver%40google.com.
