Return-Path: <kasan-dev+bncBCJZRXGY5YJBBDGZQCBAMGQE3AWJ5BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 91B2832C3AA
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Mar 2021 01:40:45 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id o206sf4703151vka.0
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Mar 2021 16:40:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614818444; cv=pass;
        d=google.com; s=arc-20160816;
        b=kfeDlqzBP57Y3Q40au9egqgP9KQeFmdGd48GKkTTwnqxjeel86XFJFR3w2a828pgyN
         C+uswWFEcUTlifWdLcaAbtBZ6HVls+a+oStjiZFU+ZuhbqdfKo7MwbiJnbJv+ocUFfFP
         mg6v5ztSVptb1nsDCcY4NlGR1p5QQCsgWn0pQa9HUxPPUhgnyxhUK6UBnyWCYU4yP2/p
         w3ETBm3CKuePNHcvNMSU0RfnUgoPvntaCsgG6xkmceM/WSfXVGT9y9wqyQwyDYO6UO7f
         6sGeOgzckP6DSAr7OKJ5C+Io5SJiLLPsl3vP9HI/txB9NLIX4ZXmQSuqsQ/YxQ5ot09T
         4m/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=zHsNUAwGNmERKPnjV7U6WB9169KXXgGiE56Jqaf4RXg=;
        b=MBETbBMsGXwZCxCTUr+QbNHSTGVoc3L313oIllWV9p7+AFpkTTNBDukTZ/Ca7dvaHp
         HMVTpRUWDaHHtABijzli5Q2EIpyXEqN9vV9CGUhjVWDsgvGDF2QXrCzN0LcLBO1q+A45
         Ty2mVk4GIS7JT57ThyQBJxFfoY5F6RLNOzVt5fKENG4+a8KK78aGlc0QqDQatGSz2nmG
         79/xAEnLTV4gH4n+vSfcLtbjtjdDklcZZWdOM5m5PbmKl7HyK6cRDmHzXjoNYUznhirg
         wHB6hqlmrw6ILBQD2R5I4eMZakbRFimI+/w6VhQyfRvyjhDTe0P77sZm1bQqlyWqYFgm
         HZkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lXqsi1zi;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zHsNUAwGNmERKPnjV7U6WB9169KXXgGiE56Jqaf4RXg=;
        b=AF2sdAxEti7WemvepAOR5PAon1C077CaAtVEDzzRawUCiG+b44Cp6TCpzC+eRFv85k
         /bdV5q4qsi8zId9c520BtJKsbdUDLTZXMqIhX3ktEpPpP05JY/Lk0xsbiMV89kEHgMdr
         4jC6qXOQVCgZCbneaZOkCP5RSlIezEfGk1SAMvvZX/6ggxqmXSCDALG3lTfpj1m4odVz
         53DOMs1ofntWhdt6A++UjEu8TTAHv6gLZg6i35ZLht5Fasaeb4VcIhW44+vPEB8fkJob
         AEHSyyk1kCZIy0GfW/97WIP0BDj2TcPzOGXC429/l2I6TDXG+au4hdSvuQem5vtfS2wc
         6x5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zHsNUAwGNmERKPnjV7U6WB9169KXXgGiE56Jqaf4RXg=;
        b=d5bpeboGHQNKjV7zM3/gfjcKHVuzbsTYkLhlA3y4UPjZQCUi0/k1YW8+s1hY7R3LVX
         2cvOeLas6WP666klmztBYmeSd+wSdlbnzeqZwyDuQH+WaQlXdnaOF7gaFAUgG7j15RZr
         nwKKw0Y+mLyAGIxBPrfCljnueUi/qc8gvlue+DfdcxDB6xqsBrEbxFAOSghX3kqp0d7Z
         7OVxS1/7CB/8gnLXijrNZWZczd7SNUtKhEbv/E+zTJ4pznTrzzs8BSBXRUStl7Yh1jew
         PRup5jEbFlxs47DItUffnJvYcPrcaisxYogLnlAzwSyr8KuWDmqvBvWkOwGflBQYZp5r
         5LgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532PNeqDLcOUGOg2xfitne5mZ1yxQBe+EHAJSSzqp4SOUrd+czoq
	B8WT5dmFAwkP6j8OJKwnzXg=
X-Google-Smtp-Source: ABdhPJxfGEbQcKM9FzIEpcQaQy8d2ZanadAubIlpJ/jEsgSijlrj519cVypqs471bMu3f2Yd+YFNBg==
X-Received: by 2002:a67:2283:: with SMTP id i125mr1245286vsi.21.1614818444363;
        Wed, 03 Mar 2021 16:40:44 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:6c44:: with SMTP id q4ls341557uas.7.gmail; Wed, 03 Mar
 2021 16:40:43 -0800 (PST)
X-Received: by 2002:ab0:1005:: with SMTP id f5mr1025197uab.79.1614818443923;
        Wed, 03 Mar 2021 16:40:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614818443; cv=none;
        d=google.com; s=arc-20160816;
        b=lDavwRhinP1JnTxTyO3OpR/n18/Dj9ff8jkgr8Y4XyIUqlz1hoHFSd8cHXc/HsRx90
         wMLO9NEwGEP1wtgij2blpNDGX51hR2TQ/+dqwuageqQsF9unn7ae9105Mg3MJtlDCaP9
         W5qxsOjLMVeBgcJVb+3h+hp9vpRY5gYd0NN1Ih4nMmlFDeSsEkz4GMj0wDgwaEHhldgf
         DaAN9n87TObCN1/CMSc0K9fpjf/kpcUS0BUEXZdK7LlhyjIIc3cgYt1wQSwzKY1PoXR9
         mw+sTvFnpnadBspFYqUuq1WYXREiSPGHLVehgjGJevelI/iET7XbXB4TxNiIYfiFTTNy
         U5jQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=AEDeJKaLb2CQuUtui+V5uC+rMZVVCrwfDkmRueAM/eU=;
        b=GmvxTJDstRy4fqaUwgURBtO4ir8yX0n7IXApnrdn4yXJTRMmBAaPwRTGzvM4xy4qfZ
         OZU/S3nTdaBGI5aH5VOtuQGOYDiA88KE3Ux5NrgF9J8AsIfH7cNTgAa6BHFoBgxCl7CG
         ofAaMeYcsINd+rtSDs6w1d7T/3Kh5Se2PqC6I7t/HRC/jQyUEGGVB667Tz2zMXQTogNo
         FjKhcRORtwXIMZMfsIwaKMu6iTcLfX71+60277VwQciHWfJDS+XqJZKdJJqzZfy/rYrM
         G2KZ1XwdRp0IMmDAzbg7l3mZy9TEvrPscC6iFhR+aesLaalXDmYoi43gGLRoGaFBpqJ1
         dWCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=lXqsi1zi;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w26si76200vse.2.2021.03.03.16.40.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 03 Mar 2021 16:40:43 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id C7EF664F1B;
	Thu,  4 Mar 2021 00:40:42 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 4/4] kcsan: Add missing license and copyright headers
Date: Wed,  3 Mar 2021 16:40:40 -0800
Message-Id: <20210304004040.25074-4-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20210304003750.GA24696@paulmck-ThinkPad-P72>
References: <20210304003750.GA24696@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=lXqsi1zi;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

From: Marco Elver <elver@google.com>

Adds missing license and/or copyright headers for KCSAN source files.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
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
index be7a0b0..d85ce23 100644
--- a/Documentation/dev-tools/kcsan.rst
+++ b/Documentation/dev-tools/kcsan.rst
@@ -1,3 +1,6 @@
+.. SPDX-License-Identifier: GPL-2.0
+.. Copyright (C) 2019, Google LLC.
+
 The Kernel Concurrency Sanitizer (KCSAN)
 ========================================
 
diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index cf14840..9fd0ad8 100644
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
index 53340d8..fc266ec 100644
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
index 75fe701..530ae1b 100644
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
index 23e7acb..45c821d 100644
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
index 209ad8d..c1dd02f 100644
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
index 7ee4055..170a2bb 100644
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
index 87ccdb3..9881099 100644
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
index d3bf87e..13dce3c 100644
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
index 9014a3a..7f29cb0 100644
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
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210304004040.25074-4-paulmck%40kernel.org.
