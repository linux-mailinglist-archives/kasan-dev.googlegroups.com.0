Return-Path: <kasan-dev+bncBDTMJ55N44FBBVGYU3GQMGQENFSEOKQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id YAnBL1asqWn0CAEAu9opvQ
	(envelope-from <kasan-dev+bncBDTMJ55N44FBBVGYU3GQMGQENFSEOKQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:22 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D21821545E
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:22 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-389eea46132sf82808981fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 08:16:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772727381; cv=pass;
        d=google.com; s=arc-20240605;
        b=DTL5BN+65wuzaLGhiFxRA6VguIrDVOagqUZcoVoVgOXdUBMEV7l8uLjlf7O26xMxw9
         s+ws2ucXNTVVlwepsg0DicRdXLAAqF9POJvK+faMAJj+5+6yruz90M+dUP42hvHe1/pN
         MK1uRLL68W3bvxOSoy/YoGxtAEd6Lnvz1G0C+1W+HUuInkiWpKSAWDNi1d3GseLFQOB1
         Bu2bUs9XRlnJtEwtYqUH9Et1zPJ8FnKHFQVZpT9+XC7M7fKo33NuWIeVStpWIkewTqvc
         QNEwO9oS8a6v0Uio2uwQpUO8x1yY3uVvkWzHuAZFCjYQ/sG1OZObrWMp9IWkBqNiqUof
         J4tA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=vDubjm47FkaK063jD7IIZZuk/G81qr7gUak62KW2cvw=;
        fh=FFcNNdZU4z/4ppTfCcAfFLRfiw73WSkbhLfCD2hdY7s=;
        b=e4A5wSZLaGC/D+U5Jtwi7j00dEAPyvVP5ifxzRxPfWg+Pkz7z401dBOEUKVc9Rdynh
         hnMb+plwgHARQx3jQUy0YURPV7hPpT631KYdJmvO4XljoazPHMXO04wg7EpvpurO95iL
         lmbMPJF6BXKO+P35EYJ1Hny7hdnHFIucX/0MtNdMXYA4+BvbUqJ2A/qolYEDi3YgBlNS
         pa/HCHVD591YnvNUtvkrfIuxE51D3+RC8hEHTjLAkhUtJLjtmqtgZqBcpbrnMBbhD37l
         PU2FcNpTiggSgb2RIpE+s2UhX9vTIvN4kVCQmxT2WY4CufaDzkCeb+0rodXHphtDwQDP
         OP0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=cQlbazqd;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772727381; x=1773332181; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vDubjm47FkaK063jD7IIZZuk/G81qr7gUak62KW2cvw=;
        b=MzJbCukdBElX3yJR8TnusqyPx/P9BUIArY5Jja00mz4CUCS/6gamkL4qBEhE6KYC8c
         sh98m1+MxK4eDT0Hd+JTkmw5TG1Pnhj/kNuIbk0zhIQwdYH1rsueb3zPB6SDlzE0uqKn
         IYWZgSB0sPEniJOAabIZZ6lPRXP3jcrJRDLxHjssA4ygNK292qmM0qkWS6ao55+23dLN
         2ZTcCsQmGnd64wF9LztQDCDDW7/NTJ6AxNAXiGbsMxRvSKsAvmUIPSDodDsiwgcmU/3K
         iC2TlPdIpbwDLJ3teZPsP2/oulIt5el7LFR8wGHvoyoznMARIsrvlmBfYdt6hHr1rhwB
         yxpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772727381; x=1773332181;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vDubjm47FkaK063jD7IIZZuk/G81qr7gUak62KW2cvw=;
        b=cbGwMRNijSs/WNq1fvAxun4F18ab9XN2sE+kfj1nVfCnht8FQOHQsK0D1N/63yKT7U
         2ePKcaC7j2ev63+zBZCl6s9YKT4TibP/rE7DtNXw77QmhdWbpgXtIyvVSW1FghbSl8bT
         XM+gqIhIeDhgAfM3yn5gqGxk36K9cHQq2qcPk/UgSg8AV+ItJ8s6v7XHPTDVoN/6Mw+M
         3l2fCiAHOWWpEoRFqnKQn5bqLPwSRUjiRoCvhASZXJAVakG6r/zisukcWRwP01u4tTP2
         jgdjJq6xJm89OX/Vr9MLPy5fCBbBxxdjPjraGoeODzba2eJ4E75ILML6GSOQJSNryHWJ
         b2Vw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUnM0Im/vyiBvDuaUIiAhsbHz+HoXoVQC+dmlJJFhjZzbtltXkpWKId7TcehVWP6FP5QrLEvQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywu5R+MPrwlgAsC/c65s2yrJol0FEKTqC+ysfiyC5H8dybAszWl
	jgh282IG4UpYCnO11uwFvqwxQzWV7AkJKVecEEuE/lk+lM2K5Ls5gmI6
X-Received: by 2002:a2e:9255:0:b0:37f:d9ba:747 with SMTP id 38308e7fff4ca-38a35129c39mr8137981fa.5.1772727381345;
        Thu, 05 Mar 2026 08:16:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+F914vgMx2JCFxcqGojute3U34vvd2KAdonLMzQm1S6LQ=="
Received: by 2002:a2e:a605:0:b0:38a:2e2b:b0d9 with SMTP id 38308e7fff4ca-38a33919a6cls944821fa.2.-pod-prod-00-eu;
 Thu, 05 Mar 2026 08:16:19 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWZ52/6Lk7q60zn9hQmVO9btwslRAV506/B62Z4k9mzmT1JYhxEW92y8iwMheLTbLzhGNhuwBIU+Vw=@googlegroups.com
X-Received: by 2002:a05:651c:620:b0:389:df67:64ef with SMTP id 38308e7fff4ca-38a352a4a0amr8055631fa.20.1772727378723;
        Thu, 05 Mar 2026 08:16:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772727378; cv=none;
        d=google.com; s=arc-20240605;
        b=a1gvOI/Ol8w5yN8CYUPO+LIOu1K0Q2jdkxima79AGZyfG7oVhlzmttGakHC1C0Wtlv
         suDeL5YXTu/9q0d7R/wBbSk9svgOZUiE1pxU5jPgG4JLZrCrnFN6A3RT+3BXYKEULzZW
         3UgGzsiIht3HYxxd33o9GQCRXjRW3+xu6kr0VKCz9Gij9JXYza4x734nHNTm2eyqTEUZ
         LAFttML9xDfoP0abDvLQ6SqfbvFhK47mV2d4bTP3TjKqmD8Lyf7Y3/tTv8epATnDFb4z
         RNC3i+p2zzC1Vu58t6HD+Lk6cPTmZRat9ej1jgQVotoVQxQHdZ24JruAIo9ittjrXv+9
         a0qA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=d/8arRnvKp6yW6gD1fp68y2qdqj0ZVn0huQFIoPOgBA=;
        fh=ULATwvCSm9MH98k3lnaJHTf9T27YdHslpejL1iZxPpg=;
        b=XsUebp8fXIPiVIMfcCGuAZV0TX7Zr+ySL42fFxvMNsxVs+4f6q/H0tO4Eu+vniwIvW
         l04PZ24n9vBg8RcROhSUVg3xOVCD+0tFlPtjA/1BcsZqxwpInZ0h6R1Eck12yAslpXrU
         xEQcHDwn5E58QXOdgkhD1QQCDC58N6uveNfthNvt1CC/ZRfiwu0Oew9FyySODeVqrJNw
         g9JcPlwCCp7AMGAT60ZFm7H4kQqPBrVntcB0kN75hrntgYc5oeUisgE9iqAeuJg6SWHL
         XKdCRXLA5kCE7EFYzhpGFgXtKBWqzAjrLrtdEYdSVQhxPL+dQHg+LypcXM+RsHaIAVL3
         JK8A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=cQlbazqd;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-38a323322aasi814441fa.0.2026.03.05.08.16.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 08:16:18 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vyBMz-00GqrH-4z; Thu, 05 Mar 2026 16:16:13 +0000
From: Breno Leitao <leitao@debian.org>
Date: Thu, 05 Mar 2026 08:15:41 -0800
Subject: [PATCH v2 5/5] workqueue: Add stall detector sample module
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260305-wqstall_start-at-v2-5-b60863ee0899@debian.org>
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
To: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, Omar Sandoval <osandov@osandov.com>, 
 Song Liu <song@kernel.org>, Danielle Costantino <dcostantino@meta.com>, 
 kasan-dev@googlegroups.com, Petr Mladek <pmladek@suse.com>, 
 kernel-team@meta.com, Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-363b9
X-Developer-Signature: v=1; a=openpgp-sha256; l=4422; i=leitao@debian.org;
 h=from:subject:message-id; bh=S4vA+q+VwMb69TSVGfpJnrhNcwW7Ul9gdGBE+SKblT4=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBpqaw0SFZKUq3gvc8ICSsX75MQ8b9+vYkk6okaq
 u/ZIg1naCmJAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaamsNAAKCRA1o5Of/Hh3
 bQaDD/92Bw7gTZQBrb/gLXTqCDRVNvQjPb94AXKsIiL9VxSQl4UMzQwlRRaq2IryGPc0WwVu0WU
 MqA1tVPiXN3y52NaZa1dfrmqTXMdDgneU9SoDX/oA6kdyQA795ZqDQ0ydkG+KhbiHTCQ3vLd6dJ
 kS2k1rgHUy9pgTQzms+447827ZB4jTVG9JlsEa5auw33GwhOejoDZ65SXLs2w8x9DJycj3gRddj
 3jis028FhGLIrfwx1Wfr4yoqvdVu+p6MmBVqvMiGJqOCERHOKf3SM9isnU6/bri1RbzrTh14Bkz
 9PN05MLdmYm4KURoT0sKqvGh0vfWg5XuOdErred6fuhJ1xR48K+R7DT+qoA4hi50YhGRo4fVNog
 ESSMjYp4Z1mhNrhVj3sFdtfVgVhrkpwBO/saPOIcR3s3lMCrzXXA3VBA1wjma2If5sodbvg8HXa
 ymb1TgUo8JKBnS5eFMp6RITlZaxwD+3oJ7w4OAcJqht+RkmXjkJfsNKKXwZfkA5QIoA8gdRE9fA
 XgLC7F8CIrMgg/W0do6L8kGvPg1prYBZG+NBjQbum5h8bec/0Cy+wTETqyV99NQoPFhp1BYJrJI
 ZXwM/Eid4My9KJNBMzNBznvxd+ySTm9ozva7scZinZFMB0Kkwl17YLrC7/EWgBD3QutV2TG1qmG
 1XsDxGyyJnV3cAw==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=cQlbazqd;
       spf=none (google.com: leitao@debian.org does not designate permitted
 sender hosts) smtp.mailfrom=leitao@debian.org
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
X-Rspamd-Queue-Id: 5D21821545E
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[kernel.org,gmail.com,linux-foundation.org];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[debian.org];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDTMJ55N44FBBVGYU3GQMGQENFSEOKQ];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[leitao@debian.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[11];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,mail-lj1-x23b.google.com:rdns,mail-lj1-x23b.google.com:helo]
X-Rspamd-Action: no action

Add a sample module under samples/workqueue/stall_detector/ that
reproduces a workqueue stall caused by PF_WQ_WORKER misuse.  The
module queues two work items on the same per-CPU pool, then clears
PF_WQ_WORKER and sleeps in wait_event_idle(), hiding from the
concurrency manager and stalling the second work item indefinitely.

This is useful for testing the workqueue watchdog stall diagnostics.

Signed-off-by: Breno Leitao <leitao@debian.org>
---
 samples/workqueue/stall_detector/Makefile   |  1 +
 samples/workqueue/stall_detector/wq_stall.c | 98 +++++++++++++++++++++++++++++
 2 files changed, 99 insertions(+)

diff --git a/samples/workqueue/stall_detector/Makefile b/samples/workqueue/stall_detector/Makefile
new file mode 100644
index 0000000000000..8849e85e95bb9
--- /dev/null
+++ b/samples/workqueue/stall_detector/Makefile
@@ -0,0 +1 @@
+obj-m += wq_stall.o
diff --git a/samples/workqueue/stall_detector/wq_stall.c b/samples/workqueue/stall_detector/wq_stall.c
new file mode 100644
index 0000000000000..6f4a497b18814
--- /dev/null
+++ b/samples/workqueue/stall_detector/wq_stall.c
@@ -0,0 +1,98 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * wq_stall - Test module for the workqueue stall detector.
+ *
+ * Deliberately creates a workqueue stall so the watchdog fires and
+ * prints diagnostic output.  Useful for verifying that the stall
+ * detector correctly identifies stuck workers and produces useful
+ * backtraces.
+ *
+ * The stall is triggered by clearing PF_WQ_WORKER before sleeping,
+ * which hides the worker from the concurrency manager.  A second
+ * work item queued on the same pool then sits in the worklist with
+ * no worker available to process it.
+ *
+ * After ~30s the workqueue watchdog fires:
+ *   BUG: workqueue lockup - pool cpus=N ...
+ *
+ * Build:
+ *	make -C <kernel tree> M=samples/workqueue/stall_detector modules
+ *
+ * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
+ * Copyright (c) 2026 Breno Leitao <leitao@debian.org>
+ */
+
+#include <linux/module.h>
+#include <linux/workqueue.h>
+#include <linux/wait.h>
+#include <linux/atomic.h>
+#include <linux/sched.h>
+
+static DECLARE_WAIT_QUEUE_HEAD(stall_wq_head);
+static atomic_t wake_condition = ATOMIC_INIT(0);
+static struct work_struct stall_work1;
+static struct work_struct stall_work2;
+
+static void stall_work2_fn(struct work_struct *work)
+{
+	pr_info("wq_stall: second work item finally ran\n");
+}
+
+static void stall_work1_fn(struct work_struct *work)
+{
+	pr_info("wq_stall: first work item running on cpu %d\n",
+		raw_smp_processor_id());
+
+	/*
+	 * Queue second item while we're still counted as running
+	 * (pool->nr_running > 0).  Since schedule_work() on a per-CPU
+	 * workqueue targets raw_smp_processor_id(), item 2 lands on the
+	 * same pool.  __queue_work -> kick_pool -> need_more_worker()
+	 * sees nr_running > 0 and does NOT wake a new worker.
+	 */
+	schedule_work(&stall_work2);
+
+	/*
+	 * Hide from the workqueue concurrency manager.  Without
+	 * PF_WQ_WORKER, schedule() won't call wq_worker_sleeping(),
+	 * so nr_running is never decremented and no replacement
+	 * worker is created.  Item 2 stays stuck in pool->worklist.
+	 */
+	current->flags &= ~PF_WQ_WORKER;
+
+	pr_info("wq_stall: entering wait_event_idle (PF_WQ_WORKER cleared)\n");
+	pr_info("wq_stall: expect 'BUG: workqueue lockup' in ~30-60s\n");
+	wait_event_idle(stall_wq_head, atomic_read(&wake_condition) != 0);
+
+	/* Restore so process_one_work() cleanup works correctly */
+	current->flags |= PF_WQ_WORKER;
+	pr_info("wq_stall: woke up, PF_WQ_WORKER restored\n");
+}
+
+static int __init wq_stall_init(void)
+{
+	pr_info("wq_stall: loading\n");
+
+	INIT_WORK(&stall_work1, stall_work1_fn);
+	INIT_WORK(&stall_work2, stall_work2_fn);
+	schedule_work(&stall_work1);
+
+	return 0;
+}
+
+static void __exit wq_stall_exit(void)
+{
+	pr_info("wq_stall: unloading\n");
+	atomic_set(&wake_condition, 1);
+	wake_up(&stall_wq_head);
+	flush_work(&stall_work1);
+	flush_work(&stall_work2);
+	pr_info("wq_stall: all work flushed, module unloaded\n");
+}
+
+module_init(wq_stall_init);
+module_exit(wq_stall_exit);
+
+MODULE_LICENSE("GPL");
+MODULE_DESCRIPTION("Reproduce workqueue stall caused by PF_WQ_WORKER misuse");
+MODULE_AUTHOR("Breno Leitao <leitao@debian.org>");

-- 
2.47.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260305-wqstall_start-at-v2-5-b60863ee0899%40debian.org.
