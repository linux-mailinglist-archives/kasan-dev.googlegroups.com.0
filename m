Return-Path: <kasan-dev+bncBAABBE76WOIQMGQEMQNMJOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id E0B9F4D70B7
	for <lists+kasan-dev@lfdr.de>; Sat, 12 Mar 2022 21:14:11 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id z19-20020a50cd13000000b0041693869e9asf6199605edi.14
        for <lists+kasan-dev@lfdr.de>; Sat, 12 Mar 2022 12:14:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1647116051; cv=pass;
        d=google.com; s=arc-20160816;
        b=uGPQ5zz64Sd4RrcVxo1gwM1UFDyiHzd2uN97KQD2NkMpziohcaKG+QK1o+Wom05pkN
         xVIT7SZ89jGI61whKDWJNQjvc6KxX+n4Dito6pbcI3CbAU5IZzCyIlo028AhKsIBJ2I1
         yqNEW6y1qWGfsPeyqhR7iz3ZnJU0xZgf58tntrg+EisBANwyQPtuvsCbo9PoAbOPbRuP
         5cP0twbeYqr3juggmCI4rGglUwvzGkVXt7JrM9uHhpWU0IX1U4CVpd4DR7tT4a0F6q+Y
         6m4fzIJZSv9B9M0OwSdPH8ubw2CFXWmB83/v+MDAUrhm74aUFULtGNlEknQIZYREf+sS
         XPXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=nXqefj8oeBGUYaXvnKbRVV+H3nT+bB36CH7R1PKWpYQ=;
        b=RliwyqM5FCHMt4nkS7YFNbA0sEi9upttgTJQcvq/C+u13O+qeNmyh2Hor55N6jYGvU
         rT9MsDRJxRnqWltlVu8mqGA0DzcKvgCmplc7EzHzmRgHiSSQGeF7Izrl0Kb6/7lZVxdW
         2ThrzwTw01OOk5troeaLf3owKXdPF3b+4fsFjZUynOoD7hmqJkG1co2tUTkJav3pGxgw
         VanO4BCiCKu1b+Qx2zs8BwS/qMOPFEphIVqUwBVU8DTxwgJ/tvISKlcvQfFjsQ05DvsJ
         xaX5cNqTE40yGCNLcDiD++XQp0xsTLtvu9VBEMd3xzglcEVGBRPEf9TSAKh5kcDKBMx/
         z5IQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KWCmw9X7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nXqefj8oeBGUYaXvnKbRVV+H3nT+bB36CH7R1PKWpYQ=;
        b=HfHRWuVLtJICRVsEs1mQPT9PRmUIVizYiBvfNLLLA0tZJCx+RFAZBfhv2z7PNJ6CGj
         fkAVsIML6ggNeXdnuUB0GspyKMEt61l2a9azLtbGEo03ltGzzjec/rb4v+l5meYlp2FK
         gpYrogRPRw78aQzwHSCWLm8Dob4GkXcmNY6FZmZ/0YJq4XBHhfG/AZliK4fzruOkfMXM
         NlwtcruWx0TAGJ1Y9Tf70uP7ZgInyaR7+7yOB4OL/hAI19MxF7sgxhWufWSEs4eAkCqy
         NnjmcSOh6e2VIENbZYm+ITxCIQy2DWbM1e6ro6oVNn4TU0SiouqRGaGNVnmluMlnXyu8
         OSXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nXqefj8oeBGUYaXvnKbRVV+H3nT+bB36CH7R1PKWpYQ=;
        b=2SCApMTw6HICm4JwggMx6ClD+IaXakK2kaZJhtO4/SjaMjfG6jzXqyNvzSloiA1hvo
         m/K1idk1apDVCvK9WANh6ndoRlU5buagtpK1BkpJyEzq/enNhIunyTIuCeqsTjC/R7v/
         AIHbt7FOcvshyZVDMcDmnDz8/4QvkQpjk0TZ2IpwJJLu27yWtJx4tD+gQe8JlDc8sE+T
         z5xEBMJGH8hEApaT6nK9Xv++NH3I6MeUs9FLx+bDZGIlv+pOl0Q/qe99RhYgSdkbLf2J
         HBvCaijSwErs3Oto/LltVuv15F9M4uzWgx228DBF4kijH0Uj1Qx/tQ7gdUnIcdTXlLq8
         CFXg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533k7Cw1WTcAK9xfshG8A6/HmNkSFgFAqOpYW7L67gWkFdejkmg9
	55XNkKPATL9FmwJ4zQclcwE=
X-Google-Smtp-Source: ABdhPJzyYn6NXA7p77S4+XL2Cl4HsoWCHXPkPX6Xt+svO52tNnope8haRfkp6GGhBpF5SDZo5o2UTg==
X-Received: by 2002:a17:906:3e90:b0:6b6:829b:577c with SMTP id a16-20020a1709063e9000b006b6829b577cmr13682760ejj.711.1647116051548;
        Sat, 12 Mar 2022 12:14:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d302:0:b0:40b:657:ac46 with SMTP id p2-20020aa7d302000000b0040b0657ac46ls2453887edq.3.gmail;
 Sat, 12 Mar 2022 12:14:10 -0800 (PST)
X-Received: by 2002:a05:6402:26d3:b0:416:4186:6d7d with SMTP id x19-20020a05640226d300b0041641866d7dmr14352299edd.129.1647116050771;
        Sat, 12 Mar 2022 12:14:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1647116050; cv=none;
        d=google.com; s=arc-20160816;
        b=Y6LNIFOpt7LZkLfxZqqG5brcM6DKHB+ZihY4RrFzUUpjo4BKeBpY0Zbogt9qJ5yKym
         MJsq15iLPrmZAVyDD1grDZ6TKT2+4ZCzSVx+ibZbdYK5JivCHelsVEHTgEdAzDqqkPbi
         CXR0ogIvtelwoc0bGCnyofnL29BuTAdv0zgb4v7l+bcRnwPbDHHAbERcMJvMiUVmALZk
         GiYY8ItiENJ2GoQdrSNd4tBhXLWNi8L4kep68mI7t1nT8N6Yx1xj3G3mmnqu8Z3NLW5Q
         UhpEhDF0KptTx3Jw5ecASr0evGnSQzuwQZ3IYqhj7xe1qMNszDopce+CRtM5E51rPKGA
         9rqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=LmoxS08scyGyVZqa/3VyRO6NmjBbbNh8W/Hs8Ybg/AU=;
        b=fdmIcsEkkfTa2/4bDEnJjeSsA6Rty+Ngd7/ALlTFMG5rU322JFkenXaNAWrx2OX/wS
         nQMcNgt5PhZZHxqA1bNLsvZv3i93Rzp3aDIczxEuhPyjbkRm+GAn9tvZTYB3k8LPz1DU
         I2T9mCYvU9+PZHhwzHvMOfS75xvgb9VLDx1xOSG48dCIhLIjIdS3bMibXiPu7fsvs01T
         U4vAQ/F3UPXqIbFdrueWRV1AZLW6n16VC8jeOBB761Qopszoz7rCkAunFVgXLP4dQLNe
         pnxZCxv0yRGamQMbfl/aLapm8kGzkOYPDUf1fCIAiSphZxi8yI2yRFtctMkIGzx6Yqo7
         SnGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=KWCmw9X7;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id r16-20020aa7cb90000000b00410871504d8si642166edt.0.2022.03.12.12.14.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sat, 12 Mar 2022 12:14:10 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kasan, scs: collect stack traces from shadow stack
Date: Sat, 12 Mar 2022 21:14:06 +0100
Message-Id: <57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=KWCmw9X7;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Currently, KASAN always uses the normal stack trace collection routines,
which rely on the unwinder, when saving alloc and free stack traces.

Instead of invoking the unwinder, collect the stack trace by copying
frames from the Shadow Call Stack whenever it is enabled. This reduces
boot time by 30% for all KASAN modes when Shadow Call Stack is enabled.

To avoid potentially leaking PAC pointer tags, strip them when saving
the stack trace.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Things to consider:

We could integrate shadow stack trace collection into kernel/stacktrace.c
as e.g. stack_trace_save_shadow(). However, using stack_trace_consume_fn
leads to invoking a callback on each saved from, which is undesirable.
The plain copy loop is faster.

We could add a command line flag to switch between stack trace collection
modes. I noticed that Shadow Call Stack might be missing certain frames
in stacks originating from a fault that happens in the middle of a
function. I am not sure if this case is important to handle though.

Looking forward to thoughts and comments.

Thanks!

---
 mm/kasan/common.c | 36 +++++++++++++++++++++++++++++++++++-
 1 file changed, 35 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d9079ec11f31..65a0723370c7 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -9,6 +9,7 @@
  *        Andrey Konovalov <andreyknvl@gmail.com>
  */
 
+#include <linux/bits.h>
 #include <linux/export.h>
 #include <linux/init.h>
 #include <linux/kasan.h>
@@ -21,6 +22,7 @@
 #include <linux/printk.h>
 #include <linux/sched.h>
 #include <linux/sched/task_stack.h>
+#include <linux/scs.h>
 #include <linux/slab.h>
 #include <linux/stacktrace.h>
 #include <linux/string.h>
@@ -30,12 +32,44 @@
 #include "kasan.h"
 #include "../slab.h"
 
+#ifdef CONFIG_SHADOW_CALL_STACK
+
+#ifdef CONFIG_ARM64_PTR_AUTH
+#define PAC_TAG_RESET(x) (x | GENMASK(63, CONFIG_ARM64_VA_BITS))
+#else
+#define PAC_TAG_RESET(x) (x)
+#endif
+
+static unsigned int save_shadow_stack(unsigned long *entries,
+				      unsigned int nr_entries)
+{
+	unsigned long *scs_sp = task_scs_sp(current);
+	unsigned long *scs_base = task_scs(current);
+	unsigned long *frame;
+	unsigned int i = 0;
+
+	for (frame = scs_sp - 1; frame >= scs_base; frame--) {
+		entries[i++] = PAC_TAG_RESET(*frame);
+		if (i >= nr_entries)
+			break;
+	}
+
+	return i;
+}
+#else /* CONFIG_SHADOW_CALL_STACK */
+static inline unsigned int save_shadow_stack(unsigned long *entries,
+					unsigned int nr_entries) { return 0; }
+#endif /* CONFIG_SHADOW_CALL_STACK */
+
 depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 {
 	unsigned long entries[KASAN_STACK_DEPTH];
 	unsigned int nr_entries;
 
-	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
+	if (IS_ENABLED(CONFIG_SHADOW_CALL_STACK))
+		nr_entries = save_shadow_stack(entries, ARRAY_SIZE(entries));
+	else
+		nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
 	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/57133fafc4d74377a4a08d98e276d58fe4a127dc.1647115974.git.andreyknvl%40google.com.
