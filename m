Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2NB5OKQMGQEZRAHETY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id E6DCF55BFF4
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 11:59:05 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id t14-20020a056402524e00b0043595a18b91sf9159344edd.13
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Jun 2022 02:59:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656410345; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZC2lYYjQFw/97pRzeNr6PkwpSs+3fmNxo/ZIrYIGD0Ye1vS9uYJo4C/GHdaLYK9bdr
         1H588z4/v4hWDzLUg3yRBtuJaKNdy+7vcmWaEQ9xj+30EA0FRiP5Q+yiOJIuEIZfhFM3
         3x3CJy4DQ0PKPxVCSSBB/IoDdDtQtOcWvfbXmyM0/RqMshVBg+KrZt5rtQ+TmEngqPVR
         XjSU5DeyP8WYLE/JeWO5t59kLnRBIu0nLYq9N5U9ueiaq2lcKKD3m9j3bzIjdXYco11X
         CoZCMUktS/QNsMuHH3MU3yEW4hFNPQWj/dWugth2+jtIfGALZZdtGFKeIiV/YD3I6V7h
         rMeA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=ZZz4wSDZJxIHFDK9FFvNrkGubFJJLVaIDsObYbc6Gn4=;
        b=h2SQ7g809BnkNmXPdoZTPD+G3DAbzmmPfsClG7hsT2h3cjpQ9NtonC4cLlaaYcbUz1
         cc//LOIDUof4M2oNxPdhxgswPBhwaoh4wrS69K4gFz3q4SXJrJ+lGE4T4ZzEdCQwGKZx
         cQcG328uXf6Qxan0elcuCpHS0+ZlBbf2KywyHI7xRu05hlqEWiqzIJBBnahWIyXy2S6C
         +sQWF4omF85tc2EgdA6N7CsnA0lHg55d5QzG90EgkMQgrqUdwR+iHbJYKvPWs2gB6s82
         5K7z6vefcx4ZDA/S0R/c44qw5S7rl5Lq7hBC1tUsFhDp1NElYUfCyA4slxd+22FFAtq+
         KV6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RQpMHh1m;
       spf=pass (google.com: domain of 359c6ygukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=359C6YgUKCZAy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZZz4wSDZJxIHFDK9FFvNrkGubFJJLVaIDsObYbc6Gn4=;
        b=IZRxNDPLHV/XNTKXAGRsaUnAF3Pwi/sxt6YrNyhgM4fgwc885rLbFc1+MTkqkijp1p
         cRf/KjvNncy+aoD4RTQxd1Lf1EcI/gsAfGuHG1QbhxHhJpgHQpvTW7GR5o1L1Vw11Zm3
         VIDdsSmkMO7uttyF+OwD1SLEqeBtt6Rxi/mDcXvuPRzK1VBvX44xF5xQrrIv2v/tpIhY
         iuC/+17DUcNTpC5TRbljBEeFhbrPwTcWgd0oWDgOvDNaX9L5qBv5wSsB6FvUOj6SSvhj
         ntLbSnv7KSdvmvomZQ7H21GUD+m0nNgu35k1tRZ0hj0WCwO8n2fDmx/wk9r+96JS1lux
         6eOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZZz4wSDZJxIHFDK9FFvNrkGubFJJLVaIDsObYbc6Gn4=;
        b=HSUmfIVMKilN26N2tqx2BQGJBo0Ctr9UAUph9K89Pz/+cPtYHbMJXNoutbGEgr6k95
         0oMUmJPLoXZj9JG+vcxtqz7JIZ1N850GY9WUe23ffQ/Vu2d75AKtn2ZjhfBc7j0B6VDI
         AFF5hQXRKNzC8eX50GTmYqinK2M/J8SlaP0e0e5rohbKugjkhWw/f0CCFhChX5QXwfyG
         5qcprtFEAvRsk41V9YC5zD6OyPivr1r0Vl765Cnf5BIoH85LbpS56rEC4p1yuQQcMsG5
         criKGu28QB0vXXy17swj3Yvs+Ndds7ayLpwTQBFDuydfIEiwypNVPjfzFuV5VNNg1x/v
         l14Q==
X-Gm-Message-State: AJIora924g3926lHYnOGEhfpUTLfIAuK9DmWn4b04nqd/j8MRaSSqfGg
	mi4wbAvrUn/BkliIep553DY=
X-Google-Smtp-Source: AGRyM1tM6VPb8HfQySpYS/BREvTfFxj3shpPbDn0uOi1T3VA+H+YKJ264YpmqeWYeCatXnENCeXH3Q==
X-Received: by 2002:a17:907:8c05:b0:726:2a09:c951 with SMTP id ta5-20020a1709078c0500b007262a09c951mr16835468ejc.143.1656410345414;
        Tue, 28 Jun 2022 02:59:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:a42b:b0:726:cbdd:466d with SMTP id
 sg43-20020a170907a42b00b00726cbdd466dls1085699ejc.9.gmail; Tue, 28 Jun 2022
 02:59:04 -0700 (PDT)
X-Received: by 2002:a17:907:d05:b0:6f4:3729:8e36 with SMTP id gn5-20020a1709070d0500b006f437298e36mr17088900ejc.475.1656410344132;
        Tue, 28 Jun 2022 02:59:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656410344; cv=none;
        d=google.com; s=arc-20160816;
        b=vDVktGu+akpJN1pgmghnAlUC0FXgQomgDJNnqRIuyX316TSQYRRtRH3C1ewHbEeiiF
         X2vUetCsCk8eEO3UyS39b0hdas4FHxkqwaNVEeq4T0QSIVG16z7WZN8B28BMW6S6b1zS
         NzXHeXW3/chDBNGUSuSf8WPBm+fjy84OiIz++C/7c5zFLeOToq3U9FmOsLT/gWgVJclR
         jO0bJ06xSeTx1aflj4/nEBz3TCQ1wonXAQP0evECtYfH7q0IbgNglleNwWAz4de3Wtj0
         TC9ew2xZsTw+almTX7T2WCUIGBdZf4QCVZKu7lCwRkp0DLhvUVVvHqf+j/TlRiY3zmZJ
         /8bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=+Sjjp8jJ7/w0ICOZmYCWvjg7GfEBySyn/+1KfIaOHFY=;
        b=RSexrp2RDqTpi3TYJoU1mdmCwCNUlWz5u24CCz6KNIjzUKXHjuJSQzzx60NZdi0ecH
         XaagQIOn/VEtmCDDI1mRahqFOm22NHhxZmfOfPURPb+FmZZchMN9b6MPCMV0f4eBdK0T
         Sxi/RV0zR4bDbZ/SYK8eYJcBZfIl5tR3XvwlzUOODZGpGkXHjagV2x3LeAfnWiv5Agm0
         4aD/Yar0UpnHIbAlOqc4gqxIBfHPqxlhy36aXIY6gEkbgIO0KLkq0Ea2sya2kWnCLl9u
         vTsn0B16tM5o4DsJX45V4/3dckJR8fYCcLKBQAygZegTTOKiKfErAKJuDXtUTKaO8SU+
         mxMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=RQpMHh1m;
       spf=pass (google.com: domain of 359c6ygukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=359C6YgUKCZAy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id q31-20020a056402249f00b0043780485814si306633eda.2.2022.06.28.02.59.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Jun 2022 02:59:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 359c6ygukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id m8-20020a056402430800b00435cfa7c6d1so9192539edc.9
        for <kasan-dev@googlegroups.com>; Tue, 28 Jun 2022 02:59:04 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:3496:744e:315a:b41b])
 (user=elver job=sendgmr) by 2002:a05:6402:1386:b0:431:6911:a151 with SMTP id
 b6-20020a056402138600b004316911a151mr22335610edv.105.1656410343984; Tue, 28
 Jun 2022 02:59:03 -0700 (PDT)
Date: Tue, 28 Jun 2022 11:58:22 +0200
In-Reply-To: <20220628095833.2579903-1-elver@google.com>
Message-Id: <20220628095833.2579903-3-elver@google.com>
Mime-Version: 1.0
References: <20220628095833.2579903-1-elver@google.com>
X-Mailer: git-send-email 2.37.0.rc0.161.g10f37bed90-goog
Subject: [PATCH v2 02/13] perf/hw_breakpoint: Clean up headers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, linuxppc-dev@lists.ozlabs.org, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=RQpMHh1m;       spf=pass
 (google.com: domain of 359c6ygukczay5fyb08805y.w864ucu7-xyf08805y0b8e9c.w86@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=359C6YgUKCZAy5FyB08805y.w864uCu7-xyF08805y0B8E9C.w86@flex--elver.bounces.google.com;
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

Clean up headers:

 - Remove unused <linux/kallsyms.h>

 - Remove unused <linux/kprobes.h>

 - Remove unused <linux/module.h>

 - Remove unused <linux/smp.h>

 - Add <linux/export.h> for EXPORT_SYMBOL_GPL().

 - Add <linux/mutex.h> for mutex.

 - Sort alphabetically.

 - Move <linux/hw_breakpoint.h> to top to test it compiles on its own.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Dmitry Vyukov <dvyukov@google.com>
---
v2:
* Move to start of series.
---
 kernel/events/hw_breakpoint.c | 19 +++++++++----------
 1 file changed, 9 insertions(+), 10 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index f32320ac02fd..1b013968b395 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -17,23 +17,22 @@
  * This file contains the arch-independent routines.
  */
 
+#include <linux/hw_breakpoint.h>
+
+#include <linux/bug.h>
+#include <linux/cpu.h>
+#include <linux/export.h>
+#include <linux/init.h>
 #include <linux/irqflags.h>
-#include <linux/kallsyms.h>
-#include <linux/notifier.h>
-#include <linux/kprobes.h>
 #include <linux/kdebug.h>
 #include <linux/kernel.h>
-#include <linux/module.h>
+#include <linux/list.h>
+#include <linux/mutex.h>
+#include <linux/notifier.h>
 #include <linux/percpu.h>
 #include <linux/sched.h>
-#include <linux/init.h>
 #include <linux/slab.h>
-#include <linux/list.h>
-#include <linux/cpu.h>
-#include <linux/smp.h>
-#include <linux/bug.h>
 
-#include <linux/hw_breakpoint.h>
 /*
  * Constraints data
  */
-- 
2.37.0.rc0.161.g10f37bed90-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220628095833.2579903-3-elver%40google.com.
