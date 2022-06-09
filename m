Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCNUQ6KQMGQESEIU5NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 79B40544A2D
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 13:31:22 +0200 (CEST)
Received: by mail-lj1-x23b.google.com with SMTP id r4-20020a2e9944000000b002555cc8cef4sf4440910ljj.16
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 04:31:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654774281; cv=pass;
        d=google.com; s=arc-20160816;
        b=r3xf4r4bKLUwh4Z0TZhUoTIXJDsKTiBcXUR+20HGy4yt0U8cvTx9HcOluzOMyJ7i9H
         4aNpQXovWcyRDyjoByNneHkzhp/egP/V4I//+6DFz+mG0+dwyj0qkrEVLbhhOupKUHx2
         esyICq9zT9QlPeXpHeS0LbKdAzeFRJn/mO1Qk6dTRnQd7iPvXT+oT72IO2+OV7q3B32o
         SPCfUzQS998UBQSqjg//ijRUJSCTwi1l/kG1O3LVMT/ZQ3Sko4Zu6K6wZL6YC7QFNfR4
         8/AZlo34bheS/pUjn/0SlRjVvwkLbTgnDKH9Vkygvws4unaUXOMN6+SLQAeR4RloHXRk
         2PmQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wwUTvwCN62rsE5hj5VhAKA8egBirnx+Kd9YTt2vHbHE=;
        b=J4HgSioZkbwd4eOQG+cx+NaLEmQueHs+gkoyOvPQVsq0fI7EmLCJjg50orj//aIOLb
         Sn621psfT2c+4EXe6MNRtwmJjcSEcTKfw0UYZqHVLoTCj9Oc+wqlkLI+ER3naFBhKtXf
         Irnj4Q6Bux/2aJ5KzGddA/3GsdHu+942n4lR1kVMe3EYOkIFdigHwOZo8pLyBKTfZ3Cc
         CjRGna09XU3/X7eSA4yAJvGy1aKry0LjnMvalffVglGDGiaNjuPAWSSvESaV04XMCHiU
         oq5YzEMHE2l/wQx8/9gy02fWvb78g8Qna3ZVkQzMMILM+di+A11tFdItohe9fZKy3mpH
         8Uvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lPOLFAza;
       spf=pass (google.com: domain of 3b9qhygukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3B9qhYgUKCV4AHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wwUTvwCN62rsE5hj5VhAKA8egBirnx+Kd9YTt2vHbHE=;
        b=WcEDd/7V4m1lql+/x38aXVmsqgdUhyoA3vqUpe6xYqjFi21FPxWJnPr89sSDugsml5
         GgxLi3laCY8FIAli4tyWTO5jd4GsqkNFI1ZNrUmOBfaIuxyN6LBjHVFEJfOA+BnlRAuZ
         z9+g32wwh9IkBVcB+HfkQB6m6jSR6ddUe89lBiGcXQYw89ggbo2t6eGrPW/VLYIMspeM
         nss2mPqzYVA8JR1LV4bRV33F/gwInMBnqs8Qt4b1m4vMI0A8Yd+RXhjkLfwGdfiAL1oS
         bBYKwmj45w5CYCgCNL9wuvE4kSgE1UKNrvv+KlOdPfUmCGtqaX/HOTnI4pCZ3C/EceMK
         UXbw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wwUTvwCN62rsE5hj5VhAKA8egBirnx+Kd9YTt2vHbHE=;
        b=oZbe4vk4pljLM60snkVdfV9ZB7nwvSUvw6vocXsc3tAdSGnwZGpOLMzYzHB9sqfu/n
         E87QQAjjqPXktlBtj/DAu4u1RAVkPK8NJ26TRvtKVFbVMb6KFRFe6Wzj0eCtypmQUQmp
         iz3XCw5VNfJPKvZMzuXXkX+FYp+Tzv6YUPZ8GFDMn7JB11PIGFkFJ9PP6+WRRTcNbvjO
         fSDhdIzWulENel5vNnXfYu2yk1O08js4iyfUS1Y+TMzvKG6yKIWzb7oaulvfO40RbAu0
         jUIsb4JTfAw7kSU/GPTu3bQzTvnS6PQu+UUtPPcQKD1yN7nzySGW4DtspCECGnqh8eA5
         ljoQ==
X-Gm-Message-State: AOAM531H+7LZVjZ7nerV9Y5XEXt/zEQCH1t3eDM0MlcuT13a4tzYtqYb
	27kHWaMRbYKlXdD/8rJ5MAQ=
X-Google-Smtp-Source: ABdhPJwEGynWPsmHePFY3rSy9MXi4QlfvQVEVMmZu9bhXaOCRqGpLAyUp69xYq0gREhRE1d/j7tOnA==
X-Received: by 2002:ac2:442d:0:b0:478:ed89:927f with SMTP id w13-20020ac2442d000000b00478ed89927fmr33658148lfl.545.1654774281816;
        Thu, 09 Jun 2022 04:31:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc24:0:b0:256:c8db:bc69 with SMTP id b36-20020a2ebc24000000b00256c8dbbc69ls682844ljf.6.gmail;
 Thu, 09 Jun 2022 04:31:20 -0700 (PDT)
X-Received: by 2002:a2e:3a16:0:b0:255:7811:2827 with SMTP id h22-20020a2e3a16000000b0025578112827mr18863464lja.130.1654774280300;
        Thu, 09 Jun 2022 04:31:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654774280; cv=none;
        d=google.com; s=arc-20160816;
        b=E/DE1ITiAL1L8fCS9XLGsh2s8biZYaokIH/QU79YJ/wMroDQqHkacxvZBJkpT1mbMB
         OFnYXCqJugslwr/mgoCUM1SyJA9PVPAAM120/SRf8BvcxsDEeV4uIwe7NFTDKtNlKPFX
         eRE2BrlqcEt2i2DUnz11ZEGZToCrsUafiosZ5iZjA53vFYmMCCL4kXya95401xESvrDv
         J+Y7GoaYzOsA0+HcfMK0MBPFFrSlarBaAwPe3MgHfFxhbykj0JCBt9yh94llkc+Ek7Gl
         4Wi7XNoTfwMdKVRbHWoIZ9r2UyBTTJVsbUG5xOXe3aXPRjM2/ZCIi/+6bEYMYG96kSfi
         bwUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=bycUJydp4Is1Pgrv0uqBEliLMdGvYRKoN6kNtR19/dc=;
        b=A1zwEkCGDEBejOThYNTjCbbLIvn7zCthKWOLMjzX3gvlXo2+sn7A2OV46Qin7wchG0
         8P3ftrihQZexx8RqycvLgSHwbqn3Xo9tuRfT5fAVwQRVhgz/SG4ngBjsjjiaDLZFDVJt
         dnt3G9v18YJSn15nHXDa1uYlVvrk1wxsYzLjHBpQXwA5mJeL/c5CCVKXJzG3XDLNKP91
         K4LRt03sa9r7dL1gVvMmLjtqggY5vGOR4qjhTabDd6SnVrI7wkthAwpPLkLi0MBdDpER
         qDZBTfrz2LZZGj5r8lNKw7SsyOgbVaFJZGw5OE4rql1ioDX7Y4HVNsbL+iWHCwicaCx2
         5sKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lPOLFAza;
       spf=pass (google.com: domain of 3b9qhygukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3B9qhYgUKCV4AHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id d31-20020a0565123d1f00b00479321d8077si709273lfv.3.2022.06.09.04.31.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jun 2022 04:31:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3b9qhygukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id kf3-20020a17090776c300b0070d149300e9so8415385ejc.15
        for <kasan-dev@googlegroups.com>; Thu, 09 Jun 2022 04:31:20 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:9c:201:dcf:e5ba:10a5:1ea5])
 (user=elver job=sendgmr) by 2002:a05:6402:11:b0:431:680c:cca1 with SMTP id
 d17-20020a056402001100b00431680ccca1mr22174051edu.420.1654774279801; Thu, 09
 Jun 2022 04:31:19 -0700 (PDT)
Date: Thu,  9 Jun 2022 13:30:46 +0200
In-Reply-To: <20220609113046.780504-1-elver@google.com>
Message-Id: <20220609113046.780504-9-elver@google.com>
Mime-Version: 1.0
References: <20220609113046.780504-1-elver@google.com>
X-Mailer: git-send-email 2.36.1.255.ge46751e96f-goog
Subject: [PATCH 8/8] perf/hw_breakpoint: Clean up headers
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Frederic Weisbecker <frederic@kernel.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Arnaldo Carvalho de Melo <acme@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, 
	Alexander Shishkin <alexander.shishkin@linux.intel.com>, Jiri Olsa <jolsa@redhat.com>, 
	Namhyung Kim <namhyung@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	linux-perf-users@vger.kernel.org, x86@kernel.org, linux-sh@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lPOLFAza;       spf=pass
 (google.com: domain of 3b9qhygukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3B9qhYgUKCV4AHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

 - Sort alphabetically.

 - Move <linux/hw_breakpoint.h> to top to test it compiles on its own.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/events/hw_breakpoint.c | 20 +++++++++-----------
 1 file changed, 9 insertions(+), 11 deletions(-)

diff --git a/kernel/events/hw_breakpoint.c b/kernel/events/hw_breakpoint.c
index 3b33a4075104..e9aa7f2c031a 100644
--- a/kernel/events/hw_breakpoint.c
+++ b/kernel/events/hw_breakpoint.c
@@ -17,26 +17,24 @@
  * This file contains the arch-independent routines.
  */
 
+#include <linux/hw_breakpoint.h>
+
 #include <linux/atomic.h>
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
 #include <linux/mutex.h>
+#include <linux/notifier.h>
 #include <linux/percpu.h>
+#include <linux/rhashtable.h>
 #include <linux/sched.h>
-#include <linux/spinlock.h>
-#include <linux/init.h>
 #include <linux/slab.h>
-#include <linux/rhashtable.h>
-#include <linux/cpu.h>
-#include <linux/smp.h>
-#include <linux/bug.h>
+#include <linux/spinlock.h>
 
-#include <linux/hw_breakpoint.h>
 /*
  * Constraints data
  */
-- 
2.36.1.255.ge46751e96f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220609113046.780504-9-elver%40google.com.
