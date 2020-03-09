Return-Path: <kasan-dev+bncBAABBPNGTLZQKGQEHKXXC2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3c.google.com (mail-yw1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8AAF017E7DC
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:30 +0100 (CET)
Received: by mail-yw1-xc3c.google.com with SMTP id w197sf16934045ywd.17
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780669; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ZXCQbQ02hv5Zs+5w1IvG/VgJTEkSzuqyEmMH1756H6fkKCBpF9NVMOrygJwX8E3N1
         FWpfgcfpMtwurUlnyff3sdag9CJkIUWkl5vzodXvxIMaQva0SYYYF+g3PP2Kj9Zye1fH
         JgNjVJRuS5fwJ/0ZeMSKWZPwISqnY7CCL4rfa3cPxw7gCRoXUU4vMAXFrPKY0FSTwgf8
         xPkTpCGGZSyDASnU6JZpUMeIicRYFLla1EO9G9Xl1fsDfEQBJL7nCGfj3GlCF/LuI6Yj
         n30jf6r8U8j952uFMZUXxIdkIkfOPxgsPL0T9JTOUTG5xsAJE+dxZl55cq0LNjzcu5zG
         5Hvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=OXKLRFgOnjZa679lXDXNEZ99jslxhi6AKXNtuZP+fdc=;
        b=xtzMwGESl0J8BD8839bspnIz/5O4KZIdjwGxiZ2F6ImyJxnhT3QU3r45dRR5FH8yef
         3j7Wq1v/5EkValHjoUjxzw/9AntE6Tsonf24fPlx7QfMriRArSLjgs/ZKdqQl4w6SeA6
         GV8ahSXjfzut4H0qFZIuKFq4lHR2vYcDjeEHtsqCUbQdYzZrFPB0gNldqlgn0O7+eQbW
         /uFjm2wGn+Gx+n84CMsFjK4yCySLcJ7bPpGjsx5UvFN/XfksZ+RgBpbC0eP0tM1pAmEk
         C9Xe+wawZpQepai8Je3P0QUNzGHEDZR8XNwlQWckXQTT9BuXSgm36qw/bXhfco1/3v/+
         C2sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=IAd2hde4;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OXKLRFgOnjZa679lXDXNEZ99jslxhi6AKXNtuZP+fdc=;
        b=Mjq++njq/W5kFjNfURk9fD+Qitw2iRRNCZwffw42978gvQnWDhQ5vhKvlAbkOZnZAb
         39zzfoZ3odn8JUcaBHtt248haPupCS/brJ/znKbV64Eo376R2fX8iZWcbF8JWjwIsogg
         yXIPCUUCWs5BU1mCzlaiY3iUabBRVeOA5ldDLF/LDhJXWg5ZMRCcs0JVuS2A1qnOWunW
         O91BA6Mn0KnrTxQ5qlugxYOE+akxurLQ2XYHVfscoUJPXOJoNzyfWWTAM7wBxM6/CliU
         7s6S40F/GhIZuIp0cxo3DEY1Nsvt7ifJWA5lMwmbK1ekL6YmX41d0R0PAE+hT5izGskH
         jRCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OXKLRFgOnjZa679lXDXNEZ99jslxhi6AKXNtuZP+fdc=;
        b=eob0G4wrR9QgrLz3Age6WevLfZlqHrxVlqej7XG5edC8nXTKFeWt94wDDwZgRpHdOB
         YUzh3PFfXz98mkpS/nWTHfa6vh8HKQ8Hg7QxYfFwokzHrRvjzgmh/M2gu0LcqWzzRxS5
         fU6Pu8Qf5mVAVDY/4HOsD3BqZktfOjp7twp+BVtyZ+75zPex5gy9Npka1uNZIM+bAsLZ
         Gku7iUwQAZbHQWNNDCahd4Wm3F35LFL/8IamqXIUQWYCRouM85LdOJbqU+LHxsFWxqkF
         1SzApoN5Do1pRKJMVoAziyeYxYsmEWKmnzZCE6U6qY8bjGe+iu6twrOOsSwKWGCQal9z
         fnog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2srrlEgkGmoZDFJkCe0I6geaqMn37ZTVtXm10I3ZVwTkvjtKZt
	KnL+TlWc5EeJsSy7STOame0=
X-Google-Smtp-Source: ADFU+vubHCb92eZAYbylmWB2M1MykU1QOeJcvFwukQH/hGTlS0RF1VuL1EXOm6j3aRVA5Do6PMyGcg==
X-Received: by 2002:a81:1a0c:: with SMTP id a12mr17959230ywa.218.1583780669567;
        Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:883:: with SMTP id e3ls727632ybq.11.gmail; Mon, 09 Mar
 2020 12:04:27 -0700 (PDT)
X-Received: by 2002:a25:22d6:: with SMTP id i205mr19938482ybi.403.1583780667816;
        Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780667; cv=none;
        d=google.com; s=arc-20160816;
        b=RVcRJjcjAarW/3H2fBV7Z31HqT9oE1tbXYh4hcuhPpac1+0Ff3KWic+ugO+Dvb8C+0
         2LalZWlNUIPwQsNhkygVt9pDnL9RDJCLJiiLA+SodEP9Ev62GrKSNCf1OBj2zYwS2/yM
         mM61ly8i7HPxD9XEU88dUZtn+VfzSE10fgXtdfA6whOFFeuMm2Sk6pXhCPJkzzfyfXid
         7xeUF/+2Lac9IqnKUkMeQbUAOCLwp/ftvl8n6aVydmLJNqxGn7q+ia8HPvpRFYJeFnO0
         3POW2AlRXnUW07cIQvR7QObUHWF18/1h4NEgZMIj6Qag95AjsiTUEiwaiNCJnzZGqJn6
         sxtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=yvt8KjFO9n8mw37NawY4wRRLaoyXNLvIN00Wd7sKOXM=;
        b=05vJwGlUJCsamUmZDn1lKFR3WvM4NP8dAbDlD/figEVB3e2c/5adpskfks0Hy2Jf5N
         T2EOZBSyWEowWwx/zTvh5eteg942bem5zIUeX4wnkayslRcv/BVRKYSoC8bvI791ldoi
         phyFuWm2RRj9u/I+u5bHqQeSgjg9MX3TrQmCDnY4dxP1q9wTtBGmGvPwoaeUhMSZwYZB
         MrfY4DeN7ME2lvk1ZxQrZWEYl4u7o83CfPmRrrvR3Ds6PQjeCh6F0SkOVjqpG/pZ7WTf
         sDNzhDqnBW9wb/uX9e2g3WS+112r+GtgUb3ZyGhdMwiVf+E28GukECFRqCrLMoYjAbPr
         UYOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=IAd2hde4;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id s64si611079ywf.0.2020.03.09.12.04.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CF29021655;
	Mon,  9 Mar 2020 19:04:26 +0000 (UTC)
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
Subject: [PATCH kcsan 19/32] kcsan: Expose core configuration parameters as module params
Date: Mon,  9 Mar 2020 12:04:07 -0700
Message-Id: <20200309190420.6100-19-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=IAd2hde4;       spf=pass
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

This adds early_boot, udelay_{task,interrupt}, and skip_watch as module
params. The latter parameters are useful to modify at runtime to tune
KCSAN's performance on new systems. This will also permit auto-tuning
these parameters to maximize overall system performance and KCSAN's race
detection ability.

None of the parameters are used in the fast-path and referring to them
via static variables instead of CONFIG constants will not affect
performance.

Signed-off-by: Marco Elver <elver@google.com>
Cc: Qian Cai <cai@lca.pw>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 24 +++++++++++++++++++-----
 1 file changed, 19 insertions(+), 5 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 87ef01e..498b1eb 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -6,6 +6,7 @@
 #include <linux/export.h>
 #include <linux/init.h>
 #include <linux/kernel.h>
+#include <linux/moduleparam.h>
 #include <linux/percpu.h>
 #include <linux/preempt.h>
 #include <linux/random.h>
@@ -16,6 +17,20 @@
 #include "encoding.h"
 #include "kcsan.h"
 
+static bool kcsan_early_enable = IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE);
+static unsigned int kcsan_udelay_task = CONFIG_KCSAN_UDELAY_TASK;
+static unsigned int kcsan_udelay_interrupt = CONFIG_KCSAN_UDELAY_INTERRUPT;
+static long kcsan_skip_watch = CONFIG_KCSAN_SKIP_WATCH;
+
+#ifdef MODULE_PARAM_PREFIX
+#undef MODULE_PARAM_PREFIX
+#endif
+#define MODULE_PARAM_PREFIX "kcsan."
+module_param_named(early_enable, kcsan_early_enable, bool, 0);
+module_param_named(udelay_task, kcsan_udelay_task, uint, 0644);
+module_param_named(udelay_interrupt, kcsan_udelay_interrupt, uint, 0644);
+module_param_named(skip_watch, kcsan_skip_watch, long, 0644);
+
 bool kcsan_enabled;
 
 /* Per-CPU kcsan_ctx for interrupts */
@@ -239,9 +254,9 @@ should_watch(const volatile void *ptr, size_t size, int type)
 
 static inline void reset_kcsan_skip(void)
 {
-	long skip_count = CONFIG_KCSAN_SKIP_WATCH -
+	long skip_count = kcsan_skip_watch -
 			  (IS_ENABLED(CONFIG_KCSAN_SKIP_WATCH_RANDOMIZE) ?
-				   prandom_u32_max(CONFIG_KCSAN_SKIP_WATCH) :
+				   prandom_u32_max(kcsan_skip_watch) :
 				   0);
 	this_cpu_write(kcsan_skip, skip_count);
 }
@@ -253,8 +268,7 @@ static __always_inline bool kcsan_is_enabled(void)
 
 static inline unsigned int get_delay(void)
 {
-	unsigned int delay = in_task() ? CONFIG_KCSAN_UDELAY_TASK :
-					 CONFIG_KCSAN_UDELAY_INTERRUPT;
+	unsigned int delay = in_task() ? kcsan_udelay_task : kcsan_udelay_interrupt;
 	return delay - (IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
 				prandom_u32_max(delay) :
 				0);
@@ -527,7 +541,7 @@ void __init kcsan_init(void)
 	 * We are in the init task, and no other tasks should be running;
 	 * WRITE_ONCE without memory barrier is sufficient.
 	 */
-	if (IS_ENABLED(CONFIG_KCSAN_EARLY_ENABLE))
+	if (kcsan_early_enable)
 		WRITE_ONCE(kcsan_enabled, true);
 }
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-19-paulmck%40kernel.org.
