Return-Path: <kasan-dev+bncBAABBONAYX3QKGQENUM4KHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CD99204602
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:39 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id z23sf1289481ote.14
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873018; cv=pass;
        d=google.com; s=arc-20160816;
        b=YW2SzUC//Kudl/qsxT5JguXjL9Ed8lOzJGIR/Ss6zx7v6rJDJBL32yNrGmj+iE7P70
         WPt2gKSSoHeSp6XvPqJonmfadc0EnrRsPmzo/3KdPoeViU2gCC28bBSY7AD7xxea8+up
         8hB9SlKZtCmq2ZmA5OYt0GZppUi8PI/KQ6PKp5qHqI6YTK3IuyuGs+DfZ8lcCkdWGuiw
         /8LLZazgtcapTTGPYwoYF0wK4421KmV66IUpFGcUj0HWMIPCzJ+E4ixroG71+aq/oGkX
         SgoFLYvml9gbC88ff/p9ny2tP4ANEkbFh/jmc9XExXQVLEG51W2Akdq0ia2WBI7/ys0v
         VbiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=bJeUGEGoJSeuboFd9SfBV/1yXxxqmvW7T4XKZg6spcA=;
        b=d62mOYRuHSmc4buaqMCPjLlXODc8AbowtxJnPqgM1Db67AmrkCFVNrbPOPDTI3DzkC
         rzLQAB3mraq3vveQ0tPcM9k4Bm5Q3mhKwTbBk4JQPY1kBXMUZRuf4Cp7jbPr6IlRJZtI
         Yk1SQ+r/oxkuC6h0ty7b1r9X3Lvb1vNhguBrRyFTryTMKHeyahUzpkzbLElqoEvFgwKx
         1/UySM44YOE+vdNZgfxQ/6D2mv8F6dRPlrg8o1Q2/IVMcuvZ1HQrZWCyr+us8fRfNK+G
         vzFsOYoKee9cvVf51C1oYrb293ByKzdEEq7x3QpUADI1fiHwn+PYf9RzzeC5OfU6lw6f
         hGOQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wO8lF03V;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bJeUGEGoJSeuboFd9SfBV/1yXxxqmvW7T4XKZg6spcA=;
        b=Ei48qjNQgwCTXyqS0uG3wB1/RWcBeeOsDs+/62mnLS/WluFzSfaSp8fLnf0FkKHPB5
         eHcoROi6xw4wPS82juQBG8rGqzA2/b+Kk5dg+wtvZbdkiy8+M/PRHMxhWtNylf3jvvFS
         xmRxfJb9aHR3eeM52xGWmeqh2yMstbH8jPuxoClFL4fn8zSGJYmAYX1Kxthq1mRApf5T
         H7Qjrp7X/r7dfzAGWRqVenrwe/wzdF2JOQtV+oG6U64OPtLhFx3gvth+Bsm0cpyGX1Ej
         cxh0wEr3IMfAJxlG5Q6HFz9B/z4fF1jInXBIp/RMhSF8RiRsMl339vy/ykPcjTLeSrje
         25rw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bJeUGEGoJSeuboFd9SfBV/1yXxxqmvW7T4XKZg6spcA=;
        b=hAB270gkhPrBBEnSPJ9PpdL4Lpose9Poz1f1hNEgWmNggtH7G7Ixb/yPORxauHSU10
         lBRdEhMVbGfvUHAMMLVL1ZYIvapk2SLDnpCXAcYClIv1Uy8OY13O4tfqWgacU+FTc85N
         zg0y8CJbn/hUpzBLkF8adjZ61xpDXvJ1kr3llpuOM420kYpv8NE2BHnWPaWXwUTEpI+1
         Bw2sh+Dmt73a0P4fwVw6aY2Lt61LES9Nc04o40qaEW0jHJ+m5sUyyrANkknUgHYGcc8U
         8ynRImE5ylzkR9lMo64QfpD6NJLXBWOYC8gaMfOCev5P0jQk0ot8Tq1/zlyKsAihhws0
         wxiA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KCkPhsJ/nrGAxZvZ5Gb+fxviXPZHI92Kl/fbMw+T+V4I8qeGw
	zKxdILjazBwYts8fOs4bLeE=
X-Google-Smtp-Source: ABdhPJxzlpFCK9lss2xMHp+DOD5YwIGH7jJG63IZuO+vh02455Q82PY9WaqyJGEqT1IGb3Qj0Sb1qw==
X-Received: by 2002:aca:3195:: with SMTP id x143mr804374oix.128.1592873017929;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3116:: with SMTP id b22ls4005059ots.6.gmail; Mon,
 22 Jun 2020 17:43:37 -0700 (PDT)
X-Received: by 2002:a05:6830:18c8:: with SMTP id v8mr16763472ote.119.1592873017662;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873017; cv=none;
        d=google.com; s=arc-20160816;
        b=wbHdCiIq2vQMu9UVUqWWK9zjcjzB3yHT+CjGs5A3Eeex6yE1J2FhLomF9Wt/0++sWP
         hlI8Re+l/qiilR8HIrvi6fiRK/bEi3xHl8I90dQVOy2qGddwJOMhfvWcTtQ8GHBkY2dF
         00wW1DeqGPQSTlB9IXBFQqBPQVHpEQ61D30KMZtQJII7JqezCGOEh9mOj/oIgHSWPWvQ
         +Ju9yXEgO7wp1S4kZ2I3Qo0+7hjc8Y4Y86/24XJutyWacoFh2b7zPOrL3QAJKaOdxJ4s
         0CQMbpQHR3935NXbtGmuJBsR58MuKXkGesrXl4+HYdWoiCn6lK8KA4nUYdvVUpc+MF3N
         z2PA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=kZu+o9d8OveyY1vW2EO1shmZ+ako2+8u75G24pT/1Zw=;
        b=vH7BMMYnQ5i6nARu0xKn5i2Kw7gULNpUJdlkyySA5SBIckwEvud0ebKa86JYSgpog+
         ewb9z/92sSTT2SOqV9LsRzqTjSOjKtB7A7Vgji1eG5ltrkgWWbcsvLfJEUUbS+6vrOFh
         zRFzFvTL+GXSr6BDhpyjO8WiUb+H200vOpDMWhPjPJcZN8QFTiMLp6bPInTVzN68ZDvj
         5y+H/EbdG9O3T9TE+lyEhioNJVyqqVu8hgj/VzF2gxC4+UXL1GMoi2qrbkASAGEE3xHE
         OnSSU2BHi3mFAc5ThRfIlnu2OB4XjGiEaeDjvStDOXl8AhUFvhPyvjeO4nhtiRr5ZJQk
         kpEg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=wO8lF03V;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a13si816252otl.0.2020.06.22.17.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id C12222083B;
	Tue, 23 Jun 2020 00:43:36 +0000 (UTC)
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
Subject: [PATCH tip/core/rcu 09/10] kcsan: Remove existing special atomic rules
Date: Mon, 22 Jun 2020 17:43:32 -0700
Message-Id: <20200623004333.27227-9-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=wO8lF03V;       spf=pass
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

Remove existing special atomic rules from kcsan_is_atomic_special()
because they are no longer needed. Since we rely on the compiler
emitting instrumentation distinguishing volatile accesses, the rules
have become redundant.

Let's keep kcsan_is_atomic_special() around, so that we have an obvious
place to add special rules should the need arise in future.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/atomic.h | 6 ++----
 1 file changed, 2 insertions(+), 4 deletions(-)

diff --git a/kernel/kcsan/atomic.h b/kernel/kcsan/atomic.h
index be9e625..75fe701 100644
--- a/kernel/kcsan/atomic.h
+++ b/kernel/kcsan/atomic.h
@@ -3,8 +3,7 @@
 #ifndef _KERNEL_KCSAN_ATOMIC_H
 #define _KERNEL_KCSAN_ATOMIC_H
 
-#include <linux/jiffies.h>
-#include <linux/sched.h>
+#include <linux/types.h>
 
 /*
  * Special rules for certain memory where concurrent conflicting accesses are
@@ -13,8 +12,7 @@
  */
 static bool kcsan_is_atomic_special(const volatile void *ptr)
 {
-	/* volatile globals that have been observed in data races. */
-	return ptr == &jiffies || ptr == &current->state;
+	return false;
 }
 
 #endif /* _KERNEL_KCSAN_ATOMIC_H */
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-9-paulmck%40kernel.org.
