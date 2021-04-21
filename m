Return-Path: <kasan-dev+bncBC7OBJGL2MHBBVUHQCCAMGQEL4KYY4Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 908BA36697D
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 12:52:06 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id 65-20020adf82c70000b0290107593a42c3sf885809wrc.5
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Apr 2021 03:52:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1619002326; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZqS3S7miJYEvovrxUN+dfChEgr1WjLotMemqjZk3Ss9v2Oxy0Kj7QUKwBm9U5qCFH5
         JBzGUAZszrqaOfOu4awSWcF+nSiQCtK0xwvbhqxpRdLs4bkqLvD4LVpsCt1Lm9q+yUjR
         xM7KJGxZvOKUbieZLRvLYiYHQZPCoAGLvj1YZOZOV2/sMdryFay17318lGupfKHmNKnD
         8qnYogdyJ0YyX4dx1xmroEqkbspxOqKiDbOxpuvDmhQ8t9k3btcZ+vj4Efj3/D+ztlTg
         PUK1Ab8S+xeeTiTJwCkNAaGVaqba4oApJk8MLq7GXeixEE1Jkw+DGuOehtkHbYCVvm6/
         U9cQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=mpdys+YVxKK1AyG2h0T65KS66SYpfZyvL6Cb5ocwfBk=;
        b=AZ8fd8Y5JJsLFTNDVd2jaux2jLU91kRnfhUfoh2lecQzjXaCBIxJ8TT7A8XJhuRSqs
         nce2J/l9Gf55GCCD2O0BNQLOYJ1J5QxGqrXAvrmqzWgHZu3I8EZrfxiv55ugAmSOVLgu
         nSNAiNVpojSgnAIAB2HnLfYDtqs4x9kmDFQRT7W6HtyBkjVSfbP067vP377gGn3xQDWp
         at08MUaBSrzY1S2fYXmSV36pBNRNy+JaHWh4rQS0Y4tPb9hhAB9U6tBySup0OK3hgPZH
         Y6+xf8z9xDL1sqXQYcbLzNK+mz8CgG2XderyvCazhJi0VlHPs9xjuwBAQ/yItQYAEwlf
         g+tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BKLqZcru;
       spf=pass (google.com: domain of 31qoayaukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31QOAYAUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mpdys+YVxKK1AyG2h0T65KS66SYpfZyvL6Cb5ocwfBk=;
        b=YStjNhxwr33XPa2JzgIPwO1eRYi4Cx1wXrGREAyjZuYhp2jCFTBxI9L39erMoRV+NY
         mFFS0usjihdLK1W+IC2MLIJOcXSuCdY3rrti7i6idDY0NiXfaZeDr0CA/bhGGzbkvf1e
         EIZ8BKTk6Ya3/xRGx8CUzp1Cn+eWdc7+GHE4R4Ytkrz1mOOHIDRXernv6CYa0eLuLMpY
         NT2DneinvA8yIAVUK75g+XVWuJk/jfuNsHJkfAkoovNrcvryP+FPDWTArvV87t1vz5EY
         RKhrA7UZLSKx/OiJ627Z1YI6tZiVbyllxbx91W43FHPDAPVMuw9m5LryLl8Pa6F7FPe8
         eXYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mpdys+YVxKK1AyG2h0T65KS66SYpfZyvL6Cb5ocwfBk=;
        b=Rj7+5Ind/gbp9yusR8eO+jzPQJMpUD9dnsgN6BK2rjecOYC38vF1JY3Y9qo6bACW/A
         hOZ/7YBDxSyEcDEPcjgHKV9JME/UlpH0kkP5U+dQ8Ig9MvdYjrbc3TOOB4vngVh8swqJ
         BMdjUPYBiqN+Jy0bY2x52UF/8nrfAAh0peewbzrQCzhuP+rarxIpamoAGyOQ/+661c8z
         yVuuTyYRc0CaJsH5kuiBYt9km6kWMbQG79hz5wBL5GpTGSAE0sWFpflPi8WmxOSnu93/
         ABZdDgHugensH2cJ2mnRz0Ef25ijNhqmGvbvcm2w4ibQ7BsW7+29fnmczrM1DPQlIqpt
         dAQQ==
X-Gm-Message-State: AOAM530bcP4iEyQ3uzbMAXMKvzk64yeK2tmA7EPMHch/gwGmezITCyYO
	ljFmMv9tjTXy0JxsmwjIYaQ=
X-Google-Smtp-Source: ABdhPJz0lZS8t41HzrsUb8W9Nllxg3r0EtI3XxIOVost3kP9r258kxnZZCVqTw0HEOSuo+mcmKz+1w==
X-Received: by 2002:adf:a3c4:: with SMTP id m4mr26177654wrb.217.1619002326387;
        Wed, 21 Apr 2021 03:52:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d1e5:: with SMTP id g5ls2438572wrd.1.gmail; Wed, 21 Apr
 2021 03:52:05 -0700 (PDT)
X-Received: by 2002:adf:9567:: with SMTP id 94mr26469845wrs.401.1619002325490;
        Wed, 21 Apr 2021 03:52:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1619002325; cv=none;
        d=google.com; s=arc-20160816;
        b=o2lV/vBBlVaobPXbREJsuoAZWtcshMCKwFdOj/lhslKW5cA1CwFdKLTyHbPchOQu55
         7znqGrtto2HHFDX4k0WDzuxhX3FiANKMmUnHeGlgWPC2AlJEL0YcEyHle1413XII9ipY
         FRSerN6NhYuFmCFbDJMAJx0oZXtVeqNokd3wFeLLLGzddqC4ZMvI/b1qtQF3kSVFYSUU
         oArTy4DJK6zpPmbEo1UGCE3iBD2iADJCer9hfuAP0/3xmgJolKwrMFaa3pqRdEwhdRrJ
         3VU5uBjnaxeWjlJKgzE4LxaE4f6qFBl2Z1tELElXS7grUEKqfhAtz+hI4QTELkLUS/ke
         CRbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=S7gKkVqw6gJJUkQX3/NKZ5hEYF7HuP5mcybwHhcoGA8=;
        b=WcSMEsgpybmqMxISbmeuWDIr18wjhwvkT38J1PyQqQxflPB8C8nF5mhgkebBpuYyLJ
         1RJRMdMqq8ldK6fguGh53GKQkQKbc07nJ/KuCPsxJWPM/6/TrqkssdUvOomWmxpyPQAj
         UH74fxlR9l4pqdPk7apxNkRo0anMhLNuD3AXNs0BgzaCtnlDO5cFJk7QgmW96RqG1SlV
         topBE+867KHyJ7SVPsUOkRJIJbLkR3a29QYV6ucyjTJfOnEgbCGygdJagTTmZFAJcY+4
         RCK9tz578S+4l3KQGj1NG5dbyjtvixa5lrsG9DdrbQdea7jKH3pjFIlb0gE0tkYF7i/O
         odfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BKLqZcru;
       spf=pass (google.com: domain of 31qoayaukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31QOAYAUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id y16si260342wrh.3.2021.04.21.03.52.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 21 Apr 2021 03:52:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31qoayaukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id i25-20020a50fc190000b0290384fe0dab00so9232669edr.6
        for <kasan-dev@googlegroups.com>; Wed, 21 Apr 2021 03:52:05 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:c552:ee7c:6a14:80cc])
 (user=elver job=sendgmr) by 2002:a17:906:3d41:: with SMTP id
 q1mr31542346ejf.282.1619002325029; Wed, 21 Apr 2021 03:52:05 -0700 (PDT)
Date: Wed, 21 Apr 2021 12:51:31 +0200
In-Reply-To: <20210421105132.3965998-1-elver@google.com>
Message-Id: <20210421105132.3965998-3-elver@google.com>
Mime-Version: 1.0
References: <20210421105132.3965998-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.368.gbe11c130af-goog
Subject: [PATCH v2 2/3] kfence: maximize allocation wait timeout duration
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, jannh@google.com, 
	mark.rutland@arm.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, hdanton@sina.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BKLqZcru;       spf=pass
 (google.com: domain of 31qoayaukceymtdmzowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=31QOAYAUKCeYMTdMZOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--elver.bounces.google.com;
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

The allocation wait timeout was initially added because of warnings due
to CONFIG_DETECT_HUNG_TASK=y [1]. While the 1 sec timeout is sufficient
to resolve the warnings (given the hung task timeout must be 1 sec or
larger) it may cause unnecessary wake-ups if the system is idle.
[1] https://lkml.kernel.org/r/CADYN=9J0DQhizAGB0-jz4HOBBh+05kMBXb4c0cXMS7Qi5NAJiw@mail.gmail.com

Fix it by computing the timeout duration in terms of the current
sysctl_hung_task_timeout_secs value.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 12 +++++++++++-
 1 file changed, 11 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 235d726f88bc..9742649f3f88 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -20,6 +20,7 @@
 #include <linux/moduleparam.h>
 #include <linux/random.h>
 #include <linux/rcupdate.h>
+#include <linux/sched/sysctl.h>
 #include <linux/seq_file.h>
 #include <linux/slab.h>
 #include <linux/spinlock.h>
@@ -621,7 +622,16 @@ static void toggle_allocation_gate(struct work_struct *work)
 	/* Enable static key, and await allocation to happen. */
 	static_branch_enable(&kfence_allocation_key);
 
-	wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate), HZ);
+	if (sysctl_hung_task_timeout_secs) {
+		/*
+		 * During low activity with no allocations we might wait a
+		 * while; let's avoid the hung task warning.
+		 */
+		wait_event_timeout(allocation_wait, atomic_read(&kfence_allocation_gate),
+				   sysctl_hung_task_timeout_secs * HZ / 2);
+	} else {
+		wait_event(allocation_wait, atomic_read(&kfence_allocation_gate));
+	}
 
 	/* Disable static key and reset timer. */
 	static_branch_disable(&kfence_allocation_key);
-- 
2.31.1.368.gbe11c130af-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210421105132.3965998-3-elver%40google.com.
