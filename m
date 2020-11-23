Return-Path: <kasan-dev+bncBC7OBJGL2MHBBO7P536QKGQEVZ3YSIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3f.google.com (mail-vs1-xe3f.google.com [IPv6:2607:f8b0:4864:20::e3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9925A2C0A60
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 14:23:08 +0100 (CET)
Received: by mail-vs1-xe3f.google.com with SMTP id g3sf3030971vso.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 05:23:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606137787; cv=pass;
        d=google.com; s=arc-20160816;
        b=lpIpeOAphGjCYsa+tMhMKYSQSSm1/1lWdKmMmp+eSchidPpUufDWlomD7s5RFh2GEG
         A7JXVaelol3oQOonpozHdiJzwTIYTSqYOC/Q1IGZ/TEktXv1rPL5hzorHFc5x/iUDUIZ
         6spuQ9EI17a6rFYBoCabKzzfhoz5ciL/yN2CQXi+3UAIKFdUuVxR/bw9pRPZSLc5f46M
         G1+jgDD11AnHBSqe5rVyg9ryYmGvxH1mW8hYITw8vCVbRB6jBhX9aH0iQkn1WxuYZB4r
         8Cb3fUlurcjWhWJHBB3kKtkS0q3GmZ/CxtYjCmmV60ASg682pA+8fJWw1c1jo6c0qK9w
         8LNA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=i9du/5MiFLG6ZSad//BJYiUzRN4UowmgwDeiovZvlAc=;
        b=vxhZbyAzLSRzCFjrOuj8X05MtCHRKVDEIsrGOAcxLNEno+MZAtJoVKKmuA88BsOKug
         Jp7uLRW6CfiM4t7hknen4ls/WS8cZ8G5h9p/Wfdi/3tNl2go2W9vdsG7o/fGyy9lWE07
         73NPWNonPZVkOpp8GODixnNHDzrgaMKIu++aexs1rpzmOo11i8uaMDror2xAtzb+Bjwo
         Z0qJf5dzvWwGZfZ+Tathoau6QXP4lwychSJ0i0NY0cveWVxUhOTsfK/XZZwHAHgkytls
         LbsB0/807zSumCJtLS9OBzcr5+SqKDFxAVpxMOt/1qeooDpNQ/6FNYxxosU23ltFwhPm
         pWGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="i/NiRwJL";
       spf=pass (google.com: domain of 3ure7xwukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ure7XwUKCR07EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=i9du/5MiFLG6ZSad//BJYiUzRN4UowmgwDeiovZvlAc=;
        b=Q7JzwJ/8f3cwPpBszf3m+5QbrU+rQX66Q/TI4K7XbCNV+24r3YofwQHb2tRUKpm1jr
         jL8LbaNDN6/PYtnK+kM+uG67FqXJocRjYtw8jR0Mek/bwL15Tmls8Thuz27Nahnp3MjW
         FhY1rmmyguBUPeRJdnztJddu+xoJeG/AHPUwE60r5pkRX2jc7UTOmtweQgp8sPjHUcjk
         Yp7fHA8zHdKwGfeV1gqqd3Tqx/Ztl1PIClYPQ3QIiRkS9MPqqSGeuYOb158/JXoW8AQM
         QhJf+ngBaBmXzMV+SJfNQYBySFQv7cUd1zET6kdXN/CdD5Tl95H70SBBInJgie1pksHx
         Uc7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=i9du/5MiFLG6ZSad//BJYiUzRN4UowmgwDeiovZvlAc=;
        b=dgqp5V7yk7Nts0aI7cQLxcDTIgSwYXIEw+uEfdxyVGyijux+Z/ttiDJ5Butw+E/ROM
         68o9IS86Vj6bfjCi6qQJzc+XJW0jMHs/pKhtlZtFxeMDTNl6X12i9y7jQKogSCtZsZov
         kjKVUHNDFJ0xlYOHFu5NQg9VuMX4vxkFHGhjTZaloCbRTtmRaJs0taRPNToPIc3ghafz
         xfrdSJ0JhooEl5XjjRgLPZU58xkUkPcOa4x4j8mVvnmngfan68QbrjdvoAHAwa2a2M0s
         76vD7RNk/D+hvsQwRfZDLGeHCLs4Mc49SYds2oDH+SR8uBfQOVqybl6Nsd35GXwC+/o+
         ZEBA==
X-Gm-Message-State: AOAM532mOSMLjMyJptqVRKLjqBDvv2DI7s3SfWJ7vzhA3hS0VnQD+Gf7
	1SzBSJnlzRiVE/94Q9b2A4M=
X-Google-Smtp-Source: ABdhPJz8fmzqVjLPLFYzRCWrxSfbM80Qei3RC3QnBZs3f0lFv9lLxSiGnDMw3/xawsqWGIw6Bf1+tg==
X-Received: by 2002:a05:6102:832:: with SMTP id k18mr2427683vsb.2.1606137787729;
        Mon, 23 Nov 2020 05:23:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c9b2:: with SMTP id f18ls764895vkm.9.gmail; Mon, 23 Nov
 2020 05:23:07 -0800 (PST)
X-Received: by 2002:a1f:1c6:: with SMTP id 189mr19582362vkb.13.1606137786999;
        Mon, 23 Nov 2020 05:23:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606137786; cv=none;
        d=google.com; s=arc-20160816;
        b=zgTLGgSJpV+yFP4wgHbfke8N6d8Ac1b6buD5wxpvJ7ylAbCBZ+boPaocuA8ozlcCRZ
         TZHv+WuwOaG9TscE9zk9dqzxdSbAgJ4jZHr7xDq9mVpqOxFkVRkbpITB7154dlImGpKc
         9wzD1iEFMy42iGY4DtnBUWw/pT5CsG2FP6UN0LpbOtTTc2gWr/xT75hrmhlCiT6EXY0f
         AvKeu34xJliwu8w9ulDzRSBLYqOizS3dzP0KC9JD4YWoYaKCUULlcVrd0OnDJ1Mqv7cq
         M2c7qEXORqW0Hgco246jBQprQS3iBgkwx3wTpfgVM1f3dNAqiKXFweTTWQIv0T+X3PZk
         +hbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=t3/TP+aeGOrrYIoQsNoDeJwx7Pw16YuC73tVL3PfhCA=;
        b=tMySKtTV2iOgeP1E4PuVrV2y5pwishUJmOKGiLlsfaGIX1i5OxKyHn2r6H2CiRZ+yq
         JBelh5hbbGrx5uAfI2FOCbmcBH9316cBLZjiE2hNpGFxAdaXi/0ehAhcjexhBh9HLJ2U
         tu9g00jsZqV0l2ezDU/tSPwlPUYCGizS398J9dgB7AcYI1bH/oSQqR0J59B9qbdx+cSH
         2wg+iWD2WT0RQ1eiobFZNs3lqHCiFZ0iWeJowRGk6VZMVwpoesNqY0SP1Ss5yERGM3bE
         +3LJti1kj4jiIcdgXtTGq/MWBr5Ih5xXkO+y/sbwjaDPdiWc8w3lzuF2l3hShynO/GZD
         3Mmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="i/NiRwJL";
       spf=pass (google.com: domain of 3ure7xwukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ure7XwUKCR07EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id n1si569602vsr.2.2020.11.23.05.23.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 05:23:06 -0800 (PST)
Received-SPF: pass (google.com: domain of 3ure7xwukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id a22so4122044qtx.20
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 05:23:06 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a0c:b5a6:: with SMTP id g38mr13953823qve.31.1606137786488;
 Mon, 23 Nov 2020 05:23:06 -0800 (PST)
Date: Mon, 23 Nov 2020 14:23:00 +0100
Message-Id: <20201123132300.1759342-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH v2] kcsan: Avoid scheduler recursion by using non-instrumented preempt_{disable,enable}()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, tglx@linutronix.de, 
	mingo@kernel.org, mark.rutland@arm.com, boqun.feng@gmail.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="i/NiRwJL";       spf=pass
 (google.com: domain of 3ure7xwukcr07eo7k9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3ure7XwUKCR07EO7K9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--elver.bounces.google.com;
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

When enabling KCSAN for kernel/sched (remove KCSAN_SANITIZE := n from
kernel/sched/Makefile), with CONFIG_DEBUG_PREEMPT=y, we can observe
recursion due to:

	check_access() [via instrumentation]
	  kcsan_setup_watchpoint()
	    reset_kcsan_skip()
	      kcsan_prandom_u32_max()
	        get_cpu_var()
		  preempt_disable()
		    preempt_count_add() [in kernel/sched/core.c]
		      check_access() [via instrumentation]

Avoid this by rewriting kcsan_prandom_u32_max() to only use safe
versions of preempt_disable() and preempt_enable() that do not call into
scheduler code.

Note, while this currently does not affect an unmodified kernel, it'd be
good to keep a KCSAN kernel working when KCSAN_SANITIZE := n is removed
from kernel/sched/Makefile to permit testing scheduler code with KCSAN
if desired.

Fixes: cd290ec24633 ("kcsan: Use tracing-safe version of prandom")
Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Update comment to also point out preempt_enable().
---
 kernel/kcsan/core.c | 15 ++++++++++++---
 1 file changed, 12 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 3994a217bde7..10513f3e2349 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -284,10 +284,19 @@ should_watch(const volatile void *ptr, size_t size, int type, struct kcsan_ctx *
  */
 static u32 kcsan_prandom_u32_max(u32 ep_ro)
 {
-	struct rnd_state *state = &get_cpu_var(kcsan_rand_state);
-	const u32 res = prandom_u32_state(state);
+	struct rnd_state *state;
+	u32 res;
+
+	/*
+	 * Avoid recursion with scheduler by using non-tracing versions of
+	 * preempt_disable() and preempt_enable() that do not call into
+	 * scheduler code.
+	 */
+	preempt_disable_notrace();
+	state = raw_cpu_ptr(&kcsan_rand_state);
+	res = prandom_u32_state(state);
+	preempt_enable_no_resched_notrace();
 
-	put_cpu_var(kcsan_rand_state);
 	return (u32)(((u64) res * ep_ro) >> 32);
 }
 
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201123132300.1759342-1-elver%40google.com.
