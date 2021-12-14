Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7FJ4SGQMGQETSKKMCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id DDE94474D7C
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:44 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id f13-20020adfe90d000000b001a15c110077sf449510wrm.8
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519484; cv=pass;
        d=google.com; s=arc-20160816;
        b=G7q9QbpraTxEZYP3MwksJYk4m/GlXbytR3BhO/YYgtNDor4soZOj4ogrCmcDo7oiEf
         kHZMtmVhZ23KF+/Bdr5Bl/bbU4xTXG+hdh1XaCxG7ojooQx+mNTP0Pvrcg3zecc4cjjF
         3mMQaV92g17fRnjpAXuAFwGE2/ncQzwDl2hhl+HhlM/JMtBAUkuo8jHoc+ZzLWDGtQgM
         hH3+PGKka4gHA4uEGynD/HE7w9vI93k/O6px8+wMZ4ltBcPLQ12juO+kJMgbirFle3N9
         HmkW6kplPwL2XnNDvyv0/YrMUvw+LRYjILruMWedldpjDj+8YY2LjhWO99odRDo2AZM3
         ho7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vFTXjziW80PBAYWkNfTPVUof3SKtTpxgJTegTK2UUAw=;
        b=LvCJaNW6MQ/sweL/w45LLqTQ3RKGQS5cpB2POQzbkYI4MhqWXYBTUtdmRMM7N8ap7X
         v008ibqY4XCzd3YxDtPqKX7T64b9/O37rGwmbwx2lKkB/JGvm0+Hk+Utpa5QKH/9Yget
         C28RuOsNUT4hv/ob2yRiwRJjq8UL2vISKVk59c//likOAh2KfJSlweRfAtMVRdmF5Sxt
         hXEhR0G1Zk+3ZdcZy9DR5b+zNm29XTYmd9pTPvszw5L5c9kT1fIeKNYe3eta9U9HiMnj
         mul3t6AEoFD3mFH71UBz33TxvfdGovmm602aryvUzlI7O02BKZDwcj/0bbardAHdCDAE
         89Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WWFffCBm;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vFTXjziW80PBAYWkNfTPVUof3SKtTpxgJTegTK2UUAw=;
        b=eqZz61GE00a2wQk7C/sM9JgPBqa1GOopStwB5TJRUUPiWm8jNc4pg5aD4dd26WZXVU
         xRCx5frhkFDRQ/JFl6mNRUEXkCnNdEWlSApsX8pQqsOxIOzMw9vJ3NC5ZvPFDSNoj5+1
         3sdp7NCnOoPnpO2gC3OCfKgeYvGE5jX/ohgj8V9H3kdFF0mUhlBARZbFXWr3TpVWEJZn
         mERyCx6oWDh2lp/V9ZuKmI+pLNy9X9x9c6S/7KVfBdbcMGS0rrL+Ph8WdTyYOyCfe8Ss
         L2OF6nhOdLCbjHPCNc5YBxhgyud6MceMTkQ3RJxBSU/+SAXlFPsB9PLLJEmejCEf8sS1
         0HQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vFTXjziW80PBAYWkNfTPVUof3SKtTpxgJTegTK2UUAw=;
        b=d0QVOtfWpF6hxM91HXQwuZAugL2f/LvKNr1judUuf85EaLq3AQobqauYazjZkkrXUg
         9QkJUqMh7LvG/JdZbQYDcCAkwy5CAqVV07LFVl2q53cjzlhT9QpV44KIdHQlH4DP6TpJ
         n9zUJ5Mu/7aLhHUQoZjBNRCmSylFFjVqgB5g4h+ECT+5PcR9P1spQ9u5+0h0+bnO0BUL
         NOh9qsfC9J5VEijx0CvWVtBStMvu5fP6kCOo0m8VNqVcF/F5S2Umx6G+2TqRxLEzfQlT
         jHLMxiVjsuNj8flhAz/swpmwlocbzy8uTWMNHUiyuXBY7ctRRITY8gzRSS3F85PRDWeh
         Bqkg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533rCTBeY5rNrkrvB3qQupyZYjQeOYjQcyNwkvOmGZg0QqNCnfUl
	NU/3pQkEUuoV78AQ9PMbHyY=
X-Google-Smtp-Source: ABdhPJz9/7Bwo8ZuWRAgsFJSdS+SkBIuB+TZNHHH3WlBhLwIUR/IlRxcZzt4m2G8yCUzf855zDn1mQ==
X-Received: by 2002:a1c:7f43:: with SMTP id a64mr1809149wmd.133.1639519484505;
        Tue, 14 Dec 2021 14:04:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d21b:: with SMTP id j27ls198594wrh.3.gmail; Tue, 14 Dec
 2021 14:04:43 -0800 (PST)
X-Received: by 2002:adf:ef52:: with SMTP id c18mr1743503wrp.162.1639519483440;
        Tue, 14 Dec 2021 14:04:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519483; cv=none;
        d=google.com; s=arc-20160816;
        b=KOW5W5ty4SsesV6ho6VQlWqW6cL95K/9cPTVuaoTm5N9VDdUKN6e+LayJuZndP7Ka/
         k8wfhcctMjd6A00GQTV+shGBtte7k7jD7/Z+07b98Rk3YMq8H6z9rlLGT/4tuZK1DHhM
         5/qexXV1hXXOIpJkN/sLW9Fe547wjEgCkEXw1FLWEvhze/nI02sZrYm5Xaebhxw2dc4n
         LnoJiRv/TtymVOtvT1LOG9uQjfKLhALi6MrbR/Ao1IPjmbn17UkGELjLkXbuonHQLYcg
         4lxI/fUKh9q6F/z5rO9ZN4s89Izs8ixop3xrG8dwUgAqomFYm2AoTkSIeVxN12qhvLLU
         g1iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=NrXSJVXN4zZ0z+hoooUBU6DhGeA64lr1ugAZVL2mKz4=;
        b=GRPBa75sFFaanEdHmLV7Mywc52q2bMQzHcofx9h5eIL4ghvUEqw1fbboCaB4zU9I+6
         X5bmLC/Sm/SXhDLKRHeWHqL6jONDa9K7myOAoFteLw/T0su2sdJPBuVwX1M2P6LUsecv
         mvWAyfI4UrC7BNo9OosGgZL/umGNQ/cz46ajn22zPaDNExgd6hx/R5oRABJ6AZgu50me
         QNiglpvpMh1B84T/coBD9oqEWEq7+Un2rLq5QCtci6TcfCvXO5NNcL99yQ0gcWng/oUo
         4jLlTNO9WZITMh2foSCeW9+ZgaJnOiK83dZ3GGCyQzbZ5zrbEXCakYPzdsydE3K1t0le
         Ixaw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=WWFffCBm;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id g9si7849wrm.3.2021.12.14.14.04.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:43 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 295B66171A;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 89C3FC34605;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 585B95C03AE; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 01/29] kcsan: Refactor reading of instrumented memory
Date: Tue, 14 Dec 2021 14:04:11 -0800
Message-Id: <20211214220439.2236564-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=WWFffCBm;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Factor out the switch statement reading instrumented memory into a
helper read_instrumented_memory().

No functional change.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 51 +++++++++++++++------------------------------
 1 file changed, 17 insertions(+), 34 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 4b84c8e7884b4..6bfd3040f46be 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -325,6 +325,21 @@ static void delay_access(int type)
 	udelay(delay);
 }
 
+/*
+ * Reads the instrumented memory for value change detection; value change
+ * detection is currently done for accesses up to a size of 8 bytes.
+ */
+static __always_inline u64 read_instrumented_memory(const volatile void *ptr, size_t size)
+{
+	switch (size) {
+	case 1:  return READ_ONCE(*(const u8 *)ptr);
+	case 2:  return READ_ONCE(*(const u16 *)ptr);
+	case 4:  return READ_ONCE(*(const u32 *)ptr);
+	case 8:  return READ_ONCE(*(const u64 *)ptr);
+	default: return 0; /* Ignore; we do not diff the values. */
+	}
+}
+
 void kcsan_save_irqtrace(struct task_struct *task)
 {
 #ifdef CONFIG_TRACE_IRQFLAGS
@@ -482,23 +497,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 * Read the current value, to later check and infer a race if the data
 	 * was modified via a non-instrumented access, e.g. from a device.
 	 */
-	old = 0;
-	switch (size) {
-	case 1:
-		old = READ_ONCE(*(const u8 *)ptr);
-		break;
-	case 2:
-		old = READ_ONCE(*(const u16 *)ptr);
-		break;
-	case 4:
-		old = READ_ONCE(*(const u32 *)ptr);
-		break;
-	case 8:
-		old = READ_ONCE(*(const u64 *)ptr);
-		break;
-	default:
-		break; /* ignore; we do not diff the values */
-	}
+	old = read_instrumented_memory(ptr, size);
 
 	/*
 	 * Delay this thread, to increase probability of observing a racy
@@ -511,23 +510,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type, unsigned
 	 * racy access.
 	 */
 	access_mask = ctx->access_mask;
-	new = 0;
-	switch (size) {
-	case 1:
-		new = READ_ONCE(*(const u8 *)ptr);
-		break;
-	case 2:
-		new = READ_ONCE(*(const u16 *)ptr);
-		break;
-	case 4:
-		new = READ_ONCE(*(const u32 *)ptr);
-		break;
-	case 8:
-		new = READ_ONCE(*(const u64 *)ptr);
-		break;
-	default:
-		break; /* ignore; we do not diff the values */
-	}
+	new = read_instrumented_memory(ptr, size);
 
 	diff = old ^ new;
 	if (access_mask)
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-1-paulmck%40kernel.org.
