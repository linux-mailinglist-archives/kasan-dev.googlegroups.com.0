Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3VD3OBQMGQEOAX45XY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id 32B8535F269
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 13:28:47 +0200 (CEST)
Received: by mail-ed1-x540.google.com with SMTP id o4-20020a0564024384b0290378d45ecf57sf3179075edc.12
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 04:28:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618399727; cv=pass;
        d=google.com; s=arc-20160816;
        b=JrdPIRkaMdZzh0oasOgJQER6QE8sZqADUhJci+c2JDDPuvCzhO6G4P11lpkIGbclKB
         PsUUYVKbiLEhQpJUPRXe+/Uem3ohDSIlG+8Nk8YCeM/nlYHvuuhNkdtTRKjjuKeXYf+F
         gAYREc8U3fc3CwGdZde9F1KuJCts9HIiJaXdJyvdEMEDJoBh+cCcX9lWH8Ne0lmynWFG
         jhu4jk+ApvHYZHy4HZPFUpUt/T4qO66AQJnipN8Y4l3b9PxeXGwgHW7O9ESkYY2NYrBZ
         5lFzrCmQ6k7DklBC3WtMSMoKadn9iPteUMbfq6pEL5rMPoQQUo2CXZMWdRf5mz5WL+1k
         ZPKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=BsUqAWnrPbv7isCi0WjzC3LFU6Ck6/BvR7h8Xv6/qC0=;
        b=lb0+T7c1P3qwz4ozp10tOCTyadhlYxEZrM9MWdVZkehaMYN1PpXIU/buVGZRoaQlYt
         YXGs84P4DYu8u4uOyAkHGGwDz2cPN2nKXp1SD4VjLvD2Ukku0Zuz8C/UfeuVzgJ3n6Uh
         N54LZIQh2b3EASSFhN7gHtwktzy307jtS4islUFEA2ZcmS0/fdAHPXDrGaxSXDNAwL0X
         9KJRpmQyxVujXsG7umcDuFceHvc5cvrRbzoNvKy9ZtKmfr70JOqPZ/iMuZlSq8simUJI
         uAWpG/SOOqLFI+r5hnwBiuRYxubeqvczKErO5o4EHq4PO9gXigsYH6NeLR3rUwWD/q6d
         YUag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vw/WsGYw";
       spf=pass (google.com: domain of 37df2yaukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=37dF2YAUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BsUqAWnrPbv7isCi0WjzC3LFU6Ck6/BvR7h8Xv6/qC0=;
        b=Z+7baMJGM810UokdyqnoowGOQ3tmR1y3+6DfYITsTgWtFJrc9FSYC9AUXzlL9xbOff
         faj/BWTbgE6I0gLEegavqROs7BNK282wahIszm93vNrxUAdnJF2NbtBmKuP4StnW9C1F
         0zh4qjG2012mwEyV3RiOU+KhTGsJ1ticTpbMFs5wAZvbA8qhmXGb3evw4UkXoPvp7vIV
         vJzXyevoHkIK5deiuWQm/PoCr2vTuplO1YxTuuB1ghAcVenJMudCjQrgqlohPx9Z+JpH
         HSavTTnyPlfpKJIjmKAUO8dtCFu7RvnJG7lSanKejGed4vcOvKob1qqHVkyznL+RPeMJ
         lGJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BsUqAWnrPbv7isCi0WjzC3LFU6Ck6/BvR7h8Xv6/qC0=;
        b=HoJUSl0AtecBsH52ZGBbF6xQgvTYYxYdj8bywMU7M77pHluuK4XLtQ0nnVOxGFmkCM
         cfBXLXw+Hsem9toXhF0glEExFu+qh33ifuhinKkJ1BpbILIuDj4ijrBx7WxxE79O/Bcf
         dJ9xto4+GOhtoC0jIptFVSSG7yWfBBevGZRjxS1vGWosfRn3UevhhsEL0Uq4g/LWuelI
         Dr49IdE2u+8piIAlLy4P6/1mG+Bl6inKA8Pff9mUw/6Y162qugrWm2UtNQBCuPopE4K2
         Io5UJQ/g6Hle3DOdAQm/hifwpzD0NkhhgIvT6/tu3dIhCGKsvBYohtfKufqXU8YVkK8R
         W9PQ==
X-Gm-Message-State: AOAM530423h/GzSlbl/IqCduya1r8N+dF8Kc/hQS1MbvkrNR+2pDvTLW
	QJ3mpHBK2ySE/psrAvR/RzY=
X-Google-Smtp-Source: ABdhPJwNzffJHjyuFtGBvoA7SKMIUZ+LuQ2vn9kp1cyuoCz8Kcp5SlUMi0VShITl7Tn6T/5c9FyYzw==
X-Received: by 2002:a17:906:4c91:: with SMTP id q17mr37648319eju.0.1618399726973;
        Wed, 14 Apr 2021 04:28:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:515:: with SMTP id m21ls693953edv.1.gmail; Wed, 14
 Apr 2021 04:28:45 -0700 (PDT)
X-Received: by 2002:a05:6402:c7:: with SMTP id i7mr40864011edu.33.1618399725820;
        Wed, 14 Apr 2021 04:28:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618399725; cv=none;
        d=google.com; s=arc-20160816;
        b=0ud7jXfBrdJGuZD0sOPfUgGMCSxp2b0TvG7HHbpbFs9t2Q8+hOHR0Okl5i/YGerxB7
         ZTKHTx5Iy5pbcF61HYhuMGYQPGx1EugPGRqiTGeI/HFQbRuQvQmcTgGqseCaEXxWw/7V
         pPapMpz+N9g3C4wL1jOmCV3h8JTZUkPqBqNEhRxOVJUDb+XOyvtT6ehOPUCrMkGYTWXB
         4Z7Ja3qHJQ9r75Llo2oEOfi0kDR04b/qE+7jsRYdTcy3UfeN4ibLNXXL0IohgvxZOHvD
         6WQOomyomeMNh6bnUDRGHUPY6ZNTvVCckhgoknRVTzRuGmwvOmnVWYCejtFqI0S88eGm
         hCxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=VkOAwUtZ9qQlBvfTOOD6U+Kd6iuYzrcUXQ5MLQjL3Vk=;
        b=I1SpXBCKozU9KhlhxjWCedEW7gDXiBrZ6PoSG2Rh+HyfnsOlcA3vppTvfWuPf2RE77
         GN+MQ6uyyWdU6tM4gxh9lqPcdo8+1IeVEO6xLMGSOZi9rVx9lSS6Qmi2d67i0YxOxDLx
         aqHU/KISr4Lbxgx8KxulG5V6hp3RPJtwvJhYH42LriRQkvkL/1+VN3eMscQ2px0Moms7
         0W9XvNW6KH/upyM9M/X5N54X8qeoHvzF2AUQukCjidvRs3yBzC4V5hJUbWxACX0EMujE
         DuF7mye02N4EpfRnkNFAOYGvWK34JsYINcL0LtmCRONOBWNZb8yxXFLZgf6Ql33GO2Og
         MXLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vw/WsGYw";
       spf=pass (google.com: domain of 37df2yaukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=37dF2YAUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id y16si1361397edq.2.2021.04.14.04.28.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Apr 2021 04:28:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37df2yaukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id r10-20020adff10a0000b02900ffcb40a9b8so940264wro.5
        for <kasan-dev@googlegroups.com>; Wed, 14 Apr 2021 04:28:45 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:4051:8ddb:9de4:c1bb])
 (user=elver job=sendgmr) by 2002:a05:600c:4b92:: with SMTP id
 e18mr2621686wmp.150.1618399725592; Wed, 14 Apr 2021 04:28:45 -0700 (PDT)
Date: Wed, 14 Apr 2021 13:28:17 +0200
In-Reply-To: <20210414112825.3008667-1-elver@google.com>
Message-Id: <20210414112825.3008667-2-elver@google.com>
Mime-Version: 1.0
References: <20210414112825.3008667-1-elver@google.com>
X-Mailer: git-send-email 2.31.1.295.g9ea45b61b8-goog
Subject: [PATCH 1/9] kcsan: Simplify value change detection
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: mark.rutland@arm.com, will@kernel.org, dvyukov@google.com, 
	glider@google.com, boqun.feng@gmail.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="vw/WsGYw";       spf=pass
 (google.com: domain of 37df2yaukcxyyfpylaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=37dF2YAUKCXYYfpYlaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--elver.bounces.google.com;
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

From: Mark Rutland <mark.rutland@arm.com>

In kcsan_setup_watchpoint() we store snapshots of a watched value into a
union of u8/u16/u32/u64 sized fields, modify this in place using a
consistent field, then later check for any changes via the u64 field.

We can achieve the safe effect more simply by always treating the field
as a u64, as smaller values will be zero-extended. As the values are
zero-extended, we don't need to truncate the access_mask when we apply
it, and can always apply the full 64-bit access_mask to the 64-bit
value.

Finally, we can store the two snapshots and calculated difference
separately, which makes the code a little easier to read, and will
permit reporting the old/new values in subsequent patches.

There should be no functional change as a result of this patch.

Signed-off-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 40 ++++++++++++++++------------------------
 1 file changed, 16 insertions(+), 24 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 45c821d4e8bd..d360183002d6 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -407,12 +407,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	const bool is_write = (type & KCSAN_ACCESS_WRITE) != 0;
 	const bool is_assert = (type & KCSAN_ACCESS_ASSERT) != 0;
 	atomic_long_t *watchpoint;
-	union {
-		u8 _1;
-		u16 _2;
-		u32 _4;
-		u64 _8;
-	} expect_value;
+	u64 old, new, diff;
 	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
@@ -468,19 +463,19 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * Read the current value, to later check and infer a race if the data
 	 * was modified via a non-instrumented access, e.g. from a device.
 	 */
-	expect_value._8 = 0;
+	old = 0;
 	switch (size) {
 	case 1:
-		expect_value._1 = READ_ONCE(*(const u8 *)ptr);
+		old = READ_ONCE(*(const u8 *)ptr);
 		break;
 	case 2:
-		expect_value._2 = READ_ONCE(*(const u16 *)ptr);
+		old = READ_ONCE(*(const u16 *)ptr);
 		break;
 	case 4:
-		expect_value._4 = READ_ONCE(*(const u32 *)ptr);
+		old = READ_ONCE(*(const u32 *)ptr);
 		break;
 	case 8:
-		expect_value._8 = READ_ONCE(*(const u64 *)ptr);
+		old = READ_ONCE(*(const u64 *)ptr);
 		break;
 	default:
 		break; /* ignore; we do not diff the values */
@@ -506,33 +501,30 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * racy access.
 	 */
 	access_mask = get_ctx()->access_mask;
+	new = 0;
 	switch (size) {
 	case 1:
-		expect_value._1 ^= READ_ONCE(*(const u8 *)ptr);
-		if (access_mask)
-			expect_value._1 &= (u8)access_mask;
+		new = READ_ONCE(*(const u8 *)ptr);
 		break;
 	case 2:
-		expect_value._2 ^= READ_ONCE(*(const u16 *)ptr);
-		if (access_mask)
-			expect_value._2 &= (u16)access_mask;
+		new = READ_ONCE(*(const u16 *)ptr);
 		break;
 	case 4:
-		expect_value._4 ^= READ_ONCE(*(const u32 *)ptr);
-		if (access_mask)
-			expect_value._4 &= (u32)access_mask;
+		new = READ_ONCE(*(const u32 *)ptr);
 		break;
 	case 8:
-		expect_value._8 ^= READ_ONCE(*(const u64 *)ptr);
-		if (access_mask)
-			expect_value._8 &= (u64)access_mask;
+		new = READ_ONCE(*(const u64 *)ptr);
 		break;
 	default:
 		break; /* ignore; we do not diff the values */
 	}
 
+	diff = old ^ new;
+	if (access_mask)
+		diff &= access_mask;
+
 	/* Were we able to observe a value-change? */
-	if (expect_value._8 != 0)
+	if (diff != 0)
 		value_change = KCSAN_VALUE_CHANGE_TRUE;
 
 	/* Check if this access raced with another. */
-- 
2.31.1.295.g9ea45b61b8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210414112825.3008667-2-elver%40google.com.
