Return-Path: <kasan-dev+bncBAABBYH5WT5AKGQEXAV6IBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id A829F2580A1
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 20:18:09 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id q2sf10102763ybo.5
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Aug 2020 11:18:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598897888; cv=pass;
        d=google.com; s=arc-20160816;
        b=bvI843Q78470scw8YrCnM12IlalJisJpW2pWnkHKmC4C+kIn8KctajXNIm6NS76SOa
         nwyhUN+LwVXw/2Ue0zU3yyoWadamz0rt1vJdli7up5+sSr1yJKhS7tohqPhjjYwKpf8p
         YXwVfeP/X+RzJiqX0THWsXfb6zDoBOROdgd4D7Q6EyqZnnPVd4ltFMtl5COhsdICK+Jm
         TWk9mr3G6+CsBOVl6pDMVeXIv0AZwzn0/ZuCUQKucl5PObaIkEEBd1GKxod+4bJZDDbO
         pm5aY796fwelfkELiFMRbUmbq7e5nuhzMMpGiGRm2iOgldXzzYOtYOSQ1nDxDQ57L7tL
         ySAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=v89fjdyQAf3/0b9qwv459I0KgNicDeZ89Her6P/uHIk=;
        b=E5X7DjOZhLeVifuu3eQpeq+TIblLt2IUqEDTdCEP4dGp5+hhfeBekgipu9I72t9OD/
         juebX/My63ENTuCDhML6WY4nDjmhb/TCJfm/FJiQBlBhJ8zgNAfBZkdDTNk0YYC2r0iQ
         0vTrAQxAodmeHY1V8zkZnRhJGAEFjW8kOCTdYOG8AmxTJxp8RccgXoO1GmLkW4Br3a6d
         W4gZzH+1/vD5jMVsUBLFiBbuDYMJSFjC+nXh4N6IjH4bT8B1bUQUb7QiZtPVt10j68V2
         trS9M+qzihByEaTC8B+7yqu5zm1hzIU09t3OUop1St0/6Uaos/ZMDjRpG33x/sdXH587
         KEVg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=MOB9L8Ay;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v89fjdyQAf3/0b9qwv459I0KgNicDeZ89Her6P/uHIk=;
        b=c64SncJb+BHoaHCoqWOQwNpDe0J0ael+F0bmDRaQFFjAsb9AghWS1xPVa5xYgV233T
         /9ciYfbzNOS57PEFI6EyW15y7syWRXZ/UrozD9QJVHH8DHDfDiVc3rWNrLS9xdC5Q1ow
         yhzz76+2r4bsiM8JXQE+kOvSNyfltX537/Gk6HGVKbiMo5SO1jI9CCTxwrtrjeH95irp
         zeFoDi7W7NIf8g7Qkj0m19CDNtXT+60admEH4XvHlpYYOjpWApcqsLRLEofDGMShkbo/
         McOK6sQ4U9C/ZvZ3yT/IwXAtcyAccAnnjhkBsAA2ieeP5TigkKlrUERUbojVH8KPKW87
         /H7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=v89fjdyQAf3/0b9qwv459I0KgNicDeZ89Her6P/uHIk=;
        b=r5auo53M2D9QA1L1qUpiwJn9OT0hb54H4aNdqcS8z+i8WoQRU5IPaSwQDdNrqT6cr5
         wIZxKGvL6k9KK84ViyxH6THCgA/qdoIoBt8z+vjItGgpmMWZ8kw7HjwiJtd2y9ADC/5u
         HUk3Pz0kaiE8zznhMzcePuNXzSQ/rFwgVnTC2/Flacld7fKw/u9y12g78elAJ65eHesV
         juHUO8JYgEIFuvNrfxvpA273OoVkWNFC6G0dTyp6jS/4n+Tz5ZyDxopcZFBr+MZdNXqG
         +kxHpFz4/LlAa9bZ0wIVpL2LejvCl1fEX8QKRKWWtmFpEvoRyHtTTMVosH3TwBiEABaa
         f/QA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531bGatM0Q+MQm34VSmBo8WA04MCZFs9dbuuIx5zAiRhmhABvhA8
	7Gha1OnMCgjCmtkVS4QKwEA=
X-Google-Smtp-Source: ABdhPJwl96tfeZcBEO1K06QeQgfy+2OsNl13aaMv1/WFfPOTZxA940RVzlzaAsB+DGkRnpjhh7DuRQ==
X-Received: by 2002:a25:bfc8:: with SMTP id q8mr4186170ybm.156.1598897888556;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:840a:: with SMTP id u10ls3452479ybk.0.gmail; Mon, 31 Aug
 2020 11:18:08 -0700 (PDT)
X-Received: by 2002:a25:8892:: with SMTP id d18mr4371152ybl.70.1598897888195;
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598897888; cv=none;
        d=google.com; s=arc-20160816;
        b=aA1Wg3w0FV0lV0XV+KuqQFKPMFE4E8ma07NVIYbWQeFNMFAFy+alaDfshxw/u1jsr1
         NsLYScJaq7/yUv4eaiCtyypN0ErPLqqSQztp+OYFqJ+lcIPt8+Ukazyt4n6teWLS5sf3
         qspEu7oA1AjRnOIRq6XaQOKLj+4W1Mm+WFe2KrBu9oPTV3vwn1BtPz1JdkkFWFS0H5UU
         E0sA+XEp1SgiVgF6Q1QFDywul1NqXBMKHtdCWb5c6/7MvNDhlgojT+4ttXGmCTVWk5jq
         pUomhiOcP6AVHp/75UAgUs//L2e0pOY5yuoczXo4sOgdMaAFfuOTgZS8cMV2yxrEwYMh
         1U7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=scVbaFsr0xeElyRWWcBbedjZGVr/31+o/vFw3qGq15I=;
        b=MlbfBR2Jq0SbrS5If3AWEGAgCtF+Z2wPn+ZV5sRmENbhsXC+qHNN4MkYeMHgJ57eWN
         0iltSjBkOglxCZ8CD94kYMkhXUnqqKhvjR7D8iJK624zD8+AvGNvzC9JwHvTe/RKmLig
         rmqffdYXLbKjINXyEixIC3asVkKo9WcmW3u5xUk83hfNMyE3MJ/ryNJotQBFq7rKfsFt
         s0Qz261W6KHur6bStil1jSj/CfZvi+prJWXtZOdtGgWl8JM2kHMxGro3s9pkM+4ksP9+
         CvuE/OX2lJn59rnWX9K5Equgca8TQADL9G5VChQYv1x6QFgAy7XcaeID+e8fQ7SxrBHy
         q93w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=MOB9L8Ay;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p14si692718ybl.4.2020.08.31.11.18.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 31 Aug 2020 11:18:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [50.45.173.55])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2776D21531;
	Mon, 31 Aug 2020 18:18:07 +0000 (UTC)
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
Subject: [PATCH kcsan 06/19] kcsan: Skew delay to be longer for certain access types
Date: Mon, 31 Aug 2020 11:17:52 -0700
Message-Id: <20200831181805.1833-6-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200831181715.GA1530@paulmck-ThinkPad-P72>
References: <20200831181715.GA1530@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=MOB9L8Ay;       spf=pass
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

For compound instrumentation and assert accesses, skew the watchpoint
delay to be longer if randomized. This is useful to improve race
detection for such accesses.

For compound accesses we should increase the delay as we've aggregated
both read and write instrumentation. By giving up 1 call into the
runtime, we're less likely to set up a watchpoint and thus less likely
to detect a race. We can balance this by increasing the watchpoint
delay.

For assert accesses, we know these are of increased interest, and we
wish to increase our chances of detecting races for such checks.

Note that, kcsan_udelay_{task,interrupt} define the upper bound delays.
When randomized, delays are uniformly distributed between [0, delay].
Skewing the delay does not break this promise as long as the defined
upper bounds are still adhered to. The current skew results in delays
uniformly distributed between [delay/2, delay].

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 10 +++++++---
 1 file changed, 7 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 4c8b40b..95a364e 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -283,11 +283,15 @@ static __always_inline bool kcsan_is_enabled(void)
 	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
 }
 
-static inline unsigned int get_delay(void)
+static inline unsigned int get_delay(int type)
 {
 	unsigned int delay = in_task() ? kcsan_udelay_task : kcsan_udelay_interrupt;
+	/* For certain access types, skew the random delay to be longer. */
+	unsigned int skew_delay_order =
+		(type & (KCSAN_ACCESS_COMPOUND | KCSAN_ACCESS_ASSERT)) ? 1 : 0;
+
 	return delay - (IS_ENABLED(CONFIG_KCSAN_DELAY_RANDOMIZE) ?
-				prandom_u32_max(delay) :
+				prandom_u32_max(delay >> skew_delay_order) :
 				0);
 }
 
@@ -470,7 +474,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * Delay this thread, to increase probability of observing a racy
 	 * conflicting access.
 	 */
-	udelay(get_delay());
+	udelay(get_delay(type));
 
 	/*
 	 * Re-read value, and check if it is as expected; if not, we infer a
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200831181805.1833-6-paulmck%40kernel.org.
