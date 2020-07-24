Return-Path: <kasan-dev+bncBC7OBJGL2MHBBDUO5L4AKGQEF5XYJ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x238.google.com (mail-oi1-x238.google.com [IPv6:2607:f8b0:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7AE1522BE6A
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 09:00:31 +0200 (CEST)
Received: by mail-oi1-x238.google.com with SMTP id u7sf4209146oif.11
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jul 2020 00:00:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595574030; cv=pass;
        d=google.com; s=arc-20160816;
        b=xlSkhucihbpFRgIvv0VgcoNtN9cRUUffMTYPnJZ8zcR8R/K8CmdFbTsoS6Dvb9SPR3
         C9jPAF6c1YJ6eNkbcFQH1AV9v0Ri8YOlhnijZIOf4dg6Dn4dl72AgOiWcdXEQ4v2ONEQ
         vtvMwb8RRzEvMA8H9UnLenIc/ThC0PkSVLvVSHXy0L57iK3Ze4Jjtv6N4g2l1lfe7P8Z
         ECUyIYQii1q5GDLaI7IbWVIguS+OSYQnqPB9Jm97nLxOsjbCRmdFu9VsvfW4gGqGLEjr
         Dnxno6amT9c6pFPoDei9DIbtXNZd+3NKAFtZidjgjAIBzQSPzon1Ior4Od8gpadbiI5i
         Mg1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=U4cwG1eAxsg5UPE26hmmp10BEqiTQ1a+BnC97uSkL3Q=;
        b=fC1felmV98/G3pWtACoMihT6zRfxw7uzGlFWc2xbZNvQdqYAXl0uRphofnI4lXiojJ
         tvwVrAp8BrSGlUGzzmbHZnnBHpKj0IFXBIhIq5XqzjsxEweHMnZ66pRF1h0TcFknA2kF
         PoFz5q2NWpm4u6/GroQ9Ye9HfwGd0oDdj70Yca1Cado9ZOqK7HFMvg9oAQZ84NrOER18
         5lqXYm0sa+NRUxQEST7FsdpPfiNtZYuV9ePGk7zoqrrO8w7he9z5A6qJlVXnsK5THhGz
         pcr6j4l3BhOV7rml6H48r66ck/hnKvkS7VaXfTP8VYlvljOEn5lWw4pbXH+KWzz1wXOM
         OfDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=utBhLhz3;
       spf=pass (google.com: domain of 3dycaxwukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3DYcaXwUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U4cwG1eAxsg5UPE26hmmp10BEqiTQ1a+BnC97uSkL3Q=;
        b=LyJ4O2J4mgYm8lQdGRMHOJyMSEIIeWAEpK2Xs4R8lYSi2c8wCwFNXAB7/TtgLvpiIM
         nLW7wjqEtTqsQhWcYH2n+NYgMJ/Ne7rMKVER99m67pqrlvdOK0fH6XVdH94LhfvGbEJa
         LmRVryPnzRzgotythuTpVp4biYx2zIKrqc4E03eRRV9O8xlUwTo6xSu0ZrIHmEce5SFV
         7ukiMY6IlHp8i731MDqk6FxnsvzT2Soe652+79AdatDRLzkSsQZLKEWDH4vHmfwZspmb
         IwMv+VIK6tiiqrwJYA3jQDkkZmrx/J54y25nkso9Wtin041VtYqP7lHybWDJFjw8D2uj
         ihMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=U4cwG1eAxsg5UPE26hmmp10BEqiTQ1a+BnC97uSkL3Q=;
        b=SjUqWGrw5FhXvEAc2b9I/QXNvOzGUquPxsbqaa+nThg4YNnAilyg5iklxdQUD3ypfY
         RLWklTRQqjA8yjMqvJefGrQwg8eoCSTz6tq9jLvoE/1ynovuDf2Z3sFIn4PSF+HLtWND
         9VOpgSgXeQ+uHh0gtDXBLWB5RtMWVBkyRrWPKGhomr0Fjmc5+gYLjruyz4Y+s8lGorEV
         xcx7W0KYu6dwIAjvHPnoKDrdGrsddh1l5vXF1xTMXQDx6m75mrf0MNbOCkuVG+1xtc7h
         14WX6IwVDOsxuxCxktjrXv0iKc16aoXhoaRyvAxyKPPdnN9Jwj/fbSv1TK7++afkSkby
         5WrQ==
X-Gm-Message-State: AOAM533jv0un2uGRm0uNCPTH3zfi4EgMGkdv0KRjDjFxMCs0hjd89GzC
	OuDlK55OC64QKG4XN2y6JpE=
X-Google-Smtp-Source: ABdhPJzS+zVlNES81uaYFieqUCwl4CUouYGc5V+lf2QunYWZMg47/aQ57yE2UbXTcy14/gffB8zuCg==
X-Received: by 2002:a9d:868:: with SMTP id 95mr7629473oty.304.1595574030197;
        Fri, 24 Jul 2020 00:00:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:31ae:: with SMTP id q14ls1617945ots.2.gmail; Fri,
 24 Jul 2020 00:00:29 -0700 (PDT)
X-Received: by 2002:a9d:eef:: with SMTP id 102mr6172176otj.225.1595574029879;
        Fri, 24 Jul 2020 00:00:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595574029; cv=none;
        d=google.com; s=arc-20160816;
        b=gOZpZyZl52y37yzRjuuEh7dMtKBd9Akp/hGBhLUcWLBEo0BmdPYvXuty9hXnROGvkH
         5WTdY1uxX+zIhmujOSNtfHLyTVHSD/1uUsRw33iuKMZJjFlBIJx4SKPflQfKyTPU9G/F
         kb7PLNWbpVABKn7HABfCsgH+nf+O4XNn9zypl5DvJhCrbOot47QRotIBU5pQdi8eKZQH
         4hMwrBXyC8SpgUvmWyR8Pz5SJ9U19G7SQ8Rhi8w8PgC8Cf/lx8CQmNz2IYa4N/Jew3+i
         Ww3mPcrzMYZ0H09AUnK8FU0HbO6hOAX6oe7HraExI2gPjEJJbp3IlkBpOtBbCJ72DuAr
         3EcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ROSpznE7uIV54LbFh2Cka7vTr1SComFhGsjc+g8qPz8=;
        b=N+P53k4tlTDXOYC9V6XecQedguV0MIKgzs9IT9d9XcX/NmOsHHh3Z47AXPLfyzjvow
         pDWhiRVwF4vcA/ZSZJb87OQ+Y447y+FgKeq9ga3V1u3EZKUP6zFG9aNQSQwHqNgtAz45
         WHjkSnC+Z3y5VvoIRE/36SVyYlSJGDnoBFlhpiXB9qfopMfItubRP5eQaRTz8KmHjiDQ
         IXB0opSCRx+kabQmB2uQEYW93UNQNb9gkRa9hEuYgo/jtRW9d2Z7LQv71WZBiXmNoMgE
         d0WtvPA2cs2wXR/lnhMqUn4owxKTaUwPOvrbnRT5R3QXWDCsDHSdUmPSjp6swfz8QWh6
         8VCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=utBhLhz3;
       spf=pass (google.com: domain of 3dycaxwukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3DYcaXwUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id m21si2345oih.4.2020.07.24.00.00.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Jul 2020 00:00:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dycaxwukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id v20so5241544qvt.15
        for <kasan-dev@googlegroups.com>; Fri, 24 Jul 2020 00:00:29 -0700 (PDT)
X-Received: by 2002:a0c:e78e:: with SMTP id x14mr8617576qvn.65.1595574029293;
 Fri, 24 Jul 2020 00:00:29 -0700 (PDT)
Date: Fri, 24 Jul 2020 09:00:03 +0200
In-Reply-To: <20200724070008.1389205-1-elver@google.com>
Message-Id: <20200724070008.1389205-4-elver@google.com>
Mime-Version: 1.0
References: <20200724070008.1389205-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.142.g3c755180ce-goog
Subject: [PATCH v2 3/8] kcsan: Skew delay to be longer for certain access types
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=utBhLhz3;       spf=pass
 (google.com: domain of 3dycaxwukcyqmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3DYcaXwUKCYQmt3mzowwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--elver.bounces.google.com;
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

Signed-off-by: Marco Elver <elver@google.com>
---
v2:
* Commit message rewording.
---
 kernel/kcsan/core.c | 10 +++++++---
 1 file changed, 7 insertions(+), 3 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index fb52de2facf3..4633baebf84e 100644
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
 
@@ -449,7 +453,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * Delay this thread, to increase probability of observing a racy
 	 * conflicting access.
 	 */
-	udelay(get_delay());
+	udelay(get_delay(type));
 
 	/*
 	 * Re-read value, and check if it is as expected; if not, we infer a
-- 
2.28.0.rc0.142.g3c755180ce-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200724070008.1389205-4-elver%40google.com.
