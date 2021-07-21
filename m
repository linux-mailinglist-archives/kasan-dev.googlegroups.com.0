Return-Path: <kasan-dev+bncBCJZRXGY5YJBBQEZ4KDQMGQE3HOEQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BC743D18AD
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 23:08:17 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id j11-20020ac8664b0000b029026549e62339sf2293332qtp.1
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 14:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626901696; cv=pass;
        d=google.com; s=arc-20160816;
        b=X7qdciLvoWv3Z/aDQrT7jN0tO96GHIvBdJZbTl6x1Ekit7iU/bdVP8AJUzMgQG3oTg
         gwnuFR7mud7cRJgFX8qJH0a+RO172+Ik8jCJnrbp4UPEe+AnYIh/ydv/KFyMPncvGIOw
         wZ0jjwvUZJ0BD7K/J3juk23gQPThNYOTS3UbMXSg23Sa3VL8ppM5P835wPwKk82rrRGZ
         EEfwbfReJ3sls6L6Y2dszfKyxOOR7tUhiL9LQNsVDVgzXezYc0iIBihNhMjdDs0K4fTk
         45LvtUdV86PmRIBj952eqzfYtdr95aH/BpTzRBme7RHYCt4O4Rszvup9HV3PhJ+xVN5Z
         KMiQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=94EJwU/aQRaBmF0uJxJ5vdMXtNNXr12+SVjU/98eYvQ=;
        b=Zu7EI31KsAQfUVy4S2kNtdlADlnRbc0lY0VEbmt9ROdaSzvDgreB7MoyYH9EJV8uI1
         KcPfh5X9JyWbizz8kl1ad7Jkx3q+bpbXbtcgjkcf/y/oViYE4Q/XS+RUaIz9vmSlKI0b
         rsmogF6hbrQWC5VSiBzmnYei+9vjEOm+anoCsfwFVsEAjpqdhS1qaq/XJo8pkC+5eh2z
         f4d6NHfZzq6AiImlXuFTYs2lb/lEMZWTNSl/VpdlTEsMIi4AgErP3fqY7x9QB8MhqsFy
         WtrcQrFeGGjuN5i8pT5M8FSfWfMXFtoVVL/PY/9ED8CEqrTZIiVeKeOh0aZ24lXqWS0X
         7HYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cx/40X+a";
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=94EJwU/aQRaBmF0uJxJ5vdMXtNNXr12+SVjU/98eYvQ=;
        b=elQXtm0B/g2FfgBPAEbbt95dNudBkCM1ffapUzcAULGNrrHHMiP5P9gbMhL/ATwTPf
         gjYs0n/j0Gc3VDnG5JKXuRZ5n818K7j5mKaY3H/KJOGezWdavMzGtRoSkjkHdWpmG5VS
         j/SvKL0e+QAPaEKjQWOxrg0PV6sauSi5cdgSw+BLpyZlUskLNwhA11sWBa2HlADwcjsW
         hJa/c5NJj+JSbF63Iev6zxP4/2f0EwHlZI8nSv/j5pYIdaULTD13mDoIxTiy2VLryl0x
         wrLnehWQ6TwYe1lQsf91hW+8/8gHnDYoF803iOapJm3fRHylTumwcSWzZOEFi2TPmUgG
         0Zpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=94EJwU/aQRaBmF0uJxJ5vdMXtNNXr12+SVjU/98eYvQ=;
        b=tG2wCuWJku8MiqG5Hr6fQEk7B6IOakOJ4hSqfav1ZjLHGSFQOI9av8rHLej6iKCsXj
         47hmrAvoYDe2+YnD5dxbiHeWOSoLMdHLv7vsVG/6Uj/VhqI0q/OoFSywMq+ASiClTV1L
         O6y88hdx8vRKdB8x8lv9axnTCmebMrYi7y0MpabIrVJw4vvLiRZvFS+NYF9HFoGHacSl
         5Gkppenf76yCcKhbfw9rfkZ/ZWLzRKBwiFzflAJrWlwv19+TSYYpT/uAo+aTzBrgSEY8
         WjDsrKH/94+TK/z9Auc/W+AH8/cw7SREERTtc+BQKhodDiEzXCb5PikQh3IoG3sQe6sr
         2jJQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533w2spRZz94eWZQ/1naP3GfOO1aWwit5H3uFV49kdm/uaaQ7Roe
	/TuYFqBhyrf0H1C+AN6E1VU=
X-Google-Smtp-Source: ABdhPJxuFzkE+PBV6lDhObGHb8/XBt2ZHty/IE1T0nrjqv63xJ/d5VHGaEsJnrjpkt4DVgEJJesj8A==
X-Received: by 2002:a37:4388:: with SMTP id q130mr35974666qka.460.1626901696159;
        Wed, 21 Jul 2021 14:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:61cb:: with SMTP id v194ls2744934qkb.4.gmail; Wed, 21
 Jul 2021 14:08:15 -0700 (PDT)
X-Received: by 2002:a37:9ec1:: with SMTP id h184mr37363025qke.0.1626901695722;
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626901695; cv=none;
        d=google.com; s=arc-20160816;
        b=U2jhecDEw0M4A9sMn91+mWHddF6UBuV7GfkOJswOoiiEUNpiXASPm+VIKIbT026xV9
         T8T1OCy303BaeVq+eGU/ZPiOQQmpKTdYlzWq2e6zxvfx1mtSlNzrvPk/fDarj0kS7lyY
         mOxsG9DXzEPnodKSI139cHUG5zD0mlHY9wY46oLKjjJeZnMLD2DsHkkXsAE7rq10v2UY
         +8Sx1P/UwYQUblKSnh/Uh9lduY+RubAAxtQ/bScTSHvKPzUTvyYrkDwk1Zv7MprWJxFe
         RqW2HrRciXd3yQDgpFrxgx9YiFNQEtjYgiNSLwjtbhSO+uq5mSRI671GzDnA/2QpsRgZ
         YTlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5wVVgl8P5u+7HrPxhn0EgbaLpUeNYc9xgCvm0Bfwggg=;
        b=kSofLZoVsDua4Ske1fAiO/+LLppD0mg6r0Ipc2LkxT1Tv1/Xj7e5maasLG9XTcBqHJ
         963lV75aQAG6bY625Y178PmDXH+D83inJM+vvCKHxUMeGkJSaIETiVaEIMh9ybTHCnFH
         ChRw/+lErIvv9xMxFgoHM2N3c7BtzDzT/rSInMehg0BcPhz4tTBCz75hJEnrb5ex7dzk
         I93tBaQYItyoUbsuESpRRKNW3X2i+62YaN5vnR60nhkFyrG49ocSxkZMti76YCL31wdi
         gpeaWqgvSigup+Xc/lw+ouuHCRMU4XW0x4nyPEhXijfGLOHgDdMFrTBarJMd02L733/P
         Ydwg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="cx/40X+a";
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id f10si2296074qkm.7.2021.07.21.14.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A2D97613E4;
	Wed, 21 Jul 2021 21:08:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 627CB5C0A2D; Wed, 21 Jul 2021 14:08:14 -0700 (PDT)
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
Subject: [PATCH kcsan 4/8] kcsan: Reduce get_ctx() uses in kcsan_found_watchpoint()
Date: Wed, 21 Jul 2021 14:08:08 -0700
Message-Id: <20210721210812.844740-4-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
References: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="cx/40X+a";       spf=pass
 (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

There are a number get_ctx() calls that are close to each other, which
results in poor codegen (repeated preempt_count loads).

Specifically in kcsan_found_watchpoint() (even though it's a slow-path)
it is beneficial to keep the race-window small until the watchpoint has
actually been consumed to avoid missed opportunities to report a race.

Let's clean it up a bit before we add more code in
kcsan_found_watchpoint().

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 26 ++++++++++++++++----------
 1 file changed, 16 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index d92977ede7e17..906100923b888 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -301,9 +301,9 @@ static inline void reset_kcsan_skip(void)
 	this_cpu_write(kcsan_skip, skip_count);
 }
 
-static __always_inline bool kcsan_is_enabled(void)
+static __always_inline bool kcsan_is_enabled(struct kcsan_ctx *ctx)
 {
-	return READ_ONCE(kcsan_enabled) && get_ctx()->disable_count == 0;
+	return READ_ONCE(kcsan_enabled) && !ctx->disable_count;
 }
 
 /* Introduce delay depending on context and configuration. */
@@ -353,10 +353,17 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 					    atomic_long_t *watchpoint,
 					    long encoded_watchpoint)
 {
+	struct kcsan_ctx *ctx = get_ctx();
 	unsigned long flags;
 	bool consumed;
 
-	if (!kcsan_is_enabled())
+	/*
+	 * We know a watchpoint exists. Let's try to keep the race-window
+	 * between here and finally consuming the watchpoint below as small as
+	 * possible -- avoid unneccessarily complex code until consumed.
+	 */
+
+	if (!kcsan_is_enabled(ctx))
 		return;
 
 	/*
@@ -364,14 +371,12 @@ static noinline void kcsan_found_watchpoint(const volatile void *ptr,
 	 * reporting a race where e.g. the writer set up the watchpoint, but the
 	 * reader has access_mask!=0, we have to ignore the found watchpoint.
 	 */
-	if (get_ctx()->access_mask != 0)
+	if (ctx->access_mask)
 		return;
 
 	/*
-	 * Consume the watchpoint as soon as possible, to minimize the chances
-	 * of !consumed. Consuming the watchpoint must always be guarded by
-	 * kcsan_is_enabled() check, as otherwise we might erroneously
-	 * triggering reports when disabled.
+	 * Consuming the watchpoint must be guarded by kcsan_is_enabled() to
+	 * avoid erroneously triggering reports if the context is disabled.
 	 */
 	consumed = try_consume_watchpoint(watchpoint, encoded_watchpoint);
 
@@ -409,6 +414,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	unsigned long access_mask;
 	enum kcsan_value_change value_change = KCSAN_VALUE_CHANGE_MAYBE;
 	unsigned long ua_flags = user_access_save();
+	struct kcsan_ctx *ctx = get_ctx();
 	unsigned long irq_flags = 0;
 
 	/*
@@ -417,7 +423,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 */
 	reset_kcsan_skip();
 
-	if (!kcsan_is_enabled())
+	if (!kcsan_is_enabled(ctx))
 		goto out;
 
 	/*
@@ -489,7 +495,7 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 	 * Re-read value, and check if it is as expected; if not, we infer a
 	 * racy access.
 	 */
-	access_mask = get_ctx()->access_mask;
+	access_mask = ctx->access_mask;
 	new = 0;
 	switch (size) {
 	case 1:
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721210812.844740-4-paulmck%40kernel.org.
