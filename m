Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK5P7CCQMGQE43LZ4WQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id AAFF439DD19
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 14:57:15 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id z3-20020adfdf830000b02901198337bc39sf7241351wrl.0
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 05:57:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623070635; cv=pass;
        d=google.com; s=arc-20160816;
        b=dAJ4P7ywgxs5PGPheMdbVSFzCvtQ1tX/c7obrrKMj7Jm2lDkdILtVvyz1HNX93b7SP
         hnoEN+aPwVjlkkjLmm9FmdTtSBeqh85zCvRecw+9SVJ8z9LEBObD2A+Qw/yxjkQQmw4M
         PxdHBCYLHfTluNBN8tb97QABRY7clk3/3mQmh9iAmTx8gFvE8JGiO+LFscM+8RPAXFVb
         kEtCZcsYP8hhKV4PKlIowDLIdwvqsTdS7oKMwomrTPxezuvQohZHV15VTIZ26WFaczJp
         KZRgQh/uSXoY/8SfiuEfT5xIrSXY7YUD0DBpc1RTN9TACmCFzHPrmN4Q3BJ44qZPP8Ai
         HYEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=H6ZeOWvKDN6T0ACW9rQ7nb1APvg2BMrIJ9wG9COVM7o=;
        b=omqILVGq124LlBsOjZR7gbmv00uLHfCL7doK/g2YlQjh+l665VpAm0NGnRTg+37xLA
         yL8h0XKRj0WPPBsqqk932P2ruf9pTaE61nMNxbZhXH6/veEDi3FmnZUHyVqmeJa8KKMl
         1w9fY8M+T3Yhwhm5khGABvatRkEg/J0LfyE71qhLjFDPN2hb7gP46d4A+d1UlOiGrGqU
         bG8W7dCV9xKdQkYHiMf17KBXvLxwhxtyS9phMl9+Vl2wnjFPawEeyriAD8gwdPOZnjrK
         rpXqFGnv6H4RFn9l+paCQoNWt6aiH4GjziFn/6kDSR0y3yHyg35XbXCt/6TtHWrdbzVG
         m+qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kZoDM0QN;
       spf=pass (google.com: domain of 3qhe-yaukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3qhe-YAUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H6ZeOWvKDN6T0ACW9rQ7nb1APvg2BMrIJ9wG9COVM7o=;
        b=l+TFe0SFTU/KuEPDK/TQx8IZoUzH296c8G/A4gJyMFSs98L9dsGfN58eZg8Ommgw7y
         ZG3awrsNz0lVKKur9KDcN9+VjEFC0o59v1dSvoaglmz69g4D2mE8EqZHbWBBvABA58c+
         0OaAjUePK5NR0M/lT8pe6byUz/p/4jBJ+rEiuYagGNrc+mKZUXSiOMApMNCwBTloZsuh
         2EOqZrcsjnmz4z4n/vBCecQN2px/CVHdYc5Q3K6aZLPHr1MUxRn1rg0pw04QIcTOjFY0
         kttNbOM+F8y5ZAjFLxVBlmk3Rfrp8IHXaK+S+eQoxM7qRU/AWyRZimdiIoh/eU1Y1gyV
         o8AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=H6ZeOWvKDN6T0ACW9rQ7nb1APvg2BMrIJ9wG9COVM7o=;
        b=kSDavjWV0mvSiezpspYX8NCqLAvTI2ON1yrrug//oDIspusAGPbN6D+Xt692w0UDK2
         5b7BsBHMlJAVTZHB3LAZOoa02xtSTwRH0uVIMShhOqAeSe+8efyFz17vGDYilIwUkp6x
         ONTsHtZKlFfs05T0muQ60jomvvRquurYu2PyIej7p/moV5DAbE/YTrw0ldyDrTw1JRo+
         gyIJX0y8/kNgIAS0JlnEGaDhaqEKpISs2meMlSADaMeFpUWiitbsQBeKetTgIWcV9yGO
         1OPj0c5On8/BRZv7Em7vsgeGxJiDuGbMETbptjiqILsJH997nO8yYg/Es6NG8+OM7Vic
         ixyQ==
X-Gm-Message-State: AOAM533PE8br7RNFvM4NtZQwsCF6syW8PPWVC8x6MKw+E0+AtrKFr/3Q
	L5/gHTJZ++C6yKw72hk6WBY=
X-Google-Smtp-Source: ABdhPJzLVABkwO6y1gle1RvqLg0OLcd0fTU7nLPYREBzO2GMJOWmHA4L1/fPuD8dj9YL33sq5pnEBQ==
X-Received: by 2002:a5d:4401:: with SMTP id z1mr17204901wrq.149.1623070635462;
        Mon, 07 Jun 2021 05:57:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eac1:: with SMTP id o1ls1605424wrn.2.gmail; Mon, 07 Jun
 2021 05:57:14 -0700 (PDT)
X-Received: by 2002:adf:dd8a:: with SMTP id x10mr17161398wrl.225.1623070634578;
        Mon, 07 Jun 2021 05:57:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623070634; cv=none;
        d=google.com; s=arc-20160816;
        b=jepCTPx+dA90HDuHJEgONiA1W4W/Gw2LOINj3EYUy/j0uAh5Mwa1eyob2xHIkTP+pw
         RWymVA9dH+jTQhVEPVSue/1Exfo0UrCkxKLsItH0OvnnB+rMN23yoeCNFNOuwEw89Rd9
         ayUGMPNZS9XGjEr/Zzw3DqMwHnKFLEgb9kkeWowACmw8iFF8pJPOCIvwtUg64eR8zpi2
         T8n0g6zSEvTNMdls5Kt4NvM5hpl7F1DTNVYFF8w8svujrKPp3x0fs89uIOwB3Cb8QEEf
         PJdSkrDkRPla/MQRINysP6tix9YLWfYRSZfVWzjbAGbiSuPgT26yXTZyNTR12OafHtMo
         Y+yQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=INnLTycaFcjURtOKla7QnFpdUDO/KdMpHCcjcKTzueY=;
        b=dXbUkXtYPw+MHVtsNpfgg0beSy5M9er0DqncHXk5QFknoQq5FB5cLBp59n65WfiJme
         o6SlI7rayV+PCJ88JCb1N8eVVuNIiybxGATJT8AoYDYOJ0xKG0OSVq77APNazojf2HsZ
         8H+hz3fJKaFda5LBlXMoXEw9swdFk44+tYFK30eEp/QJxhm+ryoCBtoG+L3Iw8ycF8k+
         JVfYxWbwUdi+fdkZ7EiELmBgkk8yc1Zj7BeYCwv87QKjffnHQ8UZd4vIOVbzNZ00rKCt
         ab4QVosRedVFnyA20yxoZM9lDTzKJ2M2+86TfR4srzyhIe4saxu6G4xUBSKo3w1Afzdm
         EQKQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=kZoDM0QN;
       spf=pass (google.com: domain of 3qhe-yaukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3qhe-YAUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id g18si458135wmc.0.2021.06.07.05.57.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 05:57:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qhe-yaukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 128-20020a1c04860000b0290196f3c0a927so6782215wme.3
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 05:57:14 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:2587:50:741c:6fde])
 (user=elver job=sendgmr) by 2002:adf:9031:: with SMTP id h46mr17415015wrh.125.1623070634196;
 Mon, 07 Jun 2021 05:57:14 -0700 (PDT)
Date: Mon,  7 Jun 2021 14:56:50 +0200
In-Reply-To: <20210607125653.1388091-1-elver@google.com>
Message-Id: <20210607125653.1388091-5-elver@google.com>
Mime-Version: 1.0
References: <20210607125653.1388091-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH 4/7] kcsan: Reduce get_ctx() uses in kcsan_found_watchpoint()
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: boqun.feng@gmail.com, mark.rutland@arm.com, will@kernel.org, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=kZoDM0QN;       spf=pass
 (google.com: domain of 3qhe-yaukcd0dkudqfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3qhe-YAUKCd0DKUDQFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--elver.bounces.google.com;
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

There are a number get_ctx() calls that are close to each other, which
results in poor codegen (repeated preempt_count loads).

Specifically in kcsan_found_watchpoint() (even though it's a slow-path)
it is beneficial to keep the race-window small until the watchpoint has
actually been consumed to avoid missed opportunities to report a race.

Let's clean it up a bit before we add more code in
kcsan_found_watchpoint().

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 26 ++++++++++++++++----------
 1 file changed, 16 insertions(+), 10 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index d92977ede7e1..906100923b88 100644
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
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607125653.1388091-5-elver%40google.com.
