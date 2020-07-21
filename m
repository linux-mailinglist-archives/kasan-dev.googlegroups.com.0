Return-Path: <kasan-dev+bncBC7OBJGL2MHBBT4H3P4AKGQEFHO5MKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id D89C6227D03
	for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 12:30:40 +0200 (CEST)
Received: by mail-pf1-x43a.google.com with SMTP id v25sf14783429pfm.15
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Jul 2020 03:30:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595327439; cv=pass;
        d=google.com; s=arc-20160816;
        b=gYMMx6gb+tAXmVu2wRD2W5W3rliO6n/VusnABA/cD2Aqmn2ZVGePb8AIpLsvfMrpk7
         tOSI5C6JQSkiPZfV46FpTgPeAPSHzrBsDgZWX+mqr6pBzPXOH9Jl38xEsLqPqJMh8uc0
         24jaYoFHCUu4FrU1FHnoSzu2ZG4drH5mS0t4nEhWQbdt2rZ/v+1ujVLgj3iadul2Px9Q
         1rldB4+hmhbgEYE7nLq+0W64TdHR1eI21z2XwNk9CF7bwJymuoMw7x5UlHPtwVvAdhxu
         hhqLbWmMlagsI8hZEupUKsIm8DQj5lYrFhxCOhCxJJHlQxUBxDpR5lhN7ASsn9zW/ReD
         f29Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=1Pg8h3w13twfXcVS0Sk4mv2XYHasXVRkY/DDc/tE+T0=;
        b=PtSFfcE3D9hXhKwFHK6P9GN0RxhJrwXFAHUaIqIPjCKkSChFSCIaIG+ft6q8P4Iy9o
         gyHs/fbyWu2iMcqOvD/R+sXfjbT30COeUmRzFMi74Sk+W4sOodKXg1W0XZ8h86Ga4zxp
         1ZQvRpHXKhtE+DrGrD564fQu23UAe02BYZn8GuhxVX6ORuSCf8+yetP1hSDk+zmdi28w
         UMuQFZ00O127K7SYBgYrOhD9MUMYgu+evzzCrkq5qcwbsRy4adLkYBaFfTVllH/zN4c4
         UbRsfQ5qLWtdImz5mUlHtBjnJkqibYowJBu8+cTf1CDWpcbuMAOgkvV70liGNr0HL6qS
         Qvnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vXrgbBZM;
       spf=pass (google.com: domain of 3zcmwxwukca4szjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3zcMWXwUKCa4SZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Pg8h3w13twfXcVS0Sk4mv2XYHasXVRkY/DDc/tE+T0=;
        b=AUlC6Ly9l8VDfrqXbxCabY/EV7ADzDFruJ09ASeb09H61bF4HG+BpdF5+UrO4ojR2X
         kGk3o1QiTF9rKbX6X0U2iZxL7drHkHyMc803dAjJXQRkuzDF+wcxAwjdjhnTVEMq9AAD
         ikh1Cpwu/GppLrIxCcljpBEa2j4NEJPrs9qE6sCZjqiw9dRNJpgeGIfkWRJO5X529tEf
         dbbn5lYNU2gbhUOH82fQBF/TkWWI7X+3GDG+WqdEJXrHcwNov41m+huaS9nAxkGbPg1B
         ReYEs5oLUvbYBTdYHxAvveAJqusvaydHWDT6hkgeRjSjX9V48gFoP1qDWwJF7l5D3iw2
         GiUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Pg8h3w13twfXcVS0Sk4mv2XYHasXVRkY/DDc/tE+T0=;
        b=BrInPTnxn5mJB2ZfKqivhSmlNEfCBX5VTBCxXFfg1RqetmsnoeJo9jjSs4NAAOA51/
         NrKo9VUAkPWDX7z6pAPuH5luKxY7q2CorgazVFqLGjl1QwY/i2Pj0PYJTThfqKzICm/n
         UH2y2JB/OqEp4waNHgc3sU49VsTcfSUsM65FIHbNy7K7clV4LZjjszbB5doZHEfObZQF
         TIvZTy9SQI4LZlJUCqcbAD5DioE99B8jNR832uYA4mpnam4eAQznf+Vfozxo7I6+A6fb
         Ahio+BUxXui1qQ7cbX9lTKb5S6gxFwN/t2cCXdf1KeaPlKdrF3RNK0VAft249faLr9Yf
         SdEg==
X-Gm-Message-State: AOAM531aeZSAQgoMgF6xrDjeogFViB5TnyOH5Gbw9r4mjYqhgXRdRkrn
	dV68Uxt1GRdlouLVde85RbM=
X-Google-Smtp-Source: ABdhPJw4v9vhyz01KrLS8fMNMHvieFCevfgMV776jozWfPgwHOj9eNgxhxTLR/b23N3iBCqRil8zWQ==
X-Received: by 2002:a63:e14c:: with SMTP id h12mr22301616pgk.110.1595327439093;
        Tue, 21 Jul 2020 03:30:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:7757:: with SMTP id s84ls5685265pfc.9.gmail; Tue, 21 Jul
 2020 03:30:38 -0700 (PDT)
X-Received: by 2002:a63:fc52:: with SMTP id r18mr22756933pgk.334.1595327438582;
        Tue, 21 Jul 2020 03:30:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595327438; cv=none;
        d=google.com; s=arc-20160816;
        b=Umel8cknCeZUL4rjewBUzhJzERixYAiP1pOt0foz1tFMD46rlBlwKMZ7fx40jqPvhT
         i1+6AyeJlWDFIZeijbRL2XZejtm5bD3/8bQ/D47zLL4Rku4xTEBkCC9UflCqYm9ug/sW
         cuN1xXj1Z1SkcTL7StdpJpJ73v/OlIN3ZdclXTBuvYdCnpYSlfTMM2neQeRVl5/UEIsF
         4x//Xl7wBldOn1E6VlC2WmVwLVx/yAk3YJSHSdOc7wsQ5e8uPqjBty6aq/pXm2grB53m
         /RgRA2nvx/JSOdH9oy1uMGSUknikkfe4ybyVjgIjN/PvHqlEjd08JdvlvLnWMBkkpYxv
         yXEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=vVlSyEcdwOQNKSx6Cnzx1nFD8CBubHuBwhuu4avdOuU=;
        b=QI3yqAJjfKGGzGzPnQDZmeUoph8VrHYjRCqwH9bx/7rFJFuN88WegCprzqQ32+98ws
         neTbg3r10g9DllQMVCRNYsi0qY2t6l+n0c0lrV4eDBSxVwWOtM+Ojn/CzdQ9Pez+Dqa4
         sbo0nO38eKagNhcoYZcc+wRZebkBxe53pNd/R2hGqHNRl0IIuHAcUYHx2y/IDX1GjVvo
         k+CwoMWBzfS7IwLJSrSOB4UNOcYg9T/2qpSl8d+z9XdY8KxesgdjCTWUAn++tlQBYR2Q
         CiwQ+67k9vE1DMEN+YjSC+9BkvO9dWLg4KmSKblRlzL4uV57Iip+UYf8vkoECYEMgkDP
         lTgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vXrgbBZM;
       spf=pass (google.com: domain of 3zcmwxwukca4szjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3zcMWXwUKCa4SZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id g5si795900pll.0.2020.07.21.03.30.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Jul 2020 03:30:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3zcmwxwukca4szjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id u186so13506851qka.4
        for <kasan-dev@googlegroups.com>; Tue, 21 Jul 2020 03:30:38 -0700 (PDT)
X-Received: by 2002:a0c:b48e:: with SMTP id c14mr26052857qve.47.1595327437707;
 Tue, 21 Jul 2020 03:30:37 -0700 (PDT)
Date: Tue, 21 Jul 2020 12:30:11 +0200
In-Reply-To: <20200721103016.3287832-1-elver@google.com>
Message-Id: <20200721103016.3287832-4-elver@google.com>
Mime-Version: 1.0
References: <20200721103016.3287832-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.rc0.105.gf9edc3c819-goog
Subject: [PATCH 3/8] kcsan: Skew delay to be longer for certain access types
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, arnd@arndb.de, mark.rutland@arm.com, 
	dvyukov@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vXrgbBZM;       spf=pass
 (google.com: domain of 3zcmwxwukca4szjsfuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3zcMWXwUKCa4SZjSfUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--elver.bounces.google.com;
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
delay to be longer. We still shouldn't exceed the maximum delays, but it
is safe to skew the delay for these accesses.

Signed-off-by: Marco Elver <elver@google.com>
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
2.28.0.rc0.105.gf9edc3c819-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200721103016.3287832-4-elver%40google.com.
