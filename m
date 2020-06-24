Return-Path: <kasan-dev+bncBAABB3WGZ33QKGQE46HQCOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 04AF8207BEE
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 21:03:12 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id fa9sf2150278pjb.4
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jun 2020 12:03:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593025390; cv=pass;
        d=google.com; s=arc-20160816;
        b=AiUVBmGIkNzc34DPRt41BT7XPw7WPAXC0oUq37iN0/sfp+w/iLkJoRV/1SNu58IP/P
         u1qDFVkxESfU54i+AKpWDEOqHG0Mp/yle+WjrZw7QrpIe62UaC4ne1PD7x2kLiUiGQdL
         L5ZBuA5Ky9xlrL19PNs1j1hXTOrdYWERsh7jP0utk3JnLZBCgYnf2X/R42hXHgRFNqPq
         8CQcKsDTazDZ7xY7evH/Yms4sb5Gad2aIZqnhS0L8V5LekvMh1e0+3xR8l9WhRzmy9Xa
         KAKJUJFSk3tUodyBW06KKVflycYZT5FFjNpD3x6KKgFTu+KQ2A+l93J8C2grz1tL5qOX
         VsxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=W5ENoMM7S2Coc7hRL3qr7iyrDRWxc8Dy8VNi1z2pb48=;
        b=JTJaiFUzI0hBl3+kGQYcSDXZm4iHiI0YZsBedpsHqI01WToGPuZgsHVIiPElelnlLG
         Ja/vP5KFRcTejndhE7gnwPqsd7HdRxyvSXFXOj5Yy0f6fiavNLqJ/mRNgX0TTle2ayfq
         PKzMF7+B8GTiVSmDo9Bchf5C1pl0mvMvCM2kZQNhc270neFNLAc0Oh1Vdio4RAHl4sk7
         Btf63mu4YuhIkwm1K76Z/qzRAlhpzJ1pFHdxJFsirnUfdIkYLZeIjUgBw4wundmc3tDK
         Cjw+QlUzmtEVrx5U/PTybtLnNVEOTHNe0VpNht7TX6dWhuMWnyR5tujzSihYZlApurel
         2/zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=swkiOYkW;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W5ENoMM7S2Coc7hRL3qr7iyrDRWxc8Dy8VNi1z2pb48=;
        b=SXBVVC5i1Y38rkjm7ksGam474ShDQk0LTLYgQuvRyemnXevQG5pLbxSllkeDUb+Uog
         gJtTMoJeDyfRguXlrxF8kxjtEIEz0z7R22kOhJLVHzZw5yJwZEPLnMPx05RzPV8uXa+O
         WJXENHJ+umGPvzUp981KW+3K3Rb35Y3GR3yCHZfyglca0zjBdQ5j+Dchtxe3LlbWJNvG
         MqQEMO/M2phsFrMlUvTPugiQ4NdRwNJLrkyPvTpPnuPuBoOcM0GG9osFdnjnTSINi/GJ
         1b2D+4y3+xt7sYySzt6WlZvHSPh0Ab/Ebp4wTltvJSlx3YBlourH6KzHSJMITD38e/wV
         l39Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W5ENoMM7S2Coc7hRL3qr7iyrDRWxc8Dy8VNi1z2pb48=;
        b=GImCLdBNYiDMVL/BBcKKboUhfgTInUMVsGboQ6rYQlWrUiz/Jm9s7TFHkVz/k9TKfr
         sm2HRqmrO4tZTZT5+i2xpTa0VrzXuxH2bK8foibSJuRsnQW1T1VJT4n1ln4VRJKR4rsi
         ZfDQox1RWhB6UWjTjPN63zWzKR+mspTkELywh1XGEGyl4yVOjrRduTMMHscyCrXh6LLq
         LkV1FZSYCT5USbuh05JWkPozJEiPMsLQNZtD0I/o58+Eu491OJzmz/4bec0RRnbH1958
         w/Mk/jVPGXMLKYyfx6XIgri+DiehzWdGHuFF18Hz0q+Pig21ZTa0BJDg9kXB4+lkZzp/
         z9Ig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5339BUJc2paO9e1jQgDPoF36A1tVsMYaeatoMB0eglbUu695NvL4
	hKcmr34jYkXN1a8ago/amyw=
X-Google-Smtp-Source: ABdhPJxrQ1Lxbk2Id4+43VPWyHJooq7Sq1o0McPgaAwwBVXN9Cpp3eWdzjvfG1z3wLmL+Yz/31UEMg==
X-Received: by 2002:a17:90b:46d3:: with SMTP id jx19mr21755788pjb.177.1593025390707;
        Wed, 24 Jun 2020 12:03:10 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:47:: with SMTP id 65ls1170593pla.9.gmail; Wed, 24
 Jun 2020 12:03:10 -0700 (PDT)
X-Received: by 2002:a17:902:b60f:: with SMTP id b15mr29794055pls.248.1593025390329;
        Wed, 24 Jun 2020 12:03:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593025390; cv=none;
        d=google.com; s=arc-20160816;
        b=CtzOuIpF60hRz5Q61qSOCN761OS5+kQ66FdZgQD8Qt8TMblLYi/ozsjYP/FnUJ715V
         Ss0GTWNynscXKa5dKOfWFfL4svARTj41hxoB8nX/O7JNolM2oI2/mKB9SQn2P12m+E0T
         vB7OUhw8WVzagSLoM+AB1nFKmdc7MC0cXt2o79wQaYsD6FY1HZOdsdDAzrZz5nRraG9m
         Kex905NYwHJx984P3e0K02zfSyK3AsQ9D+gkuJNWJ3/gBgy57Sd7gIgXk4+Ocd5nEOF0
         2CuP7U0IqkjmD5Gjkr7JzlVxORVtfFvFwKee/CzKfn8iMpBqw7pQznTQVU0uxL8ZXOJM
         NRuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=GIfRaeAH28k3+sh4mA45BCqse4ufyE4D0gt7zql9zlA=;
        b=lhxrmlf7yx0mlmsNBJ6m9mCPdl/PFFwdVsBJO/ItK913I+N26Glza7VZxbPHhXb3hk
         aoODONpDcou9yt79DTa2rKCfC3z6GhCn3B4hrkFU6bUG+rcq69op7GpU6sMJNRlZS0eZ
         g4t+XqJe6u51ldrTP3wOsjyXPV3TWL9MOvLvL6MuUEY32ItrA/uXi/fSARIH2Ai8OR8C
         kLEo4JRsxmRk0x27onoPSMrzfD+aZfNldiZjgYBMnrHRgMju9NHoe/+vb9THzecx+w5j
         Q+7ufSLWsDLb2pKgmaZA1XyoMKKD/HVSZ/W5Ka78dHVoomcVlZr+lJNdBc+ySTTHH6LG
         r4Rw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=swkiOYkW;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n68si731839pgn.1.2020.06.24.12.03.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jun 2020 12:03:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id F415020B80;
	Wed, 24 Jun 2020 19:03:09 +0000 (UTC)
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
Subject: [PATCH kcsan 3/3] kcsan: Disable branch tracing in core runtime
Date: Wed, 24 Jun 2020 12:03:07 -0700
Message-Id: <20200624190307.15191-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200624190236.GA6603@paulmck-ThinkPad-P72>
References: <20200624190236.GA6603@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=swkiOYkW;       spf=pass
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

Disable branch tracing in core KCSAN runtime if branches are being
traced (TRACE_BRANCH_PROFILING). This it to avoid its performance
impact, but also avoid recursion in case KCSAN is enabled for the branch
tracing runtime.

The latter had already been a problem for KASAN:
https://lore.kernel.org/lkml/CANpmjNOeXmD5E3O50Z3MjkiuCYaYOPyi+1rq=GZvEKwBvLR0Ug@mail.gmail.com/

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/Makefile | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/Makefile b/kernel/kcsan/Makefile
index fea064a..65ca553 100644
--- a/kernel/kcsan/Makefile
+++ b/kernel/kcsan/Makefile
@@ -8,7 +8,7 @@ CFLAGS_REMOVE_debugfs.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_report.o = $(CC_FLAGS_FTRACE)
 
 CFLAGS_core.o := $(call cc-option,-fno-conserve-stack) \
-	-fno-stack-protector
+	-fno-stack-protector -DDISABLE_BRANCH_PROFILING
 
 obj-y := core.o debugfs.o report.o
 obj-$(CONFIG_KCSAN_SELFTEST) += selftest.o
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200624190307.15191-3-paulmck%40kernel.org.
