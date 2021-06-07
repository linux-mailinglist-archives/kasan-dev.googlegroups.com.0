Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJVP7CCQMGQEDEN3PAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 4632239DD17
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 14:57:12 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id j8-20020a17090a8408b02901651fe80217sf7496813pjn.1
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 05:57:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623070631; cv=pass;
        d=google.com; s=arc-20160816;
        b=dlfjVKens4qcRIWOlEPGmNaex80dccapql1v3KspdyZQCs8h4yZDtrvsJ+3hRus/Hy
         MISy1swNawKAjHjWFcy+BaJXRtkezCN494kuAjq5w4EYx8dAqrq4pzFK7HVK0GakpU8X
         yh/QiCdSxTVVg3+YbQXR2VleUddYspix0sGgFjTfwNTxOlX4uZ6ghNOBW21CcARFmkMr
         qoVYzbfqjF73gsK8DmYfpNUs/Z/tQMmHlSshXXXGKu9xt+71UVB0vppPL7R1hHoB2fxp
         4SqVrNywix4JYQuXSxN4hJwRkFyZnYdw4s2H4jKDG7imX3tLGI2PmJeHiWxMoY2pz2E2
         SvEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=o01AtznYOHnreTe/GQDzoH98XFOoHlHS03dOHB3YfLY=;
        b=NlayWJy8hm0YwnnNb+tGM6rjKSNxDdSd90JudKms2ZQ/0ugoJsHaWiz6ljxUo6Jkd3
         g1A0hImTu1CTbgPB76IhRiPhnYljN/sLD+R41OYhQBC7j/XVALDgjFIebA65DJNMBMSS
         mod1FzZull1gSmiT2qV2G42MzPi7qhj8qRVqVnjxR1clZ0U2hndnyhbLak2x7pFUhiwb
         AlGH0AeHce1rcR2LDU2H1QdrNU4nvYMcwhdsXhOaYO/28ynMJGFZRKHsvRYk4q4QO78Z
         cKnRcMeHOsrK1/PH1pCaGUvkHExbJC+suxiwTeGPvx+jNt919Mu6+Dbg3F3Yo40grgbw
         QoeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="B5Q6qv/j";
       spf=pass (google.com: domain of 3pre-yaukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3pRe-YAUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o01AtznYOHnreTe/GQDzoH98XFOoHlHS03dOHB3YfLY=;
        b=QybJhq1d0K/oY2y5uc8gejx6a5bu1lBUADIDqbQ7XMzZQQNi/RWcOwMnnfTJIyP883
         xpjfl7vpNIsbiMA01G/85VUYu8ysBRUpMwz28BFB49mF6tGX3zWMlT2np44csg2cCM+d
         6SSld0xa4z2sjmefqQHmb0JKPTg/+SnE6WR0CgQTAyr4ruBBi7ZwUq7xxdphhf1bSUXC
         H3TBfGNq5obNx0rKiKGRDk/pGxKnG6eFKggUQEY+XZD7jrkXeXyUjtseJrqLDtKXWI6A
         CZdxj+iH8nppMb5ctJN7jWSAI3nolMpqw8zlxJeOI3oQE1Y/9+kS+vD1DArzuKTV2cur
         LwXQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o01AtznYOHnreTe/GQDzoH98XFOoHlHS03dOHB3YfLY=;
        b=VKdCNYhEdH0vyALzLfOBwxrtMiglkc/E3CViKbW/DFOlSJIQzpYkEij0KfzNixDCl1
         qHVbaFUdqNuQmPUrj2bPuQKB/D9DJWdxgt/rwTHh+bezDFSTTBU4yQhxASyRf/+ieMOp
         50RgL9hGwqRLNqcYJJ4lBWC7ECfONMNyWDJ3kyu8rVddjE0JWnA+2MN+zOlbWXkTOZUq
         JViuiXJ7nybHoFlcEbOWZYvW/EMlXljQlk2BID4n6fdbh6k1QEVVe4KQtbr6UvRXcm8s
         auHNPWzJcVr+F9FDPX9m0+BItjV3wxty82n1r1Ai6T3Fn/1+Tixxb5X5Q3FIeoNxKEhI
         zp7g==
X-Gm-Message-State: AOAM531ziCRLewA+DhIfeep44GS35X5i2Qu7dcoBlnzKRljvM3UHn65O
	fbkbIPHo/eqIRvtXJHBdX/4=
X-Google-Smtp-Source: ABdhPJwFhw2i/dy2TYEf6Wbnvw4bFyzNU0LkOa/6U60eD962ta85Eb9lsf1MScFoKs5AayleX40DfA==
X-Received: by 2002:a17:90a:5309:: with SMTP id x9mr31804979pjh.111.1623070631057;
        Mon, 07 Jun 2021 05:57:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8dc9:: with SMTP id j9ls2543307pfr.9.gmail; Mon, 07 Jun
 2021 05:57:10 -0700 (PDT)
X-Received: by 2002:a63:5616:: with SMTP id k22mr14550650pgb.41.1623070630439;
        Mon, 07 Jun 2021 05:57:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623070630; cv=none;
        d=google.com; s=arc-20160816;
        b=uSt7QeWmVSxHDRIzLQFUvd47FYGloZesdS8vvT5STOTOPt79raiGilzl6QsHJlHaVq
         9fA3p+/tAUiWJRqDaDrt4bdUayZyLJAgJB+Ud//LN8XMuAZ3oewgVYhsFyBqo9Psa4PM
         fP85R3BY5pBzc5KUHF7sFjMl/mdNpNBYb4Iiao1TWjMxp3jpJVPqoyb4nN8iMGc1N6mJ
         uog8HQ4Pj6AbcpsGxfsBI8caRzDdOsrUwmXywc7AmcqkMxFVXTlChq2tO6YUQOwOZYgn
         QBmdARws/N74lOo5O4OhSk+IsQAnlRaWRDWwnrg19e1Oql5J25wg0i0vAXa9F0ZE7Dn6
         e5iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/aaoSey+XaULg1MGdgAn1yub4BLSR83Q711t6YMKbyU=;
        b=uj72cNS/ZIADuibJrOMnnjQB4pQx0jTSK1pz4bL7PiPbkW4B3Qf6Jhw8c6nn29aYle
         af54hR7vWjaPRSWMoV8dv3VdwUa2N5J3Qn6e1mLesinsmmGmh9AnUMOsTTK1PU/+VJ9A
         mzAjHyRc+GGwSbvmfNwQMNkJJuCBHPbe8qWv99UXReBZHrXDO/soMe9amPDObVytJU3q
         1nIOSEk95Fu398oukUfCLso1K7SB9wILYvveDHmlUSSfEudc733VnG9E2VVA0MkXtpZi
         eyrVkeVGA1YbH3OzPby/g4TpNDiy4uaU73dIluPxQs/4qGSEjStCzmDFHLc4BTiDK/wh
         o8hw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="B5Q6qv/j";
       spf=pass (google.com: domain of 3pre-yaukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3pRe-YAUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id b3si59868pjz.1.2021.06.07.05.57.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jun 2021 05:57:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pre-yaukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id k12-20020a0cfd6c0000b029020df9543019so10748525qvs.14
        for <kasan-dev@googlegroups.com>; Mon, 07 Jun 2021 05:57:10 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:2587:50:741c:6fde])
 (user=elver job=sendgmr) by 2002:ad4:4e89:: with SMTP id dy9mr13977400qvb.40.1623070629649;
 Mon, 07 Jun 2021 05:57:09 -0700 (PDT)
Date: Mon,  7 Jun 2021 14:56:48 +0200
In-Reply-To: <20210607125653.1388091-1-elver@google.com>
Message-Id: <20210607125653.1388091-3-elver@google.com>
Mime-Version: 1.0
References: <20210607125653.1388091-1-elver@google.com>
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH 2/7] kcsan: Remove CONFIG_KCSAN_DEBUG
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: boqun.feng@gmail.com, mark.rutland@arm.com, will@kernel.org, 
	glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="B5Q6qv/j";       spf=pass
 (google.com: domain of 3pre-yaukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3pRe-YAUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

By this point CONFIG_KCSAN_DEBUG is pretty useless, as the system just
isn't usable with it due to spamming console (I imagine a randconfig
test robot will run into this sooner or later). Remove it.

Back in 2019 I used it occasionally to record traces of watchpoints and
verify the encoding is correct, but these days we have proper tests. If
something similar is needed in future, just add it back ad-hoc.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/core.c | 9 ---------
 lib/Kconfig.kcsan   | 3 ---
 2 files changed, 12 deletions(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 26709ea65c71..d92977ede7e1 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -479,15 +479,6 @@ kcsan_setup_watchpoint(const volatile void *ptr, size_t size, int type)
 		break; /* ignore; we do not diff the values */
 	}
 
-	if (IS_ENABLED(CONFIG_KCSAN_DEBUG)) {
-		kcsan_disable_current();
-		pr_err("watching %s, size: %zu, addr: %px [slot: %d, encoded: %lx]\n",
-		       is_write ? "write" : "read", size, ptr,
-		       watchpoint_slot((unsigned long)ptr),
-		       encode_watchpoint((unsigned long)ptr, size, is_write));
-		kcsan_enable_current();
-	}
-
 	/*
 	 * Delay this thread, to increase probability of observing a racy
 	 * conflicting access.
diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 6152fbd5cbb4..5304f211f81f 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -62,9 +62,6 @@ config KCSAN_VERBOSE
 	  generated from any one of them, system stability may suffer due to
 	  deadlocks or recursion.  If in doubt, say N.
 
-config KCSAN_DEBUG
-	bool "Debugging of KCSAN internals"
-
 config KCSAN_SELFTEST
 	bool "Perform short selftests on boot"
 	default y
-- 
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607125653.1388091-3-elver%40google.com.
