Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJFHR74QKGQEOSVAURA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 0D3DB2340F8
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 10:17:41 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id t12sf8929595wrp.0
        for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 01:17:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596183460; cv=pass;
        d=google.com; s=arc-20160816;
        b=pvaBUgCulhQf1RpSRdrlY3xhNSuTGdP2QwGWmGAY4XDlxrOTNV0vUJwo5D8nsP0VV2
         y+0tMgHFCP3LxUYqyijrS+ZNh97mdJ+VjWshfCbrNkQiXnpx5fB6qNG50w1ZwPH0gR+1
         UsMRFJp+4txF3QHK7QneD1WoAMKflaJW810UfTpInK4Kg5JHAD8X0R+MzuWGRZJWTQZy
         3uPf/ABZ4bCrHNokJ2RJ1IKf2oRdL3ZCzamu0hw4wfn5lTsiagCLt+l91AX+5E637wLi
         6KxU7zbOMeGy/khalcU/VGYqnAIqy11OKjMauLncatoVruhYcBmfSEu5eKK/gPzbo8D6
         J6ZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=OYoCbN09IOXuFXgvgzQ6Yh5Y486DH2dnl3RYXWsCL1g=;
        b=uVCgl04kYzDSc4ISPS6YYJpUB95USdrUE2Ha4fJT5KmTR8dwM6eeHx/85Bfokj+n4j
         Tpu+c0EnVNFgMAV0zL4HdiCTyxdHbp7Serl7qlcxgqgJjnI8sHldEk4T/3mJ3ITmtAQC
         XI3TISpp4IG8p7i7G2Zyj2aRhy9ciiw45lbOQK/6vjT8/pPxYuGbQ9CBjbvl3qOg3hJF
         48w2xBtm134+iKGff+ld6oIvtXEZJfiGGu2SU63j53Py6oaTdqh/7aW8aGiSseTUvnO7
         f9GrNg0XEdCPNlh9EA0eGYjOJjGUBvM2LF1X0uPU7wakMoI+s/BqSZkpQURhQKmxdqXj
         Tutg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="fHL3/dWw";
       spf=pass (google.com: domain of 3o9mjxwukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3o9MjXwUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OYoCbN09IOXuFXgvgzQ6Yh5Y486DH2dnl3RYXWsCL1g=;
        b=MfgaR198yhv2IOP+JZ7aXz/tH0CBcjLoN0D0kKGvqf/Fa/ag3uHn9fvuam+s06CITR
         VCN0pc5zmAT0NZsxTdQxUybEifNiisIfxjpA9+43TQh3sP3kggK6/xeuDBoVlSB/QppD
         vo0qjYeQnqe5H8jGi9gWnCwy9ld+zHMp5J7tBNPJHENZ7cIzUerEzAsL06zS1bxQ53CR
         DglgiuuZDsG24Sl0GBUNc881HzBTuYn2j5GM0uRJlEPC7yFwKwN7dR0bhN31u/4f5+V9
         hchy6L5u6Ffa15GQqPMISWOC1o9vbu1esh2VieZojFwuQ32/n7wJqduKhBsTkCU2XKyV
         wKtw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OYoCbN09IOXuFXgvgzQ6Yh5Y486DH2dnl3RYXWsCL1g=;
        b=NitTa/DNOsy/ioQdSAiEq7fyIF3E7RUMnIilbpfJtgxmCusuhYnIujk2t2BGrysX0B
         Cc3w7dz2AEl8eHwlHcy+YeVFk498sSvb0olHOcc3RhKPqljWcZX/tTf/bzo8USoYAGR7
         T4FeejSWaxZK9TjI0IA6CHFHjBeV47s3GgLNa48byTnrMbmITw3yLFXU+RTv7HS1EVCl
         2eoI+uGUS4Ak05R13q3h6lT74YBrue+uUGBSdJWESoIn2IfmkL1xzdkk8xAnnBsc/LyN
         cL69r+FX/hrwS60OzllCRkYMI1K+tPqrrRWtZWC3yySqFu4ygYX0e+c+obbzR2AqXEvU
         agjA==
X-Gm-Message-State: AOAM532/LLfgveNVM9QSjnkp0jpJ2fPdK7I0Pgxd4vmrFCoYDTMEGgbO
	mcOVPn+p4Xo0G77dYtBq06k=
X-Google-Smtp-Source: ABdhPJwmZTtd38+KP2GZfUfZf4AuPLcI463d+hjO8GmSEqYm462mn2X/ll7N19/p0ANd661qtxt69g==
X-Received: by 2002:a5d:4c46:: with SMTP id n6mr2587098wrt.73.1596183460834;
        Fri, 31 Jul 2020 01:17:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a3ca:: with SMTP id m10ls3120224wrb.1.gmail; Fri, 31 Jul
 2020 01:17:40 -0700 (PDT)
X-Received: by 2002:a5d:6a8d:: with SMTP id s13mr2585460wru.201.1596183460264;
        Fri, 31 Jul 2020 01:17:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596183460; cv=none;
        d=google.com; s=arc-20160816;
        b=YjziAhg7ZSDJZMB6XOVPkfZ1SHN2jF9M+/TvUk+5zsxedypxz8K7Gtd/Ftf84zC2Hn
         pfEnJik4v3pZzmdB7Ng4rb5bEq8O6JXHWiKwJsqjQEZeQeHFGxRXOrWQ89m4rDTC+0ik
         EvGkZYCraXpxpGwuRHthVFm13pKFjV0xOb9Z2Zp8j6+cDxOOATkMytnNwmm1GLF6xO/I
         tThfvFEQJ3tu4l/o1kEglrYqoC8KoQoiI+ejt7O/hmwSK7Gltuw+dGoxdbAbsK73eNeM
         xYMxO++MoWLFK8l16LMTLxHXfs9vh2gi8JAzpwAhhJb93zbNKNTZcRWuF+C4PzFN6b3K
         TTmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=wdHz4VAV7cWLg1rq1e/SyhC9acNNi0lj4Bxe95gHR1c=;
        b=G0jHaQySHa4bWzFRmdwznTfAllY2gCUZfGkF/ce6ocws7eoqwcnEG43A1swDPPk29k
         Zr3/mxcPxJ3PUrdYTM9uk+l3o7bgqhCf+WGNSBrHN0+OE/kQziUuPnjyUTf+HjXaAzQy
         +l1DP+b5PaKPyii5xtWlnIXnDJwqT45cxE591aKDF/MrX/p0Bi4/qn2YhaYd+F7X9tkO
         dzRhzNBkttQASMhodGEE4NDfoieh/KAU9zu0KO8pP5hPYs05hlSHyDQ4OhFIz0yZJ4vG
         hQkhAMt0wl6QQtkxr1OW10pO0I0G9Mo/BLO9mwxl/R5oeJNX3iKulNd1Ju7BmrYCt5VK
         ptJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="fHL3/dWw";
       spf=pass (google.com: domain of 3o9mjxwukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3o9MjXwUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id y12si441245wrt.1.2020.07.31.01.17.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 31 Jul 2020 01:17:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3o9mjxwukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id v8so1902143wma.6
        for <kasan-dev@googlegroups.com>; Fri, 31 Jul 2020 01:17:40 -0700 (PDT)
X-Received: by 2002:a1c:c90d:: with SMTP id f13mr2954894wmb.185.1596183459822;
 Fri, 31 Jul 2020 01:17:39 -0700 (PDT)
Date: Fri, 31 Jul 2020 10:17:20 +0200
In-Reply-To: <20200731081723.2181297-1-elver@google.com>
Message-Id: <20200731081723.2181297-3-elver@google.com>
Mime-Version: 1.0
References: <20200731081723.2181297-1-elver@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH 2/5] kcsan: Simplify constant string handling
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: dvyukov@google.com, glider@google.com, andreyknvl@google.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="fHL3/dWw";       spf=pass
 (google.com: domain of 3o9mjxwukcdg8fp8laiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3o9MjXwUKCdg8FP8LAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--elver.bounces.google.com;
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

Simplify checking prefixes and length calculation of constant strings.
For the former, the kernel provides str_has_prefix(), and the latter we
should just use strlen("..") because GCC and Clang have optimizations
that optimize these into constants.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/debugfs.c | 8 ++++----
 kernel/kcsan/report.c  | 4 ++--
 2 files changed, 6 insertions(+), 6 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 3a9566addeff..116bdd8f050c 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -300,16 +300,16 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
 		WRITE_ONCE(kcsan_enabled, true);
 	} else if (!strcmp(arg, "off")) {
 		WRITE_ONCE(kcsan_enabled, false);
-	} else if (!strncmp(arg, "microbench=", sizeof("microbench=") - 1)) {
+	} else if (str_has_prefix(arg, "microbench=")) {
 		unsigned long iters;
 
-		if (kstrtoul(&arg[sizeof("microbench=") - 1], 0, &iters))
+		if (kstrtoul(&arg[strlen("microbench=")], 0, &iters))
 			return -EINVAL;
 		microbenchmark(iters);
-	} else if (!strncmp(arg, "test=", sizeof("test=") - 1)) {
+	} else if (str_has_prefix(arg, "test=")) {
 		unsigned long iters;
 
-		if (kstrtoul(&arg[sizeof("test=") - 1], 0, &iters))
+		if (kstrtoul(&arg[strlen("test=")], 0, &iters))
 			return -EINVAL;
 		test_thread(iters);
 	} else if (!strcmp(arg, "whitelist")) {
diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index d05052c23261..15add93ff12e 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -279,8 +279,8 @@ static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries
 
 		cur = strnstr(buf, "kcsan_", len);
 		if (cur) {
-			cur += sizeof("kcsan_") - 1;
-			if (strncmp(cur, "test", sizeof("test") - 1))
+			cur += strlen("kcsan_");
+			if (!str_has_prefix(cur, "test"))
 				continue; /* KCSAN runtime function. */
 			/* KCSAN related test. */
 		}
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731081723.2181297-3-elver%40google.com.
