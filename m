Return-Path: <kasan-dev+bncBC7OBJGL2MHBBPGQ6P6QKGQEZOG4MKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 60C512C2384
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 12:02:21 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id q18sf51938ljj.6
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Nov 2020 03:02:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606215741; cv=pass;
        d=google.com; s=arc-20160816;
        b=mZu08lE2z4ob92njlCR+fihFt4E4yLFxQvBjwGNg+v8Av1H1RyV0z3rAqn4WTidti7
         XfDm66vn0cMHcYNy/Pk+8tuZKgE4qR8fy3UKV87B8lhJpg1gBoi5CnMNiBmJikRgv9SG
         cAVOyFmObX+C9glxzBHRxJUMIsQcDziWsX2+n3kNckLOOaEmihI4MwSMzxlrjmXcQaAW
         dCOhq0xSBX46yj2KHJ2ak2q1qJJEgQ3AFcBBYkKtXcun6MbAEh2LknQ4GjjQjOKkjcJt
         VlKdl7Sn+9wDm7SV0OCiOlv2OmntSVzQ8RYw9wOmQk2q7UlPZn3kXCnxb0VZqZagp0NL
         ypwA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=1Cq2Git6HXloFUaUOVaZK6hMZfBipTFQtvVJe1EEVhQ=;
        b=rXLrmWSlb4nbVH4GqsOxthYh+1nMudIFMV6KhX9lx4SB2pysmXdBFzOIZGWs9tOLwq
         bapgT73DRu01IghjL8o1K5254RLewkumHkvTImW1seoKp0juR8q4vvz5yC4DsaTvTCCu
         5Tun+wGrjOWoi2b7tvejG2M38ffweZQpmCNCPrJj+04O3HOUE4ry+x+A6pnQ1AwU5DZa
         /auR7xUsuRnXu7aoxfSbTtdzWtcWp2B6HJZomrHxrFqCz9uiLPu5jwSoj1gxIXnBXHBb
         xa2vESm+nlqxB++iK05+n5sblDrP63ecK8Nb3CSSHjjtXPuVymctgcDGin0qXBkli2zs
         9ETw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BsMKMOtj;
       spf=pass (google.com: domain of 3o-i8xwukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3O-i8XwUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1Cq2Git6HXloFUaUOVaZK6hMZfBipTFQtvVJe1EEVhQ=;
        b=JYlQh4yAwfHPU9fthb6GJo84UNBtQKfcAHCvR8sFb5G/LXbcXGtgB2tTv1YZm9Rmjm
         vDuA4ANTSuTpfBYDYLzLwkJFo/UZ53hwpJTEAEU32dIJz0W+LV80JP2tQOJHkYc8/Tz7
         YGQzyRIJitK87bTd0FUEB9BclWXYID259xLnBUEbH8e/gm+mvEAGNPTHEFcB5AbqGX/J
         usRKPrnjshUhvVo1QmxQEBKBhCNreM59EOlQJzCxXz1XpuCm/qGv0HTrhsRfY5IDgdEr
         K8lgARGjMzyVf8LLPIXoUN69LspNc4WQBZcH+lwxhOGUEVMs/uYlmxKZdc/8R6K5h3dO
         /Ytg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1Cq2Git6HXloFUaUOVaZK6hMZfBipTFQtvVJe1EEVhQ=;
        b=uTEQfG7CNXq1vhPrrMPzLIW6CGc5a4kQlQq+V8qIwnCj2tL+fkFn37Y9rHV1NDPm7C
         8E5RBHe1NJVffC3IIUqiX5BaLI4HqTFFQtwTpPaU8fzDhNJE0cDMMa74hkoIKdsBgyBr
         QNpFDSRYLJvPjWsI4A/frXadEd7w62YdCN+ddYgnqoVftzDc9pjrIUkYt3Z5cWt6bjbc
         CRK2sc40ZhGD9eK7biTif9WbxVBHhN9SyjVeb5KRIyBirNiS+yB3c54h1smuJ45T577F
         lFuEcC9agj8NsMcIUvzlNCGvmMBOuwhZ8Utk0Wp+8EDw96Kz/3ItLRSv/rjf/C36FsLr
         gjqA==
X-Gm-Message-State: AOAM532ECauzEjvEwNdk00N/aEOglI3kwQr6hTHQBrTEkyI9gRMEB9Ve
	4lzs/qxxj2iStK/bawyg0y0=
X-Google-Smtp-Source: ABdhPJyKDilYag3hD0UAAZfFT7QZiy7ox/ZB1+xSemF1SAiFxMJ424JegpjtCjR4bvSPhcDH3xNIoQ==
X-Received: by 2002:a19:8c0b:: with SMTP id o11mr1555682lfd.479.1606215740958;
        Tue, 24 Nov 2020 03:02:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9b9a:: with SMTP id z26ls2676097lji.7.gmail; Tue, 24 Nov
 2020 03:02:19 -0800 (PST)
X-Received: by 2002:a2e:9842:: with SMTP id e2mr1489483ljj.373.1606215739759;
        Tue, 24 Nov 2020 03:02:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606215739; cv=none;
        d=google.com; s=arc-20160816;
        b=la0qT4txc1A/USUJieBpWnFTHtoiWDtUqsVcxdEm9hfAVcdrf8pXMRiQYlJuHA/BY5
         q2gng7TVHEZzcg5W5CdoDZaFCt0ACW3WtwPCHHprviseumXKW76kT6fHP84ZZfkj2O/P
         0W2/1Z52As29rhYjREAOfr1bpVnwuKdzkCwnQqwVYctHjf8RKXq0+Usdb5GdDkKYeUFu
         FflhbnkaCZUHfVttP8tQEShq6WWY8/Vj2g/bjAnXc95kMu10+QB1xn5uFlp7b/npt9mx
         Un0x2Sb8oIb7Am7vR8cN/KGUiE+6aQjaQMLSyXdT9PeThJAngHOufDE2rxWprvsqd4gy
         H3Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ejkit5vRg/6bjTr9vpzggkXDL+i3cvGQkbbhHweAAWw=;
        b=yYYqbAIB4HNR2wj2rIn4d2UiOMliQoElKRqfc72HMwZ1vNbOM/iDt3zb1evEZRuUOw
         kTClqDZUt6rYc3SGiKCK6njawfxXbMkCK/8XPy4aT/0YiMnHazKuy7K8JAEyvWbRgKdv
         knr8GkxfVfHBauBmOdmTTTeLK2C3HkKTmMfEWEdEaXWplRCaptrJ2Y6UEPIHdNStmQGY
         ORBuO6eQbTrrXRFXvKFa5sjenuoHENwEUhGldERo6xbWcvqOQDp3BzcL/wajsBuPQ5mC
         pOtL+5Uq26rRqcS/SvZEMz3IJJaeLsMbUv5TMXPF+1EN6M13MFSSrNzDB26PRMYkbM2c
         YVCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BsMKMOtj;
       spf=pass (google.com: domain of 3o-i8xwukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3O-i8XwUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 26si413948lfr.13.2020.11.24.03.02.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Nov 2020 03:02:19 -0800 (PST)
Received-SPF: pass (google.com: domain of 3o-i8xwukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id v5so521739wmj.0
        for <kasan-dev@googlegroups.com>; Tue, 24 Nov 2020 03:02:19 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:f693:9fff:fef4:2449])
 (user=elver job=sendgmr) by 2002:a1c:790b:: with SMTP id l11mr3880480wme.53.1606215739090;
 Tue, 24 Nov 2020 03:02:19 -0800 (PST)
Date: Tue, 24 Nov 2020 12:02:10 +0100
In-Reply-To: <20201124110210.495616-1-elver@google.com>
Message-Id: <20201124110210.495616-2-elver@google.com>
Mime-Version: 1.0
References: <20201124110210.495616-1-elver@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH v3 2/2] random32: Re-enable KCSAN instrumentation
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, paulmck@kernel.org
Cc: will@kernel.org, peterz@infradead.org, tglx@linutronix.de, 
	mingo@kernel.org, mark.rutland@arm.com, boqun.feng@gmail.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BsMKMOtj;       spf=pass
 (google.com: domain of 3o-i8xwukcqqipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3O-i8XwUKCQQipzivksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--elver.bounces.google.com;
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

Re-enable KCSAN instrumentation, now that KCSAN no longer relies on code
in lib/random32.c.

Signed-off-by: Marco Elver <elver@google.com>
---
v3:
* Add patch to series, since KCSAN no longer needs lib/random32.c.
---
 lib/Makefile | 3 ---
 1 file changed, 3 deletions(-)

diff --git a/lib/Makefile b/lib/Makefile
index ce45af50983a..301020c49533 100644
--- a/lib/Makefile
+++ b/lib/Makefile
@@ -27,9 +27,6 @@ KASAN_SANITIZE_string.o := n
 CFLAGS_string.o += -fno-stack-protector
 endif
 
-# Used by KCSAN while enabled, avoid recursion.
-KCSAN_SANITIZE_random32.o := n
-
 lib-y := ctype.o string.o vsprintf.o cmdline.o \
 	 rbtree.o radix-tree.o timerqueue.o xarray.o \
 	 idr.o extable.o sha1.o irq_regs.o argv_split.o \
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201124110210.495616-2-elver%40google.com.
