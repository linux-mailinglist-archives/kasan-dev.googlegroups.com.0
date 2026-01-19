Return-Path: <kasan-dev+bncBC7OBJGL2MHBBK7YW7FQMGQEDSD25GY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id AA323D3A352
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 10:41:00 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-64d01707c32sf7155813a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 01:41:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768815660; cv=pass;
        d=google.com; s=arc-20240605;
        b=RDGcMWYP0spfJMBOaLDz5yRZSZnnHTlVVewjiEMPB7fFV01LCrnatGxOu4QIT+/r46
         61jjgOLo15yulrsdAW0+G638RCvgd1hYqV4eazamkJOgeT5ceW0n3GAy9nCf5ZaIZyXB
         wr9jzfrpQ4tZxFjrjnfpe7kA0v65E1MrqBU31lJeV4S+0UfMm71dGatToI0lW2tXL+X1
         jntHU7R1Vrh9rnBEtdUfN6sl52tEg7QAh2q+ZiWORfx3B354bEjeWuFPaLYWtNfNuG0s
         eGrcxzE23LZDjD1/q5b6kEJKvrfOOlJ6hh/Ma0SLe0K+lo/h1soP1U01rmODUycVFG/k
         dYlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=YMUXedKuS2PnfZnmv16RNlvkZZQq3qt6e7cWEGPBD4Q=;
        fh=Kxr7Gh3wdz9A9fFuSC3tJ5PXHeLJJgg0NdjVaVGk6jk=;
        b=QFVsLb4NsNXUHnRgRP4ShytM0IlF16tmWOaExlmUVQ15iljQIW6hPn6eyxpG/W6R05
         /POUE5nAR+E9WjLRgafzCNCyrsbBth5Zygc6WpY+aZtxyXnU0aRp2lcDkpjhoTwXtemv
         yQ2tOjhP8h8ydTUSAiIgaTPb8cLv5WW57RNBcv/uJwH59VeS/lASDqgcNvUWbiMpU15g
         5dGylA9Yqubw7W7+B/ZnpYKf+3f2j6b42yFbHPMirQ4FhK2ZDxiYlF8SOTG+lQJjoAYS
         gMsMKhFdMuMRjO6FjNxjkh2aG7Vt6fgoPdqYtjDHWTIEHfYYryfPglwbga+bE2sNa7Go
         UKfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2JEIzXMI;
       spf=pass (google.com: domain of 3kpxtaqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3KPxtaQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768815660; x=1769420460; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YMUXedKuS2PnfZnmv16RNlvkZZQq3qt6e7cWEGPBD4Q=;
        b=qhcRubYTCib+DFE24A/DWUSheNFBvnniSTXr3mMaVw6yplRXwmoU0DlY8qcFnjswiX
         6V9HTLo4tn4a+80/OaA38SwhzIxj/9/7XQUmQKCcdqWpjCbUeyT1QtKvzzHWdM+Zyn0I
         JdhtoUrvb+97Lok+vgDnLQDE6AdI/fkCfuVfEJGxrtXF6HQlFmkNoId8OuQjN8dRAEHA
         KYN4EkhG9+QAX9WlVJ4DrnXMwWPiGkd3uCKdLI9UiN++F1PUE+2JMTznPvBDXVzZQFIT
         KW7ObBvJg6iNtisoSgCCZFJ8Yry8xPwtUK0E5DFwWRusSGcKynB4AbKoEHqPaYPim4Ki
         eaYA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768815660; x=1769420460;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YMUXedKuS2PnfZnmv16RNlvkZZQq3qt6e7cWEGPBD4Q=;
        b=iqP2KGtncKN9zkUhf1CqUp1pZrWLD5flUgpGOUw2PFSow+IhFK6nwfwXX7bsNtK82D
         QDri4LqDUKiRDnucyITAjHkVOBowi289djQ9pMhoPQHnSysyEhBDMXtUydSM30xhcw2h
         n/cG+5lFF2Rx04gt8RiXGtdVi92vKLZV+VX24Et5bY/XVS2ragEgc/fCztujm6w2jh+C
         Wl97yWm+3hutPxRUIDbk38H5OGiOpeBcDy2yBP+HuAyvptK7aRjMzu3y+fFTkVI3nEcR
         m02Z0yEGEW2aXKsCfO5IUgTGBkX76dy1H6COQyg3BUVxDABoNGQawCuQmOZ6nHmJWA7d
         +Ddg==
X-Forwarded-Encrypted: i=2; AJvYcCVNVQZO02T2wgp1Tn9F4wuSswcM+qQx8bxP0x4a97O79EFYmX0/dcxRdvKxl/QDkTJ1ZXkZ6A==@lfdr.de
X-Gm-Message-State: AOJu0YwXvJLkPvG932nvMxyskoG3qCnZrKGJAUIvcTgIV/b4yILhTExS
	fNi7ZQ1X4gU+IfpSgP3lgNiTNKC389qIUQHuM3uJsNGQXm62uadbUr+H
X-Received: by 2002:a05:6402:5106:b0:64c:584c:556c with SMTP id 4fb4d7f45d1cf-654bb6192admr7552067a12.30.1768815659860;
        Mon, 19 Jan 2026 01:40:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FoaqxjvKgMYRIdEZroS/+u46Grx8tfX9A9l4flI17CTQ=="
Received: by 2002:a05:6402:797:b0:644:fc0e:254 with SMTP id
 4fb4d7f45d1cf-6541be8db8fls4255311a12.0.-pod-prod-04-eu; Mon, 19 Jan 2026
 01:40:57 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUNDtwnL5ZNLsx8N2TjzHMCjgGY/olxRA/0OxvnOb3H/3YJDYkHSvJAs2gnAPf72QP89Hv1keK/UTI=@googlegroups.com
X-Received: by 2002:a17:907:86a6:b0:b87:7e8:e272 with SMTP id a640c23a62f3a-b8796b21782mr999575266b.39.1768815657276;
        Mon, 19 Jan 2026 01:40:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768815657; cv=none;
        d=google.com; s=arc-20240605;
        b=MrR6DH0d5/nRjGXCeoIAkzXxX5YaNNc6km+8+YSzct5wIWdJu5BhdBHUBWOAdjiW/n
         sTfzuYJRZxkPkuyI69fJG9ZNiGnY7Kn9uCSN+hV0jBM3UOePcS+zEKVFnHT00KyYiLNN
         0GikT3Cb/SWPe2it+DE6f4cXdZqE5uQPyWlONQfXvgRFgg9tfLDVAJ3Mj13h8K4XA3mL
         9INL06n7oCMGq8Y114dbtP/xoIE0MT71eE9Foe4wAAayyO9mSK2fBCszmSm8I5oYUQ5e
         WZ4w82bRlA2HfSjunZopP4bnRhnvcQAb87amMl2pNGvJigKDR77IEY7DkH9i1o/W1HQS
         0mQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=CA3Nu437Rj+eAevya/i4iek0cQKs4Ymlx+qux+GVc44=;
        fh=tFoEUqtCubHWOZvJRKYs3Ze2DVkAnzpsG5j4olfoD+E=;
        b=XTU0pnYsxo86v+pGZu7L25bcGYpl0N1TIUtVeGr6RCeap9mgoNaQfHAYf1ljbEhnx0
         ABKj8RbNlI5g5Y+n7dU3K+AyhA+P95yA3Z0jALYM+HBREfRt0LUx08iKjK5lsHgxVz3B
         gQuHrai1beerpuOwjUirKFiJyf2IawI8gWMH0MXXANT5/Tn3ERCBnUy6nHpbKazdXA0X
         hKeauTRHlSLC7el2nw4U1iWKKCWzBuGMsApo4Lj7HVgE6E1TaBC8ePqZh6Z7TrXRnVvM
         hUqUOKJDm38m91w4Bdiuy2+0vUB1fVOBwTvKm+f38WVgFI8jiUlJ9O3duubExJyLDYSH
         z7vw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2JEIzXMI;
       spf=pass (google.com: domain of 3kpxtaqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3KPxtaQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b8794f89946si19731466b.0.2026.01.19.01.40.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 01:40:57 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kpxtaqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id ffacd0b85a97d-430fdaba167so2786225f8f.3
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 01:40:57 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUl5al7q4pj77JyEFdi5lEG4YZsB41f9Kq6wCwRmBh/iMnm9unb+De3NgHoTnUBzw3xQ5UbH2fo2zc=@googlegroups.com
X-Received: from wmbka9.prod.google.com ([2002:a05:600c:5849:b0:480:2880:4d51])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600d:6413:10b0:480:1e40:3d2
 with SMTP id 5b1f17b1804b1-4801e400518mr100658775e9.29.1768815656749; Mon, 19
 Jan 2026 01:40:56 -0800 (PST)
Date: Mon, 19 Jan 2026 10:05:54 +0100
In-Reply-To: <20260119094029.1344361-1-elver@google.com>
Mime-Version: 1.0
References: <20260119094029.1344361-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260119094029.1344361-5-elver@google.com>
Subject: [PATCH tip/locking/core 4/6] crypto: Use scoped init guard
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, Ingo Molnar <mingo@kernel.org>
Cc: Thomas Gleixner <tglx@linutronix.de>, Will Deacon <will@kernel.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Waiman Long <longman@redhat.com>, 
	Christoph Hellwig <hch@lst.de>, Steven Rostedt <rostedt@goodmis.org>, Bart Van Assche <bvanassche@acm.org>, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-security-module@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=2JEIzXMI;       spf=pass
 (google.com: domain of 3kpxtaqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3KPxtaQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

Convert lock initialization to scoped guarded initialization where
lock-guarded members are initialized in the same scope.

This ensures the context analysis treats the context as active during member
initialization. This is required to avoid errors once implicit context
assertion is removed.

Signed-off-by: Marco Elver <elver@google.com>
---
 crypto/crypto_engine.c | 2 +-
 crypto/drbg.c          | 2 +-
 2 files changed, 2 insertions(+), 2 deletions(-)

diff --git a/crypto/crypto_engine.c b/crypto/crypto_engine.c
index 1653a4bf5b31..afb6848f7df4 100644
--- a/crypto/crypto_engine.c
+++ b/crypto/crypto_engine.c
@@ -453,7 +453,7 @@ struct crypto_engine *crypto_engine_alloc_init_and_set(struct device *dev,
 	snprintf(engine->name, sizeof(engine->name),
 		 "%s-engine", dev_name(dev));
 
-	spin_lock_init(&engine->queue_lock);
+	guard(spinlock_init)(&engine->queue_lock);
 	crypto_init_queue(&engine->queue, qlen);
 
 	engine->kworker = kthread_run_worker(0, "%s", engine->name);
diff --git a/crypto/drbg.c b/crypto/drbg.c
index 0a6f6c05a78f..21b339c76cca 100644
--- a/crypto/drbg.c
+++ b/crypto/drbg.c
@@ -1780,7 +1780,7 @@ static inline int __init drbg_healthcheck_sanity(void)
 	if (!drbg)
 		return -ENOMEM;
 
-	mutex_init(&drbg->drbg_mutex);
+	guard(mutex_init)(&drbg->drbg_mutex);
 	drbg->core = &drbg_cores[coreref];
 	drbg->reseed_threshold = drbg_max_requests(drbg);
 
-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260119094029.1344361-5-elver%40google.com.
