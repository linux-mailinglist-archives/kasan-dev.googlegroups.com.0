Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIHYW7FQMGQEOZ3N3DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B28CD3A34B
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 10:40:49 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-64d2db4625esf6725365a12.0
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 01:40:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768815649; cv=pass;
        d=google.com; s=arc-20240605;
        b=P4724zuWtTpoPqKdt/mm9s2DrsYZG+LhTL+4av7pSFMTfKeMH6Mwwt6DmT4gsLFFsF
         E7z/Dz2cMRcUouTJf6JO4M2NvUk247xdF7q5be5HBLKCyjGoyKMFKIP8Wpd+2W00/GrE
         QDiq6kdzkozh3KiuUe8p/H3r8Q7JrXBHWa4esYh9SEaXm858+nSWPdHj4VPbTGqdXO3H
         6hhhqr7VvDpgcSlhL7mNngmjIT4OJV8bjNwlENl7mIUm1ET+C4IDRaFZvJjEwHkZ3n1g
         o3ifEg9zECXDCOZIqs0WoRrFoc0HvWiP0G/sYXjmsqGn00HjRpEbAxfondnYIyQwJQ0e
         1Mvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=fjoJiWyDL/w5WDAq4Ke/wVqheBYMoFfsqRzxM/FXyMw=;
        fh=nwYGBQL2HYiJ7kY6+ehZztQXm+aXZd4zUlWNEktGJ9k=;
        b=duo+z6xiqQcdljBFyXzO2GVIOqSf90/dqfGFOrnMq4xR7efG7I1lPKhVxRLdSqp0/o
         q+CxTt62BA0Sr8vPVQ0ULzK8BqpCzRRUw8gX18qmzxYoswOyw2ma6E/FAd79NiQOtpW3
         pAZsaYNoNbpS6bW6IPYTB2OfUE3Fg3d1+hbcpMULDRsZQWjIIonGdB2hp83sDZMN0m9c
         e8HVn+g/NqvasRozLCikf553IlleFyN9BhVJULehKvWrW3MS2VRkjp8TsKRPJYJeXSLf
         vri/fM9VzMXwu1OOioC24nRounNH9Poxen0CthTY+lJ+Oc5/Xd4BkoQw7qUJeZHgk7Ty
         ubUA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1XDAhO+k;
       spf=pass (google.com: domain of 3hfxtaqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HfxtaQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768815649; x=1769420449; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fjoJiWyDL/w5WDAq4Ke/wVqheBYMoFfsqRzxM/FXyMw=;
        b=jtlmZR+W+Rx4biCEdI9C8yBvJ8HL9rkzb8CUFRWy/Ibaj0MQ4RtN9OydFbeTd9GCND
         ifBMlb9qRrYRJIOr1H0iwDtAdz3xhVZnojhoC9ulSB4rrk6auNIwMaJRqFCnq7ch9Oyy
         +uN8RQHqLbal+OdM/mgSUk2JCy9rE4oow6Eb8jU2BaNcNu64yQswgwNRDKAjpeXeK7AR
         LpNylq4c1v+tNZezurgNe/O8McjIzYqfj0gS5lMsUf/sog24so0LtSIQuFsaa0c4txjf
         MJ48xh+dunv3PMVC/dTupVxBWur/xB6LvQqFpYDxt9cxpcs2Dj6D418euSpT+pVHYPkr
         9k+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768815649; x=1769420449;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fjoJiWyDL/w5WDAq4Ke/wVqheBYMoFfsqRzxM/FXyMw=;
        b=eiTarSiDxnQMwtHyoW2qpCPqFNC4N8AcGBrijmjYxu/eNtfMKmEGEWWyARZ6SRHvp2
         1e7dCGoIyRbk02RbHMiSDPi9gzgSG5NYUA61RL2GR7DGagh7sCvcvEJEbK6NE6I762BV
         2690ADy2PeYIFTE9e28Be5LAOHmJJOguPqDeSoiXkp0pQdpDNUI67I4KxrWyeAVchcFa
         uh/OL9Pv+ZjXm7hAmfb604YJx2A9AhCmA0uOx6B6xK54MCGG0Ck91z10vEi9uKtOob3K
         2Zc2d24OuylHzDz5664OmngsX7L6j8DQQbCaTFynN1v9NolwHhWkJMGu92Jrtv7IvM/T
         l/tg==
X-Forwarded-Encrypted: i=2; AJvYcCVIqdHQyzFzfNZzY/WFD0HV6BGWbnHsmI5v3gYgwsc5ahZ2mvFoEGTldXKLvS8Jy3Xj5SierA==@lfdr.de
X-Gm-Message-State: AOJu0Yx0RkmUK2EmUAQoG/viGFAvQO4ow1jVJlhWbk4Yi7cg6LqeIext
	+a6m5z+k75mdHGIwvDD1sazYI5h9Ib1cXn9lkNSQn8Sz+KyKm1jFuNeG
X-Received: by 2002:a05:6402:50ce:b0:64d:1fcf:3eda with SMTP id 4fb4d7f45d1cf-65452acb46fmr7193917a12.22.1768815648619;
        Mon, 19 Jan 2026 01:40:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HH36tHidmQ/qnsnSRAzNUUql+Y8jTPh9kN84rHm27ycw=="
Received: by 2002:a05:6402:3256:20b0:653:9932:b504 with SMTP id
 4fb4d7f45d1cf-6541c6e875fls3753368a12.2.-pod-prod-01-eu; Mon, 19 Jan 2026
 01:40:46 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUBaMxNbtUDEQTorWIzn4DD/y2WILlZmfCvboQef3EVDo3LZbvLNy2RAmWLHfUD74ADZbfpEJJyeUk=@googlegroups.com
X-Received: by 2002:a05:6402:42c4:b0:64b:57d2:7ce4 with SMTP id 4fb4d7f45d1cf-65452bcc081mr7303097a12.27.1768815646104;
        Mon, 19 Jan 2026 01:40:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768815646; cv=none;
        d=google.com; s=arc-20240605;
        b=TkgVzASE2mkzZAVchlSa++PS7Q6rGWHJ6bnbFQZwxYdr0mMb0yEwRY7nBbMirdXtfO
         Ab6lbCgerIg7oPx56t8hx4Z+78d81alULBvYSklZJnZ/ooxk9xuWIGeNfAU2+mWK3Kfd
         z3BuhMdLCx+afUIOxeHcuOX9IFvsOnIPuBlbyWuK7865oPObjclAneycW8mLS8XswPvH
         Nk54on+Yet3RT6YJhIuqA54e3ubSCkkFYyVylXuA38IO8Fx/zEfGEcYw65kwYy5gVXEZ
         wRjvGyf4SfHPvhJLo9itBhbgpo/173M77eRf4LneUrXUecEw/SPGGVsIGQTAkV6L8nl1
         My+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=Tir03/0eTjGqYap+VXkH/YQyday94uYso0Z0/c7DdeU=;
        fh=LkX6jWgsu4o6ha4orPXEnfzNVP3jotFNqvp7lSxLJoc=;
        b=Ht1FpKzMIOPo6mRzVP0fkt6kX0DiHoBf83uctdcjg6D6+GM8bSZFT0H8YNb1l5eyDW
         rNCsBvKm0b8FszCgdiwbTvLwOwKpfiEssFqOReIggW3ULns7GAE0hOqnLnNd+9iPhyDS
         pF44NyrSQw78c7S5/azElcQL+TBT3Ijtavr+daXnU0HuVqTTcBXGWxwsYpvtc0pmvBJU
         ArlCfFfX+IjfzhfYRwnlFYoJo+YPpfHIu0OA9272GxtpAWvX64ppQvd/duUOY4gSrWh9
         aAK9Ebrr+/BPdCU39y1xsE4iNKvwq2hu1S+BiIz7u96qsPvI8a2+qTC+0tYELIgw+CEn
         jcFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1XDAhO+k;
       spf=pass (google.com: domain of 3hfxtaqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HfxtaQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-654532d768bsi194724a12.7.2026.01.19.01.40.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 01:40:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hfxtaqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-4801e9e7159so14647325e9.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 01:40:46 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU7JJq2bi2v+tYQKdb1648mw9wscbEB0AmR5C+6E+B0J/qWRB3fpU0I25/V4eXPrCJnhzBON4h1UTs=@googlegroups.com
X-Received: from wmbil25.prod.google.com ([2002:a05:600c:a599:b0:46e:1e57:dbd6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:358e:b0:470:fe3c:a3b7
 with SMTP id 5b1f17b1804b1-4801e2f3083mr136239335e9.5.1768815645684; Mon, 19
 Jan 2026 01:40:45 -0800 (PST)
Date: Mon, 19 Jan 2026 10:05:50 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260119094029.1344361-1-elver@google.com>
Subject: [PATCH tip/locking/core 0/6] compiler-context-analysis: Scoped init guards
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
 header.i=@google.com header.s=20230601 header.b=1XDAhO+k;       spf=pass
 (google.com: domain of 3hfxtaqukcsaahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3HfxtaQUKCSAAHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

Current context analysis treats lock_init() as implicitly "holding" the
lock to allow initializing guarded members. This causes false-positive
"double lock" reports if the lock is acquired immediately after
initialization in the same scope; for example:

	mutex_init(&d->mtx);
	/* ... counter is guarded by mtx ... */
	d->counter = 0;  /* ok, but mtx is now "held" */
	...
	mutex_lock(&d->mtx); /* warning: acquiring mutex already held */

This series proposes a solution to this by introducing scoped init
guards which Peter suggested, using the guard(type_init)(&lock) or
scoped_guard(type_init, ..) interface. This explicitly marks init scope
where we can initialize guarded members. With that we can revert the
"implicitly hold" after init annotations, which allows use after
initialization scope as follows:

	scoped_guard(mutex_init, &d->mtx) {
		d->counter = 0;
	}
	...
	mutex_lock(&d->mtx); /* ok */

Note: Scoped guarded initialization remains optional, and normal
initialization can still be used if no guarded members are being
initialized. Another alternative is to just disable context analysis to
initialize guarded members with `context_unsafe(var = init)` or adding
the `__context_unsafe(init)` function attribute (the latter not being
recommended for non-trivial functions due to lack of any checking):

	mutex_init(&d->mtx);
	context_unsafe(d->counter = 0);  /* ok */
	...
	mutex_lock(&d->mtx);

This series is an alternative to the approach in [1]:

   * Scoped init guards (this series): Sound interface, requires use of
     guard(type_init)(&lock) or scoped_guard(type_init, ..) for guarded
     member initialization.

   * Reentrant init [1]: Less intrusive, type_init() just works, and
     also allows guarded member initialization with later lock use in
     the same function. But unsound, and e.g. misses double-lock bugs
     immediately after init, trading false positives for false negatives.

[1] https://lore.kernel.org/all/20260115005231.1211866-1-elver@google.com/

Marco Elver (6):
  cleanup: Make __DEFINE_LOCK_GUARD handle commas in initializers
  compiler-context-analysis: Introduce scoped init guards
  kcov: Use scoped init guard
  crypto: Use scoped init guard
  tomoyo: Use scoped init guard
  compiler-context-analysis: Remove __assume_ctx_lock from initializers

 Documentation/dev-tools/context-analysis.rst | 30 ++++++++++++++++++--
 crypto/crypto_engine.c                       |  2 +-
 crypto/drbg.c                                |  2 +-
 include/linux/cleanup.h                      |  8 +++---
 include/linux/compiler-context-analysis.h    |  9 ++----
 include/linux/local_lock.h                   |  8 ++++++
 include/linux/local_lock_internal.h          |  4 +--
 include/linux/mutex.h                        |  4 ++-
 include/linux/rwlock.h                       |  3 +-
 include/linux/rwlock_rt.h                    |  1 -
 include/linux/rwsem.h                        |  6 ++--
 include/linux/seqlock.h                      |  6 +++-
 include/linux/spinlock.h                     | 17 ++++++++---
 include/linux/spinlock_rt.h                  |  1 -
 include/linux/ww_mutex.h                     |  1 -
 kernel/kcov.c                                |  2 +-
 lib/test_context-analysis.c                  | 22 ++++++--------
 security/tomoyo/common.c                     |  2 +-
 18 files changed, 80 insertions(+), 48 deletions(-)

-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260119094029.1344361-1-elver%40google.com.
