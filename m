Return-Path: <kasan-dev+bncBDBK55H2UQKRBG5K5LEQMGQEKLXDXAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 41117CB56B9
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 10:55:41 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-59580c95819sf542864e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Dec 2025 01:55:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765446940; cv=pass;
        d=google.com; s=arc-20240605;
        b=ND2+IYEb03O8DyxW2wo87nyLFHqGJnELulEmTiP/YMNj685s+WZVeiQG5aruhAMGdA
         pkq4cakNSqKKeq6DLaxPC5womPEcsRih3qSxvUgXj48uqdf81unrHwYR/BmqHCjmsDGB
         5AiRYLjSN6XeS5wlZdFOdMCLSIOz4A4fiI/P84BAaCtOiivJ0alhp/DX+6CNwl9lsNW6
         90FY9QkG/Y83aUdTq1bfzTDdrGfnDEusoFDTQ8iBMFRjeyyv0zZlyhbt+HRct9ucaVnj
         4YMuVxhvHzYKc3n4NAB9kRpHAOGzaxzvGMMiiRSFvoW42309fq5Yh205jPmXZ3liW4s5
         Av1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=TFRyna31TP2hcN95GCHKRhEwf/Ffk4S1S8ZL4QDTayk=;
        fh=n32e/Y+h7lR5OD/mXlUHqtnuKUtAattZ7rKCo9UAfy8=;
        b=euG5AkCwpcMYdU3Y3avgzmoZIXeqgyMYCzHYYe3QCqBztqHpxhGuO2i3r1QpQDSpgf
         MHi3C1Z+gJaqjsz2M84motV8/mhiwiGwafIe4uk5SkCp0r68Eclc9jajTR5IwYYJqnle
         4PAWEizyYnFtzry/1MFuGxW3Xy2qqIB1TfsFm1FsTN5hyuwgQhWeiu6UQ5QrKHlm9gqw
         ptPvdDcUXEafG5L6cE/jHBavM2/v+xviSB6B3vsYnSf85bzZa+SHT6gWlFC1ysDGak8I
         SwCqLaCS06kuGAFA11AvVS0/DYpeLzzTvJSI6vxmFQYAWOkNREOYA+sLDUNUr5RvihMz
         QD7A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=E3bZKCI1;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765446940; x=1766051740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TFRyna31TP2hcN95GCHKRhEwf/Ffk4S1S8ZL4QDTayk=;
        b=gLJBv01Q4qVpGeWrYkKN/MO3mtcuJgi887DVsxXozKEbjX98rod/Qz7ySLASLdYhLY
         fZa2+4FPpu62vgACXTRJ4dskMPSv2nT9Xc73BVx+1TGslMuRUAdFvvXVtjMI3K+j0vj6
         wv04hj6GrBvpNb3hqE7Yf/+cyJvf9sKeIndqUKWzjz8Cexa9r0yOy53hY8V+8D93qySY
         9KRdyCpCWJGmSEDIIqlLrpNW8C+AiwFcZ4IPLKCDGJ8pInxMmmjsiLxP+zK5otDLuEta
         8e+KNIC+786IWhVsyVPVqxKznDewo7xYXRJ9gnbAD1AvGq0AjPcOI6s5hFLWBvCzH9EF
         qCiQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765446940; x=1766051740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=TFRyna31TP2hcN95GCHKRhEwf/Ffk4S1S8ZL4QDTayk=;
        b=HwGXwW0SLAk1ds7DfmPH9law/uotkt07EXWGDDnY3SvAvcnZzebHL3jM3RUhO8Hp6z
         UJt2eUGy9gnTFQlXumdR7p5o3kpw6uOsdeDQOoYQaEz/95TovZL28Qtwb/ldiT8wkalI
         tNQh9oTl6imc912nPXaQmL/cgROh/YG2IJyETT1k3RSes7nIvXsm6CJkAFQLYkUpe6j/
         BeSobSeekCeRPFcSdAxChBZVY5Xoe3stk8yZYdztQHLPVWPCTtKFrSZ4+4JL2I65wGyN
         Vms7bW9oFNR/UpLmFMMyxm+m2RWz3YtZSt1d5mWeZmYOERZuNiFS2EmCS5L3IDxSHwB+
         PT4Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWt3stai1PBoa5r6mfb/Jjlt0rzg3XBwVvQWDdAhzTjPHvH70380RmJqTlb6BHrY/p0hWmJ2w==@lfdr.de
X-Gm-Message-State: AOJu0YzJp8qzj1S1zbWjebdVJQJL20+WtFl7NvqfX9eVjkk3xXqBRWUd
	+Jm6w5W5RNpI/7UJ130CRpB9DK2Bsr2j2tcfvMLw5RiaY3dcBWsaqePe
X-Google-Smtp-Source: AGHT+IH4wuZkHoco23Fjwc5tzbxNLbW8JHxhQuPsIOGKaIMp4ZqvWwg3q9wyvgiqIrVNSq5oct6dhA==
X-Received: by 2002:a05:6512:4005:b0:598:ef92:d97 with SMTP id 2adb3069b0e04-598ef920dcfmr1765756e87.43.1765446940159;
        Thu, 11 Dec 2025 01:55:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbARgndPV798Or6YkkTZ1OHtjZYtNqJwmX9Zo3Htfa4Uw=="
Received: by 2002:a05:6512:2c9b:b0:598:ec8d:f528 with SMTP id
 2adb3069b0e04-598f32925e6ls191776e87.2.-pod-prod-03-eu; Thu, 11 Dec 2025
 01:55:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVwuLUux6vAXSiuN6qm7NkrCe6YWUntiiBsN6JBSeCvFt/Zv/5GjPcacm1Tw8LGGCC8nGLOB5c6ZXw=@googlegroups.com
X-Received: by 2002:a05:6512:3f28:b0:594:2f72:2f7b with SMTP id 2adb3069b0e04-598ee45d63bmr1832331e87.6.1765446936843;
        Thu, 11 Dec 2025 01:55:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765446936; cv=none;
        d=google.com; s=arc-20240605;
        b=NnVFa2NzZRfxvSmZ+3lf09/K7s+z+4KjpwL2fbm479kpn19AxUUCQUOJ/ZK1mt0F/u
         TvdVK7RPqlk2YH5mcJ1XKMvWEOQ8AvV+RSlsAtup+N7dmfFKZnxWkHbd+1mtKt6aLE0h
         vivbrW+qVsQJz+KEESRRqrjC/mKVWH3MUTjmUOZXfd/ai5RToLE8pq2vkvNHWBYig9G5
         zXHINzaIqlnOHpHGTkK8Zlc3emczI78kefxo79urs3FCcGSWt5v3lSw+nDZfTh6F1wD3
         5lQTgYWC324mkf3HjZJKrVx4YFvGfomU8l2GknDNzcz62wVvTRSG9ULkBj48XvEdU+n6
         s8mA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6WhymY9DTx4lwYH2yf2+tZtBM6CKMmmYYDOh50+lOZo=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=ejosvQgZdInO/z75De1XUWY26Xq56Y4F9Muho4barT/yqKWfQcbvBQokagmBSrQWcH
         QgDmV5F7Tf7phsnEjo9ESjftLOTBCvHrWoabCBPa/OcuGj9Yb/oVV6KhevaxRNi442+m
         1pwS3us6Ipamw+EdX2+vJCVbbYr59zru2cq07d6tFPOSM4w5a4anHWjcxjIzfF9jT7rE
         7nX9eEM2foNqgRtnZHCibv9mFZcWdgQdlvegUKoZWWJhe3+p82XB5fVaF2wGXdPNVm+0
         YJUAr5V2ofcPITOd4CLY77C/b5tPoPY60E16lawNR1LdMJaKy3Trnt9oeH2WVHNIdwCe
         WWIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=E3bZKCI1;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37fc5ca6b40si144621fa.4.2025.12.11.01.55.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Dec 2025 01:55:36 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTcWn-0000000Eibk-2SDe;
	Thu, 11 Dec 2025 09:00:02 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id DB9BD300566; Thu, 11 Dec 2025 10:55:16 +0100 (CET)
Date: Thu, 11 Dec 2025 10:55:16 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	Chris Li <sparse@chrisli.org>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Johannes Berg <johannes.berg@intel.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, linux-wireless@vger.kernel.org,
	llvm@lists.linux.dev, rcu@vger.kernel.org
Subject: Re: [PATCH v4 06/35] cleanup: Basic compatibility with context
 analysis
Message-ID: <20251211095516.GO3707837@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251120151033.3840508-7-elver@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=E3bZKCI1;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=infradead.org
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

On Thu, Nov 20, 2025 at 04:09:31PM +0100, Marco Elver wrote:
> Introduce basic compatibility with cleanup.h infrastructure: introduce
> DECLARE_LOCK_GUARD_*_ATTRS() helpers to add attributes to constructors
> and destructors respectively.
> 
> Note: Due to the scoped cleanup helpers used for lock guards wrapping
> acquire and release around their own constructors/destructors that store
> pointers to the passed locks in a separate struct, we currently cannot
> accurately annotate *destructors* which lock was released. While it's
> possible to annotate the constructor to say which lock was acquired,
> that alone would result in false positives claiming the lock was not
> released on function return.
> 
> Instead, to avoid false positives, we can claim that the constructor
> "assumes" that the taken lock is held via __assumes_ctx_guard().
> 
> This will ensure we can still benefit from the analysis where scoped
> guards are used to protect access to guarded variables, while avoiding
> false positives. The only downside are false negatives where we might
> accidentally lock the same lock again:
> 
> 	raw_spin_lock(&my_lock);
> 	...
> 	guard(raw_spinlock)(&my_lock);  // no warning
> 
> Arguably, lockdep will immediately catch issues like this.
> 
> While Clang's analysis supports scoped guards in C++ [1], there's no way
> to apply this to C right now. Better support for Linux's scoped guard
> design could be added in future if deemed critical.

Moo, so the alias analysis didn't help here?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251211095516.GO3707837%40noisy.programming.kicks-ass.net.
