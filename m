Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEF4QXFAMGQEEEKGOPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 718B9CC3330
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 14:26:42 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5959d533486sf3305745e87.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 05:26:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765891602; cv=pass;
        d=google.com; s=arc-20240605;
        b=HNTwYhAfdVgbQP1UWXA+S5t7I6HWFtna1lkgdkO1WnEfVugi+4EDTaOYwLWTMwD8bv
         sSDxI8jMED2ldfqSkL0hIaBARVyFgm0SkmCuifvaewQ9vInTeZQ1yDTbXrdyGFjmxzEE
         ZNaBfqpKLaaIPUqBz6FNsQZWQEtx919sshFPQqdu0dogezfs4wJW9sa6Md7SKjPrFqew
         1KsjrTxHMOhUZLeCFYckZb+zZ1xuUyJMm3SP6Jdv1qXaVStLfEFd8NUJo5t4oD1zo5gX
         t8krOsjyd6A4oyT/OqB4XumMX9/pTAP6kvK9gtzgMB+VjD82O2BqDdZkEoemVULu4sP/
         yT+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=oTvQxBVfe6s67RiJvfDjTd6aarp6G8zBLhFGyfs0pdU=;
        fh=w9pZ40H2YFgZjcuV7vTMVRjxcVV20JF8HnIaMZSPP7Y=;
        b=A2ixjSoUkq9pbd6G6gy3vLg8qyfJJC+f97rnc+8BKIkwzbTPmC6+A6bjuVu1wHp4LM
         qPwZT8uMH7HwAUyN6CP8cO1nZV5vHIZPMq10ES5Qg3fiIFViGglqPw4J71nEFOhtAnD8
         MgyjeFXUNK8KzJnlepITX1zZXy00Xs+zRs1ZYaJAwpGmvf/XP6P2Gd268/v7RVq22uH4
         ApwQRo5b8YxHsrb5L/x+Lo2x8I35jWK2ewr/8p3XIk4JiNd3tdsW/ZonM7RhSZXFZOVD
         ZEhJb5RDynDAXpb7bRHB+5unjNqveyV9VSZnSkblYCOkTNnSxBQwQRQU4xw1QWtF+71a
         NsjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xon5SZfI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765891601; x=1766496401; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=oTvQxBVfe6s67RiJvfDjTd6aarp6G8zBLhFGyfs0pdU=;
        b=I1o5Y12NlRXT6AvxUnpX8Wj7+aDFLXkPR2OpS041rdnpzze3VB3t40y+kNVr9Bdkj1
         aYS4lgTc055rxkYvQO89LIdlS79Cj73G43f8WoW5Jwx3wvGLCgZYb7tCiFP0gE09W2Z3
         7Ixg+XG9x8Nwo0dSbgk2jxbW9dEJMpJgjW/gIUjZzBgYG+PbU3F3xD9O/aEF4v7cBtbL
         1RW53jY6+s3uYH44CFDgWoQHNSiZospMpdCJiedNrhPyS5RxR/DD6BJF1KKLKTYCEqjw
         Y8QDcdJMNMmhlbLMgxvUHf3uYQ6opwIhGSBhMt/aeaqRA7UWCABx0myU8O2ub1LxQ+at
         WP/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765891602; x=1766496402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=oTvQxBVfe6s67RiJvfDjTd6aarp6G8zBLhFGyfs0pdU=;
        b=fIwLMKvmRad2Kd5Bzj9lRa7C/xthz7iuEXGNXlfgAYs0dNdQVs+FX16a98B/+XxkRi
         xKuvGsCrnh++1kEsmUjRnGm1a2h8l4WCO6b7is2+RIw3ipeBigH1hTdJJ4VgmlEaNOPa
         qOcMT69y8Tk2X1VHNc0dC+ikm58ymm4lXpZQabWi/ABlGiKiv7btVYpVxcZAfz3DVS1N
         QjzSkhmLL2qOJIXW/yskFJGisn5hVfpyBR+u9aT2/O7naNYa7egGFuHkSIJNG5AnHMst
         c4FiB9K0jaQnyLrnAqCNN1Bp90vWSB0e2ARrIgX3s/tnVuTedzSai8xMKziS5/8q34bX
         vcwg==
X-Forwarded-Encrypted: i=2; AJvYcCUV3POnBtNaZtX3MREjZLI1ssxujwK0dxM+5HsDwE04VKqmgcgmXNh1+ylu8p29nEqXharRLw==@lfdr.de
X-Gm-Message-State: AOJu0Yx6s3ma3tZgFt3jwnmsey/N51eYRwrkjQ7oaqhtE/9IdwIYhNyS
	nMUHxVVVGy/MK+wQIlTbuQbcUEXS6E65Q4JVXLuD4G9xY3Dy2xYKt9B+
X-Google-Smtp-Source: AGHT+IEsZkrWb0OL70Z9BB2/Cs+5Y78OQ4FkZstqdR5RygIY7XODzUGICtAIKaHCbyGtoewuliZbCg==
X-Received: by 2002:a05:6512:3a89:b0:598:853e:871e with SMTP id 2adb3069b0e04-598faa92a69mr4607179e87.50.1765891601412;
        Tue, 16 Dec 2025 05:26:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYqF6wnAlIAbUCWpQCCqYQzalcu9stEC/ZKuos4Fwxc5g=="
Received: by 2002:a05:6512:b17:b0:598:f3ba:8494 with SMTP id
 2adb3069b0e04-598fa387fcdls1807304e87.0.-pod-prod-06-eu; Tue, 16 Dec 2025
 05:26:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXVNhLI34mynyuEY+xTPGBh4ZwsiYPt8LDxWPawOCgMeBGHfX3vODR3wY27JxV+7b5VhCPUYFz1kak=@googlegroups.com
X-Received: by 2002:ac2:5f6c:0:b0:598:fac2:9f79 with SMTP id 2adb3069b0e04-598fac29f8emr3182971e87.18.1765891598220;
        Tue, 16 Dec 2025 05:26:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765891598; cv=none;
        d=google.com; s=arc-20240605;
        b=T98TH38za0RUSwmpLIpg6dR66h4VYM6YpruNSuixdX3/bT47czjRe2Y3FDRRdIEDaU
         JldRVd7m73dXWjNSXpld2PUoCae2Uid6X1070kw66LAfgXEtI9tt7p5sxl4tsYXSFD8j
         Lk/2kZsaCaq08Uuk4t7GW2UTSnhft6nytNg6B7N/hkbrHxgIzk66pX4GpMeH5yqsRmoj
         JOfW0g+pLsMbsAjT7gswsCXB4vI4dXQiZuWk3HiCj2fQmKdPn0Ylah7LqfYO9Vieyy2s
         Edu9KY+VrGiRNy6F107npZ2pDfrE6fKp8yYbGetgCgQ5WVhi17OXMb44erRK8oIe99rl
         qqJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=3V/ozmG0P6zbhJMhekfGn6dV/6uy4a54Tyfq8of8mrw=;
        fh=zAvIwnrXlqk7dUvjf1ZUy1M9t8/zWvtsXwIAPQUxQgo=;
        b=i52IdESDnCuMUUeRWRpOQfbDGOmNzf7M0HscvmN1CBIW7yDfwh2OWKP2nt1ZTqntUd
         R49Lqu3s+hyQfZjawm5EOfp+ho3a4zvKcstzk9suZCw5v+ZMXjxiMWhjLEzstva6vJ/k
         FTnECA1kDKahvDxKLTtDFhLd1xDhtSuxGXT3P17XQLgrVb/f5l6Nr1PzCQGvMIrxGHG+
         iDfo1Fuuv2URe0eW8b0sLZCP+3SwpjyW5GQXIx+89OHtdVVL97FmSJtrPjFVu0ii8oOi
         91zW/QIbXvb0yEIOdegRF3THO43tjD+/X6EVwfgP+RPh5cBU9vyuHCUn0E/6b6lPj+kB
         iCUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xon5SZfI;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::530 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x530.google.com (mail-ed1-x530.google.com. [2a00:1450:4864:20::530])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5990da111f1si50643e87.2.2025.12.16.05.26.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Dec 2025 05:26:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::530 as permitted sender) client-ip=2a00:1450:4864:20::530;
Received: by mail-ed1-x530.google.com with SMTP id 4fb4d7f45d1cf-6495e5265c9so6971884a12.0
        for <kasan-dev@googlegroups.com>; Tue, 16 Dec 2025 05:26:38 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWM9oDwKxWNEmj8AM2FbAf8X5bLoQeFG+ts0CdF9qdZVndwnHiywmQcMqmiybCmZvZX32tZUMP2zbg=@googlegroups.com
X-Gm-Gg: AY/fxX6GPhDKMkBSLvNivFX2M2SwK2twtPG4RIGPemV6skz3lI0E8m23GHMtp0hhAlb
	0JN+V8p9Zs7MdQHWZ704SQh/sL0dqtOxk32LpxiZiATCsu14DE2OpNfz3ykH3OfRQPmCq8sBKsJ
	MM0gr6hGN3bNsdmISPUfBPF6jUiVKYSFo9emtduF9O5ZGpWAWLvYO8BUGV7usXqBOedXcE5um5/
	S1viQ2n845aOSbi+2KiyV+0DTnPYgxQPtm53UzowBYGr0MaLV1FQzdpGwhdKTQ697GXDSosWaWq
	Ob6SUUZ7jf4O7jmrrhyI+2UskzZWYROPYXjORCR9pKQc6uH3oUeWns0W4q2/2olE1AQO4+0FOwH
	5B+AODDOHZNT/MwAhAP/pPD/koZHQSLln36M/dsnePuZgBfPeiw5qqC0uF5JlA37VNHrOlUffiU
	P05nF72wrHRfSAq6mEj9hF+HrZHBf++6ZJeTx3R0QzaLihn84+
X-Received: by 2002:a17:907:72c7:b0:b6d:9bab:a7ba with SMTP id a640c23a62f3a-b7d23a97591mr1453601666b.42.1765891597176;
        Tue, 16 Dec 2025 05:26:37 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:ea4c:b2a8:24a4:9ce9])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-b7cfa5d0b0dsm1693444566b.67.2025.12.16.05.26.34
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 05:26:36 -0800 (PST)
Date: Tue, 16 Dec 2025 14:26:28 +0100
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: Peter Zijlstra <peterz@infradead.org>
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
Message-ID: <aUFeBHuBJr-Y512D@elver.google.com>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
 <aUAPbFJSv0alh_ix@elver.google.com>
 <CANpmjNNm-kbTw46Wh1BJudynHOeLn-Oxew8VuAnCppvV_WtyBw@mail.gmail.com>
 <20251216122359.GS3707837@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251216122359.GS3707837@noisy.programming.kicks-ass.net>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xon5SZfI;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::530 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Tue, Dec 16, 2025 at 01:23PM +0100, Peter Zijlstra wrote:
> On Mon, Dec 15, 2025 at 04:53:18PM +0100, Marco Elver wrote:
> > One observation from the rebase: Generally synchronization primitives
> > do not change much and the annotations are relatively stable, but e.g.
> > RCU & sched (latter is optional and depends on the sched-enablement
> > patch) receive disproportionally more changes, and while new
> > annotations required for v6.19-rc1 were trivial, it does require
> > compiling with a Clang version that does produce the warnings to
> > notice.
> 
> I have:
> 
> Debian clang version 22.0.0 (++20251023025710+3f47a7be1ae6-1~exp5)
> 
> I've not tried if that is new enough.

That's new enough - it's after
https://github.com/llvm/llvm-project/commit/7ccb5c08f0685d4787f12c3224a72f0650c5865e
which is the minimum required version.

> > While Clang 22-dev is being tested on CI, I doubt maintainers already
> > use it, so it's possible we'll see some late warnings due to missing
> > annotations when things hit -next. This might be an acceptable churn
> > cost, if we think the outcome is worthwhile. Things should get better
> > when Clang 22 is released properly, but until then things might be a
> > little bumpy if there are large changes across the core
> > synchronization primitives.
> 
> Yeah, we'll see how bad it gets, we can always disable it for
> COMPILE_TEST or so for a while.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUFeBHuBJr-Y512D%40elver.google.com.
