Return-Path: <kasan-dev+bncBDBK55H2UQKRBEODQXFAMGQECWIPLKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x537.google.com (mail-ed1-x537.google.com [IPv6:2a00:1450:4864:20::537])
	by mail.lfdr.de (Postfix) with ESMTPS id 086E5CC34B3
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 14:41:39 +0100 (CET)
Received: by mail-ed1-x537.google.com with SMTP id 4fb4d7f45d1cf-64969d8d4f2sf6890508a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Dec 2025 05:41:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765892498; cv=pass;
        d=google.com; s=arc-20240605;
        b=OZwVZhNBZ8jObCXZ9o4p6MrEMtIPsV1TL3RWKyQwtmnoDS7Juzdp9etkB9K1V7ZxVt
         WRHa46d6FQrCKqvOGQ40kUv36T0gOhUu2UYWgoqREMbCPiWw56C4dXxwFgYAkjEhyaxS
         kVdS/72qMEXIAWgYEAV3IflLhd9zWXIqjhhVfE2EaqMscgtuAUK+X6cwx9M2Eo5H+ord
         S+c3LiSYKjE64o+rnrQfPsY26z87Lkqzv/KPFi+iOp2E7LEUInQWV0DtuP5JCBiqMgFN
         vF8OAUJKaLYrbeMhvBl/03h0W8fIsG1ye7cgke3tNotdk8fjmD3cxSpjK6pduYhpiZYY
         46og==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=BC+vpJUdezh0zLLEI69WTWQrOKWcwx9fy/+sEAdvefM=;
        fh=zsjT6lfeOT3CnPGGk6MOJmyjg3zc7PrMr5EfrnGNVHk=;
        b=HY+GSWANrknNJ95Qqv9zqGbfTMdgHtlOO86AfoOr3XUKm2IjAFnqznrLH6S2q/p04M
         rbu9rbGZJjPRO1+IxR1VwArGqmL6yf7Nvysnfv9lvzNM5BfiUN8yylF5bCwKmeXGlkgE
         8Voa4rB192NcyXWuhQVUN0qUdr7Bx8JBWmuqio7fYOvhDXxsaiR/ooW657Hxyo6JxPh2
         8SkWLizh3KE12otNPrf5GOp0V9zz84+ZnKWg9No0uS1j6kedNb9OzJxZ1A9eokPdJYcR
         zhcorBR9EoRGKsGPyIENbTLn0glbI5o8iKoCnL7SHxktkWnq7CnhG7sVUObHl42WeQ3d
         Oifg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=dMWulvkE;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765892498; x=1766497298; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BC+vpJUdezh0zLLEI69WTWQrOKWcwx9fy/+sEAdvefM=;
        b=QI7/NONNQTYL0fyjODQODKSGDmoGwFRbYD5iFKIvwMgNwAYIbrZ+uUEGK98Sc2HJUZ
         EECy5qhk/YAbAEJjp5KgqQtmwqTzqWcxPdwvmmIod9dflzYfMePhvFjLX4RRYpa1bG2k
         9RvvuIuiwACOJZ5Sr1kh0WftoyHozKFtu/d35+FXr97/E8B1KnlYO3bAeCG1Sx332FyP
         0ALxX8xGbdJ1/tLNRyY6rkRloFVntNBbIQDMrTuHBK0NaKZOCEerFDvNvzPY2/sa2yD9
         CPctj760cmgu0HexN5ag5zZ3CxYR9NeKJw1YMBKgOYXdqhScIJD6/mROnbEnO9HOO9x9
         q9DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765892498; x=1766497298;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=BC+vpJUdezh0zLLEI69WTWQrOKWcwx9fy/+sEAdvefM=;
        b=N47QmIsfmCG7IOpLk7qV7c1kIoCA74GsdLCu1QV8Sl3liI4q5fzoRzEqzA4FssNynu
         gaO4/B8MvjWzjNFbABhib3S3fdW5YWNYEk1DgGkfzmqid+nBuqy7E4ztlQHJ1m5zI6HV
         LeNu+LOre5QePKnJfyHxwMkXqhOLTZN3EaRB9GSwVZyvIPtYzXgeZ8i79V56u/Jc+zYL
         oUYRJfcqKTYLopmOmszIBGUnk1dXEKWK6X6D6+xlvWcv4bBBFm8YdmkCZjIQABXG7zTK
         ANkM+yU4TBM6lVa64ylmOIZwLL3qXMXGlpAHkMqojBc3cWwdjfQmY1rg64FV+vISYjFN
         nl5w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW3lJ+t2wrQK6n8F+WCaDAyUmT1l9pYljWkVenm5DwK3MUJQXaZuAYQO2iugESaElXaEzMv/A==@lfdr.de
X-Gm-Message-State: AOJu0YylqKw4r/SvjOBFZTBBMWg7AmI2MXYYZhqG+xHk+o0op6lVN2Iu
	Jkk+30gKiftJsC8KiObVjjsval2HF7jYZEVQ4psTby72hgAjQyqgi6nn
X-Google-Smtp-Source: AGHT+IE9TWpl7QUazEk8ESfqc0ffK0gkwqemX5QKf1irQ3QzPxss2dO1o+7hJDhd08s2w2w+kwxfiA==
X-Received: by 2002:a05:6402:34c6:b0:649:91f0:ec5e with SMTP id 4fb4d7f45d1cf-6499b1c86f7mr15109689a12.17.1765892498361;
        Tue, 16 Dec 2025 05:41:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbFs87kSjF37lJINuUAESwEuQWzHIfKqZY82cmA76pbIw=="
Received: by 2002:a05:6402:5346:20b0:649:7861:d7d7 with SMTP id
 4fb4d7f45d1cf-6499a484a38ls4743570a12.2.-pod-prod-04-eu; Tue, 16 Dec 2025
 05:41:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXZeT0BQoS5+s2ZMpNoChWMWZ3Q7xaKXfs9Lsi3vVnIUeEDpgn/hiSpigcU7j69mzCHJqlV6d/uq4w=@googlegroups.com
X-Received: by 2002:a17:907:d10:b0:b76:e6bd:7bcd with SMTP id a640c23a62f3a-b7d23a4bba5mr1506928766b.20.1765892495141;
        Tue, 16 Dec 2025 05:41:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765892495; cv=none;
        d=google.com; s=arc-20240605;
        b=adn5v415pkyn38ZzyZJwStxymJOeOMnX3SFe7+ocQm8ova/GfF8xFXCPnpA9MUDaTR
         x0wQyqPYNz0z14Lt7I0xgZHHrd3zWkhtXRrEmHbsy9t97s8l1k6PuF8A46xUwOazNDqj
         c/bW8ldGajVV57f3OmPij/qtzJtR/L+cFAYwD3W9EutuiitI1QmVSvIeSattXlLqCSo3
         DkKs/m8J/SM5c9lnEu61uKO6Zyfn+w/g4OUY56UPtf6zTFZtn3IN2nDwIUMz4uH7ajEF
         YgUsn8JIllqO3l1RECpWItyYzavSCWDuwlCM5RKdDv3kIMFwDAy17eLIA+q0sqnFLpP8
         Pnfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=3682UGOf9mvj955UPR/gJlxWjdDq8XctSWFz2A093u0=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=JNS4T1P5iSx2c+jn0s7SCfNctcDS8yZ58bnlrSKkk0LMcrACOGArIyYxs/vzuZvat1
         8K3fyzcj9T/pcjQXUQIeMlrWC/58QphPWavti+5TgAJd/2C0VqLo0xrtnXEaoAnKS7JI
         9AMCTfMmcLvyyu4r6uhiCSUaR/SwNuUENP8qNWSJHKbC8S+7dTQ70Qz33sJhz3dx6ZgR
         YoSmLGuKFU0a1mvZXc08H8xciVXhj2cmcfHDv0gtD32Jndp6eTa7lK5okHLfjJX9LlPk
         q6MRauplpRyyuiLMOUIDR4QoxnEPka2ZG9vXvLyQ+sTQ5wgCW0i4FOtFa1XxQlqOBbbX
         5AvA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=dMWulvkE;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b7cf9f386d6si19880766b.0.2025.12.16.05.41.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Dec 2025 05:41:35 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vVVIn-00000003LNo-2njp;
	Tue, 16 Dec 2025 13:41:21 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 0582B30029E; Tue, 16 Dec 2025 14:41:20 +0100 (CET)
Date: Tue, 16 Dec 2025 14:41:19 +0100
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
Message-ID: <20251216134119.GU3707837@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
 <aUAPbFJSv0alh_ix@elver.google.com>
 <20251216123211.GT3707837@noisy.programming.kicks-ass.net>
 <aUFdRzx1dxRx1Uqa@elver.google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aUFdRzx1dxRx1Uqa@elver.google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=dMWulvkE;
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

On Tue, Dec 16, 2025 at 02:23:19PM +0100, Marco Elver wrote:

> > Also, why do we need this second variable with cleanup; can't the
> > existing __scoped_seqlock_cleanup() get the __releases_shared()
> > attribute?
> 
> The existing __scoped_seqlock_cleanup() receives &_s (struct ss_tmp *),
> and we can't refer to the _seqlock from __scoped_seqlock_cleanup(). Even
> if I create a member seqlock_t* ss_tmp::seqlock and initialize it with
> _seqlock, the compiler can't track that the member would be an alias of
> _seqlock. The function __scoped_seqlock_next() does receive _seqlock to
> effectively release it executes for every loop, so there'd be a "lock
> imbalance" in the compiler's eyes.
> 
> So having the direct alias (even if we cast it to make it work in the
> single-statement multi-definition, the compiler doesn't care) is
> required for it to work.

Right -- it just clicked while I was walking outside. Without actual
inlining it cannot see through the constructor and track the variable :/

OK, let me stare at this more.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251216134119.GU3707837%40noisy.programming.kicks-ass.net.
