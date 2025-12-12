Return-Path: <kasan-dev+bncBDBK55H2UQKRB57P57EQMGQETKTMGPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 05514CB8A9E
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 12:09:45 +0100 (CET)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-5942ee3c805sf1269427e87.2
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 03:09:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765537784; cv=pass;
        d=google.com; s=arc-20240605;
        b=bN7elw9fcXikxf6M/fjYXHXGE+buIv14YJuwdWbi2HSC/X2Nag1oU3pcccW3ros7Lx
         Djfgff/kdpQcafOW6poBP8yFvXpndiBNfKnFYkbo66+YNntH5vTknIRjlC5E6eXUmQn+
         DY2baGLc7Tj10juauL/6W5P/8JUFKIxHltXSdCvq57EZmGAz5Dy4S4i7qLpjN7XiP86l
         BptwE1v3RT1cSIiTANsfA5lEDvD/R5QwlWn0hZq3zjqVwuMXO/o+Jt9++RFFcRIqjABM
         O/rGwBrltUtOCjSBULA24X2y1Mzd6WTT1XFJVZMmTRfAYP98Ew50HJxqC/wKHm/nbDVU
         hTtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=Nxag9KGZJKEM7tJJOvCWColmlETC6FFOh0nTDyYE9cQ=;
        fh=IJ3GrzY49C7VLLHBF+50geXK14+j975fSrO5cVktLoE=;
        b=Ltp3KjsTawA8c6HbTA836SbLxd4bOJOdovMn8GDQrom+y6exi3qDB/QmzXVM+VDS9m
         nSFXk/rUVLDoOCmd/COGmGSCADWtpBq0CL0W5VadM3+hdlX8mFcBiAk32VG/QL8MTWv3
         u8zKwUfkh4t5IAD+SwmIhdrfxIMhrrZWKlaurxAfbW9MRapiya2YY+ehWjkjIMp7BwKf
         EfFiGC7/8jH48+tQ/3psgF796ffyOwZ3Xb7Eq+DZJziy28N1WKc/RS+6/RXnDMadM985
         bNqX+yZvurgbZi6pBbxu5wzOxbGJAfIHVd6UhpryLmajMFaUaHcSnp57C1BBGptr8IlE
         +0/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=h0RqJPJB;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765537784; x=1766142584; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Nxag9KGZJKEM7tJJOvCWColmlETC6FFOh0nTDyYE9cQ=;
        b=m0jC1sovFWmtnW/9oIaZPS/ah945/nrkucSvuCBzuRJMxTqjO7iothKtc1wwOZzDwj
         23533RFY7D9I1+sDXyODsKCtTvzrVEw9glrNqYIErFwy0Wkqn3C7Q9yeJY6qcLMtNIbg
         n6AEyuRGtAUw2zyBO0kY7n7LzNiPqWdQG1mpVvb4VciZQvp0UDjtwbMAY8l9vy6DtPBc
         170CwOdMF/rSblE6uuQVBCVfjsyerDaw8uAEZR7cQRDTBCnmq9oEh9XXo69ThBf122bz
         zDN9B/FfUAgwAeCZjhVMO5q46FCcsEcDoHCfwe/J8nM+6r7Dif+71LSDDpgwPSrYMetV
         jtdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765537784; x=1766142584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Nxag9KGZJKEM7tJJOvCWColmlETC6FFOh0nTDyYE9cQ=;
        b=XdFknrY1z4EDc3JkYezZCCXuuq1+RYYoSJisuEsJQGGjVG3/NEHXP0Spyxo/sRLwfg
         Tzy9Z9PKmhJU58wrpJyzjZthQ0h86BmdpIp5hE+Jtfohq8/VHGFDKVwPhYVhhTb02i4D
         w5q3Yx+fWSUDjMdfRN099DwR9uTmQ5k5Y5eQfFoBIGA37bDV3e1Ml2GgKakOY0zQ2ouF
         +6VAO/r3LhCeJuappILkOeMvBS0USkdsB6cm5bPVbTfK9fJo3RVEFqNNHQ5D5XvMjVSC
         e9g3WfiLtAkeok6L5a38XnCoCH3zACR0PetFT40gFfjl0EMLVtF29v9XXy4Ndzr1kH6G
         XLtA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUkHBrr/jYpeNtlk0FcL+bu02pW5N9o8LOQWIU9QBcdoHuCOYGOIFn+lHcR/4iFUbehUFU7sQ==@lfdr.de
X-Gm-Message-State: AOJu0YyYcKlu7/aJw9hu0XnQRt5RBzlH/EJQmGx7hMn1ylKsR3YzRISe
	dtzJmJgcnn2kn0lqO5hFm1QCifKbm6691vba3Ry1EAYLE89iF4ugWOJS
X-Google-Smtp-Source: AGHT+IEsiDgCqBYfue/2mYCYq98pw7NmQYO2+x+gQwtzxyMiJUqwlrqHcUnJhLCfkX8b2LUKcCQUdg==
X-Received: by 2002:a05:6512:3e05:b0:594:51ac:13e with SMTP id 2adb3069b0e04-598faa42f30mr522400e87.17.1765537783899;
        Fri, 12 Dec 2025 03:09:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWa9ed7v76TLdzgx/hq5VJUVLqF1GeGrT4zFOI9NnpPm3g=="
Received: by 2002:a05:651c:3247:10b0:37a:4897:db02 with SMTP id
 38308e7fff4ca-37fcf0545bels2440221fa.2.-pod-prod-08-eu; Fri, 12 Dec 2025
 03:09:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVyMolJbscixr/hllyhsPQUQduaF4S3uCaGh2zvDUAW69gbr/YiA/4sq3DVUyxIYNEWEtAHIYZJ6oE=@googlegroups.com
X-Received: by 2002:a05:651c:3135:b0:37f:d65c:a825 with SMTP id 38308e7fff4ca-37fd65cbb01mr1899111fa.39.1765537780626;
        Fri, 12 Dec 2025 03:09:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765537780; cv=none;
        d=google.com; s=arc-20240605;
        b=ExCY3W7haVopsYVACUP46Xq2W+RTwLYN3gEOVZxAIdJVKX48dLqrk2z9GJTTT05Tqv
         QPiboZn+izdFhfIsqbJMVdPipmzy5ZvPPTqjy9NFqXHNYIs8CjWmMCRxpLCwerNI93vq
         jPUWAjhn5ZnJJMda4rDip9X217HI2LtvuDTdjMTAHTDZfNpqR1f/3c5YY7xEcUg6KWyS
         AbL+DUKGhxMTJ2h5SMn5Lq+xkGLSzakYCTAg2bINJvShS/z3wM4Jm9HfATCJCF75+bOW
         ALZTmPoExIMV9CWhO8n8xdQ39CzTP6OevIWyw8z8ukkYuUIyX5QwarzPgqOjnGLluv6j
         svfA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=sAhBWDHUpHF5PVStWIyQEDmT8IbGgPASZMaiPzih1nU=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=KQn+sxHf17bRCJlRif5CKvTMMV8JpgriaqfCV6PIL7CHzBVpjc3KZfArm4Xkb9xuw2
         ijqtJTWq/WuIpWgTP96z1b686cJdQbGrNi5fBwf77/8Hw5FdsWFnfUdgCjA0tBWfEOOH
         2coNS2cm1tTsQQMxw+zi66Y7kzBaHSnJm/lZAFK5RcM0nUS5ImY1FfSIftLzY5nyiAkx
         DR5UfeJXJUF7fbKj3gcKgSq3Qv2XZ+0F2FBIxOThMUypw2aS/ONfYoSfrTEi4Gio8GwC
         2pZpnMY7lbnRO5uo0qcMNuaJsF+3so1bAUqD7weZll9eZ6o6f04/AyImMudPyOKwxdaU
         75vw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=h0RqJPJB;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37fd2bf15f2si226221fa.7.2025.12.12.03.09.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Dec 2025 03:09:40 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vU0A9-0000000GVlg-2EQb;
	Fri, 12 Dec 2025 10:14:13 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id C422A30057C; Fri, 12 Dec 2025 12:09:28 +0100 (CET)
Date: Fri, 12 Dec 2025 12:09:28 +0100
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
Message-ID: <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=h0RqJPJB;
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

On Fri, Dec 12, 2025 at 11:15:29AM +0100, Marco Elver wrote:
> On Fri, 12 Dec 2025 at 10:43, Peter Zijlstra <peterz@infradead.org> wrote:
> [..]
> > > Correct. We're trading false negatives over false positives at this
> > > point, just to get things to compile cleanly.
> >
> > Right, and this all 'works' right up to the point someone sticks a
> > must_not_hold somewhere.
> >
> > > > > Better support for Linux's scoped guard design could be added in
> > > > > future if deemed critical.
> > > >
> > > > I would think so, per the above I don't think this is 'right'.
> > >
> > > It's not sound, but we'll avoid false positives for the time being.
> > > Maybe we can wrangle the jigsaw of macros to let it correctly acquire
> > > and then release (via a 2nd cleanup function), it might be as simple
> > > as marking the 'constructor' with the right __acquires(..), and then
> > > have a 2nd __attribute__((cleanup)) variable that just does a no-op
> > > release via __release(..) so we get the already supported pattern
> > > above.
> >
> > Right, like I mentioned in my previous email; it would be lovely if at
> > the very least __always_inline would get a *very* early pass such that
> > the above could be resolved without inter-procedural bits. I really
> > don't consider an __always_inline as another procedure.
> >
> > Because as I already noted yesterday, cleanup is now all
> > __always_inline, and as such *should* all end up in the one function.
> >
> > But yes, if we can get a magical mash-up of __cleanup and __release (let
> > it be knows as __release_on_cleanup ?) that might also work I suppose.
> > But I vastly prefer __always_inline actually 'working' ;-)
> 
> The truth is that __always_inline working in this way is currently
> infeasible. Clang and LLVM's architecture simply disallow this today:
> the semantic analysis that -Wthread-safety does happens over the AST,
> whereas always_inline is processed by early passes in the middle-end
> already within LLVM's pipeline, well after semantic analysis. There's
> a complexity budget limit for semantic analysis (type checking,
> warnings, assorted other errors), and path-sensitive &
> intra-procedural analysis over the plain AST is outside that budget.
> Which is why tools like clang-analyzer exist (symbolic execution),
> where it's possible to afford that complexity since that's not
> something that runs for a normal compile.
> 
> I think I've pushed the current version of Clang's -Wthread-safety
> already far beyond what folks were thinking is possible (a variant of
> alias analysis), but even my healthy disregard for the impossible
> tells me that making path-sensitive intra-procedural analysis even if
> just for __always_inline functions is quite possibly a fool's errand.

Well, I had to propose it. Gotta push the envelope :-)

> So either we get it to work with what we have, or give up.

So I think as is, we can start. But I really do want the cleanup thing
sorted, even if just with that __release_on_cleanup mashup or so.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251212110928.GP3911114%40noisy.programming.kicks-ass.net.
