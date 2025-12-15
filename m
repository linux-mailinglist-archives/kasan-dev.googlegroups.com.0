Return-Path: <kasan-dev+bncBC7OBJGL2MHBB546QDFAMGQE4W3E3QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x639.google.com (mail-ej1-x639.google.com [IPv6:2a00:1450:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A01CCBE187
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 14:39:05 +0100 (CET)
Received: by mail-ej1-x639.google.com with SMTP id a640c23a62f3a-b70caafad59sf258405866b.0
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Dec 2025 05:39:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765805944; cv=pass;
        d=google.com; s=arc-20240605;
        b=iYfKMdmsAK9H4YvhWPwcBspAFJ+jcIGVUBdrO1RKBRJGwNW/jiDTI734p53MGXL1Hl
         YYGi7es959k6wL7GrWHWHOCyP6C354sg104q4Fr4bfeFgl9A/zmSbpLVaNxeLTrVFSNM
         VMojfOW9AW7MD/H0ixnw9IL4bdJ19Jr49LvckAqV0z5IpXijdrEZfXZwOWV7iVh2KJyc
         rVPlD8ZAE+i5kry/DE6GyX1rXix9Y3DvDqL7Ckd6PatC0m/6K/QRLQ1vMJEGOMsRdTfD
         WmojWXvbVhtFmwNf36HMSJASKTZNl7Nt7d4TTvS5ZWSu5ei0+1keKp96xb8HuJNYD0uo
         2ApA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=pbNuE4lm+9fayMXYwI/B6c8Zc5o7bWRBcKtp39PoVRk=;
        fh=mOTpio16D0um6kDWnuHPCoWSjfsxS+N5aaeZf9YWwm8=;
        b=UdREWaCT9/RVTKQ0cWbjLJQh9P2wx/aOXnUX7MZTQkhkOXKrJLjeJVmxIXg3ZIqwe1
         LKHRdUWGW4NmCzDD/wXHCu076NaBSJstsX/viHGt6mn4Tg/pcY10uIs7GVFlAFKlMcM+
         tn2rgqr5OArG4feVSn9rkXyVGllfFrAboXcvsGektioxlOHAWXowsn1orLby3BAGdUim
         hOzwK5mWWI0mvF4jwoTKQchMb58ezntRYAQOQUhjXbcxenG3yJIv/EPlLYfzDAxQGYOm
         jXJo7Om5CXaHqMs5vkz5ZiUYmtxmmVA/A8UBCN4o57fNOI9Sv5Nd0cEXdBwikjKAgJ7d
         8S/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kMr19tp0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765805944; x=1766410744; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=pbNuE4lm+9fayMXYwI/B6c8Zc5o7bWRBcKtp39PoVRk=;
        b=LMZhkn7nHEgwiJ2t4+eGykfpEbkoeZZVCt/bqqbpbw9LhEDqRJEOzjLXaiHx2hQSdA
         gk0GhfFdX9DIxKzEPAhI8weIrSfsaHH5Hz8Or+9z/7P3nsZSO7dRfv9TaoNuYaLaLq20
         w/E6IAvFI9DzZ6AeOdlZ5oeJ+or6a2ZNxleilEBqGLW1MFPcaLotM39UhixssYJx6l50
         ebMjprFL9wA9Sf09dUGat2Ukp0kp9c/kOqqbs931RzoS0IxXsxHKJsqbN2Rrg5fnzXig
         OLQ6wC9NaSG7ND7wRfM1P5SIt2cFwD1tcwQ33nNpcbLINVk7rDTQdneaRCfkn/l32AOb
         WCDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765805944; x=1766410744;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-gg:x-beenthere:x-gm-message-state:from
         :to:cc:subject:date:message-id:reply-to;
        bh=pbNuE4lm+9fayMXYwI/B6c8Zc5o7bWRBcKtp39PoVRk=;
        b=a0IKJI1bf+Xo6hGOjOKajgcEU5BjsfMWgo3lRoSv4W1exjIOcG+/MrpqzmF9yySmK7
         CExREWTY3rDK5WYMN1jXoX+pkx1wr/3KR4mqynGJpNt5o2xARP91WLjEwPTCkeHg6QSJ
         dMPoeXCvpjSAuXQHKowES0RydsIXzhBaUUfaKRzTxq17NatI3iGxcd8dwjqnLs3FcuUx
         gZ7fKh9KbERyTiL7ZeNdyYEnxfYkbz7Q+rJ7LAgqsVHu9Err5RDLpT8pK3mnps/CcByU
         a95983XsnhKSY6fiIWjdbFbxBrb5vVLDGkj676EeSjxwNGPQvgguRyWw0TMq4sB6NgCK
         cD8Q==
X-Forwarded-Encrypted: i=2; AJvYcCUtZz6LsoSPaQp3KM317CmITSoL0Km2AXeAHKPft7lNlQuMYBMbsWybfWkLBmpzIgfzu6VRgg==@lfdr.de
X-Gm-Message-State: AOJu0YxwXwZBibRaW9i2XxiACCHjeMSf5+Bm1sgcz4EOj6GT3xGxE1RK
	wtVL72aLuZOPBQFE6yTVPCAfZ1Y39cLi1Mj2dJXmT9uUZOUQLZstC7u0
X-Google-Smtp-Source: AGHT+IHjJnLmw1Z9FOPoGPfH/6p1Bymk9JqysMSOWywhopy8TZXChmqIA7U6G8kVx1hfD0yUOvnzfQ==
X-Received: by 2002:a17:907:9613:b0:b4c:137d:89bb with SMTP id a640c23a62f3a-b7d236ff023mr1301218366b.29.1765805944007;
        Mon, 15 Dec 2025 05:39:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYh7eDsOehDaOWyqC9WCsT++TK5aUtTQRKcaUe9DKwOfQ=="
Received: by 2002:aa7:c702:0:b0:641:6610:6028 with SMTP id 4fb4d7f45d1cf-6499a47d183ls1426944a12.2.-pod-prod-03-eu;
 Mon, 15 Dec 2025 05:39:01 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUwtJR3EshvFTLXwmxsqyVAQ2hPMKeV2kRS9eukG9Mw8WqcI64ka2aMurqzpwF+8IGTkBps6tyGYpQ=@googlegroups.com
X-Received: by 2002:a05:6402:5256:b0:649:e5be:1b4e with SMTP id 4fb4d7f45d1cf-649e5be1b92mr617538a12.9.1765805940868;
        Mon, 15 Dec 2025 05:39:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765805940; cv=none;
        d=google.com; s=arc-20240605;
        b=gPDfp1Qf2w/FgRaSv21BhmS59shU+QwFcc0gcYIFw0YnWjDlVQzBa20r07JiimLmYz
         /SkEX4yGlHKvnNDlE6EV8LI8rH7wz4dgE+EuYx7erAyzxglpDYhZHmBPJEP0Xe+QF3i4
         biUYUPyqQrCu24+UMghfhlXvJMDy9C74utKKQCgpiYri5H2b++9cW5R+9tAZ8r870eAq
         DVS+BOV4Wh0yA/dmrJF5fdRk4GOgLJu23L7VmjyEyW7zh1jGABbSgCDC71Yj6UQASsSk
         eJQXOIKAZGSEqurHa/Z2cndnNgW+k7T4XsOJIirQaKSe5raeRPhHEk3rvRbsaT/ae5uv
         LHOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=HP7wXZoAxj3YG64MFXhffqc9TkW1sld9ucKsb/6ZFh4=;
        fh=hRESbI69cJ1BOLEwoqBMruLAHYVHnTtnJtS67XMGwvY=;
        b=cDppZUDYReWJtxl9Ih5h3lotTKRRMAbAL1S4xS8tuk6dVKZu2ylYLkyZMhqIE1N7Ti
         sX6pQoU4+IrdxiATJPCgjT2fbAzgSMxSIqkdkvKsRthTdl35XHIj2+WWlWahBzb0i3cK
         uzlunN1/aeXN9TkLKFGKPpdWOtHAcNUHy881vp7BXTwMjk5hxI61hjmi+AeQUiUO2deE
         nHeC6jrtGMg/SLxvxKTyD1s63+RRGrzDlbkVuXvscx4Zi3IJhp1oFAiEYaeKSXuFrVKy
         /0WarYv96wvgrAcA21eBRQFmnstCSNJLyDNTW6BzdGRtx5vQEbHrsJIXqHNFEdgOaniO
         39Qw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kMr19tp0;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-649820bbdf0si195928a12.3.2025.12.15.05.39.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Dec 2025 05:39:00 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-42e2d5e119fso1567718f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 15 Dec 2025 05:39:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWApwbEzb18Iv85x9aCTOjr5Es+DvmtPBc920b0PIV/TEhSlJNPAIURFwhP30mjzQM52hJdztxfWYk=@googlegroups.com
X-Gm-Gg: AY/fxX4g/eyG5QcouL2QmF6+GSQklzu37puZKx6dmE6XtQWMwAbIyr+IG0b/W874a3n
	KbpqGZuux9exjfL0qi+vEyEkKXwLG62bmL+KQcGEy8v/NF35Au1MmERLWjWeMBsVfVsQV7y9m9L
	LIuYreGQBfBA+KJdVYub0zAVHRnprhwUv6WRJqwYbyymuo4FBsm9QM9jgqfWgtk46TX27SojKmW
	q4/Mh6BzNwrkT6MggFhQ18SLm139n65lkX5XFN81h2QeAHEbloXCmERNGDDvllBeW8mGuKdgIHa
	rLzQtqGBVE2FdmguGW2XOh26TmsZeghf6STfXHSO2oD2wlZZanoHfQyKj6FECiv2VXwbW44aQ22
	LkS11RHPiNWLi8dIi+kf6HYtg9OEobQiNH/VRWkOH4Ids831+s55dYAW+dMUaY948Tnp61h2DS/
	uKw5OQfs/YaCl2LbVqYsBXJ8wIKHik8mwaLToWsnnGtd5k/L98
X-Received: by 2002:a05:6000:310f:b0:430:f7dc:7e8e with SMTP id ffacd0b85a97d-430f7dc809cmr4594614f8f.34.1765805939977;
        Mon, 15 Dec 2025 05:38:59 -0800 (PST)
Received: from elver.google.com ([2a00:79e0:2834:9:5741:4422:4d1d:b335])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-42fb68866f3sm21319081f8f.36.2025.12.15.05.38.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 15 Dec 2025 05:38:59 -0800 (PST)
Date: Mon, 15 Dec 2025 14:38:52 +0100
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
Message-ID: <aUAPbFJSv0alh_ix@elver.google.com>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
 <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
 <CANpmjNP=s33L6LgYWHygEuLtWTq-s2n4yFDvvGcF3HjbGH+hqw@mail.gmail.com>
 <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20251212110928.GP3911114@noisy.programming.kicks-ass.net>
User-Agent: Mutt/2.2.13 (2024-03-09)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=kMr19tp0;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::430 as
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

On Fri, Dec 12, 2025 at 12:09PM +0100, Peter Zijlstra wrote:
> On Fri, Dec 12, 2025 at 11:15:29AM +0100, Marco Elver wrote:
> > On Fri, 12 Dec 2025 at 10:43, Peter Zijlstra <peterz@infradead.org> wrote:
> > [..]
> > > > Correct. We're trading false negatives over false positives at this
> > > > point, just to get things to compile cleanly.
> > >
> > > Right, and this all 'works' right up to the point someone sticks a
> > > must_not_hold somewhere.
> > >
> > > > > > Better support for Linux's scoped guard design could be added in
> > > > > > future if deemed critical.
> > > > >
> > > > > I would think so, per the above I don't think this is 'right'.
> > > >
> > > > It's not sound, but we'll avoid false positives for the time being.
> > > > Maybe we can wrangle the jigsaw of macros to let it correctly acquire
> > > > and then release (via a 2nd cleanup function), it might be as simple
> > > > as marking the 'constructor' with the right __acquires(..), and then
> > > > have a 2nd __attribute__((cleanup)) variable that just does a no-op
> > > > release via __release(..) so we get the already supported pattern
> > > > above.
> > >
> > > Right, like I mentioned in my previous email; it would be lovely if at
> > > the very least __always_inline would get a *very* early pass such that
> > > the above could be resolved without inter-procedural bits. I really
> > > don't consider an __always_inline as another procedure.
> > >
> > > Because as I already noted yesterday, cleanup is now all
> > > __always_inline, and as such *should* all end up in the one function.
> > >
> > > But yes, if we can get a magical mash-up of __cleanup and __release (let
> > > it be knows as __release_on_cleanup ?) that might also work I suppose.
> > > But I vastly prefer __always_inline actually 'working' ;-)
> > 
> > The truth is that __always_inline working in this way is currently
> > infeasible. Clang and LLVM's architecture simply disallow this today:
> > the semantic analysis that -Wthread-safety does happens over the AST,
> > whereas always_inline is processed by early passes in the middle-end
> > already within LLVM's pipeline, well after semantic analysis. There's
> > a complexity budget limit for semantic analysis (type checking,
> > warnings, assorted other errors), and path-sensitive &
> > intra-procedural analysis over the plain AST is outside that budget.
> > Which is why tools like clang-analyzer exist (symbolic execution),
> > where it's possible to afford that complexity since that's not
> > something that runs for a normal compile.
> > 
> > I think I've pushed the current version of Clang's -Wthread-safety
> > already far beyond what folks were thinking is possible (a variant of
> > alias analysis), but even my healthy disregard for the impossible
> > tells me that making path-sensitive intra-procedural analysis even if
> > just for __always_inline functions is quite possibly a fool's errand.
> 
> Well, I had to propose it. Gotta push the envelope :-)
> 
> > So either we get it to work with what we have, or give up.
> 
> So I think as is, we can start. But I really do want the cleanup thing
> sorted, even if just with that __release_on_cleanup mashup or so.

Working on rebasing this to v6.19-rc1 and saw this new scoped seqlock
abstraction. For that one I was able to make it work like I thought we
could (below). Some awkwardness is required to make it work in
for-loops, which only let you define variables with the same type.

For <linux/cleanup.h> it needs some more thought due to extra levels of
indirection.

------ >8 ------

diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index b5563dc83aba..5162962b4b26 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -1249,6 +1249,7 @@ struct ss_tmp {
 };
 
 static __always_inline void __scoped_seqlock_cleanup(struct ss_tmp *sst)
+	__no_context_analysis
 {
 	if (sst->lock)
 		spin_unlock(sst->lock);
@@ -1278,6 +1279,7 @@ extern void __scoped_seqlock_bug(void);
 
 static __always_inline void
 __scoped_seqlock_next(struct ss_tmp *sst, seqlock_t *lock, enum ss_state target)
+	__no_context_analysis
 {
 	switch (sst->state) {
 	case ss_done:
@@ -1320,9 +1322,18 @@ __scoped_seqlock_next(struct ss_tmp *sst, seqlock_t *lock, enum ss_state target)
 	}
 }
 
+/*
+ * Context analysis helper to release seqlock at the end of the for-scope; the
+ * alias analysis of the compiler will recognize that the pointer @s is is an
+ * alias to @_seqlock passed to read_seqbegin(_seqlock) below.
+ */
+static __always_inline void __scoped_seqlock_cleanup_ctx(struct ss_tmp **s)
+	__releases_shared(*((seqlock_t **)s)) __no_context_analysis {}
+
 #define __scoped_seqlock_read(_seqlock, _target, _s)			\
 	for (struct ss_tmp _s __cleanup(__scoped_seqlock_cleanup) =	\
-	     { .state = ss_lockless, .data = read_seqbegin(_seqlock) };	\
+	     { .state = ss_lockless, .data = read_seqbegin(_seqlock) }, \
+	     *__UNIQUE_ID(ctx) __cleanup(__scoped_seqlock_cleanup_ctx) = (struct ss_tmp *)_seqlock; \
 	     _s.state != ss_done;					\
 	     __scoped_seqlock_next(&_s, _seqlock, _target))
 
diff --git a/lib/test_context-analysis.c b/lib/test_context-analysis.c
index 4612025a1065..3f72b1ab2300 100644
--- a/lib/test_context-analysis.c
+++ b/lib/test_context-analysis.c
@@ -261,6 +261,13 @@ static void __used test_seqlock_writer(struct test_seqlock_data *d)
 	write_sequnlock_irqrestore(&d->sl, flags);
 }
 
+static void __used test_seqlock_scoped(struct test_seqlock_data *d)
+{
+	scoped_seqlock_read (&d->sl, ss_lockless) {
+		(void)d->counter;
+	}
+}
+
 struct test_rwsem_data {
 	struct rw_semaphore sem;
 	int counter __guarded_by(&sem);

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aUAPbFJSv0alh_ix%40elver.google.com.
