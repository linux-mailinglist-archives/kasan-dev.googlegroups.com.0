Return-Path: <kasan-dev+bncBDBK55H2UQKRBYOH57EQMGQEWJ73H5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A2F7CB8821
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 10:44:03 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id 4fb4d7f45d1cf-647a3af31fbsf1152552a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Dec 2025 01:44:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1765532642; cv=pass;
        d=google.com; s=arc-20240605;
        b=UKucJhYDu6Tkqwlh0r2RAoI/ADb3PLZK5zzn/FwWjjprWUIlIuuGfECyTkS4/zDOGZ
         BHFnKwRfgK2RcMlerCHhIlQFnURELLljUkgeZ0VxKbXu7rm7qe2n1xTtGdWKObWEAMHr
         ULDP8dDtBbPywWJQEQzvxvt7k8tjwtLXpQiURwkOFl4zhIVBDEj8BlonA8tX+lz/BSyS
         tPaoFyvt4GO+CkMrDIrpCqud0xf0d4EN0cUo67UKgRA2PkTNK5gvzJyTQdjUtuf5ZBOE
         H8Oy4WNVb+53GamMP0OqUJQGpvDyO2TP8lbs1qcW8GH071v9AdpdvjBwVhil8+2DyQRK
         pcBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=0srrdFooc95alywFzt6CNclGMHwDssQrcwsDV9Zcx3c=;
        fh=CgG2sR6+nlG7cHhMIgKc/pKUXVYNNa8UqzWGCAMkBUc=;
        b=E/XAhKkB53M5iV+m9W5yQlKGYGh5M72rb2VK2O/k9F9cyFfRCc5DA1B8mlwPukI5Nl
         g8D49z6KoHxz3Wvq06SIHt65d+Hell5bmAsCXyM5XEpDijNuiCUaMrgRJzsTsEJOdTS3
         qeRBTwOYH15L+zSho3lFdEnS0RjVntrpilKCPKHdxNxhFAN1qCbEXJv3uTIFu6friv0/
         Ii7sSIn7I0efEjYlY+11mN031ItBW5k4P5xEgzktssgp4om+OIm4jEcEoXw0Ex0tAoRJ
         FHLI+JAohYVVMMDt3WQLcLqbVUavDPFGq+W/HURLTQVlgnkN6wFyNcKkjZReJqKYRihl
         +vJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Ur4V8SWv;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1765532642; x=1766137442; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0srrdFooc95alywFzt6CNclGMHwDssQrcwsDV9Zcx3c=;
        b=iaUf/NYVFatntcWx3OyBkZ78rLQd3wGB0K9uSsyYGIJHupIZOQGPww6OsZW5lp6lOl
         bj9L00hgLR2OpmkZ+fqmEUO82AqdN94dsCuWS1sfLDKFIL5uhjW25jnH6z+QWC4CrjCT
         9mTjNgoEuXvw+TzaErSJP4fQ5PUn3jDdAArq/Aq6Ju05W7Ab7ETAdgqFojA0J1NIzQu/
         QEYdAwmLWo+sGbD1p1piH7PYnfkvE+hlPxihRhqDhnEk7Rfli1gJbyU8lqJ2L6Oazm0L
         q71UFSxMMQSYTV4zwegoVt26c3n1thgsr5jCSaEoN5okVhCYT6lXEcndWUSV7LY+jX1i
         bmZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1765532642; x=1766137442;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=0srrdFooc95alywFzt6CNclGMHwDssQrcwsDV9Zcx3c=;
        b=tM6GS1ub4NeZ0FjUryAuXrk1lYFKPYCEuyJCgbzfnN3+Yl/1vsjqy3+ngIa3dmy1PJ
         FVUiC7gPAx4rvkP3dBc89o+F5CdWYvdtLpQ5ZoEASLo52XvbsOfgkYgHuoRrtUoyxYsq
         VR1U8HJZ5E2u6/GR5kPL9kPGrwSerdb/mDj0zt3yz9prq0UtOM0zgfCrzUJNWTZW9YjC
         mJdD/FGUh8QvVGk+hvNXfRceDUBdXp8qXVuS4zEC9216DonwlYRomTzbGwDHCNC111qR
         Hr7tdAePyyUAQEdYmGR67OaVUh3n4EcwHFxdzR9kzP5fAC2CmNkbZndxxzgyVOqWU+XU
         +4oA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUe4mmHqteEcyqBOLyd90oxOfXX09ipbIWCGiZLTnaBAgQFI2ubETFbj9Vdb3uCuS/NJ3s1Gg==@lfdr.de
X-Gm-Message-State: AOJu0Yx9SLzNuexAxbWgetvWx+b8hL8Im4JEywLP2sjrxgAjVArY9EHY
	OYhLl9z7DLmAaOXti3kkYMM7vBqLrFIWGIyxD9OCqnrqHRrex+/HMs2r
X-Google-Smtp-Source: AGHT+IFwjKq5FSRF6o7rRrYBk/+anQxrhhhXLksCRoOsE07urHX/2pVHAEYCJe5IEJJa9Bd6tMhQdA==
X-Received: by 2002:a05:6402:5192:b0:647:51a3:1fee with SMTP id 4fb4d7f45d1cf-6499b19ed2bmr1329491a12.15.1765532642257;
        Fri, 12 Dec 2025 01:44:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbl3QnGT491z3NFcDgDdDdmOC1RV0uep2N/wi+5jNPF2w=="
Received: by 2002:aa7:df8c:0:b0:640:ad82:2e60 with SMTP id 4fb4d7f45d1cf-6499a44fa2bls349701a12.1.-pod-prod-05-eu;
 Fri, 12 Dec 2025 01:43:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUctwtBmbcSaA435Ii2at4PnITNRL9PEKqwdvhak4hU48oQOdIpG1g9TbtXP7vGUp6/Cw9sdOuhwlY=@googlegroups.com
X-Received: by 2002:a17:907:7f24:b0:b73:8759:62f6 with SMTP id a640c23a62f3a-b7d23aa3786mr125170566b.60.1765532639110;
        Fri, 12 Dec 2025 01:43:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1765532639; cv=none;
        d=google.com; s=arc-20240605;
        b=kG/ESvNZrzRtN8Q29xHMVZRnfhdfdIa3+HXxeD63oJPsJQKwM97rsZ4vBnPsiQ0Unv
         leVKorvAmI1v8cpsBQ23ZPiqY5casXkOhUsQ32PVqtDPc9eRk28r2MryEgYAXvYrQN54
         7aNI6DRi0C4/9kdtwaS5f4G3MvDIAarDFuTegdLgB2vYjjT69VEfmg83lvusNFmkAKDc
         jn6H6KelhUF2JAzVjzZCTmlqWBcmhycgB1cQ/90UCb5+eARaLxs6yAWbd0R9AmoYKhKo
         L7+EYCv1mzKTcoEVcP97yroUBzhERHl1okI2cFbqmR5kdW8zKhbT2flQNlojDt1Ito/X
         hn7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=J0s9Z/Nw7eH3J6mljMw45LY45lUZplaK/cGrdA/YkXU=;
        fh=0851L0nspSnj7qhIjXjlHLoAWeF01NCU66B65AWv7JQ=;
        b=P1/afDPbkcjHVY+58wP6WS1vz0ARFDr+u01kbREYUfc16pPsp0cz/7AJsJv3OT5z9o
         ExFKOA1dSScUnDvPcwig9eDZyDrrqomup+9YuZiKTb8pH9qHeapNAsPbbikX3kEKDS12
         OguDa2j86P3oR85RxB8ZbzJ3b9nFQtd9cqBJy9oPTMDTjC4k9UzAc4Myrp0IfywuJIXs
         tKLaQG+WmBU8vE5hHeke7XjaLxu4aJzXKuLh8LYaoyQq4uwI+iw7detgoCWM0VNMmd27
         x16cjSadLa0dWg0nNMsnpunziw7Wq16At+xwZ/T422Qd5by+19BE0XIiCDnSa8F4e8lJ
         56Kg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b=Ur4V8SWv;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-649820bbdf0si72172a12.3.2025.12.12.01.43.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 12 Dec 2025 01:43:59 -0800 (PST)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from 2001-1c00-8d85-5700-266e-96ff-fe07-7dcc.cable.dynamic.v6.ziggo.nl ([2001:1c00:8d85:5700:266e:96ff:fe07:7dcc] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1vTypH-0000000GQ2D-3yf4;
	Fri, 12 Dec 2025 08:48:36 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 2F0AD30041D; Fri, 12 Dec 2025 10:43:52 +0100 (CET)
Date: Fri, 12 Dec 2025 10:43:52 +0100
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
Message-ID: <20251212094352.GL3911114@noisy.programming.kicks-ass.net>
References: <20251120145835.3833031-2-elver@google.com>
 <20251120151033.3840508-7-elver@google.com>
 <20251211121659.GH3911114@noisy.programming.kicks-ass.net>
 <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOmAYFj518rH0FdPp=cqK8EeKEgh1ok_zFUwHU5Fu92=w@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b=Ur4V8SWv;
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

On Thu, Dec 11, 2025 at 02:19:28PM +0100, Marco Elver wrote:
> On Thu, 11 Dec 2025 at 13:17, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Thu, Nov 20, 2025 at 04:09:31PM +0100, Marco Elver wrote:
> > > Introduce basic compatibility with cleanup.h infrastructure: introduce
> > > DECLARE_LOCK_GUARD_*_ATTRS() helpers to add attributes to constructors
> > > and destructors respectively.
> > >
> > > Note: Due to the scoped cleanup helpers used for lock guards wrapping
> > > acquire and release around their own constructors/destructors that store
> > > pointers to the passed locks in a separate struct, we currently cannot
> > > accurately annotate *destructors* which lock was released. While it's
> > > possible to annotate the constructor to say which lock was acquired,
> > > that alone would result in false positives claiming the lock was not
> > > released on function return.
> > >
> > > Instead, to avoid false positives, we can claim that the constructor
> > > "assumes" that the taken lock is held via __assumes_ctx_guard().
> 
> 
> > Moo, so the alias analysis didn't help here?
> 
> Unfortunately no, because intra-procedural alias analysis for these
> kinds of diagnostics is infeasible. The compiler can only safely
> perform alias analysis for local variables that do not escape the
> function. The layers of wrapping here make this a bit tricky.
> 
> The compiler (unlike before) is now able to deal with things like:
> {
>     spinlock_t *lock_scope __attribute__((cleanup(spin_unlock))) = &lock;
>     spin_lock(&lock);  // lock through &lock
>     ... critical section ...
> }  // unlock through lock_scope (alias -> &lock)
> 
> > What is the scope of this __assumes_ctx stuff? The way it is used in the
> > lock initializes seems to suggest it escapes scope. But then something
> > like:
> 
> It escapes scope.
> 
> >         scoped_guard (mutex, &foo) {
> >                 ...
> >         }
> >         // context analysis would still assume foo held
> >
> > is somewhat sub-optimal, no?
> 
> Correct. We're trading false negatives over false positives at this
> point, just to get things to compile cleanly.

Right, and this all 'works' right up to the point someone sticks a
must_not_hold somewhere.

> > > Better support for Linux's scoped guard design could be added in
> > > future if deemed critical.
> >
> > I would think so, per the above I don't think this is 'right'.
> 
> It's not sound, but we'll avoid false positives for the time being.
> Maybe we can wrangle the jigsaw of macros to let it correctly acquire
> and then release (via a 2nd cleanup function), it might be as simple
> as marking the 'constructor' with the right __acquires(..), and then
> have a 2nd __attribute__((cleanup)) variable that just does a no-op
> release via __release(..) so we get the already supported pattern
> above.

Right, like I mentioned in my previous email; it would be lovely if at
the very least __always_inline would get a *very* early pass such that
the above could be resolved without inter-procedural bits. I really
don't consider an __always_inline as another procedure.

Because as I already noted yesterday, cleanup is now all
__always_inline, and as such *should* all end up in the one function.

But yes, if we can get a magical mash-up of __cleanup and __release (let
it be knows as __release_on_cleanup ?) that might also work I suppose.
But I vastly prefer __always_inline actually 'working' ;-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251212094352.GL3911114%40noisy.programming.kicks-ass.net.
