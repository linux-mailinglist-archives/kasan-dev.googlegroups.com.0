Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJ73S3FAMGQEV56WFFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id AABC4CD1E7D
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 22:03:37 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-34aa6655510sf3172499a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 13:03:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766178216; cv=pass;
        d=google.com; s=arc-20240605;
        b=fB+cUYcTAHDaQwebva1G/CamhtTD2CFNk3uMlTC73taY4zyG2ubxuPdX2/7QjYdlM9
         z+RyZZgn1rb6p0V1bZWp0bGa4Jwpsvze/3OGIYC88lx9Pz/e0VPytvfAJsrxRGsVGjF8
         DscNCxUsG9lZ/zu3r0ExwGI+qLiIHHhmeT7qofWBLr8TLz6WUaie2CS1oP9Q1GxDg0fs
         KJzmR4hXI3M2f+JaHYcSo6AVHciutjTfRsKh/smCmSv9gdz58s/6cvuvV1J0grpcZf9d
         9fa0TeIE0LGNXq9oMnj03kVJbbh+tC659Vmup+GfkNQiX/kr05Q4K+cpSQeBotk+WwhI
         76CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=sDol7ZL5pMxlrFyjoG1D6L9Tb1hh4ZghEnzrWlUr1yY=;
        fh=w1jdyS7/ZRxbxMG3bN5zdNBpNLFw/jXaxkXxV/7rLYs=;
        b=SDGhbAoLMeHvKxPAlqLutMpjTZ384N5YvTCEsBLD5JXwwsLMQJ9dVdDKqT2iSy7elI
         zQm+voDz3U5uVtlG1gHJnS9jB3Z2VuHFoy6wExyWKRx3dFq8Ievkp5e+/OdlI5ptvKEi
         6KROH5dZSNQ3TySrfp6Lojo3+PxsFaPExaiW+bW61elYzMyuUH8bD0RtrFE2lcFJu3il
         Bdp3os402uGB6bgiQpVvkJP04tgeN4SVnE2JzYZWrXePttVyZZaSBwfcPRFFeBB5gAUQ
         p+VOjX3/Ejng0NOClgT2qU5tgH2QQ4G7qbWwtCWyWfeb01r6CjxWMOSRo5bfcyNew0Nw
         Up8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ysqALRoN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766178216; x=1766783016; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=sDol7ZL5pMxlrFyjoG1D6L9Tb1hh4ZghEnzrWlUr1yY=;
        b=hAqf5ibn8KK0rW6YzTwoA3KDC18d1rn55VYp6kuBiNqmdLo5pESP6WBOulnNFGfOVr
         CsENI8C1xuHd+Cbkr+N+szSG2epoPkOlgEOxvbxnB8bkabQrvgEOujUpf13he50ZcL4B
         ue4IpsHQKAi+41tsM+ex/Ndnt4gC6bu+2Qfy8Ac2Lo6zVk2tByy094eWRWJJXpJ4Wb1F
         f/2NFYHY2alS2sPuzk93j+5J1MrDuZEPS6R4ryVl1KTZv5i0XYCTnXoReUJZhqOE46iu
         HuUxxWuoNk+JoLnzijzijmce0rQczIV0x4RKk3djtkzzsaY0Y1pCfmNBeXSlkM0lfYjk
         bXZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766178216; x=1766783016;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sDol7ZL5pMxlrFyjoG1D6L9Tb1hh4ZghEnzrWlUr1yY=;
        b=UO44KVFI4OkLkZTrOR3eeCMHcJul4WYLNWGci8l+/WDtNLK6Mv3B6t1W0rWn13bV+z
         zVdsIjC2aRVPhqwMGDcfsr0ctQ6UVTgtCZ/lXK8+yFbaSztD6V4Pj+hNg8sDAYg7jKZS
         xeSwn6jwxzZ9WVLSOQ17p1bm3p8L8qWDmu4HwABdtsYfPZEOtL67ObctKi4KV1tGjOu3
         5CBmifx1XCVVvueTfIB4cO7HKoK+xxv3Um4yQTXL7cvs8+gUoXNLTUspUslfDULnxGkf
         k2Moj58X0b8e+BBqt3vEwFDaurBOLsD+L21/k+XVkZygGgZAvsRZhXox/nqVIv4RSsHV
         XqxQ==
X-Forwarded-Encrypted: i=2; AJvYcCVtiLyjK7717BmtNKbEmOhgOZ2wrtPxX/EP/9oSGBPZdIqRyODTocw1JHRFccymxrl1G3H6Qg==@lfdr.de
X-Gm-Message-State: AOJu0YxWF5TpTOfrWbdQLi4bGm5G7VsxnUDbv36arGnOMkyIyZfLKKg8
	Q6rra2V7N8tlfwd7jX7GWHuHz54c+R31UeyMys2RxJMWBe6+nQGGlipe
X-Google-Smtp-Source: AGHT+IFWtrUphui+mjBDaGEyPRhTnqCf7WD9fHdw4Ez4sQCMo2rvKiT6TBUzpRBtjGgYxpHa5pDQ2Q==
X-Received: by 2002:a17:90b:3f90:b0:340:bc27:97bd with SMTP id 98e67ed59e1d1-34e92129212mr3247516a91.9.1766178215957;
        Fri, 19 Dec 2025 13:03:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWbqS/H9xpJgthKon0/Hw1xl0b3ZVsv6XC5B/lxe671CPw=="
Received: by 2002:a17:90b:4c90:b0:330:4949:15b5 with SMTP id
 98e67ed59e1d1-34abcc5d730ls8742457a91.1.-pod-prod-07-us; Fri, 19 Dec 2025
 13:03:34 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUzkapIP2SA7UAgrgKyOThSnrvdUa60d5EV64PCdaxIqVYLH7EU1LxhBCAWRsv1HxjhyTShZdrRW5w=@googlegroups.com
X-Received: by 2002:a17:90b:3c4e:b0:340:c60b:f362 with SMTP id 98e67ed59e1d1-34e921131a2mr3565716a91.6.1766178214332;
        Fri, 19 Dec 2025 13:03:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766178214; cv=none;
        d=google.com; s=arc-20240605;
        b=IxXJR2fI8eOiejtZ11Hz8/EG1Bb2lOOrZTUjF+8Sv0uaTFoisSz++FCYErQDLXzI6S
         I9GJIBq54lQOEFXrYWBvBY30Nbiwm4XWDKeWSPSpVNySNRwJByOci5788EEu8RVH/iM2
         320rY2PO37o/rKcCLy57fYTSDd06Io7FTwdUXKg5PkXWyTpQJsUp4A3d5VAZeDMqDXo5
         K3eazvWpfboTOXXAn50GzvUOdOJTILn2Wzc/n8ye7pAE4UFitOfjZVMBuTozbqdCUNAK
         CI37JegMgwegLpzMrpBPGzVnxxnGFRgK3zTg8jaE+YdXZy9uYrNKu+CINMMXBfj+c+4k
         KTsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=de8pCxnipY54b0+yxIRceTprHyPFDweXvtkEVQB+6ZQ=;
        fh=lCqg5zUYdZpha6TRAA3My84nmcDeVmttWMIeUBwP0fU=;
        b=BiSywhzKOdu6WsHNUNoH5sFPv0qQzdLX8dvIXkQHUbmSzdHCobETJOZYnAvd1j6HS9
         unvOWH/hchfmKjj7iEkpzeB5m4o3Eub9d1wgYAbZgy39pwjsizdmwyyo9YX5jzBgCj4Q
         gL77Zqz5Z248RsC8xNnMCFckDBR+RaW8/EpHXujsT4EYX6l8iLhSY2LHLmb3nAfn+9jd
         +IbGLPhl7dp8SVa9GqQzu9/RVpW9Zm0MCaH9cS8QFitFhfCbS3fcMmQcBh2KGGnZmrQP
         pKbkG401PDJEehzzE2QK8iEtsd0As/AQzmzmYMX1UC9G9v68HEG0VPdTdWdjsGDXj2FF
         QSCA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ysqALRoN;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x536.google.com (mail-pg1-x536.google.com. [2607:f8b0:4864:20::536])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-7ff7d2d401csi108752b3a.8.2025.12.19.13.03.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 13:03:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as permitted sender) client-ip=2607:f8b0:4864:20::536;
Received: by mail-pg1-x536.google.com with SMTP id 41be03b00d2f7-c0ec27cad8cso1323962a12.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 13:03:34 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWOM1IIAToM6nQna3dLhY5GIR3I6XPjNAbd8qcO8MQQoIJzXPYJpugFAMOp+RIHHOpmP7IsqC8xPE0=@googlegroups.com
X-Gm-Gg: AY/fxX7FdZ9tz8djb9/27MPW0PLKGyFu2fptJJPe8ooV5joVHQy/yFKVRBnBPsF0tRT
	+zga78FMvytStwrW+EzeIoAFoP5RX3e85EtQX8fUaJ4o7Ua663BmxWHMIznyk65hBwzAw1uqdoG
	WEICy05mlYcapDr/7gDSF5s/Ir6r/mXgOkrOkr6TTmNH6e1Lnvs1Q4wrXdVJFtakr74boHxr8/f
	0NT7KmAlveCwOSsBxQC3XFxL9/HvJWcupyirU54rJH9Eoj/8zpq2+lbRw3dZp/KUfZVv6Hw/c6d
	LywP5mDcjwaIZECMpNVd0jO+FB0=
X-Received: by 2002:a05:7022:150d:b0:11c:e661:2590 with SMTP id
 a92af1059eb24-121722ba459mr3928518c88.20.1766178213442; Fri, 19 Dec 2025
 13:03:33 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-9-elver@google.com>
 <17723ae6-9611-4731-905c-60dab9fb7102@acm.org>
In-Reply-To: <17723ae6-9611-4731-905c-60dab9fb7102@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Dec 2025 22:02:57 +0100
X-Gm-Features: AQt7F2r1zeH05SJ6k_ASDq36JbXz12zcm_odE6qCh7vpVVaB3K5VKsjzaangmPo
Message-ID: <CANpmjNO0B_BBse12kAobCRBK0D2pKkSu7pKa5LQAbdzBZa2xcw@mail.gmail.com>
Subject: Re: [PATCH v5 08/36] locking/rwlock, spinlock: Support Clang's
 context analysis
To: Bart Van Assche <bvanassche@acm.org>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=ysqALRoN;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::536 as
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

On Fri, 19 Dec 2025 at 21:26, Bart Van Assche <bvanassche@acm.org> wrote:
> On 12/19/25 7:39 AM, Marco Elver wrote:
> > - extern void do_raw_read_lock(rwlock_t *lock) __acquires(lock);
> > + extern void do_raw_read_lock(rwlock_t *lock) __acquires_shared(lock);
>
> Given the "one change per patch" rule, shouldn't the annotation fixes
> for rwlock operations be moved into a separate patch?
>
> > -typedef struct {
> > +context_lock_struct(rwlock) {
> >       arch_rwlock_t raw_lock;
> >   #ifdef CONFIG_DEBUG_SPINLOCK
> >       unsigned int magic, owner_cpu;
> > @@ -31,7 +31,8 @@ typedef struct {
> >   #ifdef CONFIG_DEBUG_LOCK_ALLOC
> >       struct lockdep_map dep_map;
> >   #endif
> > -} rwlock_t;
> > +};
> > +typedef struct rwlock rwlock_t;
>
> This change introduces a new globally visible "struct rwlock". Although
> I haven't found any existing "struct rwlock" definitions, maybe it's a
> good idea to use a more unique name instead.

This doesn't actually introduce a new globally visible "struct
rwlock", it's already the case before.
An inlined struct definition in a typedef is available by its struct
name, so this is not introducing a new name
(https://godbolt.org/z/Y1jf66e1M).

> > diff --git a/include/linux/spinlock_api_up.h b/include/linux/spinlock_api_up.h
> > index 819aeba1c87e..018f5aabc1be 100644
> > --- a/include/linux/spinlock_api_up.h
> > +++ b/include/linux/spinlock_api_up.h
> > @@ -24,68 +24,77 @@
> >    * flags straight, to suppress compiler warnings of unused lock
> >    * variables, and to add the proper checker annotations:
> >    */
> > -#define ___LOCK(lock) \
> > -  do { __acquire(lock); (void)(lock); } while (0)
> > +#define ___LOCK_void(lock) \
> > +  do { (void)(lock); } while (0)
>
> Instead of introducing a new macro ___LOCK_void(), please expand this
> macro where it is used ((void)(lock)). I think this will make the code
> in this header file easier to read.

If I recall right, we needed this to generalize __LOCK(),
__LOCK_IRQ(), etc. which do preempt_disable(), local_irq_disable() in
the right way, but then need to make sure we call the right
acquire/release helper, which require different cases depending on the
lock kind. Obviously we could just expand all the macros below, but
the current pattern tried to not rewrite this altogether.

There's probably a way this can all be simplified for UP, but maybe a
separate patch. I'd leave it to the locking maintainers which way they
prefer to go.

>     > -#define __LOCK(lock) \
> > -  do { preempt_disable(); ___LOCK(lock); } while (0)
> > +#define ___LOCK_(lock) \
> > +  do { __acquire(lock); ___LOCK_void(lock); } while (0)
>
> Is the macro ___LOCK_() used anywhere? If not, can it be left out?

Yes, it's the default case if __VA_ARGS__ is empty.

> > -#define __LOCK_BH(lock) \
> > -  do { __local_bh_disable_ip(_THIS_IP_, SOFTIRQ_LOCK_OFFSET); ___LOCK(lock); } while (0)
> > +#define ___LOCK_shared(lock) \
> > +  do { __acquire_shared(lock); ___LOCK_void(lock); } while (0)
>
> The introduction of the new macros in this header file make the changes
> hard to follow. Please consider splitting the changes for this header
> file as follows:
> * A first patch that splits ___LOCK() into ___LOCK_exclusive() and
>    ___LOCK_shared().
> * A second patch with the thread-safety annotation changes
>    (__acquire() -> __acquire_shared()).

I've wrangled with this maze of interdependent macros and definitions
for days (though that was earlier in the year), believe me when I say
I tried to split it up. I think the commit message hints at this:

> Add support for Clang's context analysis for raw_spinlock_t,
> spinlock_t, and rwlock. This wholesale conversion is required because
> all three of them are interdependent.

It's like a carefully crafted house of cards: you take one away, the
whole thing breaks apart. If I recall correctly, the main problem was
that as soon as you make one of these a context lock type, and because
they are all interdependent, the compiler will just complain endlessly
about either wrong attributes or incorrectly acquired/released locks
until they are all precisely in the way you see them here.

> >   /* Non PREEMPT_RT kernels map spinlock to raw_spinlock */
> > -typedef struct spinlock {
> > +context_lock_struct(spinlock) {
> >       union {
> >               struct raw_spinlock rlock;
> >
> > @@ -26,7 +26,8 @@ typedef struct spinlock {
> >               };
> >   #endif
> >       };
> > -} spinlock_t;
> > +};
> > +typedef struct spinlock spinlock_t;
>
> Also here, a new global struct name is introduced (spinlock). Maybe the
> name of this new struct should be made more unique?

As above.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0B_BBse12kAobCRBK0D2pKkSu7pKa5LQAbdzBZa2xcw%40mail.gmail.com.
