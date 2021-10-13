Return-Path: <kasan-dev+bncBDL2TKUCPQIOLOE4RMDBUBFLC4NSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A8D8642C807
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 19:50:30 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id bi16-20020a0565120e9000b003fd56ef5a94sf2572466lfb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Oct 2021 10:50:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1634147430; cv=pass;
        d=google.com; s=arc-20160816;
        b=NWSPNrWwM+wMWLe9GKYgzOb87XMU7a8zTo4Lr+y4qjN8FyZeIFmCHFBo1s+vkGwyF9
         dKeAQxqKhgMXckZuawtVoagvoRm3XslRr5DwM66Vfow2u4EzBtn5IqppF/1kVJ8meVVi
         dnOtCJSVKTR4sLcgQW9suCtY4iGM2YIDaTDFOGjYPHBbcZ28PnKT2SfLFCI/k5RqQa7j
         R09+UJLul8wou07/beAVbvDKwxp1sVFAlppVmrKIN0+QnqRMtC7hebA8R3JIcj0xUlVw
         cZaBEyAWK6CQV2qqV62yXuTit2anNZD9BGoR7bia+NeVEgoLaBWG619h6LK2aCwS8IyG
         cYzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=F3+2s2gzRDCCQCUAsxsUWz32yfo6Dj5zVRabi9yG57Q=;
        b=TVM7XxCZqB4Qyf1z4IG/U+AsIElOYb0kgEtxCiW70uoWoa3GCRCWWXcK1kkgRrd/rf
         umEBHt/HWILqwrdkJ+HHIdoE014FQm16zJdWpW7kZmvGlXiT8fW/eQmkQXli7lZBwwe/
         pjFO/yFlYsahYk/7zQpXxZmI9eN8K3RcvWsXTvpkjX1LIeU+Ya+KkfbQkzgnBFb5AhIp
         qCaVIqfWbiMwvNz+L+Xnb5lAgAUbAtY47RikQz6W1i+etCnlAsPQFttulO6ZEcqRLLTG
         jv+RcWpbgD67kCudg7tvWjuXmGoaRgtj8pzW8ioyuL/N5qWW92EoI4fc19SagEcsMywO
         LT0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qeaOU5WP;
       spf=pass (google.com: domain of wedsonaf@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=wedsonaf@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=F3+2s2gzRDCCQCUAsxsUWz32yfo6Dj5zVRabi9yG57Q=;
        b=VRz55Nu46tkQomajTDg3+5rg1vw0RYwpPRFeGhaaY9QQ3tWnvqcpyj0h8zsys/uAC/
         TFRtWt9iQXocCT3iykJduuLFZtPK2UE65EwnxIvwLhLpEBi8nkbA31yJCDoo3jI02jaS
         CzutY0hRsqFwolm3wowD3S/AVO1DQ/memPGGM8Icb7okZ0w1Ym2ou7TYWQdzV9j4d/1g
         EuAF21USnKFIGyJagD5dbqbrQQTjqergJDx94WF7vW/qJd+h3JNgNLVOrnnD4Vcw0uyR
         8pcDGFBuVEqX+WZUUm+QaL8VV3iyAbKfPKaYMfn8orwL22ULXoU8cpfEAXgqRzw1a6Nk
         1Afg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=F3+2s2gzRDCCQCUAsxsUWz32yfo6Dj5zVRabi9yG57Q=;
        b=uBwIcEKjnTeBXGkFtrK4sU5leIs8y4/PZIY0ESOtM2z1SsleWaOZxmulWm19izqFmp
         thHYnucF2mu+sqVfyhr/RkOt3qXjaCy6sj0qcrFyDJnSNGRv7gwvQx2yeClfVJ0PPNUf
         q+hJV+SZvafhcw5BPWY7K8FXszHpGxdSJ2yU7a/h0vkmYLrCBUlbXIH3ZKg3h1Z6x+KX
         yg8z3GyPgaKrHcehyedwiU4Ur0pms3elh61IOLGg1W2ObGdWbwrauQxSjvgup9zPcmWB
         dgqO6Ocoiy5Pa/0nf5rRg4NwEtvf48lxq2h/DiUDaTmSTV7X09tzY8c5vWTgDzK6Zgnt
         E8gQ==
X-Gm-Message-State: AOAM532UtzJ8XurlNMKWc5Z/3mFW+EH7RjuY3dapKeuzH0nnNhIAJsFJ
	iffor4SwrxmHqancSCwu344=
X-Google-Smtp-Source: ABdhPJycsKam8pj0QXLoe0VzsbW9rolQj36VzTw5YaPiBSCrI00gZ2YqaFesEOi/K49jd6IEg/iSoA==
X-Received: by 2002:a2e:a54a:: with SMTP id e10mr818141ljn.274.1634147430226;
        Wed, 13 Oct 2021 10:50:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:760d:: with SMTP id r13ls594978ljc.0.gmail; Wed, 13 Oct
 2021 10:50:29 -0700 (PDT)
X-Received: by 2002:a2e:88ce:: with SMTP id a14mr820690ljk.396.1634147429067;
        Wed, 13 Oct 2021 10:50:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1634147429; cv=none;
        d=google.com; s=arc-20160816;
        b=A05gsxr5ZYGjXViWaZE0l7+dZw0Pxq2rh6vhhKMt3GF7nGH0fUtmMTPLplJc42rInf
         hVU/ICX2i7kwB4miaXi2GIfwBod1gwL4dL+ymtHTeaaIEuxdLjvuT3/m7eLfmJYV2WZz
         T9VWlFEDUMhAjZ/ECEa9wTTMBrO7eCezOLGcCueMZoKtTV7r3YjE0vZQ8lInIIe7Dfb4
         g7RYDIZ5wqRBd7KwjNkfw7cMqohoFeLcOi1d8e/Joi68Eq8VdRgnkaacQSdwtnyLpjTl
         BAkMgIq46whzmVl1jyqVXfBig1OmNX3MijKH7nR2+dspTLaRjTNZ+Q2jqYTQq/VkHZ0k
         C84w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=52v6GxGe7wvzewDWq67IcYS7Vxmb6Nbwq6eBE/FcbdE=;
        b=BHXTg/ShJUY6gexEODcnlYJsUi7f0pIYSyynMQsaMeW5+JKFP7vq0QMlFix07DJ22D
         Pxb9eo93censz0O09hkpCQsxhehFZeA1PI0NQieWNEj4jMIF0QQg7y1USIROhCF1I08q
         rd37mJp4EO5h4UKlZTIVzi1ekUV1bynwFV6324FsOfSbV9f6kwtWt2SFODzPuiCccIk1
         yAF53RxracS5N6s2CBfjVe+AlXtJUqO2ZEnRLF3M22HZ38FDusMawzE57ZE6MqNd9eXv
         iV/A472OyCHpj0iNME+e1AY9jTgFB6avYzCTMVv2RXMQ29kEVNxzAG88qCJXGUkMTnmV
         Ymgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=qeaOU5WP;
       spf=pass (google.com: domain of wedsonaf@google.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=wedsonaf@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id d19si13086lfa.0.2021.10.13.10.50.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Oct 2021 10:50:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of wedsonaf@google.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id u18so11090327wrg.5
        for <kasan-dev@googlegroups.com>; Wed, 13 Oct 2021 10:50:29 -0700 (PDT)
X-Received: by 2002:a1c:14b:: with SMTP id 72mr14694962wmb.188.1634147428469;
        Wed, 13 Oct 2021 10:50:28 -0700 (PDT)
Received: from google.com ([2a00:79e0:d:209:c85c:bd9:50ac:bc30])
        by smtp.gmail.com with ESMTPSA id z133sm6243363wmc.45.2021.10.13.10.50.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Oct 2021 10:50:28 -0700 (PDT)
Date: Wed, 13 Oct 2021 18:50:24 +0100
From: "'Wedson Almeida Filho' via kasan-dev" <kasan-dev@googlegroups.com>
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>,
	Gary Guo <gary@garyguo.net>, Marco Elver <elver@google.com>,
	Boqun Feng <boqun.feng@gmail.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	rust-for-linux <rust-for-linux@vger.kernel.org>
Subject: Re: Can the Kernel Concurrency Sanitizer Own Rust Code?
Message-ID: <YWccYPLUOH7t9JtB@google.com>
References: <20211008005958.0000125d@garyguo.net>
 <20211008174048.GS880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mOWV2SiF24E=NMB-zc2mK_UFH=CvDFxN+vdtyjy-Wm0A@mail.gmail.com>
 <20211009000838.GV880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72nGX6bgwDuVMX3nGUfs_UQB1ikOBHE-Q74nEaJ2Stx_2w@mail.gmail.com>
 <20211009235906.GY880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72mj9x7a4mfzJo+pY8HOXAshqfhyEJMjs7F+qS-rJaaCeA@mail.gmail.com>
 <20211011190104.GI880162@paulmck-ThinkPad-P17-Gen-1>
 <CANiq72ny0RCnO1+E_wBgx0C6NCaMfv82rvkLVuwmW8Y+7Kii0Q@mail.gmail.com>
 <20211013160707.GR880162@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211013160707.GR880162@paulmck-ThinkPad-P17-Gen-1>
X-Original-Sender: wedsonaf@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=qeaOU5WP;       spf=pass
 (google.com: domain of wedsonaf@google.com designates 2a00:1450:4864:20::431
 as permitted sender) smtp.mailfrom=wedsonaf@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Wedson Almeida Filho <wedsonaf@google.com>
Reply-To: Wedson Almeida Filho <wedsonaf@google.com>
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

On Wed, Oct 13, 2021 at 09:07:07AM -0700, Paul E. McKenney wrote:
> On Wed, Oct 13, 2021 at 01:48:13PM +0200, Miguel Ojeda wrote:
> > On Mon, Oct 11, 2021 at 9:01 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> > >
> > > The main issue I was calling out was not justifying Rust, but rather
> > > making sure that the exact same build could be reproduced a decade later.
> > 
> > Yes, but that is quite trivial compared to other issues I was
> > mentioning like adapting and requalifying a testing tool. For
> > instance, if you already had a team maintaining the configuration
> > management (i.e. the versions etc.), adding one more tool is not a big
> > deal.
> 
> OK, close enough to fair enough.  ;-)
> 
> > > There are things that concurrent software would like to do that are
> > > made quite inconvenient due to large numbers of existing optimizations
> > > in the various compiler backends.  Yes, we have workarounds.  But I
> > > do not see how Rust is going to help with these inconveniences.
> > 
> > Sure, but C UB is unrelated to Rust UB. Thus, if you think it would be
> > valuable to be able to express particular algorithms in unsafe Rust,
> > then I would contact the Rust teams to let them know your needs --
> > perhaps we end up with something way better than C for that use case!
> 
> Sequence locks and RCU do seem to be posing some challenges.  I suppose
> this should not be too much of a surprise, given that there are people who
> have been in the Rust community for a long time who do understand both.
> If it were easy, they would have already come up with a solution.

(Hey Paul, I tried posting on your blog series, but I'm having difficulty so I
thought I'd reply here given that we mention seqlocks and RCU here.)

I spent a bit of time thinking about sequence locks and I think I have something
that is workable. (I remind you that we use the C implementation for the
synchronisation primitives). Suppose we had some struct like so:

struct X {
    a: AtomicU32,
    b: AtomicU32,
}

And suppose we have it protected by a sequence lock. If we wanted to return the
sum of the two fields, the code would look like this:

    let v = y.access(|x| {
        let a = x.a.load(Ordering::Relaxed);
	let b = x.b.load(Ordering::Relaxed);
	a + b
    });

It would be expanded to the following machine code in aarch64 (when LTO is
enabled):

  403fd4:       14000002        b       403fdc
  403fd8:       d503203f        yield
  403fdc:       b9400808        ldr     w8, [x0, #8]
  403fe0:       3707ffc8        tbnz    w8, #0, 403fd8
  403fe4:       d50339bf        dmb     ishld
  403fe8:       b9400c09        ldr     w9, [x0, #12]
  403fec:       b940100a        ldr     w10, [x0, #16]
  403ff0:       d50339bf        dmb     ishld
  403ff4:       b940080b        ldr     w11, [x0, #8]
  403ff8:       6b08017f        cmp     w11, w8
  403ffc:       54ffff01        b.ne    403fdc
  404000:       0b090148        add     w8, w10, w9

It is as efficient as the C version, though not as ergonomic. The
.load(Ordering::Relaxed) can of course be improved to something shorter like
.load_relaxed() or even new atomic types  with .load() being relaxed and
.load_ordered(Ordering) for other ordering.

I also have guard- and iterator-based methods for the read path that would look
like this (these can all co-exist if we so choose):

    let v = loop {
        let guard = y.read();
        let a = guard.a.load(Ordering::Relaxed);
        let b = guard.b.load(Ordering::Relaxed);
        if !guard.need_retry() {
            break a + b;
        }
    };

and

    let mut v = 0;
    for x in y {
        let a = x.a.load(Ordering::Relaxed);
	let b = x.b.load(Ordering::Relaxed);
	v = a + b;
    }

The former generates the exact same machine code as above though the latter
generates slightly worse code (it has instructions sequences like "mov w10,
#0x1; tbnz w10, #0, 403ffc" and , "mov w10, wzr; tbnz w10, #0, 403ffc", which
could be optimised but for some reason isn't).

Anyway, on to the write path. We need another primitive to ensure that only one
writer at a time attempts to acquire the sequence lock in write mode. We do this
by taking a guard for this other lock, for example, suppose we want to increment
each of the fields:

    let other_guard = other_lock.lock();
    let guard = y.write(&other_guard);
    guard.a.store(guard.a.load(Ordering::Relaxed) + 1, Ordering::Relaxed);
    guard.b.store(guard.b.load(Ordering::Relaxed) + 1, Ordering::Relaxed);

The part the relates to the sequence lock is compiled to the following:

  404058:       f9400009        ldr     x9, [x0]
  40405c:       eb08013f        cmp     x9, x8
  404060:       54000281        b.ne    4040b0

  404064:       b9400808        ldr     w8, [x0, #8]
  404068:       11000508        add     w8, w8, #0x1
  40406c:       b9000808        str     w8, [x0, #8]
  404070:       d5033abf        dmb     ishst
  404074:       b9400c08        ldr     w8, [x0, #12]
  404078:       11000508        add     w8, w8, #0x1
  40407c:       b9000c08        str     w8, [x0, #12]
  404080:       b9401008        ldr     w8, [x0, #16]
  404084:       11000508        add     w8, w8, #0x1
  404088:       b9001008        str     w8, [x0, #16]
  40408c:       d5033abf        dmb     ishst
  404090:       b9400808        ldr     w8, [x0, #8]
  404094:       11000508        add     w8, w8, #0x1
  404098:       b9000808        str     w8, [x0, #8]

If we ignore the first three instructions momentarily, the rest is as efficient
as C. The reason we need the first three instructions is to ensure that guard
that was passed into the `write` function is a guard to the correct lock. The
lock type already eliminates the vast majority of issues, but a developer could
accidentally lock the wrong lock and use it in the sequence lock, which would be
problematic. So we need this check in Rust that we don't need in C (although the
same mistake could happen in C).

We can provide an 'unsafe' version that doesn't perform this check, then the
onus is on the callers to convince themselves that they have acquired the
correct lock (and they'd be required to use an unsafe block). Then the
performance would be the same as the C version.

Now that I've presented how my proposal looks like from the PoV of a user,
here's its rationale: given that we only want one copy of the data and that
mutable references are always unique in the safe fragment of Rust, we can't (and
don't) return a mutable reference to what's protected by the sequence lock, we
always only allow shared access, even when the sequence lock is acquired in
write mode.

Then how does one change the fields? Interior mutability. In the examples above,
the fields are all atomic, so they can be changed with the `store` method. Any
type that provides interior mutability is suitable here.

If we need to use types with interior mutability, what's the point of the
sequence lock? The point is to allow a consistent view of the fields. In our
example, even though `a` and `b` are atomic, the sequence lock guarantees that
readers will get a consistent view of the values even though writers modify one
at a time.

Lastly, the fact we use a generic `Guard` as proof that a lock is held (for the
write path) means that we don't need to manually implement this for each
different lock we care about; any that implements the `Lock` trait can be used.
This is unlike the C code that uses fragile macros to generate code for
different types of locks (though the scenario is slightly different in that the
C code embeds a lock, which is also something we could do in Rust) -- the Rust
version uses generics, so it is type-checked by the compiler.

RCU pointers can be implemented with a similar technique in that read access is
protected by a 'global' RCU reader lock (and evidence of it being locked is
required to get read access), and writers require another lock to be held. The
only piece that I haven't thought through yet is how to ensure that pointers
that were exposed with RCU 'protection' cannot be freed before the grace period
has elapsed. But this is a discussion for another time.

I'll send out the patches for what I describe above in the next couple of days.

Does any of the above help answer the questions you have about seqlocks in Rust?

Thanks,
-Wedson

> So the trick is to stage things so as to allow people time to work on
> these sorts of issues.
> 
> > In any case, Rust does not necessarily need to help there. What is
> > important is whether Rust helps writing the majority of the kernel
> > code. If we need to call into C or use inline assembly for certain
> > bits -- so be it.
> > 
> > > But to be fair, much again depends on exactly where Rust is to be applied
> > > in the kernel.  If a given Linux-kernel feature is not used where Rust
> > > needs to be applied, then there is no need to solve the corresponding
> > > issues.
> > 
> > Exactly.
> 
> Thank you for bearing with me.
> 
> I will respond to your other email later,.  but the focus on memory
> safety in particular instead of undefined behavior in general does help
> me quite a bit.
> 
> My next step is to create a "TL;DR: Memory-Model Recommendations" post
> that is more specific, with both short-term ("do what is easy") and
> long-term suggestions.
> 
> 							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWccYPLUOH7t9JtB%40google.com.
