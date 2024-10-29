Return-Path: <kasan-dev+bncBDBK55H2UQKRBROOQO4QMGQEX6CZXTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 6485A9B4B29
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 14:46:47 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id 4fb4d7f45d1cf-5c943824429sf3546528a12.1
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Oct 2024 06:46:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1730209607; cv=pass;
        d=google.com; s=arc-20240605;
        b=Hhl6/DVOjTjDP4fBN1ybZjEfSnbW9ld2vnxVXQpTmNZRmkRYqMYks1W/I54dQ9xnIK
         Sg8UQ8pY0XEMTXfThcdCDDANHgCA458gB48L7VShrQnKyTDP77k4pEe8am34ooB02BD8
         cjm182gnqJVylqYdDdiy3hsYRl0CkiBjx1b9xd0X7X0JlK3iW2b8VT668ZUDWHXM2ZdW
         ahZH4u2QnlAg36FomKgLc+ws/oKAkUqZY4fphvJK5iGaDBc0m2+evVB90nlmLtKbxMSv
         5BOqTsfGTix/A/f0MHlvgNYS/AuVpA85CpLHPkLCVigdtI8w0m48Tz9FV+TmI8YLkfLc
         DdQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kL06M2EHdt2iQj9Tvb6kVcqr4pmUcg4623NdjHu1ruk=;
        fh=0XH0MplXRwLqLsYWaPOWH4Hn1okx+7+r6aDtFrsGEN8=;
        b=Fl/4zBLU1cZrbnWmJDwP9nVe0RUzA1+WPplMlvzvnhSYMWDGvm25P2oDWEWqHUSoEx
         31I4oCrqnQ1L+d7lJJ8x4KEPl5ZUuaLChsHxxnGVgewkE4KPapHJps+qW9AakCBW862b
         pH/fb2s/l7pFiNP3FyynRuWA3uVmPUPoA6EuJPcjVeWEEm6HcyLR5/crOhXqCjxQHJhI
         LYH+eOdbA5zDc8KFBbVBD/JRlLkiafU8w5XxQBnrcBgs65Bzg8pN+45gkv0rJTBAYISL
         uA83qPewRlJhPDDCMkNk+1mhSWJ10ASCtYgc+3Ye3eOlwztCGcw0KijT7LYuBaclQYgr
         o0aQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="N0q/XtCe";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1730209607; x=1730814407; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kL06M2EHdt2iQj9Tvb6kVcqr4pmUcg4623NdjHu1ruk=;
        b=LEhi4YT/4YFAyQb3znqfBPiN5ziLuRcvIgAfzQcuXVqa4j/qW5UK8G34oDHShn/qLW
         U90Xp7NA3kayT8nOL/OBaTSKB6/dGJUmVPbgkEQTFauNgUKAHwBSjxnWycCbb4Bb8FlO
         xlIgdLclPrFcl5H2p+VJtTilXn0anwmE3zZTUUC6dM5Sqf9tnS3A/efiwjOeo/PzOKNo
         UBtmVZJj+K9rSzxdY4ouW3qW7LUCQwp9knwrMmFKVH+wEpd9kNsIwlnR8xKbLzQw3MXi
         BQyIYzz3SQ3tzqAyBISzTSE0ei+B6+gF3Di/oVXYbd1HByr8xpuCK6ZTSZo2qmmJn/RG
         ttIw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1730209607; x=1730814407;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=kL06M2EHdt2iQj9Tvb6kVcqr4pmUcg4623NdjHu1ruk=;
        b=udXFTQtvXA+hwDLBLvF7TKrZDCAMq6NgRhIN+nfAvBA7Y1ukFk+W8R2MmYL4WV5N7s
         X+NeCJbtbrD95raRVP0T26T+RChYnYkjwzKonEmEji67TgYFydNahZH5fHJPicLePk7+
         6ifvoA49dmpuMRxc7TArSqRgwHOnIsD+SgBwrqU5wwLLmNLYY0mcYf1c1OwGvRzI/cKy
         RBwGAaNtCZQx2B/uH32vKUnB4UfVRgcg6AX7zHP3LC5xepMHnwMBm/PruKVw3i9T9GMC
         21EWqhJbnuiCDOooWAMEmd7Xqd5ZRG1PW21O++t0UKCCDlvaB9/YqWYy5jBaDVcCOhWS
         JNOg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU8VBRZpBh1C1ntYzpPvY+Xb6FAbOsdljGLpCvFHX9eZTBLasfzYUU71Jt0Xt4FLoZuFZEhxA==@lfdr.de
X-Gm-Message-State: AOJu0YxGgT/7PYRDmc61N98l9TZdEtZgJipv0jfFk6wfqxcT1WbXVaFl
	4llPUFahNshRvzBsDtmqoCnkOVUuO+xsq9cAqAqQx1AsR/8B2Dgw
X-Google-Smtp-Source: AGHT+IEt8ci6X8Tug5qGkGnqs8m1gHeOFO5bWL0CuUbwBi1lMokUENsxxdV4MJAtBwwLQu1dVy1R6w==
X-Received: by 2002:a05:6402:2350:b0:5c9:8705:ea9c with SMTP id 4fb4d7f45d1cf-5cbbf8e176cmr8993858a12.19.1730209606070;
        Tue, 29 Oct 2024 06:46:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:520d:b0:5c8:acf3:12a7 with SMTP id
 4fb4d7f45d1cf-5cb99a0a140ls834135a12.2.-pod-prod-09-eu; Tue, 29 Oct 2024
 06:46:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVkVPbWo4szlroyWrQyaV+MwJHtDpn5zJBKGBSGAlVIRfnMQ1ti6jx3Wy35xRkY+r3jJkRXFi3xA1o=@googlegroups.com
X-Received: by 2002:a17:907:7e8e:b0:a99:e939:d69e with SMTP id a640c23a62f3a-a9de61d1a8cmr900597666b.51.1730209603585;
        Tue, 29 Oct 2024 06:46:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1730209603; cv=none;
        d=google.com; s=arc-20240605;
        b=bSYErHezAGE5kOgt+A42fdF/gNDfn1mvQRw9jB9uPnicDZAVyeYIRu/cBRRT6wIEtQ
         907G8lhoLsJqUxnyHIfbwp2fNnJOtDNTDjyY+kZoOPs1K2v1Yem+8tULjcP/9Xg7FF8T
         +dGHSBIS2WlvAIKh5EjGn+c659JjWIAAkvEGHE9ngpQKdH3ABz04DuMZr/VEPRieHCkj
         pTEBjAbUPOVlY/ifWdw2ipkoN3hGIFvyxnXUhzqD7VwqJjFvzHSFE/3OElG9iHKTJcWy
         UlTXvdPcIMMcBnI18pgcJQJaeHZ2CW+VBeLNImCmYuEmvGCPYk7lp62uQvaQt5P+ziHI
         wmNQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=z8SicmJPe91V7nwH+BPJtaqFkv7A2APH/euLs/x+oZI=;
        fh=rsYLeNn3EhqnY/ERv90DXt1NYQkHGuhFKomDG1eXtr4=;
        b=RN2m8tfQPHusc2efPf2vPDJXZtexAI86X0X2rTQIOp3ea5JmnDSaNu85kHmOxW1hw9
         ZtximEywPINwrI32fxr2osvmUWYCrunWM0ab5Zpam9GiU5Ik1s57B244ROkxW67Dpfu2
         PpjY3lSo3Hsz5tIt3DDlw/NmbVcqT4kfXeoo8jRezMusxjxuckd5nipqeUPPriVKSp3B
         h5qCID3diVMqqKskPxKUAC6KkPgDZXwsWHw1Tq40GQdjnigVxvfLsTWtguROB9C6fhSi
         0Q+cU2OcHU2Fwp3fjE66SHsoBivU8SHjzn3sQUoA6ZpuHuUDBCTTay7pRDNf8VPCn6tV
         CgPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=desiato.20200630 header.b="N0q/XtCe";
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from desiato.infradead.org (desiato.infradead.org. [2001:8b0:10b:1:d65d:64ff:fe57:4e05])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-a9afceea51asi18747566b.0.2024.10.29.06.46.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Oct 2024 06:46:43 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1:d65d:64ff:fe57:4e05;
Received: from j130084.upc-j.chello.nl ([24.132.130.84] helo=noisy.programming.kicks-ass.net)
	by desiato.infradead.org with esmtpsa (Exim 4.98 #2 (Red Hat Linux))
	id 1t5mYU-00000009uRU-1Tym;
	Tue, 29 Oct 2024 13:46:42 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 01DB830073F; Tue, 29 Oct 2024 14:46:42 +0100 (CET)
Date: Tue, 29 Oct 2024 14:46:41 +0100
From: Peter Zijlstra <peterz@infradead.org>
To: Marco Elver <elver@google.com>
Cc: Ingo Molnar <mingo@redhat.com>, Will Deacon <will@kernel.org>,
	Waiman Long <longman@redhat.com>, Boqun Feng <boqun.feng@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Mark Rutland <mark.rutland@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Alexander Potapenko <glider@google.com>
Subject: Re: [PATCH] kcsan, seqlock: Support seqcount_latch_t
Message-ID: <20241029134641.GR9767@noisy.programming.kicks-ass.net>
References: <20241029083658.1096492-1-elver@google.com>
 <20241029114937.GT14555@noisy.programming.kicks-ass.net>
 <CANpmjNPyXGRTWHhycVuEXdDfe7MoN19MeztdQaSOJkzqhCD69Q@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPyXGRTWHhycVuEXdDfe7MoN19MeztdQaSOJkzqhCD69Q@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=desiato.20200630 header.b="N0q/XtCe";
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Tue, Oct 29, 2024 at 02:05:38PM +0100, Marco Elver wrote:
> On Tue, 29 Oct 2024 at 12:49, Peter Zijlstra <peterz@infradead.org> wrote:
> >
> > On Tue, Oct 29, 2024 at 09:36:29AM +0100, Marco Elver wrote:
> > > Reviewing current raw_write_seqcount_latch() callers, the most common
> > > patterns involve only few memory accesses, either a single plain C
> > > assignment, or memcpy;
> >
> > Then I assume you've encountered latch_tree_{insert,erase}() in your
> > travels, right?
> 
> Oops. That once certainly exceeds the "8 memory accesses".
> 
> > Also, I note that update_clock_read_data() seems to do things
> > 'backwards' and will completely elide your proposed annotation.
> 
> Hmm, for the first access, yes. This particular oddity could be
> "fixed" by surrounding the accesses by
> kcsan_nestable_atomic_begin/end(). I don't know if it warrants adding
> a raw_write_seqcount_latch_begin().
> 
> Preferences?

I *think* it is doable to flip it around to the 'normal' order, but
given I've been near cross-eyed with a head-ache these past two days,
I'm not going to attempt a patch for you, since I'm bound to get it
wrong :/

> > > therefore, the value of 8 memory accesses after
> > > raw_write_seqcount_latch() is chosen to (a) avoid most false positives,
> > > and (b) avoid excessive number of false negatives (due to inadvertently
> > > declaring most accesses in the proximity of update_fast_timekeeper() as
> > > "atomic").
> >
> > The above latch'ed RB-trees can certainly exceed this magical number 8.
> >
> > > Reported-by: Alexander Potapenko <glider@google.com>
> > > Tested-by: Alexander Potapenko <glider@google.com>
> > > Fixes: 88ecd153be95 ("seqlock, kcsan: Add annotations for KCSAN")
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > >  include/linux/seqlock.h | 9 +++++++++
> > >  1 file changed, 9 insertions(+)
> > >
> > > diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
> > > index fffeb754880f..e24cf144276e 100644
> > > --- a/include/linux/seqlock.h
> > > +++ b/include/linux/seqlock.h
> > > @@ -614,6 +614,7 @@ typedef struct {
> > >   */
> > >  static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *s)
> > >  {
> > > +     kcsan_atomic_next(KCSAN_SEQLOCK_REGION_MAX);
> > >       /*
> > >        * Pairs with the first smp_wmb() in raw_write_seqcount_latch().
> > >        * Due to the dependent load, a full smp_rmb() is not needed.
> > > @@ -631,6 +632,7 @@ static __always_inline unsigned raw_read_seqcount_latch(const seqcount_latch_t *
> > >  static __always_inline int
> > >  raw_read_seqcount_latch_retry(const seqcount_latch_t *s, unsigned start)
> > >  {
> > > +     kcsan_atomic_next(0);
> > >       smp_rmb();
> > >       return unlikely(READ_ONCE(s->seqcount.sequence) != start);
> > >  }
> > > @@ -721,6 +723,13 @@ static inline void raw_write_seqcount_latch(seqcount_latch_t *s)
> > >       smp_wmb();      /* prior stores before incrementing "sequence" */
> > >       s->seqcount.sequence++;
> > >       smp_wmb();      /* increment "sequence" before following stores */
> > > +
> > > +     /*
> > > +      * Latch writers do not have a well-defined critical section, but to
> > > +      * avoid most false positives, at the cost of false negatives, assume
> > > +      * the next few memory accesses belong to the latch writer.
> > > +      */
> > > +     kcsan_atomic_next(8);
> > >  }
> >
> > Given there are so very few latch users, would it make sense to
> > introduce a raw_write_seqcount_latch_end() callback that does
> > kcsan_atomic_next(0) ? -- or something along those lines? Then you won't
> > have to assume such a small number.
> 
> That's something I considered, but thought I'd try the unintrusive
> version first. But since you proposed it here, I'd much prefer that,
> too. ;-)
> Let me try that.
> 
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20241029134641.GR9767%40noisy.programming.kicks-ass.net.
