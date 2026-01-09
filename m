Return-Path: <kasan-dev+bncBCS4VDMYRUNBBY6GQHFQMGQE2PWFO7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CD895D06CAE
	for <lists+kasan-dev@lfdr.de>; Fri, 09 Jan 2026 03:09:40 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-88a37ca7ffdsf55699036d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Jan 2026 18:09:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767924579; cv=pass;
        d=google.com; s=arc-20240605;
        b=ihJm8Bd7fywxqpshK1hp///EWHxpJ+0eWXHRYbH2Af4Ef5/tPkeB9LACXnOJeoBloW
         pxp/Dp3aInGVdfny5NASDPvgyIm+6k4rufEXW0t/cHhxHoQdHTAczMFdUEkXt949Cpo6
         PdG/FRknPmWMrCH+dAagpSmJboXzMuvuiH3GaDHx05VPTwAnxCGlQherY+Sc68uB3ICc
         OM6uBMfRf87Ab9EKNdX/R4ZPP0aDlISEzBbTvfgcT18xLZ9qv6VEvEhKSKF9yG6XJgnu
         1muh/HYeFFUcoNcvWLY/t8NNW3B11Qy6Q8fEAwCuEbHMZt2Nd9xwbleiDFI2OL2W+2wp
         +Qqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=MXkysPTkCtoUCxmYIM7JekJOdK+Hehg6dKSOxrKQWoY=;
        fh=ceH8K+6JB20//cRGrmmQ/+gdtJZ1hVvhjUgZBu5xHog=;
        b=bWB1tGjwZhk2yn3uQP/JavirI9uLVUxvhMJHhET9g8FzOFRz4gNb9HGZzo9o0ykBX7
         e7OYGgc3YiXSIAt3HczbszZU27MKJo+00pI4RfqMlMrBVBD5ESMGjVpIXh6fv+cwJ4T2
         e6ps8FMOgXckeRLR3ZyxqR1vV5zFjnu8Yl4owxif9ENEhUmDCOJT0FQUo13i/P0u21FS
         BhBl5INJfIPHoh8XQ5vGKJdvO9s0Ex0FhYn/CzNxaQlm6LgiJKvAbBuiF4Osy4Y0ui9d
         Og46w2j+WFEapn+wNxLkxwaHqmB6qsBIq8XbWLyz+PhgsjiMTq5Ei82o9phMnP1gf5sn
         VUdA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ovo2tZCR;
       spf=pass (google.com: domain of srs0=o6/j=7o=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=O6/j=7O=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767924579; x=1768529379; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MXkysPTkCtoUCxmYIM7JekJOdK+Hehg6dKSOxrKQWoY=;
        b=d9qo2Qq7BBdyqGQ5Wj2SEBKsAGVrVynkOFdpkOyYdpM4XBvbe4St+HHWyrn+Cm3ajv
         c8DaOkL/y4ke08kHCRsWDz4vY9qxL6yR423JR7Zo7aSFvG5O4oYsgSGTzpWTosw+ctQ7
         rmvevLssPq7dUmesHdrSyiSXaiC6ESkPEhFmG+h812Dmoj2L2AfrezBnbBLTfub0kkZF
         SqIXt+yKqG/AOhf6o6qrlQHqQPJGdTA3/Mv3ZL/SstZGuAFbPfrTG4PTypwp8Ih7xYcy
         5mLsRsMR5722ss3OVGHAGCCO2YbsMWTelCoycgGCwf2OTxNOl0A8evCDLKcdTRqbBgey
         5U8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767924579; x=1768529379;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:from:to:cc
         :subject:date:message-id:reply-to;
        bh=MXkysPTkCtoUCxmYIM7JekJOdK+Hehg6dKSOxrKQWoY=;
        b=soJ1WI5WGogk/cSe+Y0ysOAM5/HVT0RiiYxRXg0VUkc49rwHblU9V7vQ2mM5fEYjYl
         IiKtMIXsklImN4C3jKMkn+EvMlVGTjmLzTpj8vPa0yrcVmWt6og+crpeMwWZc0TjRvYd
         gCZh2g8JaYW7JX1lTCunskFQxtRkYZGBRO0yQBoLC6XX+1Y0b6eysoWrTLe9lGImev9r
         kGj+pGFGNO3gNfZ3tfLMuP/90AbRqsPpV9tW9jtgQY6fUNjDaHeewhnP1hqeG5rNcyES
         CyV/AecVcMt6SC7l77xYmSCD45ZrzB6XI5vhcNwnpHWLqjd0tLlkTWhOBJHSMn9FSm8l
         MYGA==
X-Forwarded-Encrypted: i=2; AJvYcCWpjpqu1rUY0FJXtkUXwCwzs8ZM8lj8io4H8tmyZqMwnEy+7g2a2SBblA3k3p8KzPz71qB0Gg==@lfdr.de
X-Gm-Message-State: AOJu0Yw9puQGvKgTexsgoa5oVlairLdZK2RtHfmYwG6+RazeE5DSwcUK
	D3NHbWWCefAPW4qlqMcviJlGlDByRNfsmU5S4fWx9eXmgmRG9E0KTIcs
X-Google-Smtp-Source: AGHT+IH+EbbcCvvshnIQfXNitHTo22rFInT34u1CsR4jttE6uMlbarbaWrxhh9F5bfTmLeQaSlDS/g==
X-Received: by 2002:a05:6214:570d:b0:888:7ba5:6b35 with SMTP id 6a1803df08f44-89084197a1amr114876476d6.19.1767924579508;
        Thu, 08 Jan 2026 18:09:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZHoNR0xYglVGcSC01WxYDIcnNxIn+74tGaaUmrGrBL5Q=="
Received: by 2002:a05:6214:212e:b0:888:3ab3:a46f with SMTP id
 6a1803df08f44-89075557aebls64231426d6.0.-pod-prod-08-us; Thu, 08 Jan 2026
 18:09:38 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXvc63+o0UMwC3eI8fGPFNWf8/mEfBUdrmxUHgq7Llw8Wqfl3yZ6L1NQlzclDbQ/3x1If5lxeXPQj8=@googlegroups.com
X-Received: by 2002:a05:6214:3199:b0:890:259c:80ff with SMTP id 6a1803df08f44-89084183bc4mr112168606d6.11.1767924578380;
        Thu, 08 Jan 2026 18:09:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767924578; cv=none;
        d=google.com; s=arc-20240605;
        b=elAuLhB15Bu+GYzlWXafufBDsoEZBPIpm6tlX/Dcwi9/m8UnPrsMQ0L0nWtsPsyh81
         IuVskCOf1RcJZ/0cI/VijagEd2OHKHUGioxPCWOdVQvsqGtDozMhUJo2E9PheaMk3Eaf
         z4TRjudgf+WzxMRDnVX9YiHwKB1HAZyS3+pRnF8LebVuvcHAUySnYIPkX/nbeGCyNiHX
         DOzXubm/QriKOFZUOW+CmfJmXwc5E6B7JCPXJlosDPcrIti++kUodDE8UIVcspxNQbKS
         ifL42wBKtw/FgwOiPZTCa9VO1mfD0vu+KjZNT2KIShPz3bf7nrRxZPUzTYQ1ZTqPoLI0
         5vqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RyyZXYReJ8JTaDe4XBVpIGWKtnPK8oE5Ye9PwPzS6Ck=;
        fh=WNM7B8O9WQm03a+uVrpoKd22xKpnFrXdFN8iGam+sXY=;
        b=LV5Eq0e2v7sR/bXagxQCTQfzo8bCzyaRcGCozUOJ2INe4HYGBj5amQCnZwfRvoSbTL
         lryDIIKPXx3adlOGaKsyqHwx+NL2m3Yqyh+bQmcL5DaQmwwyKj8GTyDTb7593hlRmgS9
         S5Z1epQsAlFUDa61xKNiPzIPR1bKV/VUtxXTGxL37VJSz2RYHJb7IvtnstIwSqaB0jVP
         iuZ+KtudkQgYdlj/emi33WIKor5gGxqJyPhkK4AlNkBJpkURcsPXJIqati+IxYrI3AYd
         ZqPFct4kDibQjVL8j4qMhp1bsf7TgZYnOGWi/T1Iaw2GUjIqhlCjxPX5DPPSECvxmO6q
         IBnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ovo2tZCR;
       spf=pass (google.com: domain of srs0=o6/j=7o=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom="SRS0=O6/j=7O=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-89082ca863dsi1814246d6.4.2026.01.08.18.09.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 08 Jan 2026 18:09:38 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=o6/j=7o=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 4094F43360;
	Fri,  9 Jan 2026 02:09:37 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 0EB2EC116C6;
	Fri,  9 Jan 2026 02:09:37 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 9E3ECCE1690; Thu,  8 Jan 2026 18:09:36 -0800 (PST)
Date: Thu, 8 Jan 2026 18:09:36 -0800
From: "'Paul E. McKenney' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>,
	Andreas Hindborg <a.hindborg@kernel.org>,
	Alice Ryhl <aliceryhl@google.com>, Gary Guo <gary@garyguo.net>,
	Will Deacon <will@kernel.org>,
	Richard Henderson <richard.henderson@linaro.org>,
	Matt Turner <mattst88@gmail.com>,
	Magnus Lindholm <linmag7@gmail.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	=?iso-8859-1?Q?Bj=F6rn?= Roy Baron <bjorn3_gh@protonmail.com>,
	Benno Lossin <lossin@kernel.org>, Trevor Gross <tmgross@umich.edu>,
	Danilo Krummrich <dakr@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	FUJITA Tomonori <fujita.tomonori@gmail.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Lyude Paul <lyude@redhat.com>, Thomas Gleixner <tglx@linutronix.de>,
	Anna-Maria Behnsen <anna-maria@linutronix.de>,
	John Stultz <jstultz@google.com>, Stephen Boyd <sboyd@kernel.org>,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	Christian Brauner <brauner@kernel.org>, Jan Kara <jack@suse.cz>,
	linux-kernel@vger.kernel.org, linux-alpha@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	rust-for-linux@vger.kernel.org, linux-fsdevel@vger.kernel.org,
	kasan-dev@googlegroups.com
Subject: Re: [PATCH 0/5] Add READ_ONCE and WRITE_ONCE to Rust
Message-ID: <b0f3b2a6-e69c-4718-9f05-607b8c02d745@paulmck-laptop>
Reply-To: paulmck@kernel.org
References: <20251231-rwonce-v1-0-702a10b85278@google.com>
 <20251231151216.23446b64.gary@garyguo.net>
 <aVXFk0L-FegoVJpC@google.com>
 <OFUIwAYmy6idQxDq-A3A_s2zDlhfKE9JmkSgcK40K8okU1OE_noL1rN6nUZD03AX6ixo4Xgfhi5C4XLl5RJlfA==@protonmail.internalid>
 <aVXKP8vQ6uAxtazT@tardis-2.local>
 <87fr8ij4le.fsf@t14s.mail-host-address-is-not-set>
 <aV0JkZdrZn97-d7d@tardis-2.local>
 <20260106145622.GB3707837@noisy.programming.kicks-ass.net>
 <7fa2c07e-acf9-4f9a-b056-4d4254ea61e5@paulmck-laptop>
 <CANpmjNPdnuCNTfo=q5VPxAfdvpeAt8DhesQu0jy+9ZpH3DcUnQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPdnuCNTfo=q5VPxAfdvpeAt8DhesQu0jy+9ZpH3DcUnQ@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ovo2tZCR;       spf=pass
 (google.com: domain of srs0=o6/j=7o=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender)
 smtp.mailfrom="SRS0=O6/j=7O=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: "Paul E. McKenney" <paulmck@kernel.org>
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

On Tue, Jan 06, 2026 at 08:28:41PM +0100, Marco Elver wrote:
> On Tue, 6 Jan 2026 at 19:18, 'Paul E. McKenney' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> > On Tue, Jan 06, 2026 at 03:56:22PM +0100, Peter Zijlstra wrote:
> > > On Tue, Jan 06, 2026 at 09:09:37PM +0800, Boqun Feng wrote:
> > >
> > > > Some C code believes a plain write to a properly aligned location is
> > > > atomic (see KCSAN_ASSUME_PLAIN_WRITES_ATOMIC, and no, this doesn't mean
> > > > it's recommended to assume such), and I guess that's the case for
> > > > hrtimer, if it's not much a trouble you can replace the plain write with
> > > > WRITE_ONCE() on C side ;-)
> > >
> > > GCC used to provide this guarantee, some of the older code was written
> > > on that. GCC no longer provides that guarantee (there are known cases
> > > where it breaks and all that) and newer code should not rely on this.
> > >
> > > All such places *SHOULD* be updated to use READ_ONCE/WRITE_ONCE.
> >
> > Agreed!
> >
> > In that vein, any objections to the patch shown below?
> 
> I'd be in favor, as that's what we did in the very initial version of
> KCSAN (we started strict and then loosened things up).
> 
> However, the fallout will be even more perceived "noise", despite
> being legitimate data races. These config knobs were added after much
> discussion in 2019/2020, somewhere around this discussion (I think
> that's the one that spawned KCSAN_REPORT_VALUE_CHANGE_ONLY, can't find
> the source for KCSAN_ASSUME_PLAIN_WRITES_ATOMIC):
> https://lore.kernel.org/all/CAHk-=wgu-QXU83ai4XBnh7JJUo2NBW41XhLWf=7wrydR4=ZP0g@mail.gmail.com/

Fair point!

> While the situation has gotten better since 2020, we still have latent
> data races that need some thought (given papering over things blindly
> with *ONCE is not right either). My recommendation these days is to
> just set CONFIG_KCSAN_STRICT=y for those who care (although I'd wish
> everyone cared the same amount :-)).
> 
> Should you feel the below change is appropriate for 2026, feel free to
> carry it (consider this my Ack).
> 
> However, I wasn't thinking of tightening the screws until the current
> set of known data races has gotten to a manageable amount (say below
> 50)
> https://syzkaller.appspot.com/upstream?manager=ci2-upstream-kcsan-gce
> Then again, on syzbot the config can remain unchanged.

Is there an easy way to map from a report to the SHA-1 that the
corresponding test ran against?  Probably me being blind, but I am not
seeing it.  Though I do very much like the symbolic names in those
stack traces!

							Thanx, Paul

> Thanks,
> -- Marco
> 
> >                                                         Thanx, Paul
> >
> > ------------------------------------------------------------------------
> >
> > diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
> > index 4ce4b0c0109cb..e827e24ab5d42 100644
> > --- a/lib/Kconfig.kcsan
> > +++ b/lib/Kconfig.kcsan
> > @@ -199,7 +199,7 @@ config KCSAN_WEAK_MEMORY
> >
> >  config KCSAN_REPORT_VALUE_CHANGE_ONLY
> >         bool "Only report races where watcher observed a data value change"
> > -       default y
> > +       default n
> >         depends on !KCSAN_STRICT
> >         help
> >           If enabled and a conflicting write is observed via a watchpoint, but
> > @@ -208,7 +208,7 @@ config KCSAN_REPORT_VALUE_CHANGE_ONLY
> >
> >  config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
> >         bool "Assume that plain aligned writes up to word size are atomic"
> > -       default y
> > +       default n
> >         depends on !KCSAN_STRICT
> >         help
> >           Assume that plain aligned writes up to word size are atomic by
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b0f3b2a6-e69c-4718-9f05-607b8c02d745%40paulmck-laptop.
