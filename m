Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAFPS66QMGQEN3VLJZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 62E9FA2BFE7
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Feb 2025 10:50:58 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3d14604a880sf1914095ab.2
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Feb 2025 01:50:58 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738921857; cv=pass;
        d=google.com; s=arc-20240605;
        b=DwghSG2BPdVZXh9lCdaCk8paVb7fZGJzftLm/mIQ4f064oryzw7bQgi0VcgogGP9wz
         E5ewCvp1eit80jgRFUni1DyJsb2Yxac5mWITJhD0OhX5JeoB3B2rnzF54YAcCVvAfmRJ
         yw4iJtIyfVooNBSypKHn4OYYknWxtXyRDRwpvYZuQSRCiJ2tyIoxuP53W1pTiDofxAs3
         +6FzFX5+mRFfJOzS4amzsK5dgFq+soelRNK8XpgSIrJXBTUnVnA5xChmrwVYfhXYv6ZU
         KEp3bDcA6GG5YHb/5JtLk8wF2WIIiAHkehl+XugOv1nAdzqBYc3bJVf/KSNzc0xGswT+
         dj5g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bj7d2GUdjfYmA1IoNtRJTiha5H0KjGuubTnKO5IsmV8=;
        fh=/gNBl786+wsAyzMYUpazxt1LaXLQDXbm/65e/BZt9Ww=;
        b=Vx1aufkomX5pLeBidRQkDkQnLQ195MYw8KSpOG0lHyJO/VS6/QcYG2bQnj61P2gx4O
         BSZZ9TVU6jYkq9cSdUCWsZBfwAcYctXmBW0hZ7JQWJHWpMc3fN08FKe8ou4ZsdbUQG1V
         UrthF+WbASK/aBuzsHLhxdkYM/yDZVqgvZeWJ08JyCLpGDIIRrTC8So62Fe9CFFu3jl6
         BD2kVlG4hdryokq+YWtxdkmWY9J3XIBuwDZPk9nXD7syR7w7mY7JKN+TbPvxchfkELC5
         /ebO4a9B5FodQ2Z8QTYt7GG6pI3Eo3FVX3e5sVYhmeeZqjPFRQ+FGRDHhGZGgXeSZDWr
         xjnQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xXxrmwZW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738921857; x=1739526657; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=bj7d2GUdjfYmA1IoNtRJTiha5H0KjGuubTnKO5IsmV8=;
        b=T3zL3ZIiMlQ0GI3OyU7uUF2nJA41XrbBchq7YSRbWg1ekGv4zjuL9l6QIMoHMpP5hS
         7vLVo/eMwTLlQIZFO0UYmA3g2P8c9wwXRO1dOohCJecyoIgdb8JSGaVeLrEIAmX392FS
         kwC9ePLunjSt6+8i/4m8vqXizUVcHEDUq0LY1EgHibUzNNrSV8i+jfSgVXpnQ5dGJh0t
         TqTWYuz788B5rRX7AFVewoWqIs16Jv29jUNxGEJsQrSntR0JzU/TY3pZI0XPDum4+V7r
         8T/A7Fxh3fzk3eOqdOJO4ltSlOzX/ezV8K6Ldd3MvuvD2DPYEvzeJua2usl7Z84Z1EoL
         bDKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738921857; x=1739526657;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=bj7d2GUdjfYmA1IoNtRJTiha5H0KjGuubTnKO5IsmV8=;
        b=wx31c0lVeRmKzZhhr0umtJqsu64aGY3qjSJmdwoJIXhgPvmdxp0RETwSehL3XZ1k2c
         udHOl40PMOjlHWbA0QBziM0UKsGEpFNqtVHP48mkbWr0xFIIys44ktW6pEEgArXCi5bf
         jAT3MHDABueZ6D+ZGQiu+kdkLY89lNh8PlkgptUzxmQ+EZ1tzqR/+52D+H7e909N6LAX
         pykygNDAuEtepxLyX+ofgp0bvCbJ/MQv+CFvb67n+a5fvSBa6dxSz4L9r8o1nLWzxNhc
         EysTiDJh7y5rpZIJe6UgK51hMjYNC7mqooGF4KIrZAFCum843VBksNNdGBi8xw41oZc7
         TBjw==
X-Forwarded-Encrypted: i=2; AJvYcCWDFNgcwc9j4uRkHleTjqoobnlt4/t6r+BmWquQXmd7zd2+FDrnztXW0puUJZjtYEMr/FjEDw==@lfdr.de
X-Gm-Message-State: AOJu0Yw9l1z2dGkEPx91BxDl/GTSlyRAVe2cMd2tI5EsterCuMaFvYGV
	nHJ4Lg8ylSeuLwhTqBWVi8caWWYZX0EqFZwLKgIJryw3O+aN51I6
X-Google-Smtp-Source: AGHT+IFuuttsyv/4bFJe71IKZyneh7qDLMWkZIkC9QGyCtGdAfH/7rgvTjJZ7LBOLeW/lz3Ig51AUw==
X-Received: by 2002:a05:6e02:b2e:b0:3d0:137a:8c77 with SMTP id e9e14a558f8ab-3d13dd026c9mr20911555ab.3.1738921856872;
        Fri, 07 Feb 2025 01:50:56 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:dccc:0:b0:3ce:27bc:c942 with SMTP id e9e14a558f8ab-3d13d868b14ls3874615ab.1.-pod-prod-02-us;
 Fri, 07 Feb 2025 01:50:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVRH11ySq2dCE2rti6ncwVY6a8vzOdhE/Jqv9qTZ2zdq+WUCBivKryPraMOB/VFssdKFD5q2ObSmkk=@googlegroups.com
X-Received: by 2002:a92:cd8c:0:b0:3d0:21f0:98f3 with SMTP id e9e14a558f8ab-3d13df6ae8fmr23168705ab.21.1738921855929;
        Fri, 07 Feb 2025 01:50:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738921855; cv=none;
        d=google.com; s=arc-20240605;
        b=EAFV+LkqXzBBIUtrKDud67MLlYhATerOLavMohoxy1Pi3Kpkb7hHv6yCoqayfIMwae
         O40C7ap3zQDw8wb5j4WFqFXsy0H54HVrJLnEJDLVlvNPuBgxfT5hyp2pWKl1VqJBYkZn
         VGDx14O6iVHkcvAcfA8/GMXoxwO2Ipe9CivyJ2ody+MFPO7uOz+xcG30B8z+15ml5LIc
         hZ7agJxKhq6FprVdDCZxQjqi79u+esa2c49bEsUjoNSCgrwjDIYos6VxtuSuhFxWBhSU
         gQ27SbSSer4lflq5XFfM714e1Aml+C26oqN43EJeCHmeUvq0PAtOTfjybgVeggIFbemg
         TErA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RDirK3mhBkbwPEuL8B+oV7JCR8taE0i7p+xewXa9S2U=;
        fh=AVxAITfFnMBImiPnNAXd552uRN9KkMvAW05umfNX9Xg=;
        b=eIQKa75e3BNwKRHfPVEwabvOh3nkq5L6//K/+6gMwx1y3PO4//cPEIV/WeY3uXg8dC
         gRxqvSLjdHxslh/2UBUUIoFVt2tkTZcqVf2QXOGk9FX4GqlGBw0X4Bnc7E1h5YebnnHK
         bU0bqKvMEOWWdZ702YGWtR8IwzBVw1WRZyre1jjEdMtD5QtiGEb12zEi8qaQpu0iDC6t
         /5a0E7HwH46NHeMoP82XmAjgE4Sc71SwCQREhHod3OZeto7YJevdV7LZ4rICgFS2fdlr
         qmcUBU1m2dmvmp5XCm0bUa+Ygmw/m5ZiSg7KEZyg4My+KjKCHr37+l9QLkJ92IMPWo4r
         XGsg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=xXxrmwZW;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d05e9af0f0si1586495ab.4.2025.02.07.01.50.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Feb 2025 01:50:55 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-21f464b9a27so23318255ad.1
        for <kasan-dev@googlegroups.com>; Fri, 07 Feb 2025 01:50:55 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVB10m+va/WlgkwjJkiaC8POAETcO11RzIqjAC79bNqgHeTbK9tdtibHI+yvV/aZRPME7T8G9Fz9oI=@googlegroups.com
X-Gm-Gg: ASbGncs6qW9KL53ywJMveNVDm4J7YeFGNaaZ939n0w0ECgQbEHzLKmFsV7ldsFudrec
	Vy9dYzTbLtDHpVO4VgyvRA3zVEvjUopCAQZMxSdVm0RvHAjcwGFUgdoCNiv+P8/5CHXPxF30ULI
	XhUc1RMKyoP/KL2kBxcp7liFLxt3o=
X-Received: by 2002:a17:902:e547:b0:215:5935:7eef with SMTP id
 d9443c01a7336-21f4e6b1204mr47269625ad.22.1738921854968; Fri, 07 Feb 2025
 01:50:54 -0800 (PST)
MIME-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com> <20250206181711.1902989-3-elver@google.com>
 <20250207082832.GU7145@noisy.programming.kicks-ass.net> <Z6XTKTo_LMj9KmbY@elver.google.com>
 <20250207094120.GA7145@noisy.programming.kicks-ass.net>
In-Reply-To: <20250207094120.GA7145@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Feb 2025 10:50:18 +0100
X-Gm-Features: AWEUYZnQWDpp3VDaOjksp9Zo0oytYCkyAdjXISUfV_jPXxvw0lspyJEb-bEMFNQ
Message-ID: <CANpmjNPfFXjwb1-ou3M6s38w=uXgHioK1d=mMSB3_HjHjV2waw@mail.gmail.com>
Subject: Re: [PATCH RFC 02/24] compiler-capability-analysis: Rename
 __cond_lock() to __cond_acquire()
To: Peter Zijlstra <peterz@infradead.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Steven Rostedt <rostedt@goodmis.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, Will Deacon <will@kernel.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=xXxrmwZW;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62b as
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

On Fri, 7 Feb 2025 at 10:41, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Fri, Feb 07, 2025 at 10:32:25AM +0100, Marco Elver wrote:
> > On Fri, Feb 07, 2025 at 09:28AM +0100, Peter Zijlstra wrote:
> > > On Thu, Feb 06, 2025 at 07:09:56PM +0100, Marco Elver wrote:
> > > > Just like the pairing of attribute __acquires() with a matching
> > > > function-like macro __acquire(), the attribute __cond_acquires() should
> > > > have a matching function-like macro __cond_acquire().
> > > >
> > > > To be consistent, rename __cond_lock() to __cond_acquire().
> > >
> > > So I hate this __cond_lock() thing we have with a passion. I think it is
> > > one of the very worst annotations possible since it makes a trainwreck
> > > of the trylock code.
> > >
> > > It is a major reason why mutex is not annotated with this nonsense.
> > >
> > > Also, I think very dim of sparse in general -- I don't think I've ever
> > > managed to get a useful warning from between all the noise it generates.
> >
> > Happy to reduce the use of __cond_lock(). :-)
> > Though one problem I found is it's still needed for those complex
> > statement-expression *_trylock that spinlock.h/rwlock.h has, where we
> > e.g. have (with my changes):
> >
> >       #define raw_spin_trylock_irqsave(lock, flags)           \
> >               __cond_acquire(lock, ({                         \
> >                       local_irq_save(flags);                  \
> >                       _raw_spin_trylock(lock) ?               \
> >                       1 : ({ local_irq_restore(flags); 0; }); \
> >               }))
> >
> > Because there's an inner condition using _raw_spin_trylock() and the
> > result of _raw_spin_trylock() is no longer directly used in a branch
> > that also does the unlock, Clang becomes unhappy and complains. I.e.
> > annotating _raw_spin_trylock with __cond_acquires(1, lock) doesn't work
> > for this case because it's in a complex statement-expression. The only
> > way to make it work was to wrap it into a function that has attribute
> > __cond_acquires(1, lock) which is what I made __cond_lock/acquire do.
>
> Does something like:
>
> static inline bool
> _raw_spin_trylock_irqsave(raw_spinlock_t *lock, unsigned long *flags)
>         __cond_acquire(1, lock)
> {
>         local_irq_save(*flags);
>         if (_raw_spin_trylock(lock))
>                 return true;
>         local_irq_restore(*flags);
>         return false;
> }
>
> #define raw_spin_trylock_irqsave(lock, flags) \
>         _raw_spin_trylock_irqsave((lock), &(flags))
>
> work?

Yup it does (tested). Ok, so getting rid of __cond_lock should be doable. :-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPfFXjwb1-ou3M6s38w%3DuXgHioK1d%3DmMSB3_HjHjV2waw%40mail.gmail.com.
