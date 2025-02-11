Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4FNVW6QMGQEJ2S76QA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 07EE0A30D67
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 14:56:02 +0100 (CET)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-47196afc5f4sf33150681cf.2
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Feb 2025 05:56:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739282161; cv=pass;
        d=google.com; s=arc-20240605;
        b=hWL1TMMLSBI8kO9BmxcdxvddWPGMMtrqPz3KhUpsMcnLPrHBDa4brRgdzyRP6KKGS0
         bANooLJMR+UTYeB7X073tOrAO//VeFG8VwO8jYdUunyd+FsFaFsiYwt1AmexkHOfH6LZ
         8BwgDTGAJip+KWo2GV7MXWTwD9s5fET/L+Ndneq4G7VbQLSDxgv3B+tyeQWKYntlD3ZU
         7RiQ5/CBpw3vPsnJthtqgVwm7Y8yonHWlLPvuvJKntoRm8Q5TBYU8jkoB3s+UxR/H2/i
         Ch0t+bsMKZ3wHiHhZj+eI9JU69p2Nu7xYtbI4JwijgSNS4tO6Nb3h5EDzUpGmUiYK0b5
         6MaA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HLKsex5D5D/s4OOvXjYP49X4xQ8REmoDDmaBHcO5Z7c=;
        fh=NLJAdagXUK/FZhOV9O90ertPgHkIizis1u3fOxujrJE=;
        b=cL4WiKAgjUGNoFozgl/LmYuTwJ6t9Qf4QWLYIe+4EYHGvKMO2I0/I3DQF3HZdC5/pf
         s7CSOohgZA6q4gzAPlnOTf4CYIXd3fquV9jBKIu78gBWvT9kCQlT8VkNfuWozm0hHrgI
         gdS+aJR0xzON2Vm9rfE5OCATOdmLtKMZUhvaq/ZceV8S2Z1vCXmtuYQLqSf+AvPYsRlZ
         38UTE3tfXD71V7HjM2teF7eIcW49ezmlWc01V+NTNPXsJ14tG3ErS5SMbu/WWsKROPPQ
         FqtLkGmtKQjkFiSuMNi0TL182OIJd4FOMvIQPaE/XmsDFj5bex9ZXPTBPl4SWV0DOd0u
         GR1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Nt892p13;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739282161; x=1739886961; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HLKsex5D5D/s4OOvXjYP49X4xQ8REmoDDmaBHcO5Z7c=;
        b=v1m4MCN5zM8GEA5wy1lDkFg6KpSqhrLnywy4Q5mlDVO2eKTP+g0MUAZGU+STV4JYc8
         xWrp1Lx7NXseidvyUjiyB1U7PjX4OA/7enCKluUTEoFW/b0iRMq9hMWawDoDJr3Hr15H
         MKcbO+lbcW9/ZGxdCwPXC3qpvVnjdOKCCOyMuu6j3CH4I54CZyXbMqJ3uq6fbiM9qiFa
         KQz9x7m2JecEAhbOD58m8AtCKXwoUmoUKjO2Tf1JxkhO4WLYhAFT3fN3Fqw0A2UjKd2Z
         v5ZsEbTH6br0wA/CeaLow8sK3Uk5FYvvYZKmLVc4RCLImfTgrE/sOfXNU8ZAj54ak6mm
         8Q0w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739282161; x=1739886961;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HLKsex5D5D/s4OOvXjYP49X4xQ8REmoDDmaBHcO5Z7c=;
        b=kQC0sUhLGTeMyCF6xqyFaPVpMQck8UpBqLY/+0N8n5wsuy5uRNGg1a0w4iq7C4O3BO
         XyoIoOx29D4UBOZNiVZJMPCjTIRt00lqwLtgCkuu5ZR/h3BOxf+UyzteHDBQenmDC9+u
         TTRUko72yZ4+G7ZxiObGW9LvtUJYKjtNXiV47gDIq29/aOAd2QGqX7qAmSWFTfNQgKDD
         Fx5iJRZ6HwheGp97Y0dDiL45QeG7DZz1GOJncUtlJrI5rYMc542Gw0ZRuUgCJ0zE8u48
         mOJzDJU2umOKRhesp5xsNpwfvL7v9OcWLvaLK6nXFLo0TiiK3wg8kteP4m69BFid+VUQ
         igbg==
X-Forwarded-Encrypted: i=2; AJvYcCUxN0JQRlfg56A+QiacKbT5FAGwZolfZKJpm0c08T+GjnN0aTh0kOLxCzcQq15QrdFK6go5TQ==@lfdr.de
X-Gm-Message-State: AOJu0YwaGndll6ZMTl0NinNgneKoYh7PILP37KAkzZuazxyEb0Cpc5yx
	Cx+2NEE5IKtC/EQWgq3MiF0TWmabaaqE/WES7v86ZlldPTbp9Jle
X-Google-Smtp-Source: AGHT+IEWMHVRRX5884OG4ZW2uOlLGbo4BmVnZywSv7XXvz2ULT1BzPNo7kjTfMwbifNuK1P9nnuF9w==
X-Received: by 2002:ac8:5742:0:b0:471:9244:c2f9 with SMTP id d75a77b69052e-471a064919dmr41292141cf.10.1739282160815;
        Tue, 11 Feb 2025 05:56:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFVEb2bvQVoFy02aJYVDLk6kQWV0RKjxCJZ/2Cv8NBzFQ==
Received: by 2002:a05:622a:4785:b0:463:f0e:44c6 with SMTP id
 d75a77b69052e-47046cada9fls23496561cf.0.-pod-prod-01-us; Tue, 11 Feb 2025
 05:55:58 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWYNvW9eSXgvbExkDIEO8WzAx3Va+9xj2cfE1LfnPipI9whLGVuTEcGSaNzihzn2RRMZ8xjm2OjN5g=@googlegroups.com
X-Received: by 2002:a05:620a:19aa:b0:7b6:dc4f:8879 with SMTP id af79cd13be357-7c06882c8d8mr606581485a.47.1739282158397;
        Tue, 11 Feb 2025 05:55:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739282158; cv=none;
        d=google.com; s=arc-20240605;
        b=Yq/9EfrSU+las8EzavOXgsn6t5B8w/q82wHMklctBnsWeC6Q+JGOK/DUtt41Uz5+lb
         HJUzsWXt+15F8sZQrDa4nsM2i1uiftwCtyh/06O68PpDoh0vin1SpmX42/keZb45i5g7
         gZRiA6/YDfKV+kznkTPzKHMj0o0d0yqMv8UUzUJZYt5Kd7eAiRJscoRkIM7iuOTTIP7S
         3JEengtCLsfuta4fcOF5etyqFg9kZt7x/hkHw5gq+HqFx0GRHgxF9yMpcF6x9JRhp35X
         YGcFoHEyC7omMQFQsmKcWUfXcXiqWaXLGKF1E2Kf82bC9BmRVh+BB8jN0yzKrDKy8df8
         gvow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AhF+JZnbICstMQ4SyijmaSYDsITfNwFybUAYOWyiZXU=;
        fh=6V9mnSRPPtLQhcL6bsiqJwB+Zx4s75HN47ss8sOTcY8=;
        b=Huha4BlTc7N+1L2EZW3Am9/hbfMPNtFxljMDOo6cyEIf3w2FjYdeejNU+9RhlL3bYM
         cRHWzAiT6JN8KQ7NuhkNLFoaSx8TEYV1ZLNxpGS6rjuaCprxt1jg0TD5pkrpMTWQtlZ1
         Oz+rnXFHAPV1v0u/kcS+JKsWuL/feTDbeJkk4A90k9ur9AOIWbjuWs4NTqLuckuRTRbB
         gAs+F9huu81rg/oca51lUh8zFJTR7Z33knU9xGzUe66RbDuynMDLvIX7W81TiNKvbRx/
         TnBAh3T7T80lG/W4jTNzypZmWn0U8OREkYrC3BUp9k8rwq3GFWUv30CONiMvmKN6ENEU
         SW2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Nt892p13;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-47140ed7620si4970361cf.0.2025.02.11.05.55.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Feb 2025 05:55:58 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id 98e67ed59e1d1-2f44353649aso8177570a91.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Feb 2025 05:55:58 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUPhoeGdjC6iR8wwHrpWP5MjDX8DWEvAsnZsT60yoquFh0bqtM0YQ1WbBF5WDvpBvV4fm2JF5ussh8=@googlegroups.com
X-Gm-Gg: ASbGnctu1T9NK/KmF7fe51LCSzGX2SbBgedvwJAd2nEFB8AGzH87jLdN8j19U52KHeu
	mNqY0ESNceLCKMYV1yxAYFS2LdLAMpZrR0Mv6WjUCr9vYcMO/G6krnSDgk5ETYF8vuDuiXFCUX1
	4nRt2qrGjHkfysFV0hysJYnT4D1/U=
X-Received: by 2002:a17:90b:1d45:b0:2ea:5e0c:2847 with SMTP id
 98e67ed59e1d1-2fa9ee17fb8mr4391611a91.22.1739282157250; Tue, 11 Feb 2025
 05:55:57 -0800 (PST)
MIME-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com> <20250206181711.1902989-9-elver@google.com>
 <e276263f-2bc5-450e-9a35-e805ad8f277b@acm.org> <CANpmjNMfxcpyAY=jCKSBj-Hud-Z6OhdssAXWcPaqDNyjXy0rPQ@mail.gmail.com>
 <f5eda818-6119-4b8f-992f-33bc9c184a64@acm.org>
In-Reply-To: <f5eda818-6119-4b8f-992f-33bc9c184a64@acm.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Feb 2025 14:55:20 +0100
X-Gm-Features: AWEUYZkwbHjIdQKR2hqck9okMpxl0TDfWkkc2sBGpPLWquXQ8_lyXjiGcdcjlSE
Message-ID: <CANpmjNPxyWey6v1tj6TwtN6Pe8Ze=wrfFFjuJFzCQTd4XM8xQA@mail.gmail.com>
Subject: Re: [PATCH RFC 08/24] lockdep: Annotate lockdep assertions for
 capability analysis
To: Bart Van Assche <bvanassche@acm.org>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Nt892p13;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1030 as
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

On Mon, 10 Feb 2025 at 19:54, Bart Van Assche <bvanassche@acm.org> wrote:
>
>
> On 2/10/25 10:23 AM, Marco Elver wrote:
> > If you try to write code where you access a guarded_by variable, but
> > the lock is held not in all paths we can write it like this:
> >
> > struct bar {
> >    spinlock_t lock;
> >    bool a; // true if lock held
> >    int counter __var_guarded_by(&lock);
> > };
> > void foo(struct bar *d)
> > {
> >     ...
> >     if (d->a) {
> >       lockdep_assert_held(&d->lock);
> >       d->counter++;
> >     } else {
> >       // lock not held!
> >     }
> >    ...
> > }
> >
> > Without lockdep_assert_held() you get false positives, and there's no
> > other good way to express this if you do not want to always call foo()
> > with the lock held.
> >
> > It essentially forces addition of lockdep checks where the static
> > analysis can't quite prove what you've done is right. This is
> > desirable over adding no-analysis attributes and not checking anything
> > at all.
>
> In the above I see that two different options have been mentioned for
> code that includes conditional lockdep_assert_held() calls:
> - Either include __assert_cap() in the lockdep_assert_held() definition.
> - Or annotate the entire function with __no_thread_safety_analysis.
>
> I think there is a third possibility: add an explicit __assert_cap()
> call under the lockdep_assert_held() call. With this approach the
> thread-safety analysis remains enabled for the annotated function and
> the compiler will complain if neither __must_hold() nor __assert_cap()
> has been used.

That's just adding more clutter. Being able to leverage existing
lockdep_assert to avoid false positives (at potential cost of few
false negatives) is a decent trade-off. Sure, having maximum checking
guarantees would be nice, but there's a balance we have to strike vs.
ergonomics, usability, and pointless clutter.

Can we initially try to avoid clutter as much as possible? Then, if
you feel coverage is not good enough, make the analysis stricter by
e.g. removing the implicit assert from lockdep_assert in later patches
and see how it goes.

I'm basing my judgement here on experience having worked on other
analysis in the kernel, and the biggest request from maintainers has
always been to "avoid useless clutter and false positives at all
cost", often at the cost of increased potential for false negatives
but avoiding false positives and reducing annotations (I can dig out
discussions we had for KMSAN if you do not believe me...).

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPxyWey6v1tj6TwtN6Pe8Ze%3DwrfFFjuJFzCQTd4XM8xQA%40mail.gmail.com.
