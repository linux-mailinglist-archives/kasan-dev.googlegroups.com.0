Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTFQ4O6QMGQEOOKBV5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F76AA40000
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 20:47:26 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id 006d021491bc7-5fceba4ad4esf1139651eaf.2
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Feb 2025 11:47:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740167245; cv=pass;
        d=google.com; s=arc-20240605;
        b=im/20z8dX4T71IXGYvXF/u0rVivjtBhAnFvdBK7oMSuvw3FpwmPEekdeoGPpK9kvvc
         snGt6ZNmndNl6+IeqOL01Hi6vnorsk2Al3vh5F9+1oxaQyGoxPPPF4Bxg/ezlDPRy3IP
         0lO2ouwTDQEj2n7VKhlx11M5Qo2QHcTM+VjzqNc7F412jtqYmtEep6ATJB3RovKDD7NK
         h4O6DzaHTAL+R4lIOgK4MHUTSRUsprUNTGru52reK436xBjRjA6kyHAjC7iPLovqJCtg
         nZEse9YA/ADQg9GX0OviSitOIY+mRTn57/VKwy+ZHRMJMB2x1M5IpW5XUGCNLldZI3uf
         410A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j+e0CY8POLaHHdhbDHYPMYWYoHyP8CBT4+F9iGqMTPw=;
        fh=vypeVHlTO1ygOCMzqZvjUCJHHPAdMRaZ3pZRYRH5Zgs=;
        b=B5XfcQgQ3y3A0pRFV6vpwLZSkFglu8+DklUcLA3o3Qv3xDe5KhDH4cjR1/bw7ql/tB
         RxPrwlH/QW2vTiT0cBb4vl9apf6CITeFnq6Z0NmID3E1oLvBfWdg4JtnX2itvR9b6cs9
         m/XuicFaPFhd24cZzzi/du1AEtidmCiZuVcCCqN2pKfQDIbDXc+zxfefbjTKSvZ/z9e3
         itTwtTRfmWsYRDCt2ra7OsQx1EYIumujbiCz80GHuKbr2XtMLRNfHPZYBIDjLKw8mSi+
         Ivxa2JDvYF7nZ2gBGNxuVv/bexfV9phjF9osyB3Ay8JR7f79pY0w3rHax5CtZn/H/XoC
         ZZmA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2VR2F8Uv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740167245; x=1740772045; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=j+e0CY8POLaHHdhbDHYPMYWYoHyP8CBT4+F9iGqMTPw=;
        b=cIK0R0Wq7vI6o/rxqIV5utq+YG4610wwAX+PBSBgCZ1OMq5B9CnKr7ip9zT7P06r8S
         c7j+UDUs80l7YtOEHkkp0XT0qBg8cRDmPdGQkhticTBrdgNRMhUZdVuqzbSyrnOUhSbN
         C8P9aVeo6i5u9ddZUQ0bEoPCGljYo9XPfW7vQtwpZ6jamTxlxaWNXOhpGaYb1lUBVaLZ
         iQeF3tR7WzsfWHst4OElgmmri8dTP4Sh2J6wFXwjGJUgt/CTvaptv3c4rGRYgBNXP76n
         sj1QKpC/thn6giqMmKj4KsQ/uw5ZXXGrssdlH8bAqP67Pip47IUzvoNwR9URXWD9L1Wu
         JN5w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740167245; x=1740772045;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=j+e0CY8POLaHHdhbDHYPMYWYoHyP8CBT4+F9iGqMTPw=;
        b=dEBB8rHQwyLW8xNYEHiNI3Ed7LACG87qjUGlOaUViIw9e0EKkqCK8Xgt2rQK6pCzMR
         VnJdhPvAtn14NBzOu4eOMzaSTPbII6THrWhn927NfeMKV4A6wM0BNhJGh1WW54+e4gjl
         Dgtyi/jLLf0TCbzg1iJPVFWxqReOyXPwzqktcnN8KbPB0Dgd8TlG3Xt2scLBWHlSTMaT
         saPZxLjBfmDCrRJGjOnNh3hxRvkUpDB55ia12Pxr5aQU6IqC5oSorp2q0oQy5KhySRgS
         UYeBveM48/Oi4QBv0CgBuyN4X2BkKsPSXDbU3jppAEouBeF18wDQLo1qT66ZzNIYXOlU
         zbfQ==
X-Forwarded-Encrypted: i=2; AJvYcCUuV/TXWDwEzhtyIDTuzrfy+2GRG70LNpdspzGzQLYpAEyN5RE9tcqSSyrqzapA7crxNnRIRA==@lfdr.de
X-Gm-Message-State: AOJu0YyL6Qsi4qh5GEDw929kRZ/H/gDh0DLxdRVGeLORE1q0Q6iB3fDs
	O4/dIUZs9YQcncNASQ1KJuFyInG3mvZKTgRwmlMagdRuHeGWMW5a
X-Google-Smtp-Source: AGHT+IGVf55Znf2Z84d6pNsv8NSvz0mYWp5vSQ1IcgyJaW5Uc/RGzolvfPKvaxi27d07YMt92lph/Q==
X-Received: by 2002:a05:6870:390f:b0:29e:61cd:d3b2 with SMTP id 586e51a60fabf-2bd50fb5f2dmr3378866fac.38.1740167244601;
        Fri, 21 Feb 2025 11:47:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFo5+8j2NecDHe26I4QDKnfy1vvRJ2aUS8OnPdvDWIUjw==
Received: by 2002:a05:6871:5206:b0:29f:cd11:1788 with SMTP id
 586e51a60fabf-2bd2fa7ffedls284267fac.2.-pod-prod-06-us; Fri, 21 Feb 2025
 11:47:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV9/dfFyQ7pCXIjKqHvyWa7VTRuh2ZkT53kZLaadPUvfN+stYROO9yl75F3kFSOWoW00E72vS0fcaM=@googlegroups.com
X-Received: by 2002:a05:6871:64c1:b0:29e:20c4:2217 with SMTP id 586e51a60fabf-2bd50fa8643mr3687227fac.33.1740167243424;
        Fri, 21 Feb 2025 11:47:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740167243; cv=none;
        d=google.com; s=arc-20240605;
        b=jEtZ1fesAOCTLivjFf7hvgFIdxGde4Af9EW2e2/udqNKmUk9EbXShOPVGMlX3eIeyQ
         Xs5NmGqBoE2+80QU8U4/uu9Nanrq9hNE4iYhqc5YVvfKT8aQUH7MN+P2R3H9tqmbkIkG
         WuwQ1C5OJwKAnQbSxq1XZqUoSIjhgzhOg8eOx6Cr1sveBRr3QxBMf8Q0tMjVaQRiSWM4
         LoE2yG6N2NlWv1V+ZoAOBeT4S8UpYbMXISJfN1ArOna+IDpK4EImbWCXg0P8VounosHG
         e0yKlbyDAqY6T4V+IEWn3DUrmf1DRTecv6yntiAw3HrF5cKC3w+4bzGGzQyBiiO4tMSf
         +Paw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ncoDsRKjh28vVH6GzAvugCMHO3v1MHxTwR6FKJOs+vU=;
        fh=lpI3MrPa7PXdVSJv8VPVImOTY60aryJBDw7wGeebNn0=;
        b=iGQnggy1fnu1GWWSHyHEoMq5JeJlXrwVekzh1eUgOVSbyTRXn+naeUg0+Qtm2OPTQI
         1rQfF+n31ieaUCRbUmay+EsTVlfwBjQa0N08GFS+dL693OEC9JXhD6nxNXx3vsMY8JGb
         j3BcPM0pexoc++WsqjcB1CjaIbFxkFwYt4RtLZHLoJiul0Sw16X+Jw9UYyB7TFY4nrAJ
         JNUemaoAOufExkdbonLsesqdaqfdAjrwxCcYN6dV75fgO2oOwLgYwSvwtJuMMc8MKRzG
         DNVYAx6FaCCWxTrkV/GMEADtsoSEdgOCslV5gpwduU/kCuJ1XerkpT/OTDA1EDKtkyR7
         cStw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=2VR2F8Uv;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1031.google.com (mail-pj1-x1031.google.com. [2607:f8b0:4864:20::1031])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-2b963a63836si862807fac.5.2025.02.21.11.47.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 21 Feb 2025 11:47:23 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as permitted sender) client-ip=2607:f8b0:4864:20::1031;
Received: by mail-pj1-x1031.google.com with SMTP id 98e67ed59e1d1-2fa48404207so5177452a91.1
        for <kasan-dev@googlegroups.com>; Fri, 21 Feb 2025 11:47:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWiNuq2SQYzLufEXyGvGMOVnvWTs8neWx4wuNXuEWIeNfGamKgN2bqePGiYllaoV4qTlXK8SGzU4ag=@googlegroups.com
X-Gm-Gg: ASbGnctx23WG9tF2vkS6inTrhuCEaDhD/EypfjBGHfgN3s4LY2dD2qFfltBokpEyHP4
	X2qa5hNbx4l3j2Vz1Rf8Jlz3RdZKuVZ/HGGFqlW6neuP+AQpgr0gig0gnGuLrSm6PJc2+9Q/8/D
	4e0qAVTlgpekqS3NmJaIysipYqG2BKls0Q/p+5BPw=
X-Received: by 2002:a17:90b:2252:b0:2ee:9b2c:3253 with SMTP id
 98e67ed59e1d1-2fce7b26274mr7182179a91.30.1740167242446; Fri, 21 Feb 2025
 11:47:22 -0800 (PST)
MIME-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com> <20250206181711.1902989-16-elver@google.com>
 <a1483cb1-13a5-4d6e-87b0-fda5f66b0817@paulmck-laptop> <CANpmjNOPiZ=h69V207AfcvWOB=Q+6QWzBKoKk1qTPVdfKsDQDw@mail.gmail.com>
 <3f255ebb-80ca-4073-9d15-fa814d0d7528@paulmck-laptop> <CANpmjNNHTg+uLOe-LaT-5OFP+bHaNxnKUskXqVricTbAppm-Dw@mail.gmail.com>
 <772d8ec7-e743-4ea8-8d62-6acd80bdbc20@paulmck-laptop> <Z7izasDAOC_Vtaeh@elver.google.com>
 <aa50d616-fdbb-4c68-86ff-82bb57aaa26a@paulmck-laptop> <20250221185220.GA7373@noisy.programming.kicks-ass.net>
In-Reply-To: <20250221185220.GA7373@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Feb 2025 20:46:45 +0100
X-Gm-Features: AWEUYZkA99crBxIegh1gRRcMrAoKxxzyxwRGmWJRS2whchm4-Eofmj8EM7dMgko
Message-ID: <CANpmjNOreC6EqOntBEOAVZJ5QuSnftoa0bc7mopeMt76Bzs1Ag@mail.gmail.com>
Subject: Re: [PATCH RFC 15/24] rcu: Support Clang's capability analysis
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
 header.i=@google.com header.s=20230601 header.b=2VR2F8Uv;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1031 as
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

On Fri, 21 Feb 2025 at 19:52, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Fri, Feb 21, 2025 at 10:08:06AM -0800, Paul E. McKenney wrote:
>
> > > ... unfortunately even for shared locks, the compiler does not like
> > > re-entrancy yet. It's not yet supported, and to fix that I'd have to go
> > > and implement that in Clang first before coming back to this.
> >
> > This would be needed for some types of reader-writer locks, and also for
> > reference counting, so here is hoping that such support is forthcoming
> > sooner rather than later.
>
> Right, so I read the clang documentation for this feature the other day,
> and my take away was that this was all really primitive and lots of work
> will need to go into making this more capable before we can cover much
> of the more interesting things we do in the kernel.
>
> Notably the whole guarded_by member annotations, which are very cool in
> concept, are very primitive in practise and will need much extensions.

I have one extension in flight:
https://github.com/llvm/llvm-project/pull/127396 - it'll improve
coverage for pointer passing of guarded_by members.

Anything else you see as urgent? Re-entrant locks support a deal breaker?

But yes, a lot of complex locking patterns will not easily be
expressible right away.

> To that effect, and because this is basically a static analysis pass
> with no codegen implications, I would suggest that we keep the whole
> feature limited to the very latest clang version for now and don't
> bother supporting older versions at all.

Along those lines, in an upcoming v2, I'm planning to bump it up to
Clang 20+ because that version introduced a reasonable way to ignore
warnings in not-yet-annotated headers:
https://git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/commit/?h=cap-analysis/dev&id=2432a39eae8197f5058c578430bd1906c18480c3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOreC6EqOntBEOAVZJ5QuSnftoa0bc7mopeMt76Bzs1Ag%40mail.gmail.com.
