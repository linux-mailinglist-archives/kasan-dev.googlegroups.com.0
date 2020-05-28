Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRVLX73AKGQELMALLBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id A428F1E65B5
	for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 17:16:24 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id w8sf8103981plq.10
        for <lists+kasan-dev@lfdr.de>; Thu, 28 May 2020 08:16:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1590678983; cv=pass;
        d=google.com; s=arc-20160816;
        b=ILhXRBkR3vyoTLbcYYRV4oc2EF9fYWTbReonq3X5uoGGXssDrcs3G+m/dJ62TUYt1e
         pcAzmRpbq4fgN0BiCWOEPQO2sN5IThi6Zkykt84duAALnHea/DjXTKVyrTYfx5n4h2Kn
         PqbIKUy2k8Se+AUsAWM0d1Vb/+NtxHEUllO5rTshUHLvQqxo8UnzxdzxkgqA1Z9pHIv5
         rgRKXa+fL8lu3NmauKFownIqQ7keQ0R/Nb39V3mKCAcRBwoYQGQFD8bdnTCvijGaMnvC
         VgnMFYDF+r/f74KOD7Kdb7cZQYWPWw7jYv1FfvFTz6CSrxzUQsMEr6x7HhIVn75yYVx7
         S54g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iyhIMbGcABLTuX8wVLqhjihG/3OwVcWxNgb1VWw3DKs=;
        b=o7FoA0m8BFRkyCDBLXAY493ObR+aOUfYKmKJNIXYEk41hZ7i/ykH6MkQ/qzTuhFtoa
         b0azy/Z7gghNOYTnbFc+F27ONAJfsXBYX7JMqDi/dukFoTlCPUQ7rCD20UBuUf5VHqFc
         k6dzHZVoj5eECVQQUCjZU3b3R9eCqPJpiYUPb9n8c2IwlISor2PAt+WUmrNDFVzrYXZq
         Kx5sA8D82dnVP+YmbSO4ZeDI/+mn4TOO/x71OBYiJV98J3NYUp+tE0UTRNMdsFZy/v6m
         iMQgF6fLfIoJNJtMUkyX+1u08P1UiyGrn9451BSRwLRqi1i/fezPOVVFowyW4abV10Tt
         p2Xw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="A4SBl6/w";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iyhIMbGcABLTuX8wVLqhjihG/3OwVcWxNgb1VWw3DKs=;
        b=mj+USX+15oQm7F5YkdSm6QVH2o3+ZZuPitHNlrRnCn7giXI0jJxtrwM9ydhUw5ZC0S
         lmoxUcEy1YgkS7AbAYYaDhy0M2i0y/ZqJ7CpRwALwhg8jZKr82MSj7TNOjfX2EKR7yPy
         D3fz8hIRl7Ft/rtMSwrMX+RmWbbsBUOS7AmO1EtGZFyVUGplls7rEoTSyC4R2f7oy6cr
         MXaPaF6tQQUugCqt4TrXY93HEfsoOAnGMl7T38Dvmk7D79XyrOa+flTw7vqACQtAbz2R
         HX3hpq04KzFHtSp9W/NJ2mQGiPBoQXFEH1PEFlhgwIeeNOPkPPlmXvu+YE4h180F0ACn
         9mXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iyhIMbGcABLTuX8wVLqhjihG/3OwVcWxNgb1VWw3DKs=;
        b=MiiukB/GtKXR3WAGHt6Z8mybAOHweq3aWjvp3pmuGmNLTPVlmXP4UVHEJYNjob56pL
         ioN9zVlQ3cs04ZXEPyiG5e6p03QjXgmUHzSxvuXlyckgNYy9SDXXT3Uurb4aOpG28oIO
         +B3pY4LTndpYLdqbsQGQUg+7wtqPEn6w6sUQqRnv6iiI6ei4jX+j8kpSXjQS+3Xbsc0f
         PJSO7wrEz8DTS2NlsSoqMbYHmCT7Dqr2D/mZm5TlneXnxt4s5fhT189A2HyQr99gq5on
         Bf4YTBTbouhbYBuhoHUeDngy7jkyL6usZhO+FT6mVj7isyENDXln+tuCvhVciRf9qFjY
         T3Ig==
X-Gm-Message-State: AOAM532OcVnvkVdNiC2TLAQKyruNPhs5JBHMc4GSOpcV7XKIil7UJw0L
	aTrJePT08SNO9yBGzQ4+zX8=
X-Google-Smtp-Source: ABdhPJxRVLT72u0Yea0vZ1fephtio66BItlZHBADlIbqou8wnJXYU41a7MjYDkLxwFkCnexTNTAUVQ==
X-Received: by 2002:a17:902:7d85:: with SMTP id a5mr4083936plm.106.1590678982934;
        Thu, 28 May 2020 08:16:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:63d0:: with SMTP id n16ls842366pgv.6.gmail; Thu, 28 May
 2020 08:16:22 -0700 (PDT)
X-Received: by 2002:a62:1d89:: with SMTP id d131mr3542831pfd.294.1590678982386;
        Thu, 28 May 2020 08:16:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1590678982; cv=none;
        d=google.com; s=arc-20160816;
        b=hCnhGHwMtcoCiq545yPlZ6nIyzSpyQA8BAjgjf/G5CQl57pqLY1EyM7VriiLMsdBGO
         VuX21Zl+YaDtEdvPkLXdsmCbVAzXKkOxDDSMC6OmtihNMIVCAqGVsORk86657aMTD4Lo
         pXIvkBhh7x5w/Clbb419wTkk2/sK/nL1cFoii86+kgZEAKyJvyOCs7Yr/A27RUwtXSur
         Qa6mVav0wamsDOr7xX3uS42jKf0iW4/NAD3tkPalHaGMl1WLZc2ZATNc9wzZBxe0DQ0j
         iba5zZt0L+NiqQnh2v4fkuoVE/be/hBVJogG68/K5uQkoWp47vGv6E6pXWUIbkTZe3Pc
         AEUw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VBOMR4dl3vHE3pgP6stmXiAZ6B3bsjHJjxfDsRtyI4A=;
        b=X7a990pXQpGi4U51OjlgX64wB7oEZIWbXYkZtbQFelz2VzE5QGg7AT/S9sAZi4Ctp+
         1fe8fGlHxPCdC5ZkJI1TIEc0JThzSrrpTLaFRBHFJoX2Hg/ECeJfYP0muI6WeR7dzsQ7
         PQC6GVVsm9hcKjKGZxua6HOmNoBt1Z2PKs495qNINzkpuTSRscxr8BqtDXotSTAld802
         iH+4zzVs6lJpaw9Fh2aBi1ubWvIOxlpSl/noA2i0qS+tRWsdC1fGU3tsMXdvusPq+Od/
         v0eNNUPvPHGqOtbySd1S7ENSMbR42XZHvEqJOofV8xHX7823aPdgAMLua/HZdWaF2QHE
         wYPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="A4SBl6/w";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id e13si556129plq.3.2020.05.28.08.16.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 May 2020 08:16:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id 23so312865oiq.8
        for <kasan-dev@googlegroups.com>; Thu, 28 May 2020 08:16:22 -0700 (PDT)
X-Received: by 2002:aca:ebc5:: with SMTP id j188mr2580409oih.70.1590678980942;
 Thu, 28 May 2020 08:16:20 -0700 (PDT)
MIME-Version: 1.0
References: <20200527103236.148700-1-elver@google.com> <CAK8P3a1MFgRxm6=+9WZKNzN+Nc5fhrDso6orSNQaaa-0yqygYA@mail.gmail.com>
 <CA+icZUWtzu0ONUSy0E27Mq1BrdO79qNaY3Si-PDhHZyF8M4S5g@mail.gmail.com>
 <CAK8P3a04=mVQgSrvDhpVxQj50JEFDn_xMhYrvjmUnLYTWH3QXQ@mail.gmail.com>
 <CA+icZUXVSTxDYJwXLyAwZd91cjMPcPRpeAR72JKqkqa-wRNnWg@mail.gmail.com>
 <CAK8P3a3i0kPf8dRg7Ko-33hsb+LkP=P05uz2tGvg5B43O-hFvg@mail.gmail.com>
 <CA+icZUWr5xDz5ujBfsXjnDdiBuopaGE6xO5LJQP9_y=YoROb+Q@mail.gmail.com>
 <CANpmjNOtKQAB_3t1G5Da-J1k-9Dk6eQKP+xNozRbmHJXZqXGFw@mail.gmail.com>
 <CA+icZUWzPMOj+qsDz-5Z3tD-hX5gcowjBkwYyiy8SL36Jg+2Nw@mail.gmail.com>
 <CANpmjNOPcFSr2n_ro8TqhOBXOBfUY0vZtj_VT7hh3HOhJN4BqQ@mail.gmail.com>
 <CA+icZUVK=5agY_FPdPeRbZyn3EoUgnmPToR3iGWuCzY+KHtoAA@mail.gmail.com>
 <CANpmjNOA2Oa=AJkKYadbvEVOaqzgD840aC5wfGGrFvDqUmjhpg@mail.gmail.com> <CA+icZUXu15=NK8wQgy=eeu=JcOGfB4Qr6UnwzTVvcH4T1L4pUQ@mail.gmail.com>
In-Reply-To: <CA+icZUXu15=NK8wQgy=eeu=JcOGfB4Qr6UnwzTVvcH4T1L4pUQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 May 2020 17:16:09 +0200
Message-ID: <CANpmjNNFxvL2Mrq1eJeRsyU19wgSdZrtLaTo2ksOfTzPTGKOzQ@mail.gmail.com>
Subject: Re: [PATCH -tip] compiler_types.h: Optimize __unqual_scalar_typeof
 compilation time
To: sedat.dilek@gmail.com
Cc: Arnd Bergmann <arnd@arndb.de>, Will Deacon <will@kernel.org>, 
	Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="A4SBl6/w";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, 28 May 2020 at 04:12, Sedat Dilek <sedat.dilek@gmail.com> wrote:
>
[...]

> > > >
> > > > In general, CONFIG_KCSAN=y and the defaults for the other KCSAN
> > > > options should be good. Depending on the size of your system, you
> > > > could also tweak KCSAN runtime performance:
> > > > https://lwn.net/Articles/816850/#Interacting%20with%20KCSAN%20at%20Runtime
> > > > -- the defaults should be good for most systems though.
> > > > Hope this helps. Any more questions, do let me know.
> > > >
> > >
> > > Which "projects" and packages do I need?
> > >
> > > I have installed:
> > >
> > > # LC_ALL=C apt-get install llvm-11 clang-11 lld-11
> > > --no-install-recommends -t llvm-toolchain -y
> > >
> > > # dpkg -l | grep
> > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261 | awk
> > > '/^ii/ {print $1 " " $2 " " $3}' | column -t
> > > ii  clang-11
> > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > ii  libclang-common-11-dev
> > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > ii  libclang-cpp11
> > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > ii  libclang1-11
> > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > ii  libllvm11:amd64
> > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > ii  lld-11
> > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > ii  llvm-11
> > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > > ii  llvm-11-runtime
> > > 1:11~++20200527111130+65030821d4a-1~exp1~20200527091804.3261
> > >
> > > Is that enough?
> >
> > Just clang-11 (and its transitive dependencies) is enough. Unsure what
> > your installed binary is, likely "clang-11", so if you can do "make
> > CC=clang-11 defconfig" (and check for CONFIG_HAVE_KCSAN_COMPILER)
> > you're good to go.
> >
>
> I was able to build with clang-11 from apt.llvm.org.
>
> [ build-time ]
>
> Normally, it takes me approx. 05:00 to build with clang-10
> (10.0.1-rc1) and Linux v5.7-rc7.
>
> This time start: 21:18 and stop: 03:45 means 06:27 - took 01:27 longer.
>
> Samsung Ultrabook 2nd generation aka Intel Sandybridge CPU with 'make -j3'.
>
> [ diffconfig ]
>
>  BUILD_SALT "5.7.0-rc7-2-amd64-clang" -> "5.7.0-rc7-3-amd64-clang"
>  CLANG_VERSION 100001 -> 110000
> +CC_HAS_ASM_INLINE y
> +HAVE_ARCH_KCSAN y
> +HAVE_KCSAN_COMPILER y
> +KCSAN y
> +KCSAN_ASSUME_PLAIN_WRITES_ATOMIC y
> +KCSAN_DEBUG n
> +KCSAN_DELAY_RANDOMIZE y
> +KCSAN_EARLY_ENABLE y
> +KCSAN_IGNORE_ATOMICS n
> +KCSAN_INTERRUPT_WATCHER n
> +KCSAN_NUM_WATCHPOINTS 64
> +KCSAN_REPORT_ONCE_IN_MS 3000
> +KCSAN_REPORT_RACE_UNKNOWN_ORIGIN y
> +KCSAN_REPORT_VALUE_CHANGE_ONLY y
> +KCSAN_SELFTEST y
> +KCSAN_SKIP_WATCH 4000
> +KCSAN_SKIP_WATCH_RANDOMIZE y
> +KCSAN_UDELAY_INTERRUPT 20
> +KCSAN_UDELAY_TASK 80
>
> I am seeing this data-races:
>
> root@iniza:~# LC_ALL=C dmesg -T | grep 'BUG: KCSAN: data-race'
> [Thu May 28 03:51:53 2020] BUG: KCSAN: data-race in
> mutex_spin_on_owner+0xe0/0x1b0
> [Thu May 28 03:52:00 2020] BUG: KCSAN: data-race in mark_page_accessed
> / workingset_activation
> [Thu May 28 03:52:02 2020] BUG: KCSAN: data-race in
> mutex_spin_on_owner+0xe0/0x1b0
> [Thu May 28 03:52:08 2020] BUG: KCSAN: data-race in
> blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> [Thu May 28 03:52:10 2020] BUG: KCSAN: data-race in dd_has_work /
> dd_insert_requests
> [Thu May 28 03:52:11 2020] BUG: KCSAN: data-race in
> mutex_spin_on_owner+0xe0/0x1b0
> [Thu May 28 03:52:13 2020] BUG: KCSAN: data-race in
> page_counter_try_charge / page_counter_try_charge
> [Thu May 28 03:52:15 2020] BUG: KCSAN: data-race in ep_poll_callback /
> ep_send_events_proc
> [Thu May 28 03:52:21 2020] BUG: KCSAN: data-race in
> mutex_spin_on_owner+0xe0/0x1b0
> [Thu May 28 03:52:25 2020] BUG: KCSAN: data-race in
> mutex_spin_on_owner+0xe0/0x1b0
> [Thu May 28 03:52:26 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 03:52:31 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 03:52:38 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 03:52:53 2020] BUG: KCSAN: data-race in dd_has_work /
> dd_insert_requests
> [Thu May 28 03:52:56 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 03:52:59 2020] BUG: KCSAN: data-race in
> blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> [Thu May 28 03:53:25 2020] BUG: KCSAN: data-race in
> rwsem_spin_on_owner+0x102/0x1a0
> [Thu May 28 03:53:25 2020] BUG: KCSAN: data-race in
> page_counter_try_charge / page_counter_try_charge
> [Thu May 28 03:53:39 2020] BUG: KCSAN: data-race in do_epoll_wait /
> ep_poll_callback
> [Thu May 28 03:53:39 2020] BUG: KCSAN: data-race in find_next_and_bit+0x30/0xd0
> [Thu May 28 03:53:41 2020] BUG: KCSAN: data-race in dd_has_work /
> dd_insert_requests
> [Thu May 28 03:53:43 2020] BUG: KCSAN: data-race in do_epoll_wait /
> ep_poll_callback
> [Thu May 28 03:53:45 2020] BUG: KCSAN: data-race in dd_has_work /
> dd_insert_requests
> [Thu May 28 03:53:46 2020] BUG: KCSAN: data-race in
> blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> [Thu May 28 03:53:47 2020] BUG: KCSAN: data-race in
> rwsem_spin_on_owner+0x102/0x1a0
> [Thu May 28 03:54:02 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 03:54:11 2020] BUG: KCSAN: data-race in find_next_and_bit+0x30/0xd0
> [Thu May 28 03:54:19 2020] BUG: KCSAN: data-race in
> rwsem_spin_on_owner+0x102/0x1a0
> [Thu May 28 03:55:00 2020] BUG: KCSAN: data-race in
> mutex_spin_on_owner+0xe0/0x1b0
> [Thu May 28 03:56:14 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 03:56:50 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 03:56:50 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 03:56:52 2020] BUG: KCSAN: data-race in
> tick_nohz_next_event / tick_nohz_stop_tick
> [Thu May 28 03:56:58 2020] BUG: KCSAN: data-race in
> blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> [Thu May 28 03:57:58 2020] BUG: KCSAN: data-race in
> blk_mq_sched_dispatch_requests / blk_mq_sched_dispatch_requests
> [Thu May 28 03:58:00 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 03:58:07 2020] BUG: KCSAN: data-race in
> tick_nohz_next_event / tick_nohz_stop_tick
> [Thu May 28 03:58:44 2020] BUG: KCSAN: data-race in
> mutex_spin_on_owner+0xe0/0x1b0
> [Thu May 28 03:58:49 2020] BUG: KCSAN: data-race in __bitmap_subset+0x38/0xd0
> [Thu May 28 03:59:46 2020] BUG: KCSAN: data-race in
> tick_nohz_next_event / tick_nohz_stop_tick
> [Thu May 28 04:00:25 2020] BUG: KCSAN: data-race in dd_has_work /
> deadline_remove_request
> [Thu May 28 04:00:26 2020] BUG: KCSAN: data-race in
> tick_nohz_next_event / tick_nohz_stop_tick
>
> Full dmesg output and linux-config attached.

Thank you for the report. There are a number of known data races. Note
that, we do not think it's wise to rush fixes for data races,
especially because each one requires careful analysis of what the
appropriate response is. In the meantime, also have a look at these 2
articles (if you haven't already), which describes the current state
of things:

1. https://lwn.net/Articles/816850/
2. https://lwn.net/Articles/816854/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNFxvL2Mrq1eJeRsyU19wgSdZrtLaTo2ksOfTzPTGKOzQ%40mail.gmail.com.
