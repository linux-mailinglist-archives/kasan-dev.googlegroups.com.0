Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAWUQCHAMGQENI62ATY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DE5E47A53D
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 08:00:20 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id m15-20020a638c0f000000b0034056b46a05sf673803pgd.15
        for <lists+kasan-dev@lfdr.de>; Sun, 19 Dec 2021 23:00:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639983618; cv=pass;
        d=google.com; s=arc-20160816;
        b=zzvrttU3ElzXEq5Cete1QEOussHh6KPJMkZHiTzB7MzygZNyRrGcGSb5J27IsTDIjd
         +/MAHhLQy9nl0mpWQCfgKrduNOTHFfh0autwSfW8CID4shcnm9Rm6Vss+8QHPnThSFNt
         zGyBu/LzaINutYENFP22WF/bFGEfsJxcMfh6eI8QhDkVtuRjBGM6z/SlbidT7GhGrsFV
         Tq6oJ51pup38xmrI/M3+zCoGe6aVBQCgpUbUs7wRnuWo5zyhAh19hxsrUexIqQNbjkoC
         MWkIcq9xNFbGKpYWS7KzGTW+DpF9SGUK9qwR3+yCIo+0awWzH/uO6izUzomyssxkiHW+
         mwfg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fbBVCnDY21zi6zYZ+iscJkOEZsu3crfH6MFo0CyAaMg=;
        b=y8Zb/qHLb1xb237k+ak6XbeXjcuhfsKd+yPjm82GLR87WvdRg3nvTVmZN11BQ6KIZQ
         wKcQ9k0Q4WgqvVSSMMWU3B0Jyg1Em+b8jC10vwTyetRzjV98Qv+42Us8YwRC8t2wBSxk
         BHmWin6KiBhI/FpCVDiMpwFlTvMbP3OvCzXrjGq+iH2QTnrqyF+5jAA3U1wd/izcHHaQ
         XMapuxaZ1RTTIzixk9f18zKKBldwp3iEJHJQiRj/9WSRPe4CDrcaWpcJ7mDFzpGkUyVj
         zWJ877ERA1PKu94cEnShIoSrVjwg4+uLMSkriLAxcsLFi0eUriFpTuIxA7Go31QNp9C4
         cqBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EhTOwMFa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fbBVCnDY21zi6zYZ+iscJkOEZsu3crfH6MFo0CyAaMg=;
        b=giOJYZgI2pRtCRmd0kGLPakRDYmAUwrVZj7fQ7YBH6TUnHM7JlrZACBNXkfjb6z7W1
         qIW1cPL67xizIXl+EudmyAOy90/jSmMoECBMRCP5OnEKCa7+QObACHuQt8yVZ9yPck+8
         /5Vz1R4PvMtbC2kQ5WcfKjv8Dgw/h8f71c73Mpp7PBkNuZrsde9syGWAkG48OptkGzD+
         xOf23XX/PxXq5aNJQc+SvMFbI47YAEo0uJjsLeg5Ny6lNdeC6+Ii/hXSiEKvygfvf6EN
         itZWRGV2NmuiTQO0sOx2LWJ2OcrLB0uxYoMZrFsj9zwOvr7D9gWJqlocbdAKJNJWjny3
         vPZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fbBVCnDY21zi6zYZ+iscJkOEZsu3crfH6MFo0CyAaMg=;
        b=f+QezVpRA4SAPDO/Gs639xNjBy0u6ohUVi8fCEJpD4YtcVUcsJJ1paK+pL+50CFsFY
         x3SRhNwMD9m0lvWFJhkbgEsFXOml4zzu8VTkWzoC66Ffx785WtpfOBNLXpk52c8qGlrD
         t7f19UhbkZEQjYQT+OC/wwd7RHNJNQxl2bS1U/nfk0oLuRBKOmP5ABtHWRfhK1xp2h20
         4f3dXvCiKYzoA7iSWLCg6g2s+3fbvj5N9jvFc2Nf/T/ELklure7j2mS7W6or/mqasLJ+
         q9Lwf3J4qVUhLu6O/dZtzi9+lD27PgOJhGnIQbYv71PCVMl1cIBGw1mAo/qPectd/LlF
         4duA==
X-Gm-Message-State: AOAM533436/Xs+m5U5DH/vVP6G6VrLy6B06lyi2rYjHL7bB4vnozCcqs
	j6UAqfvcJYfZnROCicbZR0c=
X-Google-Smtp-Source: ABdhPJwvY0VYxEAUf4r5/JkEsJM31ehfQUomeoJpNA5nPhCPEAFwL1vSW2pAwj7pTJEH2edQ1gsIjg==
X-Received: by 2002:a17:903:228f:b0:148:d5d0:5be0 with SMTP id b15-20020a170903228f00b00148d5d05be0mr15366198plh.104.1639983618322;
        Sun, 19 Dec 2021 23:00:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c91:: with SMTP id my17ls1353740pjb.3.canary-gmail;
 Sun, 19 Dec 2021 23:00:17 -0800 (PST)
X-Received: by 2002:a17:90b:1c05:: with SMTP id oc5mr2150028pjb.31.1639983616918;
        Sun, 19 Dec 2021 23:00:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639983616; cv=none;
        d=google.com; s=arc-20160816;
        b=VzGwDhU+TPfuFKrwfxK+C6dot24WATfXOC22udDnHL2bMIuc2cVxNrOBsEtYPsP9XW
         PudCwGN0MRgE3f8udTv8+3ywPDWMI9w6MswWtSH3/SEKKph2uavC80QpbXkgiBdUjI/Z
         JtJwcguVE1nsjos7oHaIvdVG4BmIJfsCpaHgTW6m7qbUXdaYMiGQr1nDTb9BNEaGyO5P
         trS9AG0wDUESdEEQm8UM2HlTYBs4jIrsouGmq4ikksca7qycnKl1dlWWW4bNLsg69Clf
         xEdQsmAfsYTFFK7xlGCmwC7LX34epuuMBRqllto5rvH+SsPdbc7lcaz/Le5v6ONrqRNl
         ZELA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bOWHMfUqWgS66PgQYYet33MLKueM0ddFZqC4iawf0eo=;
        b=XBHhCfepyE0FjjVvVan+Cvx7ClJ+11Y5BZrbXBZHZtegVg7fbyaPf6jFtc2VNVrw5H
         Lhx12F3OoJFzO7k7NjlpSQAEmA6sUIid6FLRN0SoC9zQHX8D0cOiGF+4RQ2ARaeLx9eM
         TMwGYmx4jNO0KDyN5QIQZmMlJ5EgN+xvse2xzD56gxELxlIJY6f7sDk6tUpbnYDSpAym
         z2W23zuArXsxJoJFws007crqGo/2axVuDGViB579Xh3BgZdkE8LBA8B6YSY8zjmYuJHm
         dcU59JASH+iQi88GXO5i0plDMS84RNa2izFR2jWqSHS+MkXpTb2gTLyO2+EPNKomCnUH
         8v8A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EhTOwMFa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x232.google.com (mail-oi1-x232.google.com. [2607:f8b0:4864:20::232])
        by gmr-mx.google.com with ESMTPS id c9si1093924pgw.1.2021.12.19.23.00.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 19 Dec 2021 23:00:16 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as permitted sender) client-ip=2607:f8b0:4864:20::232;
Received: by mail-oi1-x232.google.com with SMTP id u74so14444062oie.8
        for <kasan-dev@googlegroups.com>; Sun, 19 Dec 2021 23:00:16 -0800 (PST)
X-Received: by 2002:aca:af50:: with SMTP id y77mr11164327oie.134.1639983616081;
 Sun, 19 Dec 2021 23:00:16 -0800 (PST)
MIME-Version: 1.0
References: <YbHTKUjEejZCLyhX@elver.google.com> <20211209201616.GU614@gate.crashing.org>
 <CANpmjNN4OAA_DM_KNLGJah3fk-PaZktGjziiu8ztf6fevZy5ug@mail.gmail.com>
In-Reply-To: <CANpmjNN4OAA_DM_KNLGJah3fk-PaZktGjziiu8ztf6fevZy5ug@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 20 Dec 2021 08:00:00 +0100
Message-ID: <CANpmjNM3eSd9sxi-1tV0cRthJ0hudrME8nYdhYP=ttcWDoPNfg@mail.gmail.com>
Subject: Re: randomize_kstack: To init or not to init?
To: Segher Boessenkool <segher@kernel.crashing.org>
Cc: Kees Cook <keescook@chromium.org>, Thomas Gleixner <tglx@linutronix.de>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Elena Reshetova <elena.reshetova@intel.com>, Mark Rutland <mark.rutland@arm.com>, 
	Peter Zijlstra <peterz@infradead.org>, Alexander Potapenko <glider@google.com>, Jann Horn <jannh@google.com>, 
	Peter Collingbourne <pcc@google.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, linux-toolchains@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EhTOwMFa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::232 as
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

On Thu, 9 Dec 2021 at 21:33, Marco Elver <elver@google.com> wrote:
> On Thu, 9 Dec 2021 at 21:19, Segher Boessenkool <segher@kernel.crashing.org> wrote:
> > On Thu, Dec 09, 2021 at 10:58:01AM +0100, Marco Elver wrote:
> > > Clang supports CONFIG_INIT_STACK_ALL_ZERO, which appears to be the
> > > default since dcb7c0b9461c2, which is why this came on my radar. And
> > > Clang also performs auto-init of allocas when auto-init is on
> > > (https://reviews.llvm.org/D60548), with no way to skip. As far as I'm
> > > aware, GCC 12's upcoming -ftrivial-auto-var-init= doesn't yet auto-init
> > > allocas.
> >
> > The space allocated by alloca is not an automatic variable, so of course
> > it is not affected by this compiler flag.  And it should not, this flag
> > is explicitly for *small fixed-size* stack variables (initialising
> > others can be much too expensive).
> >
> > >       C. Introduce a new __builtin_alloca_uninitialized().
> >
> > That is completely backwards.  That is the normal behaviour of alloca
> > already.  Also you can get __builtin_alloca inserted by the compiler
> > (for a variable length array for example), and you typically do not want
> > those initialised either, for the same reasons.
>
> You're right, if we're strict about it, initializing allocas is
> technically out-of-scope of that feature.
>
> So, option D: Add a param to control this, and probably it shouldn't
> do it by default. Let's see how far that gets then.

Just an update: after some discussion, the Clang side says that
alloca() is in scope, because the intent is that trivially initialized
"automatic stack storage" should be handled by ftrivial-auto-var-init.
And alloca() is automatic stack storage:
https://www.gnu.org/software/libc/manual/html_node/Variable-Size-Automatic.html

So currently it looks like the builtin is the only solution in this case.

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM3eSd9sxi-1tV0cRthJ0hudrME8nYdhYP%3DttcWDoPNfg%40mail.gmail.com.
