Return-Path: <kasan-dev+bncBDYJPJO25UGBBV5PRH5QKGQENTEN2SY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 664D126C740
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 20:22:16 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id a72sf3255046oii.12
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 11:22:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600280535; cv=pass;
        d=google.com; s=arc-20160816;
        b=EJMRwOWLUxKvCkA1xLiaJcyid7NysTAFKleaYRZCUjCs8amyG8IPXBtgD3tYIE5LbV
         qq1yIYmk9wzSg4YUxHP3DRapXQL39INaBlhZ2DD9+rK3r/iP9a1400cysZBoUUhZgKwb
         c1yXc8W5AA/qXlDAilMYvUYWdTMHTK6zRn8p77LpeGNVrKl8aC3sFoKk6eabdg46dt4T
         mbkJn//1a+e5WkSMtfn93CPMHwiqPUiFP8S/d2MSHw6i3aw3Q9T6NJtdEBGAUKohls06
         m0VlQckG4zLe5d09YPTUPDEMKtoqtipdyjhZiKrCFS73xJwLigSk6F6gn7/OasV1hW6o
         mt+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=C11jAZsw9LTtuugtdTCDPJ9aLp0LRYKLs7LyvRFeI64=;
        b=ORrBhCB0+ol6Svrq49lqvsHV+L6sIo/z4EmAJbJQtr/rTvEG2djsFXrmHOJT4SrG40
         Xos3XE4TI4tEozGkFJbtpAyXYAWbTFjZBH2sXBT9OZzNh77rvyE3U3wKXsQ9Jzyd5iW9
         FYfZWYQHe5owsdSdotPxvQmm/QNj/ZrDuLCC9Wn5aplxGCQKAcqmldPrRGkfI/oxvY7P
         mSlO5D3Q1Xe470aOPqi+RBWqBiNxX8XRZb0gSrr6G4BqHk00ktGBXtNrM2TYVfJMNA/R
         +MT9Y6TSQW3BpQgU1FGz+hJ/Z2rRfrRGupfLYfvllK6ywsAsdfgN/LUIQHRwkboj68tm
         lN1g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uaTByqfC;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C11jAZsw9LTtuugtdTCDPJ9aLp0LRYKLs7LyvRFeI64=;
        b=hbGyJV8MFHSY/n8fVq9TMzTvfL9ZwjrA1kugphJPwRGX93NNftM4NSRUouVdKle5uB
         5bm7FB1DA7LH+Dk/pQjJFemEX/UpKmV0wT1MXM3y/aLsSu+zx2VjThwxEO2sp2OypE1V
         YphflDet+xKsyozvCoydlFB3tX3+ZfefbNtd6cc6qZhXOTVZSX2yYXj7gpIr+AFmpZRR
         ob5+UVR+3x015SLCv+VYiJk07q1s/hmn0pzNQ6lu9f2iBomrSJaOtcyjPtyg4U/SPHYi
         AhxMxneWNgCQvfQiRAkIAHveAOHFYo07KEEJvx+6lQErgKckJkCDVJCHvKOnyZ6ohaaO
         TxNQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C11jAZsw9LTtuugtdTCDPJ9aLp0LRYKLs7LyvRFeI64=;
        b=MJE7tvKTzIkaO3gG4E9DVnAQ8T6KOQ0WBpOhgecceEFlUqPQ3HD3hinSCtEWTWdxRK
         DqmUfAgkEisNOWoHu445914fC/ld+QPM4Kt+xk4FNX6TCv4bOmKiACkiLnUD8I9YSl9y
         7NwA/MKKRhiYZmSdODuMd4m0MRhKfMXEynsKrR9EZ6vxObnWmsYJmS/Ic0YiP3xP0rAy
         dYO/k146ss6CvKFbw5jb0i7012dvNgqYmeRVr989MwyDB15/kYG52ihgwXaXZ2Rjkzap
         pNb9WqOcjiJnKhnusak+OaTAHnkhqO1cv0dO6Q916AfiygwHS9z294OxF8pgE+/9i2o/
         +LuA==
X-Gm-Message-State: AOAM5323BCdwImKy2THDC7IuhkP6V0EmM6gC2EtR2GjGLHPf2KeAMdp7
	FUQ41RV6AFvu2lXfmVGThu8=
X-Google-Smtp-Source: ABdhPJxTqAxL9TAJfXDExhiDJ9ulnOMi/+Dj8aUpx7wRpE3lLINZ5hfQEctbWzfSs6aBR3SLgodSwQ==
X-Received: by 2002:aca:538f:: with SMTP id h137mr4136062oib.103.1600280535201;
        Wed, 16 Sep 2020 11:22:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4d2:: with SMTP id s18ls712770otd.0.gmail; Wed, 16
 Sep 2020 11:22:14 -0700 (PDT)
X-Received: by 2002:a9d:32a1:: with SMTP id u30mr14443322otb.55.1600280534877;
        Wed, 16 Sep 2020 11:22:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600280534; cv=none;
        d=google.com; s=arc-20160816;
        b=HnEFlO8pTeRzOboZClvwrZkhvAAXg6AkdZSbdua2ajndjivrZSnvgyNDMPauuCKap/
         Wv+PBySsMS/RBVY0XLM5dL/J2OHFwx08F97Tk5Baxq26Dnm+PIWy19z7c/aKixFlt16o
         FpJvFh+gEH6hXScu5mqzYH8FapEFML+dSXlekfaq3eqYuewhd9MgPG1u3zunG06I2yAi
         5Vggsrf2ygrR8R+pCQmarhFkxO7oLJBqD7YIDEVD3WJnbohKctYJxZb6PxjkTeScDmEm
         qh7ETxVZ9hCuDJcwbhcjlxbcdFP9/8NgH+R8FQFTFG4Y3PuAI16aCN37ubAfz4jS5vzS
         T1Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G4+iKrUyandKRtKRuuCLFiJQwudPWpGc6jdXc33Pspo=;
        b=lZI3Ig05VqJGgAmEP4+ww71x5DKm2giVVAuufGL54S6Bo8c0Em0x8Z0+OWjmeQOu0R
         jwhApeQ7Zbf33A5pGweBmdEwl17QG01RsWZPsSakPWV3970fBuTpq6q5IQ2p+W2OciGC
         sesim69HxXtYi5sl2Flm6k12YauIqWLqmzfZTgASLyPr/Iy7yuT/2Epdv050gASNA+v/
         81wGSzRWbj/bidbIZRptKFowF3kbOoygwaRn5JCSTKqFyLPkKBUFUlMjyCqBkvZIfHML
         Vr9LNwamSKKf9ukhgxS/SCL+LChH8wanc7AIXlR8WjVw5v0jTDqsR5PXAvzo5on44jYL
         wPIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uaTByqfC;
       spf=pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=ndesaulniers@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id k144si1136654oih.5.2020.09.16.11.22.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Sep 2020 11:22:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id bd2so3640024plb.7
        for <kasan-dev@googlegroups.com>; Wed, 16 Sep 2020 11:22:14 -0700 (PDT)
X-Received: by 2002:a17:90a:e517:: with SMTP id t23mr4866165pjy.25.1600280533846;
 Wed, 16 Sep 2020 11:22:13 -0700 (PDT)
MIME-Version: 1.0
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com> <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian> <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble> <20200915172152.GR14436@zn.tnic>
 <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
 <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com>
 <20200916083032.GL2674@hirez.programming.kicks-ass.net> <CANpmjNOBUp0kRTODJMuSLteE=-woFZ2nUzk1=H8wqcusvi+T_g@mail.gmail.com>
In-Reply-To: <CANpmjNOBUp0kRTODJMuSLteE=-woFZ2nUzk1=H8wqcusvi+T_g@mail.gmail.com>
From: "'Nick Desaulniers' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Sep 2020 11:22:02 -0700
Message-ID: <CAKwvOd=T3w1eqwBkpa8_dJjbOLMTTDshfevT3EuQD4aNn4e_ZQ@mail.gmail.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING e6eb15c9ba3165698488ae5c34920eea20eaa38e
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Rong Chen <rong.a.chen@intel.com>, kernel test robot <lkp@intel.com>, 
	"Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Daniel Kiss <daniel.kiss@arm.com>, momchil.velikov@arm.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: ndesaulniers@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uaTByqfC;       spf=pass
 (google.com: domain of ndesaulniers@google.com designates 2607:f8b0:4864:20::62b
 as permitted sender) smtp.mailfrom=ndesaulniers@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Nick Desaulniers <ndesaulniers@google.com>
Reply-To: Nick Desaulniers <ndesaulniers@google.com>
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

On Wed, Sep 16, 2020 at 1:46 AM Marco Elver <elver@google.com> wrote:
>
> On Wed, 16 Sep 2020 at 10:30, <peterz@infradead.org> wrote:
> > On Tue, Sep 15, 2020 at 08:09:16PM +0200, Marco Elver wrote:
> > > On Tue, 15 Sep 2020 at 19:40, Nick Desaulniers <ndesaulniers@google.com> wrote:
> > > > On Tue, Sep 15, 2020 at 10:21 AM Borislav Petkov <bp@alien8.de> wrote:
> >
> > > > > init/calibrate.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > > > init/calibrate.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > > > > init/version.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > > > init/version.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > > > > certs/system_keyring.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > > > certs/system_keyring.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > >
> > > This one also appears with Clang 11. This is new I think because we
> > > started emitting ASAN ctors for globals redzone initialization.
> > >
> > > I think we really do not care about precise stack frames in these
> > > compiler-generated functions. So, would it be reasonable to make
> > > objtool ignore all *san.module_ctor and *san.module_dtor functions (we
> > > have them for ASAN, TSAN, MSAN)?
> >
> > The thing is, if objtool cannot follow, it cannot generate ORC data and
> > our unwinder cannot unwind through the instrumentation, and that is a
> > fail.
> >
> > Or am I missing something here?
>
> They aren't about the actual instrumentation. The warnings are about
> module_ctor/module_dtor functions which are compiler-generated, and
> these are only called on initialization/destruction (dtors only for
> modules I guess).
>
> E.g. for KASAN it's the calls to __asan_register_globals that are
> called from asan.module_ctor. For KCSAN the tsan.module_ctor is
> effectively a noop (because __tsan_init() is a noop), so it really
> doesn't matter much.
>
> Is my assumption correct that the only effect would be if something
> called by them fails, we just don't see the full stack trace? I think
> we can live with that, there are only few central places that deal
> with ctors/dtors (do_ctors(), ...?).
>
> The "real" fix would be to teach the compilers about "frame pointer
> save/setup" for generated functions, but I don't think that's
> realistic.

So this has come up before, specifically in the context of gcov:
https://github.com/ClangBuiltLinux/linux/issues/955.

I looked into this a bit, and IIRC, the issue was that compiler
generated functions aren't very good about keeping track of whether
they should or should not emit framepointer setup/teardown
prolog/epilogs.  In LLVM's IR, -fno-omit-frame-pointer gets attached
to every function as a function level attribute.
https://godbolt.org/z/fcn9c6 ("frame-pointer"="all").

There were some recent LLVM patches for BTI (arm64) that made some BTI
related command line flags module level attributes, which I thought
was interesting; I was wondering last night if -fno-omit-frame-pointer
and maybe even the level of stack protector should be?  I guess LTO
would complicate things; not sure it would be good to merge modules
with different attributes; I'm not sure how that's handled today in
LLVM.

Basically, when the compiler is synthesizing a new function
definition, it should check whether a frame pointer should be emitted
or not.  We could do that today by maybe scanning all other function
definitions for the presence of "frame-pointer"="all" fn attr,
breaking early if we find one, and emitting the frame pointer setup in
that case.  Though I guess it's "frame-pointer"="none" otherwise, so
maybe checking any other fn def would be fine; I don't see any C fn
attr's that allow you to keep frame pointers or not.  What's tricky is
that the front end flag was resolved much earlier than where this code
gets generated, so it would need to look for traces that the flag ever
existed, which sounds brittle on paper to me.
-- 
Thanks,
~Nick Desaulniers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKwvOd%3DT3w1eqwBkpa8_dJjbOLMTTDshfevT3EuQD4aNn4e_ZQ%40mail.gmail.com.
