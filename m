Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQ55RH5QKGQEWSOEXSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 63F5126C883
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 20:51:49 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id y26sf4318648pga.22
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 11:51:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600282308; cv=pass;
        d=google.com; s=arc-20160816;
        b=CA1CkYDyB0d180Z7BIDqLUEkaCxshyqrzfCY2VIwWC5bUrXt2yjfxjFRU3r6m3dJtu
         +P6c0H6EDrcGcySh34qXbIOrnav3BZVvOsGTqVQF4VuUDuwd7FebEVIEY2YDCNRfVu1y
         FIJezsV82KYaxi7x3khz5KWtDZR4X0ik3C/wDK54OjhS83KGgvLuc6Wx5gNjLlx+gYhc
         aUkRVWiOdC5JyGV7U1Cu54K11HDRzhIBUtvT1fyGC/PwA8QILupHUQs7XsDAxFTBLz59
         rEGQnUR9T9JPdfCVD/5l0mJo//rSH+Q/NGtrPIb2aVTOXJyNQlycEDsjaRfQJIiETkyr
         +irw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j6ZyaOBfznRwZ7WxSnXjs0lR24TdtoMzc87I4w8v7Zs=;
        b=qQ3SHyhPBcLYqRjlBUGz5T5Py2v45gFIp5ZqcLSciwZ7h+0shASuMC8vS/uqBrjxnn
         udRBmI1G4yqYMnvpJvNdF7OZCtM3w4l/GbBGuHYZ9g5aSbdqKopLbFJPjrs3vcPO5BtN
         KA6QUOPe70Tg/PsDqzCSRslP+0rF0rWWMVGjZrOIn2SMuZgzkJJloX4COw3grN1QuRsw
         D+z3dvCvOUs6Xn8XKJ2kvJAF89rqYGU0hfhno9lPhP1yCN7KMSoPCDDd5NNa3y8G50OU
         CouQCw/fThKkkrWk7hze1BZ1HbjzDZxJg+3xhW60Qajp2JnT8lHmTG/w6Yj39OyiXYuX
         iPpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lj8dJnoA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j6ZyaOBfznRwZ7WxSnXjs0lR24TdtoMzc87I4w8v7Zs=;
        b=e4ucwBil8P4VjH69iUjFQPKw+l2KwP0NDmkHirmjoH41viaUjbjcybK0G7bi6cARS7
         n+17UGv2BGe9sgNsOBp41bj0BDnj1hUPW44qP0SpC4aItVgbPCP+VQxoU3lHhBRF6ifX
         JhnIbuoR20ie4k0Z1xwvgtCIYHD2R93NvkR6Ap3fZXyoubnwyoPYY5Rxyxuzs7Yscq9Y
         DBqF9ToHMB3dsVb68If6oZY/78F81v766Ng6OSRLbohUq0ZuxAPvoFn8vRlNrd4WcvwY
         91JE/zcDzYOqq4+PUJXyt7X48XbTIFS7vZ54mF3lPGfQ1kSYOQXsQL0vYOmPxzBUNaQY
         5Gqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j6ZyaOBfznRwZ7WxSnXjs0lR24TdtoMzc87I4w8v7Zs=;
        b=oKPXNhUE118GbEUsrjjQTujVUNBvpdLMmwixBkH9dQNJYoNtp5w6miRsslkcI4SKVl
         60ddD7c65LDZYZpnA/KGo6XYIGeQLA8llmLPRbRar2IHw/BsHwa9LlT+MDVeCEoKgueZ
         Emmm2yRRI5Ky3hI+qptVbWfhmEAf0Z/eHbS9q9U93d1oSn9UqPKUJZjpH0b/3L4LlD3n
         njwISvYWBZet1uF0vdibpJOs0TFY+FOR/OaodBG/oRiZQJSwAIrLuuLIv77TTpm/Rra2
         8pNR6PFIw17dHnacxCLEzx92uXFgjiGAjdIk8pdeVmyJVnXoMZNcUe7CaI4N69CMPSNz
         Avyg==
X-Gm-Message-State: AOAM5317gSkyvlccWyitYvYwt2MRIMnleJIlkbLAXNeU5dhr1WS1TJzW
	ufqqKhAyF52by19fPRr+4hY=
X-Google-Smtp-Source: ABdhPJyWYSJc1ntQx6N/Wfqux7JXuDvcvkqxm3fkl5J8JIcxsGJaFcHvQ2mj4I2SkjFMRgZTQHBF4Q==
X-Received: by 2002:a63:3441:: with SMTP id b62mr19420718pga.191.1600282308026;
        Wed, 16 Sep 2020 11:51:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bc89:: with SMTP id x9ls1482723pjr.1.canary-gmail;
 Wed, 16 Sep 2020 11:51:47 -0700 (PDT)
X-Received: by 2002:a17:90b:408b:: with SMTP id jb11mr5477059pjb.164.1600282307328;
        Wed, 16 Sep 2020 11:51:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600282307; cv=none;
        d=google.com; s=arc-20160816;
        b=npYV+vckdbJokc6wpjGXFW82+stC1X+LkJvhz2OE+9WCB3ORv8tOCNaZ3RFoTEld+q
         +dFm2eMolK9MqH3Eeqmq8TSD/D07vnVY5JLiTT3lY36dPBUQF8Svl8q3nfAuBYgFcirT
         83a54qGfdsycbX7YgkemF9PJHN9AYjb7pQfpQhwPRYLYUSLOT3EoGYBX0p5vVNNbteEy
         lnYOJXziFbtsaJrs0iI2gKoFrhSqfszt/s+c4Onge4vo/Y3f/6/jd2ImPvTo/+aogRfH
         QMoozWNnJ3zIe3j9WG4rmwr5jOCbrsE8Gf47jy/jiATvzX02O7gZKAz+Ys7gdyk79CE2
         qgmA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4+WHdAVlCFgmzmA4En+naGrx650M8JLZGe/WluGaEDs=;
        b=Dg3n7z3OBGquCOMCoZXRXSBtlThsRuybrxACkiMelio6LmQdwYrsYEiRWNiDREIKc1
         2txvltWsKweCPPljqNckscidw/BysbAI3Vj/BxFw8ZNH4S+FYdjCgDA0cAl1gtp272Zy
         3XlKYf+8VOVslv5uHVtokwksxkS0EBzeD/Zme2auBdRgd4VTJe+H/tLrSYeUoY5Pt462
         QWMkOCPtYVtf5z1V1Vt0cZR04HH8zb8tNMVsLmdGP0M8Vn3AIrkhVCg5/lzDA5LjQ2Iy
         QNBh23Fiq2wsNr3nOSFZ8n73SkhfGokgPwRSUHMfzTkesG3B5tmVDWt1FeokD4S0A+Un
         x7WA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lj8dJnoA;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22d.google.com (mail-oi1-x22d.google.com. [2607:f8b0:4864:20::22d])
        by gmr-mx.google.com with ESMTPS id y1si202315pjv.0.2020.09.16.11.51.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Sep 2020 11:51:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as permitted sender) client-ip=2607:f8b0:4864:20::22d;
Received: by mail-oi1-x22d.google.com with SMTP id c13so9282305oiy.6
        for <kasan-dev@googlegroups.com>; Wed, 16 Sep 2020 11:51:47 -0700 (PDT)
X-Received: by 2002:aca:3d07:: with SMTP id k7mr2932773oia.172.1600282306393;
 Wed, 16 Sep 2020 11:51:46 -0700 (PDT)
MIME-Version: 1.0
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com> <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian> <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble> <20200915172152.GR14436@zn.tnic>
 <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
 <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com>
 <20200916083032.GL2674@hirez.programming.kicks-ass.net> <CANpmjNOBUp0kRTODJMuSLteE=-woFZ2nUzk1=H8wqcusvi+T_g@mail.gmail.com>
 <CAKwvOd=T3w1eqwBkpa8_dJjbOLMTTDshfevT3EuQD4aNn4e_ZQ@mail.gmail.com>
In-Reply-To: <CAKwvOd=T3w1eqwBkpa8_dJjbOLMTTDshfevT3EuQD4aNn4e_ZQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Sep 2020 20:51:34 +0200
Message-ID: <CANpmjNPGZnwJVN6ZuBiRUocGPp8c3rnx1v7iGfYna9t8c3ty0w@mail.gmail.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING e6eb15c9ba3165698488ae5c34920eea20eaa38e
To: Nick Desaulniers <ndesaulniers@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, Rong Chen <rong.a.chen@intel.com>, kernel test robot <lkp@intel.com>, 
	"Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Daniel Kiss <daniel.kiss@arm.com>, momchil.velikov@arm.com, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lj8dJnoA;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22d as
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

On Wed, 16 Sep 2020 at 20:22, 'Nick Desaulniers' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Wed, Sep 16, 2020 at 1:46 AM Marco Elver <elver@google.com> wrote:
> >
> > On Wed, 16 Sep 2020 at 10:30, <peterz@infradead.org> wrote:
> > > On Tue, Sep 15, 2020 at 08:09:16PM +0200, Marco Elver wrote:
> > > > On Tue, 15 Sep 2020 at 19:40, Nick Desaulniers <ndesaulniers@google.com> wrote:
> > > > > On Tue, Sep 15, 2020 at 10:21 AM Borislav Petkov <bp@alien8.de> wrote:
> > >
> > > > > > init/calibrate.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > > > > init/calibrate.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > > > > > init/version.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > > > > init/version.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > > > > > certs/system_keyring.o: warning: objtool: asan.module_ctor()+0xc: call without frame pointer save/setup
> > > > > > certs/system_keyring.o: warning: objtool: asan.module_dtor()+0xc: call without frame pointer save/setup
> > > >
> > > > This one also appears with Clang 11. This is new I think because we
> > > > started emitting ASAN ctors for globals redzone initialization.
> > > >
> > > > I think we really do not care about precise stack frames in these
> > > > compiler-generated functions. So, would it be reasonable to make
> > > > objtool ignore all *san.module_ctor and *san.module_dtor functions (we
> > > > have them for ASAN, TSAN, MSAN)?
> > >
> > > The thing is, if objtool cannot follow, it cannot generate ORC data and
> > > our unwinder cannot unwind through the instrumentation, and that is a
> > > fail.
> > >
> > > Or am I missing something here?
> >
> > They aren't about the actual instrumentation. The warnings are about
> > module_ctor/module_dtor functions which are compiler-generated, and
> > these are only called on initialization/destruction (dtors only for
> > modules I guess).
> >
> > E.g. for KASAN it's the calls to __asan_register_globals that are
> > called from asan.module_ctor. For KCSAN the tsan.module_ctor is
> > effectively a noop (because __tsan_init() is a noop), so it really
> > doesn't matter much.
> >
> > Is my assumption correct that the only effect would be if something
> > called by them fails, we just don't see the full stack trace? I think
> > we can live with that, there are only few central places that deal
> > with ctors/dtors (do_ctors(), ...?).
> >
> > The "real" fix would be to teach the compilers about "frame pointer
> > save/setup" for generated functions, but I don't think that's
> > realistic.
>
> So this has come up before, specifically in the context of gcov:
> https://github.com/ClangBuiltLinux/linux/issues/955.
>
> I looked into this a bit, and IIRC, the issue was that compiler
> generated functions aren't very good about keeping track of whether
> they should or should not emit framepointer setup/teardown
> prolog/epilogs.  In LLVM's IR, -fno-omit-frame-pointer gets attached
> to every function as a function level attribute.
> https://godbolt.org/z/fcn9c6 ("frame-pointer"="all").
>
> There were some recent LLVM patches for BTI (arm64) that made some BTI
> related command line flags module level attributes, which I thought
> was interesting; I was wondering last night if -fno-omit-frame-pointer
> and maybe even the level of stack protector should be?  I guess LTO
> would complicate things; not sure it would be good to merge modules
> with different attributes; I'm not sure how that's handled today in
> LLVM.
>
> Basically, when the compiler is synthesizing a new function
> definition, it should check whether a frame pointer should be emitted
> or not.  We could do that today by maybe scanning all other function
> definitions for the presence of "frame-pointer"="all" fn attr,
> breaking early if we find one, and emitting the frame pointer setup in
> that case.  Though I guess it's "frame-pointer"="none" otherwise, so
> maybe checking any other fn def would be fine; I don't see any C fn
> attr's that allow you to keep frame pointers or not.  What's tricky is
> that the front end flag was resolved much earlier than where this code
> gets generated, so it would need to look for traces that the flag ever
> existed, which sounds brittle on paper to me.

Thanks for the summary -- yeah, that was my suspicion, that some
attribute was being lost somewhere. And I think if we generalize this,
and don't just try to attach "frame-pointer" attr to the function, we
probably also solve the BTI issue that Mark still pointed out with
these module_ctor/dtors.

I was trying to see if there was a generic way to attach all the
common attributes to the function generated here:
https://github.com/llvm/llvm-project/blob/master/llvm/lib/Transforms/Utils/ModuleUtils.cpp#L122
-- but we probably can't attach all attributes, and need to remove a
bunch of them again like the sanitizers (or alternatively just select
the ones we need). But, I'm still digging for the function that
attaches all the common attributes...

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPGZnwJVN6ZuBiRUocGPp8c3rnx1v7iGfYna9t8c3ty0w%40mail.gmail.com.
