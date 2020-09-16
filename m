Return-Path: <kasan-dev+bncBC7OBJGL2MHBBAVYQ75QKGQEMTKDKMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id 1852426C0AA
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 11:33:55 +0200 (CEST)
Received: by mail-vk1-xa39.google.com with SMTP id q69sf1344139vka.12
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 02:33:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600248834; cv=pass;
        d=google.com; s=arc-20160816;
        b=got2UotXgv5yDE0HW5I3e3/8YlybIJ28sCkEkocIhReUe9pK374LtRnpdPbvA13Xil
         KrQglQJV9xnHaYcjQU2qgTxOil61/Jh5LvlgfHApWaDkzJ5oANunj9p0Q3W3oWkc3YxH
         oGgK7zQ+PwezR6+oiyH8iX2PFTHzSLaD9+Nzyi90cWfWryNRiu9/k4YQXpgmBzYJgi/h
         wgzFHyxeDILp1OElJF3f3zk9fOCG+bePwL7Dm+Xfo5DsJs70/swkoxEgSqKj+gfuJMq6
         FQEH+qvVzuGy/moCjfjEIGkG/JQHbi39OIWi+HciYzE+LMwagJ3/1Y4LzUY0FaE5k+n9
         OEXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=mvRkwQ3B/oE1fg359tsGFrHZRADdDKpzw4rq9JHiwxM=;
        b=rrToJaS7JfesUREiqexFkxeVFbfxoJE9P1jekB3jFxrcUeOkb6pCdJywXtwTKmm0Eb
         O8ZDj+lCxiGIsq66lg2U6kqTUnWYIJR5r5IrDNBmXzO7kgdROaKEZun9Hm0TDefYyirb
         icEkOxG64dwDtDl8kqcbctKUD8qWxePrJW4tp23NWbAVzJBkbgJL7obMhgemyAv1+YzK
         7cCSmoAnaSUarEZDQ3WZJjEE+Wwi5iAgOpPyQWwHJVNDrTpwpcckp9VQaSfV4Yl8xT8L
         sufLyH29WYB//ceGK/N5lvtNv8ltlWYaUiRtonVimoFG5o9GdoYwS9bNonypwSkCzD/8
         tOZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b9Tdi+x3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mvRkwQ3B/oE1fg359tsGFrHZRADdDKpzw4rq9JHiwxM=;
        b=tcQTv3/u0Sz2M/Vwd45nwpbJnUMKlNMwMIq+mu3jUK5ZD3b77FoszAsEwYrCNdijAg
         b643Uq83VyL6i+09kfaovI2lUmE3lOUl16pWKq5+U+0o8zayj3XvDOgMKVGkQB2cXQ3Y
         BGb4DKV7OJDUiZBEeHE6wiRj832IIT2V8sQMzkHsfnxZ2BY3QY7aJQ+qmghNEBtwkqmD
         9/EJ31a3RHXxAZyxI77FfImP3fSt/24u+D8OQjoPBXXwmkAr2HJkJwRfKbtht2MJh2NQ
         XH0fwSF2SCkXJIDHtRmRx6LgCzj/kqzAdJcvEFkwPROycLmoT4Wz1ju6rT4gaJHVs+8+
         neyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mvRkwQ3B/oE1fg359tsGFrHZRADdDKpzw4rq9JHiwxM=;
        b=IQK7werTsTncKc6uvBM0fM1FPg2eii8ILWfq8UAcwTZ5qYLigh2CDYhZYAPgfuYIBF
         ZqOAZxexfRqbKhSuxwHpTfES62qk0RToLmOwt9p8d0uyaawWAz1pocNWV3QO1OZh9D+E
         oUErFUXrfJD/d6NaeHWNmzuXirHKo8HBtClyB9hewxKSZoeWUI/g2Q8Sk4QbkheTeqr3
         bNNpCrBZ/8D2AWdqOek3eUj2kfvldNy0kqnDigpqc7Ak4xtIdXDp7zj63rMgFZlcjTIe
         +Jq/qBtUBGMAnMIkFV7mOTp4XLeJDRnavTMuBCjwTEXm1PND3e3pOyJQGwixcXp+/8P7
         tD4g==
X-Gm-Message-State: AOAM532BZF1oIrK0o9UzTw55zPCECMv9efRvTps/HdilEvVtFUFKRdDn
	4kWsjxk2vSOEc76BQ3ZBIQA=
X-Google-Smtp-Source: ABdhPJzcQ5sTsm7O/WuPRx+UnC/yG9i+E9Immvt5FQaYs97dtRWQ4XZJ8u4L4jC8c3ZfvHpv1uR2Yw==
X-Received: by 2002:a1f:17d2:: with SMTP id 201mr4005645vkx.22.1600248834146;
        Wed, 16 Sep 2020 02:33:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:f259:: with SMTP id y25ls172657vsm.8.gmail; Wed, 16 Sep
 2020 02:33:53 -0700 (PDT)
X-Received: by 2002:a67:fe81:: with SMTP id b1mr14025534vsr.5.1600248833625;
        Wed, 16 Sep 2020 02:33:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600248833; cv=none;
        d=google.com; s=arc-20160816;
        b=f8t0gS/lIDVxG1w9fkIjD8zTE7cnKpX2WRhvs0CxNq6NOJfyZZKM6ayZ7e4zz+uMLd
         21hZSalM5zy0pwFrfnPhdFOwm3+nFMmzhd98EF27r8vY0a1UnbvFdn5uhmZ+6l2kkfhi
         q1PUBOAGvuQcwooigtsIlk8rICAjkU2+5j8fTgL4mBG3DKAp96NygS4WVdF8QMequ44k
         GGXPNXmbE0LnY8RzLw6E/4ES9lYCnzTfcc9ez6TNZBtu1xpH+PZZO6ZGSPS5oc9zBETl
         FVHZd0/rr0XewADX927lN6fnBsBLuqDRWzuhGvV/GqSXnh5A8+Jpyaf/qo+jt0t8zZYK
         W5Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+69jB+wV3csf3KfbgPgpUDFiF1twt7Lc/K19h4NVXE8=;
        b=dWOCW+1efzKb65FBzC5LmIhcLHsfkeFYLtfqVMqusmEL5y0kt8yujQa34m/QpuKcRI
         gXEDsM0zk6mYoocOsitsF84u01f84T48BTaUdbzeeth57vtnOCtaAm5Gg6JXJzbqCxjD
         mKtRjzBbEpfOEz7Kgw0G2nhZ14ZSnuxqHZYUTIsV49fyRGLjS923WhJqBOevhl35eEMj
         dbzkp0T9ifnJ7QwSjgeuso4Eg8D8qmK7caQM45B2JzW2o0JRwyPPD/LXzMzPYK4eTxfd
         GjCnN3ANg1KC708AlZ7BAmYilJVJPL1sCZa9NC0RARTM/uGdaxJpRvZoAHIgx2CDXGkY
         fjeg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b9Tdi+x3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32b.google.com (mail-ot1-x32b.google.com. [2607:f8b0:4864:20::32b])
        by gmr-mx.google.com with ESMTPS id p129si1036725vkg.3.2020.09.16.02.33.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Sep 2020 02:33:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as permitted sender) client-ip=2607:f8b0:4864:20::32b;
Received: by mail-ot1-x32b.google.com with SMTP id o8so6088617otl.4
        for <kasan-dev@googlegroups.com>; Wed, 16 Sep 2020 02:33:53 -0700 (PDT)
X-Received: by 2002:a9d:758b:: with SMTP id s11mr14889445otk.251.1600248832924;
 Wed, 16 Sep 2020 02:33:52 -0700 (PDT)
MIME-Version: 1.0
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com> <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian> <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble> <20200915172152.GR14436@zn.tnic>
 <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
 <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com>
 <20200916083032.GL2674@hirez.programming.kicks-ass.net> <CANpmjNOBUp0kRTODJMuSLteE=-woFZ2nUzk1=H8wqcusvi+T_g@mail.gmail.com>
 <20200916090620.GN2674@hirez.programming.kicks-ass.net>
In-Reply-To: <20200916090620.GN2674@hirez.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 16 Sep 2020 11:33:41 +0200
Message-ID: <CANpmjNPnnkfkRetEHWNwafP43qjbKypsWxLrBVidrzjrTOCFaQ@mail.gmail.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING e6eb15c9ba3165698488ae5c34920eea20eaa38e
To: Peter Zijlstra <peterz@infradead.org>
Cc: Josh Poimboeuf <jpoimboe@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Nick Desaulniers <ndesaulniers@google.com>, Rong Chen <rong.a.chen@intel.com>, 
	kernel test robot <lkp@intel.com>, "Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	clang-built-linux <clang-built-linux@googlegroups.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Kees Cook <keescook@chromium.org>, 
	Masahiro Yamada <masahiroy@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=b9Tdi+x3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32b as
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

On Wed, 16 Sep 2020 at 11:06, <peterz@infradead.org> wrote:
> On Wed, Sep 16, 2020 at 10:46:41AM +0200, Marco Elver wrote:
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
>
> Not only fails, lockdep for example likes to store stack traces of
> various callsites etc.. Also perf (NMI) likes to think it can unwind at
> all times.

That's fair, and I would also prefer a proper fix. :-)

> > The "real" fix would be to teach the compilers about "frame pointer
> > save/setup" for generated functions, but I don't think that's
> > realistic.
>
> How is that unrealistic? If you build with framepointers enabled, the
> compiler is supposed to know about this stuff.

If it's a bug in current compilers, it'll be hard to get the fix into
those. My suspicion is there's a bug somewhere. We can try to make new
compiler versions do the right thing. Or maybe we're just missing some
flags, which would be nice. I'll investigate some more.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPnnkfkRetEHWNwafP43qjbKypsWxLrBVidrzjrTOCFaQ%40mail.gmail.com.
