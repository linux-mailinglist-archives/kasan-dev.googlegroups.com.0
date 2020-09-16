Return-Path: <kasan-dev+bncBCV5TUXXRUIBBENLQ75QKGQE373AB4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id E1DF626C018
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 11:06:26 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id j5sf5549954qka.7
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Sep 2020 02:06:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600247186; cv=pass;
        d=google.com; s=arc-20160816;
        b=XFps6ssAjFFJ13Rk8jhvGkX8L9OKmgMpJAozeBlmkCPN2cO/PYfvpTDVd6F26ao5Ic
         zlK/WLRWCpHqapRbbVPAGkV3ibwPkofbdKsnkNOn9xcdmha5+5FXnAY6h2tWQPTwPVyd
         dkX8KyOb+64uXGRaMKEwH5vuqxhARlObr4U/7HK/Jzqrp37n0KsNmmwXeYLtqjQmDr1Z
         m2Z/GXzG7RbpVNK6RHbdKQnd4BIFzH/aI9EySuA1hCSCq8vrtsqDC900cm7Yp+fDZtRm
         ArcM3BgDk1iZXYkNJl2WMMVbOAAl5TjOo7ugPqq+cZerHpWLn/ORjqtLIAgGqOEyG7+V
         r64A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=aTQ2/gp6GpYSXe3fEpyPjFvMEFppJGq36p2tQ4FxymA=;
        b=Y8oc6BmbvJ9u3L0+LQyd/MWIVHigH09EMlWtbkVQ0gZJcpCmLbK0rV1DJF+fdN3upk
         sEKiPry/pva5kT/affxtKIWlCFAhaKJKoiPoYM3ASQkiB5YLB3S7bP1rZ8Ym/eHncc62
         mMn9OeOuI7Db1VNQMs4KyIflJiaBdHXmzjIwd2O6JxMES7bh3EAXqd4WOQpEhwypXgIb
         F/PA0914RblxMF2uedYVT8WV1zGQuwQxPWns2UB2d8eq03SVex4cOswVAuR9UG4XZzIB
         l/Be7iuAhFuXNLuSoPwIENva0/ckhqqCk2ks0Ce9pZn5+1SXEcdd1WI6u1HuLhFdPP76
         zbpQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="fEezQmk/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aTQ2/gp6GpYSXe3fEpyPjFvMEFppJGq36p2tQ4FxymA=;
        b=R0F30ICMadXUQ+ePOwmC80SBdWnHXO0LLrO8yXzLL2+HVH7K5EjBmOI+KrGp0gmPQP
         qf8gvSMOJrdEpGK1AG3wqvzYb984PMSW3Z7EZ4vinuc9bPal8jj6kl90nhjG74GqZH9s
         CAxX1zvjUFCWgvtJ06yqrBJZ4VB9HzU/vStIKwJJmVc9+8uni/8IeZ6ISgXFfwnAJ+/y
         C7GguCsE3XyUkZBYELE1wI27s7+pJGJdLapnifHkZCSmhvg8HLp1MIf3kllWGZn8+xCa
         RBng7pnJaxb81Rc4rdAQnhJK+jfc9L9aPFUritorhT0lBgfOfse/p5ma7LY1KJhS35os
         QnAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aTQ2/gp6GpYSXe3fEpyPjFvMEFppJGq36p2tQ4FxymA=;
        b=GzRM4XRi5eLLbrEAM8VNMv3SR+nCCc6amDs8J091+6aUBF4KNOc80nNm2FbqoYB3AG
         H9bYMOVaOo73T9Z4pZe+9fD5C67yI8gnrIj7cLtyvZhwUow94FQZ2qkr7+tZXfGcdyFg
         d14kD6+Xpa71MZxtH7Wqew06FtNI0Y3ZQL+mNfnHhuWkioLcssKAITr8CtRvaRPSMNPJ
         b/dar9HnzpauLvv3ZH2Qqw4bCRh+2mXSRyZaixg4pztktLKQQn4YUGjsEHRGDpoRp3nS
         a+pyhry0dNP267MWiPN4x/BtLGdDOMVlLSq+FzSfwWYuShLojRtZXgrlvtGlXa9CQHfO
         RYcQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533x9cWHy+EtrhGgJ8NSEFH4g61Fv7JaSf35ECG5pLbR4hJ912oZ
	j1V+Hq/9Xk1Ub0jn3arwkVk=
X-Google-Smtp-Source: ABdhPJwLckRdGDtPqnIjkEtdiVjZDF2rml+LGFFiacy2pH+fFvhnS/aSkWsSk1K8LqANc2YyAyIhFg==
X-Received: by 2002:a0c:f0d1:: with SMTP id d17mr5934806qvl.34.1600247185948;
        Wed, 16 Sep 2020 02:06:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:bd24:: with SMTP id m36ls328931qvg.6.gmail; Wed, 16 Sep
 2020 02:06:25 -0700 (PDT)
X-Received: by 2002:a0c:f984:: with SMTP id t4mr22373449qvn.18.1600247185484;
        Wed, 16 Sep 2020 02:06:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600247185; cv=none;
        d=google.com; s=arc-20160816;
        b=ZFe0POJA0OuhCPdVKREQzT/udbGFXGtCRIuwrq79lmKppcR445TRXghGG1DyctTUMR
         YbEOuLGHjJy37yP7pDOSJPklli6kN6yuLX/iZUxmn0vxQlgbtLklgsfNzyY787Ff8YNI
         VUXE1XPgmDSAFUPIWzzppIG4AdCFaRwEIjkwf1+IzPxZhCCo63aj9aaG9jOGsgo/BBN+
         JyL1AMUJaLMgFcQUdL/mT5vELyCLnvbUWRydfTaxY8zm1oSv2aJSSsPlsW+r82NoX3ze
         X4QlydIVfRMWylTOu32+2jGAAocgx8sLQM4DAVuyez8c31KWIQxpV2PSUC6Cid86IeXE
         d/ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=XGOGWszl2fZU1wbir3hgL3wXW46VrlHkuXhbLpO08Eo=;
        b=hBs/KrXvbzBBSnPWHj/YCUp2534uTEB0ltGY7ReySMhM6QV2wUIYcYOTHTcNhl2s2m
         10uHnPzswhyqz0MM6W08Lr4Cd3u5ggheIyZI5V32+DoiPp5o32hKuujJTWW7yEAnG0bX
         +dXNPVWnbs0OxrxconaliuKlMu6dBZTLhsb+48AJwhuA67x0Rx/+sMODWscppaqLvWNH
         aC7CnrR/7qzBq7kMbewNrTjBqhNw1vPnRyXSNgYn/W+J/R0XfAgYtzl60M8jZPCZkVkq
         01ivpo7r1ntFoWBaafb6d7UBsBF25sJRGFj3JgVsPctdGgfLqbjkpJmiQomktid/mE0m
         5zNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b="fEezQmk/";
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id n26si929735qkg.5.2020.09.16.02.06.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Sep 2020 02:06:25 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kITOP-0006oH-Lj; Wed, 16 Sep 2020 09:06:22 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 4050B3012DF;
	Wed, 16 Sep 2020 11:06:20 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 3012A2149392C; Wed, 16 Sep 2020 11:06:20 +0200 (CEST)
Date: Wed, 16 Sep 2020 11:06:20 +0200
From: peterz@infradead.org
To: Marco Elver <elver@google.com>
Cc: Josh Poimboeuf <jpoimboe@redhat.com>, Borislav Petkov <bp@alien8.de>,
	Nick Desaulniers <ndesaulniers@google.com>,
	Rong Chen <rong.a.chen@intel.com>,
	kernel test robot <lkp@intel.com>,
	"Li, Philip" <philip.li@intel.com>, x86-ml <x86@kernel.org>,
	LKML <linux-kernel@vger.kernel.org>,
	clang-built-linux <clang-built-linux@googlegroups.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Kees Cook <keescook@chromium.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [tip:x86/seves] BUILD SUCCESS WITH WARNING
 e6eb15c9ba3165698488ae5c34920eea20eaa38e
Message-ID: <20200916090620.GN2674@hirez.programming.kicks-ass.net>
References: <5f60c4e0.Ru0MTgSE9A7mqhpG%lkp@intel.com>
 <20200915135519.GJ14436@zn.tnic>
 <20200915141816.GC28738@shao2-debian>
 <20200915160554.GN14436@zn.tnic>
 <20200915170248.gcv54pvyckteyhk3@treble>
 <20200915172152.GR14436@zn.tnic>
 <CAKwvOdkh=bZE6uY8zk_QePq5B3fY1ue9VjEguJ_cQi4CtZ4xgw@mail.gmail.com>
 <CANpmjNPWOus2WnMLSAXnzaXC5U5RDM3TTeV8vFDtvuZvrkoWtA@mail.gmail.com>
 <20200916083032.GL2674@hirez.programming.kicks-ass.net>
 <CANpmjNOBUp0kRTODJMuSLteE=-woFZ2nUzk1=H8wqcusvi+T_g@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNOBUp0kRTODJMuSLteE=-woFZ2nUzk1=H8wqcusvi+T_g@mail.gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b="fEezQmk/";
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Wed, Sep 16, 2020 at 10:46:41AM +0200, Marco Elver wrote:
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

Not only fails, lockdep for example likes to store stack traces of
various callsites etc.. Also perf (NMI) likes to think it can unwind at
all times.

> The "real" fix would be to teach the compilers about "frame pointer
> save/setup" for generated functions, but I don't think that's
> realistic.

How is that unrealistic? If you build with framepointers enabled, the
compiler is supposed to know about this stuff.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200916090620.GN2674%40hirez.programming.kicks-ass.net.
