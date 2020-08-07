Return-Path: <kasan-dev+bncBC7OBJGL2MHBBR72WT4QKGQEOEAREGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id AFA6723ECB1
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 13:38:47 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id u26sf500906lfk.7
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 04:38:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596800327; cv=pass;
        d=google.com; s=arc-20160816;
        b=IMFcsCn80te+aKB0PSAwm45Sy332G+LIVr5TOc3IWLvN65Hfofovhp0eNfaOj8kJuL
         zxbDCCS1rQ+QuvNuT/xHd6YNGTWWvL96GcKhe0ptP7lB9PpL+fr/NBqUDfXGjGqbPejW
         2rASkl0bU4q9Felfz6V7VGa9LZC0XkSv7602aEUmX5a799Gry350VuXcCDSCAlQbZpkH
         9zmwCwMXfBsPFYnTg9uw09PWpLSbPEoS577UeDRScy6G9MOdaR07Nkml8P8MkVpjiVvT
         39f1kU0rYSbevM79uuguKeHHPmsUWa3t7ibusMojPQT/z1HlRgQKrUVj7oYdnaL+huuq
         CLPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=sX3wPqtwIWggEm7LKb5T1kywYALhZGs/pYZeN4IqStw=;
        b=QJzmcJLoJ8mRLjEO91cK/L4QQUzMivAPdL4bx7JSH24uP/q55ijUEwh0rSI8XXiGM1
         D9OnxPlJsVFZVbl9arne8YSzpHM6Q2uMrEfExvbo1F/rQRvaL3CIVY0JXzxv9jQawwHG
         2D7Tx05s0cjP1iM6kPhtFT+mWFNQziWRT88BRBe7ovhVACRPpb+Nc3MvEJ1XOi06tQlL
         rqHnE1jQvxHAwWYDpZhPN7PPJLipqaRW/7BwjD/qxEKvTkc4wek8GTCFV8gbTdVCBPia
         07BR+g6IZgJDdkC0aepX0a7shFYsxYhlm6qHHLt5GLljYcJIRn9RbW5yD4cn64ageD7R
         7/Cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XRsQjOfj;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sX3wPqtwIWggEm7LKb5T1kywYALhZGs/pYZeN4IqStw=;
        b=koiEHejPoZ/jryBhtQnhUomypwl95bmlGcZJosK5vUQoWM15Zfr/hQR6OsJen1naXH
         GtAf9r5M8bKfBBsiKYMLt3K1jmo8DYXCJvpsZ6hsNvY16aRIVdyhNg27oB7gOuaz5GZr
         mHXuXrvGPSNNACzdsJPEaDVhJqEizR+KLvBWCxShnwWxi4OlzjhFlXK1R+0UMaziXp53
         307li5Ntbp0WJ9LpG36i8TH5w57DNIr6dlvCL2SpYaWPybh0jC4eKqXLtbRD/3D9htZ4
         jDTnPpYASMMdGVdE7kfHvZeTlOvSqS1bfk0vX6qXoM9+RTNz/QsjB89c1zew7+pLf+Tw
         rInA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sX3wPqtwIWggEm7LKb5T1kywYALhZGs/pYZeN4IqStw=;
        b=oRINhBeHZXl0XCyMLd1QBLrf0Zakl2u7yCc8/pIuVuyUXjeZwKyo8he5Pg9JOFARcD
         Xewy1mt9kb2LkCK46O5o7rbjrEQyb65sPqxHrSY/vImcaF90wOQLywghlJeBC2bgyMdK
         SyBu3iJHh/TN0PrJijHSJzoz0zatNQ5CgSdtpvKAOw+Bh0fFCekin4uB71C5sJRbcyi6
         nX5J3CoA0nm5Ob9ucNxVdIbQOOAnt9MoGFqKT/8L8ATn2oc9vbXfQ/UxtmaqasHTZasn
         n/xII8o8Wcqpl3MfZSuK+2z1MzJ05433WAgUYamAzyXUqQB5zOR159Kk15iNQDXMMJpi
         +tpw==
X-Gm-Message-State: AOAM531FM9/VCYQWNsQykb+eXfslhqT55/SRDCh805bgkMm4ON0QYPfi
	l8WK+XuqpN2wq05thDuI0RQ=
X-Google-Smtp-Source: ABdhPJzbZjjCkU3kscYdD/R3mvADX5ZTp0t39YInNZCxZER0f1/tqlMKFyXJkkuuYE8IZDoNiDXO2Q==
X-Received: by 2002:a2e:d1a:: with SMTP id 26mr5685383ljn.412.1596800327058;
        Fri, 07 Aug 2020 04:38:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2c01:: with SMTP id s1ls24425ljs.10.gmail; Fri, 07 Aug
 2020 04:38:46 -0700 (PDT)
X-Received: by 2002:a2e:a16f:: with SMTP id u15mr6504696ljl.5.1596800326335;
        Fri, 07 Aug 2020 04:38:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596800326; cv=none;
        d=google.com; s=arc-20160816;
        b=u7vHOdW53rTWrgppRNAgFFlNux+hae/KqB+rMpRxBowu5hh83zN5ppTxRh+++LLnhP
         HOcDHTia8yNZjgM3nx1JFuNyvtbrptgMvWiaDhhzXbWYHIeSt0VOI03oIJbFidutHGve
         AF4TGPxDO5Xemo03gCQQ0SWlkmqEqDTuaI0dmYbr6ATsfyJ7lJjLHzqAm0f6LBVTMR/z
         zNNLNvQEvYsQObg8G9DYcY4f9gkB4/570fnRceTK2wZDmA5v/y20dtvRRNx4ab8HGBL4
         KA+q6as0T22aNI2d8c79NFSlvavtj6YzaPDoSdV6VkpYeX2MU2TQPa3NGevi0wYyQ+PY
         r4KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=2OvNGf73HwASsIIn3dVColNmerzHMlfHRu2Q37hp8fA=;
        b=kJKvaM2MepYGieVsDuXKOUPp5WmS4BKuf0amnj+JBmPIdnhKSkzeMOZsAlvMp0pkal
         Vg9JA+H20xjQK4fFiNsyhXdX0i+bMH+iNiGNCq3zAOhKuGaRzRZFWvt8hmsQPqbLJ8F1
         yIztCtfps2kRiMfiOqyzn/umoGaxO6Vf8An5xCammik6Z/BNM0zZfEpfMEFPoSiqPX6P
         UkF6lEClLoWqdxcUP861lLDVkK25FV/Yve2Er5kFq5Z7axY1XDXY0qPG+/OkVY4d/Ok5
         BE9ffVViaV5qOJMyE4hbT/sgEUL9aJ+lkbsukAkQgNflmIl5B48nDYSDSKDX43CiSPTR
         jQ1Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XRsQjOfj;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id 69si418488lfa.3.2020.08.07.04.38.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 04:38:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id k8so1545453wma.2
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 04:38:46 -0700 (PDT)
X-Received: by 2002:a1c:988a:: with SMTP id a132mr11991182wme.14.1596800325696;
        Fri, 07 Aug 2020 04:38:45 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id g14sm9823063wmk.37.2020.08.07.04.38.44
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Aug 2020 04:38:44 -0700 (PDT)
Date: Fri, 7 Aug 2020 13:38:38 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: =?iso-8859-1?Q?J=FCrgen_Gro=DF?= <jgross@suse.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com,
	"H. Peter Anvin" <hpa@zytor.com>,
	LKML <linux-kernel@vger.kernel.org>, Ingo Molnar <mingo@redhat.com>,
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	"Luck, Tony" <tony.luck@intel.com>,
	the arch/x86 maintainers <x86@kernel.org>, yu-cheng.yu@intel.com,
	sdeep@vmware.com, virtualization@lists.linux-foundation.org,
	kasan-dev <kasan-dev@googlegroups.com>,
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*()
 helpers
Message-ID: <20200807113838.GA3547125@elver.google.com>
References: <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
 <20200806074723.GA2364872@elver.google.com>
 <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com>
 <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
 <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XRsQjOfj;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::343 as
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

On Fri, Aug 07, 2020 at 12:35PM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> On 07.08.20 11:50, Marco Elver wrote:
> > On Fri, Aug 07, 2020 at 11:24AM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> > > On 07.08.20 11:01, Marco Elver wrote:
> > > > On Thu, 6 Aug 2020 at 18:06, Marco Elver <elver@google.com> wrote:
> > > > > On Thu, 6 Aug 2020 at 15:17, Marco Elver <elver@google.com> wrote=
:
> > > > > > On Thu, Aug 06, 2020 at 01:32PM +0200, peterz@infradead.org wro=
te:
> > > > > > > On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
> > > > > > > > Testing my hypothesis that raw then nested non-raw
> > > > > > > > local_irq_save/restore() breaks IRQ state tracking -- see t=
he reproducer
> > > > > > > > below. This is at least 1 case I can think of that we're bo=
und to hit.
> > > > > > ...
> > > > > > >=20
> > > > > > > /me goes ponder things...
> > > > > > >=20
> > > > > > > How's something like this then?
> > > > > > >=20
> > > > > > > ---
> > > > > > >    include/linux/sched.h |  3 ---
> > > > > > >    kernel/kcsan/core.c   | 62 +++++++++++++++++++++++++++++++=
+++++---------------
> > > > > > >    2 files changed, 44 insertions(+), 21 deletions(-)
> > > > > >=20
> > > > > > Thank you! That approach seems to pass syzbot (also with
> > > > > > CONFIG_PARAVIRT) and kcsan-test tests.
> > > > > >=20
> > > > > > I had to modify it some, so that report.c's use of the restore =
logic
> > > > > > works and not mess up the IRQ trace printed on KCSAN reports (w=
ith
> > > > > > CONFIG_KCSAN_VERBOSE).
> > > > > >=20
> > > > > > I still need to fully convince myself all is well now and we do=
n't end
> > > > > > up with more fixes. :-) If it passes further testing, I'll send=
 it as a
> > > > > > real patch (I want to add you as Co-developed-by, but would nee=
d your
> > > > > > Signed-off-by for the code you pasted, I think.)
> > > >=20
> > > > I let it run on syzbot through the night, and it's fine without
> > > > PARAVIRT (see below). I have sent the patch (need your Signed-off-b=
y
> > > > as it's based on your code, thank you!):
> > > > https://lkml.kernel.org/r/20200807090031.3506555-1-elver@google.com
> > > >=20
> > > > > With CONFIG_PARAVIRT=3Dy (without the notrace->noinstr patch), I =
still
> > > > > get lockdep DEBUG_LOCKS_WARN_ON(!lockdep_hardirqs_enabled()), alt=
hough
> > > > > it takes longer for syzbot to hit them. But I think that's expect=
ed
> > > > > because we can still get the recursion that I pointed out, and wi=
ll
> > > > > need that patch.
> > > >=20
> > > > Never mind, I get these warnings even if I don't turn on KCSAN
> > > > (CONFIG_KCSAN=3Dn). Something else is going on with PARAVIRT=3Dy th=
at
> > > > throws off IRQ state tracking. :-/
> > >=20
> > > What are the settings of CONFIG_PARAVIRT_XXL and
> > > CONFIG_PARAVIRT_SPINLOCKS in this case?
> >=20
> > I attached a config.
> >=20
> > 	$> grep PARAVIRT .config
> > 	CONFIG_PARAVIRT=3Dy
> > 	CONFIG_PARAVIRT_XXL=3Dy
> > 	# CONFIG_PARAVIRT_DEBUG is not set
> > 	CONFIG_PARAVIRT_SPINLOCKS=3Dy
> > 	# CONFIG_PARAVIRT_TIME_ACCOUNTING is not set
> > 	CONFIG_PARAVIRT_CLOCK=3Dy
>=20
> Anything special I need to do to reproduce the problem? Or would you be
> willing to do some more rounds with different config settings?

I can only test it with syzkaller, but that probably doesn't help if you
don't already have it set up. It can't seem to find a C reproducer.

I did some more rounds with different configs.

> I think CONFIG_PARAVIRT_XXL shouldn't matter, but I'm not completely
> sure about that. CONFIG_PARAVIRT_SPINLOCKS would be my primary suspect.

Yes, PARAVIRT_XXL doesn't make a different. When disabling
PARAVIRT_SPINLOCKS, however, the warnings go away.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200807113838.GA3547125%40elver.google.com.
