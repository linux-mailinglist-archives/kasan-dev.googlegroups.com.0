Return-Path: <kasan-dev+bncBC7OBJGL2MHBB37BWX4QKGQESKXJ3HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id E53BF23EFE0
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 17:19:11 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id t3sf863185wrr.5
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 08:19:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596813551; cv=pass;
        d=google.com; s=arc-20160816;
        b=ukTkszLH4J46ybsvznFyuwHj1cPVNH+RTkY3FSta2G7kett4sphj0wRVWnCYYjg+l+
         CldiFJziMkNSxCnK2xsTKvY2PxUlkgApso7eqAxcBje0GrTsKohXMXS++pbrvBEPFoko
         lB8vy7LGx1NX6VLI92nhSq4TYXwFXDfNeSUp0fbSpJHZAB4gDZgfP+Kc8oPtML9eX8kp
         4HFnvcJtK+1KDfVPSWlarqpl3Px+RIFwltPJzN4Xhv6ldQQXySlsXOHxCg7LB5BbP48I
         wQyehB0v0TSK3emkBl/9DwKhx13tXDSGBuRrh0RapIBDbJIhXYqoIol1GByfW1FhmOCx
         5DoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=UWBieXcs9JNnDyo76oAMOWVqp8+Qavy2uqycuV/gABo=;
        b=OKilOnRBllTkav1Xs4fzHeuP/z2wY7msdywl8VJbtbI6BqQmupr6Mf8b902iKL4/uE
         6tY4Pj2ajtcEesJP1Cfaarkx2gCxdLMZ7FlOEz2LZS6/0b8m1k9oGkutRiDY/qgvsoYD
         Tqy6QGyUmlb5wMro/7YJcM++n96riqtU7q5RxwQaqw6DGWGDdRUaLPCtb2yvqSKGFTY8
         oMFagz0oodWPkQS4YkBv0CVlJ0GgSDZek9qxOVnN1VaHbhUUHxlb+F1bPsASphIp4VZh
         FQjixvRguAVtWWoqc/OoEQZKLo2cXXbD8vRphMqwZ0RwtR6jXLHtc9aEltJqSkePQaaE
         +V3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TujP8TuZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UWBieXcs9JNnDyo76oAMOWVqp8+Qavy2uqycuV/gABo=;
        b=aSGtvG5HmdVTyMkTOqbM+Metdz2ASwxN79Q9FM8T+feHsMJgZFE/Z3D8mRaOW+8Y1L
         ep/EncqCj/m/cahAuX0y2ykajpraG3mRVNoyzqFq/PuV9E4X51CPS4ygJO6HsulAX6iR
         UxcaZVRjpxNRZhJcl4EwdUFqBzFb7/TUAYBUOlGtXQmCNOExBYyt650+QZHGpWQ0wvs+
         Lg39fjPmuTnco4oyguFRQL64+XCKL3sxT+E5Y2NqbUqIH4TxTaWU/cYGOOjyQFBWmqTV
         KjJUVSHZz4LteZPtk0rs6z9aQqtPVljPRPvpSPpcHCmBv3qqLAQNxnPxYE3kUuPHGXc6
         8RbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=UWBieXcs9JNnDyo76oAMOWVqp8+Qavy2uqycuV/gABo=;
        b=YDAXF0uQ5ovKuwXo2DKV4mbWHHGW25ZObsAyhl7VAYpDD++rlKEhuZTK4x3JQMRNQW
         eQTPrZatyVWGcu41gSz869+BJXTKI2n3PZmUkX+Spjnf4fnQWgYMK2Df8Po4sb9WAEri
         FGfy1A2G8jXWieWRWx+ySH7KXcVBeB19DRPtXYSmEpZk9saCi12vmIWdya5hevnuIh1F
         k8dQUfW5FlwXIq0CtDt0FBcQ2m8bwpNFCyilXhJK8cBf3CJKLP9FQrcfIuappsB+7vcA
         Ic2NbnkHdGl74L+UwAPTyMv62fk1NN6T02Cuxc2McLKsbnqIX2Ulz75kCPb5C+9+9Dfs
         Ydog==
X-Gm-Message-State: AOAM533VLj/UAAF6IUYExa0Mv7jNQ090o4+C7QbiPKXmpmVuwqT3V9Rp
	oB12xKonpkEazI7wjqhxGLQ=
X-Google-Smtp-Source: ABdhPJzmWTOTh2gEC+xNzEmSMq4j/yuSO4EHoM4oUKWlp4JpN8kbgaiVmYUEJvWWOP2PEyWf8uau7A==
X-Received: by 2002:a5d:618e:: with SMTP id j14mr13027512wru.374.1596813551547;
        Fri, 07 Aug 2020 08:19:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:81f4:: with SMTP id 107ls1115675wra.2.gmail; Fri, 07 Aug
 2020 08:19:10 -0700 (PDT)
X-Received: by 2002:a5d:4610:: with SMTP id t16mr13223173wrq.101.1596813550833;
        Fri, 07 Aug 2020 08:19:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596813550; cv=none;
        d=google.com; s=arc-20160816;
        b=0tfR5hrXqkG6WpFH1iraQSL3kmpg9mMP7IsXQd5ubCeh7HQRMqRJzRCHqUhb0vr6Qy
         QIMvQOdOicLXWFkWGO2FIdnH5LiBX/sZ1n+XahLS/DKS2o7izIKeU78zF3RhI5flKV+k
         djqvUVBUX9m305MMKm+nqx4ZlF4/3FgukOU1q0m8TW7+LSGLKMeEsu3s8KNxcnRCFs0/
         xUxhPvmFs38nk5CpFvKxf6oULgSv0P2bNZp8UpcojUxSouTKOSdlsRDhx814AnXEoMmf
         PIWFt9kse0EMnpS7rHyZ0r9Kam3XFs4awM+40te6hispbYJnbDjl4O8ORucVcK2pi9Mt
         nFVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=jHwuEBD3ANfATNEay78Qrd/CFOLdfE4qFBZzKEVtZCA=;
        b=ZVjce9F7tK9v67QuTz0/bGmyMpbRprRgh1QkuSqQ8yY/FjjvRGU92XRuvv9jdoVIFY
         gEoosBIq0EvgNB4yw9fwvMIdT1sxZTxT/zhRQ4tBe0D4LItpf+8otsffHcmcmMhkKfX4
         URZqC5626/dbaJ3Gmep7wg/NfQFjJhhzVy1XjnvOU1szP8RIJgrssFVTOHq7PprQ2bvo
         wnhwIJXvHQAz5JMpa0w+gM2pbmY9grMdqPy/qzbIbdM1JClw/O9wUDpsjcl4bjjS22U1
         i7PotACZx1/OMXb5EF4w46hb9QXBLZ1bM7N+/VspYyaOL/ZPL7auhurYxve/IoHWFvxW
         nNpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TujP8TuZ;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id i11si500039wra.3.2020.08.07.08.19.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 08:19:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id a14so2020872wra.5
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 08:19:10 -0700 (PDT)
X-Received: by 2002:a5d:4401:: with SMTP id z1mr12196021wrq.305.1596813550150;
        Fri, 07 Aug 2020 08:19:10 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id 111sm10899976wrc.53.2020.08.07.08.19.08
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 07 Aug 2020 08:19:08 -0700 (PDT)
Date: Fri, 7 Aug 2020 17:19:03 +0200
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
Message-ID: <20200807151903.GA1263469@elver.google.com>
References: <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com>
 <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com>
 <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com>
 <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
 <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
User-Agent: Mutt/1.14.4 (2020-06-18)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TujP8TuZ;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::443 as
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

On Fri, Aug 07, 2020 at 02:08PM +0200, Marco Elver wrote:
> On Fri, 7 Aug 2020 at 14:04, J=C3=BCrgen Gro=C3=9F <jgross@suse.com> wrot=
e:
> >
> > On 07.08.20 13:38, Marco Elver wrote:
> > > On Fri, Aug 07, 2020 at 12:35PM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> > >> On 07.08.20 11:50, Marco Elver wrote:
> > >>> On Fri, Aug 07, 2020 at 11:24AM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> > >>>> On 07.08.20 11:01, Marco Elver wrote:
> > >>>>> On Thu, 6 Aug 2020 at 18:06, Marco Elver <elver@google.com> wrote=
:
> > >>>>>> On Thu, 6 Aug 2020 at 15:17, Marco Elver <elver@google.com> wrot=
e:
> > >>>>>>> On Thu, Aug 06, 2020 at 01:32PM +0200, peterz@infradead.org wro=
te:
> > >>>>>>>> On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
> > >>>>>>>>> Testing my hypothesis that raw then nested non-raw
> > >>>>>>>>> local_irq_save/restore() breaks IRQ state tracking -- see the=
 reproducer
> > >>>>>>>>> below. This is at least 1 case I can think of that we're boun=
d to hit.
> > >>>>>>> ...
> > >>>>>>>>
> > >>>>>>>> /me goes ponder things...
> > >>>>>>>>
> > >>>>>>>> How's something like this then?
> > >>>>>>>>
> > >>>>>>>> ---
> > >>>>>>>>     include/linux/sched.h |  3 ---
> > >>>>>>>>     kernel/kcsan/core.c   | 62 +++++++++++++++++++++++++++++++=
+++++---------------
> > >>>>>>>>     2 files changed, 44 insertions(+), 21 deletions(-)
> > >>>>>>>
> > >>>>>>> Thank you! That approach seems to pass syzbot (also with
> > >>>>>>> CONFIG_PARAVIRT) and kcsan-test tests.
> > >>>>>>>
> > >>>>>>> I had to modify it some, so that report.c's use of the restore =
logic
> > >>>>>>> works and not mess up the IRQ trace printed on KCSAN reports (w=
ith
> > >>>>>>> CONFIG_KCSAN_VERBOSE).
> > >>>>>>>
> > >>>>>>> I still need to fully convince myself all is well now and we do=
n't end
> > >>>>>>> up with more fixes. :-) If it passes further testing, I'll send=
 it as a
> > >>>>>>> real patch (I want to add you as Co-developed-by, but would nee=
d your
> > >>>>>>> Signed-off-by for the code you pasted, I think.)
> > >>>>>
> > >>>>> I let it run on syzbot through the night, and it's fine without
> > >>>>> PARAVIRT (see below). I have sent the patch (need your Signed-off=
-by
> > >>>>> as it's based on your code, thank you!):
> > >>>>> https://lkml.kernel.org/r/20200807090031.3506555-1-elver@google.c=
om
> > >>>>>
> > >>>>>> With CONFIG_PARAVIRT=3Dy (without the notrace->noinstr patch), I=
 still
> > >>>>>> get lockdep DEBUG_LOCKS_WARN_ON(!lockdep_hardirqs_enabled()), al=
though
> > >>>>>> it takes longer for syzbot to hit them. But I think that's expec=
ted
> > >>>>>> because we can still get the recursion that I pointed out, and w=
ill
> > >>>>>> need that patch.
> > >>>>>
> > >>>>> Never mind, I get these warnings even if I don't turn on KCSAN
> > >>>>> (CONFIG_KCSAN=3Dn). Something else is going on with PARAVIRT=3Dy =
that
> > >>>>> throws off IRQ state tracking. :-/
> > >>>>
> > >>>> What are the settings of CONFIG_PARAVIRT_XXL and
> > >>>> CONFIG_PARAVIRT_SPINLOCKS in this case?
> > >>>
> > >>> I attached a config.
> > >>>
> > >>>     $> grep PARAVIRT .config
> > >>>     CONFIG_PARAVIRT=3Dy
> > >>>     CONFIG_PARAVIRT_XXL=3Dy
> > >>>     # CONFIG_PARAVIRT_DEBUG is not set
> > >>>     CONFIG_PARAVIRT_SPINLOCKS=3Dy
> > >>>     # CONFIG_PARAVIRT_TIME_ACCOUNTING is not set
> > >>>     CONFIG_PARAVIRT_CLOCK=3Dy
> > >>
> > >> Anything special I need to do to reproduce the problem? Or would you=
 be
> > >> willing to do some more rounds with different config settings?
> > >
> > > I can only test it with syzkaller, but that probably doesn't help if =
you
> > > don't already have it set up. It can't seem to find a C reproducer.
> > >
> > > I did some more rounds with different configs.
> > >
> > >> I think CONFIG_PARAVIRT_XXL shouldn't matter, but I'm not completely
> > >> sure about that. CONFIG_PARAVIRT_SPINLOCKS would be my primary suspe=
ct.
> > >
> > > Yes, PARAVIRT_XXL doesn't make a different. When disabling
> > > PARAVIRT_SPINLOCKS, however, the warnings go away.
> >
> > Thanks for testing!
> >
> > I take it you are doing the tests in a KVM guest?
>=20
> Yes, correct.
>=20
> > If so I have a gut feeling that the use of local_irq_save() and
> > local_irq_restore() in kvm_wait() might be fishy. I might be completely
> > wrong here, though.
>=20
> Happy to help debug more, although I might need patches or pointers
> what to play with.
>=20
> > BTW, I think Xen's variant of pv spinlocks is fine (no playing with IRQ
> > on/off).
> >
> > Hyper-V seems to do the same as KVM, and kicking another vcpu could be
> > problematic as well, as it is just using IPI.

I experimented a bit more, and the below patch seems to solve the
warnings. However, that was based on your pointer about kvm_wait(), and
I can't quite tell if it is the right solution.

My hypothesis here is simply that kvm_wait() may be called in a place
where we get the same case I mentioned to Peter,

	raw_local_irq_save(); /* or other IRQs off without tracing */
	...
	kvm_wait() /* IRQ state tracing gets confused */
	...
	raw_local_irq_restore();

and therefore, using raw variants in kvm_wait() works. It's also safe
because it doesn't call any other libraries that would result in corrupt
IRQ state AFAIK.

Thanks,
-- Marco

------ >8 ------

diff --git a/arch/x86/kernel/kvm.c b/arch/x86/kernel/kvm.c
index 233c77d056c9..1d412d1466f0 100644
--- a/arch/x86/kernel/kvm.c
+++ b/arch/x86/kernel/kvm.c
@@ -797,7 +797,7 @@ static void kvm_wait(u8 *ptr, u8 val)
 	if (in_nmi())
 		return;
=20
-	local_irq_save(flags);
+	raw_local_irq_save(flags);
=20
 	if (READ_ONCE(*ptr) !=3D val)
 		goto out;
@@ -810,10 +810,10 @@ static void kvm_wait(u8 *ptr, u8 val)
 	if (arch_irqs_disabled_flags(flags))
 		halt();
 	else
-		safe_halt();
+		raw_safe_halt();
=20
 out:
-	local_irq_restore(flags);
+	raw_local_irq_restore(flags);
 }
=20
 #ifdef CONFIG_X86_32

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200807151903.GA1263469%40elver.google.com.
