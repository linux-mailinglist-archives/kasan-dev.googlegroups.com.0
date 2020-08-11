Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHMEZH4QKGQE3ONHIGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id D26B12416C6
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 09:00:46 +0200 (CEST)
Received: by mail-qt1-x840.google.com with SMTP id q19sf9245406qtp.0
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 00:00:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597129245; cv=pass;
        d=google.com; s=arc-20160816;
        b=XAmiwwrAjiAjA3mt6N74c0KkE1vfEVLW59mKt8xo0pimNjeNKaFZ/UZvfNS84YrZv5
         T7Jqi/2cMCJHaHE3gRpqrz3wNnCeOEoBxJ/5vY0rSe3wvH3z1y9g951P63QuNA1hHj/K
         9OODDKsHOJKNE/phzCH1AGXfZBOn+duPoPHALphve8ZytisvS1igmSdfe3XzuJLe5hDe
         LAFNZ8JmfPpeLwDYA5bayMLo7qGMjlvPUsJXkXUly/RQLkEDSNeneanZj7uekuWqarpP
         gRq3y6IJnEZ+b7k5kms4NC6gLRJ7YKllH/VPyj/QJojTnLcVCNlQR93oNN/lN/799mSU
         x+2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nvorNjeGW13ljvxSaeYCi4NWNxiRvSvmF9L94r5ppNs=;
        b=OWIImFNCWQTMvBMtDIwx8Ob+sqmJkI/5PqPRJUa1oSVv0CpHhPTTAuCTNaTDmORXjw
         xN/1v0e1IbQ9A2KNEGThTc0Yj2K/zo1TSwaKoLY4mas13QzEjiB1H5gLLgnndWVq/S5I
         g+5iKthsqbXTK+/iYS0waLVZsCcftzy4aVb+UFelTBbLMqTFt0U/7mbbTuGSDr2rmkCu
         +2iU4ltM+yJX9LXAhgtKfo1TaWOgD/rIkJKU4rDODvzJPm0ozHfBrd5W7rxAGzIciuzT
         k1GVcPu6ptsyTiFvJX6kmmkNcu1b+LkcXCDfv8JzX/23VHvKWEUqR6zWsE/M5/wljEbt
         jQbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wrc1qF1A;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=nvorNjeGW13ljvxSaeYCi4NWNxiRvSvmF9L94r5ppNs=;
        b=SFmoZlzf9vC3AdEtpKoGqtRKw2PRJCZIDiGISXa0dgtm7nIedIkV2ekq5HRpZuz4Dj
         3sJnxm57FtpxBdKEPgzlE3ZBpFoWo1ymMd07qLt9pe5w/I0swGKc5PGXNWhfLzmDQOwd
         FUdD+yyHjjKaLAuVxRi5wBMy03eKgerNRQ6E5CmsAIMiM6lRDJgEBFl+ZOsLpEDInLqM
         qlkgqUSglW+fW3jmNA1ZBEUtWthb7unW3kl/XxT+4C1SKzFqmU0XBPw6eFS6MIBb9sbb
         +ftmMiQDMgtBAcmZv3N/IRbO+e/11m2xgp+KKwdFzkIaxLkJcSKso7m2AkQnolRnswHh
         QJ+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nvorNjeGW13ljvxSaeYCi4NWNxiRvSvmF9L94r5ppNs=;
        b=PYkvtk2rz2cUfUxaa8lTvDn4sAKHzk496hr4+B5a/ZjonHQhSCsoOOW6TD8FP9V9x6
         metC+IIHcIZtBzNu+pXKEs3AHAuXW6zZ94MltjRmdvBctIKz09MuxE4SyCaKrVXrvM3Z
         bxoeIZhng17luuabq9U9m7eh3vQlKTCe3Rit0x4szdMJ0sfa1EYwjaZWH8OobqOAIQSE
         KSG0kWx9goEGcbfd7RxdnKM5sXwGb6lknePrVZ5aAB0wtzORTxm7wKrqpMiv1RXmBVNA
         dpCkJK7CJYcl0HI7UMOg2eR8KkZ5EQgM/7DTXX9h71DdaFnD6RkUNxE3C/eHLsx22nUE
         CgBQ==
X-Gm-Message-State: AOAM532KkFqAYHGONzH6HzZ9GeqfGRnD1h5P2MsgLOKWEAe4nkv2IkX/
	cQL7RGCu1Cd8yXdjGrv+ikM=
X-Google-Smtp-Source: ABdhPJw9tPLwsG5Bavx/epkzb28VnGeKsZszGGv0MAFH62vN3+K8F5TH1UDCh8HkczIpVwtENV2iZA==
X-Received: by 2002:a0c:b60d:: with SMTP id f13mr29287587qve.38.1597129245518;
        Tue, 11 Aug 2020 00:00:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:8ce:: with SMTP id y14ls7837210qth.7.gmail; Tue, 11 Aug
 2020 00:00:45 -0700 (PDT)
X-Received: by 2002:ac8:568a:: with SMTP id h10mr31573564qta.239.1597129245179;
        Tue, 11 Aug 2020 00:00:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597129245; cv=none;
        d=google.com; s=arc-20160816;
        b=yN0WhbKGqxq7lD0SYi/ag8CF3PsxBPA0/TDYSnaRiWwkZJYdRpEVMIqgoG78NhnmMm
         L75j8oztYGF8vn6mpRLGciJ+mS1Z+5n61D45ZxhJrUyHoZSgVsEHe0ZwmJVeIkKfdxq6
         /ZZH5QiYjBJAk/rKAm2DpI5ATN6uNxUWjuBBbW5caS+v0gM4apJHfchiAZbVb8RDjrJ0
         j5KhWDBeJu6aKeLMasikOcVGKT0B/efNjtR0+s9dj34wXcpVSGZGb4zcEwWa/ieOXDWS
         Ll+uoZaFOzUe/4qI6ppFVZ3xkw69m6FKFq8WGpg4+yn8/h9qG+n5xRHppYdYtm9iIRtj
         DjBA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=F1s+Ab0YJ1nRhabDcWGJ1wJlu8nr2OTHTQ8v81zx/uE=;
        b=hASf1l02wKipxJumHyuKteXG7FJEmcwBKsZ8usjUkt2rSjFnQwDZ7JfSzXHSQVUmB7
         VYPx6g37Ahf/7MxnSs89BHlfgptL6fOPONAZlScNTsWbHKjMs6wf140Z8qcndlseGWt9
         XjPt0B1O3KhihRztO/wuN/OzrHjZH77v6QzEfrn04g+RfJe15rZc2OWz9VwHtPsFkjO9
         b4FnRcpza3uCs/wxeajV0/0E4qhLVcqKqn7PEFKufKn6p3JV1ouRUPuYEJPFVBuMcu2q
         IFDA16WuruAL9TRI+TFCaJ+9iYVFC56MxXQIHwpTEIiUOx867X3E6to/UZ8tKyrtWMI4
         4Lww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wrc1qF1A;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id o2si983338qkj.4.2020.08.11.00.00.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Aug 2020 00:00:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id a65so9298933otc.8
        for <kasan-dev@googlegroups.com>; Tue, 11 Aug 2020 00:00:45 -0700 (PDT)
X-Received: by 2002:a05:6830:1612:: with SMTP id g18mr3522264otr.251.1597129244426;
 Tue, 11 Aug 2020 00:00:44 -0700 (PDT)
MIME-Version: 1.0
References: <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com> <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com> <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com> <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com> <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
 <20200807151903.GA1263469@elver.google.com>
In-Reply-To: <20200807151903.GA1263469@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Aug 2020 09:00:32 +0200
Message-ID: <CANpmjNM1jASqCFYZpteVrZCa2V2D_DbXaqvoCV_Ac2boYfDXnQ@mail.gmail.com>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*() helpers
To: =?UTF-8?B?SsO8cmdlbiBHcm/Dnw==?= <jgross@suse.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com, 
	"H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Luck, Tony" <tony.luck@intel.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, yu-cheng.yu@intel.com, sdeep@vmware.com, 
	virtualization@lists.linux-foundation.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Wrc1qF1A;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as
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

On Fri, 7 Aug 2020 at 17:19, Marco Elver <elver@google.com> wrote:
> On Fri, Aug 07, 2020 at 02:08PM +0200, Marco Elver wrote:
> > On Fri, 7 Aug 2020 at 14:04, J=C3=BCrgen Gro=C3=9F <jgross@suse.com> wr=
ote:
> > >
> > > On 07.08.20 13:38, Marco Elver wrote:
> > > > On Fri, Aug 07, 2020 at 12:35PM +0200, J=C3=BCrgen Gro=C3=9F wrote:
...
> > > >> I think CONFIG_PARAVIRT_XXL shouldn't matter, but I'm not complete=
ly
> > > >> sure about that. CONFIG_PARAVIRT_SPINLOCKS would be my primary sus=
pect.
> > > >
> > > > Yes, PARAVIRT_XXL doesn't make a different. When disabling
> > > > PARAVIRT_SPINLOCKS, however, the warnings go away.
> > >
> > > Thanks for testing!
> > >
> > > I take it you are doing the tests in a KVM guest?
> >
> > Yes, correct.
> >
> > > If so I have a gut feeling that the use of local_irq_save() and
> > > local_irq_restore() in kvm_wait() might be fishy. I might be complete=
ly
> > > wrong here, though.
> >
> > Happy to help debug more, although I might need patches or pointers
> > what to play with.
> >
> > > BTW, I think Xen's variant of pv spinlocks is fine (no playing with I=
RQ
> > > on/off).
> > >
> > > Hyper-V seems to do the same as KVM, and kicking another vcpu could b=
e
> > > problematic as well, as it is just using IPI.
>
> I experimented a bit more, and the below patch seems to solve the
> warnings. However, that was based on your pointer about kvm_wait(), and
> I can't quite tell if it is the right solution.
>
> My hypothesis here is simply that kvm_wait() may be called in a place
> where we get the same case I mentioned to Peter,
>
>         raw_local_irq_save(); /* or other IRQs off without tracing */
>         ...
>         kvm_wait() /* IRQ state tracing gets confused */
>         ...
>         raw_local_irq_restore();
>
> and therefore, using raw variants in kvm_wait() works. It's also safe
> because it doesn't call any other libraries that would result in corrupt
> IRQ state AFAIK.

Just to follow-up, it'd still be nice to fix this. Suggestions?

I could send the below as a patch, but can only go off my above
hypothesis and the fact that syzbot is happier, so not entirely
convincing.

Thanks,
-- Marco

> ------ >8 ------
>
> diff --git a/arch/x86/kernel/kvm.c b/arch/x86/kernel/kvm.c
> index 233c77d056c9..1d412d1466f0 100644
> --- a/arch/x86/kernel/kvm.c
> +++ b/arch/x86/kernel/kvm.c
> @@ -797,7 +797,7 @@ static void kvm_wait(u8 *ptr, u8 val)
>         if (in_nmi())
>                 return;
>
> -       local_irq_save(flags);
> +       raw_local_irq_save(flags);
>
>         if (READ_ONCE(*ptr) !=3D val)
>                 goto out;
> @@ -810,10 +810,10 @@ static void kvm_wait(u8 *ptr, u8 val)
>         if (arch_irqs_disabled_flags(flags))
>                 halt();
>         else
> -               safe_halt();
> +               raw_safe_halt();
>
>  out:
> -       local_irq_restore(flags);
> +       raw_local_irq_restore(flags);
>  }
>
>  #ifdef CONFIG_X86_32

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNM1jASqCFYZpteVrZCa2V2D_DbXaqvoCV_Ac2boYfDXnQ%40mail.gmail.=
com.
