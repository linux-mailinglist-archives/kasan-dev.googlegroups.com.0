Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOEIWX4QKGQEVIBGIEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E4AD23ED1B
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 14:08:26 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id y9sf996738otq.8
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 05:08:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596802104; cv=pass;
        d=google.com; s=arc-20160816;
        b=EmMQ8Sqhu0klUbwSd88Q4TkFYSu/sjFLx7VkjOMYK2jKnv7bWf6x/Wd/1FYdxQnbrR
         nmiaWHR+j+n64VQ8Fb8qW+9ry6+B4UU+lWcBAVb43UFZDW4514BA1LrIRKWK1CriFA+s
         q5p9Sg/e6XIfAg12aZZQ1y9qlyS5Ywhqg/FtIgE+rMqZ8SnXblciBcgBY2M08Fkq0Qfi
         T2mGKAPufklxEZ0cZ7FSjBgxAzEub6Lz7QrZerLNpujdjsWq+ouw2coSlZcyERH5z9JE
         gOr+lt+1bKgznnqRyyCPKORc2QGqPSBhXxVbXiWRjHO+zuM7p2ZnD4ws/BeBt/mxiZcH
         BM6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Hfu5uokxJ5xKNlFXyrDb/HEsSKnvLji+RZSQcICGg8c=;
        b=jHugT/yGkk90cOCl5J5abaofLpSRjMObxhfP3PX+dwApK7SAVgZzRMxszByF05KNhX
         ieN9pxqaNMZA8T9vBzqLQj+vl8U4X84tzboOk4AYLOk55jZg8fSTsP+KRk1OBw8WcnaI
         bqLOnYfGR4SK3fEZVssuMITXDcND/fi8qe4XjXttypj2xIMyQRku1oJnlhLODbvQFA9r
         ActO+YagWN2atuwODFQ+IZa69JLhRO/9ThiV1YC8uwTU2Hq5Xx6Tnl/u+51RAcU0AQAN
         fZVGoI+vkOL+XHFNu9/C+kPuk6BWC1y+OiMySmnVsQwlBlMFfgzyRnls2SHQS57yMgDG
         tMKA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cuta9FDJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Hfu5uokxJ5xKNlFXyrDb/HEsSKnvLji+RZSQcICGg8c=;
        b=eUHNFmJmEh1Fx9GWZpIknVYBLx7Po2rhHZJxJ6GMJsydD2QsduHt7VZ9P8xNSVT02/
         3a3MTMZepIok1JvUDqWG4XBSkcefxkIzphvrdszL3ZPWKYHVyQvHdnn1GXpsxwJcxYRn
         3BmixyLHGhXVT9eD2yWbYpSb78FtsR8YEA6FotiLLBPXkn05JUfLJPJ0xUUpbdeQVyu4
         DynEyHDe+sWsNcSWvz2rpezNBYWxH4rFC9FTB2hozsz3dk1CaftnJkGUuEWtQgPdUptM
         4X911CdcOLW0pdErtdxXuccG/bNWmrcV3hvvRBF/Url/p9TBTG4EqWwjeyGwAY0nfWAw
         Qkpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Hfu5uokxJ5xKNlFXyrDb/HEsSKnvLji+RZSQcICGg8c=;
        b=S2Ifd4Od+eNJg1UCSxxAHSr0PT4u6LR+V7op6aFyXHgnfQatz19XGX4VXUfX3iTefd
         8JQQyPMXYmmQX77BJOksr7Ox95Uj+hejKNt8ujQqB8vSscPlvXMUVXkPIxeVJfMRKLlk
         PUGvCp0xDFDxihCPewyxtuHsMzqbgWHrDm7tGM4nRSYyt7GaarVYnreXqIowLGjs0rWh
         lUPnczqS4O+GXCUcXpBXnqNp4LdfKKJZIFdvlk0nQU3fSPhf6g1bMaqYoFhJe7r25Ejf
         HjpTcx2t1sMkpL2Eg3WSIkS3nbC6Qp4A5WAxA2Ud+fbY1xEKzzupLq5aMKDHZQqWw5CN
         3y+w==
X-Gm-Message-State: AOAM533gmj+FuclMAI643ug7dNgOCwXkRr9EJzifqQcD+w0gRlQq63a9
	9PxhdrnUyD4j9Aes0bEQuAc=
X-Google-Smtp-Source: ABdhPJxQEiCzfsMsje/03FmDMcvDIK/CZ1keg2adjva8Xg4ypTxSYgjcbWQvzHqYm+cWRtbmqZyMxg==
X-Received: by 2002:aca:4f8d:: with SMTP id d135mr9006078oib.74.1596802104629;
        Fri, 07 Aug 2020 05:08:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:56c3:: with SMTP id k186ls2017599oib.5.gmail; Fri, 07
 Aug 2020 05:08:24 -0700 (PDT)
X-Received: by 2002:aca:48d3:: with SMTP id v202mr11111584oia.132.1596802104332;
        Fri, 07 Aug 2020 05:08:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596802104; cv=none;
        d=google.com; s=arc-20160816;
        b=HVdP6clRK6hfsFfdNhDbyhhX0HtjxMgZtJhjL7/k5LQGA5WGawK3vChlWRKa0XQoKP
         8rGKrTdS9kyppyxxSDVqbSH4r4fHHSkGkOXKVY9ZCbd0h4fUe6JOCbu/3PbPNCeeonWY
         aSd96lLkXExrt2iA9GutScgxFKTFamqqO2YHdyqP8eumcRYfV0SHAxyzVqJqq3DluC3K
         W1+Qu7w67ymm34j4mgiSkgJsRAikLGmS8tSNf+04leBimyajRP5k4xntiYOdvP3oJpDr
         PZMMjaJPInDAM/iKbTqBrwwK5n4jRKeQ0DFxmOT63/NKfAKF/ZWe0OpX4KwEVz0/oaoJ
         vaDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ay16CW272QYTKkAOwUiRs236ospoi7GV3k++PHOMjNM=;
        b=T03KyyFs5SN5VagXSEBkMyfbHgM8k74mvyqtzSpNW4qcjOCtVo4ASjFUcWaV8QtwH3
         Z18J/r1EaFx/ujELPbNkjDcUEFAnldcyBQexLHKPsKbSkQBM7wERiTPgXijUkC1dX2Iy
         GSg5QmabXLO7AGJfMxwmiiiDg174HLFRpK8TE7k3ocEYWPOBn6ssAqCHfnLjwhFgJO6c
         7mUFdJKLmm0OlZ6POVNqS8WlFeCfD8z8OJukVnHw5/Jl5XbjNqRRa0IMnHRek9fnrAV2
         Qy1qNKxewlgOk3B020yqG1pkWK94f5yWeyGmGD97qrvpzs5q9B06jqHwVl9CjcPpQYe/
         t9vQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Cuta9FDJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id c5si184262ots.0.2020.08.07.05.08.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 05:08:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id 25so1724786oir.0
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 05:08:24 -0700 (PDT)
X-Received: by 2002:aca:b8c4:: with SMTP id i187mr11210808oif.121.1596802103701;
 Fri, 07 Aug 2020 05:08:23 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
 <20200806074723.GA2364872@elver.google.com> <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com> <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
 <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
 <fe2bfa7f-132f-7581-a967-d01d58be1588@suse.com> <20200807095032.GA3528289@elver.google.com>
 <16671cf3-3885-eb06-79ff-4cbfaeeaea79@suse.com> <20200807113838.GA3547125@elver.google.com>
 <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
In-Reply-To: <e5bf3e6a-efff-7170-5ee6-1798008393a2@suse.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Aug 2020 14:08:11 +0200
Message-ID: <CANpmjNPau_DEYadey9OL+iFZKEaUTqnFnyFs1dU12o00mg7ofA@mail.gmail.com>
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
 header.i=@google.com header.s=20161025 header.b=Cuta9FDJ;       spf=pass
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

On Fri, 7 Aug 2020 at 14:04, J=C3=BCrgen Gro=C3=9F <jgross@suse.com> wrote:
>
> On 07.08.20 13:38, Marco Elver wrote:
> > On Fri, Aug 07, 2020 at 12:35PM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> >> On 07.08.20 11:50, Marco Elver wrote:
> >>> On Fri, Aug 07, 2020 at 11:24AM +0200, J=C3=BCrgen Gro=C3=9F wrote:
> >>>> On 07.08.20 11:01, Marco Elver wrote:
> >>>>> On Thu, 6 Aug 2020 at 18:06, Marco Elver <elver@google.com> wrote:
> >>>>>> On Thu, 6 Aug 2020 at 15:17, Marco Elver <elver@google.com> wrote:
> >>>>>>> On Thu, Aug 06, 2020 at 01:32PM +0200, peterz@infradead.org wrote=
:
> >>>>>>>> On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
> >>>>>>>>> Testing my hypothesis that raw then nested non-raw
> >>>>>>>>> local_irq_save/restore() breaks IRQ state tracking -- see the r=
eproducer
> >>>>>>>>> below. This is at least 1 case I can think of that we're bound =
to hit.
> >>>>>>> ...
> >>>>>>>>
> >>>>>>>> /me goes ponder things...
> >>>>>>>>
> >>>>>>>> How's something like this then?
> >>>>>>>>
> >>>>>>>> ---
> >>>>>>>>     include/linux/sched.h |  3 ---
> >>>>>>>>     kernel/kcsan/core.c   | 62 +++++++++++++++++++++++++++++++++=
+++---------------
> >>>>>>>>     2 files changed, 44 insertions(+), 21 deletions(-)
> >>>>>>>
> >>>>>>> Thank you! That approach seems to pass syzbot (also with
> >>>>>>> CONFIG_PARAVIRT) and kcsan-test tests.
> >>>>>>>
> >>>>>>> I had to modify it some, so that report.c's use of the restore lo=
gic
> >>>>>>> works and not mess up the IRQ trace printed on KCSAN reports (wit=
h
> >>>>>>> CONFIG_KCSAN_VERBOSE).
> >>>>>>>
> >>>>>>> I still need to fully convince myself all is well now and we don'=
t end
> >>>>>>> up with more fixes. :-) If it passes further testing, I'll send i=
t as a
> >>>>>>> real patch (I want to add you as Co-developed-by, but would need =
your
> >>>>>>> Signed-off-by for the code you pasted, I think.)
> >>>>>
> >>>>> I let it run on syzbot through the night, and it's fine without
> >>>>> PARAVIRT (see below). I have sent the patch (need your Signed-off-b=
y
> >>>>> as it's based on your code, thank you!):
> >>>>> https://lkml.kernel.org/r/20200807090031.3506555-1-elver@google.com
> >>>>>
> >>>>>> With CONFIG_PARAVIRT=3Dy (without the notrace->noinstr patch), I s=
till
> >>>>>> get lockdep DEBUG_LOCKS_WARN_ON(!lockdep_hardirqs_enabled()), alth=
ough
> >>>>>> it takes longer for syzbot to hit them. But I think that's expecte=
d
> >>>>>> because we can still get the recursion that I pointed out, and wil=
l
> >>>>>> need that patch.
> >>>>>
> >>>>> Never mind, I get these warnings even if I don't turn on KCSAN
> >>>>> (CONFIG_KCSAN=3Dn). Something else is going on with PARAVIRT=3Dy th=
at
> >>>>> throws off IRQ state tracking. :-/
> >>>>
> >>>> What are the settings of CONFIG_PARAVIRT_XXL and
> >>>> CONFIG_PARAVIRT_SPINLOCKS in this case?
> >>>
> >>> I attached a config.
> >>>
> >>>     $> grep PARAVIRT .config
> >>>     CONFIG_PARAVIRT=3Dy
> >>>     CONFIG_PARAVIRT_XXL=3Dy
> >>>     # CONFIG_PARAVIRT_DEBUG is not set
> >>>     CONFIG_PARAVIRT_SPINLOCKS=3Dy
> >>>     # CONFIG_PARAVIRT_TIME_ACCOUNTING is not set
> >>>     CONFIG_PARAVIRT_CLOCK=3Dy
> >>
> >> Anything special I need to do to reproduce the problem? Or would you b=
e
> >> willing to do some more rounds with different config settings?
> >
> > I can only test it with syzkaller, but that probably doesn't help if yo=
u
> > don't already have it set up. It can't seem to find a C reproducer.
> >
> > I did some more rounds with different configs.
> >
> >> I think CONFIG_PARAVIRT_XXL shouldn't matter, but I'm not completely
> >> sure about that. CONFIG_PARAVIRT_SPINLOCKS would be my primary suspect=
.
> >
> > Yes, PARAVIRT_XXL doesn't make a different. When disabling
> > PARAVIRT_SPINLOCKS, however, the warnings go away.
>
> Thanks for testing!
>
> I take it you are doing the tests in a KVM guest?

Yes, correct.

> If so I have a gut feeling that the use of local_irq_save() and
> local_irq_restore() in kvm_wait() might be fishy. I might be completely
> wrong here, though.

Happy to help debug more, although I might need patches or pointers
what to play with.

> BTW, I think Xen's variant of pv spinlocks is fine (no playing with IRQ
> on/off).
>
> Hyper-V seems to do the same as KVM, and kicking another vcpu could be
> problematic as well, as it is just using IPI.
>
>
> Juergen

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPau_DEYadey9OL%2BiFZKEaUTqnFnyFs1dU12o00mg7ofA%40mail.gmai=
l.com.
