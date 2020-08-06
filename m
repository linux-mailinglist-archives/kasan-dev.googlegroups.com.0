Return-Path: <kasan-dev+bncBC7OBJGL2MHBBIOVWD4QKGQE7GEORUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5D41223DB80
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 18:06:58 +0200 (CEST)
Received: by mail-qk1-x73b.google.com with SMTP id n128sf33452035qke.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 09:06:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596730017; cv=pass;
        d=google.com; s=arc-20160816;
        b=rKpoAlPGScpmwJfXS4vrgV/MW/5chXqVxL0VXEg/qzPd/nhoj7kjbVma1DaodReGcF
         iQcdME9jV52NidPr1tqmQAHregguTPR24EbG+F6uX0NV0x5Fio15FsXznMGxa2aCPKYE
         c4ke2oNUPuvHRTbBLIgOuhxvdHABjVaUQvwqfBuYRt8imhoXKBgVSIfZApUSnZiIlSVS
         TiTlP7oKLNlQkhkPvOWueMSg2hML+mAsu+22B3mV8nFi2ZD/XGFzHjl+A22ODsYowFWs
         QttJjTNVm4DQIiSgVUKn0XZqHB+j7AMLSBmc7pjTF5S2Di9f6Ot9EtwapAxYtEI73YVC
         JjKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KLCIKz/1I3+Zn3KDsmZyIoQ6cUGidRxZ+TCThW5Oo2E=;
        b=YgNEzd8rqNBgojaH/Ft559RMjVcw1DMHcxScwiyw3ZwmI6tohlKl0n9M0mUi4BbR9J
         JOQvck3Yd547+GcD77yEaD62zKQJWgxRqVhlyA4fXo32htvYm8P0/QnxoOI1qorrN4JR
         n6jNajTyFVfVpHUPcAenP9sbQ48UGz5REpCc88MKk7zV6XEBK4Ss1OhPTPOTMaOD5uwU
         jMhBk4K3xmaxCFoa/zkYZgMfCxuymB2kpLTEEe0/VgN9ucIdRuunaCIShqmPaNy88lB7
         rvUkirOSlaofCZ8wuhoMYJrPDXiyko1BWf5XZ4NBVrqZ1X8yalgvmS/IOymg0FgBxT0m
         c9Dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t+y4Obij;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KLCIKz/1I3+Zn3KDsmZyIoQ6cUGidRxZ+TCThW5Oo2E=;
        b=UV/XKdhqSNVwWUEj89Gf7aqKjxiSS/ANDdLCz8K25O21MJ0EWOtxgYFY7Rxef2HPEW
         HqEJ9CFLZr+IM18PmoO1NkW3tQAyelVY9PZfRLiZHV/Nl0THT991K0wXw7veRR/TPfPR
         zDO3pvK0lmH5rExnt5+XXM4M7ZAYHRAZNdF+LNSAY9QQX0FBN61Kj3omnGCyLUZEj7jb
         3/ohRsyNj1/qsBto9G9LtZmllBLa4DviIJW+PuDX3g1p6CEyK1/hu/YbbAkqpiWi+pv3
         0yT2UjILJ5qr+43DuQYTiB6utIfBmf33pnMIMnTbm+Am8EcjEBP3UQBiB5kA4+uea1Ka
         pbmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KLCIKz/1I3+Zn3KDsmZyIoQ6cUGidRxZ+TCThW5Oo2E=;
        b=a9AjEfRWyj/kv5ynpDlQC1j4PPLHhCPPWCPl7BbCq5BqiK4uZo5cF2xoZ3C8ZhVUaM
         W8nHjt06SRyy+NL6FsHsDPSBEKiR/Oo/I8Hb+svh1WHRRbgm/xo66n7r5QXr1S2oy27a
         JnYW35FHELIMBzUA1kmA0x3+PXEhZKKrpXP0QhANQZ6HZVDEY517llLPqAjb/rcaxWkY
         UXbIc7XVS9pQXylrQPuDvA95JPtzL9/bVs4w3EZHGaXXrPG7yGCyY4CxE2TyPyP4KUZP
         pNYWL6PZshhBLPz0nONbBjP6sFHg1ueRlc28sK6DRj/LMPq+NjxdeQzsjAgaiFIQbuBe
         xVcQ==
X-Gm-Message-State: AOAM531W8RRuG6rQwB2pHU3yG934dFSirHs9TiyRCx4utl+FPJNH9kKW
	0Cyz8oQNVw14beX+1KDmiD4=
X-Google-Smtp-Source: ABdhPJypgXC+kGWJ7uVoX+W3Fo1EaoabYPFVBvkObhe0iSWzjEpVTceevurT7fsl++Tj+OTIEzNNzA==
X-Received: by 2002:a05:620a:1645:: with SMTP id c5mr9251248qko.309.1596730017338;
        Thu, 06 Aug 2020 09:06:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:36b:: with SMTP id t11ls1565533qvu.7.gmail; Thu, 06
 Aug 2020 09:06:57 -0700 (PDT)
X-Received: by 2002:a0c:f4d0:: with SMTP id o16mr9612834qvm.225.1596730017011;
        Thu, 06 Aug 2020 09:06:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596730017; cv=none;
        d=google.com; s=arc-20160816;
        b=VLlTABSu5NpWMs+FbjjEbMdxO6419tZVYLQox5OJBVzRD6Gby8e8rpXJDQk8vMxnT0
         hCr1C4BQIZ6H2m4KkSzBO+X4lUntLelmTf58tNApAOBCOIag0yS3ue3jApeUBGKEz1h8
         zheX57V8H0Mj6k5WDVAvlJMPxJGSWdO46q4+5B/dRticlkdmv+s5ltWw8U3dwm1W2tiP
         lFrysKtpGD7AqZZxtIG00Le3wagshQR1ibV7LCbTeC/1EgHAULQZsj1trnCxBCddSgBV
         KnGQtgnZgjathy32tGBt7xTjD7R9MYRlFTNA2EGzXg/jDDRMIFK/fGIb15pwPKswRIOD
         edVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kRzJPbiSWqPMYf9cXUnubjz9KwLdR0t2PlxbglQqDmQ=;
        b=cpDpP1u4850BKG1IXmrcHK4ercyD3F5x5IxGC65cEfkz1emquIwanHYRZIZjUQ23DD
         Fxe23q4huQx5hNohp6kHtI4XnBBs6fOOp0D6ug5da2W4kUew/r4VAD9csobRJfMyRxHU
         uq1DNDz0ml8g5o/Kb2T6I6/ilyD6Y9ZSqKoIrJbDC49Q6xOS3H/oUbUzeKU8wzOdQ1ej
         FZIQS2g369JtLk/w80aKg4XDPFxQ6qGCdGeotjLb0aFYKxCUD8amE0Ql5v7ms/e/oati
         iywTm6/9jUt0WrfVxYufJ4mP9upXMqpfryRY95NvM5+QYanYFYDoV+2TmlBgnKNQjXZb
         UJbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=t+y4Obij;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x344.google.com (mail-ot1-x344.google.com. [2607:f8b0:4864:20::344])
        by gmr-mx.google.com with ESMTPS id m13si261367qtn.0.2020.08.06.09.06.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Aug 2020 09:06:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::344 as permitted sender) client-ip=2607:f8b0:4864:20::344;
Received: by mail-ot1-x344.google.com with SMTP id e11so12373114otk.4
        for <kasan-dev@googlegroups.com>; Thu, 06 Aug 2020 09:06:56 -0700 (PDT)
X-Received: by 2002:a9d:65d3:: with SMTP id z19mr8224587oth.233.1596730016189;
 Thu, 06 Aug 2020 09:06:56 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000007d3b2d05ac1c303e@google.com> <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net> <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net> <20200805141709.GD35926@hirez.programming.kicks-ass.net>
 <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
 <20200806074723.GA2364872@elver.google.com> <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com>
In-Reply-To: <20200806131702.GA3029162@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Aug 2020 18:06:43 +0200
Message-ID: <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*() helpers
To: Peter Zijlstra <peterz@infradead.org>
Cc: Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com, 
	"H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Luck, Tony" <tony.luck@intel.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, yu-cheng.yu@intel.com, jgross@suse.com, sdeep@vmware.com, 
	virtualization@lists.linux-foundation.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=t+y4Obij;       spf=pass
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

On Thu, 6 Aug 2020 at 15:17, Marco Elver <elver@google.com> wrote:
>
> On Thu, Aug 06, 2020 at 01:32PM +0200, peterz@infradead.org wrote:
> > On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
> > > Testing my hypothesis that raw then nested non-raw
> > > local_irq_save/restore() breaks IRQ state tracking -- see the reproducer
> > > below. This is at least 1 case I can think of that we're bound to hit.
> ...
> >
> > /me goes ponder things...
> >
> > How's something like this then?
> >
> > ---
> >  include/linux/sched.h |  3 ---
> >  kernel/kcsan/core.c   | 62 ++++++++++++++++++++++++++++++++++++---------------
> >  2 files changed, 44 insertions(+), 21 deletions(-)
>
> Thank you! That approach seems to pass syzbot (also with
> CONFIG_PARAVIRT) and kcsan-test tests.
>
> I had to modify it some, so that report.c's use of the restore logic
> works and not mess up the IRQ trace printed on KCSAN reports (with
> CONFIG_KCSAN_VERBOSE).
>
> I still need to fully convince myself all is well now and we don't end
> up with more fixes. :-) If it passes further testing, I'll send it as a
> real patch (I want to add you as Co-developed-by, but would need your
> Signed-off-by for the code you pasted, I think.)

With CONFIG_PARAVIRT=y (without the notrace->noinstr patch), I still
get lockdep DEBUG_LOCKS_WARN_ON(!lockdep_hardirqs_enabled()), although
it takes longer for syzbot to hit them. But I think that's expected
because we can still get the recursion that I pointed out, and will
need that patch.

I also get some "BUG: MAX_LOCKDEP_CHAINS too low!" on syzbot (KCSAN is
not in the stacktrace). Although it may be unrelated:
https://lore.kernel.org/lkml/0000000000005613c705aaf88e04@google.com/
-- when are they expected?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8%2BUpoYJ%2BjQ%40mail.gmail.com.
