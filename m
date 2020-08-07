Return-Path: <kasan-dev+bncBC7OBJGL2MHBB5VQWT4QKGQE32LMZFA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DA7423E9AE
	for <lists+kasan-dev@lfdr.de>; Fri,  7 Aug 2020 11:01:43 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id p2sf531454vkp.4
        for <lists+kasan-dev@lfdr.de>; Fri, 07 Aug 2020 02:01:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596790902; cv=pass;
        d=google.com; s=arc-20160816;
        b=ctGld0s59usl9TTj5BMvTh9gp/OOLWzlv49kzlWWa4A+x27VrniyALp2TU3eJirbnx
         KPbcjRA1n2YnIHjwgY8oVYePjCLAhQyb5w/EQaUBQyIMReNUVymwMPmomBMk5z/wkh1s
         990gls5YCc3JzMG1NZjoJkCAFiGGo++Vo9bso2RGl0QjvQxp5/g6vjKLClybdDFOeQHz
         dn4nxNfoOuSBIgxk7kljPfu7zFLetci74ILpRT7H1n+VQFeKGanQCAyp1dqAr1PeA8I5
         qPBov3Boqhaj4WbK9zL49hyiToQQ/NG7q4fPAEF0++hE1lKgUQs/cK5fg+X3mR3pnY+I
         Cq/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2ww/poeR2NXv/gWG8wrQULCmQl8lFBg7dHMye/2/EPQ=;
        b=lAP8CAaoDM/HZy0xUmks8u8ww90s7QWFvGeLxsv3JyteiEXFRt80JpOdeR0Rsv8QO7
         82Tmf7nEIBswa/MkDKjC2gWSY2IzgscqFSN+H6+CRFNKlPL9SANXx7UDfM/LF9BQ+yRN
         d7mSUb0vKzqOEk1xy2614Q1PjXYI7+z6B808KxGYe2phEuAMwGhBdYAq+zpmT7i7I9JG
         knBMYweCNmeKHh+Ta+eoXYTMN7vTCg5jAx8oRLLPc9SCM7JoVvQvly4pvefPV0ZX65z6
         Dy6ZFmtG3cqrqr37faseqYtyEpysT8g9Uv+2P37W3/t9+8XmxvHvRMxptpX7lazC4YvT
         LZZQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QQCDtvOe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2ww/poeR2NXv/gWG8wrQULCmQl8lFBg7dHMye/2/EPQ=;
        b=s/39xOkiGCs5oX/c4l2qQhtm8GSPo6Pbg1uOYzRM3fxhSGoSIUvMbtUZEQjzcKsIJg
         lybtVW9/PVeB743ItpoNEHi87tMAQJl8dEdIbVO6oYoSxh7pgWs9aM63TuhtbWXOIIyB
         14y2teoHUd66sFLog+hSluVaavYLqi4+M1XvldQfxz5+A5nZzA/BIADycUXtY7EsZrcm
         L9BfVrQlvJTaf7STHRmDbAaRlxgXW0xPM9e6gDWnPM8ZH1B5Z0mw9vGlbyfGR9NguF8K
         NrkzhS0RghSh+cvuBZPL0uaoxvhzkE7aN6r9jpKK6ycJ7L8OuD2ntN5TKLf0nieM2SjD
         whqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2ww/poeR2NXv/gWG8wrQULCmQl8lFBg7dHMye/2/EPQ=;
        b=uLzJIH3pRPd8EKxZRMu+d9DvZwCqlZ++A71hJE1Ak3TX/0tcvxAb2auC6kDB7oL4Yh
         WcZFhmEIU+VPUPwayDlcGlxh8W87lkGJYDYYFlyHcpVEWPrbWYjIGUEIRmec5/drI9HC
         ePZkgjwcD+v9WjEQBS2FWUG/bPdTg4gxaMdbCKETF4Tgo5qs2LtYkU3Q5et8dWKbrEsr
         PG1C5Mmpr9j5mrIL3n0pjTQSnm3bNYlOaN4WPvHiRs8nb7sl+9bibS2NAwRCz9E5VuWI
         ZyDBcH2Xu3Ac2zQVzYPjvhob/+4LiQL6W42fskJBdN60HcY4WjebGiIFP3XLtM+plqMU
         XX+w==
X-Gm-Message-State: AOAM5313TdNbV5U5vaJRvb42X8nP7lbrA3+Xen7nqpcpxiAhvaA2e1SM
	hJJ2fx6pkp8pzmYj0jhxF5k=
X-Google-Smtp-Source: ABdhPJwwQkn1QopwwxRjMPfPuNvDaaM3+RC9rZ0M0jbaLySY7BT7IDWTiwbS0jrSphZslaXK2Q8FhQ==
X-Received: by 2002:a05:6102:7ae:: with SMTP id x14mr9276324vsg.89.1596790902478;
        Fri, 07 Aug 2020 02:01:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:dd9a:: with SMTP id i26ls339204vsk.6.gmail; Fri, 07 Aug
 2020 02:01:42 -0700 (PDT)
X-Received: by 2002:a67:ec13:: with SMTP id d19mr6698019vso.28.1596790902067;
        Fri, 07 Aug 2020 02:01:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596790902; cv=none;
        d=google.com; s=arc-20160816;
        b=Eq3PZS67SYGmdlsSU0oh1ICZmvdB1GZqaSSdwpgHfph8L6QQLs+SMX3lx4Jeucvcnc
         G+MWMSMeCK8jhoNrp06L4t9zREuvK4ndFSewBm3hqsllb5B0wuBzvcaBue5GAqYHspFk
         wGomQ1+KzvaheDzBAZCJVSIkguckXyT6drxqpXLbJH7MgqbV5d9y+bDsU6caZKgyOuyN
         YLTKRGh/HtcLVN8jpiEjqJnEiB1WPAbcrNRHfPDtx+UyMi/BOPug2FIQQT87XKi5lZg6
         gvEZVkTZZieQHgdGa4NF5guBTcmAp4PZQkPjaSp+m5A2zHIyGFqUf0EnWEcPzrR4OgvY
         hfXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AmcYU/Cqf1PQgYD//8cKRjZoT/V5udiPWhn6Gby65YU=;
        b=EF7/oFZWWhGACewAOs2JmQSQNLduUeq5DptwHU0VodayfMPYXQlr9Olt7opc2cgJuf
         z9hSNZDzVTg1Bl/mJoBEcrV9uNg3RWMpTaykpFQgSWBInbbRvAA2Z3419lxaNRNt+NXd
         sqQfHxzabTFuVtn2xzcLQuiIoQkjLuR0Hikl4KoLEzzbuDIWXPqD9hNAWVjGBIcXuhkB
         SeRhSfubU1Uhzpp6HrgL7ANTU3g71CIXlm7IB+jhUMg23CYO0ZrCKDDHh1YR/kpzSPgd
         IYGoDBwgp/WUER3MzpikoK4IvHYlciz9lhgmiMoKtkSjif10JJlfP/rR71cBlkGbwr9T
         7mOA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QQCDtvOe;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id q1si16667ual.0.2020.08.07.02.01.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 07 Aug 2020 02:01:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id l204so1316262oib.3
        for <kasan-dev@googlegroups.com>; Fri, 07 Aug 2020 02:01:42 -0700 (PDT)
X-Received: by 2002:aca:b8c4:: with SMTP id i187mr10655594oif.121.1596790901265;
 Fri, 07 Aug 2020 02:01:41 -0700 (PDT)
MIME-Version: 1.0
References: <0000000000007d3b2d05ac1c303e@google.com> <20200805132629.GA87338@elver.google.com>
 <20200805134232.GR2674@hirez.programming.kicks-ass.net> <20200805135940.GA156343@elver.google.com>
 <20200805141237.GS2674@hirez.programming.kicks-ass.net> <20200805141709.GD35926@hirez.programming.kicks-ass.net>
 <CANpmjNN6FWZ+MsAn3Pj+WEez97diHzqF8hjONtHG15C2gSpSgw@mail.gmail.com>
 <CANpmjNNy3XKQqgrjGPPKKvXhAoF=mae7dk8hmoS4k4oNnnB=KA@mail.gmail.com>
 <20200806074723.GA2364872@elver.google.com> <20200806113236.GZ2674@hirez.programming.kicks-ass.net>
 <20200806131702.GA3029162@elver.google.com> <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
In-Reply-To: <CANpmjNNqt8YrCad4WqgCoXvH47pRXtSLpnTKhD8W8+UpoYJ+jQ@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 7 Aug 2020 11:01:29 +0200
Message-ID: <CANpmjNO860SHpNve+vaoAOgarU1SWy8o--tUWCqNhn82OLCiew@mail.gmail.com>
Subject: Re: [PATCH] x86/paravirt: Add missing noinstr to arch_local*() helpers
To: Peter Zijlstra <peterz@infradead.org>
Cc: Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, fenghua.yu@intel.com, 
	"H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>, 
	Ingo Molnar <mingo@redhat.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	Thomas Gleixner <tglx@linutronix.de>, "Luck, Tony" <tony.luck@intel.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, yu-cheng.yu@intel.com, jgross@suse.com, sdeep@vmware.com, 
	virtualization@lists.linux-foundation.org, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	syzbot <syzbot+8db9e1ecde74e590a657@syzkaller.appspotmail.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QQCDtvOe;       spf=pass
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

On Thu, 6 Aug 2020 at 18:06, Marco Elver <elver@google.com> wrote:
> On Thu, 6 Aug 2020 at 15:17, Marco Elver <elver@google.com> wrote:
> > On Thu, Aug 06, 2020 at 01:32PM +0200, peterz@infradead.org wrote:
> > > On Thu, Aug 06, 2020 at 09:47:23AM +0200, Marco Elver wrote:
> > > > Testing my hypothesis that raw then nested non-raw
> > > > local_irq_save/restore() breaks IRQ state tracking -- see the reproducer
> > > > below. This is at least 1 case I can think of that we're bound to hit.
> > ...
> > >
> > > /me goes ponder things...
> > >
> > > How's something like this then?
> > >
> > > ---
> > >  include/linux/sched.h |  3 ---
> > >  kernel/kcsan/core.c   | 62 ++++++++++++++++++++++++++++++++++++---------------
> > >  2 files changed, 44 insertions(+), 21 deletions(-)
> >
> > Thank you! That approach seems to pass syzbot (also with
> > CONFIG_PARAVIRT) and kcsan-test tests.
> >
> > I had to modify it some, so that report.c's use of the restore logic
> > works and not mess up the IRQ trace printed on KCSAN reports (with
> > CONFIG_KCSAN_VERBOSE).
> >
> > I still need to fully convince myself all is well now and we don't end
> > up with more fixes. :-) If it passes further testing, I'll send it as a
> > real patch (I want to add you as Co-developed-by, but would need your
> > Signed-off-by for the code you pasted, I think.)

I let it run on syzbot through the night, and it's fine without
PARAVIRT (see below). I have sent the patch (need your Signed-off-by
as it's based on your code, thank you!):
https://lkml.kernel.org/r/20200807090031.3506555-1-elver@google.com

> With CONFIG_PARAVIRT=y (without the notrace->noinstr patch), I still
> get lockdep DEBUG_LOCKS_WARN_ON(!lockdep_hardirqs_enabled()), although
> it takes longer for syzbot to hit them. But I think that's expected
> because we can still get the recursion that I pointed out, and will
> need that patch.

Never mind, I get these warnings even if I don't turn on KCSAN
(CONFIG_KCSAN=n). Something else is going on with PARAVIRT=y that
throws off IRQ state tracking. :-/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO860SHpNve%2BvaoAOgarU1SWy8o--tUWCqNhn82OLCiew%40mail.gmail.com.
