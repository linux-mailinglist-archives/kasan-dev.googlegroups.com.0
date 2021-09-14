Return-Path: <kasan-dev+bncBCJZRXGY5YJBBD6VQOFAMGQESKEYESA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc40.google.com (mail-oo1-xc40.google.com [IPv6:2607:f8b0:4864:20::c40])
	by mail.lfdr.de (Postfix) with ESMTPS id D51AC40B6FB
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 20:31:44 +0200 (CEST)
Received: by mail-oo1-xc40.google.com with SMTP id e17-20020a056820061100b002910b1828a0sf11720315oow.16
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Sep 2021 11:31:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631644303; cv=pass;
        d=google.com; s=arc-20160816;
        b=qnaNF4AqOCfTLVA8onMCzCNm6tUNhR7A+GyjVLlSQMlHkxSP8IPD95zFi34QlA/GBE
         G1xObzDlCmnD4V3qqP/TkIy4TPtyvDXd89DhhucNxJ5WWWnlk9uQsVUNq3da7FcuPmOE
         zZmf03Df0qtMRSWCfqvmoTqmW+5jzC+aVq4Bzmk8ytwV2pcjxLYXcIaXbGkRXRS1EDmc
         G+wJObrd0rfJxcxiRRVbMS6W1enHNoHR6Ttzznb6Bg+sAxwxFHp9z4FYF/qxINJMwZiZ
         9AaX7lEVBYndOlwco9uGHzZLyTUE9K0QihqrMBK6ikGq9d3iVBT7LxPB1ETODK3kAcqA
         j8Ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=PN0dVPZfp7iCS52bghHufnnCmq7phiuiqsBuRHNB9hI=;
        b=uoJYkG/5penzeqxwIPP4cFpBNNme6WemT5Zf+Ifh1C4YDIDCsrH2W9ckPlXJFSDVw3
         f6YvKenxOKjl1uYXBaSQ7BHM5lmIPGTvdAwx1DXc+v0e+cMHWW9LlyVhxdaDnrRyJK2E
         atwVRG8PUS/Zn9Ii+2LYbXK6d0KKvpQl6Qe3alAYpRHDA9e/Xh5m86AuYXFzfGNNwnOh
         kkmd3GZLqzv3kBn4uIvJ5nvYJtNsnqUCbWiQHMO8aUQlRTG90iVkdI/k3vyVtaCyJzt/
         2euskiv/Beg33Drp0GZz9kTSMJsKOa0Owj1DKHhJ8jedPytLqgyGcOZn+JfikLHMYFwx
         TgAg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=m+iZMFxR;
       spf=pass (google.com: domain of srs0=ytkl=oe=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YTkL=OE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=PN0dVPZfp7iCS52bghHufnnCmq7phiuiqsBuRHNB9hI=;
        b=NgR5SR8eaw2y73SSVkgU6alWZviTLIyhfzDA13NKqpCLQQdP2/yDUYjOL+V1XUuXDT
         v9fahWNJfUjqxeDb1f7Wc9Bh5jId9pJZdXJkl0xoHduOtk7udDiyy/1brTZQ24vwA3Lf
         tdhrYaCQPUR+iNCPbEA0V0Io8CLlVvYdBKGKgiFAHyvIyvIu5GxwZ4wK+vOy6hy8pBPl
         1/IenqEBwB/NHg+7Uc7L8/jl2/J80DTHY/xjkfHissCJAVb/CnIoZ45mzI4eFtTPdpAI
         oHHywXSmp5hk1dTYO2BGaMzPaYGqqU1nUuxN5FF6iyPH3UnkxpC86JcQWQ3q7bBePBUH
         tZFA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PN0dVPZfp7iCS52bghHufnnCmq7phiuiqsBuRHNB9hI=;
        b=TyEoOnsMToYi3NiXznX49N2BwQYuZ0xbkxYbbsPAhVSsMJNT+8e85NmyzyQJuI2pum
         TafLBB/On07XDs3OPYWQNe1GUB+tVNnOJknOFNkGCpOucMwlBVRWXRzY+8v+IR4Ta/kh
         nVPO4aQUmnOKqkWxPnno/xR/klCBFloYlnAEe7TmciJ+EiCM78BE7AJfZbbdGJqkINLD
         iyikJfot044Vd1ikaREM+VUOQ+ae5m2h7Rn3w1EHpe7bL5FC+ceMfRIvCIUQ5JJAzNN2
         dpQqYVuQcqSUOdz/BuQjW8ofWzWLbQIc4ma69jmwxI9frL66Q+oRt+7VLucoVuX+DHeP
         QoOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533NRJhtKzb3qfrrHLZfXiToS7lZEz/GrZDqeM34HCMZIMIUtzAv
	cSxazGhvod7H5Y9+XnWTyDw=
X-Google-Smtp-Source: ABdhPJzzfn+aaPtO3Rx8zuopb/+OvH/6bgYZd9JcM3tt+DemN5vGd3fW9EtlwcBT11wiNKxQT6WQ2g==
X-Received: by 2002:a05:6808:2cb:: with SMTP id a11mr2425713oid.107.1631644303552;
        Tue, 14 Sep 2021 11:31:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d344:: with SMTP id d4ls841922oos.11.gmail; Tue, 14 Sep
 2021 11:31:43 -0700 (PDT)
X-Received: by 2002:a4a:d794:: with SMTP id c20mr15163221oou.23.1631644303161;
        Tue, 14 Sep 2021 11:31:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631644303; cv=none;
        d=google.com; s=arc-20160816;
        b=hlE1JW7ZadWuXhw1YPJa6xHqUsG0OtNDoj3gxfgkRefbEG+CN78amqAEIOCex+OQEL
         SOCniJQDmp4By0w/ORdd6pZYscO7IU7cXrikRSG1naDenjyGLZLfdvgD64xIvCViJCuO
         8A9L4qmSp4d8XWnNorQS82xQzOthLacJ+fsuRl9BMfDQeY3NPpiMN3BglDIaIcHMxTbv
         +oS1yPJn2BzGYP6L39kSIjnH+RABd1dX0jKD+6sg2KAtFQuM+iZxIbwNljTfRy5TYpgq
         87F8P/NIP2p2MD21yEP9rVIsZs4INXXGds3jxNb3R6HXxTgpdxLfNHUOn1aggfq+U1EX
         Am6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=XgJvvyC/YYtz1UPtZTCkslpIoe53PFWMGAd3A8hbFVU=;
        b=0O1X2pGl/3BCQRvmbByM5XjrG/6bpZPchB6pYXXX79jCUHLn74HblBvrYrxKXKA1qR
         zi3sfLbmvriQPsKunbh53dCJIXA18BIrDsnxvMomXKblUwERqmq6MY4pE4xcoNUceHfj
         7EznJS48m4Lv9DGeCFUYh2FyGUIqeHMOl15hd6B3/ffC7xx3k6hVohN+5/uqORgbav83
         9Loh1DItjTLZPorOHmgaL+8ObnDjmLeKmDYopLmhwbvYpzo60vHB9Fl0pVFv/86LfWN/
         E4sv50oUnt7I4eV0MUM1bdRYPdisL5Hy/zafD2FKK5a+uhzASBITAawKHsAftukmfZbc
         PKmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=m+iZMFxR;
       spf=pass (google.com: domain of srs0=ytkl=oe=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YTkL=OE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m6si995392otk.4.2021.09.14.11.31.43
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Sep 2021 11:31:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=ytkl=oe=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 50EA660F44;
	Tue, 14 Sep 2021 18:31:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 198FC5C054C; Tue, 14 Sep 2021 11:31:42 -0700 (PDT)
Date: Tue, 14 Sep 2021 11:31:42 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, Hillf Danton <hdanton@sina.com>,
	syzbot <syzbot+0e964fad69a9c462bc1e@syzkaller.appspotmail.com>,
	linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com,
	Peter Zijlstra <peterz@infradead.org>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: [syzbot] INFO: rcu detected stall in syscall_exit_to_user_mode
Message-ID: <20210914183142.GP4156@paulmck-ThinkPad-P17-Gen-1>
Reply-To: paulmck@kernel.org
References: <000000000000eaacf005ca975d1a@google.com>
 <20210831074532.2255-1-hdanton@sina.com>
 <20210914123726.4219-1-hdanton@sina.com>
 <87v933b3wf.ffs@tglx>
 <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+Yd3pEfZhRUQS9ymW+sQZ4O58Dz714xSqoZvdKa_9s2oQ@mail.gmail.com>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=m+iZMFxR;       spf=pass
 (google.com: domain of srs0=ytkl=oe=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=YTkL=OE=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Tue, Sep 14, 2021 at 08:00:04PM +0200, Dmitry Vyukov wrote:
> On Tue, 14 Sept 2021 at 16:58, Thomas Gleixner <tglx@linutronix.de> wrote:
> >
> > On Tue, Sep 14 2021 at 20:37, Hillf Danton wrote:
> >
> > > On Mon, 13 Sep 2021 12:28:14 +0200 Thomas Gleixner wrote:
> > >>On Tue, Aug 31 2021 at 15:45, Hillf Danton wrote:
> > >>> On Mon, 30 Aug 2021 12:58:58 +0200 Dmitry Vyukov wrote:
> > >>>>>  ieee80211_iterate_active_interfaces_atomic+0x70/0x180 net/mac80211/util.c:829
> > >>>>>  mac80211_hwsim_beacon+0xd5/0x1a0 drivers/net/wireless/mac80211_hwsim.c:1861
> > >>>>>  __run_hrtimer kernel/time/hrtimer.c:1537 [inline]
> > >>>>>  __hrtimer_run_queues+0x609/0xe50 kernel/time/hrtimer.c:1601
> > >>>>>  hrtimer_run_softirq+0x17b/0x360 kernel/time/hrtimer.c:1618
> > >>>>>  __do_softirq+0x29b/0x9c2 kernel/softirq.c:558
> > >>>
> > >>> Add debug info only to help kasan catch the timer running longer than 2 ticks.
> > >>>
> > >>> Is it anything in the right direction, tglx?
> > >>
> > >>Not really. As Dmitry pointed out this seems to be related to
> > >
> > > Thanks for taking a look.
> > >
> > >>mac80211_hwsim and if you look at the above stacktrace then how is
> > >>adding something to the timer wheel helpful?
> > >
> > > Given the stall was printed on CPU1 while the supposedly offending timer was
> > > expiring on CPU0, what was proposed is the lame debug info only for kasan to
> > > catch the timer red handed.
> > >
> > > It is more appreciated if the tglx dude would likely spend a couple of minutes
> > > giving us a lesson on the expertises needed for collecting evidence that any
> > > timer runs longer than two ticks. It helps beyond the extent of kasan.
> >
> > That tglx dude already picked the relevant part of the stack trace (see
> > also above):
> >
> > >>>>>  ieee80211_iterate_active_interfaces_atomic+0x70/0x180 net/mac80211/util.c:829
> > >>>>>  mac80211_hwsim_beacon+0xd5/0x1a0 drivers/net/wireless/mac80211_hwsim.c:1861
> > >>>>>  __run_hrtimer kernel/time/hrtimer.c:1537 [inline]
> > >>>>>  __hrtimer_run_queues+0x609/0xe50 kernel/time/hrtimer.c:1601
> > >>>>>  hrtimer_run_softirq+0x17b/0x360 kernel/time/hrtimer.c:1618
> > >>>>>  __do_softirq+0x29b/0x9c2 kernel/softirq.c:558
> >
> > and then asked the question how a timer wheel timer runtime check
> > helps. He just omitted the appendix "if the timer in question is a
> > hrtimer" as he assumed that this is pretty obvious from the stack trace.
> >
> > Aside of that if the wireless timer callback runs in an endless loop,
> > what is a runtime detection of that in the hrtimer softirq invocation
> > helping to decode the problem if the stall detector catches it when it
> > hangs there?
> >
> > Now that mac80211 hrtimer callback might actually be not the real
> > problem. It's certainly containing a bunch of loops, but I couldn't find
> > an endless loop there during a cursory inspection.
> >
> > But that callback does rearm the hrtimer and that made me look at
> > hrtimer_run_queues() which might be the reason for the endless loop as
> > it only terminates when there is no timer to expire anymore.
> >
> > Now what happens when the mac80211 callback rearms the timer so it
> > expires immediately again:
> >
> >         hrtimer_forward(&data->beacon_timer, hrtimer_get_expires(timer),
> >                         ns_to_ktime(bcn_int * NSEC_PER_USEC));
> >
> > bcn is a user space controlled value. Now lets assume that bcn_int is <=1,
> > which would certainly cause the loop in hrtimer_run_queues() to keeping
> > looping forever.
> >
> > That should be easy to verify by implementing a simple test which
> > reschedules a hrtimer from the callback with a expiry time close to now.
> >
> > Not today as I'm about to head home to fire up the pizza oven.
> 
> This question definitely shouldn't take priority over the pizza. But I
> think I saw this "rearm a timer with a user-controlled value without
> any checks" pattern lots of times and hangs are inherently harder to
> localize and reproduce. So I wonder if it makes sense to add a debug
> config that would catch such cases right when the timer is set up
> (issue a WARNING)?
> However, for automated testing there is the usual question of
> balancing between false positives and false negatives. The check
> should not produce false positives, but at the same time it should
> catch [almost] all actual stalls so that they don't manifest as
> duplicate stall reports.
> 
> If I understand it correctly the timer is not actually set up as
> periodic, but rather each callback invocation arms it again. Setting
> up a timer for 1 ns _once_ (or few times) is probably fine (right?),
> so the check needs to be somewhat more elaborate and detect "infinite"
> rearming.

If it were practical, I would suggest checking for a CPU never actually
executing any instructions in the interrupted context.  The old-school
way of doing this was to check the amount of time spent interrupted,
perhaps adding some guess at interrupt entry/exit overhead.  Is there
a better new-school way?

							Thanx, Paul

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210914183142.GP4156%40paulmck-ThinkPad-P17-Gen-1.
