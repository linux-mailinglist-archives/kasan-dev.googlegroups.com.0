Return-Path: <kasan-dev+bncBCMIZB7QWENRBDVSWXXAKGQENIJFMRY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0AE74FC7DF
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 14:39:28 +0100 (CET)
Received: by mail-ot1-x33e.google.com with SMTP id 60sf3221701otd.19
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 05:39:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573738766; cv=pass;
        d=google.com; s=arc-20160816;
        b=u2TiM3vGUmdX9QdiZ/gTFpYjGHeFKVa1UfMSb17XrPa6AWuHUS6yLwac68a64shn2b
         UJXHwpx9NQFIahR3gwh1x6yXwZtVuzI5N4/pRpo5FISUdTdH2rPGFITe+/JaqMgeHc2b
         RO4fcNpIGungySfjey7haiMfTXCQ2AUn6MWQ5u2Ftu6tnOviX+4Ue26KYt6afgm0mdRq
         DPozRu4wnIAveD8y1vwCjvk3MkT1Xt9kfGebywtXSG9NmQTK1HcPha6OeXf9dS60Fz5j
         42iDM2GNW1tJ74oMyQAaxEUW87RM9XF07rjce5BJlrlGEeP8el221zvoAavFok01coD6
         Qu1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=IzsaePmjIIPrxBLKUNoMQJZCa4NgW4JU5j1ghjrhOaA=;
        b=PPq2HLGRdGi8Bq1vFPkoEj3XliYaM2EPKaPfQmPP7dIq73UKI/izYeKS01dDvhph4r
         Ox0B1h5PSq9q3uXhbfY07i02dkFj2rxM5S9qXXvEE0yw0VP7ju8jot0+8NCIbC6ieX60
         mJugOfos4VR897X8KSTePi0qYZytgUActfBF4ZzfxaMHu0z+s281URMb68/YO3Q8InQ8
         Sp8euFcqQ5fsfoNm4peZWqgujTBrgAUMv2mNaG2THVc633iQn8F4ZGYrpqaq7NFX8vcI
         aFfnkE0xC6wkLFnUgfXNZATQ6Sc0S2Ll3CUyGtDKgYQ9EZoXq/LS4PpN9lhC7HRoGL/c
         p8zQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nt47RbTv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IzsaePmjIIPrxBLKUNoMQJZCa4NgW4JU5j1ghjrhOaA=;
        b=f4Lwvn2HFAEHhWlHXlXtDiBa0TxqqYriDQTMr/dhWj94MFQZtUJ5PZR08ieMesHbig
         mxm5EQVvmVJNMUHFznul4YKpLp07V5xOo+VbHZcoGLSf0GREnEwhDQj6+uBGFl4+smJc
         PN2BL0xnygwD1KPMqbkbBlaD28cKvZMyoY/p7qvhh2hflMvuQjBVWil/PNW3WvjHA6n4
         bIGAwlg1abUuyDvQC5avJaPSH3Z8V1gmBmzKOTIgFJK2qRTv8NXmeZeS7LHOOdOZT1M2
         CB5JJZTrV40JL9XfhmUdgPeakLfdWGIUx7g5mLrlU/AHgABhNEAUdEFOoPqe9Qvt2Y9Z
         SJCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IzsaePmjIIPrxBLKUNoMQJZCa4NgW4JU5j1ghjrhOaA=;
        b=Y41G3Rlz2Eh5guruVPtFU3xDBvi4/xO4erDo0gqSVaJFRTp5pNOiT4AoS41RkPskkM
         8iHWTwh+VXwAz2Ss9lH9TSEJMM/r6/7SYsjSHNPpkYxPryyCgxuHpuaWX41zznbhdVaO
         YPTi7SrGCAvLtueDxbYX4x5sduniLt5zj38sSSbpvG2660ZS5TRfSzMiemqhKGNWGTWh
         jJQbLL/28C6WSZDBM8XXar0Bxtut8WKpSnz8/NOq77/zra8aA9MkMB9pcypHzXhUktPM
         nPysg9g0iJ+m+Gn2I95n+DeM9hVIu7WaL4PZ0O6Uf5BPiyBdEojcsAtH0b+nFzT1x7gJ
         xcYw==
X-Gm-Message-State: APjAAAXhAye9z92b8TsuXKnAB1NNX3yJX3h3wEMxtU+MYxr57uNZYmMY
	bVMFnH0CX5wgJrIGfB2HozI=
X-Google-Smtp-Source: APXvYqx6y/KGWGQaecVoYkSYRMNs/wZgqBNzCu2btVbtuWSlx+0ZkZgL8UEeyJd1tKjQBuRvL8pLog==
X-Received: by 2002:a05:6830:4a1:: with SMTP id l1mr6961410otd.291.1573738766543;
        Thu, 14 Nov 2019 05:39:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:b2b:: with SMTP id t11ls1275980oij.14.gmail; Thu,
 14 Nov 2019 05:39:26 -0800 (PST)
X-Received: by 2002:aca:c50f:: with SMTP id v15mr3682146oif.5.1573738766173;
        Thu, 14 Nov 2019 05:39:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573738766; cv=none;
        d=google.com; s=arc-20160816;
        b=znbjl9OFF4GB6HpTipvCEC0b0w5hvCrUzHHw+qN8Comuw15zP5HAiW4uN74R4ylMxi
         Bb0+Tmrw8Dys2dvltDfbL1tUdXuiqFUNeaJqDRD3CSDs97b8l9U6aLIPaJoBfEd5bkKH
         aYmw0sweFcXk8PdtYqOGAhTfRIEnDeAoFnk/HYffqcXIF2UpP7eGioQ9P6d43IeYY9s3
         px7xjjqvHyukPEnTfczv+Nm2l8qRxqKBiz8H6bp/ksYkksccc/q1tPRd18zRQ660gzqW
         wAkqMf6OF3A15eTIyTFhEAe0AOLES95Lqe1MCsaCaZVbFg7sfKK2mtNL2sS3lO7vPSM2
         XUcQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vwE1RWWFWw0V4uLoO65K5NOjyOKWscg7q/BhLYdVFnQ=;
        b=qgoO3Q6Ia90yJmYOsgyas2cjswF11uClARS28fFTEu2DYKaAIXJzvwRLsr7Hlj5npH
         c91lYVz9FLhuo0HJFg1lEiNyDn1+l8I/8fS/Aq25o1LkpgANAdfnCHL5j7pa9utYup0s
         DJZ80DU9/ZFjObsXWXqN9zdsaiiahf6OnBelzrMAYG2o9TmrUJr9FMtx37SfzuemEi95
         +/IiXg7K4dv/STD8JMWsZ2pf4VXIc/ih0m/ZzIryYULBYQxjGIemVRp38eIZ9hb1Qhsm
         ySJBY8bxbygM4Soy0LUS9Bs/NVPw6BbBQRqLI2e4RYpH1k7mAH2fcNUEg42oG4ur4yl/
         9dpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nt47RbTv;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x742.google.com (mail-qk1-x742.google.com. [2607:f8b0:4864:20::742])
        by gmr-mx.google.com with ESMTPS id l141si247810oib.4.2019.11.14.05.39.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Nov 2019 05:39:26 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742 as permitted sender) client-ip=2607:f8b0:4864:20::742;
Received: by mail-qk1-x742.google.com with SMTP id z23so4930786qkj.10
        for <kasan-dev@googlegroups.com>; Thu, 14 Nov 2019 05:39:26 -0800 (PST)
X-Received: by 2002:a05:620a:14b9:: with SMTP id x25mr7641000qkj.8.1573738765358;
 Thu, 14 Nov 2019 05:39:25 -0800 (PST)
MIME-Version: 1.0
References: <0000000000007ce85705974c50e5@google.com> <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de>
 <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com>
 <CACT4Y+ap9wFaOq-3WhO3-QnW7dCFWArvozQHKxBcmzR3wppvFQ@mail.gmail.com>
 <CAK8P3a1ybsTEgBd_oOeReTppO=mDBu+6rGufA8Lf+UGK+SgA-A@mail.gmail.com>
 <CACT4Y+YnaFf+PmhDT5JRpCZ9pqjca6VeyN4PMTPbCt7F9-eFZw@mail.gmail.com> <CAK8P3a1viWDOHPxzvciDt8fPCm3XkbLJxAy1OjtJ_-vuP-86bw@mail.gmail.com>
In-Reply-To: <CAK8P3a1viWDOHPxzvciDt8fPCm3XkbLJxAy1OjtJ_-vuP-86bw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 14 Nov 2019 14:39:14 +0100
Message-ID: <CACT4Y+YsC7yX5d8Gw=C7pm_4xcZ1wjzb_=AoPOL1k5FEPERbzw@mail.gmail.com>
Subject: Re: linux-next boot error: general protection fault in __x64_sys_settimeofday
To: Arnd Bergmann <arnd@arndb.de>
Cc: Thomas Gleixner <tglx@linutronix.de>, 
	syzbot <syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com>, 
	John Stultz <john.stultz@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	Stephen Boyd <sboyd@kernel.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=nt47RbTv;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::742
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Thu, Nov 14, 2019 at 2:38 PM Arnd Bergmann <arnd@arndb.de> wrote:
>
> On Thu, Nov 14, 2019 at 2:28 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > On Thu, Nov 14, 2019 at 2:22 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > On Thu, Nov 14, 2019 at 1:43 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > On Thu, Nov 14, 2019 at 1:42 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > > On Thu, Nov 14, 2019 at 1:35 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> > > > > >
> > > > > > On Thu, 14 Nov 2019, syzbot wrote:
> > > > > >
> > > > > > From the full console output:
> > >
> > > > >
> > > > > Urgently need +Jann's patch to better explain these things!
> > > >
> > > > +Arnd, this does not look right:
> > > >
> > > > commit adde74306a4b05c04dc51f31a08240faf6e97aa9
> > > > Author: Arnd Bergmann <arnd@arndb.de>
> > > > Date:   Wed Aug 15 20:04:11 2018 +0200
> > > >
> > > >     y2038: time: avoid timespec usage in settimeofday()
> > > > ...
> > > >
> > > > -               if (!timeval_valid(&user_tv))
> > > > +               if (tv->tv_usec > USEC_PER_SEC)
> > > >                         return -EINVAL;
> > >
> > > Thanks for the report!
> > >
> > > I was checking the wrong variable, fixed now,
> > > should push it out to my y2038 branch in a bit.
> > >
> > >       Arnd
> >
> >
> > This part from the original reporter was lost along the way:
> >
> > IMPORTANT: if you fix the bug, please add the following tag to the commit:
> > Reported-by: syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com
> >
> > https://github.com/google/syzkaller/blob/master/docs/syzbot.md#rebuilt-treesamended-patches

/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
this

> Is there a recommended way to give credit to sysbot if the bug only
> existed briefly in linux-next? Simply listing Reported-by would be wrong
> when I fold the fix into my patch, and it also doesn't seem right to
> leave it as a separate patch while I'm still rebasing the branch.
>
>       Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYsC7yX5d8Gw%3DC7pm_4xcZ1wjzb_%3DAoPOL1k5FEPERbzw%40mail.gmail.com.
