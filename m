Return-Path: <kasan-dev+bncBCJZRXGY5YJBBFURZWAAMGQE2X3LYII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id F36E03081D0
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 00:28:23 +0100 (CET)
Received: by mail-pg1-x53d.google.com with SMTP id j37sf4946029pgb.9
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 15:28:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611876502; cv=pass;
        d=google.com; s=arc-20160816;
        b=SqJQ05Ay3fKXwO0VFSyIL8LXs+ubXWNiC7jf+vou+2Zy/ZwyQpz5i8HlJ8jybC29sx
         eaNEh+9IluC8Czof/GSw1+QEzK9fAGJnmTSl1B6wO6d97GoveBBHPttBVA0gBRyWIFff
         XoQ72Yb7XhRjF5VAj8rcXfAiYh9O5WLAwZ91Je7+IpcpdlBQ+Emj7vcKYHL9x46J0e1H
         BgA1F391RAYPXq3mkUovPqAdnhbGcdUJqq/boRmP7eVSaP7v2XB7KnVIakKb6cqR9bEg
         NWb6YmoIpku0NP/tJfsaIaDlxt3LtZzzTB4shRuzgwfBblzAEN0xsVp3tYGmzQ7mQ+7v
         FuXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=IoM28wGhuOeXtdoNfSV/Y8Dg2TbniT/0tSBNxRLGZB0=;
        b=z90YIEnaxkzsG3X0OW70QKFvEzxqLCltmBhzD7qrcly4qab6k7vdmv8z8SPiL6a72v
         eYV9+F2mMdDn0/8T8OLZTSynfTblVU53NOgoZO+qJiOP2C0xpr/Pt+ATsNFEmNiuCYRP
         dIYnbSnrZwonv4MXq817+ScqwGciOrvPKzkT/oM4M1mawU28K0gr2JmFAeadPqh7ZIDh
         8FnGpcteaoYG/v83db+2aNfVDlq7fRFcDlmNWn9+ch7XuARGgTQVuZHu+VCe+mn1VL09
         lp4kwuLQ21AwwkcMpG2m9jallM35bQnhMWu4gEwpYModhxeyInd7hzjXzcdlNUUhxz47
         RuJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XQ7Haa5E;
       spf=pass (google.com: domain of srs0=ta0l=g7=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=TA0l=G7=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IoM28wGhuOeXtdoNfSV/Y8Dg2TbniT/0tSBNxRLGZB0=;
        b=VTCKSHLZSdQzxWuINrq26xy1FlFhnc6piioBl4sGCKk4fIL7JeZB2qeUvi7Bo4CtvX
         nTAOy71jGD7m92I0AM44mZ9TKIB/pD2CqBEOylgsh5+SF+8JOlbLqGown7+ssWpwFfrA
         NJRcvqmBDTJkupYSwqX1siRbNzFPiD38lzkSwj898Dv5ewyGWkEYOjwDokZz0jaaNUvW
         7jRkpAzXHtqgGKLKpGrcus/UenZxuyx3P3mHdZwntQu77D6+bbkUZ4QqV9Pp7nxgjuRY
         L/5uu/NVC04psmxfvSxIed+H8fS8MDDSOtFFOV9zOqI+lM2RtczoKfK+uXKLbo+3ViCL
         CppQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IoM28wGhuOeXtdoNfSV/Y8Dg2TbniT/0tSBNxRLGZB0=;
        b=JSF6Dn/L3sMU4t4zirvE5UfGYU8U019QxAkvWXD7+dEiFMs9nD+bjGY5+VadTrgtUq
         nrC8FxtHM8175UjzaxIpP+rLW92AOeaquhQ02kMjvZvZtog8EHgUinhrooQTu9kk0+3f
         Flf6Pu/vgQgKP4yv7hNW+XtHr/PMjwKByEWjZz3gXHiRGPV7i1PBbiUjh8yyuIbKroJ/
         8JQvZu2etyEh+jPVd1vhWEp6CTVaGYwo+mclhl+QnwuPqAGWpsi8pl2pSHPjZc7zaahL
         aSh10stPuvgyLk+bNk+/oQHo8bT5bkQmFD9ty7X8xpURJme3Q5waZvdDBbqOEP9TFyTD
         t1/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Iec236Gb7HY1kBux8RI0Z6JDo/NJmQ9dnBdHAT4Ho09F84vTQ
	r97dAV2bXdSg3tLGbYkLUFM=
X-Google-Smtp-Source: ABdhPJzbi/gDdgWQYZh7QHTJ78g9RqhotDOxrAJOn2kGDwizKKyrHIQWAd1Q1jGcvJNjHDmYqspxmA==
X-Received: by 2002:a17:902:9d8b:b029:df:fab3:48ef with SMTP id c11-20020a1709029d8bb02900dffab348efmr1628202plq.79.1611876502530;
        Thu, 28 Jan 2021 15:28:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:545e:: with SMTP id e30ls2749460pgm.4.gmail; Thu, 28 Jan
 2021 15:28:22 -0800 (PST)
X-Received: by 2002:a63:a542:: with SMTP id r2mr1739415pgu.211.1611876501924;
        Thu, 28 Jan 2021 15:28:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611876501; cv=none;
        d=google.com; s=arc-20160816;
        b=EgDNemPk2ZAYqztqDoWHpp+HyjGJ643MfHYO3AxPGqbrXYU3bIxWCLiLkw0MKr7LUD
         ix/ynUksw7cJE/7YLtl/TE0ZOm296EGN9r4UuWJgCc7ZuSuU6bsntjdfM1NXwqBa0Q90
         nEKvNNbScfyV6mC0es3L3pRwlsG7qGkBMhpZGZPWM5QVExDf4/MrlS1EXpf081dk/IIe
         sjZNZNAHkBay3hfurMpEFyYzqpjfcgimGvO5UrZvdbWUUsqZ5KSeGzz06S1/sqv6Wqvx
         K5J2tB5NnNwuEeEfR6DLrmgvm7y2Eu1Un/O6Wj6q1WobXzM8iU5z8qEz8/y7K3bLP5wK
         Z2wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=dBnk820A3sgTmAaZ2TtOBY2DTFqQXQgrYdsjd0iQksA=;
        b=HfgFdFrQUaijDhYJZaZucPRB5A4pzoMUAINdTmO44xCl95XuNLODf4xiwZc0L51xhB
         in7VQ6jkJuIHHrShHE8GHVWbD5sG1R6XMnHBIe6zaQTg7Pmp24U6WcANWIw99RfhCeYY
         IQDNIUE5F7X98LW+0k+fghP0v/QXoA4R4iUrPEi5g7NAUOFX5FcAk3rd1vsVPJaMHoM6
         U/W7FF+g3G3DiXVzowistJq0QoNZp9a35V9zbmM0S+YuLh+9DTN+34MfrynH/O3/BcXf
         AlX1f7DQyhiNskIJqpxsa7dHk8eANLAqjK+S0K42yVmUnPk40rgjoM2oAwNj9CajfXXQ
         bhtw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XQ7Haa5E;
       spf=pass (google.com: domain of srs0=ta0l=g7=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=TA0l=G7=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id ep11si373028pjb.0.2021.01.28.15.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Jan 2021 15:28:21 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=ta0l=g7=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 8FA8864DEF;
	Thu, 28 Jan 2021 23:28:21 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 487AF35237A0; Thu, 28 Jan 2021 15:28:21 -0800 (PST)
Date: Thu, 28 Jan 2021 15:28:21 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KCSAN how to use
Message-ID: <20210128232821.GW2743@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
 <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
 <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
 <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
 <CACV+naoGypEtGan65+PQR0Z8pWgF=uejYTT_+bAO-Lo3O4v+CA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACV+naoGypEtGan65+PQR0Z8pWgF=uejYTT_+bAO-Lo3O4v+CA@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XQ7Haa5E;       spf=pass
 (google.com: domain of srs0=ta0l=g7=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=TA0l=G7=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

On Thu, Jan 28, 2021 at 05:43:00PM -0500, Jin Huang wrote:
> Hi, Dmitry
> Thank you for your help.
> 
> I also want to ask an interesting question about the call stack
> information, how did you get the inline function call information in the
> call stack like this:
> 
> vfs_unlink+0x269/0x3b0 fs/namei.c:3837
> 
>  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
> 
>  __do_sys_unlink fs/namei.c:3945 [inline]
> 
>  __se_sys_unlink fs/namei.c:3943 [inline]
> 
>  __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
> 
>  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
> 
>  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> 
> I use dump_stack(), but can only get this kind of info:
> 
> vfs_unlink+0x269/0x3b0
> 
> do_unlinkat+0x28a/0x4d0
> 
> __x64_sys_unlink+0x2c/0x30
> 
> do_syscall_64+0x39/0x80
> 
> entry_SYSCALL_64_after_hwframe+0x44/0xa9
> 
> Obviously, inline function info misses. When I look at the Linux Kernel
> source code, the implementation of dump_stack(), seems because the inline
> function is not within the range of kernel_text_address().
> Do you have any idea?

If you build your kernel with CONFIG_DEBUG_INFO=y, any number of tools
will be able to translate those addresses to filenames and line numbers.
For but one example, given the vmlinux, you could give the following
command to "gdb vmlinux":

	l *vfs_unlink+0x269

							Thanx, Paul

> Thank You
> Best
> Jin Huang
> 
> 
> On Wed, Jan 27, 2021 at 4:27 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> 
> > On Wed, Jan 27, 2021 at 5:57 AM Jin Huang <andy.jinhuang@gmail.com> wrote:
> > >
> > > Hi, Macro
> > > Could you provide some instructions about how to use syz-symbolize to
> > locate the kernel source code?
> > > I did not find any document about it.
> >
> > Hi Jin,
> >
> > If you build kernel in-tree, then you can just run:
> > $ syz-symbolize file-with-kernel-crash
> > from the kernel dir.
> >
> > Otherwise add -kernel_src flag and/or -kernel_obj flag:
> >
> > https://github.com/google/syzkaller/blob/master/tools/syz-symbolize/symbolize.go#L24
> >
> >
> >
> > > Thank You
> > > Best
> > > Jin Huang
> > >
> > >
> > > On Mon, Jan 11, 2021 at 2:09 AM Marco Elver <elver@google.com> wrote:
> > >>
> > >> On Mon, 11 Jan 2021 at 07:54, Jin Huang <andy.jinhuang@gmail.com>
> > wrote:
> > >>>
> > >>> Really thank you for your help, Dmitry.
> > >>> I tried and saw the KCSAN info.
> > >>>
> > >>> But now it seems weird, the KCSAN reports differently every time I run
> > the kernel, and the /sys/kernel/debug/kcsan seems does not match with the
> > KCSAN report. What is wrong?
> > >>
> > >>
> > >> /sys/kernel/debug/kcsan shows the total data races found, but that may
> > differ from those reported to console, because there is an extra filtering
> > step (e.g. KCSAN won't report the same data race more than once 3 sec).
> > >>
> > >>>
> > >>> And I also want to ask, besides gdb, how to use other ways to locate
> > the kernel source code, like decode_stacktrace.sh and syz-symbolize, talked
> > about here https://lwn.net/Articles/816850/. Is gdb the best way?
> > >>
> > >>
> > >> I use syz-symbolize 99% of the time.
> > >>
> > >>>
> > >>> Also, does KCSAN recognizes all the synchronizations in the Linux
> > Kernel? Is there false positives or false negatives?
> > >>
> > >>
> > >> Data races in the Linux kernel is an ongoing story, however, there are
> > no false positives (but KCSAN can miss data races).
> > >>
> > >> Regarding the data races you're observing: there are numerous known
> > data races in the kernel that are expected when you currently run KCSAN. To
> > understand the severity of different reports, let's define the following 3
> > concurrency bug classes:
> > >>
> > >> A. Data race, where failure due to current compilers is unlikely
> > (supposedly "benign"); merely marking the accesses appropriately is
> > sufficient. Finding a crash for these will require a miscompilation, but
> > otherwise look "benign" at the C-language level.
> > >>
> > >> B. Race-condition bugs where the bug manifests as a data race, too --
> > simply marking things doesn't fix the problem. These are the types of bugs
> > where a data race would point out a more severe issue.
> > >>
> > >> C. Race-condition bugs where the bug never manifests as a data race. An
> > example of these might be 2 threads that acquire the necessary locks, yet
> > some interleaving of them still results in a bug (e.g. because the logic
> > inside the critical sections is buggy). These are harder to detect with
> > KCSAN as-is, and require using ASSERT_EXCLUSIVE_ACCESS() or
> > ASSERT_EXCLUSIVE_WRITER() in the right place. See
> > https://lwn.net/Articles/816854/.
> > >>
> > >> One problem currently is that the kernel has quite a lot type-(A)
> > reports if we run KCSAN, which makes it harder to identify bugs of type (B)
> > and (C). My wish for the future is that we can get to a place, where the
> > kernel has almost no unintentional (A) issues, so that we primarily find
> > (B) and (C) bugs.
> > >>
> > >> Hope this helps.
> > >>
> > >> Thanks,
> > >> -- Marco
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210128232821.GW2743%40paulmck-ThinkPad-P72.
