Return-Path: <kasan-dev+bncBCJZRXGY5YJBBQNRZWAAMGQEPCKRJIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 2ABB2308279
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Jan 2021 01:37:23 +0100 (CET)
Received: by mail-ot1-x340.google.com with SMTP id g15sf3100370oti.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Jan 2021 16:37:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611880642; cv=pass;
        d=google.com; s=arc-20160816;
        b=sMwI8Z4J6WgZ0gLjsPr/O1ph/qxSx1YMrjxToGvATRFozf74tbByJ8KGROKJlVB6Ef
         lGs1KgQT6inOEy2cawIUCjbSmpz7d3E5uRRnSbzjcJY7dMCVhCS79N8mB+RxoWWU4pTt
         XWkGdl6p88WBZBIh89XtMFpVUGYENc0uZbiIGohS2imAea1OHR5UNUr/pSmS17HsZqU4
         NSOaRUK/DIw1c0W3lggUomz5v0mwGfAmuRfyJR9ocExc9m7v555NW+3/OyCXxLbMQb9w
         HynvAprXG2ggSkaDSVg8OK6ak4WGxBBMof0WrnXPA46RFgBY/JinKRChQngW6WmajCVq
         otAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature;
        bh=w1NLyHFYyiCyGjsGwdHRi8zz0fwJBMz8hymNQHwkDCA=;
        b=hPRFQOSstZBhG1i1PpYX80QhMTBFHp6JmxzjrizMuGGk2JHej0ARqdH/OWFtVXQegC
         oEs/BnlvXPmLrN2idjP4Emni5oad+1RRthucPpspLeRrzP5zhQKqffs2OMKAATGuIOvB
         ByIcCREgsS3HA6yhvN8XJOXzeO9p4RcpkO7zpTJnBgpxahrPdgrNf6ZFYZp65C3sDWuW
         yfKVGiQUmXR2One4E0VwPIVMTyCFnjD6/ObQ2EhrBn7AyBY7O7R8oRzXGX3zekMwnDct
         uzAUd5Wjh+QNXgV5mw1TRlSrLmkhSrUhZBW95FG3dh+VBmY3GnZb4OoDtaxclRqw2oKj
         kS2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o043oXph;
       spf=pass (google.com: domain of srs0=4/ob=ha=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4/Ob=HA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w1NLyHFYyiCyGjsGwdHRi8zz0fwJBMz8hymNQHwkDCA=;
        b=shrMS4FRzzpBtBHnK9GQqEJicUZcQZTtH7RDhfLLOHfV+1j1p4/WxGA0Id+bvJjFGd
         e3DZjHbFN+01u/B/3Gf0jMpQx7W6cDKSvLtOpaUNKLeeI/Q/gyfSBRLfDPb422yYjq24
         Pnv5L2ycxPheC8STXfJ5DVcGWQduPLT66hTj8AJLds+fMBmh7YG6CFhWP9baQmj0zWGb
         FclsHjq6rK7anIDv6MEQKMkqCgzdXguzOucmg9d5DA2DhGtJC1CgWmDV6DonWhcJNfc3
         lbJ8TYM9EZckmYq/beo/rfEOWNs8WltxBt4NfM9N1Fcai8MGWKUAXsk2PxkF6cD2Q9xO
         J0lQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition:in-reply-to
         :user-agent:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=w1NLyHFYyiCyGjsGwdHRi8zz0fwJBMz8hymNQHwkDCA=;
        b=ftZQaslLX2ohzpYT3GPr+L3uz/TRmVK8ewU14/vS1onVz7RCm3Ghz0BIa3Q1caMinp
         FXtt6Ja69XD/JU2N6R3DRwStFnJOsk3vC9ivV9X77VdcNFxlW3dP4PwM6Wh8PSDNS9ZS
         KE/qa+voo9ExlgWEVCEK67EuLwwiGu71XsF7aey9/LlsBERErXGMbDIdsP/CQogPfKc7
         lsNBgssaN76JKixT9jwAj1aeUyu76d2Nijs04MzHoDYa0Zmh6XYj4AeUXZVfAHD7WGyC
         jUt1dYhOYBPSu+Qi1XKdUFe7FHS32CemM26EYnzWm6ZAPDnTdv7ee3BuW/y5AFoHMd/b
         E7EQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Tgnz8wBSIEt9tvgM07HKlZxpN1PzGy8yTzRU8LMgXwxEwoV56
	Y6F/kXQvoxpnTBmVCK4ke1c=
X-Google-Smtp-Source: ABdhPJwtp56/phQgv3f38tA9bQBID+JtFXI+wp694czd7RCPR7FQgKaNXtelr7BDZ24gpcXvwbXNOA==
X-Received: by 2002:a9d:6393:: with SMTP id w19mr1366608otk.204.1611880642023;
        Thu, 28 Jan 2021 16:37:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:cd8e:: with SMTP id d136ls1559057oig.6.gmail; Thu, 28
 Jan 2021 16:37:21 -0800 (PST)
X-Received: by 2002:aca:40d:: with SMTP id 13mr1239988oie.72.1611880641387;
        Thu, 28 Jan 2021 16:37:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611880641; cv=none;
        d=google.com; s=arc-20160816;
        b=xrRbup8UOMY6VWxHr1AHMsV8lGYwtnQ0p4gybYVa8zE4cGCm28g01j6ykASARG2L0h
         EjjHpvEyQiE5R13mXYq7It64NL6TSWpLB1rR9NwNvpnWV8d6kyVmtZGFdigW5t2O9a5p
         Nw0+ARxBCl6ShLjOuqlkt1y5N26nTcV3JhHj3Puqm+3G+L0GY2wE0B+nK6vWQ3Cl+CG2
         +G9fGKKczrK1zirjZJI2adu2Gh9yvWBwATHXdVA/PY4AcO3O20nDi+tSwHAvDPj9Q+N3
         ByzSpNFLMXxf0eG9pqsh2Gbq4omsypLCpfmBjix8PDX7jh4543RQ83WzKQ6osUcbkGSD
         PKNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=fFZ/yDbgz+cPUHcEMS6lT0YzMgss38Zcwiv0OfGwIw0=;
        b=iiuoLGfUDiUTEc9WmAd5WiNNh7E/BTczDOKanbhEYi8/qZv/xlIYKXg5jRionaV/cX
         voBYHINq4jY2+KnKvWw4X9w1V0tZrRdU5mlXfc31LqCZqrT4bE+JlefkO/RCcaTUAntv
         C2L3fmmMswooO0Ig8d1zpJ12b1Hka0DdnVn7kSd7f7uyoiPei51eJ68cUmoTwQxDDg1m
         DCnAnGS6WdBfO+rAy4OJzc3we9ad6EPdAPqVeOnyyEe1EieW4yDqVOyS9GX4vd7wjC6M
         aGpjdFIsXZnVlndMKXOvLqmjWRqblq7V/684gLXtW86Mg9SAaRYHlEkbSanRawE+u91p
         haoQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=o043oXph;
       spf=pass (google.com: domain of srs0=4/ob=ha=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4/Ob=HA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m7si452948otq.5.2021.01.28.16.37.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 28 Jan 2021 16:37:21 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=4/ob=ha=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5E98664DE5;
	Fri, 29 Jan 2021 00:37:20 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id EE20A35237A0; Thu, 28 Jan 2021 16:37:19 -0800 (PST)
Date: Thu, 28 Jan 2021 16:37:19 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Jin Huang <andy.jinhuang@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>
Subject: Re: KCSAN how to use
Message-ID: <20210129003719.GY2743@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <CACV+narOjL5_o_in_WtOo9kjhcKFD4S4ozctPtdj6JR0+b8adg@mail.gmail.com>
 <CACT4Y+aAarvX0aoesAZjfTnHijwcg68G7o-mtV2CED5PgwygZQ@mail.gmail.com>
 <CACV+napfUFrnr6WxcidQG+di5YTC8KKd=pcWxAp28FJmivTgpQ@mail.gmail.com>
 <CANpmjNM_zO_u=r732JLzE5=+Timjgky+7P8So_k9_cukO876CQ@mail.gmail.com>
 <CACV+narfJs5WSpdbG8=Ui0mCda4+ibToEMPxu4GHhGu0RbhD_w@mail.gmail.com>
 <CACT4Y+aMjm9tER-tsHeUY6xjOq7pDWJxVa1_AJ-XVO8nVoAEjQ@mail.gmail.com>
 <CACV+naoGypEtGan65+PQR0Z8pWgF=uejYTT_+bAO-Lo3O4v+CA@mail.gmail.com>
 <20210128232821.GW2743@paulmck-ThinkPad-P72>
 <CACV+napTjGjYJXojTXa=Npz81sCZBtiaTci7K3Qq5gd7Myi-ow@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACV+napTjGjYJXojTXa=Npz81sCZBtiaTci7K3Qq5gd7Myi-ow@mail.gmail.com>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=o043oXph;       spf=pass
 (google.com: domain of srs0=4/ob=ha=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=4/Ob=HA=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
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

I have seen output from tools that have filled in the inline functions,
but I have no idea where to get them or how to use them.

Not much help, but at least rumor of a solution exists.  ;-)

							Thanx, Paul

On Thu, Jan 28, 2021 at 07:06:49PM -0500, Jin Huang wrote:
> Thank you for your reply, Paul.
> 
> Sorry I did not state my question clearly, my question is now I want to get
> the call stack myself, not from syzkaller report. For example I write the
> code in linux kernel some point, dump_stack(), then I can get the call
> stack when execution, and later I can translate the symbol to get the
> file:line.
> 
> But the point is dump_stack() function in Linux Kernel does not contain the
> inline function calls as shown below, if I want to implement display call
> stack myself, do you have any idea? I think I can modify dump_stack(), but
> seems I cannot figure out where the address of inline function is,
> according to the source code of dump_stack() in Linux Kernel, it only
> displays the address of the function call within 'kernel_text_address', or
> maybe the inline function calls have  not even been recorded. Or maybe I am
> not on the right track.
> I also try to compile with -fno-inline, but the kernel cannot be compiled
> successfully in this way.
> 
> Syzkaller report:
> 
> dont_mount include/linux/dcache.h:355 [*inline*]
> 
>  vfs_unlink+0x269/0x3b0 fs/namei.c:3837
> 
>  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
> 
>  __do_sys_unlink fs/namei.c:3945 [*inline*]
> 
>  __se_sys_unlink fs/namei.c:3943 [*inline*]
> 
>  __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
> 
>  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
> 
>  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> 
> dump_stack result, the* inline function* calls are missing.
> 
> vfs_unlink+0x269/0x3b0 fs/namei.c:3837
> 
>  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
> 
>   __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
> 
>  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
> 
>  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> 
> 
> Thank You
> Best
> Jin Huang
> 
> 
> On Thu, Jan 28, 2021 at 6:28 PM Paul E. McKenney <paulmck@kernel.org> wrote:
> 
> > On Thu, Jan 28, 2021 at 05:43:00PM -0500, Jin Huang wrote:
> > > Hi, Dmitry
> > > Thank you for your help.
> > >
> > > I also want to ask an interesting question about the call stack
> > > information, how did you get the inline function call information in the
> > > call stack like this:
> > >
> > > vfs_unlink+0x269/0x3b0 fs/namei.c:3837
> > >
> > >  do_unlinkat+0x28a/0x4d0 fs/namei.c:3899
> > >
> > >  __do_sys_unlink fs/namei.c:3945 [inline]
> > >
> > >  __se_sys_unlink fs/namei.c:3943 [inline]
> > >
> > >  __x64_sys_unlink+0x2c/0x30 fs/namei.c:3943
> > >
> > >  do_syscall_64+0x39/0x80 arch/x86/entry/common.c:46
> > >
> > >  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> > >
> > > I use dump_stack(), but can only get this kind of info:
> > >
> > > vfs_unlink+0x269/0x3b0
> > >
> > > do_unlinkat+0x28a/0x4d0
> > >
> > > __x64_sys_unlink+0x2c/0x30
> > >
> > > do_syscall_64+0x39/0x80
> > >
> > > entry_SYSCALL_64_after_hwframe+0x44/0xa9
> > >
> > > Obviously, inline function info misses. When I look at the Linux Kernel
> > > source code, the implementation of dump_stack(), seems because the inline
> > > function is not within the range of kernel_text_address().
> > > Do you have any idea?
> >
> > If you build your kernel with CONFIG_DEBUG_INFO=y, any number of tools
> > will be able to translate those addresses to filenames and line numbers.
> > For but one example, given the vmlinux, you could give the following
> > command to "gdb vmlinux":
> >
> >         l *vfs_unlink+0x269
> >
> >                                                         Thanx, Paul
> >
> > > Thank You
> > > Best
> > > Jin Huang
> > >
> > >
> > > On Wed, Jan 27, 2021 at 4:27 AM Dmitry Vyukov <dvyukov@google.com>
> > wrote:
> > >
> > > > On Wed, Jan 27, 2021 at 5:57 AM Jin Huang <andy.jinhuang@gmail.com>
> > wrote:
> > > > >
> > > > > Hi, Macro
> > > > > Could you provide some instructions about how to use syz-symbolize to
> > > > locate the kernel source code?
> > > > > I did not find any document about it.
> > > >
> > > > Hi Jin,
> > > >
> > > > If you build kernel in-tree, then you can just run:
> > > > $ syz-symbolize file-with-kernel-crash
> > > > from the kernel dir.
> > > >
> > > > Otherwise add -kernel_src flag and/or -kernel_obj flag:
> > > >
> > > >
> > https://github.com/google/syzkaller/blob/master/tools/syz-symbolize/symbolize.go#L24
> > > >
> > > >
> > > >
> > > > > Thank You
> > > > > Best
> > > > > Jin Huang
> > > > >
> > > > >
> > > > > On Mon, Jan 11, 2021 at 2:09 AM Marco Elver <elver@google.com>
> > wrote:
> > > > >>
> > > > >> On Mon, 11 Jan 2021 at 07:54, Jin Huang <andy.jinhuang@gmail.com>
> > > > wrote:
> > > > >>>
> > > > >>> Really thank you for your help, Dmitry.
> > > > >>> I tried and saw the KCSAN info.
> > > > >>>
> > > > >>> But now it seems weird, the KCSAN reports differently every time I
> > run
> > > > the kernel, and the /sys/kernel/debug/kcsan seems does not match with
> > the
> > > > KCSAN report. What is wrong?
> > > > >>
> > > > >>
> > > > >> /sys/kernel/debug/kcsan shows the total data races found, but that
> > may
> > > > differ from those reported to console, because there is an extra
> > filtering
> > > > step (e.g. KCSAN won't report the same data race more than once 3 sec).
> > > > >>
> > > > >>>
> > > > >>> And I also want to ask, besides gdb, how to use other ways to
> > locate
> > > > the kernel source code, like decode_stacktrace.sh and syz-symbolize,
> > talked
> > > > about here https://lwn.net/Articles/816850/. Is gdb the best way?
> > > > >>
> > > > >>
> > > > >> I use syz-symbolize 99% of the time.
> > > > >>
> > > > >>>
> > > > >>> Also, does KCSAN recognizes all the synchronizations in the Linux
> > > > Kernel? Is there false positives or false negatives?
> > > > >>
> > > > >>
> > > > >> Data races in the Linux kernel is an ongoing story, however, there
> > are
> > > > no false positives (but KCSAN can miss data races).
> > > > >>
> > > > >> Regarding the data races you're observing: there are numerous known
> > > > data races in the kernel that are expected when you currently run
> > KCSAN. To
> > > > understand the severity of different reports, let's define the
> > following 3
> > > > concurrency bug classes:
> > > > >>
> > > > >> A. Data race, where failure due to current compilers is unlikely
> > > > (supposedly "benign"); merely marking the accesses appropriately is
> > > > sufficient. Finding a crash for these will require a miscompilation,
> > but
> > > > otherwise look "benign" at the C-language level.
> > > > >>
> > > > >> B. Race-condition bugs where the bug manifests as a data race, too
> > --
> > > > simply marking things doesn't fix the problem. These are the types of
> > bugs
> > > > where a data race would point out a more severe issue.
> > > > >>
> > > > >> C. Race-condition bugs where the bug never manifests as a data
> > race. An
> > > > example of these might be 2 threads that acquire the necessary locks,
> > yet
> > > > some interleaving of them still results in a bug (e.g. because the
> > logic
> > > > inside the critical sections is buggy). These are harder to detect with
> > > > KCSAN as-is, and require using ASSERT_EXCLUSIVE_ACCESS() or
> > > > ASSERT_EXCLUSIVE_WRITER() in the right place. See
> > > > https://lwn.net/Articles/816854/.
> > > > >>
> > > > >> One problem currently is that the kernel has quite a lot type-(A)
> > > > reports if we run KCSAN, which makes it harder to identify bugs of
> > type (B)
> > > > and (C). My wish for the future is that we can get to a place, where
> > the
> > > > kernel has almost no unintentional (A) issues, so that we primarily
> > find
> > > > (B) and (C) bugs.
> > > > >>
> > > > >> Hope this helps.
> > > > >>
> > > > >> Thanks,
> > > > >> -- Marco
> > > >
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210129003719.GY2743%40paulmck-ThinkPad-P72.
