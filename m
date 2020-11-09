Return-Path: <kasan-dev+bncBC7OBJGL2MHBBEPOUT6QKGQE2US6WMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 12D4A2AB84C
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Nov 2020 13:33:23 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id x28sf484096oog.8
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Nov 2020 04:33:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604925201; cv=pass;
        d=google.com; s=arc-20160816;
        b=TYxn79mcvteHcYoQDitzPxc93KkVe3HHnbVuh6c2HCEcrO91pDxSKLyVDUcBmRB9BX
         bU7iJLyBSW044LEX9iWDAVFnzeIEedT1xkNkgsqx4FOAAsj4IR4kCyuTQNWiupMnujtm
         DQI32nKqcE4GodA5YrXhld1aam1o8h6jTTPmrRiKLW9VG9WcYcWrbK99Z+M44nF841Ey
         e5q3+jVKbz28tTb/Gi/5wRURaBOJU2xeHiM6H5qOiyA2SiJVlsDf7aHRAocBt2SPrjwT
         7s7Y8bH1lI7n4VlFdnVRPOEzGKt6g641qXCvAT71Ljp5Wc7SUC59Lg1jt4JLr6aDVS7x
         mgIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=/A/KGObitSWwMVMp3+Q47KAKqAsYHOqVvZT8n0vCcBk=;
        b=eVPeF0sSNAQ6NRSJpHUu0p51l79bnMpH3rzn8XB1ZBf8QvAOTTDpe4+m9ucijSSSDC
         mUUXQ7ESxNEjju0HAVBG0Y05b4uCy7yH2xjXtDBmdDgA9700GOyBcyJHuQAyRRLzh3Xm
         JuOt9oFqaQrhGse6tTM0eZ6H5yFLCizjyv2i5eozDJgD9+60UXK09n5VTqYT4YIKFAFe
         7sMhea6NDMhdGwPucp94/Krp3KCdVHBFAyEw8cz6HXiHy490Cd/C4rMClgnTfkyj5mgG
         kvi9wxywOHRZeGQDVtmbr7+rf8iWFeH/y9wQzjD+WCJkmcnxhGsiaskOjYGUD0O7CZ2x
         qXKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mKJ2p/2T";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/A/KGObitSWwMVMp3+Q47KAKqAsYHOqVvZT8n0vCcBk=;
        b=T8E/yhGe2pTq+Pn8TQlcYs9qWGVlpmY4mIIcr4QUbrMmo6kyYyxMe5uBYdPfkfg5XC
         h12HgHhap4J7UVNVXoALdkm4+eJvHzASbaZkJcjR297Brfxt3dLv8As2v7nxb4cjrwwS
         UomX3nVWWoYjwgLSyl5QN2nchJIrKZuXcOut61RAZj7/PJ6rfUq2m5+AshV+dTgIvZHP
         sspnNL7lXiBlLfbebMYIiGO0I9JtPSMu3tZIrXbTymCJMDBhOhnB8+h9Y+gNU99HkrSy
         jAop0Rs9KhPlfqp14BOyJRwtpqNYY96msjh5bJK2PinRyc9smKvOuwvW4KFvYXXOxbE6
         C9Xg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/A/KGObitSWwMVMp3+Q47KAKqAsYHOqVvZT8n0vCcBk=;
        b=oHW8GcrzY7mpaHCM3rrbEVrW+czY9JMUtY/e800j2MiZUhkqq82xMFRXVnL9+bh8Kt
         Cm2LmjS4BHRE7BO9ZSjbK7wL8OlKgVzHpls1d20iOFPApcX+deCiLrs7wgJ4KNiqFB3W
         dHtyKEGjKKso+yOFUc3tevEewCM4ropSBAiuCr52qG1bzcqkLl2IZlFJlBGWaC2LC5Ee
         N2AHhaqiPDqRfmrZylvAoDvZ0tmJs1Nd8tIcwgp/dVTjzBsHkcF/iLgPjNgpgDX95bFM
         EojG6KpArDbW6ACzzxWpcv6Q2rS0cjkRRnrkniCLMIwC85DrQCVHD2PCLTXHBQrWMZCx
         OtQw==
X-Gm-Message-State: AOAM533DYbxxCasORueEWlaIhx8p+3MxLGUMXIfQUxuUyGdMC/az0IK+
	AP79N7d7SFJYxil/g6X0Fs8=
X-Google-Smtp-Source: ABdhPJz0DC3F66PcQU+Xi447tmmKbbXmnynJhMUOQNAt1gnvUqSR080iOSolA6xHuVapC5q5k84NwQ==
X-Received: by 2002:a05:6830:1015:: with SMTP id a21mr10724158otp.143.1604925201805;
        Mon, 09 Nov 2020 04:33:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6b0f:: with SMTP id g15ls2067560otp.0.gmail; Mon, 09 Nov
 2020 04:33:21 -0800 (PST)
X-Received: by 2002:a9d:12ca:: with SMTP id g68mr10419351otg.322.1604925201431;
        Mon, 09 Nov 2020 04:33:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604925201; cv=none;
        d=google.com; s=arc-20160816;
        b=Z8bHeRljgnP/IHP9/LjCSYkNodEC5/G5XAwVzSoiQNEZLH3/+SBW45uGOX0H6OI0aE
         GRiaUUfqHHvB2uCWNuF8Z6inST1QwL3v54ZlbSsF+Xzzm860gbEWSlEdw9u4kj7dN2IY
         TqygHV3niJTb1p4gODFAnhrVUVJGJCKWMDYAwqfnpXEdP2wnGUq/5cSqgaAlUZKTKr1X
         6v9zo7+Mqiw+u7pa1QlXuHj83vuuuQX6l23EOk6spXW6kIkHQevzAC/hsXpQOraDtol0
         3SUfN+Q3DR5+4FF2deHybY/wqmKCQhGRK6PkcMxY3OSJe9jka3/AUz7cu6G/VxwTEtfm
         95ag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9NUPc+lgCHVUf8pBfcr8nzqHrlS7dd93RRj1NccXDio=;
        b=uK0tCZF0CVuj8OGE5KaOZAuzVsDRdrsMThdeed7y8DUWwab/GcLcV2/mFUEC/ZHryv
         GQ5YPDwXTO1PcCAROe3bf6GCzfYtvN3hzi5WfG+azZd9VtI48oMweTUSAmzVuGYwpfcb
         NYDGb3XX/zOuoLfkQ4GoCJB7Rh9PhnaUCfVvssB236w20GcO2NY/vNYJ8AyPoLudOk8U
         uuSrNef+5rTdd/IjH9mzB0PxtApL2ILa7RDfj8G6PmYbsnsel9r0kL/K25Sas/bkyw6s
         U9mcwidbFJrqruTkgKpKrnB4QqX7hHNyHlk/7dLntONbM9QvXlEDrG9hbJzfcnAdu94p
         R39Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="mKJ2p/2T";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id r6si1134423oth.4.2020.11.09.04.33.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Nov 2020 04:33:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id u127so10022547oib.6
        for <kasan-dev@googlegroups.com>; Mon, 09 Nov 2020 04:33:21 -0800 (PST)
X-Received: by 2002:a05:6808:5ca:: with SMTP id d10mr4813067oij.70.1604925200954;
 Mon, 09 Nov 2020 04:33:20 -0800 (PST)
MIME-Version: 1.0
References: <20201106041046.GT3249@paulmck-ThinkPad-P72> <CANpmjNPaKNstOiXDu7OGfT4-CwvYLACJtbef8L0f18qn1P4e8g@mail.gmail.com>
 <20201106144539.GV3249@paulmck-ThinkPad-P72> <20201106174756.GA11571@paulmck-ThinkPad-P72>
 <CANpmjNPduS1bfieEEh5W+Apmq0+OQjOOTv_cj5E9jb1mwJfDqw@mail.gmail.com>
In-Reply-To: <CANpmjNPduS1bfieEEh5W+Apmq0+OQjOOTv_cj5E9jb1mwJfDqw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Nov 2020 13:33:09 +0100
Message-ID: <CANpmjNMS+mKEdCUH7NW01siUA8StdBzn00n-MmAPJzrStxzDZA@mail.gmail.com>
Subject: Re: KCSAN build warnings
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="mKJ2p/2T";       spf=pass
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

On Fri, 6 Nov 2020 at 19:02, Marco Elver <elver@google.com> wrote:
> On Fri, 6 Nov 2020 at 18:47, Paul E. McKenney <paulmck@kernel.org> wrote:
> > On Fri, Nov 06, 2020 at 06:45:39AM -0800, Paul E. McKenney wrote:
> > > On Fri, Nov 06, 2020 at 09:23:43AM +0100, Marco Elver wrote:
> > > > On Fri, 6 Nov 2020 at 05:10, Paul E. McKenney <paulmck@kernel.org> wrote:
> > > > > Hello!
> > > > >
> > > > > Some interesting code is being added to RCU, so I fired up KCSAN.
> > > > > Although KCSAN still seems to work, but I got the following build
> > > > > warnings.  Should I ignore these, or is this a sign that I need to
> > > > > upgrade from clang 11.0.0?
> > > > >
> > > > >                                                         Thanx, Paul
> > > > >
> > > > > ------------------------------------------------------------------------
> > > > >
> > > > > arch/x86/ia32/ia32_signal.o: warning: objtool: ia32_setup_rt_frame()+0x140: call to memset() with UACCESS enabled
> > > > > drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_prefault_relocations()+0x104: stack state mismatch: cfa1=7+56 cfa2=-1+0
> > > > > drivers/gpu/drm/i915/gem/i915_gem_execbuffer.o: warning: objtool: eb_copy_relocations()+0x309: stack state mismatch: cfa1=7+120 cfa2=-1+0
> > > >
> > > > Interesting, I've not seen these before and they don't look directly
> > > > KCSAN related. Although it appears that due to the instrumentation the
> > > > compiler decided to uninline a memset(), and the other 2 are new to
> > > > me.
> > > >
> > > > It might be wise to upgrade to a newer clang. If you haven't since
> > > > your first clang build, you might still be on a clang 11 pre-release.
> > > > Since then clang 11 was released (on 12 Oct), which would be my first
> > > > try: https://releases.llvm.org/download.html#11.0.0 -- they offer
> > > > prebuilt binaris just in case.
> > > >
> > > > Otherwise, what's the branch + config this is on? I can try to debug.
> > >
> > > You called it -- yes, I am still using the old clang.  I will try
> > > out the new one, thank you!
> >
> > Huh.  I have an x86_64 system running CentOS 7, and I see PowerPC
> > binaries on that page for that OS level, but not x86_64 binaries.
> > Am I blind this morning?
>
> You're right it's not there.
>
> > If I am not blind, what is my best way forward?
>
> Hmm, chances are one of the other ones will work. I just tried the one
> for "SuSE Linux Enterprise Server 12SP4" on a Debian box and it worked
> fine. All you need is for the 'bin/clang' binary to work, although
> there's a chance something else might not work due to missing
> libraries, it doesn't matter as long as we can build the kernel. :-)

Did you manage to resolve this? And did the warnings disappear?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMS%2BmKEdCUH7NW01siUA8StdBzn00n-MmAPJzrStxzDZA%40mail.gmail.com.
