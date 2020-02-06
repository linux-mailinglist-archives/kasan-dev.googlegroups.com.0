Return-Path: <kasan-dev+bncBDK3TPOVRULBB4FX6HYQKGQEM7TQQ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4DED8154B31
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2020 19:33:21 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id be8sf4984405edb.16
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2020 10:33:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581014001; cv=pass;
        d=google.com; s=arc-20160816;
        b=tzw7uxI9uVDbhykC1DuOy91LUZTI8Bpbd1YVfq2FTZaqoeChlncvBADs72twI3D9xJ
         qeevh71Eo7PkMVceiJ/4FI9gHhzgj1+dd5zVqAobC90byS9GujB7QQ0XVZ1MmFOseWJg
         pv7udWeXGg9BzUU2wxLvr2dqv8FsUzlc462OLiI8rTWa/XNXlOokS1rHawIERp3kJsQy
         aYTEPDdN5+bAxzreZXUZaTzs3l/gAYueeNLJfKiwDBXFF71YAOOocqsm1d9U4qbpDnd2
         z1OGjFOOqoA/94w1wsMOjn3TWYjQJqNUPwzwdGqhxy/0fXijN/vmsvJuiPVASP6mZaI8
         KGtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=napzq/vPGUaxwn+rPQtTSX/vlOyEs0NB82DIhnvdtKA=;
        b=jK8ymdX8veBLi88Q3FQmhRnkrhr4vqL79YjL6lgcBNkLMrYnhWdq7pbdn6rjf+I1r0
         5SqJrejD5njdsMIMqt1zViTiXYbiDHctq9yCKd3Ka5kixDD/7e7jmtkRs/EUDOjLZnSk
         +2rqVFs7wlZE+/rPSbPT0ZV6ETzqXK62iMWGDqBDcCFHen1L1PMdhh9s3wvL1k29xbHM
         KYWJ886Igm20Y1qmntnOKWyhGF0ZZweofmP00R+ZnkbclZ0KuLhU/Gp0aC77PoKq9VtW
         MKpwYBVZ7KdL6b4v5P+AMChMqztSl54/Kk7yt8RFsvQpiP5oblpp5Dch6m/ZT/STSkRB
         sedQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HR7uoCJJ;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=napzq/vPGUaxwn+rPQtTSX/vlOyEs0NB82DIhnvdtKA=;
        b=KPz8JiayOJ8nrYJjKURh01pwxKjZIfWj1fCYeojYYxYTiTXT0F8OOHdRZhJmqBVCMb
         EFdWjIW5b1iBYYVXzfcYFH2obSFBODs+0BHlWlSeFrT3G7mVHuFU7eIhDvTbVsUmbVTO
         9vD7d0o+grxqVXT6zkVSwnJjc0BxpH5VB1c7wj/dYuc0RhL/2iY9CaxcAH0ON6RMfXvw
         A2K8jUNYVLNJ04tvZsBLx4uSl0SWgvW/n+8U3uEXgPB6wUoQ8gLl3tDyaAzdOl7XW/us
         LB5pD+rJphj2M3mIFgtWfIF+bAB+EuI0+e/wwzg6pCqDvDpq1NDsP4zFnPUfw8FYtIoi
         kLqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=napzq/vPGUaxwn+rPQtTSX/vlOyEs0NB82DIhnvdtKA=;
        b=C05AUmVGB7j9hp/Pilw8J4LaJFOLn02sqhs+Z6vfQHj5WBI7CHcZFJlYokY7scvX+L
         jphacxThqMQ0I/cnU4z4nc+vrXc1rKYAM0C59hlrQXh3hEpgae8VjtuCZqIOO7Ew6NFc
         EBz+t3f7CNIpvqrxUgfV365Lj99q8gW71ayG4Pkk9gs/8ziBOmxwwTC/iSBKpcB/UpTc
         9ZLl4YElySN3brhY0fmErB1nUOw7uUdwwLuJtEXfjapOq3UshPfqyQg5KmfcO+sy8mlJ
         PZWdAYV84/J/2x9o/sqjSox6Kqj7x+P3DUj+WXJptTqoVc47rgDignUJmRXv8EetIMjy
         HqiQ==
X-Gm-Message-State: APjAAAW3zYT4XWr2FbSVBvhqjVAbsazbCFQp6lWN+RrGFO2JF5NQ8cDQ
	DY2koOjfBdzzCA7PMEVUoTs=
X-Google-Smtp-Source: APXvYqw2wsbMDVMM0h9wGK9PPLzNlO4Pjmokg6BLKKuPQ/hoo9t9gPELXO9qonIF5L8kq05uoI765A==
X-Received: by 2002:a17:906:4a12:: with SMTP id w18mr4592689eju.321.1581014001052;
        Thu, 06 Feb 2020 10:33:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:bfe7:: with SMTP id vr7ls3690688ejb.1.gmail; Thu, 06
 Feb 2020 10:33:20 -0800 (PST)
X-Received: by 2002:a17:906:3786:: with SMTP id n6mr4633293ejc.124.1581014000528;
        Thu, 06 Feb 2020 10:33:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581014000; cv=none;
        d=google.com; s=arc-20160816;
        b=kzYSkzXcSieffQLO5SVJ5b6SZ/nK6o3d4WaTNIv+wYmnd0JOrhUX4w09famTHoSVvL
         4JpoE8SDGnir3fyd0xM4tZkTA+hxk7jUy71UVLiyGlekPWZb6fPJE4mUSjdt2aESsqW2
         ymwe6iDOAfoUagW0NxqKjyBvkL3RsHrByu7dyzaz/370YqBbS/yq2WhbH/mMa1p7Q/iq
         3x5Splu/nTZCgQ7uYRrDMvey39iSv27BgR79Fs0Ffv2bp7v1SgWKQComHFJaGr+mRAeX
         EjcCwGVG19hNuMU9savpEbtSyiu+NlcPeWJ/MV9LfFgWkgE1p6h/N+ai0NCByB6EKJbi
         nRZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/o0TABmh3sA91z50JGeWR2QdDzZnMyxEswlhRW37yD8=;
        b=se3Br5RMqrDdMxB7Wsm8/i1kHCvIaWPVdD+FFnRkqz9Pf/P68g44RLhKfhrPqyqa2I
         IC5bZTBjK8BwfwIdJfd/5Ro+V9BvuzZLBwRgHxK32Dxd2MSuzOzxxfaHdF69ma/a9reR
         EpF+0eBZiMP+90vaLn5CqsyQFs3gNr+/uZ35g/JhzxrHWnhfxbzGEhOXih9XZFaJLhH8
         wZ5lXoYktYcyqNDdN55uJXh/t78R5oyLSYOnnTL0HM9AqACwrRSbwCobkgEq3s3aWQpx
         RFRbTZ080tKohKLwRtU3gZfd4Yxm8olb/QkIr0G6n1JUUD8J1LuIHCEiLkCVk/acx970
         LN1g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HR7uoCJJ;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id n1si24661edw.4.2020.02.06.10.33.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2020 10:33:20 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id z3so8446701wru.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2020 10:33:20 -0800 (PST)
X-Received: by 2002:a05:6000:108e:: with SMTP id y14mr5254368wrw.338.1581013999924;
 Thu, 06 Feb 2020 10:33:19 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
 <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
 <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
 <CACT4Y+brqD-o-u3Vt=C-PBiS2Wz+wXN3Q3RqBhf3XyRYaRoZJw@mail.gmail.com>
 <2092169e6dd1f8d15f1db4b3787cc9fe596097b7.camel@sipsolutions.net>
 <CACT4Y+b6C+y9sDfMYPDy-nh=WTt5+u2kLcWx2LQmHc1A5L7y0A@mail.gmail.com>
 <CACT4Y+atPME1RYvusmr2EQpv_mNkKJ2_LjMeANv0HxF=+Uu5hw@mail.gmail.com>
 <CACT4Y+bsaZoPC1Q7_rV-e_aO=LVPA-cE3btT_VARStWYk6dcPA@mail.gmail.com> <CACT4Y+Z6_CwVyJhr3SdDejFsrXcM11LVY+gh4oKP6k03Pn95AA@mail.gmail.com>
In-Reply-To: <CACT4Y+Z6_CwVyJhr3SdDejFsrXcM11LVY+gh4oKP6k03Pn95AA@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Feb 2020 10:33:08 -0800
Message-ID: <CAKFsvULhg7i=tuw1LMS9avy4-NgDDfK2k-_kCa3CH3sNRXa0Qw@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Johannes Berg <johannes@sipsolutions.net>, Richard Weinberger <richard@nod.at>, 
	Jeff Dike <jdike@addtoit.com>, Brendan Higgins <brendanhiggins@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, David Gow <davidgow@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, anton.ivanov@cambridgegreys.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HR7uoCJJ;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Fri, Jan 17, 2020 at 2:05 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Fri, Jan 17, 2020 at 11:03 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Fri, Jan 17, 2020 at 10:59 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Thu, Jan 16, 2020 at 10:39 PM Patricia Alfonso
> > > <trishalfonso@google.com> wrote:
> > > >
> > > > On Thu, Jan 16, 2020 at 1:23 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > >
> > > > > On Thu, Jan 16, 2020 at 10:20 AM Johannes Berg
> > > > > <johannes@sipsolutions.net> wrote:
> > > > > >
> > > > > > On Thu, 2020-01-16 at 10:18 +0100, Dmitry Vyukov wrote:
> > > > > > >
> > > > > > > This should resolve the problem with constructors (after they
> > > > > > > initialize KASAN, they can proceed to do anything they need) and it
> > > > > > > should get rid of most KASAN_SANITIZE (in particular, all of
> > > > > > > lib/Makefile and kernel/Makefile) and should fix stack instrumentation
> > > > > > > (in case it does not work now). The only tiny bit we should not
> > > > > > > instrument is the path from constructor up to mmap call.
> > > >

By initializing KASAN as the first thing that executes, I have been
able to get rid of most of the "KASAN_SANITIZE := n" lines and I am
very happy about that. Thanks for the suggestions!

> > > If that part of the code I mentioned is instrumented, manifestation
> > > would be different -- stack instrumentation will try to access shadow,
> > > shadow is not mapped yet, so it would crash on the shadow access.
> > >
> > > What you are seeing looks like, well, a kernel bug where it does a bad
> > > stack access. Maybe it's KASAN actually _working_? :)
> >
> > Though, stack instrumentation may have issues with longjmp-like things.
> > I would suggest first turning off stack instrumentation and getting
> > that work. Solving problems one-by-one is always easier.
> > If you need help debugging this, please post more info: patch, what
> > you are doing, full kernel output (preferably from start, if it's not
> > too lengthy).
>
> I see syscall_stub_data does some weird things with stack (stack
> copy?). Maybe we just need to ignore accesses there: individual
> accesses, or whole function/file.

It is still not clear whether the syscall_stub_data errors are false
positives, but while moving the kasan_init() to be as early as
possible in main(), I ran into a few more stack-related errors like
this(show_stack, dump_trace, and get_wchan). I will be taking your
advice to focus on one thing at a time and temporarily disable stack
instrumentation wherever possible.

--
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvULhg7i%3Dtuw1LMS9avy4-NgDDfK2k-_kCa3CH3sNRXa0Qw%40mail.gmail.com.
