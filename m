Return-Path: <kasan-dev+bncBCMIZB7QWENRBYHQ3KDAMGQETAU4PHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B3863B4CCD
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Jun 2021 07:17:22 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id o189-20020a378cc60000b02903b2ccd94ea1sf11732769qkd.19
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Jun 2021 22:17:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624684641; cv=pass;
        d=google.com; s=arc-20160816;
        b=VqoaXrPWdxPX4pNmzuH8xBbkADn/jL7kwOJ1Kl1reaWE6y1Iazu2MXa/IgN4tRXuMN
         exIE5V5z/g5OJTEVhivuuneLMrp5OwrtDa4q/KiKkIxPU6yH2J0qZ3JiUaoNPpZPJeBn
         XVsgm5fgd6/SpPm/5Y8bHUzxlf/0fK3P6ClsM6sQvSak1keitdynl03H4Qy1QXc24ezP
         Hwr07x6KltzGdbihiZZ0WIKoqlzZxxxQRmNXGqibFkBIJllkELHSrY1PxRfr/TiuYwlh
         NlIMR0I7NOLIMrDeldel66s9wQO6Pu1BJX238OwxHEJGcsRiaBszagDEese6cUvQO4eG
         x71g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=oU3lNIszRu2wpA/uN7w7ZKJ+pO2krYs2+TDc1YEPIhA=;
        b=mH10yoQh6SnuKkFITULVZLM+t8JyG/JC4Pmmev1FTVZ0Z6A7yAfoT0mOLTuBErYR19
         COx56IUo5/fa+/CYOKRU89YT9nK26Ynw+g02P2EkE7nZ4zNIuceRmrdSKadJy3N10SCz
         TJfgHBy76kn0yFpxf9RubsE6qbnutGUg5/GU9nwByFzV37L+KP0bgaPchkJalOARoURb
         oHqra4mMkP1O9KdROEyJcLPSCe+0E5c6GWjDpyZC2cV7ka0J2l6c7qlSk+iAARZfbO1H
         Q3uxDvSsQwwwi/qWuiL6t/xvbv/ImFT8RD6uuboh8DvbtKNjSBnb6l/V38yWVdFIY08M
         L24Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XVUAzVFO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oU3lNIszRu2wpA/uN7w7ZKJ+pO2krYs2+TDc1YEPIhA=;
        b=khPHDrnnGkod79/Kll96wHCkQq3bbz6KoJwirMZb+vTX8pmGlqQNcreWpZV/HK6FtO
         8G17UW5UTf0bD+cFcgYZGaHETOb2j8V6so+uHbO8iCSGzmGdc0cgMQYTk6jmqIeJ1G8/
         a1jbf3iw6GE34LpZQ8SPVyEuOqIQijMhPf+ZCsuCgkqMY3+Z/2QYgXceXd6iN/JU4UNA
         LvuPS2iW2wBiPQVKTkL8Uw2xEEoivve7AVfel0GR0m6+MgFsw2frFlML1hwaESrggIoe
         e0spWlnIGcktpdcdW1ARWcZwQzFjgiibXDo8qJJBvexjrb1fC8Pds6qkvrzpEfGoh0hv
         I9tQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oU3lNIszRu2wpA/uN7w7ZKJ+pO2krYs2+TDc1YEPIhA=;
        b=ZaiAcvlrqe3YWDqbac3JvM6JPNlHkqW/b8QgdQ51XsEh/i6jcrxa3SWCLkPCh4QtjQ
         i/xQIN80/8wZK61sGmiRLcqicdI/ULspMqwaNMtoWYLqI4/8TgVoK6xO1dWkLgKOgGVT
         R92GKql+/JCIE+wdVC0V/lK0Lsum/yPMK/r0tHa9DzGRMYygZiu+Riool4BP2r7Su3Xx
         OAf9nfnnl6CLOJ3UtDnM6/EnJUtftEr0kXbP0vVPgGmWNH+6hLREL6nesjebBzbuN8Z2
         Fnlg4vknr7Ls9gpdbrb3yKboK3Pl2b31dnEkkMtp9g4KNfxKuSouWeILZwDavovSG5lp
         KWTQ==
X-Gm-Message-State: AOAM5335HKbsLSg4AhC7syC7+AtLnO1yu0mBYWvNLz4jKoYehSjgid7F
	+Py1WONZfB0/y6v1pIO6v4g=
X-Google-Smtp-Source: ABdhPJz2tPKfzibAF3UWc1RCKy+BfIX1jgZCLGCvi4CgceQVQqm5vOJfdVq1SfswF1AvtJhSRXeevg==
X-Received: by 2002:a05:620a:1258:: with SMTP id a24mr15065524qkl.225.1624684641083;
        Fri, 25 Jun 2021 22:17:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:4367:: with SMTP id u7ls3928435qvt.10.gmail; Fri, 25 Jun
 2021 22:17:20 -0700 (PDT)
X-Received: by 2002:a0c:fd85:: with SMTP id p5mr14325416qvr.22.1624684640662;
        Fri, 25 Jun 2021 22:17:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624684640; cv=none;
        d=google.com; s=arc-20160816;
        b=JbqexCY8hre9dBGN5fK7z1vd1GMFSly54A6GzH6Z8idtgo8dusNYPLX9+n8OFYg0qO
         5mqVBtqDjEmEZrdIWRNSqVdUeIKSV3J5SPb4Z+/T8PiBxGMMjT81SVkd6F8ePqARxMMx
         IM+r0KxuxkJpYT6BzL3g1nfEhnKCDVHqJTbsdbmpRrQb77s0/xMjQLIEPkMZVHP22hDh
         FJ+LQmGCX+O89f6G1Ae6B66iDYAqV+TXANo5L1yK+T6KV3R1+4jvc3HuOpvLzoRqTgHQ
         ox2/ttIY0Zo2UIiKjxLvNWdblxYBYfO4e9IPQQ5sN8Wou6aWIKDZLowGjxdQNWF8YC3F
         MfJg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=omobQP/IX1kTmQx8gX/JOAH5N2ogu7UgIhNdX+iiGPw=;
        b=N3PR5StYv5BJXmWVpHQhZ9OSkAjLzvupthnbCN86S9YHrvh9YN8/lrwgxVkwWRPQAT
         zvD+FlhTIXL9nCKeArFrsACeMSRD6wO+IY/rDKjKs+vUjBPTHqU54WpGBt6XsFacFsrU
         TiKDkuymvMnJfg948YE5Aadfm32RZky5i7zxOIUWbSPOe/o0EqjhMU0qkVWuRt+1zwYE
         0ZtwG/P9A+bQWXHrSouxpZA8xyG2IdB17gPizRDT3T7d1WfN5uZg4o0pZV9Uw9+r34vX
         UbDR5ew+8ASswLlx5m+y+i3Pr4QmVzU0nuiEShNVP4iaDVqBYLCUCupFiZQ0VYE02/Te
         +o6A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=XVUAzVFO;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x835.google.com (mail-qt1-x835.google.com. [2607:f8b0:4864:20::835])
        by gmr-mx.google.com with ESMTPS id c15si1052406qko.1.2021.06.25.22.17.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Jun 2021 22:17:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835 as permitted sender) client-ip=2607:f8b0:4864:20::835;
Received: by mail-qt1-x835.google.com with SMTP id d5so9212096qtd.5
        for <kasan-dev@googlegroups.com>; Fri, 25 Jun 2021 22:17:20 -0700 (PDT)
X-Received: by 2002:a05:622a:15cc:: with SMTP id d12mr12416182qty.67.1624684640111;
 Fri, 25 Jun 2021 22:17:20 -0700 (PDT)
MIME-Version: 1.0
References: <000000000000ef5d1b05c57c2262@google.com> <87fsx7akyf.fsf@disp2133>
 <CACT4Y+YM8wONCrOq75-TFwA86Sg5gRHDK81LQH_O_+yWsdTr=g@mail.gmail.com> <87lf6x4vp1.fsf@disp2133>
In-Reply-To: <87lf6x4vp1.fsf@disp2133>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 26 Jun 2021 07:17:09 +0200
Message-ID: <CACT4Y+YdFpx7-f-YwTnhj6Yy_aYGW7qkj+XV-7QT73DB2a=cmQ@mail.gmail.com>
Subject: Re: [syzbot] KASAN: out-of-bounds Read in do_exit
To: "Eric W. Biederman" <ebiederm@xmission.com>
Cc: syzbot <syzbot+b80bbdcca4c4dfaa189e@syzkaller.appspotmail.com>, 
	akpm@linux-foundation.org, ast@kernel.org, christian@brauner.io, 
	jnewsome@torproject.org, linux-kernel@vger.kernel.org, minchan@kernel.org, 
	oleg@redhat.com, syzkaller-bugs@googlegroups.com, 
	Ingo Molnar <mingo@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=XVUAzVFO;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::835
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

On Fri, Jun 25, 2021 at 8:59 PM Eric W. Biederman <ebiederm@xmission.com> wrote:
>
> Dmitry Vyukov <dvyukov@google.com> writes:
>
> > On Thu, Jun 24, 2021 at 7:31 AM Eric W. Biederman <ebiederm@xmission.com> wrote:
> >>
> >> syzbot <syzbot+b80bbdcca4c4dfaa189e@syzkaller.appspotmail.com> writes:
> >>
> >> > Hello,
> >> >
> >> > syzbot found the following issue on:
> >>
> >> This looks like dueling debug mechanism.  At a quick glance
> >> stack_no_used is deliberately looking for an uninitialized part of the
> >> stack.
> >>
> >> Perhaps the fix is to make KASAN and DEBUG_STACK_USAGE impossible to
> >> select at the same time in Kconfig?
> >
> > +kasan-dev
> >
> > Hi Eric,
> >
> > Thanks for looking into this.
> >
> > I see several strange things about this KASAN report:
> > 1. KASAN is not supposed to leave unused stack memory as "poisoned".
> > Function entry poisons its own frame and function exit unpoisions it.
> > Longjmp-like things can leave unused stack poisoned. We have
> > kasan_unpoison_task_stack_below() for these, so maybe we are missing
> > this annotation somewhere.
> >
> > 2. This stand-alone shadow pattern "07 07 07 07 07 07 07 07" looks fishy.
> > It means there are 7 good bytes, then 1 poisoned byte, then 7 good
> > bytes and so on. I am not sure what can leave such a pattern. Both
> > heap and stack objects have larger redzones in between. I am not sure
> > about globals, but stack should not overlap with globals (and there
> > are no modules on syzbot).
> >
> > So far this happened only once and no reproducer. If nobody sees
> > anything obvious, I would say we just wait for more info.
>
>
> I may be mixing things up but on second glance this entire setup
> feels very familiar.  I think this is the second time I have made
> this request that the two pieces of debugging code play nice.
>
> Perhaps it is a different piece of debugging code and KASAN that
> I am remembering but I think this is the second time this issue has come
> up.

This is the only mention of DEBUG_STACK_USAGE on kasan-dev:
https://groups.google.com/g/kasan-dev/search?q=DEBUG_STACK_USAGE

Searching lore:
https://lore.kernel.org/lkml/?q=KASAN+%22DEBUG_STACK_USAGE%22

I found mention of:
kernel-hacking: move SCHED_STACK_END_CHECK after DEBUG_STACK_USAGE

Maybe you remember these 2?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYdFpx7-f-YwTnhj6Yy_aYGW7qkj%2BXV-7QT73DB2a%3DcmQ%40mail.gmail.com.
