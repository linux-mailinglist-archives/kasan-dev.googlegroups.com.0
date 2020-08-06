Return-Path: <kasan-dev+bncBCMIZB7QWENRBLUIWD4QKGQEOKVTW3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x738.google.com (mail-qk1-x738.google.com [IPv6:2607:f8b0:4864:20::738])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A33E23DAAB
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Aug 2020 15:22:56 +0200 (CEST)
Received: by mail-qk1-x738.google.com with SMTP id v16sf33484735qka.18
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Aug 2020 06:22:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596720175; cv=pass;
        d=google.com; s=arc-20160816;
        b=BmZOxdFVT47ZQ/2YFUQ8YwPMopyZiVsvWJShPgBUaw8chzT8IFb+BAkqMWwbhxwljo
         9hCVUwbV2t8ofoRGQQ0+AEMTH9SVWh33u4rmluQupr+93mxsF0kiBRUpenagezgNrsBu
         f/AGBPw/K+QhVavIkK/yJsnjT9TYwGpRYZh4DkXIhF77Hq1DD8yqsu1spBW3ABGlL55b
         wLMqeOZaal1Wl4MyqusiO+OUFjkH7pmW6JXI5N1yp879dz4y29amoboacZWPBfAiMDCC
         9PHx+/LqrXEy39zecjxKiUa4jgF6R3+FjgzSJtKDPuIOklPrcDE/ON9NYCRRziyFLIZ/
         aYYA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=eezoRCSp+HIhlOvdgGhWmGutl+egjG7jdYvzls8hS+Q=;
        b=l5lBTriBU8DpqbzCq0FyR1lcqWT1ZIX9wG5v474L6vw0XJLlhNv//je11vJExzpADI
         CijoT4heDxou6WjA+dHwHGyoEmciJtGvTTNBYvNrZqve4iYdnRegvqDU/A2jAgG6jXIa
         IC60+8z9n+EpkZ38XlVS8LBixT4Srb9ovMEr5kbQ5krPUiM/22wq4GQEJQotwykwMCnu
         IcBBHce/FtbkGDVou5qsg9jqMiCJsqiVAIoWeBQSSvn+o1NGdcR+EvbW9MYjxsN6cYw2
         eM7o8b0WooafWWI3E2AebYdDsziLFvj9Jep8PUPauR5wmMmReH/8LV+51q5AbqNFHplN
         9A3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Mg6HboN/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eezoRCSp+HIhlOvdgGhWmGutl+egjG7jdYvzls8hS+Q=;
        b=LifGjS9SX+q88tTM99iacQnHbD1eZgm2JK6FcqDEK/Zx99m7dDxOFTl+YxkoXauy7P
         Ln5tggSt9bhFWaqN1gAU6cl6gKErmpfW9vb2zBQQsTUzf2e8346opNyjLmA29kr5o6DA
         nJRWZ0jjFlGXv0Ey3fObSSFsejCUvGH7QWuXxTLiyY8/B9AtAS7thAoThoH0JHqgLrx9
         RXY3jDCsUMlwYeCMnJVbX4zu1h+r3C4+RxlXiRnTU++z1PvUtJE0rvJ/tqEYknzEIGHD
         ln13KGl6yq0AzW/q3c9+Ase79Fl6f85n40kQ37R5MeemusajJdIRGznac38fFzxcNLOC
         OArQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=eezoRCSp+HIhlOvdgGhWmGutl+egjG7jdYvzls8hS+Q=;
        b=jX51tERyIuCntIB32qbHvM3Sz4ErSfMRVFpVgajIKni784Yoxiz86GJeGZeRjKZ5Ex
         skwu8pfyFGzi6PXO314hk5jAe4dbnHG8k/aRSAclgPcIcLSqK10sXiu3Ek0yXJ1r+SLk
         Z6cYvaSGtgyiIcN3gkkk06V/g2U/RL9nAx6uKp6JHZzj7ttDZwHx7fIys4MaXcr3RnE/
         NvFZl22RlafkQzqmhEspGdF0jrHEDE9jq7ezE0z1BHCtcsne4E6TcsMuUCOFzr/+yhLp
         0bp2zqeTxVYxD8p0l7yzJKrvHH5BHdCK4lmyXC2+r2EQVuyamzHDnTmh7nL+iSaQRHil
         70zA==
X-Gm-Message-State: AOAM532PXi9R9caVQuT5VLq/VspGquHjJwDSkLDeiHkqte9yXzyEsglP
	ayT+KQqPFNl/Spa0u9KzEeY=
X-Google-Smtp-Source: ABdhPJyjinaa3Un7O81srr2ZE8GD8mrO0v26nPqxSYBatR57FxE5jZdCI7voStkwOouLqzhCwcgbjw==
X-Received: by 2002:a37:714:: with SMTP id 20mr8796535qkh.367.1596720174815;
        Thu, 06 Aug 2020 06:22:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:120e:: with SMTP id u14ls2683062qkj.3.gmail; Thu,
 06 Aug 2020 06:22:54 -0700 (PDT)
X-Received: by 2002:a37:bc87:: with SMTP id m129mr8419800qkf.47.1596720174461;
        Thu, 06 Aug 2020 06:22:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596720174; cv=none;
        d=google.com; s=arc-20160816;
        b=S8Wai994a9rY2nN1Fggfj9rc7cjCRGNKYdfocW2JbAlsIL1F7P6TR9WLmxak1+Pv3b
         JqSdMZ1bvjsxAJO4J0xpws7rFE87u+kkfH7rRblRJCyiWuIy/U2RXgecDiOjlGUjuJ4t
         hbxzAAmLwU+8mjNhsktxbpFdqWEMvRDA2SHaLKz0obJhCYCJaUALFVQjyJk1VA1SspDG
         1ppZMJ3sQXWgAMWAOcsKWylSdX6vNS8yOnQqSDy6SAlgYwKaQFcbpIf//CPRw1MevI/n
         B1llOF2gEnA3yEGj3RaMFf2T8NcrLDSelxzaUKS3R6rPCWFP9nGpqoVDEAfpOTj0/feh
         RAQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=l452q3QF9j1q5B+O8g1DRoVbZw8RLr9ADl2JOygRsek=;
        b=iS1eMbtFhYDKSN0rbQa3eHWpw8m/uNgjKr/39T7lLdnL9L7JddOsOKgNDHUeSYQ2H8
         7wV0cTN09tQkTDmsMZ3s/zer6wlXD9A9G3VB0ilrPssbHP2YIgsgmD1EQLz6YMQGQ6D9
         kj+A8kaaVDmqqr5fO19zB6O7wUjhp0mX6W9tr5sIymYAebu+O8ihyuYNpEYAfduRBt3l
         TUf0bV6qvvM/+ofwcRoU9ICotuSNb2AgnlEaXHuM2ci66FZihjYBq9X6jys2CgrLaoHJ
         kR1XesWBHQR1lV5LFKzH/xOFsAPVlEMVtajejAQswmC1vIBShE4dFB8ja1s1qucaP+Je
         Zzsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Mg6HboN/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id s124si294492qke.3.2020.08.06.06.22.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Aug 2020 06:22:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id w9so36268348qts.6
        for <kasan-dev@googlegroups.com>; Thu, 06 Aug 2020 06:22:54 -0700 (PDT)
X-Received: by 2002:ac8:154:: with SMTP id f20mr8501217qtg.57.1596720173806;
 Thu, 06 Aug 2020 06:22:53 -0700 (PDT)
MIME-Version: 1.0
References: <20200805230852.GA28727@paulmck-ThinkPad-P72> <CANpmjNPxzOFC+VQujipFaPmAV8evU2LnB4X-iXuHah45o-7pfw@mail.gmail.com>
In-Reply-To: <CANpmjNPxzOFC+VQujipFaPmAV8evU2LnB4X-iXuHah45o-7pfw@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 6 Aug 2020 15:22:42 +0200
Message-ID: <CACT4Y+Ye7j-scb-thp2ubORCoEnuJPHL7W6Wh_DLP_4cux-0SQ@mail.gmail.com>
Subject: Re: Finally starting on short RCU grace periods, but...
To: Marco Elver <elver@google.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Kostya Serebryany <kcc@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	"'Dmitry Vyukov' via syzkaller-upstream-moderation" <syzkaller-upstream-moderation@googlegroups.com>, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Mg6HboN/";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::841
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

On Thu, Aug 6, 2020 at 12:31 PM Marco Elver <elver@google.com> wrote:
>
> +Cc kasan-dev
>
> On Thu, 6 Aug 2020 at 01:08, Paul E. McKenney <paulmck@kernel.org> wrote:
> >
> > Hello!
> >
> > If I remember correctly, one of you asked for a way to shorten RCU
> > grace periods so that KASAN would have a better chance of detecting bugs
> > such as pointers being leaked out of RCU read-side critical sections.
> > I am finally starting entering and testing code for this, but realized
> > that I had forgotten a couple of things:
> >
> > 1.      I don't remember exactly who asked, but I suspect that it was
> >         Kostya.  I am using his Reported-by as a placeholder for the
> >         moment, but please let me know if this should be adjusted.
>
> It certainly was not me.
>
> > 2.      Although this work is necessary to detect situtions where
> >         call_rcu() is used to initiate a grace period, there already
> >         exists a way to make short grace periods that are initiated by
> >         synchronize_rcu(), namely, the rcupdate.rcu_expedited kernel
> >         boot parameter.  This will cause all calls to synchronize_rcu()
> >         to act like synchronize_rcu_expedited(), resulting in about 2-3
> >         orders of magnitude reduction in grace-period latency on small
> >         systems (say 16 CPUs).
> >
> > In addition, I plan to make a few other adjustments that will
> > increase the probability of KASAN spotting a pointer leak even in the
> > rcupdate.rcu_expedited case.
>
> Thank you, that'll be useful I think.
>
> > But if you would like to start this sort of testing on current mainline,
> > rcupdate.rcu_expedited is your friend!

Hi Paul,

This is great!

I understand it's not a sufficiently challenging way of tracking
things, but it's simply here ;)
https://bugzilla.kernel.org/show_bug.cgi?id=208299
(now we also know who asked for this, +Jann)

I've tested on the latest mainline and with rcupdate.rcu_expedited=1
it boots to ssh successfully and I see:
[    0.369258][    T0] All grace periods are expedited (rcu_expedited).

I have created https://github.com/google/syzkaller/pull/2021 to enable
it on syzbot.
On syzbot we generally use only 2-4 CPUs per VM, so it should be even better.

> Do any of you remember some bugs we missed due to this? Can we find
> them if we add this option?

The problem is that it's hard to remember bugs that were not caught :)
Here is an approximation of UAFs with free in rcu callback:
https://groups.google.com/forum/#!searchin/syzkaller-bugs/KASAN$20use-after-free$20rcu_do_batch%7Csort:date
The ones with low hit count are the ones that we almost did not catch.
That's the best estimation I can think of. Also potentially we can get
reproducers for such bugs without reproducers.
Maybe we will be able to correlate some bugs/reproducers that appear
soon with this change.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYe7j-scb-thp2ubORCoEnuJPHL7W6Wh_DLP_4cux-0SQ%40mail.gmail.com.
