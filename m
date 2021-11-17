Return-Path: <kasan-dev+bncBDKPDS4R5ECRBOFS2KGAMGQENWMKFTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa37.google.com (mail-vk1-xa37.google.com [IPv6:2607:f8b0:4864:20::a37])
	by mail.lfdr.de (Postfix) with ESMTPS id E39EE454080
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 06:55:05 +0100 (CET)
Received: by mail-vk1-xa37.google.com with SMTP id f11-20020a1f9c0b000000b002e52d613018sf790153vke.20
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Nov 2021 21:55:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637128504; cv=pass;
        d=google.com; s=arc-20160816;
        b=Gqgft47GiDgmsbrNCL45oMHLobZU0KbA+5urCNW0oVsXx423G/ou04G0xhbzlCy+mP
         dcvX0L+5LqBclLd8SQg8if+ezsBh3Jq9+KivPzP3V753K30DXaivzY6/NDSqr90ONyNq
         mKYWJ30qYRTKlYfg6XzeSgDJTxLC9igVSgVAKe++5A9TrmEXtY9MFRWB+GTyBE4Xoi+h
         oYcmR/axubWKVT3wQuL1+CPy504CPW+d3PGJyHwG2iulWuiVl2O5tSupaUbM2Xa8sWuH
         KIMVPxeWAgISuaxnM72YZx+qEYWcQvaDUArYFr7SJFQvLNqQCfDPPJDQztDSOrcfRYTe
         XNKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=1o9BByPxHPvo6UBUZ/pi8IfXxdOo/XZ55ppCobx5OMk=;
        b=dJSJ6g+gA1OM0VQws5+GQgBdvIVEdR3UX6vW/Z63+2/qSpjqXIycHPmpttz0efGQWe
         QeV70wVHVM7nq94y7waI42dyxc1vXDqifxP/VTkG/7FYCKcCQe1Nzu/MM17Tw17CoNsW
         +U2/hyeTYycepcbbFtGxHCRth2aU6AuhDwJkWPj7JLSz8U2CVo38kcO78SEvVqxMGotR
         5Ahtkh3KdcKU5Oqi549+mwDiNvzEk1sj/6GlKcs8I2clR6mdXX8fkebXMq9AiO04vXnz
         w5pm9kL2pSnsomapVTJq1YwUnuxD7IP0fS8CenQLcOqfXND8xcisEl/0iT6/njSadI7h
         T/UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=XeG50oA0;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1o9BByPxHPvo6UBUZ/pi8IfXxdOo/XZ55ppCobx5OMk=;
        b=lOa9tIqVgfkukv6IWFHnOZdWhOhNbK2xZGsW1Bs9O/SV7oJqS0n6eExQOSro0EU53C
         XuTgPqza/2/vDcnQoKfeEctmYYDOpF9x4MY3Gyk0cWlg3ryE3YG444Qb3MucZ5z4xwuq
         CkQyVmRyGtHfeXlxYyQOBcOXwgf0MYavi2krt5Xumaad44VKgN0jKm5at+vjRuS9XqGc
         snCWz34thDv1yRhXx1MM+7lxco9meMxP8RSTXfNtybaczb+5f9lMUhSbJYYgrEB2Tq0Y
         q4hg27GZDPW1arHFv/hekP+S7GKJsTVVBfhQVx0yJ1NEp4wqw7z81V9sRjbCmAHUX4EX
         4AMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1o9BByPxHPvo6UBUZ/pi8IfXxdOo/XZ55ppCobx5OMk=;
        b=qjUrjvPT/evQarwUMkZ3pv6K7x38j3JgSImZE6M7B+bD01h+367D7l7+FPwvgWkl4m
         LHTFKLNn11g5PkjbobCgpQnqjliLCGUtNrv61wrZU4oB9I41TW5/hse4TyQ3fM0wf7PV
         HvcrJYhyciEnuL4M6NbOeh5u1eRtFk0lpiQ17GSEkhfHwetdPgqhJR85wL4DpENQ7LfB
         WyhDcR00WojUe0PcNTLXMxfu2sVqRY/sh2u7F9bjlbwIZanzLRbXv3pHp9pz78HEOr0N
         Ry5/1kEGejq1GGPPL/m1PeAgADiOiUy77H70vK2pk3/Khi3E5LqFqclvalsJ4XtjHsUX
         PomQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533/VU2XuI2e5q5Bva2KzRQnIJ1cZD7GwCAEN9MouAeBreENy+b+
	GBXxaomdoMgDLxXh6qqjAI4=
X-Google-Smtp-Source: ABdhPJz8ZOSbzzpvNQv+IptGH+kzdIwM+vtDrIo28OAe03aO8Y6Lk++/IjEDrJPIZPnSAt3QzlUAYQ==
X-Received: by 2002:ab0:5a23:: with SMTP id l32mr19763594uad.129.1637128504639;
        Tue, 16 Nov 2021 21:55:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:3d9a:: with SMTP id l26ls2004407uac.8.gmail; Tue, 16 Nov
 2021 21:55:04 -0800 (PST)
X-Received: by 2002:ab0:63ce:: with SMTP id i14mr19336634uap.130.1637128504189;
        Tue, 16 Nov 2021 21:55:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637128504; cv=none;
        d=google.com; s=arc-20160816;
        b=Vqs+YuWD5AYax8FySb2SGBcqWB3H3dXbyowfJ6bofDg0qcjFII9ZoZ6/O5fxrjbriQ
         MH5QQQToxsJXY/yDkk0ByUUsaArbaoTx1pv7QQOUr001OSfLVg4oVDXbkxzJ9+Zu4sLo
         A1NP7QCgB27nQB3cnRMTmoVNG/CT4WfckUOwA+inmN60m/e1COFBx/spkBZejTqf0KU5
         ZGfUVYiW/OSsVMdPJUZk8JgddCNnCOGo2GIWTBItgI5QbgTl+ScXWfXZtvis84hp3mo3
         tg5ZxlQNjtIne36uLam88fPM+Hbjmk7L6k42+gEtQ9urMmoD9g9eumxcFJH/eOOnm656
         S8Zw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BrkwcwkttrB5ifjfBku0kt7bp7zUGWIamThouDnJlbw=;
        b=Q+rWMeqTCQ85I0o9fQYLvcW9O+Yuzcm+g/N/uBVjmp7neJVVoqUZH8i5HGetAkrkyP
         gt+qU8//8cAT/r0qzerw1I8wZpoKHczrvybChZT+Se+XwyLFns73UIIobJflPpAk+LgA
         Htt2Y07LusgDF5Bf6DEDn2jboc1iZhc0IBvcxBiFmw+FYnzHGh1pxu5Qi4lbbQi97Krc
         n/DbtTMshHaBeEeqe9PdplDvzMd3qBoWlCtmbHjAOdGahc24FEoDp2sHtrmOsIv3RRU6
         24t3sEXgOUmbXB0Wow8E60KGSi8qUh03k6kxbb2nVlRyxZU0R2ifGsxDvEwCSzzNf4E1
         P9Qw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112 header.b=XeG50oA0;
       spf=pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id r20si239571vsn.2.2021.11.16.21.55.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Nov 2021 21:55:04 -0800 (PST)
Received-SPF: pass (google.com: domain of songmuchun@bytedance.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id u60so3995276ybi.9
        for <kasan-dev@googlegroups.com>; Tue, 16 Nov 2021 21:55:04 -0800 (PST)
X-Received: by 2002:a25:ef0b:: with SMTP id g11mr15001602ybd.404.1637128503870;
 Tue, 16 Nov 2021 21:55:03 -0800 (PST)
MIME-Version: 1.0
References: <20211111015037.4092956-1-almasrymina@google.com>
 <CAMZfGtWj5LU0ygDpH9B58R48kM8w3tnowQDD53VNMifSs5uvig@mail.gmail.com>
 <cfa5a07d-1a2a-abee-ef8c-63c5480af23d@oracle.com> <CAMZfGtVjrMC1+fm6JjQfwFHeZN3dcddaAogZsHFEtL4HJyhYUw@mail.gmail.com>
 <CAHS8izPjJRf50yAtB0iZmVBi1LNKVHGmLb6ayx7U2+j8fzSgJA@mail.gmail.com>
 <CALvZod7VPD1rn6E9_1q6VzvXQeHDeE=zPRpr9dBcj5iGPTGKfA@mail.gmail.com>
 <CAMZfGtWJGqbji3OexrGi-uuZ6_LzdUs0q9Vd66SwH93_nfLJLA@mail.gmail.com>
 <6887a91a-9ec8-e06e-4507-b2dff701a147@oracle.com> <CAHS8izP3aOZ6MOOH-eMQ2HzJy2Y8B6NYY-FfJiyoKLGu7_OoJA@mail.gmail.com>
 <CALvZod7UEo100GLg+HW-CG6rp7gPJhdjYtcPfzaPMS7Yxa=ZPA@mail.gmail.com>
 <YZOeUAk8jqO7uiLd@elver.google.com> <CAHS8izPV20pD8nKEsnEYicaCKLH7A+QTYphWRrtTqcppzoQAWg@mail.gmail.com>
In-Reply-To: <CAHS8izPV20pD8nKEsnEYicaCKLH7A+QTYphWRrtTqcppzoQAWg@mail.gmail.com>
From: Muchun Song <songmuchun@bytedance.com>
Date: Wed, 17 Nov 2021 13:54:25 +0800
Message-ID: <CAMZfGtXuKt_6JGG=N_u0LiMkjYw20CQsUj6tEERU+E0NLCpmbg@mail.gmail.com>
Subject: Re: [PATCH v6] hugetlb: Add hugetlb.*.numa_stat file
To: Mina Almasry <almasrymina@google.com>
Cc: Marco Elver <elver@google.com>, Shakeel Butt <shakeelb@google.com>, 
	"Paul E. McKenney" <paulmck@kernel.org>, Mike Kravetz <mike.kravetz@oracle.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Shuah Khan <shuah@kernel.org>, 
	Miaohe Lin <linmiaohe@huawei.com>, Oscar Salvador <osalvador@suse.de>, Michal Hocko <mhocko@suse.com>, 
	David Rientjes <rientjes@google.com>, Jue Wang <juew@google.com>, Yang Yao <ygyao@google.com>, 
	Joanna Li <joannali@google.com>, Cannon Matthews <cannonmatthews@google.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: songmuchun@bytedance.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@bytedance-com.20210112.gappssmtp.com header.s=20210112
 header.b=XeG50oA0;       spf=pass (google.com: domain of songmuchun@bytedance.com
 designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=songmuchun@bytedance.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=bytedance.com
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

On Wed, Nov 17, 2021 at 4:48 AM Mina Almasry <almasrymina@google.com> wrote:
>
> On Tue, Nov 16, 2021 at 4:04 AM Marco Elver <elver@google.com> wrote:
> >
> > On Mon, Nov 15, 2021 at 11:59AM -0800, Shakeel Butt wrote:
> > > On Mon, Nov 15, 2021 at 10:55 AM Mina Almasry <almasrymina@google.com> wrote:
> > [...]
> > > > Sorry I'm still a bit confused. READ_ONCE/WRITE_ONCE isn't documented
> > > > to provide atomicity to the write or read, just prevents the compiler
> > > > from re-ordering them. Is there something I'm missing, or is the
> > > > suggestion to add READ_ONCE/WRITE_ONCE simply to supress the KCSAN
> > > > warnings?
> >
> > It's actually the opposite: READ_ONCE/WRITE_ONCE provide very little
> > ordering (modulo dependencies) guarantees, which includes ordering by
> > compiler, but are supposed to provide atomicity (when used with properly
> > aligned types up to word size [1]; see __READ_ONCE for non-atomic
> > variant).
> >
> > Some more background...
> >
> > The warnings that KCSAN tells you about are "data races", which occur
> > when you have conflicting concurrent accesses, one of which is "plain"
> > and at least one write. I think [2] provides a reasonable summary of
> > data races and why we should care.
> >
> > For Linux, our own memory model (LKMM) documents this [3], and says that
> > as long as concurrent operations are marked (non-plain; e.g. *ONCE),
> > there won't be any data races.
> >
> > There are multiple reasons why data races are undesirable, one of which
> > is to avoid bad compiler transformations [4], because compilers are
> > oblivious to concurrency otherwise.
> >
> > Why do marked operations avoid data races and prevent miscompiles?
> > Among other things, because they should be executed atomically. If they
> > weren't a lot of code would be buggy (there had been cases where the old
> > READ_ONCE could be used on data larger than word size, which certainly
> > weren't atomic, but this is no longer possible).
> >
> > [1] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/asm-generic/rwonce.h#n35
> > [2] https://lwn.net/Articles/816850/#Why%20should%20we%20care%20about%20data%20races?
> > [3] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/explanation.txt#n1920
> > [4] https://lwn.net/Articles/793253/
> >
> > Some rules of thumb when to use which marking:
> > https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/memory-model/Documentation/access-marking.txt
> >
> > In an ideal world, we'd have all intentionally concurrent accesses
> > marked. As-is, KCSAN will find:
> >
> > A. Data race, where failure due to current compilers is unlikely
> >    (supposedly "benign"); merely marking the accesses appropriately is
> >    sufficient. Finding a crash for these will require a miscompilation,
> >    but otherwise look "benign" at the C-language level.
> >
> > B. Race-condition bugs where the bug manifests as a data race, too --
> >    simply marking things doesn't fix the problem. These are the types of
> >    bugs where a data race would point out a more severe issue.
> >
> > Right now we have way too much of type (A), which means looking for (B)
> > requires patience.
> >
> > > +Paul & Marco
> > >
> > > Let's ask the experts.
> > >
> > > We have a "unsigned long usage" variable that is updated within a lock
> > > (hugetlb_lock) but is read without the lock.
> > >
> > > Q1) I think KCSAN will complain about it and READ_ONCE() in the
> > > unlocked read path should be good enough to silent KCSAN. So, the
> > > question is should we still use WRITE_ONCE() as well for usage within
> > > hugetlb_lock?
> >
> > KCSAN's default config will forgive the lack of WRITE_ONCE().
> > Technically it's still a data race (which KCSAN can find with a config
> > change), but can be forgiven because compilers are less likely to cause
> > trouble for writes (background: https://lwn.net/Articles/816854/ bit
> > about "Unmarked writes (aligned and up to word size)...").
> >
> > I would mark both if feasible, as it clearly documents the fact the
> > write can be read concurrently.
> >
> > > Q2) Second question is more about 64 bit archs breaking a 64 bit write
> > > into two 32 bit writes. Is this a real issue? If yes, then the
> > > combination of READ_ONCE()/WRITE_ONCE() are good enough for the given
> > > use-case?
> >
> > Per above, probably unlikely, but allowed. WRITE_ONCE should prevent it,
> > and at least relieve you to not worry about it (and shift the burden to
> > WRITE_ONCE's implementation).
> >
>
> Thank you very much for the detailed response. I can add READ_ONCE()
> at the no-lock read site, that is no issue.
>
> However, for the writes that happen while holding the lock, the write
> is like so:
> +               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] += nr_pages;
>
> And like so:
> +               h_cg->nodeinfo[page_to_nid(page)]->usage[idx] -= nr_pages;
>
> I.e. they are increments/decrements. Sorry if I missed it but I can't
> find an INC_ONCE(), and it seems wrong to me to do something like:
>
> +               WRITE_ONCE(h_cg->nodeinfo[page_to_nid(page)]->usage[idx],
> +
> h_cg->nodeinfo[page_to_nid(page)] + nr_pages);

How about using a local variable to cache
h_cg->nodeinfo[page_to_nid(page)]->usage[idx],
like the following.

long usage = h_cg->nodeinfo[page_to_nid(page)]->usage[idx];

usage += nr_pages;
WRITE_ONCE(h_cg->nodeinfo[page_to_nid(page)]->usage[idx], usage);

Does this look more comfortable?

>
> I know we're holding a lock anyway so there is no race, but to the
> casual reader this looks wrong as there is a race between the fetch of
> the value and the WRITE_ONCE(). What to do here? Seems to me the most

It's not an issue, because fetching is a read operation and the
path of reading a stat file is also a read operation. Both are "plain"
operations.

> reasonable thing to do is just READ_ONCE() and leave the write plain?

I suggest using WRITE_ONCE() here and READ_ONCE() in the reading.

Thanks.

>
>
> > Thanks,
> > -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMZfGtXuKt_6JGG%3DN_u0LiMkjYw20CQsUj6tEERU%2BE0NLCpmbg%40mail.gmail.com.
