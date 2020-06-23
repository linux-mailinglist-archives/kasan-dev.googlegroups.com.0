Return-Path: <kasan-dev+bncBCMIZB7QWENRBXHWY33QKGQE7DH5W6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 03FFD204C32
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 10:20:46 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id o100sf1655877pjo.9
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 01:20:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592900444; cv=pass;
        d=google.com; s=arc-20160816;
        b=djAzhi+1B98dYXH7lkJe5fCh4V51kh8713NdRxvqIvdzuRwuQm6zzSbrofgVzc8gvG
         XAQ3V5WfAinbOVgl0QuWrzGT4qgGRXzD/mDOOgWxfV51tCJxKuVL0lpmtxsXrEzV7Cfi
         Lxq+rtB4Yqxv+TPJVSmFBWJSMVHF5Nw/lW4HvC9vBzuuimVoNRQFp4pb9ZyE0hL9GU0e
         aBo8j744Qdw0Tp4Jdh+a9piDmUQ9kmv3a8j4Teygj0zaE4TvYE1toX5Y3Hu/QsJv+9jz
         pPWp0Evuta4wfY0mex5Ad6vn5yM3ZHEzC0XFMIzNndI3zHWXqYxCASbkuxpdN15FVzkX
         OU9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZGVdiCBBxYe9StU2bvbKsKB1/quzl17gE7LUWIBYEQM=;
        b=bNwPmZ0b+0CdBFEInddVrSnQr0bmUanlNzEk1D7vMP3J/i//Og01Fhor/4t5u/cxMS
         sVHVaSlm2g+wetaPt6/Gv+L9mI8ihxTKYTPF/oy5Q0BtYOer6FsHP5JYXELMjxXy37WZ
         3MLB19+ExsypZ6IhEHP0Z2yDxEZk9F8gPlLfMSzOrDamNaj1kH+YT+KhD3IQ4EqzOQvn
         tlN/BeWF3hqvI8dKVbpXUlRnbt8tdpwcMCOE1i+qAiHv1uxZ2C3Lb+9Zn/4M8OD96ErF
         53EjeQuZt5yZtwnM2dCLs+yiomuskgaEpRh2uwWPPtEL/HbyuOUjrkULTZpcp249w27o
         Z9OQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lu0BRWhc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZGVdiCBBxYe9StU2bvbKsKB1/quzl17gE7LUWIBYEQM=;
        b=D0F/OLBvIuxl6mvKfv5DcuswWR3wFGTjMBjCiiyiMJNcxKetav/2CfeB3eYWJjuK0X
         XAzeWYVLBeb4AHXWgCbED7wlFhAe8A1qqjdhT1FheLLDHuxvkCdakTJhKzT1gv9bYssQ
         zrD38+sHDLRkm8lNACsEAb2NZeBG2/lFHv7dVMoy3aBx4ysfkBV3uSrBihXQzF2O79e5
         I5B4bLbn8l5nw7JfLtDmOzPzh0j6TVlA2TYCayzeVfJ+wHcmBTk2JO7qFJHp1qjAdQIJ
         8haXTcO/TJjSwKTuoDY4vG41mf9/ws2ckl0Mi/SjE181Lj/nXiCr2mZzCLPFi5lz/N2n
         Uvcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZGVdiCBBxYe9StU2bvbKsKB1/quzl17gE7LUWIBYEQM=;
        b=R8s5VtW7vhh4HJFpcB3fb6HEGUeCYvm2CkrU5Ke7xQcXMaQCN0Y0vuWhnSgaNYeZh2
         ASjUfAxVqPZMquIIjPSpEUOj7xYG9LYSToDB2NCTTQHkafgLnfwtqyVAy9k7KqgKUwxu
         Rl1xgCGAdkXySRDdOm8Jgc1xza0rlAd4CEVmOBcOPuxxgYFOZgPLT6bQVnaAH7WKCo6N
         O64wvViVfDgsCx7zXfODBiaJeczKCQAYA9RZGcZ0X740dvl+VEOaspElgfFknNgEaIVk
         uUkmUjQk5QINikmPeYL85L1eC86xElnLppElCFA1dthq2SktOneatF8k6YgXpFs9DSrx
         A8jA==
X-Gm-Message-State: AOAM531BxBe7368YSPk40akdbZIjyDP1TybfVoIRzQWJRoQ/iT1pMIYC
	OGdC1zttSKamTy7g/Hr1AG4=
X-Google-Smtp-Source: ABdhPJympyRcF9HFgkGLyqAttz0mVLp1hoNFGNy6qBl0jue8ian3MNQ5Hpqf+jwlganF2LYsch+Jdw==
X-Received: by 2002:a63:de18:: with SMTP id f24mr15735252pgg.415.1592900444536;
        Tue, 23 Jun 2020 01:20:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:e312:: with SMTP id g18ls6454549pfh.9.gmail; Tue, 23 Jun
 2020 01:20:44 -0700 (PDT)
X-Received: by 2002:a62:5e85:: with SMTP id s127mr10456058pfb.236.1592900444137;
        Tue, 23 Jun 2020 01:20:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592900444; cv=none;
        d=google.com; s=arc-20160816;
        b=uPb0gj0m2SFEz2wPvXk+OFvrY3+CqKMn17ruVCS7sYy7pxk0CWsh9qyaPPTwjabhm8
         I/s+mGZFj0qkKqlC97qeGJl/ntftrhrFzRXBucKiwGy4nC0raFxTTYLER3iNWOyCdn9f
         fXSJFQ5sPGxOjTesu4pVNBYPnzLxozDs5D2XkSg32pWva2Qgv3JRAIX9FDt5dYxjFNh6
         GKQjkBDx3X8sdpBOvlirnPvd7g9TIuzPFa4vAya/B3VxAePbnjWHI37is5S/dKUrILzi
         roxgymxZALkCPvdeqJjk8Fp5aKC0ZdT1U2Pf3vg8Gau0I+4M9Sj/uA6LxQiE2n5MANiz
         TKkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oTCrk0q7d5uObaa5idNAN9eS899lK9/IM36Im/keRbk=;
        b=VLNGPXVBGzbTiT3rig8I6knoQ52XOL0tpLTkUC1XHck+3KI37EschlXe84uadJXI9c
         y3DE8lIaUXGJvY+aD9lIUX1Ff8LkdyDcFCCj6q7TMj9mXlOudYBe4sChAw1vE1oiK2TP
         8ibsr1yc8TtPw43vUGK7OtTQ82C03bjPK2ncw3inktfz026ZFoavph+JFePZtE6tA4aJ
         a3IWjTf6PymC39eUoUgDd5YL8gL6STDgrYaSOJRBJ13X/Of6ypGCtBM3P08J0FqG+42M
         pGsw77vekURjDWWL9EL4mPkGUziya0BNHq/Z8ZKwcfhANM/RHvfasaWqeyKCklmusAwZ
         gGJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Lu0BRWhc;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id l9si50140pjw.2.2020.06.23.01.20.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Jun 2020 01:20:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id 80so6197829qko.7
        for <kasan-dev@googlegroups.com>; Tue, 23 Jun 2020 01:20:44 -0700 (PDT)
X-Received: by 2002:a37:4851:: with SMTP id v78mr18721413qka.256.1592900442889;
 Tue, 23 Jun 2020 01:20:42 -0700 (PDT)
MIME-Version: 1.0
References: <20200601050847.1096-1-walter-zh.wu@mediatek.com> <1592899732.13735.8.camel@mtksdccf07>
In-Reply-To: <1592899732.13735.8.camel@mtksdccf07>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 10:20:31 +0200
Message-ID: <CACT4Y+Y4Fe55Sz0Z7TQsKq_4UnfOOYAKtHd5xmMmb8FT2wLN8g@mail.gmail.com>
Subject: Re: [PATCH v7 0/4] kasan: memorize and print call_rcu stack
To: Walter Wu <walter-zh.wu@mediatek.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Josh Triplett <josh@joshtriplett.org>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Lai Jiangshan <jiangshanlai@gmail.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Andrey Konovalov <andreyknvl@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	wsd_upstream <wsd_upstream@mediatek.com>, linux-mediatek@lists.infradead.org, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Lu0BRWhc;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Tue, Jun 23, 2020 at 10:09 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
>
> On Mon, 2020-06-01 at 13:08 +0800, Walter Wu wrote:
> > This patchset improves KASAN reports by making them to have
> > call_rcu() call stack information. It is useful for programmers
> > to solve use-after-free or double-free memory issue.
> >
> > The KASAN report was as follows(cleaned up slightly):
> >
> > BUG: KASAN: use-after-free in kasan_rcu_reclaim+0x58/0x60
> >
> > Freed by task 0:
> >  kasan_save_stack+0x24/0x50
> >  kasan_set_track+0x24/0x38
> >  kasan_set_free_info+0x18/0x20
> >  __kasan_slab_free+0x10c/0x170
> >  kasan_slab_free+0x10/0x18
> >  kfree+0x98/0x270
> >  kasan_rcu_reclaim+0x1c/0x60
> >
> > Last call_rcu():
> >  kasan_save_stack+0x24/0x50
> >  kasan_record_aux_stack+0xbc/0xd0
> >  call_rcu+0x8c/0x580
> >  kasan_rcu_uaf+0xf4/0xf8
> >
> > Generic KASAN will record the last two call_rcu() call stacks and
> > print up to 2 call_rcu() call stacks in KASAN report. it is only
> > suitable for generic KASAN.
> >
> > This feature considers the size of struct kasan_alloc_meta and
> > kasan_free_meta, we try to optimize the structure layout and size
> > , lets it get better memory consumption.
> >
> > [1]https://bugzilla.kernel.org/show_bug.cgi?id=198437
> > [2]https://groups.google.com/forum/#!searchin/kasan-dev/better$20stack$20traces$20for$20rcu%7Csort:date/kasan-dev/KQsjT_88hDE/7rNUZprRBgAJ
> >
> > Changes since v1:
> > - remove new config option, default enable it in generic KASAN
> > - test this feature in SLAB/SLUB, it is pass.
> > - modify macro to be more clearly
> > - modify documentation
> >
> > Changes since v2:
> > - change recording from first/last to the last two call stacks
> > - move free track into kasan free meta
> > - init slab_free_meta on object slot creation
> > - modify documentation
> >
> > Changes since v3:
> > - change variable name to be more clearly
> > - remove the redundant condition
> > - remove init free meta-data and increasing object condition
> >
> > Changes since v4:
> > - add a macro KASAN_KMALLOC_FREETRACK in order to check whether
> >   print free stack
> > - change printing message
> > - remove descriptions in Kocong.kasan
> >
> > Changes since v5:
> > - reuse print_stack() in print_track()
> >
> > Changes since v6:
> > - fix typo
> > - renamed the variable name in testcase
> >
> > Walter Wu (4):
> > rcu: kasan: record and print call_rcu() call stack
> > kasan: record and print the free track
> > kasan: add tests for call_rcu stack recording
> > kasan: update documentation for generic kasan
> >
>
> Hi Andrew,
>
> Would you tell me why don't pick up this patches?
> Do I miss something?
>
> I will want to implement another new patches, but it need to depend on
> this patches.

On a related note.
Doing this for workqueue on top of these patches may be useful as
well, here is syzbot UAFs that mention process_one_work:
https://groups.google.com/forum/#!searchin/syzkaller-bugs/%22use-after-free%22$20process_one_work%7Csort:date

In some of these access/allocation happened in in process_one_work, in
some workqueue queueing stack may not add much.
But if we take the last one:
https://groups.google.com/forum/#!searchin/syzkaller-bugs/%22use-after-free%22$20process_one_work%7Csort:date/syzkaller-bugs/IYE0kt0BZMQ/zNM5rlzjAQAJ
It's exactly the same "free stack is useless" situation:

Freed by task 17:
 kfree+0x10a/0x220 mm/slab.c:3757
 process_one_work+0x76e/0xfd0 kernel/workqueue.c:2268
 worker_thread+0xa7f/0x1450 kernel/workqueue.c:2414
 kthread+0x353/0x380 kernel/kthread.c:268

The same may stand for times, I think I've seen some bugs where the
bad access happens in the timer as well.
Adding workqueue and timers should be pretty minimal change I think.


> > Documentation/dev-tools/kasan.rst |  3 +++
> > include/linux/kasan.h             |  2 ++
> > kernel/rcu/tree.c                 |  2 ++
> > lib/test_kasan.c                  | 30 ++++++++++++++++++++++++++++++
> > mm/kasan/common.c                 | 26 ++++----------------------
> > mm/kasan/generic.c                | 43 +++++++++++++++++++++++++++++++++++++++++++
> > mm/kasan/generic_report.c         |  1 +
> > mm/kasan/kasan.h                  | 23 +++++++++++++++++++++--
> > mm/kasan/quarantine.c             |  1 +
> > mm/kasan/report.c                 | 54 +++++++++++++++++++++++++++---------------------------
> > mm/kasan/tags.c                   | 37 +++++++++++++++++++++++++++++++++++++
> > 11 files changed, 171 insertions(+), 51 deletions(-)
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1592899732.13735.8.camel%40mtksdccf07.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BY4Fe55Sz0Z7TQsKq_4UnfOOYAKtHd5xmMmb8FT2wLN8g%40mail.gmail.com.
