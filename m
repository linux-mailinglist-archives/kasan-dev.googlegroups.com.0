Return-Path: <kasan-dev+bncBCMIZB7QWENRBV4JSKBAMGQEJ3W6SSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 97A7F32FF87
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Mar 2021 08:46:32 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id v196sf8625454ybv.3
        for <lists+kasan-dev@lfdr.de>; Sat, 06 Mar 2021 23:46:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615103191; cv=pass;
        d=google.com; s=arc-20160816;
        b=nq9YdtsfaPhUJ30CJUAt1+7vglKxAxEjh51eUI3+gHkolQMYkmlSfAPtjOW4GOHeuT
         Eg0+qEzq3OyEbzeDJlqToZQVPyKBiWdzkQ+re6dg3yoDkwFAjOwsq/Ri9c/fIdyBt83w
         cQScbSl6MI8QFPhnNcQgOzU8GmgeN/OXdVTTgisP0qwPfIuJRuXiyiQuzsUo3ugL7uLJ
         sW3S4YZKctQLxhHzmctmGU7S601Ww9f0D/cNILwqRdjrT7CcvLgM1byp4uoZF50xhXK9
         zpH3wDtZnD685dknf4E8EDgarX4KA2S557KYfWx3sAg6P5hryy4S7x5dISgUNje2YmQ8
         ICVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4zWIorBvtTFoszvy4C8UfW0jOtYeHvoxt9vEt08gyKs=;
        b=tdyGOCyviJ+1NnJTQhrX/A8eSBSZaITFYSTCW3pVLCl0Kg9/vP7T6ZaMOEZFOUgFie
         EkGT2KXd/SqL4aysbWaph+dfbEczlkb6Ceo+ktiTF6ZfJLU7n2IBjha2z3CApaDaqG1J
         E9Vker0ABVdEwL0B1pGIO+If3u64VGoruD2Mf/HRrjJMXjByFKCUycalV7mP4aSJRYoA
         vxOSKOMdWbVo6lf9MiJBHRwJeaUfL3NRPt3aDFyae31OHvU0hXjgTT9HuervRDkPnag1
         /ioChpjJJyGVQTGBXppoNdQEVbVEaChriIG7IymLKDR7a4Ehgb+x0Dkir7XnJEf9Hfmn
         Ccvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pnyWli3g;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4zWIorBvtTFoszvy4C8UfW0jOtYeHvoxt9vEt08gyKs=;
        b=rPku9SuDJ623cMhZVsCth1PX+tcqRaustvKZLOk5Rnfv+KY/t92aCQUY5ZxDTzwYqz
         v4sLpvisP+3waYKsfnU8IK1euTxW6KT7siB8aChCkVXqrzYv7jkHcorZ9z4UzS/fBSeC
         hNE9q29aEJOz1jSajII2bGvvjwBk7nKxN8jDlCkZvd1nLBT/MynsZ8EP9H2j/Mk+e/e4
         vwO80k2kC/QWAgwwgP+lasQnT83vVOtZ2P3YjUOCk0yAiI6GSi/q3aFAjQTwc9zULRkN
         bQIjflYx8M6g8LrPU1Vk9sk74iX3HmTipSpabOIfI4WvKf7KUd7T9tqIqXLOQiQw7xY4
         i8bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4zWIorBvtTFoszvy4C8UfW0jOtYeHvoxt9vEt08gyKs=;
        b=Xye5BL64CJDbS3fIGkjfC7DOE8CsHS6gI7Tr/b1CRyyFeYXPSxM7YAbljDZRJeWP1s
         chqpTPKLQUs8DBFcYPAg9T5VEhk1zZ40QnsW9BakoUDxfnkYNRuRP/LAtjhDstwLK+Ut
         RFxMVUNRuyE4eN0nOztjPjdFRTxpsD91mbD/fDhiIw2IhnOcetgr5iPaxuQGMvVfa+Uw
         hNNEa87sThaFiAlEbmdNrdtZFw3RlaeJh2tHQiEGSMDlTaLQAMTYAbGWK65d9b1jA1NG
         OYspgC8l9pVqu/PNoeH/at5WIdBjScrRZXiNzYM/A4fW2a/Ch24Ob3qqkFmH6V7EjKPU
         VPPA==
X-Gm-Message-State: AOAM533o2K71zJo0r+xfQGiOhRQtVPZbnzzoxSFjpZhUw13U1vzCwGf9
	qziPQzF6GqgaBG7XSi9tsA4=
X-Google-Smtp-Source: ABdhPJyZWqlSRidSWg+WXgq2f1yfhueFzxx8sV09S5XKv3LqfA1V4ZNLboncsd9ICU5V+Pq85XtmbA==
X-Received: by 2002:a25:dc8:: with SMTP id 191mr26465070ybn.246.1615103191441;
        Sat, 06 Mar 2021 23:46:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9805:: with SMTP id a5ls6989053ybo.7.gmail; Sat, 06 Mar
 2021 23:46:31 -0800 (PST)
X-Received: by 2002:a25:ae64:: with SMTP id g36mr25544205ybe.296.1615103190992;
        Sat, 06 Mar 2021 23:46:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615103190; cv=none;
        d=google.com; s=arc-20160816;
        b=nKldv4vZec7bQmKiX4VyrQeSLRZ0TaguLJ5GpagBInTxhiy6yjqk1MoscFbnBmD/vO
         +Qevu0ypQFEo3q9cEEAyfw+ydmB1Qof95ISR67AsgL6ISxQMLwNzG67/QN6bWDL/fKBd
         2I65ldVSHa4zKfY+PVr7gj/ZUOfFpAO9DWMGc6saTRpOnkSoWKdD7YHhg4mfNqSvIalb
         W/7+wyp8f0LI8HQtQVSfOPOGzIbh0p7vIt8LmVl/aGbSIfzhR18gvUjNn2VQuSbomYXX
         taKzW+eFdyEubnQqMLfX0gbZrFyVLffdUZY/Q7VK0dh8aGiC7vHkLwiswxthAx+Gebjs
         c2vw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hQtEqMHNvN9OvaCbhllTDDfdBhxggIMHD/rchmXP5Hc=;
        b=u/t65z/7RCDpcvXryLvSHUSmwLwtn/oS2BTNMtwTeL6PWNWT5SPy08sHClY8trH5dI
         ixUpLMeFpdPt4Bzuo/OpCrSc7ez4aJcB6pLEi4TsZiK9/jZ5YsZIs5LW399dwMTnblpI
         CErpxW9yPLjpFfxC4QHNU62wnBxt/7wgqyAn3VF+ersW5d8K7apblHWW1s8V9Haj48jL
         6PWH+G7943g38xkKCAnAKV5ZAynmJUdFb7FMvf8YOPHJiuUbFR2OBJ3WZomc0jdrTn5M
         zp4zdK2LABazdtU6RsjeB9jzU+WpY5L7TcW24axzu8AbiVb/Yl4sKEJSTmVk/cuxrI7u
         Lu3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pnyWli3g;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2e.google.com (mail-qv1-xf2e.google.com. [2607:f8b0:4864:20::f2e])
        by gmr-mx.google.com with ESMTPS id t17si712120ybl.2.2021.03.06.23.46.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 06 Mar 2021 23:46:30 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2e as permitted sender) client-ip=2607:f8b0:4864:20::f2e;
Received: by mail-qv1-xf2e.google.com with SMTP id 15so3147781qvp.13
        for <kasan-dev@googlegroups.com>; Sat, 06 Mar 2021 23:46:30 -0800 (PST)
X-Received: by 2002:a0c:8304:: with SMTP id j4mr16019838qva.18.1615103190414;
 Sat, 06 Mar 2021 23:46:30 -0800 (PST)
MIME-Version: 1.0
References: <CABXGCsP63mN+G1xE7UBfVRuDRcJiRRC7EXU2y25f9rXkoU-0LQ@mail.gmail.com>
 <CACVXFVOy8928GNowCQRGQKQxuLtHn0V+pYk1kzeOyc0pyDvkjQ@mail.gmail.com>
 <20210305090022.1863-1-hdanton@sina.com> <CACVXFVPp_byzrYVwyo05u0v3zoPP42FKZhfWMb6GMBno1rCZRw@mail.gmail.com>
 <E28250BB-FBFF-4F02-B7A2-9530340E481E@linaro.org> <YEIBYLnAqdueErun@T590> <20210307021524.13260-1-hdanton@sina.com>
In-Reply-To: <20210307021524.13260-1-hdanton@sina.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 7 Mar 2021 08:46:19 +0100
Message-ID: <CACT4Y+aLnam+7FGx9MiMRRbgFE6v+Vg6Hu0hkx+P=h+DL8Mayg@mail.gmail.com>
Subject: Re: [bugreport 5.9-rc8] general protection fault in __bfq_deactivate_entity
To: Hillf Danton <hdanton@sina.com>
Cc: Ming Lei <ming.lei@redhat.com>, Paolo Valente <paolo.valente@linaro.org>, 
	Ming Lei <tom.leiming@gmail.com>, Mikhail Gavrilov <mikhail.v.gavrilov@gmail.com>, 
	linux-block <linux-block@vger.kernel.org>, Jens Axboe <axboe@fb.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pnyWli3g;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2e
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

On Sun, Mar 7, 2021 at 3:15 AM Hillf Danton <hdanton@sina.com> wrote:
>
> On Fri, 5 Mar 2021 18:01:04 +0800  Ming Lei wrote:
> > On Fri, Mar 05, 2021 at 10:32:04AM +0100, Paolo Valente wrote:
> > > I'm thinking of a way to debug this too.  The symptom may hint at a
> > > use-after-free.  Could you enable KASAN in your tests?  (On the flip
> > > side, I know this might change timings, thereby making the fault
> > > disappear).
> >
> > I have asked our QE to reproduce the issue with debug kernel, which may take a
> > while. And I can't trigger it in my box.
> >
> > BTW, for the 2nd 'kernel NULL pointer dereference', the RIP points to:
> >
> > (gdb) l *(__bfq_deactivate_entity+0x5b)
> > 0xffffffff814c31cb is in __bfq_deactivate_entity (block/bfq-wf2q.c:1181).
> > 1176           * bfq_group_set_parent has already been invoked for the group
> > 1177           * represented by entity. Therefore, the field
> > 1178           * entity->sched_data has been set, and we can safely use it.
> > 1179           */
> > 1180          st = bfq_entity_service_tree(entity);
> > 1181          is_in_service = entity == sd->in_service_entity;
> > 1182
> > 1183          bfq_calc_finish(entity, entity->service);
> > 1184
> > 1185          if (is_in_service)
> >
> > Seems entity->sched_data points to NULL.
>
> Hi Ming,
>
> Thanks for your report.
>
> Given the invalid pointer cannot explain line 1180, you are reporting
> a different issue from what Mike reported, and we can do nothing now
> for both without a reproducer.
>
> Dmitry can you shed some light on the tricks to config kasan to print
> Call Trace as the reports with the leading [syzbot] on the subject line do?

+kasan-dev

Hi Hillf,

KASAN prints stack traces always unconditionally. There is nothing you
need to do at all. Do you have any reports w/o stack traces?

"[syzbot]" is prepend by syzbot code. If you want some prefix, you
would need to prepend it manually.



> > > Thanks,
> > > Paolo
> > >
> > > > Il giorno 5 mar 2021, alle ore 10:27, Ming Lei <tom.leiming@gmail.com> ha scritto:
> > > >
> > > > Hello Hillf,
> > > >
> > > > Thanks for the debug patch.
> > > >
> > > > On Fri, Mar 5, 2021 at 5:00 PM Hillf Danton <hdanton@sina.com> wrote:
> > > >>
> > > >> On Thu, 4 Mar 2021 16:42:30 +0800  Ming Lei wrote:
> > > >>> On Sat, Oct 10, 2020 at 1:40 PM Mikhail Gavrilov
> > > >>> <mikhail.v.gavrilov@gmail.com> wrote:
> > > >>>>
> > > >>>> Paolo, Jens I am sorry for the noise.
> > > >>>> But today I hit the kernel panic and git blame said that you have
> > > >>>> created the file in which happened panic (this I saw from trace)
> > > >>>>
> > > >>>> $ /usr/src/kernels/`uname -r`/scripts/faddr2line
> > > >>>> /lib/debug/lib/modules/`uname -r`/vmlinux
> > > >>>> __bfq_deactivate_entity+0x15a
> > > >>>> __bfq_deactivate_entity+0x15a/0x240:
> > > >>>> bfq_gt at block/bfq-wf2q.c:20
> > > >>>> (inlined by) bfq_insert at block/bfq-wf2q.c:381
> > > >>>> (inlined by) bfq_idle_insert at block/bfq-wf2q.c:621
> > > >>>> (inlined by) __bfq_deactivate_entity at block/bfq-wf2q.c:1203
> > > >>>>
> > > >>>> https://github.com/torvalds/linux/blame/master/block/bfq-wf2q.c#L1203
> > > >>>>
> > > >>>> $ head /sys/block/*/queue/scheduler
> > > >>>> ==> /sys/block/nvme0n1/queue/scheduler <==
> > > >>>> [none] mq-deadline kyber bfq
> > > >>>>
> > > >>>> ==> /sys/block/sda/queue/scheduler <==
> > > >>>> mq-deadline kyber [bfq] none
> > > >>>>
> > > >>>> ==> /sys/block/zram0/queue/scheduler <==
> > > >>>> none
> > > >>>>
> > > >>>> Trace:
> > > >>>> general protection fault, probably for non-canonical address
> > > >>>> 0x46b1b0f0d8856e4a: 0000 [#1] SMP NOPTI
> > > >>>> CPU: 27 PID: 1018 Comm: kworker/27:1H Tainted: G        W
> > > >>>> --------- ---  5.9.0-0.rc8.28.fc34.x86_64 #1
> > > >>>> Hardware name: System manufacturer System Product Name/ROG STRIX
> > > >>>> X570-I GAMING, BIOS 2606 08/13/2020
> > > >>>> Workqueue: kblockd blk_mq_run_work_fn
> > > >>>> RIP: 0010:__bfq_deactivate_entity+0x15a/0x240
> > > >>>> Code: 48 2b 41 28 48 85 c0 7e 05 49 89 5c 24 18 49 8b 44 24 08 4d 8d
> > > >>>> 74 24 08 48 85 c0 0f 84 d6 00 00 00 48 8b 7b 28 eb 03 48 89 c8 <48> 8b
> > > >>>> 48 28 48 8d 70 10 48 8d 50 08 48 29 f9 48 85 c9 48 0f 4f d6
> > > >>>> RSP: 0018:ffffadf6c0c6fc00 EFLAGS: 00010002
> > > >>>> RAX: 46b1b0f0d8856e4a RBX: ffff8dc2773b5c88 RCX: 46b1b0f0d8856e4a
> > > >>>> RDX: ffff8dc7d02ed0a0 RSI: ffff8dc7d02ed0a8 RDI: 0000584e64e96beb
> > > >>>> RBP: ffff8dc2773b5c00 R08: ffff8dc9054cb938 R09: 0000000000000000
> > > >>>> R10: 0000000000000018 R11: 0000000000000018 R12: ffff8dc904927150
> > > >>>> R13: 0000000000000001 R14: ffff8dc904927158 R15: ffff8dc2773b5c88
> > > >>>> FS:  0000000000000000(0000) GS:ffff8dc90e0c0000(0000) knlGS:0000000000000000
> > > >>>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > > >>>> CR2: 0000003e8ebe4000 CR3: 00000007c2546000 CR4: 0000000000350ee0
> > > >>>> Call Trace:
> > > >>>> bfq_deactivate_entity+0x4f/0xc0
> > > >>>
> > > >>> Hello,
> > > >>>
> > > >>> The same stack trace was observed in RH internal test too, and kernel
> > > >>> is 5.11.0-0.rc6,
> > > >>> but there isn't reproducer yet.
> > > >>>
> > > >>>
> > > >>> --
> > > >>> Ming Lei
> > > >>
> > > >> Add some debug info.
> > > >>
> > > >> --- x/block/bfq-wf2q.c
> > > >> +++ y/block/bfq-wf2q.c
> > > >> @@ -647,8 +647,10 @@ static void bfq_forget_entity(struct bfq
> > > >>
> > > >>        entity->on_st_or_in_serv = false;
> > > >>        st->wsum -= entity->weight;
> > > >> -       if (bfqq && !is_in_service)
> > > >> +       if (bfqq && !is_in_service) {
> > > >> +               WARN_ON(entity->tree != NULL);
> > > >>                bfq_put_queue(bfqq);
> > > >> +       }
> > > >> }
> > > >>
> > > >> /**
> > > >> @@ -1631,6 +1633,7 @@ bool __bfq_bfqd_reset_in_service(struct
> > > >>                 * bfqq gets freed here.
> > > >>                 */
> > > >>                int ref = in_serv_bfqq->ref;
> > > >> +               WARN_ON(in_serv_entity->tree != NULL);
> > > >>                bfq_put_queue(in_serv_bfqq);
> > > >>                if (ref == 1)
> > > >>                        return true;
> > > >
> > > > This kernel oops isn't easy to be reproduced, and  we have got another crash
> > > > report[1] too, still on __bfq_deactivate_entity(), and not easy to
> > > > trigger.  Can your
> > > > debug patch cover the report[1]? If not, feel free to add more debug messages,
> > > > then I will try to reproduce the two.
> > > >
> > > > [1] another kernel oops log on __bfq_deactivate_entity
> > > >
> > > > [  899.790606] systemd-sysv-generator[25205]: SysV service
> > > > '/etc/rc.d/init.d/anamon' lacks a native systemd unit file.
> > > > Automatically generating a unit file for compatibility. Please update
> > > > package to include a native systemd unit file, in order to make it
> > > > more safe and robust.
> > > > [  901.937047] BUG: kernel NULL pointer dereference, address: 0000000000000000
> > > > [  901.944005] #PF: supervisor read access in kernel mode
> > > > [  901.949143] #PF: error_code(0x0000) - not-present page
> > > > [  901.954285] PGD 0 P4D 0
> > > > [  901.956824] Oops: 0000 [#1] SMP NOPTI
> > > > [  901.960490] CPU: 13 PID: 22966 Comm: kworker/13:0 Tainted: G
> > > >  I    X --------- ---  5.11.0-1.el9.x86_64 #1
> > > > [  901.970829] Hardware name: Dell Inc. PowerEdge R740xd/0WXD1Y, BIOS
> > > > 2.5.4 01/13/2020
> > > > [  901.978480] Workqueue: cgwb_release cgwb_release_workfn
> > > > [  901.983705] RIP: 0010:__bfq_deactivate_entity+0x5b/0x240
> > > > [  901.989016] Code: b8 30 00 00 00 75 18 48 81 ff 88 00 00 00 74 0f
> > > > 0f b7 47 8a 83 e8 01 48 8d 04 40 48 c1 e0 04 4c 8b 73 68 48 63 73 40
> > > > 48 89 df <4d> 8b 3e 4d 8d 64 06 10 e8 48 f0 ff ff 49 39 df 0f 84 87 01
> > > > 00 00
> > > > [  902.007763] RSP: 0018:ffffb77107f0bd98 EFLAGS: 00010002
> > > > [  902.012986] RAX: 0000002fffffffd0 RBX: ffff9853ca9c6098 RCX: 0000000000000046
> > > > [  902.020119] RDX: 0000000000000001 RSI: 00000000474b1168 RDI: ffff9853ca9c6098
> > > > [  902.027253] RBP: 0000000000000000 R08: 0000000000000000 R09: ffff985470c2fed0
> > > > [  902.034383] R10: 0000000000000001 R11: ffff9853c9287d98 R12: ffff9853ca8b8000
> > > > [  902.041515] R13: 00000000000000ff R14: 0000000000000000 R15: ffff985b44308098
> > > > [  902.048647] FS:  0000000000000000(0000) GS:ffff98631f980000(0000)
> > > > knlGS:0000000000000000
> > > > [  902.056732] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > > > [  902.062479] CR2: 0000000000000000 CR3: 00000001c0ac2002 CR4: 00000000007706e0
> > > > [  902.069611] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> > > > [  902.076744] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> > > > [  902.083876] PKRU: 55555554
> > > > [  902.086589] Call Trace:
> > > > [  902.089042]  bfq_pd_offline+0x89/0xd0
> > > > [  902.092708]  blkg_destroy+0x52/0xf0
> > > > [  902.096200]  blkcg_destroy_blkgs+0x46/0xc0
> > > > [  902.100300]  cgwb_release_workfn+0xbe/0x150
> > > > [  902.104485]  process_one_work+0x1e6/0x380
> > > > [  902.108497]  worker_thread+0x53/0x3d0
> > > > [  902.112161]  ? process_one_work+0x380/0x380
> > > > [  902.116346]  kthread+0x11b/0x140
> > > > [  902.119581]  ? kthread_associate_blkcg+0xa0/0xa0
> > > > [  902.124199]  ret_from_fork+0x1f/0x30
> > > > [  902.127780] Modules linked in: sunrpc scsi_debug iscsi_tcp
> > > > libiscsi_tcp libiscsi scsi_transport_iscsi nft_reject_inet
> > > > nf_reject_ipv4 nf_reject_ipv6 nft_reject nft_ct nft_chain_nat nf_nat
> > > > nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 ip_set nf_tables nfnetlink
> > > > rfkill intel_rapl_msr intel_rapl_common isst_if_common skx_edac nfit
> > > > libnvdimm x86_pkg_temp_thermal intel_powerclamp coretemp kvm_intel kvm
> > > > ipmi_ssif irqbypass mgag200 rapl i2c_algo_bit iTCO_wdt drm_kms_helper
> > > > intel_cstate iTCO_vendor_support syscopyarea sysfillrect sysimgblt
> > > > acpi_ipmi mei_me fb_sys_fops intel_uncore pcspkr dell_smbios dcdbas
> > > > dell_wmi_descriptor wmi_bmof mei cec i2c_i801 ipmi_si acpi_power_meter
> > > > lpc_ich i2c_smbus ipmi_devintf ipmi_msghandler drm fuse xfs libcrc32c
> > > > sd_mod t10_pi crct10dif_pclmul crc32_pclmul crc32c_intel ahci libahci
> > > > megaraid_sas tg3 ghash_clmulni_intel libata wmi dm_mirror
> > > > dm_region_hash dm_log dm_mod [last unloaded: ip_tables]
> > > > [  902.208546] CR2: 0000000000000000
> > > > [  902.211881] ---[ end trace 827b8521dc634ca4 ]---
> > > >
> > > >
> > > > --
> > > > Ming Lei
> > >
> >
> > --
> > Ming
> >
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaLnam%2B7FGx9MiMRRbgFE6v%2BVg6Hu0hkx%2BP%3Dh%2BDL8Mayg%40mail.gmail.com.
