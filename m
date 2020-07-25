Return-Path: <kasan-dev+bncBC7OBJGL2MHBBJE26H4AKGQEIVBYXPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id E175F22D868
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 17:17:57 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id j207sf8362697ybg.20
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Jul 2020 08:17:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1595690276; cv=pass;
        d=google.com; s=arc-20160816;
        b=QFtWPpbHCER42wTXzs2prnfgkwCAvRX+QgwFxs8JBsP3q0KH0stX4OTHadRELIPqX1
         JzZPDzJEKzhA8O05X/AwQfKtv9UV2u8nVg/xgZ6pNQKMpcuIYpArOLJ284F3bnGgq7LH
         12LAcsgOyMRRBT31IfIQRxwZxNivo7ZmkX+VbMJckOEAOhFc8Jt7XKTqZavG9j/mzSCk
         2JL6gGyqABSx9bpVqqqgQPaRQTyZ2539trIIPgdjlmO+WCZ/dMMtdhtmUrV14kLlWXoV
         aJQ+g4vJFjlbkDg3EJ7bgFJygrZm+Cj5ZfjkJq3VY5IwLeaf53dVyOd91FLPR9II2EtO
         3wXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xqLsV3gjK/ymEZ7+7rNA5ELY/0GkkHqe36BR6zuS1QA=;
        b=o2jQXyoAIZcV4uxdBiYOfAQ5ydzjeEbfsOsetYCBGBiwUpaRporL//WHsLu8lbdqr5
         nbZ7u63DjUq/gvX2DE2n7EuUKqppqW7drNCAdFrH/S62TDfPSteRgGk6Nz67nHG30SxP
         KlE3mhaFtsW9dboS7l7y8dg5kFsLqV4C5xBB65b1wNcC8+Dft8McmuG0wKGP2JEQCmeH
         9XsqH9pbskVnX3LKAXHe0hWpJN+DeC0XHjwtCH8kj+pJG9CdqyHSnwMT7hsCIG4RluKo
         H1ANUSK8ES0NXuRxqIXQsdlUzPGqzb5yAs2YZgQd2gSPWykUqSj4bR5P9oMm4BgLgKK0
         X+Tw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iuCaR7FL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xqLsV3gjK/ymEZ7+7rNA5ELY/0GkkHqe36BR6zuS1QA=;
        b=YeDGt9u7/Qa1JTMHI7VLGspPFmfKg21l+r+SWs60ZcOmyavkr0UnrQTwNZHl6AMZHq
         kaZHAxrGjnwjhBSQetpjdZcSmBuTskgirRLohtyFbqDchWL9rxFhjlwCY/sYPk/aL9Rz
         F8pq88ftiP1xJd5jB7881JbWuYJzSDdaGUIvxIOqVilPKZh4MG/vhBn6tEJORxCscj7D
         XeiyWSsRMAdRYxvN45ciYHBCxJ/IfFvUb85hT3jutG7kO3GLSvdWUV477AG/Z+xGIZSa
         Dgvh+az/E4GKPPLi+xykPx8LZuDf9gqw4IfcDok0OujPwT4YI61tLsBbQDYrjpeeinMN
         W2yg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xqLsV3gjK/ymEZ7+7rNA5ELY/0GkkHqe36BR6zuS1QA=;
        b=KmfUHxRGzDRbmBRFuMuczzN2NkNAVBoJS6rAfj7DiLMMYTeOj+WrTgYpuTCzkhq2d+
         ixhWs5pD3K52iGLwtOWHTTQ4vffe+fkuSksPh5uBC5LwbXVyoXwhljpd4G8gj3vcufbX
         o13HFwj57WrRswny/ouLdGLMs/H2vU2ZwORHYPLu2Yxof1bACRW9XGbcaEQjjynzHFLB
         sPJBacW3ls2jCMu+FWIlCm/o1r0CTe4osZUpewXSlTCP6u8DtJOCkOT8ObAvACZJxWMG
         WDppXRbJGCA3Pvowali/OqlLU4QOslA5HStp8gEI2t/bQpHaw7R7A08iGBk0N0JUxWu0
         Imjg==
X-Gm-Message-State: AOAM530r1bDzEC6KpbRKnC1lI/YJVmcofKLc5fv2vMmmu6GewuWdSN5h
	5rQMBFSivBsgMrtXceHTDWE=
X-Google-Smtp-Source: ABdhPJxUW24uZ4+YDLvHNcEWcgIpSVfqXDTKqkqAm/zs6nTT5GnxtvoNrpNkfG2g8YQKANYRDLJBIA==
X-Received: by 2002:a25:a104:: with SMTP id z4mr24324697ybh.40.1595690276714;
        Sat, 25 Jul 2020 08:17:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3812:: with SMTP id f18ls3168478yba.6.gmail; Sat, 25 Jul
 2020 08:17:56 -0700 (PDT)
X-Received: by 2002:a5b:449:: with SMTP id s9mr11569795ybp.465.1595690276130;
        Sat, 25 Jul 2020 08:17:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1595690276; cv=none;
        d=google.com; s=arc-20160816;
        b=szClmPzfUGK6opPDVjlUgDLmxTy7qqKKazHP7D5oBxkuH2KM4zPr/bZGhSY7xPSwsa
         CNNpxE0lIZW2Uk9pcq74lUzmp69cLvbB1tfDTdS8Y7yl1Sal03Lt5Wsvj8c/Thpc0ypk
         vocQWzfDA7iZalOApagdCay6cS/MdXJ1Aqc9jHIGxW8thEif16nmp/C9CEe7BNK9rdcb
         7Rhoz1K9xWT6x9o/l8PEv//M6F/jQ/Uu+Emn24nwDtA5muflqg/T+qYZacq0dqSCJOt9
         imkO6UMrjdKSfIQ8AG5TE6rhfZMzpqmtRDwrHCPCzPpwyBjOPMen/PYnIuT0+c4rSHGc
         5Hxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ltOnyPTnPyHESFo1zHjbKU6HFj1ufxds9tDCUi8zQHY=;
        b=qRQ/KI4TAgBSm/b9zViI3IiUYu2RcM1V0eLwXQ2JSFNxKj7nT+Ib1fp3vee2jqsV0K
         44XHxYwB2mqR1eAzl6liDKDVBXALnyQmDAHOM5o21WYTaTGQDS7Z9Q4lCa09zvoE+Tn0
         RHqMBzVAv2aV92ckeITRjpZ0+hX68PP2DfDQlz4PdnObLM6X3iBA9qShU0NanstSSYs7
         uaLaN9wqT7UdsIkAG/MR99Br0gHJ2yxLRdnNHblQAAdGTjV9+wqMRAVCLKaMCIXsHyiW
         h717WHNUYvNZBC10mq1VJ07Vyv99oUjP99lO/XRJ+CDCluHriMbTtktVdiEqth3eKqOe
         zLXw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iuCaR7FL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id l10si218088ybt.5.2020.07.25.08.17.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 25 Jul 2020 08:17:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id h1so9178994otq.12
        for <kasan-dev@googlegroups.com>; Sat, 25 Jul 2020 08:17:56 -0700 (PDT)
X-Received: by 2002:a9d:4b01:: with SMTP id q1mr14243995otf.17.1595690275384;
 Sat, 25 Jul 2020 08:17:55 -0700 (PDT)
MIME-Version: 1.0
References: <20200220141551.166537-1-elver@google.com> <20200220185855.GY2935@paulmck-ThinkPad-P72>
 <20200220213317.GA35033@google.com> <20200725145623.GZ9247@paulmck-ThinkPad-P72>
In-Reply-To: <20200725145623.GZ9247@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 25 Jul 2020 17:17:43 +0200
Message-ID: <CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn+1TB99OF2Hv0S_A@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Add option to allow watcher interruptions
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Peter Zijlstra <peterz@infradead.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iuCaR7FL;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

[+Peter]

On Sat, 25 Jul 2020 at 16:56, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> On Thu, Feb 20, 2020 at 10:33:17PM +0100, Marco Elver wrote:
> > On Thu, 20 Feb 2020, Paul E. McKenney wrote:
>
> I am clearly not keeping up...  :-/

Not to worry, I think the local_t idea was discarded based on Peter's
feedback anyway at one point.

> > > On Thu, Feb 20, 2020 at 03:15:51PM +0100, Marco Elver wrote:
> > > > Add option to allow interrupts while a watchpoint is set up. This can be
> > > > enabled either via CONFIG_KCSAN_INTERRUPT_WATCHER or via the boot
> > > > parameter 'kcsan.interrupt_watcher=1'.
[...]
> > > > As an example, the first data race that this found:
> > > >
> > > > write to 0xffff88806b3324b8 of 4 bytes by interrupt on cpu 0:
> > > >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]
> > > >  __rcu_read_lock+0x3c/0x50 kernel/rcu/tree_plugin.h:373
[...]
> > > > read to 0xffff88806b3324b8 of 4 bytes by task 6131 on cpu 0:       |
> > > >  rcu_preempt_read_enter kernel/rcu/tree_plugin.h:353 [inline]  ----+
[...]
> > > >
> > > > The writer is doing 'current->rcu_read_lock_nesting++'. The read is as
> > > > vulnerable to compiler optimizations and would therefore conclude this
> > > > is a valid data race.
> > >
> > > Heh!  That one is a fun one!  It is on a very hot fastpath.  READ_ONCE()
> > > and WRITE_ONCE() are likely to be measurable at the system level.
> > >
> > > Thoughts on other options?
> >
> > Would this be a use-case for local_t? Don't think this_cpu ops work
> > here.
> >
> > See below idea. This would avoid the data race (KCSAN stopped
> > complaining) and seems to generate reasonable code.
> >
> > Version before:
> >
> >  <__rcu_read_lock>:
> >      130      mov    %gs:0x0,%rax
> >      137
> >      139      addl   $0x1,0x370(%rax)
> >      140      retq
> >      141      data16 nopw %cs:0x0(%rax,%rax,1)
> >      148
> >      14c      nopl   0x0(%rax)
> >
> > Version after:
> >
> >  <__rcu_read_lock>:
> >      130      mov    %gs:0x0,%rax
> >      137
> >      139      incq   0x370(%rax)
> >      140      retq
> >      141      data16 nopw %cs:0x0(%rax,%rax,1)
> >      148
> >      14c      nopl   0x0(%rax)
> >
> > I haven't checked the other places where it is used, though.
> > (Can send it as a patch if you think this might work.)
> >
> > Thanks,
> > -- Marco
> >
> > diff --git a/include/linux/rcupdate.h b/include/linux/rcupdate.h
> > index 2678a37c31696..3d8586ee7ae64 100644
> > --- a/include/linux/rcupdate.h
> > +++ b/include/linux/rcupdate.h
> > @@ -50,7 +50,7 @@ void __rcu_read_unlock(void);
> >   * nesting depth, but makes sense only if CONFIG_PREEMPT_RCU -- in other
> >   * types of kernel builds, the rcu_read_lock() nesting depth is unknowable.
> >   */
> > -#define rcu_preempt_depth() (current->rcu_read_lock_nesting)
> > +#define rcu_preempt_depth() local_read(&current->rcu_read_lock_nesting)
> >
> >  #else /* #ifdef CONFIG_PREEMPT_RCU */
> >
> > diff --git a/include/linux/sched.h b/include/linux/sched.h
> > index 0918904c939d2..70d7e3257feed 100644
> > --- a/include/linux/sched.h
> > +++ b/include/linux/sched.h
> > @@ -10,6 +10,7 @@
> >  #include <uapi/linux/sched.h>
> >
> >  #include <asm/current.h>
> > +#include <asm/local.h>
> >
> >  #include <linux/pid.h>
> >  #include <linux/sem.h>
> > @@ -708,7 +709,7 @@ struct task_struct {
> >       cpumask_t                       cpus_mask;
> >
> >  #ifdef CONFIG_PREEMPT_RCU
> > -     int                             rcu_read_lock_nesting;
> > +     local_t                         rcu_read_lock_nesting;
> >       union rcu_special               rcu_read_unlock_special;
> >       struct list_head                rcu_node_entry;
> >       struct rcu_node                 *rcu_blocked_node;
> > diff --git a/init/init_task.c b/init/init_task.c
> > index 096191d177d5c..941777fce11e5 100644
> > --- a/init/init_task.c
> > +++ b/init/init_task.c
> > @@ -130,7 +130,7 @@ struct task_struct init_task
> >       .perf_event_list = LIST_HEAD_INIT(init_task.perf_event_list),
> >  #endif
> >  #ifdef CONFIG_PREEMPT_RCU
> > -     .rcu_read_lock_nesting = 0,
> > +     .rcu_read_lock_nesting = LOCAL_INIT(0),
> >       .rcu_read_unlock_special.s = 0,
> >       .rcu_node_entry = LIST_HEAD_INIT(init_task.rcu_node_entry),
> >       .rcu_blocked_node = NULL,
> > diff --git a/kernel/fork.c b/kernel/fork.c
> > index 60a1295f43843..43af326081b06 100644
> > --- a/kernel/fork.c
> > +++ b/kernel/fork.c
> > @@ -1669,7 +1669,7 @@ init_task_pid(struct task_struct *task, enum pid_type type, struct pid *pid)
> >  static inline void rcu_copy_process(struct task_struct *p)
> >  {
> >  #ifdef CONFIG_PREEMPT_RCU
> > -     p->rcu_read_lock_nesting = 0;
> > +     local_set(&p->rcu_read_lock_nesting, 0);
> >       p->rcu_read_unlock_special.s = 0;
> >       p->rcu_blocked_node = NULL;
> >       INIT_LIST_HEAD(&p->rcu_node_entry);
> > diff --git a/kernel/rcu/tree_plugin.h b/kernel/rcu/tree_plugin.h
> > index c6ea81cd41890..e0595abd50c0f 100644
> > --- a/kernel/rcu/tree_plugin.h
> > +++ b/kernel/rcu/tree_plugin.h
> > @@ -350,17 +350,17 @@ static int rcu_preempt_blocked_readers_cgp(struct rcu_node *rnp)
> >
> >  static void rcu_preempt_read_enter(void)
> >  {
> > -     current->rcu_read_lock_nesting++;
> > +     local_inc(&current->rcu_read_lock_nesting);
> >  }
> >
> >  static void rcu_preempt_read_exit(void)
> >  {
> > -     current->rcu_read_lock_nesting--;
> > +     local_dec(&current->rcu_read_lock_nesting);
> >  }
> >
> >  static void rcu_preempt_depth_set(int val)
> >  {
> > -     current->rcu_read_lock_nesting = val;
> > +     local_set(&current->rcu_read_lock_nesting, val);

> I agree that this removes the data races, and that the code for x86 is
> quite nice, but aren't rcu_read_lock() and rcu_read_unlock() going to
> have heavyweight atomic operations on many CPUs?
>
> Maybe I am stuck with arch-specific code in rcu_read_lock() and
> rcu_preempt_read_exit().  I suppose worse things could happen.

Peter also mentioned to me that while local_t on x86 generates
reasonable code, on other architectures it's terrible. So I think
something else is needed, and feel free to discard the above idea.
With sufficient enough reasoning, how bad would a 'data_race(..)' be?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPhuvrhRHAiuv2Zju1VNSe7dO0aaYn%2B1TB99OF2Hv0S_A%40mail.gmail.com.
