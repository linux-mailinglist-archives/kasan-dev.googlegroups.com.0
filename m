Return-Path: <kasan-dev+bncBCMIZB7QWENRBNGQSKBAMGQEGXHIJHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id DC611330010
	for <lists+kasan-dev@lfdr.de>; Sun,  7 Mar 2021 11:17:25 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id x197sf4706475pfc.18
        for <lists+kasan-dev@lfdr.de>; Sun, 07 Mar 2021 02:17:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615112244; cv=pass;
        d=google.com; s=arc-20160816;
        b=ILundf/QtsE5rU5lqePg44vZtCSF+5DOVYsvZ+QUNZqezOrjZtBU3InYF0HkBS1UhB
         Oxfx8rYELOfETC7ZjsISEVFp2QtS/VZ0xxZ2z3sxTZ5j9GDRg5mU/Jn4FQazDrl5yVQA
         d2d7UWIcaGV74ljN/G7hbTz9UP5Kpl+GqIxCxXDAWNjt7L2YKXaJ7pVqXDCL5tzJHzSW
         l9F1kOPuBCi9uOjO8/hDJI3T8laLRxzlLA1uoWZYEPAHuwgT9bdkp2wMrVrHau/0ic8B
         fqgJEfETYx36pz0TqYBTPtGhoYyMNi5M5tj+++b0bn0GQ55CFKUuED4RwdoiZbFJYoey
         n9rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=usvfbA/YOqT6xAU2+fexdULtmRqSkUGajnJnxIKl8Y8=;
        b=KuObolWESHdkRw8uf8P/1dhYkr9vAprKkFK/byY93bLzNpgjEVz2pk8+nEyp+1guh7
         Iulj0eCJcFips4I42CxNkKEDJHDydg8VNxSgyEPsMEw4S4mX8+ImOZ02qD9B4ZqUgULo
         g1BHuChjxJfAMyFDgis0/OOdiEE8X3mbzB/iJZ6zWsWd1nTrLcMWwNQmLLHd6tidBAAD
         PtPqpQPtL85LOf+7W0aKExuzEhzUgCUeY9vprnPTXdD/jvkg0p2KCttFnRhbVfgCvwmN
         oY9mev7ryR5jRCiKTyvu/kvGh6mMWp74PQokLFLbmLZmgLYI8xAJsPOCtBlyw2yqVUIE
         /Vtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FAhX+sQb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=usvfbA/YOqT6xAU2+fexdULtmRqSkUGajnJnxIKl8Y8=;
        b=Z2/6F8+NAI0m/m5ia+PAQfrIMRMlaGokzkbZSSJwA8aH5iUbZ1HWza1ADy4Tm+XX8J
         kOtY6OBFPNJmnLuayAfQk2uU7R5aKG/di0zqDVxM+WJaUXjROqoOKLi5tWk9PzSBYVjH
         FAo16zqXuWSxpESoDqMGkSxaYha6NxclMZijRePxfK7jIfU7P/FIPhmMc7DdkzppBHEK
         okX2Y9XWfG7xYDeFaw3q3tsIVxQLp1BIYU3wXxavjnJcuUPNim6cMfcI+0ukahDv6oZ1
         03qRsLPs6kzWyZBMTdQljS/vbzEjUTvCdEzeQeOBFQPVhKNFf6iw8EQP1rdZJ6WaYxuX
         adbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=usvfbA/YOqT6xAU2+fexdULtmRqSkUGajnJnxIKl8Y8=;
        b=qA8Ms8kMu34FkI87HJb8dtdBwMBMzjB/PmNjbC+o2r0grQIHI0nqlz/4P7AKJ6UL2h
         eo678ie8lQXg+MKoem2J9J4WPVpSKMcWZ3Ksj9zzk4hksEdmIlYKlrlu07dD+OP2EdJD
         iJBfaNryX6ZsiT5Sr2tbWYoY98A5Qq4F4OyVcmQVdBcXg3oHlDdQhZKOFE+ZmWcwQVS/
         IIjLVTy6ItM0VFH/uDPnGcDcGYyq7PdDfoXFTov0CLyTShUJMW7aiIePcnaxwOxAeOFN
         HatT2BfynR1UQgLR5HKH0bpXGywD94he3GUlosykv5OJH8AmFGPpvytcO7rF8aPHmei1
         Jp/A==
X-Gm-Message-State: AOAM533qelKJGASIvnWP42Mp2hfU1rxr5vws/mNX6Nki1pPWNruRodh9
	YS6+x6/TFiyIFr0rwsYYQ5E=
X-Google-Smtp-Source: ABdhPJykt+NWiJk3DsjqxupipApJ1MTPkh405IrxtENvGE0jXswKhHgbXuFo3KvdBzn+yXxMET0kKQ==
X-Received: by 2002:a05:6a00:847:b029:1b3:b9c3:11fb with SMTP id q7-20020a056a000847b02901b3b9c311fbmr16673492pfk.44.1615112244612;
        Sun, 07 Mar 2021 02:17:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1057:: with SMTP id gq23ls6580478pjb.0.gmail; Sun,
 07 Mar 2021 02:17:24 -0800 (PST)
X-Received: by 2002:a17:902:c246:b029:e4:63a6:e8d2 with SMTP id 6-20020a170902c246b02900e463a6e8d2mr16125997plg.51.1615112244118;
        Sun, 07 Mar 2021 02:17:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615112244; cv=none;
        d=google.com; s=arc-20160816;
        b=UbBq/5zdL1gYWJEGV/GyTncK7Oc8nC61nud9heKNwSfDDS6GxydX6R6q5uqHumsjEV
         o9JkaMh1H9TtPoqKIo74t/dtS3MleQqLlwQA+Cx0o55ah7KuI1U215rrFsjokF0ZgI87
         +yZhtLk+Pj3j9/b9OFhCQ7hsv10URUkDoJleJHEz5xs79dQVp3qC6KX5wSzn2lf8fOJX
         b6qR/Nw6Utyx8fyZNrQElydSQxKaE8Q9Jfs0Mci1YZf0mePzHq04mHXQUL6N3/GrCyGn
         mRSgjWdLfTv0ssONU2KL+BS08+8hH+reUChghCc4BVJ7hnosGwZ7FnHOe0w66+Z0djzo
         rSug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Sel+nftChg+kM2jOw+J/2yqQU62BUDNfivprLpMSJls=;
        b=08ndBSvW3X3iMiFgtXt1rAXnsctjnHBI/yo20OX2Bjs33WySq1AYQxlgKpwFRjSGhf
         HIhJ9GGq/vpfw7CrOvfxPI1yPk0dvi+psNqh6Fq4/gtVFZAgsbJgkyPH9ancrWqaIw4q
         S6jf8Qg2Uy7sKsmvImv8XGECckdxTpPJu3SXdx9438lJX/DZsev7eDrbAnJMoJrWvXgP
         h6Fh2uENEDQde2+pE4OzQxrNRb4QStiu6fk3Te+hhqISGRXSX0AcAVcv6wEfzhl1DLsV
         U5Y+OuvudKpzSy7E4V33pbY5g/iT8hyuD2cNKCZ7+EsE/b1cCuLhhXdN/ApCv2Vsar8w
         R8ZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FAhX+sQb;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82d as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82d.google.com (mail-qt1-x82d.google.com. [2607:f8b0:4864:20::82d])
        by gmr-mx.google.com with ESMTPS id r23si379126pfr.6.2021.03.07.02.17.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 07 Mar 2021 02:17:24 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82d as permitted sender) client-ip=2607:f8b0:4864:20::82d;
Received: by mail-qt1-x82d.google.com with SMTP id t13so4036125qta.11
        for <kasan-dev@googlegroups.com>; Sun, 07 Mar 2021 02:17:24 -0800 (PST)
X-Received: by 2002:ac8:5847:: with SMTP id h7mr14323827qth.43.1615112243553;
 Sun, 07 Mar 2021 02:17:23 -0800 (PST)
MIME-Version: 1.0
References: <CABXGCsP63mN+G1xE7UBfVRuDRcJiRRC7EXU2y25f9rXkoU-0LQ@mail.gmail.com>
 <CACVXFVOy8928GNowCQRGQKQxuLtHn0V+pYk1kzeOyc0pyDvkjQ@mail.gmail.com>
 <20210305090022.1863-1-hdanton@sina.com> <CACVXFVPp_byzrYVwyo05u0v3zoPP42FKZhfWMb6GMBno1rCZRw@mail.gmail.com>
 <E28250BB-FBFF-4F02-B7A2-9530340E481E@linaro.org> <YEIBYLnAqdueErun@T590>
 <20210307021524.13260-1-hdanton@sina.com> <CACT4Y+aLnam+7FGx9MiMRRbgFE6v+Vg6Hu0hkx+P=h+DL8Mayg@mail.gmail.com>
 <20210307100900.13768-1-hdanton@sina.com>
In-Reply-To: <20210307100900.13768-1-hdanton@sina.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sun, 7 Mar 2021 11:17:12 +0100
Message-ID: <CACT4Y+aT0BySK8RVv5tC1pQDPg-7Z_DRToNH7vE7_5pQkqcs1g@mail.gmail.com>
Subject: Re: [bugreport 5.9-rc8] general protection fault in __bfq_deactivate_entity
To: Hillf Danton <hdanton@sina.com>
Cc: Ming Lei <ming.lei@redhat.com>, Paolo Valente <paolo.valente@linaro.org>, 
	Ming Lei <tom.leiming@gmail.com>, Mikhail Gavrilov <mikhail.v.gavrilov@gmail.com>, 
	Palash Oswal <oswalpalash@gmail.com>, linux-block <linux-block@vger.kernel.org>, 
	Jens Axboe <axboe@fb.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FAhX+sQb;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82d
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

On Sun, Mar 7, 2021 at 11:09 AM Hillf Danton <hdanton@sina.com> wrote:
>
> On Sun, 7 Mar 2021 08:46:19 +0100  Dmitry Vyukov wrote:
> > On Sun, Mar 7, 2021 at 3:15 AM Hillf Danton <hdanton@sina.com> wrote:
> > >
> > > Dmitry can you shed some light on the tricks to config kasan to print
> > > Call Trace as the reports with the leading [syzbot] on the subject line do?
> >
> > +kasan-dev
> >
> > Hi Hillf,
> >
> > KASAN prints stack traces always unconditionally. There is nothing you
> > need to do at all.
>
> Got it, thanks.
>
> > Do you have any reports w/o stack traces?
>
> No, but I saw different formats in Call Trace prints.
>
> Below from [1] is the instance without file name and line number printed,
> while both info help spot the cause of the reported issue.


KASAN always prints stack traces w/o file:line info, like any other
kernel bug detection facility. Kernel itself never symbolizes reports.
In case of syzkaller, syzkaller will symbolize reports and add
file:line info. The main config it requires is CONFIG_DEBUG_INFO.

You may see syzkaller kernel configuration guide here:
https://github.com/google/syzkaller/blob/master/docs/linux/kernel_configs.md

Or fragments that are actually used to generate syzbot configs in this
dir (the guide above may be out-of-date):
https://github.com/google/syzkaller/blob/master/dashboard/config/linux/bits/base.yml
https://github.com/google/syzkaller/blob/master/dashboard/config/linux/bits/debug.yml
https://github.com/google/syzkaller/blob/master/dashboard/config/linux/bits/kasan.yml

Or a complete syzbot config here:
https://github.com/google/syzkaller/blob/master/dashboard/config/linux/upstream-apparmor-kasan.config


> >>>>>>>>>>>>>>>>>>>>>>>>>
>
> I was running syzkaller and I found the following issue :
>
> Head Commit : b1313fe517ca3703119dcc99ef3bbf75ab42bcfb ( v5.10.4 )
> Git Tree : stable
> Console Output :
> [  242.769080] INFO: task repro:2639 blocked for more than 120 seconds.
> [  242.769096]       Not tainted 5.10.4 #8
> [  242.769103] "echo 0 > /proc/sys/kernel/hung_task_timeout_secs"
> disables this message.
> [  242.769112] task:repro           state:D stack:    0 pid: 2639
> ppid:  2638 flags:0x00000004
> [  242.769126] Call Trace:
> [  242.769148]  __schedule+0x28d/0x7e0
> [  242.769162]  ? __percpu_counter_sum+0x75/0x90
> [  242.769175]  schedule+0x4f/0xc0
> [  242.769187]  __io_uring_task_cancel+0xad/0xf0
> [  242.769198]  ? wait_woken+0x80/0x80
> [  242.769210]  bprm_execve+0x67/0x8a0
> [  242.769223]  do_execveat_common+0x1d2/0x220
> [  242.769235]  __x64_sys_execveat+0x5d/0x70
> [  242.769249]  do_syscall_64+0x38/0x90
> [  242.769260]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
>
> [1] https://lore.kernel.org/lkml/CAGyP=7cFM6BJE7X2PN9YUptQgt5uQYwM4aVmOiVayQPJg1pqaA@mail.gmail.com/

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaT0BySK8RVv5tC1pQDPg-7Z_DRToNH7vE7_5pQkqcs1g%40mail.gmail.com.
