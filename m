Return-Path: <kasan-dev+bncBDGPTM5BQUDRBFOWXSBAMGQE6UTKWHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 78F7D33AEEC
	for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 10:38:30 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id t14sf11655794oic.18
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 02:38:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615801109; cv=pass;
        d=google.com; s=arc-20160816;
        b=zqt2+zcfYEHLA9rRbaPDSIQDP9HlVCNBboK9Z6Wj0aXK6huGniiDcSmxNtwMmIcAv+
         YCg22nv/Gf10C28oOJu7pMVmObTRMbMMUxN97w2lwWBOsEeNQJK3MBlCqeXPgPpLtThD
         uxMFspQHOBUnH6vH8hk7We5Lqxgx/pJoxE+ke/Jwo3NVK2B5/yGm3V8Hj6ePLxujd90z
         fkFXhNIFwfKoY3JNZiXCYj+SqQx1bYdncVajHitsumeigJjbhfrjFb5K08xN7zgyd4ZL
         tEXcvCpLtc/lfBdKf4QGZAOEJcMlzcBY4j135kd7Yk0b2uYZDEHDXRjuv7MeWM3cdUcY
         Omew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:dkim-signature;
        bh=FIrIzP28VNKkLEcMoTk2NSsjc8JFNFtt9CIXPdIzcb8=;
        b=S+gclBNCeOaYsIUSYqfa2Xj008CyoZKU9uUpZfzRDBO291aWXOt2KNfBioENP2/Czb
         1hv03mjXpeUI8iijEFi3SDLV5nauqy6hIOG0rSS9dNcvAgAGSdRa9dhMwdkwLzQAWFEh
         aquyGsZlCVxMba4CojrRBNLXuXmHmT4D2bqNx0VJPq4US42Wg4RVe7npMgRYAdRdEXKx
         9m79Uy2i86W07d+cMaFvTW4aiv+g9uhVE0JaL2CxSXxObiLOH4Ccr1hiRlGH5sWYDPu6
         4qhULxNcv/+k9Xd++fVCOgyeRj19n8m2qpCoGWAR0elF/x5C8sQVu3TNE5Y87uC6JyY2
         e+Ow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="D8SU/ZVB";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:message-id:subject:from:to:cc:date:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FIrIzP28VNKkLEcMoTk2NSsjc8JFNFtt9CIXPdIzcb8=;
        b=jyLmvOkXlbdy7cwx3hyQl83LxPBeMdYq/6mVX1tlAPEpwCxl0w8EezyaiFMtZkfOP7
         ZogHAk0I/SnDLuEtF9CedYuT7agsUh21ReonkPHZcMzqX8qXCC+Nb/AgpiSgipl4Ucqe
         R0QmTGU6j3hkF+bNxHGtYo5yEvBgAsl0zwpuH4qhaiqnC7A0htgKhOz43/IGIbC3n03/
         g2qxgJizVrsVODOBpZdihozSXZ9dl12f+yvErK+FP9moJ0iHkygqdMBcaFtIszLpUnAl
         UP9JWlTYiTnBsMSuIiNsXZxFyWTEFatfTuXT6SNC89KMyQBlYza2SYjYq3NbBpTiUAip
         gclg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:message-id:subject:from:to:cc:date
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FIrIzP28VNKkLEcMoTk2NSsjc8JFNFtt9CIXPdIzcb8=;
        b=DSE8axtFourfd1WTs+aKys0f9PYOmjmf8+A2ral00NVtBgvwRydrJh5TaQhLHrWTF/
         gunCdfofv88hVdoiFWZXL7Ps4BdUN8BpwSRKKXh9Q8WddB7LzPjUTsVKnXxCQXNW0lD8
         Kz/mZ8U8XgGrZ4DzRFT15BZn+X2s1ueH4XNU5xuCWMwE32N59u8u/3s9o5WTy76FQp3q
         PYwSUTDNTJzMcNa64IqDax6/NhVCMP7sDSeCqAmE+nowsmAx39kjLO6OdY97gdlmD4IG
         svNdyDBWZgfGqJJicrQDLOcg/hP9JP81UwNvGTuPikAuZqjlpt5vpflev0V21D/eM2c+
         m6gA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532+ZsJ6yTp4IPEj6U1nOpL1G5p4bQGaohMzhz4mBj2DBYyEnHJ3
	DXUpv/vHgg5iJZICoRa4o3s=
X-Google-Smtp-Source: ABdhPJxev1HkRccDlnuemfko1lSbXkrmym9l54e0FqyfcQdb5WvVZkWkITqtAGRHUYckQhAHJU7V6Q==
X-Received: by 2002:a9d:4587:: with SMTP id x7mr13554310ote.274.1615801109338;
        Mon, 15 Mar 2021 02:38:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:12f2:: with SMTP id g105ls4114541otg.6.gmail; Mon, 15
 Mar 2021 02:38:28 -0700 (PDT)
X-Received: by 2002:a9d:7617:: with SMTP id k23mr12884217otl.142.1615801108757;
        Mon, 15 Mar 2021 02:38:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615801108; cv=none;
        d=google.com; s=arc-20160816;
        b=YkXmV18J/6ypWcsbf/vlLU7oKMI7reMd08ymq49uwuTByCNn0t7PD7mYKnxoxhZtqv
         kO1HyFnwcfwQl0FZkEA0K0n2ZIdddW21W0+Xz/DpDoBE0a+jdgU6p364Jv4i+Egb59Xw
         I1oAGzZHTp3UVNAooqurm5i0DvhJ+8diyTh52zfMzUeiw1sQOtadVh0k4qpmzZIwzPuy
         ExOOiT4cFKBw8yAcFN6WjQQMMtAq9eXVKMJRjoecQjyri2gaOHOjzmBLskg/bdtOurOn
         VnIMMyYp+fMRWq3ZqBJ1rZBQPsqCEkAP7kZtz9NUG0GL9xfy4dsqHXQc9qZ7fSFr3+Gh
         VMHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to:date
         :cc:to:from:subject:message-id:dkim-signature;
        bh=bPuVjFo6Jbk+asJxO6pPeVmiKh3ForgwpqM3f8bjyIU=;
        b=rYKzV14/uqP4H0/f32NJxMjhWrJjNUBtW4PtbJMrA7oZVWfVVgYpBvLnD2AAZTnXzp
         7sA8ouepj5DjedHXaOKKoUV/lA2kF3X/skaSNDWOSuT7ghWkUfU5RP2Il9ltC8tXq8AW
         12EctChN7xc6N8A0/jFKLcBSiuo1v/T2h7toXCZf0AchJ+i7rrQoYmhkO2x0kGsBmjqU
         ydgWtyM6PCSBDAu+TB52xaZQCn/yJedbQz4Yq6itVhhJo0Pltr3OYn0QaFqndL5uz5Az
         FQs0z9tnpsS72aQbDk2prhln4AB8eb6H4wdFbtLcZLTmhxNpcCYfaLcYLqlsMN4dubkQ
         1Shg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="D8SU/ZVB";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw02.mediatek.com ([210.61.82.184])
        by gmr-mx.google.com with ESMTP id h5si1014678otk.1.2021.03.15.02.38.27
        for <kasan-dev@googlegroups.com>;
        Mon, 15 Mar 2021 02:38:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as permitted sender) client-ip=210.61.82.184;
X-UUID: 477c428a4827495a83b913091db26065-20210315
X-UUID: 477c428a4827495a83b913091db26065-20210315
Received: from mtkcas06.mediatek.inc [(172.21.101.30)] by mailgw02.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.14 Build 0819 with TLSv1.2 ECDHE-RSA-AES256-SHA384 256/256)
	with ESMTP id 1031721851; Mon, 15 Mar 2021 17:38:24 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 15 Mar 2021 17:38:22 +0800
Received: from [172.21.84.99] (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 15 Mar 2021 17:38:22 +0800
Message-ID: <1615801102.24887.4.camel@mtksdccf07>
Subject: Re: [PATCH] task_work: kasan: record task_work_add() call stack
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Dmitry Vyukov <dvyukov@google.com>
CC: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Matthias Brugger <matthias.bgg@gmail.com>, "Andrey
 Konovalov" <andreyknvl@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Jens Axboe <axboe@kernel.dk>, Oleg Nesterov
	<oleg@redhat.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM
	<linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>, Linux ARM
	<linux-arm-kernel@lists.infradead.org>, wsd_upstream
	<wsd_upstream@mediatek.com>, <linux-mediatek@lists.infradead.org>
Date: Mon, 15 Mar 2021 17:38:22 +0800
In-Reply-To: <CACT4Y+YrFeRQkw+M8rpOF5169LFn9+puL3Dh1Kk1AOoKV-nyrQ@mail.gmail.com>
References: <20210315015940.11788-1-walter-zh.wu@mediatek.com>
	 <CACT4Y+YrFeRQkw+M8rpOF5169LFn9+puL3Dh1Kk1AOoKV-nyrQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Mailer: Evolution 3.2.3-0ubuntu6
MIME-Version: 1.0
X-TM-SNTS-SMTP: 3B89127E2864DD5DFFD3E95D33CE31C96FF11CB243C9301855A3735564F8F2002000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="D8SU/ZVB";       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.184 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

On Mon, 2021-03-15 at 07:58 +0100, 'Dmitry Vyukov' via kasan-dev wrote:
> On Mon, Mar 15, 2021 at 3:00 AM Walter Wu <walter-zh.wu@mediatek.com> wrote:
> >
> > Why record task_work_add() call stack?
> > Syzbot reports many use-after-free issues for task_work, see [1].
> > After see the free stack and the current auxiliary stack, we think
> > they are useless, we don't know where register the work, this work
> > may be the free call stack, so that we miss the root cause and
> > don't solve the use-after-free.
> >
> > Add task_work_add() call stack into KASAN auxiliary stack in
> > order to improve KASAN report. It is useful for programmers
> > to solve use-after-free issues.
> >
> > [1]: https://groups.google.com/g/syzkaller-bugs/search?q=kasan%20use-after-free%20task_work_run
> >
> > Signed-off-by: Walter Wu <walter-zh.wu@mediatek.com>
> > Suggested-by: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> > Cc: Dmitry Vyukov <dvyukov@google.com>
> > Cc: Andrey Konovalov <andreyknvl@google.com>
> > Cc: Alexander Potapenko <glider@google.com>
> > Cc: Andrew Morton <akpm@linux-foundation.org>
> > Cc: Matthias Brugger <matthias.bgg@gmail.com>
> > Cc: Jens Axboe <axboe@kernel.dk>
> > Cc: Oleg Nesterov <oleg@redhat.com>
> > ---
> >  kernel/task_work.c | 3 +++
> >  mm/kasan/kasan.h   | 2 +-
> >  2 files changed, 4 insertions(+), 1 deletion(-)
> >
> > diff --git a/kernel/task_work.c b/kernel/task_work.c
> > index 9cde961875c0..f255294377da 100644
> > --- a/kernel/task_work.c
> > +++ b/kernel/task_work.c
> > @@ -55,6 +55,9 @@ int task_work_add(struct task_struct *task, struct callback_head *work,
> >                 break;
> >         }
> >
> > +       /* record the work call stack in order to print it in KASAN reports */
> > +       kasan_record_aux_stack(work);
> 
> I think this call should be done _before_ we actually queue the work,
> because this function may operate on non-current task.
> Consider, we queue the work, the other task already executes it and
> triggers use-after-free, now only now we record the stack.

agree, what do you think below change?

--- a/kernel/task_work.c
+++ b/kernel/task_work.c
@@ -34,6 +34,9 @@ int task_work_add(struct task_struct *task, struct
callback_head *work,
 {
    struct callback_head *head;

+   /* record the work call stack in order to print it in KASAN reports
*/
+   kasan_record_aux_stack(work);
+
    do {
        head = READ_ONCE(task->task_works);
        if (unlikely(head == &work_exited))
@@ -55,9 +58,6 @@ int task_work_add(struct task_struct *task, struct
callback_head *work,
        break;
    }

-   /* record the work call stack in order to print it in KASAN reports
*/
-   kasan_record_aux_stack(work);
-
    return 0;
 }

> Moreover, I think we can trigger use-after-free here ourselves while
> recording the aux stack. We queued the work, and the work can cause
> own free, so it's not necessary live by now.

Sorry, I don't fully know your meaning, do you mean we should add an
abort when detect use-after-free?

> 
> >         return 0;
> >  }
> >
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index 3436c6bf7c0c..d300fe9415bd 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -146,7 +146,7 @@ struct kasan_alloc_meta {
> >         struct kasan_track alloc_track;
> >  #ifdef CONFIG_KASAN_GENERIC
> >         /*
> > -        * call_rcu() call stack is stored into struct kasan_alloc_meta.
> > +        * Auxiliary stack is stored into struct kasan_alloc_meta.
> >          * The free stack is stored into struct kasan_free_meta.
> >          */
> >         depot_stack_handle_t aux_stack[2];
> > --
> > 2.18.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1615801102.24887.4.camel%40mtksdccf07.
