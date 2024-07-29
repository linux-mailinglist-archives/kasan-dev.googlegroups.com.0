Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGOYT22QMGQERGVBIBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A6EE93F8AB
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 16:50:04 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-709474fc9edsf2387448a34.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jul 2024 07:50:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722264602; cv=pass;
        d=google.com; s=arc-20160816;
        b=TuXbyvaJMG05Fcv+LBnxEmDRpEef77SWu46p+smluKmPZpGPoiy50kGdBFB3JiiRth
         soyZA4EmYP/pAl3mD+9bWqcpURxbPp7sFH9hZffRyXNMIctRpRjUJCDZduQfGnkhJzRW
         vULpe6ZYuLmFV9IktL07NknKt/YRrNhpz95s8MnjpXhTxHfr5CFZzw1c8N8wG3jsKcyx
         KBMvD8svdFqZ+adnjMgBQ16CgKU6yF3pu0nO3Xvj04V/6m8xJZhitd9tNR7C9uHU3zK1
         1bNmYnPWYhZgDnB+UHJorXWCOfhULwX3gRek4k5qTqWeHIUcG7YByy0eUFhQpJH4RWNe
         EbBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=inY9nrHhFDCYNDUDHduXI7pdWi4xwJVebGGnUQMY1YI=;
        fh=FwtILx/SDtohsPWOK5cWWsv0juTtkULF6LEmyyOy2sY=;
        b=shqSj19U5ABc2DbN1jJfN7DFiGzgAT0xccCHJkcEzXPcrgQVlAabI5POuVlB6ufzXq
         fjnFA0E3nE+VlGTxk/QTDlFEGQBn1rQUXULxk2K0WwHgXv5shRgwdJFIGNZ8K1IopMXV
         7xtZ4I5EVFcaG0s/UhrGuzYhD6TlR599qHoc9Ux906w2HHUboA8WeJhR3dd+eZUdU2sm
         5KpF8AGM3DPRzLogWekQ1ucQ1S7SmIcEL3eq7rwn02rXHqBHtD78sEyXpGibU4DFm3BJ
         7kSTZ7XKkYBqeVg4/tQV1F/CHG4gSGBBvDZOcU0Ky3qUdst6RGe2Y+JwtvbCvCCh1uDI
         XfHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FwvhCIVZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722264602; x=1722869402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=inY9nrHhFDCYNDUDHduXI7pdWi4xwJVebGGnUQMY1YI=;
        b=XUHCrfFuaRIW6qdReCzoXbhL8Ke/IGBplDWQaJ2Yv1zeSRW7We3ZmgRRqsKqueD1on
         I1GUO5I6azTfRpGDa0pLUNtFrxwPeJVOxRy4Yq+Nc9TZSYbh6/TKD+qAHZauPudgEd/g
         4a0LSJesDKxBasvgf03RBfyoyf/3WubzhutafP5gtzWnAGItAXfuuK5rv8V1CzRM9bAc
         rWsiPPly22/Vo5CBa5q5aL18CYDHuqaiwihtoYmolBON7eKQPHSPRPt8wINx/e4DVekY
         fE1EAC/yXiEZHWs3s0J/YJzHb6cLPpjrDA9fdIJE9osK/kNK4SG778s4tWtD92QNLdrO
         URnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722264602; x=1722869402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=inY9nrHhFDCYNDUDHduXI7pdWi4xwJVebGGnUQMY1YI=;
        b=S2Z9zYprG2cNhN1XyO4BGtwM889IAfgpZ1TTLsixNSIlz0HObHItJLOZ6YEsas6VZ5
         rT+nDpX0uX3yh0LCYQ6/K1ZVnD5yNuraSt77vHCVkqPAsIw6nQnOyeE5e9US1ZNbT/6r
         QOJ26IdhyHDNc+XwTkwDHOdSPDNtdLKhcRbgOZM5Hpc8fVkffXbVBEdXbwDtpzhec35k
         XGkapNszP/CQJb++jkgM6KWqyMNlaVRmzsXpZ6ZrN/qLDRdiiiYS/KYmb5nqaAHTyZt7
         FAy6b6Kz82Jzw5UPDy5sXabC1YgJ70flV6irXLwwNqvAQREk8qk3LLjDntZN513ut8FD
         WdSQ==
X-Forwarded-Encrypted: i=2; AJvYcCUSvTrdk4pPTGqldhzySgUqJJWRg5Th672GEWkY0WOtDJT3IOi8dyeFe+3Zv24pCJM07shCkUUTFKoLkFxBja8XHQC7LsFuAA==
X-Gm-Message-State: AOJu0YwY2Fq9xUNyWJtNhbNPODur9CMS0kzWItqx3JNghs+mVwsSoAJ5
	GnMFvFg+xGRjyhZwqUJDIxLnnipOgcKYnCJeokz3kVUQW/GjeWC2
X-Google-Smtp-Source: AGHT+IHdW5HiMCVO2SP3ucAh6JSmFf0B90DOIUfWM1KFT1IZxhxmcyjl9Pi5loeYhQUh/o0LvkFNAw==
X-Received: by 2002:a05:6820:821:b0:5c4:1476:f6af with SMTP id 006d021491bc7-5d5d0ec231emr7751532eaf.3.1722264601335;
        Mon, 29 Jul 2024 07:50:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:3059:0:b0:5c4:69bc:810f with SMTP id 006d021491bc7-5d5ae916e1als4277337eaf.2.-pod-prod-07-us;
 Mon, 29 Jul 2024 07:50:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWar6qP9xudr6CGj8DupqSNLnRrgqdOKnLE2VdfVrs4Y2Ti6F4DQ6PVDjlogbwb8x65oIp1wQx0+NIQHEGXQV3fBfnp6p+qpZh/KQ==
X-Received: by 2002:a05:6830:3742:b0:703:77a2:2854 with SMTP id 46e09a7af769-70940c98610mr10269430a34.28.1722264600262;
        Mon, 29 Jul 2024 07:50:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722264600; cv=none;
        d=google.com; s=arc-20160816;
        b=L+fJDZCADVM0pGEoVpDOyw6/mozSbEHJzMsmTjVlMcwaAlT3AL1zbu2z/z09rEDDUx
         1vaoIQ3CHHO9xlF/qlu6pxALcxbWvNZW9PzqWGVqtcOqzsrEqpGzolSlso386tpI5qdB
         Bek4At3J9Er4zBJvTo07LuihDsO16hesNnHmhGZH6pH1cPP5UAwSI8ZLfNFC2UItdrqv
         f1egagE1z5MM1AWvEdxaemJSlzFYgRgZ6sRlU+jRqAsdVRxT9gyfZY7EQXGXIma5rReu
         XicPg0Fpuac+3NibFGAOeTAa4CkuS4U9IsyRPUVeLon8B3hTruWAERJQtyY/jmNQ9Xzh
         pdYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Dc5OnpQkO4GI5cUSMqWm8aEGW3XO5gfb3sMJB+82c8A=;
        fh=wYgYSf5bsBnchDeh4IWaEEnDvARs/tawLXRRvJ0HfkM=;
        b=gWh+QI9m5WklQcJfI4KQ/+JrJw1X7LdK3ZTOVyy3kEr4NlWnK32xlOCD6nGslumLYi
         MrN8uBCNaWdpz+BHC42/llvIjkpX/GRQQHmSQ74m/gogj/HyagXH1pSHNuiOGmkBojS4
         m9RLHlL0nPBdyJ/Wi+a0QO8uvTvdDo4lxXQL+Kixzs/nUKzfPi8B/KhUVDuX8dnqKbYb
         Cdl8GtMp/tcPDPGro65MULPH6LWqEJVCnRxVNrdlKZA8x6x6iOAurmAaWza9FubjJ9aq
         2QCxpi1Gsu8nNpT/xLZTsQ1aANQTZ/fnqQovb9eJjZE2LiAiVNq8KwaH96cMUGbaeVeo
         zV/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FwvhCIVZ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-vk1-xa2b.google.com (mail-vk1-xa2b.google.com. [2607:f8b0:4864:20::a2b])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-70930508994si394703a34.2.2024.07.29.07.50.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Jul 2024 07:50:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) client-ip=2607:f8b0:4864:20::a2b;
Received: by mail-vk1-xa2b.google.com with SMTP id 71dfb90a1353d-4f6b7250d6dso1299258e0c.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Jul 2024 07:50:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW2esJRbWKlIYQP34Mhjyi/gl+iBoBNX7lXuiKMNl7WWgx98gg3nUrC6zT0iDQYacvmRZ7Dv/YL9XMfZsff98o+cXnL3DJcNn4H3w==
X-Received: by 2002:a05:6122:310a:b0:4f6:a5ed:eb11 with SMTP id
 71dfb90a1353d-4f6e68f714amr9340551e0c.8.1722264599389; Mon, 29 Jul 2024
 07:49:59 -0700 (PDT)
MIME-Version: 1.0
References: <20240729022158.92059-1-andrey.konovalov@linux.dev> <CANpmjNP6ouX1hSayoeOHu7On1DYtPtydFbEQtxoTbsnaE9j77w@mail.gmail.com>
In-Reply-To: <CANpmjNP6ouX1hSayoeOHu7On1DYtPtydFbEQtxoTbsnaE9j77w@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Jul 2024 16:49:20 +0200
Message-ID: <CANpmjNOTnYUZDNG0z64rY7fOd2f2ZPW9qV6Gaz1=n_NWmHjAZA@mail.gmail.com>
Subject: Re: [PATCH] kcov: properly check for softirq context
To: andrey.konovalov@linux.dev
Cc: Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Aleksandr Nogikh <nogikh@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Alan Stern <stern@rowland.harvard.edu>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Marcello Sylvester Bauer <sylv@sylv.io>, linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org, 
	syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com, stable@vger.kernel.org, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FwvhCIVZ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 29 Jul 2024 at 11:42, Marco Elver <elver@google.com> wrote:
>
> On Mon, 29 Jul 2024 at 04:22, <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@gmail.com>
> >
> > When collecting coverage from softirqs, KCOV uses in_serving_softirq() to
> > check whether the code is running in the softirq context. Unfortunately,
> > in_serving_softirq() is > 0 even when the code is running in the hardirq
> > or NMI context for hardirqs and NMIs that happened during a softirq.
> >
> > As a result, if a softirq handler contains a remote coverage collection
> > section and a hardirq with another remote coverage collection section
> > happens during handling the softirq, KCOV incorrectly detects a nested
> > softirq coverate collection section and prints a WARNING, as reported
> > by syzbot.
> >
> > This issue was exposed by commit a7f3813e589f ("usb: gadget: dummy_hcd:
> > Switch to hrtimer transfer scheduler"), which switched dummy_hcd to using
> > hrtimer and made the timer's callback be executed in the hardirq context.
> >
> > Change the related checks in KCOV to account for this behavior of
> > in_serving_softirq() and make KCOV ignore remote coverage collection
> > sections in the hardirq and NMI contexts.
> >
> > This prevents the WARNING printed by syzbot but does not fix the inability
> > of KCOV to collect coverage from the __usb_hcd_giveback_urb when dummy_hcd
> > is in use (caused by a7f3813e589f); a separate patch is required for that.
> >
> > Reported-by: syzbot+2388cdaeb6b10f0c13ac@syzkaller.appspotmail.com
> > Closes: https://syzkaller.appspot.com/bug?extid=2388cdaeb6b10f0c13ac
> > Fixes: 5ff3b30ab57d ("kcov: collect coverage from interrupts")
> > Cc: stable@vger.kernel.org
> > Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
> > ---
> >  kernel/kcov.c | 15 ++++++++++++---
> >  1 file changed, 12 insertions(+), 3 deletions(-)
> >
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index f0a69d402066e..274b6b7c718de 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -161,6 +161,15 @@ static void kcov_remote_area_put(struct kcov_remote_area *area,
> >         kmsan_unpoison_memory(&area->list, sizeof(area->list));
> >  }
> >
> > +/*
> > + * Unlike in_serving_softirq(), this function returns false when called during
> > + * a hardirq or an NMI that happened in the softirq context.
> > + */
> > +static inline bool in_softirq_really(void)
> > +{
> > +       return in_serving_softirq() && !in_hardirq() && !in_nmi();
> > +}
>
> Not sure you need this function. Check if just this will give you what you want:
>
>   interrupt_context_level() == 1
>
> I think the below condition could then also just become:
>
>   if (interrupt_context_level() == 1 && t->kcov_softirq)
>
> Although the softirq_count() helper has a special PREEMPT_RT variant,
> and interrupt_context_level() doesn't, so it's not immediately obvious
> to me if that's also ok on PREEMPT_RT kernels.
>
> Maybe some RT folks can help confirm that using
> interrupt_context_level()==1 does what your above function does also
> on RT kernels.

Hmm, so Thomas just told me that softirqs always run in threaded
context on RT and because there's no nesting,
interrupt_context_level() won't work for what I had imagined here.

So your current solution is fine.

Acked-by: Marco Elver <elver@google.com>

> >  static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_struct *t)
> >  {
> >         unsigned int mode;
> > @@ -170,7 +179,7 @@ static notrace bool check_kcov_mode(enum kcov_mode needed_mode, struct task_stru
> >          * so we ignore code executed in interrupts, unless we are in a remote
> >          * coverage collection section in a softirq.
> >          */
> > -       if (!in_task() && !(in_serving_softirq() && t->kcov_softirq))
> > +       if (!in_task() && !(in_softirq_really() && t->kcov_softirq))
> >                 return false;
> >         mode = READ_ONCE(t->kcov_mode);
> >         /*
> > @@ -849,7 +858,7 @@ void kcov_remote_start(u64 handle)
> >
> >         if (WARN_ON(!kcov_check_handle(handle, true, true, true)))
> >                 return;
> > -       if (!in_task() && !in_serving_softirq())
> > +       if (!in_task() && !in_softirq_really())
> >                 return;
> >
> >         local_lock_irqsave(&kcov_percpu_data.lock, flags);
> > @@ -991,7 +1000,7 @@ void kcov_remote_stop(void)
> >         int sequence;
> >         unsigned long flags;
> >
> > -       if (!in_task() && !in_serving_softirq())
> > +       if (!in_task() && !in_softirq_really())
> >                 return;
> >
> >         local_lock_irqsave(&kcov_percpu_data.lock, flags);
> > --
> > 2.25.1
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOTnYUZDNG0z64rY7fOd2f2ZPW9qV6Gaz1%3Dn_NWmHjAZA%40mail.gmail.com.
