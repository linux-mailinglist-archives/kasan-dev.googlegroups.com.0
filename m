Return-Path: <kasan-dev+bncBCXKTJ63SAARBYFTRSHAMGQE5FLUGSI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id CCBB247D1AA
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Dec 2021 13:28:17 +0100 (CET)
Received: by mail-pj1-x1037.google.com with SMTP id p4-20020a17090a348400b001b103a13f69sf3731988pjb.8
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Dec 2021 04:28:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640176096; cv=pass;
        d=google.com; s=arc-20160816;
        b=u6SAmzoeTjBrV++AYg8exoXHjjwRjujBS4hv6AezLGvfEYHUAlH6oJwYn/A/01I48E
         BzU06acl8eGKIWIXaK9NXdqq9Vm2xOTXh4TTPycKnkLvgRh0AkHoSOa41T6/kqEp/dfR
         oorHRlHK75Bh1w/O7bn1IU1tdXwRQqBtJzg8qAWJuoF1Kz+bdjJHeeHJ5QZUPrvqRqum
         7qfdwuxqn93whu9/mPIH74eWGUI1DfCDQteDf0Wn5RgXeKRXzTwxWwzmQSpXltXhI253
         hP8cxpgSsiCSEudkdf6AMPjTXmps4kFDvy7dzvOTVYp4YcvNjJLfOIPYErk/oexKptPv
         wzHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9gjhKOxpYURFJvuzf4+PaDTR0WKCB4msp4dXKLpVJrY=;
        b=Tp38ljOCQ/eRBORA04zLvukUFCY3b9jX1S6yG+8PJ8e51OK12TCexPcdytvywqF1h0
         Mj08wYptcwfvrxMgC/uG0NUk7PbSxru9GjZbEF22rQTZjzzshWNDpALluGmb/YWNbhK9
         cZkN7J8b0m8B9LtWvdfCSdiP5NPj9T6Y4GpS8soW95ns+ERQCZlJaGO+447BuyMIrGnw
         9NKcF14bTdpNmQ0keVIAIE6PYPRXj9l5FXWqoQICG0vcwzV8MEwBSYqkwpM9oVRaM2/4
         Co8irgVLTqOYgs58VkXMVtfEw3/4YGboh6N6uhZN2VBK7KMuimmtpqeLKhZMqNu3VPh9
         syRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UfOW6bZR;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9gjhKOxpYURFJvuzf4+PaDTR0WKCB4msp4dXKLpVJrY=;
        b=SSqlZzyhBsjj3+bcE3Sw2DfF/qOuNFdHQf9F4NkQQwosn5/QbvFeqPM5sWBB0EgSbG
         HBXuJIiQVYneU4wbsDg10SMS+2UU72nvUAOgGkCsJxGDlSXVoFXaUR7kJmJsJcyx2jy3
         bVAopaKk5Bwhs489hkR50Mha3vb9jyZLrpbLPKYPryVjA4nLl4GDoxNOpyrqszjCMkiK
         FoxRt7lx9llhaiQnt7+2nCZUlRw3Tf0l79OYJvusLO0FkLuoNmGNzdXwpcLqzuwtNVrr
         R2TphLkt4DLl3gg9df1Up6+i3s5Lu5WIqkTFoy/A0g6WxHcfPh/yqrHpD1gGZVG2P+nq
         FUUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9gjhKOxpYURFJvuzf4+PaDTR0WKCB4msp4dXKLpVJrY=;
        b=7gdqbPlWl7lKv8lg8yJPBh06ZL3oJpYh+1FagktFZYnJaEiIxflRIjoBAJ8wZtE8Yq
         d+0Ob/iRfHmFlc2h7HKfG0GhaeHoDmYB1fP3r+tTPfIFLq8GirczTzbevnkQ1DeQpVOg
         d3+Cj9Ul2U+yGXG+Rrm0i24oG6GQaLLhYHC8+YBfc0aQ0qpA3PkGVZ+o2e8rVOU3Lmyj
         ZWe127gTmwJd3sS5NEKMGckYFYKuL1Ty9mKlsxKFzdOAeDiMo49inOdSq1LTK3JSavrC
         txNtetEGQTbvkfF0qAyBIa7UwmNBSt+CE3HWnR3BDNVaPg6DS6CGBVkdzsDoGLK5CHJu
         mPLQ==
X-Gm-Message-State: AOAM530UlAvVir1DV53ee/JOVC3RTsvNb/a/qk34M0i5tLbz8tIR94Jr
	97uMQ3q/+dXvfjeExdhWB4w=
X-Google-Smtp-Source: ABdhPJwBgsKvdOrONJkqGo8YabJqhmEBny2rpufD5+hf/wuJB8i1sxKc8EN/0lG5pmNd5VQU7HDn9A==
X-Received: by 2002:a17:90a:f682:: with SMTP id cl2mr1078313pjb.124.1640176096394;
        Wed, 22 Dec 2021 04:28:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7359:: with SMTP id d25ls864403pgn.2.gmail; Wed, 22 Dec
 2021 04:28:15 -0800 (PST)
X-Received: by 2002:a63:88c2:: with SMTP id l185mr2547389pgd.77.1640176095877;
        Wed, 22 Dec 2021 04:28:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640176095; cv=none;
        d=google.com; s=arc-20160816;
        b=UNu01FuCXhWdqlVt8m6D/BEHJxBDcmeBIU3fqux+zZb5usyhvo34bcg7hfMGO9ugff
         2C77d5HK/mR9vM8NO7WCYgbsltyi5rIsyTkgS7sDM3HDjM08bWlsGymts5OCEfg5m5QT
         H7GQNOmtEx+LeDGQTaW3dwLICFilEkyifpF3VL/FK47sezibzOhECZIYwLb0HV9qefrx
         C7Nb5f2rrMXn+6hQXzhzv1TMVTwALsnZ1u7QDC1jtqiaaUuheMuoJxWFGEfSannJLwtQ
         00Ck2L2tzQIWATW/aidvmhtmwBBakkm/y/cQ0e0zzI2NuKUiHmKz+kkFjr0lbnzUSYW1
         DlHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B4l29Q6VoPrVDbqTDrgQxK8AEFTdPzsV04sjKB67kbI=;
        b=kjMF9uS6Ci9TssLE2hPqBZyJ9L+rFE9Nd+SmcS5JB/1yKH7w882kMWLUZsbN5dA0iT
         y7wsrD3vs5zTSih+jsURpW19l9T9ZH8irEcvK86kpBlSyZbMCPQGgjwd/ExI4KSPZG6S
         scTIGTIKoFtEamaIGogAIRcJl77RjWt/tjRtRw3S0how6yXFMoYfhOiWcqF5BkdxzPFC
         6roKASb39CRRQCyo8WRRHTFwBATLKJyVoVhS7Er+dUU8LM2UGwagzvfOAqZqRI/t6dOx
         4j+IshF6kSZ0H0kJtdMvaPoDrtSjDU/Gz2nbP9/TI1MIVyhtRoco6qWn/TEdfLmolsus
         kHcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=UfOW6bZR;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::132 as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x132.google.com (mail-il1-x132.google.com. [2607:f8b0:4864:20::132])
        by gmr-mx.google.com with ESMTPS id k14si532731pji.1.2021.12.22.04.28.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Dec 2021 04:28:15 -0800 (PST)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::132 as permitted sender) client-ip=2607:f8b0:4864:20::132;
Received: by mail-il1-x132.google.com with SMTP id b1so1666783ilj.2
        for <kasan-dev@googlegroups.com>; Wed, 22 Dec 2021 04:28:15 -0800 (PST)
X-Received: by 2002:a05:6e02:20ee:: with SMTP id q14mr1201784ilv.44.1640176095373;
 Wed, 22 Dec 2021 04:28:15 -0800 (PST)
MIME-Version: 1.0
References: <20211221170348.1113266-1-nogikh@google.com> <20211221170348.1113266-2-nogikh@google.com>
 <CANpmjNMAWuE0Y20ZuBUSRXkvWZd8NC1d=DDYYrEZytJz9ndxeA@mail.gmail.com>
In-Reply-To: <CANpmjNMAWuE0Y20ZuBUSRXkvWZd8NC1d=DDYYrEZytJz9ndxeA@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 Dec 2021 13:28:04 +0100
Message-ID: <CANp29Y64kQ01XTi422jowTh+PFYKxXcLY1NP=is-3cP1n6YpgQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/2] kcov: split ioctl handling into locked and
 unlocked parts
To: Marco Elver <elver@google.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Taras Madan <tarasmadan@google.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=UfOW6bZR;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::132 as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

> To do that, you'd have to add the locking around KCOV_INIT_TRACE here,

Argh, indeed! Thanks, I'll fix it in v3.

> Also, I find that kcov_ioctl_unlocked() isn't a very descriptive name,
since now we have both locked and unlocked variants. What is it
actually doing?

The main motivation behind introducing that function was to get the
ability to do some processing outside of a spin lock without major
code refactoring. So it kind of wraps the existing ioctl processing
and, if it's KCOV_INIT_TRACE, performs the action itself.

I'm now thinking that we could probably do without introducing an
extra function at all - by moving `spin_lock_irqsave (&kcov->lock,
flags);` and `spin_unlock_irqrestore(&kcov->lock, flags);` into the
`kcov_ioctl_locked` function (and rename it into sth like
`kcov_do_ioctl`). So it could look like this:

switch (cmd) {
case KCOV_INIT_TRACE:
//...
}
spin_lock_irqsave (&kcov->lock, kcov_flags);
switch (cmd) {
case KCOV_ENABLE:
//...
default:
//...
}
spin_unlock_irqrestore(&kcov->lock, kcov_flags);


On Tue, Dec 21, 2021 at 9:19 PM Marco Elver <elver@google.com> wrote:
>
> On Tue, 21 Dec 2021 at 18:04, Aleksandr Nogikh <nogikh@google.com> wrote:
> >
> > Currently all ioctls are de facto processed under a spin lock in order
> > to serialise them. This, however, prohibits the use of vmalloc and other
> > memory management functions in the implementation of those ioctls,
> > unnecessary complicating any further changes.
> >
> > Let all ioctls first be processed inside the kcov_ioctl_unlocked()
> > function which should execute the ones that are not compatible with
> > spinlock and pass control to kcov_ioctl_locked() for all other ones.
> >
> > Although it is still compatible with a spinlock, move KCOV_INIT_TRACE
> > handling to kcov_ioctl_unlocked(), so that its planned change is easier
> > to follow.
> >
> > Signed-off-by: Aleksandr Nogikh <nogikh@google.com>
> > ---
> >  kernel/kcov.c | 64 +++++++++++++++++++++++++++++++--------------------
> >  1 file changed, 39 insertions(+), 25 deletions(-)
> >
> > diff --git a/kernel/kcov.c b/kernel/kcov.c
> > index 36ca640c4f8e..5d87b4e0126f 100644
> > --- a/kernel/kcov.c
> > +++ b/kernel/kcov.c
> > @@ -564,31 +564,12 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
> >                              unsigned long arg)
> >  {
> >         struct task_struct *t;
> > -       unsigned long size, unused;
> > +       unsigned long flags, unused;
> >         int mode, i;
> >         struct kcov_remote_arg *remote_arg;
> >         struct kcov_remote *remote;
> > -       unsigned long flags;
> >
> >         switch (cmd) {
> > -       case KCOV_INIT_TRACE:
> > -               /*
> > -                * Enable kcov in trace mode and setup buffer size.
> > -                * Must happen before anything else.
> > -                */
> > -               if (kcov->mode != KCOV_MODE_DISABLED)
> > -                       return -EBUSY;
> > -               /*
> > -                * Size must be at least 2 to hold current position and one PC.
> > -                * Later we allocate size * sizeof(unsigned long) memory,
> > -                * that must not overflow.
> > -                */
> > -               size = arg;
> > -               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> > -                       return -EINVAL;
> > -               kcov->size = size;
> > -               kcov->mode = KCOV_MODE_INIT;
> > -               return 0;
> >         case KCOV_ENABLE:
> >                 /*
> >                  * Enable coverage for the current task.
> > @@ -685,6 +666,43 @@ static int kcov_ioctl_locked(struct kcov *kcov, unsigned int cmd,
> >         }
> >  }
> >
> > +static int kcov_ioctl_unlocked(struct kcov *kcov, unsigned int cmd,
> > +                            unsigned long arg)
> > +{
> > +       unsigned long size, flags;
> > +       int res;
> > +
> > +       switch (cmd) {
> > +       case KCOV_INIT_TRACE:
> > +               /*
> > +                * Enable kcov in trace mode and setup buffer size.
> > +                * Must happen before anything else.
> > +                */
> > +               if (kcov->mode != KCOV_MODE_DISABLED)
> > +                       return -EBUSY;
> > +               /*
> > +                * Size must be at least 2 to hold current position and one PC.
> > +                * Later we allocate size * sizeof(unsigned long) memory,
> > +                * that must not overflow.
> > +                */
> > +               size = arg;
> > +               if (size < 2 || size > INT_MAX / sizeof(unsigned long))
> > +                       return -EINVAL;
> > +               kcov->size = size;
> > +               kcov->mode = KCOV_MODE_INIT;
> > +               return 0;
>
> This patch should be a non-functional change, but it is not.
>
> To do that, you'd have to add the locking around KCOV_INIT_TRACE here,
> and then do whatever else you're doing in patch 2/2.
>
> > +       default:
> > +               /*
> > +                * All other commands can be fully executed under a spin lock, so we
> > +                * obtain and release it here to simplify the code of kcov_ioctl_locked().
> > +                */
> > +               spin_lock_irqsave(&kcov->lock, flags);
> > +               res = kcov_ioctl_locked(kcov, cmd, arg);
> > +               spin_unlock_irqrestore(&kcov->lock, flags);
> > +               return res;
> > +       }
> > +}
> > +
> >  static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >  {
> >         struct kcov *kcov;
> > @@ -692,7 +710,6 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >         struct kcov_remote_arg *remote_arg = NULL;
> >         unsigned int remote_num_handles;
> >         unsigned long remote_arg_size;
> > -       unsigned long flags;
> >
> >         if (cmd == KCOV_REMOTE_ENABLE) {
> >                 if (get_user(remote_num_handles, (unsigned __user *)(arg +
> > @@ -713,10 +730,7 @@ static long kcov_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
> >         }
> >
> >         kcov = filep->private_data;
> > -       spin_lock_irqsave(&kcov->lock, flags);
> > -       res = kcov_ioctl_locked(kcov, cmd, arg);
> > -       spin_unlock_irqrestore(&kcov->lock, flags);
> > -
> > +       res = kcov_ioctl_unlocked(kcov, cmd, arg);
>
> Also, I find that kcov_ioctl_unlocked() isn't a very descriptive name,
> since now we have both locked and unlocked variants. What is it
> actually doing?
>
> Perhaps kcov_ioctl_with_context()? Assuming that 'struct kcov' is some
> sort of context.
>
> >         kfree(remote_arg);
> >
> >         return res;
> > --
> > 2.34.1.307.g9b7440fafd-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANp29Y64kQ01XTi422jowTh%2BPFYKxXcLY1NP%3Dis-3cP1n6YpgQ%40mail.gmail.com.
