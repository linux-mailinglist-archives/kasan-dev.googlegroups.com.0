Return-Path: <kasan-dev+bncBCMIZB7QWENRBQEF7HUAKGQEJWHBCVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 706B45FCD2
	for <lists+kasan-dev@lfdr.de>; Thu,  4 Jul 2019 20:17:38 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id x18sf4086570pfj.4
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Jul 2019 11:17:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1562264257; cv=pass;
        d=google.com; s=arc-20160816;
        b=IO/Fw7RRsNmFYOKPIwwdSXXzjZjJl0dePp8naKxBIilFkHYERtW07ya7IQ6IFzzuSI
         OeGTM0OGcML9tMQz2CGq4/AFIJjgHa0+6Zqg1r83XT4BoX6Eo633oUIj87VerawqctqB
         Mswr00uJH02zGwK6YZDEJelxcOl/WM+4c0a8FbDkWixegJoIlo6v36WkMmx29hGMFEda
         saYEG9OyZUy7i4tZDaAV8Fj0jRJoNaQVpc+prd1QZdh5kkQPtSu2jwbGwO6fYz6SGuOt
         4AU0gUu/Eb5RwshjLCoLB3sft8SfdtoO/USpG1K7FCXyfsVd2cafjfyjJt4oVSNvjDc7
         9EGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=PBPzTIhwJxlWLDZy6abh++HFxi6z9NCdBjLKmv6q/+A=;
        b=pxnWExHeyR/CWVxh5b2yqdX1zI0IqwVU787j4VDWCDeQ73mUxZKoAWVtCdztZk0vYo
         gN+DvU6lp0ebUzRZp/NBdTjxUtTbodMjVkH8pFUBxmfJX8VCgeL5ootolgoZIY9SRJQ1
         p1PfyY3xrRq31t8mDit1lH1QQVYUsujvpE8J4MKY5tRMpMNbOKH6hm0ZD7PCvpMHRCxE
         Kla2ZFHsajZ9qYtP3oIyoElxgXTk4/EAUzXz5TmeXJyieWXxq/a6cpzENcxNJYkLJbW3
         R155uNfCF0xu4zsSj5lPDCBoBOaYCTHWIZrD/DGwn/uTpEkyW4E7h3QLTL+FUzQBDPGp
         iBkA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wza567oi;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PBPzTIhwJxlWLDZy6abh++HFxi6z9NCdBjLKmv6q/+A=;
        b=axrOLBbi4ecPRklPWU1GvTG6JVBrVpc/kKo2eG3Vj5t2CvPstI7zcoJmGAypTBgd1l
         Tg2GOFHebGMGEp02+cw04rW5U9QdOes5rXgPHsaojaynpBz/qZzO5Wl0qa7kUGrEmvl5
         Zxg1t3imh3VeAO5SGN6mK/6kotvke1jiL+0/3s7Lb/kcGsRwPbjA4JtdjO6yJVXdF3s3
         yTNQ0wrqd6l9AZyXPI1TPyPJOSFXmBc8pChwDuiC+RZSTPDTaAKEbz2Z9h5hUpVCNFV2
         ycaIfRTFp/+JIBSwLvpixapBImtZUS6XOL4sXZmJvIXSf1JuBAqAKVZtZZ1Uho15nTXO
         w9FA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PBPzTIhwJxlWLDZy6abh++HFxi6z9NCdBjLKmv6q/+A=;
        b=kz5NpMidEk2jWgk3qwZLJPQ/eZg0Zd0ms8+6AYAtxgMB9Gai6MDqULRP3DUmPsGCV3
         YxLdFEaKteTMB8+lr+rFoSwepUcSNFbG8TxyFqeBRiboOKESdR+/Qg8U+87DSJ+kM0YQ
         QGIoYgyZ6wxvhRs+mNxU0yLPMMdQxzqN34+6pW+JoFiUHxsNPeiw+lQ7Og92CGpg709z
         cxXp8RInXsaOSefLXzGpr0VCUUxkybMDSh3dGIS4ywQKxrUsNzaEJK+XGpKqm5kYr2eo
         W0SgwfBJadtXXBqraTKjD5wnQPak6KX009fbzJ/fRdOMcUXHnt8VOHTGHtNGxyfBHe+f
         bCBQ==
X-Gm-Message-State: APjAAAWofU0pKbI1eSk8f21pJ9orjWnozKVYiuhUR7BfG0ZY/K637ons
	hZBON1HnxAuwKWVYCcfBGKQ=
X-Google-Smtp-Source: APXvYqzo1gkao1DJQ9Y+a9OMTUmHmz/3vb582lU8/xK/G0cFf8C+BHprsdjW45dCkO/ZXFVnZa2l1g==
X-Received: by 2002:a17:902:bd0a:: with SMTP id p10mr51109842pls.134.1562264256903;
        Thu, 04 Jul 2019 11:17:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3aa7:: with SMTP id b36ls2300960pjc.5.gmail; Thu, 04
 Jul 2019 11:17:36 -0700 (PDT)
X-Received: by 2002:a17:90a:3787:: with SMTP id v7mr912380pjb.33.1562264256558;
        Thu, 04 Jul 2019 11:17:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1562264256; cv=none;
        d=google.com; s=arc-20160816;
        b=ZJ3DGueiR7KWCxPl8UxH7N5sxh4kZv919sQkEjH7VCIOjGHm8L3ov+ih/WCIdDIrmy
         U4yrQQVc21dmJmKrUYw3RETsA64fYDyrWScTAL4jYxht2mwsKOV7VaMx6O/yGkKUgdNK
         ij6IlUQyoE3MkSmqT1HP5ef/cbBtCALyp5OHe8p6uC1FX9LlpqOVHOANguVgnRtAu2WC
         AM6cEmC3AAlUkr3NyDdOXtY8Fu3HeUYqS+qaQZw9jrvYaECEfeS8sXyUd3QLROE8GBSX
         U+5bxkiUmkM2CIDSzoSlSfyKZ9rG6MZJfIZh879WwlWrC5vDvDyzJYjme6PisaSwwAp2
         iDDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5O9Sg0RsDq/nxAyy+yEbF36kFyDmAIEDqTN9gM8DM2M=;
        b=BDQZSeM4KJe/7c2BSWSLrSW8l/tkgYsm3VAtliia+pR6DkXfNon7WutzTzTvTzhMYX
         pr05KDA/f+uIZ0Z2KNmbbmzGAYbXLAo8NpCWP7SBb66Z6+yqza3vLLdOulxkgqnG109v
         1hQPMlDfhuIsO1Dn0Y6BrRABWU++fK+55x3TJL/i5A985jjUvugnJXnPSV8SYswrax9u
         MsgdqqeZl6mg/JLLOljVck74fzGT6K7QDXNQXhtC5a9azL8klNGarcbazYnswUCtWEaF
         dgin/exPlH9EbAtgCx5L3xt1+i9xGWHpBA4bx365zhww42RL/5L2DKXYveJIp5zmtwLw
         lrig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Wza567oi;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd30.google.com (mail-io1-xd30.google.com. [2607:f8b0:4864:20::d30])
        by gmr-mx.google.com with ESMTPS id g189si221081pgc.3.2019.07.04.11.17.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 Jul 2019 11:17:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d30 as permitted sender) client-ip=2607:f8b0:4864:20::d30;
Received: by mail-io1-xd30.google.com with SMTP id m24so4904500ioo.2
        for <kasan-dev@googlegroups.com>; Thu, 04 Jul 2019 11:17:36 -0700 (PDT)
X-Received: by 2002:a5d:80d6:: with SMTP id h22mr24400816ior.231.1562264256022;
 Thu, 04 Jul 2019 11:17:36 -0700 (PDT)
MIME-Version: 1.0
References: <CAOMFOmWDTkJ05U6HFqgH2GKABrx-sOxjSvumZSRrfceGyGsjXw@mail.gmail.com>
 <CACT4Y+bNm9jhttwVtvntVnyVqJ0jw5i-s6VQfCYVyga=BnkscQ@mail.gmail.com>
 <CAOMFOmWrBT8z8ngZOFDR2d4ssPB5=t-hTwump6tF+=7A4YhvBA@mail.gmail.com>
 <CACT4Y+ZJcp9fTsnvc+S3mG5qUJwvdPfgyi3O5=u_+=LGrbTzdg@mail.gmail.com> <CAOMFOmW3td2MYdDEAY1ivjW7fLdtgdk_E_J1VTqNj5ZWNYenaA@mail.gmail.com>
In-Reply-To: <CAOMFOmW3td2MYdDEAY1ivjW7fLdtgdk_E_J1VTqNj5ZWNYenaA@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 4 Jul 2019 20:17:24 +0200
Message-ID: <CACT4Y+YO8d6xQvjDFNKn83+JWms=75VWL5CASC8F974x7obM4Q@mail.gmail.com>
Subject: Re: KTSAN and Linux semaphores
To: Anatol Pomozov <anatol.pomozov@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Wza567oi;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d30
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

On Wed, Jul 3, 2019 at 5:45 PM Anatol Pomozov <anatol.pomozov@gmail.com> wrote:
> > > And btw semaphores do not use atomics. It is a non-atomic counter
> > > guared by a spinlock.
> >
> >
> > Ah, ok, then I guess spinlocks provided the necessary synchronization
> > for tsan (consider semaphores as applied code that uses spinlocks,
> > such code should not need any explicit annotations). And that may be
> > the right way to handle it, esp. taking into account that it's rarely
> > used.
>
> The spinlock provides a critical section for the internal counter only
>
> https://github.com/google/ktsan/blob/ktsan-master/kernel/locking/semaphore.c#L61

But this may be already enough.
Any down on the semaphore decrements the counter, consequently it
acquires the spinlock, consequently it synchronizes with whoever
executed up on the semaphore via the spinlock.
1. KTSAN understands raw_spin_lock_irqsave, right?
2. Have you seen false positives? Could you post an example?

> If we want to add KTSAN support to semaphores then interceptors need
> to be added to semaphore.c. But it requires introducing idea of
> non-owned mutexes.
> Also how KTSAN suppose to handle non-1 based semaphores?

I would suggest that we use ktsan_sync_acquire/ktsan_sync_release.
They don't have any notion of ownership/critical sections/etc, but
they are enough to prevent false positives.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYO8d6xQvjDFNKn83%2BJWms%3D75VWL5CASC8F974x7obM4Q%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
