Return-Path: <kasan-dev+bncBDK3TPOVRULBBC5IS7ZAKGQEE7VKS4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B9B815CE5C
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 23:56:12 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id w12sf2595679wmc.3
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Feb 2020 14:56:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581634572; cv=pass;
        d=google.com; s=arc-20160816;
        b=U4L/H/88bUHrfAVDz/ed9t5y5ek2r/myD7N8OF/wGyAu6j68qlR9tnfyopCJLWcK99
         s4rrqQrxuCMX+h0U5vcc1wjtDHl48W2uYaypPvnD2IaERQyiDqmoqebQJi3BLlvqxUMa
         PilMvmGxRA+qIiGlDjM2W10COg/mybPasOBrMUR26a1YYmKaY45lrgc51tC9zWL0F+m4
         rIQh+Ig5hYQogqE3PogpnMjJ0nq3zebtHh9rjpNUFasdh0Y/f4qGNqk1p27F2ixWy8DK
         LyF0axrI/LtTWoqP64MJkP7152diBhNCph9NmDs4DvueL+Sbn8b87HqiVz7X2PSca4ki
         4uNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Flbm+qS1dPZHDRCbY2C/J9IHHUgG6fJaol/Er7dG9rE=;
        b=TjmSgSEVyRrnFu8E8fyY6cgF/FKlzdRIHpRKxpLgYw+r6Y2uqCaH3nJMYO+mw3I5D/
         KHB1ZoF1qKHVubqvx/uGwqFVhqtDTElaLbjulxPoz4/VRWoOsYrZLkX9Yzh6+j0T4Jsj
         AOyRdsuhLte6yaS10BmzMMn8JH3QEvpK20/CRgchigkjRR6/M/gQj7BlcoaL+ayte+n1
         GHB9OS0xjyWSqfL1uHbvBPIrlhqm1nG0F3BugUAL3YPtU+unYPYoRVXn4rHGnArxoEIf
         yVuU4xAIXcQHgv3jY7w5Z/FyK3RyX+5oXoy/tGsTGeFITuajGWrwx3A516ZCbyRFxNea
         nMSw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=urydw5lY;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Flbm+qS1dPZHDRCbY2C/J9IHHUgG6fJaol/Er7dG9rE=;
        b=TFh7jKx2qA5gx2lGtf/6clDL70gq9isp1Hp8EKE3DLgrja2aJzWxsDj5pKEUX32ZDv
         393CWf1Ln8ErjoRC4k7GBbkT6XH4pQo/Gtp8PnumD/HzjFp2Ddvkeg8BIqKVsWzBDLsU
         T0IVPgQnD8/ouXD2uLaOQMwOlUI1q+VW35L2Kcpy+JbR3V0xizyVUVQNOaLfWdGcLWz8
         Q/ibYQii+kCYdHHcGqXYoq4hj7mzlummADjQh9PCAANkb3YPjKc0J1ilhyFybJ5N0sKF
         nrmBdBmjQ25yl3ty1OXJKyIWqy0PQfja6xOhSPIBTYmd7Tevv5yTWnmrMHJOIcSNXJvn
         T6uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Flbm+qS1dPZHDRCbY2C/J9IHHUgG6fJaol/Er7dG9rE=;
        b=sl8BRcT0sniBFa9Uk2sqc7m+8YDw0sDZRdiZ6Sp4SjDcv0eWtujsIMPjBqK/FUPb76
         k0KW0tWe5188iM4hW82klnrBnMHWpQNHgvsRqIKVNTacEU4j6uRF8H5MwU72Jtf1jXDD
         oPuREgwsEWMrlqATfsDwlBPh5RIIUQ5Llh64iIMtjPsKaP2gcNJazZes0PgIhIc4WKuE
         9o6ep14/xUdUjlVJZAZ98QkljnhKieEEBQH4z0EUHCW6sTtJfOB1ivgH0oclIKs1O7Ne
         F2uf4OV5ZK1ulUUH+KMHo6GqihzJTETF0uW5ruExytWWpXptAQhUcTq7hYnw4r6DQ1HO
         bJAg==
X-Gm-Message-State: APjAAAWGDrhUblMdafQC/Dlz0S+qQ2l2v9a2Q3gSIOXDnBRj0dp8EScN
	EFd1BQTMG+GvV0fSC7AA4gI=
X-Google-Smtp-Source: APXvYqyRpRPljT1L+moyNjGSmvvNebsgNbpslypJVfdPxsnwpS2/TXruITwgxlJLWVaGrZ9oRafKJQ==
X-Received: by 2002:a7b:c318:: with SMTP id k24mr374133wmj.54.1581634571885;
        Thu, 13 Feb 2020 14:56:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c0d9:: with SMTP id s25ls4695198wmh.0.gmail; Thu, 13 Feb
 2020 14:56:11 -0800 (PST)
X-Received: by 2002:a1c:bdc6:: with SMTP id n189mr355061wmf.102.1581634571320;
        Thu, 13 Feb 2020 14:56:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581634571; cv=none;
        d=google.com; s=arc-20160816;
        b=HqGjQNYVsuLSd/zhuZZevgj+Xot7RNEIxLw8hZaf+IXkrDLGuXNRlE1dqAjeLwVpzY
         XZ/CpZ9ZaMhCRCQGrJ13/A/kgC+Ek6ndcweGf5wz/U94Owh8N2Lkqs/I+qve3beQCl2A
         Sd5Lo8L+rKIottNR5X6kuJyUWB1F+odWApz4jIu4/l+FgtUHPuOoJ/olL3TYwNywS/DR
         SDpP9E7ruGzl7wMeF3vNBBVGD9cwoyPxX148so1RtymI4uDJuLlrSmuh5HxHL18vKtj3
         SuLYwHkQJIFPCWrwDyLSqVXT0nmhE6jAnauE1OKi9AfbQ5l/UivaoRNgfLgKiIgRQtDS
         xy7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L6x9Zqpmo0Kh0pEK6dhHMoc2fR4pHbKz2xssvvuJ+eg=;
        b=N7mW4y0/G1Mo75Bmdq3yG8Qfsw0T/hTZzHn0pfXacCz4L6a1RrLnUVdQhIrw8/o5j5
         31+Kca6979xH/ST3mL6cbG5dMFSjiWpRhyw7GMRlom1ZL7GoqQOI6iVDmoUZCGRqkd0P
         BzPuLGrGVjk4wTOy8bn5k6kgLbqm6cE+mlVz0jKCQE1a2xkHVGSC+81xohlWL+orTLro
         uOKZD+BqYoLlx9xFX7OewRAvfHrnWswvMP+qn92Rffj4Hw7B5rvYWwaGAC5hnLnSvgVr
         OAjOsgERVGFONwsFLIj0a61d21wC2Zv1okDwfi1bGDpcwn9PftjJJkLTlbx3U1D+x5j/
         h2pw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=urydw5lY;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id p29si153120wmi.2.2020.02.13.14.56.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Feb 2020 14:56:11 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id a5so8067663wmb.0
        for <kasan-dev@googlegroups.com>; Thu, 13 Feb 2020 14:56:11 -0800 (PST)
X-Received: by 2002:a05:600c:214f:: with SMTP id v15mr352785wml.110.1581634570688;
 Thu, 13 Feb 2020 14:56:10 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <CACT4Y+b4+5PQvUeeHi=3g0my0WbaRaNEWY3P-MOVJXYSO7U5aA@mail.gmail.com>
 <CAKFsvU+zaY6B_+g=UTpOddKXXgVaKWxH3c8nw6GSLceb1Mg2qA@mail.gmail.com>
 <CACT4Y+aHRiR_7hiRE0DmaCQV2NzaqL0-kbMoVPJU=5-pcOBxJA@mail.gmail.com>
 <CAKFsvUJ2w=re_-q5PTV8c30aVwot8zMOipRvhD9cCx-9cc-Ksw@mail.gmail.com> <CACT4Y+ZJeABriqRZkThVa-MNDBwe7cH=Hmq1vonNmyCTMZOu6w@mail.gmail.com>
In-Reply-To: <CACT4Y+ZJeABriqRZkThVa-MNDBwe7cH=Hmq1vonNmyCTMZOu6w@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Feb 2020 14:55:59 -0800
Message-ID: <CAKFsvUKun6HOk_9ocZ81YebEp90jr3WsAah24HDQQQqY9eamjg@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Jeff Dike <jdike@addtoit.com>, Richard Weinberger <richard@nod.at>, anton.ivanov@cambridgegreys.com, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, David Gow <davidgow@google.com>, 
	Brendan Higgins <brendanhiggins@google.com>, linux-um@lists.infradead.org, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=urydw5lY;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::342
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Wed, Feb 12, 2020 at 9:40 PM 'Dmitry Vyukov' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Wed, Feb 12, 2020 at 11:25 PM Patricia Alfonso
> <trishalfonso@google.com> wrote:
> > > On Wed, Feb 12, 2020 at 1:19 AM Patricia Alfonso
> > > <trishalfonso@google.com> wrote:
> > > >
> > > > On Thu, Jan 16, 2020 at 12:53 AM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > >
> > > > > > +void kasan_init(void)
> > > > > > +{
> > > > > > +       kasan_map_memory((void *)KASAN_SHADOW_START, KASAN_SHADOW_SIZE);
> > > > > > +
> > > > > > +       // unpoison the kernel text which is form uml_physmem -> uml_reserved
> > > > > > +       kasan_unpoison_shadow((void *)uml_physmem, physmem_size);
> > > > > > +
> > > > > > +       // unpoison the vmalloc region, which is start_vm -> end_vm
> > > > > > +       kasan_unpoison_shadow((void *)start_vm, (end_vm - start_vm + 1));
> > > > > > +
> > > > > > +       init_task.kasan_depth = 0;
> > > > > > +       pr_info("KernelAddressSanitizer initialized\n");
> > > > > > +}
> > > > >
> > > > > Was this tested with stack instrumentation? Stack instrumentation
> > > > > changes what shadow is being read/written and when. We don't need to
> > > > > get it working right now, but if it does not work it would be nice to
> > > > > restrict the setting and leave some comment traces for future
> > > > > generations.
> > > > If you are referring to KASAN_STACK_ENABLE, I just tested it and it
> > > > seems to work fine.
> > >
> > >
> > > I mean stack instrumentation which is enabled with CONFIG_KASAN_STACK.
> >
> > I believe I was testing with CONFIG_KASAN_STACK set to 1 since that is
> > the default value when compiling with GCC.The syscall_stub_data error
> > disappears when the value of CONFIG_KASAN_STACK is 0, though.
>
>
> Then I would either disable it for now for UML, or try to unpoision
> stack or ignore accesses.
>
Okay, I'll probably disable it in UML for now.


-- 
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUKun6HOk_9ocZ81YebEp90jr3WsAah24HDQQQqY9eamjg%40mail.gmail.com.
