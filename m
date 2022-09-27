Return-Path: <kasan-dev+bncBD52JJ7JXILRBI5AZGMQMGQERO33QXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id C44495EB6C2
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Sep 2022 03:21:40 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id b16-20020a056512061000b0049771081af2sf2954525lfe.5
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Sep 2022 18:21:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664241700; cv=pass;
        d=google.com; s=arc-20160816;
        b=hXb51YIk217jf7JqoDmSj6yLOg4zvmfXH7nld58UZyOvwIvqfkHYXzrkcp6p/o0zCr
         iJ/RLPNrpTnINAEFpXbU4mzosEAuFg8XxzKNZlIGZdzrLu6lTxBWxodi6EUoYM66GJG4
         UkjoakToH5I/Nerc5r9y//Um/tXSpT+VGpkW5gTDf6ZlnOC3h/cmnxtSfRI9SOgNjFlg
         SPY+UR4p0F/4OChyJqG906T5I+/7L6FKoo0rKweG364bSw1ogdZ6LRnd34r8DeJgcHGS
         Cnk2Zi1cKBLEeGyVLC6kjHMnVBPy65xFJo2Pp9mp46Kzl+zp9yZz03sWIMVuEU7H5O7M
         3iZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ra/CYr4WLMtqGtIdNq7MY+mEMZaVNqRXCreSrXM7FoM=;
        b=Z0SXRf9Du8o9uiyDtyyQsAUeKFNNg7HdglHQXhLCztqufzoMsBynG2bFiTcGUw6xiZ
         2OqB7Olk3G5B56NsQzrlTdWJdzL+NLrfm0vyB0kgS+m+CzYB71tBhQJtU+h24HQrjU+k
         drhgfBJUpmoEkFJKqqIMjtvlNYdi9N9za5TyEH3bLt0qokswSxQB60olX/kTlaRvlN11
         SDUN9C+OR0XZa50UdjtFz2smlU9QjUsrOyuuNMhPxwXmU8MQ/tpS8kS/1yZkCFk/OVJK
         0/0sVxkV0c2rIVNL6Vkou/CMGHQYu7adiVYFqAUxw3pC8E80PoCfbrH3YPlw//dftQPO
         NqOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EkWSYBUh;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=Ra/CYr4WLMtqGtIdNq7MY+mEMZaVNqRXCreSrXM7FoM=;
        b=di4PuAqQ+S2hzdy1ZLmME0T0iyi0bPOkHmLbABXh2S5zZ05fjrKdtx3xWzGqL2lttd
         pKx9/nP0W1/uQ2NaxaEOSgpLnLfxV87MX8t6eQRR2aJZ9UlT8lQz3notVzhS0HrXRERw
         6aqIp/2iEbLasayXPUN+WS4UYzf+t43BrCUX1wGt1YkBB6kyUXMTq0doopnwZLyOmmMo
         +YsKpg7bTmPqTxy6fKOdPA4qDuFVdizEAklWlMXytJlKIC1Ii0Gm321gX1LhUtGa8yF5
         Z/Cz6KuCJfAMrIdT60n5q1rN+Inn3r54eWONu/28zlzTDpQf9PvYcpUhUW1KvwPKQNfj
         dy1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=Ra/CYr4WLMtqGtIdNq7MY+mEMZaVNqRXCreSrXM7FoM=;
        b=F04uuZwTTUKl77NHvtsKqaEVqICFkPEN0md8pMPILAXVmU9Vd2lFXyYP2U3hlEuv5J
         DIHN2Ij26NrRmDi2HAzNwD7Sh/JDOn5QZFP8aIY6CGnIWiaLk7DNSE2mM6WlYCeSj4jB
         wOTQkt1dDwk0u9aOOU4roFSPeqqTuCJ1pT9ffsceUC1rXh3etTSOwx8xSCkdOaqpLrm0
         alWjkIsVHX7mWpFFq9SfxlRXGt6MNkJmcRnPV5y8BppOg2kGGAGtce5MB400bengptkr
         gp31RTUGRQADRuN/65hzr3cNZ1aevIhOuilljfGN8Rsu6rknJUJArWwIVJBsN3MyEIcc
         6o2A==
X-Gm-Message-State: ACrzQf3Y2e2M6YQd1+OvweNWYbyeIepabm2ffnd5FRmBjT5Ru3X3wouj
	Npw2gbDWcbuVgzXfrsInTt8=
X-Google-Smtp-Source: AMsMyM7ubQBme/lNnJUUpBvWotWwvFmh1kRK5SVvw0zM6odOMaL5P1duM4GXdmymxDV89tzjTPn9oA==
X-Received: by 2002:ac2:508b:0:b0:4a0:5d6b:ff14 with SMTP id f11-20020ac2508b000000b004a05d6bff14mr6603242lfm.409.1664241700063;
        Mon, 26 Sep 2022 18:21:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:46da:0:b0:48b:2227:7787 with SMTP id p26-20020ac246da000000b0048b22277787ls851850lfo.3.-pod-prod-gmail;
 Mon, 26 Sep 2022 18:21:38 -0700 (PDT)
X-Received: by 2002:a05:6512:b0d:b0:4a1:baad:8d7a with SMTP id w13-20020a0565120b0d00b004a1baad8d7amr4754713lfu.293.1664241698827;
        Mon, 26 Sep 2022 18:21:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664241698; cv=none;
        d=google.com; s=arc-20160816;
        b=xaF0yaiJDoM1vpufGH2d/65OUE4xm6PZIX2D9IbZ0+r4CVUkaEVGxl64qpOSfysOGU
         ptifGmw/O9KTe7NVZil0E9DkVyf+2fiuYN8+QdG2rUdIjIPeYfiMN1whRiBoR/7VpE/I
         PbfrwZ+CKorMSIDfRW1Fj5vzmy1+apGs3oOeNnDJ9fWEfa5D43VW98WlPPaZoSL20w0i
         33IWY/yWHlWVtx7rxHXcQWV/v0cX8G1z2fSWuOcpQ1eytZvZA7BsDsG1lipughXGKljg
         /bgmz6MGWUn9CF7/9Rcq5rXrh1ZiAzneXe9JyCRoT2zlBhNgFQdso3fismQhdAG0+PT1
         hPvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=acezLh2g6SPY0/YcmOwVy1TcnXLq7PIJSasjJauijnc=;
        b=UoVbdxSEynEcIYI6pypYKLRn88yh1Mt8gYtZ86AJj4PfGhRZ77dv8T7lKhVgyJS27U
         KlBUDOyLqR0SOfnyG7Eqsojf0YLV35RN5F3w45vC/f0wjwyK1eaKdT3OFpO5rPfZdtR/
         s9Dd7MhIxzbpVJYPzI397pl/+jdpUJNbjSaEpWewnxXN4+xtQ8nsnHy4qGFn6FRflBL7
         bQjFqnwwGp9x+rZUN8bHVzOJfqtyG0N7o5O4UHPcacKtTh8z0aX0NoAs/u9jCem5bffC
         7S8Do0kf8fEmmkV4dXAYkHjvGU9m0Zk1RsI9wHjiW12DaUFGXm6c9B8Bo+8QHLb/gMq2
         1Kdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=EkWSYBUh;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::32d as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32d.google.com (mail-wm1-x32d.google.com. [2a00:1450:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id v7-20020ac25587000000b0049ba11e2f38si415lfg.11.2022.09.26.18.21.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Sep 2022 18:21:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::32d as permitted sender) client-ip=2a00:1450:4864:20::32d;
Received: by mail-wm1-x32d.google.com with SMTP id iv17so5594377wmb.4
        for <kasan-dev@googlegroups.com>; Mon, 26 Sep 2022 18:21:38 -0700 (PDT)
X-Received: by 2002:a05:600c:21c2:b0:3b4:7272:bfd3 with SMTP id
 x2-20020a05600c21c200b003b47272bfd3mr822268wmj.148.1664241698147; Mon, 26 Sep
 2022 18:21:38 -0700 (PDT)
MIME-Version: 1.0
References: <20220910052426.943376-1-pcc@google.com> <CA+fCnZdwqOJaT+UXaRF_1Lu8661bxB2WOYb1TiXunBoXdvTBhg@mail.gmail.com>
 <CAMn1gO4XNgWCxmkt8D3SKXUzAbwqTmrAdwBh45vz4WoPoJ6Chg@mail.gmail.com> <CA+fCnZcu=Zii9K6VA+W_ji7z=C8WifNxX3xL_a=u1Q7wbeoOVw@mail.gmail.com>
In-Reply-To: <CA+fCnZcu=Zii9K6VA+W_ji7z=C8WifNxX3xL_a=u1Q7wbeoOVw@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Sep 2022 18:21:26 -0700
Message-ID: <CAMn1gO7ni478G=Z0FwYMoGm1d04BETpwPkg8J=bKa0SO3217eA@mail.gmail.com>
Subject: Re: [PATCH] kasan: also display registers for reports from HW exceptions
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=EkWSYBUh;       spf=pass
 (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::32d as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Sat, Sep 24, 2022 at 11:23 AM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Tue, Sep 13, 2022 at 6:00 AM Peter Collingbourne <pcc@google.com> wrote:
> >
> > Hi Andrey,
> >
> > The most useful case would be for tag check faults with HW tags based
> > KASAN where the errant instruction would result in an immediate
> > exception which gives the kernel the opportunity to save all of the
> > registers to the struct pt_regs.
>
> Right.
>
> > For SW tags based KASAN with inline
> > checks it is less useful because some registers will have been used to
> > perform the check but I imagine that in some cases even that could be
> > better than nothing.
>
> Let's not print the registers for the SW_TAGS mode then. I think
> sometimes-irrelevant values might confuse people.

Done in v2.

> > Peter
> >
> > > > We can do this easily for reports that resulted from
> > > > a hardware exception by passing the struct pt_regs from the exception into
> > > > the report function; do so.
> > > >
> > > > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > > > ---
> > > > Applies to -next.
> > > >
> > > >  arch/arm64/kernel/traps.c |  3 +--
> > > >  arch/arm64/mm/fault.c     |  2 +-
> > > >  include/linux/kasan.h     | 10 ++++++++++
> > > >  mm/kasan/kasan.h          |  1 +
> > > >  mm/kasan/report.c         | 27 ++++++++++++++++++++++-----
> > > >  5 files changed, 35 insertions(+), 8 deletions(-)
> > > >
> > > > diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
> > > > index b7fed33981f7..42f05f38c90a 100644
> > > > --- a/arch/arm64/kernel/traps.c
> > > > +++ b/arch/arm64/kernel/traps.c
> > > > @@ -1019,9 +1019,8 @@ static int kasan_handler(struct pt_regs *regs, unsigned long esr)
> > > >         bool write = esr & KASAN_ESR_WRITE;
> > > >         size_t size = KASAN_ESR_SIZE(esr);
> > > >         u64 addr = regs->regs[0];
> > > > -       u64 pc = regs->pc;
> > > >
> > > > -       kasan_report(addr, size, write, pc);
> > > > +       kasan_report_regs(addr, size, write, regs);
> > > >
> > > >         /*
> > > >          * The instrumentation allows to control whether we can proceed after
> > > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > > index 5b391490e045..c4b91f5d8cc8 100644
> > > > --- a/arch/arm64/mm/fault.c
> > > > +++ b/arch/arm64/mm/fault.c
> > > > @@ -316,7 +316,7 @@ static void report_tag_fault(unsigned long addr, unsigned long esr,
> > > >          * find out access size.
> > > >          */
> > > >         bool is_write = !!(esr & ESR_ELx_WNR);
> > > > -       kasan_report(addr, 0, is_write, regs->pc);
> > > > +       kasan_report_regs(addr, 0, is_write, regs);
> > > >  }
> > > >  #else
> > > >  /* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
> > > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > > index d811b3d7d2a1..381aea149353 100644
> > > > --- a/include/linux/kasan.h
> > > > +++ b/include/linux/kasan.h
> > > > @@ -353,6 +353,16 @@ static inline void *kasan_reset_tag(const void *addr)
> > > >  bool kasan_report(unsigned long addr, size_t size,
> > > >                 bool is_write, unsigned long ip);
> > > >
> > > > +/**
> > > > + * kasan_report_regs - print a report about a bad memory access detected by KASAN
> > > > + * @addr: address of the bad access
> > > > + * @size: size of the bad access
> > > > + * @is_write: whether the bad access is a write or a read
> > > > + * @regs: register values at the point of the bad memory access
> > > > + */
> > > > +bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
> > > > +                      struct pt_regs *regs);
> > > > +
> > > >  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> > > >
> > > >  static inline void *kasan_reset_tag(const void *addr)
> > > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > > index abbcc1b0eec5..39772c21a8ae 100644
> > > > --- a/mm/kasan/kasan.h
> > > > +++ b/mm/kasan/kasan.h
> > > > @@ -175,6 +175,7 @@ struct kasan_report_info {
> > > >         size_t access_size;
> > > >         bool is_write;
> > > >         unsigned long ip;
> > > > +       struct pt_regs *regs;
> > > >
> > > >         /* Filled in by the common reporting code. */
> > > >         void *first_bad_addr;
> > > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > > index 39e8e5a80b82..eac9cd45b4a1 100644
> > > > --- a/mm/kasan/report.c
> > > > +++ b/mm/kasan/report.c
> > > > @@ -24,6 +24,7 @@
> > > >  #include <linux/types.h>
> > > >  #include <linux/kasan.h>
> > > >  #include <linux/module.h>
> > > > +#include <linux/sched/debug.h>
> > > >  #include <linux/sched/task_stack.h>
> > > >  #include <linux/uaccess.h>
> > > >  #include <trace/events/error_report.h>
> > > > @@ -284,7 +285,6 @@ static void print_address_description(void *addr, u8 tag,
> > > >  {
> > > >         struct page *page = addr_to_page(addr);
> > > >
> > > > -       dump_stack_lvl(KERN_ERR);
> > > >         pr_err("\n");
>
> Please pull this pr_err out of this function and put right before the
> function is called.

Done in v2.

> > > >
> > > >         if (info->cache && info->object) {
> > > > @@ -394,11 +394,14 @@ static void print_report(struct kasan_report_info *info)
> > > >                 kasan_print_tags(tag, info->first_bad_addr);
> > > >         pr_err("\n");
> > > >
> > > > +       if (info->regs)
> > > > +               show_regs(info->regs);
>
> Looks like show_regs prints with KERN_DEFAULT. Inconsistent with
> KERN_ERR used for the rest of the report, but looks like there's no
> easy way to fix this. Let's leave as is.

Ack.

Peter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO7ni478G%3DZ0FwYMoGm1d04BETpwPkg8J%3DbKa0SO3217eA%40mail.gmail.com.
