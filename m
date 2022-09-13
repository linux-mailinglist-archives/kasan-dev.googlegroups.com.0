Return-Path: <kasan-dev+bncBD52JJ7JXILRBTMAQCMQMGQE7ZUBDYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 494035B6653
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Sep 2022 06:00:14 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id h4-20020a05651211c400b00497abd0d657sf3416185lfr.13
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Sep 2022 21:00:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1663041613; cv=pass;
        d=google.com; s=arc-20160816;
        b=DYTLtRQ3aDLqKse8/ypxktm7vIgKBSjiqFlI19MponsjOZWBbiD7E9x5tNfeJDG7i3
         pk51FBVCPa2GxiNjkG7fqlmImg72/pVl0vKLpY2qb4ldjYCIHyPvOgPdP7Gl2nikgz3B
         fV7cCo/N0cdiA4olii5gQgxrtO0hILxpG3KyC3JjimVZe08SGWf/eOilZO8T/kqtNVjf
         eOGOxON1cij6pXDXMBZXi5s0HQfkCyLKIEIK+fz4HfQ16uaintxg315T58h5iLlyqg+6
         IvNUdo8fX//Wqt47I4jAGPCEQsFS8fIm3w2GtvmFdy9I8USmeRgb1o0n/kpiE11/qtpS
         ZFdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=E5QK+iMseYIPJ976LM4PObX5yXB9GfGDpKtXwWw6G0A=;
        b=xNNzf1ztYUsr2gFlIyg6rHqtDQcytNBpLhu3dbej6nYRipVQ450vM3fdsMU5wJjSKl
         Oys7l1WpfxzFVTjceag1QbSmhQ1GxrPYrcbMREXadFEKrmlnZa/mCMUdYMt4CnNqSBrv
         zF6FlmyU1uvT3ehkDLFJuGx33DkqEt+Uk0o/iHwuafc84e1qEs0m+Jgzyo/n6nqDtgYW
         i9A9rpOaoAzCjsrJd8Bs2oSqtFxXUlyQlVxyIeJixTqgT13zRYn0dM+pa/9Xc3jT+3J2
         U3VGsljndcPJU2Il8FphunKZMEqcniOUgDDQpLzkHYkYLsy5G001n+voes+PqrhUU8Om
         cu3g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=f7LnaQLY;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date;
        bh=E5QK+iMseYIPJ976LM4PObX5yXB9GfGDpKtXwWw6G0A=;
        b=Rn8lCOd9jaeofZ9PoqcMf8YB1pgGvpltMPz0AY5CWu+HJdPMfntz+hknXqtmqXm+7Q
         KBumm7iNd/jP1CI8SYwY//+su5OVa94uRG80SV8QEVoFpcZM8Fpudssv9lEOIIhT9BQT
         mWu77mJzE7FZvg4YPaMa9ctvYnw0WxdD/VuI7oGumfQ4PRMmJd4e1ejyNqQFZbsCqohy
         pBsjZzXCVcuR4MxggETYEkc94UagvevsJAHefaSoHXkj5b4XGxhg/QW6Rc3RDkAIQA47
         HiKV5Vk/SSjBCfLihJZt7fDdNxhG1jRVWYvcgD0BUO3mJ+O6XLE+hgU64go6xVA3ipxJ
         AK6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date;
        bh=E5QK+iMseYIPJ976LM4PObX5yXB9GfGDpKtXwWw6G0A=;
        b=u9ClK/cx18O9mFsv2btrgcsmD37lycQrH/2psfafiQNKhnryHPQD+C8TEwib5tZQwy
         sRoC51EkfdtPEt8w02QwgIdW0slQ6i4B1PnZycuREeBunvvRigvyPi0e0zUMoBcVrebl
         lMvlnZQBBWeGygtcuJbsG/XOcpuYZ/28Vs8+v+92ZpAXcyi29fkvEpD7f7LTz0VvUypf
         H8IQED4tc8b+buBqvfk8Nwwd/2AIJ9AxQLW9B1Og/4u+Gn9pBSNv5LWdXOqeFhDRNlSN
         KFGkfqW5BolH2qXI0/7S2RHH0Y6PIutqKEUdtQlNgnl/Qof/VLOSIyusUS/kNc4VTupv
         caBA==
X-Gm-Message-State: ACgBeo3QbMV+wAf6bCnT4JUg+SfArbArLXp/3AmqontE+qPl9KX7DxL/
	an0ELE7jqCljGS1yaGWHTls=
X-Google-Smtp-Source: AA6agR48XvUEj00EDavzQiR1JytlEmgCgtj/vkCwRu1G+JXDYIQWO6CPHw3I7lGo/pn7Wmk2476upA==
X-Received: by 2002:a05:6512:1094:b0:498:f9ed:71 with SMTP id j20-20020a056512109400b00498f9ed0071mr7325161lfg.556.1663041613467;
        Mon, 12 Sep 2022 21:00:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:17a6:b0:25d:4f02:5abf with SMTP id
 bn38-20020a05651c17a600b0025d4f025abfls1843221ljb.2.-pod-prod-gmail; Mon, 12
 Sep 2022 21:00:12 -0700 (PDT)
X-Received: by 2002:a05:651c:1591:b0:268:f837:2821 with SMTP id h17-20020a05651c159100b00268f8372821mr8948832ljq.323.1663041612211;
        Mon, 12 Sep 2022 21:00:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1663041612; cv=none;
        d=google.com; s=arc-20160816;
        b=eqb8tIlhpCWx4O2uL8rY74fJj9+BmwSDQbvoWt0Xz8XKEHP0St67rxduPADREzAh4u
         ull8yBgPSKJQQ33IKnkFJHi8QEUyx7ENcRpKJW9/LGfp5WciJvh8TzbiVFu7enT3kU3B
         ORrFaGBiTSymWDmzRYgUr9ANxT8LUS2aCg8+HSHNRoVDOD0oooCatierQYQE1IVGLWDB
         WwJFLyF9D1BNf4u9WKH0BA+jbRk2v2fRnK6KFHzH64IwMFlNsy1jBfmHxXEz5BonkBxB
         DJ2B0ltb0ZWgW4heO/c6Mi+qeQcN2hyNxIKOZY2vX08aqVfM4co82xZkXTmxVp4tMDnd
         3czw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tLzfemK94ccJN8xFwB/gjaf5FTSGs6wi566JJO0+Q0k=;
        b=kE4KDrbVC+wk+uqkO5rMiTq91qs+0Ajf2c+LQDJkIn7zb/troPObRUztp/1Dl0WSiq
         8dvSiHVQ5QKhFUbzBA511gjGnULjWoeBRZHOCcRrJDE9gVqq48siZ5pjrkvXP/NCeMvb
         a5yGXsHc9w9De/wRR9pQAx7Mu175JBl6B8bcO73lMK2HFoQG+V+jnCHVsBFvF8VC3SZS
         h4V9TtHdSQD5eanhOxjAjIm3q4eovW/FaKVh1sICTsJFCigDpy3TknaLBXuyf+1MQP1Z
         17/xinodl90nJdE8Hsog+lWpkFS/SqkO6tVnOz6xy9dXo4ywdu2TlP3BxSmmhL9o13BH
         CZ0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=f7LnaQLY;
       spf=pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id g6-20020a056512118600b0048b12871da5si296975lfr.4.2022.09.12.21.00.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Sep 2022 21:00:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id cc5so8876626wrb.6
        for <kasan-dev@googlegroups.com>; Mon, 12 Sep 2022 21:00:12 -0700 (PDT)
X-Received: by 2002:a5d:4090:0:b0:22a:3ba5:18fd with SMTP id
 o16-20020a5d4090000000b0022a3ba518fdmr11212886wrp.572.1663041611318; Mon, 12
 Sep 2022 21:00:11 -0700 (PDT)
MIME-Version: 1.0
References: <20220910052426.943376-1-pcc@google.com> <CA+fCnZdwqOJaT+UXaRF_1Lu8661bxB2WOYb1TiXunBoXdvTBhg@mail.gmail.com>
In-Reply-To: <CA+fCnZdwqOJaT+UXaRF_1Lu8661bxB2WOYb1TiXunBoXdvTBhg@mail.gmail.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Sep 2022 21:00:00 -0700
Message-ID: <CAMn1gO4XNgWCxmkt8D3SKXUzAbwqTmrAdwBh45vz4WoPoJ6Chg@mail.gmail.com>
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
 header.i=@google.com header.s=20210112 header.b=f7LnaQLY;       spf=pass
 (google.com: domain of pcc@google.com designates 2a00:1450:4864:20::42d as
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

On Sat, Sep 10, 2022 at 2:40 PM Andrey Konovalov <andreyknvl@gmail.com> wrote:
>
> On Sat, Sep 10, 2022 at 7:24 AM Peter Collingbourne <pcc@google.com> wrote:
> >
> > It is sometimes useful to know the values of the registers when a KASAN
> > report is generated.
>
> Hi Peter,
>
> What are the cases when the register values are useful? They are
> "corrupted" by KASAN runtime anyway and thus are not relevant to the
> place in code where the bad access happened.
>
> Thanks!

Hi Andrey,

The most useful case would be for tag check faults with HW tags based
KASAN where the errant instruction would result in an immediate
exception which gives the kernel the opportunity to save all of the
registers to the struct pt_regs. For SW tags based KASAN with inline
checks it is less useful because some registers will have been used to
perform the check but I imagine that in some cases even that could be
better than nothing.

Peter

> > We can do this easily for reports that resulted from
> > a hardware exception by passing the struct pt_regs from the exception into
> > the report function; do so.
> >
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > ---
> > Applies to -next.
> >
> >  arch/arm64/kernel/traps.c |  3 +--
> >  arch/arm64/mm/fault.c     |  2 +-
> >  include/linux/kasan.h     | 10 ++++++++++
> >  mm/kasan/kasan.h          |  1 +
> >  mm/kasan/report.c         | 27 ++++++++++++++++++++++-----
> >  5 files changed, 35 insertions(+), 8 deletions(-)
> >
> > diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
> > index b7fed33981f7..42f05f38c90a 100644
> > --- a/arch/arm64/kernel/traps.c
> > +++ b/arch/arm64/kernel/traps.c
> > @@ -1019,9 +1019,8 @@ static int kasan_handler(struct pt_regs *regs, unsigned long esr)
> >         bool write = esr & KASAN_ESR_WRITE;
> >         size_t size = KASAN_ESR_SIZE(esr);
> >         u64 addr = regs->regs[0];
> > -       u64 pc = regs->pc;
> >
> > -       kasan_report(addr, size, write, pc);
> > +       kasan_report_regs(addr, size, write, regs);
> >
> >         /*
> >          * The instrumentation allows to control whether we can proceed after
> > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > index 5b391490e045..c4b91f5d8cc8 100644
> > --- a/arch/arm64/mm/fault.c
> > +++ b/arch/arm64/mm/fault.c
> > @@ -316,7 +316,7 @@ static void report_tag_fault(unsigned long addr, unsigned long esr,
> >          * find out access size.
> >          */
> >         bool is_write = !!(esr & ESR_ELx_WNR);
> > -       kasan_report(addr, 0, is_write, regs->pc);
> > +       kasan_report_regs(addr, 0, is_write, regs);
> >  }
> >  #else
> >  /* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
> > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > index d811b3d7d2a1..381aea149353 100644
> > --- a/include/linux/kasan.h
> > +++ b/include/linux/kasan.h
> > @@ -353,6 +353,16 @@ static inline void *kasan_reset_tag(const void *addr)
> >  bool kasan_report(unsigned long addr, size_t size,
> >                 bool is_write, unsigned long ip);
> >
> > +/**
> > + * kasan_report_regs - print a report about a bad memory access detected by KASAN
> > + * @addr: address of the bad access
> > + * @size: size of the bad access
> > + * @is_write: whether the bad access is a write or a read
> > + * @regs: register values at the point of the bad memory access
> > + */
> > +bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
> > +                      struct pt_regs *regs);
> > +
> >  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> >
> >  static inline void *kasan_reset_tag(const void *addr)
> > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > index abbcc1b0eec5..39772c21a8ae 100644
> > --- a/mm/kasan/kasan.h
> > +++ b/mm/kasan/kasan.h
> > @@ -175,6 +175,7 @@ struct kasan_report_info {
> >         size_t access_size;
> >         bool is_write;
> >         unsigned long ip;
> > +       struct pt_regs *regs;
> >
> >         /* Filled in by the common reporting code. */
> >         void *first_bad_addr;
> > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > index 39e8e5a80b82..eac9cd45b4a1 100644
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -24,6 +24,7 @@
> >  #include <linux/types.h>
> >  #include <linux/kasan.h>
> >  #include <linux/module.h>
> > +#include <linux/sched/debug.h>
> >  #include <linux/sched/task_stack.h>
> >  #include <linux/uaccess.h>
> >  #include <trace/events/error_report.h>
> > @@ -284,7 +285,6 @@ static void print_address_description(void *addr, u8 tag,
> >  {
> >         struct page *page = addr_to_page(addr);
> >
> > -       dump_stack_lvl(KERN_ERR);
> >         pr_err("\n");
> >
> >         if (info->cache && info->object) {
> > @@ -394,11 +394,14 @@ static void print_report(struct kasan_report_info *info)
> >                 kasan_print_tags(tag, info->first_bad_addr);
> >         pr_err("\n");
> >
> > +       if (info->regs)
> > +               show_regs(info->regs);
> > +       else
> > +               dump_stack_lvl(KERN_ERR);
> > +
> >         if (addr_has_metadata(addr)) {
> >                 print_address_description(addr, tag, info);
> >                 print_memory_metadata(info->first_bad_addr);
> > -       } else {
> > -               dump_stack_lvl(KERN_ERR);
> >         }
> >  }
> >
> > @@ -458,8 +461,8 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
> >   * user_access_save/restore(): kasan_report_invalid_free() cannot be called
> >   * from a UACCESS region, and kasan_report_async() is not used on x86.
> >   */
> > -bool kasan_report(unsigned long addr, size_t size, bool is_write,
> > -                       unsigned long ip)
> > +static bool __kasan_report(unsigned long addr, size_t size, bool is_write,
> > +                       unsigned long ip, struct pt_regs *regs)
> >  {
> >         bool ret = true;
> >         void *ptr = (void *)addr;
> > @@ -480,6 +483,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
> >         info.access_size = size;
> >         info.is_write = is_write;
> >         info.ip = ip;
> > +       info.regs = regs;
> >
> >         complete_report_info(&info);
> >
> > @@ -493,6 +497,19 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
> >         return ret;
> >  }
> >
> > +bool kasan_report(unsigned long addr, size_t size, bool is_write,
> > +                       unsigned long ip)
> > +{
> > +       return __kasan_report(addr, size, is_write, ip, NULL);
> > +}
> > +
> > +bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
> > +                      struct pt_regs *regs)
> > +{
> > +       return __kasan_report(addr, size, is_write, instruction_pointer(regs),
> > +                             regs);
> > +}
> > +
> >  #ifdef CONFIG_KASAN_HW_TAGS
> >  void kasan_report_async(void)
> >  {
> > --
> > 2.37.2.789.g6183377224-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMn1gO4XNgWCxmkt8D3SKXUzAbwqTmrAdwBh45vz4WoPoJ6Chg%40mail.gmail.com.
