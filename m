Return-Path: <kasan-dev+bncBDW2JDUY5AORBOEWXWMQMGQEJ7SUGNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C4A2A5E8F4F
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 20:23:53 +0200 (CEST)
Received: by mail-ot1-x33b.google.com with SMTP id u7-20020a0568301f4700b006540f740af1sf1405905oth.15
        for <lists+kasan-dev@lfdr.de>; Sat, 24 Sep 2022 11:23:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1664043832; cv=pass;
        d=google.com; s=arc-20160816;
        b=wd8Eh2T6VYHdcH2R6L17ZUnVBTZ0QOpMcmoWYwt4W/BDPf8IVb0sz+V0/pKiqSKKir
         UboIU02zGaDoRFRAKIxt35PeNRHNXkSeIQL+dQTAWoNhu/8CebUsnP3HQNo/tn9S+0I0
         XP7RRtdp8enbJUzLnVU0EO1hc6nnO/UT1YeklNYoIfGkX0tyFtw3E2Cc6s4MgcmRY5s7
         URKaqdtfWEnvcrH1RY5xe/xunTpYsgnDbDzbQkGtcAm9yA0zk6azJ4Z27fpBmAFiqH4y
         zmFyF9HbMhjmFnKz+wRv0U5xfPXT/nKhexHxueVc2+d5eGqkI8er2tT6FvRAXGTYrFHw
         gR9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=z/2ovAPSSTt74i4gftw5os385/c/ARWjFQf5kZTVojo=;
        b=opvfhy/Y2MwiPB19TNF25xsprafzEgFth59P1UjYk7esaN3myB3coF0TSoPWi1oLch
         0HSU7RiKZHoiZOQl6bYM1R6q36llV0YV/G0G+A4ZrkOY5ue2J8T/NUFgvINP2s7IGeF1
         FAnS/lbYYJ+iJxEx7k+hj28DbFYGfNXWPADJeArfYyhhHB2cTQgvtrWwMlncG2/B0/bB
         qVwt02sz6PTMIA2PIxUluGrf+XDH7YHi28np48tvDK3RBLwnOqrsUpP3WFRfqfWMjhPg
         hD6WElYRKAu8q1j3UJOPL3RJbcr9rp2yhYxIY5HqNNeGeGFm1w+3IVwjuLwkFT2ueCqR
         5Qow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bTCoA431;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date;
        bh=z/2ovAPSSTt74i4gftw5os385/c/ARWjFQf5kZTVojo=;
        b=raoBSmwBreL+EfM2JPG4YU0FLH9V60phhg54WAjrfXsx6TJQH6AYi07WzMNVMVXOf/
         Y0NkFzLIfze0eO4IKH/9krY/942EMPvXIeLwG8L7UxksOl/q3vTiRpODldX/pN0tR3a0
         1z/vUMxkQkfs9vv5RnBmf0iJ4BUnd5I7EwbH8jMAHef0pISahjmher6EC+0iJ3vIw6y7
         0fdAP/oe2jYV4uxv59g6mUuA1EQ1p5x3ZRNRZWgm2dRi7InWsukEDkLF11lXZbCxSic6
         b9fJkp5csr0aZyJoWeiw0eNSZcxb3Lkf/uXgSdjUMDL4O/3/R7Slk9cjASmg/LYv2wPQ
         YhTg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date;
        bh=z/2ovAPSSTt74i4gftw5os385/c/ARWjFQf5kZTVojo=;
        b=pEDqOTns3/y02xPZyuI38l3jjSHrGfaItEbci7//GWI28e+Dbf147Ra+EpWhLMfQJQ
         vBZM4hXzgRfaVw3bpNPFD+9oK/Adcf3Gcp8opZCzX3EjxETISa267nyuWkELySgIyb+a
         16wzH80jUJNa2GvVZ4xGlwHM+5e3EWQ3sG7Yc3gQBNIYn9wdXKDeREa9QgUIQmDAKHVW
         ZgJJv0DaRC6dzRX0paG6ojvL2IHqYbJNp2nKJbAVVhdSdxyF10cjApXmbfw0Tg/I/ZtK
         VmbUqi4ylspngI12bniJWgp70qht06llaFtOpR+6ia18+s4Xr1Cg/JfJ59U8YVGEKT40
         WmzQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=z/2ovAPSSTt74i4gftw5os385/c/ARWjFQf5kZTVojo=;
        b=zRcV7lJEPVk0VhTC+w4CoSHwUNv+5vNoxosFhtawu2gaH/TY41WW7nmqJiN4tlRiP1
         omBtlmXXg4Awl1+7yAsEBQ3F0R0sYhv3TbegnFDps5GbmdON4kebCTpvBOibT3ANUOmC
         wy0CPeWQo423ncip+fAH7cx+sf/P9woQ05TUIErwQexnjC+1cK7M60a16+p2YUcdCHYY
         nWis5qxDCM9UNlA0Q0JJzpxoYxU7N/uiKGQ+C2y+n6n2L+HQCFI5U3AkLXN/Cu3Q+M4/
         Wr1FMSIl32LPXuolnBF01OclvhhmSnqsgpYbTVNKeVm3DAaTd4AC9pBCIWaFIdIrmiST
         JE8Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0RScXSLktZFUaBn7B5DyqYysbAFUZVm/wPCtAo2QPp15x8fVrN
	+MrW52l2jJCtcaa7U/g9Yj8=
X-Google-Smtp-Source: AMsMyM7VShnyYAPcbZvZmcmwKHFuFbZfhK9pN3UD7cDhESOW56mFtq7/tzKAp6jpr9Tf4sg6UAmouA==
X-Received: by 2002:a05:6808:1a8d:b0:34f:dbe0:5bf5 with SMTP id bm13-20020a0568081a8d00b0034fdbe05bf5mr11447340oib.147.1664043832348;
        Sat, 24 Sep 2022 11:23:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:1808:0:b0:350:c124:2844 with SMTP id h8-20020aca1808000000b00350c1242844ls5811535oih.8.-pod-prod-gmail;
 Sat, 24 Sep 2022 11:23:51 -0700 (PDT)
X-Received: by 2002:a05:6808:209a:b0:350:8336:58be with SMTP id s26-20020a056808209a00b00350833658bemr11784911oiw.38.1664043831876;
        Sat, 24 Sep 2022 11:23:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1664043831; cv=none;
        d=google.com; s=arc-20160816;
        b=dcn/cyVjjAYNE3NDV1wjVlzQ6JVEfkRJn5bnzKO5kqO4ENmCMcWZPPc19qRPdYU1t1
         hte/BRXUan50tA7D9gzeCumS4/785h6iaEXRKfBng/ZSy9ieUwyls4Ov7a10xORr0ZgQ
         mCSrPoO3j3x4QOaG5po9GFjpSRVuBsyP7ORVo51jIeQGoXGXEns5HDAjbaJNo0Rq3xRX
         j9piU4/j4wfN14doBMxTQZ7mEukb1K9GI4RIQ+0zjTJ2dhAVMSLbHS1k2U+Og3C6qdql
         oyelTbaLLACr+ljOx56/eeqYyfdW3C87OTTz/MVELoKc/cL0LcYiPMd23igaldl1ZMId
         WWiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/xbnrBG4oL9dWuD2fAga6eZYd+IqJp16vFuKkeWlnK0=;
        b=cwY76oF3wWqqdAZm0S5zuqD+IY/VpWFL1qKDVtqEd33IiAkmsvz6ZDjPChaujeqixj
         fDaLjzLpkf0z4TF4+gMqUVNpPM6+7mHIWeyDVgC1Cm8nYhY8nSG088SF5G7MwHZZ6QZc
         jYixStSSx8iqfE9LvTSIv+AsVBocKpb5r3ZPUuaz1u//EeAhYuYoMCm3e/nAG2P7MXzc
         JrhV7TnyMn8v3Ka0aaWVUkZkCIjS5Vru/GDH9T8mjzZAhG6eYSHftAdcePQCiZRoVDIg
         6JO66CNZZrt/fgsateh8GDUTU3GGaQmKi4eVnn1vPSNkTfGd9wLsB60Ulvra0CJ/bANA
         HfAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=bTCoA431;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id 16-20020a9d0290000000b006540ebbeec7si609728otl.0.2022.09.24.11.23.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 24 Sep 2022 11:23:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id ay9so1950076qtb.0
        for <kasan-dev@googlegroups.com>; Sat, 24 Sep 2022 11:23:51 -0700 (PDT)
X-Received: by 2002:a05:622a:34f:b0:35d:10ce:a72 with SMTP id
 r15-20020a05622a034f00b0035d10ce0a72mr12244010qtw.391.1664043831367; Sat, 24
 Sep 2022 11:23:51 -0700 (PDT)
MIME-Version: 1.0
References: <20220910052426.943376-1-pcc@google.com> <CA+fCnZdwqOJaT+UXaRF_1Lu8661bxB2WOYb1TiXunBoXdvTBhg@mail.gmail.com>
 <CAMn1gO4XNgWCxmkt8D3SKXUzAbwqTmrAdwBh45vz4WoPoJ6Chg@mail.gmail.com>
In-Reply-To: <CAMn1gO4XNgWCxmkt8D3SKXUzAbwqTmrAdwBh45vz4WoPoJ6Chg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Sat, 24 Sep 2022 20:23:40 +0200
Message-ID: <CA+fCnZcu=Zii9K6VA+W_ji7z=C8WifNxX3xL_a=u1Q7wbeoOVw@mail.gmail.com>
Subject: Re: [PATCH] kasan: also display registers for reports from HW exceptions
To: Peter Collingbourne <pcc@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=bTCoA431;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::832
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Sep 13, 2022 at 6:00 AM Peter Collingbourne <pcc@google.com> wrote:
>
> Hi Andrey,
>
> The most useful case would be for tag check faults with HW tags based
> KASAN where the errant instruction would result in an immediate
> exception which gives the kernel the opportunity to save all of the
> registers to the struct pt_regs.

Right.

> For SW tags based KASAN with inline
> checks it is less useful because some registers will have been used to
> perform the check but I imagine that in some cases even that could be
> better than nothing.

Let's not print the registers for the SW_TAGS mode then. I think
sometimes-irrelevant values might confuse people.

> Peter
>
> > > We can do this easily for reports that resulted from
> > > a hardware exception by passing the struct pt_regs from the exception into
> > > the report function; do so.
> > >
> > > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > > ---
> > > Applies to -next.
> > >
> > >  arch/arm64/kernel/traps.c |  3 +--
> > >  arch/arm64/mm/fault.c     |  2 +-
> > >  include/linux/kasan.h     | 10 ++++++++++
> > >  mm/kasan/kasan.h          |  1 +
> > >  mm/kasan/report.c         | 27 ++++++++++++++++++++++-----
> > >  5 files changed, 35 insertions(+), 8 deletions(-)
> > >
> > > diff --git a/arch/arm64/kernel/traps.c b/arch/arm64/kernel/traps.c
> > > index b7fed33981f7..42f05f38c90a 100644
> > > --- a/arch/arm64/kernel/traps.c
> > > +++ b/arch/arm64/kernel/traps.c
> > > @@ -1019,9 +1019,8 @@ static int kasan_handler(struct pt_regs *regs, unsigned long esr)
> > >         bool write = esr & KASAN_ESR_WRITE;
> > >         size_t size = KASAN_ESR_SIZE(esr);
> > >         u64 addr = regs->regs[0];
> > > -       u64 pc = regs->pc;
> > >
> > > -       kasan_report(addr, size, write, pc);
> > > +       kasan_report_regs(addr, size, write, regs);
> > >
> > >         /*
> > >          * The instrumentation allows to control whether we can proceed after
> > > diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> > > index 5b391490e045..c4b91f5d8cc8 100644
> > > --- a/arch/arm64/mm/fault.c
> > > +++ b/arch/arm64/mm/fault.c
> > > @@ -316,7 +316,7 @@ static void report_tag_fault(unsigned long addr, unsigned long esr,
> > >          * find out access size.
> > >          */
> > >         bool is_write = !!(esr & ESR_ELx_WNR);
> > > -       kasan_report(addr, 0, is_write, regs->pc);
> > > +       kasan_report_regs(addr, 0, is_write, regs);
> > >  }
> > >  #else
> > >  /* Tag faults aren't enabled without CONFIG_KASAN_HW_TAGS. */
> > > diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> > > index d811b3d7d2a1..381aea149353 100644
> > > --- a/include/linux/kasan.h
> > > +++ b/include/linux/kasan.h
> > > @@ -353,6 +353,16 @@ static inline void *kasan_reset_tag(const void *addr)
> > >  bool kasan_report(unsigned long addr, size_t size,
> > >                 bool is_write, unsigned long ip);
> > >
> > > +/**
> > > + * kasan_report_regs - print a report about a bad memory access detected by KASAN
> > > + * @addr: address of the bad access
> > > + * @size: size of the bad access
> > > + * @is_write: whether the bad access is a write or a read
> > > + * @regs: register values at the point of the bad memory access
> > > + */
> > > +bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
> > > +                      struct pt_regs *regs);
> > > +
> > >  #else /* CONFIG_KASAN_SW_TAGS || CONFIG_KASAN_HW_TAGS */
> > >
> > >  static inline void *kasan_reset_tag(const void *addr)
> > > diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> > > index abbcc1b0eec5..39772c21a8ae 100644
> > > --- a/mm/kasan/kasan.h
> > > +++ b/mm/kasan/kasan.h
> > > @@ -175,6 +175,7 @@ struct kasan_report_info {
> > >         size_t access_size;
> > >         bool is_write;
> > >         unsigned long ip;
> > > +       struct pt_regs *regs;
> > >
> > >         /* Filled in by the common reporting code. */
> > >         void *first_bad_addr;
> > > diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> > > index 39e8e5a80b82..eac9cd45b4a1 100644
> > > --- a/mm/kasan/report.c
> > > +++ b/mm/kasan/report.c
> > > @@ -24,6 +24,7 @@
> > >  #include <linux/types.h>
> > >  #include <linux/kasan.h>
> > >  #include <linux/module.h>
> > > +#include <linux/sched/debug.h>
> > >  #include <linux/sched/task_stack.h>
> > >  #include <linux/uaccess.h>
> > >  #include <trace/events/error_report.h>
> > > @@ -284,7 +285,6 @@ static void print_address_description(void *addr, u8 tag,
> > >  {
> > >         struct page *page = addr_to_page(addr);
> > >
> > > -       dump_stack_lvl(KERN_ERR);
> > >         pr_err("\n");

Please pull this pr_err out of this function and put right before the
function is called.

> > >
> > >         if (info->cache && info->object) {
> > > @@ -394,11 +394,14 @@ static void print_report(struct kasan_report_info *info)
> > >                 kasan_print_tags(tag, info->first_bad_addr);
> > >         pr_err("\n");
> > >
> > > +       if (info->regs)
> > > +               show_regs(info->regs);

Looks like show_regs prints with KERN_DEFAULT. Inconsistent with
KERN_ERR used for the rest of the report, but looks like there's no
easy way to fix this. Let's leave as is.

> > > +       else
> > > +               dump_stack_lvl(KERN_ERR);
> > > +
> > >         if (addr_has_metadata(addr)) {
> > >                 print_address_description(addr, tag, info);
> > >                 print_memory_metadata(info->first_bad_addr);
> > > -       } else {
> > > -               dump_stack_lvl(KERN_ERR);
> > >         }
> > >  }
> > >
> > > @@ -458,8 +461,8 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
> > >   * user_access_save/restore(): kasan_report_invalid_free() cannot be called
> > >   * from a UACCESS region, and kasan_report_async() is not used on x86.
> > >   */
> > > -bool kasan_report(unsigned long addr, size_t size, bool is_write,
> > > -                       unsigned long ip)
> > > +static bool __kasan_report(unsigned long addr, size_t size, bool is_write,
> > > +                       unsigned long ip, struct pt_regs *regs)
> > >  {
> > >         bool ret = true;
> > >         void *ptr = (void *)addr;
> > > @@ -480,6 +483,7 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
> > >         info.access_size = size;
> > >         info.is_write = is_write;
> > >         info.ip = ip;
> > > +       info.regs = regs;
> > >
> > >         complete_report_info(&info);
> > >
> > > @@ -493,6 +497,19 @@ bool kasan_report(unsigned long addr, size_t size, bool is_write,
> > >         return ret;
> > >  }
> > >
> > > +bool kasan_report(unsigned long addr, size_t size, bool is_write,
> > > +                       unsigned long ip)
> > > +{
> > > +       return __kasan_report(addr, size, is_write, ip, NULL);
> > > +}
> > > +
> > > +bool kasan_report_regs(unsigned long addr, size_t size, bool is_write,
> > > +                      struct pt_regs *regs)
> > > +{
> > > +       return __kasan_report(addr, size, is_write, instruction_pointer(regs),
> > > +                             regs);
> > > +}
> > > +
> > >  #ifdef CONFIG_KASAN_HW_TAGS
> > >  void kasan_report_async(void)
> > >  {
> > > --
> > > 2.37.2.789.g6183377224-goog
> > >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZcu%3DZii9K6VA%2BW_ji7z%3DC8WifNxX3xL_a%3Du1Q7wbeoOVw%40mail.gmail.com.
