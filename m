Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6VV335AKGQEIZ7ZAAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id BA6D8261306
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 16:53:47 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id v16sf5957997ilh.15
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 07:53:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599576826; cv=pass;
        d=google.com; s=arc-20160816;
        b=cASBHdf0AAA0V0IhaOCiAUsu1Fner0H5QW++Htwr2YjKOkdhav6r1kERcduaW6xeXo
         0E5vDQdfsV9Ym25tW8n9dZn8hJbcHwMndAHs9pOgQCS/HPUwWONK50XulBj0mw0W7zRh
         9S8/LHY4abZd5ZIWjZNskzPMkn9r9cNggWw5Ie7NgtL11ao76gTMCvuIUt4N2bz1xdps
         phc42pa26t1M9v73a8yjTkx4BkMtnuM3w7w7COsDEHVfrezzB0tWLZJrnHy2o9G1iddb
         VhWHSvUa2T9JXkMWOHmH+uBnGqVeGRUYEb/CL2XT6kygW7cUtB7EorRqeAAwSYNrg/wp
         Pi2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=j5dV+sdEWcUaWRTSNp0ZPh4WxbOa4goYCoTO6AKSLq8=;
        b=suZNY/YSmxCH2aFunGmmA8LHa6al7ZLnFyESer5t9Prex1qlDx/A/lTCuv06s9AOZy
         Atpzg2FddcLlqdqBW/lqsXBnPLTlBDLe3WQJrfbVu3yqVJtU7Df6TCOzKcvXWeopxbdj
         VrTLMpgsvp+u86cXGtg77ZpJB2EDZKLOdYC4WyDMR/AAtGsYGHSaAWnJsZOHfwwGwtCP
         g+v6bouH2d8wekWzW8vP+fUcX+lQb4h1WB4mHZwJRMOJUIMCQ8xe49lUgnFUSHQBEaPz
         GVpR+mgVqyCW0WZ/9rib6bJpjbDi6Qd5bZ502LTry2SLvwkWfardUzdFDoEriBp/xs7M
         +NOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M3kd1XId;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j5dV+sdEWcUaWRTSNp0ZPh4WxbOa4goYCoTO6AKSLq8=;
        b=JoF5oNqcUK0EfJbSBzLbu9E41KQN3e/5FaAvsq4CmyKYVxVh36mnMyuXilYV2nGESY
         VKipKAl8YWa2/can2XMtOHVmszgX5eozeHGKs69+/d6f/MlQaTbRFvQIe0GdpCBUFA3j
         c1HQtJZeJTaF8GoYhYBzj3ZlXW7x0kBxpUlJ7OEz+roO/lTheuiJm6yk3yPvHzovKCNj
         M13ORl1xvuufD356uO9ims+SglVtNFoLqHMpI5Rj8A9ZsaCgH+QLBL1xVZIGGndRPGbx
         +Jj6nMovNiJdUoiuUZAyhBa3FRUY5bdoqrNsylDNWe+vAN1+67qiUPrCxv3qRcnuM/KM
         lkAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j5dV+sdEWcUaWRTSNp0ZPh4WxbOa4goYCoTO6AKSLq8=;
        b=p+CX1R7C0LCmfSjeI+CmPTA4BFKVaTLe8iLpDJcsA8EyiHm0y5xVzc11D54/owh/kJ
         ZTj5lVYwk1RlW1jYgef9qZmGXf8zdlJ9a5A4jFPkneQoa1ta3VLmvhwCPwQbOXza9jzg
         6/zlNgZ/g8HiTw6sPYgr9xdfn+GdQwr/DQ8a2Rc3ABHdHj1yNQAmruZn3ym/otHc+tHw
         STDwBjo7EoEqTbPMwGKj1pwjxZ1sUghdtnfzebL7imCvnZCAqSnlLa6dJy8HnmMH6FAi
         ei9QdoR8Zp4wYYSQso3//chloSDnkom9eDt/gGXu44oq9cGeRwOq40lJ7WuatQqsrFuy
         5zag==
X-Gm-Message-State: AOAM533yAqUm5/CIEBqjfaZczoQOImF4aycObKLb56U4Zfvw5vcrTWaF
	u1dvK5zgHUcs7z6uHalVqy0=
X-Google-Smtp-Source: ABdhPJzRNMgdTGUh22omBozL2T1LhJ8UPCqECzc1vaDCZbSl/ktxP5RpiGr1iawArnNCiEEld9L0gg==
X-Received: by 2002:a05:6602:22cf:: with SMTP id e15mr14357998ioe.114.1599576826714;
        Tue, 08 Sep 2020 07:53:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:8897:: with SMTP id d23ls3104267ioo.10.gmail; Tue, 08
 Sep 2020 07:53:46 -0700 (PDT)
X-Received: by 2002:a05:6602:26d0:: with SMTP id g16mr20724116ioo.149.1599576826339;
        Tue, 08 Sep 2020 07:53:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599576826; cv=none;
        d=google.com; s=arc-20160816;
        b=aQYZ/TOp3HoQS8jdi8eXR3YxSSUpTgUZxG/L+ma/SpuxHoVUHo6RhC/BEigHDZYURg
         8P+gGaBqNq73ZexsyXSBtXh2YSnHJ+rCvaF/raCBqsnuN9/3SDLvP/kVhyB7Vlo2J1Tq
         hOax4IzijdHDLEPWq8iK4udxAGocer8L71UAYwkCUDChnyEoXHkCQHvXWb79gVvqKGe4
         /R3Sw2nCFZe5L3sxnWbazvnvO3l/3ZrnuwuykpKK9SCz61Gzw8uTeYHhsCoaUlBXCgpr
         8tjVLkaFIdfzPv8ViRIXopZxkGjZGh5umCFinw2J/eOWgTw61/LXKu0oA1NNC6MHUaGK
         Zp6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h4oc8hr/YvrS6TIcr2rM+0VMi5Y0HYQXm5AxoqLVhU0=;
        b=vtLjibP/KrVmNSDkzJJUDohBshSjvPNK3vF0beUZBHvcxwwWDITmnedysuWrsEVujx
         ENYbjiSrZfJQtgp+wznkS7T0LaqDIYczTERplxjV0nLpp12YRZ0TwoCM/i0ZlK+VjwGL
         YxZujIPSrOKEATNc/TqI5hhcvnYMJF2JTyVC4549wrFd7K4d4FR0D/1Ujtm1Nbj77yRu
         7jaIjc86c0IodhraP+e2vtBMY3rK4vnbkploThiVNruc2qrXYI2N8fb6gLCrXaH2wSwr
         ciFl0+QV+he4hqtX681GxZRnkRwUNG/afmy7MmGf74j7a6X9v8Ddf2ac6u9a9X54Sk0h
         CSZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=M3kd1XId;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id k88si1311372ilg.0.2020.09.08.07.53.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 07:53:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id x123so1021772pfc.7
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 07:53:46 -0700 (PDT)
X-Received: by 2002:a62:7cd0:: with SMTP id x199mr710416pfc.114.1599576825487;
 Tue, 08 Sep 2020 07:53:45 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
 <20200827103819.GE29264@gaia> <8affcfbe-b8b4-0914-1651-368f669ddf85@arm.com>
 <20200827121604.GL29264@gaia> <CAAeHK+yYEFHAQMxhL=uwfgaejo3Ld0gp5=ss38CjW6wyYCaZFw@mail.gmail.com>
In-Reply-To: <CAAeHK+yYEFHAQMxhL=uwfgaejo3Ld0gp5=ss38CjW6wyYCaZFw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 16:53:34 +0200
Message-ID: <CAAeHK+wZtsoPXe-ZiMJM-SdxBrraxUTfbZ5oJR8SR05qcZcQnQ@mail.gmail.com>
Subject: Re: [PATCH 24/35] arm64: mte: Switch GCR_EL1 in kernel entry and exit
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=M3kd1XId;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::442
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Tue, Sep 8, 2020 at 4:02 PM Andrey Konovalov <andreyknvl@google.com> wrote:
>
> On Thu, Aug 27, 2020 at 2:16 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> >
> > On Thu, Aug 27, 2020 at 11:56:49AM +0100, Vincenzo Frascino wrote:
> > > On 8/27/20 11:38 AM, Catalin Marinas wrote:
> > > > On Fri, Aug 14, 2020 at 07:27:06PM +0200, Andrey Konovalov wrote:
> > > >> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> > > >> index 7717ea9bc2a7..cfac7d02f032 100644
> > > >> --- a/arch/arm64/kernel/mte.c
> > > >> +++ b/arch/arm64/kernel/mte.c
> > > >> @@ -18,10 +18,14 @@
> > > >>
> > > >>  #include <asm/barrier.h>
> > > >>  #include <asm/cpufeature.h>
> > > >> +#include <asm/kasan.h>
> > > >> +#include <asm/kprobes.h>
> > > >>  #include <asm/mte.h>
> > > >>  #include <asm/ptrace.h>
> > > >>  #include <asm/sysreg.h>
> > > >>
> > > >> +u64 gcr_kernel_excl __read_mostly;
> > > >
> > > > Could we make this __ro_after_init?
> > >
> > > Yes, it makes sense, it should be updated only once through mte_init_tags().
> > >
> > > Something to consider though here is that this might not be the right approach
> > > if in future we want to add stack tagging. In such a case we need to know the
> > > kernel exclude mask before any C code is executed. Initializing the mask via
> > > mte_init_tags() it is too late.
> >
> > It depends on how stack tagging ends up in the kernel, whether it uses
> > ADDG/SUBG or not. If it's only IRG, I think it can cope with changing
> > the GCR_EL1.Excl in the middle of a function.
> >
> > > I was thinking to add a compilation define instead of having gcr_kernel_excl in
> > > place. This might not work if the kernel excl mask is meant to change during the
> > > execution.
> >
> > A macro with the default value works for me. That's what it basically is
> > currently, only that it ends up in a variable.
>
> Some thoughts on the topic: gcr_kernel_excl is currently initialized
> in mte_init_tags() and depends on the max_tag value dynamically
> provided to it, so it's not something that can be expressed with a
> define. In the case of KASAN the max_tag value is static, but if we
> rely on that we make core MTE code depend on KASAN, which doesn't seem
> right from the design perspective.

Thinking more about this, I think we've actually discussed moving
KASAN_MAX_TAG to somewhere in low-level headers, so I guess we can
reuse that and make gcr_kernel_excl a define. I'll look into this.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwZtsoPXe-ZiMJM-SdxBrraxUTfbZ5oJR8SR05qcZcQnQ%40mail.gmail.com.
