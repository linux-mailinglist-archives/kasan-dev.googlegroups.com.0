Return-Path: <kasan-dev+bncBDX4HWEMTEBRB4565T6AKGQEESPRTZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 6EB9729F5B6
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 21:00:52 +0100 (CET)
Received: by mail-pl1-x639.google.com with SMTP id r9sf2760111plo.13
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 13:00:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604001651; cv=pass;
        d=google.com; s=arc-20160816;
        b=ICiZuSWsehLcu4//EMdnKNn2GpyULOvdFHZMJSL8Dh51170tHnlaxrSmc+Tg+4nGpi
         lSvoKPzsOsZvPtNhi2ml3mjVjWU2v+nueKJZUoQwtViuTETmcCsl3f5mP/98QrHBjcmc
         F2HF2pn/YoY5vFqt4sGewfRn002ZQ2w7pMfOOdRq+s8HrqDnQpxbvcAf1/wenFGUFBBh
         15wooa3gmF0OqSfcptDLGJdX3AVOYq+pSnQKQnbliQ/Plo/I7eX23gofn2ypY/aC2ZJC
         JJVfmiuVl5xg+lQWjhfr0wk4Ia/Tji99ajTPImycHswOzqqsWEOFQ94PtbfpsEdQYt1u
         jr3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=TVpwlHKhPi3EtxG7Tq/0BAyj4KJXQPbR29VzzQaN/ZY=;
        b=NJDZFgAAwYh+9Jbs46u52L4Rdxc6kCQG2mhkUIMXI5E9Eo4I1WfRVxJtFAYqg3GR2m
         SKlyev8Zr53vzsSiDAbJmpwG2fLMUXKvFVykK3NInLpwO1ws7noRX0FwoNgkCCrGyjv0
         BiF2ArickLhJ/WhyennF2yEKnYQrhOKp0BEleBq5I3Ss+4tc50NXffwE3b1jrcB0LDby
         mWg7fFlYIfa52+3LOl59meyAGhxfhhDFmFii15TsL4S64nju1gY5DPKlAiPn44s4xxy/
         oru6NNQk0Sc43pa1JtBht3MXzoCOYvJJIynt0iHkBom4Zpr/LSpOzjdCB7q/LMnOxfJQ
         Nrdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iMDTwDLe;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TVpwlHKhPi3EtxG7Tq/0BAyj4KJXQPbR29VzzQaN/ZY=;
        b=gtGXjFKPuIjxW7tkp02R/8EJget52WcCe7dbuGbYzeKJAbM5cmSbagPSVuMB5a4U32
         FckjxixLa99p/jjVGKR9HkgdvQuol7onYG26tdycbkRxGcLBf2D5Zedg0pq5kcI1DDLl
         UVwCeR1FlF9Ek9Y6407S+4MHc2YuAjeH9ejDVsxhQp7w+1ePvTS62TLSAonOfVfN+zOS
         2iGKKVqCtursWwQmBdCQfYWQEp1WgVfcmYO5LqLvfdpn8pJJH/Qma97oOhCGs4Zk8Dks
         PGQWOlD8KR3+HXZIKnY9aw8nwMUtzCv8bN8srJL/zpWtYXLqfXMM9fdEzI1qXCZMMlpk
         tiCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TVpwlHKhPi3EtxG7Tq/0BAyj4KJXQPbR29VzzQaN/ZY=;
        b=rRdlXuc7vaymdyO7E6tPaxy1taD/rfW6/n2HBKVX5yiyxqGmOvHMnTuJNwuA8bhcqh
         uYHKiaiLc/2NVG/Gz+LTLn9LSXzjAKqYFMpWvt0A73KRKdl+ltm6y8b2drkgesU1Bc7o
         TCr5DN32+Nn5lZg9ajXRk4XbCIELthv5Av8rmQN0UYc8bnTNobSOMTlcctE1i4k2iQcb
         nI8908UAffPi+bCUs5m97DM9C/eb74O5AkI4XOvVVhKBUeGmPVakFQeK9UV3L94Aii6f
         g6cvrLRRoX8MUXKQYDqZjkW3VCYbpuIf8bJVTI/o9tpPqsAbqZ7Pn8C7oATs7HdSbn+b
         VU6g==
X-Gm-Message-State: AOAM531I0B9h2OfzWD58yWfdvdN0YreB/mjWhqYl3mmIfe1fDKn69uIe
	xbl1/rMz3z3rVCuLRV7s98w=
X-Google-Smtp-Source: ABdhPJz620AyAMBmOLid6fXPtUGv630g/j3LR4KH7ZGIEhIwNvJRPIiWUco/NB9nDgIrzppIjLsX1Q==
X-Received: by 2002:a63:c211:: with SMTP id b17mr5283524pgd.195.1604001651129;
        Thu, 29 Oct 2020 13:00:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:b56:: with SMTP id a22ls1442318pgl.6.gmail; Thu, 29 Oct
 2020 13:00:50 -0700 (PDT)
X-Received: by 2002:a65:56ca:: with SMTP id w10mr2329380pgs.204.1604001650207;
        Thu, 29 Oct 2020 13:00:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604001650; cv=none;
        d=google.com; s=arc-20160816;
        b=za5dYYjxJ/Q2YqwM39pGNNMvMcLRf7eMZEns0YuUnZGaA/ymNn2CrLf2tv8psYhpK6
         TY6FI3j2gZDqot/vyZUMcSePZdmrh0T+QVZhnUV4UAmDqk14viQhjznDStKaBx551qzJ
         qlNvRnYfWN+2Ly/1xALJjeDQekJUKOkP3gHjs8vi6yG88rkm+YeQM3ITmM4rKDTtpLck
         aZuWBCN/umf5741NdBWKAlmICwFn1Ur6nJgNqzOfytEiWZrKmVDwsDZp6LJCiF5+C4AF
         4YaTK5Q2uUZSM14zBu3LV4mclDIGjrWEHqU19ohQfvtO7mI3DaJVrRwEc4tZHBS7Z/Wq
         smFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lCP1WO1+VHzaoW6B3s0gmUP2QnpBjOsDZXHhfza/ed8=;
        b=srTdl/h2EGMJSIeH98u53UEXQBTlF3wPkClEplvMm1qArhQoh7wjSeToTgl6Va0rZH
         2qiGXDr6LQq5wWrusyKgSfIZ4u1n6dAbNajghCq4Rjvu5OSzHVz2S3CV7dJ5z/+qbpDa
         69NZjcjD760CHiKzYJ1lvm38vL7VEdqsjiGuP1vKiKua3UojtcPq/5iAT4B516Ttjfvc
         8n/9XfV8DgUYZfdBAQ9xQaWq9Gc1bTap1c8lKJH9w2ErRontP2Q27KU+tv6kAZYbqeSH
         Offudm4QAtkj4wF8rcKW4aFtT5mXbYzg8e0+xFiwjinDnAzO4fYsEeT10cDo2B+4DNMA
         hQPw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iMDTwDLe;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id t126si328245pgc.0.2020.10.29.13.00.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 13:00:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id 15so3220088pgd.12
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 13:00:50 -0700 (PDT)
X-Received: by 2002:a17:90b:807:: with SMTP id bk7mr1438790pjb.166.1604001649764;
 Thu, 29 Oct 2020 13:00:49 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com> <1049f02fb4132390a6a314eb21dccfe5500e69d6.1603372719.git.andreyknvl@google.com>
 <CACT4Y+a8e3c54Bzf5r2zhoC-cPziaVR=r89ONxrp9gx9arhrnw@mail.gmail.com>
In-Reply-To: <CACT4Y+a8e3c54Bzf5r2zhoC-cPziaVR=r89ONxrp9gx9arhrnw@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 29 Oct 2020 21:00:38 +0100
Message-ID: <CAAeHK+wKWrhBC0V8Y=FEj8Cz+DuLdpEMy3KXeF96dyNc+L7qSg@mail.gmail.com>
Subject: Re: [PATCH RFC v2 05/21] kasan: allow VMAP_STACK for HW_TAGS mode
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Kostya Serebryany <kcc@google.com>, Peter Collingbourne <pcc@google.com>, 
	Serban Constantinescu <serbanc@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iMDTwDLe;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::543
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

On Tue, Oct 27, 2020 at 1:49 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Oct 22, 2020 at 3:19 PM Andrey Konovalov <andreyknvl@google.com> wrote:
> >
> > Even though hardware tag-based mode currently doesn't support checking
> > vmalloc allocations, it doesn't use shadow memory and works with
> > VMAP_STACK as is.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> > Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
> > ---
> >  arch/Kconfig | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/arch/Kconfig b/arch/Kconfig
> > index af14a567b493..3caf7bcdcf93 100644
> > --- a/arch/Kconfig
> > +++ b/arch/Kconfig
> > @@ -868,7 +868,7 @@ config VMAP_STACK
> >         default y
> >         bool "Use a virtually-mapped stack"
> >         depends on HAVE_ARCH_VMAP_STACK
> > -       depends on !KASAN || KASAN_VMALLOC
> > +       depends on !(KASAN_GENERIC || KASAN_SW_TAGS) || KASAN_VMALLOC
>
> I find it a bit simpler to interpret:
>
>     depends on !KASAN || KASAN_HW_TAGS || KASAN_VMALLOC
>
> due to simpler structure. But maybe it's just me.

This looks better, will fix in the next version, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwKWrhBC0V8Y%3DFEj8Cz%2BDuLdpEMy3KXeF96dyNc%2BL7qSg%40mail.gmail.com.
