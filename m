Return-Path: <kasan-dev+bncBCCMH5WKTMGRBM4RUP5QKGQEB7TGVPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 7DE67272A56
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 17:37:24 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id b17sf4289060ljp.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 08:37:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600702644; cv=pass;
        d=google.com; s=arc-20160816;
        b=hb+JKFf8SSIy1zZ3WFPVWbjx/MxtxMuUQyhyaKlCQBHitVUQYDBctQQmSia3bXcuvS
         cHQIWy93KQpuVLUV2rs7HqA94ctO4ABzcTNvLgh03jXj/j77xpfQ3xrWZX/Nv1WiWMx+
         BUccZldAWitPFnPxUKmfMtNcIpAfL6c4LGyYoLKXtRC4uNL0oeishuN6gtgXstJEdAOl
         IZE7vL/7T0m11OJmmuglddwIC//dLXAnYgGvbXubIwQ1Q8119OldDYa65u6sF+SlAgS5
         9kzxt0h2+GlB0x0K10ypA7XGl/TjWvPV0l6+4xmDVJOM8nXktuF9iSXpz0AOXZc3nNap
         evkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ZeoMTV7nmCzmZszpl/3tmk529dTy11IbB7QWjHSVJeA=;
        b=sQJGBzpM9FCjRcsRPOldQSMj/EBzFCP4vU7Kr1ElELTmhol9GpBFLWnQDb8eqBUG6v
         JQZYGsP9DAfLTA+vYcZOmy8qFcgCjJQKfD34UU4+lC7o/z/Qy0xPT8/DNEMatiUNz/2y
         0yrEEC+cB+V7JxwJTpWLa3bJzRqU36MbEMhybn4AZJ2tLHkRWdxdPt5cGb73cXa4tLqc
         D/olR3bQMnCG75nkpVCos4vT70/Dp6HbcXWIjvQklP2xoearzu6DKrQ23vaLJ5K3Mc/e
         zCQtHzTqmLVBQM6DdkLplOl8k9X4it4PEUAM/LQtD5JswNaL/8lnwwKCnK+izN8sjMUx
         mv8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BYc74rVc;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZeoMTV7nmCzmZszpl/3tmk529dTy11IbB7QWjHSVJeA=;
        b=gv6NCyrT4bC6PWsXeba/1lKUrVfJ+3+mrJ4+PbCUlUw5ZkKRmtWr9fCyGtBUgyKlSz
         aNt7KL4Y7o9HhGJntSnzvhuOB4Xi53nGdSovM512KuVg7uEDjEgKWnBa213Wox8ouMUF
         FApgllru886+a+6XSYp8cfvRRo7pfB4JMNSM3oI/RTtR/TlpBG23Ez7SUvOX3REP8ynS
         Svsr0sFiPv0KkzWPoPKM4bm2Lmysi0MNHoSWO8Uiw7iKwQLTNXQasSbrM2NsI9l7jbL0
         kzEe2RtBONxRGL7kLIcoXblVbEG8BIV5NQzEqHWpIw24fZV1Vl3aur8Svj3Xi8hnSm4e
         419Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZeoMTV7nmCzmZszpl/3tmk529dTy11IbB7QWjHSVJeA=;
        b=OWaIO5IMIlqCYsViGkLuG8jpz2YGofW4nMXrGVRf1DEeK6tjkwI0xztFlBugCvDZee
         B0JtkVNuI7HTiaEO7UyWhApSo1fySfvlt2kRUR1oQBdffxmnxT0ofP2UZh83z2JxhndG
         B2fpr3yEPk1INaTjoEDu8N0rot9/VSOtQouB2qRS+3nebJfVHf8bAkFpmQZOy9nc806G
         RpHHo9MCAf6YhsP3X73wgsfqAzUaQRbaNBgK4b5Xgyjl7dNfcSuUEVc+y4k9ORR3gDyp
         Kl1yy8gFOu7RWkdxtvDVGQjUafN+RjsZP9P3MCi7HDD0gyburs2klJJW/NI+581rR37g
         TvzQ==
X-Gm-Message-State: AOAM5320Q5klM4WMkwuvp+yPCc2QPfT0gO/sITNLIRi9+QFXZ6TTSl5l
	4+pfOyZhtX4txRMlngbfCls=
X-Google-Smtp-Source: ABdhPJy4GbQ4BkO8gRMJ6++Q704Q4ivRrf2R50KRq4pXoucpCyixH6+Osgd+1RjJkkh3/S7itEe/8w==
X-Received: by 2002:a19:8c4a:: with SMTP id i10mr184327lfj.566.1600702643945;
        Mon, 21 Sep 2020 08:37:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7c08:: with SMTP id x8ls1752344ljc.6.gmail; Mon, 21 Sep
 2020 08:37:22 -0700 (PDT)
X-Received: by 2002:a2e:808a:: with SMTP id i10mr90484ljg.313.1600702642756;
        Mon, 21 Sep 2020 08:37:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600702642; cv=none;
        d=google.com; s=arc-20160816;
        b=OzukM2K24zqE0RQrqI/1tP02FOgJkITEKvfg2/jsaR66HTy95WvBbfCmdqXJCYdu7+
         2eFZM8Yej6WKP94sEoCE15J+fonjMwvzbbk2Fj+bDVzTCYaUOaTk7QuFqLgI++N1/DMh
         DCiAhszD8r1Pf3Y/zJ8JEITFdOBZONJkRF24XCjgS+omX5aB8P2rOpu/jtdkp6YcH3oK
         5ghGwSL3NzzqfFjwkVPpZ3wEScnNi61v/YbhzQs9kvebcoB+sTUfLEyh0aSGvwwrasPs
         IBu9w7s4AIebjVzT8uzFsacj7u64h7jhFTNVDaw1JDVdfZOsjWG4gsOb7aReLhm255Me
         ZimQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kVxfXE34UyHx4a9aedDaVHUi6pKMiF4098HvY7EGT4c=;
        b=AQin80/eVqfPnBC4rdHqhrBem9IJiCI4w0ckjahicjwUiwy9/mB0rXjONBp4TSQDLE
         +8WQsTSjTb2mQDQMGir76PvokQsrav8GrtJEcwK4Z+/21u0EJ32pEHoGjOv94K93d3Yj
         eM/6PSrkz9Rq94teUepNMb2ZZCHO5iR6XLvD23cKdt+gqpoekeJFhGYLlzr1HVCbML2F
         3JJriWW5iWOikiXiucA2WTeZsIAwYN5pNjV+jh4uLqBF6Jn5A4rmVWmdo+Hl5qNIZoLj
         CMPyNRv8xMNp8NqJWjEyH0vZxHUxWtxF/RRPuC9ABTT5+W0meKwNpSueIZM0YBRl52jC
         VKYw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BYc74rVc;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x342.google.com (mail-wm1-x342.google.com. [2a00:1450:4864:20::342])
        by gmr-mx.google.com with ESMTPS id j75si322263lfj.5.2020.09.21.08.37.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 08:37:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as permitted sender) client-ip=2a00:1450:4864:20::342;
Received: by mail-wm1-x342.google.com with SMTP id z9so13213241wmk.1
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 08:37:22 -0700 (PDT)
X-Received: by 2002:a7b:c4d3:: with SMTP id g19mr199189wmk.165.1600702641972;
 Mon, 21 Sep 2020 08:37:21 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck> <CAG_fn=WKaY9MVmbpkgoN4vaJYD_T_A3z2Lgqn+2o8-irmCKywg@mail.gmail.com>
In-Reply-To: <CAG_fn=WKaY9MVmbpkgoN4vaJYD_T_A3z2Lgqn+2o8-irmCKywg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Sep 2020 17:37:10 +0200
Message-ID: <CAG_fn=XV7JfJDK+t1X6bnV6gRoiogNXsHfww0jvcEtJ2WZpR7Q@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Will Deacon <will@kernel.org>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BYc74rVc;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::342 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Sep 21, 2020 at 4:58 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Mon, Sep 21, 2020 at 4:31 PM Will Deacon <will@kernel.org> wrote:
> >
> > On Mon, Sep 21, 2020 at 03:26:04PM +0200, Marco Elver wrote:
> > > Add architecture specific implementation details for KFENCE and enable
> > > KFENCE for the arm64 architecture. In particular, this implements the
> > > required interface in <asm/kfence.h>. Currently, the arm64 version does
> > > not yet use a statically allocated memory pool, at the cost of a pointer
> > > load for each is_kfence_address().
> > >
> > > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > > Co-developed-by: Alexander Potapenko <glider@google.com>
> > > Signed-off-by: Alexander Potapenko <glider@google.com>
> > > Signed-off-by: Marco Elver <elver@google.com>
> > > ---
> > > For ARM64, we would like to solicit feedback on what the best option is
> > > to obtain a constant address for __kfence_pool. One option is to declare
> > > a memory range in the memory layout to be dedicated to KFENCE (like is
> > > done for KASAN), however, it is unclear if this is the best available
> > > option. We would like to avoid touching the memory layout.
> >
> > Sorry for the delay on this.
>
> NP, thanks for looking!
>
> > Given that the pool is relatively small (i.e. when compared with our virtual
> > address space), dedicating an area of virtual space sounds like it makes
> > the most sense here. How early do you need it to be available?
>
> Yes, having a dedicated address sounds good.
> We're inserting kfence_init() into start_kernel() after timekeeping_init().
> So way after mm_init(), if that matters.

The question is though, how big should that dedicated area be?
Right now KFENCE_NUM_OBJECTS can be up to 16383 (which makes the pool
size 64MB), but this number actually comes from the limitation on
static objects, so we might want to increase that number on arm64.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXV7JfJDK%2Bt1X6bnV6gRoiogNXsHfww0jvcEtJ2WZpR7Q%40mail.gmail.com.
