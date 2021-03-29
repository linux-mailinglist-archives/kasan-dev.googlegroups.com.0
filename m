Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQEZRGBQMGQEJJW3SPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A58134D9BF
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 23:55:14 +0200 (CEST)
Received: by mail-pl1-x63a.google.com with SMTP id a16sf6221313plm.17
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 14:55:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617054913; cv=pass;
        d=google.com; s=arc-20160816;
        b=C9cn2H6xisEldTJziJ68AqS728O4g/DcPWTMdwOrqLbeqzU6nekWASBuNoSz4oGCFT
         NhwX0pv5H/dLnpJvhFfRd1VVye1SGLNzG3YCrTtqxSsk1IyhjmQiNxOlJur25IEsCOHI
         QDSXb/lYdJBDqFfVu2xpas+Yxqu9H6z87RIAn1aZv0RbGq5jSAmevDpV6puYKs+mvgEJ
         wrQVn8LBFWd8Ya2GIADggiU5+Hain7iSXehzfi4QFQzl35Rct7iCE7CjDsGnUB3FxUeV
         YBoph9gZsiC8Q6qog9HStm1bxLfqDD3Z2QNP4s2A7dPmXkdO7n0g7qVEu/lSZ2tPH745
         OTZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IyzagYTScJw3t/1Tkhdk5P1B1me8nbKyGG0YJVVYz2E=;
        b=Wf27TzT7IqAtgFPerm74KiTSb9BJzOVZfLzitw/qmVwT3NNPLyWZexYhPyc7Ba9mxh
         8wI2rxfXOWjbq/ezlheRlS8dk99ps/CM/Pk8pyPx2v6ouQvwWxI9AJZjxUBYq5gMdyKW
         0BN0SH3VEsd92l+WCi6Z8ZJDUaaUWVZGCG76vQbQ+oQhEGcY4bE3gap0PR2YCyWyCMpP
         do6gSUVC5RcJntNQdprUtsSnmPG74eTrcaTgBvuzYjl2DMGBUsPwXPpZVauJ/2GyX3DS
         GRGpB6GaCD1i1vMxACiyfRsT4WLlK+x99T1cysGQK1ZNIhbzSz3Q7byzgQFHMgtT8Bdv
         3+5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S5OHFkj9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=IyzagYTScJw3t/1Tkhdk5P1B1me8nbKyGG0YJVVYz2E=;
        b=Dx4XRV0+Uwh1P4VYoIuzsvW56F3kputTw+6TdyDhgbE0AWganqMAn4FtZOxFKf/31+
         oarZj3GP4mkRQk4gPzZoVRkm9jbqXo/NN/cWHwmrDbFpUm1I7a0khpmjFwtqqg4DO4sa
         hgjT5ZmEjqYamcJAp7IRzmHpasnxK4KgyJj5T1+x+7EMJ+SQWtnpGr4RhMMDJd+mSdqi
         KsZO4p0/u63EPEiGBYmUq+BrJW8SQq+JbyZCxmcKaYjYhTaeBHhhuUFQ4RG/0392cRrO
         9iVl2wW0kIFPTuTnVe8yhP6BRdO/4OjyqZPs6cJn4J8O+pZ6z9BCZhmZqeAs57iQFYgk
         90Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=IyzagYTScJw3t/1Tkhdk5P1B1me8nbKyGG0YJVVYz2E=;
        b=ulYohXMKLFhF3BNp5kSAZUGsQylfso4P/j8veJBoWXsBxO11zFwameQP0cOdwz16UC
         EP0glLu+QTltbBHsYlaYeHaNraFyEsl0pUMOPR8Mso98+G1sZr+59fI4OynU1jn+MwWN
         1Kis2BGvDqsXZynafVCER/fOrVEJQUBhhJ/n6t3OogZqiz9xq7fR9fmZsd/PHCxb7Uvd
         tSNOI7z/G3+Uog4Q0WBxbItXgDJIpPLFwgG07rQnTWQQSxGVGa11Rg2QGV4GPwq7yBiP
         s2SawIFBgwnbiqR8rtn57/fOH/JZc6LBYCaM82VPlAJLR4AJx918gP5p2lzE9g4MJ9jC
         cVJQ==
X-Gm-Message-State: AOAM532PBOX6jUfddsrz++bLsnFRkflZe8fdfDZ8n7a5eN6zAbU4el3v
	YgloJfzOrIOtflzZDvwzLyg=
X-Google-Smtp-Source: ABdhPJzuBDFdgqUURQNzjCjyx0BBjyE7cQhZ6BEzK3GlNKmEgJM1sIY2ScG2MuxYQjcVgEUyKSNxYg==
X-Received: by 2002:a63:2507:: with SMTP id l7mr25915912pgl.198.1617054912840;
        Mon, 29 Mar 2021 14:55:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:eacc:: with SMTP id p12ls9605855pld.11.gmail; Mon,
 29 Mar 2021 14:55:12 -0700 (PDT)
X-Received: by 2002:a17:902:5608:b029:e7:32fd:ce99 with SMTP id h8-20020a1709025608b02900e732fdce99mr17621146pli.0.1617054912312;
        Mon, 29 Mar 2021 14:55:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617054912; cv=none;
        d=google.com; s=arc-20160816;
        b=p+xTCGjtJ35UnbjGaQQEMJTBI58LEFV+ozw3lHc6QWS0i+wwxC3v0hKHRP41iB+SgS
         +VDC/+ktuWy2zsEPfj9z42y+KmZtBBFe1SmalZZCWaknIH+g0lkCwpQZiDeQkxkuwYGx
         qdbsbygMHu/KImlrx3fCOSZc+Fm7mlNJ/uWB5WzCRwK3YmCSnOIp463S73wZR/rtHEWq
         vlN/xcHJDuB0kRMgJsXhhfuTEJKWz9+oq26zJTS3XkHOIJ7dSixHNATwLlwR4QWFiZkG
         xrTCSMSglVFrBjzbEIgSia+dor+gDSp4aCHIuDWx57qFLUUeIFnOuaU1StDxOwBKZ9F9
         idWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=lXwK9TDHJMeRrnXTHqrcsnlfyiEUU93Inkgor2Calrw=;
        b=KrMQzxvSrYTpFCo0Q2fJm1j0r353Md99VeXuDyrvl8RE41UatrF9sjYTKHsxPx2XYJ
         oSk7GGDVc34pVQAEvFQbgjduaqAxjnOoeBFQp3JGBraYvhyqaBH+FJyTjdL6SpD7CPGz
         AIi1BSK9egeP1NyUlm8rgXAuV3GKPDpQv9rnSaLFQjnGZbgsvo+JDLIYd3gui4iGGXf3
         WGCm/1NXRPTj/EiqFKmv8o4CWlmT86OgbHn+DJEksMvEy+Vo4foo27ekt4lT7RSsS80O
         R/AKwe0vOKCH5SbCcNQt5Xvz/60i9DZ3VxzEkEJ0H8UhoadIfZ6PsI3Sorkqc8kfKCcL
         Ratg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=S5OHFkj9;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32d.google.com (mail-ot1-x32d.google.com. [2607:f8b0:4864:20::32d])
        by gmr-mx.google.com with ESMTPS id t5si1108265pgv.4.2021.03.29.14.55.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 14:55:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as permitted sender) client-ip=2607:f8b0:4864:20::32d;
Received: by mail-ot1-x32d.google.com with SMTP id 68-20020a9d0f4a0000b02901b663e6258dso13672665ott.13
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 14:55:12 -0700 (PDT)
X-Received: by 2002:a05:6830:148c:: with SMTP id s12mr25234396otq.251.1617054911480;
 Mon, 29 Mar 2021 14:55:11 -0700 (PDT)
MIME-Version: 1.0
References: <CANpmjNPjj7ocn6rf-9LkwJrYdVw3AuKfuF7FzwMu=hwe7qrEUw@mail.gmail.com>
 <ED2525DC-4591-46D1-8238-0461D5006502@amacapital.net>
In-Reply-To: <ED2525DC-4591-46D1-8238-0461D5006502@amacapital.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Mar 2021 23:54:59 +0200
Message-ID: <CANpmjNO+_4C0dYs6K8Ofy-xVSYxO8OtXSRbW6vCXBYdjJSjqbQ@mail.gmail.com>
Subject: Re: I915 CI-run with kfence enabled, issues found
To: Andy Lutomirski <luto@amacapital.net>
Cc: Dave Hansen <dave.hansen@intel.com>, "Sarvela, Tomi P" <tomi.p.sarvela@intel.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=S5OHFkj9;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Mon, 29 Mar 2021 at 23:47, Andy Lutomirski <luto@amacapital.net> wrote:
>
>
> > On Mar 29, 2021, at 2:34 PM, Marco Elver <elver@google.com> wrote:
> >
> > =EF=BB=BFOn Mon, 29 Mar 2021 at 23:03, Dave Hansen <dave.hansen@intel.c=
om> wrote:
> >>> On 3/29/21 10:45 AM, Marco Elver wrote:
> >>>> On Mon, 29 Mar 2021 at 19:32, Dave Hansen <dave.hansen@intel.com> wr=
ote:
> >>> Doing it to all CPUs is too expensive, and we can tolerate this being
> >>> approximate (nothing bad will happen, KFENCE might just miss a bug an=
d
> >>> that's ok).
> >> ...
> >>>> BTW, the preempt checks in flush_tlb_one_kernel() are dependent on K=
PTI
> >>>> being enabled.  That's probably why you don't see this everywhere.  =
We
> >>>> should probably have unconditional preempt checks in there.
> >>>
> >>> In which case I'll add a preempt_disable/enable() pair to
> >>> kfence_protect_page() in arch/x86/include/asm/kfence.h.
> >>
> >> That sounds sane to me.  I'd just plead that the special situation (no=
t
> >> needing deterministic TLB flushes) is obvious.  We don't want any folk=
s
> >> copying this code.
> >>
> >> BTW, I know you want to avoid the cost of IPIs, but have you considere=
d
> >> any other low-cost ways to get quicker TLB flushes?  For instance, you
> >> could loop over all CPUs and set cpu_tlbstate.invalidate_other=3D1.  T=
hat
> >> would induce a context switch at the next context switch without needi=
ng
> >> an IPI.
> >
> > This is interesting. And it seems like it would work well for our
> > usecase. Ideally we should only flush entries related to the page we
> > changed. But it seems invalidate_other would flush the entire TLB.
> >
> > With PTI, flush_tlb_one_kernel() already does that for the current
> > CPU, but now we'd flush entire TLBs for all CPUs and even if PTI is
> > off.
> >
> > Do you have an intuition for how much this would affect large
> > multi-socket systems? I currently can't quite say, and would err on
> > the side of caution.
>
> Flushing the kernel TLB for all addresses
> Is rather pricy. ISTR 600 cycles on Skylake, not to mention the cost of l=
osing the TLB.  How common is this?

AFAIK, invalidate_other resets the asid, so it's not explicit and
perhaps cheaper?

In any case, if we were to do this, it'd be based on the sample
interval of KFENCE, which can be as low as 1ms. But this is a
production debugging feature, so the target machines are not test
machines. For those production deployments we'd be looking at every
~500ms. But I know of other deployments that use <100ms.

Doesn't sound like much, but as you say, I also worry a bit about
losing the TLB across >100 CPUs even if it's every 500ms.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNO%2B_4C0dYs6K8Ofy-xVSYxO8OtXSRbW6vCXBYdjJSjqbQ%40mail.gmai=
l.com.
