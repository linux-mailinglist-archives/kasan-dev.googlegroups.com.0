Return-Path: <kasan-dev+bncBDDL3KWR4EBRBX5JUP5AKGQEJVERZNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B2A5255816
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Aug 2020 11:56:49 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id v15sf404425ilm.17
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Aug 2020 02:56:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598608608; cv=pass;
        d=google.com; s=arc-20160816;
        b=oHDZgIwWI6AiVbhCgbIp9/phFhTnzYgA9UXL35lIoOqvlq4hLKLJuQ7yW6k6iI++Ss
         e+UwyjHvuJeqkMOIs81YbDryRFIgvPxwmZFXkPtR87ZXrLUNgdj8KCyvC09+SZq8CiJC
         bzROyq7fjtFtK8UGSjVfVVt3CZ7eBQA3jiCZu4yvMuZ94TUTKOFMuWBs9syN4lJhvp3q
         jPwXsLrh1gvlbwwHNJER0WUAHIA1KlpyLCRsi64B5vG56hXEwqSMvP4i23aWXZ4GMkVf
         3cY0Y+87H3HoUU3kY/zQXCiTwHULSkQ6y++1U4at7MVa/hJY1AiXTwJITUpVpm1F/r+U
         McqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=tZme0d/AbJMaGymJQgtG73ZpI710xhD4nrQPmeVcjWk=;
        b=IL/NGOY53qZuYSzrUn5OZdFMUlI0gRy0/HOdDOHrIkhQa9yPU1pC2vHB7LOCGoEMFJ
         uqWH12enADww4VLZgHEM5GuczUhWkh/C/9gRh+iJpotPMIoTahk6f0RfOeq7a4t6N+N5
         gxUOXqkYZ0Fv6m0H30QbYvrKaRf0hR5Q9dgrkG/z0xBcp6t4Q22dYK1JaJsicUV34I+F
         nM9Pf//o4jw7WqkbhU/b8l+GTm5V02KtH/IzsZ2Z2NfisP0hoWbgYov6VBibJhdjQGwh
         Hw67zgnMpnoX/k2VJulw3OcfeZdkgDd1ixuYRoi1oqoVDV/yyWda6WBEzjYsFRWdkPVW
         Wr5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tZme0d/AbJMaGymJQgtG73ZpI710xhD4nrQPmeVcjWk=;
        b=D/ek1ktgVi3QPNZ27P/lBhYmHgXwJb4j/FE1zsF5CAfV8Of+oUDOwvGXdExSbNQHf3
         XERUyr1D5iyPAddxGPLdsIULB5PN0XtZOLMiM8M4g6v+j1S7pcMUPjML+uFk+yh9RBrA
         NGcFNatEsJ/7cTjr5ylrF1CxAGnQ8V1eXu6Lxo5FnEa3wCF7/XPgFR9pqdxEdhZBKBVr
         JE30gQkF/eLTEJMikW+36v0JifB38RxO3tUlf/H57i9vgL/kU4SwOn6m7Ds8LwZWKgg8
         9mXORBtPU6jLha0TIsVy343l4zlS8kq6EbtIL2G7WH+Ij9QRgHMkFcNGwdpb1+Y27bpa
         9I5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tZme0d/AbJMaGymJQgtG73ZpI710xhD4nrQPmeVcjWk=;
        b=A5az+5PiDHYCdAsjmelousNK33me3CrFw1ICuSHB7IhcKoTsPwbquQcD+lNekL1nrQ
         Wwdx1JXP5Mkupytb3MUn+nUzxmew7e92tU+sGBDJumb4AOHK0YfckmZf7juS5wLECIxB
         YKe3TkixcjGZzsZr9hghJfhy8dDuLJjINQSVwR6TZKrK6Q5WADpXjIjgyRH7d4UsDRjF
         AL2rLTO2mC8iT91H2r0cqmzOaGiQCrPezL9GQAbJVJikxdul3668DJm+ZVn2MfsO8xIc
         HNOXTwuJwVE7gAFYZ2IZhoeVSeELbqFY2u4F0tNSUdhkEm2Ca3GVLfNA2muHVodc0g/n
         mSNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533fVHtGGa4hCt4JRJ/0kpD0BcKOoJrWuv/WE/mtIWzD5hUrfzy1
	v5IgOg7sD0ahMtO+JPM4C/o=
X-Google-Smtp-Source: ABdhPJzCyjwPgvrcKCefkeCAqoijoBkRMTIE0emk13iLftSoGRD1Of4++yCXQ8jzdWx8vwcMSXBwwg==
X-Received: by 2002:a5e:c00f:: with SMTP id u15mr661873iol.6.1598608608088;
        Fri, 28 Aug 2020 02:56:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:1489:: with SMTP id j9ls92279jak.4.gmail; Fri, 28
 Aug 2020 02:56:47 -0700 (PDT)
X-Received: by 2002:a05:6638:2653:: with SMTP id n19mr442968jat.34.1598608607720;
        Fri, 28 Aug 2020 02:56:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598608607; cv=none;
        d=google.com; s=arc-20160816;
        b=Tc7fwAHTWgKZcqhy2vLn0WhmK0cwhZKHyJCb4e2MNc5aQjvPR/vOkG23xBvy7ZTdVt
         d/MujZH/bbrk4da662Brx7iUljF/V5ZCsmMgbIldeYai68mhPOh+7SpVjDc2+h4EGkn7
         BfN8sCd9eJ8zEf6rEOHBhidwnC1sRAm+Qy9WJPm1MAIxsl8kw6MZ5qNMSvTLBAcMJ6yZ
         0wNOlnDuXbp9z1ajoQ+IQEZUTCyN+PLJV0Kr+qtlJY41w+7kU3SXdmng2Cx5vTE4jonn
         MU20dCzBzOBCUOlaDRxP9yZiEQjwlsQsLrPoI0hHtrjWHCvQucAaWM9MeZ7JNiBUDmmF
         689Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=G6SBICsoo4KmrgAoqg80mPXmPRpG8yWjGtFzEw2Nki8=;
        b=owMXt8tXyM7Sm/sN9SzmvUuElhjSYNkOe5klyYWGt1y7cghsHo2JyXR/ZTuWBD/P3s
         9YN9uoYbcroTw5UD8vDYqXRmRcZlhAQoln0skAkE68fOzibQwPldUT9RotUrpKo5ziSN
         3H529BvyNfNYVPyXmQqz40XHHwEkeU/Zez613nXUAoL3FovRYGO3/BH0iW0oU5Dku/BL
         K+USaNSJolvs+Yn5WU/VrbtRm0JD48Qhy8M9m6d9GgzYvKVvDmessXq5SfPp3CeXJV1Y
         VCygzY7b4Mi01f70g09WEwIACWbRGajjfuGyxGHdJymN+z+riDodS34F8iL9IX2SU0oO
         +S+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id j127si32869iof.4.2020.08.28.02.56.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 28 Aug 2020 02:56:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [46.69.195.127])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 3CAEB208D5;
	Fri, 28 Aug 2020 09:56:44 +0000 (UTC)
Date: Fri, 28 Aug 2020 10:56:41 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Linux Memory Management List <linux-mm@kvack.org>,
	LKML <linux-kernel@vger.kernel.org>
Subject: Re: [PATCH 21/35] arm64: mte: Add in-kernel tag fault handler
Message-ID: <20200828095641.GD3169@gaia>
References: <cover.1597425745.git.andreyknvl@google.com>
 <f173aacd755e4644485c551198549ac52d1eb650.1597425745.git.andreyknvl@google.com>
 <20200827095429.GC29264@gaia>
 <CAAeHK+xHQDMsTehppknjNTEMFh18ufWB1XLUGdVFoc-QZ-mVrw@mail.gmail.com>
 <20200827131045.GM29264@gaia>
 <CAAeHK+xraz7E41b4LW6VW9xOH51UoZ+odNEDrDGtaJ71n=bQ3A@mail.gmail.com>
 <20200827145642.GO29264@gaia>
 <CAFKCwrhAPrognS7WtKXV-nJN-9k6BW+RWmM56z-urvbWepTAKg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAFKCwrhAPrognS7WtKXV-nJN-9k6BW+RWmM56z-urvbWepTAKg@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Thu, Aug 27, 2020 at 12:14:26PM -0700, Evgenii Stepanov wrote:
> On Thu, Aug 27, 2020 at 7:56 AM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > On Thu, Aug 27, 2020 at 03:34:42PM +0200, Andrey Konovalov wrote:
> > > On Thu, Aug 27, 2020 at 3:10 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
> > > > On Thu, Aug 27, 2020 at 02:31:23PM +0200, Andrey Konovalov wrote:
> > > > > On Thu, Aug 27, 2020 at 11:54 AM Catalin Marinas
> > > > > <catalin.marinas@arm.com> wrote:
> > > > > > On Fri, Aug 14, 2020 at 07:27:03PM +0200, Andrey Konovalov wrote:
> > > > > > > +static int do_tag_recovery(unsigned long addr, unsigned int esr,
> > > > > > > +                        struct pt_regs *regs)
> > > > > > > +{
> > > > > > > +     report_tag_fault(addr, esr, regs);
> > > > > > > +
> > > > > > > +     /* Skip over the faulting instruction and continue: */
> > > > > > > +     arm64_skip_faulting_instruction(regs, AARCH64_INSN_SIZE);
> > > > > >
> > > > > > Ooooh, do we expect the kernel to still behave correctly after this? I
> > > > > > thought the recovery means disabling tag checking altogether and
> > > > > > restarting the instruction rather than skipping over it.
> > [...]
> > > > > Can we disable MTE, reexecute the instruction, and then reenable MTE,
> > > > > or something like that?
> > > >
> > > > If you want to preserve the MTE enabled, you could single-step the
> > > > instruction or execute it out of line, though it's a bit more convoluted
> > > > (we have a similar mechanism for kprobes/uprobes).
> > > >
> > > > Another option would be to attempt to set the matching tag in memory,
> > > > under the assumption that it is writable (if it's not, maybe it's fine
> > > > to panic). Not sure how this interacts with the slub allocator since,
> > > > presumably, the logical tag in the pointer is wrong rather than the
> > > > allocation one.
> > > >
> > > > Yet another option would be to change the tag in the register and
> > > > re-execute but this may confuse the compiler.
> > >
> > > Which one of these would be simpler to implement?
> >
> > Either 2 or 3 would be simpler (re-tag the memory location or the
> > pointer) with the caveats I mentioned. Also, does the slab allocator
> > need to touch the memory on free with a tagged pointer? Otherwise slab
> > may hit an MTE fault itself.
> 
> Changing the memory tag can cause faults in other threads, and that
> could be very confusing.

It could indeed trigger a chain of faults. It's not even other threads,
it could be the same thread in a different function.

> Probably the safest thing is to retag the register, single step and
> then retag it back, but be careful with the instructions that change
> the address register (like ldr x0, [x0]).

This gets complicated if you have to parse the opcode. If you can
single-step, just set PSTATE.TCO for the instruction. But the
single-step machinery gets more complicated, probably interacts badly
with kprobes.

I think the best option is to disable the MTE checks in TCF on an
_unhandled_ kernel fault, report and continue. For the KASAN tests, add
accessors similar to get_user/put_user which are able to handle the
fault and return an error. Such accessors, since they have a fixup
handler, would not lead to the MTE checks being disabled.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200828095641.GD3169%40gaia.
