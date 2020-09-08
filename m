Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7E3335AKGQE3ZKNG7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3c.google.com (mail-vk1-xa3c.google.com [IPv6:2607:f8b0:4864:20::a3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 5623E26123A
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Sep 2020 15:58:21 +0200 (CEST)
Received: by mail-vk1-xa3c.google.com with SMTP id h68sf4292334vka.8
        for <lists+kasan-dev@lfdr.de>; Tue, 08 Sep 2020 06:58:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599573500; cv=pass;
        d=google.com; s=arc-20160816;
        b=ou0zvhr1U0va/BLZ22kusadHboFJ8AJ19wf+nPVebe+3SAbnZzD6dmiGMDnQJw1w/n
         7Er5Y7hwj7JCwjyRCasKtHuXQ+oSm0e7dw+8TLWcNcpFZQmiyLve/X658AA1M3YhEnYG
         Z1vwwv0c//ChBj4s6MjH9l/Pbq5wPj1h/6tRi9sxVvFbTY+rApAFU07ALqQI796kwSuA
         oFbcvvZSmbUK5ZWdOSE+raPf0sNRlQwtntrY0TYfipMLfLfjdHQISgv6zW0chwMlPUav
         aVT6/L4uKPnFWzdX69SttUcJLz6VRjgviKAvPPq+fuM0DQQLfyu8T0rNaS9qR2r+BGe2
         o1uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Xdzh0uSbM4tplDCln2en60bLpYmePtpg8qs53EDorEE=;
        b=rO6kkjjFxUjGiEhcRo7xGExxpTY7gtumNLTAbE1+Ifl+QsHw3USJYpYz3WMoUS3vGI
         0jgmRYO6UhsESTXQkwfhzn91JInyFsN/22Om0GS/D94ys7RT/41PjDRuzHtZHODdy6Px
         n0KB5p4KipCAxCdZo5IC59tlupqzcPMJztHMqCP71RU0MmcFHMW/8sdg6WUgU+SuLoG8
         CjPdEDLaF/BUN8q9VIkAcfBzG1xSHomqLN4HHj1yzD3gsCtqCTQFFaii9GXO+GEi0hh6
         lGSSKm1/FDPRXvxGWFUv4tmEtfn9tBsU8PWiL6F9xp9RFgQfm2JjamUQQ46gYvDjL91G
         Farw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LDlIF57Z;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xdzh0uSbM4tplDCln2en60bLpYmePtpg8qs53EDorEE=;
        b=s4sl0pWa3mIeDEdPSHZJXcv6QN9Bjf1/RWNfN0huq/JsTx2hcNtYyhNy9FFI/oglp7
         eu65HKBdWq6BI7j74Oti8ZnV2mx60c+sKKGSxqduO6Xl5pepiGN2pZV8y2VrextzcdKo
         N0qVwqekI5r7KjRtyU8aZF8zWgr1BC66FdKibXZbIZVYKrcfNkmDgilBUzU8J+tgW88u
         dixHpR8fI27jOwFIG6V6NClDgVG1T9fM6AanipDdDxQk473QwGLapNCvtfA+rgKHC7hR
         2igoaRS4BzON7FEs82iVcVL3O8BlNfoNHk2RkYjzVNFVJ/wPByeNXRDcwc4HV0pess7m
         n5Dg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Xdzh0uSbM4tplDCln2en60bLpYmePtpg8qs53EDorEE=;
        b=I3arQV6GmwxXxpe4bYeZUn6uFn6dKQYYRBZT6+jZOnegPKDt4xBvkbdjTkF3AXMiYa
         XGeIvar3ewKai9l0NGxUgpt6hGydQaye0gmhFZesJBRcGWCr79pV8oWAgFKUzQvMkQp/
         BezU8Ei3pNN8HeBtN6tL1bnKLIv/k4SzXFVfYjbSuxEqRDlRZBcmK0LpieALMH8Nea5m
         cOk/cnblk7zqLK8/p7q1Xpv0vzhjS1YjiWrkBr5KqcdLApuKD8l1CGzJcqRwo2iS9x1e
         n0T3ncDmk7ceIKdQ9sOaK4cyhkk6m7YphQx+TLNTPGflAmh2IQPzvTERuuXFaTMs80eG
         F6FQ==
X-Gm-Message-State: AOAM530HqwvWTxoN6aoFlxcmxGS9IJrO/A0ojgF0tD2+dKkuMVM5vkak
	QcwFLkExWebCcR2dihjrDBI=
X-Google-Smtp-Source: ABdhPJyMhRpZo77D6e3tswLUKuxCsIuceozUi8EyCvXK2yDiGQ9DY71/A5ZzioR2UVs572HKd/OXaw==
X-Received: by 2002:ab0:6307:: with SMTP id a7mr1099356uap.139.1599573500110;
        Tue, 08 Sep 2020 06:58:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2bd7:: with SMTP id s23ls1406270uar.8.gmail; Tue, 08 Sep
 2020 06:58:19 -0700 (PDT)
X-Received: by 2002:ab0:4261:: with SMTP id i88mr13186979uai.42.1599573499760;
        Tue, 08 Sep 2020 06:58:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599573499; cv=none;
        d=google.com; s=arc-20160816;
        b=ieua0efiF9IkxvPn/iqu4oGqCXnuqoTyIA2fFOTtqY2RHnzBMWP6viP/0Ti95SRlLa
         VnwiK4Ud3dl4KHIjYlpqmxepUNE7eSB2SSphsyig6Kjpl/+bqpAw8aUXR9Od30UsakOY
         yguM2R9uN9Ysr7VHsATdJT2j44UDDEX8j241DmMC/+klafZWQVaMaeuUhAEAwIlCOB5P
         bmUlIqFGpEyR8ox0ra5jFWRn1sGItqSgjmkrKLue7jN0yszAbcRUpeJ7ZWrsQ9m6bmed
         4WzXJGpWet2csemwImEtf7UhxkETiX32eAphTWSVpY5mw5oYjlGZapjViZI4CejuIHan
         8jJQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xfiGgLfl6xBSxCvQGQIeZLhg6EqD8qTgC7ENKGicg+c=;
        b=SdnEGwiiVE9Axcu9Hu9ZFU858KZtsUE7Y2yVT/SjYTOXAK3FRVXYOmp4/FfOmuSN2H
         j2CRS2R6JSnaTc5F2Gj1+JK/+O5JLRucn5K0Q8JD59pmr4ZN6FxSH8OvwN5OwCH5+7oV
         O4BDK+14o/jf/+jfILDC+guM8k8thYYhIBbwHxROPsPYKw+/mgzRr/xd/LAwSFYyT3Q8
         v7Wal5EYXUZ3/q6bn5G4zCy0TeQ7lO7D2SqK+tHYX5RDUs1i91wY1V+q5r5SkiBOKf43
         2gPQO3y79nDIcNPUE6eUh7RKu9/xUfXkuAThCYmSwL66zWIlk4/6/LxKqLG7tJdZ9xIk
         agbQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LDlIF57Z;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1041.google.com (mail-pj1-x1041.google.com. [2607:f8b0:4864:20::1041])
        by gmr-mx.google.com with ESMTPS id q10si667348uas.1.2020.09.08.06.58.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 08 Sep 2020 06:58:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041 as permitted sender) client-ip=2607:f8b0:4864:20::1041;
Received: by mail-pj1-x1041.google.com with SMTP id mm21so8329877pjb.4
        for <kasan-dev@googlegroups.com>; Tue, 08 Sep 2020 06:58:19 -0700 (PDT)
X-Received: by 2002:a17:90a:81:: with SMTP id a1mr3972154pja.136.1599573498717;
 Tue, 08 Sep 2020 06:58:18 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com> <ec314a9589ef8db18494d533b6eaf1fd678dc010.1597425745.git.andreyknvl@google.com>
 <20200827103819.GE29264@gaia>
In-Reply-To: <20200827103819.GE29264@gaia>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 8 Sep 2020 15:58:07 +0200
Message-ID: <CAAeHK+wX-8=tCrn_Tx7NAhC4wVSvooB=CUZ9rS22mcGmkLa8cw@mail.gmail.com>
Subject: Re: [PATCH 24/35] arm64: mte: Switch GCR_EL1 in kernel entry and exit
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
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
 header.i=@google.com header.s=20161025 header.b=LDlIF57Z;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1041
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

On Thu, Aug 27, 2020 at 12:38 PM Catalin Marinas
<catalin.marinas@arm.com> wrote:
>
> On Fri, Aug 14, 2020 at 07:27:06PM +0200, Andrey Konovalov wrote:
> > @@ -957,6 +984,7 @@ SYM_FUNC_START(cpu_switch_to)
> >       mov     sp, x9
> >       msr     sp_el0, x1
> >       ptrauth_keys_install_kernel x1, x8, x9, x10
> > +     mte_restore_gcr 1, x1, x8, x9
> >       scs_save x0, x8
> >       scs_load x1, x8
> >       ret
>
> Since we set GCR_EL1 on exception entry and return, why is this needed?
> We don't have a per-kernel thread GCR_EL1, it's global to all threads,
> so I think cpu_switch_to() should not be touched.

Dropping this line from the diff leads to many false-positives... I'll
leave this to Vincenzo.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BwX-8%3DtCrn_Tx7NAhC4wVSvooB%3DCUZ9rS22mcGmkLa8cw%40mail.gmail.com.
