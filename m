Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZMRRHUAKGQEPVE2FZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x739.google.com (mail-qk1-x739.google.com [IPv6:2607:f8b0:4864:20::739])
	by mail.lfdr.de (Postfix) with ESMTPS id 5428443626
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 15:00:22 +0200 (CEST)
Received: by mail-qk1-x739.google.com with SMTP id t196sf16545411qke.0
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 06:00:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560430821; cv=pass;
        d=google.com; s=arc-20160816;
        b=gi7948Kl/k/RZ/86yXKClIfRghn0naF69Gs6YfurPx/sicAFUBLPmS62VGBvbE6Mnf
         /oVuktFQX8ByJOTPnx93tGGsNF3Zsd0ACFiq/Cfvfi4j625a7NY3Flw4+f7xDuEBx62E
         M/lBvsT0K5mmZZWu9M1Iqw5x3DHMYfaZXd8PzZcGs6VdjE32yJVSdCDpvJdhp+ZyQToD
         xzrcYWfQ+f+tVlgIy5mHdNEE0zu1Qm5j5JkyPRhSfYWFsY+IbP88D3WAZdu0fL+zgVhO
         LCxo+7udV6klwZ8XMjqrzfJdjeTd5gzy16v8lm8w1q0znDHJaCXZzskTAomaB9/AeISV
         OtNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ifQd9//tK9j7/Bvv10PPmN3H+1VAntxLS/g/Q/EzWu0=;
        b=nXdMCC34Y3o2Uk7FSSjFeYTLpg6gIIgYXMro4GlbsSWYcaVF729S4t5J746JU7n+h7
         nja021/u5CnUSZDS3/iZ7kJ6j00vog5J3m5r+Gan170KtYLt02lLsBNBabI16Q3JG5W5
         BhU2QXLotuWFGuTQgpiRrL3Qe3gVmj6ZRI7M2ZziV8/tiBFgHAolK4vHxKkaFjfKB3MA
         LXss7eYyyMLe64qim4LAgYQorOS25nLQuY54D040SB7rflG1j1WAd59v0nnnPDYhUcWZ
         DUwmlJnKQ5BLfi5Mv8o/h2SFweBIyAfvBliOHZM0VGlk8gBXHUM+DqdoWni2sDDoW2Ji
         oKuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b72rTZ+B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ifQd9//tK9j7/Bvv10PPmN3H+1VAntxLS/g/Q/EzWu0=;
        b=ZhGb73LrEnTRqfKendnFErzDtJjtL9TkFT7fuiGy52GAHfibnbYCdC+1ZYATZx43C/
         X//GHqSJlvfJ4NsF4jNwuo6lD35PIHcqdwqP6EEtv8K3RwroQD+eaV0tRUVvbZ0oLJAr
         VWa4/3D90v8ihXF+8FDiEbJEpLSEbPydq99fd4/O6Yp1y8/+ahY4xlgur/325cG8i1j1
         CAqf7i8Ji9jWa7T9cQ/eXnUJnxkWvpVzOClLj5k6qoCB6t9uVJnXI60f+/ikmr5APVNE
         vOFTT8FzAfHf+/h/wIVfTftBnqw4I8Sz4oH1+FWaW8kEuNnzkm3mSfdeDRustFcuqVJy
         f87A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ifQd9//tK9j7/Bvv10PPmN3H+1VAntxLS/g/Q/EzWu0=;
        b=Ixj0RUgU44Yu0KYNmxWmjIF+fIhd8o5gKiip5F0P6qx0G3k6z7uBXnsOKXZimrFbgr
         JAse8M7hNQDM/KtBhMTmYkTLLxUimHNyuyPLtlVVzx6ZJ83ub3WJPRmegrPSPY+cJXRa
         rB5xBDICvVBXMGHCejtM6bamedfRN4rmCV6o7EPeBam/GTYdQHCf2nhf6gHhXZQe3NPU
         Hj3LLm4Fx14katgHBBibvAqIvZhlQ9VJh4v61P09gFu2Prym436aZfVCvKTX/O79RW3h
         YhVvu0p9nn+y6z3/hlNEuaf0N36ujvvEpz+NWeqdJM+nwpJvun1yn7f9uNyNkrYQ5cEK
         VKJA==
X-Gm-Message-State: APjAAAU33ZDvCx4ugHvNL7fsNuE+Vh83B5gJ/wt8tJykmj6NSuxh6vGs
	O2yeeV6NB0rw7uFZBkJaij4=
X-Google-Smtp-Source: APXvYqwN/TmbiFyh9R9W9eYhoruZSdsIE0QbhpMpLr88CEqsaK6d5WqWGtvHEzMSx7cLgUzjSn2Z/Q==
X-Received: by 2002:a0c:9253:: with SMTP id 19mr3469308qvz.180.1560430821477;
        Thu, 13 Jun 2019 06:00:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:ee67:: with SMTP id n7ls549177qvs.15.gmail; Thu, 13 Jun
 2019 06:00:21 -0700 (PDT)
X-Received: by 2002:a05:6214:248:: with SMTP id k8mr3464733qvt.200.1560430821213;
        Thu, 13 Jun 2019 06:00:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560430821; cv=none;
        d=google.com; s=arc-20160816;
        b=hHh2+Pnpf2v1+X7QLHXFXpzR81vqVv+5K1/V9jI4TqOXvdkGHtWYRB9bWIXC4uE+bi
         vES8A3plko9AG6Tz6Kj2KiVYEih2FQlTZ41VBMljpDQNZv8e1M8t/ceEX7KKUzK45UYG
         ZdWO/OugVcvDRx7qM1LhMueCU/3UXGHJyzJo+PNqeLcnKnjf7S4sC+p1RRK7ZG6YA8OT
         nt5/I83E48epuXGioQfHXCfj6irKdAaSeMjWSztgzuS8HHMy1bOzNnQS9RyqjNwgMh2t
         pNzeBMqgdENty9kpSuTusmxREWNyIdrJh1S1CRzZnnzII0JUlW1VxhkDoC2UxXQVWi92
         Z2wQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=c4JaIYgXBMbRJcuOmI53AtHtAH/wFo1Lowg4JHM/fXs=;
        b=y1HRV2NEr8DN/EEC59Z4+58uIX2EQmodyI/Q7RKrij0UKWWu/31bvORIffYVPeNBjE
         ag6OFe8vqB4Z8EFRIrdR9Fa2/Vl0aJSuaA563MIzZUQi+fVi9Hodc0AzMlyH6MYbA7W0
         rjc+q0j5HdApyyvIaAMCnDS3xVGPEdPr4y9bMYSXmSkvbq3mu2/hYL4lKG4eac6/YIru
         kPcuvHDTzk7OlCcwn8q7fwYJ/x6uRCo2mvzYP+xOBN0zW2teR5qyrVF0+hswIiDAhsYQ
         8nvSp7XuF5yG0eqVc2swzXOHWswFN22llPQX2dDNoxiiPoZsU0O2L7vTTFs3V7w6eRQL
         FuXg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=b72rTZ+B;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x243.google.com (mail-oi1-x243.google.com. [2607:f8b0:4864:20::243])
        by gmr-mx.google.com with ESMTPS id c39si156342qta.5.2019.06.13.06.00.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 06:00:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as permitted sender) client-ip=2607:f8b0:4864:20::243;
Received: by mail-oi1-x243.google.com with SMTP id s184so14328076oie.9
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 06:00:21 -0700 (PDT)
X-Received: by 2002:aca:e044:: with SMTP id x65mr2874683oig.70.1560430820644;
 Thu, 13 Jun 2019 06:00:20 -0700 (PDT)
MIME-Version: 1.0
References: <20190613123028.179447-1-elver@google.com> <20190613123028.179447-2-elver@google.com>
 <6cc5e12d-1492-d9b7-3ea7-6381407439d7@virtuozzo.com>
In-Reply-To: <6cc5e12d-1492-d9b7-3ea7-6381407439d7@virtuozzo.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Jun 2019 15:00:09 +0200
Message-ID: <CANpmjNNMmSHvP+tzod=WeoDp6jsxGsDKV5cXiTr3F9fxEMasaw@mail.gmail.com>
Subject: Re: [PATCH v4 1/3] lib/test_kasan: Add bitops tests
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Mark Rutland <mark.rutland@arm.com>, "H. Peter Anvin" <hpa@zytor.com>, Jonathan Corbet <corbet@lwn.net>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=b72rTZ+B;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::243 as
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

On Thu, 13 Jun 2019 at 14:49, Andrey Ryabinin <aryabinin@virtuozzo.com> wrote:
>
>
>
> On 6/13/19 3:30 PM, Marco Elver wrote:
> > This adds bitops tests to the test_kasan module. In a follow-up patch,
> > support for bitops instrumentation will be added.
> >
> > Signed-off-by: Marco Elver <elver@google.com>
> > Acked-by: Mark Rutland <mark.rutland@arm.com>
> > ---
>
> Reviewed-by: Andrey Ryabinin <aryabinin@virtuozzo.com>
>
>
>
>
> > +static noinline void __init kasan_bitops(void)
> > +{
> > +     /*
> > +      * Allocate 1 more byte, which causes kzalloc to round up to 16-bytes;
> > +      * this way we do not actually corrupt other memory, in case
> > +      * instrumentation is not working as intended.
>
> This sound like working instrumentation somehow save us from corrupting memory. In fact it doesn't,
> it only reports corruption.

Thanks, I removed the confusing wording. Sent v5.

> > +      */
> > +     long *bits = kzalloc(sizeof(*bits) + 1, GFP_KERNEL);
> > +     if (!bits)
> > +             return;
> > +
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To post to this group, send email to kasan-dev@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6cc5e12d-1492-d9b7-3ea7-6381407439d7%40virtuozzo.com.
> For more options, visit https://groups.google.com/d/optout.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNMmSHvP%2Btzod%3DWeoDp6jsxGsDKV5cXiTr3F9fxEMasaw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
