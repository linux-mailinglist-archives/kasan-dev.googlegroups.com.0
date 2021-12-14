Return-Path: <kasan-dev+bncBDW2JDUY5AORBFHH4OGQMGQEK5YA4QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 74D2B474C27
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 20:42:14 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id t8-20020a92c908000000b002a4303742d6sf136756ilp.23
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 11:42:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639510933; cv=pass;
        d=google.com; s=arc-20160816;
        b=wNZ2q4AzhL5uXOJQGx+Rd6LFHqUH1xoT7I4sLN1Yq/+Cnoi8NmtE1X09toCgbHwrcY
         JE3wEnoIj5+v3Mvumd20HaLvgQtLmkouwe9CWjrrKwu7670FJTBeEs/yRUmcAPRutAUd
         MEJaF3fExgyu/7mxJkcixthlWR9O9eOrZoeMki1iYGG8KBKyIDicApDwi9eUujtzzuqz
         w37FRYGaO/AGRUweqsS8kxL2xRmL3t83ipbjbrduiXwDR6lqrwR+lWri7igQVSQBiIAr
         qsPWr5zUdQ06fA+pDOhvBv98aBdSYT6h3Bcx3Cu8V/hIeLbQcTQEbsvkbMyFZTPYTIhG
         ZFTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=A7qBIydriHHNhyKptF3X4e7k6ibLUWJWeCtEaswuEIo=;
        b=S9HqXrtzY/0+jDlmh786J+kHCcDsmWui7KjTDr0ZLNSO3v9t0HqXaUdLhc44zn/CcZ
         U/70vRUAWITMRk0AHNpl+z2L2u57dHBRLj1x4Q8kYQDhiWqPNt9dbDpTjN2tjZn5mJof
         mZjutpyZey2QVNhGnSLElWDMPnjnVibIFZG6YWfuKvhSDp/7MPiODIZ0dOZLkF//GM2+
         SyxTGPUDgJ/t2LEx6uV3jucwdYAqAsf0TQttuXZ5ywGLtkUBOhD/DFgoORRGy2uY+x+o
         WYCUZtXS8JxnER6NxD+j2tFmofUC8iEJQErHOzX26MioHPQfDY6JB5bOBC6f3N6Biu5i
         o1hA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ew5BVOtU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A7qBIydriHHNhyKptF3X4e7k6ibLUWJWeCtEaswuEIo=;
        b=COs1HLH61SqMvvNT+c4N+HHVPB4/FlkUbZay0p21S12nMyPZQFh4+/IJjjEOLxqWUn
         l+/zdepKStK6/j3Vz5eF/pa4p+k0L2Ad++uWIQfcs42Mk4F02DSpuYg/7FieollyjRgh
         Ww9dELadcDzI9pEJMLitKqSsHz17uabjC55cDBGVuALhbdCVhV9NtdqkMPkwEN0b3pev
         VnPGicTzV2AZgjYJ6HVBeRsc5gVrjUWpNmGUPRGyMoaLbuqUd1uJ1PVmKySkn4in509B
         1sVYCMLKOfLZcujOfd86H8EyPdTDIZG7wEV1CnE+vJEaZItaQBdNsniszxLTA5WC2VG4
         Xn2w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A7qBIydriHHNhyKptF3X4e7k6ibLUWJWeCtEaswuEIo=;
        b=PEvSIp2XptoJy0BOvSAWjcALAz5clQv1JLkwj/jAZl9rXXlmrzk5Bhqw89wyJnVjTJ
         nCU+4LmukBmkH3f3bxX1Ae8OAESCeQy/FoyU9Sj3i2SVhr43NOGOmUrOxIXRd5z26cKn
         4VcNYOplaWojShmuGc/nSZi9qeUg/83eGc2wRo818DbhEIxLmTouFd6SfkJSRpfuG1EJ
         RXwTDmPuZP3FDdZJDf4m23qN+ZPNb20k4ROU5XEsokph/KPe3APn3x0FA/0TxLgtkRTE
         f1Pm/4jhOeKKDp8CZHFXAgiQGQSHkWK+CwONx+jhkt3LrjQLkJK6xiYGe6Cp0p6eh6xC
         FH6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=A7qBIydriHHNhyKptF3X4e7k6ibLUWJWeCtEaswuEIo=;
        b=kpMTQ0Y3nO7FEi1qg8kPhg1H9O/jVkKeWufksvdhiuf/Co2YIFX/2U0Tl9/NoGbPAk
         yoWVv5Lb6elNjLUd9YxNg8ewjMHJ0X7crGtvDOiZ6Sni/NdPM5rDJv7PUUJBMifGcPSM
         lAvPH2nReSq4+bPIJkvuf5iDuafpQzWo22OlO5CSu8uC5J0UZjpc0PL4Oz9ObCl/LUG8
         C2K+kL8a0+ozpnmW6kdZLb3Ht9qfN7xHpO3mTFh/y+j1YTbNRvKP5pFMvI6MEGl7EX6n
         XjT5Hs5dI9UigF7SNJ1VYDXfY6LM9R5Jf5XHi3JVbHkEXdPBbuFXaEyZDHtXZNsJoZi0
         xjwg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533oCcFldw8j3Xqvp7Y7l1DarQSF0oK+IMcgg0J9mC5YI4D29TYq
	HwA9dfFSSjDXZYu2dwkgREo=
X-Google-Smtp-Source: ABdhPJw7vih8lSqrogdoZVFIum0jhnURethT/+6BbTjesP5s0BlGtzKk5HZ8E0qyPLxqSR+Nfa2Mig==
X-Received: by 2002:a02:b889:: with SMTP id p9mr4197387jam.500.1639510932986;
        Tue, 14 Dec 2021 11:42:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:358b:: with SMTP id v11ls3536834jal.7.gmail; Tue,
 14 Dec 2021 11:42:12 -0800 (PST)
X-Received: by 2002:a05:6638:2649:: with SMTP id n9mr4169159jat.369.1639510932655;
        Tue, 14 Dec 2021 11:42:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639510932; cv=none;
        d=google.com; s=arc-20160816;
        b=PYAv6CnjWmIfvaL7/2YE/QwI15oMMO1OcmRCL1GVRkkMzqGg1CL79BcRLUkMYJzJ0c
         tHRJRIkvLHpG+6Kxq7tB3k2lQm2O6KFFTUneAVtX+WQHykCvNLw5xHCqs8x+t/Zq27tb
         V4ShbNzaAoznorVsIp1BsuqPmrdr6Q0Tu096M5iHx5pc8VatPC+zfJJVn+XBOHN+NSAt
         6tt3nAh64+Q8T9xlFglaQxHsvfHZPeOL549v8E4VvRt9WesKgB8l9hvKGXr6sF5EdaCZ
         tLg/yYn62i4ei6gORpN7nKCIWIJNiDmqmkKNW1OwnImZ3XkfNeD9II3xIXMAEg2ZdYxy
         I9QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=46avN96nbskMUAFWXD0G4IICxhuVMqWM0c7esNIiqMg=;
        b=OVxcs33KrqN33jvvJtNYE6BS44bnXlSP0aVfzQiTQ7EfRfkP53P6v7PUKwBGDsN0xR
         Thf+KI0ZktlqjqjVCI9om1E/sBXbKJNpYhGfd82NJNRXE2QpaX4Po/wIjllui1//UBIo
         FkL350YQKcxDFFvnqfNq1jhlQOD1NM5qDFFUaVG6CONtW6EADwrIxMIOZ9D5oN6GjE+C
         rCIxKJseZI3AiVN28W9TbXKJ/LXS0Ub6Sl7E82BpUMH4AU0uzP3lWF34anppJ0BwU9mV
         XfUC8A7QG7yJibfY/IL4LPfzIVqXrKgHU7Sw+fDYcUSTJ4aPvklo+j4Gp1ynLm6YTLwi
         yOWA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=ew5BVOtU;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd2e.google.com (mail-io1-xd2e.google.com. [2607:f8b0:4864:20::d2e])
        by gmr-mx.google.com with ESMTPS id g14si44737ilf.1.2021.12.14.11.42.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 14 Dec 2021 11:42:12 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e as permitted sender) client-ip=2607:f8b0:4864:20::d2e;
Received: by mail-io1-xd2e.google.com with SMTP id z18so26179617iof.5
        for <kasan-dev@googlegroups.com>; Tue, 14 Dec 2021 11:42:12 -0800 (PST)
X-Received: by 2002:a02:830e:: with SMTP id v14mr4174019jag.644.1639510930962;
 Tue, 14 Dec 2021 11:42:10 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <c77f819e87b9fefcb26c6448a027b25c939f079e.1639432170.git.andreyknvl@google.com>
In-Reply-To: <c77f819e87b9fefcb26c6448a027b25c939f079e.1639432170.git.andreyknvl@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 14 Dec 2021 20:42:00 +0100
Message-ID: <CA+fCnZfP+j6ra4vExsOg96yVHTHQy_NB65-TT=S=9Gr1X62yiA@mail.gmail.com>
Subject: Re: [PATCH mm v3 30/38] kasan, vmalloc: don't tag executable vmalloc allocations
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=ew5BVOtU;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::d2e
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

On Mon, Dec 13, 2021 at 10:54 PM <andrey.konovalov@linux.dev> wrote:
>

[...]

> @@ -3133,10 +3133,14 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
>          * (except for the should_skip_init() check) to make sure that memory
>          * is initialized under the same conditions regardless of the enabled
>          * KASAN mode.
> +        * Tag-based KASAN modes only assign tags to non-executable
> +        * allocations, see __kasan_unpoison_vmalloc().
>          */
>         kasan_flags = KASAN_VMALLOC_VM_ALLOC;
>         if (!want_init_on_free() && want_init_on_alloc(gfp_mask))
>                 kasan_flags |= KASAN_VMALLOC_INIT;
> +       if (pgprot_val(prot) == pgprot_val(pgprot_nx(prot)))

Can simply compare with PAGE_KERNEL here to match the check in
arch_vmalloc_pgprot_modify(). Will do in v4.

> +               kasan_flags |= KASAN_VMALLOC_NOEXEC;
>         addr = kasan_unpoison_vmalloc(addr, real_size, kasan_flags);
>
>         /*
> @@ -3844,7 +3848,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
>         for (area = 0; area < nr_vms; area++)
>                 vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
>                                                          vms[area]->size,
> -                                                        KASAN_VMALLOC_NONE);
> +                                                        KASAN_VMALLOC_NOEXEC);
>
>         kfree(vas);
>         return vms;
> --
> 2.25.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfP%2Bj6ra4vExsOg96yVHTHQy_NB65-TT%3DS%3D9Gr1X62yiA%40mail.gmail.com.
