Return-Path: <kasan-dev+bncBC7OBJGL2MHBB3WPXLTQKGQEPYUJCKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 0A96C2E14C
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 17:40:32 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id l12sf1050308oii.10
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 08:40:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559144431; cv=pass;
        d=google.com; s=arc-20160816;
        b=svBwQyx8QazNbjtYZRvu7aGFXI0AbfSWu/KLcp+sdzT7YoEBpXVlq0gHtT/xjd7tku
         oXsWZT28xLkCfwEkhNf7kvDRch2Q6OnmDS96+7Vj+AfdkRo1fDCJFxQ9TD2X2luUz5HA
         bY2E8pCVYS8J5P5hT3DB9mRvdYSBmGO/+LG7u+PqPGmvjXLzdX+llvKPHF07zqCHe8tS
         PxyAYiFSjmbSzY14o7Q9c1aqidAm3FdEeM2WBN3Ntmiej5qUJ/VM/1qlomWo8ZPG6AXD
         B5+1R7qyBuCF6042T4oiMwGHj3vfm4iSmPlWICHmKBiLCyWSwpMRGG3I4hf+YgFpL1FL
         RK8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=yvbAluIglL5kZjBescbTVHvbuE0nBhm0MzHVAU9W97Q=;
        b=MubmDCnweT5yUPTglw6XbxXK1nKYbqwjvWMEcav/0NMaqd9jX/DxrY/HzyObVTbhx7
         S3zdPTRhMYgkZkMHIbzBMPNlXkuWxQVBZH+AT+6fBpg1q22Q+H9s1Q4WM7snIPnlbqeq
         htbjhSOc72s+t17Io5W1uhoawgZiZebuNXRY97rCF9PFuBHesSQA/5lFlR34sGDO+tja
         20cnyQ/ENLg60vpdBHazdhaibWTqfqn7AVmfrvMKYOh0MFvIlUhgTxAZEJKosUDEqO2k
         O/HePP6X0/nSgaB97mR2hi4aY65fG9qixqWpq2aPwvLAoUxUmPovnSaVtZnqUcm0VZeJ
         qgmg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lxpQoNYt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yvbAluIglL5kZjBescbTVHvbuE0nBhm0MzHVAU9W97Q=;
        b=fRGsG1S2sXeZP5Jt0nWXGsP5FkS+NTN6IKHLM/BgMmTldIuIN5cdz+UVH8kA8WtsrV
         iOTszv9c0PyKY/PtPpTeq0lDrGzdGfpputCSqRgDwcIflBzYXTTPrZUpa9p2qKG5nYjM
         w/J3KR6TrhCOUUWF4HnHFu5Tc0+F1jOTds1dkrO4RR8OtbKrohqrJHeXPZGzE0OtEqi2
         GFD19Oy4flFbzP5bdljU7nCynoaJjKb1qZI86rBlXkjCr+Nf7w2qVBSbkz2PSxfNeOqw
         lGuRwL5wuipVkij54ve7vv1KLjOJwozAigoW+SaPqorgtCBYYp6MBIhi2dRO+1Jxpp3U
         QQrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=yvbAluIglL5kZjBescbTVHvbuE0nBhm0MzHVAU9W97Q=;
        b=cH/3kMLAlzzXBHdH0MsajBLiqg8UppFl20LIGNmhxt/cb1TljPdPjZqNpN0fcXU3AY
         90wFS1b71IbpMq/+Z5I/sIXlbbvj8CxZRn/O6rw1Rz2xtwjeLAxgN8f9KDOseFUsEQ4j
         zUnERWkww2ZAFEz51pE4qNwu3zXUOyNy88GdWwrXelohVVesdB+YN82/RLSMCFtT+lTS
         LClGvzoJnr84ndbxEKuLzsyVUzanxiGC0YcY24B+Lea7QURF0JFoFM4NSkcHPe5RjEkd
         lY4juSvhAW9f3E7KJQ7/QE9OfpwQcjXnnUbZ/NA4Fa0erVrrQU71J6227a4f7Hbur1TZ
         7xuw==
X-Gm-Message-State: APjAAAUxv3XKTGov80htBGAJySW/rxmJ4hnPRFwCPCHpNkgu6GiNMJpQ
	Qx26CH8+fmPPxJEItbhwI1Q=
X-Google-Smtp-Source: APXvYqy0VyWoEua2aM/4DxQC4Ah5vs3zM0jyxiANC1+0Bnp0BknjD0LZbQiOSc8BvcPySEsnzEm0HA==
X-Received: by 2002:aca:4bd2:: with SMTP id y201mr6347183oia.12.1559144430868;
        Wed, 29 May 2019 08:40:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:bad7:: with SMTP id k206ls409464oif.11.gmail; Wed, 29
 May 2019 08:40:30 -0700 (PDT)
X-Received: by 2002:aca:4d48:: with SMTP id a69mr6759414oib.113.1559144430468;
        Wed, 29 May 2019 08:40:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559144430; cv=none;
        d=google.com; s=arc-20160816;
        b=m4Uxo6oNIJPZjs0gFyRCw1OcP2npClbYoiKmEKXnSIFs4y+ikQ6fl8NRqL3gImyqs7
         bzI4df4+zd5L4oUhK4QNmB60vSNOrIuZdZrMnzKGHLyIJKhbqmGXPnAayI9yvewmBjOn
         CPnv95qLnP74bR3CFPu58yPmDEPY4aD0mY2y2OQ58h47BQJYb8XLs4CXAe4sk+Q7yvDO
         DZpI7D4oTG6vguGvFdm7u+SxPJtloz8Fco65oZTUChwcR8gk9bHol+mwcpan9gQv72Z7
         axiELagLNo37r8cl1BT6P/h6+ZE1Zm2YMyIBS/Wcx36o0M8pENxMT481nIvpEK56H2Ul
         WMAA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UdjXt9MPMtTsYy13tJGECQSLwoGNk530tR9PZnS8SV0=;
        b=Dpk8bboSRAFbvJ46fqnltPGUbOmMMKXTmiQ4bUwxP7QYJV5WbcMbZyHMA/zxxbtCgt
         YhmdMAgd/2jqGgHyqr7OI/fZNRx8C9TiYhyT3iL6qff6mx+Z+OZqABk++0xBERh5GWJz
         PmObQEzcojNhWrtc2ReOLZk11/tbuv2HhenOKkbGFX83EC41H2FzvTIFq13vq4KsiN9s
         Iliko9aA/EGhPqUnN5IErmBReW9SLSH/GIlx5EntGl+7CIhZmvcSILVRGsCfK1eF/KzO
         s2BGtrwHYHUNZFRP5rIy+qJVWDsiJab7+bUluEFenJy/ZpITVeclH8G8qMrmf8KoxVVi
         mWRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lxpQoNYt;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x335.google.com (mail-ot1-x335.google.com. [2607:f8b0:4864:20::335])
        by gmr-mx.google.com with ESMTPS id l18si978717otn.4.2019.05.29.08.40.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 08:40:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as permitted sender) client-ip=2607:f8b0:4864:20::335;
Received: by mail-ot1-x335.google.com with SMTP id c3so2493437otr.3
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 08:40:30 -0700 (PDT)
X-Received: by 2002:a9d:6f8a:: with SMTP id h10mr30106057otq.2.1559144429648;
 Wed, 29 May 2019 08:40:29 -0700 (PDT)
MIME-Version: 1.0
References: <20190529141500.193390-1-elver@google.com> <20190529141500.193390-4-elver@google.com>
 <20190529153258.GJ31777@lakrids.cambridge.arm.com>
In-Reply-To: <20190529153258.GJ31777@lakrids.cambridge.arm.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2019 17:40:18 +0200
Message-ID: <CANpmjNPPKaURFT=HDSy9K3MBHoJgAz-+Z1zN38GMZdqNXDMsuQ@mail.gmail.com>
Subject: Re: [PATCH v2 3/3] asm-generic, x86: Add bitops instrumentation for KASAN
To: Mark Rutland <mark.rutland@arm.com>
Cc: peterz@infradead.org, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, corbet@lwn.net, tglx@linutronix.de, 
	mingo@redhat.com, bp@alien8.de, hpa@zytor.com, x86@kernel.org, arnd@arndb.de, 
	jpoimboe@redhat.com, linux-doc@vger.kernel.org, 
	LKML <linux-kernel@vger.kernel.org>, linux-arch@vger.kernel.org, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lxpQoNYt;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::335 as
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

On Wed, 29 May 2019 at 17:33, Mark Rutland <mark.rutland@arm.com> wrote:
>
> On Wed, May 29, 2019 at 04:15:01PM +0200, Marco Elver wrote:
> > This adds a new header to asm-generic to allow optionally instrumenting
> > architecture-specific asm implementations of bitops.
> >
> > This change includes the required change for x86 as reference and
> > changes the kernel API doc to point to bitops-instrumented.h instead.
> > Rationale: the functions in x86's bitops.h are no longer the kernel API
> > functions, but instead the arch_ prefixed functions, which are then
> > instrumented via bitops-instrumented.h.
> >
> > Other architectures can similarly add support for asm implementations of
> > bitops.
> >
> > The documentation text has been copied/moved, and *no* changes to it
> > have been made in this patch.
> >
> > Tested: using lib/test_kasan with bitops tests (pre-requisite patch).
> >
> > Bugzilla: https://bugzilla.kernel.org/show_bug.cgi?id=198439
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > Changes in v2:
> > * Instrument word-sized accesses, as specified by the interface.
> > ---
> >  Documentation/core-api/kernel-api.rst     |   2 +-
> >  arch/x86/include/asm/bitops.h             | 210 ++++----------
> >  include/asm-generic/bitops-instrumented.h | 317 ++++++++++++++++++++++
> >  3 files changed, 370 insertions(+), 159 deletions(-)
> >  create mode 100644 include/asm-generic/bitops-instrumented.h
>
> [...]
>
> > diff --git a/include/asm-generic/bitops-instrumented.h b/include/asm-generic/bitops-instrumented.h
> > new file mode 100644
> > index 000000000000..b01b0dd93964
> > --- /dev/null
> > +++ b/include/asm-generic/bitops-instrumented.h
> > @@ -0,0 +1,317 @@
> > +/* SPDX-License-Identifier: GPL-2.0 */
> > +
> > +/*
> > + * This file provides wrappers with sanitizer instrumentation for bit
> > + * operations.
> > + *
> > + * To use this functionality, an arch's bitops.h file needs to define each of
> > + * the below bit operations with an arch_ prefix (e.g. arch_set_bit(),
> > + * arch___set_bit(), etc.), #define each provided arch_ function, and include
> > + * this file after their definitions. For undefined arch_ functions, it is
> > + * assumed that they are provided via asm-generic/bitops, which are implicitly
> > + * instrumented.
> > + */
>
> If using the asm-generic/bitops.h, all of the below will be defined
> unconditionally, so I don't believe we need the ifdeffery for each
> function.
>
> > +#ifndef _ASM_GENERIC_BITOPS_INSTRUMENTED_H
> > +#define _ASM_GENERIC_BITOPS_INSTRUMENTED_H
> > +
> > +#include <linux/kasan-checks.h>
> > +
> > +#if defined(arch_set_bit)
> > +/**
> > + * set_bit - Atomically set a bit in memory
> > + * @nr: the bit to set
> > + * @addr: the address to start counting from
> > + *
> > + * This function is atomic and may not be reordered.  See __set_bit()
> > + * if you do not require the atomic guarantees.
> > + *
> > + * Note: there are no guarantees that this function will not be reordered
> > + * on non x86 architectures, so if you are writing portable code,
> > + * make sure not to rely on its reordering guarantees.
>
> These two paragraphs are contradictory.
>
> Since this is not under arch/x86, please fix this to describe the
> generic semantics; any x86-specific behaviour should be commented under
> arch/x86.
>
> AFAICT per include/asm-generic/bitops/atomic.h, generically this
> provides no ordering guarantees. So I think this can be:
>
> /**
>  * set_bit - Atomically set a bit in memory
>  * @nr: the bit to set
>  * @addr: the address to start counting from
>  *
>  * This function is atomic and may be reordered.
>  *
>  * Note that @nr may be almost arbitrarily large; this function is not
>  * restricted to acting on a single-word quantity.
>  */
>
> ... with the x86 ordering beahviour commented in x86's arch_set_bit.
>
> Peter, do you have a better wording for the above?
>
> [...]
>
> > +#if defined(arch___test_and_clear_bit)
> > +/**
> > + * __test_and_clear_bit - Clear a bit and return its old value
> > + * @nr: Bit to clear
> > + * @addr: Address to count from
> > + *
> > + * This operation is non-atomic and can be reordered.
> > + * If two examples of this operation race, one can appear to succeed
> > + * but actually fail.  You must protect multiple accesses with a lock.
> > + *
> > + * Note: the operation is performed atomically with respect to
> > + * the local CPU, but not other CPUs. Portable code should not
> > + * rely on this behaviour.
> > + * KVM relies on this behaviour on x86 for modifying memory that is also
> > + * accessed from a hypervisor on the same CPU if running in a VM: don't change
> > + * this without also updating arch/x86/kernel/kvm.c
> > + */
>
> Likewise, please only specify the generic semantics in this header, and
> leave the x86-specific behaviour commented under arch/x86.

The current official API documentation refers to x86 bitops.h (also
see the Documentation/core-api/kernel-api.rst change):
https://www.kernel.org/doc/htmldocs/kernel-api/API-set-bit.html

I'm happy to change in this patch, but note that this would change the
official API documentation.  Alternatively it could be done in a
separate patch.

Let me know what you prefer.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPPKaURFT%3DHDSy9K3MBHoJgAz-%2BZ1zN38GMZdqNXDMsuQ%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
