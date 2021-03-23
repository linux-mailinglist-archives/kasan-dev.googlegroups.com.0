Return-Path: <kasan-dev+bncBDX4HWEMTEBRBYMI5CBAMGQE5FQ23SA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id EDCA534625B
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 16:08:18 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id c6sf1255255otl.14
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 08:08:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616512098; cv=pass;
        d=google.com; s=arc-20160816;
        b=nvO9PtX7+iXetmyrxPyok7hSZpbSoYcN6a0X63/DoCm049pqKDzdkBL1/FgafcP1nJ
         Lzchj7/UxMD9hpxteWZseIhwmd2s6F6PaR8tBr+lX5R9VRGZNZNQKl3rVGywFnV78KiT
         UP+j/EFBmKVYLZ0gDnRQNl+7gkAIvtdqozBAGVuu0CIAKLJZu3bNa5kRaF9IC8PnCMZr
         IzLpT3nMO+jH0vau56Eju1TlmIrAGInPrNZH/zgEoX+cO2k/Pf/DCz04/BMbQqPaquzn
         hSZv7cph0glJU+GzWcDTY4oiaJvSmZJM4OMLcytqhtBc1lHhAyM5JVrjbu7v2PT633Yj
         /f7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ByiJo2JGB3PEfm3fsG59LFOUlNmpyMKX5E/3zNqHDIY=;
        b=McCiClB2MVFiD0izUCBto/jvgv9KFbm8cUgtP04Sn8cU1jlYSqRtzkt6V2KTDu1vRq
         Jm1c58TbUw7//coXcCUKmmjIM4lcyjYRcEq/phZaqvk3uHov/ooIrwHWNWCP+A6pv8JB
         IkzrmRP/GxdC5IqZkHUTVU2tPKsXxkqXiDm/DSSrVZGIBoA0J48GXew+gDo/LKzalVgU
         rAvV/pcKKXv3wxGh5vZT/Q8YOHelv8lC5VSMiAXpiZF9Hifis2KxM0z/P4Mp6U771607
         8oZ2AVu3aG3QJhRIB5rd5GwbxrdNypNPn8+Y8yD2tAFoVc0f1yaMRBV8T/qsirdA0Deh
         dvdw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JlfWnvho;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ByiJo2JGB3PEfm3fsG59LFOUlNmpyMKX5E/3zNqHDIY=;
        b=DHw7uWWIeGecVuco0taKPoDs9elqAChBP3tVvEf8BhkyTKaJL2wx/zSAGqVMfcd+8y
         tAyRaaI3sicVOdZJV8xCW6eQo8dYgWCCvCknV7BGsm2PfmP1JUuFk3MDpwL04NDhpiR6
         fsZ0V32/vPwsSPf+UnjshcWsZktKh40CG4BDULOcb9DoZZ0wjVHfF/neV4wpQsBKg2cB
         6w8dgE35OPWR0FPrpmmifFcGEj/m/gTnIbD4VQnLZgn++RYqpdqkkewqJzrurhbJbb9S
         HnS29yWKBVmhOxZMFxYSW3ARn0LruMMpwqurnW6wR71a061xRYc/NaGKxrO+dx0MXRUl
         +T2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ByiJo2JGB3PEfm3fsG59LFOUlNmpyMKX5E/3zNqHDIY=;
        b=cCgMlupgBgdXfXc+U6MeHRwgUIGU4YX4n41lbNhhcNTR+m0YxCKjhE5S3OhZvLN6Io
         /hVl0IJrqCMGbZCYJt/4tVBghO8PU2K6MD8qNx9+xQU5n3jZ4CfqCdql1mRCxrauk7rj
         FJysg/99rLo4gf0FJfBnBiHMMctwsgnc8PiKYtZ1bYCDre5pwFGi2eCHyI68aTg+2o1x
         fBuGOlZo7ggKvzlwKOUe9bpPbeaIb2WF0oOaS1u/dC50o4WpHKJdQkxSjFjtBEEV5Xt8
         DFDU9iFlJsSHN+UBzxG3Ufl57FotUw6nM88EppVuSuo2nLVR03qQHRZRjY61UUShOLZF
         SD7A==
X-Gm-Message-State: AOAM531+DcfLs7EiZqYKjI7nVpOfHaR0Z1M6pTPbd7mf/QseT4llfOXd
	w1524LWL2KUvY4t488ZUfco=
X-Google-Smtp-Source: ABdhPJwECEz5VJM3XXazECKjy1KWqb9BvcNaK3W8RrVL925m8/lDOsSeO0u1O5nCNNlfM9lKgnVZcg==
X-Received: by 2002:a9d:6481:: with SMTP id g1mr4651070otl.303.1616512097962;
        Tue, 23 Mar 2021 08:08:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:a403:: with SMTP id v3ls992134ool.6.gmail; Tue, 23 Mar
 2021 08:08:17 -0700 (PDT)
X-Received: by 2002:a4a:e8d1:: with SMTP id h17mr4222865ooe.20.1616512097641;
        Tue, 23 Mar 2021 08:08:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616512097; cv=none;
        d=google.com; s=arc-20160816;
        b=Wwd59QOzfCS8WMvDYlHDaamCdgpQqk9cYMM0PMuVuK1SJ08Ns5jBivD64JHZYeD+yz
         1f2MvpRqHXPVDfjjPt0IywMlX7jc7A/Ai2ep1tTfQUQH1py+bP/JU/18atOGJKyCJHzg
         POmvqA01y0NwXlAWzHJ48zjcOIS1OxZl/M/sbwCb8LflaRPeiOWKBolZxauphMKSGHva
         KgICupHaWjlkqLN20IkByUFBgHxbR4T4WRsikBkL627ZW7CIyODmv5nxBIu16w+ZyY55
         vBSXDAcD1ClPLxGWq4gJxgE8TYY5xu6fLncrWqA+j/nCfkgj5upGXenqxJE6UCRyKkjm
         sy3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=B/0oH/sIKlTyqEM5+DPElcup5AqdVgWb/d4FeBXrA9I=;
        b=cob8COUQTl0t8xky9VXkKSq6ya+lsf9LmZ7d0FO6niFSlPdu/Vglp8dtYRqObxLBsb
         HiEUIPVk9FGa9Q42AP4qmxRCSV/9ZqXjZX6JR5TBO9cAMlE56vYVYk5ty5QM4EOnOYuL
         f0ZGsZ1FRG6athn1D2UFGW2SSDikPSKU7AA+goPe6ueGDM0iKdm/WykBAjHdOD77YkRW
         8Nl06Ty94UZsDoacgcFKLk3DAEYOpbqN8KxV2fw5f0v6FpoN6tBWOxStki6mKdpEId2M
         kBPlPccK+NBClF7mmu0TE+LgVH8UehqyyBcLDUsU9JnGU5LxX9MKGch60AuCYOIjhczK
         F5Yw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JlfWnvho;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id f2si1460073oob.2.2021.03.23.08.08.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 08:08:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id mz6-20020a17090b3786b02900c16cb41d63so10254439pjb.2
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 08:08:17 -0700 (PDT)
X-Received: by 2002:a17:90a:8c08:: with SMTP id a8mr5052138pjo.136.1616512097128;
 Tue, 23 Mar 2021 08:08:17 -0700 (PDT)
MIME-Version: 1.0
References: <20210315132019.33202-1-vincenzo.frascino@arm.com> <20210318185607.GD10758@arm.com>
In-Reply-To: <20210318185607.GD10758@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Mar 2021 16:08:05 +0100
Message-ID: <CAAeHK+w+pHtKNwxz5Scdp9_48jmSLfeBqBGqKQT+-aFO486GzA@mail.gmail.com>
Subject: Re: [PATCH v16 0/9] arm64: ARMv8.5-A: MTE: Add async mode support
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JlfWnvho;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::1035
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

On Thu, Mar 18, 2021 at 7:56 PM Catalin Marinas <catalin.marinas@arm.com> wrote:
>
> On Mon, Mar 15, 2021 at 01:20:10PM +0000, Vincenzo Frascino wrote:
> > This patchset implements the asynchronous mode support for ARMv8.5-A
> > Memory Tagging Extension (MTE), which is a debugging feature that allows
> > to detect with the help of the architecture the C and C++ programmatic
> > memory errors like buffer overflow, use-after-free, use-after-return, etc.
> >
> > MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
> > (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
> > subset of its address space that is multiple of a 16 bytes granule. MTE
> > is based on a lock-key mechanism where the lock is the tag associated to
> > the physical memory and the key is the tag associated to the virtual
> > address.
> > When MTE is enabled and tags are set for ranges of address space of a task,
> > the PE will compare the tag related to the physical memory with the tag
> > related to the virtual address (tag check operation). Access to the memory
> > is granted only if the two tags match. In case of mismatch the PE will raise
> > an exception.
> >
> > The exception can be handled synchronously or asynchronously. When the
> > asynchronous mode is enabled:
> >   - Upon fault the PE updates the TFSR_EL1 register.
> >   - The kernel detects the change during one of the following:
> >     - Context switching
> >     - Return to user/EL0
> >     - Kernel entry from EL1
> >     - Kernel exit to EL1
> >   - If the register has been updated by the PE the kernel clears it and
> >     reports the error.
> >
> > The series is based on linux-next/akpm.
>
> Andrew, could you please pick these patches up via the mm tree? They
> depend on kasan patches already queued.

Hi Andrew,

Looks like these patches have reached a stable state.

Could you please pick them up into mm targeting 5.13?

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bw%2BpHtKNwxz5Scdp9_48jmSLfeBqBGqKQT%2B-aFO486GzA%40mail.gmail.com.
