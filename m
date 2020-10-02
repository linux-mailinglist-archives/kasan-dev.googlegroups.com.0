Return-Path: <kasan-dev+bncBCMIZB7QWENRBUHP3T5QKGQE62DIOPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FBE82814F7
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 16:23:13 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id k18sf720484ots.1
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Oct 2020 07:23:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601648592; cv=pass;
        d=google.com; s=arc-20160816;
        b=KLzTUd7Al5ltJ8JkbE4oAzoDjGv5P5ms1KuMCCoVoy9+jeHWbrNlfx9ouWfQPhiDmo
         9q3jyoIb4R6erGRbBvPnZrFS5Uw0dllzUWQfBiH+/h/qI9OljQ5OSawhfKkMPLdjswax
         loSc/5r38uZS336QRxZ9hPlHwvl5PrFnAuuEfOK0BLiLdRlfMMc2lq04blqTpStvn8OX
         PypB+PBEeCOwVhBfJoULoZjiSEH2/IZQ8fdR53MW4p0abdfN7wsIZWtmmcycKn0GqKam
         tbGq7O68eiIU284OVvfqL49QCBq/VqTDoIxNYvhdH7/vEd/B40ai6EgWYBVcy2U35lgN
         gUBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lhoYFTAmVj+I/Md/oSSbVAab9uoCrYcM49qZysl3Lko=;
        b=T+xs2tUun8TRvDQTMbFS3a95K0MlIABxtYQm+PgKrwzZNt3kqIS0hTD2CTcFy7IAe+
         NeFemG4PBH2QPfDQWJidjHRQ1eEkGadntyw5kItCdw9Ru9ey7776wtRMbiBYIRyC74+O
         63vaiXvhsJQgu7vA7Au8MQ+gyQzU1NvVKZj2AAl8gqdczgMLL2IsEH87/ZnAwXT5e5Bz
         0sDHvyzGzMqDeJdq8eICJZ/Nxma7JZ4h0I+6lt7nYoQo2dHflQ7P/ftsaz3rcubkQaNd
         eQtVhhNvbZz55fnAH/lVg+7nTIJR63eTAtTXuEAbBDx6V6qtLLRogpPxACD79lEt5G74
         +23g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RKfZWi+R;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lhoYFTAmVj+I/Md/oSSbVAab9uoCrYcM49qZysl3Lko=;
        b=RyaqwAM1/hw+OoV7rBN+GdHUz24C5AZb93oIcf2wpoccwuTfASRhQ4QNxgY5mIsX//
         SxcqDeuzE7E2q8lYdNz+8GkpgpodAL/y7ioCo1gyyr+CG2xdxuChOMPmEFbAtWNdOxiE
         aP6z+66X+hdt3uQUOkCUlXm/uRAJpbP56yQLp1xEmWU/AbA2z8FCx3K/3qGyTipEOZFN
         MRvMnopInOyhvlUGAuX3Knjjd2q28rnkWcbLjKNI1V45Tj2AZYA6oIWyAeNaw0S4D5qk
         M5bRmUJn+dblv8fAA6HZx1FSUbRMOvfNzmAP4aIoRmMGkOrDQWRxCM2WDH77SrPv3Atl
         Qqlw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lhoYFTAmVj+I/Md/oSSbVAab9uoCrYcM49qZysl3Lko=;
        b=rMAAKFdrp2OY8XdUSzQVZOfzrpK6zupJCeUjpvZ4Ug51UI1pXpnPxlrYSzpLZnH+Pq
         KyL3pLR7BPbK3z3wcvzgPhY4LfQa3ANKw4+MNd6MNQsxHLeplK4mwPYPRq4L8ToT7zuh
         A3qr0XvlR6rFqYQVzJPINm7wNg253Z3ljmhqZEvaIHQ01H5MEjrF8OslUSeFLIDI2iTr
         B9975T77gUWqWoyjyxTpVnPh80L0+9GA46hO6CK7QhHRjkY/RwfaJlkarezHxdefRWiK
         THaWhKPfTxtxPbaa/37d+PvBlrZqXFy4k2trQ3+Mi7tSe9+n69I8/N3tKMXpYiG8h/cQ
         sI4g==
X-Gm-Message-State: AOAM53039fkZLJq7T76ifoQBXPRfYPS44UBxA+9VYTbH3S1QPtcNHDJu
	CUJ7xTXpR5JdG2Dk1nCS0qE=
X-Google-Smtp-Source: ABdhPJw14sxd7vKPB4fx/qG1oONeG4XF8rxCFosTB4stXNTeWm9NTGO4ru44Nqoo0Yhr4+ja6b4eVQ==
X-Received: by 2002:a9d:6219:: with SMTP id g25mr1938845otj.58.1601648592097;
        Fri, 02 Oct 2020 07:23:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:dd0b:: with SMTP id u11ls395088oig.6.gmail; Fri, 02 Oct
 2020 07:23:11 -0700 (PDT)
X-Received: by 2002:a05:6808:8f3:: with SMTP id d19mr1417713oic.34.1601648591739;
        Fri, 02 Oct 2020 07:23:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601648591; cv=none;
        d=google.com; s=arc-20160816;
        b=x7Ulznwb4ROmKrmkipmwybEkf0XiIFka6ttDwQ0CVEVWgrHbW7x05CfNvFX4KYVCz5
         fTs4DfZbimHH4/mmV+tnTNme8gKoulO+HvEgqOSiXPcL/sz088YFP0M1TZTrqaWvc2bN
         BnJBk5K9bJ20o5OtlZx8Snrd3Vj8GLtAdPi8oiqTN+0x69T9/2ieaxixa2Km8KeyK5z1
         te2pNuK+iamJYMrjn0azBf27OOjij/z7rjmADD1yDENupbw7xdfTMeJCRWP/eYGzVVIf
         BxXmXd1tBiGKufjZ0LwTPOa21AWTAftPd+8uhwsYjycsHB0pPqLvDJPSfOl8SXxsvz9U
         VHGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=CAgelpYpJihRsjmlp4EjmhmaunlYd8C4mVKtF8jDi3w=;
        b=t5LNT0X2EQbREZa1jkcRqxZ90VFOhnGR+sWSiTJ4B2DLSP8XXGPzhQpJEvy6thud6q
         KO+7in5xw5zWP+miXK3PUQ7GDAZbTFLSecOh12pke0rcmTAbz+B3peEGkgDNjFHh9ox0
         n0WUtIInBA5l0UoQ9S3cQCqN2C2MiECavdExPmP65msCRan7FHm93qG/7BHDCO8q+hCo
         oFoprA+oT3RYK1Y6Yxdo5typsAuTPwUEVrA9xgOiNaGY9EUR1c321yx0WjYgQUTKxt4t
         wvPc6/5ZXrR70wUUHcSUcVaBBcgPrmzeUJBNwiY7m2baOzMxYssKQ32vz7818D3pyyWv
         bsxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RKfZWi+R;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id d1si136757oom.0.2020.10.02.07.23.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Oct 2020 07:23:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id c18so1324352qtw.5
        for <kasan-dev@googlegroups.com>; Fri, 02 Oct 2020 07:23:11 -0700 (PDT)
X-Received: by 2002:ac8:4806:: with SMTP id g6mr2529805qtq.380.1601648590888;
 Fri, 02 Oct 2020 07:23:10 -0700 (PDT)
MIME-Version: 1.0
References: <20200929133814.2834621-1-elver@google.com> <20200929133814.2834621-2-elver@google.com>
 <CAG48ez3+_K6YXoXgKBkB8AMeSQj++Mxi5u2OT--B+mJgE7Cyfg@mail.gmail.com> <CAG48ez1MQks2na23g_q4=ADrjMYjRjiw+9k_Wp9hwGovFzZ01A@mail.gmail.com>
In-Reply-To: <CAG48ez1MQks2na23g_q4=ADrjMYjRjiw+9k_Wp9hwGovFzZ01A@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 2 Oct 2020 16:22:59 +0200
Message-ID: <CACT4Y+a3hLF1ph1fw7xVz1bQDNKL8W0s6pXe7aKm9wTNrJH3=w@mail.gmail.com>
Subject: Re: [PATCH v4 01/11] mm: add Kernel Electric-Fence infrastructure
To: Jann Horn <jannh@google.com>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Alexander Potapenko <glider@google.com>, "H . Peter Anvin" <hpa@zytor.com>, 
	"Paul E . McKenney" <paulmck@kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Andy Lutomirski <luto@kernel.org>, 
	Borislav Petkov <bp@alien8.de>, Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Eric Dumazet <edumazet@google.com>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Hillf Danton <hdanton@sina.com>, Ingo Molnar <mingo@redhat.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, Will Deacon <will@kernel.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	kernel list <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RKfZWi+R;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Fri, Oct 2, 2020 at 9:54 AM Jann Horn <jannh@google.com> wrote:
>
> On Fri, Oct 2, 2020 at 8:33 AM Jann Horn <jannh@google.com> wrote:
> > On Tue, Sep 29, 2020 at 3:38 PM Marco Elver <elver@google.com> wrote:
> > > This adds the Kernel Electric-Fence (KFENCE) infrastructure. KFENCE is a
> > > low-overhead sampling-based memory safety error detector of heap
> > > use-after-free, invalid-free, and out-of-bounds access errors.
> > >
> > > KFENCE is designed to be enabled in production kernels, and has near
> > > zero performance overhead. Compared to KASAN, KFENCE trades performance
> > > for precision. The main motivation behind KFENCE's design, is that with
> > > enough total uptime KFENCE will detect bugs in code paths not typically
> > > exercised by non-production test workloads. One way to quickly achieve a
> > > large enough total uptime is when the tool is deployed across a large
> > > fleet of machines.
> [...]
> > > +/*
> > > + * The pool of pages used for guard pages and objects. If supported, allocated
> > > + * statically, so that is_kfence_address() avoids a pointer load, and simply
> > > + * compares against a constant address. Assume that if KFENCE is compiled into
> > > + * the kernel, it is usually enabled, and the space is to be allocated one way
> > > + * or another.
> > > + */
> >
> > If this actually brings a performance win, the proper way to do this
> > would probably be to implement this as generic kernel infrastructure
> > that makes the compiler emit large-offset relocations (either through
> > compiler support or using inline asm statements that move an immediate
> > into a register output and register the location in a special section,
> > kinda like how e.g. static keys work) and patches them at boot time,
> > or something like that - there are other places in the kernel where
> > very hot code uses global pointers that are only ever written once
> > during boot, e.g. the dentry cache of the VFS and the futex hash
> > table. Those are probably far hotter than the kfence code.
> >
> > While I understand that that goes beyond the scope of this project, it
> > might be something to work on going forward - this kind of
> > special-case logic that turns the kernel data section into heap memory
> > would not be needed if we had that kind of infrastructure.
>
> After thinking about it a bit more, I'm not even convinced that this
> is a net positive in terms of overall performance - while it allows
> you to avoid one level of indirection in some parts of kfence, that
> kfence code by design only runs pretty infrequently. And to enable
> this indirection avoidance, your x86 arch_kfence_initialize_pool() is
> shattering potentially unrelated hugepages in the kernel data section,
> which might increase the TLB pressure (and therefore the number of
> memory loads that have to fall back to slow page walks) in code that
> is much hotter than yours.
>
> And if this indirection is a real performance problem, that problem
> would be many times worse in the VFS and the futex subsystem, so
> developing a more generic framework for doing this cleanly would be
> far more important than designing special-case code to allow kfence to
> do this.
>
> And from what I've seen, a non-trivial chunk of the code in this
> series, especially the arch/ parts, is only necessary to enable this
> microoptimization.
>
> Do you have performance numbers or a description of why you believe
> that this part of kfence is exceptionally performance-sensitive? If
> not, it might be a good idea to remove this optimization, at least for
> the initial version of this code. (And even if the optimization is
> worthwhile, it might be a better idea to go for the generic version
> immediately.)

This check is very hot, it happens on every free. For every freed
object we need to understand if it belongs to KFENCE or not.

The generic framework for this already exists -- you simply create a
global variable ;)
KFENCE needs the range to be covered by struct page's and that's what
creates problems for arm64. But I would assume most other users don't
need that.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba3hLF1ph1fw7xVz1bQDNKL8W0s6pXe7aKm9wTNrJH3%3Dw%40mail.gmail.com.
