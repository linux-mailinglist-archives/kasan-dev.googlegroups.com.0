Return-Path: <kasan-dev+bncBC7OBJGL2MHBB37646BAMGQEAZUVOMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 78DFF3461CA
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 15:47:12 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id t81sf1022152oif.11
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Mar 2021 07:47:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616510831; cv=pass;
        d=google.com; s=arc-20160816;
        b=H6icYMEWIjW6Fmr1JD1p3DXJT/eSnTekMFN8rYXuN/AfdhtRmU+v+AO0S2ouC/LI/c
         zwjJup6zwE7zjNOClV+75UkKdxMTFQiX6MtvHuoPZXOZV5XnWiMmGZHfPVzCcA96Aoj9
         fIuvaHfFi0+cHZcCJgSi+Qq53wa7uH5i8IBIR02diHSR8mUeWjuU+YoKS2IVIg02nBBK
         f5XhIR80tCoWQFcyprYbo0M38bC9UL+/o/YsFyUb5z+PzmCX58pYxdswoMYVn2MF/+c5
         ttXR5+Z6sHbkUVOxFqggL+1yAUqkgzUQ2Itj8RpON6Ca+96xJxIvjBi/pBj6IadQpvSD
         Ynsw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=bIiZn1VwnXR7nWlpmV8MIqsNXsiVcGt5YYtqvnUvlNk=;
        b=qCp/SVmhH+qwXShn1ONjUoGzMC6uiL1hZ/fKAAMo4xZ2icaVsQCUpNI19mOa+lG6aD
         9Tp0EUV3GKzwCvhBSPa03OuY73wZ+jTsK6zYVtUPhj6WzaDCm74Hxy86sGd6VcOtGMhv
         DAxIL3AbM7qZWqopMPWu0iC25/Df2bKmsu8dLudRYnPSXUxoA0QERzfuyixtJjy0U8Qc
         HJvxWKVowKMxcTqSmrhWYtRBOuLdoKi7YAACBXZLRWsv39+S+16EFUONbYnCbfX604+N
         p83rc55klKvkpEu2hjE4vU4+CoKp11DpTKMtiqOkbx55LZ06YSMo5is1unqAHIzp13CL
         u23A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ad/94qNm";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bIiZn1VwnXR7nWlpmV8MIqsNXsiVcGt5YYtqvnUvlNk=;
        b=YATIPvLfXjW1dvsSx4rPqE6kwOrOOv9TgD2Vqh/4vj+iJouwMRIwLfv78gnQmkbGvi
         R37kAkVVBCt4/0FXOgyfP/r4dOLX3ISMZdIaES+GqpYtxMHi5g0qZB8ETQesXEYOY0rq
         hP6yHhbgW/YZIXEE/eLybEzNhY0VzjaID5QpVoASjNo+nRDUEPxhygXkO33w5BKR4Y+M
         ze0oAqxnnuS9aCGNWygA6BzAEZDU9Vs0yDV9EhYf+B/mW4lygTu+mTNICpSJcYSpwwHH
         O2YaAHtnGht694t0aIOUH4rr1bSX55j/zqX9rCzkN6Y8jHAoLSDmlkJNuR1SawJZYFwy
         WXIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=bIiZn1VwnXR7nWlpmV8MIqsNXsiVcGt5YYtqvnUvlNk=;
        b=P8AMMiLDC1+cJKFp8bffpaVdizfCVz3EcGEpxyVP512YkvMexOHEFUUcIquhA4hP7Q
         /tVi8ExIQTBDImyIC+eDAkdwD55h70uZopSQ6vJMSnDTrURZC5MmV71r2iYFtUWm+Hze
         46q8JGz4Cto4LDoU2ITN/kEkMhIrcMy/nC7NJIdQUDGlZZbK8V/hJ+SC9isZ6R/mjz/C
         XkK7xe56mnPtlEAwPVQJVVCewFT16N/pLURv9jkLt+rXvDs1c2pRFn5KmWq13F8gwklf
         GBayO/RAH3b18DQKS7bPGtaGNCnW6BLt/9MbTqz7nT8o0jf9UQeyDbc1RKXXJVPAPnRM
         OdqQ==
X-Gm-Message-State: AOAM5305aIT63Pimt/KJP0Gt+fUlOUkxW6ilWayaCNXSTs1jmZqJC/vV
	ewAnXrVm25VLa5jRIOJ+KB8=
X-Google-Smtp-Source: ABdhPJyxbpLpLBgtghoYiKyZiGeUDbZfEPlsM2xzBmZAglMhfjCmJjZjE8ilD94mKTtAsghViTsnnQ==
X-Received: by 2002:a9d:7d8e:: with SMTP id j14mr4688426otn.227.1616510831274;
        Tue, 23 Mar 2021 07:47:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:f057:: with SMTP id o84ls2096765oih.3.gmail; Tue, 23 Mar
 2021 07:47:10 -0700 (PDT)
X-Received: by 2002:aca:ea44:: with SMTP id i65mr3516603oih.149.1616510830916;
        Tue, 23 Mar 2021 07:47:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616510830; cv=none;
        d=google.com; s=arc-20160816;
        b=oSbzBB073hgZjwi0KD3+u0esukZSKvGrVTTym8nXCaTM6x5sT5iGTTX7igMpHGzvo6
         uMRlHS/lGcL8T2v35ggtc9+A52WE61Drkd3pynB509y1mlDKeYqpf/exoS1wmD5p6K/a
         pKvA8kcxaK7Cm7PEm3XlY6oherpviOwB/KS0oJ2gILxeKgNK2TDmjg4PMOoMw7NshwmN
         NN+0NhWoI5P9fvdDqq0T2NKrEo2bB56o014kAskUWe6qzhZ8AgTVAKgHqXXmY7M7dP0x
         Cz23jhllDtpX2DXrAFQ+fBRi9jyia7EommQjgMMC+ACrzO0oRSUQpaXv75ILt4gK17S+
         MgjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=gpia+Vnmelhb+By3tpLV5AdcKYYPAVWKDovgDS0Hqc4=;
        b=R25yzDOx+s4WzpXqtc+0QdfPDF0jqXz39qDhM67uGC/IydGfMDXJeDunyEEpHBvANl
         H6CxM1Jqxz3uU/BX7QQeuwfJIRatfGaEG3t/A8ZDdBl0dVkSNZI7eOhyuesihZnQiIq0
         T8muF9X3RCP+8W6AA8PIOC0DCRJLtJweXIqhOO3tsA8vHGFw0fKemeveurPlbDOR4pyI
         iDCrTHK+Jf3Y35EFlAViJQ1MNJsY1aLz4RPQjldcs/PNKkPf5DtWQcg+BJdsaPXeCVhM
         Hyr5ycK6rPhVSGONjvM2Wxd2219ZrEUlYlrClrveHblbMbJ/z1lxqLyM016BDw8zP6ac
         sgug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="Ad/94qNm";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x336.google.com (mail-ot1-x336.google.com. [2607:f8b0:4864:20::336])
        by gmr-mx.google.com with ESMTPS id f2si1452800oob.2.2021.03.23.07.47.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 Mar 2021 07:47:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as permitted sender) client-ip=2607:f8b0:4864:20::336;
Received: by mail-ot1-x336.google.com with SMTP id w21-20020a9d63950000b02901ce7b8c45b4so19673641otk.5
        for <kasan-dev@googlegroups.com>; Tue, 23 Mar 2021 07:47:10 -0700 (PDT)
X-Received: by 2002:a05:6830:148c:: with SMTP id s12mr4771829otq.251.1616510830338;
 Tue, 23 Mar 2021 07:47:10 -0700 (PDT)
MIME-Version: 1.0
References: <ebe1d0bd-39fe-d7a0-9dcc-d8e70895a078@i-love.sakura.ne.jp>
 <CANpmjNM60W4nYEYCEt9SJ9f4L194WEk_ORey8s+DbgnokJZ53g@mail.gmail.com> <YFnmayHmYcrNk3V+@elver.google.com>
In-Reply-To: <YFnmayHmYcrNk3V+@elver.google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Mar 2021 15:46:58 +0100
Message-ID: <CANpmjNM5xCWXdErqv4btAL2yvqVpWWXcjG6659hNy_NBQ0YdaA@mail.gmail.com>
Subject: Re: [5.12-rc4] int3 problem at kfence_alloc() when allocating memory.
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="Ad/94qNm";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::336 as
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

On Tue, 23 Mar 2021 at 14:00, Marco Elver <elver@google.com> wrote:
>
> On Tue, Mar 23, 2021 at 12:37PM +0100, Marco Elver wrote:
> > On Tue, 23 Mar 2021 at 09:33, Tetsuo Handa
> > <penguin-kernel@i-love.sakura.ne.jp> wrote:
> > > When I run
> > >
> > >   qemu-system-x86_64 -no-reboot -smp 8 -m 4G -kernel arch/x86/boot/bzImage -nographic -append "oops=panic panic_on_warn=1 panic=1"
> > >
> > > on Ubuntu 20.04.2 LTS running on VMware Workstation on Windows PC, I randomly hit crash at arch_static_branch() when allocating memory.
> > >
> > >   # ./scripts/faddr2line vmlinux kmem_cache_alloc_node_trace+0x1a4/0x8b0
> > >   kmem_cache_alloc_node_trace+0x1a4/0x8b0:
> > >   arch_static_branch at arch/x86/include/asm/jump_label.h:25
> >
> > So this is pointing at asm_volatile_goto().
> >
> > >   (inlined by) kfence_alloc at include/linux/kfence.h:119
> > >   (inlined by) slab_alloc_node at mm/slub.c:2830
> > >   (inlined by) kmem_cache_alloc_node_trace at mm/slub.c:2957
> > >
> > > Kernel config is at http://I-love.SAKURA.ne.jp/tmp/config-5.12-rc4-kfence . Any ideas?
> >
> > We're still trying to debug, but thus far have narrowed it down to:
> >
> > 1. A QEMU bug. It only reproduces in x86 emulation mode. When adding
> > -enable-kvm, it no longer reproduces. I also managed to segfault qemu.
> >
> > 2. A really bad race in jump_labels subsystem that only manifests in
> > emulation mode? Since we also continuously run on syzbot with various
> > instances, my guess is that we should have already found it on syzbot,
> > if this was the case.
> >
> > I'm currently trying to repro the qemu segfault and also build qemu with ASan.
>
> I got the below with ASan on qemu and attached .config, and running this
> for ~5min:
>
>         while ./qemu-system-x86_64 -no-reboot -smp 10 -m 2G -kernel arch/x86/boot/bzImage -nographic \
>                 -append "oops=panic panic_on_warn=1 panic=1 kfence.sample_interval=1 nokaslr"; do sleep 0.5s; done
[...]
> | =================================================================
> | ==3499864==ERROR: AddressSanitizer: heap-use-after-free on address 0x61900083cd50 at pc 0x55e1e9ad65fb bp 0x7f82e71fd800 sp 0x7f82e71fd7f8
> | READ of size 8 at 0x61900083cd50 thread T2
> | [    4.710656][    T1] pci 0000:00:02.0: reg 0x30: [mem 0xfebe0000-0xfebeffff pref]
> | [    4.710656][    T1] pci 0000:00:03.0: [8086:100e] type 00 class 0x020000
> | [    4.710661][    T1] pci 0000:00:03.0: reg 0x10: [mem 0xfebc0000-0xfebdffff]
> | [    4.710661][    T1] pci 0000:00:03.0: reg 0x14: [io  0xc000-0xc03f]
> | [    4.710661][    T1] pci 0000:00:03.0: reg 0x30: [mem 0xfeb80000-0xfebbffff pref]
> | [    4.710661][    T1] ACPI: PCI Interrupt Link [LNKA] (IRQs 5 *10 11)
> | [    4.710661][    T1] ACPI: PCI Interrupt Link [LNKB] (IRQs 5 *10 11)
> | [    4.710661][    T1] ACPI: PCI Interrupt Link [LNKC] (IRQs 5 10 *11)
> | [    4.710661][    T1] ACPI: PCI Interrupt Link [LNKD] (IRQs 5 10 *11)
> | [    4.710661][    T1] ACPI: PCI Interrupt Link [LNKS] (IRQs *9)
> |     #0 0x55e1e9ad65fa in io_writex ../accel/tcg/cputlb.c:1408
> |     #1 0x55e1e9af547f in store_helper ../accel/tcg/cputlb.c:2444
> |     #2 0x55e1e9af547f in helper_le_stl_mmu ../accel/tcg/cputlb.c:2510
> |     #3 0x7f836f4c7b9c  (<unknown module>)
> |
> | 0x61900083cd50 is located 208 bytes inside of 1024-byte region [0x61900083cc80,0x61900083d080)
> | freed by thread T11 here:
> |     #0 0x7f83af0c51f8 in __interceptor_realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:164
> |     #1 0x7f83ae6afde7 in g_realloc (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x57de7)
> |
> | previously allocated by thread T11 here:
> |     #0 0x7f83af0c51f8 in __interceptor_realloc ../../../../src/libsanitizer/asan/asan_malloc_linux.cpp:164
> |     #1 0x7f83ae6afde7 in g_realloc (/lib/x86_64-linux-gnu/libglib-2.0.so.0+0x57de7)
> |
> | Thread T2 created by T0 here:
> |     #0 0x7f83af0702a2 in __interceptor_pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:214
> |     #1 0x55e1ea02aefe in qemu_thread_create ../util/qemu-thread-posix.c:558
> |
> | Thread T11 created by T0 here:
> |     #0 0x7f83af0702a2 in __interceptor_pthread_create ../../../../src/libsanitizer/asan/asan_interceptors.cpp:214
> |     #1 0x55e1ea02aefe in qemu_thread_create ../util/qemu-thread-posix.c:558
> |
> | SUMMARY: AddressSanitizer: heap-use-after-free ../accel/tcg/cputlb.c:1408 in io_writex
> | Shadow bytes around the buggy address:
> |   0x0c32800ff950: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> |   0x0c32800ff960: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> |   0x0c32800ff970: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
> |   0x0c32800ff980: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
> |   0x0c32800ff990: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
> | =>0x0c32800ff9a0: fd fd fd fd fd fd fd fd fd fd[fd]fd fd fd fd fd
> |   0x0c32800ff9b0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
> |   0x0c32800ff9c0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
> |   0x0c32800ff9d0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
> |   0x0c32800ff9e0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
> |   0x0c32800ff9f0: fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd fd
> | Shadow byte legend (one shadow byte represents 8 application bytes):
> |   Addressable:           00
> |   Partially addressable: 01 02 03 04 05 06 07
> |   Heap left redzone:       fa
> |   Freed heap region:       fd
> |   Stack left redzone:      f1
> |   Stack mid redzone:       f2
> |   Stack right redzone:     f3
> |   Stack after return:      f5
> |   Stack use after scope:   f8
> |   Global redzone:          f9
> |   Global init order:       f6
> |   Poisoned by user:        f7
> |   Container overflow:      fc
> |   Array cookie:            ac
> |   Intra object redzone:    bb
> |   ASan internal:           fe
> |   Left alloca redzone:     ca
> |   Right alloca redzone:    cb
> |   Shadow gap:              cc
> | ==3499864==ABORTING
>
> This looks like a racy use-after-free...

I reported https://bugs.launchpad.net/qemu/+bug/1920934 -- probably
not much else we can do for now.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNM5xCWXdErqv4btAL2yvqVpWWXcjG6659hNy_NBQ0YdaA%40mail.gmail.com.
