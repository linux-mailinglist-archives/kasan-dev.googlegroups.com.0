Return-Path: <kasan-dev+bncBCMIZB7QWENRBEX23GBQMGQEEVIWYBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4956235EC35
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Apr 2021 07:26:44 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id g12-20020a056a001a0cb0290249be0baf34sf427500pfv.16
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Apr 2021 22:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1618378002; cv=pass;
        d=google.com; s=arc-20160816;
        b=YXqO1PTzov0lA0wp59UB2guiXCinnkQWjbFlIFQ/Ed45bI93GlSDXX7yH1p9BSmzK0
         XatBmZrSQn86quoAIl7wll6xmWKrZLbPHKPJMJLXOllqf1PrMCqI+9v34Q5splIDuqNF
         4xxOL4Tt58uCyv159kplZWsieGVwpVc56iiq7/EgH2ioSor/HhC1EjGafWkadtkIncjy
         OHJpTJGrVq0LxcwP0GL8Rw0qyZ1DmdkBPbrJKraz7Ktkiwz9sY/LGn5Ow00HljUW3wG3
         4ZGHaFaa79Ln3q5+zz7fk85UwYGUA1DPFUAcY4jGVOLeW+2qg5G/pZ2vi0M+okSSzF7y
         kAlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=YPS59FYbN96/X9Ckk8OzdRKViXb96iwD/8mglzskYGk=;
        b=KvCnPlO2iZFg6OYeqOfWAkGxBjxEKRRU0dSUUl7MNGCQzAhKJrdKl3i9ZINrG8RD4t
         ZdNfE+PGRML6ft2lUBF4Zc0Kp0TXUqBZYTf200gmGBXENkDlq5cqxwBAYZOun9UbGotv
         LnF5XQ78uadOIX1dqlPPoUbNkqM2kcJIocykue/Bj5cWBMsP1YWiHmmD6FeLAgb95at+
         y1WmY698Bk5O6hyFsdUgv4MukepfZzJDhcaXjNQZ71efcjND/ivEFNo4HGB+QmIUzVR/
         DWxytlDeGCnnmkgHVtcjDXYm2PXxaVeffVfnR91Oc3gSYef2oLwkT0CWLvGNnSC/mStI
         fyMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cGSbC3qL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=YPS59FYbN96/X9Ckk8OzdRKViXb96iwD/8mglzskYGk=;
        b=SepVLYdf8VUTuMpBQotjMkIe6hSpOpmtFRc9gmFmlRfn87xi2m2WotXmWDXJ7sNDdw
         /6PWHUUyEbP3KZvFwDQbsoPZH5YlWYqAEFcHuOqLKa7lVejXMEniyiavPFAKTW1YE4UK
         MHy7xH1fp2EMe5PKTWw4texMnTd8zSw8hWTJb7EEu2a+zb6dP5IaTmDaLqfa67pHXKzZ
         j38uFhm3OF2HN29qjQav7HPHq7UT0X3BBwYPMss25x42RofI5cEEW5nNqS1xQjHCSARG
         Hma5a0pK357jjl2K54AVAb0JC12v2SiMtW4i7fb/UpmNPqoroIW2w4dWFPg3iKonZ4vE
         0vZw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YPS59FYbN96/X9Ckk8OzdRKViXb96iwD/8mglzskYGk=;
        b=oyDdNpyZs4AZ3139BS69lIfGDzNhtuAleeB0Kq5q0xrri0svfm3PP776QzDDc08WoQ
         uw0BfrP0cX0tpHkZa6dUItS0Nu2zROsC7iaW3ldMoAIi7ppu68oc3ZnYS2OM6xYkDead
         qrpU9HmBI8YDJ1mWW6bpUb+PxoZJcd1Ac6PQeswnDs1tVPcGIq05OuV0S5UybIjumeWQ
         a7gusHwrEZ8YdC04ct3xfs/gookfiMCr8Gq2W5k9WDWhItsP/Wqk+wHbLQ4F0I3NudU/
         yUaLTzzkUztG/uCbVpyUjuOuUDBcNMLWqNP4isBFrVN1PJYMG06P0tIghjV3UbJCEw9g
         ZUYA==
X-Gm-Message-State: AOAM5324jhz4vNeyStZGyPojycXxByFDPSeyH4ARD22/+M3XqzDxXnpK
	yrV40fR5mJnYdVYu/XUcmiw=
X-Google-Smtp-Source: ABdhPJzqSf5SxaYpJKCFYr3WZAxeIPkxz5/9iytybhxUwia8RtGOWpZiu8zVnlX2KvO4segYFj9OdQ==
X-Received: by 2002:a17:90b:344a:: with SMTP id lj10mr1640779pjb.101.1618378002568;
        Tue, 13 Apr 2021 22:26:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d385:: with SMTP id e5ls579461pld.10.gmail; Tue, 13
 Apr 2021 22:26:41 -0700 (PDT)
X-Received: by 2002:a17:902:bd08:b029:e9:4227:427e with SMTP id p8-20020a170902bd08b02900e94227427emr35165794pls.58.1618378001732;
        Tue, 13 Apr 2021 22:26:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1618378001; cv=none;
        d=google.com; s=arc-20160816;
        b=ECz8Y5cbJ/sziTAnKRWFJCIQNrPkupGVhQZfZwtMjLn3NppQBUSMFAno6XL2sHWgXL
         rpaKV3bvckxWRHcONd5a/+iYZof9bkGo/Pz7OkAYmC+KjCUPuv8z365djKtIwXTcRwYB
         kcVrxdREAFynkJfOSWyPkvAey99+bdSWoAjmhd1qlyt3Eg8bBInC4UDuDu+rPO4bwIwY
         W3A7z2rokfInnnCnanUnWNJehM5wXV8VRrm+PjKbm49lmRk63Shcn/M7jkrFbSYlE46o
         W8Mzy5ibpqZ3ok1TlymPQP+C6NUS7KJncbUjt9ZPvdaE9rX1FHHcRgl9FJqNqs+WOWb/
         NqFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=goGn5IVq7iLXQjA/Ay9tLsM6lzkzcPfAVlxbYsVpcH4=;
        b=yjB2SpuvY2FKe53NmoD1KoSTuRB7Y5f+XZ1GApHKg+X85RYBUcmDPBHA2bNkwi+qGZ
         AgNoQiaQ4MP1LVwJ2Z+mmq2ef5+PTKrlc1XpBvwDGT+5PZbh+8CNy9sjoHyG6CJAFO0E
         zTrQvW1Jn7jIvOoXilG89sL8pXa4y0M6ZZR3z88PjM8I1b8tAwucgTRMEuH1UOAV9qFy
         P01yme5T4Xr6Ffhz97xhRFuRNk3nkdaocu6FNi2ehAylWomp6E1oc/7JZ40uAEqYAw2d
         DYULxUZEthoBm/dDVJLlF7NsFmclBgdqfUdOeevctOAn4GlqaCWaKyPYmp9hEDBymRNn
         tXbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=cGSbC3qL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x82e.google.com (mail-qt1-x82e.google.com. [2607:f8b0:4864:20::82e])
        by gmr-mx.google.com with ESMTPS id u12si1587033pgf.0.2021.04.13.22.26.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Apr 2021 22:26:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e as permitted sender) client-ip=2607:f8b0:4864:20::82e;
Received: by mail-qt1-x82e.google.com with SMTP id m16so13984022qtx.9
        for <kasan-dev@googlegroups.com>; Tue, 13 Apr 2021 22:26:41 -0700 (PDT)
X-Received: by 2002:ac8:110d:: with SMTP id c13mr33322391qtj.337.1618378000643;
 Tue, 13 Apr 2021 22:26:40 -0700 (PDT)
MIME-Version: 1.0
References: <BY5PR11MB4193DBB0DE4AF424DE235892FF769@BY5PR11MB4193.namprd11.prod.outlook.com>
 <CACT4Y+bsOhKnv2ikR1fTb7KhReGfEeAyxCOyvCu7iS37Lm0vnw@mail.gmail.com> <182eea30ee9648b2a618709e9fc894e49cb464ad.camel@gmx.de>
In-Reply-To: <182eea30ee9648b2a618709e9fc894e49cb464ad.camel@gmx.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Apr 2021 07:26:29 +0200
Message-ID: <CACT4Y+bVkBscD+Ggp6oQm3LbyiMVmwaaX20fQJLHobg6_z4VzQ@mail.gmail.com>
Subject: Re: Question on KASAN calltrace record in RT
To: Mike Galbraith <efault@gmx.de>
Cc: "Zhang, Qiang" <Qiang.Zhang@windriver.com>, Andrew Halaney <ahalaney@redhat.com>, 
	"andreyknvl@gmail.com" <andreyknvl@gmail.com>, "ryabinin.a.a@gmail.com" <ryabinin.a.a@gmail.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=cGSbC3qL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::82e
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

On Wed, Apr 14, 2021 at 6:00 AM Mike Galbraith <efault@gmx.de> wrote:
>
> On Tue, 2021-04-13 at 17:29 +0200, Dmitry Vyukov wrote:
> > On Tue, Apr 6, 2021 at 10:26 AM Zhang, Qiang <Qiang.Zhang@windriver.com=
> wrote:
> > >
> > > Hello everyone
> > >
> > > In RT system,   after  Andrew test,   found the following calltrace ,
> > > in KASAN, we record callstack through stack_depot_save(), in this fun=
ction, may be call alloc_pages,  but in RT, the spin_lock replace with
> > > rt_mutex in alloc_pages(), if before call this function, the irq is d=
isabled,
> > > will trigger following calltrace.
> > >
> > > maybe  add array[KASAN_STACK_DEPTH] in struct kasan_track to record c=
allstack  in RT system.
> > >
> > > Is there a better solution =EF=BC=9F
> >
> > Hi Qiang,
> >
> > Adding 2 full stacks per heap object can increase memory usage too much=
.
> > The stackdepot has a preallocation mechanism, I would start with
> > adding interrupts check here:
> > https://elixir.bootlin.com/linux/v5.12-rc7/source/lib/stackdepot.c#L294
> > and just not do preallocation in interrupt context. This will solve
> > the problem, right?
>
> Hm, this thing might actually be (sorta?) working, modulo one startup
> gripe.  The CRASH_DUMP inspired gripe I get with !RT appeared (and shut
> up when told I don't care given kdump has worked just fine for ages:),
> but no more might_sleep() gripeage.
>
>
> CONFIG_KASAN_SHADOW_OFFSET=3D0xdffffc0000000000
> CONFIG_HAVE_ARCH_KASAN=3Dy
> CONFIG_HAVE_ARCH_KASAN_VMALLOC=3Dy
> CONFIG_CC_HAS_KASAN_GENERIC=3Dy
> CONFIG_KASAN=3Dy
> CONFIG_KASAN_GENERIC=3Dy
> CONFIG_KASAN_OUTLINE=3Dy
> # CONFIG_KASAN_INLINE is not set
> CONFIG_KASAN_STACK=3D1
> CONFIG_KASAN_VMALLOC=3Dy
> # CONFIG_KASAN_MODULE_TEST is not set
>
> ---
>  lib/stackdepot.c |   10 +++++-----
>  1 file changed, 5 insertions(+), 5 deletions(-)
>
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -71,7 +71,7 @@ static void *stack_slabs[STACK_ALLOC_MAX
>  static int depot_index;
>  static int next_slab_inited;
>  static size_t depot_offset;
> -static DEFINE_SPINLOCK(depot_lock);
> +static DEFINE_RAW_SPINLOCK(depot_lock);
>
>  static bool init_stack_slab(void **prealloc)
>  {
> @@ -265,7 +265,7 @@ depot_stack_handle_t stack_depot_save(un
>         struct page *page =3D NULL;
>         void *prealloc =3D NULL;
>         unsigned long flags;
> -       u32 hash;
> +       u32 hash, may_prealloc =3D !IS_ENABLED(CONFIG_PREEMPT_RT) || pree=
mptible();
>
>         if (unlikely(nr_entries =3D=3D 0) || stack_depot_disable)
>                 goto fast_exit;
> @@ -291,7 +291,7 @@ depot_stack_handle_t stack_depot_save(un
>          * The smp_load_acquire() here pairs with smp_store_release() to
>          * |next_slab_inited| in depot_alloc_stack() and init_stack_slab(=
).
>          */
> -       if (unlikely(!smp_load_acquire(&next_slab_inited))) {
> +       if (unlikely(!smp_load_acquire(&next_slab_inited) && may_prealloc=
)) {
>                 /*
>                  * Zero out zone modifiers, as we don't have specific zon=
e
>                  * requirements. Keep the flags related to allocation in =
atomic
> @@ -305,7 +305,7 @@ depot_stack_handle_t stack_depot_save(un
>                         prealloc =3D page_address(page);
>         }
>
> -       spin_lock_irqsave(&depot_lock, flags);
> +       raw_spin_lock_irqsave(&depot_lock, flags);
>
>         found =3D find_stack(*bucket, entries, nr_entries, hash);
>         if (!found) {
> @@ -329,7 +329,7 @@ depot_stack_handle_t stack_depot_save(un
>                 WARN_ON(!init_stack_slab(&prealloc));
>         }
>
> -       spin_unlock_irqrestore(&depot_lock, flags);
> +       raw_spin_unlock_irqrestore(&depot_lock, flags);
>  exit:
>         if (prealloc) {
>                 /* Nobody used this memory, ok to free it. */
>
> [    0.692437] BUG: sleeping function called from invalid context at kern=
el/locking/rtmutex.c:943
> [    0.692439] in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 1, =
name: swapper/0
> [    0.692442] Preemption disabled at:
> [    0.692443] [<ffffffff811a1510>] on_each_cpu_cond_mask+0x30/0xb0
> [    0.692451] CPU: 5 PID: 1 Comm: swapper/0 Not tainted 5.12.0.g2afefec-=
tip-rt #5
> [    0.692454] Hardware name: MEDION MS-7848/MS-7848, BIOS M7848W08.20C 0=
9/23/2013
> [    0.692456] Call Trace:
> [    0.692458]  ? on_each_cpu_cond_mask+0x30/0xb0
> [    0.692462]  dump_stack+0x8a/0xb5
> [    0.692467]  ___might_sleep.cold+0xfe/0x112
> [    0.692471]  rt_spin_lock+0x1c/0x60

HI Mike,

If freeing pages from smp_call_function is not OK, then perhaps we
need just to collect the objects to be freed to the task/CPU that
executes kasan_quarantine_remove_cache and it will free them (we know
it can free objects).

> [    0.692475]  free_unref_page+0x117/0x3c0
> [    0.692481]  qlist_free_all+0x60/0xd0
> [    0.692485]  per_cpu_remove_cache+0x5b/0x70
> [    0.692488]  smp_call_function_many_cond+0x185/0x3d0
> [    0.692492]  ? qlist_move_cache+0xe0/0xe0
> [    0.692495]  ? qlist_move_cache+0xe0/0xe0
> [    0.692497]  on_each_cpu_cond_mask+0x44/0xb0
> [    0.692501]  kasan_quarantine_remove_cache+0x52/0xf0
> [    0.692505]  ? acpi_bus_init+0x183/0x183
> [    0.692510]  kmem_cache_shrink+0xe/0x20
> [    0.692513]  acpi_os_purge_cache+0xa/0x10
> [    0.692517]  acpi_purge_cached_objects+0x1d/0x68
> [    0.692522]  acpi_initialize_objects+0x11/0x39
> [    0.692524]  ? acpi_ev_install_xrupt_handlers+0x6f/0x7c
> [    0.692529]  acpi_bus_init+0x50/0x183
> [    0.692532]  acpi_init+0xce/0x182
> [    0.692536]  ? acpi_bus_init+0x183/0x183
> [    0.692539]  ? intel_idle_init+0x36d/0x36d
> [    0.692543]  ? acpi_bus_init+0x183/0x183
> [    0.692546]  do_one_initcall+0x71/0x300
> [    0.692550]  ? trace_event_raw_event_initcall_finish+0x120/0x120
> [    0.692553]  ? parameq+0x90/0x90
> [    0.692556]  ? __wake_up_common+0x1e0/0x200
> [    0.692560]  ? kasan_unpoison+0x21/0x50
> [    0.692562]  ? __kasan_slab_alloc+0x24/0x70
> [    0.692567]  do_initcalls+0xff/0x129
> [    0.692571]  kernel_init_freeable+0x19c/0x1ce
> [    0.692574]  ? rest_init+0xc6/0xc6
> [    0.692577]  kernel_init+0xd/0x11a
> [    0.692580]  ret_from_fork+0x1f/0x30
>
> [   15.428008] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   15.428011] BUG: KASAN: vmalloc-out-of-bounds in crash_setup_memmap_en=
tries+0x17e/0x3a0

This looks like a genuine kernel bug on first glance. I think it needs
to be fixed rather than ignored.

> [   15.428018] Write of size 8 at addr ffffc90000426008 by task kexec/118=
7
> [   15.428022] CPU: 2 PID: 1187 Comm: kexec Tainted: G        W   E     5=
.12.0.g2afefec-tip-rt #5
> [   15.428025] Hardware name: MEDION MS-7848/MS-7848, BIOS M7848W08.20C 0=
9/23/2013
> [   15.428027] Call Trace:
> [   15.428029]  ? crash_setup_memmap_entries+0x17e/0x3a0
> [   15.428032]  dump_stack+0x8a/0xb5
> [   15.428037]  print_address_description.constprop.0+0x16/0xa0
> [   15.428044]  kasan_report+0xc4/0x100
> [   15.428047]  ? crash_setup_memmap_entries+0x17e/0x3a0
> [   15.428050]  crash_setup_memmap_entries+0x17e/0x3a0
> [   15.428053]  ? strcmp+0x2e/0x50
> [   15.428057]  ? native_machine_crash_shutdown+0x240/0x240
> [   15.428059]  ? kexec_purgatory_find_symbol.isra.0+0x145/0x1a0
> [   15.428066]  setup_boot_parameters+0x181/0x5c0
> [   15.428069]  bzImage64_load+0x6b5/0x740
> [   15.428072]  ? bzImage64_probe+0x140/0x140
> [   15.428075]  ? iov_iter_kvec+0x5f/0x70
> [   15.428080]  ? rw_verify_area+0x80/0x80
> [   15.428087]  ? __might_sleep+0x31/0xd0
> [   15.428091]  ? __might_sleep+0x31/0xd0
> [   15.428094]  ? ___might_sleep+0xc9/0xe0
> [   15.428096]  ? bzImage64_probe+0x140/0x140
> [   15.428099]  arch_kexec_kernel_image_load+0x102/0x130
> [   15.428102]  kimage_file_alloc_init+0xda/0x290
> [   15.428107]  __do_sys_kexec_file_load+0x21f/0x390
> [   15.428110]  ? __x64_sys_open+0x100/0x100
> [   15.428113]  ? kexec_calculate_store_digests+0x390/0x390
> [   15.428117]  ? rcu_nocb_flush_deferred_wakeup+0x36/0x50
> [   15.428122]  do_syscall_64+0x3d/0x80
> [   15.428127]  entry_SYSCALL_64_after_hwframe+0x44/0xae
> [   15.428132] RIP: 0033:0x7f46ad026759
> [   15.428135] Code: 00 48 81 c4 80 00 00 00 89 f0 c3 66 0f 1f 44 00 00 4=
8 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <=
48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 0f d7 2b 00 f7 d8 64 89 01 48
> [   15.428137] RSP: 002b:00007ffcf6f96788 EFLAGS: 00000206 ORIG_RAX: 0000=
000000000140
> [   15.428141] RAX: ffffffffffffffda RBX: 0000000000000006 RCX: 00007f46a=
d026759
> [   15.428143] RDX: 0000000000000182 RSI: 0000000000000005 RDI: 000000000=
0000003
> [   15.428145] RBP: 00007ffcf6f96a28 R08: 0000000000000002 R09: 000000000=
0000000
> [   15.428146] R10: 0000000000b0d5e0 R11: 0000000000000206 R12: 000000000=
0000004
> [   15.428148] R13: 0000000000000000 R14: 0000000000000000 R15: 00000000f=
fffffff
> [   15.428152] Memory state around the buggy address:
> [   15.428164]  ffffc90000425f00: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 =
f8 f8 f8
> [   15.428166]  ffffc90000425f80: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 =
f8 f8 f8
> [   15.428168] >ffffc90000426000: 00 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 =
f8 f8 f8
> [   15.428169]                       ^
> [   15.428171]  ffffc90000426080: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 =
f8 f8 f8
> [   15.428172]  ffffc90000426100: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 =
f8 f8 f8
> [   15.428173] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> [   15.428174] Disabling lock debugging due to kernel taint
>
> kasan: stop grumbling about CRASH_DUMP
>
> Signed-off-by: Mike Galbraith <efault@gmx.de>
> ---
>  arch/x86/kernel/Makefile |    1 +
>  kernel/Makefile          |    1 +
>  2 files changed, 2 insertions(+)
>
> --- a/arch/x86/kernel/Makefile
> +++ b/arch/x86/kernel/Makefile
> @@ -105,6 +105,7 @@ obj-$(CONFIG_X86_TSC)               +=3D trace_clock.=
o
>  obj-$(CONFIG_CRASH_CORE)       +=3D crash_core_$(BITS).o
>  obj-$(CONFIG_KEXEC_CORE)       +=3D machine_kexec_$(BITS).o
>  obj-$(CONFIG_KEXEC_CORE)       +=3D relocate_kernel_$(BITS).o crash.o
> +KASAN_SANITIZE_crash.o         :=3D n
>  obj-$(CONFIG_KEXEC_FILE)       +=3D kexec-bzimage64.o
>  obj-$(CONFIG_CRASH_DUMP)       +=3D crash_dump_$(BITS).o
>  obj-y                          +=3D kprobes/
> --- a/kernel/Makefile
> +++ b/kernel/Makefile
> @@ -72,6 +72,7 @@ obj-$(CONFIG_CRASH_CORE) +=3D crash_core.o
>  obj-$(CONFIG_KEXEC_CORE) +=3D kexec_core.o
>  obj-$(CONFIG_KEXEC) +=3D kexec.o
>  obj-$(CONFIG_KEXEC_FILE) +=3D kexec_file.o
> +KASAN_SANITIZE_kexec_file.o :=3D n
>  obj-$(CONFIG_KEXEC_ELF) +=3D kexec_elf.o
>  obj-$(CONFIG_BACKTRACE_SELF_TEST) +=3D backtracetest.o
>  obj-$(CONFIG_COMPAT) +=3D compat.o
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BbVkBscD%2BGgp6oQm3LbyiMVmwaaX20fQJLHobg6_z4VzQ%40mail.gm=
ail.com.
