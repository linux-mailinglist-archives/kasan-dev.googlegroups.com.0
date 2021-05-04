Return-Path: <kasan-dev+bncBCMIZB7QWENRBA7NYOCAMGQEOX2MHFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe40.google.com (mail-vs1-xe40.google.com [IPv6:2607:f8b0:4864:20::e40])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D3FC372685
	for <lists+kasan-dev@lfdr.de>; Tue,  4 May 2021 09:23:48 +0200 (CEST)
Received: by mail-vs1-xe40.google.com with SMTP id z7-20020a67ca070000b0290220c083d3acsf3992737vsk.21
        for <lists+kasan-dev@lfdr.de>; Tue, 04 May 2021 00:23:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620113027; cv=pass;
        d=google.com; s=arc-20160816;
        b=m6HCPYe2fMQ2qGBBUwSUCJZhz1Gs7KF3XX817BHraqBlWmytxWPR0bpjThQDxHHd6+
         Pegz/Y98GbkEjPArqLn4k2lO7LoIa6VyWPbAOEqAoqRp/QRQ/sQayCQRFvzDyDilhWFq
         35utXwuMY2CrsEO8L+O3j39joD2f/cVn/EK9/F3HAXyzim0aLeKRidb3bvkIMy/xQfog
         T266sqX8SqV9y/IMZQt7Krgc/hix+dMpxvSup6cuyz2Us7B9zUaBfnDHMaRauEeCKTs3
         nbJ8Bmxy8UvDCU7OLF3lwrzfg/SXIzWdDX3DHgn0YjlH+ytcCfwuhXLd5pUgzUL6aBie
         C0bg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=9HwSulSdzzL0TTP4Ka2HAyr3JtHhx6CUNXUiV4Utjfo=;
        b=E/1uGkclpPuZdmEVnbyjTXvD1BpDHHypdkDUD5/x+L3RE/gUrEQugo/kF5Tqq0E0Ax
         KoPfPDGRKtdaBuk2+4PslQIYOs+rhEvbJJz0IkI9d70Gpug49AWkpmC/P1rxOyvS1Eyd
         OYIpj+dzdIwXnzTZtg2+6RxyLCs5TcH2f/w6iE2IoFit/JioDR/aMG3a6vWNdXgjdFNT
         Sid1lVhRwi1jia6f0oru01UTcpf4HuFjArHdKBef0RMkUmUwyRHOuzsh/B6K1xyYXz5/
         ns8eNIlfVZQSO6tX8fgUpffnvgdfbvr8VR1MWAYmsw5dmtxoFVjju/7WhYdOARM67WBO
         S6og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P+F1pXmx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9HwSulSdzzL0TTP4Ka2HAyr3JtHhx6CUNXUiV4Utjfo=;
        b=nRMj5H9IbWfZS1i73Wob6UwgrzbNe0SH6c7L/BQBXEZabwS+dWLIfajkLU3+xht4Aj
         b8ifbeVCdAAqDamt98v/cMtQ/SI8bb7tXU2grnBzYCjve+o/gnN0CoNiXd6rjxORqfmo
         tx4AsHFDDX2dH56oia7AzRLvPX7/9ZMRkr0GudBjjHZIsGtWNMr/W4wUf6WAADjx74/Z
         gpUx6fTWV/9Ge9izJWre5/vwITKrEHu1NuwAA/qmlew4/qWKSDyqO6M5II4xIT/QWGrf
         gNY8QR8L2VVGD3tivowKngpvigzq+bbGrKugBk/D7hrIy3ZZZsUJlItig0dkncFILWoJ
         F+rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9HwSulSdzzL0TTP4Ka2HAyr3JtHhx6CUNXUiV4Utjfo=;
        b=gDop/VPOE4nrz32xFCBB7etkLB58KumI7KCmD62Ocp0TzXVX8d+x+IjpTj7RZhmW0Q
         hCAR4S4dTBReqcFbCfIbQoUtxPpOdvaguuRQe2R1LuPDvNKoxi7oeamcqCUEfp1YObpr
         xbhEXsVBYU5JSvNCF/s8ZOfplWij5NnLPRi+Wobb3PPh21u5S+4H2XCmUirQvaKDbn0m
         F/S0LK7Y/WdSYdr7wxT7HFRvW3YQH0Mhfb0W5jqVH04izZGl/dFt8jvxWaGN5lZ+oLdi
         FXNN5oXeCKLgjeEAHFWRc1TX+DeUOMEONPLA2iumVk1srBgApRlys3rgPk5Mynp7xhdY
         XxEg==
X-Gm-Message-State: AOAM532Nm2sBTKOP3xekt6QAoDzUC6XiluHhHjQQXzb0iEYS5IZYj4x5
	C9jTGneoHM+1PFprakgQtGQ=
X-Google-Smtp-Source: ABdhPJzIPkXXGfLhdyvbLHqSxUJtgVLOvbrpZU5G6iwJoRFWrm8DEAYUwiomnN+z+4DAJxe5K0C1QA==
X-Received: by 2002:a67:f498:: with SMTP id o24mr19859462vsn.6.1620113027103;
        Tue, 04 May 2021 00:23:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:cd34:: with SMTP id a20ls421049vkm.1.gmail; Tue, 04 May
 2021 00:23:46 -0700 (PDT)
X-Received: by 2002:a1f:d382:: with SMTP id k124mr18647949vkg.0.1620113026638;
        Tue, 04 May 2021 00:23:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620113026; cv=none;
        d=google.com; s=arc-20160816;
        b=i6VwkdkTP+2uSWsgulet1edNKfvP5aF7izIxp+eSIIdpU/2IuY6JeygA3Hz+g8Nhk/
         HhAWbyUURk3JoNmc/Lj9Q7v7QpJuG08xQgYdqTxtsd4L3ROpKruq4scPvkTw6fm/0ulp
         uNAh30oQFjgv2sAVujmVmdnlaOqjn0gQ9RkM7slTrzOXKjLy2yxJlexE52k+V8ry/yff
         cAG0wWFMpnn4uxa9NutgR/tBEfbckxis5dq6OWylC3wU65bLdjOZX9sEJmiQv8w6lEX0
         6+K2zNjgV7wjWRXlMdm5xp8TNdvEXd6DrPGZFX4/X6/BrOBWrrNP62T6zY1MgzkCV/lq
         raYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1wh+voeRpBtj/D9Yl3BnvAMQbLR9Yn1kha/VrRnOBis=;
        b=DKueGEbbP8epvG0+tKZEqnagoUn5oPVYbH6PsbLeIXBSbW05nFhIa+uYSX44t8nKnD
         kRyTrKnou8WF/vo4HvfIjYX89+cKWIp9KBZCtkj8znudk6ijxn/nS4CO9xdAQiRgBtG+
         5ED94s+gIeGiLfFVq4ROfWM6W0Du4lw8LMNaAVX3gs4bMg265C3gNdbkEQAkE2bA4VhD
         RKUMJIREq0Zg6jIgL5Ax17uXjxBcyJ58WsXgjhZEynHV/ERys8vggBgHRO4zljar+GSB
         4w4tkfJkRa9DBg7sRAf4gSVEBP8ER2h7Px9OQ/FsfgG5Eb+uBZdSfdmG8dmkTiwX7AEI
         1r/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=P+F1pXmx;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id m184si156876vkg.5.2021.05.04.00.23.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 May 2021 00:23:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id n22so5630243qtk.9
        for <kasan-dev@googlegroups.com>; Tue, 04 May 2021 00:23:46 -0700 (PDT)
X-Received: by 2002:ac8:110d:: with SMTP id c13mr20734116qtj.337.1620113025987;
 Tue, 04 May 2021 00:23:45 -0700 (PDT)
MIME-Version: 1.0
References: <20210504024358.894950-1-ak@linux.intel.com>
In-Reply-To: <20210504024358.894950-1-ak@linux.intel.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 4 May 2021 09:23:34 +0200
Message-ID: <CACT4Y+a5g5JeLJFPJEUxPFbMLXGkYEAJkK3MBctnn7UA-iTkXA@mail.gmail.com>
Subject: Re: [PATCH] stackdepot: Use a raw spinlock in stack depot
To: Andi Kleen <ak@linux.intel.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Peter Zijlstra <peterz@infradead.org>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=P+F1pXmx;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::829
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

On Tue, May 4, 2021 at 4:44 AM Andi Kleen <ak@linux.intel.com> wrote:
>
> In some cases kasan with lockdep complains about its own use of the stack
> depot lock. I think it happens when the kasan usage is nested inside a
> raw spinlock and it happens to create a new stack depot.
>
> Make the stackdepot lock raw too

+kasan-dev

Hi Andi,

So why is this a false positive that we just need to silence?
I see LOCKDEP is saying we are doing something wrong, and your
description just describes how we are doing something wrong :)
If this is a special false positive case, it would be good to have a
comment on DEFINE_RAW_SPINLOCK explaining why we are using it.

I wonder why we never saw this on syzbot. Is it an RT kernel or some
other special config?
A similar issue was discussed recently for RT kernel:
https://groups.google.com/g/kasan-dev/c/MyHh8ov-ciU/m/nahiuqFLAQAJ
And I think it may be fixable in the same way -- make stackdepot not
allocate in contexts where it's not OK to allocate.



> Example trace:
>
> [    1.156154] ACPI Error: No handler or method for GPE 01, disabling event (20210105/evgpe-839)
> [    1.156235] =============================
> [    1.156238] [ BUG: Invalid wait context ]
> [    1.156242] 5.12.0-00071-gb34886074b65 #45 Not tainted
> [    1.156249] -----------------------------
> [    1.156252] swapper/0/1 is trying to lock:
> [    1.156258] ffffffff8535e158 (depot_lock){..-.}-{3:3}, at: stack_depot_save+0x162/0x450
> [    1.156288] other info that might help us debug this:
> [    1.156292] context-{5:5}
> [    1.156297] 3 locks held by swapper/0/1:
> [    1.156304]  #0: ffff888100838658 (*(&acpi_gbl_gpe_lock)){....}-{3:3}, at: acpi_ev_detect_gpe+0xa8/0x3e6
> [    1.156333]  #1: ffffffff85133dc0 (rcu_read_lock){....}-{1:3}, at: __queue_work+0xd5/0x1010
> [    1.156363]  #2: ffff88815a04ec18 (&pool->lock){....}-{2:2}, at: __queue_work+0x258/0x1010
> [    1.156391] stack backtrace:
> [    1.156395] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.12.0-00071-gb34886074b65 #45
> [    1.156407] Call Trace:
> [    1.156413]  dump_stack+0xfa/0x151
> [    1.156427]  __lock_acquire.cold+0x366/0x41f
> [    1.156450]  ? orc_find+0x233/0x3c0
> [    1.156462]  ? __sanitizer_cov_trace_pc+0x1d/0x50
> [    1.156476]  ? lockdep_hardirqs_on_prepare+0x3e0/0x3e0
> [    1.156491]  ? ret_from_fork+0x1f/0x30
> [    1.156503]  ? deref_stack_reg+0x90/0x90
> [    1.156516]  lock_acquire+0x194/0x690
> [    1.156528]  ? stack_depot_save+0x162/0x450
> [    1.156541]  ? rcu_read_unlock+0x40/0x40
> [    1.156553]  ? arch_stack_walk+0x88/0xf0
> [    1.156566]  ? ret_from_fork+0x1f/0x30
> [    1.156579]  _raw_spin_lock_irqsave+0x3b/0x60
> [    1.156591]  ? stack_depot_save+0x162/0x450
> [    1.156603]  stack_depot_save+0x162/0x450
> [    1.156616]  kasan_save_stack+0x32/0x40
> [    1.156629]  ? kasan_save_stack+0x1b/0x40
> [    1.156642]  ? kasan_record_aux_stack+0xbc/0xe0
> [    1.156653]  ? insert_work+0x4b/0x2e0
> [    1.156665]  ? __queue_work+0x4cf/0x1010
> [    1.156677]  ? queue_work_on+0xb3/0xc0
> [    1.156689]  ? acpi_os_execute+0x1ca/0x340
> [    1.156701]  ? acpi_ev_gpe_dispatch+0x208/0x273
> [    1.156713]  ? acpi_ev_detect_gpe+0x35e/0x3e6
> [    1.156724]  ? acpi_ev_gpe_detect+0x269/0x334
> [    1.156736]  ? acpi_update_all_gpes+0x1cf/0x206
> [    1.156748]  ? acpi_scan_init+0x2a8/0x702
> [    1.156761]  ? acpi_init+0x230/0x2ba
> [    1.156773]  ? do_one_initcall+0xf0/0x540
> [    1.156784]  ? kernel_init_freeable+0x38e/0x412
> [    1.156796]  ? kernel_init+0x12/0x1cf
> [    1.156807]  ? ret_from_fork+0x1f/0x30
> [    1.156818]  ? kmem_cache_alloc_trace+0xf1/0x850
> [    1.156831]  ? lockdep_hardirqs_on_prepare+0x3e0/0x3e0
> [    1.156844]  ? lockdep_hardirqs_on_prepare+0x3e0/0x3e0
> [    1.156858]  ? acpi_scan_init+0x2a8/0x702
> [    1.156870]  ? do_one_initcall+0xf0/0x540
> [    1.156881]  ? kernel_init+0x12/0x1cf
> [    1.156892]  ? ret_from_fork+0x1f/0x30
> [    1.156903]  ? _raw_spin_unlock+0x1f/0x30
> [    1.156915]  ? lock_acquire+0x194/0x690
> [    1.156927]  ? __queue_work+0x258/0x1010
> [    1.156940]  ? rcu_read_unlock+0x40/0x40
> [    1.156952]  ? lock_is_held_type+0x98/0x110
> [    1.156964]  ? lock_is_held_type+0x98/0x110
> [    1.156977]  ? rcu_read_lock_sched_held+0xa1/0xe0
> [    1.156991]  kasan_record_aux_stack+0xbc/0xe0
> [    1.157003]  insert_work+0x4b/0x2e0
> [    1.157016]  __queue_work+0x4cf/0x1010
> [    1.157031]  queue_work_on+0xb3/0xc0
> [    1.157044]  acpi_os_execute+0x1ca/0x340
> [    1.157056]  acpi_ev_gpe_dispatch+0x208/0x273
> [    1.157069]  acpi_ev_detect_gpe+0x35e/0x3e6
> [    1.157082]  ? acpi_ev_gpe_dispatch+0x273/0x273
> [    1.157096]  ? lockdep_hardirqs_on_prepare+0x273/0x3e0
> [    1.157109]  ? _raw_spin_unlock_irqrestore+0x2d/0x40
> [    1.157122]  acpi_ev_gpe_detect+0x269/0x334
> [    1.157136]  ? acpi_bus_init+0x7ee/0x7ee
> [    1.157148]  acpi_update_all_gpes+0x1cf/0x206
> [    1.157161]  ? acpi_get_gpe_device+0x182/0x182
> [    1.157174]  ? acpi_get_table+0x11f/0x1f5
> [    1.157186]  ? write_comp_data+0x2a/0x80
> [    1.157199]  acpi_scan_init+0x2a8/0x702
> [    1.157212]  ? acpi_match_madt+0xc4/0xc4
> [    1.157225]  ? __sanitizer_cov_trace_pc+0x1d/0x50
> [    1.157239]  ? __pci_mmcfg_init+0x91/0x21f
> [    1.157251]  ? __sanitizer_cov_trace_pc+0x1d/0x50
> [    1.157265]  acpi_init+0x230/0x2ba
> [    1.157277]  ? acpi_bus_init+0x7ee/0x7ee
> [    1.157290]  ? rcu_read_lock_bh_held+0xc0/0xc0
> [    1.157304]  ? write_comp_data+0x2a/0x80
> [    1.157332]  do_one_initcall+0xf0/0x540
> [    1.157357]  ? perf_trace_initcall_level+0x3e0/0x3e0
> [    1.157370]  ? rcu_read_lock_sched_held+0xa1/0xe0
> [    1.157384]  ? rcu_read_lock_bh_held+0xc0/0xc0
> [    1.157398]  ? __kmalloc+0x1ae/0x380
> [    1.157410]  ? write_comp_data+0x2a/0x80
> [    1.157424]  kernel_init_freeable+0x38e/0x412
> [    1.157437]  ? rest_init+0x381/0x381
> [    1.157462]  kernel_init+0x12/0x1cf
> [    1.157474]  ret_from_fork+0x1f/0x30
>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: peterz@infradead.org
> Cc: akpm@linux-foundation.org
> Signed-off-by: Andi Kleen <ak@linux.intel.com>
> ---
>  lib/stackdepot.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/lib/stackdepot.c b/lib/stackdepot.c
> index 49f67a0c6e5d..df9179f4f441 100644
> --- a/lib/stackdepot.c
> +++ b/lib/stackdepot.c
> @@ -71,7 +71,7 @@ static void *stack_slabs[STACK_ALLOC_MAX_SLABS];
>  static int depot_index;
>  static int next_slab_inited;
>  static size_t depot_offset;
> -static DEFINE_SPINLOCK(depot_lock);
> +static DEFINE_RAW_SPINLOCK(depot_lock);
>
>  static bool init_stack_slab(void **prealloc)
>  {
> @@ -305,7 +305,7 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>                         prealloc = page_address(page);
>         }
>
> -       spin_lock_irqsave(&depot_lock, flags);
> +       raw_spin_lock_irqsave(&depot_lock, flags);
>
>         found = find_stack(*bucket, entries, nr_entries, hash);
>         if (!found) {
> @@ -329,7 +329,7 @@ depot_stack_handle_t stack_depot_save(unsigned long *entries,
>                 WARN_ON(!init_stack_slab(&prealloc));
>         }
>
> -       spin_unlock_irqrestore(&depot_lock, flags);
> +       raw_spin_unlock_irqrestore(&depot_lock, flags);
>  exit:
>         if (prealloc) {
>                 /* Nobody used this memory, ok to free it. */
> --
> 2.25.4
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Ba5g5JeLJFPJEUxPFbMLXGkYEAJkK3MBctnn7UA-iTkXA%40mail.gmail.com.
