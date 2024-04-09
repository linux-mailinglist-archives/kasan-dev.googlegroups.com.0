Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4VK22YAMGQERPWXSYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 469FC89E331
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Apr 2024 21:22:28 +0200 (CEST)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5aa26b7b674sf2861332eaf.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Apr 2024 12:22:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712690547; cv=pass;
        d=google.com; s=arc-20160816;
        b=tPS/VhQkA4SDJZqqSh6fK7oIzSe3QPOghLNSTZUrpc9xHp+y0l5Tz00cr5Y7PssIW9
         MMnDrTphKj5qI6MwFu2v1KEQUlNlEhPfOV586aq1LOnh/wbHoAba1Nk4gq+0kV4egSda
         BZau8vLloBdLHQLqwYHGpr4TVk7j7ET9xCfcoyC8KV9boWR6/gWTzalpSrt3f+6C5uT4
         6PtGl66C1j7rBsWItb+qteu8FaJIZ8vTHPByx6l5ylTFk6tws1I/v2bfhRhvrBab4Uu8
         NFs+COLu1WkJo72uC2pYdyGou9vbIqYw+u3lhvhBMhbclKHPn+YOBLsOns2WmMYFhX7G
         dbow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=VG+73IWppNMJWuWogavox32Pxqm8brwPEQaQFhrvGS0=;
        fh=8RpK7HIWqiK7SxN7nXKVbc82fYiNK9Rn7120XR3+DYs=;
        b=VESsLQjgA5gwMxfpYXgeAIm897bbMsqRfdp63nEY4YGPjtjyKn346g5ALx625BlDXc
         mKvR8l+JEUdhuvxN0XaJoyGImHST0XLKr3zSI1+jt6ffSRsKb4XP5v+68kSPm5Rrr0g1
         V/FZw5XW/k4P31s3brh0FncPa3IlJJ68UqdUB/uIWerolB4rOWTOtiJs1FFVBhVPXe/o
         C/d6EPG4nsFPPT0SReYuNbBmqCOiOU3ardONo5saqPIeK0fOR+5X+UkBGzj7Q2HAjVkg
         at+UcVuzgX+MxHvlZ2zW90PKSxbpqhn5vTyWODoCBileDLrV2D8zZtjudiPZPL6xweFC
         ANoA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LBsEXxzh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712690547; x=1713295347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=VG+73IWppNMJWuWogavox32Pxqm8brwPEQaQFhrvGS0=;
        b=dsYFhe0F08rCN279Cu/6bUZ0wxEalLUHvIkzHV4qwln3yOOIeikY7q/Sgygqygx6nq
         twlMqWHCxUzkH1+sLhM74i+Huz1ZwC6ukMf46QUnN+KM7KXId/8xKFgDCK+HmChw554e
         eRkFCIiMSyYrHOSbV1tCl+DtF5OSMiahnBJIQUTIVTUbg1XDaMwd+shqiXKOQSr7oGnB
         UcG0bYVMl9I403S1CVobMI5q41eiT4cCESfb7MlzPTPSKM9xa3mFUriwZiKIRnUqVwD3
         9GhV33wj/xyQl75Kvs4scUCVz2wGA9LYpSICpoLqQoalmbyJmXRnF82Z/aGedRpirWTo
         2zrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712690547; x=1713295347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=VG+73IWppNMJWuWogavox32Pxqm8brwPEQaQFhrvGS0=;
        b=r3V86nITA9OrjXBOD/LEoIGd6chE05ByKABjaNs5Epccy56qxbDiVVbt27Vx6TsAdC
         j6eD7gTp6rBrItuuiZMLdkHaZexZgTnT/xlPF/bI8a2rZo2vp5sBIyjAU2ZOzu8YirX+
         KC7vTeVhRgF6QU/dsekyzI3fbonh95LdQgDxLPziJHwwgJjUef9xbvLdE2rJYrAMZUnn
         SQXJhjutkLoZi4mCWwHw71lZQrFNn6HOxV7BesPjWGMsVB46qCMyPZ/JIgv5L9uI+4Cl
         +haMUq2NnKZ5ovUmjSW+mLujCqDrUzEKKC35V+8T68RTp57Ati5mJrNuW0DAoY2rVWHu
         T7yQ==
X-Forwarded-Encrypted: i=2; AJvYcCVuo6XK98DfzdWDrA50VSLD5QW7neYQ5x9xuwwdKoWtyxY1jODN85uBiTZFy+UmC4Kx2L/nFrs8umiz3GStwVCnSiUDL6S2cQ==
X-Gm-Message-State: AOJu0YyMmA4OfiHbJxHT2EIKXaTpQtTZ7VX64gQvhftDrUglqT6ulAjB
	MNkekX+kUqY7N8DogQwa/YGrCTyb8k2XHAXlCr9HIVDToPy+O3Hs
X-Google-Smtp-Source: AGHT+IGuO2J0Zseku0ga6quh9mEmUyTUVknSVrmEXW1t21TWz516Lr+mexWIgPegJzcYCqI4n4heKg==
X-Received: by 2002:a05:6820:200f:b0:5a7:afa0:4a0f with SMTP id by15-20020a056820200f00b005a7afa04a0fmr1127517oob.8.1712690547001;
        Tue, 09 Apr 2024 12:22:27 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5b84:0:b0:5a4:6ef1:24f0 with SMTP id g126-20020a4a5b84000000b005a46ef124f0ls5134621oob.0.-pod-prod-03-us;
 Tue, 09 Apr 2024 12:22:25 -0700 (PDT)
X-Received: by 2002:a05:6830:410a:b0:6ea:122f:3e77 with SMTP id w10-20020a056830410a00b006ea122f3e77mr985819ott.31.1712690545451;
        Tue, 09 Apr 2024 12:22:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712690545; cv=none;
        d=google.com; s=arc-20160816;
        b=J5OXVYGZRHSyw+bgvHccOrI+JhRtmr0H4MU1+SluK1u8aaHOoEHKou7d8EAnvZgtdG
         KVC9bGUu3paK19uSSPVqMoc671pr757wBnVRNVPtWo6YY+BJqQNobDwZKGHmejUkj+x8
         9Wy8/U/EUfYe3I5kkRqUwB/t+HBPZWh6uuT6/fGu7UwtKSwylOvU3hbuIPTXZ85ssbNK
         sluEiZw22594j1mZVWQDZKQeRt0/a8dWk4yp2KYUf8A+A3WTYQ3jFSCu10jvpILoDGS9
         rNgmfEhyCcL9SBYYzGNxohfA820TrEX/8rIekV+X2mIqe3T56WSh6vqg8mnm9G30TLEN
         iCiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=z6tJNUDO0MMVmBUJFDnCuInyM8ZpQ/ZJFxGiIT+wCvI=;
        fh=i2AX6nm5Aoc20z+HvMKdcT+ADnvezhC4ZqbvMykcghw=;
        b=RHfdSCBOs+8bzxQoKVJFOXVSfKTb+ZSALYgn9R7ZIrvnXaQC9Z/1LtfMUkp7mYA/Be
         Y+ewHR6LsuNsscRdsk/hUsCB6vQiDflrvU03rNNfUjK5C6+95yv5CfUK6a0tofFx8pV/
         X6V0y71TwbBcow7FPQOjO331iCeeAVwhTYUyulOykRHhjFXZOZed/j5/J6wTCepG0vuq
         snzI1Ckh6EYRwU33nRG1zhyewJPOeA4og797/V0UK+7y0SKIEo1cqpbnCBLRbCoAEoaV
         kRdzN6EDrwaQfP5pDNXybm4avabMEjM29VvinkfH+6CzDpCEYCxlW02Rc5vrSKg9nEBz
         zQqQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=LBsEXxzh;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vk1-xa2b.google.com (mail-vk1-xa2b.google.com. [2607:f8b0:4864:20::a2b])
        by gmr-mx.google.com with ESMTPS id bf13-20020a056830354d00b006ea0b56baf7si474828otb.2.2024.04.09.12.22.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Apr 2024 12:22:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as permitted sender) client-ip=2607:f8b0:4864:20::a2b;
Received: by mail-vk1-xa2b.google.com with SMTP id 71dfb90a1353d-4daa513e430so1781257e0c.2
        for <kasan-dev@googlegroups.com>; Tue, 09 Apr 2024 12:22:25 -0700 (PDT)
X-Received: by 2002:a05:6122:1685:b0:4da:aff6:5eee with SMTP id
 5-20020a056122168500b004daaff65eeemr715039vkl.15.1712690544607; Tue, 09 Apr
 2024 12:22:24 -0700 (PDT)
MIME-Version: 1.0
References: <bd455761-3dbf-4f44-a0e3-dff664284fcc@molgen.mpg.de>
 <CANpmjNMAfLDZtHaZBZk_tZ-oM5FgYTSOgfbJLTFN7JE-mq0u_A@mail.gmail.com>
 <05ba71e6-6b4e-4496-9183-c75bfc8b64cd@molgen.mpg.de> <782006d6-c3f1-4f61-aa40-e9b3903bdbf4@molgen.mpg.de>
In-Reply-To: <782006d6-c3f1-4f61-aa40-e9b3903bdbf4@molgen.mpg.de>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 9 Apr 2024 21:21:46 +0200
Message-ID: <CANpmjNOsZydmYVU-waN1BdA=2RH0fhjmZcjnaf4JiObA++1p2w@mail.gmail.com>
Subject: Re: BUG: unable to handle page fault for address: 0000000000030368
To: Paul Menzel <pmenzel@molgen.mpg.de>
Cc: kasan-dev@googlegroups.com, Thomas Gleixner <tglx@linutronix.de>, 
	Borislav Petkov <bp@alien8.de>, Peter Zijlstra <peterz@infradead.org>, 
	Josh Poimboeuf <jpoimboe@kernel.org>, Ingo Molnar <mingo@redhat.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, x86@kernel.org, 
	LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=LBsEXxzh;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::a2b as
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

On Thu, 28 Mar 2024 at 17:17, Paul Menzel <pmenzel@molgen.mpg.de> wrote:
>
> Dear Marco, dear Linux folks,
>
>
> Am 26.03.24 um 13:44 schrieb Paul Menzel:
> > [Cc: +X86 maintainers]
>
> > Thank you for your quick reply. (Note, that your mailer wrapped the
> > pasted lines.)
> >
> > Am 26.03.24 um 11:07 schrieb Marco Elver:
> >> On Tue, 26 Mar 2024 at 10:23, Paul Menzel wrote:
> >
> >>> Trying KCSAN the first time =E2=80=93 configuration attached =E2=80=
=93, it fails to boot
> >>> on the Dell XPS 13 9360 and QEMU q35. I couldn=E2=80=99t get logs on =
the Dell
> >>> XPS 13 9360, so here are the QEMU ones:
> >>
> >> If there's a bad access somewhere which is instrumented by KCSAN, it
> >> will unfortunately still crash inside KCSAN.
> >>
> >> What happens if you compile with CONFIG_KCSAN_EARLY_ENABLE=3Dn? It
> >> disables KCSAN (but otherwise the kernel image is the same) and
> >> requires turning it on manually with "echo on >
> >> /sys/kernel/debug/kcsan" after boot.
> >>
> >> If it still crashes, then there's definitely a bug elsewhere. If it
> >> doesn't crash, and only crashes with KCSAN enabled, my guess is that
> >> KCSAN's delays of individual threads are perturbing execution to
> >> trigger previously undetected bugs.
> >
> > Such a Linux kernel booted with a warning on the Dell XPS 13 9360 (but
> > booted with *no* warning on QEMU q35) [1], but enabling KCSAN on the
> > laptop hangs the laptop right away. I couldn=E2=80=99t get any logs of =
the laptop.
>
> In the QEMU q35 virtual machine `echo on | sudo tee
> /sys/kernel/debug/kcsan` also locks up the system. Please find the logs
> attached.
>
>      [   78.241245] BUG: unable to handle page fault for address:
> 0000000000019a18
>      [   78.242815] #PF: supervisor read access in kernel mode
>      [   78.244001] #PF: error_code(0x0000) - not-present page
>      [   78.245186] PGD 0 P4D 0
>      [   78.245828] Oops: 0000 [#1] PREEMPT SMP NOPTI
>      [   78.246878] CPU: 4 PID: 783 Comm: sudo Not tainted 6.9.0-rc1+ #83
>      [   78.248289] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009),
> BIOS rel-1.16.1-0-g3208b098f51a-prebuilt.qemu.org 04/01/2014
>      [   78.250763] RIP: 0010:kcsan_setup_watchpoint+0x2b3/0x400
>      [   78.252108] Code: ea 00 f0 48 ff 05 25 b4 8f 02 eb e0 65 48 8b
> 05 7b 53 23 4f 48 8d 98 c0 02 03 00 e9 9f fd ff ff 48 83 fd 08 0f 85 fd
> 00 00 00 <4d> 8b 04 24 e9 bf fe ff ff 49 85 d1 75 54 ba 01 00 00 00 4a 84
>      [   78.256284] RSP: 0018:ffffbae1c0f5bc48 EFLAGS: 00010046
>      [   78.257548] RAX: 0000000000000000 RBX: ffff9b95c4ba93b0 RCX:
> 0000000000000019
>      [   78.259158] RDX: 0000000000000001 RSI: ffffffffb0f82d36 RDI:
> 0000000000000000
>      [   78.260781] RBP: 0000000000000008 R08: 00000000aaaaaaab R09:
> 0000000000000000
>      [   78.262417] R10: 0000000000000086 R11: 0010000000019a18 R12:
> 0000000000019a18
>      [   78.264040] R13: 000000000000001a R14: 0000000000000000 R15:
> 0000000000000000
>      [   78.265658] FS:  00007f65e3a91f00(0000)
> GS:ffff9b9d1f000000(0000) knlGS:0000000000000000
>      [   78.267480] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>      [   78.268804] CR2: 0000000000019a18 CR3: 0000000102e26000 CR4:
> 00000000003506f0
>      [   78.270424] Call Trace:
>      [   78.271036]  <TASK>
>      [   78.271572]  ? __die+0x23/0x70
>      [   78.272344]  ? page_fault_oops+0x173/0x4f0
>      [   78.273400]  ? exc_page_fault+0x81/0x190
>      [   78.274373]  ? asm_exc_page_fault+0x26/0x30
>      [   78.275395]  ? refill_obj_stock+0x36/0x2e0
>      [   78.276410]  ? kcsan_setup_watchpoint+0x2b3/0x400
>      [   78.277556]  refill_obj_stock+0x36/0x2e0
>      [   78.278540]  obj_cgroup_uncharge+0x13/0x20
>      [   78.279596]  __memcg_slab_free_hook+0xac/0x140
>      [   78.280661]  ? free_pipe_info+0x135/0x150
>      [   78.281631]  kfree+0x2de/0x310
>      [   78.282419]  free_pipe_info+0x135/0x150
>      [   78.283395]  pipe_release+0x188/0x1a0
>      [   78.284303]  __fput+0x127/0x4e0
>      [   78.285114]  __fput_sync+0x35/0x40
>      [   78.285958]  __x64_sys_close+0x54/0xa0
>      [   78.286914]  do_syscall_64+0x88/0x1a0
>      [   78.287810]  ? fpregs_assert_state_consistent+0x7e/0x90
>      [   78.289185]  ? srso_return_thunk+0x5/0x5f
>      [   78.290203]  ? arch_exit_to_user_mode_prepare.isra.0+0x69/0xa0
>      [   78.291568]  ? srso_return_thunk+0x5/0x5f
>      [   78.292518]  ? syscall_exit_to_user_mode+0x40/0xe0
>      [   78.293651]  ? srso_return_thunk+0x5/0x5f
>      [   78.294606]  ? do_syscall_64+0x94/0x1a0
>      [   78.295516]  ? arch_exit_to_user_mode_prepare.isra.0+0x69/0xa0
>      [   78.296876]  ? srso_return_thunk+0x5/0x5f
>
> Can you reproduce this?

This seems to be a compiler issue with a new feature introduced in
6.9-rc1, and it's fixed in 6.9-rc2. It was fixed by: b6540de9b5c8
x86/percpu: Disable named address spaces for KCSAN

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNOsZydmYVU-waN1BdA%3D2RH0fhjmZcjnaf4JiObA%2B%2B1p2w%40mail.=
gmail.com.
