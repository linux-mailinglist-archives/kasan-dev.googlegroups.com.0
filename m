Return-Path: <kasan-dev+bncBCCMH5WKTMGRBE5ZWTUAKGQE6DWDJOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 9AD664EE6F
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 20:06:13 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id y75sf4846884pfg.1
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 11:06:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561140372; cv=pass;
        d=google.com; s=arc-20160816;
        b=RT+3c9nMkUK+XOXnirs1262HAoywSs6gOW5qpYtLqwJds28tcl/DLU8Cmn+V6r7EE4
         kZyhGxClVNEKgSUOIFc1xOkPuwvqMkSV28A+8BI9wVjc/a0LzRxPfnXDcGWJMsmuJhoh
         WlpRsJZCHkm3YPpq3XT+u2EXX2MGcHpfZxpp+DHu+d2PRt4t0Siinaw2pbaVVrMeDzX+
         AmIbM2OWIKC0yPl1ReFoZ3dQA7FfpIA9lbizR9G7CWzx3m38LdVKUnS8GV72ThAFqNzI
         WkOn1iLH9PfUnFZvuEMJ0ftVUjA5PI2fyzudyO64VddoG+1k5Lis8+oVCiG8MbJa3D05
         LqOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Zis2s2ko2ZTyHcHH67pRxP+8f+eDyCmPqTlw2a/kqlM=;
        b=K4RxEz1PQJc6NC5Le21WAk66WOUHrTDwlobAdYFfbuo5H0FMFvbGKZJrfbZpQkmU9T
         lGFwhgiitrMUHsq5dU0Lg+0Tp149a/pSyEK9fffP8o9rVOSFJnrh7M5bnoOdipIFVXUT
         A0pQcwxWDbxGXW3vdX02s/Bf1m9NhrhWiKuICl7NBJ0IHpb5qsNBmfzCFSL1D6yWlLvH
         hqckQopQDWmvPOrCaTZVvfUAcVM4TR2Iu1UmhFNyNN6Yi5fXxMCIMk/zMf+Aamgax2aL
         gGzMju1niOypUurqyG3txHwCaGVeOD+UpoarIt2oDonG2o7S0W/iZo62XFnmddLu5j4e
         Hmiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WeCYFqWD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e41 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zis2s2ko2ZTyHcHH67pRxP+8f+eDyCmPqTlw2a/kqlM=;
        b=cLBs5ycr6gJa0kKx4+zzGGbCq1BC1NgKOWqHlXAZqGC501x1UO832e4qdyqIagO2Jj
         InKS+UTEhn3KTwvr8JJaM39wmTmrnlQ6HvHTLQ0kBGIAMk9FmNbLi3qCgUrnchEhypn5
         sYQxzNEN2wyGYccAhTHZJs7JtsyeF4VMSijRLl4P0kuwPNasZbktF1ZNXNm5uPYHCQmB
         7WYHPiIYIYQyupPe2cOIcJN4jQtMrqSbHsszPYOcl3G+Qd8fzm6bPd957dz1FH2ZBgSl
         h+0P37pYCZejX/LQhGCLVJaOnqZswW3VaydYbNoUNwT4AmQVffUzX3NZI3cpU76i145g
         wQcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Zis2s2ko2ZTyHcHH67pRxP+8f+eDyCmPqTlw2a/kqlM=;
        b=M7crX4gqaoAsCykknncmuAyWA1KTa9vwkHNH5XlpBRKeVlEJojm6lOuRE8u5DOos/5
         JnSXsWHmWFsH9FOfPIfcHZTDbPECKopViV2dG81xWDDqFABniv8SD3tjj3C3+SILNQ5a
         ZAHHx0LJVmPLc2SAnzw00Slrs9v83wcTjgd/upWPWcrRMy6NfFRtPpUCSMzw1MQ6NkU2
         dRLC2D+lo2a2zpqx7ro7dk2DUQpjmPizhMaFa/ri8LEBwj7DBvScvJT/14kD5chRIKmj
         5padJ6tJ8LAGc1zQEXoAQks34vNgbJFZiru/jXDhjPG8YbBXE1XwFl1iEaGGb0KyXd5F
         pGgw==
X-Gm-Message-State: APjAAAV1lGuEq1zNVIFJ2j5eyLTPaW7yP1OHt8cD060x1SWiMXC34OWE
	Svay2QbruC9pS4NrUQ+gepA=
X-Google-Smtp-Source: APXvYqz+zkrTtk5jKsfsn8mJ8jABtR1NeIUuogjuUB3dq24IK+0pcmMu2W8j/hVyhGNjVXp9dNjR/g==
X-Received: by 2002:a17:902:6903:: with SMTP id j3mr56700459plk.247.1561140371827;
        Fri, 21 Jun 2019 11:06:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:de4d:: with SMTP id y13ls1901853pgi.12.gmail; Fri, 21
 Jun 2019 11:06:11 -0700 (PDT)
X-Received: by 2002:a63:490d:: with SMTP id w13mr19923684pga.355.1561140371363;
        Fri, 21 Jun 2019 11:06:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561140371; cv=none;
        d=google.com; s=arc-20160816;
        b=MNiF4AsgHvoxzIaYqF8IlU3BUwuhVgXFr2eso+BF/8tOJLLjpIZrP1f8jlTUyZfvpd
         1b0qsvBNgXY98KBW/uF4VEkhLRnT65KNBDaCo9lPgWw8vsYWYUHSqPB5+/Vi+Wup94+z
         8DDpbkvZtGrjSa2tdxjvVZPhtCRAcN3/iFyxlSO7vlJgTknp3wAGarr9TuONC8MAPx29
         VtdaHl7+SA7eDYfdthYbCxmAuAE9QP2VR6lXPLmZPNylwSqL4QL4wc7HF3jMB6gO6Yje
         5u6pxVxIIfMY0YY6ZQAZ37tokHDcO8lPylSo3Sgn/KtMXaiQOdcDZPpXxZ5mMjT4caI9
         k0Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1M3GxCI0tM/I+qEQB1Oa0kKyMXQBYWQu/Dg2M4jg5/o=;
        b=X405MJkYDBxjjoogzlEnMMTQ9qNhFdvFoApuUbWryXNmwZgYmTvEVZ1QTLzTmeMvvr
         dCVL+NBZTOppNu3KGy0Cx+iDB6nnpPNVkZibz5S3EUQRvpmJ4mKD/BeQ0HvaRMjXVnYY
         D4nboW8dkN4yKp2R29PAkSG3Ocyz1/0clh7rfj35wMt3Dja/i3UciUWPCK8uFUxYg5Y8
         7vqlNcSQTCyfjPpi312h1GAh0bpkvaYG4jbj5gSDahZcTxfhWSbBx5YufDu0tWG3e4ak
         u+eAZawYBkvaajszNkBGn26JgrSTN/GLKfrOCt/2c/X51YC64pUNPRvR1mzRwP/jzndc
         vvvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WeCYFqWD;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e41 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe41.google.com (mail-vs1-xe41.google.com. [2607:f8b0:4864:20::e41])
        by gmr-mx.google.com with ESMTPS id s60si94803pjc.2.2019.06.21.11.06.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2019 11:06:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e41 as permitted sender) client-ip=2607:f8b0:4864:20::e41;
Received: by mail-vs1-xe41.google.com with SMTP id u3so4400682vsh.6
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2019 11:06:11 -0700 (PDT)
X-Received: by 2002:a67:11c1:: with SMTP id 184mr46866880vsr.217.1561140370275;
 Fri, 21 Jun 2019 11:06:10 -0700 (PDT)
MIME-Version: 1.0
References: <CADvbK_fCWry5LRV-6yzkgLQXFj0_Qxi46gRrrO-ikOh8SbxQuA@mail.gmail.com>
In-Reply-To: <CADvbK_fCWry5LRV-6yzkgLQXFj0_Qxi46gRrrO-ikOh8SbxQuA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 21 Jun 2019 20:05:58 +0200
Message-ID: <CAG_fn=UoK7qE-x7NHN17GXGNctKoEKZe9rZ7QqP1otnSCfcJDw@mail.gmail.com>
Subject: Re: how to start kmsan kernel with qemu
To: lucien xin <lucien.xin@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>, Dmitriy Vyukov <dvyukov@google.com>
Content-Type: multipart/alternative; boundary="000000000000379536058bd9515b"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WeCYFqWD;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e41 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

--000000000000379536058bd9515b
Content-Type: text/plain; charset="UTF-8"

Hi Xin,

Could you please share the config you're using to build the kernel?
I'll take a closer look on Monday when I am back to the office.

On Fri, 21 Jun 2019, 18:15 Xin Long, <lucien.xin@gmail.com> wrote:

> this is my command:
>
> /usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kvm -cpu host \
>     -net nic -net user,hostfwd=tcp::10022-:22 \
>     -kernel /home/kmsan/arch/x86/boot/bzImage -nographic \
>     -device virtio-scsi-pci,id=scsi \
>     -device scsi-hd,bus=scsi.0,drive=d0 \
>     -drive file=/root/test/wheezy.img,format=raw,if=none,id=d0 \
>     -append "root=/dev/sda console=ttyS0 earlyprintk=serial rodata=n \
>       oops=panic panic_on_warn=1 panic=86400 kvm-intel.nested=1 \
>       security=apparmor ima_policy=tcb workqueue.watchdog_thresh=140 \
>       nf-conntrack-ftp.ports=20000 nf-conntrack-tftp.ports=20000 \
>       nf-conntrack-sip.ports=20000 nf-conntrack-irc.ports=20000 \
>       nf-conntrack-sane.ports=20000 vivid.n_devs=16 \
>       vivid.multiplanar=1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \
>       spec_store_bypass_disable=prctl nopcid"
>
> the commit is on:
> commit f75e4cfea97f67b7530b8b991b3005f991f04778 (HEAD)
> Author: Alexander Potapenko <glider@google.com>
> Date:   Wed May 22 12:30:13 2019 +0200
>
>     kmsan: use kmsan_handle_urb() in urb.c
>
> and when starting, it shows:
> [    0.561925][    T0] Kernel command line: root=/dev/sda
> console=ttyS0 earlyprintk=serial rodata=n       oops=panic
> panic_on_warn=1 panic=86400 kvm-intel.nested=1       security=ad
> [    0.707792][    T0] Memory: 3087328K/4193776K available (219164K
> kernel code, 7059K rwdata, 11712K rodata, 5064K init, 11904K bss,
> 1106448K reserved, 0K cma-reserved)
> [    0.710935][    T0] SLUB: HWalign=64, Order=0-3, MinObjects=0,
> CPUs=2, Nodes=1
> [    0.711953][    T0] Starting KernelMemorySanitizer
> [    0.712563][    T0]
> ==================================================================
> [    0.713657][    T0] BUG: KMSAN: uninit-value in mutex_lock+0xd1/0xe0
> [    0.714570][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 5.1.0 #5
> [    0.715417][    T0] Hardware name: Red Hat KVM, BIOS
> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> [    0.716659][    T0] Call Trace:
> [    0.717127][    T0]  dump_stack+0x134/0x190
> [    0.717727][    T0]  kmsan_report+0x131/0x2a0
> [    0.718347][    T0]  __msan_warning+0x7a/0xf0
> [    0.718952][    T0]  mutex_lock+0xd1/0xe0
> [    0.719478][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
> [    0.720260][    T0]  ? vprintk_func+0x6b5/0x8a0
> [    0.720926][    T0]  ? rb_get_reader_page+0x1140/0x1140
> [    0.721632][    T0]  __cpuhp_setup_state+0x181/0x2e0
> [    0.722374][    T0]  ? rb_get_reader_page+0x1140/0x1140
> [    0.723115][    T0]  tracer_alloc_buffers+0x16b/0xb96
> [    0.723846][    T0]  early_trace_init+0x193/0x28f
> [    0.724501][    T0]  start_kernel+0x497/0xb38
> [    0.725134][    T0]  x86_64_start_reservations+0x19/0x2f
> [    0.725871][    T0]  x86_64_start_kernel+0x84/0x87
> [    0.726538][    T0]  secondary_startup_64+0xa4/0xb0
> [    0.727173][    T0]
> [    0.727454][    T0] Local variable description:
> ----success.i.i.i.i@mutex_lock
> [    0.728379][    T0] Variable was created at:
> [    0.728977][    T0]  mutex_lock+0x48/0xe0
> [    0.729536][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
> [    0.730323][    T0]
> ==================================================================
> [    0.731364][    T0] Disabling lock debugging due to kernel taint
> [    0.732169][    T0] Kernel panic - not syncing: panic_on_warn set ...
> [    0.733047][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G    B
>         5.1.0 #5
> [    0.734080][    T0] Hardware name: Red Hat KVM, BIOS
> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> [    0.735319][    T0] Call Trace:
> [    0.735735][    T0]  dump_stack+0x134/0x190
> [    0.736308][    T0]  panic+0x3ec/0xb3b
> [    0.736826][    T0]  kmsan_report+0x29a/0x2a0
> [    0.737417][    T0]  __msan_warning+0x7a/0xf0
> [    0.737973][    T0]  mutex_lock+0xd1/0xe0
> [    0.738527][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
> [    0.739342][    T0]  ? vprintk_func+0x6b5/0x8a0
> [    0.739972][    T0]  ? rb_get_reader_page+0x1140/0x1140
> [    0.740695][    T0]  __cpuhp_setup_state+0x181/0x2e0
> [    0.741412][    T0]  ? rb_get_reader_page+0x1140/0x1140
> [    0.742160][    T0]  tracer_alloc_buffers+0x16b/0xb96
> [    0.742866][    T0]  early_trace_init+0x193/0x28f
> [    0.743512][    T0]  start_kernel+0x497/0xb38
> [    0.744128][    T0]  x86_64_start_reservations+0x19/0x2f
> [    0.744863][    T0]  x86_64_start_kernel+0x84/0x87
> [    0.745534][    T0]  secondary_startup_64+0xa4/0xb0
> [    0.746290][    T0] Rebooting in 86400 seconds..
>
> when I set "panic_on_warn=0", it foods the console with:
> ...
> [   25.206759][    C0] Variable was created at:
> [   25.207302][    C0]  vprintk_emit+0xf4/0x800
> [   25.207844][    C0]  vprintk_deferred+0x90/0xed
> [   25.208404][    C0]
> ==================================================================
> [   25.209763][    C0]  x86_64_start_reservations+0x19/0x2f
> [   25.209769][    C0]
> ==================================================================
> [   25.211408][    C0] BUG: KMSAN: uninit-value in vprintk_emit+0x443/0x800
> [   25.212237][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G    B
>           5.1.0 #5
> [   25.213206][    C0] Hardware name: Red Hat KVM, BIOS
> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> [   25.214326][    C0] Call Trace:
> [   25.214725][    C0]  <IRQ>
> [   25.215080][    C0]  dump_stack+0x134/0x190
> [   25.215624][    C0]  kmsan_report+0x131/0x2a0
> [   25.216204][    C0]  __msan_warning+0x7a/0xf0
> [   25.216771][    C0]  vprintk_emit+0x443/0x800
> [   25.217334][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0x20
> [   25.218127][    C0]  vprintk_deferred+0x90/0xed
> [   25.218714][    C0]  printk_deferred+0x186/0x1d3
> [   25.219353][    C0]  __printk_safe_flush+0x72e/0xc00
> [   25.220006][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> [   25.220635][    C0]  irq_work_run+0x1ad/0x5c0
> [   25.221210][    C0]  ? flat_init_apic_ldr+0x170/0x170
> [   25.221851][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> [   25.222520][    C0]  irq_work_interrupt+0x2e/0x40
> [   25.223110][    C0]  </IRQ>
> [   25.223475][    C0] RIP: 0010:kmem_cache_init_late+0x0/0xb
> [   25.224164][    C0] Code: d4 e8 5d dd 2e f2 e9 74 fe ff ff 48 89 d3
> 8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 20 48 09 c1 48 89 0b
> e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
> [   25.226526][    C0] RSP: 0000:ffffffff8f40feb8 EFLAGS: 00000246
> ORIG_RAX: ffffffffffffff09
> [   25.227548][    C0] RAX: ffff88813f995785 RBX: 0000000000000000
> RCX: 0000000000000000
> [   25.228511][    C0] RDX: ffff88813f2b0784 RSI: 0000160000000000
> RDI: 0000000000000785
> [   25.229473][    C0] RBP: ffffffff8f40ff20 R08: 000000000fac3785
> R09: 0000778000000001
> [   25.230440][    C0] R10: ffffd0ffffffffff R11: 0000100000000000
> R12: 0000000000000000
> [   25.231403][    C0] R13: 0000000000000000 R14: ffffffff8fb8cfd0
> R15: 0000000000000000
> [   25.232407][    C0]  ? start_kernel+0x5d8/0xb38
> [   25.233003][    C0]  x86_64_start_reservations+0x19/0x2f
> [   25.233670][    C0]  x86_64_start_kernel+0x84/0x87
> [   25.234314][    C0]  secondary_startup_64+0xa4/0xb0
> [   25.234949][    C0]
> [   25.235231][    C0] Local variable description:
> ----flags.i.i.i@vprintk_emit
> [   25.236101][    C0] Variable was created at:
> [   25.236643][    C0]  vprintk_emit+0xf4/0x800
> [   25.237188][    C0]  vprintk_deferred+0x90/0xed
> [   25.237752][    C0]
> ==================================================================
> [   25.239117][    C0]  x86_64_start_kernel+0x84/0x87
> [   25.239123][    C0]
> ==================================================================
> [   25.240704][    C0] BUG: KMSAN: uninit-value in vprintk_emit+0x443/0x800
> [   25.241540][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G    B
>           5.1.0 #5
> [   25.242512][    C0] Hardware name: Red Hat KVM, BIOS
> 1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
> [   25.243635][    C0] Call Trace:
> [   25.244038][    C0]  <IRQ>
> [   25.244390][    C0]  dump_stack+0x134/0x190
> [   25.244940][    C0]  kmsan_report+0x131/0x2a0
> [   25.245515][    C0]  __msan_warning+0x7a/0xf0
> [   25.246082][    C0]  vprintk_emit+0x443/0x800
> [   25.246638][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0x20
> [   25.247430][    C0]  vprintk_deferred+0x90/0xed
> [   25.248018][    C0]  printk_deferred+0x186/0x1d3
> [   25.248650][    C0]  __printk_safe_flush+0x72e/0xc00
> [   25.249320][    C0]  ? printk_safe_flush+0x1e0/0x1e0
> [   25.249949][    C0]  irq_work_run+0x1ad/0x5c0
> [   25.250524][    C0]  ? flat_init_apic_ldr+0x170/0x170
> [   25.251167][    C0]  smp_irq_work_interrupt+0x237/0x3e0
> [   25.251837][    C0]  irq_work_interrupt+0x2e/0x40
> [   25.252424][    C0]  </IRQ>
> ....
>
>
> I couldn't even log in.
>
> how should I use qemu with wheezy.img to start a kmsan kernel?
>
> Thanks.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUoK7qE-x7NHN17GXGNctKoEKZe9rZ7QqP1otnSCfcJDw%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.

--000000000000379536058bd9515b
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"><div>Hi Xin,</div><div dir=3D"auto"><br></div><div dir=3D=
"auto">Could you please share the config you&#39;re using to build the kern=
el?</div><div dir=3D"auto">I&#39;ll take a closer look on Monday when I am =
back to=C2=A0the office.<br><br><div class=3D"gmail_quote" dir=3D"auto"><di=
v dir=3D"ltr" class=3D"gmail_attr">On Fri, 21 Jun 2019, 18:15 Xin Long, &lt=
;<a href=3D"mailto:lucien.xin@gmail.com">lucien.xin@gmail.com</a>&gt; wrote=
:<br></div><blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;bor=
der-left:1px #ccc solid;padding-left:1ex">this is my command:<br>
<br>
/usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kvm -cpu host \<br>
=C2=A0 =C2=A0 -net nic -net user,hostfwd=3Dtcp::10022-:22 \<br>
=C2=A0 =C2=A0 -kernel /home/kmsan/arch/x86/boot/bzImage -nographic \<br>
=C2=A0 =C2=A0 -device virtio-scsi-pci,id=3Dscsi \<br>
=C2=A0 =C2=A0 -device scsi-hd,bus=3Dscsi.0,drive=3Dd0 \<br>
=C2=A0 =C2=A0 -drive file=3D/root/test/wheezy.img,format=3Draw,if=3Dnone,id=
=3Dd0 \<br>
=C2=A0 =C2=A0 -append &quot;root=3D/dev/sda console=3DttyS0 earlyprintk=3Ds=
erial rodata=3Dn \<br>
=C2=A0 =C2=A0 =C2=A0 oops=3Dpanic panic_on_warn=3D1 panic=3D86400 kvm-intel=
.nested=3D1 \<br>
=C2=A0 =C2=A0 =C2=A0 security=3Dapparmor ima_policy=3Dtcb workqueue.watchdo=
g_thresh=3D140 \<br>
=C2=A0 =C2=A0 =C2=A0 nf-conntrack-ftp.ports=3D20000 nf-conntrack-tftp.ports=
=3D20000 \<br>
=C2=A0 =C2=A0 =C2=A0 nf-conntrack-sip.ports=3D20000 nf-conntrack-irc.ports=
=3D20000 \<br>
=C2=A0 =C2=A0 =C2=A0 nf-conntrack-sane.ports=3D20000 vivid.n_devs=3D16 \<br=
>
=C2=A0 =C2=A0 =C2=A0 vivid.multiplanar=3D1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \<=
br>
=C2=A0 =C2=A0 =C2=A0 spec_store_bypass_disable=3Dprctl nopcid&quot;<br>
<br>
the commit is on:<br>
commit f75e4cfea97f67b7530b8b991b3005f991f04778 (HEAD)<br>
Author: Alexander Potapenko &lt;<a href=3D"mailto:glider@google.com" target=
=3D"_blank" rel=3D"noreferrer">glider@google.com</a>&gt;<br>
Date:=C2=A0 =C2=A0Wed May 22 12:30:13 2019 +0200<br>
<br>
=C2=A0 =C2=A0 kmsan: use kmsan_handle_urb() in urb.c<br>
<br>
and when starting, it shows:<br>
[=C2=A0 =C2=A0 0.561925][=C2=A0 =C2=A0 T0] Kernel command line: root=3D/dev=
/sda<br>
console=3DttyS0 earlyprintk=3Dserial rodata=3Dn=C2=A0 =C2=A0 =C2=A0 =C2=A0o=
ops=3Dpanic<br>
panic_on_warn=3D1 panic=3D86400 kvm-intel.nested=3D1=C2=A0 =C2=A0 =C2=A0 =
=C2=A0security=3Dad<br>
[=C2=A0 =C2=A0 0.707792][=C2=A0 =C2=A0 T0] Memory: 3087328K/4193776K availa=
ble (219164K<br>
kernel code, 7059K rwdata, 11712K rodata, 5064K init, 11904K bss,<br>
1106448K reserved, 0K cma-reserved)<br>
[=C2=A0 =C2=A0 0.710935][=C2=A0 =C2=A0 T0] SLUB: HWalign=3D64, Order=3D0-3,=
 MinObjects=3D0,<br>
CPUs=3D2, Nodes=3D1<br>
[=C2=A0 =C2=A0 0.711953][=C2=A0 =C2=A0 T0] Starting KernelMemorySanitizer<b=
r>
[=C2=A0 =C2=A0 0.712563][=C2=A0 =C2=A0 T0]<br>
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
[=C2=A0 =C2=A0 0.713657][=C2=A0 =C2=A0 T0] BUG: KMSAN: uninit-value in mute=
x_lock+0xd1/0xe0<br>
[=C2=A0 =C2=A0 0.714570][=C2=A0 =C2=A0 T0] CPU: 0 PID: 0 Comm: swapper Not =
tainted 5.1.0 #5<br>
[=C2=A0 =C2=A0 0.715417][=C2=A0 =C2=A0 T0] Hardware name: Red Hat KVM, BIOS=
<br>
1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014<br>
[=C2=A0 =C2=A0 0.716659][=C2=A0 =C2=A0 T0] Call Trace:<br>
[=C2=A0 =C2=A0 0.717127][=C2=A0 =C2=A0 T0]=C2=A0 dump_stack+0x134/0x190<br>
[=C2=A0 =C2=A0 0.717727][=C2=A0 =C2=A0 T0]=C2=A0 kmsan_report+0x131/0x2a0<b=
r>
[=C2=A0 =C2=A0 0.718347][=C2=A0 =C2=A0 T0]=C2=A0 __msan_warning+0x7a/0xf0<b=
r>
[=C2=A0 =C2=A0 0.718952][=C2=A0 =C2=A0 T0]=C2=A0 mutex_lock+0xd1/0xe0<br>
[=C2=A0 =C2=A0 0.719478][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state_cpuslo=
cked+0x149/0xd20<br>
[=C2=A0 =C2=A0 0.720260][=C2=A0 =C2=A0 T0]=C2=A0 ? vprintk_func+0x6b5/0x8a0=
<br>
[=C2=A0 =C2=A0 0.720926][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x114=
0/0x1140<br>
[=C2=A0 =C2=A0 0.721632][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state+0x181/=
0x2e0<br>
[=C2=A0 =C2=A0 0.722374][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x114=
0/0x1140<br>
[=C2=A0 =C2=A0 0.723115][=C2=A0 =C2=A0 T0]=C2=A0 tracer_alloc_buffers+0x16b=
/0xb96<br>
[=C2=A0 =C2=A0 0.723846][=C2=A0 =C2=A0 T0]=C2=A0 early_trace_init+0x193/0x2=
8f<br>
[=C2=A0 =C2=A0 0.724501][=C2=A0 =C2=A0 T0]=C2=A0 start_kernel+0x497/0xb38<b=
r>
[=C2=A0 =C2=A0 0.725134][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_reservations+=
0x19/0x2f<br>
[=C2=A0 =C2=A0 0.725871][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_kernel+0x84/0=
x87<br>
[=C2=A0 =C2=A0 0.726538][=C2=A0 =C2=A0 T0]=C2=A0 secondary_startup_64+0xa4/=
0xb0<br>
[=C2=A0 =C2=A0 0.727173][=C2=A0 =C2=A0 T0]<br>
[=C2=A0 =C2=A0 0.727454][=C2=A0 =C2=A0 T0] Local variable description:<br>
----success.i.i.i.i@mutex_lock<br>
[=C2=A0 =C2=A0 0.728379][=C2=A0 =C2=A0 T0] Variable was created at:<br>
[=C2=A0 =C2=A0 0.728977][=C2=A0 =C2=A0 T0]=C2=A0 mutex_lock+0x48/0xe0<br>
[=C2=A0 =C2=A0 0.729536][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state_cpuslo=
cked+0x149/0xd20<br>
[=C2=A0 =C2=A0 0.730323][=C2=A0 =C2=A0 T0]<br>
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
[=C2=A0 =C2=A0 0.731364][=C2=A0 =C2=A0 T0] Disabling lock debugging due to =
kernel taint<br>
[=C2=A0 =C2=A0 0.732169][=C2=A0 =C2=A0 T0] Kernel panic - not syncing: pani=
c_on_warn set ...<br>
[=C2=A0 =C2=A0 0.733047][=C2=A0 =C2=A0 T0] CPU: 0 PID: 0 Comm: swapper Tain=
ted: G=C2=A0 =C2=A0 B<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 5.1.0 #5<br>
[=C2=A0 =C2=A0 0.734080][=C2=A0 =C2=A0 T0] Hardware name: Red Hat KVM, BIOS=
<br>
1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014<br>
[=C2=A0 =C2=A0 0.735319][=C2=A0 =C2=A0 T0] Call Trace:<br>
[=C2=A0 =C2=A0 0.735735][=C2=A0 =C2=A0 T0]=C2=A0 dump_stack+0x134/0x190<br>
[=C2=A0 =C2=A0 0.736308][=C2=A0 =C2=A0 T0]=C2=A0 panic+0x3ec/0xb3b<br>
[=C2=A0 =C2=A0 0.736826][=C2=A0 =C2=A0 T0]=C2=A0 kmsan_report+0x29a/0x2a0<b=
r>
[=C2=A0 =C2=A0 0.737417][=C2=A0 =C2=A0 T0]=C2=A0 __msan_warning+0x7a/0xf0<b=
r>
[=C2=A0 =C2=A0 0.737973][=C2=A0 =C2=A0 T0]=C2=A0 mutex_lock+0xd1/0xe0<br>
[=C2=A0 =C2=A0 0.738527][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state_cpuslo=
cked+0x149/0xd20<br>
[=C2=A0 =C2=A0 0.739342][=C2=A0 =C2=A0 T0]=C2=A0 ? vprintk_func+0x6b5/0x8a0=
<br>
[=C2=A0 =C2=A0 0.739972][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x114=
0/0x1140<br>
[=C2=A0 =C2=A0 0.740695][=C2=A0 =C2=A0 T0]=C2=A0 __cpuhp_setup_state+0x181/=
0x2e0<br>
[=C2=A0 =C2=A0 0.741412][=C2=A0 =C2=A0 T0]=C2=A0 ? rb_get_reader_page+0x114=
0/0x1140<br>
[=C2=A0 =C2=A0 0.742160][=C2=A0 =C2=A0 T0]=C2=A0 tracer_alloc_buffers+0x16b=
/0xb96<br>
[=C2=A0 =C2=A0 0.742866][=C2=A0 =C2=A0 T0]=C2=A0 early_trace_init+0x193/0x2=
8f<br>
[=C2=A0 =C2=A0 0.743512][=C2=A0 =C2=A0 T0]=C2=A0 start_kernel+0x497/0xb38<b=
r>
[=C2=A0 =C2=A0 0.744128][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_reservations+=
0x19/0x2f<br>
[=C2=A0 =C2=A0 0.744863][=C2=A0 =C2=A0 T0]=C2=A0 x86_64_start_kernel+0x84/0=
x87<br>
[=C2=A0 =C2=A0 0.745534][=C2=A0 =C2=A0 T0]=C2=A0 secondary_startup_64+0xa4/=
0xb0<br>
[=C2=A0 =C2=A0 0.746290][=C2=A0 =C2=A0 T0] Rebooting in 86400 seconds..<br>
<br>
when I set &quot;panic_on_warn=3D0&quot;, it foods the console with:<br>
...<br>
[=C2=A0 =C2=A025.206759][=C2=A0 =C2=A0 C0] Variable was created at:<br>
[=C2=A0 =C2=A025.207302][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0xf4/0x800<br=
>
[=C2=A0 =C2=A025.207844][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed=
<br>
[=C2=A0 =C2=A025.208404][=C2=A0 =C2=A0 C0]<br>
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
[=C2=A0 =C2=A025.209763][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_reservations+=
0x19/0x2f<br>
[=C2=A0 =C2=A025.209769][=C2=A0 =C2=A0 C0]<br>
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
[=C2=A0 =C2=A025.211408][=C2=A0 =C2=A0 C0] BUG: KMSAN: uninit-value in vpri=
ntk_emit+0x443/0x800<br>
[=C2=A0 =C2=A025.212237][=C2=A0 =C2=A0 C0] CPU: 0 PID: 0 Comm: swapper/0 Ta=
inted: G=C2=A0 =C2=A0 B<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 5.1.0 #5<br>
[=C2=A0 =C2=A025.213206][=C2=A0 =C2=A0 C0] Hardware name: Red Hat KVM, BIOS=
<br>
1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014<br>
[=C2=A0 =C2=A025.214326][=C2=A0 =C2=A0 C0] Call Trace:<br>
[=C2=A0 =C2=A025.214725][=C2=A0 =C2=A0 C0]=C2=A0 &lt;IRQ&gt;<br>
[=C2=A0 =C2=A025.215080][=C2=A0 =C2=A0 C0]=C2=A0 dump_stack+0x134/0x190<br>
[=C2=A0 =C2=A025.215624][=C2=A0 =C2=A0 C0]=C2=A0 kmsan_report+0x131/0x2a0<b=
r>
[=C2=A0 =C2=A025.216204][=C2=A0 =C2=A0 C0]=C2=A0 __msan_warning+0x7a/0xf0<b=
r>
[=C2=A0 =C2=A025.216771][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0x443/0x800<b=
r>
[=C2=A0 =C2=A025.217334][=C2=A0 =C2=A0 C0]=C2=A0 ? __msan_metadata_ptr_for_=
store_1+0x13/0x20<br>
[=C2=A0 =C2=A025.218127][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed=
<br>
[=C2=A0 =C2=A025.218714][=C2=A0 =C2=A0 C0]=C2=A0 printk_deferred+0x186/0x1d=
3<br>
[=C2=A0 =C2=A025.219353][=C2=A0 =C2=A0 C0]=C2=A0 __printk_safe_flush+0x72e/=
0xc00<br>
[=C2=A0 =C2=A025.220006][=C2=A0 =C2=A0 C0]=C2=A0 ? printk_safe_flush+0x1e0/=
0x1e0<br>
[=C2=A0 =C2=A025.220635][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_run+0x1ad/0x5c0<b=
r>
[=C2=A0 =C2=A025.221210][=C2=A0 =C2=A0 C0]=C2=A0 ? flat_init_apic_ldr+0x170=
/0x170<br>
[=C2=A0 =C2=A025.221851][=C2=A0 =C2=A0 C0]=C2=A0 smp_irq_work_interrupt+0x2=
37/0x3e0<br>
[=C2=A0 =C2=A025.222520][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_interrupt+0x2e/0x=
40<br>
[=C2=A0 =C2=A025.223110][=C2=A0 =C2=A0 C0]=C2=A0 &lt;/IRQ&gt;<br>
[=C2=A0 =C2=A025.223475][=C2=A0 =C2=A0 C0] RIP: 0010:kmem_cache_init_late+0=
x0/0xb<br>
[=C2=A0 =C2=A025.224164][=C2=A0 =C2=A0 C0] Code: d4 e8 5d dd 2e f2 e9 74 fe=
 ff ff 48 89 d3<br>
8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 20 48 09 c1 48 89 0b<br>
e9 81 fe ff ff &lt;55&gt; 48 89 e5 e8 20 de 2e1<br>
[=C2=A0 =C2=A025.226526][=C2=A0 =C2=A0 C0] RSP: 0000:ffffffff8f40feb8 EFLAG=
S: 00000246<br>
ORIG_RAX: ffffffffffffff09<br>
[=C2=A0 =C2=A025.227548][=C2=A0 =C2=A0 C0] RAX: ffff88813f995785 RBX: 00000=
00000000000<br>
RCX: 0000000000000000<br>
[=C2=A0 =C2=A025.228511][=C2=A0 =C2=A0 C0] RDX: ffff88813f2b0784 RSI: 00001=
60000000000<br>
RDI: 0000000000000785<br>
[=C2=A0 =C2=A025.229473][=C2=A0 =C2=A0 C0] RBP: ffffffff8f40ff20 R08: 00000=
0000fac3785<br>
R09: 0000778000000001<br>
[=C2=A0 =C2=A025.230440][=C2=A0 =C2=A0 C0] R10: ffffd0ffffffffff R11: 00001=
00000000000<br>
R12: 0000000000000000<br>
[=C2=A0 =C2=A025.231403][=C2=A0 =C2=A0 C0] R13: 0000000000000000 R14: fffff=
fff8fb8cfd0<br>
R15: 0000000000000000<br>
[=C2=A0 =C2=A025.232407][=C2=A0 =C2=A0 C0]=C2=A0 ? start_kernel+0x5d8/0xb38=
<br>
[=C2=A0 =C2=A025.233003][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_reservations+=
0x19/0x2f<br>
[=C2=A0 =C2=A025.233670][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_kernel+0x84/0=
x87<br>
[=C2=A0 =C2=A025.234314][=C2=A0 =C2=A0 C0]=C2=A0 secondary_startup_64+0xa4/=
0xb0<br>
[=C2=A0 =C2=A025.234949][=C2=A0 =C2=A0 C0]<br>
[=C2=A0 =C2=A025.235231][=C2=A0 =C2=A0 C0] Local variable description: ----=
flags.i.i.i@vprintk_emit<br>
[=C2=A0 =C2=A025.236101][=C2=A0 =C2=A0 C0] Variable was created at:<br>
[=C2=A0 =C2=A025.236643][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0xf4/0x800<br=
>
[=C2=A0 =C2=A025.237188][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed=
<br>
[=C2=A0 =C2=A025.237752][=C2=A0 =C2=A0 C0]<br>
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
[=C2=A0 =C2=A025.239117][=C2=A0 =C2=A0 C0]=C2=A0 x86_64_start_kernel+0x84/0=
x87<br>
[=C2=A0 =C2=A025.239123][=C2=A0 =C2=A0 C0]<br>
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
[=C2=A0 =C2=A025.240704][=C2=A0 =C2=A0 C0] BUG: KMSAN: uninit-value in vpri=
ntk_emit+0x443/0x800<br>
[=C2=A0 =C2=A025.241540][=C2=A0 =C2=A0 C0] CPU: 0 PID: 0 Comm: swapper/0 Ta=
inted: G=C2=A0 =C2=A0 B<br>
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 5.1.0 #5<br>
[=C2=A0 =C2=A025.242512][=C2=A0 =C2=A0 C0] Hardware name: Red Hat KVM, BIOS=
<br>
1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014<br>
[=C2=A0 =C2=A025.243635][=C2=A0 =C2=A0 C0] Call Trace:<br>
[=C2=A0 =C2=A025.244038][=C2=A0 =C2=A0 C0]=C2=A0 &lt;IRQ&gt;<br>
[=C2=A0 =C2=A025.244390][=C2=A0 =C2=A0 C0]=C2=A0 dump_stack+0x134/0x190<br>
[=C2=A0 =C2=A025.244940][=C2=A0 =C2=A0 C0]=C2=A0 kmsan_report+0x131/0x2a0<b=
r>
[=C2=A0 =C2=A025.245515][=C2=A0 =C2=A0 C0]=C2=A0 __msan_warning+0x7a/0xf0<b=
r>
[=C2=A0 =C2=A025.246082][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_emit+0x443/0x800<b=
r>
[=C2=A0 =C2=A025.246638][=C2=A0 =C2=A0 C0]=C2=A0 ? __msan_metadata_ptr_for_=
store_1+0x13/0x20<br>
[=C2=A0 =C2=A025.247430][=C2=A0 =C2=A0 C0]=C2=A0 vprintk_deferred+0x90/0xed=
<br>
[=C2=A0 =C2=A025.248018][=C2=A0 =C2=A0 C0]=C2=A0 printk_deferred+0x186/0x1d=
3<br>
[=C2=A0 =C2=A025.248650][=C2=A0 =C2=A0 C0]=C2=A0 __printk_safe_flush+0x72e/=
0xc00<br>
[=C2=A0 =C2=A025.249320][=C2=A0 =C2=A0 C0]=C2=A0 ? printk_safe_flush+0x1e0/=
0x1e0<br>
[=C2=A0 =C2=A025.249949][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_run+0x1ad/0x5c0<b=
r>
[=C2=A0 =C2=A025.250524][=C2=A0 =C2=A0 C0]=C2=A0 ? flat_init_apic_ldr+0x170=
/0x170<br>
[=C2=A0 =C2=A025.251167][=C2=A0 =C2=A0 C0]=C2=A0 smp_irq_work_interrupt+0x2=
37/0x3e0<br>
[=C2=A0 =C2=A025.251837][=C2=A0 =C2=A0 C0]=C2=A0 irq_work_interrupt+0x2e/0x=
40<br>
[=C2=A0 =C2=A025.252424][=C2=A0 =C2=A0 C0]=C2=A0 &lt;/IRQ&gt;<br>
....<br>
<br>
<br>
I couldn&#39;t even log in.<br>
<br>
how should I use qemu with wheezy.img to start a kmsan kernel?<br>
<br>
Thanks.<br>
</blockquote></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To post to this group, send email to <a href=3D"mailto:kasan-dev@googlegrou=
ps.com">kasan-dev@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CAG_fn%3DUoK7qE-x7NHN17GXGNctKoEKZe9rZ7QqP1otnSCfcJDw%=
40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.goo=
gle.com/d/msgid/kasan-dev/CAG_fn%3DUoK7qE-x7NHN17GXGNctKoEKZe9rZ7QqP1otnSCf=
cJDw%40mail.gmail.com</a>.<br />
For more options, visit <a href=3D"https://groups.google.com/d/optout">http=
s://groups.google.com/d/optout</a>.<br />

--000000000000379536058bd9515b--
