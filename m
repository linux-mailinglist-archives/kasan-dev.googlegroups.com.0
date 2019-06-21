Return-Path: <kasan-dev+bncBCWPNP5RT4JRBB4FWTUAKGQETXMGBKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43a.google.com (mail-wr1-x43a.google.com [IPv6:2a00:1450:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 232F64ECDD
	for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 18:15:04 +0200 (CEST)
Received: by mail-wr1-x43a.google.com with SMTP id i2sf2847989wrp.12
        for <lists+kasan-dev@lfdr.de>; Fri, 21 Jun 2019 09:15:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1561133703; cv=pass;
        d=google.com; s=arc-20160816;
        b=wysFYdKpEMZHWDgmNaenaGDVLHzwVN/vuPwef5p+r+sOpJqx5/uQRunrgMTTMRQT9n
         JTAPL9yu43HCEDMzKiuIgRpq8ed6lQrHxl293YutWBdr/vs7cLmMAdKG2ghyhO27kO5l
         iORZ5hGyfF80DXxisp6qdm5nf6/P1659BaYhTfivdNjdms0AW8JpUIdwNRX2070GkIIA
         ugKDb35Gj+jN8kMWewOMxeOGdhGUugiAS3LidOrlaN6tqBcistRBqTv49VIFX2Z5WrTd
         bvyDFR8yG+mCe+M5+sWz7eKYBhW/UNUuHw6tDogyo8vJ3VQcIiT/obOCYB/W2pmasSCw
         9epw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature:dkim-signature;
        bh=ktUQIM6IVFeFfm3hD4iib+WhIIaMdGIYVM9ZuOAuWgs=;
        b=VLZlJpbJs2Ovsk/RLrUOEclccPApqGGGe0DtDl2fFXdUHnaU0iqhMM1XSxvxsAjG8l
         N7zUO0Je6QhmjhO0yk33qndBN1Z3f8B2/E1sTCO4C4BxcJxZru+dbdjASWJX9quHvaWs
         oa7qPVmpZNGn3GH9zPiKBIqAQQc2vOQpa+PkaBQ+6B0uS9WIiBhQ0KzIwtMY80LLR0b4
         z0YH3iPw3Umr88B65Va/egHIU91xUkSbqovHhyiUoOshqsJv8verjPNFpWwSu+B+sv0K
         7Qj+Jdk5a+OVJ5EOKupfDAO3YNZQwjrmpbuRM63lzO3zkHR2r538lZgGIxIZcmOXUl2X
         mABg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XZaKpFlD;
       spf=pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ktUQIM6IVFeFfm3hD4iib+WhIIaMdGIYVM9ZuOAuWgs=;
        b=jinEbZqPY1pMAwf/mgA2zWjL7iSEtS/VtuYSGyeB9tK3XvhqYL6R0wGbyRYGFK6poX
         hPKfCj3pJUddtN2EIji6sO6CjjuewheXdgyIS9R7TbILCBFOXZHYbxXp9LSwVFqeavKl
         GnMMdksEh6+XFUUHhYJvNtMIpV26vbqZRiXHEbZYJQPkP29F/IuLJuuSWl2Q577Dfl1y
         5ZOEacDAWYul3NBEkKZLTuymbCNJJYRrPikvQhWT/qFD7MeF6T0XftIozSf1ZvBQnc4A
         U+lxmBhBWtXu94wfWRAfL3iP9CzswmoknLkYaIsMmoYcwXAOti7pFdzxOeYCT1zH3Erw
         oAWw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:from:date:message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ktUQIM6IVFeFfm3hD4iib+WhIIaMdGIYVM9ZuOAuWgs=;
        b=DuJXGDTOoHVZJgHdX22Rv0tcsh7fSttkMu79eKP4vITGevtu+mKNWfV9efgHUAGPIA
         lrt7cHvqkxXSBp3c4zhQLpj9bXFXVc2mLioG2VaU4GMQlhs1/TY0k3hrwXZMd72InPev
         qlpq/khgnCpJDZEnhkUFolhRl9KcdD8D3vnJyPYy+Eyjtw7VJgcmwHrG1WUPiyC8MLAy
         X8qn40t+9P4bIvjAX7kxyoRaVz855+HDSG/qVPVcsm873n9kBAHuAzBptti4OB5vwxre
         zwz3PfSqlWS2bJBcRmfXB7NO8gdIbhxumiAKQvKIQytcq2dNz1JeqTNAj2mYEzLtxzwv
         l4+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ktUQIM6IVFeFfm3hD4iib+WhIIaMdGIYVM9ZuOAuWgs=;
        b=SThHCj7ZBzaYgUiEwd1kG+ThrGa3qsFTucSQzkskxzCLTNc26r93gMo3Bzhc5vvgt2
         jeJFPKtTIW0Mkh+9Wugf8D6Eu+U5bIlrhnU9fX14ZQkCRuNIJgy05a9mlAGxRQpb0Rtq
         N6ZXkZOw0HtOWoHmqoQxBGrMPRZFn5EUvBbPSacz0KL/Ox9tzlEJyWapnSOXMxAC+3h+
         7M5K33XR3aWAY2HWVtqLi1zMvh4dlNtCwzsU/OF5VVXLezXBqkHBT8296Dj/sUG62ZMt
         RG+sj5h7EkYW6r8tRup79YcqldFIWXNzRIp/4UCloFwh4Tvr3XaDpsRBvZ4UzLEVfH/k
         sKCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVTUXcx7cHQHDfSMa4NDvws8/p2twmIN826tTet/2cerxdyAqVd
	FU5IThD/tNBBlY0oqFw+Y6M=
X-Google-Smtp-Source: APXvYqzLzFldTFaTpIBFVBYx9YoRDtXbLQCr0Yix0fGlAbFUnTro7aRVDg5IXQ4AoxP5/k5FY06dTQ==
X-Received: by 2002:a7b:cd9a:: with SMTP id y26mr4919179wmj.44.1561133703843;
        Fri, 21 Jun 2019 09:15:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7fd1:: with SMTP id a200ls2752716wmd.2.gmail; Fri, 21
 Jun 2019 09:15:03 -0700 (PDT)
X-Received: by 2002:a1c:35c9:: with SMTP id c192mr4789309wma.147.1561133703293;
        Fri, 21 Jun 2019 09:15:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1561133703; cv=none;
        d=google.com; s=arc-20160816;
        b=UWp9vVnmSVm8YIAQgg9Vihl/ZYn2zoD2q3Z0fPXX7s1i6bgmYzd/lKEs5Je24MENes
         /hcxpAWNxq+soL0x/T2/9ZW+opV2Xps6RWMrkK3tD27bw4mQqLjGSY5bf+v3JlQ8JgJl
         efV9QOcT/rCqykurDMHd8bQKDWkwFwdQIc/9nGyVIRGeY6RyrIxFHMagvEO0AZu22/Je
         yGEhzGuDBD2jEVWoYodUWBcj6SbwDqGjQSXas8Cs2zWjt5nyplYULOpNVbVTgq372fC1
         3qAmh65OS7bUbyagAIHNAtdLrRPoZAMq7Dm0+wnuJtrtDZ8tzcqOl2wKiRaUhlgwdy0w
         +TVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=QW1DCJopudeRLH3CLEcf+sxJPxOPEhS9Re9YlAeHxGA=;
        b=HFhX3wSvlhJhOibUlmhJumRdGXbUjM9ATeQB0SDJqS5kGZcMGkoZENDKTLJl6wetJw
         sthAGY6XNZNowHfQdyHQ5pCMKcJwN4fQqi4QDLKhhmZihUipCMew8QrynstrrXlAPupk
         8nj1LTtYdJ4329dlu3lTIFhHrNQLViZTXzkxDa1ZJZzy+DzHYZwG7TcDUMM4CcBW2Oqj
         OIyShsf5sUA3G4D75j5TSuNn0Np/jxmgjj81b8aDPcyHHDsJY0KmEcQSSYxSAP9nL7oc
         vVZd4PMvHCKlQB5pq/YsBaPmVrvoLeRjbGN0WIfLFt73OzKOjJa4BHWsSz5yhVCSmbNP
         ttdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=XZaKpFlD;
       spf=pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id j15si748577wmh.0.2019.06.21.09.15.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Fri, 21 Jun 2019 09:15:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id g135so6825726wme.4
        for <kasan-dev@googlegroups.com>; Fri, 21 Jun 2019 09:15:03 -0700 (PDT)
X-Received: by 2002:a7b:cd15:: with SMTP id f21mr4386381wmj.99.1561133702637;
 Fri, 21 Jun 2019 09:15:02 -0700 (PDT)
MIME-Version: 1.0
From: Xin Long <lucien.xin@gmail.com>
Date: Sat, 22 Jun 2019 00:14:51 +0800
Message-ID: <CADvbK_fCWry5LRV-6yzkgLQXFj0_Qxi46gRrrO-ikOh8SbxQuA@mail.gmail.com>
Subject: how to start kmsan kernel with qemu
To: kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: lucien.xin@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=XZaKpFlD;       spf=pass
 (google.com: domain of lucien.xin@gmail.com designates 2a00:1450:4864:20::343
 as permitted sender) smtp.mailfrom=lucien.xin@gmail.com;       dmarc=pass
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

this is my command:

/usr/libexec/qemu-kvm -smp 2 -m 4G -enable-kvm -cpu host \
    -net nic -net user,hostfwd=tcp::10022-:22 \
    -kernel /home/kmsan/arch/x86/boot/bzImage -nographic \
    -device virtio-scsi-pci,id=scsi \
    -device scsi-hd,bus=scsi.0,drive=d0 \
    -drive file=/root/test/wheezy.img,format=raw,if=none,id=d0 \
    -append "root=/dev/sda console=ttyS0 earlyprintk=serial rodata=n \
      oops=panic panic_on_warn=1 panic=86400 kvm-intel.nested=1 \
      security=apparmor ima_policy=tcb workqueue.watchdog_thresh=140 \
      nf-conntrack-ftp.ports=20000 nf-conntrack-tftp.ports=20000 \
      nf-conntrack-sip.ports=20000 nf-conntrack-irc.ports=20000 \
      nf-conntrack-sane.ports=20000 vivid.n_devs=16 \
      vivid.multiplanar=1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2 \
      spec_store_bypass_disable=prctl nopcid"

the commit is on:
commit f75e4cfea97f67b7530b8b991b3005f991f04778 (HEAD)
Author: Alexander Potapenko <glider@google.com>
Date:   Wed May 22 12:30:13 2019 +0200

    kmsan: use kmsan_handle_urb() in urb.c

and when starting, it shows:
[    0.561925][    T0] Kernel command line: root=/dev/sda
console=ttyS0 earlyprintk=serial rodata=n       oops=panic
panic_on_warn=1 panic=86400 kvm-intel.nested=1       security=ad
[    0.707792][    T0] Memory: 3087328K/4193776K available (219164K
kernel code, 7059K rwdata, 11712K rodata, 5064K init, 11904K bss,
1106448K reserved, 0K cma-reserved)
[    0.710935][    T0] SLUB: HWalign=64, Order=0-3, MinObjects=0,
CPUs=2, Nodes=1
[    0.711953][    T0] Starting KernelMemorySanitizer
[    0.712563][    T0]
==================================================================
[    0.713657][    T0] BUG: KMSAN: uninit-value in mutex_lock+0xd1/0xe0
[    0.714570][    T0] CPU: 0 PID: 0 Comm: swapper Not tainted 5.1.0 #5
[    0.715417][    T0] Hardware name: Red Hat KVM, BIOS
1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
[    0.716659][    T0] Call Trace:
[    0.717127][    T0]  dump_stack+0x134/0x190
[    0.717727][    T0]  kmsan_report+0x131/0x2a0
[    0.718347][    T0]  __msan_warning+0x7a/0xf0
[    0.718952][    T0]  mutex_lock+0xd1/0xe0
[    0.719478][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
[    0.720260][    T0]  ? vprintk_func+0x6b5/0x8a0
[    0.720926][    T0]  ? rb_get_reader_page+0x1140/0x1140
[    0.721632][    T0]  __cpuhp_setup_state+0x181/0x2e0
[    0.722374][    T0]  ? rb_get_reader_page+0x1140/0x1140
[    0.723115][    T0]  tracer_alloc_buffers+0x16b/0xb96
[    0.723846][    T0]  early_trace_init+0x193/0x28f
[    0.724501][    T0]  start_kernel+0x497/0xb38
[    0.725134][    T0]  x86_64_start_reservations+0x19/0x2f
[    0.725871][    T0]  x86_64_start_kernel+0x84/0x87
[    0.726538][    T0]  secondary_startup_64+0xa4/0xb0
[    0.727173][    T0]
[    0.727454][    T0] Local variable description:
----success.i.i.i.i@mutex_lock
[    0.728379][    T0] Variable was created at:
[    0.728977][    T0]  mutex_lock+0x48/0xe0
[    0.729536][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
[    0.730323][    T0]
==================================================================
[    0.731364][    T0] Disabling lock debugging due to kernel taint
[    0.732169][    T0] Kernel panic - not syncing: panic_on_warn set ...
[    0.733047][    T0] CPU: 0 PID: 0 Comm: swapper Tainted: G    B
        5.1.0 #5
[    0.734080][    T0] Hardware name: Red Hat KVM, BIOS
1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
[    0.735319][    T0] Call Trace:
[    0.735735][    T0]  dump_stack+0x134/0x190
[    0.736308][    T0]  panic+0x3ec/0xb3b
[    0.736826][    T0]  kmsan_report+0x29a/0x2a0
[    0.737417][    T0]  __msan_warning+0x7a/0xf0
[    0.737973][    T0]  mutex_lock+0xd1/0xe0
[    0.738527][    T0]  __cpuhp_setup_state_cpuslocked+0x149/0xd20
[    0.739342][    T0]  ? vprintk_func+0x6b5/0x8a0
[    0.739972][    T0]  ? rb_get_reader_page+0x1140/0x1140
[    0.740695][    T0]  __cpuhp_setup_state+0x181/0x2e0
[    0.741412][    T0]  ? rb_get_reader_page+0x1140/0x1140
[    0.742160][    T0]  tracer_alloc_buffers+0x16b/0xb96
[    0.742866][    T0]  early_trace_init+0x193/0x28f
[    0.743512][    T0]  start_kernel+0x497/0xb38
[    0.744128][    T0]  x86_64_start_reservations+0x19/0x2f
[    0.744863][    T0]  x86_64_start_kernel+0x84/0x87
[    0.745534][    T0]  secondary_startup_64+0xa4/0xb0
[    0.746290][    T0] Rebooting in 86400 seconds..

when I set "panic_on_warn=0", it foods the console with:
...
[   25.206759][    C0] Variable was created at:
[   25.207302][    C0]  vprintk_emit+0xf4/0x800
[   25.207844][    C0]  vprintk_deferred+0x90/0xed
[   25.208404][    C0]
==================================================================
[   25.209763][    C0]  x86_64_start_reservations+0x19/0x2f
[   25.209769][    C0]
==================================================================
[   25.211408][    C0] BUG: KMSAN: uninit-value in vprintk_emit+0x443/0x800
[   25.212237][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G    B
          5.1.0 #5
[   25.213206][    C0] Hardware name: Red Hat KVM, BIOS
1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
[   25.214326][    C0] Call Trace:
[   25.214725][    C0]  <IRQ>
[   25.215080][    C0]  dump_stack+0x134/0x190
[   25.215624][    C0]  kmsan_report+0x131/0x2a0
[   25.216204][    C0]  __msan_warning+0x7a/0xf0
[   25.216771][    C0]  vprintk_emit+0x443/0x800
[   25.217334][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0x20
[   25.218127][    C0]  vprintk_deferred+0x90/0xed
[   25.218714][    C0]  printk_deferred+0x186/0x1d3
[   25.219353][    C0]  __printk_safe_flush+0x72e/0xc00
[   25.220006][    C0]  ? printk_safe_flush+0x1e0/0x1e0
[   25.220635][    C0]  irq_work_run+0x1ad/0x5c0
[   25.221210][    C0]  ? flat_init_apic_ldr+0x170/0x170
[   25.221851][    C0]  smp_irq_work_interrupt+0x237/0x3e0
[   25.222520][    C0]  irq_work_interrupt+0x2e/0x40
[   25.223110][    C0]  </IRQ>
[   25.223475][    C0] RIP: 0010:kmem_cache_init_late+0x0/0xb
[   25.224164][    C0] Code: d4 e8 5d dd 2e f2 e9 74 fe ff ff 48 89 d3
8b 7d d4 e8 cd d7 2e f2 89 c0 48 89 c1 48 c1 e1 20 48 09 c1 48 89 0b
e9 81 fe ff ff <55> 48 89 e5 e8 20 de 2e1
[   25.226526][    C0] RSP: 0000:ffffffff8f40feb8 EFLAGS: 00000246
ORIG_RAX: ffffffffffffff09
[   25.227548][    C0] RAX: ffff88813f995785 RBX: 0000000000000000
RCX: 0000000000000000
[   25.228511][    C0] RDX: ffff88813f2b0784 RSI: 0000160000000000
RDI: 0000000000000785
[   25.229473][    C0] RBP: ffffffff8f40ff20 R08: 000000000fac3785
R09: 0000778000000001
[   25.230440][    C0] R10: ffffd0ffffffffff R11: 0000100000000000
R12: 0000000000000000
[   25.231403][    C0] R13: 0000000000000000 R14: ffffffff8fb8cfd0
R15: 0000000000000000
[   25.232407][    C0]  ? start_kernel+0x5d8/0xb38
[   25.233003][    C0]  x86_64_start_reservations+0x19/0x2f
[   25.233670][    C0]  x86_64_start_kernel+0x84/0x87
[   25.234314][    C0]  secondary_startup_64+0xa4/0xb0
[   25.234949][    C0]
[   25.235231][    C0] Local variable description: ----flags.i.i.i@vprintk_emit
[   25.236101][    C0] Variable was created at:
[   25.236643][    C0]  vprintk_emit+0xf4/0x800
[   25.237188][    C0]  vprintk_deferred+0x90/0xed
[   25.237752][    C0]
==================================================================
[   25.239117][    C0]  x86_64_start_kernel+0x84/0x87
[   25.239123][    C0]
==================================================================
[   25.240704][    C0] BUG: KMSAN: uninit-value in vprintk_emit+0x443/0x800
[   25.241540][    C0] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G    B
          5.1.0 #5
[   25.242512][    C0] Hardware name: Red Hat KVM, BIOS
1.11.1-3.module+el8.1.0+2983+b2ae9c0a 04/01/2014
[   25.243635][    C0] Call Trace:
[   25.244038][    C0]  <IRQ>
[   25.244390][    C0]  dump_stack+0x134/0x190
[   25.244940][    C0]  kmsan_report+0x131/0x2a0
[   25.245515][    C0]  __msan_warning+0x7a/0xf0
[   25.246082][    C0]  vprintk_emit+0x443/0x800
[   25.246638][    C0]  ? __msan_metadata_ptr_for_store_1+0x13/0x20
[   25.247430][    C0]  vprintk_deferred+0x90/0xed
[   25.248018][    C0]  printk_deferred+0x186/0x1d3
[   25.248650][    C0]  __printk_safe_flush+0x72e/0xc00
[   25.249320][    C0]  ? printk_safe_flush+0x1e0/0x1e0
[   25.249949][    C0]  irq_work_run+0x1ad/0x5c0
[   25.250524][    C0]  ? flat_init_apic_ldr+0x170/0x170
[   25.251167][    C0]  smp_irq_work_interrupt+0x237/0x3e0
[   25.251837][    C0]  irq_work_interrupt+0x2e/0x40
[   25.252424][    C0]  </IRQ>
....


I couldn't even log in.

how should I use qemu with wheezy.img to start a kmsan kernel?

Thanks.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADvbK_fCWry5LRV-6yzkgLQXFj0_Qxi46gRrrO-ikOh8SbxQuA%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
