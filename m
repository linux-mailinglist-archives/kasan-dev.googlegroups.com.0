Return-Path: <kasan-dev+bncBDOPF7OU44DRBVPAROFQMGQERHEMYHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id AF49D428195
	for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 15:53:25 +0200 (CEST)
Received: by mail-ed1-x538.google.com with SMTP id v2-20020a50f082000000b003db24e28d59sf13427528edl.5
        for <lists+kasan-dev@lfdr.de>; Sun, 10 Oct 2021 06:53:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633874005; cv=pass;
        d=google.com; s=arc-20160816;
        b=JpbgmtGZjgdbnXePuVSRKgJkNINn+9Mdl+vv+jw5/n07+ZNGlRHBv+4H9aFTCAny2z
         mr4iw04dWoIBk16hGGtq6aI1Kough+UImXo+alL8ZBB/xWQeN+OK/xThOBzdrhmhUKfb
         mT8RdIx5N/06wPBCojCHbzmlN8uLhew9wk7O862S7wV7lCeR9N2YqpzulakvZaNr8+qd
         9yfz6T1u5v3yqv2Qdm9JT2miKp0Aa5RdP63fgiECClR0wNo88wisBmrYg3vWsWku+AuT
         7PG09X9NBrqqO+K+aouN3vHlYRhksDeSa08heuDosigMRsVteCDggy+Ao3Vmi1FhzeqR
         wHjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=LzTSsQOwmlF0GE2hFOJEG5nysy8RsCCU8khIOEOCPgE=;
        b=Fgebf8QA/54TzQcSPzi18PFyxxf4qdA92xrEx9ZYWaIyjjTQhArcLaG9McHZLhE7u7
         OSH1yHF6HGjrRN++MNHSBas6gd2iV1hA09XJKSimDhwAZM7KV50qP6pu6FgZXOci6veE
         OSyzrXYgYV8sqHdtJobZs8E6fG5n4x4TApZhonxF+TRh4i0toQB1v4UhdGuLHtju00tR
         Yi6EFuhon2fki6B+q2gB53lwcDofM/ysufIYlqnGtE8Tkrk2n8e1816YEsbkbfOtbnwN
         qzE92gkR7+DUecr8yHS1N9zP7Cs+ybilfX3LIOVWrfyLdHtpAZx+kODAzADFhMSlhLqv
         leDQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=BgwnmNSr;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:mime-version
         :content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=LzTSsQOwmlF0GE2hFOJEG5nysy8RsCCU8khIOEOCPgE=;
        b=dDhnKOgizV/+PKWcUftthNtviAaP/luSNklyUzGfuCRzhlAUnLK1gD1EB6DBVDY9Vv
         PKpu3SMtzIEaGm+o6S7tpYQagWoe87vMJDxDq5Wd0ncZuYsu8/tkk3epvPAopDv4WRnc
         N0C4clJJv8t1GiIIEJqLB2S3qqonpkr4Wfl1u2NRtGVy/61PBRihV/cjC6dBnPpbYRKv
         3wViOEHQ7pllmH2ymXmZeNo2ZVSKXzMLH1pK8biSRAFBzIXDdCa39m2lVMbpoZht6tZX
         2pFVpyp+nuj82cQJc9iRwUy4MAsHc+U7YFohysrpbxakNSKQh1mVcOz2RlQC0KZsbGK2
         CRnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :mime-version:content-disposition:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LzTSsQOwmlF0GE2hFOJEG5nysy8RsCCU8khIOEOCPgE=;
        b=rSaiZTG+u/AngIWd3mnCBVQZtRFi3+l0z+MzZzVRUdBqYJiGlWAgjlRReEV9Qslhlr
         rn0Ts/SSS0trpzWTsNl83SQtvBlA+9QyGFh+7lZ77SHXf0cdHTY05UfPHin5dXcQUW+C
         XALomhCTsfelpNLIA+q+/1iy1BWPHtc8582cF9c4VE8MG/G5V/32ArirNCPhrWfW/JQ1
         s7ujLCyKsGT7Zshk/OpCXOjif2K1d30/3HWSjIf6/ah4jHp+q6F5h4CevoZYxv2SRTI0
         khyE0oes5Iq1Ow5MTP8cFXDR68IL8YNcgdgNPUiWAgVydJpRtcFZT54IaG/IEE+vEvqY
         rsVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Ynzex9WBgHKLAFEWbEHKHu8XFJOkCKh8vnZDyU3kNcl9Iotz2
	uEdlOov3wF2x19wudQCi2As=
X-Google-Smtp-Source: ABdhPJxCcjDvibzSDCM506QAaTlgpyPjNWoBI2zvxedcJA+pqO77fqWUSVOt7XAeWeYAgzdhCeG4YA==
X-Received: by 2002:aa7:dbd2:: with SMTP id v18mr32838479edt.315.1633874005480;
        Sun, 10 Oct 2021 06:53:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:1693:: with SMTP id hc19ls1416636ejc.9.gmail; Sun,
 10 Oct 2021 06:53:24 -0700 (PDT)
X-Received: by 2002:a17:906:7007:: with SMTP id n7mr18533663ejj.275.1633874004503;
        Sun, 10 Oct 2021 06:53:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633874004; cv=none;
        d=google.com; s=arc-20160816;
        b=KbRVCY6+FukSFHXLiFHTJti1b13KkNSOnJsLP7CsVUVGCZ8TJLhqbYIP1u2OynwUk0
         eS0lPKiWOH8GaPJ/8KWx7HD9zutrV+h3D/LgNuAGWQNFhtMrNP+lBnRMuJ9WIFCFQDcn
         lWGuZbxa5fzRHFxQOD+HydolxhgKlIUOauw22lx4qmHpodA2ulMM6QnN3Mqsj9OuDJt1
         rfnFJxjAA/V/D8bLqzX1XRZUf56bVTLsN1rkg7lBOzSdpTsMWUj5AqzmCD6T4MvnTlUb
         iCg3IiDulqJuTGWzjwOch6nevyzLDLmyo1ecWOV5xqbLYvkYG1GOGfANE/qiDSI6g5Yu
         AUTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=cWmRjV0wZ18cbgRf5UvNL+wnZ92ayCL+tBImhmYVm7c=;
        b=XYyuQw9J0IL9a6bROtgvqzoQVdeivqYPcfyb/KGfwoPkow1vOsd06bSt0A/atEMIJB
         BZ0XBY4juRAVCxyODEmQgBzXT82CHUKN3J8LLCYfwKknJdSejfwIN5U2htB/0bpzH0tt
         YcDqX9pAsB8D7Gu1TJI4HMapX921kXBx+C9pru9Am8Bca9LwoWxeVBizQdU4cnJQKc6J
         P1XpURhs++jAeQiPDakUkLG6cU3iQxbqxn0Zwo2Jz+3KbrBoHH44WTP1xkfq8hNhFnSS
         J6GVmE87k0LDoYXTj9iDhMbHpZ8sezR+9EV+tnrENqcc+P0A928fE4TqZ+LO5j5lwN0k
         WhsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@canonical.com header.s=20210705 header.b=BgwnmNSr;
       spf=pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
Received: from smtp-relay-internal-0.canonical.com (smtp-relay-internal-0.canonical.com. [185.125.188.122])
        by gmr-mx.google.com with ESMTPS id i5si365663edk.3.2021.10.10.06.53.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Oct 2021 06:53:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122 as permitted sender) client-ip=185.125.188.122;
Received: from mail-ed1-f70.google.com (mail-ed1-f70.google.com [209.85.208.70])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-relay-internal-0.canonical.com (Postfix) with ESMTPS id EE85940012
	for <kasan-dev@googlegroups.com>; Sun, 10 Oct 2021 13:53:23 +0000 (UTC)
Received: by mail-ed1-f70.google.com with SMTP id x5-20020a50f185000000b003db0f796903so13401460edl.18
        for <kasan-dev@googlegroups.com>; Sun, 10 Oct 2021 06:53:23 -0700 (PDT)
X-Received: by 2002:a17:906:52d6:: with SMTP id w22mr16390611ejn.248.1633874003494;
        Sun, 10 Oct 2021 06:53:23 -0700 (PDT)
X-Received: by 2002:a17:906:52d6:: with SMTP id w22mr16390591ejn.248.1633874003248;
        Sun, 10 Oct 2021 06:53:23 -0700 (PDT)
Received: from localhost ([2001:67c:1560:8007::aac:c1b6])
        by smtp.gmail.com with ESMTPSA id v13sm2111473ejh.62.2021.10.10.06.53.22
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 10 Oct 2021 06:53:23 -0700 (PDT)
Date: Sun, 10 Oct 2021 15:53:21 +0200
From: Andrea Righi <andrea.righi@canonical.com>
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: BUG: soft lockup in __kmalloc_node() with KFENCE enabled
Message-ID: <YWLwUUNuRrO7AxtM@arighi-desktop>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: andrea.righi@canonical.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@canonical.com header.s=20210705 header.b=BgwnmNSr;       spf=pass
 (google.com: domain of andrea.righi@canonical.com designates 185.125.188.122
 as permitted sender) smtp.mailfrom=andrea.righi@canonical.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=canonical.com
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

I can systematically reproduce the following soft lockup w/ the latest
5.15-rc4 kernel (and all the 5.14, 5.13 and 5.12 kernels that I've
tested so far).

I've found this issue by running systemd autopkgtest (I'm using the
latest systemd in Ubuntu - 248.3-1ubuntu7 - but it should happen with
any recent version of systemd).

I'm running this test inside a local KVM instance and apparently systemd
is starting up its own KVM instances to run its tests, so the context is
a nested KVM scenario (even if I don't think the nested KVM part really
matters).

Here's the oops:

[   36.466565] watchdog: BUG: soft lockup - CPU#0 stuck for 26s! [udevadm:333]
[   36.466565] Modules linked in: btrfs blake2b_generic zstd_compress raid10 raid456 async_raid6_recov async_memcpy async_pq async_xor async_tx xor raid6_pq libcrc32c raid1 raid0 multipath linear psmouse floppy
[   36.466565] CPU: 0 PID: 333 Comm: udevadm Not tainted 5.15-rc4
[   36.466565] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.14.0-2 04/01/2014
[   36.466565] RIP: 0010:__kmalloc_node+0xcf/0x370
[   36.466565] Code: 00 85 c0 74 20 49 8b 45 00 a8 03 0f 85 8e 02 00 00 65 48 ff 08 e8 01 7a e3 ff 45 31 ff e9 a3 00 00 00 45 31 ed 4d 85 f6 74 f0 <0f> 1f 44 00 00 48 c7 45 c8 00 00 00 00 4d 8b 06 65 4c 03 05 19 87
[   36.466565] RSP: 0018:ffffb512802c3aa8 EFLAGS: 00000286
[   36.466565] RAX: 0000000000000000 RBX: 0000000000000dc0 RCX: 0000000000000000
[   36.466565] RDX: 0000000000000000 RSI: 0000000000000dc0 RDI: ffff998601042700
[   36.466565] RBP: ffffb512802c3af0 R08: ffffeb90800b5c00 R09: 0000000000000000
[   36.466565] R10: 0000000000000293 R11: ffff99861e02f448 R12: 0000000000000dc0
[   36.466565] R13: 0000000000000000 R14: ffff998601042700 R15: ffffffff8b519c4d
[   36.466565] FS:  00007f08d0674d00(0000) GS:ffff99861e000000(0000) knlGS:0000000000000000
[   36.466565] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   36.466565] CR2: 00005622f86e3108 CR3: 00000000033c8000 CR4: 00000000000006f0
[   36.466565] Call Trace:
[   36.466565]  memcg_alloc_page_obj_cgroups+0x3d/0x90
[   36.466565]  allocate_slab+0xc1/0x440
[   36.466565]  ? get_any_partial+0x85/0x190
[   36.466565]  new_slab+0x3a/0x60
[   36.466565]  ___slab_alloc+0x562/0x6b0
[   36.466565]  ? __alloc_file+0x28/0xe0
[   36.466565]  ? __alloc_file+0x28/0xe0
[   36.466565]  ? dput+0x84/0x180
[   36.466565]  ? step_into+0x312/0x380
[   36.466565]  kmem_cache_alloc+0x299/0x2d0
[   36.466565]  ? __alloc_file+0x28/0xe0
[   36.466565]  __alloc_file+0x28/0xe0
[   36.466565]  alloc_empty_file+0x45/0xc0
[   36.466565]  path_openat+0x47/0x2b0
[   36.466565]  do_filp_open+0xb2/0x150
[   36.466565]  ? putname+0x55/0x60
[   36.466565]  ? __check_object_size.part.0+0x128/0x150
[   36.466565]  ? __check_object_size+0x19/0x20
[   36.466565]  ? alloc_fd+0x53/0x170
[   36.466565]  do_sys_openat2+0x9b/0x160
[   36.466565]  __x64_sys_openat+0x55/0x90
[   36.466565]  do_syscall_64+0x5c/0xc0
[   36.466565]  ? exit_to_user_mode_prepare+0x37/0xb0
[   36.466565]  ? syscall_exit_to_user_mode+0x27/0x50
[   36.466565]  ? __x64_sys_newfstatat+0x1c/0x20
[   36.466565]  ? do_syscall_64+0x69/0xc0
[   36.466565]  ? do_syscall_64+0x69/0xc0
[   36.466565]  ? do_syscall_64+0x69/0xc0
[   36.466565]  entry_SYSCALL_64_after_hwframe+0x44/0xae
[   36.466565] RIP: 0033:0x7f08d0c0466b
[   36.466565] Code: 25 00 00 41 00 3d 00 00 41 00 74 4b 64 8b 04 25 18 00 00 00 85 c0 75 67 44 89 e2 48 89 ee bf 9c ff ff ff b8 01 01 00 00 0f 05 <48> 3d 00 f0 ff ff 0f 87 91 00 00 00 48 8b 4c 24 28 64 48 2b 0c 25
[   36.466565] RSP: 002b:00007ffe10be08f0 EFLAGS: 00000246 ORIG_RAX: 0000000000000101
[   36.466565] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007f08d0c0466b
[   36.466565] RDX: 0000000000080000 RSI: 00007ffe10be0a70 RDI: 00000000ffffff9c
[   36.466565] RBP: 00007ffe10be0a70 R08: fefefefefefefeff R09: fefefeff716e6c71
[   36.466565] R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000080000
[   36.466565] R13: 00005622f86e2520 R14: 0000000000000003 R15: 00007ffe10be0990

It looks like this is pointing at asm_volatile_goto():

crash> gdb list *(__kmalloc_node+0xcf)
0xffffffff8b4f8e3f is in __kmalloc_node (/build/impish/arch/x86/include/asm/jump_label.h:27).
22      
23      #ifdef CONFIG_STACK_VALIDATION
24      
25      static __always_inline bool arch_static_branch(struct static_key *key, bool branch)
26      {
27              asm_volatile_goto("1:"
28                      "jmp %l[l_yes] # objtool NOPs this \n\t"
29                      JUMP_TABLE_ENTRY
30                      : :  "i" (key), "i" (2 | branch) : : l_yes);
31      

And it seems that we're hitting an int3:

crash> bt 1
PID: 1      TASK: ffff998601248000  CPU: 3   COMMAND: "systemd"
    [exception RIP: poke_int3_handler+89]
    RIP: ffffffff8be6ac89  RSP: ffffb51280013b80  RFLAGS: 00000046
    RAX: 000000008c0010a7  RBX: 0000000000000000  RCX: ffffb51280013ba8
    RDX: 0000000000000000  RSI: ffffffff8c000a99  RDI: ffffb51280013ba8
    RBP: ffffb51280013b98   R8: 0000000000000000   R9: 0000000000000000
    R10: 0000000000000000  R11: 0000000000000000  R12: ffffb51280013ba8
    R13: 0000000000000000  R14: 0000000000000000  R15: 0000000000000000
    CS: 0010  SS: 0018
 #0 [ffffb51280013b80] exc_int3 at ffffffff8be69e80
 #1 [ffffb51280013ba0] asm_exc_int3 at ffffffff8c000aa1
 #2 [ffffb51280013c28] __kmalloc_node at ffffffff8b4f8e40
 #3 [ffffb51280013c80] __kmalloc_node at ffffffff8b4f8e16
 #4 [ffffb51280013cd8] kvmalloc_node at ffffffff8b4885c8
 #5 [ffffb51280013d00] seq_read_iter at ffffffff8b56139c
 #6 [ffffb51280013d60] seq_read at ffffffff8b561585
 #7 [ffffb51280013de8] vfs_read at ffffffff8b531b0f
 #8 [ffffb51280013e28] ksys_read at ffffffff8b5321d7
 #9 [ffffb51280013e68] __x64_sys_read at ffffffff8b532269
#10 [ffffb51280013e78] do_syscall_64 at ffffffff8be6900c
#11 [ffffb51280013f50] entry_SYSCALL_64_after_hwframe at ffffffff8c00007c
    RIP: 00007fc076f2e912  RSP: 00007ffde04ba888  RFLAGS: 00000246
    RAX: ffffffffffffffda  RBX: 000055e3b310bc30  RCX: 00007fc076f2e912
    RDX: 0000000000000400  RSI: 000055e3b31415e0  RDI: 0000000000000029
    RBP: 00007fc077031560   R8: 0000000000000029   R9: 0000000000000050
    R10: 0000000000001000  R11: 0000000000000246  R12: 00007fc07679a6c0
    R13: 0000000000000d68  R14: 00007fc077030960  R15: 0000000000000d68
    ORIG_RAX: 0000000000000000  CS: 0033  SS: 002b

If I disable CONFIG_KFENCE the soft lockup doesn't happen and systemd
autotest completes just fine.

We've decided to disable KFENCE in the latest Ubuntu Impish kernel
(5.13) for now, because of this issue, but I'm still investigating
trying to better understand the problem.

Any hint / suggestion?

Thanks,
-Andrea

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YWLwUUNuRrO7AxtM%40arighi-desktop.
