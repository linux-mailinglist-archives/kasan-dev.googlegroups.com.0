Return-Path: <kasan-dev+bncBAABB45EU2IQMGQEVRA4SNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E3FC4D40F1
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Mar 2022 06:53:56 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id d40-20020a0565123d2800b004482625da41sf1404261lfv.20
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Mar 2022 21:53:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646891636; cv=pass;
        d=google.com; s=arc-20160816;
        b=w5Rdgm64BAfq9QunYliBeaXSWRsOJAYPLM+14/CJWQCucsO6n2xAkcp6+Yqf0kb1zp
         odUVMlHOSyij4rZAnfGD0G29gqXrUIT8j7hXpf1dCEAOtoXMirhU3Wj1m2EkqKiO1pAh
         meRsfKvrnSO/l6GKItOPvVH3tKtJpquG9Zi3m7DHNlcpELIUiocqB24UP37F7jE3BFHJ
         NnwbiikOPxiLdXLeeFDea1A1525rutNAWjRfQ+xz58FM67EWX+AjbThLdapoA33bFiau
         HS2R48QD6E89GUHjutzCftoc0SWidMtDPsPC1Vs7L2otrqh+PVpBPWEdyIYG+oWho0x4
         LDjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:subject
         :reply-to:cc:from:to:date:dkim-signature;
        bh=W8I6M/B/sFpdkPmRmZVwyNm7UUy/mD3ekx4Gkkxf1s4=;
        b=zO8S8u135YD9CyMSQRzwTuH6l2L/zEJMkGCF8tH5Z3Bi4pLGHkob3zzHl3Qzc3JWtd
         UHBvD3SEdkGHwbpjg5thGtLgpdYrODb0wBB3YVpOf6bv1u/d1aWxujYVInCoq5KB4kIj
         1hiE2wpqSATiLUfu8GCHUJ/4FchxGHa65yYIaWyb7Ne/89JocibrF3Umsd1AXlKNQeE0
         Y/Uv03tn711XfjM1OfpYsSuVd4Ofh8sb9TUP7KdO5oGkI/xcrtRcKdC0W+qQGu6XzR8v
         xOfVZW8h2ZhpnLOtIKnDciuteDdQqxbT9r3ZeBTCm/9652hieP/liKGziSHjelXL8UY6
         XLRQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail3 header.b="cPx/XV3F";
       spf=pass (google.com: domain of maciej.grochowski@protonmail.com designates 185.70.43.22 as permitted sender) smtp.mailfrom=maciej.grochowski@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:to:from:cc:reply-to:subject:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=W8I6M/B/sFpdkPmRmZVwyNm7UUy/mD3ekx4Gkkxf1s4=;
        b=h28Iuyojm7SCHwtrlgm3OX1dESE4gxITHWL0zoiVl/GCdLq9DGxh7qMot78lWbhjsF
         56ktLrEzLWNBYvPmshC/RwNveLDtOkFbnQQ0KstQ4QCM8fwUQM1Q3O87ufNoWv0n12EC
         j1sxytJKZw7h3WS1MDCokrGPkqD1Uy9K++YbvRHSOsQIkGfZUBEAbDHHhdKx/jmyvOjr
         eZ/xxfRGsuj2SzKjUE51IBrzj7DvOnFoMRUmcuDxvlC3KiP/Stfg0pgCdmAKKNKBh+nl
         6QHt1/RTO5kkGfB65wqv2Bgzwx2QlkWPxJwHFMNnFDm0h8lv0rprdBpOx8JiQzZAZD+N
         IiMQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:to:from:cc:reply-to:subject:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=W8I6M/B/sFpdkPmRmZVwyNm7UUy/mD3ekx4Gkkxf1s4=;
        b=bd055q9/j2w9iayYQFMMjJR8Ob//x4j71Rh4hWhkOMlk6TxphQWoCGwl4VvoUSRre5
         iMrq26WRTnjpGpXCv5vrKCbuRqQL6gmswUC0M7wGm7fi/C8S1uBkB/iFs8pYKwICmpIt
         YiSUumHWt56PIz9aJtpnsiHcggiet6KaUn4pAm2HaqYyvspcySilK6e65eD5ab4/5OVV
         58wIu4vZ9M99bzAd6DrZjdPM0TYR8/DB6Zkipi9rFzuyhRZYHsaqjYj3BM3J28L4thET
         Y8dYUgogpLEV0PFP9kTVUIpsCz/9b8154Xey0VWSIAXDzmuVICGl65DiUKNuv7sb9PqN
         jjFQ==
X-Gm-Message-State: AOAM531A8LkNQCwHEUI1JtJC8XoTXLsaXoB0yeeY2xEgUgPE7mpDrrZz
	0ptznNu6yYl4qyE7ApSasrc=
X-Google-Smtp-Source: ABdhPJwI0j9yRyFz6P5Wvvodn/gjC8zwxh1BDVosjJ5A0WRqqv33/Zrb2O4853qR+wgYuPGFpbQ6eA==
X-Received: by 2002:a05:6512:3ba4:b0:445:c23a:a007 with SMTP id g36-20020a0565123ba400b00445c23aa007mr1997510lfv.357.1646891635752;
        Wed, 09 Mar 2022 21:53:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:983:b0:247:f348:285b with SMTP id
 b3-20020a05651c098300b00247f348285bls859904ljq.4.gmail; Wed, 09 Mar 2022
 21:53:54 -0800 (PST)
X-Received: by 2002:a2e:9847:0:b0:238:eca:62fd with SMTP id e7-20020a2e9847000000b002380eca62fdmr1967910ljj.65.1646891634838;
        Wed, 09 Mar 2022 21:53:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646891634; cv=none;
        d=google.com; s=arc-20160816;
        b=zABc68b+YAYdGn2zVRbya6cZtt84dgmVi7nKYlNcdkjjmN37b/N5LJyzTUJwII0WD6
         NYHGUflRKhaMcELjMUgL6hmiqNNdgmBY4z2UhMrm9w8R3Ou0YbX2EY5zExHKeWhJnoau
         NvdxpS84x5fNSHpNxVyVqc5oRBSR1s8Rp0WNIR8yIR2izCyb9P5pm9UTo2E1u7v3seC+
         QQQdfmPGAkwFcytMejaPQHRcYPk/0zBxczS+vEWyj9i2b9+pkr2N7/Rx1bEd5SUmtvsX
         fXwC2CvsLMsMTFCQY05em7Pvmrl3Ci1Fb9cuzNyCCQJ0qtapBaE25AW+GpMkswFbXIpt
         nKhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:subject:reply-to:cc:from:to:dkim-signature
         :date;
        bh=6cixij2V70l6aGWYtOtxkrlG6GHacNuBJaK6yWkfnm8=;
        b=CE2Z8IHT+zkZDtoQKMNXuGwOPSDJkxJRfShgNs+12Z9oQjIpO54Fy9AHBwA3bzi52k
         Y7pID37aeD09tYnimR7KwtPL0J7j+UUKjBdfd2jCIrCDubwmye9tC13zuyYHco8zEGkd
         DFYgcehRVG7cbQabgf2uEzEmAiH/BcwiMrk0f+kxwf461f+2CoapgY2Ts2qK+VsDCjAG
         HKWK2coEb1TdYBK12tIf+Z/mCHyzGyxvmBITeXTLs3dYSMyDbMGuBtw556qkVbQIiDnY
         yDQ8MVXBYY0UpXLVr8ADJLMKEtL/mnVSZU49x1DrFSfYf/Z6vR7hIdac6A62JhH6VCre
         JrKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@protonmail.com header.s=protonmail3 header.b="cPx/XV3F";
       spf=pass (google.com: domain of maciej.grochowski@protonmail.com designates 185.70.43.22 as permitted sender) smtp.mailfrom=maciej.grochowski@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id w17-20020a05651c103100b00247ec5b4180si224638ljm.4.2022.03.09.21.53.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Mar 2022 21:53:54 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.grochowski@protonmail.com designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Thu, 10 Mar 2022 05:53:51 +0000
To: "kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>
From: "'Maciej' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: "maciej.grochowski@protonmail.com" <maciej.grochowski@protonmail.com>
Reply-To: Maciej <maciej.grochowski@protonmail.com>
Subject: KASAN Page Fault in kasan_check_range
Message-ID: <_nwXMUNLOQOevscYZc-5BgcvpW52Ih6Af4oVUiey8_-0yw7fUwSM_BbdQGgenQSfOhiYoCJ8wxTxa_mxzmNyQnNUla3JkvCkJk8w7eMXg58=@protonmail.com>
MIME-Version: 1.0
Content-Type: multipart/alternative;
 boundary="b1_utKJACYrCNLsqvx4LZjKEuJkoUvzR4TwTzvC18quJ0"
X-Original-Sender: maciej.grochowski@protonmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@protonmail.com header.s=protonmail3 header.b="cPx/XV3F";
       spf=pass (google.com: domain of maciej.grochowski@protonmail.com
 designates 185.70.43.22 as permitted sender) smtp.mailfrom=maciej.grochowski@protonmail.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=protonmail.com
X-Original-From: Maciej <maciej.grochowski@protonmail.com>
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

This is a multi-part message in MIME format.

--b1_utKJACYrCNLsqvx4LZjKEuJkoUvzR4TwTzvC18quJ0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Hi kasan-dev group!

I am working on my PCI driver that is spawning polling thread which is work=
ing on the queues that exist in the MMIO memory that belongs to the BAR of =
the device. The device is FPGA like external Endpoint with shared memory to=
 another system with ARM core on the other side. This system can be configu=
red of the BAR's is custom, so there is no generic kernel driver yet. I am =
trying to use a large memory BAR (in order of 512MB MMIO memory).
The system works fine, although when I turn on the KASAN, I run into Page f=
ault in the kasan_check_range function.
Code that is instrumented is checking request structure in the MMIO memory =
which is filled properly, but KASAN check seems to use some wrong address.

During development, I want to use KASAN as a tool to catch bugs, although I=
 reached the point where I could not explain the issue or provide a workaro=
und.
I am looking for any tips about any additional debug information or KASAN l=
ogs that could help me narrow down the issue.

This issue initially occurred on the 5.10 stable kernel, but I updated to t=
he latest stable 5.17, and I am still getting the same page fault. (I saw t=
here was recently a couple of improvements to KASAN).
The only thing that I can think of is that maybe KASAN Shadow buffer is not=
 big enough due to the additional MMIO memory that I am using in the driver=
, although I cannot verify that.

For KASAN I tried inline and outline instrumentations as well as enable/dis=
able "Back mappings in vmalloc space with real shadow memory" but none of t=
his settings have impact on the Page fault.

I would appreciate any help or suggestion on where to search for more clues=
!

Logs below:

[..] BUG: unable to handle page fault for address: ffffed8008000001
[..] irq event stamp: 823286
[..] irq event stamp: 16677449
[..] #PF: supervisor read access in kernel mode
[..] hardirqs last enabled at (823285): [] _raw_spin_unlock_irq+0x24/0x50
[..] #PF: error_code(0x0000) - not-present page
[..] PGD 0
[..] hardirqs last enabled at (16677449): [] set_root+0x1f0/0x270
[..] hardirqs last disabled at (823286): [] __schedule+0xc28/0x10b0
[..] P4D 0
[..] softirqs last enabled at (822698): [] __do_softirq+0x50e/0x756
[..] hardirqs last disabled at (16677448): [] set_root+0x1be/0x270
[..] softirqs last disabled at (822689): [] irq_exit_rcu+0xde/0x110
[..] softirqs last enabled at (16676820): [] __do_softirq+0x50e/0x756
[..] Oops: 0000 [#1] PREEMPT SMP DEBUG_PAGEALLOC KASAN NOPTI
[..] softirqs last disabled at (16676519): [] irq_exit_rcu+0xde/0x110
[..] CPU: 43 PID: 3664 Comm: polling_worker- Tainted: G OE 5.17.0-rc7 #1
[..] RIP: 0010:kasan_check_range+0x111/0x1c0
[..] Code: 01 4c 39 c0 0f 84 8b 00 00 00 80 38 00 74 ee 49 89 c0 b8 01 00 0=
0 00 4d 85 c0 0f 85 82 00 00 00 5b 5d 41 5c c3 48 85 db 74 6b <41> 80 39 00=
 75 6f 48 b8 01 00 00 00 00 fc ff df 49 01 d9 49 01 c0
[..] RSP: 0018:ffffc9000732fd88 EFLAGS: 00010202
[..] RAX: ffffed8008000001 RBX: 0000000000000001 RCX: ffffffffc09ffdff
[..] RDX: 0000000000000001 RSI: 0000000000000002 RDI: ffff8c004000000c
[..] RBP: ffffed8008000002 R08: 1ffff18008000001 R09: ffffed8008000001
[..] R10: ffff8c004000000d R11: ffffed8008000001 R12: ffff8881df500000
[..] R13: ffff8881df50000f R14: ffff88815ab10f88 R15: ffff88815ab10f88
[..] FS: 0000000000000000(0000) GS:ffff888df0400000(0000) knlGS:00000000000=
00000
[..] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[..] CR2: ffffed8008000001 CR3: 000000014991e002 CR4: 0000000000770ee0
[..] PKRU: 55555554
[..] Call Trace:
[..] polling_thread_io+0x15a/0x1c0 [my_module]
[..] ? polling_thread_io+0x10/0x10 [my_module]
[..] kthread+0x17d/0x1b0
[..] ? kthread_complete_and_exit+0x20/0x20
[..] ret_from_fork+0x22/0x30
[..]
[..] CR2: ffffed8008000001
[..] ---[ end trace 0000000000000000 ]---
[..] RIP: 0010:kasan_check_range+0x111/0x1c0
[..] Code: 01 4c 39 c0 0f 84 8b 00 00 00 80 38 00 74 ee 49 89 c0 b8 01 00 0=
0 00 4d 85 c0 0f 85 82 00 00 00 5b 5d 41 5c c3 48 85 db 74 6b <41> 80 39 00=
 75 6f 48 b8 01 00 00 00 00 fc ff df 49 01 d9 49 01 c0
[..] RSP: 0018:ffffc9000732fd88 EFLAGS: 00010202
[..] RAX: ffffed8008000001 RBX: 0000000000000001 RCX: ffffffffc09ffdff
[..] RDX: 0000000000000001 RSI: 0000000000000002 RDI: ffff8c004000000c
[..] RBP: ffffed8008000002 R08: 1ffff18008000001 R09: ffffed8008000001
[..] R10: ffff8c004000000d R11: ffffed8008000001 R12: ffff8881df500000
[..] R13: ffff8881df50000f R14: ffff88815ab10f88 R15: ffff88815ab10f88
[..] FS: 0000000000000000(0000) GS:ffff888df0400000(0000) knlGS:00000000000=
00000
[..] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[..] CR2: ffffed8008000001 CR3: 000000014991e002 CR4: 0000000000770ee0
[..] PKRU: 55555554

Decoding Code:
Code: 01 4c 39 c0 0f 84 8b 00 00 00 80 38 00 74 ee 49 89 c0 b8 01 00 00 00 =
4d 85 c0 0f 85 82 00 00 00 5b 5d 41 5c c3 48 85 db 74 6b <41> 80 39 00 75 6=
f 48 b8 01 00 00 00 00 fc ff df 49 01 d9 49 01 c0
All code
=3D=3D=3D=3D=3D=3D=3D=3D
0: 01 4c 39 c0 add %ecx,-0x40(%rcx,%rdi,1)
4: 0f 84 8b 00 00 00 je 0x95
a: 80 38 00 cmpb $0x0,(%rax)
d: 74 ee je 0xfffffffffffffffd
f: 49 89 c0 mov %rax,%r8
12: b8 01 00 00 00 mov $0x1,%eax
17: 4d 85 c0 test %r8,%r8
1a: 0f 85 82 00 00 00 jne 0xa2
20: 5b pop %rbx
21: 5d pop %rbp
22: 41 5c pop %r12
24: c3 retq
25: 48 85 db test %rbx,%rbx
28: 74 6b je 0x95
2a:* 41 80 39 00 cmpb $0x0,(%r9) <-- trapping instruction
2e: 75 6f jne 0x9f
30: 48 b8 01 00 00 00 00 movabs $0xdffffc0000000001,%rax
37: fc ff df
3a: 49 01 d9 add %rbx,%r9
3d: 49 01 c0 add %rax,%r8

Code starting with the faulting instruction
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
0: 41 80 39 00 cmpb $0x0,(%r9)
4: 75 6f jne 0x75
6: 48 b8 01 00 00 00 00 movabs $0xdffffc0000000001,%rax
d: fc ff df
10: 49 01 d9 add %rbx,%r9
13: 49 01 c0 add %rax,%r8

(gdb) list *kasan_check_range+0x111
0xffffffff815643a1 is in kasan_check_range (mm/kasan/generic.c:85).
80
81 static __always_inline unsigned long bytes_is_nonzero(const u8 *start,
82 size_t size)
83 {
84 while (size) {
85 if (unlikely(*start)) <<<< start seems to not be mapped
86 return (unsigned long)start;
87 start++;
88 size--;
89 }

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/_nwXMUNLOQOevscYZc-5BgcvpW52Ih6Af4oVUiey8_-0yw7fUwSM_BbdQGgenQSfO=
hiYoCJ8wxTxa_mxzmNyQnNUla3JkvCkJk8w7eMXg58%3D%40protonmail.com.

--b1_utKJACYrCNLsqvx4LZjKEuJkoUvzR4TwTzvC18quJ0
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<span>Hi kasan-dev group!</span><div><br></div><div><span>I am working on m=
y PCI driver that is spawning polling thread which is working on the queues=
 that exist in the MMIO memory that belongs to the BAR of the device. The d=
evice is FPGA like external Endpoint with shared memory to another system w=
ith ARM core on the other side. This system can be configured of the BAR's =
is custom, so there is no generic kernel driver yet. I am trying to use a l=
arge memory BAR (in order of 512MB MMIO memory).</span></div><div><span>The=
 system works fine, although when I turn on the KASAN, I run into Page faul=
t in the kasan_check_range function.</span></div><div><span>Code that is in=
strumented is checking request structure in the MMIO memory which is filled=
 properly, but KASAN check seems to use some wrong address.</span></div><di=
v><br></div><div><span>During development, I want to use KASAN as a tool to=
 catch bugs, although I reached the point where I could not explain the iss=
ue or provide a workaround.</span></div><div><span>I am looking for any tip=
s about any additional debug information or KASAN logs that could help me n=
arrow down the issue.</span></div><div><br></div><div><span>This issue init=
ially occurred on the 5.10 stable kernel, but I updated to the latest stabl=
e 5.17, and I am still getting the same page fault. (I saw there was recent=
ly a couple of improvements to KASAN).</span></div><div><span>The only thin=
g that I can think of is that maybe KASAN Shadow buffer is not big enough d=
ue to the additional MMIO memory that I am using in the driver, although I =
cannot verify that.</span></div><div><br></div><div>For KASAN I tried inlin=
e and outline instrumentations as well as enable/disable "<span>Back mappin=
gs in vmalloc space with real shadow memory" but none of this settings have=
 impact on the Page fault.</span></div><div><br></div><div><span>I would ap=
preciate any help or suggestion on where to search for more clues!</span></=
div><div><br></div><div><br></div><div><span>Logs below:</span></div><div><=
br></div><div><span>[..] BUG: unable to handle page fault for address: ffff=
ed8008000001</span></div><div><span>[..] irq event stamp: 823286</span></di=
v><div><span>[..] irq event stamp: 16677449</span></div><div><span>[..] #PF=
: supervisor read access in kernel mode</span></div><div><span>[..] hardirq=
s last &nbsp;enabled at (823285): [<span>] _raw_spin_unlock_irq+0x24/0x50</=
span></span></div><div><span>[..] #PF: error_code(0x0000) - not-present pag=
e</span></div><div><span>[..] PGD 0</span></div><div><span>[..] hardirqs la=
st &nbsp;enabled at (16677449): [<span>] set_root+0x1f0/0x270</span></span>=
</div><div><span>[..] hardirqs last disabled at (823286): [<span>] __schedu=
le+0xc28/0x10b0</span></span></div><div><span>[..] P4D 0</span></div><div><=
span>[..] softirqs last &nbsp;enabled at (822698): [<span>] __do_softirq+0x=
50e/0x756</span></span></div><div><span>[..] hardirqs last disabled at (166=
77448): [<span>] set_root+0x1be/0x270</span></span></div><div><span>[..] so=
ftirqs last disabled at (822689): [<span>] irq_exit_rcu+0xde/0x110</span></=
span></div><div><span>[..] softirqs last &nbsp;enabled at (16676820): [<spa=
n>] __do_softirq+0x50e/0x756</span></span></div><div><span>[..] Oops: 0000 =
[#1] PREEMPT SMP DEBUG_PAGEALLOC KASAN NOPTI</span></div><div><span>[..] so=
ftirqs last disabled at (16676519): [<span>] irq_exit_rcu+0xde/0x110</span>=
</span></div><div><span>[..] CPU: 43 PID: 3664 Comm: polling_worker- Tainte=
d: G &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; OE &nbsp; &nbsp; 5.17.0-rc7 #1</spa=
n></div><div><span>[..] RIP: 0010:kasan_check_range+0x111/0x1c0</span></div=
><div><span>[..] Code: 01 4c 39 c0 0f 84 8b 00 00 00 80 38 00 74 ee 49 89 c=
0 b8 01 00 00 00 4d 85 c0 0f 85 82 00 00 00 5b 5d 41 5c c3 48 85 db 74 6b &=
lt;41&gt; 80 39 00 75 6f 48 b8 01 00 00 00 00 fc ff df 49 01 d9 49 01 c0</s=
pan></div><div><span>[..] RSP: 0018:ffffc9000732fd88 EFLAGS: 00010202</span=
></div><div><span>[..] RAX: ffffed8008000001 RBX: 0000000000000001 RCX: fff=
fffffc09ffdff</span></div><div><span>[..] RDX: 0000000000000001 RSI: 000000=
0000000002 RDI: ffff8c004000000c</span></div><div><span>[..] RBP: ffffed800=
8000002 R08: 1ffff18008000001 R09: ffffed8008000001</span></div><div><span>=
[..] R10: ffff8c004000000d R11: ffffed8008000001 R12: ffff8881df500000</spa=
n></div><div><span>[..] R13: ffff8881df50000f R14: ffff88815ab10f88 R15: ff=
ff88815ab10f88</span></div><div><span>[..] FS: &nbsp;0000000000000000(0000)=
 GS:ffff888df0400000(0000) knlGS:0000000000000000</span></div><div><span>[.=
.] CS: &nbsp;0010 DS: 0000 ES: 0000 CR0: 0000000080050033</span></div><div>=
<span>[..] CR2: ffffed8008000001 CR3: 000000014991e002 CR4: 0000000000770ee=
0</span></div><div><span>[..] PKRU: 55555554</span></div><div><span>[..] Ca=
ll Trace:</span></div><div><span>[..] &nbsp;polling_thread_io+0x15a/0x1c0 [=
my_module]</span></div><div><span>[..] &nbsp;? polling_thread_io+0x10/0x10 =
[my_module]</span></div><div><span>[..] &nbsp;kthread+0x17d/0x1b0</span></d=
iv><div><span>[..] &nbsp;? kthread_complete_and_exit+0x20/0x20</span></div>=
<div><span>[..] &nbsp;ret_from_fork+0x22/0x30</span></div><div><span>[..] &=
nbsp;</span></div><div><span>[..] CR2: ffffed8008000001</span></div><div><s=
pan>[..] ---[ end trace 0000000000000000 ]---</span></div><div><span>[..] R=
IP: 0010:kasan_check_range+0x111/0x1c0</span></div><div><span>[..] Code: 01=
 4c 39 c0 0f 84 8b 00 00 00 80 38 00 74 ee 49 89 c0 b8 01 00 00 00 4d 85 c0=
 0f 85 82 00 00 00 5b 5d 41 5c c3 48 85 db 74 6b &lt;41&gt; 80 39 00 75 6f =
48 b8 01 00 00 00 00 fc ff df 49 01 d9 49 01 c0</span></div><div><span>[..]=
 RSP: 0018:ffffc9000732fd88 EFLAGS: 00010202</span></div><div><span>[..] RA=
X: ffffed8008000001 RBX: 0000000000000001 RCX: ffffffffc09ffdff</span></div=
><div><span>[..] RDX: 0000000000000001 RSI: 0000000000000002 RDI: ffff8c004=
000000c</span></div><div><span>[..] RBP: ffffed8008000002 R08: 1ffff1800800=
0001 R09: ffffed8008000001</span></div><div><span>[..] R10: ffff8c004000000=
d R11: ffffed8008000001 R12: ffff8881df500000</span></div><div><span>[..] R=
13: ffff8881df50000f R14: ffff88815ab10f88 R15: ffff88815ab10f88</span></di=
v><div><span>[..] FS: &nbsp;0000000000000000(0000) GS:ffff888df0400000(0000=
) knlGS:0000000000000000</span></div><div><span>[..] CS: &nbsp;0010 DS: 000=
0 ES: 0000 CR0: 0000000080050033</span></div><div><span>[..] CR2: ffffed800=
8000001 CR3: 000000014991e002 CR4: 0000000000770ee0</span></div><div><span>=
[..] PKRU: 55555554</span></div><div><br></div><div><span>Decoding Code:</s=
pan></div><div><span>&nbsp;Code: 01 4c 39 c0 0f 84 8b 00 00 00 80 38 00 74 =
ee 49 89 c0 b8 01 00 00 00 4d 85 c0 0f 85 82 00 00 00 5b 5d 41 5c c3 48 85 =
db 74 6b &lt;41&gt; 80 39 00 75 6f 48 b8 01 00 00 00 00 fc ff df 49 01 d9 4=
9 01 c0</span></div><div><span>All code</span></div><div><span>=3D=3D=3D=3D=
=3D=3D=3D=3D</span></div><div><span>&nbsp; &nbsp;0: &nbsp; 01 4c 39 c0 &nbs=
p; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; add &nbsp; &nbsp;%ecx,-0x40(%rcx,%rdi=
,1)</span></div><div><span>&nbsp; &nbsp;4: &nbsp; 0f 84 8b 00 00 00 &nbsp; =
&nbsp; &nbsp; je &nbsp; &nbsp; 0x95</span></div><div><span>&nbsp; &nbsp;a: =
&nbsp; 80 38 00 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;cmpb=
 &nbsp; $0x0,(%rax)</span></div><div><span>&nbsp; &nbsp;d: &nbsp; 74 ee &nb=
sp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; je &nbsp; &nbsp=
; 0xfffffffffffffffd</span></div><div><span>&nbsp; &nbsp;f: &nbsp; 49 89 c0=
 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;mov &nbsp; &nbsp;%r=
ax,%r8</span></div><div><span>&nbsp; 12: &nbsp; b8 01 00 00 00 &nbsp; &nbsp=
; &nbsp; &nbsp; &nbsp;mov &nbsp; &nbsp;$0x1,%eax</span></div><div><span>&nb=
sp; 17: &nbsp; 4d 85 c0 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &n=
bsp;test &nbsp; %r8,%r8</span></div><div><span>&nbsp; 1a: &nbsp; 0f 85 82 0=
0 00 00 &nbsp; &nbsp; &nbsp; jne &nbsp; &nbsp;0xa2</span></div><div><span>&=
nbsp; 20: &nbsp; 5b &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;=
 &nbsp; &nbsp; &nbsp;pop &nbsp; &nbsp;%rbx</span></div><div><span>&nbsp; 21=
: &nbsp; 5d &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; =
&nbsp; &nbsp;pop &nbsp; &nbsp;%rbp</span></div><div><span>&nbsp; 22: &nbsp;=
 41 5c &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; pop &=
nbsp; &nbsp;%r12</span></div><div><span>&nbsp; 24: &nbsp; c3 &nbsp; &nbsp; =
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;retq</span></=
div><div><span>&nbsp; 25: &nbsp; 48 85 db &nbsp; &nbsp; &nbsp; &nbsp; &nbsp=
; &nbsp; &nbsp; &nbsp;test &nbsp; %rbx,%rbx</span></div><div><span>&nbsp; 2=
8: &nbsp; 74 6b &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nb=
sp; je &nbsp; &nbsp; 0x95</span></div><div><span>&nbsp; 2a:* &nbsp;41 80 39=
 00 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; cmpb &nbsp; $0x0,(%r9) &nbsp;=
 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &lt;-- trapping instruction</spa=
n></div><div><span>&nbsp; 2e: &nbsp; 75 6f &nbsp; &nbsp; &nbsp; &nbsp; &nbs=
p; &nbsp; &nbsp; &nbsp; &nbsp; jne &nbsp; &nbsp;0x9f</span></div><div><span=
>&nbsp; 30: &nbsp; 48 b8 01 00 00 00 00 &nbsp; &nbsp;movabs $0xdffffc000000=
0001,%rax</span></div><div><span>&nbsp; 37: &nbsp; fc ff df</span></div><di=
v><span>&nbsp; 3a: &nbsp; 49 01 d9 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp=
; &nbsp; &nbsp;add &nbsp; &nbsp;%rbx,%r9</span></div><div><span>&nbsp; 3d: =
&nbsp; 49 01 c0 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;add =
&nbsp; &nbsp;%rax,%r8</span></div><div><br></div><div><span>Code starting w=
ith the faulting instruction</span></div><div><span>=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D</span></div><div><span>&nbsp; &nbsp;0: &n=
bsp; 41 80 39 00 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; cmpb &nbsp; $0x0=
,(%r9)</span></div><div><span>&nbsp; &nbsp;4: &nbsp; 75 6f &nbsp; &nbsp; &n=
bsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; jne &nbsp; &nbsp;0x75</span>=
</div><div><span>&nbsp; &nbsp;6: &nbsp; 48 b8 01 00 00 00 00 &nbsp; &nbsp;m=
ovabs $0xdffffc0000000001,%rax</span></div><div><span>&nbsp; &nbsp;d: &nbsp=
; fc ff df</span></div><div><span>&nbsp; 10: &nbsp; 49 01 d9 &nbsp; &nbsp; =
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;add &nbsp; &nbsp;%rbx,%r9</span></=
div><div><span>&nbsp; 13: &nbsp; 49 01 c0 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp=
; &nbsp; &nbsp; &nbsp;add &nbsp; &nbsp;%rax,%r8</span></div><div><span>&nbs=
p; </span></div><div><br></div><div><span>(gdb) list *kasan_check_range+0x1=
11</span></div><div><span>0xffffffff815643a1 is in kasan_check_range (mm/ka=
san/generic.c:85).</span></div><div><span>80</span></div><div><span>81 &nbs=
p; &nbsp; &nbsp;static __always_inline unsigned long bytes_is_nonzero(const=
 u8 *start,</span></div><div><span>82 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &n=
bsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; =
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;size_t size)</span></div><d=
iv><span>83 &nbsp; &nbsp; &nbsp;{</span></div><div><span>84 &nbsp; &nbsp; &=
nbsp; &nbsp; &nbsp; &nbsp; &nbsp;while (size) {</span></div><div><span>85 &=
nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;=
if (unlikely(*start))	&lt;&lt;&lt;&lt; start seems to not be mapped</span><=
/div><div><span>86 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; =
&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;return (unsigned long)start=
;</span></div><div><span>87 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp=
; &nbsp; &nbsp; &nbsp; &nbsp;start++;</span></div><div><span>88 &nbsp; &nbs=
p; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;size--;</s=
pan></div><div><span>89 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;}</=
span></div><span></span>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/_nwXMUNLOQOevscYZc-5BgcvpW52Ih6Af4oVUiey8_-0yw7fUwSM_B=
bdQGgenQSfOhiYoCJ8wxTxa_mxzmNyQnNUla3JkvCkJk8w7eMXg58%3D%40protonmail.com?u=
tm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgid/ka=
san-dev/_nwXMUNLOQOevscYZc-5BgcvpW52Ih6Af4oVUiey8_-0yw7fUwSM_BbdQGgenQSfOhi=
YoCJ8wxTxa_mxzmNyQnNUla3JkvCkJk8w7eMXg58%3D%40protonmail.com</a>.<br />

--b1_utKJACYrCNLsqvx4LZjKEuJkoUvzR4TwTzvC18quJ0--

