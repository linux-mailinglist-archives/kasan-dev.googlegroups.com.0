Return-Path: <kasan-dev+bncBCMIFTP47IJBBSXZ3S3AMGQE5I3SNKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DB5696A4B4
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Sep 2024 18:43:56 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-71454420f65sf4527094b3a.1
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Sep 2024 09:43:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725381834; cv=pass;
        d=google.com; s=arc-20240605;
        b=g2+LZL4ssGMniD7H5EQHraAbLQd8OEprJ5tL1bSEZ7ERGJf2UZzli5YYg4p8r6w9nm
         AMuvSaL1VnfINGCCDGe51yqBTlAOvNu1bCE42OJljxa7IIH9rIC7MVNSS/Rk/Z89rc2w
         tfN09MzphaixLr1BYSWhVJJ5nNq4lcfEaGqBgJ+BDjdLimTOGdH2Yn4kA4RjKxTsxD3i
         sr60D/omDIriZ+rVJonW3nrAlmeVKJKafXq+gwO02XxGcuEc7bkNrt714K7RF1CPxK47
         feSTacXVp/4KreqlWO0BbmdyJj+lOcSVFiDQN01CRT4yiJrcJdDQ5C2wF4wHEaXaL8wp
         Qsng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:dkim-signature;
        bh=s7b1Om3aE3a8RchbDYdw1VUCvbSEbSmwg1LnW6/xb1U=;
        fh=J4TRUhxCd7sY5iwHkvrvsk0kBIM+Smb7WXuPfKGyW5s=;
        b=TUPCydoHHkOvLvmSbiWs7Z1bsplJOpjDk65m0r0w0WKMxOOVyyY1Wqh6u3N1DhL1XA
         MUQTG5lhlbyBPHbL7X/APwVmmLMoYt3LEaxZRgtDCgOnIUpTUC7YdioR05pNce9xW3+p
         R1gGM2siZy8nCSbuu5ilEsiyWZM9BjzsXMUN/v4d9SuC5e4m4qwsx6TTm+548AAhAiFw
         Q1y6N3QS7ePPjVdHcMLpwTckednCUpbqmghxqlbEvcZKsYt4d1etFoPPKEBN/Q/Votaf
         3EDdt2JdAVGlHCEDhnV0EXXzYDpXzDoMr+HVXZ3xf/q+t5xeGIghypq95HdNlfwFfMv8
         rSGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=as64zRUk;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725381834; x=1725986634; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :from:to:cc:subject:date:message-id:reply-to;
        bh=s7b1Om3aE3a8RchbDYdw1VUCvbSEbSmwg1LnW6/xb1U=;
        b=Q1M4cT7bKBNXLIKiQNv9I33EDQTz6RbE0UnpCtnq2EblgUd1f0XeBSKxqg16tXkCut
         iOApDF4DqIE3D/ifDSVEMUdIn/SjAZTcT+i7ZU1g31mSzRTQZOA+C1/CWUqepvwzbMko
         ggcI4CB6rvXkzEScfuyxItdBXCg6bnEVG1Z+3EK9TbpcbM5kANoJP+20kB3ikd3Kc9E2
         p8kll9tneM2toXQA0JqRfayZzH2AZFcZffiRCOChe9VZHNIvqdZHXJX5Mq/i1ZP59g0L
         lH2wJqC8RFbOzAbvJhljug/W8rnAN3Me6bhvRW111FzlGfQGlf/MslYrT+YCyMqVo4z+
         Rkfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725381834; x=1725986634;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=s7b1Om3aE3a8RchbDYdw1VUCvbSEbSmwg1LnW6/xb1U=;
        b=tDKsRV0AqJ3h5n0xA7HH0FAUnSxMXElT0TbJc1T8fXqTAujhpz3q8Dxpn1502C+U+U
         AZL+dpvnoNnhEucdmCbS3WnUBhV6cIibkj1TDN3XVZx9FTnB54e3CftOFKj85zZ4v2tA
         dZ/+uBJV8ymDh+3bTg4ol+Bc1LVRkNXr1BgySoam2C5K7PeidfJoCSWV5IAO5gXec+jv
         As7GTHtRjNQEvZJ7o4fHIzqedkX3sQfbMJvTdu9N1EAu5uagkLXV5Ke/FwSsZxsh0yWj
         Y5w/zx7WUFYKW2El1GR2sr9zIXe1n9dzEmYvREo2zISPbcpbrusB/CSjjUHcZao1+MLD
         a0kQ==
X-Forwarded-Encrypted: i=2; AJvYcCUIbTedb+s3jNKsNcavjtcmMugZ9IcuxsctMDFk5asIopMdzOkJ1Q43hCKKW1+0g5xMr2IKuQ==@lfdr.de
X-Gm-Message-State: AOJu0YwrEQdl0Wie/gzyZJxE3OMw0n0qwx3XLBi9uJs0FR/4VYBeHJ8x
	J6Xm04n/O+OTIZ2Bk/wwU2lpWXIDMCFo+3t079qS6vuPxCdCO7TU
X-Google-Smtp-Source: AGHT+IHqB4V08BpE4E+pG5IUxrtZKqsbH0efP9nWXPf1r4G/XoE6d+9eK8B6Kq+I8TuVV7dX6E0dPw==
X-Received: by 2002:a05:6a00:4fd4:b0:714:27b1:ae20 with SMTP id d2e1a72fcca58-7173fb74babmr11040266b3a.27.1725381834298;
        Tue, 03 Sep 2024 09:43:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1803:b0:70d:34f0:218c with SMTP id
 d2e1a72fcca58-715de43cf83ls3418878b3a.0.-pod-prod-05-us; Tue, 03 Sep 2024
 09:43:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXBs2Y86Q20doIPLWPihkua4rw9z9/cn1Zzwa+LJ8eey93OCTaq8wJIwEThQVKzhz569xMrxdUhZRs=@googlegroups.com
X-Received: by 2002:a05:6a20:d487:b0:1ca:edfc:8550 with SMTP id adf61e73a8af0-1cece5d1383mr13961853637.38.1725381832909;
        Tue, 03 Sep 2024 09:43:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725381832; cv=none;
        d=google.com; s=arc-20240605;
        b=SIfDGPp3Iilq1eIsX0SWcxOV1TxOiV4ddtqmsdXBzRz0TU0DLkWS2fe28d9ufAR4cI
         kRYrCiwpSst5BbHTSLwgLI/GahHlC6IPR54EldDkeC5OYPBkk1Vh7OVUb2aT7EX744s/
         aZS+CE8EA3Q2fAi9ZEAqGDz9mGnxEXK48e8P8xplPkBf5fqXcA0WtzLowwbpUz5oDlxc
         0O4yECoHLYZ1ise95fNh2y0DxmHXOsR333U7O6yRmPtAm4fYjFkmT32wUobN3i9Kn3vJ
         1svOt2wbi+pcV1BWcWDp+CNKZ1t1wV3evvNbqpl/UoSMQiHC36na0c4Pv/McCEUCUTZT
         jZ0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=BqvXA/3XZ5X8cHInUkHq4ej7Z/KzDFXPr58Ls+fV6i4=;
        fh=pdo3grNhdWIN/q/vuerE2RZZUaVvLJlop8ZRScrZiHw=;
        b=OV9I1qIKPyAkacNoi3WA/V/WO0/dogJb1ECNfAh+1/4RQIMCrbieeRSyI7U/8g4uqP
         q7lFbgqLPYL+a5Td/gbFV+SoFjuwC2hR5FxLZGxXm1BgWa5jcT18RijSE3Iu8s6pkvdQ
         rso1iBqEmVCJuXyvD39cvZeAVocDvgGHllLnhFe9cFWjaRmwJJnNEN4xUIignJI7aVk/
         H+cI+c5Jn0VFL76NwFZyMgTV55swpqik0D2tE6ITizJLPTzCLjf95Ha+gVEJwm5bMMVW
         2zXe6mLihBw9jbQqR8N2ApCn5nch7h+70cGr/JJG9ZAsXyXbDloCKXkP1pitIYNo2+i9
         zLyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=as64zRUk;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-io1-xd36.google.com (mail-io1-xd36.google.com. [2607:f8b0:4864:20::d36])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d8b26f6b31si273470a91.1.2024.09.03.09.43.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2024 09:43:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::d36 as permitted sender) client-ip=2607:f8b0:4864:20::d36;
Received: by mail-io1-xd36.google.com with SMTP id ca18e2360f4ac-82a151ac935so213375939f.3
        for <kasan-dev@googlegroups.com>; Tue, 03 Sep 2024 09:43:52 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWKJBsjxkbrdGnbEwhBAX555g46OYQfHfUELDNYyaaEiyu0TwMU6gs94so5KFIRd6yQXzugOBe4Dqs=@googlegroups.com
X-Received: by 2002:a05:6602:15c6:b0:82a:2cd4:a788 with SMTP id ca18e2360f4ac-82a37560e77mr1271578739f.15.1725381832025;
        Tue, 03 Sep 2024 09:43:52 -0700 (PDT)
Received: from [100.64.0.1] ([147.124.94.167])
        by smtp.gmail.com with ESMTPSA id 8926c6da1cb9f-4ced2de7825sm2781071173.63.2024.09.03.09.43.49
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Sep 2024 09:43:50 -0700 (PDT)
Message-ID: <d7a686a5-dfc8-4e26-8e4a-11f90fbf6d68@sifive.com>
Date: Tue, 3 Sep 2024 11:43:48 -0500
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [syzbot] [arm?] upstream test error: KASAN: invalid-access Write
 in setup_arch
To: Marc Zyngier <maz@kernel.org>, Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
 Aleksandr Nogikh <nogikh@google.com>, kasan-dev
 <kasan-dev@googlegroups.com>, Will Deacon <will@kernel.org>,
 syzbot <syzbot+908886656a02769af987@syzkaller.appspotmail.com>,
 catalin.marinas@arm.com, linux-arm-kernel@lists.infradead.org,
 linux-kernel@vger.kernel.org, syzkaller-bugs@googlegroups.com
References: <000000000000f362e80620e27859@google.com>
 <20240830095254.GA7769@willie-the-truck> <86wmjwvatn.wl-maz@kernel.org>
 <CANp29Y6EJXFTOy6Pd466r+RwzaGHe7JQMTaqMPSO2s7ubm-PKw@mail.gmail.com>
 <CAG_fn=UbWvN=FiXjU_QZKm_qDhxU8dZQ4fgELXsRsPCj4YHp9A@mail.gmail.com>
 <86seugvi25.wl-maz@kernel.org>
Content-Language: en-US
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
In-Reply-To: <86seugvi25.wl-maz@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=as64zRUk;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::d36 as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

On 2024-09-03 11:05 AM, Marc Zyngier wrote:
> On Tue, 03 Sep 2024 16:39:28 +0100,
> Alexander Potapenko <glider@google.com> wrote:
>>
>> On Mon, Sep 2, 2024 at 12:03=E2=80=AFPM 'Aleksandr Nogikh' via kasan-dev
>> <kasan-dev@googlegroups.com> wrote:
>>>
>>> +kasan-dev
>>>
>>> On Sat, Aug 31, 2024 at 7:53=E2=80=AFPM 'Marc Zyngier' via syzkaller-bu=
gs
>>> <syzkaller-bugs@googlegroups.com> wrote:
>>>>
>>>> On Fri, 30 Aug 2024 10:52:54 +0100,
>>>> Will Deacon <will@kernel.org> wrote:
>>>>>
>>>>> On Fri, Aug 30, 2024 at 01:35:24AM -0700, syzbot wrote:
>>>>>> Hello,
>>>>>>
>>>>>> syzbot found the following issue on:
>>>>>>
>>>>>> HEAD commit:    33faa93bc856 Merge branch kvmarm-master/next into kv=
marm-m..
>>>>>> git tree:       git://git.kernel.org/pub/scm/linux/kernel/git/kvmarm=
/kvmarm.git fuzzme
>>>>>
>>>>> +Marc, as this is his branch.
>>>>>
>>>>>> console output: https://syzkaller.appspot.com/x/log.txt?x=3D1398420b=
980000
>>>>>> kernel config:  https://syzkaller.appspot.com/x/.config?x=3D2b7b31c9=
aa1397ca
>>>>>> dashboard link: https://syzkaller.appspot.com/bug?extid=3D908886656a=
02769af987
>>>>>> compiler:       gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils =
for Debian) 2.40
>>>>>> userspace arch: arm64
>>>>
>>>> As it turns out, this isn't specific to this branch. I can reproduce
>>>> it with this config on a vanilla 6.10 as a KVM guest. Even worse,
>>>> compiling with clang results in an unbootable kernel (without any
>>>> output at all).
>>>>
>>>> Mind you, the binary is absolutely massive (130MB with gcc, 156MB with
>>>> clang), and I wouldn't be surprised if we were hitting some kind of
>>>> odd limit.
>>>>
>>>>>>
>>>>>> Downloadable assets:
>>>>>> disk image (non-bootable): https://storage.googleapis.com/syzbot-ass=
ets/384ffdcca292/non_bootable_disk-33faa93b.raw.xz
>>>>>> vmlinux: https://storage.googleapis.com/syzbot-assets/9093742fcee9/v=
mlinux-33faa93b.xz
>>>>>> kernel image: https://storage.googleapis.com/syzbot-assets/b1f599907=
931/Image-33faa93b.gz.xz
>>>>>>
>>>>>> IMPORTANT: if you fix the issue, please add the following tag to the=
 commit:
>>>>>> Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
>>>>>>
>>>>>> Booting Linux on physical CPU 0x0000000000 [0x000f0510]
>>>>>> Linux version 6.11.0-rc5-syzkaller-g33faa93bc856 (syzkaller@syzkalle=
r) (gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) #=
0 SMP PREEMPT now
>>>>>> random: crng init done
>>>>>> Machine model: linux,dummy-virt
>>>>>> efi: UEFI not found.
>>>>>> NUMA: No NUMA configuration found
>>>>>> NUMA: Faking a node at [mem 0x0000000040000000-0x00000000bfffffff]
>>>>>> NUMA: NODE_DATA [mem 0xbfc1d340-0xbfc20fff]
>>>>>> Zone ranges:
>>>>>>   DMA      [mem 0x0000000040000000-0x00000000bfffffff]
>>>>>>   DMA32    empty
>>>>>>   Normal   empty
>>>>>>   Device   empty
>>>>>> Movable zone start for each node
>>>>>> Early memory node ranges
>>>>>>   node   0: [mem 0x0000000040000000-0x00000000bfffffff]
>>>>>> Initmem setup node 0 [mem 0x0000000040000000-0x00000000bfffffff]
>>>>>> cma: Reserved 32 MiB at 0x00000000bba00000 on node -1
>>>>>> psci: probing for conduit method from DT.
>>>>>> psci: PSCIv1.1 detected in firmware.
>>>>>> psci: Using standard PSCI v0.2 function IDs
>>>>>> psci: Trusted OS migration not required
>>>>>> psci: SMC Calling Convention v1.0
>>>>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>>>> BUG: KASAN: invalid-access in smp_build_mpidr_hash arch/arm64/kernel=
/setup.c:133 [inline]
>>>>>> BUG: KASAN: invalid-access in setup_arch+0x984/0xd60 arch/arm64/kern=
el/setup.c:356
>>>>>> Write of size 4 at addr 03ff800086867e00 by task swapper/0
>>>>>> Pointer tag: [03], memory tag: [fe]
>>>>>>
>>>>>> CPU: 0 UID: 0 PID: 0 Comm: swapper Not tainted 6.11.0-rc5-syzkaller-=
g33faa93bc856 #0
>>>>>> Hardware name: linux,dummy-virt (DT)
>>>>>> Call trace:
>>>>>>  dump_backtrace+0x204/0x3b8 arch/arm64/kernel/stacktrace.c:317
>>>>>>  show_stack+0x2c/0x3c arch/arm64/kernel/stacktrace.c:324
>>>>>>  __dump_stack lib/dump_stack.c:93 [inline]
>>>>>>  dump_stack_lvl+0x260/0x3b4 lib/dump_stack.c:119
>>>>>>  print_address_description mm/kasan/report.c:377 [inline]
>>>>>>  print_report+0x118/0x5ac mm/kasan/report.c:488
>>>>>>  kasan_report+0xc8/0x108 mm/kasan/report.c:601
>>>>>>  kasan_check_range+0x94/0xb8 mm/kasan/sw_tags.c:84
>>>>>>  __hwasan_store4_noabort+0x20/0x2c mm/kasan/sw_tags.c:149
>>>>>>  smp_build_mpidr_hash arch/arm64/kernel/setup.c:133 [inline]
>>>>>>  setup_arch+0x984/0xd60 arch/arm64/kernel/setup.c:356
>>>>>>  start_kernel+0xe0/0xff0 init/main.c:926
>>>>>>  __primary_switched+0x84/0x8c arch/arm64/kernel/head.S:243
>>>>>>
>>>>>> The buggy address belongs to stack of task swapper/0
>>>>>>
>>>>>> Memory state around the buggy address:
>>>>>>  ffff800086867c00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
>>>>>>  ffff800086867d00: 00 fe fe 00 00 00 fe fe fe fe fe fe fe fe fe fe
>>>>>>> ffff800086867e00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
>>>>>>                    ^
>>>>>>  ffff800086867f00: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
>>>>>>  ffff800086868000: fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe fe
>>>>>> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
>>>>>
>>>>> I can't spot the issue here. We have a couple of fixed-length
>>>>> (4 element) arrays on the stack and they're indexed by a simple loop
>>>>> counter that runs from 0-3.
>>>>
>>>> Having trimmed the config to the extreme, I can only trigger the
>>>> warning with CONFIG_KASAN_SW_TAGS (CONFIG_KASAN_GENERIC does not
>>>> scream). Same thing if I use gcc 14.2.0.
>>>>
>>>> However, compiling with clang 14 (Debian clang version 14.0.6) does
>>>> *not* result in a screaming kernel, even with KASAN_SW_TAGS.
>>>>
>>>> So I can see two possibilities here:
>>>>
>>>> - either gcc is incompatible with KASAN_SW_TAGS and the generic
>>>>   version is the only one that works
>>>>
>>>> - or we have a compiler bug on our hands.
>>>>
>>>> Frankly, I can't believe the later, as the code is so daft that I
>>>> can't imagine gcc getting it *that* wrong.
>>>>
>>>> Who knows enough about KASAN to dig into this?
>>
>> This looks related to Samuel's "arm64: Fix KASAN random tag seed
>> initialization" patch that landed in August.
>=20
> f75c235565f9 arm64: Fix KASAN random tag seed initialization
>=20
> $ git describe --contains f75c235565f9 --match=3Dv\*
> v6.11-rc4~15^2
>=20
> So while this is in -rc4, -rc6 still has the same issue (with GCC --
> clang is OK).

I wouldn't expect it to be related to my patch. smp_build_mpidr_hash() gets
called before kasan_init_sw_tags() both before and after applying my patch.

Since the variable in question is a stack variable, the random tag is gener=
ated
by GCC, not the kernel function.

Since smp_build_mpidr_hash() is inlined into setup_arch(), which also calls
kasan_init(), maybe the issue is that GCC tries to allocate the local varia=
ble
and write the tag to shadow memory before kasan_init() actually sets up the
shadow memory?

Regards,
Samuel

>> I am a bit surprised the bug is reported before the
>> "KernelAddressSanitizer initialized" banner is printed - I thought we
>> shouldn't be reporting anything until the tool is fully initialized.
>=20
> Specially if this can report false positives...
>=20
> Thanks,
>=20
> 	M.
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/d7a686a5-dfc8-4e26-8e4a-11f90fbf6d68%40sifive.com.
