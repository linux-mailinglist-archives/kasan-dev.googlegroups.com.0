Return-Path: <kasan-dev+bncBC5L5P75YUERB3UNQTXQKGQEJH3RHMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1A2B910D53A
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 12:54:23 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id k14sf5500187ljh.14
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 03:54:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575028462; cv=pass;
        d=google.com; s=arc-20160816;
        b=mAjXwFrzSlmi72hAUHLbiupKR4ZuCIG8It3ODn3wLgOZE0CULKJtvt468P5pQKj6o0
         ZfvTLWwXAeClCLS+hlGMpvX0jh2jlRip8zygszprm4Mm2u6mK/wLUcOQQL2E0gwI/OtZ
         AvW5ubRtF63JJ70ggDupjb6NpXwOmgedIRHWIoTqNZ1N4RNBASf9REhsehgfGmJHCo5+
         bMhHg6E1eDqQGnrU782kQje5UiBu8WB/Db6Vvf9/UY2sPBjcC4iqPO8wY824g8Akw9Gb
         8VJOclPo0lFISFPVsKpdidck4W9FegnSTF8uZDG+Qljxj4hY8VdlNErc3JZXWL72m66/
         Qdiw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=UEQZ6iJixqv6U/3w65YxMoo3LqxPqjXujhiGoeUigRM=;
        b=EGBtGnX8ju52YbK2W/jL/x/wZJCVCULTHSvjUniEwwI2cT+V14t5jfpQCKmSEwmHng
         Qh9U/YvJxD+8wu4j6ZY4PYcpEYMqmE5CtvLNuMsStSoJOLPGn85/tzOI8Ra3qkEBY2FW
         9ZmtiTBC09N351QQ5ZsyK8HWgolUyp2SiHu0nv9knjHzdwIMW3L5ucC464p8bz1WeAp0
         s3mLCXGh+S0xmR4cHqSUXUozGdLu5kYFVbc+dRfoBBcV/yrxnjRdOIKdqMGZYn9N7gz6
         toq5xpQQIaQABlZwoepUgha6wkw+eonCyrvcV7VoKJ5M2fQVuImmc8qFAvfsVLojETJi
         qBTw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=UEQZ6iJixqv6U/3w65YxMoo3LqxPqjXujhiGoeUigRM=;
        b=kD73ypPxqQ5F91F4PpIwbZAJZXgQfSnbh45Wf+4glkLcQKJtpxFitP0VV/MNqRCcMy
         EtY7OGwQaCMLbfARKtnqefvzyoYfotS3Sq/fiNVzhwY3aXtQOYVIvqAY/tdGwchSztv1
         NMwGJyIUxxRbx9I5ESffKUa58iiUkfeFoYSQ+zFkWhfnhMim+IKpP9DMoThg5olYAFem
         BB74WZ3Ehv6+5dsplLEubI2x3SWuliVvu7RKudmcT+6KLwy55+Tt/87n88Jd4OyMM8Pm
         SiWxX0L7tCvWrnJTXgwITqOZuzide9C/3dMWFdctIeS0RcZAASC5G7G52sCyC1qB660T
         jXeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=UEQZ6iJixqv6U/3w65YxMoo3LqxPqjXujhiGoeUigRM=;
        b=gf3KRs6HRVZ9IXcHAMDaHlWBICH1wvv28m1Ydvyb6YUbQpb31u2rA7erO5VWtzYIOv
         4cHiqdtjmtJJxG4ITFdJfntvvEZYtx46AxQtyf7MF3bNe+vD0/UeCGs5FsKFbQorH/hy
         nK6bw0W6aoiV5LArlpLkWFqysY1orKSRGftge/qGFoOIx/Zt2NcDgmsjWEOza7Clgfo+
         rnNnkHq4PPCpz1CW6xZIWKMCCkZ7pr6nXDzu0/8jOp0SiJ/qTD5ReXQK8A1Z0LMF5dAn
         GKoR4+HhGSXefAW/qnSBi6cQ8YHd2tWSNAUULkHEp+SJ5AMjqUD3lCWUZoZChRRy0OGq
         sTvQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUl/4P5pTPwBkLjgySCInExIFcE2MW67yfofpJT74eObXY6P1KN
	zw9eQ99cQMnWfPwtLQ4o8f0=
X-Google-Smtp-Source: APXvYqyZEwHEbwIjA+J8MbhZVNaJzwsF5zeYWpynEJxYB6qFtiP8IABZk6Wv7ZF8ZyUhadRSWNEVfg==
X-Received: by 2002:a05:651c:1059:: with SMTP id x25mr38148450ljm.255.1575028462647;
        Fri, 29 Nov 2019 03:54:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:c4:: with SMTP id 4ls4191286ljr.6.gmail; Fri, 29
 Nov 2019 03:54:22 -0800 (PST)
X-Received: by 2002:a2e:9e97:: with SMTP id f23mr37630751ljk.89.1575028462143;
        Fri, 29 Nov 2019 03:54:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575028462; cv=none;
        d=google.com; s=arc-20160816;
        b=EBHXSkzif+SY1tHFWr7GBVLxwJFUgKc5vr2+9sSvq3LBb1NGe6SMA3tjue6P/nz6EO
         P1bOX1kul4hVYiKJ7eTy+z7FoVml5Tc64Z62+V5G/imrxyoLyYOG+5SgpvxjF7y6Be5X
         w/Kc4P/VT2kHGNu6dVzUzcL3JDl8jtjOQDUEDGPwmGn3CwstQf/KvYQ71/sNbE/bxz7F
         gN+C6VYW2W6+3Q+gsgm1xA7Z35FnAsx8P7eWkXHBi5KbsdYNNX0+rw4LRDvhw249hehh
         C1rv3SNJE2z2Dw1Pb43+1mcCcPRuoKKvMw8DtJ6P1C25qo5e3DZ8QZvXN6PGkqkorFgh
         7NnQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=EpTt5h2xe7Qr8bkLZFpPYO9S15dsBvWy8lId4Sjp+O8=;
        b=msJOGNocXj1skOJHNummHUuYZ4GSgemmKET7B+Ns/2NgDKdGzUoUkLV3P+OKdkxyGW
         cRxj9nlLBYcC+awVe106ESnR4MOZMTgSzkgiGsT1y1Cc3V/k9KmL2qUASG5TTDlYy0X/
         89gE8sOdsRHY4LSF+9Lrx3qDA1JHyJaVkiTrQOfsOdcFdao/HbOe/uO7vHT7BbngPi5C
         m51biFOIOzvln4ZPyDxAn/qkRk2cO3Pc7rw6G7dZZ9CVeM1Y59WZ/YBBSwMkoDaULxZV
         NxsTbENHmBEeTJsSQV5Bb4KbRJTdSjjbqR4hA2De8ctT0ocpiPkUchv9Kqzha12gdhEA
         cNBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
Received: from relay.sw.ru (relay.sw.ru. [185.231.240.75])
        by gmr-mx.google.com with ESMTPS id o193si307023lff.4.2019.11.29.03.54.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Nov 2019 03:54:22 -0800 (PST)
Received-SPF: pass (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as permitted sender) client-ip=185.231.240.75;
Received: from dhcp-172-16-25-5.sw.ru ([172.16.25.5])
	by relay.sw.ru with esmtp (Exim 4.92.3)
	(envelope-from <aryabinin@virtuozzo.com>)
	id 1iaeqZ-0002Up-5S; Fri, 29 Nov 2019 14:54:03 +0300
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real
 shadow memory
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Daniel Axtens <dja@axtens.net>, Qian Cai <cai@lca.pw>,
 kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
 the arch/x86 maintainers <x86@kernel.org>,
 Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>,
 Christophe Leroy <christophe.leroy@c-s.fr>,
 linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
 Vasily Gorbik <gor@linux.ibm.com>
References: <20191031093909.9228-1-dja@axtens.net>
 <20191031093909.9228-2-dja@axtens.net> <1573835765.5937.130.camel@lca.pw>
 <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
 <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com>
 <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
 <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
 <CACT4Y+Yog=PHF1SsLuoehr2rcbmfvLUW+dv7Vo+1RfdTOx7AUA@mail.gmail.com>
 <2297c356-0863-69ce-85b6-8608081295ed@virtuozzo.com>
 <CACT4Y+ZNAfkrE0M=eCHcmy2LhPG_kKbg4mOh54YN6Bgb4b3F5w@mail.gmail.com>
From: Andrey Ryabinin <aryabinin@virtuozzo.com>
Message-ID: <56cf8aab-c61b-156c-f681-d2354aed22bb@virtuozzo.com>
Date: Fri, 29 Nov 2019 14:53:49 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.2.2
MIME-Version: 1.0
In-Reply-To: <CACT4Y+ZNAfkrE0M=eCHcmy2LhPG_kKbg4mOh54YN6Bgb4b3F5w@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: aryabinin@virtuozzo.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of aryabinin@virtuozzo.com designates 185.231.240.75 as
 permitted sender) smtp.mailfrom=aryabinin@virtuozzo.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=virtuozzo.com
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



On 11/29/19 2:47 PM, Dmitry Vyukov wrote:
> On Fri, Nov 29, 2019 at 12:38 PM Andrey Ryabinin
> <aryabinin@virtuozzo.com> wrote:
>>>>>
>>>>>
>>>>> Not sure if it's the same or not. Is it addressed by something in flight?
>>>>>
>>>>> My config:
>>>>> https://gist.githubusercontent.com/dvyukov/36c7be311fdec9cd51c649f7c3cb2ddb/raw/39c6f864fdd0ffc53f0822b14c354a73c1695fa1/gistfile1.txt
>>>>
>>>>
>>>> I've tried this fix for pcpu_get_vm_areas:
>>>> https://groups.google.com/d/msg/kasan-dev/t_F2X1MWKwk/h152Z3q2AgAJ
>>>> and it helps. But this will break syzbot on linux-next soon.
>>>
>>>
>>> Can this be related as well?
>>> Crashes on accesses to shadow on the ion memory...
>>
>> Nope, it's vm_map_ram() not being handled
> 
> 
> Another suspicious one. Related to kasan/vmalloc?

Very likely the same as with ion:

# git grep vm_map_ram|grep xfs
fs/xfs/xfs_buf.c:                * vm_map_ram() will allocate auxiliary structures (e.g.
fs/xfs/xfs_buf.c:                       bp->b_addr = vm_map_ram(bp->b_pages, bp->b_page_count,
 
> 
> BUG: unable to handle page fault for address: fffff52005b80000
> #PF: supervisor read access in kernel mode
> #PF: error_code(0x0000) - not-present page
> PGD 7ffcd067 P4D 7ffcd067 PUD 2cd10067 PMD 66d76067 PTE 0
> Oops: 0000 [#1] PREEMPT SMP KASAN
> CPU: 2 PID: 9211 Comm: syz-executor.2 Not tainted 5.4.0-next-20191129+ #6
> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
> rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
> RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
> 30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
> 04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
> RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
> RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
> RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
> RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
> R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
> R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
> FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> PKRU: 55555554
> Call Trace:
>  xfs_buf_ioend+0x228/0xdc0 fs/xfs/xfs_buf.c:1162
>  __xfs_buf_submit+0x38b/0xe50 fs/xfs/xfs_buf.c:1485
>  xfs_buf_submit fs/xfs/xfs_buf.h:268 [inline]
>  xfs_buf_read_uncached+0x15c/0x560 fs/xfs/xfs_buf.c:897
>  xfs_readsb+0x2d0/0x540 fs/xfs/xfs_mount.c:298
>  xfs_fc_fill_super+0x3e6/0x11f0 fs/xfs/xfs_super.c:1415
>  get_tree_bdev+0x444/0x620 fs/super.c:1340
>  xfs_fc_get_tree+0x1c/0x20 fs/xfs/xfs_super.c:1550
>  vfs_get_tree+0x8e/0x300 fs/super.c:1545
>  do_new_mount fs/namespace.c:2822 [inline]
>  do_mount+0x152d/0x1b50 fs/namespace.c:3142
>  ksys_mount+0x114/0x130 fs/namespace.c:3351
>  __do_sys_mount fs/namespace.c:3365 [inline]
>  __se_sys_mount fs/namespace.c:3362 [inline]
>  __x64_sys_mount+0xbe/0x150 fs/namespace.c:3362
>  do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
>  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> RIP: 0033:0x46736a
> Code: 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f
> 84 00 00 00 00 00 0f 1f 44 00 00 49 89 ca b8 a5 00 00 00 0f 05 <48> 3d
> 01 f0 ff ff 73 01 c3 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48
> RSP: 002b:00007fb49bda8a78 EFLAGS: 00000202 ORIG_RAX: 00000000000000a5
> RAX: ffffffffffffffda RBX: 00007fb49bda8af0 RCX: 000000000046736a
> RDX: 00007fb49bda8ad0 RSI: 0000000020000140 RDI: 00007fb49bda8af0
> RBP: 00007fb49bda8ad0 R08: 00007fb49bda8b30 R09: 00007fb49bda8ad0
> R10: 0000000000000000 R11: 0000000000000202 R12: 00007fb49bda8b30
> R13: 00000000004b1c60 R14: 00000000004b006d R15: 00007fb49bda96bc
> Modules linked in:
> Dumping ftrace buffer:
>    (ftrace buffer empty)
> CR2: fffff52005b80000
> ---[ end trace eddd8949d4c898df ]---
> RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
> 30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
> 04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
> RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
> RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
> RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
> RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
> R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
> R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
> FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> PKRU: 55555554
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56cf8aab-c61b-156c-f681-d2354aed22bb%40virtuozzo.com.
