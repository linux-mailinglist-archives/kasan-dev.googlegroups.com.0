Return-Path: <kasan-dev+bncBCMIZB7QWENRBVOXTXXQKGQEIF7X6NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9B8B911244D
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 09:18:30 +0100 (CET)
Received: by mail-il1-x13b.google.com with SMTP id v11sf5267219ilg.6
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 00:18:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575447509; cv=pass;
        d=google.com; s=arc-20160816;
        b=X6+8JAU1w7QntwARcdIb4WFitDn/TQ84Wtv0CKGo+AZdPlGoaoiPW23cOFUEoacTLK
         t0560xET+fT8IDdSc2uK/RkDhsFFAzBDCzLT2+oqlV56+zRLUxFRio+aQyU1YYtulbUq
         bIXK7bSRDxXPKyUOL2CG01A5XXyIPsRelNzBKGIowPkru8x7zEXL+GIB/DbXuKSf5HHi
         0i26f6qgizA70ZqW1xdaJwGpmVFVQ4jHXGUWNVabM2QLEHVyOb2qDNz/8XZ1DJmKuPak
         4vHQYqJgbZ26Jd5Qm/VJfF4mDiTi1O7tigZVEmEcg2pkmP63DqwFDXcGRHM5JFaNRWq9
         dSrA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=X6NTq7oBuMbuFEwa9ERkF8q+w5MNYlicZh3iX4hJ9UM=;
        b=pBtoMfmL1jEyJhc+skn2HWxJvSQw+zcun/f9OoC0YuciFnEn7KtlpQ4jkC0Y1HjINM
         W41+LucyD3wT7dDNo7hxIYOQ1bbyVoeP5ZPCsoV7crbreEGL6GLzkuB0Kocv9m9PoGTx
         67CsE6vJryTepOuBISBVSQYEY62X+1WDdvDlnY3TIk9Qx+t2MiFougUizKHW3DH7p2Qd
         wLpJSX6V5GWLz40E0zURK20+op5PvA2gwWO3bKOgb5RGdWp47BzJgPSH80ORn6w311W5
         TLwDVVlMahsZ8dhx23QLoaqXtIDOrEdnVJ8BghbrYiYJpmXf6iGiZ6o56RL4OcQrm9YW
         P+kg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bNmjEXsL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X6NTq7oBuMbuFEwa9ERkF8q+w5MNYlicZh3iX4hJ9UM=;
        b=kpYUCWOnlKHkPIW/xR6mZW4PXh1bXRZBAZxi88NdF+msndFs0Sx5T2bzbyoqU4y/Ci
         +1FZR95RYIisnNDWsL5V3gKaOvZBtWLXfIt8KBE/yWCFEE3P0WCH6cGfS5ADwbAAD5e/
         xGCZeXBmAB8ObGj+5diI+MyBztlb+Fe0YR4OlTCIcqYhKp7fw+fOOcsh+HuJ8MNxFJFT
         wwnSsp+vQwTfujOJrzClbbo2qEvso4yoiPGaQ5r2L/aWBhVcCgAjpzxBZ6eKvjNnNvjY
         ZIqL1z230i22C80ES0ZnGll0O4Zlouyf2Z/RZoUlwudCkXqBZGFneOwv/zNZ464xJSKN
         Bx8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=X6NTq7oBuMbuFEwa9ERkF8q+w5MNYlicZh3iX4hJ9UM=;
        b=P6NWNkzeu19oLsG0f8eWJAgF04oU3zOyz879Og/JSjRqA4krQmkc5pHi9Dfstq8J4R
         nTMl/af3KWWCeL2t/BnPsygr71TRVFXllZB3JuBbEKJPuO3KLWnVH15aZ6csDOslx5OJ
         HDDLjtCahfFOX5KqafmfJXS5055uJhhjOY5yc3cAoBL1KUkp1nL9brfaOlzaA8Ae4jqG
         ynKw6UX4PWCFrzxvGEwozRiuRAb4NXibjGU0mdpC+UPT7JY8l24YNShv7IAoteCngyZj
         VuSoyY03HlRwBELWj5fcedtJOcgYS4V6KZ/u/ViXlEPJTkEpUeAbN8MpCH9UmzII2nHZ
         TpYw==
X-Gm-Message-State: APjAAAUbudwv9XXCT7Ha2YjoSOf/8CzFss68eW5hgqb0TwJAmMdkA/ku
	CyIDbMZpSLl1rPG5J01dkUg=
X-Google-Smtp-Source: APXvYqyhwOH05Hw5hMUEfAgXEInD2HDgMu8VKOyT/GsRhlAw0+QXGRQjpH6yg74OFmRXcuV2f9TSEA==
X-Received: by 2002:a02:cca4:: with SMTP id t4mr1770545jap.57.1575447509073;
        Wed, 04 Dec 2019 00:18:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9ecd:: with SMTP id s74ls1061068ilk.15.gmail; Wed, 04
 Dec 2019 00:18:28 -0800 (PST)
X-Received: by 2002:a92:35dd:: with SMTP id c90mr2356625ilf.257.1575447508759;
        Wed, 04 Dec 2019 00:18:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575447508; cv=none;
        d=google.com; s=arc-20160816;
        b=PuMXOAUdxE9V/OYl8Q2gMQHKqdhxvLxwyrZ69MgO/URbo1rLCnuBS1wi1A3vxkLlWr
         bKD3YOPJ3JQTfS7F2i+daINcT5HYiFh1DscW0qNdD/HBmDu4BgnpzrDdtXlkijn0+5uI
         XsvIOAYcMqhii/iYIvUsiY/t0qrvbA/ZCM3jaGkZG9+doCCg8tduBIocjfwv68rCcbyS
         NEQCvGiNuwnUPbs2LAzx6Zg8iN8ByvkjJ1FsQSCSsJNoQ0ALzKa8em6SzKvv3uZfhmO2
         K568+884FK7TQqOegad+w4i6XXw81GSrMV4OMe8czFCSOiBkDc/MiRvEDLLE5fJMYLo7
         +IFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IOrpunYOl9f5imurR4iaLW0MWbzeDjpl3e51EdkQBxM=;
        b=arjn0jtx1rmu4UnJBBEB9kahAl6pMw8U/0I6YsGCm4KwabPj4z5JCLgyYkiWHz4O6E
         ghNrDWl7529CNhFGu9yXjwH4K/G+CJB6T0+9BL2alP4KzJ2T8nR68lfK8OgJyUe5Tx90
         6q9jrh/OVEtQKo1OIxCimC3ClDouF65hxoDlWflVpfjGD99pWSiqXUYNM7NGF7Z0ZDpN
         mD/zbc8MHjFMGlIS4hbJxAlQsE3yg02j4L62hbuLdXK5Z5Ce8ocrZzv7nmxXmEjfOWgA
         s7OYJX27nbTaZ5WDjqQZb397K7MAXJ9j/ZA/fgSQJloEXmvOs6YMG42hhE9GDZbCB6f1
         1AYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bNmjEXsL;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf43.google.com (mail-qv1-xf43.google.com. [2607:f8b0:4864:20::f43])
        by gmr-mx.google.com with ESMTPS id g10si341868ilb.2.2019.12.04.00.18.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Dec 2019 00:18:28 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43 as permitted sender) client-ip=2607:f8b0:4864:20::f43;
Received: by mail-qv1-xf43.google.com with SMTP id y8so2710426qvk.6
        for <kasan-dev@googlegroups.com>; Wed, 04 Dec 2019 00:18:28 -0800 (PST)
X-Received: by 2002:a0c:c125:: with SMTP id f34mr1555482qvh.22.1575447507606;
 Wed, 04 Dec 2019 00:18:27 -0800 (PST)
MIME-Version: 1.0
References: <000000000000314c120598dc69bd@google.com>
In-Reply-To: <000000000000314c120598dc69bd@google.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Dec 2019 09:18:16 +0100
Message-ID: <CACT4Y+ZTXKP0MAT3ivr5HO-skZOjSVdz7RbDoyc522_Nbk8nKQ@mail.gmail.com>
Subject: Re: BUG: unable to handle kernel paging request in pcpu_alloc
To: syzbot <syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Daniel Axtens <dja@axtens.net>
Cc: Andrii Nakryiko <andriin@fb.com>, Alexei Starovoitov <ast@kernel.org>, bpf <bpf@vger.kernel.org>, 
	Daniel Borkmann <daniel@iogearbox.net>, Martin KaFai Lau <kafai@fb.com>, LKML <linux-kernel@vger.kernel.org>, 
	netdev <netdev@vger.kernel.org>, Song Liu <songliubraving@fb.com>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Yonghong Song <yhs@fb.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bNmjEXsL;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f43
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

On Wed, Dec 4, 2019 at 9:15 AM syzbot
<syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following crash on:
>
> HEAD commit:    1ab75b2e Add linux-next specific files for 20191203
> git tree:       linux-next
> console output: https://syzkaller.appspot.com/x/log.txt?x=10edf2eae00000
> kernel config:  https://syzkaller.appspot.com/x/.config?x=de1505c727f0ec20
> dashboard link: https://syzkaller.appspot.com/bug?extid=82e323920b78d54aaed5
> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=156ef061e00000
> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=11641edae00000
>
> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com

+Daniel, is it the same as:
https://syzkaller.appspot.com/bug?id=f6450554481c55c131cc23d581fbd8ea42e63e18
If so, is it possible to make KASAN detect this consistently with the
same crash type so that syzbot does not report duplicates?


> RDX: 000000000000003c RSI: 0000000020000080 RDI: 0c00000000000000
> RBP: 0000000000000000 R08: 0000000000000002 R09: 0000000000000000
> R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000018
> R13: 0000000000000004 R14: 0000000000000005 R15: 0000000000000000
> BUG: unable to handle page fault for address: fffff91ffff00000
> #PF: supervisor read access in kernel mode
> #PF: error_code(0x0000) - not-present page
> PGD 21ffe6067 P4D 21ffe6067 PUD aa56c067 PMD aa56d067 PTE 0
> Oops: 0000 [#1] PREEMPT SMP KASAN
> CPU: 1 PID: 8999 Comm: syz-executor865 Not tainted
> 5.4.0-next-20191203-syzkaller #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> Google 01/01/2011
> RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
> RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
> RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
> RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
> RIP: 0010:check_memory_region+0x9c/0x1a0 mm/kasan/generic.c:192
> Code: c9 4d 0f 49 c1 49 c1 f8 03 45 85 c0 0f 84 10 01 00 00 41 83 e8 01 4e
> 8d 44 c0 08 eb 0d 48 83 c0 08 4c 39 c0 0f 84 a7 00 00 00 <48> 83 38 00 74
> ed 4c 8d 40 08 eb 09 48 83 c0 01 49 39 c0 74 53 80
> RSP: 0018:ffffc90001f67a80 EFLAGS: 00010216
> RAX: fffff91ffff00000 RBX: fffff91ffff01000 RCX: ffffffff819e1589
> RDX: 0000000000000001 RSI: 0000000000008000 RDI: ffffe8ffff800000
> RBP: ffffc90001f67a98 R08: fffff91ffff01000 R09: 0000000000001000
> R10: fffff91ffff00fff R11: ffffe8ffff807fff R12: fffff91ffff00000
> R13: 0000000000008000 R14: 0000000000000000 R15: ffff88821fffd100
> FS:  00000000011a7880(0000) GS:ffff8880ae900000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffff91ffff00000 CR3: 00000000a94ad000 CR4: 00000000001406e0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> Call Trace:
>   memset+0x24/0x40 mm/kasan/common.c:107
>   memset include/linux/string.h:410 [inline]
>   pcpu_alloc+0x589/0x1380 mm/percpu.c:1734
>   __alloc_percpu_gfp+0x28/0x30 mm/percpu.c:1783
>   bpf_array_alloc_percpu kernel/bpf/arraymap.c:35 [inline]
>   array_map_alloc+0x698/0x7d0 kernel/bpf/arraymap.c:159
>   find_and_alloc_map kernel/bpf/syscall.c:123 [inline]
>   map_create kernel/bpf/syscall.c:654 [inline]
>   __do_sys_bpf+0x478/0x3810 kernel/bpf/syscall.c:3012
>   __se_sys_bpf kernel/bpf/syscall.c:2989 [inline]
>   __x64_sys_bpf+0x73/0xb0 kernel/bpf/syscall.c:2989
>   do_syscall_64+0xfa/0x790 arch/x86/entry/common.c:294
>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> RIP: 0033:0x442f99
> Code: e8 ec 09 03 00 48 83 c4 18 c3 0f 1f 80 00 00 00 00 48 89 f8 48 89 f7
> 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff
> ff 0f 83 cb 08 fc ff c3 66 2e 0f 1f 84 00 00 00 00
> RSP: 002b:00007ffc8aa156d8 EFLAGS: 00000246 ORIG_RAX: 0000000000000141
> RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 0000000000442f99
> RDX: 000000000000003c RSI: 0000000020000080 RDI: 0c00000000000000
> RBP: 0000000000000000 R08: 0000000000000002 R09: 0000000000000000
> R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000018
> R13: 0000000000000004 R14: 0000000000000005 R15: 0000000000000000
> Modules linked in:
> CR2: fffff91ffff00000
> ---[ end trace 449f8b43dad6ffb8 ]---
> RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
> RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
> RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
> RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
> RIP: 0010:check_memory_region+0x9c/0x1a0 mm/kasan/generic.c:192
> Code: c9 4d 0f 49 c1 49 c1 f8 03 45 85 c0 0f 84 10 01 00 00 41 83 e8 01 4e
> 8d 44 c0 08 eb 0d 48 83 c0 08 4c 39 c0 0f 84 a7 00 00 00 <48> 83 38 00 74
> ed 4c 8d 40 08 eb 09 48 83 c0 01 49 39 c0 74 53 80
> RSP: 0018:ffffc90001f67a80 EFLAGS: 00010216
> RAX: fffff91ffff00000 RBX: fffff91ffff01000 RCX: ffffffff819e1589
> RDX: 0000000000000001 RSI: 0000000000008000 RDI: ffffe8ffff800000
> RBP: ffffc90001f67a98 R08: fffff91ffff01000 R09: 0000000000001000
> R10: fffff91ffff00fff R11: ffffe8ffff807fff R12: fffff91ffff00000
> R13: 0000000000008000 R14: 0000000000000000 R15: ffff88821fffd100
> FS:  00000000011a7880(0000) GS:ffff8880ae900000(0000) knlGS:0000000000000000
> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> CR2: fffff91ffff00000 CR3: 00000000a94ad000 CR4: 00000000001406e0
> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>
>
> ---
> This bug is generated by a bot. It may contain errors.
> See https://goo.gl/tpsmEJ for more information about syzbot.
> syzbot engineers can be reached at syzkaller@googlegroups.com.
>
> syzbot will keep track of this bug report. See:
> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> syzbot can test patches for this bug, for details see:
> https://goo.gl/tpsmEJ#testing-patches
>
> --
> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/000000000000314c120598dc69bd%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZTXKP0MAT3ivr5HO-skZOjSVdz7RbDoyc522_Nbk8nKQ%40mail.gmail.com.
