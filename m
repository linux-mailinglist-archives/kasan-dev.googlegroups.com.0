Return-Path: <kasan-dev+bncBDQ27FVWWUFRBDUSULXQKGQEIOU5AEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id D3040113ADD
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 05:35:27 +0100 (CET)
Received: by mail-pj1-x103d.google.com with SMTP id s3sf1100841pji.18
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Dec 2019 20:35:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575520526; cv=pass;
        d=google.com; s=arc-20160816;
        b=SP3S50ekGqI+adIWLeECkdyezU+BCBK/U8vwzm0dibb2sra/eYxRe9SSCVBhsQQ5X9
         ePLd18LS+EbPxkRIWfkKVvArOy/s78fZ1rtIxMdVrOae1SXVDOmAfU6skf/XMVKMyfcJ
         XxVTqY/5yqabK+SSTpaopeBYVk/K0ddlBMIStz0UoC4sr17oIIaP3tInTxaCejhwLwE+
         Wxlc9n+19Ua+QJbe5CceOFiRvIFk8n0INJoH3snJmsv8ID4P3aJpQTXM3oRKgtZUQj5I
         +m4yXEYbwDQpCJFjY7JEG4/KLDpSbAdlGNMxAUNxAldsCkOZdLAWWMDI1ujz5lIONGfd
         xm6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=m0tHc+odUMQ5mngcA0JiY0RyF2m4vxwio1q/Z850xw8=;
        b=mUUJLdjgDm+tA7H9bdMXlPvAjL70LruXaAJRmme3MPr6hxz77+1asg/ftnR5bLLGwz
         acLT16UctamvXtPsYe/Qwecb7PILg0+93wSR6P3tZaGlR58wdxNqzMCrMdZdJwLY6EKf
         OgqAPCL+qgvBuo5Nn/E6MFB8wVn/58IgTafId/DTLjewd82zWqVSWnUr0wlMVhs9KKK2
         qa2cuF25aSL5qq8eyC6FKqkoiqv0/PFi/7H3nEPoKW6Y3owui4sfEmiHhBjVqzkJt5xb
         mqHp45eiWWyVcmwvnRKauMuZLjILCu3/ZinYOi7HvYTTSmiqkHKOQG2Bo5RlOmrdt3tQ
         5VXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HTnzmMsS;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m0tHc+odUMQ5mngcA0JiY0RyF2m4vxwio1q/Z850xw8=;
        b=Jd/67ytyi+ulaE4DNNTq6CmutwWsaESCje8ntMylNbjn7sL3ihq3bqFG5tPhd/IVNR
         d3F/uU79NA4r7ei3HdASonYQPiWVziNkHG8Z3PL5DiLSjy44fMpVkUv9ED51xmbY8Sre
         FRq4WSUA6PNQQjapPe9qBxM3C3pPmqH/A3x6jrxmvdaH/bQ4g89fnCKTDBp4byaIjZAh
         cKIbaWG37xTgDozXdMCu6UNUwAhfnztMe10wX0aFsUINUexU6gnIO8PzKCxBB+mWgycX
         vF0IeMWXDiBuGHz0c084pTSObz5DA162Q/wc5Vvh3QgMr9ZtpflcZQKJOk5fqunXgTY1
         Gpvw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m0tHc+odUMQ5mngcA0JiY0RyF2m4vxwio1q/Z850xw8=;
        b=L35jP7l7LHJzTRJXjYtnkjN58OWYoKeabVbAbVSn1l6xiBJDgimbqPn5AM/poI6Qem
         jaZhFOpNaLqFK/IFROzRpdjFlYmLxbDYpYmGmN11o4rCaoB1yAReEZWVxNwvwNrEm9Nq
         SOtCsobqWB5Cr7niERktEpqVD8dTCYLHJPyA//sODzGfjP30wQqHiFgeoA8NkyYIUyby
         Ffq5oVIZ9BKMVUXBUUIqf3YDxLijoIev/CRMg68PlCTEjlyS4yojXLZ0wttalXCqTQC8
         vCxpwixL1NBT6ILJYdFVon2LjzoSEp9+5kVW374ZPFfwcS6vpB+2mZC/7lS8hKixiLVS
         bGxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU8T0Pr7mVjifLRwOI0wRHtYH351X7vDOCfEMLBiI8gZdK2ZM1J
	/idNSv7MB+cbUicJGy/1W00=
X-Google-Smtp-Source: APXvYqz9bWKOFT+GwtTIBqXd+n7DfNdi5cfmC5Em40Bjp/BSQzD4Xeyz7oak8Pi4ZvRO3CuUEhJHNA==
X-Received: by 2002:a63:d66:: with SMTP id 38mr7195628pgn.233.1575520526102;
        Wed, 04 Dec 2019 20:35:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:160b:: with SMTP id 11ls509413pfw.7.gmail; Wed, 04 Dec
 2019 20:35:25 -0800 (PST)
X-Received: by 2002:a63:cd06:: with SMTP id i6mr7459488pgg.48.1575520525603;
        Wed, 04 Dec 2019 20:35:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575520525; cv=none;
        d=google.com; s=arc-20160816;
        b=nlFnmWkIblFC31T6nuY8tuKuOJz2LOcu64N3gny+Sxgf/8Vg5K/wE0vm0r5MD7RO+F
         +8q2pFS2ZvlGvgofmtRJBYVgpuz/srlKC/Abh7fDGme5PGRCz1Rh33XjIhhRQlUa0gm6
         UxVjdSjReuB46RggNhv77uY910qaenpP1T8bYbJxKfOUTKqvnYCFrdkSAzP60jE7r8s9
         s1wDmunxtWYVPkCC6GDaSS9sbBWHQ5/NpZTi1LMQl+G+A9FLZA8ApoWWgTHn/ZEU9Dvs
         zyAIZB8hHQL0e3X1NU5g+AyNhSZY88dM9k7Vn16voMIK0BVibYXAgqRbAn8oxjHRE5RK
         oLIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=s6emKmGGeuSq3wtIVxjBKVR6ZpCN8AX3rs92e/sQ08s=;
        b=VF6DzQgUUbMErIDYq9A8Bjl8zr7j9tynZJifqlQ1mZGmXShR41PV37dil3Rrz5BMbA
         9ZL/sZtKphpd+HAd1jwZ6jiqMZJHhIagPH8qzaHmpAC4/qzMeJ9LayIur6hzW0iGDCJM
         LBuzGf6Xid45fZpmWZ5s5QTCNnW3YyvSKQIKjrIR9gGs5oWnrJLnsrh5GZufCCYZaTVB
         EGhzCx5aJroE3b8cKXY2CTY9+8B0uXEopHJHW1nzkf0LMHLqJUm3yQGist5U7LbyoW67
         Gp+VPQhHHFKdcrQYmahU52ks1a/V/v/An+C6yp6N7jEukIyAvDpdu7ovVJwOTzi/7iS6
         yTxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=HTnzmMsS;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id 17si276906pjb.2.2019.12.04.20.35.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Dec 2019 20:35:25 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id h13so698881plr.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Dec 2019 20:35:25 -0800 (PST)
X-Received: by 2002:a17:90a:bb0b:: with SMTP id u11mr7305972pjr.12.1575520525179;
        Wed, 04 Dec 2019 20:35:25 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-7daa-d2ea-7edb-cfe8.static.ipv6.internode.on.net. [2001:44b8:1113:6700:7daa:d2ea:7edb:cfe8])
        by smtp.gmail.com with ESMTPSA id c184sm10147599pfa.39.2019.12.04.20.35.23
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 04 Dec 2019 20:35:24 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Dmitry Vyukov <dvyukov@google.com>, syzbot <syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrii Nakryiko <andriin@fb.com>, Alexei Starovoitov <ast@kernel.org>, bpf <bpf@vger.kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Martin KaFai Lau <kafai@fb.com>, LKML <linux-kernel@vger.kernel.org>, netdev <netdev@vger.kernel.org>, Song Liu <songliubraving@fb.com>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Yonghong Song <yhs@fb.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>
Subject: Re: BUG: unable to handle kernel paging request in pcpu_alloc
In-Reply-To: <CACT4Y+ZTXKP0MAT3ivr5HO-skZOjSVdz7RbDoyc522_Nbk8nKQ@mail.gmail.com>
References: <000000000000314c120598dc69bd@google.com> <CACT4Y+ZTXKP0MAT3ivr5HO-skZOjSVdz7RbDoyc522_Nbk8nKQ@mail.gmail.com>
Date: Thu, 05 Dec 2019 15:35:21 +1100
Message-ID: <877e3be6eu.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=HTnzmMsS;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

>> HEAD commit:    1ab75b2e Add linux-next specific files for 20191203
>> git tree:       linux-next
>> console output: https://syzkaller.appspot.com/x/log.txt?x=10edf2eae00000
>> kernel config:  https://syzkaller.appspot.com/x/.config?x=de1505c727f0ec20
>> dashboard link: https://syzkaller.appspot.com/bug?extid=82e323920b78d54aaed5
>> compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
>> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=156ef061e00000
>> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=11641edae00000
>>
>> IMPORTANT: if you fix the bug, please add the following tag to the commit:
>> Reported-by: syzbot+82e323920b78d54aaed5@syzkaller.appspotmail.com
>
> +Daniel, is it the same as:
> https://syzkaller.appspot.com/bug?id=f6450554481c55c131cc23d581fbd8ea42e63e18
> If so, is it possible to make KASAN detect this consistently with the
> same crash type so that syzbot does not report duplicates?

It looks like both of these occur immediately after failure injection. I
think my assumption that I could ignore the chance of failures in the
per-cpu allocation path will have to be revisited. That's annoying.

I'll try to spin something today but Andrey feel free to pip me at the
post again :)

I'm not 100% confident to call them dups just yet, but I'm about 80%
confident that they are.

Regards,
Daniel
>
>> RDX: 000000000000003c RSI: 0000000020000080 RDI: 0c00000000000000
>> RBP: 0000000000000000 R08: 0000000000000002 R09: 0000000000000000
>> R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000018
>> R13: 0000000000000004 R14: 0000000000000005 R15: 0000000000000000
>> BUG: unable to handle page fault for address: fffff91ffff00000
>> #PF: supervisor read access in kernel mode
>> #PF: error_code(0x0000) - not-present page
>> PGD 21ffe6067 P4D 21ffe6067 PUD aa56c067 PMD aa56d067 PTE 0
>> Oops: 0000 [#1] PREEMPT SMP KASAN
>> CPU: 1 PID: 8999 Comm: syz-executor865 Not tainted
>> 5.4.0-next-20191203-syzkaller #0
>> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
>> Google 01/01/2011
>> RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
>> RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
>> RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
>> RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
>> RIP: 0010:check_memory_region+0x9c/0x1a0 mm/kasan/generic.c:192
>> Code: c9 4d 0f 49 c1 49 c1 f8 03 45 85 c0 0f 84 10 01 00 00 41 83 e8 01 4e
>> 8d 44 c0 08 eb 0d 48 83 c0 08 4c 39 c0 0f 84 a7 00 00 00 <48> 83 38 00 74
>> ed 4c 8d 40 08 eb 09 48 83 c0 01 49 39 c0 74 53 80
>> RSP: 0018:ffffc90001f67a80 EFLAGS: 00010216
>> RAX: fffff91ffff00000 RBX: fffff91ffff01000 RCX: ffffffff819e1589
>> RDX: 0000000000000001 RSI: 0000000000008000 RDI: ffffe8ffff800000
>> RBP: ffffc90001f67a98 R08: fffff91ffff01000 R09: 0000000000001000
>> R10: fffff91ffff00fff R11: ffffe8ffff807fff R12: fffff91ffff00000
>> R13: 0000000000008000 R14: 0000000000000000 R15: ffff88821fffd100
>> FS:  00000000011a7880(0000) GS:ffff8880ae900000(0000) knlGS:0000000000000000
>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> CR2: fffff91ffff00000 CR3: 00000000a94ad000 CR4: 00000000001406e0
>> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>> Call Trace:
>>   memset+0x24/0x40 mm/kasan/common.c:107
>>   memset include/linux/string.h:410 [inline]
>>   pcpu_alloc+0x589/0x1380 mm/percpu.c:1734
>>   __alloc_percpu_gfp+0x28/0x30 mm/percpu.c:1783
>>   bpf_array_alloc_percpu kernel/bpf/arraymap.c:35 [inline]
>>   array_map_alloc+0x698/0x7d0 kernel/bpf/arraymap.c:159
>>   find_and_alloc_map kernel/bpf/syscall.c:123 [inline]
>>   map_create kernel/bpf/syscall.c:654 [inline]
>>   __do_sys_bpf+0x478/0x3810 kernel/bpf/syscall.c:3012
>>   __se_sys_bpf kernel/bpf/syscall.c:2989 [inline]
>>   __x64_sys_bpf+0x73/0xb0 kernel/bpf/syscall.c:2989
>>   do_syscall_64+0xfa/0x790 arch/x86/entry/common.c:294
>>   entry_SYSCALL_64_after_hwframe+0x49/0xbe
>> RIP: 0033:0x442f99
>> Code: e8 ec 09 03 00 48 83 c4 18 c3 0f 1f 80 00 00 00 00 48 89 f8 48 89 f7
>> 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff
>> ff 0f 83 cb 08 fc ff c3 66 2e 0f 1f 84 00 00 00 00
>> RSP: 002b:00007ffc8aa156d8 EFLAGS: 00000246 ORIG_RAX: 0000000000000141
>> RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 0000000000442f99
>> RDX: 000000000000003c RSI: 0000000020000080 RDI: 0c00000000000000
>> RBP: 0000000000000000 R08: 0000000000000002 R09: 0000000000000000
>> R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000018
>> R13: 0000000000000004 R14: 0000000000000005 R15: 0000000000000000
>> Modules linked in:
>> CR2: fffff91ffff00000
>> ---[ end trace 449f8b43dad6ffb8 ]---
>> RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
>> RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
>> RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
>> RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
>> RIP: 0010:check_memory_region+0x9c/0x1a0 mm/kasan/generic.c:192
>> Code: c9 4d 0f 49 c1 49 c1 f8 03 45 85 c0 0f 84 10 01 00 00 41 83 e8 01 4e
>> 8d 44 c0 08 eb 0d 48 83 c0 08 4c 39 c0 0f 84 a7 00 00 00 <48> 83 38 00 74
>> ed 4c 8d 40 08 eb 09 48 83 c0 01 49 39 c0 74 53 80
>> RSP: 0018:ffffc90001f67a80 EFLAGS: 00010216
>> RAX: fffff91ffff00000 RBX: fffff91ffff01000 RCX: ffffffff819e1589
>> RDX: 0000000000000001 RSI: 0000000000008000 RDI: ffffe8ffff800000
>> RBP: ffffc90001f67a98 R08: fffff91ffff01000 R09: 0000000000001000
>> R10: fffff91ffff00fff R11: ffffe8ffff807fff R12: fffff91ffff00000
>> R13: 0000000000008000 R14: 0000000000000000 R15: ffff88821fffd100
>> FS:  00000000011a7880(0000) GS:ffff8880ae900000(0000) knlGS:0000000000000000
>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> CR2: fffff91ffff00000 CR3: 00000000a94ad000 CR4: 00000000001406e0
>> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>>
>>
>> ---
>> This bug is generated by a bot. It may contain errors.
>> See https://goo.gl/tpsmEJ for more information about syzbot.
>> syzbot engineers can be reached at syzkaller@googlegroups.com.
>>
>> syzbot will keep track of this bug report. See:
>> https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
>> syzbot can test patches for this bug, for details see:
>> https://goo.gl/tpsmEJ#testing-patches
>>
>> --
>> You received this message because you are subscribed to the Google Groups "syzkaller-bugs" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to syzkaller-bugs+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/syzkaller-bugs/000000000000314c120598dc69bd%40google.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/877e3be6eu.fsf%40dja-thinkpad.axtens.net.
