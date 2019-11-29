Return-Path: <kasan-dev+bncBCMIZB7QWENRB6FFQTXQKGQE2KLM63A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id B9F6D10D5CA
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 13:45:45 +0100 (CET)
Received: by mail-yb1-xb38.google.com with SMTP id c66sf20139835ybf.16
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 04:45:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575031544; cv=pass;
        d=google.com; s=arc-20160816;
        b=oxtCU1kLm7qlXRHuCpSgPlkvY45fNJkCrGZkaATjY8XClxThx8osLuLhp6YUxmWtjG
         JKl32/x0vVEpXc6p96HF7xAZWIFfzzXaZvG/uXKXN5qJvGZEoSbbniZN3lIa4MScfior
         hY+v/YPNG9lvbm4w5FogNjyDUWAjrDMEhCk0C+MkqHHYlfdT7ccxz1SEN9Lu4bp6gZBv
         BKH40NSacplitAs3nL/2P3D2Es8D1OgL6HjkjnlEtv0zMHqbMOyMkFdCWGb85JL319NH
         q5ywFnPwXf4eXD0wPu2xV7x5VcP0CYMoPqxY1NGPnzSxp/bGr+vmEE+2x4Y3oKabiWUR
         8Vcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=wZa9EshDLL48dVIP0148qWyNQj76wgwVN9pty1MP2YU=;
        b=rbyhcP93Sp9m0rcEaUZoTE8uDj4mGf4yAmbXloc+5edlKCnOzAyNAfsYLRqoxmvXYq
         y2IrB3ywlptVNopml2XbJijeY8mat256gfQZt89vBfJb4c977KzBnupGXeWfNiTeKcdq
         SbyIRV63DR2R7ZFclWpUChtMIrQgfTcqNqf1BtTFvqjSBWiwnZ/ghIlCP1qHCIyiN0pt
         NOk8DmJUMCwDfEEv4uwsYmmmky0W66VlH6rVNs2cKvsExpfECyYOMDLIJPiZxzJgjkGY
         YMhS+1U6LPeF+qL5bDnmclJftWEWNp7IRR5Qe5+M8aK85HTozbg99RB6Yg+jpvAYxzWo
         mIuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CJJJYOkM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wZa9EshDLL48dVIP0148qWyNQj76wgwVN9pty1MP2YU=;
        b=eNnLnuPXsihWPuMfpKQRW9bJOjh4CGDRlA40/9Ry+aIU80tXVtQnkePotL75NC8aKY
         sIH3TZ2Evrhrt+9KHPkute00BiAvszj+ymJZhLZKahFFs0cgrAQ+VptvGUv1DVoEZBtW
         cP4fHRu7kGrnXRet1JBTptFb/ziizrgpVfHxRkzM1yC1MN3lvyamKQLqMWzvpy8ZKnac
         wUOOyDhbjA2qoDl28X8AuQP1vLHSXNXdP94frwfwzeNb8oebiq0u61iVZITLinlIQKmp
         Iq9pO0a0MlseT9dl5ezGs9IBw7abB6Mdt/9N7qXFtm4HMH2+H7GpqEX4le71QyM27ORz
         e0sg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wZa9EshDLL48dVIP0148qWyNQj76wgwVN9pty1MP2YU=;
        b=Z14n2o9d7O0jIPbl/l8VwVw5nBegMXUmCfgQBBMHNLxTYorMd1uzwGJb809qc0SuC8
         oACPd9E51dZidzO9gku4KPE06VnwG6TndkqiNQHVXWntHU85i9Wna4aHS1shog7uLQDU
         CWblGbZcHUUEcbf4J2zunLdKGftNIYbb2Ao4qS778xmODSy+ny0vHBIWJhL14CKOn80A
         7avdxYYzArTOVy9Ebh5M3+4PiIWM92VOgFfyvARDFqFh1HVPuoHGIL5KDFAli8IqXWx9
         6w/lLJTd4CZnXjzjwUXRTB2Q61aY5L2zgJbfy49ysvKAouIXgzCAATd+HuYGiergl4RF
         DTYQ==
X-Gm-Message-State: APjAAAWKcZoDPn3KytPdQ9OuV4MWaZ2VNyzkdIjCjOBPralQsVf8E6Kh
	JEkBRpoa8haAnS0Fk9B5G7E=
X-Google-Smtp-Source: APXvYqxtUy4/NHBsgStHCjaQ288U5ytGDhiK3iI3i0FQfTK/nQouTa8+6hqyhgW8Jtk2UNVW08Qz5A==
X-Received: by 2002:a25:2f47:: with SMTP id v68mr8663755ybv.311.1575031544429;
        Fri, 29 Nov 2019 04:45:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:adcd:: with SMTP id d13ls5017704ybe.10.gmail; Fri, 29
 Nov 2019 04:45:44 -0800 (PST)
X-Received: by 2002:a25:bb87:: with SMTP id y7mr7066468ybg.473.1575031543949;
        Fri, 29 Nov 2019 04:45:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575031543; cv=none;
        d=google.com; s=arc-20160816;
        b=CZed1sPYGMC8tenh1knnE+Tshg4aGkGZqhKuvQsvV8VBY5UKxUqyIa/1Tg5jb1Jnv6
         ImVCyaM8UFn+j5vmPLfw8ak1yY5yOgBQiQFOimehFyls7n5+FKKS5AR2zupd/YMCufCB
         69hq+SxREWKD3lE0v2q3T+X7p6TQUQMW8AoFl8Auk6UYPe44f3L+FHxx42weqszCE8nW
         r6cLdsBTQ/AwVcPebC1YaGY+NOuAPwuXfL6OHPzsoLta1AEJF8mIJWIdyNyzS6c016Zq
         l2vtT1w61rL75GeN+fcUIasVYAdc7b3vRUnFn+rEa4W8pfx5oL3Kw+etI89l3KnrlXx0
         lzyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wx7NQBMKWHI+Zpf0YKVppXTB13KFXEE9ItlHNJ/fMPA=;
        b=N4E3+YeSHhJs9EcuXPASqW8xcWBN5RyOBdBsyVWccgMH1xW294kvYQTFl/sZ36PTLp
         PTvzmDzLPzvm32TJHAZCqgzRmWUb4nWgIaYv3vm/1VqXbifjDSAYk8Dk2KG2XLUYAp9l
         VEA4IXOHw1LRbX8ycqeuYi5cyuVHwJY3ibBcDynCklGkYLLhF8orPvPYOcHZV4unP6zs
         OApFhl+agH5UBXQzZ9w6WVKYyej/bQfI2ZPY1yGDSyPj0y2s51gQTNOBkoAtq7cVh2tn
         jAjPXHrQ5Z64A/2i7KJ6YTmfWf0Fe4zzbPfgZdcqNlx/3MNYUrsuN7Dc79+u3uZ9TQ+S
         g7eA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CJJJYOkM;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e43 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe43.google.com (mail-vs1-xe43.google.com. [2607:f8b0:4864:20::e43])
        by gmr-mx.google.com with ESMTPS id u17si251435ybu.1.2019.11.29.04.45.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 04:45:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e43 as permitted sender) client-ip=2607:f8b0:4864:20::e43;
Received: by mail-vs1-xe43.google.com with SMTP id y195so5652238vsy.5
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 04:45:43 -0800 (PST)
X-Received: by 2002:a67:5f81:: with SMTP id t123mr33094560vsb.240.1575031542911;
 Fri, 29 Nov 2019 04:45:42 -0800 (PST)
MIME-Version: 1.0
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net>
 <1573835765.5937.130.camel@lca.pw> <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
 <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com> <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
 <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
 <CACT4Y+Yog=PHF1SsLuoehr2rcbmfvLUW+dv7Vo+1RfdTOx7AUA@mail.gmail.com>
 <2297c356-0863-69ce-85b6-8608081295ed@virtuozzo.com> <CACT4Y+ZNAfkrE0M=eCHcmy2LhPG_kKbg4mOh54YN6Bgb4b3F5w@mail.gmail.com>
 <56cf8aab-c61b-156c-f681-d2354aed22bb@virtuozzo.com> <871rtqg91q.fsf@dja-thinkpad.axtens.net>
In-Reply-To: <871rtqg91q.fsf@dja-thinkpad.axtens.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Nov 2019 13:45:30 +0100
Message-ID: <CACT4Y+axv26RvEUYkhnOkt+0pgdxkSiMVKYNvswSXaGsQLxg7g@mail.gmail.com>
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real
 shadow memory
To: Daniel Axtens <dja@axtens.net>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Qian Cai <cai@lca.pw>, 
	kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, 
	"the arch/x86 maintainers" <x86@kernel.org>, Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	Christophe Leroy <christophe.leroy@c-s.fr>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, 
	Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CJJJYOkM;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::e43
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

On Fri, Nov 29, 2019 at 1:29 PM Daniel Axtens <dja@axtens.net> wrote:
> >>> Nope, it's vm_map_ram() not being handled
> >> Another suspicious one. Related to kasan/vmalloc?
> > Very likely the same as with ion:
> >
> > # git grep vm_map_ram|grep xfs
> > fs/xfs/xfs_buf.c:                * vm_map_ram() will allocate auxiliary structures (e.g.
> > fs/xfs/xfs_buf.c:                       bp->b_addr = vm_map_ram(bp->b_pages, bp->b_page_count,
>
> Aaargh, that's an embarassing miss.
>
> It's a bit intricate because kasan_vmalloc_populate function is
> currently set up to take a vm_struct not a vmap_area, but I'll see if I
> can get something simple out this evening - I'm away for the first part
> of next week.
>
> Do you have to do anything interesting to get it to explode with xfs? Is
> it as simple as mounting a drive and doing some I/O? Or do you need to
> do something more involved?

As simple as running syzkaller :)
with this config
https://github.com/google/syzkaller/blob/master/dashboard/config/upstream-kasan.config

> Regards,
> Daniel
>
> >
> >>
> >> BUG: unable to handle page fault for address: fffff52005b80000
> >> #PF: supervisor read access in kernel mode
> >> #PF: error_code(0x0000) - not-present page
> >> PGD 7ffcd067 P4D 7ffcd067 PUD 2cd10067 PMD 66d76067 PTE 0
> >> Oops: 0000 [#1] PREEMPT SMP KASAN
> >> CPU: 2 PID: 9211 Comm: syz-executor.2 Not tainted 5.4.0-next-20191129+ #6
> >> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
> >> rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
> >> RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
> >> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
> >> 30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
> >> 04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
> >> RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
> >> RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
> >> RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
> >> RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
> >> R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
> >> R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
> >> FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
> >> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> >> CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
> >> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> >> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> >> PKRU: 55555554
> >> Call Trace:
> >>  xfs_buf_ioend+0x228/0xdc0 fs/xfs/xfs_buf.c:1162
> >>  __xfs_buf_submit+0x38b/0xe50 fs/xfs/xfs_buf.c:1485
> >>  xfs_buf_submit fs/xfs/xfs_buf.h:268 [inline]
> >>  xfs_buf_read_uncached+0x15c/0x560 fs/xfs/xfs_buf.c:897
> >>  xfs_readsb+0x2d0/0x540 fs/xfs/xfs_mount.c:298
> >>  xfs_fc_fill_super+0x3e6/0x11f0 fs/xfs/xfs_super.c:1415
> >>  get_tree_bdev+0x444/0x620 fs/super.c:1340
> >>  xfs_fc_get_tree+0x1c/0x20 fs/xfs/xfs_super.c:1550
> >>  vfs_get_tree+0x8e/0x300 fs/super.c:1545
> >>  do_new_mount fs/namespace.c:2822 [inline]
> >>  do_mount+0x152d/0x1b50 fs/namespace.c:3142
> >>  ksys_mount+0x114/0x130 fs/namespace.c:3351
> >>  __do_sys_mount fs/namespace.c:3365 [inline]
> >>  __se_sys_mount fs/namespace.c:3362 [inline]
> >>  __x64_sys_mount+0xbe/0x150 fs/namespace.c:3362
> >>  do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
> >>  entry_SYSCALL_64_after_hwframe+0x49/0xbe
> >> RIP: 0033:0x46736a
> >> Code: 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f
> >> 84 00 00 00 00 00 0f 1f 44 00 00 49 89 ca b8 a5 00 00 00 0f 05 <48> 3d
> >> 01 f0 ff ff 73 01 c3 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48
> >> RSP: 002b:00007fb49bda8a78 EFLAGS: 00000202 ORIG_RAX: 00000000000000a5
> >> RAX: ffffffffffffffda RBX: 00007fb49bda8af0 RCX: 000000000046736a
> >> RDX: 00007fb49bda8ad0 RSI: 0000000020000140 RDI: 00007fb49bda8af0
> >> RBP: 00007fb49bda8ad0 R08: 00007fb49bda8b30 R09: 00007fb49bda8ad0
> >> R10: 0000000000000000 R11: 0000000000000202 R12: 00007fb49bda8b30
> >> R13: 00000000004b1c60 R14: 00000000004b006d R15: 00007fb49bda96bc
> >> Modules linked in:
> >> Dumping ftrace buffer:
> >>    (ftrace buffer empty)
> >> CR2: fffff52005b80000
> >> ---[ end trace eddd8949d4c898df ]---
> >> RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
> >> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
> >> 30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
> >> 04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
> >> RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
> >> RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
> >> RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
> >> RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
> >> R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
> >> R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
> >> FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
> >> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> >> CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
> >> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> >> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> >> PKRU: 55555554
> >>
> >
> > --
> > You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> > To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> > To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56cf8aab-c61b-156c-f681-d2354aed22bb%40virtuozzo.com.
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871rtqg91q.fsf%40dja-thinkpad.axtens.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Baxv26RvEUYkhnOkt%2B0pgdxkSiMVKYNvswSXaGsQLxg7g%40mail.gmail.com.
