Return-Path: <kasan-dev+bncBDQ27FVWWUFRBNU6QTXQKGQERYM4JCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id EBD3C10D5AD
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 13:29:43 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id s14sf24724936ila.0
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 04:29:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575030582; cv=pass;
        d=google.com; s=arc-20160816;
        b=KWhdswv+qim3fuRN5ImuMpsZpoE60nSwQT7LTY9MA2M63CFJgZj/Ek2j7LfGxcNyC/
         4A3M/RbuuqAf+lYpjZU/78dFX6TbEOOhQHXAXpUBzjaNUx8cDK/OgoW/xK52MIZ45Nv6
         OQOx+xGgdG1idyJRvs+TulJv8P2VXlFk6Igl0Q/33H9P2tJKrmLa3QhgyQn3gZoyPBQn
         ErqErrYMwO6ePZDutB8mGfoxXKrKKmiqaxk1pPm2jIkuLQC6BlPpLHjaCrpyRMj7Gppy
         JjoSc8wiVdz/dvkiSVS4lhzB3CdTGHD0FAu9AZsoDv6AN/vplKupCdAfNixQc8SfaTSQ
         DcBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=kjtkiAdtxuGS7IHLPtcjGBcjzs4h1lz8gWW8kbaHR50=;
        b=ERcZi5u5Fsgh2GJWPW4rrownM7nReJyDitWvycd1/Te1tH5byMYpBfnPxB9HAIrCV/
         VMdtjz0hn2jVDPa8jpzqqIpO2BvKJqe4JaQHb3U626H0Bow0784dRhjpCNIiLJPeOOH2
         RgL5u3yumMLkgvs0UNr5KcmkCCirVYJLhueXIzEXUYM6BwixfOrTihGIVOAroQWMEVQb
         fuUvvg1LvCsyhz2hVxWJs3lwILGFY4XrFxsGRFKOPv7zvQWejSPDfTU1unMdCssfojqB
         bGryDtvbUmpFoQkRY20XuC+qCDehJMWNGqKXK0lzszfXdE9FmNiFf5arRhRo+BV9+Lu8
         2Lqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=SNCyuNH+;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kjtkiAdtxuGS7IHLPtcjGBcjzs4h1lz8gWW8kbaHR50=;
        b=fR839u0QeDpBybJC0+SOFFEoYtD7pyE61UUqbJPa8Ri91t0Ffd6UXlqxyqfr0YKSgj
         rRkAQp2HLaDUG3iedDGkZPye/qUbe0V3JZRSW+Or5kdiIztsPgEBe9WYfb9Yjl2q2sC+
         Db00WpxMe9euT52SEiQqTO2dpvGowtrbYiwkUf0qiuzXNzA8bYabMZ+B82DKl28vPzPw
         5VdlqwF01sP7T2a/bAToN/0zQ/gUpVMdtWAcUnMMZCZcne66qfGHO7VMRhs/8SDiYkgI
         Eqni9FS22sZ45HJI5W72NpDA2kc43Rwgz40xiTJzIT9LUQTvb5SeEEkbZ2iaR/0NQh7w
         zXmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kjtkiAdtxuGS7IHLPtcjGBcjzs4h1lz8gWW8kbaHR50=;
        b=JCJuYIP4IOxVX3LyXbhByQ9LHgH0eOFGVPtSY1DwP6puPuLcpVQdPLPRjV7N6Q3dr7
         bl2sx/8bS8snR1GL54jzvq3sFoXFWlUtTi1jEJPdnvG3+NiRGpMIpx39T3RmD+ENMDS4
         jIFDiSUPrBpaMSzGJzLe+B9kIg7JPfdaC80B/5oO2pxHKvhADpo2rad9M1NbencGU93D
         vlbOT8zMsh/SrsmphEPcSwq6xcUOMRbphS0+ESRKbD+yD/7uYHcKhu1hax8wYNmuNbEu
         ydVbbln2w0xvlex7uF4kO/IIS9W+8f04e6ufASPaE27ull8hBu07LM2hm2j5+EeG+VSj
         YGAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXMUkLTI34LZuTstIo0i3bZuxHo+KybUXCO3+qCM6o/GyayN7dv
	4lSbAUyuV0o+2dDBLNN5cYA=
X-Google-Smtp-Source: APXvYqx9q2ssunvoFR0eSdy/q1pjl5dcrMewKVnRlxZRpsDwrJyX/qgS1BhIqe1q+Inybge2NjoZRQ==
X-Received: by 2002:a02:b385:: with SMTP id p5mr7834520jan.43.1575030582361;
        Fri, 29 Nov 2019 04:29:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:960e:: with SMTP id a14ls4447162ioq.11.gmail; Fri, 29
 Nov 2019 04:29:41 -0800 (PST)
X-Received: by 2002:a5d:9602:: with SMTP id w2mr42129614iol.34.1575030581921;
        Fri, 29 Nov 2019 04:29:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575030581; cv=none;
        d=google.com; s=arc-20160816;
        b=bvdHusRB1PIMIRFH6VXXI6R49eUHwLKUBLJg2D+ZHsfpYFQAcuK/4A19SrnE9O9fVz
         /7Qdp8Eb7HpaAcdG+xmUbjpBkpzz3Jmn85lAtNckZtel2pPwi4jS1Sa7o5lCn5Ns4cC0
         m1xxobJdc+K1n+k2Zi4hzqClCviJ1LiGyhf5xbbhMmxVP2pMRsn0gaJnjhLEXexiZByT
         kf7VRxXcovGH7WESW8YYYdVwzjcX+ohtuodv+PWLiCJyF67kUoQq5jh5Noqe9vVT5eFv
         xuiFcDBz+gnjtBna32kK1cTPjVPGSqeavz4wcfyqsrYuqAQBuJ9cWIlk0uoCQ479ZPRd
         CCgQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=lnTkdY6JVf48jCKaReWad7d/qEHhWQwMJZ+Le786aD8=;
        b=ljbdcD9A89xSjuKbf4oUw4DQVAf1WDdVpW5Tq4VWH211SbepMLgajLTYq4MH1Xpm10
         0mOoFlTzfBLNfe5alPocQS0Q/a8JfBV2D+t2VLnGxmjCKwvBYSN5D8BXOAT+WIfPsZyF
         iBHdFoQrsiXlcfJCeW/bhGNk2Y+CCTRQ3Lyt+5iPxYtzM83BAu5sUVMqLIouS/MGjvJm
         OhnUkhxABLmaTFkwR68JkpymCEfURYcP5Y+QxkhkX10lCOpchrpeYgBhf+u5euD+ICOA
         npRaLiuxLZwWfO8o67+Add/u6rh8yX7t7PjyooIRvgutQk5GavAg0ft1RCvK0ZKjxeba
         RNsQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=SNCyuNH+;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id g10si747672ilb.2.2019.11.29.04.29.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 04:29:41 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id x28so14586117pfo.6
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 04:29:41 -0800 (PST)
X-Received: by 2002:a65:66d7:: with SMTP id c23mr13939244pgw.40.1575030581240;
        Fri, 29 Nov 2019 04:29:41 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-4092-39f5-bb9d-b59a.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:4092:39f5:bb9d:b59a])
        by smtp.gmail.com with ESMTPSA id b7sm14724610pjo.3.2019.11.29.04.29.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Nov 2019 04:29:40 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>
Cc: Qian Cai <cai@lca.pw>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, the arch/x86 maintainers <x86@kernel.org>, Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, Christophe Leroy <christophe.leroy@c-s.fr>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, Vasily Gorbik <gor@linux.ibm.com>
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <56cf8aab-c61b-156c-f681-d2354aed22bb@virtuozzo.com>
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net> <1573835765.5937.130.camel@lca.pw> <871ru5hnfh.fsf@dja-thinkpad.axtens.net> <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com> <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com> <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com> <CACT4Y+Yog=PHF1SsLuoehr2rcbmfvLUW+dv7Vo+1RfdTOx7AUA@mail.gmail.com> <2297c356-0863-69ce-85b6-8608081295ed@virtuozzo.com> <CACT4Y+ZNAfkrE0M=eCHcmy2LhPG_kKbg4mOh54YN6Bgb4b3F5w@mail.gmail.com> <56cf8aab-c61b-156c-f681-d2354aed22bb@virtuozzo.com>
Date: Fri, 29 Nov 2019 23:29:37 +1100
Message-ID: <871rtqg91q.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=SNCyuNH+;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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


>>> Nope, it's vm_map_ram() not being handled
>> 
>> 
>> Another suspicious one. Related to kasan/vmalloc?
>
> Very likely the same as with ion:
>
> # git grep vm_map_ram|grep xfs
> fs/xfs/xfs_buf.c:                * vm_map_ram() will allocate auxiliary structures (e.g.
> fs/xfs/xfs_buf.c:                       bp->b_addr = vm_map_ram(bp->b_pages, bp->b_page_count,

Aaargh, that's an embarassing miss.

It's a bit intricate because kasan_vmalloc_populate function is
currently set up to take a vm_struct not a vmap_area, but I'll see if I
can get something simple out this evening - I'm away for the first part
of next week.

Do you have to do anything interesting to get it to explode with xfs? Is
it as simple as mounting a drive and doing some I/O? Or do you need to
do something more involved?

Regards,
Daniel

>  
>> 
>> BUG: unable to handle page fault for address: fffff52005b80000
>> #PF: supervisor read access in kernel mode
>> #PF: error_code(0x0000) - not-present page
>> PGD 7ffcd067 P4D 7ffcd067 PUD 2cd10067 PMD 66d76067 PTE 0
>> Oops: 0000 [#1] PREEMPT SMP KASAN
>> CPU: 2 PID: 9211 Comm: syz-executor.2 Not tainted 5.4.0-next-20191129+ #6
>> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
>> rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
>> RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
>> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
>> 30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
>> 04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
>> RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
>> RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
>> RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
>> RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
>> R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
>> R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
>> FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
>> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>> PKRU: 55555554
>> Call Trace:
>>  xfs_buf_ioend+0x228/0xdc0 fs/xfs/xfs_buf.c:1162
>>  __xfs_buf_submit+0x38b/0xe50 fs/xfs/xfs_buf.c:1485
>>  xfs_buf_submit fs/xfs/xfs_buf.h:268 [inline]
>>  xfs_buf_read_uncached+0x15c/0x560 fs/xfs/xfs_buf.c:897
>>  xfs_readsb+0x2d0/0x540 fs/xfs/xfs_mount.c:298
>>  xfs_fc_fill_super+0x3e6/0x11f0 fs/xfs/xfs_super.c:1415
>>  get_tree_bdev+0x444/0x620 fs/super.c:1340
>>  xfs_fc_get_tree+0x1c/0x20 fs/xfs/xfs_super.c:1550
>>  vfs_get_tree+0x8e/0x300 fs/super.c:1545
>>  do_new_mount fs/namespace.c:2822 [inline]
>>  do_mount+0x152d/0x1b50 fs/namespace.c:3142
>>  ksys_mount+0x114/0x130 fs/namespace.c:3351
>>  __do_sys_mount fs/namespace.c:3365 [inline]
>>  __se_sys_mount fs/namespace.c:3362 [inline]
>>  __x64_sys_mount+0xbe/0x150 fs/namespace.c:3362
>>  do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
>>  entry_SYSCALL_64_after_hwframe+0x49/0xbe
>> RIP: 0033:0x46736a
>> Code: 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f
>> 84 00 00 00 00 00 0f 1f 44 00 00 49 89 ca b8 a5 00 00 00 0f 05 <48> 3d
>> 01 f0 ff ff 73 01 c3 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48
>> RSP: 002b:00007fb49bda8a78 EFLAGS: 00000202 ORIG_RAX: 00000000000000a5
>> RAX: ffffffffffffffda RBX: 00007fb49bda8af0 RCX: 000000000046736a
>> RDX: 00007fb49bda8ad0 RSI: 0000000020000140 RDI: 00007fb49bda8af0
>> RBP: 00007fb49bda8ad0 R08: 00007fb49bda8b30 R09: 00007fb49bda8ad0
>> R10: 0000000000000000 R11: 0000000000000202 R12: 00007fb49bda8b30
>> R13: 00000000004b1c60 R14: 00000000004b006d R15: 00007fb49bda96bc
>> Modules linked in:
>> Dumping ftrace buffer:
>>    (ftrace buffer empty)
>> CR2: fffff52005b80000
>> ---[ end trace eddd8949d4c898df ]---
>> RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
>> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
>> 30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
>> 04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
>> RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
>> RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
>> RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
>> RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
>> R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
>> R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
>> FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>> CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
>> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>> PKRU: 55555554
>> 
>
> -- 
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56cf8aab-c61b-156c-f681-d2354aed22bb%40virtuozzo.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/871rtqg91q.fsf%40dja-thinkpad.axtens.net.
