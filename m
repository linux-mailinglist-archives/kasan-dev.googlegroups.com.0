Return-Path: <kasan-dev+bncBCMIZB7QWENRB3MKQTXQKGQEMPMVW3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id C1D1110D527
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 12:47:59 +0100 (CET)
Received: by mail-pf1-x439.google.com with SMTP id a13sf17909769pfi.23
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 03:47:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575028077; cv=pass;
        d=google.com; s=arc-20160816;
        b=MTyN4vcjeO/aV3cwJho4u7F/MUqIfPYR7Y1mQFt0abvlSAlPoM/rNamceM9yNSZqMp
         GVqXkzT3ho3JqvJH1H0/fUqncDjfpi1asWGUQnkJMv60SaLFh5Q7GEoFVhUKNCYWEo4K
         vMK0fbID48hZO9lnxGw2yE6TQGOl3YTcpFOV5TG633ZhBg0XvpM/sCow0aa87kdEcCWL
         tIR3ufiHlRR1rSXU/5yWyiNrYStysaXTXIfBGcg9oWo50x7DJxbMJdtrXZ1fRAPVtLCW
         lC8gPDriH1T0efuP72DIg2kGMjCdvDcfWDBt3q1VrizQZcl9Wp2RFv1m1Wp75xInz4pK
         W8+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=VdvOVmh1kSbptSnvHBmDja1seLhOhqQKa4Qad79P7kc=;
        b=rHxnKytEDcPEh4a9uLAtpiPHHSMUSIAVKyMhj2YxYrrgD7uMiV92wZLJzwWxdn7hK5
         jHMUMhQVUB+mKy6e787J9wcd5i4jrn3Ab958Keg1ZiMgVYvF1whRg3gel5sipe9h4Xk2
         oTL7kOh9JIZcIHSQN/xPvaC8hYyc/iFuLS+bSaqBx3LOR9LAmY/I/Uejx1DgUP7F0q0+
         l6HTsLu8KhuFHqaPtHcX6PCn6EtS+pCO0HOsLuiIEU3MICvggIsWZd+eLEqM9yGio6sF
         aXY/OsPgD/r3TThpElzxMPQwEJXQifPWUJn+08Jylcv1uqNVb/5XTzEjusyrrALjBUiF
         UEqg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rvkrwkPn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VdvOVmh1kSbptSnvHBmDja1seLhOhqQKa4Qad79P7kc=;
        b=X2tQLS7ps1m7Hn/8a0T03q0jIYvhtujSW92R6dWBG8/64vx8Tbm9ZzEu+bzLyDeX05
         9698oGqS0jqXbOI2lklFXrGW7rA9n1P3Y/MNqkjgM0Ps8u9QnaFgxRIn/5ZTDjqoLlYr
         zc5WY9U1m+LvfjF2jCyeq+4YgMvHIEJcLayiB8rDRAE7S4n5o1elzkPYOUe9baL/BZy2
         w2Gb+ynjxm8Dh4Pqr3eOq3FE6dOaX80HhRV5dbL0RsbDk7k5B8tZi9FjXIQSZ3sv5f1X
         1qM+Wl6kKNtDwHuIZTeFrcWIYzy5CfA4Cu7O0d40CHkkAawEVxoNTxhymV3IyxPdt8N3
         fSJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VdvOVmh1kSbptSnvHBmDja1seLhOhqQKa4Qad79P7kc=;
        b=mHWeAKO4TkalNd1ABgC0fvRuWxtqKdFwoRmWA9nBWwzRAT9Ptx+Ip5enIAu0XWWvtb
         c56oSzr1XZNlzXr/Qw4wuFshSju7EcgnacVLGmwdEQ9jkPU1sg95rdlJrqlLo+Bb9Znk
         sz3Wd0/tptSXnDyWrwjrERfjt921vl0tOtpf38mLuEaCwrBf8eYJSZml5vmHZTM9nBrj
         fAokstnW1K9GtxJevBGXwhjtyl2+urDisom0vOAtElpmUlII6JGzQocShQJXTrcMNgzN
         K0ymnuj8UVhyudL42toQGpyR7wrFTf2sJZtWdXF1727HmJzOSCCqTjUBGti/gBIL9rf4
         9WxQ==
X-Gm-Message-State: APjAAAWDKrLQkNAIvcPgKcHLEMYOb7y7gk9bcyNVU8JDkoA5AQ/A65ke
	YstOuflcyJG4Dv19tmdlMJM=
X-Google-Smtp-Source: APXvYqxCNhrQsd+PDACu5coy1rCRP/Dx758+rNaY7aKyCbF3PdKb07E6KCuXjZYq1fqQR41S/kdh0w==
X-Received: by 2002:a17:902:8c8c:: with SMTP id t12mr3770942plo.21.1575028077685;
        Fri, 29 Nov 2019 03:47:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1801:: with SMTP id 1ls1691529pfy.13.gmail; Fri, 29 Nov
 2019 03:47:57 -0800 (PST)
X-Received: by 2002:a63:5962:: with SMTP id j34mr15853805pgm.421.1575028077130;
        Fri, 29 Nov 2019 03:47:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575028077; cv=none;
        d=google.com; s=arc-20160816;
        b=wdrKeHXil04rq1wiv6TGsBY+Cu1WJHubMKwUW+trfMq+RWYI+n5r2BtmcHjvcjAqd/
         svgOQXUx6gO2tBkz3oiK2g64dnmIz7hPEEG4cREOxXMGg4KiJ/+gFIrz8ZKtB+8xRYEX
         fKdQdxSjj5fPWNwUdHFDY/KkIJDAtLgoTe7QvX047wDgkkgESplxtqoaFfC4FNSwCsw2
         X6GE//fqcooVarrgr4sWH33En99fY6Y7EHWAcYMyeUPThjAUpPXULuPFxym9XT7zrBsr
         GXeR/D9H4iPUBx/z+JEobTeDHNIB3lOBg9mppOjd+D26Yb3XxVdYVr2aOEW1uPs+SKz1
         Yxfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=P+2G3R6cNvGwqJrWJESzI9weRmKK12p/MVr0x5c311Y=;
        b=yH4l6PqFXNfxQg+3e8hgvo2/Ir8ooMqCFZfqJ+O0r6y9iNXZbThVdF8dnPm4sLwTJD
         zPVtqNKoCsI0V/ypGC0qStORod2xwJNwGMEkKQ5NoepS89oSA7/vT9EiDuz8j8wYBqEV
         mkaUuzP/PI44z/F2ha7rjJGdUUI+i5JXB4HgYca/rFQo6il04M8SffGNQxkppqYIjcsx
         2kee0SJMz95C8xlWCasEQyWBOKEDmlD110punpntok4mJMZY5m7fi2ODYWAWdvhOSHVz
         2mM33m4k9FwpMTfzSePmAxgsGmbrTTAA8A8UAzwdpUE3XATe8YwpW+iRdM+BP/V7g9Mt
         bEpw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rvkrwkPn;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id 17si314608pjb.2.2019.11.29.03.47.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 03:47:57 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id a137so23448257qkc.7
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 03:47:57 -0800 (PST)
X-Received: by 2002:a37:de12:: with SMTP id h18mr15428363qkj.256.1575028075712;
 Fri, 29 Nov 2019 03:47:55 -0800 (PST)
MIME-Version: 1.0
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net>
 <1573835765.5937.130.camel@lca.pw> <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
 <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com> <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
 <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
 <CACT4Y+Yog=PHF1SsLuoehr2rcbmfvLUW+dv7Vo+1RfdTOx7AUA@mail.gmail.com> <2297c356-0863-69ce-85b6-8608081295ed@virtuozzo.com>
In-Reply-To: <2297c356-0863-69ce-85b6-8608081295ed@virtuozzo.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 29 Nov 2019 12:47:43 +0100
Message-ID: <CACT4Y+ZNAfkrE0M=eCHcmy2LhPG_kKbg4mOh54YN6Bgb4b3F5w@mail.gmail.com>
Subject: Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real
 shadow memory
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Daniel Axtens <dja@axtens.net>, Qian Cai <cai@lca.pw>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux-MM <linux-mm@kvack.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Christophe Leroy <christophe.leroy@c-s.fr>, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, Vasily Gorbik <gor@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rvkrwkPn;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Fri, Nov 29, 2019 at 12:38 PM Andrey Ryabinin
<aryabinin@virtuozzo.com> wrote:
> >>>
> >>>
> >>> Not sure if it's the same or not. Is it addressed by something in flight?
> >>>
> >>> My config:
> >>> https://gist.githubusercontent.com/dvyukov/36c7be311fdec9cd51c649f7c3cb2ddb/raw/39c6f864fdd0ffc53f0822b14c354a73c1695fa1/gistfile1.txt
> >>
> >>
> >> I've tried this fix for pcpu_get_vm_areas:
> >> https://groups.google.com/d/msg/kasan-dev/t_F2X1MWKwk/h152Z3q2AgAJ
> >> and it helps. But this will break syzbot on linux-next soon.
> >
> >
> > Can this be related as well?
> > Crashes on accesses to shadow on the ion memory...
>
> Nope, it's vm_map_ram() not being handled


Another suspicious one. Related to kasan/vmalloc?

BUG: unable to handle page fault for address: fffff52005b80000
#PF: supervisor read access in kernel mode
#PF: error_code(0x0000) - not-present page
PGD 7ffcd067 P4D 7ffcd067 PUD 2cd10067 PMD 66d76067 PTE 0
Oops: 0000 [#1] PREEMPT SMP KASAN
CPU: 2 PID: 9211 Comm: syz-executor.2 Not tainted 5.4.0-next-20191129+ #6
Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
PKRU: 55555554
Call Trace:
 xfs_buf_ioend+0x228/0xdc0 fs/xfs/xfs_buf.c:1162
 __xfs_buf_submit+0x38b/0xe50 fs/xfs/xfs_buf.c:1485
 xfs_buf_submit fs/xfs/xfs_buf.h:268 [inline]
 xfs_buf_read_uncached+0x15c/0x560 fs/xfs/xfs_buf.c:897
 xfs_readsb+0x2d0/0x540 fs/xfs/xfs_mount.c:298
 xfs_fc_fill_super+0x3e6/0x11f0 fs/xfs/xfs_super.c:1415
 get_tree_bdev+0x444/0x620 fs/super.c:1340
 xfs_fc_get_tree+0x1c/0x20 fs/xfs/xfs_super.c:1550
 vfs_get_tree+0x8e/0x300 fs/super.c:1545
 do_new_mount fs/namespace.c:2822 [inline]
 do_mount+0x152d/0x1b50 fs/namespace.c:3142
 ksys_mount+0x114/0x130 fs/namespace.c:3351
 __do_sys_mount fs/namespace.c:3365 [inline]
 __se_sys_mount fs/namespace.c:3362 [inline]
 __x64_sys_mount+0xbe/0x150 fs/namespace.c:3362
 do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
 entry_SYSCALL_64_after_hwframe+0x49/0xbe
RIP: 0033:0x46736a
Code: 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f
84 00 00 00 00 00 0f 1f 44 00 00 49 89 ca b8 a5 00 00 00 0f 05 <48> 3d
01 f0 ff ff 73 01 c3 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007fb49bda8a78 EFLAGS: 00000202 ORIG_RAX: 00000000000000a5
RAX: ffffffffffffffda RBX: 00007fb49bda8af0 RCX: 000000000046736a
RDX: 00007fb49bda8ad0 RSI: 0000000020000140 RDI: 00007fb49bda8af0
RBP: 00007fb49bda8ad0 R08: 00007fb49bda8b30 R09: 00007fb49bda8ad0
R10: 0000000000000000 R11: 0000000000000202 R12: 00007fb49bda8b30
R13: 00000000004b1c60 R14: 00000000004b006d R15: 00007fb49bda96bc
Modules linked in:
Dumping ftrace buffer:
   (ftrace buffer empty)
CR2: fffff52005b80000
---[ end trace eddd8949d4c898df ]---
RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
PKRU: 55555554

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZNAfkrE0M%3DeCHcmy2LhPG_kKbg4mOh54YN6Bgb4b3F5w%40mail.gmail.com.
