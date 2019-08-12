Return-Path: <kasan-dev+bncBDQ27FVWWUFRBLVJYPVAKGQET6JXOKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 39D7989579
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2019 04:53:36 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id i70sf78284078ybg.5
        for <lists+kasan-dev@lfdr.de>; Sun, 11 Aug 2019 19:53:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565578414; cv=pass;
        d=google.com; s=arc-20160816;
        b=BS1IHZyQazYqQ4MyQyRYEwv+k5Om1yo9BIrS4gtpMvvPFF3VOJOEHwlZRfRzed+o9+
         GgpJAUa/xNNu1MQw5ESH3u8XHaZgsx9pbE8ilp9ToI7GcvHLmrPwofDSPK0NGRLeV0XQ
         GedaIit8o3KSpXa3NMjh/vm6XXQSo2SonZFnSLcRJRowgv4BQU70WlBBoBJnKhYJa1dM
         e2F7H4snL5NMtHwtRCDXisG+gBVCxOWtZ0E1eRqUMJ8lckOlne1LFDqcrrXbnTsrtPjk
         3ompoXwcpfKRSyUhvL/Gw8RqV6Sztffvn7wo/Z+ILkcx9vgs+Cl75NZE2hQ3uYdCoXzy
         y9AQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=nlFJ668mg6hEnJDXdXBL2zwzOnH3SK5MUxaRZw8MeGM=;
        b=L4SU7Q6rqA0NEByRPE2vGS4XAVNVdkBaGLCPV5YTxcsRNc1z80QNJkqdKOwYjylHpA
         l0muXUNx5JKFWlWlA4sqycsHflZf1uj3a2TzJzBQ9Yg8bqSAZ6siCP8m8pc2NKGsDAbC
         jxEpSodnzz2UyIRtk7JEHj7OYXQxpfn7qz9qZRNGb8Bcm+4dS8KQcCwONhlf9av8DJAD
         WYvf6Xndcju2ZG+E9VSWFfvt9b2ZoI6TB+4vLU8Gl264aQxrotNhmerkBm09Y3NP0hbH
         LU73bW96vLZivV2frMu4B+aS8gB5bffc7sWykz0GsX34iy2swF8sMnRflt035wnLWoZ/
         /77w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=T90xIibo;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nlFJ668mg6hEnJDXdXBL2zwzOnH3SK5MUxaRZw8MeGM=;
        b=aZsFY8OnO1RXlz9bpI5oar+mab+tqoXX3Va2Xvko5mEkafthLldAGR70FOt/A3Ttju
         8M0Hkm34vBqQ6npXCJdbX7uM5xk5aey4TGmeX25lJ96pXvYBjWqhNeSZLkKJn6Q6pqfl
         oteuoA3iqDs94H1gJ6pnGwjDFBkb44+GPKvHcaX1a6E1mt/Exns1cnvG4I0dxkn4FPsn
         H/KrAE5fFy3Qj++VJZeU/aNkyeKfKK0UWiM7nsRfwj1pcvqQf8CGVa6dBsK+vjllwVt+
         3G/P4f0o3vOPcJOosDOei4LHIoEzZujAW6HaAVvL+qxou5z7M3GsxFF1YimPcAdOf60N
         txaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nlFJ668mg6hEnJDXdXBL2zwzOnH3SK5MUxaRZw8MeGM=;
        b=DDyMzUsaZd5iPB4Kb0RQlmb6b4LZXbWjVaWRYXVloAsjrL8m25wegjghzr3BT+xd6G
         FV9F/3nG0eT5MDTPss5xrYv7F7G7SFz8xfWqkVlxDz5Aj8WBvIMddHrw+X5J+PscvNJ2
         KMDXaa/ynx2J4Q+fMoR/X2/QL2vSYxuzeqZ4lKTbbVzNjXmzU5kUT6bEyBGYFKMUH+o+
         ViP6nN5EMDhtAIsIIOPPRru6x4TJmBzL8WYzuigF31ZjqBi4UjSLG/d1r+d5Xg20FzkX
         pa0FjWopnfWoXP8U3uOV+chwldh1BD83xzdYBvqgJl3oiv+B3s2wZD3A/UambNQ4S2Iw
         m9LQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAV8biiwemOeIRtjgQ72SqodJgLL9g9JI8BECmlFEd/0oZMRwAXR
	DWmGPxMDcIJ7GZ+89pUdh8s=
X-Google-Smtp-Source: APXvYqzKGpB94AKo26rEyyzFGcSbWllB0BzBle1pbypEoct8NfPAXzDeaQxKeydmi9HnfRieFgJ1mw==
X-Received: by 2002:a81:6c8a:: with SMTP id h132mr23045728ywc.314.1565578414705;
        Sun, 11 Aug 2019 19:53:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:e4c2:: with SMTP id n185ls3332173ywe.1.gmail; Sun, 11
 Aug 2019 19:53:34 -0700 (PDT)
X-Received: by 2002:a81:af06:: with SMTP id n6mr22776444ywh.449.1565578414315;
        Sun, 11 Aug 2019 19:53:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565578414; cv=none;
        d=google.com; s=arc-20160816;
        b=N8t3unYW5aD9FLqpuobW8Uy/oCw5WmrRzvby8CjF/EDvq2rVHDLC/4SP4f+fXorRJK
         o3gaImo7dybHCUz25+OLnf+QWshiWgzUKzYUP9j8R9wQjogzVS/9yylJlnOFUT5Q9nb+
         gXzgUAJwwFldUJO31VwnqCr7PIoIyPiWUe1ukbQ7XnUV2oyO6ks/TGXGx7goaAyKXiwQ
         qIX1ZsoF21IPsECJzaTwGqbW5Eik42quApkC0hp7rnFEHlXZaLfqeNje/SHP/MQDGuLK
         cgiKKzOdni2/tjND70MJERNddAn2LKqrr23xUNZj5YiK64nkedJ32QvqMwcTJLeD+bhY
         kkmQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=dXAwlxqvWpTq/VMVrnK7FGyu0HZLxIWbkokfBoAnTq4=;
        b=k/f8Wv0N6gNlf2VMPOS3ss+isw7LfN9rnJkyKqdvlIND/ejAlUNEwV7U4XcXsMfa8q
         ZuswWymoewlPxzoSkMkRBoqVfxI+PfY1izWnMEgC/IGz7NCaGuMJIi6kdFZlV0ijyjZ8
         kImLe7y6ozUBgU1TAMP2vtwG8HuJJ7cqXROhbapoSj3XuV1osnzPQjEQyH/Lz5iPc4HG
         LTN2JNZ51vraQ7nECf2s/ZuXuDCH1M4Lhl98FHKGAK/KbdMeSeHR514S+tCHQNK45ntd
         z4g6RTcQ6GhSsiwU4dIEhzskzUjwyPGg/QR4EmJ4E/PLnxN+1MN0ZczpA1miSQqnS58z
         ce+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=T90xIibo;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x544.google.com (mail-pg1-x544.google.com. [2607:f8b0:4864:20::544])
        by gmr-mx.google.com with ESMTPS id c76si162807ybf.3.2019.08.11.19.53.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Sun, 11 Aug 2019 19:53:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as permitted sender) client-ip=2607:f8b0:4864:20::544;
Received: by mail-pg1-x544.google.com with SMTP id l21so48743523pgm.3
        for <kasan-dev@googlegroups.com>; Sun, 11 Aug 2019 19:53:34 -0700 (PDT)
X-Received: by 2002:a62:3543:: with SMTP id c64mr32989322pfa.242.1565578413205;
        Sun, 11 Aug 2019 19:53:33 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id i137sm112983579pgc.4.2019.08.11.19.53.30
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Sun, 11 Aug 2019 19:53:32 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com
Subject: Re: [PATCH v3 1/3] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20190809095435.GD48423@lakrids.cambridge.arm.com>
References: <20190731071550.31814-1-dja@axtens.net> <20190731071550.31814-2-dja@axtens.net> <20190808135037.GA47131@lakrids.cambridge.arm.com> <20190808174325.GD47131@lakrids.cambridge.arm.com> <20190809095435.GD48423@lakrids.cambridge.arm.com>
Date: Mon, 12 Aug 2019 12:53:25 +1000
Message-ID: <87y2zzf61m.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=T90xIibo;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::544 as
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

Mark Rutland <mark.rutland@arm.com> writes:

> On Thu, Aug 08, 2019 at 06:43:25PM +0100, Mark Rutland wrote:
>> On Thu, Aug 08, 2019 at 02:50:37PM +0100, Mark Rutland wrote:
>> > Hi Daniel,
>> > 
>> > This is looking really good!
>> > 
>> > I spotted a few more things we need to deal with, so I've suggested some
>> > (not even compile-tested) code for that below. Mostly that's just error
>> > handling, and using helpers to avoid things getting too verbose.
>> 
>> FWIW, I had a quick go at that, and I've pushed the (corrected) results
>> to my git repo, along with an initial stab at arm64 support (which is
>> currently broken):
>> 
>> https://git.kernel.org/pub/scm/linux/kernel/git/mark/linux.git/log/?h=kasan/vmalloc
>
> I've fixed my arm64 patch now, and that appears to work in basic tests
> (example below), so I'll throw my arm64 Syzkaller instance at that today
> to shake out anything major that we've missed or that I've botched.
>
> I'm very excited to see this!
>
> Are you happy to pick up my modified patch 1 for v4?

Thanks, I'll do that.

I'll also have a crack at poisioning on free - I know I did that in an
early draft and then dropped it, so I don't think it was painful at all.

Regards,
Daniel

>
> Thanks,
> Mark.
>
> # echo STACK_GUARD_PAGE_LEADING > DIRECT 
> [  107.453162] lkdtm: Performing direct entry STACK_GUARD_PAGE_LEADING
> [  107.454672] lkdtm: attempting bad read from page below current stack
> [  107.456672] ==================================================================
> [  107.457929] BUG: KASAN: vmalloc-out-of-bounds in lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
> [  107.459398] Read of size 1 at addr ffff20001515ffff by task sh/214
> [  107.460864] 
> [  107.461271] CPU: 0 PID: 214 Comm: sh Not tainted 5.3.0-rc3-00004-g84f902ca9396-dirty #7
> [  107.463101] Hardware name: linux,dummy-virt (DT)
> [  107.464407] Call trace:
> [  107.464951]  dump_backtrace+0x0/0x1e8
> [  107.465781]  show_stack+0x14/0x20
> [  107.466824]  dump_stack+0xbc/0xf4
> [  107.467780]  print_address_description+0x60/0x33c
> [  107.469221]  __kasan_report+0x140/0x1a0
> [  107.470388]  kasan_report+0xc/0x18
> [  107.471439]  __asan_load1+0x4c/0x58
> [  107.472428]  lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
> [  107.473908]  lkdtm_do_action+0x40/0x50
> [  107.475255]  direct_entry+0x128/0x1b0
> [  107.476348]  full_proxy_write+0x90/0xc8
> [  107.477595]  __vfs_write+0x54/0xa8
> [  107.478780]  vfs_write+0xd0/0x230
> [  107.479762]  ksys_write+0xc4/0x170
> [  107.480738]  __arm64_sys_write+0x40/0x50
> [  107.481888]  el0_svc_common.constprop.0+0xc0/0x1c0
> [  107.483240]  el0_svc_handler+0x34/0x88
> [  107.484211]  el0_svc+0x8/0xc
> [  107.484996] 
> [  107.485429] 
> [  107.485895] Memory state around the buggy address:
> [  107.487107]  ffff20001515fe80: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
> [  107.489162]  ffff20001515ff00: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
> [  107.491157] >ffff20001515ff80: f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9 f9
> [  107.493193]                                                                 ^
> [  107.494973]  ffff200015160000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> [  107.497103]  ffff200015160080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> [  107.498795] ==================================================================
> [  107.500495] Disabling lock debugging due to kernel taint
> [  107.503212] Unable to handle kernel paging request at virtual address ffff20001515ffff
> [  107.505177] Mem abort info:
> [  107.505797]   ESR = 0x96000007
> [  107.506554]   Exception class = DABT (current EL), IL = 32 bits
> [  107.508031]   SET = 0, FnV = 0
> [  107.508547]   EA = 0, S1PTW = 0
> [  107.509125] Data abort info:
> [  107.509704]   ISV = 0, ISS = 0x00000007
> [  107.510388]   CM = 0, WnR = 0
> [  107.511089] swapper pgtable: 4k pages, 48-bit VAs, pgdp=0000000041c65000
> [  107.513221] [ffff20001515ffff] pgd=00000000bdfff003, pud=00000000bdffe003, pmd=00000000aa31e003, pte=0000000000000000
> [  107.515915] Internal error: Oops: 96000007 [#1] PREEMPT SMP
> [  107.517295] Modules linked in:
> [  107.518074] CPU: 0 PID: 214 Comm: sh Tainted: G    B             5.3.0-rc3-00004-g84f902ca9396-dirty #7
> [  107.520755] Hardware name: linux,dummy-virt (DT)
> [  107.522208] pstate: 60400005 (nZCv daif +PAN -UAO)
> [  107.523670] pc : lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
> [  107.525176] lr : lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
> [  107.526809] sp : ffff200015167b90
> [  107.527856] x29: ffff200015167b90 x28: ffff800002294740 
> [  107.529728] x27: 0000000000000000 x26: 0000000000000000 
> [  107.531523] x25: ffff200015167df0 x24: ffff2000116e8400 
> [  107.533234] x23: ffff200015160000 x22: dfff200000000000 
> [  107.534694] x21: ffff040002a2cf7a x20: ffff2000116e9ee0 
> [  107.536238] x19: 1fffe40002a2cf7a x18: 0000000000000000 
> [  107.537699] x17: 0000000000000000 x16: 0000000000000000 
> [  107.539288] x15: 0000000000000000 x14: 0000000000000000 
> [  107.540584] x13: 0000000000000000 x12: ffff10000d672bb9 
> [  107.541920] x11: 1ffff0000d672bb8 x10: ffff10000d672bb8 
> [  107.543438] x9 : 1ffff0000d672bb8 x8 : dfff200000000000 
> [  107.545008] x7 : ffff10000d672bb9 x6 : ffff80006b395dc0 
> [  107.546570] x5 : 0000000000000001 x4 : dfff200000000000 
> [  107.547936] x3 : ffff20001113274c x2 : 0000000000000007 
> [  107.549121] x1 : eb957a6c7b3ab400 x0 : 0000000000000000 
> [  107.550220] Call trace:
> [  107.551017]  lkdtm_STACK_GUARD_PAGE_LEADING+0x88/0xb4
> [  107.552288]  lkdtm_do_action+0x40/0x50
> [  107.553302]  direct_entry+0x128/0x1b0
> [  107.554290]  full_proxy_write+0x90/0xc8
> [  107.555332]  __vfs_write+0x54/0xa8
> [  107.556278]  vfs_write+0xd0/0x230
> [  107.557000]  ksys_write+0xc4/0x170
> [  107.557834]  __arm64_sys_write+0x40/0x50
> [  107.558980]  el0_svc_common.constprop.0+0xc0/0x1c0
> [  107.560111]  el0_svc_handler+0x34/0x88
> [  107.560936]  el0_svc+0x8/0xc
> [  107.561580] Code: 91140280 97ded9e3 d10006e0 97e4672e (385ff2e1) 
> [  107.563208] ---[ end trace 9e69aa587e1dc0cc ]---

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87y2zzf61m.fsf%40dja-thinkpad.axtens.net.
