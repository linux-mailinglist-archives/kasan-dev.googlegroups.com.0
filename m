Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBEHMQTXQKGQEGRF6NTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C0DD110D7BF
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 16:15:30 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id d12sf19038572qvj.16
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 07:15:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575040529; cv=pass;
        d=google.com; s=arc-20160816;
        b=oMcwHZVFJc8PIc/jNNUwg/J90/drOQYz/O7SCX2MTs0V18OddC2xCvYU14ChYAv3pd
         DJFsQfq1PUIVDzlAHN4rRYlj3yGfF0nVyr5gSORju0e55XnWCBQ5ZnUK8bOo/sdHgKYp
         ++AK7Za+Hmh03bxkWgM8SBrA4ELCo6VuucGudOeAHU+qqLcUGpJZaGFLQD0wgL5OyF4n
         pfIgXwqHRmLrFMcbLOvoXqmL0lvLn6K4h12pLHj/uRo4wYwiw/bU+hUvWAEYj5RlcMYy
         +7FzUWZWFnYJhEzHbK9Tn+NbG5X5Tpt0CyU7+HfTWlqDa3dRmOXlCN2n8iajfM/hAdiP
         xhgg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=zm0k537QxNSpeKB0LYLv2/CSjtk6rvukc+NCJCIVCCs=;
        b=U2PzlLjbRJse09Lb1gdcPq2AtdIuU/RmLfrkltHviwxNruIk+35j1CvEd9o2UqpeKt
         GfE7++1ULYEcTH/XeoEJfwBbRxtoYKSdWltiC8S7Tm8QWZzsGdbc20RDunkEBNVTlVHw
         AEqaWhykvK76FNO1/Yj/coBIPtg/4Jy691zGArpBBYI06bU5o3sXSBQG/dbiEAAbzWRh
         +i4P0VhAjVhq3tJebF3DAkBrdZYHWSbRSYDj70OTmAxJjoqE3bk6iadDk83kSJ1X/e3n
         SN/oUN9SxC3eEybZOdcY5oPcApXkGg7fEGV9he01q+h/0gG3Bw8lIB5chff3beEXYygH
         3ewg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="G2Z/aSJp";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc:message-id
         :references:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zm0k537QxNSpeKB0LYLv2/CSjtk6rvukc+NCJCIVCCs=;
        b=TCWcXe7ArDI4GWF6VhqlVdsTVK+cR57TyWH2DVEutp84ZR5atMx44sTdk4m3dmfWhm
         afBBBRR/J02pkkxl1C6CkX4Jj7tJDe5gmBA0uBG51U22gl1r79ibxnco774ZleQvsdkE
         2NQK5IQ54cCZJ/iktfXEV/Ox0jhbbEibXMNC3LsQd72dWvwH2Edg4eECrsSjU/AbKWTk
         +fBdSie2DK4i4ey/pgnXtD93XYBeN0AYZpThFM4YDwNtwv78qQcT4L/pUh7ow2/Dt+Hf
         WuM0hQgsIRn3DLnqdhX3qkBOwaUyOUcjOSaAJy3zp4OQpFyyo7kmBup3wBZMCLk7+ML5
         hp5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:message-id:references:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zm0k537QxNSpeKB0LYLv2/CSjtk6rvukc+NCJCIVCCs=;
        b=XSfgxF4LWmSli8T8uALk2ntLUR8xLCaFTxYZZ39RindVlh2ex1PovrxeH8An7PKbTm
         OR50OFVRPCypQLxo53dIFxz0bPRNrGz1zm8TUGcS4bJ0TUCWlawwVRsFvmZ05KwkDdds
         BZ1WdmGg8emAohVOS0J2SlVlJnamYWBTAxaqAa3KbEy/jw57vT+5RoFVPznc4JWCX4Fh
         crt2bFeTDprIfKLcdNtM/q7BPUPPctNoMbXPtCXEANVl+PugOpm7lwzjqUZjcTSUyEQY
         8rtvDOwkVz2u1PLketgWeQrESAnL0j0/q5kjPpI1LRDFXbwy0NKeNeUFipZ9I/5h3+K6
         sz7Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXOYlAcuyAZyBD1WDWouW4kQHNmWbK9B6fVmddy2SBCAKVNTOCJ
	PV6DfUbbGjCqCJvGbX6X+Og=
X-Google-Smtp-Source: APXvYqxKvQaA7yiHXuEZuxVtGO02pk+SjIOVKcuOV/oidSGSDL0GUjUWdhIiTD0EURwe3LpdWxAEsg==
X-Received: by 2002:a05:6214:1493:: with SMTP id bn19mr5596795qvb.83.1575040528938;
        Fri, 29 Nov 2019 07:15:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:218b:: with SMTP id g11ls892601qka.10.gmail; Fri,
 29 Nov 2019 07:15:28 -0800 (PST)
X-Received: by 2002:a37:bd41:: with SMTP id n62mr16993117qkf.379.1575040528470;
        Fri, 29 Nov 2019 07:15:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575040528; cv=none;
        d=google.com; s=arc-20160816;
        b=HcX1XqL0SiMCO5L1gLgvsgUlCdmTWzGw6bRuTNbjr6lxb7MYPod/NBjScoL5efD9UC
         pg9h0A3+n7CO4LXWQO2ejsuYNXBdRSXJEzVuE+erzoKPMZWfKqdbJxU04p8jWFgWWrmS
         ZYzlLA8LwSWiQvzeeeSaBLBMvW+N4rKHQ1ZypsorfzzOzW5DLn/B4Iz/rvLANFxljW21
         CvZ71wsODcr6qMu0hDVhdzFFckwVB4e1OxI3FCeRT+WJfERbBBr97WvMuk5Xrl5Ws3X9
         Bt42xl3qJ3A+9BeXOo3ruzBbJfd0CAbZ/3LknK9yclhVBPwAqy92ENfpfysKTXtmfeKJ
         wUNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=yJShtf3/esmyNyieK8L5Aqur+hkWJ6a+EPrMUvaw//k=;
        b=MUas2y2eJq7pl4aU8zWpEziGPcHyvcBIbdvozYavrIeY9fYI//GSdjYTECSG3SeEVW
         vD8Ze9/JfnZvxtQmMyb0X/V0oLcP0cJzTsML52KD54jbEV2rTez9Jz+NzaJ/sgD3sVW3
         PFOeFffQmyoEilR26PYTwwUyCHBlhyrtNTz16j0lsqsw9qGMpuGXqY0J/jwrAsM29M5J
         FnFgdcbrUglR+T+cDgvfcy53vWYoyyPcPyK7cA7+TMkZDeWFp+KXJcWx4hUglC9bY6zZ
         0IUC3N16dgXJzfJEOrxCre7FxFWQCqKmZpf6OZm2U60wG9r14BaV283q6bj3oxN0uyn7
         DWMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b="G2Z/aSJp";
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x841.google.com (mail-qt1-x841.google.com. [2607:f8b0:4864:20::841])
        by gmr-mx.google.com with ESMTPS id 123si55447qkh.3.2019.11.29.07.15.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 07:15:28 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as permitted sender) client-ip=2607:f8b0:4864:20::841;
Received: by mail-qt1-x841.google.com with SMTP id p5so2002781qtq.12
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 07:15:28 -0800 (PST)
X-Received: by 2002:ac8:1115:: with SMTP id c21mr38478911qtj.188.1575040527681;
        Fri, 29 Nov 2019 07:15:27 -0800 (PST)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id r8sm11478938qti.6.2019.11.29.07.15.26
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 29 Nov 2019 07:15:27 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.0 \(3601.0.10\))
Subject: XFS check crash (WAS Re: [PATCH v11 1/4] kasan: support backing
 vmalloc space with real shadow memory)
From: Qian Cai <cai@lca.pw>
In-Reply-To: <871rtqg91q.fsf@dja-thinkpad.axtens.net>
Date: Fri, 29 Nov 2019 10:15:25 -0500
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Linux-MM <linux-mm@kvack.org>,
 the arch/x86 maintainers <x86@kernel.org>,
 Alexander Potapenko <glider@google.com>,
 Andy Lutomirski <luto@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 Mark Rutland <mark.rutland@arm.com>,
 Christophe Leroy <christophe.leroy@c-s.fr>,
 linuxppc-dev <linuxppc-dev@lists.ozlabs.org>,
 Vasily Gorbik <gor@linux.ibm.com>,
 linux-xfs@vger.kernel.org,
 "Darrick J. Wong" <darrick.wong@oracle.com>
Message-Id: <27B18BF6-757C-4CA3-A852-1EE20D4D10A9@lca.pw>
References: <20191031093909.9228-1-dja@axtens.net>
 <20191031093909.9228-2-dja@axtens.net> <1573835765.5937.130.camel@lca.pw>
 <871ru5hnfh.fsf@dja-thinkpad.axtens.net>
 <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com>
 <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com>
 <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com>
 <CACT4Y+Yog=PHF1SsLuoehr2rcbmfvLUW+dv7Vo+1RfdTOx7AUA@mail.gmail.com>
 <2297c356-0863-69ce-85b6-8608081295ed@virtuozzo.com>
 <CACT4Y+ZNAfkrE0M=eCHcmy2LhPG_kKbg4mOh54YN6Bgb4b3F5w@mail.gmail.com>
 <56cf8aab-c61b-156c-f681-d2354aed22bb@virtuozzo.com>
 <871rtqg91q.fsf@dja-thinkpad.axtens.net>
To: Daniel Axtens <dja@axtens.net>
X-Mailer: Apple Mail (2.3601.0.10)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b="G2Z/aSJp";       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::841 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Nov 29, 2019, at 7:29 AM, Daniel Axtens <dja@axtens.net> wrote:
> 
>>>> 
>>>> Nope, it's vm_map_ram() not being handled
>>> 
>>> 
>>> Another suspicious one. Related to kasan/vmalloc?
>> 
>> Very likely the same as with ion:
>> 
>> # git grep vm_map_ram|grep xfs
>> fs/xfs/xfs_buf.c:                * vm_map_ram() will allocate auxiliary structures (e.g.
>> fs/xfs/xfs_buf.c:                       bp->b_addr = vm_map_ram(bp->b_pages, bp->b_page_count,
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


I instead trigger something a bit different by manually triggering a crash first to make the XFS
partition uncleanly shutdown.

# echo c >/proc/sysrq-trigger

and then reboot the same kernel where it will crash while checking the XFS. This can be workaround
by rebooting to an older kernel (v4.18) first where xfs_repair will be successfully there, and then rebooting
to the new linux-next kernel will be fine.

[  OK  ] Started File System Check on /dev/mapper/rhel_hpe--sy680gen9--01-root.
         Mounting /sysroot...
[  141.177726][ T1730] SGI XFS with security attributes, no debug enabled
[  141.432382][ T1720] XFS (dm-0): Mounting V5 Filesystem
[**    ] A start job is running for /sysroot (39s / 1min 51s)[  158.738816][ T1720] XFS (dm-0): Starting recovery (logdev: internal)
[  158.792010][  T844] BUG: unable to handle page fault for address: fffff52001f0000c
[  158.830913][  T844] #PF: supervisor read access in kernel mode
[  158.859680][  T844] #PF: error_code(0x0000) - not-present page
[  158.886057][  T844] PGD 207ffe3067 P4D 207ffe3067 PUD 2071f2067 PMD f68e08067 PTE 0
[  158.922065][  T844] Oops: 0000 [#1] SMP DEBUG_PAGEALLOC KASAN PTI
[  158.949620][  T844] CPU: 112 PID: 844 Comm: kworker/112:1 Not tainted 5.4.0-next-20191127+ #3
[  158.988759][  T844] Hardware name: HP Synergy 680 Gen9/Synergy 680 Gen9 Compute Module, BIOS I40 05/23/2018
[  159.033380][  T844] Workqueue: xfs-buf/dm-0 xfs_buf_ioend_work [xfs]
[  159.061935][  T844] RIP: 0010:__asan_load4+0x3a/0xa0
[  159.061941][  T844] Code: 00 00 00 00 00 00 ff 48 39 f8 77 6d 48 8d 47 03 48 89 c2 83 e2 07 48 83 fa 02 76 30 48 be 00 00 00 00 00 fc ff df 48 c1 e8 03 <0f> b6 04 30 84 c0 75 3e 5d c3 48 b8 00 00 00 00 00 80 ff ff eb c7
[  159.061944][  T844] RSP: 0018:ffffc9000a4b7cb0 EFLAGS: 00010a06
[  159.061949][  T844] RAX: 1ffff92001f0000c RBX: ffffc9000f800000 RCX: ffffffffc06d10ae
[  159.061952][  T844] RDX: 0000000000000003 RSI: dffffc0000000000 RDI: ffffc9000f800060
[  159.061955][  T844] RBP: ffffc9000a4b7cb0 R08: ffffed130bee89e5 R09: 0000000000000001
[  159.061958][  T844] R10: ffffed130bee89e4 R11: ffff88985f744f23 R12: 0000000000000000
[  159.061961][  T844] R13: ffff889724be0040 R14: ffff88836c8e5000 R15: 00000000000c8000
[  159.061965][  T844] FS:  0000000000000000(0000) GS:ffff88985f700000(0000) knlGS:0000000000000000
[  159.061968][  T844] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  159.061971][  T844] CR2: fffff52001f0000c CR3: 0000001f615b8004 CR4: 00000000003606e0
[  159.061974][  T844] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[  159.061976][  T844] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[  159.061978][  T844] Call Trace:
[  159.062118][  T844]  xfs_inode_buf_verify+0x13e/0x230 [xfs]
[  159.062264][  T844]  xfs_inode_buf_readahead_verify+0x13/0x20 [xfs]
[  159.634441][  T844]  xfs_buf_ioend+0x153/0x6b0 [xfs]
[  159.634455][  T844]  ? trace_hardirqs_on+0x3a/0x160
[  159.679087][  T844]  xfs_buf_ioend_work+0x15/0x20 [xfs]
[  159.702689][  T844]  process_one_work+0x579/0xb90
[  159.723898][  T844]  ? pwq_dec_nr_in_flight+0x170/0x170
[  159.747499][  T844]  worker_thread+0x63/0x5b0
[  159.767531][  T844]  ? process_one_work+0xb90/0xb90
[  159.789549][  T844]  kthread+0x1e6/0x210
[  159.807166][  T844]  ? kthread_create_worker_on_cpu+0xc0/0xc0
[  159.833064][  T844]  ret_from_fork+0x3a/0x50
[  159.852200][  T844] Modules linked in: xfs sd_mod bnx2x mdio firmware_class hpsa scsi_transport_sas dm_mirror dm_region_hash dm_log dm_mod
[  159.915273][  T844] CR2: fffff52001f0000c
[  159.934029][  T844] ---[ end trace 3f3b30f5fc34bbf1 ]---
[  159.957937][  T844] RIP: 0010:__asan_load4+0x3a/0xa0
[  159.980316][  T844] Code: 00 00 00 00 00 00 ff 48 39 f8 77 6d 48 8d 47 03 48 89 c2 83 e2 07 48 83 fa 02 76 30 48 be 00 00 00 00 00 fc ff df 48 c1 e8 03 <0f> b6 04 30 84 c0 75 3e 5d c3 48 b8 00 00 00 00 00 80 ff ff eb c7
[  160.068386][  T844] RSP: 0018:ffffc9000a4b7cb0 EFLAGS: 00010a06
[  160.068389][  T844] RAX: 1ffff92001f0000c RBX: ffffc9000f800000 RCX: ffffffffc06d10ae
[  160.068391][  T844] RDX: 0000000000000003 RSI: dffffc0000000000 RDI: ffffc9000f800060
[  160.068393][  T844] RBP: ffffc9000a4b7cb0 R08: ffffed130bee89e5 R09: 0000000000000001
[  160.068395][  T844] R10: ffffed130bee89e4 R11: ffff88985f744f23 R12: 0000000000000000
[  160.068397][  T844] R13: ffff889724be0040 R14: ffff88836c8e5000 R15: 00000000000c8000
[  160.068399][  T844] FS:  0000000000000000(0000) GS:ffff88985f700000(0000) knlGS:0000000000000000
[  160.068401][  T844] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[  160.068404][  T844] CR2: fffff52001f0000c CR3: 0000001f615b8004 CR4: 00000000003606e0
[  160.068405][  T844] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
[  160.068407][  T844] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
[  160.068410][  T844] Kernel panic - not syncing: Fatal exception
[  160.095178][  T844] Kernel Offset: 0x21c00000 from 0xffffffff81000000 (relocation range: 0xffffffff80000000-0xffffffffbfffffff)
[  160.541027][  T844] ---[ end Kernel panic - not syncing: Fatal exception ]---

> 
> Regards,
> Daniel
> 
>> 
>>> 
>>> BUG: unable to handle page fault for address: fffff52005b80000
>>> #PF: supervisor read access in kernel mode
>>> #PF: error_code(0x0000) - not-present page
>>> PGD 7ffcd067 P4D 7ffcd067 PUD 2cd10067 PMD 66d76067 PTE 0
>>> Oops: 0000 [#1] PREEMPT SMP KASAN
>>> CPU: 2 PID: 9211 Comm: syz-executor.2 Not tainted 5.4.0-next-20191129+ #6
>>> Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS
>>> rel-1.12.0-59-gc9ba5276e321-prebuilt.qemu.org 04/01/2014
>>> RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
>>> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
>>> 30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
>>> 04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
>>> RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
>>> RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
>>> RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
>>> RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
>>> R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
>>> R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
>>> FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
>>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>>> CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
>>> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>>> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>>> PKRU: 55555554
>>> Call Trace:
>>> xfs_buf_ioend+0x228/0xdc0 fs/xfs/xfs_buf.c:1162
>>> __xfs_buf_submit+0x38b/0xe50 fs/xfs/xfs_buf.c:1485
>>> xfs_buf_submit fs/xfs/xfs_buf.h:268 [inline]
>>> xfs_buf_read_uncached+0x15c/0x560 fs/xfs/xfs_buf.c:897
>>> xfs_readsb+0x2d0/0x540 fs/xfs/xfs_mount.c:298
>>> xfs_fc_fill_super+0x3e6/0x11f0 fs/xfs/xfs_super.c:1415
>>> get_tree_bdev+0x444/0x620 fs/super.c:1340
>>> xfs_fc_get_tree+0x1c/0x20 fs/xfs/xfs_super.c:1550
>>> vfs_get_tree+0x8e/0x300 fs/super.c:1545
>>> do_new_mount fs/namespace.c:2822 [inline]
>>> do_mount+0x152d/0x1b50 fs/namespace.c:3142
>>> ksys_mount+0x114/0x130 fs/namespace.c:3351
>>> __do_sys_mount fs/namespace.c:3365 [inline]
>>> __se_sys_mount fs/namespace.c:3362 [inline]
>>> __x64_sys_mount+0xbe/0x150 fs/namespace.c:3362
>>> do_syscall_64+0xfa/0x780 arch/x86/entry/common.c:294
>>> entry_SYSCALL_64_after_hwframe+0x49/0xbe
>>> RIP: 0033:0x46736a
>>> Code: 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f
>>> 84 00 00 00 00 00 0f 1f 44 00 00 49 89 ca b8 a5 00 00 00 0f 05 <48> 3d
>>> 01 f0 ff ff 73 01 c3 48 c7 c1 bc ff ff ff f7 d8 64 89 01 48
>>> RSP: 002b:00007fb49bda8a78 EFLAGS: 00000202 ORIG_RAX: 00000000000000a5
>>> RAX: ffffffffffffffda RBX: 00007fb49bda8af0 RCX: 000000000046736a
>>> RDX: 00007fb49bda8ad0 RSI: 0000000020000140 RDI: 00007fb49bda8af0
>>> RBP: 00007fb49bda8ad0 R08: 00007fb49bda8b30 R09: 00007fb49bda8ad0
>>> R10: 0000000000000000 R11: 0000000000000202 R12: 00007fb49bda8b30
>>> R13: 00000000004b1c60 R14: 00000000004b006d R15: 00007fb49bda96bc
>>> Modules linked in:
>>> Dumping ftrace buffer:
>>>   (ftrace buffer empty)
>>> CR2: fffff52005b80000
>>> ---[ end trace eddd8949d4c898df ]---
>>> RIP: 0010:xfs_sb_read_verify+0xe9/0x540 fs/xfs/libxfs/xfs_sb.c:691
>>> Code: fc ff df 48 c1 ea 03 80 3c 02 00 0f 85 1e 04 00 00 4d 8b ac 24
>>> 30 01 00 00 48 b8 00 00 00 00 00 fc ff df 4c 89 ea 48 c1 ea 03 <0f> b6
>>> 04 02 84 c0 74 08 3c 03 0f 8e ad 03 00 00 41 8b 45 00 bf 58
>>> RSP: 0018:ffffc9000a58f8d0 EFLAGS: 00010a06
>>> RAX: dffffc0000000000 RBX: 1ffff920014b1f1d RCX: ffffc9000af42000
>>> RDX: 1ffff92005b80000 RSI: ffffffff82914404 RDI: ffff88805cdb1460
>>> RBP: ffffc9000a58fab0 R08: ffff8880610cd380 R09: ffffed1005a87045
>>> R10: ffffed1005a87044 R11: ffff88802d438223 R12: ffff88805cdb1340
>>> R13: ffffc9002dc00000 R14: ffffc9000a58fa88 R15: ffff888061b5c000
>>> FS:  00007fb49bda9700(0000) GS:ffff88802d400000(0000) knlGS:0000000000000000
>>> CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
>>> CR2: fffff52005b80000 CR3: 0000000060769006 CR4: 0000000000760ee0
>>> DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
>>> DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
>>> PKRU: 55555554
>>> 
>> 
>> -- 
>> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
>> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
>> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/56cf8aab-c61b-156c-f681-d2354aed22bb%40virtuozzo.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/27B18BF6-757C-4CA3-A852-1EE20D4D10A9%40lca.pw.
