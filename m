Return-Path: <kasan-dev+bncBCQPF57GUQHBBMUO22TQMGQEH2DNEYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BB3A79121D
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Sep 2023 09:28:52 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-40ff67467c9sf13338351cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Sep 2023 00:28:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1693812531; cv=pass;
        d=google.com; s=arc-20160816;
        b=pT+1b/aJNsTVcmowV/rVZ1wcPMKWJ8IrB4JBkKWJdmlINaWHSCN1EbTXkstLlRcueg
         soItEZTYvH4MliK/Ig0XFq7a8nLzaFU0LiKg4aC/oXDp7PtoJhYEPcMSqFANiPJ3f16k
         xB7xJ2QhNB7/lXvmV1u4AF02tj4ZeFm1MCMmQjIIht23SBO0Mu7RE0uec5ZOB+OX8Oym
         0wr6kyqTVoiY/f8Mk89UwCWVQlTY26SB+orzl+JVbVIWRSovghp/mZYe3Q/qruwVLV2A
         +LKECfOUlb+cTjq2+Pf+ZIO8tMAsqaVhdQWhw7BwIeVAgQscb+T0ISmOfch/+pyUpgHi
         hSmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=naaIKKVtOnKtHNuHDxvyPJMuy29pYUo0Frcfu4umdpc=;
        fh=WFd4Yb7NbyOwqfkX2n4pk4dP8YEjPYLbj67MoNiN2Ac=;
        b=koXDNNK61WyIq643NX4HlyQhYWkuR7y+AMANXnCziCS9ofh2nUQtxpOsUchbnBK0KJ
         NFMNUdDOe6PNh7Oxh/3I6RrkNpURsfKXwxSarf2tTNYkxIKrr5UeSfLbNtE6FxWPOfYr
         UQgafACBI/acPVSQqfjGSVU/8cuAHyCHk9wS7zsJdIgDwyAU2OAi/a1MprHOSSuuIWru
         L4jdIkIDbuSE4/ZrppkrksiVqvW7qL/iG9cgfUuGEehqvII+85V0gShdcPFMCos7qtGO
         DPZ9X0rvvgWZ7z4fp/StVH9uXwTzAnQR12ZzPCtRUWhwVUTRbC78mjPspTvsCgihdRpX
         J5nQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3myf1zakbaeqy45qgrrkxgvvoj.muumrk0ykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.215.207 as permitted sender) smtp.mailfrom=3MYf1ZAkbAEQy45qgrrkxgvvoj.muumrk0ykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1693812531; x=1694417331; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=naaIKKVtOnKtHNuHDxvyPJMuy29pYUo0Frcfu4umdpc=;
        b=quuRxTm9Ci9ZtQMoa6AmBkAjxfMe2FXw1JY354ygkuYEiPuE5++S1hsPk7xRLyo1dh
         oMu8+SBfmrJsJRSf++KId1TlkTs0JlHa2z27nxqWSKppcg/6zPFT1CPRPrXrPdt9vv2q
         FfrO/BwzEg92GuXvqAGPcg8G58V5UHi66Jf0/rVSMVIpyLO6tZqH/GWnutTvqxX835q2
         7nxvoCrHdcgLK4lBPQX8k8avOYxYkZg76t42rchWiain+RgyVd0AbHUDimipP2ys9k1B
         TMd/RgKfithC2VWP4ic+hcmdLp8/h0vgYEoyqdpgF+cMntoO9I1XRKutEB7EP+y1A6yb
         MBpA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1693812531; x=1694417331;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:date:mime-version:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=naaIKKVtOnKtHNuHDxvyPJMuy29pYUo0Frcfu4umdpc=;
        b=cK5n6msb518U4mGzYJUVqGGfwwsmfWCWIjwvEXlXRDjav3pmjgpkc1LzCwQ0qQt7wK
         qm40ILXdf4Uj7hV7SwuGlxQQQc4SoX+B5Y3j1vBtRNWy4iln5oqVePmy43z5TMp4n+LC
         TUZyna3NpHo4rYy8ahoecI4UMv+Ma/GumcmNLMr44xu1EIeaWyTqKClI4BDF0nfK8U8P
         eq1Je+0rBq8Ap0q74IDNLPZKErGJ8SkbjnK5dV8iQ0AkVREj93M3mMWR/ADJgWr+as7a
         A/bS4NuQZcSghH2XCfparc6vbRP3NmRasAm903S46P5S2rUHwPIvGJMuA/cwWx6k9tBX
         hO1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy9Uca5VYn98j63FaClffhAKBqfA1HZMGFR+hABb51c4B/MUXWW
	wRQ82yrORz27F0vPimwehF0=
X-Google-Smtp-Source: AGHT+IFKBvkq56vyQyOSaMZRNpg4iVACbZhxqGwahF2qOcwgK0XNmFsmbTniCE0KNpER1Y8389TZ8w==
X-Received: by 2002:ac8:5944:0:b0:400:9896:b0fa with SMTP id 4-20020ac85944000000b004009896b0famr14465767qtz.64.1693812530914;
        Mon, 04 Sep 2023 00:28:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:7495:0:b0:410:a04b:4f1f with SMTP id v21-20020ac87495000000b00410a04b4f1fls5004047qtq.1.-pod-prod-02-us;
 Mon, 04 Sep 2023 00:28:50 -0700 (PDT)
X-Received: by 2002:a1f:4e03:0:b0:48d:aae:3969 with SMTP id c3-20020a1f4e03000000b0048d0aae3969mr7067025vkb.10.1693812530164;
        Mon, 04 Sep 2023 00:28:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1693812530; cv=none;
        d=google.com; s=arc-20160816;
        b=R8hNT62RtWPGEyahdDJRkuVmFDoa59mh5clqH37U+pU+y8vV3CICluXbeEcYVkqyym
         EgGH/PyU2BfKfddGVjBny5Fx/pk4S3JpVT7DzgSIcZFtl4PmQ8+hJUhuUTRMBcrD1GkI
         HIypkMVXpZXDdfls/ySZ6zxle+AJQEp5/Qku0GgBfYC3Hgs+zM7YAF/uA/M6V8CXTHh+
         l16DKnkJeDavIblS5xY2q1R+Kl7+gAlY0PSKGHHJC9NyTF6u7IeBAlxGOl12/T5kIwWf
         xIMsyeFkTyadiM8TaRDsq13eZI+qZX0rTe+FaS1Np4IhGp7wR6fkok571Sqq9GuAoCDc
         wlTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:date:mime-version;
        bh=RyV0kvyh71m+vpajhSXcdd50x/LNT9I94jfNTNHz0Pk=;
        fh=WFd4Yb7NbyOwqfkX2n4pk4dP8YEjPYLbj67MoNiN2Ac=;
        b=MmvXxZufjPPIGXjSPfyzCCx9JBBUw6OWE++HV5F8po0ox4a9tkhKAhEJINUl6p9pCU
         oj955RQDergbNPebYL3IrJ9CnD8+QOzxH+cNsYOJI7QMGJG3H5/Lr8AHountpRJGvXCz
         X6hm9PDaMW/dqrJAOF7G1HSjazKVXMnrmMv+bHo71RHlEAzixUBHvyQj8Pljqq/Fou8j
         MFoNezntYkKMypIUAqF35JYDWEms7QZiTFScNbUiJk0kPbJG7j0CdmmGQwjFfjNt6+wM
         X+h3c+s0mY1mUBNexUDABrqfMnDGKSQZy6yJDZvAS3rGETAS+yRNVQQETsv9B8Tjs2pa
         DvdA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3myf1zakbaeqy45qgrrkxgvvoj.muumrk0ykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.215.207 as permitted sender) smtp.mailfrom=3MYf1ZAkbAEQy45qgrrkxgvvoj.muumrk0ykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-pg1-f207.google.com (mail-pg1-f207.google.com. [209.85.215.207])
        by gmr-mx.google.com with ESMTPS id j9-20020ac5ccc9000000b0048d29aa0861si1793378vkn.1.2023.09.04.00.28.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 04 Sep 2023 00:28:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3myf1zakbaeqy45qgrrkxgvvoj.muumrk0ykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.215.207 as permitted sender) client-ip=209.85.215.207;
Received: by mail-pg1-f207.google.com with SMTP id 41be03b00d2f7-5709e2551bcso531220a12.3
        for <kasan-dev@googlegroups.com>; Mon, 04 Sep 2023 00:28:50 -0700 (PDT)
MIME-Version: 1.0
X-Received: by 2002:a63:3eca:0:b0:56f:9c2d:b6b3 with SMTP id
 l193-20020a633eca000000b0056f9c2db6b3mr2148910pga.1.1693812529267; Mon, 04
 Sep 2023 00:28:49 -0700 (PDT)
Date: Mon, 04 Sep 2023 00:28:49 -0700
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000001f905c0604837659@google.com>
Subject: [syzbot] [gfs2?] INFO: task hung in write_cache_pages (3)
From: syzbot <syzbot+4fcffdd85e518af6f129@syzkaller.appspotmail.com>
To: agruenba@redhat.com, akpm@linux-foundation.org, anprice@redhat.com, 
	cluster-devel@redhat.com, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-fsdevel@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3myf1zakbaeqy45qgrrkxgvvoj.muumrk0ykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.215.207 as permitted sender) smtp.mailfrom=3MYf1ZAkbAEQy45qgrrkxgvvoj.muumrk0ykxiutzktz.ius@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
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

Hello,

syzbot found the following issue on:

HEAD commit:    92901222f83d Merge tag 'f2fs-for-6-6-rc1' of git://git.ker..
git tree:       upstream
console+strace: https://syzkaller.appspot.com/x/log.txt?x=16880848680000
kernel config:  https://syzkaller.appspot.com/x/.config?x=3d78b3780d210e21
dashboard link: https://syzkaller.appspot.com/bug?extid=4fcffdd85e518af6f129
compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Debian) 2.40
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=17933a00680000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=12ef7104680000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/f58f2fdc5a9e/disk-92901222.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/16dba3905664/vmlinux-92901222.xz
kernel image: https://storage.googleapis.com/syzbot-assets/3a5b1d5efdbd/bzImage-92901222.xz
mounted in repro: https://storage.googleapis.com/syzbot-assets/821293a2c99e/mount_0.gz

The issue was bisected to:

commit 47b7ec1daa511cd82cb9c31e88bfdb664b031d2a
Author: Andrew Price <anprice@redhat.com>
Date:   Fri Feb 5 17:10:17 2021 +0000

    gfs2: Enable rgrplvb for sb_fs_format 1802

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=16c9842ba80000
final oops:     https://syzkaller.appspot.com/x/report.txt?x=15c9842ba80000
console output: https://syzkaller.appspot.com/x/log.txt?x=11c9842ba80000

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+4fcffdd85e518af6f129@syzkaller.appspotmail.com
Fixes: 47b7ec1daa51 ("gfs2: Enable rgrplvb for sb_fs_format 1802")

INFO: task kworker/u4:5:138 blocked for more than 143 seconds.
      Not tainted 6.5.0-syzkaller-11075-g92901222f83d #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:kworker/u4:5    state:D stack:21344 pid:138   ppid:2      flags:0x00004000
Workqueue: writeback wb_workfn (flush-7:0)
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5382 [inline]
 __schedule+0x1873/0x48f0 kernel/sched/core.c:6695
 schedule+0xc3/0x180 kernel/sched/core.c:6771
 io_schedule+0x8c/0x100 kernel/sched/core.c:9026
 folio_wait_bit_common+0x871/0x12a0 mm/filemap.c:1304
 folio_lock include/linux/pagemap.h:1042 [inline]
 write_cache_pages+0x517/0x13f0 mm/page-writeback.c:2441
 iomap_writepages+0x68/0x240 fs/iomap/buffered-io.c:1979
 gfs2_writepages+0x169/0x1f0 fs/gfs2/aops.c:191
 do_writepages+0x3a6/0x670 mm/page-writeback.c:2553
 __writeback_single_inode+0x155/0xfa0 fs/fs-writeback.c:1603
 writeback_sb_inodes+0x8e3/0x11d0 fs/fs-writeback.c:1894
 __writeback_inodes_wb+0x11b/0x260 fs/fs-writeback.c:1965
 wb_writeback+0x461/0xc60 fs/fs-writeback.c:2072
 wb_check_background_flush fs/fs-writeback.c:2142 [inline]
 wb_do_writeback fs/fs-writeback.c:2230 [inline]
 wb_workfn+0xc6f/0xff0 fs/fs-writeback.c:2257
 process_one_work+0x781/0x1130 kernel/workqueue.c:2630
 process_scheduled_works kernel/workqueue.c:2703 [inline]
 worker_thread+0xabf/0x1060 kernel/workqueue.c:2784
 kthread+0x2b8/0x350 kernel/kthread.c:388
 ret_from_fork+0x48/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304
 </TASK>
INFO: task syz-executor336:5029 blocked for more than 143 seconds.
      Not tainted 6.5.0-syzkaller-11075-g92901222f83d #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor336 state:D stack:23408 pid:5029  ppid:5028   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5382 [inline]
 __schedule+0x1873/0x48f0 kernel/sched/core.c:6695
 schedule+0xc3/0x180 kernel/sched/core.c:6771
 io_schedule+0x8c/0x100 kernel/sched/core.c:9026
 folio_wait_bit_common+0x871/0x12a0 mm/filemap.c:1304
 folio_lock include/linux/pagemap.h:1042 [inline]
 write_cache_pages+0x517/0x13f0 mm/page-writeback.c:2441
 iomap_writepages+0x68/0x240 fs/iomap/buffered-io.c:1979
 gfs2_writepages+0x169/0x1f0 fs/gfs2/aops.c:191
 do_writepages+0x3a6/0x670 mm/page-writeback.c:2553
 filemap_fdatawrite_wbc+0x125/0x180 mm/filemap.c:393
 __filemap_fdatawrite_range mm/filemap.c:426 [inline]
 __filemap_fdatawrite mm/filemap.c:432 [inline]
 filemap_fdatawrite+0x143/0x1b0 mm/filemap.c:437
 gfs2_ordered_write fs/gfs2/log.c:740 [inline]
 gfs2_log_flush+0xa42/0x25f0 fs/gfs2/log.c:1098
 gfs2_trans_end+0x39f/0x560 fs/gfs2/trans.c:158
 gfs2_page_mkwrite+0x1262/0x14f0 fs/gfs2/file.c:533
 do_page_mkwrite+0x197/0x470 mm/memory.c:2931
 do_shared_fault mm/memory.c:4647 [inline]
 do_fault mm/memory.c:4709 [inline]
 do_pte_missing mm/memory.c:3669 [inline]
 handle_pte_fault mm/memory.c:4978 [inline]
 __handle_mm_fault mm/memory.c:5119 [inline]
 handle_mm_fault+0x22b2/0x6200 mm/memory.c:5284
 do_user_addr_fault arch/x86/mm/fault.c:1413 [inline]
 handle_page_fault arch/x86/mm/fault.c:1505 [inline]
 exc_page_fault+0x2ac/0x860 arch/x86/mm/fault.c:1561
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:570
RIP: 0033:0x7f088fba48e7
RSP: 002b:00007fff09b9e550 EFLAGS: 00010286
RAX: 0030656c69662f2e RBX: 0000000000000000 RCX: 0000000020000180
RDX: 00000000c018937d RSI: 00000000ffffffff RDI: 0000000000000010
RBP: 00007f088fc5f5f0 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000005 R11: 0000000000000246 R12: 00007fff09b9e580
R13: 00007fff09b9e7a8 R14: 431bde82d7b634db R15: 00007f088fc2203b
 </TASK>
INFO: task gfs2_logd:5032 blocked for more than 144 seconds.
      Not tainted 6.5.0-syzkaller-11075-g92901222f83d #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:gfs2_logd       state:D stack:28672 pid:5032  ppid:2      flags:0x00004000
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5382 [inline]
 __schedule+0x1873/0x48f0 kernel/sched/core.c:6695
 schedule+0xc3/0x180 kernel/sched/core.c:6771
 schedule_preempt_disabled+0x13/0x20 kernel/sched/core.c:6830
 rwsem_down_write_slowpath+0xedd/0x13a0 kernel/locking/rwsem.c:1178
 __down_write_common+0x1aa/0x200 kernel/locking/rwsem.c:1306
 gfs2_log_flush+0x105/0x25f0 fs/gfs2/log.c:1042
 gfs2_logd+0x488/0xec0 fs/gfs2/log.c:1325
 kthread+0x2b8/0x350 kernel/kthread.c:388
 ret_from_fork+0x48/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304
 </TASK>
INFO: task gfs2_quotad:5033 blocked for more than 144 seconds.
      Not tainted 6.5.0-syzkaller-11075-g92901222f83d #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:gfs2_quotad     state:D stack:27216 pid:5033  ppid:2      flags:0x00004000
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5382 [inline]
 __schedule+0x1873/0x48f0 kernel/sched/core.c:6695
 schedule+0xc3/0x180 kernel/sched/core.c:6771
 schedule_preempt_disabled+0x13/0x20 kernel/sched/core.c:6830
 rwsem_down_read_slowpath+0x5f4/0x950 kernel/locking/rwsem.c:1086
 __down_read_common kernel/locking/rwsem.c:1250 [inline]
 __down_read kernel/locking/rwsem.c:1263 [inline]
 down_read+0x9c/0x2f0 kernel/locking/rwsem.c:1522
 __gfs2_trans_begin+0x55c/0x940 fs/gfs2/trans.c:87
 gfs2_trans_begin+0x71/0xe0 fs/gfs2/trans.c:118
 gfs2_statfs_sync+0x41e/0x870 fs/gfs2/super.c:298
 quotad_check_timeo fs/gfs2/quota.c:1510 [inline]
 gfs2_quotad+0x37f/0x680 fs/gfs2/quota.c:1552
 kthread+0x2b8/0x350 kernel/kthread.c:388
 ret_from_fork+0x48/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304
 </TASK>
INFO: lockdep is turned off.
NMI backtrace for cpu 0
CPU: 0 PID: 29 Comm: khungtaskd Not tainted 6.5.0-syzkaller-11075-g92901222f83d #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 07/26/2023
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:88 [inline]
 dump_stack_lvl+0x1e7/0x2d0 lib/dump_stack.c:106
 nmi_cpu_backtrace+0x498/0x4d0 lib/nmi_backtrace.c:113
 nmi_trigger_cpumask_backtrace+0x198/0x310 lib/nmi_backtrace.c:62
 trigger_all_cpu_backtrace include/linux/nmi.h:160 [inline]
 check_hung_uninterruptible_tasks kernel/hung_task.c:222 [inline]
 watchdog+0xdf5/0xe40 kernel/hung_task.c:379
 kthread+0x2b8/0x350 kernel/kthread.c:388
 ret_from_fork+0x48/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304
 </TASK>
Sending NMI from CPU 0 to CPUs 1:
NMI backtrace for cpu 1
CPU: 1 PID: 68 Comm: kworker/u4:4 Not tainted 6.5.0-syzkaller-11075-g92901222f83d #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 07/26/2023
Workqueue: events_unbound toggle_allocation_gate
RIP: 0010:__insn_get_emulate_prefix arch/x86/lib/insn.c:91 [inline]
RIP: 0010:insn_get_emulate_prefix arch/x86/lib/insn.c:106 [inline]
RIP: 0010:insn_get_prefixes+0x113/0x18a0 arch/x86/lib/insn.c:134
Code: 0f b6 04 03 84 c0 0f 85 fd 10 00 00 41 0f b6 6d 00 bf 0f 00 00 00 89 ee e8 5a 5e c8 f6 4d 8d 65 02 83 fd 0f 0f 85 15 01 00 00 <4d> 39 f4 0f 87 0c 01 00 00 48 8b 44 24 08 48 c1 e8 03 48 b9 00 00
RSP: 0018:ffffc90001597660 EFLAGS: 00000246
RAX: 0000000000000000 RBX: 1ffffffff160ae95 RCX: ffffffff8b0574ab
RDX: ffff888018ab8000 RSI: 000000000000000f RDI: 000000000000000f
RBP: 000000000000000f R08: ffffffff8ac531f6 R09: 0000000000000000
R10: ffffc900015979c0 R11: fffff520002b2f43 R12: ffffffff8b0574ac
R13: ffffffff8b0574aa R14: ffffffff8b0574b9 R15: ffffc900015979c0
FS:  0000000000000000(0000) GS:ffff8880b9900000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 0000555efaf520e8 CR3: 000000000d130000 CR4: 00000000003506e0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
 <NMI>
 </NMI>
 <TASK>
 insn_get_opcode+0x1b2/0xa50 arch/x86/lib/insn.c:272
 insn_get_modrm+0x22e/0x7a0 arch/x86/lib/insn.c:343
 insn_get_sib arch/x86/lib/insn.c:421 [inline]
 insn_get_displacement+0x13e/0x980 arch/x86/lib/insn.c:464
 insn_get_immediate+0x382/0x13d0 arch/x86/lib/insn.c:632
 insn_get_length arch/x86/lib/insn.c:707 [inline]
 insn_decode+0x370/0x500 arch/x86/lib/insn.c:747
 text_poke_loc_init+0xed/0x860 arch/x86/kernel/alternative.c:2312
 arch_jump_label_transform_queue+0x8b/0xf0 arch/x86/kernel/jump_label.c:138
 __jump_label_update+0x177/0x3a0 kernel/jump_label.c:475
 static_key_disable_cpuslocked+0xce/0x1b0 kernel/jump_label.c:235
 static_key_disable+0x1a/0x20 kernel/jump_label.c:243
 toggle_allocation_gate+0x1b8/0x250 mm/kfence/core.c:834
 process_one_work+0x781/0x1130 kernel/workqueue.c:2630
 process_scheduled_works kernel/workqueue.c:2703 [inline]
 worker_thread+0xabf/0x1060 kernel/workqueue.c:2784
 kthread+0x2b8/0x350 kernel/kthread.c:388
 ret_from_fork+0x48/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x11/0x20 arch/x86/entry/entry_64.S:304
 </TASK>
INFO: NMI handler (nmi_cpu_backtrace_handler) took too long to run: 1.251 msecs


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
For information about bisection process see: https://goo.gl/tpsmEJ#bisection

If the bug is already fixed, let syzbot know by replying with:
#syz fix: exact-commit-title

If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

If you want to overwrite bug's subsystems, reply with:
#syz set subsystems: new-subsystem
(See the list of subsystem names on the web dashboard)

If the bug is a duplicate of another bug, reply with:
#syz dup: exact-subject-of-another-report

If you want to undo deduplication, reply with:
#syz undup

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000001f905c0604837659%40google.com.
