Return-Path: <kasan-dev+bncBCQPF57GUQHBBGOQ5KEQMGQE7Y36QGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 530E440610F
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:34:34 +0200 (CEST)
Received: by mail-qv1-xf3b.google.com with SMTP id h9-20020a05621413a900b0037a2d3eaf8fsf660466qvz.8
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:34:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631234073; cv=pass;
        d=google.com; s=arc-20160816;
        b=JMoRaQ/le7uYQXzKkKvynrrRYrnDbb1BeYAverdiThMUBBIKjgUN77uxpbiwfSMi4W
         KMe+pNgy20ZZXNfRnCLt41YkDPX4+pgtf1/QSqMWjXAmivubqHAIB80DIFe+C/5QxXKe
         bf9vR1bhITdtSZ08aVazsPB0xttEMv4KttBrarB/wt/wwYFIy+CpZbX8uw1sQSCUrSKX
         AnCsIJx5hR3ZxchyHuQ5PLyDi0aJr+haq+KWtUrmXQwWeYuugVnRYqMFW3m4MPLVXPQC
         kERKdLcf5m6O02JeeqoTgh3hKG3ghlfklZtkmpsODlkW4AT2kSv/PcxUJSIzqz0XwhR0
         ppow==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=34rx63hclRrGI3JUB2qfu59XZrdJq7Bs6z1zk5CAP+A=;
        b=gs2gIkJ1hrqTfMR4Zdmr+8OuYX0II9JkUIfUcTd6+1Dw0iqRG73lKQe4uTbm8JlKAH
         ZlGHpwpmyuh1CG+lJcmqUsvGFe07+nVuDEPdAVblPp8/lRwS7T3GrP0tME5Ka+CeGOz+
         HsT3RwOVODH60B7zHGdrOFuL6frqVnx7WdjU0khdDuIwp6Y0APKrf7pmcXjwmM5Eu/hI
         jNYpS41CsGT1SwU6o+o1mXHeimJvarEZGXhBZwXq69dkgFBIc8gYUOfBofpWcq5iKYJT
         14tDBiUfbcUzNChrKGFxAhtMDC5b6wV/dcAnQPf7F03fd8ZNjxzmHybA5sPN3bq6KKs3
         rPkQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3gkg6yqkbagmtzalbmmfsbqqje.hpphmfvtfsdpoufou.dpn@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.72 as permitted sender) smtp.mailfrom=3GKg6YQkbAGMTZaLBMMFSBQQJE.HPPHMFVTFSDPOUFOU.DPN@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:date:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=34rx63hclRrGI3JUB2qfu59XZrdJq7Bs6z1zk5CAP+A=;
        b=rt4EfcypOvjjh60l92JG/cbaaQ6Dd+NtkvFD6snffrzdaNqGks0e/jsdkdLHrx9R56
         XgDVykiC7iGFislOQJNWFlF3mcUqnHuJ3EGfg+xyr/I3jVbdEtKZYd+T9S6/1NKZhc3k
         g07wSANxUt7fTO0UF7VuWKjs16HWhNzs0SFrYBqY0xtp010kuRxjQP2dCNihxb0drmE6
         8BoyiZs7cRkLEKBTxdUd0LpH0/FBRwfByi8aOOuuBjcaceJ6Ifcw7hYbiBBkwMebKQG2
         oLMZRlKb7s+od06gTxvbDPaQ8f8/Vqf25yo6qfxBM6yy6BaLNvxI9nu3nAqUzPDYv6BO
         hVeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:date:message-id:subject:from
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=34rx63hclRrGI3JUB2qfu59XZrdJq7Bs6z1zk5CAP+A=;
        b=lLYrMXXnuUUXpkP/CBimUDWMO/Hz64d4fwWMTj+3dzzUu42JtHooz0FuMLb81i0V0W
         8oYiuZV05hC2k6cxMB5u67xtZGLrX5XFaWArHnpA+Qa12DZ7Aj6qhTEVMUEu+F9HEOqT
         mgmnP9EGIkJE9bEvVX4wdfnfE3kjjK4LlAVDkk0M1A1f0sHpNwjoxM2YjU/0c0pOiMPi
         g9vjQl17EWKOgI0+IjMXmqa3VpA3UdWBBO9XLVdGftDOXfa9onSrWJ8UPD4xgpFLL6ka
         ULST0Fs6mr3M9eBCHxk8rBuWeZPGMAEWo2PdTBHwn146gum5be5Qy5Kz5BrdTrV1Lzxd
         AEZg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532o2AWvVN9kS1q/k0ix/iFO+8WuPLtnJhps/tErhQwAU+YWWgp4
	K1ZAQx9YdlmbVDDwL17VLNY=
X-Google-Smtp-Source: ABdhPJzx1KE3z8MTOw5kAM82Xa8/k64CJcFZ5qLufLauXf/h9pixytKQQYqC7GxMeCeQUptCFjhu/A==
X-Received: by 2002:a05:620a:14ad:: with SMTP id x13mr5552089qkj.172.1631234073469;
        Thu, 09 Sep 2021 17:34:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6782:: with SMTP id b2ls2106867qtp.11.gmail; Thu, 09 Sep
 2021 17:34:33 -0700 (PDT)
X-Received: by 2002:ac8:7f51:: with SMTP id g17mr5575656qtk.16.1631234073008;
        Thu, 09 Sep 2021 17:34:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631234073; cv=none;
        d=google.com; s=arc-20160816;
        b=iZUn8StJtJBYxPLxCBj2VAFifXTbdRPG71MkTgOBJqWNU+0hhATbvy0aJIBiPLKiDs
         GMnXpR3YFTmL/yr9dscWKdVsa35L70tjdTZTJRbAmEqpzZfFN6+PiGITnrZNjiyUAv1g
         551yqv7UThvwa2KKVJpOz7rVMBhRfRfzeX7lmYiY98dCPtWsoamnph/4wik2CuKok5tZ
         cDQEjI4qm/vvod6OUXrahoEL8rncaB1o1y709EGbCqwvDEPzkKN2+kFdGfp10or+isRg
         Y+O9cRy7ZAXq8/fUlmZXhlVPPDmcWiupI2/YR1Yaey/XDGoD2Q8lisN5/XuVtB9S4esy
         bt6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:date:mime-version;
        bh=7Dh5mijrqSL6MQmilhCXyQSFiAQjt8KP7FPQ6faPMOw=;
        b=yf7TTwj0DVXMblc9+CEF69nfywzq8tiQElt8TdCfUL5Auw6znjfrYxYft7X9qh6plP
         9tllt7quH2h4Jxdek9rl9iY0ta6q3s3me+LV/LFbwTkGvwb7wHHfeooI3JrMPyBH5kEi
         qsaW6+k03lZLO4VuHAIu6kyBazeXTqCii2VpAv6BR9ul6vzQQSq5QQ6e4+CneyABsBZX
         Pcz1D+NUn4U1bS63DH64V0y1NeRnIkoXAdFgBAUmwX+YkNUIzxZtvLvuvN44LL85Q6Ve
         LU5gmAkFUkQYVVOvmuGXtVPLvPvjR/J18RLkcnKXorS2sjjlpaCkljQFO2iQigx6MVRZ
         tbCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3gkg6yqkbagmtzalbmmfsbqqje.hpphmfvtfsdpoufou.dpn@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.72 as permitted sender) smtp.mailfrom=3GKg6YQkbAGMTZaLBMMFSBQQJE.HPPHMFVTFSDPOUFOU.DPN@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f72.google.com (mail-io1-f72.google.com. [209.85.166.72])
        by gmr-mx.google.com with ESMTPS id f13si276849qko.2.2021.09.09.17.34.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:34:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gkg6yqkbagmtzalbmmfsbqqje.hpphmfvtfsdpoufou.dpn@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.72 as permitted sender) client-ip=209.85.166.72;
Received: by mail-io1-f72.google.com with SMTP id h3-20020a056602008300b005b7c0e23e11so126543iob.4
        for <kasan-dev@googlegroups.com>; Thu, 09 Sep 2021 17:34:32 -0700 (PDT)
MIME-Version: 1.0
X-Received: by 2002:a92:bf01:: with SMTP id z1mr1018591ilh.155.1631234072620;
 Thu, 09 Sep 2021 17:34:32 -0700 (PDT)
Date: Thu, 09 Sep 2021 17:34:32 -0700
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <00000000000071b5b105cb994728@google.com>
Subject: [syzbot] kernel panic: panic_on_warn set (3)
From: syzbot <syzbot+8d41ad9c88279d71f7c9@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3gkg6yqkbagmtzalbmmfsbqqje.hpphmfvtfsdpoufou.dpn@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.72 as permitted sender) smtp.mailfrom=3GKg6YQkbAGMTZaLBMMFSBQQJE.HPPHMFVTFSDPOUFOU.DPN@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    ac08b1c68d1b Merge tag 'pci-v5.15-changes' of git://git.ke..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=16144a63300000
kernel config:  https://syzkaller.appspot.com/x/.config?x=16e23f04679ec35e
dashboard link: https://syzkaller.appspot.com/bug?extid=8d41ad9c88279d71f7c9
compiler:       gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.1
userspace arch: i386
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=136aedb5300000

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+8d41ad9c88279d71f7c9@syzkaller.appspotmail.com

 handle drivers/base/devtmpfs.c:382 [inline]
 devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
 devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
 kthread+0x3e5/0x4d0 kernel/kthread.c:319
 ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
==================================================================
Kernel panic - not syncing: panic_on_warn set ...
CPU: 0 PID: 22 Comm: kdevtmpfs Not tainted 5.14.0-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 01/01/2011
Call Trace:
 __dump_stack lib/dump_stack.c:88 [inline]
 dump_stack_lvl+0xcd/0x134 lib/dump_stack.c:105
 panic+0x2b0/0x6dd kernel/panic.c:232
 kfence_report_error.cold+0x304/0xa56 mm/kfence/report.c:264
 kfence_handle_page_fault+0x203/0x630 mm/kfence/core.c:880
 page_fault_oops+0x1c5/0x6b0 arch/x86/mm/fault.c:686
 kernelmode_fixup_or_oops+0x219/0x280 arch/x86/mm/fault.c:755
 __bad_area_nosemaphore+0x36d/0x400 arch/x86/mm/fault.c:801
 do_kern_addr_fault+0x5b/0x70 arch/x86/mm/fault.c:1200
 handle_page_fault arch/x86/mm/fault.c:1473 [inline]
 exc_page_fault+0x155/0x180 arch/x86/mm/fault.c:1531
 asm_exc_page_fault+0x1e/0x30 arch/x86/include/asm/idtentry.h:568
RIP: 0010:kvm_fastop_exception+0xf6a/0x1058
Code: d3 ed e9 ef d4 6e f8 49 8d 0e 48 83 e1 f8 4c 8b 21 41 8d 0e 83 e1 07 c1 e1 03 49 d3 ec e9 45 e2 6e f8 49 8d 4d 00 48 83 e1 f8 <4c> 8b 21 41 8d 4d 00 83 e1 07 c1 e1 03 49 d3 ec e9 35 ec 6e f8 bd
RSP: 0018:ffffc90000dcfae8 EFLAGS: 00010282
RAX: 0000003361736376 RBX: ffff88806f1e3068 RCX: ffff88823bd14020
RDX: ffffed100de3c614 RSI: 0000000000000005 RDI: 0000000000000007
RBP: 0000000000000005 R08: 0000000000000000 R09: ffff88806f1e3098
R10: ffffed100de3c613 R11: 0000000000000000 R12: ffff88823bd14020
R13: ffff88823bd14020 R14: ffff88806f1e3098 R15: dffffc0000000000
 d_lookup+0xd8/0x170 fs/dcache.c:2370
 lookup_dcache+0x1e/0x130 fs/namei.c:1520
 __lookup_hash+0x29/0x180 fs/namei.c:1543
 kern_path_locked+0x17e/0x320 fs/namei.c:2567
 handle_remove+0xa2/0x5fe drivers/base/devtmpfs.c:312
 handle drivers/base/devtmpfs.c:382 [inline]
 devtmpfs_work_loop drivers/base/devtmpfs.c:395 [inline]
 devtmpfsd+0x1b9/0x2a3 drivers/base/devtmpfs.c:437
 kthread+0x3e5/0x4d0 kernel/kthread.c:319
 ret_from_fork+0x1f/0x30 arch/x86/entry/entry_64.S:295
Kernel Offset: disabled
----------------
Code disassembly (best guess):
   0:	d3 ed                	shr    %cl,%ebp
   2:	e9 ef d4 6e f8       	jmpq   0xf86ed4f6
   7:	49 8d 0e             	lea    (%r14),%rcx
   a:	48 83 e1 f8          	and    $0xfffffffffffffff8,%rcx
   e:	4c 8b 21             	mov    (%rcx),%r12
  11:	41 8d 0e             	lea    (%r14),%ecx
  14:	83 e1 07             	and    $0x7,%ecx
  17:	c1 e1 03             	shl    $0x3,%ecx
  1a:	49 d3 ec             	shr    %cl,%r12
  1d:	e9 45 e2 6e f8       	jmpq   0xf86ee267
  22:	49 8d 4d 00          	lea    0x0(%r13),%rcx
  26:	48 83 e1 f8          	and    $0xfffffffffffffff8,%rcx
* 2a:	4c 8b 21             	mov    (%rcx),%r12 <-- trapping instruction
  2d:	41 8d 4d 00          	lea    0x0(%r13),%ecx
  31:	83 e1 07             	and    $0x7,%ecx
  34:	c1 e1 03             	shl    $0x3,%ecx
  37:	49 d3 ec             	shr    %cl,%r12
  3a:	e9 35 ec 6e f8       	jmpq   0xf86eec74
  3f:	bd                   	.byte 0xbd


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
syzbot can test patches for this issue, for details see:
https://goo.gl/tpsmEJ#testing-patches

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00000000000071b5b105cb994728%40google.com.
