Return-Path: <kasan-dev+bncBCQPF57GUQHBBKEJTLXQKGQE3VIO7VQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E62CB11018E
	for <lists+kasan-dev@lfdr.de>; Tue,  3 Dec 2019 16:52:09 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id s10sf3195245ilh.7
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 07:52:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575388328; cv=pass;
        d=google.com; s=arc-20160816;
        b=V6ya02LA0a0MjfmWbJ4wfkJkN7d3ECUOR9173BlJUkvig+BNy3Ds3FVbZPDjksm1W5
         JCkiagPOrjVBx9JFiF6mgNVEaPL3TEnLLVo/PNj6q/WznEv+KqtM3rtMlmgDu37MF0O8
         NQ2Lagq+e0mhGdrGEKj1b2kJu3gEn64fLd5OjluX7VgB58xzziXjXEL8ij0cATkTjhRk
         VB1Nrf8Xd5P4Q13G3HS5iCcRm7qV75GibplzqF3u/AbxfzYO0vfVh7T34xPx2EYQz4ZH
         ZvQ188Fe/rrl5/giMXM85WW7nOfCF+s69YVz8ORWBM/4SAgoYWIpZ/AItUx0AyOglQHi
         SHaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=y0SZ7Z9Okh9IkYbmTI2xGhvmLnpxs0FyKZUD0U40G+Q=;
        b=e/9Ax7cdwLdwNZWj93qoqD95Pmkn2CRnLVBcvLXxyEKWB4fkp+BFwWil+ytFPfPJGk
         c/bXQjVYm6MUZUWA60eljlkg1UKLlPnjwVb6EjW6NXo85KIIkQ5wvvVutIUX/2u4EKPX
         CYTBNW5CaK+yAm23oieShq/awWdQeLxXZuAFU0TBwY8aqlv39x8EjcXThMOBgZ+PHiA6
         a723JR3Hcp5TPTN1GxnvX2ujvuWgkNjhgHh23+aamoyxlS2C5zPyjVt+d8aG95WwHfA9
         zis6RWupuhzW0uixmcj8Nfh/IIEJy5sicdWePL46iVAzWCHG0mJXbZ6RUlfkLqrix8KL
         jIew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3p4tmxqkbaeau01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.70 as permitted sender) smtp.mailfrom=3p4TmXQkbAEAu01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=y0SZ7Z9Okh9IkYbmTI2xGhvmLnpxs0FyKZUD0U40G+Q=;
        b=IjmkRg1OvaRobTWLPk9dgwxagKEKh2XFc9GWDhhtY9EOClNrE+GRj80WVFEc3CCB59
         muykLitDwJtMfoKkD1NlRQL7bIkaLd7Z2X0Edc1eymO2TyXmkC7fv83jSdhBvM7GIRvh
         1B+n8z1dtY3mtJZJdKDtfUiflWRcqoWQ0Dqr6m73mbt24z4NadsO2v0K8tggc6ncmicu
         cqto+tAd/k37o2hWiCuyU3ufeONemnoC9wHOEowCbWAv6mo6gGIkbC0yLfTBBnl/vXPA
         NkQWhhldTn1ev7jdiqx0U3k4Q0hkoEbiG2XaYGGASb4wrs6FH90JwUj3JD9Uh+MqrUD4
         hUuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=y0SZ7Z9Okh9IkYbmTI2xGhvmLnpxs0FyKZUD0U40G+Q=;
        b=CA3Tpds1hZxSHEjh53/cmylFXd0r+m5apbjhsvAQijxUkqynPTr9rnifJowl1QwSAt
         +eom21YnTZlLMI+Isxmw/MnOTNFXnA9bq8wSJJ+9v3N8NtJ7Zz6sMXWWoYPNIaADTD5R
         XiG2u1AKuAffsJWSBFfDPXEGF/5OjRGvVm1Xhy0UR0W+2Yb70v57N2B+w7rjpWC/pEJQ
         dbFYvFJNUdXrK/hEEm3O5Hyn9t4RZflvwOo0FSZqEdGEqSaPSyHASLNkMJWgzgrLsrbj
         HgOfUkExUSL/xXhlrt42t2JbeXyCc9f3y77kVKJKtV1Tk6fRnKlrn6hSWY7130RHLZvy
         6Spg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXKgi8oZPyBqZvjPexxtqokBThmijrd2kCMUWxSzEGK8WKzGuto
	R2mbbUGSpKkUxLuwRqwi2u4=
X-Google-Smtp-Source: APXvYqxHXOFvw8omZCaKjNYVSwR+2q99/7Aa6mBILk9KiC+GNnhN/r8m1/AsOOKPJ5x1AtPTZCkPVA==
X-Received: by 2002:a92:8311:: with SMTP id f17mr5496628ild.82.1575388328619;
        Tue, 03 Dec 2019 07:52:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5e:960e:: with SMTP id a14ls536593ioq.11.gmail; Tue, 03 Dec
 2019 07:52:08 -0800 (PST)
X-Received: by 2002:a5d:964a:: with SMTP id d10mr2757302ios.231.1575388328159;
        Tue, 03 Dec 2019 07:52:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575388328; cv=none;
        d=google.com; s=arc-20160816;
        b=Qjed/woszm7eSbpoQ/gPPpheKFJLooG+QM7CP759txLxcYIWE/Kpt51b0/u1mtia56
         fOmllFBj0Np2QaQB5DDtEsSPgNkCMV9cnZf1uV7unQ/2JEmBOqNQp0dTTpQSrUvf4/tR
         yCHaRon1pxKl2O0bxnAFFyTsNduzkXboluH75YbCRjaQ3/SSWdILwO72dF0YwHWZ6Y7i
         1AmUkPMaeTDjEWGmkt0rDrCRH7K8w7u0kJ6FkdY9tpX/uLAjRMnLLWNUWFsWeXjGZFIA
         2dUWjZiHOB2wwgm/r3IXxDPQJrKS9UYptl52HmXXun46JuK3SrLMU95K3z8Yrq1U5UNk
         pw0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=qWkyIPu2o6vdgwTgEGOSkN6/EDBPIm6eU4NPNmjP8sE=;
        b=PObBJfktgd+NvPuIGT37luHpiIVzkBJKvg7cj7AUywtl/AeloIO2FDT98ZhaFO8Emc
         yxRmsflBwNuccF8MhYMxHEOl1mce+eKO0b+fgpLOAQntZOKqdDdMAFAfic/tZO1Qi4aX
         7hH8ygUIiK2ebduk9vsKsDjxRadzeCfF+OG+1yBNhd+ARTSuva5IX6stX0fPtaiykm8M
         bb8gUPp2nGldEfzRKk7T9ll2CuAOO9sWXcUNd770O1WKUQ2p1sMiQL7iO56/Gp/8jh27
         id+2fZSD+v6hkc/2xaOBLSK08xVqvH4nf0Zsa80YL1mowMbuW5PGd//yUyhRMFDw2ba3
         SKPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3p4tmxqkbaeau01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.70 as permitted sender) smtp.mailfrom=3p4TmXQkbAEAu01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f70.google.com (mail-io1-f70.google.com. [209.85.166.70])
        by gmr-mx.google.com with ESMTPS id k9si214247ili.4.2019.12.03.07.52.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Dec 2019 07:52:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3p4tmxqkbaeau01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.70 as permitted sender) client-ip=209.85.166.70;
Received: by mail-io1-f70.google.com with SMTP id q4so2741221ion.5
        for <kasan-dev@googlegroups.com>; Tue, 03 Dec 2019 07:52:08 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a5d:8744:: with SMTP id k4mr2936669iol.227.1575388327907;
 Tue, 03 Dec 2019 07:52:07 -0800 (PST)
Date: Tue, 03 Dec 2019 07:52:07 -0800
In-Reply-To: <00000000000080f1d305988bb8ba@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000ab3afd0598cead51@google.com>
Subject: Re: BUG: unable to handle kernel paging request in ion_heap_clear_pages
From: syzbot <syzbot+be6ccf3081ce8afd1b56@syzkaller.appspotmail.com>
To: arve@android.com, christian@brauner.io, devel@driverdev.osuosl.org, 
	dja@axtens.net, dri-devel@lists.freedesktop.org, dvyukov@google.com, 
	gregkh@linuxfoundation.org, joel@joelfernandes.org, 
	kasan-dev@googlegroups.com, labbott@redhat.com, 
	linaro-mm-sig-owner@lists.linaro.org, linaro-mm-sig@lists.linaro.org, 
	linux-kernel@vger.kernel.org, maco@android.com, sumit.semwal@linaro.org, 
	syzkaller-bugs@googlegroups.com, tkjos@android.com
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3p4tmxqkbaeau01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.70 as permitted sender) smtp.mailfrom=3p4TmXQkbAEAu01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

syzbot has found a reproducer for the following crash on:

HEAD commit:    76bb8b05 Merge tag 'kbuild-v5.5' of git://git.kernel.org/p..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=159d0f36e00000
kernel config:  https://syzkaller.appspot.com/x/.config?x=dd226651cb0f364b
dashboard link: https://syzkaller.appspot.com/bug?extid=be6ccf3081ce8afd1b56
compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=171f677ae00000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=11db659ce00000

IMPORTANT: if you fix the bug, please add the following tag to the commit:
Reported-by: syzbot+be6ccf3081ce8afd1b56@syzkaller.appspotmail.com

BUG: unable to handle page fault for address: fffff52000680000
#PF: supervisor read access in kernel mode
#PF: error_code(0x0000) - not-present page
PGD 21ffee067 P4D 21ffee067 PUD aa51c067 PMD a8372067 PTE 0
Oops: 0000 [#1] PREEMPT SMP KASAN
CPU: 1 PID: 3666 Comm: ion_system_heap Not tainted 5.4.0-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS  
Google 01/01/2011
RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
RIP: 0010:check_memory_region+0x9c/0x1a0 mm/kasan/generic.c:192
Code: c9 4d 0f 49 c1 49 c1 f8 03 45 85 c0 0f 84 10 01 00 00 41 83 e8 01 4e  
8d 44 c0 08 eb 0d 48 83 c0 08 4c 39 c0 0f 84 a7 00 00 00 <48> 83 38 00 74  
ed 4c 8d 40 08 eb 09 48 83 c0 01 49 39 c0 74 53 80
RSP: 0018:ffffc9000cf87ab8 EFLAGS: 00010212
RAX: fffff52000680000 RBX: fffff52000681600 RCX: ffffffff85d95629
RDX: 0000000000000001 RSI: 000000000000b000 RDI: ffffc90003400000
RBP: ffffc9000cf87ad0 R08: fffff52000681600 R09: 0000000000001600
R10: fffff520006815ff R11: ffffc9000340afff R12: fffff52000680000
R13: 000000000000b000 R14: 0000000000000000 R15: ffffc9000cf87d08
FS:  0000000000000000(0000) GS:ffff8880ae900000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: fffff52000680000 CR3: 00000000a6755000 CR4: 00000000001406e0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
  memset+0x24/0x40 mm/kasan/common.c:107
  memset include/linux/string.h:365 [inline]
  ion_heap_clear_pages+0x49/0x70 drivers/staging/android/ion/ion_heap.c:106
  ion_heap_sglist_zero+0x245/0x270 drivers/staging/android/ion/ion_heap.c:130
  ion_heap_buffer_zero+0xf5/0x150 drivers/staging/android/ion/ion_heap.c:145
  ion_system_heap_free+0x1eb/0x250  
drivers/staging/android/ion/ion_system_heap.c:163
  ion_buffer_destroy+0x159/0x2d0 drivers/staging/android/ion/ion.c:93
  ion_heap_deferred_free+0x29d/0x630  
drivers/staging/android/ion/ion_heap.c:239
  kthread+0x361/0x430 kernel/kthread.c:255
  ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352
Modules linked in:
CR2: fffff52000680000
---[ end trace 6d0e26662c48296a ]---
RIP: 0010:memory_is_nonzero mm/kasan/generic.c:121 [inline]
RIP: 0010:memory_is_poisoned_n mm/kasan/generic.c:135 [inline]
RIP: 0010:memory_is_poisoned mm/kasan/generic.c:166 [inline]
RIP: 0010:check_memory_region_inline mm/kasan/generic.c:182 [inline]
RIP: 0010:check_memory_region+0x9c/0x1a0 mm/kasan/generic.c:192
Code: c9 4d 0f 49 c1 49 c1 f8 03 45 85 c0 0f 84 10 01 00 00 41 83 e8 01 4e  
8d 44 c0 08 eb 0d 48 83 c0 08 4c 39 c0 0f 84 a7 00 00 00 <48> 83 38 00 74  
ed 4c 8d 40 08 eb 09 48 83 c0 01 49 39 c0 74 53 80
RSP: 0018:ffffc9000cf87ab8 EFLAGS: 00010212
RAX: fffff52000680000 RBX: fffff52000681600 RCX: ffffffff85d95629
RDX: 0000000000000001 RSI: 000000000000b000 RDI: ffffc90003400000
RBP: ffffc9000cf87ad0 R08: fffff52000681600 R09: 0000000000001600
R10: fffff520006815ff R11: ffffc9000340afff R12: fffff52000680000
R13: 000000000000b000 R14: 0000000000000000 R15: ffffc9000cf87d08
FS:  0000000000000000(0000) GS:ffff8880ae900000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: fffff52000680000 CR3: 00000000a6755000 CR4: 00000000001406e0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000ab3afd0598cead51%40google.com.
