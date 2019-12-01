Return-Path: <kasan-dev+bncBCQPF57GUQHBBDFQR7XQKGQE54VGNSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 49E9F10E24F
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Dec 2019 16:11:10 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id o144sf16593670vko.13
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Dec 2019 07:11:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575213069; cv=pass;
        d=google.com; s=arc-20160816;
        b=SsNjdGLQvS1+bMuJfi5FSPug97iRzFLUP+2Jqqe4Vl+Uegx0ozwIwgpjCVxb/qwHnL
         NhqHo2VGFK+mFXWSmekS8HMkOBon9Todvl+KKGrH4dgwxT8noaVQDxh+/PTITIHbndag
         EFZUYwA9wFSHgq17FoBFed71amSIyhLKb+oJfOMJnttw9adHTyK0YOreHt7ifztq/2b1
         ntPHCbrPnwzb39LrwsCRMexjTrIOqbjUIGEdoc+U0Zfuvs8iLvf89+r8xiV7NAqbPwgu
         4eoUvUFuxaON5Y5dOelDtTWQFevX5+e/KZqBJrZJiFNlmQjsCL7dGOfnD1ywQ41fM9b5
         QixQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=qvUzxkIpIGGDdVS9+Lehi7IXN1IxAsWZLLIfLUmchbU=;
        b=B/vSj+pANic7dwvAckVVjVUvft8eIynzIGj0FIe6pCCF6NY5THYOMaLOWWUW0c10Pd
         8FpamknifCw/VVfu2Fbi1DXIVpUT5i/K294Jmf6NqM2cnaT4XeuFlzrNrftZGPsIhcah
         gkTJXJKWfd5cRwMli7gWfbmbepCBnUI/hbR05sJtTQpGuh5v75u1g/9Ef+JCu0Ocf9dO
         zE0YiRXWGYTU9DwIAkD0vJD8wpwTWK+p0Fi11U4PewFBKR/7I+8nxzEXwOvWIb3EzhMc
         xvYo4+lFPjFSM4ze8mnfuV0tCNeaNMMs2gssmNVIrhS3mrd1f+e/MT16idGYsTXWf6AC
         lx6g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3c9jjxqkbaeau01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3C9jjXQkbAEAu01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qvUzxkIpIGGDdVS9+Lehi7IXN1IxAsWZLLIfLUmchbU=;
        b=cUhsGwUIK/1PcgDjD8+/LhngSgbcbUG/IT9jgYwYjer0o5dQ4vef3teLEsN/aLeT35
         qgAmpUaB80bFpzAlhUAZhQjDCq4CIzxylFrMj8GlNeNkYgcY1P4aAMgyrmOLTFKe4Yus
         Nb0BhGmyBC0T9iIk+ZtQAQ1CnycvGQHYFb1wmDKd3/AUSNUiLzXrGZ3lixexOkn/frFX
         VrrB+DX0uFAlVJerjiWv+PDGmmU6mnlBw3zaXdpNp1y1RsAxMjAS2yMEk7K02kixVD7+
         HQMKFsdcS0F17Cs025UpbfaBBEv7EgYr02ptTtRxDIZ3uuHW+LoJlsXbqBXaQhb2MUm0
         COxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=qvUzxkIpIGGDdVS9+Lehi7IXN1IxAsWZLLIfLUmchbU=;
        b=nRsYbQn+hsKCG++n9XJofrhZ5C4IUNgQ4e1+RaJa8v1bW0PHdPUNM2Qg4TPbB2MZRU
         GpUkmymaIpkO9n9ER4kwoVgwuplIIKb7TxX0EgGUJVrBcj/AOZINXguDhwN6ENd0NIQz
         EfRVB9enjP9/P2BZ717LwtiZJdaKgthi1pcCknox7QF00qBt/6e5yBYzewQ0/nes9cAM
         w8C4X274++nBHJk3k6/2j3ALnOzwhwYA7965ec+RQjqaEwTlPoRYnt9VCKA+B+nDgLrv
         xqkGbxAQyMzsj78zNW+y3C0f7X4N9VNVJx8RCgItwPzGRHkhYVGMOOM0Wr7hnL5JSMHO
         1SaA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXQv2VuHG943hw7eASDBY6NU6lP1lrzIIy4ynPmuP8+DXbldzGT
	ftoccRp1Ma0iwa39bYDyT6g=
X-Google-Smtp-Source: APXvYqzIhm+uMNLOptVwzY+r5lHh9V7hg/VWDdqfVAMs0pNue84xn01c4S0sGvNG1oVmC6bMfZCMIA==
X-Received: by 2002:ab0:1c6:: with SMTP id 64mr15481252ual.13.1575213068924;
        Sun, 01 Dec 2019 07:11:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2808:: with SMTP id o8ls203889vko.2.gmail; Sun, 01 Dec
 2019 07:11:08 -0800 (PST)
X-Received: by 2002:a1f:1782:: with SMTP id 124mr3105430vkx.27.1575213068437;
        Sun, 01 Dec 2019 07:11:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575213068; cv=none;
        d=google.com; s=arc-20160816;
        b=zo7u+rUIqSRraGuHdLMv2KQAfD6vCb6zMAfjeEtEa5Y7MI2mqfBTTSCmX3d1Dtl8gI
         GC+DSx9+EGd8uqCWH8tYyH+I3giv6esQu3Lg+zYCv97jCb4qDueeyangXrXhrTmU6I6a
         /MdmQHI0t3w24OhdoCsojoFht3vN2gfwJKq4BElHEjb9eu03HV4h7FtKA3J0PN+c41ON
         dGAs4xYZppFnoJTbOwnGB2tFjFs7utqNBDkrNimq6lvvpCcvle3wu0M8zhpSTjONoiPi
         /ZibLgHeyJyTxCEdjq3SOHJGvsEZBUPgdFnVHB3TTf16rrTZ3MeCKVcP8i/V+4s/tB9V
         d4hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=5CLgl9PicPFQzTSO+Rj6AM4Crp6GMlB9i01lWqmMoZY=;
        b=piy/CsiJeYAVCRpIrHNNeHQyyxHJxQqKKXALNGR/j7LaEtTSsKG8oM/ZWyyiLYCq4+
         i8LLQHtEnwIyVsp3REZw0GY/y6YB9EYerhYBeR4MViwCaZD5ENDIZ6xqUccBD8xlP8HS
         e4/3d2g5gJ4FYLrRhcxD/AhSOyEsANYCe8y/k7rA1N07W3zyhSEqh78IETZtTfMw6EuG
         vfnlU/OBdk3mAosSvbFzVExC7L3wuT2prIZs0eMkwt8KNhcV0PQLRxbmaGdjmjgBP+Ti
         VZDHbxJTSlLD2lDfopsBQ6Jmkn/VHwX319QKmF8wzAgvaQd4s9znk7hR02RGtko+DrJY
         nDsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3c9jjxqkbaeau01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) smtp.mailfrom=3C9jjXQkbAEAu01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f200.google.com (mail-il1-f200.google.com. [209.85.166.200])
        by gmr-mx.google.com with ESMTPS id f186si1307874vkc.5.2019.12.01.07.11.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 01 Dec 2019 07:11:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3c9jjxqkbaeau01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.200 as permitted sender) client-ip=209.85.166.200;
Received: by mail-il1-f200.google.com with SMTP id d14so1741676ild.22
        for <kasan-dev@googlegroups.com>; Sun, 01 Dec 2019 07:11:08 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a92:690c:: with SMTP id e12mr61025372ilc.153.1575213067870;
 Sun, 01 Dec 2019 07:11:07 -0800 (PST)
Date: Sun, 01 Dec 2019 07:11:07 -0800
In-Reply-To: <000000000000c280ba05988b6242@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000005b28f90598a5df9c@google.com>
Subject: Re: BUG: sleeping function called from invalid context in __alloc_pages_nodemask
From: syzbot <syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, aryabinin@virtuozzo.com, 
	christophe.leroy@c-s.fr, dja@axtens.net, dvyukov@google.com, 
	glider@google.com, gor@linux.ibm.com, hdanton@sina.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	mark.rutland@arm.com, penguin-kernel@I-love.SAKURA.ne.jp, 
	syzkaller-bugs@googlegroups.com, urezki@gmail.com
Content-Type: text/plain; charset="UTF-8"; format=flowed; delsp=yes
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3c9jjxqkbaeau01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.200 as permitted sender) smtp.mailfrom=3C9jjXQkbAEAu01mcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    419593da Add linux-next specific files for 20191129
git tree:       linux-next
console output: https://syzkaller.appspot.com/x/log.txt?x=177a9712e00000
kernel config:  https://syzkaller.appspot.com/x/.config?x=7c04b0959e75c206
dashboard link: https://syzkaller.appspot.com/bug?extid=4925d60532bf4c399608
compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=16148e9ce00000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=12a1f786e00000

IMPORTANT: if you fix the bug, please add the following tag to the commit:
Reported-by: syzbot+4925d60532bf4c399608@syzkaller.appspotmail.com

BUG: sleeping function called from invalid context at mm/page_alloc.c:4681
in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 9065, name:  
kworker/1:3
4 locks held by kworker/1:3/9065:
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: __write_once_size  
include/linux/compiler.h:247 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: arch_atomic64_set  
arch/x86/include/asm/atomic64_64.h:34 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: atomic64_set  
include/asm-generic/atomic-instrumented.h:868 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: atomic_long_set  
include/asm-generic/atomic-long.h:40 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at: set_work_data  
kernel/workqueue.c:615 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at:  
set_work_pool_and_clear_pending kernel/workqueue.c:642 [inline]
  #0: ffff8880aa026d28 ((wq_completion)events){+.+.}, at:  
process_one_work+0x88b/0x1740 kernel/workqueue.c:2235
  #1: ffffc90002177dc0 (pcpu_balance_work){+.+.}, at:  
process_one_work+0x8c1/0x1740 kernel/workqueue.c:2239
  #2: ffffffff8983ff20 (pcpu_alloc_mutex){+.+.}, at:  
pcpu_balance_workfn+0xb7/0x1310 mm/percpu.c:1845
  #3: ffffffff89851b18 (vmap_area_lock){+.+.}, at: spin_lock  
include/linux/spinlock.h:338 [inline]
  #3: ffffffff89851b18 (vmap_area_lock){+.+.}, at:  
pcpu_get_vm_areas+0x3b27/0x3f00 mm/vmalloc.c:3431
Preemption disabled at:
[<ffffffff81a89ce7>] spin_lock include/linux/spinlock.h:338 [inline]
[<ffffffff81a89ce7>] pcpu_get_vm_areas+0x3b27/0x3f00 mm/vmalloc.c:3431
CPU: 1 PID: 9065 Comm: kworker/1:3 Not tainted  
5.4.0-next-20191129-syzkaller #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS  
Google 01/01/2011
Workqueue: events pcpu_balance_workfn
Call Trace:
  __dump_stack lib/dump_stack.c:77 [inline]
  dump_stack+0x197/0x210 lib/dump_stack.c:118
  ___might_sleep.cold+0x1fb/0x23e kernel/sched/core.c:6800
  __might_sleep+0x95/0x190 kernel/sched/core.c:6753
  prepare_alloc_pages mm/page_alloc.c:4681 [inline]
  __alloc_pages_nodemask+0x523/0x910 mm/page_alloc.c:4730
  alloc_pages_current+0x107/0x210 mm/mempolicy.c:2211
  alloc_pages include/linux/gfp.h:532 [inline]
  __get_free_pages+0xc/0x40 mm/page_alloc.c:4786
  kasan_populate_vmalloc_pte mm/kasan/common.c:762 [inline]
  kasan_populate_vmalloc_pte+0x2f/0x1c0 mm/kasan/common.c:753
  apply_to_pte_range mm/memory.c:2041 [inline]
  apply_to_pmd_range mm/memory.c:2068 [inline]
  apply_to_pud_range mm/memory.c:2088 [inline]
  apply_to_p4d_range mm/memory.c:2108 [inline]
  apply_to_page_range+0x445/0x700 mm/memory.c:2133
  kasan_populate_vmalloc+0x68/0x90 mm/kasan/common.c:791
  pcpu_get_vm_areas+0x3c77/0x3f00 mm/vmalloc.c:3439
  pcpu_create_chunk+0x24e/0x7f0 mm/percpu-vm.c:340
  pcpu_balance_workfn+0xf1b/0x1310 mm/percpu.c:1934
  process_one_work+0x9af/0x1740 kernel/workqueue.c:2264
  worker_thread+0x98/0xe40 kernel/workqueue.c:2410
  kthread+0x361/0x430 kernel/kthread.c:255
  ret_from_fork+0x24/0x30 arch/x86/entry/entry_64.S:352

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000005b28f90598a5df9c%40google.com.
