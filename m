Return-Path: <kasan-dev+bncBCQPF57GUQHBBIW36TGAMGQEPWSF6CI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 2PVRA6UtnWnONAQAu9opvQ
	(envelope-from <kasan-dev+bncBCQPF57GUQHBBIW36TGAMGQEPWSF6CI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 05:48:37 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FE2C181BB0
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 05:48:36 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-67997c054e1sf5771020eaf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Feb 2026 20:48:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771908514; cv=pass;
        d=google.com; s=arc-20240605;
        b=DL9xj8iLKcxuCOMj7QzBvVKYO/IfWpEbvIHfFtGWs8sqHxzIceD2mymwtRjRA2yYP2
         POfkdlBgCX7di2ANfN8CUWZh3ncW4jNZ8L32fNjFNnRjv34mmpRGd9rUn3wm83wmF3Uu
         MIhkyLfupve7mQjr/4eTml4CXBbMCZiCOLWO3zRAmxs3Kk9dO9Ws7WtivKKEFWCYBJg/
         Yrt3cFzfZ4q2ez7TfSo/i/jSY4OqNBAUHa3EMp8H4/VUg8J3ZRuciYzeWCl7XpMNv3Qg
         J7G2IRXk1psdCjCwRlsjAlhgaM5YEE69Gi342WOzIKI6fLIxcr0fLJDqg0ixq8chC7Ep
         00Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=7NSmRVRwJWCgtajxY5v3SKS6EgX1MvFyc4pxSQVsnAo=;
        fh=2Cj8knqrb7dtWSb52TZ6uu/zkEL8QIy3ePIqahRqRxc=;
        b=cyfoNEn/2EnmFaazUu2ZfzkvtN5qs1IAxD+QSC3p0QCZXPatLTQB3GAh/TBP08IjWC
         WBYSj6z1wE392To8rIExAtsJu8z+ssbnCvkwODnTxCqfLVlvfdGErFMoTuHsHRa0XKZw
         hzjHH/INrtdsQJq86R0t26BSMRSFLd7LLFEnDTxPAX2J7XzxeASoTW+7fSbRUPLnhyNi
         H4XDBoLMc/SQ2+sjXocrul5Pe8IY2YqCidis6tmHDcKRx611b7BGP1Ej4c1knFBKIC+M
         Vqsv32KAmQzdFOEv4y+85nyBxfJSQin4jcX72Js0VqgmIXSyIYi4DYILuEE8yQ4hMTbv
         7wlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3os2daqkbamq289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.161.69 as permitted sender) smtp.mailfrom=3oS2daQkbAMQ289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771908514; x=1772513314; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7NSmRVRwJWCgtajxY5v3SKS6EgX1MvFyc4pxSQVsnAo=;
        b=Gl5mOfsNmYd0eQNuaOpW8MnOalR7644GIXPNxbtHbvOqBLtrcqnfmVP376FAYF0eeI
         /7ZgQ1gh2p33NUG5dipxjh5V0JO00W7kb1S8p94SBbBrYOmkP7w0nlC98zQptJVU430j
         hV1WEpvZ0WwOOGi3UF8BqNh5l1txgxNU+v8halHRYsEHKHrASi7OQ5x0+G9m45rs3Fo4
         JoA03TMnXtS0GRVS2+NX0jwTDoRXDehpSRdweJ+n6bW2JBKq6xUtR8dJjUnoB0J3WIrm
         f/4EF+GLABCkHosQhzXXRxhmoGHqgf8WRYtLXi/Ed5M0mIjPutGM0XHpQcc1jVK4AkDo
         ySCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771908514; x=1772513314;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:date:mime-version:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7NSmRVRwJWCgtajxY5v3SKS6EgX1MvFyc4pxSQVsnAo=;
        b=fFJPtY854MTMTPjlvk7d0OW6W1HwBePzaLCkX2wY3p7VnDh8RvoH0jw+ge9cYwqAKA
         BsD7lvzsglgy6WoXc72ZkI+y2EQEMMO1X/+5Gghj8pYKnYQWJAglZo7evHc0071IVLpe
         fyEh/riuxV4hWBmo0bZKkCpkHml4Np4oz5EZ9Nx1zY6T/phgni3PY3Pn0kCWAycaI/LO
         x5wAVM+ks7W4ZZUhmVjvvR2hr9A9HrTB7kFSD5rjRPgx/f+7XipW6UXVNgd9+PRVB66l
         Dgty6R3XguNBSZgr78Jh/HHhysRQcB1DugI8qRXSb8Gjusc76F/iMD9TU4tal36xk66O
         fCfg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8ik7NdESpcFFwjaNRC4JUxlgFc+DV8np6rbViguMyIW8wuemo+JhHs8u7O6HPEArXzpXByA==@lfdr.de
X-Gm-Message-State: AOJu0YzYFv/pUBXG3EodUqjhqVaJQ5FxtaZMUykKLTt2w5tzIM+LiePK
	dGwEpaebkuKXgYHP1NTF97Dbkejaequ+NLQoYKgNN5T18mKrK1QrPxJV
X-Received: by 2002:a05:6871:7bc8:b0:408:6bba:434e with SMTP id 586e51a60fabf-4157a4ea17amr4556434fac.0.1771908514364;
        Mon, 23 Feb 2026 20:48:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HX01niblzkGei+4lmxaJIPKAaUg+YR3O9zgoBRAIE5gw=="
Received: by 2002:a05:6871:8898:20b0:408:8d90:8652 with SMTP id
 586e51a60fabf-415cf38841dls76495fac.1.-pod-prod-00-us; Mon, 23 Feb 2026
 20:48:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXdwmIXxnx7Ti2/jhdJBSD7mbcv/AN69tc4V114v3II9Zn5FiIa3BCN54PnNtbR1dNAiDabN42SJhU=@googlegroups.com
X-Received: by 2002:a05:6870:37cc:b0:413:9c82:8742 with SMTP id 586e51a60fabf-415458deaeemr8751533fac.27.1771908513334;
        Mon, 23 Feb 2026 20:48:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771908513; cv=none;
        d=google.com; s=arc-20240605;
        b=T5I+6KGfYoJieheorsCktwg/O/KSyKIcFmWVwUAPt10DLsJlMThjwxFJ/o56Bcs7k+
         vJP5F/IYEH/KspVPdVGVc+sFqGgoLJMNz2XMcIKfrSsdjvyKk26sLTP+BipYQ3CbO6Xt
         j/0qnXKwzV8CEuTTKtuqTrz+JgUS3qIL00Rp0GAJkseHeOk6RuWQDnubVI0/CZm7Lfw7
         Ctb47K+K/lSqX3CctFDtrCqfvaPoJGj28+x+mZWjRVQDPikezPfHI7cJCJU7xbjCYhwd
         BAG8GrDC/ymPDGw4tJMPVajkhQ6ScxY4F0HryAy+EGAeBSIK854auodz+fh1ho8x0TqB
         sEzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:date:mime-version;
        bh=oWtSLJc4nIIjVEnAWb0GJjQ5OC/U2fFyyXC24rRSQ+U=;
        fh=PPtyo13exDPEb9q0c3bVbFPpkPvz90zRq87itdHMWMM=;
        b=TPiwRHFYyd3CR1xVlqoWPd1HZbWfUHLsiTeUlZzRP5aTn/9PKjqDHhkM8/aIbx7TA2
         poYBgbtbySkc7LUUv4rqP19orDO0eBOe8uuWGy2yf3kcCLuejOx+U+z9z83WDygtTdsJ
         v4djMbO+/XPyv4XXAE+9ZI9u648j3RkWTcaNQADYi5hGNWFAajZ88xay1HYbpzsFd6EE
         J7md1ZsUN1xKWVE9xrJOruZqW13gHYCt63ZnIKM/aXcCFxd0rrmiaaKXlSuVMrkVlb4T
         zaeoEthT4lWr22R5og8EjFe/tHmzspdc+jqF1PU+hzU5jKzaRwPvBHYyxw4OzVHEFgye
         +oeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3os2daqkbamq289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.161.69 as permitted sender) smtp.mailfrom=3oS2daQkbAMQ289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-oo1-f69.google.com (mail-oo1-f69.google.com. [209.85.161.69])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-4157d1e89b5si306072fac.3.2026.02.23.20.48.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Feb 2026 20:48:33 -0800 (PST)
Received-SPF: pass (google.com: domain of 3os2daqkbamq289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.161.69 as permitted sender) client-ip=209.85.161.69;
Received: by mail-oo1-f69.google.com with SMTP id 006d021491bc7-676c2e00f3fso72252540eaf.0
        for <kasan-dev@googlegroups.com>; Mon, 23 Feb 2026 20:48:33 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVFVatsKGtx9RChUzcPLH3NTqxJoJ78z/G/Q2uBRxgSJfYLE3bYV+y7AFvNEuZJy5x0H2Hgtie299o=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6820:c8d:b0:679:9252:6607 with SMTP id
 006d021491bc7-679b123dc2bmr8849685eaf.41.1771908513053; Mon, 23 Feb 2026
 20:48:33 -0800 (PST)
Date: Mon, 23 Feb 2026 20:48:33 -0800
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <699d2da1.a00a0220.121a60.00f4.GAE@google.com>
Subject: [syzbot] [kasan?] [mm?] WARNING in __kfence_free (4)
From: syzbot <syzbot+ac1ff64591d23db965f7@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, kees@kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3os2daqkbamq289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.161.69 as permitted sender) smtp.mailfrom=3oS2daQkbAMQ289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.61 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	URI_HIDDEN_PATH(1.00)[https://syzkaller.appspot.com/x/.config?x=1bd834155be39cb];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	DMARC_POLICY_SOFTFAIL(0.10)[appspotmail.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	HAS_LIST_UNSUB(-0.01)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBCQPF57GUQHBBIW36TGAMGQEPWSF6CI,ac1ff64591d23db965f7];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[appspotmail.com:email,googlegroups.com:email,googlegroups.com:dkim,mail-oo1-xc37.google.com:helo,mail-oo1-xc37.google.com:rdns];
	MIME_TRACE(0.00)[0:+];
	TO_DN_NONE(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[syzbot@syzkaller.appspotmail.com,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[9];
	REDIRECTOR_URL(0.00)[goo.gl];
	SUBJECT_HAS_QUESTION(0.00)[]
X-Rspamd-Queue-Id: 6FE2C181BB0
X-Rspamd-Action: no action

Hello,

syzbot found the following issue on:

HEAD commit:    8bf22c33e7a1 Merge tag 'net-7.0-rc1' of git://git.kernel.o..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=1220195a580000
kernel config:  https://syzkaller.appspot.com/x/.config?x=1bd834155be39cb
dashboard link: https://syzkaller.appspot.com/bug?extid=ac1ff64591d23db965f7
compiler:       aarch64-linux-gnu-gcc (Debian 14.2.0-19) 14.2.0, GNU ld (GNU Binutils for Debian) 2.44
userspace arch: arm64

Unfortunately, I don't have any reproducer for this issue yet.

Downloadable assets:
disk image (non-bootable): https://storage.googleapis.com/syzbot-assets/fa3fbcfdac58/non_bootable_disk-8bf22c33.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/80710eccc853/vmlinux-8bf22c33.xz
kernel image: https://storage.googleapis.com/syzbot-assets/9a174aad260d/Image-8bf22c33.gz.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+ac1ff64591d23db965f7@syzkaller.appspotmail.com

soft_limit_in_bytes is deprecated and will be removed. Please report your usecase to linux-mm@kvack.org if you depend on this functionality.
------------[ cut here ]------------
WARNING: mm/kfence/core.c:1224 at __kfence_free+0x60/0x100 mm/kfence/core.c:1244, CPU#1: syz-executor/3322
Modules linked in:
CPU: 1 UID: 0 PID: 3322 Comm: syz-executor Not tainted syzkaller #0 PREEMPT 
Hardware name: linux,dummy-virt (DT)
pstate: 81402009 (Nzcv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=--)
pc : __kfence_free+0x60/0x100 mm/kfence/core.c:1224
lr : kfence_free include/linux/kfence.h:187 [inline]
lr : slab_free_hook mm/slub.c:2625 [inline]
lr : slab_free mm/slub.c:6124 [inline]
lr : kfree+0x3bc/0x3f4 mm/slub.c:6442
sp : ffff800089acbab0
x29: ffff800089acbab0 x28: fbf0000005fa0000 x27: 0000000000000000
x26: 0000000000084008 x25: ffff800082a81000 x24: 0000000000000000
x23: f6f0000003412e00 x22: ffff80008033b784 x21: ffffc1ffc1ffc000
x20: 5eaf80008033b784 x19: fff000007d89df78 x18: 0000000000000002
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 000000000006f7ec x12: 0000000000000001
x11: 0000000000000400 x10: 0000000000006400 x9 : 00000000000000b0
x8 : f3f000000622c45c x7 : 0000000000000024 x6 : 0000000000000024
x5 : 000000000000003c x4 : fff000007d87a000 x3 : ffff800082a81000
x2 : ffff800082a815e0 x1 : f4f0000005ff0c80 x0 : fff000007ff00000
Call trace:
 __kfence_free+0x60/0x100 mm/kfence/core.c:1244 (P)
 kfence_free include/linux/kfence.h:187 [inline]
 slab_free_hook mm/slub.c:2625 [inline]
 slab_free mm/slub.c:6124 [inline]
 kfree+0x3bc/0x3f4 mm/slub.c:6442
 kvfree+0x3c/0x58 mm/slub.c:6760
 xt_free_table_info+0x80/0x90 net/netfilter/x_tables.c:1213
 __do_replace+0x250/0x310 net/ipv4/netfilter/ip_tables.c:1084
 do_replace net/ipv6/netfilter/ip6_tables.c:1158 [inline]
 do_ip6t_set_ctl+0x374/0x418 net/ipv6/netfilter/ip6_tables.c:1644
 nf_setsockopt+0x68/0xb0 net/netfilter/nf_sockopt.c:101
 ipv6_setsockopt+0x90/0xe4 net/ipv6/ipv6_sockglue.c:978
 tcp_setsockopt+0x20/0x3c net/ipv4/tcp.c:4217
 sock_common_setsockopt+0x1c/0x28 net/core/sock.c:3973
 do_sock_setsockopt+0xa4/0x198 net/socket.c:2322
 __sys_setsockopt+0x7c/0x100 net/socket.c:2347
 __do_sys_setsockopt net/socket.c:2353 [inline]
 __se_sys_setsockopt net/socket.c:2350 [inline]
 __arm64_sys_setsockopt+0x28/0x40 net/socket.c:2350
 __invoke_syscall arch/arm64/kernel/syscall.c:35 [inline]
 invoke_syscall+0x48/0x104 arch/arm64/kernel/syscall.c:49
 el0_svc_common.constprop.0+0x40/0xe0 arch/arm64/kernel/syscall.c:132
 do_el0_svc+0x1c/0x28 arch/arm64/kernel/syscall.c:151
 el0_svc+0x34/0x124 arch/arm64/kernel/entry-common.c:724
 el0t_64_sync_handler+0xa0/0xf0 arch/arm64/kernel/entry-common.c:743
 el0t_64_sync+0x1a4/0x1a8 arch/arm64/kernel/entry.S:596
---[ end trace 0000000000000000 ]---


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

If the report is already addressed, let syzbot know by replying with:
#syz fix: exact-commit-title

If you want to overwrite report's subsystems, reply with:
#syz set subsystems: new-subsystem
(See the list of subsystem names on the web dashboard)

If the report is a duplicate of another one, reply with:
#syz dup: exact-subject-of-another-report

If you want to undo deduplication, reply with:
#syz undup

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/699d2da1.a00a0220.121a60.00f4.GAE%40google.com.
