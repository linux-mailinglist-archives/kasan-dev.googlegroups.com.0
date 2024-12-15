Return-Path: <kasan-dev+bncBCQPF57GUQHBBCOX7K5AMGQEAJ2X3LI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1138.google.com (mail-yw1-x1138.google.com [IPv6:2607:f8b0:4864:20::1138])
	by mail.lfdr.de (Postfix) with ESMTPS id 339219F2314
	for <lists+kasan-dev@lfdr.de>; Sun, 15 Dec 2024 11:12:27 +0100 (CET)
Received: by mail-yw1-x1138.google.com with SMTP id 00721157ae682-6ef55d44f73sf24060217b3.3
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Dec 2024 02:12:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1734257545; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZHdeh2an6voNGBam2LV/8ht+CTAxxLiLU0HQLBj8vsMRMlqQRLfiWKiT5rcNgcE7c3
         7MmW3ma46FQGPefdm7tPwf9uDFCNuxtQ0ebaGdiWtUWtx7kVUA+VZVfEqGGBZr4QZaGs
         uDlYkxSPaVvGS2OGUja2ZdUqk6Ji4GqSEdV2+Ipg4Mm6XGLFH1C+5AJ5C2UA4mnmzfFa
         6CMVO0/C5iGFE5fkkseEOhY+bg4nDUXY7jVYPgbk1Ux2M0TjdKZiR08HS5WAVWiFOBxi
         nhOgU+GeLkLR6YvXpqBBAIAEV/G+I1kH7qqP2J/yHvdyYMNouTm+6PZTEBjVikD75O1s
         9/XQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=DGgmXLRTPDcDeutAWzUxlDa5d1k3Fx8ff+a1tfJfZE0=;
        fh=lBdBnbNf5HsJlnhVPBXFNqsHAeemKm+4TiczN1iYS2A=;
        b=dylVZVLNbdCap9XxO2wvWh8Ru1xcgOqJLEYYEddf2+ALgbjCN7NCXmeX6M5uHpO9ll
         IJU523BIlJuJuxW3NaLzDpazu2mpk7GF27XXnXFluiZzVg4QqqJFJyIahfFdFXXZK2up
         FAb3qrQ8YeSYNbFmFTYQUJoMnrDW4gQ88BJhWmsQtMbf4t4vFgBzAOF/zqGlSc1KRaE5
         WKgGoaWUFk247aRon6mk1Q1RQH1h1/xxsGM4szCEcNu1GA3E5huSNMjaWaUvTHwTMiRK
         AvziN9XePJSGPj4VsDOMN3H4bb3tsrHq0dhlgvzpV5/YmA/a9XVJSrAZ9nhY1qlczotj
         0h9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3h6tezwkbajomste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.205 as permitted sender) smtp.mailfrom=3h6teZwkbAJoMSTE4FF8L4JJC7.AIIAF8OM8L6IHN8HN.6IG@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1734257545; x=1734862345; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DGgmXLRTPDcDeutAWzUxlDa5d1k3Fx8ff+a1tfJfZE0=;
        b=ovpAYhXqYmFdZvBE7ilNMUDnagk3MaSm3Z30nAGPCbwVQkTiGi/4yweWPdoDMDfw/y
         qbcjAyZ+j/xAV928ok1IT0yvunVC2zJAjmJNKa9H8vsLPd7mnhRmIaWkoXBAJUNZ3px5
         zIi/BUK3Cod03XlhXsyfMfcVZp7Op4FLsM4gLUs4Ft+FFcJDTsNtKZTw93nJbYEOo+V2
         hEXe/YM80Cn0UfA/wmQBiBcaf3r3AVeVYpMDQor0g81ofZZJvCG1GRgDpt9U+/hBMD2Y
         DBcXyavt1lWGYjHVtsgjdcWqjEdhHaTGlMJ1GG8+51+h2fR+5DZWTB9DwaIbokMiBngK
         xFKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1734257545; x=1734862345;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DGgmXLRTPDcDeutAWzUxlDa5d1k3Fx8ff+a1tfJfZE0=;
        b=DDeMpL7Xw53rBlNHfi9rujDGJFT3mUJdOTQ7+I5VUuaCkIF4cS6jO+kCmgNPNWBj9f
         rH1Sq2l4F18QwlTxXKi9faroNbj1Q1ptyWOMwiGQwDUviaKBSaAo9srCmEd2h7eGEjj+
         NqGeUGtCpzqp2x6jMISj5x9bntOKLhpMTlrB7ocZZW4MNXb6A9JfjDoIeBtqG7CojBtC
         J0d/ZVhW2DHqfw/9NkZz+9WQ2gnNWjgPYB0ShKPa7tRxbioOeRjOZCtffauMvxuB86km
         /IdRnOHhuykt3H3ZLGGOuXB6jNUnqPKNlb6M28LjI9mJiCPx8ADEyPdJmJRArDo/A7h9
         87PQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJ2WNs5RzF8ozZJpLlAbqzMbwLfajBnEy4C4KeidNTk11uJL/h3ClH7sSjBxQ+pUfwb/iPfw==@lfdr.de
X-Gm-Message-State: AOJu0Ywo/nKocPynYMU8MKdgzT/1u/j+Px34UOuWuZD5vfCqNuKSzF4C
	x7Vp+d4V2VVDiYN255xY+5JWCi1pDbmQtTBGCCH8zAWJWSzf1a06
X-Google-Smtp-Source: AGHT+IFIE5IhBMdQHVJXnfUYvaYoUhFgwA3m9mnG6gSrvQ86K1iGFn3Re2twdLpSfVMOaOKTn8FrRw==
X-Received: by 2002:a05:6902:1692:b0:e4b:25c6:54f1 with SMTP id 3f1490d57ef6-e4b25c65776mr1380600276.33.1734257545447;
        Sun, 15 Dec 2024 02:12:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:830f:0:b0:e3c:9f51:6da with SMTP id 3f1490d57ef6-e43b216a866ls1775847276.2.-pod-prod-03-us;
 Sun, 15 Dec 2024 02:12:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVLkHdg6uXbpJBaYAlATTKaBz2pJH9mSoF73b1VYfYhB2R3g+JX1SdL/V5gsCp5ttoaNLmP3rEG3oA=@googlegroups.com
X-Received: by 2002:a05:6902:a85:b0:e4d:3fa8:b924 with SMTP id 3f1490d57ef6-e4d3fa9164dmr237441276.53.1734257544499;
        Sun, 15 Dec 2024 02:12:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1734257544; cv=none;
        d=google.com; s=arc-20240605;
        b=ga3ZP/57Xzc2eaxepksq+ivv4zn2UWJg08bT/+QrWte80RSN1AMKCu8MZr5tlJHr4k
         xPQs12EA9ESocz5vUVIqR+LZEJpk7WKGsd/tBTOOUEmJsH3Rv8nBzxzlb339RTjvXHce
         dDW/c9Wn/bq1LfMqdnUy/tUhwdpu4NnOvqbAqyUmySlmdbZBUga+NnU0NwlA8S6NmFQe
         C54Jc3L7EKpntPIKuWb9xPi9KQ4ZirTtBNf31T6p95854d9lWT4Y4UC2pbfcBH9Mm5mo
         fbhB70ngfOCIMDxm1Hc7yM1OUFBTyLzJeN8HxWzroFIMOb+HgGMfJvDEqyloLi9zNXgW
         C0mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=643DiHG3EUFao9sts4NqrLKwx9WEZmymFRelU6s+3fM=;
        fh=0x1PEC02qMeVRr8+hcA6hd2iantqqeFkm9x6LrKijXI=;
        b=Yqsu8O3k6yVH/p+14W+ztHo6GD+Hsb/30WZQgMtK0Z6YmSJE4ERQ5vWRWOT9ZcZZV1
         BadWsaWxO+ZM/oklrlWNRl8j8ibd3mZpoyicWakWaZtTRHy87lCuNBI0AiQ+rQZhjijE
         DcSwm/QshkUwrC4usqPZ3nge1BGXHOrlBPeq5zRgMRhpXnuF/blguqpBZ3xmvzbkueOj
         CySjejXl9zi5BOxhXJH8MdsOrUwCPK87tWOufNXFTxH0lFzm4rzJUaygHuONNm5C3qM6
         VoySr7KS2nSDAi7bXt2SO4p3bvzMos+Tigw/1WS74NL9y3K7y1LB+jHOoMJHcedEUIfw
         ZYCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3h6tezwkbajomste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.205 as permitted sender) smtp.mailfrom=3h6teZwkbAJoMSTE4FF8L4JJC7.AIIAF8OM8L6IHN8HN.6IG@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f205.google.com (mail-il1-f205.google.com. [209.85.166.205])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e480158570asi108802276.1.2024.12.15.02.12.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 15 Dec 2024 02:12:24 -0800 (PST)
Received-SPF: pass (google.com: domain of 3h6tezwkbajomste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.205 as permitted sender) client-ip=209.85.166.205;
Received: by mail-il1-f205.google.com with SMTP id e9e14a558f8ab-3ac005db65eso31649355ab.3
        for <kasan-dev@googlegroups.com>; Sun, 15 Dec 2024 02:12:24 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXmFtsj82VMVDBaEkEGIUB48PWGpJOLWZQEO+mBNxFBctvyZYmriTlX+oZPeQ+cLQ7yFA1YBe09S2o=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:190f:b0:3a7:e800:7d26 with SMTP id
 e9e14a558f8ab-3aff6eada72mr98056395ab.8.1734257543991; Sun, 15 Dec 2024
 02:12:23 -0800 (PST)
Date: Sun, 15 Dec 2024 02:12:23 -0800
In-Reply-To: <67275485.050a0220.3c8d68.0a37.GAE@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <675eab87.050a0220.37aaf.00f6.GAE@google.com>
Subject: Re: [syzbot] [mm?] WARNING: locking bug in __rmqueue_pcplist
From: syzbot <syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com>
To: 42.hyeyoo@gmail.com, akpm@linux-foundation.org, andreyknvl@gmail.com, 
	bigeasy@linutronix.de, boqun.feng@gmail.com, bsegall@google.com, cl@linux.com, 
	dietmar.eggemann@arm.com, dvyukov@google.com, elver@google.com, 
	frederic@kernel.org, glider@google.com, iamjoonsoo.kim@lge.com, 
	jannh@google.com, jiangshanlai@gmail.com, joel@joelfernandes.org, 
	josh@joshtriplett.org, juri.lelli@redhat.com, kasan-dev@googlegroups.com, 
	liam.howlett@oracle.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	llong@redhat.com, longman@redhat.com, lorenzo.stoakes@oracle.com, 
	mathieu.desnoyers@efficios.com, mgorman@suse.de, mingo@redhat.com, 
	neeraj.upadhyay@kernel.org, paulmck@kernel.org, penberg@kernel.org, 
	peterz@infradead.org, qiang.zhang1211@gmail.com, rcu@vger.kernel.org, 
	rientjes@google.com, roman.gushchin@linux.dev, rostedt@goodmis.org, 
	ryabinin.a.a@gmail.com, syzkaller-bugs@googlegroups.com, tglx@linutronix.de, 
	tj@kernel.org, urezki@gmail.com, vbabka@suse.cz, vincent.guittot@linaro.org, 
	vincenzo.frascino@arm.com, vschneid@redhat.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3h6tezwkbajomste4ff8l4jjc7.aiiaf8om8l6ihn8hn.6ig@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.205 as permitted sender) smtp.mailfrom=3h6teZwkbAJoMSTE4FF8L4JJC7.AIIAF8OM8L6IHN8HN.6IG@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

syzbot has found a reproducer for the following issue on:

HEAD commit:    a0e3919a2df2 Merge tag 'usb-6.13-rc3' of git://git.kernel...
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=15a4c344580000
kernel config:  https://syzkaller.appspot.com/x/.config?x=b874549ac3d0b012
dashboard link: https://syzkaller.appspot.com/bug?extid=39f85d612b7c20d8db48
compiler:       gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=139407e8580000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=179407e8580000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/694eb7d9bffc/disk-a0e3919a.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/1350ab6a6022/vmlinux-a0e3919a.xz
kernel image: https://storage.googleapis.com/syzbot-assets/f64266879922/bzImage-a0e3919a.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+39f85d612b7c20d8db48@syzkaller.appspotmail.com

=============================
[ BUG: Invalid wait context ]
6.13.0-rc2-syzkaller-00333-ga0e3919a2df2 #0 Not tainted
-----------------------------
syz-executor300/5884 is trying to lock:
ffff88813fffc298 (&zone->lock){-.-.}-{3:3}, at: rmqueue_bulk mm/page_alloc.c:2307 [inline]
ffff88813fffc298 (&zone->lock){-.-.}-{3:3}, at: __rmqueue_pcplist+0x6bb/0x1600 mm/page_alloc.c:3001
other info that might help us debug this:
context-{2:2}
5 locks held by syz-executor300/5884:
 #0: ffff888036701f20 (&mm->mmap_lock){++++}-{4:4}, at: mmap_read_lock include/linux/mmap_lock.h:144 [inline]
 #0: ffff888036701f20 (&mm->mmap_lock){++++}-{4:4}, at: __mm_populate+0x21d/0x380 mm/gup.c:2014
 #1: ffffffff8e1bb500 (rcu_read_lock){....}-{1:3}, at: rcu_lock_acquire include/linux/rcupdate.h:337 [inline]
 #1: ffffffff8e1bb500 (rcu_read_lock){....}-{1:3}, at: rcu_read_lock include/linux/rcupdate.h:849 [inline]
 #1: ffffffff8e1bb500 (rcu_read_lock){....}-{1:3}, at: count_memcg_events_mm.constprop.0+0x3a/0x340 include/linux/memcontrol.h:994
 #2: ffffffff8e1bb500 (rcu_read_lock){....}-{1:3}, at: rcu_lock_acquire include/linux/rcupdate.h:337 [inline]
 #2: ffffffff8e1bb500 (rcu_read_lock){....}-{1:3}, at: rcu_read_lock include/linux/rcupdate.h:849 [inline]
 #2: ffffffff8e1bb500 (rcu_read_lock){....}-{1:3}, at: ieee80211_rx_napi+0xa6/0x400 net/mac80211/rx.c:5491
 #3: ffff888067a68168 (&rdev->bss_lock){+.-.}-{3:3}, at: spin_lock_bh include/linux/spinlock.h:356 [inline]
 #3: ffff888067a68168 (&rdev->bss_lock){+.-.}-{3:3}, at: cfg80211_inform_single_bss_data+0x791/0x1de0 net/wireless/scan.c:2329
 #4: ffff8880b8644c58 (&pcp->lock){+.+.}-{3:3}, at: spin_trylock include/linux/spinlock.h:361 [inline]
 #4: ffff8880b8644c58 (&pcp->lock){+.+.}-{3:3}, at: rmqueue_pcplist mm/page_alloc.c:3030 [inline]
 #4: ffff8880b8644c58 (&pcp->lock){+.+.}-{3:3}, at: rmqueue mm/page_alloc.c:3074 [inline]
 #4: ffff8880b8644c58 (&pcp->lock){+.+.}-{3:3}, at: get_page_from_freelist+0x350/0x2f80 mm/page_alloc.c:3471
stack backtrace:
CPU: 0 UID: 0 PID: 5884 Comm: syz-executor300 Not tainted 6.13.0-rc2-syzkaller-00333-ga0e3919a2df2 #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 11/25/2024
Call Trace:
 <IRQ>
 __dump_stack lib/dump_stack.c:94 [inline]
 dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120
 print_lock_invalid_wait_context kernel/locking/lockdep.c:4826 [inline]
 check_wait_context kernel/locking/lockdep.c:4898 [inline]
 __lock_acquire+0x878/0x3c40 kernel/locking/lockdep.c:5176
 lock_acquire.part.0+0x11b/0x380 kernel/locking/lockdep.c:5849
 __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline]
 _raw_spin_lock_irqsave+0x3a/0x60 kernel/locking/spinlock.c:162
 rmqueue_bulk mm/page_alloc.c:2307 [inline]
 __rmqueue_pcplist+0x6bb/0x1600 mm/page_alloc.c:3001
 rmqueue_pcplist mm/page_alloc.c:3043 [inline]
 rmqueue mm/page_alloc.c:3074 [inline]
 get_page_from_freelist+0x3d2/0x2f80 mm/page_alloc.c:3471
 __alloc_pages_noprof+0x223/0x25b0 mm/page_alloc.c:4751
 alloc_pages_mpol_noprof+0x2c9/0x610 mm/mempolicy.c:2269
 stack_depot_save_flags+0x8e0/0x9e0 lib/stackdepot.c:627
 kasan_save_stack+0x42/0x60 mm/kasan/common.c:48
 __kasan_record_aux_stack+0xba/0xd0 mm/kasan/generic.c:544
 task_work_add+0xc0/0x3b0 kernel/task_work.c:77
 __run_posix_cpu_timers kernel/time/posix-cpu-timers.c:1223 [inline]
 run_posix_cpu_timers+0x69f/0x7d0 kernel/time/posix-cpu-timers.c:1422
 update_process_times+0x1a1/0x2d0 kernel/time/timer.c:2526
 tick_sched_handle kernel/time/tick-sched.c:276 [inline]
 tick_nohz_handler+0x376/0x530 kernel/time/tick-sched.c:297
 __run_hrtimer kernel/time/hrtimer.c:1739 [inline]
 __hrtimer_run_queues+0x5fb/0xae0 kernel/time/hrtimer.c:1803
 hrtimer_interrupt+0x392/0x8e0 kernel/time/hrtimer.c:1865
 local_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1038 [inline]
 __sysvec_apic_timer_interrupt+0x10f/0x400 arch/x86/kernel/apic/apic.c:1055
 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline]
 sysvec_apic_timer_interrupt+0x52/0xc0 arch/x86/kernel/apic/apic.c:1049
 asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:702
RIP: 0010:__sanitizer_cov_trace_switch+0x4f/0x90 kernel/kcov.c:351
Code: 83 f8 10 75 2f 41 bd 03 00 00 00 4c 8b 75 00 31 db 4d 85 f6 74 1e 48 8b 74 dd 10 4c 89 e2 4c 89 ef 48 83 c3 01 48 8b 4c 24 28 <e8> 8c fd ff ff 49 39 de 75 e2 5b 5d 41 5c 41 5d 41 5e c3 cc cc cc
RSP: 0018:ffffc90000007098 EFLAGS: 00000212
RAX: 0000000000000000 RBX: 0000000000000020 RCX: ffffffff8aaf7a17
RDX: 0000000000000000 RSI: 00000000000000f4 RDI: 0000000000000001
RBP: ffffffff8cc04980 R08: 0000000000000001 R09: 00000000000000e8
R10: 0000000000000000 R11: 0000000000000004 R12: 0000000000000000
R13: 0000000000000001 R14: 0000000000000020 R15: dffffc0000000000
 _ieee802_11_parse_elems_full+0x297/0x4340 net/mac80211/parse.c:293
 ieee802_11_parse_elems_full+0x9ca/0x1680 net/mac80211/parse.c:984
 ieee802_11_parse_elems_crc net/mac80211/ieee80211_i.h:2384 [inline]
 ieee802_11_parse_elems net/mac80211/ieee80211_i.h:2391 [inline]
 ieee80211_inform_bss+0xfd/0x1100 net/mac80211/scan.c:79
 rdev_inform_bss net/wireless/rdev-ops.h:418 [inline]
 cfg80211_inform_single_bss_data+0x8f6/0x1de0 net/wireless/scan.c:2334
 cfg80211_inform_bss_data+0x205/0x3ba0 net/wireless/scan.c:3189
 cfg80211_inform_bss_frame_data+0x272/0x7a0 net/wireless/scan.c:3284
 ieee80211_bss_info_update+0x311/0xab0 net/mac80211/scan.c:226
 ieee80211_scan_rx+0x474/0xac0 net/mac80211/scan.c:340
 __ieee80211_rx_handle_packet net/mac80211/rx.c:5232 [inline]
 ieee80211_rx_list+0x1bd7/0x2970 net/mac80211/rx.c:5469
 ieee80211_rx_napi+0xdd/0x400 net/mac80211/rx.c:5492
 ieee80211_rx include/net/mac80211.h:5166 [inline]
 ieee80211_handle_queued_frames+0xd5/0x130 net/mac80211/main.c:441
 tasklet_action_common+0x251/0x3f0 kernel/softirq.c:811
 handle_softirqs+0x213/0x8f0 kernel/softirq.c:561
 __do_softirq kernel/softirq.c:595 [inline]
 invoke_softirq kernel/softirq.c:435 [inline]
 __irq_exit_rcu+0x109/0x170 kernel/softirq.c:662
 irq_exit_rcu+0x9/0x30 kernel/softirq.c:678
 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline]
 sysvec_apic_timer_interrupt+0xa4/0xc0 arch/x86/kernel/apic/apic.c:1049
 </IRQ>
 <TASK>
 asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:702
RIP: 0010:rcu_read_unlock include/linux/rcupdate.h:878 [inline]
RIP: 0010:count_memcg_events_mm.constprop.0+0x108/0x340 include/linux/memcontrol.h:998
Code: ba 01 00 00 00 89 de 48 89 ef e8 c3 13 22 00 9c 5b 81 e3 00 02 00 00 31 ff 48 89 de e8 91 2d b7 ff 48 85 db 0f 85 06 02 00 00 <e8> 13 2b b7 ff e8 9e 50 46 09 31 ff 89 c3 89 c6 e8 43 2d b7 ff 85
RSP: 0018:ffffc90002ee7a90 EFLAGS: 00000293
RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffffffff81e2da5e
RDX: ffff88803650a440 RSI: ffffffff81e2da68 RDI: 0000000000000007
RBP: ffff888035a04000 R08: 0000000000000007 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000200
R13: ffff8880223138d8 R14: 0000000000000000 R15: ffff88803650a440
 count_memcg_event_mm include/linux/memcontrol.h:1004 [inline]
 mm_account_fault mm/memory.c:5978 [inline]
 handle_mm_fault+0x5cc/0xaa0 mm/memory.c:6138
 faultin_page mm/gup.c:1196 [inline]
 __get_user_pages+0x8d9/0x3b50 mm/gup.c:1494
 populate_vma_page_range+0x27f/0x3a0 mm/gup.c:1932
 __mm_populate+0x1d6/0x380 mm/gup.c:2035
 mm_populate include/linux/mm.h:3386 [inline]
 vm_mmap_pgoff+0x293/0x360 mm/util.c:585
 ksys_mmap_pgoff+0x7d/0x5c0 mm/mmap.c:542
 __do_sys_mmap arch/x86/kernel/sys_x86_64.c:89 [inline]
 __se_sys_mmap arch/x86/kernel/sys_x86_64.c:82 [inline]
 __x64_sys_mmap+0x125/0x190 arch/x86/kernel/sys_x86_64.c:82
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f9a0d37bde9
Code: 28 00 00 00 75 05 48 83 c4 28 c3 e8 c1 1f 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007f9a0cb00148 EFLAGS: 00000246 ORIG_RAX: 0000000000000009
RAX: ffffffffffffffda RBX: 00007f9a0d4031f8 RCX: 00007f9a0d37bde9
RDX: b635773f06ebbeee RSI: 0000000000b36000 RDI: 0000000020000000
RBP: 00007f9a0d4031f0 R08: 00000000ffffffff R09: 0000000002000000
R10: 0000000000008031 R11: 0000000000000246 R12: 00007f9a0d4031fc
R13: 000000000000006e R14: 00007ffd73f9daf0 R15: 00007ffd73f9dbd8
 </TASK>
----------------
Code disassembly (best guess):
   0:	83 f8 10             	cmp    $0x10,%eax
   3:	75 2f                	jne    0x34
   5:	41 bd 03 00 00 00    	mov    $0x3,%r13d
   b:	4c 8b 75 00          	mov    0x0(%rbp),%r14
   f:	31 db                	xor    %ebx,%ebx
  11:	4d 85 f6             	test   %r14,%r14
  14:	74 1e                	je     0x34
  16:	48 8b 74 dd 10       	mov    0x10(%rbp,%rbx,8),%rsi
  1b:	4c 89 e2             	mov    %r12,%rdx
  1e:	4c 89 ef             	mov    %r13,%rdi
  21:	48 83 c3 01          	add    $0x1,%rbx
  25:	48 8b 4c 24 28       	mov    0x28(%rsp),%rcx
* 2a:	e8 8c fd ff ff       	call   0xfffffdbb <-- trapping instruction
  2f:	49 39 de             	cmp    %rbx,%r14
  32:	75 e2                	jne    0x16
  34:	5b                   	pop    %rbx
  35:	5d                   	pop    %rbp
  36:	41 5c                	pop    %r12
  38:	41 5d                	pop    %r13
  3a:	41 5e                	pop    %r14
  3c:	c3                   	ret
  3d:	cc                   	int3
  3e:	cc                   	int3
  3f:	cc                   	int3


---
If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/675eab87.050a0220.37aaf.00f6.GAE%40google.com.
