Return-Path: <kasan-dev+bncBCQPF57GUQHBB4OET24AMGQEVGQ2NMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 434FE9982B1
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 11:46:27 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6cbe4fc0aa7sf16856486d6.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Oct 2024 02:46:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728553586; cv=pass;
        d=google.com; s=arc-20240605;
        b=O0+VKCsS/rq4KDiQcGhGBRJkKW7Sqh2XaNLntojB/nIrN0Ttoy4k9UwKLe+agWgyYB
         h/yfRjNloYAvrOwLL67aegvbzrNv5tcVXNZOAPwiojYBbqYXtG1f8HsztRm+SD7rSl/x
         G8LXqrt4Yez2Rc37/qk8ACifDi5GOBMuBpU1ces+JpSdMfytBr81JCrCfJ3pdb8X+epw
         PYI3t39BnKC3eUF0EGhYKik6Qb0aORwQYhowVwrjCR8Y1KoHZK5GZBvtj/Exg7Brc8kZ
         UQC+7DEVWjVol/6Y4myVzb54l3mrjrqZL2LrFImVIEj8prgyRkntYYSJglWMNBRxmSY7
         2eSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=I+Lo6Ckhn3783uY1uH1xmPBC78r4IVOkZT6Uqz0OJS8=;
        fh=T9pMEMbeHMiO3C6APPeW72IS/hZvXvfjz+yiTZj8YIA=;
        b=HY+6XJNesrdprY4g66Ir3YalRDFhYle59V3phes/WiznD2QIRiH0AwjcXyz6482/uI
         j5s4IgF7UoAXpT1Buh1KrlAIMWWaPJcOCJu3NYV/Cx15sD462rz/si2dkuL3fif1M8JL
         WuItPX/3cwHzzO+MDzcNmkbm0W218xa05nagosi2Ek3Gl0tbYDnMINL0/Lhd2og7lqlV
         PgaIewElBn8hRy21XkWxKW/EelsYLU/4x8+kcZQpUPF47hR/C/TkpFN9UMxSCud2Ao53
         Twhvo417B49ndKqyxMThStapJcT7cdWxJ+yP9CdgojIVf9RW1MhfGFQ0qZeJ3k8nae2c
         qvlQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3ckihzwkbabmbhi3t44xat881w.z77z4xdbxav76cx6c.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3cKIHZwkbABMBHI3t44xAt881w.z77z4xDBxAv76Cx6C.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728553586; x=1729158386; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=I+Lo6Ckhn3783uY1uH1xmPBC78r4IVOkZT6Uqz0OJS8=;
        b=RAvHU9+3RxIC5XlpqDJm0Wb9JmBpDddtCZl2xsp1zjQHtRsimW5xf7aOOOpX4Zmzio
         X9vWFDwy2ULd2m7SRwr87es5LHdgOA2L3xBgYUidqr3mEKOddw0G4n/7IN+lPY4t9nRq
         Fb5BqZ+2E91Jnt/xffjAVh2Oe4yQssnH0DiJ85J95+p4pgmum3I4IJAFalx538uAjO4X
         meNNLwAHeXxw5UzKRQfntaJm39SeW3GiijEWrPG36Y1kks9UGAOlthq8FGLbAe0QDQKd
         HHDEHdHhlTWoGhMMGShOUMGfNTL8+WtmRp7HxOqw7j4lY6v6k4+TIRCNHkonx8BER1r1
         rI2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728553586; x=1729158386;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=I+Lo6Ckhn3783uY1uH1xmPBC78r4IVOkZT6Uqz0OJS8=;
        b=cQVyhXrNtOqgUvt0hgwmMog/IinUjyAa9IZes9GhSDv/4pSA4RM8q4q6pM8sXs9Wgf
         fG6E7YvoWbwAFavmxiMF6/bqxlW5jdWa/E7On1FzVswE2p9vDP58+zyBE6h751BgZ+Ei
         a0stFhpE9dq477AFbPQT1eDCUspNhyaDE7ON+xAx6xYd3sdLl6Cg6TuxK9g4MdejlsIm
         l/+YiVqwtfarEQGfCvB2+dEU6082SKhxSMjBpC+PVdU4NyhpTmg1Q1Rs8jrK592GEa9D
         p3um2QG/x7uk6mDb79hQITdy7YWKdD+/2sQGddi0ZN3t9hL5HA3mUhHIPrcWEnUSXXk7
         BMUg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXo2gtZP69kUI+EJimzyek+3lI6qIH7qvMH9S1b6bTdjdWQ5vavV02FyQNt68TMCWk78ld/Qg==@lfdr.de
X-Gm-Message-State: AOJu0YxwzAfvsjl0drg1RnYwJQ+FPxMeq5mrrixWmDEJeBFmRjOSQwnS
	sfqCpb4Zz61mhwRFi3FUXLDOf1DNpRjhELgU4n5PxcANHqY1H0YL
X-Google-Smtp-Source: AGHT+IFNMAL1A2Aqupiu4OSnd2euvpAenAdF9KDa9erK/fBV6j1Re4PyXSSmnyI0lUzJot192riE0A==
X-Received: by 2002:a0c:c302:0:b0:6cb:e72a:3c31 with SMTP id 6a1803df08f44-6cbe72a452dmr21581056d6.13.1728553586043;
        Thu, 10 Oct 2024 02:46:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:248f:b0:6b7:8ba3:a39a with SMTP id
 6a1803df08f44-6cbe56591f0ls10720606d6.1.-pod-prod-04-us; Thu, 10 Oct 2024
 02:46:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW55lcH64Er0MPVYRq882zdvMfX4VZtjMAUokX09OlKArQPqnRzVghBiyNvIWU7z8hbXUnZOS62IQ4=@googlegroups.com
X-Received: by 2002:a05:6102:160e:b0:492:a6fb:23e5 with SMTP id ada2fe7eead31-4a448d3ea7emr4861841137.3.1728553585210;
        Thu, 10 Oct 2024 02:46:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728553585; cv=none;
        d=google.com; s=arc-20240605;
        b=KUHZXFye4OyPltX+0qw3d87aoTHpVSHTRhYRLKSUb7+tUQQiv4YBI/Y5cusKt4Q4jy
         Z0QvI3aYpNMqtTY2Ly0MoYyJxNbTa8IZsbbL2U4luT4BrYjpPNFmwJvlVVsLBhdQ4ffB
         2uf1fVkeX7OxZz0c0J+Dvr9rxpW7DnqWI88xcv07axCcnaD/KkknDeOYLcc8Su0xHyjJ
         xt19v+l9NDaZs3Mk61m9hgL6J4iVJWy6o2PHQg1f16tMFbwZkthOmg49JntddvputtCy
         PdzDpwy6tjtmOUpFBnJ1IGlK9jXjUFE+scKrvIRtb4STw3oXJdxJtfci9JxRTz7u+9sp
         Udvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=fSMKPiAAVBf5LSl+D34DdF2HaAtrX+sLOOSYL+YMUpQ=;
        fh=9CRYK2wf4WF4TqETbLj0lqOYYsk8JDAMaZrYjxLKHwM=;
        b=ba4d52zQp3UpUCR5Yah8PKH2c1Y9kJggLLOxSEjUm28YI3cknQ4eHvA8UWN4mGKeVR
         FlsxytIN8j4Z9rq9PA43Cf1kDm9eK/4QaKAJGBpbTsjYHVHZ9MqomhRrHImh8CGycXcM
         fnpOrLPY0/LKf+DoN+ufvXSH19bdFbmxxzNJpn6iMiWqOmzqTHv1AHcl0XJjsh1/Bmje
         4MLuFce/mvk21qKqRDGdCGE5QpzR11s2cYbNSWXN7BpwesKAj3xIw6X43QeflKLO6Tn4
         T2EqPQe3QvbsSGHdUj5ujzflaTStiTOfN5VVKpa8TFknnQRYPqlzSWoXiqbXJybUWwz9
         4g0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3ckihzwkbabmbhi3t44xat881w.z77z4xdbxav76cx6c.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) smtp.mailfrom=3cKIHZwkbABMBHI3t44xAt881w.z77z4xDBxAv76Cx6C.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f199.google.com (mail-il1-f199.google.com. [209.85.166.199])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-84fd312e9adsi38740241.0.2024.10.10.02.46.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2024 02:46:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ckihzwkbabmbhi3t44xat881w.z77z4xdbxav76cx6c.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.199 as permitted sender) client-ip=209.85.166.199;
Received: by mail-il1-f199.google.com with SMTP id e9e14a558f8ab-3a342e872a7so7924135ab.3
        for <kasan-dev@googlegroups.com>; Thu, 10 Oct 2024 02:46:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV+0p1YigADlXU5f6kn27pDWbIkzkG9V8wzgMZpV8H+JqJeTQbQqfbrWpOd9gumBSURusTYuiUDWY4=@googlegroups.com
MIME-Version: 1.0
X-Received: by 2002:a05:6e02:138a:b0:3a0:9f85:d74f with SMTP id
 e9e14a558f8ab-3a397d0fc3emr47740625ab.16.1728553584564; Thu, 10 Oct 2024
 02:46:24 -0700 (PDT)
Date: Thu, 10 Oct 2024 02:46:24 -0700
In-Reply-To: <0000000000005d16fe061fcaf338@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <6707a270.050a0220.64b99.0015.GAE@google.com>
Subject: Re: [syzbot] [mm?] INFO: task hung in hugetlb_wp
From: syzbot <syzbot+c391aebb8e8e8cd95c55@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, kasan-dev@googlegroups.com, 
	keescook@chromium.org, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	muchun.song@linux.dev, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3ckihzwkbabmbhi3t44xat881w.z77z4xdbxav76cx6c.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.199 as permitted sender) smtp.mailfrom=3cKIHZwkbABMBHI3t44xAt881w.z77z4xDBxAv76Cx6C.v75@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    b983b271662b misc: sgi-gru: Don't disable preemption in GR..
git tree:       upstream
console+strace: https://syzkaller.appspot.com/x/log.txt?x=14874b27980000
kernel config:  https://syzkaller.appspot.com/x/.config?x=fb6ea01107fa96bd
dashboard link: https://syzkaller.appspot.com/bug?extid=c391aebb8e8e8cd95c55
compiler:       gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=118c6fd0580000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=16b6a040580000

Downloadable assets:
disk image: https://storage.googleapis.com/syzbot-assets/26adc3db9854/disk-b983b271.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/957da8fb32ba/vmlinux-b983b271.xz
kernel image: https://storage.googleapis.com/syzbot-assets/81f66240a49a/bzImage-b983b271.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+c391aebb8e8e8cd95c55@syzkaller.appspotmail.com

INFO: task syz-executor966:9384 blocked for more than 143 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:26992 pid:9384  tgid:9380  ppid:5243   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6831
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_wp+0x1b4a/0x3320 mm/hugetlb.c:5894
 hugetlb_fault+0x2248/0x2fa0 mm/hugetlb.c:6454
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x7a3/0x13f0 arch/x86/mm/fault.c:1389
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:rep_movs_alternative+0x33/0x70 arch/x86/lib/copy_user_64.S:58
Code: 40 83 f9 08 73 21 85 c9 74 0f 8a 06 88 07 48 ff c7 48 ff c6 48 ff c9 75 f1 c3 cc cc cc cc 66 0f 1f 84 00 00 00 00 00 48 8b 06 <48> 89 07 48 83 c6 08 48 83 c7 08 83 e9 08 74 df 83 f9 08 73 e8 eb
RSP: 0018:ffffc9000ca47c48 EFLAGS: 00050246
RAX: 0000000000000000 RBX: 0000000000000008 RCX: 0000000000000008
RDX: fffff52001948f98 RSI: ffffc9000ca47cb8 RDI: 000000002002d008
RBP: 000000002002d008 R08: 0000000000000000 R09: fffff52001948f97
R10: ffffc9000ca47cbf R11: 0000000000000000 R12: ffffc9000ca47cb8
R13: 000000002002d010 R14: 0000000000000000 R15: 0000000020019680
 copy_user_generic arch/x86/include/asm/uaccess_64.h:121 [inline]
 raw_copy_to_user arch/x86/include/asm/uaccess_64.h:142 [inline]
 _inline_copy_to_user include/linux/uaccess.h:188 [inline]
 _copy_to_user+0xac/0xc0 lib/usercopy.c:26
 copy_to_user include/linux/uaccess.h:216 [inline]
 msr_read+0x14f/0x250 arch/x86/kernel/msr.c:69
 vfs_read+0x1ce/0xbd0 fs/read_write.c:567
 ksys_read+0x12f/0x260 fs/read_write.c:712
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1ba3b462d9
RSP: 002b:00007f1ba3afe218 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
RAX: ffffffffffffffda RBX: 00007f1ba3bcd328 RCX: 00007f1ba3b462d9
RDX: 0000000000018ff8 RSI: 0000000020019680 RDI: 0000000000000003
RBP: 00007f1ba3bcd320 R08: 0000000000000000 R09: 0000000000000000
R10: 0072736d2f232f75 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
INFO: task syz-executor966:9388 blocked for more than 143 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:27104 pid:9388  tgid:9380  ppid:5243   flags:0x00000006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 io_schedule+0xbf/0x130 kernel/sched/core.c:7559
 folio_wait_bit_common+0x3d8/0x9b0 mm/filemap.c:1309
 __folio_lock mm/filemap.c:1647 [inline]
 folio_lock include/linux/pagemap.h:1148 [inline]
 folio_lock include/linux/pagemap.h:1144 [inline]
 __filemap_get_folio+0x6a4/0xaf0 mm/filemap.c:1900
 filemap_lock_folio include/linux/pagemap.h:788 [inline]
 filemap_lock_hugetlb_folio include/linux/hugetlb.h:795 [inline]
 hugetlb_fault+0x16ff/0x2fa0 mm/hugetlb.c:6406
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x60d/0x13f0 arch/x86/mm/fault.c:1338
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0033:0x7f1ba3b0f030
RSP: 002b:00007f1ba3add220 EFLAGS: 00010217
RAX: 00007f1ba3b0f030 RBX: 00007f1ba3bcd338 RCX: ffffffffffffffb0
RDX: 0000000000000000 RSI: 0000000000000080 RDI: 00007f1ba3bcd338
RBP: 00007f1ba3bcd330 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
INFO: task syz-executor966:9434 blocked for more than 143 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:27728 pid:9434  tgid:9430  ppid:5238   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6831
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x7a3/0x13f0 arch/x86/mm/fault.c:1389
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:rep_movs_alternative+0x33/0x70 arch/x86/lib/copy_user_64.S:58
Code: 40 83 f9 08 73 21 85 c9 74 0f 8a 06 88 07 48 ff c7 48 ff c6 48 ff c9 75 f1 c3 cc cc cc cc 66 0f 1f 84 00 00 00 00 00 48 8b 06 <48> 89 07 48 83 c6 08 48 83 c7 08 83 e9 08 74 df 83 f9 08 73 e8 eb
RSP: 0018:ffffc9000cde7c48 EFLAGS: 00050246
RAX: 0000000000000000 RBX: 0000000000000008 RCX: 0000000000000008
RDX: fffff520019bcf98 RSI: ffffc9000cde7cb8 RDI: 000000002001d448
RBP: 000000002001d448 R08: 0000000000000000 R09: fffff520019bcf97
R10: ffffc9000cde7cbf R11: 0000000000000000 R12: ffffc9000cde7cb8
R13: 000000002001d450 R14: 0000000000000000 R15: 0000000020019680
 copy_user_generic arch/x86/include/asm/uaccess_64.h:121 [inline]
 raw_copy_to_user arch/x86/include/asm/uaccess_64.h:142 [inline]
 _inline_copy_to_user include/linux/uaccess.h:188 [inline]
 _copy_to_user+0xac/0xc0 lib/usercopy.c:26
 copy_to_user include/linux/uaccess.h:216 [inline]
 msr_read+0x14f/0x250 arch/x86/kernel/msr.c:69
 vfs_read+0x1ce/0xbd0 fs/read_write.c:567
 ksys_read+0x12f/0x260 fs/read_write.c:712
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1ba3b462d9
RSP: 002b:00007f1ba3afe218 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
RAX: ffffffffffffffda RBX: 00007f1ba3bcd328 RCX: 00007f1ba3b462d9
RDX: 0000000000018ff8 RSI: 0000000020019680 RDI: 0000000000000003
RBP: 00007f1ba3bcd320 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
INFO: task syz-executor966:9437 blocked for more than 144 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:27408 pid:9437  tgid:9430  ppid:5238   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6831
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
 vfs_fallocate+0x459/0xf90 fs/open.c:333
 ksys_fallocate fs/open.c:356 [inline]
 __do_sys_fallocate fs/open.c:364 [inline]
 __se_sys_fallocate fs/open.c:362 [inline]
 __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1ba3b462d9
RSP: 002b:00007f1ba3add218 EFLAGS: 00000246 ORIG_RAX: 000000000000011d
RAX: ffffffffffffffda RBX: 00007f1ba3bcd338 RCX: 00007f1ba3b462d9
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000004
RBP: 00007f1ba3bcd330 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000400 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
INFO: task syz-executor966:9679 blocked for more than 144 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:28288 pid:9679  tgid:9678  ppid:5241   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6831
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x7a3/0x13f0 arch/x86/mm/fault.c:1389
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:rep_movs_alternative+0x33/0x70 arch/x86/lib/copy_user_64.S:58
Code: 40 83 f9 08 73 21 85 c9 74 0f 8a 06 88 07 48 ff c7 48 ff c6 48 ff c9 75 f1 c3 cc cc cc cc 66 0f 1f 84 00 00 00 00 00 48 8b 06 <48> 89 07 48 83 c6 08 48 83 c7 08 83 e9 08 74 df 83 f9 08 73 e8 eb
RSP: 0018:ffffc9000d2b7c48 EFLAGS: 00050246
RAX: 0000000000000000 RBX: 0000000000000008 RCX: 0000000000000008
RDX: fffff52001a56f98 RSI: ffffc9000d2b7cb8 RDI: 0000000020020f20
RBP: 0000000020020f20 R08: 0000000000000000 R09: fffff52001a56f97
R10: ffffc9000d2b7cbf R11: 0000000000000000 R12: ffffc9000d2b7cb8
R13: 0000000020020f28 R14: 0000000000000000 R15: 0000000020019680
 copy_user_generic arch/x86/include/asm/uaccess_64.h:121 [inline]
 raw_copy_to_user arch/x86/include/asm/uaccess_64.h:142 [inline]
 _inline_copy_to_user include/linux/uaccess.h:188 [inline]
 _copy_to_user+0xac/0xc0 lib/usercopy.c:26
 copy_to_user include/linux/uaccess.h:216 [inline]
 msr_read+0x14f/0x250 arch/x86/kernel/msr.c:69
 vfs_read+0x1ce/0xbd0 fs/read_write.c:567
 ksys_read+0x12f/0x260 fs/read_write.c:712
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1ba3b462d9
RSP: 002b:00007f1ba3afe218 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
RAX: ffffffffffffffda RBX: 00007f1ba3bcd328 RCX: 00007f1ba3b462d9
RDX: 0000000000018ff8 RSI: 0000000020019680 RDI: 0000000000000003
RBP: 00007f1ba3bcd320 R08: 0000000000000000 R09: 0000000000000000
R10: 0072736d2f232f75 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
INFO: task syz-executor966:9684 blocked for more than 144 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:27408 pid:9684  tgid:9678  ppid:5241   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6831
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
 vfs_fallocate+0x459/0xf90 fs/open.c:333
 ksys_fallocate fs/open.c:356 [inline]
 __do_sys_fallocate fs/open.c:364 [inline]
 __se_sys_fallocate fs/open.c:362 [inline]
 __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1ba3b462d9
RSP: 002b:00007f1ba3add218 EFLAGS: 00000246 ORIG_RAX: 000000000000011d
RAX: ffffffffffffffda RBX: 00007f1ba3bcd338 RCX: 00007f1ba3b462d9
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000004
RBP: 00007f1ba3bcd330 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000400 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
INFO: task syz-executor966:9733 blocked for more than 145 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:28288 pid:9733  tgid:9731  ppid:5239   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6831
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x7a3/0x13f0 arch/x86/mm/fault.c:1389
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:rep_movs_alternative+0x33/0x70 arch/x86/lib/copy_user_64.S:58
Code: 40 83 f9 08 73 21 85 c9 74 0f 8a 06 88 07 48 ff c7 48 ff c6 48 ff c9 75 f1 c3 cc cc cc cc 66 0f 1f 84 00 00 00 00 00 48 8b 06 <48> 89 07 48 83 c6 08 48 83 c7 08 83 e9 08 74 df 83 f9 08 73 e8 eb
RSP: 0018:ffffc9000d2e7c48 EFLAGS: 00050246
RAX: 0000000000000000 RBX: 0000000000000008 RCX: 0000000000000008
RDX: fffff52001a5cf98 RSI: ffffc9000d2e7cb8 RDI: 0000000020023000
RBP: 0000000020023000 R08: 0000000000000000 R09: fffff52001a5cf97
R10: ffffc9000d2e7cbf R11: 0000000000000000 R12: ffffc9000d2e7cb8
R13: 0000000020023008 R14: 0000000000000000 R15: 0000000020019680
 copy_user_generic arch/x86/include/asm/uaccess_64.h:121 [inline]
 raw_copy_to_user arch/x86/include/asm/uaccess_64.h:142 [inline]
 _inline_copy_to_user include/linux/uaccess.h:188 [inline]
 _copy_to_user+0xac/0xc0 lib/usercopy.c:26
 copy_to_user include/linux/uaccess.h:216 [inline]
 msr_read+0x14f/0x250 arch/x86/kernel/msr.c:69
 vfs_read+0x1ce/0xbd0 fs/read_write.c:567
 ksys_read+0x12f/0x260 fs/read_write.c:712
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1ba3b462d9
RSP: 002b:00007f1ba3afe218 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
RAX: ffffffffffffffda RBX: 00007f1ba3bcd328 RCX: 00007f1ba3b462d9
RDX: 0000000000018ff8 RSI: 0000000020019680 RDI: 0000000000000003
RBP: 00007f1ba3bcd320 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
INFO: task syz-executor966:9735 blocked for more than 145 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:27408 pid:9735  tgid:9731  ppid:5239   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6831
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
 vfs_fallocate+0x459/0xf90 fs/open.c:333
 ksys_fallocate fs/open.c:356 [inline]
 __do_sys_fallocate fs/open.c:364 [inline]
 __se_sys_fallocate fs/open.c:362 [inline]
 __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1ba3b462d9
RSP: 002b:00007f1ba3add218 EFLAGS: 00000246 ORIG_RAX: 000000000000011d
RAX: ffffffffffffffda RBX: 00007f1ba3bcd338 RCX: 00007f1ba3b462d9
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000004
RBP: 00007f1ba3bcd330 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000400 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
INFO: task syz-executor966:9786 blocked for more than 145 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:27648 pid:9786  tgid:9785  ppid:5236   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6831
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 handle_mm_fault+0x930/0xaa0 mm/memory.c:6060
 do_user_addr_fault+0x7a3/0x13f0 arch/x86/mm/fault.c:1389
 handle_page_fault arch/x86/mm/fault.c:1481 [inline]
 exc_page_fault+0x5c/0xc0 arch/x86/mm/fault.c:1539
 asm_exc_page_fault+0x26/0x30 arch/x86/include/asm/idtentry.h:623
RIP: 0010:rep_movs_alternative+0x33/0x70 arch/x86/lib/copy_user_64.S:58
Code: 40 83 f9 08 73 21 85 c9 74 0f 8a 06 88 07 48 ff c7 48 ff c6 48 ff c9 75 f1 c3 cc cc cc cc 66 0f 1f 84 00 00 00 00 00 48 8b 06 <48> 89 07 48 83 c6 08 48 83 c7 08 83 e9 08 74 df 83 f9 08 73 e8 eb
RSP: 0018:ffffc9000d477c48 EFLAGS: 00050246
RAX: 0000000000000000 RBX: 0000000000000008 RCX: 0000000000000008
RDX: fffff52001a8ef98 RSI: ffffc9000d477cb8 RDI: 00000000200226e0
RBP: 00000000200226e0 R08: 0000000000000000 R09: fffff52001a8ef97
R10: ffffc9000d477cbf R11: 0000000000000000 R12: ffffc9000d477cb8
R13: 00000000200226e8 R14: 0000000000000000 R15: 0000000020019680
 copy_user_generic arch/x86/include/asm/uaccess_64.h:121 [inline]
 raw_copy_to_user arch/x86/include/asm/uaccess_64.h:142 [inline]
 _inline_copy_to_user include/linux/uaccess.h:188 [inline]
 _copy_to_user+0xac/0xc0 lib/usercopy.c:26
 copy_to_user include/linux/uaccess.h:216 [inline]
 msr_read+0x14f/0x250 arch/x86/kernel/msr.c:69
 vfs_read+0x1ce/0xbd0 fs/read_write.c:567
 ksys_read+0x12f/0x260 fs/read_write.c:712
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1ba3b462d9
RSP: 002b:00007f1ba3afe218 EFLAGS: 00000246 ORIG_RAX: 0000000000000000
RAX: ffffffffffffffda RBX: 00007f1ba3bcd328 RCX: 00007f1ba3b462d9
RDX: 0000000000018ff8 RSI: 0000000020019680 RDI: 0000000000000003
RBP: 00007f1ba3bcd320 R08: 0000000000000000 R09: 0000000000000000
R10: 0072736d2f232f75 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
INFO: task syz-executor966:9787 blocked for more than 146 seconds.
      Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
"echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message.
task:syz-executor966 state:D stack:27408 pid:9787  tgid:9785  ppid:5236   flags:0x00004006
Call Trace:
 <TASK>
 context_switch kernel/sched/core.c:5322 [inline]
 __schedule+0xef5/0x5750 kernel/sched/core.c:6682
 __schedule_loop kernel/sched/core.c:6759 [inline]
 schedule+0xe7/0x350 kernel/sched/core.c:6774
 schedule_preempt_disabled+0x13/0x30 kernel/sched/core.c:6831
 __mutex_lock_common kernel/locking/mutex.c:684 [inline]
 __mutex_lock+0x5b8/0x9c0 kernel/locking/mutex.c:752
 hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
 vfs_fallocate+0x459/0xf90 fs/open.c:333
 ksys_fallocate fs/open.c:356 [inline]
 __do_sys_fallocate fs/open.c:364 [inline]
 __se_sys_fallocate fs/open.c:362 [inline]
 __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f1ba3b462d9
RSP: 002b:00007f1ba3add218 EFLAGS: 00000246 ORIG_RAX: 000000000000011d
RAX: ffffffffffffffda RBX: 00007f1ba3bcd338 RCX: 00007f1ba3b462d9
RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000004
RBP: 00007f1ba3bcd330 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000000400 R11: 0000000000000246 R12: 00007f1ba3b9a328
R13: 00007f1ba3b9a078 R14: 0072736d2f232f75 R15: 7570632f7665642f
 </TASK>
Future hung task reports are suppressed, see sysctl kernel.hung_task_warnings

Showing all locks held in the system:
1 lock held by khungtaskd/30:
 #0: ffffffff8e1b8340 (rcu_read_lock){....}-{1:2}, at: rcu_lock_acquire include/linux/rcupdate.h:337 [inline]
 #0: ffffffff8e1b8340 (rcu_read_lock){....}-{1:2}, at: rcu_read_lock include/linux/rcupdate.h:849 [inline]
 #0: ffffffff8e1b8340 (rcu_read_lock){....}-{1:2}, at: debug_show_all_locks+0x7f/0x390 kernel/locking/lockdep.c:6720
2 locks held by kworker/u8:5/793:
2 locks held by getty/4972:
 #0: ffff88814bbbb0a0 (&tty->ldisc_sem){++++}-{0:0}, at: tty_ldisc_ref_wait+0x24/0x80 drivers/tty/tty_ldisc.c:243
 #1: ffffc90002f062f0 (&ldata->atomic_read_lock){+.+.}-{3:3}, at: n_tty_read+0xfba/0x1480 drivers/tty/n_tty.c:2211
2 locks held by syz-executor966/9384:
 #0: ffff88807b034418 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_trylock include/linux/mmap_lock.h:163 [inline]
 #0: ffff88807b034418 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:6099 [inline]
 #0: ffff88807b034418 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x35/0x6a0 mm/memory.c:6159
 #1: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_wp+0x1b4a/0x3320 mm/hugetlb.c:5894
3 locks held by syz-executor966/9388:
 #0: ffff888079ca1ec8 (&vma->vm_lock->lock){++++}-{3:3}, at: vma_start_read include/linux/mm.h:704 [inline]
 #0: ffff888079ca1ec8 (&vma->vm_lock->lock){++++}-{3:3}, at: lock_vma_under_rcu+0x13e/0x980 mm/memory.c:6228
 #1: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
 #2: ffff88802db4ace8 (&resv_map->rw_sema){++++}-{3:3}, at: hugetlb_vma_lock_read mm/hugetlb.c:276 [inline]
 #2: ffff88802db4ace8 (&resv_map->rw_sema){++++}-{3:3}, at: hugetlb_vma_lock_read+0x105/0x140 mm/hugetlb.c:267
2 locks held by syz-executor966/9434:
 #0: ffff88805f660198 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_trylock include/linux/mmap_lock.h:163 [inline]
 #0: ffff88805f660198 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:6099 [inline]
 #0: ffff88805f660198 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x35/0x6a0 mm/memory.c:6159
 #1: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
3 locks held by syz-executor966/9437:
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: ksys_fallocate fs/open.c:356 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __do_sys_fallocate fs/open.c:364 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __se_sys_fallocate fs/open.c:362 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 #1: ffff888030dd9588 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: inode_lock include/linux/fs.h:815 [inline]
 #1: ffff888030dd9588 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x2b6/0xfc0 fs/hugetlbfs/inode.c:828
 #2: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
2 locks held by syz-executor966/9679:
 #0: ffff88807c5a1498 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_trylock include/linux/mmap_lock.h:163 [inline]
 #0: ffff88807c5a1498 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:6099 [inline]
 #0: ffff88807c5a1498 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x35/0x6a0 mm/memory.c:6159
 #1: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
3 locks held by syz-executor966/9684:
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: ksys_fallocate fs/open.c:356 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __do_sys_fallocate fs/open.c:364 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __se_sys_fallocate fs/open.c:362 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 #1: ffff88807a45da98 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: inode_lock include/linux/fs.h:815 [inline]
 #1: ffff88807a45da98 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x2b6/0xfc0 fs/hugetlbfs/inode.c:828
 #2: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
2 locks held by syz-executor966/9733:
 #0: ffff88807b17b118 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock_killable include/linux/mmap_lock.h:153 [inline]
 #0: ffff88807b17b118 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:6108 [inline]
 #0: ffff88807b17b118 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x3a9/0x6a0 mm/memory.c:6159
 #1: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
3 locks held by syz-executor966/9735:
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: ksys_fallocate fs/open.c:356 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __do_sys_fallocate fs/open.c:364 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __se_sys_fallocate fs/open.c:362 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 #1: ffff88807a45e4b8 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: inode_lock include/linux/fs.h:815 [inline]
 #1: ffff88807a45e4b8 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x2b6/0xfc0 fs/hugetlbfs/inode.c:828
 #2: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872
2 locks held by syz-executor966/9786:
 #0: ffff88805f768198 (&mm->mmap_lock){++++}-{3:3}, at: mmap_read_lock_killable include/linux/mmap_lock.h:153 [inline]
 #0: ffff88805f768198 (&mm->mmap_lock){++++}-{3:3}, at: get_mmap_lock_carefully mm/memory.c:6108 [inline]
 #0: ffff88805f768198 (&mm->mmap_lock){++++}-{3:3}, at: lock_mm_and_find_vma+0x3a9/0x6a0 mm/memory.c:6159
 #1: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlb_fault+0x307/0x2fa0 mm/hugetlb.c:6326
3 locks held by syz-executor966/9787:
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: ksys_fallocate fs/open.c:356 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __do_sys_fallocate fs/open.c:364 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __se_sys_fallocate fs/open.c:362 [inline]
 #0: ffff8881456d0420 (sb_writers#10){.+.+}-{0:0}, at: __x64_sys_fallocate+0xd9/0x150 fs/open.c:362
 #1: ffff88807a910148 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: inode_lock include/linux/fs.h:815 [inline]
 #1: ffff88807a910148 (&sb->s_type->i_mutex_key#15){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x2b6/0xfc0 fs/hugetlbfs/inode.c:828
 #2: ffff8881412dc698 (&hugetlb_fault_mutex_table[i]){+.+.}-{3:3}, at: hugetlbfs_fallocate+0x577/0xfc0 fs/hugetlbfs/inode.c:872

=============================================

NMI backtrace for cpu 1
CPU: 1 UID: 0 PID: 30 Comm: khungtaskd Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024
Call Trace:
 <TASK>
 __dump_stack lib/dump_stack.c:94 [inline]
 dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120
 nmi_cpu_backtrace+0x27b/0x390 lib/nmi_backtrace.c:113
 nmi_trigger_cpumask_backtrace+0x29c/0x300 lib/nmi_backtrace.c:62
 trigger_all_cpu_backtrace include/linux/nmi.h:162 [inline]
 check_hung_uninterruptible_tasks kernel/hung_task.c:223 [inline]
 watchdog+0xf0c/0x1240 kernel/hung_task.c:379
 kthread+0x2c1/0x3a0 kernel/kthread.c:389
 ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:147
 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244
 </TASK>
Sending NMI from CPU 1 to CPUs 0:
NMI backtrace for cpu 0
CPU: 0 UID: 0 PID: 4662 Comm: klogd Not tainted 6.12.0-rc2-syzkaller-00061-gb983b271662b #0
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024
RIP: 0010:check_kcov_mode kernel/kcov.c:183 [inline]
RIP: 0010:__sanitizer_cov_trace_pc+0x13/0x70 kernel/kcov.c:217
Code: 84 00 00 00 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa 65 48 8b 15 64 59 76 7e 65 8b 05 65 59 76 7e <a9> 00 01 ff 00 48 8b 34 24 74 1d f6 c4 01 74 43 a9 00 00 0f 00 75
RSP: 0018:ffffc900033efaa0 EFLAGS: 00000293
RAX: 0000000080000000 RBX: 0000000000000000 RCX: ffffffff84430a29
RDX: ffff88807d2f5a00 RSI: ffffffff844309e3 RDI: 0000000000000005
RBP: ffff8880248e98c0 R08: 0000000000000005 R09: 0000000000000000
R10: 0000000000000000 R11: 0000000000000000 R12: ffff888079859c80
R13: 0000000000000001 R14: ffff8880248e98c0 R15: ffff8880248e98c0
FS:  00007efe5ee35380(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000
CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
CR2: 00005638ed3e1400 CR3: 000000007c050000 CR4: 00000000003526f0
DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
Call Trace:
 <NMI>
 </NMI>
 <TASK>
 arch_static_branch arch/x86/include/asm/jump_label.h:27 [inline]
 security_sock_rcv_skb+0x5d/0x210 security/security.c:4748
 sk_filter_trim_cap+0xd2/0xac0 net/core/filter.c:151
 sk_filter include/linux/filter.h:1062 [inline]
 unix_dgram_sendmsg+0x66a/0x19e0 net/unix/af_unix.c:2061
 sock_sendmsg_nosec net/socket.c:729 [inline]
 __sock_sendmsg net/socket.c:744 [inline]
 __sys_sendto+0x479/0x4d0 net/socket.c:2209
 __do_sys_sendto net/socket.c:2221 [inline]
 __se_sys_sendto net/socket.c:2217 [inline]
 __x64_sys_sendto+0xe0/0x1c0 net/socket.c:2217
 do_syscall_x64 arch/x86/entry/common.c:52 [inline]
 do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7efe5ef979b5
Code: 8b 44 24 08 48 83 c4 28 48 98 c3 48 98 c3 41 89 ca 64 8b 04 25 18 00 00 00 85 c0 75 26 45 31 c9 45 31 c0 b8 2c 00 00 00 0f 05 <48> 3d 00 f0 ff ff 76 7a 48 8b 15 44 c4 0c 00 f7 d8 64 89 02 48 83
RSP: 002b:00007ffdfcdf97a8 EFLAGS: 00000246 ORIG_RAX: 000000000000002c
RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007efe5ef979b5
RDX: 000000000000008b RSI: 000055ec577dbd60 RDI: 0000000000000003
RBP: 000055ec577d52c0 R08: 0000000000000000 R09: 0000000000000000
R10: 0000000000004000 R11: 0000000000000246 R12: 0000000000000013
R13: 00007efe5f125212 R14: 00007ffdfcdf98a8 R15: 0000000000000000
 </TASK>
INFO: NMI handler (nmi_cpu_backtrace_handler) took too long to run: 1.352 msecs


---
If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6707a270.050a0220.64b99.0015.GAE%40google.com.
