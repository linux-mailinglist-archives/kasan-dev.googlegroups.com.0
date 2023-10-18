Return-Path: <kasan-dev+bncBCQPF57GUQHBBQ74XSUQMGQEK3DX2JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id BD0117CD225
	for <lists+kasan-dev@lfdr.de>; Wed, 18 Oct 2023 04:09:08 +0200 (CEST)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-1c8c1f34aadsf8672783fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 17 Oct 2023 19:09:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1697594947; cv=pass;
        d=google.com; s=arc-20160816;
        b=lbE7xNBUkIPIaG34lNs25UzWOGqQOMgPmKdJz+WhWQygsTHieLCbpyOK7wAf5lJvJE
         BFmdaoY9IWpl8s9qIfsmITZapjjz3WuwftVSfgM/Euy/3BX323Rf4FP/TUJrmMoTZfDT
         mUgCyH8L7Wubu+ZeG1CQer02A0LeFowEUQW7P7OapsBs9f4jslsnMNGNp8L+7wpHesgX
         az2kocc9tStKVfWztqv3gaqaWq5yJzsLc3czin1EL8xUozAG8eYB1GombnTxBThzitvP
         jtHxOOHvuZPTCerjYivFfxcXVXEX6ueTatgBpw04ehaoxbX8mOES8H6ZU25OVJBOg1mj
         Douw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=K/fzDqzUdCCZWs4F1iYjuK054u3IuNzREwXFHGIJyQs=;
        fh=EhI7raQVU504SOliCsBJmME7ipf9kYC5/YzijMn2XTc=;
        b=lbW4BLxNQM3EYB+qs1oKpPCe/3nrHH/b4at37lP16xurGrcHoqwZGuuPLfkbq311eR
         U/Bf+nBJ2f/zmtk0expFl3q00FAvvYQxiwj2KzhEARZ8TnMS3qIjuiT1lIpxicT1gRHS
         Y+B4HqkZl1+9DsG5AKdUimI3e6d9aLU2/1mf4lNv5YDm3N5TEemp2SJjm7Vov5I7PtyP
         SB+3Fez0ITVsueP59H/zDygKLA8dGqURHLSX+BJAvuTK8BSWg8CUF+aWn8yjMKPQj3Kf
         WLQiK2uYITIyj2q8sUgysCfVRM3R/CyDfWRKDETgt+Wds7lEVmaJE9vMD8QoOCinnKGI
         D9uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3qj4vzqkbaksdjkvlwwpclaato.rzzrwpfdpcnzyepye.nzx@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.160.80 as permitted sender) smtp.mailfrom=3Qj4vZQkbAKsdjkVLWWPcLaaTO.RZZRWPfdPcNZYePYe.NZX@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1697594947; x=1698199747; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:date:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=K/fzDqzUdCCZWs4F1iYjuK054u3IuNzREwXFHGIJyQs=;
        b=nzpDWdwDCr6G+AH2AZA32Cg6DmHklz2np41OAqudio5Fvp8vTM/AGDUY/0nwhSwZAl
         hn9WTiURW0WoyD6n0abd3X73Fp3YfpHtOAIQRLuc+uOGQpG1pmmadU3M341EnEgUpu9r
         uWJzOePzxcnhc9CA5KegGpdp68obGdwoqipVurjTHEE5nzAVkVB8ZKbfj6DPAie6iDAN
         sQI+2JdDw9aWZBzmGAannQgMGQQJOQ07jGdC7n4O/U4rX3zBu2cu2B6pdeCFLGvZf9LB
         11CEla/r+/OZ00qw2jbYm/9NWtSXBkCKtCkIz/Kh58LTvClUnArV0gWL0I/3iOjaUHzN
         ZpXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1697594947; x=1698199747;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:date:mime-version:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=K/fzDqzUdCCZWs4F1iYjuK054u3IuNzREwXFHGIJyQs=;
        b=qYabs1bxo4UMGeRBiZy3L2fobEIFBAWw6AK+C6wdGY5QBh0yFf9YfbbzAxRrkxXF8k
         j2O5wlNEbglwIR8wfP0ogB8Vm3ODpuzDDZBpue40zeqjqTw2fewt98g1e0W/JquHsSFN
         XcKEZSH72TKHwn2BJXQwrk17+eAh8VG9W1a+J5M8L1rv2aH568LmBgqD2fy3otpIvd5u
         v8WP99VnOCOEGcRuEqQjJHBedyDljb92+F/PkExfDO3+nlACOBofc/K7JZ/BHMsQFEgs
         aU9sI9XowAh02RccJ3hihrPH8iUJA7G+U2ZoO7AffH00lncqkv4tXat+7SDhAybyvI+G
         Nz3Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz/UqyWyIgc3pvC4SMzmzIVtMZ9uar0E5xEZcT5rCARP0JxjnSq
	6Aers8fsxdM2rfuCm+imcfM=
X-Google-Smtp-Source: AGHT+IEE3lZr9w1GJ+G8hNDyd/VzpEPalNAHZY6CfIiRGRMvOYc9LnJUxtsVAUkEcD3VOvuI2gWA1A==
X-Received: by 2002:a05:6870:4997:b0:1ea:85a:db2e with SMTP id ho23-20020a056870499700b001ea085adb2emr4296751oab.45.1697594947345;
        Tue, 17 Oct 2023 19:09:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:b18:b0:1dd:4b2c:7730 with SMTP id
 lh24-20020a0568700b1800b001dd4b2c7730ls3189365oab.0.-pod-prod-04-us; Tue, 17
 Oct 2023 19:09:06 -0700 (PDT)
X-Received: by 2002:a05:6808:21a8:b0:3af:a107:cf58 with SMTP id be40-20020a05680821a800b003afa107cf58mr5313014oib.41.1697594946361;
        Tue, 17 Oct 2023 19:09:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1697594946; cv=none;
        d=google.com; s=arc-20160816;
        b=MXckE4GZj6R2DQA6vdx/GTgKL55UZ85o7jSvrVBzdkCIyL2XF4Fe+3bQzpwo6dMV8C
         sxhv1BXFQ4K2iG9c+x0jwSmAaF2BmF9UzBFBZPsrVXLwE0vFC5u3XhsO0owc1hQXQenA
         akPNWbEQpi+OhYClzaf4+xZ818GuSRv8VBHaDsRyIN+zTuXhm0uEl2L3dOgco7Dk+nL2
         kGEjAM9JkwJmoZs82zXW0P6qsdCTxskcT8aAuShfxR46xfO9WGwmYQ7GeSbeGKzOspdg
         3Q0fhcUl8KggvPXnnuh5P3DxI/6DXclAkSjxNbTYoLO13qNi3rbDUpaop8dQ/tda5lLQ
         pEMw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:date:mime-version;
        bh=rQ7FtIypEQj/f0AClAakDsoov2FH7bW4DoRItDFF3Y4=;
        fh=EhI7raQVU504SOliCsBJmME7ipf9kYC5/YzijMn2XTc=;
        b=tXKNFoV/nCQ3i9LmXEFvk6uWBgSVb1eTuEeunP5NEk7SYEEkeAiQ+WaqG/bTk2Ic55
         ZMQlEc41zFu01fanVKPf4JM32yKRsw/Q4D8W9DJBWw7K7LB9ouir5FFa0z4RhPyI56AX
         OJo7Syh+vhbvvXNTxmQuhp4kiLCiLKcC4r+iybdN43IirxwcZCL2OxPDcoXbfPY8mECd
         VALxhzQL9CLNJtrLU3DQU+WLKyI2KQH2vv0MMo8irvCZdbTRU90HaYL/gSN8eXiA6sn1
         xWPBU9UiEyoi2YYamM4PsAZ9z8tr8iz6jNWYsg74UtVAcch83289D3oughugQQkJlmzx
         gDgQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3qj4vzqkbaksdjkvlwwpclaato.rzzrwpfdpcnzyepye.nzx@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.160.80 as permitted sender) smtp.mailfrom=3Qj4vZQkbAKsdjkVLWWPcLaaTO.RZZRWPfdPcNZYePYe.NZX@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-oa1-f80.google.com (mail-oa1-f80.google.com. [209.85.160.80])
        by gmr-mx.google.com with ESMTPS id r32-20020a056808212000b003b2e4bcfc9dsi94851oiw.4.2023.10.17.19.09.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 17 Oct 2023 19:09:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qj4vzqkbaksdjkvlwwpclaato.rzzrwpfdpcnzyepye.nzx@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.160.80 as permitted sender) client-ip=209.85.160.80;
Received: by mail-oa1-f80.google.com with SMTP id 586e51a60fabf-1c8c1f34aadso8672768fac.3
        for <kasan-dev@googlegroups.com>; Tue, 17 Oct 2023 19:09:06 -0700 (PDT)
MIME-Version: 1.0
X-Received: by 2002:a05:6870:3282:b0:1d6:5e45:3bc7 with SMTP id
 q2-20020a056870328200b001d65e453bc7mr1646497oac.5.1697594946128; Tue, 17 Oct
 2023 19:09:06 -0700 (PDT)
Date: Tue, 17 Oct 2023 19:09:06 -0700
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000bc90a60607f41fc3@google.com>
Subject: [syzbot] [mm?] [kasan?] WARNING in __kfence_free (3)
From: syzbot <syzbot+59f37b0ab4c558a5357c@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3qj4vzqkbaksdjkvlwwpclaato.rzzrwpfdpcnzyepye.nzx@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.160.80 as permitted sender) smtp.mailfrom=3Qj4vZQkbAKsdjkVLWWPcLaaTO.RZZRWPfdPcNZYePYe.NZX@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    213f891525c2 Merge tag 'probes-fixes-v6.6-rc6' of git://gi..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=14a731f9680000
kernel config:  https://syzkaller.appspot.com/x/.config?x=a4436b383d761e86
dashboard link: https://syzkaller.appspot.com/bug?extid=59f37b0ab4c558a5357c
compiler:       aarch64-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40
userspace arch: arm64

Unfortunately, I don't have any reproducer for this issue yet.

Downloadable assets:
disk image (non-bootable): https://storage.googleapis.com/syzbot-assets/384ffdcca292/non_bootable_disk-213f8915.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/98b9a78b6226/vmlinux-213f8915.xz
kernel image: https://storage.googleapis.com/syzbot-assets/8ed2ef54968f/Image-213f8915.gz.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+59f37b0ab4c558a5357c@syzkaller.appspotmail.com

------------[ cut here ]------------
WARNING: CPU: 1 PID: 3252 at mm/kfence/core.c:1147 __kfence_free+0x7c/0xb4 mm/kfence/core.c:1147
Modules linked in:
CPU: 1 PID: 3252 Comm: syz-executor.1 Not tainted 6.6.0-rc6-syzkaller-00029-g213f891525c2 #0
Hardware name: linux,dummy-virt (DT)
pstate: 81400009 (Nzcv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=--)
pc : __kfence_free+0x7c/0xb4 mm/kfence/core.c:1147
lr : kfence_free include/linux/kfence.h:187 [inline]
lr : __slab_free+0x48c/0x508 mm/slub.c:3614
sp : ffff800082cebb50
x29: ffff800082cebb50 x28: f7ff000002c0c400 x27: ffff8000818ca8a8
x26: ffff8000821f0620 x25: 0000000000000001 x24: ffff00007ffa3000
x23: 0000000000000001 x22: ffff00007ffa3000 x21: ffff00007ffa3000
x20: ffff80008004191c x19: fffffc0001ffe8c0 x18: ffffffffffffffff
x17: ffff800080027b40 x16: ffff800080027a34 x15: ffff800080318514
x14: ffff8000800469c8 x13: ffff800080011558 x12: ffff800081897ff4
x11: ffff800081897b28 x10: ffff800080027bfc x9 : 0000000000400cc0
x8 : ffff800082cebc30 x7 : 0000000000000000 x6 : 0000000000000000
x5 : ffff80008004191c x4 : ffff00007f869000 x3 : ffff800082420338
x2 : fcff000006a24ec0 x1 : ffff00007f8a50a0 x0 : ffff00007ffa3000
Call trace:
 __kfence_free+0x7c/0xb4 mm/kfence/core.c:1147
 kfence_free include/linux/kfence.h:187 [inline]
 __slab_free+0x48c/0x508 mm/slub.c:3614
 do_slab_free mm/slub.c:3757 [inline]
 slab_free mm/slub.c:3810 [inline]
 __kmem_cache_free+0x220/0x230 mm/slub.c:3822
 kfree+0x5c/0x74 mm/slab_common.c:1072
 kvm_uevent_notify_change.part.0+0x10c/0x174 arch/arm64/kvm/../../../virt/kvm/kvm_main.c:5908
 kvm_uevent_notify_change arch/arm64/kvm/../../../virt/kvm/kvm_main.c:5878 [inline]
 kvm_dev_ioctl_create_vm arch/arm64/kvm/../../../virt/kvm/kvm_main.c:5107 [inline]
 kvm_dev_ioctl+0x3e8/0x91c arch/arm64/kvm/../../../virt/kvm/kvm_main.c:5131
 vfs_ioctl fs/ioctl.c:51 [inline]
 __do_sys_ioctl fs/ioctl.c:871 [inline]
 __se_sys_ioctl fs/ioctl.c:857 [inline]
 __arm64_sys_ioctl+0xac/0xf0 fs/ioctl.c:857
 __invoke_syscall arch/arm64/kernel/syscall.c:37 [inline]
 invoke_syscall+0x48/0x114 arch/arm64/kernel/syscall.c:51
 el0_svc_common.constprop.0+0x40/0xe0 arch/arm64/kernel/syscall.c:136
 do_el0_svc+0x1c/0x28 arch/arm64/kernel/syscall.c:155
 el0_svc+0x40/0x114 arch/arm64/kernel/entry-common.c:678
 el0t_64_sync_handler+0x100/0x12c arch/arm64/kernel/entry-common.c:696
 el0t_64_sync+0x19c/0x1a0 arch/arm64/kernel/entry.S:595
---[ end trace 0000000000000000 ]---


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

If the bug is already fixed, let syzbot know by replying with:
#syz fix: exact-commit-title

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000bc90a60607f41fc3%40google.com.
