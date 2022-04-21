Return-Path: <kasan-dev+bncBCQPF57GUQHBBMFZQSJQMGQEXQZSEKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 842DD509B59
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 10:58:25 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id m16-20020ad45050000000b00446393a7a9fsf3442911qvq.6
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Apr 2022 01:58:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1650531504; cv=pass;
        d=google.com; s=arc-20160816;
        b=Wg+vLxuOFxFdg1L1F3BAaN8Qnw7ITor5go8qYfkg/Zo8AUtQKpowNlWUBYedtrhRU2
         pr0ts26MhUkB1+Fy41Nu2gxhoA1O1XOz3d0EeOsBvwCLNChC0Zmczv8Iipa7YJbMEkJc
         hZqGLxKB6L329uKfJFxsc4o3sv+QSLnnyMOYkQlrNbygeL2k/0ETmL9gW2v58taQxU6z
         SiEhBmAJrO6DgPCxGA39YYZsgJplQZha/T8rFUNi81sGsvVrA3VSDzNtUXNoa/3ne6CX
         4RwlCKSGwhHatAUUMwCx5FjR8oCiBA4wwnrZlahdOh2eOfQ1uXgtWVBrmoCd49TajHei
         nt2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id:date
         :mime-version:sender:dkim-signature;
        bh=C7UXuC6MnxPr+dgw9IY/hUkldV14MUoMK6ePzssZ1hk=;
        b=rDJ1ycz6mjmBshXuXnF+7gI2KuZqu3ZELqV5KfX1EIrOXz5hUAXe8ZlJ80xCPuyv43
         RozKlp76aIglTMbCCZQPyQJuJKp5IBz6PPmywJWsmZTElRJS+nGPN2Ke+XxcnF9LDzN3
         HTFQAv76T/3Ae4dYnz4nDl5jVRWhprDphA9B9XP5xoK3OrmkBp/2a9ATyc4jCKtONR61
         tdx23EvCmHjSIazQ8J0xeRgRidnwSL0YlAJxsEY+rWoaCOC6Ae8tFZN4+9778Uc5iV+o
         harpB/v6PQLjPXvF04fta80X9Iub21TSTWwFOaMssp+nqXjUR3kMvI0oE7H7ytRyZE2U
         kK1Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3rxxhygkbaiy289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.72 as permitted sender) smtp.mailfrom=3rxxhYgkbAIY289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:date:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=C7UXuC6MnxPr+dgw9IY/hUkldV14MUoMK6ePzssZ1hk=;
        b=Pn1dsnmS70MatyI2WmBrz2GkxxU1CseymRoImrEzsvtmLeZ7xOi8YCtCdQ2pvhzzA/
         UXv51P4OthLlfKyiNuXLkbzqtEeEcSPuNrpPYTaRrmhOsnFJjYuOOjWU4HAqgCTCDbkt
         +7AtHkNL3jT2Qs+a2dwKj+WuBl9YX4XMCdc0312VXmr5ejwcFRwrByeSpb+6sn5iWfvQ
         7I+JOWgccpvanBWrIiNANquENLkES4HoWLMQFPwyEI3BhGDc2KsZ3p5jbhQHaJIS3EI6
         BZJTHmoAXAUC1LNr+EXEDizGR4tw0WOC0yMic0Zbrwv1tmvAE19gyhV63iMs4FvxtBt7
         akOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:date:message-id:subject:from
         :to:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=C7UXuC6MnxPr+dgw9IY/hUkldV14MUoMK6ePzssZ1hk=;
        b=sQU6/2p0dR3JlHpcb5F+DMIo7W3HNO53LmEQVRjxhh8kEhYUHOn8pQvwQXIeizoEtS
         oiQrJJ/7jkx5lSW/w//3dQHxEC/2XZzDsPCWvywvYVNXibY5Uo6dDcjFoR5Vd66M+ala
         9FM0DJplWGB+Gw5JOJZUH+mwaAQj3Let8hAkjkoMQH8wt2qZih1rJ6ulj1wKqu4uSB4R
         AeaMvIEPm5fdjBv/ZVhOhkr+/KELyOl3ccovG27cs04XJVomaKrzjaCtFIfRRBbhoDY4
         c+R+mta+ni2btpUVgOiHp0PTPmNSOO8hvRQj+i6L8RlQhlyKeiZaXtOV+LR+FzvC2TW1
         WpBw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530DYgmdBHDOSF2w8I55riGTcm2oTjjK3B0UgA9qEntkmeWdc8hp
	A1UICn4sQ7TlVB+iEd1+NBw=
X-Google-Smtp-Source: ABdhPJxmwCKwYRwf63LbA4stuB8M7U6g/Kzzld9DgItti94JxOo05qVHrurCak1qCAA3V2EbZcBFPw==
X-Received: by 2002:a05:622a:1051:b0:2f2:681:458c with SMTP id f17-20020a05622a105100b002f20681458cmr10143198qte.581.1650531504403;
        Thu, 21 Apr 2022 01:58:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:45a8:0:b0:446:1f10:4a71 with SMTP id y8-20020ad445a8000000b004461f104a71ls2169886qvu.7.gmail;
 Thu, 21 Apr 2022 01:58:23 -0700 (PDT)
X-Received: by 2002:ad4:5ce5:0:b0:44c:3aec:5f65 with SMTP id iv5-20020ad45ce5000000b0044c3aec5f65mr1777206qvb.86.1650531503858;
        Thu, 21 Apr 2022 01:58:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1650531503; cv=none;
        d=google.com; s=arc-20160816;
        b=F29/FK+iVCYgMKaI49lrdUlBC1t+EN6ejBTdZW9/HyNhvy0zvhRNzX/lzsB3+T2CCc
         oEdtln2ScMdKxeCytbE7Bgf8XUYywzCRvJcy1zoAVCBzBtlU0/lbBGjHTQuNVUwjZZLv
         0oNQMYWZKJy5+q3yDcEbOt/9rv9CRm0afUDe87muzFyQYl0PCmgTsepMV1iLNMy7H/tj
         t16qV0acHiticfRtKcPYOAIsWWbrj5eKjuFhhRJTBDUD1r19m/2xqQ7FoE13/7vRJhm4
         sd4H/y+xmY/kM3thYVJgDGWI1MVewyT730Gu7QLUc/CinweL8hSiEX6uFZdpxvcvDPxW
         SLfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:date:mime-version;
        bh=hEgnTex8BYwpSBORN3EBim5ECJvWbtZDB9zT3ak4tmY=;
        b=Q7efmyAj5Ph61nHB4MwdSHCeTTSqulVZrr1Gl6S/C4DSqjc9MBIRup35KRjjrhFRs5
         5tHxWgwhuseDoLGAjmp8tnwSR6TdnNQXnrf/n9Vz8sIEpF0qZ/KGBaB6Z85y8iJuF6sS
         VBjKSvCh1dCT2T0k5pN19f9zG6K/sph4YczR3bWpGmjvOCf18Nc76661YKKK16Oa8CxT
         giRqVqwDbLgNNGagW4R376Z4/cpgtders4zMMwBv+/zabGxF1O122m9JizqoG5GcUsiZ
         M4lRHQXHdhwVbrFWfYvTAre7Fphb5MwOo9qYxljwh7F4JHlCHmSp5hdVgr7PdPv4dS0N
         eyEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3rxxhygkbaiy289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.72 as permitted sender) smtp.mailfrom=3rxxhYgkbAIY289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-io1-f72.google.com (mail-io1-f72.google.com. [209.85.166.72])
        by gmr-mx.google.com with ESMTPS id l10-20020ae9f00a000000b0069e24bffeb9si481530qkg.6.2022.04.21.01.58.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Apr 2022 01:58:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rxxhygkbaiy289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.72 as permitted sender) client-ip=209.85.166.72;
Received: by mail-io1-f72.google.com with SMTP id j6-20020a5d93c6000000b0064fbbf9566bso2861156ioo.12
        for <kasan-dev@googlegroups.com>; Thu, 21 Apr 2022 01:58:23 -0700 (PDT)
MIME-Version: 1.0
X-Received: by 2002:a05:6602:2dcf:b0:656:d2f8:9dee with SMTP id
 l15-20020a0566022dcf00b00656d2f89deemr3420087iow.29.1650531503466; Thu, 21
 Apr 2022 01:58:23 -0700 (PDT)
Date: Thu, 21 Apr 2022 01:58:23 -0700
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000f46c6305dd264f30@google.com>
Subject: [syzbot] WARNING in __kfence_free
From: syzbot <syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, dvyukov@google.com, elver@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3rxxhygkbaiy289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.72 as permitted sender) smtp.mailfrom=3rxxhYgkbAIY289ukvvo1kzzsn.qyyqvo42o1myx3ox3.myw@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    559089e0a93d vmalloc: replace VM_NO_HUGE_VMAP with VM_ALLO..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=10853220f00000
kernel config:  https://syzkaller.appspot.com/x/.config?x=2e1f9b9947966f42
dashboard link: https://syzkaller.appspot.com/bug?extid=ffe71f1ff7f8061bcc98
compiler:       aarch64-linux-gnu-gcc (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2
userspace arch: arm64

Unfortunately, I don't have any reproducer for this issue yet.

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+ffe71f1ff7f8061bcc98@syzkaller.appspotmail.com

------------[ cut here ]------------
WARNING: CPU: 0 PID: 2216 at mm/kfence/core.c:1022 __kfence_free+0x84/0xc0 mm/kfence/core.c:1022
Modules linked in:
CPU: 0 PID: 2216 Comm: syz-executor.0 Not tainted 5.18.0-rc3-syzkaller-00007-g559089e0a93d #0
Hardware name: linux,dummy-virt (DT)
pstate: 80400009 (Nzcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : __kfence_free+0x84/0xc0 mm/kfence/core.c:1022
lr : kfence_free include/linux/kfence.h:186 [inline]
lr : __slab_free+0x2e4/0x4d4 mm/slub.c:3315
sp : ffff80000a9fb980
x29: ffff80000a9fb980 x28: ffff80000a280040 x27: f2ff000002c01c00
x26: ffff00007b694040 x25: ffff00007b694000 x24: 0000000000000001
x23: ffff00007b694000 x22: ffff00007b694000 x21: f2ff000002c01c00
x20: ffff80000821accc x19: fffffc0001eda500 x18: 0000000000000002
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000001 x13: 000000000005eb7f x12: f7ff000007a08024
x11: f7ff000007a08000 x10: 0000000000000000 x9 : 0000000000000014
x8 : 0000000000000001 x7 : 0000000000094000 x6 : ffff80000a280000
x5 : ffff80000821accc x4 : ffff80000a50e078 x3 : ffff80000a280348
x2 : f0ff00001e325c00 x1 : ffff80000a522b40 x0 : ffff00007b694000
Call trace:
 __kfence_free+0x84/0xc0 mm/kfence/core.c:1022
 kfence_free include/linux/kfence.h:186 [inline]
 __slab_free+0x2e4/0x4d4 mm/slub.c:3315
 do_slab_free mm/slub.c:3498 [inline]
 slab_free mm/slub.c:3511 [inline]
 kfree+0x320/0x37c mm/slub.c:4552
 kvfree+0x3c/0x50 mm/util.c:615
 xt_free_table_info+0x78/0x90 net/netfilter/x_tables.c:1212
 __do_replace+0x240/0x330 net/ipv6/netfilter/ip6_tables.c:1104
 do_replace net/ipv6/netfilter/ip6_tables.c:1157 [inline]
 do_ip6t_set_ctl+0x374/0x4e0 net/ipv6/netfilter/ip6_tables.c:1639
 nf_setsockopt+0x68/0x94 net/netfilter/nf_sockopt.c:101
 ipv6_setsockopt+0xa8/0x220 net/ipv6/ipv6_sockglue.c:1026
 tcp_setsockopt+0x38/0xdb4 net/ipv4/tcp.c:3696
 sock_common_setsockopt+0x1c/0x30 net/core/sock.c:3505
 __sys_setsockopt+0xa0/0x1c0 net/socket.c:2180
 __do_sys_setsockopt net/socket.c:2191 [inline]
 __se_sys_setsockopt net/socket.c:2188 [inline]
 __arm64_sys_setsockopt+0x2c/0x40 net/socket.c:2188
 __invoke_syscall arch/arm64/kernel/syscall.c:38 [inline]
 invoke_syscall+0x48/0x114 arch/arm64/kernel/syscall.c:52
 el0_svc_common.constprop.0+0x44/0xec arch/arm64/kernel/syscall.c:142
 do_el0_svc+0x6c/0x84 arch/arm64/kernel/syscall.c:181
 el0_svc+0x44/0xb0 arch/arm64/kernel/entry-common.c:616
 el0t_64_sync_handler+0x1a4/0x1b0 arch/arm64/kernel/entry-common.c:634
 el0t_64_sync+0x198/0x19c arch/arm64/kernel/entry.S:581
---[ end trace 0000000000000000 ]---


---
This report is generated by a bot. It may contain errors.
See https://goo.gl/tpsmEJ for more information about syzbot.
syzbot engineers can be reached at syzkaller@googlegroups.com.

syzbot will keep track of this issue. See:
https://goo.gl/tpsmEJ#status for how to communicate with syzbot.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000f46c6305dd264f30%40google.com.
