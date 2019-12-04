Return-Path: <kasan-dev+bncBCMIZB7QWENRBVVGTXXQKGQE43DASGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id CE2C61122F0
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Dec 2019 07:33:59 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id t33sf4031741ybt.20
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Dec 2019 22:33:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575441238; cv=pass;
        d=google.com; s=arc-20160816;
        b=dWJiDDW5vHiTghnFBLwcuaUNmo8tZEO8GMgcj8vL5zv+/dxXqFwf7kgPfHynoIq0M/
         Mdp5+80knhZbd6lCIzllMIzdH5WIOyv18xMhGM7RkozGZoNY5QnHMMwphG9KanX0CxiO
         X18V/pXXEqX864MFm7qFbCvIUKPvnhA40L02oTc5q4NFSYcR8flL43BCuFptjPYQG12X
         MZUf58tMdBLe7TQCcnvLCFzPD1AIBNefmvLZUcnZllc/Ea8QNd1rrITD8wqWa9drUo+p
         aDXXqKRwNk/hsC7Nu/XfglhRJEUPj34M9PV93GsZBOQtkB7SHmNN75aIp4Temp7FKLQ5
         GRZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=q4LvH1iKtP3qd/fmGNN7tdSqBMypyUEDf1ei2yaX1Z4=;
        b=C1MSHiTBF4xook6mcK2LQhH0W1xaFhINvM9e5XOjZlES4DjEBS5w6UZpcoemaJe7MW
         yvLdVslmQKVsDIFFbh7xmud0Q5DJLRkWF/iJaqYXCr3KcQUSOFF8MShwRGw0kYp7DF+I
         iyzBesmsxKsRe5FvdlhT+Lf1RFI2jxFpXWPWZcT3F6GQqtB9M8O94whXqEZbW0OD4GMj
         PTZS4w4k63ge7+MnPBh1oaSnLqc3LiB6N61ENxHAtHC7P7bOlOEyZLiwf6euho3M78l2
         tEE3kQaudcXp1UBNMEOIvMgqN12+VKaATmRWNW2CA3rSdTL2cuPv+ndOukOLSaSEqzIB
         pQOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dHJn7DD/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q4LvH1iKtP3qd/fmGNN7tdSqBMypyUEDf1ei2yaX1Z4=;
        b=emT8k0wI5S+3KRkxPqzKTQw7IewO3sfoRail6QBZPFA6z8MFYBFxaQBCDmcLm+0+hM
         ZgCCyi96bN1d3rg3ZV03f92fiD6tPa/zmtxVoLw8CqOsnYCS9bJtr5GJblAuwLpZaVgF
         NJsGOlG5ICE+A8YQz4KGH7n713D4QZLbLpOPllcfV6qxCIFq2vzT7clU7zPgwEksP+ia
         YwCLoX2STkeQBZEXOi/T9rBBKU7fIEHnGs+Oc7ZQRRq8JKgfWFOoH9WtBLSIWRWy/eeP
         XWMxqhnd5yh31KzIa9tkKStd4UaCyHnbO3as1f4xc09tE14sTHbHQS0FFd59iMg++MeL
         qaDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q4LvH1iKtP3qd/fmGNN7tdSqBMypyUEDf1ei2yaX1Z4=;
        b=tkH7OTV4dB7mk7FWlIIGc5MQiS0SOhD4eR/70DWGJrDzufp2RT4H1h4MeXWTcttpzk
         ozb8ZA389rLNa34OMLz1wSIiiSRxdi0AGrsaa7RzDpudZ8uB9Oj17963XUKUKEWZVHJt
         +rCEOAYV92GuayvLX71TlCTPX3+v37S9/j3+rVeTVf0DI+1AVKRzznwEGPs1lNEa0E8e
         M+Txj1mQh5p7AsLbLyKBg9KbOMaNZCSLtHfakKL+6OkREsdB064mqp+t/iezUfDRTHLz
         cE+qm7R8eBb8v8ZoWfeV0JUuqD9R1JwXEFpysZdeczETSXOveHJIwMGq9qQ0+mnZZw4k
         BcGA==
X-Gm-Message-State: APjAAAUlX4mehhEqBlErhA2oU9Ta7LTAvsaRsDFJP0Yxt/MRF+cm48sr
	4GK5QDkctPHCiGD3e0WUyRY=
X-Google-Smtp-Source: APXvYqwCkuESy+SOtCOji/2OtyD9Pv4+E2IrbkAOgm6jfADTBRutZdLqLgTA5r+JRm53uDk/c5AoJw==
X-Received: by 2002:a81:8107:: with SMTP id r7mr978407ywf.398.1575441238560;
        Tue, 03 Dec 2019 22:33:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:c842:: with SMTP id k2ls850038ywl.7.gmail; Tue, 03 Dec
 2019 22:33:58 -0800 (PST)
X-Received: by 2002:a81:79c2:: with SMTP id u185mr1021137ywc.313.1575441238165;
        Tue, 03 Dec 2019 22:33:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575441238; cv=none;
        d=google.com; s=arc-20160816;
        b=YDFXHLq4n9smTCTvKOjfPRdNPvLRx7TtlRJxn6pU3C7h2WpyQ1YLj8aQ3K2OIPJO7d
         +M9WqXMyUfLDajARvG/QwXKOey9452rwmz+LziIJvEHzAHwW6GiN9EzNcpOLMq4CkAk+
         zrQ1b60H86rwm2zxfSsujBYyWFgBNwnOb3/ZDJAMFCJciSNaYwKyYw/BHTnrJ/bCfql4
         QqrZ69kyERUxlvoij44C82fjVEL+TpWT6ysAHPJ+lwRxWJwQNe1Ocml58uqWLwguz6Gs
         jNhZH4KBWSTTRWtkIk15Tpl4rskxtfBZthH7rtf7xFEiJfX+7TTERw74Ns5lmgCmtAp7
         C09A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2cRSRnUjyOWj8W68zyd7mIujpzqYQeBmGrBj93EFUXY=;
        b=eIPxLSXX8JcPfp7l+haVQPAcAJ8T17PjUpElddSFZ4VRpyk9euV6hhs0yGYIim2Kdi
         GEKPZPfnygPTgaiKz78WCD3sGA2n/foCJLd4dcT/GyEfsKcTLIP9hkKJ++Jho8pzWn8G
         LpQfWsiKtCTqr4B6t3kyIJ/WF7tJ6h+sRNwRJPNmfsaLV9M6HVOqmMew1HfyZj0QWwEU
         oY4MLMWHOYfsj19Rz1oB5BOPdfdJhY0Ok24xxPaCGIpuimBw/W/jYnNW5kDNsQzlMW5l
         RZP8tRJM1atPJazU3e4ObNcKvVXA5WsXplRANnC+rIMMRPEprhERgUZ05NW/GaymqlMz
         53Aw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="dHJn7DD/";
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id a7si359366ybo.0.2019.12.03.22.33.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Dec 2019 22:33:58 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id v23so6150266qkg.2
        for <kasan-dev@googlegroups.com>; Tue, 03 Dec 2019 22:33:58 -0800 (PST)
X-Received: by 2002:a37:4782:: with SMTP id u124mr1427511qka.8.1575441237260;
 Tue, 03 Dec 2019 22:33:57 -0800 (PST)
MIME-Version: 1.0
References: <0000000000002cfc3a0598d42b70@google.com> <CAKMK7uFAfw4M6B8WaHx6FBkYDmUBTQ6t3D8RE5BbMt=_5vyp9A@mail.gmail.com>
In-Reply-To: <CAKMK7uFAfw4M6B8WaHx6FBkYDmUBTQ6t3D8RE5BbMt=_5vyp9A@mail.gmail.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Dec 2019 07:33:45 +0100
Message-ID: <CACT4Y+aV9vzJ6gs9r2RAQP+dQ_vkOc5H6hWu-prF1ECruAE_5w@mail.gmail.com>
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Daniel Vetter <daniel.vetter@ffwll.ch>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>, 
	Kentaro Takeda <takedakn@nttdata.co.jp>, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	James Morris <jmorris@namei.org>, "Serge E. Hallyn" <serge@hallyn.com>, 
	linux-security-module <linux-security-module@vger.kernel.org>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Daniel Thompson <daniel.thompson@linaro.org>, 
	dri-devel <dri-devel@lists.freedesktop.org>, ghalat@redhat.com, 
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Sam Ravnborg <sam@ravnborg.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="dHJn7DD/";       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::743
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, Dec 3, 2019 at 11:37 PM Daniel Vetter <daniel.vetter@ffwll.ch> wrote:
>
> On Tue, Dec 3, 2019 at 11:25 PM syzbot
> <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com> wrote:
> >
> > Hello,
> >
> > syzbot found the following crash on:
> >
> > HEAD commit:    76bb8b05 Merge tag 'kbuild-v5.5' of git://git.kernel.org/p..
> > git tree:       upstream
> > console output: https://syzkaller.appspot.com/x/log.txt?x=10bfe282e00000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=dd226651cb0f364b
> > dashboard link: https://syzkaller.appspot.com/bug?extid=4455ca3b3291de891abc
> > compiler:       gcc (GCC) 9.0.0 20181231 (experimental)
> > syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=11181edae00000
> > C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=105cbb7ae00000
> >
> > IMPORTANT: if you fix the bug, please add the following tag to the commit:
> > Reported-by: syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com
> >
> > ==================================================================
> > BUG: KASAN: slab-out-of-bounds in memcpy include/linux/string.h:380 [inline]
> > BUG: KASAN: slab-out-of-bounds in fbcon_get_font+0x2b2/0x5e0
> > drivers/video/fbdev/core/fbcon.c:2465
> > Read of size 16 at addr ffff888094b0aa10 by task syz-executor414/9999
>
> So fbcon allocates some memory, security/tomoyo goes around and frees
> it, fbcon goes boom because the memory is gone. I'm kinda leaning
> towards "not an fbcon bug". Adding relevant security folks and mailing
> lists.
>
> But from a very quick look in tomoyo it loosk more like "machine on
> fire, random corruption all over". No idea what's going on here.

Hi Daniel,

This is an out-of-bounds access, not use-after-free.
I don't know why we print the free stack at all (maybe +Andrey knows),
but that's what KASAN did from day one. I filed
https://bugzilla.kernel.org/show_bug.cgi?id=198425 which I think is a
good idea, I will add your confusion as a data point :)
Re this bug, free stack is irrelevant, I guess it's when the heap
block was freed before it was reallocated by console. So it's plain
out-of-bounds in fbcon_get_font, which looks sane and consistent to me
and reproducible on top.


> > CPU: 0 PID: 9999 Comm: syz-executor414 Not tainted 5.4.0-syzkaller #0
> > Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS
> > Google 01/01/2011
> > Call Trace:
> >   __dump_stack lib/dump_stack.c:77 [inline]
> >   dump_stack+0x197/0x210 lib/dump_stack.c:118
> >   print_address_description.constprop.0.cold+0xd4/0x30b mm/kasan/report.c:374
> >   __kasan_report.cold+0x1b/0x41 mm/kasan/report.c:506
> >   kasan_report+0x12/0x20 mm/kasan/common.c:638
> >   check_memory_region_inline mm/kasan/generic.c:185 [inline]
> >   check_memory_region+0x134/0x1a0 mm/kasan/generic.c:192
> >   memcpy+0x24/0x50 mm/kasan/common.c:124
> >   memcpy include/linux/string.h:380 [inline]
> >   fbcon_get_font+0x2b2/0x5e0 drivers/video/fbdev/core/fbcon.c:2465
> >   con_font_get drivers/tty/vt/vt.c:4446 [inline]
> >   con_font_op+0x20b/0x1250 drivers/tty/vt/vt.c:4605
> >   vt_ioctl+0x181a/0x26d0 drivers/tty/vt/vt_ioctl.c:965
> >   tty_ioctl+0xa37/0x14f0 drivers/tty/tty_io.c:2658
> >   vfs_ioctl fs/ioctl.c:47 [inline]
> >   file_ioctl fs/ioctl.c:545 [inline]
> >   do_vfs_ioctl+0x977/0x14e0 fs/ioctl.c:732
> >   ksys_ioctl+0xab/0xd0 fs/ioctl.c:749
> >   __do_sys_ioctl fs/ioctl.c:756 [inline]
> >   __se_sys_ioctl fs/ioctl.c:754 [inline]
> >   __x64_sys_ioctl+0x73/0xb0 fs/ioctl.c:754
> >   do_syscall_64+0xfa/0x790 arch/x86/entry/common.c:294
> >   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> > RIP: 0033:0x4444d9
> > Code: 18 89 d0 c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 48 89 f8 48 89 f7
> > 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff
> > ff 0f 83 7b d8 fb ff c3 66 2e 0f 1f 84 00 00 00 00
> > RSP: 002b:00007fff6f4393b8 EFLAGS: 00000246 ORIG_RAX: 0000000000000010
> > RAX: ffffffffffffffda RBX: 00007fff6f4393c0 RCX: 00000000004444d9
> > RDX: 0000000020000440 RSI: 0000000000004b72 RDI: 0000000000000005
> > RBP: 0000000000000000 R08: 0000000000000000 R09: 0000000000400da0
> > R10: 00007fff6f438f00 R11: 0000000000000246 R12: 00000000004021e0
> > R13: 0000000000402270 R14: 0000000000000000 R15: 0000000000000000
> >
> > Allocated by task 9999:
> >   save_stack+0x23/0x90 mm/kasan/common.c:71
> >   set_track mm/kasan/common.c:79 [inline]
> >   __kasan_kmalloc mm/kasan/common.c:512 [inline]
> >   __kasan_kmalloc.constprop.0+0xcf/0xe0 mm/kasan/common.c:485
> >   kasan_kmalloc+0x9/0x10 mm/kasan/common.c:526
> >   __do_kmalloc mm/slab.c:3656 [inline]
> >   __kmalloc+0x163/0x770 mm/slab.c:3665
> >   kmalloc include/linux/slab.h:561 [inline]
> >   fbcon_set_font+0x32d/0x860 drivers/video/fbdev/core/fbcon.c:2663
> >   con_font_set drivers/tty/vt/vt.c:4538 [inline]
> >   con_font_op+0xe18/0x1250 drivers/tty/vt/vt.c:4603
> >   vt_ioctl+0xd2e/0x26d0 drivers/tty/vt/vt_ioctl.c:913
> >   tty_ioctl+0xa37/0x14f0 drivers/tty/tty_io.c:2658
> >   vfs_ioctl fs/ioctl.c:47 [inline]
> >   file_ioctl fs/ioctl.c:545 [inline]
> >   do_vfs_ioctl+0x977/0x14e0 fs/ioctl.c:732
> >   ksys_ioctl+0xab/0xd0 fs/ioctl.c:749
> >   __do_sys_ioctl fs/ioctl.c:756 [inline]
> >   __se_sys_ioctl fs/ioctl.c:754 [inline]
> >   __x64_sys_ioctl+0x73/0xb0 fs/ioctl.c:754
> >   do_syscall_64+0xfa/0x790 arch/x86/entry/common.c:294
> >   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> >
> > Freed by task 9771:
> >   save_stack+0x23/0x90 mm/kasan/common.c:71
> >   set_track mm/kasan/common.c:79 [inline]
> >   kasan_set_free_info mm/kasan/common.c:334 [inline]
> >   __kasan_slab_free+0x102/0x150 mm/kasan/common.c:473
> >   kasan_slab_free+0xe/0x10 mm/kasan/common.c:482
> >   __cache_free mm/slab.c:3426 [inline]
> >   kfree+0x10a/0x2c0 mm/slab.c:3757
> >   tomoyo_init_log+0x15c1/0x2070 security/tomoyo/audit.c:294
> >   tomoyo_supervisor+0x33f/0xef0 security/tomoyo/common.c:2095
> >   tomoyo_audit_env_log security/tomoyo/environ.c:36 [inline]
> >   tomoyo_env_perm+0x18e/0x210 security/tomoyo/environ.c:63
> >   tomoyo_environ security/tomoyo/domain.c:670 [inline]
> >   tomoyo_find_next_domain+0x1354/0x1f6c security/tomoyo/domain.c:876
> >   tomoyo_bprm_check_security security/tomoyo/tomoyo.c:107 [inline]
> >   tomoyo_bprm_check_security+0x124/0x1a0 security/tomoyo/tomoyo.c:97
> >   security_bprm_check+0x63/0xb0 security/security.c:784
> >   search_binary_handler+0x71/0x570 fs/exec.c:1645
> >   exec_binprm fs/exec.c:1701 [inline]
> >   __do_execve_file.isra.0+0x1329/0x22b0 fs/exec.c:1821
> >   do_execveat_common fs/exec.c:1867 [inline]
> >   do_execve fs/exec.c:1884 [inline]
> >   __do_sys_execve fs/exec.c:1960 [inline]
> >   __se_sys_execve fs/exec.c:1955 [inline]
> >   __x64_sys_execve+0x8f/0xc0 fs/exec.c:1955
> >   do_syscall_64+0xfa/0x790 arch/x86/entry/common.c:294
> >   entry_SYSCALL_64_after_hwframe+0x49/0xbe
> >
> > The buggy address belongs to the object at ffff888094b0a000
> >   which belongs to the cache kmalloc-4k of size 4096
> > The buggy address is located 2576 bytes inside of
> >   4096-byte region [ffff888094b0a000, ffff888094b0b000)
> > The buggy address belongs to the page:
> > page:ffffea000252c280 refcount:1 mapcount:0 mapping:ffff8880aa402000
> > index:0x0 compound_mapcount: 0
> > raw: 00fffe0000010200 ffffea0002a3ae08 ffffea0002a6aa88 ffff8880aa402000
> > raw: 0000000000000000 ffff888094b0a000 0000000100000001 0000000000000000
> > page dumped because: kasan: bad access detected
> >
> > Memory state around the buggy address:
> >   ffff888094b0a900: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> >   ffff888094b0a980: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
> > > ffff888094b0aa00: 00 00 fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> >                           ^
> >   ffff888094b0aa80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> >   ffff888094b0ab00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> > ==================================================================
> >
> >
> > ---
> > This bug is generated by a bot. It may contain errors.
> > See https://goo.gl/tpsmEJ for more information about syzbot.
> > syzbot engineers can be reached at syzkaller@googlegroups.com.
> >
> > syzbot will keep track of this bug report. See:
> > https://goo.gl/tpsmEJ#status for how to communicate with syzbot.
> > syzbot can test patches for this bug, for details see:
> > https://goo.gl/tpsmEJ#testing-patches

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BaV9vzJ6gs9r2RAQP%2BdQ_vkOc5H6hWu-prF1ECruAE_5w%40mail.gmail.com.
