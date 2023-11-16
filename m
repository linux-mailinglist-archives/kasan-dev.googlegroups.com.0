Return-Path: <kasan-dev+bncBCQPF57GUQHBBX5522VAMGQEYRCRVHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 755FC7EDAF6
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 05:47:28 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-421a7c49567sf104771cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Nov 2023 20:47:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700110047; cv=pass;
        d=google.com; s=arc-20160816;
        b=TGVzIHkWpHtaqYNQ0guA+DQQkQSf8/gXe87vC/uwBjfCidrR1PpikUQh2WxxKRmhAb
         eheuXNCOFMumyd0Y7gQmkVY21EkK2JJ22cZeBdG7LrCBwkRyXto9IO/SOagNClK+/QS9
         4idvNwQRM/Y0RX3v+m4xCv4lQ4YsuOM65IFVKINvwaWnbDI/cP9E14PvGfR7xfpOe4zT
         bcDI/5QyIyay8yWcb7nrycD2i7TnWuOwKSFj6xdw94bmO/nUrTJy65CRYBRg2G/RiidC
         2drM8bGcgQtmvPQsFrdlbgQHSCJ9h7bQtom6roeTTPert2uWTO8FNOuYsGbRa39rPjWS
         9XfA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=DH3We/cQL8FRXBFkq2Vahc4SCkGLApQUFXsR31dtK38=;
        fh=EGwHunK6aSP+kOzephDMn/0uSw5iUpdck6JnjMy+0Gk=;
        b=TpLXH1PobsF26X71gwqiDyG2pScq60rAGR1pvfctHOucqCLc1tpTK0Fym7sW440+vn
         uMNn3lOOpThkeMxL5OBNWCAf+yzkJ18ZEfxzvVTjmJHDoHKHfnyOwVxP2cZel8IsAWIs
         0mbL4BtfYzuWnlLVpUTvXyPrf1+vMeVtFk6fW5zc8bpqBVorM5H1RTFHXHClcbE1QgjC
         KSADW1zjVmHkvhn/8RZWQTlG4GHPte+S9Akw57cJdqw0Iib7PpzshQ71ye6Qjd+0cea8
         KLklQ0k2KYVQyg4Zo0LpmSPATrVEod9/24fAiYZ7CE1dXIG+aRMnXVTbUdrjhq6vqAB9
         O5Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 33z5vzqkbakiuabmcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.215.208 as permitted sender) smtp.mailfrom=33Z5VZQkbAKIUabMCNNGTCRRKF.IQQINGWUGTEQPVGPV.EQO@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700110047; x=1700714847; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:from:subject:message-id:in-reply-to:date
         :mime-version:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=DH3We/cQL8FRXBFkq2Vahc4SCkGLApQUFXsR31dtK38=;
        b=KHdq1OuYLGzSBth9PaJ9tgAMGETqxiMqEFR0pg4IDUkBhXUery24v24zzjYBSYGR4S
         ZI2j76qv8h4Xe7LcK1B/SjVDhosycei05usPYNaboT/ZTfsp71vO3JAf2Upg+uW3VFpt
         dOfFPlZzlW6lNORGeyY1PZfpfSfstpGoacCAjYaZgCgaeu6Yp/X3IEMM0eZCd7FCgi//
         /tiUwCIdv/cHOIj13f3IRUyPo4GoQHJC5azcl8/RNHRPqaKKMoSQKH7xEMhX4KpmAMgZ
         Pa2mHKISXC4gqrrkKUAv66F6HoPOed8zpApzrbcNmvMbRYFmq+RZLJLvgFniZgYLxLxm
         qkdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700110047; x=1700714847;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:from:subject
         :message-id:in-reply-to:date:mime-version:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DH3We/cQL8FRXBFkq2Vahc4SCkGLApQUFXsR31dtK38=;
        b=DT68H8etCsCzCI3F/69axsfdpxumyVNdfIuhH7Ez6lk6ghEK0RwAX9Qj0UW82i+ooL
         j79t3dIgukPuEMv8EOblRfn9Gj6oOC2GaH7zaIhHL/7CIzDWjSU1dPap8C4VHU1X7Bl5
         wsQI5UUqNKHqjjepmpclOYMhLZGNyas9sX2vDUsk3e60leWa/NYJIoKYMorFYHpn07A/
         fh99CrJOhGkANRfEKLu3hGNAQbsqHMXhA9sUJh7OTfQvxnl94K6TlYx6UiX58KL9a6uy
         3HyB26qcX78k5fwg2B9A4l+advc7315Q5XjBCaD04BeV3peyhAq0BPN+Moker57oH7Gm
         AR1g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxQKBs6DxhodYHFgapstEdrkxY8hXBlL4LOl7atyTAwKWP6e9jM
	spcUcNX56dfLDs8kZSWknes=
X-Google-Smtp-Source: AGHT+IG2XG75gwAgbbdu+n0/UkkEp/8a2EnzRR96/E2Eqp+645Qn/9MFw+6+/+UMvPDeG7rMO9pyuw==
X-Received: by 2002:a05:622a:1c14:b0:420:d718:5016 with SMTP id bq20-20020a05622a1c1400b00420d7185016mr136092qtb.26.1700110047294;
        Wed, 15 Nov 2023 20:47:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d12:0:b0:421:c71a:9295 with SMTP id f18-20020ac85d12000000b00421c71a9295ls557031qtx.0.-pod-prod-01-us;
 Wed, 15 Nov 2023 20:47:26 -0800 (PST)
X-Received: by 2002:a05:6122:220e:b0:4ab:f1f8:3171 with SMTP id bb14-20020a056122220e00b004abf1f83171mr14865268vkb.6.1700110046479;
        Wed, 15 Nov 2023 20:47:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700110046; cv=none;
        d=google.com; s=arc-20160816;
        b=t6QnlaAY09cWj6H/BqGKNQe+eDaMEC+ZyI6tQtLONdPvU+zGWr1F1uEUDxRt32CcFX
         jAyU7Ym9Njp37fpAFtAHDNnBjKf2NON2Vk40nnBN18/XtFOoWH6K+OpTQG+Rw4sFdSVx
         m9QCB5PRwyxfm2hnleCxMzbcTFoOpacWB6A9AWfyYolggPfpE2h2u1lNEEtaRu+7V6fJ
         5I2m7vRd5VXizkUKddkkf1Bu3cf2eW8SckqSokC8pTrSTq/wIJgCYlN0NoR6PsiHw0aF
         gND0pw07mWd8RBurpU5kFnJGllxZvsrNQhjxdh6kGIgUou1zhVzEfgfk8Y6ICjWXpPOX
         yR/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=B60E/VSdBhhfKFYxTN6YDvuRBN0E3qm6OgTMvsAq+pU=;
        fh=EGwHunK6aSP+kOzephDMn/0uSw5iUpdck6JnjMy+0Gk=;
        b=tmflCjei0Wfx7CdZ2KOya0GNbDdFe5BZM5UNGMthklDr3pPB1tHvxdL+GxZP6HCPXA
         bZf+NWCHCNX71jhCCflTuhuzGIGXBiPS1AEwsKoL0ZPq7DrKIhKZycLnU4cbOcLHOuT3
         9twAVS0tSD5Kqea/GfTJPsQ+WQpc5lyQDpvqlD6Rce8o56AFdW8RLiqtN1ZBUMNro5tq
         UTkoyNqbSgzKbMvZ6d6pavsSX0RArDNVUK3AsCpuhHvGRTXK3cBnr2edxn5/TsURftkB
         WLrS9ep80tjJDP0Hnc+jcHD9cboXPMQ+qk6+eHgZIisiJZIi2E2UDGQTjflNOuthm+r2
         vPag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 33z5vzqkbakiuabmcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.215.208 as permitted sender) smtp.mailfrom=33Z5VZQkbAKIUabMCNNGTCRRKF.IQQINGWUGTEQPVGPV.EQO@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-pg1-f208.google.com (mail-pg1-f208.google.com. [209.85.215.208])
        by gmr-mx.google.com with ESMTPS id cd12-20020a056130108c00b007b5fcda34aesi1543585uab.0.2023.11.15.20.47.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 15 Nov 2023 20:47:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 33z5vzqkbakiuabmcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.215.208 as permitted sender) client-ip=209.85.215.208;
Received: by mail-pg1-f208.google.com with SMTP id 41be03b00d2f7-5c1bfc5066aso478058a12.2
        for <kasan-dev@googlegroups.com>; Wed, 15 Nov 2023 20:47:26 -0800 (PST)
MIME-Version: 1.0
X-Received: by 2002:a63:2603:0:b0:5bd:29ba:452a with SMTP id
 m3-20020a632603000000b005bd29ba452amr143632pgm.6.1700110045561; Wed, 15 Nov
 2023 20:47:25 -0800 (PST)
Date: Wed, 15 Nov 2023 20:47:25 -0800
In-Reply-To: <000000000000bc90a60607f41fc3@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <000000000000584a26060a3db788@google.com>
Subject: Re: [syzbot] [kasan?] [mm?] WARNING in __kfence_free (3)
From: syzbot <syzbot+59f37b0ab4c558a5357c@syzkaller.appspotmail.com>
To: akpm@linux-foundation.org, andreyknvl@gmail.com, dvyukov@google.com, 
	elver@google.com, glider@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, muchun.song@linux.dev, 
	syzkaller-bugs@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 33z5vzqkbakiuabmcnngtcrrkf.iqqingwugteqpvgpv.eqo@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.215.208 as permitted sender) smtp.mailfrom=33Z5VZQkbAKIUabMCNNGTCRRKF.IQQINGWUGTEQPVGPV.EQO@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
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

HEAD commit:    c42d9eeef8e5 Merge tag 'hardening-v6.7-rc2' of git://git.k..
git tree:       upstream
console output: https://syzkaller.appspot.com/x/log.txt?x=13de8198e80000
kernel config:  https://syzkaller.appspot.com/x/.config?x=65a222833c8bc575
dashboard link: https://syzkaller.appspot.com/bug?extid=59f37b0ab4c558a5357c
compiler:       aarch64-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40
userspace arch: arm64
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=15bd8f98e80000

Downloadable assets:
disk image (non-bootable): https://storage.googleapis.com/syzbot-assets/384ffdcca292/non_bootable_disk-c42d9eee.raw.xz
vmlinux: https://storage.googleapis.com/syzbot-assets/e62e8cdf4401/vmlinux-c42d9eee.xz
kernel image: https://storage.googleapis.com/syzbot-assets/d4650ef9b454/Image-c42d9eee.gz.xz

IMPORTANT: if you fix the issue, please add the following tag to the commit:
Reported-by: syzbot+59f37b0ab4c558a5357c@syzkaller.appspotmail.com

------------[ cut here ]------------
WARNING: CPU: 0 PID: 138 at mm/kfence/core.c:1147 __kfence_free+0x7c/0xb4 mm/kfence/core.c:1147
Modules linked in:
CPU: 0 PID: 138 Comm: kworker/u4:6 Not tainted 6.7.0-rc1-syzkaller-00019-gc42d9eeef8e5 #0
Hardware name: linux,dummy-virt (DT)
Workqueue: events_unbound bpf_map_free_deferred
pstate: 81400009 (Nzcv daif +PAN -UAO -TCO +DIT -SSBS BTYPE=--)
pc : __kfence_free+0x7c/0xb4 mm/kfence/core.c:1147
lr : kfence_free include/linux/kfence.h:187 [inline]
lr : __slab_free+0x48c/0x508 mm/slub.c:3614
sp : ffff800082c3bbb0
x29: ffff800082c3bbb0 x28: faff000002c03e00 x27: 0000000000000000
x26: f4ff000002c18028 x25: ffff00007ff8f138 x24: ffff00007ff8f000
x23: 0000000000000001 x22: ffff00007ff8f000 x21: ffff00007ff8f000
x20: ffff80008024297c x19: fffffc0001ffe3c0 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 00000000200122aa
x14: 0000000000000273 x13: 0000000000000000 x12: 0000000000000001
x11: 0000000000000001 x10: 40fbfcfeb3055ba3 x9 : 0000000000000000
x8 : ffff800082c3bc90 x7 : 0000000000000000 x6 : 0000000000000000
x5 : ffff80008024297c x4 : ffff00007f868000 x3 : ffff8000824a02b8
x2 : f0ff000008cd7140 x1 : ffff00007f8a1350 x0 : ffff00007ff8f000
Call trace:
 __kfence_free+0x7c/0xb4 mm/kfence/core.c:1147
 kfence_free include/linux/kfence.h:187 [inline]
 __slab_free+0x48c/0x508 mm/slub.c:3614
 do_slab_free mm/slub.c:3757 [inline]
 slab_free mm/slub.c:3810 [inline]
 __kmem_cache_free+0x220/0x230 mm/slub.c:3822
 kfree+0x5c/0x74 mm/slab_common.c:1056
 kvfree+0x3c/0x4c mm/util.c:653
 bpf_map_area_free+0x10/0x1c kernel/bpf/syscall.c:325
 htab_map_free+0x134/0x298 kernel/bpf/hashtab.c:1556
 bpf_map_free_deferred+0x44/0x60 kernel/bpf/syscall.c:701
 process_one_work+0x148/0x258 kernel/workqueue.c:2630
 process_scheduled_works kernel/workqueue.c:2703 [inline]
 worker_thread+0x2b4/0x3cc kernel/workqueue.c:2784
 kthread+0x114/0x118 kernel/kthread.c:388
 ret_from_fork+0x10/0x20 arch/arm64/kernel/entry.S:857
---[ end trace 0000000000000000 ]---


---
If you want syzbot to run the reproducer, reply with:
#syz test: git://repo/address.git branch-or-commit-hash
If you attach or paste a git patch, syzbot will apply it before testing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/000000000000584a26060a3db788%40google.com.
