Return-Path: <kasan-dev+bncBDKMZTOATIBRB367WW7QMGQEIKILB6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id CCFD9A793A6
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Apr 2025 19:12:17 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-39123912ff0sf17797f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Apr 2025 10:12:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743613937; cv=pass;
        d=google.com; s=arc-20240605;
        b=fqRn5i9E2lB2S4R063U6KwxqjIx/RfiuMZlaz81slohzsHn30LEbMY5YJoxjwnOAvc
         sV4BQMO3/WMNlyihleaRjBwH8XsFjjrYfhA7xYsXPbKA2XiGGR7cOK4Dcfou/f91woYW
         tJg472pmwczgfbXQp20jbCYVeZCYJebN1kYqcTxc5YEaWKzdQHCP8S9a0Gjbt5/Jyynw
         jVr+OmDwpPZw3XR/bg4ObS5qMW0+ztH4Sxllo/gw8atN9pY6whI6wRbhICCk94e4IXpC
         nCUADp+gBMqO2do11Z6C4hQKvHe3tNqh+4461b0KYeOYvtTfgEzQAHnRmucg6AaQOK63
         NfDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=+h0lLjxmmW/lrnt9xcheRcJQeH7uzNIJtzqiypqU5Z0=;
        fh=XMKD/QmB2MtXeH1VKU/WviwIdE6xBqiDASCFsmSnHQo=;
        b=TyEqwBOC53XEY8mbPS3nUPO38weZxjeeoDo4ujel2uLTvp+iVjEupSPcOxFwe+V/g6
         kmQ6SyqBpkTc51pTW6QvJxob+TGgNz47wcrThU64W/H/qejUgn1J2MsoU57oXGkN4iVW
         h0TnRf1+muLzcz2C+uRm+SwDWf7CnLxRTzaP5m9rL6cFfSjIuDe1FDS5sPwMD9YHu3h2
         HDtdl2is1hMOH6PE7ZWZRUpY3oZ6ejfRE2zlFCAub/JmzlQ8rYWS8K8CS8lymRmjaX3m
         GzuQm3wix5zW4U0YUm5Zcna0BbPxLK2W10lTjwgvB/jh1U8JbdYvxtajHBrR48VgMhzu
         njhw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rkmT8BDu;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743613937; x=1744218737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+h0lLjxmmW/lrnt9xcheRcJQeH7uzNIJtzqiypqU5Z0=;
        b=FJwXrLIpV5w/Vr749z7u2vGZCGBbBHWNSvA1lNUkMBd+U8kzJJfnbdiaYCDtxd4V9o
         QR+pTtTNcYcaltWwQo5/IzMk9C0Orc57jtYyyS35oocE4qiKWPZmB2CJCQwDk5VOVhuJ
         uDsbyXI7x/3f2ZrW/dGCnSr+3UVMuvbBghMak2/aokrdXQfwVkeVCxOoxJWoym9PAxpt
         9Cp4kXfquHLAb+VhaAYvQQza9DGgthTHwfcNv++JOzWcwcRh6piLT1ghiKywlWXsr7Pd
         trfNlvGoc0+Hq8kCdICwlKMKRdR+DJdTqshcc9nzS45TKYpGJbjYkoxTPDTKPP/KEt+3
         WXag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743613937; x=1744218737;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+h0lLjxmmW/lrnt9xcheRcJQeH7uzNIJtzqiypqU5Z0=;
        b=LaXguw8YBZ8G85P3M1IJd87gJhHG9uUsVmrYmUuyxfgPNELx4T7Wx4i3hIYU/djHaa
         C54HsKmSGi2ZexjkyoyPPB2qNjb3nYiKDUfMNZvb/UvcB3A4sUwcbvijZBgbZdMEfso5
         i+LSp97A/kKNu3Fx+2xwGOtvmROkpdgS+HW7Jxzned08xpcfd/OekQOyhHSrTf+LDarL
         SWoX9cEfc75+67n+cJX4zGo4MmQ2E2lbBHX/o4pbeFBulAzldYxfxkn4ldn7UsluQEMy
         dWE8Pn/Chc6L8BsiG7YFCAGIOMT488n5TvZkGKx/UtI0EKTLsTdO98hcDXtFgqoT9B5O
         UOrg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXJOVFBEDBKdnrKtdWIdRMrSTvVPtrxh3ittSSqOv2bLm42j6i34uDocveTY5o8kTXLSsyIOw==@lfdr.de
X-Gm-Message-State: AOJu0Yxa2dl9/gJJ93+jyKMqAFBwW/htjvgFLy3XxyGL1H0NWvUnJRAs
	C5Bwakz5griWJlqpipKkmUxMWLAPp71Gxh2arARTrrfP1C9O9Q7c
X-Google-Smtp-Source: AGHT+IHyCFOD1amth2+vTIOsMJ6cGHPMXWdT1i+lnUjXhfaQVG9Eu4JUa0kwSj0DNcrPTCMyy3ncPg==
X-Received: by 2002:a05:6000:2408:b0:39c:1404:42df with SMTP id ffacd0b85a97d-39c14044386mr14045308f8f.30.1743613936329;
        Wed, 02 Apr 2025 10:12:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIl3UBFa+95DD/I8aa/k1qjjPP5jqdjI0pJHC9qfyIbqg==
Received: by 2002:a5d:5f43:0:b0:38f:2204:701a with SMTP id ffacd0b85a97d-39c2e23e00els64348f8f.2.-pod-prod-08-eu;
 Wed, 02 Apr 2025 10:12:13 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVNOxdczNAud3RLYQu/b0KEBQAxFEUlG8ZzXiTLxJ0/TtMKBZbEqmZEcwEbT2cgjmVJBrMSi/wIN3U=@googlegroups.com
X-Received: by 2002:adf:9d83:0:b0:391:39bd:a361 with SMTP id ffacd0b85a97d-39c120dd6edmr11639420f8f.18.1743613933398;
        Wed, 02 Apr 2025 10:12:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743613933; cv=none;
        d=google.com; s=arc-20240605;
        b=i1JgOVoPsFrNstF8qjllqKY3688e0SsZ8BHvVhmgOwLRLtrODKdaciAzok6wZuuJ9x
         2uByPbLc4zbzkmJTin3xcFZRq03Bx99wFy2Vkrz8Im/3OkXIo7Krx8bBi1mowhkcFzC1
         7o2j2NBhBbNJnMHyeOKlW1LgZwuwqK6913DxvTRP1vtfqL7jAlzpgQOOaPz9wyB4uCYL
         FBaEG+oPiIhiGzKIq4bRvWpxi514OJGyNRaYubiR4d0z04k6VhCkhxdwkd3gyw4r2Dtm
         JlQucdBGMid6JqR9EPRkvaWhZPSHcbbVSHC61BjNmVwVBrlSjSAy2/OH2c01asgauDI2
         fnug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from
         :dkim-signature:date;
        bh=IjttORXuJuOhbug6A1JnjM3d6RTs252U2IBKWjaHPWs=;
        fh=KkfmahYuUfDzssE6vqJO7GOX7cNAd3pi2ivkNfvBrDs=;
        b=Z1R3fUX34lWlrsUh+ODHncMLDJDxNKP5wvT4DrVJrXmKPsgHHT02uRtgPJ71GpLbjr
         +sRRUDkRRui2XxcW7jjBzZY3/ShBsebDkKMCDw8RzY7CvylVSG/boe4DyTUrgR/2jGUP
         EdnHNOZICuTgBkvn9lJOOifcEDXhjN64+rAvIDJiTSBOnMSRehHCMx7UyAGaHC0oxFWh
         WQP4oAU8/Gq6wmMrN78A0ntzc33YT+ZcwoldEzfqYFnXhHsSqxbhRXaPAAZ5ZDrbqpfH
         2H9SYpaWgdSQk3zYjA+iIjBtHsfE/COnhKEiU6VdyZoF50ZPZJPm3L+hxoW0mlnjMPqM
         jNwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=rkmT8BDu;
       spf=pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-189.mta1.migadu.com (out-189.mta1.migadu.com. [2001:41d0:203:375::bd])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-39c0b799a6asi192086f8f.4.2025.04.02.10.12.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 02 Apr 2025 10:12:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of kent.overstreet@linux.dev designates 2001:41d0:203:375::bd as permitted sender) client-ip=2001:41d0:203:375::bd;
Date: Wed, 2 Apr 2025 13:12:07 -0400
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Kent Overstreet <kent.overstreet@linux.dev>
To: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com
Subject: Re: [PATCH] kmsan: disable recursion in kmsan_handle_dma()
Message-ID: <vd736huqp7kfy3gbzeowm2kzk72nst2s37knhuwlqvncwpsl22@oxilwothvgta>
References: <20250321145332.3481843-1-kent.overstreet@linux.dev>
 <CAG_fn=WmyMug7mkD57OubPz31mH_W7C1u-VStCQ7UeYh_CCtPg@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=WmyMug7mkD57OubPz31mH_W7C1u-VStCQ7UeYh_CCtPg@mail.gmail.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: kent.overstreet@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=rkmT8BDu;       spf=pass
 (google.com: domain of kent.overstreet@linux.dev designates
 2001:41d0:203:375::bd as permitted sender) smtp.mailfrom=kent.overstreet@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

On Wed, Apr 02, 2025 at 05:00:54PM +0200, Alexander Potapenko wrote:
> On Fri, Mar 21, 2025 at 3:53=E2=80=AFPM Kent Overstreet
> <kent.overstreet@linux.dev> wrote:
> >
> > I'm not sure if this check was left out for some reason, maybe have a
> > look? But it does fix kmsan when run from ktest:
> >
> > https://evilpiepirate.org/git/ktest.git/
>=20
> Kent, do you happen to have a recursion stack trace for this problem?
> Or maybe you can share the repro steps?

If you want to reproduce it, use ktest:
https://evilpiepirate.org/git/ktest.git/

btk run -IP ~/ktest/tests/fs/bcachefs/kmsan-single-device.ktest crc32c

(or any kmsan test)

And you'll have to create a kmsan error since I just fixed them - in the
example below I deleted the #if defined(KMSAN) checks in util.h.

The thing that's required is virtio-console, since that uses DMA unlike
a normal (emulated or no) serial console.

> I started looking, and in general I don't like how inconsistently
> kmsan_in_runtime() is checked in hooks.c
> I am currently trying to apply Marco's capability analysis
> (https://web.git.kernel.org/pub/scm/linux/kernel/git/melver/linux.git/log=
/?h=3Dcap-analysis/dev)
> to validate these checks.

Yeah, I was noticing that.

Would lockdep or sparse checks be useful here? You could model this as a
lock you want held or not held, no?

Here's a log of the previous run. We just loop infinitely on those
warnings, the actual log was 6MB for a ~10 second run.

Running test kmsan-single_device.ktest on moria at /home/kent/linux
building kernel... done
 [!p ]104  [?7hKernel version: 6.14.0-rc6-ktest-00264-g78d9afd5262f-dirty

hook init_build_bcachefs_tools

install -m0755 -D fsck/bcachefsck_fail fsck/bcachefsck_all -t /usr/libexec

install -m0644 -D fsck/bcachefsck_fail@.service fsck/bcachefsck@.service fs=
ck/system-bcachefsck.slice fsck/bcachefsck_all_fail.service fsck/bcachefsck=
_all.service fsck/bcachefsck_all.timer -t /usr/lib/systemd/system

install -m0755 -D target/release/bcachefs  -t /sbin

install -m0644 -D bcachefs.8    -t /usr/share/man/man8/

install -m0755 -D initramfs/script /usr/share/initramfs-tools/scripts/local=
-premount/bcachefs

install -m0755 -D initramfs/hook   /usr/share/initramfs-tools/hooks/bcachef=
s

install -m0644 -D udev/64-bcachefs.rules -t /usr/lib/udev/rules.d/

ln -sfr /sbin/bcachefs /sbin/mkfs.bcachefs

ln -sfr /sbin/bcachefs /sbin/fsck.bcachefs

ln -sfr /sbin/bcachefs /sbin/mount.bcachefs

ln -sfr /sbin/bcachefs /sbin/mkfs.fuse.bcachefs

ln -sfr /sbin/bcachefs /sbin/fsck.fuse.bcachefs

ln -sfr /sbin/bcachefs /sbin/mount.fuse.bcachefs

sed -i '/^# Note: make install replaces/,$d' /usr/share/initramfs-tools/hoo=
ks/bcachefs

echo "copy_exec /sbin/bcachefs /sbin/bcachefs" >> /usr/share/initramfs-tool=
s/hooks/bcachefs

echo "copy_exec /sbin/mount.bcachefs /sbin/mount.bcachefs" >> /usr/share/in=
itramfs-tools/hooks/bcachefs

hook init_noop



Running tests crc32c



=3D=3D=3D=3D=3D=3D=3D=3D=3D TEST   crc32c



WATCHDOG 6000

bcachefs (vdb): starting version 1.25: extent_flags opts=3Derrors=3Dro,fsck

bcachefs (vdb): initializing new filesystem

bcachefs (vdb): going read-write

bcachefs (vdb): marking superblocks

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D

------------[ cut here ]------------

WARNING: CPU: 1 PID: 451 at mm/kmsan/kmsan.h:114 kmsan_internal_check_memor=
y+0x317/0x550

Modules linked in:

CPU: 1 UID: 0 PID: 451 Comm: kworker/u64:5 Not tainted 6.14.0-rc6-ktest-002=
64-g78d9afd5262f-dirty #158

Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16=
.3-2 04/01/2014

Workqueue: btree_update btree_interior_update_work

RIP: 0010:kmsan_internal_check_memory+0x317/0x550

Code: a2 1c 59 03 00 45 89 ef 74 ca e9 44 02 00 00 0f 0b c6 05 8c 1c 59 03 =
00 83 3d 88 1c 59 03 00 0f 84 26 fe ff ff e9 2b 02 00 00 <0f> 0b c6 05 71 1=
c 59 03 00 83 3d 6d 1c 59 03 00 0f 84 93 fe ff ff

RSP: 0018:ffff8881ee4727d0 EFLAGS: 00010002

RAX: ffff8881d41365b8 RBX: 0000000000000000 RCX: 0000000000000001

RDX: 0000000000000002 RSI: ffff88827dbf5400 RDI: ffff888105337a04

RBP: 0000000000000000 R08: ffff88827dbf6000 R09: ffff888105337a00

R10: 0000000000000000 R11: ffffffffffffffff R12: ffff888104b37a00

R13: 0000000000000008 R14: 000000000d8c007c R15: 00000000ffffffff

FS:  0000000000000000(0000) GS:ffff88827cb00000(0000) knlGS:000000000000000=
0

CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033

CR2: 0000561140a700d0 CR3: 000000020b88b000 CR4: 0000000000750eb0

PKRU: 55555554

Call Trace:

 <TASK>

 ? show_trace_log_lvl+0x2af/0x470

 ? kmsan_handle_dma+0x99/0xb0

 ? __warn+0x24c/0x5b0

 ? kmsan_internal_check_memory+0x317/0x550

 ? report_bug+0x5e6/0x8f0

 ? kmsan_internal_check_memory+0x317/0x550

 ? handle_bug+0x63/0x90

 ? exc_invalid_op+0x1a/0x50

 ? asm_exc_invalid_op+0x1a/0x20

 ? kmsan_internal_check_memory+0x317/0x550

 kmsan_handle_dma+0x99/0xb0

 virtqueue_add+0x36c8/0x5cf0

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? kmsan_get_metadata+0x100/0x150

 virtqueue_add_outbuf+0x93/0xc0

 put_chars+0x37e/0x890

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? get_chars+0x270/0x270

 hvc_console_print+0x28e/0x7d0

 ? kmsan_internal_set_shadow_origin+0x71/0xf0

 ? kmsan_get_metadata+0x100/0x150

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? hvc_remove+0x1e0/0x1e0

 console_flush_all+0x762/0xfe0

 console_unlock+0x104/0x560

 vprintk_emit+0x6f0/0x970

 _printk+0x18e/0x1d0

 ? _raw_spin_unlock_irqrestore+0x1f/0x40

 kmsan_report+0x90/0x2a0

 ? kmsan_internal_chain_origin+0xb6/0xd0

 ? bch2_btree_insert_key_leaf+0x231/0xda0

 ? kmsan_internal_chain_origin+0x5d/0xd0

 ? kmsan_internal_memmove_metadata+0x173/0x220

 ? rw_aux_tree_set+0x2f2/0x420

 ? bch2_bset_fix_lookup_table+0xa81/0xd20

 ? bch2_bset_insert+0xb6f/0x1540

 ? bch2_btree_bset_insert_key+0x991/0x23e0

 ? bch2_btree_insert_key_leaf+0x231/0xda0

 ? __bch2_trans_commit+0xa05e/0xb430

 ? btree_interior_update_work+0x191c/0x4000

 ? process_scheduled_works+0x88b/0x1730

 ? worker_thread+0xd2c/0x1200

 ? kthread+0x9c7/0xc80

 ? ret_from_fork+0x56/0x70

 ? ret_from_fork_asm+0x11/0x20

 ? kmsan_get_metadata+0x100/0x150

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? kmsan_get_metadata+0x100/0x150

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? bch2_bset_insert+0x14a1/0x1540

 ? filter_irq_stacks+0x47/0x180

 ? kmsan_get_metadata+0x100/0x150

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? __bkey_unpack_pos+0x5ac/0x780

 ? kmsan_get_metadata+0x100/0x150

 __msan_warning+0x8c/0x110

 bch2_bset_verify_rw_aux_tree+0x8b3/0xa00

 bch2_bset_fix_lookup_table+0xa8c/0xd20

 bch2_bset_insert+0xb6f/0x1540

 ? bch2_btree_node_iter_bset_pos+0x130/0x280

 bch2_btree_bset_insert_key+0x991/0x23e0

 ? kmsan_get_metadata+0x100/0x150

 bch2_btree_insert_key_leaf+0x231/0xda0

 __bch2_trans_commit+0xa05e/0xb430

 ? btree_interior_update_work+0x191c/0x4000

 btree_interior_update_work+0x191c/0x4000

 ? bch2_fs_btree_interior_update_init_early+0x1c0/0x1c0

 process_scheduled_works+0x88b/0x1730

 worker_thread+0xd2c/0x1200

 ? kmsan_get_metadata+0x100/0x150

 kthread+0x9c7/0xc80

 ? schedule_tail+0x125/0x1b0

 ? pr_cont_work+0xb70/0xb70

 ? kthread_unuse_mm+0x140/0x140

 ret_from_fork+0x56/0x70

 ? kthread_unuse_mm+0x140/0x140

 ret_from_fork_asm+0x11/0x20

 </TASK>

---[ end trace 0000000000000000 ]---

------------[ cut here ]------------

WARNING: CPU: 1 PID: 451 at mm/kmsan/kmsan.h:121 kmsan_internal_check_memor=
y+0x22f/0x550

Modules linked in:

CPU: 1 UID: 0 PID: 451 Comm: kworker/u64:5 Tainted: G        W          6.1=
4.0-rc6-ktest-00264-g78d9afd5262f-dirty #158

Tainted: [W]=3DWARN

Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16=
.3-2 04/01/2014

Workqueue: btree_update btree_interior_update_work

RIP: 0010:kmsan_internal_check_memory+0x22f/0x550

Code: 00 ff 88 b0 0f 00 00 0f 84 ef fe ff ff eb 1b 65 48 8b 04 25 c0 d0 0a =
00 48 05 78 09 00 00 ff 88 b0 0f 00 00 0f 84 d2 fe ff ff <0f> 0b c6 05 59 1=
d 59 03 00 83 3d 55 1d 59 03 00 0f 84 bc fe ff ff

RSP: 0018:ffff8881ee4727d0 EFLAGS: 00010002

RAX: ffff8881d41365b8 RBX: 0000000000000000 RCX: 0000000000000000

RDX: 0000000000000010 RSI: ffff888105337a00 RDI: 000000000d8c007c

RBP: 0000000000000000 R08: 0000000000000007 R09: 0000000000000000

R10: 0000000000000000 R11: ffffffffffffffff R12: ffff888104b37a00

R13: 0000000000000008 R14: 000000000d8c007c R15: 00000000ffffffff

FS:  0000000000000000(0000) GS:ffff88827cb00000(0000) knlGS:000000000000000=
0

CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033

CR2: 0000561140a700d0 CR3: 000000020b88b000 CR4: 0000000000750eb0

PKRU: 55555554

Call Trace:

 <TASK>

 ? show_trace_log_lvl+0x2af/0x470

 ? kmsan_handle_dma+0x99/0xb0

 ? __warn+0x24c/0x5b0

 ? kmsan_internal_check_memory+0x22f/0x550

 ? report_bug+0x5e6/0x8f0

 ? kmsan_internal_check_memory+0x22f/0x550

 ? handle_bug+0x63/0x90

 ? exc_invalid_op+0x1a/0x50

 ? asm_exc_invalid_op+0x1a/0x20

 ? kmsan_internal_check_memory+0x22f/0x550

 kmsan_handle_dma+0x99/0xb0

 virtqueue_add+0x36c8/0x5cf0

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? kmsan_get_metadata+0x100/0x150

 virtqueue_add_outbuf+0x93/0xc0

 put_chars+0x37e/0x890

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? get_chars+0x270/0x270

 hvc_console_print+0x28e/0x7d0

 ? kmsan_internal_set_shadow_origin+0x71/0xf0

 ? kmsan_get_metadata+0x100/0x150

 ? kmsan_get_shadow_origin_ptr+0x46/0xa0

 ? hvc_remove+0x1e0/0x1e0

 console_flush_all+0x762/0xfe0

 console_unlock+0x104/0x560

 vprintk_emit+0x6f0/0x970

 _printk+0x18e/0x1d0

 ? _raw_spin_unlock_irqrestore+0x1f/0x40

 kmsan_report+0x90/0x2a0

 ? kmsan_internal_chain_origin+0xb6/0xd0

 ? bch2_btree_insert_key_leaf+0x231/0xda0

 ? kmsan_internal_chain_origin+0x5d/0xd0

 ? kmsan_internal_memmove_metadata+0x173/0x220

 ? rw_aux_tree_set+0x2f2/0x420

 ? bch2_bset_fix_lookup_table+0xa81/0xd20

 ? bch2_bset_insert+0xb6f/0x1540

 ? bch2_btree_bset_insert_key+0x991/0x23e0

 ? bch2_btree_insert_key_leaf+0x231/0xda0

 ? __bch2_trans_commit+0xa05e/0xb430

 ? btree_interior_update_work+0x191c/0x4000

 ? process_scheduled_works+0x88b/0x1730

 ? worker_thread+0xd2c/0x1200

 ? kthread+0x9c7/0xc80

 ? ret_from_fork+0x56/0x70

 ? ret_from_fork_asm+0x11/0x20

 ? kmsan_get_metadata+0x100/0x150

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/v=
d736huqp7kfy3gbzeowm2kzk72nst2s37knhuwlqvncwpsl22%40oxilwothvgta.
