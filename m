Return-Path: <kasan-dev+bncBDW2JDUY5AORBOHFQS2QMGQEH4I67YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id F2AB493B557
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 18:58:33 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-42668796626sf52211475e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2024 09:58:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1721840313; cv=pass;
        d=google.com; s=arc-20160816;
        b=P0vuGfdAIf54TRscpv4PYS2rAPhG0W9N0m5SINLwAXa6t1PleidvI0dW7ov3NKXUuc
         JW972B7uOZj8WOAadElTC3xuHM/dgIpZgqreyk5rudIGsLaWKPHZyndiUlso9zj42buR
         NAMarkhA7QP1LuZT3UfIZ5g8z5KKLriEMXUbq5Wbf5dK3GytlECMI0G7lYviEZNU/eSk
         zWf38aeo2oHPIhCPMieErp25+/ELRGv7B6gG9cIHg2c4e6iCJOvpuVbA5G+UJPHJqOsQ
         7cdbf86IDdwLMy739NarROfjErfJH/NUcImjyLxo2MB8DtpGq2QJNUusxojlslMGXlsD
         jfDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=BKnGCq+Sq4VCkikUhpmgMWN36IKLSuQ8V5FxWoQiM28=;
        fh=rTGv9H/lIMIfQSZ/NsxX9sBoAiolI7AZ10jWfjvzSqc=;
        b=yrjt/Y6Z5oiigOa8Fb+7TSyP5zon3hjLb2w/eDKulc9Cpo0bfI1d2xUVnfFQ5fUEon
         YZJYGbekBGuO1feqpl1WKwsy1q33Ye6DBPbzVX8mUCiRw0IEQVHP37RxNnQcOOn83iq0
         joxfgOzoEzuV8eb2CxLcXqw4YhymwV8d1mal/zR89angj9Ly5OCurHn+KaTLStEM715O
         Nw0MJpYZLHhJjZYdzYSYLtNFd63vkXlbRYYU69MOhg8vha+oIsjaU8WZfSZqruAzTajc
         zVKWnT5Trow37C/THr5qMsak71Kh7j/HFgZHtGEAw/wzpx1fknTpUnV4NnS09M2Quuwf
         tduQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W8u27l4n;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1721840313; x=1722445113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=BKnGCq+Sq4VCkikUhpmgMWN36IKLSuQ8V5FxWoQiM28=;
        b=I3jX5dT68Gaej3OKvV65jlV5A5kHs8qjLJV34BqOU7eXju/vTYaQWU6avzcLzwWmvr
         AOWgFG1HwWf4mlTngt9MWujpkOL7EdpOYjaj51lr0binHKxoonw9YDNzvyGLivmH8ccK
         pckG+i30jOlzV86fwnSBTVDzpaLOrUCcBIS+zFd0+a8KYHTvNVO/krblBObXvs7IrXvi
         wARirDiyYpNEyln1NklbPIOZIYTL7fuHwuzC7vMSJ7t9OjISUG2IGqziBotVdPVEVo8L
         o8JqqYQTMpipFhUhJwwXG7aPTOcFl5Px/cbcTq1Z4Y/hybwjwsOLLu/vxLcNHXol5Ld9
         fmNA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1721840313; x=1722445113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=BKnGCq+Sq4VCkikUhpmgMWN36IKLSuQ8V5FxWoQiM28=;
        b=mwZFdK82TMaTlhoVQk9q6Tdof3Y9XdscfCFc/KspDpgK9ishMkIKVyCPgAyoegYE1r
         4BfbApynMnV8muW20aq4EmvhuMd7Ouk3RQlaSuJVNH7d6ybmECzgoCm2xIXiT85bL/sF
         +id6MPkp7ajZV/l3ekQmutsUGbnwlrUf76YCHiKSi4u6bEh0rCazTqi4HTQcuWEM9UtG
         HQR7n6dzPhZwMLvgGXKzcd33Jdy/BbSlUeggNS47zJc0qVBxKCyjhFs9bhV232u0H0XZ
         e3nTe083gfwvHuB/AAt6vqRUuC+ccGQS5bceQNyHWqCsst+vI2bGq0Ez/5m73r8z5mAj
         zizw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1721840313; x=1722445113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BKnGCq+Sq4VCkikUhpmgMWN36IKLSuQ8V5FxWoQiM28=;
        b=szTzwtaopHV1YqytWjmPj+mpZwtHDelYoW0Kg8Sz9CyaFaOpmf8FBe98bGZDJuFyzI
         1cRp4Q1KJgL43c1BqoQDeAE4luNKhDBhr+q+cZWI9+VsU7r+ozFXrnle5EcnZV/m+7Oz
         wk3Udqmnfg2Fsw8WNM3eIbjvghJDTPO3vCHnvyp2vV8jlSXwZ0fRfIAIKeGfJR6cIRhB
         Dv/Z8NlECxGus++lLHUV9e3nwQOswbSZcw9L2B0TLI5W1ku4ACRPNEzfiHrH2WVo/HdP
         et4KJ3jEIVRSDTrQezmIW2d+1TGNpmH4TTqN8b9agtYnKxIUnezAxCDlCtlqjLSxlXI1
         OnYA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUaSE2JRNIXMBOg7RvVZgxz7QB457bh3xXYIYClSJdhjVbFxNWyghoO7r9JlW3MdbboOB0CylqpXXWMGBfDvHRwPYAhAMEYMw==
X-Gm-Message-State: AOJu0YyoluWfE5lCrILnXiYZ1vUOVTT3ow4fPC9Zl+XtX9LQdMQ+7c1F
	ZWDmOYpXUS8vc2u/zuzQJOM4/9PcfpI6/dtoqDcWYo+MwUq5AeHH
X-Google-Smtp-Source: AGHT+IEwkJNp7GCvRfFaUcSIszvoRsU/LXrhb67QAxzRUANowz6w7YbA4d/4Woogox2UridIBFEwWg==
X-Received: by 2002:a05:6000:4024:b0:366:e7aa:7fa5 with SMTP id ffacd0b85a97d-36b31ac772dmr213044f8f.1.1721840312932;
        Wed, 24 Jul 2024 09:58:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e112:0:b0:368:63d:bc74 with SMTP id ffacd0b85a97d-36b31a705fels17863f8f.1.-pod-prod-03-eu;
 Wed, 24 Jul 2024 09:58:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXvh0FM2D0rfzo/CWu6KPKbDS43S3HDyjxWSoGyGgKqKEeeDaARI28IgEtKwP4S/q3/m5pguveyEcq9dp9sUsuefp5gmqtBDAXfFg==
X-Received: by 2002:a05:6000:10c4:b0:367:f281:260e with SMTP id ffacd0b85a97d-36b31ac7126mr201982f8f.3.1721840310794;
        Wed, 24 Jul 2024 09:58:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1721840310; cv=none;
        d=google.com; s=arc-20160816;
        b=gERobKfLv62HB78Y//rEN73joQFwJFddynXRUAq+GUfHAsUMASNjDl3G9YHZiLSAAS
         /pjAI2R+w4B0Qpdp4xUfAQBbq+sQea64jyN3Qt9lcLQGPrGjiI3/ATLhu/5YUCfAkueZ
         j5EYmKrV/KsgvbpXeLfCa5aS7jvWisVgS8grtw4DnN9irsr6j0aZSXFznZ+IilAi4m1z
         rRRTkpSHDbW/hKLUNrGmshzI3Yfd5tmll5tORTw8blXFS2suiBnVibtvx++bnNdn3xux
         tZgAb5MBCkotGWeEcg6y7mk9PlrS3DpSYGzd0Tn6iz/q/3YIUHL/cJ4geN1iwgwMg8xX
         sX+Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n0ehM3meCwqPiDPhpWbCbP7i9znvpSX8RvjFc9Xbyvo=;
        fh=piboUdWPKTCJPsf6UGjsct5CVcH2Xp3W5Qaq4oDBjls=;
        b=JXVIwLTsBhEn5nca/e54BZDKWON6ASIA2phtcNpc8wxceOb/8A9KZOK1FFHaILm9Xb
         s2FzUSk371s3KZ7Ln2sH/RFioS9Q/vJY7igCwg/yfsI41HcltEMD5Kb47dbkxo8xtCnM
         N154659Mu+YIYhasLY/mjHO8Bs8ONqWilh0Jv1dah271l+ZPVSPIb1r7LQUHNYR/16CX
         vdaE4NaI0Ju3aw+r1aIZsyTFaFQXLAzS1I2itIY2294VemVRIqM5FKWGJ+DvPOdEawRM
         TnDUrHeS32wCuQO33jISLyJLW3YTl2fUlJ+j7MS+6avAAjN1EHC9Gb5SsA+RMcl3jSyz
         0DOA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=W8u27l4n;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-427ff751fadsi575745e9.1.2024.07.24.09.58.30
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Jul 2024 09:58:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-3685a5e7d3cso4023641f8f.1;
        Wed, 24 Jul 2024 09:58:30 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVVk/cJDlfLUyZTY0cfKpvKSndkV2jGXp6FWrS6l7fC1RK4yztrOKU2ABQbOTjLbYWsaLlcueZY7tjT26BGL+J8qwZBouVYCpMrTogYGVsfKOZse0uZBynauDdROqeX4FPLu5yq9FDyP/+tpA==
X-Received: by 2002:a05:6000:110b:b0:367:8fee:443b with SMTP id
 ffacd0b85a97d-36b31b4cc21mr186316f8f.41.1721840309941; Wed, 24 Jul 2024
 09:58:29 -0700 (PDT)
MIME-Version: 1.0
References: <00000000000045457e061df061c3@google.com>
In-Reply-To: <00000000000045457e061df061c3@google.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 24 Jul 2024 18:58:18 +0200
Message-ID: <CA+fCnZf+7Z1=khHu8vKDpRyqCu9=ajNVRwzhHiumt6UMqBDCtA@mail.gmail.com>
Subject: Re: [syzbot] [usb?] KMSAN: kernel-infoleak in raw_ioctl (2)
To: Alexander Potapenko <glider@google.com>
Cc: gregkh@linuxfoundation.org, linux-kernel@vger.kernel.org, 
	linux-usb@vger.kernel.org, syzkaller-bugs@googlegroups.com, 
	syzbot <syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>
Content-Type: multipart/mixed; boundary="00000000000008e577061e01304d"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=W8u27l4n;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

--00000000000008e577061e01304d
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Tue, Jul 23, 2024 at 10:55=E2=80=AFPM syzbot
<syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com> wrote:
>
> Hello,
>
> syzbot found the following issue on:
>
> HEAD commit:    2c9b3512402e Merge tag 'for-linus' of git://git.kernel.or=
g..
> git tree:       upstream
> console+strace: https://syzkaller.appspot.com/x/log.txt?x=3D1197b6b598000=
0
> kernel config:  https://syzkaller.appspot.com/x/.config?x=3D6bfb33a8ad104=
58f
> dashboard link: https://syzkaller.appspot.com/bug?extid=3D17ca2339e34a1d8=
63aad
> compiler:       Debian clang version 15.0.6, GNU ld (GNU Binutils for Deb=
ian) 2.40
> syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=3D1626b995980=
000
> C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=3D1572eb2198000=
0
>
> Downloadable assets:
> disk image: https://storage.googleapis.com/syzbot-assets/f8543636ba6c/dis=
k-2c9b3512.raw.xz
> vmlinux: https://storage.googleapis.com/syzbot-assets/403c612b7ac5/vmlinu=
x-2c9b3512.xz
> kernel image: https://storage.googleapis.com/syzbot-assets/88dc686d170a/b=
zImage-2c9b3512.xz
>
> IMPORTANT: if you fix the issue, please add the following tag to the comm=
it:
> Reported-by: syzbot+17ca2339e34a1d863aad@syzkaller.appspotmail.com
>
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
> BUG: KMSAN: kernel-infoleak in instrument_copy_to_user include/linux/inst=
rumented.h:114 [inline]
> BUG: KMSAN: kernel-infoleak in _copy_to_user+0xbc/0x110 lib/usercopy.c:45
>  instrument_copy_to_user include/linux/instrumented.h:114 [inline]
>  _copy_to_user+0xbc/0x110 lib/usercopy.c:45
>  copy_to_user include/linux/uaccess.h:191 [inline]
>  raw_ioctl_ep0_read drivers/usb/gadget/legacy/raw_gadget.c:786 [inline]
>  raw_ioctl+0x3d2e/0x5440 drivers/usb/gadget/legacy/raw_gadget.c:1315
>  vfs_ioctl fs/ioctl.c:51 [inline]
>  __do_sys_ioctl fs/ioctl.c:907 [inline]
>  __se_sys_ioctl+0x261/0x450 fs/ioctl.c:893
>  __x64_sys_ioctl+0x96/0xe0 fs/ioctl.c:893
>  x64_sys_call+0x1a06/0x3c10 arch/x86/include/generated/asm/syscalls_64.h:=
17
>  do_syscall_x64 arch/x86/entry/common.c:52 [inline]
>  do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83
>  entry_SYSCALL_64_after_hwframe+0x77/0x7f
>
> Uninit was created at:
>  slab_post_alloc_hook mm/slub.c:3985 [inline]
>  slab_alloc_node mm/slub.c:4028 [inline]
>  __do_kmalloc_node mm/slub.c:4148 [inline]
>  __kmalloc_noprof+0x661/0xf30 mm/slub.c:4161
>  kmalloc_noprof include/linux/slab.h:685 [inline]
>  raw_alloc_io_data drivers/usb/gadget/legacy/raw_gadget.c:675 [inline]
>  raw_ioctl_ep0_read drivers/usb/gadget/legacy/raw_gadget.c:778 [inline]
>  raw_ioctl+0x3bcb/0x5440 drivers/usb/gadget/legacy/raw_gadget.c:1315
>  vfs_ioctl fs/ioctl.c:51 [inline]
>  __do_sys_ioctl fs/ioctl.c:907 [inline]
>  __se_sys_ioctl+0x261/0x450 fs/ioctl.c:893
>  __x64_sys_ioctl+0x96/0xe0 fs/ioctl.c:893
>  x64_sys_call+0x1a06/0x3c10 arch/x86/include/generated/asm/syscalls_64.h:=
17
>  do_syscall_x64 arch/x86/entry/common.c:52 [inline]
>  do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83
>  entry_SYSCALL_64_after_hwframe+0x77/0x7f
>
> Bytes 0-4095 of 4096 are uninitialized
> Memory access of size 4096 starts at ffff888116edb000
> Data copied to user address 00007ffefdca74d8
>
> CPU: 0 PID: 5057 Comm: syz-executor289 Not tainted 6.10.0-syzkaller-11185=
-g2c9b3512402e #0
> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS G=
oogle 06/27/2024
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D

Hi Alex,

This appears to be some kind of a bug in KMSAN.

I applied a debugging patch that prints the data submitted by ath9k,
tracks the data being copied to Raw Gadget, and prints the data copied
to userspace by Raw Gadget (attached). I see that the submitted and
the copied data match (at least, the first 8 bytes). I also see that
the data is copied from ath9k to Raw Gadget as intended. So the data
should be initialized. However, somehow, KMSAN doesn't track that.

The bug is reproducible via the C reproducer, but you have to keep it
running for a minute or so. The output with the debugging patch is
somewhat messy due to multiple threads being involved, but you can
start unveiling it backwards from the kernel address printed in the
KMSAN report.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf%2B7Z1%3DkhHu8vKDpRyqCu9%3DajNVRwzhHiumt6UMqBDCtA%40mai=
l.gmail.com.

--00000000000008e577061e01304d
Content-Type: text/x-patch; charset="US-ASCII"; name="ath9k.patch"
Content-Disposition: attachment; filename="ath9k.patch"
Content-Transfer-Encoding: base64
Content-ID: <f_lz033g5w0>
X-Attachment-Id: f_lz033g5w0

ZGlmZiAtLWdpdCBhL2RyaXZlcnMvbmV0L3dpcmVsZXNzL2F0aC9hdGg5ay9oaWZfdXNiLmMgYi9k
cml2ZXJzL25ldC93aXJlbGVzcy9hdGgvYXRoOWsvaGlmX3VzYi5jCmluZGV4IDBjNzg0MWY5NTIy
OC4uZTQxOTU0YTk4Mjk0IDEwMDY0NAotLS0gYS9kcml2ZXJzL25ldC93aXJlbGVzcy9hdGgvYXRo
OWsvaGlmX3VzYi5jCisrKyBiL2RyaXZlcnMvbmV0L3dpcmVsZXNzL2F0aC9hdGg5ay9oaWZfdXNi
LmMKQEAgLTEwODMsNiArMTA4Myw3IEBAIHN0YXRpYyBpbnQgYXRoOWtfaGlmX3VzYl9kb3dubG9h
ZF9mdyhzdHJ1Y3QgaGlmX2RldmljZV91c2IgKmhpZl9kZXYpCiAJCXRyYW5zZmVyID0gbWluX3Qo
c2l6ZV90LCBsZW4sIDQwOTYpOwogCQltZW1jcHkoYnVmLCBkYXRhLCB0cmFuc2Zlcik7CiAKK3By
X2VycigiISBhdGg5azogdHJhbnNmZXIgPSAlZCwgYnVmID0gJXB4LCBieXRlcyA9ICVseFxuIiwg
KGludCl0cmFuc2ZlciwgYnVmLCAqKHVuc2lnbmVkIGxvbmcgKilidWYpOwogCQllcnIgPSB1c2Jf
Y29udHJvbF9tc2coaGlmX2Rldi0+dWRldiwKIAkJCQkgICAgICB1c2Jfc25kY3RybHBpcGUoaGlm
X2Rldi0+dWRldiwgMCksCiAJCQkJICAgICAgRklSTVdBUkVfRE9XTkxPQUQsIDB4NDAgfCBVU0Jf
RElSX09VVCwKZGlmZiAtLWdpdCBhL2RyaXZlcnMvdXNiL2dhZGdldC9sZWdhY3kvcmF3X2dhZGdl
dC5jIGIvZHJpdmVycy91c2IvZ2FkZ2V0L2xlZ2FjeS9yYXdfZ2FkZ2V0LmMKaW5kZXggMzk5ZmNh
MzJhOGFjLi4wYWYyMGFjNTY2MDIgMTAwNjQ0Ci0tLSBhL2RyaXZlcnMvdXNiL2dhZGdldC9sZWdh
Y3kvcmF3X2dhZGdldC5jCisrKyBiL2RyaXZlcnMvdXNiL2dhZGdldC9sZWdhY3kvcmF3X2dhZGdl
dC5jCkBAIC03ODMsNiArNzgzLDkgQEAgc3RhdGljIGludCByYXdfaW9jdGxfZXAwX3JlYWQoc3Ry
dWN0IHJhd19kZXYgKmRldiwgdW5zaWduZWQgbG9uZyB2YWx1ZSkKIAkJZ290byBmcmVlOwogCiAJ
bGVuZ3RoID0gbWluKGlvLmxlbmd0aCwgKHVuc2lnbmVkIGludClyZXQpOworY3VycmVudC0+a21z
YW5fY3R4LmFsbG93X3JlcG9ydGluZyA9IGZhbHNlOworaWYgKGxlbmd0aCA+PSA4KSBwcl9lcnIo
IiEgZXAwX3JlYWQ6IGxlbmd0aCA9ICV1LCBkYXRhID0gJXB4LCBieXRlcyA9ICVseFxuIiwgbGVu
Z3RoLCBkYXRhLCAqKHVuc2lnbmVkIGxvbmcgKilkYXRhKTsKK2N1cnJlbnQtPmttc2FuX2N0eC5h
bGxvd19yZXBvcnRpbmcgPSB0cnVlOwogCWlmIChjb3B5X3RvX3VzZXIoKHZvaWQgX191c2VyICop
KHZhbHVlICsgc2l6ZW9mKGlvKSksIGRhdGEsIGxlbmd0aCkpCiAJCXJldCA9IC1FRkFVTFQ7CiAJ
ZWxzZQpkaWZmIC0tZ2l0IGEvZHJpdmVycy91c2IvZ2FkZ2V0L3VkYy9kdW1teV9oY2QuYyBiL2Ry
aXZlcnMvdXNiL2dhZGdldC91ZGMvZHVtbXlfaGNkLmMKaW5kZXggZjM3YjBkODM4NmMxLi4xNjkw
ZTQ5MDZjNDMgMTAwNjQ0Ci0tLSBhL2RyaXZlcnMvdXNiL2dhZGdldC91ZGMvZHVtbXlfaGNkLmMK
KysrIGIvZHJpdmVycy91c2IvZ2FkZ2V0L3VkYy9kdW1teV9oY2QuYwpAQCAtMTM1MCw3ICsxMzUw
LDEwIEBAIHN0YXRpYyBpbnQgZHVtbXlfcGVyZm9ybV90cmFuc2ZlcihzdHJ1Y3QgdXJiICp1cmIs
IHN0cnVjdCBkdW1teV9yZXF1ZXN0ICpyZXEsCiAJCWlmICh0b19ob3N0KQogCQkJbWVtY3B5KHVi
dWYsIHJidWYsIGxlbik7CiAJCWVsc2UKK3sKK3ByX2VycigiISBkdW1teTogbWVtY3B5KCVweCwg
JXB4LCAldSlcbiIsIHJidWYsIHVidWYsIGxlbik7CiAJCQltZW1jcHkocmJ1ZiwgdWJ1ZiwgbGVu
KTsKK30KIAkJcmV0dXJuIGxlbjsKIAl9CiAKQEAgLTEzNzksNyArMTM4MiwxMCBAQCBzdGF0aWMg
aW50IGR1bW15X3BlcmZvcm1fdHJhbnNmZXIoc3RydWN0IHVyYiAqdXJiLCBzdHJ1Y3QgZHVtbXlf
cmVxdWVzdCAqcmVxLAogCQlpZiAodG9faG9zdCkKIAkJCW1lbWNweSh1YnVmLCByYnVmLCB0aGlz
X3NnKTsKIAkJZWxzZQoreworcHJfZXJyKCIhIGR1bW15OiBtZW1jcHkoJXB4LCAlcHgsICV1KVxu
IiwgcmJ1ZiwgdWJ1ZiwgbGVuKTsKIAkJCW1lbWNweShyYnVmLCB1YnVmLCB0aGlzX3NnKTsKK30K
IAkJbGVuIC09IHRoaXNfc2c7CiAKIAkJaWYgKCFsZW4pCg==
--00000000000008e577061e01304d--
