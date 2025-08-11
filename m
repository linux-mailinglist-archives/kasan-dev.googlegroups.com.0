Return-Path: <kasan-dev+bncBDW2JDUY5AORBWXE47CAMGQER2A5LBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id F2ED9B20A77
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:38:35 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-55b8422dbdasf2569918e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 06:38:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754919515; cv=pass;
        d=google.com; s=arc-20240605;
        b=KylGGmdfEGGS+MlsXZOw8bSKHo0636+Yna6VJblIVjgvbWFvutM8hPEa996s8UnC1D
         OVdIJ4cn8z5UVUv1ECKTRUv0po3Lgp4LENZCSXn52opm8BXTooA984VfFmPDtOnxIHVT
         Nou90PBvSX59bqNeUEX6m6nJx/iYacfceQzX7mBF+SD7AjtucTrC0gwdXXJPVLLLuV82
         UQYZ0dEG7qxW0h44xCyX0uISfyPqT0qYaCAuP5jaL3LMZS7JtvFiZH3RFDogURuIR6fq
         s2OPceednIxEXztVnmE/NecsNDdFlRm8YxXk75lOtniXqN0HfboyKNCgvKuWLWIukjpR
         Qx2g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=tpobxaeuddq2qRYPhyWt2STC5T2A1xuqkNYJnRwwk+8=;
        fh=2g3q1bTUvxSprHMyajvQ4o1HNJZR43QDGmkd/OXIEQM=;
        b=atniEeS6DXG5oKwSaQidTcqyt6c5AbAEspRBjjEnvhkdVkKPReOScJpFm9edlQjr53
         BaDe2ZdesJAR+dKzYD8jQd7sa3XlHuaXdBBKzym6XCuWf8iUmo3zjXIsA/Aj3h0f/nPy
         W4xb7voB63lF/c8eZhNw6bOMpNRbvrP9Ikt9W3sbF74OWnZpM+cemHkk3sAXmXjyVxPr
         X/wCurqq/UWKXYjH5sMG3FpVkWTFC6pWPxUYk3EpLnld9h3cU1K0vAGU15g19/sxkdLJ
         XUA22jG7AEv1JAJ3mKDctSAN7CB1UAwXrp1ukbHUvQvjvFdMgJdpc2bEpkrjmdVyj2Gs
         0DxQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ea/x8q0R";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754919515; x=1755524315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tpobxaeuddq2qRYPhyWt2STC5T2A1xuqkNYJnRwwk+8=;
        b=n3i3V+tnVzw6KTtcnl/gewDxkfMZUTyWDMAVhihJ/qFZU38zHhuaPxdMUPgFRC4oZb
         xehRzoXJnwM8NNkuJIznrzo4EZqxwKheSnaTT6p1fCimlsem1EAF3pTl343O10AZtqs1
         eGTLA+rDWgAjMoIpdnK4vQJ7R+t/aNV0JkpmfydroR/3lS0uTjcuUfHxYs2l411zVP60
         NRMNPon3cs3eGar8KjzuYbUlfOGYzRmKj6UR9CQqf/FsACh1HsgwZpb1qOmOZmtEDRhZ
         CN2/jnR4ouluSC4nx/rjZaYIl47zn31HYy3gXAWxR7SB9+T1laH9C0TfO5sMRHzHvLHK
         bVZw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1754919515; x=1755524315; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=tpobxaeuddq2qRYPhyWt2STC5T2A1xuqkNYJnRwwk+8=;
        b=gYn+bqzFbznxrsP85UDA3TQOFX1tSRLXbFErh0zl5gnXi6fpgeU/YmIyL4cHaLEX5B
         PEPlm1+GdHyfwfgi3eBOYAuBF7CMSIb0pnqx21l4G4js+jj/qEOAP8YFj3H55v2q/Wiy
         MHTw9tswCNPS7xIrn2QNMC2OqAR1kwpr2dAy88Q9MBEzSsIr1lNNNI8LfImbxldmce3U
         zid2SMaudBgNFxxgbtxazgQd0TCMUEzdEpoGdmUmESlngROWWZfEzQudJEUxKpORFz7k
         GnsTJq7owkGVRvO7npJc/fhFKx4r0gYk4cvDlKoUDplL2FepT0m8iQjRV0hd5pLmGc3p
         f+8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754919515; x=1755524315;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tpobxaeuddq2qRYPhyWt2STC5T2A1xuqkNYJnRwwk+8=;
        b=SoCIeRiDnpNwoxmYTywyg8ZbIcTbC3UnDxtti81jgkvcMK7lYSgN4IMh/Asvqfr6Rv
         G4hPIATjWywL4nIjQYXb0xJv1884qpbO6Mg1X5PMI2krl6O1i7CmMoYnniXedo3XRCWV
         kE7XqdmmgB9XmPfKAg4Sfv1aX+Ih69Sq1szvuB9hGcWr/idKLaG6PChXHUVigS5YJA2X
         /oYYhv/FBJvM6r49Fxj+fzJf5rGye7sl5kESDfk9VsLuyIavB6Y1vVAYIfJBvGHTPybf
         VnZzhFd9GcfWIvLAa61bNxzqKJ1F0tiwOumplklctCM0OV2dP1C8FRnZKs0s6pYrAqRC
         yGbg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXik9989lDBECQDWDWZLTV4smnv4LwktbgewpfPT6Afppcw3kzet2U8EX8i86ypQ0h9I30/qw==@lfdr.de
X-Gm-Message-State: AOJu0Yz3x63ZTXmQmxnKFPU7iAuSl3vvBzQX/bDw3frziqtsR9AJ93af
	gaCXyv1HwmENUFWh6/3rN4o3uPQeNQu7mVj+8vfu/huRhLvqKyOBuQ94
X-Google-Smtp-Source: AGHT+IEOdq8muKrFdHeuNlFr9tmrDtrz96LzGonVHujXRNGQR5sk2NlEx1qeLngLG/1v4+WdXzPgkg==
X-Received: by 2002:a05:6512:118d:b0:553:a469:3fed with SMTP id 2adb3069b0e04-55cc009eff8mr3862890e87.11.1754919514725;
        Mon, 11 Aug 2025 06:38:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdUQpRQ947NWSMj+Y5LIStRwoOSxUZWEMH8zDa/g1RqGA==
Received: by 2002:a05:651c:31d6:b0:333:c7c4:6b7b with SMTP id
 38308e7fff4ca-333c7c47552ls2366791fa.1.-pod-prod-03-eu; Mon, 11 Aug 2025
 06:38:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXGcD1+RCLvUtJ2jPXTaIT3SgVw0xffhYxmxSSoCq+IOFdhF1sY3Y0eLPaJ0v1NWkLWQDewpWoSgkU=@googlegroups.com
X-Received: by 2002:a2e:b8cc:0:b0:333:ac42:8d6a with SMTP id 38308e7fff4ca-333ac4296a6mr23701271fa.3.1754919511691;
        Mon, 11 Aug 2025 06:38:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754919511; cv=none;
        d=google.com; s=arc-20240605;
        b=FutLT2A6SLp9WUchSXCKyETlUsDO1dvQBQ6YL8AiCAny/bCD6RzF2HqFL+NU7LigL/
         7h4uc7mdATGPXM++YrzHNshFG5vLYdomVAH/7SHcNXPuv1MxFuDRFFXrRyouK2JQaT+/
         U56upfwNWQc3k2+JbtRoW65URzQEVHOwjM1fO0qXFiPP4kbcN1Qi3/16sCZZIMZt5j2C
         Z7frtnLwfe+sa/pr3N+up58hj098xHn3H1VKqtEM83W0b31SyR2zMdrltIbr+GoWcJ2x
         qfd5uFZbnLAwh79+mgiyTjfMIZHfFdHQV2Tx7rqhUAEkKjYIl82loU9Wqq4jwYOb77e4
         sOWg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1kbINbP8WLaLr5mOXjjJSrdAAtJw6w4ZFXcoqIl+hSs=;
        fh=P/XAQlONbiHk0H1+hu5KXhPMJ9uSCvX/vXoBrI3OPpE=;
        b=W+6wLS89d8FY6AzAqkiZgGiwznXu2bdOrHoX1eqa0EfI1nL6nMaotXxWr7+72Kn2ep
         htzqTdYeCRGBvwadg/LMb4bNIC3y2I8W6G6oTe137z2tZ6C12z1mbYNLG8ozC+JhhUK+
         uEEXXAA1HXoL+zn1Hk4fC3zJ9HL/M9/LXRNM2wgOvVpXO4kTN1ISI9UYvl8uZNhoefte
         5cMY5jIrWJMAnxMsdogTR4cEYn4QCDYDwrczcFlCo+d6WOqK4Tcx5c04fdIyPHVT9P6u
         NvBFp2hbSXPNcTs2m5eFcOggrF05IPWMSnDPbPmx0F40TKLUNPu0eJFHr1XXk6/4VW9M
         VSBQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="ea/x8q0R";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-33237efa732si6053901fa.2.2025.08.11.06.38.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 06:38:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-3b78bca0890so2113894f8f.3;
        Mon, 11 Aug 2025 06:38:31 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUGZNCo8VJuyATTrGs39Xhlk7uwpsqdb+pZwhnWdK23bpziUlFg+gUc8uRmbM0EdJawdhLx17Uxkiw=@googlegroups.com, AJvYcCUukY3OIm2bLLoNsL4VynuKKkZmf892Rq/AdJmfmN6DHug2KoUD6JMwNVHBZCHRbEOsY/QotZsWEaZWUi7c4BA=@googlegroups.com
X-Gm-Gg: ASbGncvov5bvpBSF0zc+r3igk9SmCDKsktJBwGhWnnY49aAjdOUapb5kVpXP66F256p
	Z2Jy+V7HgoQsafXIMuOg1Fny68iH13yJzkFMHWQRt24MY2NcUVDwvZLnG8yyBmjC7QYCJeAkwkN
	FHN548DNit3djhAsN+kAooC2KPvbCX5v9Mvxxo8uyvrF2YQFAa/iMBy3QioQGHKDyHHE0I+zGQC
	cX4/g==
X-Received: by 2002:a05:6000:2011:b0:3a5:1cc5:aa6f with SMTP id
 ffacd0b85a97d-3b900b4dbdemr9521937f8f.34.1754919510792; Mon, 11 Aug 2025
 06:38:30 -0700 (PDT)
MIME-Version: 1.0
References: <686ea951.050a0220.385921.0016.GAE@google.com> <aG7pfqqhk47YXFNz@dread.disaster.area>
 <CANp29Y700diEaeHd6bHksAL_60D+vJD-95EqcveqMME0smNJnw@mail.gmail.com>
In-Reply-To: <CANp29Y700diEaeHd6bHksAL_60D+vJD-95EqcveqMME0smNJnw@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 11 Aug 2025 15:38:17 +0200
X-Gm-Features: Ac12FXyLwMPgBtXA0Gq8HKHELEpcXOwD5qy9_RF6aOPgWMkTUfSEdQ1ChL4vEts
Message-ID: <CA+fCnZfMMb0Rw68BczORoDQSDJaQy93n8TAA44JwS4P0s=abkw@mail.gmail.com>
Subject: Re: [syzbot] [xfs?] possible deadlock in xfs_ilock_attr_map_shared (2)
To: Aleksandr Nogikh <nogikh@google.com>, Dave Chinner <david@fromorbit.com>
Cc: syzbot <syzbot+3470c9ffee63e4abafeb@syzkaller.appspotmail.com>, cem@kernel.org, 
	linux-kernel@vger.kernel.org, linux-xfs@vger.kernel.org, 
	syzkaller-bugs@googlegroups.com, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="ea/x8q0R";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42c
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

On Thu, Jul 10, 2025 at 10:03=E2=80=AFAM 'Aleksandr Nogikh' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Hi Dave,
>
> On Thu, Jul 10, 2025 at 12:13=E2=80=AFAM 'Dave Chinner' via syzkaller-bug=
s
> <syzkaller-bugs@googlegroups.com> wrote:
> >
> > On Wed, Jul 09, 2025 at 10:39:29AM -0700, syzbot wrote:
> > > Hello,
> > >
> > > syzbot found the following issue on:
> > >
> > > HEAD commit:    733923397fd9 Merge tag 'pwm/for-6.16-rc6-fixes' of gi=
t://g..
> > > git tree:       upstream
> > > console output: https://syzkaller.appspot.com/x/log.txt?x=3D13f535825=
80000
> > > kernel config:  https://syzkaller.appspot.com/x/.config?x=3Db309c907e=
aab29da
> > > dashboard link: https://syzkaller.appspot.com/bug?extid=3D3470c9ffee6=
3e4abafeb
> > > compiler:       Debian clang version 20.1.7 (++20250616065708+6146a88=
f6049-1~exp1~20250616065826.132), Debian LLD 20.1.7
> > >
> > > Unfortunately, I don't have any reproducer for this issue yet.
> > >
> > > Downloadable assets:
> > > disk image (non-bootable): https://storage.googleapis.com/syzbot-asse=
ts/d900f083ada3/non_bootable_disk-73392339.raw.xz
> > > vmlinux: https://storage.googleapis.com/syzbot-assets/be7feaa77b8c/vm=
linux-73392339.xz
> > > kernel image: https://storage.googleapis.com/syzbot-assets/a663b3e314=
63/bzImage-73392339.xz
> > >
> > > IMPORTANT: if you fix the issue, please add the following tag to the =
commit:
> > > Reported-by: syzbot+3470c9ffee63e4abafeb@syzkaller.appspotmail.com
> > >
> > > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D
> > > WARNING: possible circular locking dependency detected
> > > 6.16.0-rc5-syzkaller-00038-g733923397fd9 #0 Not tainted
> > > ------------------------------------------------------
> > > syz.0.0/5339 is trying to acquire lock:
> > > ffffffff8e247500 (fs_reclaim){+.+.}-{0:0}, at: might_alloc include/li=
nux/sched/mm.h:318 [inline]
> > > ffffffff8e247500 (fs_reclaim){+.+.}-{0:0}, at: prepare_alloc_pages+0x=
153/0x610 mm/page_alloc.c:4727
> > >
> > > but task is already holding lock:
> > > ffff888053415098 (&xfs_nondir_ilock_class){++++}-{4:4}, at: xfs_ilock=
_attr_map_shared+0x92/0xd0 fs/xfs/xfs_inode.c:85
> > >
> > > which lock already depends on the new lock.
> > >
> > >
> > > the existing dependency chain (in reverse order) is:
> > >
> > > -> #1 (&xfs_nondir_ilock_class){++++}-{4:4}:
> > >        lock_acquire+0x120/0x360 kernel/locking/lockdep.c:5871
> > >        down_write_nested+0x9d/0x200 kernel/locking/rwsem.c:1693
> > >        xfs_reclaim_inode fs/xfs/xfs_icache.c:1045 [inline]
> > >        xfs_icwalk_process_inode fs/xfs/xfs_icache.c:1737 [inline]
> > >        xfs_icwalk_ag+0x12c5/0x1ab0 fs/xfs/xfs_icache.c:1819
> > >        xfs_icwalk fs/xfs/xfs_icache.c:1867 [inline]
> > >        xfs_reclaim_inodes_nr+0x1e3/0x260 fs/xfs/xfs_icache.c:1111
> > >        super_cache_scan+0x41b/0x4b0 fs/super.c:228
> > >        do_shrink_slab+0x6ec/0x1110 mm/shrinker.c:437
> > >        shrink_slab+0xd74/0x10d0 mm/shrinker.c:664
> > >        shrink_one+0x28a/0x7c0 mm/vmscan.c:4939
> > >        shrink_many mm/vmscan.c:5000 [inline]
> > >        lru_gen_shrink_node mm/vmscan.c:5078 [inline]
> > >        shrink_node+0x314e/0x3760 mm/vmscan.c:6060
> > >        kswapd_shrink_node mm/vmscan.c:6911 [inline]
> > >        balance_pgdat mm/vmscan.c:7094 [inline]
> > >        kswapd+0x147c/0x2830 mm/vmscan.c:7359
> > >        kthread+0x70e/0x8a0 kernel/kthread.c:464
> > >        ret_from_fork+0x3f9/0x770 arch/x86/kernel/process.c:148
> > >        ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:245
> > >
> > > -> #0 (fs_reclaim){+.+.}-{0:0}:
> > >        check_prev_add kernel/locking/lockdep.c:3168 [inline]
> > >        check_prevs_add kernel/locking/lockdep.c:3287 [inline]
> > >        validate_chain+0xb9b/0x2140 kernel/locking/lockdep.c:3911
> > >        __lock_acquire+0xab9/0xd20 kernel/locking/lockdep.c:5240
> > >        lock_acquire+0x120/0x360 kernel/locking/lockdep.c:5871
> > >        __fs_reclaim_acquire mm/page_alloc.c:4045 [inline]
> > >        fs_reclaim_acquire+0x72/0x100 mm/page_alloc.c:4059
> > >        might_alloc include/linux/sched/mm.h:318 [inline]
> > >        prepare_alloc_pages+0x153/0x610 mm/page_alloc.c:4727
> > >        __alloc_frozen_pages_noprof+0x123/0x370 mm/page_alloc.c:4948
> > >        alloc_pages_mpol+0x232/0x4a0 mm/mempolicy.c:2419
> > >        alloc_frozen_pages_noprof mm/mempolicy.c:2490 [inline]
> > >        alloc_pages_noprof+0xa9/0x190 mm/mempolicy.c:2510
> > >        get_free_pages_noprof+0xf/0x80 mm/page_alloc.c:5018
> > >        __kasan_populate_vmalloc mm/kasan/shadow.c:362 [inline]
> > >        kasan_populate_vmalloc+0x33/0x1a0 mm/kasan/shadow.c:417
> > >        alloc_vmap_area+0xd51/0x1490 mm/vmalloc.c:2084
> > >        __get_vm_area_node+0x1f8/0x300 mm/vmalloc.c:3179
> > >        __vmalloc_node_range_noprof+0x301/0x12f0 mm/vmalloc.c:3845
> > >        __vmalloc_node_noprof mm/vmalloc.c:3948 [inline]
> > >        __vmalloc_noprof+0xb1/0xf0 mm/vmalloc.c:3962
> > >        xfs_buf_alloc_backing_mem fs/xfs/xfs_buf.c:239 [inline]
> >
> > KASAN is still failing to pass through __GFP_NOLOCKDEP allocation
> > context flags. It's also failing to pass through other important
> > context restrictions like GFP_NOFS, GFP_NOIO, __GFP_NOFAIL, etc.
> >
> > Fundamentally, it's a bug to be doing nested GFP_KERNEL allocations
> > inside an allocation context that has a more restricted allocation
> > context...
> >
> > #syz set subsystems: kasan
>
> Thanks for the analysis!
>
> I've added the kasan-dev list to Cc.

Filed a bug: https://bugzilla.kernel.org/show_bug.cgi?id=3D220434

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZfMMb0Rw68BczORoDQSDJaQy93n8TAA44JwS4P0s%3Dabkw%40mail.gmail.com.
