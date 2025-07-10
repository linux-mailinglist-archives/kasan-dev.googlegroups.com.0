Return-Path: <kasan-dev+bncBCXKTJ63SAARBQHHXXBQMGQE2RR7QLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id E81BAAFFB9C
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 10:03:13 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id 3f1490d57ef6-e81d151012csf850935276.2
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 01:03:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752134593; cv=pass;
        d=google.com; s=arc-20240605;
        b=WrZzgoW0szpL2dbje4rrfimL6VSdOpX7NZMnnvpC7z8sbz4BpwG6UBzV7eHPaUlrVq
         mdm3OGAbWMc+BMTpbntyOqhhcuyiB+AHYfWJlACvbmSYd2EO1lxsV2v+mAcYbooUljrh
         CQAHaw7YmQSlN3MPd0RZ2FmOYA2a4hNQZQB6Iujqvo0eGBlpRyb2tlKgwwy8qYf/ZreA
         flnLXGRfdbZbqds7FEuxbVT8hJyBxlv0zTEWJbfESkTmgZ6X+55WF20Nv2goLt8w3bv5
         MKcDxJACtCXjwIVlxBaENvL3ALvTx7vh3lw2cx9X+0jQ3ppcNhfW2I3/+g1uu9DAl1RA
         21pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BupIerU2LEKg4ipdQPRmsS7kMn+1MDUYiHo3Fnqwn9c=;
        fh=R+I5/Xni0QAzDZELcaUHoJ01ODmmYfzCLpKVFCgPj/Q=;
        b=EyXsQrC7rzwknUgmfCtgJNrh8J7ZoyQ7rpPUPwgLsQVqI4ji7PZtkXVA0Byh/tk0mB
         4LbC19ff+w/+9dUH+IMxfsxIE9QELOLDbPjJdmLCwUwLL/NlN+KHz/7RuUCbEX/Z7CPr
         Mx8sBmPydgdTi369ETR/9R7hIbtvacGbqq3ZKfp69RGh6o8CMPlN2lvvY7sICPqZYMgh
         lCpJ0BiaamZhUx7WJ65A9sqwtLd9tziNpVFCJROoSR+t5sJugOqgMrQseO08morm9u/e
         ajNL45MDb5QFf8lVMSze+dHAAIkualiat1HzclMghCD6pHeffb+6BD1l3qSqY1NEkT4M
         t8zw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iKcVqIgx;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752134593; x=1752739393; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BupIerU2LEKg4ipdQPRmsS7kMn+1MDUYiHo3Fnqwn9c=;
        b=mwkub5OQxSTtFtpAD+JWK+iNzfutBGphCDAQWKnt2gIba4xLmWvyenDd1Ac9ZlFB0e
         biCpgmfsgJ7jwcrXmMZ9N70ByXKUVos+rmfLj3SRt47SpjpuYK0pAvjzwRGgRc+FBz0y
         1D5L+riTi+vVVJMVP1TLesHt6604tg4wB5MmEty/hTeRJ6BQtA/NIC1GK9argI6galrz
         ePE5hqJpgEOiDLWyKe8GiPMN2eWAugHh3YBty1TuF/cp9t0rZC5Z/12h2uhuSsiWLWG3
         e8Ka/CYwfrmtFDUcjxA3SOoFf7vx6lDzJAL9th6XaJ3hGzeHSl078YviF5WMFoylPOr/
         Clbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752134593; x=1752739393;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=BupIerU2LEKg4ipdQPRmsS7kMn+1MDUYiHo3Fnqwn9c=;
        b=wLAYaV89U6MjZc44DPvjjI0oXESneL6sR0iZglNa85eyRYrs/f/6wK85IjjonuK6As
         vsRlv2QuGtlYjDDZE1wgaZd+XfRc4Ju5TV1t02CBIYkNwiHvdepA5TkzaAAQqE012ore
         p0ScbkyUfLmOJ6+YWBb8swoQlSk5X82//NXG5Ud4jf5Di/kMGevFHU6LDr2lSmC57d9j
         nVUxsphebFeRP+g4kcDiTTODYXRqrr9AI2RoxMiIw42OMP2ah2WZ4mfecVIOoAFhLAh/
         exJySPAZ9fUfcBtyVQBOM3KDnDuXuBpBUdbL5wGH8z0VOe/cpX2u53jmM2IUlmfl3ODU
         Z+yQ==
X-Forwarded-Encrypted: i=2; AJvYcCX0+2PtEezcyVi1YbTPQjc16lXkC09KnTDYU59aczslVzjNH8fOSrU5hHin0VLZmc7fh4jxKQ==@lfdr.de
X-Gm-Message-State: AOJu0YzBTGX9xnB6PBpO3k/GhZDpZHf4jtefyWrYIR9UOj8X+ets6q16
	+GKAXXzGNYeHAlrhYq3czyWktot9yi+F5uvbERKeAcel1uDnKhPv2VC4
X-Google-Smtp-Source: AGHT+IHKYjyjjWF7V5UGqzaR+aaBhJfvU5J6JXeUE5bzUu0s6CoDW2ueC+GN3Ufsx0KCuYTcT9RcUQ==
X-Received: by 2002:a05:6902:6a8a:b0:e89:9f1a:df2e with SMTP id 3f1490d57ef6-e8b77d98918mr2513775276.12.1752134592800;
        Thu, 10 Jul 2025 01:03:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfLZe3vCwXexRXkeojP+LTUgxK3rRpeg39dTM4yhJj0xw==
Received: by 2002:a05:6902:33c6:b0:e7d:801a:4dd6 with SMTP id
 3f1490d57ef6-e8b777b9475ls776590276.0.-pod-prod-05-us; Thu, 10 Jul 2025
 01:03:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVlIvdjYFW0SX3vW02gE2hktEPgEOic2vB5Jp5p1wfYA9T9P63vRKjkEHZuNZdV4rOfbAEkTE+OG3s=@googlegroups.com
X-Received: by 2002:a05:690c:6606:b0:703:b3b8:1ca1 with SMTP id 00721157ae682-717c165556emr30667197b3.5.1752134591790;
        Thu, 10 Jul 2025 01:03:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752134591; cv=none;
        d=google.com; s=arc-20240605;
        b=Csf6SJqLg+Nry9yYaVIDT+Z82rx+Ibo0OSFZssabFrGdDdEzpPDnDcIZn1Olk8quV5
         aYCwvCu2TmS3vTJhJEgmU8Bh5SRXrwP3jScGNFiiJ9kJHbz66y6xWKGveusfJbYj0UDn
         nufazcOAZ0i/d5g57+lGL9JiKnDI25FKBk4z4OuZot81Nx3oSnKAtYq2qGuIUCMbzDwz
         CzXZoTJjLDnq1uC0V4xmhDKNt5/DTlNwTCStjXuajb5l2m081YrUAsGkDeS4f6bFkhxf
         LgYanEGAVAZDM7tXJ4uncelLHxD5uCtIc4WK6TR5nFwduP87kQ1Dy2pxKJUEru1b+yVV
         yVIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Dn1s1OnqM766ROLY29Wi7jVidC52A92cp1/CyP/E9uk=;
        fh=8biNjBqYmh+o0Y7tuG/czS5YXr6M4bCCvXAWkBhWz28=;
        b=fVqSRzlaTND8FzS6mm3uQTrqdEgBzk0pk3kDuxk3Ej8PgL/XEERab+PskDA9BUur5Y
         oeuq5oLv8M/6yYNI/GC7uAIRBnGSpMrohdOxEZSJ7T8mjPst8aC2qjIogIpH+Sw2mctn
         eqEjZa9+RkCO8bnBTO6CVUOppa4Ch+ErGWZ9emiEcw3o/8wQGqMjqZaFJh0m7tZIJXgC
         o+QkyftsHc+oDjQmIMxQNUzFScF0PhLMEtyMf2z3f/jVSSO2gEBVOZlBM2tmTg4OrtcI
         ffUjGN9pburfjl2hg07mj80uoMh0oUZJaAaq8Q6mpWMdxJPLrxq73w+gOLZzfEWmZHBE
         Sl0A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=iKcVqIgx;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-717c614d5ccsi553247b3.4.2025.07.10.01.03.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 01:03:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id 41be03b00d2f7-b1fd59851baso598355a12.0
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 01:03:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVJ3UetKxSZhupC+Qle7ugTtipieUvREgW3MRCzbdFFkZN9OYzwa202mMfUwNz2llrcU+jQwRB3CeE=@googlegroups.com
X-Gm-Gg: ASbGncvVKG3UYzlmgA3m7dDp6/Wd3bqy348mTsLYJR9CLlxHmr0cGZTzYU3xcdYdy0C
	tkZmVyl88mlAK40rJgSYHun7JRtZ4kdIhNIOMkdjTP2+MSuL/xb+mkQ0xRURV0MaWAOqLKo2yTx
	IAbhqlfqjlSKT6KqSqUm8EiEAUa1l3oxvaDqwXGId3K1WfzMzmhd02u+CNmJWP4ELLcGciAGloJ
	ed9Qeo5rffb
X-Received: by 2002:a17:90b:5345:b0:31a:bc78:7fe1 with SMTP id
 98e67ed59e1d1-31c3c2d4748mr4761227a91.18.1752134590559; Thu, 10 Jul 2025
 01:03:10 -0700 (PDT)
MIME-Version: 1.0
References: <686ea951.050a0220.385921.0016.GAE@google.com> <aG7pfqqhk47YXFNz@dread.disaster.area>
In-Reply-To: <aG7pfqqhk47YXFNz@dread.disaster.area>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 10 Jul 2025 10:02:59 +0200
X-Gm-Features: Ac12FXy6k_Uf27DJHMFvYT-oDiqLCYYE_boXGcb3Fh1zipBMh0T2QL10IhXu33M
Message-ID: <CANp29Y700diEaeHd6bHksAL_60D+vJD-95EqcveqMME0smNJnw@mail.gmail.com>
Subject: Re: [syzbot] [xfs?] possible deadlock in xfs_ilock_attr_map_shared (2)
To: Dave Chinner <david@fromorbit.com>
Cc: syzbot <syzbot+3470c9ffee63e4abafeb@syzkaller.appspotmail.com>, cem@kernel.org, 
	linux-kernel@vger.kernel.org, linux-xfs@vger.kernel.org, 
	syzkaller-bugs@googlegroups.com, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=iKcVqIgx;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::52c as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

Hi Dave,

On Thu, Jul 10, 2025 at 12:13=E2=80=AFAM 'Dave Chinner' via syzkaller-bugs
<syzkaller-bugs@googlegroups.com> wrote:
>
> On Wed, Jul 09, 2025 at 10:39:29AM -0700, syzbot wrote:
> > Hello,
> >
> > syzbot found the following issue on:
> >
> > HEAD commit:    733923397fd9 Merge tag 'pwm/for-6.16-rc6-fixes' of git:=
//g..
> > git tree:       upstream
> > console output: https://syzkaller.appspot.com/x/log.txt?x=3D13f53582580=
000
> > kernel config:  https://syzkaller.appspot.com/x/.config?x=3Db309c907eaa=
b29da
> > dashboard link: https://syzkaller.appspot.com/bug?extid=3D3470c9ffee63e=
4abafeb
> > compiler:       Debian clang version 20.1.7 (++20250616065708+6146a88f6=
049-1~exp1~20250616065826.132), Debian LLD 20.1.7
> >
> > Unfortunately, I don't have any reproducer for this issue yet.
> >
> > Downloadable assets:
> > disk image (non-bootable): https://storage.googleapis.com/syzbot-assets=
/d900f083ada3/non_bootable_disk-73392339.raw.xz
> > vmlinux: https://storage.googleapis.com/syzbot-assets/be7feaa77b8c/vmli=
nux-73392339.xz
> > kernel image: https://storage.googleapis.com/syzbot-assets/a663b3e31463=
/bzImage-73392339.xz
> >
> > IMPORTANT: if you fix the issue, please add the following tag to the co=
mmit:
> > Reported-by: syzbot+3470c9ffee63e4abafeb@syzkaller.appspotmail.com
> >
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D
> > WARNING: possible circular locking dependency detected
> > 6.16.0-rc5-syzkaller-00038-g733923397fd9 #0 Not tainted
> > ------------------------------------------------------
> > syz.0.0/5339 is trying to acquire lock:
> > ffffffff8e247500 (fs_reclaim){+.+.}-{0:0}, at: might_alloc include/linu=
x/sched/mm.h:318 [inline]
> > ffffffff8e247500 (fs_reclaim){+.+.}-{0:0}, at: prepare_alloc_pages+0x15=
3/0x610 mm/page_alloc.c:4727
> >
> > but task is already holding lock:
> > ffff888053415098 (&xfs_nondir_ilock_class){++++}-{4:4}, at: xfs_ilock_a=
ttr_map_shared+0x92/0xd0 fs/xfs/xfs_inode.c:85
> >
> > which lock already depends on the new lock.
> >
> >
> > the existing dependency chain (in reverse order) is:
> >
> > -> #1 (&xfs_nondir_ilock_class){++++}-{4:4}:
> >        lock_acquire+0x120/0x360 kernel/locking/lockdep.c:5871
> >        down_write_nested+0x9d/0x200 kernel/locking/rwsem.c:1693
> >        xfs_reclaim_inode fs/xfs/xfs_icache.c:1045 [inline]
> >        xfs_icwalk_process_inode fs/xfs/xfs_icache.c:1737 [inline]
> >        xfs_icwalk_ag+0x12c5/0x1ab0 fs/xfs/xfs_icache.c:1819
> >        xfs_icwalk fs/xfs/xfs_icache.c:1867 [inline]
> >        xfs_reclaim_inodes_nr+0x1e3/0x260 fs/xfs/xfs_icache.c:1111
> >        super_cache_scan+0x41b/0x4b0 fs/super.c:228
> >        do_shrink_slab+0x6ec/0x1110 mm/shrinker.c:437
> >        shrink_slab+0xd74/0x10d0 mm/shrinker.c:664
> >        shrink_one+0x28a/0x7c0 mm/vmscan.c:4939
> >        shrink_many mm/vmscan.c:5000 [inline]
> >        lru_gen_shrink_node mm/vmscan.c:5078 [inline]
> >        shrink_node+0x314e/0x3760 mm/vmscan.c:6060
> >        kswapd_shrink_node mm/vmscan.c:6911 [inline]
> >        balance_pgdat mm/vmscan.c:7094 [inline]
> >        kswapd+0x147c/0x2830 mm/vmscan.c:7359
> >        kthread+0x70e/0x8a0 kernel/kthread.c:464
> >        ret_from_fork+0x3f9/0x770 arch/x86/kernel/process.c:148
> >        ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:245
> >
> > -> #0 (fs_reclaim){+.+.}-{0:0}:
> >        check_prev_add kernel/locking/lockdep.c:3168 [inline]
> >        check_prevs_add kernel/locking/lockdep.c:3287 [inline]
> >        validate_chain+0xb9b/0x2140 kernel/locking/lockdep.c:3911
> >        __lock_acquire+0xab9/0xd20 kernel/locking/lockdep.c:5240
> >        lock_acquire+0x120/0x360 kernel/locking/lockdep.c:5871
> >        __fs_reclaim_acquire mm/page_alloc.c:4045 [inline]
> >        fs_reclaim_acquire+0x72/0x100 mm/page_alloc.c:4059
> >        might_alloc include/linux/sched/mm.h:318 [inline]
> >        prepare_alloc_pages+0x153/0x610 mm/page_alloc.c:4727
> >        __alloc_frozen_pages_noprof+0x123/0x370 mm/page_alloc.c:4948
> >        alloc_pages_mpol+0x232/0x4a0 mm/mempolicy.c:2419
> >        alloc_frozen_pages_noprof mm/mempolicy.c:2490 [inline]
> >        alloc_pages_noprof+0xa9/0x190 mm/mempolicy.c:2510
> >        get_free_pages_noprof+0xf/0x80 mm/page_alloc.c:5018
> >        __kasan_populate_vmalloc mm/kasan/shadow.c:362 [inline]
> >        kasan_populate_vmalloc+0x33/0x1a0 mm/kasan/shadow.c:417
> >        alloc_vmap_area+0xd51/0x1490 mm/vmalloc.c:2084
> >        __get_vm_area_node+0x1f8/0x300 mm/vmalloc.c:3179
> >        __vmalloc_node_range_noprof+0x301/0x12f0 mm/vmalloc.c:3845
> >        __vmalloc_node_noprof mm/vmalloc.c:3948 [inline]
> >        __vmalloc_noprof+0xb1/0xf0 mm/vmalloc.c:3962
> >        xfs_buf_alloc_backing_mem fs/xfs/xfs_buf.c:239 [inline]
>
> KASAN is still failing to pass through __GFP_NOLOCKDEP allocation
> context flags. It's also failing to pass through other important
> context restrictions like GFP_NOFS, GFP_NOIO, __GFP_NOFAIL, etc.
>
> Fundamentally, it's a bug to be doing nested GFP_KERNEL allocations
> inside an allocation context that has a more restricted allocation
> context...
>
> #syz set subsystems: kasan

Thanks for the analysis!

I've added the kasan-dev list to Cc.

--=20
Aleksandr

>
> --
> Dave Chinner
> david@fromorbit.com
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ANp29Y700diEaeHd6bHksAL_60D%2BvJD-95EqcveqMME0smNJnw%40mail.gmail.com.
