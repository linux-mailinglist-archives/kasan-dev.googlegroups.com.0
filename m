Return-Path: <kasan-dev+bncBCQJ32NM6AJBBKUZUOPAMGQEVXLTGRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id B97E16730A1
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Jan 2023 05:53:00 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id o19-20020a17090a9f9300b002296c011686sf502554pjp.8
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Jan 2023 20:53:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674103979; cv=pass;
        d=google.com; s=arc-20160816;
        b=o7nE0IHzD2KJAZxLFHS94Dc9eVBTL1yGGXxNsEFC+5Vs/w8PmF6L/2ppCYHv/y3kmV
         rT2u3eEQd5R9XS5Mk6haCNeWuJe9vqp4JYw0YacIMRfIV1dvVCWFGk+OZChlqVfyo4Tg
         cMyT4xCOJJaXLn9Zk1cdFxo21L1enETTlG9/IDI7VlZrIp8phBzyuTYtI7XpyUp4X08E
         AY0OiZFhL9ipg8KQgyKBTDNLN+e2P0GFg9UvuUHG8t7xJj+rZ/JsvE4Y1G8W/rHHymyT
         Bp/xmQnm7jXkC/zoSgj0P8XZ2VWR9qkUS4W9I0tLl9sssJs939l6jyB/XIainfhcN/WC
         6xSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=a10uDmbvEXhumu7uAs3iJyGTJ1GAXelWTtO6Z7Sj6Ns=;
        b=bq2c1ZCv1vDzqpMZMyd6Yp257pSyFOhUZ8v0L+nFTP4TQIOB7GnG3boEl2tZx11jOf
         3s+ju1NJ3Taw+mSXoVMWQZWBrIHKsIOIgMnEfG4MUNkGF+VQtLArCN+Og2MyI72VSc4h
         kOVloAOms5z0OIP6QHDazZ3UEEikB0kw5y5jrMWK3JWwBQoa4Tqi93zlzMEAw1HxMvtn
         aFQAePWilaDAoaWNSYl7dSom6yRURq1ODuEot28YD33e/K/RP+G7zIGlNy62E89U1iN6
         zjDYJTVXbdeMm/47g2cMlnLgM+OAKe2Som/PuQf1/3dzQKJpulciCwSm/z3Br2l/IkbL
         U1iw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@fromorbit-com.20210112.gappssmtp.com header.s=20210112 header.b="ldYd/bdZ";
       spf=neutral (google.com: 2607:f8b0:4864:20::431 is neither permitted nor denied by best guess record for domain of david@fromorbit.com) smtp.mailfrom=david@fromorbit.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=a10uDmbvEXhumu7uAs3iJyGTJ1GAXelWTtO6Z7Sj6Ns=;
        b=Yy4P0odPYzwJn2onVPDPxYAYQVnmTsrgwEk0hiCQqPthUsbzs/1Ig3ySaeNMsXzgxa
         RUChm+YqVc/I5SxQwjQ+ZmXDR6QJfnMGGkGk9hk+Pn/E+JGOCRM4nUEtsAeznBJ5fOjK
         AnK8pid647Sy69RrsIt+NHd9qHqs4nt/nzBo7ecN4pSmDiQ1XVIULv23PfiV/ijxAJ2O
         PCiVgf5b6Jdoq9zagM2QgPW2exm0M6B7hkLuJ53MmaAg2PPS9LggxgbB8Et+fuOZta97
         Gibbl9wvFY3E6RzD0/3AtwpgujG7VHKPFMvDL0fBf0rYjuF0hoPMQ2qhauJ1dUnbMGvn
         8VPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=a10uDmbvEXhumu7uAs3iJyGTJ1GAXelWTtO6Z7Sj6Ns=;
        b=mJOsHUr1QA6nEw6vX/si3G22zyyEdjtRJ51r5X0UQve/uVpNbrtuW7CtNPf6NU8fsT
         DbGcBnKucGIZKJJvA11uNJpoTNRPckm+N0YJeldBEUw13ofg60oEMXy+4W5ZMwD5vh0t
         shI18xQDAt8PGFy8ozq5qhd0c9/LpybXIMa6IGtnnoSkHoV54p07PslAzwWyPn9x+Wn/
         bjG1Ji8bO63mcO/Te2YpYTLbwv1IFeApaABMneKFV8fTvYS7dqFfgWWKyfvzfBBL17i1
         GzKUiYECoRshS8G83BeDZ0MSzUrzU56JBfkeuhFCOYLXtZzssIUDcsUBWfNErZ8tzv1k
         0Wpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kr6yQtcGRRy56By73K35RfLGeaeCN79kzgyH+RnWAC4dMG3WBBP
	8plWH2HEW4DPExzkJZfevAM=
X-Google-Smtp-Source: AMrXdXs4lcg2elrZqOcG3Bd/Zm+oizY53qzVR2YgdIuPPQcxWM8VTIzo9vLj5SnEIPJfLd3B1lZWuQ==
X-Received: by 2002:a17:90a:3f86:b0:229:6b20:2418 with SMTP id m6-20020a17090a3f8600b002296b202418mr1069878pjc.117.1674103978996;
        Wed, 18 Jan 2023 20:52:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:3801:b0:227:1b53:908c with SMTP id
 w1-20020a17090a380100b002271b53908cls4177156pjb.1.-pod-canary-gmail; Wed, 18
 Jan 2023 20:52:58 -0800 (PST)
X-Received: by 2002:a17:90a:7f8a:b0:229:3d3a:49cb with SMTP id m10-20020a17090a7f8a00b002293d3a49cbmr10429667pjl.4.1674103977971;
        Wed, 18 Jan 2023 20:52:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674103977; cv=none;
        d=google.com; s=arc-20160816;
        b=pY88jd+AdnRLzs+pm91/OmevDvNxkrWLxcIdNSP2NTLmWmLHpLtQ/LfMxSg7GS+R7v
         45U5c31D1aW52EVdA+nk2yKu0Zhv9nJHWY3HsFSQ2mmnEbBN1Yky+qY9MXHAGkqoSL/4
         OVRJw6+ijTBHxivsdHIeRKrYwqD1CCf5LMtZhWxL3wWrggK3YChdLEZit1AWOqS4gzd3
         1fhLeiuIJqYfTQEItuwco6dXt2k3sKruGA8/KosZVm4+rOc4J3vog6hKTu8WhF7rZ3jT
         jaj19CenwP+4pqSynpIF+86qQN/IJV2JsDATzqsgNBEZkTlGXUAkFG9jckOERm/Lvs2g
         OZGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=j62/8OeG5uBY+uaMfuKtbVcz9TiZfyS9W41aQ0k/c2Q=;
        b=UR2rLLMEquNNyBDiYsiEGWwtDhWhXbAuAH+cct09QhfD/sf82v55rYV1qStzygesR2
         hRKxD3irnM39A8GGsACQNWRv892mRKhiHIq2kzZ01el1aHw85K9escEawhImP6ArSlXp
         Lfeo9zGND9pciRgCwnrz0tbHjAgiNYSWHhMx1tfV0kaup+afoMxL80iFFa7aZw9Ido6a
         4GenJ1prJW6o4U4n2wBNV2anKb6kvV7iMSdwjlkR1XiAxFpYIITVpNlXTZigihn9fESu
         57paXXGA9JK8AZ5m8dEZMK0+1F9bp9Jpf7f4qNGkFFP5eXT/Qz+6UpJ21VSY2bbBj0wc
         3kNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@fromorbit-com.20210112.gappssmtp.com header.s=20210112 header.b="ldYd/bdZ";
       spf=neutral (google.com: 2607:f8b0:4864:20::431 is neither permitted nor denied by best guess record for domain of david@fromorbit.com) smtp.mailfrom=david@fromorbit.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id gt7-20020a17090af2c700b00219b6acf453si327550pjb.3.2023.01.18.20.52.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Jan 2023 20:52:57 -0800 (PST)
Received-SPF: neutral (google.com: 2607:f8b0:4864:20::431 is neither permitted nor denied by best guess record for domain of david@fromorbit.com) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id 20so583654pfu.13
        for <kasan-dev@googlegroups.com>; Wed, 18 Jan 2023 20:52:57 -0800 (PST)
X-Received: by 2002:a05:6a00:21c9:b0:58d:f607:5300 with SMTP id t9-20020a056a0021c900b0058df6075300mr3984784pfj.8.1674103977488;
        Wed, 18 Jan 2023 20:52:57 -0800 (PST)
Received: from dread.disaster.area (pa49-186-146-207.pa.vic.optusnet.com.au. [49.186.146.207])
        by smtp.gmail.com with ESMTPSA id 134-20020a62148c000000b0056bc30e618dsm22979484pfu.38.2023.01.18.20.52.56
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Jan 2023 20:52:56 -0800 (PST)
Received: from dave by dread.disaster.area with local (Exim 4.92.3)
	(envelope-from <david@fromorbit.com>)
	id 1pIMuz-004okg-Lr; Thu, 19 Jan 2023 15:52:53 +1100
Date: Thu, 19 Jan 2023 15:52:53 +1100
From: Dave Chinner <david@fromorbit.com>
To: Damien Le Moal <damien.lemoal@opensource.wdc.com>
Cc: "linux-xfs@vger.kernel.org" <linux-xfs@vger.kernel.org>,
	Dave Chinner <dchinner@redhat.com>,
	"Darrick J. Wong" <djwong@kernel.org>, kasan-dev@googlegroups.com,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>
Subject: Re: Lockdep splat with xfs
Message-ID: <20230119045253.GI360264@dread.disaster.area>
References: <f9ff999a-e170-b66b-7caf-293f2b147ac2@opensource.wdc.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f9ff999a-e170-b66b-7caf-293f2b147ac2@opensource.wdc.com>
X-Original-Sender: david@fromorbit.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@fromorbit-com.20210112.gappssmtp.com header.s=20210112
 header.b="ldYd/bdZ";       spf=neutral (google.com: 2607:f8b0:4864:20::431 is
 neither permitted nor denied by best guess record for domain of
 david@fromorbit.com) smtp.mailfrom=david@fromorbit.com
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

[cc kasan list as this is a kasan bug]

On Thu, Jan 19, 2023 at 10:28:38AM +0900, Damien Le Moal wrote:
> I got the below kasan splat running on 6.2-rc3.
> 
> The machine is currently running some SMR & CMR drives benchmarks and xfs is
> used only for the rootfs (on an m.2 ssd) to log test results. So nothing special
> really exercising xfs.
> 
> My tests are still running (they take several days so I do not want to interrupt
> them) so I have not tried the latest Linus tree. Have you got reports of
> something similar ? Is that fixed already ? I did not dig into the issue :)
> 
> 
> ======================================================
> WARNING: possible circular locking dependency detected
> 6.2.0-rc3+ #1637 Not tainted
> ------------------------------------------------------
> kswapd0/177 is trying to acquire lock:
> ffff8881fe452118 (&xfs_dir_ilock_class){++++}-{3:3}, at:
> xfs_icwalk_ag+0x9d8/0x11f0 [xfs]
> 
> but task is already holding lock:
> ffffffff83b5d280 (fs_reclaim){+.+.}-{0:0}, at: balance_pgdat+0x760/0xf90
> 
> which lock already depends on the new lock.
> 
> 
> the existing dependency chain (in reverse order) is:
> 
> -> #1 (fs_reclaim){+.+.}-{0:0}:
>        fs_reclaim_acquire+0x122/0x170
>        __alloc_pages+0x1b3/0x690
>        __stack_depot_save+0x3b4/0x4b0
>        kasan_save_stack+0x32/0x40
>        kasan_set_track+0x25/0x30
>        __kasan_kmalloc+0x88/0x90
>        __kmalloc_node+0x5a/0xc0
>        xfs_attr_copy_value+0xf2/0x170 [xfs]

It's a false positive, and the allocation context it comes from
in XFS is documented as needing to avoid lockdep tracking because
this path is know to trigger false positive memory reclaim recursion
reports:

        if (!args->value) {
                args->value = kvmalloc(valuelen, GFP_KERNEL | __GFP_NOLOCKDEP);
                if (!args->value)
                        return -ENOMEM;
        }
        args->valuelen = valuelen;


XFS is telling the allocator not to track this allocation with
lockdep, and that is getting passed down through the allocator which
has not passed it to lockdep (correct behaviour!), but then KASAN is
trying to track the allocation and that needs to do a memory
allocation.  __stack_depot_save() is passed the gfp mask from the
allocation context so it has __GFP_NOLOCKDEP right there, but it
does:

        if (unlikely(can_alloc && !smp_load_acquire(&next_slab_inited))) {
                /*
                 * Zero out zone modifiers, as we don't have specific zone
                 * requirements. Keep the flags related to allocation in atomic
                 * contexts and I/O.
                 */
                alloc_flags &= ~GFP_ZONEMASK;
>>>>>>>         alloc_flags &= (GFP_ATOMIC | GFP_KERNEL);
                alloc_flags |= __GFP_NOWARN;
                page = alloc_pages(alloc_flags, STACK_ALLOC_ORDER);

It masks masks out anything other than GFP_ATOMIC and GFP_KERNEL
related flags. This drops __GFP_NOLOCKDEP on the floor, hence
lockdep tracks an allocation in a context we've explicitly said not
to track. Hence lockdep (correctly!) explodes later when the
false positive "lock inode in reclaim context" situation triggers.

This is a KASAN bug. It should not be dropping __GFP_NOLOCKDEP from
the allocation context flags.

-Dave.


>        xfs_attr_get+0x36a/0x4b0 [xfs]
>        xfs_get_acl+0x1a5/0x3f0 [xfs]
>        __get_acl.part.0+0x1d5/0x2e0
>        vfs_get_acl+0x11b/0x1a0
>        do_get_acl+0x39/0x520
>        do_getxattr+0xcb/0x330
>        getxattr+0xde/0x140
>        path_getxattr+0xc1/0x140
>        do_syscall_64+0x38/0x80
>        entry_SYSCALL_64_after_hwframe+0x46/0xb0
> 
> -> #0 (&xfs_dir_ilock_class){++++}-{3:3}:
>        __lock_acquire+0x2b91/0x69e0
>        lock_acquire+0x1a3/0x520
>        down_write_nested+0x9c/0x240
>        xfs_icwalk_ag+0x9d8/0x11f0 [xfs]
>        xfs_icwalk+0x4c/0xd0 [xfs]
>        xfs_reclaim_inodes_nr+0x148/0x1f0 [xfs]
>        super_cache_scan+0x3a5/0x500
>        do_shrink_slab+0x324/0x900
>        shrink_slab+0x376/0x4f0
>        shrink_node+0x80f/0x1ae0
>        balance_pgdat+0x6e2/0xf90
>        kswapd+0x312/0x9b0
>        kthread+0x29f/0x340
>        ret_from_fork+0x1f/0x30
> 
> other info that might help us debug this:
> 
>  Possible unsafe locking scenario:
> 
>        CPU0                    CPU1
>        ----                    ----
>   lock(fs_reclaim);
>                                lock(&xfs_dir_ilock_class);
>                                lock(fs_reclaim);
>   lock(&xfs_dir_ilock_class);
> 
>  *** DEADLOCK ***
> 
> 3 locks held by kswapd0/177:
>  #0: ffffffff83b5d280 (fs_reclaim){+.+.}-{0:0}, at: balance_pgdat+0x760/0xf90
>  #1: ffffffff83b2b8b0 (shrinker_rwsem){++++}-{3:3}, at: shrink_slab+0x237/0x4f0
>  #2: ffff8881a73cc0e0 (&type->s_umount_key#36){++++}-{3:3}, at:
> super_cache_scan+0x58/0x500
> 
> stack backtrace:
> CPU: 16 PID: 177 Comm: kswapd0 Not tainted 6.2.0-rc3+ #1637
> Hardware name: Supermicro AS -2014CS-TR/H12SSW-AN6, BIOS 2.4 02/23/2022
> Call Trace:
>  <TASK>
>  dump_stack_lvl+0x50/0x63
>  check_noncircular+0x268/0x310
>  ? print_circular_bug+0x440/0x440
>  ? check_path.constprop.0+0x24/0x50
>  ? save_trace+0x46/0xd00
>  ? add_lock_to_list+0x188/0x5a0
>  __lock_acquire+0x2b91/0x69e0
>  ? lockdep_hardirqs_on_prepare+0x410/0x410
>  lock_acquire+0x1a3/0x520
>  ? xfs_icwalk_ag+0x9d8/0x11f0 [xfs]
>  ? lock_downgrade+0x6d0/0x6d0
>  ? lock_is_held_type+0xdc/0x130
>  down_write_nested+0x9c/0x240
>  ? xfs_icwalk_ag+0x9d8/0x11f0 [xfs]
>  ? up_read+0x30/0x30
>  ? xfs_icwalk_ag+0x9d8/0x11f0 [xfs]
>  ? rcu_read_lock_sched_held+0x3f/0x70
>  ? xfs_ilock+0x252/0x2f0 [xfs]
>  xfs_icwalk_ag+0x9d8/0x11f0 [xfs]
>  ? xfs_inode_free_cowblocks+0x1f0/0x1f0 [xfs]
>  ? lock_is_held_type+0xdc/0x130
>  ? find_held_lock+0x2d/0x110
>  ? xfs_perag_get+0x2c0/0x2c0 [xfs]
>  ? rwlock_bug.part.0+0x90/0x90
>  xfs_icwalk+0x4c/0xd0 [xfs]
>  xfs_reclaim_inodes_nr+0x148/0x1f0 [xfs]
>  ? xfs_reclaim_inodes+0x1f0/0x1f0 [xfs]
>  super_cache_scan+0x3a5/0x500
>  do_shrink_slab+0x324/0x900
>  shrink_slab+0x376/0x4f0
>  ? set_shrinker_bit+0x230/0x230
>  ? mem_cgroup_calculate_protection+0x4a/0x4e0
>  shrink_node+0x80f/0x1ae0
>  balance_pgdat+0x6e2/0xf90
>  ? finish_task_switch.isra.0+0x218/0x920
>  ? shrink_node+0x1ae0/0x1ae0
>  ? lock_is_held_type+0xdc/0x130
>  kswapd+0x312/0x9b0
>  ? balance_pgdat+0xf90/0xf90
>  ? prepare_to_swait_exclusive+0x250/0x250
>  ? __kthread_parkme+0xc1/0x1f0
>  ? schedule+0x151/0x230
>  ? balance_pgdat+0xf90/0xf90
>  kthread+0x29f/0x340
>  ? kthread_complete_and_exit+0x30/0x30
>  ret_from_fork+0x1f/0x30
>  </TASK>
> 
> 
> -- 
> Damien Le Moal
> Western Digital Research
> 

-- 
Dave Chinner
david@fromorbit.com

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230119045253.GI360264%40dread.disaster.area.
