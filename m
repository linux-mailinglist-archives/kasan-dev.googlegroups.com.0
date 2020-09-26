Return-Path: <kasan-dev+bncBCMIZB7QWENRB2GMXP5QKGQENDRHPOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x639.google.com (mail-pl1-x639.google.com [IPv6:2607:f8b0:4864:20::639])
	by mail.lfdr.de (Postfix) with ESMTPS id 07984279762
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Sep 2020 08:57:46 +0200 (CEST)
Received: by mail-pl1-x639.google.com with SMTP id 10sf336228ple.19
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 23:57:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601103464; cv=pass;
        d=google.com; s=arc-20160816;
        b=bAxi3WAXwJYsYylp49ov7W9NlVgqdIJWRbV/Qrhb0AAVGQZtB/nSota2dQMTjFA+eS
         TjQBpAkMaLvEqfeRKkp+innsaps4O7svGcMB7w/a4NBhAPbANEwTldxpJt8Zx4u6Ajmg
         GYKdHgLqBrTGqBhAo7HIK9uiMC4UCdGwfDNXRass6Sztj3SmOrbHMfMZaIq238e6WUIR
         vjYuv0EOWcmfL8ejDNXsH6LpujRquhiCCmdRvZX3RmWa/+B/0pY9ZEQ87THlESJlucTu
         F/bqLLhP85okucQPKjtMPySIsxk8KebeYYnKZEj3C3IEDaH5+DvNiFUDhnF/J7gyYEu5
         gQyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=pqj4MViBAV0uK9HCsBGkaA+15GKpdppuJjrVolaRE44=;
        b=CX0gLKgI8Pc6MjWcV82elS7Tg9m4fhohM1yBPLQyfIm9n2t4Sxb681KOnf9XvzOZQZ
         5q1AHqL+H27SMZTIjWl0SBzetvxvb5govPwuU8hAAKwVy/98L9Sv4zyVA/Rjzc/4z/A2
         YkRljoYm3g9XnfqQGJVGAgQ6OcmpCvpVrLzEXXQiKt+JxaO/Euired8U7dvuNZsd+X+V
         mlOvU+JYBK20jrK3wwETv0o9VQtLv+xxuBpWX9bAsrUmdALYBmBBIc/+HeVZdyOPNigj
         z64O6dNlPwjNLA5HN4rpch5ZSOfgQQPThf0Zgn+bKzH4GtfiAEPYbm4VbhA7hDk7WQWc
         Sjaw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B6YOE4J2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pqj4MViBAV0uK9HCsBGkaA+15GKpdppuJjrVolaRE44=;
        b=VS15Yrq7DI6E4hH9w+1RzWSfNXC6L93Dp2b5b0z+qRdOwAgP4hVgWw7S7uOgdEfJDH
         d2ODt33j/urcAb2A9JEgb7iUOH++ylIGghshpWOVQwhfCf4jVg56PQQhqBOexAxq/swY
         I1y85XP2If8C01D/qUE/QffIxj2fhHbsqJaA5VkPwmcirGDM6W621MuZuAbKTVbn3FQI
         3DlPway3lQBFf8lPcqrZd1GMqizkJwh3IAnDzUtYiLDO4MYR6Cq7NQpgQClPHmb0jcAK
         msr6uBjF3krUr7tmHhHZzhzsFV1JVN8WxsMQoEX52ebuc77/PwskjBb4HSd2udap4Sj/
         /ynA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pqj4MViBAV0uK9HCsBGkaA+15GKpdppuJjrVolaRE44=;
        b=NAowOmBo6fq3PDK0Z47IiO11ytrhYI/S7Hmmhwzh1BxmGrfTCK6YbV5lJgWUPAo6Q2
         GTL+eMTkvNkSRPbDQEj//+gUww8CrBSkL7VO9tP+2xi9tvzNHkQ61g242CbKHhKieeuB
         IfVnRkoCrvQNY3pXVBARqtLFPEo710lqxOtJSRydpUd/7P4MX6kpoZdloAUKupG1TB81
         SyCJx/dvVlTj0ClV33sj2Hxl9qTcXUmYeQc78gnoqGyRABFheOudK0YgMElv3dxd8rQS
         W/NQFdtgLyAcwB/B7054Y9Pff4trwLMK8gs8ZbdwMWzsWbd5QeiNvCEl74Z+HaGtfIWr
         ZHcg==
X-Gm-Message-State: AOAM5333KESQ9LfMShLQqR0za4CbE0q6bDuSArM1JrhYI2f6Nwyn44k3
	OeBv4opFm5hlsO3SMfpY8r0=
X-Google-Smtp-Source: ABdhPJwGMAikQUNXp49g6jD2hOXY++N0h7Z1ujT4wBziXQpGF8OpqNjXEvrsGtmdY7R1QBFIDVruJg==
X-Received: by 2002:a63:4d48:: with SMTP id n8mr2024472pgl.70.1601103464746;
        Fri, 25 Sep 2020 23:57:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6381:: with SMTP id h1ls377294pgv.1.gmail; Fri, 25 Sep
 2020 23:57:44 -0700 (PDT)
X-Received: by 2002:a65:5903:: with SMTP id f3mr1958946pgu.119.1601103464201;
        Fri, 25 Sep 2020 23:57:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601103464; cv=none;
        d=google.com; s=arc-20160816;
        b=exYDoodtsBfx0Fm3VFAKuBW0Rs6yWN3Agr4f7L4RLuHElPf4A56uw/YKTurlisTbl5
         lVAuOLE0oB/26To4bM92JdQY13YTZDlnONiAaxdpbd+1Sp4bqX7tb2u3m4Vqzw7cIG8C
         kbqW74CxbBKYCTkm6rlmSIcTlteZ39uliHWHEO9+RZzJQ3ScmHhZqW6XBuCxTRUmBPeH
         QgW6Oymdp/Kh0A4wph8ExGsX3my2UjDvs3y1r61E6YOBH/yHUIcs9w30C+ziEa0IsNoI
         iCaEbgHjoPCXZp5NxXda7ubFZaHLPR8gcZEBymgcmBg0BY8al7qcyUPonqSH0dTuDDTW
         MEkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ElMbl9FGWVUm1Yrk69NIS8KWp3PMh9I8eCVmETr6sBI=;
        b=u4eYiQGzno8cVG1NE69ATnU0CZjxMMg0pwXw+KEzFd7oapaenZufqQSy2jl5JPGUML
         VCBWjkA4dwiZ4DYStlwILdnrefZBeJCCI4zZrIw5SxNji+j/Id9LOtgexFxJzz9CDjN6
         LpMVZ5hgWLYqHk4dbGS10rH5+kyk8hjXtgjXhF2cmUFhWX1bYidXS4hvH8F8zEVq8pY7
         eCrktdyxDsuWCOYqs1/YomL3DKHZbDmlWgeQsAGYdCVyVk5FzWxWKAi/t6GCH4STAeoX
         1R0tRicx/aTNVCHfG6jQ5Mk8ARj6FDgpqZ6mNAuZmj/NjnpJfi6efakxLLAWWqSINhpL
         VVaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=B6YOE4J2;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id m62si80992pgm.2.2020.09.25.23.57.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 25 Sep 2020 23:57:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id w12so5393671qki.6
        for <kasan-dev@googlegroups.com>; Fri, 25 Sep 2020 23:57:44 -0700 (PDT)
X-Received: by 2002:a37:9c4f:: with SMTP id f76mr3495736qke.250.1601103463438;
 Fri, 25 Sep 2020 23:57:43 -0700 (PDT)
MIME-Version: 1.0
References: <20200925184327.7257b6bb@kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com>
In-Reply-To: <20200925184327.7257b6bb@kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 26 Sep 2020 08:57:32 +0200
Message-ID: <CACT4Y+bK+0aeJb_2ULmouuH3+_OPOqMTtv1UOp2td73cqcZL-w@mail.gmail.com>
Subject: Re: KASAN vs RCU vs RT
To: Jakub Kicinski <kuba@kernel.org>
Cc: kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=B6YOE4J2;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::733
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

On Sat, Sep 26, 2020 at 3:43 AM Jakub Kicinski <kuba@kernel.org> wrote:
>
> Hi!
>
> I couldn't find this being reported in a quick search, so let me ask.
>
> With 5.9 I'm seeing a lot (well, once a boot) splats like the one below.
>
> Is there a fix?

Hi Jakub,

FWIW this is the first time I see this BUG. I don't remember it was
mentioned on kasan-dev before.

The commit that added this BUG was added in March 2020, so is not new...

> [  563.227358] =============================
> [  563.227722] [ BUG: Invalid wait context ]
> [  563.228063] 5.9.0-rc6-02036-g7e4a153c60d2-dirty #267 Not tainted
> [  563.228606] -----------------------------
> [  563.228950] NetworkManager/758 is trying to lock:
> [  563.229344] ffffffffa74b5ad8 (depot_lock){-.-.}-{3:3}, at: stack_depot_save+0x1c5/0x3f0
> [  563.229996] other info that might help us debug this:
> [  563.230406] context-{5:5}
> [  563.230641] 7 locks held by NetworkManager/758:
> [  563.231006]  #0: ffff88804d6f00f0 (&f->f_pos_lock){+.+.}-{4:4}, at: __fdget_pos+0x71/0x80
> [  563.231658]  #1: ffff88805692c450 (sb_writers#3){.+.+}-{0:0}, at: vfs_write+0x2a7/0x350
> [  563.232290]  #2: ffffffffa7763b28 (rtnl_mutex){+.+.}-{4:4}, at: addrconf_sysctl_disable+0x186/0x350
> [  563.232998]  #3: ffff888033e911a0 (&ndev->lock){++.-}-{3:3}, at: ipv6_mc_down+0x1d/0x150
> [  563.233674]  #4: ffff88804f0f24c0 (&mc->mca_lock){+.-.}-{3:3}, at: igmp6_group_dropped+0xfa/0x550
> [  563.234437]  #5: ffff888045688280 (_xmit_ETHER){+...}-{3:3}, at: dev_mc_del+0x1f/0x70
> [  563.235119]  #6: ffff88805ae23890 (krc.lock){..-.}-{2:2}, at: kvfree_call_rcu+0x6c/0x380
> [  563.235846] stack backtrace:
> [  563.236146] CPU: 0 PID: 758 Comm: NetworkManager Not tainted 5.9.0-rc6-02036-g7e4a153c60d2-dirty #267
> [  563.236949] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.13.0-2.fc32 04/01/2014
> [  563.237685] Call Trace:
> [  563.237948]  dump_stack+0xae/0xe8
> [  563.238279]  __lock_acquire.cold+0x1b9/0x34d
> [  563.238689]  ? lock_downgrade+0x3a0/0x3a0
> [  563.239070]  ? stack_access_ok+0x3a/0x90
> [  563.239510]  ? lockdep_hardirqs_on_prepare+0x260/0x260
> [  563.239997]  ? entry_SYSCALL_64_after_hwframe+0x44/0xa9
> [  563.240474]  lock_acquire+0x14f/0x5e0
> [  563.240882]  ? stack_depot_save+0x1c5/0x3f0
> [  563.241297]  ? lock_release+0x430/0x430
> [  563.241693]  ? arch_stack_walk+0xa2/0xf0
> [  563.242069]  _raw_spin_lock_irqsave+0x48/0x60
> [  563.242484]  ? stack_depot_save+0x1c5/0x3f0
> [  563.242868]  stack_depot_save+0x1c5/0x3f0
> [  563.243242]  kasan_save_stack+0x32/0x40
> [  563.243609]  ? kasan_save_stack+0x1b/0x40
> [  563.243983]  ? __kasan_kmalloc.constprop.0+0xc2/0xd0
> [  563.244431]  ? kmem_cache_alloc+0xee/0x2e0
> [  563.244810]  ? fill_pool+0x211/0x320
> [  563.245149]  ? __debug_object_init+0x7d/0x610
> [  563.245551]  ? debug_object_activate+0x2bb/0x2e0
> [  563.245968]  ? kvfree_call_rcu+0x7b/0x380
> [  563.246342]  ? __hw_addr_del_entry+0x110/0x140
> [  563.246766]  ? dev_mc_del+0x4c/0x70
> [  563.247122]  ? igmp6_group_dropped+0x1ab/0x550
> [  563.247551]  ? ipv6_mc_down+0x37/0x150
> [  563.247921]  ? addrconf_ifdown.isra.0+0x924/0xaa0
> [  563.248365]  ? dev_disable_change+0xb6/0x130
> [  563.248781]  ? addrconf_sysctl_disable+0x227/0x350
> [  563.249232]  ? proc_sys_call_handler.isra.0+0x172/0x310
> [  563.250571]  ? vfs_write+0x159/0x350
> [  563.250922]  ? ksys_write+0xc9/0x160
> [  563.251283]  ? do_syscall_64+0x33/0x40
> [  563.251648]  ? entry_SYSCALL_64_after_hwframe+0x44/0xa9
> [  563.252118]  ? mark_lock+0x90/0xb20
> [  563.252472]  ? __lock_acquire+0x85c/0x2f50
> [  563.252861]  ? mark_lock+0x90/0xb20
> [  563.253207]  ? lockdep_hardirqs_on_prepare+0x260/0x260
> [  563.253677]  ? __lock_acquire+0x85c/0x2f50
> [  563.254067]  ? mark_lock+0x90/0xb20
> [  563.254418]  ? kasan_unpoison_shadow+0x33/0x40
> [  563.254833]  __kasan_kmalloc.constprop.0+0xc2/0xd0
> [  563.255278]  kmem_cache_alloc+0xee/0x2e0
> [  563.255659]  fill_pool+0x211/0x320
> [  563.255999]  ? __list_del_entry_valid.cold+0x4f/0x4f
> [  563.256458]  ? lockdep_hardirqs_on_prepare+0x260/0x260
> [  563.256945]  ? __lock_acquire+0x85c/0x2f50
> [  563.257333]  __debug_object_init+0x7d/0x610
> [  563.257742]  ? debug_object_destroy+0x150/0x150
> [  563.258163]  debug_object_activate+0x2bb/0x2e0
> [  563.258580]  ? debug_object_assert_init+0x230/0x230
> [  563.259058]  ? rwlock_bug.part.0+0x60/0x60
> [  563.259478]  kvfree_call_rcu+0x7b/0x380
> [  563.259848]  __hw_addr_del_entry+0x110/0x140
> [  563.260256]  dev_mc_del+0x4c/0x70
> [  563.260596]  igmp6_group_dropped+0x1ab/0x550
> [  563.260998]  ? igmp6_send+0xa30/0xa30
> [  563.261360]  ? mark_held_locks+0x65/0x90
> [  563.261736]  ipv6_mc_down+0x37/0x150
> [  563.262088]  addrconf_ifdown.isra.0+0x924/0xaa0
> [  563.262514]  ? lock_acquire+0x14f/0x5e0
> [  563.262883]  ? add_addr+0x1c0/0x1c0
> [  563.263227]  ? lock_release+0x430/0x430
> [  563.263603]  ? create_object.isra.0+0x212/0x530
> [  563.264022]  ? lock_is_held_type+0xbb/0xf0
> [  563.264415]  dev_disable_change+0xb6/0x130
> [  563.264809]  ? addrconf_notify+0x1220/0x1220
> [  563.265214]  ? mutex_trylock+0x169/0x180
> [  563.265593]  ? addrconf_sysctl_disable+0x186/0x350
> [  563.266057]  addrconf_sysctl_disable+0x227/0x350
> [  563.266526]  ? dev_disable_change+0x130/0x130
> [  563.266965]  ? dev_disable_change+0x130/0x130
> [  563.267508]  ? _copy_from_user+0x8e/0xd0
> [  563.267951]  proc_sys_call_handler.isra.0+0x172/0x310
> [  563.268576]  ? proc_sys_lookup+0x2d0/0x2d0
> [  563.269041]  ? avc_policy_seqno+0x28/0x30
> [  563.269521]  ? lock_is_held_type+0xbb/0xf0
> [  563.269923]  vfs_write+0x159/0x350
> [  563.270261]  ksys_write+0xc9/0x160
> [  563.270609]  ? __ia32_sys_read+0x50/0x50
> [  563.270993]  ? ktime_get_coarse_real_ts64+0x103/0x120
> [  563.271467]  ? ktime_get_coarse_real_ts64+0xaa/0x120
> [  563.271938]  do_syscall_64+0x33/0x40
> [  563.272305]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
> [  563.272789] RIP: 0033:0x7f6dd1c5faf7
> [  563.273141] Code: c3 66 90 41 54 49 89 d4 55 48 89 f5 53 89 fb 48 83 ec 10 e8 fb fc ff ff 4c 89 e2 48 89 ee 89 df 41 89 c0 b8 01 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 35 44 89 c7 48 89 44 24 08 e8 34 fd ff ff 48
> [  563.274705] RSP: 002b:00007fffe513d7b0 EFLAGS: 00000293 ORIG_RAX: 0000000000000001
> [  563.275363] RAX: ffffffffffffffda RBX: 0000000000000018 RCX: 00007f6dd1c5faf7
> [  563.275980] RDX: 0000000000000002 RSI: 00007fffe513d7e0 RDI: 0000000000000018
> [  563.276593] RBP: 00007fffe513d7e0 R08: 0000000000000000 R09: 00007fffe513d230
> [  563.277202] R10: 0000000000000000 R11: 0000000000000293 R12: 0000000000000002
> [  563.277814] R13: 0000000000000018 R14: 0000000000000000 R15: 00007fffe513d7e0
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200925184327.7257b6bb%40kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbK%2B0aeJb_2ULmouuH3%2B_OPOqMTtv1UOp2td73cqcZL-w%40mail.gmail.com.
