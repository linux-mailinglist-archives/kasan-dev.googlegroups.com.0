Return-Path: <kasan-dev+bncBAABBQVZXL5QKGQEUUIGTII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id D3354279602
	for <lists+kasan-dev@lfdr.de>; Sat, 26 Sep 2020 03:43:31 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id s13sf370381otq.15
        for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 18:43:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601084610; cv=pass;
        d=google.com; s=arc-20160816;
        b=C7SPTOM9r7/ORaB3enLRiDlS4uybEnWaYSb/hV8Yk0HCVQvNQpcX+I5RIl54i7VB5E
         ffPIP04hd8jtFCS26ey6yG31Dbhaa4Go0b+o5zX4NilpSKoPvDDmaRmeUWLY9pOjtEBp
         1Yrl0+sfnie9mG4ZYgQzFmyaRXzPKtNxGOf6e6qQBh1BdrqY7hGDrfz8qidQS1lNcFwr
         Ctupv0Xsi1CvLoYutU+C9jZW080XdJdhXUfX/bONaTjd4FHHnh1PR2e/DsKPYoQzwZAc
         tXmEHG4Hny+KThEACCTLZBYvtCQq+/78Mp+rTyBHQ0Ez5F1rgKmmyh5x+IpRqXUJtcwF
         i2gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:subject:to:from:date:sender:dkim-signature;
        bh=k5QBlDD+iXTVnyIEZgY7qieIKBHSik1ZDFsasUArvy4=;
        b=rCk9Mo1xrUT56h5v80Ci2mavclBpKyOVegTYm4uElVjFqVKi4H+6hzXclMRCaVOa7t
         57IuIRIa5StaopJfOjlhdntSxGSOzP/+ZRIpQyVvFVTWcDwEL+NjOzAlkmb/cYUY4adI
         oMHolg39wZ7gWteIgDPRZfNxgsa5KZ5GNk5KjxuRQJX3F/X8JmcTI+MHbSGbHHR8ePQf
         DnXiKqulCLUrJoFvXJYd+WLd8thA2e5tERrXphiF6FR+hYXJhyS/0IIsTLX3BW9AK97s
         67ZER07+LklBB2RZ9eOO6draH0fJ0N9z9GI6P66xMZw61+80W4Ji3YMJfMxQbkjLo548
         p3Mw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=rrGEiTes;
       spf=pass (google.com: domain of kuba@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:subject:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=k5QBlDD+iXTVnyIEZgY7qieIKBHSik1ZDFsasUArvy4=;
        b=GS3JVhFokepGfFpNdYcVJaCPt2EeeCl92yAc5y3KhAbjCs4+zkmB31Q7HzX6wRT1Ma
         tg5C8T8fLnfXXyaYm1kjLwLLbwv6nl+OnybGirz1Q0oOVCWGhiP2MYJJvolb0JpJiDZw
         KNh4LDauQCSsQWlRdrRexJotBLiLR2KM8QG24PZycr3XocQL+0b4EjdW2w1+sOdwZWMU
         ZSZLGX0wMxXqpzsj+jvbPaPcyvXr7F90jF76bdsx1+rx5JvNvsTksLu4qbk5legZa1EF
         T6Rgm1bVIxW/dm7nVfaqvleuPOXN7xjtkFNl5VoAMn9AN8hJwUY/3HOmqXMbSDrqCAiU
         K+RA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:subject:message-id
         :mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k5QBlDD+iXTVnyIEZgY7qieIKBHSik1ZDFsasUArvy4=;
        b=AMNY6CEbyTECUEJbcVmMXW4McxnFBBT+vhgV6xWcf7WFdpvDhdZjlMoSw9SmYCoSLI
         /i+flStcEH8cEEw6sfpMneIbzxMT1dBNIm3ubCD4u74QVkJOVfS8busYj4SOYR4dI9Pg
         o6I0j884sIUl/GYl5sF6JyytAaWuWlc+ZThLgbu5WzeeneeJUppYuHCGEP2l7540dPRw
         9V8/1a7Kka7Pg0VxHZRkG728gJPot8JoxIhC/laTlHZySXb6cN/nQUFWm7LUNQg3rrqC
         qmbC73JsntuXeBKFM161xRKEYlbkZRnsn+w5useHC7HpnnJIm10YDExxO1qhUBVB/XCd
         sQOQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533Z/QcLVJtznl/Y4en+ySovwFcejDbdznytQVccerAOd9t52lVq
	/yag20e4SZPUpAGT2NGKcx4=
X-Google-Smtp-Source: ABdhPJz2N/XT+JVk1sm111xPE2Q725XH5XrKbO54fGLaNhAWVtwgJgMLkwYq069wgtglnzOiRd3uCg==
X-Received: by 2002:a9d:7d89:: with SMTP id j9mr2120390otn.205.1601084610573;
        Fri, 25 Sep 2020 18:43:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:2208:: with SMTP id b8ls396844oic.9.gmail; Fri, 25 Sep
 2020 18:43:30 -0700 (PDT)
X-Received: by 2002:aca:4fd5:: with SMTP id d204mr222007oib.58.1601084610138;
        Fri, 25 Sep 2020 18:43:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601084610; cv=none;
        d=google.com; s=arc-20160816;
        b=tHGOuTWMQNVxdWwqP0qYFSzRNFVOCummHirUrVtZPw8B1RtBf12OQZ88ektq3LdAiv
         V3Cme6lPwsHUT9LIA5pSl6zRwRYFpdoLiB4YwL6EtBa/W0v6mY3+SMH7kYeSJkNPwA2V
         ZwXr2yeZv+4/f6ofucnSSYKiuEL5S0X+0ILj2Pvn09wBrIWHXMCXbpJlTerky1O1d8JH
         5oTtVIZRkLidmZzhp0mNMUcumgg/FtnQGh7oFlTsM6RJquChIC6yo5jXWuHAsW/M75f+
         ZEVdKOG1DnZdOQsHhaTSAvpxtamNx/fR3rMQoz0xPto/KPbyk4sUqLGpWmcwMBviX0et
         kYHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:subject:to:from
         :date:dkim-signature;
        bh=/+oIbpIhev/zbOpCoaLSOTML7oJ78mrwa6echOiyx+k=;
        b=0Z5cNB0ynM3vCvX6m/2yCe+dJBRA4ZRQEwls8S8ljF6r9IBX3QNw53MaeIFD02lFXg
         ZLQjJN778XF19gLnDMd3Q17tkSHI+q9AU46hyq7yCDPXERzYEAFxwz9+pvjXhrKFqJij
         4LH4s7YbYSffu7dp0mpziG04uYV928mKWDzI0hVSbO+rfqZXJq1yR6zuy+rdyXshAL/7
         KX/saMK+s72TGj55mUw9KGMCeiUPJ7dG4umjI5PT2JTHHp9bFZPLTKmL3LOWlrZbgSjk
         haBeKre7v40Ebl2/NuG+CVUAbnMB40ofP6g6pPUhI18+SQQRk/q4TgQpnXJS8ksQbDhl
         +tgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=rrGEiTes;
       spf=pass (google.com: domain of kuba@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=kuba@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o22si477907otk.2.2020.09.25.18.43.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 25 Sep 2020 18:43:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of kuba@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com (unknown [163.114.132.6])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 2518620936
	for <kasan-dev@googlegroups.com>; Sat, 26 Sep 2020 01:43:29 +0000 (UTC)
Date: Fri, 25 Sep 2020 18:43:27 -0700
From: Jakub Kicinski <kuba@kernel.org>
To: kasan-dev@googlegroups.com
Subject: KASAN vs RCU vs RT
Message-ID: <20200925184327.7257b6bb@kicinski-fedora-pc1c0hjn.dhcp.thefacebook.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: kuba@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=rrGEiTes;       spf=pass
 (google.com: domain of kuba@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=kuba@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Hi!

I couldn't find this being reported in a quick search, so let me ask.

With 5.9 I'm seeing a lot (well, once a boot) splats like the one below.

Is there a fix?

[  563.227358] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D
=E2=80=8B=E2=80=8B[  563.227722] [ BUG: Invalid wait context ]
=E2=80=8B=E2=80=8B[  563.228063] 5.9.0-rc6-02036-g7e4a153c60d2-dirty #267 N=
ot tainted
=E2=80=8B=E2=80=8B[  563.228606] -----------------------------
=E2=80=8B=E2=80=8B[  563.228950] NetworkManager/758 is trying to lock:
=E2=80=8B=E2=80=8B[  563.229344] ffffffffa74b5ad8 (depot_lock){-.-.}-{3:3},=
 at: stack_depot_save+0x1c5/0x3f0
=E2=80=8B=E2=80=8B[  563.229996] other info that might help us debug this:
=E2=80=8B=E2=80=8B[  563.230406] context-{5:5}
=E2=80=8B=E2=80=8B[  563.230641] 7 locks held by NetworkManager/758:
=E2=80=8B=E2=80=8B[  563.231006]  #0: ffff88804d6f00f0 (&f->f_pos_lock){+.+=
.}-{4:4}, at: __fdget_pos+0x71/0x80
=E2=80=8B=E2=80=8B[  563.231658]  #1: ffff88805692c450 (sb_writers#3){.+.+}=
-{0:0}, at: vfs_write+0x2a7/0x350
=E2=80=8B=E2=80=8B[  563.232290]  #2: ffffffffa7763b28 (rtnl_mutex){+.+.}-{=
4:4}, at: addrconf_sysctl_disable+0x186/0x350
=E2=80=8B=E2=80=8B[  563.232998]  #3: ffff888033e911a0 (&ndev->lock){++.-}-=
{3:3}, at: ipv6_mc_down+0x1d/0x150
=E2=80=8B=E2=80=8B[  563.233674]  #4: ffff88804f0f24c0 (&mc->mca_lock){+.-.=
}-{3:3}, at: igmp6_group_dropped+0xfa/0x550
=E2=80=8B=E2=80=8B[  563.234437]  #5: ffff888045688280 (_xmit_ETHER){+...}-=
{3:3}, at: dev_mc_del+0x1f/0x70
=E2=80=8B=E2=80=8B[  563.235119]  #6: ffff88805ae23890 (krc.lock){..-.}-{2:=
2}, at: kvfree_call_rcu+0x6c/0x380
=E2=80=8B=E2=80=8B[  563.235846] stack backtrace:
=E2=80=8B=E2=80=8B[  563.236146] CPU: 0 PID: 758 Comm: NetworkManager Not t=
ainted 5.9.0-rc6-02036-g7e4a153c60d2-dirty #267
=E2=80=8B=E2=80=8B[  563.236949] Hardware name: QEMU Standard PC (Q35 + ICH=
9, 2009), BIOS 1.13.0-2.fc32 04/01/2014
=E2=80=8B=E2=80=8B[  563.237685] Call Trace:
=E2=80=8B=E2=80=8B[  563.237948]  dump_stack+0xae/0xe8
=E2=80=8B=E2=80=8B[  563.238279]  __lock_acquire.cold+0x1b9/0x34d
=E2=80=8B=E2=80=8B[  563.238689]  ? lock_downgrade+0x3a0/0x3a0
=E2=80=8B=E2=80=8B[  563.239070]  ? stack_access_ok+0x3a/0x90
=E2=80=8B=E2=80=8B[  563.239510]  ? lockdep_hardirqs_on_prepare+0x260/0x260
=E2=80=8B=E2=80=8B[  563.239997]  ? entry_SYSCALL_64_after_hwframe+0x44/0xa=
9
=E2=80=8B=E2=80=8B[  563.240474]  lock_acquire+0x14f/0x5e0
=E2=80=8B=E2=80=8B[  563.240882]  ? stack_depot_save+0x1c5/0x3f0
=E2=80=8B=E2=80=8B[  563.241297]  ? lock_release+0x430/0x430
=E2=80=8B=E2=80=8B[  563.241693]  ? arch_stack_walk+0xa2/0xf0
=E2=80=8B=E2=80=8B[  563.242069]  _raw_spin_lock_irqsave+0x48/0x60
=E2=80=8B=E2=80=8B[  563.242484]  ? stack_depot_save+0x1c5/0x3f0
=E2=80=8B=E2=80=8B[  563.242868]  stack_depot_save+0x1c5/0x3f0
=E2=80=8B=E2=80=8B[  563.243242]  kasan_save_stack+0x32/0x40
=E2=80=8B=E2=80=8B[  563.243609]  ? kasan_save_stack+0x1b/0x40
=E2=80=8B=E2=80=8B[  563.243983]  ? __kasan_kmalloc.constprop.0+0xc2/0xd0
=E2=80=8B=E2=80=8B[  563.244431]  ? kmem_cache_alloc+0xee/0x2e0
=E2=80=8B=E2=80=8B[  563.244810]  ? fill_pool+0x211/0x320
=E2=80=8B=E2=80=8B[  563.245149]  ? __debug_object_init+0x7d/0x610
=E2=80=8B=E2=80=8B[  563.245551]  ? debug_object_activate+0x2bb/0x2e0
=E2=80=8B=E2=80=8B[  563.245968]  ? kvfree_call_rcu+0x7b/0x380
=E2=80=8B=E2=80=8B[  563.246342]  ? __hw_addr_del_entry+0x110/0x140
=E2=80=8B=E2=80=8B[  563.246766]  ? dev_mc_del+0x4c/0x70
=E2=80=8B=E2=80=8B[  563.247122]  ? igmp6_group_dropped+0x1ab/0x550
=E2=80=8B=E2=80=8B[  563.247551]  ? ipv6_mc_down+0x37/0x150
=E2=80=8B=E2=80=8B[  563.247921]  ? addrconf_ifdown.isra.0+0x924/0xaa0
=E2=80=8B=E2=80=8B[  563.248365]  ? dev_disable_change+0xb6/0x130
=E2=80=8B=E2=80=8B[  563.248781]  ? addrconf_sysctl_disable+0x227/0x350
=E2=80=8B=E2=80=8B[  563.249232]  ? proc_sys_call_handler.isra.0+0x172/0x31=
0
=E2=80=8B=E2=80=8B[  563.250571]  ? vfs_write+0x159/0x350
=E2=80=8B=E2=80=8B[  563.250922]  ? ksys_write+0xc9/0x160
=E2=80=8B=E2=80=8B[  563.251283]  ? do_syscall_64+0x33/0x40
=E2=80=8B=E2=80=8B[  563.251648]  ? entry_SYSCALL_64_after_hwframe+0x44/0xa=
9
=E2=80=8B=E2=80=8B[  563.252118]  ? mark_lock+0x90/0xb20
=E2=80=8B=E2=80=8B[  563.252472]  ? __lock_acquire+0x85c/0x2f50
=E2=80=8B=E2=80=8B[  563.252861]  ? mark_lock+0x90/0xb20
=E2=80=8B=E2=80=8B[  563.253207]  ? lockdep_hardirqs_on_prepare+0x260/0x260
=E2=80=8B=E2=80=8B[  563.253677]  ? __lock_acquire+0x85c/0x2f50
=E2=80=8B=E2=80=8B[  563.254067]  ? mark_lock+0x90/0xb20
=E2=80=8B=E2=80=8B[  563.254418]  ? kasan_unpoison_shadow+0x33/0x40
=E2=80=8B=E2=80=8B[  563.254833]  __kasan_kmalloc.constprop.0+0xc2/0xd0
=E2=80=8B=E2=80=8B[  563.255278]  kmem_cache_alloc+0xee/0x2e0
=E2=80=8B=E2=80=8B[  563.255659]  fill_pool+0x211/0x320
=E2=80=8B=E2=80=8B[  563.255999]  ? __list_del_entry_valid.cold+0x4f/0x4f
=E2=80=8B=E2=80=8B[  563.256458]  ? lockdep_hardirqs_on_prepare+0x260/0x260
=E2=80=8B=E2=80=8B[  563.256945]  ? __lock_acquire+0x85c/0x2f50
=E2=80=8B=E2=80=8B[  563.257333]  __debug_object_init+0x7d/0x610
=E2=80=8B=E2=80=8B[  563.257742]  ? debug_object_destroy+0x150/0x150
=E2=80=8B=E2=80=8B[  563.258163]  debug_object_activate+0x2bb/0x2e0
=E2=80=8B=E2=80=8B[  563.258580]  ? debug_object_assert_init+0x230/0x230
=E2=80=8B=E2=80=8B[  563.259058]  ? rwlock_bug.part.0+0x60/0x60
=E2=80=8B=E2=80=8B[  563.259478]  kvfree_call_rcu+0x7b/0x380
=E2=80=8B=E2=80=8B[  563.259848]  __hw_addr_del_entry+0x110/0x140
=E2=80=8B=E2=80=8B[  563.260256]  dev_mc_del+0x4c/0x70
=E2=80=8B=E2=80=8B[  563.260596]  igmp6_group_dropped+0x1ab/0x550
=E2=80=8B=E2=80=8B[  563.260998]  ? igmp6_send+0xa30/0xa30
=E2=80=8B=E2=80=8B[  563.261360]  ? mark_held_locks+0x65/0x90
=E2=80=8B=E2=80=8B[  563.261736]  ipv6_mc_down+0x37/0x150
=E2=80=8B=E2=80=8B[  563.262088]  addrconf_ifdown.isra.0+0x924/0xaa0
=E2=80=8B=E2=80=8B[  563.262514]  ? lock_acquire+0x14f/0x5e0
=E2=80=8B=E2=80=8B[  563.262883]  ? add_addr+0x1c0/0x1c0
=E2=80=8B=E2=80=8B[  563.263227]  ? lock_release+0x430/0x430
=E2=80=8B=E2=80=8B[  563.263603]  ? create_object.isra.0+0x212/0x530
=E2=80=8B=E2=80=8B[  563.264022]  ? lock_is_held_type+0xbb/0xf0
=E2=80=8B=E2=80=8B[  563.264415]  dev_disable_change+0xb6/0x130
=E2=80=8B=E2=80=8B[  563.264809]  ? addrconf_notify+0x1220/0x1220
=E2=80=8B=E2=80=8B[  563.265214]  ? mutex_trylock+0x169/0x180
=E2=80=8B=E2=80=8B[  563.265593]  ? addrconf_sysctl_disable+0x186/0x350
=E2=80=8B=E2=80=8B[  563.266057]  addrconf_sysctl_disable+0x227/0x350
=E2=80=8B=E2=80=8B[  563.266526]  ? dev_disable_change+0x130/0x130
=E2=80=8B=E2=80=8B[  563.266965]  ? dev_disable_change+0x130/0x130
=E2=80=8B=E2=80=8B[  563.267508]  ? _copy_from_user+0x8e/0xd0
=E2=80=8B=E2=80=8B[  563.267951]  proc_sys_call_handler.isra.0+0x172/0x310
=E2=80=8B=E2=80=8B[  563.268576]  ? proc_sys_lookup+0x2d0/0x2d0
=E2=80=8B=E2=80=8B[  563.269041]  ? avc_policy_seqno+0x28/0x30
=E2=80=8B=E2=80=8B[  563.269521]  ? lock_is_held_type+0xbb/0xf0
=E2=80=8B=E2=80=8B[  563.269923]  vfs_write+0x159/0x350
=E2=80=8B=E2=80=8B[  563.270261]  ksys_write+0xc9/0x160
=E2=80=8B=E2=80=8B[  563.270609]  ? __ia32_sys_read+0x50/0x50
=E2=80=8B=E2=80=8B[  563.270993]  ? ktime_get_coarse_real_ts64+0x103/0x120
=E2=80=8B=E2=80=8B[  563.271467]  ? ktime_get_coarse_real_ts64+0xaa/0x120
=E2=80=8B=E2=80=8B[  563.271938]  do_syscall_64+0x33/0x40
=E2=80=8B=E2=80=8B[  563.272305]  entry_SYSCALL_64_after_hwframe+0x44/0xa9
=E2=80=8B=E2=80=8B[  563.272789] RIP: 0033:0x7f6dd1c5faf7
=E2=80=8B=E2=80=8B[  563.273141] Code: c3 66 90 41 54 49 89 d4 55 48 89 f5 =
53 89 fb 48 83 ec 10 e8 fb fc ff ff 4c 89 e2 48 89 ee 89 df 41 89 c0 b8 01 =
00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 35 44 89 c7 48 89 44 24 08 e8 34 fd f=
f ff 48
=E2=80=8B=E2=80=8B[  563.274705] RSP: 002b:00007fffe513d7b0 EFLAGS: 0000029=
3 ORIG_RAX: 0000000000000001
=E2=80=8B=E2=80=8B[  563.275363] RAX: ffffffffffffffda RBX: 000000000000001=
8 RCX: 00007f6dd1c5faf7
=E2=80=8B=E2=80=8B[  563.275980] RDX: 0000000000000002 RSI: 00007fffe513d7e=
0 RDI: 0000000000000018
=E2=80=8B=E2=80=8B[  563.276593] RBP: 00007fffe513d7e0 R08: 000000000000000=
0 R09: 00007fffe513d230
=E2=80=8B=E2=80=8B[  563.277202] R10: 0000000000000000 R11: 000000000000029=
3 R12: 0000000000000002
=E2=80=8B=E2=80=8B[  563.277814] R13: 0000000000000018 R14: 000000000000000=
0 R15: 00007fffe513d7e0

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200925184327.7257b6bb%40kicinski-fedora-pc1c0hjn.dhcp.thefacebo=
ok.com.
