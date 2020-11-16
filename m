Return-Path: <kasan-dev+bncBCMIZB7QWENRBPHQZD6QKGQEAEHBU3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id D76742B3E9B
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 09:28:45 +0100 (CET)
Received: by mail-pg1-x53e.google.com with SMTP id e3sf10438042pgu.1
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 00:28:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605515324; cv=pass;
        d=google.com; s=arc-20160816;
        b=OqBTBg04/Op/jzVpQ8OFeeODPxremMZon92Fn4uR59D/oFUI9hQYMs6ybFXkHH/mOn
         UuHD9d83Kq21ZEjQFPTV0x2TBsMHct8LEtATyY7LPu4zNZmyQIz12Z304C+xnOygpG8e
         4Ckxhfi36RRwmmuZiqrdKVeE86U/Gn/8QEVcFIzlK3lmP6eOJq5Wxx6cVNLo4ToEiJyM
         iPWJx+DMg9Gb3JBoZVa9jJZRvYZUSUjh2JYTxFVRlX2fPN4+RhZAwpnA/OAlmW0fhkob
         f2hpsdY2Vkk62tTFWb6ypGA+sUJS+9yZEterx0aCVxzxk0IZjn5EK1T1qDCPBCTRAgO8
         icFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2dStxpzeiWFHW5xA7gdNoOZcWHRawnFJYtwKUxHhy78=;
        b=Vq1VIKfkoIIhywrDRkYQdR5opQcJz4BJ3Hr22+jk2/SdwpPf+QoA3ADqpNdncK+rLx
         IqX3oNknsRLh/B7HbQLb0MKsrlM1i2uAlqCpR84Tj1ZhxyobDk0yzf8+z4YIXlhIygQZ
         ArfcEmljc1gLLEf6UwughAFQUW7d1mCtfDunFTIqGxtbe2kT1mN5T2vpNFABHE2/0ZuN
         4hJBg3FAo8cAsj429gNyyki388Va82zBPUpcbUcFyYblcERpnLhxUSBbTcYEqX2Oto1T
         0XA0f9TFtqnrGnU++hd4v81YN2HxkUH4ADy4aab22SP+Y08FtauhPdS5WOXIWM0JHqFr
         VpmA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hcdN1geX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2dStxpzeiWFHW5xA7gdNoOZcWHRawnFJYtwKUxHhy78=;
        b=BIEnnX2Y7dBO1/c7AbVXlf/paVqjVj41E1Nb35ngHXv2Pagi2ih6IH1eWUsNws60ag
         EzsjBerrdUnd05cmF+rMjdrLDhuM623T2eLFLmn0qGXi1L60n7Onz97YVJeH2gIv/bnF
         sGLKEy7NJYDaro9lZFq1poT7P8uWVk/FX2n2rSOw9xDpItLQubMtCnn0CO2ODqyGZW9/
         J31g0HhapoaWNVVm3hSND/SmAGOnL3DxW+1C5QlX49Xff+fi6qCU/IqsFgH/9ABKFw7q
         qWuXaOFl0Cw0+bUjJ+ZnJ3deTIOpfdAC/2ZCiP9WkFZ7CgfW2PpJ4Y6EjbbgrRGskSDm
         lS9Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2dStxpzeiWFHW5xA7gdNoOZcWHRawnFJYtwKUxHhy78=;
        b=ozaVdNYpljGDHHMm/AQQyHvQx/iUxrDgG5daMiTuWAVfhjqvZ6bkyUhvLz6pOXUYvH
         AxT3hmVpXdY4DV2Wr3efomo+EFvO5xiBJ0UuVT85NXv5f1ekB0oO9wovcIatnHHLz6dn
         PRdiMcr+WH39RcYtS18LUcabOaDVdfkcGQa2no7LvGW64Cwb80JXNgL7Q6KcW7tB3QPe
         udKFt2b6r3QoM0qSx9daTp11fw9ixgWBqir/oA8s0JpbHjM1q/EZ7FFGLLSnx81Vir1g
         VVbFz4xB4rpi+v2I5dsjwyOMVvfB53ILhy0ogKi03A6eGKK+PUo/Af+bEJ4PPY+MNd45
         EWTQ==
X-Gm-Message-State: AOAM5336y3nBUr/f0dzYSRbo0puEvp87v3SDv3enPoPuscnR+BwjmBH/
	YEyj6y5/t698/sSeAbgr+vA=
X-Google-Smtp-Source: ABdhPJyzRQcsqsVcyMxlLxYIJPCZ0gZMXAATY3wdhdsTd0D0lfezyx1GsFOGh62TK9cgP0NGbk0VEQ==
X-Received: by 2002:a17:90b:1106:: with SMTP id gi6mr15651336pjb.70.1605515324639;
        Mon, 16 Nov 2020 00:28:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a47:: with SMTP id x7ls3764909plv.1.gmail; Mon, 16
 Nov 2020 00:28:44 -0800 (PST)
X-Received: by 2002:a17:90a:cc0b:: with SMTP id b11mr14628752pju.97.1605515323846;
        Mon, 16 Nov 2020 00:28:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605515323; cv=none;
        d=google.com; s=arc-20160816;
        b=mogX4/5FhwGtd+Nq9gnIS32FK/wnwi4HCjCQvJTNTO+WFtyfP0tGSl3Fq+PfgLCjsT
         k3BkmyQ+DhmmfAwNyqxYCcqyHgqVt2AS78B8fHJ04vKg3XnDMbGmCiPnorDQIQjX+ghe
         QBCraXN+V4rCJc9q3AMyIc3e9+NC0aBKU14Ux665pgzhRdx5wxAmedCzM9wqYK+jnlyv
         2cZlP8V+mdnwLZ477pcNuC5o49VCq+kCXMuJ5XOjkPnJU0pSNOcnIcS1gp4mc31wLZV9
         5UBciESTTBv/a0BWE7F2XCyXx5yPddN94kjEz7d5vzEzVfK/6lf6TkwBgMSgmQtma8hM
         cAcg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=wHNwi87I8mu2yoDqnGm+Ng68SFloTCHjyLT3M1GoBFg=;
        b=bbnpoSpSYsde1/kkf9X4bE164jOgpeuMdHWzU6la0nGLCarCevKmN7Kn4JFJ1VvH+B
         dZJx9nyGnY5pSu33/uxrtC26YuJNFwB6F0Fi2XKYr1RIqdDLmy4GmcLxJ2z9MAwAIIls
         hgw+A/gQ3Mv7XuNkOE3xpMvqiIFL9cJrKpZ8KCyMvSyIiH4eeHMWeAIarY4BFiVyWZF7
         oZ7dAC5QKk2014NjOZiHfwYb1+/8QGrfrQ1SSXxvDXN5IjAMSua7H6a4yMmyTA+MgHMU
         9cQ8vZpPtn6OSk5rFWkd8xMmKJ4xoKfEJK+g8GQ+8Nq1suEFrIdPlfK6vT2as7fdzj4R
         k9IA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hcdN1geX;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id lw12si1024800pjb.1.2020.11.16.00.28.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 16 Nov 2020 00:28:43 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id b11so8401534qvr.9
        for <kasan-dev@googlegroups.com>; Mon, 16 Nov 2020 00:28:43 -0800 (PST)
X-Received: by 2002:a0c:e911:: with SMTP id a17mr14538647qvo.18.1605515322660;
 Mon, 16 Nov 2020 00:28:42 -0800 (PST)
MIME-Version: 1.0
References: <64637dc5-a480-4ae2-903e-9d70a7fdff98n@googlegroups.com>
In-Reply-To: <64637dc5-a480-4ae2-903e-9d70a7fdff98n@googlegroups.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 16 Nov 2020 09:28:30 +0100
Message-ID: <CACT4Y+bLDd8n1K9FevEUprki9J1rR=xv6cnCvsaOGZNUsKhuAQ@mail.gmail.com>
Subject: Re: KMSAN: WARNING at drivers/gpu/drm/drm_gem_vram_helper.c:284 drm_gem_vram_offset
To: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
Cc: kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hcdN1geX;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f42
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

On Mon, Nov 16, 2020 at 6:51 AM mudongl...@gmail.com
<mudongliangabcd@gmail.com> wrote:
>
> Hi all,
>
> I built the kmsan with github kmsan repo HEAD, however, when I leveraged syzkaller to fuzz this kernel image, the VMs is always broken with the following WARNING report:
>
> ```
> [   18.093341][    T1] ------------[ cut here ]------------
> [   18.093419][    T1] WARNING: CPU: 1 PID: 1 at drivers/gpu/drm/drm_gem_vram_helper.c:284 drm_gem_vram_offset+0x128/0x140
> [   18.093431][    T1] Modules linked in:
> [   18.093472][    T1] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc1 #2
> [   18.093489][    T1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1 04/01/2014
> [   18.093532][    T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140
> [   18.093574][    T1] Code: 48 c7 c3 ed ff ff ff 31 c0 31 c9 eb b4 8b 7d d4 e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e fc 4d 85 ff 0f 85 6e ff ff ff <0f> 0b 31 c0 31 c9 31 db eb 8d 8b 7d d4 e8 96 78 1e fc e9 67 ff ff
> [   18.093594][    T1] RSP: 0000:ffff8880125a6718 EFLAGS: 00010246
> [   18.093622][    T1] RAX: 0000000000000000 RBX: ffff8880155efd80 RCX: 00000000151efd80
> [   18.093645][    T1] RDX: ffff8880151efd80 RSI: 0000000000000040 RDI: ffff8880155efd80
> [   18.093669][    T1] RBP: ffff8880125a6748 R08: ffffea000000000f R09: ffff8880bffd2000
> [   18.093691][    T1] R10: 0000000000000004 R11: 00000000ffffffff R12: ffff8880155efc00
> [   18.093711][    T1] R13: 0000000000000000 R14: ffff8880125b0a10 R15: 0000000000000000
> [   18.093736][    T1] FS:  0000000000000000(0000) GS:ffff8880bfd00000(0000) knlGS:0000000000000000
> [   18.093757][    T1] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> [   18.093777][    T1] CR2: 0000000000000000 CR3: 0000000010229001 CR4: 0000000000770ee0
> [   18.093797][    T1] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000
> [   18.093816][    T1] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400
> [   18.093828][    T1] PKRU: 55555554
> [   18.093839][    T1] Call Trace:
> [   18.093886][    T1]  bochs_pipe_enable+0x16f/0x3f0
> [   18.093935][    T1]  drm_simple_kms_crtc_enable+0x12e/0x1a0
> [   18.093973][    T1]  ? bochs_connector_get_modes+0x1e0/0x1e0
> [   18.094011][    T1]  ? drm_simple_kms_crtc_check+0x210/0x210
> [   18.094049][    T1]  drm_atomic_helper_commit_modeset_enables+0x362/0x1000
> [   18.094095][    T1]  drm_atomic_helper_commit_tail+0xd3/0x860
> [   18.094135][    T1]  ? kmsan_get_metadata+0x116/0x180
> [   18.094171][    T1]  commit_tail+0x61c/0x7d0
> [   18.094205][    T1]  ? kmsan_internal_set_origin+0x85/0xc0
> [   18.094246][    T1]  drm_atomic_helper_commit+0xbfe/0xcb0
> [   18.094284][    T1]  ? kmsan_get_metadata+0x116/0x180
> [   18.094322][    T1]  ? drm_atomic_helper_async_commit+0x780/0x780
> [   18.094361][    T1]  drm_atomic_commit+0x192/0x210
> [   18.094400][    T1]  drm_client_modeset_commit_atomic+0x700/0xbe0
> [   18.094444][    T1]  drm_client_modeset_commit_locked+0x147/0x860
> [   18.094481][    T1]  ? drm_master_internal_acquire+0x4a/0xd0
> [   18.094513][    T1]  drm_client_modeset_commit+0x98/0x110
> [   18.094551][    T1]  __drm_fb_helper_restore_fbdev_mode_unlocked+0x1a7/0x2a0
> [   18.094586][    T1]  drm_fb_helper_set_par+0x12a/0x220
> [   18.094620][    T1]  ? drm_fb_helper_fill_pixel_fmt+0x780/0x780
> [   18.094646][    T1]  fbcon_init+0x1959/0x2910
> [   18.094685][    T1]  ? validate_slab+0x30/0x730
> [   18.094714][    T1]  ? fbcon_startup+0x1590/0x1590
> [   18.094746][    T1]  visual_init+0x3bb/0x7b0
> [   18.094786][    T1]  do_bind_con_driver+0x136e/0x1c90
> [   18.094834][    T1]  do_take_over_console+0xe0a/0xef0
> [   18.094875][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> [   18.094907][    T1]  fbcon_fb_registered+0x51c/0xae0
> [   18.094954][    T1]  register_framebuffer+0xb68/0xfc0
> [   18.094999][    T1]  __drm_fb_helper_initial_config_and_unlock+0x17d2/0x2030
> [   18.095047][    T1]  drm_fbdev_client_hotplug+0x7a3/0xe80
> [   18.095085][    T1]  drm_fbdev_generic_setup+0x2b9/0x890
> [   18.095124][    T1]  bochs_pci_probe+0x7de/0x800
> [   18.095161][    T1]  ? qxl_gem_prime_mmap+0x30/0x30
> [   18.095193][    T1]  pci_device_probe+0x95f/0xc70
> [   18.095227][    T1]  ? pci_uevent+0x7b0/0x7b0
> [   18.095259][    T1]  really_probe+0x9af/0x20d0
> [   18.095298][    T1]  driver_probe_device+0x234/0x330
> [   18.095334][    T1]  device_driver_attach+0x1e8/0x3c0
> [   18.095370][    T1]  __driver_attach+0x30d/0x780
> [   18.095399][    T1]  ? klist_devices_get+0x10/0x60
> [   18.095431][    T1]  ? kmsan_get_metadata+0x116/0x180
> [   18.095463][    T1]  bus_for_each_dev+0x252/0x360
> [   18.095493][    T1]  ? driver_attach+0xa0/0xa0
> [   18.095527][    T1]  driver_attach+0x84/0xa0
> [   18.095558][    T1]  bus_add_driver+0x5d6/0xb00
> [   18.095596][    T1]  driver_register+0x30c/0x830
> [   18.095632][    T1]  __pci_register_driver+0x1fa/0x350
> [   18.095669][    T1]  bochs_init+0xd6/0x115
> [   18.095703][    T1]  do_one_initcall+0x246/0x7a0
> [   18.095734][    T1]  ? qxl_init+0x165/0x165
> [   18.095779][    T1]  ? kmsan_get_metadata+0x116/0x180
> [   18.095815][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> [   18.095844][    T1]  ? qxl_init+0x165/0x165
> [   18.095878][    T1]  do_initcall_level+0x2b4/0x34a
> [   18.095913][    T1]  do_initcalls+0x123/0x1ba
> [   18.095947][    T1]  ? cpu_init_udelay+0xcf/0xcf
> [   18.095978][    T1]  do_basic_setup+0x2e/0x31
> [   18.096011][    T1]  kernel_init_freeable+0x23f/0x35f
> [   18.096049][    T1]  ? rest_init+0x1f0/0x1f0
> [   18.096080][    T1]  kernel_init+0x1a/0x670
> [   18.096111][    T1]  ? rest_init+0x1f0/0x1f0
> [   18.096141][    T1]  ret_from_fork+0x1f/0x30
> [   18.096166][    T1] Kernel panic - not syncing: panic_on_warn set ...
> [   18.096192][    T1] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc1 #2
> [   18.096208][    T1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1 04/01/2014
> [   18.096219][    T1] Call Trace:
> [   18.096254][    T1]  dump_stack+0x189/0x218
> [   18.096287][    T1]  panic+0x38e/0xae4
> [   18.096335][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> [   18.096364][    T1]  __warn+0x433/0x5c0
> [   18.096402][    T1]  ? drm_gem_vram_offset+0x128/0x140
> [   18.096434][    T1]  report_bug+0x669/0x880
> [   18.096474][    T1]  ? drm_gem_vram_offset+0x128/0x140
> [   18.096506][    T1]  handle_bug+0x6f/0xd0
> [   18.096537][    T1]  __exc_invalid_op+0x34/0x80
> [   18.096566][    T1]  exc_invalid_op+0x30/0x40
> [   18.096603][    T1]  asm_exc_invalid_op+0x12/0x20
> [   18.096640][    T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140
> [   18.096674][    T1] Code: 48 c7 c3 ed ff ff ff 31 c0 31 c9 eb b4 8b 7d d4 e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e fc 4d 85 ff 0f 85 6e ff ff ff <0f> 0b 31 c0 31 c9 31 db eb 8d 8b 7d d4 e8 96 78 1e fc e9 67 ff ff
> [   18.096693][    T1] RSP: 0000:ffff8880125a6718 EFLAGS: 00010246
> [   18.096721][    T1] RAX: 0000000000000000 RBX: ffff8880155efd80 RCX: 00000000151efd80
> [   18.096743][    T1] RDX: ffff8880151efd80 RSI: 0000000000000040 RDI: ffff8880155efd80
> [   18.096767][    T1] RBP: ffff8880125a6748 R08: ffffea000000000f R09: ffff8880bffd2000
> [   18.096787][    T1] R10: 0000000000000004 R11: 00000000ffffffff R12: ffff8880155efc00
> [   18.096807][    T1] R13: 0000000000000000 R14: ffff8880125b0a10 R15: 0000000000000000
> [   18.096849][    T1]  ? drm_gem_vram_offset+0x79/0x140
> [   18.096884][    T1]  bochs_pipe_enable+0x16f/0x3f0
> [   18.096927][    T1]  drm_simple_kms_crtc_enable+0x12e/0x1a0
> [   18.096964][    T1]  ? bochs_connector_get_modes+0x1e0/0x1e0
> [   18.097001][    T1]  ? drm_simple_kms_crtc_check+0x210/0x210
> [   18.097039][    T1]  drm_atomic_helper_commit_modeset_enables+0x362/0x1000
> [   18.097083][    T1]  drm_atomic_helper_commit_tail+0xd3/0x860
> [   18.097120][    T1]  ? kmsan_get_metadata+0x116/0x180
> [   18.097156][    T1]  commit_tail+0x61c/0x7d0
> [   18.097190][    T1]  ? kmsan_internal_set_origin+0x85/0xc0
> [   18.097230][    T1]  drm_atomic_helper_commit+0xbfe/0xcb0
> [   18.097267][    T1]  ? kmsan_get_metadata+0x116/0x180
> [   18.097305][    T1]  ? drm_atomic_helper_async_commit+0x780/0x780
> [   18.097341][    T1]  drm_atomic_commit+0x192/0x210
> [   18.097378][    T1]  drm_client_modeset_commit_atomic+0x700/0xbe0
> [   18.097422][    T1]  drm_client_modeset_commit_locked+0x147/0x860
> [   18.097459][    T1]  ? drm_master_internal_acquire+0x4a/0xd0
> [   18.097491][    T1]  drm_client_modeset_commit+0x98/0x110
> [   18.097528][    T1]  __drm_fb_helper_restore_fbdev_mode_unlocked+0x1a7/0x2a0
> [   18.097562][    T1]  drm_fb_helper_set_par+0x12a/0x220
> [   18.097596][    T1]  ? drm_fb_helper_fill_pixel_fmt+0x780/0x780
> [   18.097621][    T1]  fbcon_init+0x1959/0x2910
> [   18.097660][    T1]  ? validate_slab+0x30/0x730
> [   18.097688][    T1]  ? fbcon_startup+0x1590/0x1590
> [   18.097719][    T1]  visual_init+0x3bb/0x7b0
> [   18.097758][    T1]  do_bind_con_driver+0x136e/0x1c90
> [   18.097807][    T1]  do_take_over_console+0xe0a/0xef0
> [   18.097848][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> [   18.097879][    T1]  fbcon_fb_registered+0x51c/0xae0
> [   18.097917][    T1]  register_framebuffer+0xb68/0xfc0
> [   18.097961][    T1]  __drm_fb_helper_initial_config_and_unlock+0x17d2/0x2030
> [   18.098009][    T1]  drm_fbdev_client_hotplug+0x7a3/0xe80
> [   18.098047][    T1]  drm_fbdev_generic_setup+0x2b9/0x890
> [   18.098085][    T1]  bochs_pci_probe+0x7de/0x800
> [   18.098123][    T1]  ? qxl_gem_prime_mmap+0x30/0x30
> [   18.098152][    T1]  pci_device_probe+0x95f/0xc70
> [   18.098187][    T1]  ? pci_uevent+0x7b0/0x7b0
> [   18.098217][    T1]  really_probe+0x9af/0x20d0
> [   18.098255][    T1]  driver_probe_device+0x234/0x330
> [   18.098291][    T1]  device_driver_attach+0x1e8/0x3c0
> [   18.098326][    T1]  __driver_attach+0x30d/0x780
> [   18.098355][    T1]  ? klist_devices_get+0x10/0x60
> [   18.098388][    T1]  ? kmsan_get_metadata+0x116/0x180
> [   18.098419][    T1]  bus_for_each_dev+0x252/0x360
> [   18.098448][    T1]  ? driver_attach+0xa0/0xa0
> [   18.098482][    T1]  driver_attach+0x84/0xa0
> [   18.098512][    T1]  bus_add_driver+0x5d6/0xb00
> [   18.098550][    T1]  driver_register+0x30c/0x830
> [   18.098585][    T1]  __pci_register_driver+0x1fa/0x350
> [   18.098620][    T1]  bochs_init+0xd6/0x115
> [   18.098651][    T1]  do_one_initcall+0x246/0x7a0
> [   18.098680][    T1]  ? qxl_init+0x165/0x165
> [   18.098727][    T1]  ? kmsan_get_metadata+0x116/0x180
> [   18.098763][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> [   18.098791][    T1]  ? qxl_init+0x165/0x165
> [   18.098824][    T1]  do_initcall_level+0x2b4/0x34a
> [   18.098859][    T1]  do_initcalls+0x123/0x1ba
> [   18.098890][    T1]  ? cpu_init_udelay+0xcf/0xcf
> [   18.098921][    T1]  do_basic_setup+0x2e/0x31
> [   18.098958][    T1]  kernel_init_freeable+0x23f/0x35f
> [   18.098993][    T1]  ? rest_init+0x1f0/0x1f0
> [   18.099024][    T1]  kernel_init+0x1a/0x670
> [   18.099054][    T1]  ? rest_init+0x1f0/0x1f0
> [   18.099085][    T1]  ret_from_fork+0x1f/0x30
> [   18.099240][    T1] Dumping ftrace buffer:
> [   18.099250][    T1]    (ftrace buffer empty)
> [   18.099250][    T1] Kernel Offset: disabled
> [   18.099250][    T1] Rebooting in 1 seconds..
> ```

Hi,

The WARNING does not look KMSAN-related, KMSAN is not in the stack and
the subsystem is not KMSAN. Please report it to DRM maintainers.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbLDd8n1K9FevEUprki9J1rR%3Dxv6cnCvsaOGZNUsKhuAQ%40mail.gmail.com.
