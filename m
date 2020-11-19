Return-Path: <kasan-dev+bncBCH2XPOBSAERBF5A276QKGQEAJS2QYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 28F132B89D8
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Nov 2020 02:53:29 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id i7sf1828110otp.14
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Nov 2020 17:53:29 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3KsnaCPlxDBIGHAT1t9LsKoYPvMRrvZAYhPWLVlDhp0=;
        b=sDoWkLCfUJz89WxE37PIr2FTOvIrGVbpg5IZunJeRqlCyhDEonh55W65w9zximhhmV
         mkIJExZJwu8iOP+nQrpOYwYnQH79mrpclCWxbrek2teLanIAyvZvUgWIrZZy8zCi9JVW
         xND/hMYKHIJk21CNbcn34dF3IT2D72bNgILEcfBAD2RYuW47x2iyrtj1Cpat8Ns6ybUV
         9q8erHc/17nXNDyG8OQit0xyPdKMQlv3IlRgmlNoxprxu1jN7+YnzxohqOcbRV+CP95u
         7Fnff4Ocv90PhSZTI5HURfO30dy4XwUFa22WEWWdUFUWYXMLCpqR3q6MrLrR58jXfJQT
         R/xQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3KsnaCPlxDBIGHAT1t9LsKoYPvMRrvZAYhPWLVlDhp0=;
        b=X31wRQBRfoM1apzH1FzV+shd4baT+woYOxMYyPjDdtNqBzr3ajoxHl1NSY3Vr37RaZ
         E5AcX2Ojo+sqNlfp/S4SQNPUnG63bv5FALK+rCe+cXMxaXjUAz04wc6vfMZ/JsQwb++1
         Z+bvNxJgsb39cPQ98Jn/SPRl7StmTr3pvR/Ryv0LEunIF4sktS4RdUkuzNE8UGyO4N/8
         /Og0HtLxdcd8EuZezllHzG2u3Kfz6QRlQ7KLCifAAYEKmioNoIsZmEXG6MVaboOCLC/N
         XFdWlUXz2gPjk4/FhzfLiSe2UQn+f3EjO2O4s959j5HqgQrZq7YuFfc8eCScUR3adFZP
         iBRA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=3KsnaCPlxDBIGHAT1t9LsKoYPvMRrvZAYhPWLVlDhp0=;
        b=qympeVwSl/SeLMdWydiHoKTnC5Hh64THqiiR6zrEEH0I2uJflHjIZmvQ8bqnYT9nOS
         Zmnj+Jga+kR5/jayhpSQelitaWsDhu3U6U1IpffrtjP40OKhA52zBpYwKb2Y3YKN18V+
         mtEMqQyyNrOhMNlhKers0IEuQmnNq4qf27FC0gR0ziWLGS/fN2/m00tx8heifauxm+Ym
         KULMOrnkSmsrzgFYW8UuRZGuR4YWHK7i2zJ25PRMT1GtFn3MgCKw7Lp09+W+++b8MjPN
         KU1vWWDtlansSj/m20gFzDo8FxJVGQHf6u+WlcGjJW3lq3dBmFA1QfGWE6fGyvEFWLpA
         8D2A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531VaMb8uX3lmlfq36QUQ3e3wfpiR3WeNdGIwUK8zy1xkXcYKf/w
	jS7Hd8X4EiCAGgKSDOaOfOA=
X-Google-Smtp-Source: ABdhPJyadw2re7PnFBdsut8lQ8ULmKgWrpt/ACWVIaERznLktTx0tQ8eohFveRlRaDrwO1gPx7EM5w==
X-Received: by 2002:a9d:a4d:: with SMTP id 71mr8151372otg.257.1605750807906;
        Wed, 18 Nov 2020 17:53:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:416:: with SMTP id 22ls325869oie.7.gmail; Wed, 18 Nov
 2020 17:53:27 -0800 (PST)
X-Received: by 2002:aca:c146:: with SMTP id r67mr1321289oif.134.1605750807287;
        Wed, 18 Nov 2020 17:53:27 -0800 (PST)
Date: Wed, 18 Nov 2020 17:53:26 -0800 (PST)
From: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <a63a2733-1b7c-4bac-ad47-ea6e3999b953n@googlegroups.com>
In-Reply-To: <CACT4Y+bLDd8n1K9FevEUprki9J1rR=xv6cnCvsaOGZNUsKhuAQ@mail.gmail.com>
References: <64637dc5-a480-4ae2-903e-9d70a7fdff98n@googlegroups.com>
 <CACT4Y+bLDd8n1K9FevEUprki9J1rR=xv6cnCvsaOGZNUsKhuAQ@mail.gmail.com>
Subject: Re: KMSAN: WARNING at drivers/gpu/drm/drm_gem_vram_helper.c:284
 drm_gem_vram_offset
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_1334_728886479.1605750806379"
X-Original-Sender: mudongliangabcd@gmail.com
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

------=_Part_1334_728886479.1605750806379
Content-Type: multipart/alternative; 
	boundary="----=_Part_1335_292298641.1605750806379"

------=_Part_1335_292298641.1605750806379
Content-Type: text/plain; charset="UTF-8"

I see. Thanks, I will report it to DRM maintainers.

On Monday, November 16, 2020 at 4:28:44 PM UTC+8 Dmitry Vyukov wrote:

> On Mon, Nov 16, 2020 at 6:51 AM mudongl...@gmail.com
> <mudongl...@gmail.com> wrote:
> >
> > Hi all,
> >
> > I built the kmsan with github kmsan repo HEAD, however, when I leveraged 
> syzkaller to fuzz this kernel image, the VMs is always broken with the 
> following WARNING report:
> >
> > ```
> > [ 18.093341][ T1] ------------[ cut here ]------------
> > [ 18.093419][ T1] WARNING: CPU: 1 PID: 1 at 
> drivers/gpu/drm/drm_gem_vram_helper.c:284 drm_gem_vram_offset+0x128/0x140
> > [ 18.093431][ T1] Modules linked in:
> > [ 18.093472][ T1] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc1 #2
> > [ 18.093489][ T1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), 
> BIOS 1.13.0-1ubuntu1 04/01/2014
> > [ 18.093532][ T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140
> > [ 18.093574][ T1] Code: 48 c7 c3 ed ff ff ff 31 c0 31 c9 eb b4 8b 7d d4 
> e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e fc 4d 85 ff 0f 85 6e ff ff 
> ff <0f> 0b 31 c0 31 c9 31 db eb 8d 8b 7d d4 e8 96 78 1e fc e9 67 ff ff
> > [ 18.093594][ T1] RSP: 0000:ffff8880125a6718 EFLAGS: 00010246
> > [ 18.093622][ T1] RAX: 0000000000000000 RBX: ffff8880155efd80 RCX: 
> 00000000151efd80
> > [ 18.093645][ T1] RDX: ffff8880151efd80 RSI: 0000000000000040 RDI: 
> ffff8880155efd80
> > [ 18.093669][ T1] RBP: ffff8880125a6748 R08: ffffea000000000f R09: 
> ffff8880bffd2000
> > [ 18.093691][ T1] R10: 0000000000000004 R11: 00000000ffffffff R12: 
> ffff8880155efc00
> > [ 18.093711][ T1] R13: 0000000000000000 R14: ffff8880125b0a10 R15: 
> 0000000000000000
> > [ 18.093736][ T1] FS: 0000000000000000(0000) GS:ffff8880bfd00000(0000) 
> knlGS:0000000000000000
> > [ 18.093757][ T1] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033
> > [ 18.093777][ T1] CR2: 0000000000000000 CR3: 0000000010229001 CR4: 
> 0000000000770ee0
> > [ 18.093797][ T1] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 
> 0000000000000000
> > [ 18.093816][ T1] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 
> 0000000000000400
> > [ 18.093828][ T1] PKRU: 55555554
> > [ 18.093839][ T1] Call Trace:
> > [ 18.093886][ T1] bochs_pipe_enable+0x16f/0x3f0
> > [ 18.093935][ T1] drm_simple_kms_crtc_enable+0x12e/0x1a0
> > [ 18.093973][ T1] ? bochs_connector_get_modes+0x1e0/0x1e0
> > [ 18.094011][ T1] ? drm_simple_kms_crtc_check+0x210/0x210
> > [ 18.094049][ T1] drm_atomic_helper_commit_modeset_enables+0x362/0x1000
> > [ 18.094095][ T1] drm_atomic_helper_commit_tail+0xd3/0x860
> > [ 18.094135][ T1] ? kmsan_get_metadata+0x116/0x180
> > [ 18.094171][ T1] commit_tail+0x61c/0x7d0
> > [ 18.094205][ T1] ? kmsan_internal_set_origin+0x85/0xc0
> > [ 18.094246][ T1] drm_atomic_helper_commit+0xbfe/0xcb0
> > [ 18.094284][ T1] ? kmsan_get_metadata+0x116/0x180
> > [ 18.094322][ T1] ? drm_atomic_helper_async_commit+0x780/0x780
> > [ 18.094361][ T1] drm_atomic_commit+0x192/0x210
> > [ 18.094400][ T1] drm_client_modeset_commit_atomic+0x700/0xbe0
> > [ 18.094444][ T1] drm_client_modeset_commit_locked+0x147/0x860
> > [ 18.094481][ T1] ? drm_master_internal_acquire+0x4a/0xd0
> > [ 18.094513][ T1] drm_client_modeset_commit+0x98/0x110
> > [ 18.094551][ T1] __drm_fb_helper_restore_fbdev_mode_unlocked+0x1a7/0x2a0
> > [ 18.094586][ T1] drm_fb_helper_set_par+0x12a/0x220
> > [ 18.094620][ T1] ? drm_fb_helper_fill_pixel_fmt+0x780/0x780
> > [ 18.094646][ T1] fbcon_init+0x1959/0x2910
> > [ 18.094685][ T1] ? validate_slab+0x30/0x730
> > [ 18.094714][ T1] ? fbcon_startup+0x1590/0x1590
> > [ 18.094746][ T1] visual_init+0x3bb/0x7b0
> > [ 18.094786][ T1] do_bind_con_driver+0x136e/0x1c90
> > [ 18.094834][ T1] do_take_over_console+0xe0a/0xef0
> > [ 18.094875][ T1] ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> > [ 18.094907][ T1] fbcon_fb_registered+0x51c/0xae0
> > [ 18.094954][ T1] register_framebuffer+0xb68/0xfc0
> > [ 18.094999][ T1] __drm_fb_helper_initial_config_and_unlock+0x17d2/0x2030
> > [ 18.095047][ T1] drm_fbdev_client_hotplug+0x7a3/0xe80
> > [ 18.095085][ T1] drm_fbdev_generic_setup+0x2b9/0x890
> > [ 18.095124][ T1] bochs_pci_probe+0x7de/0x800
> > [ 18.095161][ T1] ? qxl_gem_prime_mmap+0x30/0x30
> > [ 18.095193][ T1] pci_device_probe+0x95f/0xc70
> > [ 18.095227][ T1] ? pci_uevent+0x7b0/0x7b0
> > [ 18.095259][ T1] really_probe+0x9af/0x20d0
> > [ 18.095298][ T1] driver_probe_device+0x234/0x330
> > [ 18.095334][ T1] device_driver_attach+0x1e8/0x3c0
> > [ 18.095370][ T1] __driver_attach+0x30d/0x780
> > [ 18.095399][ T1] ? klist_devices_get+0x10/0x60
> > [ 18.095431][ T1] ? kmsan_get_metadata+0x116/0x180
> > [ 18.095463][ T1] bus_for_each_dev+0x252/0x360
> > [ 18.095493][ T1] ? driver_attach+0xa0/0xa0
> > [ 18.095527][ T1] driver_attach+0x84/0xa0
> > [ 18.095558][ T1] bus_add_driver+0x5d6/0xb00
> > [ 18.095596][ T1] driver_register+0x30c/0x830
> > [ 18.095632][ T1] __pci_register_driver+0x1fa/0x350
> > [ 18.095669][ T1] bochs_init+0xd6/0x115
> > [ 18.095703][ T1] do_one_initcall+0x246/0x7a0
> > [ 18.095734][ T1] ? qxl_init+0x165/0x165
> > [ 18.095779][ T1] ? kmsan_get_metadata+0x116/0x180
> > [ 18.095815][ T1] ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> > [ 18.095844][ T1] ? qxl_init+0x165/0x165
> > [ 18.095878][ T1] do_initcall_level+0x2b4/0x34a
> > [ 18.095913][ T1] do_initcalls+0x123/0x1ba
> > [ 18.095947][ T1] ? cpu_init_udelay+0xcf/0xcf
> > [ 18.095978][ T1] do_basic_setup+0x2e/0x31
> > [ 18.096011][ T1] kernel_init_freeable+0x23f/0x35f
> > [ 18.096049][ T1] ? rest_init+0x1f0/0x1f0
> > [ 18.096080][ T1] kernel_init+0x1a/0x670
> > [ 18.096111][ T1] ? rest_init+0x1f0/0x1f0
> > [ 18.096141][ T1] ret_from_fork+0x1f/0x30
> > [ 18.096166][ T1] Kernel panic - not syncing: panic_on_warn set ...
> > [ 18.096192][ T1] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc1 #2
> > [ 18.096208][ T1] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), 
> BIOS 1.13.0-1ubuntu1 04/01/2014
> > [ 18.096219][ T1] Call Trace:
> > [ 18.096254][ T1] dump_stack+0x189/0x218
> > [ 18.096287][ T1] panic+0x38e/0xae4
> > [ 18.096335][ T1] ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> > [ 18.096364][ T1] __warn+0x433/0x5c0
> > [ 18.096402][ T1] ? drm_gem_vram_offset+0x128/0x140
> > [ 18.096434][ T1] report_bug+0x669/0x880
> > [ 18.096474][ T1] ? drm_gem_vram_offset+0x128/0x140
> > [ 18.096506][ T1] handle_bug+0x6f/0xd0
> > [ 18.096537][ T1] __exc_invalid_op+0x34/0x80
> > [ 18.096566][ T1] exc_invalid_op+0x30/0x40
> > [ 18.096603][ T1] asm_exc_invalid_op+0x12/0x20
> > [ 18.096640][ T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140
> > [ 18.096674][ T1] Code: 48 c7 c3 ed ff ff ff 31 c0 31 c9 eb b4 8b 7d d4 
> e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e fc 4d 85 ff 0f 85 6e ff ff 
> ff <0f> 0b 31 c0 31 c9 31 db eb 8d 8b 7d d4 e8 96 78 1e fc e9 67 ff ff
> > [ 18.096693][ T1] RSP: 0000:ffff8880125a6718 EFLAGS: 00010246
> > [ 18.096721][ T1] RAX: 0000000000000000 RBX: ffff8880155efd80 RCX: 
> 00000000151efd80
> > [ 18.096743][ T1] RDX: ffff8880151efd80 RSI: 0000000000000040 RDI: 
> ffff8880155efd80
> > [ 18.096767][ T1] RBP: ffff8880125a6748 R08: ffffea000000000f R09: 
> ffff8880bffd2000
> > [ 18.096787][ T1] R10: 0000000000000004 R11: 00000000ffffffff R12: 
> ffff8880155efc00
> > [ 18.096807][ T1] R13: 0000000000000000 R14: ffff8880125b0a10 R15: 
> 0000000000000000
> > [ 18.096849][ T1] ? drm_gem_vram_offset+0x79/0x140
> > [ 18.096884][ T1] bochs_pipe_enable+0x16f/0x3f0
> > [ 18.096927][ T1] drm_simple_kms_crtc_enable+0x12e/0x1a0
> > [ 18.096964][ T1] ? bochs_connector_get_modes+0x1e0/0x1e0
> > [ 18.097001][ T1] ? drm_simple_kms_crtc_check+0x210/0x210
> > [ 18.097039][ T1] drm_atomic_helper_commit_modeset_enables+0x362/0x1000
> > [ 18.097083][ T1] drm_atomic_helper_commit_tail+0xd3/0x860
> > [ 18.097120][ T1] ? kmsan_get_metadata+0x116/0x180
> > [ 18.097156][ T1] commit_tail+0x61c/0x7d0
> > [ 18.097190][ T1] ? kmsan_internal_set_origin+0x85/0xc0
> > [ 18.097230][ T1] drm_atomic_helper_commit+0xbfe/0xcb0
> > [ 18.097267][ T1] ? kmsan_get_metadata+0x116/0x180
> > [ 18.097305][ T1] ? drm_atomic_helper_async_commit+0x780/0x780
> > [ 18.097341][ T1] drm_atomic_commit+0x192/0x210
> > [ 18.097378][ T1] drm_client_modeset_commit_atomic+0x700/0xbe0
> > [ 18.097422][ T1] drm_client_modeset_commit_locked+0x147/0x860
> > [ 18.097459][ T1] ? drm_master_internal_acquire+0x4a/0xd0
> > [ 18.097491][ T1] drm_client_modeset_commit+0x98/0x110
> > [ 18.097528][ T1] __drm_fb_helper_restore_fbdev_mode_unlocked+0x1a7/0x2a0
> > [ 18.097562][ T1] drm_fb_helper_set_par+0x12a/0x220
> > [ 18.097596][ T1] ? drm_fb_helper_fill_pixel_fmt+0x780/0x780
> > [ 18.097621][ T1] fbcon_init+0x1959/0x2910
> > [ 18.097660][ T1] ? validate_slab+0x30/0x730
> > [ 18.097688][ T1] ? fbcon_startup+0x1590/0x1590
> > [ 18.097719][ T1] visual_init+0x3bb/0x7b0
> > [ 18.097758][ T1] do_bind_con_driver+0x136e/0x1c90
> > [ 18.097807][ T1] do_take_over_console+0xe0a/0xef0
> > [ 18.097848][ T1] ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> > [ 18.097879][ T1] fbcon_fb_registered+0x51c/0xae0
> > [ 18.097917][ T1] register_framebuffer+0xb68/0xfc0
> > [ 18.097961][ T1] __drm_fb_helper_initial_config_and_unlock+0x17d2/0x2030
> > [ 18.098009][ T1] drm_fbdev_client_hotplug+0x7a3/0xe80
> > [ 18.098047][ T1] drm_fbdev_generic_setup+0x2b9/0x890
> > [ 18.098085][ T1] bochs_pci_probe+0x7de/0x800
> > [ 18.098123][ T1] ? qxl_gem_prime_mmap+0x30/0x30
> > [ 18.098152][ T1] pci_device_probe+0x95f/0xc70
> > [ 18.098187][ T1] ? pci_uevent+0x7b0/0x7b0
> > [ 18.098217][ T1] really_probe+0x9af/0x20d0
> > [ 18.098255][ T1] driver_probe_device+0x234/0x330
> > [ 18.098291][ T1] device_driver_attach+0x1e8/0x3c0
> > [ 18.098326][ T1] __driver_attach+0x30d/0x780
> > [ 18.098355][ T1] ? klist_devices_get+0x10/0x60
> > [ 18.098388][ T1] ? kmsan_get_metadata+0x116/0x180
> > [ 18.098419][ T1] bus_for_each_dev+0x252/0x360
> > [ 18.098448][ T1] ? driver_attach+0xa0/0xa0
> > [ 18.098482][ T1] driver_attach+0x84/0xa0
> > [ 18.098512][ T1] bus_add_driver+0x5d6/0xb00
> > [ 18.098550][ T1] driver_register+0x30c/0x830
> > [ 18.098585][ T1] __pci_register_driver+0x1fa/0x350
> > [ 18.098620][ T1] bochs_init+0xd6/0x115
> > [ 18.098651][ T1] do_one_initcall+0x246/0x7a0
> > [ 18.098680][ T1] ? qxl_init+0x165/0x165
> > [ 18.098727][ T1] ? kmsan_get_metadata+0x116/0x180
> > [ 18.098763][ T1] ? kmsan_get_shadow_origin_ptr+0x84/0xb0
> > [ 18.098791][ T1] ? qxl_init+0x165/0x165
> > [ 18.098824][ T1] do_initcall_level+0x2b4/0x34a
> > [ 18.098859][ T1] do_initcalls+0x123/0x1ba
> > [ 18.098890][ T1] ? cpu_init_udelay+0xcf/0xcf
> > [ 18.098921][ T1] do_basic_setup+0x2e/0x31
> > [ 18.098958][ T1] kernel_init_freeable+0x23f/0x35f
> > [ 18.098993][ T1] ? rest_init+0x1f0/0x1f0
> > [ 18.099024][ T1] kernel_init+0x1a/0x670
> > [ 18.099054][ T1] ? rest_init+0x1f0/0x1f0
> > [ 18.099085][ T1] ret_from_fork+0x1f/0x30
> > [ 18.099240][ T1] Dumping ftrace buffer:
> > [ 18.099250][ T1] (ftrace buffer empty)
> > [ 18.099250][ T1] Kernel Offset: disabled
> > [ 18.099250][ T1] Rebooting in 1 seconds..
> > ```
>
> Hi,
>
> The WARNING does not look KMSAN-related, KMSAN is not in the stack and
> the subsystem is not KMSAN. Please report it to DRM maintainers.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a63a2733-1b7c-4bac-ad47-ea6e3999b953n%40googlegroups.com.

------=_Part_1335_292298641.1605750806379
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

I see. Thanks, I will report it to DRM maintainers.<br><br><div class=3D"gm=
ail_quote"><div dir=3D"auto" class=3D"gmail_attr">On Monday, November 16, 2=
020 at 4:28:44 PM UTC+8 Dmitry Vyukov wrote:<br/></div><blockquote class=3D=
"gmail_quote" style=3D"margin: 0 0 0 0.8ex; border-left: 1px solid rgb(204,=
 204, 204); padding-left: 1ex;">On Mon, Nov 16, 2020 at 6:51 AM <a href dat=
a-email-masked rel=3D"nofollow">mudongl...@gmail.com</a>
<br>&lt;<a href data-email-masked rel=3D"nofollow">mudongl...@gmail.com</a>=
&gt; wrote:
<br>&gt;
<br>&gt; Hi all,
<br>&gt;
<br>&gt; I built the kmsan with github kmsan repo HEAD, however, when I lev=
eraged syzkaller to fuzz this kernel image, the VMs is always broken with t=
he following WARNING report:
<br>&gt;
<br>&gt; ```
<br>&gt; [   18.093341][    T1] ------------[ cut here ]------------
<br>&gt; [   18.093419][    T1] WARNING: CPU: 1 PID: 1 at drivers/gpu/drm/d=
rm_gem_vram_helper.c:284 drm_gem_vram_offset+0x128/0x140
<br>&gt; [   18.093431][    T1] Modules linked in:
<br>&gt; [   18.093472][    T1] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5=
.10.0-rc1 #2
<br>&gt; [   18.093489][    T1] Hardware name: QEMU Standard PC (i440FX + P=
IIX, 1996), BIOS 1.13.0-1ubuntu1 04/01/2014
<br>&gt; [   18.093532][    T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140
<br>&gt; [   18.093574][    T1] Code: 48 c7 c3 ed ff ff ff 31 c0 31 c9 eb b=
4 8b 7d d4 e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e fc 4d 85 ff 0f 8=
5 6e ff ff ff &lt;0f&gt; 0b 31 c0 31 c9 31 db eb 8d 8b 7d d4 e8 96 78 1e fc=
 e9 67 ff ff
<br>&gt; [   18.093594][    T1] RSP: 0000:ffff8880125a6718 EFLAGS: 00010246
<br>&gt; [   18.093622][    T1] RAX: 0000000000000000 RBX: ffff8880155efd80=
 RCX: 00000000151efd80
<br>&gt; [   18.093645][    T1] RDX: ffff8880151efd80 RSI: 0000000000000040=
 RDI: ffff8880155efd80
<br>&gt; [   18.093669][    T1] RBP: ffff8880125a6748 R08: ffffea000000000f=
 R09: ffff8880bffd2000
<br>&gt; [   18.093691][    T1] R10: 0000000000000004 R11: 00000000ffffffff=
 R12: ffff8880155efc00
<br>&gt; [   18.093711][    T1] R13: 0000000000000000 R14: ffff8880125b0a10=
 R15: 0000000000000000
<br>&gt; [   18.093736][    T1] FS:  0000000000000000(0000) GS:ffff8880bfd0=
0000(0000) knlGS:0000000000000000
<br>&gt; [   18.093757][    T1] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080=
050033
<br>&gt; [   18.093777][    T1] CR2: 0000000000000000 CR3: 0000000010229001=
 CR4: 0000000000770ee0
<br>&gt; [   18.093797][    T1] DR0: 0000000000000000 DR1: 0000000000000000=
 DR2: 0000000000000000
<br>&gt; [   18.093816][    T1] DR3: 0000000000000000 DR6: 00000000fffe0ff0=
 DR7: 0000000000000400
<br>&gt; [   18.093828][    T1] PKRU: 55555554
<br>&gt; [   18.093839][    T1] Call Trace:
<br>&gt; [   18.093886][    T1]  bochs_pipe_enable+0x16f/0x3f0
<br>&gt; [   18.093935][    T1]  drm_simple_kms_crtc_enable+0x12e/0x1a0
<br>&gt; [   18.093973][    T1]  ? bochs_connector_get_modes+0x1e0/0x1e0
<br>&gt; [   18.094011][    T1]  ? drm_simple_kms_crtc_check+0x210/0x210
<br>&gt; [   18.094049][    T1]  drm_atomic_helper_commit_modeset_enables+0=
x362/0x1000
<br>&gt; [   18.094095][    T1]  drm_atomic_helper_commit_tail+0xd3/0x860
<br>&gt; [   18.094135][    T1]  ? kmsan_get_metadata+0x116/0x180
<br>&gt; [   18.094171][    T1]  commit_tail+0x61c/0x7d0
<br>&gt; [   18.094205][    T1]  ? kmsan_internal_set_origin+0x85/0xc0
<br>&gt; [   18.094246][    T1]  drm_atomic_helper_commit+0xbfe/0xcb0
<br>&gt; [   18.094284][    T1]  ? kmsan_get_metadata+0x116/0x180
<br>&gt; [   18.094322][    T1]  ? drm_atomic_helper_async_commit+0x780/0x7=
80
<br>&gt; [   18.094361][    T1]  drm_atomic_commit+0x192/0x210
<br>&gt; [   18.094400][    T1]  drm_client_modeset_commit_atomic+0x700/0xb=
e0
<br>&gt; [   18.094444][    T1]  drm_client_modeset_commit_locked+0x147/0x8=
60
<br>&gt; [   18.094481][    T1]  ? drm_master_internal_acquire+0x4a/0xd0
<br>&gt; [   18.094513][    T1]  drm_client_modeset_commit+0x98/0x110
<br>&gt; [   18.094551][    T1]  __drm_fb_helper_restore_fbdev_mode_unlocke=
d+0x1a7/0x2a0
<br>&gt; [   18.094586][    T1]  drm_fb_helper_set_par+0x12a/0x220
<br>&gt; [   18.094620][    T1]  ? drm_fb_helper_fill_pixel_fmt+0x780/0x780
<br>&gt; [   18.094646][    T1]  fbcon_init+0x1959/0x2910
<br>&gt; [   18.094685][    T1]  ? validate_slab+0x30/0x730
<br>&gt; [   18.094714][    T1]  ? fbcon_startup+0x1590/0x1590
<br>&gt; [   18.094746][    T1]  visual_init+0x3bb/0x7b0
<br>&gt; [   18.094786][    T1]  do_bind_con_driver+0x136e/0x1c90
<br>&gt; [   18.094834][    T1]  do_take_over_console+0xe0a/0xef0
<br>&gt; [   18.094875][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
<br>&gt; [   18.094907][    T1]  fbcon_fb_registered+0x51c/0xae0
<br>&gt; [   18.094954][    T1]  register_framebuffer+0xb68/0xfc0
<br>&gt; [   18.094999][    T1]  __drm_fb_helper_initial_config_and_unlock+=
0x17d2/0x2030
<br>&gt; [   18.095047][    T1]  drm_fbdev_client_hotplug+0x7a3/0xe80
<br>&gt; [   18.095085][    T1]  drm_fbdev_generic_setup+0x2b9/0x890
<br>&gt; [   18.095124][    T1]  bochs_pci_probe+0x7de/0x800
<br>&gt; [   18.095161][    T1]  ? qxl_gem_prime_mmap+0x30/0x30
<br>&gt; [   18.095193][    T1]  pci_device_probe+0x95f/0xc70
<br>&gt; [   18.095227][    T1]  ? pci_uevent+0x7b0/0x7b0
<br>&gt; [   18.095259][    T1]  really_probe+0x9af/0x20d0
<br>&gt; [   18.095298][    T1]  driver_probe_device+0x234/0x330
<br>&gt; [   18.095334][    T1]  device_driver_attach+0x1e8/0x3c0
<br>&gt; [   18.095370][    T1]  __driver_attach+0x30d/0x780
<br>&gt; [   18.095399][    T1]  ? klist_devices_get+0x10/0x60
<br>&gt; [   18.095431][    T1]  ? kmsan_get_metadata+0x116/0x180
<br>&gt; [   18.095463][    T1]  bus_for_each_dev+0x252/0x360
<br>&gt; [   18.095493][    T1]  ? driver_attach+0xa0/0xa0
<br>&gt; [   18.095527][    T1]  driver_attach+0x84/0xa0
<br>&gt; [   18.095558][    T1]  bus_add_driver+0x5d6/0xb00
<br>&gt; [   18.095596][    T1]  driver_register+0x30c/0x830
<br>&gt; [   18.095632][    T1]  __pci_register_driver+0x1fa/0x350
<br>&gt; [   18.095669][    T1]  bochs_init+0xd6/0x115
<br>&gt; [   18.095703][    T1]  do_one_initcall+0x246/0x7a0
<br>&gt; [   18.095734][    T1]  ? qxl_init+0x165/0x165
<br>&gt; [   18.095779][    T1]  ? kmsan_get_metadata+0x116/0x180
<br>&gt; [   18.095815][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
<br>&gt; [   18.095844][    T1]  ? qxl_init+0x165/0x165
<br>&gt; [   18.095878][    T1]  do_initcall_level+0x2b4/0x34a
<br>&gt; [   18.095913][    T1]  do_initcalls+0x123/0x1ba
<br>&gt; [   18.095947][    T1]  ? cpu_init_udelay+0xcf/0xcf
<br>&gt; [   18.095978][    T1]  do_basic_setup+0x2e/0x31
<br>&gt; [   18.096011][    T1]  kernel_init_freeable+0x23f/0x35f
<br>&gt; [   18.096049][    T1]  ? rest_init+0x1f0/0x1f0
<br>&gt; [   18.096080][    T1]  kernel_init+0x1a/0x670
<br>&gt; [   18.096111][    T1]  ? rest_init+0x1f0/0x1f0
<br>&gt; [   18.096141][    T1]  ret_from_fork+0x1f/0x30
<br>&gt; [   18.096166][    T1] Kernel panic - not syncing: panic_on_warn s=
et ...
<br>&gt; [   18.096192][    T1] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5=
.10.0-rc1 #2
<br>&gt; [   18.096208][    T1] Hardware name: QEMU Standard PC (i440FX + P=
IIX, 1996), BIOS 1.13.0-1ubuntu1 04/01/2014
<br>&gt; [   18.096219][    T1] Call Trace:
<br>&gt; [   18.096254][    T1]  dump_stack+0x189/0x218
<br>&gt; [   18.096287][    T1]  panic+0x38e/0xae4
<br>&gt; [   18.096335][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
<br>&gt; [   18.096364][    T1]  __warn+0x433/0x5c0
<br>&gt; [   18.096402][    T1]  ? drm_gem_vram_offset+0x128/0x140
<br>&gt; [   18.096434][    T1]  report_bug+0x669/0x880
<br>&gt; [   18.096474][    T1]  ? drm_gem_vram_offset+0x128/0x140
<br>&gt; [   18.096506][    T1]  handle_bug+0x6f/0xd0
<br>&gt; [   18.096537][    T1]  __exc_invalid_op+0x34/0x80
<br>&gt; [   18.096566][    T1]  exc_invalid_op+0x30/0x40
<br>&gt; [   18.096603][    T1]  asm_exc_invalid_op+0x12/0x20
<br>&gt; [   18.096640][    T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140
<br>&gt; [   18.096674][    T1] Code: 48 c7 c3 ed ff ff ff 31 c0 31 c9 eb b=
4 8b 7d d4 e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e fc 4d 85 ff 0f 8=
5 6e ff ff ff &lt;0f&gt; 0b 31 c0 31 c9 31 db eb 8d 8b 7d d4 e8 96 78 1e fc=
 e9 67 ff ff
<br>&gt; [   18.096693][    T1] RSP: 0000:ffff8880125a6718 EFLAGS: 00010246
<br>&gt; [   18.096721][    T1] RAX: 0000000000000000 RBX: ffff8880155efd80=
 RCX: 00000000151efd80
<br>&gt; [   18.096743][    T1] RDX: ffff8880151efd80 RSI: 0000000000000040=
 RDI: ffff8880155efd80
<br>&gt; [   18.096767][    T1] RBP: ffff8880125a6748 R08: ffffea000000000f=
 R09: ffff8880bffd2000
<br>&gt; [   18.096787][    T1] R10: 0000000000000004 R11: 00000000ffffffff=
 R12: ffff8880155efc00
<br>&gt; [   18.096807][    T1] R13: 0000000000000000 R14: ffff8880125b0a10=
 R15: 0000000000000000
<br>&gt; [   18.096849][    T1]  ? drm_gem_vram_offset+0x79/0x140
<br>&gt; [   18.096884][    T1]  bochs_pipe_enable+0x16f/0x3f0
<br>&gt; [   18.096927][    T1]  drm_simple_kms_crtc_enable+0x12e/0x1a0
<br>&gt; [   18.096964][    T1]  ? bochs_connector_get_modes+0x1e0/0x1e0
<br>&gt; [   18.097001][    T1]  ? drm_simple_kms_crtc_check+0x210/0x210
<br>&gt; [   18.097039][    T1]  drm_atomic_helper_commit_modeset_enables+0=
x362/0x1000
<br>&gt; [   18.097083][    T1]  drm_atomic_helper_commit_tail+0xd3/0x860
<br>&gt; [   18.097120][    T1]  ? kmsan_get_metadata+0x116/0x180
<br>&gt; [   18.097156][    T1]  commit_tail+0x61c/0x7d0
<br>&gt; [   18.097190][    T1]  ? kmsan_internal_set_origin+0x85/0xc0
<br>&gt; [   18.097230][    T1]  drm_atomic_helper_commit+0xbfe/0xcb0
<br>&gt; [   18.097267][    T1]  ? kmsan_get_metadata+0x116/0x180
<br>&gt; [   18.097305][    T1]  ? drm_atomic_helper_async_commit+0x780/0x7=
80
<br>&gt; [   18.097341][    T1]  drm_atomic_commit+0x192/0x210
<br>&gt; [   18.097378][    T1]  drm_client_modeset_commit_atomic+0x700/0xb=
e0
<br>&gt; [   18.097422][    T1]  drm_client_modeset_commit_locked+0x147/0x8=
60
<br>&gt; [   18.097459][    T1]  ? drm_master_internal_acquire+0x4a/0xd0
<br>&gt; [   18.097491][    T1]  drm_client_modeset_commit+0x98/0x110
<br>&gt; [   18.097528][    T1]  __drm_fb_helper_restore_fbdev_mode_unlocke=
d+0x1a7/0x2a0
<br>&gt; [   18.097562][    T1]  drm_fb_helper_set_par+0x12a/0x220
<br>&gt; [   18.097596][    T1]  ? drm_fb_helper_fill_pixel_fmt+0x780/0x780
<br>&gt; [   18.097621][    T1]  fbcon_init+0x1959/0x2910
<br>&gt; [   18.097660][    T1]  ? validate_slab+0x30/0x730
<br>&gt; [   18.097688][    T1]  ? fbcon_startup+0x1590/0x1590
<br>&gt; [   18.097719][    T1]  visual_init+0x3bb/0x7b0
<br>&gt; [   18.097758][    T1]  do_bind_con_driver+0x136e/0x1c90
<br>&gt; [   18.097807][    T1]  do_take_over_console+0xe0a/0xef0
<br>&gt; [   18.097848][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
<br>&gt; [   18.097879][    T1]  fbcon_fb_registered+0x51c/0xae0
<br>&gt; [   18.097917][    T1]  register_framebuffer+0xb68/0xfc0
<br>&gt; [   18.097961][    T1]  __drm_fb_helper_initial_config_and_unlock+=
0x17d2/0x2030
<br>&gt; [   18.098009][    T1]  drm_fbdev_client_hotplug+0x7a3/0xe80
<br>&gt; [   18.098047][    T1]  drm_fbdev_generic_setup+0x2b9/0x890
<br>&gt; [   18.098085][    T1]  bochs_pci_probe+0x7de/0x800
<br>&gt; [   18.098123][    T1]  ? qxl_gem_prime_mmap+0x30/0x30
<br>&gt; [   18.098152][    T1]  pci_device_probe+0x95f/0xc70
<br>&gt; [   18.098187][    T1]  ? pci_uevent+0x7b0/0x7b0
<br>&gt; [   18.098217][    T1]  really_probe+0x9af/0x20d0
<br>&gt; [   18.098255][    T1]  driver_probe_device+0x234/0x330
<br>&gt; [   18.098291][    T1]  device_driver_attach+0x1e8/0x3c0
<br>&gt; [   18.098326][    T1]  __driver_attach+0x30d/0x780
<br>&gt; [   18.098355][    T1]  ? klist_devices_get+0x10/0x60
<br>&gt; [   18.098388][    T1]  ? kmsan_get_metadata+0x116/0x180
<br>&gt; [   18.098419][    T1]  bus_for_each_dev+0x252/0x360
<br>&gt; [   18.098448][    T1]  ? driver_attach+0xa0/0xa0
<br>&gt; [   18.098482][    T1]  driver_attach+0x84/0xa0
<br>&gt; [   18.098512][    T1]  bus_add_driver+0x5d6/0xb00
<br>&gt; [   18.098550][    T1]  driver_register+0x30c/0x830
<br>&gt; [   18.098585][    T1]  __pci_register_driver+0x1fa/0x350
<br>&gt; [   18.098620][    T1]  bochs_init+0xd6/0x115
<br>&gt; [   18.098651][    T1]  do_one_initcall+0x246/0x7a0
<br>&gt; [   18.098680][    T1]  ? qxl_init+0x165/0x165
<br>&gt; [   18.098727][    T1]  ? kmsan_get_metadata+0x116/0x180
<br>&gt; [   18.098763][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
<br>&gt; [   18.098791][    T1]  ? qxl_init+0x165/0x165
<br>&gt; [   18.098824][    T1]  do_initcall_level+0x2b4/0x34a
<br>&gt; [   18.098859][    T1]  do_initcalls+0x123/0x1ba
<br>&gt; [   18.098890][    T1]  ? cpu_init_udelay+0xcf/0xcf
<br>&gt; [   18.098921][    T1]  do_basic_setup+0x2e/0x31
<br>&gt; [   18.098958][    T1]  kernel_init_freeable+0x23f/0x35f
<br>&gt; [   18.098993][    T1]  ? rest_init+0x1f0/0x1f0
<br>&gt; [   18.099024][    T1]  kernel_init+0x1a/0x670
<br>&gt; [   18.099054][    T1]  ? rest_init+0x1f0/0x1f0
<br>&gt; [   18.099085][    T1]  ret_from_fork+0x1f/0x30
<br>&gt; [   18.099240][    T1] Dumping ftrace buffer:
<br>&gt; [   18.099250][    T1]    (ftrace buffer empty)
<br>&gt; [   18.099250][    T1] Kernel Offset: disabled
<br>&gt; [   18.099250][    T1] Rebooting in 1 seconds..
<br>&gt; ```
<br>
<br>Hi,
<br>
<br>The WARNING does not look KMSAN-related, KMSAN is not in the stack and
<br>the subsystem is not KMSAN. Please report it to DRM maintainers.
<br></blockquote></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/a63a2733-1b7c-4bac-ad47-ea6e3999b953n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/a63a2733-1b7c-4bac-ad47-ea6e3999b953n%40googlegroups.com</a>.<b=
r />

------=_Part_1335_292298641.1605750806379--

------=_Part_1334_728886479.1605750806379--
