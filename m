Return-Path: <kasan-dev+bncBCH2XPOBSAERB6NGZD6QKGQE32DAYLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 52DE32B3CB4
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 06:51:54 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id e206sf6220859oib.0
        for <lists+kasan-dev@lfdr.de>; Sun, 15 Nov 2020 21:51:54 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VBqHJ0MP3t6nkVIjQ4cNazs/muHJsRacOaLHKW/Gv0I=;
        b=rOVs222hSNKxDJUiiI7q+IvfJBwJOk2Nnd/Gl1NnM15TDcc77GRITg4JkofseKgLCC
         OVMIBinZNw2B2BYpHxH3SGAqfxFUGmMyu62M/y0ZzLfKF9V7GyOy/R9kqtUhewQVSTQc
         izRGHdLIlzSG3ziCBXjR8fAj+38kaodazRTk0mtSau56A1EArRMxcL0GafgNxe9S/NGs
         BdfZEynDXQ/3BYwbaBtUwxJgyI3bSnm/YzXb9cVvpXQ+qCTZmjOUFnoyw24npS0C0dgg
         VU8e0CvD5Y1JdMH8Hp6/UJ8ZTfyFjFDq0HpnRzwrM4XwVA6G349R+IzPwoKbFmUFf6lE
         z4cg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:subject:mime-version:x-original-sender
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VBqHJ0MP3t6nkVIjQ4cNazs/muHJsRacOaLHKW/Gv0I=;
        b=lbAR6os7Fi+mOYvTvA9l594rxZZUK7WiEndti78kHP1kRddB1hb/MBhlBeAX5H3zQ5
         bWwMu54fZy3YhIaeKmHQbnGisBJir8gN1z91d9kRAxcMyQwLKp95d3trrCcvUemlAdBE
         G3gHZU8q74wIhJLa6qOcFNUOTS3V/YhAiuJBAZcuecb6IxH7x0aSEzCkBfPkJXrSpmug
         evZrdmHutcUF2SZCfVY21bkQfgzDDDgOtDUp5asRmceYFEHy+U1Te21/b9zFPs9FuJ7U
         g6AV/rdMgXCg8FtmRAxLF/HHLC0oVAPaS7KFi/O4DGyUDFOo5KQf+Cmz8It0l7rqbM5m
         VPQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VBqHJ0MP3t6nkVIjQ4cNazs/muHJsRacOaLHKW/Gv0I=;
        b=D8ovOInPsfIjU0+k5AnrsnRIOH2PY2ywCKLlhUzkjE5wWInRn9/zCtRph8LtHDZtpc
         IIpXZr9CmxUk/2gd5IdbumU36Q59bzjItJyhVXnO0957Y2aDjWQ7GQqLU3N1FPYRcdrx
         0xvhnPAL/L3QzG4ITHkKJvgMjqfJnr3U2qJtrAzcM/lctP7EM8nEQlUR+QH/l3Onwz3h
         qycHB6x5L26g0UlTNNINFvp+pUrRuSvy7ZtWumUWrmC/iJavfYrppTZsucSbL6L5l4PF
         Qql9fOY+aFsevUK10WbTNtRAoOWsbAoJExltfEJHU33E0f0D634KpqND8GzNI4yyqR/G
         pr7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531A7rgfNBiIZHTQPLqdtzF026HDp77O7FWeEdlvsFgiYkr61Myr
	8LIkw5Hh885/+a4isUUPw9w=
X-Google-Smtp-Source: ABdhPJz/16zbmHmgZJff8xVMRDuQS3SRovoTLOplsMLrfoBMVq99HSmdP2H3O6GzZYItPxgjh0jTbQ==
X-Received: by 2002:a4a:cf05:: with SMTP id l5mr9287960oos.7.1605505913164;
        Sun, 15 Nov 2020 21:51:53 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:7994:: with SMTP id h20ls3019982otm.2.gmail; Sun, 15 Nov
 2020 21:51:52 -0800 (PST)
X-Received: by 2002:a9d:4d17:: with SMTP id n23mr9026666otf.43.1605505912624;
        Sun, 15 Nov 2020 21:51:52 -0800 (PST)
Date: Sun, 15 Nov 2020 21:51:51 -0800 (PST)
From: "mudongl...@gmail.com" <mudongliangabcd@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <64637dc5-a480-4ae2-903e-9d70a7fdff98n@googlegroups.com>
Subject: KMSAN: WARNING at drivers/gpu/drm/drm_gem_vram_helper.c:284
 drm_gem_vram_offset
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_1637_1549063135.1605505911962"
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

------=_Part_1637_1549063135.1605505911962
Content-Type: multipart/alternative; 
	boundary="----=_Part_1638_992832524.1605505911962"

------=_Part_1638_992832524.1605505911962
Content-Type: text/plain; charset="UTF-8"

Hi all,

I built the kmsan with github kmsan repo HEAD, however, when I leveraged 
syzkaller to fuzz this kernel image, the VMs is always broken with the 
following WARNING report:

```
[   18.093341][    T1] ------------[ cut here ]------------
[   18.093419][    T1] WARNING: CPU: 1 PID: 1 at 
drivers/gpu/drm/drm_gem_vram_helper.c:284 drm_gem_vram_offset+0x128/0x140
[   18.093431][    T1] Modules linked in:
[   18.093472][    T1] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc1 
#2
[   18.093489][    T1] Hardware name: QEMU Standard PC (i440FX + PIIX, 
1996), BIOS 1.13.0-1ubuntu1 04/01/2014
[   18.093532][    T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140
[   18.093574][    T1] Code: 48 c7 c3 ed ff ff ff 31 c0 31 c9 eb b4 8b 7d 
d4 e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e fc 4d 85 ff 0f 85 6e ff 
ff ff <0f> 0b 31 c0 31 c9 31 db eb 8d 8b 7d d4 e8 96 78 1e fc e9 67 ff ff
[   18.093594][    T1] RSP: 0000:ffff8880125a6718 EFLAGS: 00010246
[   18.093622][    T1] RAX: 0000000000000000 RBX: ffff8880155efd80 RCX: 
00000000151efd80
[   18.093645][    T1] RDX: ffff8880151efd80 RSI: 0000000000000040 RDI: 
ffff8880155efd80
[   18.093669][    T1] RBP: ffff8880125a6748 R08: ffffea000000000f R09: 
ffff8880bffd2000
[   18.093691][    T1] R10: 0000000000000004 R11: 00000000ffffffff R12: 
ffff8880155efc00
[   18.093711][    T1] R13: 0000000000000000 R14: ffff8880125b0a10 R15: 
0000000000000000
[   18.093736][    T1] FS:  0000000000000000(0000) 
GS:ffff8880bfd00000(0000) knlGS:0000000000000000
[   18.093757][    T1] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[   18.093777][    T1] CR2: 0000000000000000 CR3: 0000000010229001 CR4: 
0000000000770ee0
[   18.093797][    T1] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 
0000000000000000
[   18.093816][    T1] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 
0000000000000400
[   18.093828][    T1] PKRU: 55555554
[   18.093839][    T1] Call Trace:
[   18.093886][    T1]  bochs_pipe_enable+0x16f/0x3f0
[   18.093935][    T1]  drm_simple_kms_crtc_enable+0x12e/0x1a0
[   18.093973][    T1]  ? bochs_connector_get_modes+0x1e0/0x1e0
[   18.094011][    T1]  ? drm_simple_kms_crtc_check+0x210/0x210
[   18.094049][    T1]  
drm_atomic_helper_commit_modeset_enables+0x362/0x1000
[   18.094095][    T1]  drm_atomic_helper_commit_tail+0xd3/0x860
[   18.094135][    T1]  ? kmsan_get_metadata+0x116/0x180
[   18.094171][    T1]  commit_tail+0x61c/0x7d0
[   18.094205][    T1]  ? kmsan_internal_set_origin+0x85/0xc0
[   18.094246][    T1]  drm_atomic_helper_commit+0xbfe/0xcb0
[   18.094284][    T1]  ? kmsan_get_metadata+0x116/0x180
[   18.094322][    T1]  ? drm_atomic_helper_async_commit+0x780/0x780
[   18.094361][    T1]  drm_atomic_commit+0x192/0x210
[   18.094400][    T1]  drm_client_modeset_commit_atomic+0x700/0xbe0
[   18.094444][    T1]  drm_client_modeset_commit_locked+0x147/0x860
[   18.094481][    T1]  ? drm_master_internal_acquire+0x4a/0xd0
[   18.094513][    T1]  drm_client_modeset_commit+0x98/0x110
[   18.094551][    T1]  
__drm_fb_helper_restore_fbdev_mode_unlocked+0x1a7/0x2a0
[   18.094586][    T1]  drm_fb_helper_set_par+0x12a/0x220
[   18.094620][    T1]  ? drm_fb_helper_fill_pixel_fmt+0x780/0x780
[   18.094646][    T1]  fbcon_init+0x1959/0x2910
[   18.094685][    T1]  ? validate_slab+0x30/0x730
[   18.094714][    T1]  ? fbcon_startup+0x1590/0x1590
[   18.094746][    T1]  visual_init+0x3bb/0x7b0
[   18.094786][    T1]  do_bind_con_driver+0x136e/0x1c90
[   18.094834][    T1]  do_take_over_console+0xe0a/0xef0
[   18.094875][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
[   18.094907][    T1]  fbcon_fb_registered+0x51c/0xae0
[   18.094954][    T1]  register_framebuffer+0xb68/0xfc0
[   18.094999][    T1]  
__drm_fb_helper_initial_config_and_unlock+0x17d2/0x2030
[   18.095047][    T1]  drm_fbdev_client_hotplug+0x7a3/0xe80
[   18.095085][    T1]  drm_fbdev_generic_setup+0x2b9/0x890
[   18.095124][    T1]  bochs_pci_probe+0x7de/0x800
[   18.095161][    T1]  ? qxl_gem_prime_mmap+0x30/0x30
[   18.095193][    T1]  pci_device_probe+0x95f/0xc70
[   18.095227][    T1]  ? pci_uevent+0x7b0/0x7b0
[   18.095259][    T1]  really_probe+0x9af/0x20d0
[   18.095298][    T1]  driver_probe_device+0x234/0x330
[   18.095334][    T1]  device_driver_attach+0x1e8/0x3c0
[   18.095370][    T1]  __driver_attach+0x30d/0x780
[   18.095399][    T1]  ? klist_devices_get+0x10/0x60
[   18.095431][    T1]  ? kmsan_get_metadata+0x116/0x180
[   18.095463][    T1]  bus_for_each_dev+0x252/0x360
[   18.095493][    T1]  ? driver_attach+0xa0/0xa0
[   18.095527][    T1]  driver_attach+0x84/0xa0
[   18.095558][    T1]  bus_add_driver+0x5d6/0xb00
[   18.095596][    T1]  driver_register+0x30c/0x830
[   18.095632][    T1]  __pci_register_driver+0x1fa/0x350
[   18.095669][    T1]  bochs_init+0xd6/0x115
[   18.095703][    T1]  do_one_initcall+0x246/0x7a0
[   18.095734][    T1]  ? qxl_init+0x165/0x165
[   18.095779][    T1]  ? kmsan_get_metadata+0x116/0x180
[   18.095815][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
[   18.095844][    T1]  ? qxl_init+0x165/0x165
[   18.095878][    T1]  do_initcall_level+0x2b4/0x34a
[   18.095913][    T1]  do_initcalls+0x123/0x1ba
[   18.095947][    T1]  ? cpu_init_udelay+0xcf/0xcf
[   18.095978][    T1]  do_basic_setup+0x2e/0x31
[   18.096011][    T1]  kernel_init_freeable+0x23f/0x35f
[   18.096049][    T1]  ? rest_init+0x1f0/0x1f0
[   18.096080][    T1]  kernel_init+0x1a/0x670
[   18.096111][    T1]  ? rest_init+0x1f0/0x1f0
[   18.096141][    T1]  ret_from_fork+0x1f/0x30
[   18.096166][    T1] Kernel panic - not syncing: panic_on_warn set ...
[   18.096192][    T1] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc1 
#2
[   18.096208][    T1] Hardware name: QEMU Standard PC (i440FX + PIIX, 
1996), BIOS 1.13.0-1ubuntu1 04/01/2014
[   18.096219][    T1] Call Trace:
[   18.096254][    T1]  dump_stack+0x189/0x218
[   18.096287][    T1]  panic+0x38e/0xae4
[   18.096335][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
[   18.096364][    T1]  __warn+0x433/0x5c0
[   18.096402][    T1]  ? drm_gem_vram_offset+0x128/0x140
[   18.096434][    T1]  report_bug+0x669/0x880
[   18.096474][    T1]  ? drm_gem_vram_offset+0x128/0x140
[   18.096506][    T1]  handle_bug+0x6f/0xd0
[   18.096537][    T1]  __exc_invalid_op+0x34/0x80
[   18.096566][    T1]  exc_invalid_op+0x30/0x40
[   18.096603][    T1]  asm_exc_invalid_op+0x12/0x20
[   18.096640][    T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140
[   18.096674][    T1] Code: 48 c7 c3 ed ff ff ff 31 c0 31 c9 eb b4 8b 7d 
d4 e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e fc 4d 85 ff 0f 85 6e ff 
ff ff <0f> 0b 31 c0 31 c9 31 db eb 8d 8b 7d d4 e8 96 78 1e fc e9 67 ff ff
[   18.096693][    T1] RSP: 0000:ffff8880125a6718 EFLAGS: 00010246
[   18.096721][    T1] RAX: 0000000000000000 RBX: ffff8880155efd80 RCX: 
00000000151efd80
[   18.096743][    T1] RDX: ffff8880151efd80 RSI: 0000000000000040 RDI: 
ffff8880155efd80
[   18.096767][    T1] RBP: ffff8880125a6748 R08: ffffea000000000f R09: 
ffff8880bffd2000
[   18.096787][    T1] R10: 0000000000000004 R11: 00000000ffffffff R12: 
ffff8880155efc00
[   18.096807][    T1] R13: 0000000000000000 R14: ffff8880125b0a10 R15: 
0000000000000000
[   18.096849][    T1]  ? drm_gem_vram_offset+0x79/0x140
[   18.096884][    T1]  bochs_pipe_enable+0x16f/0x3f0
[   18.096927][    T1]  drm_simple_kms_crtc_enable+0x12e/0x1a0
[   18.096964][    T1]  ? bochs_connector_get_modes+0x1e0/0x1e0
[   18.097001][    T1]  ? drm_simple_kms_crtc_check+0x210/0x210
[   18.097039][    T1]  
drm_atomic_helper_commit_modeset_enables+0x362/0x1000
[   18.097083][    T1]  drm_atomic_helper_commit_tail+0xd3/0x860
[   18.097120][    T1]  ? kmsan_get_metadata+0x116/0x180
[   18.097156][    T1]  commit_tail+0x61c/0x7d0
[   18.097190][    T1]  ? kmsan_internal_set_origin+0x85/0xc0
[   18.097230][    T1]  drm_atomic_helper_commit+0xbfe/0xcb0
[   18.097267][    T1]  ? kmsan_get_metadata+0x116/0x180
[   18.097305][    T1]  ? drm_atomic_helper_async_commit+0x780/0x780
[   18.097341][    T1]  drm_atomic_commit+0x192/0x210
[   18.097378][    T1]  drm_client_modeset_commit_atomic+0x700/0xbe0
[   18.097422][    T1]  drm_client_modeset_commit_locked+0x147/0x860
[   18.097459][    T1]  ? drm_master_internal_acquire+0x4a/0xd0
[   18.097491][    T1]  drm_client_modeset_commit+0x98/0x110
[   18.097528][    T1]  
__drm_fb_helper_restore_fbdev_mode_unlocked+0x1a7/0x2a0
[   18.097562][    T1]  drm_fb_helper_set_par+0x12a/0x220
[   18.097596][    T1]  ? drm_fb_helper_fill_pixel_fmt+0x780/0x780
[   18.097621][    T1]  fbcon_init+0x1959/0x2910
[   18.097660][    T1]  ? validate_slab+0x30/0x730
[   18.097688][    T1]  ? fbcon_startup+0x1590/0x1590
[   18.097719][    T1]  visual_init+0x3bb/0x7b0
[   18.097758][    T1]  do_bind_con_driver+0x136e/0x1c90
[   18.097807][    T1]  do_take_over_console+0xe0a/0xef0
[   18.097848][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
[   18.097879][    T1]  fbcon_fb_registered+0x51c/0xae0
[   18.097917][    T1]  register_framebuffer+0xb68/0xfc0
[   18.097961][    T1]  
__drm_fb_helper_initial_config_and_unlock+0x17d2/0x2030
[   18.098009][    T1]  drm_fbdev_client_hotplug+0x7a3/0xe80
[   18.098047][    T1]  drm_fbdev_generic_setup+0x2b9/0x890
[   18.098085][    T1]  bochs_pci_probe+0x7de/0x800
[   18.098123][    T1]  ? qxl_gem_prime_mmap+0x30/0x30
[   18.098152][    T1]  pci_device_probe+0x95f/0xc70
[   18.098187][    T1]  ? pci_uevent+0x7b0/0x7b0
[   18.098217][    T1]  really_probe+0x9af/0x20d0
[   18.098255][    T1]  driver_probe_device+0x234/0x330
[   18.098291][    T1]  device_driver_attach+0x1e8/0x3c0
[   18.098326][    T1]  __driver_attach+0x30d/0x780
[   18.098355][    T1]  ? klist_devices_get+0x10/0x60
[   18.098388][    T1]  ? kmsan_get_metadata+0x116/0x180
[   18.098419][    T1]  bus_for_each_dev+0x252/0x360
[   18.098448][    T1]  ? driver_attach+0xa0/0xa0
[   18.098482][    T1]  driver_attach+0x84/0xa0
[   18.098512][    T1]  bus_add_driver+0x5d6/0xb00
[   18.098550][    T1]  driver_register+0x30c/0x830
[   18.098585][    T1]  __pci_register_driver+0x1fa/0x350
[   18.098620][    T1]  bochs_init+0xd6/0x115
[   18.098651][    T1]  do_one_initcall+0x246/0x7a0
[   18.098680][    T1]  ? qxl_init+0x165/0x165
[   18.098727][    T1]  ? kmsan_get_metadata+0x116/0x180
[   18.098763][    T1]  ? kmsan_get_shadow_origin_ptr+0x84/0xb0
[   18.098791][    T1]  ? qxl_init+0x165/0x165
[   18.098824][    T1]  do_initcall_level+0x2b4/0x34a
[   18.098859][    T1]  do_initcalls+0x123/0x1ba
[   18.098890][    T1]  ? cpu_init_udelay+0xcf/0xcf
[   18.098921][    T1]  do_basic_setup+0x2e/0x31
[   18.098958][    T1]  kernel_init_freeable+0x23f/0x35f
[   18.098993][    T1]  ? rest_init+0x1f0/0x1f0
[   18.099024][    T1]  kernel_init+0x1a/0x670
[   18.099054][    T1]  ? rest_init+0x1f0/0x1f0
[   18.099085][    T1]  ret_from_fork+0x1f/0x30
[   18.099240][    T1] Dumping ftrace buffer:
[   18.099250][    T1]    (ftrace buffer empty)
[   18.099250][    T1] Kernel Offset: disabled
[   18.099250][    T1] Rebooting in 1 seconds..
```


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/64637dc5-a480-4ae2-903e-9d70a7fdff98n%40googlegroups.com.

------=_Part_1638_992832524.1605505911962
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div>Hi all,</div><div><br></div><div>I built the kmsan with github kmsan r=
epo HEAD, however, when I leveraged syzkaller to fuzz this kernel image, th=
e VMs is always broken with the following WARNING report:</div><div><br></d=
iv><div>```</div><div>[&nbsp; &nbsp;18.093341][&nbsp; &nbsp; T1] ----------=
--[ cut here ]------------</div><div>[&nbsp; &nbsp;18.093419][&nbsp; &nbsp;=
 T1] WARNING: CPU: 1 PID: 1 at drivers/gpu/drm/drm_gem_vram_helper.c:284 dr=
m_gem_vram_offset+0x128/0x140</div><div>[&nbsp; &nbsp;18.093431][&nbsp; &nb=
sp; T1] Modules linked in:</div><div>[&nbsp; &nbsp;18.093472][&nbsp; &nbsp;=
 T1] CPU: 1 PID: 1 Comm: swapper/0 Not tainted 5.10.0-rc1 #2</div><div>[&nb=
sp; &nbsp;18.093489][&nbsp; &nbsp; T1] Hardware name: QEMU Standard PC (i44=
0FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1 04/01/2014</div><div>[&nbsp; &nbsp;=
18.093532][&nbsp; &nbsp; T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140</div=
><div>[&nbsp; &nbsp;18.093574][&nbsp; &nbsp; T1] Code: 48 c7 c3 ed ff ff ff=
 31 c0 31 c9 eb b4 8b 7d d4 e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e=
 fc 4d 85 ff 0f 85 6e ff ff ff &lt;0f&gt; 0b 31 c0 31 c9 31 db eb 8d 8b 7d =
d4 e8 96 78 1e fc e9 67 ff ff</div><div>[&nbsp; &nbsp;18.093594][&nbsp; &nb=
sp; T1] RSP: 0000:ffff8880125a6718 EFLAGS: 00010246</div><div>[&nbsp; &nbsp=
;18.093622][&nbsp; &nbsp; T1] RAX: 0000000000000000 RBX: ffff8880155efd80 R=
CX: 00000000151efd80</div><div>[&nbsp; &nbsp;18.093645][&nbsp; &nbsp; T1] R=
DX: ffff8880151efd80 RSI: 0000000000000040 RDI: ffff8880155efd80</div><div>=
[&nbsp; &nbsp;18.093669][&nbsp; &nbsp; T1] RBP: ffff8880125a6748 R08: ffffe=
a000000000f R09: ffff8880bffd2000</div><div>[&nbsp; &nbsp;18.093691][&nbsp;=
 &nbsp; T1] R10: 0000000000000004 R11: 00000000ffffffff R12: ffff8880155efc=
00</div><div>[&nbsp; &nbsp;18.093711][&nbsp; &nbsp; T1] R13: 00000000000000=
00 R14: ffff8880125b0a10 R15: 0000000000000000</div><div>[&nbsp; &nbsp;18.0=
93736][&nbsp; &nbsp; T1] FS:&nbsp; 0000000000000000(0000) GS:ffff8880bfd000=
00(0000) knlGS:0000000000000000</div><div>[&nbsp; &nbsp;18.093757][&nbsp; &=
nbsp; T1] CS:&nbsp; 0010 DS: 0000 ES: 0000 CR0: 0000000080050033</div><div>=
[&nbsp; &nbsp;18.093777][&nbsp; &nbsp; T1] CR2: 0000000000000000 CR3: 00000=
00010229001 CR4: 0000000000770ee0</div><div>[&nbsp; &nbsp;18.093797][&nbsp;=
 &nbsp; T1] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 00000000000000=
00</div><div>[&nbsp; &nbsp;18.093816][&nbsp; &nbsp; T1] DR3: 00000000000000=
00 DR6: 00000000fffe0ff0 DR7: 0000000000000400</div><div>[&nbsp; &nbsp;18.0=
93828][&nbsp; &nbsp; T1] PKRU: 55555554</div><div>[&nbsp; &nbsp;18.093839][=
&nbsp; &nbsp; T1] Call Trace:</div><div>[&nbsp; &nbsp;18.093886][&nbsp; &nb=
sp; T1]&nbsp; bochs_pipe_enable+0x16f/0x3f0</div><div>[&nbsp; &nbsp;18.0939=
35][&nbsp; &nbsp; T1]&nbsp; drm_simple_kms_crtc_enable+0x12e/0x1a0</div><di=
v>[&nbsp; &nbsp;18.093973][&nbsp; &nbsp; T1]&nbsp; ? bochs_connector_get_mo=
des+0x1e0/0x1e0</div><div>[&nbsp; &nbsp;18.094011][&nbsp; &nbsp; T1]&nbsp; =
? drm_simple_kms_crtc_check+0x210/0x210</div><div>[&nbsp; &nbsp;18.094049][=
&nbsp; &nbsp; T1]&nbsp; drm_atomic_helper_commit_modeset_enables+0x362/0x10=
00</div><div>[&nbsp; &nbsp;18.094095][&nbsp; &nbsp; T1]&nbsp; drm_atomic_he=
lper_commit_tail+0xd3/0x860</div><div>[&nbsp; &nbsp;18.094135][&nbsp; &nbsp=
; T1]&nbsp; ? kmsan_get_metadata+0x116/0x180</div><div>[&nbsp; &nbsp;18.094=
171][&nbsp; &nbsp; T1]&nbsp; commit_tail+0x61c/0x7d0</div><div>[&nbsp; &nbs=
p;18.094205][&nbsp; &nbsp; T1]&nbsp; ? kmsan_internal_set_origin+0x85/0xc0<=
/div><div>[&nbsp; &nbsp;18.094246][&nbsp; &nbsp; T1]&nbsp; drm_atomic_helpe=
r_commit+0xbfe/0xcb0</div><div>[&nbsp; &nbsp;18.094284][&nbsp; &nbsp; T1]&n=
bsp; ? kmsan_get_metadata+0x116/0x180</div><div>[&nbsp; &nbsp;18.094322][&n=
bsp; &nbsp; T1]&nbsp; ? drm_atomic_helper_async_commit+0x780/0x780</div><di=
v>[&nbsp; &nbsp;18.094361][&nbsp; &nbsp; T1]&nbsp; drm_atomic_commit+0x192/=
0x210</div><div>[&nbsp; &nbsp;18.094400][&nbsp; &nbsp; T1]&nbsp; drm_client=
_modeset_commit_atomic+0x700/0xbe0</div><div>[&nbsp; &nbsp;18.094444][&nbsp=
; &nbsp; T1]&nbsp; drm_client_modeset_commit_locked+0x147/0x860</div><div>[=
&nbsp; &nbsp;18.094481][&nbsp; &nbsp; T1]&nbsp; ? drm_master_internal_acqui=
re+0x4a/0xd0</div><div>[&nbsp; &nbsp;18.094513][&nbsp; &nbsp; T1]&nbsp; drm=
_client_modeset_commit+0x98/0x110</div><div>[&nbsp; &nbsp;18.094551][&nbsp;=
 &nbsp; T1]&nbsp; __drm_fb_helper_restore_fbdev_mode_unlocked+0x1a7/0x2a0</=
div><div>[&nbsp; &nbsp;18.094586][&nbsp; &nbsp; T1]&nbsp; drm_fb_helper_set=
_par+0x12a/0x220</div><div>[&nbsp; &nbsp;18.094620][&nbsp; &nbsp; T1]&nbsp;=
 ? drm_fb_helper_fill_pixel_fmt+0x780/0x780</div><div>[&nbsp; &nbsp;18.0946=
46][&nbsp; &nbsp; T1]&nbsp; fbcon_init+0x1959/0x2910</div><div>[&nbsp; &nbs=
p;18.094685][&nbsp; &nbsp; T1]&nbsp; ? validate_slab+0x30/0x730</div><div>[=
&nbsp; &nbsp;18.094714][&nbsp; &nbsp; T1]&nbsp; ? fbcon_startup+0x1590/0x15=
90</div><div>[&nbsp; &nbsp;18.094746][&nbsp; &nbsp; T1]&nbsp; visual_init+0=
x3bb/0x7b0</div><div>[&nbsp; &nbsp;18.094786][&nbsp; &nbsp; T1]&nbsp; do_bi=
nd_con_driver+0x136e/0x1c90</div><div>[&nbsp; &nbsp;18.094834][&nbsp; &nbsp=
; T1]&nbsp; do_take_over_console+0xe0a/0xef0</div><div>[&nbsp; &nbsp;18.094=
875][&nbsp; &nbsp; T1]&nbsp; ? kmsan_get_shadow_origin_ptr+0x84/0xb0</div><=
div>[&nbsp; &nbsp;18.094907][&nbsp; &nbsp; T1]&nbsp; fbcon_fb_registered+0x=
51c/0xae0</div><div>[&nbsp; &nbsp;18.094954][&nbsp; &nbsp; T1]&nbsp; regist=
er_framebuffer+0xb68/0xfc0</div><div>[&nbsp; &nbsp;18.094999][&nbsp; &nbsp;=
 T1]&nbsp; __drm_fb_helper_initial_config_and_unlock+0x17d2/0x2030</div><di=
v>[&nbsp; &nbsp;18.095047][&nbsp; &nbsp; T1]&nbsp; drm_fbdev_client_hotplug=
+0x7a3/0xe80</div><div>[&nbsp; &nbsp;18.095085][&nbsp; &nbsp; T1]&nbsp; drm=
_fbdev_generic_setup+0x2b9/0x890</div><div>[&nbsp; &nbsp;18.095124][&nbsp; =
&nbsp; T1]&nbsp; bochs_pci_probe+0x7de/0x800</div><div>[&nbsp; &nbsp;18.095=
161][&nbsp; &nbsp; T1]&nbsp; ? qxl_gem_prime_mmap+0x30/0x30</div><div>[&nbs=
p; &nbsp;18.095193][&nbsp; &nbsp; T1]&nbsp; pci_device_probe+0x95f/0xc70</d=
iv><div>[&nbsp; &nbsp;18.095227][&nbsp; &nbsp; T1]&nbsp; ? pci_uevent+0x7b0=
/0x7b0</div><div>[&nbsp; &nbsp;18.095259][&nbsp; &nbsp; T1]&nbsp; really_pr=
obe+0x9af/0x20d0</div><div>[&nbsp; &nbsp;18.095298][&nbsp; &nbsp; T1]&nbsp;=
 driver_probe_device+0x234/0x330</div><div>[&nbsp; &nbsp;18.095334][&nbsp; =
&nbsp; T1]&nbsp; device_driver_attach+0x1e8/0x3c0</div><div>[&nbsp; &nbsp;1=
8.095370][&nbsp; &nbsp; T1]&nbsp; __driver_attach+0x30d/0x780</div><div>[&n=
bsp; &nbsp;18.095399][&nbsp; &nbsp; T1]&nbsp; ? klist_devices_get+0x10/0x60=
</div><div>[&nbsp; &nbsp;18.095431][&nbsp; &nbsp; T1]&nbsp; ? kmsan_get_met=
adata+0x116/0x180</div><div>[&nbsp; &nbsp;18.095463][&nbsp; &nbsp; T1]&nbsp=
; bus_for_each_dev+0x252/0x360</div><div>[&nbsp; &nbsp;18.095493][&nbsp; &n=
bsp; T1]&nbsp; ? driver_attach+0xa0/0xa0</div><div>[&nbsp; &nbsp;18.095527]=
[&nbsp; &nbsp; T1]&nbsp; driver_attach+0x84/0xa0</div><div>[&nbsp; &nbsp;18=
.095558][&nbsp; &nbsp; T1]&nbsp; bus_add_driver+0x5d6/0xb00</div><div>[&nbs=
p; &nbsp;18.095596][&nbsp; &nbsp; T1]&nbsp; driver_register+0x30c/0x830</di=
v><div>[&nbsp; &nbsp;18.095632][&nbsp; &nbsp; T1]&nbsp; __pci_register_driv=
er+0x1fa/0x350</div><div>[&nbsp; &nbsp;18.095669][&nbsp; &nbsp; T1]&nbsp; b=
ochs_init+0xd6/0x115</div><div>[&nbsp; &nbsp;18.095703][&nbsp; &nbsp; T1]&n=
bsp; do_one_initcall+0x246/0x7a0</div><div>[&nbsp; &nbsp;18.095734][&nbsp; =
&nbsp; T1]&nbsp; ? qxl_init+0x165/0x165</div><div>[&nbsp; &nbsp;18.095779][=
&nbsp; &nbsp; T1]&nbsp; ? kmsan_get_metadata+0x116/0x180</div><div>[&nbsp; =
&nbsp;18.095815][&nbsp; &nbsp; T1]&nbsp; ? kmsan_get_shadow_origin_ptr+0x84=
/0xb0</div><div>[&nbsp; &nbsp;18.095844][&nbsp; &nbsp; T1]&nbsp; ? qxl_init=
+0x165/0x165</div><div>[&nbsp; &nbsp;18.095878][&nbsp; &nbsp; T1]&nbsp; do_=
initcall_level+0x2b4/0x34a</div><div>[&nbsp; &nbsp;18.095913][&nbsp; &nbsp;=
 T1]&nbsp; do_initcalls+0x123/0x1ba</div><div>[&nbsp; &nbsp;18.095947][&nbs=
p; &nbsp; T1]&nbsp; ? cpu_init_udelay+0xcf/0xcf</div><div>[&nbsp; &nbsp;18.=
095978][&nbsp; &nbsp; T1]&nbsp; do_basic_setup+0x2e/0x31</div><div>[&nbsp; =
&nbsp;18.096011][&nbsp; &nbsp; T1]&nbsp; kernel_init_freeable+0x23f/0x35f</=
div><div>[&nbsp; &nbsp;18.096049][&nbsp; &nbsp; T1]&nbsp; ? rest_init+0x1f0=
/0x1f0</div><div>[&nbsp; &nbsp;18.096080][&nbsp; &nbsp; T1]&nbsp; kernel_in=
it+0x1a/0x670</div><div>[&nbsp; &nbsp;18.096111][&nbsp; &nbsp; T1]&nbsp; ? =
rest_init+0x1f0/0x1f0</div><div>[&nbsp; &nbsp;18.096141][&nbsp; &nbsp; T1]&=
nbsp; ret_from_fork+0x1f/0x30</div><div>[&nbsp; &nbsp;18.096166][&nbsp; &nb=
sp; T1] Kernel panic - not syncing: panic_on_warn set ...</div><div>[&nbsp;=
 &nbsp;18.096192][&nbsp; &nbsp; T1] CPU: 1 PID: 1 Comm: swapper/0 Not taint=
ed 5.10.0-rc1 #2</div><div>[&nbsp; &nbsp;18.096208][&nbsp; &nbsp; T1] Hardw=
are name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1 04/0=
1/2014</div><div>[&nbsp; &nbsp;18.096219][&nbsp; &nbsp; T1] Call Trace:</di=
v><div>[&nbsp; &nbsp;18.096254][&nbsp; &nbsp; T1]&nbsp; dump_stack+0x189/0x=
218</div><div>[&nbsp; &nbsp;18.096287][&nbsp; &nbsp; T1]&nbsp; panic+0x38e/=
0xae4</div><div>[&nbsp; &nbsp;18.096335][&nbsp; &nbsp; T1]&nbsp; ? kmsan_ge=
t_shadow_origin_ptr+0x84/0xb0</div><div>[&nbsp; &nbsp;18.096364][&nbsp; &nb=
sp; T1]&nbsp; __warn+0x433/0x5c0</div><div>[&nbsp; &nbsp;18.096402][&nbsp; =
&nbsp; T1]&nbsp; ? drm_gem_vram_offset+0x128/0x140</div><div>[&nbsp; &nbsp;=
18.096434][&nbsp; &nbsp; T1]&nbsp; report_bug+0x669/0x880</div><div>[&nbsp;=
 &nbsp;18.096474][&nbsp; &nbsp; T1]&nbsp; ? drm_gem_vram_offset+0x128/0x140=
</div><div>[&nbsp; &nbsp;18.096506][&nbsp; &nbsp; T1]&nbsp; handle_bug+0x6f=
/0xd0</div><div>[&nbsp; &nbsp;18.096537][&nbsp; &nbsp; T1]&nbsp; __exc_inva=
lid_op+0x34/0x80</div><div>[&nbsp; &nbsp;18.096566][&nbsp; &nbsp; T1]&nbsp;=
 exc_invalid_op+0x30/0x40</div><div>[&nbsp; &nbsp;18.096603][&nbsp; &nbsp; =
T1]&nbsp; asm_exc_invalid_op+0x12/0x20</div><div>[&nbsp; &nbsp;18.096640][&=
nbsp; &nbsp; T1] RIP: 0010:drm_gem_vram_offset+0x128/0x140</div><div>[&nbsp=
; &nbsp;18.096674][&nbsp; &nbsp; T1] Code: 48 c7 c3 ed ff ff ff 31 c0 31 c9=
 eb b4 8b 7d d4 e8 bd 78 1e fc e9 56 ff ff ff 8b 3a e8 b1 78 1e fc 4d 85 ff=
 0f 85 6e ff ff ff &lt;0f&gt; 0b 31 c0 31 c9 31 db eb 8d 8b 7d d4 e8 96 78 =
1e fc e9 67 ff ff</div><div>[&nbsp; &nbsp;18.096693][&nbsp; &nbsp; T1] RSP:=
 0000:ffff8880125a6718 EFLAGS: 00010246</div><div>[&nbsp; &nbsp;18.096721][=
&nbsp; &nbsp; T1] RAX: 0000000000000000 RBX: ffff8880155efd80 RCX: 00000000=
151efd80</div><div>[&nbsp; &nbsp;18.096743][&nbsp; &nbsp; T1] RDX: ffff8880=
151efd80 RSI: 0000000000000040 RDI: ffff8880155efd80</div><div>[&nbsp; &nbs=
p;18.096767][&nbsp; &nbsp; T1] RBP: ffff8880125a6748 R08: ffffea000000000f =
R09: ffff8880bffd2000</div><div>[&nbsp; &nbsp;18.096787][&nbsp; &nbsp; T1] =
R10: 0000000000000004 R11: 00000000ffffffff R12: ffff8880155efc00</div><div=
>[&nbsp; &nbsp;18.096807][&nbsp; &nbsp; T1] R13: 0000000000000000 R14: ffff=
8880125b0a10 R15: 0000000000000000</div><div>[&nbsp; &nbsp;18.096849][&nbsp=
; &nbsp; T1]&nbsp; ? drm_gem_vram_offset+0x79/0x140</div><div>[&nbsp; &nbsp=
;18.096884][&nbsp; &nbsp; T1]&nbsp; bochs_pipe_enable+0x16f/0x3f0</div><div=
>[&nbsp; &nbsp;18.096927][&nbsp; &nbsp; T1]&nbsp; drm_simple_kms_crtc_enabl=
e+0x12e/0x1a0</div><div>[&nbsp; &nbsp;18.096964][&nbsp; &nbsp; T1]&nbsp; ? =
bochs_connector_get_modes+0x1e0/0x1e0</div><div>[&nbsp; &nbsp;18.097001][&n=
bsp; &nbsp; T1]&nbsp; ? drm_simple_kms_crtc_check+0x210/0x210</div><div>[&n=
bsp; &nbsp;18.097039][&nbsp; &nbsp; T1]&nbsp; drm_atomic_helper_commit_mode=
set_enables+0x362/0x1000</div><div>[&nbsp; &nbsp;18.097083][&nbsp; &nbsp; T=
1]&nbsp; drm_atomic_helper_commit_tail+0xd3/0x860</div><div>[&nbsp; &nbsp;1=
8.097120][&nbsp; &nbsp; T1]&nbsp; ? kmsan_get_metadata+0x116/0x180</div><di=
v>[&nbsp; &nbsp;18.097156][&nbsp; &nbsp; T1]&nbsp; commit_tail+0x61c/0x7d0<=
/div><div>[&nbsp; &nbsp;18.097190][&nbsp; &nbsp; T1]&nbsp; ? kmsan_internal=
_set_origin+0x85/0xc0</div><div>[&nbsp; &nbsp;18.097230][&nbsp; &nbsp; T1]&=
nbsp; drm_atomic_helper_commit+0xbfe/0xcb0</div><div>[&nbsp; &nbsp;18.09726=
7][&nbsp; &nbsp; T1]&nbsp; ? kmsan_get_metadata+0x116/0x180</div><div>[&nbs=
p; &nbsp;18.097305][&nbsp; &nbsp; T1]&nbsp; ? drm_atomic_helper_async_commi=
t+0x780/0x780</div><div>[&nbsp; &nbsp;18.097341][&nbsp; &nbsp; T1]&nbsp; dr=
m_atomic_commit+0x192/0x210</div><div>[&nbsp; &nbsp;18.097378][&nbsp; &nbsp=
; T1]&nbsp; drm_client_modeset_commit_atomic+0x700/0xbe0</div><div>[&nbsp; =
&nbsp;18.097422][&nbsp; &nbsp; T1]&nbsp; drm_client_modeset_commit_locked+0=
x147/0x860</div><div>[&nbsp; &nbsp;18.097459][&nbsp; &nbsp; T1]&nbsp; ? drm=
_master_internal_acquire+0x4a/0xd0</div><div>[&nbsp; &nbsp;18.097491][&nbsp=
; &nbsp; T1]&nbsp; drm_client_modeset_commit+0x98/0x110</div><div>[&nbsp; &=
nbsp;18.097528][&nbsp; &nbsp; T1]&nbsp; __drm_fb_helper_restore_fbdev_mode_=
unlocked+0x1a7/0x2a0</div><div>[&nbsp; &nbsp;18.097562][&nbsp; &nbsp; T1]&n=
bsp; drm_fb_helper_set_par+0x12a/0x220</div><div>[&nbsp; &nbsp;18.097596][&=
nbsp; &nbsp; T1]&nbsp; ? drm_fb_helper_fill_pixel_fmt+0x780/0x780</div><div=
>[&nbsp; &nbsp;18.097621][&nbsp; &nbsp; T1]&nbsp; fbcon_init+0x1959/0x2910<=
/div><div>[&nbsp; &nbsp;18.097660][&nbsp; &nbsp; T1]&nbsp; ? validate_slab+=
0x30/0x730</div><div>[&nbsp; &nbsp;18.097688][&nbsp; &nbsp; T1]&nbsp; ? fbc=
on_startup+0x1590/0x1590</div><div>[&nbsp; &nbsp;18.097719][&nbsp; &nbsp; T=
1]&nbsp; visual_init+0x3bb/0x7b0</div><div>[&nbsp; &nbsp;18.097758][&nbsp; =
&nbsp; T1]&nbsp; do_bind_con_driver+0x136e/0x1c90</div><div>[&nbsp; &nbsp;1=
8.097807][&nbsp; &nbsp; T1]&nbsp; do_take_over_console+0xe0a/0xef0</div><di=
v>[&nbsp; &nbsp;18.097848][&nbsp; &nbsp; T1]&nbsp; ? kmsan_get_shadow_origi=
n_ptr+0x84/0xb0</div><div>[&nbsp; &nbsp;18.097879][&nbsp; &nbsp; T1]&nbsp; =
fbcon_fb_registered+0x51c/0xae0</div><div>[&nbsp; &nbsp;18.097917][&nbsp; &=
nbsp; T1]&nbsp; register_framebuffer+0xb68/0xfc0</div><div>[&nbsp; &nbsp;18=
.097961][&nbsp; &nbsp; T1]&nbsp; __drm_fb_helper_initial_config_and_unlock+=
0x17d2/0x2030</div><div>[&nbsp; &nbsp;18.098009][&nbsp; &nbsp; T1]&nbsp; dr=
m_fbdev_client_hotplug+0x7a3/0xe80</div><div>[&nbsp; &nbsp;18.098047][&nbsp=
; &nbsp; T1]&nbsp; drm_fbdev_generic_setup+0x2b9/0x890</div><div>[&nbsp; &n=
bsp;18.098085][&nbsp; &nbsp; T1]&nbsp; bochs_pci_probe+0x7de/0x800</div><di=
v>[&nbsp; &nbsp;18.098123][&nbsp; &nbsp; T1]&nbsp; ? qxl_gem_prime_mmap+0x3=
0/0x30</div><div>[&nbsp; &nbsp;18.098152][&nbsp; &nbsp; T1]&nbsp; pci_devic=
e_probe+0x95f/0xc70</div><div>[&nbsp; &nbsp;18.098187][&nbsp; &nbsp; T1]&nb=
sp; ? pci_uevent+0x7b0/0x7b0</div><div>[&nbsp; &nbsp;18.098217][&nbsp; &nbs=
p; T1]&nbsp; really_probe+0x9af/0x20d0</div><div>[&nbsp; &nbsp;18.098255][&=
nbsp; &nbsp; T1]&nbsp; driver_probe_device+0x234/0x330</div><div>[&nbsp; &n=
bsp;18.098291][&nbsp; &nbsp; T1]&nbsp; device_driver_attach+0x1e8/0x3c0</di=
v><div>[&nbsp; &nbsp;18.098326][&nbsp; &nbsp; T1]&nbsp; __driver_attach+0x3=
0d/0x780</div><div>[&nbsp; &nbsp;18.098355][&nbsp; &nbsp; T1]&nbsp; ? klist=
_devices_get+0x10/0x60</div><div>[&nbsp; &nbsp;18.098388][&nbsp; &nbsp; T1]=
&nbsp; ? kmsan_get_metadata+0x116/0x180</div><div>[&nbsp; &nbsp;18.098419][=
&nbsp; &nbsp; T1]&nbsp; bus_for_each_dev+0x252/0x360</div><div>[&nbsp; &nbs=
p;18.098448][&nbsp; &nbsp; T1]&nbsp; ? driver_attach+0xa0/0xa0</div><div>[&=
nbsp; &nbsp;18.098482][&nbsp; &nbsp; T1]&nbsp; driver_attach+0x84/0xa0</div=
><div>[&nbsp; &nbsp;18.098512][&nbsp; &nbsp; T1]&nbsp; bus_add_driver+0x5d6=
/0xb00</div><div>[&nbsp; &nbsp;18.098550][&nbsp; &nbsp; T1]&nbsp; driver_re=
gister+0x30c/0x830</div><div>[&nbsp; &nbsp;18.098585][&nbsp; &nbsp; T1]&nbs=
p; __pci_register_driver+0x1fa/0x350</div><div>[&nbsp; &nbsp;18.098620][&nb=
sp; &nbsp; T1]&nbsp; bochs_init+0xd6/0x115</div><div>[&nbsp; &nbsp;18.09865=
1][&nbsp; &nbsp; T1]&nbsp; do_one_initcall+0x246/0x7a0</div><div>[&nbsp; &n=
bsp;18.098680][&nbsp; &nbsp; T1]&nbsp; ? qxl_init+0x165/0x165</div><div>[&n=
bsp; &nbsp;18.098727][&nbsp; &nbsp; T1]&nbsp; ? kmsan_get_metadata+0x116/0x=
180</div><div>[&nbsp; &nbsp;18.098763][&nbsp; &nbsp; T1]&nbsp; ? kmsan_get_=
shadow_origin_ptr+0x84/0xb0</div><div>[&nbsp; &nbsp;18.098791][&nbsp; &nbsp=
; T1]&nbsp; ? qxl_init+0x165/0x165</div><div>[&nbsp; &nbsp;18.098824][&nbsp=
; &nbsp; T1]&nbsp; do_initcall_level+0x2b4/0x34a</div><div>[&nbsp; &nbsp;18=
.098859][&nbsp; &nbsp; T1]&nbsp; do_initcalls+0x123/0x1ba</div><div>[&nbsp;=
 &nbsp;18.098890][&nbsp; &nbsp; T1]&nbsp; ? cpu_init_udelay+0xcf/0xcf</div>=
<div>[&nbsp; &nbsp;18.098921][&nbsp; &nbsp; T1]&nbsp; do_basic_setup+0x2e/0=
x31</div><div>[&nbsp; &nbsp;18.098958][&nbsp; &nbsp; T1]&nbsp; kernel_init_=
freeable+0x23f/0x35f</div><div>[&nbsp; &nbsp;18.098993][&nbsp; &nbsp; T1]&n=
bsp; ? rest_init+0x1f0/0x1f0</div><div>[&nbsp; &nbsp;18.099024][&nbsp; &nbs=
p; T1]&nbsp; kernel_init+0x1a/0x670</div><div>[&nbsp; &nbsp;18.099054][&nbs=
p; &nbsp; T1]&nbsp; ? rest_init+0x1f0/0x1f0</div><div>[&nbsp; &nbsp;18.0990=
85][&nbsp; &nbsp; T1]&nbsp; ret_from_fork+0x1f/0x30</div><div>[&nbsp; &nbsp=
;18.099240][&nbsp; &nbsp; T1] Dumping ftrace buffer:</div><div>[&nbsp; &nbs=
p;18.099250][&nbsp; &nbsp; T1]&nbsp; &nbsp; (ftrace buffer empty)</div><div=
>[&nbsp; &nbsp;18.099250][&nbsp; &nbsp; T1] Kernel Offset: disabled</div><d=
iv>[&nbsp; &nbsp;18.099250][&nbsp; &nbsp; T1] Rebooting in 1 seconds..</div=
><div>```</div><div><br></div><div><br></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/64637dc5-a480-4ae2-903e-9d70a7fdff98n%40googlegroups.c=
om?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msgi=
d/kasan-dev/64637dc5-a480-4ae2-903e-9d70a7fdff98n%40googlegroups.com</a>.<b=
r />

------=_Part_1638_992832524.1605505911962--

------=_Part_1637_1549063135.1605505911962--
