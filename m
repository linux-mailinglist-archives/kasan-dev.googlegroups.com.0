Return-Path: <kasan-dev+bncBCT6537ZTEKRBI5DTWOAMGQEDW6WYOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93d.google.com (mail-ua1-x93d.google.com [IPv6:2607:f8b0:4864:20::93d])
	by mail.lfdr.de (Postfix) with ESMTPS id D85A863D5F8
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 13:50:44 +0100 (CET)
Received: by mail-ua1-x93d.google.com with SMTP id h14-20020a9f300e000000b0041878808d9dsf9187517uab.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 04:50:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669812643; cv=pass;
        d=google.com; s=arc-20160816;
        b=dXz9F61ToHT0IVQWUNA3JxJELET1FGr0fRqp8bVqjaMQNAoPrvliaOIB1RkkV0rQkx
         0kkgpom3fLp1TkbWACbMoUR6RYIoFjZUqmOHFIEn9YSPPB7VlLdgS5+M/uNTQ6zY8wS+
         0OS6vYiQcxhVa7isyBBhkIklVujFG5CcJqtQ8Ew6kXf4QKmzB7cJhEAA/PYTTCXs3glr
         UR1wtWziTthXCgFTYLAEipC4m/hAU8HeQyznQPk8ROgQJ+UWFqpMGfe19RjCzEC/YNEr
         Uzkfq+r0KQb0NuVKitn38S5HMb/lH997xVXOKHdNWKecGmB8xdTnDyhPynZd4keNph5T
         t1GQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=qer3k9lF/XXAdtfyFMQo/QZYBy45AtjjNBxpjz0nI2I=;
        b=BsgTOKYKZBvcqj+xkc50a2MJrDAQRQBoTJfsH6Uo0L687txTblQmeUHQhvva4W9Jse
         OeIohBdi20mhZ4CtaKk6tiTTC9pn7Je6m9vKOWBYUjEaEl6JWxi73F2EzGuOmMaid3cA
         cUZ3TxpUUbPzRohiT2jHVy9vvIc30oNaIwCtTckfmRZKohx5aQx4kamBdbPgqypE3g4+
         9rR3X/pRMVsRv2G9weeTI/NGj4IsMTk93Z1F5WSOw6PWWHUDkbPvxcthraP2PyLCvvVr
         Vk4E+xhixZYC4MrcejXHuESecTXRrKCtu5YG1HMBlirMVutTBykF/G/VWj58JuJpA9Xf
         KKpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=sC6+H6sy;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=qer3k9lF/XXAdtfyFMQo/QZYBy45AtjjNBxpjz0nI2I=;
        b=K43m7FW2a30wYCbQye4Mv6n+x+fJvJt+obyzlj78W+jA3TJaiZ4vmm6Nra6zt338Xc
         poi/dD0JnwnxMCxz1/1qTwOLkLc+7ob05kAubJ8CV1PyDDFjXdvMJMGDRQb9V5UOIfl5
         HWvZHi7XTRO3TMHvffOfir/i9SzOqQygIxjDkra4hYUAGFp0ueg+ejY9/Rr1yDGHOHzQ
         93hoxN0nMr6kFE44jsEucQgOolCTx4C4tUXU7Mr4VU7IqSTcPSuLojvCii3AxEUC5xLc
         xYvOaCV8MT0eIWDFlGlzKLeiKLasOmjUjN3ccFKih1syUYXKKOR5GXH8GnAVPRrNXC59
         sMWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qer3k9lF/XXAdtfyFMQo/QZYBy45AtjjNBxpjz0nI2I=;
        b=L701y+o9xXeaeRYSKOGC20xGjj9u2aZJYjhaxAQF3+1zwFoi1r9+DWQASKlsr7vNuY
         gwJBqe74cU3MGFD4srqSFZowB61eY2CxSBGJJ5HXH0hffiL3MAsoYZB03L6+CosMiucz
         aaljKOBLd/fE81EBdcMsMoMVHmMhM46zgv3M466EAwG9F3s2uEOXLHixCYQlDLjJe672
         0KwRBNwJmjjox2yQ1ur48iauLO6WfDBlBTSXh7G4RIMdduWN+g3JKGpevbTPElHj32qK
         P22wOnBfq5BVEnFPchVzrC/ZBSVBb8LoHPqTanzy7Ma+blhuEC+Re28+dbkv7Bn4JU5p
         ZjdA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pllf6JNjfOfb0GhhneMzNPimvukoD33x0pBnq5ckZ2xybxdLtHU
	w+YSwupohuB5AQGRrtpiQxA=
X-Google-Smtp-Source: AA0mqf7p5O0OJQgjwf/oH0fh2xFYu50IdGBSuOi0uC2Yx66qpdTXZEiao4UkEUxLreKJ8n9P6llx3Q==
X-Received: by 2002:ab0:388d:0:b0:418:e13c:a79b with SMTP id z13-20020ab0388d000000b00418e13ca79bmr23497942uav.79.1669812643712;
        Wed, 30 Nov 2022 04:50:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d299:0:b0:3b0:cd74:d6e5 with SMTP id z25-20020a67d299000000b003b0cd74d6e5ls532942vsi.8.-pod-prod-gmail;
 Wed, 30 Nov 2022 04:50:43 -0800 (PST)
X-Received: by 2002:a67:ee47:0:b0:3aa:2:a1e4 with SMTP id g7-20020a67ee47000000b003aa0002a1e4mr24371665vsp.30.1669812643147;
        Wed, 30 Nov 2022 04:50:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669812643; cv=none;
        d=google.com; s=arc-20160816;
        b=xPDqUgyUg9EEkJMaE21WcuDAAGcvNtvZqT2vgGSgDWm1oiOzUFan1dfkggURqDDsg6
         hJInnK5E8M93w+Y7XZvcTt1+2vMj2LB601k19tvD5reaStnPNcRWRs8npWh9p/2ep3y8
         1TTDdfqcGLfYOWV2hTsNH50g1TSsChVNsBdXVAokXLytl1diZC04YDdk7AdatdmRgD1T
         JWd+9gqUMJU3td8S33jNT+YYR2bz6lOoK7+lduYm4JuZIKcjYgPTslGLKNWgRa3V5eaG
         LI4j+4EPRwS1IyHRk0B30W+ipTUs/IRoRf2hv/Zg+zDoVqNhc1jCS+LAfeI54Y9zb2s8
         yLSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=61fKaN1RgZu/xXzq2GQeDUU3FSJDk3tRJK16ifRK9+c=;
        b=N++il8+OvqsgVyRno9ryGGxe+L/XEMYJdN0mhaI5aKK6+drxvHokAWl4CEL7zV/egi
         9hUd2MsPX3hcScFl62f1A9qvBzB3Beq+5iJWDylq0leKoVAHyu/5BkBtYYT4mHxsu8wZ
         K8eIEJCiPvfxvT4QHYWnseWoO7/BEBClBTVmApqOz2ieyE1z7NbO222LsHI4fyTJ7PUZ
         eT42e/75glm/VnRs6E4dtLzYCFZmUFhLyFNeWxrg1kqf4RIIUPH1LS1e+PUYCQilXXHq
         tujkdCZ0J9uvkj4lnEbSEGD93Ms6FiZ0S7aav4YPhu/1VI+6BjtIHvpPw8MpI6PQwqfN
         y8hg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=sC6+H6sy;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yw1-x1136.google.com (mail-yw1-x1136.google.com. [2607:f8b0:4864:20::1136])
        by gmr-mx.google.com with ESMTPS id h10-20020a1f210a000000b003bcdc7856dasi92470vkh.5.2022.11.30.04.50.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Nov 2022 04:50:43 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::1136 as permitted sender) client-ip=2607:f8b0:4864:20::1136;
Received: by mail-yw1-x1136.google.com with SMTP id 00721157ae682-3c090251d59so114293537b3.4
        for <kasan-dev@googlegroups.com>; Wed, 30 Nov 2022 04:50:43 -0800 (PST)
X-Received: by 2002:a81:dd8:0:b0:3b8:97ce:990a with SMTP id
 207-20020a810dd8000000b003b897ce990amr26466371ywn.448.1669812642465; Wed, 30
 Nov 2022 04:50:42 -0800 (PST)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Wed, 30 Nov 2022 18:20:30 +0530
Message-ID: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
Subject: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
To: rcu <rcu@vger.kernel.org>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	kasan-dev <kasan-dev@googlegroups.com>
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Dominique Martinet <asmadeus@codewreck.org>, 
	Netdev <netdev@vger.kernel.org>, Marco Elver <elver@google.com>, 
	Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=sC6+H6sy;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::1136 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

[Please ignore if it is already reported, and not an expert of KCSAN]

While booting arm64 with allmodconfig following kernel BUG found,
this build is enabled with CONFIG_INIT_STACK_NONE=y

[    0.000000] Booting Linux on physical CPU 0x0000000000 [0x410fd034]
[    0.000000] Linux version 6.1.0-rc7-next-20221130 (tuxmake@tuxmake)
(aarch64-linux-gnu-gcc (Debian 11.3.0-6) 11.3.0, GNU ld (GNU Binutils
for Debian) 2.39) #2 SMP PREEMPT_DYNAMIC @1669786411
[    0.000000] random: crng init done
[    0.000000] Machine model: linux,dummy-virt
...
[  424.408466] ==================================================================
[  424.412792] BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
[  424.416806]
[  424.418214] write to 0xffff00000a753000 of 4 bytes by interrupt on cpu 0:
[  424.422437]  p9_client_cb+0x84/0x100
[  424.425048]  req_done+0xfc/0x1c0
[  424.427443]  vring_interrupt+0x174/0x1c0
[  424.430204]  __handle_irq_event_percpu+0x2c8/0x680
[  424.433455]  handle_irq_event+0x9c/0x180
[  424.436187]  handle_fasteoi_irq+0x2b0/0x340
[  424.439139]  generic_handle_domain_irq+0x78/0xc0
[  424.442323]  __gic_handle_irq_from_irqson.isra.0+0x3d8/0x480
[  424.446054]  gic_handle_irq+0xb4/0x100
[  424.448663]  call_on_irq_stack+0x2c/0x38
[  424.451443]  do_interrupt_handler+0xd0/0x140
[  424.454452]  el1_interrupt+0x88/0xc0
[  424.457001]  el1h_64_irq_handler+0x18/0x40
[  424.459856]  el1h_64_irq+0x78/0x7c
[  424.462331]  arch_local_irq_enable+0x50/0x80
[  424.465273]  arm64_preempt_schedule_irq+0x80/0xc0
[  424.468497]  el1_interrupt+0x90/0xc0
[  424.471096]  el1h_64_irq_handler+0x18/0x40
[  424.474009]  el1h_64_irq+0x78/0x7c
[  424.476464]  __tsan_read8+0x118/0x280
[  424.479086]  __delay+0x104/0x140
[  424.481521]  __udelay+0x5c/0xc0
[  424.483905]  kcsan_setup_watchpoint+0x6cc/0x7c0
[  424.487081]  __tsan_read4+0x168/0x280
[  424.489729]  p9_client_rpc+0x1d0/0x580
[  424.492429]  p9_client_getattr_dotl+0xd0/0x3c0
[  424.495457]  v9fs_inode_from_fid_dotl+0x48/0x1c0
[  424.498602]  v9fs_vfs_lookup+0x23c/0x3c0
[  424.501386]  __lookup_slow+0x1b0/0x240
[  424.504056]  walk_component+0x168/0x280
[  424.506807]  path_lookupat+0x154/0x2c0
[  424.509489]  filename_lookup+0x160/0x2c0
[  424.512261]  vfs_statx+0xc0/0x280
[  424.514710]  vfs_fstatat+0x84/0x100
[  424.517308]  __do_sys_newfstatat+0x64/0x100
[  424.520189]  __arm64_sys_newfstatat+0x74/0xc0
[  424.523262]  invoke_syscall+0xb0/0x1c0
[  424.525939]  el0_svc_common.constprop.0+0x10c/0x180
[  424.529219]  do_el0_svc+0x54/0x80
[  424.531662]  el0_svc+0x4c/0xc0
[  424.533944]  el0t_64_sync_handler+0xc8/0x180
[  424.536837]  el0t_64_sync+0x1a4/0x1a8
[  424.539436]
[  424.540810] read to 0xffff00000a753000 of 4 bytes by task 74 on cpu 0:
[  424.544927]  p9_client_rpc+0x1d0/0x580
[  424.547692]  p9_client_getattr_dotl+0xd0/0x3c0
[  424.550564]  v9fs_inode_from_fid_dotl+0x48/0x1c0
[  424.553550]  v9fs_vfs_lookup+0x23c/0x3c0
[  424.556144]  __lookup_slow+0x1b0/0x240
[  424.558655]  walk_component+0x168/0x280
[  424.561192]  path_lookupat+0x154/0x2c0
[  424.563721]  filename_lookup+0x160/0x2c0
[  424.566337]  vfs_statx+0xc0/0x280
[  424.568638]  vfs_fstatat+0x84/0x100
[  424.571051]  __do_sys_newfstatat+0x64/0x100
[  424.573821]  __arm64_sys_newfstatat+0x74/0xc0
[  424.576650]  invoke_syscall+0xb0/0x1c0
[  424.579144]  el0_svc_common.constprop.0+0x10c/0x180
[  424.582212]  do_el0_svc+0x54/0x80
[  424.584475]  el0_svc+0x4c/0xc0
[  424.586611]  el0t_64_sync_handler+0xc8/0x180
[  424.589347]  el0t_64_sync+0x1a4/0x1a8
[  424.591758]
[  424.593045] 1 lock held by systemd-journal/74:
[  424.595821]  #0: ffff00000a0ead88
(&type->i_mutex_dir_key#3){++++}-{3:3}, at: walk_component+0x158/0x280
[  424.601588] irq event stamp: 416642
[  424.603875] hardirqs last  enabled at (416641):
[<ffff80000a552040>] preempt_schedule_irq+0x40/0x100
[  424.609078] hardirqs last disabled at (416642):
[<ffff80000a5422b8>] el1_interrupt+0x78/0xc0
[  424.613887] softirqs last  enabled at (416464):
[<ffff800008011130>] __do_softirq+0x5b0/0x694
[  424.618699] softirqs last disabled at (416453):
[<ffff80000801a9b0>] ____do_softirq+0x30/0x80
[  424.623562]
[  424.624841] value changed: 0x00000002 -> 0x00000003
[  424.627838]
[  424.629117] Reported by Kernel Concurrency Sanitizer on:
[  424.632298] CPU: 0 PID: 74 Comm: systemd-journal Tainted: G
       T  6.1.0-rc7-next-20221130 #2
26b4d3787db66414ab23fce17d22967bb2169e1f
[  424.639393] Hardware name: linux,dummy-virt (DT)

Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>

--
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYsK5WUxs6p9NaE4e3p7ew_%2Bs0SdW0%2BFnBgiLWdYYOvoMg%40mail.gmail.com.
