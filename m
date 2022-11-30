Return-Path: <kasan-dev+bncBC7OBJGL2MHBBOVFTWOAMGQERO6IJYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id DFADB63D60D
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 13:55:23 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id n10-20020a056e02140a00b00302aa23f73fsf15334570ilo.20
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Nov 2022 04:55:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1669812922; cv=pass;
        d=google.com; s=arc-20160816;
        b=tfpfOcPMnVoVaTmezV4VQYgOiCbywkeOwuM+BGhvULLVw+A01lojU1T0okU/BjrVYJ
         2KEnVOhW5b8r2z7Uq7xl/BZKEnbzE15UiXxCOTW0FWmVeSiVGuwf+5KmjwbAZgdou4Q5
         Z0LG9fZLNWgfQsQqnHLoohR2fR59DoRBAhziUv2FMtvV5LSXkpkml7DhqFHKZmMnpydT
         V5pWPBxG/wM5KX1062uPb7eF3XqyZ6LC21LMEToF7KDUKTWYKq0o1JhHsyTGH7AyiA//
         8kEd8EUdCg+3rAfvgNftj46ASiidzIlTCL/a75aBr4w7TaV2JYIcvnXaPIDMeQw5b3Re
         LXrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=nHahX8wrB1iBC3vSuHvyMPimH07k66ZvySYdjeKkIcA=;
        b=JeQEdQOQ6awZZUsnkEy91MO1BAUFe2JTf/3sWRAw7E+DGG4bqnoairNc4wjUleul4Z
         42s5mWqefkO1Dr7CWxsw9XlS8pmg3AyRTRI4kKeyzmR2Dg5EgHlKFBxJwk+lKFSJSzAt
         34h7D+XWikXeq6mX4luN4el4Vl+CpRUzO60+Xb7EqxkKfNw+D/hBJZUShGkzY0mgxr2q
         ScS2iG5KT27ziXuro3o5kDxn2j998/uuZzwS3ZOp6Gln82ySVmBpdlhC5ockNqTlLGlc
         f5nh5mV+QSvz2mZsBpS5DeLaH7A0nvNP0MxRWzCQ1cyWL95XiwuGCgJRgrsZcim9LWdr
         piMg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tLoUY6yS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=nHahX8wrB1iBC3vSuHvyMPimH07k66ZvySYdjeKkIcA=;
        b=ruKZIPfWk1dmo5OUUZSS2HlRUQYfb8/+LwfFtLMrc4b1/JqWuBavRfvg77WeKQrd1t
         KUVBTrVXx7xIp65b1PfusxTxQ2H+JLIqA0c8TDFRFK0cHfwqSh3B4ILPxmmBTYRsF+z1
         v7VbV+s+3yw8huRT6kOg+Vxafmw2W7rj1KLecYCxItzx0g3h250u8BFKJHX/0NU7dkau
         lUIsWjTdZsyKXDdaTC/OH/WXM6IySC9EQ+L3GL02+YYvaUtVxw9gFCGw1vxZkwP8qqiw
         +pFqmmLAorOa56UWuVGah1MKT0h0RhrRNcXzaLmbauZjzoWJSR9jv5i6wT4KTebXnkJp
         g2rA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=nHahX8wrB1iBC3vSuHvyMPimH07k66ZvySYdjeKkIcA=;
        b=TwgvYuRi7PtZlcWSApIviaoMG42Clu1oqFRoBGr/aenpeld7t9a+8gPBHTOKDAq67g
         BAv43ApW7M83TF6v77QOPZmgqo9LNBPoH05XqRmeyBtT36WYPnhXIAk6WJVJ5hmVi0n/
         4I2xJSdp45pDKoWOZa47zTEV0WGktZV9YybVLzbHfZflNWtWkUdCStPHFZEcmUU1ZcfI
         9gjKc6gmoIYWRKjeEU/IbEFQpr2QvFJQ7xRrUuJ2a7dHR5uDVum4YbgcBZtCNlCEGxgh
         NtH8nl9tokunBKLLYi4Db6VBW0qFvT1MrMCp6lGIFMrBMx228TDFa76tu8PYRPQx2wY3
         2lEQ==
X-Gm-Message-State: ANoB5pkLRETLWeAlEHWboqI6ewFF3h5o+IsKQaE4KPKtnoP0SUDYUd18
	y6M9MpybOFDC7ZAdW3KVxho=
X-Google-Smtp-Source: AA0mqf4YqOytHmeYdryJfvJpe0/G9qD+t5NIv+pV90Xpznuqd23TOYa7wVOqnuSEQWqP8U9s+jKYDw==
X-Received: by 2002:a6b:590c:0:b0:6bc:a758:9546 with SMTP id n12-20020a6b590c000000b006bca7589546mr21887766iob.78.1669812922279;
        Wed, 30 Nov 2022 04:55:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:13ed:b0:302:b56a:ce1f with SMTP id
 w13-20020a056e0213ed00b00302b56ace1fls2550996ilj.9.-pod-prod-gmail; Wed, 30
 Nov 2022 04:55:21 -0800 (PST)
X-Received: by 2002:a92:cb4b:0:b0:303:1c17:25e9 with SMTP id f11-20020a92cb4b000000b003031c1725e9mr5540998ilq.278.1669812921697;
        Wed, 30 Nov 2022 04:55:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1669812921; cv=none;
        d=google.com; s=arc-20160816;
        b=tA9XqfUUVG+gCeAYGeUxFwQKYfTd2BSm32Dw/AsbrygMJKiXqDvWPfPgN2ERHHWNQE
         yyTj6nbuhXHcAZnoSiyRuV/9n3ungdsNCCYF10ORJlI2pukkTWIhBwW0Ye/CJQs0UtJe
         Cs7MRwLLuDWQD9Ox/8ijUPiFP/HWMVuLpWB7nluzlHQemyCuaxlDNGgEEfiz7UYT2uJg
         9V29vpa7PKzq7U990OlFFSfQDX5vO09+KjIaPTWbOOas0DuPUt0xSW1rXl4uj1u5cMy0
         z36YaYMwtmnwSMPsKeuNUAxCfHSEy3QDBokPQ22iqvBRKLj7FL5Gxt392UbO4W3TvnUA
         ybcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qcByqO83gXA2mDu4S2UZuW8nauup/l1bwCTETtFovXc=;
        b=Pl7DlqBU7TRavqUjkWbu8ROOrZONRxc3h5nFSVcsaA//jcoaf+sjozs9biwobkz3RI
         Lzk4sFi/TcnL3wvV9dTaxv5qNu93eKUxEZ5d0xhE04NZaK2dmQ/59pSpUiBlU5wOxoka
         pP3mffTrhnjBLxIOENWKgK4wjK5uZT/YyO5tzcDQl7R36iBvg8PL0sgH04WCQF6vDx+9
         zsuCMkJdjpz/LBwjA+KsMgcto7SfsAEEQLkgw91IWpq7DJOQ5c0sov13udHZJn8yy6OQ
         Iced6mkGIs4+KkPw1jjdMkF0ffb7x/5STGUCjTY68BcbcaK27bUtfAxqoFFGZQjOExXg
         j91A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=tLoUY6yS;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2a.google.com (mail-yb1-xb2a.google.com. [2607:f8b0:4864:20::b2a])
        by gmr-mx.google.com with ESMTPS id i21-20020a6b3b15000000b006a128dbb6efsi67714ioa.0.2022.11.30.04.55.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Nov 2022 04:55:21 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as permitted sender) client-ip=2607:f8b0:4864:20::b2a;
Received: by mail-yb1-xb2a.google.com with SMTP id e141so21426575ybh.3
        for <kasan-dev@googlegroups.com>; Wed, 30 Nov 2022 04:55:21 -0800 (PST)
X-Received: by 2002:a25:7343:0:b0:6f3:aedd:e75 with SMTP id
 o64-20020a257343000000b006f3aedd0e75mr24051955ybc.611.1669812921041; Wed, 30
 Nov 2022 04:55:21 -0800 (PST)
MIME-Version: 1.0
References: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
In-Reply-To: <CA+G9fYsK5WUxs6p9NaE4e3p7ew_+s0SdW0+FnBgiLWdYYOvoMg@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 30 Nov 2022 13:54:44 +0100
Message-ID: <CANpmjNOQxZ--jXZdqN3tjKE=sd4X6mV4K-PyY40CMZuoB5vQTg@mail.gmail.com>
Subject: Re: arm64: allmodconfig: BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
To: Naresh Kamboju <naresh.kamboju@linaro.org>
Cc: rcu <rcu@vger.kernel.org>, open list <linux-kernel@vger.kernel.org>, 
	kunit-dev@googlegroups.com, lkft-triage@lists.linaro.org, 
	kasan-dev <kasan-dev@googlegroups.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Dominique Martinet <asmadeus@codewreck.org>, Netdev <netdev@vger.kernel.org>, 
	Anders Roxell <anders.roxell@linaro.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=tLoUY6yS;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 30 Nov 2022 at 13:50, Naresh Kamboju <naresh.kamboju@linaro.org> wrote:
>
> [Please ignore if it is already reported, and not an expert of KCSAN]
>
> While booting arm64 with allmodconfig following kernel BUG found,
> this build is enabled with CONFIG_INIT_STACK_NONE=y

Unsure why CONFIG_INIT_STACK_NONE=y is relevant.

> [    0.000000] Booting Linux on physical CPU 0x0000000000 [0x410fd034]
> [    0.000000] Linux version 6.1.0-rc7-next-20221130 (tuxmake@tuxmake)
> (aarch64-linux-gnu-gcc (Debian 11.3.0-6) 11.3.0, GNU ld (GNU Binutils
> for Debian) 2.39) #2 SMP PREEMPT_DYNAMIC @1669786411
> [    0.000000] random: crng init done
> [    0.000000] Machine model: linux,dummy-virt
> ...
> [  424.408466] ==================================================================
> [  424.412792] BUG: KCSAN: data-race in p9_client_cb / p9_client_rpc
> [  424.416806]
> [  424.418214] write to 0xffff00000a753000 of 4 bytes by interrupt on cpu 0:
> [  424.422437]  p9_client_cb+0x84/0x100

Please always provide line numbers and kernel commit hash or tag (I
think it's next-20221130, but not entirely clear).

Then we can look at git blame of the lines and see if it's new code.

> [  424.425048]  req_done+0xfc/0x1c0
> [  424.427443]  vring_interrupt+0x174/0x1c0
> [  424.430204]  __handle_irq_event_percpu+0x2c8/0x680
> [  424.433455]  handle_irq_event+0x9c/0x180
> [  424.436187]  handle_fasteoi_irq+0x2b0/0x340
> [  424.439139]  generic_handle_domain_irq+0x78/0xc0
> [  424.442323]  __gic_handle_irq_from_irqson.isra.0+0x3d8/0x480
> [  424.446054]  gic_handle_irq+0xb4/0x100
> [  424.448663]  call_on_irq_stack+0x2c/0x38
> [  424.451443]  do_interrupt_handler+0xd0/0x140
> [  424.454452]  el1_interrupt+0x88/0xc0
> [  424.457001]  el1h_64_irq_handler+0x18/0x40
> [  424.459856]  el1h_64_irq+0x78/0x7c
> [  424.462331]  arch_local_irq_enable+0x50/0x80
> [  424.465273]  arm64_preempt_schedule_irq+0x80/0xc0
> [  424.468497]  el1_interrupt+0x90/0xc0
> [  424.471096]  el1h_64_irq_handler+0x18/0x40
> [  424.474009]  el1h_64_irq+0x78/0x7c
> [  424.476464]  __tsan_read8+0x118/0x280
> [  424.479086]  __delay+0x104/0x140
> [  424.481521]  __udelay+0x5c/0xc0
> [  424.483905]  kcsan_setup_watchpoint+0x6cc/0x7c0
> [  424.487081]  __tsan_read4+0x168/0x280
> [  424.489729]  p9_client_rpc+0x1d0/0x580
> [  424.492429]  p9_client_getattr_dotl+0xd0/0x3c0
> [  424.495457]  v9fs_inode_from_fid_dotl+0x48/0x1c0
> [  424.498602]  v9fs_vfs_lookup+0x23c/0x3c0
> [  424.501386]  __lookup_slow+0x1b0/0x240
> [  424.504056]  walk_component+0x168/0x280
> [  424.506807]  path_lookupat+0x154/0x2c0
> [  424.509489]  filename_lookup+0x160/0x2c0
> [  424.512261]  vfs_statx+0xc0/0x280
> [  424.514710]  vfs_fstatat+0x84/0x100
> [  424.517308]  __do_sys_newfstatat+0x64/0x100
> [  424.520189]  __arm64_sys_newfstatat+0x74/0xc0
> [  424.523262]  invoke_syscall+0xb0/0x1c0
> [  424.525939]  el0_svc_common.constprop.0+0x10c/0x180
> [  424.529219]  do_el0_svc+0x54/0x80
> [  424.531662]  el0_svc+0x4c/0xc0
> [  424.533944]  el0t_64_sync_handler+0xc8/0x180
> [  424.536837]  el0t_64_sync+0x1a4/0x1a8
> [  424.539436]
> [  424.540810] read to 0xffff00000a753000 of 4 bytes by task 74 on cpu 0:
> [  424.544927]  p9_client_rpc+0x1d0/0x580
> [  424.547692]  p9_client_getattr_dotl+0xd0/0x3c0
> [  424.550564]  v9fs_inode_from_fid_dotl+0x48/0x1c0
> [  424.553550]  v9fs_vfs_lookup+0x23c/0x3c0
> [  424.556144]  __lookup_slow+0x1b0/0x240
> [  424.558655]  walk_component+0x168/0x280
> [  424.561192]  path_lookupat+0x154/0x2c0
> [  424.563721]  filename_lookup+0x160/0x2c0
> [  424.566337]  vfs_statx+0xc0/0x280
> [  424.568638]  vfs_fstatat+0x84/0x100
> [  424.571051]  __do_sys_newfstatat+0x64/0x100
> [  424.573821]  __arm64_sys_newfstatat+0x74/0xc0
> [  424.576650]  invoke_syscall+0xb0/0x1c0
> [  424.579144]  el0_svc_common.constprop.0+0x10c/0x180
> [  424.582212]  do_el0_svc+0x54/0x80
> [  424.584475]  el0_svc+0x4c/0xc0
> [  424.586611]  el0t_64_sync_handler+0xc8/0x180
> [  424.589347]  el0t_64_sync+0x1a4/0x1a8
> [  424.591758]
> [  424.593045] 1 lock held by systemd-journal/74:
> [  424.595821]  #0: ffff00000a0ead88
> (&type->i_mutex_dir_key#3){++++}-{3:3}, at: walk_component+0x158/0x280
> [  424.601588] irq event stamp: 416642
> [  424.603875] hardirqs last  enabled at (416641):
> [<ffff80000a552040>] preempt_schedule_irq+0x40/0x100
> [  424.609078] hardirqs last disabled at (416642):
> [<ffff80000a5422b8>] el1_interrupt+0x78/0xc0
> [  424.613887] softirqs last  enabled at (416464):
> [<ffff800008011130>] __do_softirq+0x5b0/0x694
> [  424.618699] softirqs last disabled at (416453):
> [<ffff80000801a9b0>] ____do_softirq+0x30/0x80
> [  424.623562]
> [  424.624841] value changed: 0x00000002 -> 0x00000003
> [  424.627838]
> [  424.629117] Reported by Kernel Concurrency Sanitizer on:
> [  424.632298] CPU: 0 PID: 74 Comm: systemd-journal Tainted: G
>        T  6.1.0-rc7-next-20221130 #2
> 26b4d3787db66414ab23fce17d22967bb2169e1f
> [  424.639393] Hardware name: linux,dummy-virt (DT)
>
> Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>
>
> --
> Linaro LKFT
> https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOQxZ--jXZdqN3tjKE%3Dsd4X6mV4K-PyY40CMZuoB5vQTg%40mail.gmail.com.
