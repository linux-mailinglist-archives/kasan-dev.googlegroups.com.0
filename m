Return-Path: <kasan-dev+bncBC7M5BFO7YCRBG7RVKNAMGQER7HZT2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 622F35FFA58
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Oct 2022 15:41:51 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id e8-20020a5b0cc8000000b006bca0fa3ab6sf6747899ybr.0
        for <lists+kasan-dev@lfdr.de>; Sat, 15 Oct 2022 06:41:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665841309; cv=pass;
        d=google.com; s=arc-20160816;
        b=ECEj6KLQtcjrkn/kf70+vLCX+8rXm1Bq+wlftb7OY1IU6x0jxpNl7R20oymVbvnEyz
         UH/+LGwJy2gVzK81yHTpQBs4SEytmUehSRDqEThHjH6sJ5LWwnvrfd8Wr7eUKqktBGUu
         /lXoY3I2SAO6iVPfC9oKJzCLdbnJq7cuIhh8N1n7NBxkV11MXhW+WdzJOpXjXND9nep2
         gdP+DguWZTP4rhga9LUnRy7zyYIQhRguweu71X66IOgtNgQ2JQs7lcu+YMqFZocpItYc
         n4fF308gvWHTzsCmhkr6GZzEQvQ3fy/BbhxAY0eo6UPsYvNzanIIKWgAJCliluAVwSr1
         awTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=4R8/COySYCRpOMfiZghTopLinqYDaEy+RuAxpZvJz6A=;
        b=iznV9oivtfNOsNOYEwJoZ8VrrYV9BH2H4AiiDdbepgCOSKGTLcoUhQkq56oLS8DCL7
         BKbGJG7B0M4aSOsPHXuHy+Nmf5N0QcZvGUtmPnkOhPSolzjJouJqrLbv/YaUfE6PPdcK
         akyIiFJrLm0xsjmQPL8p7ZqFaK6qLSPQ3IVQ3V2GdmZAO8BFSv0bKR8e7asPG6scuB3U
         kbRTsybW1Xvmvtox4tXDWEf8V+sAUrJgKwclzHyKPKK9/l7efryUgP6/dnAlPP8ACI9k
         KBnIakjBUZoKSPjaDY56BL4ONvBKjvCMUbGAC20jJQKpVbj8R0d3cxAn/AYdJwC3t0Vz
         vvjQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=SZkdrFC7;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2001:4860:4864:20::30 as permitted sender) smtp.mailfrom=groeck7@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4R8/COySYCRpOMfiZghTopLinqYDaEy+RuAxpZvJz6A=;
        b=nJsfBh9OZGj8ohfdGv9E4PCkrCSxxZ2u4Zf5FOWJjeWentr0lrrlvIuqrzjks6mbci
         M1YaiThXYA49LiI0T4e5q6myVI0MwUUdoNNpvdhTc2vYUGKpQO0/NJflAdy4aoUoYzNw
         Xm48an0q6n2q+92UIi0mok8F5cXZzJFLp+hQ4QG4ixehlkEpdenPH0IvOL7BcN0WG7Rf
         Sfm820mC3fBOuTkLLTDH1CC2eDlgBjoC7JeW/cpC7giWQyKS+uYpUSbLA/R2GCMtAuqq
         TXDvD/8zAz5WsMidMQOmDiSiA/rUJOMEVoxInF1+PTA2esPAYsw51XeqbVDVh+jWdU2g
         GDig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:message-id:subject:cc:to:from:date
         :sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4R8/COySYCRpOMfiZghTopLinqYDaEy+RuAxpZvJz6A=;
        b=WB1AFec1zfFcGRtuPxjCRlnZvj+aZFkuOBQQF5j9mRNkRCALDNGAy8TkxqmgGJtABi
         c8KtuWedcmmp6ZJuI7Ud8xnm5Liz9ig9MrYhfcr21NtzpIv2MVffhNLO1IQ0rsuJF/yF
         cXUeQdtTYDn0f7JKSbG5Dekt3vPc8hPPZjH98hkme2cX/aI7cNx3iWOIfO9ivCOZgpbq
         Cli24K2O9A0FjtAud/OVNdhMVZtDD/7rm6xjDyA77dEGCECRbl8ORBnvANGOQHi06YZd
         ISVF8fewpLyWL2xulGMyYZ9XVoQC1MMOwDtC9tqEFp6WFnPG3Xz8aUA/QBOq/FfgKF5Y
         OO+w==
X-Gm-Message-State: ACrzQf0wg9sUniwpBPiRDjeC3XUttWB9AAKYve4gu6MZaWaoExRWi9Tq
	J3nqT82PQKdCthXqbKCSiZI=
X-Google-Smtp-Source: AMsMyM7ciLRViadAe+/8ICI8wxvbARdQYcbvZ4oV5jGlQmj5aOxKlt1/z6sxbBZwWbi4geQrx9aDCQ==
X-Received: by 2002:a0d:cc41:0:b0:357:46a0:18a5 with SMTP id o62-20020a0dcc41000000b0035746a018a5mr2238311ywd.28.1665841308008;
        Sat, 15 Oct 2022 06:41:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:5d1:0:b0:361:5499:a642 with SMTP id 200-20020a8105d1000000b003615499a642ls2968396ywf.0.-pod-prod-gmail;
 Sat, 15 Oct 2022 06:41:47 -0700 (PDT)
X-Received: by 2002:a81:8392:0:b0:356:509a:532e with SMTP id t140-20020a818392000000b00356509a532emr2348745ywf.410.1665841307294;
        Sat, 15 Oct 2022 06:41:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665841307; cv=none;
        d=google.com; s=arc-20160816;
        b=toCzhC7VpLlP+kvK3Clb21NxSXuqVilz4972INhJ5tvyF7YalHMZdIXjuSvak72tUW
         UCr/45KpHxlpORCVjrYVUZMFw8Q2J+86OXDVp7Z8AzGnjg4pWeOYdz1kcJD9psiMYMZF
         RGM524ZDGT8fPB/V/bC6lo1zBEoFUSkfEh4iNHSlXRbup5unWkhWNZkXX70NQKoVzoxq
         CvNj77y0F+0f7eaFCX1gp1br6KtCvUl+gvB2LApwtO2gBrvj0kiaeY3nyoaqc6E+jZ3h
         hqkLAniMIDuvZhFr5hM8KvYclFOD0d0vDJx8lgRJV3Ic9vqGO3glkO1MHooG8hGb9i6X
         p2aA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=ip/0L2qERVAjyL9wVuuTT33jhk9G53en83NEZUi4J4A=;
        b=PKDOyNaZg307ossOtY5VaYnEfwbNlB2XN9FcLg04L2r8Zx5IiqPXPi2i0hDJV+8jak
         X/5fhhGytbqBzNqFnhRZZRFMh46u+B+YsmMXgwQ4RPEh19BiipE3s7HuHQd3MAuEv+Aj
         GuuZoLxyhbySZYt/Rg0lm2dTZCw048v08Jux7X/MTSP4M0IKkSfl+19pnmaZu/SiAAyE
         I+HaBs2IcNkJKL6rrooU3crc0O1pXnTJHYKYpaIjW51oFtyVsgkStAhVX5x8ajPQO2yw
         81s0EEPEh01wUfnSKUsChGd7XHAQAIBx6G/yZ0P4/7bJvcVRDMGWwUxWWke9GpbA1k7M
         CmWw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=SZkdrFC7;
       spf=pass (google.com: domain of groeck7@gmail.com designates 2001:4860:4864:20::30 as permitted sender) smtp.mailfrom=groeck7@gmail.com
Received: from mail-oa1-x30.google.com (mail-oa1-x30.google.com. [2001:4860:4864:20::30])
        by gmr-mx.google.com with ESMTPS id h20-20020a25d014000000b0069015ac7716si262691ybg.0.2022.10.15.06.41.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 15 Oct 2022 06:41:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of groeck7@gmail.com designates 2001:4860:4864:20::30 as permitted sender) client-ip=2001:4860:4864:20::30;
Received: by mail-oa1-x30.google.com with SMTP id 586e51a60fabf-132b8f6f1b2so8889164fac.11
        for <kasan-dev@googlegroups.com>; Sat, 15 Oct 2022 06:41:47 -0700 (PDT)
X-Received: by 2002:a05:6870:fb93:b0:131:c354:b7d3 with SMTP id kv19-20020a056870fb9300b00131c354b7d3mr1436921oab.20.1665841306856;
        Sat, 15 Oct 2022 06:41:46 -0700 (PDT)
Received: from server.roeck-us.net ([2600:1700:e321:62f0:329c:23ff:fee3:9d7c])
        by smtp.gmail.com with ESMTPSA id v24-20020a4ae058000000b00480ba1434a6sm1042864oos.34.2022.10.15.06.41.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 15 Oct 2022 06:41:46 -0700 (PDT)
Sender: Guenter Roeck <groeck7@gmail.com>
Date: Sat, 15 Oct 2022 06:41:44 -0700
From: Guenter Roeck <linux@roeck-us.net>
To: kasan-dev@googlegroups.com
Cc: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>
Subject: Warning backtraces when enabling KFENCE on arm
Message-ID: <20221015134144.GA1333703@roeck-us.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: linux@roeck-us.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=SZkdrFC7;       spf=pass
 (google.com: domain of groeck7@gmail.com designates 2001:4860:4864:20::30 as
 permitted sender) smtp.mailfrom=groeck7@gmail.com
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

Hi,

I keep seeing the following backtrace when enabling KFENCE on arm
systems.

[    9.736342] ------------[ cut here ]------------
[    9.736521] WARNING: CPU: 0 PID: 210 at kernel/smp.c:904 smp_call_function_many_cond+0x288/0x584
[    9.736638] Modules linked in:
[    9.736707] CPU: 0 PID: 210 Comm: S02sysctl Tainted: G        W        N 6.0.0-12189-g19d17ab7c68b #1
[    9.736806] Hardware name: Generic DT based system
[    9.736871]  unwind_backtrace from show_stack+0x10/0x14
[    9.736948]  show_stack from dump_stack_lvl+0x68/0x90
[    9.737021]  dump_stack_lvl from __warn+0xc8/0x1e8
[    9.737091]  __warn from warn_slowpath_fmt+0x5c/0xb8
[    9.737162]  warn_slowpath_fmt from smp_call_function_many_cond+0x288/0x584
[    9.737247]  smp_call_function_many_cond from smp_call_function+0x3c/0x50
[    9.737329]  smp_call_function from set_memory_valid+0x74/0x94
[    9.737407]  set_memory_valid from kfence_guarded_free+0x280/0x4bc
[    9.737487]  kfence_guarded_free from kmem_cache_free+0x388/0x3e0
[    9.737566]  kmem_cache_free from dequeue_signal+0x16c/0x220
[    9.737641]  dequeue_signal from get_signal+0x17c/0xa34
[    9.737713]  get_signal from do_work_pending+0x118/0x560
[    9.737784]  do_work_pending from slow_work_pending+0xc/0x20
[    9.737857] Exception stack(0xe97b5fb0 to 0xe97b5ff8)
[    9.737926] 5fa0:                                     000000d4 bef68244 00000000 00000000
[    9.738017] 5fc0: 00000000 00000000 000d8b6c 00000072 00000001 b6fdf060 00000000 b6fdfa04
[    9.738105] 5fe0: bef68200 bef681f0 b6f8c4dc b6f8b998 60000010 ffffffff
[    9.738181] irq event stamp: 1018
[    9.738233] hardirqs last  enabled at (1017): [<c030ad70>] do_work_pending+0xa8/0x560
[    9.738322] hardirqs last disabled at (1018): [<c13d7fc4>] _raw_spin_lock_irq+0x68/0x6c
[    9.738413] softirqs last  enabled at (0): [<c034392c>] copy_process+0x66c/0x18a4
[    9.738500] softirqs last disabled at (0): [<00000000>] 0x0
[    9.738649] ---[ end trace 0000000000000000 ]---

This is an example seen when running the 'virt' emulation in qemu
with a configuration based on multi_v7_defconfig and KFENCE enabled.

The warning suggests that interrupts are disabled. Another KFENCE
related warning is

[   11.378812] ------------[ cut here ]------------
[   11.379050] WARNING: CPU: 0 PID: 0 at kernel/smp.c:912 smp_call_function_many_cond+0x3b0/0x3cc
[   11.379775] Modules linked in:
[   11.380136] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G                 N 6.0.0-12189-g19d17ab7c68b #1
[   11.380373] Hardware name: ARM-Versatile Express
[   11.380669]  unwind_backtrace from show_stack+0x10/0x14
[   11.380858]  show_stack from dump_stack_lvl+0x50/0x6c
[   11.380989]  dump_stack_lvl from __warn+0xc8/0x194
[   11.381106]  __warn from warn_slowpath_fmt+0x5c/0xb8
[   11.381225]  warn_slowpath_fmt from smp_call_function_many_cond+0x3b0/0x3cc
[   11.381369]  smp_call_function_many_cond from smp_call_function+0x3c/0x50
[   11.381507]  smp_call_function from set_memory_valid+0x74/0x94
[   11.381657]  set_memory_valid from kfence_guarded_free+0x280/0x4bc
[   11.381800]  kfence_guarded_free from kmem_cache_free+0x338/0x390
[   11.381930]  kmem_cache_free from rcu_core+0x340/0xc24
[   11.382053]  rcu_core from __do_softirq+0xf0/0x41c
[   11.382192]  __do_softirq from __irq_exit_rcu+0xa4/0xc8
[   11.382315]  __irq_exit_rcu from irq_exit+0x8/0x10
[   11.382429]  irq_exit from __irq_svc+0x88/0xb0
[   11.382596] Exception stack(0xc1f01ee8 to 0xc1f01f30)
[   11.382786] 1ee0:                   00000005 00000000 00000279 c031c200 c1f0d840 c2197020
[   11.382947] 1f00: c1f08d10 c1f08d6c c1e73368 c21958cc 00000000 00000000 ffffffff c1f01f38
[   11.383094] 1f20: c0307d18 c0307d1c 60000013 ffffffff
[   11.383220]  __irq_svc from arch_cpu_idle+0x38/0x3c
[   11.383341]  arch_cpu_idle from default_idle_call+0x60/0x160
[   11.383472]  default_idle_call from do_idle+0x1f8/0x29c
[   11.383597]  do_idle from cpu_startup_entry+0x18/0x1c
[   11.383712]  cpu_startup_entry from rest_init+0xf4/0x100
[   11.383834]  rest_init from arch_post_acpi_subsys_init+0x0/0x8
[   11.384051] ---[ end trace 0000000000000000 ]---

This is also seen with the same emulation. It suggests that the call is
made from outside task context, which presumably can also result in a
deadlock.

I see those warnings only with arm emulations. The warnings are not new;
they are seen since kfence support for arm has been added.

Is this a real problem ? Either case, is there a way to address the
warnings ?

Thanks,
Guenter

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221015134144.GA1333703%40roeck-us.net.
