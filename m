Return-Path: <kasan-dev+bncBCT6537ZTEKRBJVX3CNQMGQEEFPIGZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 46B5562D968
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 12:31:52 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id c10-20020a17090aa60a00b00212e91df6acsf962154pjq.5
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Nov 2022 03:31:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668684710; cv=pass;
        d=google.com; s=arc-20160816;
        b=SLm0QYquu4sWg1d1cZXVICQ5bifk4h8xU2oPIzJtxTy6JNnlIrRKiAqqxE6aEloYOJ
         9ypGD8ulLh21/Tcl74OJxAJoEFimzL/dFF5cCB1+jmovhFHqh5lDEr9v22+YTQyu3N1c
         3cOimfcKt22ohghA2btIBGWSoYJCYLP5aMji+Dg8/RoFkZwlMTYUOG3vtt66VHinUJ0V
         K62y0TFgak+vdEsNf6I24E62USqn9gNSEHB0+iHVD/MG9IP9xpiP7eKPaiVTVcMzFyf/
         BGA1GbADdnvfARM2Dnft+SkAn1ZsMU+uWdXZPKaR/A/0kllUeeadfkMfwmhZvnox7lq6
         th+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=7/aIO5oUNNjR6Ah6KjzMBEi93gjqLZfPM6Qk1lbBrqI=;
        b=KgiGsin3AP0WAnjV+enysJTRaPg9d62asdMp8cE0XFVdXd8FUS3m31jKq/QPKSqkxA
         y5DilXxzHdiW/gmFNbQgHQLB1B4XS9E2n42HUzxJ6CIsZ6y/HLvTDsLpnUtfyTXZcicr
         rhpaK86KvJ3t+E9S5Rnol1ck75ypgvpFAtkdZ0mg85uobbVGTgQi7S4gdxrLoc2+68h4
         FOKdqxU1EJcsHRTTBymb9scmyqavWqDpY4/BwEl5q6xeeNXTKllSGBLBcxAzHXLmlKfc
         8TLfj9jtWvr48CkuIEN46EWdiJFEP0JP8ICmu2Yma9sXInyntpPino3D3G7RNhTRd25A
         yc4g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=C47Xa9ZW;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7/aIO5oUNNjR6Ah6KjzMBEi93gjqLZfPM6Qk1lbBrqI=;
        b=QeJiguCDEo4lmDpf1lBXossOAM8GoAkLsVeWKfHDmn+r7M0fPxjs7/R3UHDH9JeIF0
         oEVFe9CCQXRInaRL8HfA948DcCHzdkDB1DgYXq74UWdYgzjGZqEoAnYZBZuX36pLGIbs
         wDVpTtOJBbL6ujchHGAl7T/vmfmj3eQThGnflb25EgNNXEvTjPG8Pc/Bs5yfJzYDMtVI
         E7ETycS0zRF7H+CcjOJbOsObTDkg6nTYke+IR6lbm0nMl0BcxIctlXWVOj15dEZAMowt
         4wVjJpKKhusFoBcTDOZSpejDM2rnz/BVMzb8GcvIgrOgAIyuDiisMTblZMtRzgYK4tBg
         4rhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-gm-message-state:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7/aIO5oUNNjR6Ah6KjzMBEi93gjqLZfPM6Qk1lbBrqI=;
        b=bAsdelrXSHhmPAbhaRsT29rX4pbm662fBEJu/seF3lngVGXV/DAdxCk3v6Y1EP6cTW
         f//PMVsr+gasKmKtLyYTgn95lrBJi/plIGAx8mxDZSs/TQgyGW6yxrtyG89C9aS3n0gQ
         nC3Ne9Yzhzx5wIzuqhEaO4M9SDa3zwQjUGfyqWxcttizfPJ4cxfKrCI2xlEyKymfpKgE
         peSMvgn2JdoIc44wumJV1bRTVJU8Txp1/BiIqvkWdk3cMefAeNw7WhVcXrcthT6hqW/4
         oOnfX8nyxsSKZvOxznEeNsYAuMRm01n3yCX3Tjl1aXvKJ+d4XgIeA22JRK3s0JxfdQ0z
         8QwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5plcUlGlFwSkpH2o9sOX85tgLDsGtgMeSsQrCjbT1QGGgYEpsx4/
	TV2xY/O0/wa8lHY4d4zQDus=
X-Google-Smtp-Source: AA0mqf7Bk53BHF0W7D3SOmr5V6Oa4YfEIGpZeuZ9KxFqnIClDuqPcQYPFaWlnVQWxbIeZGU6JezFjw==
X-Received: by 2002:aa7:9551:0:b0:56b:1fca:18b0 with SMTP id w17-20020aa79551000000b0056b1fca18b0mr2570500pfq.42.1668684710328;
        Thu, 17 Nov 2022 03:31:50 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1016:b0:213:e:b27 with SMTP id b22-20020a17090a101600b00213000e0b27ls4045793pja.0.-pod-canary-gmail;
 Thu, 17 Nov 2022 03:31:49 -0800 (PST)
X-Received: by 2002:a17:90a:d497:b0:213:1ce7:d962 with SMTP id s23-20020a17090ad49700b002131ce7d962mr2485591pju.63.1668684709630;
        Thu, 17 Nov 2022 03:31:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668684709; cv=none;
        d=google.com; s=arc-20160816;
        b=lZyhmd2tRmyWKSbdH4M3BEFfkJNJVtRXQC9ekw8XAWy0T1Kuxic0RW+0v7aKFiEqvS
         A0GYEx/wkZPdhSj+mxXG2vOc9/5WHVXDBEZG7DSnKwhEWLkhu6quCpmeYc8e8rOekXsV
         r+S2O1whZUkvhuA4psU7TQTU0+tZe8Sf3nKredD6/reV3eli/S7BGYK3ifDcNviuvqE1
         EFw3wWYn/UjvrpvE8QVvDmkzTktFhv2w/36qHtOO+5FZulX4FTn4YU3wMG593n8jcMLi
         Pb5L0CgR4gq9JQIRgjSoOKvxG+CCVEE3T9Ap8t8komWDXPy3FxNO4EdJj6bWko8WKZwD
         072A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=i16ycnAEmJ+xybZKFB6Q2+GrX06wVG/BMACMYkIBt2s=;
        b=LzZzFE8Ilb0dnvkAeVXahK8Cd9kk8RmpeWpnpSc1PNtBpvYspARzvyVHb2e8cyFF5n
         CFcbiQUmoR9jJsw6153hZJFNlT/1OgdqxWfxGZOiTmt1vb77fFbUgYqeyWSN6G8U5VgW
         RhjLqX/UqYNvrz2SRi7k+liBO8tn93o3n+0PNDklHeVDK5RMyG73+b30Znl6T/c2XTCX
         UhMAWUHdD69nni4Ybx1txjkFz4tKIV5SRVE9MsUfQ28PSVZzyauAunM1GN5dZ5r6Pryt
         UtEjPsbq/SYwl5LoP1gxn/fo68gwfxEQKUA9TvMMxzShhDMMJKDag19WvyvuATNM/Dzy
         Sp8w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=C47Xa9ZW;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id z10-20020a170903018a00b00185499dcc29si59026plg.7.2022.11.17.03.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 17 Nov 2022 03:31:49 -0800 (PST)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id z192so1552420yba.0
        for <kasan-dev@googlegroups.com>; Thu, 17 Nov 2022 03:31:49 -0800 (PST)
X-Received: by 2002:a25:880e:0:b0:6e6:e31e:3dc5 with SMTP id
 c14-20020a25880e000000b006e6e31e3dc5mr1685536ybl.534.1668684708480; Thu, 17
 Nov 2022 03:31:48 -0800 (PST)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Thu, 17 Nov 2022 17:01:37 +0530
Message-ID: <CA+G9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA@mail.gmail.com>
Subject: WARNING: CPU: 0 PID: 0 at arch/x86/include/asm/kfence.h:46 kfence_protect
To: kasan-dev <kasan-dev@googlegroups.com>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	regressions@lists.linux.dev, lkft-triage@lists.linaro.org
Cc: Andrew Morton <akpm@linux-foundation.org>, Marco Elver <elver@google.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=C47Xa9ZW;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
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

Kunit test cases failed and found warnings while booting Linux next
version 6.1.0-rc5-next-20221117 on qemu-x86_64 [1].

It was working on Linux next-20221116 tag.

[    0.663761] WARNING: CPU: 0 PID: 0 at
arch/x86/include/asm/kfence.h:46 kfence_protect+0x7b/0x120
[    0.664033] WARNING: CPU: 0 PID: 0 at mm/kfence/core.c:234
kfence_protect+0x7d/0x120
[    0.664465] kfence: kfence_init failed

Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>

Regressions found on qemu_x86_64:[2]

    - kunit/test_use_after_free_read
    - kunit/test_invalid_access
    - kunit/test_double_free-memcache
    - kunit/test_krealloc
    - kunit/test_shrink_memcache
    - kunit/test_memcache_typesafe_by_rcu
    - kunit/test_use_after_free_read-memcache
    - kunit/test_invalid_addr_free-memcache
    - kunit/test_out_of_bounds_read-memcache
    - kunit/test_memcache_alloc_bulk
    - kunit/test_out_of_bounds_read
    - kunit/test_memcache_ctor
    - kunit/test_corruption-memcache
    - kunit/test_gfpzero
    - kunit/test_out_of_bounds_write
    - kunit/test_out_of_bounds_write-memcache
    - kunit/test_kmalloc_aligned_oob_read
    - kunit/test_free_bulk-memcache

[    0.663758] ------------[ cut here ]------------
[    0.663761] WARNING: CPU: 0 PID: 0 at
arch/x86/include/asm/kfence.h:46 kfence_protect+0x7b/0x120
[    0.663782] Modules linked in:
[    0.663788] CPU: 0 PID: 0 Comm: swapper/0 Not tainted
6.1.0-rc5-next-20221117 #1
[    0.663795] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.12.0-1 04/01/2014
[    0.663801] RIP: 0010:kfence_protect+0x7b/0x120
[    0.663811] Code: f1 f1 f1 f1 c7 40 04 04 f3 f3 f3 65 48 8b 04 25
28 00 00 00 48 89 45 d8 31 c0 e8 e0 0d ba ff 48 85 c0 74 06 83 7d a0
01 74 17 <0f> 0b 0f 0b c6 05 cb 97 1d 03 00 45 31 c0 c6 05 c0 97 1d 03
01 eb
[    0.663819] RSP: 0000:ffffffff9c407d98 EFLAGS: 00010002
[    0.663826] RAX: ffff8880adc01020 RBX: 00000000000001ff RCX: 80000001000001e3
[    0.663830] RDX: dffffc0000000000 RSI: ffff88811ac00000 RDI: ffff8880adc01020
[    0.663836] RBP: ffffffff9c407e18 R08: ffffffff997c8ef8 R09: ffffea00046b7f87
[    0.663841] R10: fffff940008d6ff0 R11: 0000000000000001 R12: 1ffffffff3880fb3
[    0.663845] R13: ffff88811ac00000 R14: ffffea00046b7fc0 R15: 0000000000000200
[    0.663852] FS:  0000000000000000(0000) GS:ffff88811b400000(0000)
knlGS:0000000000000000
[    0.663859] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    0.663864] CR2: ffff88813ffff000 CR3: 00000000ac814000 CR4: 00000000000406b0
[    0.663869] Call Trace:
[    0.663871]  <TASK>
[    0.663876]  ? __pfx_kfence_protect+0x10/0x10
[    0.663886]  ? __pfx_set_memory_4k+0x10/0x10
[    0.663899]  kfence_init_pool+0x1ea/0x350
[    0.663909]  ? __pfx_kfence_init_pool+0x10/0x10
[    0.663919]  ? random_init+0xe9/0x13b
[    0.663930]  ? __pfx_random_init+0x10/0x10
[    0.663936]  ? _find_next_bit+0x46/0xe0
[    0.663947]  kfence_init+0x42/0x1e8
[    0.663959]  start_kernel+0x1fd/0x3a6
[    0.663970]  x86_64_start_reservations+0x28/0x2e
[    0.663978]  x86_64_start_kernel+0x96/0xa0
[    0.663986]  secondary_startup_64_no_verify+0xe0/0xeb
[    0.664001]  </TASK>
[    0.664003] ---[ end trace 0000000000000000 ]---
[    0.664032] ------------[ cut here ]------------
[    0.664033] WARNING: CPU: 0 PID: 0 at mm/kfence/core.c:234
kfence_protect+0x7d/0x120
[    0.664045] Modules linked in:
[    0.664049] CPU: 0 PID: 0 Comm: swapper/0 Tainted: G        W
   6.1.0-rc5-next-20221117 #1
[    0.664055] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996),
BIOS 1.12.0-1 04/01/2014
[    0.664058] RIP: 0010:kfence_protect+0x7d/0x120
[    0.664068] Code: f1 f1 c7 40 04 04 f3 f3 f3 65 48 8b 04 25 28 00
00 00 48 89 45 d8 31 c0 e8 e0 0d ba ff 48 85 c0 74 06 83 7d a0 01 74
17 0f 0b <0f> 0b c6 05 cb 97 1d 03 00 45 31 c0 c6 05 c0 97 1d 03 01 eb
4a 48
[    0.664074] RSP: 0000:ffffffff9c407d98 EFLAGS: 00010002
[    0.664080] RAX: ffff8880adc01020 RBX: 00000000000001ff RCX: 80000001000001e3
[    0.664085] RDX: dffffc0000000000 RSI: ffff88811ac00000 RDI: ffff8880adc01020
[    0.664090] RBP: ffffffff9c407e18 R08: ffffffff997c8ef8 R09: ffffea00046b7f87
[    0.664095] R10: fffff940008d6ff0 R11: 0000000000000001 R12: 1ffffffff3880fb3
[    0.664099] R13: ffff88811ac00000 R14: ffffea00046b7fc0 R15: 0000000000000200
[    0.664105] FS:  0000000000000000(0000) GS:ffff88811b400000(0000)
knlGS:0000000000000000
[    0.664112] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    0.664116] CR2: ffff88813ffff000 CR3: 00000000ac814000 CR4: 00000000000406b0
[    0.664121] Call Trace:
[    0.664123]  <TASK>
[    0.664126]  ? __pfx_kfence_protect+0x10/0x10
[    0.664136]  ? __pfx_set_memory_4k+0x10/0x10
[    0.664146]  kfence_init_pool+0x1ea/0x350
[    0.664156]  ? __pfx_kfence_init_pool+0x10/0x10
[    0.664166]  ? random_init+0xe9/0x13b
[    0.664172]  ? __pfx_random_init+0x10/0x10
[    0.664179]  ? _find_next_bit+0x46/0xe0
[    0.664186]  kfence_init+0x42/0x1e8
[    0.664196]  start_kernel+0x1fd/0x3a6
[    0.664205]  x86_64_start_reservations+0x28/0x2e
[    0.664213]  x86_64_start_kernel+0x96/0xa0
[    0.664221]  secondary_startup_64_no_verify+0xe0/0xeb
[    0.664232]  </TASK>
[    0.664235] ---[ end trace 0000000000000000 ]---
[    0.664465] kfence: kfence_init failed

metadata:
  git_ref: master
  git_repo: https://gitlab.com/Linaro/lkft/mirrors/next/linux-next
  git_sha: af37ad1e01c72483c4ee8453d9d9bac95d35f023
  git_describe: next-20221117
  kernel_version: 6.1.0-rc5
  kernel-config: https://builds.tuxbuild.com/2Hfb6n1z0frt4iBlIvqUzjMHiLm/config
  build-url: https://gitlab.com/Linaro/lkft/mirrors/next/linux-next/-/pipelines/697483979
  artifact-location: https://builds.tuxbuild.com/2Hfb6n1z0frt4iBlIvqUzjMHiLm
  toolchain: gcc-11


[1] https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20221117/testrun/13045566/suite/kunit/test/kfence/log
[2] https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20221117/testrun/13045566/suite/kunit/tests/
[3] https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20221117/testrun/13045566/suite/kunit/test/test_invalid_access/history/



--
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYuFxZTxkeS35VTZMXwQvohu73W3xbZ5NtjebsVvH6hCuA%40mail.gmail.com.
