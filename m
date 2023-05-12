Return-Path: <kasan-dev+bncBCT6537ZTEKRBXHJ7CRAMGQEN32QPYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id C34F3700850
	for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 14:45:17 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id af79cd13be357-7576d7e62d4sf424295585a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 12 May 2023 05:45:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683895516; cv=pass;
        d=google.com; s=arc-20160816;
        b=iNRC1G8/MwkkFYQJiur96Jx/VoTgi1KNkWUKQiAqyQZBXL6b+RBZq/9rtOo+u8dfcI
         xIyREn1m3knl1qKd2S+DOMew4AJetOppJwrpcVkTPM623KLWwFjsiQuqPgj9ZRdPooZa
         QkqksVER3ElpHcv7SKUcps0PxxyaV+7hIBjGyMdm/n83s38rWUaGLGqJ4KKbLwVapSkW
         IA1NdkqSS+QDsj4lofJb8XpamxYyYO/lfy/kSTNs+lWSrOSBgE2YGExm0y0D0Yyb8uOl
         U0+qqInx8AVIWFIjxU3E+eWb2td0bmfOYAIrsPo48W7O2/vxbe1vpYjuMuNib5FHkbUs
         GHNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=INPg0EXSy9vHfNRPu8R3D4aZ0BlWfsQssyyQ5AJYpVU=;
        b=sgfA+Y3qI9rd12ToI2wkqMe25ZAGExvdmAWpznSFp20atX7NId7jpcJJfG24jNTJcW
         HkRaLVrxzLKMouNofSTCsK1+O+vjO9BcS2Eiq41BbCRH4CCVW9FGHUSeNfrfUHUMsAI+
         064BeuJwtAZ3ybpX5e5YtDPSsNXNKTBzddegnCuEXwdd8S8MNwb/AWQqtbuaCqeYdKEF
         ylpRKrlkOpHooER/wFuMtqkMxQp/KEayN0ephnkKGqhQkMM+YGO8e6dNxls+jKC+dt95
         t7s6e7pmpC5ERG8o/q2S45wWjscwTKeHbrD64qnGrpq5z/nkoz4qEgP0ucoFESKKcTRj
         Eyrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Rka/vwND";
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683895516; x=1686487516;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:mime-version
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=INPg0EXSy9vHfNRPu8R3D4aZ0BlWfsQssyyQ5AJYpVU=;
        b=CVIiurLer8RFIxR9WGeJhjGxWWndvKd87uVrKuAMGEs6OKcfKH5tFfl/VJFU1WnYCc
         iKHqVI/JGr5VdJTn2FIXwnz9oyy4W+5GiQjjvk76jbSHgzHR5t86ianWdhBozcU8tGsh
         Tg1kaVQOiQ19+8A24k3NAsNOx6HiYDRiJ845Vwk/59D8VolTWee9mg0QQss9QFMaUz6E
         AB537cBb/x46Liyu8jCo3VQOCE231kZ3Jsy+FsmwMSpDq1JdRJewDrEtILZg90NT4VXN
         L2hYmY8LxjaUOg43j6kTZXyeHxbFm1xLspnrretHM7Oi71GGDrDDnTyJ+8s1d+Bqeq4E
         ftWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683895516; x=1686487516;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=INPg0EXSy9vHfNRPu8R3D4aZ0BlWfsQssyyQ5AJYpVU=;
        b=OfIem5XASnA6Uf6O6CibAlLFNdnvq76K+PtVlv8fUQpBktxVom47WC2fIscz9JGbSL
         MsOj9W+CdryDAgFvStFauh0i3Bz+us4ok+LfBde7SOIzluy9LzM3ERjEWZyb/6o9gpix
         YifTIznu9IM8DU2Rk2rasBCPoPRt4DuLm8CiCuYzG5aXf+7ln2FpGIfzmuOXgt3Wp9Jl
         svR/7wCIer0I3L8kbhwfxaJP4HVYHabbx332dMXATkO3cPlwKfAk8MiHr5VWf2kc3Z9i
         TOk67KjaufCE0TqofMpgP7lplcvB/0+9qnQP/+H6CWZKUqdJmwH/pzcZGCrA9Ly3il3I
         xphw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyiwxHq+PsyQ/Rf3UCUKajk1+4SJkKGQbM4c2Ky2KegxOXajgEg
	A02dufQpJ8tLIRl2Sq3JDTs=
X-Google-Smtp-Source: ACHHUZ7+dKQ3q/5bC/vJKjhXv8H+YfmJRWYWm0adiLlq3gM0uXvh3TUnTQq5l5pPfZSK3v+oXKnQEw==
X-Received: by 2002:a05:620a:1a9e:b0:759:2a47:c74c with SMTP id bl30-20020a05620a1a9e00b007592a47c74cmr88468qkb.4.1683895516558;
        Fri, 12 May 2023 05:45:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:598a:b0:3ef:32a6:5f61 with SMTP id
 gb10-20020a05622a598a00b003ef32a65f61ls35678049qtb.11.-pod-prod-gmail; Fri,
 12 May 2023 05:45:16 -0700 (PDT)
X-Received: by 2002:a05:622a:148a:b0:3f2:a8db:3d57 with SMTP id t10-20020a05622a148a00b003f2a8db3d57mr40646331qtx.3.1683895515990;
        Fri, 12 May 2023 05:45:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683895515; cv=none;
        d=google.com; s=arc-20160816;
        b=XQoRhIBJ0MbsvO+giSAhb6uIjBporBc4YU6iBfsIT3oGELASQBYceupXVIpSyiqyFe
         d6UbzOJC7AU+4gR1ZaNDihQGptjJeYNCclbQX+tR2qOFtq0oa35bHb/0trTSu8dXO6pY
         aPl/nYMFIShVVFqin8ypPjHuiSe4AaVuCIwzJ/mqYgVUapjvQAsgR3Q4cQFMOXGgoDTn
         l51SPFHasnd+dHx7T0rqgf6dinrbN87S7rLF890S0Lr6r+GiC2fFv21a1fN7npw722sj
         GVUm8CFSJNSE1iislT4vriWKGZCKUwt+G3CkeAZK/o3THF7onI6GHgp8mQwmajYV//1r
         czsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=uEVJBPg36YfGHVd65N+50ADOheZJS8325x8ke0EcSFQ=;
        b=q83rEHrkLj8dwaQtnG8jbzbgkaZmjIyPIM2K8dKhyQ6GGDCucpuTZ2N0KXYaIwcjD3
         41Ecmi2Tc7QYfg02cP+b+pjY0q9cfLV9wD1FWvqhmWNoD27BRhBb/Geq9QwHTIE9VfQ8
         k84gG0RJu4YbAEBUxXldYy+ydVG4LgZGpbpQsdIpaTAEU4kv0Io1UogLL6uP04ftsbYa
         DPa5mzs2AIy12SDCP74BLAoY91QPStlw6FhF83PWIwWMgikE/FC9anEiZB/bC2Sh4ogH
         VPA4igYJ3gKprSF/7ihNP72iQlUejU5/x+qSw3vztqiIkqhhMioDW12sdwcv/BmCNmT1
         OJWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b="Rka/vwND";
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-vk1-xa36.google.com (mail-vk1-xa36.google.com. [2607:f8b0:4864:20::a36])
        by gmr-mx.google.com with ESMTPS id dv15-20020a05620a1b8f00b0075909e9609esi251241qkb.4.2023.05.12.05.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 May 2023 05:45:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::a36 as permitted sender) client-ip=2607:f8b0:4864:20::a36;
Received: by mail-vk1-xa36.google.com with SMTP id 71dfb90a1353d-4538491df02so550844e0c.2
        for <kasan-dev@googlegroups.com>; Fri, 12 May 2023 05:45:15 -0700 (PDT)
X-Received: by 2002:a1f:c583:0:b0:436:597e:2c85 with SMTP id
 v125-20020a1fc583000000b00436597e2c85mr363322vkf.2.1683895515382; Fri, 12 May
 2023 05:45:15 -0700 (PDT)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Fri, 12 May 2023 18:15:04 +0530
Message-ID: <CA+G9fYvVcMLqif7f3yayN_WZduZrf_86xc2ruVDDR7yphLC=wQ@mail.gmail.com>
Subject: next: WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744 __alloc_pages+0x2e8/0x3a0
To: open list <linux-kernel@vger.kernel.org>, linux-mm <linux-mm@kvack.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, kunit-dev@googlegroups.com, 
	lkft-triage@lists.linaro.org
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Mel Gorman <mgorman@techsingularity.net>, Dan Carpenter <dan.carpenter@linaro.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b="Rka/vwND";       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::a36 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
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

Following kernel warning has been noticed on qemu-arm64 while running kunit
tests while booting Linux 6.4.0-rc1-next-20230512 and It was started from
6.3.0-rc7-next-20230420.

Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>

This is always reproducible on qemu-arm64, qemu-arm, qemu-x86 and qemu-i386.
Is this expected warning as a part of kunit tests ?

Crash log:
-----------

[  663.530868]     KTAP version 1
[  663.531545]     # Subtest: Handshake API tests
[  663.533521]     1..11
[  663.534424]         KTAP version 1
[  663.535406]         # Subtest: req_alloc API fuzzing
[  663.542460]         ok 1 handshake_req_alloc NULL proto
[  663.550345]         ok 2 handshake_req_alloc CLASS_NONE
[  663.558041]         ok 3 handshake_req_alloc CLASS_MAX
[  663.565790]         ok 4 handshake_req_alloc no callbacks
[  663.573882]         ok 5 handshake_req_alloc no done callback
[  663.580284] ------------[ cut here ]------------
[  663.582129] WARNING: CPU: 0 PID: 1200 at mm/page_alloc.c:4744
__alloc_pages+0x2e8/0x3a0
[  663.585675] Modules linked in:
[  663.587808] CPU: 0 PID: 1200 Comm: kunit_try_catch Tainted: G
          N 6.4.0-rc1-next-20230512 #1
[  663.589817] Hardware name: linux,dummy-virt (DT)
[  663.591426] pstate: 22400005 (nzCv daif +PAN -UAO +TCO -DIT -SSBS BTYPE=--)
[  663.592978] pc : __alloc_pages+0x2e8/0x3a0
[  663.594236] lr : __kmalloc_large_node+0xbc/0x160
[  663.595548] sp : ffff80000a317bc0
[  663.596577] x29: ffff80000a317bc0 x28: 0000000000000000 x27: 0000000000000000
[  663.598863] x26: ffff0000c8925b20 x25: 0000000000000000 x24: 0000000000000015
[  663.601098] x23: 0000000000040dc0 x22: ffffbf424e7420c8 x21: ffffbf424e7420c8
[  663.603100] x20: 1ffff00001462f88 x19: 0000000000040dc0 x18: 0000000078b4155a
[  663.605582] x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
[  663.607328] x14: 0000000000000000 x13: 6461657268745f68 x12: ffff60001913bc5a
[  663.609355] x11: 1fffe0001913bc59 x10: ffff60001913bc59 x9 : 1fffe0001913bc59
[  663.611004] x8 : 0000000041b58ab3 x7 : ffff700001462f88 x6 : dfff800000000000
[  663.613556] x5 : 00000000f1f1f1f1 x4 : 00000000f2f2f200 x3 : 0000000000000000
[  663.615364] x2 : 0000000000000000 x1 : 0000000000000001 x0 : ffffbf42516818e2
[  663.617753] Call trace:
[  663.618486]  __alloc_pages+0x2e8/0x3a0
[  663.619613]  __kmalloc_large_node+0xbc/0x160
[  663.621454]  __kmalloc+0x84/0x94
[  663.622551]  handshake_req_alloc+0x74/0xe8
[  663.623801]  handshake_req_alloc_case+0xa0/0x170
[  663.625467]  kunit_try_run_case+0x7c/0x100
[  663.626592]  kunit_generic_run_threadfn_adapter+0x30/0x4c
[  663.628998]  kthread+0x1d4/0x1e4
[  663.629715]  ret_from_fork+0x10/0x20
[  663.631094] ---[ end trace 0000000000000000 ]---
[  663.643101]         ok 6 handshake_req_alloc excessive privsize
[  663.649446]         ok 7 handshake_req_alloc all good
[  663.651032]     # req_alloc API fuzzing: pass:7 fail:0 skip:0 total:7
[  663.653941]     ok 1 req_alloc API fuzzing
[  663.665951]     ok 2 req_submit NULL req arg
[  663.674278]     ok 3 req_submit NULL sock arg
[  663.682968]     ok 4 req_submit NULL sock->file
[  663.694323]     ok 5 req_lookup works
[  663.703604]     ok 6 req_submit max pending
[  663.714655]     ok 7 req_submit multiple
[  663.725174]     ok 8 req_cancel before accept
[  663.733780]     ok 9 req_cancel after accept
[  663.742528]     ok 10 req_cancel after done
[  663.750637]     ok 11 req_destroy works
[  663.751884] # Handshake API tests: pass:11 fail:0 skip:0 total:11
[  663.753579] # Totals: pass:17 fail:0 skip:0 total:17

links:
------

 - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230512/testrun/16901289/suite/log-parser-boot/test/check-kernel-exception/log
 - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230512/testrun/16901289/suite/log-parser-boot/tests/
 - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230420/testrun/16385677/suite/log-parser-boot/test/check-kernel-warning-ac79d2ca0f443d407d9749244f1738c9a2b123c609820f82d9e8907c756f5340/log
 - https://qa-reports.linaro.org/lkft/linux-next-master/build/next-20230512/testrun/16901289/suite/log-parser-boot/test/check-kernel-warning-ac79d2ca0f443d407d9749244f1738c9a2b123c609820f82d9e8907c756f5340/history/


--
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYvVcMLqif7f3yayN_WZduZrf_86xc2ruVDDR7yphLC%3DwQ%40mail.gmail.com.
