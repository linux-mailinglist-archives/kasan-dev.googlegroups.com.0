Return-Path: <kasan-dev+bncBCT6537ZTEKRBR6ESCFQMGQECVLYUJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BE61428C2C
	for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 13:38:48 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id c2-20020adfa302000000b0015e4260febdsf13017192wrb.20
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Oct 2021 04:38:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633952328; cv=pass;
        d=google.com; s=arc-20160816;
        b=M3Yzwn9b0YI/PIdK5h+SMd0OOpoX4EEqeUzKI1uoQdSuORL4gUD/gqJzdIH0nLp0Ob
         z3ld/YkXNZA2GQ3JsaSWiTgDcwH6GY/eVbEtm9ooUfewYRoxuBNaLIJ6xEuTEaqQqIcu
         0eHWkJpLIRoW6+BskEN6TOpzEUG0IRFHsHu27vuGtjE43pVN5rX4rF/EtFD6+AD/qphZ
         VCUKHih4tK9f2xPVDMOykkyH4uk0uE3Fh/E3IHbcivs5okabXk1+geGu5h3y62FGRqnK
         OVfIijjLqHVhh9IC3q2dmlT2AJqlXC8Ufto0myfNdyG12eYn4kB9+AdjBbUYaqvk8b/P
         2KIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :mime-version:sender:dkim-signature;
        bh=jxbPZX1cgJovJH7RSUvmnBSQ6ezcbfmodmT0c4BQb2o=;
        b=h1ZSdqnhkaEVDC+4POw+hC2eUJ8i+xj1vDEXjQg5Lsa0UDKd+1flRlopAH65IwZuDP
         krVG2kvn3DSMe89Bifr8z10E75nnu06WJ4CbXE8xc3+n623iB9K6luk/3s3GROvBXtUG
         6BP3xPzpESp/XAoQ3ZA6qs1krjAzJoS/hsrq6zUFZgnnf/1gVK/52Jhl9duAY18jR26s
         5wjxkDO0r6j/FbTmm9zTyVxBMvNheyjWZx0cY7hcmTh5e0B5L6nq295Q2q+jm1AVJ7Tk
         fCcaUWwStNY3LMY2+txM9Dk9RfoFb1Q+ji7bU8XvOsIaTEb2Qs/G/8OWu9QGI1VCyo02
         lPog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=qomjv+hA;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:date:message-id:subject:to:cc
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jxbPZX1cgJovJH7RSUvmnBSQ6ezcbfmodmT0c4BQb2o=;
        b=XAnlxEma4tzgSJxYYoXszjUn/lLpkeX16NQGNqdXvIoNdJM2vgZvW3nX0QptB4vZc7
         FLOnUEde/rckd4NrLxJZyO7s3xtYK/vRyV+u+9JmDNCYfAhJ5VpIjYyLmF0z0g975n16
         ffE1QcpasZcuHBTsimNotNvfMiDagipVWCIiva28FQQhi1nhlAY4AfUPdBC4G66pI0fx
         DAsh9Z/vRrxbhX0/AnG2SMvR8SXL4Qu6KVW9u2SuxVdbEcGypqSz3QcgIFNohapLqU4K
         sxqNpWtOa+TL6OxGWYGi/jXSDBonF4YyFUl1Yc9ne8jYqCWqDMRXOTQT98zN3r6mViL2
         DoWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:date:message-id:subject
         :to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jxbPZX1cgJovJH7RSUvmnBSQ6ezcbfmodmT0c4BQb2o=;
        b=li/ShRqebIBVrwBfkCehtnWhaPPS7yyCXFSs/HsXoz6Bm33a66JB1SOSqCty7qEwWx
         ZlqGo7Fv5+MhDPo6OcYY5PZ0zoHKNn7c6oMr+ZyKY/YJf4P3mAJlVCJyAOTf5Ahl+nNn
         27omr7nHPj/uCWkCG5A8Ujm7vDv8tW2HBCLbZj178AgTXMMWZk69BKVodvaRouSMbnio
         bpGDVrXT1eNLuoOytv5ibMO0La3Xgk2fRk3VDdQNhLnESLwFZBKs05l3aLHaSkHVGtFI
         U9zmj1NQhNAKIswcVCinp7B4AG1yT6aeG0iPCYHm8nGFjK5mbvFTpW+X/k/NrD9U5zJo
         wPtQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531HZsyfFrQVQfuUrY3QfBcYnFXz4UCuxwPOK1V5K+pVtBeyOeA4
	cUmLvoY96o930JyqDch+VMA=
X-Google-Smtp-Source: ABdhPJz9Pf/lH3rMleTIou7e4s7isVt/P/GFNCAzhSTWCYxmGihrZl21HRxE/3+aGEp3cy98GzC03g==
X-Received: by 2002:adf:b34c:: with SMTP id k12mr23425865wrd.1.1633952328080;
        Mon, 11 Oct 2021 04:38:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1caa:: with SMTP id k42ls7344826wms.3.canary-gmail;
 Mon, 11 Oct 2021 04:38:47 -0700 (PDT)
X-Received: by 2002:a1c:4d06:: with SMTP id o6mr2285106wmh.137.1633952327155;
        Mon, 11 Oct 2021 04:38:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633952327; cv=none;
        d=google.com; s=arc-20160816;
        b=JnJvuxHRFsUu+LIt+dvqpvxw3T1UbiLbZ9bPxWhl620Ay3f0Z/oAk30E+wlSfoxDwx
         QHqdv/JWpuF866TbT/kbGcb4U6moFEchCL+es2A7P6gd8126OdCrnXaTYa4Bp+KwYg+U
         NYw5tBmjinKowKzcZpmwbM62xUyt9OHTZdZub41zLZGPt7g+LLVqFV2ozDduh8J2mqui
         M/apmM2RmRSbdrGkYXrqM6X7BDo1XV2NEAP+g54F+ZD5tqtQU+5+fyDPbkaLbY/J02eV
         lr+J3V3cRz7+Ruw90APZHMq1efGAMK7V2DcbLmUIUWcdLsvwxVgQHCfaxk1srlRAoAha
         y/fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=aVAseHFlKtR4hY18T2FRHhS7NIeZFLXno7FnFl0RhbU=;
        b=GD6zkvIsdvMDIuVakaVvpV7JuSyyod0C362Rs+Q7Ija0D8ssgvgfua4RLgBfdX1htt
         N3FAKi+XLwkc2hL9ICQGpx3TiWQXDz3Njab/DXypCaMi5V4E1jLXipI9jI3o5FQrp82R
         1OlUjw9JYyHQmPAB6tEyCMECBhLnl472ZewD0wr0Y3tQb9MVU5kN0m0pcIJq68zfOYRE
         jBcwH7gG216kv/tpt+ouzpf9ju3b+n23adzUJ1770PMW0slebye0kAVzEgtFgAmozNda
         HtUtQpqVszyhqLcY3qRrajVMpzcRXJWVwOFT6WbzCKjFlbNkLjDuA8YuUnLv+7lq+nW3
         ryTw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=qomjv+hA;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-ed1-x52e.google.com (mail-ed1-x52e.google.com. [2a00:1450:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id y1si346644wmj.1.2021.10.11.04.38.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Oct 2021 04:38:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2a00:1450:4864:20::52e as permitted sender) client-ip=2a00:1450:4864:20::52e;
Received: by mail-ed1-x52e.google.com with SMTP id d3so39161975edp.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Oct 2021 04:38:47 -0700 (PDT)
X-Received: by 2002:a17:906:318b:: with SMTP id 11mr25186720ejy.493.1633952326385;
 Mon, 11 Oct 2021 04:38:46 -0700 (PDT)
MIME-Version: 1.0
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Mon, 11 Oct 2021 17:08:35 +0530
Message-ID: <CA+G9fYv1Vbc-Y_czipb-z1bG=9axE4R1BztKGqWz-yy=+Wcsqw@mail.gmail.com>
Subject: mm/kasan/init.c:282:20: error: redefinition of 'kasan_populate_early_vm_area_shadow'
To: Linux-Next Mailing List <linux-next@vger.kernel.org>, open list <linux-kernel@vger.kernel.org>, 
	linux-mm <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundatio.org>, Stephen Rothwell <sfr@canb.auug.org.au>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=qomjv+hA;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2a00:1450:4864:20::52e as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
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

Regression found on x86_64 gcc-11 built with KASAN enabled.
Following build warnings / errors reported on linux next 20211011.

metadata:
    git_describe: next-20211011
    git_repo: https://gitlab.com/Linaro/lkft/mirrors/next/linux-next
    git_short_log: d3134eb5de85 (\"Add linux-next specific files for 20211011\")
    target_arch: x86_64
    toolchain: gcc-11

build error :
--------------
mm/kasan/init.c:282:20: error: redefinition of
'kasan_populate_early_vm_area_shadow'
  282 | void __init __weak kasan_populate_early_vm_area_shadow(void *start,
      |                    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
In file included from include/linux/mm.h:34,
                 from include/linux/memblock.h:13,
                 from mm/kasan/init.c:9:
include/linux/kasan.h:463:20: note: previous definition of
'kasan_populate_early_vm_area_shadow' with type 'void(void *, long
unsigned int)'
  463 | static inline void kasan_populate_early_vm_area_shadow(void *start,
      |                    ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
make[3]: *** [scripts/Makefile.build:288: mm/kasan/init.o] Error 1
make[3]: Target '__build' not remade because of errors.


Reported-by: Linux Kernel Functional Testing <lkft@linaro.org>

build link:
-----------
https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/build.log

build config:
-------------
https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/config

# To install tuxmake on your system globally
# sudo pip3 install -U tuxmake
tuxmake --runtime podman --target-arch x86_64 --toolchain gcc-11
--kconfig defconfig --kconfig-add
https://builds.tuxbuild.com/1zLv2snHfZN8QV01yA9MB8NhUZt/config

-- 
Linaro LKFT
https://lkft.linaro.org

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BG9fYv1Vbc-Y_czipb-z1bG%3D9axE4R1BztKGqWz-yy%3D%2BWcsqw%40mail.gmail.com.
