Return-Path: <kasan-dev+bncBDIK5VOGT4GRBEN77CCQMGQE2CLPPSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id B415739DDA5
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Jun 2021 15:30:58 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id x15-20020a17090a46cfb029016dd9f9451bsf5294093pjg.2
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jun 2021 06:30:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623072657; cv=pass;
        d=google.com; s=arc-20160816;
        b=FgFewKOycXyl9rHqDKVDt3cupbPyf097wmWhQ3xGxlQ5aZ1wDY9BtnvYYfpWvIB5jQ
         85662BnTfcTaDNbLD5ICoj2NEt/P+1Tq/tR+PErSTuNth700bxAOU6vTmTJRBa37s9up
         PqtXto7P5OqQKXLWuA5/9zzcTqP1g228nOSTj3NE09Rb0V4Yx6tnKQtcmEWQ21smFPjp
         uKztIPP62NgCPPtzZldXEXdV7XgiHEPQjoL8pC+4Z5oThoPp+Sb5As6iU251LIfa/mWY
         MGOkgvP1yWK4i3QhS9Xe48mFDNdSJGJzYwBPIEwj8WmZAxWjbkFnQl+y/r50w88R1isP
         6Uyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=tIPYtS9ocovXdsAqbd7vGyNT4COy3SGhI7C8h0UFOLI=;
        b=W3L66032GKuOhVrAY3mE+DubO9bPessL/CeIYHanmteIJ8nmkh+36Tz08smdISyfVq
         d63T5tNNrekWgQ4jsp0+CYgqTktIBvQPCSKHMiv4MMy5KtO4n+Z4Ba5IwJoJjlKyK8L8
         s0j2JuDN/w09NAuZhhwIG2Jml396U/PMOV4VyzaOlHjRVQ0+4dx+LiC+Em7i1VXG7V3j
         0474Wcyhc7P9VLZxKGLVN7+Ehzk+IZgAZziTLVfRRlgHCYssSkVUlWHsLHV7a0G8k1Kc
         cS8HQNbpTXy7o+AYfusVRxiJvUfwIvM3OVjW5NTq/SGIv7ek5vpUYN0X6REY5n1ehV3q
         lMYw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tIPYtS9ocovXdsAqbd7vGyNT4COy3SGhI7C8h0UFOLI=;
        b=FIr7GNP9k3VI+jUodaeJ7cXnFRkXaY9TtxLa1QNhHULBTAXMeO2BfrzTk3dCnYfHTn
         +KwoNQQBeHxFTUOEDVm1SA9/PHigt55bNxJEtF7NttsU1rSFO1g4JuROrGjLXbp/6j39
         76SPvCE9W0Rf7FytILVEypVKohAmfBeGwoBuv7520ChnIXz0WkwcaI5XXsUEXLxE4WQ9
         BAwGp4s103ZvBLZICNXAV8iHGWJefdbRcksMmzKBw648bU6LZIUy0FmGT3BlEkpFUSvO
         gnQQv2yPsl5fiiUGdGAFGNQMJ7UuhtL0IYrYgb1I6aNabo7L6JjMmVaX6w4WdcFhejt6
         C7oA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tIPYtS9ocovXdsAqbd7vGyNT4COy3SGhI7C8h0UFOLI=;
        b=O4VJHa3whSLDdspm6o+vo+vMx5DxTmJ/aLunChtIqq6JooecoRpm8Qi+wO/DYpSBVq
         NE6tUXMaIvR1UsphanNBcxJJfbxgyIj7D9Jox9lgtFGtL0upwF4fWTAaLD8hRF2LECGL
         NaDq/rWR+MaNRXeS7RFPJUYZRyfOpv9+1XNs76lavB0UiGe6Wf5lHoIbbfmYhx5hJaXy
         1gk+J5aX4IcolQa9g+Mqd4gKKsxYxq+BK/12l8NlwFMz+E+3W9Qflprg3j1uU+1kTGlJ
         9w9Ro3UZDMrCorv463IuNdam8vcEpa78suyT3aJXjR+xCfwLn2JCkiY1h8wiCxpurvXK
         v3ww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532m4wxInWf+eKyedipqr5Mr8PLlxxyLAEn5WzOAVzLG6FHYnSeq
	Zo45AsDnBwPwDmcTn1zXVTA=
X-Google-Smtp-Source: ABdhPJxLVKrLlzziMIM0AF4367RqdBhf7ujAliXYcX14oloaRAAEmlbHpHcCYe6Y/iYnipPkBM9J/A==
X-Received: by 2002:a17:90a:7188:: with SMTP id i8mr6362503pjk.189.1623072657475;
        Mon, 07 Jun 2021 06:30:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:1d2:: with SMTP id e18ls2624179plh.6.gmail; Mon, 07
 Jun 2021 06:30:57 -0700 (PDT)
X-Received: by 2002:a17:90a:db04:: with SMTP id g4mr28318654pjv.81.1623072656974;
        Mon, 07 Jun 2021 06:30:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623072656; cv=none;
        d=google.com; s=arc-20160816;
        b=zX6CmToZMnrty8bXo9rfwKc66EGInoJpIb92EA5LXx9h5eYH1dzYqZ8ZWCLS9CHRQ/
         wxsx8rjHiAHNY5lSKKv2wFZtz1KAvSnVzg2WDI1VnZBMLFhErjFAO5yI3mdkGzBbYLEK
         WoxPpHPuTDFfdtODAn+GDN6sJ2b+xYm2A8GE8a4Bb2c/5LltuG9R7IjEp6kO+JZKkfWl
         AX2cTJWEMSMkAGZ/Qts30sGr0urjVtvyLgEwIoi26k974sAQKV6psAuYQjHinuLK6U6m
         /1rA8BTXXJs1QYmTXKbnM6EbVf/O3STGfHwNkG2EoWdLrZLIXyAwrLGrpz6AkYy6yHsd
         sTUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=VJUwT0YTYjSyUglOcHZq+j1MTPWtXrlt3C8dX3KW4QA=;
        b=sm8ikQOoWEi9CPeaKp0s9CnK/XTKKOXE5DWcCZ1cwMw4seTu9L/DXttpufvF8laDQM
         BpWGJw2AOV3P85KnO5ufJl39sCQl1AU4pqKtdj0sfj9va5mXj6cqkq0QHpedi6zzsVPr
         ZzSAZYg6iMpsx9zCaYocje5a2LEH9VgLo5jpAtM/hnwcT4zqYL6q7Z2m0SBR1753x2Dj
         VibJQoFZ41Ued3wAK4PUwKuUxeiWsJQpTHI1Dh66qRXpuNzKC5aiK0X75lAmkKKutNQq
         9W76eFqN4n6194NwT2aBddlI/nLO9eDX4k0uQdnAQE2dHuGZMR9ugB2MUxDr+ENjq8zH
         JU0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id f16si945752plj.1.2021.06.07.06.30.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Jun 2021 06:30:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggemv704-chm.china.huawei.com (unknown [172.30.72.56])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4FzDh80WTkz6wvJ;
	Mon,  7 Jun 2021 21:27:52 +0800 (CST)
Received: from dggpemm500006.china.huawei.com (7.185.36.236) by
 dggemv704-chm.china.huawei.com (10.3.19.47) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 7 Jun 2021 21:30:54 +0800
Received: from thunder-town.china.huawei.com (10.174.177.72) by
 dggpemm500006.china.huawei.com (7.185.36.236) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2176.2; Mon, 7 Jun 2021 21:30:53 +0800
From: Zhen Lei <thunder.leizhen@huawei.com>
To: Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann
	<daniel@iogearbox.net>, Andrii Nakryiko <andrii@kernel.org>, Martin KaFai Lau
	<kafai@fb.com>, Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>,
	John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
	<glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Luis Chamberlain <mcgrof@kernel.org>, Petr Mladek
	<pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Sergey Senozhatsky
	<senozhatsky@chromium.org>, Andy Shevchenko
	<andriy.shevchenko@linux.intel.com>, Rasmus Villemoes
	<linux@rasmusvillemoes.dk>, Andrew Morton <akpm@linux-foundation.org>, netdev
	<netdev@vger.kernel.org>, bpf <bpf@vger.kernel.org>, kasan-dev
	<kasan-dev@googlegroups.com>, linux-kernel <linux-kernel@vger.kernel.org>
CC: Zhen Lei <thunder.leizhen@huawei.com>
Subject: [PATCH v2 0/1] lib/test: Fix spelling mistakes
Date: Mon, 7 Jun 2021 21:30:35 +0800
Message-ID: <20210607133036.12525-1-thunder.leizhen@huawei.com>
X-Mailer: git-send-email 2.26.0.windows.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.174.177.72]
X-ClientProxiedBy: dggems703-chm.china.huawei.com (10.3.19.180) To
 dggpemm500006.china.huawei.com (7.185.36.236)
X-CFilter-Loop: Reflected
X-Original-Sender: thunder.leizhen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of thunder.leizhen@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=thunder.leizhen@huawei.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=huawei.com
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

v1 --> v2:
Add "found by codespell" to the commit message.

Zhen Lei (1):
  lib/test: Fix spelling mistakes

 lib/test_bitops.c | 2 +-
 lib/test_bpf.c    | 2 +-
 lib/test_kasan.c  | 2 +-
 lib/test_kmod.c   | 6 +++---
 lib/test_scanf.c  | 2 +-
 5 files changed, 7 insertions(+), 7 deletions(-)

-- 
2.25.1


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210607133036.12525-1-thunder.leizhen%40huawei.com.
