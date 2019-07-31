Return-Path: <kasan-dev+bncBDQ27FVWWUFRBLMAQXVAKGQE3EP4ZMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 613407BA79
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 09:15:58 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id v17sf33102174ybq.0
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Jul 2019 00:15:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564557357; cv=pass;
        d=google.com; s=arc-20160816;
        b=erW2+gmukHMxQTna/K9IiFM9A4mEs9pYzplEyvUlurFhjzDQb99MjYi/qYR7RKTnBj
         y8hpY1PUrFLJrwvbjL38qneK/AIbpp4lakle3ySaqESsMPDXwj70grg3f7iVa25Yqg6w
         F3Zbj3Nkj0aGWhsAPuPLi5u0ETRGCvR6rtsY6v72kBeZPyKk//37IXqysgTJI6dSzkAM
         o3jvF4PRSqXJpFwo+tzQH0gDh5Bi4X6U2L1tmm0VA0fLJmOZAXrlKEYonkH8WrohcTdi
         SA8LIYSnyW0mTX0qhSe8z0nLJt9IoGSo4jd5qywfbi390vin8QRB+lzATPCk0SbXTacB
         NG6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=NUn15KZsf6TC6k4FiY5WEPeo6GiAH+htk0UFtV9QSko=;
        b=nTd0SW7Q3HiE5MuKmA4JyBkJxOcCQ2dsKiQ5o2z1UxEMAC/hLz0K1eG6XieY9vISiV
         G/EGexlgCdFWMD9kSYJfBNL76BWHpXHLm+st15UDY0GsMJm4616ZHtvGMWB6o8YdBjRX
         bl9uzNBFSFHvNGwHJBEA+ZAoxoG3i+t7gtOYPNHpsTHwM+BOhv1aSPsFZBjW0xNP4GL0
         giUyjrEAEhdBRRLoNrwui7cxxme0CpPiGT7n6nhNez7gkgP249x3+s8AdE/BclfG+9/O
         rCUseeCy1oEiEJLOtfbRJsHI9hXwP2lZlyrGkH/geaVvReMnlTzK0u0qlPDNlfIjHe39
         T7og==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=AHPx62HM;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=NUn15KZsf6TC6k4FiY5WEPeo6GiAH+htk0UFtV9QSko=;
        b=OlDvtGh4VHGDfHbZpBPx0TzHC43Idi4Y81ue2in6xf0JSr0A7pKyU6HMAPieAaWvlL
         n57UYoTUgrWMV9J6WKrI2gXSyEI9c8w1oS96DAGisi1THzalFtgOrJDuNq1PoXQGSIgy
         SzCm+oh3jvZ2e3/xx9Xi33WSwJclwiEj3AuEsFwxQg3Lu5ht/f028XFcvPX5hpVYNcG4
         P+lkj1/LhhActJWhLZeROSh3u+zAXFpJl+vLBS3rkarq8jH4hftmi4WuCOluvDRmEaKU
         /YUL12NRxF5t2mmmNTNyW+UwKMs2JzENyubGy2wwrgx9pcKDim1M0+7qPPKg91AvPmR3
         oq1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=NUn15KZsf6TC6k4FiY5WEPeo6GiAH+htk0UFtV9QSko=;
        b=CXrr9lIjkYAYaI0OjbXXht2s+oKGHlvpi5cFv8DvZDxG7tgg0fBa2SE8ujMH0LlYcE
         UgeQ9hY/Oh8o5HBnMwZaY8Ss4x2rOyNHSY5614QAJ/i+sEmADL5iFcdELASGBhhsVPKg
         fjLptlylPQ/6Yo589dKNMPZlvV8cjHjvwG8MlH5wxJ8ZWrLtIChzuDMBitcxvGR377YO
         rz+9/8U6I1jFZoe2qUk+VvRoTGEuvY50iNOvorR0orfCOMA4TEG3373PW+c20LU9EnBi
         5Cp5mzovEvGpr3WfGq3nhMbxXtPhuClF38iUBXX1yCcgTRrZwrmoJ0hF4o9cNaYCwXlC
         6okQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXAwSev1wf8UDiKJYicSqDmUJYOpcb3YPShXOgijx7crPzZcl3u
	DALYdBKRx35QlsCJV418g0c=
X-Google-Smtp-Source: APXvYqweYeQhIz63TpO5tvX+y2QZ4/wz5qA88A+Fyat7CXhqpEsGKyu6A/HzrtyGw0uhc1eaFqJ5oA==
X-Received: by 2002:a5b:b12:: with SMTP id z18mr76561172ybp.373.1564557357271;
        Wed, 31 Jul 2019 00:15:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:410c:: with SMTP id o12ls7816189yba.8.gmail; Wed, 31 Jul
 2019 00:15:57 -0700 (PDT)
X-Received: by 2002:a25:bc0d:: with SMTP id i13mr78236127ybh.253.1564557356987;
        Wed, 31 Jul 2019 00:15:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564557356; cv=none;
        d=google.com; s=arc-20160816;
        b=BWsBbl253bdfGWzu/sBAE6y7vQHBgiyJsCkdBTm4sfU0xR3oHz309rcdml3LcVAFx/
         7KUBhitT0t5S3IDiQRhp1zc8ZguOqG91Qe9orQxs1nkCqYFLIDN9zT9ySKdOvey6bizH
         WHRyFH4L0lqkB9wTMspiPxFbI8Oh/e8UkqVpcAHtPOfF4028aDSXBX2Ma9DVsCMDI8De
         /6ha28Ra4HIK7qaDyPEBzVJno3bbg3kv9o8HNKB/I6seY9DNK3MJrz90ELx1U9Q058Ev
         +pcM8lYTI6SqYfWmSNbUN2aSR2OzcqeeCO0B01SSxh9qHKNnzYqvtjtdOPKhOxr2XbSs
         WHPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=pBb3SjcJAJvGT3ZKVh7XtBW59bi/thuEuHRFZNsNtKI=;
        b=ow9Qe+CEjLpO/36R1I9kC2JMUveuA91idBHyFIROmK0rKMtZzyrfiqhOQVGs9Abth4
         7nQTrbV9emDRdnT5pgXeiedY/e6DCXE50DjqYC4i6RxMIQi88NrJXpbMXebSOTto59ng
         UNBR0dW+NmYqMB5Ss4H3wTHIzh/tZjUR9Wh4WLZBR2cN5aMoYui+KNHzDFN9pJT2Gew4
         J2kUIE9o7LATBawIC1mv8MBhOmmZPqXY6gHrM+uhQydiG12UUPeSyZV9gM53SCvAJ2gS
         DX92Wy/0i/5Uo3dd2tGT0pNgZmMludIGZC4Zs1Wv6OMEjcSbOhUwnb9tPz/dafxtXipH
         xQeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=AHPx62HM;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x442.google.com (mail-pf1-x442.google.com. [2607:f8b0:4864:20::442])
        by gmr-mx.google.com with ESMTPS id j15si2956972ywa.3.2019.07.31.00.15.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 31 Jul 2019 00:15:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as permitted sender) client-ip=2607:f8b0:4864:20::442;
Received: by mail-pf1-x442.google.com with SMTP id g2so31338039pfq.0
        for <kasan-dev@googlegroups.com>; Wed, 31 Jul 2019 00:15:56 -0700 (PDT)
X-Received: by 2002:a17:90a:29c5:: with SMTP id h63mr1357413pjd.83.1564557355793;
        Wed, 31 Jul 2019 00:15:55 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id x13sm71508648pfn.6.2019.07.31.00.15.54
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Wed, 31 Jul 2019 00:15:55 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH v3 0/3] kasan: support backing vmalloc space with real shadow memory
Date: Wed, 31 Jul 2019 17:15:47 +1000
Message-Id: <20190731071550.31814-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=AHPx62HM;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::442 as
 permitted sender) smtp.mailfrom=dja@axtens.net
Content-Type: text/plain; charset="UTF-8"
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

Currently, vmalloc space is backed by the early shadow page. This
means that kasan is incompatible with VMAP_STACK, and it also provides
a hurdle for architectures that do not have a dedicated module space
(like powerpc64).

This series provides a mechanism to back vmalloc space with real,
dynamically allocated memory. I have only wired up x86, because that's
the only currently supported arch I can work with easily, but it's
very easy to wire up other architectures.

This has been discussed before in the context of VMAP_STACK:
 - https://bugzilla.kernel.org/show_bug.cgi?id=202009
 - https://lkml.org/lkml/2018/7/22/198
 - https://lkml.org/lkml/2019/7/19/822

In terms of implementation details:

Most mappings in vmalloc space are small, requiring less than a full
page of shadow space. Allocating a full shadow page per mapping would
therefore be wasteful. Furthermore, to ensure that different mappings
use different shadow pages, mappings would have to be aligned to
KASAN_SHADOW_SCALE_SIZE * PAGE_SIZE.

Instead, share backing space across multiple mappings. Allocate
a backing page the first time a mapping in vmalloc space uses a
particular page of the shadow region. Keep this page around
regardless of whether the mapping is later freed - in the mean time
the page could have become shared by another vmalloc mapping.

This can in theory lead to unbounded memory growth, but the vmalloc
allocator is pretty good at reusing addresses, so the practical memory
usage appears to grow at first but then stay fairly stable.

If we run into practical memory exhaustion issues, I'm happy to
consider hooking into the book-keeping that vmap does, but I am not
convinced that it will be an issue.

v1: https://lore.kernel.org/linux-mm/20190725055503.19507-1-dja@axtens.net/
v2: https://lore.kernel.org/linux-mm/20190729142108.23343-1-dja@axtens.net/
 Address review comments:
 - Patch 1: use kasan_unpoison_shadow's built-in handling of
            ranges that do not align to a full shadow byte
 - Patch 3: prepopulate pgds rather than faulting things in
v3: Address comments from Mark Rutland:
 - kasan_populate_vmalloc is a better name
 - handle concurrency correctly
 - various nits and cleanups
 - relax module alignment in KASAN_VMALLOC case

Daniel Axtens (3):
  kasan: support backing vmalloc space with real shadow memory
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC

 Documentation/dev-tools/kasan.rst | 60 ++++++++++++++++++++++
 arch/Kconfig                      |  9 ++--
 arch/x86/Kconfig                  |  1 +
 arch/x86/mm/kasan_init_64.c       | 61 +++++++++++++++++++++++
 include/linux/kasan.h             | 16 ++++++
 include/linux/moduleloader.h      |  2 +-
 kernel/fork.c                     |  4 ++
 lib/Kconfig.kasan                 | 16 ++++++
 lib/test_kasan.c                  | 26 ++++++++++
 mm/kasan/common.c                 | 83 +++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |  3 ++
 mm/kasan/kasan.h                  |  1 +
 mm/vmalloc.c                      | 15 +++++-
 13 files changed, 291 insertions(+), 6 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190731071550.31814-1-dja%40axtens.net.
