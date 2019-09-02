Return-Path: <kasan-dev+bncBDQ27FVWWUFRBMPWWPVQKGQEWPIYFHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 78899A54B2
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Sep 2019 13:21:22 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 16sf11429040ybn.10
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Sep 2019 04:21:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567423281; cv=pass;
        d=google.com; s=arc-20160816;
        b=T1SFv8Q1TH1JBBwRejbElEWYGv4b2c9vQOL6RjUxGQ+VsQQ3KseuTZVqN+1dL8Iwvr
         ZxiPxy5YtXGTzmyn1KwoLZ0vFJB7YYygYTDCfmLipNupydFtKb+rcqEsNQeuX64Ml6Ql
         Jrl99AE13+47pGYijDYjRala3uDgy3LQY0jBqb5cG624gnyov8Dq/IlBwSfGppZdpt3M
         Lm9FYIrz0uhhnO9apCaxerS5iYXXQttuubXaY1KkvT0jhg1Ir1WGY/NHZRXKeWUFpgMU
         tVyL0XiL9UZOuLnHFeRc7nrbHZCoOou/vZ+/6SoLXI8yDJ2+YzcrMBP8wBcvuoON3R97
         HeLQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=GgaJ8Ti+eMe664e8jXtYP8GFJTtSC663zrnCeqDYZyU=;
        b=YPTd8ECqohFYN8DyuLcxdzrsCI1N52JjxtXchUzNDDLQhVS985trJ92HDLJDY2rCf+
         f6ssamGbJW6ENbNJNezD/cg7SJCHrOQqGMNKw07Su2+jcyZOtsSfSwOwk5kcobR/XCsr
         BCgaQ0170/Yp/T2V/3VjhaokY6pBSXtKd7DkM33vCXiv3i2F8OpKEUQd5mxk83pfa9SJ
         CUX+/7bz7UWd64Yds4P7WIRWu/DbrbxrV5aSzB/A3gH3OY8TlPue+8xCrLGt+z/yoqT/
         Ph1UjW8Ztjt+HvKVyJNVqInoBSRkNiQ07w/pTSO0ZXo27GQSa8BkT3gRwqrCOgcsEn2E
         FS8A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Rhhm4VfH;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GgaJ8Ti+eMe664e8jXtYP8GFJTtSC663zrnCeqDYZyU=;
        b=Svo/jTF5NsSibu9s/p/RK9oZOOBOlU9EZr0qBSzl7tpZ8peL3gdGu4wml1p5yTiQMf
         dN/Ac9bv8gFQol5AD2K3w7gyEFdaY8uek7eX5SKOhuMr7Gfu28iu2xz6rJThGwXWr72L
         Uy9sj3X21iooYnUwEYnF0qwh8fYb3/rnD2uFUifXxURrpAuPvCw9Qe37gcWljQjmPUnt
         Gv1T+986RcbmMSpSOmOdPfJr2Y7/sW+gxA1815oSl6QV3IbXZ32dwCH0dkgozydXSw4M
         ZCSJCIm6YLlpO2WjpvczzhDSt4qGTdhkHJLTvpmHiEwfF7QBApfbF19VG4J2bgJQtLlF
         nemw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GgaJ8Ti+eMe664e8jXtYP8GFJTtSC663zrnCeqDYZyU=;
        b=H/5rN+70OBvNoz1+OSssxEsGdpmz2Fp1flVYUK/ICE0TQztMtjZJn6mB/4+kylbAaL
         VOr72lFJodRjsXdCLRqvHCkyT2LJjxlyQqCXM0sjQ+wmDJBmjbUsDWFDGIwoctLeaSG9
         mXIT65eAJDbEfexZ7OaPrfdRZ+0qNFhWtdgwu9jjgGdJsEQBGC9O1yDCmRRwTe7+pGJ5
         vUqP3lCxOUDVvlIfo6iD4K4GwagA+q+Pf/SEVgrcdUJAAkBbdlN6tFbCwXJC4ktRmHW0
         trhtPoU6oSClMpwfpD7O7yvFMRqM/mlYcGB5RIhNEprMoyH3G4d93B1OmbJ46dAXvVG6
         cnEg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUZwDDJX7fl4gyETtg4B9fOPTX9SVmzxyrZSvxPQnY920YZ4UDr
	I/EG4YjyOZHgPa9VVYyf8Fc=
X-Google-Smtp-Source: APXvYqzEZhpZAEZvWYOeT7mTOtBZlVXeFaMR37HjmBWoM/nOPxE6EB5KtYfF/K4Az4Pe70O5z5QPMQ==
X-Received: by 2002:a25:7087:: with SMTP id l129mr20563540ybc.420.1567423281377;
        Mon, 02 Sep 2019 04:21:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:77c5:: with SMTP id s188ls1744528ybc.6.gmail; Mon, 02
 Sep 2019 04:21:20 -0700 (PDT)
X-Received: by 2002:a25:d901:: with SMTP id q1mr20752641ybg.195.1567423280606;
        Mon, 02 Sep 2019 04:21:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567423280; cv=none;
        d=google.com; s=arc-20160816;
        b=m3jAXwI4nCTssY/UeHY4mCizj6wv3tUDdAcDjAHJHOW16sjw8slYJ1LS8Bh6GYwf86
         cNh8yiFZojR1hAyy9/qBDcWqU9zZjq9h8csq5yBUbEQk4czmrG867XfvX0g7rJOt/bMh
         tRRf4R2oesqeQDbXhBQv5nKBa4Bux4/VvJ1yU49B2GEoTvoOWxDQPUrNW3OFyOhIa/A0
         Jhzu/eZFw/UKcn7NCdXKML+yex6fYJstPlR9utyjedVbM3xonDvl0odTrnDp+ZDO4L9X
         l/1Wuc0DTT//xb+73Y9Dal2Onm7afk8/XNzSAUk//f+lu9Ifc9E03847X6yAOhyLpXVc
         4/Kw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=73TlGEwK6oKiZ/rkmArAnsPJNae2N4hkEOloXefysjM=;
        b=OJx4ejsZHjSGKiUwHWcbeXdhQiGS1rYkoqh4ljIEBvnQ7aE7yKD7qXz6lLs/kNFXDD
         zQLcRDkqs7loIBjoUaafHQT6Q6+RklDjqYU0b4Kmmr2X6IgTjL7VAIzfEMtxIidOt2h7
         ChOqhJnIlhasJHe6ZntKaDGVAH2S+krUL/mSOp+IrKn6z47zwsFElSJpEDXg5TrnL+dA
         vYpCXvt2IZkWNKlxnQvg0WHuKTy7FsG0rjpLV4nuuTL5EWBRlnZlJQr4+2zKUp57QJ+w
         f/ZGq3Gr2cXsXn93RCv2tEesKoaLSOGBKKle7eE8L0EFxCatMczZUYiqsnQFj5pYgw3D
         Q1JA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Rhhm4VfH;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x543.google.com (mail-pg1-x543.google.com. [2607:f8b0:4864:20::543])
        by gmr-mx.google.com with ESMTPS id f78si212136yba.1.2019.09.02.04.21.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Sep 2019 04:21:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as permitted sender) client-ip=2607:f8b0:4864:20::543;
Received: by mail-pg1-x543.google.com with SMTP id d10so2783275pgo.5
        for <kasan-dev@googlegroups.com>; Mon, 02 Sep 2019 04:21:20 -0700 (PDT)
X-Received: by 2002:a62:80cb:: with SMTP id j194mr34723282pfd.183.1567423279444;
        Mon, 02 Sep 2019 04:21:19 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id x12sm1054597pff.49.2019.09.02.04.21.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Sep 2019 04:21:18 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	linux-kernel@vger.kernel.org,
	mark.rutland@arm.com,
	dvyukov@google.com,
	christophe.leroy@c-s.fr
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v6 0/5] kasan: support backing vmalloc space with real shadow memory
Date: Mon,  2 Sep 2019 21:20:23 +1000
Message-Id: <20190902112028.23773-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Rhhm4VfH;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::543 as
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
means that kasan is incompatible with VMAP_STACK.

This series provides a mechanism to back vmalloc space with real,
dynamically allocated memory. I have only wired up x86, because that's
the only currently supported arch I can work with easily, but it's
very easy to wire up other architectures, and it appears that there is
some work-in-progress code to do this on arm64 and s390.

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

Instead, share backing space across multiple mappings. Allocate a
backing page when a mapping in vmalloc space uses a particular page of
the shadow region. This page can be shared by other vmalloc mappings
later on.

We hook in to the vmap infrastructure to lazily clean up unused shadow
memory.


v1: https://lore.kernel.org/linux-mm/20190725055503.19507-1-dja@axtens.net/
v2: https://lore.kernel.org/linux-mm/20190729142108.23343-1-dja@axtens.net/
 Address review comments:
 - Patch 1: use kasan_unpoison_shadow's built-in handling of
            ranges that do not align to a full shadow byte
 - Patch 3: prepopulate pgds rather than faulting things in
v3: https://lore.kernel.org/linux-mm/20190731071550.31814-1-dja@axtens.net/
 Address comments from Mark Rutland:
 - kasan_populate_vmalloc is a better name
 - handle concurrency correctly
 - various nits and cleanups
 - relax module alignment in KASAN_VMALLOC case
v4: https://lore.kernel.org/linux-mm/20190815001636.12235-1-dja@axtens.net/
 Changes to patch 1 only:
 - Integrate Mark's rework, thanks Mark!
 - handle the case where kasan_populate_shadow might fail
 - poision shadow on free, allowing the alloc path to just
     unpoision memory that it uses
v5: https://lore.kernel.org/linux-mm/20190830003821.10737-1-dja@axtens.net/
 Address comments from Christophe Leroy:
 - Fix some issues with my descriptions in commit messages and docs
 - Dynamically free unused shadow pages by hooking into the vmap book-keeping
 - Split out the test into a separate patch
 - Optional patch to track the number of pages allocated
 - minor checkpatch cleanups
v6: Properly guard freeing pages in patch 1, drop debugging code.

Daniel Axtens (5):
  kasan: support backing vmalloc space with real shadow memory
  kasan: add test for vmalloc
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC
  kasan debug: track pages allocated for vmalloc shadow

 Documentation/dev-tools/kasan.rst |  63 ++++++++++++
 arch/Kconfig                      |   9 +-
 arch/x86/Kconfig                  |   1 +
 arch/x86/mm/kasan_init_64.c       |  60 +++++++++++
 include/linux/kasan.h             |  31 ++++++
 include/linux/moduleloader.h      |   2 +-
 include/linux/vmalloc.h           |  12 +++
 kernel/fork.c                     |   4 +
 lib/Kconfig.kasan                 |  16 +++
 lib/test_kasan.c                  |  26 +++++
 mm/kasan/common.c                 | 165 ++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |   3 +
 mm/kasan/kasan.h                  |   1 +
 mm/vmalloc.c                      |  45 +++++++-
 14 files changed, 432 insertions(+), 6 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190902112028.23773-1-dja%40axtens.net.
