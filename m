Return-Path: <kasan-dev+bncBDQ27FVWWUFRB64FT7WQKGQETAB6JRI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 30DB6DA307
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Oct 2019 03:25:16 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id o11sf866419iop.12
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Oct 2019 18:25:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571275515; cv=pass;
        d=google.com; s=arc-20160816;
        b=kjQ9Mz/IaQDc/QGeatspiZlRW5To7oGuFybOPh++COr3WMc57h4vaxt54OE/jz3gXL
         ZpacvNqwD3+LRZZv8zzNunISWmi+FtpNJoNdRt/wTXnQRMzlqlDT2DRuqzOwAcxCkzm9
         sqhHPIOXbDt6Z4V5KV8p8rh61QIEFJByMotG5LK9hRQ+/TQ0aQeaeY6Sr2/a/miDQPi3
         CSwZN1sQqwFUc/Q8yEAJSUM+sTb7OWna7SiMCZP4KeVR6VYU+5Ot6DMBas/HJmwZF7OL
         7XemZoqPAQyZujo5gkU088gQ0ZGWtu4hgwpjOnRNczwixQTE5UkutbPHazUQbAmKE7W+
         EPZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=KXcNqOsHEim90A7R0CQgSz45LVAz9z36rWbQuTsURG0=;
        b=V4TdADQ8eNjjf2wUsII7+wjgKMSDiNPMlNNHHZWTFWq4/USKJoXy7hqJRqoDO4fgsv
         oLdggNHe+kA2ZBspx4ovs7CYP6wtiaDFRoW5HFn1t+kSLPnq0SByx/+lRgOO9qN1SUUS
         Rih5orAHNMq1jvTcFgbjWwHtyIvnqFB8kOVn33j+Te0C5+WJgYbq4KhaiNAiSidFIWKc
         tVg6s8pNOXfS2zprDlE2n37B0U9YQECg1cdtDewLeFXD1dW1UTTmmNxBjnpsgpaEkUg0
         Ch51oQ+rxl17KuF486u7PCRWZufadbXRyyHTb6xeHOKMOnM9OPCtoCPGFqPXwoLHmcEQ
         ktfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="LV/Egggh";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KXcNqOsHEim90A7R0CQgSz45LVAz9z36rWbQuTsURG0=;
        b=jVl2S2s3bdyMt42MpmHFieG98vAWNEWD3h+MzxJ224YCQfObYzsQBVLXcLUnzoHq32
         T8YP1avPUWDRM8OD5aUbqb7fFMCOGe5JTLNU4bbNpfVyuCdF4td3bQ18MSNKSBZb520U
         5YEUC3S3gmg+koAgqYWqMAsKeJO8l4bm6WtEWwcP4CcRONZ7QPaN4Ro1O7ZeBvqLAAU1
         K2bGBNUBTTvFOCEDmY2gBx7S+0B/JwgZFDIijf0jyrqxeVfdnjk4ReJrZlrRgKwnHP+0
         9O7gfFvpkRd9BFBrJjERGLgpmtPMasDd6yfihqzztcADUA7CCU/Rj3vBZEAU4y4evDBj
         Ve8Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KXcNqOsHEim90A7R0CQgSz45LVAz9z36rWbQuTsURG0=;
        b=jzPycddQHwIoLo9TaHUrxx72us3EXe7/g6TkJI7LdAmnX0yeXbqQ3/Yh1NjMAtTPBt
         BFt28OkhsVOPjq9Hpde9gaqy+BOhww0ktj7gudWavhtCz+b2bZwS0LYCogTDFaW0L6+N
         wN/JqNEYmGuopM1pf10UEkOguTdrRjNFms78gKZahYGSCzCZ51Yo6dNobRba5eKM9hiR
         j+mvTFHUDpkQ4svEBJYERuiXbXtNE3zu2QO9HPEHQb8p7lUBXMsHbNPDYfsWu4b3bNfi
         a30cAGuqoQwKHXpQ0SpIyC5lsgU0oWD6Xrh9sTwQHpcx/qeQ8G7NswjzCQ+L1vOOwTwx
         4VsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVYt4ZxPXHPYFzJyU5ZXdsQXizB7qBbNuAU7V0K+HqbuJaFeua8
	atInz/UUCyhGRqhjjEChxtY=
X-Google-Smtp-Source: APXvYqx0VVtz9eW37gReT+Hp5IIlp0iZDR9qq4dQw9mvoX64p1byvQnibE4n70RwXLfg21Y8fejT0w==
X-Received: by 2002:a05:6602:158:: with SMTP id v24mr572923iot.91.1571275515133;
        Wed, 16 Oct 2019 18:25:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:5d01:: with SMTP id w1ls159357jaa.2.gmail; Wed, 16 Oct
 2019 18:25:14 -0700 (PDT)
X-Received: by 2002:a02:3903:: with SMTP id l3mr909861jaa.72.1571275514680;
        Wed, 16 Oct 2019 18:25:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571275514; cv=none;
        d=google.com; s=arc-20160816;
        b=nDqDEudbKDahdETztpl5jmn14tWwWw7zdFSRYeqjLH4PDzPdg7W+s8qaV74NVK2rDk
         sDTA2cd2xdKDSJd2MR9V2I1eB7tKFw6Rwe3Zd3c3JZoZy7S/ghWuukyManXL2OI/5Zl4
         EnuhuXiFbz4Df1wKnxPt70yD6a+HOGZLppOdgI+8hWY5aEw5byUACbcFQioun+0nzJNj
         HYCwAZRs7ru5y8zbnxJsVeD32L3AQcwUfsCM8eymP3Kdz2FqBIB23mXF8TeKgpwewNzU
         pEwh6ffMWgt90Jy8bOaKJC6/47pFR+kysfomLvKHWaC42nbGeRYWxf1jLWSD7W5XuDoE
         HOEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=/v+BCQB3jIKYbebgETHehC+eMOtsuCBonYyqEVSANPw=;
        b=AXwLDaS2H8bFR1wjfPakghjCs9JOg53aRB7JPBZCJViFH69QFbWRSmU0BQ+OhNm+1j
         /xDfcv7l8OvydBMzzkIFI/JeEFgFmMEGbBcKKpJOvNfzP1sZzQEuhusNkeFxNQmyFJ9v
         Ekpeth/Gc6LcsqBCohz3Ydz1pbnv/WPSi0GulLtNuS8hrgCH0XG6Fz7HkL+VC4a0vFla
         Q712eb4jdYxBLuQpPu/SAsNz75HMq4EJHVUAnEtudc1ImJRFPqqrUNs+eM0SVy6HoN1R
         lnWXAeLZ85yXEbEnLRj2elsvk1wmwkaAhK5jixI0a6b+xLAybI0WVxPIxJUxF92BBXoZ
         D8FA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="LV/Egggh";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id i8si32641ilq.4.2019.10.16.18.25.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Oct 2019 18:25:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id t10so281227plr.8
        for <kasan-dev@googlegroups.com>; Wed, 16 Oct 2019 18:25:14 -0700 (PDT)
X-Received: by 2002:a17:902:bd08:: with SMTP id p8mr1254986pls.248.1571275513540;
        Wed, 16 Oct 2019 18:25:13 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id h14sm348412pfo.15.2019.10.16.18.25.11
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Oct 2019 18:25:12 -0700 (PDT)
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
Subject: [PATCH v9 0/5] kasan: support backing vmalloc space with real shadow memory
Date: Thu, 17 Oct 2019 12:25:01 +1100
Message-Id: <20191017012506.28503-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="LV/Egggh";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::643 as
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
v6: https://lore.kernel.org/linux-mm/20190902112028.23773-1-dja@axtens.net/
 Properly guard freeing pages in patch 1, drop debugging code.
v7: https://lore.kernel.org/linux-mm/20190903145536.3390-1-dja@axtens.net/
    Add a TLB flush on freeing, thanks Mark Rutland.
    Explain more clearly how I think freeing is concurrency-safe.
v8: https://lore.kernel.org/linux-mm/20191001065834.8880-1-dja@axtens.net/
    rename kasan_vmalloc/shadow_pages to kasan/vmalloc_shadow_pages
v9: address a number of review comments for patch 1.

Daniel Axtens (5):
  kasan: support backing vmalloc space with real shadow memory
  kasan: add test for vmalloc
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC
  kasan debug: track pages allocated for vmalloc shadow

 Documentation/dev-tools/kasan.rst |  63 ++++++++
 arch/Kconfig                      |   9 +-
 arch/x86/Kconfig                  |   1 +
 arch/x86/mm/kasan_init_64.c       |  60 ++++++++
 include/linux/kasan.h             |  31 ++++
 include/linux/moduleloader.h      |   2 +-
 include/linux/vmalloc.h           |  12 ++
 kernel/fork.c                     |   4 +
 lib/Kconfig.kasan                 |  16 ++
 lib/test_kasan.c                  |  26 ++++
 mm/kasan/common.c                 | 237 ++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |   3 +
 mm/kasan/kasan.h                  |   1 +
 mm/vmalloc.c                      |  48 +++++-
 14 files changed, 503 insertions(+), 10 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191017012506.28503-1-dja%40axtens.net.
