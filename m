Return-Path: <kasan-dev+bncBDQ27FVWWUFRB56I2LVAKGQEE74V4BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 994C28E1BE
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2019 02:16:56 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id z93sf905781qtc.22
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2019 17:16:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565828215; cv=pass;
        d=google.com; s=arc-20160816;
        b=UbC3R+00GX1O+AltsdONFTQCfMTwgCVWXV7tR2saLmDWg8vkTf8gg5i6jbRDRUWpNr
         03puN9eUzboVeXZDkyV8qWXsOCxX3pdlQXn9qbNW7jJM0EOQPHV23QRsSLKay/vSYXmQ
         UUh6V5fkkAmcdpBPtTEfntFy5sHfy60cYJVLn9EaMj4sLvbYEb6bASiAP78Q373zI8F+
         +2HHHLa4mn3GAXntl1TW9Chdvgf1mVnfk4DbgBMWHuls9yMw/nvsoXX4fMusowB9GCNT
         yexOnZJFp1/GyBi9RFLV5H6xJwjcfiD35Q2jrzM3ach+p2OvjiASA7w6accfHYhuQ2Fr
         u3LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pVw0o9/ls5hzD+lUWOBeL5pMUpLzVPIdOGFAGqE91C8=;
        b=ne+UeKtkvrSOZ/tVC1GEl1S2gfFwAiJRzoCA8EvKEa2BhljxYmvNavTRmVgYLXj0Yd
         L0j6LXdFrJOAyV46iIvalYc8JQWaOSArnmDX2v9F0R9aczeaNrh1xyZU+Ei3S+P0N9yr
         mCMyN/scuAJMWtiXTQH415/k92e2VYV3Twb7xPl3Xv3TyJvNIH9coH+A5/aISIDDpqkc
         ZeIuCYzf/WE9ESdFDuVVuPUPcQxroMoYQHyqBIDUo8lqnNL8GkbniNZ3AIH5VJ18h7VB
         B7cFt3sl57csHtJ0HbfA01C15sHZCwpzMuh4ZJj9vt8Hi5IcFNEQEioqPGh0Z1wUZ9M7
         kASg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bkxZ5igs;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pVw0o9/ls5hzD+lUWOBeL5pMUpLzVPIdOGFAGqE91C8=;
        b=EWR4kdfPuSpdqf1mTbOPA0Bi6sIklU9REWTOTjmQ0zPaG5lj9ffjNIEVqxPYpk++A0
         fdH/o75mz77VnwbMH1U8vxDAVNuXLIz72dl+L/B08yqkD2o3ZA+USlDFqmqU+yvJ0BPA
         QA9PTrTwrVikiSROW70otM3NqpPr0VmnjIT5NX97mCeMfi/zWuP3sgUxtjq5eVa3V4Ap
         mGwbkrYwBcsG6Qolh2hZYctyJKwo2O4V0StA6KVqCEVJzwfu0ttcff90lM55QV3dOjDG
         otUbdJge2vYNYriHoQqHC6ES8bebAalgv2/UcAx1222r8fPl6g3E7IOS5pm0lDCCnxdu
         WglQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=pVw0o9/ls5hzD+lUWOBeL5pMUpLzVPIdOGFAGqE91C8=;
        b=kAOVn7x6OImAmUYqNcEvH8JVhCDksxqaTCoI7RqQ58imHl4C/rVa8mK0dvr8lWohLA
         FQO/DvH/4/SXn50+enLmJjXgQ2h/l5pq8ekRgYkHv2c18VW0Gv4lJ3pOg5WHB5dxZjJJ
         NVKve0qi5Dkyr9QWZ9CHtWXEgXyNmqUGnqzTVo6x4NuE1ATXI3S4LqdF39jaoa93Y34D
         qVL54s1+lHZLKO10Rj7rAJ8k1nWLMol5iqDLStC1scJLWvXcg4y9Ypxk1AXfV/3Ve9hD
         gTuUTqKb5obGb39PU+SzvQ44ocRus0ZmWhB8SlI1JKNgwXHAIvc1IquO7kWR0oZrxiwz
         FvDQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUV5NpSD2SzS+VhV0Ak0k5Kc1pU+aX4S670rvt41fucaRBRwZab
	SulwOkulqJEOeZ92erD5Rrk=
X-Google-Smtp-Source: APXvYqyVr1oBL9JgHpr3MxH/h7b+IxvmtUFuyv1wtTgFqnj5j5PX3qZvMT1ZFHPJu3kFVNWwAZQwJA==
X-Received: by 2002:aed:3923:: with SMTP id l32mr1695350qte.339.1565828215601;
        Wed, 14 Aug 2019 17:16:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:d801:: with SMTP id u1ls1042760qkf.13.gmail; Wed, 14 Aug
 2019 17:16:55 -0700 (PDT)
X-Received: by 2002:a37:6583:: with SMTP id z125mr1746991qkb.21.1565828215293;
        Wed, 14 Aug 2019 17:16:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565828215; cv=none;
        d=google.com; s=arc-20160816;
        b=H9iTk6yOR+3WSdoNg5imqkF4dOWZedp/8V0F/wTpVs0HVYF+hpO1hBwwj20Crk0+XB
         5Cc+wQ+uN+nqnm7H8nBsOzigKC8XdtcHtPnugP6omxVzA11u1qFw9/P2RJQ2GgWZ4VH9
         eSHkuHzc7MU4gv0mLXDqvxPxgfEiR2fnELbdUpTwefdWvrmpu5ryOPOhjmBXNFXdo2lc
         DIC9X0Lp1SWorVIJhuRkG+3RHP2sWerpiFSjC2/du1BHuPLGg1rFciQSH3fxPLGM34kA
         WJqVBtrdpV3i8g4nzaPBO0gV47CjEqwukvOvZl0vAsI54qoZmogQ+7SEDQOnRWaONpVo
         Gr2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=G8E+rJpVyLTQoZWEfd9l8Yi8PuLGKA2rJdGSnf5/Kng=;
        b=ihfRnXXGH51amdlGUqVfCja3M76pGm+3wGO99pbOGeUlOeYeEIZMlLpD1if5T1MfqX
         oHhokaflkEf0s2NZrnwbBf9iybyi9ddORFKkoR9i+uZsGCW7Uf3yrmdYomKAUpoheUVE
         Rk2wwhMJtOcTLjJVx7VFlxu3un3g5yAbzJaiZp3POPr5Acb3MtmW7eUzYVLxRhputM7D
         TSQwMj92/5/eX5FmWToQLWwGYLueKWYUHqdjh4LEMS4DK1TW2gSHqvrjUNoAuiny5NuQ
         ygO63ee71ooLL4Pe4kx9aBuhQtvf/fViKGTemHql+D8GZon+FPnwUODnRV4V/Y1X3Ogp
         EdYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=bkxZ5igs;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id p24si94164qtq.5.2019.08.14.17.16.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2019 17:16:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id g2so387279pfq.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2019 17:16:54 -0700 (PDT)
X-Received: by 2002:a62:b60e:: with SMTP id j14mr2722718pff.54.1565828213449;
        Wed, 14 Aug 2019 17:16:53 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id m4sm1197573pff.108.2019.08.14.17.16.51
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2019 17:16:52 -0700 (PDT)
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
Cc: linuxppc-dev@lists.ozlabs.org,
	gor@linux.ibm.com,
	Daniel Axtens <dja@axtens.net>
Subject: [PATCH v4 0/3] kasan: support backing vmalloc space with real shadow memory
Date: Thu, 15 Aug 2019 10:16:33 +1000
Message-Id: <20190815001636.12235-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=bkxZ5igs;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as
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
v3: https://lore.kernel.org/linux-mm/20190731071550.31814-1-dja@axtens.net/
 Address comments from Mark Rutland:
 - kasan_populate_vmalloc is a better name
 - handle concurrency correctly
 - various nits and cleanups
 - relax module alignment in KASAN_VMALLOC case
v4: Changes to patch 1 only:
 - Integrate Mark's rework, thanks Mark!
 - handle the case where kasan_populate_shadow might fail
 - poision shadow on free, allowing the alloc path to just
     unpoision memory that it uses

Daniel Axtens (3):
  kasan: support backing vmalloc space with real shadow memory
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC

 Documentation/dev-tools/kasan.rst | 60 +++++++++++++++++++++++++++
 arch/Kconfig                      |  9 +++--
 arch/x86/Kconfig                  |  1 +
 arch/x86/mm/kasan_init_64.c       | 61 ++++++++++++++++++++++++++++
 include/linux/kasan.h             | 24 +++++++++++
 include/linux/moduleloader.h      |  2 +-
 include/linux/vmalloc.h           | 12 ++++++
 kernel/fork.c                     |  4 ++
 lib/Kconfig.kasan                 | 16 ++++++++
 lib/test_kasan.c                  | 26 ++++++++++++
 mm/kasan/common.c                 | 67 +++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |  3 ++
 mm/kasan/kasan.h                  |  1 +
 mm/vmalloc.c                      | 28 ++++++++++++-
 14 files changed, 308 insertions(+), 6 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190815001636.12235-1-dja%40axtens.net.
