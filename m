Return-Path: <kasan-dev+bncBDQ27FVWWUFRBREI4XUQKGQEKXL53BA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F3017469C
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Jul 2019 07:55:17 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id s9sf43639331qtn.14
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Jul 2019 22:55:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564034116; cv=pass;
        d=google.com; s=arc-20160816;
        b=eT4I4Z56/+uMQOc/YzPUUwZ47qbTtoJHep4fbKtjKboTk8Dmmqbt6w+6zRXgnDvxUF
         4kpWhgYrrluh8z+teKSInVX2vPVwLFUtvi+4HdDcFp1ZaD9h8fVYq2Lf+Cm/LWlRYC/z
         9wJSXNrqibDdxM61wlCRInOCpDSrvjdVkeyLaCwcd1rTkH0v85IK/DCepXUue++XIZD8
         uJBQ2CSFtkCYge6HmPEE708xoiNqlQntiskjEoIgl5KtMYqGaW2SyLMYZaZBazWfnvf+
         IVEPsAIFV4buGQIp/wriasMIC7cci8+8IdxBDnE0moUjQlAIxgkFGm2E4203bsUT+2gF
         CYmA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=nnHqIVcxx8bRzU5QLGl3zVhQO83cMUP0OQ+YDJ2mdg4=;
        b=z4LmEzAAUNsvyQ5lj7y2tMg3ZQmZO+i0CDsXOpySFaDj1pU7Y7gd7ioMlXVw7tdb1k
         mEkWy4XZHRJPs3clTD7CZtv1ryvyUjkTpVe8lldV8Wyux0JbqtiMbKFTi7c5f5CFpuY9
         RUHOIjoaHA+RZDTnT2QRrDim9I1WBqbE4p9ow02pYnGtzPP63B527hZBRBI3euaDiTHS
         rYaY9l8L+PeqKkM5F19E+7BffXKOAmKD8s9UonriDsUYvM5TUp+2YcR0MTnbv5P/Tta4
         5lS0/Kg/6UiVUM2ztPi3m4J/qGeM5Y5lbSgEDanp+HJjWy3Owp8ik3pZy2c+CPEk9lz8
         Qpyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=QX20Wp3w;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nnHqIVcxx8bRzU5QLGl3zVhQO83cMUP0OQ+YDJ2mdg4=;
        b=EVDyFpieZcwIZ8kT2nVWG6A+4KnFUY4qaDA8LnJiylMC+ufnJTS+c/Qsqzn0xHwMAe
         iQhxaCSS7uDEppASD2FZ5uKaFg+pJ8tip3IcBBZMLM5nQmYb1CADpHt/TWc1BlDx5ASc
         MumgJXxEOw52uczZqrgiKa+nqyW4AkJM5UoBc8HKHIzZPoloQ/3Up4gRyFEfF2bEWbK+
         9syQjOCQcE9T/tuuyjHzshl/BbpMP3U8pBD+AWSAfJ2UV+2WLC50PzPrVXT6V52uJO8z
         9aSYppynEr8Yu2wetCMRyIRlvbfWbHF4z2aSSxJfyaqP8kYcsuhK25yMCREY2VtcO4LF
         9CSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nnHqIVcxx8bRzU5QLGl3zVhQO83cMUP0OQ+YDJ2mdg4=;
        b=tRBiIMr+AGZlWa3K4xyToUMgRjiPpNHnNnj3AUvviAh4rjyYFfGd6SMRH5krGtjjrK
         8TICXlAtDw7VZ0cOrYRKRvi4OspyxNUP3Q9bsSeCZFSSidvzjRSc/e4eGAjOFMNUReca
         /gjqcB3BvP2rPIsnSrJVR3ZRdZZpmIV8yThkHECsjLcDaaswV4DDHksJxeOsMwCEf1YN
         Tz4dpjrVPGAKtXLpTEV9/9g3sq2ZQkdoW6qhPoKjT8Msi9L1V7Jf+zLvrQyUJPcvjE86
         v+ArkJdPQl8stob4ef4dRi/9iWzScc8f1NUkpOgDmhVnIA5HHYc1RrE21gBLjOXt739a
         nyjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVzAwEHbHIythTTdDGO3LpY7qmi4Q5z8PCd0EqC2KS/zDMB8KAW
	/8IsqAF/8QvG3rE6wdRXmSc=
X-Google-Smtp-Source: APXvYqwIefbdOhHtyKggvpaFhtysMd+WVK5/p6Cp4PpeZ2oQE5n553sXpNFGglWaT2o6fKqHrd3KcA==
X-Received: by 2002:aed:2241:: with SMTP id o1mr61128532qtc.233.1564034116585;
        Wed, 24 Jul 2019 22:55:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:9d4f:: with SMTP id g76ls5711qke.0.gmail; Wed, 24 Jul
 2019 22:55:16 -0700 (PDT)
X-Received: by 2002:a37:a388:: with SMTP id m130mr59656106qke.250.1564034116334;
        Wed, 24 Jul 2019 22:55:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564034116; cv=none;
        d=google.com; s=arc-20160816;
        b=Eg+1or0s2JjMDFZUoGImll5Lrev8oDdpyZnxTWl7Oy7QzbVa1BSNzUnK8OqrZGTiKx
         CAb8libxroNtZH2Ndx0FGG0UdkIcL+/fmuEsNuxvS+hWIaq88GFYiBT4VG2vX1FHF07i
         xNQajsFRKvjOWqnILvE8rXiH133ya5nC3ZCnkoFsXkAOBjHhy8vwG0A/70se2xLhxQty
         p0TM9FKWsqgU5p+bRNQb2yvSoxFsmAwUgfq0B+e2KOPJ5a29MSCwXfvQT/0299x8Gr/1
         T6keOLz85UbU8w/l2pVQ66fKFuln24PmnQSw2dKGkYht0xKI2QKGRwBHwHfU7EOg8WcV
         eiNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=e1xfsz0ZoNGxWjOEVlpLO8+aT1x4jFathNoxDpZIVqk=;
        b=ltd4CLBECr7YUGYCmi+jM4/LlFF1OBcEaW2s/NUgnCXVBWoIokSFK6zRaeGRHjw+Ih
         KnE81yu9i3E5AIeJ2jyW6VaZPjDpQBzHrLoNh+Klp2nGtxGQI2RfzNqQZ7rB1xz0qNjX
         w0UTH7dbpru0LprNMS/Xfuew6qfTH0AeZGRWsv9AT3vzJqgtn9tT5qndK4ZWOjmxerhm
         hykiZdRlqb9Okzn9bhzFoK2PSQLs+HUVRkaWvAnEpKE924siHUPlRoQ2CNbxNW9foSuw
         mPJdDrVhP7E2C06dY7tvsPb8EdKO9vp9tOgVtUzk2aMR4reV5rZl+/I5iYl3lNNaGECj
         zj9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=QX20Wp3w;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id c79si2194663qke.4.2019.07.24.22.55.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Jul 2019 22:55:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id s1so16124432pgr.2
        for <kasan-dev@googlegroups.com>; Wed, 24 Jul 2019 22:55:16 -0700 (PDT)
X-Received: by 2002:a63:c008:: with SMTP id h8mr82471776pgg.427.1564034114982;
        Wed, 24 Jul 2019 22:55:14 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id a3sm51027777pfi.63.2019.07.24.22.55.13
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Wed, 24 Jul 2019 22:55:14 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	x86@kernel.org,
	aryabinin@virtuozzo.com,
	glider@google.com,
	luto@kernel.org,
	dvyukov@google.com
Cc: Daniel Axtens <dja@axtens.net>
Subject: [PATCH 0/3] kasan: support backing vmalloc space with real shadow memory
Date: Thu, 25 Jul 2019 15:55:00 +1000
Message-Id: <20190725055503.19507-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=QX20Wp3w;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
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

Daniel Axtens (3):
  kasan: support backing vmalloc space with real shadow memory
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC

 Documentation/dev-tools/kasan.rst | 60 +++++++++++++++++++++++++++++++
 arch/Kconfig                      |  9 ++---
 arch/x86/Kconfig                  |  1 +
 arch/x86/mm/fault.c               | 13 +++++++
 arch/x86/mm/kasan_init_64.c       | 10 ++++++
 include/linux/kasan.h             | 16 +++++++++
 kernel/fork.c                     |  4 +++
 lib/Kconfig.kasan                 | 16 +++++++++
 lib/test_kasan.c                  | 26 ++++++++++++++
 mm/kasan/common.c                 | 51 ++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |  3 ++
 mm/kasan/kasan.h                  |  1 +
 mm/vmalloc.c                      | 15 +++++++-
 13 files changed, 220 insertions(+), 5 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190725055503.19507-1-dja%40axtens.net.
