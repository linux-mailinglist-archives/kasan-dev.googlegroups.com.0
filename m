Return-Path: <kasan-dev+bncBDQ27FVWWUFRBD7AUHVQKGQEVWN5BKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3d.google.com (mail-yw1-xc3d.google.com [IPv6:2607:f8b0:4864:20::c3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 53A22A2B79
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Aug 2019 02:38:40 +0200 (CEST)
Received: by mail-yw1-xc3d.google.com with SMTP id x20sf3926768ywg.23
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Aug 2019 17:38:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1567125519; cv=pass;
        d=google.com; s=arc-20160816;
        b=NirfNHC6AdcFT+Ea/5kBndypiUIBHoyBwfuv/jV2/adeAB6rCe0s4uE5sl5vSGSOE5
         aCUq3n204pgJTivKZv8IVlNWEjpTVki14JAp5zXU1ivXRcyo+razrT0nRY8l9gX4uN98
         dtglwGr/4oItehN5HBMzO7iRevhsUYMiC0I1W5PWyEbRZ89cWZy8GzBa7JNJQ2sYCtaB
         ni24YtL3Vkpwf5SpEqxizZ2kt1A+aR8uMz2gK1QOosOz5oeE+n241YGn0p+nT/ZpGeTH
         uJzO3hNXfSadcbKPHPyuFZoT0SNjA0htEEOc12apscfwX00uoabwk5pj1aHdjdf+CXwQ
         OjTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=xmcCdManFXEK35bczh8HV4CFw1wCKXdAZSrn+INecH4=;
        b=Qjb2VoeF1WwYp4eR2vZncPvgrK7jkc/KQhyWlktSaldp3Ue4UOKb+e7OQhoPogSM50
         yEdv0N1/W1KSZVdFR2Cw3lpMSODyb/Ji1rRPf5aMgaOcvN5NMTHFJ/NZHrzR+QKm+1pM
         Un3BFLNKJpp6I7bOssfhnR0IypkAVHHris63WNduJlT2PovYjZQxzSRKCjMZiAQNa5L0
         I5tJk4NPVvMRoK/ykXEdtudcyFAOx8qRZOv9jK7O7MT8erIM+e0bAW9fhk6bBYPb9PFA
         ZiI5OlIpFqQyGZ5cWJZ5Fub6tb5IKgvi9SZcZ7CO6yuzA0/aDuRy3SzZ4BvsfCYjxWui
         fwxg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=pu31SPJC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xmcCdManFXEK35bczh8HV4CFw1wCKXdAZSrn+INecH4=;
        b=nklYvubvOVyJkzCLtE6a6y5xhvnZOJBx3HcRfHWSFE11cl7MrotD/ujrv3ps5j9nNe
         RB+l8I3gK0nBe7L5T5Rt76U066JL6cyOuONfrLpxh2xUGYIzKpY6Vn/X5//AQXW/mElL
         C8d98TwOagsiYj7WfJ+fP4qkolBOdSVjlTJGaKXSIk/Vlz2xLkAtSYvz5EFL/WztAwyF
         0S+0w/wj1GRiqvYJBe35ON34ds8uBq7s2FZNDxFMm8cqdFbzys/mHlqzF8p9jn9rYxPf
         vc+lAEwmP+wQqhz0XoU9CXgE8vYOhfH0Ys+mqykfYdmaMQRu6qeSJEf5emBODO4NOQFE
         leLg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=xmcCdManFXEK35bczh8HV4CFw1wCKXdAZSrn+INecH4=;
        b=fjbEGBPPpyM3oPpCyAL512qkQAM9jzjiUqXDStwvYTKJ2BJjn+rp+wT7Jm2DusG5Tk
         /ClFCJMJGQBRMx63wMLQkTJoFZWyPqaK2DnrFeX/vhGZRxTbIIeIk/iFk6HtGsDLxKJV
         +ImODw9Ayubvv7wBvES1debl9dJwzEcCHvEyATX8/4paDmsfhxSSFffx0Sh1tBWL+HZz
         1GB0aQ77TpdUW6fwGKNkqai8kQg+ELY3moh3bTObh8UWYqfR66bEimVhoDjxNSBRJKEx
         cvJAb6ARiFZnQwhU9Yyi/8BNXVnGV+wmOpLUc3ht9ha+Q7O78MYDbbyM0R3Crdu1vj4w
         GdGw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXWs8oUmfxpsm+2SfupHyOdeuax74nhJ7/D+Mph0jm/t4+7YKNJ
	IMtmZskq5SQwVJb1ajEsHxs=
X-Google-Smtp-Source: APXvYqw+5rJAhtVy40IjwJJJWhwVIDJZQsVvIVQCoNkQSiBSSkrs2swD63AR65y9mxYXt16L3iKUFg==
X-Received: by 2002:a81:1cc1:: with SMTP id c184mr9812589ywc.297.1567125519345;
        Thu, 29 Aug 2019 17:38:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:77c5:: with SMTP id s188ls197886ybc.6.gmail; Thu, 29 Aug
 2019 17:38:38 -0700 (PDT)
X-Received: by 2002:a25:6b02:: with SMTP id g2mr9486150ybc.109.1567125518898;
        Thu, 29 Aug 2019 17:38:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1567125518; cv=none;
        d=google.com; s=arc-20160816;
        b=m9fgqoDynpkx4G55b/PrRANK/YErqMpKTOPYHaaD0bREggfeZf/NnQ22fOgKsMmroe
         fBD8qQevCbiT6sHrxkSllnEk3AMkGh1e4er7m+OvwyUKYU45TkAQBLGtR37BXnn7aeOP
         WV4OzPXgi4KEiluRhdx9wSjxI9YEqG2/KlshyJivHWltZEJ6B7SDMlUJuUAkbOfeMuAF
         ACEwJ3vkT07fsgE84aqNckaYKDJoJIdtUBGVF6lx7xjc9Y9oTqU3DgVSZgkzpkiGtS1g
         OrONOgi8dPz82m/oDuNr95EdLDv2xYgxrGxIcYqp3M1TZWv33xcD3jUEvK2Ak8SPMk64
         kKtg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=DSLyHXthXaKXOQZ8SFsqItHK5pHRiDWtPuxcUQu12HE=;
        b=hiyed7lWzrWhKey6q4WJGE8VzzlMOs0Hxy6Z3NpY19HGlDHqc8QA+3tulrgBaitjGd
         7QHfD46A6V+dbdZ+B2w+orvdMIjwo8X/nSLVPb5p+QkPBaUEH5oxjQpufMn85QbbXmE4
         uiyEN9rCg3b1T4eLWJRMVOJfzDef93wvhCTSCLOqjhpWCPH25ccJtJC0+cbX+pwkXXHF
         ZTOZ5QtSQdmL7rxtEUckuNzOU4YA8OneKmUHyaxKd06Rs3IbTp23xp2IzeWOi3d1nNLQ
         xImEIyQs3joD4G1HIVcobrGXu0F0vsb8lQT2He+1J7UIpNq+z6EiB/3a1SjZKjLSVG5T
         ZlgA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=pu31SPJC;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x441.google.com (mail-pf1-x441.google.com. [2607:f8b0:4864:20::441])
        by gmr-mx.google.com with ESMTPS id n40si221204ywh.3.2019.08.29.17.38.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Aug 2019 17:38:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::441 as permitted sender) client-ip=2607:f8b0:4864:20::441;
Received: by mail-pf1-x441.google.com with SMTP id w16so3311090pfn.7
        for <kasan-dev@googlegroups.com>; Thu, 29 Aug 2019 17:38:38 -0700 (PDT)
X-Received: by 2002:a63:9245:: with SMTP id s5mr10952781pgn.123.1567125517640;
        Thu, 29 Aug 2019 17:38:37 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id a16sm4341162pfk.5.2019.08.29.17.38.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 29 Aug 2019 17:38:36 -0700 (PDT)
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
Subject: [PATCH v5 0/5] kasan: support backing vmalloc space with real shadow memory
Date: Fri, 30 Aug 2019 10:38:16 +1000
Message-Id: <20190830003821.10737-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=pu31SPJC;       spf=pass
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
v5: Address comments from Christophe Leroy:
 - Fix some issues with my descriptions in commit messages and docs
 - Dynamically free unused shadow pages by hooking into the vmap book-keeping
 - Split out the test into a separate patch
 - Optional patch to track the number of pages allocated
 - minor checkpatch cleanups

Daniel Axtens (5):
  kasan: support backing vmalloc space with real shadow memory
  kasan: add test for vmalloc
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC
  kasan debug: track pages allocated for vmalloc shadow

 Documentation/dev-tools/kasan.rst |  63 +++++++++++
 arch/Kconfig                      |   9 +-
 arch/x86/Kconfig                  |   1 +
 arch/x86/mm/kasan_init_64.c       |  60 +++++++++++
 include/linux/kasan.h             |  31 ++++++
 include/linux/moduleloader.h      |   2 +-
 include/linux/vmalloc.h           |  12 +++
 kernel/fork.c                     |   4 +
 lib/Kconfig.kasan                 |  16 +++
 lib/test_kasan.c                  |  26 +++++
 mm/kasan/common.c                 | 170 ++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |   3 +
 mm/kasan/kasan.h                  |   1 +
 mm/vmalloc.c                      |  45 +++++++-
 14 files changed, 437 insertions(+), 6 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190830003821.10737-1-dja%40axtens.net.
