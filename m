Return-Path: <kasan-dev+bncBDQ27FVWWUFRBROX5LWQKGQE2ABNPBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 10922EACA0
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 10:39:19 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id g135sf4046872ybf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Oct 2019 02:39:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1572514757; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hd0h/mZy8+6dlQSio/pEtLQ1JWFPYA1DKmkpR+yk55P3j/skvRyNhknlKLfSVrcD29
         qeINEu7tRnEYHSGVlfC4mM6i8sCp3wwsPRZwQmR6UcpPuaIYJauz7aqsFuSUONo+L4vC
         I3cfJPbwKJLewl+kcZB+nSb+TWt2FM2DGsO++N7FD/wr4TKV386xqmikMT8LtiBgzXUp
         jLyncYRdUs9gTTdXOm/tAKIbwDfqcV2KHlQsAm68N5aQpVz2ttno7X2s443DJz5NISOm
         FPAiWaGU2k0GJzahFsjxo8qdQrp/XaTieFcRqBZXCKAC51c4ToNB3b2kMjNvVlw+ZlLE
         fEOg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=YqGj1+K98p90Yy9IoMSc+wgt3eMOWyDl+657tuEWWdM=;
        b=YvE084qy+hqU53Lv0Y9fcLQ5kgb3yKOf2ivNf9I3dxrHbuaLF7tFIdAWQBF/SYoSXT
         0SsuvfkVmyV72X7gW3WMEO4x/J/rJC/ep5z7lMEt5ooWsJNdK258BdCyAQlPjQpz1Rln
         GHdFpzDYEP6wUdqZLmJEAFDFlGIbT+dkpcOdqdM5+2+t3EyqS8OsIpWLPAHv7MDuSHDc
         pFBVFm4pwyZ+MmFOJn5mLtx4crhSEHqfiyMf5jvJmlIidaM5LSFaf/pd6hqvRYT/v/L4
         3Rdt4SxHv2kjUr9TzONJvFRrE4Es/8RqOJTt0k8yQVZPcHiiABf4cEqZBNiOQfY79MnY
         riXg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Z8ihK2yz;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YqGj1+K98p90Yy9IoMSc+wgt3eMOWyDl+657tuEWWdM=;
        b=TobXnier+Egonlb0g4O0uAaEUjcpmPQy5eWVGVqX2FHlAEXImsGmlfWamapU84VJLO
         XLOokDQvnHC2xZs+C5qOTWrwtZDkOMt/0Z6ZtXYOU5s7T1cEFYotCHgIoEwQh28YXgkx
         I33ZXvDeJt1PZXFQXIb8m8X/es+AdHO75HyeIr3TC44xFEHcLXpULxQXsrUmNc2o3/xe
         LL192636V5jaOfucr05iyxw8Gf921V0FThUHVLvrM5CnHGpKzhBaMmB3161hpUZekEOU
         moLo1+w66pFaJ0HOa6HEs4XwAPRGQj34WJ0JeoDel9pWK9bHsZvcrlt+3Smu/9Jvmb9O
         8wSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YqGj1+K98p90Yy9IoMSc+wgt3eMOWyDl+657tuEWWdM=;
        b=dyF58SfJYffmFtg/KkZp95r8euIrlXhkGA0x6/mOQGq0wEQr3LifSIPadKhJlwLNpL
         iqCxE0WGGVI/c27GPeIqqzOHFEwi4kEoDyEIDr/8B5hhsihs+yWZKSip7tuYCJEAC+HO
         ea2R4SeT1XFceHp00CX9U0WXKZ7FM7jBflYnBmw5tCqjsFA3oCvamLq4cDCFMCwcnS+/
         i4F+K02L7/U8z+yWCF2nci2QB0Ev8UI2c/er5tBxPQUHiaSb2X/aU2kq/3ForgkQLK+S
         r2h23no/w4hciqpSk70kjqkk7xv+HCPcqoilPn2ZbS6mSFeeYUJCLPt+SJAL4FUOWrgQ
         s2eQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUSWnldTsHSykipeb0qz6myYFe1uRLlkajIj1Om0mtf1FQfdEik
	dgzfgkljlwc4qpvZjFuZvTg=
X-Google-Smtp-Source: APXvYqx/+Bn4uCb1HXGr+1b8RRE810begZ9VdP+luBNBaY8H6Z4JPCMYsMl8aD30sKLEvOCoCha3bQ==
X-Received: by 2002:a81:61c3:: with SMTP id v186mr3392314ywb.151.1572514757732;
        Thu, 31 Oct 2019 02:39:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:9209:: with SMTP id b9ls355944ybo.3.gmail; Thu, 31 Oct
 2019 02:39:17 -0700 (PDT)
X-Received: by 2002:a25:5f4f:: with SMTP id h15mr3530427ybm.0.1572514757292;
        Thu, 31 Oct 2019 02:39:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1572514757; cv=none;
        d=google.com; s=arc-20160816;
        b=MsCjzBAsn7cpdl+dh/+ruxIQq40aOjmj8HKQCR11zeriSwhruJjs2hHQ880VITJHeE
         Ihgb/mDdQtPhjzLlpD/vZek0Du9Sm5GNATExch3t2Gfi0LttcOxF11L0UeRhMmJirPvQ
         9bAgWWeDowqf88aOk9uehu9uSnfOJC2WubsRJh2cl0K4AgIX5muJ30vsQ1h2LzwlgeL/
         X3RdXvMgmbfUHX4cquGDu4AbamiwKy62+8RLNy3mAyo21lR/CYLwFyGGFIO/diY0H3un
         DzbZZWc+HRAQAbqU+oDXilThlI2vm1v6YAa/xnXLbTIWY/+bQIUNaI727u/C3iQcpBes
         07Ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=tw/W6NbXnb4qm98VeXSbJQHRtU1hT68y9JEMgvYPvkw=;
        b=MPMqVUYjDfl/X5dPzM2uz3FgealhjiBxsdLDmcROqe+RWy3P+eTI1YhmNInw/GXt0C
         pJa9EcO60tYpsbJ1sO6H3875Pz9f11a3MEfqh4cp9o26Vw4bYU953DVRJyk/x2la1vKk
         rx1GPOIt87xwVblwNAidFe86OXyLIm/a5+KSSlHX5WUTW7agwvWNdF9MB2lkTF2fxT24
         WRfZ/UU9AZuAeQ3cDC4iyhX3cVLBHvdOSsLnuPKv40iAHRC+Z18bViFnduPK2ziQLK5I
         NFgO5cXZEwHgD+HxdDstW7U+kRdhMe+owaovov0Mr/1WO46NE4QMCfe7O7HlHpd5oc/K
         rT5Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=Z8ihK2yz;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id r9si209398ybc.0.2019.10.31.02.39.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 31 Oct 2019 02:39:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id d13so3998517pfq.2
        for <kasan-dev@googlegroups.com>; Thu, 31 Oct 2019 02:39:17 -0700 (PDT)
X-Received: by 2002:a63:4b06:: with SMTP id y6mr5232911pga.409.1572514756048;
        Thu, 31 Oct 2019 02:39:16 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-783a-2bb9-f7cb-7c3c.static.ipv6.internode.on.net. [2001:44b8:1113:6700:783a:2bb9:f7cb:7c3c])
        by smtp.gmail.com with ESMTPSA id a18sm742715pff.95.2019.10.31.02.39.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Oct 2019 02:39:15 -0700 (PDT)
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
Subject: [PATCH v11 0/4] kasan: support backing vmalloc space with real shadow memory
Date: Thu, 31 Oct 2019 20:39:05 +1100
Message-Id: <20191031093909.9228-1-dja@axtens.net>
X-Mailer: git-send-email 2.20.1
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=Z8ihK2yz;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
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

Testing with test_vmalloc.sh on an x86 VM with 2 vCPUs shows that:

 - Turning on KASAN, inline instrumentation, without vmalloc, introuduces
   a 4.1x-4.2x slowdown in vmalloc operations.

 - Turning this on introduces the following slowdowns over KASAN:
     * ~1.76x slower single-threaded (test_vmalloc.sh performance)
     * ~2.18x slower when both cpus are performing operations
       simultaneously (test_vmalloc.sh sequential_test_order=1)

This is unfortunate but given that this is a debug feature only, not
the end of the world. The benchmarks are also a stress-test for the
vmalloc subsystem: they're not indicative of an overall 2x slowdown!


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
v9: https://lore.kernel.org/linux-mm/20191017012506.28503-1-dja@axtens.net/
    (attempt to) address a number of review comments for patch 1.
v10: https://lore.kernel.org/linux-mm/20191029042059.28541-1-dja@axtens.net/
     - rebase on linux-next, pulling in Vlad's new work on splitting the
       vmalloc locks.
     - after much discussion of barriers, document where I think they
       are needed and why. Thanks Mark and Andrey.
     - clean up some TLB flushing and checkpatch bits
v11: Address review comments from Andrey and Vlad, drop patch 5, add benchmarking
     results.

Daniel Axtens (4):
  kasan: support backing vmalloc space with real shadow memory
  kasan: add test for vmalloc
  fork: support VMAP_STACK with KASAN_VMALLOC
  x86/kasan: support KASAN_VMALLOC

 Documentation/dev-tools/kasan.rst |  63 ++++++++
 arch/Kconfig                      |   9 +-
 arch/x86/Kconfig                  |   1 +
 arch/x86/mm/kasan_init_64.c       |  61 ++++++++
 include/linux/kasan.h             |  31 ++++
 include/linux/moduleloader.h      |   2 +-
 include/linux/vmalloc.h           |  12 ++
 kernel/fork.c                     |   4 +
 lib/Kconfig.kasan                 |  16 +++
 lib/test_kasan.c                  |  26 ++++
 mm/kasan/common.c                 | 231 ++++++++++++++++++++++++++++++
 mm/kasan/generic_report.c         |   3 +
 mm/kasan/kasan.h                  |   1 +
 mm/vmalloc.c                      |  53 +++++--
 14 files changed, 500 insertions(+), 13 deletions(-)

-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20191031093909.9228-1-dja%40axtens.net.
