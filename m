Return-Path: <kasan-dev+bncBAABBAUB36GQMGQEKP2XA3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0097B4736BF
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:52:03 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id y9-20020aa7c249000000b003e7bf7a1579sf15134501edo.5
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:52:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432322; cv=pass;
        d=google.com; s=arc-20160816;
        b=JLu+VCbWd5hA4SxGJBtXoYQFBRp4CHutL6D4laTcmodmHf7Euh57cROOshSGcY8sR1
         Zy0MrN2u9/DX+fQtj5tA4IzrykpzB3yQjgrAhml8khMGC8m9Lg2zogJomB1pxATUUHpe
         f0CnU87hmFZjDozmLswluwYmRbtkFBAQ7zH8m68lB4VpYXRgpL7vgf43fnMJ8tfuHXL1
         KK8OKU5QqHIRGnbvrKAGXE4lA4ihs3YrdrJd7CyWpcC7/sVkwrKG6DvTeOdSgkgwIy3B
         0b/qVfWCDknBMPCuw7hLJiP6WUaj5QhFeMAYihfkKMaN3iYiQ/E8Qyy1D86jHgCxxtET
         IojQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=m82WXS+TsLFYBO7Ixxc7lYHpwSkR5Aq23sbOCtnZURE=;
        b=ugR7LqT7tNFwq4j7hi6prgqJUb2g/j03MThdY6lfoS7iL6S7lEWXwC0th1jEJtCpCj
         iahHCB9C3PkEDAWpctO0nGRXHO2mEc1lcNGea4mLsdDVTW2uXn6P0GHYeNaEZT6V1MN6
         dsirVYhneogEWc2CjACKJ/LtzgcosIXlSBGZo+6qUn9yHR62wtvp3DuOLkFad6MaNUb2
         a14glaB7RpQD1dfo3UnTLo279gvn/ByoMVBAfRrASdlsBwCsVsI5B0SWGi3bgjeLIj7b
         gZfuuBtZoEjutc/0gth74MwGlTJS0wuamWboCkcz5XZg6ZpKVJha4OIuZxriTXKtMXf0
         GMfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lbgVieQN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=m82WXS+TsLFYBO7Ixxc7lYHpwSkR5Aq23sbOCtnZURE=;
        b=VBdl426Pzr+Dfb7cfqwGyW8uvP3yAb8XjiCVr4LvqiMAO9tkdQmJYQfMsM1nxLtrM0
         ogPTjGeaM1P9sw8XztPl7lJd2Q4/xvqnN6u+XYg7vc88HpJaFAdmL3kEcu4IDs+FUHue
         tXxvBGrgg6gtXnYMTA/FVWgB2+c7QvvtO9npoEpn7Do9XjeQ+W42q1zn5TDO8x0Ne33B
         sICAPG8BLbhijbOnk7Bj1AWkSOD3V8HATbVkJuGmMZzW7400JjteYED0CGBr94B62/4J
         0tWa7SyZ+H5pOyuOBKpypMocHEmaj+BzXbbvbjZxcfJ6eR6R82eFlPTLxIdcwcVXB617
         wY2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=m82WXS+TsLFYBO7Ixxc7lYHpwSkR5Aq23sbOCtnZURE=;
        b=G2XN4JHk+TnH3VihNj37HszsBkNhyh9JPiHekh7NGD8tF9zQPFKSRoVkB8bbfc4sEY
         Z1dzlIHP3PeNKnSJW1MOhUUrzzxjhM3FumiwFlJfbu/oTuepf2BFtYEvWKnTdHrBXReu
         Sdqjm2wH0hxoM2Twok/lXEg50cYCj7JlbvzF8K2l4etVn41oAhMaJnvEDJHqpWU+rIdM
         Ry76hfRu3n0Mshpm7mVLRoTHMD+D9gSxKW8WfrK3gtY4C80qtSsG2T7HegvR9UbGD0ti
         W8hKqsQYntesfQu5LIYl+QZXmJwe8uM71Ibb45L0xkroWoFoa0DSDQ5hwEPlLpHJYlz6
         E/Ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533cuVx2z5nIzYGtgD1MC4WqZCCC9NutLYFYF9jV1sx8UdSrI/Ed
	uYsIPxLSxmRrwHfzNALyGAQ=
X-Google-Smtp-Source: ABdhPJyuAozc6UVddfDy++1BZlzP3GlUhIptWBDgdNLU2sGG6hwGpT/m/sJ7i9iT3g6Pv9WhPzHZPw==
X-Received: by 2002:a17:906:9144:: with SMTP id y4mr1178327ejw.98.1639432322630;
        Mon, 13 Dec 2021 13:52:02 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c013:: with SMTP id e19ls5942977ejz.3.gmail; Mon, 13
 Dec 2021 13:52:01 -0800 (PST)
X-Received: by 2002:a17:907:72d0:: with SMTP id du16mr1095684ejc.599.1639432321873;
        Mon, 13 Dec 2021 13:52:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432321; cv=none;
        d=google.com; s=arc-20160816;
        b=HAbfFoxW3kbKmW+sQJyzjP2CsV4oruBHlqp5GcEbysc6B0LsRhSTGBeVURH/Q7TcKI
         B1X+EL7J9hr8Yt0ckXJxo+NvZxRuPiu/HOpu/kpwRW7m20KbIz+LXVL6ASScn3ZV3+YI
         6EUmMewritHfAKkFocj9gULpKp73iS0pcvWlEQwI9jRsANXB88TBt5mfj7lr941a5tao
         WwGAE109+HSXKpbw5DKvWut7cH39scvAWFItgdKEB4MPJQvgi+bnqCsWAzJfkHsY4mtY
         nSQOW4QqXMRvLgv9dvr8lXdEO6gORz47j7WxCkdsAYVDFdzw8NycYfjX9z6F7WR9Br8H
         gL7A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=RFB0qTMdGtbT7R5B69C0dmQ2ImMSks0KRl4KeR6DWno=;
        b=ZZrTwO139oLcsxZbsUn1PQgPEvfzTTfFndEY+34qasCtr7uJ3CtueqmcvWXNguQqHe
         Ar/PEKzXs03WuVJNrjG0diUIEZpeMa6fIibZ/mv03qIz0GLuyBmSe/6V/zqeF2Zgd2qK
         +j7Kt4KGpnrKz63M8i5IxazN1AVr2i9rQG1KD1GalRLDc+Wb9XcNvkNPOaCbPybYK9oP
         f122UB1bEujMaArTZZTCR1Xj3wTd/6+khq54hfMg7kdBftJtR+pgRet17fTQB/IUP9vD
         wbbhazPHVGsfE+kTMX7gXibKVihnqEn2f2ZtywhjftmgYrpAmobkNyGbb5VkjnQDPwE9
         A2JQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=lbgVieQN;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id i23si744241edr.1.2021.12.13.13.52.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:52:01 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 00/38] kasan, vmalloc, arm64: add vmalloc tagging support for SW/HW_TAGS
Date: Mon, 13 Dec 2021 22:51:19 +0100
Message-Id: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=lbgVieQN;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Hi,

This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
KASAN modes.

The tree with patches is available here:

https://github.com/xairy/linux/tree/up-kasan-vmalloc-tags-v3-akpm

About half of patches are cleanups I went for along the way. None of
them seem to be important enough to go through stable, so I decided
not to split them out into separate patches/series.

The patchset is partially based on an early version of the HW_TAGS
patchset by Vincenzo that had vmalloc support. Thus, I added a
Co-developed-by tag into a few patches.

SW_TAGS vmalloc tagging support is straightforward. It reuses all of
the generic KASAN machinery, but uses shadow memory to store tags
instead of magic values. Naturally, vmalloc tagging requires adding
a few kasan_reset_tag() annotations to the vmalloc code.

HW_TAGS vmalloc tagging support stands out. HW_TAGS KASAN is based on
Arm MTE, which can only assigns tags to physical memory. As a result,
HW_TAGS KASAN only tags vmalloc() allocations, which are backed by
page_alloc memory. It ignores vmap() and others.

Changes in v2->v3:
- Rebase onto mm.
- New patch: "kasan, arm64: reset pointer tags of vmapped stacks".
- New patch: "kasan, vmalloc: don't tag executable vmalloc allocations".
- New patch: "kasan, arm64: don't tag executable vmalloc allocations".
- Allowing enabling KASAN_VMALLOC with SW/HW_TAGS is moved to
  "kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS", as this can only
  be done once executable allocations are no longer tagged.
- Minor fixes, see patches for lists of changes.

Changes in v1->v2:
- Move memory init for vmalloc() into vmalloc code for HW_TAGS KASAN.
- Minor fixes and code reshuffling, see patches for lists of changes.

Thanks!

Andrey Konovalov (38):
  kasan, page_alloc: deduplicate should_skip_kasan_poison
  kasan, page_alloc: move tag_clear_highpage out of
    kernel_init_free_pages
  kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
  kasan, page_alloc: simplify kasan_poison_pages call site
  kasan, page_alloc: init memory of skipped pages on free
  kasan: drop skip_kasan_poison variable in free_pages_prepare
  mm: clarify __GFP_ZEROTAGS comment
  kasan: only apply __GFP_ZEROTAGS when memory is zeroed
  kasan, page_alloc: refactor init checks in post_alloc_hook
  kasan, page_alloc: merge kasan_alloc_pages into post_alloc_hook
  kasan, page_alloc: combine tag_clear_highpage calls in post_alloc_hook
  kasan, page_alloc: move SetPageSkipKASanPoison in post_alloc_hook
  kasan, page_alloc: move kernel_init_free_pages in post_alloc_hook
  kasan, page_alloc: simplify kasan_unpoison_pages call site
  kasan: clean up metadata byte definitions
  kasan: define KASAN_VMALLOC_INVALID for SW_TAGS
  kasan, x86, arm64, s390: rename functions for modules shadow
  kasan, vmalloc: drop outdated VM_KASAN comment
  kasan: reorder vmalloc hooks
  kasan: add wrappers for vmalloc hooks
  kasan, vmalloc: reset tags in vmalloc functions
  kasan, fork: reset pointer tags of vmapped stacks
  kasan, arm64: reset pointer tags of vmapped stacks
  kasan, vmalloc: add vmalloc tagging for SW_TAGS
  kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
  kasan, vmalloc: don't unpoison VM_ALLOC pages before mapping
  kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
  kasan, page_alloc: allow skipping memory init for HW_TAGS
  kasan, vmalloc: add vmalloc tagging for HW_TAGS
  kasan, vmalloc: don't tag executable vmalloc allocations
  kasan, arm64: don't tag executable vmalloc allocations
  kasan: mark kasan_arg_stacktrace as __initdata
  kasan: simplify kasan_init_hw_tags
  kasan: add kasan.vmalloc command line flag
  kasan: allow enabling KASAN_VMALLOC and SW/HW_TAGS
  arm64: select KASAN_VMALLOC for SW/HW_TAGS modes
  kasan: documentation updates
  kasan: improve vmalloc tests

 Documentation/dev-tools/kasan.rst   |  17 ++-
 arch/arm64/Kconfig                  |   2 +-
 arch/arm64/include/asm/vmalloc.h    |  10 ++
 arch/arm64/include/asm/vmap_stack.h |   5 +-
 arch/arm64/kernel/module.c          |   5 +-
 arch/arm64/net/bpf_jit_comp.c       |   3 +-
 arch/s390/kernel/module.c           |   2 +-
 arch/x86/kernel/module.c            |   2 +-
 include/linux/gfp.h                 |  28 +++--
 include/linux/kasan.h               |  97 +++++++++------
 include/linux/vmalloc.h             |  18 ++-
 kernel/fork.c                       |   1 +
 kernel/scs.c                        |   4 +-
 lib/Kconfig.kasan                   |  20 +--
 lib/test_kasan.c                    | 181 +++++++++++++++++++++++++++-
 mm/kasan/common.c                   |   4 +-
 mm/kasan/hw_tags.c                  | 166 ++++++++++++++++++++-----
 mm/kasan/kasan.h                    |  16 ++-
 mm/kasan/shadow.c                   |  63 ++++++----
 mm/page_alloc.c                     | 150 +++++++++++++++--------
 mm/vmalloc.c                        |  78 ++++++++++--
 21 files changed, 668 insertions(+), 204 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1639432170.git.andreyknvl%40google.com.
