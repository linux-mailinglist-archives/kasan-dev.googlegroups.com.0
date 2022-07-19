Return-Path: <kasan-dev+bncBAABB27M26LAMGQENLEDFTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id BBB1E578EBE
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:10:20 +0200 (CEST)
Received: by mail-ed1-x53d.google.com with SMTP id j6-20020a05640211c600b0043a8ea2c138sf8804720edw.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:10:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189420; cv=pass;
        d=google.com; s=arc-20160816;
        b=AJHNEsaGVeFcen+zYmee6Q52Sl6DSKgSTO8RQShpsDko6eoiglIu1Z5URU2Li/p/6J
         /rRbQws4QKO+yewb8h/lWoctlzNIJYisWxrS55SGi2TpsEVpQUVmxniwAbi955S493I9
         grg6wgsLm3W8xsNLqVzODJ/7ycyy2y5LRANskHQbWven/l3NE1c0tIzw4RqYzWqlZGiS
         xVZ69CKz03+7yT9H0G+9Qvk2liEXmFyXQwRQqLFLr97cyBSdNB9qA2dZ/sfp56q1exI0
         N13Q/NoHIETVV7A0qI2++EnlcU1E/Twggqcjs6WyQz742PNufhPNlCRKImElTz0LxP17
         0a+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=vrmndMfKtK5gcMOhA4BeraudMRhwyB08hfD5xvH+OCI=;
        b=zTzNqVHxJdw/3z1bzn+2Yr91uyNu3MrS87Cyz11JPiYPxc61l+9Gz0u6R/0kIzLYyE
         JoIJ9QabKgi+ppKPFVdKlx/4tdgQ59B6RK5xB6kubvajZGlMoZNuqvlcCX3WRZNdkuzx
         cyOCgS9EERFBzWfmOmOmJPI34ZxjuyNVeNALSSVi9e5Pyzod+4P7W/uobdCjlzz/IRsW
         PtopRYpGMhQbgPZxg1eui6bfEZJUWN13Cpxt8ZrXM001ekE5u5arbHzVwWgaznvwob1J
         u9v9OVkKxQh3ZGrLjEhTnmxqnJlw3jGNuh70R0xVjSNMirqRHWeFqEWACYClGf3PmZab
         DX8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AQGV5pN4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vrmndMfKtK5gcMOhA4BeraudMRhwyB08hfD5xvH+OCI=;
        b=YgGA+DJz++8X0QnkHu+G0JBZQiEeLZ3O7ZZcjvIo/578Zz9dvdKjaQ2Mc0j8ayn/Kk
         9LXheKjGnqDb9xBgbUVjrqyRn60cDb+B6uZmF5Wt4gDgOiB0rDS8crC9xfxbAzXazqiZ
         87GmoKHfj4SWyHmU/TuWa5sN+WAWXm9h6SzNJTllPF4I05IBxqZSc+60mq8XhY1DQmrf
         v3gv1AWT5t57PVLbHDU5P/hh7Ae70FdqH712Wpwa3+O2b9gbXPy7aWrdsZwV4wp4C+Kq
         QZQ6kpEQR/OxkhXfIIcXyPkXwiZrJPOVrpu+kbLAQ2azkAnCG+5OM3hHf6IHt2N7TdI8
         FhjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=vrmndMfKtK5gcMOhA4BeraudMRhwyB08hfD5xvH+OCI=;
        b=0X/U290cbtBGaaNSL2feNLn6x4VoqXg/YsDjG+u9yJq16BIO03JneIAFBkuWZ/oaSE
         ef3y/UJRT9/yuoI2jG1uuzBuMApqULvhSQcYUNdM+oo10mI19NT11QWC1VV0cc+NkbJw
         sXAN9dbcMhjqRa8x+KN9MnSgtkZrEGdyYUhtqcH2u0bCFObHKuNf371iGLE/PfwttICI
         3rAGeVxUfyUbNjSiDsOoFgeAywVVQ7y/aPak5MFvR7c4z8oduNLj/rXrFkW9+DXE6d5Q
         Om8dk5VHvYBc3VpJIz1CGF0P/LWZEgfWhJ+zDoSZMZ6PDgOXMYz8PBHMuHaexiS78IER
         gYtA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8YgZ6dOgsC0hwjU9fSnf2OoFIbwUVU5CbkVIu8+pmkfa9wpGoM
	s/dVJJQkTqeqz/6mILfbWqs=
X-Google-Smtp-Source: AGRyM1smkUdUvqFG6+6ezldpDn7IDx0IYPv7Ezk1sCjKYZHRm2yfSEeTXkbEFihgnG4LkDrkpfQjOA==
X-Received: by 2002:a17:907:7f94:b0:72b:47da:4bf3 with SMTP id qk20-20020a1709077f9400b0072b47da4bf3mr28447298ejc.157.1658189420037;
        Mon, 18 Jul 2022 17:10:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:34cc:b0:43a:7c1c:8981 with SMTP id
 w12-20020a05640234cc00b0043a7c1c8981ls73461edc.0.-pod-prod-gmail; Mon, 18 Jul
 2022 17:10:19 -0700 (PDT)
X-Received: by 2002:a05:6402:35d1:b0:43a:cb5b:208b with SMTP id z17-20020a05640235d100b0043acb5b208bmr40053768edc.275.1658189419314;
        Mon, 18 Jul 2022 17:10:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189419; cv=none;
        d=google.com; s=arc-20160816;
        b=wPcmNMDCMr7DgeZtM2CHnK5CH5bihVf4OPTX3sL3YFr+eflh1I6gimjbC2sZMkzGOY
         W8tWCOZ/CHKjJFgpRVya4tDS7l7sE8+IDGkC6TQCwHmWcwxe/cgv3NuWYTss1/8aRty0
         wzD8mPnvH8R4Z7GhHHORNG3E8bcx+Bpp1PfQJ6PoOnud45K8nzrdMWQ14BknnoV81JMj
         /8Q+QTLe1uf0wM7MeUJpI9u1/iKpdgVGuQaFSy8CjfoPZ7/rTYy+KcIOHRmte6MBgwd4
         cdjFeDImV9MRF5/um1HW1yvZuphGEPQXwyIZ+aYhqcMFVYlfALdYqx814p3PvlQi5pqD
         nJOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=W6bMOfDQQrC3t+AXklBVrLreFIQ/eHKpGdhG0Mq/jjQ=;
        b=ImBZc3va8UnzlKcahMXCQN1p8Sw5082c7E2KXODYBa2VvpanYMgwLTCixVs5BS+SQ2
         siN8zfd+phCc9tHDGTL1bxQKdGlXqR+z6cPVfWhOQ/uAB1f/4GlNMLVqkJf9Ela8AuU6
         J/t/TkCCubkhiRLepx8t5FU4ptnBcl+GgHYumG0jIyoQaP9yf5+U3CNVsUM+2ES/DwYj
         FzI2kTGoLPPrl5FCggh4XCo+6GUNWP9JU2iag2rcJPn49l+RtxyiSXC4OGf6JvywN1Sk
         n5uf9Ca7ni5Gi81OFlmlLaMoJSbazm+WC6Bs4L74kezkzoO8Kv/ZXymXFBck6JWxmLXY
         x7AA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=AQGV5pN4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id n26-20020aa7c45a000000b004359bd2b6c9si366411edr.3.2022.07.18.17.10.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:10:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 00/33] kasan: switch tag-based modes to stack ring from per-object metadata
Date: Tue, 19 Jul 2022 02:09:40 +0200
Message-Id: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=AQGV5pN4;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

This series makes the tag-based KASAN modes use a ring buffer for storing
stack depot handles for alloc/free stack traces for slab objects instead
of per-object metadata. This ring buffer is referred to as the stack ring.

On each alloc/free of a slab object, the tagged address of the object and
the current stack trace are recorded in the stack ring.

On each bug report, if the accessed address belongs to a slab object, the
stack ring is scanned for matching entries. The newest entries are used to
print the alloc/free stack traces in the report: one entry for alloc and
one for free.

The advantages of this approach over storing stack trace handles in
per-object metadata with the tag-based KASAN modes:

- Allows to find relevant stack traces for use-after-free bugs without
  using quarantine for freed memory. (Currently, if the object was
  reallocated multiple times, the report contains the latest alloc/free
  stack traces, not necessarily the ones relevant to the buggy allocation.)
- Allows to better identify and mark use-after-free bugs, effectively
  making the CONFIG_KASAN_TAGS_IDENTIFY functionality always-on.
- Has fixed memory overhead.

The disadvantage:

- If the affected object was allocated/freed long before the bug happened
  and the stack trace events were purged from the stack ring, the report
  will have no stack traces.

Discussion
==========

The proposed implementation of the stack ring uses a single ring buffer for
the whole kernel. This might lead to contention due to atomic accesses to
the ring buffer index on multicore systems.

At this point, it is unknown whether the performance impact from this
contention would be significant compared to the slowdown introduced by
collecting stack traces due to the planned changes to the latter part,
see the section below.

For now, the proposed implementation is deemed to be good enough, but this
might need to be revisited once the stack collection becomes faster.

A considered alternative is to keep a separate ring buffer for each CPU
and then iterate over all of them when printing a bug report. This approach
requires somehow figuring out which of the stack rings has the freshest
stack traces for an object if multiple stack rings have them.

Further plans
=============

This series is a part of an effort to make KASAN stack trace collection
suitable for production. This requires stack trace collection to be fast
and memory-bounded.

The planned steps are:

1. Speed up stack trace collection (potentially, by using SCS;
   patches on-hold until steps #2 and #3 are completed).
2. Keep stack trace handles in the stack ring (this series).
3. Add a memory-bounded mode to stack depot or provide an alternative
   memory-bounded stack storage.
4. Potentially, implement stack trace collection sampling to minimize
   the performance impact.

Thanks!

---

Changes v1->v2:
- Rework synchronization in the stack ring implementation.
- Dynamically allocate stack ring based on the kasan.stack_ring_size
  command-line parameter.
- Multiple less significant changes, see the notes in patches for details.

Andrey Konovalov (33):
  kasan: check KASAN_NO_FREE_META in __kasan_metadata_size
  kasan: rename kasan_set_*_info to kasan_save_*_info
  kasan: move is_kmalloc check out of save_alloc_info
  kasan: split save_alloc_info implementations
  kasan: drop CONFIG_KASAN_TAGS_IDENTIFY
  kasan: introduce kasan_print_aux_stacks
  kasan: introduce kasan_get_alloc_track
  kasan: introduce kasan_init_object_meta
  kasan: clear metadata functions for tag-based modes
  kasan: move kasan_get_*_meta to generic.c
  kasan: introduce kasan_requires_meta
  kasan: introduce kasan_init_cache_meta
  kasan: drop CONFIG_KASAN_GENERIC check from kasan_init_cache_meta
  kasan: only define kasan_metadata_size for Generic mode
  kasan: only define kasan_never_merge for Generic mode
  kasan: only define metadata offsets for Generic mode
  kasan: only define metadata structs for Generic mode
  kasan: only define kasan_cache_create for Generic mode
  kasan: pass tagged pointers to kasan_save_alloc/free_info
  kasan: move kasan_get_alloc/free_track definitions
  kasan: cosmetic changes in report.c
  kasan: use virt_addr_valid in kasan_addr_to_page/slab
  kasan: use kasan_addr_to_slab in print_address_description
  kasan: make kasan_addr_to_page static
  kasan: simplify print_report
  kasan: introduce complete_report_info
  kasan: fill in cache and object in complete_report_info
  kasan: rework function arguments in report.c
  kasan: introduce kasan_complete_mode_report_info
  kasan: implement stack ring for tag-based modes
  kasan: support kasan.stacktrace for SW_TAGS
  kasan: dynamically allocate stack ring entries
  kasan: better identify bug types for tag-based modes

 Documentation/dev-tools/kasan.rst |  15 ++-
 include/linux/kasan.h             |  55 ++++------
 include/linux/slab.h              |   2 +-
 lib/Kconfig.kasan                 |   8 --
 mm/kasan/common.c                 | 175 +++---------------------------
 mm/kasan/generic.c                | 154 ++++++++++++++++++++++++--
 mm/kasan/hw_tags.c                |  39 +------
 mm/kasan/kasan.h                  | 173 ++++++++++++++++++++---------
 mm/kasan/report.c                 | 117 +++++++++-----------
 mm/kasan/report_generic.c         |  45 +++++++-
 mm/kasan/report_tags.c            | 128 +++++++++++++++++-----
 mm/kasan/sw_tags.c                |   5 +-
 mm/kasan/tags.c                   | 138 ++++++++++++++++++-----
 13 files changed, 620 insertions(+), 434 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1658189199.git.andreyknvl%40google.com.
