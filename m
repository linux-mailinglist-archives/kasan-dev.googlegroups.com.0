Return-Path: <kasan-dev+bncBAABBMFX52VAMGQEROKMJKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x540.google.com (mail-ed1-x540.google.com [IPv6:2a00:1450:4864:20::540])
	by mail.lfdr.de (Postfix) with ESMTPS id C56147F1B54
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 18:47:29 +0100 (CET)
Received: by mail-ed1-x540.google.com with SMTP id 4fb4d7f45d1cf-548eadba14dsf245199a12.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 09:47:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700502449; cv=pass;
        d=google.com; s=arc-20160816;
        b=0+a7uu6f4yFEO4nHpG+6vH4+cAlJiA2gf2E59J0NbcoGZPUtsCc6jYUbm91oUWo8bh
         T8SYX7f0MmxF3LeOeWmJmt+zFOECvzhvPBfohp3E+xUd7zucVWFVM/9jUrvCOtRI1KKq
         fjuySgIicwOglUoLrYWZ3lXV7tShz+xNRzT5kkr5kPICui0jE5pW7bfFn/PbZipRpkXb
         aGhA7He+XXaFymXzw5mnyJX2cKImwYJNlgLj7ECe+QCewqiZTl8RMUsoDcWbrFLdS+SD
         vjhutRnqSjBAZ2dA44AwDOwy+5sJ7VSV3MXxptk0IkQje94y1Cvf0hCjs5wjqVgzsdsF
         WQhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=OO0YhRZUYteknPDjSc91WsHdWgmL4ArzEnXJRd2EOSw=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=d9awVQ8j4pomIqFV0QamNNOjB9J7t/zrAEhnOJQ739dpBLdGBC6xf/ZlZ4B1G0FAgJ
         W/M4IH3dbuJqUBCTqHHFZITkVV8A+ywwG2yhn5GKj/L6eZHkMSakr9VE/mpizwM4P7rE
         sCNG+pRR+2hxw79WXGjxz6hRkyTKuENDsfSACEj9RULEtWqPdTR9plmGCz3aAC6VcDRz
         4IlofXuxImrX9KPTYRGn4gHD76y03wyCi4h9niAh493J3BW/3lNATMu1kSntoRXXsvGj
         P1efuqPaWo0JqM224sI94v6ODcJWtnhmyIZQkn3/we88rArfnIgCAhi1uYQkNLAhPFNc
         IXIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LrmT6z7B;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.172 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700502449; x=1701107249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OO0YhRZUYteknPDjSc91WsHdWgmL4ArzEnXJRd2EOSw=;
        b=uenvLXhIQgupybKOWNDyUDiUIHvTS87rT1kXV1wgddlGdWyBrPn+OMnRRl2DdxHYH0
         RRgyRWL7wqzJ7voKju0X09Ao0fAW70JRc1f2CVmPMhKrY3KnyUGvAoGpuqRcZSFyDeay
         sWnM7NBnBMl03hOrLJ3XW43xaJgUaR1rUchGtUzdewGz4GERJb8Yn/oYj3PQtjEnh1yp
         aPor043viDYF1Wj+7ALjVVgpNIY5lP984+aQ2fpy3gjeuWgHDw98Ud+h3OHsqYZhNRem
         N2i5EP5Y2bCjDJNyf2fXiKqWLOvkkayshrYPveO/xJCmr8KSeKHX48vkMOKI3GfnyyDC
         n3lA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700502449; x=1701107249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=OO0YhRZUYteknPDjSc91WsHdWgmL4ArzEnXJRd2EOSw=;
        b=SjZwzN8HmGRKvXffWMXzbC6YdVRJtyVa5MwOX2A7FJl/oB9+S93e2HvWomPW6rQhfI
         8V21SwxJEl1Jaz9l4bxdhENBS+EGIDDAKB+0p3a3vbb8Vc9wxVIdJ9FnF8XG1ZhW5EHe
         Agwd29jNlbD8JgdjPm+wHoECxXcSAC9gdbFmOEcyGxdFoUDixZGdDyLGuu9jdWrLC2C/
         8p+w+fcSEuES1/9L910EXNqLRiZmDq5pEoc+1y1He0CF6VUwiZgztvOk+eggdkPC1sWN
         vHHbvCxMiz49Q/d10D06Q8jIuY+JroBz11tef9CtNWfbgeyaL4AKYDMdTCcELo8rC3aT
         fnIA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwmG8Im8rdLpR2w2lfq02o2JrKR6blGaZmJOaw6HDFUw90GAIOr
	fqd/zQSyT4pFEwOWy8Bt5zw=
X-Google-Smtp-Source: AGHT+IFayOxV5oZcl/ZSLGcruIJCRbgBJIK2K8yPU1+Pmu3Bbr/a68PUtM7N3ULCFJIc2fGcUdcvjA==
X-Received: by 2002:aa7:cfd1:0:b0:514:9ab4:3524 with SMTP id r17-20020aa7cfd1000000b005149ab43524mr111550edy.7.1700502448837;
        Mon, 20 Nov 2023 09:47:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:343:b0:548:b79a:16c with SMTP id
 r3-20020a056402034300b00548b79a016cls86644edw.1.-pod-prod-02-eu; Mon, 20 Nov
 2023 09:47:27 -0800 (PST)
X-Received: by 2002:a05:6402:2d2:b0:543:5db5:2fb7 with SMTP id b18-20020a05640202d200b005435db52fb7mr104996edx.6.1700502447275;
        Mon, 20 Nov 2023 09:47:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700502447; cv=none;
        d=google.com; s=arc-20160816;
        b=tUwCQiK6QQrjGTQ/hI+xHloVtsDNkPisJCYN+pWggXN4Uq3PhSZQ/nKRjsWN2h9kzt
         8sROSqi1B07KODQiN2LLanpTOzI5Yr8f7rTsib8BkNg6Qgn86Qaoj7zT/XE5dQ0tRVFu
         GAc5HehuJk3KRJhr2+a5FVy2OdpSfNqjJCvE2gvIIoat9Fo+44rb8Af9+DdaGdZetZvD
         YpksuC4OOVQPp50+fIPcchbo9Ozn1Ay6hvxwVXN2KHndOeqNM+/ZUL4ZZcGryM3a3kJt
         chr7a3OR7+bOt7CDdHMg9+fOqXlXBa9fZoq2Pzyk1UQWtMgOUhCrg7x/ForZ0PtGssqm
         P4HA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=dirg16X8IjWPdQeQGOiKGtH7xHuc5gOowsqXecWSLlM=;
        fh=qWoxmPN1zRqnLSoCWGpfFsDtzJsx/SGdqx98lbP+Uho=;
        b=gnRUJGBXbzd+LmvtHWrNV6SoXZJwnybPYh57PXXcB5Iqr2EMWO8+dtOcEBkIUZe3vu
         7fesTossTLLzgGPXe0sT91u03K0obhntSPcCyPNF/gFZxzX8cjUTfEg/drmtTR8RwA9A
         rsiM4Y+NEclwWM7KOcYvudRwSuDkw6kT3EQHJIZo01XK9RPIQksnYd2WsAcl3oVwXxV4
         BZUJfgTcSrdiQ/j6TCpc2swgz3A0/8cmq8xZoWTAgfqQLAco/fPNxMA5BxfTTW3AWMfX
         o+swVcmngZNDJwl9Ql6R0HWx4hohaKOD/zxA+Z5V3mugbjFituFemqEKXYFSn1pAXfzp
         X74w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=LrmT6z7B;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.172 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-172.mta1.migadu.com (out-172.mta1.migadu.com. [95.215.58.172])
        by gmr-mx.google.com with ESMTPS id h21-20020a0564020e9500b0053e90546ff6si329293eda.1.2023.11.20.09.47.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 09:47:27 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.172 as permitted sender) client-ip=95.215.58.172;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v4 00/22] stackdepot: allow evicting stack traces
Date: Mon, 20 Nov 2023 18:46:58 +0100
Message-Id: <cover.1700502145.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=LrmT6z7B;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.172 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Currently, the stack depot grows indefinitely until it reaches its
capacity. Once that happens, the stack depot stops saving new stack
traces.

This creates a problem for using the stack depot for in-field testing
and in production.

For such uses, an ideal stack trace storage should:

1. Allow saving fresh stack traces on systems with a large uptime while
   limiting the amount of memory used to store the traces;
2. Have a low performance impact.

Implementing #1 in the stack depot is impossible with the current
keep-forever approach. This series targets to address that. Issue #2 is
left to be addressed in a future series.

This series changes the stack depot implementation to allow evicting
unneeded stack traces from the stack depot. The users of the stack depot
can do that via new stack_depot_save_flags(STACK_DEPOT_FLAG_GET) and
stack_depot_put APIs.

Internal changes to the stack depot code include:

1. Storing stack traces in fixed-frame-sized slots (vs precisely-sized
   slots in the current implementation); the slot size is controlled via
   CONFIG_STACKDEPOT_MAX_FRAMES (default: 64 frames);
2. Keeping available slots in a freelist (vs keeping an offset to the next
   free slot);
3. Using a read/write lock for synchronization (vs a lock-free approach
   combined with a spinlock).

This series also integrates the eviction functionality into KASAN:
the tag-based modes evict stack traces when the corresponding entry
leaves the stack ring, and Generic KASAN evicts stack traces for objects
once those leave the quarantine.

With KASAN, despite wasting some space on rounding up the size of each
stack record, the total memory consumed by stack depot gets saturated due
to the eviction of irrelevant stack traces from the stack depot.

With the tag-based KASAN modes, the average total amount of memory used
for stack traces becomes ~0.5 MB (with the current default stack ring size
of 32k entries and the default CONFIG_STACKDEPOT_MAX_FRAMES of 64). With
Generic KASAN, the stack traces take up ~1 MB per 1 GB of RAM (as the
quarantine's size depends on the amount of RAM).

However, with KMSAN, the stack depot ends up using ~4x more memory per a
stack trace than before. Thus, for KMSAN, the stack depot capacity is
increased accordingly. KMSAN uses a lot of RAM for shadow memory anyway,
so the increased stack depot memory usage will not make a significant
difference.

Other users of the stack depot do not save stack traces as often as KASAN
and KMSAN. Thus, the increased memory usage is taken as an acceptable
trade-off. In the future, these other users can take advantage of the
eviction API to limit the memory waste.

There is no measurable boot time performance impact of these changes for
KASAN on x86-64. I haven't done any tests for arm64 modes (the stack
depot without performance optimizations is not suitable for intended use
of those anyway), but I expect a similar result. Obtaining and copying
stack trace frames when saving them into stack depot is what takes the
most time.

This series does not yet provide a way to configure the maximum size of
the stack depot externally (e.g. via a command-line parameter). This will
be added in a separate series, possibly together with the performance
improvement changes.

---

Changes v3->v4:
- Rebase onto 6.7-rc2.
- Fix lockdep annotation in depot_fetch_stack.
- New patch: "kasan: use stack_depot_put for Generic mode" (was sent for
  review separately but now merged into this series).
- New patch: "lib/stackdepot: print disabled message only if truly
  disabled" (was sent for review separately but now merged into this
  series).
- New patch: "lib/stackdepot: adjust DEPOT_POOLS_CAP for KMSAN".

Changes v2->v3:
- Fix null-ptr-deref by using the proper number of entries for
  initializing the stack table when alloc_large_system_hash()
  auto-calculates the number (see patch #12).
- Keep STACKDEPOT/STACKDEPOT_ALWAYS_INIT Kconfig options not configurable
  by users.
- Use lockdep_assert_held_read annotation in depot_fetch_stack.
- WARN_ON invalid flags in stack_depot_save_flags.
- Moved "../slab.h" include in mm/kasan/report_tags.c in the right patch.
- Various comment fixes.

Changes v1->v2:
- Rework API to stack_depot_save_flags(STACK_DEPOT_FLAG_GET) +
  stack_depot_put.
- Add CONFIG_STACKDEPOT_MAX_FRAMES Kconfig option.
- Switch stack depot to using list_head's.
- Assorted minor changes, see the commit message for each path.

Andrey Konovalov (22):
  lib/stackdepot: print disabled message only if truly disabled
  lib/stackdepot: check disabled flag when fetching
  lib/stackdepot: simplify __stack_depot_save
  lib/stackdepot: drop valid bit from handles
  lib/stackdepot: add depot_fetch_stack helper
  lib/stackdepot: use fixed-sized slots for stack records
  lib/stackdepot: fix and clean-up atomic annotations
  lib/stackdepot: rework helpers for depot_alloc_stack
  lib/stackdepot: rename next_pool_required to new_pool_required
  lib/stackdepot: store next pool pointer in new_pool
  lib/stackdepot: store free stack records in a freelist
  lib/stackdepot: use read/write lock
  lib/stackdepot: use list_head for stack record links
  kmsan: use stack_depot_save instead of __stack_depot_save
  lib/stackdepot, kasan: add flags to __stack_depot_save and rename
  lib/stackdepot: add refcount for records
  lib/stackdepot: allow users to evict stack traces
  kasan: remove atomic accesses to stack ring entries
  kasan: check object_size in kasan_complete_mode_report_info
  kasan: use stack_depot_put for tag-based modes
  kasan: use stack_depot_put for Generic mode
  lib/stackdepot: adjust DEPOT_POOLS_CAP for KMSAN

 include/linux/stackdepot.h |  59 ++++-
 lib/Kconfig                |  10 +
 lib/stackdepot.c           | 452 ++++++++++++++++++++++++-------------
 mm/kasan/common.c          |   8 +-
 mm/kasan/generic.c         |  27 ++-
 mm/kasan/kasan.h           |   2 +-
 mm/kasan/quarantine.c      |  26 ++-
 mm/kasan/report_tags.c     |  27 +--
 mm/kasan/tags.c            |  24 +-
 mm/kmsan/core.c            |   7 +-
 10 files changed, 427 insertions(+), 215 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1700502145.git.andreyknvl%40google.com.
