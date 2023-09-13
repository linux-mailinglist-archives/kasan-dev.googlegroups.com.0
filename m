Return-Path: <kasan-dev+bncBAABBCW4Q6UAMGQEJOPZSBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 0EA0079F003
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:14:52 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2bbbaa6001dsf204141fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:14:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625291; cv=pass;
        d=google.com; s=arc-20160816;
        b=KrsvKP5fZnoVd9BVu5cTFfYMLHOBZLnR/NLrty1geLeBn6toZ+LTklvn9M0OcI9nBW
         CKFFJheQ+Ej4N7S5nBdcVFBlTu0egcB92oUoXcq/1cVMtU+Y9trbiFJn9KVLPI/GS7w7
         /POJ4BhUjihsWUB7UEg4pm2uuQJmnGFV3bJoGbUS6ZFSIzmDsP1WTU71iBEm6hJiPYgg
         64Q449SKiUbj27k8CRc9YTfLg3NW888B4bK8Wf3fjd5QQtN1kmZTDRnQYaGLRiPDyYZ7
         JhjH9Jbap2273yMQvijhNcN7nle1LB9I1LlmlpOzCzmt10uQl7M7+lpFsA+/C7rSnBbR
         UORg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=IEEIDGJxCYxQy3Nq1PnfIRHRVOCtnntWdNEN33TtIOc=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=m5d0yahac9k8ncSgAjCKfjnY++7ENjCQlLw1a+QFjhbsBhjknPnJLZ8Hba3E4Fjh3M
         WM5sxvgaoa266Sy1ny6ixQhKYuiinB4ip9xlPanzrmrQNS3hQIdutVFmzzpuSG/k7A3E
         2tN2DZKAkjLoZwLF/6/407sFiTIjlhxwiBfJUsDDBttw8Wls36LmZ1UIy46OPuF0d+Vc
         vDmOmuhtb4xxQKS3r80Orlt8VkT2zqHg/p80VuXWlRq1DARAKq57JXWFK1cdQvFVePoS
         4Td1yzbxN326HI/m/UCAZ6uvEXxoJlbBbU5nqaLyORZ2RQo5fufr1kE/otQP1ugtP58w
         fCkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ODwSiHci;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::e1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625291; x=1695230091; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IEEIDGJxCYxQy3Nq1PnfIRHRVOCtnntWdNEN33TtIOc=;
        b=GGej0ufp6TDueoxl4rKwEH4gfnyZmAThLGvvsZxhgNoSDSZWZ7d2h2XdafhT9JfEsQ
         964F9HQHBlK0JpOWIrZ0B/dIeBh46f2lPvs48OeV/qws2jVnaLqRNC1C0hQd6R0TILkt
         k+ieWEbQT/29nqmziv82fvoBIZMNju9UX1SioYcFxyEnWeqJ/EqhO16ZbdwjYYx3je3G
         g+XeXK6p6U0D0AZD2ah28V63qs06x3dJro3cMxVTOXBK4MVN4PK4cMHNvu9n+g3o44QL
         wuPe2PGHVNHE5vJeFRGCsa1ERm58DKtfdAL1Af0aoVQEclAHw4RI9SOV1u+YXIO2qGz4
         +m3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625291; x=1695230091;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=IEEIDGJxCYxQy3Nq1PnfIRHRVOCtnntWdNEN33TtIOc=;
        b=tNUayjDI7NVY2xJPh5T00xLdNdOUaAO12C3q1tzxvqW0Z9fBH3NGDaYE9p4zvcX2ib
         4c6JsTCewcmHq2a+xSQIxE0GGH6hT6y0HV/gryyybKvV+0qFuOwaovFWq2BRmacQV+9S
         kvrN8a+HMgyIngZjxympOcPOMMvkVbAFEEVAL9B2LW0deEynTgCgevIzOInZpV7Y0Teu
         vj2q3XfcG8OhLXiacKVOLfueHGTDKk82oyHWUD+LjBAiuFK8VBEFago3zWZOOscRiQ2n
         z5+1RKz6EcB04LU6TTIDyCwprSV6pLpvu40XLQsWL7lFfJPfKJG7oPbzNf/eWwmqoHeW
         2dSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YznwnKFJjptXbE/mJihbB33LpjOqcS+I+wKhWa92fSG/O7tuVFt
	5iUATYS4Bopi4/WZRIrdT2U=
X-Google-Smtp-Source: AGHT+IFvo1cxWTZlsTMbiyKgaoV2/FJ+7x5uNmX1UW1oLIVREET6Hq4xr71QjmA2pi0hXyYfHAS5PQ==
X-Received: by 2002:a05:6512:2207:b0:502:a46e:257a with SMTP id h7-20020a056512220700b00502a46e257amr3240139lfu.56.1694625290482;
        Wed, 13 Sep 2023 10:14:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3d25:b0:502:d736:5e79 with SMTP id
 d37-20020a0565123d2500b00502d7365e79ls357369lfv.1.-pod-prod-03-eu; Wed, 13
 Sep 2023 10:14:49 -0700 (PDT)
X-Received: by 2002:a05:6512:5c7:b0:4ff:7e04:7575 with SMTP id o7-20020a05651205c700b004ff7e047575mr2505365lfo.14.1694625289054;
        Wed, 13 Sep 2023 10:14:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625289; cv=none;
        d=google.com; s=arc-20160816;
        b=BpPKWAu3ILQSYxvssNCRph/OIiUjxhNsuUkAeTP5wZp4Hz/k5rqgzGtNNz85M2IJOH
         mDpGqeXRyQyrQwGQitAms5CY+TyDnx/1YuzGwFyv3BitU+CKgCQsoHPxx2t+gzEXmz3c
         XsxmYeJEXGDQMRJtWAJaGucUOegn1dzXymLxQfYlaE0UfjVZYM1z5uSyLKyBRYJEFsiS
         c8cQN68WVGCljesltRPI//0ixrBS664qJQjsxfXiHqozinWpYu1zaH5KcKFe2zijP6hu
         LMHrVPfef7zCYTse9MceeSnU1p5epGVfGVRRXGs0XT0cfWMErx/5qE2zrfVUrfBDch6I
         byQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Gc6HzykR+A0L83xKMiWxb5E3eMlheJobgexoepcnfG0=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=hmsHdqBH/jgjU6J1ZLiuHYBCdMLAOfO8X+rOJGoPvyop7nGNnK6ncqxPLMpRDgig5i
         z73tqG23IibHHVW/GNhbtpqXnDaAym0gntpeMFy8Bv+SrRN2vimOLsyqqo/HNNCkVhFY
         R09bSqT0G2Cxr5SZITEHim0dvMCA6a/teJq6roLUI97MUtkfiln+N4DiD36x81qy2sKt
         zy7jpUVJ5J/hlE6egLrsOaStJjNw7X9mo/bwBJd4PgBHJCaXbPF7WV37++sLyvjMVqH0
         IsD1x+am8Z3If+40GQdfPzX9THU5AZtwNA8Qn5pr6Eo/ouylsZbgiK/Smqa2EXw7yaVh
         whvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ODwSiHci;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::e1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-225.mta0.migadu.com (out-225.mta0.migadu.com. [2001:41d0:1004:224b::e1])
        by gmr-mx.google.com with ESMTPS id b17-20020a056512305100b00502d58d12bdsi203773lfb.3.2023.09.13.10.14.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Sep 2023 10:14:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::e1 as permitted sender) client-ip=2001:41d0:1004:224b::e1;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Oscar Salvador <osalvador@suse.de>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 00/19] stackdepot: allow evicting stack traces
Date: Wed, 13 Sep 2023 19:14:25 +0200
Message-Id: <cover.1694625260.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ODwSiHci;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::e1 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

1. Storing stack traces in fixed-frame-sized slots; the slot size is
   controlled via CONFIG_STACKDEPOT_MAX_FRAMES (vs precisely-sized
   slots in the current implementation);
2. Keeping available slots in a freelist (vs keeping an offset to the next
   free slot);
3. Using a read/write lock for synchronization (vs a lock-free approach
   combined with a spinlock).

This series also integrates the eviction functionality in the tag-based
KASAN modes.

Despite wasting some space on rounding up the size of each stack record,
with CONFIG_STACKDEPOT_MAX_FRAMES=32, the tag-based KASAN modes end up
consuming ~5% less memory in stack depot during boot (with the default
stack ring size of 32k entries). The reason for this is the eviction of
irrelevant stack traces from the stack depot, which frees up space for
other stack traces.

For other tools that heavily rely on the stack depot, like Generic KASAN
and KMSAN, this change leads to the stack depot capacity being reached
sooner than before. However, as these tools are mainly used in fuzzing
scenarios where the kernel is frequently rebooted, this outcome should
be acceptable.

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

Changes v1->v2:
- Rework API to stack_depot_save_flags(STACK_DEPOT_FLAG_GET) +
  stack_depot_put.
- Add CONFIG_STACKDEPOT_MAX_FRAMES Kconfig option.
- Switch stack depot to using list_head's.
- Assorted minor changes, see the commit message for each path.

Andrey Konovalov (19):
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

 include/linux/stackdepot.h |  59 ++++--
 lib/Kconfig                |  10 +-
 lib/stackdepot.c           | 410 ++++++++++++++++++++++++-------------
 mm/kasan/common.c          |   7 +-
 mm/kasan/generic.c         |   9 +-
 mm/kasan/kasan.h           |   2 +-
 mm/kasan/report_tags.c     |  27 +--
 mm/kasan/tags.c            |  24 ++-
 mm/kmsan/core.c            |   7 +-
 9 files changed, 356 insertions(+), 199 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1694625260.git.andreyknvl%40google.com.
