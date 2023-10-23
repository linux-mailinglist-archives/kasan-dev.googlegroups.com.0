Return-Path: <kasan-dev+bncBAABBY533KUQMGQEZM7JCOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 744687D3C3E
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 18:23:00 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-53e08e439c8sf3945380a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 09:23:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698078180; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kx2lrb/Mng2zYxMJNMHW7qBNm2P4w16pAVL0Q9LSrrd4pHURJcbMlFQDAlCOTojrlv
         tmM4NdwCVBjeVZpb8ECbT6lMkm5fsNXXFnxfc1aUxjnWYCsENN7tU9islF2kQpj18VIj
         +QtvTyEcrU7wdTq2lgnTaSqzsNRgLY9+GHyfONrGbPnZvHaFRWCviecNKyPLktRv/scu
         XbWmeygtwcJdGBjuNN7tcE86fN6ZoV05khH0Ou8pQelxsjJ31kM1WwibHadDcNpWTZKv
         RcZhQB3qv6+qKmb7jqRJhElIAmIgLXurmvA0JTeJG8OpsqDZeGRSoJDZLQ6gteGNb3UJ
         xGJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=HCYb9ONRnp7eSTAFY0UQsEt2RgYtZ9QRb5FLeZ1ZMLo=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=deZSOv0doaGLj92EVn/YdRG2/oZZYXrclipSyVpFUrjC/NhVBc/np9gl7AqzTbtjH8
         aEjdBBZPGncKZS9QmJHpUWRC/Q1E4ypNagGy10HUtgWKi+KdXQc2HLgFL4xqu7Fp0WzB
         XQj6+54diD79zdqf0ExWgoKV+QH3c8RxmQcUxCC4BfF62WMbPyO6+DXDYW1aVE4xyqF+
         VIH84EZHOaTtIyFTAA/Mgxi2X7UteUgOgv3etVyGpqxtjVbu0Kxsk2rEj0sci5nmj5dT
         HGbVohdyvtcM/yLxPL/dtiTP6IFmXlwczjOWOolIEi6tFuTRJWDsNZBRppO4fjiCDHjg
         PbKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=en6BEB2N;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.210 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698078180; x=1698682980; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HCYb9ONRnp7eSTAFY0UQsEt2RgYtZ9QRb5FLeZ1ZMLo=;
        b=vNlzeOciUkGxLa89nReXjRmNlGaWsMLffPVWTbc2A4qcpGwzqFyQWdTTnt4vMmmSOQ
         j43HBNTJyYORd45uKRma9KgovxtsPN0d53rD7+UGcpgYx5SyQcxkELiXOdxKrOO2+GDZ
         NrOw6/o/HN5SCDsm+VkZf7JW7sXU34XYA1RU5eS6QPyVAhDdsWHzO6qB/fry95wlYT66
         KFgKJXWwyc7wFLCzljOWWXPeMNuyIUEikkj2U4sutdJkA/m6CXSgRAvw+oD5CRWK6yzv
         J35zYPBzdOfmNJoEZdI02Ntl3f6rXa5a1q0tI3yCmS0BaN6YL/nMiBOByAQCi8bR5f9m
         rn7Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698078180; x=1698682980;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HCYb9ONRnp7eSTAFY0UQsEt2RgYtZ9QRb5FLeZ1ZMLo=;
        b=PK6QV2mZdy2OIpG2Jjp+v+JHo1cwimQv4SlxOZfPQ+Y7advoal6SsCrSJXh6YzXwfS
         4TYh2C0Tu5N5vxI+t/Nfe5WAYRQ8v1evwbXr3Aw0la5EtLO8V1CV7yMAJF6ZPBgBa0hD
         rp/QJv6br85U+OMAPeymMG2fwSvN67vVcP++GtmHR8uTHkptfe9PwMAvEA2Y6JWKGcsn
         xuy0k1p2nvwGunTFMaivlyUJHLKXPJkgqkG2pZQqbRV8xOU0z0YoXwNHM4p+3uD/5YD1
         wVZrLAssqJnZ3DYSufWmc7jdZDhQBI2e+2Nl+mSYmbilO5WB24Wks0S2ywPjFfwOPYgl
         VMFw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yxuty3psFrgKa9E44SfTn4EljUgcS9YiEe8d5WTWEEzahh/8pRr
	KIw4sH+pzH82exb4phxE5XI=
X-Google-Smtp-Source: AGHT+IFTbXkK0Dwflq2hIhV08uqKoDm7bWjmqieCaXUjAYr0a3SuN44tSoMKKTEfTfPH4aYOaKj4kg==
X-Received: by 2002:a05:6402:268f:b0:52a:38c3:1b4b with SMTP id w15-20020a056402268f00b0052a38c31b4bmr8970355edd.15.1698078179690;
        Mon, 23 Oct 2023 09:22:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:249c:b0:530:eb75:8932 with SMTP id
 q28-20020a056402249c00b00530eb758932ls343290eda.2.-pod-prod-00-eu; Mon, 23
 Oct 2023 09:22:58 -0700 (PDT)
X-Received: by 2002:a05:6402:5c4:b0:531:14c4:ae30 with SMTP id n4-20020a05640205c400b0053114c4ae30mr13000139edx.0.1698078177779;
        Mon, 23 Oct 2023 09:22:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698078177; cv=none;
        d=google.com; s=arc-20160816;
        b=OivJoXAxetgooTylLvHb304QZWMUMhOeW877Fn1m7VEL406m24YxBPAGI6oTgXjoIb
         SrE42uhjRe1JT0P9dUp+qR19Fz2E48A/jnORQUK62zfybkxwg5qJ32xl7ek+E+cP7gCu
         LWQOn0g0AQ2E/geXVjYkF+7k9KzGECCcn5ZxpaBR5i3h0IHhtJjh1/8+7tLHBFKYbyeQ
         sEE0vKz3AHu7rPo7uI5Li2X9MkecDYfLf3uyjTTdSVIM6OkHp82n9xjuUyN9wUWA2hG7
         KqvVErp+w7kwF+KzUFRKDbTzKo3OzaSyDFAshHZTiqSUtaMRioT0fyIOYq64/SVczPVa
         lOpQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=hE8/xihIXcLGI8uaU/L34q0MmNF0Ny3eNAOyLz5owLs=;
        fh=nfQSbTp1dWHt2Ier1Up8UhVNdXOqoJJLNvTrpT3jJEk=;
        b=Pdw9TWXuvXE17JO1Fga17xrID9DLfgtlgffrkdxYvb5CtQMop0GoWunh4Rhg64v25J
         s9EtkE/aB2muUU21cY9ZlnAoTwsBioLNvNXFH5OYbPnixcyzas7vxGuq4g25Cf1J0+SV
         xbHo6IoH1Lm0BV0lYikbNZk10sl2AyuExTezmkIeFFVT5QpWBn4gBuTyaR69hObcU31t
         EyuznLVOcP1vhzO0Pkk05ldEG4W1++q8NccUVVis698NEWg3Us7Yte/Es3frh+L4PUo7
         ZLlKmPopc5tO/I51lnB7Xpo9lQBsNUlEm6Z6PjJW6EpiM33XLFAw7T6CnVQau281yZdF
         oODw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=en6BEB2N;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.210 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-210.mta0.migadu.com (out-210.mta0.migadu.com. [91.218.175.210])
        by gmr-mx.google.com with ESMTPS id p10-20020a056402500a00b0053e326c0717si211146eda.3.2023.10.23.09.22.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Oct 2023 09:22:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.210 as permitted sender) client-ip=91.218.175.210;
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
Subject: [PATCH v3 00/19] stackdepot: allow evicting stack traces
Date: Mon, 23 Oct 2023 18:22:31 +0200
Message-Id: <cover.1698077459.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=en6BEB2N;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.210
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
 lib/Kconfig                |  10 +
 lib/stackdepot.c           | 418 ++++++++++++++++++++++++-------------
 mm/kasan/common.c          |   7 +-
 mm/kasan/generic.c         |   9 +-
 mm/kasan/kasan.h           |   2 +-
 mm/kasan/report_tags.c     |  27 +--
 mm/kasan/tags.c            |  24 ++-
 mm/kmsan/core.c            |   7 +-
 9 files changed, 365 insertions(+), 198 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1698077459.git.andreyknvl%40google.com.
