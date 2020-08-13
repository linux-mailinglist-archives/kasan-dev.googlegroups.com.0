Return-Path: <kasan-dev+bncBCS37NMQ3YHBBCNU2X4QKGQEGETY23A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3B4D4243C57
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 17:19:38 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id c186sf2076036wmd.9
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Aug 2020 08:19:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597331978; cv=pass;
        d=google.com; s=arc-20160816;
        b=gbrJD+tHBPOudO/euwugt5JPCMZyub4gOQ3SJqK8O6qgcXMTkFlj4UP+xBYRZHW0cE
         nmReLzMQX6ooHTsAXXRWOwCrLdJVNDhXpF93WprIh5LW2RUd4HuuTejRBvCUYFZzhHnV
         StRJeOLnbBkhlfgqSNegEglTBstD0ci+Nf6Zr+80OwdiG7ppYvrFZKPrHisORhxhiGng
         /KeOlfEUS3z1DQoiNx0YGtyh8yUmXMowwrnXh5h9cYzoR7IkXaVYOxt96/KXgfz5Omf1
         7JB8L+TAfhyp6tGFunopGuDSd5Mb4zVaFw0Ljpg47xIc9YNiAZufqWDAMu5CuOCKSZLe
         UrIA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=tWK0oUv5Ll4YRV1mlvtvtXI3b1diQiV1FbiLsWavRAM=;
        b=z4MRKE42w+L2Dl9tSIr609X9x1JL52L0cchoEnNz6pxA2MwP6X+2fAQQ5ILX1BgOe5
         it6kTb5fy24jTyKvqUUp5zHQX+bDJHGaPqHvA4gd72GtYmDICdDSDNdrccmKWS+0hRl6
         2m86bg1vE3SWyJZ5/EVvyLddtUyBWkv3DQigtn1WsO1MO0G0vM+ELQGu3eTFEXHYsZfu
         CLDZQWd09KeY2GwXSwhZpU6KUKC7p42R/Vys6vv5yDlxTAppWWPSlWPTunxmXBvSqat5
         4infkCn05uQ726/+Tpx+y93hIXoZ/cn37hiCfP773msEGvBAJS/Y8NYaG9v8RmtdXKjr
         CW7g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tWK0oUv5Ll4YRV1mlvtvtXI3b1diQiV1FbiLsWavRAM=;
        b=Y9/dYeoeAMUQt7jLhG3VcXd0GOcZv9N42WJetfERfJV3p4kms/wYt1TVrR8Ihu+JQU
         ePBrvsuHVjhZyNE4RktXZrC3fVvwto27dY51khr+Z+PPkp8JgFi+6DL6HCKcKEn3LV4g
         TgRc1vfZI6MaN2mGq8JgTnvVarkL3ftEVoP4lmURcflxIAC9ntOmy5jE1/hnrIBIMwDj
         HdHLsGHtHEy9BkQo2dygseuNTYgOm49z4nadCKwUnHDY8LTz10NmPVFTu6I0moyhwdKK
         Z1fRYaN1S/oGUR2ztlRT6S+2gVIS1bYEYxk3KTuXEC2uSTbttUKzDrI0YSJ681FOmm3P
         FkBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tWK0oUv5Ll4YRV1mlvtvtXI3b1diQiV1FbiLsWavRAM=;
        b=pV3RAPdb4GlRBHAPF1XVxXgof25E3kcqzMyvr1F6yu8L+JQ/YDOYu1VGfCqgbDqPwj
         YTd+yCSYxydQisVtanJSUXLEDqDupsVHvbdaEReSaLZNSUvA+bQfYhxf8g8qVmbatq4u
         T496Hcxw+9CpqTvqrfIB1WoYLgAkiAOQliwBKnC8SQ3RPz9/E1xAGRkrRgRVTmyHhoeQ
         61WV5pILtWc0apkWUFWJ/O2aw2WNOS2NcTKxCSEu3wv7AhSdYqdO//AdokkRwY5VOrst
         T6YvvjBQb0jCmK0mQ+mMKFHu4E0xAYqB9FlYNQY9g6uiujwOj56YyUvUjDxOGgHMasZj
         EfnQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533kBE1ApGbt24GjOn5ob/CqjP4p/5Y7Pe2CPXAP8yk6kRIGJ2zD
	dct1TjpB8gOiQXG+pX7yXbk=
X-Google-Smtp-Source: ABdhPJxUPO+SraBJssQTni0wZot2EfZFMeoy/jj3SxDtxed6631AJ7UOekaWoaK3jkK900eUNCvrHw==
X-Received: by 2002:adf:e9cd:: with SMTP id l13mr4992054wrn.340.1597331977852;
        Thu, 13 Aug 2020 08:19:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e78f:: with SMTP id n15ls1693191wrm.1.gmail; Thu, 13 Aug
 2020 08:19:37 -0700 (PDT)
X-Received: by 2002:a5d:6a4e:: with SMTP id t14mr4618661wrw.135.1597331977408;
        Thu, 13 Aug 2020 08:19:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597331977; cv=none;
        d=google.com; s=arc-20160816;
        b=UCc+SEIx+wE19wcYu2gjhVKmTZmKG97sYaLINlASEgjbxmifBsYHVE/4zmtaX5ujYn
         N23+YDSMKQV3ETkKjThkKGCCya6TfbSgL0ZZImxlVvgvTOLWcqnihSDqNlH0pEi+iRG0
         9sTjBVIIqOoyjWOq1TotnWcTkPcFD7aRm7iUnUrDT5chJHSG2ld7G+Nd4Ea2DKvNw65D
         gT2Is5Qq0fOzlI1vWH1qGiE0ll9+HrnWK4img0e6VqidYQ8WKwXsecanFjHRceZS5sTk
         oHDx19Vbv8LmDr0WCo3BV3BQx48GYlY7KslbW0R6zQGO6NeIfht7DL8KLwAsfWc8W4lt
         Cbgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=kHpviHVAWFum71m9T91C+ViCrMTffHDaBIsRm4hTUyU=;
        b=jkFLryl2DT+BO9gDHWIoB3H8sd9cBhP4nh3BjTawpqKDdUIT27+cv4gYxkoDQALR+I
         gMheazvD7ws7diEIYpMmImu/BuaDcKqb7rHO3o2DItQcrw1NpiHdta12WseG6ebZIkE9
         bdX/6FMJ/B60RF4uh5pBBgDNqh2BmBc5joDbFK5IpWDfwdDdlYGrnnhFsJV+X/EBIrfT
         dyxXo+p3dZ8i2x1tFyvyYsyEf3vf0WBGShwB2QnOh9w3VfOyCfy3zWtxmztDuUjWxK2s
         3hsr4tz17L8I2HxVcSW7DiFWJ4fFKl894PMGD88+T08+fTzYR3C7STHaPT1eO2UMp7VL
         oMSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wr1-f67.google.com (mail-wr1-f67.google.com. [209.85.221.67])
        by gmr-mx.google.com with ESMTPS id o134si220747wme.0.2020.08.13.08.19.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Aug 2020 08:19:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) client-ip=209.85.221.67;
Received: by mail-wr1-f67.google.com with SMTP id f1so5656571wro.2
        for <kasan-dev@googlegroups.com>; Thu, 13 Aug 2020 08:19:37 -0700 (PDT)
X-Received: by 2002:a5d:6505:: with SMTP id x5mr4470670wru.336.1597331977069;
        Thu, 13 Aug 2020 08:19:37 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id d23sm10394044wmd.27.2020.08.13.08.19.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 13 Aug 2020 08:19:36 -0700 (PDT)
From: Alexander Popov <alex.popov@linux.com>
To: Kees Cook <keescook@chromium.org>,
	Jann Horn <jannh@google.com>,
	Will Deacon <will@kernel.org>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	Patrick Bellasi <patrick.bellasi@arm.com>,
	David Howells <dhowells@redhat.com>,
	Eric Biederman <ebiederm@xmission.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Laura Abbott <labbott@redhat.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC 0/2] Break heap spraying needed for exploiting use-after-free
Date: Thu, 13 Aug 2020 18:19:20 +0300
Message-Id: <20200813151922.1093791-1-alex.popov@linux.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

Hello everyone! Requesting for your comments.

Use-after-free vulnerabilities in the Linux kernel are very popular for
exploitation. A few examples:
 https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html
 https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html?m=1
 https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html

Use-after-free exploits usually employ heap spraying technique.
Generally it aims to put controlled bytes at a predetermined memory
location on the heap. Heap spraying for exploiting use-after-free in
the Linux kernel relies on the fact that on kmalloc(), the slab allocator
returns the address of the memory that was recently freed. So allocating
a kernel object with the same size and controlled contents allows
overwriting the vulnerable freed object.

I've found an easy way to break heap spraying for use-after-free
exploitation. I simply extracted slab freelist quarantine from KASAN
functionality and called it CONFIG_SLAB_QUARANTINE. Please see patch 1.

If this feature is enabled, freed allocations are stored in the quarantine
and can't be instantly reallocated and overwritten by the exploit
performing heap spraying.

In patch 2 you can see the lkdtm test showing how CONFIG_SLAB_QUARANTINE
prevents immediate reallocation of a freed heap object.

I tested this patch series both for CONFIG_SLUB and CONFIG_SLAB.

CONFIG_SLAB_QUARANTINE disabled:
  # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
  lkdtm: Performing direct entry HEAP_SPRAY
  lkdtm: Performing heap spraying...
  lkdtm: attempt 0: spray alloc addr 00000000f8699c7d vs freed addr 00000000f8699c7d
  lkdtm: freed addr is reallocated!
  lkdtm: FAIL! Heap spraying succeed :(

CONFIG_SLAB_QUARANTINE enabled:
  # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
  lkdtm: Performing direct entry HEAP_SPRAY
  lkdtm: Performing heap spraying...
  lkdtm: attempt 0: spray alloc addr 000000009cafb63f vs freed addr 00000000173cce94
  lkdtm: attempt 1: spray alloc addr 000000003096911f vs freed addr 00000000173cce94
  lkdtm: attempt 2: spray alloc addr 00000000da60d755 vs freed addr 00000000173cce94
  lkdtm: attempt 3: spray alloc addr 000000000b415070 vs freed addr 00000000173cce94
  ...
  lkdtm: attempt 126: spray alloc addr 00000000e80ef807 vs freed addr 00000000173cce94
  lkdtm: attempt 127: spray alloc addr 00000000398fe535 vs freed addr 00000000173cce94
  lkdtm: OK! Heap spraying hasn't succeed :)

I did a brief performance evaluation of this feature.

1. Memory consumption. KASAN quarantine uses 1/32 of the memory.
CONFIG_SLAB_QUARANTINE disabled:
  # free -m
                total        used        free      shared  buff/cache   available
  Mem:           1987          39        1862          10          86        1907
  Swap:             0           0           0
CONFIG_SLAB_QUARANTINE enabled:
  # free -m
                total        used        free      shared  buff/cache   available
  Mem:           1987         140        1760          10          87        1805
  Swap:             0           0           0

2. Performance penalty. I used `hackbench -s 256 -l 200 -g 15 -f 25 -P`.
CONFIG_SLAB_QUARANTINE disabled (x86_64, CONFIG_SLUB):
  Times: 3.088, 3.103, 3.068, 3.103, 3.107
  Mean: 3.0938
  Standard deviation: 0.0144
CONFIG_SLAB_QUARANTINE enabled (x86_64, CONFIG_SLUB):
  Times: 3.303, 3.329, 3.356, 3.314, 3.292
  Mean: 3.3188 (+7.3%)
  Standard deviation: 0.0223

I would appreciate your feedback!

Best regards,
Alexander

Alexander Popov (2):
  mm: Extract SLAB_QUARANTINE from KASAN
  lkdtm: Add heap spraying test

 drivers/misc/lkdtm/core.c  |   1 +
 drivers/misc/lkdtm/heap.c  |  40 ++++++++++++++
 drivers/misc/lkdtm/lkdtm.h |   1 +
 include/linux/kasan.h      | 107 ++++++++++++++++++++-----------------
 include/linux/slab_def.h   |   2 +-
 include/linux/slub_def.h   |   2 +-
 init/Kconfig               |  11 ++++
 mm/Makefile                |   3 +-
 mm/kasan/Makefile          |   2 +
 mm/kasan/kasan.h           |  75 +++++++++++++-------------
 mm/kasan/quarantine.c      |   2 +
 mm/kasan/slab_quarantine.c |  99 ++++++++++++++++++++++++++++++++++
 mm/slub.c                  |   2 +-
 13 files changed, 258 insertions(+), 89 deletions(-)
 create mode 100644 mm/kasan/slab_quarantine.c

-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200813151922.1093791-1-alex.popov%40linux.com.
