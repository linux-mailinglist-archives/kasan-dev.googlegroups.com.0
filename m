Return-Path: <kasan-dev+bncBCS37NMQ3YHBB674ZX5QKGQEEVTRJHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id B2CC927D5D3
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 20:35:40 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id z77sf3380125lfc.2
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 11:35:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601404540; cv=pass;
        d=google.com; s=arc-20160816;
        b=crioxybVOW/C2oXtk43Lzk1DLrnbqQ/A4Bi2C6WRtaiM+7IDPo+n13f4CAYyMOihcv
         liDplbwJrgGh03dr/khaIGC3tv9wlP/xN6+B5Ba/zlYhY46LW7GvcEZj4Q2ltqJSjw8z
         s5IJkTxvBRN3mirjZS9njKHhaWWcXIwa5dNYdvv+G1nOiI0p1KidD/8e9bVDWBjCIySu
         2mk8YWiGYkkvAP+uYH6KU1CQgT4k17P5vSu83ByAZ5ndXWLzb3gb1CTmd9OJ2ZHPCTXV
         igsUB4GkijIK69VvZKAHFCl0jtlNRXwwZYe/wQEQkyksstMI/DO//Wh9ZQKuvJ4uPN52
         G2tg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=2cezj6g0LQceYlr4eH0O4djE0fRTpYwppnP4BfZ2PXU=;
        b=icG3EFUX3BAdr9EWizGySOm+u8NKFIaLVTV+nyQ06+bsB1WtQFTchSw5Qy1dTGZLmX
         FhP01bvOzyE51UlgLhaI/FEVovLx8fQic0s75GIY8HwFNT5MfY25SR8eE0U8TEkTLxoP
         aAhWZZlR2NgXmuT6z9Kn+zg3ZO4D+VWYigO36Zs9t+mQTTjfZIb50xCExu7roTFX4JQS
         PCUMSCshT5+3FsWwKLRTP/LHY5UhWShcZrepO3kPjx7AyfqJGQMks0mb/H5tRiK8600R
         1hWRXarsBphKnCpVNVmPjZ5ZDAMIbpiAoAdUww0woRJDf7gM2qO142ZSRpB38TXSERG8
         lsRA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2cezj6g0LQceYlr4eH0O4djE0fRTpYwppnP4BfZ2PXU=;
        b=Ani/+2FmQyjE7r0RROvaqohrC/mM6vD6Ftz+ho+4RqxXi88/KTHZpN2+w35XGX6D0l
         WjXCxOKSu6jSBNmM/r43fO3yNRldLLAAG/QxIZUEZ8t/jafFIFNR+YhckCKMW3+meZRs
         4uHcUAvHdQLyxcv8MdwdplvMGFAaecPos0PUh5CkSkWb2m5OzMLqQLNocyA+j3i3WX1n
         w4bo87rxSo2VMJVzzK9RdgcMCUxOOphyXe3L/U90/alsIkfXyV5hWtqGHC4Q7FUHVGkk
         UdGtcCd3GPFQeiAFGIgHONWGUMyNzH5TmTlgvSRyZUIsx7NL79b5zZm3TwQVhCc11KAA
         wUDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2cezj6g0LQceYlr4eH0O4djE0fRTpYwppnP4BfZ2PXU=;
        b=mgxyAOTiHs2AkOPIBBEfZOlRt1po9TdJBx9BYiHonAxjYN/vysoybfokVxs/1jOWD0
         6Mzj7vD+tklP8GXGwf2YQp20Vnq2J/VNlFsduvHXqnByE/eMtv9r7tJuHLPYFCtdBXmb
         65JKjZhyBhqpYpvZyupb7xURbef6ih0WN98iELFJqCBAoDeN4mWR4RfqxfK9rvgqiExX
         IlQSlb9eo5mS0FQwn86IO1Jvsndf7NGnDIsdChPxHUEp+KMnLYAM/tchUmenkU4OnQV4
         HHsCCApX/T8Hc6HTCle+CriqcxHVaX59bOssLBYCj9KGS0BSJEdCLY2zccoMtmhFoEzu
         V4qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ztbyvKQ/q32pJ3AqyUiuKfhZMkLJgenwqOnX1Dy7RmfRfNR3+
	K1Stx7qVUkClxInn278e3eA=
X-Google-Smtp-Source: ABdhPJwquAlD0WZ68LAk3HwRHLw3UKeQu13OLqsYwK3GJX2Q2xWKesDeOORcrkOtWXMLwq/CY6mMqQ==
X-Received: by 2002:a2e:a48c:: with SMTP id h12mr1736263lji.221.1601404540189;
        Tue, 29 Sep 2020 11:35:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:544e:: with SMTP id d14ls1311395lfn.2.gmail; Tue, 29 Sep
 2020 11:35:39 -0700 (PDT)
X-Received: by 2002:ac2:5a04:: with SMTP id q4mr1881043lfn.450.1601404538976;
        Tue, 29 Sep 2020 11:35:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601404538; cv=none;
        d=google.com; s=arc-20160816;
        b=vJWPkr6CvIw/fQ+6eploHmvppF/wzjz93Zt1Ez0ZjOUjs70N9rPWhfU4+rw749zm2m
         I0y4Duptd24Ubh+IppEMMst5xOVZbiO5Yzx6QETbEKI9UvKVEIGhk0kHqA7wbNjgPhnj
         R0rYtgrDpc+qu16VTR7+paGKr5Fc4QYx2Fg01xmHG+khRboBNGf82LPAaAmaTyrzqVxw
         DPDSGngfUeTrTiVbAS8ovakoWU4nPCiWxLA7uXUqyLsf9SiHHxSDJPEOkn1XtYBcPN06
         L4+5P2TGps48VfMvjwQKtxikT+rVzZdSJdHqCFM4YSX5ngnOM11DBn8qqN3QvVGBu7Pa
         3Mvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=eqJLertCH1IwPmpvLzgQGPTWwPvCX5lgWM52z3jpf1I=;
        b=flEhAkzFVXnNAxjIbnOnUdiwOpP4T0y8A4DBNCXmZzs4Q0J1GeouNzanX1iErLx/SB
         VLhmwY9XI7gBDzVbV9oY8KZcx3aTwwbMEPIg/pL96M2kRuFLBmpYkxsUx5R7kmnqWbEM
         NfUtKE1FI9vQu0ttCvKgHT+MPBWCdU8JNmcrZ0VjmWISVX4KejGkXEN09ZPArFwLrflM
         240CTZC33YTZQ3D8m4Nw8F4f7l/2dkd+jJBvC/jzs5r8Nhzo06AKBLaCnWV+WSxulOP1
         xNsvymwesWfwt+/almh1Veud5kTU+GVma95cPhprqGqSZL6Jouoo2SsdljAfobgp0DbQ
         SDAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-wr1-f67.google.com (mail-wr1-f67.google.com. [209.85.221.67])
        by gmr-mx.google.com with ESMTPS id q20si310063lji.2.2020.09.29.11.35.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Sep 2020 11:35:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.221.67 as permitted sender) client-ip=209.85.221.67;
Received: by mail-wr1-f67.google.com with SMTP id z4so6573923wrr.4
        for <kasan-dev@googlegroups.com>; Tue, 29 Sep 2020 11:35:38 -0700 (PDT)
X-Received: by 2002:a5d:6b84:: with SMTP id n4mr6285730wrx.55.1601404538270;
        Tue, 29 Sep 2020 11:35:38 -0700 (PDT)
Received: from localhost.localdomain ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id b188sm12151271wmb.2.2020.09.29.11.35.33
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Sep 2020 11:35:37 -0700 (PDT)
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
	Daniel Micay <danielmicay@gmail.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Matthew Wilcox <willy@infradead.org>,
	Pavel Machek <pavel@denx.de>,
	Valentin Schneider <valentin.schneider@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	kernel-hardening@lists.openwall.com,
	linux-kernel@vger.kernel.org,
	Alexander Popov <alex.popov@linux.com>
Cc: notify@kernel.org
Subject: [PATCH RFC v2 0/6] Break heap spraying needed for exploiting use-after-free
Date: Tue, 29 Sep 2020 21:35:07 +0300
Message-Id: <20200929183513.380760-1-alex.popov@linux.com>
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

This is the second version of the heap quarantine prototype for the Linux
kernel. I performed a deeper evaluation of its security properties and
developed new features like quarantine randomization and integration with
init_on_free. That is fun! See below for more details.


Rationale
=========

Use-after-free vulnerabilities in the Linux kernel are very popular for
exploitation. There are many examples, some of them:
 https://googleprojectzero.blogspot.com/2018/09/a-cache-invalidation-bug-in-linux.html
 https://googleprojectzero.blogspot.com/2019/11/bad-binder-android-in-wild-exploit.html?m=1
 https://a13xp0p0v.github.io/2020/02/15/CVE-2019-18683.html

Use-after-free exploits usually employ heap spraying technique.
Generally it aims to put controlled bytes at a predetermined memory
location on the heap.

Heap spraying for exploiting use-after-free in the Linux kernel relies on
the fact that on kmalloc(), the slab allocator returns the address of
the memory that was recently freed. So allocating a kernel object with
the same size and controlled contents allows overwriting the vulnerable
freed object.

I've found an easy way to break the heap spraying for use-after-free
exploitation. I extracted slab freelist quarantine from KASAN functionality
and called it CONFIG_SLAB_QUARANTINE. Please see patch 1/6.

If this feature is enabled, freed allocations are stored in the quarantine
queue where they wait for actual freeing. So they can't be instantly
reallocated and overwritten by use-after-free exploits.

N.B. Heap spraying for out-of-bounds exploitation is another technique,
heap quarantine doesn't break it.


Security properties
===================

For researching security properties of the heap quarantine I developed 2 lkdtm
tests (see the patch 5/6).

The first test is called lkdtm_HEAP_SPRAY. It allocates and frees an object
from a separate kmem_cache and then allocates 400000 similar objects.
I.e. this test performs an original heap spraying technique for use-after-free
exploitation.

If CONFIG_SLAB_QUARANTINE is disabled, the freed object is instantly
reallocated and overwritten:
  # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
   lkdtm: Performing direct entry HEAP_SPRAY
   lkdtm: Allocated and freed spray_cache object 000000002b5b3ad4 of size 333
   lkdtm: Original heap spraying: allocate 400000 objects of size 333...
   lkdtm: FAIL: attempt 0: freed object is reallocated

If CONFIG_SLAB_QUARANTINE is enabled, 400000 new allocations don't overwrite
the freed object:
  # echo HEAP_SPRAY > /sys/kernel/debug/provoke-crash/DIRECT
   lkdtm: Performing direct entry HEAP_SPRAY
   lkdtm: Allocated and freed spray_cache object 000000009909e777 of size 333
   lkdtm: Original heap spraying: allocate 400000 objects of size 333...
   lkdtm: OK: original heap spraying hasn't succeed

That happens because pushing an object through the quarantine requires _both_
allocating and freeing memory. Objects are released from the quarantine on
new memory allocations, but only when the quarantine size is over the limit.
And the quarantine size grows on new memory freeing.

That's why I created the second test called lkdtm_PUSH_THROUGH_QUARANTINE.
It allocates and frees an object from a separate kmem_cache and then performs
kmem_cache_alloc()+kmem_cache_free() for that cache 400000 times.
This test effectively pushes the object through the heap quarantine and
reallocates it after it returns back to the allocator freelist:
  # echo PUSH_THROUGH_QUARANTINE > /sys/kernel/debug/provoke-crash/
   lkdtm: Performing direct entry PUSH_THROUGH_QUARANTINE
   lkdtm: Allocated and freed spray_cache object 000000008fdb15c3 of size 333
   lkdtm: Push through quarantine: allocate and free 400000 objects of size 333...
   lkdtm: Target object is reallocated at attempt 182994
  # echo PUSH_THROUGH_QUARANTINE > /sys/kernel/debug/provoke-crash/
   lkdtm: Performing direct entry PUSH_THROUGH_QUARANTINE
   lkdtm: Allocated and freed spray_cache object 000000004e223cbe of size 333
   lkdtm: Push through quarantine: allocate and free 400000 objects of size 333...
   lkdtm: Target object is reallocated at attempt 186830
  # echo PUSH_THROUGH_QUARANTINE > /sys/kernel/debug/provoke-crash/
   lkdtm: Performing direct entry PUSH_THROUGH_QUARANTINE
   lkdtm: Allocated and freed spray_cache object 000000007663a058 of size 333
   lkdtm: Push through quarantine: allocate and free 400000 objects of size 333...
   lkdtm: Target object is reallocated at attempt 182010

As you can see, the number of the allocations that are needed for overwriting
the vulnerable object is almost the same. That would be good for stable
use-after-free exploitation and should not be allowed.
That's why I developed the quarantine randomization (see the patch 4/6).

This randomization required very small hackish changes of the heap quarantine
mechanism. At first all quarantine batches are filled by objects. Then during
the quarantine reducing I randomly choose and free 1/2 of objects from a
randomly chosen batch. Now the randomized quarantine releases the freed object
at an unpredictable moment:
   lkdtm: Target object is reallocated at attempt 107884
   lkdtm: Target object is reallocated at attempt 265641
   lkdtm: Target object is reallocated at attempt 100030
   lkdtm: Target object is NOT reallocated in 400000 attempts
   lkdtm: Target object is reallocated at attempt 204731
   lkdtm: Target object is reallocated at attempt 359333
   lkdtm: Target object is reallocated at attempt 289349
   lkdtm: Target object is reallocated at attempt 119893
   lkdtm: Target object is reallocated at attempt 225202
   lkdtm: Target object is reallocated at attempt 87343

However, this randomization alone would not disturb the attacker, because
the quarantine stores the attacker's data (the payload) in the sprayed objects.
I.e. the reallocated and overwritten vulnerable object contains the payload
until the next reallocation (very bad).

Hence heap objects should be erased before going to the heap quarantine.
Moreover, filling them by zeros gives a chance to detect use-after-free
accesses to non-zero data while an object stays in the quarantine (nice!).
That functionality already exists in the kernel, it's called init_on_free.
I integrated it with CONFIG_SLAB_QUARANTINE in the patch 3/6.

During that work I found a bug: in CONFIG_SLAB init_on_free happens too
late, and heap objects go to the KASAN quarantine being dirty. See the fix
in the patch 2/6.

For deeper understanding of the heap quarantine inner workings, I attach
the patch 6/6, which contains verbose debugging (not for merge).
It's very helpful, see the output example:
   quarantine: PUT 508992 to tail batch 123, whole sz 65118872, batch sz 508854
   quarantine: whole sz exceed max by 494552, REDUCE head batch 0 by 415392, leave 396304
   quarantine: data level in batches:
     0 - 77%
     1 - 108%
     2 - 83%
     3 - 21%
   ...
     125 - 75%
     126 - 12%
     127 - 108%
   quarantine: whole sz exceed max by 79160, REDUCE head batch 12 by 14160, leave 17608
   quarantine: whole sz exceed max by 65000, REDUCE head batch 75 by 218328, leave 195232
   quarantine: PUT 508992 to tail batch 124, whole sz 64979984, batch sz 508854
   ...


Changes in v2
=============

 - Added heap quarantine randomization (the patch 4/6).

 - Integrated CONFIG_SLAB_QUARANTINE with init_on_free (the patch 3/6).

 - Fixed late init_on_free in CONFIG_SLAB (the patch 2/6).

 - Added lkdtm_PUSH_THROUGH_QUARANTINE test.

 - Added the quarantine verbose debugging (the patch 6/6, not for merge).

 - Improved the descriptions according to the feedback from Kees Cook
   and Matthew Wilcox.

 - Made fixes recommended by Kees Cook:

   * Avoided BUG_ON() in kasan_cache_create() by handling the error and
     reporting with WARN_ON().

   * Created a separate kmem_cache for new lkdtm tests.

   * Fixed kasan_track.pid type to pid_t.


TODO for the next prototypes
============================

1. Performance evaluation and optimization.
   I would really appreciate your ideas about performance testing of a
   kernel with the heap quarantine. The first prototype was tested with
   hackbench and kernel build timing (which showed very different numbers).
   Earlier the developers similarly tested init_on_free functionality.
   However, Brad Spengler says in his twitter that such testing method
   is poor.

2. Complete separation of CONFIG_SLAB_QUARANTINE from KASAN (feedback
   from Andrey Konovalov).

3. Adding a kernel boot parameter for enabling/disabling the heap quaranitne
   (feedback from Kees Cook).

4. Testing the heap quarantine in near-OOM situations (feedback from
   Pavel Machek).

5. Does this work somehow help or disturb the integration of the
   Memory Tagging for the Linux kernel?

6. After rebasing the series onto v5.9.0-rc6, CONFIG_SLAB kernel started to
   show warnings about few slab caches that have no space for additional
   metadata. It needs more investigation. I believe it affects KASAN bug
   detection abilities as well. Warning example:
     WARNING: CPU: 0 PID: 0 at mm/kasan/slab_quarantine.c:38 kasan_cache_create+0x37/0x50
     Modules linked in:
     CPU: 0 PID: 0 Comm: swapper Not tainted 5.9.0-rc6+ #1
     Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-2.fc32 04/01/2014
     RIP: 0010:kasan_cache_create+0x37/0x50
     ...
     Call Trace:
      __kmem_cache_create+0x74/0x250
      create_boot_cache+0x6d/0x91
      create_kmalloc_cache+0x57/0x93
      new_kmalloc_cache+0x39/0x47
      create_kmalloc_caches+0x33/0xd9
      start_kernel+0x25b/0x532
      secondary_startup_64+0xb6/0xc0

Thanks in advance for your feedback.
Best regards,
Alexander


Alexander Popov (6):
  mm: Extract SLAB_QUARANTINE from KASAN
  mm/slab: Perform init_on_free earlier
  mm: Integrate SLAB_QUARANTINE with init_on_free
  mm: Implement slab quarantine randomization
  lkdtm: Add heap quarantine tests
  mm: Add heap quarantine verbose debugging (not for merge)

 drivers/misc/lkdtm/core.c  |   2 +
 drivers/misc/lkdtm/heap.c  | 110 +++++++++++++++++++++++++++++++++++++
 drivers/misc/lkdtm/lkdtm.h |   2 +
 include/linux/kasan.h      | 107 ++++++++++++++++++++----------------
 include/linux/slab_def.h   |   2 +-
 include/linux/slub_def.h   |   2 +-
 init/Kconfig               |  14 +++++
 mm/Makefile                |   3 +-
 mm/kasan/Makefile          |   2 +
 mm/kasan/kasan.h           |  75 +++++++++++++------------
 mm/kasan/quarantine.c      | 102 ++++++++++++++++++++++++++++++----
 mm/kasan/slab_quarantine.c | 106 +++++++++++++++++++++++++++++++++++
 mm/page_alloc.c            |  22 ++++++++
 mm/slab.c                  |   5 +-
 mm/slub.c                  |   2 +-
 15 files changed, 455 insertions(+), 101 deletions(-)
 create mode 100644 mm/kasan/slab_quarantine.c

-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200929183513.380760-1-alex.popov%40linux.com.
