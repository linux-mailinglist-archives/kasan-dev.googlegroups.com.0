Return-Path: <kasan-dev+bncBAABBV5UTKGQMGQEUP6GK5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 126D146405E
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:40:41 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id l15-20020a056402124f00b003e57269ab87sf18124242edw.6
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:40:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308439; cv=pass;
        d=google.com; s=arc-20160816;
        b=bmKYLg5hsvfl55Edx+U2Artj6NCMNGk1jKYX0dIRRZFlu992/xFZZDPzqcULH1zau9
         O7rm2e7763O504fGXqipjWJGkPzBEjWDvu1nihYdXgDixZApxN+fbvXuFzYPF9VZ4Cfv
         JikUOL51oDrAxRM4eAFtSzyCcpjUyeJw1PizbD7j+EKoU54mfbo7MNakb8wuOsB4dIKM
         EpX4U2GIONQjl9tbyVoByZ/PcN1kk8cV4Z88Zcq5xTkGBQEniUNIDbYakkHN3HidPer4
         46C9/5r/WfxN5ATZbYuhoK9R2q/l3gn6PMkUnHRXXi5/NfwB9EZcBIbp5EdXBU9mStSv
         7NTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6C81FHcbR48tBGT3fZJQksg0eHQMX/idZt8myU5O12U=;
        b=NwX9+yGG3dg5n7S+C3b2ZNAHAFkuLnBDzdShIcCyqZhfRpFOnFRq2C0dJeh/inGYv5
         Hrwe8NPba7ZE8tAmArbuH7nPgvXJCHKJdbsPiRQMy1qO8TuVDqBHHdHC2y+ZX09mgCKi
         qnqZP8tNUAvbJ4B8NiSwPdeG23OdyWqOw7O6Y6+CWmYYhXzjf8qNXSvXsq1ih+YxuAv+
         oLeJMPz+o/cQ9ARSEAV4x8UE0XzYJf1qEFeGwlrAmonFpFTdRjjBXbmq5vhWDlhZErPC
         ZYEwWrKv0OCaZ+lZ4U4KS4ixV0bdcOdPO7YS6baXGKTxxSbZPmmU7BsvrPiY+DM7DwDm
         W7qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="gni20/Gn";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6C81FHcbR48tBGT3fZJQksg0eHQMX/idZt8myU5O12U=;
        b=MbT1XT9wSaFSgsWPhcGTd7PbAljdrpI1CD65DccUDGmmqoGxv5imp5LUsVWlK2YSaP
         FnRu+5NJ4H7kYn0Tce6roWHmimBz0ka6x9kv9cs541ls1/Jfg+5DRvugrfIGHxaVR7Op
         IJQbkpfnbXmjQ4puD5xG/m5R8g395rJGhSwQLNDVSjKbj/I/xUDjknEZ5TtK46osTv9A
         nmkpRxDyB8vfpfT2BGfZzpuJWVNCcBgEGUxo7mPWgv1xJ1zNp9x70kR8Md+kFqqLroQF
         Qk+E3u1VV5w9f7EbKXkzmwHQM64WqxIoiXIu14YEreb0Tga4vtXsHBO2YwoK4u3PCUAC
         rYrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6C81FHcbR48tBGT3fZJQksg0eHQMX/idZt8myU5O12U=;
        b=nqRF/EldwC6fUgkmrSORaMMAJNf7BAYPftQIOa5XEyhGU7zEYekL+JaLaPxo4njxRW
         9QLuTfr/Cr5FfbLJ7AjlyCRI3573gUnczEnWrBo8EN/17+Aqnhc4O66RjKlJ0weEJ5i9
         PPOFcMjmurYtaghOSLBn5dOWlFd3zQ+XlA7AKQpAmtppOdYJgWy3X0362twGcBaDAMmU
         vaLYgIrkfTQoEbZxTsAwNYsG0oqvXoCtZQttD/WCHKmneD00qUyhPx7SOgURZf2uvaql
         lQaJcaroNzUqEjDn/+XLKqrUwrG80TZD5t++60Lo5vZwpnjUZ4h+AVywcFkRBagnHVYq
         rQKA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533W2wIeMGCQy13ojuFCxQcf9b1LMFsWt72mceLhuXXSoXvV8qxT
	/Y2MdwN+6zjgj2N1nc9cJU0=
X-Google-Smtp-Source: ABdhPJwrfrPKEQ2zJNF5//rh+Ncr7L9DhOf7M6DUZ+TTlbSPZDdNnQe3euH4OC3nBEuejZX3+R1frg==
X-Received: by 2002:a17:906:aecf:: with SMTP id me15mr1914129ejb.351.1638308439690;
        Tue, 30 Nov 2021 13:40:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:c944:: with SMTP id h4ls186308edt.1.gmail; Tue, 30 Nov
 2021 13:40:38 -0800 (PST)
X-Received: by 2002:aa7:cb48:: with SMTP id w8mr2396462edt.402.1638308438816;
        Tue, 30 Nov 2021 13:40:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308438; cv=none;
        d=google.com; s=arc-20160816;
        b=joFjOsE7TpGmVOerLNT34Q92v+cM5c37jCOm/UoznpisMH34EAH3HrTpwikDn0ssng
         1Iwajx7nTdolVVIPuMZgYyane0sIaehdFcabrUIuXM6wq3iIoEHyZ1rpQWPs7FJudwBh
         1rD3k48LBGQTaBfjYLZ9xt7okVVK2jZb/WeVUDw7uJQS5cWs9i3sCElQ2ENOemaWcZvi
         HSkSKIg2UgKEdWWzRzRKWEnRGfPkGt6GVXK0Bme54aLrexpLHQg2s2bJvYf3Jb76oXQu
         R1WrLvhtV4S0KgNB71teFPflfIQlnwYu2hJ2V16QRtn+U5ErV0BjVgJ58xKQ9HHJFd7y
         NEXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Rcspyw3aJSs9x/mVwJKJ/FdDOElM4iaddbIoQBCce4s=;
        b=ikIkaDO5Z4MxM60stijDGm+mWbdOzA+lExVpUDH3DHwSGGJmYQRSzy54j6+omH91Iv
         Axso9uUPAQhdW5Vds9mGj2KyInkQma9PxFzfsDw6JCGsc8qt3Wrzkxg6vsI8xZzYVi3p
         hmb5KrtpW4RA8JbKW14xBgEH9r0UipV/RCUIZjhvEfGoa0DQAKroVjAKrIR7UeQ++97+
         sUWR9Dweho6fAngumZwQ0w99In3BOT23wMU8nZeZHpRTDyPG0V/xvE4EpWQTjRa3TcRQ
         VQJAPNoUMnMW5UPVsx3gJuqWXLrBTiAq0XUinP9ATFLuXVFKDAxwx9MamG072NBep5Cu
         lSvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="gni20/Gn";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id eb8si1631834edb.0.2021.11.30.13.40.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:40:38 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 00/31] kasan, vmalloc, arm64: add vmalloc tagging support for SW/HW_TAGS
Date: Tue, 30 Nov 2021 22:39:06 +0100
Message-Id: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="gni20/Gn";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

Hi,

This patchset adds vmalloc tagging support for SW_TAGS and HW_TAGS
KASAN modes.

About half of patches are cleanups I went for along the way. None of
them seem to be important enough to go through stable, so I decided
not to split them out into separate patches/series.

I'll keep the patchset based on the mainline for now. Once the
high-level issues are resolved, I'll rebase onto mm - there might be
a few conflicts right now.

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

Two things about the patchset that might be questionable, and I'd like
to get input on:

1. In this version of the pathset, if both HW_TAGS KASAN and memory
   initialization are enabled, the memory for vmalloc() allocations is
   initialized by page_alloc, while the tags are assigned in vmalloc.
   Initially I thought that moving memory initialization into vmalloc
   would be confusing, but I don't have any good arguments to support
   that. So unless anyone has objecttions, I will move memory
   initialization for HW_TAGS KASAN into vmalloc in v2.

2. In this version of the patchset, when VMAP_STACK is enabled, pointer
   tags of stacks allocated via vmalloc() are reset, see the "kasan,
   fork: don't tag stacks allocated with vmalloc" patch. However,
   allowing sp to be tagged works just fine in my testing setup. Does
   anyone has an idea of why having a tagged sp in the kernel could be
   bad? If not, I can drop the mentioned patch.

Thanks!

Andrey Konovalov (31):
  kasan, page_alloc: deduplicate should_skip_kasan_poison
  kasan, page_alloc: move tag_clear_highpage out of
    kernel_init_free_pages
  kasan, page_alloc: merge kasan_free_pages into free_pages_prepare
  kasan, page_alloc: simplify kasan_poison_pages call site
  kasan, page_alloc: init memory of skipped pages on free
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
  kasan, fork: don't tag stacks allocated with vmalloc
  kasan, vmalloc: add vmalloc support to SW_TAGS
  kasan, arm64: allow KASAN_VMALLOC with SW_TAGS
  kasan, vmalloc, arm64: mark vmalloc mappings as pgprot_tagged
  kasan, vmalloc: don't unpoison VM_ALLOC pages before mapping
  kasan, page_alloc: allow skipping unpoisoning for HW_TAGS
  kasan, vmalloc: add vmalloc support to HW_TAGS
  kasan: add kasan.vmalloc command line flag
  kasan, arm64: allow KASAN_VMALLOC with HW_TAGS
  kasan: documentation updates
  kasan: improve vmalloc tests

 Documentation/dev-tools/kasan.rst |  17 ++-
 arch/arm64/Kconfig                |   2 +-
 arch/arm64/include/asm/vmalloc.h  |  10 ++
 arch/arm64/kernel/module.c        |   2 +-
 arch/s390/kernel/module.c         |   2 +-
 arch/x86/kernel/module.c          |   2 +-
 include/linux/gfp.h               |  17 ++-
 include/linux/kasan.h             |  90 +++++++++------
 include/linux/vmalloc.h           |  18 ++-
 kernel/fork.c                     |   1 +
 lib/Kconfig.kasan                 |  20 ++--
 lib/test_kasan.c                  | 181 +++++++++++++++++++++++++++++-
 mm/kasan/common.c                 |   4 +-
 mm/kasan/hw_tags.c                | 142 +++++++++++++++++++----
 mm/kasan/kasan.h                  |  16 ++-
 mm/kasan/shadow.c                 |  54 +++++----
 mm/page_alloc.c                   | 138 +++++++++++++++--------
 mm/vmalloc.c                      |  65 +++++++++--
 18 files changed, 597 insertions(+), 184 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1638308023.git.andreyknvl%40google.com.
