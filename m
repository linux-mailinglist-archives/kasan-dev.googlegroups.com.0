Return-Path: <kasan-dev+bncBAABBBVOWK4AMGQEPWL46JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CCA399BE70
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 05:59:03 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6cbd2cb2f78sf75996986d6.0
        for <lists+kasan-dev@lfdr.de>; Sun, 13 Oct 2024 20:59:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728878342; cv=pass;
        d=google.com; s=arc-20240605;
        b=Nlx6SvnWow5MdvwaTACr30XS+v+FbXg850qpCFikWUCUppb5NGgiSAb/olwjwwSiQ2
         8BSFbL/LLtPsp/SbTj6QsYBrfQBhlWJvyqfaBH1nm1odM4UsqwxUGUyz/+Q4a/89CMBL
         k/+62/vI+AryBPgeQWFmTpyAh9G0RBfpDBfGEmMK1v2pehlRGVT1sbNPfIMEMNhf6JJf
         Tw5VbSlRWlzv4Q+oQODWvflPu+Iz2cgq+SEOF38xSYWEFvmUVP51tFVX890zJi3RrWWg
         fgWw4e4zY9V/OE4hPVzCq+EmOQotsbFJoaBPk0GnOtH6VJZmrCUZjdOG9f+ZNvK0TqNi
         zhZg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=pObMglnB96kEp+l3QajGm5DshLJZ0CFYfmUqf5zzQjQ=;
        fh=Ko0Xlw58Se0BX5xHChxJYhvA9YNIvBtqP+7WdI0e2xc=;
        b=Dp7/uFJCioCOPNoBuNrgYinV8CYFazOdmXnjxJwneJ69jQX+RveftLdN962EnmMD+Y
         w/JQGqYsC3VBMF5Ve5mUBnYrP2VUuxp5saM8n4BQOScjJMkKSiTtCjGHIcSi4MElKvuo
         ZsdERUeSJItAE/9uwFCBEE3uYD6+Md3EUWlTOc8jTnhW/VOVVCuT6uGpOBMso6sBbE2j
         xal8F3sz5Km+X7hf9qHoVGXVu0BSOk5QwH/gAOh0ZEAVxRFealnMXQtVmaKliBl00hBq
         TaNRq00tCBk9eN92L5VFUMU/lQ2u6ScSVladDQuy8PPjm2B+8bzUy6Jz9g49ADqgB83X
         XhjA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728878342; x=1729483142; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pObMglnB96kEp+l3QajGm5DshLJZ0CFYfmUqf5zzQjQ=;
        b=B2NE6pDVn7sOEefvgCAWu9eP5HR/N8BHTaZguAaRR9MX6bVQYTvrvp8GkVg9HbzhBq
         Rze0EwBG1edWWCtOtTK/gDWZvdB0boLRhyblDTT8Ihmc8AmMBk96D7G7mM06az9AO4LU
         W+WUsc8Om1Pah2NO+YkLgoawmZKVhlqO3NaoN3asTxNsY5xTx47K0FJI9xMZyvitqi5K
         vZNxs8nLmsjyOF+8Rrt/gU8mAO3KqaO+tXCvcJrmZq7is23gTm5pd/1F1UeD0phRMMoz
         nb9aUXoMuHuqBsYQZuK8JCcue0vdO360cmBwCv8uGNV3kBan7q58RDMkOVSMT2jKm7eo
         eUqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728878342; x=1729483142;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=pObMglnB96kEp+l3QajGm5DshLJZ0CFYfmUqf5zzQjQ=;
        b=CEW5EUdTTLRkXMs6aAPMKdqeDqz2UnL/UlXRlGQk8WVAz+OFM6CtepWJFeCGqk5iPZ
         kNoU+sdYf093dmZ5m3uYozNvnIlcxOhfi/E5P3486kgdzF9klv30f/8vQ9tlp4UWjcg9
         H+xF24vfyo+k2H/N3qE1vvdufkZPF4gyH9VW7IPtBj00+z6EHmHC8OMPJF+U31sRGNUp
         VBEjiunzaGK+5zk/FnUhCCbbLEDadWVWocdmMky3QSUudw91OvLo34gcShyJkIC5ctI5
         6Ythgf7njGirJ2pIDRNWi7yLpcYQ6AHimVZOxh9Nr2PmQARP6ai0MQvPi65UF6Tn0/nW
         tjqg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU51Y9PR/kJ95tjAe/9uv8RndAaiN3KQLmIgBzNXroKLYuvemzl1WulR09nBUrG5JLfrQkb5Q==@lfdr.de
X-Gm-Message-State: AOJu0YwpLEayeP215lLtBbVuBZ5tK2i+eeqj/GDFTTfE5RUB/SIZp8K+
	saw6J1XaTrRa9jNrQyf6x2p5G7vE0s/WFpLHAnMhuW8YDDaIfXWl
X-Google-Smtp-Source: AGHT+IGah0zY8WTyOmuwEalXaG43zs86AxPUHIUAgzzB+XrZ/wm7M6Qk8/QNfXfuKIgugjGsH1sN6Q==
X-Received: by 2002:a05:6214:3912:b0:6cb:f904:4633 with SMTP id 6a1803df08f44-6cbf9044699mr130618556d6.9.1728878342169;
        Sun, 13 Oct 2024 20:59:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:1d03:b0:6c5:1cfa:1e03 with SMTP id
 6a1803df08f44-6cbe56639cels28952946d6.1.-pod-prod-00-us; Sun, 13 Oct 2024
 20:59:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVzrimkfsZsRzVlK4tZNwHn9jF2va089RcQ7xpudOVbiiVlOB7Lla64HjhDVwSvD6Jqr3UkSpUBhFA=@googlegroups.com
X-Received: by 2002:a05:6122:2508:b0:50d:4bd2:bc9b with SMTP id 71dfb90a1353d-50d4bd2c032mr1355744e0c.0.1728878341454;
        Sun, 13 Oct 2024 20:59:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728878341; cv=none;
        d=google.com; s=arc-20240605;
        b=Tx2B8+2qmDKvWT170slptR0fV9dZug7b7Z15cjKleH046pRb9HYnb5SZkBGB5n9UyH
         OoBy1ch3c534r+3bIKccshZqLU3q+m0cMEb6tGlVFmKkywEhesAahnxHxXs4bdyBMxc0
         to6LgyxvGYLAjT1ngGhfpDqUNLvdzm1XeY3BW3VnVyrR/RwNpkmuc8pcM2VkmAbpKb54
         xsTYC//kb0smR1w0OOu4gnIWnKNJt+M5yZBG5ZpJS3Q/NB50v3Y8UljE7EXn13z2XAT3
         cr5heoV2hVydL9wwyRwSK2scD1yyolwqxZNi0k5BdMANPOQhx7TFGqen2oLIqYoalwj4
         +VuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=kJf0bhlzRwFJdD6ttbRFo0QxETGkwmAfI75yB+TvWTY=;
        fh=W/+Rlbd92klLtgnDZozu+1Zm8L3oNk9WCo5yqUG4SDo=;
        b=li2Elc0CgkAUp38z/6G0MjUcIQ5F19E9Hl4OvJsy5DtFJ0MjyzN3/+D/M6ofBzrq96
         3ds8ZP4jSG0wDuK/qWS/fAjprgEP6hdeqEG5jwmBXzf5dqHGtQjffa3Rlv85+FrCnGqk
         JLR6ff7rlyCIoNiXBxNY00/ol59seNyV7H1IuY95cEBY5xKFWoytdSYmbc3Q6hLi3tN8
         I7P0z08JK1ukHR+HWYLGcN21UxLwed4UCKaeX1oURf2eCms9GiIiQ6B2Tvw/ew0tz1DT
         VQq1eIs9xRpyo1K8HlmvS5GbwZOyZTmqQn9z0F+xcWdsXENSEDTrmyzz1LBDawy5pLuD
         POUg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=maobibo@loongson.cn
Received: from mail.loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id 71dfb90a1353d-50d08a78eacsi563810e0c.5.2024.10.13.20.58.59
        for <kasan-dev@googlegroups.com>;
        Sun, 13 Oct 2024 20:58:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from loongson.cn (unknown [10.2.5.213])
	by gateway (Coremail) with SMTP id _____8CxLOsAlwxncQIaAA--.37528S3;
	Mon, 14 Oct 2024 11:58:56 +0800 (CST)
Received: from localhost.localdomain (unknown [10.2.5.213])
	by front1 (Coremail) with SMTP id qMiowMBxXuT_lgxnc6EoAA--.1717S2;
	Mon, 14 Oct 2024 11:58:56 +0800 (CST)
From: Bibo Mao <maobibo@loongson.cn>
To: Huacai Chen <chenhuacai@kernel.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: David Hildenbrand <david@redhat.com>,
	Barry Song <baohua@kernel.org>,
	loongarch@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH v2 0/3] LoongArch: Fix vmalloc test issue
Date: Mon, 14 Oct 2024 11:58:52 +0800
Message-Id: <20241014035855.1119220-1-maobibo@loongson.cn>
X-Mailer: git-send-email 2.39.3
MIME-Version: 1.0
X-CM-TRANSID: qMiowMBxXuT_lgxnc6EoAA--.1717S2
X-CM-SenderInfo: xpdruxter6z05rqj20fqof0/
X-Coremail-Antispam: 1Uk129KBjDUn29KB7ZKAUJUUUUU529EdanIXcx71UUUUU7KY7
	ZEXasCq-sGcSsGvfJ3UbIjqfuFe4nvWSU5nxnvy29KBjDU0xBIdaVrnUUvcSsGvfC2Kfnx
	nUUI43ZEXa7xR_UUUUUUUUU==
X-Original-Sender: maobibo@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of maobibo@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=maobibo@loongson.cn
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

On LoongArch 3C5000 Dual-Way machine, there are 32 CPUs and 128G RAM,
there are some errors with run vmalloc test with command like this
  insmod test_vmalloc.ko   nr_threads=32  run_test_mask=0x3af

Here is part of error message and summary test report for failed cases:
 WARNING: CPU: 13 PID: 1457 at mm/vmalloc.c:503 vmap_small_pages_range_noflush+0x388/0x510
 CPU: 13 UID: 0 PID: 1457 Comm: vmalloc_test/15 Not tainted 6.12.0-rc2+ #93

 Trying to vfree() nonexistent vm area (000000004dec9ced)
 WARNING: CPU: 3 PID: 1444 at mm/vmalloc.c:3345 vfree+0x1e8/0x4c8
 CPU: 3 UID: 0 PID: 1444 Comm: vmalloc_test/2

 Trying to vfree() bad address (00000000fc7c9da5)
 WARNING: CPU: 10 PID: 1552 at mm/vmalloc.c:3210 remove_vm_area+0x88/0x98
 CPU: 10 UID: 0 PID: 1552 Comm: kworker/u144:3

Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: random_size_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: random_size_align_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: kvfree_rcu_2_arg_vmalloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: random_size_align_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: fix_size_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: random_size_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: random_size_align_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: random_size_align_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: kvfree_rcu_2_arg_vmalloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: random_size_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: kvfree_rcu_1_arg_vmalloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: fix_size_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000
Summary: long_busy_list_alloc_test passed: 0 failed: 1 repeat: 1 loops: 1000000

The mainly problem is that function set_pte() and pte_free() is not atomic,
since these functions need modify two consecutive pte entries for kernel
space area to assure that both pte entries with PAGE_GLOBAL bit set. And
there is contension problem between them.

With this patchset, vmalloc test case passes to run with command
  insmod test_vmalloc.ko   nr_threads=32  run_test_mask=0x3af

---
  v1 ... v2:
    1. Solve compile warning issue by declaring function
       kernel_pte_init() in header file include/linux/mm.h
    2. Add kernel_pte_init() in function zero_pmd_populate() called by
       file mm/kasan/init.c
    3. Merge the first two patches into one since both these two patches
       set pte entry with PAGE_GLOBAL in different modules
    4. Remove amotic operation with pte_clear(), using generic read and
       clear operation, vmalloc test pass to run also
    5. refresh some comments description
---
Bibo Mao (3):
  LoongArch: Set initial pte entry with PAGE_GLOBAL for kernel space
  LoongArch: Add barrier between set_pte and memory access
  LoongArch: Remove pte buddy set with set_pte and pte_clear function

 arch/loongarch/include/asm/cacheflush.h | 14 +++++++++-
 arch/loongarch/include/asm/pgalloc.h    | 13 +++++++++
 arch/loongarch/include/asm/pgtable.h    | 36 +++++--------------------
 arch/loongarch/mm/init.c                |  4 ++-
 arch/loongarch/mm/kasan_init.c          |  4 ++-
 arch/loongarch/mm/pgtable.c             | 22 +++++++++++++++
 include/linux/mm.h                      |  1 +
 mm/kasan/init.c                         |  8 +++++-
 mm/sparse-vmemmap.c                     |  5 ++++
 9 files changed, 73 insertions(+), 34 deletions(-)


base-commit: 6485cf5ea253d40d507cd71253c9568c5470cd27
-- 
2.39.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241014035855.1119220-1-maobibo%40loongson.cn.
