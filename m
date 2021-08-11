Return-Path: <kasan-dev+bncBAABBROG2CEAMGQEGKBUYVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 57C603E989B
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 21:21:42 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id l12-20020a5d6d8c0000b029015488313d96sf1072848wrs.15
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 12:21:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628709702; cv=pass;
        d=google.com; s=arc-20160816;
        b=Dx+G9L5MEdspnBW2BapeaBjiKxicR5bgUYFImJggZWTY7BLChdtoTBiFWwyrIdnN9v
         mQVGrlxbZxdSeQvw5g8HgovbE0TBD8VeW1RzVekNW7bq95TbuO1z/1wuZsAW5840QwFv
         y7CJTfUIMgfqEhJ73Ch+GElp/dGS/nz7TO44jRCZH2fZJEzQp57CGn2xqmxcAq0QGV2s
         NzbN8tFD8QDE2PryJ2Gx4PrQzc0tPwMcbfDYAyjL4n4t8v7tqhes9ZwF+DE0sUm0h8Y8
         eA88YGrDTouqkeWoM4GEAYWjnQ+gBhYPHP6FN0zu0X1QPbgLPuo1gWxLS0UbfNBW8yho
         bL3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=+tyQZta1jk3X3edc3/nayK5/qceebwnYzQjPuejW/JY=;
        b=kSTgQA5VsbusKBhdEBV7prb6yLMkPm+tUwiIeezTOIplsZVNST30B3V0+9Lc5asxY1
         hb1E3FaBZpd95dDfkyd1FhKEhG5VTenEO8rbe8g01IACfsfe8b/lR+R2nv8OuCXGfleu
         O8/GMC8Gy66DrSwemZkHUibxZqjJ9uT4yTbBALlHNjVRlZ7FjgLYc6GkqjhgOJGmyvCK
         Q3b4MuOWqAJtHRms62QmDP+VlF1orTGlD1tlnWItHmb4zLTLFCmhs4uq5GfbVHItHYxI
         +R8vcdrxokr4WOO43r++rLLx9NvKxL1/5rmVmiWLwtj1KO8sUQ2DxdMx/lQErEUwL1T2
         C49Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XglRGggb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+tyQZta1jk3X3edc3/nayK5/qceebwnYzQjPuejW/JY=;
        b=aKZrBLdwseaZqt6uX29CBND3TOLml+q41yVV3nKjJJwp0DH3NgsNh3vtNcvq+7l4Di
         0jkNC/bj4NOmTQunIle+VKO4bW3GAj/kIdGGZPHQodSzLhrh034AR0Wy+bLV95LsuLp/
         WvFmx6iH4Jc7BvK2nnU/N31V8r9mkcXUtloww9EGPOeORDU+F4yAS1gIym2G3EcgzQxD
         7RcHCvK1mecj9kaUIWxGTD203OXJxSYYag2GzkT5KgbqDrGFTzjD9L3HijqLQWkHRQfN
         YuaxqFqXH8YfhYNBNbKChwlAZnszc0kzUCbFTdM0LSejUBdnwjdWfurMpkyiSxOfjUyU
         /ljg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+tyQZta1jk3X3edc3/nayK5/qceebwnYzQjPuejW/JY=;
        b=doFtWZNbRrHHmQ7MYYxk0uZ/52VvgXEKDfLRpzKI5zlmmNk+jFreDE5XpnWAjCHlU3
         72kI7l67uVe0uI8IdmsqGRA0/eFiahMoJi5ZtiiN/3kl09FSeIKBaQIyK2XCQUtIw3oS
         DH7xiK1l4HScRTJMK56D32ItLGpVU16jEdCW/4CRTE9/DvOCxpuP7VF64EnnpHhWK5Da
         TmVZY5aNvQDHT3isMSqbsOKQe1XmX8eMiZKDOfx6OpE7hi6sOt6qOgGvytFtNH9p0ueQ
         SIUDd1oxiGXzKagf2T5PYnruxP8GI2YZPLcSn7LluqfurE2TD1bkzhwrsAWio5BxVURU
         CF1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533wodlBOMTarYMCI8yXgp/O86MJsalw+KrY9l0l0cPxMdXn73UZ
	VGpRezPc2PT41SeC3CJ2e4o=
X-Google-Smtp-Source: ABdhPJwkMxvA/T8pt8cnq1pM11KRJPRjPf36fI5rxVWCxnrBe+9PEH+FRGry+1yyBrSB36g8iHwRSw==
X-Received: by 2002:a05:600c:198f:: with SMTP id t15mr11352810wmq.76.1628709702061;
        Wed, 11 Aug 2021 12:21:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:cb09:: with SMTP id u9ls1603801wmj.1.gmail; Wed, 11 Aug
 2021 12:21:41 -0700 (PDT)
X-Received: by 2002:a1c:26c5:: with SMTP id m188mr11466435wmm.19.1628709701294;
        Wed, 11 Aug 2021 12:21:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628709701; cv=none;
        d=google.com; s=arc-20160816;
        b=IwboeoZT2nrqq6JUpxmGKROR3OT/lE68353/8GFG+enx5eDEmoT2FtpdxLfkkzfWvb
         /Vk41a7T4ump0npkiZb6I1d6UXLFlHQDJGah0JYJggwV8Hlq6NmxTHZSxLkpTaPeRO55
         XnXLK+YodRTJv9PmFhyYMevtgTXbt60O8OK5+yllvUNTrMn3LuHj4HRqALx1wcmsGtdb
         IrSNPJC4QPZyE63nCXmMwQA+cgCBSrFSgZzB/ljPXOiv8JqFG2twz9X0TqXCq6QMkL0K
         6c9V2liAsPIguKyf7vPex7NsrcP8hcreubL0PzFFIRKKRqXhe+OroZnZ4mNU7Dx5K7hJ
         DGGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=lNfCPiEqsvC4j0wratT12NabqkYWU1ro94i4c/TmnC4=;
        b=dtXu3dScSjKIRtZ7wtkm4T7Ey4eikFj9NGRqsgfxZUK4SCuNWWgE8AoKyZLPwoiBsx
         NhrX7Izz8aT4uaig35AfHi/hwKw/AbTgEqd96X5kvo7tqqdYdZ659cCYF7VgG08od8xY
         15xwiiz1+JteygGiim/jakvwsKCq6IoKqHUHlxngEenJ0COCN3xYZ9/CVR6V1x44fwBp
         pib4Iqr+hhITiUrQ2UBBC9Qqt5sRTzdr2zv1bnt4D9HKM9XtN/8dO8OdI0N025i2EL2i
         CP4he65LSyWvCfsHSXtkbjbI1syE5RsNbs/YEcQVknpaRcCyfCnyrXrWcuFU0glnwkyZ
         QVXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XglRGggb;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id x5si8672wrl.1.2021.08.11.12.21.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 11 Aug 2021 12:21:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 0/8] kasan: test: avoid crashing the kernel with HW_TAGS
Date: Wed, 11 Aug 2021 21:21:16 +0200
Message-Id: <cover.1628709663.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XglRGggb;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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

From: Andrey Konovalov <andreyknvl@gmail.com>

KASAN tests do out-of-bounds and use-after-free accesses. Running the
tests works fine for the GENERIC mode, as it uses qurantine and redzones.
But the HW_TAGS mode uses neither, and running the tests might crash
the kernel.

Rework the tests to avoid corrupting kernel memory.

Andrey Konovalov (8):
  kasan: test: rework kmalloc_oob_right
  kasan: test: avoid writing invalid memory
  kasan: test: avoid corrupting memory via memset
  kasan: test: disable kmalloc_memmove_invalid_size for HW_TAGS
  kasan: test: only do kmalloc_uaf_memset for generic mode
  kasan: test: clean up ksize_uaf
  kasan: test: avoid corrupting memory in copy_user_test
  kasan: test: avoid corrupting memory in kasan_rcu_uaf

 lib/test_kasan.c        | 74 ++++++++++++++++++++++++++++-------------
 lib/test_kasan_module.c | 20 +++++------
 2 files changed, 60 insertions(+), 34 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1628709663.git.andreyknvl%40gmail.com.
