Return-Path: <kasan-dev+bncBAABBAHM2SEAMGQEZFS5NBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F6173EA6DD
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 16:53:53 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id d16-20020ac25ed00000b02903c66605a591sf1931328lfq.15
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Aug 2021 07:53:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628780033; cv=pass;
        d=google.com; s=arc-20160816;
        b=BYupE4yLgnOisg3uQPW05cBd0pCNkqBUNFvEGYP/MA41XqeWiTdam24tVUilgUDg5C
         h+z1MIZRD+eko8vfgYx1AaE/GPPRS2UmXNNo6OvgmPE4EMspOYJwS+Y3ScHm0SYJS+kh
         HI+nfJT55HKfcqpZ2UpUgxukNxGWw2gBZmESfbMebuHKuYpi+wX/lyTL4j3LhITwFom6
         0MPd1uzMqBdWPMGheGUcHGVgqfSiRQ6f0zTAe91Av7ZHbjf6dk25aj4W1IgcFG0yq2yz
         8L/bkGX0wEPzB9qbrUt6mlPRarRO3CheYzxHby9FeFWhjOYYoekAS/bQq5aD2OliB/Ua
         2rlQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=6wyRi3B7PsBWHF46y4yF0CUCDW9QaIxZaI7fMCmyq2Q=;
        b=t2uVGca+6kFi2OjjU7ALWdjxiDYb+JCTAQnep+2lT7jLGDqzbTI0e7/eymD6AcF8Cq
         m5FGWuB2vNd0NmjVP3FV3N++DOi03X2utF1URkYfVHmpvUKbq36KyrGloIjoHnJQtubf
         f7pA7Rax3cdAdcJccRC01WQgcu3IxEcXJYZYAjHVPTOMZP1wJ4ILZvG2RQ2gZFth9Q5H
         fhSSA7o3UQoblkFiDYdo1HE49IaxR66DM3LDFSmzpMRDptcA/iemlfXmywf+vZ+Q60gz
         pxuuwvRD3egl77WMWoQLeK2CCZuQA7lWH8FoucWmnuBH9S1APxy8d0xfUuDySL4rTNtH
         AicQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="olo/lvSA";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6wyRi3B7PsBWHF46y4yF0CUCDW9QaIxZaI7fMCmyq2Q=;
        b=bbfWHtv5rqZoQ/9YvR2ThxLm/JOZZB0rPjdk/XKqHpSN75Tg3mxo13zqZ7q36xO8b1
         BCWuI4Dq9bAYkxVof0WgUq484DD58vwDL0UQau0dGkToWKYC84uF6IRdhOGCMOKsOJFz
         gIZD5vq2WVqLBdQYXRnhEFMeL8RsTWvMp+zOkBKZ10QRm6AjJ/xIXHu0wrWfZS+vFgZz
         n/CanUvgh2CvqGxlNlHpcR5z56C5xyzA22wotThqM6N6peqyT+LaahJWqPJ8koo2k5/z
         FKd9ZJUMorv+VBiumuRXFzYuHgj4HR+aG7X3gsfWorE+D4hzBOHhThvqrfHatLFen+rE
         89sA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=6wyRi3B7PsBWHF46y4yF0CUCDW9QaIxZaI7fMCmyq2Q=;
        b=NBSNfrcxC58Jqp+DY7uKYww20IW1ytbUBbIo6KclvpSinO4Fg2gc3M42PlmwSDMr03
         KykK0qkp7KkCzUgY8sIKOITrkbj++2oUtEnd1d8RrKXM6It9ZuXK4kV+64jRHeRiwCK+
         ZQNnpMqqT8PyFBDzPimngmNJZ3/n+NJD6x8DYPHW6QO8Wtm++gQqOqkbZm5lKl4jbKCs
         YYFVSv1nWS5MASnbt3aEAKJxv3QE/9EgxTUBWqQWyNB/Mi0nWjMXGzHO0MSqIpvxlhVu
         /m2rvuMb5HfiEDwhp7icMbKcInSU0UnfhRkX0SkVkvHV03xV4QwdJ5oX/S8SLodU16dd
         i+wQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GWi5ZcvXMi2A2nW6UwPS9zva+J7UUuASuqKNKZltqa5keRHSY
	tf5PMLvQjvoMvcg/A9DBmJc=
X-Google-Smtp-Source: ABdhPJxHMDs98KwENEg8qtDgcXN1gtfaHLxJA2O0YR3rpDkul8zFQk44ATP34nzVX3MI6E7DIIPA6Q==
X-Received: by 2002:a05:651c:1190:: with SMTP id w16mr3218897ljo.179.1628780033034;
        Thu, 12 Aug 2021 07:53:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:691e:: with SMTP id e30ls726522lfc.0.gmail; Thu, 12 Aug
 2021 07:53:52 -0700 (PDT)
X-Received: by 2002:a19:6510:: with SMTP id z16mr2680160lfb.566.1628780032194;
        Thu, 12 Aug 2021 07:53:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628780032; cv=none;
        d=google.com; s=arc-20160816;
        b=wRUnzPDNyVMlZlh8fL6+lCYFRNLUaZCag7bermdrn3wHgdnShP90JCtm96DosT++m4
         IB/MwZARBvONWm0tL/onT3Q+Id/RoMhWyzoSgfgk6QK6hsISwDlwFyV2A3uwGh29CWm0
         vINCdqxDSmvId4ZnaaNoEevGOlwyJTjReGgpMI0VgHaU0G2EowKx/Inyvk5BTGYAg8jt
         XZoVUBkpO5cxkbpT31/f/GerScZ2GkIJxAnyjivVMbnE9lZiIYlI4xybNYTYP4tPlwep
         bFWiprmu3tLaVrbYM2r5W1RNY6dz3hv97Vq4tJi9fJ5CuM2ZORw86GP0hXOnMzK07unC
         GcHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=y4INfxuNvGKmJ7fA8mFpegB4/XD7G/W0BELDU6wu598=;
        b=Uwa4wpnaP7z7/FmUlRZaMu5jyP7J5ecmLzRSrBNTY42AXgSZS8TU87uMu2hgj8LPu/
         AsZiTBx2ebNFLtYb4sywYadPhVbwEjYzFjWLiNNRbriGxhyo5C83W3AzlJLg/nycoTaE
         BALPkgPGlPn3J2fylE8NU/Pyz69TUviWAuy3Y8rKiOVuNadPsf5Mbo98FFKA01HcvSs4
         f8epDP4HcVGCoqnkrUWE5NeCCwac+zAqMfu8l2s7qmT+VIyYbHYXiBU++vvuSTBk/n7m
         zXj7pWGaJk3mubstgJpZXK0PFdFbtlpjvdPHoZF31O+NEAMFLgO4S+W2sypfVk9NdDnS
         1g+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="olo/lvSA";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id g15si127106lfu.1.2021.08.12.07.53.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 12 Aug 2021 07:53:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH v2 0/8] kasan: test: avoid crashing the kernel with HW_TAGS
Date: Thu, 12 Aug 2021 16:53:27 +0200
Message-Id: <cover.1628779805.git.andreyknvl@gmail.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="olo/lvSA";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
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

From: Andrey Konovalov <andreyknvl@gmail.com>

KASAN tests do out-of-bounds and use-after-free accesses. Running the
tests works fine for the GENERIC mode, as it uses qurantine and redzones.
But the HW_TAGS mode uses neither, and running the tests might crash
the kernel.

Rework the tests to avoid corrupting kernel memory.

Changes v1->v2:
- Touch both good and bad memory in memset tests as suggested by Marco.

Andrey Konovalov (8):
  kasan: test: rework kmalloc_oob_right
  kasan: test: avoid writing invalid memory
  kasan: test: avoid corrupting memory via memset
  kasan: test: disable kmalloc_memmove_invalid_size for HW_TAGS
  kasan: test: only do kmalloc_uaf_memset for generic mode
  kasan: test: clean up ksize_uaf
  kasan: test: avoid corrupting memory in copy_user_test
  kasan: test: avoid corrupting memory in kasan_rcu_uaf

 lib/test_kasan.c        | 80 +++++++++++++++++++++++++++++------------
 lib/test_kasan_module.c | 20 +++++------
 2 files changed, 66 insertions(+), 34 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1628779805.git.andreyknvl%40gmail.com.
