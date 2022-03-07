Return-Path: <kasan-dev+bncBAABBGHQS2IQMGQEMVVQ4KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id BBC9C4CF2D4
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Mar 2022 08:45:30 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id p15-20020a17090a748f00b001bf3ba2ae95sf1386597pjk.9
        for <lists+kasan-dev@lfdr.de>; Sun, 06 Mar 2022 23:45:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1646639129; cv=pass;
        d=google.com; s=arc-20160816;
        b=ISot+VRvgKWpX3IEOcDEOjHBG+2z3jJ/M9xMtCqRJZMv7eotGeRdCfcDgQm3iMfkRO
         3XvBuJntB5edFk7VegDFI5iDe8Dr8Q29D2Ee66EfewcIa/Tu55JTUH5JnSgxGlhY3PSJ
         EPjd70bmsWABSVX9B2DLQxia1iOby1UQRi44LbKbyhZr3FgG3BJWCpfFUwfK5U3YdJEZ
         cIcXf1I9d+OWKFXMAP7Hs4W1zXI8vYkL8aDQmvDMFjPDHTAoHnQdXYhI1VKcXMh7mypb
         H/nyw6ycbf906cUOvavUwNJre89WaG/AVYlhRS7CBHwOMsN+18uThocZ9HU8OhVAt8eM
         nt0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=jxBvlwuwrqBmY8Y1Lfw/2KiC4G23cyFjrN9i/XD7+aI=;
        b=T/p6hyk1x9azMHtEd5vuZYibYIRq+n/1qyTxwKKI+A3IxcEkb2w5bVuJWpY/bsnm0V
         l6iQ3CeqO7vwfzuiAxzKd/oE4Nf/jy2ENM+zniN3MCtM+E/p26svQgnPSqdie0vefOZh
         tO57uFq4nCJM9+BmLHjYUXr/qzF0mkP6whRvnU5dlUkLBRdorfUQLAqFFH3+/hynuJ6z
         85Anlye5rFK+48rH0ZjKcEBuVqqfhMFhcPfY+Gp4WfYPrsqXmLywsLYgOeKVFLDHc6y+
         0nw4Dt3ssjGcSdseT9EArqQGIAmkOuUqH73z11foGrm6f9RWjjvWJ3mj17xX36+7RAQV
         cHxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.57 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jxBvlwuwrqBmY8Y1Lfw/2KiC4G23cyFjrN9i/XD7+aI=;
        b=TKQyrnY4JV9J8zIqyEqUrbmtqXw59sW+J9xO30z9TFnudW5FNWtMTRRn5C7VSnOY7q
         LcuvED01Cj6IeM6m6n0DKEU30nZm8JR7mwrCixVNm5xp6zzHlJ2WNf72bm5km/E5RogH
         nfjhObiZWXTDsiOfehw15PGdxmkr289st28LEQOK8xEHO1/tGOU7h4vJV85kT+kvTfPJ
         4SdvyFt+PUtixwrTjCVpfvP5TXfZMXWx106+ixM/ye0Gp31BUspcNiguHdobFesv7x4b
         CF1eGn1Astb6oLw3ovi1tcDXKVkvCFQaC+4NuD6OZ/wFjJNhxgBY6cQ1HkaLdmWdKDE0
         zWYw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=jxBvlwuwrqBmY8Y1Lfw/2KiC4G23cyFjrN9i/XD7+aI=;
        b=tKQYA2QU5PYdh8JzAMQ/OtXYVxrBi98qoKqmtDcjWli8L0f0Z4utUfePxFXnMonnQj
         bFrW3VdyOtkOLfzKoorFi0onQPonI6nF3sMngrHKBE7VTWkU9euQtkpDpsagYjvykS52
         oj12j1xOWz2795nHN0xdY11Lg6lBzRGzIJ/UiCSme7cx0Pjd/3l7wuKg7qHZYwmc11Ro
         J//QbnRJ32EK4M9VAeQlWzI/1mk8t5O0gogVwIU0ZtzXBJa0RRh8cmYpkL9PM+++W01U
         oUnRlcM3qFJHw9S7Geawv8uIvT+VC/ev41wI2BJxKOwwLGEw01Wmo0JO/3Pe7Rz82GfL
         r04A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531d8iA80PAUTsL+/DCGlpWmqLZRBdW1c5fVsRN3FARtloAvZijo
	SzXdlikGOSRFbMfqyNpfh+M=
X-Google-Smtp-Source: ABdhPJw9UCkJOhzy2GNFczWUGOqXE1p3GXLAu7BL7/bPxloK3rk9qfyNar2Jw/3IZmarYNkac/UKMQ==
X-Received: by 2002:a17:902:ea09:b0:151:f547:653e with SMTP id s9-20020a170902ea0900b00151f547653emr443023plg.24.1646639128879;
        Sun, 06 Mar 2022 23:45:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:c08:0:b0:380:5d90:d260 with SMTP id b8-20020a630c08000000b003805d90d260ls677570pgl.3.gmail;
 Sun, 06 Mar 2022 23:45:28 -0800 (PST)
X-Received: by 2002:a63:3c10:0:b0:380:37f0:7067 with SMTP id j16-20020a633c10000000b0038037f07067mr3934965pga.254.1646639128301;
        Sun, 06 Mar 2022 23:45:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1646639128; cv=none;
        d=google.com; s=arc-20160816;
        b=TX3ApEboETlWKy/YUi4iJ7eScROjVSPcYXV7/L085eSQcoRsvoXKqWeRKJngf/uWtw
         KCFkFtkXb9rF299pCb/9HXcqeO8T2bMs+rtW3qCJAB9wXyPio0kh8qCSbqyPzDWvRlGK
         7v2kVpj9/SFzl79LxPEyJRHwF/kDcT4zEHEAh9kX4EdRap1PWeCAGBDUrI90O/m0ai3g
         UQC0q6fPe7JKxLAYbWfDE1AXvLUGd15qpYmZkI8XdmdxhxIlr3B913iRG8y5BZlU/GfE
         AcW6d6iu1yPMkHlyQOXBgYUBFUk7Cqi+6AdNY/kbmeXeRn62jp6fzLvql52LrK5d1f9L
         /fVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=a/dfgBQDQmkAUJTdz/ItD/Y770sABdRQ4HBGyPTkbWg=;
        b=hZHN0CwZItCISvR10nBMhIrNJRkiDEBnVI92O4QIvxy2KYy5c4q/LWmJrJp8xQXXgH
         mKEQupO+jI5idW8u+Se2cLreIpwS78xBDE5HCX3VB9TcdLs07z8GDOkwH2y10kZpKwVx
         HqwzyTlnO/jiCmKi2ASjTOulPWErsBqH9bZU6yNMfpIhvpfKlooVHt6BHi5pTegiyhZc
         rm736MVmReu+7GQZOHXOZZQpRQ646CRODH5idC4gNbGPvva9JK4plMFUoubefvIn6T5j
         Y1Y1sca8cg+SvFuKgvNSNrDXE/Gxe7QxNElt9v8kApthI9A/yqAujyfMC8A8nUNvxFn3
         xu9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.57 as permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
Received: from out30-57.freemail.mail.aliyun.com (out30-57.freemail.mail.aliyun.com. [115.124.30.57])
        by gmr-mx.google.com with ESMTPS id hg2-20020a17090b300200b001bedb198e40si881121pjb.2.2022.03.06.23.45.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 06 Mar 2022 23:45:28 -0800 (PST)
Received-SPF: pass (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.57 as permitted sender) client-ip=115.124.30.57;
X-Alimail-AntiSpam: AC=PASS;BC=-1|-1;BR=01201311R191e4;CH=green;DM=||false|;DS=||;FP=0|-1|-1|-1|0|-1|-1|-1;HT=e01e04400;MF=dtcccc@linux.alibaba.com;NM=1;PH=DS;RN=7;SR=0;TI=SMTPD_---0V6SREaW_1646639116;
Received: from localhost.localdomain(mailfrom:dtcccc@linux.alibaba.com fp:SMTPD_---0V6SREaW_1646639116)
          by smtp.aliyun-inc.com(127.0.0.1);
          Mon, 07 Mar 2022 15:45:25 +0800
From: Tianchen Ding <dtcccc@linux.alibaba.com>
To: Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v3 0/2] provide the flexibility to enable KFENCE
Date: Mon,  7 Mar 2022 15:45:14 +0800
Message-Id: <20220307074516.6920-1-dtcccc@linux.alibaba.com>
X-Mailer: git-send-email 2.27.0
MIME-Version: 1.0
X-Original-Sender: dtcccc@linux.alibaba.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of dtcccc@linux.alibaba.com designates 115.124.30.57 as
 permitted sender) smtp.mailfrom=dtcccc@linux.alibaba.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=alibaba.com
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

This is v3 for (re-)enabling KFENCE.

If CONFIG_CONTIG_ALLOC is not supported, we fallback to try
alloc_pages_exact(). Allocating pages in this way has limits about
MAX_ORDER (default 11). So we will not support allocating kfence pool
after system startup with a large KFENCE_NUM_OBJECTS.

When handling failures in kfence_init_pool_late(), we pair
free_pages_exact() to alloc_pages_exact() for compatibility
consideration, though it actually does the same as free_contig_range().

v3:
Use alloc_pages_exact() instead of alloc_contig_pages()
if CONFIG_CONTIG_ALLOC is not defined.

v2: https://lore.kernel.org/all/20220305144858.17040-1-dtcccc@linux.alibaba.com/
Take KFENCE_WARN_ON() into account. Do not allow re-enabling KFENCE
if it once disabled by warn.
Modify func names and comments.

RFC/v1: https://lore.kernel.org/all/20220303031505.28495-1-dtcccc@linux.alibaba.com/

Tianchen Ding (2):
  kfence: Allow re-enabling KFENCE after system startup
  kfence: Alloc kfence_pool after system startup

 mm/kfence/core.c | 126 +++++++++++++++++++++++++++++++++++++++--------
 1 file changed, 105 insertions(+), 21 deletions(-)

-- 
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220307074516.6920-1-dtcccc%40linux.alibaba.com.
