Return-Path: <kasan-dev+bncBAABBEVVTKGQMGQELHMJSKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9F49446406A
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 22:41:38 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id p17-20020adff211000000b0017b902a7701sf3842440wro.19
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 13:41:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638308498; cv=pass;
        d=google.com; s=arc-20160816;
        b=PaqrFVUKD/iRmpAYBTAmLhYEzERKcQuzaxlxKDP6VnlZYp2LMIW3NnWO7AIFcPtk2o
         h5Y3Wv9F10T2ALSpdXFYiFjAYu381u/7FoPtgYCHMxXGs14byPcnYcXltr67PmVmY04J
         HoJQSfYDTCx9Uq/EG0JxKSXAGKY2supclKQsaFoFXE0YIDP94TCTG+VzK8+E/DCWJ/Jd
         eTM7/7Vc/fveqJpbxt3GOP0o7I0Ca1z5IyC72ucaGY/smjh95rLt+HinGxIny3ZG3sRf
         jMe1JTYqEl2EVldAksJpu5laEDUNCVjREkyK0arvVizwSRq8YM6u9vO/6f9oOETw4xSK
         l82A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Ny6TdBuLcD0wV9YNULlyRNhV2xZtkxKC5Z15xmK4Y7E=;
        b=CFi0mNYKC0CQZZngDlqDhetwVkuLBzaCrnV5HfENR9pf1zyt3mGny1kWWqfQ+ySABY
         aLd4bgG/t3dyd1Hs18ts0JA/9NxpeNM1X9EtgCa4hi2y7xUFZLWYZe6wvIOEJOVoFOYY
         rh0aNSEpdGZHQBwFStrxgAkYfahnKcopi90zVY+wr2l3Eo7RJ2RZVaSCSio+zaiz0mT7
         Ii+zKuUdPGa3K10aeB59KDcu3060VbpoNaLj97IbO/hl6t9m+w+qrcl/LkKzjhy1J1Sr
         w/yHtPTx4zi3UQC+2XGmrZZQ0qvSspxgIRsV2jKE7BoGy4WwqpzhoC0IksTjgTCSacJD
         brBA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=O1N5ChXO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ny6TdBuLcD0wV9YNULlyRNhV2xZtkxKC5Z15xmK4Y7E=;
        b=Lfs490QD52CVO97pV7hNQIG1Exjc4Fl6dkpHq689x6Dii9sFdMIAbQVwDAK4y5AueO
         MCq7+Pinlm+7SW267q/edZav6qlT1nWzIffy9BubjwrrNKKwmsCHPJ+1JRVwkL2jqpw6
         iGK+U1Pg10nzovPeWFwQOTg8ieS0n+Fe+TuJBwAI8sidluzDDWze2aDLgdmuTauHhD9d
         expNL4s1hLybnRbCpW2XgLbwYV3wa9v71/XvPYcfQuVDpOcaTAR1RZ04woaNcZuVJ1qW
         PaJQfRG8UE1lUZJaOvVuCeanzC/uuEAwFhz6/+h0A4HP4+tWZUlyjL9sW2jF8P9T4p/B
         hEhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ny6TdBuLcD0wV9YNULlyRNhV2xZtkxKC5Z15xmK4Y7E=;
        b=qIcYhkfUk/gPL8JDl8O7K7OS3MhVm3SCIqrw/uaUwvCzzYRoE2kxnwyk40wAcPNjWb
         o3PdmRyoAkTnBj0Kgf6zeR0QEEAU2JI+0p27NhL8Qh9z0VmUmspQ90799cMa0qRkrTLt
         w1vf2o3MUdclluTLHNdTGSjF7IRgu8vipjvMfAIetiLUG1sL9D2YRx8MgR6CBTGZHwUT
         XjtQT2wUeK5l+yFX2HssnQ8asovS+c/XSO8rjVEx0r2ryF864sGWKfhQ1Ccr5AB/HZD3
         gk3TEWffCTbpXNo8QD+fiJ5/kzcXHuLtPZiaO86jqUfeh8CWBg/Zig9vhVqoaa21WBYB
         D7xw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532C5aNvcq8cReuuGlUJe+8RAomMvzePgm0JtNMfw3h+m8qHbwBC
	CaMLYBuj7T6SBm4eKA9mXDY=
X-Google-Smtp-Source: ABdhPJwypnjjBJEfTyW1DhFvUrPAJmCYFf8tOO2czyMfpCRxBxq4l1lnzUOxeYUfqRWiSHf5Zd2T7Q==
X-Received: by 2002:a5d:4fcc:: with SMTP id h12mr1862006wrw.434.1638308498391;
        Tue, 30 Nov 2021 13:41:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1c7:: with SMTP id 190ls2108757wmb.3.canary-gmail; Tue,
 30 Nov 2021 13:41:37 -0800 (PST)
X-Received: by 2002:a05:600c:35d2:: with SMTP id r18mr1613061wmq.166.1638308497758;
        Tue, 30 Nov 2021 13:41:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638308497; cv=none;
        d=google.com; s=arc-20160816;
        b=QM+1QCyDQbijGqZlP7KfoXVHqKUvO24+Qt3AvqmPmWFUIbHPcjtZrnBGUwTs+0v62R
         1CwCZUqmBQcFKAskNlZ+uml1kVm3NzWrvr6g4Hz0eWXep6C7AEnxwsrM4DhJJKBq6Mld
         8ftFOhznziv7V4HjNo0xf7M5PZnLiAFDQ9CVsDI2+HacqId+5dNfy0sZCX2W2TfV62G1
         6eI64NgXs8Q8BZuEAMkwWvKctpYj4EyAi2xhJ2vhNsy/RuQD9EUIJJpNqgsBI/E1I2uI
         6fYU/bwoHdH32oyv3x4WiBwUiBVtK3VRxQrniwhSqBM24GWuPSz2/uOM4t+3BGPmLR8E
         jAqA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=2VlRNVgjD8s3LiQBttrzG+uL14gJGV2zDjLV32J+vek=;
        b=x+VCULUrSNycpNcRuwhIJ0aCidQj7ha3upJSjp8Mo5f7S/euP/gcdDX0yGqY/nAUGt
         BYan0WfP9FvbCpShwan9I8CPXRiNJO4J1tkwmhBHlC+EpJaJlLwgftmMYWQbm28NvmHx
         LhlfvdltFgs95milKhL3h2g/z3ruCro2J/e9/h74AyjDw5umB71mVae2akuh0SzAESNw
         OwVc0srkbAsD9o28If/JqspUJhFJBUs9kj+AFReI0RmzK/d9brMuKvY15hka0hyTA4jy
         Tee85L1T4LZf4Pw5NwA+KRSqkV6qp3hssi5BN1COGUcV8qCzXtTf6KFwCX2+DW0Hs3hL
         Cjag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=O1N5ChXO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id z64si494929wmc.0.2021.11.30.13.41.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 13:41:37 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH 06/31] mm: clarify __GFP_ZEROTAGS comment
Date: Tue, 30 Nov 2021 22:41:28 +0100
Message-Id: <4f6d3dd6f1ab9d7774c96ca0ad6d8cabebf0914b.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=O1N5ChXO;       spf=pass
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

From: Andrey Konovalov <andreyknvl@google.com>

__GFP_ZEROTAGS is intended as an optimization: if memory is zeroed during
allocation, it's possible to set memory tags at the same time with little
performance impact.

Clarify this intention of __GFP_ZEROTAGS in the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index b976c4177299..dddd7597689f 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -232,8 +232,8 @@ struct vm_area_struct;
  *
  * %__GFP_ZERO returns a zeroed page on success.
  *
- * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
- * __GFP_ZERO is set.
+ * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
+ * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
  *
  * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
  * on deallocation. Typically used for userspace pages. Currently only has an
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4f6d3dd6f1ab9d7774c96ca0ad6d8cabebf0914b.1638308023.git.andreyknvl%40google.com.
