Return-Path: <kasan-dev+bncBDX4HWEMTEBRBO4D62AAMGQE5IQOJQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa38.google.com (mail-vk1-xa38.google.com [IPv6:2607:f8b0:4864:20::a38])
	by mail.lfdr.de (Postfix) with ESMTPS id 2EBF1310EBD
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:34:52 +0100 (CET)
Received: by mail-vk1-xa38.google.com with SMTP id n14sf1764790vkq.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:34:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546491; cv=pass;
        d=google.com; s=arc-20160816;
        b=C2yhImsxXPOYvdBRAmdhvMEBLnR6C5kAnGp9r6EVKxLiT5T50yq73f6KpabHgWjjXI
         c4xIML2jPNK4S58VQrz6+gnvIbcj6GkJOvQDd9ptEZ0d4AUB8b6fp2pYe8/PchL4DFid
         wjI6dz1DpskUKXwI94ffN7QgAs8IhJ7/8PKssxkWa3588dpT64m4cOubgpxjtEFzKHQS
         FhKJETMZe4XEDnFXY+T5VrkmFcEXdywzbOwglhGlmD2g5O6zTl1Y9G8dLz4cUW8atvoM
         I61bZkuNHn9P0C7TNwhA/Kp4MMM1dfR2KUbUUdVbdu9dAqXfhUBh4Vut6tA5fYzE3N9F
         aQEQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=7av35d950uUGiXEZxvwPW/qyTELacR4K15W6joJM30k=;
        b=YEYDHSE33tMcn974df5h6Law8v3TiUnc8Krl38E/xFR1hF9OTKXEwEnQbkUKN/RFrN
         RbAaOG85M+XqElJkiQfp81MzTNgJVzsiLCtSujAcwPg90px1e5GiC7Q/9o5Bwd15OuJb
         LKT+wReqQ4q+ghjGJU6JgrLNd0eE/U2oo2Oe0reqrpo3pIqsXpE+Fwehpfq1xhutmHsY
         xgmISixaTkKLs43CqW0Nq3v2zgtOmJBIKU/N96FEfW6+8RtDHdKENxI0A+5iPRzEvN7e
         6sURsulXKlevWvA3KRgRV0pzYz88XdfXKb97thg51pQoWZkShBmTbQQBpt8teoRGPxW3
         wxHA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gREtjvrN;
       spf=pass (google.com: domain of 3uoedyaokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3uoEdYAoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7av35d950uUGiXEZxvwPW/qyTELacR4K15W6joJM30k=;
        b=YYSD0ntXnIILDEj1vwRIULuzqCWv/pjchKLIqnH2DWJPcl42SQ3okk3VLzbwesKipf
         lbIpYK+nXo4b23y7J/X8cNpbULq2FKppvTW/BYMESXSA3Xl+v4cWGAoSV6TzWzW4auLX
         yMJMbZRvguti6SRr72Hnnyqrp4k2rkox3CSz9RYuB9uHzhz0skKn518x18LOhK1LoinK
         Kap1XyRqjCjovdfzBS0mE0YZy5ODQPcc5STYQJ5xzaJtPxMwWZ6ftXg+qGlN03fBB/Oc
         FDVyE8Fbu+mmhkgprFh8S32vXRZVrfBx8gRNUs6GHHG1S7i+fnJ2Jzj+uyqSb0weBHRa
         DNeQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7av35d950uUGiXEZxvwPW/qyTELacR4K15W6joJM30k=;
        b=nStJffDbrMRYsFnLKRtEZcol3kDnxbbEGJ+LcEVoyOtIAumeQB9KFrVILoCVSn3p0t
         5rtSvF845W2PzPFyIN4Tc14k9WhOqRvePjjJ6vu0UeiOkjXlDes7S4Diq+mFI1InLwb4
         hBrRQ/YMzz138Ek6fj/NzqyQv++kGXEowHT07xzPLY2qKOiFVV0v4hvJYEMzY+4/facY
         Rat9dPFbwWPoieBF4KIIrP4tMgkl1X5LmVpKmAo6m/fgUatkv2+Ffj55GxKVIlIMqF35
         8tUb80jD4IaJuPeI1L2+f9nH1efIYPOiFPykTqvgEwKPaESeIoGpAoD2cLGoLMhFHF1s
         qOew==
X-Gm-Message-State: AOAM532s1XjO1GvNoFaBsFX8wfd3Hll8ncJKn63qX061FNQC6F0Bc8D6
	68Oyg5Y6blaM/rnx00L+jGE=
X-Google-Smtp-Source: ABdhPJzkOiotRBzjciMNjPfBhnzrApxmOr3rPK4v6ZBnWrCgB736+rP12g2u9Tx9b9Sk+Rgf+RE9EQ==
X-Received: by 2002:a67:808a:: with SMTP id b132mr3917773vsd.8.1612546491262;
        Fri, 05 Feb 2021 09:34:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:67c6:: with SMTP id w6ls805711uar.3.gmail; Fri, 05 Feb
 2021 09:34:50 -0800 (PST)
X-Received: by 2002:ab0:2142:: with SMTP id t2mr3847762ual.102.1612546490692;
        Fri, 05 Feb 2021 09:34:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546490; cv=none;
        d=google.com; s=arc-20160816;
        b=ESVWxo+Tsz0F623/gbiw4dqLoIS6Wc9fuaFaDJeEdg2zt0K+uzCAe152jLhRaqjILZ
         p/OCbalhChzcYc9O7gy2aLGg4Lb51bIa0KsxgvLDnbN05FJ3y2dHW4jrAwC3LkOc0wMp
         3Mjz/hsPrj/3ETyfUpOUzht4cTzw7Ws/GcklNZ5OrMXHB7Xky8t7hAkRW8O17TqXkqUH
         rbBSJcDREfeQRE6Uy9L88h2/SMDjJneAszJdtZlU6OsyiXZw/BkFhmPyNNYIgkKvuYPq
         hTSL2GEmSBKdsR6YzDg4Ou56gFhgVxuDnGVtAbzgPiIfKOuYiE1lV6uB8AAXUjkcmSy3
         eZEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=uW4XwdDsDqPZKdJsjSNV/lvgiACDWFIJBYlg/yy/ua8=;
        b=wu9kxZylA+M+5Cn1wwxiRsu5Ws2YmsCt6n1bYrQEYR/Sai2hMpvKT8Zx+TBEQbEXUl
         SieYupVpES/KRekNh4hdxMqKnW9pJY/TuXopIArsYge7b7s2K+g30/pL3Rv1lgRYnZr5
         niVW/x06Tv2pwzG0Ta0YoTyfZ39zMr5nbKZ8JaoUq+V7szwgUKv/6WcjnPYOahgSNoQa
         GpKp5pOFrluATNKhaKo6jjQg9eeUd17Z9xftdP0b/ANZCSqvOwt5mW+KohsOByyMHuWi
         SeVkMgWwARA59FPA65cse12zv2kOpZNEisaOp/ZlEi6WLWnDs6evpHCBch9OJgP9aSYg
         Cdfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gREtjvrN;
       spf=pass (google.com: domain of 3uoedyaokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3uoEdYAoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id q1si637980vsn.1.2021.02.05.09.34.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:34:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uoedyaokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id v1so5540005qvb.2
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:34:50 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a0c:9b9e:: with SMTP id
 o30mr5523277qve.62.1612546490248; Fri, 05 Feb 2021 09:34:50 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:34 +0100
Message-Id: <cover.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 00/13] kasan: optimizations and fixes for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gREtjvrN;       spf=pass
 (google.com: domain of 3uoedyaokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3uoEdYAoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This patchset makes the HW_TAGS mode more efficient, mostly by reworking
poisoning approaches and simplifying/inlining some internal helpers.

With this change, the overhead of HW_TAGS annotations excluding setting
and checking memory tags is ~3%. The performance impact caused by tags
will be unknown until we have hardware that supports MTE.

As a side-effect, this patchset speeds up generic KASAN by ~15%.

Changes v2->v3:
- Rebased onto mm.
- Add documentation update patch.

Changes v1->v2:
- Use EXPORT_SYMBOL_GPL() for arm64 symbols.
- Rename kmalloc bool flag argument to is_kmalloc.
- Make empty mte_set_mem_tag_range() return void.
- Fix build warning in 32-bit systems by using unsigned long instead
  of u64 in WARN_ON() checks.
- Minor changes in comments and commit descriptions.
- Use kfence_ksize() before __ksize() to avoid crashes with KFENCE.
- Use inline instead of __always_inline.

Andrey Konovalov (13):
  kasan, mm: don't save alloc stacks twice
  kasan, mm: optimize kmalloc poisoning
  kasan: optimize large kmalloc poisoning
  kasan: clean up setting free info in kasan_slab_free
  kasan: unify large kfree checks
  kasan: rework krealloc tests
  kasan, mm: fail krealloc on freed objects
  kasan, mm: optimize krealloc poisoning
  kasan: ensure poisoning size alignment
  arm64: kasan: simplify and inline MTE functions
  kasan: inline HW_TAGS helper functions
  arm64: kasan: export MTE symbols for KASAN tests
  kasan: clarify that only first bug is reported in HW_TAGS

 Documentation/dev-tools/kasan.rst  |   8 +-
 arch/arm64/include/asm/cache.h     |   1 -
 arch/arm64/include/asm/kasan.h     |   1 +
 arch/arm64/include/asm/mte-def.h   |   2 +
 arch/arm64/include/asm/mte-kasan.h |  65 ++++++++--
 arch/arm64/include/asm/mte.h       |   2 -
 arch/arm64/kernel/mte.c            |  48 +-------
 arch/arm64/lib/mte.S               |  16 ---
 include/linux/kasan.h              |  25 ++--
 lib/test_kasan.c                   | 111 +++++++++++++++--
 mm/kasan/common.c                  | 187 ++++++++++++++++++++---------
 mm/kasan/hw_tags.c                 |   2 +-
 mm/kasan/kasan.h                   |  72 +++++++++--
 mm/kasan/shadow.c                  |  53 ++++----
 mm/slab_common.c                   |  18 ++-
 mm/slub.c                          |   3 +-
 16 files changed, 425 insertions(+), 189 deletions(-)

-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1612546384.git.andreyknvl%40google.com.
