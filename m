Return-Path: <kasan-dev+bncBDX4HWEMTEBRBH547T7QKGQEYZ6AG5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa39.google.com (mail-vk1-xa39.google.com [IPv6:2607:f8b0:4864:20::a39])
	by mail.lfdr.de (Postfix) with ESMTPS id B871F2F4FBB
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:21:52 +0100 (CET)
Received: by mail-vk1-xa39.google.com with SMTP id p184sf1139699vkd.18
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:21:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554911; cv=pass;
        d=google.com; s=arc-20160816;
        b=bKpjS1vlsiYmYTWYa8J5YXN9wwNzsx5l6hM+QqPPL2jPzcF7yOw/ZaGZ3piUQqNdYP
         CQ5WXom+avBxEbEdy9iKNr1IytPpfbJHCSQNscVIX6t+2+1V6VPInIMfs5Zw37CfGIlf
         w73GzVY7XU/H00R9rcSlhls7gjaxtuODYQjxRQ8U0wkgRtlIV5ReNuwFeiw7vB8sfF1w
         VFyZ0JeGQq4u3QUs9gdbn621x3fH4VwtXnqekNS5kDwxmfa6rjGdunq9vNCqahqvszV2
         73hz9zmoZQ/fX9vc5x7jLOEWShy488S5FLAw5BJCRVd1WI8X2ZqO69Hlfbnn8R3Ul2j4
         HAAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=PIVqBYs6A4JTrB113Jgccurxkw5kS3CAQ+gVtqT2bDA=;
        b=rsEArjvdXxiWrWrAKQ/mcrlI3x8jROgUt/J/c7ZPIErqFjtjpC84jioFoFCZKBE5oR
         m/tlPOtFHX3Wi5VoFymOUAByWU7rXnMNtR6DRAeASQB1A/4bcI5edPP7QgFWQvNpyRG+
         /yL/ehzC3WMzi+hbQ2pF6Sh0d5OxktISFeLZ123nAAylDQAF4V6CQ2rlsst8TsW5Fwt+
         zYrVzbe82hGXOlSwW4LVV6DprdjrXYV4emEoHGSK+HfzBgvo151hwivPjdCUUVbL+2cC
         hUK8lzu4UeM+st07dRCMDvAZfnNTFMStuqlQC7lmSov70rNH6sGeF2Tz9IRFVLBwXh8Z
         n+jg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YKY7gx5S;
       spf=pass (google.com: domain of 3hh7_xwokcv05i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Hh7_XwoKCV05I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PIVqBYs6A4JTrB113Jgccurxkw5kS3CAQ+gVtqT2bDA=;
        b=PoF2AHNQBhLTQhr9SufP7BmlfOplx2Hc6gJxESDXM7g1sqi6A/iDSL9HMpwvCGfmqo
         XjQH++8fLvWn/SD0OOrXJm9yV7YowvaS9JwSCDtwt8E6dTwWXOm/NBVgAiA+YwboAjLN
         GEnaPX7NCpjhMqas9SQ2linUbLBjpjs4PlAqfVq8CbiyTiU+M6v5sludMKUhkeA5DrCc
         vyGR+t1Vt6e4UD9prducvCl7n3Ihz71sXY8O+GI+UX1n1RFB8ui2Q5WCTQ5/miATRDip
         TP+X8g+MUcpYuadkVO5QcpFDjuCZaQzev5aG9Di1y9rXC8iLJqq8y5c7fiF/n1rqjacS
         PRIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PIVqBYs6A4JTrB113Jgccurxkw5kS3CAQ+gVtqT2bDA=;
        b=d44ianMhzkr2/tv31cB+vNv2lmltEnIcslnkhUdkFi6DB6HxOFSXlYFcf4kQSxjDO5
         Ak2YWSR7otzOW7H8zDbsDR+ciu7SRguGQWq9qbPQ6WjzGFadlC9w98BHwWG7iTUq+sgY
         Fi9H1tGPzyqSFqeWaeVZGsa22fzQlOpp3Kn3uUYBbIP27Nzc6ZXM6n2H+n3olLAVBBV9
         n4DH7dcJqvcYa8RDbT61H9m1xQo6Hy+DtEekL+SRKiVCrbRtOHNTGS/eWwLXuzqVPY/c
         Iz50CB2iYYa/LiYupC+uTxTuvWNxFBrusgG6oB9wSBEqWaxNqLxUbXM2WJZklGlOBrjh
         dI+g==
X-Gm-Message-State: AOAM532RLEfIzXEQn4AsFVmYS+KCNasXKeVJtPVkuYGrjZNOGQKOjldQ
	EFfLwqTnxAedWaXxUrz8tQw=
X-Google-Smtp-Source: ABdhPJzCsIHoAtYww/DX6xPwXq/y2EjpHqZViaqwm/xnBC2XiG2K2UZzecmpj0IpD5JSf1j5ESz61g==
X-Received: by 2002:a05:6122:12bb:: with SMTP id j27mr3047088vkp.18.1610554911836;
        Wed, 13 Jan 2021 08:21:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:2645:: with SMTP id m66ls315559vsm.3.gmail; Wed, 13 Jan
 2021 08:21:51 -0800 (PST)
X-Received: by 2002:a67:e3d4:: with SMTP id k20mr2687820vsm.25.1610554911287;
        Wed, 13 Jan 2021 08:21:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554911; cv=none;
        d=google.com; s=arc-20160816;
        b=NS25C9eSxevZfBoo6/xJ765eyVc/glTJKPM+2wmWXjid8ZcLyecu2mvSDju9/mpSZt
         zunFKTrZvlHK1Xw7iNwGf1z/zKnL8OCG9qsH69fzFVbM5/I2OZvTrdmJrzdeSKq/hYvx
         MB5XlSBCoZK/CD6YXARM8j3ahg/jkZnRwrm8/anVB6dR/6O+kiMJdKhmdDUT8ltjLeip
         AUfKfQ+zQqz6k3JAG8sVbLLgife6rj/iVuUquibb6WHLYZ9P26/nImhiW+s3rHwU3RR7
         aiIX1nmTBi/y8mfHU2p6SMhAX8ae6AtV6nsgPivYGOAWPv4mCO5w8LU3shjFoeW4a8ru
         7TUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=d+lRqXXla6mV/kMKnUzgl/DAB69C3QZUVHCf/SWSD4s=;
        b=mkOLKp5fEK2LH60LY0U6N+9SUsjSQQd+1sWAMJMReGEwk6/BDezvd6hPjYJ4AIAHMp
         etzl/EqrdP7FJPb+nFgZqpoz8se3SbOAwCkX/5FKY1T+CVUEOa/kh9MGZcDe6MBqhqWS
         EuAdScj+tQWzM4bUAao212OgmN37y6ppqdNy6gN+VSx3+c7afcoZMZmm8oeBwOK0aEt1
         +Wz/sZX1Ok+RTLOgHxRQWV1Y/E1ufdki9V2SVPRNwE9k7u8IRjmcPay3s6yZAjU+Elf3
         qnjiVFTK2ClLaTh9ooDii9T3kC0gcYPlnxD8RnmwyryAk8E+3iXsMDWqrCnc4/9xxAaV
         2MLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YKY7gx5S;
       spf=pass (google.com: domain of 3hh7_xwokcv05i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Hh7_XwoKCV05I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id y127si141579vsc.0.2021.01.13.08.21.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:21:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3hh7_xwokcv05i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id t18so1831661qva.6
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:21:51 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4870:: with SMTP id
 u16mr3018876qvy.44.1610554910673; Wed, 13 Jan 2021 08:21:50 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:29 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <1d82c593424e75ce15554a77e64794a75f8ed0c9.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 02/14] kasan: clarify HW_TAGS impact on TBI
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=YKY7gx5S;       spf=pass
 (google.com: domain of 3hh7_xwokcv05i8m9tfiqgbjjbg9.7jhf5n5i-89qbjjbg9bmjpkn.7jh@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3Hh7_XwoKCV05I8M9TFIQGBJJBG9.7JHF5N5I-89QBJJBG9BMJPKN.7JH@flex--andreyknvl.bounces.google.com;
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

Mention in the documentation that enabling CONFIG_KASAN_HW_TAGS
always results in in-kernel TBI (Top Byte Ignore) being enabled.

Also do a few minor documentation cleanups.

Link: https://linux-review.googlesource.com/id/Iba2a6697e3c6304cb53f89ec61dedc77fa29e3ae
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 16 +++++++++++-----
 1 file changed, 11 insertions(+), 5 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 0fc3fb1860c4..26c99852a852 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -147,15 +147,14 @@ negative values to distinguish between different kinds of inaccessible memory
 like redzones or freed memory (see mm/kasan/kasan.h).
 
 In the report above the arrows point to the shadow byte 03, which means that
-the accessed address is partially accessible.
-
-For tag-based KASAN this last report section shows the memory tags around the
-accessed address (see `Implementation details`_ section).
+the accessed address is partially accessible. For tag-based KASAN modes this
+last report section shows the memory tags around the accessed address
+(see the `Implementation details`_ section).
 
 Boot parameters
 ~~~~~~~~~~~~~~~
 
-Hardware tag-based KASAN mode (see the section about different mode below) is
+Hardware tag-based KASAN mode (see the section about various modes below) is
 intended for use in production as a security mitigation. Therefore it supports
 boot parameters that allow to disable KASAN competely or otherwise control
 particular KASAN features.
@@ -305,6 +304,13 @@ reserved to tag freed memory regions.
 Hardware tag-based KASAN currently only supports tagging of
 kmem_cache_alloc/kmalloc and page_alloc memory.
 
+If the hardware doesn't support MTE (pre ARMv8.5), hardware tag-based KASAN
+won't be enabled. In this case all boot parameters are ignored.
+
+Note, that enabling CONFIG_KASAN_HW_TAGS always results in in-kernel TBI being
+enabled. Even when kasan.mode=off is provided, or when the hardware doesn't
+support MTE (but supports TBI).
+
 What memory accesses are sanitised by KASAN?
 --------------------------------------------
 
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1d82c593424e75ce15554a77e64794a75f8ed0c9.1610554432.git.andreyknvl%40google.com.
