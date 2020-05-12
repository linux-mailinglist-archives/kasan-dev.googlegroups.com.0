Return-Path: <kasan-dev+bncBAABBM4I5H2QKGQE4SSXYOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93a.google.com (mail-ua1-x93a.google.com [IPv6:2607:f8b0:4864:20::93a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A5E71CED17
	for <lists+kasan-dev@lfdr.de>; Tue, 12 May 2020 08:37:40 +0200 (CEST)
Received: by mail-ua1-x93a.google.com with SMTP id g7sf891056uac.16
        for <lists+kasan-dev@lfdr.de>; Mon, 11 May 2020 23:37:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589265459; cv=pass;
        d=google.com; s=arc-20160816;
        b=kK30qdYuUqji2bcSGNXC6Brx560guDv4YDp1aB14vhXEAS6ibkw/xOZwX6HMX8M9xB
         OiJ0PUxK9GUxs89WfcKz1zhFknBHvLcVQCXetzhRunrt7V94LH8PsIcNhtAhRBI2qKxq
         JFAycRKOIFvMQyuUGplui1gI8iTIVYAr6mLy4t0HDT6blkj9KAAyK8y+bEU20qWTI9a2
         sOnzqTq9bu5bBqNOKnZFGREGmEmpESRFY5HwQX2DPxXh0AlruyqMgmbnVv4sM4DiQcf2
         N+QWIswwjtRCGaMgGPciCWo2Zf7tyxu0xlB+UxMUXiqJgkr+W78YdrhR/clTYskolgNE
         oy8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4EtqvbRlE/oyBHWhPKZ8cth9id7t9f0x82S6dR/BSTU=;
        b=CG0FTASJuMVj5L3MtFMaurES+jmGenSqi2drjNzuh6QdZF2u0q1cN2ryzTRlmLIhrm
         2tPXllIUyurTUh69lEirLTi3sLKKB1bt3kCKmpFIIo9jFQDjpN4O/s6LX0PivI36ghP3
         o3CAmDDgOjbpQYsfjc63Oc3aqSczqn0mjYK51RVKc9oP5E7SyeBgBA+y2LnnYLJZJT2Z
         wU5bydMuACTEbsycRcAdwKByMrpbA6fZcXAxUoYrbI9OXHOMA/hSXChWg0mafblD0QrN
         BFc8hmPq95vmcQIgZDFEbc8h1C/XmMyoCkrpehwRvMUCmu5oxvbG4S2qNC1uQqcNrowo
         crAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=XLI8Ef5w;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4EtqvbRlE/oyBHWhPKZ8cth9id7t9f0x82S6dR/BSTU=;
        b=kSlC/PPjMhtcVM8iSQxdDcZ+RrECm03ovqBmNrQ0nnuCjtDfnyjtwd2Cxet20kbgrn
         70eyc/Gagvhm6Qxu1jAd5iYd/HFdcZt/I9GJQjcHj//fHSESiPkI1ixZ6ViOBWi9Egy4
         lkE537htpPLB5OQsLH+lkH7I5tnnTQXqW9MrZpXnxAVHsmulPrXn0DbXl4rCKNY6Prs5
         PYH3XXf1NscYz1SMblvrcKL5YJifUH2DlkYydXp1SqBFjie3Eb5wYAYuJICdhE9irZCn
         WKvu5HRqisB6naPDjIfX0zL5vEjNJ+fmVff6d37uW3MpUIs0MiNysv5bey5jK5ZnN9bk
         O+Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4EtqvbRlE/oyBHWhPKZ8cth9id7t9f0x82S6dR/BSTU=;
        b=t1ggkWpAm2nh7e40kkhjN0Sii/QHpHcqD4s+VG+P86Q10M0ItK08+xrvt1kJ6aX5jw
         iSVhp/jLJJuXuIi9y9uG1oJfF5BjqARZz1fQk9/QL75LbZuE6apgp9rImC+Ux/UdJaj6
         A3VCmtRL4wky5N5+h3uGHQgTexkCDAfNV9v+KcQY3BrJp7GsKIf0LWESinWquNgDm2Ik
         Fw6NJIihBtxxxSVxWpySwMLydLDKsyX1wvdpBhpJyqd1VwQh7YSgnZucJYnfxNB2LvEZ
         RnGgJrG5VyxWGsYAdRZvFogF7Smwsk0tqXi/kfwP96Haqth5a96taPIVVc2uURY70bWv
         Oihg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532zADOgd5QxgwiLfKjezA4QUghJoCO2frwBNCyQDhEXUDKu3fXw
	n1ue1niRVhSVjv8oIeCrqk4=
X-Google-Smtp-Source: ABdhPJz/kPg7V1uAb0BK0BkpJp6yEKHrud1KRhq5eNmnPtynIOnWM3u9fxOYFUWEuKvino5/Kf6+Og==
X-Received: by 2002:a1f:2c54:: with SMTP id s81mr7320327vks.82.1589265459366;
        Mon, 11 May 2020 23:37:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:fb99:: with SMTP id n25ls1420985vsr.5.gmail; Mon, 11 May
 2020 23:37:39 -0700 (PDT)
X-Received: by 2002:a67:ee0d:: with SMTP id f13mr14740825vsp.191.1589265459106;
        Mon, 11 May 2020 23:37:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589265459; cv=none;
        d=google.com; s=arc-20160816;
        b=S8iAjFg6nEv+to8cK7U8lsQfN1GZAp6O85BtYdqx31zRDU+2BNrHbjnM+oZ9nMhaka
         IlXt5HD+n6sEj6FcX4Hfu6RoOTtugAjVIqiufDVAmA2AoW2d32UTlC9bJWVdYY6jUKas
         EWSbbSr7sBQj/q7LVCFSbdBVho7Qliwp3csuDRr7Nd1b0MJbrsknFGFOLdAcWB9ffgxb
         asAO5WvHS4SjAIHfZ3ps1POQjt8zdrwTQPVF3fj1CPJWodxfC2rzP3/Z6smJUY9hc3rJ
         ExH8CrHZj65EIcfOMqpmrU8gi8CN3e43cOVxd2iO34FF09Y7Q6qpupCqCyyJ1aqP2U7z
         ajPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=Uajlj0vn8iVuIWxdxvNlVpeu9pNPutcN8OXzxhnDGLU=;
        b=Hqmzbb+M6SJwWhCjFUp17UQl2PrY2HwNDE1tCBPRQCo/+uQz0Oq3d7SWHfnyaJ80h+
         EHesIrHNKvqT23Bfg2+edJazZaC82r1BMvzEsR7m9sW/BaxLBY58akhWzsd+s9siHp2A
         AN02YLhX7anWI2VNJXrvPqmF8jrRCebDt1SNz+xzeKfI4WLZbjtrKOLKkBqO8+F7hxOq
         Q6LQN6wuYK+b+qFNEvn7m2RN7UI882kYkXhTo+3w/ifLkwRhmfAFGQZ9fIoKSqM9Md27
         kPMvHwBKsro9Obw6rkI5CKtpfNkApFUYCW4scaDv9Ex+jUEz7EeaN1cj6ejDXY8kr5ug
         fZQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=XLI8Ef5w;
       spf=pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id a205si609939vsd.2.2020.05.11.23.37.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 11 May 2020 23:37:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from localhost (unknown [213.57.247.131])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 8C24E20752;
	Tue, 12 May 2020 06:37:37 +0000 (UTC)
From: Leon Romanovsky <leon@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <adech.fo@gmail.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Leon Romanovsky <leonro@mellanox.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Michal Marek <mmarek@suse.cz>,
	linux-kernel@vger.kernel.org
Subject: [PATCH rdma-next 1/2] kasan: fix compilation warnings due to missing function prototypes
Date: Tue, 12 May 2020 09:37:27 +0300
Message-Id: <20200512063728.17785-2-leon@kernel.org>
X-Mailer: git-send-email 2.26.2
In-Reply-To: <20200512063728.17785-1-leon@kernel.org>
References: <20200512063728.17785-1-leon@kernel.org>
MIME-Version: 1.0
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=XLI8Ef5w;       spf=pass
 (google.com: domain of leon@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

From: Leon Romanovsky <leonro@mellanox.com>

__asan_report_* function generates the following warnings while compiling
kernel, add them to the internal header to be aligned with other __asan_*
function prototypes.

mm/kasan/generic_report.c:130:6: warning: no previous prototype for '__asan_report_load1_noabort' [-Wmissing-prototypes]
  130 | void __asan_report_load##size##_noabort(unsigned long addr) \
      |      ^~~~~~~~~~~~~~~~~~
mm/kasan/generic_report.c:143:1: note: in expansion of macro 'DEFINE_ASAN_REPORT_LOAD'
  143 | DEFINE_ASAN_REPORT_LOAD(1);
      | ^~~~~~~~~~~~~~~~~~~~~~~

<...>

mm/kasan/generic_report.c:137:6: warning: no previous prototype for '__asan_report_store1_noabort' [-Wmissing-prototypes]
  137 | void __asan_report_store##size##_noabort(unsigned long addr) \
      |      ^~~~~~~~~~~~~~~~~~~
mm/kasan/generic_report.c:148:1: note: in expansion of macro 'DEFINE_ASAN_REPORT_STORE'
  148 | DEFINE_ASAN_REPORT_STORE(1);
      | ^~~~~~~~~~~~~~~~~~~~~~~~

Fixes: 0b24becc810d ("kasan: add kernel address sanitizer infrastructure")
Signed-off-by: Leon Romanovsky <leonro@mellanox.com>
---
 mm/kasan/kasan.h | 12 ++++++++++++
 1 file changed, 12 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e8f37199d885..d428e588c700 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -230,15 +230,27 @@ void __asan_load16(unsigned long addr);
 void __asan_store16(unsigned long addr);

 void __asan_load1_noabort(unsigned long addr);
+void __asan_report_load1_noabort(unsigned long addr);
 void __asan_store1_noabort(unsigned long addr);
+void __asan_report_store1_noabort(unsigned long addr);
 void __asan_load2_noabort(unsigned long addr);
+void __asan_report_load2_noabort(unsigned long addr);
 void __asan_store2_noabort(unsigned long addr);
+void __asan_report_store2_noabort(unsigned long addr);
 void __asan_load4_noabort(unsigned long addr);
+void __asan_report_load4_noabort(unsigned long addr);
 void __asan_store4_noabort(unsigned long addr);
+void __asan_report_store4_noabort(unsigned long addr);
 void __asan_load8_noabort(unsigned long addr);
+void __asan_report_load8_noabort(unsigned long addr);
 void __asan_store8_noabort(unsigned long addr);
+void __asan_report_store8_noabort(unsigned long addr);
 void __asan_load16_noabort(unsigned long addr);
+void __asan_report_load16_noabort(unsigned long addr);
 void __asan_store16_noabort(unsigned long addr);
+void __asan_report_store16_noabort(unsigned long addr);
+void __asan_report_load_n_noabort(unsigned long addr, size_t size);
+void __asan_report_store_n_noabort(unsigned long addr, size_t size);

 void __asan_set_shadow_00(const void *addr, size_t size);
 void __asan_set_shadow_f1(const void *addr, size_t size);
--
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200512063728.17785-2-leon%40kernel.org.
