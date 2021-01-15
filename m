Return-Path: <kasan-dev+bncBDX4HWEMTEBRBANNQ6AAMGQE44GBDBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D2FE2F82F3
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:06 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id k4sf3378512ljb.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733186; cv=pass;
        d=google.com; s=arc-20160816;
        b=NNAVM70qSr/ELhCf6M+sdtmmzRgls3ihx6uPmc6YALhENpieABpoTjY2ck16r2zXp3
         Xk1IUY+rPjk19sHxWiFPL4v+FSejTF7vsMwTYi2xsxJD/dSYMs0K+xW9GkXlx7jKih9M
         5U2dh5UD7XjjcARxD4V87PKO2yyVWG1IEt6KMLWJAme8nJAksMHuJj45p0DBmL7ezMzi
         F3RQGkxXXulLuN8cZApi6pjR4Pl/wsjsIZY0K3v7vYsLpQDkPX5akmm8R2D+jkZe0I6G
         K35A9pYHSQHRkH6kU9N6fXjAqNexgiy+mf51pvcsj8bfIssxQ6lK0Ik66eOanP/yrKJ0
         bSSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=e0+dpG1ssgPd+US63qLq25zCAtn/cmHEuaX6jE9wb5g=;
        b=flBDHsk1NuQdWgywXuNlnWRO8ChedYh5KlCd9KWjEkiJV0QuIC15YbmVRZqWc8rwsy
         n3oWIxT68Z+hbYTbf4CZKHKTY5hc0/6WhD+iyZhzeDXG1PL883av596NSm5Hg2S8fTYl
         jsqeHXTI8ff7QtqXH+GCSHU2rXYAn3XPWbhXYsy9AopIVtr3s5BBK60A7EFjmus60GZT
         iTLanItqFqaD6cSF6h7Vo0/nGrAJRSA/qXtFlBBRtWgHpWaT8Edte3w4/SZBDo5bbopv
         IqNwepOfPjIlnDdzO3V8xN25vJw7YkPhS8evWjgUuEIVSjBy4rrURLrSl4hivGLlZNCC
         UnFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KgXsADO6;
       spf=pass (google.com: domain of 3gnybyaokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3gNYBYAoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=e0+dpG1ssgPd+US63qLq25zCAtn/cmHEuaX6jE9wb5g=;
        b=E1W3GR/Tf7gIOblloC4AVMe+6aYe1OKdZoCga4p1neq1bQFwCKfoCYNGEr9w7lspLK
         gKZ7x2clyyeRo5jeaCpW67iwr1cZLRTJhgWYyekqVEcWHi+G0r1kyaZnq/3ENE0BXwp4
         1HCoLBV2C3sfBE7dT4lIbRZ/QtqD2nmfnCUX86AFdC1GDkHon3h22cCtDeok3FYKXnJQ
         6nUoDpOh95ms1uVi7Uw4OcGNqSbEdaGujpb1KgEfgKipxzUSHR9TCdjJ7oCnGPX4DW3u
         KmGty01jrIz0AdV+fnfWJuCUG58CU6aoNpJ/9MoUjXiDXxwcQZ6Mc0fTE+yiqmlYpCZC
         CFZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0+dpG1ssgPd+US63qLq25zCAtn/cmHEuaX6jE9wb5g=;
        b=rKdYmG3/F7juapWE5T24Lflxaxs6VEvF5JZAc43zsEC35lwXHq1BP0BFIgJzFV3chi
         HwB1CiEJEMzZBvOG+2oyrcfezyv/8LkerjEAZHhRcU3Sso9LVxxrURbF9gL1oQo4yuzl
         VSzWuD1HfF057SiCI/TvjZYBo9PqGz0BNo9Ss/9Ca8EGWGYjNvlsVUa9B6rUpF7YWSka
         5bC0p8FDfpUnMba9f99Z0s+JmVUquiUez9UfQtDnTHh/E8XNvSk2VtIgquP9L5tLvUD0
         c/CN5ZcnURu4mfwKSNqJZGWpYxiPL2eBHO24kwpnfO+n4r/+6JDnD4dKpTzD6LEzwKdG
         BWgg==
X-Gm-Message-State: AOAM5301NKOzJ6EajYKC02RPgn3kacaUyhXqPC3KeZPeu9a8P1eDT+VA
	ovRMPzU8aNlqBNvzIT8Pdok=
X-Google-Smtp-Source: ABdhPJw2yVTxWzR0mK3cm0hgRlA1otwhi7Fv/PZvMxrFhCEFGXMuY3rhfg0T83OQQixxnPbmm7kqMw==
X-Received: by 2002:ac2:593a:: with SMTP id v26mr4119228lfi.591.1610733185886;
        Fri, 15 Jan 2021 09:53:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:89d3:: with SMTP id c19ls1705104ljk.0.gmail; Fri, 15 Jan
 2021 09:53:04 -0800 (PST)
X-Received: by 2002:a2e:9f01:: with SMTP id u1mr5513674ljk.386.1610733184836;
        Fri, 15 Jan 2021 09:53:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733184; cv=none;
        d=google.com; s=arc-20160816;
        b=q5OUc06CXXHi81MhbXUmtYvCCWuU9VRJXFqGuVHDtuGjYP+d9r/Oyv9ZIRk+MYg25V
         1t5Nw5/Mc1Jm7GtdsIAgAgnH1su7x0sXup40o+UJyBU4G8PXDox1RN9mNeDNNzz2KElM
         QgTvH6iGJV74u1H6/3h6YQX93pAmFyRNf83g75ywctZCGAbH698WeVRsUZ6JpLBI75fg
         YH9nzcpHsKzgNAEnFQiDs8ECHrWiBd0zwlaLdAARmloJ4CwZDvroSxWPsdA2bVO2ozlE
         rGKoz05AZQ9dxZzTEd+4K7K9L5CpkKlh1Wsm/hknWwB+hT8M1q6zUhNCyM2eMFjpJ4LJ
         A8Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=d+lRqXXla6mV/kMKnUzgl/DAB69C3QZUVHCf/SWSD4s=;
        b=aQbv1Rf5Gy7jz+PzXPq8uplbg31NDDoUF1yLXfmYl0Oh3893YOG49GFY9I0uvG2KT2
         eCl3dHzoR6AxA8JzOmKAWaYWuofV+oVsqH5YBX3HY0vWIV29tqm1vetKn8dy4/e+Rrdr
         D92Dap0VVeHR5T8yRC2JuWMSQVaS/QdMnSDWKEJa4PCZkL5oRXaDdoQqJl30Rv+qtLMv
         zwcIEqd5DXleaBJeeN/ykZj7ymWzCGlUObsgYBK51BiIfP8pwzciR3+e0lWDgmeDfyy8
         qKH34SlvHY02lv+FIAgWxY1oekBSeGHglZ2/KJ8liqkALCclbZI83z6h4hIUyjAOhMez
         984A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KgXsADO6;
       spf=pass (google.com: domain of 3gnybyaokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3gNYBYAoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id f21si503999lfe.9.2021.01.15.09.53.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3gnybyaokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id k67so3270390wmk.5
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:e60f:: with SMTP id
 p15mr14224523wrm.60.1610733184113; Fri, 15 Jan 2021 09:53:04 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:39 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <3b4ea6875bb14d312092ad14ac55cb456c83c08e.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 02/15] kasan: clarify HW_TAGS impact on TBI
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
 header.i=@google.com header.s=20161025 header.b=KgXsADO6;       spf=pass
 (google.com: domain of 3gnybyaokctsxkaobvhksidlldib.zljhxpxk-absdlldibdolrmp.zlj@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3gNYBYAoKCTsXkaobvhksidlldib.ZljhXpXk-absdlldibdolrmp.Zlj@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3b4ea6875bb14d312092ad14ac55cb456c83c08e.1610733117.git.andreyknvl%40google.com.
