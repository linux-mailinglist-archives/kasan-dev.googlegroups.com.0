Return-Path: <kasan-dev+bncBDX4HWEMTEBRBOG72L7QKGQEOKKYDHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 251192EB285
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:10 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id v138sf138739pfc.10
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871288; cv=pass;
        d=google.com; s=arc-20160816;
        b=SeoFeqVeqb7ZLFfzLwuz8w7kcD9l10wLlrW0C906447V+asKJuhQ9uD84rdnLbEyqM
         Wu5VhlDu/m+1PxAkltst5JfmDubq/y8LbZutcIOjCRQpCnz/K23CufHw8VUIa/PqjntU
         S8LZ22rv/7ecik+gH6mO+TFoDB1r6I9U5K0P/JOg4HT769ab9eU0FWu+NfW2x/2fPn4T
         IZI6xsz3HEDGWs3oLY6hM96FyRekc8wgMfdKUY3nzLzWCYW/UHJ6clwvdPPR/0/zOeAD
         By22wlEnch0NVwiR69tHM/3xIW40P5df3mEIzqWz5G4fwObv5ORZR/7g8XS4VqJXE1Ud
         sc+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=HESqrheyd65bgkAYOtbRtiGXPmOukVoqs+Hyc8BBhvM=;
        b=Mr4nvStby/U6M1Y8tyYtMtTeOFRXaGmZXl0AFnZDi/NH0IAeuHjqBdvShxvN8POGWV
         sPTHTQBIbaB5bYIQzOQY3w0XJqDnwLBXXc7OWMlZyVddKcaLag15TGqtg/bM0ExD2CuW
         5Or7kpkT3TIentGzHyP+gGF/gJNEjuUhihdNBOGep1+mfO1WnRCUPkVOTD90IhdooalE
         nUY9g6s+6UpSYvc8iLucVoUGizokOK1u/rCtcbBBz14e1CMSe2+nsseXbVxSUUJRNrO3
         PlbFdeTdCPI4Ds5E6doR3sKBUrrvjhYGLa4IPmFOPFx5dV1EqT94BuGtqMrhBXca+/Dw
         1DuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RE48ZQIZ;
       spf=pass (google.com: domain of 3t6_0xwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3t6_0XwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=HESqrheyd65bgkAYOtbRtiGXPmOukVoqs+Hyc8BBhvM=;
        b=cVBAg1X5ENxtF9J2KTxAw275dv4BXVqgfPYWGtTKlz/JQWunuD/AWy4L2FMCcYtyoe
         F+p/6MRs+mOvT9BRj9rmRN9jXMClf0LBPmodJDIaBcdk2Suuq1n7xE9oOSFyMs2VuMGs
         2JU2EbF6Ie4ZnIiqLDGgh5lMnOcxAaGMt+JMKOa3+9nkdZWxMP9phmzv+6tlm4dH4p67
         GtU4LeHNRkK8C5/Je22cjr9S98y8g4uQIJbTvi761ziugRhACCNQsWmUpleW6pFK6W83
         i5hb5sIdjUHcHtZ5LZ0HrAyKNuSmJpqjY64xpWjPi6k524PC3uqLM1dGh8z2dcejG+lV
         E7/Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HESqrheyd65bgkAYOtbRtiGXPmOukVoqs+Hyc8BBhvM=;
        b=n6nqKEge+o0w3fuEkoobuFQ8cLfVwLJvcQ2DMUCAn8414K5kbQ75wU0K0bYfFyNeyi
         opCPN8Iv/HoQ//8A0wT0a6yLWYwRRg+8MzoO/mSQTwRlaegTNnzQjyaFP5h+He0o7VMl
         jVSPk2sVi404kF0//B2fYUoQUeKd+421+2Jk9RElYemquJ/MXx//+Ij8aqc1n7a9wAbe
         ThESGp4EmbS1L56J+XYNghJbM0GS/AMRvSg62G0Gc64fm3mLOgD4hMlVUzEEPinutWxv
         9ZaSWfgopvoCAr4lBHr47nHjB3yHLHFgzFakmXppTsPbT6UDs0SX7pnQC+yBaWb2E9K3
         gDxA==
X-Gm-Message-State: AOAM531FTm2KA+Iysk5r6bRILDs8yDer9q2XjQSpNCEqkZ28qi3MZ44V
	15uRxNZrgU0XekAmrIXsk64=
X-Google-Smtp-Source: ABdhPJwFnKXDnNvgHuylsJtpp0vFMIKNhrSjLXatC5MG7wB/byAzBcQdE24nPpOig5PL6ZHYJ9/+IQ==
X-Received: by 2002:a17:90b:8d8:: with SMTP id ds24mr496429pjb.134.1609871288745;
        Tue, 05 Jan 2021 10:28:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c205:: with SMTP id 5ls169014pll.11.gmail; Tue, 05
 Jan 2021 10:28:08 -0800 (PST)
X-Received: by 2002:a17:90b:1249:: with SMTP id gx9mr465613pjb.169.1609871288032;
        Tue, 05 Jan 2021 10:28:08 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871288; cv=none;
        d=google.com; s=arc-20160816;
        b=ae1Rgt+dwL3lY1gay+ba1VdMAFMMqWKpI337VMTrQiVp8F7f0KMrede95nBt6TIIAh
         ba4vlLZt2obOIC4Q/jmcIYVlr8mMwJqvI0BAJhZNuyCWTsn4FQgy6g1QvxQXswECMaE1
         c9XxlxGozahG5U5FHnw77bktQfXB4IpetdJEPO0f5Qh65hQrSWuv7TMfw2iJ3sjWcuL6
         K4iqKJXVo6R4lLSFwOMbg0yqCQOtR1rFtQwzKaheKpvLokHC8N93GiVLuUxkyrx53ZwL
         4fKpsFmBrbUNAtAVgZtpkhh8rqqcgqAAvFSH3fiXJ3yfoBdPdUCFdpFEVTtrcJn0Y/BA
         ThqQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=VRs7dAB+P//KjkP9Cahy8mQRvB3cL9kKzxtAOErS7Qw=;
        b=xBuAP7aDQWQAS6us8FPjiU97HdxX7HuYlSlVa0OqxT80YtMzHrfs495AUkoLdgZGh1
         HyNIZgYSUql8mJ4+svRQkXfrI8q2jMR0YWyOicLNV6p+E9L6VcjvbzMLzUJgKE8pQPpT
         pZui75xiyuBsxjkHp6oWVZESL8Df5n90bj6po2yjzRJwwbptCHj1AM4lafMn4W+l7PZ1
         HOowiiYKvNJRVqE7eIUAFcafQFpMId5mcLXdL/Tr2xLLkIdocECKB2Hx9xA2bZknJl05
         t0V01zAVZvPo+0CkzVpLUM0ibuaM/b8EAP1LCvipKoutVn/FzW4MzAazTLTflPCZm7wZ
         6kOg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RE48ZQIZ;
       spf=pass (google.com: domain of 3t6_0xwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3t6_0XwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id kr15si238688pjb.2.2021.01.05.10.28.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:08 -0800 (PST)
Received-SPF: pass (google.com: domain of 3t6_0xwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id c17so375756qvv.9
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:07 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6214:684:: with SMTP id
 r4mr745500qvz.54.1609871287214; Tue, 05 Jan 2021 10:28:07 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:46 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <a5dfc703ddd7eacda0ee0da083c7afad44afff8c.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 02/11] kasan: clarify HW_TAGS impact on TBI
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RE48ZQIZ;       spf=pass
 (google.com: domain of 3t6_0xwokce4qdthuoadlbweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3t6_0XwoKCe4QdThUoadlbWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--andreyknvl.bounces.google.com;
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

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Iba2a6697e3c6304cb53f89ec61dedc77fa29e3ae
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
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a5dfc703ddd7eacda0ee0da083c7afad44afff8c.1609871239.git.andreyknvl%40google.com.
