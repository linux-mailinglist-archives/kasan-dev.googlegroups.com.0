Return-Path: <kasan-dev+bncBAABBUWI3SJAMGQE2TCXVQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id A310E4FFF45
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 21:28:19 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id w34-20020a0565120b2200b0044adfdd1570sf1301314lfu.23
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Apr 2022 12:28:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1649878099; cv=pass;
        d=google.com; s=arc-20160816;
        b=CUuDthv6oBrLvuvWRtw4osI70je72U8oyuuSQ4JPhw20sYhOuW8GyfAQxC/GinEgrD
         2lWCbSFgpgt8HQ/1RswB+1j5G4qWpcs5fVJt+oEHZA1WoNMQSpYEPY05wmO0DJrH5+j/
         WRS7QX7bJ/mhca10+kOWRI0eOlPbQxP/mtlj7bOib2Sf/ualdHUHBD555hpemugPuzHM
         443iDIgFCeI+0cj3+d0JDQboUFEzR0S7aneMwdSWjULeu1sCDtYbZeSmEwOVZwmDdwVQ
         v44azEffrUh926Uzf+YL52NbLFRtpRb1KcaFcQg39w6pHNUVVdIOmtgqD5unD4JUvYZ/
         8Rbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Nrt79YRKkNvx0ig/3oyUPs6MRTdvcIDEmOLzdK5N3kQ=;
        b=mz+x4bQWa8SsZFfJ4UXzVGMpBQmze/XIMKku69rWO3ybggFUJmFgbrMTvhhLjCNEcj
         9/LTPJuecVB4dziat5gj9XtKdXx1vUp0yg4Z+8Va00MZtrimBr9AhLM6EsXuaxA9P/an
         VMMnQYKy6Xo2DB0DvpS/gy4QqwxIhZL2h3vX5jfPif4M7ZAesnVKavqwqi4qiJGOXIR6
         6MtMKTVirZtGQJlDXvfEkSJSutoN0k9JMGHbxQoO2Op3T9sVZSw8S8iQDBt3ScRI5qq5
         ZKxo1yyhcK+Wm12nETBnKk4wv7ADq6J4srGGJDLX8q+/zlU0/b1pVGRe20CQiU09VC0w
         woqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sgF7TidZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nrt79YRKkNvx0ig/3oyUPs6MRTdvcIDEmOLzdK5N3kQ=;
        b=Ssl1cT/kPjL9zzhzt7n/GgAp5DesKO7qA52ysQrD0WAgeE0n6myEBukYWFcIAEPhYH
         SHNvqSQGBMA1HS6pj2pnwCHqUNyta6tythRvB/e82N8aanJ8IZJTwHFngu46Ibgq0rU8
         JwM0UiJNAEzIcVbDjrgZeW7HC+wE5G7zWu3snhawhUKnZBhdFxydLwFOLtYu+z+wo08f
         nPo7Cr4FH3UQVOrUAQj4vym18Zz5CvR31aR6Pp5PmrKqQSUxEGaGpuyZ5grL7CVpPpqe
         96b1mLOMLhPawEFxEj73GizKuqoea06ozYunB6KjTfBqBQVYnVOsR9BsVRt2srkfOzf6
         MzNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Nrt79YRKkNvx0ig/3oyUPs6MRTdvcIDEmOLzdK5N3kQ=;
        b=dBoQa1bsxoLHiwA0GdQphGb2u9Vw58hau96GYIlk4k1iWLl8BGqEciJKfJGth+z60z
         ypDiM+SEO4eT53ktDpBGhnmPSOD9AstUbVHXe2hqXIBRD7wEXmkwZcmAQyJwVoelLdAR
         bfRnEqcuPNJh8fk00p732WCt5ETDy1sdaFPfYJkdZx8By+DcO0B5H+Kby8nIYPe/13/A
         TziHiBhNJiG9Z0AHflwmGtx0OAWcrEWw5H8aVowdwutt6RWYLmuxxlEshi1vWItSxjqg
         axk9FasL4LnJSV+LfiqIyl8U31r0Rfnl47WmlMJX5WfNEITymeS8KxHG/LN4L5/5jMxW
         dpcw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tcIorQhQniHTULy4/O/Bm7LKs6R2z0v8JwxOjBcdMjwiYHGQO
	HMpLlgTBMBoRARrOUatNH2o=
X-Google-Smtp-Source: ABdhPJwnkRNmn0qXbkEOzSTb6aTenfhgGR7387HhHSUR0KTPCm1Pm68tSIjqkSXgQhTPs6HYjvVDEg==
X-Received: by 2002:a05:6512:3d08:b0:46b:a03f:6896 with SMTP id d8-20020a0565123d0800b0046ba03f6896mr13713552lfv.120.1649878099238;
        Wed, 13 Apr 2022 12:28:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4e0a:0:b0:46c:56e3:aa04 with SMTP id e10-20020ac24e0a000000b0046c56e3aa04ls2617660lfr.3.gmail;
 Wed, 13 Apr 2022 12:28:18 -0700 (PDT)
X-Received: by 2002:a05:6512:b18:b0:44a:9a1f:dcf6 with SMTP id w24-20020a0565120b1800b0044a9a1fdcf6mr29624704lfu.4.1649878098495;
        Wed, 13 Apr 2022 12:28:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1649878098; cv=none;
        d=google.com; s=arc-20160816;
        b=QO1L019k2HXL7NA2XJ4+FLaYdUV1AK4DyfJ7L06GS4pwGukTdY1Pk3Wwza2vNCW6r4
         BEYsEuwEViYlSTcmWLUKz/1M+t4eDhQ+AFixdH7j+JF7fvdn/0g4v//i9usZmLmUTYBQ
         BPJhpJkqu7ywRo6pnLznCS01tfTi+ArrT08kvkKEPH673BqCHTMD0go/Bt9dtIiVigSi
         UeAdAbBtG7NwUgUzEwq4wuCrvhNHj5Cxd0+xZmItWzrQF2/OEFCTKdM4dKCKEqi9SHIz
         wW/dKo1wu2aVA60C+WZw95JUNM+C/SyBJ3AARCXJQIFgBdRgOooqNy4N9mBe7zhULthh
         EXHQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=JDSn48VO/uynw53/sb4SAMVT5nBlYcr9rW/XWz8GxpM=;
        b=JTnBe+ydJjjiLmN9n2GJNWygBxQcdjWazPWIDKiLAAibiUeUuJF4A38OcMlVxapjqp
         9Oi9Fnf5c2LoayC1Vza8ebgLZfpKo6LXv55UAgKZpnl/SOPNherDgsnd4wlLnzS1xKdA
         tzo5gvq8rVXIrDIkptANAnz4cJv0mc4XqkTcpDhMws1o1VBMubYE4ua/OmlZ6Tj7xhVY
         88/r6FLixyxW4DZfDwTcg7E+rVtgh+55cfXe4UrIle5OYiw1QkcN3kVjeAseo9kec7gZ
         +KLsUBYSfaRloWMSm1jC65E+LAV6DkIe8hyAbmQTXqxh3wK6Aj6LUPvI8yQ70HlH2kfV
         chfA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=sgF7TidZ;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id n10-20020a2e904a000000b0024b54b241c1si641042ljg.1.2022.04.13.12.28.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 13 Apr 2022 12:28:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Sami Tolvanen <samitolvanen@google.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v3 3/3] kasan: use stack_trace_save_shadow
Date: Wed, 13 Apr 2022 21:26:46 +0200
Message-Id: <05fb7a41510f471f82aa1f3930ed3aac8abe2410.1649877511.git.andreyknvl@google.com>
In-Reply-To: <cover.1649877511.git.andreyknvl@google.com>
References: <cover.1649877511.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=sgF7TidZ;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

From: Andrey Konovalov <andreyknvl@google.com>

Use stack_trace_save_shadow() to collect stack traces whenever
CONFIG_HAVE_SHADOW_STACKTRACE is enabled. This improves the
boot time of a defconfig build by ~30% for all KASAN modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 4 +++-
 1 file changed, 3 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 23b30fa6e270..00fef2e5fe90 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -97,7 +97,9 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc)
 	unsigned long entries[KASAN_STACK_DEPTH];
 	unsigned int nr_entries;
 
-	nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
+	nr_entries = stack_trace_save_shadow(entries, ARRAY_SIZE(entries));
+	if (nr_entries < 0)
+		nr_entries = stack_trace_save(entries, ARRAY_SIZE(entries), 0);
 	return __stack_depot_save(entries, nr_entries, flags, can_alloc);
 }
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/05fb7a41510f471f82aa1f3930ed3aac8abe2410.1649877511.git.andreyknvl%40google.com.
