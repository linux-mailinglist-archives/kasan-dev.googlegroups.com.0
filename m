Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQHORT6QKGQEOYYJF4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id F152A2A7149
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 00:20:33 +0100 (CET)
Received: by mail-pg1-x53b.google.com with SMTP id s4sf14918436pgk.17
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 15:20:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604532032; cv=pass;
        d=google.com; s=arc-20160816;
        b=keU0e16kKcv4P8ajVCqhAsRufTMbgr3qGknX2GrcZeEwF2G35TszA92qTOYPKldaWd
         /6SlwTYOQ/Rk4ttbkWQxJQlkEVnbE0I0QLEeNb3lMeTCEVJK0L9uKvjuAx0jgxGdpi11
         u2uy3HY3wlZq4oOuQEXDobnh6byOIO3Mj8GZ3KkrLZpWh7ha+1UfwEs+jttJnyfhfS0t
         TclZ/20r92YuYePkYQPeGkDEAWSw+/HNIfIjj01w5/SREc/s5tXKjNBkLoYzIHWq5obi
         tbTFD4MnTzXlqcW6qGYfxIF3V1vyL0/4+XGi7WscpKPh7UWgZNZD4dvth4K3c0Al3snk
         C0Pg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=aWyT4p0nBsXEwTJhbCanlDmJDckoC12IwA3mElHEO7A=;
        b=wRmjaWVPzspJj4MQh/ivJqvSs8Kh54mi4znkzyXOuD8dwvDNtEBU9lKN+umkXdjVvs
         l0c1uHqNs6tMVj1e0QgcDUSDYs0sRSuC4cmB5bktLYAMdbyrIkb2/sBum/bxdfTOedJZ
         SjfeSGaDd601NRNzcJ1XgQwxQ2iiFyLgLTbt12eUmABB1DPhiI7Y9VUt6AClZrNWkynF
         5HB1MrE3fj07TLjZOvLxX0VP32Y7b9zlAZImE0Ylik23Xoj2DrAu8NkeDiBZiughLkZz
         P3E/zETDz+vmYUNimSEJ3LD2M5GGDKM5+uvh08C8aaMCIUrTY1jd/ybUWUtuWMAscWeD
         dDAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vNs/tV40";
       spf=pass (google.com: domain of 3pzejxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PzejXwoKCT4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=aWyT4p0nBsXEwTJhbCanlDmJDckoC12IwA3mElHEO7A=;
        b=QlBauQu+uBekp/mYqqpTvh1AWX2yInGaOgN9NO7DPERJNe74naL1cIU87c3RxIA8vo
         emc8oXBNI19XenFOp9VN8Dz0heSeR4/sPpR7TenfeYg3WcwUCNMtS7DoMgzbh6jj0FW3
         6oUO2XOlCYAAa31GcnsBicobxh/3RFfsmHL26v2YI/qHYkeakhHg16x6IgCve4W2iebY
         i+ACbCoq8c6Se6ibwXHfbFALdH579P8NptwbH3PT6ruvEjvriIcDupZvHU6wHaiIuLeO
         Za+oVrQp0vhXUmZPIjmn1UeC3hRADitCnnVBG9wqN/Vh0OANIzN9byKgZCar4kjj/Ala
         /emA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aWyT4p0nBsXEwTJhbCanlDmJDckoC12IwA3mElHEO7A=;
        b=EjQiJqXKO2lN5/6GGUA0XTAqpV1D1vtl3LVb0b1tpho4f4j0eUJG9AuFVDcU5H9d9k
         CIxJqLfFd8N5g8uEzwpQPLpIi4/IRo3XZ123lVwd5OdnnkM61qsBqe2eVj8c5Och3MqU
         /zAH5iEbpP/OckQfkb52MvOd22IqynmF7tIJrrj4s9CfN+IwFRrDdiVMQMj3XAdzQ3qq
         wlvC/4Jkn4h1gfosK964kGWQqqbWkqxZ7hBeSrYlpw5SJdYPq+DKVib5yvZrqVoI+b3x
         Os9xF84CRDCGqLMyjjQjvlzoiOEG5f+PTNOGi29OfbnQZtbKjhascuu3inC8fe/sDYD+
         RmDQ==
X-Gm-Message-State: AOAM532M4aXlWYI4V8YZXp5P/ASmxFtljYkqhp2zl0JfVk+7uDizfAnx
	/teTgEGOZ78RZmzAIWRd838=
X-Google-Smtp-Source: ABdhPJyCv2jv9R3xfaWKikje4ulQg7nOfVBxb4TwjybfdijCqTP3FP/hIST7uYBpSyxDpH12L3PWFw==
X-Received: by 2002:a17:90a:716:: with SMTP id l22mr274894pjl.32.1604532032749;
        Wed, 04 Nov 2020 15:20:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:6a85:: with SMTP id n5ls1657263plk.9.gmail; Wed, 04
 Nov 2020 15:20:32 -0800 (PST)
X-Received: by 2002:a17:90a:6007:: with SMTP id y7mr223073pji.153.1604532032179;
        Wed, 04 Nov 2020 15:20:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604532032; cv=none;
        d=google.com; s=arc-20160816;
        b=lRrX8rbQ3NDGZ514Ls6nFkSWQJN/3fiQVVYWUXt+kP/WidoTW94bBVniDMUU1Bje8h
         ZFDBQKyTpKqSCzsF9b+Nz5f+t5qpp/rM/grDWI5LGe4p8Lt9n+jMpwqHKjkC5UvHhvA6
         u8/MR9KYd/xKlpAsJh0ukYoROpFM2oZ2KZazcEeQo7ZzIFgU5YtcSgkPLQGqywBWO8gJ
         f7DCADN0yoxuW6xKwGgD9cKjwU6ae57uqn4+uouLsPeI3Tkq44MJ8WEsK4lmvN64/MJw
         MdVIun6SkohY4E9PPjmW5Dw4Y499CQeT9RUQKD80MJUOOxypTx2YywpDHXBRvvL99vVX
         MV+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=E7M1YMbMIR4yMAYd8ymzpiiG9f9KaGeAaRDscMDAbI8=;
        b=iorrnW6p5gfKW/Wgr/cbjAdVwr5KkxWqanWv67QC2SfxeMyycZ4AXm3fYBkWybqeP9
         6W//iNu3QZL+6vHZf64bTMec5t9l1DwpdeUEAkhRrJNJ4ZMwebgPM/h474OzCMpFlXMm
         LtWVVBSMeBbQ5Y3897crNIvKFGgGuy82wTwnE3Xo6TLVryanmxgudNuPWWwfcL327ErU
         gugE06WyLULdUUW76/55p1FQOvaiwGtQ+8YDDzxyaQCDrt17oqgpr9RJ2jVhwYbw5GgE
         Sb7lUjh0CVVO46hlNqcqP90NtdOfo+jIxHJEz8ZyMZH4jKfDUMc8pFqZVjHHWJZ1gWxS
         ixJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="vNs/tV40";
       spf=pass (google.com: domain of 3pzejxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PzejXwoKCT4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id z12si266122pjf.3.2020.11.04.15.20.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 15:20:32 -0800 (PST)
Received-SPF: pass (google.com: domain of 3pzejxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id d41so13724821qvc.23
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 15:20:32 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4b32:: with SMTP id
 s18mr435733qvw.16.1604532031338; Wed, 04 Nov 2020 15:20:31 -0800 (PST)
Date: Thu,  5 Nov 2020 00:18:50 +0100
In-Reply-To: <cover.1604531793.git.andreyknvl@google.com>
Message-Id: <dff2b79698978d86f4813fb7901492a1a61190b7.1604531793.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604531793.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v8 35/43] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Will Deacon <will.deacon@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="vNs/tV40";       spf=pass
 (google.com: domain of 3pzejxwokct4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3PzejXwoKCT4fsiwj3ps0qlttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN has granules of MTE_GRANULE_SIZE. Define
KASAN_GRANULE_SIZE to MTE_GRANULE_SIZE for CONFIG_KASAN_HW_TAGS.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index e3cd6a3d2b23..618e69d12f61 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,7 +5,13 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#else
+#include <asm/mte-kasan.h>
+#define KASAN_GRANULE_SIZE	MTE_GRANULE_SIZE
+#endif
+
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 #define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dff2b79698978d86f4813fb7901492a1a61190b7.1604531793.git.andreyknvl%40google.com.
