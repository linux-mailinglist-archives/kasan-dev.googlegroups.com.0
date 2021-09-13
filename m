Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB44Q7SEQMGQECZXBFNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id BDED3408633
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 10:14:43 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id x33-20020a0565121321b02903ac51262781sf2909148lfu.9
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Sep 2021 01:14:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631520883; cv=pass;
        d=google.com; s=arc-20160816;
        b=so7eDfMDxAnizlFKaejBP37+3XCyoM6csoMxwTvCahQ1nEHL6r9aWnM7UjyhcJrlUe
         S3E3EaMXhF57zO80rsQinbdFSKEfnzD81S1QWBMQLaZ0kmu+BMVsQ2KhIpIL5xmgKCtm
         nT7g5GC3smNuU5yUZmcD34qMFWriBryWUkuMxVSMmVoQb7S5hMg1ARsIH5WqoWhDlyOD
         YraZ4xJiuW9kLOj1++58/D8agzPKNOYJlPTGSGKaXNa+ynn/ycULyOypX87/wcIIYnPY
         woU1EZQCJ3cPTdSAk7ytp3xXEOCPKy0xJkQflaldKob8ZNPCCd9GKUVmkAIEnwx86pc4
         z1bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Yns5XyytZx+5hKbBH2mXWDH8FizRRJTzlaxHulNRSGU=;
        b=mTXQuot4W2kO9oD+WOjagf9Qxc0anK1t3zC6Wn0PdADLaKEKR4L8PzpYLwbcA78Uah
         4aQmUSoI20iMMN54nEdJvKJV+whd++TS7bm8fsKi1wdykhKxK47P+uo/IP10Gtg5qorZ
         D5MUsjFPQ1Cr2IDgZAiWy2vgAk9HMxeHEvgB2MlByQncjoMexkD24hAXW+YhtFwsy8JS
         CJhTP8bl8VhMQOpo1nB5jJUWL6ga24s4m/kHWAv1JrnI2P68sULwSi5/gcpE1JkyU8qv
         FU3X2rPINGTzbb8XjRA1e2wq9yRuZSKciH3zGa+y7+HYmA51mCrXdwF/32YHPWVBTDQK
         4e0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yns5XyytZx+5hKbBH2mXWDH8FizRRJTzlaxHulNRSGU=;
        b=RtpW8jPj3JrM27N/+VVqzv5cNlUgxUPCTtioLM4XQrF/nbiVTdR57Vr91OwJzmQ8ed
         DfWpqmKosAhMh73+PVbZsjKlRBqUuzPketn4VFwam5sXNHLCoGHCEm3A8mIuVL6OndI+
         KXtieIa+8X0nfCnoyaD8m0Co+SiGI0XN6N+aJhPXw7beTVSGNhnQGU6ZVShlUkjcu6D7
         pBsMssqElDZ5GYsNtyYHQfW0AZCND5MSaDO/sc9mt7afWbg1W3v4S4EZikpKU/zOMMLn
         pu29Fj7sbqfXS78uKEnvfOg9/jSe8Q/Ek+jJ4ZCLdYfmpikLn5baaFJp55gGWZ3xE8xo
         WiKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Yns5XyytZx+5hKbBH2mXWDH8FizRRJTzlaxHulNRSGU=;
        b=nodW+rMEv7NzF9ztDooMlI9LtULmAoe8Nzoqy2NglJSJ2HEnWmkoAHxvFGXGKBKKpT
         hHVuckzICtjNgyTWU/81XjXqrcsI7hdHF4DvZt8e6uviS1dk9jaRpDM61xFu+3wcxSIu
         MdEIIYNVSlrH3W4JnwMiO05aTQqGBK3NEGNOTLLhs3s7f1rPKSgYXUmNhBl/slsA3JDn
         BjleaXz2cZKpV1ftzLq+ZSRW8G+BroefqDGjCzburkC8/nu9xSWRsVbuLvnaYavgqnEO
         FsMgOXHIBf+GUPxk8sdp2TvaENuCYV80aCRWaVhSe5I+LVjk34wbf4ckqEFuxF3Hwr0q
         VkYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jr7Hj5T/WREOUpeB5uicnEgTqJ8Kuz7GNLxTZZC5tTZ6xAWKY
	40MTAl7O8mycQfsdU0YFoK0=
X-Google-Smtp-Source: ABdhPJyVGdACltDgP9dAQEsqSWkfajAfyAS8gqdSmLGYAJ9jFBR7SGCzT0whSsiax2u2XRiR51fkDQ==
X-Received: by 2002:a2e:8795:: with SMTP id n21mr9617201lji.474.1631520883360;
        Mon, 13 Sep 2021 01:14:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3b88:: with SMTP id g8ls907654lfv.1.gmail; Mon, 13
 Sep 2021 01:14:42 -0700 (PDT)
X-Received: by 2002:a05:6512:15a4:: with SMTP id bp36mr8002610lfb.509.1631520882397;
        Mon, 13 Sep 2021 01:14:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631520882; cv=none;
        d=google.com; s=arc-20160816;
        b=GJMNnPKLcjMeZ5Am6VXuf+vOpZQqXDvQmtUuJsNqZxpc7obb2DpbpguWtd1c/i+tnQ
         EqghQFE2yX2qUxHflwSRRL+kqNvmhGxI8Dl34qQTObEAVtE4MecNy/lSQtVAHId78kCk
         NIKuo7cIK7qYo5F9oC0pq24GCiK2nFk/Qu5MZeqnwFUjY9X+Qu/oPNY230YYSIkq5BUj
         TmbefHkvmfnauawDbwpuooYG/ALIrUfQsPDficy+FpggOap+PPqtPPlAzWt1uLk3rHCX
         t4A4RTpL7nO6JZuFKXKzk1C6O9o3Fa1R/CZiDeGm7kaaeOd6gIp/AhvAT0NqRrQrEoo3
         SKEQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=h4TFq+ONFMOnuXcVEFhxxYRG4zxyZkmPPOduL3GdT9E=;
        b=Lq0G4esOFG7K2xFwRoLuqlxaHRLnKIKF1646qW9L36qvvyYu7d+X+Jx53xKTqcdhOC
         +ih3srM+uDxr6J1w5NlIGCStpL16xqSFFr3wZm7CMNGQ9pWH0BaXsG3VPZnLNN2ACtqj
         KBWgIr0N+EjPCSKKYqZxA3a06E0Ztf9mRdv9sBPp/1FfybFQ2vokgwK9BpgA+W3Be7g+
         phoaRhP+/424CT/zCi/WX9UnnlhaI/TB1uOChvFV/M7LngdWi1rJ6pyhN6cG8jvi29ZL
         iMUta+YsJni2Fjkh8ZTpc2VclSv6kvMMh8VKjEeEqiVOxNnJdOW3UCrDsd/6p7GI/y8Y
         rDig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z4si747465lfr.2.2021.09.13.01.14.42
        for <kasan-dev@googlegroups.com>;
        Mon, 13 Sep 2021 01:14:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7E2A9101E;
	Mon, 13 Sep 2021 01:14:41 -0700 (PDT)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 98DEC3F5A1;
	Mon, 13 Sep 2021 01:14:39 -0700 (PDT)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: vincenzo.frascino@arm.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: [PATCH 1/5] kasan: Remove duplicate of kasan_flag_async
Date: Mon, 13 Sep 2021 09:14:20 +0100
Message-Id: <20210913081424.48613-2-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.33.0
In-Reply-To: <20210913081424.48613-1-vincenzo.frascino@arm.com>
References: <20210913081424.48613-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

After merging async mode for KASAN_HW_TAGS a duplicate of the
kasan_flag_async flag was left erroneously inside the code.

Remove the duplicate.

Note: This change does not bring functional changes to the code
base.

Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
 mm/kasan/kasan.h | 2 --
 1 file changed, 2 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 8bf568a80eb8..3639e7c8bb98 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -38,8 +38,6 @@ static inline bool kasan_async_mode_enabled(void)
 
 #endif
 
-extern bool kasan_flag_async __ro_after_init;
-
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #else
-- 
2.33.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210913081424.48613-2-vincenzo.frascino%40arm.com.
