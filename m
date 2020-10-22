Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2UNY36AKGQEFVQLWAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9DF62295FAE
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:19:38 +0200 (CEST)
Received: by mail-ed1-x53e.google.com with SMTP id dn20sf663663edb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:19:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372778; cv=pass;
        d=google.com; s=arc-20160816;
        b=pw3LaJgLvXNpBhpmBPpS+yztjfFfueHbRBgpjYZC6mfS3Kfn39H9nhgwXkqOmQUEDX
         xAduIqEpM4WqtaLwQlYV7645Yh86+dAUuVHFG9fHCAIKttFQ3a76rVuK7bxB7GOiBVOb
         yL1/bI3lwMKQmnZLrvMDlwoXI5Yy5vze+6d/Y1VjsgVoXeKsvKu++v0226fsOYWpls74
         jCxVsagSkHeQZPqvZ9ILZ6F19T5wNMT0ygVHBXa55BqPUf4WFI0V0dfJ9qYb8GjEQoZv
         UFxHgAfmpBLKVyoPZhI64fXCdwyLmy846dKcEHugPBdgmJoDrKv1OKNKpcnQMRIGqId4
         efHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=MhG7BzZpzR+axjcXfY3SPudc5BBZ5C/5bi6UEg8RRwI=;
        b=OWd3dGY8S/+DO/SJJ+UVQjOEsAjxKSc2PAXSIbxgRcaLakN6QhsrHRHPs3CU5Mt34m
         CzFvHzODmPEhF2ZtruCmDSjufWgBHv5bDNNpzarWUU404gFr6fEg5QD/EnKQPruRwbmT
         nKK6GpJQFmWdiAorbpgo7bE69ZsIqcLSw9aN8Qm5dFYZkH9IZEFzcV0hfpsYED5RN5wY
         H9HNXjnZMcSeDlskRN9lDRByR+lvHMV6KnbTPx94XO9RRGqssNr2nwDbDxxGHt3KX7Dj
         escZnx8lJZzTAHGH9nwHLX1HZH8oXyJpdki2W4Epf65aXJK9kVHavutR730gDFzNds2N
         NIig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FFBTC951;
       spf=pass (google.com: domain of 36iarxwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36IaRXwoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=MhG7BzZpzR+axjcXfY3SPudc5BBZ5C/5bi6UEg8RRwI=;
        b=sDS2DtwFbYnmRNiYSOxGtBMj1rTkrHgsudp2SDHm7aZQBP8KWYx873v/t0Ysrb0w31
         hboQFOesmhyWJA86H+RAK6we3kbP0ZNeNfGncyGxhk2FhsJ/xnxw7Lf/OJPhhSMCV5GM
         DP/7NLkdIpsGFZYzSpmlbww8dkoHJmjePKs3z8w4Uzv3sIe8ZyaGOdMZ/bAv/d01l46Q
         VQWcOAxGRtL77/4JETcOw8vtswg+lH0rW5WP7b1L+FitB0avdE8QGyRjH8wF+YsJ5b5R
         TuwxpjS1A0mmk4DXiiMVEz6LZgWsSQwpYrgMb59E7/rDfuKQtu9ssQ1900AfS5s/EAM1
         NnCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MhG7BzZpzR+axjcXfY3SPudc5BBZ5C/5bi6UEg8RRwI=;
        b=F3ujflAUAsqifkfGenxdxtbuSEAl/k5c6IDyyO1YpFAdohPn9mh9nUAuqUrrm4hmIN
         2+s9mmaMMQpX83QtgQQobPaWRZXImsi4vEh4S2auRb3LDf0HkCVkw2ojE1DxEDqcWDtW
         P6iP0xeGSfO2BHbSR+rlSwV96YuZnF3ktBpBfcoO2Id11Od5nUt+6JlutvdvjUhqYG1N
         vylAj8407caV0nRF5KSBMxir15VErExMibUXib4XHNgRsIhkxCtdJ8Jq+E2VsVbarUSU
         CBq/KeHh9tb1vG6HINjCR72ioD9JhtrHyzJKFV+REQ5Q1NVrBdaLeY28vlXUNamRQiIu
         85LQ==
X-Gm-Message-State: AOAM532CYQmCHHW0cn2VcSfhUW1DEY+n0LiIGQqLXNuP0OZ/o/I3mpB8
	zeJLgsq2x0FjHALRQmZOzgg=
X-Google-Smtp-Source: ABdhPJzWIN+xgpSf4tyUKhBuKbkjVOqkBa2T8cjjcnchy9rXpSRK7waKFdKCDy8B5uAno/jjxy0uIg==
X-Received: by 2002:a05:6402:1148:: with SMTP id g8mr2257881edw.271.1603372778370;
        Thu, 22 Oct 2020 06:19:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:2319:: with SMTP id l25ls848432eja.5.gmail; Thu, 22
 Oct 2020 06:19:37 -0700 (PDT)
X-Received: by 2002:a17:906:a4b:: with SMTP id x11mr2312282ejf.11.1603372777368;
        Thu, 22 Oct 2020 06:19:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372777; cv=none;
        d=google.com; s=arc-20160816;
        b=gGGakU/Ovdq52yce6IOiGuIKug1abW7oKnxwq7S6YUR6oY6InhWqhah1CoTAkUyR1r
         mhIIY5m1ijkgMSSoRD/y3c70+XeC3ofctNG3w5m1Run7r4Ut8pQwIrKBrLc5RxCDnJK5
         pZtCWqDhByQ6MD4ngSG+IT+42NToHI55ZBV7ifeE172nCUsb5Ayel1l7ZTRpG5QCLiww
         O4F1OAxqMiivJ+Z8t6T72EWHFJqzSC6AZeOAanlIJ8LFN4cC+8EZP76nkmHQ7MRI2qkB
         ewdrqEYZ8YXTEqArRUzb85na7VXiqh3GFFcGKw7vNTXyOFYbc9KT/adMfRxvOhU6lSJF
         m55Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hz6KTz5FwSVcKdBcrWKk1T0dlNcGWPgygtgKcp7KEb8=;
        b=oyDEHGGX1fho5WRKRXjIushi5wb1QGQoEm2baPvlZvJGw3IYcWF6LfWNhVB7TSVa7R
         oCvnEnSIbGbymulFzmwIwZZRW18up61gzTrlMkMLONNyGailruvkeJBLynJcVLQdhFXs
         b0T/nyKBY2JHFGt0zmeCohmQTzB3vUt/mAy1qPoYkxReJvEV7mouL6ZvzmDHz+u6rxz9
         2u1X/C5MFHRUqC1vJxcQMwSSQCkZNFni4Mey2fcbXXB8qgHrDiFMHGyQF8dYcDGM8kLc
         QlCSRK/+opJHP9VI/xW2aCVAhsSV13Lb0c+t39Lw8+7/9pwWsoYgnTXUJpSTP1MkUe+f
         ilew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FFBTC951;
       spf=pass (google.com: domain of 36iarxwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36IaRXwoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id u13si30075edb.0.2020.10.22.06.19.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of 36iarxwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id m20so610762wrb.21
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:37 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:108:: with SMTP id
 o8mr2676067wrx.256.1603372776882; Thu, 22 Oct 2020 06:19:36 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:18:57 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <1049f02fb4132390a6a314eb21dccfe5500e69d6.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 05/21] kasan: allow VMAP_STACK for HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FFBTC951;       spf=pass
 (google.com: domain of 36iarxwokct8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=36IaRXwoKCT8boesfzlowmhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--andreyknvl.bounces.google.com;
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

Even though hardware tag-based mode currently doesn't support checking
vmalloc allocations, it doesn't use shadow memory and works with
VMAP_STACK as is.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I3552cbc12321dec82cd7372676e9372a2eb452ac
---
 arch/Kconfig | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/arch/Kconfig b/arch/Kconfig
index af14a567b493..3caf7bcdcf93 100644
--- a/arch/Kconfig
+++ b/arch/Kconfig
@@ -868,7 +868,7 @@ config VMAP_STACK
 	default y
 	bool "Use a virtually-mapped stack"
 	depends on HAVE_ARCH_VMAP_STACK
-	depends on !KASAN || KASAN_VMALLOC
+	depends on !(KASAN_GENERIC || KASAN_SW_TAGS) || KASAN_VMALLOC
 	help
 	  Enable this if you want the use virtually-mapped kernel stacks
 	  with guard pages.  This causes kernel stack overflows to be
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1049f02fb4132390a6a314eb21dccfe5500e69d6.1603372719.git.andreyknvl%40google.com.
