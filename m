Return-Path: <kasan-dev+bncBDX4HWEMTEBRBAFAVT6QKGQETKQGSSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 814852AE2A8
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:11:12 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id y1sf1858776wma.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:11:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046272; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ckMqc/i/XouxkC6CtXl/4FQY56gbcE2Qlv/sS0TZ2payyJ4McdMfIo9h3wvjF18qU
         JAjy+jymizQGuYehw6NhEQuVCG0yHXJUjdfFR5z8lkEGQ0bp1kH3q9vHzw6IqOmGrMr4
         jZrCLLzmPA1dw6aVc1OFHhpeQGy+atEcRT1oCD45gvzYJell3HxhkaBsiV5yr3CuBKnS
         wbibEY6uemEbyXG4aO6cJX10MhLoV9Ow6wc3GCa53X4c5Fh8PT5ZkHMqAdpHb1ACoVK+
         ZF6MverZ9UHTkYLC92CBw/s4qJ/iLev2OJixd7hlMdTf9NypQ5oRfwndhit6IYD8Qy2P
         I5Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=QWU8vrbeDUXfZx+UYgmQjbM7+ETiH1mTUiwAMBvh0ts=;
        b=uPhKTUBD9lWqNkwe47mOkN3DZqcoFh3rX1pgs6E0G0Hyp3fUF4cGdmL8NYVAh3H+l5
         NKJAj5j1o2Mcb6UYhz3LXJRh327UmMEeDHVZzkcMFrXPilAcs6RpFuFXsQO5ec9Vjw2P
         cEWWkBAXV5HJSbDZDjnY7SiOH4ioErQDxb3VsXLDEhL4shsldzjYzO1NKNbwkvgm8TuG
         V28McerHWXw1OHUCzHrYR8ZlDntZx0UJWRBq/udYWEXKah3WQ9kbivFlvy3KdzgVsZ10
         RdifY5VfUUXUSwfH/bQ/J/F3THXUaWixzXUATxzX3Zztd2F2TOxgUtXiTbhUDREqf+Ki
         RLkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vg43E0A6;
       spf=pass (google.com: domain of 3_g-rxwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3_g-rXwoKCc0t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QWU8vrbeDUXfZx+UYgmQjbM7+ETiH1mTUiwAMBvh0ts=;
        b=T4C8fQpXKuoqDTiF3iAFyjwwNapFDwlQCkfuwsc0a8rzoqIBE/hvPcmYs8VjqQ67Xm
         TEF/KzneCGDCH/TnHAFNtU2zBxIbfru8M0I1T/4fdI4aC6PHM3n9Iriv0d/4qFC7mZAX
         AVtTCDz7WndT77F018PxvWdL+O93FCg6PaCCnN6nuqyMcS217vAsO25ms9UWWhbhKccd
         3vrroZRUXGb2xrcoMMtFwGEumXVkzm/SdhUZQB9tXQYPer4rjhPDCPO3pvNMkvslN3wq
         8FMZiOdLTapM0Llii1mmFmBYxxCkFhiJgP33damB44qdyhuCK8F7e+VlFf54mpbokiVF
         9/AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QWU8vrbeDUXfZx+UYgmQjbM7+ETiH1mTUiwAMBvh0ts=;
        b=CcY/jE2edTvU2UvmriOZv8X4KaEOMJqYiXzxw4umjJc2qozqVarA7ajzUhBUUOZNGV
         3+zVlkkO6oWCOWDHOIIKLYfDesVme8UzYIVLQUgILWbAgOYkxSH4NvF3hMeZVH3IjG98
         b9Ur2PniIBGUJUlVJ15VWtmTdcwF8je+RK0c81JCQRKQuopZuqy4M9hpy29VLNSpiU/f
         b6+qV1HKgVRrlqH/M5+TZKjsaemQKzonS2gHGB4r1CIuMX+sMPrbSELeoT3nMEx1GxuE
         ZWpdD+PXs/OVPsFQsI1hjyQrpfSPnz5uj+mKDo1ywI49pZ4HSQY7+jzL9CWehkFKIf/j
         Yvtg==
X-Gm-Message-State: AOAM531q8BJVsarwPX/keGIONSHIV4PE5RwwBdnHdSkCbI4hVtHFCiai
	YcSpcNfgR2wPK6bxS0gY/n8=
X-Google-Smtp-Source: ABdhPJwPvJwZegrnCoCqATWLG7GwjijgxEGFRAfswHPO1E5znHWspVM27bnVoGHuYh6p3hMfZYWcGw==
X-Received: by 2002:adf:fb06:: with SMTP id c6mr27655672wrr.117.1605046272249;
        Tue, 10 Nov 2020 14:11:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:1bc1:: with SMTP id b184ls209966wmb.1.canary-gmail; Tue,
 10 Nov 2020 14:11:11 -0800 (PST)
X-Received: by 2002:a1c:6508:: with SMTP id z8mr273322wmb.80.1605046271345;
        Tue, 10 Nov 2020 14:11:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046271; cv=none;
        d=google.com; s=arc-20160816;
        b=KIrdry4dk8EMG85VPdPd6AjEcjsTIfxzaNUiCpuUepw1p2xU5Nc/PVNWC84t7UptMT
         exwQk1818Gsmwe243fs0CBYciyQDjcJj7P0eCy4ty1b+9ktGyWzM4i5T6EQY/pIYLp3i
         +M7XFa4ZjeRMoZXe9Of5qxW2VdrnonpgD5bzf1Y1oZVOJIgPkLl+HqkW1tgSnmvAgVhm
         BO5o0CqoxX7AhICD753c+NQpaSufYtyx3IVx2bw1QCH5RQlNcvG2qd3o2jcw4K1otrFD
         uNRYyGIkikeCP1a/vvhwDKFC9Nc+Mvg/yAfrveRhEmWq9lUv/oUKVPY3NWThE9y6UjAc
         LE7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=+WfGVmUcfITRHEHJPKcL2vISbLS+w5GU8CW99F+itqc=;
        b=NCJpDlw64x3iVdAUJcrVdM4S2ydWgW+AYbQsNKd43VnA9yeoTrj1CslT0u4fg5wj0n
         AAaToeZoSt4G1PxJhkNV2h+9miLM2k7sowedCkbctEiQFx+riQ6vunwdJ6SWJGmxdr5m
         BHhPlRLNr0rMCOpwai4BISgF0XUzJRWRTqunH41BrBL/wTz9S38O1RJAyxOj08bDpfAy
         nhx3rjpT7/BUL50B5AVyfJYsFp2EGS8bEZx7xVwObhdAWCpc8rkEWLzNHaQIqat79jqv
         8yaQbyVvrVgAt3E9pGXAeytIcfj8BfNJz3Q+RQ/j6rfObs26VKHIOzoKH1+vKkOzH7Vd
         A6OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vg43E0A6;
       spf=pass (google.com: domain of 3_g-rxwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3_g-rXwoKCc0t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id p16si4316wmc.1.2020.11.10.14.11.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:11:11 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_g-rxwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id c8so1159691wrh.16
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:11:11 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:ce99:: with SMTP id
 q25mr243582wmj.35.1605046270971; Tue, 10 Nov 2020 14:11:10 -0800 (PST)
Date: Tue, 10 Nov 2020 23:09:59 +0100
In-Reply-To: <cover.1605046192.git.andreyknvl@google.com>
Message-Id: <24a25ef0fcfa07a94129e2ae5ec72f829c57ac42.1605046192.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046192.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v9 02/44] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
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
 header.i=@google.com header.s=20161025 header.b=vg43E0A6;       spf=pass
 (google.com: domain of 3_g-rxwokcc0t6waxh36e4z77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3_g-rXwoKCc0t6wAxH36E4z77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--andreyknvl.bounces.google.com;
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

Currently only generic KASAN mode supports vmalloc, reflect that
in the config.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 542a9c18398e..8f0742a0f23e 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -155,7 +155,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/24a25ef0fcfa07a94129e2ae5ec72f829c57ac42.1605046192.git.andreyknvl%40google.com.
