Return-Path: <kasan-dev+bncBDX4HWEMTEBRBD4MXT6QKGQEGUQFPKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x338.google.com (mail-ot1-x338.google.com [IPv6:2607:f8b0:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id B706E2B2832
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:52 +0100 (CET)
Received: by mail-ot1-x338.google.com with SMTP id i7sf3073889otp.14
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305871; cv=pass;
        d=google.com; s=arc-20160816;
        b=T9Zla3bwA/edq26U/fYObDO0ATh2d7NwhjE1jSMMGq0LFalDhYqaAyEgrrxWuofdFV
         cflvnZDYW6lQOJ5iZ1n41BU4KLJEsosI+hrlqmEJ3aLxmWA6pM7RthHz4q8Am+7p/BA3
         7ZUpgNJOCy/3uTH/OjP3KDUlBFR410nObm/8/geO2gt2PZMVZp48QheH8Tly1lZBrDuT
         93u+5Dek/fNBGfJUO2TY8hRQmz6hHGhwD+t/TrSoHNszr3pU6EOhPhvELUV9OCIGS+/H
         NuV5jmneOtAJ5+VLWNmKFrLaNDdN4sh0DfGXO5dnIKVJRyZ80YL7NDbXg27uWKuTWEtW
         5HxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=49JqDgV6qFFZKXWHM9UNMefUPIo9Mes6VgloOAPreig=;
        b=pXd1yCjd6mQxxFuktwD/3Dh60tsatxlkpfuPEr9JPC9I+s27Dk5RBK2J+W9uie8RiG
         btmE+vW5x1Vd6wIqtXvt6IwIMjYQR1oyVEsYsyuhrGlx2vh0hVIS6IRD1IW1UL5aXw4f
         3JC9hhA1tX4BV1FKmqknoj1fh5FRDxTO0YIGVLsg1LCzRZ4LBFgt3HzJcrTsyCb2BC24
         Fu9yB5HoeQwsvPep0AkiNEvjvXV/cEKeYc7eB0WkfK1pHIusb3kY8xHoAHjI1yKyYXu9
         ZHTpNDxuNs2MdqkWRaADshGV2oLHsnwrzdD/2SpLUBMtWEqmeKwwzzcYIHhZGa5WwE9Q
         MiSQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dThXa5Fe;
       spf=pass (google.com: domain of 3dwavxwokcdo6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3DwavXwoKCdo6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=49JqDgV6qFFZKXWHM9UNMefUPIo9Mes6VgloOAPreig=;
        b=gig67gbotBTOFUIYzTSMCMC69F+fBxDe6sXs6eAh6LCrdBjSj2KBYQvTYvQ4SQcjCO
         cJ0foO2OuUU1VWQcqoyf1mGwTcbqz27DYBg0TPzxcdO/918AFURVvhO/3qD7XGX63RQa
         4L3M5Gte+3RfZfrzGQrqQqSTU/DTiSmtvc5WMsCjxSaNIlUrz/wE8/9m0K4VMheHccfm
         kDqdmdZIq2b+CDxFe3kpq5LrN18eTT3LJ3CkLTsOTAIm/1+nlb85ZWfSkrEaTvntbVXf
         a/9BARp0v7KeOITnyoggd2m2ZFQ9lNqW8ULgVr/kEizZ6tt2whQ9XYOaaGbBOJO9hdAb
         w5mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=49JqDgV6qFFZKXWHM9UNMefUPIo9Mes6VgloOAPreig=;
        b=S1Ypn1PZG2tKlJeHHjAWlYfSZ2RiOau82FDdHdwRbhBeK+EwnizGsACffad6w7/Eqq
         B9ngJXHDdqB77W/cqipxFkrFLBA00XpJwhnvCEHGBLNUrBHBDUBI4mrKeSxjEPzXxn8V
         e3Y+NNu5g1HCQsGgbTbfh9cERfU1MCw8tB966fNSAbx/vNDdTRnw6V8VG+nzDJlRp4ao
         OknDsUUD0+CEBwfCXa4oOGou/9FdEgDydv8c7oBXbe9q9L8s68HyhrU7pgnTU4UWTvnd
         G0klfvammDJPRGIiTM36uqfQuVhiN5ozCM5fCVUFzExWINaPnuQnkM9EJVRAg7O+hqRj
         FAFw==
X-Gm-Message-State: AOAM530eySXSyhxJfTVaTioy3jrPUO2M+sIsJtF7nPv73bP866UfFLpV
	ZfOEz84IQgv7IuToJ6cRtNk=
X-Google-Smtp-Source: ABdhPJw0L4SX0Df/rLAbCUbLVE6T3tHkjitWK944YKpoUsLruDVhhiNPmR+MZ+tsZbt5G1U8qVT8Fg==
X-Received: by 2002:aca:2b0c:: with SMTP id i12mr3055337oik.72.1605305871792;
        Fri, 13 Nov 2020 14:17:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:a843:: with SMTP id r64ls1845044oie.2.gmail; Fri, 13 Nov
 2020 14:17:51 -0800 (PST)
X-Received: by 2002:aca:919:: with SMTP id 25mr3074891oij.3.1605305871491;
        Fri, 13 Nov 2020 14:17:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305871; cv=none;
        d=google.com; s=arc-20160816;
        b=P1ujC9VtZz9LY05bSTkSZAQ8NPVBUPHoYPXcWWPWZN1lEJNEztCx3gB2caEmqk5jBO
         uVAj1+OMGjao7QteYhiKaqBHwxOolzNcTTeOsrA2+oTHHI5jNmp44H6gLEe2y0OznFi+
         fjCcMGCNGLpvWTthE8YWd6QSOSwvp7OCLLo9N6z1v0z0uM/khF1S2SCTqNzi6WAS12LR
         6gFYiChf+oXFQz/lj4GII1/jN/RB7Y3KdLHIYcyB/YND8MC4nQcBPuOMOu8mi3XYvvXI
         uLctOB9Lsv3LPNvSW5+XxS1h7+51NXprPZs6d0AnHKYSQMjVP/RHclIJzh72Dl61qmwG
         IShw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=xwfpXyrGyTT8uiupaW5ZYtlwdHToRfd3Od6MwRYYRNc=;
        b=LFDjaq5tq6RKct1/Gk/FJTeTN9bfAFSFhkNJKMPry/eiX4eZGtiBUhegMbu1fsHWxW
         ULgZXri2AT1F9aEaZhW+z8PEQtZb3Z80cvkPiAyBw8ctWTdSTOBfe+G2F7+rcWOB7Aw7
         5e+weLisHxa6jecT+uVfkFq45bDaSPbOfBj8pt0PXan0m0lfqs27IeGsddrU26XdlJe/
         lDjlpVbhpMrcoCb6v6YeSs4oYm2exkypIB3Cv0SIWDfoDL+oxiz88VJDNywT2fs8Z9dM
         Ym/0O6JiEUp4pTGDcPuTigWdwFGdPwSCvxiOEL6Vj2FNIqvggewZySnUXfSIOHUZWXQ3
         d6kA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dThXa5Fe;
       spf=pass (google.com: domain of 3dwavxwokcdo6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3DwavXwoKCdo6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id f16si926640otc.0.2020.11.13.14.17.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:17:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3dwavxwokcdo6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id e22so6599649qte.22
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:17:51 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:4d84:: with SMTP id
 cv4mr4852557qvb.14.1605305871168; Fri, 13 Nov 2020 14:17:51 -0800 (PST)
Date: Fri, 13 Nov 2020 23:16:08 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <0355e2644c50417c41d3d2da23c95a50e122716b.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 40/42] kasan, arm64: enable CONFIG_KASAN_HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=dThXa5Fe;       spf=pass
 (google.com: domain of 3dwavxwokcdo6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3DwavXwoKCdo6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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

Hardware tag-based KASAN is now ready, enable the configuration option.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I6eb1eea770e6b61ad71c701231b8d815a7ccc853
---
 arch/arm64/Kconfig | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index b732c8280fc1..35e7cd2d7755 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -136,6 +136,7 @@ config ARM64
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN if !(ARM64_16K_PAGES && ARM64_VA_BITS_48)
 	select HAVE_ARCH_KASAN_SW_TAGS if (HAVE_ARCH_KASAN && !ARM64_MTE)
+	select HAVE_ARCH_KASAN_HW_TAGS if (HAVE_ARCH_KASAN && ARM64_MTE)
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0355e2644c50417c41d3d2da23c95a50e122716b.1605305705.git.andreyknvl%40google.com.
