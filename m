Return-Path: <kasan-dev+bncBDX4HWEMTEBRB25O5T6AKGQENTAFPNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 1BF6029F4EB
	for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 20:26:36 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id l16sf1263771qvt.17
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 12:26:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603999595; cv=pass;
        d=google.com; s=arc-20160816;
        b=DgPT0QYWKGcHWiflQAzAEviASsTmcF0Ca/dJa93vIDtHXUC05NNI9waljyeWwUhoH4
         8HoYvarm1B9v6ANBZ/YPUiJFZgwCI8WJJse7GW5pWNTB8jghn4KRqRfyaZK2BiJ9U/Lb
         PTTYzS2rxwV88lLmmGj6mx60BNGHm+FtWdrUdwtPoX+Ukf2hot0RqSoYPi+utTVpegSn
         m8TvrzQhp1pWgcWTEPfX/wzJ4d67ZlbP4x4rb1H7aPQUl1+3SUVmkoyHc0XSe6GpXdPO
         MaeZfb6DJT2NLFKZL/K5G2bEvJmyj6QdIyCOVRNfu1wrUymbK4NEhREMLZDowgTemVee
         3mxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=+7q7hQ4MJrcdnwL3mDcrR49H7Gp75hTwb21ODVDdXm8=;
        b=UAH1v9E1AOmVv/2BKDPZbKz1STOoaCVKyLwPzN3qJk+ubQM8QITiaSjQi4OyXgTOwD
         K85TVMpI8zOn7vDXBfcGB1krCaQ1uYtFLYEcg3grARCegJbmFZpDTepBYHQp4ju+pfAh
         kUIqxQE5vfl3cuQw/iJGBpmdYe5OCVdKWNd3OfRGW/MUIQxm4KX0ZMjoSjOh0IgZ9jee
         K7rtkvPmPJJWRX/yPTFE8d8rFuH75LB7mLAu9EWiRXDpad2EoJUTbyCLwJM0HSjv//1C
         +tgjQpQltFFp8Y3aO/A80294doOUoixwG6AYXiNx+HS7w4iCOS+u7yAbRBk1VAcyMYPn
         6KnQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g2qMPTpM;
       spf=pass (google.com: domain of 3ahebxwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ahebXwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+7q7hQ4MJrcdnwL3mDcrR49H7Gp75hTwb21ODVDdXm8=;
        b=WbY3xolC8CepVYsK9Uk2kFWDl9+4Q4W7+c+YzyHRYrgCfBCCTQIziDeys8c+jn1UM0
         OI0UX22MbbpDoVjO2yiJzAexRyHolUQWI/FS/uFettA0tLA7XS7c6RogURUgF3t7Sm4s
         alqRfNUVibahm02kj6PWw2Div+iDT+ZP3scZ4iUwYUYPy7wNQxajcLCO7TTsipaZNwaz
         5mvEhePLpzAK4Y+k7qNqwfK+VHBC9vnTIDutmPNutEu6f1CGB1yqcdauRE8TP4J6I3wK
         RLzf4jXT8YRZysHCs7raJLld0ERPwhjP0OnYMGXd2nhhQlAYe30CuZeDGSLqYQt9Cokk
         h73g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+7q7hQ4MJrcdnwL3mDcrR49H7Gp75hTwb21ODVDdXm8=;
        b=kg4vuejLiiBZw+mHTsNwe9bbxpjKvz/7tdK31nshJ756xdbfOGyEHJtxCvI8bEne5T
         d+5KptSgPFlGc1qXkM/Hi+4YIPmWGMg6rX0Qz/CFQvzNSrcLVrA1sSgzla8Dup+dLem4
         L1aI9ufLFtAfwodaBbMNbaAawb/DmCLgjXW2D7EXLDIH7FalY4tsyRiyjf86/0DjiF3z
         qmoY9j14WjfJSUVw1hJs759/tIp2g6hHdI2FzGG85nW8kHJLNaaFpxjdSN3u2KMe6TIv
         fsdert4gjtNKKaOidlJRV41u2PR+Q4mS1Kkmz1a0GwuQLg9oOAceA0VNJRyuZXNAA5V3
         FYzw==
X-Gm-Message-State: AOAM532DiyPv6Jp58ew5w3cRaHxeAnsLE1+i4jUE2tkrIQj0WHy27QIC
	HLsTv/cxJSVdbEAPhI3FExk=
X-Google-Smtp-Source: ABdhPJxe1ceogzh29zsgskag/iJEyIfs6b17iUncXfI/JiSf+MYPLMfVqNUQlcjmqnqd0B0Y/vn77A==
X-Received: by 2002:ac8:8b8:: with SMTP id v53mr5100022qth.387.1603999595159;
        Thu, 29 Oct 2020 12:26:35 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:80af:: with SMTP id 44ls1017151qvb.2.gmail; Thu, 29 Oct
 2020 12:26:34 -0700 (PDT)
X-Received: by 2002:a05:6214:16c5:: with SMTP id d5mr5534638qvz.42.1603999594728;
        Thu, 29 Oct 2020 12:26:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603999594; cv=none;
        d=google.com; s=arc-20160816;
        b=qpUtXB1ggFhFxxG3XvDepUM1JaKiTANbrUiYeG8qotJjE18cOenC5VgkBF6rwnJxeM
         kb4MT4ZeV4+9dIrM1AGlVNej2tZHajEaikydIcLtJITVf50M4fUcpN8k0ffVJLjlDChf
         EyIhG8htNRMeSr1YRavdVDNDQLGZ7g1UrhG9EZU6Fw5W9g8Jl7qQG/ShhxVOxH2DDDdK
         q7P7thuRcmMgzk2/2Xj1QjSmEie3isOsIGOpxw73taCkIhpSavMYqKYR0nqmSw69an81
         pga3K+iy87tHw6A4WnkZVywqyRo/hT1fp8f4FN689IZC7npIDudTMpbMWiY8qFzuv0Vj
         dkRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LIY2nrONxUEpI3abKUGgXLbsvOzrU8dATPLwmTEHaeU=;
        b=cg9Rfh65/BPviZNWu4ckPQ+mM7HeK3JQTcPFgYTJo/lSqsLcZ41pSEkcgOB+9mLIMS
         vIVbQ2ZsHJHl0yCwhLm8Hr7uI8B89peKFo3+OVoBQhzWqgIZpwTWaeSCbjOhsKMcq1rw
         wfMKaSFNchlVCvI5/ULUgYLBLfF0zkg8GuQzAcn/+zmia8rI7RbyLEMDh0EwA0fS0xyF
         7mXpEW5wNNlGLA0wNlJuDBM0T0WKPiLuXleuMyo1aMvlb4eidzhaFTz6vr3OmBqmLREZ
         KPCIa5tIrUaOAyxSbj/TN7SueXBOZQh9A9/rc3FQLJcNmQ2MZ6hi2CqrU1vxE4BH3jKe
         zx7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=g2qMPTpM;
       spf=pass (google.com: domain of 3ahebxwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ahebXwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id h21si181770qka.7.2020.10.29.12.26.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 12:26:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ahebxwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id n23so1353860qkn.1
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 12:26:34 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:b48d:: with SMTP id
 c13mr5755976qve.13.1603999594373; Thu, 29 Oct 2020 12:26:34 -0700 (PDT)
Date: Thu, 29 Oct 2020 20:25:32 +0100
In-Reply-To: <cover.1603999489.git.andreyknvl@google.com>
Message-Id: <d06c8e518e50d119785963b596fafacfdd6846b9.1603999489.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603999489.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v6 11/40] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=g2qMPTpM;       spf=pass
 (google.com: domain of 3ahebxwokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3ahebXwoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d06c8e518e50d119785963b596fafacfdd6846b9.1603999489.git.andreyknvl%40google.com.
