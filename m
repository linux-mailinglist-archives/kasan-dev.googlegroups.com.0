Return-Path: <kasan-dev+bncBDX4HWEMTEBRB6WD3H5QKGQE6XRBXKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 27C8D280AED
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Oct 2020 01:10:51 +0200 (CEST)
Received: by mail-lf1-x13d.google.com with SMTP id 1sf51756lfq.18
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 16:10:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601593850; cv=pass;
        d=google.com; s=arc-20160816;
        b=lLEowv3ej6FYmJy1bY6hgKrBy6qWm2Rh8fEUyoyplvyoV9dO/LKu1SPtG7JIUX/pz3
         fAgb5sMCI37raM1uqJj1q/TzO+L04MjaAM6FtROttgkeIxhasMruHn6YFvkS87mlbD6g
         G/lNFrJyyrdLJ+c4W0GlVrS5s4eDfThb5KA9x6/uB/m6gkDNFEkd62IrSuombMOSOO/P
         5jvfxXpHrjLOqU/4XM7keamd6sJLNfPoB2iZ544TiOSrwT7SY1KHfxeDLG2oOOqJRWjr
         6dd86tbMxm63olMpANSJ42WaB+1iF/Z4MzSeOHbTu/u5nXWFWFBdiV+/RMcuHkqO9z4b
         Gwjg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=YrN6fEXkHEwlpxxv6kWJsmZ6uZH4BkIN0uSeD7xx5rc=;
        b=MBx/98TRmCFgsU5QRs6iHMHNZ76LzcrSskNrBkrx6H66CD3o6TQp6y42eaiHwKneHO
         g0nIfdMkj81JBSrl0d7JwTwb56k98NLqzQBeB7CDbOuqs8C/f6b6wza1F+Skl3WWuZON
         6AsuuXSp45Wt37pcssyuvsLseZLgzrW4pm4dYfAzQfr5SUHcqvyNxKiK4oTQT1W4rdU5
         lvfKLs7SAxRpxWnkPum5JUwVl8Qpw4yAKkr+4GR8swRB26Xo9f9a747ZAJlV5pNkeNbd
         cRbpY15HtMdS3Noue43M4n579hDXmCE/8kfkC/7/9GYF02J5ktCstS2ohDgCHYa0tc0D
         qh/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q1pZ45jU;
       spf=pass (google.com: domain of 3-gf2xwokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3-GF2XwoKCZc1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YrN6fEXkHEwlpxxv6kWJsmZ6uZH4BkIN0uSeD7xx5rc=;
        b=IMBOz2INl2sFVbWTbN+lS05tTWLyUraBxnC9VBS+pi4jrw/PG/jskowH4awzyTX5Ff
         rsKMYhFfW1rYpMaHVWUWKxfHfv3+8c72qVeA4OErx10UYdtPiJiymo/bjT0Q+pu3Ls+u
         5ePt2tb7ZL4x1HOPJkhOExzlitx4Qrkt5qNV7qxnpIiMrEwybI1knOovaVDQI9Out5il
         EKhNxr1hsADvjxI2hc7LlkGSBjEj+k8QRU8vw9GpRM+5buooN6TJZi3t8UjTrN9snG0y
         L0LW/iICLNoHyl/ZUfRQuY2CoeUKJcD+cmjqWncVPMzvVhsA7CgcSHch081GsvgmSiQX
         sitQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YrN6fEXkHEwlpxxv6kWJsmZ6uZH4BkIN0uSeD7xx5rc=;
        b=dacDgCXvZIYLTTUqD17JeRG8qSNX458lnt0T+AHvKbRS6FpFtDlhY6pFMuJgiqX1zp
         A71GCInVZMLt04PysqpdPpo8uU/f8W100C6yC7zGI8DglkEbEjj1Nu7gixXJSa5rGv0Q
         DHt8wGMdnCrOsRDquejy6Gb7sSdWqJbmtYhF+dXT/d3c7nrqrgax0kUFtRdlLJiMrntz
         6AtLoJEJXwla7e9MbqBH42g3FHYICWF3KpYxhitF/FtR2JcGLBrrVWPxhnXFIOt/4EO4
         qWwER1uuEZDDLzXWlVJ7W8KE7Elfv5yqfGAsmnw5N0g3avSdzvA12C36sRChmPz+7JB5
         brEQ==
X-Gm-Message-State: AOAM532bU26z9PPfeO8QTs5lxEDuTYLwMdalg5n+7MLpFH/xq7owfkIv
	tN7nFJwyKRokiEN5ws2iIWA=
X-Google-Smtp-Source: ABdhPJw83CvJQpsNHOkMixs5ntNHC1DOL81gY3FcPQQI1uwhQe87KtEdI72aoh85ZaQqDpj8VnSxyA==
X-Received: by 2002:a19:457:: with SMTP id 84mr3246732lfe.205.1601593850677;
        Thu, 01 Oct 2020 16:10:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:3c13:: with SMTP id j19ls1070654lja.10.gmail; Thu, 01
 Oct 2020 16:10:49 -0700 (PDT)
X-Received: by 2002:a2e:7c14:: with SMTP id x20mr3336032ljc.220.1601593849568;
        Thu, 01 Oct 2020 16:10:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601593849; cv=none;
        d=google.com; s=arc-20160816;
        b=s9aWb/UUmwKKcd3Fezkac1naMCg01PLXX2kfaYsIJWIqHczTm/CqWUJortE3b/eXpJ
         N7UKcCrPswrDcgrMOVTAm+NFwXl0HDzzgBWHD5oCKQk38W9L0+AMHSWwuTrdRUpg+/DP
         6SK8VsObtg3wDx2+ByL3VMsDj55uPlmf3x2QyVHDAEtLs04fUmbjOMUCSQoM2EPVvIo1
         JIULMnUPaJo8KLiSEqCE2XCbiDxhC8OHAKccTb4S5fGetlJv8E5Xy/sV9vq+sy9fRfiF
         VNPfjrN/2zSVg96S1pEgX8FLrS8mwoiO2O7VY1PuPSpN1Tjf7aQGwGTA4um6CMzg7rbv
         tY4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Tqg/PaARbGGjCbcEwXf/kx8hqamrKXV0hm6ycbrMYh0=;
        b=wwvwc2s75hov8Ed7FCJft/m+I8gQFDLcPnrKYRFCKl9I3HM/q2kWfapO858R4iCH6/
         3n5+AvqNzV5v5xKn0lIFOmHhXb2X0Gj12kUZ+CW9Eji4kw39b/ydH8cUie0qb38e5ekS
         RGwDUlOKXSlZWjIMlcmjC3H3wNUwfjwE/acN0p18NdKO3gIZgtgcRTEKtMEAeiQ/cU6V
         h5o3fDZepCZ1kHFQVvvlDyA/6x0cYicy3HUKmsfgsClfK5+v8J8gCq2iY2I4Bqotm8cq
         GWLeMSpDgI6ByPs39up9nNif332hMeukk069gvqDhoshemzw0kfGmV7tXqUAQ1d8gfyr
         YIcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=q1pZ45jU;
       spf=pass (google.com: domain of 3-gf2xwokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3-GF2XwoKCZc1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f12si206116lfs.1.2020.10.01.16.10.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 16:10:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3-gf2xwokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id a12so119629wrg.13
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 16:10:49 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:2146:: with SMTP id
 v6mr2207908wml.159.1601593848953; Thu, 01 Oct 2020 16:10:48 -0700 (PDT)
Date: Fri,  2 Oct 2020 01:10:03 +0200
In-Reply-To: <cover.1601593784.git.andreyknvl@google.com>
Message-Id: <ce172045681b07836b42e5d9761be8d2d6d98b06.1601593784.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1601593784.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.709.gb0816b6eb0-goog
Subject: [PATCH v4 02/39] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=q1pZ45jU;       spf=pass
 (google.com: domain of 3-gf2xwokczc1e4i5pbemc7ff7c5.3fdb1j1e-45m7ff7c57iflgj.3fd@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3-GF2XwoKCZc1E4I5PBEMC7FF7C5.3FDB1J1E-45M7FF7C57IFLGJ.3FD@flex--andreyknvl.bounces.google.com;
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
index 047b53dbfd58..e1d55331b618 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -156,7 +156,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.28.0.709.gb0816b6eb0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ce172045681b07836b42e5d9761be8d2d6d98b06.1601593784.git.andreyknvl%40google.com.
