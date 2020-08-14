Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKUT3P4QKGQENWZDNGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9637B244DCF
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 19:28:10 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id q16sf2187509lfm.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Aug 2020 10:28:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597426090; cv=pass;
        d=google.com; s=arc-20160816;
        b=r5Y1GGmLIAn12rzbxOWNXsM0rerG4BGDeF7ZyDNLDpURVubZSCiRF5RVocXCW+W2x6
         DzmXlGwjcCnGcpiNlmfwjOJyELgc+iejhn3s1yKu1YaVna34iFUeSfLWzTh0QLHvXox5
         K+OwI0d6BPP2V1BSRNlan6ecPY36087I7tHlm9sLXVVomeoOuriJ6wQ1xEzesNHAybwe
         oZk/sZdGMuPD2N8S7Ctw1KDraBespeEombwJs1AowoeYLy974dz7lZYsXXtClvpqu7Hp
         7xx+YZaT1Wr2dJt78BoQQLL/w/9NfyFMIW0ziYuYEmzq2i6l0hX70l417hMa2wNyWfrh
         8Sfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oHAkuwIE768So/3iOy4ldGnIoEjsU0vDy3WEoeGGTo8=;
        b=NlBdcxa78+jw5ElymHyHV7IYsUs9gml4tp7/jXAxhwD4nfBNVIsC+qvTI1WG4kL9Dp
         FecCAzpGzXJp+nIOE5SQribRAgTUnqEcU9mH5B625xyCjMWYAPv0TQiFamA6AcK2Z3JO
         pO/NUg+d5ENPdC9gNnIBULmYUcXv1OGduoavKBVhR+TBSd0Rlsn1oxhe3mRDt0mZ8kBc
         8to+McjbSrDeZWCWnTUJ2BT1pR7rlhvs4yo+UhnXcY+Y9YKH/26x30JCGdQYHO7Dqtn7
         E1x4m3x/xS9xGDl0HaXex/2A17zGTC4vQn7aBkZV+qafTS/uCm01Df+UZN9P5vz28yt5
         eIvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MpeccDbA;
       spf=pass (google.com: domain of 3qmk2xwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3qMk2XwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oHAkuwIE768So/3iOy4ldGnIoEjsU0vDy3WEoeGGTo8=;
        b=C64arzyDm80GngRKq25xLmDpyb8XSdsXZyn3Gh3XINDOOIjAXsnCJVwreIW+KpqMZd
         tHWzQDtgisSZWIvsiNq8qQdT02H++dna052U4rjqO/39bOn7EwNwmE0DYS17m51IRT+7
         +JgGJKsYaLGjCEDQSxAlbV5nJ+syev2xaAVgRlzv3QsgQ85gvl98AGRkC2V96bYkBQ6B
         vY5BUy0Zj+qtkxefIGQv9jxz7CsaEmIw3mJINfgMmw/igLq/7FrQ0Uw/2prxsY4ZFa6J
         Ufh1o91dghBXaJwEkiGeH7Nn2TMVS95SQrcfbvh4D5+nRSWcUni/2+224dZYYY8x6wiB
         R5ag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oHAkuwIE768So/3iOy4ldGnIoEjsU0vDy3WEoeGGTo8=;
        b=fmukbcsgYvSXwbCEkquJ6SZI6EXc7vRK3TLJ2kTZ9NtbPObVxN+4Dx4lPRYBuOkV9z
         M5esyup4bYoQDYUVouKMRsu4DuMPQQA0AWgPaFrGRZQILFIhXpHcieQ668+P10EDpkb0
         r8Tw35L1IFfSTuVQiDNK7q0nRO0eanv4os3A521bBciNzk1oy40DRXyxA88tSXrviI+4
         usinKKqAyfQ+H9vL2R9+Qe4mWrMlgV7DPNkid8bnlOub3ALa3mzYtvkCRlncBHz01EqZ
         wl1YevCWNdIJtA3rDFOLfdt9QiBDR8FjWki/xXa75ezEjnLWKV8ZB1ZXsaup7qarW3r+
         gZ7g==
X-Gm-Message-State: AOAM530VF7+RXfAQNaYbLfkaD4aiQrw4aNDBcBHMPqdCW/cz5/x/beqU
	qqn+JZZZg5EIrJ0egequkrU=
X-Google-Smtp-Source: ABdhPJwk4UEC98A+32MnQFKNUsihV9dVX1qpuu7HagpUPRwYbxZ+Nqg1hLoUTNLrttDuZQq4DbiGmg==
X-Received: by 2002:a2e:9a91:: with SMTP id p17mr1861638lji.378.1597426090144;
        Fri, 14 Aug 2020 10:28:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:4f43:: with SMTP id a3ls246837lfk.3.gmail; Fri, 14 Aug
 2020 10:28:09 -0700 (PDT)
X-Received: by 2002:a19:f105:: with SMTP id p5mr1706454lfh.118.1597426089557;
        Fri, 14 Aug 2020 10:28:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597426089; cv=none;
        d=google.com; s=arc-20160816;
        b=D35DVhQUqoQa3msH/ZTyH5ilDexLBQhCGsHh4UT8Cyl0AA+90EQz9LT1JtA+QoognQ
         lKQWXCDFNLYvfySondGZ/5LckMxhx4whH9gYBtK0qjE7/Ue+ChoX6nuuGQEHHbcyl/Eh
         CEAnCgGanjG4bx9H5qeW4RDxo/mAfsRQ2Huti6kxgUXtkpq+MBBtP2synAUs0Ez/Rm+z
         W4T/gglqzS2yJI53oZapgc2JKXxkTbSVymXd5b8NXYrfGWaxUluPlCsfemjdkaYgMUAO
         BtTqmcJSIoA++xpofvyEF3lSs8n9YOSh2wTUp4EbZSoKQQs07Tj/AWJkzj3AXotAsxwU
         bbQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=zi4RvguO5V6krMCBAUSDmKnZjdOOk8JOKWNtsbuVl1k=;
        b=gtUkm3cRJO6/CwpSxj/5d+z3/ZlhykUxyHDdU7KCvJJPLVJYuEeUlE4M+Cz8Jr2PbR
         NnZvnqihKcNCfN9tx/N5wIqrvUcrjOaMe6/NM2wr6BtXcBoYuzRNjQXb5IgeIL/Zi1NA
         rrX5vqVgobtgP52Wql+iEPUGk2L3uwyCXL4X2aRNYPvl5Mzt2hT86LJFXURGvwz/Jkom
         y/Ryc3dwR8UlegatsJ52AJ3Whqy9QD1dMNAuv4szBO6GyvOFXceyxz3u4Vyn99skiKEJ
         zVBxOdaODSMZNpPQa5Jlp0dswexnakuZdlYnv6tmOoquU0iNrS3UwNMvx24UH63sHwcg
         H+EQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=MpeccDbA;
       spf=pass (google.com: domain of 3qmk2xwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3qMk2XwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id u9si497009ljg.8.2020.08.14.10.28.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Aug 2020 10:28:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qmk2xwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id s4so3428407wmh.1
        for <kasan-dev@googlegroups.com>; Fri, 14 Aug 2020 10:28:09 -0700 (PDT)
X-Received: by 2002:a7b:c219:: with SMTP id x25mr3405298wmi.101.1597426088961;
 Fri, 14 Aug 2020 10:28:08 -0700 (PDT)
Date: Fri, 14 Aug 2020 19:27:01 +0200
In-Reply-To: <cover.1597425745.git.andreyknvl@google.com>
Message-Id: <5185661d553238884613a432cf1d71b1480a23ba.1597425745.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1597425745.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.220.ged08abb693-goog
Subject: [PATCH 19/35] kasan: don't allow SW_TAGS with ARM64_MTE
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
 header.i=@google.com header.s=20161025 header.b=MpeccDbA;       spf=pass
 (google.com: domain of 3qmk2xwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3qMk2XwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
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

Software tag-based KASAN provides its own tag checking machinery that
can conflict with MTE. Don't allow enabling software tag-based KASAN
when MTE is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/Kconfig.kasan | 1 +
 1 file changed, 1 insertion(+)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index b4cf6c519d71..e500c18cbe79 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -69,6 +69,7 @@ config KASAN_GENERIC
 config KASAN_SW_TAGS
 	bool "Software tag-based mode"
 	depends on HAVE_ARCH_KASAN_SW_TAGS && CC_HAS_KASAN_SW_TAGS
+	depends on !ARM64_MTE
 	help
 	  Enables software tag-based KASAN mode.
 
-- 
2.28.0.220.ged08abb693-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5185661d553238884613a432cf1d71b1480a23ba.1597425745.git.andreyknvl%40google.com.
