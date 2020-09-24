Return-Path: <kasan-dev+bncBDX4HWEMTEBRBG6GWT5QKGQEA2HHZPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id CE7B1277BF3
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:52:12 +0200 (CEST)
Received: by mail-pj1-x103b.google.com with SMTP id i23sf367907pju.7
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:52:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987931; cv=pass;
        d=google.com; s=arc-20160816;
        b=zFRmOlxCbcNO+kpMtcpQHBw81pRZj4epsco8+LWXlEaHbThQa3EDEA358c268h1LMd
         rTJqn8XQ1hwwuyTl8/hKPo35kTWxrMetX45YY0F8M75fBWT3lNWHLFdBHEONvOwCGO7e
         kaxukngnDbe/xr+TVlHwFuE8Kw8sFbCXIdWcp4IBI5xaS3m7iTsi6V1bzZGuAQYLPEoD
         uNtISdOCOpt04TeJ3mhDOG++1orzv9xHdjbiLt2B9enJYmFsATAFgx8RcK8D93MGk6is
         mTvBMJP2yx9vu2WJv/7o0pwrATj0cylUt/n+HYxx92SLA5qEedi1gufDyVw+EhbrXkyf
         Kkag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=oQvKfbmOSIs3+BKcUD52SymUmi7FI2DSYaXJoym6N0c=;
        b=Hyi7BCA7T1MvgxTzDkz26AVsNy1ksOGsG+aYJ+FtLXKVoIHp/zygPalRCyt/j9ESFO
         p9kRpx2xzKdg2SjuWq7qsgS+kTRPgwpmhPlEkgO00bp3G7oWSM9wpUZTWcHvNgKNp6Me
         nVXmyDRrqjrrJkcw8pa8pPuuhKMIo3Jl3MJbfZL5vU651wYyK2q2k6G3gGC2FY1E6vzk
         dSrHFa51KV13/I1N17KgxngWjgNFFQd7uxXvZZ6IMUYMbJ/ujHjfDo7X2LmmiVViWlcG
         vwbXhMrtn49OWfWolTXy8BvJkKDVko3uyNyV6fWL/H7rq59HGcZ6W4oLYf1NGGoY1h1i
         F+5w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jivKxzVo;
       spf=pass (google.com: domain of 3gintxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GiNtXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oQvKfbmOSIs3+BKcUD52SymUmi7FI2DSYaXJoym6N0c=;
        b=DMhI2nrD3rtXrfpJWu4W61wU0kfkA6E8KtIyEH/oeMNFB+oSDFijQ+ieJm9NEPa8k+
         k0HmbeDTblAzz0TgGD4D1KjHGhsgNglYmYL9ThfgpmUSr0lUWDb4jJnjMjjl5meEAkDk
         racXeWTNJAk3UbJwC5T1XtPSRubs9LmXNwqwLY/pubh2xmuVgkbuXLoorLJIoceLUCIV
         C7mptLTlRFj0pg2IfYQBsLiyFRkOigbQ4baO20a4TbSeATYLeKfPFc4QzkaFEs3b0h5n
         sgQ4e86i/3fjYAkYgbOU4wXEG7ar1NAspj5AjkLFu2+1vvzRayHAfJOOykRLEd0NM7fZ
         thrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oQvKfbmOSIs3+BKcUD52SymUmi7FI2DSYaXJoym6N0c=;
        b=DmZpRi3KE9KzgerqUZhVgyQWVHRxtX9Ttcvd5sGwC+LwtHHmGxZQShhX7XkR4EI0wp
         kbVPMWtpFdd5R/nns0CLJtm1iNMWPEddbJaBOLbOc/lfqHxzIvUgvfFwEvHeBFAXcQhO
         45uGZX2voxXhV+jfwuDZlsT/kvht1Jdbt4X6Ad5N16l1ga+Yqr+hqiP0GHn9z5p2mEGs
         UdfwAha1fSbA6b4Q8h2DM0gZjTNJnXPDGEkFeb/RXzHHeDiOpwSj0yJciOSvEAXA2bqP
         9KrIDfQb+/KK8Qd/duKYOuI1PtEUQ8KfoFErwq5Y3jGEl/pfJE6Ur4gxsF5QPmMJAjm/
         Ao8w==
X-Gm-Message-State: AOAM5332r2GtUoHOxermh2IDjcCpQsxCaXGpxMyqkI/esmLAS3XcaNjA
	EFYkdUUbQc4X8ULp1H2NWxw=
X-Google-Smtp-Source: ABdhPJyP5I4PMfF4aIWtrnwiPLdcnNagI4/voyfskrz0XkEchhJ0hIQFUqTEXQ/l7eWZQoq/Ji/g4w==
X-Received: by 2002:a63:1a21:: with SMTP id a33mr1067422pga.305.1600987931612;
        Thu, 24 Sep 2020 15:52:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:480c:: with SMTP id a12ls318180pjh.3.gmail; Thu, 24
 Sep 2020 15:52:11 -0700 (PDT)
X-Received: by 2002:a17:902:9a98:b029:d2:6232:e26c with SMTP id w24-20020a1709029a98b02900d26232e26cmr1386472plp.1.1600987931060;
        Thu, 24 Sep 2020 15:52:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987931; cv=none;
        d=google.com; s=arc-20160816;
        b=fk5cqgRQJTLnAIbAuKh57k3g3X2jlYjk7P8bOgXE1Io4JN8R+RREcFCYupfYDVFNVO
         E0xSktDiGszWZVnpyiH4tC3NXAL8HZXavgMWsFSfEKfosmuLYaep+iRaWePfRCk6WFBo
         21mLGmmBTnu9pvVspkq+sK5qb9EZCPReFDIkc8MFnpOARFnvbtn0kDY1xXc58V2U/VTV
         ubvnpL8rk/GVhVXyy/G8mymjQ4uuynAHwEDF2WqtyYGC6ZJNSVy8gunGylcknrdX12Vp
         5Uv4msVBNh9bBLz1hzZ53hJZeWbmLYgx3rCOnwRJxIyOi+UyKamC8XLyQJVc/s0krxoQ
         0WoQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=sJr1Ezt1QTZM7xCujMwarLHpec0t/6/LWXnFkCD3rjo=;
        b=xqhwHKZRHtRDj4kPqwJzIbJ2FggmmFtjizKiRekpW6qUQi3DMMA5mwcVlBsLyqTW2t
         PIsosJGvTuZ1LEADDhunO8SOBIqww9EOa+ASLupw44vc184prt9Ehe/3O+rgFfrBJutT
         CeZWj4ogT7SOSMSV3jpc3Yg7VhRZfi+iJ1ERIkYAUw0kZZnjGPoj1JIRUQ7DGsvZrcjl
         PMTL2ng1dSTsuf85H4baphireFVKZkFv8Fx6qMfSBNKmXfnk2GIG7xENNX0wRELdBGFK
         wcqLna4OkJWg1NecSJwh0FfHRK912F4cGOeh6uKk1aYNGESZJXrp4RQzclSjb+KMgGs6
         TWcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jivKxzVo;
       spf=pass (google.com: domain of 3gintxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GiNtXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id d3si54433pld.1.2020.09.24.15.52.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:52:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gintxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id a16so516333qtj.7
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:52:11 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f6c4:: with SMTP id
 d4mr1575582qvo.41.1600987930210; Thu, 24 Sep 2020 15:52:10 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:39 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <08b7f7fe6b20f6477fa2a447a931b3bbb1ad3121.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 32/39] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=jivKxzVo;       spf=pass
 (google.com: domain of 3gintxwokcrcxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3GiNtXwoKCRcxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
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
---
Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 9c73f324e3ce..bd51ab72c002 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -5,7 +5,13 @@
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
+#else
+#include <asm/mte-kasan.h>
+#define KASAN_GRANULE_SIZE	(MTE_GRANULE_SIZE)
+#endif
+
 #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
 #define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
 
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/08b7f7fe6b20f6477fa2a447a931b3bbb1ad3121.1600987622.git.andreyknvl%40google.com.
