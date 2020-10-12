Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEUBSP6AKGQETR2VXNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id 366B328C312
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 22:46:12 +0200 (CEST)
Received: by mail-pl1-x63d.google.com with SMTP id w16sf4591614ply.15
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Oct 2020 13:46:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602535571; cv=pass;
        d=google.com; s=arc-20160816;
        b=Hl/L7ByofZwdKovBo/jvmd7zrXuPhb3DV8551ESdiViFkIjEVNNN6T1sYgn1JcLE6+
         bYzcsWAd0i6dDzR25W+lhBbN3kvjHBC3SBpQgptqpW+pxjh92Eo4UVlIFgmh3a681y/l
         c6NdSa7zSFBDOy2HBGXf4fXbXzXhcdq9q8zCag6P8k77ss+AyqsY6l8i22klNvuJn7kM
         Lh0caJsBEQt6bcfbZPHHL4cr6Z7lo/CyaQSJYct8hx8yQSVUh6NiZ8Ec7E3Tfbo5PwMW
         iW+lxFakBEYO2SHTtIu8wUMlfLBEoZ5FkYMy3+v68r4/y9qoxIip+a31usEYUWL+Eyrh
         c7hQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=IciXF/MpQQsD2vcitJFnkl4i+K7ZCoE4kXKYp3NQ14c=;
        b=h1tl0JB6Wts63ouvh+BUZL13NyfQOcTpEDDb53nuanMTQIA7k+T8ms/W1KMqi65m6f
         +Nbq5uWwCWy1ec486jUqrWTlE3IWUsx2Z2xIvREEnkqwmVq1SvAXYUENeRpeboz3lkDo
         yIQWoUneyJ1fzWJWprGLiQwkLGSoZQbB9F3DsyxdYf3t39oJsbcNFNXI/J9qeso4kGxq
         Tg4z1KiceN1TKMi+Ijd5IcFVP12gGH+q6N9RgpT/qEoaurlUfmOR+/WPTya1PxepekrM
         OCtuwWDd7ZxPGm2LGnbhTy56tfts9RThGwjHdpFijUVkhYHoskvDB2YFB7E5LjrohVLq
         0uCA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sZhcn8kF;
       spf=pass (google.com: domain of 3kccexwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3kcCEXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=IciXF/MpQQsD2vcitJFnkl4i+K7ZCoE4kXKYp3NQ14c=;
        b=A5pERRRW8fh8GFDMwnj1Y/shtiQe6bFtRR2VlQIwZDzib5o7s3J1aqq/OQMnxvNXRt
         MIw0IGwVaJmYeg+ZC9GDTDxAsmrh1BIjvPOry6ipVI3sWf3uS6cb4MOZ/ie6Yc4YZmUa
         xBIH2IU87vWgnTeJOvShPPdweAH04CuNmMpHXCX60t+lsMeKX1Efy2ZJr9GCa4MctOhz
         IGE0UcZTiEMUdlFlXCtt19kFAHKoBxug32miyVgpOAVwCOfVkWMH/4Gnatq8wMG8KLqJ
         /hNmh5AObANKwnthh8pOa+Jy9ks0oRWw5S3930ABe6mks3hce/P09fnaFjM12J4DEfzM
         phQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=IciXF/MpQQsD2vcitJFnkl4i+K7ZCoE4kXKYp3NQ14c=;
        b=gGOA8QgR8ZQxQnrBvvlexDTYEvvgwOGtGFEj6P/mIDJxm0YbDconArr5FnU/brqUZO
         7hj/oWp2+XED3L4f66KQoVCChyCNuZj62Zq57RR/v5d6bvred5OmhJkwiDCsVQZGtn/5
         7CCCIwypHeOC/5HiVoMTDgttwi5gjbVqiO84P8FeMMQ+7n2IjKImxz6HTNbvbctSOSa6
         rz3C8fhMxfRBvVMAzutwqheI5/0YUdENF4Nx/nxZxTnhEkAAPBAHwBlYqcKsOjSdT89m
         zJWyzxLkUgAuMKiyQhWgSNvxXeTcr7J3EoANq9h+AO4NSGFp67c8vIofKkhoPUDsnhoA
         4P0Q==
X-Gm-Message-State: AOAM533wlUjJfn+Mgp3c//cKJ5vvbH0l72H1rPZGqyeErnsIU5A78BKp
	yfWZyksbauAjkQ3XWRu+Glc=
X-Google-Smtp-Source: ABdhPJwiqjs4JI2TcJ1o2mjWoUaquyOkhZT8oJMxOQmum2G4S+3IkqZRsYFq4VtW4UzReeRsRYKv5Q==
X-Received: by 2002:a17:902:64c8:b029:d3:c561:5819 with SMTP id y8-20020a17090264c8b02900d3c5615819mr25444580pli.32.1602535570956;
        Mon, 12 Oct 2020 13:46:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:fc20:: with SMTP id j32ls6033239pgi.11.gmail; Mon, 12
 Oct 2020 13:46:10 -0700 (PDT)
X-Received: by 2002:a05:6a00:170a:b029:152:6881:5e2d with SMTP id h10-20020a056a00170ab029015268815e2dmr25439630pfc.20.1602535570379;
        Mon, 12 Oct 2020 13:46:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602535570; cv=none;
        d=google.com; s=arc-20160816;
        b=eykCjwmOtLd9Z5t1VkkD6sUUPBYEZsUqSfQJEiPr7GkBolm+0GgyUnTUtItrEH/DDY
         fCV8Ie7QPyTHo5lhB9wxZ5yvek/VT1odpXFrQxQML805z5wopB9vd0/v28d3HG2/H/CI
         273nkLgwMmKObsNA3hEtyEWfLu3sBiaJ8v3lc1zxp8K5Q3/RJ1iZsMnuGrlRTYg3DHFu
         Es/ue1w1xisk4LdVJoMpNSmRyCslyZcf4GF4mzmO4E671W/XiiXlbI8F6uNCKqH4mKl8
         V4H7E2tA6spqLVCqmr+bXdnb7oelwteyjoMILTLehfXhTVOt4OdWYbyxsxG/BoSLfEZU
         EukA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yun2eenyP8tmp8dDLy7lH/4hFLH7rzsqZ0SoQ3Etw3s=;
        b=LVGbIo7PPsls37Z1P2YvbMu5Sgg5QSdck8io3S2SbOIyY/Ww3LP7YIXoet2nrldt7o
         ImLeE1jJU0a4tNU0nXW4cZ3huEMhCsjN7gZSN2VNoxvSIzcqrR/C9I1hTz9qUJaQ9di/
         J2unCqG1igIy6r+fU6O39KAZI0tFVnj+xtdvQGob2wu05qnzDOMwvz3Xn4Riwi0Go/+D
         1+QETV/ZAVvypb3QDvTBHRpbO3q85pIlwueNk2nYCkeneMjbWHBY2Z3fDw6CGKTKiPP0
         s5w0W7W8mc/zsqXHCE7Mqg0hb1UmVwv0JYWEX1VEWQDgfXEVog8rxI+niAz5gA+/spdA
         Z/8Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=sZhcn8kF;
       spf=pass (google.com: domain of 3kccexwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3kcCEXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id i4si1608411pjj.2.2020.10.12.13.46.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Oct 2020 13:46:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kccexwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id y45so11521495qve.15
        for <kasan-dev@googlegroups.com>; Mon, 12 Oct 2020 13:46:10 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:48c6:: with SMTP id
 v6mr3525139qvx.11.1602535569462; Mon, 12 Oct 2020 13:46:09 -0700 (PDT)
Date: Mon, 12 Oct 2020 22:44:38 +0200
In-Reply-To: <cover.1602535397.git.andreyknvl@google.com>
Message-Id: <e91065e84521993ac7756822267353ac3deaff64.1602535397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602535397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH v5 32/40] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=sZhcn8kF;       spf=pass
 (google.com: domain of 3kccexwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3kcCEXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
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
index 9c73f324e3ce..cf03640c8874 100644
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
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e91065e84521993ac7756822267353ac3deaff64.1602535397.git.andreyknvl%40google.com.
