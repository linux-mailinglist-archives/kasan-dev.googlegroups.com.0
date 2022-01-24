Return-Path: <kasan-dev+bncBAABBIGVXOHQMGQEU3WIQ2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 390D94987C3
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:06:25 +0100 (CET)
Received: by mail-wr1-x43e.google.com with SMTP id h12-20020adfa4cc000000b001d474912698sf2194825wrb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:06:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047585; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZLak3oRX1ZVP3ykQ6NQMQCojfG37ek7EmqWrrSWGcG47KGaR5ARoRMQ5+Y7700S+75
         WjcA4Bu/jVw64zoCbrXvoULy13LPhV0l9Vp/MWHphj9WVUeuKRQlCYK2aPCHHbki7xqG
         IhgcdbiM31QMAVCDh9jcsPPXvBbkk9at0+uGLOqtskq2pE7gRDR/9yCORi5IUT7Bfl3m
         Guwimaz1zS2eOtVZcdI+FQ9jvwhy7Q/0JLq9Yn8Tz9OAQtfW7MsqIZwQ3Fl2ntwNCHuV
         xbt1ZIda48eqbSD13w9v5kp+vuElWPUZhAuWhRYQTPu9BOfOIIAjoNk1ZkuPMdRnvwQP
         pDwg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=QvkuuGgWpChPYaURchxk+asv3XeLdh7DvLxWJq4mtIM=;
        b=kH56Z8dFZkSAlHP2opPi19s3op+gfaXcml6Kjf/O0CWtN7QgPxLm6rJBLX1WGvp1jt
         QupUXT4fW8B9ISYcKtw1/VGonXo1ViBzCEpu+3dp3RoSqpIIPRtEJVwwEPmMxQ3wwI0O
         TEFtye9Dq7NZT2G2DUAAThx8wXMOnjhgirOSbyF/++0iTKgDKYsqLvK6Q4JncJw7tfj5
         vjJVVCKvUqVTYwPpxL6CWnUD923gDPq7aKYDolmDb6DAfhl3N5kTxsDnM5QJisl179Dy
         4s8xQYsXO085iCatyhxXFBBjbaTTQD+S04CPVH0X5JirJXsqp/wu9wyBygLAEzTG+pbV
         zReA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=anLPN68h;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QvkuuGgWpChPYaURchxk+asv3XeLdh7DvLxWJq4mtIM=;
        b=VA967BGPhF0eXuST76seD+l0zJ+FbFeZP/QC9kPuDJcAZoxqpCrec8WMYXsxbH81rM
         mB5uKfz2+ln+UJ64S+rmZDaaO/qKWHn+9NFfmQC/kPn/C9JvL3adldZis61XPZDbC4Ho
         csvWoMKsVmCoopoztSDCpdKGE22FjoQHrdxEs/9BNl26GDAC9gzCqKHAx6zIv+rPb5Ex
         f2C+MNW96ELkXKMM5MWCAvL3UxbZEwzO67bzaB03C+xPKjZlZ6XK5BOPJrBZJWu+Nd4E
         IJ+O9rbrGynF/jFYhWMG/1nhZ+3CecRTd4BFYA5XNFtJe3/+g6KEvT60inZv9NY+h2TT
         AQmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QvkuuGgWpChPYaURchxk+asv3XeLdh7DvLxWJq4mtIM=;
        b=ti3tq4J1tNQcShJWj3a+gTDBe/3ig3ND8QUcvcqsxHeJnw60vyCMG54hZ7p2z2CfmU
         w8sEKGYIQW/TygeM0Jba0jhjBluOxtgQoIYfiRciQOG5cs3pLOEs9EZpN2bpwh2UzUyf
         kWJGSyLQlVbbAaVuVKrGdHyyIrBYcGRbiAlomLeRaKQi+pDwb+EKuxdbWe1WvWgHV/Sl
         iTOay8eI+U3zCIUKo8swV6S1SOE58eB6oQipWZwJ+5mJOcC86fFPS1jiv456ER71532N
         D+Ogj1ExIxQuSr0ll1xF7Tftps6BoUhI/MEyVLpigbB3hWm0vGc8lREjrHIo7mD355Nr
         lL9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531P16Pwdzvazbz2MEmTopml9azmEm3d7+M2msAt7Qaoz7hTGx7Q
	i/XEHmi0gcF9XqQqVGyk+Ko=
X-Google-Smtp-Source: ABdhPJx22g+wFDdiRfQhIznHcgNIDl89I3ENVdRSZSPnQLMyW/FmSkm+hyXeRGbfWuoqJyabw0tN1A==
X-Received: by 2002:a05:6000:15c9:: with SMTP id y9mr10967786wry.121.1643047584984;
        Mon, 24 Jan 2022 10:06:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:e390:: with SMTP id e16ls299536wrm.0.gmail; Mon, 24 Jan
 2022 10:06:24 -0800 (PST)
X-Received: by 2002:a5d:6548:: with SMTP id z8mr8396889wrv.297.1643047584377;
        Mon, 24 Jan 2022 10:06:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047584; cv=none;
        d=google.com; s=arc-20160816;
        b=OZ++Ao8zubxpaG06/yC9Y+tbQm0EClqXjUAb0kfcwwzmNCZx/OgiE/jspXpXBF4xpB
         qg68QpZschUnLgb7y0yeVDHgz1OViq4nSdx7ACl2Ow0lr5Fbgy0dtYWJDPtYWKx6XHJ9
         AeifJlmR4WktfqCW0dFvW3uYDWdmVIMdVaCgbg/ePpbwRU+LjLq9+fYMt5QyWbdB5GG5
         grRnI2Jq1sasF+pMbKOqgdmRJXDOBiwDgJiYKYYlWsqSfqVYhSiDnSBhalNWw2uqhu1H
         Mzm6YbdT5OWTaXDPSIkm+rFaHHyc14cHWoYKN6ATlyxylfhqh1IkdX+8hHr1ZVrDTWp3
         Pq8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=60ognrjQYhvO9ri8tnI6aAPda5fVQLb01YF0/tgqKOQ=;
        b=cx3zFLmunz3AdOrWl7Mx7/+qcYBaY25/IxcbrsIuX40gLQG+K2MduV+ozuF+uWPIy0
         RpjNgIdDE2Ry79RjbHKKJAoOx0KNGVI6Fg7/OaXo7WkQm/7xMSlpTCp3uCd/BdUS4gKD
         tdJ0HBHMrRgdBg5Dh1XOEcyVAGwHACj8cW4A03RwQTIAMtbHwVPaT2hkdnaYBxYeYCQ5
         q530zyAwq/bkpzwbeMUd1oo30gh+eLTeSb9uXSqiA6tQlRpUVEK170BzHmvd0VEuaGUq
         nWxWuMEY6RyEm16AmyWyhmqcMTE/pC2DrPMhcjKPxiYdatHeogoQ/ixXRouvhpwUrsM7
         vHLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=anLPN68h;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id d14si578934wrz.4.2022.01.24.10.06.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:06:24 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v6 27/39] kasan, mm: only define ___GFP_SKIP_KASAN_POISON with HW_TAGS
Date: Mon, 24 Jan 2022 19:05:01 +0100
Message-Id: <44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=anLPN68h;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Andrey Konovalov <andreyknvl@google.com>

Only define the ___GFP_SKIP_KASAN_POISON flag when CONFIG_KASAN_HW_TAGS
is enabled.

This patch it not useful by itself, but it prepares the code for
additions of new KASAN-specific GFP patches.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v3->v4:
- This is a new patch.
---
 include/linux/gfp.h            |  8 +++++++-
 include/trace/events/mmflags.h | 12 +++++++++---
 2 files changed, 16 insertions(+), 4 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 581a1f47b8a2..96f707931770 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -54,7 +54,11 @@ struct vm_area_struct;
 #define ___GFP_THISNODE		0x200000u
 #define ___GFP_ACCOUNT		0x400000u
 #define ___GFP_ZEROTAGS		0x800000u
+#ifdef CONFIG_KASAN_HW_TAGS
 #define ___GFP_SKIP_KASAN_POISON	0x1000000u
+#else
+#define ___GFP_SKIP_KASAN_POISON	0
+#endif
 #ifdef CONFIG_LOCKDEP
 #define ___GFP_NOLOCKDEP	0x2000000u
 #else
@@ -251,7 +255,9 @@ struct vm_area_struct;
 #define __GFP_NOLOCKDEP ((__force gfp_t)___GFP_NOLOCKDEP)
 
 /* Room for N __GFP_FOO bits */
-#define __GFP_BITS_SHIFT (25 + IS_ENABLED(CONFIG_LOCKDEP))
+#define __GFP_BITS_SHIFT (24 +					\
+			  IS_ENABLED(CONFIG_KASAN_HW_TAGS) +	\
+			  IS_ENABLED(CONFIG_LOCKDEP))
 #define __GFP_BITS_MASK ((__force gfp_t)((1 << __GFP_BITS_SHIFT) - 1))
 
 /**
diff --git a/include/trace/events/mmflags.h b/include/trace/events/mmflags.h
index 116ed4d5d0f8..cb4520374e2c 100644
--- a/include/trace/events/mmflags.h
+++ b/include/trace/events/mmflags.h
@@ -49,12 +49,18 @@
 	{(unsigned long)__GFP_RECLAIM,		"__GFP_RECLAIM"},	\
 	{(unsigned long)__GFP_DIRECT_RECLAIM,	"__GFP_DIRECT_RECLAIM"},\
 	{(unsigned long)__GFP_KSWAPD_RECLAIM,	"__GFP_KSWAPD_RECLAIM"},\
-	{(unsigned long)__GFP_ZEROTAGS,		"__GFP_ZEROTAGS"},	\
-	{(unsigned long)__GFP_SKIP_KASAN_POISON,"__GFP_SKIP_KASAN_POISON"}\
+	{(unsigned long)__GFP_ZEROTAGS,		"__GFP_ZEROTAGS"}	\
+
+#ifdef CONFIG_KASAN_HW_TAGS
+#define __def_gfpflag_names_kasan					      \
+	, {(unsigned long)__GFP_SKIP_KASAN_POISON, "__GFP_SKIP_KASAN_POISON"}
+#else
+#define __def_gfpflag_names_kasan
+#endif
 
 #define show_gfp_flags(flags)						\
 	(flags) ? __print_flags(flags, "|",				\
-	__def_gfpflag_names						\
+	__def_gfpflag_names __def_gfpflag_names_kasan			\
 	) : "none"
 
 #ifdef CONFIG_MMU
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/44e5738a584c11801b2b8f1231898918efc8634a.1643047180.git.andreyknvl%40google.com.
