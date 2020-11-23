Return-Path: <kasan-dev+bncBDX4HWEMTEBRBD5O6D6QKGQE5G3THXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1B4782C155C
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:09:52 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id w1sf3886356ljm.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:09:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162191; cv=pass;
        d=google.com; s=arc-20160816;
        b=QNxbPZ/xdEKgidJgqTYQI9FQvT52DtRuVoXPyC3hPd/Of4fYTXC0PZAQhse2pSdOep
         OzLGUlND2MbhTIFIpQa+JpL9Lfi25ucBGWUUr45/7v3zH8L/+ubln3qtWGedX2eOACGd
         xngVejKy2EjQaMS6Y+jP3XFh3IomCDF8kB6hTH4kePL3hbWjhMxVrXZ7HOQz/AH9KXJu
         vrP4qYnAbUcOn1Ty2l2bgtQAQNfkXSgiQFb1eCQuzpbKpEdPvHFKokI3GVUS2I5S7K0u
         Xafm0NWxW5WUPDlG9xbCTOAhQyVQrmSyLfkxgQA/SNfhoW2aQ0XCfYiJShDEw08Bp0af
         Lamg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=wI3bCW4C+j9squRRwfsRyVduaJWsiwrsBKXdJ+J59pE=;
        b=XaZpV1pYI8DLJQTv4INX0RdbDv0vyJIK04Xkid1O69G4hsMhHuT+IXwBofMWfo+uSu
         aSXUOHdVeWfBIsal+ZYRYirqor3Sazx3gzf2dYhPt4Tl7Wj2I6Po8htfQJPID+/NVi3m
         bGMk7jiAoOBilh4yFeT6Sfb3F/SCpGV75a7xlC6wmZ+oW+2GMXGMFLOWgUy4qPqxhOoM
         e6iROstLk1/DfORYhrS3A8zbO7KtwbTnDH7vz3+UUx8vRR74DCHprciE/8ulSev7IkRf
         62fZqUCigqj5prkBo4jYxnUFLCUpVPJdLnEtFWml70EO+g9KDbIeS6aVoRafGAvl4Z7E
         M1bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FfWNnS6D;
       spf=pass (google.com: domain of 3cxe8xwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Cxe8XwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=wI3bCW4C+j9squRRwfsRyVduaJWsiwrsBKXdJ+J59pE=;
        b=Cs1hpGa9Twsd+BIH/khIsT6eHvScP4FSj7Qj8iQaSwAXOn1mlonelGXn08GkjtnyXa
         FNo4w4KBaFhUc2xJM/mVyRjbU6REe5d+QcCXP2gRWX5agtVVvWRoiBJWE9P3K3Acg+kZ
         efYpEdF35XPeggehU7ll0jZ5RZ2tQ3JL+WzDtL107Ujs5cNpTBvWtncDCyF5sZR9cZnR
         V17m+ysQgQlmTugu52RIgd//H/+OrYA+XZ6q1xAnmu57nuqDbokLn+8aZMGa7ngQq/SF
         dSf2svWhp3MF7hgJfqpWHOpxm9XakmtFTFfx0G0vnkrV2DJRPM0iiW9VmpOK2kGrVAFV
         GQqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wI3bCW4C+j9squRRwfsRyVduaJWsiwrsBKXdJ+J59pE=;
        b=uYj5SMg13tok3HA1mYREp2igYtw2zvR1ackbQ4gtRb2CeuTxnRYv4gUnyIoJ6Qq+sN
         DOYg41dZFdeZmFlXeZCgZXgHXAal4wEjRTZSSxFEUjT9Rc1EurkzOIIoICS3+rSFKD7I
         CGMmRmMdDNTB4w10zTJfzv8HIq92wjBn1EGNjgmWfAbd3RrdU+Ba4T13tCVHW57+wurS
         dNdERhFBvjUI+vgeNvzw88zTWCgk+WvKRc3Od7mLm+wpGdRNUtWcn/vi82OERH+RpG0S
         ibu46dl4ldKF87hHtcVHYwTF7eK+pRYur7iTCg3+0Hz2T99n7E/319BpZ2c3lexaLSz+
         Pldg==
X-Gm-Message-State: AOAM5335y7cXYt9vNfgI4ySZqP6o4sBZxyyyEyAXaztcEU1DgYxBBhrV
	bgzM2TUJ5NS/SVEXIPW5wO4=
X-Google-Smtp-Source: ABdhPJxhV3B2T4WjXR5IgibjuP/OMjFldD3WvsCf+DuupqTrHqUgAMpP26A/n1k0qu+NcgCjP3+9FA==
X-Received: by 2002:a2e:948:: with SMTP id 69mr486889ljj.180.1606162191548;
        Mon, 23 Nov 2020 12:09:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:ccc2:: with SMTP id c185ls3987813lfg.3.gmail; Mon, 23
 Nov 2020 12:09:50 -0800 (PST)
X-Received: by 2002:a19:3817:: with SMTP id f23mr336022lfa.587.1606162190648;
        Mon, 23 Nov 2020 12:09:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162190; cv=none;
        d=google.com; s=arc-20160816;
        b=K8PqYXWjk7WV7JzyYw4II3I7FYrQueYu2b2VyuzjHvaH7Ffo21Su8pnkgUf6x+mM48
         o854ZNTNr0o48VtUAdgowG2w0Ds4MBsV+A76hbMkmHsBHc1eVprf0HDjWNKSnEGZFA5l
         j61/Cayp7UnXBVxsiGaN69g5RcFqoLyJgf+sQYLmiYApfjSCGhNntHWvPCz5pQm0A8MY
         qMpo22H1arYDk0ybS6YPLRN24UsRPmFq5xxTA8g/t4ur0dCqXYGZhQAQZGpVJKfooamh
         YvafQ7fHoTF17b68H8zeMnFuVDy4PhOoOdeuJdmQPpgh9NTuBqjif80SqHvPY9vD86fF
         7Xsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=gEnDsD+N69lIXG3Ma+biKqxogEfpaBdkZlhoQUvyVBc=;
        b=O9dFzMOjFhh+pRR8FlrpxTnruow3OG0Bgindq5/3Km+xsJzCJFbxMvM4Vn7Mqswlri
         JRkaW30D6dI68116jkz/6RLVw39fXzt2KJlumUI7mL8QR7jvnj5JBXyhcj+CUWTRi3PR
         QXEmKGARskxRwbYLcbKYIGti+eAp8c/Omv7/LveI0XTNjwwe05oGgjDooSltUbS2ej5C
         XH9vsG4/IZG2DZIBhKtrGI0g27pxI/pF6RDhxHQaiN0PDgNnsqu0aBMjJgSuxKySFFtQ
         kvg8LPz40HFvlw/WsDNRoKQlCVIG2yAsQzuemH87Rc3VPcYo1SHgc59k1arPBOEnKYAw
         p33w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FfWNnS6D;
       spf=pass (google.com: domain of 3cxe8xwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Cxe8XwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id v2si10458ljd.5.2020.11.23.12.09.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:09:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3cxe8xwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id h13so6187846wrr.7
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:09:50 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:398a:: with SMTP id
 g132mr585815wma.51.1606162187602; Mon, 23 Nov 2020 12:09:47 -0800 (PST)
Date: Mon, 23 Nov 2020 21:07:58 +0100
In-Reply-To: <cover.1606161801.git.andreyknvl@google.com>
Message-Id: <3d15794b3d1b27447fd7fdf862c073192ba657bd.1606161801.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606161801.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v11 34/42] kasan: define KASAN_GRANULE_SIZE for HW_TAGS
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
 header.i=@google.com header.s=20161025 header.b=FfWNnS6D;       spf=pass
 (google.com: domain of 3cxe8xwokcs4kxnboiuxfvqyyqvo.mywukckx-nofqyyqvoqbyezc.myw@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3Cxe8XwoKCS4KXNbOiUXfVQYYQVO.MYWUKcKX-NOfQYYQVOQbYeZc.MYW@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I5d1117e6a991cbca00d2cfb4ba66e8ae2d8f513a
---
 mm/kasan/kasan.h | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index bc4f28156157..92cb2c16e314 100644
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
 
 #define KASAN_MEMORY_PER_SHADOW_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3d15794b3d1b27447fd7fdf862c073192ba657bd.1606161801.git.andreyknvl%40google.com.
