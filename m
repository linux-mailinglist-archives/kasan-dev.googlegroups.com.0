Return-Path: <kasan-dev+bncBAABBAWBTKGQMGQEZS52VTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id 061C14640F3
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 23:06:59 +0100 (CET)
Received: by mail-wm1-x33a.google.com with SMTP id 205-20020a1c00d6000000b003335d1384f1sf14548756wma.3
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Nov 2021 14:06:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638310018; cv=pass;
        d=google.com; s=arc-20160816;
        b=xHGGstBYpv57m7DG/wF2OOJO9b1XMj8vRf/MOXZCy0HiIuvf279iqG4RHOuBVaymty
         WSfz1gwaBLrCErjDd0BslEeNz3FuKs0ZkHRmw97VOY+O2cRyScU2WXgkX6H/pS7T4Sbh
         82xIx4j5mAWAP+3LEqWC1RYKNZYqTleL4o1P256VPvy5NCKj9qEaUFXVIdjSVTBOcfE+
         wQUnmEL8edItk74TL+iQ/2cEhlDLB3D/4AL2X0Bo5TflNZb7XikTD6fWZSOoPAe+xfzg
         5c14x/Az8sk6GXakFpnLxqgC/GWwvJcXcseuEnJnRq5olHCTQwhPq64t48Flup7QrpMi
         OFWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=aZdJ5jD+E4OiZQYevM6MxocJsBYYlEEhb5bAnZWURTU=;
        b=TAy295A+KLdPVpCGd5851iGpVH8nVPhOlUgYfO1DVuaVkA9smX9lS9G3BLWXYkBdlX
         9T5zMWlp7H/qA5FNAD7Sak5fbkoDaqsy/D1MaVpWkdnRlWxbxMX97prQRxecVciXXqSa
         CUkTnJdH5SgR+M5VIsoNi+R2HGska7z3ROfFmmy+08G493G+rjNESKmzbM1CwEOg5wOh
         2j1txuAxQDuUWU1csD0T20pfm3J0MN3jAqTxzkGPCBK8BMo13RSBFxLuFJD0ugKjHhFH
         +MvG7ahQoJ/vs9X3Y7SQF8KQbvjDOEHU3jYhvoYFREY/fr97i8Q8CqmhdufMO0pQdXrv
         QeYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hv7+PXgz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aZdJ5jD+E4OiZQYevM6MxocJsBYYlEEhb5bAnZWURTU=;
        b=IxNk9OxKE1rOPZZoeYObFNnxyEenooBqIu2fhR359L/YctF3GBPje/b7b1aaAxhFfF
         Bipqnrm3JZUTXmB0muma9EVkonqXi0ReL2lLIsWL+QI5sHYT7xtZQVN/K8V9cjPEeb7q
         7l5Scblj1DXcDDkJPdu23Kar6ZaHDrDXBLeptPpm/ZhIpfWa0RjfYiT/jbFTydGyzNk5
         d6RwJAO2OQOJ+mBBa58BEMQOPaOJjt6XSgRZ7WsRTkS2BhAlWVt3EN7ELumujo6L0Ul8
         YzRKcxJLREU/7lZR/WKPoKGDT8LupW60BlIXqX5gIc4xlR5dmkTnb1x2Jb1eOEj9MO6z
         L0hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aZdJ5jD+E4OiZQYevM6MxocJsBYYlEEhb5bAnZWURTU=;
        b=GdwJu4LfFumvcO1Mp4Koon35jkUPwIB7fE8ASAhn4C0FUgKeR2QdfsdlIFC/y8eFkn
         8NrhCSlmPjchRmkloyGpKpRp09khCnkHOg6IjQbShJLSS/NHwxUMYRWCwajBpooA2Lbe
         t/1Lt/cdo6q7L1+JSzkTA2V9CaVB7zRCssVsGfkFNbx7HF7BkeNB8N9X+mIatyWho2IV
         uh5wJ0nAUHztxABu3Ppx86pNYAMeNQ69G62VXuSKmRrjINfO7Dp2EVEyKB+qOxIzs7Wg
         9g9VIWt7iQM6zekbcUutku6GvzOA8tOGj3lE1a8w9b+ZdIETfTcZYjqarH84dy7ZzZn4
         p48A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531c7p8GwGK1H+S1EKiSGsZV3tNrPtsd43SOPh100uinp1tLM1CT
	Zz+nlsb6RYCMmx1c6PoaOOU=
X-Google-Smtp-Source: ABdhPJxPeyNfcSKuXHaXc2Cq0wYl2AwzqoaKKUCJSkGjOTozXCUx3U1CzahY1Tnc+jYV2ae0qr3nBQ==
X-Received: by 2002:adf:f589:: with SMTP id f9mr1816834wro.505.1638310018822;
        Tue, 30 Nov 2021 14:06:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:770f:: with SMTP id t15ls94670wmi.3.gmail; Tue, 30 Nov
 2021 14:06:58 -0800 (PST)
X-Received: by 2002:a7b:c407:: with SMTP id k7mr1777193wmi.35.1638310018148;
        Tue, 30 Nov 2021 14:06:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638310018; cv=none;
        d=google.com; s=arc-20160816;
        b=zYlott5xXlPjPIpElQ5gUzvBHuS13x5soNS6/wmqJIFjQO1jC9Z95QYz/HGtwIU04J
         4V/OQCMRRN6Y/hNHD1FKPGk9nNgLsZEGMW9OD0Hg+UnlDmrYs3qyDO1BCAtuJQt9FqVR
         b/LCiQX5JEEYMR6DuFMuex1KwgKyJrEQj/6iBtYBO2aoKcUw/WW4T8YBXmfm9MgQFKUT
         kgm+/nHajc4xC+q+vCmb8GPLWlLJ7ZPZ5xTzFOZyfgYnXFsgiVbRFaDiTK3R2EVO8u+H
         VWCZ1fYQ1sXP5LVq4jVT+2sLqCOdVwxP2hjHpgzINrr4nsOeumv+RoW58pYfLzqeTNO4
         Qs9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qxn2Xep6jUSip5qM4WVsL2tCgAIiNA6s93LyLl9ypbE=;
        b=rwhVwfN6rZ6iqmJuAHIVkL2gA/6NFlIZZCEhX8dwOEhn0XY2CToGNa1OBRfl5Aeb69
         X0PZoIbNvApwaAAXC3b84aY6+ePk13jK6DxbgeQHx0vPkIhTk4wH3y0wRTUvTlyjPUHt
         me+Q6vMzNYD7kOzKwcJnaZEwN02898kiM4y2t4WHJS39CJY6NcoFMZ5UT5poPIc06XF/
         HGuTMIhO4N1/CNY/b4mIw0SJI70KC4e7Rqv48LZC7GJh+PP58JuvhRxtnQPXH8ojn/9M
         DWzmoPFYOic1RmZAyLtJsf8M+eHsg+PPEGijAcGjHpcLisOW8ZVTw4NE208w09G2gWu9
         ohpg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=hv7+PXgz;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [2001:41d0:2:863f::])
        by gmr-mx.google.com with ESMTPS id p11si257570wms.3.2021.11.30.14.06.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 30 Nov 2021 14:06:58 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:863f:: as permitted sender) client-ip=2001:41d0:2:863f::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 17/31] kasan, vmalloc: drop outdated VM_KASAN comment
Date: Tue, 30 Nov 2021 23:06:56 +0100
Message-Id: <a7214f1376700b74d98c66c2fc1792be7c54f3cb.1638308023.git.andreyknvl@google.com>
In-Reply-To: <cover.1638308023.git.andreyknvl@google.com>
References: <cover.1638308023.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=hv7+PXgz;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:863f:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

The comment about VM_KASAN in include/linux/vmalloc.c is outdated.
VM_KASAN is currently only used to mark vm_areas allocated for
kernel modules when CONFIG_KASAN_VMALLOC is disabled.

Drop the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/vmalloc.h | 11 -----------
 1 file changed, 11 deletions(-)

diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index 6e022cc712e6..b22369f540eb 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -28,17 +28,6 @@ struct notifier_block;		/* in notifier.h */
 #define VM_MAP_PUT_PAGES	0x00000200	/* put pages and free array in vfree */
 #define VM_NO_HUGE_VMAP		0x00000400	/* force PAGE_SIZE pte mapping */
 
-/*
- * VM_KASAN is used slightly differently depending on CONFIG_KASAN_VMALLOC.
- *
- * If IS_ENABLED(CONFIG_KASAN_VMALLOC), VM_KASAN is set on a vm_struct after
- * shadow memory has been mapped. It's used to handle allocation errors so that
- * we don't try to poison shadow on free if it was never allocated.
- *
- * Otherwise, VM_KASAN is set for kasan_module_alloc() allocations and used to
- * determine which allocations need the module shadow freed.
- */
-
 /* bits [20..32] reserved for arch specific ioremap internals */
 
 /*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a7214f1376700b74d98c66c2fc1792be7c54f3cb.1638308023.git.andreyknvl%40google.com.
