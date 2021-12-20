Return-Path: <kasan-dev+bncBAABBMXZQOHAMGQE6WKV3YY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 18D1747B575
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:59:15 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id bi14-20020a05600c3d8e00b00345787d3177sf573497wmb.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:59:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037555; cv=pass;
        d=google.com; s=arc-20160816;
        b=SuQ+JwSjDI0Wq+/h3pGevnRnjn+LzrFPqb44aIPct42Z/Z+NDBDJyeEAP86Cyjjm4M
         CLxcC30VZ5gpq45ZDaSAPGscbGRcwjjap0texneLUQ4qpR48Caa9d9ArNwGx+IkVfwCf
         GE/AeTEtIWkVgEWzVKtX4sYydFDwCG+F6fyNddJjZ0rrPLFn5TAZRryMljd21AMxwjI0
         Ho1zcVX3vSerjIc79RLJJyYNuyCL7HSg7zxNv13uHhuQ3t0Rgc6g2wGizk9f1PR002tH
         r0BY2T880cs7hVzgDCJNv9NHfXQmh9KMTNISGL9H4lS0cxEv1StoxDwe/1s7ArHAwZfY
         EJtw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=CqrPnj6W1zl0GdivtJuMptdlkYDUBuc89jvIXD5swhU=;
        b=iGeM+3MAf2avZW4S89UOadcP3IRDi4xURnJXVdAASSIy2j7G2zR7m41zUoNpzSMGL8
         st+Lg20CySd6H71yQJ9Kw2ZCRgy8AOI4lsMeGZy9BeRmNqtVrkZVqA1JCrcHD82WzncI
         gDAJOTSQnnEWK3D78JmWWEeOJcBBAqcyfVx3mOrzO2Yzahc/cVFEr+Fv0HwK555PVRif
         rLyb0t+lSASQCtFFuUmSNS55WoLdU9n4+y/CkpmfJZHsB4Qx3uFoQZ2+nG/au5haJAC6
         Bi1u9XjL9M/3jcQULfFHZ5gWcLwQ7y6Vvv4zFra+cTV9DrN5OJw6gxQ6n2IyEON3Z0nE
         VJcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n3qgP2Kw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CqrPnj6W1zl0GdivtJuMptdlkYDUBuc89jvIXD5swhU=;
        b=pw9VaTLn+va6CJnUYnUEA+61Mas4Rpgt0FaWhUoJtqp/ZmdsRNYMtbWtirz2HKrK1Y
         kZ5+eHNgx2vkKP446h+oSTt9ROO3gwUl04KBlX/6kNsXI4gh59kqh+yjC8Vu0OPJ7CGk
         VE7T2j2YTz1Uy+Bc59dFJ3OZ9IuKGWqWMNeHFdxWJycFs15qLfeSHsQI6+G76yCcRdMU
         nn+VymyfOXBBaEuxAy5vNvAf5yG1lBSD2ppURg2S/TGfK0/eFX380J0+uYz3KwB52X5u
         ifbBD+PBJZGhjIiWV7rm9ZhfMTVitflS5+AcqSSo5lywHld4OYty6IPjW2YK87GcWaSh
         9/2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=CqrPnj6W1zl0GdivtJuMptdlkYDUBuc89jvIXD5swhU=;
        b=NIiNd/ej12iZnb2hSosLhVyybWAP+dxxU2uL/xEeNXyRnEbesg7BO+jK9KfYmURCrR
         /MI9iEQHeEr4dIyaZh1tOj6CDTwxzXUYnq3c5U4au5fJVxPHBZ/WyV089GSzZLOaBBDK
         G9uT5fxtDh8w+EJ6DJ1jR4YzkMWDRAOjTngAi5peXYwGRGoot+lIHuhcY+N68eY26y4i
         6cTfYzqg+h85nusHazhOpAcJRcjuTUEVfus8O+51LY6QHPLYZV7JxOpKd9+l76UmKo+g
         h0WLGdknmM+g/C9vpFat9jXLyqJv21MYdCcapom+0Geqtu3nUwfFKXJU1Nf6FkWacUWF
         ReqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Jio5Qjp1ao8GFAjPvr3V4VxEAdfnAoFKTMXqwV8B9vvkhGgqy
	tUpaFkE7PhWP+kpHYljbO6w=
X-Google-Smtp-Source: ABdhPJyoiASQwnuJ60k8znmd2jeoz+owYufpOX73SgShIbqAPhT4N6j50GiUSVccoemgEmxy1Jo40g==
X-Received: by 2002:a05:6000:1acb:: with SMTP id i11mr107791wry.244.1640037554858;
        Mon, 20 Dec 2021 13:59:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5082:: with SMTP id a2ls6376420wrt.1.gmail; Mon, 20 Dec
 2021 13:59:14 -0800 (PST)
X-Received: by 2002:a05:6000:15c6:: with SMTP id y6mr114911wry.20.1640037554213;
        Mon, 20 Dec 2021 13:59:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037554; cv=none;
        d=google.com; s=arc-20160816;
        b=uPRRtvs3ebJLno5UlcBG2zBsV2H8gGdzTXfahp3M6DX4u2CVSrlL0m9+kSHW9vk+PE
         CeNWGpQEtjRbdGxmp+1SqcKduOkSCBErBZB2EFWnfNKjb9UYR3z5srLAnX2Ir/Gt8Wn1
         NApd8XklE2LZF/TryLn64ZO39N4POLYw1JWflr+V2PZaAeTkqQPlZWalem7LVDrDpxGN
         zVLL/gEAQw2zzE0dcF3o9WKvRFWjWqePBV08JnoLygKqrk6jW9npF5apQBw2LzDr3NmD
         Sinx9dTRBagneaW9zl6Pbeas9e3KIZYny+XoWFmHeinx7MvPN141w2T4Qz57TBJmXkmW
         dHwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aF/w+x0GM7OFXEFWoRiyjv8BJ7kPS/Lh2UMzxPnFpS8=;
        b=yNbudXercupwinmecADDEm2p1GuUcH0KicYaRSULHv4TwQvzfpD5DSZ71fujSN2lrn
         4oggQFWw4FIifk3vSkgWUHrsujM6S9QR/WSy8utfspr9cajrGlaBg7HQDR9Z3ExlEUwE
         NcIkuBeDQIC068VQZQ3ybJWUgWC0zcREuPI9zcvXsXrHzeEocq6tUxvTuF/D0jGw2HKU
         9klwU8NwRxlV1/xdsYZzS58fgTgS3KVw90P0J0yQmIFC+0Yl9gfM9foshoxnvdAn7tAx
         CJbhT1h7LWa0TsAljuv3kBYtaqTIeKOy+3b7op+kLqR8IZTF4KC0ZGo8KI1eiUi1Gz6T
         V5zQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=n3qgP2Kw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id o29si31923wms.1.2021.12.20.13.59.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 13:59:14 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
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
Subject: [PATCH mm v4 07/39] mm: clarify __GFP_ZEROTAGS comment
Date: Mon, 20 Dec 2021 22:58:22 +0100
Message-Id: <92f3029f3647ab355450ed5c8252bad8cfae1e09.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=n3qgP2Kw;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

__GFP_ZEROTAGS is intended as an optimization: if memory is zeroed during
allocation, it's possible to set memory tags at the same time with little
performance impact.

Clarify this intention of __GFP_ZEROTAGS in the comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/gfp.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 0b2d2a636164..d6a184523ca2 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -228,8 +228,8 @@ struct vm_area_struct;
  *
  * %__GFP_ZERO returns a zeroed page on success.
  *
- * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
- * __GFP_ZERO is set.
+ * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
+ * is being zeroed (either via __GFP_ZERO or via init_on_alloc).
  *
  * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
  * on deallocation. Typically used for userspace pages. Currently only has an
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/92f3029f3647ab355450ed5c8252bad8cfae1e09.1640036051.git.andreyknvl%40google.com.
