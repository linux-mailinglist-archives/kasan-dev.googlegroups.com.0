Return-Path: <kasan-dev+bncBAABB3HM26LAMGQE7772PBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 44E64578EBF
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Jul 2022 02:10:21 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id r82-20020a1c4455000000b003a300020352sf5451538wma.5
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Jul 2022 17:10:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1658189420; cv=pass;
        d=google.com; s=arc-20160816;
        b=Obk42Zh2NuLHCvr1L5X9K/Fi+POD+fp7BlRjnVIO6VL+4VF7eOaS0C13hHSPBlUdou
         c3qOYwEmIiNaNBbwFghitzE/ErZqg4XPAZCrfITLpvSKZXOLffSrb03oS4QTOg3VjloP
         s4i5jAjTGmABi2IIQHnK6PgYrgRNor5fepNH4DMUc+YHan6CpkJHs3ZiUoKo48a/ytx8
         3xNweZRUUasv8gobSnBPbmvLXwonxwHYJ1liiCe2HPhAvFQimPB357otfU3tBd7plzAf
         ehi/OVzcofuoP4g1W2bjLTEXIpPUbc28hEHyX/z9/eMzZp1Rp4aXGyJ+SD3izIyu0D7B
         wioQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=I3C65/VAMTZNML1mrNCCX/BAQXoRD3Nwc2iXaJqLa80=;
        b=mqVUa1OzYL1ozG0Q25EdpIvQiTX3Wp8vZ+uTsn6oSobKWOwBnCNh7KC2K1FujWsyps
         VHtLl+hreW9I/iXXGQDHuG77zYRV1hRJhnthXG86qBV+Ds63iaotcCSV6xH44M3WOlxN
         HtM1nFTI4V4yFbsTCyADt03F6Xgvs8INt7Z/MJPr1xNFT8LVKnWv5bTLEo3aeB9WSL0t
         is2rstA78vlr4K70bOz0KBq7INCwqyrb5azS++haTdauoRmZX+9SGF+9n6f37/swNSGx
         6+5DWATn8FrC+9ncA39AwqCHyi6T65ZZsDdPdzsaLUW8whl4URgdIlWjHYMlm94j5Ecy
         I1dw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=u99oHTV4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3C65/VAMTZNML1mrNCCX/BAQXoRD3Nwc2iXaJqLa80=;
        b=l29L2B1dpwRRqT3GFgTtJ3citNjxlw7I/Qt94hcrXnV6tGB7a3BpqhisaE8Uy8/kNY
         12f4jzDnKWls2VNhXlf8u9k4eRP+7L9Xks4e4LFbzLnDlodepuH2XGrrevKoDmyuNecc
         OiQ/cC6B5VJC1BEqwy+FWc0Xbpsk0uqKwAqKvnrheEvFGMl7GlW3gPBL6Cfa1YkvrXvQ
         JvsTWgvLpRVWfyCpCkV0QykRjm2P5eQrlwWLkDSWVPddpcY3Otn9qjGPhhrLumVwXW5Q
         vXwCWIIM0XdpokEfR5H/y+9Ty5Ax18S2gn5BxsQABK//3SGSNkwuO33oaFYHeK/Ct+hY
         +V0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=I3C65/VAMTZNML1mrNCCX/BAQXoRD3Nwc2iXaJqLa80=;
        b=V13p7JaxpGJZbCKSG6Am/NmBqg71jROvTQoeplQfocnbM7QX1VPxHFD29GxlyZIQ0k
         4/wcPEJCZVKFLth7n8PJxRoIsWknPt9FByzNujPRj0ddAqMuaEnxOD5Bw66WkKoOR0MA
         hJb/m5gc8u7bKV9adAwGlc2qHTx/KfDBTNB6hVwHzY28K09QkISDQmSSk8+9e+P5jWVK
         GGzhgeHUJFtZDA8o046FgTN0m0wgaGnxpuSuWeNtVC+gGqx1+fUXzA+Fns3StDwyYzcg
         IBLmY4LLF3mQ0kLocpyyb3mXPmfcei1q5FtjpFEF70SXMaYcdNUIEwqersfaRA06+YcC
         YOfw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora/gi/FCPOksijje3+9kVX2G3m0RpN+FOTxP8BR4E20gnVNIbj9D
	AS5bJz5wMNGO5T/S3Gy4kqs=
X-Google-Smtp-Source: AGRyM1uCi86eqhBlvFZzQGgb05o/oeBahzxoGzJY9hrW7W/GC6s9MowA+pgPQeoGkJVbnS8qvSc9Jw==
X-Received: by 2002:adf:f20f:0:b0:21d:6de6:6f47 with SMTP id p15-20020adff20f000000b0021d6de66f47mr25356833wro.532.1658189420608;
        Mon, 18 Jul 2022 17:10:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1ac7:b0:21d:ab25:25ba with SMTP id
 i7-20020a0560001ac700b0021dab2525bals471878wry.2.gmail; Mon, 18 Jul 2022
 17:10:19 -0700 (PDT)
X-Received: by 2002:a05:6000:1046:b0:21d:6c52:b648 with SMTP id c6-20020a056000104600b0021d6c52b648mr24909034wrx.131.1658189419869;
        Mon, 18 Jul 2022 17:10:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1658189419; cv=none;
        d=google.com; s=arc-20160816;
        b=Q/9JuMA2PFm7agEvp3JQQSd5eBPHalvlHh/5nSq61AEGnj808mUq24adu80qKv52vJ
         ptH69TcgoOgaez6rKmPtzUpvE7eIBVQyO2wEWX+1iMrouox6SrzGM1AYaHKvu2cdXb4r
         Ng27CjvCJS1SirceT0N4cph2iE68vdUntl7sESOwQjgLJw6DFyvA72wEe1OI2YKE5oTR
         1FgWFDf8QFgyV7qTOTAqdAf0sOB6H1RlSjuV4Y/HfjV6GCzswHiIqhwu1kgCJ6zyCcyA
         aq2mNbUvgocR6DMzFN2PqnJbBJtNoZs/r22+mxa1U3VSOB7mW+nzVqS12yikkXf42y5Y
         mB4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=sonD4+6h/lo8DkbhcKGrk86DBB0a/jVHQ/3znGtvMfA=;
        b=cyLCgwkT/2d4NMlDKZQs1VeFoY84QUIT5EzGR88EZNCrAfyoEmOTpbE1mo80m2vbyg
         13PuC/TmkAzUnIzYYV2xEh7dP1ttuB8WNhIYNlBdhacwqN2O5bSKZK6WwLekBfQJsGNk
         lHLpYz47U/SvuJVvdpARwo8SGvJvoAGVU08XH5d7bf8EVWNwPObh8C9QfcJXFv77Ttid
         P1L4orubaCZkLyBO2Fc3OfDzuI3yw0hHx22Vm3ocoaM+c/4cVCPomlso/UzuWfbQcABp
         XLLHvTvaK2DPtvfpfDOyfRXIZkD5aTNI2MDCVYKDH/ZhXY3fO9NOvz7rDCLuCg5ys3nL
         ejxA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=u99oHTV4;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id bz9-20020a056000090900b0021da74303d2si486099wrb.8.2022.07.18.17.10.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 18 Jul 2022 17:10:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v2 01/33] kasan: check KASAN_NO_FREE_META in __kasan_metadata_size
Date: Tue, 19 Jul 2022 02:09:41 +0200
Message-Id: <e4a075c43dc6793253976780311543fefd82cba3.1658189199.git.andreyknvl@google.com>
In-Reply-To: <cover.1658189199.git.andreyknvl@google.com>
References: <cover.1658189199.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=u99oHTV4;       spf=pass
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

__kasan_metadata_size() calculates the size of the redzone for objects
in a slab cache.

When accounting for presence of kasan_free_meta in the redzone, this
function only compares free_meta_offset with 0. But free_meta_offset could
also be equal to KASAN_NO_FREE_META, which indicates that kasan_free_meta
is not present at all.

Add a comparison with KASAN_NO_FREE_META into __kasan_metadata_size().

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

This is a minor fix that only affects slub_debug runs, so it is probably
not worth backporting.
---
 mm/kasan/common.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 707c3a527fcb..b7351b860abf 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -223,8 +223,9 @@ size_t __kasan_metadata_size(struct kmem_cache *cache)
 		return 0;
 	return (cache->kasan_info.alloc_meta_offset ?
 		sizeof(struct kasan_alloc_meta) : 0) +
-		(cache->kasan_info.free_meta_offset ?
-		sizeof(struct kasan_free_meta) : 0);
+		((cache->kasan_info.free_meta_offset &&
+		  cache->kasan_info.free_meta_offset != KASAN_NO_FREE_META) ?
+		 sizeof(struct kasan_free_meta) : 0);
 }
 
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e4a075c43dc6793253976780311543fefd82cba3.1658189199.git.andreyknvl%40google.com.
