Return-Path: <kasan-dev+bncBAABB4WTXOHQMGQERPNT2WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 8C7CC49879A
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:03:31 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id bg32-20020a05600c3ca000b00349f2aca1besf271335wmb.9
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:03:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047411; cv=pass;
        d=google.com; s=arc-20160816;
        b=NM2NHrKIy79KJPQYnwRgr6atu/bergIaNakiH7BHRyTXbZXjxXP6VtjGaYdhth7Kal
         bPGENYoZcBiLBK2v/0qqV6E3JJq2psskcQo6zFa4u3Lf3FzhMRXx0qWkFhFjYvrnyvdU
         h5/Pfg6Uhvnl4p7iUDVEybRutPDhLadSwBYEFkOHeCpUtlxpufxMoj44TbpxFP51GnPS
         neK01ReYm8VzK/gl4s8bO3Q9c1p8mmYXela2u4fU3GGkoTcSj/ID8k6UdQIKIOTVDS1d
         TvkwKE2d/YojnxLTP5pVluivgXRwBdglLyWXpaDQcUrH2iwtXzfmkUWv4a0/3kLnaDm1
         w4iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ZwUMcvuTK6vW7dctHTq0TvPkGiFxBkoxMtvriqKGoKQ=;
        b=cNO896ofJ0wJNHEhLu39go6+idFOoyCPEwCHFk2O7v5Ez31TXCDh5uamxORaK+rpep
         Z/AbbinYxxMhbCEvBiWcCH14QHiRL5wigRsr+6E50MY+gCEmrO6K/avLjJ0UVF+bo0Pc
         XYncuD4reJvsB6QOSO+2gJbB0hmG4bMBKixiElEiIPjRieysH+9LotoFibMtIxOx2Nf7
         w4ppsnT/EicIsWHKo+zH6KiTESinNqQ8GpVcTjG09a0j4uncQrDiHCAYMA002xUG+C1Y
         Sduq32EvMnNZayL535geDOgS2uP6GLvkLNQ5W9yY4JQWynnyms1wiMIJBiyYSTjaVZcX
         ixqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZoBLjoIt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZwUMcvuTK6vW7dctHTq0TvPkGiFxBkoxMtvriqKGoKQ=;
        b=lOsNnZ668H98Bm63KWFxlkDYYei/oQFmGo3/xYMHth4iZWKep/G6tn2MGyEI8u40lT
         teGSkzpjzgS3QkDW9wOUeQvb6DEN5Pw0DbVVmnaTxwekIr7HZj17JzCWvuHFrURgAA4x
         vgu8WxVV+GFm9aGQIBzkdCAFPtR3ROc2zRlJgL2W4rFANwgsjDidxUfiTkgFS0RmBCAm
         SvDIuo9Z5eXAg5tHVeL5c7dg+BAi9tekKCeM5EX1qOC4ygXzy+TSmoc+VyonK+I9+rWj
         jABbTs/kqCZ5ayu29jK5wML9c2HXJUhp9hBf1hluWMNYYBHzHVq5crFbkZsdrnnUYZd2
         R8PA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ZwUMcvuTK6vW7dctHTq0TvPkGiFxBkoxMtvriqKGoKQ=;
        b=apv2suYtHzH4nwmXKBWmNhiEjsd36SAq5wlUi5OumDHQTQAsNzRf11HKAHJSNTQkXx
         QdXID33/AgvRQnaMcajA1FQKDsI0tnT7bOHZ5JAxLYyTzeNy1kifzUZ4MtjHYpE3MKQn
         s/dwq517LoScwcGzJ+ghYDHJcaqBlpy6cyYoiR/nBkXXeJQiTj5q9REDBklviziaLcpW
         9sz5b0T8WU4pZuixxQdqaqnQULwBiOLuOuT6x9bkGsmJ0/sgJ9WhQMqKj//36yddMEWk
         n6MF4E8NvcVg0DRzkVUHsYV78qlVSCL+pQwt31pLsb1oW+Qs3FoQTLokEIrE7KOR0OrK
         XftQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530F7vKPLEG5MQT6GDSMZyEofRoAtTpmGjEwKY4L1xpufslY6bJs
	X9H9cZuph9/GYKD65WUH9kc=
X-Google-Smtp-Source: ABdhPJwQToLJYTrPoBT2t4nVXk/pUfROgZbGXCRgoa4KC7noTVtordyRs4uC7CaVEop8H/nxGCl+xQ==
X-Received: by 2002:a7b:c007:: with SMTP id c7mr2822106wmb.27.1643047411180;
        Mon, 24 Jan 2022 10:03:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1e0c:: with SMTP id ay12ls17175wmb.1.experimental-gmail;
 Mon, 24 Jan 2022 10:03:30 -0800 (PST)
X-Received: by 2002:a05:600c:4e53:: with SMTP id e19mr2761116wmq.15.1643047410230;
        Mon, 24 Jan 2022 10:03:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047410; cv=none;
        d=google.com; s=arc-20160816;
        b=Ku9lEUwQUMWWx0iVbm717gPnWEt9RGHm0uC9lUE9xRO8sOmmvZNZ4Q9f5avsIDd5zd
         8zcg9O6sKlx8xAWaQvuZcxacRaL9tRNhyMm2kL5ivKWLzqJAeLR4LMYbRHTdmwDtbO3L
         Y8Z1nNt6kZLbZ8PCCXJ+DtZ+cOru+kzf1j1+D38YbOUkg2Qz5YEYAn2suVkUZneoTiit
         TIZPVb/nY4Z+2U8Ry/rhuhxZVrKfDtquPUV1gavCbPRNS+AUW1oH2IYTHxY/4+eBVoBv
         1pmNxhraYWbqUYnvKW++ATIFYraD321TIkvaGw97zXL+wnxwuAMoragTaMPXmFEPGdFO
         gTMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=jPJkDDMANdyat2fWnF0ePoGcf0BIkGWaR4hg7xwqn8k=;
        b=xDc+WlXuaDnKZa6wHF3ax/krN8olZmXyxa6thv3aFKvItZGCfBj9no3fshCYe+vDNS
         sYj9jtadwgyLbbV7KfRUffqAFGRngS/EIaXie9Qxb0Xl7+04r/bELuWZTfFvvoJ3mtz/
         BzzvSdeO4o8FA85mi1Lr+jr7je9+GEQjWzMs2Ey8YfB+JVftWkuwgDuuZzZ887OGDlLq
         JjcVn9tYopT2G4zV0XesxzK0mAiOkFANk+0FMhU/RB3cwgU1AZVdWbNFP7qR8UiPglyU
         l7c5Sb9f/M0ApUb5UbNfis8FSMqZqReC/CQUSeqTH9yBpLpIgrjlSgNDwBkCS+LNWsAg
         gPwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=ZoBLjoIt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id d14si578595wrz.4.2022.01.24.10.03.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:03:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH v6 07/39] mm: clarify __GFP_ZEROTAGS comment
Date: Mon, 24 Jan 2022 19:02:15 +0100
Message-Id: <cdffde013973c5634a447513e10ec0d21e8eee29.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=ZoBLjoIt;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Changes v4->v5:
- Mention optimization intention in the comment.
---
 include/linux/gfp.h | 6 ++++--
 1 file changed, 4 insertions(+), 2 deletions(-)

diff --git a/include/linux/gfp.h b/include/linux/gfp.h
index 80f63c862be5..581a1f47b8a2 100644
--- a/include/linux/gfp.h
+++ b/include/linux/gfp.h
@@ -232,8 +232,10 @@ struct vm_area_struct;
  *
  * %__GFP_ZERO returns a zeroed page on success.
  *
- * %__GFP_ZEROTAGS returns a page with zeroed memory tags on success, if
- * __GFP_ZERO is set.
+ * %__GFP_ZEROTAGS zeroes memory tags at allocation time if the memory itself
+ * is being zeroed (either via __GFP_ZERO or via init_on_alloc). This flag is
+ * intended for optimization: setting memory tags at the same time as zeroing
+ * memory has minimal additional performace impact.
  *
  * %__GFP_SKIP_KASAN_POISON returns a page which does not need to be poisoned
  * on deallocation. Typically used for userspace pages. Currently only has an
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cdffde013973c5634a447513e10ec0d21e8eee29.1643047180.git.andreyknvl%40google.com.
