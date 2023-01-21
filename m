Return-Path: <kasan-dev+bncBDUNBGN3R4KRBEVAV2PAMGQEBLKYFKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B1B36764DD
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:15 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id u11-20020a05620a430b00b007052a66d201sf5028067qko.23
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285074; cv=pass;
        d=google.com; s=arc-20160816;
        b=dkIvFQ8x+GHMfkPYAhI/YaTpTxKgLTzuSUTMPd6RCDfzsw6Kib4LruHP9hQDZByV3z
         2i6lzXepzFoUbiUskJpRg02meIfkK0Z9US69oXmFclKhjXtb/H4uAX/vyZ4aQrnkLe68
         Pc6RJ8YpoxyQD80EGDApj1MElqkpAKoq8FcIXeETKfPj6e31/E3uof0y40RNfliN3Gpv
         SMEWGy1rVEFabc6yAT1uwJBE/KnHLH4zn3jQ7pTRYBnIjZM2g9mDUjZCzxVUm2xbSO92
         I0DQWrtPz6aid3LK4v+XgfL0PWwf9hbIHqvBPYr6ah5VVs2/lw3Hx2WVf5d85yH2vFmn
         yWQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ElPvL/w7d5q41Zm6WMjhkQEkRby2OkPC/V55ASs7kCE=;
        b=M9fjHYPsbAqlAP/MtNyKFeEhS1Bk9y0wwPOUuPD/9X15ZALFrWih7Q5kYyhmpFNHIm
         GmfYZtdfOry53s9Tnzc3KLryB2xIJMCJF2LnZbEa/EL6r93hBpIu9zYzY4p9b6pcduj1
         NU+RbSpMWXsLjYZ52fDKMNQx+4bkH+kgD1McJpIhf5zMDzWPlZPUqRIg2nlFi6wg/Ksj
         2RSp7pysyUrHoJA8OIG2/9Nnr7JQ3m3pQryljrf9LyUMWLfVGzB4jRWDNp0HwknIUvAo
         0L3jKn94KrIxtjO01+Rl1WIlW5o/eV3S4SXE3jj3dzwcB+9I/GZOY9UqiHzUcUY2xEoE
         99dg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=VeEOKHCn;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ElPvL/w7d5q41Zm6WMjhkQEkRby2OkPC/V55ASs7kCE=;
        b=P4SpME+tLlPwyBd3jUHPBe7C7Q2gRqqGAVA3hkeCrTyih/1CubJmIwJ8lhrouqjjU3
         FUini/O/h5gRSbA9b5dBtJunnPgzxHHBBVVE1KnRpq3N0vXMgCu/LLiySjRJeZhCoA44
         v/VhOsNQE38hs5sT6kj6or/LhfQkVhjaP2zmSyQI7TH4Lv96v1Rzs6m/LI19OhXzjlkl
         hhTkhJosTmo1oPby4prJf9moVVlZzIB14GOnyGOiUg8/JOm8BvcJkK9S/Y9p3pbK936L
         OIgZguIpg3u6oEeLN2N8O0vpHhT/YPOEYTZBKjfRxJzVg/jWji9SGlypT2nvVxxVpUy+
         VJUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ElPvL/w7d5q41Zm6WMjhkQEkRby2OkPC/V55ASs7kCE=;
        b=sydUPN/1IQFnjBMz6r3uAaHXc8mmcIqaCwwb9JZE+lcsBIotY1elF5aWZXfBygeku4
         tsi0OXczcQOt9IZBGuoFsUGi1EV+zlYaFNo9dApbYc2GgEnv8NO+LFy62YNMdOP+BnZh
         KEl1q86o193fkACr5yIz3Yhe49TrZ+TymriGF8I2Pxv87UUSPyjBUFJ9PuZKeABMUmeE
         lPzDQsS6AdcOarhTbRvbntAeCVdpCVaLhDZilYx6GVtgWrwiyQD8MA39BD287gPwym/s
         Qw2Qs3zyBBAxeNT4P2AFyNOM4oh7AixB84OeSbpbFLPE66+8rrXV5MJtVbR1hphODhm1
         LMcA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpxDwTPntMirzq02dtXvPRHUQaSBPA4e7rCN5d/I1oHmXvl3C40
	jE9lPnr0HiKEuDjLeYjVgiI=
X-Google-Smtp-Source: AMrXdXsvvgYtp+q4JfHBtnVmqA+IRD58mDKG8MIQM8GBzkEOlqtC+TO8QYqRmpL6ZBurB8TbAlaadA==
X-Received: by 2002:a05:6214:2d02:b0:534:6d37:975c with SMTP id mz2-20020a0562142d0200b005346d37975cmr1071954qvb.121.1674285074417;
        Fri, 20 Jan 2023 23:11:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:3310:b0:535:5ef8:149d with SMTP id
 mo16-20020a056214331000b005355ef8149dls2880739qvb.9.-pod-prod-gmail; Fri, 20
 Jan 2023 23:11:14 -0800 (PST)
X-Received: by 2002:a05:6214:5246:b0:52e:6f33:ec2 with SMTP id kf6-20020a056214524600b0052e6f330ec2mr24048664qvb.31.1674285073933;
        Fri, 20 Jan 2023 23:11:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285073; cv=none;
        d=google.com; s=arc-20160816;
        b=IDjaGmVVoN+6SgYt6G7/43/8Hdn2iNxCQ01nlZTu5g0daNG0AuPkbJV8ekrl/BgY0o
         eIgIxNGoXeGCBPnsy3O3jsf9YqLCAcdR3Sud9c2G2vS69DrFl0DCvrEEXQA8stSLPT+q
         q6SJvx3D7zpeFZ5a9DX5H6uIADRMtX6RhK9oXw4eqMZVZ9FgPe9gDWz5JjCDkMM6xn9t
         BmcbU9WzCtCnvGjk3r2meN3BEov/eBLB4jf4O7EBxPNaX8oqtu6YF1BerJxr/jgaO+FU
         d2K72ZeCgBFDxpqZ7uIu0O+gyZlcXlol9O77zAlcLEuIlnRh8ZPUIjE95yfKmk/XKHij
         b4vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=CBsCp/QzNVZu+9wjEps4s2+qTeM/ys5OZl1OD4aXEDs=;
        b=Nc6pNaHzIO/reGaKlKu7cnM1FpqwjZwPE+5Xn812mNOBuLk4hGON5gCRrj5RG2T+Fu
         eU0IkIQXBXzXKSrFKyLZu9n4lFYr4InA/6Nu5CvGodmbNviw6L8UvdGh058Ji1mcLkuI
         Quk/wG/ytEsHIlpROzckC+LqZfYHfNHD16HmmZRVMLUmn9kny/pMkYq3zNUbejcUZpTh
         eO6cIAqVhUSggStnRIRGxmJsdGIFe3GKIX7l+pmBjY99/aI/662CReroMiQhQsvaDvGD
         aNNu9+7iIHVYpWVh8MzFLZ9g9YZGalveJ3A8ytW3C4NqUIJZe5TVJ8fX4Bt316Av/oaK
         WGew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=VeEOKHCn;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id c3-20020a05620a0ce300b006fe3de3ed80si1180944qkj.4.2023.01.20.23.11.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:13 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ81t-00DTpv-53; Sat, 21 Jan 2023 07:11:09 +0000
From: Christoph Hellwig <hch@lst.de>
To: Andrew Morton <akpm@linux-foundation.org>,
	Uladzislau Rezki <urezki@gmail.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org
Subject: [PATCH 06/10] mm: move __remove_vm_area out of va_remove_mappings
Date: Sat, 21 Jan 2023 08:10:47 +0100
Message-Id: <20230121071051.1143058-7-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=VeEOKHCn;
       spf=none (google.com: bombadil.srs.infradead.org does not designate
 permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
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

__remove_vm_area is the only part of va_remove_mappings that requires
a vmap_area.  Move the call out to the caller and only pass the vm_struct
to va_remove_mappings.

Signed-off-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
---
 mm/vmalloc.c | 10 ++++------
 1 file changed, 4 insertions(+), 6 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 3c07520b8b821b..ee0d641019c30b 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2614,18 +2614,15 @@ static inline void set_area_direct_map(const struct vm_struct *area,
 			set_direct_map(area->pages[i]);
 }
 
-/* Handle removing and resetting vm mappings related to the VA's vm_struct. */
-static void va_remove_mappings(struct vmap_area *va, int deallocate_pages)
+/* Handle removing and resetting vm mappings related to the vm_struct. */
+static void vm_remove_mappings(struct vm_struct *area, int deallocate_pages)
 {
-	struct vm_struct *area = va->vm;
 	unsigned long start = ULONG_MAX, end = 0;
 	unsigned int page_order = vm_area_page_order(area);
 	int flush_reset = area->flags & VM_FLUSH_RESET_PERMS;
 	int flush_dmap = 0;
 	int i;
 
-	__remove_vm_area(va);
-
 	/* If this is not VM_FLUSH_RESET_PERMS memory, no need for the below. */
 	if (!flush_reset)
 		return;
@@ -2691,7 +2688,8 @@ static void __vunmap(const void *addr, int deallocate_pages)
 
 	kasan_poison_vmalloc(area->addr, get_vm_area_size(area));
 
-	va_remove_mappings(va, deallocate_pages);
+	__remove_vm_area(va);
+	vm_remove_mappings(area, deallocate_pages);
 
 	if (deallocate_pages) {
 		int i;
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-7-hch%40lst.de.
