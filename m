Return-Path: <kasan-dev+bncBDUNBGN3R4KRBHFAV2PAMGQEZ63TDMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id A6EE56764E2
	for <lists+kasan-dev@lfdr.de>; Sat, 21 Jan 2023 08:11:25 +0100 (CET)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-15fe7396eb4sf708019fac.12
        for <lists+kasan-dev@lfdr.de>; Fri, 20 Jan 2023 23:11:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1674285084; cv=pass;
        d=google.com; s=arc-20160816;
        b=TqUT0u1Z49ny5QRTe8SLBHDJjh/uEsZ96Aa6tsayGwlLwDaV3UPpBb5zz5ydg+WIQM
         +Y6W0gI3dXkAOVctzo92gnmyTkRmLVGMi8VNd/3uoVxuUtnc6xIcdx1/IUC5pTbTUb9S
         2zfr7G1PM1MWMZhwrKqyAM8uH9P9PQcVfAt/UMsvgPLcbncBGtS+A3gR5+HUnRjNXTxt
         DuHxWQDWNf8sinHnSGi6OJv78AtE1vRFCJk3VqLQLJPAZVQCBHRWUiM8uanK7CcXSm7f
         x/MoW4SE7NS5DOdYeBIkkewhl+TANFv3hTaIDDk8Yyest3Y66+gxSZoKac2s0nQmgkKM
         CvcQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=b7//y9GljHZMzBgGzb3hV1NtRiB9DBy4lXBM7JsOfmo=;
        b=I4zuvp516h5FdvgFfDZKvtctYIzHt7OAq1C7/vMDe/JokGgUdiailBwyQvLGSapNzD
         4poCkZDFb3923W7BGgVRxwPdd/jkCdDPLF41dlQc0jTL1SWoPyFhGz5Lf+QefttYF1r/
         SiHO53pLqzkU0QB0Ug7j6heRctW9+lSyEC8VVJOzYX0Ax/57OcqcOLARsD62XkSUZR89
         H7FbDoYMDzYwsmr9MU8okaFLSm/5AN0epL/rrNcmNOEE9JnFkJeqiNF4hTr3MDkYV8K8
         BhjE8M7Mfoiq/4pcQJLeK+FaIEUwRDZdYue/N51noym6Iny7h/4BZcOM+T7UBF+mPvdO
         aIeQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=BxwUWG+8;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b7//y9GljHZMzBgGzb3hV1NtRiB9DBy4lXBM7JsOfmo=;
        b=VEjeHHKjAPk3tpl00IGcf7PdUjx4JONiwo9OfyJ1VtwyVnL6X7ptaVNisAHaw+Tumo
         7QQrTgdLoWCZ6FrwPgccedVrCR5eR3bNZdypCOVXMOIngL5P5cFMbCb6zmFmHcOzpl/6
         2mbgl1YusMiob2OBpVk2OGWkNh8IIDiCXmidbeoXSRJfpL/s9kiDhO9UUItysF5zmD+U
         cbTe8wFLYMVPd27Gy7THSNikycpyBTfnLrGoTpaTCCQ7t1cWOljrcC7abRPhO5pxpLt1
         0eoFg3pICNjbMX+9YB9oygC3ppqOkKq+bPjlLFgCJ6E7m5mC7u3GrFc18GtQz3toVWOw
         q8rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b7//y9GljHZMzBgGzb3hV1NtRiB9DBy4lXBM7JsOfmo=;
        b=ugA+TqETAr7D6OKrKJNQH2DAaBYNoLHyheNq3Oxn66AgWnokY9iSWPRTROH0mypj16
         LS6t26WtrdsZ6Su591IpkvfR6KJ1kBxXf0jgXzwI8heITP0hErrR00yh72QfrgKlF63v
         weBIXxwP7JOavBvp2p1mK9EL+iRFwD2MRm8HugJc0V9CbyErPIvGWMw0VtvIz2b5DPXb
         fougjYTh3VG0CMpgLE9cIepmaokNXjsXx/NCfXsUbKkF1ULidk+tLtegsJgJTHWnP9uN
         8UyxqGnNgx8kWY8Rka9Q5APbLTkVmRcr3Xd4o8qy4kXqZuMhixfNdDQCmlZsWPmG/z5/
         8Wrw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpt8GTuENW5TXwusb+FgPXhNrpUKSjBBRzsCsHSPxCrn9GEI9n4
	JhwMEXx9MhcuRe6ozT9J1Rs=
X-Google-Smtp-Source: AMrXdXuHXKGKUZZLcKR0npBCzbhusxi/DtxSOslbiWVZc3HBhlX3SZC85du4CdhdmwIUXOq57ocBEA==
X-Received: by 2002:a05:6871:4485:b0:150:2bf1:4446 with SMTP id ne5-20020a056871448500b001502bf14446mr1771605oab.228.1674285084467;
        Fri, 20 Jan 2023 23:11:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:52c4:0:b0:4a3:3f3b:df28 with SMTP id d187-20020a4a52c4000000b004a33f3bdf28ls357698oob.2.-pod-prod-gmail;
 Fri, 20 Jan 2023 23:11:24 -0800 (PST)
X-Received: by 2002:a4a:8f04:0:b0:4a3:9f7a:add0 with SMTP id e4-20020a4a8f04000000b004a39f7aadd0mr7436668ool.5.1674285083942;
        Fri, 20 Jan 2023 23:11:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1674285083; cv=none;
        d=google.com; s=arc-20160816;
        b=vjzh6rV2Pmunk5+YAGkr1/DPoGnZ85u8ih7T56FGuqHl1N59Erz0BAtsm3Wbq6YVlk
         MBDJkQpo0RkScIMYlr3+8612ulP+wrA1Y/OYir3lA6zBbKVoDQwXr6djz0KsaF+t3B0N
         ekil4sc8e7jyNOvp/7ox4GB39hfdO5LGwyUU6sf00L7w71F7ur/LvhZK62GL3fLoRyD4
         iCtOih60KwTnNtGm9+8RN33sCDDWyJ1Brn3X97Jt/z16IFDVefQs+tQywf3ScnlrX9r+
         8l4f8tnXYKY5D7TZdK8lhz+FXh5VC2B0tMG8ytXCUDkxekMcEfbb0R9w2/XX6AX+ca8q
         yVgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=MVFwvinoUqx5/lg5psoeJPHtHhWtA7mgRAAlRnZDces=;
        b=Q4eT5YUBBrBWVDVkAbJhteqAKmboL9reVGVI2NRPD6BzM87titNF34U+jTgfUiKJXV
         nBlJqyKpOXLPfgeE8OcCkXPtby6wO8KLP2nJ2gVt6Kzf0kIfhnnt72O8DqmCMQ2eLiEO
         ALQOH1zpTKEe/cSsoUYLvtsTgBLQNiIwBbkKJB45zLSQOpdtGsncWrwFTUfFhjKi9C5B
         MPQW9aA0GdEXcDSdD255XUZO1WvDJVZikdKtSHrhEWjQGBGVppjI8WP6dzJwcH15hqvW
         ygSgbNhLk1bYQo+1k6whFoPAxQPwpHVTZ+8Mlr4+fB+X2RHu8Lwn8vAsWUUmrcR1ODqD
         +TUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=BxwUWG+8;
       spf=none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) smtp.mailfrom=BATV+1651c3ebed9361b307e7+7090+infradead.org+hch@bombadil.srs.infradead.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id f6-20020a4abb06000000b004f52827c8b8si1465707oop.2.2023.01.20.23.11.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 20 Jan 2023 23:11:23 -0800 (PST)
Received-SPF: none (google.com: bombadil.srs.infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from [2001:4bb8:19a:2039:6754:cc81:9ace:36fc] (helo=localhost)
	by bombadil.infradead.org with esmtpsa (Exim 4.94.2 #2 (Red Hat Linux))
	id 1pJ823-00DTtM-NY; Sat, 21 Jan 2023 07:11:20 +0000
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
Subject: [PATCH 10/10] mm: refactor va_remove_mappings
Date: Sat, 21 Jan 2023 08:10:51 +0100
Message-Id: <20230121071051.1143058-11-hch@lst.de>
X-Mailer: git-send-email 2.39.0
In-Reply-To: <20230121071051.1143058-1-hch@lst.de>
References: <20230121071051.1143058-1-hch@lst.de>
MIME-Version: 1.0
X-SRS-Rewrite: SMTP reverse-path rewritten from <hch@infradead.org> by bombadil.infradead.org. See http://www.infradead.org/rpr.html
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=BxwUWG+8;
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

Move the VM_FLUSH_RESET_PERMS to the caller and rename the function
to better describe what it is doing.

Signed-off-by: Christoph Hellwig <hch@lst.de>
Reviewed-by: Uladzislau Rezki (Sony) <urezki@gmail.com>
---
 mm/vmalloc.c | 27 ++++++++-------------------
 1 file changed, 8 insertions(+), 19 deletions(-)

diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 6bd811e4b7561d..dfde5324e4803d 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2617,35 +2617,23 @@ static inline void set_area_direct_map(const struct vm_struct *area,
 			set_direct_map(area->pages[i]);
 }
 
-/* Handle removing and resetting vm mappings related to the vm_struct. */
-static void vm_remove_mappings(struct vm_struct *area, int deallocate_pages)
+/*
+ * Flush the vm mapping and reset the direct map.
+ */
+static void vm_reset_perms(struct vm_struct *area)
 {
 	unsigned long start = ULONG_MAX, end = 0;
 	unsigned int page_order = vm_area_page_order(area);
-	int flush_reset = area->flags & VM_FLUSH_RESET_PERMS;
 	int flush_dmap = 0;
 	int i;
 
-	/* If this is not VM_FLUSH_RESET_PERMS memory, no need for the below. */
-	if (!flush_reset)
-		return;
-
-	/*
-	 * If not deallocating pages, just do the flush of the VM area and
-	 * return.
-	 */
-	if (!deallocate_pages) {
-		vm_unmap_aliases();
-		return;
-	}
-
 	/*
-	 * If execution gets here, flush the vm mapping and reset the direct
-	 * map. Find the start and end range of the direct mappings to make sure
+	 * Find the start and end range of the direct mappings to make sure that
 	 * the vm_unmap_aliases() flush includes the direct map.
 	 */
 	for (i = 0; i < area->nr_pages; i += 1U << page_order) {
 		unsigned long addr = (unsigned long)page_address(area->pages[i]);
+
 		if (addr) {
 			unsigned long page_size;
 
@@ -2740,7 +2728,8 @@ void vfree(const void *addr)
 		return;
 	}
 
-	vm_remove_mappings(vm, true);
+	if (unlikely(vm->flags & VM_FLUSH_RESET_PERMS))
+		vm_reset_perms(vm);
 	for (i = 0; i < vm->nr_pages; i++) {
 		struct page *page = vm->pages[i];
 
-- 
2.39.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230121071051.1143058-11-hch%40lst.de.
