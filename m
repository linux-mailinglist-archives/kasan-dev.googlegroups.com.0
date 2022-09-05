Return-Path: <kasan-dev+bncBAABB56K3GMAMGQEXQMSVVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 619EF5ADAAD
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:09:12 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id h133-20020a1c218b000000b003a5fa79008bsf7913608wmh.5
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:09:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412152; cv=pass;
        d=google.com; s=arc-20160816;
        b=hJS+6WpkYE+OH2MGkPTTp+iJ5LjBMl461tBwxQs0ABkdTyq9Ttt6QiqdJNszMhuR5p
         ttAeUv4LPG++s++o00aAzS7yDkHztnc8m26ovfnWK6mO0f35m6MbAx8z1VqOQeh/lvM8
         aDUIcg8ljUNc2443Pt2nFK/Xj+0WwZYEKnaoQIX0m2gWqgXIrW/eWXwgU+WTyOQSrHL5
         P155WM+1mcbz4krbkpxdtGtLennDo/NNOU5MOLh28ku8v+yLodo8vZh42tHCB+UBo81a
         kE3OsxAg+FKwm21nccnHUrUb6eNE4E7ED3SMtMQvXD//js6ihGwBzfZzJ8CcQlhqj8x1
         N6OQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=gZ43J1pz96zV0GKaoPIgtskV2cgTlncjAt7COLJT0VU=;
        b=n/AMP0rdPqglr/Z/i1wz1bHRNC5/bbh9tGuWvBGx5gRPpCkbsnnsdJ9OV5Yet36xDK
         UZjblZH36KmkZXQoJsj1slk/Po26yh9Vbl8MVn3Ny8dLSMoBfPJOdLEcBWagQDlPjefg
         2ZCtoT/xUbZkUbjwNA890mH1iUUBrW4YwzA/7wuLrmiPQG9FT7icPi7RDR0XxhTsI+Xy
         wi8wD6cfms+t4k+fGsrsSMu52hSWBplHOWmP1XxbvitmAgfkdSHY7Y8KKsGo5cLz8KSi
         nbbXuTY3ZSbPnPCbUul593cnmAd3wkPZMxLbSmHeYPYMtbiVaLVYE/ObVWdgvxyUkCeR
         yRpg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XC2G9nUX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=gZ43J1pz96zV0GKaoPIgtskV2cgTlncjAt7COLJT0VU=;
        b=VhbdNGLcuJaXSfnHkPk0ndpTJ0B0xzp1UGPGM8rbT495vxIyBI8XVMmsUl6eSiRAZU
         PXYw5gd5SFbtAoJyZXs0vF04PKRloW4v1t6aSkcYrpcX5mWIoMworwl6CTZKIFasjIEM
         6dm1KiXdBpKfbxeG56jptPehKMNrehbkUU/xmjHdibnTLLpwsDsmgX20EuTsgaBjX+5Z
         SJ4+3QY/fUXAyO9y44L1rCsox7W1fNApUQJpNA27uIlAF55IRK4Xn2XF0OlJ21qcWr6V
         NlYwBWjchSsqXyxSj1cSacC3y4FhUzJVBHinBoev3IORe8psh+efybwYVWjD1c1A3bww
         rftA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=gZ43J1pz96zV0GKaoPIgtskV2cgTlncjAt7COLJT0VU=;
        b=rBeeRSpanYs8b1JqpVrfVq6y4waTjpb+m8WN9+FcxsUrCAsQ2UQ4be/tGEbP6f4S4z
         MAKOEueW7jUrF4gfaL0G4X/VVUzzC5znlur6wzLfl2UWn+nrscKVsinhq9ERCTtPV7uD
         FoaBTKPiv6J+a3vGk7ZqKns0gy0+tBxTIsFIZArfFRqnJyW1FQaJ7C73BEVQtux1Bclj
         0zAMEEiJ3UHxIVJnQ28+cXkfKheeliSZNywMOLOJtIjFfak2nuDVZgNajCjrsreKbRG9
         FQnXtUQffRpSEIyfU4/Msk5pskV+4IfiZb0HiXMxVix3ACBvoFYqkVQawfuoPj5pyTnO
         0pPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo2TFquUfCp8Gi9ikTqs+88iCawhpPe1E1vOxCcZ6mt4Z1fZbPf+
	oAyVJu/NHYtlFzBkMePZxfY=
X-Google-Smtp-Source: AA6agR4NMep/wvmjytq0vKbkQ4y13zcgjDZAyu0nhsojVzfTJqy1ZIse55rsrhvOeTnaZorT4Pvdlg==
X-Received: by 2002:a7b:c844:0:b0:3a9:70d2:bf23 with SMTP id c4-20020a7bc844000000b003a970d2bf23mr11711866wml.165.1662412152118;
        Mon, 05 Sep 2022 14:09:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c5:0:b0:3a5:24fe:28ff with SMTP id g5-20020a7bc4c5000000b003a524fe28ffls4172751wmk.0.-pod-control-gmail;
 Mon, 05 Sep 2022 14:09:11 -0700 (PDT)
X-Received: by 2002:a05:600c:410d:b0:3a6:1db8:b419 with SMTP id j13-20020a05600c410d00b003a61db8b419mr11851354wmi.119.1662412151525;
        Mon, 05 Sep 2022 14:09:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412151; cv=none;
        d=google.com; s=arc-20160816;
        b=rVhMJloXXRAWbjnjgz67S2k0NL6L8CXYccqFf7kAkOO0asv2wNEYNx5XJ8NROfvnfo
         u6t0FEcPPdRO8aMppEmSxYGkmO0aKS1t1kfVRwJcPAeuyo1A3gjxYSe//Fise0xjykfd
         TY0dQl3TYOWoVhufSWKaLx9en0vrVrr4m9k0mhRF5Nxdiqa+ZCkN8XDwzQ430Mz1nNEq
         k4d3R3nIhrBuHLrAZIOhwv2ZlXw43vKH7P0fNGoyCLtPtnYynmcxBXraY81TiX2kdLDG
         WfNXBioqnoq4Nkv0kaVC74q+UcWcZNzKBZvzlmzxtK/XIlJGUyJipmFwxY8HqnujKqk2
         urYQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=i+QvTW07XA+L+c+k80OvSUNhWYirWKC1C/9s/Xy3OVY=;
        b=vt3LiHXyeALVs3v06VQGMUHCNu2sZRQq0141/t0JFrdEEADaY/EECusG4I5jI/lrla
         ZdNl+lV7VHYoof8Nx4w1IE0BhibgP8zPS6clcvoZLL9Fc7RSck+NDT+XCX7VzR9RQMUx
         06z0vk6kaHB/lNhkPTprdGs4JqExruaiI6liDaR5SJgTngok2LDTbgRvdp+M1hoRWHU5
         Q4RTLN/kmEenbLYh7OgpgI5jQjYdO3HVdvqDTxYrTQJMb1MdyV8TXwHxZ/oHHUbaa9CI
         2o5aDZWrq+NMrvyfTl8okzWsBCUp1MOjhP8/tQrJJ3Vhy0XmGiTSBS9+NViP7Ac46F/E
         MueA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=XC2G9nUX;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id j21-20020a05600c1c1500b003a54f1563c9si614441wms.0.2022.09.05.14.09.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:09:11 -0700 (PDT)
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
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 22/34] kasan: use virt_addr_valid in kasan_addr_to_page/slab
Date: Mon,  5 Sep 2022 23:05:37 +0200
Message-Id: <c22a4850d74d7430f8a6c08216fd55c2860a2b9e.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=XC2G9nUX;       spf=pass
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

Instead of open-coding the validity checks for addr in
kasan_addr_to_page/slab(), use the virt_addr_valid() helper.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v1->v2:
- This is a new patch.
---
 mm/kasan/report.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 83f420a28c0b..570f9419b90c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -208,14 +208,14 @@ static void print_track(struct kasan_track *track, const char *prefix)
 
 struct page *kasan_addr_to_page(const void *addr)
 {
-	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
+	if (virt_addr_valid(addr))
 		return virt_to_head_page(addr);
 	return NULL;
 }
 
 struct slab *kasan_addr_to_slab(const void *addr)
 {
-	if ((addr >= (void *)PAGE_OFFSET) && (addr < high_memory))
+	if (virt_addr_valid(addr))
 		return virt_to_slab(addr);
 	return NULL;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c22a4850d74d7430f8a6c08216fd55c2860a2b9e.1662411799.git.andreyknvl%40google.com.
