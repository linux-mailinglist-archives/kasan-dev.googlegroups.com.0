Return-Path: <kasan-dev+bncBCT4XGV33UIBBRFL3GKAMGQECC5IPSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C0F10539597
	for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 19:52:05 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id a14-20020a2e88ce000000b00254078ad384sf2735038ljk.7
        for <lists+kasan-dev@lfdr.de>; Tue, 31 May 2022 10:52:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654019525; cv=pass;
        d=google.com; s=arc-20160816;
        b=oRtLZ0QzuXXqo0ctXEAP4EENTp9Yci5D7uK8pJi6ZLkoy6j87yQdfAcA1QPdI/ueNZ
         2kP55Y00NEUspRp6JZ1wDIayArllQp4gnj3SU9blF+gE5fIFF2ui7lno0O1tEHtqpNQI
         HEUzkBhC35ONNIu+h/Iz+krTO+xTTvX+BSLI3dxxF09ChwPjd4wzG9Mr4hiU/FqOvRNG
         dCI5ChLv3By8MhcgBcscPzvVHXgTEvD8oim1Qpt67Na66pcxIZRfzFwthUTSnF32LttQ
         NGfe+3ZSDwpE8y5vGKxl1pbjtZamwXLC0eDB0nb/sxhDBuH1ifUhHHJqk0oO6hHaJ8rR
         Lvkw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=/3q0C1EkuQEaEiF1enNFAJMk8oOqOgFbZrVtStwm9Gc=;
        b=NOb4oPn0GUx8pZ/eYOz6nTtxkv1rasbAEVioJ7nJCHlwLEPqnw2B5zX4tywuLJWlU1
         H+Jp3kM5ohw9uEcfE3SjwLyuLkorn0qgXNPP0PkBlFT5v5iSmXmhqIy1Z5ysKs1GAhAL
         GhEwDIBuGrVaWWrM2cDRtatLggKhTp1IU1OTldYqB1Tal+pfJp0CWtLSnjTkTFNbbgOz
         eF9vqYcNm2EW7xgSwSnUeKXfQ7H46aq36mz6YlnpPaJc8wuIlw2QMqjY3tKc9bbpHEtv
         jgbd9s91yhtvdF1P1zcflbf2P7mI1g7DeaTKCRFRjGnROq/f35Tzx/Gf/8mmmzrcEk0a
         uq6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="OxCWkOU/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/3q0C1EkuQEaEiF1enNFAJMk8oOqOgFbZrVtStwm9Gc=;
        b=fc6Cv9Mp73EOLo646J9ALNAzfqZ0z/hstN6Cxm/x/W1q7HgPQp50610Gy9X/c4DJDU
         KMgqB5ldv2AtC7DjMu37jkcbfEES23S/2yf4+WDQPtkf1oJMmioK+gKkavLRlCiSsXpj
         i0VTBueFWe2vCr7SoWpblNSQseBLrpkzvDbjpPkqqG+1sMvpU/EO8sehvwqLDVb9d7hM
         piIEtkWVI/BdDcduINWI7jSPmf5zZuXjpmRExEbLANKsFEg6ZDHTqjZnk6dB+vUckd7P
         DbziTt8rWVLnNwJVy6Ac33bG1x6+/B/SKaV3yBz4iVIV4TAGoCTMNMcF3nksgScRzErb
         I80g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/3q0C1EkuQEaEiF1enNFAJMk8oOqOgFbZrVtStwm9Gc=;
        b=0Qco7jMqPmftU32q5WqAE2/CdzSuuCu6MuoNnvEI4sqLDMfEEQSUcF5mC9rvTVBCwl
         UEIeN37ZUdfnyd7eYpwdmnGu0KLOn8v1LTHKXvRHOzrsVEh80Fyp8g/8UmtkWN4yIqE8
         OupNqrP0zAo3tjBsdakJRyE3hMhVuf/B39xO9b23vUShH03+kCdqY3fLHEoRIlM52LY3
         HXIihYs2qm+OuHEk4ifWtnL+7OK437Qo6YyU6jDnzcDSH3xur3+sao9Ji6Qp+eSByVFv
         VF/fNziwIm88mkUtgMkgTNEBNd1/w5iux8jZ3jnRIGN1Rb3Qc2nFko+B3QAr4V8hhGwL
         Zc6g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532EqeDElhukhOHxCTItUoYAkb+8mwZU7razQp25CryrANF7iKpO
	VV6WLnCkl2WeN57mMbpD3bI=
X-Google-Smtp-Source: ABdhPJxFCCD1c+GDg+5xY/9z0N1lsPZMY8+07ZTp64+u+arXslgGmRkf5AMeA5lAIAH/kpwby//afQ==
X-Received: by 2002:ac2:505a:0:b0:478:5082:eb1e with SMTP id a26-20020ac2505a000000b004785082eb1emr39030895lfm.551.1654019524959;
        Tue, 31 May 2022 10:52:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a7c8:0:b0:255:4831:bd8 with SMTP id x8-20020a2ea7c8000000b0025548310bd8ls115128ljp.11.gmail;
 Tue, 31 May 2022 10:52:03 -0700 (PDT)
X-Received: by 2002:a2e:3112:0:b0:24f:132a:fd71 with SMTP id x18-20020a2e3112000000b0024f132afd71mr37042193ljx.522.1654019523487;
        Tue, 31 May 2022 10:52:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654019523; cv=none;
        d=google.com; s=arc-20160816;
        b=XvejFiMnAGARextlj+ItZLE1szzwC5QnPOsEB4UYYPKYelt03xzyk3iq5d44dGGaWy
         wS86RedRNHr02Z1npYyNtMB+BoRa0GWRdFAQ3kyMEdZ/bsUmvj8zLPtESE1WCJnGz/TV
         gh3dWcwVice6dLf9gcnV64hqZZiRk3sy2ZJcz23EvZZ/pliOxSlvaUb3DSxZLIFFosKW
         N1ZXIyQ/swXi3NFp4ZVZ1Ly+0tlfa+LWv0Ue2iwXK4MzjTGAyBHJVaS5Xlpx4PLO4Tsv
         /LdK4OcXf56EtuH1N//EkORALUmsEFdUoqoZeXxNtvKByki6txYzSwt5b3809Q5YatED
         ISYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=d2vu0dnwiwxYpi/Uo7lHFyFUWVxqcu4fKiDfzJHG+cc=;
        b=zNXDwB1RFUbJ0RFQ6fkT/5H/5mHMbBAqUNjDJuW6sgVk1Mxm1L9OZShsF5wVwbMnbZ
         Ac3R24cxqLOFLbfgBvCl4DGw103ksBoXclEOOT4XYpSuH+hsXtXhxr/BLji98gWkD3ht
         r8YSlSxHr2Popuq+4F35o1cU/xKvEyuBdav2pgVENMB/D2VpOYKNss/P6gMF+Tre4zOe
         JIthl4i4zwUAfcZPOWuZlxEeeCQltZByMij3lUug2mG65s8QPCNrmlhs8tALudZ/spIY
         C3ImyyZhJsV9XTEiHQ84a/HwOd/oGwpVWX5dY5BuMq5R8WGV1FOMknHv5NuqcmIZW5gc
         MozA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b="OxCWkOU/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id v15-20020a05651203af00b0046bbea539dasi630721lfp.10.2022.05.31.10.52.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 31 May 2022 10:52:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id AC880B81117;
	Tue, 31 May 2022 17:52:02 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 20E06C385A9;
	Tue, 31 May 2022 17:52:01 +0000 (UTC)
Date: Tue, 31 May 2022 10:52:00 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 2/3] mm: introduce clear_highpage_tagged
Message-Id: <20220531105200.587db61db99f19e308a05c5e@linux-foundation.org>
In-Reply-To: <d6ba060f18999a00052180c2c10536226b50438a.1654011120.git.andreyknvl@google.com>
References: <4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl@google.com>
	<d6ba060f18999a00052180c2c10536226b50438a.1654011120.git.andreyknvl@google.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b="OxCWkOU/";
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 31 May 2022 17:43:49 +0200 andrey.konovalov@linux.dev wrote:

> From: Andrey Konovalov <andreyknvl@google.com>
> 
> Add a clear_highpage_tagged() helper that does clear_highpage() on a
> page potentially tagged by KASAN.

clear_highpage_kasan_tagged() would be a better name, no?

--- a/include/linux/highmem.h~mm-introduce-clear_highpage_tagged-fix
+++ a/include/linux/highmem.h
@@ -243,7 +243,7 @@ static inline void clear_highpage(struct
 	kunmap_local(kaddr);
 }
 
-static inline void clear_highpage_tagged(struct page *page)
+static inline void clear_highpage_kasan_tagged(struct page *page)
 {
 	u8 tag;
 
--- a/mm/page_alloc.c~mm-introduce-clear_highpage_tagged-fix
+++ a/mm/page_alloc.c
@@ -1311,7 +1311,7 @@ static void kernel_init_pages(struct pag
 	/* s390's use of memset() could override KASAN redzones. */
 	kasan_disable_current();
 	for (i = 0; i < numpages; i++)
-		clear_highpage_tagged(page + i);
+		clear_highpage_kasan_tagged(page + i);
 	kasan_enable_current();
 }
 
_

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220531105200.587db61db99f19e308a05c5e%40linux-foundation.org.
