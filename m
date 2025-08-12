Return-Path: <kasan-dev+bncBCKPFB7SXUERBHXR5TCAMGQEDN5FRZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D37A8B2275B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 14:50:40 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 3f1490d57ef6-e917c1cbf5esf1074325276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 05:50:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755003039; cv=pass;
        d=google.com; s=arc-20240605;
        b=i87w3VAxjIk6dvFfQsFcJBCRGb4EC7onF8JlMHqzUgcetKgkcVGOVuJy8WooJQUPZa
         lSIzeTwxgxxZiREurWGa0DmDHM5T+aFOlBJxtfDcuIjC+dCUrvGIR7A/JfDBe6/8DVx3
         wv+1pBMXTtxASlFeOSXWuM4Q2Rnz8NQjK4wspQpSvg/xt5aJFa0zsL3Fskq1jAzdnedA
         MvEu3Ib5B6x6wj3eI1l0qH2pu2L5rtQhHeLJtVKDtYbeGmrcSu5MdYcOvzON4L02bTuJ
         4RGph0siVdFbRWu269ycW65JrvWTx2wQvk8Dtui2mEH9hdhyybPEqdfZN7xM0L/5GWQt
         +m6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=YT51WUHAEKhfG+YDsBoeXwKjLVkqalaTaqntaecx0U4=;
        fh=ynRDY5b7rDaJCOhr9f8GUBFvRGCwpIyqD4yWi+7sk1E=;
        b=j5BW1aYWvpBwOrxLuAzuPkzPBUemA4s0Bs9OyO8zXfIWTdyJLGB+07+1bmcEW5f9Vm
         FR7LCwMNaYVk7UkqTgm9OH+1xEFOMZjr4xrYLfpt20SwE1M7MQEHFbbc0GtmWRcufPzD
         KK2pSQ3vufKB2eh/fdP4VWwiGFBqLqAV4vlySmK4yyimaNxTNYypB9i79zMmFHUxOlV+
         Vji11QwsproxMPGJVHQSvOT01bEPQYNxREDxr274Sbuq189KH9aOFyhjNxaarU6NgOZg
         hdQxUErZdTOabXqBrUNhMe4pW2au3DvAm1lLZXHHp4xOIPUzbLY4ZpXuGSXoS9u6y7AT
         YBIA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=jPQXWaKl;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755003039; x=1755607839; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YT51WUHAEKhfG+YDsBoeXwKjLVkqalaTaqntaecx0U4=;
        b=GCW8D/yWOw9DeHu+uD8lVnbtMEH2IgEYXXucZXXPfu7iDFK7mXFJdXjq8x2VBMSMGU
         xD9J/doEIPg7xeDkZtNc+9VmUBGPahuv+euraRlNd4GE6elZHpfPj2KMmreGjAKn8Dpl
         IghPd6UPcrsxh2tEVnr5V6SWHAhw+iewuXYaSatfPRYqJ8r7OTS1pFz41CD/XsfBKO7Y
         I8eZizmPu8UAiD9M46ocx5yc9dgVkTTsRr2Bqpd1fKccuj2nUCEeUGP1reqZXjLFqouc
         9Gi2LeawW22R1wriantaGpVjSs1eVyIJAitQiizlpZ8MrnF/lCHs3gFoLW2+O89S8Xb2
         aOKw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755003039; x=1755607839;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=YT51WUHAEKhfG+YDsBoeXwKjLVkqalaTaqntaecx0U4=;
        b=pq+o6ISJEgbBx19O/SgIXZkuqNWynNpYeszSHto18hz5clw3zPFu7i7BiE4MqJLcKw
         8kmq1vjPWE8KsjQPSYL3peMRNBZxrdkgUS5eczYYiJRyWPlmad0Fe0nKKL+GUP/DA3dH
         tYyOvhkbJnShEb0c6Nx+I7Bhy2b+8TsZ1Kk/+a5HnPLupshLsL7kxb7/JymjDEaWPaQL
         CgAl/IOqcqA1X8Gc0YrG1ZEHBNIAZ/pEgNbatpnc/02qtdKOBxkqQKMDoBCN26Cg4ADw
         O5vAbolwSDChlHbZU1lNQHDY0sm4ubw2CAQ8b32jgPRyZOAIKpd/szJSjaa5W8Ydhsxf
         1DLA==
X-Forwarded-Encrypted: i=2; AJvYcCWIZkSr/xhVOcuHPTLH0/f4X8H34LHRWX+wXSRMppZpTD/KVnEWi2BxzdXRor+pzzjPb0UjUw==@lfdr.de
X-Gm-Message-State: AOJu0Yw5GV9irCQvoVCF1LKuaE2CacuFAI2/S9xgY46yGen96WjusELg
	gqCjRGEFpjH1zCtY+rconZN23v1HVDP7EL35NkUaGWQOAPYs/BnY8s5I
X-Google-Smtp-Source: AGHT+IGmofGTZx5xnMsy1j+LF66wN7lryJX+mG0uGIrOUOlGwD1Cee+pidHhRTPrCVdCAtCSENC4HQ==
X-Received: by 2002:a05:6902:703:b0:e90:6c6c:dc3a with SMTP id 3f1490d57ef6-e906c6cdf2fmr11479149276.34.1755003039244;
        Tue, 12 Aug 2025 05:50:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfWeSS89wmqlhmqOnSwpdZyoOCkRV54Y9yBnqBorQ7fPg==
Received: by 2002:a25:3d02:0:b0:e8d:fb9f:25f3 with SMTP id 3f1490d57ef6-e906465ea61ls2342306276.0.-pod-prod-09-us;
 Tue, 12 Aug 2025 05:50:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVIlNyv0GuiAxNqR0Y7qmgc22jY9yKabWUqtlQzXyveGyiTixcnnmjrbC6Z0x9ti5RYGYdP6k+XcCw=@googlegroups.com
X-Received: by 2002:a05:690c:9409:20b0:71c:7eb:3556 with SMTP id 00721157ae682-71c07eb44edmr100126267b3.15.1755003038264;
        Tue, 12 Aug 2025 05:50:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755003038; cv=none;
        d=google.com; s=arc-20240605;
        b=jQvvxCWNokyohLhOyhvbbR//Mf+LAXeb5lZI+MVyPvjw3GpVOuRixbP+6MnVbjZrmb
         9qUuvyV9WkeiMC8Rve1rJFS6hJ5f1r+YwFCFO1ox/phQJ5vuP0Dz2cPUewfCNZlghMbl
         gMu+D3hzORLtxRx4zEhh2gcBXmU6MtO4ryFkj2zl69gVKueylxHOolsfw45hbElo9iYW
         GOHH2vO50ew/ohhnEiv5RSVBhNQiKvgi8gYlFX+m/r2eMRxST7iO6orXf5VH8jCuHzr+
         cNN8jxO9fgde6N30e24ULFFEqfBfGGPF2YxWqS/EV+XTv5LD1ZWVONsQIzCuDzG+uCP+
         Jbnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=rmch9LxILHmDSZgEKLxWACfFjV5jmswbcfLkcrWwQo8=;
        fh=ZQiobZ3avnYd2dMV0+zhbhF+LZ041TMixvjrGLjsPak=;
        b=DcEKUUYjGf6ozeQIhV3d3tmYZKVhtiJgQPGWSfTwiFun+RbTX8KRyoyHTVa1x7+dXr
         aujDN+X0revXtBNCVAgumoh/lrM2Yqp0++AtJXWLmJg5jRzAHKvPv8vKIR7lQT5lvzV/
         WAZZm+SlqUIlHkkJe+RQGLMT89MD/YDXIxKbzs2LUel3wBNP0O3zgj3QE0g4LtbXws/6
         6SOIjU+J/i9D1paNXH9Zip7KUsIhF1GocrdC3yfKDvWK0ysyGL7NkBYsKQ+/EeDila7K
         58VKaMAR0nkt/tE9rbT6hBJiK2V/mLfMs89MnjSTrAr7EW3BzWFl4brE27H4FQxA1rGr
         Sc6A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=jPQXWaKl;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71b5a2dc4f6si12046507b3.0.2025.08.12.05.50.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 12 Aug 2025 05:50:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-57-v2GUSWdCNJ2cbTTT3izsjQ-1; Tue,
 12 Aug 2025 08:50:34 -0400
X-MC-Unique: v2GUSWdCNJ2cbTTT3izsjQ-1
X-Mimecast-MFC-AGG-ID: v2GUSWdCNJ2cbTTT3izsjQ_1755003030
Received: from mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.4])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 0D25E19560B5;
	Tue, 12 Aug 2025 12:50:30 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.156])
	by mx-prod-int-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id D92EC3001458;
	Tue, 12 Aug 2025 12:50:22 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	glider@google.com,
	andreyknvl@gmail.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v2 05/12] arch/arm64: don't initialize kasan if it's disabled
Date: Tue, 12 Aug 2025 20:49:34 +0800
Message-ID: <20250812124941.69508-6-bhe@redhat.com>
In-Reply-To: <20250812124941.69508-1-bhe@redhat.com>
References: <20250812124941.69508-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.4
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=jPQXWaKl;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

And also add code to enable kasan_flag_enabled, this is for later
usage.

And also need skip kasan_populate_early_vm_area_shadow() if kasan
is disabled.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/arm64/mm/kasan_init.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d541ce45daeb..0e4ffe3f5d0e 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -384,6 +384,9 @@ void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
 {
 	unsigned long shadow_start, shadow_end;
 
+	if (!kasan_enabled())
+		return;
+
 	if (!is_vmalloc_or_module_addr(start))
 		return;
 
@@ -397,6 +400,9 @@ void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
 
 void __init kasan_init(void)
 {
+	if (kasan_arg_disabled)
+		return;
+
 	kasan_init_shadow();
 	kasan_init_depth();
 #if defined(CONFIG_KASAN_GENERIC)
@@ -405,6 +411,7 @@ void __init kasan_init(void)
 	 * Software and Hardware Tag-Based modes still require
 	 * kasan_init_sw_tags() and kasan_init_hw_tags() correspondingly.
 	 */
+	static_branch_enable(&kasan_flag_enabled);
 	pr_info("KernelAddressSanitizer initialized (generic)\n");
 #endif
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250812124941.69508-6-bhe%40redhat.com.
