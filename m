Return-Path: <kasan-dev+bncBCKPFB7SXUERB4VQUTEQMGQECIALMXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DDB76C90C5D
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Nov 2025 04:35:16 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-7b90740249dsf2045028b3a.0
        for <lists+kasan-dev@lfdr.de>; Thu, 27 Nov 2025 19:35:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764300915; cv=pass;
        d=google.com; s=arc-20240605;
        b=aIbJErV/w2JF5li68ByvljSdm7LS5EdRTVp5W+CGqXtRVRwVTqYBXrl/LY1MnmQENu
         YENwBtMI69Jk4ZPctueCwk7wI9Pt1p/q4z6n8COvAozxsiXP+ZziM4gaQl3kyG21IF8o
         27N1SXmrMxGTcP55RX50oIhMmGo5UQMua2RdfN0yQgK5rrfBRqecFNTJZwIXqRxBZVW+
         avQGoMq30I4cijskQux2cTS3kMbEDteT0aN4RubhDgwUGB5p7Xy2xfbPMPOmK2wjBmi4
         RAVe8EntVuMGgtee8Xs0GSAG7QP9okH0FKXoU+7FRTi2sHd0EaYy5ilXY31PV1la/7vu
         GHaQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=rymdP0BALflbX2sgrd6mGK4nreM5IAfTCMDbSwJTxj8=;
        fh=igL4cXp2j8MA7A8QpqckvOU7XTezG7S2veymFFtRMMU=;
        b=C/ZPy7aQ+mlh3Crg623ClT8xMBPofw6iXXzbBal7T+eKik3OyKcOGM7mkwCtX49UNi
         MQAcISI7sa50EWnIT5nekZx4WgYv9xRFWVwg2xjzQx7wlY72cTrqsUOUz8VKVT/F58G2
         aueylQiPnkQBIEQDwreApjY4cfh9BE+oigjNgNN8kShHw1ViOyJ/3RFqe4sX1/kUCDyU
         u3jLxvU9dDAQZ+Fv/8bwL0dkVP3chBpfE4MBEw4iP7hvQxu0w4bvrj+8r3Gk+kSXu0Uc
         HqePAIZ1chpRKjxQO/bMjvhV3S/ewTE143f3Ik79GKJqQwHW38Jh2nULmT3oHLjRGiJE
         YFoQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bAWg3Cq9;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764300915; x=1764905715; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=rymdP0BALflbX2sgrd6mGK4nreM5IAfTCMDbSwJTxj8=;
        b=tXn4c9t+tJbRX98M1ZwCRk3YUq+kTcXpB1+My2kerSHM7XYPqNtIN1a6ei90THeJHK
         1bpLGpOlZUT1oGo2y9QuNW0bG9J7EJkeA70B4vB2MiTHw5tl/fIeSftQtTlkI/mtpTwy
         MkPbWGTMNglxQt4IrsEJM5vFNR7VrWvcG+k1ebj11PSp57/XZfLw3otOmoXOU0nFnmL7
         dNXYfkOQsxGbCLxxDlTJxEptWJ55E39q3LweshaF/Pfw/wUt8ZOYKanGxSzZRoUGbhSy
         anXkRGjrkTEvEifn6xCTLoBxd73K2P4HAYXhN33+Uyb8v1NYR5nfQMPTCNHVO8L7IyQo
         uCgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764300915; x=1764905715;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=rymdP0BALflbX2sgrd6mGK4nreM5IAfTCMDbSwJTxj8=;
        b=MxXoQHGGkd8lBFdMCgQB+CVj67iQjV1hBFgvXbPh1Jy1YGjdiTsxGDsZaiNe55a9Al
         bg3niNevjFyjWWIqGHxFN76OVtRZlg4kbCKw47EmbVaV8la/pCFJZm1PyhPdTnALHk+r
         zUzJJdATVZswVpfxzw4kMrlBSik7FwdbmqsHHayq48RhpImzN/9TSInDfXxuTIl7y7wV
         Jsjj1HCTynmW9WS8diEkgcUe/tF2KhGugRQZHmfI6MV0vfda7HXFRaJUABDHQZmG6Cri
         qn9RkzqtB6t/0OqschxSHXkPnzuTJhCgVXQOmTTsvAC73zwiP1aecFip2jYD2q0+rSUj
         gn2Q==
X-Forwarded-Encrypted: i=2; AJvYcCVbVV6Alu3Wd9CLXBZv6WXJ9FOHPB9+TW5YXyOzbz2Xg9FRMNMspAIypp1tOG8Qp/JMHklFjg==@lfdr.de
X-Gm-Message-State: AOJu0YyVOmEJrWkka75O28bACJIov1k+qHPdXrp/hHzgCwllTTQQ9UMI
	lp7NwVN26QuOpeNmUg+Vi1cO63AzpPQ8iDFXsC90iTm8Cr/khze0fm3j
X-Google-Smtp-Source: AGHT+IF4GPeb7xOGwsIqjBmAbc/99QMdTE6nQ8K7789W4VKYOpYCQWxirtHUXkHt8vVVhizLgUVxpg==
X-Received: by 2002:a05:6a00:4b43:b0:7ab:63fe:d7d5 with SMTP id d2e1a72fcca58-7c58e113bb0mr25202639b3a.20.1764300915121;
        Thu, 27 Nov 2025 19:35:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Z/TM8TXcf37Uj10zgPeuBH4j+uEcn9YLpHYVI4yB6xcg=="
Received: by 2002:a62:ee18:0:b0:793:1b79:ee57 with SMTP id d2e1a72fcca58-7d065f43721ls1340384b3a.2.-pod-prod-01-us;
 Thu, 27 Nov 2025 19:35:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV3plHPyS5nijbUUxeVH8mw2mQJDEYwfzyNuE9Ouos65G2/yw/NBnGxohW3KyXTItSnX0blnInosa4=@googlegroups.com
X-Received: by 2002:a05:6a20:4306:b0:342:44f3:d1bc with SMTP id adf61e73a8af0-3614ed922b6mr30007415637.35.1764300913659;
        Thu, 27 Nov 2025 19:35:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764300913; cv=none;
        d=google.com; s=arc-20240605;
        b=g7MxYVfDK9gUW2vMj6vmQ3kv8P5wSRqyQLs73QwM5WbjZXqI2LtLlW27FaP3pVaMxm
         3pZSPT2wFTlbXVXGNTETu0ZOuQNBy1GI7X0Q4zLSIeiUiL49AFgPd10sKYhJaT7p/ppL
         KG1NKJhlhvVxXkx8vtt+Rz4BF1wk7WlHkV6sE1WiAcBg9uYAJ2pfNdbQNhv00CaLsQq4
         NqmRS1UiD/K3iRu1Mh9AmV6ormVOjai+KDmiq6wNBn/CPMRPUYvD59y4ejI1jIeVCpFn
         C1ycomfTtDe5kDEPx6LJD/9XRGsGfRacqxx9uqpcT5LAx1P6DfABZ36ztayPb8HCKyDz
         HK2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=IKXZUrmhKSnLBrasgIFsU0j1OV2RdKEZHqiMi8x1qZQ=;
        fh=aEQmsInlyk63tcRJ6ERxNRQHD2gDv2Sri9NMdFIY8HY=;
        b=UgV6TnmnMK/ZF0g8ZJd++Uca2kWO1E24JBhTncMfSQ931Zq5DY88iH5EIyng2x7q3c
         SElu/TsgL8ndawWJBbhFD9uNwAlF2UZSzlFrFYJ02sx2n1szw//uwmysVoDQPtZlXDhm
         wKEJx2gbDZCmuQ22pd0hYEqDuOzeZyHOLC8NoYi4gl/SxSmQNVzWkmWD9MLhfvkpelHL
         o0/34aTVzuBHCzLiuiXjuRZjbrYIVbwuvX1w7Sd2r7NQbCzui2jpUUdHorL2sHTJfHV3
         QB5y+TRNnueAH8anz2Tt19Ufl1wzSQ174QNyqSSDgU1kwzhmsajng2b6kFwM954KnzyH
         vODg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=bAWg3Cq9;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-be4fae68bacsi89460a12.1.2025.11.27.19.35.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 27 Nov 2025 19:35:13 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-286-_d3nj9KnOtCZzyg-FTOf-A-1; Thu,
 27 Nov 2025 22:35:10 -0500
X-MC-Unique: _d3nj9KnOtCZzyg-FTOf-A-1
X-Mimecast-MFC-AGG-ID: _d3nj9KnOtCZzyg-FTOf-A_1764300908
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5E284195608F;
	Fri, 28 Nov 2025 03:35:08 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.7])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 6219519560B6;
	Fri, 28 Nov 2025 03:35:00 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: linux-mm@kvack.org
Cc: ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	vincenzo.frascino@arm.com,
	akpm@linux-foundation.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	kexec@lists.infradead.org,
	elver@google.com,
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>,
	linux-um@lists.infradead.org
Subject: [PATCH v4 11/12] arch/um: don't initialize kasan if it's disabled
Date: Fri, 28 Nov 2025 11:33:19 +0800
Message-ID: <20251128033320.1349620-12-bhe@redhat.com>
In-Reply-To: <20251128033320.1349620-1-bhe@redhat.com>
References: <20251128033320.1349620-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=bAWg3Cq9;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
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

And also do the kasan_arg_disabled chekcing before kasan_flag_enabled
enabling to make sure kernel parameter kasan=on|off has been parsed.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-um@lists.infradead.org
---
 arch/um/kernel/mem.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 39c4a7e21c6f..08cd012a6bb8 100644
--- a/arch/um/kernel/mem.c
+++ b/arch/um/kernel/mem.c
@@ -62,8 +62,11 @@ static unsigned long brk_end;
 
 void __init arch_mm_preinit(void)
 {
+#ifdef CONFIG_KASAN
 	/* Safe to call after jump_label_init(). Enables KASAN. */
-	kasan_init_generic();
+	if (!kasan_arg_disabled)
+		kasan_init_generic();
+#endif
 
 	/* clear the zero-page */
 	memset(empty_zero_page, 0, PAGE_SIZE);
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251128033320.1349620-12-bhe%40redhat.com.
