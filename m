Return-Path: <kasan-dev+bncBCKPFB7SXUERBO55SXCQMGQENMAPGFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D4990B2D38A
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:35:56 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-30ccea6baa0sf5243600fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:35:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668155; cv=pass;
        d=google.com; s=arc-20240605;
        b=du72zc1b/8xC6qrwEPcSd4I+Nd2moIKyawZgTRmclQFpTbiEPBNMxEpdD0nVvGD8dQ
         s7LdJ8NmjkPuTEDp7m3V9+xkOJNPOwBJJ0xKSXKUHqB0MtbJ9T9mI2kq02ENeEKz9Pl9
         CGcYjOEgh81fZ0zEaEHkDHPFaODRhmPEi1TEqg80F5hjJcLZ77QCB1CHJeCpsFC2uVym
         ohsbCW1Cv1H8DMJ4I576gNqlHyGrZnMRZ8XoJWPFbZDKXW7kyJkvi4TwOhB0lDcpE2/A
         yPUlHAC+GK6YRddqyDr31jjwYHQDuoegL2Llic39GBgrjVnilvhwSTk9VTvSiAo4+WD1
         btCA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=WPNB1qKtq9pnwZamAogk7+/z7Ir9QgGT8OV30PM+UiY=;
        fh=J8jA2byw5MQRnVkG4eYzjHMb/P/tFHcuu9BRYvSLD94=;
        b=hXNjdX+F1HxMcQt8egvsXjOJIsbpONsf+DWnQY3jKo2N2SwHAfLm21qR6hKtjYJEYp
         CB36mbwQu3a/SQQVVrxF/JjfoZmeHMWTBeDtRwIAa1DZgy1lbG4j+/rIjBqdqCOlY/C5
         OkdjzpjJkplyOj/cZRJQfE7UfBMrLSi5U4FDTCt1DbGqS6iKPLuqKkULPku3ABaNIKFw
         JHcV7AEvigijFsRpZ+dgrKKrQS9e3TaH3mkopfH12Y9ZfPxVECeG0vDkkSgwO+WhUHxx
         HfgniZ9M0oPI6V+l4SNT/Y4VUXm7a1/a3RI6bJRRPKYQtz1Sl695PVOr96FoAeM2tL08
         VKnA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZyGkWVeF;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668155; x=1756272955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WPNB1qKtq9pnwZamAogk7+/z7Ir9QgGT8OV30PM+UiY=;
        b=Ap4eirf2JNJpcKPKGGHZ5JrFwJYGJaTx72mXeu7U0NYNy3q0MdKF6oB5eCOgwvB9ay
         XzOoTcx4+9LhGWcne1cL3n2VptoYBcz3oIqGoq4haA8WVlgbBEv+LFnnwETPhAqY5q9d
         ulOcPV5HPsMmIOutOZ5WKjVzBDuJb+tL6mjr4EcYee6Oz4ntu8C57jiYWbCGWhkmqUbj
         CZl6pmKVUWMOg7f/pRKWFqJnNNrJ+Ez9/8bB/Cr5i07H5HQGvSMiPv0XAovnPnxHpGjL
         6ZhZr/fBPwKupUiCgGtcYU9KGaG01kbau5GKLelNfEltJ3KJpI/BCEOr1ce2DdcAwYa8
         acWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668155; x=1756272955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WPNB1qKtq9pnwZamAogk7+/z7Ir9QgGT8OV30PM+UiY=;
        b=br8dLGb6pbJyOWAgaeEiCdTsv4X7xbBmfif35xeQclbIRqihaG7s4bAanp3xr7MXb6
         C1iu2Px7ll9ZIKQqDDVRmCMiRBRUwdCOUloehQyo8h+rREdn7jz1Fe3wpwTkLKS5yoPX
         lRsGop4+ZkQNfbgo1+REHBBZ59cPrEhnQEOxD6PRfoZg01R8C2iFPRYaFnSeOzO3lCnY
         zvDHhUbBHr//v+bDRgxmEVHHX8AJ06cw3E24aFmN2wIASfuxHNF+Oe3pc6eJHGMTxBCs
         hAQwDuBsuv43Iu412mwpZ/DUKDd85Nh+M5adXV2s3WbEhOWkecA/mYTFwMpmIFHqo+c/
         jC2g==
X-Forwarded-Encrypted: i=2; AJvYcCVmhXl0b5NyYT4xbGk34DYvmxaQKT/QS7UTQH1PheCYPcSKeXAedzCNb1ezSeXlUsZIm+o/1g==@lfdr.de
X-Gm-Message-State: AOJu0Yxa2gkELSsS7nyHYKNLQSLCSVmDvbo5sn0JhscjO0x9leRbVsWT
	zPpc2nPiXxWkMAIQkZ6g+3+5kMCymqoA5VT1iQp+hr146+l9Dk/xiDS0
X-Google-Smtp-Source: AGHT+IGj+GnSkAqo9XPInflpA//CQ7bp15FiHteCphAaJmyQPnbQQYhrKApwHJuzo0zC/YRyO43cuw==
X-Received: by 2002:a05:6820:400c:b0:61d:a30b:7d5b with SMTP id 006d021491bc7-61da30b7edfmr24393eaf.4.1755668155484;
        Tue, 19 Aug 2025 22:35:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcCNKVA0fNH1r2NWeiBxIg2oqc8yFuNpznZ+zGpFX++gg==
Received: by 2002:a05:6820:7614:b0:61b:ef85:89c0 with SMTP id
 006d021491bc7-61bef85a51fls927002eaf.0.-pod-prod-02-us; Tue, 19 Aug 2025
 22:35:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVMtwGzwGpkm+16cAXFyyl6KUHrUlBw8xmdc8+flxlkUS9p4eUkJ+u3LnzHHm3eQHrZUHLTIaUcNKU=@googlegroups.com
X-Received: by 2002:a05:6830:3698:b0:73e:94d4:ec6 with SMTP id 46e09a7af769-744ebc5070fmr1115565a34.28.1755668154524;
        Tue, 19 Aug 2025 22:35:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668154; cv=none;
        d=google.com; s=arc-20240605;
        b=FrwDxqhSLrbBsYrDbQPRn0NwC0nKc0V28yj0KzVFAb53aRPT5SFvuGyP5e8MaMo1uL
         fgjnmYOHpsgIZnOSTkRnR6GndHS/CEymDlez9vy12M0SPiaB5fugFMSVrgN1pCBcoJhd
         9v9NkQcgz9xjwIGVQ6VkyTEAlK2LA/TCZlyc/PZ7QGLcco0B4luZS+/CQVDDjNLFCbJA
         yvHe5nc0A3aETmKhE2ElZRJqXP/HMlkTIbwpo+Ng/opGMTiGA/DR+1HBGoC4qvNiRcMF
         og49/vGQtURXnVpC4CKXjTTLFTHP3UNgtQiPj9++YeWEhbLMbpa8mW4t2BfsLOu1+Bq/
         /Lgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1F98A6khDpxH5CCRtSbMqyknw7kFB7aw/3wgsldUGho=;
        fh=NXbV5ohCfOyHdEWSL7FOtNKIczhwSC3wS44hia1kWhY=;
        b=AHgUCdCGmj6s1fyG41ITZvUQPLpl12qhgendBBNNdGPe/TKELDBb5u8sNxtNzIHO+w
         6Q0BDsx8ra6R6IqtgPLU3hj1UFZuz6p0auxD9zAhv+nqjpIi51zqupGlGAE1wAa0wJTV
         KmHU8UFgXhTJ31wR/Ic6MoVVfW0l3xSE0ceOgah5idG559T9SghSoqxLl2LegiTOwW3I
         LAVZrIv+Q0/lsiD9SlTARGeotoAFCQYK1gw1WR0Pt2W16Zh5+yQT2yntxuaRPgIyXAeR
         NMpPjOMbOGPJjUJaqHsrsYmozvea2FoyYx6Shh8ALP9lfvfgTuqZOt47o5DUp7DdBb7y
         jQVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=ZyGkWVeF;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74397c87331si94158a34.1.2025.08.19.22.35.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:35:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-684-xEr3pfhWP_q7Ci4sKv6iNA-1; Wed,
 20 Aug 2025 01:35:51 -0400
X-MC-Unique: xEr3pfhWP_q7Ci4sKv6iNA-1
X-Mimecast-MFC-AGG-ID: xEr3pfhWP_q7Ci4sKv6iNA_1755668149
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id AFD7918004A7;
	Wed, 20 Aug 2025 05:35:48 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 178F519560B0;
	Wed, 20 Aug 2025 05:35:39 +0000 (UTC)
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
	sj@kernel.org,
	lorenzo.stoakes@oracle.com,
	elver@google.com,
	snovitoll@gmail.com,
	christophe.leroy@csgroup.eu,
	Baoquan He <bhe@redhat.com>,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v3 04/12] arch/arm: don't initialize kasan if it's disabled
Date: Wed, 20 Aug 2025 13:34:51 +0800
Message-ID: <20250820053459.164825-5-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=ZyGkWVeF;
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

And also add code to enable kasan_flag_enabled, this is for later
usage.

Here call jump_label_init() early in setup_arch() so that later
kasan_init() can enable static key kasan_flag_enabled. Put
jump_label_init() beofre parse_early_param() as other architectures
do.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-arm-kernel@lists.infradead.org
---
 arch/arm/kernel/setup.c  | 6 ++++++
 arch/arm/mm/kasan_init.c | 6 ++++++
 2 files changed, 12 insertions(+)

diff --git a/arch/arm/kernel/setup.c b/arch/arm/kernel/setup.c
index 0bfd66c7ada0..453a47a4c715 100644
--- a/arch/arm/kernel/setup.c
+++ b/arch/arm/kernel/setup.c
@@ -1135,6 +1135,12 @@ void __init setup_arch(char **cmdline_p)
 	early_fixmap_init();
 	early_ioremap_init();
 
+	/*
+	 * Initialise the static keys early as they may be enabled by the
+	 * kasan_init() or early parameters.
+	 */
+	jump_label_init();
+
 	parse_early_param();
 
 #ifdef CONFIG_MMU
diff --git a/arch/arm/mm/kasan_init.c b/arch/arm/mm/kasan_init.c
index 111d4f703136..c764e1b9c9c5 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -212,6 +212,8 @@ void __init kasan_init(void)
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * We are going to perform proper setup of shadow memory.
 	 *
@@ -300,6 +302,10 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	pr_info("Kernel address sanitizer initialized\n");
 	init_task.kasan_depth = 0;
 }
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-5-bhe%40redhat.com.
