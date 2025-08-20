Return-Path: <kasan-dev+bncBCKPFB7SXUERB655SXCQMGQEPWKYLAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id DFED3B2D396
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:37:00 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cce9bb2bbsf12330785fac.1
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:37:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668219; cv=pass;
        d=google.com; s=arc-20240605;
        b=EagIJtZucLz9xd779tLSDgXpp6nAhtLiBOLfq2AF9t1MZz/+nZ+Y3PyQ1wggsBV7FD
         0zcYZkX019bVyv7sqIkC0anc0UwIefcZBh+JBhqPz19JGJv7ASXc0Bac/zLErn4l8cBT
         QePbHoQQxhoNJBbQwdW60gINmwhFucAMVMnXO9HClOaYe9R2BdRT3Dk23AV1gpLIxLr5
         KFd5qa5juyhMY2n/7P3TCWsqB1jpBvRMDTwfhm74/8KCqfRBFltxWmT65k9JPk4vGvfH
         2zGcP53WBPDARZ+eghdGf6Rqx6zoCu/5K+/CyOoiLou07OUIdgJtXtLdedLlVYASULrw
         3UxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=VBwM6zmS3UozTQjU1BhTBGqcvc58hjWYXiM2l1LZqjQ=;
        fh=AN8XJh9aYrhoOkQ1VEnTxheQQTNrfudkRfNnHFmkZ2c=;
        b=fFXkqU2Hmx2O4LCSwFrWKYvNyV80iF1AnEa3LDDbyjUsw+LEs+Nb1eLgbN9mQiI02A
         Ku+bUtdLFvoIUS2SpEie5+k2Zig7Qr2F3Gqu8GKTmWVVZybheeXY3m5Suc2hYtvkeupL
         Ur/NF0C8pz/03Lb+63G2vRxTrTbXgx99Ak+Hp93F5LNR6m6YRWtncNLjyVogopRkkeD7
         1PQqfG3+Ubo/EAKLjP6R1UhfSPMcaHD+g2MEiMz2X6LrJZJWfF3I6Gwb/xUQ3D6MHFZW
         HwwvbxSQFLg7oOnpmpVvsz/wdpGmolioHoQgAZogGdNv5V/aZF/BNbM76hXval7Xe7U2
         vvKw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="fe1y/WEh";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668219; x=1756273019; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VBwM6zmS3UozTQjU1BhTBGqcvc58hjWYXiM2l1LZqjQ=;
        b=kB1mk716BQzpAbzHH6AI/QdGuFV32nTX8C1lIdNGOFLiMrF1yqOKxUf8HFdO9RLdQ2
         w1ik99UoFL0ybbW6kwYBPMmxz7AcyLgP1dJcHgu98dtEpKtXoBMxEUs3NxjRnl1ZzMPJ
         UAr7ZSzGRxPPpm9/wAqmbw6blw7cHSUBpHBGBYs8evqHx/rXHjGG0QMo4uIXv958Y4A6
         KvETM8enRNRaJyc51VLzp+O1PsZ/hg4+P4HTgE1XmNT9L2vOq89Y1j15eljgxmVECYCY
         BsgRsaiIRb4ReahmFSsppkZJ+OWGb/g46YXveEYstQk7PK0TfMVJJicCrTVq/P2piK2e
         g0ZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668219; x=1756273019;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VBwM6zmS3UozTQjU1BhTBGqcvc58hjWYXiM2l1LZqjQ=;
        b=SAXj45YR6eeWlkcbTKFqLoM7YtcMFRew/9OHsj+nX0ot3NWx3PI2Zwy/L+i/YfXcjt
         qDKl6er4RJDUzWnmgC3F5VPAJSrm9aGi7OlSojy6xYcoInqA+aSH5IhF8POdvV3QBzTi
         Kf0Mh1S8TmXLvt/4ypVIcCM+nXFygKKaS0I0l+hUbpStClCvr4Wiy/9kGids1X84Lhv4
         7K6nZnRZBPdEIGgqhXt+BaSv62Sox697sStmEKwEFG/v1GWk55DPPWrrD+spVkAR7dlJ
         kyHS7H7Qd3mumYsAuuQSQgpghMAbHRLuRzb2IjAOUpX9KYeR2pD1m+64CcsNlyum98OV
         WHug==
X-Forwarded-Encrypted: i=2; AJvYcCXP15gUPZ2w70hoalFGEj6cmZh0lLgU2LRj6M0gzgc1mHZWed+k2ARBjcoGpAWsDOSiHxjCxQ==@lfdr.de
X-Gm-Message-State: AOJu0YwjgBTNIi0aDAWBPy1yyJroIWV326d0JGGsGEWoCVtioTvkstnp
	YoyAA/X5sN8ooqxo/Mk98JKmjv5Lmlwwu5JsKZqymEpM2cDXrTiOEnjn
X-Google-Smtp-Source: AGHT+IGj+/Yl/ou3juMsdBCkLPQYgvC2LXOT5+vxwU0EikMLbK2OxzXCHqr65h0QzgZqeFsWB7iKxw==
X-Received: by 2002:a05:6870:d8c8:b0:2d4:e101:13ec with SMTP id 586e51a60fabf-311229edf1cmr916036fac.33.1755668219536;
        Tue, 19 Aug 2025 22:36:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdRtLjjluHGM/G5liTRaGYL6MKThAQgYF4CfIvd9Vncpw==
Received: by 2002:a05:6871:a198:b0:310:fb62:8fdb with SMTP id
 586e51a60fabf-310fb6295a5ls788640fac.0.-pod-prod-08-us; Tue, 19 Aug 2025
 22:36:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWUZvQzRn7SuhhuJJ71uBfgZjvNr7nANMrSxixFn9JvZRfJxTvPQeHaS+UpWmZy9iFMEFAidqYKf3Q=@googlegroups.com
X-Received: by 2002:a05:6871:7287:b0:30b:6fa2:6974 with SMTP id 586e51a60fabf-311227cff0fmr1044286fac.3.1755668218590;
        Tue, 19 Aug 2025 22:36:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668218; cv=none;
        d=google.com; s=arc-20240605;
        b=Ej09S/NO2qoy6VC+nQKrKSPs8vbaAvivSyeg/zcicVjAAGXV+qIVws99ABj2DtJ5EZ
         c60Sf3Gyy043B3XvMdPDt/+xoHpR4qw3qHpjLsU/MmDdQ2m6zwWmaHHQlaVJ8Ph9YRO+
         xyPYdwYj4ek591nQMORk3iJS/UEs3JBItM1FNvQzkcd/KPl0NWIldo2HtDA6ySZEnbdk
         bb1dgWFsEKtnfP6mzo7lUisZAYappmn4IQnLfQGc9IrltZpW8DTNrqXo/8hNkMW56Q7B
         Tc3soYcFVVvM2byc1y+rZ9Atn58nL7efmCX4p82GMGuRhn6xwJnMkTGwOFlCdoFiE45/
         iEdg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=VcfWxvd2gMUp9MiHd8sOWfFMV/Om7sFRA8QIIlclSZk=;
        fh=RuePE0XEqrJKKw0BZZ2S3iWqG8PrJ/tYSNkGyEhO+R4=;
        b=YALEIcUnmP49V/7NJWbSpUU0qXob5avr0buWw07Vdg8FFEAfQzCtyxGesQ6+LLQlHE
         whInztMzYN2WcdAICgK6Bv5IvVsGrYiu+p27UXFZtXUUnPf77vkMjhaH9gMmM+Layxlb
         AwlvDWNgCML/4A/4LZ/SpDiNKf88zkid3VdrsW2amcF+9N2CSt2yc3xICz72ii/P2W7N
         wOanLA9k5wJI/HYsZToi9JSu2HF0tEvBsfPNcQu4sgrOo03sXQ0TIe8weCeEAwJ5eRQR
         uKFAX19+ZvYKg9bLhAFoNvgBAEJYkmEVYbLeFcowi729Q7YAuW7/MjAduYim9A5nSHYs
         xwhQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b="fe1y/WEh";
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-74391f34356si582320a34.3.2025.08.19.22.36.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:36:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-608-kDHKpYH-PcCG6_xA3bDyRQ-1; Wed,
 20 Aug 2025 01:36:50 -0400
X-MC-Unique: kDHKpYH-PcCG6_xA3bDyRQ-1
X-Mimecast-MFC-AGG-ID: kDHKpYH-PcCG6_xA3bDyRQ_1755668205
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 26AEB1800346;
	Wed, 20 Aug 2025 05:36:45 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id B28D119560B0;
	Wed, 20 Aug 2025 05:36:34 +0000 (UTC)
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
	Chris Zankel <chris@zankel.net>,
	Max Filippov <jcmvbkbc@gmail.com>
Subject: [PATCH v3 10/12] arch/xtensa: don't initialize kasan if it's disabled
Date: Wed, 20 Aug 2025 13:34:57 +0800
Message-ID: <20250820053459.164825-11-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b="fe1y/WEh";
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
Cc: Chris Zankel <chris@zankel.net>
Cc: Max Filippov <jcmvbkbc@gmail.com>
---
 arch/xtensa/kernel/setup.c  | 1 +
 arch/xtensa/mm/kasan_init.c | 6 ++++++
 2 files changed, 7 insertions(+)

diff --git a/arch/xtensa/kernel/setup.c b/arch/xtensa/kernel/setup.c
index f72e280363be..aabeb23f41fa 100644
--- a/arch/xtensa/kernel/setup.c
+++ b/arch/xtensa/kernel/setup.c
@@ -352,6 +352,7 @@ void __init setup_arch(char **cmdline_p)
 	mem_reserve(__pa(_SecondaryResetVector_text_start),
 		    __pa(_SecondaryResetVector_text_end));
 #endif
+	jump_label_init();
 	parse_early_param();
 	bootmem_init();
 	kasan_init();
diff --git a/arch/xtensa/mm/kasan_init.c b/arch/xtensa/mm/kasan_init.c
index f39c4d83173a..4a7b77f47225 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -70,6 +70,9 @@ void __init kasan_init(void)
 {
 	int i;
 
+	if (kasan_arg_disabled)
+		return;
+
 	BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_START -
 		     (KASAN_START_VADDR >> KASAN_SHADOW_SCALE_SHIFT));
 	BUILD_BUG_ON(VMALLOC_START < KASAN_START_VADDR);
@@ -92,6 +95,9 @@ void __init kasan_init(void)
 	local_flush_tlb_all();
 	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
 
+	/* KASAN is now initialized, enable it. */
+	static_branch_enable(&kasan_flag_enabled);
+
 	/* At this point kasan is fully initialized. Enable error messages. */
 	current->kasan_depth = 0;
 	pr_info("KernelAddressSanitizer initialized\n");
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-11-bhe%40redhat.com.
