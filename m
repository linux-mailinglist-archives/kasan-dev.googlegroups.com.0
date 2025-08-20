Return-Path: <kasan-dev+bncBCKPFB7SXUERBBV6SXCQMGQEQ3OTBQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3d.google.com (mail-oa1-x3d.google.com [IPv6:2001:4860:4864:20::3d])
	by mail.lfdr.de (Postfix) with ESMTPS id D685EB2D39A
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Aug 2025 07:37:11 +0200 (CEST)
Received: by mail-oa1-x3d.google.com with SMTP id 586e51a60fabf-30cceb0a741sf10509160fac.2
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Aug 2025 22:37:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755668230; cv=pass;
        d=google.com; s=arc-20240605;
        b=BCU3hlK6q89v4N6qwkgzWGVi1E+m51Vk418svB99zVJzY7KNTpw4l32RFhOO+1swSZ
         QZ3zAkW+ymwIF2h4twQYINCA52sseCaiHaEcRgT9ECQ5tDeP1dBLYavcynCqy87zGRE7
         hcSbgtZ50DjyHfZAK4Zdx7J2YCtaXqrwrmW3EY0mL6MqEwJHQhuzbIAhlhnacvVuyisZ
         zOpNaAFY1wFE+/aOztVRq/1Xg7eglv3C4WZwW2wu67co2XbOius3cPlLPGorGC8hFD6p
         AFmmtxIltByWL3dWmzkDgfg7hgFpmA3xL8LAPWwNNN3IhCL01hGAdqNspuZOptscyCuJ
         zhZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=zVjedjDYMGNtKORzENSNI7NJGkHlr8Ql7pcCULwQR1I=;
        fh=K4jNNC710Aj/ZSCiqseYrmxvLqO9DzCK4CAsCj9lHrk=;
        b=ZyrNRLsFgEGeegxGvDehXOrIxN4+5dIDl8BzfCdJrbTCPxgXujxFA+OP01dTcvaRJZ
         fVmbAFtXn8JbB/uTxlPf7vYOOQ2uDQ9ePDraKMFBJV3P8d6LqAxvtqcPEgrSi+tiyylS
         aVVTj0S8JCUFJJrblQmKxZ/2Qg4Ki4QnCxnPsgbsbPAMr3aBP+4gz6JN72GUBevW2ZP+
         lNJF6vh4GzyT82eHHcJ2GaV0F6fuc8jNj5aRvMiOtpdV0csOr+tDK5VFjZgJysb5nyRe
         fYB/sJRXm4GbM2FY87ipW1aK2iJVl2zI9zs+uc7l3E6bkjMNaSpYTuIYnzEMjSmkmwOh
         gInQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Sm5nir1T;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755668230; x=1756273030; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=zVjedjDYMGNtKORzENSNI7NJGkHlr8Ql7pcCULwQR1I=;
        b=o+JM4XJIjHkO8DawVt7X1IJRaXfpfmmYpw5LuSKDsumkgZjKNr8uiXksdyESVZEDMe
         kwAjAPcbwH46rZjCi7Zs/yrvb1hQGkQBykWxHBn4rYrKj3o6DIOrEDXwy8ryPkKWU+ui
         sH9+5Kj8PeQJzdZ3EXP6xniMy4Se28IVwt0Q+0mj7OnF+CsiQlHDFcIxoLDOCKyJsrui
         JxjxfPhX8z8ROZVfQM1pWe5/KsgMEciFL/XIU9CANuHd8jD0Gs77iPRB2zsU984PCFGL
         5izt8FI0Q7um8C94uVSV9h38DMfSSAppeuvWWRxjqUZ7FtWMLwKehvvtS3dwMr5uyXJG
         x+Bw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755668230; x=1756273030;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=zVjedjDYMGNtKORzENSNI7NJGkHlr8Ql7pcCULwQR1I=;
        b=b/h6RqSTGW+ashKF27NBWTn+KD5WZ6TpROCp75DgUh88vc8AfOP+1wLvkgO9x8mzTJ
         HIsFritKdE1pFWR5xJ6v4mRfLvJb04x+coy87kvVZJ4JlAAHYRl7iycmNSXfEDWDrRx0
         7g24P5uvWPildW9TBgG82ORPTAJAEfuHQAaWddrY36akdSJrjmdQwEgxWTLwRNn/JBB8
         4CkezAzzNylnkobrf0DoMzLdYSkg+hLLgFgtyodhUdlGAefFM5jemhgiU8ECWhm13KSo
         HWLdYYYrhzs1V0uzMcPAqiAt1GcDH17cnZZVzz1bCiJvH0lq3DOGoDJYzomCCVuJ7IKc
         N99Q==
X-Forwarded-Encrypted: i=2; AJvYcCWrr2t/E6Qe3r8YkZ1C6DC97XfsjKOqet9iYZHUPQFrZpR2jXcqlugf8QmNDgc7wyd9ZeYWMg==@lfdr.de
X-Gm-Message-State: AOJu0YycoPTrviK4iiuS6uQCT4tO/NIg8TvAfra9/75BslI0H2o60Cta
	j25/d4JIaJRJcmEBDkbE7812iEn7iKklsjwdn1HbiWbOiKdN6+541iua
X-Google-Smtp-Source: AGHT+IH5k8bNMPZz95zrKFtQxMEqKo9ZNMcxFW1Ab3RKORBsKSYTXKmUBmYfqBpxof5L3oU+OM2e6g==
X-Received: by 2002:a05:6871:5a11:b0:307:bf08:86f0 with SMTP id 586e51a60fabf-311228320f1mr1025227fac.9.1755668230380;
        Tue, 19 Aug 2025 22:37:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeOe78ULHwT44hVFB3pT/v70nFZMe+FyRk0jK6YUKVRXQ==
Received: by 2002:a05:6870:8288:b0:30b:85bc:4baf with SMTP id
 586e51a60fabf-30cce766a14ls3151859fac.0.-pod-prod-07-us; Tue, 19 Aug 2025
 22:37:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUv6av7L1kThK+DAE4Bb4PJm6y98rGwt4nrF+8ONxd5BMYvYMWEIQdPPYSR9Hb1py6o534ayPPzcx8=@googlegroups.com
X-Received: by 2002:a05:6808:1485:b0:435:744c:9297 with SMTP id 5614622812f47-43772016ce5mr808492b6e.16.1755668229590;
        Tue, 19 Aug 2025 22:37:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755668229; cv=none;
        d=google.com; s=arc-20240605;
        b=duJLhQrEHxBM3unMm9s5E60figtPAE1GjsZLsRyNR7RK9k3GnAw8aPxxI7JATSCZv1
         J5jW0zRebHu2LiPzrWyRWj5v+mXRai1Zytxy6g2z/OfAlcOlAZX03bIhWt0pwqUjdWnF
         yBS4WwYhHQgiwkVsRY94aB/Nr3MkeJWmxXw0KsuDc/5sSwjtJ+UF9xy2Y+IKXRnes3ss
         a/rBCoS0GqpY+Wvr9+JuAuAeQcVB0D2NzJSZsEGNuZakPWpW2V42YbuEEk30hokWP2a1
         hjaJwdzTJuu5TpnKJweTfQ7xftE5Tdj1oB5qKkdbkxAUrTQLhSoGNOgeN5wp5BNFAmno
         dSOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=n2YWNQ1R3q2yuyqJw9ejU5xCE0/f1sakMXwMmNRUMe4=;
        fh=yx2TOEA8OAv6JgprDRqBo1i40dkdP17DWUnpFH3PSuc=;
        b=iQ5ynyXKBU1aPJhJnugDGRmn0TC5+6l1zoEMfryf3VncXCgP0KLwgyHnh9/2g9Y58S
         jDkpkyv4AZWYUMH6D2JoVy+2hBIjYnW0EdHyRhCsuSXG+5LfzbOLk0iXW79NREjfOFCJ
         eXZjcwOLO08YFi0evBle2ThUBjQgfE6DDNJqfu+aRYPc2ZBCgpPBKatndMod71vRl0FC
         +v8YJ5zaYhQqzQifYVss1a5BsUz7s3x3FwGvSdwlimsXC7w7twtGRwQ48JjAstm2PS7B
         PG8tLvNoXPn6MJJzUowgfBAyKCY94ybK9P0oka7Vp1pKJ0Ohr6jxA/l3uT217gU755MK
         hCmA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Sm5nir1T;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-435ed1496d7si584570b6e.2.2025.08.19.22.37.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Aug 2025 22:37:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-590-SD3MvwL6PoWLgsvGYJ6o_w-1; Wed,
 20 Aug 2025 01:37:05 -0400
X-MC-Unique: SD3MvwL6PoWLgsvGYJ6o_w-1
X-Mimecast-MFC-AGG-ID: SD3MvwL6PoWLgsvGYJ6o_w_1755668223
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 54F0C1956079;
	Wed, 20 Aug 2025 05:37:03 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.99])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 2ED4819560B0;
	Wed, 20 Aug 2025 05:36:54 +0000 (UTC)
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
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v3 12/12] mm/kasan: make kasan=on|off take effect for all three modes
Date: Wed, 20 Aug 2025 13:34:59 +0800
Message-ID: <20250820053459.164825-13-bhe@redhat.com>
In-Reply-To: <20250820053459.164825-1-bhe@redhat.com>
References: <20250820053459.164825-1-bhe@redhat.com>
MIME-Version: 1.0
Content-type: text/plain; charset="UTF-8"
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Sm5nir1T;
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

Now everything is ready, set kasan=off can disable kasan for all
three modes.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 include/linux/kasan-enabled.h | 18 ++++++++----------
 1 file changed, 8 insertions(+), 10 deletions(-)

diff --git a/include/linux/kasan-enabled.h b/include/linux/kasan-enabled.h
index 32f2d19f599f..21b6233f829c 100644
--- a/include/linux/kasan-enabled.h
+++ b/include/linux/kasan-enabled.h
@@ -4,34 +4,32 @@
 
 #include <linux/static_key.h>
 
+#ifdef CONFIG_KASAN
 extern bool kasan_arg_disabled;
 
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
 
-#ifdef CONFIG_KASAN_HW_TAGS
-
 static __always_inline bool kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
+#else /* CONFIG_KASAN */
+static inline bool kasan_enabled(void)
+{
+	return false;
+}
+#endif
 
+#ifdef CONFIG_KASAN_HW_TAGS
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return kasan_enabled();
 }
-
 #else /* CONFIG_KASAN_HW_TAGS */
-
-static inline bool kasan_enabled(void)
-{
-	return IS_ENABLED(CONFIG_KASAN);
-}
-
 static inline bool kasan_hw_tags_enabled(void)
 {
 	return false;
 }
-
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #endif /* LINUX_KASAN_ENABLED_H */
-- 
2.41.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250820053459.164825-13-bhe%40redhat.com.
