Return-Path: <kasan-dev+bncBCKPFB7SXUERBGHA7LGAMGQE55LTDDA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GC1wJxuwnmlxWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBGHA7LGAMGQE55LTDDA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:17:31 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 245C719412B
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:17:31 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-358e5e33ddcsf1467613a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:17:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007449; cv=pass;
        d=google.com; s=arc-20240605;
        b=KRw99p/MPcA2xLLzzyDTJq4bPF4gtwKXgSeW5YIMJFXr3opwwylsjxQ8GqU0K9AFdR
         lr7pgLo1DwO7o6T6zLFwNW0cZXTjqv1SeNLFxhnxhRz4BAlU0lokfSGAGXccwQ5LOGkX
         n+svCUkhz32z8zpwfzW3HhCFX6m5URaNECRv9d2WzSrtNWfWiJbk1hVcR06H4zp5bqQ2
         Iri3MLGGx3Zispul9L2ViceZfSI9a94tYNxf8oCIbQWLUHTdTE3ziRccMwtLJXPF8AOP
         uZ4iIxlSiUlBFL1gJl8VO2GP0qQUv69rpDhLKZwGv4DEeqUSm9dxJyDZvKtcEoTsccE2
         q7DA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=RzpbN852e+kbJWLNLOckjSfBHf/wFBD52lhltqMXWLg=;
        fh=iZiCPgfz1RCf70pX1t6TvffuuuZ5RMYUU0b2eSOoQ50=;
        b=YZLTRkUD3dfYp3hQrEqEa2mbiGjKCvEFf8dqE2KGNVug+9ZY6gKaLtZ6+/P0v+u/yv
         5yT18R/8eueXqJFuLyhfN7rVUhYibTDBkzmyg3szHDIcZIvlecKTybOXpmlZXRq7Yxdx
         Vgj7MASlfkupk+ZVGN7+el+ML0Km3ZEbl2g5MLjVcJcck8aSjtjtpEjkLbdN7rqInAKS
         VsbcSV1ae7BwWPh9lkSWQquayV6GSuGXe9Q+JYLJq1/jTiT56Fvf6cPg4WQD3Us4cdVT
         FWEfJGo7/BTmiMmt6VG61pCf8UarzU5K0sb9AsQHiNO7LIqUc0DqcwgecyItDmTZzVZ1
         tDxw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Sdltovha;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007449; x=1772612249; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=RzpbN852e+kbJWLNLOckjSfBHf/wFBD52lhltqMXWLg=;
        b=VWDtI3Gg6wUlK1RzsuMisAX+cPBpFIvDcQrruYdPqfMBsTMZvY53Bm0jNU0MepZt+a
         asp3GoqFtpa7Q0y5VHRiaCEx6Bg1mQIoitG3Hbe5K/36hCnCiw1h/8wa/YMGBxHthnt2
         jO6ycfVrUIjXcM/0YadMHMoA4epiLR4xzym4H/nKjP+xgEhj242YDzvfbH1axsXdn2H8
         aD+zJ9He32hITwDt7KmMqZB50lJHtE8zTkQ6QnmtziKv9XJypkIdhocUVnuMQoZjD+gU
         vE1USKBMwvKHHW4C9kAJQwq4WHxTBmBMW5IOk/S6qDVljpgtCI9g8z7g1NMDgwKHFsbI
         9Yhw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007449; x=1772612249;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RzpbN852e+kbJWLNLOckjSfBHf/wFBD52lhltqMXWLg=;
        b=sc2dY04VQrDB1kx+LOl1K1PbT+LYpOz0hASmNRMx0fsGWiED/eiCDLw8xlRdtdpkKF
         +w08di3s+YoRnPCilqBUDpeQQpCTAc47syQOES40s/BAOTPTlA5MKp4x5A6OChz+xvaf
         novttqpKK+o2PIcCGy+om+dSBEkQ3WaBRvoWsdo3HEskz/5xE8oou68Sq7fjjHl1BFL7
         9rd2sxsFzmrIUPzWEvd0R57WwfPXdngWZfq+IlAldF9fzslU0tugGMwWLNgJj7QdaYG+
         hgQ9QAJjfLLM0T8FNjx7YWMkWirXYwHQsug1gWAee14d1nKie4HAMg0k9YAnB6o+7VSZ
         u8DQ==
X-Forwarded-Encrypted: i=2; AJvYcCV5RjItCrZNqDpcY4P+wvU8bIE8gBJID2jTkAOw13eTQTr4zINTaSHm5ItlCZai/Z6BBRwOqg==@lfdr.de
X-Gm-Message-State: AOJu0YxVZ0iNlIJLOWHR2MXUmk3JM+oDGHpZ7O0+n72bvgroRVuzGZGu
	D0ppBoCIxGtVb23tjQoRXoB17SJv/bNG91FTjQ0XlnaV/XS9Rwn9qiF2
X-Received: by 2002:a17:90b:5146:b0:32e:a8b7:e9c with SMTP id 98e67ed59e1d1-358ae8c84ebmr11323376a91.29.1772007449396;
        Wed, 25 Feb 2026 00:17:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Ho0/UEC31w5kB2PZeLiQqD5YYbokkFst7ZNCxucW4tLA=="
Received: by 2002:a17:90a:38e5:b0:343:ca22:84f6 with SMTP id
 98e67ed59e1d1-3590f1fc9a5ls348607a91.0.-pod-prod-07-us; Wed, 25 Feb 2026
 00:17:27 -0800 (PST)
X-Received: by 2002:a17:90a:e706:b0:356:83b2:539b with SMTP id 98e67ed59e1d1-358ae8e5e45mr13444662a91.32.1772007447062;
        Wed, 25 Feb 2026 00:17:27 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007447; cv=none;
        d=google.com; s=arc-20240605;
        b=XuYJju+nCDE7xyuHEK8o8ITBZmJSSg2GiGvn6KRIj4/Ukvn2zpoAMUT3kwIOAS7R4N
         x4pfQu3/RUCCUmp84b0+Gswf1UzaghiJjixaJTDaTbpyCdNkk6A7TYHovKITIV1gJZFO
         qBY+WwaLPk2vpuktqiFqggNcFlOksvfkv/roWxnjLB5dmMtyJdqYxOMieM/BHsV71Hx0
         wapa8pWfrBoJu+oaBvILyk/WCxrhlEB68q/WdatH1637Sx+hYKEczX4SKeImRKr8caPH
         tupSdg1anpnk2fYYkQtxuMD3mqhaYYNxtrWLv/lY3GVuJj/MFyoc4QiLNBRacixoii/A
         0zVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=oV6MOc6IZ/eQSfEt7lDYf3QV1I2fYi7uzloZcjfdDk8=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=HcpwZjGVhhd3bQO5kcyX9Y6feYoIQfb4xWzH3Gu5pBCgPCv39r1FNILgT6F4c832TN
         SOXkS42ayNmXW8XbaukQUZ7LHp628mesHgJL44T3pLDuitxVBYbO6F2O2x0MoY9oJLh+
         quk5uwuGGnM9K1VcPFkBdaX8CO15trRGaAgztGSuwC7Upv1b/IbBPyN0W/2s60q3ES7n
         IYLo56a6ou8THP38TQNFJ9Xb7CrUlCeV2Jci42fcofrlwGm9OnNT76Sl2/xnTlgNK+mP
         WABeRYM1X63/grstBFIIBpXiAPTme/iJb38gcgtnJ2uMiiBAnsYR9Xq//LuvtC9OoTvh
         awKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Sdltovha;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3591309f3desi18252a91.0.2026.02.25.00.17.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:17:27 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-477-d1eK6WOzOV6_MuYcbjoUdg-1; Wed,
 25 Feb 2026 03:17:22 -0500
X-MC-Unique: d1eK6WOzOV6_MuYcbjoUdg-1
X-Mimecast-MFC-AGG-ID: d1eK6WOzOV6_MuYcbjoUdg_1772007439
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 33B381955E8C;
	Wed, 25 Feb 2026 08:17:16 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 657C01800465;
	Wed, 25 Feb 2026 08:17:04 +0000 (UTC)
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Cc: linux-mm@kvack.org,
	andreyknvl@gmail.com,
	ryabinin.a.a@gmail.com,
	glider@google.com,
	dvyukov@google.com,
	linux-kernel@vger.kernel.org,
	linux-um@lists.infradead.org,
	linux-arm-kernel@lists.infradead.org,
	loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org,
	linux-riscv@lists.infradead.org,
	x86@kernel.org,
	chris@zankel.net,
	jcmvbkbc@gmail.com,
	linux-s390@vger.kernel.org,
	hca@linux.ibm.com,
	Baoquan He <bhe@redhat.com>
Subject: [PATCH v5 15/15] mm/kasan: clean up unneeded ARCH_DEFER_KASAN and kasan_arch_is_ready
Date: Wed, 25 Feb 2026 16:14:12 +0800
Message-ID: <20260225081412.76502-16-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: AC0BDh7XYWSK4u3fNB0dVrxSRdAB_SsIs610OBXJXxw_1772007439
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Sdltovha;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBGHA7LGAMGQE55LTDDA];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.986];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail-pj1-x103b.google.com:helo,mail-pj1-x103b.google.com:rdns]
X-Rspamd-Queue-Id: 245C719412B
X-Rspamd-Action: no action

Since commit 1e338f4d99e6 ("kasan: introduce ARCH_DEFER_KASAN and unify
static key across modes"), kasan_arch_is_ready() has been dead code.
And up to now, ARCH_DEFER_KASAN is useless too because of code change
for 'kasan=on|off'.

Here clean them up.

Signed-off-by: Baoquan He <bhe@redhat.com>
---
 arch/loongarch/Kconfig |  1 -
 arch/powerpc/Kconfig   |  1 -
 arch/um/Kconfig        |  1 -
 lib/Kconfig.kasan      | 12 ------------
 mm/kasan/kasan.h       |  6 ------
 5 files changed, 21 deletions(-)

diff --git a/arch/loongarch/Kconfig b/arch/loongarch/Kconfig
index d211c6572b0a..4b7802d02911 100644
--- a/arch/loongarch/Kconfig
+++ b/arch/loongarch/Kconfig
@@ -9,7 +9,6 @@ config LOONGARCH
 	select ACPI_PPTT if ACPI
 	select ACPI_SYSTEM_POWER_STATES_SUPPORT	if ACPI
 	select ARCH_BINFMT_ELF_STATE
-	select ARCH_NEEDS_DEFER_KASAN
 	select ARCH_DISABLE_KASAN_INLINE
 	select ARCH_ENABLE_MEMORY_HOTPLUG
 	select ARCH_ENABLE_MEMORY_HOTREMOVE
diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index ad7a2fe63a2a..b51fbc25bdc9 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -122,7 +122,6 @@ config PPC
 	# Please keep this list sorted alphabetically.
 	#
 	select ARCH_32BIT_OFF_T if PPC32
-	select ARCH_NEEDS_DEFER_KASAN		if PPC_RADIX_MMU
 	select ARCH_DISABLE_KASAN_INLINE	if PPC_RADIX_MMU
 	select ARCH_DMA_DEFAULT_COHERENT	if !NOT_COHERENT_CACHE
 	select ARCH_ENABLE_MEMORY_HOTPLUG
diff --git a/arch/um/Kconfig b/arch/um/Kconfig
index 098cda44db22..fd0bedd2c696 100644
--- a/arch/um/Kconfig
+++ b/arch/um/Kconfig
@@ -6,7 +6,6 @@ config UML
 	bool
 	default y
 	select ARCH_DISABLE_KASAN_INLINE if STATIC_LINK
-	select ARCH_NEEDS_DEFER_KASAN if STATIC_LINK
 	select ARCH_WANTS_DYNAMIC_TASK_STRUCT
 	select ARCH_HAS_CACHE_LINE_SIZE
 	select ARCH_HAS_CPU_FINALIZE_INIT
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index a4bb610a7a6f..f82889a830fa 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -19,18 +19,6 @@ config ARCH_DISABLE_KASAN_INLINE
 	  Disables both inline and stack instrumentation. Selected by
 	  architectures that do not support these instrumentation types.
 
-config ARCH_NEEDS_DEFER_KASAN
-	bool
-
-config ARCH_DEFER_KASAN
-	def_bool y
-	depends on KASAN && ARCH_NEEDS_DEFER_KASAN
-	help
-	  Architectures should select this if they need to defer KASAN
-	  initialization until shadow memory is properly set up. This
-	  enables runtime control via static keys. Otherwise, KASAN uses
-	  compile-time constants for better performance.
-
 config CC_HAS_KASAN_GENERIC
 	def_bool $(cc-option, -fsanitize=kernel-address)
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index fc9169a54766..f08f7f75c285 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -552,12 +552,6 @@ static inline void kasan_poison_last_granule(const void *address, size_t size) {
 
 #endif /* CONFIG_KASAN_GENERIC */
 
-#ifndef kasan_arch_is_ready
-static inline bool kasan_arch_is_ready(void)	{ return true; }
-#elif !defined(CONFIG_KASAN_GENERIC) || !defined(CONFIG_KASAN_OUTLINE)
-#error kasan_arch_is_ready only works in KASAN generic outline mode!
-#endif
-
 #if IS_ENABLED(CONFIG_KASAN_KUNIT_TEST)
 
 void kasan_kunit_test_suite_start(void);
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-16-bhe%40redhat.com.
