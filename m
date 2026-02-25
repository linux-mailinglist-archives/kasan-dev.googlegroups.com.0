Return-Path: <kasan-dev+bncBCKPFB7SXUERBPO77LGAMGQE3ZG7APQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +O5UMr+vnmlxWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBPO77LGAMGQE3ZG7APQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:59 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 6BCEF19403B
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:59 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-896fa0fcf27sf720773366d6.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:15:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007358; cv=pass;
        d=google.com; s=arc-20240605;
        b=QTjhHbbvyVdJ0v6RbpUAIo0oqgObOs3zyabftL1UNsK6lnNsnRJafomArRwzeS91B4
         Xveb1nqF5JHGg/mtlLJrHE4jVFlLFHslMPrMEOLjADabsE7HXkNZn3YeBIXxuwyNJUQ1
         ja2CooSoSadc24eH1jPLMhz5r/3h8y72eiGvaHMdb6h8dGgLM+h79MTUslv3ZXvkdtS9
         LYaxhUFckMqyszYMyglqY7te3ZpuS5A74RE+141J2Cy7r0oe9efHPByBULd33g0olY8o
         fxfA7zBPu+u8Bbx2/BKw9wwos6XUrbVgd0pbFQsPfS58C+W/vL+Hs5Xw7ln4wVO7U7oC
         jpuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=tdNj9+X/Gatp3jIZyUPLH891LIKdZG7OCc/DedERb0Q=;
        fh=3uwMwhTUuwMhLTP90EhFvzuB1InKI6Ha4tv5aD2mceI=;
        b=SFDFEgxE3jYXyiBWS7+ed/UP1X6RXlAm025XahIbgZYLKkf11FV51QAOsj7qH4PYu/
         WBUKg5j1gTlcejeaZXV3xyK6XyrcrTinGStgKKEo/u7jhSnUWr0bQVVviLIX9amQSsph
         xEkw5JOiUg4+/7uU/ZZl0uUn1k1b5U5hlnJYSR1rVOAPotH9W0Niw8CkKqe//7+uoZVM
         4/Wh2WhdtvmfkEKVrsr4L4eQARGMH9cnzXJk/a1NLsTxRK/edp3RAvJ7Xf4I2CzZeqJm
         LPC0TgZzFFePkG1DcmCqmpRmhV8fZKkMdMglzW1+CbkEiMX7cPf9SeBbeLkaAFkAtdVY
         ncgg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cnrbxVUs;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007358; x=1772612158; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=tdNj9+X/Gatp3jIZyUPLH891LIKdZG7OCc/DedERb0Q=;
        b=b43565dADIwzkXQ0lJjvy0f1TW7LH92dw6gawJAyp+JqOqbF2838NUhhmdxJjyRI9p
         /MiymgRoF7wDvmj/DI4yEbb9AX0UwXv9s6SI8JxKR84syNs4ajPs+OE3NCwJgIPwGMIa
         0w1xZ80PHOUPaoiNBUAOWYNzyxY06CIxMjR+6HM2fdkSMKrqy2SArSkZeq6NvV2KEaS6
         tHOX76OeeUYKx334JvxG4tRnlh/L4cc0UN2iPx1G/XpPQaX2l84YQ0sBtIdaRZE2jYKP
         4r/dKK99OD+2KVFfdCqqRMO/bdYuGv6xkJkCaB/lUf0ay5AZYfI7DGf/l+6mmYZhBH74
         TPyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007358; x=1772612158;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tdNj9+X/Gatp3jIZyUPLH891LIKdZG7OCc/DedERb0Q=;
        b=AvT+/NcIu00JGnHRmIf3rFx7u/AOEWUNHGI1lfz6wnnoGAg1YK4TtQYSsM4T8i8YlE
         KagpxHz+uuG5yPdzigmriFAbHVoZkomzwds71ml5PJw5sadfojEQiPCAAzdg6G1I3Nn8
         xM0reYKrW+fskzoChXZSBTyhZPyXUdaihD8vKZFaPTDujQFulxfb18IDTbzUPdKtNMVL
         0XbfSjyjWtNkqgrVTKFIW/7Lj5GGFjHK8QPTZWJXcxm9CpRxH24qvkM5GiK6x7xRGdNd
         eh7oBWY2Iiz5FUMMDCXoAgrSQckk6poAjmtUsqSsR/OmMJDV8DPRX7A0HlbGvBe3+sdp
         X/pg==
X-Forwarded-Encrypted: i=2; AJvYcCUxRKfyCmGNOd2yNknBLVhrLOhG70AiAu8vFjrCGe3h7b49Ytp8yyiL+D49/1ZPkms3hjlOwQ==@lfdr.de
X-Gm-Message-State: AOJu0YwiugPCcJzvfyOjd76gVxXKnl85dioAHKbUKZEmntBPB4umUDcG
	gZS8sD01zmEFi1rez342Vs1mRaX6AMw4eL+4djMPy9++J89pDfAtPnTg
X-Received: by 2002:ad4:5962:0:b0:895:4a0f:ea74 with SMTP id 6a1803df08f44-89979ecaffemr228070716d6.37.1772007357968;
        Wed, 25 Feb 2026 00:15:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HN0AKtXcwg9+kADW39gSGetnNElyxMK59GB5LxZ0jYYQ=="
Received: by 2002:a05:6214:da3:b0:899:ad0a:7ac5 with SMTP id
 6a1803df08f44-899ba0c6d8dls6877416d6.1.-pod-prod-02-us; Wed, 25 Feb 2026
 00:15:56 -0800 (PST)
X-Received: by 2002:a05:6122:4596:b0:55a:63c3:f7a7 with SMTP id 71dfb90a1353d-568e48bb403mr7031931e0c.14.1772007356781;
        Wed, 25 Feb 2026 00:15:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007356; cv=none;
        d=google.com; s=arc-20240605;
        b=HFTjHd5PXMqpSBkq0bw/xmqIzbGTeVoB+8Hka2gwEgi80zkj7ybtYJeY5djCcxaHoy
         UOdP5/XKov70bZgV22+EMOrRuJgCJgW2eGjqjjKznSwASxQAvX8njsa/JOEownBwdSwA
         RKGaWlSbIoP7GcivObU/9ufblccmJNnJBAikWd+RgDZKpOpQiCwXusF5dAf7VN0sAUe2
         iE99NKt7axmIIRYV0eeJDSVgHvBLxv67K3ZLIkmV1PMWIA72COYvMyL6cscckLWc+dzm
         488xV/Vmh3rqOrRXiN8CRLauss4aKIVIz3Daye4gqmK6RD3Ieqo0XIPKy488YpvD1gXE
         DHaA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=qbXEkZK+UBZ3F7j2MH1sXu6emUlCr8xCSA0nHJ3EKL0=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=bMWnB58PiCE6xQtu0rIcTtpezb1VsjV8k3EVFxF6v6EPxTckPrNFcNkyyUXEGDTEsZ
         HpFlOYqoSV7w6WQl0zwIVQbJD+pp2Ep8aK3VufOqGwP8oHo7s8L58Qu32uC+IAHy4Fxw
         rQ1V49MA0lCqI9BqXRSqADscSMy46GFEsjBTrzb4lbqNzbuyRVUWTAd8XRZ2fOFOoVGs
         bJPN/mdK+PcHd35dsH5RKN7fW7s/Syn/u+39dp10JsaSdO+CiA7ZMwMqIFcBLpRYY/SG
         eDJpmBZc3W2wjA878cRWYLjo2UJC2mpVr7Fmg12EoIEMbyLu9JhxDKaTToWjZc2GccfF
         9xqw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=cnrbxVUs;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-568e5905015si409143e0c.7.2026.02.25.00.15.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:15:56 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-304-4chxBKYfMym28iynbNI3jg-1; Wed,
 25 Feb 2026 03:15:50 -0500
X-MC-Unique: 4chxBKYfMym28iynbNI3jg-1
X-Mimecast-MFC-AGG-ID: 4chxBKYfMym28iynbNI3jg_1772007348
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-05.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 0CB5F195609F;
	Wed, 25 Feb 2026 08:15:48 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id C1E3A1800286;
	Wed, 25 Feb 2026 08:15:38 +0000 (UTC)
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
Subject: [PATCH v5 07/15] arch/arm64: don't initialize kasan if it's disabled
Date: Wed, 25 Feb 2026 16:14:04 +0800
Message-ID: <20260225081412.76502-8-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: XkAd8O-MDjIFm5FOKG83yFl3KEn8WkekC1N7S_ILQi0_1772007348
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=cnrbxVUs;
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
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBPO77LGAMGQE3ZG7APQ];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.978];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[infradead.org:email,googlegroups.com:email,googlegroups.com:dkim,mail-qv1-xf3e.google.com:helo,mail-qv1-xf3e.google.com:rdns]
X-Rspamd-Queue-Id: 6BCEF19403B
X-Rspamd-Action: no action

Here, kasan is disabled if specified 'kasan=off' in kernel cmdline.

And also need skip kasan_populate_early_vm_area_shadow() if kasan
is disabled.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-arm-kernel@lists.infradead.org
---
 arch/arm64/mm/kasan_init.c | 7 +++++++
 1 file changed, 7 insertions(+)

diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index abeb81bf6ebd..4a58e609c81b 100644
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
 
@@ -397,6 +400,10 @@ void __init kasan_populate_early_vm_area_shadow(void *start, unsigned long size)
 
 void __init kasan_init(void)
 {
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
+
 	kasan_init_shadow();
 	kasan_init_depth();
 	kasan_init_generic();
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-8-bhe%40redhat.com.
