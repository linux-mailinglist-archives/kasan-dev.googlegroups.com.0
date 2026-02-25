Return-Path: <kasan-dev+bncBCKPFB7SXUERBNG77LGAMGQERZE5IYY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MCv6CbavnmmRWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERBNG77LGAMGQERZE5IYY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:50 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id C09DB194024
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:15:49 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-7986c067508sf2079957b3.2
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:15:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007348; cv=pass;
        d=google.com; s=arc-20240605;
        b=dflJ+Fbgs2y384DH/oSDZYLWUSdt4raB9jv82RNwcHemdvlZG9JKWFbVv0FXW3QEj9
         x+9yCgCOracdMyzuRFucKFBT14dy01LJfJTN7XyePojQ2zkjOsOEH7fUV9/3rWYDeiMT
         oL9cT49t153TrmPKdBZFL67dUndVdWDskPlq6zqf2szt8J81mR3aR5Eg6xmdxbAgWJUO
         a/FXnhWDisKDXquGgYOMFw8mI6n5q52mpd0HGGDUtW6BeKJ1L81TdW642sieRqWEbtKc
         xa9oGSvj0HViVFuiBKMwIz544kXgj+c1Nm0TH0eVbytcL8dpWe6qHuKdcE2RWzFwFpGH
         JHEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=7pAa7zmGvzL2wKlrgd+19Vd4blRWE2vQhffMFTh7yKQ=;
        fh=6nSoWHkBKYAgEaH82/snWj64qqO2K9hsJJXxLLptr5A=;
        b=jdHoLfXw3mGLL2ELV3DLWqB4iZmg2NChrZvybvS+wrPphj7RRH225Omm1kny36wRPp
         mTUfxJJxo63x+uGmmFGL3/KMTNiJffWxLwemTKmCW8qsC55GsZo6UBQ18eFaFU7pxpoq
         bmizBTTde8slzFO+4Dh35qZzzkeI5pVjV9DXjiX2ukofSxuAYQlXgELaMA/lqtoibfuX
         sv+JBstOvLqCShQ9B61EBpOxaDBELVK6Z9r5KnGNVst5GGtuX/mtT1IBIrbd6PBaJAyX
         2Ll2/hrfD9SMaZjdbBV1itkwiPsp7rKVeufsZaqbF4h1ERnVd8Gw/piU8LxVMum1Gb/H
         DLCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IZq3puuy;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007348; x=1772612148; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=7pAa7zmGvzL2wKlrgd+19Vd4blRWE2vQhffMFTh7yKQ=;
        b=hY/WzVCZq+HGw1SIxnFnm/AeiUI2HyKF1+Jeer8FTdJUsH0FCeyLWlj3/sxowF4S1i
         AMfrm9mIoXKOFYaSARVyzz/nrKngGjMxm43lpBE/JUleYdn0gDCuxfcY5Y1GtIFw4WOp
         C9kDNzQ3rbBEVjiOghCO5D8dfEbG8RMh6A3x75AbZKKDrPFW0j0mNkQkk6tC5v27e43b
         Krdaj1lrNizKkKerDgcfqC4rBuKbBBJw/36Q1H0QDMA5AS52t6fpthzBfjV4cJsJUkUj
         XgiX908NUMUlz1jHTxYFJrYgJsL1yXu7rfGBYDfjsVGDPBSO5UN6ZArfdEtrs1reRtuG
         QqHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007348; x=1772612148;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7pAa7zmGvzL2wKlrgd+19Vd4blRWE2vQhffMFTh7yKQ=;
        b=sFvR6lAZ2/YA45MRCSrGYDFeAtMV7jfdFEsS1RGPrsqBpvGFcImKdGTm5adAIvjVGk
         GoHoItdVZJ6hfTQ5wK7eYUGO+MJAV90K4l5hivZFdxaKIXdJgSYbWGqZ9mF2R17NsJRN
         jEhMioA16c+0sA2OjI3fhNfrG0Y/1Czbc28/aPZEGZPRT7XsbvRnyhCNxUVtj8IABDnU
         MXGaXlkonyINEVUkNR0eG1caW7iUq28muBir9ygODWhqCqNER2Dilbk6eQ9KR2SkvPJD
         wz3Tdq/Hw+4x1snR+gimMTp4qH/dcxYe0SMh00cY0Un0CRiMu5DH1/SfJRvN/Q37e5u1
         /WQw==
X-Forwarded-Encrypted: i=2; AJvYcCUCnwYPcjFcYpwabux493+Q1Oku8ds6nm4eq7jmriZwBn6ePFD4Avy5Wrr6OmLSkXAuLRv4PQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywl+upu1tAoLleB68q9gjDVyk5PMMZAmuEDdxrbv2VP+mwWzj70
	CfklAe4a8YJMTWbZjMM3dOzcon03MTD7uBWsVVhFFJ50jrq4+GpyVGyq
X-Received: by 2002:a05:690c:c4f3:b0:797:d1c3:fa8 with SMTP id 00721157ae682-7982919f6ebmr115054457b3.66.1772007348496;
        Wed, 25 Feb 2026 00:15:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gsv87s7drnH66M2w0KAkud3hHpjrMoHgoBD4dhDpmxBw=="
Received: by 2002:a53:b496:0:b0:64a:d210:f4d2 with SMTP id 956f58d0204a3-64caa97c978ls236760d50.1.-pod-prod-08-us;
 Wed, 25 Feb 2026 00:15:47 -0800 (PST)
X-Received: by 2002:a05:690e:1553:20b0:64c:2a4b:731 with SMTP id 956f58d0204a3-64c78f65e0fmr9576645d50.62.1772007347419;
        Wed, 25 Feb 2026 00:15:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007347; cv=none;
        d=google.com; s=arc-20240605;
        b=SUbn1ARnSoAwLNA+FLtqyjoMDAk+Kli2d9dTZXGuGqjRsO9mSagx7j6EGzclcT2WkH
         pUGKcpa+9DWDH2emWhaPq2v3jSpX50xl5oMXJD3/7a32HxZib3UThLzvXu2PjAsYG9qO
         ACjmz49kj9OcR6ll10uCY9TJEbhQEiaeWDUvoVW4UrYmRrotsoMYjQcdy27Z23IDDLtL
         Y9qkhRU/f9cKbU61l90QfXXanYLJ8drLnl5FrQTkwdbpWkmFuU+Cxbjmhz9YE/xhoNvC
         iM086jMZUKzKZngrEDEJY0gw4uJoMwgSIuEoDBFombLe0lFcvdUGwHyYuVGGm7jfDgYN
         PH/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=I228xoUl4+ZrgdKCBvI2rCmcNIzmRojWxOXL2gQGmtk=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=KPxRHIvrQosv1s+BNpH8yfbYV9Hqeb9Ok4XLFQ/P1Y8TXmR6F1Y8obi0NUKYYzX7ch
         0cm/8MO/htfdMtBWYsRWXOJAh5ou/DzNXv1prSS8dFit5TLVQiIYnfdI1IVdAoMyPjxv
         RzM6zoJcDgzGf+sGSPWkNg2B8i0VUc9YX0IbYzkgPdA4CwCBj/xGljIf5jBpRoMrQKpn
         pLRUp0xr39wThuXjw3yqdvxcuB6nWyIdroVL8nTEin5G/2WtgqZeRzXG/U1uopSX6Qq/
         IfFzcO+AxaqLl/tViohV7v//p+RW7+XNHkhLcPV3xyMNX8gsywKPM74ihh+fYX8I3b0S
         WaDQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=IZq3puuy;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-64c7a13a8adsi404274d50.0.2026.02.25.00.15.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:15:47 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-675-rwD-1e3zOqOiSldVPhFTdg-1; Wed,
 25 Feb 2026 03:15:40 -0500
X-MC-Unique: rwD-1e3zOqOiSldVPhFTdg-1
X-Mimecast-MFC-AGG-ID: rwD-1e3zOqOiSldVPhFTdg_1772007338
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 01DB51956070;
	Wed, 25 Feb 2026 08:15:38 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 68EB31800286;
	Wed, 25 Feb 2026 08:15:29 +0000 (UTC)
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
Subject: [PATCH v5 06/15] arch/arm: don't initialize kasan if it's disabled
Date: Wed, 25 Feb 2026 16:14:03 +0800
Message-ID: <20260225081412.76502-7-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: lUUtKGp4KAsti1oUbjG63WaM0lO-pCOr1OLSbX49VT4_1772007338
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=IZq3puuy;
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
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERBNG77LGAMGQERZE5IYY];
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
	DBL_BLOCKED_OPENRESOLVER(0.00)[infradead.org:email,mail-yw1-x113f.google.com:helo,mail-yw1-x113f.google.com:rdns]
X-Rspamd-Queue-Id: C09DB194024
X-Rspamd-Action: no action

Here, kasan is disabled if specified 'kasan=off' in kernel cmdline.

And also call jump_label_init() early in setup_arch() so that later
kasan_init() can enable static key kasan_flag_enabled. Put
jump_label_init() beofre parse_early_param() as other architectures
do.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-arm-kernel@lists.infradead.org
---
 arch/arm/kernel/setup.c  | 6 ++++++
 arch/arm/mm/kasan_init.c | 3 +++
 2 files changed, 9 insertions(+)

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
index c6625e808bf8..82ec043c891f 100644
--- a/arch/arm/mm/kasan_init.c
+++ b/arch/arm/mm/kasan_init.c
@@ -212,6 +212,9 @@ void __init kasan_init(void)
 	phys_addr_t pa_start, pa_end;
 	u64 i;
 
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
 	/*
 	 * We are going to perform proper setup of shadow memory.
 	 *
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-7-bhe%40redhat.com.
