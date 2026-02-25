Return-Path: <kasan-dev+bncBCKPFB7SXUERB7W77LGAMGQETTCVLOA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id aBf4BQGwnmmeWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERB7W77LGAMGQETTCVLOA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:17:05 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id AB3161940D4
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:17:04 +0100 (CET)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-896f2e45fb0sf28906246d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:17:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007423; cv=pass;
        d=google.com; s=arc-20240605;
        b=IUGsvaWqdme3p8Nfnqj4hy3it/LbdqnBU0ibVk/GC9JOWrksF/e4Qo9InM1cFJ/vaI
         z1z29Lwm3sYQ/YFXmWCwUB2L53DQ0w6Gjgf1Qrz2MaFiVdZKbnzhYZR0sytJqyKTzNcM
         3iGomVPxC46MkgvRT+ym6JM3A7AyUw8H8/AElcuWXB0Mibj+DSsLp8zbRaKq4MACM6f+
         uYBfH5wZ6XfUuJ7OYdIDwNbHVyJAnS4sgNZazILR0Kw8+BIeqvxUY9LMuI7Zs0D+kH5J
         i0qFQLihUhFbuuQwHepnecW2ERYGqo+8BGe4dmuhmh63TdRzQrqCjy4ZRLclOtgH4/SB
         9PJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=QcLdr6aa8AIZJfc9FKS0froe0vxWKkZveX/fsuxRh2A=;
        fh=WiUwzyRh8GA0A+d3e112mToXtXXvbbojvu4foUCtmUM=;
        b=dendUA+V+j9raUEDU6ffNVJxS1+QerRE3yHCf92f0X1To+amt7Hs5bieXJRJifYt5F
         fxFojIZKPXYrixc40ICVD5l86Dok1gA6Z0uAjwdK0CtdxtfEmBgItk2dk9fgAXygOpPp
         9f8HJ4H+Szkr9qIqExUsnNgK2LjPfmloh3ih/GcBaSZm4UaXRCkW8X3wMIARELE7238M
         rMc55BB0EQQBu8sGdVF+tlJ9U/2dqIp5jG9Zq38yS7g0XpiBCD6H90eNUqEFbPit9CXx
         lUBMpuD4rLnNTwb0UjyPoyDBXRieRSEXALEep5p0oOaebkteZVOf43E6297gK8n4jfAu
         4Ojg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Ig+rRKcR;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007423; x=1772612223; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QcLdr6aa8AIZJfc9FKS0froe0vxWKkZveX/fsuxRh2A=;
        b=lGwyLeD3gmYPKaisd7Q7noIvgrOu3jc9wyh41rhAn5crq7n0hQujN2pVAcYaCzfSFF
         hIkvKdyzYOJH91v8tT35Gvtm560myadd9ojWhbi20qJbEvwpgX0SxL6yZ0Gw9YKR97uq
         ggFWSAfPfkcBa0JzPeCOTy8VYD49fHODFw802t7DnsN7iMoWjdl6uxvC5daTdfaPZsdI
         zhf495ipxmTx5ZKcXUItVDF6a6Oj9rZxM2EqKHvMGShuFWl0tXmN86IhzYF4w0004wL6
         +wr5OlPqv0JUmIABprX68BcY9kfjJMCC7+++jwz6Py9S3p/UCzkbeGc/wLU+Gh8jFICQ
         36Zg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007423; x=1772612223;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QcLdr6aa8AIZJfc9FKS0froe0vxWKkZveX/fsuxRh2A=;
        b=tkIpdx27Y5FyI2JzaftieTm62IdgIfxqcoTwisIxUE10cO4V4e97od4RvrGIHe9KbM
         oR2CXHh+qWIVk21inCzkRZmqmCQgwIhVmNx0kNvWk+kmt/PsJ3v8fXfcmKrmzke8mDkh
         R0ukvv6bAEZISnHTx/5NHZEMYGWBe9QEQQneXxjO/dvK6+4SbA5ELMZKCU7wLVUmMP1O
         4h1GavQiwr9bsLQTJvQTXDfqdeB5VecPAn2WFuyx1xnjEZVkVUlUXKFxXzKZTv2Z5pUn
         KXCYL7DBdIgucKGJDrFjEpXyRUE7c+ullDR3MT5McPz+ByzoPU3sZTrxFmPKedSmgSzS
         DQtw==
X-Forwarded-Encrypted: i=2; AJvYcCVS0fk0r4KcFkWTSz+opBN//XXViIJpVvcx54+5xG5zkPvCoaMjNw7unQmtlOX+Lac1C1s/ng==@lfdr.de
X-Gm-Message-State: AOJu0YyhPeea77N5wHpb9Lg1A1JgNA90ER1bD0wg+D4xWChA5edErS3P
	vjYk2vpFGnRegVhE/eNG8YcvoykqOn7lPYanKl+ADgyhiwuKEct6PdmA
X-Received: by 2002:a0c:e702:0:b0:899:b3fe:c340 with SMTP id 6a1803df08f44-899b3fecb41mr28054976d6.22.1772007423148;
        Wed, 25 Feb 2026 00:17:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HfydaC/uPwKIv8bVkrL99EZOo4+iMKXu2/iu2oVXQMBw=="
Received: by 2002:a05:6214:2682:b0:895:1d69:34ba with SMTP id
 6a1803df08f44-899ba0e7d7bls5214856d6.2.-pod-prod-00-us; Wed, 25 Feb 2026
 00:17:01 -0800 (PST)
X-Received: by 2002:a05:6214:c61:b0:899:af38:ce1f with SMTP id 6a1803df08f44-899b34f0b0fmr37772476d6.20.1772007421276;
        Wed, 25 Feb 2026 00:17:01 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007421; cv=none;
        d=google.com; s=arc-20240605;
        b=Le6kFvhkCvTv0lX1famNebCZOf1tlhJH7OabRyCSkG2Jb8PQ0Cbhp/3QYiWd6fEh3b
         ktzqTcONIq8wCRh4GvUdT49E1joUOc8QMvUJKGE50RyLWDq25Lu39rUeHj5tNDKwhN53
         zyy2S2D0Noz2CHEpsvf86j1qhbaFk0VbJA+EWx0sq9qjCvEPJSt+4bq6A8VhCtk/Eezv
         vHn6q26PL2BUvlcnk/IBSdjqjvt7z3ul+Yta1XX0UOAhADYKXjYxYV7N8SD8yjoh7qg2
         IK6spS0rwZD7Hzvxkg2T1J/JqA9WkfNaIMIqnJwQI7nK74vfdyek8f64WDbs4akp/xB+
         jxXw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pa4Mok84BgrIJ096oguK0x0r8biU2FN9KdJaqHRRdYY=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=XcvfMTJsmHCR0Q6niXtcjz3dR7gQdDKgrS8PQCyfoBPuhjZV5/+GRyc7glx9Syo78U
         Rr8mLwm8TUsPzdLZwFl2TqozvbPp/fJETqEIw4KHQ0RlsoJd1MrpnjuB5jBpFoWrkUWj
         fUP52uUoyxYItXWLgYtMk1IEbPLYvHgUUXzhM0ZHmvvQDXzDeNpzskckEfLGao04BS8p
         zz4dIILvr154PcRcMbqm4+TAg5W9ExjWCP5OIIXYqgCjLMrFW9x5J838rMCvgVhqRrE6
         OSut6In4vL4Vva0IUCdgTT8PtSRbQncPZs7SCEoi0z1BPOeMN6xLRnirNZMV+cKlkfG+
         2m7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=Ig+rRKcR;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-507252a6d3fsi2745711cf.8.2026.02.25.00.17.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:17:01 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-35-165-154-97.us-west-2.compute.amazonaws.com [35.165.154.97]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-199-nAFljNsZOpiYJ57hUOCZnA-1; Wed,
 25 Feb 2026 03:16:54 -0500
X-MC-Unique: nAFljNsZOpiYJ57hUOCZnA-1
X-Mimecast-MFC-AGG-ID: nAFljNsZOpiYJ57hUOCZnA_1772007412
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 32EB918003FC;
	Wed, 25 Feb 2026 08:16:52 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id A81041800351;
	Wed, 25 Feb 2026 08:16:42 +0000 (UTC)
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
Subject: [PATCH v5 13/15] arch/um: don't initialize kasan if it's disabled
Date: Wed, 25 Feb 2026 16:14:10 +0800
Message-ID: <20260225081412.76502-14-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: BpzBS9zBIGIwxup3lqr2Mff3AMHWRobZaKxjDOhm19s_1772007412
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=Ig+rRKcR;
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
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERB7W77LGAMGQETTCVLOA];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.980];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,infradead.org:email,mail-qv1-xf37.google.com:helo,mail-qv1-xf37.google.com:rdns]
X-Rspamd-Queue-Id: AB3161940D4
X-Rspamd-Action: no action

Here, kasan is disabled if specified 'kasan=off' in kernel cmdline.

And also wrap up the kasan code into CONFIG_KASAN ifdeffery scope.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: linux-um@lists.infradead.org
---
 arch/um/kernel/mem.c | 5 ++++-
 1 file changed, 4 insertions(+), 1 deletion(-)

diff --git a/arch/um/kernel/mem.c b/arch/um/kernel/mem.c
index 89c8c8b94a79..2bf858ab35b5 100644
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
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-14-bhe%40redhat.com.
