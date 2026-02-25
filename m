Return-Path: <kasan-dev+bncBCKPFB7SXUERB4W77LGAMGQE4IQNYDY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id QCPaIfWvnmlxWwQAu9opvQ
	(envelope-from <kasan-dev+bncBCKPFB7SXUERB4W77LGAMGQE4IQNYDY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:53 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 255D11940AF
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 09:16:53 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-358f8b01604sf3586546a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Feb 2026 00:16:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772007411; cv=pass;
        d=google.com; s=arc-20240605;
        b=WivaWx+RN8krB0w1PcjzQmIXAeBByAEK76R+nrurEhCCmAAsyWAMmTWk8VwG0IZ9wc
         62gkfFuAT85gG070E5AO5USMPoCvPhKFK7FzMK0is5sRePuwZ8MZgfRK21SKZe3UZH30
         kKpKGthClE99eiqVLiRbAkDbWPLlnpwyNssjg4d2h+uQ6PYsvn1l2ogHNPSUIH7N+XO1
         uH1nU9DZ+TwuSkOSUwrbJJ0hxmI3l4rZ3v6IOAsSeAG+dM5127HK052ylJkzKZgi7wm6
         4hztFRGb95cLJq3HOMZty4DDyPYJNBMKtGWJt3ykAdztvECQGbQ46GBzDd1prq0CDlml
         hbnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DEyRqTj276HdVFwgzuizdDIpAEivtHZDktDzOOkLaII=;
        fh=CiklMY74dBxEyYmtStyh0KGBQHinMOmaBVOH5TZr+U8=;
        b=KLNNPcc3awwMm/rZw+9Hgn/D8Gh0n5M9B3XXIsZxHPlJiI86hSzxMHpsnETG3kfGYL
         pMXt4+7NrxA4A1ACHir0rqJ0lYZjhbkw+h076gtqNkTZfXFrknu1m/6eqFmWgclIu+AV
         5zrn8ZrmCGJLUXHLzfFXix5ieG3I3Wj25m9DsZTqL6DyzPNJSNdSbqt5gf3HjD/Y3+7v
         bJRUo16T4IlyRXnUyiqyb7MDpKVwFJpOSME7Gp8heZCZqB2rzMJhyTj7MLmL3/K43B+a
         9YhfhjherwcnwtE52K9pJPdK9+23s2SO3wGucWHFuweuO2F9k50zVCyn6q4Swoi6tCzR
         Byxg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TFvSnbXk;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772007411; x=1772612211; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DEyRqTj276HdVFwgzuizdDIpAEivtHZDktDzOOkLaII=;
        b=Cep33AmAYjkFHQNIk7yRetxjRrV5Hym38jWlXfTtPc4LhXTR9ljCzqWKBnZZi2vMvC
         9nCcW6Yha7n8B3jnLRHXFJ8zDC+V3aSO6d5Wf5/W0zPOoD9SeV4xo23HorZBN1Xc4I9g
         N/XKIyjIZh8ZJ5wSsMLqVqhkKcFl8QbJXB4bCDr7D+pKggntHyClGlLPo7ZMS4o+9sy9
         uoQkP9UudzVwuZ9Tf1MpU0n7lxaXa9cVrw5sniaA318XJXzyFM8XcY56sSq99k0vh/us
         Yhp5g5k+kC5bin5Ulx44/YqavUxpgxfjG1abKNvY7Bin/OXRd7D47l8+iXftRG80PU5J
         00MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772007411; x=1772612211;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DEyRqTj276HdVFwgzuizdDIpAEivtHZDktDzOOkLaII=;
        b=U9PSdn8KntV9gCLcrT052Q3QIFnERDyScJ5X4UGl5B23iqhfpobzSv5LxhVlY3Zqg/
         FhbkPCS7bNOf0EJRJA/hbtZa09RsRYadfycnzgs33QoESs041qq71/pSEoojwOW3VfyF
         ztJzWOtjXrBGTsreiIU9EuIirhJ2q8sgizmUI/l6ptolnxmY+XqDY6ahWVrMfrri2Fou
         48OF4jmF4JJevJUhKfOWn0U6e3sV5UrnIFo55leAV8+hT00cdo6USEjK7QsnJeiJWldO
         0ZP933BRNxFLJCU9geFheq6T1lOGk0ihyucruH1C5rR6+3YxBXFp/sXxyKKm6NEVargv
         p7Ig==
X-Forwarded-Encrypted: i=2; AJvYcCW3f2rX6Gi+5xH+955Bc4llJSQM0LuHZ7uOQsPaFXfgOnfe7PMfI4qK9ArXTHbLBG8a5X+VZA==@lfdr.de
X-Gm-Message-State: AOJu0YzF/E1Ntn5FOuOq++Mv2opCCkFXVSoxNTuRau6QUN9KxyytKOBT
	KmeeTFXx6yigoVcdgdzyl681GHdr+uF/4ntQQeAAENVDU4FDhxWJHR2t
X-Received: by 2002:a17:90b:4c4c:b0:340:ca7d:936a with SMTP id 98e67ed59e1d1-3590f135a7cmr1706895a91.18.1772007411277;
        Wed, 25 Feb 2026 00:16:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FrAQmBQ42T+T5NFyUhc8OMkgQa6/tpuYTKFAlBA+bQQw=="
Received: by 2002:a17:90b:3f0b:b0:354:ffe7:a92b with SMTP id
 98e67ed59e1d1-359105cfd0bls482587a91.0.-pod-prod-06-us; Wed, 25 Feb 2026
 00:16:50 -0800 (PST)
X-Received: by 2002:a17:903:198d:b0:2ad:4265:bfab with SMTP id d9443c01a7336-2add1224527mr16230395ad.5.1772007409946;
        Wed, 25 Feb 2026 00:16:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772007409; cv=none;
        d=google.com; s=arc-20240605;
        b=KkbMxQrnRA6edl0o4jEMJRiUy7OhyoFV/gtg32ngEZZ86citZPb3EMhS5Gw82yhrfM
         WRApbRos0o3PxS5mQRDyKjPwz8+zbubV9QcmBHqf3Ew9Zi+Hu6N3Vy1rgIxHVBEErsu+
         kOvu/B6OIjIMvq8/WA/6M+U+FrE/uMATWJKoYrsaTv1Ec9kGaJaXKj0UMUuqCHEFHBd0
         BwJbvm7jVUjz62EQrd+KgyoQwsEn8nMv2Af7JtG5i6B4Hvp5NV550rEXkyJsvMsADjiy
         I0Xwp46YC5U47Vt1jw1CnRmPhQkSkrio54JDz5UBajqx3qSNFUoP/qSeKq63pqsmvwkU
         QpYw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4hnbGAm/9+0AQuOsI/z6/MObWdWASDtilCdbwr5t2xI=;
        fh=1u/rAQ2shkgBy1hSbEpxEfZyuRFBHpgek1Apm2Xu8ks=;
        b=PeKteUA3mz6xgBAZ8uWICdwgtJ3ccS8gx6slNRwuHQd3RTGik9/XQOBOa/9sfKAWK4
         wXVMx/RSxi4orBB3HddUTGgRZdd1vt1PhmTpKlyMmFOSi28+dtuIEkkYjv6kGVXG91qm
         CNvOZbxytIqXOcikxsYFuiZqA8C+ddVBAWKFqTM0VbOCnflb/ze8D0bXsJeFxLHBoqkJ
         emOfvuGiQdNfvi9jiCjOHWbpIym3IR2PySgQW2piwPLTuJZ6KmXgN6DpeuGg5AV1czP5
         v2ytr0jeIqjzTEvv30XBwnFvpDJzStuf4Ypm7p4g+hvoIzbbLX5w56vPKCSAuPQz7l6j
         ABJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=TFvSnbXk;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2ad74e46058si4713935ad.3.2026.02.25.00.16.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 25 Feb 2026 00:16:49 -0800 (PST)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-354-kB3PHjUANFi-zOP_mIJF6w-1; Wed,
 25 Feb 2026 03:16:43 -0500
X-MC-Unique: kB3PHjUANFi-zOP_mIJF6w-1
X-Mimecast-MFC-AGG-ID: kB3PHjUANFi-zOP_mIJF6w_1772007401
Received: from mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.111])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-01.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id A6D5A19560A7;
	Wed, 25 Feb 2026 08:16:41 +0000 (UTC)
Received: from MiWiFi-R3L-srv.redhat.com (unknown [10.72.112.55])
	by mx-prod-int-08.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTP id 8570F1800465;
	Wed, 25 Feb 2026 08:16:32 +0000 (UTC)
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
Subject: [PATCH v5 12/15] arch/xtensa: don't initialize kasan if it's disabled
Date: Wed, 25 Feb 2026 16:14:09 +0800
Message-ID: <20260225081412.76502-13-bhe@redhat.com>
In-Reply-To: <20260225081412.76502-1-bhe@redhat.com>
References: <20260225081412.76502-1-bhe@redhat.com>
MIME-Version: 1.0
X-Scanned-By: MIMEDefang 3.4.1 on 10.30.177.111
X-Mimecast-MFC-PROC-ID: UqL4DefT5F1VayMBaOc89nNUj4hHmfW5xB3x9uCCbxM_1772007401
X-Mimecast-Originator: redhat.com
Content-type: text/plain; charset="UTF-8"
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=TFvSnbXk;
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
	TAGGED_FROM(0.00)[bncBCKPFB7SXUERB4W77LGAMGQE4IQNYDY];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[kvack.org,gmail.com,google.com,vger.kernel.org,lists.infradead.org,lists.linux.dev,lists.ozlabs.org,kernel.org,zankel.net,linux.ibm.com,redhat.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[bhe@redhat.com];
	NEURAL_HAM(-0.00)[-0.981];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,zankel.net:email,mail-pj1-x1040.google.com:helo,mail-pj1-x1040.google.com:rdns]
X-Rspamd-Queue-Id: 255D11940AF
X-Rspamd-Action: no action

Here, kasan is disabled if specified 'kasan=off' in kernel cmdline.

And also call jump_label_init() early in setup_arch() so that later
kasan_init() can enable static key kasan_flag_enabled. Put
jump_label_init() beofre parse_early_param() as other architectures
do.

Signed-off-by: Baoquan He <bhe@redhat.com>
Cc: Chris Zankel <chris@zankel.net>
Cc: Max Filippov <jcmvbkbc@gmail.com>
---
 arch/xtensa/kernel/setup.c  | 1 +
 arch/xtensa/mm/kasan_init.c | 4 ++++
 2 files changed, 5 insertions(+)

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
index 0524b9ed5e63..eb367b801218 100644
--- a/arch/xtensa/mm/kasan_init.c
+++ b/arch/xtensa/mm/kasan_init.c
@@ -70,6 +70,10 @@ void __init kasan_init(void)
 {
 	int i;
 
+	/* If KASAN is disabled via command line, don't initialize it. */
+	if (kasan_arg_disabled)
+		return;
+
 	BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_START -
 		     (KASAN_START_VADDR >> KASAN_SHADOW_SCALE_SHIFT));
 	BUILD_BUG_ON(VMALLOC_START < KASAN_START_VADDR);
-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260225081412.76502-13-bhe%40redhat.com.
