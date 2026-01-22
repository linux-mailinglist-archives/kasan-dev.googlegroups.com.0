Return-Path: <kasan-dev+bncBDN6TT4BRQPRBCWJY3FQMGQEX4R6NHI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id ULI0HoykcWmgKQAAu9opvQ
	(envelope-from <kasan-dev+bncBDN6TT4BRQPRBCWJY3FQMGQEX4R6NHI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 05:16:12 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D5A161A5A
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 05:16:12 +0100 (CET)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-8947c4398c4sf18039736d6.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jan 2026 20:16:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769055371; cv=pass;
        d=google.com; s=arc-20240605;
        b=i0qpMETk4idrY+HBkTohxFP7/wpAXY0+IyB4Wmh6YZvIJBdYYdvwqCfHYXO5WrD/mC
         KsoOpyM9UpJ+h9uZW5kVik+CYMaxegPyk1MbadNI5F/FMMWdAptMdYHX3rluaWa3YN2Y
         7YYx9lWYlpua9bQtjTptehb7lchwFQ/1WHxc+I8PbpSmpiMORSxcjOMg414TPNmrfOJ1
         lSKPUFvTr7Z+EDqsfEDUAnCfiiQz3t7U5egXZdlmvjLGVt16qNPCcJTLnmU8bcsnf5T4
         Ltduhqk9EGx/I4SkSSaIrXphAsCauYdJoYgFm4ifFNvUMgZ0GQvexSyL9iSGbUzwlHsM
         ldKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:cms-type:mime-version
         :message-id:date:subject:cc:to:from:dkim-filter:sender
         :dkim-signature;
        bh=N9qj5NibX7h9QKtpjfgJt5LD5F7+r0PQCwIw87E27m4=;
        fh=jnYRI8YlL2W0N5EIskJmLAtorM+6LJQPjce6STMDtPY=;
        b=KX/zscrZcR3B1oN9ZKHXRfk/eITV96DWLaAoGfrbx8zdwbA+g0YU6R2aSvZpS67Htq
         3ooW4dYHWJsndNmAaVTiGCuZbbMGYybTpoEpwMEgX8lcFLQ3Dj68HGcUCfBaRJbKTBiS
         Ka0La6GcdhBXry2jOWRrZENymgvOdL1qT6qh2UyBNIbszMB+3Vq0gPPHRAdty9jmTIWB
         FlNnhJJKzWpkCiH05xB7XNJ5d84riyhsR0aBpBDnmJCxo0seIJ5IGnFtSUAAGVVQxNW6
         vuRu0Tx4IngIq5+U7gLguax+E4c5Y5cbYGOyw7sV9/cYiJgQbIthnf+B5M4vJcNHFb+n
         1bTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=UP6ztmWt;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769055371; x=1769660171; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:cms-type:mime-version:message-id:date
         :subject:cc:to:from:dkim-filter:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=N9qj5NibX7h9QKtpjfgJt5LD5F7+r0PQCwIw87E27m4=;
        b=steOA2pJ6qZSXsR75pvejDF9e9YJh8/isuNPaaX+/TjU6MBHwTtpOxKb4FCk9U+HUO
         g2f0cJPy/MyQ6QoGniBnD5ABvfcLymW67Sn45QCQWBGEKZaicGo7GwCAiTg9gllfIMvE
         UuNMoqFoFM60L4CrRx+nezydNO6XRR8YorFIu7WWpAwGv/eGrjxTJJE9/gNbaKqx2vO8
         6Hdv7xHKeBwK/PGO801PmlLYTBx/I0YPlCqZ0ty8lxT1lusXOvvXPQ8LsDVdrou1DkkJ
         ko/VMChlwPQr4y/A9v2VMGK4ANFX5AcbGtkmxWxFiV3hteL+Q5apWQIjmke91zKtvFEb
         qViw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769055371; x=1769660171;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :cms-type:mime-version:message-id:date:subject:cc:to:from
         :dkim-filter:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=N9qj5NibX7h9QKtpjfgJt5LD5F7+r0PQCwIw87E27m4=;
        b=sWXxz11pkn6gKGCOZOmout6AIEgzFaH0tpfONJxgENrMCdMRHaQtBVjHQwVVyojPBJ
         lU3SxVuuLwTiXKU+0uWKiZQeKfL2GSb6pUobuwX8oBrQnWfja4T8FjqeMOgqVYnhKY9S
         63TW/Dq/AlZiTgy+OoEBPcdxd8ZU9wuE8LwNcev76XnvQtqbklmvRX9CeYsCQf79g7js
         tXhxdbGJRwIq4MkYkzKUKLsQVbsofheKY59YVpUUEp9FYGC+1CtSdoJmoCJshHvsHn24
         C8AKbHH5k8RMKDAbIGkIu2ptXN3ZxPYBNS6A8GMHoS76yHwT5jgbjVz/keCsQkj/cU+b
         K9Og==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXtuH7KOOu3ZEfEp3eqh60QUuAYIKj0dKXUtcfRy17VmO4TIxb+QtlQSy/g0DIs86KJeDJJNA==@lfdr.de
X-Gm-Message-State: AOJu0YxzUaTQF1KSsTbMZIQH5sn3sYqfZXlV5P2O7ceK/deiHDZajNVi
	2LSL+hbpuz2M0kVnXFO9ILOQ0tUUDFcsDlJ9AzAYB20nd7fLM1mUZ52X
X-Received: by 2002:ad4:5d4c:0:b0:890:7eed:a7d3 with SMTP id 6a1803df08f44-8942ddca5b0mr346216386d6.55.1769055370720;
        Wed, 21 Jan 2026 20:16:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FVVCPifPe4e6OWzeVb0oSh3TqycZ4Njq9Y6NEczveezA=="
Received: by 2002:a05:6214:f0f:b0:880:57b3:cd12 with SMTP id
 6a1803df08f44-8947dea81b9ls8304566d6.1.-pod-prod-03-us; Wed, 21 Jan 2026
 20:16:09 -0800 (PST)
X-Received: by 2002:a05:6122:3d08:b0:559:6663:8b1a with SMTP id 71dfb90a1353d-563b5b7a4aemr6273572e0c.4.1769055369774;
        Wed, 21 Jan 2026 20:16:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769055369; cv=none;
        d=google.com; s=arc-20240605;
        b=RaO/ePABCdlA8ArkQkrx40r5jGPiga+wgf64XCYTQNV3YdYabQAyyA8mPDaUfMkdU0
         tsluA8cm+QsVWcBWPslpBWeWMQqRH6VGOJvLrhSlSJ5apU35IsjkT5ip8aUSFStywOLe
         MaB+fQiC3gP+R+LaoTaKok1/9pHAkrZRXbMqMa3pw1VcCUnT2RlNKrF7P6FKZmH64HGH
         g39KLlI63veeTgd/XXkAdeMypan8HqV1BSZi6XP/ShEYaIyNhxhQ9+0oxUmEMz6uiPiH
         TH5VKx2HplXNVoeU/tYE6FTdB8RwIfEpbl6UyVtudtc8M3Y1CPIJeeAuF8TRf+im1UoQ
         Le6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:cms-type:content-transfer-encoding:mime-version
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-filter;
        bh=ulwZDueuEPaWeca2kmd0L47zzrWdpEGAgSW2N/gE+Yg=;
        fh=y3RtOpmSOKVo6vUB+iKgjogMbUIdbWzJBMkV+gUh2/A=;
        b=Oat/eJ8rFLoZoRE0M7DaIuU0GuTpjuSMEupj6GyUgn5Kal/9KCMxHK9I+kZS6vG0jG
         CyC9PuHa4FDWV4/X7gMg57T1ZmDBABhqvqPbU3nHnC2+jGCyA/P7Hac/Afbysjtfl4JA
         ewa6kth1CU33MEYednSWHr2eG15CULr+TzB9Nx2ZJA9rln8a7xJ3kDk6ohlTBI8Q6j2U
         vxT1c9HuVsBkYdvUfX1tcot8DH4Zo7EQ1TPKeWrhS6TplWfKjhYkCEz10YC+YqGlYAFL
         vVE0fVQmwj1CabJWm/NSx36syl/Yfe2z3JGjSgET7ockeqhqBIB6E7tKcVmUDne5yTe/
         JmJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=UP6ztmWt;
       spf=pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) smtp.mailfrom=maninder1.s@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.samsung.com (mailout2.samsung.com. [203.254.224.25])
        by gmr-mx.google.com with ESMTPS id a1e0cc1a2514c-94812f36ea5si136108241.0.2026.01.21.20.16.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jan 2026 20:16:09 -0800 (PST)
Received-SPF: pass (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as permitted sender) client-ip=203.254.224.25;
Received: from epcas5p2.samsung.com (unknown [182.195.41.40])
	by mailout2.samsung.com (KnoxPortal) with ESMTP id 20260122041607epoutp0212ae6642e3e8373fbf8b8a5f9eaf1a69~M8nvII-Bs0836608366epoutp02T
	for <kasan-dev@googlegroups.com>; Thu, 22 Jan 2026 04:16:07 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.samsung.com 20260122041607epoutp0212ae6642e3e8373fbf8b8a5f9eaf1a69~M8nvII-Bs0836608366epoutp02T
Received: from epsnrtp02.localdomain (unknown [182.195.42.154]) by
	epcas5p3.samsung.com (KnoxPortal) with ESMTPS id
	20260122041606epcas5p3c2ae4cf2d797eed268772f8c60d1e326~M8nuuy6-k2478324783epcas5p3U;
	Thu, 22 Jan 2026 04:16:06 +0000 (GMT)
Received: from epcas5p1.samsung.com (unknown [182.195.41.39]) by
	epsnrtp02.localdomain (Postfix) with ESMTP id 4dxSRV4bksz2SSKX; Thu, 22 Jan
	2026 04:16:06 +0000 (GMT)
Received: from epsmtip1.samsung.com (unknown [182.195.34.30]) by
	epcas5p4.samsung.com (KnoxPortal) with ESMTPA id
	20260122041606epcas5p4fb3f5c418b79bf19682e60022d7f1718~M8nugqkEh0494404944epcas5p4w;
	Thu, 22 Jan 2026 04:16:06 +0000 (GMT)
Received: from localhost.localdomain (unknown [107.97.243.203]) by
	epsmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20260122041604epsmtip1810334375c21d205d0ec8887af3691db~M8ns316Pt1745917459epsmtip1m;
	Thu, 22 Jan 2026 04:16:04 +0000 (GMT)
From: Maninder Singh <maninder1.s@samsung.com>
To: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, akpm@linux-foundation.org
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Maninder Singh <maninder1.s@samsung.com>
Subject: [PATCH 1/1] kasan: remove unnecessary sync argument from
 start_report()
Date: Thu, 22 Jan 2026 09:45:56 +0530
Message-Id: <20260122041556.341868-1-maninder1.s@samsung.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
X-CMS-MailID: 20260122041606epcas5p4fb3f5c418b79bf19682e60022d7f1718
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
CMS-TYPE: 105P
X-CMS-RootMailID: 20260122041606epcas5p4fb3f5c418b79bf19682e60022d7f1718
References: <CGME20260122041606epcas5p4fb3f5c418b79bf19682e60022d7f1718@epcas5p4.samsung.com>
X-Original-Sender: maninder1.s@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=UP6ztmWt;       spf=pass
 (google.com: domain of maninder1.s@samsung.com designates 203.254.224.25 as
 permitted sender) smtp.mailfrom=maninder1.s@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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
X-Spamd-Result: default: False [0.89 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	MID_CONTAINS_FROM(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	DMARC_POLICY_SOFTFAIL(0.10)[samsung.com : SPF not aligned (relaxed), DKIM not aligned (relaxed),none];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDN6TT4BRQPRBCWJY3FQMGQEX4R6NHI];
	RCVD_TLS_LAST(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_TO(0.00)[gmail.com,google.com,arm.com,linux-foundation.org];
	DBL_BLOCKED_OPENRESOLVER(0.00)[samsung.com:mid,samsung.com:email,mail-qv1-xf38.google.com:helo,mail-qv1-xf38.google.com:rdns];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[maninder1.s@samsung.com,kasan-dev@googlegroups.com];
	FROM_HAS_DN(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	RCPT_COUNT_SEVEN(0.00)[10];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	RCVD_COUNT_SEVEN(0.00)[8]
X-Rspamd-Queue-Id: 1D5A161A5A
X-Rspamd-Action: no action

commit 7ce0ea19d50e ("kasan: switch kunit tests to console tracepoints")
removed use of sync variable, thus removing that extra argument also.

Signed-off-by: Maninder Singh <maninder1.s@samsung.com>
---
 mm/kasan/report.c | 8 ++++----
 1 file changed, 4 insertions(+), 4 deletions(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 62c01b4527eb..27efb78eb32d 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -203,7 +203,7 @@ static inline void fail_non_kasan_kunit_test(void) { }
 
 static DEFINE_RAW_SPINLOCK(report_lock);
 
-static void start_report(unsigned long *flags, bool sync)
+static void start_report(unsigned long *flags)
 {
 	fail_non_kasan_kunit_test();
 	/* Respect the /proc/sys/kernel/traceoff_on_warning interface. */
@@ -543,7 +543,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_ty
 	if (unlikely(!report_enabled()))
 		return;
 
-	start_report(&flags, true);
+	start_report(&flags);
 
 	__memset(&info, 0, sizeof(info));
 	info.type = type;
@@ -581,7 +581,7 @@ bool kasan_report(const void *addr, size_t size, bool is_write,
 		goto out;
 	}
 
-	start_report(&irq_flags, true);
+	start_report(&irq_flags);
 
 	__memset(&info, 0, sizeof(info));
 	info.type = KASAN_REPORT_ACCESS;
@@ -615,7 +615,7 @@ void kasan_report_async(void)
 	if (unlikely(!report_enabled()))
 		return;
 
-	start_report(&flags, false);
+	start_report(&flags);
 	pr_err("BUG: KASAN: invalid-access\n");
 	pr_err("Asynchronous fault: no details available\n");
 	pr_err("\n");
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260122041556.341868-1-maninder1.s%40samsung.com.
