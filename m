Return-Path: <kasan-dev+bncBAABBL7NSH6QKGQEIY4B5PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id A98D32A897E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 23:03:29 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id x23sf1399134ooq.1
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 14:03:29 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604613808; cv=pass;
        d=google.com; s=arc-20160816;
        b=sXSQVmhGGi6SgNsIwM9vfQnNFnv+hHmOKVAcOlxJolvlZF4i0slsv7/EsHjWsc6e7v
         pVecrZyEu0W6RI3t7CQf6iTjLW3jtIsxX3zMBEsrTNBCXKnVy6xXfrSQxtmK+F6Usf4Z
         kzu5i0nuPVycGL+WdhubfCXazoJKIo5OZZ/iqGq1rTgaxBxQMM5dTkv/hSUb/OrFRe0I
         H6QCS1D8jeuQP2qOXN8PkWkArk6LhqT7q1lcRI3rNCDYWhv/+v1L0ohRe19U/9GeqwG3
         e/VnU6kwldECcTKl1INGAyBd0GtE8MQJS28MEEccYKuA6q36xM9n0Or+RpTg5//2K1aa
         Xpbg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=TuLRyltqTCoQiK9PPEJBupNlbgMS7RxNXrGoMeNd+NA=;
        b=UEEmwbK9X+TssAimUbrTquUgmKySruYO5JqsBnXVSNrXZreFDgJumnXP1tLI2YyE5b
         zioOnMaWM54yh5k0povs66oYMiiOD1sIOI8PEXmFE58skaLejl0kpHYfKJLRc/dzLqeD
         EvIKRpwFd3bEOgfJqnddHmEJpdXjKw+R89S4QLB5Jbpr2p19YFdFUssUDXkuQK/muuv3
         bM0lU7oIw3+WWMF7w76tdgHoNf276nFGk+cfiMw+HSDt8uxTqsW/jOl3F4V1fO2+FyF7
         QJh4j7xX1s7Psy0ODJECvOJafq3jZG4mKcz1pduMbCfODMbDi4DGvC9p3arX9adZPboO
         jL4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ztmRX1Ph;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TuLRyltqTCoQiK9PPEJBupNlbgMS7RxNXrGoMeNd+NA=;
        b=LY6j1852AuI9omkZLZvTO4OVAQQCYAa4TIIrNVlrwPAStOq46psQJTiuEOa1zw0JoX
         H2jpeJmEY2UjQjLdtfeIXgDk8lkQzeAcYZo/inXXBG7Jg0BgjiQsEXFDgoPcEzozCpQj
         qnYK4I2AAuPaGYPnF6FAWm0uGingBgNO72Tnv1Og1GduaEZc6AeXX+KQMgJELZLbf/UZ
         Vc56ChRlhJ9vmBVwBJjipW3e1MLhVpsTXiIRBhp4wYPvjgHe7Qxy6FuAaE4A8A07SGOY
         JqwSaDNKmy+cN58NlGGSPrY4Ln16Ez4hJ/CheRSrUyBBACO2Z+PpBlD0xSIEX5vDyvt7
         Lsfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TuLRyltqTCoQiK9PPEJBupNlbgMS7RxNXrGoMeNd+NA=;
        b=nQIaDQgbGbmPssJPa27/UCVaSzDyKrsC+8f4YVPwJlXRhkV2E0nhyTlwJFVtcdR5Hd
         GpIggelqIFHfadM+QMHA/WAFT+Q8ana5xqH/1DSA4Dpe6PSvX1h8qHBDzerx4ZbNZkp8
         z3xnjx1zo2mJ2eOm8eXeAPxCf2IGcjQZrS6nQ2Cc9wqJlPD91NCFaNpe1S/AlA3YUd93
         XWsOyFtsDRb9tK7xiaxUgbPPfJt39kIN+gkYZgaRPJB9eyoikKl0Yx/iqlVatCcMI7oA
         pptSeqtP1rxJY3N0yWK9ghjzkNkHJOPl75CB/hcCUNzaO1fCPATaKQcb1Tb+Yqhl9Lx3
         OfYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533n6SJGe1Uwvt2Fgjw7EvPw6FuNkLcN1MhiY5rkt93XkLTD3vTv
	yLhtSEylhoyphiExyYoqR7s=
X-Google-Smtp-Source: ABdhPJy0+Of9gs48v/MTHqgK9tAR+PrZzGxtGKblIkjjzPi5PNp5NHbBtZTYMmu4LiZ+yr6YVF9WRA==
X-Received: by 2002:a9d:5b1:: with SMTP id 46mr2952961otd.276.1604613807163;
        Thu, 05 Nov 2020 14:03:27 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:6c48:: with SMTP id g8ls793606otq.8.gmail; Thu, 05 Nov
 2020 14:03:26 -0800 (PST)
X-Received: by 2002:a9d:5543:: with SMTP id h3mr3092609oti.241.1604613806400;
        Thu, 05 Nov 2020 14:03:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604613806; cv=none;
        d=google.com; s=arc-20160816;
        b=VRFQWJYaNQM5XDL2Pd4saDPPIZGfZaSAmcSaGaVp6fZH2bpzgoLep6dzOgUQ+q+3b7
         86e4VhPFYYjsZttdHIC3b1bMWEcRm2n8E+2jo6csib+PPy4YIV6onamvDqRjFZL6P+lW
         m0/qoUrtrQr/r8XADpUY/bDMUnJUnr11hb8gjn0dNqzBtJUhQaz+DcDnpnJ+12EXmsGl
         Bk/+IT9kMNdbzpsI28R9MC6727DN+4Nq5spI97hArGgIZ/TbgtvTQlK5uj9/04y8xUs1
         eD+18C4fbG5toadFdl78xwMee17jYTz3BDMw3+fwdiCwzFQiugE2Gw68v1d+xm9RNAYF
         g1lA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=NpTrVAaJNTJ86VpfcHc4IkZdS3FrlhuPnYjUt994fC0=;
        b=Q9lLrFqzAv8WHAiAheW+sEzdSo7ZXB4EyvYSRqGCWlFPg2dtyhcHs3k54qT00elz8j
         00ungD7R46BiAoJgaPabBvRNbw0TulCWtY325fZeJ3fl6cL708CGFVwXOmcD5HYRiHnQ
         gX71XDt9zv82BPGi7Snr2Qw6PdNFESp2nBR2QRDw9iyhVzcpIdmtX6Hj1P5cuS50YoWK
         bgz3eB2ivzgMv2yqJKuy0darjMmNCrdztQzWRaRfOXTavKA5sE8A5wjwtzDbzPZSE7eC
         ZwP6YeI+SnKvWPpdvaSwggRNP+j8iUQJhlDfO+hdvdGfV+k1Zop/56o0DBV7mELgGwIp
         W0Ww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ztmRX1Ph;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id i23si367531otk.5.2020.11.05.14.03.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 14:03:26 -0800 (PST)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-104-11.bvtn.or.frontiernet.net [50.39.104.11])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 44E202078E;
	Thu,  5 Nov 2020 22:03:25 +0000 (UTC)
From: paulmck@kernel.org
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 1/3] kcsan: selftest: Ensure that address is at least PAGE_SIZE
Date: Thu,  5 Nov 2020 14:03:22 -0800
Message-Id: <20201105220324.15808-1-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20201105220302.GA15733@paulmck-ThinkPad-P72>
References: <20201105220302.GA15733@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ztmRX1Ph;       spf=pass
 (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=paulmck@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

In preparation of supporting only addresses not within the NULL page,
change the selftest to never use addresses that are less than PAGE_SIZE.

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/selftest.c | 3 +++
 1 file changed, 3 insertions(+)

diff --git a/kernel/kcsan/selftest.c b/kernel/kcsan/selftest.c
index d98bc20..9014a3a 100644
--- a/kernel/kcsan/selftest.c
+++ b/kernel/kcsan/selftest.c
@@ -33,6 +33,9 @@ static bool test_encode_decode(void)
 		unsigned long addr;
 
 		prandom_bytes(&addr, sizeof(addr));
+		if (addr < PAGE_SIZE)
+			addr = PAGE_SIZE;
+
 		if (WARN_ON(!check_encodable(addr, size)))
 			return false;
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105220324.15808-1-paulmck%40kernel.org.
