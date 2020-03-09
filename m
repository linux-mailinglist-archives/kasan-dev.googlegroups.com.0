Return-Path: <kasan-dev+bncBAABBOVGTLZQKGQE3MZ5EVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8191D17E7D3
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:28 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id c81sf3142453pfc.23
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780667; cv=pass;
        d=google.com; s=arc-20160816;
        b=WK43946RRGIRqf22wgrp7EfL17tK7kWMReZMuo/neqNwm1xCpShdTshbQkOfDvg8fq
         o3aHxQ7u7AnQUGWdICo0r3557XZb0lOhWokFKVrGb5OkPkQtM64MClWVkRV7aNPQGxD2
         EFPz2oJcQMhvylS/HZXUh7AIzQ8uCDgyf9pCnxf/vhlMsI8ZAcZ9g/K0f+KApslpnhgf
         xARJXbSNB+Qz1aR5j8rtF/BAxnXJupr7/dqa2GwCpSuGcawx2EWiL8d2EqqItJjrzQQy
         Gb4Ree5FHnVS2e+ZX+elfGFqy0nBAbTaCYMJlQGTDrfSV8fGq3/V329I644AguXlNtA5
         A6Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=cYTIN64yinBf9GK0bHZGmbT/0SrVecfFHeNcznJrf/4=;
        b=z7dbOrSiVEoxTbT8BGEeD+u4jHJclFdvu6pGNRfP9KbHcmmugs/OVL1SuHoa6xmK6d
         xdv0tRh4OHH4oqhUlUdqb12ran64FpldlsQqZfCtTDgQR9HVk4sdob4uXdbioC3Ltrbp
         yskSsZX80PzqGZW+UCMR1gDmq6NTWGKrJ9t6tte4/fV+mQXVviBstJaiQerVmdG8GGsU
         qqFZW3TiGjme8R78QrqVWeLDiEp4doDJxGXPcELOnp5IQEuVdX6sobwITjuKUesxO13N
         ustf6msvIKU54T/Fs+se9AWU29NWRWORwjgrOlxX23+WKz9izqy1vRHDc6/TwXLwYSj+
         aOiw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=eDlsutZ1;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cYTIN64yinBf9GK0bHZGmbT/0SrVecfFHeNcznJrf/4=;
        b=kEHiUI8oqISBwIlFeD4/3AnF1UoEKe8RNzHd+jAEu6CRqeQ6gTqoNuiaW3p0BiLT2z
         pz+GHYuyW8YDq0IX/PUbFbLwoM0KRy9ZlSrHVKwbTb7aDXd9VAHPSAS4AKda5OXW7ZSe
         07L4YNGJIPG+9G/AE2PFz8ipKu42S6zEuLi81/fUb/td4/dB530IN6L0izvA/wt6x0gn
         qGL+am58+d8h9qbv2VBJ3cRoYB6psBezmXJ2VmQWsI/Uk3l1lL0767oQos5MKWBL28UT
         NjhTO/tAwauSlMwgbcOewwTZ09v95nW8iiqFDkBIgZ5vlxOoT4fscFmloXsfPJgfmyvi
         Anmw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cYTIN64yinBf9GK0bHZGmbT/0SrVecfFHeNcznJrf/4=;
        b=g5Yk2oANDqfcb1RVZ6yCqiBRpTJFepAdzGcqvJ83bHiiybGVludsxSAGi9XitHWUDq
         etkGqJjvkc4xmI9GWKL5WP9dnrbJzZtWc+qpv0ede+9K9JJpW7AHIKA44pWe3Uu0Pnxw
         Jl3Ugu1iEMhjJ2SmtHGe74Dnea4rAfxEOHGIJ2vQG49hUV3osU9hSW4iPO+ELEIz23M0
         dVV3fHQMu6e4rOgARneBs9iBxWc314AvycWoDVIvSOE//ragdwC6d5BE4vkB5xEgm9oZ
         Zqdzaqd570EOj1eQ2JwsEqPvpW0ho8YoYFVY6sbk5mmGmfu5WcY87cQArgjv/bJS6t+X
         yKFQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2NMmWVAPFsPlbXeaekIfbGa0ejqeei+a0g306gLWlm6lc85SMk
	ZA/Y66y9WnjBfYZJVmrJQ9k=
X-Google-Smtp-Source: ADFU+vv2aboNCmLJK+rR3RzVhTSmksR0tXVWnCswIF8/Kn7kt0yOH9gtOawDrRIYgDrhN7vCckviLg==
X-Received: by 2002:a63:f311:: with SMTP id l17mr17849684pgh.142.1583780666324;
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:7744:: with SMTP id s65ls3939893pgc.3.gmail; Mon, 09 Mar
 2020 12:04:26 -0700 (PDT)
X-Received: by 2002:a65:640f:: with SMTP id a15mr7171968pgv.416.1583780665929;
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780665; cv=none;
        d=google.com; s=arc-20160816;
        b=Wrx54Rz5OQkrIMgOYZIHHMVG0XEC3RIsHBEwJR750xaVKUbsuKignn27rvkSg07yft
         aPrJP/XEN3S9ApTbXJfD3B83bcDT1B4ntkGCRGKaGPgxXs5PtbmRM6m04WrvThtS+TRE
         kAKs5+l0JDO08Is8b0CzTqIRMsHCjHuYLWBzlmmSKadut1v+JTawYmcxKw973E7wg1KH
         Vlq0C/9vSjcWQaguno6LDGTFbRuHbhVRXZrhJ/4VW7+PILztqCt74yW5pVMrCXBEn/Pb
         OqTWifecSam52gsICjDbaS8HccV3N5wakVXyHOXgxhBZ105XeaOt4XTFwbGVS8/vFygO
         gHVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=F9h/orVBALQlahIgI3JMj67dOTR/JZFqUV4PLWbBEw8=;
        b=KH71KGwkOIJhj4BeKR97cxzA+QCUrZLu6uUO5QgHdrViAMhxOrRitRDOjfbDPYdMsV
         ePNLFutplzHyOR97DpV36VtvH66XlkFOMbCGpA17OffhlCGZCj6+D2y6tjiTgYnuMQkE
         c0a9OrvrrNrtF8hq6lQP1k+BgQP9gGzhBFGB1WMWGsJOOddvkNApqYazEYBa64I9Td1o
         +g7GVepHxOkiqtP9PM0dwhjMvZ6EkrWPURmbEZHOkJBRZCbcTYe3ntn4NRxVFsvoUu0a
         CK/3PBa+gsqG8xIFmYnTBBDcahZlJfDRitThSXGKfVra7ST8e7Dc+5pJ1T2BaJLm54hq
         mNnQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=eDlsutZ1;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y3si629793plr.1.2020.03.09.12.04.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 90F122465D;
	Mon,  9 Mar 2020 19:04:25 +0000 (UTC)
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
Subject: [PATCH kcsan 14/32] kcsan: Cleanup of main KCSAN Kconfig option
Date: Mon,  9 Mar 2020 12:04:02 -0700
Message-Id: <20200309190420.6100-14-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=eDlsutZ1;       spf=pass
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

This patch cleans up the rules of the 'KCSAN' Kconfig option by:
  1. implicitly selecting 'STACKTRACE' instead of depending on it;
  2. depending on DEBUG_KERNEL, to avoid accidentally turning KCSAN on if
     the kernel is not meant to be a debug kernel;
  3. updating the short and long summaries.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 lib/Kconfig.kcsan | 13 ++++++++-----
 1 file changed, 8 insertions(+), 5 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 020ac63..9785bbf 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -4,12 +4,15 @@ config HAVE_ARCH_KCSAN
 	bool
 
 menuconfig KCSAN
-	bool "KCSAN: watchpoint-based dynamic data race detector"
-	depends on HAVE_ARCH_KCSAN && !KASAN && STACKTRACE
+	bool "KCSAN: dynamic data race detector"
+	depends on HAVE_ARCH_KCSAN && DEBUG_KERNEL && !KASAN
+	select STACKTRACE
 	help
-	  Kernel Concurrency Sanitizer is a dynamic data race detector, which
-	  uses a watchpoint-based sampling approach to detect races. See
-	  <file:Documentation/dev-tools/kcsan.rst> for more details.
+	  The Kernel Concurrency Sanitizer (KCSAN) is a dynamic data race
+	  detector, which relies on compile-time instrumentation, and uses a
+	  watchpoint-based sampling approach to detect data races.
+
+	  See <file:Documentation/dev-tools/kcsan.rst> for more details.
 
 if KCSAN
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-14-paulmck%40kernel.org.
