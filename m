Return-Path: <kasan-dev+bncBAABBO5GTLZQKGQE2UXRZTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 297B017E7D2
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:28 +0100 (CET)
Received: by mail-yw1-xc3b.google.com with SMTP id g188sf5726862ywf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780667; cv=pass;
        d=google.com; s=arc-20160816;
        b=XkgGKyO22eUZPC88MkTN9C0cde2KIGOFx35fvnz2n8LGuaev4uemJpfZVRBhGQSQJ2
         wUBOcdJMuz38ieVez0ElNnA5z0LJB4isFzje8DFEE3Me3YBWdclDvs382o+ZrJ7Pn2py
         FT1KOIlQdsIFjp9mS2H32lV6ZcWbGdrwqmit0mWZOpBLoeHgVCl3mJXfTxGixXqFFQcG
         sLNetU/76qKob5jaWUilZjIMGKdTQBQ6t/7VtEZlCA+Kt0MiY8r1kUszyRVGvroNWI16
         V83iSsUZ+/oLWZZPHQS67gwXXq3sPmAQhl+Jf61rhLTPqNpGVzgLIoCO0TLK2+UTsvlG
         eaXA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=fXjt/Z+u5ESF4y08q1pVPcOgecCAfZuMwcOfbo4gL4A=;
        b=s27vEfQLGh4U/9gVv8YUNTXfc0pRYnQjNiwD2wUGfhRSdFJX9wF16HWaMEKB6Kn4Xc
         NPs1hUo8DzFfk7RYPmPcAaGOtav4JHQ1q4XDgdgvqxtYjLit6+9d/6vz62MBjkGTP4Pb
         qu8dkWNZ7H6AqqNG3svLAfEHnFKiwe4YybnazTkBvLHIywbB6zolZMoj02FV0Gkh54hE
         gU9nnf4zjHBBZe8N9pQMPWhwLBxvisJGWLGgr9etTinXWiDLBaruVCGsZJiUjyKgkJFU
         /Kw1Yhxkw0KDwiWKFXwJYCMd7q0u85gaDpnSWq3L434VUu9fI7uSOVPMIuHvXuytPnR6
         i6Jw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ou5GJgW0;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fXjt/Z+u5ESF4y08q1pVPcOgecCAfZuMwcOfbo4gL4A=;
        b=jaBEy1l6LNOerH/hzuccTb7t/ZjXdF7/HTl8EpLzdyNUIf7uf0mCjZbXGRI+4/NbRt
         V/srjS6Mb369qsVmclmHArJDjEQf6OmhwDicnn6f9XVaPplxBEGvVYW7OWOENuTjU0Im
         NOZNDCkqc4Re9aBKUgdm7xKu4fKM4QQwBEvet7GTHqFUrBTy/6d2UfnT8vo5gA2DOa4q
         gbQVVkLwQHkG7rUQUPQuXQwm3rW44oma7fq2Iyi+ZD/l0dWWLY3DOS6yo7Pg1k+ruBc4
         n/2mqzfIo+BV/GXpgq6V/wKkaMsSVzEwUsfDN03zrGgufEshRNP12sRjP6nNUJsNTUHt
         uU/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fXjt/Z+u5ESF4y08q1pVPcOgecCAfZuMwcOfbo4gL4A=;
        b=GH+EbSfNRRdVeruxnOkRrBHZLbusbFCzmHOyOVpj3QCODjUataIVr2cgmqeYQPY69T
         kA64/J0nqA/8XRJAVbVv+9dF4zealQ+Gc//e+6k+zbLzTNNCRozfvGgUVImsObXgxgb5
         7A/fGX2/bhiwvSwBrKu1RVwNYCmUTAz6Q0wh3XewndXcDEFC+LsYM9e9F6oLSG49rq1K
         aM3PXtBc77qRHUyUXUA/o7hD59P+pV+qBN+piJn66wTAlCsaNRNgqdYSRcSFy+/uI2Aq
         5A6DwMvglm/e6RxOx2QyHsMU3P9DeNGSJ7JvzGvN/6Fnd2o9LSP2Yk6f0aVOE68RVKda
         9Kig==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ1SdWlEj+bdTMfC4VTmstI4kxvWemvfZRKgf+dwEF3YePLYxZkR
	9FJ0+2fBzX87BVj375Uuu6g=
X-Google-Smtp-Source: ADFU+vuRNv0WIvtOI/ftzKlcIwZO0GtZEK5BD+CPQKr8wSbS7pUMxaa9a43kbiO2SZL2jT8A8VAMhg==
X-Received: by 2002:a25:dac9:: with SMTP id n192mr957701ybf.285.1583780667148;
        Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ca87:: with SMTP id a129ls2943324ybg.6.gmail; Mon, 09
 Mar 2020 12:04:26 -0700 (PDT)
X-Received: by 2002:a25:e812:: with SMTP id k18mr19388993ybd.93.1583780666770;
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780666; cv=none;
        d=google.com; s=arc-20160816;
        b=IsdDT/a2BfUZ66DpslUKWuKCBjSSHvbwb/gHHuO+5CTnOtSKhj5hSHjx21EzLmwekT
         t8wrPE4/6rSQ+rTGSF4cJ3xx9j4w2r/BVDZza/fa0DsEX5HlYec3D0J3nlVnp4I3akNl
         3uvp/nE7C1ruLgRZ2aVeff7K2Jyzzg7ofaifaL7HV3foPyNN4SSMwDERDbh+Nt2UlfHI
         p/6lCetU1EwBKSJIEszK1XgaR/3dW7dkO24H7HZfDhpXvXHXSZ4kgm1LLT5mdyGe74JE
         vP8O++UQTP1ta9yYzWOw/aVYksDoQfRJYcXPfeqREqE6EEnxEkYaD3MCPKZSLPTG86ZI
         zrtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=iTBirUbRM2fpi6ZrkpyYsTtPtCRdflYdovd3S/OOiBM=;
        b=VRzpAQcFgd5jGRYKO42QYcti6TQc2KaXa74l5WzshuzHtkh0ieZYnpemsyWYShqdvZ
         rDe1kIDzXrrAJzBpCggGqTkTX46gGD1ce4FV1zL0R8eCDjh1amZl1wEuaWjqodsGsmcK
         ST7/UK8fmWcshjrWnFflk8x1jQcQrmG7qmqil4Gmohn+VscxdO9dpSjKWlsC89AEKMhK
         EzhAHTFs/QUar0TiETo+WhHKa4A5xYDvvvN3bJLE3GKspV7UemoTOe1VSq00UUYFiFwW
         +db/sSwdfTkA9qQ5j1sBonO74lX2fqa/cBZRBBiKkTgKsOt5bYl7fSP7IcA23rinGMTK
         OYig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ou5GJgW0;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y19si740181yby.1.2020.03.09.12.04.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id CDDCA2253D;
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
Subject: [PATCH kcsan 15/32] kcsan: Fix 0-sized checks
Date: Mon,  9 Mar 2020 12:04:03 -0700
Message-Id: <20200309190420.6100-15-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ou5GJgW0;       spf=pass
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

Instrumentation of arbitrary memory-copy functions, such as user-copies,
may be called with size of 0, which could lead to false positives.

To avoid this, add a comparison in check_access() for size==0, which
will be optimized out for constant sized instrumentation
(__tsan_{read,write}N), and therefore not affect the common-case
fast-path.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c |  7 +++++++
 kernel/kcsan/test.c | 10 ++++++++++
 2 files changed, 17 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index e3c7d8f..82c2bef 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -456,6 +456,13 @@ static __always_inline void check_access(const volatile void *ptr, size_t size,
 	long encoded_watchpoint;
 
 	/*
+	 * Do nothing for 0 sized check; this comparison will be optimized out
+	 * for constant sized instrumentation (__tsan_{read,write}N).
+	 */
+	if (unlikely(size == 0))
+		return;
+
+	/*
 	 * Avoid user_access_save in fast-path: find_watchpoint is safe without
 	 * user_access_save, as the address that ptr points to is only used to
 	 * check if a watchpoint exists; ptr is never dereferenced.
diff --git a/kernel/kcsan/test.c b/kernel/kcsan/test.c
index cc60002..d26a052 100644
--- a/kernel/kcsan/test.c
+++ b/kernel/kcsan/test.c
@@ -92,6 +92,16 @@ static bool test_matching_access(void)
 		return false;
 	if (WARN_ON(matching_access(9, 1, 10, 1)))
 		return false;
+
+	/*
+	 * An access of size 0 could match another access, as demonstrated here.
+	 * Rather than add more comparisons to 'matching_access()', which would
+	 * end up in the fast-path for *all* checks, check_access() simply
+	 * returns for all accesses of size 0.
+	 */
+	if (WARN_ON(!matching_access(8, 8, 12, 0)))
+		return false;
+
 	return true;
 }
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-15-paulmck%40kernel.org.
