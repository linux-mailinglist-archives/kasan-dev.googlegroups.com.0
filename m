Return-Path: <kasan-dev+bncBCJZRXGY5YJBBQEZ4KDQMGQE3HOEQXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 806963D18AF
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 23:08:17 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id np8-20020a17090b4c48b029017365ced08esf458792pjb.3
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Jul 2021 14:08:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626901696; cv=pass;
        d=google.com; s=arc-20160816;
        b=EBtcemgDTFoaApm6QRf2LHjI+3vSmFaCinRUnjSiYZvXoKfGo828JVcAHh3kJ1gUXN
         02C9PnMEYYhw+MYGGqkr0ariyOzzbSQZALSQp6qP0XYfRRBQ8Q8kLgm71wEFTDHx27CE
         fXE7wyN0727i1nsRj5PmX7XG4QCb+qUT4V+BhnrobRBu8NAhbaIOcsMqSneQyeklKOAk
         A4pasdbiI32t2ZDRUD7gYMdjmQaXeC5T0uxNtBcpcjDFWGgQ1shegRCC8Euh+ov4Relt
         c95aiR6746hrhKJy2K2l3JjrT0EwoHZ+XKfknYwejSp9dO2B04nKBWFSMZ6g0yztGDvH
         NC/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=lXSYitqy85hKOkhy9W7H7r4EqYDwbZ90q417GZ213Dg=;
        b=C6QYZ9/47IvHmr7wNw5aRJ705wsPyklm83bta89OhiV8teprS9vSXFlb85t5cTEkZv
         GGPjJx+81lbpHNJ/LEySMBYNxMhezFInBy7FQgtNgdsoBEw8hKJtqO/3YyglZYMhE9jl
         e27LHSUyvHAmnVCPtYkujFohGmSiMo8aVCyIjIkZFkbqcTTiEjN5cYEMUN3v2AvFr5DW
         eII+XcmgxJBonSDuH59mlqd4Y5BoDWbQjmQFE/PlmGwBsJR62QdEOq4lC1bJHo2vUj6+
         BNCDrOn5W32zD1fE2Y5T+uzwafkNh4+pID3Nlvh85vu8TlUGUa9M3bKVlr3kJj5e8zBB
         tkdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OUvN784F;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lXSYitqy85hKOkhy9W7H7r4EqYDwbZ90q417GZ213Dg=;
        b=AXI1D1MzVpiIYUenChJkCj9ZgWAt3GWO1UzA4FKnQ4lOrSzBEsWt8DWPexF7M2MNTi
         H43q4MijX9zypOz7AVXw9H0/ZO4qWuREBNL32ocydesayvbQ/hLBub47axNgUfAOy+vg
         M8yQuMQBlvkLNxcQsu8jU9dqbhmkxa0IIlggIaA4Xgt1+3N+uatup1WDBpjE/ofYyQS5
         xxIlyDpVOvq0TtWXYuWH0uiPi6brwRmxAqqPpUzPiGDgBlM4mYwo4gLdyUWpLkz6Solx
         C1ZM21cNp8VEH6gZtJMRoV4NHV5YZPvy5+fGc6DwMUyXtGz5X5kg/5X5nMVuTZTveN/j
         4+KA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lXSYitqy85hKOkhy9W7H7r4EqYDwbZ90q417GZ213Dg=;
        b=lZDOuqf6biLv16/mMll4whYL4DT3erKpnInLJkDvcuRInJQ6aMWoYRGr43c9K//5MO
         RfUbxuqQp5Ebsr7BHRCihuiuccg6AAU4e2tVXZbJJpCsNnvnD+MujufU76mTqyXP3lXt
         wmCE5IWIG6pGlVpBqu6QpzHjhBlj1nYf+eA77G31FSYCjZ2D4ptmXQNodzJzgzn9S2xi
         oDaCJ00rzyH5kylqjjJce0kaRRJbP4sMl/KCc5dl10ebGbtRC+QL4k3akOpmptNVoWzD
         hnO/3ZPmM9sn7vT6VjvWmV82zQQRA7T+XAwe644+4G57LrDxUsHQxaXcGZ8joEEjqMOW
         I+PQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530/6IGAL6AhrcTVfhTPp5yjh/AGKdnbCynw0DKj1vt1wEGwfnJ7
	5+AoiGFLzpjFQFnaptDzl40=
X-Google-Smtp-Source: ABdhPJyn9ozjvBMe5VazGB50vMCv3jt88JHfRlHjbcyuni17pHPKId7hv09w/+uJ7j8qq8BXIX8qJA==
X-Received: by 2002:a63:580c:: with SMTP id m12mr37956492pgb.157.1626901696205;
        Wed, 21 Jul 2021 14:08:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6487:: with SMTP id e7ls1881711pgv.7.gmail; Wed, 21 Jul
 2021 14:08:15 -0700 (PDT)
X-Received: by 2002:a62:1d84:0:b029:304:5af1:65f6 with SMTP id d126-20020a621d840000b02903045af165f6mr37683704pfd.80.1626901695660;
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626901695; cv=none;
        d=google.com; s=arc-20160816;
        b=yyFa22e1W4k8iAi/x1Pe/m+UGgsMEcj/16Ee+VqWzA6qrLIve8UUdKY4okaX4Yele1
         drFRaDS5fwjvHRXE87jS2xg50drEiGIEGAjC2nMd+hO3uva0j3npux8ro8n94P761zVi
         qIS729aNKeebt+C+Yiv1dkKAz16w6TBmAYIoTVuSYFyvqQnH9YYG/P7SE8hhvBK+08IO
         wJ8HDVK6WMrLBpmxyi/4u3aTX64pC8YGfl+qAYehDkhA4CEowySDxXRjivADjOcOv3eC
         tPwLG1WdYXwOdwHY0fPew8dW4kGcmnpe4oSCH5BwEv0Evq/I4kZ/njMGb3b7blpaqCY7
         N76A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=aWynijcMBs0SRBNGW3jGUkhZBJ4P43BHc43uVx0Gmkw=;
        b=oqOvZy8SWneUqLFpymV97AM/rLA3hPh0jK6cAq8dLqxCRg6ml+OFCQjEJNCbPl9HGY
         ZNbvR4JT5RRt/L+p41I4dATd9KrAso3eovR2lLW2/QxxXh0NdvGZneyRi4fR6oKBYozb
         Qwuom44Ccz/4qxOWOZTeVtwQhZNNYpngnaWnG8icP2oJkQtgJrSg+mPlbZZ9328d45pl
         eMhm1B0WaYTL9eVERcr1jQt3nvEIOZyJMZShd1A3oHU7+1NwKNIlwhVXgf/gx2eNvabG
         lb2/17g0mlKy+7bX2yYJnXb4UFQec0A93Delai2hQq1DftZTsDMyYUpt9KfCHH1XBW8u
         oxEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=OUvN784F;
       spf=pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 136si1058309pfz.2.2021.07.21.14.08.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 21 Jul 2021 14:08:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E65EB6141C;
	Wed, 21 Jul 2021 21:08:14 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 6C88C5C0C70; Wed, 21 Jul 2021 14:08:14 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
	Mark Rutland <mark.rutland@arm.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 6/8] kcsan: Print if strict or non-strict during init
Date: Wed, 21 Jul 2021 14:08:10 -0700
Message-Id: <20210721210812.844740-6-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
References: <20210721210726.GA828672@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=OUvN784F;       spf=pass
 (google.com: domain of srs0=6g4i=mn=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=6g4i=MN=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

Show a brief message if KCSAN is strict or non-strict, and if non-strict
also say that CONFIG_KCSAN_STRICT=y can be used to see all data races.

This is to hint to users of KCSAN who blindly use the default config
that their configuration might miss data races of interest.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 9 +++++++++
 1 file changed, 9 insertions(+)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 439edb9dcbb13..76e67d1e02d48 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -656,6 +656,15 @@ void __init kcsan_init(void)
 		pr_info("enabled early\n");
 		WRITE_ONCE(kcsan_enabled, true);
 	}
+
+	if (IS_ENABLED(CONFIG_KCSAN_REPORT_VALUE_CHANGE_ONLY) ||
+	    IS_ENABLED(CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC) ||
+	    IS_ENABLED(CONFIG_KCSAN_PERMISSIVE) ||
+	    IS_ENABLED(CONFIG_KCSAN_IGNORE_ATOMICS)) {
+		pr_warn("non-strict mode configured - use CONFIG_KCSAN_STRICT=y to see all data races\n");
+	} else {
+		pr_info("strict mode configured\n");
+	}
 }
 
 /* === Exported interface =================================================== */
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210721210812.844740-6-paulmck%40kernel.org.
