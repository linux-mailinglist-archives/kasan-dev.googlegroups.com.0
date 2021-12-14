Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A6E1474D82
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:46 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id m17-20020aa7d351000000b003e7c0bc8523sf18264557edr.1
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=F66qAmxnclF4I1XHvI9ohsUIEVfMrvZr5JGSxQGSXrWzI8mmH0HQ9xY8livHPsVcKI
         wTfQD9R3cueba5gA0m457E5edekQwJu301RPTuMMS5VVusAHrO5fuy9Z+fmWJVATGIOL
         h+bW3vecNB44BM7aeppd5S8ZtsoxY+EQWikSB2/RaiNUMAQwHkro3x6aHsx9q/4U+Jkb
         2yn5tMHj/b2RYOfvsMRDEOV8pl6rEgZECawKsC+J3iWNviYLezIHlIzy7w7vSAmFlOgw
         3DKEycTKA8nbDx3sXi2Uiw1JYj7AdUaAAvtJsirupvsjpOlbVzWWf4g6N+ATI86HgOpY
         EFDA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2C+kiaA1rc8pOFe2L7ORH7Qc/tJRtHjcbu9hwv03aOs=;
        b=SUl99eIxEyVV3xoC6WZzdWE1+G/+mugDSK4uD+zzPqFoQ0+v5i4GMHA3fkUqI8eZUC
         g0+jpzM7WpeVv5rLPdoxWRv6t2+u8oRgbhXD4Qtf+p5V3lDVqgBNmG/uipoIKvNhx7Qq
         PP+upgcI8RG5rDqzvEzrE+Amf9wd3uuZfjjMNKvqyMqgt4yc/sHKchpguuLQkeAHsg0/
         SgKL110UaJ4P2IGJxtDxfbLkbaHJ2SVyRrOSv3KuJ73vo5osJUOPge6a2gVTutKz3yVd
         58N7x4IYFb7bWYSY4c4rJ6eMYWcKAe3vwTUxbAyVjMYXKe0e9Iz/fgkr9Q+W0U8opX32
         sxLg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nnfGd9Nj;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2C+kiaA1rc8pOFe2L7ORH7Qc/tJRtHjcbu9hwv03aOs=;
        b=WBjdHp7WvB/pifwq49cInX6aWjI7EdYXYOHXeNzT5uX5uno9rQhtMlNZB52yTyc5cb
         VutFX2H8x34K2Tn7CbaL41RjA/k25ND6YZxysALEal+VEBJlHCJrQZGLo/Tphhv13g9m
         q47iRt1J7f5t9023EtNoFSY/tdw9MtaaNHy7NxFpPGA4o9BLxyHba3fKdCsn1Z0sWJ4+
         pd4B1LF06H0rWaJCVyrWDclR9WLsroJmDZvfZvZJiCgqfopkjZhEbxfE25+k8w0/u5OI
         rXgOtziPD9Uyy2U+3yKKfni6z5iyG8mSsLG0ER01OKPqrSqYNjZt9Bbmz5KDzoBdP+7s
         qtBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2C+kiaA1rc8pOFe2L7ORH7Qc/tJRtHjcbu9hwv03aOs=;
        b=7wMfFAGIJzBwDgPGP5HGpjmoxBkf5BYN8OytQVLGlyuyGSKAg5tLIvoBozf9j9luL8
         QM0GOHrzztuKzZqWq6jFaAKmIjYRWlBvouy44POpN9mbPf5nLIO+qd/eQEXqdHUomLVX
         6cYCQyfaPuF0It/q23K9e0ZvjMRKutzSq6FdGiznsj4gu2gmaeE1+71k0pNWfXS5Tiry
         LUXQX6le8vxknUQB+vB1z/i9RkvuovCu9k4uy10tuFjHfNr4Jp5hE7V8fUt5srWjROz7
         l6NxmJg+MRje7KBqbW5OMP1ND+GBelH96xODgVB6xTR7+6hxKJ03kQP2bed51DyDVPx6
         2ayw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531XaLq8lND/yR+KDCJX7GH7OkOJJtFy585yBMUqC/x0Q/uqAWBz
	WyJ30zDI07Z9kKOtRt7chqc=
X-Google-Smtp-Source: ABdhPJxTqReMP2Ru/3wq3y9B3eBp4DO3jq2cQJf0OQcVC+wZOURndUVK8aeWI1d47vbS8Rj7v2Xkfg==
X-Received: by 2002:a17:906:fac1:: with SMTP id lu1mr8324068ejb.171.1639519486360;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:d2c3:: with SMTP id k3ls43114edr.2.gmail; Tue, 14 Dec
 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a05:6402:195:: with SMTP id r21mr11451177edv.174.1639519485329;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=MUFeksmxP/Z8KBbFPb9SauSLnqqBBxJLTheIPs4w58frja10Me6lOcDcc7wDsl7UOy
         gPHG2UvB/oXISV7sPipiTHphfJw9MYNau2OXCZMXtdYadUR4wm0EoTYCuH+vhjCpxRNP
         xBv9dC8Kg+LWBgOyXk0+uXJ4v5FKtVe/fnR6RqBT9IMpVhtBvgqpbR+VbqPLKrrptEyp
         AxQmoNdAHf70aMdRvvaaCs0ZokMzqgH456JDvjn3WQeciW+zhJIZKzvt1kITMIE0uFJM
         n93PwCb2VtsIxSpmSsQWWilghIHVwBicReNuaKH/lj9HPpSdp4W7iFRQ/MEkaHTAFFoc
         CBDA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=DQMn6r5BVD9YmJTDi96xnogVvDRL3ucOGznON7FTapk=;
        b=xGjCPtik07SxCtOTJDsbOw+JrfSgg2ge4Ir0WE1uaqaMnpy3tQjzLtnzCl/Di50xVX
         s0/RkeA85A6MafDEyustY7/j6K+Qi9iesT14r+JXmQFw0tN5YWg7npdzx+i3F43AWIeN
         0/V3+V1AXDIFFWxzQKLFdPFxd9CxdN2cSG2NNPtb36sKuGCvOSl4NKSuC4i8oTSI20dU
         aIyYH9hLp3nliUOG0PltthmoMky4hrW04FODjH5onZxRrrAHD589ilhp93uFRv9Nnpsu
         OOd3QLH9ySKFk9vRsEdHzZ86tRynjqCDzDEHPE86fMO7QoliKzjQ8pqKDdhdxoZFZfAU
         ndwA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=nnfGd9Nj;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id bs25si2734ejb.2.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 3C98761759;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3386DC3462D;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 849335C1E8A; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 22/29] objtool, kcsan: Add memory barrier instrumentation to whitelist
Date: Tue, 14 Dec 2021 14:04:32 -0800
Message-Id: <20211214220439.2236564-22-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=nnfGd9Nj;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Adds KCSAN's memory barrier instrumentation to objtool's uaccess
whitelist.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 tools/objtool/check.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index 21735829b860c..61dfb66b30b64 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -849,6 +849,10 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store16_noabort",
 	/* KCSAN */
 	"__kcsan_check_access",
+	"__kcsan_mb",
+	"__kcsan_wmb",
+	"__kcsan_rmb",
+	"__kcsan_release",
 	"kcsan_found_watchpoint",
 	"kcsan_setup_watchpoint",
 	"kcsan_check_scoped_accesses",
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-22-paulmck%40kernel.org.
