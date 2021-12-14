Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7NJ4SGQMGQELIIP4WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 58E4E474D8B
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-oi1-x239.google.com with SMTP id i82-20020acab855000000b002bcea082cf7sf13334708oif.22
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=nTPjDnkBrHam3DxBDDqdnl6L1QvOi7+8dSMXr888sXzC70wzvHNUF1W00fr8uTJGzh
         6boWXq9HTsNlh3M2EJ1FIGckLLLsQH+TC56KRxmasLSzXRLZ3wS3M9CYdOkCMrixZzgm
         dGai3nj9Ada8wPjB4NgTE8y7RQjqFnCp7HUqG8jfHqPt3Y/WaXJaHr5w7AdIkKjVjBll
         ++7rxi1VZJzlgjh00Qs2vicZazRET2CCU7nsdZvVIEokSwMHz3Uw/PJuO+rMFlc1ibSa
         YLM6/kYh5JCxAbyAP8vlf+yHuzcs53SDnYGPfAPxj+3fBjf3B5zmCXKGAH/nZZYMFptO
         Vjeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Eib7RcyK/snS1thmB68lhHZIlbDr/MfMI4XQSB66ndI=;
        b=WCiw1txaqvkPQqVRKwyU5/YOkVcnf5QyWv1jCHYZ7Tc9NUgENnOpvWDQwaSKqT2aL7
         zwbZLQQbQTqRVe6dJFdfVe7IPtFzhOkhVPPRLQ2eANlov4lH+QfuOL0fmttAX8FJNMUq
         NYpEJUHLptClqQu524SGTwwLl0bqQ7gBTc5uLd2j1hnjxjsSyZcVhCNthwbw4O72P8Kg
         1NNUNyKejx+MycnT8/poYjuI4PT708N1toZrn1AP08FwbWpV/gF4b8D+mqhDe0Ps8Nx6
         DSJQxOkQUWR2KOigL1TSJJLQ9ap6KxvttjZyglW2ps1j9bGwrTssetK5Et0u5fa2b0Sy
         ft8w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EWYhAJOB;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Eib7RcyK/snS1thmB68lhHZIlbDr/MfMI4XQSB66ndI=;
        b=cAIGebefJdH2TlvGbnrCLRZ0SP2BaC+cuxoD0IhOHm5utzEZe2ozJs7iHY3VlOlhD3
         zUlbSJm+MC0bCdIvDdG74jPrN21AcvKt6Ep+AydKu72l0yK/iFsvNYPLTg+izNWA71jt
         vPus71FOyB5p2mSNWMIDs40Utm8U/wCAXTQ8wZQnpSekql4bkA8tl9eU+jSqGqLR+iLw
         CAftmz18iOc27DD2WXwpCX+EouNyAmOoOxrA53vs2IACCCHCUHVEAa/Ee1ZsqFlRtNsi
         lS+DpJdnMvHK0LmDck71hCrg6hcQlUS05eRkUJx3HaOTQ3mFP2julecdnpUSiI+it1hM
         E3Mw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Eib7RcyK/snS1thmB68lhHZIlbDr/MfMI4XQSB66ndI=;
        b=rxk6GlsWSzgGGriKg02/mzMhUc1AAeIcUq98f2NUgSWwCweJu7ernObmCzAzV9MhkD
         anekPx1OFlnmXC5ksToqp6yAS3d5kFhwhkP2lpVEHNc458bXAPW7ZPcMQPmzUdjRIbgG
         88WmFZSYylByhTJ/hf7kavQR+P+yAOCziO3AjXs9PJfMzQEuhWbBWGxDfLdAWvVCLHqp
         L91tm+hLbHlImY06FjgeFlPwV/CHZQZN4QK2cgOu++wj1Z1zzZ7PNczshSzTqq0JqNEE
         c8yc4gJrQLekOXqhixKWQYDj14VqQbMraS+PxG4tn0ppTiHV44AWlJ37tdQrK/uRFPAp
         pg6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZIjXvG+2zK507cFoKWI1IJOyCVfNKkg7dFtaqAxkfNdnnejTV
	Zo+Owe9kWVu0dcNJ3YjcTG0=
X-Google-Smtp-Source: ABdhPJwPXroaeXDKSqfnALvG4MyWABtgiyWA62HJpCKgxiBD8LXWI6chXsnes/kISzq8FT7BXOAwLQ==
X-Received: by 2002:a4a:430b:: with SMTP id k11mr1051815ooj.69.1639519486029;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:457:: with SMTP id 81ls36946otc.5.gmail; Tue, 14 Dec
 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a9d:805:: with SMTP id 5mr6317677oty.383.1639519485636;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=DXZvqNn5cotUiEBmDMptHYDkMq6J+1JJovFtDukd/u1Zkh1KfaD1laFbqoBE9Vzk1e
         fCrYmyCfFKH1yt3Tc3xQ+1vmekSga1nMwyfO20P73bPOOgQrErk4X84h9j+RHY41NN/Y
         BeEyjhW9HIyAojZScmv2HpmZoBlkJpzwBKyUlhKBRDbwjes8emnvnLISzdUnc/3NY472
         yuY7HwBgzjA1MPrq9wY1Aylg4fH9F8IF/o4FNTQOUFlwy9nNUkPHjHMq0oCJvlrbkUZn
         AFuofHsRQ1dnMBuuR77ylUN41OgaIrLMbzQ2CrmlL4NgqWjPAorJQyo8ctG1OkhdO69d
         x03g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=7yvwNq4zGQn44aROTVogWtpSRGmYJc1zCuHqgw7k4XI=;
        b=LqzFYfVSFgd+kiNTAsoEzI+vR6Fxym6JWMopbSTPtgseHwqIOiON5M9raQ3sh9twEU
         GC53jW6SjDkfZ9eZ71joHlyKaC2Q/hIwjuGGcfTKKX5AWpZg11Q42V+F8S5SXsx2nXVt
         1oRumTW0bnHawYzlXnAbUarCKGyAT4kNJoFQOTLyha5BtIDFw9SbBz3qh4r3Xlplpbia
         LaadSSi0WRgCmWjm4lquGNZqhLY3mLnOJA+jGA4DV02EUOx1MKLobcOfiSbH50gle372
         sRi3I8vp+ZjoYX5NiCOe6r+DzGnQN2K0CSZ2pt6p/OmR8nl0+PhTcY/BHAGc9GAeEbbw
         IgSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=EWYhAJOB;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id e30si4950ote.0.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id 6BC7DCE1AE2;
	Tue, 14 Dec 2021 22:04:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 98898C34600;
	Tue, 14 Dec 2021 22:04:41 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 5C1485C0556; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
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
Subject: [PATCH kcsan 02/29] kcsan: Remove redundant zero-initialization of globals
Date: Tue, 14 Dec 2021 14:04:12 -0800
Message-Id: <20211214220439.2236564-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=EWYhAJOB;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

They are implicitly zero-initialized, remove explicit initialization.
It keeps the upcoming additions to kcsan_ctx consistent with the rest.

No functional change intended.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 init/init_task.c    | 5 -----
 kernel/kcsan/core.c | 5 -----
 2 files changed, 10 deletions(-)

diff --git a/init/init_task.c b/init/init_task.c
index 2d024066e27bd..73cc8f03511a3 100644
--- a/init/init_task.c
+++ b/init/init_task.c
@@ -182,11 +182,6 @@ struct task_struct init_task
 #endif
 #ifdef CONFIG_KCSAN
 	.kcsan_ctx = {
-		.disable_count		= 0,
-		.atomic_next		= 0,
-		.atomic_nest_count	= 0,
-		.in_flat_atomic		= false,
-		.access_mask		= 0,
 		.scoped_accesses	= {LIST_POISON1, NULL},
 	},
 #endif
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index 6bfd3040f46be..e34a1710b7bcc 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -44,11 +44,6 @@ bool kcsan_enabled;
 
 /* Per-CPU kcsan_ctx for interrupts */
 static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
-	.disable_count		= 0,
-	.atomic_next		= 0,
-	.atomic_nest_count	= 0,
-	.in_flat_atomic		= false,
-	.access_mask		= 0,
 	.scoped_accesses	= {LIST_POISON1, NULL},
 };
 
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-2-paulmck%40kernel.org.
