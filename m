Return-Path: <kasan-dev+bncBAABBJ5H3X2AKGQEQ7K43UQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id AADD91AB0C9
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:16 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id u1sf1021769ybm.3
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975655; cv=pass;
        d=google.com; s=arc-20160816;
        b=tJiqizqWTicUqWvej3oUe8doCgdWvQ7seSVpb+H10ekmaORymE/7SseGub60fye085
         tx8nKICoPxZSqSpVSqZ/VPxbQbtESfODE40NRiOCSZPrYKADRm22Yo+QjoSg2lyO8Q+8
         oEEZt65PB1PUTp5nHZQc28oVEN4s9ThflbIHjk60+wkAvi+qR3P28zOynwm09khqwPp+
         FdZJgWNocBEjoL7+v19buN83yv1sDZ0TY71jC0BnDKnwmfim0OkYpe6qEz/a3Ph4aGQ8
         BbVEg45s5A79vxj401t5xaCNV2fLH0U8h9deRg2dFlraNfVjqBaBU2CLnMZ1+AqupBQJ
         hJpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=Vav2OHWQ388ex4SrASwBqiVVs+hTe225S6itN0XEJiA=;
        b=LYt5+gB122KGHS0vpxGwjaxipER+Eact993UYkvU0xZRWF4hXMGjRaupAz6p2bYy53
         IHHtzJhC8YRL4huZVAK4WpsNhb5gnVSDaU5FuWS3TjcmFFVpoxK+ZO+uHvtvWsoRUpwq
         xclk+yydBWbxsequcS8peLiFgD1yljTJ1rUlF4815jkwHadU+/78kPIEx72LdnJinb/U
         wQO2UQD2LQ/GapjzTD0dm3MdW3QTqoDQriYkW7xtRluC5OhMLiUf5qIBY9Znw0Ljd0rp
         giAUmsU9jvsiiB9FvizT20j43VZJ/B6Fp9gXqp3oGx7JBpyPYAwIIe8rvXW9QxQHbAFT
         AwcQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZzPgZgiX;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vav2OHWQ388ex4SrASwBqiVVs+hTe225S6itN0XEJiA=;
        b=tYusn9P4AFB4pxyzSus09FbPUXHjw5/0V8j3NcGlm3s3jgtWE65Drmd2QR1+ryoZ6P
         0M5HKXgImSEnPxY8937tZugGPBT3vzxeGl60WjpMA94jLtH4i4PESmOIAOQUbU1+WlY1
         LmrPySAk7jtS8YA4jYZTKv7AD8hRBSLCGVxDpJeL2ohl+RqDfSueyPBsoWIhXYtSxwEX
         IIgtmtS37lhNDANedjIKEINDAmRg2eAV0co27ZbZVUnbISFMvCNuf/vMMSlK09bmYH1r
         THHzd+1xK6WmZ+uVkRJv2OCOfKpjfc8Q07oDdqz6nce/dC4suIE8BDzAZOt3DCQwxbsh
         2kfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vav2OHWQ388ex4SrASwBqiVVs+hTe225S6itN0XEJiA=;
        b=PtOqPSdLpz+xG9968uESqadU1pOZqWSefxd4QFiMH7HQyxoTEumOtxColNHwNe1ZgE
         x6zCWRVGWmLzDlDopJrLmAvXG7QXKjLs8NXHd0rZHu12gwJfcDthlWdLLaBTAVQuVfZT
         Xi+3hYbeZYICVmPW4mM6cjR0CpVKHusVlOAM79EEJpkpuqEWpxlsPxwjDF7o6lAqp5x2
         51KDpWMNFfLSpLzL7hQUvXNYFAgzNqHCUj4wDHqNuiIVdRBKPH9GrnHeX2OJp+Mdw3ct
         z5cNf5gxEe4D2OaaVl/64gHQpWwQIcqO4MWpEID80HStpeFrwhs31gVf+W1Xo9xDaFdk
         m0VA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuYfuJDG8nfNiwdYcadg5mUyOfmK8sJ03l6fJAMLj+pR609kujpf
	WV1BXMX6JZtnRr5laeZYcBE=
X-Google-Smtp-Source: APiQypK3cGaQ3le55pi3pF4tv2LTI0Sbv5dQYwnCj+AT1TuyO3MQvmKP0Cw3XoI3neeUMMgjNgaB9Q==
X-Received: by 2002:a25:870a:: with SMTP id a10mr10828658ybl.279.1586975655380;
        Wed, 15 Apr 2020 11:34:15 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2ace:: with SMTP id q197ls3109510ybq.1.gmail; Wed, 15
 Apr 2020 11:34:15 -0700 (PDT)
X-Received: by 2002:a25:cb11:: with SMTP id b17mr10632562ybg.417.1586975655084;
        Wed, 15 Apr 2020 11:34:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975655; cv=none;
        d=google.com; s=arc-20160816;
        b=xvFrfhHHG8g3R/rADHlaBX5SRcwtDZeQml0wmTvIdqHZK3/bwThbWeaI+SfFK7fAJx
         lP2h3YF3bb0r2SBERj1qbPMq57iaawCOZoI778lvHpryDHo+mA8iVBQLWjcUD6bgRW+c
         xAN6vT8gXT99IcVK42EA3i0RHopvnigPEr9CsPS0N9mrwGNAClP5ZWzQSXCOt8UvyubX
         ZIgs+S67eX0otz6maknLBpYf9ZIjTNBxwHMmF+pMk64vFzlTwVUcz+QVs9nFODERjcMb
         AnjhNTZRg1BhKA78/Km1J3JgFQK7WCHVTTY4Wh443EiWsxPsuapNxENGuDj5cAYvaEB4
         J7QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=bm//1UWMQExXPldTMc1TEbEbMebt/31HpZtErvsA6u0=;
        b=x1r/q4LsJhUqA0GjgLsVgPMluBcniodOXn3S7HFbesD8cCiEg0r8xMi5Z5OG3RLsKy
         tf39UEWv/tPfvyxYMhlMUUp6iwf1ZsfJjrPb+4NCa5WErGM3NRY/Q4zV14UNp8eTuSL5
         q5Cou13eF7UIPx2C0FPlQUDQuKAP8l5hO+u0Ta4baeOOcvqIjuObR8t0UqHR412ZdbMi
         EmiCN7sQkRTi0R8tErbqAblEyFwNxamGjcM0+hlOzMQNyeaWYbL/jVgmte5hcug2NPY8
         7hhbM7drdJBlu+VulHHXlBOUOs6vMvtrzBiuAB3jxLW3nbsos9haCnXEQfEQyJAh74NB
         88jg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=ZzPgZgiX;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id m18si1024722ybf.2.2020.04.15.11.34.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id E1ADC2168B;
	Wed, 15 Apr 2020 18:34:13 +0000 (UTC)
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
	Qiujun Huang <hqjagain@gmail.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH v4 tip/core/rcu 04/15] kcsan: Fix a typo in a comment
Date: Wed, 15 Apr 2020 11:34:00 -0700
Message-Id: <20200415183411.12368-4-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=ZzPgZgiX;       spf=pass
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

From: Qiujun Huang <hqjagain@gmail.com>

s/slots slots/slots/

Signed-off-by: Qiujun Huang <hqjagain@gmail.com>
Reviewed-by: Nick Desaulniers <ndesaulniers@google.com>
[elver: commit message]
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/core.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index eb30ecd..ee82008 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -45,7 +45,7 @@ static DEFINE_PER_CPU(struct kcsan_ctx, kcsan_cpu_ctx) = {
 };
 
 /*
- * Helper macros to index into adjacent slots slots, starting from address slot
+ * Helper macros to index into adjacent slots, starting from address slot
  * itself, followed by the right and left slots.
  *
  * The purpose is 2-fold:
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-4-paulmck%40kernel.org.
