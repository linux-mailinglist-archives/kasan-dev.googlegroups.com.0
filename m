Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFEH53AAMGQELCAFX5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id F3368AAE5B5
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 18:00:22 +0200 (CEST)
Received: by mail-wm1-x338.google.com with SMTP id 5b1f17b1804b1-43ea256f039sf354365e9.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 09:00:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746633622; cv=pass;
        d=google.com; s=arc-20240605;
        b=OupjhgJMTOj6q3uDUde7tjuNe15WhmrlD0xF3QqOHxi//7RcaX8gckNoAwm/d41SLd
         ZZn6rgExS7aQk0OsV0zRn+8+AbE/tyWRaNvpS/4emn7xefgGLBX0AVBQOiKwGEdFuwCJ
         T6q4GJ4mMetwLCklYqPQ0fdVNkmIEvQmaNpVEHlLpPNUgSSDFFrly/EwkhxRGAdlvPOB
         UVshvT3c5rGIa/RMa5F1r3+SeiKcAGKJMJ5ljS79RPjHlt+xz27l25+AHIWN1rZXFfoO
         hYCNAa9lwPDM8LdEu/2fX2Qa+FI8WTjNWoETtmV7SXLivOoa6nq8hIkx0wws6PsvE5Hv
         xPIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=qam/kggpbDgNcIlmvK4okOsOo+y4l6rCGSL+X1961Mc=;
        fh=bVYQKKm/eMpkl259wluwvTB337LP1/0WpVJvuGvYW9o=;
        b=H/zw9r6Ew/dGFp+BPdP+u3uOnSnS0OojODhtkbgaiXLO42hT9LG9ZFzIkJYJzPrnBF
         dy4k2Vw38g3Gt4TG2OuKj2YHD2V9gn4f2nO0UF3pUjhKgwES65LPlxdBF70iaOUQldx/
         wA+yLcgXaYgffJ7OL9Cf9qvyUnFWa3oxOrrfwqPYLXc0zRuuNnlXuiXITGru/Rtvb65s
         Lsjoy+zClxPMXwgiGzDOyFHtb1S11cgTshzVeGaK5FaQRtsquvwOkhcfpVlQxhm9Z6HM
         eWeCr+xLZn0oYTKcH4UCF8ZQSJrHyNBI1KENfBUuhoqBs6PoKkaVaO+YZ5qIbL5Tw6Vs
         ssCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nG2sLxRc;
       spf=pass (google.com: domain of 3kimbaaykcu0v0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kIMbaAYKCU0v0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746633622; x=1747238422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qam/kggpbDgNcIlmvK4okOsOo+y4l6rCGSL+X1961Mc=;
        b=CMD/OKgSzsXwBWqNZAMWXE+5sBhCwycJAmDwRSJ4llhwLRkiUm0BNMqsf7/1yC4X7p
         DUBzulpy+0A50mYkKrWd/XZwPGUbhPDI7UuB1KoikFvPGPDzDJndTLmwCpdBtmEnzrQn
         pB+bbjEcrFd3Hxvdq1U8K/L2OJRwuCtFWoDj8kxSfTlMWO+59RIJo7ns1ZJRwivYphTV
         Q08mhLNbw/FjG/PqwNCeVLdW/SlYl7Cv8jQm0G9YmU1tN/frdfp9z0zv3jQ3BEh0/cNr
         jPdh42ltrkEQIq4KsUptRodXeobU78DX/Ov05VMCgokcZS2EvVdjiGycHJt4wKhNjmFF
         AtPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746633622; x=1747238422;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=qam/kggpbDgNcIlmvK4okOsOo+y4l6rCGSL+X1961Mc=;
        b=ZsE1TyXAbOYaAMpPjO9s92Pk0e8I1+yz953Fd13WJtvNurc+hjOYrX3xxrwfQsVtei
         AzlQW0g6rk/j1N21mxJ/ijSlXyoHdVx8/m+ktJsmZANGvkTsYsW23xlOqZlTwY9sbcEU
         /MuI+PgeGuyIc5/osdiVLOsDjejoshFXpezEWsPXqs6OqcMizDZCUzKiWXjzbGH1peUj
         6kfMf9Mj6BDuVj5fRk/92+4caaglb/yVEDTyIlOPPfQBwmF13+CxHf9Mz6SXjff4N6us
         lOmCoe45h6YOcDMlpZ8iw08wV9vWqIHhcTzwgySll11q+lWiHzit5jT7tiyecN288pgO
         inVA==
X-Forwarded-Encrypted: i=2; AJvYcCX7xTM+SsAMtYnnuzsp8UcnamZENQB86pnmApw9goD8uqiLW2ylYl4MpJEZlBBSiIhhnd2CGQ==@lfdr.de
X-Gm-Message-State: AOJu0Yx8DFtgvtX/NSDcKElZpak5bw2yTQw+FNZ4v44lqMJzBXSWh51j
	Cy74mxqJvVqhTqWuSqYJsxc2GfwRuSPzqyPC8tt3m47qUTa0NsY8
X-Google-Smtp-Source: AGHT+IFofwlNje6qq2yJ6d06SAo9iwbLt2cU0WxYoFW4jlWCt3fmtpv7S5KlCLCtB9A57J7ST188+Q==
X-Received: by 2002:a05:600c:6097:b0:43d:45a:8fbb with SMTP id 5b1f17b1804b1-442d033f8e4mr439815e9.22.1746633621303;
        Wed, 07 May 2025 09:00:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBGliMU1jER3e54Cx6QQLj4hpMghz8G8EvU/NBK8XyegMA==
Received: by 2002:a05:600c:3587:b0:43d:1776:2ec2 with SMTP id
 5b1f17b1804b1-442d02d3970ls78045e9.2.-pod-prod-09-eu; Wed, 07 May 2025
 09:00:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVnmKw/mRyt55jpJcWkiJkqxuvyFIoB6WwZeDktnSxnPPNRAaIkySa/q5PIHcfjy9B1Y4WwZyAzDqw=@googlegroups.com
X-Received: by 2002:a05:600c:37cd:b0:43c:f6b0:e807 with SMTP id 5b1f17b1804b1-442d034bcbamr364895e9.31.1746633616783;
        Wed, 07 May 2025 09:00:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746633616; cv=none;
        d=google.com; s=arc-20240605;
        b=T2xDXxDHpPO596JIO95tdFsphK8Dbr2dVnyBckZF9+/nIYXfEDTRaOdGSxjLdV23wo
         zAL+OTQGA8jnLyq2IOsU5tffPpWGApAK233WCtWrydEDpe0TzV3sIFIIDug+uCybN1Ij
         fAO6bE7aobBMA8cTGdTKwJyOjf+pMA1/BWAwu3O6F8HLCL+/HhixCen542G1WLf2z2XR
         fciqILPpIFDYwhRaWmWvUW21apkfPp4pJBq29senskJV5Xcm7iYBzhBxh4262LehXmmH
         OyaDXssgnyAW8xahjGVq+kNqt9En/7rY4fEKg8viZOxWd0UMgndmjKiPuSE1+/9qBLUF
         QtNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=vXPWjkInimv+c0IvUnqWtZ/bOGRa5nQDErIPmKwQCf8=;
        fh=LqrnRsS/Pq6FjLUS1W2HV/6PC0ERhZyagEPCEEHbtos=;
        b=BY/kHIqDQ3TerOPThkzkpfbVJaLX7oCIdcHGmhQYhj/9a29sS/QfCp3/kWPTHC6Ve3
         2G2E1x2OsaMQSjl5MOj5knqPuj8CXwgWHT4FaQ64HoUj+YMaDXmWG5Gi0L/12aOwSDqj
         VFMIU4effKV+sqKYO3vpZIhEbUhyEXR3sLSw9GwbAJ/ZRvraI8PAMZOND7Kd5ccx0zE+
         eAONrVJr6Ia1ch+ua5K227f0md1g94djUJYyDmC7EafA2hTIB5ZPEAcoyjHUSsyAg4c7
         UrS7ki82SQbTp8fbHJxZtyspwOPWyZimngiN0QJoDkVfUYafONqYzbtPLw0t0Yxmc3ej
         toaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nG2sLxRc;
       spf=pass (google.com: domain of 3kimbaaykcu0v0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kIMbaAYKCU0v0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-441d11a0b76si610925e9.0.2025.05.07.09.00.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 May 2025 09:00:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3kimbaaykcu0v0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-ac6ce5fe9bfso343457066b.1
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 09:00:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW7PbcUQWkICKTn/82GbBbOh4msIg7sfZprJJvYIJrX4/Nilxoxxb1t+zx+EtqV6kkoekIbonAbqbo=@googlegroups.com
X-Received: from ejbbx20.prod.google.com ([2002:a17:906:a1d4:b0:acb:59f0:cc9e])
 (user=glider job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:8688:b0:ad1:8dd3:a4eb
 with SMTP id a640c23a62f3a-ad1e8d0d9e5mr360033666b.56.1746633616362; Wed, 07
 May 2025 09:00:16 -0700 (PDT)
Date: Wed,  7 May 2025 18:00:08 +0200
Mime-Version: 1.0
X-Mailer: git-send-email 2.49.0.967.g6a0df3ecc3-goog
Message-ID: <20250507160012.3311104-1-glider@google.com>
Subject: [PATCH 1/5] kmsan: apply clang-format to files mm/kmsan/
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: elver@google.com, dvyukov@google.com, bvanassche@acm.org, 
	kent.overstreet@linux.dev, iii@linux.ibm.com, akpm@linux-foundation.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nG2sLxRc;       spf=pass
 (google.com: domain of 3kimbaaykcu0v0xst6v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3kIMbaAYKCU0v0xst6v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

KMSAN source files are expected to be formatted with clang-format, fix
some nits that slipped in. No functional change.

Cc: Ilya Leoshkevich <iii@linux.ibm.com>
Signed-off-by: Alexander Potapenko <glider@google.com>
---
 mm/kmsan/core.c   | 4 ++--
 mm/kmsan/hooks.c  | 4 +---
 mm/kmsan/init.c   | 3 +--
 mm/kmsan/shadow.c | 3 +--
 4 files changed, 5 insertions(+), 9 deletions(-)

diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
index a495debf14363..a97dc90fa6a93 100644
--- a/mm/kmsan/core.c
+++ b/mm/kmsan/core.c
@@ -159,8 +159,8 @@ depot_stack_handle_t kmsan_internal_chain_origin(depot_stack_handle_t id)
 	 * Make sure we have enough spare bits in @id to hold the UAF bit and
 	 * the chain depth.
 	 */
-	BUILD_BUG_ON(
-		(1 << STACK_DEPOT_EXTRA_BITS) <= (KMSAN_MAX_ORIGIN_DEPTH << 1));
+	BUILD_BUG_ON((1 << STACK_DEPOT_EXTRA_BITS) <=
+		     (KMSAN_MAX_ORIGIN_DEPTH << 1));
 
 	extra_bits = stack_depot_get_extra_bits(id);
 	depth = kmsan_depth_from_eb(extra_bits);
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 3df45c25c1f62..05f2faa540545 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -114,9 +114,7 @@ void kmsan_kfree_large(const void *ptr)
 	kmsan_enter_runtime();
 	page = virt_to_head_page((void *)ptr);
 	KMSAN_WARN_ON(ptr != page_address(page));
-	kmsan_internal_poison_memory((void *)ptr,
-				     page_size(page),
-				     GFP_KERNEL,
+	kmsan_internal_poison_memory((void *)ptr, page_size(page), GFP_KERNEL,
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
 }
diff --git a/mm/kmsan/init.c b/mm/kmsan/init.c
index 10f52c085e6cd..b14ce3417e65e 100644
--- a/mm/kmsan/init.c
+++ b/mm/kmsan/init.c
@@ -35,8 +35,7 @@ static void __init kmsan_record_future_shadow_range(void *start, void *end)
 	KMSAN_WARN_ON(future_index == NUM_FUTURE_RANGES);
 	KMSAN_WARN_ON((nstart >= nend) ||
 		      /* Virtual address 0 is valid on s390. */
-		      (!IS_ENABLED(CONFIG_S390) && !nstart) ||
-		      !nend);
+		      (!IS_ENABLED(CONFIG_S390) && !nstart) || !nend);
 	nstart = ALIGN_DOWN(nstart, PAGE_SIZE);
 	nend = ALIGN(nend, PAGE_SIZE);
 
diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
index 1bb505a08415d..6d32bfc18d6a2 100644
--- a/mm/kmsan/shadow.c
+++ b/mm/kmsan/shadow.c
@@ -207,8 +207,7 @@ void kmsan_free_page(struct page *page, unsigned int order)
 	if (!kmsan_enabled || kmsan_in_runtime())
 		return;
 	kmsan_enter_runtime();
-	kmsan_internal_poison_memory(page_address(page),
-				     page_size(page),
+	kmsan_internal_poison_memory(page_address(page), page_size(page),
 				     GFP_KERNEL,
 				     KMSAN_POISON_CHECK | KMSAN_POISON_FREE);
 	kmsan_leave_runtime();
-- 
2.49.0.967.g6a0df3ecc3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250507160012.3311104-1-glider%40google.com.
