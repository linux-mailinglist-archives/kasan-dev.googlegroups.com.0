Return-Path: <kasan-dev+bncBCS4VDMYRUNBBLPX7WZAMGQEYBSLEJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id CAA938FBD72
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Jun 2024 22:40:14 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-4402626c981sf29671cf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jun 2024 13:40:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717533613; cv=pass;
        d=google.com; s=arc-20160816;
        b=0vqm50/M1vxuT69Bq4D1fPCrELowfJT1Mbljtl8Lykdr9z05RtOjTeDI8M6yH+Nb1S
         szaOXWlZqO4mFLv/ceSoZNGqyMcncLyrZj95GpLkFTkolf4jW//VUtTNUJMmpaMNSIyP
         U87qJb6gcNXHefC7c5pxupv9aiJVf7im0vitIxUwRojJ6sfBqPcq+amU3SDoYOLngxYQ
         9xHMIcX+7siHByx6wRh8EpzeyUf0FHK4c+nhVM1clH5r2k0GJuE2PTd+hsVxAno228CU
         3WdlniUdtzDnNB6gXXsLgWvcJdHsJjx2CLBBenJtDpWTYUUivW0KTC5hBOLJffnJBqXS
         /GZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=AfHte+8lfW+RZskaj/q84DM7InbVj7XdCJnx2T1xAD0=;
        fh=ErjUNw3CDh7Bq2GfPyPdZG/HS74S3wUPmpucnEI4MXg=;
        b=wNmhtqVbau8MijmJeJfGI+7giLpdqiciInPViMX2sZs0v/u16jRKEuFPrDF762ucnr
         nsxngL9DFhymVqDD0ydiSZUWZISLUt3efAYJNnHacYghrdrnRVqbexDQsAP3UxpdAgsJ
         zv/6AMaLOBe//4wk6JeTfVxRtSKVIQyVc0jcak7ahMmno1747Rn0PW6SI0HPuVwSAx9K
         kKPBBW/SU1zxNOAU/4PBRJ8/T/lQMiIjQ5LfrqWoTTMCZ14C8pid4flp4eWvkYM/xJhE
         EiroehkH/9wr/aYCVzIfmo/C1PUD4K5BAFaV05PX3A/a0LC279syfOG+EEUsPwszUuhq
         Ck1A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hyNtBL0+;
       spf=pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717533613; x=1718138413; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=AfHte+8lfW+RZskaj/q84DM7InbVj7XdCJnx2T1xAD0=;
        b=I+t0Q6lE5pMhrfcRW0bBYKRjtKQVtBM7/4UbmJfrWE6YjY33zbhYTokGq/rUE+pj9X
         43G7/V8ILOd8puUbQbCXa/+yhx3ih8IxJ2/CY40lvW5KmQfvhMTeE5hVtA9O+6MDk9tV
         xYCfznZdJU77xXZn7XhwX91a79AJI+THcrW+weiJvTU5oo4H7P7ANcjq7bMSJWih6OlV
         3YbDrNiGM00k2fNAGgiq8saQP9HdVa2MDKcHT2TdI02mtgm6DDn8kd7KCToCkaz9oUTL
         5iPr1+sKEFPz/O7PxMIaYKJqZrWGhzvmEefmkMo5qnqMJryCnr8Ao1Vo/EHWsSP3vEjp
         YQ3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717533613; x=1718138413;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AfHte+8lfW+RZskaj/q84DM7InbVj7XdCJnx2T1xAD0=;
        b=JNMV8XSMY4CRkbALO8fKHdxAiY/GRHzrMwJ2+Rjdz0FPu3ODFzipdL/X1/wrtLM/pt
         hXIiZ+sdpFVC033kl2zEVyS8ioZ/aH97Ajc/Qmp29pycO88vw5We/Id6V9cqBZTnb/Xk
         wqndRY5AJbpRHLRby7TU/BUqbOXXQnmaFcu1+IEsAon/mXLGAjiWMTn12Hlo0+Ic2Svt
         B6bC0D3rYlYHXhdE0eDYjqNi5JXg37c5E77X+C+tTRNAhXUItCNFfwZT/vDZStbZ1vMI
         ye31BCnECQXQByPAxtcYMgJCvsd+tyi90QdwgArrtRHAieVa2pbdEit8flSDhMWZqdLJ
         lzdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXZ/ObZTVNwXNwgUpTGSiVUmQeMJEuyBaLqAmTnW+T7cMSKf0RzljwaqB1EH42fBzlbvu4rUHVVcKzuf+v8HozU5IRXPgECGg==
X-Gm-Message-State: AOJu0Yw6+b/dzqnMHGIFPcJ/r4rKV5y/9N92KWXds/TgkXwadtpLB7eb
	AnCX/zSryAZxBcyyXYgUL1wkYpTMq6Us1d8fwSpD4kTP797Ll6+Q
X-Google-Smtp-Source: AGHT+IGUsLdqbjGK4I74Vrr95Kf8OwdQlvJd1x1UVofSHw2p3APK3u+7uDHgKj/V0Yfs/fLQf8gaXg==
X-Received: by 2002:a05:622a:598b:b0:43f:fc3d:8c27 with SMTP id d75a77b69052e-4402b94b22emr645861cf.23.1717533613551;
        Tue, 04 Jun 2024 13:40:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7416:0:b0:df7:8a9f:8453 with SMTP id 3f1490d57ef6-dfab15f4289ls265945276.1.-pod-prod-04-us;
 Tue, 04 Jun 2024 13:40:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU59HO6FnAlf7QmLl7j6nOJfrTgc4G3xVvP4eq8p6hElzumL6GhfxmjeOf5aR6GgC1RTBNG3pVWfI7JbvKry9XDiOuo/Mhl5N46dg==
X-Received: by 2002:a25:3554:0:b0:de5:5a6f:a52a with SMTP id 3f1490d57ef6-dfacac4b79cmr575737276.26.1717533612081;
        Tue, 04 Jun 2024 13:40:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717533612; cv=none;
        d=google.com; s=arc-20160816;
        b=Yvuc0qG4OQHPZ0DQWv2zQdhF8/V8Eq0zEVaXA+soyc4kYHg7pJAvCodp1vdCP3r5kd
         O7dlQcQ6ZU+BmX4vBafj3caVxPqdPuWs/qOcuta0cCmsNZAjul0TflrGk+x/UuIWJx60
         Ma5nJQG0/4L8JVo98fOZpOhmfsawKwwauPYoFaiCWa+fahsVYN4BWX7ICajxP7lTr8Ej
         TB+B+4iPS4bLSV+TD8VhCv16VmlsSWOLiWW0vohDmw6wJaBBjm83Vhh7WbSoWgWnkLhR
         lgYY/gyclJMmnLHPnHs+XjAMkAM979JcUf6cOeehcSy5EKnbpbYw5zvmXR6li5EhrVvT
         59hg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=6i+xVPeCY6CJ6ByLWIrcyLpi4H/8gAkg6v8gNSiW06Q=;
        fh=ptObe5pUj9nmlB23BpUPVCl68aEomaRZivpJ6UjPRjw=;
        b=mW8mcqk21ftyTIrbb/Xf98T6uihytWJIOiNWqmR/Oew4g2bdKfRPOAeegH0r8YcCs2
         zmXtHza1DFk511F/glJ6KPtYm8bPp+EVEJpOqpIVutNzLV7qDnZ9TSvWXv0tALdHL8rG
         bEkEO+OO6zh/WlEIC5AOZbI/d3ylUa0FQQRO0dYqNdC6VW90XPapF4aWoIfwzeRWQev9
         9uDdGqiNBo45TkdzkzjyBooqiFAeczJ/cPF4VzPRekguR9dmQLZ03EOSuFrARqmZfSMO
         GhwdbTX+3giWW/wEPzRn9+p1n+mXQ8dYuwFczEqeLmUjFNMCBRK/iKNFHFQniqYcYVvs
         Jdow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=hyNtBL0+;
       spf=pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-dfa6efe6db6si633706276.1.2024.06.04.13.40.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Jun 2024 13:40:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 94FCDCE131D;
	Tue,  4 Jun 2024 20:40:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CEDA0C3277B;
	Tue,  4 Jun 2024 20:40:08 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 7ABB9CE3F0F; Tue,  4 Jun 2024 13:40:08 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@meta.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	Jeff Johnson <quic_jjohnson@quicinc.com>,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 2/2] kcsan: test: add missing MODULE_DESCRIPTION() macro
Date: Tue,  4 Jun 2024 13:40:06 -0700
Message-Id: <20240604204006.2367440-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <ecf1cf53-3334-4bf4-afee-849cc00c3672@paulmck-laptop>
References: <ecf1cf53-3334-4bf4-afee-849cc00c3672@paulmck-laptop>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=hyNtBL0+;       spf=pass
 (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

From: Jeff Johnson <quic_jjohnson@quicinc.com>

Fix the warning reported by 'make C=1 W=1':
WARNING: modpost: missing MODULE_DESCRIPTION() in kernel/kcsan/kcsan_test.o

Signed-off-by: Jeff Johnson <quic_jjohnson@quicinc.com>
Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/kcsan_test.c | 1 +
 1 file changed, 1 insertion(+)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index 0c17b4c83e1ca..117d9d4d3c3bd 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1620,5 +1620,6 @@ static struct kunit_suite kcsan_test_suite = {
 
 kunit_test_suites(&kcsan_test_suite);
 
+MODULE_DESCRIPTION("KCSAN test suite");
 MODULE_LICENSE("GPL v2");
 MODULE_AUTHOR("Marco Elver <elver@google.com>");
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240604204006.2367440-2-paulmck%40kernel.org.
