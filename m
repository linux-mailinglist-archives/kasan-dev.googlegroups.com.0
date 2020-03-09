Return-Path: <kasan-dev+bncBAABBPFGTLZQKGQE6HA3DYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id E9EF717E7D8
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:29 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id b17sf8002411iln.23
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780669; cv=pass;
        d=google.com; s=arc-20160816;
        b=Oj+Spa/Pcc91P+gkeWaVplRXfcL+/0/fpxciluja0pSBVVEHhMycoC0G0BOyU3uz/+
         Ame19YNoPuq55oe/uDFDq9qsSpcAyNXKtdFPMLImyzXtmiBzwsDKN/pBSiCaKMn4Mk3X
         +4n0U7wf0PbYD0V195ZyMQ5Z9lFnMNujsU5Rc9zuOqSO8gbClVc0eDCYvCO+7VHsB535
         aMT+1LleLN+2VcBZrLzf2bCuSbGCSDpNXqzgcWfMU8cWk8/Oqf22hl18NjU/+vGphsni
         OwwdndA65gC1zWQt5rgZzIN8ftzCkqF+tO8+Nsjk4WwhpRCbzyHSTU2/rFvZgoYjLVD5
         ua1g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=E2illdMhVPSElC3HD/tOsM2H0YdozrjNtyqSFlkob7A=;
        b=ezHbPTpU01zDMJLX/pUzEmvNJhdffx6mTPFwKrFepRj3kYhSPomYXq2kqLn0n0eund
         LzbVh/R7mYOBDxUOKm3xKYN2tAGOdOd/4678MXiotTfDEzoZPhT/qNrCpA/zn5+eX40s
         6GYWKtIxO4LqdnuFfkWgVteOrm674gD1YtbwKsRgVY8KanMFj9f5+i71bI/rIUeFG2U2
         dAikwrwxkPchdzfNujxo14Szf2/3A7fdbGAgJOHFGHJ3A2WrfCKvfSsZ9AImSbrD8tpu
         bjgZaKuyWtvPPv8HXarSWhXfciN4q3e+3tBPqr+x2CkFVhNTgMwOEyjvKDlTSeZOfSsx
         hyoA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=oNQ6AOwV;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E2illdMhVPSElC3HD/tOsM2H0YdozrjNtyqSFlkob7A=;
        b=PX6kirDvCFnTHLae+uuzjew4QyXX1z1+m0kN7xBMCwEtvkfIbw1Jg0nbVe1xri3Bqe
         nlngkygb8mi0HsIhSZ8Y5kCjZe8uWKLxaElsR4909VH9SSKnTvLmPfYixpN5LfSDr/Pz
         6ypuuSLfiow1C8dHxZcd/qDxUB6JOrhUHxCqZBKf77DIHPi/j88YWOlwWBo7h8TwCng7
         6QcMa9Y+HmxudICt0HwfLYCyJL3ulWjbyYt1j4j7COEriuHVa9BGA+x7bVmq/yRDkZnS
         iTiJT2Fll+2Pyi9C1/tto8GZkFImXnGqWFGB1O/rDFxRPDdpYTI36h/RT/AAvdlFSdMM
         9Zww==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=E2illdMhVPSElC3HD/tOsM2H0YdozrjNtyqSFlkob7A=;
        b=BO5+auv0dnsllNQ+gOwxPuz1ybQvfG2FlCX8w+FA8h2quKTnYT0QrpmQZEiRKyaLJV
         947JGYdGHzPXiJyUAYqIpdbA4Va0ufZzomJy8uw+F3MwU+alDK2VLebzEvS8vdbgh0o5
         /L/S1pExieQMthqE/R0WEUkOl4yXg+dnSeVhgNCDcMoxUfBkX+7OmoqsOVCVY3PuJp8f
         8ospA+5/qKt87Pe9F8pfAiiimZlRsexcaj0ssrbr20wO5tIlPprPKZ9ur/DNo+TlQJL9
         zj0F0lAm1HNdh9chc69R9+KiAvkG1W/WKv1qW/B5Zflj33S8MCYD9ipwvYe3Z9p4iybk
         tptg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ0zafb9Wnx5R53/wz9jCpbTfZpBvWXhBljCOOVSgEt4aroF8bha
	2AHkUF2T1DMSkXoTeEAi7Xg=
X-Google-Smtp-Source: ADFU+vvOBz3gQpvbu6FhBQpTQvOYiIK1NTyXJSQDlLqc7HamVNvUeTS5PKiv5ApYpDr872Uo8fwXyg==
X-Received: by 2002:a92:395a:: with SMTP id g87mr15419854ila.35.1583780668927;
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c534:: with SMTP id m20ls2724308ili.9.gmail; Mon, 09 Mar
 2020 12:04:28 -0700 (PDT)
X-Received: by 2002:a92:ddcb:: with SMTP id d11mr16554093ilr.211.1583780668300;
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780668; cv=none;
        d=google.com; s=arc-20160816;
        b=VIp5Y6K3fAxgjjbvw5iI8SGackKXxBLKc44eQTuadVsuJpnR1Rh49TD8IPErTBuJ0O
         GwiFVwoT9fovU4oAxbzYBl62lif67gZPFJVawSxAjhNK9scrr/A2oOCq/KXf/vDvPSvy
         QBk7cjT+/M2RHHZ/8N7wyp7RtzKB5I5HTaVOcMZAJYCrshkuLPOkI2iiZFF1nzCi43RT
         eS3f5k5Z/iY98nRzq0E6XhsybvtvVc6vPpQnJ0jDP4qHdQA6VEWWdHk8hShiXfhhn644
         9PJf0wYgqN6gZhfS0abVJrLMTHcvGk+GkDt4DgqpdaHJgbyn3NWblfAgnLRlWr5G8vgH
         X6GQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=8biS9m5tfiRvUkBLy0oODFHotRHIS2qcdFemUDoNtHM=;
        b=EZ3jBXpNEDwe+cz/PaAtndOa2mMKLV4ElIPzoaZlj+mIkE87mS2lCYpzkjH9n+Yv0b
         XOSjVxk+94GXqwTLXG6NWeln/YQnSUp6FjQEWpkU7LpRaFzgvstoTYb9Y6xtD/DqESZz
         2z32WPSSGL1qsYsGBgkSjxkobUMsZxdkjr0atURMbA2tKWHLkjjtt1IEpHmG+Zy9CKsz
         w9ugNzTvoaQ57loT8sMH9uWz2kzikK1bIC2lw3edge4vrgamHzg4xM3f86Y+aOyZqec0
         yOMRN6G4AWb0G84Q3gkiqf/sRechAFfhu6kEpbKImL7Y3UaL7rme/02tT5ado8Ve5RX+
         gkIg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=oNQ6AOwV;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t64si500438iof.2.2020.03.09.12.04.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 92FA72467F;
	Mon,  9 Mar 2020 19:04:27 +0000 (UTC)
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
Subject: [PATCH kcsan 22/32] compiler.h, seqlock.h: Remove unnecessary kcsan.h includes
Date: Mon,  9 Mar 2020 12:04:10 -0700
Message-Id: <20200309190420.6100-22-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=oNQ6AOwV;       spf=pass
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

No we longer have to include kcsan.h, since the required KCSAN interface
for both compiler.h and seqlock.h are now provided by kcsan-checks.h.

Signed-off-by: Marco Elver <elver@google.com>
Acked-by: John Hubbard <jhubbard@nvidia.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/compiler.h | 2 --
 include/linux/seqlock.h  | 2 +-
 2 files changed, 1 insertion(+), 3 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index c1bdf37..f504ede 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -313,8 +313,6 @@ unsigned long read_word_at_a_time(const void *addr)
 	__u.__val;					\
 })
 
-#include <linux/kcsan.h>
-
 /**
  * data_race - mark an expression as containing intentional data races
  *
diff --git a/include/linux/seqlock.h b/include/linux/seqlock.h
index 239701c..8b97204 100644
--- a/include/linux/seqlock.h
+++ b/include/linux/seqlock.h
@@ -37,7 +37,7 @@
 #include <linux/preempt.h>
 #include <linux/lockdep.h>
 #include <linux/compiler.h>
-#include <linux/kcsan.h>
+#include <linux/kcsan-checks.h>
 #include <asm/processor.h>
 
 /*
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-22-paulmck%40kernel.org.
