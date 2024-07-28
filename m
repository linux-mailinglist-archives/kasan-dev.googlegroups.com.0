Return-Path: <kasan-dev+bncBC5JXFXXVEGRB5VKS22QMGQEWKC2KWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4EDE393E1AC
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 02:48:56 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-44ffb762db6sf26269031cf.2
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Jul 2024 17:48:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722127735; cv=pass;
        d=google.com; s=arc-20160816;
        b=GVCmWxiKKRDTOmXCNYlRcgQ7v4YkExphBtPTiMsjLAGydUXZm64MKo3O81fBHdtZBX
         OUjxf0F85Z/7///DkCJSaLjaaAlL7wa/w49m3qF4/TbKK6iSAHzX456jafnpI7dj1m5B
         QxltYu7Aqgybrqa62oVxSq+wcMZ7tWeQg0D24JL1nRe3hFubvJFlUIkFgK3ZaHruTa0Q
         xUSFTQPRnAN0rpFQOYA5wJDOhAanQDqtbIPPzSguPMTOybDlmw9buZt21EQeqbD0O4Xe
         NZdUFIh5Iki6t+jWzuqU2ZxxZQF4w1AInkOGpDObko09KvqJdBIjzpCcGgm2wSTsJZf1
         QEqQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=eobcDfg//s5WnRPcWrh3ZvGJp4S4ZZrhKmrfOUaShE8=;
        fh=G6PYZe/yk/n+9zvFRhW5V1rueJQq9tlitQ4RpgcY2LU=;
        b=QrJq3L84gz49hwIDhdrj5n+OEG9D9apNNXlVcyFUlVhuixOt96xW5wSAPizhMLtZoT
         3HRlEK+H/O5SyClz4gSBwjYSV/Y6kdZk9ZW3g/wTmz1rQl81m+PLyI8+8+M5De4DelV1
         h1xMeOGdlRV5HyJPisnQpxmLtKsRCY/zYBzFMfqjYMYva9yL+6weUgMPF/nzBUMXrHTL
         4Gr/5vMquojndrP1amcFTqMA5d1sP55qBHvuWPxlvkd8RgVa0DhhmB/ioHub+uUl2A1D
         5wDudSy0IqPp8DW7EpCHYt6shSx9WA2S9rI4La4yIemF1Yb2OgUbgBGDLIRUahuzziXJ
         jIeQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mYW2Oh1k;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722127735; x=1722732535; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=eobcDfg//s5WnRPcWrh3ZvGJp4S4ZZrhKmrfOUaShE8=;
        b=T3+wL5HCuSkCIBhm7p75HVQ6ndVgyHrRp5U2qRzHZsohd7AGD/2ac0hD87xdWsMAcu
         OByYNomdaZuOEyNkKzllOSLLATqWfzEfk17CLT3NXGJ6OVRDFWvWcFrhtMaIPE0vLwSa
         HRsmkrjVdn6BMmY4gmEfSwh5z7Q0jEx4ARCf/nWG75I3rtYuCrHB1EUjPu+IElIE0tan
         Nun7+2WLTmq4u1Kh7THyw738hWMXYAV3qJRkR+6uMiuG0CGEnK03QKVGeUBjBiyjbdSf
         DNC8OnEK6KNx29o7uKPSHAkPVWfFPhJx332o75WuXOx6VB9+Su4b6HeaNc9fdyURz3Ku
         nq5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722127735; x=1722732535;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eobcDfg//s5WnRPcWrh3ZvGJp4S4ZZrhKmrfOUaShE8=;
        b=AoYZdbkU9JX40q9xUOJ4J8Lg7BkC8fl7tREWVfULLCflgLeVv0vSB3eq0M/QK6OzUM
         XCC3UN/DRxPM3EOUwoMGQBNzbgXuOMPXtvCq0atZrWwEQSSH1kKW5kQkvhqp6QKdqaQY
         8vqcj0WKnWazuPJt7X/x3wmz00dVx5T0s7LxE9YlgWkj6OGp/aVnDGBXse+EaBxQG1Rl
         lEH6146O+dPuha0qc1kcsTypjKHDtF6ipaLPmYPzXlIIL+/aPOcS2XG4f+PGrwot/O+a
         wkGsq2WUmbobO0+dOfvgcI0c1pA79payVO3HBhQ29OHLGjiu9fhYJjSs+aIV25KfQOG9
         GpRw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXnl6p30s8uiEPAA357MPtk9jmUTzPmzyG8SLucjmTU8NNnQZo633wSr7Ldij1m5EcKVtWzotk1yrTpBEfOBVhJUMX6zl3tmA==
X-Gm-Message-State: AOJu0YzFvTEYRw5jcXu3METJX/91KL/n9PYATc2ENCE99+9j2s0oQ9+H
	wyy3wtfrEvgEpUVKgHa+lS9HlZOyt59X1SAxwc3F1BL1PNtTTyLR
X-Google-Smtp-Source: AGHT+IFAuCnI/X+nq7XwM13CfhEe7N/DkznbAFvMVdD94P9/Wb4nVw/HYxSP7c9M4kBvJboJb2yEpQ==
X-Received: by 2002:ac8:5f8a:0:b0:447:e004:5fcc with SMTP id d75a77b69052e-45004f503b8mr64980261cf.43.1722127735071;
        Sat, 27 Jul 2024 17:48:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:138e:b0:44b:e6db:de28 with SMTP id
 d75a77b69052e-44fe31ae9f3ls59605501cf.2.-pod-prod-04-us; Sat, 27 Jul 2024
 17:48:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVL03uXYWVt29lQ/yU3ToPobhvEhJPUFNj/keUhl9Ha4dvQeuHGJ8e5HZvyvDiaYYMO/OLfCWQZMXbw5OVDCMk/i+HTMXfJ2RivPQ==
X-Received: by 2002:a05:620a:170c:b0:79f:1776:356b with SMTP id af79cd13be357-7a1e522a195mr539869585a.8.1722127734532;
        Sat, 27 Jul 2024 17:48:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722127734; cv=none;
        d=google.com; s=arc-20160816;
        b=KbimyL5tNmzYESkzIO6iCtX64h96K9EpMptRUKKhW4i9wJc6uD7PURnQ+ZJmXY653d
         33cLcsOc4wTQMqVK2QSJ3QvzHxtkBW0uYahLOnQhws0xULHmM9wp85TT0WVuSkQtmoOL
         xboutlERqDP66PKUd/KQ/X86PIhmqRsFCGcMNEM5OcDtE9qZShOWc5Zl2ZJNdvyYieBe
         s9FZ2mMMi4y58Ppxjemr+bxaBUng7n94m0XOG3tIP7+kHbkxUqA1F+pWg5zlvZ4hnx5d
         /sgof+lQBX0+DWFOTvC8JtR4nOGNFO6rZgVdWSZHuSriyLtydTastvI8u5/yKEcKYhLF
         r4lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=q1ULxvO01BPvR9CHaXloPph0Np5G9GSzBSBYTjZLDnI=;
        fh=NHFfq/j/rWHP94bByHknyzKqAJRJzQrt4qr9AibEjk0=;
        b=sCNnnHWH2MHro+9YuN/sNO/5fm0lJeKkEITicXLwOdrKz6OlqpKXcWL4v3plfnxIpr
         7N7B7TOjgC/zQ84qqzlNW+uLuuRVoE2DVf1TjMHuHIJceAnwOmgvmn4S3ot6aJd91ClA
         MyOUpZslPwmHqVLQJrOsItUJlfeqWwWzVdfyCm3OYcYlt1Odpn34zTeAFMH35pzTxmaV
         ZDHVwDABwgKk1iO1oUJ0ucTYSlOpbd5ICaR0jXDWCAul13UbRjKsTKY0BVUBVgJWKf2i
         xRo19mZNe8stDbbpiayYVC8G1diI/TBQWtypoFL5ncXwJmfG+Jw7/zDXpp62dBxTEV0G
         S+2Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=mYW2Oh1k;
       spf=pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a1d739946csi25825285a.1.2024.07.27.17.48.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 27 Jul 2024 17:48:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 1CF52611CF;
	Sun, 28 Jul 2024 00:48:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1828CC32781;
	Sun, 28 Jul 2024 00:48:51 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: "Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>,
	dave@stgolabs.net,
	josh@joshtriplett.org,
	frederic@kernel.org,
	neeraj.upadhyay@kernel.org,
	joel@joelfernandes.org,
	boqun.feng@gmail.com,
	urezki@gmail.com,
	rcu@vger.kernel.org
Subject: [PATCH AUTOSEL 5.15 2/6] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Sat, 27 Jul 2024 20:48:43 -0400
Message-ID: <20240728004848.1703616-2-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20240728004848.1703616-1-sashal@kernel.org>
References: <20240728004848.1703616-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 5.15.164
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=mYW2Oh1k;       spf=pass
 (google.com: domain of sashal@kernel.org designates 139.178.84.217 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
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

From: "Paul E. McKenney" <paulmck@kernel.org>

[ Upstream commit 6040072f4774a575fa67b912efe7722874be337b ]

On powerpc systems, spinlock acquisition does not order prior stores
against later loads.  This means that this statement:

	rfcp->rfc_next = NULL;

Can be reordered to follow this statement:

	WRITE_ONCE(*rfcpp, rfcp);

Which is then a data race with rcu_torture_fwd_prog_cr(), specifically,
this statement:

	rfcpn = READ_ONCE(rfcp->rfc_next)

KCSAN located this data race, which represents a real failure on powerpc.

Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Acked-by: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: <kasan-dev@googlegroups.com>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 kernel/rcu/rcutorture.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/rcu/rcutorture.c b/kernel/rcu/rcutorture.c
index 9d8d1f233d7bd..a3bab6af4028f 100644
--- a/kernel/rcu/rcutorture.c
+++ b/kernel/rcu/rcutorture.c
@@ -2186,7 +2186,7 @@ static void rcu_torture_fwd_cb_cr(struct rcu_head *rhp)
 	spin_lock_irqsave(&rfp->rcu_fwd_lock, flags);
 	rfcpp = rfp->rcu_fwd_cb_tail;
 	rfp->rcu_fwd_cb_tail = &rfcp->rfc_next;
-	WRITE_ONCE(*rfcpp, rfcp);
+	smp_store_release(rfcpp, rfcp);
 	WRITE_ONCE(rfp->n_launders_cb, rfp->n_launders_cb + 1);
 	i = ((jiffies - rfp->rcu_fwd_startat) / (HZ / FWD_CBS_HIST_DIV));
 	if (i >= ARRAY_SIZE(rfp->n_launders_hist))
-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240728004848.1703616-2-sashal%40kernel.org.
