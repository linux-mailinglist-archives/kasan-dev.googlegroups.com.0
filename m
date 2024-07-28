Return-Path: <kasan-dev+bncBC5JXFXXVEGRB2NKS22QMGQEOKEMT4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 30BA793E1AB
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 02:48:43 +0200 (CEST)
Received: by mail-il1-x140.google.com with SMTP id e9e14a558f8ab-397a7f98808sf57368735ab.0
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Jul 2024 17:48:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722127722; cv=pass;
        d=google.com; s=arc-20160816;
        b=cgpkqAx3xyLZ/fpDYkC0X/ig5lrR8x6oYEYXS3h7Q69n5cwhdtzOC+VX/0PV4xlkdQ
         fdD3eB9OUq47Gl3jT+bj+PhLP3D4/T466e3l7SyRa97rcHYzjpKZXJxaYlvyzQFNOPXU
         YWDMyJfmJBiIWZ4WYq5vv7jPiLYXOwO+BEldcOesMdMd/MxWDMqx6kBSeHXjm/tryZx6
         QHaz0bqmz7ngCMTQMAqUTrheCkdjBIy+mrKfXt9Q/VEhjWIWzgy70JQD+8LLmWXBqBJe
         IfguBdsBIoOwnJzOz7sqJvgJ9K//G4ICD9jW9RmuzqjMtfME0S9RcTkkPTqMajVRbeyX
         Ir6A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=r/GFPqUYmMU4yF/+Djwlbrf4aKMDZdw/APeGFzyHKAI=;
        fh=gC3Cl1EuqQ//c8q2lCbHiK3ZSORTjnpSrtcbe9ud3NA=;
        b=Rxl1L9nqTeWsYhEJto5dKZ2LKNeGR9ikPZUMDwysUuEN2PU05pcDjIpOJ6bZYQ/EF7
         an3U/Y3EGFwFM0HAEmV/iMzZIeKjPzJwzcnq0oCqNyursbIrkiQroV0lsmhdLoXzxG+k
         /WTa8sK/0aQyHpFzW2gfs7ksksuEjGEVNo4+SNSkaJUXhqIrpliu5HKz8gCuQLNnlKQG
         qQyrUyoJQZztRqCee1BVCzA5rqdOtStMj13AQ6+6D0dxW6XnbkbMB4COvZg0ATCXpkBK
         WhsWN+qRs9HbSvVmmIK98pyTtbyO61GKWWRN21GCM9nk/s67M4Me1bFFOQLjYV4hW4IZ
         qxtA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FLOuECl3;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722127722; x=1722732522; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=r/GFPqUYmMU4yF/+Djwlbrf4aKMDZdw/APeGFzyHKAI=;
        b=qAgguLj3Br6OAtr0hz2CVwjyNUbGPlQktybyBf386tdnLhEQPBkJS/DbUw0M+NXsgV
         HowBKXoGO2cNBQvrQWyCa0JrWpTwI04bvuWFPDpLcr+ppiOgz2O7QXQjj4gxz87wlJrV
         rqYFJNUCgL9RO5sCK0ZcK3QuB6+SwhtY6WDOunrwSYToHuMc5B1vfcuYfh//WGzkcWCp
         LaOa4mlyunasP2CX+c92sOtPMNFYbJ3oMVCoGuZHY/qRH8+LcuD2z83eYkOeRS2FEuTn
         71tPPk16lfFUKXA/DkRctcsnxA8JpuifYYSo7p+0j1/T6KhG+XzNRh5HaMvr1mZdRpzZ
         Dt8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722127722; x=1722732522;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=r/GFPqUYmMU4yF/+Djwlbrf4aKMDZdw/APeGFzyHKAI=;
        b=wn98nNVwWiR9c0lXCPcMm350wfVBTNTFYY1JIQLU/Lq2KaXAJYzJZg48dJZOuonQQD
         t/tzb57uzryXtqhHRQ02mDXfFzQ1hnyVUbmot7dFC2bDvjoTttEl2/dHa7Z5+q7t+CFG
         q6zjU1Z+Lfq6pE0rpSFYN01p9Eyv18qqb7VBdk2H4zPfanIl3vFtRCUhELLZLaC8XUn5
         E3M+WnO/WiW8soL98F/pzVS9F5SXiYGOYb/n3p8Qw9aY2F2JEjExDxTk3y3UtfcZtBg5
         6YOoo5l9llUePTR9yfvn+qO9HpB7tNDpbiDDyN1Jqz/e+GBiM/i71JNKbVy+RJREoqKY
         OIyQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCW2geqgcvVHA1344H+k2ZzrAROaA6kN04Xdx/Aw1OR35pwp4jFWKgBCOM0a8HIdjJt+MzkoxY8F1WKtEIZI9BZV+9FeSnsTUQ==
X-Gm-Message-State: AOJu0Yx8+n7Hgfwz8L79UnfAydVPDyXO/JUnGAUbULmYJD/BZLjqcFXs
	+7nSf2EwXct2UPeMrR/5ALlqLUlNEVYdhtXH34g6oBEWcC7P2Blz
X-Google-Smtp-Source: AGHT+IHc+1s8Ed4HbJ9RVUV4a3Qc0F28Mj6hGwnXZH0J5+MO6WcEi4kWGN/echte/a4PBBKlAtZGjQ==
X-Received: by 2002:a05:6e02:184d:b0:39a:12d7:2841 with SMTP id e9e14a558f8ab-39aec2e3585mr58368785ab.15.1722127721759;
        Sat, 27 Jul 2024 17:48:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c5ad:0:b0:39a:ea14:41fa with SMTP id e9e14a558f8ab-39aea1442fdls8907525ab.2.-pod-prod-04-us;
 Sat, 27 Jul 2024 17:48:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDIOG4Ue6U5fCfQOxigYRT89F0IbDJIGPS2tCl7EbfeopSXXk1Gvy+dJvOjrf3lV+xHVkaN25VRsSXUbwh4/iWjJRwy8REACoowA==
X-Received: by 2002:a05:6602:1544:b0:806:6b24:ee1e with SMTP id ca18e2360f4ac-81f95c5730fmr409756539f.15.1722127720908;
        Sat, 27 Jul 2024 17:48:40 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722127720; cv=none;
        d=google.com; s=arc-20160816;
        b=m9MbUArU9HHlKBMPEBFT2tLEw8FhlsufSdl1pcdfvLQPyAqbEo0RMHRgyWCMfzk/ao
         MXWYLErBT5vu3R7oqAKzg1N27epJViwhCOQl8FntDhwHyowBUT2Li8MiEgQxYSqhUlFG
         jlJlJxbnLLqNix49EtVZLXPAb6tGv5AhBlyEN6bBwrW1WXXu9BMb7aqj8+QYaSq/2h6v
         oEg/R1Fd2Y9mWkevI6gm1cB0iOxmwZUfBREaePFTMINW2SQxKYQSHUHExzyJTz9zF2DN
         zjCc8aLaIFqYAKLP+RnNE3e0VqUOFDObGeGt6colxGZgRy8Am93rLlwlgKVrWkNOxmQh
         Rk7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=FwcEUzfNT2R141CHQsPSrRYXAWNtvQkPcFccxAimg4o=;
        fh=NHFfq/j/rWHP94bByHknyzKqAJRJzQrt4qr9AibEjk0=;
        b=d7/Bij43f3r9H8ASZ/d420Fci+yTTrnVcZQlUWuij6sRt/24uUMGg3VaNzqtD9rv1i
         VyPekHSN5BoUS+Tfc4Ox0iPBuZyvcRt9jQazBsZO6rbQMRHs4pEhAzaXhphN6OTmXzdt
         kEEuVwhmg035pFMuiQnM4PAt3ll5DYCOZXRE4KRWcp5afgu2fBBEPwOah1EFF4kKJY8k
         tNs8jfGrKBmpSEMtAgE4xzNnEBl9uKhN1iDC34ZfWTjlPj7+Ay8GSvJ06hv/JBmzyVgU
         bVehS96wbLEeDqytqS/FYO2q0fo6RKUyLraKRaZvBjysuwjCstAO6eUdTTbcKZiZ/BJB
         tMYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=FLOuECl3;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4c29fa26139si301880173.1.2024.07.27.17.48.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 27 Jul 2024 17:48:40 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 25B10CE01B6;
	Sun, 28 Jul 2024 00:48:38 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 884C9C32781;
	Sun, 28 Jul 2024 00:48:35 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 6.1 2/8] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Sat, 27 Jul 2024 20:48:24 -0400
Message-ID: <20240728004831.1702511-2-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20240728004831.1702511-1-sashal@kernel.org>
References: <20240728004831.1702511-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.1.102
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=FLOuECl3;       spf=pass
 (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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
index 8c45df910763a..c14517912cfaa 100644
--- a/kernel/rcu/rcutorture.c
+++ b/kernel/rcu/rcutorture.c
@@ -2547,7 +2547,7 @@ static void rcu_torture_fwd_cb_cr(struct rcu_head *rhp)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240728004831.1702511-2-sashal%40kernel.org.
