Return-Path: <kasan-dev+bncBC5JXFXXVEGRBVVKS22QMGQEW6VV4BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4A2D193E1A6
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 02:48:24 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6b79409b763sf25542836d6.3
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Jul 2024 17:48:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722127703; cv=pass;
        d=google.com; s=arc-20160816;
        b=NZu9rKlMZ8SY42G0kyuOifnPGXyCLYkZ/Xk7wZf8f1lRtpGsUW9NdATFWq9X+ohYMb
         l83Vj7vZMyY/AM+1hMVtkcaTEBg2AEUNhKAFE7uTuyvEbKCOw4PmtNfXgpCARMh/Yod9
         xosWfvquizV5UWVF5m6qste6ncTpvB+jjWkJeok11wxQ66+vAx3wEbArGL5/iK7Li3oV
         eTf02Z4HoU3kER9lsOKDvw8uQEo4xPjAyzKNSMqgpnpfRhXQNxI+uWfJExk/trAB6Kvh
         w73nAxUfT0fo1MTCS/MVMW0wQYUYdPr7hWIjgIXptCa/Ozm+fn459o/N+vrEHo8cjUya
         0+6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=TblZaPkL+mi3mD8vQz6NWo5qaFS3fMd+uaYEj0CZ8N0=;
        fh=wansdSBvVVeQTDIk03uyXKa2cyAn2Oarg9OQ/C1C4bY=;
        b=U/qjhHSF71P2rin0G3RJ1VKGjjBu4yU57XArjgOOz/7bSwMPcgdFaoZYbqEgXGfXnE
         +/4LLhIWhF8jRuko8t8Mb0/sADSuQujh74dujc1eCIkq8iHCrZI9pWj6m1JuGLzMh9MK
         pXRAZ50bcqk+Lv/XCdDQLTifAyca5ZQob+BUykwWQr7Vbsozee58lwXdZt9OwM2JkEks
         7g5FAq/bTkHd0OaFukYyNe8dkDVstzXaMbaEdGVbRazPsSASFG/PfG9qnfnAEf0NfLCH
         NK9GCqLIKYNc4Rd86P9BrDDHq9mmspc3iy+km4Tmom8eTe1VwCEXdxwM9AYZtBKxKAYR
         xQgA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Cshcsmb1;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722127703; x=1722732503; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TblZaPkL+mi3mD8vQz6NWo5qaFS3fMd+uaYEj0CZ8N0=;
        b=h9wpyAMo+VooeNATkOGXwVsgp8FqQecmU4D9PAwyoCfAHBB4ZUaVNCLP+VRwGMRmqa
         bOsrtA4hzGAZKxtCVJ/yjVVUGVbyXAxEWmYEIV/c0W8cxXNijVPDOYjAitedCpXE/d2n
         xfmmbhuZ5STsEH7rufHFTqJwr02eydfmGhf945D+jpOjqRra4WCMEVspgvOcoOeZt/eq
         BB3XTjU71jctN9cTUFvBHRRaRKFsKV5p78Qp3+WesLLfV4By1TsuJdE7Qu8YeYv4eBvi
         zG1yCjswjunpgC6940QJfYkN9Iag8VxSQ1urvhXiUsf6rIaH4vbPZ/c9xL5HM1TF8hIU
         i+OQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722127703; x=1722732503;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TblZaPkL+mi3mD8vQz6NWo5qaFS3fMd+uaYEj0CZ8N0=;
        b=Sd8DxmYuHggaMaZj0/kszW0y60EQqg4rJNx7JEn84v4ITnfp6YzSj8rTmz+3xGiPMR
         9kskmScb7y0MOYR7kNAwbCT5jOW8bNuBZLj4Zyd0CyDwtQkrJnc0YeXdK0WXojk8SwUU
         UIijNHsUZpaoR4uDwsf4rd1KwoXQtdE+DpYI5iiredgl35N+mwk3k6Wap+y+7VyWJX9t
         EQI9uiRI1ktwil3Jh1AdHr53hDAjJ34s8CAGtobl6pILz6NcJdnPQpJ5cZZF2EZ6Aa32
         PWs396pRtAVBcb1QXGBZylFRkjhRiSXk67rbAynm0Ng+OJeKZJDxoKmDgoxZNfMq1Iqq
         MBLA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX2hYCyaNGyIraQ80GEmIVjGwJzWWbeQkCm4BPUf3b8B2wUFWXYOzhJg2ASQQCa2UqZRY+xQcvYr4niruRdu4b+DBxm2B4T4A==
X-Gm-Message-State: AOJu0YwCwHpLDI2bjbr+iZSd9UbFsF9Sx4+RzIm2iqCLbX5EUiZTNmUP
	YzoKiyItgVSjIEreUT7ZhWK/7iel778XFj5oe2c/LLWKyTvYHctN
X-Google-Smtp-Source: AGHT+IEt2CcNXRFiRilGS3D8rIR4h3jiowAwjzbLzTZ0ZDfDjBFjAhBG5Ji00/GSzUextqK3EVtK9Q==
X-Received: by 2002:a05:6214:238b:b0:6b2:bdcc:f45b with SMTP id 6a1803df08f44-6bb55ada2b7mr43435456d6.47.1722127702827;
        Sat, 27 Jul 2024 17:48:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2e09:b0:6b5:f4e:9d67 with SMTP id
 6a1803df08f44-6bb3c08537als47453546d6.0.-pod-prod-05-us; Sat, 27 Jul 2024
 17:48:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTy8x5rCPmuioHrwRVHD3sKOWRyP4akPZ+kMg4TGdPiP8EgMPpCdYMMrU5YREgWMjvd82DPz+6i0ciZgz24Sv1dJDfIDkJuSqyxw==
X-Received: by 2002:a05:6214:2607:b0:6b5:40d:c2d9 with SMTP id 6a1803df08f44-6bb559baf6cmr62759746d6.19.1722127701987;
        Sat, 27 Jul 2024 17:48:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722127701; cv=none;
        d=google.com; s=arc-20160816;
        b=hR5ZGwI5T3tjwV0mmI/wXcMlS/DEOdhp+OYvPQ072OgF4MthNIPUo9l8orKpu4vLzD
         qhafOZ81Zz9CeAZc3V2gmj1ja/pxoj042t6uEFzKQARH2BFRXcLVbcVbNFUXEtJ/ZGb6
         5fckSQpbI2y3g1ptjp6FqM/8dSPAVKA7stRtEXM+cmXdQ/p4ayn84RuDogk33KKoWzkg
         WECdeD8n5R8pmkgmmhII4K6Izdw7zhmz8Q1n/GVjrX1VVB9LNp1l64welJugHrZNDiS9
         Lz1pZttH3Xf5oDiEKdS8bwG0MaEhVb3+zSADzfqNnL1yWCQuO2uYQwbj/v3vJKbzoDE7
         /J+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SgSU32V9Lvy5ruyGMVryVvxVutfl7ogc3dOB+ZYtZvg=;
        fh=NHFfq/j/rWHP94bByHknyzKqAJRJzQrt4qr9AibEjk0=;
        b=cOpyqDLsupER8+6R0j5Y2pDP1kPGTM6ZC8D5Vg/4QIkQpATh0Ot3X9fi8uFv0f/khy
         2dr1lElZlJLMQPkAviMzYyRUwZuYYwGd5XK9HPKjzGK1e6O6/Pxv0i9A8dvuVCN5ybHg
         b4xjoBODJphYPuHgBy6OuaivPOxDJVyYKJmnBAkrzZrLT9YT6qwP/BVQapJJ5V3iHPDQ
         Pm+2cd/n5pm3NvgTY9t12/PdEO+XjQWzNd1xzFfsfeQi/6K/rhkD1K9MgVWUc3Lzu7tK
         s7zPqs+3cI1pBfyMATFcnfpWoS5kAfMKS3CFdZWLkiaHQJQU9UKwcdJzHSRI8SW1CmR3
         ebhw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Cshcsmb1;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a1d744617asi29345285a.6.2024.07.27.17.48.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 27 Jul 2024 17:48:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 7579561196;
	Sun, 28 Jul 2024 00:48:21 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6D027C4AF09;
	Sun, 28 Jul 2024 00:48:19 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 6.6 4/9] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Sat, 27 Jul 2024 20:48:05 -0400
Message-ID: <20240728004812.1701139-4-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20240728004812.1701139-1-sashal@kernel.org>
References: <20240728004812.1701139-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 6.6.43
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Cshcsmb1;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as
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
index 781146600aa49..46612fb15fc6d 100644
--- a/kernel/rcu/rcutorture.c
+++ b/kernel/rcu/rcutorture.c
@@ -2592,7 +2592,7 @@ static void rcu_torture_fwd_cb_cr(struct rcu_head *rhp)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240728004812.1701139-4-sashal%40kernel.org.
