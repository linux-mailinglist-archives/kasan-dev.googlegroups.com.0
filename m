Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBYFF7C2QMGQESPZADUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id B7B42953579
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 16:38:25 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-39d10b6da2dsf10060105ab.0
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 07:38:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723732704; cv=pass;
        d=google.com; s=arc-20160816;
        b=LliDhkjKcL2zckiixhWspWsh7+194OwcnDDCLSwSY6p4EuQmyA/cH8oIbwz1u0tmC1
         V5OQEnopqLol++uOUN8J4OhgJrS202D/13FSG2LiINzYZ5o/VXhos0fDU61CUDt6U4MU
         IWCA4sG4zrGZ+uSk1LT6fnLwOV21rQisvQ9jIeBEpqDB3X/LD4zNNw7DCddutyIgncvT
         kgFOSamx5P4iZrIXCoAxgAkdwPN1c2DzWD8SGplI4TTotqMGRwvCKWDXCJDyPI70Ot8X
         JpRnJzoupgrb+O6qwlYlW5BNq7Mml9b1o7JPxWtEwKMsrNdy4lEQHt+yX4L5ZbJV1G3W
         vetA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=d1TxM8eC/iv7QWa9KoPRu1+BOjevPXC6kzsJZ6ZVWO8=;
        fh=v79NTcb01EKm/6vaRcg2cBn1Y0f9T3RwXCT3hk3xOt0=;
        b=iKNNEuEB2cJndLb1gP5T4bPhgnajt4ZvNuNQUETKofe4TwPWKLkLUFPbV1Xr8eV0jm
         BaL20cEeB927fxfDjliCCnLGOe7rk4xERuYqC4+kvxN7vpTrvokX53LSAPB/o5cCd3oR
         AWYyuISaN3qJbrhqGNpWj572y2tZoR9nyuq0NOqSgqOO2BWtbFYGBE08yLE2Ti09xNFV
         SOSQyyv6B16fVEbJTFimxiRuq4CWs5Kuud9qv9CcDlBlXVb4kS8rydG/zbIQI7HGbbCQ
         bDjg5NLMmH/mRJkMXbO6zld5bv6dP+raTL+z/tpbNgkWUcGSbpqiNIt7J7sBKHi/qcsI
         Fycg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="k4S/LXyJ";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723732704; x=1724337504; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d1TxM8eC/iv7QWa9KoPRu1+BOjevPXC6kzsJZ6ZVWO8=;
        b=gEF6TH1e9jxs7aFFFuoPN4AXk3XE3lHdrzY646vutoKEsvUdPqhqCdxKeZ95EXkpaC
         4bWbGWsoMydao2C0V0l/03wAUt1k6fdWlUitT2f1yiGM3rfEZo0JFblW+k33J8FHtBI+
         W4iPaLNMsSW/XX04GNzlAB5auGEk1/+MdP50+AvUraI+415AEPIP/5keHAbY0bmkhpko
         fM0PpDdjgAHDQlYSWvLZ1oxS5u99gEYBc9RVqzV4c2rJnp9yAiC66htlWZ/ql9ifSZ4a
         M89l1vcJAEeXr9tTyzUfMq7KOtLHHTqCb41oAzbhgqx7jKXCcnMPXrVR42qqNwUsO/EV
         IcCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723732704; x=1724337504;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=d1TxM8eC/iv7QWa9KoPRu1+BOjevPXC6kzsJZ6ZVWO8=;
        b=NTULyWmj6tOVUfVGhwWTjUwxAPlHMvMBVqDryUshYN7i/nhyxhHAz97vURc2mDi8e5
         NEV9omUd/DGhLp8vdeHg0JIlwgDcGd3ZJGSVywfjAF10KGnsw5vW+Pcxjd8PcsUEfmhi
         PU6XaxwIxY1CZhjUtiIJQd69U6QpAH9K02HfrvWTJkopgGOK3k2i6UIL5aVngAHG+TwF
         98vIDfxZEqlVeZGbTZ6N9K6u3IQOg4AhEcIH7lGkzwaWONr88iUOyurDxWF1jwrfhVrB
         e0xfRZ3YI0aTx3Mn4c1SK0pb71aQ2pOs+vqU58NlKEvpuZ61LWZW4CP+qfIc4AetCk9c
         4a8w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU3JwfHqOKCDtTu6mG2kBtA3oTcDA8ZCMzAJ3KZaPaQ4e3qxl0FJns4pAPktyVTKIgRpYBKule0DX9A0A5nDOIwBZio5uKFfA==
X-Gm-Message-State: AOJu0Ywb4AN4FHfBiRzGwKTl5fZ93wRQHXb70wCWJB6S/PAKBKEHM2+R
	Jl1ufKehJYbSlU1KZE5IlT0CSMdoiyzI32Zq8Y7hwEzsIqdv0lbS
X-Google-Smtp-Source: AGHT+IGpJTuea5CUErOyYSLZ74OD8igYIOon/6icOnN8Y4QuB8raUsR0pojm+hiHM1QnJ2upcPECsQ==
X-Received: by 2002:a05:6e02:1e08:b0:397:a41d:aa8e with SMTP id e9e14a558f8ab-39d26c42d03mr756305ab.0.1723732704286;
        Thu, 15 Aug 2024 07:38:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c54e:0:b0:375:a4ed:3509 with SMTP id e9e14a558f8ab-39d1bc97693ls5856485ab.2.-pod-prod-03-us;
 Thu, 15 Aug 2024 07:38:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVuLCMBTpf4Ls8bdNrCqxvtsSvDjmMdYhANvUXk0/AkN0AnUhHcHomxj/uEqxBd99Qon9yNQxwEsA/wrA/hO4PWquBfotiYxy6kSg==
X-Received: by 2002:a05:6602:13c1:b0:803:5e55:ecb2 with SMTP id ca18e2360f4ac-824f2514b9dmr5776639f.0.1723732703491;
        Thu, 15 Aug 2024 07:38:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723732703; cv=none;
        d=google.com; s=arc-20160816;
        b=geHkAj1ziQ8K1bToD2i7Mhi8AE/kC9ogrh57oqPixHt7e1kUYg4MphZ8Z1tjRx4b5c
         hihtKMoJMZW60Yg54txYoFz08eQdTgJG+oHfAJLmx7sAKpU6oO8iuhqAglmFhzbOeHfV
         dYpW8bizgY6gbRdm7FaZld2n30GJzDa1R2qtgdb0XeVNCiukgRgCHxahh5L/Tr2ZaTWu
         NzuL2kYdcufQv3NR8z5lF/dbr5ogCqbV1HF110e7uguR6yU7PZk+slpaYNHuGY7EDP/E
         GnId60ibrofSloeBGQtvfFOZ0NGjibPNvDCEEhbrKp3bMazcIlptScyt5vDJbk/g+jdB
         FzHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=UTF6rqo6dnnTNcTJ1HgVFKsxS9b7J4lltBlURS5uNX8=;
        fh=+Zf9XVYT93rNkJvMi/4JPCjvm6CKgnQ5JePRwHTRxAQ=;
        b=PjZS7JD9vveqMgK2HfNevITlHR6zAOJWCdEisLaGx55TglU9dQcA+rCBeRfv5FlmVw
         tx21U3Q1fMfJlcg93IZ+WvCVHYWsr/aMm1xNFj+lPz5UoRfpCTcYzLttoF/SttqkNlSZ
         dyGbkOE8LEgz348BD7JAZOA1iZze03p3Ov8N4OXW95Og1umXcZH5z3cmP+tcmOtTriMR
         qPXJVAUb1Xu9qxi/wXUSdE/D0NlqH2eUW7aNbvecRsOzNvluctcYel9t/NadAmkLaH3w
         EJxUlQO0oX469PUSCEOnzCpwc9eP/OIu4ZkfVqA5uix8oU5bFp7z0dt43o6Q19CdjQKV
         wMMA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b="k4S/LXyJ";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4ccd6f4c80fsi52041173.6.2024.08.15.07.38.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Aug 2024 07:38:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2DEFD61ED0;
	Thu, 15 Aug 2024 14:38:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 65E88C32786;
	Thu, 15 Aug 2024 14:38:22 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: stable@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	patches@lists.linux.dev,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH 5.10 261/352] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Thu, 15 Aug 2024 15:25:27 +0200
Message-ID: <20240815131929.532094273@linuxfoundation.org>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <20240815131919.196120297@linuxfoundation.org>
References: <20240815131919.196120297@linuxfoundation.org>
User-Agent: quilt/0.67
X-stable: review
X-Patchwork-Hint: ignore
MIME-Version: 1.0
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b="k4S/LXyJ";
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

5.10-stable review patch.  If anyone has any objections, please let me know.

------------------

From: Paul E. McKenney <paulmck@kernel.org>

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
index 9f505688291e5..5c4bdbe76df04 100644
--- a/kernel/rcu/rcutorture.c
+++ b/kernel/rcu/rcutorture.c
@@ -1867,7 +1867,7 @@ static void rcu_torture_fwd_cb_cr(struct rcu_head *rhp)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240815131929.532094273%40linuxfoundation.org.
