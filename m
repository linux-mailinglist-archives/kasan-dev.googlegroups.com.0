Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBQHF5C2QMGQEB67KMYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id E172694F258
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 18:05:22 +0200 (CEST)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-44fefc0296esf94317211cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 09:05:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723478721; cv=pass;
        d=google.com; s=arc-20160816;
        b=YUkM8jAXDdCJLrg+i32tCn2szbluE/tnqkShC1dBXiqQ+28zD3bzzJfFm4eAqrNuEq
         N0r+9GhHW+DRqfx2Dskh9Q1jPAIH5RtuSyyeKEnQIYIWlSvZx5kTVoFpfzGmaRSCj3m1
         volH7dYf3+RuMoaUGIqWJhE2WFX2s/mH+Ju7Sb8j24jecVdLLISGs9lgV5xlXcpIUz3d
         CBH59/2MLuoKmJYK4dFKzj2mn3NNrcuokGiOFnPBugN8RZdVQwwmti0mNKyxdb2rMIlw
         TwVQ81bniQ52tXzztlnMhQjv3g3DEf3yuVBHfz+G3/NJXOsABiGdA5ZVkLqIlRazO755
         SC2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=AmEZCQhFrGP0v5z8LbGBFc1hpxzL8Oc8AU9CfxcXvc8=;
        fh=XXvK3Wo754TUGK0zVT8v/xi3vAERKfMKL/NkgM8ZgRI=;
        b=lR6xPwIQcGupJIu7eWheQvThXTOHyRbXpCLy9mIikVXJpBZpWVqWHzZboAoK6UqbSj
         eLb8mjk/jwauFkmlacGzu445RzGADubC/P4G0Bn1PzBwF/Cs/TY8nmElIR1UAdgpGOWT
         BnPQcMUhdXehUXJmu64QJ5cirwGnD+cKX+MimNsPFJsHN5f8hWLtf7+ms/+IQbOdY8Qh
         j6RYdhpCu75RDGaXO7lip8wJandtoK2Xuu3hjz31We9uKOhpDf8U2KfacOitQL1+Poyc
         /lsZ8FSRrjinfI7rGzGncJPJPVSIUZxRh+HkOF+RscKw0SX0gxkTDnUt94gaNUkib66g
         cHvw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=xKXEoQ3N;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723478721; x=1724083521; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AmEZCQhFrGP0v5z8LbGBFc1hpxzL8Oc8AU9CfxcXvc8=;
        b=WK8Aj3TyYP8ciMU/JWFhvD1H6NX8VtWqv0tKCTeC+SqsloOlfIyXSXUdSx00ekRrBi
         0tqCrQrp+2NSXnwVqTrEOqZwf69RkVJy/Wghncswj7L7Ig1i3m4JZm0MWcBoOKjN25oM
         XL22RLOHs1wojsTBOqpSmtISmIr2hLJ5s6FuoMFwAWaECh3Lehtq1upokpr3wZLY3Um/
         yi73gCmjRiLJOoGyMVtPRjGbLVerq59O4htQVeSHhst2haq9qarl5DER6BY/LSCibgHi
         cdZ8oSM5ViJvy8DdWYN52WpudfoBh5p3h5WVP67OH/Po5wkbejfz54FqyVzqNqgSGf8I
         X+hg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723478721; x=1724083521;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AmEZCQhFrGP0v5z8LbGBFc1hpxzL8Oc8AU9CfxcXvc8=;
        b=YnXMB1Is4FpFSWsvvf2VOwcyShZxWAf8e68WGpfAxJ/X5yjv7N/hgwKbArLvcSP6tC
         o0+VgeX9qQFHAHt7Qk2df8CUu+ocv4fr2bWqNvua0sk/V74DYisMnfN94dIZi5FXGNet
         rp0i1aZXkRSRxqx0csWZayUiP0iR7q10uXPcgt4diA101MjFx1Bb/7tUQ+a6vevj+gL6
         ODLKLENAUqW+4Wsz5WB43GQ2ulV+J5XpfpLjpBEyaHuRGpCOfA1EKfKFLQiAdUf7UboA
         DnT06SSc37LS+NfUWsoplteT9YTnBntMs9jW0DKzGgqy/SymzkkDWPpKiPN9RSlZjmHh
         e7hQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVd1TGmkzH0e1qU1nxHhTuYxtecchIcb7sg1tZzWftU3vNuox5XsoylLrdBfs5xHebPgK7/W2YpKlzMTAdu/1Hf61kuHs7FQQ==
X-Gm-Message-State: AOJu0Yy6eq0T7TWWkkFkvS7ghAjvZgw/MXUhxMWK3BqkLNy25kVP4rJ8
	q/q4UrT7E4rcOefDTD2t4t5nLniI2a1innr+JgZLI4WRNDFcFNdR
X-Google-Smtp-Source: AGHT+IF9Y4NGC85PLjDhguJBv6maCXCP8eSlSuKJmMZIlUTBEvTE+cNQU5y+knwcLEvJgmVq+qvccA==
X-Received: by 2002:a05:622a:164c:b0:447:e4df:1865 with SMTP id d75a77b69052e-4534cacd1b0mr1854291cf.13.1723478720978;
        Mon, 12 Aug 2024 09:05:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:19a4:b0:440:38e6:c194 with SMTP id
 d75a77b69052e-451d132b28als6682161cf.2.-pod-prod-00-us; Mon, 12 Aug 2024
 09:05:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsGdGrpTBUl1zZmYLEDA6wDx4J8BbctM/yV9QkGtWs462Ba8aVAoxdUM4pYfP+VmBOW11kp2TsTYngC+9I8LBQ5HngI8CX39ge3g==
X-Received: by 2002:a05:622a:2598:b0:453:1334:9725 with SMTP id d75a77b69052e-4534ca71b95mr2641511cf.3.1723478719857;
        Mon, 12 Aug 2024 09:05:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723478719; cv=none;
        d=google.com; s=arc-20160816;
        b=i+UtAxqye05/9NpNbSWwyxFDi67x/yqWOfTT3wY96BoKDYuBkZ3I+TyGNp08SiC4Vf
         U1WIlvs0GnUcrpSRvuZZgSJuJdNS67bvsECfXTy4T+qPrwqaM4Ris7PpTMF21P225ZeJ
         AVuxuPKoadhsD1Lgy/qCZaAcFJzY2h6p8YfFJvHfTj+r8b80qcetw62JqjMEFMduE/ou
         9uUBZvBkai6+4TiIIxpckmVHYTchNL4jqbf9agTG/7SBt5vrCnqgzrZPnijH6dfO+fPp
         vHflj24P0sDcxGahQEVwJlIXkMYN23FJsHM3RZ+cI1mvccUexG8nvg/Zc+NmF0J8VJiw
         a9Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=vVtlSQFnWCSpNSsChJOeu01Lg8gSHg0CIcCBEYxMeHs=;
        fh=+Zf9XVYT93rNkJvMi/4JPCjvm6CKgnQ5JePRwHTRxAQ=;
        b=xMR1fitETTWhnHrKYBRewd9S3pqULkhMjpw8arU2FAZqlquRwvndmE72I1cv1b65Y1
         ykHP01tw3tED7yRs3e3PJYwk1DVt/Irp9PbPkQmSQ8A+dM3iueKbMG8GXIqrSxWaUZbx
         99AH5J4wmgph+aeoGtIYvl7m+ugYbbCPy7Djo+O5gf8svPnqfCEi5OKAYvmA1CPs8+q4
         S7UGVGU7vIVwAUqPfqSq+oVRbu2ta0ppeorVCGYpTarvm7flDAAnLbCKZ832QYGCj/K/
         fDnODbQGgI4au6byOQrCArTQLjtRPhC5PswJJac5mPw51sEVr+L0ep9C+ZMJP1oz43Jd
         QlmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=xKXEoQ3N;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4531c1a434bsi2166581cf.1.2024.08.12.09.05.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Aug 2024 09:05:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id C43D0CE0AD6;
	Mon, 12 Aug 2024 16:05:16 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id CA479C32782;
	Mon, 12 Aug 2024 16:05:14 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: stable@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	patches@lists.linux.dev,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH 6.1 016/150] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Mon, 12 Aug 2024 18:01:37 +0200
Message-ID: <20240812160125.786769750@linuxfoundation.org>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <20240812160125.139701076@linuxfoundation.org>
References: <20240812160125.139701076@linuxfoundation.org>
User-Agent: quilt/0.67
X-stable: review
X-Patchwork-Hint: ignore
MIME-Version: 1.0
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=xKXEoQ3N;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
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

6.1-stable review patch.  If anyone has any objections, please let me know.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812160125.786769750%40linuxfoundation.org.
