Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBW4T7C2QMGQEKU5J22I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 8B5519531E9
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 15:59:57 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6bf6a05cb2esf9889946d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Aug 2024 06:59:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723730396; cv=pass;
        d=google.com; s=arc-20160816;
        b=fCO+1SCCzWKHLJ2D3wcfQy+6U4NFkjvXH/O8IiRlDaRFnbGkDfVkWcRiosTK6+/tsT
         oMflQ0M1wcpuu7lRbgvvCecmxrW4yIL3bJbccMJeyq2ARYzYIzO90oSalO0g6g/mL0cN
         inhNR0SANiBrQzHy+2bd5hT9thdkK5wOhJmnO+ddRDepXTh8QP5wCvmDessUSOb2qa1G
         GeG9gEwtNTJFNZAhhtF3K2TiGJPjZpYcWiDGLQPNFZRFmNoh1BlUXRDWGT48kImWMJdN
         K1IamwakfvmtCPzt+/ywbPtjW76BiAFD2m4JCZwSdQN9reDgoQTsy5ZFO2z0eOHjoM0L
         3c3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=bI23BTZWT6i7s0HYEi+IKgL91dvZGl+u/9hZmUkzrFQ=;
        fh=Z52DY29GNgARBcrTpbzaNmlqbvxD659SOzZLyqQI2eM=;
        b=G2hN8MkfT8wRxJkdGUyaIjzJhCKrAlSFyt8sD+8tbXjqzkxM+jO2ZPe0O2xCXCoUZV
         g3wl8me0exgYe78wtY8/68fmbfJYMoRJtgothXBSsNBuwFlAmsgOF0RuqCOJtWeR15ef
         /p+a9D1I9enZLd8DxHBDQm1ZzpzR2w6UpN9/ulkXhC3a4ek9q82xthIVlQKW58Bder/0
         2ZPG4q6o1TCSiQ44E/K5qyJZavMjk/PF/G7pRF8xDwI4RLn5ZVzpU3QZRvoqVWyedELg
         nDdaf0Vcyr8UxwW3HRl2tsP5HppGeQSFZGqySeirWg2m5lD80FMopdfrq/FH0E0UexWf
         Yi/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=oj2VQ6xk;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723730396; x=1724335196; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bI23BTZWT6i7s0HYEi+IKgL91dvZGl+u/9hZmUkzrFQ=;
        b=jq5SsXogslAMb+fuIcxkEILPl6tP7RnK6tutECEXu7aEBU5yWP5Av8mag+zt+gecZ2
         /ULBH2liiD9Q//NDNs3A5HnGd7hjMSU4U6FmrKRsvDQcBuLTy7xsXhfXnqaSToj3o4Ow
         QXlmS8MQJ2askhW3nmeL8SxgrwGvC/eYS9W6ZmdkudAxefdT7cHSbrBDApBY4R0QQ3HH
         EGqV1+6g0VSvDvGtlTEKboZQ/ALCPAklqm1S1gyRUapj08K00C1VdAtWvCWSW7H2XIZK
         vtl1OZ2TEK00ZcCE+aXbs/PO3rv/DV7TyQr8QVJZ1bl4JCuMokXcTBENqJ6NebG3N/wD
         wOhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723730396; x=1724335196;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bI23BTZWT6i7s0HYEi+IKgL91dvZGl+u/9hZmUkzrFQ=;
        b=MvcIXAKFVl+32bvcdkucYEAvgrgETyScbJYLFJsl1q6VJSv1h/iJpXvCv2nrheKk4l
         cXPkOQDlesa6utOpkS8R0hiPt0/GKxucCg3pnlYl6ZTKZo4s9V9gJpFBDykCQWVe8Prs
         aKC8wZdMpW3+3Qp8q1dOZRWvGvrnnSv97a0jlwBDx8UTYTd+sfsIp+fkArOUgRIcBVnB
         9HuubAIfUiuE2vep2qbYE4yABk8U5QYJ8OvtbYkViKLiNhktEd3b+XiYWpmIxEG6C9WE
         DvAlEaFFzTwY9xPBLttbhxab0tpRS/5njnS8HhthjOs5hYq4rSCssaCI5rhgXEx1xGzw
         phiA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVnSKffz7lofMVVQ6Ou+rv0EBpkmPHu5DrK4avQq0HLIvBQWlwRK6vFAMJd9ZUYjT2ieA90Y+DaqSPBI+bo0xDWT9vTZum59Q==
X-Gm-Message-State: AOJu0YxYVU4eA67bIZWukZiKjY7z8Onokhu0lHRQuc8LP1UBEodvygh9
	D0c1uvV13mLqGLKSuLxnVIo9ovvQZlZyC67b+5athtnFZeB2qnl7
X-Google-Smtp-Source: AGHT+IHzJBbDN0Mh1ZSVi3GxW54A0m1AoTy74K2kZUYuMElJtj98RlUXsWISAVOLRi4MztuvBoC8Yg==
X-Received: by 2002:a05:6214:460d:b0:6bf:78ad:ebc8 with SMTP id 6a1803df08f44-6bf78adf931mr15556266d6.24.1723730396020;
        Thu, 15 Aug 2024 06:59:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:e87:b0:6b0:7204:3b2 with SMTP id
 6a1803df08f44-6bf6d92b5dcls16124106d6.2.-pod-prod-09-us; Thu, 15 Aug 2024
 06:59:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2yIQZgukNQ0g55vpJqnIOVqTnYE6MgNOd7f3zNjLP9N8xCTTBkZ5sbM6UvajtFYHBehAr95xi+1t3srVOqoj3LOFnEY+KK7Q1OQ==
X-Received: by 2002:a05:6122:411a:b0:4f5:28e3:5a5a with SMTP id 71dfb90a1353d-4fad1c3b117mr7435523e0c.4.1723730395141;
        Thu, 15 Aug 2024 06:59:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723730395; cv=none;
        d=google.com; s=arc-20160816;
        b=Z2T7QLyXcsAKyfiw18KLEX2/3UXi/0JsJjAiRLkpoOmM3D4wtT6qzoIZyQdbJ89J+H
         p5jta6bfkjIbWZTSw6VWmkWvKTiEwCFCzWyS3RrhpwZFQ3hjN8ZtW/0jo6YngV/8kZmY
         i654fNF9QmgzhjznHJoHD5vgTLKuMK3bj7KHzdvu5vuvPKIuyOuk9KGMguEyVjANYu8U
         7aXOvYDNR/NXKN3RbUWcHC+Ale4DBK131Z0dBV3azvD4Yz+ZyycNvyWuHJHyEB5jQZpk
         1W27N+gBDI3CldN4dELJBfAfAd6Ed7J815fgWl8j4k72gbARpjcpkMPMEY+CTwhBg0wV
         Hi2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=WbM92fOiXTsEdAemuO0oohfNbS8MnvAtXKsysak2VqA=;
        fh=+Zf9XVYT93rNkJvMi/4JPCjvm6CKgnQ5JePRwHTRxAQ=;
        b=b+mMEvX5IXhxxjGfIP6bjENHcpBtXwqwbbULL0hccLkrBK3Am5yUP6i0ndaYcr2aEq
         +fdrw/go6bo+fqLrygsATPcs0bONVEQ6il1pApvZ9t326zm3fN36QbpXmwjW0p48J5ah
         XUYB9AeBUUxtRi93rdp/p5MA364jwi4sCbMinglxMVE6D86OXgsIFKTZJfgQ2B7NFdYE
         mQSazKrfOxdPTC38IEMBD/BveycO5d/r37YyrC6ktIUh3qBZi9d8rsO9ycUgHfyp8hgR
         rZQNzTcZG3RkwB3mRCFQ/gU6n1IXNZVhPHOJWIYq/toL0CQMRdHgcAXxTYSjL7eyDXcp
         ctBg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=oj2VQ6xk;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-4fc5b8cf564si68277e0c.1.2024.08.15.06.59.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Aug 2024 06:59:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id A1E8161D52;
	Thu, 15 Aug 2024 13:59:54 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id EEF3CC32786;
	Thu, 15 Aug 2024 13:59:53 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: stable@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	patches@lists.linux.dev,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH 5.15 367/484] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Thu, 15 Aug 2024 15:23:45 +0200
Message-ID: <20240815131955.611546451@linuxfoundation.org>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <20240815131941.255804951@linuxfoundation.org>
References: <20240815131941.255804951@linuxfoundation.org>
User-Agent: quilt/0.67
X-stable: review
X-Patchwork-Hint: ignore
MIME-Version: 1.0
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=oj2VQ6xk;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
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

5.15-stable review patch.  If anyone has any objections, please let me know.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240815131955.611546451%40linuxfoundation.org.
