Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBZHJ5C2QMGQEET7P33I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id E588A94F325
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 18:14:29 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-44fe32a1a4csf57267251cf.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Aug 2024 09:14:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723479269; cv=pass;
        d=google.com; s=arc-20160816;
        b=PrqMFJnvx21WDnfxqwf5/PMG+ukt/ISVaw994uvYqoMqqqOye6dDcfVlR4GMwa39lq
         gzlNz7LL6rGyS8WR3o2wVkIK6jYjzyXZ96fCzyhfB9sMxVqFRvjXsNmU6XY1r4XvkP7J
         fuy7oS5EE/pEfXu+Xd8t9btIvqpPWMzlZdNu02J1aGp+AYsiF/Oq33KcTStq3ed49hLo
         Kfit3XrGB8O5789KArdB5yLqOZ6Zm6Xz6zCovpMb5d5Cg3DO11IQo9CT4artKZFECSSq
         WIeo5rwUSJE2rFAKQfMgW/pss2VUnrztxik6a6I0aIvf4Gj/AAGQvt0jXVq0qddPCgaV
         tEWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:sender
         :dkim-signature;
        bh=qXgNazi/fj9Wq8Ls7DwaJmyQqKiK2uDGRlkxGUXEzZI=;
        fh=vI0hKr2bF+snfI6p1AIYG3Y3mJD6JXesuKoB2sau480=;
        b=ilL7WqvHPQmBQ0E+Lw1Per666fZgKVKCfUUH++MG8wmg9cn5auxIi+lgAinKABrX2q
         LpWSJ6sLpbgictJ5z7K7+koAwEdn9xmN0sxCEgHndVLXXYqnRs6iY3G3sIzC4KTynOuK
         I6w7o646p59Dj0k4kJ0FtWZo2gq/L168Yl/mc0SJSPvHIoG6MgPRdEXQ4Aw/gzobWVmr
         LNZobQynGX141iEgY9cbeuYO/28pganqDPFd41y7jlzohRsw36022yQ8FjEpxStYTO6q
         lp0Hi1hiZBt9AMuYJWjYrneHF+YTJ9gWnldE693zugkyLu5rqolAlYv4DgiJHhMZfkwm
         ec8Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=eoUczXA0;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723479269; x=1724084069; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qXgNazi/fj9Wq8Ls7DwaJmyQqKiK2uDGRlkxGUXEzZI=;
        b=r9pMyW8EzRv+e80CHvmU0dFrE+QBNfHV0Gs9kybozspSN1c4A2oEVJCIamCIiMPm99
         IdMgDqZ2Rskj/EfXoz9yOv3atF6rqwJk0FlKiTtj7FM4YvxzRHMMZwwG+lIuPn7PAGuQ
         0UW6sx3THUqr9axxBva5lS2/j/Y8SPik1rxK35/IbYCWrMGYf/wy9Aua8QKTpxUUEFMq
         XyPusnCeqvUEqSll4zJAvvRUBIUhHFpamoodMIHlUF4Yp7kH4HSPON7M/NKVragCD5MM
         yxCJ/xLssiigdYO6zCfLQttsLkOdL/z9LxinHsWvrI57XMyZBY+IcQGeNpfWYrpTJOKT
         D2YQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723479269; x=1724084069;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:message-id:date:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qXgNazi/fj9Wq8Ls7DwaJmyQqKiK2uDGRlkxGUXEzZI=;
        b=KtivqHcjcj5n+Jfu93LMzPAgjA9JALcFY//MWzwzXd3oxT7yDi5+nIMKwcgPnEErxM
         PaFdOxPWoQJHpDONo3xwakXqeePysQXTh531nWuw5SjZE1PlyUDjvwmZuGv84EmE3+yX
         usaN9dQpLNTgGsTZ0c5kq4X1PURxjJZ+vHjMm8wo4JQnCwz03oz0NfPdcsSNgOTQzNPT
         Nat1L6lVw8ffBspibjdD0p83adMjlA+4ljraO+cnwwxHC+IJvQ6Pio+n/yaQeJwlGNDe
         VErVwTr+D2DNJmMSiccvc8Z0c2xennD/2r1GP86dlVsR6siZLNPUyCNvAjHlxfudiQJB
         qDmw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWDeQ+mSgG007ajgPBUaTLrCL9fPlFcbfN4mjDj4BDE0K8aDU6D9GP7fvuwiJ8E5cdik1zjJHnQayHiFQ/nzvLDszJM4CI1bg==
X-Gm-Message-State: AOJu0YzEvS2E5b9GrM/DKKwGlnVyr6X3AMpn93zOMlJIAC6tNXCBRFYM
	g1dwAExG3IXA6WxsVV25DTgDstZR4UPtQp3VWYLbByIAAZR75EeP
X-Google-Smtp-Source: AGHT+IELbAOMW9FX/rXnPAzKvGfp6FDL1ol2i1N5YInH6dWd+tFaiept8P7i50lyDDrhJVbGnOPGOQ==
X-Received: by 2002:a05:622a:4249:b0:44f:e5fd:4654 with SMTP id d75a77b69052e-45349a6df5cmr10993281cf.43.1723479268650;
        Mon, 12 Aug 2024 09:14:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5813:0:b0:447:ed03:aa4b with SMTP id d75a77b69052e-451d12f6c25ls73841941cf.2.-pod-prod-09-us;
 Mon, 12 Aug 2024 09:14:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVi9z2OQOHIetyvTYsuOFiD/WVEoa+oJykykRZ5TAU/amFaFL5LL/4jDC/WNaBH3+dIujW1u4gEFsqNP2BQ9CRmp9q+YOGIPHhbSw==
X-Received: by 2002:a05:620a:404b:b0:7a1:d40c:c3c9 with SMTP id af79cd13be357-7a4e16190admr72647985a.69.1723479267959;
        Mon, 12 Aug 2024 09:14:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723479267; cv=none;
        d=google.com; s=arc-20160816;
        b=SVBge/yukgW2hliwaZ3exBN9FqeOQgNFdMakpHCc/MoRSXrfT1bXkaGdi89HaNOhsV
         uTUZ5XdmbbnJWsrISLrCyqSPz/nMHDpO3Pm13l5bb6vet/BVdnnNyc1d5FkCVMG+VA4p
         +8hQZcDX/v20NchS8Thcosx+mVXT8fSyJj3CC+QMfQGNyuZJ4ujMSzC3aKIMvGmwr9YC
         eju5+1sl3sQ4jHrKXGe7zivJlyKmi5B6G3mMdWQehcnxQCQS5VeEy/HZ1UwglYGfQRF7
         z9BMDBXkr0vyvhoc9yprjki/w4nd5yhnUOa1Quc2+01L7Q1BGEfsJ5eh5yJRZBg2S2n9
         0GEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:user-agent:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=aIkyUvlrrnZ82YbLXrTZ8f2lI3/oO4fN6qQ4eERaKVI=;
        fh=+Zf9XVYT93rNkJvMi/4JPCjvm6CKgnQ5JePRwHTRxAQ=;
        b=TBfMMR2ZUr01PIFdExBcMqhY8BJERx98UU0/LamIy9mdF46gEbMcOVanHmhpiT8kUw
         X7M7AxG2uFu4zfsbVW0w74mRFoEqnsI7att6GFhpcF7dgTy0ltWDEt6FbEl9F8yHnYw+
         lklaCMj5zVQUzpQfcrVra0Tq0FshHdQwE7EFwpAAx5MwV+lWOf08M8QQ45HCbLuf6URk
         9cc6+V5KiE4QZPGcr4XT8N2V7752JQ6dz+OEwzfQwuLoBJ9E95QrP9xq/mB2hCvt2L5c
         o78N6GorW11ObsHAHHJgyA085P3YgE2VHnE/kceTmIUIGBITG/nUoZqSNd8aE5Pd4mNP
         qrig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=eoUczXA0;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a4c7e01cc9si21151885a.4.2024.08.12.09.14.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Aug 2024 09:14:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 85D42611BB;
	Mon, 12 Aug 2024 16:14:27 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BC7F6C32782;
	Mon, 12 Aug 2024 16:14:26 +0000 (UTC)
From: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
To: stable@vger.kernel.org
Cc: Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	patches@lists.linux.dev,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com,
	Sasha Levin <sashal@kernel.org>
Subject: [PATCH 6.6 026/189] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Mon, 12 Aug 2024 18:01:22 +0200
Message-ID: <20240812160133.152514634@linuxfoundation.org>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <20240812160132.135168257@linuxfoundation.org>
References: <20240812160132.135168257@linuxfoundation.org>
User-Agent: quilt/0.67
X-stable: review
X-Patchwork-Hint: ignore
MIME-Version: 1.0
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=eoUczXA0;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
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

6.6-stable review patch.  If anyone has any objections, please let me know.

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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240812160133.152514634%40linuxfoundation.org.
