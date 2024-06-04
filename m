Return-Path: <kasan-dev+bncBCS4VDMYRUNBB55N72ZAMGQEUTCGH4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x1140.google.com (mail-yw1-x1140.google.com [IPv6:2607:f8b0:4864:20::1140])
	by mail.lfdr.de (Postfix) with ESMTPS id 03BCB8FBF09
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Jun 2024 00:36:41 +0200 (CEST)
Received: by mail-yw1-x1140.google.com with SMTP id 00721157ae682-62a08099116sf917597b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Jun 2024 15:36:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1717540599; cv=pass;
        d=google.com; s=arc-20160816;
        b=kKjz/UtxYlkPdukLPLVX53oR/Hr/yG7V1P9Qq7bSvBg3vkiNMAEhHUwWFH+gzAazdv
         qc1CWqBVdGX5p/XVDYSH+zPJhM8izjXEW5BBQ6etvxEU4Av7JhYsmZ+P2gxzE/TvsA6m
         CEV25rhdIkH6hMqkKh3Wg3oUhv4/YXE6cZva6ZwsqNLY04PmiGo9aouL0iuEsic5lrDl
         FhJOm810ybqMZtyBvoTw/sTeI2NIMwgv7JHBQNZNBXnZ77SXHoUsH/EuhgKjzScCBbVa
         H5aMDOHf4u3V3ndiqbFmkRwQbdMQU/NnCeSsOTui3joZYLZXIqhFoaTioCofY/AGLIU6
         AGKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=h45eLmNjTdJZcRZ/U//652FLKpiJUVWN1kfnJh5qJe0=;
        fh=hg5Z1gwa9MZR2G9ebFaGfHom1x4SdT+/iy3tkYSXiU4=;
        b=T5YI9jxKpy2KAODFVQWoz2RySHyxPBmkzo1Dcqsn/Ll0fDIdhtIHYUd0k8IyQUSI0u
         4h3PnBhW2Bti0SK1o7A5kwlwWno6S4WvamCdaz6QVagBw8cW0+uEtCFlEbPD4UYXqoBq
         sZJoY3uzp93VbNlBa9U1n7LODgeCAJph+jFBffJsY5UkiF3bC/Zi+szE4NUDjDJuTV/x
         sKWPKeijjYlp6DzIUOiBOLKc/Jp1aq6ZSXceFBjdVxaaQdKervWV/csPRFszh4w4+AYX
         vVaulUCkIj352qgD5GJxe6HVcL009sUCVm92gebgCeFeK5JDLHJu3r94TzO8dTeQG3eD
         Lcww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fjtHMhPW;
       spf=pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1717540599; x=1718145399; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=h45eLmNjTdJZcRZ/U//652FLKpiJUVWN1kfnJh5qJe0=;
        b=VT7BnTXeNxwr4qY9YzDyyXK+1QZl1xx3gROwM2+a38Ga7ZAPZsM4XibaWpxovSxGXh
         auLw0RH8vGL2JPE2Wegga3/UeyFEBRxzlMr+1V94XAXMdL9T3ly3JJM+jLEqVxgxDk2E
         uV/OM+FTNWz3y94T528ofIcpxFtWmu+wwANAXDqYPMgwNlRR2JEKmj1ydu/CYNeaqnbZ
         RF65xyC4ZYUsRQ/L0bvs9v804Xydihase5MFzvwQ/2cIjVvB+8Hqe+DBbn0Czs+v/Rnb
         nN2so2FWTS019n8zpJgnHA3Bct119IA/9EHUfPrnvccJj4VBb9JkEZlS7anmcnNjQEY3
         t2HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1717540599; x=1718145399;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=h45eLmNjTdJZcRZ/U//652FLKpiJUVWN1kfnJh5qJe0=;
        b=DeFbj5QcZQlEuUWhJFByaIn0DrFQfBMnLIMg0JreydRhQ5LQWn0KgXioLmc3oWwGp0
         Q37r+VoOlcYrLocWAJhZhi8NcfidqM7itDmu4cpdibjaLCEOhsUcvzADBWu+5xgLMrFy
         7vSqbg1uaKmtw37oLjriZuj8ITRom+Rb6HiielypPpvpXaKZHa++9z7ZzMZHpFjc+Vn1
         hhQ9ZYKZQ/+fDR7LAtLegRu6A8j801cAE1Yv483wSxyJ6U34crYEdKhqDt7swetxXRru
         u8s9cEUaV03WsCGjdG68seBuasf3XjOMhbxuXk6fipoeJJ248n+jQ/XhViS9Ox5L8DkE
         7OGg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVVnEHTKtPt09JeaWAD1/67Rtub+Ec7yKINIEFIrhkAxy/Z1s3J+wOwL34YlYQsEfMG00UzK8s4dCvusdNewPEvzYBKsoef4w==
X-Gm-Message-State: AOJu0YzGv1Mu967XAA6V6Vopniyt4AeurRzXkcQuIzqMCj/UnLuqQ5ZV
	QqRqY3m6WwccjCAXg5vXLcNhtB2m56B/tlihwLTDaFrQQYt+fTID
X-Google-Smtp-Source: AGHT+IEOklBp010EJ3HZu00klYut/bl6MJ51J/+1z6tRhJjJtPyefLalEg5mX/LRYk14z6IFIN5j4g==
X-Received: by 2002:a05:6902:2481:b0:df7:a3c6:c849 with SMTP id 3f1490d57ef6-dfacad59181mr538807276.4.1717540599271;
        Tue, 04 Jun 2024 15:36:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:550b:0:b0:dfa:7b7c:c81 with SMTP id 3f1490d57ef6-dfa7b7c0ffals2075618276.2.-pod-prod-07-us;
 Tue, 04 Jun 2024 15:36:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVLMvUt3sI2BCoaNmMSppf1kQvO3WpkxJvLHbtxyqZX5Pi6C+gXxBDr9yKp2GT0fBEalF/YEtasvqUkce7UxrQIobjw98HrE/INFg==
X-Received: by 2002:a25:9744:0:b0:dfa:471c:b26 with SMTP id 3f1490d57ef6-dfacac4a276mr802007276.15.1717540598238;
        Tue, 04 Jun 2024 15:36:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1717540598; cv=none;
        d=google.com; s=arc-20160816;
        b=P31aw3rTWVX5hGtJUhpPszNyD/nG/GcAazUnjn3XZvjg3HgI6/gKW5k+h64ouPNe5O
         NS1RyRM1sBk9jyaHRMQDv0PHJsUM39uJXv0PTXjxebwnzQqRjBlew68uv/vn0ss6+4iD
         RP7PyPEEQxCTtDfcGGoNG0TFmEblsIdaoDNGyBsIOL04g+VwG80+d+zUqlAklURG5aOs
         go1okAzdPVxI6lCLIl1XJ5cQBH8KQ7ibOELuA8ago/+AD4fPJT3HF1SIS9yRGchl7KKc
         xzaAyTiQJxPwZneYqTP4TTt8NLB/ncSTlIZaEGzqml2m0ujC0qD0XB/K6dtZdu9RU3NH
         T59Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=chb9X1EdNZO7eVwZukx05DsmvpaRvgAKv7ZsRMoWBM0=;
        fh=f8E1eMpO3U3yPJt6moXL1m3uGC8xSawVJE6XK5RxOoU=;
        b=nyu5Qo8218uz6uqF79o+9M7anuUl02AGTjpaL74yKXxYAE7nw911U/EagB0TaM7p8l
         tBQhI04xMSUcWbVV6r2on5NNTVQA7tvberZCKFiiwTrSqTuyYAY6+eRSXhCOlo0b6S3T
         CXfVeP3C85OEfBgk1VGz0EndWUFqrqhQYcxQP0rBDYgXbQbnHxo8e/4LAMjyld7f6UuX
         HWgN3UXCrdMtzt2cjtrntZXyRdoLVYPEEaNcXQqHW7gM2zMoP0k7Mu6PLqYU1gktWavi
         7dK2xwJgMSDumyRLi+j2RR7J5YUF72qEShXnf6mdaWg3bOU25/QQno9CofhOEITq17CS
         eMeQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fjtHMhPW;
       spf=pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-dfaccef4be1si13675276.0.2024.06.04.15.36.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 04 Jun 2024 15:36:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id CFD37CE123D;
	Tue,  4 Jun 2024 22:36:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2B587C2BBFC;
	Tue,  4 Jun 2024 22:36:35 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id DF4C3CE3F0F; Tue,  4 Jun 2024 15:36:34 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: rcu@vger.kernel.org
Cc: linux-kernel@vger.kernel.org,
	kernel-team@meta.com,
	rostedt@goodmis.org,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH rcu 2/4] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Tue,  4 Jun 2024 15:36:31 -0700
Message-Id: <20240604223633.2371664-2-paulmck@kernel.org>
X-Mailer: git-send-email 2.40.1
In-Reply-To: <e14ba19e-53aa-4ec1-b58d-6444ffec07c6@paulmck-laptop>
References: <e14ba19e-53aa-4ec1-b58d-6444ffec07c6@paulmck-laptop>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fjtHMhPW;       spf=pass
 (google.com: domain of srs0=8uga=ng=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 145.40.73.55 as permitted sender) smtp.mailfrom="SRS0=8uGa=NG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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
Cc: Marco Elver <elver@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>
Cc: <kasan-dev@googlegroups.com>
---
 kernel/rcu/rcutorture.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/kernel/rcu/rcutorture.c b/kernel/rcu/rcutorture.c
index 44cc455e1b615..cafe047d046e8 100644
--- a/kernel/rcu/rcutorture.c
+++ b/kernel/rcu/rcutorture.c
@@ -2630,7 +2630,7 @@ static void rcu_torture_fwd_cb_cr(struct rcu_head *rhp)
 	spin_lock_irqsave(&rfp->rcu_fwd_lock, flags);
 	rfcpp = rfp->rcu_fwd_cb_tail;
 	rfp->rcu_fwd_cb_tail = &rfcp->rfc_next;
-	WRITE_ONCE(*rfcpp, rfcp);
+	smp_store_release(rfcpp, rfcp);
 	WRITE_ONCE(rfp->n_launders_cb, rfp->n_launders_cb + 1);
 	i = ((jiffies - rfp->rcu_fwd_startat) / (HZ / FWD_CBS_HIST_DIV));
 	if (i >= ARRAY_SIZE(rfp->n_launders_hist))
-- 
2.40.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240604223633.2371664-2-paulmck%40kernel.org.
