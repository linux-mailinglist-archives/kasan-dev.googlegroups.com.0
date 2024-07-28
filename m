Return-Path: <kasan-dev+bncBC5JXFXXVEGRBBVLS22QMGQEA4JCLYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id C4FEF93E1B0
	for <lists+kasan-dev@lfdr.de>; Sun, 28 Jul 2024 02:49:11 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-6b7a4c02488sf28881976d6.0
        for <lists+kasan-dev@lfdr.de>; Sat, 27 Jul 2024 17:49:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722127750; cv=pass;
        d=google.com; s=arc-20160816;
        b=JLTPsp2Z/Zej5m1Noph/L38h6q9B/SnS6w00xZp2OQF9KonyHnArMA3VmSGliv9Vcr
         ewQveqlqdPsdLbYxDYSn7lXfmGribuVkFLHNUQmVUqWtJLmQUMO25xMinT0jLIe5u9wb
         UbhrM8wXE26mWVtxXMPG/H12u2z6MXvvnznSoKq8ajdGYpYLK7UvDm4iONHdkT3FAPV7
         iezAKPtNlUh7rONRAmoNB4oFK5HoxksvQxJmxfeCURRlOg8J0h2DyIKYN6WTwdU4p4dZ
         MlceykDQQXewgquQrTBc3YJG1tA7FeLqUTNqkn/ZurjRVUVgenGIjPirHvT6hLv0ijBU
         Zxpg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=RDVV0uReEJ6Wk22tKbdSTEyZE25vuzuj3bvLASOYR0s=;
        fh=SPSHF61F14DQ/I8JWLPVkni8TBeXXPsP8UhIPcd5YVs=;
        b=nTEhgRNMiQMEHI/mjuUkeM2hNXjrsEOk2pes+RLQxWaoArZhT+RB1Gvnkmgrmi/8L7
         tTEs9UrIEHnnpo0kz8vGkYIVRM3ErE7haKMovRXCYY4OG4TAoPCrfuDvK23hoKp9AFY3
         EfbZHBiwsnIXv17VN1DN18eIhDXlZZkKKrgyOq6NA3lIen3geUGMC0GKwqKNSkeyyvUz
         d8AtkSQkmI3+efgx1zGexYfYq41224Xo1XDVoqnGy78HVHF6cpUsfoTp54rOoLvOby3G
         V5ZQFUgE0EzdTKSwXy85Jkz4nZVzRR5qLGPkFoMsqCaAvArc/9zZdTHJD/JAh4Zd5NiC
         aaLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=loQTUp7I;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722127750; x=1722732550; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=RDVV0uReEJ6Wk22tKbdSTEyZE25vuzuj3bvLASOYR0s=;
        b=xqc0pBXztu2bjmNdwwykZ828cuvfMlFoYlrzam0Xw9CZQe07WgQQizd2A6MVzThmsP
         Ed4qMLihj4QSMnfEsRTO/7qiEEkRccJNNO9gzOYGeedJ8B3xfl+A5txNwyEn8M1qYR/q
         9OmHBkXeuUJFduitig0vEXQlFTfq2EbcwCEYn8d5TqcufhbDIiPvcbaO8aUsWOyeQPV7
         PYjGW/OEBCjsw28/yG0h5dpWHSehF1w0Q21jNeq6IuSahajljiq7TTMkDV3dIIVU2nyT
         GOpb4cGjqVrQSCJAl2xw6hNRtPXa3pHyFMmxi1gCCyzawcpYpQwcJpXwCvzFxlp/5zZr
         sxaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722127750; x=1722732550;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RDVV0uReEJ6Wk22tKbdSTEyZE25vuzuj3bvLASOYR0s=;
        b=rBbkk0SXTJHfYaYATvxBZ8avPlPtBJrJE1C2gGVpGeLYwexYSHeLeoyZrMcCzXjxYO
         EGTQ2mXJUn2vMNhSpZXBQaE3vDhaipu4JmCOWHlog3eTqNfliCT05OrOvMIL2ad7qHFh
         u1Il+aDbGyG2oUuv44fpyV1gXUdHYH2cFMevo8eMh4IPGvx8H3bsYH5VStRHBdrwVwgU
         fULSD5bGVBwy5TANb+Fr5dZXNM6jtoJIv1DpNAb/nk35gZyzSCQdsx8aQkiN04q6lfjs
         zg0ibrPtUYaSK0W5eK8N4ZUE2HcpHHIkhF0xLG27AQfz6LXN7rnt/iwG/Hu48oBRkkKz
         4fTg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUVaKfCw5zh83pzICW5ZLIIxkxehUugknSB+ZlHm+ARCK2wa+pGx/EYR8zmsd95qTE7FM8ViJPVN0IZel1guRu3zK60fdD9aA==
X-Gm-Message-State: AOJu0YzcIxDS8epGxTXsO4rt1M7hz4Qu5pob/lckDzijXiADr1Bi4G1c
	LeaMiAbgBOOlEyxuPJnncNAgvisNiRU0F1aNfpDco/+SkvYVfQRS
X-Google-Smtp-Source: AGHT+IH2HSKQKEt6LdrlolfftBHEV+dxREpKOZaH5Wt09K/3FO5BG4pkU2FY7ITZyLv3cMyANc+wbg==
X-Received: by 2002:a05:6214:2424:b0:6b7:9d3b:b5e0 with SMTP id 6a1803df08f44-6bb55aafd2amr58847136d6.35.1722127750556;
        Sat, 27 Jul 2024 17:49:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2d07:b0:6b0:84a4:8f6d with SMTP id
 6a1803df08f44-6bb3c070ee9ls52367786d6.0.-pod-prod-02-us; Sat, 27 Jul 2024
 17:49:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTdcuJnrzTNBivet7W8PYb/ebm+tzvnUx+5BvM8Iv5aozPwgkRUanFedrlImpKxt/xaFFoJIsVRVAi/yg11+oRAvFmAXcN3g3mSQ==
X-Received: by 2002:a05:6214:daf:b0:6b7:b236:6964 with SMTP id 6a1803df08f44-6bb559a0aefmr35882286d6.12.1722127749882;
        Sat, 27 Jul 2024 17:49:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722127749; cv=none;
        d=google.com; s=arc-20160816;
        b=b7lTpN1TJQOJINoNnJpxXafPsweESatdWKuPg/hFj34/9cWsw6/wtmQ0DuNOj//baS
         rJIWUteKukQ2kQvNVMcVQ70VQSEQsn7nBYpOrJCZj92SeK3mgP78lLTfGb0UoTY2kWgA
         tR73VVAsVmajWiQU2NEurUlxlQWNpSiKxlq5Wth04oX5O+N34ZWFCkjDNFOYM62ZKwrv
         AnmVgVlP/1jFsw3Q9NtzvtaLe2dBY1uK4InP5LH4a7TCl3I/FPgO+oaAkLsNLqUPoSnf
         JyZ5CRUeK1E8X2D7ILo+dvqrI/Wllkyt4gwtqRV576lGAUjLH//yr4LRrMUyM1FjngGE
         Nm4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=r6LQuMeJaKxQ8xBD622+98+x8+DMQ3mJJIli/EeEaVI=;
        fh=NHFfq/j/rWHP94bByHknyzKqAJRJzQrt4qr9AibEjk0=;
        b=sYfnAQ1cW7+sHI8vwmtVW1359jpQIFFnTPmFOZBnqAbZRzxlh9e/EbZ3/3AK/unTkK
         /mdxZlfynCA6mihZsUsi9jz4MWnuPTuHWIXYUEb+Zn0jB5vEZFIY3ZWDyRfgS8pRMP3B
         Jph+hMvM28vB2bmcScr+bX4ijXYS08Olo08joTrOwHORR83rrCXZi0CyLiWI42SARcIP
         rTGwGgdQ/Ypj1AwsgJbLgv7bWSKgZS5r4vCB5zILt3ZC8B/S2Ja1ThjcC97x6/rebobB
         i/FZrEFmq8jqUs3xx3yDzvcRfYwjbXa6Zp1GjI8P1pN1C9sRbJDaIZ/Xh7ADTtfd/XXT
         E1vQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=loQTUp7I;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6bb3fae8690si1991106d6.6.2024.07.27.17.49.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 27 Jul 2024 17:49:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 53C6ECE092A;
	Sun, 28 Jul 2024 00:49:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C89E8C4AF07;
	Sun, 28 Jul 2024 00:49:04 +0000 (UTC)
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
Subject: [PATCH AUTOSEL 5.10 2/6] rcutorture: Fix rcu_torture_fwd_cb_cr() data race
Date: Sat, 27 Jul 2024 20:48:55 -0400
Message-ID: <20240728004901.1704470-2-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
In-Reply-To: <20240728004901.1704470-1-sashal@kernel.org>
References: <20240728004901.1704470-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-stable-base: Linux 5.10.223
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=loQTUp7I;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240728004901.1704470-2-sashal%40kernel.org.
