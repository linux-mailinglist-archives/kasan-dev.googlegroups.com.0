Return-Path: <kasan-dev+bncBAABBOFAYX3QKGQE7TCNIVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id BBF312045FA
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:37 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id c6sf12044249plr.21
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873016; cv=pass;
        d=google.com; s=arc-20160816;
        b=XxJ9Oo8HeYwpEH7HeG57mYTZsgEitiqxk4vsaQ7S+s0T088ng7alFl18rrH+CNbFA8
         0jnztufcLST4LKR0E5VUyh5Es1WbkG+pnz3CB1CtGEVAtlnqy4JLqm1FxVHRBenuODMQ
         MghMZOXyF+hSIehXc9xVEFSPOUHq8vCnHY69wkwFMJXxAkeqrNJWYRfe/1wltLl9r8mD
         zq2vyFGwRCRKnKyuwwtnPcBpkKMm6piZ+kW2RU5UVvhum73BaV65kVLrvuEohld+UzU3
         QTdnGVsgYt3+LAqOSZ8kTRIe2xS1CU3nWfzEs8XDHFl+A2br8LRnv0EZuAbjbaQEVp4K
         dGRw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=78Dgmu+O9N9eyVDBlHm2JGHXvgx0NWwhU2J4SlCtuLc=;
        b=Dm1C2dzrNONQjrRvGqSrfXuqXedUJU0o9qC3icbw3r0h7SKR1J0UnQNUJHkrOpFsA0
         P58DgYxXWXIEfIQaVl8t9yHxl+2f430VdSnPiphBmf1N8y1T0F78JwUsy7f2EFObrffw
         jvGovw3aSizJXccq99DOwU+oez1FP/jZcWJ9oyLG2gvD0wnG/Gs/WCVYssHMKXcsEHWs
         Y0GRVUZ88bJ3QWOJOH8E+hMi3RbHH8Xa7Cw4SVWzVt+uo1npTwkmte3HaQu+MOk2BUy5
         GCoY3AQ4Gw1o1qho7Rm6rKKrC9OiJ0aFHwVfKGMvgXkaY9KUrlN8B0NWzZ+akx7gHGnH
         fvJw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CjbevtBI;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=78Dgmu+O9N9eyVDBlHm2JGHXvgx0NWwhU2J4SlCtuLc=;
        b=s1u2wT2n6BVCw+GGpL9jKoLZsv+SvUai8uuIxW8ybwEH8ZdGdX0nP+TchsL4xiX3kV
         th0zwYzAZY63gI/iw9k1fquVOd4VTPoJvBeycQFdEsHW8c5WU6ThB6xY3mdtfrLBGPGA
         J0irI33W93UiEbE7hLTva2IQAqBSQSWr1vEAZTS+DvHvAVnFtIA4mF0RyTD/qEbu50vn
         QiIJmigq6fp/Jzaq8p3eOA5rSiyWlqTS1yV1BNjt+KMNoYXLGeolJqPHFFxlg8vvuVKi
         0O/lLBlPYzxyy06QPq3FH5ntzNL5VxiKJ2VKVSyNdjoUwWu4A0SB37+Jcfo9z5/tPudo
         evtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=78Dgmu+O9N9eyVDBlHm2JGHXvgx0NWwhU2J4SlCtuLc=;
        b=AwTHJawXMvxeP+cx5j5Ya9Q0sUZ33U4WvJKXGdoQ/BgTUvjYsoShgkvPUrYMO21GTM
         uS0DJK0OM60jYeOoadRbzq9xfYbrz4RHnp9y8uq6nhIQjJSItlh7Ah5cMy8vaplmIr5C
         tgIhgpdEsrSRuLptCPwbxUzlZ0FoYr8s6N/8TH+Daz8sXQULxm2M/q8LxQW2UnC8k9Vd
         w9Rw28W43OZwc0K1ZqkfmHFLxZFYTSHD2p4+QQLe98ZRsAVSmVHRUDO556AlexLCI2MY
         aLyVQWZOsJXmqq6rrUPY/wdd1OMtHaEDoPlRrz7A4+4Vukf7+uZRtETS1BcenA+jjY5+
         EZ3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NQa+9VaP/0Fd6Up1r6m9thbVACUZT2y0/SdnVCb8DUy6yiVJF
	GM26Q0hS6w0EkcCZo3wUt6I=
X-Google-Smtp-Source: ABdhPJwNwVJbsH3Vv7M815gaCfxZhhBRWEYD/w5JftYJhi7/dOZNAqYduvw0I/Ka4V96gQM9kx2+BA==
X-Received: by 2002:a63:be4e:: with SMTP id g14mr5386727pgo.193.1592873016373;
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7686:: with SMTP id m6ls6939060pll.1.gmail; Mon, 22
 Jun 2020 17:43:36 -0700 (PDT)
X-Received: by 2002:a17:902:d902:: with SMTP id c2mr23033535plz.194.1592873016043;
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873016; cv=none;
        d=google.com; s=arc-20160816;
        b=EOhqzwFrtEMOQyvlLe1QnMcSReYwPBiwnK5chxNaUUVRcjbtA4PVZgoEJhXJJRC0Yv
         fnTcTSvOhKZPG00EsCEcr0hz9W+dlozgcP5XLJCGvizYi/t+QrXRYoWCCizEU6421P8u
         VXPs4A6reAPpdGGwzFNWzXX2BJu3vOyftI0DUzLT98Wwd2m0bykruc5ncK5zRW8E6iHp
         wcDIe3866+BqiN/lAggri+VTJ4pWC1KugtjBPR4TtibFE78jxoTgudDN97skMbks5eeE
         +m5WucjOMO3YO50fbqi4q6CM9OS7pSJ1lKsX6FnQ+ZwtVApqxO0dRSfwHWMpXgJBk4Ec
         5F4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=Wkb7huhiUQIkUSoH6wB0zdrlB8AIT2ApH+24aAy9/DQ=;
        b=eYlp6l9mGRy7LEf5EoONa+cmpfy479BgLHrGlvLSgEpueFB+u2TE2JOvCHay3jivKG
         oBkXvTdOEGZ4ECPAa0hqLMKiugt66gq16o2flajhVSaOVrVK/NQuiqNiHfrQSAuteVBO
         nWWwB1p/VJ2Sc1l4VYoRUNDHRMvouFZdBt7gypS4BYgO1QCzgQ/Yxa/nsh2jMa/qgWn7
         DsD6xHzu2VRhVzk1IiRF0uj4k78ORtwEFmQVHpx6Uz3Ap6QIyCw45lAQ2i2pqfwdFgJw
         rThmbJVmfVGdW1Srp+rmi/uP/HQ90VPxly6+mFgjTq9ILnvh55/F74slyaNyWjPvwmdv
         T20w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=CjbevtBI;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id y9si753551pgv.0.2020.06.22.17.43.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id B3F2F20809;
	Tue, 23 Jun 2020 00:43:35 +0000 (UTC)
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
	"Paul E. McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 03/10] rculist: Add ASSERT_EXCLUSIVE_ACCESS() to __list_splice_init_rcu()
Date: Mon, 22 Jun 2020 17:43:26 -0700
Message-Id: <20200623004333.27227-3-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=CjbevtBI;       spf=pass
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

From: "Paul E. McKenney" <paulmck@kernel.org>

After the sync() in __list_splice_init_rcu(), there should be no
readers traversing the old list.  This commit therefore enlists the
help of KCSAN to verify this condition via a pair of calls to
ASSERT_EXCLUSIVE_ACCESS().

Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
Cc: Marco Elver <elver@google.com>
---
 include/linux/rculist.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/rculist.h b/include/linux/rculist.h
index df587d1..2ebd112 100644
--- a/include/linux/rculist.h
+++ b/include/linux/rculist.h
@@ -248,6 +248,8 @@ static inline void __list_splice_init_rcu(struct list_head *list,
 	 */
 
 	sync();
+	ASSERT_EXCLUSIVE_ACCESS(*first);
+	ASSERT_EXCLUSIVE_ACCESS(*last);
 
 	/*
 	 * Readers are finished with the source list, so perform splice.
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-3-paulmck%40kernel.org.
