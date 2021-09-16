Return-Path: <kasan-dev+bncBCJZRXGY5YJBB5NARKFAMGQEK4LQ5WA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id B20D140D0E2
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Sep 2021 02:31:50 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id j42-20020ab0186a000000b002b0bf3870desf2459944uag.23
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Sep 2021 17:31:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631752309; cv=pass;
        d=google.com; s=arc-20160816;
        b=I3dH9whQbbthVvBftGjEqqhrnlAfCfNfjTfEH63uI2Cs2iK9fad46u/oBJdAmGwKhq
         it/gtL72sfQ6T8IaCS/UK+OUjbeA49o5dwqHGCYiGfrm/cWIU/K4/vIgLH7SSepYczC0
         VyI+mNTCLOypR6ampl53R3z4d4P/gLtU66n751PPSPlckZzTEIAy71qG5pz7rNsim+tP
         KFL6AnW2nYTc6dRsRdjkOoxz4QDPEoadkWXGNCw2CwAN4iSaMl6B9kEJGOt3K3xtOtBg
         QXHQKzPvL57IglbtlMWx6AV5lMQzxCivFcnp+OAVAiET/n8z7aKcXfBGcldFDhtAvT2U
         qw7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=WuHvOh9zbkT7DbkOVPzb2CvLV1AT9uPlWSjkpU/Ntc4=;
        b=HSbuwlq8CKSV094lQtnYFHGL3az5h+W+U+1XXXuqaofjqjO7gS7Lhu+FSyh8pjIvBB
         bk5w3wFEg8p1886+wNppRlxTYqZN7J9NmIS56/OZRbXZOain5S1NIwvwefOhwOdb5UoH
         HX3s8Qzu9Ter9H/2j4aHm/z3cSSwsdT+KHbzkx4oENa7AMyf76xEsV4/tzsml5KzDclN
         yKdfbWfb3CTKxjtPKD8DyiA0eNYoxyTOyz5NVkcFjUjfkJ5poby/aAkog9850pVs8ki+
         jYDCwfzDZZpkw9Vqg+Ae8tfbOdeKg41GST+jX+BP1YTHFnEqDY225Ai3n1qlnFh6tPRJ
         vDtA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DFYIMOmQ;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WuHvOh9zbkT7DbkOVPzb2CvLV1AT9uPlWSjkpU/Ntc4=;
        b=SmR0A6RXAR5Z8A0lnt7/YSTcimPcvG5S2ekntzmfITA9RtiOEif+BLcj4DHp/CpRm2
         Nfg1nMGvvq/ekvEbJQe9l3ux6rl/UInY/UUO9/r1G1O0yRCn3YB1CuVVQo/eVPC1ASKr
         IpRTSvsqNegI+iCvg7F5zBu8i3ABC3pvHflpWPnn7hc0VH2w0Z+ShVYCGyuOhzFH5n6e
         /30T4yYpPbVSigyAnYgNymLN72o6pHvZkYkSGrsMDlCaXF3dwWyQPAOnxI8VwoPXqI3p
         ZX67yZcokcKM3fd+w7Rp6T/IoLdCxUkXFrhXQMzygzmErb7G4kksF5qhuH3SbGzB/Y0I
         3SJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=WuHvOh9zbkT7DbkOVPzb2CvLV1AT9uPlWSjkpU/Ntc4=;
        b=ovFd1jZYwTvNd5ERnM0eNl0DzfJjJDWgITJeSt/MLrOOkubGeT4TxxJpIRq/qS54GZ
         Jj0qe9ZfiqSl8EhAxfdovVHGQhTNY1u8XcmPiYA78rNqD707MxcjCW+bxJLsQfmgCrZV
         WkttHdNFDwgcgqTu8dsqjYfQq4qob2aZj3COR/C+9FxljNFGxXxkJin0kCD276US+4x8
         jHqtnuXjAFaHT2NlTP1vGg28OgkRf76j0w79qr+zspi8eaiiRD4laVDuIFkSkedYhNno
         DZSaxEYe9nnxbFR/y8pvhXAD5ECZc1fDeBhzsIZHddks6zNFU3JAvK/q3fkvoxFncG2G
         mhtg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532BsiVTtxiEJP5FLAOQCPoXBhWJ2MVox2vTjpNSnVe+oEPnWXkj
	PPdtgNChBg/myUVBV/7Rjx8=
X-Google-Smtp-Source: ABdhPJylPd7yS5ng80oN1hQP2G3QU8iLzwPqwNJqjIcyq0JOAvL3C+tC6BWGHrmih3z5lzJ7MuXPCg==
X-Received: by 2002:ab0:3c89:: with SMTP id a9mr2667723uax.32.1631752309742;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1f:2c8b:: with SMTP id s133ls201765vks.4.gmail; Wed, 15 Sep
 2021 17:31:49 -0700 (PDT)
X-Received: by 2002:a1f:2306:: with SMTP id j6mr2513132vkj.26.1631752309112;
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631752309; cv=none;
        d=google.com; s=arc-20160816;
        b=qsda00+Uf0F5BOLNtpfBWuElZqqZvHN2QH68587XvKS2KyYEy25Gewa1eh5yflZGUb
         op0pl0trk1001W/LOD9bmhOtoUh4HlHd1wACegz9Orc5pZlBG+y09GjnEfhS/ZMtBkrY
         ukKlxu9Pj+fUPYLQKtVN4bAiuyLEZ/1iShiGm8+mCZV1sNuhb8WHlOGLThhb1VtW8oHH
         GssFtdRhZHTvp+xOVln12U4k7agdqg5UuUCkpjqmr8kODmHqdGdHJzDk2gQNQF+utWW4
         Cj8P/iDtQYH/y77HIWtORl7psj5j20jI5xioddrlSJUtbuZc+QNGkIST76xfGo2h3Wsd
         Ke9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pWQzYywK5iJy+NBc9SPmuf0sBezpWZ+0ZOv8g9vjiEM=;
        b=f3gW9nebl9tUYNIIezoj1n3vnK1bYh+KBjMar8z7E+Qh0BuwYXSyBOE1r49T/ME8t1
         nTG+7czzJ+m3TVfeYMChklRa5Zb1h9cY4xrT6GHH9q4akn/1thbMJo3e5NJRQL3tiZJZ
         lFBKk4JG47KAaptQzRiURNOkMif7y0IHaXzGWPgNMH+ykoYeaYM715F0FH3bQrvFhlSq
         9L53LLYG0AcirYwdf9cA1tdibkLnB2hBkUtbBAKBdEp984HRlBincGs9JnC7W6mjzkG2
         gALkUlwBS2PsBXE2Oxm+9nHHmEYvbwQXYFa78mjRREg0T/cUE+k7i8O8GDoNzwHjRfZ5
         N/+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DFYIMOmQ;
       spf=pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id u23si330316vsn.2.2021.09.15.17.31.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Sep 2021 17:31:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id E03AB611C1;
	Thu, 16 Sep 2021 00:31:47 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id B44265C0926; Wed, 15 Sep 2021 17:31:47 -0700 (PDT)
From: "Paul E. McKenney" <paulmck@kernel.org>
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 5/9] kcsan: Save instruction pointer for scoped accesses
Date: Wed, 15 Sep 2021 17:31:42 -0700
Message-Id: <20210916003146.3910358-5-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
References: <20210916003126.GA3910257@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DFYIMOmQ;       spf=pass
 (google.com: domain of srs0=j1cw=og=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=J1Cw=OG=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

From: Marco Elver <elver@google.com>

Save the instruction pointer for scoped accesses, so that it becomes
possible for the reporting code to construct more accurate stack traces
that will show the start of the scope.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/kcsan-checks.h |  3 +++
 kernel/kcsan/core.c          | 12 +++++++++---
 2 files changed, 12 insertions(+), 3 deletions(-)

diff --git a/include/linux/kcsan-checks.h b/include/linux/kcsan-checks.h
index 9fd0ad80fef6..5f5965246877 100644
--- a/include/linux/kcsan-checks.h
+++ b/include/linux/kcsan-checks.h
@@ -100,9 +100,12 @@ void kcsan_set_access_mask(unsigned long mask);
 /* Scoped access information. */
 struct kcsan_scoped_access {
 	struct list_head list;
+	/* Access information. */
 	const volatile void *ptr;
 	size_t size;
 	int type;
+	/* Location where scoped access was set up. */
+	unsigned long ip;
 };
 /*
  * Automatically call kcsan_end_scoped_access() when kcsan_scoped_access goes
diff --git a/kernel/kcsan/core.c b/kernel/kcsan/core.c
index bffd1d95addb..8b20af541776 100644
--- a/kernel/kcsan/core.c
+++ b/kernel/kcsan/core.c
@@ -202,6 +202,9 @@ static __always_inline struct kcsan_ctx *get_ctx(void)
 	return in_task() ? &current->kcsan_ctx : raw_cpu_ptr(&kcsan_cpu_ctx);
 }
 
+static __always_inline void
+check_access(const volatile void *ptr, size_t size, int type, unsigned long ip);
+
 /* Check scoped accesses; never inline because this is a slow-path! */
 static noinline void kcsan_check_scoped_accesses(void)
 {
@@ -210,8 +213,10 @@ static noinline void kcsan_check_scoped_accesses(void)
 	struct kcsan_scoped_access *scoped_access;
 
 	ctx->scoped_accesses.prev = NULL;  /* Avoid recursion. */
-	list_for_each_entry(scoped_access, &ctx->scoped_accesses, list)
-		__kcsan_check_access(scoped_access->ptr, scoped_access->size, scoped_access->type);
+	list_for_each_entry(scoped_access, &ctx->scoped_accesses, list) {
+		check_access(scoped_access->ptr, scoped_access->size,
+			     scoped_access->type, scoped_access->ip);
+	}
 	ctx->scoped_accesses.prev = prev_save;
 }
 
@@ -767,6 +772,7 @@ kcsan_begin_scoped_access(const volatile void *ptr, size_t size, int type,
 	sa->ptr = ptr;
 	sa->size = size;
 	sa->type = type;
+	sa->ip = _RET_IP_;
 
 	if (!ctx->scoped_accesses.prev) /* Lazy initialize list head. */
 		INIT_LIST_HEAD(&ctx->scoped_accesses);
@@ -798,7 +804,7 @@ void kcsan_end_scoped_access(struct kcsan_scoped_access *sa)
 
 	ctx->disable_count--;
 
-	__kcsan_check_access(sa->ptr, sa->size, sa->type);
+	check_access(sa->ptr, sa->size, sa->type, sa->ip);
 }
 EXPORT_SYMBOL(kcsan_end_scoped_access);
 
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210916003146.3910358-5-paulmck%40kernel.org.
