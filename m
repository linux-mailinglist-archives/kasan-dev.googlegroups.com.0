Return-Path: <kasan-dev+bncBAABBONAYX3QKGQENUM4KHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 690FA2045FD
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 02:43:38 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id c3sf21954117ybi.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 17:43:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592873017; cv=pass;
        d=google.com; s=arc-20160816;
        b=zlPBp6ZuZ0/wTtVssetrss7IW9Mg4vorPOO6nUVTPn90M4NdxTjJ9zKDc9apdg2N50
         DeqYW310/kM/RlP17cLEyp7TTeGlRTk97OdzWgk8eu8fkF7OqWmYpr2Oy9KqqESWPMbq
         Pl1Orqlv6hDxFv3kwyVVspOhfK5w1deBKs97GH6TESgJ3bin+BrvnoAjxorQs1gXcJ3X
         408N1PV9lKVQy10WM+K7+1oNNRW/pozqDpW3OlnMoPg7LJxFIjFFTk86ekXqsgkRWbTz
         KAYUjkTc4hb+8N1KMkuiisBKM9SxBukrhD0MEG9t1DxMRUloWojHMNURYxIB8pxGGlrt
         CCrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=8rJN//fWW5Hg2wzYdOgMQGsBCRHeEcWs23LiMign3AQ=;
        b=KJV6JFVUSFgLDa0YR9jpIsHlQm8uS9ZPdQu/7aOHnYO0CPljyQPtPd4OjlzizqKVU0
         uNhAQaSBJubSRYA+8/6ninhHwcPTfSEeQFFJL+uFWG3DJmEnrGB6LjhVP3WlZbK9E1Tv
         7TNNql1RhvybCn9PdlAzXhm2+lGY9UVrFIcutmANFV72EKvqXfOw9tiGD1UeT0Fzbox6
         z7fsvodXS+Ynmlm3xV5BhGLy6NMc6Ej4CauIaYcgyXz9CvDUZTEUzHgyJ5nl7GQVlklo
         XeMfiKOt7pFUc1Nv2p4GInK/co1gwp/siK3Yhc/fS+Wr50ZtDQERIOhCi8r5FGX0p8SI
         TCFQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=O63hfk33;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8rJN//fWW5Hg2wzYdOgMQGsBCRHeEcWs23LiMign3AQ=;
        b=ov7cty6SXzyK7l45f8T8juYqS8Q5itYE+4PrMdnDd8XD/8pw868z7RFyUJhAiYKDHT
         XnDo7ygbQ5Ojy8xwzv/L2nerBm9uOzHrAowoOTslxty2R9bmX3AMzlUcRs9enxL5zs20
         7Uj2hUh+vP1IrcU46atnvs49TswUo67+LU8DzU+ShL+Hs3Qs38sfdmPbcHIEaJJFYffS
         MZsLr5CLp6Hv89QgTUGz067d49SiWvfb0hrMa6QFyjMAafnoN0Ak8oXq/SygtwA4OxmM
         jVbcbRNiDe0x8cr55ut4qmNjtu2+7THl9dY2VBpmJcYO7ag5KDaBXmGq/3SOhhZhXDcP
         HYSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8rJN//fWW5Hg2wzYdOgMQGsBCRHeEcWs23LiMign3AQ=;
        b=mZH5/Z19FCPaxCvjT/vFYjHRcRCCbfblb9gbV9O+3P92J6gT0+gyPvjGZb7kyxZkjv
         8wSU5/jM4eB1Qzw9rvr+qMS13Jboqa5Z6djh9zU4lj30ZTa0vF3pTf3XcYwRtU/prYAf
         DYTJY8j07HBW9YXGwqUIeFU6P9PHP7IjYzRBO1jqyd7nOvADcaAAGUZdbBBp48Ic5yfq
         DA7UbPrho8taWdhOVfm99nyJLHYGra3drNb6BPUD4FuLBJQWwtexs+hQ0VEwvz2fd9ho
         C/rmMm1BhSt/geUAlJJMiuI3iVkt1YSF1W7Ru+38gBdEHB5Ug81KksH3spcn9D0Yngdq
         ZhMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531V/DB64dHdTx5hgebTrJ1AyOKJJ311YpEM6XzsV2qrEVPGmf+l
	ADZVco5UavWDnwdTQyqU404=
X-Google-Smtp-Source: ABdhPJwiBtqsMcm/jx3ylnfOmLyIMM+CRMPM1Pw03NKTRle4db3/TAznd1lncOLPbpaZzPtOYx+K1Q==
X-Received: by 2002:a25:6852:: with SMTP id d79mr18365603ybc.418.1592873017469;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b18b:: with SMTP id h11ls7158540ybj.4.gmail; Mon, 22 Jun
 2020 17:43:37 -0700 (PDT)
X-Received: by 2002:a25:408:: with SMTP id 8mr31362236ybe.500.1592873017158;
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592873017; cv=none;
        d=google.com; s=arc-20160816;
        b=Ell+r7gvjqOFQRrxaR6HTJVep+g+t5lfSxOek1HngwVzQ6IjJEB6KQSoqWLTtrEHby
         4Nojw/VizbMhgBw3DLU/GJt2zK467F+KxrcoS6ZXEgl0G+Q9DUGEM2ZxBaCKIEGg2Hty
         H+Mveu6T2iAcl/EvGtvjvRa+PyvJlKgBl0UfeUWUixQMUF0afQt+p+nI9EdVeuBldFUC
         yuEvEL7Vj5Usjai8JBL6T+tIUTbxNhnN1HflPFg6DcUCXskS+Pw0ERniKMex27mefJmO
         BXVY/M5yveEvo5WhM3Mv+KPN/7Dac4YUAx+wxgckqds6d2wx5XIDHjWjOlyI2ueJVAt+
         VAnA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=ACPa5STdAeqwXyXt083/SW8sQHalkG/lcuV4WdTt6u0=;
        b=A4kS9fBzquMkC+uWbcEo19p0CWN1bhGEcryFjr1HSF9r/75dmzAtVr56/3vj4rEc4g
         RgEpVXPPJdNzxIgSpNBy+UVAiFTJxfdo59xg8o+AKj3KEpTl1CPeKGKkTqmr2c62qX/U
         QzLDKvwkloShxo+SMOHkyZEcUaxhzwaLtRbkBllaeTW20KSqQ2sZFwKo6eEu9uPXscZZ
         m0dJux0K43E9Io6QFNG5ZHh70fSff7j2chMmlobwFFzcmsaDhrYnMPRA+qXm0EagDVIz
         86CtIXli6D5KCUc0oLqhFiZUXnC3Cflm3UJYVE5MwMYGtFG6aMOIU2n6rKs6P15iXiPi
         NVUg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=O63hfk33;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k75si463386ybk.0.2020.06.22.17.43.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Jun 2020 17:43:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 252CC20874;
	Tue, 23 Jun 2020 00:43:36 +0000 (UTC)
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
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH tip/core/rcu 05/10] locking/osq_lock: Annotate a data race in osq_lock
Date: Mon, 22 Jun 2020 17:43:28 -0700
Message-Id: <20200623004333.27227-5-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200623003731.GA26717@paulmck-ThinkPad-P72>
References: <20200623003731.GA26717@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=O63hfk33;       spf=pass
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

From: Qian Cai <cai@lca.pw>

The prev->next pointer can be accessed concurrently as noticed by KCSAN:

 write (marked) to 0xffff9d3370dbbe40 of 8 bytes by task 3294 on cpu 107:
  osq_lock+0x25f/0x350
  osq_wait_next at kernel/locking/osq_lock.c:79
  (inlined by) osq_lock at kernel/locking/osq_lock.c:185
  rwsem_optimistic_spin
  <snip>

 read to 0xffff9d3370dbbe40 of 8 bytes by task 3398 on cpu 100:
  osq_lock+0x196/0x350
  osq_lock at kernel/locking/osq_lock.c:157
  rwsem_optimistic_spin
  <snip>

Since the write only stores NULL to prev->next and the read tests if
prev->next equals to this_cpu_ptr(&osq_node). Even if the value is
shattered, the code is still working correctly. Thus, mark it as an
intentional data race using the data_race() macro.

Signed-off-by: Qian Cai <cai@lca.pw>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/locking/osq_lock.c | 6 +++++-
 1 file changed, 5 insertions(+), 1 deletion(-)

diff --git a/kernel/locking/osq_lock.c b/kernel/locking/osq_lock.c
index 1f77349..1de006e 100644
--- a/kernel/locking/osq_lock.c
+++ b/kernel/locking/osq_lock.c
@@ -154,7 +154,11 @@ bool osq_lock(struct optimistic_spin_queue *lock)
 	 */
 
 	for (;;) {
-		if (prev->next == node &&
+		/*
+		 * cpu_relax() below implies a compiler barrier which would
+		 * prevent this comparison being optimized away.
+		 */
+		if (data_race(prev->next) == node &&
 		    cmpxchg(&prev->next, node, NULL) == node)
 			break;
 
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200623004333.27227-5-paulmck%40kernel.org.
