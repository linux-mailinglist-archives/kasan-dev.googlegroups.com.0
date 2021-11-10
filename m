Return-Path: <kasan-dev+bncBDAOBFVI5MIBBPWVWCGAMGQEKVMWZOY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id B7E0544CA88
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 21:25:34 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id bn14-20020a05651c178e00b002164a557684sf1039628ljb.6
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Nov 2021 12:25:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636575934; cv=pass;
        d=google.com; s=arc-20160816;
        b=sOxiX0DqBG5d2UHx2LZNN8jr+KBmUf9zsAbCkXp5Cz5jHkmntbvjBJJBiKAiTWSGh/
         8oPqIfjJcRI3+2/feJJv1uGU0o7hD2vJN4IuPtbguv1lESMn4MhThnRK+hK1neVDw4Da
         fIggGGe3iEFaQjatj/OWHOeTOOMoHXl0zbYl1pOtgMIb64CBvf4UKA0NYtvb9UHrYDwr
         KqS/OfH8ncxjChACcAvwB8MrJYwUVPutNlKkt9SRuwlIeZByeuECnJdb0s5f7NGIydnR
         LE/ZwF5+DAW4VmqiD1aiBYzi5CSj390ZGH4LuXsZPjHCHEwIWQiOiazQLAyYI0N3SdL8
         BSVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=sub0K+NxNgVCW9xUgYaoLy5frUKMoMZ9Pz1/IXjiRaM=;
        b=lEERWihnpy47q0iZehqbJHFXm25NMxhq1bfJ8lPsHwjdpRNbmYXsIRwtA8v2PR9HlH
         Oo6MXmsHDXEQuiMq/VhtccRxsYJ1Kb2rRB+ItOr/icnier+W8+yc+pp1IRfV3jUNwAds
         qZaJXyAICSXxcv+Le7xjFZzZAgpJxEgEpsFK7aPeduSUeXDonZXV5jQQjE7lci0hXD1q
         oV6Y6fNpmWdP3uhqSRe26zBrxDZ1J5p8YjFXlBJTqa4EI+BQmwU8QWHqeawGer0WSYUS
         U+NdRQEbNwTleCEKFF5Oga+P6uSpwQiN471f8idwP+KJfa8A6gV2WAFotKHv+ZqPtxzh
         7y7A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sub0K+NxNgVCW9xUgYaoLy5frUKMoMZ9Pz1/IXjiRaM=;
        b=X7Pv7udlbrrD+A+DKPRN38V7Xefx0bJj5oMpypf7TXWGxywaU+QVaSHmoSsdtcwBtO
         tP6Y9+gL3rm3yU2o/lmTka+y4nX/5L8IG49n1lz3V7kH+LobLnv5g2oWHzApv76Z80Yu
         eVsI2GTUvCKMN+EPbXR7OAv5S9H682MndVUj3P3K4GyEoRiiSLD7eHasJQCCJ+TulUxw
         IyCYKYtTxTJNSwrUEHqnFa0RKgstnHPbJAJQVqnvero9PPGfMfHrdSw2UUaFhqmq0Odh
         K2h9cwro834owrvtlso2FOr1VyIncWa0HuR+qzpooKf5MNC7h5t8G7ku4D3wYoBtOsm9
         pidQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sub0K+NxNgVCW9xUgYaoLy5frUKMoMZ9Pz1/IXjiRaM=;
        b=zGxLlKqy2Bh05TGfIb3JzxhW/4bwvPwuZkBfE61yb9B6Ohwp2sqH72gmtb1TyslqkM
         fzqZuobNc/IceTfioFQDuwEFcOvt7o6InUa8uxgMvqJRCAnu8YApUpJjYczNFhYEy3Vr
         aPjzz6BhKiypq4pYZVFfvC3GzxksySvmHl/IAlx8Pte2BqZwyyOf+lNt2igXvP8UFq3D
         rlBYvhXZ75NTUfaq8BNgasUi+B6SjQafdOW/QXXNclXnSvjYgnmLyumKSTTSmyzXIVCS
         T7v20TAHgH5Xl5tsdQY2QmLUOzVJPUci1vbeIpbcCb9Hlxp8OVLZ9MKzj2OzDzOUqytb
         nCvw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531LwHq8eyCcJJ4IfFo86QCBPXcU9W1gGRVOZvGcTt6wZY+rZ1gL
	vnA9IyPLkrNJrohSPBj0Q18=
X-Google-Smtp-Source: ABdhPJx3d6NxsdE/FPN+8HEXxELuq09SUSUDnvtZuKLTd3NYJhwGspYg3/vtU0jv9ErIeaYuOLAVjw==
X-Received: by 2002:a19:495c:: with SMTP id l28mr1767843lfj.484.1636575934352;
        Wed, 10 Nov 2021 12:25:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3499:: with SMTP id v25ls765890lfr.0.gmail; Wed, 10
 Nov 2021 12:25:33 -0800 (PST)
X-Received: by 2002:ac2:5444:: with SMTP id d4mr1698840lfn.678.1636575933365;
        Wed, 10 Nov 2021 12:25:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636575933; cv=none;
        d=google.com; s=arc-20160816;
        b=CvQ9HHdXqGGJc02yytQ545xWZt+EsrmJH5Z5rpESvr9hpk2veJMke/Y92gMtctAuQ1
         FMInFnxpm/efye+l7X2EqMV6wX5GdUiignJ6Fh5ZK0xbgt8ZPBEDpFfXP2XOx9ghiXeI
         qXB2B+5j6F7dX5Eocbr+rY6mH1kuOeOHn1yfki58aXmSbNeDfwPHB+bHdMU5YuH1WBaz
         70Ub8H88BfQR3tFLZ/nQLoVrcd0xgzPFrewaIN+yO/DuFmh/sqy0ipgdRjiMpQpvYYAi
         DaBOqzRr09eNyv3ZJQC7Z17NnSuYt0M2kdPPR/HDVl9gLsBRvKekfL6T/BGj0iWqv0F8
         cgdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=PoBwm/0Xc8vtDx20M5jR9OXkjk5Bdq8yEO841ox6ezQ=;
        b=h2TDpO1agqYNUA1Wmpa56VZvRj17xW1oWS9lB/EqDYykoOoh3BteHVASLU8h0VpOd5
         wSmVH1mbV+IwXst8OrkEHsLOZH8l0mrV5hDHGtiTqn6cbZK0kzZTWdJ8ytzUhlFWZfSc
         GnPFjEG0e16A9VjlRG6b1nG9cYFx9lGpWEBdH1UeuFmN9AfhKjUl8WrqjxftQaTI8v1s
         ERXkn4ujGWYYp0ZEMofYTgy3T58Gs4m+OUVuOyBsaM1AuGWsEVIl0ayICmAI1Gk5Rjv5
         JxH5reJmSoAYakRqBjWu9geQsiMMW6TolxuBSY//0wWjOCKVG3iZhX142eKOEGwVrOtN
         iZZA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z12si84295lfd.12.2021.11.10.12.25.33
        for <kasan-dev@googlegroups.com>;
        Wed, 10 Nov 2021 12:25:33 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 78FE01474;
	Wed, 10 Nov 2021 12:25:32 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 3B4283F5A1;
	Wed, 10 Nov 2021 12:25:30 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linuxppc-dev@lists.ozlabs.org,
	linux-kbuild@vger.kernel.org
Cc: Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Benjamin Herrenschmidt <benh@kernel.crashing.org>,
	Paul Mackerras <paulus@samba.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v2 4/5] kscan: Use preemption model accessors
Date: Wed, 10 Nov 2021 20:24:47 +0000
Message-Id: <20211110202448.4054153-5-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20211110202448.4054153-1-valentin.schneider@arm.com>
References: <20211110202448.4054153-1-valentin.schneider@arm.com>
MIME-Version: 1.0
X-Original-Sender: valentin.schneider@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Per PREEMPT_DYNAMIC, checking CONFIG_PREEMPT doesn't tell you the actual
preemption model of the live kernel. Use the newly-introduced accessors
instead.

Signed-off-by: Valentin Schneider <valentin.schneider@arm.com>
---
 kernel/kcsan/kcsan_test.c | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index dc55fd5a36fc..14d811eb9a21 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1005,13 +1005,13 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
 	else
 		nthreads *= 2;
 
-	if (!IS_ENABLED(CONFIG_PREEMPT) || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
+	if (!is_preempt_full() || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
 		/*
 		 * Without any preemption, keep 2 CPUs free for other tasks, one
 		 * of which is the main test case function checking for
 		 * completion or failure.
 		 */
-		const long min_unused_cpus = IS_ENABLED(CONFIG_PREEMPT_NONE) ? 2 : 0;
+		const long min_unused_cpus = is_preempt_none() ? 2 : 0;
 		const long min_required_cpus = 2 + min_unused_cpus;
 
 		if (num_online_cpus() < min_required_cpus) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211110202448.4054153-5-valentin.schneider%40arm.com.
