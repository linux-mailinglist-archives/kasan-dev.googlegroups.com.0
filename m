Return-Path: <kasan-dev+bncBDAOBFVI5MIBB5PPXKGAMGQESLSR64A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 4158F44ECDC
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 19:52:38 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id q17-20020adfcd91000000b0017bcb12ad4fsf1726010wrj.12
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Nov 2021 10:52:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1636743158; cv=pass;
        d=google.com; s=arc-20160816;
        b=YLOykSJqCftmKWE1+mpP/R1z1A+iA16bjKl5Z/Je8paMx2HqJkCJjjF4wrpO0EwFFp
         zZFZzVsnlvGr79brnQIVW3IbaUnPVOYpxKSG79v4kD/qDfl1vJO0O80vy56aQR80hy01
         ZYHyvjA0iR2Kf6WSKvCv4JBK9sD81xc2qeLes6OmahZa/rLeWeMrfepeq2JNccaDDhYq
         Rd5s0/eYqkf3281Uw0j2B+eKD/SF33/HodCNObqkQ6TTh+AQ+NS1313INB5Psb+zTUEU
         aF5A9AuP1gahebjSEVJ0jObbC0qszXM1Hv6hX3wzXHmDPjOW4KUlcPTt8x55k2dTD/VM
         PthA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Sj+6n5W2xjnlMXYm5Ixo8f95JhC6a3r907TKpDLNlzI=;
        b=yaTBthzNGX6fiSKaGE9zsZAX1xGmUPQJxsp2G+pbYG2Ag6D5aACJkKP77yxF6fqY+G
         34nzjtGy7qVGOD9462sZLkVtfxOIfWpAyh256+0fVyjj1sZ2afS93GYr5K1NIEDGQzbv
         nPwedJcIUK7LtY1gg0W8P9pMlgpPBBwHvEh411tyitgMI44rtbE/hhHJmG/x0flBH7kv
         D21FlJEuPZQEKSkeGT5qDsfbjg46zWhVBL83OQI623LZfVyWXP7NY6bg82l+zDzAcQPN
         sZ1yQ533FEoWZnibm+U0xdmTwJEi34czcTtnoVjmiop3S0GQl5lufVWcBXYi5O7jezj4
         m8qQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sj+6n5W2xjnlMXYm5Ixo8f95JhC6a3r907TKpDLNlzI=;
        b=oxNzoQeK5zZqSROZQBvReb/0SkgELl1sJ1hGKLkxEmg/bOhho7n8qQ60qXmUdO8/Xk
         OK6kyF38AgO4RYDORrLmY9PVInnGeQJx1obGCeQFDlNqDpLsKkO1O1l11z2zOX36sQfQ
         oIUa7ABmm1ftbHLHNS0A4FthPmD+1GoysSvpTsKWVY/ttm+YmcZ07dOTT5Xr0rN+KQ47
         fJdSTJPhlVbV7e6gY4j6qsAJX8NS+AzK1cN0jINnRV8SIWPdTSKyYbdlf5nomyFlpqYm
         ANuhDG4gQAvWfL1rwLKC4zMovSoDN+OpOi/+akXoV3Vp4Way5E5GKDYKmqu+KhG/iKJ4
         Wv2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Sj+6n5W2xjnlMXYm5Ixo8f95JhC6a3r907TKpDLNlzI=;
        b=T8s2wujXsrVvxBpQsv3ICG5yTqQznWMkoJBsOCKQ7gFhb5FEDI/U0PVQW7l2Y93BJz
         65AabDCfqdjrDRY2rc2khYqgMItVjIimj4jmsssCJ65CUCPyqgU80S1lmp3r3deuGWfY
         jW71EO3LweZE+e/kTqhMU6BZAp7mrireNxshF5lxA/cYDjF9PoDz2sQin4FYLMKWUWgP
         Rm8cSsIP8ueYNiitXRpiewEQVrUAq1AeUN3kia+BMG7SYNu0Y/bl1UA6ATBGR7VRhA0u
         Z6GCURZDzEnzL7/4LczAQ92eg0Gate2KlPXOTbTtUtruk+Cx2xTXrDUto+g655IomzWa
         lWIw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532P0jn/rKWc//slkQFF1pK6fwM7mci7z+bHnBtVaJBkBCxdmMgU
	/QMAya4EMB0wJRZkMfVkBIY=
X-Google-Smtp-Source: ABdhPJzW0ObFVrkGUhJ0PCe7Y9tjsdRvScQ1Ruw7Sl7Y8c7bWJIE+7aPG+0rRic9wmU7r5uplNARBQ==
X-Received: by 2002:adf:f5ce:: with SMTP id k14mr20560979wrp.100.1636743158017;
        Fri, 12 Nov 2021 10:52:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:ad6:: with SMTP id c22ls7078109wmr.1.canary-gmail;
 Fri, 12 Nov 2021 10:52:37 -0800 (PST)
X-Received: by 2002:a05:600c:a05:: with SMTP id z5mr19271308wmp.73.1636743157150;
        Fri, 12 Nov 2021 10:52:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1636743157; cv=none;
        d=google.com; s=arc-20160816;
        b=aAjGC4p4DRBL9+sVKO+hmk65Hl7u6rt5vq7Deo5N7tviA/kF5Z22SwV4sz3yQ7BG6+
         eR20EQV+zpY1RFXD6B7B4J1kSPnvQoiVwiM0S9yl2khaSBWD9Z75GqTgvP24X/IfIRlJ
         etyhpd+QN/SRg4V/tBG3oLdp4ZqRnGuSIsaR7Xl0KrhIRUlRqlpEksi5+S4uu7YYn3/6
         DmewyDswV5TZ7iCBD7yu3vxOgcnxhvW+ObIK00oHhh1AjQt18+C3kFXXbScZzEJ2x9wE
         aIDSKHC5SvJbburtDPoIN9xkaYj/Blj9bBz406TzU8dtx+XpImfPy1c1RRzYr2/tkf94
         nP5Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=cPfWP2RFkPNV1TK81cDEy6tICkOtmn39nfKve+VEV0k=;
        b=WB7qKbrqruuU8DNHOeeqJRXMzClxPtZQ0INxABa3aehEbnzsHP6vmuXe4uyngx+vMT
         wjblds1oAulXUKxfd/6Sqltf8VWP42qHGpHgXengOrONfS1j3uiCcQv7OjNRG4nbkHLj
         SvP5hsIVdEgklN/0vytBzxB4PWRfQUQIwYqLZhAoZFAG7RkL+SA+tpDnE0au3OyxKxNk
         0C4P6yk1bvYWdvX3YB/gwFepE+wTEuosaRQnjXit0Gj2IdAA7myObGzC0YHDzFtXXLdh
         LOnJNITbYFnLVPG6MHP1Bt7qgqAaGr6O7EaxXgu31t+GAHekR8+uPxwpqv3M04nkK8fr
         Z01Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=valentin.schneider@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c10si198025wmq.4.2021.11.12.10.52.37
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Nov 2021 10:52:37 -0800 (PST)
Received-SPF: pass (google.com: domain of valentin.schneider@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 6A9B513D5;
	Fri, 12 Nov 2021 10:52:36 -0800 (PST)
Received: from e113632-lin.cambridge.arm.com (e113632-lin.cambridge.arm.com [10.1.196.57])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPA id 9AB093F70D;
	Fri, 12 Nov 2021 10:52:34 -0800 (PST)
From: Valentin Schneider <valentin.schneider@arm.com>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kbuild@vger.kernel.org
Cc: Marco Elver <elver@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Frederic Weisbecker <frederic@kernel.org>,
	Mike Galbraith <efault@gmx.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Masahiro Yamada <masahiroy@kernel.org>,
	Michal Marek <michal.lkml@markovi.net>,
	Nick Desaulniers <ndesaulniers@google.com>
Subject: [PATCH v3 3/4] kcsan: Use preemption model accessors
Date: Fri, 12 Nov 2021 18:52:02 +0000
Message-Id: <20211112185203.280040-4-valentin.schneider@arm.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20211112185203.280040-1-valentin.schneider@arm.com>
References: <20211112185203.280040-1-valentin.schneider@arm.com>
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
Reviewed-by: Marco Elver <elver@google.com>
---
 kernel/kcsan/kcsan_test.c | 5 +++--
 1 file changed, 3 insertions(+), 2 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index dc55fd5a36fc..97cf1efce36a 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1005,13 +1005,14 @@ static const void *nthreads_gen_params(const void *prev, char *desc)
 	else
 		nthreads *= 2;
 
-	if (!IS_ENABLED(CONFIG_PREEMPT) || !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
+	if (!preempt_model_preemptible() ||
+	    !IS_ENABLED(CONFIG_KCSAN_INTERRUPT_WATCHER)) {
 		/*
 		 * Without any preemption, keep 2 CPUs free for other tasks, one
 		 * of which is the main test case function checking for
 		 * completion or failure.
 		 */
-		const long min_unused_cpus = IS_ENABLED(CONFIG_PREEMPT_NONE) ? 2 : 0;
+		const long min_unused_cpus = preempt_model_none() ? 2 : 0;
 		const long min_required_cpus = 2 + min_unused_cpus;
 
 		if (num_online_cpus() < min_required_cpus) {
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211112185203.280040-4-valentin.schneider%40arm.com.
