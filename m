Return-Path: <kasan-dev+bncBDTMJ55N44FBBTGYU3GQMGQEYRATXPI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eHGAIk6sqWn0CAEAu9opvQ
	(envelope-from <kasan-dev+bncBDTMJ55N44FBBTGYU3GQMGQEYRATXPI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:14 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 269DB215450
	for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 17:16:14 +0100 (CET)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-439c112b1a4sf2398456f8f.3
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Mar 2026 08:16:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772727373; cv=pass;
        d=google.com; s=arc-20240605;
        b=NuzS5LuweaX+uIWiVt+GUkIIgZniVYmXv/kjAroBUHEeNgpdbE9hpNmIUTAIM6CKLy
         7OzG2i2nnehjAd6Alii64semDhChcs+B4J/TeX32hOrmZqtSZII5b6HZVInRcwl7plm5
         WbuA0s7WsiOX2qeQQHQun8p/ORLmX697pkBSr2CmSqwYHfU1c+Jo5qc+W8FELCHky3qt
         E3/ntAF879zfw5SQE2toOqlKEK8oog4OYEUm2yJk4AHn5+Z/h4nrfcMKU49JtRAyq8xi
         /PipgtCyKBlBD6NQ3/+ByewnbnFUpFO6E8YuZ9WHVzli+WjOCuSIBvYiUfkkz8hXsQU3
         xarQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=g2Wrv5kc+33xAV7hkXSL/fZGck5bh6Cg5YzOcfaV6lA=;
        fh=KOLsn087+2xIt+D0aQa+zDqTrsA2HM6mH8cxZtOb3ak=;
        b=VLKZ8Z7Q5BriQ5rLhHDFtURUQ8ryfqUVSlGc1OuZz08BzS9FdWhiarjqDcBGMz3dBX
         7FAjP+xUYQaJTAPsbcHLaXwZrljr78rQigsp/gCZopYETHhwOBCljW7VczJMYUW17PJ7
         DG+g+NnekHH26dYSPw4G/solnWdLCPQ1gHIigtmim5TWG2+eWIBnuMMHLzwYfF4zDemb
         kU82S6S5ks3Yt1mP0oDv3hpmjHD38wA8P6kRqtxw2kRbGyjIxx/MO65hup/911YO3RKb
         +nZs9BqXciVAh+G/EHZRlclJvxRfB+XeOQzWVDDkQDE+2eaN7w0dRTgOdVzO+w16olNS
         EOdQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=mgME5aVF;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772727373; x=1773332173; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g2Wrv5kc+33xAV7hkXSL/fZGck5bh6Cg5YzOcfaV6lA=;
        b=pChDw9ddTuzchFUEx2zBO4BDW44knvxVOLrDLvy1SocMvAkVSgvFMp02KY60/AYLVt
         OwW6E39nxypgUlvhZ1jYZmw9oC1WRHPHCLW8DH7ElGi0pHlHEcvWqwwjSdAXu7189Xwm
         +VTI5/kkTzEHNEpLLrkDNumOVZvhU42sr9V6rfkiz663EyUmaGw8KaLjbpELggdg9RFg
         ZhuDr5QNDimwHWPoWOVjA+ZJGrjjq1727ioxYMsXSy//dg54aFB2rmBpBrMUcVdYDz4O
         kxj5uBGOyu9trP53zYrWiz7SsdgZk2ZBNoc3EJ2tQ3IicVvGW8WlTfQiB8fD8mqT11in
         bQ/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772727373; x=1773332173;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=g2Wrv5kc+33xAV7hkXSL/fZGck5bh6Cg5YzOcfaV6lA=;
        b=rc75T2Xf37v9dG9FT5U/E5tuhVfAg35cchefhz5S5/48rIHLblaQ85HSCirB0M7Sur
         UKQnicIKwc2X5pL8/sMjQbqrVU2M6OYOazllxiL16Er1MrjhKeB6FNqY85IPIIQqqd8Z
         9y6fv64AJ45cPGfT8JV4zFBe9aJoSFML/bsOCdvRjvIyEsYK5KFR7oTcHN7NCEGoU9op
         EAjfPXs/nZABo0ipKpdCC7oSIGYRJmuBzK819x0Fbp+NxLpcgH077aO4nq5ZjswwIS/+
         dtAjcmMK23MrxAKh0umQs0vSJLoqzKbUbyN7e/gvVjNtvpUnsLdrFkE7N5kCs5YFTTAM
         g+Nw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX0Nk3R2Il1kNOcoyP/Nna9F5eOb+y+qJCwP44Fn1XUM10q3k1jBCcnxet6yT6vVutYqAWcdg==@lfdr.de
X-Gm-Message-State: AOJu0Yyix7cTCCSYU+SXv6ERZaWgNAq3SNoIeieq5XxEpcKW+hWA/6hI
	Q0f4rkmTubJu4A+FnndLMA1X0ygu7PW4CYuF51+/pNE/PO4IM1RwxXMo
X-Received: by 2002:a05:6000:1a8f:b0:439:bf2f:1233 with SMTP id ffacd0b85a97d-439c7fa6931mr11813070f8f.20.1772727372755;
        Thu, 05 Mar 2026 08:16:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G26I6zsXFz1GegdyRzOPjkmE+Z+8zEISIf61tKmo8feA=="
Received: by 2002:a05:6000:18a8:b0:439:cba4:b223 with SMTP id
 ffacd0b85a97d-439cd2faa8als639337f8f.0.-pod-prod-04-eu; Thu, 05 Mar 2026
 08:16:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW9NEvTxgOmcDIqt8yf89r3muBKQXX8VSjDuhH0eX36Q+cvrcI8VpPKX8uj7nYW9EzWh07EavcqRcE=@googlegroups.com
X-Received: by 2002:a05:6000:430e:b0:439:abcd:b317 with SMTP id ffacd0b85a97d-439c7fa5837mr12018604f8f.14.1772727370531;
        Thu, 05 Mar 2026 08:16:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772727370; cv=none;
        d=google.com; s=arc-20240605;
        b=GpAyiP9h3xx7d8nhG5Z0tz9QxenDrVD8Q5mLauwaI4riZrA8ERAIGbzbIY4nBL+6NE
         cyYN6RoinRsVmLwAzOX3MJrZ3LaYQJIqzVhcg0Uhkt6R7RpbzEZ2icG6utxC4jWrSnyd
         hlniRTFXI2lE7SduGh9w0KepgN7qb1jcHtAH9qXRIsEaRJVD3cf6AHj0lKVyQnqdUiVw
         IFPrrmL+2i0RjABS0XVeDBhXHRa2g/7D6TPG4IsoWOAvvg5dMciSSR2R+GA86gfNW/ec
         lMV5n9XoEQf73LKahQ5uXlNJceByIhRtyhVh6lVPOYh8u5/3/+zK7rnqjJYChAvd3nVG
         qPeQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature;
        bh=/p5loGM8jok20LIPIaiNcteQRMdR3qdR3xO0RfQ3suo=;
        fh=ULATwvCSm9MH98k3lnaJHTf9T27YdHslpejL1iZxPpg=;
        b=KFa1qPwrp3yn7BSBlyiWtYetBXJS4zKf9PoXKUA8IZYpCEbusqBpj47PQjj48/MNKD
         D1T8L445tk0iakzwSHV0/FPhVDXP+/HsPwGShdVLYV/x0G8Lo5P+2ksgY3lS7mZxAcWf
         NOcLpyVDARLCHDfW7tKQvyC5xsdWre2EZT1oh8DVbId19+brRoVG7fjVcE6hRI/O41i8
         vshKaY8qmLzytk1fsKICwWtRfjmasNmHnpuiQT+WZ0rk8MS/mSME/bVWHe4ts9Yi9eGF
         eMoXkE4mugPJsOkS3OomOkJ8Nf1JWyKIuuzHyTNOVweexKVQjkGZuausyYRbZcNeMDEZ
         IoVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@debian.org header.s=smtpauto.stravinsky header.b=mgME5aVF;
       spf=none (google.com: leitao@debian.org does not designate permitted sender hosts) smtp.mailfrom=leitao@debian.org
Received: from stravinsky.debian.org (stravinsky.debian.org. [2001:41b8:202:deb::311:108])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-439b11edf03si266978f8f.2.2026.03.05.08.16.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 05 Mar 2026 08:16:10 -0800 (PST)
Received-SPF: none (google.com: leitao@debian.org does not designate permitted sender hosts) client-ip=2001:41b8:202:deb::311:108;
Received: from authenticated user
	by stravinsky.debian.org with esmtpsa (TLS1.3:ECDHE_X25519__RSA_PSS_RSAE_SHA256__AES_256_GCM:256)
	(Exim 4.94.2)
	(envelope-from <leitao@debian.org>)
	id 1vyBMr-00Gqqh-8x; Thu, 05 Mar 2026 16:16:05 +0000
From: Breno Leitao <leitao@debian.org>
Date: Thu, 05 Mar 2026 08:15:39 -0800
Subject: [PATCH v2 3/5] workqueue: Show in-flight work item duration in
 stall diagnostics
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260305-wqstall_start-at-v2-3-b60863ee0899@debian.org>
References: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
In-Reply-To: <20260305-wqstall_start-at-v2-0-b60863ee0899@debian.org>
To: Tejun Heo <tj@kernel.org>, Lai Jiangshan <jiangshanlai@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>
Cc: linux-kernel@vger.kernel.org, Omar Sandoval <osandov@osandov.com>, 
 Song Liu <song@kernel.org>, Danielle Costantino <dcostantino@meta.com>, 
 kasan-dev@googlegroups.com, Petr Mladek <pmladek@suse.com>, 
 kernel-team@meta.com, Breno Leitao <leitao@debian.org>
X-Mailer: b4 0.15-dev-363b9
X-Developer-Signature: v=1; a=openpgp-sha256; l=2206; i=leitao@debian.org;
 h=from:subject:message-id; bh=6FexgOl/YVWpjj0jIRoVNTpnAdN4iYrWi4l+UFPFdMU=;
 b=owEBbQKS/ZANAwAIATWjk5/8eHdtAcsmYgBpqaw0TAz/Z05WDXEWmt2FKYK+iZ/e261ng5cVl
 LBj4qKqu+aJAjMEAAEIAB0WIQSshTmm6PRnAspKQ5s1o5Of/Hh3bQUCaamsNAAKCRA1o5Of/Hh3
 bXauD/9uatHOJbfvUmvQ+aZQo6ietoqjfzHWNG7lgcm5OuGbOWKexKTQLk5uDmFDm3AatM1NjSd
 r6qG6KO6iUCrAlQKhiMGv8cqxURUdx1WwwvaBLqIbmRVD0jDFv5nGrUN013v9lw+t2dfGUkx+8r
 9FxPQXQIWKqsVF4yhVhzDnAnbtsgnrN5u7tRpxPpM7C5jVKcpBn0iFyoZsF7b+PBSN9KlkKCh/9
 bMnhamRCLxjMO3xomfcfVcfjjkzdV+uslmYsgDUbVa7EMkokG55p6FU92mTH5/9PhizwEmyEk9E
 CRSAy53kT/XvBtVCqRnRqH+jujw4ClC/19NftRVpLFu6mkwjQKvwi3QF5U1fWBFTiDKz3jkG3oB
 l2pqKDibvfJbu38oSo1aABvGiMyKEVNBZgBILv3uql2P6S0h5IiwEYGJMR1VNO781kXUuM6UX4T
 kikn4vktRTgdoqQm0/MM9vrwcc2yUqseMbxZPlH7GfIJlLgGb9thuuGoFYybVy766Fb0KI+iMvv
 BE6LsOBRHTJ0wHELnH+Ne3Nj9cWb5G7sen7+MQD9xEQwCNOiZ1cKeASgMPV0xLoyCYERG+SUTGk
 eY/56XmW8OtuE0eu+cxvwyOIqAi1w2fDGXNP8S3ajkou5ddvi2wWk3eNM6k0V7N1CRs/tL87cpC
 sbC2y3cAhr+0MUQ==
X-Developer-Key: i=leitao@debian.org; a=openpgp;
 fpr=AC8539A6E8F46702CA4A439B35A3939FFC78776D
X-Debian-User: leitao
X-Original-Sender: leitao@debian.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@debian.org header.s=smtpauto.stravinsky header.b=mgME5aVF;
       spf=none (google.com: leitao@debian.org does not designate permitted
 sender hosts) smtp.mailfrom=leitao@debian.org
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
X-Rspamd-Queue-Id: 269DB215450
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MAILLIST(-0.20)[googlegroups];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_TO(0.00)[kernel.org,gmail.com,linux-foundation.org];
	RCVD_TLS_LAST(0.00)[];
	DMARC_NA(0.00)[debian.org];
	MIME_TRACE(0.00)[0:+];
	FORGED_SENDER_MAILLIST(0.00)[];
	TAGGED_FROM(0.00)[bncBDTMJ55N44FBBTGYU3GQMGQEYRATXPI];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_NEQ_ENVFROM(0.00)[leitao@debian.org,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	MID_RHS_MATCH_FROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	RCPT_COUNT_SEVEN(0.00)[11];
	TO_DN_SOME(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email]
X-Rspamd-Action: no action

When diagnosing workqueue stalls, knowing how long each in-flight work
item has been executing is valuable. Add a current_start timestamp
(jiffies) to struct worker, set it when a work item begins execution in
process_one_work(), and print the elapsed wall-clock time in show_pwq().

Unlike current_at (which tracks CPU runtime and resets on wakeup for
CPU-intensive detection), current_start is never reset because the
diagnostic cares about total wall-clock time including sleeps.

Before: in-flight: 165:stall_work_fn [wq_stall]
After:  in-flight: 165:stall_work_fn [wq_stall] for 100s

Signed-off-by: Breno Leitao <leitao@debian.org>
---
 kernel/workqueue.c          | 3 +++
 kernel/workqueue_internal.h | 1 +
 2 files changed, 4 insertions(+)

diff --git a/kernel/workqueue.c b/kernel/workqueue.c
index 687d5c55c6174..56d8af13843f8 100644
--- a/kernel/workqueue.c
+++ b/kernel/workqueue.c
@@ -3204,6 +3204,7 @@ __acquires(&pool->lock)
 	worker->current_pwq = pwq;
 	if (worker->task)
 		worker->current_at = worker->task->se.sum_exec_runtime;
+	worker->current_start = jiffies;
 	work_data = *work_data_bits(work);
 	worker->current_color = get_work_color(work_data);
 
@@ -6359,6 +6360,8 @@ static void show_pwq(struct pool_workqueue *pwq)
 			pr_cont(" %s", comma ? "," : "");
 			pr_cont_worker_id(worker);
 			pr_cont(":%ps", worker->current_func);
+			pr_cont(" for %us",
+				jiffies_to_msecs(jiffies - worker->current_start) / 1000);
 			list_for_each_entry(work, &worker->scheduled, entry)
 				pr_cont_work(false, work, &pcws);
 			pr_cont_work_flush(comma, (work_func_t)-1L, &pcws);
diff --git a/kernel/workqueue_internal.h b/kernel/workqueue_internal.h
index f6275944ada77..8def1ddc5a1bf 100644
--- a/kernel/workqueue_internal.h
+++ b/kernel/workqueue_internal.h
@@ -32,6 +32,7 @@ struct worker {
 	work_func_t		current_func;	/* K: function */
 	struct pool_workqueue	*current_pwq;	/* K: pwq */
 	u64			current_at;	/* K: runtime at start or last wakeup */
+	unsigned long		current_start;	/* K: start time of current work item */
 	unsigned int		current_color;	/* K: color */
 
 	int			sleeping;	/* S: is worker sleeping? */

-- 
2.47.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260305-wqstall_start-at-v2-3-b60863ee0899%40debian.org.
