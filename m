Return-Path: <kasan-dev+bncBC7OBJGL2MHBBRHS6WAAMGQEUQH2W3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D872310E3C
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 17:58:45 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id c2sf4172734lff.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 08:58:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612544325; cv=pass;
        d=google.com; s=arc-20160816;
        b=rjCIcZD0hrxWvuCTriW9R9Biob8QPVV6tRiHq+oJq0PNOf2QYJWbVxOe4dxlDmyjM0
         K2qXJ+QrefFh/EFzPt/hNai56/+LXLUIjfCK1tZMzHpazKKQhS+VYN4x16dLLyVS8Ptu
         MhtQZ/+EFpyc6WbJJ46CInwLFa9aoHXOe0+Lz6HiS0IWNIyss+GqnpqlAy7c6/cB5zAj
         W2PSshA75Ay6WWcvo18CV54BUJSdfwk4l1h8O5DTGLIX0ipLWvjnNG6wHS9pNyWv/nK4
         PfmBinUWhnJ7s1PsDY9aucMaZNdl8Lo6wXxSWZ/aSGO600VATFFz+ZjhEIdk4HrNsR1g
         0kJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:sender:dkim-signature;
        bh=XvCBsk0hbubyc4cm7wbGinbDlNmWv0VFNlpCV7wiKZQ=;
        b=Hv8A6PkIkzrLAQYI7fT6pwGl+8XEfvFSbxri3G8B7vzrttLdW/AEhscEr62doB9eLO
         7j3+XtxNJNoV85prdTMq+O8WsYCadoqA9JeQyVTalJ8dJfup9IaRYTojy5g47BnkXmbQ
         9lZMJQvCgq88ELazysHzTMUcjQ/Moz9GFtyYDIiYZ2fKKuKMdxbkmRJEt7yvlMu2ORzP
         aEJyelGmtFT6wOEga0FAgx+ehpjyUiCEXI1kfEiDNwKm1pVfJ6GhQqK6U81A7eDQRJb+
         IVHy2Yr2TV2C0lZDIWhoGmsp9n5OdY2o/Wbo5WMSUKbbo0HLri3wTf34Jf1D8l5i1iP5
         0FPw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KBklsWed;
       spf=pass (google.com: domain of 3q3kdyaukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Q3kdYAUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=XvCBsk0hbubyc4cm7wbGinbDlNmWv0VFNlpCV7wiKZQ=;
        b=siq+lus3XnjJV24utcIL1NJ/moJGb/ylWAUy6OJalis2tgNwhn4IjBlKClLKiYGL0y
         IHUj76G8kUcO549gnEyp3Jxz0SZ1iWIjQZGWOS2wP9XDHebo4fSMeKrD/4XBVc8EerbC
         YQ2MfJfZwEcmj941tqURs82c0a0vMc675AOa1UTcih2Hyr+8waGUoZgrG0stNqcx8vYC
         +6ZUeqmEUiohlidYFLKvGTsngSC6RpeYBBh/FnBWqECblsjNA0iKsX/Lozt2j/4Y/2Kk
         cX5cm/NW1F2FKHEpJ4dFgRyZkH4zVRMoqquUvvQEMf6ICXNrRP78D8qcHG5IpkLWfgxM
         nkHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:message-id:mime-version:subject:from
         :to:cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=XvCBsk0hbubyc4cm7wbGinbDlNmWv0VFNlpCV7wiKZQ=;
        b=j56mUAMrsx3VcNx85kpIURmvkbgP0zrJ3dEQABci5YzsLM7Tsgq1pHl0nP0GSwMidL
         NHaWV3ya0E1m4A8nqDmH+eTjbcwTFM5xryxCwCxGwOdRCcRmg6m9Pdu2pY2kI8sNv4g0
         0ocvbL1kalbJgid6JTjQaUTDkGceLeHWDLSiUaCsYNKR49hE5JjJhuiMRNFd7ecmlHaX
         O5MdeImDzyzZhi4JV6UfKi5x0TpJFG5Jb709IW0R2KItoEi5xH0wVzojc7vaDZsXGRAX
         Ijlj3m6nwCyGYJlcTVhXKCQwMNOulnK6Kh2UjhcYNZixjV+7qow3B9DquydTwucuWIOy
         HNtA==
X-Gm-Message-State: AOAM5331Rh8syWi4B594E5FgHMde1GmnW9yTpx2R2ya4VhUdePoIptA7
	ywjcHTUV56aKLLbQr3abmoA=
X-Google-Smtp-Source: ABdhPJwR8RQ62H3zzaMmZsf0TlbZEG+mfb03VWbqUW1Fk6d/h2vEMtn8d7OfxnxpKdYetx7htde5mQ==
X-Received: by 2002:a2e:8144:: with SMTP id t4mr3293693ljg.9.1612544325009;
        Fri, 05 Feb 2021 08:58:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1397:: with SMTP id k23ls1798467ljb.11.gmail; Fri,
 05 Feb 2021 08:58:43 -0800 (PST)
X-Received: by 2002:a2e:3c0c:: with SMTP id j12mr3220522lja.305.1612544323879;
        Fri, 05 Feb 2021 08:58:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612544323; cv=none;
        d=google.com; s=arc-20160816;
        b=Jx7xlV2pYEoC/nKYe4hcQvuN2ND6gX8WSfRES7xQcaClwbPtzllNihZNHKpkSS+NTh
         hGzOhRyxBSuYS+awDblyw2BwTv4tJbcWq6PxY+YtP5yzhg3msj6yUYMVmPtaGjnGUUn3
         M+c/cK0JHB+THhSx+/6aQfSX7E5VxFL/bW29LoGqdJ6djtV9ovu9snr8LsyuQ60v3WUQ
         JAgfzRK9HsqGEn7W8RHRgIqxWtlhY7k94MwFPOVtavQq2prQnasTcBGhZ/HGaM08ksCs
         MRttoJ3LmPyr9akJq2So512pUOIgjFHI8EglLBCunsRzPQmqIUJWHORu1ELBwEj4hLAx
         PUNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:sender
         :dkim-signature;
        bh=4GtWCwQDeimvfkN1mTaSptGywDj7eww9UKGtvZYIBUg=;
        b=Dgfr0SQRwcMqr2BfpoRYVQyTZeeLbMJ+m5+YivLfSsFNNTHYKF5Z4krlH//wNGazKl
         WWSZU14fPTHjDSFGKcUSWU27hxa8HVFsaPT+Sl+XWMAdzhocO3KTxixGLAf78DxKFQyK
         4gKIEWu+uJ/8wBWGZzdepLmoTPLWlilBbX16mPzZUN8xNgF7uQ8A2zedCk4V/nzDjIU8
         qqtYnGU0ylmuvXpeCpBto75lSq2yS9dBoyYHoQOjBGMCaCj8k1KqLjWEn1DLprJ86Y1D
         jj0sRkgWO+/IZRtPSLGONY/clIe2B8MB16NSvxxchB9vz9H5eowG9nwKxQuEcghMiLfA
         v/RQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KBklsWed;
       spf=pass (google.com: domain of 3q3kdyaukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Q3kdYAUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x649.google.com (mail-ej1-x649.google.com. [2a00:1450:4864:20::649])
        by gmr-mx.google.com with ESMTPS id d25si402828lji.8.2021.02.05.08.58.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 08:58:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3q3kdyaukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com designates 2a00:1450:4864:20::649 as permitted sender) client-ip=2a00:1450:4864:20::649;
Received: by mail-ej1-x649.google.com with SMTP id yh28so7051105ejb.11
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 08:58:43 -0800 (PST)
Sender: "elver via sendgmr" <elver@elver.muc.corp.google.com>
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:c86d:8e60:951e:3880])
 (user=elver job=sendgmr) by 2002:a50:e14d:: with SMTP id i13mr2777193edl.106.1612544323216;
 Fri, 05 Feb 2021 08:58:43 -0800 (PST)
Date: Fri,  5 Feb 2021 17:58:35 +0100
Message-Id: <20210205165835.821714-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH] blk-mq-debugfs: mark concurrent stats counters as data races
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, axboe@kernel.dk, 
	linux-block@vger.kernel.org, 
	syzbot+2c308b859c8c103aae53@syzkaller.appspotmail.com, 
	syzbot+44f9b37d2de57637dbfd@syzkaller.appspotmail.com, 
	syzbot+49a9bcf457723ecaf1cf@syzkaller.appspotmail.com, 
	syzbot+b9914ed52d5b1d63f71d@syzkaller.appspotmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KBklsWed;       spf=pass
 (google.com: domain of 3q3kdyaukcbiwdnwjyggydw.ugecsksf-vwnyggydwyjgmhk.uge@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::649 as permitted sender) smtp.mailfrom=3Q3kdYAUKCbIWdnWjYggYdW.UgecSkSf-VWnYggYdWYjgmhk.Uge@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

KCSAN reports that several of the blk-mq debugfs stats counters are
updated concurrently. Because blk-mq-debugfs does not demand precise
stats counters, potential lossy updates due to data races can be
tolerated. Therefore, mark and comment the accesses accordingly.

Reported-by: syzbot+2c308b859c8c103aae53@syzkaller.appspotmail.com
Reported-by: syzbot+44f9b37d2de57637dbfd@syzkaller.appspotmail.com
Reported-by: syzbot+49a9bcf457723ecaf1cf@syzkaller.appspotmail.com
Reported-by: syzbot+b9914ed52d5b1d63f71d@syzkaller.appspotmail.com
Signed-off-by: Marco Elver <elver@google.com>
---
Note: These 4 data races are among the most frequently encountered by
syzbot:

  https://syzkaller.appspot.com/bug?id=7994761095b9677fb8bccaf41a77a82d5f444839
  https://syzkaller.appspot.com/bug?id=08193ca23b80ec0e9bcbefba039162cff4f5d7a3
  https://syzkaller.appspot.com/bug?id=7c51c15438f963024c4a4b3a6d7e119f4bdb2199
  https://syzkaller.appspot.com/bug?id=6436cb57d04e8c5d6f0f40926d7511232aa2b5d4
---
 block/blk-mq-debugfs.c | 22 ++++++++++++----------
 block/blk-mq-sched.c   |  3 ++-
 block/blk-mq.c         |  9 ++++++---
 3 files changed, 20 insertions(+), 14 deletions(-)

diff --git a/block/blk-mq-debugfs.c b/block/blk-mq-debugfs.c
index 4de03da9a624..687d201f0d7b 100644
--- a/block/blk-mq-debugfs.c
+++ b/block/blk-mq-debugfs.c
@@ -554,15 +554,16 @@ static int hctx_dispatched_show(void *data, struct seq_file *m)
 	struct blk_mq_hw_ctx *hctx = data;
 	int i;
 
-	seq_printf(m, "%8u\t%lu\n", 0U, hctx->dispatched[0]);
+	seq_printf(m, "%8u\t%lu\n", 0U, data_race(hctx->dispatched[0]));
 
 	for (i = 1; i < BLK_MQ_MAX_DISPATCH_ORDER - 1; i++) {
 		unsigned int d = 1U << (i - 1);
 
-		seq_printf(m, "%8u\t%lu\n", d, hctx->dispatched[i]);
+		seq_printf(m, "%8u\t%lu\n", d, data_race(hctx->dispatched[i]));
 	}
 
-	seq_printf(m, "%8u+\t%lu\n", 1U << (i - 1), hctx->dispatched[i]);
+	seq_printf(m, "%8u+\t%lu\n", 1U << (i - 1),
+		   data_race(hctx->dispatched[i]));
 	return 0;
 }
 
@@ -573,7 +574,7 @@ static ssize_t hctx_dispatched_write(void *data, const char __user *buf,
 	int i;
 
 	for (i = 0; i < BLK_MQ_MAX_DISPATCH_ORDER; i++)
-		hctx->dispatched[i] = 0;
+		data_race(hctx->dispatched[i] = 0);
 	return count;
 }
 
@@ -581,7 +582,7 @@ static int hctx_queued_show(void *data, struct seq_file *m)
 {
 	struct blk_mq_hw_ctx *hctx = data;
 
-	seq_printf(m, "%lu\n", hctx->queued);
+	seq_printf(m, "%lu\n", data_race(hctx->queued));
 	return 0;
 }
 
@@ -590,7 +591,7 @@ static ssize_t hctx_queued_write(void *data, const char __user *buf,
 {
 	struct blk_mq_hw_ctx *hctx = data;
 
-	hctx->queued = 0;
+	data_race(hctx->queued = 0);
 	return count;
 }
 
@@ -598,7 +599,7 @@ static int hctx_run_show(void *data, struct seq_file *m)
 {
 	struct blk_mq_hw_ctx *hctx = data;
 
-	seq_printf(m, "%lu\n", hctx->run);
+	seq_printf(m, "%lu\n", data_race(hctx->run));
 	return 0;
 }
 
@@ -607,7 +608,7 @@ static ssize_t hctx_run_write(void *data, const char __user *buf, size_t count,
 {
 	struct blk_mq_hw_ctx *hctx = data;
 
-	hctx->run = 0;
+	data_race(hctx->run = 0);
 	return count;
 }
 
@@ -702,7 +703,8 @@ static int ctx_completed_show(void *data, struct seq_file *m)
 {
 	struct blk_mq_ctx *ctx = data;
 
-	seq_printf(m, "%lu %lu\n", ctx->rq_completed[1], ctx->rq_completed[0]);
+	seq_printf(m, "%lu %lu\n", data_race(ctx->rq_completed[1]),
+		   data_race(ctx->rq_completed[0]));
 	return 0;
 }
 
@@ -711,7 +713,7 @@ static ssize_t ctx_completed_write(void *data, const char __user *buf,
 {
 	struct blk_mq_ctx *ctx = data;
 
-	ctx->rq_completed[0] = ctx->rq_completed[1] = 0;
+	data_race(ctx->rq_completed[0] = ctx->rq_completed[1] = 0);
 	return count;
 }
 
diff --git a/block/blk-mq-sched.c b/block/blk-mq-sched.c
index deff4e826e23..71a49835e89a 100644
--- a/block/blk-mq-sched.c
+++ b/block/blk-mq-sched.c
@@ -332,7 +332,8 @@ void blk_mq_sched_dispatch_requests(struct blk_mq_hw_ctx *hctx)
 	if (unlikely(blk_mq_hctx_stopped(hctx) || blk_queue_quiesced(q)))
 		return;
 
-	hctx->run++;
+	/* data race ok: hctx->run only for debugfs stats. */
+	data_race(hctx->run++);
 
 	/*
 	 * A return of -EAGAIN is an indication that hctx->dispatch is not
diff --git a/block/blk-mq.c b/block/blk-mq.c
index f285a9123a8b..1d8970602032 100644
--- a/block/blk-mq.c
+++ b/block/blk-mq.c
@@ -341,7 +341,8 @@ static struct request *blk_mq_rq_ctx_init(struct blk_mq_alloc_data *data,
 		}
 	}
 
-	data->hctx->queued++;
+	/* data race ok: hctx->queued only for debugfs stats. */
+	data_race(data->hctx->queued++);
 	return rq;
 }
 
@@ -519,7 +520,8 @@ void blk_mq_free_request(struct request *rq)
 		}
 	}
 
-	ctx->rq_completed[rq_is_sync(rq)]++;
+	/* data race ok: ctx->rq_completed only for debugfs stats. */
+	data_race(ctx->rq_completed[rq_is_sync(rq)]++);
 	if (rq->rq_flags & RQF_MQ_INFLIGHT)
 		__blk_mq_dec_active_requests(hctx);
 
@@ -1419,7 +1421,8 @@ bool blk_mq_dispatch_rq_list(struct blk_mq_hw_ctx *hctx, struct list_head *list,
 	if (!list_empty(&zone_list))
 		list_splice_tail_init(&zone_list, list);
 
-	hctx->dispatched[queued_to_index(queued)]++;
+	/* data race ok: hctx->dispatched only for debugfs stats. */
+	data_race(hctx->dispatched[queued_to_index(queued)]++);
 
 	/* If we didn't flush the entire list, we could have told the driver
 	 * there was more coming, but that turned out to be a lie.

base-commit: 61556703b610a104de324e4f061dc6cf7b218b46
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210205165835.821714-1-elver%40google.com.
