Return-Path: <kasan-dev+bncBAABBKNH3X2AKGQE5OU4ZVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id B7B9E1AB0D0
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:18 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id h10sf6033900ilq.22
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975657; cv=pass;
        d=google.com; s=arc-20160816;
        b=Nj7tVe2RJahIgCs0TMNBJ7vYtqFpLOtHtlI+oFGcMf1+aCMontS4SDB0AQhsuSzOMK
         sHr3zOpuH7TdeCq3ZNPCms/AC7HJrb6Gtod6SCp28Vy5NOb4ZvMKfD1uQShtQ7m8gK01
         YPvXggDKrBkF7Tdm5EMiktaFfTwyfCKeoR48m4Kp8/5Q7UjjpTyXKrFWmKT5AOc0Avzd
         yjtccJSob5KyIeCDkI5ccHv4Tt+RnxKO2++kWempXmVtzn+5GJSQBWSTLwKkLKN1IID9
         TxxuCEOSycPlnqe0v97K+yQTa+IjShMLVp1ew+ry4LYjEJ7QSM1qvYOkxCHmi1jApHmK
         EF8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=4BSzQONFi8qvCUc2Be8xV2RdAK5kK7qDoz62lspC9b8=;
        b=VfbjZy+JPPJ6YwYBa0Xo38rQylN7usl7N+r2OZhlljMKdjfmCZM1EkjYztJGq3v3W8
         qFcnz0N8J3B2YMH7Uq5cAx1gUGgkLu+oI7/Bk7BPDA/1RBM0mh49ZqxTUXTmaSNL0jH+
         wwPrdHVj52YWK9D7RNe804zPorRX+f3y8mJHu+4HKHbhfAxak0qfJCD6aLYvprgDQj60
         kCYADhoK4vjgIueZbHWVGC4uCUQwr0JlWcXHYp5g88eTfmKq1nFzIDPV/3rVvW/UqecS
         OhAGukoY6B2ulHrggjk2U6/jsXAQBgdU7Nr9iuvjViqKYZA8ymVsF3H5zzO+WEVxyBYV
         Bq/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=MKmQtSlY;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4BSzQONFi8qvCUc2Be8xV2RdAK5kK7qDoz62lspC9b8=;
        b=ZwLJ4FgiasuQhD/q1zF3vmezes1TpEDN3Mrx3JiUngBEu1vD7i2xCwMOrJuoYjKQT9
         1zKFNq++dZXdSh8dcJDhzvd8VQ0QxQ92q9v5dO6Io12ph9ad1+qAibT0+EY1eAsGU5yb
         84uirWNe2PKeEfaR965OwxZr2ODzvT57TuifdzBmc5xtj7fPEAIYOUXLhBAvfNrP71a1
         BIar3G+B1wkRm1Ijjj3ZoorH/Y1HqZNM++V2rxl6OqvVdyF2aUn1kc/F9SSfM9kcRfCj
         Ilp+nz5U73h0l8kCbeNmtNCytepIG9u8F812YsZzQTQIfU6LTF2B5FcjXCvExYI8+Yrv
         SEOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4BSzQONFi8qvCUc2Be8xV2RdAK5kK7qDoz62lspC9b8=;
        b=GCUcGPVAAM9q8fuyEfEFx+qCLTph4YnQACRnVYRSMVU6AXX44/6XiBDZ3SQ7AQM7vA
         NOmQCPO2WiE3zV3ia5LwRQKcbObA3SBilcr79OxNqz290K0ld4Bbsk51yMUNGoQ3kIDa
         Sm7DQLjJzJkc2agh83aeuaM6x7/yE4sayXt0RuOg8NdzNvVFPG9D2mAO18rDvEVzTsaG
         SvLs3h5JHm0nkQHgR4HEt48loe/tuoyU88NxUDqn2SxDVNLvh0hUYF7eLF4vQig8hxSi
         KoRbrJlkAJQ8NAvRzIi39VYO4HhI/eDqmidoG0IB8nFO1LNAw/GBp524FMDgSTviNmw3
         cP1A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pubd63CrQmpsPrMccl8wc8ubgoNzuWr383CyPvfZnLUGwDhQMc7y
	uRIh+rD806DsbhDGgLPdDNQ=
X-Google-Smtp-Source: APiQypIidlHRYOl3oz0MaNXSTP2H01TPR4b4gBBvF55LeNP/SjDaSL215lS3skOojfdqcQGpeHxGEA==
X-Received: by 2002:a5d:8b57:: with SMTP id c23mr27542879iot.161.1586975657756;
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:da50:: with SMTP id p16ls1673305ilq.9.gmail; Wed, 15 Apr
 2020 11:34:17 -0700 (PDT)
X-Received: by 2002:a92:c788:: with SMTP id c8mr6709372ilk.279.1586975657330;
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975657; cv=none;
        d=google.com; s=arc-20160816;
        b=dCjC8vUrm3g1DAtUygbMfK7y1fNucvRVKU7HZSgkrn0ur236vDcWBvZK1ebWm7wEsW
         mfI5A7ZVcDkdrZLIMDskIH4TDnmKaHWHPnzmpKWXphtr0j2LwtxbBxZo2AN/mQIBU9jR
         3qEpkZdNrFxn/BPbhQ5S8QL1CCdKmr466y+4SS2vcpgr7FOF8nJOUo3VhnX5wHG5fzVn
         uqE+l51zGKG5GRUwJjf4raZYRkZmmIXffdye6h9pRAvQOgCT0AV5OczZvvYgENGfnamT
         A01muI5A1St4yyffysoEX/lI1g613EDmrJV1tv2d9Z9/IRX+0WwdyntbszLGLeL29kto
         DUQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=C0Z3UhAR3AGX+Jcyg4v/MKi8Bmp4qrJarD6KpHQxLH0=;
        b=g+wbLhXZBsWv6NxoWziGp24v/cbVQhFhd1tz2GpQ5SU+RMMpymX3PTGjkeSPmwcRQ5
         6VvOZK2yHQhkkDK/wVOC9mo7Oxxch2J5xeInVJ4tXOUlnbQPL0m8XO2geQ7MmxYDV6vq
         5QdcyU2y+bFZxuRBftPhMONCs46NkIvxscirhVIMMB8U4sYLTXNEK7rwXkjw4rXfNdrQ
         JlKIWuj7BvqA79swaxByompx6eE3vTl1+AMOHIIbCE3T75gkGAagEbBQDLK6t0kp80lK
         cxrkY2yaVRc/6s6Z+WCEf/G3ixc7Gss8v+cO3IDE61bA2ZJomBOoh6cd8eK5B96m5VT4
         LG4Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=MKmQtSlY;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x16si329587iov.1.2020.04.15.11.34.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 9A9B82166E;
	Wed, 15 Apr 2020 18:34:16 +0000 (UTC)
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
Subject: [PATCH v4 tip/core/rcu 14/15] kcsan: Fix function matching in report
Date: Wed, 15 Apr 2020 11:34:10 -0700
Message-Id: <20200415183411.12368-14-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=MKmQtSlY;       spf=pass
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

From: Marco Elver <elver@google.com>

Pass string length as returned by scnprintf() to strnstr(), since
strnstr() searches exactly len bytes in haystack, even if it contains a
NUL-terminator before haystack+len.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/report.c | 18 +++++++++---------
 1 file changed, 9 insertions(+), 9 deletions(-)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index ddc18f1..cf41d63d 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -192,11 +192,11 @@ skip_report(enum kcsan_value_change value_change, unsigned long top_frame)
 		 * maintainers.
 		 */
 		char buf[64];
+		int len = scnprintf(buf, sizeof(buf), "%ps", (void *)top_frame);
 
-		snprintf(buf, sizeof(buf), "%ps", (void *)top_frame);
-		if (!strnstr(buf, "rcu_", sizeof(buf)) &&
-		    !strnstr(buf, "_rcu", sizeof(buf)) &&
-		    !strnstr(buf, "_srcu", sizeof(buf)))
+		if (!strnstr(buf, "rcu_", len) &&
+		    !strnstr(buf, "_rcu", len) &&
+		    !strnstr(buf, "_srcu", len))
 			return true;
 	}
 
@@ -262,15 +262,15 @@ static const char *get_thread_desc(int task_id)
 static int get_stack_skipnr(const unsigned long stack_entries[], int num_entries)
 {
 	char buf[64];
+	int len;
 	int skip = 0;
 
 	for (; skip < num_entries; ++skip) {
-		snprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
-		if (!strnstr(buf, "csan_", sizeof(buf)) &&
-		    !strnstr(buf, "tsan_", sizeof(buf)) &&
-		    !strnstr(buf, "_once_size", sizeof(buf))) {
+		len = scnprintf(buf, sizeof(buf), "%ps", (void *)stack_entries[skip]);
+		if (!strnstr(buf, "csan_", len) &&
+		    !strnstr(buf, "tsan_", len) &&
+		    !strnstr(buf, "_once_size", len))
 			break;
-		}
 	}
 	return skip;
 }
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-14-paulmck%40kernel.org.
