Return-Path: <kasan-dev+bncBAABBKNH3X2AKGQE5OU4ZVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B5D71AB0CF
	for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 20:34:18 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id f4sf13004273iov.22
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Apr 2020 11:34:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586975657; cv=pass;
        d=google.com; s=arc-20160816;
        b=gUwWHMnsG8YJ89SG7yjBWEMg3UoAYVCt+0ndy9iVBQaqe5oR3nG7oF5GCbqMABWA6f
         1cs1yeGKp11VKlhoEQJflrU370zYykX/qyiIc+GVja1wccPJmBDhZoChXIZ9d7lYEo5I
         GJOIS0sNUEKiVhc0IiAaetjpp2SGYzSExTASutnNIF/7gNYW8BZFIvJVUxF+KBiDRSv/
         utIhQeme+yI6cyyQIDsBz7jMW/9/Lh/cxGdoY8P6mjdUX4rELgDh17NsXH+xPt+46PNs
         t3LqnTjETfqJi04Z3SXlWWN9YmEwRujbJfLLcf5OxkTkC98ZkzD/nWPGPYz87h0+n4+3
         MqVw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=RObYv5OYOn0iwU9b3LSZLvhjVr6RikjHhkS+Z1y7jcs=;
        b=FC9OTcCt5EFQZsA+UGeCsn4KVkFK8HlUooVZxk0WOUeKt81dgLZl8Qsv2sWTtpNOSQ
         RBItz9LhUNi+6n3OGrhW4BL/C1V7N9oO/YckJ/sktHXL3kCkCTkqOPvTnhcaowN0xAiL
         GPi8+/E6zXCNR8IISFqJY80i9HMWZnqragAIhHOWwg6E7yvZF7JATPcvxW52+hkQLWij
         b/d53QVWiEqhMdp6Ef6MOO4Wb3JlFnhRi0Dm79nT2rADDEJLoRD0Vw5ZiSnq03FeExGK
         1rvx5qsGjI6NFEJnJ7banWAc0EIR/4DM6c8Rzv+yoHDYS9LEZqmi7kdmpm/DeM2CNsFO
         cLNg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=g9gpm3SV;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RObYv5OYOn0iwU9b3LSZLvhjVr6RikjHhkS+Z1y7jcs=;
        b=IJ/XLdldl3vwaJ0T1g70sakbHc8MfUbG9pSbwscKBxxlO7twTFZdikLIr3vYTXgsjG
         lyZplycYpya9AZDmmQ51RajUZEYUnkjsaGPXRcCuxdPxqAPpvpzTyfpfQrQyyiEn2lt3
         kaBBZEftyfMAKERUQiTOHf6ZSotc0pGxJ5RLJ4M1HvivMVWeae/Ik0CULI+5uBFXAmB6
         L6zPDeh4xwMEJBLEH8j1QumI8L15A+KTBe63dvhhP05bLElQq3kTXiNGo3ZjODN1hRqr
         LYkuTHLM5ZIhOH2wgsW/fGiaf05p5UP7P3z5IO7g9uT3L00z6ix11vDBPVd6ubg/tm6b
         xiUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RObYv5OYOn0iwU9b3LSZLvhjVr6RikjHhkS+Z1y7jcs=;
        b=VVZTFuJFnUkKW+g8MhmH3Nfgk1ASQDOUSeRZHkBiGf277dW9xrLPwl6Vf9b1WVUzfq
         fvhgN0sxfYo2wj7U6mehbng9TUSfgeQ71IeSiqTt5KfEt4LnWBPHbeEZUOmPLs1mD4UR
         OyILqg3cRMfegu399RMM8x3Ny6/Ny029JUflI3XZWoOl2aQDGWcsWPDXgh33YOLCKefV
         8s1OYPzXBMJsnj57XwvE57EP67LHwfs5IQVcOA8u28xNCt0xYFyBRb/UmH+SVvQkikJU
         42zZTVWMzoc5MvMmSRMJLRnFYGk/M/aRkHmw+WUoopfYv4y2T6+nnt4onDKz9e27al+6
         33aw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub8ZM82CJ2gPnoh/SmbRonnRy9nmGgD/Ey7zZWmUeemxiYULuav
	208mOGhvque0qfeJSh+qC2A=
X-Google-Smtp-Source: APiQypK3cR2XFEkn62OHNBzUwLZdEbrZT36ONSMKtMrZ6g8YZe+dpy4bH28ly9HbJhYKtUMWzEXamg==
X-Received: by 2002:a6b:6e08:: with SMTP id d8mr6231326ioh.167.1586975657466;
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:52c8:: with SMTP id d191ls1674478jab.6.gmail; Wed, 15
 Apr 2020 11:34:17 -0700 (PDT)
X-Received: by 2002:a02:5249:: with SMTP id d70mr27629996jab.121.1586975657103;
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586975657; cv=none;
        d=google.com; s=arc-20160816;
        b=GSkGIgr+TiGYrBzOpcdBdR2X8yMFJAyqxlFTcCFY0Mt1c5sse7Ablc28751lz1qBzI
         rHGS3MV6aKh7rX2/JEpS6m62ae+uKtXvhyc6xj+eNQHv08kkK88sAzQfdXmBTwaiT7Tm
         493pOQ+/VvLA/NP5hAAnxmM0EHOqV2sMOJ4jHV0rodeKouBrMrExtU2wgwdw2/74Et5d
         8Y0yZFEL71GigaGfheHtkbCt1y37fPBWd82hPTcQW+u/0zRwsbcwF5OVmYe0iHEvnbLW
         FquVIJjUSfs/Hnx4ypvC/X9s+5QLxwULpcnMTQcneOOZDG3pz3X+IKv3L62fxZl7W92X
         Y7Fg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=4qsGGHNlyxCnlawrzpU6TD6qLJEgCTW3wjFXzxEKomc=;
        b=a6dopXW+ZkLsMoFDw9zTZljGTiHQApoFKmoH0YjZw3nOjeqK1y1Hj9UekTbbrdVNa4
         0eCEwem1WssEhfRb3Wy/p/0Rhe7OWr7IXpeyEwjus5/mKemmLXGyWxITX+gX8nVCVJFr
         ILEKSROBKQaRVj4C8Tr7CP6BZNO0Foo7OOVc8AAD8+4JGM/lJ2cIfZKkxacoKe/nzCvU
         KgKXDRjPQ3zjovhJ7Yv6Xy1gnwrUOr5sW6lO9hAil5ZTNvv9gTMufD6k3DGClk70lcyJ
         CCWjG6awnQw5+FN3z1/OtFOo+WCzlxBYiEbmdC0HMRCJ7OGSe7s3zvOory/QrvYAqfh1
         2B3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=g9gpm3SV;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id t125si1768054iof.4.2020.04.15.11.34.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Apr 2020 11:34:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 57D3721655;
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
	"Paul E . McKenney" <paulmck@kernel.org>,
	Will Deacon <will@kernel.org>
Subject: [PATCH v4 tip/core/rcu 13/15] kcsan: Change data_race() to no longer require marking racing accesses
Date: Wed, 15 Apr 2020 11:34:09 -0700
Message-Id: <20200415183411.12368-13-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200415183343.GA12265@paulmck-ThinkPad-P72>
References: <20200415183343.GA12265@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=g9gpm3SV;       spf=pass
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

Thus far, accesses marked with data_race() would still require the
racing access to be marked in some way (be it with READ_ONCE(),
WRITE_ONCE(), or data_race() itself), as otherwise KCSAN would still
report a data race.  This requirement, however, seems to be unintuitive,
and some valid use-cases demand *not* marking other accesses, as it
might hide more serious bugs (e.g. diagnostic reads).

Therefore, this commit changes data_race() to no longer require marking
racing accesses (although it's still recommended if possible).

The alternative would have been introducing another variant of
data_race(), however, since usage of data_race() already needs to be
carefully reasoned about, distinguishing between these cases likely adds
more complexity in the wrong place.

Link: https://lkml.kernel.org/r/20200331131002.GA30975@willie-the-truck
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Will Deacon <will@kernel.org>
Cc: Qian Cai <cai@lca.pw>
Acked-by: Will Deacon <will@kernel.org>
Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 include/linux/compiler.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index f504ede..1729bd1 100644
--- a/include/linux/compiler.h
+++ b/include/linux/compiler.h
@@ -326,9 +326,9 @@ unsigned long read_word_at_a_time(const void *addr)
 #define data_race(expr)                                                        \
 	({                                                                     \
 		typeof(({ expr; })) __val;                                     \
-		kcsan_nestable_atomic_begin();                                 \
+		kcsan_disable_current();                                       \
 		__val = ({ expr; });                                           \
-		kcsan_nestable_atomic_end();                                   \
+		kcsan_enable_current();                                        \
 		__val;                                                         \
 	})
 #else
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200415183411.12368-13-paulmck%40kernel.org.
