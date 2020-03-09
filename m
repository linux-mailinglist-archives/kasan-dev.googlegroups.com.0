Return-Path: <kasan-dev+bncBAABBPFGTLZQKGQE6HA3DYI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 32CCD17E7D7
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Mar 2020 20:04:29 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id x2sf8069715ila.6
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Mar 2020 12:04:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1583780668; cv=pass;
        d=google.com; s=arc-20160816;
        b=w5uOGjp3O04Jqrpu/sXMXKBNQHEqfKG9b37u3j24nyfnovyhlu0hGjScM6ClESbwB6
         pqSghd5RAHszZ+9ZsX/NiSS+WU+/P6pZHNj8xrRLYUeNU1mT6LirRHlpDA+3abvgNbEf
         PXXOsGC8jXvUMCgd69T0ILfH4hwyjGPSBg3YO3CVob4Rgk7ii+hMf0300ute4epP+bAH
         sSvB+gbb8sSQG5Zeffp4oitxK66kVu/kYGgkf3m0DyDQ2yYIULpbVQmIaJbEu9S9NSDw
         oRX88Ov9mb7d/2/B+nL22gHtWLQ+k67ofKJM8HGw1k6+YPggz7gUYO9x3SJfp+JQSVRP
         dpww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=hbzMm9mSpMqAgbxSCP9sTNnrdvfFbfCPpUXran1J1Uc=;
        b=g86x4QeKMso6EbWGrF+E7rwcurMgTpUAlJqEZZlir7nIh5veEiKW/4F2avA6U+u7Ml
         kiamEihcRYoLSDn+ycaWNuvcdNQ9Hg82QomEt8rnCoXSAseAiqMhcSi3V5jbu+cVbXfG
         7UZ8NyXVd22lGNp3VNbW3eBUuyEFx3ngnQ4xIbO1Mur1a5c0XZFUSgvfSXFegQdMGfCX
         EEV50ReN3ojWjRZDy90otkbzHoG2GF/D/i2mba0cYmvPNZO16aYU9bctg0FdH2m2AuEs
         b+aDJnNaacHzTeoxGUxglI0coEKf9oKook8aWrLAuepwwyofwJmBGFwULLvqbt9gztFJ
         ZAYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Udws6YeY;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hbzMm9mSpMqAgbxSCP9sTNnrdvfFbfCPpUXran1J1Uc=;
        b=l4DdCBTXVBSbiff9pfF8ohmAxpjXvWkJCGbDQmKE5eaYkWk4ml7pD5cCVP0nydLE/L
         KdrFMrMvdE7nTONhFG8q43gEK+o1tphTm6q3Pt0brbH3jfi97B3wdxdDoGQTKs6MdWw2
         jv845Bu9UMJ4Fn08Q2VEoLIqiP2It/3wQ4Gw7b7dcG04TiWCF7teIr6lbs54tSktyGar
         PUo2T2/RAzbP62vxapsRZLAVcDhp3z0T868IKiU3ZES/hoPqrb6Pzt1BFZPeCd3745D8
         JBZq1X2A+gXnV7veA/p3KWIg47RtIAuCPruMpIwvc3GLthcrP4rxaMIyQFrE0g1a8VCQ
         /3Jw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hbzMm9mSpMqAgbxSCP9sTNnrdvfFbfCPpUXran1J1Uc=;
        b=bgW1JJsAROztT8lyY8x1O5LPcScWDjN7tXrUSxAD3MYl2a3YcKI8IG3M19DxXbWtM4
         IamWE8YiOPQPFIknx82BN7qUe3VtHgBrlgw7dixqXtQEqeIga704W3jNaQawCAp5Qz/j
         OGSR4+qsZcPR/pSdOr1fcklq+bvN46xHfq8xlXUmCL2/QZjx/CJBfFQSXgVfHufteM9x
         s35To73Ug0c4ZpKyoQt+2YbAc1AiVK6W4KPmp50oRFtKzb+j1SYuF2ViD2P6N2sU/TKJ
         ntapCWJ5FcayzP9ZmL0kZbSsFfr+PZuJ1B4CnfaMph0lr7zdlQ0a2eZW3c1NxKN15eyW
         yjSw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANhLgQ2Yov8nbd9NNs/oUvzj5a9S/xu6Sr/Gmp2ZE029xSSm/6RrCxr0
	To3mLAHNIF1NehktG2/ieTs=
X-Google-Smtp-Source: ADFU+vsdXXdsy0ell1vvgFR/SN9y0gD+QeUdJw2KlT45iBBzqy110fIa+betyPYMGkK+plG2Hlv5eQ==
X-Received: by 2002:a02:a412:: with SMTP id c18mr17004851jal.69.1583780668193;
        Mon, 09 Mar 2020 12:04:28 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca92:: with SMTP id t18ls2723211ilo.5.gmail; Mon, 09 Mar
 2020 12:04:27 -0700 (PDT)
X-Received: by 2002:a92:5f5b:: with SMTP id t88mr2261363ilb.192.1583780667826;
        Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1583780667; cv=none;
        d=google.com; s=arc-20160816;
        b=Fj65Brng6ujXK7OMtgCtCpkHOev4B0zm3cCwePVKsvBTktih4GsB/AgqlRDxBH31h1
         ygLSzLMh4T4emhM3a3g0eZUdywwcBz42Fos/0iQfzYDU+oUBp2KQPejVoJ64DdrYoK/f
         7vkiH8Zlxuqvubs8boGIHmuU+4PbTxWEXVEonShG3zgjHn7oP2cB54l4WFU+9yasvDya
         Hzc6XnswBbvN32skvT9J/1taZU5wmQ3YeL1X08mE53HDaJymVHFWp69/pE3V9ontVa/v
         ITRtTcVHGdBc29IjDu4fANXpnziR1JT+OgfRragXkdJJd/qnKceuRNkKCNBYfHZJuNZp
         0o2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from
         :dkim-signature;
        bh=15ARx1YToHX4rpjIXyTdjQwrVNcIJKN1xPCYiL0kg0o=;
        b=00FSXpIaGeaKZe0pp/D+K8zG8uo/vFmwiUxQoHVmqsqqcGc9em6wUVkeutB3OH0xYv
         4jnn2iTjkdNv6o+5EJwbB711dBs+AFWTHBNrRjUiUdJlmaoc9bZ4mG258Ttufuf0kArg
         fEQ3L9gX5dNqW/1IWpXTyCkg08dc1JCJla0rsPEDA98Aj3ZKRnrGcjTHhvEgfGefY4sE
         KucxC70J187eeRv9Fu35n6HnGf/fyt3p6T3aeqbncxRa7lGYZxqb7DwxGW0Ts/svKQDI
         o28jeSOiUI60WIwqBQ1n4IIAkMeyAP8FxUc49zZsC1e0QIBEK/ub6UZn9o8uShXVi1re
         +mvQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=Udws6YeY;
       spf=pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=paulmck@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id d26si571861ioo.1.2020.03.09.12.04.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 09 Mar 2020 12:04:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (50-39-105-78.bvtn.or.frontiernet.net [50.39.105.78])
	(using TLSv1.2 with cipher ECDHE-RSA-AES128-GCM-SHA256 (128/128 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 191B62468D;
	Mon,  9 Mar 2020 19:04:27 +0000 (UTC)
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
Subject: [PATCH kcsan 20/32] kcsan: Fix misreporting if concurrent races on same address
Date: Mon,  9 Mar 2020 12:04:08 -0700
Message-Id: <20200309190420.6100-20-paulmck@kernel.org>
X-Mailer: git-send-email 2.9.5
In-Reply-To: <20200309190359.GA5822@paulmck-ThinkPad-P72>
References: <20200309190359.GA5822@paulmck-ThinkPad-P72>
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=Udws6YeY;       spf=pass
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

If there are at least 4 threads racing on the same address, it can
happen that one of the readers may observe another matching reader in
other_info. To avoid locking up, we have to consume 'other_info'
regardless, but skip the report. See the added comment for more details.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 kernel/kcsan/report.c | 38 ++++++++++++++++++++++++++++++++++++++
 1 file changed, 38 insertions(+)

diff --git a/kernel/kcsan/report.c b/kernel/kcsan/report.c
index 3bc590e..abf6852 100644
--- a/kernel/kcsan/report.c
+++ b/kernel/kcsan/report.c
@@ -422,6 +422,44 @@ static bool prepare_report(unsigned long *flags, const volatile void *ptr,
 			return false;
 		}
 
+		access_type |= other_info.access_type;
+		if ((access_type & KCSAN_ACCESS_WRITE) == 0) {
+			/*
+			 * While the address matches, this is not the other_info
+			 * from the thread that consumed our watchpoint, since
+			 * neither this nor the access in other_info is a write.
+			 * It is invalid to continue with the report, since we
+			 * only have information about reads.
+			 *
+			 * This can happen due to concurrent races on the same
+			 * address, with at least 4 threads. To avoid locking up
+			 * other_info and all other threads, we have to consume
+			 * it regardless.
+			 *
+			 * A concrete case to illustrate why we might lock up if
+			 * we do not consume other_info:
+			 *
+			 *   We have 4 threads, all accessing the same address
+			 *   (or matching address ranges). Assume the following
+			 *   watcher and watchpoint consumer pairs:
+			 *   write1-read1, read2-write2. The first to populate
+			 *   other_info is write2, however, write1 consumes it,
+			 *   resulting in a report of write1-write2. This report
+			 *   is valid, however, now read1 populates other_info;
+			 *   read2-read1 is an invalid conflict, yet, no other
+			 *   conflicting access is left. Therefore, we must
+			 *   consume read1's other_info.
+			 *
+			 * Since this case is assumed to be rare, it is
+			 * reasonable to omit this report: one of the other
+			 * reports includes information about the same shared
+			 * data, and at this point the likelihood that we
+			 * re-report the same race again is high.
+			 */
+			release_report(flags, KCSAN_REPORT_RACE_SIGNAL);
+			return false;
+		}
+
 		/*
 		 * Matching & usable access in other_info: keep other_info_lock
 		 * locked, as this thread consumes it to print the full report;
-- 
2.9.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200309190420.6100-20-paulmck%40kernel.org.
