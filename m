Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE5WR32AKGQEZ6X76XI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id C8FD6199F29
	for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 21:33:39 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id w12sf13383926wrl.23
        for <lists+kasan-dev@lfdr.de>; Tue, 31 Mar 2020 12:33:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585683219; cv=pass;
        d=google.com; s=arc-20160816;
        b=0oc8qjbf7kFn/woYkYrqH+Ezr/G/vUTS3O3NOTzVjnqtV4tKT6QlI5PI6njy7+l2cS
         Kj+D8w10+EkdoNMw/FZ04vGTm/ILRE1twtEy6awUpiF+jC1/2siXBSRx1OuowBWHtn5D
         j5ZYAF5LYWMUni33WHB0TJCbs3erBI758BPO27jQBjQ+H5RDs1EhZdTi/b5dyw8q5T3A
         ofOB2zsFlaNHS4eC86Su14sTrlq6ACF9DTVxUzXleKCUc/hZ9GmO4XtEDHSmu8meZHuI
         XO6bhyzwmAoXoHXXuOHrH9nKOs/MPdTjPDgxffK2i++7s8STkkseNI/JKN8tL2pvOpTO
         Vw2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=mUWLdj2sd23MohKF1fOwl3OOlrQNCJvZu108mVjswTg=;
        b=XeS0FVTx5aGDOztH8bwkJ0wcUsf0ZXCl9bUrvaNO2M9dOiFyOrQlf6dS3Y/KDkU2Ot
         dkzIoo4LKY5eL4/3HBJppOrPFCHHaoUp5BBSLbfVFklQVmplSPUCI98XrfzW6werSzSV
         vGCOXQrjHKXEgWNS9WWJd7cWDvnuzri2lskv29LNTGkJZ85LUxKfKs8A3fvDhV0r5/w6
         /7P0MPNFKP6do9hZm8YNHsYEWFPARFn3Pfy0Z87qMemkC3C5Syfwyo5Bv7kY60jCXZq2
         4voJBhXh5d/QliDaZnfXztbL/+h2sGvj5G+1qJL4lZd6qLSgI673msLveNNkeCS55WiT
         EoRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bcrbEQbz;
       spf=pass (google.com: domain of 3epudxgukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3EpuDXgUKCVEx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mUWLdj2sd23MohKF1fOwl3OOlrQNCJvZu108mVjswTg=;
        b=m9p3W7EzsW/AsJusgIfct+ceQ4W1oL7QJeKbGBazEwoyv6ruAM1nWW4CJ2GVEv8U2+
         ONT9EzkIBOiupNx62iUWvS1/NNQvlfdXOcYP+Z0d25Q02wQ0Jx0hnaA6+4yXbcDFj7Bz
         XV5ts15qf+FTeRx3wNp6c8Y2gMyr4el9wgqkXluPeKTqNTSAppNM52QxdTxFfybnR71C
         tsy1dG+EcHeUCc8PUbIU8bdTyBOEU65MryjoeX+73x4pVCR4/upVTsN/iWB/DdiGahiJ
         0BRXuVHs17jJstpjpDCkrx5Wrg/yNcC2iah7eCvJisIJtZlVa3skt8/3qFubTuDR8OGF
         DpKg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=mUWLdj2sd23MohKF1fOwl3OOlrQNCJvZu108mVjswTg=;
        b=Rn78r+tx8k2Rd6AkbAyuepyKd7Qbz0C90Z0zH/E2JkrwSzatE121uSZN44C/4nn/6u
         kNiB8lV2vK5rBAelliS6pRPPK9LX5P9XmLSUZSMlWVvoIh9U9hC802DpotH/5YYin29U
         F3IBUaFFs9kXrICgeE/1eO7LxYdXBQY73Kl+R7dWvr0yE3TMdvZx+oDKzth6jfpl308r
         p8EyrRmKPNUqcNjiEP1VdJ1D9tIjQD5j31dnFXOaeA8StgqIefhE7MA3f+aSdn1d4sep
         +QevgVshW0uoKK/9cKODglxmdXyAinRFQQU1YEGi2G1rpH/YBpKSN2jjjSK7x+y9a04m
         Y2bQ==
X-Gm-Message-State: AGi0PubBl9+qmcksu1XB0tGQ0TIWPdXfadrU+fKBBU8bi5/MB6yyfsEO
	IdiTXBTAKKINsWD+qk/Cfn8=
X-Google-Smtp-Source: APiQypIzkXyIkTEjN3ndvSnpCkRMmjHSSIgbHMT/MmvRhUOfS6l++HFc7zbJK0YTlWa5HaK0vFCcFw==
X-Received: by 2002:a1c:2c41:: with SMTP id s62mr422360wms.188.1585683219549;
        Tue, 31 Mar 2020 12:33:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f2cf:: with SMTP id d15ls2267810wrp.8.gmail; Tue, 31 Mar
 2020 12:33:39 -0700 (PDT)
X-Received: by 2002:adf:8187:: with SMTP id 7mr23097877wra.358.1585683218984;
        Tue, 31 Mar 2020 12:33:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585683218; cv=none;
        d=google.com; s=arc-20160816;
        b=etNNWCpy+YEFMo2FWNI0TqmsJVJoGVKwSvKyDzo7AJnpgG6k75Sg4Cp7BKKZsAulfw
         AnzrMEm1X9OyGAqe5YXAgsF5afm6kbmNZTqS6JqWF/xmNJ+gJUKc5LLix6EuWJS94Qwf
         KD0ZXSQd6j+GaSVMEbT1rFW1mZBuamvRV7u9vrgKKJ31yKw+mkrkQp9srS6YR4s3ZaVU
         6h/7RXGPhP0VenQBkxZfqCzZtyf+qScF6MT3SuxOnCLxU9hLxgOeCt4Sm0rLmf3rhBCk
         FN4h845tQU2HqLgL2Q2/xx8uti7SI8rMvWPgwUKbqh8ezCYEZgweBspj6mFkBIl8AYF7
         OlXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=9pebgwHDTkH6XXgFkmfU8WrI61o8Xng8dx0KtxlN/Ec=;
        b=fb9DCXR10Kkpq1VO5n/n9rO2JW1i6FxM/G5WdUTDMJgh08VVIqGnFYdV0Nuela0e7a
         VqmR6jJ7fAo2N3uyb6Wuc8v31rsUpYhJqAWJoexwTigpUlJy1vnh43nqlpDfB2Xetj66
         NHJB9yxFSgTkoVRuq9L4eN4XaBfIto8n0upU9vDYd1IRQ4xt1OvWh/EgjRx4AoYVue1V
         /+XC92einvUhwrdlMUPaPrlFy0ds2gyPYn8SeHIGnWTunahHH8Vk2DsKpIr2fUclVNqk
         N/xicSSY/F4m1Ejyt7k3bAzvhUuGC4xDb59t/hcdfxFrrq9zbxLg3/Uk0xAJ6ivJ+QP3
         y2vg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bcrbEQbz;
       spf=pass (google.com: domain of 3epudxgukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3EpuDXgUKCVEx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id x204si184798wmb.3.2020.03.31.12.33.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 31 Mar 2020 12:33:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3epudxgukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id w8so1470190wmk.5
        for <kasan-dev@googlegroups.com>; Tue, 31 Mar 2020 12:33:38 -0700 (PDT)
X-Received: by 2002:adf:b1c6:: with SMTP id r6mr21490360wra.49.1585683218503;
 Tue, 31 Mar 2020 12:33:38 -0700 (PDT)
Date: Tue, 31 Mar 2020 21:32:33 +0200
In-Reply-To: <20200331193233.15180-1-elver@google.com>
Message-Id: <20200331193233.15180-2-elver@google.com>
Mime-Version: 1.0
References: <20200331193233.15180-1-elver@google.com>
X-Mailer: git-send-email 2.26.0.rc2.310.g2932bb562d-goog
Subject: [PATCH 2/2] kcsan: Change data_race() to no longer require marking
 racing accesses
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Will Deacon <will@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bcrbEQbz;       spf=pass
 (google.com: domain of 3epudxgukcvex4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3EpuDXgUKCVEx4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
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
Signed-off-by: Marco Elver <elver@google.com>
Cc: Paul E. McKenney <paulmck@kernel.org>
Cc: Will Deacon <will@kernel.org>
Cc: Qian Cai <cai@lca.pw>
---
 include/linux/compiler.h | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/include/linux/compiler.h b/include/linux/compiler.h
index f504edebd5d7..1729bd17e9b7 100644
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
2.26.0.rc2.310.g2932bb562d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200331193233.15180-2-elver%40google.com.
