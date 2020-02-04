Return-Path: <kasan-dev+bncBC7OBJGL2MHBB2XT4XYQKGQERUKB75I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 602B8151BCD
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2020 15:04:27 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id x23sf2488882lfc.5
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2020 06:04:27 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580825067; cv=pass;
        d=google.com; s=arc-20160816;
        b=kqd8RBNPXEaI0XOHgPgnZLCvfT5NG0xt6GXymLokRXu2f4IxH6CVPlDsh6QFuZh6L+
         NXHaUjJMk/M2/nDCddexAcAQew+GTEfP6YLpbnj+Jhri1MPXLI6X+hDbTvlbTiPW522Q
         Sszf+l8qcNw8i8KYGNGGmPmwkafWhGWmhciCUimvZPhz/fVik0EUvpk0nmMsw2KjJ3ku
         tmHWEjbJMYwuqCze5hof8YY2Ae4PAkHKjw8hTJN9BR1DgBFOfAdzVNZK2QPSCEkfwjwT
         fx7EdL83oKNDdrUBGySkqIqaL3fbpm/fAOcZSYC99QzcxCgZmsnel0FJvyn8Ser3fOKu
         zRMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=6ETM3viQI42iKUMzicavklQHPyECzjRNl1FLOAORPFY=;
        b=QCY1zipPdvliLztjboakVG6tgsIObn9tkEMpHOpKHbDu5wVkCq7mJs9VSc1aosDtis
         4kJWwSXgNokRB5B8sC84t9iF+7mRyG4ddnSIY6M3900MSxGi+gAHiowfkmTZgXswwjzp
         +6GtvqZDymb7IUY6akGKyR6GVPbWEa2325KCLV/Gq4CrMAjtKizMpvRSNdeMeYi/Q2p9
         fbggB4rdql9aKLqz/JhltPhRB5ZnmPQXMAULa0jPmzyAuAfZwDRz0vds8WPJyyCbr1Gc
         k+q7S2EZWwOVEyd059VhuZindLMppALTBHbhPB4wo22fIG7lX6LXBLWAEPZaj5l6Es4p
         Smug==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PD1xyBi0;
       spf=pass (google.com: domain of 32nk5xgukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=32nk5XgUKCasPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ETM3viQI42iKUMzicavklQHPyECzjRNl1FLOAORPFY=;
        b=an7aiBa6nMcmcXFQyha1leYpYdgq40tB7xq2wnbviWaCKTQ2RGs9npSS+Rs5GXv15H
         e5APw3CTcuqv8wZojbwY1mzzU1MS1se2pOvK0c53FPozJ5DY5blVDLGkfaJT0sPJFnWE
         iXYXyEOFoNFkHYdJ2JOvNAKvX4MVAvu+OQ/91ipioV15W47rYa3ed+sIOd9HcCr5VslM
         apvcT6EcLb2CVo+qtXgt+4aRnrqv9/TY06c1Wkq9X+phj4d1VeEuGh+onTDfJW8J/QpA
         wkGXjK8vJAdMoEFTmMQEnRdqUWrkieGqzrH1RswI4Zx46MVL+MPvxJvtD4kcUDWgdDfm
         Nn2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ETM3viQI42iKUMzicavklQHPyECzjRNl1FLOAORPFY=;
        b=gdqNXa9WFUFrTzu1yN8lAihTU0gkpP54+yi20P/tMPoQHiDMPfcNcrHCMaVRvmC7eu
         wn6xkGfwHnS1hA2LreLAkT0ifFvVNA9VIHmXJZRT65xfhdKU5SI/yh3jn88CC18pRsGY
         25tJ3ydcTQSILsCYE7sl//XNHpPIRlqQeorq7YBcZuvqUnC7WUvUSLszzvGYGBzkrvmp
         4d5nRcYmOqV8XsrMYutddHROGRwnQUtzat8vy4/OB+vCXwkDXF15JZdGTJnclnULM7qI
         RFtL8SuogUMeSOXtCcMpJPFlRXVigmrJQpH8C1p59mmGImIV5/kRKoXX2irgzMXqiSWd
         exbg==
X-Gm-Message-State: APjAAAWJaxc4fy/3OPJzQwXYpls82iwPUPVvcZO8cnMW1XFSsdsRoUxr
	UVaGhWqaJxCVaBfvwLR7yzU=
X-Google-Smtp-Source: APXvYqy9+Z1GaKZPyvYjMiS/UErRfSmil4YhvJcTumqt/luPGSB9WussDviN2wWYIviVoDDh1gEFzg==
X-Received: by 2002:a2e:b0db:: with SMTP id g27mr17026123ljl.74.1580825066906;
        Tue, 04 Feb 2020 06:04:26 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:3f0b:: with SMTP id m11ls1593759lfa.0.gmail; Tue, 04 Feb
 2020 06:04:26 -0800 (PST)
X-Received: by 2002:ac2:46c2:: with SMTP id p2mr14792104lfo.139.1580825066127;
        Tue, 04 Feb 2020 06:04:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580825066; cv=none;
        d=google.com; s=arc-20160816;
        b=NkkxkiJceUYhjXLCsx6/sLwU2jYSPtJBzBaj3tA8xswxwbRryVX3ZqyzP4vav0ZQvH
         wOkf9VrOqdUGA7JwRX9UYMEv3m1ceVW2+mKBhtQy15dK8mGZkTpW1iNjyr0tS8VGsLho
         /UNLQIVKbO30YpGqfYHyaRsbHkmqjGJ2GtHA8r1WDRqxWYtUZHEKj7bE6y0mtmz1hIq8
         cqx1AL46+hoc6OJgxJRtAh2IgVRJ/25hmL00R7mbyw61FBX1QWZpDeobzKWmb9zpN0E2
         xokII4VgHfZ+fNEEtJB4ugp9xk+nfypSNbuFqRx1eG+/VI80FE4kAPpTBVMLmvtsYY5P
         DY0Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=KtW08c4N/a2oVRHrX0WYeOZxmDiJvCqs/eWAvVn9zAs=;
        b=0VzVMeuVBy1LHrhq8iaXBK+Z2jM/mx2sqGhYXm6sffPRLnfDh3CIGnxvjmxbtoyua7
         QIIs6j0M02w0WfLZtTH3YIh+VJYKBgi5ApaMOnDQ4hQIdJZ+SnM6/srwQcHbQj7zCm/y
         j0KL2/g6BgyOe40fCW9AUsBev+NoYQ/yKS9nQiBSQWnGQTtf+fnQNelBukWtrccDWcT7
         S47HQLmteDzl6b8B3Rl4fKVgLhshRMlIJeanqQpFPKeYvzGR6ffIWEtEjnNhZz4yygCr
         jDWAxGc1wl7lPDGj37K/iBHrV/2EvqZNhkynGWQQ8K3Xi5c08x6chef7DfNEEnqIqLiL
         2M3w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PD1xyBi0;
       spf=pass (google.com: domain of 32nk5xgukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=32nk5XgUKCasPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id x5si1078883ljh.5.2020.02.04.06.04.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Feb 2020 06:04:26 -0800 (PST)
Received-SPF: pass (google.com: domain of 32nk5xgukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id n23so3653993wra.20
        for <kasan-dev@googlegroups.com>; Tue, 04 Feb 2020 06:04:26 -0800 (PST)
X-Received: by 2002:adf:fa86:: with SMTP id h6mr21824539wrr.418.1580825050694;
 Tue, 04 Feb 2020 06:04:10 -0800 (PST)
Date: Tue,  4 Feb 2020 15:03:52 +0100
In-Reply-To: <20200204140353.177797-1-elver@google.com>
Message-Id: <20200204140353.177797-2-elver@google.com>
Mime-Version: 1.0
References: <20200204140353.177797-1-elver@google.com>
X-Mailer: git-send-email 2.25.0.341.g760bfbb309-goog
Subject: [PATCH 2/3] kcsan: Clarify Kconfig option KCSAN_IGNORE_ATOMICS
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, andreyknvl@google.com, glider@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PD1xyBi0;       spf=pass
 (google.com: domain of 32nk5xgukcaspwgpcrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=32nk5XgUKCasPWgPcRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--elver.bounces.google.com;
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

Clarify difference between options KCSAN_IGNORE_ATOMICS and
KCSAN_ASSUME_PLAIN_WRITES_ATOMIC in help text.

Signed-off-by: Marco Elver <elver@google.com>
---
 lib/Kconfig.kcsan | 15 ++++++++++++---
 1 file changed, 12 insertions(+), 3 deletions(-)

diff --git a/lib/Kconfig.kcsan b/lib/Kconfig.kcsan
index 08972376f0454..35fab63111d75 100644
--- a/lib/Kconfig.kcsan
+++ b/lib/Kconfig.kcsan
@@ -131,8 +131,17 @@ config KCSAN_ASSUME_PLAIN_WRITES_ATOMIC
 config KCSAN_IGNORE_ATOMICS
 	bool "Do not instrument marked atomic accesses"
 	help
-	  If enabled, never instruments marked atomic accesses. This results in
-	  not reporting data races where one access is atomic and the other is
-	  a plain access.
+	  Never instrument marked atomic accesses. This option can be used for
+	  more advanced filtering. Conflicting marked atomic reads and plain
+	  writes will never be reported as a data race, however, will cause
+	  plain reads and marked writes to result in "unknown origin" reports.
+	  If combined with CONFIG_KCSAN_REPORT_RACE_UNKNOWN_ORIGIN=n, data
+	  races where at least one access is marked atomic will never be
+	  reported.
+
+	  Like KCSAN_ASSUME_PLAIN_WRITES_ATOMIC, conflicting marked atomic
+	  reads and plain writes will not be reported as data races, however,
+	  unlike that option, data races due to two conflicting plain writes
+	  will be reported (if CONFIG_KCSAN_ASSUME_PLAIN_WRITES_ATOMIC=n).
 
 endif # KCSAN
-- 
2.25.0.341.g760bfbb309-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200204140353.177797-2-elver%40google.com.
