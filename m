Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZE522AAMGQELJNYCKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73b.google.com (mail-qk1-x73b.google.com [IPv6:2607:f8b0:4864:20::73b])
	by mail.lfdr.de (Postfix) with ESMTPS id AE8163096EC
	for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 17:52:53 +0100 (CET)
Received: by mail-qk1-x73b.google.com with SMTP id c63sf4282197qkd.1
        for <lists+kasan-dev@lfdr.de>; Sat, 30 Jan 2021 08:52:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612025572; cv=pass;
        d=google.com; s=arc-20160816;
        b=uiWbpRJqqFP3ZA92jMrZoVTd3D8Z1TnZmvCzw/k2Dtrq2J47+2dpZzD5OHy8NtNnzt
         UU04tkDNxZE24tCQz4P6B62AVjEXZ8AGnyxD61OOouk6zAeDCWZyCQQ4TjZNincM4Rlh
         KSee/b65bz+lxOzg57m1kspe7OuBUYpyXiyNQtzpeS0ffIhwDeUIyeUNr/668wvoQXUD
         kjCWwRJt3NCSwvnUy8iEVunQKSD6l7YLVEyMdfVI2rSH2x37dw27LoJ0on6IJZnt5a78
         gtzsCqENosK7ToPOlD9odgVVLTCAU+KgdCv92Q4+UFBoT/nfyNvSE0iSe6RKg2RF/iLb
         lS4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=OaZOGHBvoy74G6QAKN6CiGRq4ZOkqIdkOVlD2aJoO3I=;
        b=bGH3tGDxPFDJ6pPFBomsLBU06/hlGy4s4mCSgxeLj05+976kXSI4LKkuML25z8jXkC
         /1GkEkVwD4eRnryJNV6RDs9VZ9ch9SPnb7FZqYqgvwFT2EYBu13MVNN9M8F5utCVmdgU
         UW+xUgjkRg3E46H2f5zh//nT0dWqsjH9vyKsBH9N7ITIe5jQLQFOshHiZrVJs4dNYMJb
         Ioho+5oAN9E4bpyMXIH6tYmfn6qYo+fNNQgpc6oP/tpS690IkCZtmfn2TE+Ey40QB/D0
         3hgbKHYVHrYjeUmMZ8XSlZOVtEDRPOrwoYmvTeBlbxSy7LjDBfIhGBGk4glMIA/w+zD4
         5HLA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OaZOGHBvoy74G6QAKN6CiGRq4ZOkqIdkOVlD2aJoO3I=;
        b=bmwP8Y9gM/21KW/JqUQzoM2jcbEdlSp1SMvljI6ua3XMXghlyfY/QiMZ4yXY0COXC5
         8nEk/Y9XmdejCO83XkjR2GhqUVvKvxCToN+RR64KPFT7pZpAW0FO96sT6DmeizRITr1k
         m7gHAqZ2hk4nqSIBCFb6puEgzDiyhSpwDXoZjItqmgUWpBjVrvrTShZAZKG/oF/JS8/N
         mlAH/EdvM00CyG4EpTDV//6iYcF+zIfW1doXODWpOmSw+AuHsSRqxQ6C7cWXvqHzWDN5
         9CPsiD4vRpTp913GWzM8z4TMQ8FStYjdMpv6Nn6cYUMklTg1NcLWTZrYWnX6mQfqkCT9
         nJug==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OaZOGHBvoy74G6QAKN6CiGRq4ZOkqIdkOVlD2aJoO3I=;
        b=pW1VoVopLRe/4qSPVyh6qreB8BfMclaExZVVfMmY24GbxT4651VBKJqhpqjuc8yHfl
         Rj1HwVaIEx2hOudqiGHyMpxUFhbRInzcv+6rVKvYuPoHjakvM7mIIrZGPpRhUAf/ndOD
         ZG4vDygKn8s0gQXcj8EoXSwQ222qT5TW/ReNTEGKZBtJBD60a3XkRT5Rjoe+yisVj1DA
         I1qROqdpSc98/58cCBxH/J+r5nOWmtt41qAiHne4xuzycLxqnqZ5lm9Ue8FnWXqdUqfA
         yUEMdYUuYLvtgNBKbRnoTQGiOZM1e4wWhhgWxu/6A7LJlmY1q1iXr3pQd9kWcWbREQ95
         IQ2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532MXVsWV+tGQjpzJtw3Tcw27yZuWCgfFmM2FydTHTCsw/8qZNDG
	OsLNSkffm4GONtvSCwNAw+g=
X-Google-Smtp-Source: ABdhPJwylm90fOaBGg2ryIB07Z2U/+ktS7i46vbw0sC5P5OHc1vSmoszAqVCTaXXH9YFO788SlGiKw==
X-Received: by 2002:a37:a755:: with SMTP id q82mr9608774qke.7.1612025572786;
        Sat, 30 Jan 2021 08:52:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5e13:: with SMTP id h19ls321542qtx.7.gmail; Sat, 30 Jan
 2021 08:52:52 -0800 (PST)
X-Received: by 2002:ac8:6f5b:: with SMTP id n27mr4413055qtv.154.1612025572421;
        Sat, 30 Jan 2021 08:52:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612025572; cv=none;
        d=google.com; s=arc-20160816;
        b=BdUikj9YsHlDVsiUbHIdm1bWPTATFtXrwYv0EOVr7o1Hx4duR81Z+t2YMJmRNIJ8Sx
         WnqTzm/NUoBXSIvYO8AnhGiO2p8zqqHlquXmdt5kSdFcBkrXNLN5tUi3hCu+YLGW8axe
         GwDOoiEwLBdDXTGy2yTH0jX59q4ZcodMeGmWGzk7+OQGN7BJ0kpzdel0m9k65XFvfGhF
         WKfIuUbOJ99ukJsDFAYEXsOgl7TMnr7JhJzedmYmqNc/2Pdd8h/yyDbPi8HqBn8Yy9BT
         59bxX9qIwPNT58ddeuUph46WeieTScoWuNO14fNl8T88aOSHOj5HOtqOTLOnR5QUpgdl
         5TLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from;
        bh=66NUF2svl3NXghVPiBBpnsWX+ldmFm+jrfwDBc8eS1o=;
        b=oATkbEeSoNAaTV56MQ+aNE0CpaRed7REUryc+Gk3vIbJL8SzRHKnlLP+P7+xPVFZQb
         iMwQHmpLBk0smEtZR4N76+GuGstcSrmCSwtehBMDCaA4ZvIa+WkY8z60k6fKp+QVfnWK
         OMfxYzGxSHpvNXN2gHS64O6OIPN6lbT9PyKeTWjPQGi0KIxAWcxgr6NG4Fk5vtea5kxz
         qPcOP30JR/ByeeALaIAG7S6GxnEO+/JcUZutuUZ6l8Mrm4cg2jnr68MG085+azdA0+m6
         1vr5MGQ+mHtXJ4PZfBKAC0ZFdVIRZ+F+8P2v8BrfVUGwcT0wQu91WV05loIonPVkRqpU
         zCOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id z14si989559qtv.0.2021.01.30.08.52.52
        for <kasan-dev@googlegroups.com>;
        Sat, 30 Jan 2021 08:52:52 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id F3BC1150C;
	Sat, 30 Jan 2021 08:52:51 -0800 (PST)
Received: from e119884-lin.cambridge.arm.com (e119884-lin.cambridge.arm.com [10.1.196.72])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 130AA3F73D;
	Sat, 30 Jan 2021 08:52:49 -0800 (PST)
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
To: linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v11 5/5] kasan: don't run tests in async mode
Date: Sat, 30 Jan 2021 16:52:25 +0000
Message-Id: <20210130165225.54047-6-vincenzo.frascino@arm.com>
X-Mailer: git-send-email 2.30.0
In-Reply-To: <20210130165225.54047-1-vincenzo.frascino@arm.com>
References: <20210130165225.54047-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
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

From: Andrey Konovalov <andreyknvl@google.com>

Asynchronous KASAN mode doesn't guarantee that a tag fault will be
detected immediately and causes tests to fail. Forbid running them
in asynchronous mode.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 7285dcf9fcc1..f82d9630cae1 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -51,6 +51,10 @@ static int kasan_test_init(struct kunit *test)
 		kunit_err(test, "can't run KASAN tests with KASAN disabled");
 		return -1;
 	}
+	if (kasan_flag_async) {
+		kunit_err(test, "can't run KASAN tests in async mode");
+		return -1;
+	}
 
 	multishot = kasan_save_enable_multi_shot();
 	hw_set_tagging_report_once(false);
-- 
2.30.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210130165225.54047-6-vincenzo.frascino%40arm.com.
