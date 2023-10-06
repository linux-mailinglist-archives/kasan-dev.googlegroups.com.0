Return-Path: <kasan-dev+bncBAABBW6KQCUQMGQEQNMGGZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id A63727BBB9B
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Oct 2023 17:18:52 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-530d9bcd11esf8984a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Oct 2023 08:18:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696605532; cv=pass;
        d=google.com; s=arc-20160816;
        b=qiokPQoaBfEQMj3Z/6g/sXDqLsRmWCxnPon0btpxsQZoTtgxVCJVLYrTh527OEJNhk
         n9+B8hvqDdupO4vw9dRsq9fv9n2WtO8aL7TA5jQ7WHyqidg5UdxmZxHmQlAhzWTekvRK
         m0yy6x2ZDOBnXRWpLP4zOaEMPbhAXsH7o5xv0s67wO+PCeq0Of7igXT2h/EuweHqoAsm
         ldwkQYLQMxphKAq9CVzeTxNoAQAWH6a7+nUxLUHPESt+dPVe0ucPV0trTRyr4on9fQcp
         KzoR/V7nrovZZMqfsBgbj4V0c7sHHsFCDvZUklkbCsamuU8X5XbdJIpZfcGDxnDHvkEc
         bc2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=LHj/TuqwpgHUOTI0WV2mfPYOb8gNg80+9tii9Ikg/6s=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=ktBGu7msnBOYiDouCCDutQvrZqjSPMxt1EyIKLt9WaO0feIOB55HxQVjS08YaxCnIz
         6/Mb7Lp2wcx9v4cuwJc0wHELj55ChahjBk1OL2s6CtxAGMe7e9xbVbRpcIhmZKWnXniW
         jJxkeVECWcUxhAfY0ztKNlApQ5igTQD3SsuI3yhxqSLY2XQ3kEASsLBFKK3WRDbU5Pw5
         CFkQve10esAciVrxjzROPGMy/pG+RLnfZAXfFDeja11Qk7KcMmpLf0xjcBzFzRGRFOJ2
         MZa2a7UQyTxmLAUYiIgp4tiagkZKP9GyjlR+Hf7ZxyLc84Zrugq5F9mFmEzEw4Z4TzRY
         BLNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=neSUwvro;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696605532; x=1697210332; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LHj/TuqwpgHUOTI0WV2mfPYOb8gNg80+9tii9Ikg/6s=;
        b=KGPJZsbPgOpggB1Cw5cJqoKLaByEtQ/zEixHK1yNTwXF1DO9+AOM+kU12JMe46qVGF
         uxYR1Lqy55dnZ1JzfcUq7j/6koOrterqwy9g7Eld56/nmN0OcRsQoDaNCwkX9N4WrQp2
         EgjfPUeEqNYPZgwpBkkye0Jkyh70bdLeiiZNNrl0qHuCYF6U7yMAjeqpJgGOMEqgANsK
         yPLZbExlZig+LVG8uRaTQD23QPJK3AgcRACaQyzm/i/QtJeJVwyqfBpSK/WKRinI8T88
         Tqbta8G1oILs5wCOy+g5pieyUbYtRyDL4+IWNH2j3pXXJianTVCcBfq9lC4UMx6xUxjk
         JC7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696605532; x=1697210332;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LHj/TuqwpgHUOTI0WV2mfPYOb8gNg80+9tii9Ikg/6s=;
        b=Wa2AG6lGIx5/f1JijIDUCODtkqscZkeemYy76M4eIqEP/J94tBiSJ8VZ0gB0R0YkYf
         oCFIFolGVr2NFvyuZVt3Lv6rTcVj6cXRrrdGb9pcfo3021QzJYZGHCU72mFBE89cwp06
         jS3mH0a5Q/iJCgEwfBRjWEnG6+6t3YzIMZpUBGxfXyOMb1sePRYYag3gMJXDRmPo07/e
         GUXmwG4mhrREHJSQoSoQZk6UMA6Qz0BG/fjAXr4q1qUeGSCgy3uw9KMyE3Udpwn3/AI7
         qFH1QqwL3IJ82buIymGA8qhQEwPcMmq7Ja1sV+BEnak+zQBnX1h+OOwxChUvwROFC4SP
         NGww==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwQb/ObUO6GYSi0y7mcqOT/vajhwQYQJyeBvMJam53dRMz8mxu0
	dfGD0sHPXT0cwh3mu6KaydY=
X-Google-Smtp-Source: AGHT+IEZYlQWjhtd7gOpAFypzotKgfNaL2j9jKbU+0SOv3MH/HSDsXFlpDPYTlUMkJfcVKiI3Un49g==
X-Received: by 2002:a05:6402:d4b:b0:53a:ff83:6123 with SMTP id ec11-20020a0564020d4b00b0053aff836123mr78774edb.3.1696605531569;
        Fri, 06 Oct 2023 08:18:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fb0f:0:b0:537:f054:9a83 with SMTP id d15-20020a50fb0f000000b00537f0549a83ls412078edq.1.-pod-prod-07-eu;
 Fri, 06 Oct 2023 08:18:50 -0700 (PDT)
X-Received: by 2002:aa7:d94e:0:b0:530:bd6b:7a94 with SMTP id l14-20020aa7d94e000000b00530bd6b7a94mr8410464eds.24.1696605529980;
        Fri, 06 Oct 2023 08:18:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696605529; cv=none;
        d=google.com; s=arc-20160816;
        b=G7j3HgPAK0rq8QFG+XXfEk78p1/+xuUjCdudxbUgMF3F5/5+lPkSgWf/a23zQu3P7v
         PG1E0y9kKh7MJ/J3wydxZOYeusEda288E7up4BuGZZw1JxCimhY2YAl4+2w+qxKlHw4b
         lRAOV6EfbONEdLY6yvsOaO/ySlkBtYoU/8Xxe4Bh1Q0aXSEIH5wydlShyiuQsheVXR+q
         Pwj+fxiyjHvKj5/jLBjr1khyyVsV20dfPXkwPE6wsAYmce/MErk/CMdvfo/3hNrkTb+0
         ZzKRWfc5hvlqdqePaSYgCVv4KvRxgFskahgD6ZUqtx0v9aKXEveqqdrHamD9sD37f7yu
         j3aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=FLvCKBjoIRy4tmBKqXgjqjKrcGEcT90AXXA8acJ55o4=;
        fh=MvduW7TtfFJGfZiC/W6aaLQjI7EqApwiKAwimfBfFME=;
        b=vx+aYCfSwFab75ACz0SxfeR78j2IaywI4WSqzEbqwWnArx/dR2VHIa92p7IMtdXMBF
         h8BmdSZi0OTrnSL2sGGvoZmFqaOIQky3vB7AcaAXUzmBsKPYBYhjz97HVx0tTbydZWy6
         6ZagoReKj5iMgsw5CqyiXV3xUvm1dTYtW290l21NziWTVItsVnVaGWPdipY+vnrDm7fe
         tGC7O5TLWeJzPAbsh+olEv6BgpSNC9DWOUHSjWSjk/SCgjad2eQvIigxmUsFNQQgHEpg
         0+5kxQAqg1QptkrQk5vsvCrmt9BuaA1h5twR6s7Y0g7E9AFSAr+VL6bjuMBWBcwWC1L+
         l6VQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=neSUwvro;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-200.mta0.migadu.com (out-200.mta0.migadu.com. [2001:41d0:1004:224b::c8])
        by gmr-mx.google.com with ESMTPS id en22-20020a056402529600b00537e9d25c00si236018edb.4.2023.10.06.08.18.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 06 Oct 2023 08:18:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::c8 as permitted sender) client-ip=2001:41d0:1004:224b::c8;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH 0/5] kasan: assorted fixes and improvements
Date: Fri,  6 Oct 2023 17:18:41 +0200
Message-Id: <cover.1696605143.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=neSUwvro;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::c8 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Andrey Konovalov (5):
  arm64, kasan: update comment in kasan_init
  kasan: unify printk prefixes
  kasan: use unchecked __memset internally
  kasan: fix and update KUNIT_EXPECT_KASAN_FAIL comment
  Documentation: *san: drop "the" from article titles

 Documentation/dev-tools/kasan.rst |  7 +++++--
 Documentation/dev-tools/kcsan.rst |  4 ++--
 Documentation/dev-tools/kmsan.rst |  6 +++---
 arch/arm64/mm/kasan_init.c        |  6 +++++-
 mm/kasan/kasan_test.c             | 11 ++++++-----
 mm/kasan/kasan_test_module.c      |  2 +-
 mm/kasan/quarantine.c             |  4 +++-
 mm/kasan/report.c                 |  4 ++--
 mm/kasan/report_generic.c         |  6 +++---
 mm/kasan/shadow.c                 |  2 +-
 10 files changed, 31 insertions(+), 21 deletions(-)

-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/cover.1696605143.git.andreyknvl%40google.com.
