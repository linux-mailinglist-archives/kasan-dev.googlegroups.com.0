Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV4RRHUAKGQEUK2CEKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F1E743622
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 15:00:08 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id y7sf14436394pfy.9
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Jun 2019 06:00:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1560430807; cv=pass;
        d=google.com; s=arc-20160816;
        b=seBeNGHAqjkgS7w1jte4GsNGNZswbh2ha4iKLXosnSWgPYCGFjYguEJ7JDfKvYa9aj
         SmylZGfuYMRtuPmijrfhZAAuQGkoYSNcebhEs21SB2AUQTq24Az3Qwnr0sF7IJZAmuEB
         /NJg5DC6S3lblrw6qr1D5cljtyPAc/YucNQTIygpS6GPN8J0R8gWlUbpFwvu+5ECgp41
         m3L8R3GLKYOceO6QGcNPvSDDu40Y0l9kykhJxfHYt5PLrp2BBaHDLgyQNFgQUQGjfbKS
         GQ02gLyJC8GFIRY1NOK1ADTuzSTb6FELu5+yB6R38VllBosH1cfCLVyc1B7qlY+/zfEg
         eM5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=TNp+BNoS6er2Nx0CoTzdEUJjCNUxpLhAEeJwd8sxJT0=;
        b=ZmPHqFmTvDL/3wsIIJ5PXY84JtPN1T6BTb+32H5baAVBGz5ens+8/d3TttuC5TtQSE
         FayxrRZnH2IOlPuVk4/sJByF/+LeUPYAq/bePfaBWyS1cVqg1+P8g0A2UtwPCs/2fSON
         jUy/OkSbeMO0z5KOYbAV1w17N0pTOHetnRKtNm1kybeaBxEMngCqUZw/eoY89se/T/hc
         PLmhNhE50a+pFPKA+Lg8aQG9z8IPPX3a1puj10PWXYwEl0vdKc/5Cv3P9/5QlozqYlsX
         KjFFZjB2CDe+c8PRufsjcx9ojDTvSAneHX7z1K2CB/Brp16clRWQVVKDDgQHHbM16n0s
         CfRw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WxypDLVb;
       spf=pass (google.com: domain of 31ugcxqukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=31UgCXQUKCV4AHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=TNp+BNoS6er2Nx0CoTzdEUJjCNUxpLhAEeJwd8sxJT0=;
        b=pdwsfiJHDaNEsZWhZD8fYXx5v5KCjWacVpq8K8g7O0barjMwJION55IwBVBZBkg+G0
         zjylCkmRZEYxuFPlxwOdbc4PT6Oqkw0ojMjDFTNa4KQ5thbp6NeE6WHbtwgASF5muEp6
         3YIhhw7ynG/pvYoDdQZ1JGyq/aELgVGBPbvv135iaVbc62KWgROqZmPpc0D1UXSpTVf8
         wQGzsZlQoRXI2XB9LPSofmMOQ9XxQXdC6Uc/s4n1U7x1aXZQgZfXUCuQkMrkWvu1ysoq
         1wkdDByKEXpEJwMhAsFzjruORBvvH/RvqoHWtFxHdWcVXa84cGeJSHxSGNNai7tEFRTg
         aDXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=TNp+BNoS6er2Nx0CoTzdEUJjCNUxpLhAEeJwd8sxJT0=;
        b=DNwODTNftvfdZ488Avy8szuET+ku1En2Vdb9Cm4BXn+xBt/F6vm4swuD+iGRSjcwhC
         n3zsC3kEUUBLFgJnOMYNILM8gX3cspo9XD82pjhgkHkfCfJgt+r0kM791mgjGQtLLqv0
         H0kXBLrojsSr2jtA2FlrBKsWKqVvNLwo7XiWwxNkQDDVGQ97BQ6gBRThyv4BtFJzWFuI
         BI5W34yzsRYjwY8ASScsbYS4AF91qvwTnIRLL8fulENa9drwPI5nA5D2UnyP2T1LFCwm
         uFN/IYc16ZG0DJeQXeQVVGcSYuhdeFFOBUYfNyi1VqF018Wif7NN9vIdo7vcoB2YtceU
         V4xA==
X-Gm-Message-State: APjAAAXMcAww8idrH6xaydk9ddojbaabpqWa7FLqcPJYaXOLj+OHy3H2
	R9XA3LJki/9PTpsK0axwOoI=
X-Google-Smtp-Source: APXvYqxaPo5PNc9RRiRWrzQjRjDKlfbqQhz40QT00xyuz74GgcyunMwESWpleLaZi3DwXsMguzhYvQ==
X-Received: by 2002:a17:90a:7184:: with SMTP id i4mr5534503pjk.49.1560430807114;
        Thu, 13 Jun 2019 06:00:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8c8d:: with SMTP id t13ls1415377plo.13.gmail; Thu,
 13 Jun 2019 06:00:06 -0700 (PDT)
X-Received: by 2002:a17:90a:b104:: with SMTP id z4mr5493565pjq.102.1560430806749;
        Thu, 13 Jun 2019 06:00:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1560430806; cv=none;
        d=google.com; s=arc-20160816;
        b=xBjcQtSzxK6Hi4qRybbdEIjufDMnr4HtbH3g/6HbGm1ZEndT3RiRFcfgGkruLshJuw
         D97GVYR7LUWN2pwS+3hNkmyZ/5fHqoU6gncgj7b42+/YJqaolYvhc/oRAX0zRCKDNUzS
         fO+Mb1zbIPyglt521q+8uJt1mx/3h0wSEepZQ/8Kra6xcJy+mQTYHdOeVWd1SMWOYi4x
         7Lbpcpwdj32fQU5VwyDl0OunSu03wsK90D8n4S2q8dg77ucS13tb2JucK6cD1xH7Mpcx
         Yh0RSRbKlzSQ5NIIl1Dv0QSsQMthMLxXATST2AyzekoUeauIgaZ6J6YYLJXBVXp4aU5T
         172Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=50HPP5ae9Rk5gHtTtValAbuIThOVqS9Fd5PO1+T5JvA=;
        b=N5eobViIYkf/Cs/A2++BMXT9Yg8IwLYhaZnlwd3PGnom5kWihAFzv9b9Z2NRDKF5QY
         PThrE2vH6Mt0BNGN56WBVclJMytkZgA7mABRcCZ1oWwKCnsQnNKJEoI2SnWrtpDyPxJb
         M8eXtnxgo5wQvcZ2ZqLqY5v8BWfHHRg3pK0kABLTubJWT10XHpvZcA9dX2uC5d0xIJrm
         gt2vRrDU+/wXoeYzLGb3o8yu+zcbwt8qDouMFX2TkEOYjEhV8vSW9IkjKZUmeYJ5wHuH
         Ryo2rFskqcjRo2wSrPRtfxTsMprch2fdG17vJyjQJ9ZWw67x9JPrQRsQ4xYmGpALV5pu
         +w4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WxypDLVb;
       spf=pass (google.com: domain of 31ugcxqukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=31UgCXQUKCV4AHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id 137si76311pfa.2.2019.06.13.06.00.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Thu, 13 Jun 2019 06:00:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31ugcxqukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id g56so17419024qte.4
        for <kasan-dev@googlegroups.com>; Thu, 13 Jun 2019 06:00:06 -0700 (PDT)
X-Received: by 2002:a05:620a:624:: with SMTP id 4mr71498850qkv.15.1560430805871;
 Thu, 13 Jun 2019 06:00:05 -0700 (PDT)
Date: Thu, 13 Jun 2019 14:59:47 +0200
Message-Id: <20190613125950.197667-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.22.0.rc2.383.gf4fbbf30c2-goog
Subject: [PATCH v5 0/3] Bitops instrumentation for KASAN
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: peterz@infradead.org, aryabinin@virtuozzo.com, dvyukov@google.com, 
	glider@google.com, andreyknvl@google.com, mark.rutland@arm.com, hpa@zytor.com
Cc: corbet@lwn.net, tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, 
	x86@kernel.org, arnd@arndb.de, jpoimboe@redhat.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arch@vger.kernel.org, 
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=WxypDLVb;       spf=pass
 (google.com: domain of 31ugcxqukcv4ahranckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--elver.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=31UgCXQUKCV4AHRANCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--elver.bounces.google.com;
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

Previous version:
http://lkml.kernel.org/r/20190613123028.179447-1-elver@google.com

* Only changed lib/test_kasan in this version.

Marco Elver (3):
  lib/test_kasan: Add bitops tests
  x86: Use static_cpu_has in uaccess region to avoid instrumentation
  asm-generic, x86: Add bitops instrumentation for KASAN

 Documentation/core-api/kernel-api.rst     |   2 +-
 arch/x86/ia32/ia32_signal.c               |   2 +-
 arch/x86/include/asm/bitops.h             | 189 ++++------------
 arch/x86/kernel/signal.c                  |   2 +-
 include/asm-generic/bitops-instrumented.h | 263 ++++++++++++++++++++++
 lib/test_kasan.c                          |  81 ++++++-
 6 files changed, 382 insertions(+), 157 deletions(-)
 create mode 100644 include/asm-generic/bitops-instrumented.h

-- 
2.22.0.rc2.383.gf4fbbf30c2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190613125950.197667-1-elver%40google.com.
For more options, visit https://groups.google.com/d/optout.
