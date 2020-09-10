Return-Path: <kasan-dev+bncBC6OLHHDVUOBBV47475AKGQE2GLDNUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3a.google.com (mail-io1-xd3a.google.com [IPv6:2607:f8b0:4864:20::d3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 2CB77263DEA
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 09:03:53 +0200 (CEST)
Received: by mail-io1-xd3a.google.com with SMTP id a15sf3684266ioc.14
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 00:03:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599721432; cv=pass;
        d=google.com; s=arc-20160816;
        b=xMLc3csJLUJZRP+45rGyTkoYWvZPKVQMieTr3Y6Dhx5nA6bxfTXAn84/AUTLkhulvD
         ouYLGBmVOO1eG0F32nSW9kLQwvHaBjS2rU2f/eQ1WaeUwccXuOwy/Y9y5f9hz7vukBD6
         xQ7YcUWXBcisJEeA/6ZwA0tD3ZzjaBdyiyGQUUc0AG6K87xc43HjQJVkFXsddCTixL00
         Q3Qr54UCcjhkvrHmcYJyfjo7ESqO6spPxOnqXs2TumX9ZVbJf733k68aNDJCcAyhuDAw
         7UVkn1L1nEhwyRk5cAvJJK4o0ndQsO2ZzydM7whO6Rydg1OPd+lCFrQfPmmbMBrsJVmb
         SSkA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=pWA9zPCGs6OQ1yrEzu7F/nfiCKC9zJhjo1R8H3Nf1Vc=;
        b=YxB++Yj8EAoORpB8KAyuDjsbusgB2pIk+65tL920Dhh8JpYaeI8qeABbxK/8fJtXjr
         3ZkZlvduxxPpV5AYbQBIil6GzqvQN36+U/CCtNZRCGP0CDFsoSKSVM79CqXFFRWxm+Jx
         YvzsfqGv47Eq3KflvMCJDJ+McZyOVqCgh83bIB2TZCsalRqGUFr7jBEmZinhyUmg8hDd
         aB2hKtGdPiiNaJGas/3NYgg4thDyqwfRfe3e8GB18hrc79G5v71YRC5mgQU5JhLvhzJf
         A5l8iF2fsNT6VLYKg7oLxtnrMnXct6ZdmDMc7uwPC8HsX8EWQZapjLq8mm3FoJgR2NNd
         sSEA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SWzaAF3z;
       spf=pass (google.com: domain of 31s9zxwgkcd0c9uhcfnvfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=31s9ZXwgKCd0C9UHCFNVFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=pWA9zPCGs6OQ1yrEzu7F/nfiCKC9zJhjo1R8H3Nf1Vc=;
        b=krBxdi/I6mvQaCK3M7ismrsFN+SlhIeC8XeTeMiux4Kw1ipSGkUFtPcnQtAshw+08q
         pfk3J/AgmXCjthrjHszPSeAJoMHKN2qxJQ70vWVbglMqPAede10rXv6yyJljPcNFKT5W
         9cD+JLw4pMaDew10bs4CM7aEKDkmgTaZZMkUz+GS28qqmS0OHjpAMotNXI1xxQ+vb5XS
         VNWh6Ux/Hg3fHstp/i88JRYSLns04YgUH0+L1T7aUNtZfmjN0OhMdJWfl7H7fAOWOSPE
         y7uvosyvnmr6Sp+nL+m3Ul9x9IIbMDoP3L+7Wtz3MlbR0gJPIFodAZamponlc99ueDos
         n/8g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=pWA9zPCGs6OQ1yrEzu7F/nfiCKC9zJhjo1R8H3Nf1Vc=;
        b=U2+lE4BPcPEFkNY/SYQT6GkrcFYwo2pa+VvuOPnh4SZFZMHPzAJa1BR8LRSozLFNC5
         I7KwzQciAVIu4B1DsyF+SMGmXlOVnCV0JH+wIzjBPx3XTmJNXFI+yHW66XK/r/aVcTaO
         Gjjp+pmKG9gZz37AMlz3fmuqmyHyN85IwIL0qKLirq1+HB+KbsU/yYeKHVyAJsxYDVE7
         tTAU2kmVvOVeEkPovI7m8fKOax0hUKwNX3CEFkRCGTW1SGHuvn9TBnw4tFv3um3uwrxo
         8PzmSiDPZ63UyxX7quQZF1qO/ZBTjOtP/lgs6T9uWG8yiCecvcF0wbnYtiWK7h68aNFf
         h5YQ==
X-Gm-Message-State: AOAM5331cpVB49FklEKBmua1UiJVHRd+7XlwoDrypCIv65809UfZD5IX
	iDX5/RG2BAJ5QUQpXGVk+9c=
X-Google-Smtp-Source: ABdhPJxj7sdoDkhxhWDuoLbtazQ6AzWdDOe0oclu2aTaca2lB7Nz0mkSCIL7hbjGrZwtC0ED2vqEmg==
X-Received: by 2002:a92:d48e:: with SMTP id p14mr7192546ilg.259.1599721431748;
        Thu, 10 Sep 2020 00:03:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d68e:: with SMTP id p14ls1371075iln.11.gmail; Thu, 10
 Sep 2020 00:03:51 -0700 (PDT)
X-Received: by 2002:a92:c851:: with SMTP id b17mr7072711ilq.26.1599721431321;
        Thu, 10 Sep 2020 00:03:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599721431; cv=none;
        d=google.com; s=arc-20160816;
        b=rOhd36Rqhunh7WliBSxiDQsa/5WTftNBeH0UDaKe+aDPKs+kC4ZFfI99gXbEEIZvUJ
         N7DW423SajTqdngYK+zTIRcx7Q7j88LyoambpNXT3eV3ioS7zMRW+hONRinNsjc9KRyx
         dVyZ158uKwCTWnK0T0jMN/miuh2MteiipRMkebLhyNSkn92V50hWOuS/o9OFZmJCVo5E
         wb4ouYbg27xTYhSdH/JUlVTHzqS6ifHUC5XfF3IUb44cJjFABHCOe85q4SpxRpYjB0NQ
         A7IaxK/KEvuP5k1HKuoi3VppsBzkOBQqc/3gi4Od9dk3sz4LuWd9zlG0C80buemAhTNJ
         chnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yVT9yLW7JYWhoMqFcNSvIQqOD/OC9Y5kGyMXj6mDfzA=;
        b=xhg4Kt7zM+X2aDmgzwRdveCJ7ccUx1waTNuHCcWkFsbivaLfVvWtsz4xH/6ZhzbYzK
         TKlBqAeSF9hRAYTavBB8k790eKMDW8Fyzxd/golN6EG4k9FCUndB61Z4R2EhdD6pq0pi
         s1sGO8BPAVljzB50CqSajGUlrjUp7gnRREOGkO8j2DgKpvb6pdtvMMoXVQJFyh7cONuF
         Xsmh0qk24FTPPijvdVJb6n2M9UgE94lEYjkp/9pTpwazKW4KmhWp51C97MFPPRakWkN6
         W+noDaLQSWszq5UlXTh5Kepj03x2TuELj5gHi1hI2zjZifjJy4p9gKknk955XqY/rrl1
         i3Dg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SWzaAF3z;
       spf=pass (google.com: domain of 31s9zxwgkcd0c9uhcfnvfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=31s9ZXwgKCd0C9UHCFNVFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id f80si505360ilf.3.2020.09.10.00.03.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 00:03:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 31s9zxwgkcd0c9uhcfnvfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id s3so4577007ybi.18
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 00:03:51 -0700 (PDT)
Sender: "davidgow via sendgmr" <davidgow@spirogrip.svl.corp.google.com>
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:42a8:f0ff:fe4d:3548])
 (user=davidgow job=sendgmr) by 2002:a25:ef03:: with SMTP id
 g3mr9920500ybd.364.1599721430919; Thu, 10 Sep 2020 00:03:50 -0700 (PDT)
Date: Thu, 10 Sep 2020 00:03:30 -0700
In-Reply-To: <20200910070331.3358048-1-davidgow@google.com>
Message-Id: <20200910070331.3358048-6-davidgow@google.com>
Mime-Version: 1.0
References: <20200910070331.3358048-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH v13 5/5] mm: kasan: Do not panic if both panic_on_warn and
 kasan_multishot set
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SWzaAF3z;       spf=pass
 (google.com: domain of 31s9zxwgkcd0c9uhcfnvfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=31s9ZXwgKCd0C9UHCFNVFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

KASAN errors will currently trigger a panic when panic_on_warn is set.
This renders kasan_multishot useless, as further KASAN errors won't be
reported if the kernel has already paniced. By making kasan_multishot
disable this behaviour for KASAN errors, we can still have the benefits
of panic_on_warn for non-KASAN warnings, yet be able to use
kasan_multishot.

This is particularly important when running KASAN tests, which need to
trigger multiple KASAN errors: previously these would panic the system
if panic_on_warn was set, now they can run (and will panic the system
should non-KASAN warnings show up).

Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Brendan Higgins <brendanhiggins@google.com>
Tested-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/report.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index e2c14b10bc81..00a53f1355ae 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -95,7 +95,7 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn) {
+	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags)) {
 		/*
 		 * This thread may hit another WARN() in the panic path.
 		 * Resetting this prevents additional WARN() from panicking the
-- 
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200910070331.3358048-6-davidgow%40google.com.
