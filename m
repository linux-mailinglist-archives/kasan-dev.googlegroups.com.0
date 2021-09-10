Return-Path: <kasan-dev+bncBC5JXFXXVEGRBR6J5KEQMGQESOOBZQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 361294060D2
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Sep 2021 02:20:24 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id a62-20020a254d410000b0290592f360b0ccsf110924ybb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Sep 2021 17:20:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631233223; cv=pass;
        d=google.com; s=arc-20160816;
        b=vueT8LTSCTl9EkaPPwhuuzNd8fXUduoXA0HNmQV7flFF+qa+FyWKl57uY2XF/Nqszw
         FTPWSp6DlzuIHg/+xt2/kNEPPDGBh7XS1nSArtzb5JsQmRYFn7IaK0+3xmDOwjY1oxVN
         IabvxpEgptmh960Ma8emAHMLscB65DYN12Lme6/gqEDMcc8sb3krIjLoj2LnTU+XlDtb
         vI76eRUFd7iTBpvKmjd1KLzfWst/S75BJizNvrif9UGRdgXMvlvzsDrlcQrWyx8O4wl0
         mJzaPMWXtXPNpru9sYqf+ntq3y9duPluL84fvcJc7EnjCdqm6KUJoR9PAtmmzfgQ3JaV
         zCvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=vRLD/VlBabTRSoRgCUAAaWquksqRgxEc51/p+YHcUfc=;
        b=dHNkk8QxHYu2mXoASFtsHoJwmHGC/e2EhAsAYxyiIWxIJ6sW1DnuQ8X/rJbAexfx6g
         7pKHT8v/nShJnNUE2BDPSdjB6lbcNCNKy8gK07kf59J/qbCT/Ukq71KORLxnPqU5XZ5B
         XzigdcGZSpPFGnWCieAO2kql/ePKFPlCMSndIuGf0YBiy/lRTyGoqKuO3VngUF4RAGG1
         Fq9vJn9fYZ7QwJwUCxEo6N2nOIKLyEdynmzHXgkBxxt59tjYhBGkQSnXESOr1ZkZpwKQ
         fa8DFdqPkkNs53MP5ju+AYMhXnxdAyc1mLS0U9W06C1joEhAR7KI6gtav/3jmPU0fab2
         LNuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sgRq1KEd;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vRLD/VlBabTRSoRgCUAAaWquksqRgxEc51/p+YHcUfc=;
        b=LWT41K9ZJzGx+fMokANDdtO5z+9FbnBeZDjOKwJU6RAs3LpRBtHFjJlDJwuPf0ejjO
         WOjRB6oJMsWktd/Lb31naBH3t/CChr8smPj1CLL42A3yJdxphAQBtyCTBFg0z/DFCRy2
         G0jzRhTgyeCIB2pKJqhQv+V3FoTQOsCQJllHyGxYmzrczhQ6I02S6SNygVLzTUFmzFMm
         8XDUBPD8WmEGN+oD9nTXojZmtb74uG+EdF4+G1/eR6RUwqf35hAZMq9sPavxTqp91T49
         LTTWBj0Uq1kPpfUq2qMhoxLYJmySAuYjcV/EXemOEJX4yvj567Ejgb0KEhCRZvQOKPkn
         22UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=vRLD/VlBabTRSoRgCUAAaWquksqRgxEc51/p+YHcUfc=;
        b=8EnxAUVNVhv83XAFvQQKnvYghIESnLlpzaCL1JocZIhyMNipL56FoV1xvFFLsNpurD
         /7vrx6ZAw1SmPCgorcdU5VL2bNxv1uV4OjWDZw/kZmzEFS7HqmKvSTL0KOfTqOGGHP/c
         6chz4OeC4IP8f7DTkLAiXaFYq0aFXQRNTSFA2MO9i2hXmy8JYtyqgsDJ2az9qD8sG0We
         0IRk0ZDYhSxieHMj/x7OCyMbgfM7nXBBYabNb7+3g/VlS6OZHFIK+gcPXMZt6cuWhOkX
         zxrjwuxoquY+2lqf6EoNQOOXw8gt5y6u9QKoVuJBbRItkdZvqH1RUn/Y1h0KTlBO8bnG
         b6DQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53209cM81e9UKLyO3BQRX/8K+qIQHx/Qrag49fnh6y0GIEIXXaR6
	VaIaG+B5bmDnk4OJvxBjHW0=
X-Google-Smtp-Source: ABdhPJx7gphkMZwCTJtrGjVM8XWvFcC0Zpsg/JCSjZqky8OO35u/oJGSMRVYJGGAO9SdVTXbDncxYw==
X-Received: by 2002:a25:3604:: with SMTP id d4mr6868966yba.4.1631233223134;
        Thu, 09 Sep 2021 17:20:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:ac8b:: with SMTP id x11ls1914958ybi.1.gmail; Thu, 09 Sep
 2021 17:20:22 -0700 (PDT)
X-Received: by 2002:a25:3f03:: with SMTP id m3mr7845015yba.547.1631233222629;
        Thu, 09 Sep 2021 17:20:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631233222; cv=none;
        d=google.com; s=arc-20160816;
        b=W2D139nGqSMTHg1FOrfBLqoLNR6q34QMEh4uc8ZsGKnhVbqivutNcH9WDpfRnJxADi
         6lgL2g8Tho6jehP6i74NNE2V3xnooy26J+G8FVOEtF8oZePTzDmZP7ewyBrtQJ5gvuZj
         E4D3w5jo82AVa+4W5Cv0CjHyVNNP1SXsKQ8THLQUa6L7iz4xAa4FJD+R90XY6OKcIu7j
         voezKb7L+S7oqyIuRTV+s9Gotr6+cfsQ71K5dmEEvaF41KXs8F8cRA96MukADzmGG/ns
         G1rCx3BsiWL5QzE5BYPcj7DbI8abkyMErRL8rA/2jtNpLe6LAzUTOVxHdZtCo6ycUhJG
         SVKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=b527gvfes419LR4ulS+UzTrRxw3yDw2xIXMKG9ycwuc=;
        b=iudeHnKv58KSSNIYoq8YnYYiMWGFPNeSYXE8nRr48Nj9OjGXQpFnL10gadiFRYNjOP
         Ypxe+Zb3hCia0rIo3qs1fKklNQ4ol2V9frQrK0OJK0ufmaW9CoyltPjFCsaMq55Spcc0
         SlLt3Hq4OEcIaamD2F4lQTVLNID0YsG+fHeVFBPWWSxxquK8W+wNkhIsv7g0NwgoMIqz
         YwqH9a+fzch3kHdhYCdYA9VcnIB/1MmiDB7z8VREiwBMYo6D9gNQFgHw8ssu/EUOkRID
         kd5GSJ0YymaRJoIPkJajujmzrCs4gtkOjtOCDbKFDxPVLAaTqvtHOjtVcexdvgVtFSEv
         zfRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=sgRq1KEd;
       spf=pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id k1si313506ybp.1.2021.09.09.17.20.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Sep 2021 17:20:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 954A6610E9;
	Fri, 10 Sep 2021 00:20:20 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: linux-kernel@vger.kernel.org,
	stable@vger.kernel.org
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	Sasha Levin <sashal@kernel.org>,
	kasan-dev@googlegroups.com
Subject: [PATCH AUTOSEL 5.13 85/88] kasan: test: only do kmalloc_uaf_memset for generic mode
Date: Thu,  9 Sep 2021 20:18:17 -0400
Message-Id: <20210910001820.174272-85-sashal@kernel.org>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <20210910001820.174272-1-sashal@kernel.org>
References: <20210910001820.174272-1-sashal@kernel.org>
MIME-Version: 1.0
X-stable: review
X-Patchwork-Hint: Ignore
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=sgRq1KEd;       spf=pass
 (google.com: domain of sashal@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE
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

From: Andrey Konovalov <andreyknvl@gmail.com>

[ Upstream commit 25b12a58e848459ae2dbf2e7d318ef168bd1c5e2 ]

kmalloc_uaf_memset() writes to freed memory, which is only safe with the
GENERIC mode (as it uses quarantine).  For other modes, this test corrupts
kernel memory, which might result in a crash.

Only enable kmalloc_uaf_memset() for the GENERIC mode.

Link: https://lkml.kernel.org/r/2e1c87b607b1292556cde3cab2764f108542b60c.1628779805.git.andreyknvl@gmail.com
Signed-off-by: Andrey Konovalov <andreyknvl@gmail.com>
Reviewed-by: Marco Elver <elver@google.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
Signed-off-by: Sasha Levin <sashal@kernel.org>
---
 lib/test_kasan.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 00b7061edf59..c8ca85fd5e16 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -523,6 +523,12 @@ static void kmalloc_uaf_memset(struct kunit *test)
 	char *ptr;
 	size_t size = 33;
 
+	/*
+	 * Only generic KASAN uses quarantine, which is required to avoid a
+	 * kernel memory corruption this test causes.
+	 */
+	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
+
 	ptr = kmalloc(size, GFP_KERNEL);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr);
 
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210910001820.174272-85-sashal%40kernel.org.
