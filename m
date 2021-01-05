Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRW72L7QKGQEEKTWIQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id C061A2EB28A
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:22 +0100 (CET)
Received: by mail-lf1-x13a.google.com with SMTP id 202sf2052242lfk.5
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:22 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871302; cv=pass;
        d=google.com; s=arc-20160816;
        b=S091sLhx++/n0v37Zq5jjsGjAdnf0QB/C7zUfFii/mqY/I+DhLoLIJVDhPrOT6+fOd
         bua6dFc79HSGWzB9an2O1J23MWf6/9JfJjjqkcIFrHnzXEd0xe4B46hKFPJNhb4ognqW
         F9DbmxzlyqxMsY9KaP0jXRmL5K7QKqxcOeHZv+gcMi7ZB0aGvlSYw1cUp5YMls9K6OWa
         240+1Kz4WM+S+9WO+pF4eS7uw6dRXKrZjisU3UVDpfyX3MIzzWrE3uMFXCnhvOE82nKo
         MSPsQE4EDFjzav4XA1aG8cI/ns8OxCgtZUWlkPyz5XCjKcqMRdtt1sQIU6cyIS2w92Ms
         OFIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=xh2DkQQjX6uxBKnM49F+6JsuNRxhyZMz0J15fOgDamQ=;
        b=lVjyhW6aHEAm87xKLu0FOJokTQDQ0SPmVk1kZXnL+Q950IABn+ZP5pYra3gWYygnES
         7/UNmVf+xgVxcSxKfFUbsYj1ZQllXmZZDMNSkB2OpAp4QiSDMKvyHrkn4LOeE2OHfeL6
         G5vwKxMB4oF9hX5QIjwgj7I0u9nIoVe9n30pfMuPsQkFTzhc3RHDSWWEcBZw0b/4/Zb4
         vCSCqb14LrECrrLOwXXEYni9uKyqU6VVd1OOxUk91chFFAx1aU+U863aBZrPIgAX0yww
         LqFm1DLh7zTgNfy1Zjo17cOGu4To50sP3zEyrXfWASeiNrJ6T13VNqrtafADDaMhknk8
         1O4w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bRtGkcqX;
       spf=pass (google.com: domain of 3xk_0xwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xK_0XwoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xh2DkQQjX6uxBKnM49F+6JsuNRxhyZMz0J15fOgDamQ=;
        b=OqZgkONG7SB7E9WQ+Yw84vKKm6I1ZiTti9gRmVapcdtd9eGjEKpbcpGY9htdpekgT/
         PrDG/zPdudeVl13xvQi3tW3YzsieD72VT9tAmCxQzZ3uG9nxqfwDCFLWBSDvi3nJrTeJ
         /cQhQ/qHbPV41+3RTSjj56aRuUakDGSRjxiYGDYe4+rK55oWAAD+uICrqcceYu+nGop7
         PAh6vgh9IXostFLNFPgyZlDIpnQgGZFL1wvUz0cI6jUUWCLQW3YOU/csStYT59qcKfV1
         N08IjRT9Y+tsVPpK7VuuND68N6CfETFj1x3rgynN7Hdr9gEF1Ea7L9GatxNFZZ4Jyumi
         BpMA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xh2DkQQjX6uxBKnM49F+6JsuNRxhyZMz0J15fOgDamQ=;
        b=GjXLma7odEGpByOXal+tCmPN6bxBBeWGG5YIyBX3UShoE5A26WLCB42J6x1Kc/3zYb
         D1QLuNHvYJxB7RbsrOWL3BIlKIoHnC24qnDZwCkYrqFP7UEAcf3kke2GT0/9RWau+GEP
         CmUnENJFEApQuMK4pdBWxmd6OIFYifGYQLGexaYLl7FxhdHx/fh1WHnXi6kC98eUIp89
         PXVGZxl2QI8ODJerSybqCKz1+OmVbURlUe4B78p9QcwUL5Y1oO6VIrT2bM0xYAczJwNb
         yVsxx8RHoTgAy+Qs67+PbHHWSSA6IWphX8CUmlX/JljOuLdwFnnlW+klecfIOkH1QB9m
         uq+w==
X-Gm-Message-State: AOAM532LY0S9H8DWv+/8Fq1SL7Q7wlE8c2Ch351rRsklzGCCKGsUWwb6
	XKoIblImcATC2+MLIjgjzb4=
X-Google-Smtp-Source: ABdhPJyxnrMiWZH01h91EUXpInb4gd2xEEDvYAMMmSyxvYEUJGTZVpLaAPjCTipnIBpkqrzS3ps2EQ==
X-Received: by 2002:a19:5e5b:: with SMTP id z27mr264616lfi.143.1609871302372;
        Tue, 05 Jan 2021 10:28:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10d4:: with SMTP id k20ls149641lfg.3.gmail; Tue, 05
 Jan 2021 10:28:21 -0800 (PST)
X-Received: by 2002:a19:ca5a:: with SMTP id h26mr267359lfj.612.1609871301375;
        Tue, 05 Jan 2021 10:28:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871301; cv=none;
        d=google.com; s=arc-20160816;
        b=hvQ/Iz9RNB6hlk+Qzmgn9txU3+56vRNbCYMZfeV1aBdkapRAoPb/irgoHjgDthxb1t
         dl/Hr1rnj/YOUaz/PLzZgmVzh/l0Vz3axreEBgj0yArdWWgOfodK8L+5hMF+WNFFVYzc
         /jkaAhT7zWEINxdvxrzXtxyPzMHta+eqJy/iEh1KNPXin587C2k0T6YImrJ725s5Z3fC
         ShvAVIzxN/cYij7VdlJysYT2ZRqzWxCPNIL1M6BKr6uYwJtVCBAKLJm4IeP2q40GHw0n
         g+6+vYgNRUp+Esp0QVdcI1QHBqP8ToSzKl7q01B22iaTTvnQA682U18Nc7QcylhLBF9P
         Y+Hw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=L2nfB5IDe6UR5zw3FZON/Z4AbH3dOVMSon2hvUv5xm8=;
        b=TXf45Kwwtf4SvkAtM03/cUhiQh2C9QtAUyo7rjwom3blIurNGcm6zSMAGabVpbw6Z7
         5rXSWAaycRHwDhOF1qoV7s7t2OI/yfA/M1Dg/xIdD0WI5sk9a40H0HMWnrt41jgP1C8e
         rAW3458GNZeEIfiviWDncNsZZN1m0PM2PC1YbIlLjC6eENuXdmD+XFQSlcz8xyrXpbRZ
         3A28kvHEHkv/hMkebj+4QxtztM+juO/QKmmjVRNBZm8/2qRNB9bccVNLkNPLCa+aHkCg
         Z1+e9eBTd7H2KKRvYCHppAaN0tCsCK4EhsF2zU6fWHd0KbTvpA/lTOx3sBpZbNx9ac0l
         sxtQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bRtGkcqX;
       spf=pass (google.com: domain of 3xk_0xwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xK_0XwoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id i18si1859lfp.2.2021.01.05.10.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:21 -0800 (PST)
Received-SPF: pass (google.com: domain of 3xk_0xwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id k67so164417wmk.5
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:21 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:f18a:: with SMTP id
 h10mr893184wro.244.1609871300796; Tue, 05 Jan 2021 10:28:20 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:51 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <a37dab02f89ad93cc986a87866da74fb8be1850d.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 07/11] kasan: add compiler barriers to KUNIT_EXPECT_KASAN_FAIL
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bRtGkcqX;       spf=pass
 (google.com: domain of 3xk_0xwokcfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3xK_0XwoKCfsdqguh1nqyojrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

It might not be obvious to the compiler that the expression must be
executed between writing and reading to fail_data. In this case, the
compiler might reorder or optimize away some of the accesses, and
the tests will fail.

Add compiler barriers around the expression in KUNIT_EXPECT_KASAN_FAIL.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/I046079f48641a1d36fe627fc8827a9249102fd50
---
 lib/test_kasan.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index dd3d2f95c24e..b5077a47b95a 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -79,7 +79,9 @@ static void kasan_test_exit(struct kunit *test)
 				NULL,				\
 				&resource,			\
 				"kasan_data", &fail_data);	\
+	barrier();						\
 	expression;						\
+	barrier();						\
 	KUNIT_EXPECT_EQ(test,					\
 			fail_data.report_expected,		\
 			fail_data.report_found);		\
-- 
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a37dab02f89ad93cc986a87866da74fb8be1850d.1609871239.git.andreyknvl%40google.com.
