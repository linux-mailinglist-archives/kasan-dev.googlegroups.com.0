Return-Path: <kasan-dev+bncBDX4HWEMTEBRBZV2QKAAMGQEZUIB4DQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id C425E2F6B25
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:37:10 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id r5sf2263706wma.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:37:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653030; cv=pass;
        d=google.com; s=arc-20160816;
        b=H5JSGmCUInqnwUJCr6IRYHM9HsrUIac4InZv2BvJ+WacO/xPgCkentM3oXQqxkwoAL
         H5FGHetVotXM/nmTnTqYaoICiHmiHQ3cOALOqytxuWmOuy8WQAfXsP7rCj4wmXwFxAWO
         oTZmhw/tDPnOcA86wRN1hGDOkfX/jodTB2gGM8s1eJY1orHROs04Tf8LI81UOZyGtUCE
         qGp3DCgVIHmIwt0k+bvNUNXzDXFwblUSVTt052lv31f0Eo6cossqoW53u1JuB7UkPMBt
         xtRy41AuBFm48UVRsK0yxuSMGkv6bumR03EvrkDI+boUk1cCzT73rrOKm9qktbmKyLV5
         BKuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=RXHjT20DqsaLs56j4RAwXAvGVpJiI8RqSzF+xNS8Jos=;
        b=lB0UD9FwUGmUzx1xVmNbZt/5IAiEL7Gb5T1EHNRAP51jfRi/RTqDJd4wA7Em1QfeLq
         jcCmINJa6f+o+0SL/NE4NTqtTn0dW5fH5/U64TqnLEMJCQQfiiJl+0OdHC/M8VKIHuwH
         ilwl4/kZrhEQkPaYbMRuSxCMzzs4V7NDHcKrguDGRyVEkBjDGMGCMWWHqJKhPXToHvf4
         YWjJkWRIUocElOo61h3iQ8uG4ImeUj/XS1ftpGS960hUimutjcEesNp/VOWbUxdrnQ1g
         XHWQsA1DmyWuqMbfnIhqmF3E7fH9n/WZVzxAXgaVXiDQQuGzN643QLsTEkrzVqXrpJpN
         USBQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SxaVUGgJ;
       spf=pass (google.com: domain of 3zz0ayaokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ZZ0AYAoKCagIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RXHjT20DqsaLs56j4RAwXAvGVpJiI8RqSzF+xNS8Jos=;
        b=cCIJ/tMPJDcwPdlFosF75QXISFMHEU9/EbMS+ROJcZwVZgZUhmqwudNj5+nO9oYHZl
         PCDM4HipFMDAnG5+UYzs/o/nDt1Z8gzvpoUhQIDABjNSq4nm4A/cva1f6b6YrnQ9bBln
         M8ZxFqH79tn4MpME4pnt7fZH0MuMYaMDQMn34NVA80RM4JARegBl/zPiKvxYRl7cq7eM
         VECwZBo1Shu5AxIUQfxCZ9bkSdwClePEUgOoJ9nMBt9kF9xlrEQOe8TPPcmzI1Nl5g2I
         qub++SyPNAgQyG3tCRpN0cfkpC5USvcxiqYO+1ZUF+bSZqSRYEyZie6dL13nHoGhtLNI
         zrDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RXHjT20DqsaLs56j4RAwXAvGVpJiI8RqSzF+xNS8Jos=;
        b=o7E/bKNV+nZ9puRvRiP/FopjUvWvtclExYsPdlt+y8SP4+2nEGD/WEI4gvAEjU3Cj/
         jBrmWgVRfogjmMfaJK9Xlv7uzkHpuy/4+xeiXaxSdWEEAykB+IE/esfNHyaH/qX/zTG6
         3qDWw7HdJUUBQz/fYY2M9zKxtKmm0FiB1+/0qBUO+lKIgg15zVPpJXqhmcxuEJU9z6hA
         mATk5aMxi9/t6zfZK39Xhn8J5E0nZEeZC4ipSs1reIxjWVF/eykwu6PHhLtKzUe+QPd1
         hPzAr7upHbkLz0cxrSxi61OWQ8we8554YpVHlFEwAfmEUS2P/glqXzFw8gWYHcxw3eEC
         cEmA==
X-Gm-Message-State: AOAM532Q87MjqHQ/iEruvWZUV5QHyRTMxY3Utq6vsHJ7Ou/JoLZ+FVC5
	NMxTzxLx/5ZVFzdR8hMNn5U=
X-Google-Smtp-Source: ABdhPJxETuzpwe/BWOcR/vtYv266vYRHW/d8ZYZjSdrJ5MlT5vWAFuOIcfend+djeEbYN4ItNX8gEw==
X-Received: by 2002:a05:600c:22c9:: with SMTP id 9mr4201014wmg.45.1610653030593;
        Thu, 14 Jan 2021 11:37:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:66c5:: with SMTP id k5ls6482829wrw.3.gmail; Thu, 14 Jan
 2021 11:37:09 -0800 (PST)
X-Received: by 2002:a5d:688d:: with SMTP id h13mr9868694wru.28.1610653029771;
        Thu, 14 Jan 2021 11:37:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653029; cv=none;
        d=google.com; s=arc-20160816;
        b=ExqSvZPrsh7ykqDF00ykV1Hk/DiVTB+MAQUdJYHgdmUGSpQH1Y4+98ZW3YQPlCrdTq
         EWxmRQSiDgRZbMwRB7E9drwOMle2uNmsPeyFBFQ3EgEFpOG76sXX8qLGDUphhYe3i1IS
         dRBLXleE4MOrek3Yd0y6WBnHnDEeAM7mHnDaP/HgiRkdrkOnFKU3LKRsVE4VFYnRTy+5
         sVzkGzclTAI3nQSmzV6/wdBPNuvQNwXbXYcZnsxMz9KTcEsAqlAtxjd/Yq7F3Xgz/ypE
         9hF/lzDz2JVKYzUDOyrcqTGnCY93cHIQg0jpAF8qCbubOlk2nbP6BxcCje3YoV0GWOob
         vhCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=zyyZOaAWvcuFygSPGgq4+eSGOnhBneBdiwht0viZDwY=;
        b=cEiwAMnT+v0F+6Ct9fMEpuisQmIInngIdBy+RlG53YkuteND+H+EYqRbo+StIvhv0P
         nR7dV1RttkApT02G7o6fyX5E9QpGd4/N2l9eko55bLRTFUp+50knLo6zaGrqqgt3aON0
         E6ZjdnUojxCjsoXE6JnpkEWWGiuKPH+c0+O2QxSM2lKu5k54zOPzMM7FYlcjhkcabYyd
         sa5rfg95HZ16BGjuHDt/IrOi7zweLDBg8a/3jmofjInusvuLg0pGf6MdL62qdaYksrTi
         St4t/AFoxc4FQPHgLvR/pA5cYp/1Ujtdr7gIbks18jk/tw7LmaZgjOksihgbPKbUJQ2D
         WQ5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SxaVUGgJ;
       spf=pass (google.com: domain of 3zz0ayaokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ZZ0AYAoKCagIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x549.google.com (mail-ed1-x549.google.com. [2a00:1450:4864:20::549])
        by gmr-mx.google.com with ESMTPS id b1si355222wrv.5.2021.01.14.11.37.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:37:09 -0800 (PST)
Received-SPF: pass (google.com: domain of 3zz0ayaokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::549 as permitted sender) client-ip=2a00:1450:4864:20::549;
Received: by mail-ed1-x549.google.com with SMTP id g6so2801035edw.13
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:37:09 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6402:379:: with SMTP id
 s25mr7276006edw.367.1610653029351; Thu, 14 Jan 2021 11:37:09 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:31 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <da60f1848b42dd04a4977e156715c8d0382a1ecd.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 15/15] kasan: don't run tests when KASAN is not enabled
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SxaVUGgJ;       spf=pass
 (google.com: domain of 3zz0ayaokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::549 as permitted sender) smtp.mailfrom=3ZZ0AYAoKCagIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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

Don't run KASAN tests when it's disabled with kasan.mode=off to avoid
corrupting kernel memory.

Link: https://linux-review.googlesource.com/id/I6447af436a69a94bfc35477f6bf4e2122948355e
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 lib/test_kasan.c | 5 +++++
 1 file changed, 5 insertions(+)

diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index a96376aa7293..6238b56127f8 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -47,6 +47,11 @@ static bool multishot;
  */
 static int kasan_test_init(struct kunit *test)
 {
+	if (!kasan_enabled()) {
+		kunit_err(test, "can't run KASAN tests with KASAN disabled");
+		return -1;
+	}
+
 	multishot = kasan_save_enable_multi_shot();
 	hw_set_tagging_report_once(false);
 	return 0;
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/da60f1848b42dd04a4977e156715c8d0382a1ecd.1610652890.git.andreyknvl%40google.com.
