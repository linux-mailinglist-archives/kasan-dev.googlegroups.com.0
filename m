Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUOFWT5QKGQEWHO2TOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id F3455277BBE
	for <lists+kasan-dev@lfdr.de>; Fri, 25 Sep 2020 00:50:57 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id m125sf317541wmm.7
        for <lists+kasan-dev@lfdr.de>; Thu, 24 Sep 2020 15:50:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600987857; cv=pass;
        d=google.com; s=arc-20160816;
        b=u8E1Cs9WGb5prBPONdXEz+Q0FFYD4cMiq44G5BJFDxcgNH7yAp3i/6bbRgOwsAchDT
         o+ym1JNbWbFU1EfxT4HmoOYj83hs1nqUKYGyH5FCQze6qXE45MiPMWqQBA9Jtlx2TBmA
         lQDV4FnTTSkCGvq6aImbTf+1okgZE8LgO7nFIDy4HNZVId+Mt0cAuNs0wwRBUiZ+RPiL
         zms5DMM3l/16bQq8CpfDQvlUcjZCZorbXhtepydjGcv4fPe22X/HTQs+/RVPwJUEULSX
         XssAdeeUOyIHaZyRsXe4b8Dt1/Nn7hYQjusK7PIiqQzwsut9IQqI60agsqJxvZeMUZiu
         ORBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=qnjJxt0w8Udketthvjw2LHhC9pVbgtrsmfAURiQ1qJQ=;
        b=AdX5oueJYc6Jyrz8Qp/7iLBqjMYCcODFht3tzFGZz3MQ0gMLNUOxERHFkEC1i7b6Ns
         HZETdna8Kjq+qjfM1743i6ocBIXSmOTwPvlolpxbFlr3R37suks1ArMB8tQg36AIB0N/
         sQV6t6C0a4xTVNqp+eJcA/rA38DYeRS2Lan3uOyifrBhSZzQu1XeanLjTLwVS/+S6Tao
         T8IKsUYphIxgojbRJu4w4/LPgYuPU15s1Zg/hQvV0KBPxAeoJYWFP1BHYEZhRQC3+b81
         1rIycD1i8Jg3RpowkqVHPjZicDhKB/mfQQieTuI6ecwEGzs7ei+j7AsO+BIsh7mt1XMB
         HWhw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DlhSwUvs;
       spf=pass (google.com: domain of 30cjtxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30CJtXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=qnjJxt0w8Udketthvjw2LHhC9pVbgtrsmfAURiQ1qJQ=;
        b=TsS6HI0rO0K4GmXrBbkit+j3V97RJo6toYcXUmlZkV3Ms9P9coBPrnHZ4x5lG7oDxH
         aIVJQbVfj46wR7pqp4iENaHCQSamysto0UEZWQHNwvdMpq7ztQbxYSDxLCKmrWwyFXX7
         cOoX9h1pds2o8NCwMFjhD50Dlp0CDJkfbIaHBmtX7ZbMCga27qIIAIYnEfuoJ3v6LUJ9
         0aBIdxNuqoOF5GFGyiqjqI65z7k5Ox9VUxYfhfty+U/w+U9LXdkAQiwUPPXJJxHyo5wL
         49hJAW5wS5npImMlE4+oww4Mz5zG0OJnTEDsQMkPnOV8tx6YQeuHSeIfc8k9riX2RglR
         Eb/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qnjJxt0w8Udketthvjw2LHhC9pVbgtrsmfAURiQ1qJQ=;
        b=RFrBWv9NlQoVMrK6ZQPemNUHPlMY7SUpXZFt8zzOhGivF9jk+hanzWsLPJnk0qS24H
         hI8YoROHgzi+353gL5zH9CYRWrbGiZWb1+XtbQMKVFtFbzfrQi/uETSQMGB+y2WFHddI
         0nteW33HY1fApbgsTgrWY1JPuavAUZ7ek/OLGLYrGgZfTlaYT6m9++11bbUDJ4/BiDCj
         sVHvqQskgRT/t5gk7yUnyhSCpc/KJBAysn8isfC+yxGZUyaERiEZFh3l0jsT7f1E/H7t
         o3BXU5Evwh3SG3as/bzvj3jnwAYJsNKTyWBP5sU74h8kQ4BSWNp3fh4yCk1PgOS5ck7b
         bo1w==
X-Gm-Message-State: AOAM5319tjpEBCZKE3KAXVTDA85l8OEqZTC5te3ytEu8uo9f0M54+QAW
	UU1JV3Yzkj4jHMeJfieJ6p4=
X-Google-Smtp-Source: ABdhPJwjfuNX4/fnSbfKzyIBu/R1enkw77cxeQcMVoCEILcFUfteu3lZAqY0ikz7gSK+GLNRtUVEsA==
X-Received: by 2002:adf:8405:: with SMTP id 5mr1220389wrf.143.1600987857662;
        Thu, 24 Sep 2020 15:50:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:230d:: with SMTP id 13ls226453wmo.0.canary-gmail;
 Thu, 24 Sep 2020 15:50:56 -0700 (PDT)
X-Received: by 2002:a1c:750d:: with SMTP id o13mr918689wmc.54.1600987856645;
        Thu, 24 Sep 2020 15:50:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600987856; cv=none;
        d=google.com; s=arc-20160816;
        b=UWA7R7z6Twqv/tbPGGxpRMnQPFO/JrqQVLkHVd8VFerQRJmt6qzpUjjK1Gb7Bd1dHJ
         nu6DtvVVwlpmxv+PR3P4tfFZAiPQmmVOnEfP2NZX0dkFZi9JtzZEso3tr1//ocT6qEXL
         YR+BOl5vicBr7xZsIcI7j3OzbpZfWrWB4BPPTwxQlMiLtIXSDR4zl7kNjT18hl8SV6+w
         BtsKZZv+juLIFzx+AMrUYnagcQBM3XnIewJyAV36UKNAIF3nNytTdGjz0wGmYZfITI64
         2SwQ3SloeGSuCHAGPOYSB7GETJoIpYKpet076JXCA/Saj+ERZhY539fI/PqewUTzEoas
         gMlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Vj3UBI45JrVAWbqportzsgEf+6x4gUm8mMtKJtG/e0A=;
        b=Q2hTIjeN29KKUhXQcXoQaYcnaNaQdbkKNOe5mvcREn+3Feq2aw5BCP2FNLuoakg8tR
         gY4Y94OQ2xAekv8WyMNfewMeihkn9eh+Lr+Q9Nnza0Byb9A3VGw3QLV7SGdYjhMLCKgD
         JEu4/OJk2YmLJ3vxxG2Osx9c2v41VKhuC1x9vVfe7erln1PxtYcGloxN+fhr8oPePytz
         NFduTdoclh1KGDw9VUkiQiyGRnOPvMWhhxC2MYcJhl8fVOuxRK5fUle1e0I4X3Zjy2no
         K3HcQhOyQWhacL+fKIvUwSDRKPi5Tp6VZpaUhrlA0BsyIgyqru/ghKfQOiBcoAsO0Mqa
         MBVg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DlhSwUvs;
       spf=pass (google.com: domain of 30cjtxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30CJtXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id v5si23036wrs.0.2020.09.24.15.50.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 24 Sep 2020 15:50:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30cjtxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id b7so290755wrn.6
        for <kasan-dev@googlegroups.com>; Thu, 24 Sep 2020 15:50:56 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cd8b:: with SMTP id
 y11mr864526wmj.172.1600987856018; Thu, 24 Sep 2020 15:50:56 -0700 (PDT)
Date: Fri, 25 Sep 2020 00:50:09 +0200
In-Reply-To: <cover.1600987622.git.andreyknvl@google.com>
Message-Id: <bc98612aeb00e3ffad45a103fdbfa4fc383b3d0d.1600987622.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1600987622.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.681.g6f77f65b4e-goog
Subject: [PATCH v3 02/39] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev@googlegroups.com
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Elena Petrova <lenaptr@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DlhSwUvs;       spf=pass
 (google.com: domain of 30cjtxwokccsr4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=30CJtXwoKCcsr4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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

Currently only generic KASAN mode supports vmalloc, reflect that
in the config.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
---
Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 047b53dbfd58..e1d55331b618 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -156,7 +156,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.28.0.681.g6f77f65b4e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bc98612aeb00e3ffad45a103fdbfa4fc383b3d0d.1600987622.git.andreyknvl%40google.com.
