Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJW4QD6QKGQE2SBBVPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 6DB672A2F00
	for <lists+kasan-dev@lfdr.de>; Mon,  2 Nov 2020 17:04:54 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id j13sf6654270wrn.4
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Nov 2020 08:04:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604333094; cv=pass;
        d=google.com; s=arc-20160816;
        b=NZ5Tc5BDRlawh4Po3syATHpTLw2u9Kxe1X4NbOD1FYVFjLWvfBWLbJtvLsjNfX5K2n
         WnJNJkpwDmR5YgMyGFFU8stKwo/1gPQUX7jyOlYKUaw97jDDWBzVZTdRL/Uufp1/6nx6
         PJCdU3II0Dmmn9g/ryTlhsc3hU9swzJv23t9oyM0tsQO9Tg61ToPiVzJwL/fJr4WfExR
         mbh2BVQtKoG+q7ibPuauzj9zQWMQaOeux2Y/tIgMrpDY3PyhWzfFEQZrxtiInk0UgwIK
         fbCC2K5JtCKBi6cte0UxDLQlyi7ed6dfmvIG2fLnfyJsvLSzbzu/jr+0zwG2IQOrBIiH
         Eu+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=z5AW5ICx44aM0lG8Tlo5zaohzipOjM4t0YonBcwVtvU=;
        b=U2oWqqEvFZBl9uBVuVlCACJdPx+coqHi0BzUhgcVGRkERePcmSnEJIfHbAfatlxiWX
         bilH2bD9iKzcUwITM2e43g1Xn/u4eiRu/ZiA/YbEt7YFnLTQq2dc9kSbG8AyMc+DF9uG
         e3z/u480YbeWYIEb1JbNBryyr8GkEXrxyBwEw9WtT4AQBIhvFYs3hNLApVI4FrUZarBr
         L4hLWmVaVdfZHn7+BBmI8QMn4eYKWiKhCL5BFpL+tWsjGrWqh9tG8/IacXpNI76pWM62
         +mLyb5VAIqOujudY7uWyugz32UstRNXXA97rLb3NEnacE2SbzYVflXpJKxszgQhR4u9M
         Km9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U8TbU6Or;
       spf=pass (google.com: domain of 3js6gxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JS6gXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=z5AW5ICx44aM0lG8Tlo5zaohzipOjM4t0YonBcwVtvU=;
        b=lUXcKue7Vv+wudK+hKGCcN34JUa2UWfKitNdua16+S18o4Pun/YlK7KlqiIn7KSMl9
         vRSy8CgZ4V0Uj4msG0R2Xj5EIdtSVtqn5xUR4JPaOmY91vfkpmK/1Pmv1frEvZh3HE0p
         GSjAWVgtpe9YgJJgG7OAslX4gq/2pFMlIXSvG3R8JJRfO6XXw+ul1SdDxdMSAyKzqMoV
         a8cITf9MCynLMAs4bdFoYcxMqquJ57r5GizIXOgOcYMxoKgnWmzuukx3liqKMTozT6l7
         7rxN3mWCRdEe8BcbEy2xpjxH3iKKY1D0+Qxq5LkJrFmUhVpBB9nXy81zHsYBgiQ/n7UA
         jrWw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z5AW5ICx44aM0lG8Tlo5zaohzipOjM4t0YonBcwVtvU=;
        b=TgI90GhYEKlTSiEzJ0BcG5Na0NVurvm26ZxFcmnguSSUPYFbSOPlbTab8Y+Eit9ugZ
         YoNrBPO0kkVaFIfBgnecTukcEJpMkzYDsjMnIWZUBOCL8UFREK1FrVTPCN3GqhmTCasV
         EeWxty38nBuwcsdlBFeRbE6T3n/SxSHbzaBwo+qksRxDOzMWI1XyOZEaoHmXdta8mw91
         DYIn9okyAKvqmEEXTv4T5gOboZjS4BRTayEigFrLCs8N1QyIvGHiED1l0JK43Z5ZY203
         5tllLpaDE7qibBv5M6Qc7SjfpdYkz49zoJla1U38YKWC98/7YDdzDTZUcKsZFgXHnoGD
         6JQw==
X-Gm-Message-State: AOAM530FIx133cm+hTcu6LRE6E6/qRoZHWa6Z/7LyA1C9aqdlwAIcQWF
	iRP2dyONHkn+oBVwpdroPu4=
X-Google-Smtp-Source: ABdhPJyhla1SXv5YUSjkD6/1yrosQn8Ri/f/M3OvBkPLRUe78W2Qv6neu4KBP5MBD634nYwPxmKtrg==
X-Received: by 2002:adf:db03:: with SMTP id s3mr22229396wri.152.1604333094252;
        Mon, 02 Nov 2020 08:04:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f00f:: with SMTP id j15ls8285982wro.2.gmail; Mon, 02 Nov
 2020 08:04:53 -0800 (PST)
X-Received: by 2002:adf:f7c3:: with SMTP id a3mr22400647wrq.254.1604333093535;
        Mon, 02 Nov 2020 08:04:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604333093; cv=none;
        d=google.com; s=arc-20160816;
        b=NqJ3Vuln9Cm9Gu6UpF4Ilo7ta27wb9S0m0VWk0nIzcPlAjBoSnrum0yl1IVSI5tRdc
         K/uqr7QssYqPiGgf33ENr+H2w0qk2Fcbzgonm3y5cMcP6YW8A8pNA3kzyX+HuOTkSj8H
         4t9FT07avk0OMb6NF+Ie0IsWxu6QGG5ArzHCJCZUNJJsk2bzltCl+LX7PF0IF58PyBkB
         cfb6bqBw0DCw34QcNdnNdQZ5Xvd+VIILUHBnIieSeZ4B/wirWvalDBrAfL5IqaBx25SS
         S6UYXtZV3TXRlXMTQPpVdxVhtKH1+BvBHA0mx7+FZg/fuRBatnQ0cJ78sjohdPDJtomp
         y0ZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LIY2nrONxUEpI3abKUGgXLbsvOzrU8dATPLwmTEHaeU=;
        b=jCJIIcYInKPH1cC+Vw8FTZeW/QvmdH5eVZPJDFjMWYNP1+CkkKhCjsUTkjUE4fhEHs
         Z8uA+gBCeCCIksTe3vSBMoRTeO+oevI/Bk1Av9HizOHH6Iwmx45O8uQcHdm20XtvI9iI
         2rvlNZwMaLwaAcoboZBSGNWqck3/NFobwEQHTYwius2w4BkklB4NKwE+8dkKKQH0bE71
         JNFNSbaO9aPgkIos9JpmweyO4tvVMMbIeE0tRyWp5CkHgu+oM2ZOtA1syM9yXrz3C7Lj
         7pAMLxoi6bilFBUqB/1MKMM1fnSMqfRQi6jGQ7yBg9dqegebydKXahSHGrBz5zd+vqLx
         ARuA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=U8TbU6Or;
       spf=pass (google.com: domain of 3js6gxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JS6gXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id e5si541468wrj.3.2020.11.02.08.04.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 02 Nov 2020 08:04:53 -0800 (PST)
Received-SPF: pass (google.com: domain of 3js6gxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id m20so6612454wrb.21
        for <kasan-dev@googlegroups.com>; Mon, 02 Nov 2020 08:04:53 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:dc4c:: with SMTP id
 m12mr8197981wrj.177.1604333093213; Mon, 02 Nov 2020 08:04:53 -0800 (PST)
Date: Mon,  2 Nov 2020 17:03:51 +0100
In-Reply-To: <cover.1604333009.git.andreyknvl@google.com>
Message-Id: <d8fef04e7ddb79187d76865d7f3da7077288da44.1604333009.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604333009.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH v7 11/41] kasan: KASAN_VMALLOC depends on KASAN_GENERIC
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=U8TbU6Or;       spf=pass
 (google.com: domain of 3js6gxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3JS6gXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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
Reviewed-by: Marco Elver <elver@google.com>
---
Change-Id: I1889e5b3bed28cc5d607802fb6ae43ba461c0dc1
---
 lib/Kconfig.kasan | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index 542a9c18398e..8f0742a0f23e 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -155,7 +155,7 @@ config KASAN_SW_TAGS_IDENTIFY
 
 config KASAN_VMALLOC
 	bool "Back mappings in vmalloc space with real shadow memory"
-	depends on HAVE_ARCH_KASAN_VMALLOC
+	depends on KASAN_GENERIC && HAVE_ARCH_KASAN_VMALLOC
 	help
 	  By default, the shadow region for vmalloc space is the read-only
 	  zero page. This means that KASAN cannot detect errors involving
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/d8fef04e7ddb79187d76865d7f3da7077288da44.1604333009.git.andreyknvl%40google.com.
