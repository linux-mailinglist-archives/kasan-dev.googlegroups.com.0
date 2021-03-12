Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMHTVWBAMGQEHVT5MSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 15CC9338FE3
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:24:50 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id k10sf12319068pfp.15
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:24:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559088; cv=pass;
        d=google.com; s=arc-20160816;
        b=OsRctpYmcqBiI7JQC1T3QyhBLOU55tZBo84Cg/tU8kmMaF7l16PTnNHutvvUSEpCwi
         xvv59ZJjxPhFkKNls2Sm4gjocTOcvWMSEWWZrUROO9eFX359eWOikn9etRU/GF28Wekw
         I0QixZBY88X4H3vT6nV6H9jKZHeGt1AIQapzO67VU0xG1G6F5khmQVXTmSWxug8c9zbX
         OVfyzcBNaKpYHC9+EQDCsDD3am/vQc2Hbq981VGhqBMJH7NkmZjGh3EC9HpZH/ktcbMW
         0Iv8TEqveN1/k6G/pM3ZNuHKrM63z6eo07ybIp9Y3IvXe2Bq5ijxAcpqhu0ZlnatfLPM
         oRdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=6EfQn3MVXvIhNX2o17dVETe5X+QS64hIVHBOpZAauKE=;
        b=OBj5TB30iG4I8+nGWbhiQpvXh2ZdT9HDUsqWyQjrlpbc3TWt5PwLcMUmsxJOXlhunW
         2DQgtnHKLIvFb/YZCsQmRIdL+M4F+5lSfifrleb4CQ24uUMtkQmEfXnHHsREkDEPlxUR
         4CHPqxvtO7ycyCAQv4ZEzu5M6OWbuXrG0C3XVq935yvX1r0oovpS1tv4n9AaAWCEoVJo
         LHq+9b7s0p5nOnPt0zp+o82XBSsL+JFlMXczRGVl2eB7uN4lik5ysQk04NeIhK25yrya
         saJSaeoY6Ei8yuV84exSiOlsPxhWGbSTzaTS0pCzImU4YktZs2NUtnTwIsSuGHfxLI+X
         xk3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hTQLmWZF;
       spf=pass (google.com: domain of 3r3llyaokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3r3lLYAoKCdg4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6EfQn3MVXvIhNX2o17dVETe5X+QS64hIVHBOpZAauKE=;
        b=mwHJKTfK7pOKuMy3IcyECtVIJ2q58rRLme8uWEbFoIhENSvP/DE8oiVcjFs5xivG0P
         weZznHM7Hnc3vmg6UjCXnqM2vi/Qn92BotFXGjhelI4fkno+L7hyQ7J5LenLux+WsL0z
         o4uE061gvVeicD7XznCE6SStvd8EkWk4djCkgZxN78eapD4mdL/co8mOsJrGomcgWcwG
         1Q7Oy93uzxAYan+vdk2hdV0Wn+NuxzD4rSW858BgGy2RY+tVrYA2kODaj9iP3tn2+AFh
         ZO6Zv+zYOy05HIDP01sw8sgVgcvsOOAfl2e4cnx9NlJNEUvDG8foERqHKy2dQYktHOIy
         Zz8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6EfQn3MVXvIhNX2o17dVETe5X+QS64hIVHBOpZAauKE=;
        b=eWagTl962fAu1PzXuXE8WkNeFGB0/msv/C+hJHYkleWzjRlbmtQ1RKT8oKxbwB05y8
         J1BDXItv8HQ6f0QKn6ofD4AQygWThCkpl4munJJbX3FdXNvLQNdSWBni0h3mA5I2L7h6
         6ZvrNNeE98vhVVXXaLIOWLKzj9CRwH3DBxEUIXe5esIVvlR6Hav/N3DnKrRtnpZBGYBT
         saQYomcf7BtYDIBtCGf0T03m+asajvAsMBcPXERzaJ/zJxTsKwKW9riCy9+Mwxn2j5jG
         beufJJrI1Eumr4l0eRe0qkw8A7M6HUwIr1YJqF4H3N6WXvhgmObayIBxKsnrYYcJj9ME
         Twpw==
X-Gm-Message-State: AOAM530L5w7pEI4EcOT3L6x6UrlZRZpAlr52nTyGwoZSwKTDfpy3B1DU
	2VXM5Wu1J0AQAf6k523U27Y=
X-Google-Smtp-Source: ABdhPJyGOcUwptstfWV648EIx8QXEDCfEuCshd50jI/yGJATkBFYBOA6rWbQux0SG+Qc8i5hndbNQA==
X-Received: by 2002:a17:90b:438a:: with SMTP id in10mr14375715pjb.165.1615559088789;
        Fri, 12 Mar 2021 06:24:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:2c8c:: with SMTP id s134ls3819741pfs.6.gmail; Fri, 12
 Mar 2021 06:24:48 -0800 (PST)
X-Received: by 2002:a63:c343:: with SMTP id e3mr12278967pgd.8.1615559088326;
        Fri, 12 Mar 2021 06:24:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559088; cv=none;
        d=google.com; s=arc-20160816;
        b=RbqC0DWDIOVgNh/BLZUVMUP8zeiW0WxpD7moEecsYkrdZvTBAqCXA6/daY8uSB4Zhi
         g3LyPu9/XtFPEULpOaHNIo0Y6p2zaVo67GhjRL9xuLOH2aysy89cIeoipqHiww9XtDql
         jnLXxIlZ4tVW080K1UR+Bsk1jIMVNZVDbjZJNAg6CBKkA87WXxUfNqD+bE5vZZ83umTh
         yndHGfsQxmxeSLzC5rM/ivHVGPDKGo3fiSUtQJxv5TcjwbC6wfYTxTRcN3r8ZXFF5SL+
         YuJFGw2JBtL3tHPNY8qmL8YDoxCKfWN9ZG3chbEoruUZFtfpZlnPsm4Ns0gD2qQ7aEbG
         qSLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=JZTsOk7rsE4y13QJJB2MKSWKMrX5Hi5qHr1bAz5AyQ0=;
        b=giAaFttkhyuG0l/X9gh2RU866RaHYGhHf0c0ro1Gugus6Oxb7JjQU4Q0UEzuxx0EGd
         8neBSDshGndkZ168UGvlr8IR/c0vxH89CUTGHs4W6nvk3VLvUKjwzp2zaOxDhBnWtXID
         C+r8xVrGrVN7vsgGD6kTTVfzMwDMWMzZ/RayTpRStVJ8a7K6OkOr1HdFnF2uwvS89VEP
         Ui9AZDs7JKCTDp60fyMBwp1IMdtCSRAbk2Qqf0Ga1PGHW4zRtcmFCyvasUnOIUFw2SwN
         T3boxJeAuQut/O0AUv1rOxQbBBmO0q00kqyvxb4LJDECSMhoSehFrHNFkz3VOkzHrpLN
         nQ5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hTQLmWZF;
       spf=pass (google.com: domain of 3r3llyaokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3r3lLYAoKCdg4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id f7si346029pjs.1.2021.03.12.06.24.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:24:48 -0800 (PST)
Received-SPF: pass (google.com: domain of 3r3llyaokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id u15so17632975qvo.13
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:24:48 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:ad4:51c1:: with SMTP id
 p1mr12931323qvq.39.1615559087508; Fri, 12 Mar 2021 06:24:47 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:28 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <01364952f15789948f0627d6733b5cdf5209f83a.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 05/11] kasan: docs: update boot parameters section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hTQLmWZF;       spf=pass
 (google.com: domain of 3r3llyaokcdg4h7l8sehpfaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3r3lLYAoKCdg4H7L8SEHPFAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--andreyknvl.bounces.google.com;
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

Update the "Boot parameters" section in KASAN documentation:

- Mention panic_on_warn.
- Mention kasan_multi_shot and its interaction with panic_on_warn.
- Clarify kasan.fault=panic interaction with panic_on_warn.
- A readability clean-up.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 14 ++++++++++----
 1 file changed, 10 insertions(+), 4 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index cd12c890b888..1189be9b4cb5 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -174,10 +174,16 @@ call_rcu() and workqueue queuing.
 Boot parameters
 ~~~~~~~~~~~~~~~
 
+KASAN is affected by the generic ``panic_on_warn`` command line parameter.
+When it is enabled, KASAN panics the kernel after printing a bug report.
+
+By default, KASAN prints a bug report only for the first invalid memory access.
+With ``kasan_multi_shot``, KASAN prints a report on every invalid access. This
+effectively disables ``panic_on_warn`` for KASAN reports.
+
 Hardware tag-based KASAN mode (see the section about various modes below) is
 intended for use in production as a security mitigation. Therefore, it supports
-boot parameters that allow to disable KASAN competely or otherwise control
-particular KASAN features.
+boot parameters that allow disabling KASAN or controlling its features.
 
 - ``kasan=off`` or ``=on`` controls whether KASAN is enabled (default: ``on``).
 
@@ -185,8 +191,8 @@ particular KASAN features.
   traces collection (default: ``on``).
 
 - ``kasan.fault=report`` or ``=panic`` controls whether to only print a KASAN
-  report or also panic the kernel (default: ``report``). Note, that tag
-  checking gets disabled after the first reported bug.
+  report or also panic the kernel (default: ``report``). The panic happens even
+  if ``kasan_multi_shot`` is enabled.
 
 Implementation details
 ----------------------
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01364952f15789948f0627d6733b5cdf5209f83a.1615559068.git.andreyknvl%40google.com.
