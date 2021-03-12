Return-Path: <kasan-dev+bncBDX4HWEMTEBRBLHTVWBAMGQEYQAYLZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id AB0DF338FE0
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:24:45 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id h6sf10324427plr.23
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:24:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559084; cv=pass;
        d=google.com; s=arc-20160816;
        b=Axf3igB17JWWzbCddZCc0/TYeW65JikumS28Is235dw5IsDttyVxa/P3taT1pXMJmf
         wejWD6RA7tRtTFeZy3QqflKQrBGXPq5cQ1VdWaKGoZ9Mv5Vuo1AOcInvSedtA//wX8UN
         C2JgjOULisOAbT+94kDLaeqEgr3YEIUEriTjPxofW9Dzaokx1yjzBro4RJ8zoyazCIVY
         fh0uIOkW56yTLNKqJWyI7W7V28gIQiOOHNb/XVdoslGauhm4me+KCRfLeWdk6UFmKD7M
         uP7JmtzDR4QAdFR/8XETRAgyj8shmOcjcAzNhLN+iucq8PsMl/yViwmkZw8BRMkxMk5q
         aBYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qxIomPbuY36pPgxEpxmVIIomvvrM2v4BogaBMt+czys=;
        b=uBiRLlmW4uzzNWtIiaxXLARQyxdP74SJsav2idCaRYg9Tc0MdFghWSXBBZgtxIBCzP
         yOr+kTwQHPDpDkGz0D7Jk3eaGesKdNNV4IQ6+5fJsdnZnRHEbToBEz1XPI730QjJmrXV
         bFGRf+dVCf+mSxo7DWN+dKHgXU8Io2IOMz3gF/zIibSr2FWZqgweSMwfrb1otMMa6Efq
         tzgrhSmpgERLAbw5hGL3thJl1PRpCAIH1U/c5ZlI8t5LK/kkOCFocf0oDp/lGuAd97gE
         lpJakkYqdm6FJa3dk7Rtshh2vD5Wgj9qFk6HrVpVWRC+YgDFxU/y2QO9pBkSmmkLoOPr
         i5UQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BfEhzme8;
       spf=pass (google.com: domain of 3qnllyaokcdmzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3qnlLYAoKCdMzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qxIomPbuY36pPgxEpxmVIIomvvrM2v4BogaBMt+czys=;
        b=XDwzqIOkuVSdKejPD9jrNXC8xUhBi9Skqx4FxTzn2Oe9QkkR8Mqd4UCK/fxNdNUZ8S
         j5JdNE1iEa+Gd8YY1fm1TYUruYl/gExoJVno6Bv/exHwF70TfwS9nspwF6lS0eDxMQMI
         209f+ixHM0NLMt8mF3OpJZbMsyFk2ElIy0BxJlnyxDjVddE4IdR1pOxGWyRU/nd61dhz
         c1EpRBSXh/fThx7MGqj5zAUxeVAcwGDyXgXeY0qCU23m5AkuvA/Ep6ehCddWkiNjFhnH
         yd7NbFfpzVBBG5iTXmE8Otr0TIkw7rVA7BvsxAiAnbHtLpcdI2Cz3IVvS9Rg7O/5J9Pu
         6KaA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qxIomPbuY36pPgxEpxmVIIomvvrM2v4BogaBMt+czys=;
        b=qy0Cjd5RZAhSiYnkSijBD0rLY0Iq28wnPqRz965AkJUwKwtAe3NYgPDRvPj7PGI9X1
         pSEoFVcrhKEKNOtGGAJESVczfg2dDalnODSiQqCn10vokgy2aW5uVHqpJ/HR0ut9KVpm
         D05ZMVXK63f4onwr4KdHEEC3d44JcOM/jZEssoB0xDH3PWuiyNqcx11VOy+2MlHIbIXy
         qw4S4fAiJwBx29TLLNKYysL0Nn7AgusgjXT6NbNTc09auIDb6YJ/KvPZM9rqtpSE/vBB
         VPt+MBKU2NuPEpFSsA1d5xqzJyG7ZceGsAhWU+OqIg70todvrgaE+DlIwZA/F2VphBwD
         WWEQ==
X-Gm-Message-State: AOAM532aiEkYsQmP/77JBXQzkU6ftaFRRaUHJUMFLdof1EkjhBn7RQ86
	2ncnFLYS3BEkVT47U8A0da4=
X-Google-Smtp-Source: ABdhPJyzbnESeeyeemsnrlYjIZVVG6IikAT4llQ84fttUi1lIwNeZEu66AZIqzkQZYhxknhIv0NBvQ==
X-Received: by 2002:a17:902:cec8:b029:e4:a497:da92 with SMTP id d8-20020a170902cec8b02900e4a497da92mr14045411plg.74.1615559084462;
        Fri, 12 Mar 2021 06:24:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:1417:: with SMTP id 23ls3815489pfu.9.gmail; Fri, 12 Mar
 2021 06:24:43 -0800 (PST)
X-Received: by 2002:aa7:86d9:0:b029:1ff:275c:b67a with SMTP id h25-20020aa786d90000b02901ff275cb67amr8102478pfo.69.1615559083644;
        Fri, 12 Mar 2021 06:24:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559083; cv=none;
        d=google.com; s=arc-20160816;
        b=zqhLmCv2ycm7HnPcIbPgRdz2aCMM9kzCIf/8/W2loUVF3UDLA9rK3BIsnNJx5BEQ+a
         k8WdWSC4hQzZkze8DGJtXbiKIvhSM44l0pV1fY9EL/Eiq46kffeFtFdnMwAKW3cA/hOQ
         oIrtVohOiGZa63GslZI3SQCHFDJhAnon8yknxgCnqMQO63oGrbk1BCrZ5Z34IllSKy9S
         GZBG6tMDK4qnUib/VsT1oSE4J4OQfmEhZBdmbCFAFU4Fmrv6YU/S4fFJyP9nNT5FXCkt
         1DaPkMbwlzQDqjGNf3b6/5KaFzjBClB8kmiWfYo8JqyhJSwq/fq4onw2FvdCUWbNx6RU
         zmVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=UIn9R6iWNTpuninm8yzAqfvqLsQ1Z3TszvORzjzD33U=;
        b=y2/lg/dZ705FxR2ga/1QgOq5KWUi+3q04GFm+Y19W+VT+21tZhHOnJKt6Z2xPXUWi1
         yw6mcNJ/aRIqONs49bGESZJeNjAihowP2hYh4SfHrnAU9x33pD7m/V36c+Rq+OP78IuR
         CeGXoBLO/LGvQ2/RJlX9xBvBh138CCshuXP5YqeIO/m1+zWyYBjxqgA1WDUwPZzG3G01
         csNceQ9z2/131Pb0yNRl/uIgnl2uywLodG8RvbdcR2B7M7LdjgflOxYfcJZ8q74NoeyY
         T1de3Qzp51wJIMLOx2VasXtgLCBVbLeRZHdhmul1+590rXP1H6W0TzNJgwTlNrihmQ4k
         FD0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=BfEhzme8;
       spf=pass (google.com: domain of 3qnllyaokcdmzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3qnlLYAoKCdMzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id x1si365935plm.5.2021.03.12.06.24.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:24:43 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qnllyaokcdmzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id a1so18184371qkn.11
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:24:43 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a0c:aa45:: with SMTP id
 e5mr1897790qvb.44.1615559082706; Fri, 12 Mar 2021 06:24:42 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:26 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <48427809cd4b8b5d6bc00926cbe87e2b5081df17.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 03/11] kasan: docs: update usage section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=BfEhzme8;       spf=pass
 (google.com: domain of 3qnllyaokcdmzc2g3n9cka5dd5a3.1db9zhzc-23k5dd5a35gdjeh.1db@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3qnlLYAoKCdMzC2G3N9CKA5DD5A3.1DB9zHzC-23K5DD5A35GDJEH.1DB@flex--andreyknvl.bounces.google.com;
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

Update the "Usage" section in KASAN documentation:

- Add inline code snippet markers.
- Reword the part about stack traces for clarity.
- Other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 23 +++++++++++------------
 1 file changed, 11 insertions(+), 12 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 2f2697b290d5..46f4e9680805 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -41,22 +41,21 @@ and riscv architectures, and tag-based KASAN modes are supported only for arm64.
 Usage
 -----
 
-To enable KASAN configure kernel with::
+To enable KASAN, configure the kernel with::
 
-	  CONFIG_KASAN = y
+	  CONFIG_KASAN=y
 
-and choose between CONFIG_KASAN_GENERIC (to enable generic KASAN),
-CONFIG_KASAN_SW_TAGS (to enable software tag-based KASAN), and
-CONFIG_KASAN_HW_TAGS (to enable hardware tag-based KASAN).
+and choose between ``CONFIG_KASAN_GENERIC`` (to enable generic KASAN),
+``CONFIG_KASAN_SW_TAGS`` (to enable software tag-based KASAN), and
+``CONFIG_KASAN_HW_TAGS`` (to enable hardware tag-based KASAN).
 
-For software modes, you also need to choose between CONFIG_KASAN_OUTLINE and
-CONFIG_KASAN_INLINE. Outline and inline are compiler instrumentation types.
-The former produces smaller binary while the latter is 1.1 - 2 times faster.
+For software modes, also choose between ``CONFIG_KASAN_OUTLINE`` and
+``CONFIG_KASAN_INLINE``. Outline and inline are compiler instrumentation types.
+The former produces a smaller binary while the latter is 1.1-2 times faster.
 
-For better error reports that include stack traces, enable CONFIG_STACKTRACE.
-
-To augment reports with last allocation and freeing stack of the physical page,
-it is recommended to enable also CONFIG_PAGE_OWNER and boot with page_owner=on.
+To include alloc and free stack traces of affected slab objects into reports,
+enable ``CONFIG_STACKTRACE``. To include alloc and free stack traces of affected
+physical pages, enable ``CONFIG_PAGE_OWNER`` and boot with ``page_owner=on``.
 
 Error reports
 ~~~~~~~~~~~~~
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/48427809cd4b8b5d6bc00926cbe87e2b5081df17.1615559068.git.andreyknvl%40google.com.
