Return-Path: <kasan-dev+bncBAABBBMLXCHAMGQEBVZPT5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id E623E481FBB
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:16:21 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id r20-20020a2eb894000000b0021a4e932846sf8504117ljp.6
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:16:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891781; cv=pass;
        d=google.com; s=arc-20160816;
        b=M+0yftW7foZDzIZZlHRGnG3qyaPtkebG49M+rpqOdJgvG9JBQX4BpUOTYfA/7dkHub
         8j4KadH8D/NWRwFyU6PVQo48fJ54egj8upVd8XwYdoup2nnljxKFCG/zgdFQj0g3dR9i
         4dTn8a4ZcvIa/9wh3WOjt0vXt0Xk1bDApk+50bexWwSZDwIZjjTKcnS8NgUAJN9wxei2
         vTVS3ATe27IDrZ4nJOXFL1hOC3rDxDL5WRVvyYPjlaG0APiaMmxuswjmJj5NsSe9Zi5b
         L+vpNs4IFPESjI+KUJ5TRWiMfAbl3pLir+CV5JIjctA/9UIFQBO+7mYVFCUyOEoSbZ9j
         0Fig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=INiogfPUakgtKUWW8ad/wueMrBaUTYPlbmCgIQ2o+N8=;
        b=ma+XnMlSQ+BjnP4d8I0rwkVQpQw6OLuMafv4vYqUcsy+YGcVpOalzeDE7NyIYQitox
         tcHXQ1tn+7dKUTDoJDLEdMx0AotZulOcKs/m5ImkLSR7gXx7oiB2lUK/sVMTzX7S34yQ
         7zK9z+9L2CmZi6BFCCPS/coESFObVXnlOJyHjxBbdXBs/SpkZxcj/k78Bpc5v4SMhvcQ
         quscJJ/zspgWXifdtgIK9vnfA09zgvjhw/U6mX9tPMMkMhG8L63vuDVowOB0z66c1mu9
         ji7AfDuuB9E9doIgt6sSgtLxdRgpnVE7L86U1QfCfmQWvXj7/knpwSTw22uUhpFf6Fq4
         IRjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HQhqX9Ou;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=INiogfPUakgtKUWW8ad/wueMrBaUTYPlbmCgIQ2o+N8=;
        b=Aj0jBXB1B6cPs0DiZOhuupOmfg42dWDIstBEQwbknY3bs0PjVPQpCyLb9uBElATxAO
         XN4iyCAp2AuCsN2pAnj26uB1EgER3NFRiEVlBL1IAIYTZH+PzVKpelAHSfMln9+Cd9ED
         l24j3bph2MYcaYG70KQZDb83it1z26WlnyNiE0RX+5jfuHHFBCIKl9exP+Sqi9Rzkdx8
         ZokDCFfS/9tadD38R8/T4y9DEus6DOQtCVdwYkm8NWzQ9eJHM7AlOEh/TRyKt6YHK7hg
         6R88Ln47T0Vk9/uDDCqeSLqBV4phriaMZUggt1FvG1qn4rVe8yh4reP/4a91iImilC6t
         3Jjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=INiogfPUakgtKUWW8ad/wueMrBaUTYPlbmCgIQ2o+N8=;
        b=V1GEmkevvX11ofspxFxZAAoIPu0uXzFY+ZhgV6n5tL/2d798C3wSCo8aDcRpp4SuEx
         9ejGYloBb5Tf1cs7KxqOWoQqiBUNl+YcW+ktm0lEO3hzo8p3LG4szWc/HUVCN4sa5nhM
         cA13a27jJ4dLvuQLBym21tGfv94Q0san6Z3ByM61evrg7RpltzeLzzhDO23F6e8pluNA
         Ch3kTVJuTR85F8+gQ8VPsC22BS7GYqR6XM/vQQLfA9CDIj0sYUcm+jND3+DjQYERLY8E
         QTl9kTGH9lvRVl9EX6/DJMe/YiRjivZUrUqO9GJSquOr1x1eGw/+V3BgUIw44GuZwwc2
         D6nw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530RKbeT0wXM2KoAZ9H7b14R3GHoYI0WUd3EeZ/rjkEosgnKEnot
	yksgbschVlUiCIeltE1KdjI=
X-Google-Smtp-Source: ABdhPJxE0XATbI/AI1s9OKJNpL62+Rw1uvw9i+sQG0PxALFEMS3AvrfaZ2hFUD5u2ZeZGIXShT8kjQ==
X-Received: by 2002:a19:ee01:: with SMTP id g1mr28763518lfb.50.1640891781327;
        Thu, 30 Dec 2021 11:16:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:454:: with SMTP id g20ls1929675ljg.1.gmail; Thu, 30
 Dec 2021 11:16:20 -0800 (PST)
X-Received: by 2002:a05:651c:1246:: with SMTP id h6mr13717345ljh.300.1640891780606;
        Thu, 30 Dec 2021 11:16:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891780; cv=none;
        d=google.com; s=arc-20160816;
        b=VblV3jebFeH+W49OEoWzbKhTzvb36yeBuMkfzIgQ6EpRXzabeeR8MV2nHnzz+amrbR
         K5rG038xa38KKVnT0LTieHTNbO7Fw0mRjUnYPDRLPsSzX4Ylb1BKsSiI6BR/x7OAGxeu
         UZWJHrrbW4WLsBsFRBH8yo4x+bI6ucMymIF6G1tNp3SGxcZ1Bi8VcqsakZEnjZzCuJYn
         yynEjw4HJiP5N5WbnQBvTLjP4F6NC5/1bLnmq60NDMgWOSjWz4vFi/xzBPeIWnZG6SO6
         0sWpB2fBxAwL5SwmiP9oZ51rO9ykJs8pSeen/rF5d+nvxwtXGFJBu4mgRBzeQdMShe10
         tW2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=woHyASpRd1dsSk1k8aXjCDxvW5sGTzgveGosFVStA8I=;
        b=B9dTWgjELBbMFcLRYf0zDk9mFzjYUcsniIHmXoHM290wQIo0o+TIJh/zrzBL+k+ntK
         U6O8gYYn6Y9tgFhi/ImeeopLdKZCtq1/gjQgCf9zgGR0nALwVnrsAYNiJwjsWnavS/4/
         Sv0dTrlOdGbDrARcI7eqvQDZ/RymQ9ASNMdMHVEGZNLqN/YaW2zFAV8AyLm1WkhChaXD
         jdRKrFc9ioQO1NA8RU/zjKsn6rJWifdYgpP0aiTmHF0SujBj+zBg1fy4boovO4yCkV7I
         NqTuGcTrVqxjJhOPEFqmq5rSj5ewV5jPfdHLWT28Laf0j3FVgmP+wDADipv/YbHoUWnL
         xrxg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=HQhqX9Ou;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [2001:41d0:2:aacc::])
        by gmr-mx.google.com with ESMTPS id d1si969728ljq.5.2021.12.30.11.16.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:16:20 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:aacc:: as permitted sender) client-ip=2001:41d0:2:aacc::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 33/39] kasan: mark kasan_arg_stacktrace as __initdata
Date: Thu, 30 Dec 2021 20:14:58 +0100
Message-Id: <4ee96e054d59a2c65dace818cfa2c2e2bd1cb2ee.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=HQhqX9Ou;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:aacc:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

As kasan_arg_stacktrace is only used in __init functions, mark it as
__initdata instead of __ro_after_init to allow it be freed after boot.

The other enums for KASAN args are used in kasan_init_hw_tags_cpu(),
which is not marked as __init as a CPU can be hot-plugged after boot.
Clarify this in a comment.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Suggested-by: Marco Elver <elver@google.com>

---

Changes v1->v2:
- Add this patch.
---
 mm/kasan/hw_tags.c | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 2e9378a4f07f..6509809dd5d8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -40,7 +40,7 @@ enum kasan_arg_stacktrace {
 
 static enum kasan_arg kasan_arg __ro_after_init;
 static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
-static enum kasan_arg_stacktrace kasan_arg_stacktrace __ro_after_init;
+static enum kasan_arg_stacktrace kasan_arg_stacktrace __initdata;
 
 /* Whether KASAN is enabled at all. */
 DEFINE_STATIC_KEY_FALSE(kasan_flag_enabled);
@@ -116,7 +116,10 @@ static inline const char *kasan_mode_info(void)
 		return "sync";
 }
 
-/* kasan_init_hw_tags_cpu() is called for each CPU. */
+/*
+ * kasan_init_hw_tags_cpu() is called for each CPU.
+ * Not marked as __init as a CPU can be hot-plugged after boot.
+ */
 void kasan_init_hw_tags_cpu(void)
 {
 	/*
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/4ee96e054d59a2c65dace818cfa2c2e2bd1cb2ee.1640891329.git.andreyknvl%40google.com.
