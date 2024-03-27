Return-Path: <kasan-dev+bncBC5JXFXXVEGRBPFASCYAMGQEWOLWIZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3b.google.com (mail-qv1-xf3b.google.com [IPv6:2607:f8b0:4864:20::f3b])
	by mail.lfdr.de (Postfix) with ESMTPS id E542388DFA5
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 13:25:33 +0100 (CET)
Received: by mail-qv1-xf3b.google.com with SMTP id 6a1803df08f44-69057317d23sf108673276d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 05:25:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711542333; cv=pass;
        d=google.com; s=arc-20160816;
        b=NCfzevLL3RmQQgr9qFXknArRYvYJZQwyq+9rvMdUp7dUycYukjIgdXZMvbciVjYdLz
         ubIPvP3WNpySzhzFa0R84JnLmHa1vDZAJGDohpvxjFSMVs9yn6MoqhGV0ksDNyNzuJOv
         Xf98Ay36MMgNUpeGAmd4DnF2DCOQeweeMmlH97yJKnHF7fPRdUxuqViQtVOl3oVwgjIq
         QwH1Htv26g2pT2n/b4A9ZDNGPdT5qII8OKy4zhSU+bHZaDDSe3FMFAVZMa8meZUJ6qJc
         BlGPFIxxSEm1LFO2fhnoBv6edoltgDcunM38OO7EWcE7w2gBpXw/muskWrmAC3PwrNm9
         P9Rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=b+o2GZE+0Hsue0A49FcTeELPS7tRGa/3JSM47NOOml0=;
        fh=LkeGZd5UHN3CuFD4zJ8ZoEIHaD7Kxr5kuAN4ODgJ+o8=;
        b=Fk8JDV77bXYqVeYwVYmXo1UcgsCzGAg6YYYAbAimjQV3Atn8sBAgHUxqgvYuZsfFH6
         I5eHhtgjy/ceS0jrz9Ut6o6381LVUCwCfnba9h+zzUdLewWb1JOydtUGx1wLfMEOrP3+
         b7UD7jHdH1w/KRyJmtG+OuimoGuarZ6G1RNKhdAouO/9b5bUqhaf5YOucfH39momUBna
         3B71eeKXRjW5bblG/M5P+x0sYXIbEURn1of7ob+a02KaoTGbeOoboBJ2SdOVXfMTckm6
         YhZ+eV0ilhJ2dxv65jgI4QTlR7/s5+y1xUdXsm3f78yfEmpx168eMGS/L0zkSAQaxhJ/
         SvjQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=quj1LnWo;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711542333; x=1712147133; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b+o2GZE+0Hsue0A49FcTeELPS7tRGa/3JSM47NOOml0=;
        b=ssdrU1QSpzMIfO/CkFq+QAiHP8qdsuG1QXCZWgBbMWQS1lFSKwN4iWHbFHqrtFYpk/
         /P9TM9kpnbJa5O6objpd3K84SVNSsXV3kT/huRSZ2JjPJFS+PIjlquHmNVIkbS5juJT3
         Eckvt/1kPXPy0TS58/FFRA+VG6GpXvxC7Jk6jg9TakBcw1e1h94Nkgj5cBcLdxakcC+z
         p0m7XsVA1B7erqOv27jb2y6HjIyABnesVCPuiqghkni8f7qC5XBGSltwCZEhDTyGUOey
         a5yQ+T4Ndtwy2UjBgnWFGqSAIQwbk8pqM7M+tA81sdbCmYZAIgroT6ep5aSCY4i8rMdR
         mzqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711542333; x=1712147133;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b+o2GZE+0Hsue0A49FcTeELPS7tRGa/3JSM47NOOml0=;
        b=BU+x6LlxoYV2HCvEK2QaILO6qMuw/kLC/pUOrGYpxu9z6w3+nvy7DEAU3QI6LEyODQ
         nVg2ccEnajLIfBj37eCE+cuH/65OUmZ9ZySeUaw+6eEVGikbWeV+5KsVZhj61PtBrx0b
         Ud1JaTq23qVVwdL5ATRGd08YeBIuRnZHtljI6HRyvVYcen4GIwm2c1nxG7Av/uNHdllf
         /PE2QY2CPDLxdVao25O6+U6qxHnI79XUJw5LQ3JAgysIojvpxvvB21q2D/eijgfVIP1G
         4Tf/+v4YyLamvBshM+kTa7JRObVUx3B757eI9hRMxTzVi9v58cn5JyL1oSnhh7Npi0W0
         ZcLQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWcSg+kJe5HPdaC1EDdLqa2mwnivbkPqRDtht0Qv3QQUfU/ReoEhzC+KXj6WzER0IbwcFDZD9IJOh3306iyaz9dMcq/L3sYeA==
X-Gm-Message-State: AOJu0YwIElBqnKgT441V91H37zn9mnvjxQ88Mr1DHHD4qxkRT5uR1rt5
	uN7OVwFdZwminhW/MjwxsKK5/BLGlpqNaCOCP/U4YQAT0FlLg+IF
X-Google-Smtp-Source: AGHT+IHKoKVT0AmgyZ+etFhpB6h/1Ya8gdrpZbN0kkeUABWtFpWbWUwpIqsk4YkQ8Jrcy0ASIObUrQ==
X-Received: by 2002:a05:6214:2268:b0:696:4f6d:cd73 with SMTP id gs8-20020a056214226800b006964f6dcd73mr3031430qvb.44.1711542332562;
        Wed, 27 Mar 2024 05:25:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:dc2:b0:696:8a5d:3e4d with SMTP id
 2-20020a0562140dc200b006968a5d3e4dls9685qvt.1.-pod-prod-06-us; Wed, 27 Mar
 2024 05:25:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/m069jYrWIrOQsvjgAaD5bq48FOWlVQFcSi8PvTv2T5BWLd360fNldXHnCHjrsZQayOtDqNOV1MJSezYd9DUFo+fgmd9GbzD32Q==
X-Received: by 2002:a05:6122:362b:b0:4d8:7b33:c624 with SMTP id du11-20020a056122362b00b004d87b33c624mr2334298vkb.0.1711542331640;
        Wed, 27 Mar 2024 05:25:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711542331; cv=none;
        d=google.com; s=arc-20160816;
        b=0UWWJtNbdgV/ml4yrmQvrh33Ytp4byuG8RhGLOqEAUuxDhAR2iN9Z2m0bt/ywuPYvL
         NWhU+IVUaxQ/n16pCGk71hPinmcr5oWD1kYQZQN5r6peJfgmzc/zGuq5Y9Ai79F6gVZY
         BjIyai7Y1U5prDUYHGrEWjNZMuCGyXoIQ3YmMT3vmGJOXeajbyDczvWzGfkbic9ABD+1
         EaS3lzON1WISYDP5x6WOy1OvU19bL2t3ImqrDXXT6Ibsl1qs3xBJFchS8QXfExpG8nJN
         yjdaDofeoV77RJLEFj0GuTNAvSCW7fLhczjBVlZhqW2E+wejtTGG+pzQ0Bd6cttswyxz
         kcSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=kuFgGPxHH8PsnTJyUHYZC6HdvYMrswroVqiPdiRbgVM=;
        fh=qBkFaWQOrnxqs/N6JdyMIIszgBjtt2b4Sv8dQ0VMb1U=;
        b=MF9V2ge8L3tNytlpuTRe/JsP7L8WN0JPrEIcfMm3d5uq7p97IcySH6DTmRIarMGVGz
         8S4IP1xBEKqyXHSbjVo12hAi2OTBcQtX/AVSoL6M7lWuHQl8AFNzHX5QYnOahk8A8u+j
         js8rGLK841bgoEO11qIKRzz8SYDgV2ndFlN5VrsXx0Ri5QkZHMwx6ahoKe0vXEYUKUje
         BrIOcO/NPDKyve4206f87YKP+N6W61Qd2EHLrp/3lNkSalosQN6HtLOjqL4OMVShiTTt
         KmirVmZyiZD3PkhTqoes2BZr2oK3+07k+572AEztnDcT5RwFpRjThGyU5cpspXuLO+ph
         mkYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=quj1LnWo;
       spf=pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id n190-20020a1fd6c7000000b004d3c4a37c63si1294116vkg.2.2024.03.27.05.25.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Mar 2024 05:25:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 2751861515;
	Wed, 27 Mar 2024 12:25:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id AEF1DC433F1;
	Wed, 27 Mar 2024 12:25:29 +0000 (UTC)
From: Sasha Levin <sashal@kernel.org>
To: stable@vger.kernel.org,
	arnd@arndb.de
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Marco Elver <elver@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: FAILED: Patch "kasan/test: avoid gcc warning for intentional overflow" failed to apply to 4.19-stable tree
Date: Wed, 27 Mar 2024 08:25:28 -0400
Message-ID: <20240327122528.2840267-1-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Patchwork-Hint: ignore
X-stable: review
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=quj1LnWo;       spf=pass
 (google.com: domain of sashal@kernel.org designates 2604:1380:4641:c500::1 as
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

The patch below does not apply to the 4.19-stable tree.
If someone wants it applied there, or to any other stable or longterm
tree, then please email the backport, including the original git commit
id to <stable@vger.kernel.org>.

Thanks,
Sasha

------------------ original commit in Linus's tree ------------------

From e10aea105e9ed14b62a11844fec6aaa87c6935a3 Mon Sep 17 00:00:00 2001
From: Arnd Bergmann <arnd@arndb.de>
Date: Mon, 12 Feb 2024 12:15:52 +0100
Subject: [PATCH] kasan/test: avoid gcc warning for intentional overflow

The out-of-bounds test allocates an object that is three bytes too short
in order to validate the bounds checking.  Starting with gcc-14, this
causes a compile-time warning as gcc has grown smart enough to understand
the sizeof() logic:

mm/kasan/kasan_test.c: In function 'kmalloc_oob_16':
mm/kasan/kasan_test.c:443:14: error: allocation of insufficient size '13' for type 'struct <anonymous>' with size '16' [-Werror=alloc-size]
  443 |         ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
      |              ^

Hide the actual computation behind a RELOC_HIDE() that ensures
the compiler misses the intentional bug.

Link: https://lkml.kernel.org/r/20240212111609.869266-1-arnd@kernel.org
Fixes: 3f15801cdc23 ("lib: add kasan test module")
Signed-off-by: Arnd Bergmann <arnd@arndb.de>
Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Alexander Potapenko <glider@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: Arnd Bergmann <arnd@arndb.de>
Cc: Dmitry Vyukov <dvyukov@google.com>
Cc: Marco Elver <elver@google.com>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: <stable@vger.kernel.org>
Signed-off-by: Andrew Morton <akpm@linux-foundation.org>
---
 mm/kasan/kasan_test.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/mm/kasan/kasan_test.c b/mm/kasan/kasan_test.c
index 318d9cec111aa..2d8ae4fbe63bb 100644
--- a/mm/kasan/kasan_test.c
+++ b/mm/kasan/kasan_test.c
@@ -440,7 +440,8 @@ static void kmalloc_oob_16(struct kunit *test)
 	/* This test is specifically crafted for the generic mode. */
 	KASAN_TEST_NEEDS_CONFIG_ON(test, CONFIG_KASAN_GENERIC);
 
-	ptr1 = kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL);
+	/* RELOC_HIDE to prevent gcc from warning about short alloc */
+	ptr1 = RELOC_HIDE(kmalloc(sizeof(*ptr1) - 3, GFP_KERNEL), 0);
 	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ptr1);
 
 	ptr2 = kmalloc(sizeof(*ptr2), GFP_KERNEL);
-- 
2.43.0




-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240327122528.2840267-1-sashal%40kernel.org.
