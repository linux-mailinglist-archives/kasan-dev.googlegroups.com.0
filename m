Return-Path: <kasan-dev+bncBC5JXFXXVEGRBUU6SCYAMGQEFQQU7VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 772FF88DF23
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 13:21:40 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1dee0dd9193sf1314235ad.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Mar 2024 05:21:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1711542099; cv=pass;
        d=google.com; s=arc-20160816;
        b=s6vmuFm0Kpp8a0cFRSEO4YVApcWZClCPp/DjDpjcVsxXdSAo9cNIIy/l71gmmBQD1G
         3Q7yrxb4m+NMlp5JzhIA+2Uq0352xqIUr8OFKtfCB1KrRjimo/NigjDFB3//LgGIm4+r
         hAnGargQmJblC4GloKGLXzCpjM8V6ThwNReNyQHdB6FW60P7SKD74wPAKdagxx4b54G8
         SG87BxXAJ62q6gjuHhl7gy9oNRgpZdA06ZY0DWVLFvMiF3hz5OadHJd3M3G+7rufi1Ar
         GZ1pdXat+dX13zesk+/uCIVUCwOjNJOxHAHQ06qnB+yQkUJQqmkMMIYl+luLp+c1Cs0t
         KirQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=TTY0nfYtugNJUMJfjGVcJ5uwxtDKbtZt2/V9AXZ0/Fw=;
        fh=t3OTMV1iOU6Oc9RyJlfCLBrsuzJbDOJ4U4w+hzKREeQ=;
        b=D3VTAiiyUz5puxXjqduSxTIn2gRjVuXSpvM7cJJwjSP8MzYSTKOuIR8Dfd4zjTH7NN
         RhnKeDCkdctXW5PbNV0GIV8/BWjGfZ/R/nlF1oF57zMtjKF8kMv/bc9MGMwtfAmRB9qR
         JE8qy1mhBXKW+pxBsPwJW41eLfPz0YH8TzQ5nE19K4UJOavsVL7wAX/1RM2sKwN9alLD
         OTKczFWLZt2qKsYzYs68rHJA2flx7pgQ2aUbypK/8kxt5DKSL4mCfv8+ssmsYYnJbVFT
         5ahlsj4yQp155i/QgtQ7S3rqyf//fRJxAUwuhdvJx3ygUlzN36VOhYpTkfFV1Hblm+k8
         k8cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KB2em1D0;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1711542099; x=1712146899; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TTY0nfYtugNJUMJfjGVcJ5uwxtDKbtZt2/V9AXZ0/Fw=;
        b=oEH966RRNioheH6d1wU3a5wwoi7ym4mJGDUhd6xhhSdNcrZEHDrizSHhprJFlDTHO1
         BhLA+4lsv3TDnInPQzBTJSXyyidKRCvYu8W1NfIa6pjV+5dhJ2POWzKljISFWieOLxbj
         SYY0L0/1a9zsmFeyRNYLnJX8+2WB1MzrAK7ifZcO+rvW4/QOb0F00kP9b2UADZZ9WU44
         iGlyzDTYdlX5TmkT+u8mh6eusIcUWooXUV/xqoL2+R33Gr469dBqV2WKL3Eq9yxErqW3
         zxaSpJMFGH1PKyDtqOzGmN9KczEQTSEl7e7FkYNA4Lexh7aSvvqZz8mZa22WcnCQsYbk
         NQ3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1711542099; x=1712146899;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TTY0nfYtugNJUMJfjGVcJ5uwxtDKbtZt2/V9AXZ0/Fw=;
        b=PUqLZwcaT5L8ikQFEfZwffVgpT06M/hBpVFKFa/2V86QNTCT/5rJwEL/nUcSDCDoKV
         aHy543q/xBtsGTJXoiDxPsnSctIF7XV4ISAJhFfkKTbxAapTBZ/L2FYCKFcr8rKIL1W1
         gSRQqxolChBKDlcOCQzxkulrziTB+qflQ2yfnfsr5KWaWVzpXZGOpZRiCZVMXAOtgWW7
         pjgMz8RybbzTOFWqX5dBoaGfEf/VY4PeXCkNIj3h8TP1YU4s15nZ3fH2c+E7hRzQbMkz
         SY4+JU30BKnlqQXpS9jYYIaEmygt3LdqB2HSRz2XW7B/IwCEEQQTB7eNCFhXPd9c57vP
         bHBw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWyFxdF7G3d5PRL2O2zgE1FwIKqIURrcl870HrMjICz3jBDeiy/9Ec7MLE53BrmZgsweDDm26yGz+ZpI/GyPui9Vl0wbo2GGA==
X-Gm-Message-State: AOJu0Ywa3XDjE74KtaTXTfKUUdULzdfS1CSsZ4XM7bYkYNvpBpCSItoZ
	2RneF/lgCuDX32QFRKFiYXMb/NJYJ0StZBT+g2P4MxcHMu6fgTZ1
X-Google-Smtp-Source: AGHT+IFye0vCOEdgk5UCgAoOK1fMYMeIdv4gFtveqVY17BDTHyAVTmP0JGN+sgKMTPYXdNyZE+puWg==
X-Received: by 2002:a17:902:f603:b0:1e0:a86c:9736 with SMTP id n3-20020a170902f60300b001e0a86c9736mr152464plg.20.1711542098725;
        Wed, 27 Mar 2024 05:21:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:6708:b0:6ea:88c6:1f11 with SMTP id
 hm8-20020a056a00670800b006ea88c61f11ls2087610pfb.2.-pod-prod-06-us; Wed, 27
 Mar 2024 05:21:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWwcTM0UmjBGJOnMBRZIYjdk3pM0+LwR7xzQQhMizlrde1tjTJZzYCGMVvM1+oTS+UDj0LCdnXQ5qtJroXvPYe3y1DUm/90OaXpQA==
X-Received: by 2002:a05:6a00:238c:b0:6e3:c568:47aa with SMTP id f12-20020a056a00238c00b006e3c56847aamr3148019pfc.24.1711542097438;
        Wed, 27 Mar 2024 05:21:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1711542097; cv=none;
        d=google.com; s=arc-20160816;
        b=eqM5mEyY5dj3VtxrOSs1C7OOq1+eo5BIgeWBk2g+Yb1yfVD5xx/5tZv6+Hvx98/dMw
         w0u18+mCGsLw+I+G1RAvgSuY5EkfSrAjUkTkgTl996VFEsvlEoM84PJmUd8pQqKT58LS
         BnExka1Kixd/5Ri4V9zhzmLkM4JXjYQczoW6Avsz9mfzeTLTpx5kUz+yJTmTLK0TEODe
         vsHdtP3HPFGa5rpRDcgbUK+VEGGWf9zIRiOXJq1wHPE8IDu+v9KzTJn59YQe3N3x7PhM
         YnmeLUX2e9qNwN6t0ZamLJiwq4qsEsPo2W9J9jDwt94n7jGQBBA49ayOdEwf1UEQ1P2O
         OaNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=DvxeNx817YfSAiEoXBhONny+Aq+9e2NUTQuEJP520p0=;
        fh=qBkFaWQOrnxqs/N6JdyMIIszgBjtt2b4Sv8dQ0VMb1U=;
        b=E8MO6Ik4anob7V1P8VPW7hj97E9d+WAY4Lzp+yR6cReHSyLifXkY0eH/eM6klypX8R
         lmgWp7BojXLpVeGYluinsMTrX60hlgOG4YNo+pFOS3yIt+wE+eIIziJbn/qa/eX5M5j2
         8qSvAWqbpB00vbZSx+uYzhCt+aIZ2SO5hwnKcup60bG879lFeQ2fE8/blssMf6nF5n5A
         OJ/TqJk8EYIC/F9gYFV0Fzf5mEetJ95xoZVczR0zmekN1gmur+5uivxFwFz5h5uXe88a
         glZv1B6/kPYg43IibV08KtqZ+JWgxu1S0i+c0orkEP15p1KYskXZE+XIsEqYSfKp/kyd
         foig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=KB2em1D0;
       spf=pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=sashal@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id z2-20020a626502000000b006eac41e9673si263863pfb.2.2024.03.27.05.21.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Mar 2024 05:21:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id B0235CE0E36;
	Wed, 27 Mar 2024 12:21:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1389AC433F1;
	Wed, 27 Mar 2024 12:21:33 +0000 (UTC)
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
Subject: FAILED: Patch "kasan/test: avoid gcc warning for intentional overflow" failed to apply to 5.4-stable tree
Date: Wed, 27 Mar 2024 08:21:32 -0400
Message-ID: <20240327122133.2836943-1-sashal@kernel.org>
X-Mailer: git-send-email 2.43.0
MIME-Version: 1.0
X-Patchwork-Hint: ignore
X-stable: review
X-Original-Sender: sashal@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=KB2em1D0;       spf=pass
 (google.com: domain of sashal@kernel.org designates 145.40.73.55 as permitted
 sender) smtp.mailfrom=sashal@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

The patch below does not apply to the 5.4-stable tree.
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240327122133.2836943-1-sashal%40kernel.org.
