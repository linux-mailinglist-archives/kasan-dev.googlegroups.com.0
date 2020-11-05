Return-Path: <kasan-dev+bncBDX4HWEMTEBRBRECRX6QKGQEWSYEF7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4158B2A7383
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:03:17 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id x23sf149867ooq.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:03:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534596; cv=pass;
        d=google.com; s=arc-20160816;
        b=TY+bnYd2BLjtmN1eT5QePB7EtM99BzqnC1NqGuGvUR1zqw0NdMEQ671dtbWx8FN89i
         DWX7XYZWyhUKWEeYmeYFpV0GIZZhtobdALNdcnhjk9PYk4+B4rHcBPWpbzqdJNf7qf/0
         dPiLnI9p4+cz8kwajtjYnY75iJ0YsDEmJjy0qMCiD0c1OyVWWtyW7YrbdIqjQwfDBgOm
         IzLu6vfNZ56lIOsPtLXWY3mhavCoEPz+oL0QPWLxg5dgzGnSl0aaWd7yXMwJToxvW8GR
         VbPQKps2CsZ+zNjMSo6g0P6a8YB0hHDeEpE1DfTXEG4S0cG+78lT0kaffhF3HqdRXmwe
         XieA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=0gRSk/WY9BfShEItsLS8PHOgP34z/2+0gNPXg6Gpyrk=;
        b=qtd9dMK9JeiHNKer2NH8vypYepN7FJQRHRrOCJYQjVPIA/Ze1DJusvtP3T250aKNHi
         vIctbEBEhfvtTSMIOwbe3aYwDII+FcP8YVVOPl2M11vo1jNiUWil/G2pSaEaJ2zrDq9p
         C+EAQ7u/PMTXoXmsZKqgheKLJMTa4g9xZB0FAhtxNkg7DUNnvcAjrByobcqGN0H669ro
         3w+Xf0DSiHcZAOgMjWNF1e/lidLlwFRckrQ4c3upWMWINEALSAAMwOWvg4bSE+3bQOLL
         PhW9ttfuqng3l3lKTADGRaO1kj6Mg+4Rpv5yeaIbU/T8yl3VLZRMK5q7Po9iko+N94z0
         8hVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iKpb0OkO;
       spf=pass (google.com: domain of 3q0gjxwokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Q0GjXwoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=0gRSk/WY9BfShEItsLS8PHOgP34z/2+0gNPXg6Gpyrk=;
        b=hBqkTyAf9JegG2/oh2HFQe4lAh5HY4DeswxQ7HbiJk2yJIOzKyIZuuTbK0n254kSja
         yL1RF43Pb8oSEKm4NkOth9cCEt9mAxcRF82bEP8UnCL0qvnri6WQSVS19WBOJDYf7rfS
         kyih51M8Gdo5nkwnp2BEO4ow98Jtid16uCvxNXpRhysEndWUcbOq+kAwAr+xebCXd6cW
         u/qhcPTd1GaPq4mFx7bbH8ElMPBn4+HjNNWXQw9ED4GYxDDSYkp4sSrxgi+qh2Xrnm2j
         CpFcWrGoiQahF8erc6zXINqYFwqVUx3MIoqJ/R1Ll34Fzw46kz7a1XIUeMMVEVZkBCbj
         /KGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=0gRSk/WY9BfShEItsLS8PHOgP34z/2+0gNPXg6Gpyrk=;
        b=HG2FjVgVLO545jrXF6SnEpEFSIJZBQqWt3FKNz6oQ/dFTCvIX9xmUAxWYOAOwAIE1N
         ZO3vBjW0r81T+tBGwexE2cBPnfzi0W5YkHXzslOgH38vFXddXXMQYh3WJ5lh4g3UaXPL
         WA0cKeCugr+c9RwaK6cnq8Uw2NbER7edgMTUjiOqSpuy2m9jyNO0ppAFFt/xsHIr1A1b
         7bOy2U1rb8ytwt2FmWuq2t3eI1LipaxWWMErtojoi9AxPmnmW61vYUOKJtm+XJEae3DQ
         K5ln5Tcs7w/PEogUZjPyNMFCpHzWEZpq9zbweUFeAmYZuY2SGBE7Jc8Xt7HLGsGA/CZZ
         UTEQ==
X-Gm-Message-State: AOAM5327aKLbY6B7/Kp7w2gHlD47nPMoobMHPMWoZGAGm9dlQb8zi1KY
	0IU57F7xC+4PwrPEfcqg7Mk=
X-Google-Smtp-Source: ABdhPJxf/ToxLqrVcADQ0+Mpe/ADBzi4oNO6VHCgbGe9sATT90z9lfk/wiKU2kkvq5PRms6ko76jLw==
X-Received: by 2002:a9d:65d7:: with SMTP id z23mr149486oth.131.1604534596258;
        Wed, 04 Nov 2020 16:03:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4713:: with SMTP id u19ls1029252oia.0.gmail; Wed, 04 Nov
 2020 16:03:15 -0800 (PST)
X-Received: by 2002:aca:3fc4:: with SMTP id m187mr21377oia.20.1604534595827;
        Wed, 04 Nov 2020 16:03:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534595; cv=none;
        d=google.com; s=arc-20160816;
        b=DHS6j3WyeMqQfrX3vIA2EM+//PaIBVhkrOZPppMfiEtuAuYdAeOpNcpTdeKqEN2Gy+
         TZ1nuFEw9uS5z4zlrIVy65uxr/FqM5eIgXHSDz/8Pz/IM4DuR67vZlI3NteYUREfiCGH
         evUU5j7XrBiik0LQtl/tu2GYXhkBf3cnaWyvK9mV8k1T/iqP0ycvA64jdu2YzxSRhVeh
         U1n72qw1q4t6O889uqntZMW+t+neaYEsMNQXV0+wy+oAXyuUDeduOSn2jnMTUqkXp9m+
         94bP3dI86qchyKmOisyJhUyOvfJ0XdetLlvGSNgnStznSzqWpCfOzq3NgOKkKtPjRUek
         XIjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Z3EYeS+tIqBFVXo6hPJUkFm8u6eCOLhA7qycqAqlcHg=;
        b=BMcTG9DGmwBPVEubXcKNoNYdD2FQUNXe18g3vCj/Z6u4EGJJOvrieCp4avzlCFOO5f
         CHzONn4izFO+6zI0j2eXJkrTScHlkWO6UM+VlUdFFFcwWirAb0ZCu1C2qh2cFplX3vDT
         Z9NIKbRCs5K1rLo6HYPWF7Hhh1EMRqm/kMS0O++9O8n+NmDY+AZuv2qdHO2JiYM4GOue
         UHZqXBFKZ9CaPU91flXFHHKnwaNb3auowj97K7j6XstH9vR92lzNutuQcYNg5vgQXo4s
         b2vjbNbMsXPIhD034OgN1nNoQqnBibvyaDJ1BxOo9iFPKmRlaqXXLfjQprlKppb3ANoR
         +8SQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=iKpb0OkO;
       spf=pass (google.com: domain of 3q0gjxwokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Q0GjXwoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id v11si320865oiv.0.2020.11.04.16.03.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:03:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3q0gjxwokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i39so138429qtb.1
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:03:15 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f7cb:: with SMTP id
 f11mr315849qvo.34.1604534595295; Wed, 04 Nov 2020 16:03:15 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:27 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <1f2309b6c4aa9554b298e82bd830aca7dc6877c3.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 17/20] kasan: clarify comment in __kasan_kfree_large
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=iKpb0OkO;       spf=pass
 (google.com: domain of 3q0gjxwokcvyyb1f2m8bj94cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Q0GjXwoKCVYyB1F2M8BJ94CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--andreyknvl.bounces.google.com;
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

Currently it says that the memory gets poisoned by page_alloc code.
Clarify this by mentioning the specific callback that poisons the
memory.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I1334dffb69b87d7986fab88a1a039cc3ea764725
---
 mm/kasan/common.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 40ff3ce07a76..4360292ad7f3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -436,5 +436,5 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
 		kasan_report_invalid_free(ptr, ip);
-	/* The object will be poisoned by page_alloc. */
+	/* The object will be poisoned by kasan_free_pages(). */
 }
-- 
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1f2309b6c4aa9554b298e82bd830aca7dc6877c3.1604534322.git.andreyknvl%40google.com.
