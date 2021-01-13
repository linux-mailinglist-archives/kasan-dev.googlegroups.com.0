Return-Path: <kasan-dev+bncBDX4HWEMTEBRBXFT7T7QKGQE6NU43IQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id 30B0E2F4F6B
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:03:41 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id cq17sf1076826edb.17
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:03:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610553821; cv=pass;
        d=google.com; s=arc-20160816;
        b=UoGzmvpM4OytaRkPWFmYFSCA3bYjDh3AJXlcbTLupCyA18q4llN49h/OZhTd/GYA7Q
         UTE0YCRuQXHR1zZlark/Ec8isi8mNfHFsqk1xDe1ips0XenixqLrYGacBsFITzRUWzge
         HVkSHyd61I+/PLWDAjVwpuMVJ1Mdr+eB5oUcciuHXJs1W0tDBupl7tn8Mp67BNwZyfRp
         psyILx5aRQt6GwuubHYNMCADgu8oYTLMLWSb8UQTlt4gG30OsNduk4cupoKKQHsyDzuA
         jECkVuNO8Sna49uZ4AYUGnQcPFUOahJaD/TlJyleivkK4DoCrBUdiJTp/c794DnCTfvd
         qOEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=b8moC4qJBQtrxbxkSRHfEYl/JJq8PgKqYxBGIiR1z0k=;
        b=0/EeLAgdlLLj7JqK9xFSw7NbXDB4Uqf19Ndqz6EdaRLrnitvt0BJ3ySEhZ68TgZy7C
         bZ4k69usPFLWvwbQl061bJTVZFo/52bOAN6pXrhmiXq4kqYP5YkVx3RYe8RmNzGL9vqW
         gG1pI1VxtJQRuIjLTGBB2i9y4cWWrSO5sIVfi0RCTkxBnfvk2uD3h+2ZNyrGhSimaeAs
         ptHk0zEf67Go2rnpf3osqC8HqZED78qoZzaXr6kc9UF0J0dWDK0AI1uxsGywZyJZLP1k
         lMbFPBtpR9eULXHbAPpwGvZ3NNrggF8uo1PQOxdQRmvYXHGb9Lpdly6a9pIJhMBBw3HO
         fpsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CDyrzARr;
       spf=pass (google.com: domain of 32xn_xwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=32xn_XwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=b8moC4qJBQtrxbxkSRHfEYl/JJq8PgKqYxBGIiR1z0k=;
        b=C+nfGguOI61Gf2/VgooBrEP9qOXCVGCuYerKY0rnNmHoePaBI1fypJ+r/N/NpgPfP6
         VJfNcyvR2Wn9YlJLu/87/ZeA7cZRsuNOqSZO4v4ny/EPwYrPV0A0jJtCRPLQR0H1QJ7o
         pV2yTPpHNkdWa94SPwsczcCDfimebXhDb/W5lAobDwwwrftrLwqBzlFibNxfa6UNBZpn
         7NoFymnri58wuBZO/iEgfF7TQPuy14S50+6sYPvG2CvAS8Ea9yYiTlROQgJrYFomNzAO
         8vugCRH6GuzGKlLQnor59MPxY83L8wJ8swLUKNtlWvjXCc9WUgVvwDBnEFiZhwWcA13I
         VWBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=b8moC4qJBQtrxbxkSRHfEYl/JJq8PgKqYxBGIiR1z0k=;
        b=LqpgfpsKtfz7qd//K3Nzd8bThJoPzYwgK+8xu6xiEQWKoJzkaH4bkgmcRSbuHnE8E+
         gnH9johuKKlr9HRJkRHbHZo3htRwPVUzcMOkU2+B5xJV7myM+sxf/SfLvphIFjSvkwql
         F2qM7DDQ0iFEouTLzrhf1MW3ihVHSPR3K68L7XhqNUBxUAGVL8xS4OFCb/7uXZUWM+Rv
         gm/+E18t3jZ0er/CZx5iV6NMZrQy2mlCCSAwLg7qSXXjDrVsTCb4hvHkzqgGn3WBHWM5
         ROBJg0vsXKMnxBpqUcdU7ZdR9bq5ED3EQgXLtbhV/SMIn9P4cMiRa89UXcxkxWwp4z7D
         wlDQ==
X-Gm-Message-State: AOAM532Bi5dnzpDeVeQ6mCp717mPMG6fwTEShTP4DFCL1i+5f704b7L0
	bLQo06aduQ9L6TQUJNMrkOo=
X-Google-Smtp-Source: ABdhPJz2XnorDpZMiZlQhAcp6nLhH+mFTz/b5LpKWCN7FPIRpKmThoQWuVEYb/yd8oqKGYepttWJjw==
X-Received: by 2002:a17:906:4a14:: with SMTP id w20mr2163139eju.192.1610553820912;
        Wed, 13 Jan 2021 08:03:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:fd15:: with SMTP id i21ls3114977eds.1.gmail; Wed, 13 Jan
 2021 08:03:40 -0800 (PST)
X-Received: by 2002:aa7:d0c5:: with SMTP id u5mr2272619edo.46.1610553819981;
        Wed, 13 Jan 2021 08:03:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610553819; cv=none;
        d=google.com; s=arc-20160816;
        b=j0tNmUFyfCuEs8eW+fkP7lTt5NdmJHTOjnzk6ZCoiKGyd3JMbR3l7n61uEN5PnYskc
         tTrxNan85fN6xQLG1fCIFjh9Ajd9NTmTdozP+AuPqmvSbOFwe5YB81TCzM0L6eURbtk3
         oC1CsPOr5KCTDQMpgiFD4wHYASfemhY1XVUKHhXPT0uLf8HFFnEhZfLmvE3jwSl6xhVp
         loz/ySU+3Ora/Wxc2mj7SV1sXRl2GNC38w9YPx9f7HRN4AKhwm5W1yDU61NSbbUkQNRh
         7SQmYNzVN3PiiLP95aWvN8a3dnE5BCLNkySZnBri4rAs98PCcpvOPrqBoOV4VC21oJc2
         O1jg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TionkskhfJFUpeI/OKXUNvEID4OHoy9zg6Ffh7JmH8U=;
        b=KVRq18NmF1VtW74MqOFFbMLV/wu3k7eLOtg3lBZEUZ5LjEvhI6Rbnt/B9cIedaCYld
         eQkcH3B8hL2Z3RFyxEwpdv/GwJzFjt6MT7/q9kXohmLu5/G/bEZNHSq30sXHyCns1AED
         7iOsDxK95QX2iH0uDxegqMJ590Uvx/k6ZXUrXp+Ed/kNQO8LT6M1/+uT+OBIir8tAXcT
         G/lN43gNnKmZE0nsnkJzAg0fySa3++9UC5ND78RsSBS7U+PeSA+uIwu0vgsaZD1z3Oj+
         cKU8xbz+FxJl6VXC/bAavJX18FWlGhAN/s1SYJ+WoJzR1IlHyk2Aj0cdoyj2y4RskwBh
         XIVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CDyrzARr;
       spf=pass (google.com: domain of 32xn_xwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=32xn_XwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id cc25si83781edb.2.2021.01.13.08.03.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:03:39 -0800 (PST)
Received-SPF: pass (google.com: domain of 32xn_xwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id g16so1176511wrv.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:03:39 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:6000:222:: with SMTP id
 l2mr3287308wrz.392.1610553819541; Wed, 13 Jan 2021 08:03:39 -0800 (PST)
Date: Wed, 13 Jan 2021 17:03:30 +0100
In-Reply-To: <cover.1610553773.git.andreyknvl@google.com>
Message-Id: <1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610553773.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH 2/2] kasan, arm64: fix pointer tags in KASAN reports
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CDyrzARr;       spf=pass
 (google.com: domain of 32xn_xwokcris5v9wg25d3y66y3w.u642sas5-vwdy66y3wy96c7a.u64@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=32xn_XwoKCRIs5v9wG25D3y66y3w.u642sAs5-vwDy66y3wy96C7A.u64@flex--andreyknvl.bounces.google.com;
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

As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
that is passed to report_tag_fault has pointer tags in the format of 0x0X,
while KASAN uses 0xFX format (note the difference in the top 4 bits).

Fix up the pointer tag before calling kasan_report.

Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649
Fixes: dceec3ff7807 ("arm64: expose FAR_EL1 tag bits in siginfo")
Fixes: 4291e9ee6189 ("kasan, arm64: print report from tag fault handler")
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/mm/fault.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 3c40da479899..a218f6f2fdc8 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -304,6 +304,8 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
 {
 	bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
 
+	/* The format of KASAN tags is 0xF<x>. */
+	addr |= (0xF0UL << MTE_TAG_SHIFT);
 	/*
 	 * SAS bits aren't set for all faults reported in EL1, so we can't
 	 * find out access size.
-- 
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1965508bcbec62699715d32bef91628ef55b4b44.1610553774.git.andreyknvl%40google.com.
