Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB6OFUTCAMGQETZDYGIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33a.google.com (mail-ot1-x33a.google.com [IPv6:2607:f8b0:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id B6F42B1538F
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:31 +0200 (CEST)
Received: by mail-ot1-x33a.google.com with SMTP id 46e09a7af769-73c88fe25a6sf3031003a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817850; cv=pass;
        d=google.com; s=arc-20240605;
        b=Yo0ESNQuS4eREB7HsT9VJZzBUcF4HGTn1k9PT5UyxzrMLq/pfQL54LzFxR/T44Cvdb
         yMlKTNTiPgWN1Hm7haOfpufcHoYbFFKdxmOelu3sypaV1rgQ+8L9CGRXOZAtV8LMC4fS
         U8adSG2HNV/pKH81KRugLcc7Je4+Q/hczrIMwZPihLpHbkym+ANKgTJo0JJIPhmIOjMH
         IaFBag6HWoV1VVOUfWyCqxjBJSXb8g6rw/MT1ssQhYbd2pec6GQ0oILF4IW4ggTzpMCR
         z1tNm/ngV9eOqnZG7UH9KNmPPk+Jv5cLfcBrO0SnUxGNLHBCnx2jlYF9iXayDYLXlpbT
         lcXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=H82UoKx+9VY5qq0/V9PL/UNL5hT+4M2RGcbPJEJJ0yQ=;
        fh=XGhe7lheinxJyoB2NrGOcM9ybWEZkGaQ3PR4CKGX8y4=;
        b=R5Mt+jnCAq4MdFAIYvHRrCQCJt/+O6R/x8c/a8OxY4vWKfCjh4Pc2sj08inIyqh09b
         MGHnlkKpEHbrXhxxrBW86GLhi+qXpQtDyDVRF3OwfgwSY38i0D/E5nigh3ZnbsiH7QUD
         1uDQ/YW3H5cCRS19XDnw8PhK0zqv7vt2W+sPKq8I4f8UqIrPQpIoVE7NKUjU8P6w43tz
         w2IjrO2TxMWnS9fFXYD8/2hPa8znLHanql8NFZeX2V35K1ZF0Ir0A78T159GV3pz4WUj
         p2ELlYTVzUwC6g3g6+39O4AQ0ORfdCn+SAblHPFWYnNQa7rLcsZXqKCUVcG7eLDjDn/A
         wSKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pDFMDBLV;
       spf=pass (google.com: domain of 39ykjaagkcawymduqhuosaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=39yKJaAgKCawYMdUQhUOSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817850; x=1754422650; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=H82UoKx+9VY5qq0/V9PL/UNL5hT+4M2RGcbPJEJJ0yQ=;
        b=PlCJYaNZ7O8ydMLm3bpwcEQyMJY2vDSMJDNxAhqDdT8JACU3iquGOLFS4YE5cJ+jAO
         Im/Tpmf0uJo97cMDph5TYHv315bzqrwGLHDEuKJegoQh1BTabSBKcJMBNcP56QbENMec
         iRLjPM7S5+oeskKRHqgQTMBn9jjfJQvWG8WYyDjsi3FmlL8tDg5Gqqn8AzM7rVvRvUbE
         Hbw8EjsZGIFBVwdTLGdb3nNqDSECNQX+RXgr+w58ZPuybVCAI1dVFkCnfUf3E0J0u0Wh
         E8gNLzhMgLK1ShULNZVU+os/RkVDBRe20OljM1Ud3qI9X0QLmPQy42DfjF5dR9jDSDVn
         fODg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817850; x=1754422650;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=H82UoKx+9VY5qq0/V9PL/UNL5hT+4M2RGcbPJEJJ0yQ=;
        b=oAIN2o7TD/T5RLnSDgiAFRYELWI8WMHiunk4GpQvL3uc2WpTyEThz2VIpGj1WXU198
         JZA6wbtYvBDqkU7mztHNkOPAfgRnM3QmwZWwuPH2OuiAdnaRGMOB0zXZFLylbCHhtw+O
         MaEYsbREJR3BbRnYVMsEqxcZv8Z51Kenb8VmAnWMDz1K13zeAHnd9webevwTZopaVxvV
         Ub51iP7OLuXn5E6GjACnU5DPCpN9K2AlTSTUC4BsEEkW9dvXBA5sm4Tmoa9Pssc46m3p
         8Zh9us9TmHYrSILKjUBfabkZEOWh1WJtqNOEU9B4sYG8LT5bPfIgc/R61p6AYMTqmtBp
         F23g==
X-Forwarded-Encrypted: i=2; AJvYcCXFIORV7Ww7ScJozXGF8fJlJ9ffpj7LFVyuZIwj9pEERc6WBGmZdsyyVIpQTGAEZ8DFBAabwA==@lfdr.de
X-Gm-Message-State: AOJu0YwRgvJoEOTqo2bmsgWCPBvxNRRuaOh5GgAEUIMHV280DgeBh0jV
	US5rdmMzTD5zXN/JvzblwVcoNiYgzVaP+Y4SvX32+B0X5wxp3BBt7GpJ
X-Google-Smtp-Source: AGHT+IERvaQ/8/oiXYkEzZNnMbCm4qyAilkIiri1MFlb5HOO2vlc0+hDuCAfkIlrXl3WMvY7SahI0A==
X-Received: by 2002:a05:6820:998:b0:615:7f6b:30e8 with SMTP id 006d021491bc7-6195d2a25a5mr542177eaf.5.1753817850106;
        Tue, 29 Jul 2025 12:37:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcRdAqxeImCCu34lA5LRz3K69npLJpDlarESAMNqnUP+A==
Received: by 2002:a05:6820:5181:b0:615:eae6:7d9c with SMTP id
 006d021491bc7-618fa26e096ls777286eaf.2.-pod-prod-04-us; Tue, 29 Jul 2025
 12:37:28 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXnMFilWpXsBolz3OKZtXmMjTlqtZatsb+U2nEkwykoXJ82Zk6gM4SNNYpxls9tcFTW7x3hnKRwVAA=@googlegroups.com
X-Received: by 2002:a05:6820:218:b0:615:b2c9:7ffd with SMTP id 006d021491bc7-6195cf925ccmr636900eaf.0.1753817848408;
        Tue, 29 Jul 2025 12:37:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817848; cv=none;
        d=google.com; s=arc-20240605;
        b=OGEWOHnchSAmLdiwLk/tdt/IufQMPXsmiXB65BXdCLpIRq5vRoPCwAYeqm9oFWQk//
         8qFqKkhKD+HJsUrgy+NFIh2rnt4Y1kMW7tHqtL3hfL1WoWF2UHpAPkJPErOBDRHDtQFu
         asEv3vD+Xe5iXE4Q6aCoad2atfArNcAzJAt5RznyOB4RAr9bbJw+sMqKWPi89T5lg49U
         Dq1cWS6XjicboK8bOhO+AouoRYJ+qcqnEYdekMAtd6bLoW9Ip2A9GqyNH0ApSa6L9tuJ
         F5BTpoG5WU8bbCP1VijDa4szEZAAuRQu3QwB5163XCJe6rYMNzNMHmivuX14yPFiS/JD
         AG4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Z1gbKWHstsqjpQUrskmEj35TBdlQ+Ks8m0MsBKhxomQ=;
        fh=BxKB9xSa2Pl6M2Dm7EyC/pPCaAm5OhiRHAQO2Nbxt40=;
        b=RPLOzc2PwIkK90cMSd2rAh1RxQYp86c4AFu1RU2vm+4CKSOYNd2hb3rYY9RdYyIa76
         4hJWtuIOSaQBdwQzetnNAj0i9H3bO7uqtszwrFD8MZQ7DdIAg/9bnnPiyzxlqp2l3+Bv
         PAaQ+BEIsLCmR938TwcUtClFWzi4PLhvd7tzfHkENpgmbS4uBh7N7W1Riql8Kf6wzru/
         gHrNhUSrIUcSBdopKhV6CerRRNArGY4RLc8mU03/4v5FvwPj7IeVhjwh4ryHElSVJOpq
         lRK+xCbwr2OXAOgK7R6p+J1RahrxLYMsnt+hb/hfXOC2Ip6srjuBZ3hc7m1cjNNZH2GN
         +yYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pDFMDBLV;
       spf=pass (google.com: domain of 39ykjaagkcawymduqhuosaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=39yKJaAgKCawYMdUQhUOSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61913d4b060si757563eaf.0.2025.07.29.12.37.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 39ykjaagkcawymduqhuosaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id af79cd13be357-7c790dc38b4so39043585a.0
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:28 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVhxq/O4/YjlwSKpK+YbXStCP2SL+LI9uyb8aaXWLOFlIRcqy5cqiw2fxiqu8sLuIfrlTVX37vjmqs=@googlegroups.com
X-Received: from qkkh15.prod.google.com ([2002:a05:620a:10af:b0:7e6:4e45:e180])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:57d8:b0:7e6:5f1c:4d78 with SMTP id af79cd13be357-7e66ed5c00fmr119271185a.33.1753817847731;
 Tue, 29 Jul 2025 12:37:27 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:43 +0000
In-Reply-To: <20250729193647.3410634-1-marievic@google.com>
Mime-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-6-marievic@google.com>
Subject: [PATCH 5/9] drm/xe: Update parameter generator to new signature
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
To: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev
Cc: elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org, 
	Marie Zhussupova <marievic@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pDFMDBLV;       spf=pass
 (google.com: domain of 39ykjaagkcawymduqhuosaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=39yKJaAgKCawYMdUQhUOSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marie Zhussupova <marievic@google.com>
Reply-To: Marie Zhussupova <marievic@google.com>
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

This patch modifies `xe_pci_live_device_gen_param`
in xe_pci.c to accept an additional `struct kunit *test`
argument.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---
 drivers/gpu/drm/xe/tests/xe_pci.c | 2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

diff --git a/drivers/gpu/drm/xe/tests/xe_pci.c b/drivers/gpu/drm/xe/tests/xe_pci.c
index 1d3e2e50c355..62c016e84227 100644
--- a/drivers/gpu/drm/xe/tests/xe_pci.c
+++ b/drivers/gpu/drm/xe/tests/xe_pci.c
@@ -129,7 +129,7 @@ EXPORT_SYMBOL_IF_KUNIT(xe_pci_fake_device_init);
  * Return: pointer to the next &struct xe_device ready to be used as a parameter
  *         or NULL if there are no more Xe devices on the system.
  */
-const void *xe_pci_live_device_gen_param(const void *prev, char *desc)
+const void *xe_pci_live_device_gen_param(struct kunit *test, const void *prev, char *desc)
 {
 	const struct xe_device *xe = prev;
 	struct device *dev = xe ? xe->drm.dev : NULL;
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-6-marievic%40google.com.
