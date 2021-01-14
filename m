Return-Path: <kasan-dev+bncBDX4HWEMTEBRBM5ZQKAAMGQENMQQ5JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id CF48C2F6B08
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:34:12 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id r22sf2331842ljd.4
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:34:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610652852; cv=pass;
        d=google.com; s=arc-20160816;
        b=ipZ0jihYbsUta0Z8b1qANQneZ46S7qXJsGCf608Q7EFNSgEFP1ZgHFKGBnNE/VbUZn
         8bPQBdoAnmlEpJnhsJu81LviEDm1Juw0Q36Lgtw7PtJ73zUfiPXtN9oP0IFVw4NUsuGO
         FLL/OUHsJWrdERdYSuvivAwQeK/6Xy//TpYBLtWRLOtm56wVfPIkP1Et5Q1kguIa9mhi
         1COYShEt6aibOVWDpIR2Ycontn12DxZhSuTqNQTzzsofrZhU+Eo2/BiSvuVry2hYvnrf
         QakmctcYWpk5/k88eXbPS6lD22Gv4WB1dVzrFs4y+il7XlkoLLviZDTVj8tEI9QTF28K
         O+qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6S9csgr/YwCdz4ALl39zya3+WgxMwSbWoIX1j09SEYU=;
        b=DOe9XHIaeaCeO7gq8pWT2qNcGYI4pWA7/F387fL3mZQ+iLuThap2qrIdzMVr/VrZA+
         hv4n9IC/AClcs5pl2qsCmKXiVTrEg8oTDUdONyGZjb5tTk+FVtTElDoC2/tvmi2oNs2N
         aRx7HkTTk5q9hA6aioXHx6JRYMkK4KVWpbKSm2TwpExEArvzkgGd8asKf/Ww/VInRZKQ
         y1iS7M6610mN7Tyz9UNphe4rSjGIaLJo7CPrXgbK3V0tEs+qCfYYJKv28u6F1j6AoKA1
         R8r6JE7y+JxpbNzpN8RLzVwN+6Z+9bAAE3AIivZ+8EijUEetSx+6vmxvexShxOyln6H9
         XTsg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tmcmrez4;
       spf=pass (google.com: domain of 3szwayaokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3sZwAYAoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6S9csgr/YwCdz4ALl39zya3+WgxMwSbWoIX1j09SEYU=;
        b=ADtbekVzR0QmMLLlyTFaBDq+3gZ6RrJZWhhkyzzla33r68MX2OOI7R1tA9SjGCgL1Q
         pnsH8nJjTWACVdQIRJHhRNKIg7uUk7a1Fkm6NFJCQxdK9qRSSZ3MQzktA48drHn7BAif
         iS3UWbAjfPD6oKSYDT/niD6L9+/d97D6XqUMWPRulINGrKAvmnjt5yQGVHL+GidIXZet
         azgGHJM32PbzLUCV9iNmI2bxBS9697mV00KfLnyVjRHGjRvZ9veaUMW4ghtCjG6l604B
         ghDfPE2fzi24euHkUgmGXOsFlBi1BEKjatURga2wttXlQ9fGjxP+ZGN7fxAyoOEBv5Wf
         CaHQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6S9csgr/YwCdz4ALl39zya3+WgxMwSbWoIX1j09SEYU=;
        b=FRDpT+YCKA1+Czxkv3/K1+Wi/BumFEQyGjaU/FU3DqLRMjSqc0esYfklEtsSmhZYrV
         7lSUfxTQqivx1iG12+Qm7DXD8Irs7Yxs9STxkEjT3e4dpV8zt9GYVnTzJm54MTZYDmVb
         xdsh5pLmm2wn8oZiSKfOEb02ec5myUT+sj9DOXJqWqxvQ6hLlZIVS6W+XHw8Ei4aa0aX
         CkhiseTNdczB8mNQR0P1oCU6NsvKcoryGJ9xSCMz9ZxbZPeJwcbinUxezz0g85tLKPWK
         WVQdz5Epmighq/nWl9JBTy15qYGBXyhjY+Fgc+TumodoK3UF8Ekh97SI1Bk36tVTrOcB
         4ZZw==
X-Gm-Message-State: AOAM5305quokLgmyEtD4SAGepwB0j9ciAJxkH+COOR9VN+sCzuNeaQ3e
	0JMDZvKuY5pcvNJNZfSMBU8=
X-Google-Smtp-Source: ABdhPJzNDKCVFXbsWgxkuDyuHQzLLIm5Twmb8RFPah4eCLEIMzPq5P6LmbRKMYOGd9x811FQAkFDOA==
X-Received: by 2002:a19:5218:: with SMTP id m24mr3963108lfb.232.1610652852114;
        Thu, 14 Jan 2021 11:34:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7d0d:: with SMTP id y13ls1140192ljc.9.gmail; Thu, 14 Jan
 2021 11:34:10 -0800 (PST)
X-Received: by 2002:a2e:9b4f:: with SMTP id o15mr3533908ljj.393.1610652850244;
        Thu, 14 Jan 2021 11:34:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610652850; cv=none;
        d=google.com; s=arc-20160816;
        b=g3Q+TVj+PRWUev9NEVdvO7N6R+I3zD5jBxiXgvWA81T2hTc+4q1KPORDMQCHmUxnvQ
         kMfvx2SoyjY6qUomVkVj6uLi4iHSImLIgjeXYJ7T/Ds3FFl+yPzFO5DzwTQj0duYQuc3
         uwe/KN7vHB4h2KMtp+lm/2pb0iVNzdU7Oyj8n6eNXMxQt+rP+bq19e/bz/6SqJWmRovQ
         3ZwkGXgrMG/my3+zQVYRFU3eE9T6ru7cLgtj2y7HR0H4MHHHGKCFn/a3SJ1nZKX9muzn
         BWZO9HA4IVYUAKMkXXOX5+FpruMs7nSS/89oKOt4HFTuZ3qxR4T7A5BDFAV+iQiIDEIK
         MK7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=TionkskhfJFUpeI/OKXUNvEID4OHoy9zg6Ffh7JmH8U=;
        b=IRQEB5BE0VqTs1NwQGlGQmBscW9cKU8toJt3Vmy0tloH3AW+g+g96ma+DPubGVKkgm
         C2w7U58cPtlEzuaU87be9qF37yByloVy/Wy5lj6iFWfoik8G4h1nWORFlkW/84NHlDrR
         IuRGtN2YlYCqCzTsXirrm4ISmObpqlmb0uodUmztgVHNujpYA4BipL0Qp9xfpxzxAXjN
         KwAkBgKmhcML9ISvIcxc5QSWCFURYb4FEGe2Z1KSpmlIhoRSHexwrgnpUb/AqymJXKJy
         ErHpgJzkBKcC+qnemqKWCjom8PBUIqgJiUD6Jh+MK1hjjAVw5iCDwHZL2iA2I9qbDHO0
         /g/w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Tmcmrez4;
       spf=pass (google.com: domain of 3szwayaokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3sZwAYAoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id i18si254681lfp.2.2021.01.14.11.34.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:34:10 -0800 (PST)
Received-SPF: pass (google.com: domain of 3szwayaokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id x20so2257883wmc.0
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:34:10 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:258:: with SMTP id
 24mr5507364wmj.16.1610652849704; Thu, 14 Jan 2021 11:34:09 -0800 (PST)
Date: Thu, 14 Jan 2021 20:33:57 +0100
In-Reply-To: <cover.1610652791.git.andreyknvl@google.com>
Message-Id: <3d9e6dece676e9da49d9913c78fd647db7dad552.1610652791.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652791.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 2/2] kasan, arm64: fix pointer tags in KASAN reports
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Tmcmrez4;       spf=pass
 (google.com: domain of 3szwayaokcfiuhxlysehpfaiiafy.wigeumuh-xypaiiafyaliojm.wig@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3sZwAYAoKCfIUhXlYsehpfaiiafY.WigeUmUh-XYpaiiafYaliojm.Wig@flex--andreyknvl.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/3d9e6dece676e9da49d9913c78fd647db7dad552.1610652791.git.andreyknvl%40google.com.
