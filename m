Return-Path: <kasan-dev+bncBDX4HWEMTEBRBW4LXT6QKGQES3UV3CA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 45FF12B280E
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:17:00 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id s22sf4860783ljs.10
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:17:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605305820; cv=pass;
        d=google.com; s=arc-20160816;
        b=MVZZrQW5taxDanPMOr+l8N+wYM/AxsEGEhu8Lrj9w6Wn0agHEd7ZMF3wG+By3flZpb
         1XoG6bxRxitQm0gVnWYV0661nmjtM0+7iJpF/Apo3JU6GtX5Wd46kExHNUWVXc678Zty
         iXHp6Zz9tPVBoO0wUejbwnOPvXOfmuO8caFMApuGldq6JX3E/K8geHG5YCS7Hvg13F1K
         iPgti8yaRZqAmTLeUPaIngKHnZmJNJTgruMNKlpKYoHeGfDmWN6DGEpVWNgWOz1msqq3
         veSPlzXKJmUt3C2nD57g+X3cZ2K2Zr6cKRqMJtyO6WEQzEs3tVf9qZUHmG0hO2s0Wu/6
         barA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=inJsLm59w3jKz1sMxFYohqc5KabJ0nq5SPI2Z/tlqwE=;
        b=IOIUh+V3+oDm0fAFsA1XT9R80k9ak8DlgNKlWb2Mwj1ZnvusX+3sg8Q0h+SPlXzyJg
         rbOaxM9Z23M3CJyC132j2pHlHbG3ceBJPWKP3nNjaiEQXyaq+0/pdaFDCnPJLdpH6dcA
         JNkOm3Yv2NbxEUzYpza4B7YzTLpTXJKzMquluwOETpsdo9Se1c4XD774/Sk49NQOySvr
         EPbIzhWDBZJl1T7HRx6jLH0G60IpkqyxxF7RJMOrKXBrO07Sfp/cXQpS0Pu0WyU3hzHR
         bELSQ/LQrH+J7fZcc8EcZraTB7m2e3nfEM/XE69cq5jsS8uu0N94e2qxnFI5WW4D6XH7
         2UuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gwWZ+UhQ;
       spf=pass (google.com: domain of 32gwvxwokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32gWvXwoKCaUFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=inJsLm59w3jKz1sMxFYohqc5KabJ0nq5SPI2Z/tlqwE=;
        b=ego3MZJE6Mq8ZfuteXRwQh0i1nYpq+5Y3++9VecBSZmEofGhCgQnTepIflGDtV+tiD
         S5xcgD3lRKasyysA/ZjIGx4SJ7HwHYw2ovyPIF5mt0vFSZKd8TkExk1Dn9OnfJYxF0AZ
         pEK+OzSn27POCoN675Zt3AOWSMTRKESU2S8tDCES2k6llM4GC9GAqiCi+2Uo3LwE//J2
         wymPoW6OJ5KckqdJ3Ar10FLTzJ3kVbjfLemztlBgJNcpEqnDiiwU7YA0N8X9nJs4ZUaL
         v8n24nBGimYjY3FzU+uKD0ZNA39rIg9ZXA3kl+iUpugXdUv/JG7QUAjH0mSjrhs6OWBL
         nDHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=inJsLm59w3jKz1sMxFYohqc5KabJ0nq5SPI2Z/tlqwE=;
        b=dGbzZgia05GwaB1cZ0JyWRIs6JwmU6mlvJq/PripAQeQUGRI8AP8jN0Z4FEJjpCa7U
         8mHoHBgRUdmV7qnR7OvR+E7r0Z/GRbL64CE2hY1v9g7ivm9OvJdxDjbfH8kukSP/U+8e
         h5advdxKbOO930BEKMB59qo7eJbb2fopZrM90IAhev0slcqJq3A3q9L2gp+76PiDjNkO
         biq73+68BPpU9SThdimS1LCWnt+h/fMDAPOiHACXtB5BsnLBa4BGm652rDn+q2JG3QUe
         5mJ178naSNZac8cILq44Y09NCUYti+ecWQ5Cfnva4sbK/qRzZqw7DIpTUzFvun8D1vIQ
         VgOA==
X-Gm-Message-State: AOAM532kcdJW26OVedDXiNf3QNUK9wqAxVCcbWICKs65NMMf7cdXhSBP
	fWNTsy2gfmosKvsydrjnIg0=
X-Google-Smtp-Source: ABdhPJycqxXNrQTIVk4Ha7sK40BC5PfQnGrb2Gh62zFxtgLsNwMeRaOCCcUHOHpJwKgDnR0hgZysPQ==
X-Received: by 2002:a2e:5750:: with SMTP id r16mr2318826ljd.61.1605305819886;
        Fri, 13 Nov 2020 14:16:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:480e:: with SMTP id v14ls4568934lfa.2.gmail; Fri, 13 Nov
 2020 14:16:58 -0800 (PST)
X-Received: by 2002:a19:6541:: with SMTP id c1mr1855341lfj.183.1605305818765;
        Fri, 13 Nov 2020 14:16:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605305818; cv=none;
        d=google.com; s=arc-20160816;
        b=fwHdiEmSJ+hIGjrc+vA58QclmXb54hLw1YTgOR2AApECsbwHgUNPkksH2QFlojdCBx
         PdAq7rANlvKGDEp5dhhiQDdXQ5OilyPOpgLmwqgQ6M8rTGwclUi2pzlTOOOGyH0tySTQ
         3gcP8CvgksnuN+yBIkR2Dx+dQWSJQ2WfZrHknEruqqPqlXzrIqVGAl5GRDgespQRaAoC
         bPwIgmz/hpdwvkzZVeoWsaC0FaTpW3JfbpFursZewg4T07RXrDT1dYaC4+bjlmFWQblk
         TdjOBkYW/y+Ykl2179l5HcInjxx0/mADu2r73R0RYLdUhYXpAtb8Ad81zucTPkceRzNk
         Yt2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=yKCkBgNRmvI+VGlyeWsyI6UJ3UVry+X9WEXdpst8yJw=;
        b=ueYgYQB8eFnybHke7siga3sJTVRitvos6m254ayCOEgKtyjFFcuMn6BHKvJnBvaf+h
         U52nwuJ8Dbrys2w0DW5f1oHdXJ69wEQhyXa8guUhyVFdUHVgUjddIPjRWscWb/a9/Frk
         hijVQ/+j9MaONI8gdF5ESqzsubH4V1pj52yQ+DJSLjBA0BKHo0vhY2WHaHHkW3ovVkWO
         +Wj7I2pIug+6LWBitfPSHJde0hbRdY1GhVVZ7KazdiU46QPe7y8oXFAd1IKl94CypEy5
         uw+zenJZg2OO5ZUiYhrjfft1jdPLXbn4wSHNbhtX3RWol0b+P0Nt1YbvIkZuDPJqDmS1
         HQrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=gwWZ+UhQ;
       spf=pass (google.com: domain of 32gwvxwokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32gWvXwoKCaUFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id y12si234524lfb.1.2020.11.13.14.16.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:16:58 -0800 (PST)
Received-SPF: pass (google.com: domain of 32gwvxwokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id h9so3558199wmf.8
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:16:58 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:e284:: with SMTP id
 v4mr6412618wri.271.1605305818271; Fri, 13 Nov 2020 14:16:58 -0800 (PST)
Date: Fri, 13 Nov 2020 23:15:46 +0100
In-Reply-To: <cover.1605305705.git.andreyknvl@google.com>
Message-Id: <ec80ee52d741da81e4e2c08a09c3dff5feab5260.1605305705.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305705.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v10 18/42] kasan: rename addr_has_shadow to addr_has_metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=gwWZ+UhQ;       spf=pass
 (google.com: domain of 32gwvxwokcaufsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=32gWvXwoKCaUFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
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

This is a preparatory commit for the upcoming addition of a new hardware
tag-based (MTE-based) KASAN mode.

Hardware tag-based KASAN won't be using shadow memory, but will reuse
this function. Rename "shadow" to implementation-neutral "metadata".

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Reviewed-by: Marco Elver <elver@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
Change-Id: I03706fe34b38da7860c39aa0968e00001a7d1873
---
 mm/kasan/kasan.h          | 2 +-
 mm/kasan/report.c         | 6 +++---
 mm/kasan/report_generic.c | 2 +-
 3 files changed, 5 insertions(+), 5 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 488ca1ff5979..c79d30c6fcdb 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -147,7 +147,7 @@ static inline const void *kasan_shadow_to_mem(const void *shadow_addr)
 		<< KASAN_SHADOW_SCALE_SHIFT);
 }
 
-static inline bool addr_has_shadow(const void *addr)
+static inline bool addr_has_metadata(const void *addr)
 {
 	return (addr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
 }
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index af9138ea54ad..2990ca34abaf 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -361,7 +361,7 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	untagged_addr = reset_tag(tagged_addr);
 
 	info.access_addr = tagged_addr;
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		info.first_bad_addr = find_first_bad_addr(tagged_addr, size);
 	else
 		info.first_bad_addr = untagged_addr;
@@ -372,11 +372,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	start_report(&flags);
 
 	print_error_description(&info);
-	if (addr_has_shadow(untagged_addr))
+	if (addr_has_metadata(untagged_addr))
 		print_tags(get_tag(tagged_addr), info.first_bad_addr);
 	pr_err("\n");
 
-	if (addr_has_shadow(untagged_addr)) {
+	if (addr_has_metadata(untagged_addr)) {
 		print_address_description(untagged_addr, get_tag(tagged_addr));
 		pr_err("\n");
 		print_shadow_for_address(info.first_bad_addr);
diff --git a/mm/kasan/report_generic.c b/mm/kasan/report_generic.c
index b543a1ed6078..16ed550850e9 100644
--- a/mm/kasan/report_generic.c
+++ b/mm/kasan/report_generic.c
@@ -118,7 +118,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (info->access_addr + info->access_size < info->access_addr)
 		return "out-of-bounds";
 
-	if (addr_has_shadow(info->access_addr))
+	if (addr_has_metadata(info->access_addr))
 		return get_shadow_bug_type(info);
 	return get_wild_bug_type(info);
 }
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ec80ee52d741da81e4e2c08a09c3dff5feab5260.1605305705.git.andreyknvl%40google.com.
