Return-Path: <kasan-dev+bncBC6ZNIURTQNRBS5O37FQMGQESEMP3GA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id uCYPHE3Xd2mFlwEAu9opvQ
	(envelope-from <kasan-dev+bncBC6ZNIURTQNRBS5O37FQMGQESEMP3GA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:06:21 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13d.google.com (mail-lf1-x13d.google.com [IPv6:2a00:1450:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id 1253F8D803
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:06:21 +0100 (CET)
Received: by mail-lf1-x13d.google.com with SMTP id 2adb3069b0e04-59e0342155dsf34597e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 13:06:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769461580; cv=pass;
        d=google.com; s=arc-20240605;
        b=gpRpk9MLbps+P6Fp7eTpW+e6xbnj7pyLHJEURXBEmnLcxlfe3HemZwCSO5mlIlDNV2
         N721fZxCraNLCx67RDO3WQlU2UcVSU9JRDda7cBUgOyf7UtuqXjbCtC5WQm+aCA4X5Fl
         osdiFW1fJRG7kcplBLjKKyvzQ/FyBDry1dZwZzqqCV51ftCDSzpm9d987Mc923xR0R3c
         JsSHnQ899K/OaonGjB8WeFsNMVjuOUnIChCWZyc2yP4bGvg911cLKVZX+NVl5EFjyRyg
         mQf7AnlwMqHmb9XtNcZhXy9IMQ4oBasq9RRFZMt21EsGA8l4C8ggkQeK8UyZRZkbATQx
         ev+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=suqmMBWRMw7oJcWuc8sDhrmclce7nkEXYCy5HzIRgP4=;
        fh=FG9zxT517yjqcRnubqx4AOWERbFc7OFq/SvaQw1N9yM=;
        b=lAUpfnccDOIiNBFV4f0wyHKXjd81J6VN3W5kyGS4Y93lHKYQromQK1V+emQe/ToHVY
         xudJyDbNEPF3WDVrG0GLBA+A+ruKwTd5T6nEX3x+kXg5kImMZ8Akx741muvYu2bILZY9
         WEr3UjUC5xMLDFv+L+wFGJ55GyHqqfCKUTL1EXQK8z5Vb6F3KJkVhWaithCs20hsHUIH
         /KqMMopSfmcTj3uoBtNx0cjPij157BErImQtepOv9y5/fBm8rN/F6PqxVQibLDncOgB1
         iqB3V3q7zKtfw8tuXP32m73yC/lcOk+xbqXxERQNoQzNxXvHb7e3ZwAXr/888FmeApQ9
         feYQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=google header.b=D0wCmue1;
       spf=pass (google.com: domain of andrew.cooper3@citrix.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andrew.cooper3@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769461580; x=1770066380; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=suqmMBWRMw7oJcWuc8sDhrmclce7nkEXYCy5HzIRgP4=;
        b=NvFwB2N+0I5tsMjW79BPg75iiq9BR5R7zgffs8vQH5S7qPLrPIcpaYcC4R5Nwk5fHf
         A4xwZIBZNiQgp0TWN31Lzw3+qGKlWpzd8BJ9myQ8MTgDUKwetXb51Uz81SpcVJPXqr8e
         aZ00eASi0Cp7MzpNIYiouxqjxv21ygB+uPxuzoP40nx9HsycmxOjoPd3pfOkClaZsd5e
         0XauqjAe9JWBQkmPQRmAyuQYEuFUBz9713SRFnAF37MrcChpO73hxRkhT3p3JZssh+Sh
         glmWGfvfP2mjpOQ/Y7olsA5Wk2R30cTv8eHtEj0t7TbGoqe2EN30FzOoY179a6+B6rLU
         9wTg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769461580; x=1770066380;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=suqmMBWRMw7oJcWuc8sDhrmclce7nkEXYCy5HzIRgP4=;
        b=IHCZ9RTbT9usLGSSpcJS4kkuO8HjkPDtkAu/5dPMmipHqbho23M0xTVskcKF3WMdFR
         RdDBhvSFpI7IrExfC1Ueq6s+iYSEGvgDT3BqSjALhnV+WSc2GL89Y98HbRlrk2wbH8pC
         hUlimd198pOd21Fal7cDoE1gskqALrnhm3lox/TiT6LMEXT7mKXfQoH0n2DT5aAZoQh+
         KYQNESEnEWh1/3m/CB2BtAl+daWwy41A9vgM2ik1h54cKOCfTTsT/COJ9CB5MB8IH8GV
         sqlW8O09as2iTCykbjDC8O4Zd0DxoBMRVhRlaX7j3dUEOOaGghZSfd1d6jcOqxotqZI1
         9QEg==
X-Forwarded-Encrypted: i=2; AJvYcCWWDFkrdVgoWgHT9OIbYEAVM9NUtnVST9YY9kvsmr01HKFwwdbTm1Nw2X00pGRQLBXSNPZqoA==@lfdr.de
X-Gm-Message-State: AOJu0Yw8iehpAAClgg0S3cEjaJxQRAdGfTAWV3ijTrUyWEucct8GYpMe
	2U6z014bBbE3WkIRAnLJpj1kQAgpuW8hQfdshWwTUJSIFXILpsHXs8ai
X-Received: by 2002:a05:6512:3b06:b0:59d:e659:9c96 with SMTP id 2adb3069b0e04-59df3a4bb79mr1896563e87.50.1769461579946;
        Mon, 26 Jan 2026 13:06:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E2yA/DrwWZcg+xSJ2EROYGjDtLnQADc2n92Q8c3kZ2BA=="
Received: by 2002:a05:6512:3e1f:b0:598:e361:cc93 with SMTP id
 2adb3069b0e04-59dd783be5dls1434437e87.0.-pod-prod-05-eu; Mon, 26 Jan 2026
 13:06:16 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVniQe197A+o32Fd0e+OEyUbGYDLdqrnXwLQdZBrx4eh+545jc6XAEDIvUeGkeJAMhLo+ivggZDxh8=@googlegroups.com
X-Received: by 2002:a05:6512:3f0d:b0:59b:6ae7:63ee with SMTP id 2adb3069b0e04-59df3608ef3mr1961046e87.3.1769461576566;
        Mon, 26 Jan 2026 13:06:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769461576; cv=none;
        d=google.com; s=arc-20240605;
        b=f2qcA1gNlHlMKsvUK5TLixUzq/l8KJiIZwJHVsjRY5iAeIvj0aeWdPRxTX+cQa4Vws
         bgUq3yG2KZVMGhsbgufmqOZC9oisbasQi8G88dRH0fPnWZHLZs/iXKuXpD1W4Qg8XD98
         ipc59dOUwT37MtL1fvwGncP+F/wN9pmCdTFKY0Ecax18RFVdX69N6Ehdq7k5NlRJGaxh
         eteVcp5Cq1wqvg/rtGlIbcNtPOZlwCq7eyncV4dyqtAsEq8OL5N3nUd4ZzoSTe9sH0v/
         wjBAwvruwj1OIIjMTJkklE1KcKn8NA62Hv4DJu6VyVfH4NbkvajJmIpu/KdEQjOojZfW
         MEFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=p+rst1/+zmZkVpczY40RlzwyLz+AGToKNu6aYTlMfJo=;
        fh=FmUNlJIfLZJLfuCeKSHOqu2U6VoJctObPh4axsZfSIQ=;
        b=k+lrWsalQOMvKUczUIVlCptz0jQhSg3PZGpDHTW7GD/rR+dYsXn8EVk5TDPgilPNyy
         C5udTbEeiAgRKCi+V/ebQpEGVxf/uyJFU58jJQFUVFTakK6fBsTD7PjvEy9o3tkCCfGf
         rBeqraA7FPGUaTUo+B1FKbdjWrFt8VDitmZqzpw1+uikyQ2tLrB7QYmisQlJkDMr6uFr
         mpsemfANqzKnBcIKU+afrq0N1LzYaaSbzHsbvw2OT71HIX1EkTRYw2zDElidN2U8Q8En
         MyS8vzVzAJPrJazkS7bbxgJ3+8Gn1dA558wg36pxeBeHoX97oE/5ByljWERbB/qnIjdH
         X6Vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=google header.b=D0wCmue1;
       spf=pass (google.com: domain of andrew.cooper3@citrix.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andrew.cooper3@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59de5ab3aa4si215762e87.4.2026.01.26.13.06.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Jan 2026 13:06:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrew.cooper3@citrix.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id 5b1f17b1804b1-47ee807a4c5so51825105e9.2
        for <kasan-dev@googlegroups.com>; Mon, 26 Jan 2026 13:06:16 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWKEeVQMfCj0avj6c/su7uOTJpN9Hr3bAha2FXmRRypnpPsn5cfkimg28HFIl/pU54fr8bjMCUZMx0=@googlegroups.com
X-Gm-Gg: AZuq6aIhQ018hBbpQ8hn5ZEbp50IoLT6VkMs/7lNayH9XHC0tvW9c9qab77L1Kl6ilF
	UOsdR6yif+tq9K0T+R3kq0WTBHvtDpd021bYDP2n5zctE1bwTxAAOHghzBDJdlMVpVFtREyO2Pc
	r5g8Mfc5EBOV+LCETb41W2Vl/uhGM/+NdQ2obCqU5h3xbtA/ZM62kCSU2A7dR2S0/dalUr13uxo
	Dz/NBOZytkm0UpGPHzp2HmdLZ04t5KsPIHZdwvySgkunQ4di33liNeymVtRXF1pTpDi53Cvr6RO
	y4q+ARZ6Kvb9NkKR1MzGNU57HXPZfLhob9jHHL4hIYuSl9JU0fZipqQbsaJqO6ajIOT2MNYiwYs
	/25snOkJFNTmnhiremnKp6WdWgHHK+0D29FsYtsKOzR9dmy1GB2RBgf/bkyD/yzxCR7v6XAmWAU
	/Wc6uK7L2xw8xVV2nQA6Km/rkb/gXzRrppo0K89PH9BvPeW7Q4yU1VcQTzg8+kJw==
X-Received: by 2002:a05:600c:3113:b0:47d:403e:4eaf with SMTP id 5b1f17b1804b1-480650f2933mr32460585e9.10.1769461575594;
        Mon, 26 Jan 2026 13:06:15 -0800 (PST)
Received: from localhost.localdomain (host-92-26-102-188.as13285.net. [92.26.102.188])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-48066c40e04sm12700165e9.13.2026.01.26.13.06.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 13:06:15 -0800 (PST)
From: "'Andrew Cooper' via kasan-dev" <kasan-dev@googlegroups.com>
To: LKML <linux-kernel@vger.kernel.org>
Cc: Andrew Cooper <andrew.cooper3@citrix.com>,
	Ryusuke Konishi <konishi.ryusuke@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Thomas Gleixner <tglx@linutronix.de>,
	Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	x86@kernel.org,
	"H. Peter Anvin" <hpa@zytor.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Jann Horn <jannh@google.com>,
	kasan-dev@googlegroups.com
Subject: [PATCH] x86/kfence: Fix booting on 32bit non-PAE systems
Date: Mon, 26 Jan 2026 21:06:12 +0000
Message-Id: <20260126210612.2095681-1-andrew.cooper3@citrix.com>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
References: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=google header.b=D0wCmue1;       spf=pass
 (google.com: domain of andrew.cooper3@citrix.com designates
 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=andrew.cooper3@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Andrew Cooper <andrew.cooper3@citrix.com>
Reply-To: Andrew Cooper <andrew.cooper3@citrix.com>
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC6ZNIURTQNRBS5O37FQMGQESEMP3GA];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[citrix.com,gmail.com,google.com,linutronix.de,redhat.com,alien8.de,linux.intel.com,kernel.org,zytor.com,linux-foundation.org,googlegroups.com];
	RCPT_COUNT_TWELVE(0.00)[15];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[andrew.cooper3@citrix.com];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-0.999];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[citrix.com:replyto,citrix.com:email,citrix.com:mid,googlegroups.com:email,googlegroups.com:dkim,intel.com:email,linux-foundation.org:email,mail-lf1-x13d.google.com:helo,mail-lf1-x13d.google.com:rdns,alien8.de:email]
X-Rspamd-Queue-Id: 1253F8D803
X-Rspamd-Action: no action

The original patch inverted the PTE unconditionally to avoid
L1TF-vulnerable PTEs, but Linux doesn't make this adjustment in 2-level
paging.

Adjust the logic to use the flip_protnone_guard() helper, which is a nop on
2-level paging but inverts the address bits in all other paging modes.

This doesn't matter for the Xen aspect of the original change.  Linux no
longer supports running 32bit PV under Xen, and Xen doesn't support running
any 32bit PV guests without using PAE paging.

Fixes: b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
Reported-by: Ryusuke Konishi <konishi.ryusuke@gmail.com>
Closes: https://lore.kernel.org/lkml/CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com/
Signed-off-by: Andrew Cooper <andrew.cooper3@citrix.com>
CC: Ryusuke Konishi <konishi.ryusuke@gmail.com>
CC: Alexander Potapenko <glider@google.com>
CC: Marco Elver <elver@google.com>
CC: Dmitry Vyukov <dvyukov@google.com>
CC: Thomas Gleixner <tglx@linutronix.de>
CC: Ingo Molnar <mingo@redhat.com>
CC: Borislav Petkov <bp@alien8.de>
CC: Dave Hansen <dave.hansen@linux.intel.com>
CC: x86@kernel.org
CC: "H. Peter Anvin" <hpa@zytor.com>
CC: Andrew Morton <akpm@linux-foundation.org>
CC: Jann Horn <jannh@google.com>
CC: kasan-dev@googlegroups.com
CC: linux-kernel@vger.kernel.org
---
 arch/x86/include/asm/kfence.h | 9 +++++----
 1 file changed, 5 insertions(+), 4 deletions(-)

diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index acf9ffa1a171..40cf6a5d781d 100644
--- a/arch/x86/include/asm/kfence.h
+++ b/arch/x86/include/asm/kfence.h
@@ -42,7 +42,7 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 {
 	unsigned int level;
 	pte_t *pte = lookup_address(addr, &level);
-	pteval_t val;
+	pteval_t val, new;
 
 	if (WARN_ON(!pte || level != PG_LEVEL_4K))
 		return false;
@@ -57,11 +57,12 @@ static inline bool kfence_protect_page(unsigned long addr, bool protect)
 		return true;
 
 	/*
-	 * Otherwise, invert the entire PTE.  This avoids writing out an
-	 * L1TF-vulnerable PTE (not present, without the high address bits
+	 * Otherwise, flip the Present bit, taking care to avoid writing an
+	 * L1TF-vulenrable PTE (not present, without the high address bits
 	 * set).
 	 */
-	set_pte(pte, __pte(~val));
+	new = val ^ _PAGE_PRESENT;
+	set_pte(pte, __pte(flip_protnone_guard(val, new, PTE_PFN_MASK)));
 
 	/*
 	 * If the page was protected (non-present) and we're making it

base-commit: fcb70a56f4d81450114034b2c61f48ce7444a0e2
-- 
2.39.5

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260126210612.2095681-1-andrew.cooper3%40citrix.com.
