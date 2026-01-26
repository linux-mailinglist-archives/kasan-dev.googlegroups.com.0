Return-Path: <kasan-dev+bncBC6ZNIURTQNRBXNQ37FQMGQEBTWJ5WQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id eHxqFF/Yd2mFlwEAu9opvQ
	(envelope-from <kasan-dev+bncBC6ZNIURTQNRBXNQ37FQMGQEBTWJ5WQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:10:55 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id E63F18D922
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 22:10:54 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id 2adb3069b0e04-59b70088327sf2900427e87.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 13:10:54 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769461854; cv=pass;
        d=google.com; s=arc-20240605;
        b=Mu/Z0YaAdP0r6wmc1ib2354AkbvDB8HAf/YAiHHuZujG4DA0pFaKUeTfnyjAmEppSS
         SjPjd6B6QFgJdKCV6DDmmFwk7HzHanXL9Q3nZCSYD3JrV/ezsmzWkpTvQdNylq8K72Lz
         ujE8vlgGb/EXovpssOICp7sp/1pZGBTkXIozgJ2VMi3DNyJ5OnLJKpBfgblTTIZ17O1D
         NESxxz7DamZY0bKt6G5JrQ7GEAXkSFlUKp0LdhgbRYDoGMu5Z+NInI3MKZwY5W1taTVU
         1MtrIXXDd8U9u1I48kHyrDG5Trwfza/AgfnBXA9fw62I6Kc7PN61QICHs9N/CiKBC9iC
         Zb0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=DF6FHgmY6tORg8xTpehPQ4gKpQ4cc0P6CaG7lVnjxOo=;
        fh=lblQOViCxyVzLDqt9nfbCeOOPDcYwvipnpvGmTbeK1w=;
        b=NsTmmYUzdqqlfGzHD3uEBOL0wNn6j06C7x0hZALSbzkhgP7eUCD3adkZddUIRsilsL
         xSQEeeL/VFz8JujHF/NZ52itcP4FkTAWoqT3lC1YSJAviaIPO2Ybe1bFzwTlzYJXTaV+
         R/HlKKJAvbl44QCnWMBhs9RavZ9HP8UgSz1tdmtkK2VKrgyvftS1HiWPxhUPTk0zegqh
         a8ZRaoetsJZvPtdWNTcLW3DXthQaHYS6e8Z920D7IHD5zthRgqmFoW5PoP/rkhCAaSIC
         Sh0a2OoOdhyFkoapakOQ4AIpr86CRw6GINxQ2FBiF2GEOl5cFFQ/a35bwqbg47MorRCC
         qtkw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=google header.b=WK4hEgo9;
       spf=pass (google.com: domain of andrew.cooper3@citrix.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andrew.cooper3@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769461854; x=1770066654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=DF6FHgmY6tORg8xTpehPQ4gKpQ4cc0P6CaG7lVnjxOo=;
        b=UHz2H4Qat2Muz779adcpIWoKfcUhxsJXRLV112U68FyqFif8v91wQqO2iN2FyOo2Gy
         jgZUOtPJRVe1DgbgJ18b50JYIGD5r/6zIVltZ9ZstWWGuX6BZ2mfYxatHzOvfKFtYPa4
         sMdvVzbKRmdkecRzgKapLNS/I4vFuM0OoyXm7QGsXGk/R+f7gJ4ORRHzoHjWs0Um2ek8
         2HwD5FhMHFPQ5Wug6KR0/vxvHrww6NlYNyZtUF1FGJ6MKieVeB+20Vk6rZTq7oTyoB3P
         xwVhocB8dFQuxCrkDlwQKc6KecWEZ2yI2Juc560YMgv3FJPaijesBhDxgb+bcL2WBcG7
         ZQHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769461854; x=1770066654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=DF6FHgmY6tORg8xTpehPQ4gKpQ4cc0P6CaG7lVnjxOo=;
        b=fh39LhBBwiniObw1jhArS+iI0x7pBi3wy7stezGSHJ0xLnBgWtFCyJr/mwQsxHt4Kh
         f9nOHQv3pdnJt9t/EmgId0LrDtSRDB0GXGhj3fPMIShftrIMV4JZaWd6QWVy5fd1iFun
         HAx3UCEZhOzBEVzoE12Gx1U6TbuphtFEzD4p9iD0kHPwPNIxogb7Q1tTGaawVkYeD8ET
         YYjJD+AUjx/pm2JgmDZ8YDIbLSuKatiKe7PwlrVmIdzKEs28lBC8tmVt8bNkqG5V6OvY
         QBDbKfuNHiKQ7beI9Znt+sq/7jrYWk5V4SjAE/Xm7RXPqZRjoIl6dvWAO5dHgLp1Zm0F
         mYmA==
X-Forwarded-Encrypted: i=2; AJvYcCXQ6YMTSd4Gn4wKCIlxxhkfW+E6qqQBdGz+93lCwZH+Ro6Yu0JjulmkMFi94KEP/bUI1vlzCQ==@lfdr.de
X-Gm-Message-State: AOJu0YyvD+zWcoxfOm4V5mDyvN2tBNMq27aY3h7cEmfNsDQ6cOKizRry
	AEb8qwpzUlisjNwfMqEddraYSryIoSsdVGwX+rTC5yvO/pojmVQCDwjG
X-Received: by 2002:a05:6512:3089:b0:59d:e589:c977 with SMTP id 2adb3069b0e04-59df3a123a3mr1748096e87.26.1769461854141;
        Mon, 26 Jan 2026 13:10:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+E4+rCu0crDNRyk0pakv+Nbbl+ZoQ9Xj1udQ1inUvZHMg=="
Received: by 2002:a05:6512:2352:b0:59b:6cb8:9cf3 with SMTP id
 2adb3069b0e04-59dd797aabfls1483862e87.1.-pod-prod-03-eu; Mon, 26 Jan 2026
 13:10:51 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW40uxEDROUm416MZTKusAYr4guL2QrMS3RxJ+purniD+Zfht3YLqZtsm2si86nVamMnk5QsxP8H7Q=@googlegroups.com
X-Received: by 2002:a05:651c:1445:b0:383:210a:7b2c with SMTP id 38308e7fff4ca-385fa1ba55amr22142821fa.44.1769461851091;
        Mon, 26 Jan 2026 13:10:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769461851; cv=none;
        d=google.com; s=arc-20240605;
        b=PKbvvslhLMV5xvrDOf4HypXH0KKcEMAkJFe9mDZ6b+d0yyGhzAB3hagPFBMUl9Pcuw
         Ga1mfASqSkItrmMaHtgriCatUpHIMj/HEm8Cv8KR3JeJfKECgnLrjmndp9Drqzga4Sjd
         49x2NU0o1VHc6Ad8SRIY6zLPPqMRgFnye1lq8UWd5GCt8OQLn/YqQOnRC+jNY3i5h9iS
         ZBUi5wS05eGfu53kenLdOU9f7sB0hjmticVyNPbNfapFQ0dETcHxHdeQEgpEDPqIft5w
         iZFXLmKmbkDeFA+GFow9ImK3lMk0g1H/J1a8hrnsJFAVOQkT7gJF2p30Fw1lkvyOjphe
         VR7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=SPdFNoBhwc/42UhsY49ECO9+OSxJlw6W4wx9EBbbxTg=;
        fh=Wv5l1/cvP+AIe4h4rrmyQ/goxOBxC8IBo5IPTsY5oyo=;
        b=lrV56KcCRdHnpBFNC3016CWiEkxyQ3TnOoNje3D2bKBL63X7ypCD2FAXLA37F2W8gm
         jH5qxlc3Mvmgs8Zhm1wD7wx3f0RwS3b+1nnuKvzr395vh88nhuFFWeCFaz76qAvpEXSA
         Z0bKg0cAPMtyaCVulZAjSNZdckZx0lsfHdD2co44alLM0mtkBsV3k+f5eCSQd6Xb9WyD
         f2Tp+PepyeHGkBf3a2OPn1ni0Zk3eKrhLgLicGOGwZPe3DeBXEyGV9d/CTMbkQjvRVbo
         +0VgpFInNYVkdPHhaMeYva/u06R6/JcLTBQGHxMa3IwsPz4QuS6hRrwQFz5HKuU6eEu6
         PjXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@citrix.com header.s=google header.b=WK4hEgo9;
       spf=pass (google.com: domain of andrew.cooper3@citrix.com designates 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andrew.cooper3@citrix.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=citrix.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x334.google.com (mail-wm1-x334.google.com. [2a00:1450:4864:20::334])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385d9f8dae7si2365161fa.1.2026.01.26.13.10.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Jan 2026 13:10:50 -0800 (PST)
Received-SPF: pass (google.com: domain of andrew.cooper3@citrix.com designates 2a00:1450:4864:20::334 as permitted sender) client-ip=2a00:1450:4864:20::334;
Received: by mail-wm1-x334.google.com with SMTP id 5b1f17b1804b1-4801c2fae63so39339275e9.2
        for <kasan-dev@googlegroups.com>; Mon, 26 Jan 2026 13:10:50 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWoQUjHV799w5rkXCW/oVkuxzK2054o0obt/fNCHRfFdj/PRp3lEqjjQ1EIJbnLKptdzrdryMGkFSQ=@googlegroups.com
X-Gm-Gg: AZuq6aKJaLtNIm9YdX2yKH80sPMRKyXlkbrVHSYQWBsEAUs5evim1iz1bgPpvBrL/Lv
	INzpQHU/IQgFW73TYDTHwbuhGRibkiEdt/aDVDBXR1zmp0EA/PXT0jMm5iEFtiw/kj4E0xL4MLp
	SkjxDFnRAiDuxJ/AWaz3GznGsvaqw79cVdlM9xIQwXbHvlcdu0bo+hEUWezzpoPC4rbp0sWidI4
	c2XTxWOCyCoKjUFJfNI787JVH57XLcn8EvoiuF7H8z+HYZgVF4rrlTCyHvR+NgxNj6NXTjPNc+o
	seFt4p7vN9e6ljF2Imy+w8B2kpmtw6T2C6dayknMSf6Oa6plyin7NM8aStuAL98mxJ+TJUtfTdT
	e/TwioX7Uz5dhXBbNR1KMmEllHz+V+m5uAh24HD/DnNw+BVHZVPTNWs/EfkAI4tdMsv7wjbk0H+
	g8UM4GY2QCZr/lzReJFXBrngSY/80SM/WbiZIuGThVfoVBf0PW4fVkGvT9l4BmCg==
X-Received: by 2002:a05:6000:22c1:b0:435:960c:5286 with SMTP id ffacd0b85a97d-435ca1ae448mr9047616f8f.58.1769461850008;
        Mon, 26 Jan 2026 13:10:50 -0800 (PST)
Received: from localhost.localdomain (host-92-26-102-188.as13285.net. [92.26.102.188])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-435b1e715d3sm33097044f8f.28.2026.01.26.13.10.49
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 26 Jan 2026 13:10:49 -0800 (PST)
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
Subject: [PATCH v2] x86/kfence: Fix booting on 32bit non-PAE systems
Date: Mon, 26 Jan 2026 21:10:46 +0000
Message-Id: <20260126211046.2096622-1-andrew.cooper3@citrix.com>
X-Mailer: git-send-email 2.39.5
In-Reply-To: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
References: <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: andrew.cooper3@citrix.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@citrix.com header.s=google header.b=WK4hEgo9;       spf=pass
 (google.com: domain of andrew.cooper3@citrix.com designates
 2a00:1450:4864:20::334 as permitted sender) smtp.mailfrom=andrew.cooper3@citrix.com;
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
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBC6ZNIURTQNRBXNQ37FQMGQEBTWJ5WQ];
	RCVD_TLS_LAST(0.00)[];
	FREEMAIL_CC(0.00)[citrix.com,gmail.com,google.com,linutronix.de,redhat.com,alien8.de,linux.intel.com,kernel.org,zytor.com,linux-foundation.org,googlegroups.com];
	MIME_TRACE(0.00)[0:+];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[15];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[andrew.cooper3@citrix.com];
	NEURAL_HAM(-0.00)[-0.999];
	RCVD_COUNT_FIVE(0.00)[5];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[alien8.de:email,linutronix.de:email,linux-foundation.org:email,zytor.com:email,citrix.com:replyto,citrix.com:email,citrix.com:mid,intel.com:email,googlegroups.com:email,googlegroups.com:dkim,mail-lf1-x13c.google.com:helo,mail-lf1-x13c.google.com:rdns]
X-Rspamd-Queue-Id: E63F18D922
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
v2:
 * Fix a spelling mistake in the comment.
---
 arch/x86/include/asm/kfence.h | 7 ++++---
 1 file changed, 4 insertions(+), 3 deletions(-)

diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.h
index acf9ffa1a171..dfd5c74ba41a 100644
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
+	 * Otherwise, flip the Present bit, taking care to avoid writing an
 	 * L1TF-vulnerable PTE (not present, without the high address bits
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260126211046.2096622-1-andrew.cooper3%40citrix.com.
