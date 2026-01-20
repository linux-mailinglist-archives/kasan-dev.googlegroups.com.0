Return-Path: <kasan-dev+bncBDJY5C7M4EMRBTOUX3FQMGQE32OAEKA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id GNgVJ0+qb2lUEwAAu9opvQ
	(envelope-from <kasan-dev+bncBDJY5C7M4EMRBTOUX3FQMGQE32OAEKA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:16:15 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3EA064737C
	for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 17:16:15 +0100 (CET)
Received: by mail-wm1-x33d.google.com with SMTP id 5b1f17b1804b1-47d4029340asf51762515e9.3
        for <lists+kasan-dev@lfdr.de>; Tue, 20 Jan 2026 08:16:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768925774; cv=pass;
        d=google.com; s=arc-20240605;
        b=FrYx9sQMRZuFPn2W1KT3GQiHUme7n26CbRRRWzuoE+jwFKTpinzohsqKY4DfQ/KnJP
         Jp/afi717RZpAZHMgqZeMYxLeckv5VP9Q9yUinE8vdiv30fF4iearlYG+N8dxdMgfKc7
         0Pox7o6H+gjsm2GH5oNAYNjCMaA05FXvSlvY9EERKNJFLfMfmue6o0U7VeXiF4ps99Kp
         XMtFIuXZOBDFxuHYMeSRhnoZbnts4FKTwCWG/Rz20O/nWzNZkUSLu/mubD+Jl6l18f8H
         bsILu5SlbSBeoJWWYUlSB/QWjTKlk0TWbEXcwzmNDH42FnWL6PS4gfpR6ylBlpmLRAVd
         mshg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:mime-version:date:dkim-signature;
        bh=ltRf2si2kLCfA0VeLIMc31E2il+htIYFPrh1aIy4gAk=;
        fh=b8CViXPiY9kx68lyfbI2bpFO1+0WLOHDY5wDOFj5YZs=;
        b=eBV6Hys7v5mSmF+faoC3/P1ZElGX+6mAhv4Dki72RqFU8aWLmw3uC+OIx3DV4NrR8i
         sw3HAqBwFnrKhFFnLz9Khc2fUNHsuQDXEgimuos5WTX5BrRF1g/e6+61UZ+ZxR1wh0TM
         MsN8CeVLLW5oqcW+diExEk4T5tIvUN2omJJL5IcJsElmeN6du8aoeJ5A47pUwwcwBLKw
         BWlr3H2wMiVf1W6TBMI3rPPf4EpMA0B2+Er3Wns/d7fPUAX+XuMvduzEDhKiQPg7qJWA
         ODW122o5gJyc3y+SpE597IO94xwHxxbbGTuUNaoC+oHYOKGzwrsgNo9Kq42lgd+6GZwu
         VTew==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=i0k2z96S;
       spf=pass (google.com: domain of 3s6pvaqukcbafycodweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--pimyn.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3S6pvaQUKCbAfYcodWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--pimyn.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768925774; x=1769530574; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ltRf2si2kLCfA0VeLIMc31E2il+htIYFPrh1aIy4gAk=;
        b=UjIFLw78mAliYM0ExyGciEpfZooMRtFKBZav9vD0sPds+PsqLALUZi2Tf+iEjAGFK4
         rq8AB5dSrK5T8KOy9F3JkRSNxq1Gp6bjqFuu7D0J5yLQ888yh3YG9aqTqXWgesSsxc+K
         U4VZIRnO48bYt6zwPZHt03bZKp+euiT+dV1+WslGz7twvA/VphetZe9GX3UmZfdagVgq
         ogt4+U/4PM1/my07xhN5Z3yzV2GzTSlKixT/1dT//AqmY0rj3+jNfAhyKHqKBdBX45JE
         9cu6k613IP+Zh1Eny/f70y4c2FmbQSnfVQLxH0hWClzy16Ov+wfPMPiF/Afynz1mokF6
         atjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768925774; x=1769530574;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:mime-version:date:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ltRf2si2kLCfA0VeLIMc31E2il+htIYFPrh1aIy4gAk=;
        b=MnBH1v+H4nfMUXR5YkzjNWDrjMilDB8Ujptvr5c31po81kfVtb71Rbp0C9GJl1Q+T0
         29dHoykqh30NNiw9tsxEFFyuOfeLu6r6CNp9AQMggJ0LYoCxAQ8JNRy0yvudFejVZ3l1
         EZgT/PGHbXzLYuKCAdOtH4jrqC4nRLQ9by2DRUGkjWj8z414r0OY0XwMMLvoxfuDFRwY
         djPxEZMeUGp53cPQ1Dm08SGjSQVYpEoHojvMWevGHX7wqYeoN02e3DuTs3QQD75vghfj
         WSH00193clxSRg4PtcVBln42tEo/UYvu65P32lm9fHlsDlRsrHKMs7+RWXWMW5Rqws+k
         6WhQ==
X-Forwarded-Encrypted: i=2; AJvYcCW+F2BXRAYYOlCt049WVC0TRsBOTjPJ6INDlcvkqPHGiix8fORcG+TEAIpcBgM77tFlcphkkA==@lfdr.de
X-Gm-Message-State: AOJu0YwJwJPOfqCRhRAlx12vxS5NcFOwhgnP62DZ09kQr2QhiYdEAtkQ
	Wss0HsDHAp8LLkuy9ozuRWqnQDt29Y7wljv9Be5rsn2xuOmluv77f4XE
X-Received: by 2002:a05:600c:524a:b0:47a:935f:61a0 with SMTP id 5b1f17b1804b1-4803e710fa6mr36179695e9.0.1768925774480;
        Tue, 20 Jan 2026 08:16:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GJAImFgub56ugAOHalAIJPux5HgQLwQ2Oqf8iTCig6Eg=="
Received: by 2002:a05:600c:1c16:b0:47e:c74a:d81a with SMTP id
 5b1f17b1804b1-47f3b7e1129ls30557735e9.2.-pod-prod-09-eu; Tue, 20 Jan 2026
 08:16:12 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXv1Segi6aTIkVUelZQuG8kPBVlTof4SvMFZm+y3rYQBUHB7Qgye0vCJZtAzUCbCSkdttTL+pAjivY=@googlegroups.com
X-Received: by 2002:a05:6000:1448:b0:430:ff8b:fdc2 with SMTP id ffacd0b85a97d-4358ff3a262mr3822112f8f.60.1768925772288;
        Tue, 20 Jan 2026 08:16:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768925772; cv=none;
        d=google.com; s=arc-20240605;
        b=VWmUnDEd+zcAnnUdW1qqhVA+LWWJaxVy+DCUbrvSqO9gjz5xcRAOTM8bAOtT9McO+J
         f/N92ffpJ+w0ki/kGjydd9o/lQ+YetRWShB6n+QlfOcCsD0qEK58ynVsIAitcbKKZY3N
         nLBW5GqsalSG7dI0BwGAF9RdeINJqNHMgwKAGhVH++mAOzn4Ls/KYCfVtiBJ/x22/Wp4
         ghkbd0UvOx/jNGBBRTLs3jjYoJ653LtyAUa8yvJyUDS1wJqA114FCgeofdxwogXgZCfZ
         iEId3rtFGDBV5D1RuxljLGhVjVtIi2rt0j+48YDHdQ3gW327MYILPi9Q9FHexf5Plra2
         GKow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:mime-version:date:dkim-signature;
        bh=zECdq2qx8LIRzMbM9dI3FS5kU++am0Lig5cv/EMeCDY=;
        fh=p8uNtbtR5sEczilpwiE3OIHS3lcUZxwmNJiKfiKPYQs=;
        b=aHX1pV+BZnUf+4qPnn26iu3V9fdhxS18Ur63ekRm72Fq8qqeUTtD/3dzWYT5HDVIez
         kMMe2SXjsz5qcqV5Es+uNTztJSc1uGAjfB9bR4/qk3WIEWnM2qCcZw2BH0bBgwe36xLK
         H18i7KEWhyPFc31wJqB7MTcDcVgRRaYieZg3enJAsifRNimexs7lMrb8Z8gY+x71vbDs
         vOayVP1/QrWftdmVb3qoJ6+UbonpwBFulbbrhO4K9OIsPB0l788LCV27aaYwXqsXnFi6
         jq3WWE6fl4eA5dEAE3qyz8Pb+riVswn4EH6bkYG3RS0OHwqWkAMZ5VibEoro5RTJT0wX
         IMjA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=i0k2z96S;
       spf=pass (google.com: domain of 3s6pvaqukcbafycodweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--pimyn.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3S6pvaQUKCbAfYcodWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--pimyn.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435699214e2si221194f8f.1.2026.01.20.08.16.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 20 Jan 2026 08:16:12 -0800 (PST)
Received-SPF: pass (google.com: domain of 3s6pvaqukcbafycodweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--pimyn.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id 5b1f17b1804b1-47ee868f5adso42731855e9.0
        for <kasan-dev@googlegroups.com>; Tue, 20 Jan 2026 08:16:12 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXVM+s5SFG+qI41tUnLCHTIlGbESpJSO7t//IKi+OGIe89jpMCCBgUfhZEXRhk7hpEHgzCC5OPhnjk=@googlegroups.com
X-Received: from wmsm27.prod.google.com ([2002:a05:600c:3b1b:b0:477:9769:66d0])
 (user=pimyn job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:8b78:b0:47e:e8c2:905f
 with SMTP id 5b1f17b1804b1-4801e30a790mr216491795e9.8.1768925771811; Tue, 20
 Jan 2026 08:16:11 -0800 (PST)
Date: Tue, 20 Jan 2026 17:15:10 +0100
Mime-Version: 1.0
X-Mailer: git-send-email 2.52.0.457.g6b5491de43-goog
Message-ID: <20260120161510.3289089-1-pimyn@google.com>
Subject: [PATCH] mm/kfence: randomize the freelist on initialization
From: "'Pimyn Girgis' via kasan-dev" <kasan-dev@googlegroups.com>
To: pimyn@google.com
Cc: akpm@linux-foundation.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, elver@google.com, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: pimyn@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=i0k2z96S;       spf=pass
 (google.com: domain of 3s6pvaqukcbafycodweewbu.secaqiqd-tulweewbuwhekfi.sec@flex--pimyn.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3S6pvaQUKCbAfYcodWeeWbU.SecaQiQd-TUlWeeWbUWhekfi.Sec@flex--pimyn.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Pimyn Girgis <pimyn@google.com>
Reply-To: Pimyn Girgis <pimyn@google.com>
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
X-Spamd-Result: default: False [-0.71 / 15.00];
	MID_CONTAINS_TO(1.00)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	MV_CASE(0.50)[];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBDJY5C7M4EMRBTOUX3FQMGQE32OAEKA];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_SEVEN(0.00)[9];
	TO_DN_NONE(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	HAS_REPLYTO(0.00)[pimyn@google.com];
	DKIM_TRACE(0.00)[googlegroups.com:+]
X-Rspamd-Queue-Id: 3EA064737C
X-Rspamd-Action: no action
X-Rspamd-Server: lfdr

Randomize the KFENCE freelist during pool initialization to make allocation
patterns less predictable. This is achieved by shuffling the order in which
metadata objects are added to the freelist using get_random_u32_below().

Additionally, ensure the error path correctly calculates the address range
to be reset if initialization fails, as the address increment logic has
been moved to a separate loop.

Cc: stable@vger.kernel.org
Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
Signed-off-by: Pimyn Girgis <pimyn@google.com>
---
 mm/kfence/core.c | 23 +++++++++++++++++++----
 1 file changed, 19 insertions(+), 4 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 577a1699c553..9e8b3cfd3f76 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -596,7 +596,7 @@ static void rcu_guarded_free(struct rcu_head *h)
 static unsigned long kfence_init_pool(void)
 {
 	unsigned long addr, start_pfn;
-	int i;
+	int i, rand;
 
 	if (!arch_kfence_init_pool())
 		return (unsigned long)__kfence_pool;
@@ -647,13 +647,27 @@ static unsigned long kfence_init_pool(void)
 		INIT_LIST_HEAD(&meta->list);
 		raw_spin_lock_init(&meta->lock);
 		meta->state = KFENCE_OBJECT_UNUSED;
-		meta->addr = addr; /* Initialize for validation in metadata_to_pageaddr(). */
-		list_add_tail(&meta->list, &kfence_freelist);
+		/* Use addr to randomize the freelist. */
+		meta->addr = i;
 
 		/* Protect the right redzone. */
-		if (unlikely(!kfence_protect(addr + PAGE_SIZE)))
+		if (unlikely(!kfence_protect(addr + 2 * i * PAGE_SIZE + PAGE_SIZE)))
 			goto reset_slab;
+	}
+
+	for (i = CONFIG_KFENCE_NUM_OBJECTS; i > 0; i--) {
+		rand = get_random_u32_below(i);
+		swap(kfence_metadata_init[i - 1].addr, kfence_metadata_init[rand].addr);
+	}
 
+	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+		struct kfence_metadata *meta_1 = &kfence_metadata_init[i];
+		struct kfence_metadata *meta_2 = &kfence_metadata_init[meta_1->addr];
+
+		list_add_tail(&meta_2->list, &kfence_freelist);
+	}
+	for (i = 0; i < CONFIG_KFENCE_NUM_OBJECTS; i++) {
+		kfence_metadata_init[i].addr = addr;
 		addr += 2 * PAGE_SIZE;
 	}
 
@@ -666,6 +680,7 @@ static unsigned long kfence_init_pool(void)
 	return 0;
 
 reset_slab:
+	addr += 2 * i * PAGE_SIZE;
 	for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
 		struct page *page;
 
-- 
2.52.0.457.g6b5491de43-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260120161510.3289089-1-pimyn%40google.com.
