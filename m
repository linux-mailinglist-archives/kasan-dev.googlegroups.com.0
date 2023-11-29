Return-Path: <kasan-dev+bncBAABBYEVTSVQMGQERZN5UVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23f.google.com (mail-oi1-x23f.google.com [IPv6:2607:f8b0:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id E7C6D7FD35A
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:49 +0100 (CET)
Received: by mail-oi1-x23f.google.com with SMTP id 5614622812f47-3b2e7a8fbbdsf7309054b6e.1
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251808; cv=pass;
        d=google.com; s=arc-20160816;
        b=KjhAGFkXGuuBPQo5RVi0M+mRMYvroTfw9K806vZYt/TlPBKhtrmu/oMRYm/elSouBS
         2AmMy/WBJ2Oei2AB8ezGC0zqeCJrMwcncSYDvz4C0+BvR69Ajv31ULFNYsJIEjx8aYBs
         X5tBTYo6srlJqwWfviWS3iNFVYLLglG6IPlfALpnEzmeMo/Vxjb+cFl5pieHUHwR5AII
         lUZvuNHDlVxqPitetB+nJVLUjX2fO1L4m+2+2p53oLv9lDY4zqxrDyNthBpV6tCkxt7v
         4b5oYYEmIaFhgrIo4GZOJ6beLg2csyEBRGj/zgcFaj1wOw40gUhx4biN9lmpyTCaM40k
         FqyA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=k/PGACigi/FSr7YF3X6InU3ToLSoxG+gBVLuyhQtLgk=;
        fh=BM+YXXPDItJMOh98QtZoCEH1RXzAZsCss4yDzENT5Z4=;
        b=g1Rx5l7ssMTLQcTysfisFzfquJcOPIXb1ab8904c+DUZ/Gc2ZIhxTQFByQbBVWR56+
         kTQcMkBP+bS+6j4QNJBeiANPTIf3FdQQDxWjRM2cdDU2qNB30pbop7Vr8RO9TOZl/s6j
         lLHcaHQhvAJB5VZvBGaydpzUCOHGOe4gjLaJY3zgeM1aIn/r//OMlCkdU6d3C/GyG7Dh
         YByQe/hBi027Qbltr4zx65dBDn/fMescijNjamrXEu/X/PvUAdBA1/T0dmhtGCJW6C9k
         XlG466HnrSYv9o2fTyabhXJUI8GQpb0aZg5TUXdkLjWMICrQJDJpbZn3lfvcSXbCy3Nz
         r8Bw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251808; x=1701856608; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k/PGACigi/FSr7YF3X6InU3ToLSoxG+gBVLuyhQtLgk=;
        b=KQJsprFaJCfZLZgVAgHHb71Hg882yGGuX+hfrtTH0AcgGHldRN/XdBkyB+p674+BDb
         /5nY+zKS+FRIf5FWHrpuW5pTrnkrcLfLLMPGnQYltwd8bChD/axEBHpEhwWe4sCbrbcy
         OncAEH+BkcqZcps0eSAq1XsdSRlzTW74sbonYSI5NiM7poY23f84BWFBu2ZAnlIDu47S
         yo5fg6+iwI/bnB/ZUgUtRs7DiqjXgY0tlBMwiYdfg8DnXaX2dBOScHIa0SlY1u/78pIx
         jPpBH/rgydMbQUKjKS4AFlgc+14ayJvxtCfIiKGRKLD2lxzmDYUK8RnU/CvlLKL5KCx8
         uQOg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251808; x=1701856608;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=k/PGACigi/FSr7YF3X6InU3ToLSoxG+gBVLuyhQtLgk=;
        b=Ont4p/Mj4nPEmH8loAcrGcaMV4kV+DBYxUwAc93Q/fv1ZsCquaWzQvSFMcFU/f6yNo
         g477RXKwk7err8OfLb47pfMJWVTGXkRxgov0un+9XPGnbFixuS5E2dCyvQZSIrjL8O40
         5bPyCcrpyFTDPd7y2i3/7hBrBP0ypbtNV60AZLDUr4wkJO8fE7JomGq+ac5v71vlZlgg
         PLlQRzD/ollY2FREU1Z9Cszm9Peo6z5rrRc3xv01aUNo9gABbHJibfVWeG98EFS8QE/u
         zKj+tOpXkCYmRP9BTCi168pBWQY5Zwufenws6Ej39vzsUqqXXPy1oeUCZO7qsr5X/aP1
         jrmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyTeunOHG8n9NHW4PQxJQbSwi9HQXwFGbE2xqyytWX6sOMpn7DV
	8kE8SHTbw+zXQ+Y84T/lf6Q=
X-Google-Smtp-Source: AGHT+IHtqKzwiI0Rx1x+yZgPF3iFWW2htiGE0wcopXeojDUYdL1tOxaFbUgLH/B88ZzferQM1Zbiaw==
X-Received: by 2002:a05:6808:2088:b0:3b8:5e81:bc81 with SMTP id s8-20020a056808208800b003b85e81bc81mr13629989oiw.15.1701251808682;
        Wed, 29 Nov 2023 01:56:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:82d4:0:b0:6cb:bb61:5684 with SMTP id f20-20020aa782d4000000b006cbbb615684ls154497pfn.2.-pod-prod-07-us;
 Wed, 29 Nov 2023 01:56:48 -0800 (PST)
X-Received: by 2002:a63:a1e:0:b0:5c1:8ec:cbee with SMTP id 30-20020a630a1e000000b005c108eccbeemr3009738pgk.2.1701251808071;
        Wed, 29 Nov 2023 01:56:48 -0800 (PST)
Received: by 2002:a05:620a:170d:b0:77d:a5e0:dc7c with SMTP id af79cd13be357-77da5e0dd27ms85a;
        Wed, 29 Nov 2023 01:53:40 -0800 (PST)
X-Received: by 2002:a05:6512:3d91:b0:50a:a6e2:ae73 with SMTP id k17-20020a0565123d9100b0050aa6e2ae73mr10646240lfv.44.1701251618765;
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251618; cv=none;
        d=google.com; s=arc-20160816;
        b=gSTsoh9jOgL0eVL5vPnQ4wTh8g3Wdce1Gn71zWVKDJsHGiMkJP2AyR+4L1XPm1bByC
         oeR7tCo3FR4T+h3pdlotpq9RDvU6OO+RlttXDPQPRyVWDTV3VVxT2oZdaJrWnsi9W297
         bPt/6Tvd/VI87GHNiESUMF9W5K8Y3Bch6bY9EV7fBBVZKfF6c9VO/ijmz3MjGKu/7TAy
         yISZqHAWgx05Rv9C9aCFdf2HYWDfxnl1q688uYKikqiyMW+2DRTrEPsVLVx+UMYmTAdS
         L15LX6VbbFMXgNLBn+u5Jmu+X0JmmROeDUftrex34Ul+xSWOXXVdPFHaT1/t1/W/RkIq
         uVLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=sIzawMHw0qEvdtsrb8CaYai+9KHMb5Dh5VZ/ALQ2CnQ=;
        fh=BM+YXXPDItJMOh98QtZoCEH1RXzAZsCss4yDzENT5Z4=;
        b=ObT7QBgq635buT/rtXzbObvKs3RRL80oLd18zHoGYcCSWiDQ4N+CDb4u9Zsu6NnUg5
         lkTJbPFLgp1jJGosqyL0HdqIh5rM2ZmXgXBI7z0tKpOcRIcPYtt5wtokDaO0lEXgg9cs
         tRyj8k/apA+xFoojkJZot2bKlbgu9ivSE3jcPjSLJgvSgj+aNHjA7QNmaBI25D4gmZpr
         02kuo+WstEQ5nYxboQxn9nm4+ev6i+LIWt3Xz9pGcPps+5DAeN96goHp4V7Jl5oXcJLc
         bX7C4ZL4J/Iwf5gTGggI7MfuGr6o9dG7GJDwft6bMsvG6QTWd9UbcnEXg1m5Lo4V/cNA
         iPqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id i21-20020a056512341500b0050bc7296c7csi29769lfr.2.2023.11.29.01.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id EE57F1F8BB;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 73E2B13A9E;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id eE8DHCEKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 29 Nov 2023 10:53:32 +0100
Subject: [PATCH RFC v3 7/9] maple_tree: use slub percpu array
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231129-slub-percpu-caches-v3-7-6bcf536772bc@suse.cz>
References: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
In-Reply-To: <20231129-slub-percpu-caches-v3-0-6bcf536772bc@suse.cz>
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
 Matthew Wilcox <willy@infradead.org>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, maple-tree@lists.infradead.org, 
 kasan-dev@googlegroups.com
X-Mailer: b4 0.12.4
X-Spamd-Bar: ++++++++++++
X-Spam-Score: 12.58
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: EE57F1F8BB
X-Spam-Flag: NO
X-Spam-Level: ************
X-Spamd-Result: default: False [12.58 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_SPF_SOFTFAIL(4.60)[~all:c];
	 R_RATELIMIT(0.00)[to_ip_from(RLhc4kaujr6ihojcnjq7c1jwbi)];
	 RCVD_COUNT_THREE(0.00)[3];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-0.999];
	 FROM_EQ_ENVFROM(0.00)[];
	 R_DKIM_NA(2.20)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.00)[28.50%];
	 ARC_NA(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 NEURAL_SPAM_LONG(3.39)[0.969];
	 RCPT_COUNT_TWELVE(0.00)[16];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,lists.infradead.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Just make sure the maple_node_cache has a percpu array of size 32.

Will break with CONFIG_SLAB.
---
 lib/maple_tree.c | 9 ++++++++-
 1 file changed, 8 insertions(+), 1 deletion(-)

diff --git a/lib/maple_tree.c b/lib/maple_tree.c
index bb24d84a4922..d9e7088fd9a7 100644
--- a/lib/maple_tree.c
+++ b/lib/maple_tree.c
@@ -6213,9 +6213,16 @@ bool mas_nomem(struct ma_state *mas, gfp_t gfp)
 
 void __init maple_tree_init(void)
 {
+	int ret;
+
 	maple_node_cache = kmem_cache_create("maple_node",
 			sizeof(struct maple_node), sizeof(struct maple_node),
-			SLAB_PANIC, NULL);
+			SLAB_PANIC | SLAB_NO_MERGE, NULL);
+
+	ret = kmem_cache_setup_percpu_array(maple_node_cache, 32);
+
+	if (ret)
+		pr_warn("error %d creating percpu_array for maple_node_cache\n", ret);
 }
 
 /**

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-7-6bcf536772bc%40suse.cz.
