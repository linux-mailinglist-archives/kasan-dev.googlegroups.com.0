Return-Path: <kasan-dev+bncBAABBVUVTSVQMGQESOO3BAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id C805E7FD357
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:39 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 3f1490d57ef6-da040c021aesf9015927276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251798; cv=pass;
        d=google.com; s=arc-20160816;
        b=BS8mFDEH/wVR2/3E2Ul8LFhk1jm3RvO5k1/o+eSXFQbd1rpl1rHnlse33AKOV42Gx+
         YE5+PtL4UGndafrb3AU6M4EBTmC8YB0XBSgUicgpptqZ7muutu9t+wM/TAmZhPgJ7TpY
         GDl6ISla5gIEWj6RGzoiPfXgsnpS9nD5faRmRBJxbWu1ANV8dMleCyTACRSuZqc8Mu+K
         9OAMYPZGO3u2L1mgn1U04an8k10UtatrUGvwtn0sSoWAS/j42pOvyWsaKoVtrdQjKGyJ
         dmZDQtBchs/SWf8aiLtfE56WuzTaOP+HPzzF0SPcVR8F3H8b/MGleF93qM3ZJbMAEttb
         Uigw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=1dZAE5fC+mlxsqXeOQsCcr35aHKLMTrbOU6fehH7jJ8=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=svOOSVxDH6tS4Y7LBGGe3C4tl2FkFTT8Tqr20FGblV5maQ2h+vkD6ObTWSLWWIRnTG
         xajhmfx/nHhODLWlItKJ2juUGDj14BO1itvX8VuMD9mjfSrGppGCRZ0yEmeWlgN/ITi2
         62kuc0XE+LuleRJrvnfEsM5pyyNqg0ASxo9c+WxLIvXjW61qt8YFGG5iaz90Fe5DgC5R
         iGTK53FdoodMpdiCHosZyDm07NdIbHlzkYQZqP8EdtQPHPVn/BNdFNFGf0CBhY4IFZFW
         O1Qorze1Yq4ZXpmxUicPnOvpFjtmh0F0Uo2crtyY8bpesXyJMRBQIy0JQydIX0mf7SFI
         K6ag==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251798; x=1701856598; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1dZAE5fC+mlxsqXeOQsCcr35aHKLMTrbOU6fehH7jJ8=;
        b=uL3LjUWECDisxZVXO5lDJS9gyL/tJjnJOSWlVXzfEoj1hHYnlR2mSggrpbHggQ24Ka
         g9f9dZhSaTuIJvUVbpjh4wDrhXydODtFPhvpIU1h5EsI755+RP4wBNLfTxCUydJIqDiT
         86DsqiSCWX7l0QFyOeAOtNvhvw95Xw0CqSQ8QtXX9xJH9n/2DnR0GE6QLTvDaEEtusPg
         Y17By23MR4lICih6BPCiNVEAZMggeQsU0M/SY1/yBZ+3ngylq+rvJURXc1I4efW0Q2ru
         ogu3pfGuGH7wTHaGt9cMinrReVyUTItUFaH8PT6vdXpa/yD6Eb+xZ7RrV1J/7ND97WR5
         +nfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251798; x=1701856598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1dZAE5fC+mlxsqXeOQsCcr35aHKLMTrbOU6fehH7jJ8=;
        b=pX4zKvcUzJM5rL443MpPagcj6khlRPEAQqFw0h+2KCFnJ6Kkdjd2OHOtDzpNQ6rrar
         Xx9iIKSMFcyCHAenRB6J2DXqoOkxYq3VrL2KyJmu5g/lwjEdh9Ftmw+fujO7g0ueqHSd
         5fE6jXvvpv2ykpz4T5v+tEsWpYXDJtOxtWAK9gIP9Llx8X6xqTbu2Q+2OyCNheGn/Q2j
         wPbXrPDTGLkwOKDWHIIS/u3fon2AVhkJNtr1tH96Ug2n5PPMZZgEzafdr5cMn0ant8/e
         qStClfD+FJdJ1XSPcm10C5JrxXJVlVPXe3Fgvr5q7pDg08/27lP/7ueHl4Rb5YmWYudC
         XKwQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy3bxTlAlTKDBPD3AjPuJ0mskAT+Pq+57IWExdKPXj7GzzmiOA8
	KJBAAEsbV13ZqEqcqA+Ah9o=
X-Google-Smtp-Source: AGHT+IFzWcSTNhqGCQZJge6+oJqmoKulpSDZ7poNMbTbQaY89mOd6V/TcI+qT31zk98tXcZ7yQpxDQ==
X-Received: by 2002:a25:94d:0:b0:d9a:66a1:a957 with SMTP id u13-20020a25094d000000b00d9a66a1a957mr16715844ybm.13.1701251798466;
        Wed, 29 Nov 2023 01:56:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:418c:0:b0:670:a1c0:e4e2 with SMTP id e12-20020ad4418c000000b00670a1c0e4e2ls5147095qvp.1.-pod-prod-04-us;
 Wed, 29 Nov 2023 01:56:38 -0800 (PST)
X-Received: by 2002:a0c:fa46:0:b0:67a:2416:36ba with SMTP id k6-20020a0cfa46000000b0067a241636bamr434848qvo.4.1701251798139;
        Wed, 29 Nov 2023 01:56:38 -0800 (PST)
Received: by 2002:a05:620a:8ec3:b0:77d:cfff:33fb with SMTP id af79cd13be357-77dcfff3957ms85a;
        Wed, 29 Nov 2023 01:53:39 -0800 (PST)
X-Received: by 2002:a05:6402:8d0:b0:54b:e7c8:c9ee with SMTP id d16-20020a05640208d000b0054be7c8c9eemr119181edz.38.1701251618348;
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251618; cv=none;
        d=google.com; s=arc-20160816;
        b=KYPv1JtvnAe0qikMb8yeCsnQVM0nD+513/5IvyQ2bPREIy/XB/InpXxTHC/8GmBe+s
         PTLZsuLAXWuDJr4/uwyhJkL5T5MTBqnT48ZiZrvfzYkKzkgrX81zz6U6NNS0n3pMbzBK
         mjSZCrhCpLfSxGKjSc6TUbDNPufa0NyWFMs4LTHXfJc204v24E3pfJLZWbIAZzcF8hrG
         2Qc9aVezlTxZGEeaMzAWW1/egKjj3KJ363zA3XG8tFXzK/uClg7L0falorpFl8OBFgy8
         uHvw6SuemUHC0PhbmT+lojQkDCuP3dYIFbsjguoQXhXtEKOPt3iVcugk9TVUAeM8P7Yv
         Ijxw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=ItnxEFdMdReUcgI2eC5m3fUPnWv97oIpUOC4WdcPO3w=;
        fh=uYnIsWZ9n80gkcnhZMgoujzKtxA7UEl4GQvTBFLbimw=;
        b=kaH+EPPU8fWQTgYL4Z1zbaWVOHNldaI2vIvq/NnHLxRqW7kGQrmGaWzQ8b/xwyNs18
         fiFiM5KYRCI1ruhtOpD28LmBZRRrDm06oTdHxv9sFRDByE5qaR5cOmkoq8xkXuUCut+S
         ZsPWs9SS9y2j+Xy7NPHXF3+gJImVXS6emi4h24idkbTyEkfFk/FF9uvfUVqURLNCA0Iq
         Q1n0rYOuNdov7bfssIEq/egQVzWENBS03zxt0jFNt1S9nstcQjauEkBQy7TUCdQ3qn/e
         Y7NtQujKiOBmuDwYhvoQUp5a3XQZ3rkLql7OGCyb+fZec5Tlp7Yna++CsbiaG4jlxi3w
         mNUQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id er26-20020a056402449a00b005489dbe8653si718468edb.2.2023.11.29.01.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id EEF061F8BD;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 911A113AA0;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id YPESIyEKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 29 Nov 2023 10:53:33 +0100
Subject: [PATCH RFC v3 8/9] maple_tree: Remove MA_STATE_PREALLOC
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231129-slub-percpu-caches-v3-8-6bcf536772bc@suse.cz>
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
 kasan-dev@googlegroups.com, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: 
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: EEF061F8BD
X-Spam-Score: -4.00
X-Spam-Flag: NO
X-Spamd-Result: default: False [-4.00 / 50.00];
	 TAGGED_RCPT(0.00)[];
	 REPLY(-4.00)[]
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

From: "Liam R. Howlett" <Liam.Howlett@oracle.com>

MA_SATE_PREALLOC was added to catch any writes that try to allocate when
the maple state is being used in preallocation mode.  This can safely be
removed in favour of the percpu array of nodes.

Note that mas_expected_entries() still expects no allocations during
operation and so MA_STATE_BULK can be used in place of preallocations
for this case, which is primarily used for forking.

Signed-off-by: Liam R. Howlett <Liam.Howlett@oracle.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 lib/maple_tree.c | 20 ++++++--------------
 1 file changed, 6 insertions(+), 14 deletions(-)

diff --git a/lib/maple_tree.c b/lib/maple_tree.c
index d9e7088fd9a7..f5c0bca2c5d7 100644
--- a/lib/maple_tree.c
+++ b/lib/maple_tree.c
@@ -68,11 +68,9 @@
  * Maple state flags
  * * MA_STATE_BULK		- Bulk insert mode
  * * MA_STATE_REBALANCE		- Indicate a rebalance during bulk insert
- * * MA_STATE_PREALLOC		- Preallocated nodes, WARN_ON allocation
  */
 #define MA_STATE_BULK		1
 #define MA_STATE_REBALANCE	2
-#define MA_STATE_PREALLOC	4
 
 #define ma_parent_ptr(x) ((struct maple_pnode *)(x))
 #define mas_tree_parent(x) ((unsigned long)(x->tree) | MA_ROOT_PARENT)
@@ -1255,11 +1253,8 @@ static inline void mas_alloc_nodes(struct ma_state *mas, gfp_t gfp)
 		return;
 
 	mas_set_alloc_req(mas, 0);
-	if (mas->mas_flags & MA_STATE_PREALLOC) {
-		if (allocated)
-			return;
-		WARN_ON(!allocated);
-	}
+	if (mas->mas_flags & MA_STATE_BULK)
+		return;
 
 	if (!allocated || mas->alloc->node_count == MAPLE_ALLOC_SLOTS) {
 		node = (struct maple_alloc *)mt_alloc_one(gfp);
@@ -5518,7 +5513,6 @@ int mas_preallocate(struct ma_state *mas, void *entry, gfp_t gfp)
 	/* node store, slot store needs one node */
 ask_now:
 	mas_node_count_gfp(mas, request, gfp);
-	mas->mas_flags |= MA_STATE_PREALLOC;
 	if (likely(!mas_is_err(mas)))
 		return 0;
 
@@ -5561,7 +5555,7 @@ void mas_destroy(struct ma_state *mas)
 
 		mas->mas_flags &= ~MA_STATE_REBALANCE;
 	}
-	mas->mas_flags &= ~(MA_STATE_BULK|MA_STATE_PREALLOC);
+	mas->mas_flags &= ~MA_STATE_BULK;
 
 	total = mas_allocated(mas);
 	while (total) {
@@ -5610,9 +5604,6 @@ int mas_expected_entries(struct ma_state *mas, unsigned long nr_entries)
 	 * of nodes during the operation.
 	 */
 
-	/* Optimize splitting for bulk insert in-order */
-	mas->mas_flags |= MA_STATE_BULK;
-
 	/*
 	 * Avoid overflow, assume a gap between each entry and a trailing null.
 	 * If this is wrong, it just means allocation can happen during
@@ -5629,8 +5620,9 @@ int mas_expected_entries(struct ma_state *mas, unsigned long nr_entries)
 	/* Add working room for split (2 nodes) + new parents */
 	mas_node_count_gfp(mas, nr_nodes + 3, GFP_KERNEL);
 
-	/* Detect if allocations run out */
-	mas->mas_flags |= MA_STATE_PREALLOC;
+	/* Optimize splitting for bulk insert in-order */
+	mas->mas_flags |= MA_STATE_BULK;
+
 
 	if (!mas_is_err(mas))
 		return 0;

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-8-6bcf536772bc%40suse.cz.
