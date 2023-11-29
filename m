Return-Path: <kasan-dev+bncBAABBYEVTSVQMGQERZN5UVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4671E7FD35B
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 10:56:50 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-285adda4d3dsf5553316a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 01:56:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701251809; cv=pass;
        d=google.com; s=arc-20160816;
        b=cBA7hpSIsnt+Qd8dUfGhwicO1K3BDNk/T7g3UZfA97KuGzoQpoa8KaRj5nLnfFdrsf
         LSezTU04KUkqzhng/UwznfYj109VfqvgDjakJXeoZ/88h49eWI/LogE6Kr6F3pyNx3rU
         lFjFDq1e2t9sPJ5rbftLzZhbEMa5JMnCB2puxufklcUcesEJVY6YmrzWVsUPEhlw4VOm
         m8PlieDaYdaWj4xmvhxlb4o5fOWqcb5MQRCIimznxCve/Ake2vqYB6jXPBNxrA8JoP12
         juKV/uDekdwJzY+7Pq2DG9SfTxMFdHD5EMmR+gKNPYCm9saGexwylW4FjLD8Zb2He5jk
         dIyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=rGHROt905Q0TAKG3YFC4OGxbYwfT8BR3l2nga8nC+eo=;
        fh=BM+YXXPDItJMOh98QtZoCEH1RXzAZsCss4yDzENT5Z4=;
        b=X7GbaIGrY/7G/uBCQZ6caSpi1Y2F/ixwkfkW0ygscb6Fpwypcb7IG008wCVL4CUvad
         JBISVwQP9aBiuEJoEFsazSVIkdQknAz3DaKHf+EmiObR84GRkRcas4sKVcZ/TN3nvggk
         cqwDeeV0gTfgJJOQJ4T06xveJFznaNLUEQHiZvTAaPSy6Z099RVmA2xVmiCnYnCYw1cs
         wZFRvJwRp6RfFt9cUJlrS8uBqM7/a4R+omHXMq0T24OB80Wjk3JczyWwCn+Uji9g3CfV
         /F8CsSbxHUjI04rmtC/kHnNioaRMBbusMpBYx0/dF7nea/yIJFZvctMKHcAnqMUtSieZ
         MgbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=inSOz4yT;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701251809; x=1701856609; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=rGHROt905Q0TAKG3YFC4OGxbYwfT8BR3l2nga8nC+eo=;
        b=mTd5K+ZD0tfHFsywRWnPi55lWEWuJ8Ph7WmNhD0cTKoo58KHV54kmfhgfwI5ryygV8
         Iqj4to5Rb+W/DT6+5eW+OgE/0eO2Y2sJ2JENQH8RI/DKqdux1xlccnBZ1QTuu3+y6p25
         7ATU4OW6m4c/SF+R8agxcxn2yWN3Jd6f8J8gt96Q8ijqEMJMRvZMUbHQeH5ux95ChTS7
         od2YQE4JyJHQbMcaMbqOnLkwHbeRI73Sx7bGMqDVHgdifRd4PDICdvHs9FZGF2rvG4kj
         +Ocj2nfB7H9MBRGlFM6GQkQ1rNQIg4phT63R4dFwcBAKmlaZwBCkSi3nXJWAGz8eKCxO
         /H7A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701251809; x=1701856609;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=rGHROt905Q0TAKG3YFC4OGxbYwfT8BR3l2nga8nC+eo=;
        b=VkJZmn6bNpVWM7BIK+aqpjCdVBg5J5m+piMSJLdOLJW4P70RahVZ/ENaXVgMQ83ruB
         UhL+ahVOB33/mr8wNheGwGgrTZ83tb+1Z0BNBDrDJ4vW5XvQmwkzksQwiaS9DazVR6La
         j7hQGLKoCtoqxRlk6cMvNLAS0GKJGZNkmj1QDX+ZdWSyawWyeLabhx2o9JUAVCmfyxJ/
         eoV3j3idmzU2ZH4i0tJLRBm1dH6YDb5g91365lACjRPP10w96VqObfIBdQEXBo/7FiDW
         Ate68QN/fQ1PYq4NPQYqEjYk0ni3b9s63lMSfZR/qIrjWgvdwbod6OvWuWTwUGPR9Ko4
         EgHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwVd9OE7AjlcZE/0NhRBXOtuqEcKtYyltmPLkwqERdwSA96AjTU
	N7oJlOvHDRdKcLwGGNe2TOk=
X-Google-Smtp-Source: AGHT+IFLA4kFmoyYjgLT78IrBtMark+uz8TJH8zXd6WqyCzQmhnAJFFlqBelNdmPLxsB2dB7QrcBlA==
X-Received: by 2002:a17:90a:d494:b0:285:8939:c4b3 with SMTP id s20-20020a17090ad49400b002858939c4b3mr17099755pju.13.1701251808851;
        Wed, 29 Nov 2023 01:56:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:ad4a:b0:285:8816:b36c with SMTP id
 w10-20020a17090aad4a00b002858816b36cls3759041pjv.1.-pod-prod-02-us; Wed, 29
 Nov 2023 01:56:48 -0800 (PST)
X-Received: by 2002:a17:90b:23c2:b0:285:67e4:eb3f with SMTP id md2-20020a17090b23c200b0028567e4eb3fmr3740710pjb.2.1701251808237;
        Wed, 29 Nov 2023 01:56:48 -0800 (PST)
Received: by 2002:a05:620a:2410:b0:778:a9dc:3cb2 with SMTP id af79cd13be357-77d641b56c2ms85a;
        Wed, 29 Nov 2023 01:53:40 -0800 (PST)
X-Received: by 2002:ac2:4201:0:b0:50b:c0c1:933f with SMTP id y1-20020ac24201000000b0050bc0c1933fmr2068643lfh.46.1701251618765;
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701251618; cv=none;
        d=google.com; s=arc-20160816;
        b=EEz5G4rBmfQCnQpjIvgdH6TeqixXmVlE1fCFS06jFUMMzULRt2AFbQalP3/GnuJmCz
         KhhHZDBXlgG15zmCNw/huButMFWwow6obGI/03dACu+0thIzL/Hh27bRn7kF2G6nycKd
         ZkofuGB8ARt/VQgOxTtjITUZT7LohMgBJ3ttelrRnqJ4O4Pob3Y9udc3I7OKzfXjMpiE
         afdmL3vYy8FOzYhnnOiUF9+2/1fjElbNM1GDCwlCpQ7rHId599j8KytHYuII1QajGGV1
         CPhylLb/X4ahH7FZr+vaSPDUuCwANLpEKZk5qPs+/Eco5uykFjLjbUhyC3pUuuwKgnW1
         pCXQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=OzJx1XLcKpfOVPPxGeC45HXa1Ww2Cw/dmnDirEUeMrA=;
        fh=BM+YXXPDItJMOh98QtZoCEH1RXzAZsCss4yDzENT5Z4=;
        b=o9tCpjye324swR1CRyneCTT/SNU28ubvoAkzG85qo2CxbvNBehZwecVmvKwqgIoKl8
         RNzgfTHw83PWJKvZ5jJ2ZQnMg+sLPcKkm01Os8GFAuuEh33Dtsw0h+vSMTeilbcCN1fd
         HKf8FO3t/f5bMeKg4mk4Aok7mFPBzME3wqa4H9qi6+8/4e6oqpZ/K2AOlfhAiwbfmfK4
         qDiz/guRlFsnrVp5C/JY0jJ0MNZ9v9Oe/MGF0CivJ0uSIFdYYNlKFq3FnQPKB2Br1uX9
         4CbDdr1qyAOlTBY/kz0hGVnLdnyF5L0WR+mmP0v15ecXTD6xb4WypFgOcFAHE4YZYsNM
         Dt+w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=inSOz4yT;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id k33-20020a0565123da100b004ffa201cad8si731161lfv.9.2023.11.29.01.53.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Nov 2023 01:53:38 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id F1F931F8BE;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AC77013AA1;
	Wed, 29 Nov 2023 09:53:37 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id aFDSKSEKZ2UrfQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 29 Nov 2023 09:53:37 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 29 Nov 2023 10:53:34 +0100
Subject: [PATCH RFC v3 9/9] maple_tree: replace preallocation with slub
 percpu array prefill
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231129-slub-percpu-caches-v3-9-6bcf536772bc@suse.cz>
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
X-Spam-Flag: NO
X-Spam-Level: 
X-Spamd-Result: default: False [0.20 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 BAYES_HAM(-0.00)[29.13%];
	 RCVD_COUNT_THREE(0.00)[3];
	 R_RATELIMIT(0.00)[to_ip_from(RLtz7ce9b89hw8xzamye9qeynd)];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[16];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,linux.dev,gmail.com,google.com,kvack.org,vger.kernel.org,lists.infradead.org,googlegroups.com];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: 0.20
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=inSOz4yT;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

With the percpu array we can try not doing the preallocations in maple
tree, and instead make sure the percpu array is prefilled, and using
GFP_ATOMIC in places that relied on the preallocation (in case we miss
or fail trylock on the array), i.e. mas_store_prealloc(). For now simply
add __GFP_NOFAIL there as well.
---
 lib/maple_tree.c | 17 ++++++-----------
 1 file changed, 6 insertions(+), 11 deletions(-)

diff --git a/lib/maple_tree.c b/lib/maple_tree.c
index f5c0bca2c5d7..d84a0c0fe83b 100644
--- a/lib/maple_tree.c
+++ b/lib/maple_tree.c
@@ -5452,7 +5452,12 @@ void mas_store_prealloc(struct ma_state *mas, void *entry)
 
 	mas_wr_store_setup(&wr_mas);
 	trace_ma_write(__func__, mas, 0, entry);
+
+retry:
 	mas_wr_store_entry(&wr_mas);
+	if (unlikely(mas_nomem(mas, GFP_ATOMIC | __GFP_NOFAIL)))
+		goto retry;
+
 	MAS_WR_BUG_ON(&wr_mas, mas_is_err(mas));
 	mas_destroy(mas);
 }
@@ -5471,8 +5476,6 @@ int mas_preallocate(struct ma_state *mas, void *entry, gfp_t gfp)
 	MA_WR_STATE(wr_mas, mas, entry);
 	unsigned char node_size;
 	int request = 1;
-	int ret;
-
 
 	if (unlikely(!mas->index && mas->last == ULONG_MAX))
 		goto ask_now;
@@ -5512,16 +5515,8 @@ int mas_preallocate(struct ma_state *mas, void *entry, gfp_t gfp)
 
 	/* node store, slot store needs one node */
 ask_now:
-	mas_node_count_gfp(mas, request, gfp);
-	if (likely(!mas_is_err(mas)))
-		return 0;
+	return kmem_cache_prefill_percpu_array(maple_node_cache, request, gfp);
 
-	mas_set_alloc_req(mas, 0);
-	ret = xa_err(mas->node);
-	mas_reset(mas);
-	mas_destroy(mas);
-	mas_reset(mas);
-	return ret;
 }
 EXPORT_SYMBOL_GPL(mas_preallocate);
 

-- 
2.43.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231129-slub-percpu-caches-v3-9-6bcf536772bc%40suse.cz.
