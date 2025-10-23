Return-Path: <kasan-dev+bncBDXYDPH3S4OBBTHG5DDQMGQE45HL5RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id AA95CC018E5
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 15:53:17 +0200 (CEST)
Received: by mail-wr1-x440.google.com with SMTP id ffacd0b85a97d-4270a273b6esf574534f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Oct 2025 06:53:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761227597; cv=pass;
        d=google.com; s=arc-20240605;
        b=bVzuDYMEhk4BVfkWbZnS+CijuMDi+m1tyVjgKN1q1cli1pq8MaXkITQjPnDwUOnvaO
         BDl+HSqCFKQnHWe7mBHOs7C7NoqUo8wHeg14bU8d2M1eP15bpAUA/Jz4+t/6oZo0VE02
         OoTQHjRue4MqUvjVg1PPslzMSxcz7LrYgxPZt1gFMpuHOCbZ4ikW5xP6mqOlZvQ/S8es
         p/BSwmxGlCPs75ceCz9z8z0ctuQ7SiuI8klQFerWGu93be1GWyaEXRJwHvx23rq6iCJS
         m2UctZL0MQBzwToLsd1BN+ARhHN5MAWIwBzzHHN6YQ1l9AnVPd2vSwsbyaCoOGdMhGH7
         61Fw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=WMO9LdhkHYrKCDg1Mih3T5qliSJPgfPwHIngpkj7CJU=;
        fh=xFpm480Q7a8wGTaO6LOmWGpFUKW+4sTNBV8KyCXFSCw=;
        b=XQqXfvwTWgJs31Yi6b/sHFEkwnp+raAx8PrEnc0W/v1z1DGML+Sw18TlQAloEyneTc
         8OyFNk5kD4JxtVgUHlSbMfGrFGTIiXNJRbKcPymMl0LYVK1cVX8/3UmCZ9unB9o3A+MW
         61HX+jV7FyQ/ez2sJ+dFwEAc8a5xsprd9UrejOvSL2C2JDovNgw9mNFUt7Iey6HcnSXl
         uFvZXPtQ1Rm0Lo7CEGAsrf3arRtRJOysBCkZQDBq0vuB/TrhlrdIUiD5+lc1pX5Z1RST
         lJNmW62nT89i14OqSMRIs21K9JNEIlHtCOU1UENHC8u6e2hK9nEkBAyG2YK182hk0pSH
         AYWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761227597; x=1761832397; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WMO9LdhkHYrKCDg1Mih3T5qliSJPgfPwHIngpkj7CJU=;
        b=G7/dPCd72KDZYhRERsfJn0ZQaTmilIJbO09PDSOI6XYZ78H2p0TJQ7lFfkoC2o9fkM
         wjI0xTuCKorNH7UJAoFEYyJ8b9BtGuFD8F3pg1zVYc908hNI+3zN0uJTVB7kXbHTCeMH
         wWJhtnmcXjWWuLl866Lg/firS36Nho33P01lmHvgHwDMni4utKY2bsb9BTMZ2OvD6rRp
         5ZJU7Pqa6GvpTno6zZoAEq6f2i6r6kHFZ1a6n42zEzX3qdP1NtL/6J53EZRAGtyhtGH9
         lXpkuwEXv31vSWox4JDuBbyPu924nC41TRypIOd0SmBRZzTE26/bMF4dWoqpUeqvIobX
         4Bqw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761227597; x=1761832397;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WMO9LdhkHYrKCDg1Mih3T5qliSJPgfPwHIngpkj7CJU=;
        b=jChQLspzBYHjGuhtiZx3pR3BK9WIDbSrrTm+tuuf9Q1dIIsf3R2R2edmCwSR7OUVo7
         9gwzrcKKMCnksHaDz1U7H/Gd2Vui6Sh28oWgV6/dVreuik12i82Kw5Ly9XbLYIyhJd7l
         BZxTjE/3eXz/NVRtxzOKiYnEw9tVhkjlONG3cANOs/KwZVSXcGzztHUkiH9+XfyEbN/8
         anNCKgRTpCGLJqFE5D8v3zqK37DCEJ0qXy2uaEqiMCOzd+h4UaP1WGXVN9AphuNpI8tC
         9oGMlAYck6BMrXl8zUvixf8YiI/NBkMQSyoU3uTs6xoJzbJ6WSdx3+D4RStJ8PkDLTY8
         7x2A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWsD4n6DbFZIs0uuRgtDXeRI4yJq8vfrSa9g9DUZQT6bq8z8s6GMycxoGZIHiX2AQU74y2nOQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy4yUvidWrkYJrxD4+HEy5TfCEpIZwid1dAn/Uu9EoQ6t32PL8n
	GXsZz95M9ixFFiOOBWgWvFcY8Y/H/HMtdfMAFkW/hQGKi0fYOjRhTwgt
X-Google-Smtp-Source: AGHT+IGDKDT8Ntw0o69wzm0tjxDrjag2NdHTUhETMHp0SlR7ejQucjONKQ6poVIs6L4Tw4zrIZMHDQ==
X-Received: by 2002:a05:6000:220c:b0:3de:b99d:d43 with SMTP id ffacd0b85a97d-42704da613emr16062522f8f.19.1761227597083;
        Thu, 23 Oct 2025 06:53:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bMU95NBntQAkpnX5qcdHdbKzV1VgEApSbs4x/CZ//KDw=="
Received: by 2002:a5d:5f91:0:b0:3f8:e016:41ab with SMTP id ffacd0b85a97d-42989c9d925ls429587f8f.0.-pod-prod-03-eu;
 Thu, 23 Oct 2025 06:53:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+tlPUMuSVnZ5GVCR1wGzZD379fRiQYkiIjEzS0c6Mwhp1e/6fWTokas26MZFUO4QnN9VxmaOGoi4=@googlegroups.com
X-Received: by 2002:a05:6000:4285:b0:426:d57a:da9d with SMTP id ffacd0b85a97d-42704e0ef3emr15945398f8f.59.1761227594499;
        Thu, 23 Oct 2025 06:53:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761227594; cv=none;
        d=google.com; s=arc-20240605;
        b=EyWqJ0qwbtSgrSk25xD2s990Az3wgRy3zhaboeL94NKuqTL40vuLNIACX7113K8tv3
         L3KU5i7UR1u+zupJyZ2s5bsjv321XYStdLOawAW9/kwNecZfJEVQShk8+wVz59u5+dHO
         MTsqTvtfJuVs8U1n669e03zBjxVISri17PWpPqEjqgpzzgBIHP+9j08kgM+I8jj2JNNn
         ryOZVbTRnU6PLO5HyaBVwAEMGcY+lYYbzfevSP/yUUSAaujCn/6DnX6eRR6p7W4QlgH3
         p1PtLNHHm6JI32ZhouFIeeUzaZYgviRbwfgX6oUslbZnIOhEjOfsEHyhzjidIm7egS/u
         E7eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=DrlFHykmUtdWxWD3YL+aFPlZh2N+eP7cnHN9uFKsaCA=;
        fh=P0r4/dMJvcdpdyMOyJR1abGuGu+lkksl0rleFR28jng=;
        b=UZb43pkUSiRh3zreRemG+6ktksii5kA52Snp8sccCC/5a+pzn50LvYmY3+n4+ySuO4
         27oF0m87yx9CLkIrxukpK4hp99/fuVCKOjG1JcmGXEGoMmIxcgxGci6JO5mI682EZbiP
         oefqvlALJf5YiyYDXkkAGC0jAaxjkOlCkadyYfZYubjPMFJOZtVQh4cmFfhoCLR5m4N3
         Me3GFYXuy504IECvvhUymJSwT9z4nkMFcveOtBimKpZ/lPimYEneC6fAG6i1jls+WMDE
         X7cZwZeulfp3M2zMCnpNQXAsvFNYDq31+mnsFUOhM/PX0aweux21cCD8+RKElN3L1pYf
         e8CA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-429898a0117si42699f8f.5.2025.10.23.06.53.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Oct 2025 06:53:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id BA61721279;
	Thu, 23 Oct 2025 13:53:01 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id ED1B413B11;
	Thu, 23 Oct 2025 13:52:54 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id OMeeOTYz+mjvQQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Thu, 23 Oct 2025 13:52:54 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Thu, 23 Oct 2025 15:52:41 +0200
Subject: [PATCH RFC 19/19] slab: remove frozen slab checks from
 __slab_free()
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20251023-sheaves-for-all-v1-19-6ffa2c9941c0@suse.cz>
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
To: Andrew Morton <akpm@linux-foundation.org>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>
Cc: Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Spamd-Result: default: False [-4.00 / 50.00];
	REPLY(-4.00)[]
X-Rspamd-Queue-Id: BA61721279
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Rspamd-Action: no action
X-Spam-Flag: NO
X-Spam-Score: -4.00
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
 sender) smtp.mailfrom=vbabka@suse.cz
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

Currently slabs are only frozen after consistency checks failed. This
can happen only in caches with debugging enabled, and those use
free_to_partial_list() for freeing. The non-debug operation of
__slab_free() can thus stop considering the frozen field, and we can
remove the FREE_FROZEN stat.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 20 +++++---------------
 1 file changed, 5 insertions(+), 15 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 515a2b59cb52..9b551c48c2eb 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -336,7 +336,6 @@ enum stat_item {
 	FREE_RCU_SHEAF_FAIL,	/* Failed to free to a rcu_free sheaf */
 	FREE_FASTPATH,		/* Free to cpu slab */
 	FREE_SLOWPATH,		/* Freeing not to cpu slab */
-	FREE_FROZEN,		/* Freeing to frozen slab */
 	FREE_ADD_PARTIAL,	/* Freeing moves slab to partial list */
 	FREE_REMOVE_PARTIAL,	/* Freeing removes last object */
 	ALLOC_FROM_PARTIAL,	/* Cpu slab acquired from node partial list */
@@ -5036,7 +5035,6 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 
 {
 	void *prior;
-	int was_frozen;
 	struct slab new;
 	unsigned long counters;
 	struct kmem_cache_node *n = NULL;
@@ -5059,9 +5057,8 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		counters = slab->counters;
 		set_freepointer(s, tail, prior);
 		new.counters = counters;
-		was_frozen = new.frozen;
 		new.inuse -= cnt;
-		if ((!new.inuse || !prior) && !was_frozen) {
+		if (!new.inuse || !prior) {
 			/* Needs to be taken off a list */
 			n = get_node(s, slab_nid(slab));
 			/*
@@ -5083,15 +5080,10 @@ static void __slab_free(struct kmem_cache *s, struct slab *slab,
 		"__slab_free"));
 
 	if (likely(!n)) {
-
-		if (likely(was_frozen)) {
-			/*
-			 * The list lock was not taken therefore no list
-			 * activity can be necessary.
-			 */
-			stat(s, FREE_FROZEN);
-		}
-
+		/*
+		 * The list lock was not taken therefore no list activity can be
+		 * necessary.
+		 */
 		return;
 	}
 
@@ -8648,7 +8640,6 @@ STAT_ATTR(FREE_RCU_SHEAF, free_rcu_sheaf);
 STAT_ATTR(FREE_RCU_SHEAF_FAIL, free_rcu_sheaf_fail);
 STAT_ATTR(FREE_FASTPATH, free_fastpath);
 STAT_ATTR(FREE_SLOWPATH, free_slowpath);
-STAT_ATTR(FREE_FROZEN, free_frozen);
 STAT_ATTR(FREE_ADD_PARTIAL, free_add_partial);
 STAT_ATTR(FREE_REMOVE_PARTIAL, free_remove_partial);
 STAT_ATTR(ALLOC_FROM_PARTIAL, alloc_from_partial);
@@ -8753,7 +8744,6 @@ static struct attribute *slab_attrs[] = {
 	&free_rcu_sheaf_fail_attr.attr,
 	&free_fastpath_attr.attr,
 	&free_slowpath_attr.attr,
-	&free_frozen_attr.attr,
 	&free_add_partial_attr.attr,
 	&free_remove_partial_attr.attr,
 	&alloc_from_partial_attr.attr,

-- 
2.51.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251023-sheaves-for-all-v1-19-6ffa2c9941c0%40suse.cz.
