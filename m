Return-Path: <kasan-dev+bncBDXYDPH3S4OBBA44VHFQMGQEJN7ZFAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id C1A02D32C84
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:41:08 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-59b7e2b4a18sf1369915e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:41:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574468; cv=pass;
        d=google.com; s=arc-20240605;
        b=AzcHgcbna2OKGkbW0liN5gIFMB6dD30vVcTKmnEc7zSEh1xTVzGrKJkZsgvask0Jle
         f4UiZQzMhRHMcd8iQxQjdG5K9mqMtZeS/hH5ALXk9DNU3XnGuY3Hcn4siKSPB9ybQu9I
         93rsNplKn5ZSU2jLVHEHT/fEFHoCudlPYjoYvQ6aZbqCmvCJiiQxnwv4yQTHcNNUAjTb
         KQrvHRv7hVl8VnTlyxkWXUIH0aoLfrZHvrgMCAo7vGFbMa2gdPcW4Fc+PCwLif5W5gtt
         zfHur+IRFhFy5xq4/izbdYN6SRA7sfDeb3/qXkF0YTYrvCkgX7y2EznO4OhdGIFQ59Ld
         wVRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=nInMwzqZJktS6g6Oh09omhpZuKJynOGF5T+Q0xnrf90=;
        fh=TnjqxwNNRihuxluJahelxfmxcSTk0/vdqeDXzkGauXo=;
        b=lRHzHN9D4iX/ANfJVIrqDIEtXSBRuUQ5tx2c0rezue+ZzXJ2OwGS5KZ1j6RHE3w7Ng
         BESjDgAtVUOAxL0edzg7JRucE7zAdVLtL+iJmxQ127jYI9uvdivBsmnmLo5eR5krVkqV
         FbGCAmYXflI4acm32l4dV6Ph9+f2jbg0P2EhD1fUP/o97TkCx1N/cDMSMJq8WMGtrbbp
         aF8j6lU/4IV2PlZvH3HTKA9oyffjP8xNpiM+ZZ8sG2DQZo0PxRVAqqTb9pf+ueyXDGti
         +1MeqB/nBjEP2GZmDA1whVN9eDTGR4cEvz5/zY5jX6z2MYqAkm/35Sz1Fz/aKZ5Ar5co
         8EhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=k9V8NlvM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=KtR4ezr7;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=k9V8NlvM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=KtR4ezr7;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574468; x=1769179268; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nInMwzqZJktS6g6Oh09omhpZuKJynOGF5T+Q0xnrf90=;
        b=e1h2gVA2LFGmrQTzj0zTH4BAOCyVVCmLVAXbBENG8ef3FSGb7PKf9MzRb07yFxGZNR
         556hjXV53+2n7dmdldZzCJaXSGDy8JjMwmj3gZlCRTH+rqKiSPlYsHGXfMm9H3U9CYrl
         FWgR4hbVQ59c1KxQS8aXQtpz/n9mZgMcK3N9GShrA+PRmNibanmpfhYImHmnutQRHfdv
         b/AUtQyCmCa2lgfLB01bo9JxiE6zp2Jh1jC6oFeBhLR3eabt8XD6YquVLatppuOI8NaX
         9J6mgWwFoDjiWvOgXgcmOJ0YuGSz5MJhQuOeiTzAHsyBp++EAnrWFz9g/e/Ac8dij45m
         Mlkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574468; x=1769179268;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=nInMwzqZJktS6g6Oh09omhpZuKJynOGF5T+Q0xnrf90=;
        b=TtgbYBlcDJn54CpvSG1lddSxMfoLCgMNthnLmFSDh7TjawiWsJVH+38L1mMmW08cmf
         sedUj9Yji0uUs6rjYh0amyZKficRbh7l93mcjo6keD0IcRWwIA9vte5PjHsZ/WSNLiSL
         qYjVMWwk43P7194EVapNVErvJR7DM40jCl2MKSiSkegfhLqL3C9w3AmFgBJV6Wt/J2et
         wmhmtEdJPR9GcKfAqrBGFbJEPNRuMts0tc1Og2Vbg3T1XPjGGy/Hbb2UsWCW0r+BR5qk
         Hb4E9mat4q3gyzTB1inRwxMY04qmag9C5pnjnVavx7CzkboaaOozAOw9DI1EzXwOHN82
         a0Fg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUMtc6zagJ8KYE+sqGSwS29V7Hf1nu0D1F+r3BFuL1Wq+hvTww1utdEs1/+AM4PtD6TpZv3hQ==@lfdr.de
X-Gm-Message-State: AOJu0YyHGQ+cHQnIk2Pzs+YluNHbWTbbrjJbPN/gHaC4zCL54Ipc4i7N
	IBCFsGImfp23TlYr0DlaWL+i0PkX1pIEWA8WAHZWh3IsAqrvIY+TGe9V
X-Received: by 2002:a05:6512:138f:b0:59a:183c:4863 with SMTP id 2adb3069b0e04-59baeeb1d8cmr1015299e87.8.1768574467729;
        Fri, 16 Jan 2026 06:41:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FpPBlKw3nmZv9wCjGMV2NHwBCZfXwGSuklBHDglBQaeA=="
Received: by 2002:a05:6512:12d1:b0:59b:6d59:30f5 with SMTP id
 2adb3069b0e04-59ba718d57cls797497e87.2.-pod-prod-02-eu; Fri, 16 Jan 2026
 06:41:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWqcazGNZoSVeCO6e+YmJlVi88LR5v+Bla66ik4XYVonJArDmld5vk+bmCwL1zqT2eJRQQ/Q3qvAjc=@googlegroups.com
X-Received: by 2002:a05:6512:1192:b0:59b:7aa9:3e34 with SMTP id 2adb3069b0e04-59baef00632mr990702e87.43.1768574464840;
        Fri, 16 Jan 2026 06:41:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574464; cv=none;
        d=google.com; s=arc-20240605;
        b=T3UPTTETpQV96sr232a29ruVGKcnBLqLD82LkxvAzm5tE+SAOMB0vsaDZUysaPNYfc
         cn6rBxbUfJUITvfn4HAJylrxSxgzY3MC+1Z0OTHdRXQ+jOyWVJX6NCRQxO+9SJtFmzqZ
         dA8ao+ZWYP2YKBCoyMDeyp2GZyJPVcgV95mbbVp/pAvr9a7h57OaWjbY5FOExMOOA8Rp
         o/1eC5CTo+hGYgaLeeRxyukKKJSsvXIixDuedNKS/NMWTWOuFhOn/zcMT+Fhs/r5T7So
         RdXm3j1FlsWteXcvZYQxtD8CbRJrJMgGMkw1b5HqVv7QcxQgS0MDxEmBnpscYi1hXaYZ
         Nx6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=MkNKfm5uHwOYSqEkkRpaI5Z97WwBojUZ970Bd/6ZMy4=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=huALHvvXG1fxLNr3wcboy9xA0eI4Xk1ieaK/dz5JZtyKRXRNbWU2fh9fpS2mvk5zkl
         wbCm97qVsvKX67YkmsewFGri5umqbpUOmeN28xpGDy8m5BtvJkiHRszV7uQSejt4uV2p
         R1wS0vAfrRT3/S5q+dzAFet5kDTlfP1XQx9YgtiFz9G6qrEjKVFkHcXagA/pmoqVOdI9
         MqSSHeHC8CK0i/z39eDnqDanh00brzdXOnMW17571LZy3bpBkYMeZYbkALJcS5Pzve9e
         o2xWDvLmfRr/VLw1ETcTRWIXUZC/xMVZG5Ub2fJQMnwnziCXbNAkCn/R5iV3Hdh1HRJL
         xnbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=k9V8NlvM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=KtR4ezr7;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=k9V8NlvM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=KtR4ezr7;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59baf341ef5si59188e87.1.2026.01.16.06.41.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:41:04 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 6908E337D0;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 4DE2F3EA63;
	Fri, 16 Jan 2026 14:40:38 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id oFrAEuZNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:38 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:36 +0100
Subject: [PATCH v3 16/21] slab: remove unused PREEMPT_RT specific macros
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-16-5595cb000772@suse.cz>
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz>
To: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
 Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>
Cc: Hao Li <hao.li@linux.dev>, Andrew Morton <akpm@linux-foundation.org>, 
 Uladzislau Rezki <urezki@gmail.com>, 
 "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
 Suren Baghdasaryan <surenb@google.com>, 
 Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
 Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, linux-rt-devel@lists.linux.dev, 
 bpf@vger.kernel.org, kasan-dev@googlegroups.com, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.3
X-Spamd-Result: default: False [-4.51 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	MX_GOOD(-0.01)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RBL_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	MIME_TRACE(0.00)[0:+];
	ARC_NA(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	DKIM_TRACE(0.00)[suse.cz:+];
	RCPT_COUNT_TWELVE(0.00)[18];
	RCVD_COUNT_TWO(0.00)[2];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	DNSWL_BLOCKED(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER(0.00)[2a07:de40:b281:106:10:150:64:167:received];
	MID_RHS_MATCH_FROM(0.00)[];
	R_RATELIMIT(0.00)[to(RL941jgdop1fyjkq8h4),to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Rspamd-Queue-Id: 6908E337D0
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=k9V8NlvM;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=KtR4ezr7;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=k9V8NlvM;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519
 header.b=KtR4ezr7;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

The macros slub_get_cpu_ptr()/slub_put_cpu_ptr() are now unused, remove
them. USE_LOCKLESS_FAST_PATH() has lost its true meaning with the code
being removed. The only remaining usage is in fact testing whether we
can assert irqs disabled, because spin_lock_irqsave() only does that on
!RT. Test for CONFIG_PREEMPT_RT instead.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 24 +-----------------------
 1 file changed, 1 insertion(+), 23 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index bb72cfa2d7ec..d52de6e3c2d5 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -201,28 +201,6 @@ enum slab_flags {
 	SL_pfmemalloc = PG_active,	/* Historical reasons for this bit */
 };
 
-/*
- * We could simply use migrate_disable()/enable() but as long as it's a
- * function call even on !PREEMPT_RT, use inline preempt_disable() there.
- */
-#ifndef CONFIG_PREEMPT_RT
-#define slub_get_cpu_ptr(var)		get_cpu_ptr(var)
-#define slub_put_cpu_ptr(var)		put_cpu_ptr(var)
-#define USE_LOCKLESS_FAST_PATH()	(true)
-#else
-#define slub_get_cpu_ptr(var)		\
-({					\
-	migrate_disable();		\
-	this_cpu_ptr(var);		\
-})
-#define slub_put_cpu_ptr(var)		\
-do {					\
-	(void)(var);			\
-	migrate_enable();		\
-} while (0)
-#define USE_LOCKLESS_FAST_PATH()	(false)
-#endif
-
 #ifndef CONFIG_SLUB_TINY
 #define __fastpath_inline __always_inline
 #else
@@ -719,7 +697,7 @@ static inline bool __slab_update_freelist(struct kmem_cache *s, struct slab *sla
 {
 	bool ret;
 
-	if (USE_LOCKLESS_FAST_PATH())
+	if (!IS_ENABLED(CONFIG_PREEMPT_RT))
 		lockdep_assert_irqs_disabled();
 
 	if (s->flags & __CMPXCHG_DOUBLE)

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-16-5595cb000772%40suse.cz.
