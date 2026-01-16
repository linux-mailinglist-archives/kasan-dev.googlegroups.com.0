Return-Path: <kasan-dev+bncBDXYDPH3S4OBBZ43VHFQMGQE3R2RQIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63a.google.com (mail-ej1-x63a.google.com [IPv6:2a00:1450:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id E46CDD32C41
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:40 +0100 (CET)
Received: by mail-ej1-x63a.google.com with SMTP id a640c23a62f3a-b7fe37056e1sf234084966b.2
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574440; cv=pass;
        d=google.com; s=arc-20240605;
        b=Kwq6KI4iMvdL8gtywtJOjsNjFmTX3Vbhl2oIGUncvgtEKP1v51dDJ998XgoRdnZiHp
         tSrW2aU+HlR+99uZSHK25Och11rYlZP10AGKdqTM68LLdNODRngNGb5j3ULblbw/Ohgd
         xwe4kKavJoFSWVNZnHUG9f1wInhMjITvf4pogLVpL2xvbgOO8Yp2pSYL0p0/RvZ6oCQS
         Jgx456xm7EufLSvu0FDqTFFZy8vxipF+ZsmLxfXRYAEaR3+gfNVidmnmbtRYPdc2Iu6+
         RtkWWwzP6RNbkkoC6I+ymwJY9mdOPMdTu3h51H8mlQDle2m1Q2LNJbW4THGbshXIZueV
         YISQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=BY/1dyN5bCYDjxK4x/XQu68kW1eH0xVA9BCseehh8X0=;
        fh=k7WVshmDuiwWjeX5MmSqh4cI8jLqZEAGsw4odakcpUs=;
        b=SaATEsZYYvUWemBFJz+TPxy0F73KGJdkvlGlaN/DawQ3cOBzOrbuTRxU5748E4nOwO
         uZmuMvbqtROMmpATHYrzaXXZ4s1E6LF3VkeWoh/KYFIPHD+g8a2wozGWY5LHim1xtNKW
         Ic/0989dXeIYi8tHeqAOnT/vUN4LjaMJ3rRNKYCtZYmAez52XbTWNjC+672x78eLARNJ
         b/X+AT+REqIIIMbXY3o8Q6zWQ+puE90qZJdGJxknHdQbP0l3bTTs2bv2kc7LbLZdvMDV
         pgYHLEgubIHj2oiJSPhlzQee/Lg8NuaQXdG46W6wVfQr3qRE12Q/uSNTFNosqwsf0kgb
         Hbiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WOx4muwU;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WOx4muwU;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574440; x=1769179240; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BY/1dyN5bCYDjxK4x/XQu68kW1eH0xVA9BCseehh8X0=;
        b=cXHoYm/ldqNAO2fRkM10eC5jMnmT8VyU8/3Vul9XnZP9z6Zm7+l16cCS7HwWO5/M1y
         UmuVou3JBwZNOFnKUiSvsPpqxWogSa93eU1rMe1OQTGJ8gkDuZsLwUCDO37Y84SVqICd
         oi7oALanLvt/q5p/DJovtP0/iJ3GkdgiNkOEHoPQ1uzckM9AmKWDz/WY2DU7j0B+NATl
         622gbS/SghsC9U7bh47LbIoL2bWrZqWfY7vykwwxnwnPLOb/AW6ujGg6zWbfzo9VjAFJ
         WTdJymMrn+L/vcQLqpjg3kstSiex/lvSUvURTQSgaCwlsrrXTDVN3qlrZSYEeRuvjpVT
         l8cw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574440; x=1769179240;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=BY/1dyN5bCYDjxK4x/XQu68kW1eH0xVA9BCseehh8X0=;
        b=MCm4mHwvEeY+pBHYfpK+16te9bokHaEvK5zIjn7t9kn1OQEg38ABbgEV8ZFIeUkmF4
         1Zl1WsawRH5aQwpBuIS5/wlbgE7OPB2xjx+lg8t8s5EZK2lSl2+zgg1Ftv3RiHmBvmE7
         QK3pEJi/6w9rlF7rNlJ1ZL1mj5XAH2s+fRiTbHsatO7EPJVC06F9YnVUxyzlITpj1k/h
         5LLtCBgVysTIzKgt8Xc1A2KfMeizpux39j6gT5c4YZAEK7ayPFF4tE+OKC/pQpHXj8EU
         ToSEgGV/heJf2F5i/yG+ZD/+5a7YwOqJpjJDdB4OrMo8g3HkBFMWoMT92pDgWvSG4tCe
         rsIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUWZ8oUDFZMLz51+glxBqUum6ltbZnTEZPrOHKW7NEmVscUITXitk2nrCP4k6JXC+3OoepixA==@lfdr.de
X-Gm-Message-State: AOJu0YzL6fiw/P+SWsJC68ymKt050KcoNoozxgq30S8bSVS5pgkF97kJ
	ENYE8uT8G433+ovCJrB6lDMbH/CyHhGdo+CSSB3sGvKshfRnxSNZHZYG
X-Received: by 2002:a17:906:478b:b0:b87:2f29:206f with SMTP id a640c23a62f3a-b8792ddb91dmr260864866b.17.1768574439937;
        Fri, 16 Jan 2026 06:40:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+EjlEX2YPg8Url++inb8Rd3Ys2yA70U1v02P0aId+jDUQ=="
Received: by 2002:a05:6402:394:b0:650:855d:592a with SMTP id
 4fb4d7f45d1cf-6541c5e016fls1616013a12.2.-pod-prod-07-eu; Fri, 16 Jan 2026
 06:40:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWsq0B5EDgtg6hnGvqfYZypOFO9Rc1OTR/hB1D238vTPBHAfdw/h8OaB1z2mXdFz3VQIlT/uZg7ZWA=@googlegroups.com
X-Received: by 2002:a17:907:8692:b0:b87:6ce:1269 with SMTP id a640c23a62f3a-b8792de8e4cmr251514166b.19.1768574437564;
        Fri, 16 Jan 2026 06:40:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574437; cv=none;
        d=google.com; s=arc-20240605;
        b=g9OvtT6peBnQcbrCFmRYGSEJMVnwsVVQLrdkwzaDIFsSnQLBa9v19Zao4ifWP3VZIq
         LYkrpiR4nWkiphMuEBnQoxC+PHiECWkhsMPs7eZ3BDOJ5aE4QorbyizjrbyRch7FsPrl
         Wm+mE9nNksz9WmuR2Sf9CIlgWtG0INPV6tZ6MrsUd3AUSBbSOA8G5DhgMbDSdmbpooYD
         nFpnBCFJMuX42HkfUH70wx9NTJ+1t1uOgZIzA58Ch4sXXBjebVHbQ5ZD6J8uUYIwMFaq
         EtuohnjjCvIOv/rY6Dy5qIrtZDX43nAAoEx5FPPW3hc4KeFc/tpzVheYAcICGw7Y8QVn
         1Kow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=gOKU0T0kl+7yhz3gb2FHYxgpYP3PPC7SU1SA5tPPFio=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=KEKQHEluVjfEf+2M2RMsG39yUo6/Q11OuVpkf6Qtv0gUblgCADZ/zJy7IUSMZ26B3U
         cP8eo28xXxmz4RPRRAo9AMAOZKl+c71RJ8tngQ5FtqOtP04CgiympoWdkeRRH++lZVto
         HAjKa8VgUXnUJ3BgcRlRcsSzDF2wzZMaM5SCLg1oOdV8udV1AqIdMDwzlcMeaH99eC+q
         rIV/AO6gRdQgDW4ZFqR7UrasMw91pjgtQetkHtWfF0TKnTei/7qaJGCNT4Pi4Z1MOr3u
         SGEOwE0L5gCmAv8OZBMVYI6yKaTH2VlwZD60RDVdTbNwUAz6VIa4tOR9+drxnrojZt1G
         HSEQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WOx4muwU;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WOx4muwU;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b87959b318fsi6075466b.3.2026.01.16.06.40.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:37 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 0D0215BE7B;
	Fri, 16 Jan 2026 14:40:37 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E2B5D3EA63;
	Fri, 16 Jan 2026 14:40:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id eB0QN+RNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:36 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:24 +0100
Subject: [PATCH v3 04/21] mm/slab: make caches with sheaves mergeable
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-4-5595cb000772@suse.cz>
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
	R_RATELIMIT(0.00)[to_ip_from(RLfsjnp7neds983g95ihcnuzgq)];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Flag: NO
X-Spam-Score: -4.51
X-Rspamd-Queue-Id: 0D0215BE7B
X-Rspamd-Action: no action
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=WOx4muwU;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=WOx4muwU;       dkim=neutral (no key)
 header.i=@suse.cz;       spf=pass (google.com: domain of vbabka@suse.cz
 designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

Before enabling sheaves for all caches (with automatically determined
capacity), their enablement should no longer prevent merging of caches.
Limit this merge prevention only to caches that were created with a
specific sheaf capacity, by adding the SLAB_NO_MERGE flag to them.

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 13 +++++++------
 1 file changed, 7 insertions(+), 6 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index ee245a880603..5c15a4ce5743 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -162,9 +162,6 @@ int slab_unmergeable(struct kmem_cache *s)
 		return 1;
 #endif
 
-	if (s->cpu_sheaves)
-		return 1;
-
 	/*
 	 * We may have set a slab to be unmergeable during bootstrap.
 	 */
@@ -189,9 +186,6 @@ static struct kmem_cache *find_mergeable(unsigned int size, slab_flags_t flags,
 	if (IS_ENABLED(CONFIG_HARDENED_USERCOPY) && args->usersize)
 		return NULL;
 
-	if (args->sheaf_capacity)
-		return NULL;
-
 	flags = kmem_cache_flags(flags, name);
 
 	if (flags & SLAB_NEVER_MERGE)
@@ -336,6 +330,13 @@ struct kmem_cache *__kmem_cache_create_args(const char *name,
 	flags &= ~SLAB_DEBUG_FLAGS;
 #endif
 
+	/*
+	 * Caches with specific capacity are special enough. It's simpler to
+	 * make them unmergeable.
+	 */
+	if (args->sheaf_capacity)
+		flags |= SLAB_NO_MERGE;
+
 	mutex_lock(&slab_mutex);
 
 	err = kmem_cache_sanity_check(name, object_size);

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-4-5595cb000772%40suse.cz.
