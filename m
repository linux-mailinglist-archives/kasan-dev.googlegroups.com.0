Return-Path: <kasan-dev+bncBDXYDPH3S4OBBYVVZTFQMGQEPKRDB5I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6Ks3B+Qac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBYVVZTFQMGQEPKRDB5I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:24 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id B0A78712D7
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:23 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-6581a45f30esf4316161a12.2
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151203; cv=pass;
        d=google.com; s=arc-20240605;
        b=TGOp/WBdGyvxuo27h0drDUa18Blim/Tb/73aEMbPU47ZRqQ0mOfeVsJf19rInLqO8y
         IDWhJLauoYz/UUFdna0npm1yUWSPXLgOp4OI7dBMX7rc+fr6vzzma1GjsZQjB7nlVfl0
         4O10HfYoDqNtywHzeAOftWNm8aOSBzpGrlT2gTLbV8iMmsJ8woQPtM8XIbndDLNlPbwH
         U+GaxBzsxe7aHAsSNqCZF+KHeXqzadFWFHlWZOYo70POXXp/S2Gq+hdUg7CEvt09fAh2
         dASXbbMuffuBmYCmyPOvBCf7T7u0qKHta3fd/c1SAn3QS4ILAZGhMQXIPx1X+dIAYQ4A
         +jfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=6oHe4KPDFJLMdp3K+Cumbw0qeReWOcA+GWrKZZJX0dQ=;
        fh=iOKWS08+NCClpQ/erVVdvLlo+cRCWVABvOGqYdyHoBg=;
        b=hkVVme0Whm/IHt1tJoKyI2KhBHGf3kZb76IvxfNQmRc+CyLa8bvjiSlIeQqGuoQVNw
         AK+e4jGds/qyCCMW3PkQX4uiOyp8F3vxvnN32eZuuM5ql0IXLz8L7EhAUuqenLGnOiq9
         hHO0V+E0aJLvuETvO1P/+lwi1WhqwgVEs5t4NO8t8xOKpL7V8KYmCpHyYZ6jWjv9XfDU
         PVWKAi6zAoSwGow7PpxX1Vyn8aQ5UCC389kMdJR+UYIDhy5ixszvPFvLBQrS6cWxh5WD
         uWCiZrb4/0m2ONmCJTxbkOf9EELBU2u1HA7D5eX8yILHx4Wi49tkyBreD4G00/4Z8/sw
         lyKA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151203; x=1769756003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6oHe4KPDFJLMdp3K+Cumbw0qeReWOcA+GWrKZZJX0dQ=;
        b=aFGRHYxVIIlp6zqLNCZ3B4VcfAB74aptFtJl9BCcefLDYZrMXYIRYUODp6CnaaGYHm
         UmKyscwEtz4zJKK3D1tKbveB4VDeXh8ltS5XeVrzdkHAO9v1r2R7x4sTenVjeBOtRDsl
         uOrcycaC4sS2SR2aEgHemTd9Ad9P9P3eyf9MRpcld9aJW6ReN4xYOzdfWwN1XSx/ncgf
         9zYJWiU5fY5M1jwfHfuVXewHXYMFQZa2ZATW58oXLXIJ/jbCyC/7/NX38VjU9bUMf/UO
         gDY1Lxx9CFF4II+esDDx6xtQfkcGBJKZeFU7HEUWNEddjFVPfLjatjuUt08YpjqE0c7M
         j9iQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151203; x=1769756003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6oHe4KPDFJLMdp3K+Cumbw0qeReWOcA+GWrKZZJX0dQ=;
        b=Na2lsOsluz+5ephxL4fl81UuDDkIyFEk2Bz/5bP34xzlLzKO7BssBDYmpal0q6XdHU
         AZqYhAqIevJzs22HPHcWR+E4eAwX3hX91e8JfxafSXnSOHB9hs4vA90zFRXyGx5ddOwX
         6mxLqWcADOnEYGtuUYXwiJ5sBtkF2GL7JsaPE7BCa2GF7XyEGKGcwUwiUy7hgrbw8CDI
         U5QcMLkX94Z6/LysIKSx0I1PGHultAHLbSBNH4DE+a6A1K1G4+Rqe71KMUn8KmDoQiVV
         YAWO/b4o53xjOmN7aZARBVfNcaKxqYX7DH+0GYArrQIiTDkFH79kVcICtrvz+HmUQplr
         E8DQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXFwNi4UJPw6jnaJQAI+1Rjb2g9njIUzkX8CVCJdOgiuHVtnXeLXIdRd0yc/vwHNGsVhVkJkg==@lfdr.de
X-Gm-Message-State: AOJu0YySBSYn9SdpyoZZ6Gm6YusQMm7TaX5oeeB4VcmWGeXAd/Sod6/l
	/GCoWxQ2lpHXev3K23xXb4JVck4QB+YjPMmlShAqqq8pQx1bu4+4s6Wb
X-Received: by 2002:a05:6402:144b:b0:64d:4a01:fc23 with SMTP id 4fb4d7f45d1cf-65848762170mr1406364a12.10.1769151203080;
        Thu, 22 Jan 2026 22:53:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G06iz3vx+ZxzxtAZsp+slHk5mNduV07gs5pPDQFco+DA=="
Received: by 2002:a05:6402:5359:10b0:658:2e7d:4dbb with SMTP id
 4fb4d7f45d1cf-658329fa061ls2675664a12.0.-pod-prod-08-eu; Thu, 22 Jan 2026
 22:53:21 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU6dQu0fbYiEM/qDx/G6TcbS6WKVibSph4Cp7DHLzH3OQcXiOmD0Oq+RzX263FmYRuMHiHhRtXlwOI=@googlegroups.com
X-Received: by 2002:a17:906:4787:b0:b87:fc5:40bd with SMTP id a640c23a62f3a-b885af085eamr134150366b.65.1769151200884;
        Thu, 22 Jan 2026 22:53:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151200; cv=none;
        d=google.com; s=arc-20240605;
        b=ZLTZ7iH/5kGpu+cNxKSjO2yFpb1OqT/0/3QkREmhahWZoDzAISCAgb3KE6pbR7GDxS
         Yz7NFhYl/6hHOuPl2FffQnReoFEZ82RZtcD+jHUJ4M60VD9xLZlCAGd9PTlxA0VHkK23
         YwRKVjIDwWHfoy2qhQv0vu+hUEu+L33KiRqtsinpbLo2Nk57NknCrZdCbRTllPiMA5TW
         1vptaLHbo+3V99cIdNUPJdlRm8ACSIzu/GWlLvC5fea8FgRWpx67KjyBKt26U+Yzbq+A
         QdbnAOWjOkOmcgMBlqUocGXHo97VTvAMC4cQIVGJc4N2e4n8vhVivuEkd2C3y/zYligD
         o+mQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=6kTHheWfs8SEmgcjXleoxxOUgg6tYL7rw7gDEvGl0jc=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=eKnfmieUoEXN6Ctstsq2EMZgxJhgXgdf7DBZ93gqR5MQtCuIDCGiFHbzc5LasezCs7
         gNlrkgzOJbn3tsBSoPW1v6o/37XMR3wBfRvHUKlO5GjdIneTtMmQmAXz59n9G6Ooulmf
         ezqP/ypB8X3J65qou36n5cFwNHmaGYZB+/Q9FUMvVzFbLWZxrY2yJGeoG61BrHjl0c3v
         A2+3QNi+GUTkG1NJTT9kT6qMVgpIqi7hTtyga2LtC8vrziaXxpStSaR95syry6CjE1By
         DWiRH1e39yiKcvchhbnEgAmekQeg6TNFSrMUxlRecVRBUL8Ie9DqAgQu8c9n4gKyEIR6
         B0OQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b885aecb85dsi2834166b.0.2026.01.22.22.53.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:20 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id ACE3E5BCCF;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 96A26139EC;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id KGCAJNUac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:09 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:43 +0100
Subject: [PATCH v4 05/22] mm/slab: make caches with sheaves mergeable
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-5-041323d506f7@suse.cz>
References: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
In-Reply-To: <20260123-sheaves-for-all-v4-0-041323d506f7@suse.cz>
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
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36:c];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBYVVZTFQMGQEPKRDB5I];
	RCVD_TLS_LAST(0.00)[];
	FROM_HAS_DN(0.00)[];
	DMARC_NA(0.00)[suse.cz];
	FORGED_SENDER_MAILLIST(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	RCPT_COUNT_TWELVE(0.00)[18];
	MIME_TRACE(0.00)[0:+];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	ASN(0.00)[asn:15169, ipnet:2a00:1450::/32, country:US];
	TO_DN_SOME(0.00)[];
	RCVD_COUNT_FIVE(0.00)[6];
	FROM_NEQ_ENVFROM(0.00)[vbabka@suse.cz,kasan-dev@googlegroups.com];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	NEURAL_HAM(-0.00)[-0.978];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,suse.cz:mid,suse.cz:email,mail-ed1-x53e.google.com:helo,mail-ed1-x53e.google.com:rdns]
X-Rspamd-Queue-Id: B0A78712D7
X-Rspamd-Action: no action

Before enabling sheaves for all caches (with automatically determined
capacity), their enablement should no longer prevent merging of caches.
Limit this merge prevention only to caches that were created with a
specific sheaf capacity, by adding the SLAB_NO_MERGE flag to them.

Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-5-041323d506f7%40suse.cz.
