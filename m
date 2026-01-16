Return-Path: <kasan-dev+bncBDXYDPH3S4OBB2M3VHFQMGQEA2ITBMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 31368D32C48
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 15:40:43 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-64b8a632dc7sf2599788a12.3
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:40:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768574442; cv=pass;
        d=google.com; s=arc-20240605;
        b=kHqvXKgKc9itOz7hI1OGG5B3gu89QKFCrokMEjzcMk99cHnwyQGyJegCT2rQFjSXdn
         9+ZMWbaIb0As60IRrZ+gdqw9iht53eW4D3twNy+pn6c7YzPp2O7Mzo0xmDRkg5RZQS8/
         fyVr0/16W4NEbjftBL97YUoj04jKAF1zNc3AoRbiNfCsOtK0xUCsteAeUpBLBkFOMAWR
         Mop47Ll9/UabFHuWLODe3ihtKkyCz+/si/q1TJca9o85jPj02KRdkJ+nc8SBcnnXf16H
         rVtUEmcFLYQanDIOZErrRTeP1CnQ4UMYLQy9BJdBSvzT41rkJ6b2359JgGTetEKoLy5W
         mvqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=E39t0CzOiRW2AKGQ440pzMMdIUXCKVdy+mVHg+HdacY=;
        fh=ASv39MLW4xplsdsS4Ni//P/gilwJaknQxjr472F9Fco=;
        b=YYFH+NJl8PrOk7cxZd7Qwz2luNSm7dRYgjgzZoNcFBecwYTTTq1v5ofpBoSphp8fp4
         SsdyMC32YLc97A+RsIfgMImBdifTvaLDZpBydq0SBoEG7F5Nr1fhQfWM1ObdvYUR+Ocd
         8q+/2+5dR246F2ld3munG2xxGGXQwXr2eG4fMO+v2zlnmAGgDwk+ZDF/46xR8cnCy8mM
         BgEjniRFRL4PJUBajBDBkWHJ7Je1evAgDRqTtmlJgudEovqoLE1Yk3rHqX/RvJaT8LMy
         8H7Sw4KEf+u8522zFsO1xiHIuDmLPkT1/aaUrEZ7W1ckJpP5KJNXhzNfFMS5vwKnOmKs
         kEdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0uDN5flZ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0uDN5flZ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768574442; x=1769179242; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E39t0CzOiRW2AKGQ440pzMMdIUXCKVdy+mVHg+HdacY=;
        b=KLzofmXEepZFCx8ruNW9QCVptWZ+8Jf3mlGoQ6QfrIP8qZuuNB1a9eazVflXoh43oj
         fTzNdy7JJK+Cxg3If44dIG1WYuQfOBgzt7LewO4nXFye3qpoi94MoFr0yfqT2IhnwB0b
         ZxPyaBE2ClGKAdr4+oIo/0WMl5FJso4SqMnr02GMzOBabxyQMb6FOljLvhzmoOZrjBZv
         0g2U7FRvkyn4E35BBSDDQ7l20HBmob8G3iSTizLMOzUd0BS1/WEMNmHJC+wfPmO8ziZt
         5zRYvJCRh39bT1hQ7PgypDJq2HS7Gdf7rXvwmenXne/AixbbX1lmqzytO48BzEitqkzL
         KElw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768574442; x=1769179242;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=E39t0CzOiRW2AKGQ440pzMMdIUXCKVdy+mVHg+HdacY=;
        b=Q2nWpjF2ZiWTSiMEuwqQGb/yezQwPkPUgUAH7WyzCBFcZcnhsNFO5EBz3M6O9EOcjh
         HVTMtQKnfeW6jN2YP/3f8XnHUfqCU3Flyeq2KxmZ58NmcVMgZY1I7fVOFKOL7tp4BE25
         VBJmJUutD/5harTePUc4lUbv9SuR8bExegL+qKAriToL2+gowwgtsFxsGRFDOyz7+lcX
         l+NQ+5Gc0ywhs+3TLfWR5ljySC3zrFRaI/qtYGe6TFTmt4bc6mxtYUx2TptT5tFA8GOi
         DNlG14DtCt8eXzwByHMq4eBRSefCACGVQpng/tvW4GUnBalDs/w61eZub6w2aNXO/70l
         SM6A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWbll9FMeYwfjQ649hcmWnHfZVCAzze+QNMpXceCv1OWfgMR7abDV7flyp/S8KTEFsOjQt9/w==@lfdr.de
X-Gm-Message-State: AOJu0YwYfxUeGpXtA+5alRb8kjUW8nkbW9Wff8RVW8K3LGRX828zpex4
	GV95izU6VZoE9hoqsYJFY7p8ssEPkrSmIW9/JM3RuuPm0uyGJUArekg/
X-Received: by 2002:a17:907:6e94:b0:b87:b87:cdb7 with SMTP id a640c23a62f3a-b8796bb8150mr210269066b.64.1768574442352;
        Fri, 16 Jan 2026 06:40:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HMkbMEau8d6OhRr6Mm+TgIgT/e0+vv4xXm3mI7I3cyxw=="
Received: by 2002:aa7:dcc5:0:b0:64b:9695:8dac with SMTP id 4fb4d7f45d1cf-6541c6d7b00ls218224a12.2.-pod-prod-05-eu;
 Fri, 16 Jan 2026 06:40:40 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW1aflETj0d8hpHof97WkOQ2IhABSwBA6Hc4TDZwzReVVrRPjNdEyB0e2EK3u71d6Oqy1rAUXUXoZ4=@googlegroups.com
X-Received: by 2002:a05:6402:26d3:b0:64b:42a6:3946 with SMTP id 4fb4d7f45d1cf-654b93641a7mr2123671a12.7.1768574440241;
        Fri, 16 Jan 2026 06:40:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768574440; cv=none;
        d=google.com; s=arc-20240605;
        b=KBYPjMT9zir+3msDzdN8DgFjn2T605/yTmljeMecxsb8DfyV3ygOf60/FaLg5E9u7q
         BXeiovGIWBxwzFge4cHpwZ1hUVSu2fdtEgJuemD4qKf1kjB5AlV2AASklduKY538Cr4q
         fQWePQY80IUG1idmkn5ENou2QkCAXbTUWgtPdTpPej+0eqEFQgrP/FG64R/YHl//vVex
         D5eyzoMq525MDgzDiVnjuXevKSqEXCeHDyHzfNuIwuyh07eLVsPl8XyJQRFEF1kUYOGq
         hGlkfy0Yo/APRhKQ8sgKJHQRSsgDzqPwcl5uEi/rDK3UsKiGXyljrNNoAdfvP4HT+9Z8
         /8Aw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=ROlivulU3ZUUmQJGgAdryy78yr1ISK1JLKlofJUd2Bs=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=X0MvWTHlgd7tIcsj3FgT+hf6ZUUEc7tuZIDnj8rzB8f6o5gPqoYyT+6cZOyl2IjhqX
         veypDS3+YtUa4N/Pd0+WeA3fdW7rWqeflc636fk4/pnlPUGXi8N7F6gvWcsYv2Wad2Cs
         rJGYlkONCG21quGWDiIFdm5wncdejeD8WytTbyWSC93MSJBLyE7WdpanneHrRm7rrOgv
         fMfq5z9toy8zWV68LHRMzuUsxBwdoLxbH7Z4Vej+hM6QKD4XRxEFDu/DEz8fKbhUVMv9
         9WC72o/Ty70jSrvHKcj6f5R3f6xR6+5SXLi8JuAG5G0d6inyBjPRaIgrmy/zMEGyyGqP
         CiwA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0uDN5flZ;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=0uDN5flZ;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-65452cca91fsi40098a12.2.2026.01.16.06.40.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 16 Jan 2026 06:40:40 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CC4BA337F3;
	Fri, 16 Jan 2026 14:40:36 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id A881F3EA66;
	Fri, 16 Jan 2026 14:40:36 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id CEjcKORNamnydgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 16 Jan 2026 14:40:36 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 16 Jan 2026 15:40:22 +0100
Subject: [PATCH v3 02/21] slab: add SLAB_CONSISTENCY_CHECKS to
 SLAB_NEVER_MERGE
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260116-sheaves-for-all-v3-2-5595cb000772@suse.cz>
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
X-Spam-Score: -4.30
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-0.999];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	MIME_TRACE(0.00)[0:+];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	RCPT_COUNT_TWELVE(0.00)[18];
	FROM_EQ_ENVFROM(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_DN_SOME(0.00)[]
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=0uDN5flZ;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=0uDN5flZ;       dkim=neutral (no key)
 header.i=@suse.cz header.s=susede2_ed25519;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

All the debug flags prevent merging, except SLAB_CONSISTENCY_CHECKS. This
is suboptimal because this flag (like any debug flags) prevents the
usage of any fastpaths, and thus affect performance of any aliased
cache. Also the objects from an aliased cache than the one specified for
debugging could also interfere with the debugging efforts.

Fix this by adding the whole SLAB_DEBUG_FLAGS collection to
SLAB_NEVER_MERGE instead of individual debug flags, so it now also
includes SLAB_CONSISTENCY_CHECKS.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 5 ++---
 1 file changed, 2 insertions(+), 3 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index ee994ec7f251..e691ede0e6a8 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -45,9 +45,8 @@ struct kmem_cache *kmem_cache;
 /*
  * Set of flags that will prevent slab merging
  */
-#define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
-		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
-		SLAB_FAILSLAB | SLAB_NO_MERGE)
+#define SLAB_NEVER_MERGE (SLAB_DEBUG_FLAGS | SLAB_TYPESAFE_BY_RCU | \
+		SLAB_NOLEAKTRACE | SLAB_FAILSLAB | SLAB_NO_MERGE)
 
 #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
 			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)

-- 
2.52.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260116-sheaves-for-all-v3-2-5595cb000772%40suse.cz.
