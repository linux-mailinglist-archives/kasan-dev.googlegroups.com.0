Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBFBSTFQMGQEPUZ7VDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FEB8D13901
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 16:17:26 +0100 (CET)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-59b67b93cf5sf5111214e87.0
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 07:17:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768231045; cv=pass;
        d=google.com; s=arc-20240605;
        b=ILsuLVPN5gPrtfmQGqD4v6xLSGb4DnEqOpIYwlJaSa/1uAxf5IieNIx4wNH0X1hBtB
         xCFmRXgx0lX5n3+YLLv3GKAFirx1k+0+QHz0/HA382Lz7p4HKoaYn+mJQcg+NMjuKYTA
         RL2G1zGuTX4vPzm5Wli9uAVio5RXndxpkPUEhJ3iz/zcQnHbfAlTm26UZTkt6ndjnz+n
         8WNmL2uQy/kP3Dmt1UHwOydu9RWNDvGTcqJsp8u5YSw8nVl6ffy3X6jZ9mKoKqwZe12e
         oZ6ceaLqRYXatIHkerJFVACQ2vtR3ABxqGNcI8nz2iqrko+PWVeEviUQPSnAI8rBgHfJ
         hLKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=tjNu64nkcyR7NvhzIbwq27P06n7utyNDeDa97KD58iA=;
        fh=7/KQa61gpxQ7nHTYlvtjqLciSDhuXZP76646WlJzCSo=;
        b=ExgzXAK9UD3RubNvekJwY9InAY2qN2JuThRYp3fyDJ97/VZqVRCGUeb6X0lCMCIeYt
         Q0tliSinbm3quC6sboKrWwdJb3I4JkHN6UmnOdm3pnopcmyPnhsRinI7u97weOr+VXp6
         3K2lBYLy3A6twfcUGz9jfHzou4snjU16qU+DBV3Qp5yPwcdQHVKaGlosOI2/SB6EGyBX
         0HXyk2I5mZ08eh3fJge3QojK0i+lb+A/u1sLGKJE+ZDD7qoSF32zqFrDzjMtPOpsEZyr
         UcS0A4a1XhcQhPj1Wwpeg/YEdCaYMGC+O7FHgkRLAcQrXjFK4/nFZ08F0LwwmCkJjBdf
         Hz/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BvgqrFK6;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BvgqrFK6;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768231045; x=1768835845; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tjNu64nkcyR7NvhzIbwq27P06n7utyNDeDa97KD58iA=;
        b=eMRixfKq0WnTFyVMB4kILMQhF4pRwp8hsdkxbm6ciSrVBBRMBKXaqltThKtzL7baTp
         /NRfl7LADZ9N8UY57SDOiEvkYgJ0Bsqht9LF9Bdya4gdKgDl7hQPoWP81fGuOCN/NekZ
         faaSwKLrVIqeYN0UPwr45cnMctR8SSFWz+g7PjI5Lv4URqZbt7yW4Zr26ph++KEq12fn
         km0DMAxm+x9Sjgqr2A/+8Z/d7DxZiZ9iMmvrlczqmWdnYFJCCQ1TGENbTqXErtRHoqB8
         OEVO9rJWpGowXIR4cqv67YJ7/2VEhqDQg1bhl9CqcSrVZ5TY8E8sBpn/hIiqGP0igFDz
         BYtg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768231045; x=1768835845;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tjNu64nkcyR7NvhzIbwq27P06n7utyNDeDa97KD58iA=;
        b=TbjmRUqEgu0IV543cDET10fyRiMlqxCAl1C6Yrd/AspzcEKC9QNC19qPpBxb3wxGjm
         4cvAGbOFpArBD/zbZvb7SKmrWq156DYQGgLDgGEBU8u6uymHV7uh00XFRuJ+qzr4wcCV
         anufvj2tmPvK2tWolavTjEJRDIVhCF/Q9lAaGUjn31YQ3pY6bvHLeXnpXNrYXzK0bOJe
         +2Sg7p0hBYCZUOfyzg521sFEr/5zIZoYKmAVJKjE9itfNL5lvV+3oTgBb4M7zPk1KE7X
         9qjFh1GjaYGDaFi/Fu9UuJd6yC8OsDQvnMqssAIM34S0kHPy1VW3XCCy0unLbzNbKQKy
         1mdA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUrZv/NxKeaKUwfgEM7x5pZdp92r4QYegecPFrGaby3Ix70ZJnC1uXc9sbkaEXaBSk2771e+A==@lfdr.de
X-Gm-Message-State: AOJu0YwPSeu32GXGlbPrtIigkz8RqeOmlz1aKTp3NpyCPGgaSdJZOjHG
	G+bQTGSI67IVlUUDvmGx/moQ6R+JvrAgg1V3H+ZuRqtZA6ynnKlZmDXj
X-Google-Smtp-Source: AGHT+IGDXjvYqRvG39ukyFlxobFfBkSt+pX+mVZLps23FeijQOy31y4CfK8u/agvLtypm5ZJBrFapw==
X-Received: by 2002:ac2:4e0b:0:b0:59b:8264:ba46 with SMTP id 2adb3069b0e04-59b8264bb80mr3166843e87.42.1768231045340;
        Mon, 12 Jan 2026 07:17:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HGV/gIzHoPgO30xwmhyszzAeLnvlV0cvPS+dg4JcMUMQ=="
Received: by 2002:a05:6512:3d0c:b0:59b:6a98:7132 with SMTP id
 2adb3069b0e04-59b6a987291ls83531e87.2.-pod-prod-05-eu; Mon, 12 Jan 2026
 07:17:22 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXm35x3zpkc0zRdGIo8dobqCotrY27eY3rBOB+ky1RHk3I1zOK9EOUCSWNyXWDM1q/Jzw91lOXI5AY=@googlegroups.com
X-Received: by 2002:a05:6512:3f0f:b0:598:faf1:3c95 with SMTP id 2adb3069b0e04-59b6f04f7ddmr4542696e87.36.1768231042515;
        Mon, 12 Jan 2026 07:17:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768231042; cv=none;
        d=google.com; s=arc-20240605;
        b=QImoSYC88NYdOT+MbIcl3KUA+QxXwBuG9r82dTxPUVz8ZvW/hpiAlw9650IMcRrVcb
         VTjN4R0Jn2u+h51DjFHondmd99+gJc5Mnbmqi53in8SmXvHbV9dYkNUUVR2oEH2MFb4M
         PyDTU3aPFKa48O5Erxwj2jrA7+mKwpZyxgC1pBh50DxWNXG7gHfItyleCkwDokPtRGHg
         OIsodAjP4jDwdlSZhf+k1XYIUyumLEtlQ3FyBhvPhbx19+sRqBEDNuLVRxaDfyW6/D6B
         Ndnd0KqRp1oSpVuzb8cNlZk9wG9Jf24X28JvLIHeCfQVzQ53y4f3goyH6M0Oh9Myyylv
         KJFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=RB7Ucfc9JWHOv3Ic49uJAd7t2evzS3bLNSohJ8k5FrU=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=MYwmCZ3quqSYZHjG+PDSfj/59LuzbgnRTm14hOYzA+RmzJ+XXxXl2lOZIsyWieZHLf
         DFeoalp7LfVVVj34N2suqY1i5RyAmRegTcxWL6IYawEPc9PFp/AJbKgYDXAPo5q6/fm4
         /YzRXQX1F/a6tv4bk4+5qPcf5Mzwifi/Jmnvk8d3R1WuY+Kr18QWgCy1oib6YqDlRrNE
         LsGcnamfyngRyivCz69DTUWtUCE5PRB/F1FLEPlCOWRGmDB0HruAetmgTg8472r3RRrz
         Oo3osscld9BcCX4kjYAf6BWtl8f94Z1yU6+xkht/8rGOlKOid5lPY2h9LkxoOhoeYeu/
         jQdg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BvgqrFK6;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=BvgqrFK6;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59b6f504593si238542e87.4.2026.01.12.07.17.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 07:17:22 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 21F445BCD6;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 05AB23EA63;
	Mon, 12 Jan 2026 15:16:59 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id +GoZAWsQZWn7FgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 12 Jan 2026 15:16:59 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 12 Jan 2026 16:17:09 +0100
Subject: [PATCH RFC v2 15/20] slab: remove unused PREEMPT_RT specific
 macros
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260112-sheaves-for-all-v2-15-98225cfb50cf@suse.cz>
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
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
X-Spamd-Result: default: False [-8.30 / 50.00];
	REPLY(-4.00)[];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FUZZY_RATELIMITED(0.00)[rspamd.com];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[18];
	ARC_NA(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	R_RATELIMIT(0.00)[to_ip_from(RLwn5r54y1cp81no5tmbbew5oc)];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux.dev,linux-foundation.org,gmail.com,oracle.com,google.com,linutronix.de,kernel.org,kvack.org,vger.kernel.org,lists.linux.dev,googlegroups.com,suse.cz];
	MID_RHS_MATCH_FROM(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid,suse.cz:email]
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=BvgqrFK6;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=BvgqrFK6;       dkim=neutral (no key)
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

The macros slub_get_cpu_ptr()/slub_put_cpu_ptr() are now unused, remove
them. USE_LOCKLESS_FAST_PATH() has lost its true meaning with the code
being removed. The only remaining usage is in fact testing whether we
can assert irqs disabled, because spin_lock_irqsave() only does that on
!RT. Test for CONFIG_PREEMPT_RT instead.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 24 +-----------------------
 1 file changed, 1 insertion(+), 23 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 882f607fb4ad..088b4f6f81fa 100644
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
@@ -707,7 +685,7 @@ static inline bool __slab_update_freelist(struct kmem_cache *s, struct slab *sla
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260112-sheaves-for-all-v2-15-98225cfb50cf%40suse.cz.
