Return-Path: <kasan-dev+bncBDXYDPH3S4OBB4NVZTFQMGQEXQKZEAI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id EBypNPMac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBB4NVZTFQMGQEXQKZEAI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:39 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 779B271331
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:39 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-3831426aeb1sf9137391fa.3
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:39 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151219; cv=pass;
        d=google.com; s=arc-20240605;
        b=Z5zibP7hINlDIZjXxmd4YJR8F/m+oEKKLQgSDW68ffd/VyWmJSMmLbndx3Z55Pf0Vh
         B1T+LFHnvK1ZkzR9tcxfN1vEDKmLnVkZhlcomUkNth3AP6rgv9XRM2eNsBBf6Gq0X4fH
         cjbVY4XOoOCvgZaI8Tv+b4QluOj4EtSHl8lZOa/gtOfZohZFzgbS0f/OEwQ3KyIQ8Rbp
         cXzq/sFWRpPAzOrqbkry6FTbcC5w1KmJTtX7M5PaI9WeBaWbYGXXi1krhw1tQ1MM0yTE
         FRDQM+xtewOoQxNrTEXpm1IFcmoQHGmCLa5EED3zcydVwxG8tdMNMwHQlICRRo9qYQN/
         98Lw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=1PslOKPyP4ZxTMK2EeRGVm7Bmjaco2Ilju4A+8reXUs=;
        fh=aHFTHWKH9DSc7iH9S9GigR+sEm4cNDn8xj6Q3Mm4PwY=;
        b=KBLTSrdkEqtW+SNnIkrOE6cPzyjzVVpTXerqryu/YEx9tzOhsaTDAyfMKCUg88nuJI
         FbrXXwyeUsvA7cj84QvYHEaC8a8XmqOrNPDICJIQJ5SZmVkdJokPo5h0wbBaiJlDGxcs
         DC/w05G8xE9FLcBiFkKXHGdPo79sFQGDDXi3hRv77TPNhjI0sEZsp9hE1bbhB1Yuo6/n
         v58iuYJSbdlJMbF2sn71flNHTGg0DXytnO5w5zOKXy/zhDVubUkjcK4yTTB9B9p08/HR
         U1+3iPXBr0Zq9SirwjWSRxErOhI+wE+xkNJbtAUy8M9HOLlNFXLKGMdEhY+AW/zYgEgh
         BuFQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rIH49ban;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rIH49ban;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151219; x=1769756019; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1PslOKPyP4ZxTMK2EeRGVm7Bmjaco2Ilju4A+8reXUs=;
        b=Vd/2YZpMQiO9ypEtLwZ8s1VHxJZc6Ad0Yaf+ASAuYeLSz1jp7q/zGnXBNjNZ6lSQfp
         ObM/bYMM89/s0r4YtkLea3KyNpHPyqWh+qExNpSBGWgmS0Ei5poIFEGbBS88oTVdxkzr
         zVw7/i9Q3Cb/AvJ1jzQ7buvZje91SrT613R0nMienJZsrBYpXgKjB2T9UBwlBqm5TAQS
         tGz1oLpQ3KrCITdsAFBx/AMKLWY6ARKC5LhcVeck1bNo4/ONVFo6r1Ypav2BSZDK1wmX
         OV+I2ffOTw8MzUDMXT6aX2GrS/ewrSI1tn8U5Rn+xzZZ0ca4tefGX4kWyS/Gp5HBdcf6
         08LQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151219; x=1769756019;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1PslOKPyP4ZxTMK2EeRGVm7Bmjaco2Ilju4A+8reXUs=;
        b=Zur5G0KhAqlMFIVSImDqR6gtHqCBPvF/dT8N+6lNx140DWsmUVBewIXWhrqLsGBM1x
         pjBaxOx5PiTyZcVWx0GBkpKqL9iwrnw3XHOnxvDS+omCzlaKIFYd7w5bET3+Ve+ar0vL
         +2UtfdYy+IUJTYz03cTVPiUtAZ4Cfn79bMyAobjtkn8HAcUOa+LkpaChxFy4i84WpHzq
         D3i9umTzBXQ3iwm/wfzCeuIVRU/PMWfiNenTNUsUaPrfajLXD9I47kUuTQVlcthn8MQN
         clp+bspMpOjbq9l2Pi0XHFHcmch7Jzj4k9/E21QlVv+vn9AkussDFxXETtonAPbZqe9Z
         XdKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXOFh+QPjCRxBCynhiaHkYkDT1RVWlYNztXk0fayXp4kYTf9iiLFqnPSxYvm+PCF+0pJqxxkg==@lfdr.de
X-Gm-Message-State: AOJu0YyIiO5VEbutBLZTNSVZu0T6P08if+Xj/TgdNbM/2FKPQVunoW1P
	dyinwu5FqWWVjuA5ZmAkxddrcKr0K0mvRPsgDDoOBXhQY9df9YBEnEaa
X-Received: by 2002:a05:651c:4186:b0:382:f994:e545 with SMTP id 38308e7fff4ca-385da07ecbdmr5700521fa.34.1769151218531;
        Thu, 22 Jan 2026 22:53:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Ec0tT4Ru8a8HjYnyopsylmdLNHjTlEBcarLjwzHBsNtw=="
Received: by 2002:a2e:8604:0:b0:37f:d2b5:65f0 with SMTP id 38308e7fff4ca-385c2386402ls1924521fa.0.-pod-prod-04-eu;
 Thu, 22 Jan 2026 22:53:35 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWKVws5G0BHY28dgCt6CjSQVFN+qnDUnmpuq11ZODWNzgsXIG5/VsQwm7Nq0hUp8Yk86J4u6gAJOig=@googlegroups.com
X-Received: by 2002:a05:651c:41c9:b0:37b:ab43:8958 with SMTP id 38308e7fff4ca-385d9f55f4emr5568501fa.16.1769151215491;
        Thu, 22 Jan 2026 22:53:35 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151215; cv=none;
        d=google.com; s=arc-20240605;
        b=iiA42DnyvFcztB2OUuNQCqiqSY42a1yrH6jckuwa+7tJPjh3/4xyC/bVmw0HhdwWEI
         6uAJFCCh1meMcOGUgGXd67jfbwG9sXcwDF/oq7gotSNyb5Wt8cVbl37Qt8xGa5q+O7OR
         woBIaxuBwxP/SSrKnEjneSNNQ9Q9vaXK3wjKdMYxuhRspg46KE8J1pKzKdGqcVjbTnqi
         6MT7xMHeMaxdqX8pRbWSXg1SILbjtQAxoRyRYLK7W5XzGL618rCDnF+qlW9l519s8siS
         f3JIPw1Bz61N85HpnPru+1xu/QVn4l+stoix1XB/+iNpA9ikknmdqjpRZRH0h35Mb8k5
         Da2A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=aH0Ena7htnUNZ5YqbWqwyKSCHR1cGZCmyIRyJ4sibZE=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=WKMJXzGBA7WPNWiB2w/NKp1KIw2+6kOWVQOMRCuWd6MSViSH0RnmhpN/m3mCCq1PWO
         e1a0Uu23D2trjt1dK99Ox330cqVD1+d617rRqCNdK1khfuqfUUTFwB0LP0v5H3vMSmd8
         1YK0d8W+JCK1qWKC3W/ke7A2W/WtIGVJcowqUqx37TjPsLfMvdFflBEAU9rJ56KdDo/k
         UvjoChDjkw4N2FZnZ35QBngOImtLb2V/sW+y+o9X9G+Pqdwmc1LuW0L3Ddzue+P4cdU3
         KOxytubXKSznPdaXEa3esA+Lbn8P75kW+EUIuHjcOQCMtp2XLly/WktjUfMxqG2i0Xcc
         emgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rIH49ban;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=rIH49ban;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385d9f8daf2si412031fa.2.2026.01.22.22.53.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:35 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 12D975BCD4;
	Fri, 23 Jan 2026 06:53:11 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E19B9139E9;
	Fri, 23 Jan 2026 06:53:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id OJDONtYac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:55 +0100
Subject: [PATCH v4 17/22] slab: remove unused PREEMPT_RT specific macros
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-17-041323d506f7@suse.cz>
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
X-Spam-Flag: NO
X-Spam-Score: -8.30
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=rIH49ban;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=rIH49ban;       dkim=neutral
 (no key) header.i=@suse.cz;       spf=pass (google.com: domain of
 vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBB4NVZTFQMGQEXQKZEAI];
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
	NEURAL_HAM(-0.00)[-0.973];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,oracle.com:email,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: 779B271331
X-Rspamd-Action: no action

The macros slub_get_cpu_ptr()/slub_put_cpu_ptr() are now unused, remove
them. USE_LOCKLESS_FAST_PATH() has lost its true meaning with the code
being removed. The only remaining usage is in fact testing whether we
can assert irqs disabled, because spin_lock_irqsave() only does that on
!RT. Test for CONFIG_PREEMPT_RT instead.

Reviewed-by: Hao Li <hao.li@linux.dev>
Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slub.c | 24 +-----------------------
 1 file changed, 1 insertion(+), 23 deletions(-)

diff --git a/mm/slub.c b/mm/slub.c
index 8ecd5766635b..1d135baf5e9e 100644
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
@@ -713,7 +691,7 @@ static inline bool __slab_update_freelist(struct kmem_cache *s, struct slab *sla
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-17-041323d506f7%40suse.cz.
