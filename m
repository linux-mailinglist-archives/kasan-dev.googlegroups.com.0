Return-Path: <kasan-dev+bncBDXYDPH3S4OBBWNVZTFQMGQEJG7CFTA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id +DZ/Kdsac2mwsAAAu9opvQ
	(envelope-from <kasan-dev+bncBDXYDPH3S4OBBWNVZTFQMGQEJG7CFTA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:15 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 336BF712A6
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Jan 2026 07:53:15 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-59b6d228006sf1146937e87.0
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Jan 2026 22:53:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769151194; cv=pass;
        d=google.com; s=arc-20240605;
        b=LRDd1YCNygbmJ4ESfZ3kbtT9aogmRIGREeS3W+VdI4lgnKR4L1rXm10Af5tr9Xe4Jm
         wTcHMLPizHmhrndNwJLwO/Yrqk1sUTfcvFog8zUolTgW+rk6neWQ8whj/zhhc1Zu/U81
         du90/vjYVzplH5W7p/hEi4XbtOqebCxn3lYHQ7ZnHfL/Cy3thy8MFqBX4JEXIlHVmA9r
         8sT/oxTDaUroV61HjEXdHAnSpq+MPie/GTRi+jCZATOyCOwu2Dvg+ykj8HDccvPZ6tvN
         Fbpil4Cjjig0dAaPkqPELijwcVf/Rbag3TbrBTU1Dp40YwXm0F47dckWg5ilWox1pzPh
         a0bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=H1iSSoJvs4VOHaxtO0jHP3YtDa/5RZ0TpKs+MwZ4fTY=;
        fh=Ge3gaqO2ptaK69diuL4yjffDR5IurSZsovGhGFNZGKI=;
        b=MR78VOHUNp/MdYCTk4hC6bTfbsLLNcdYjXNAOCzauMHL8wUQMO2EosAObTxGK9V9Wu
         P0O35ZysjJ1nQJmYWQrbFE0EYMNE1ITzo29bGwUvN4gpymGk0a3EpJBaZ6kNVSurTfup
         P44/b7jdnS/LUaIsL7tDOaPGIsMc3ECrXxL0CuiN5snZUnOkGWJ3ZYRtQCUih6rQ+yX8
         ZVexTnUKfCjHo+y27eTZgQmSvmzBGLgHVLGoeFML+rbWxjpwhNuj/b0t+5/nN6K9GhDn
         u05y6+Tsizitm/7c/07/sIOzxH/katoQaBCaJosWV7xLT4zja5EqLya2Vvw1lx0xbeRa
         krCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WZgDDmnw;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769151194; x=1769755994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H1iSSoJvs4VOHaxtO0jHP3YtDa/5RZ0TpKs+MwZ4fTY=;
        b=qM0mubtUUtTJvKdUK7g4RBDpplmctLAq7XuqiEKx7jEw7jLhTLHD1Q7LooLCdbJmVY
         Fgn+KXDh1tEYU/qjBq9XbLkbTqbqpzCu0iDVCBX8BwuM6sX2BBfSiYnfmztB7HTMENSG
         fce7vi0eUgqUEE5yyPefTqN70hbCCsspoXKZRWYna45jIVJtfgKZSou7HDi0FoxPfCoq
         Z3VasHmLLMItMuQ0VzGT5TXk7p/zojk2X4J3r3WloOlpCD2dMmBDw2jevSWZQiI8TMtq
         DDGSxYZH75GH+TPfWAmfXObBB09koM7Vc0JpZ9CIsZUp269PNjmEc7XpWoIMG5aQzC/a
         Q7Ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769151194; x=1769755994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H1iSSoJvs4VOHaxtO0jHP3YtDa/5RZ0TpKs+MwZ4fTY=;
        b=kdcKbkaHx4eo8L6N/LjDA46AqtXKHwmByyEiWqbFZHNt47wbLzmI9nesgZhojkbIH/
         xvPACxp0WshHG/l73OF/VCLiFzI+VUV4t0TwXHopMH87znTHKdg5ymfw2Bvw4c5F7poM
         ka5VLpxJ4HhEhTIZF6MdnkuDzdzduRXYdXK48YAjAw5cEfg0gQfzdthlxhaHy/D8Wzs7
         u1IUKEYsWTFdCLJSjHkzZEX0tNDSjzv0yZtmzM75mnmT5AA9qlkgKyCj9vm1mJ9t896V
         8adCbqAL0ji0oafk0xSAHD12v0rZ5DIXAPaVX3vspT3nhonMwRonq9LVPVqoipFtvkyb
         LluA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXwWabA4+x/uZygaWEbKuIUUKgFlWwLmiV9V7v/yiFNHwtPAtd8uFZnkFq0fEkbT2UlUm4gKA==@lfdr.de
X-Gm-Message-State: AOJu0YyJuZEv0afJwC5rJD/AqgQDRacxG6NjI/Lp/orRANYTSXLyF1kP
	hXerbrmUCss76kWFiN9DYJWKiBn/zYHeRNTdbIy5R36GopzdmEBEzpP6
X-Received: by 2002:a05:6512:2207:b0:59d:e07f:8bfb with SMTP id 2adb3069b0e04-59de49282cemr670600e87.45.1769151194052;
        Thu, 22 Jan 2026 22:53:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FhNGvLMVSNV8wkdzJWV9CyDL0SCOvfWUNv5H0d3j2s3w=="
Received: by 2002:a05:6512:2352:b0:59b:a040:2eb6 with SMTP id
 2adb3069b0e04-59dd7979f26ls527378e87.1.-pod-prod-02-eu; Thu, 22 Jan 2026
 22:53:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWxadxOLx3upQI8XtQ/pKxRQFKIorZ8O2cy6PZQLs7f0arAhL6YqT89nKhfkMFl3W57QAkPA5woSls=@googlegroups.com
X-Received: by 2002:a2e:beab:0:b0:383:1704:2207 with SMTP id 38308e7fff4ca-385da008a59mr5758791fa.20.1769151191358;
        Thu, 22 Jan 2026 22:53:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769151191; cv=none;
        d=google.com; s=arc-20240605;
        b=efOaiu7/BiVJyKM4/4UIDficpDDTqQK0p7su/aVKPHOcCD5ysZOmlf2AZtTBVmN2Kt
         dfUg1glbh3R6n2vtz3WqXbiusvtJm+7zN1v26Nd66glLS40FobMnsd/5cMwGn/I8vBI8
         k2OW6DK548jrauBFXwxMf8OTG+YpxWJN92X1yk5T1ndDgI8w7j1czlXR00yTRjoHUfx+
         UeWd3IllfGWA97FyU3tqQ/nTuTMAQrV10OYl/oUyiX4J1aujanNHK1UM2PaAWq5xNvCG
         g6pMjvvL2OIGqk+K8ab0hMdFCoSbw0xNPGIhqwghh8WFJh8eYdQeUzjHA4kHLqTgw1SY
         qdhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=p1HSP8e11HaumGUNzZ8v9KE8CG2FWMpTiIvIoTBcPSA=;
        fh=+YiR3k2M4/hjhpad8/hMpDOxCdG92wPg4T+KQWP+jEY=;
        b=kCVZVjeRrVYoAALgvADvyPzi8sOdaHnKM1DWuSHGftT0XaA7MJn6zjudH15SfJUhiZ
         QpKrHJT0KMLB4E0vs1GESBonZituFs5BeP0btZUvTuOCTxb91hA+30+KwWb3ZDFBwfCm
         9I38gGKPtrDLlnYfcjAyt+EScrdKqT0AGBz7mE5bx9iotKQibcXZGRAVA2s+3Pe/hhaS
         r1l8iJEYiQ4oRMaKudYlMFNUUlGYuPGaFOX1hzprHsHSVqmVchrnHOuJZB/jxgAaDTer
         PdmZOhpqjXzeTHNtAjnINSYrsRyC33drYTgm2XtEbMHrzV6t6F+rQlE+lfJa2HadVPqQ
         gZYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=WZgDDmnw;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [195.135.223.131])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385da117b3bsi320391fa.6.2026.01.22.22.53.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 22 Jan 2026 22:53:11 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.131 as permitted sender) client-ip=195.135.223.131;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 95E685BCCD;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 61D11139EA;
	Fri, 23 Jan 2026 06:53:09 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id cLyTF9Uac2k4YgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 23 Jan 2026 06:53:09 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Fri, 23 Jan 2026 07:52:41 +0100
Subject: [PATCH v4 03/22] slab: add SLAB_CONSISTENCY_CHECKS to
 SLAB_NEVER_MERGE
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260123-sheaves-for-all-v4-3-041323d506f7@suse.cz>
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
X-Spam-Score: -4.00
X-Rspamd-Pre-Result: action=no action;
	module=replies;
	Message is reply to one we originated
X-Spam-Level: 
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=WZgDDmnw;       dkim=neutral
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
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TAGGED_FROM(0.00)[bncBDXYDPH3S4OBBWNVZTFQMGQEJG7CFTA];
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
	NEURAL_HAM(-0.00)[-0.987];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid,suse.cz:email,oracle.com:email]
X-Rspamd-Queue-Id: 336BF712A6
X-Rspamd-Action: no action

All the debug flags prevent merging, except SLAB_CONSISTENCY_CHECKS. This
is suboptimal because this flag (like any debug flags) prevents the
usage of any fastpaths, and thus affect performance of any aliased
cache. Also the objects from an aliased cache than the one specified for
debugging could also interfere with the debugging efforts.

Fix this by adding the whole SLAB_DEBUG_FLAGS collection to
SLAB_NEVER_MERGE instead of individual debug flags, so it now also
includes SLAB_CONSISTENCY_CHECKS.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>
Reviewed-by: Harry Yoo <harry.yoo@oracle.com>
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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260123-sheaves-for-all-v4-3-041323d506f7%40suse.cz.
