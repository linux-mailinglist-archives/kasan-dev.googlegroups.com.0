Return-Path: <kasan-dev+bncBDXYDPH3S4OBBCM2ZW2QMGQE3T4SKKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 3652C94A585
	for <lists+kasan-dev@lfdr.de>; Wed,  7 Aug 2024 12:31:39 +0200 (CEST)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2ef23d3650fsf15975151fa.2
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Aug 2024 03:31:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723026698; cv=pass;
        d=google.com; s=arc-20160816;
        b=NOh4JQUBnZqptO+i8Xf7fBUYQbJtmPrmW3sOfxjZ9x/Vk7EP25FbDc3cPe9cjvxXZA
         +821Tt8iBLtQZJYwgNv0wM1TZoNUx81LOjekrq0T1PWr3h5vUswF3RM9IlIMQLiC1uIY
         DuyyU2E6FdR9vwrsieQ4gKugJjN66tpyWkkjFSnbJggUTWpNJKsPsCBR7uX7mU5fFuVD
         AFynsCiBT3EZq0tPzHO//nwF13mXMYrgRE9VdZknuUKT/Tbgb/CJwkDlFzT3MG3U8I24
         fi4Igj6nxv09wXflMF+6LEQGjoQpGhKLdjt6lLtiH2UbeBOoJyZzVzc/2w1u1WemwJYi
         2rQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=y3z8dSnYx2yxPW1ozVVfs80KPPaM2PHOiBX/9DnWjF4=;
        fh=hToXHN4UAVmzqT34Ht1dFreoV59a1D4qx4FpVKWrFlg=;
        b=lT+aVxwk75MWjpl78KoeV5397/q/ULD7Q8NtSlk48dQyYSp/KE2Wrqt4+QryvC3gIX
         d4iImNtl34/6wta8+Pjmq01m9hTC/i153VV7sqDVnEce2beso8r/n1bXjXFNM2wlNPID
         /BORJacrfcp0AceBycb1CPvRfyBzk0QAPK/XdXex4Bo1vNN5YwOg0ROQ8D8Pd1XlnYEb
         CrZQSFGgVxuBCw6WO5Wg65PieTUmBmAd//F+faca0Mwb8Wrgpm6TOjOKiwmdruY/FFPA
         xd0Dho/MkRUrdCgezzGRx13/ZzsJI3F3QYc09Emx93y61swNb8kH4uLyEMmM84wWqxC5
         2t8w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="wJzF/g6n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="wJzF/g6n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723026698; x=1723631498; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y3z8dSnYx2yxPW1ozVVfs80KPPaM2PHOiBX/9DnWjF4=;
        b=BB3EZ/JYc/z7wu1ZO+vrWpHTcOJJ/9CDYUFgt0CiowguSrOOk2nRLgCMoO///NPf6w
         KYBcb10lWTSgdM1BQgznhy0+gjHyyss1dD8JI3jTuHm+41+jToMXxP5mV27hNPdlg6gT
         JCyfVyZaAPpp9J5bqEfZpwXsuBdlYrznoT7X1txKcPk+Uc4e+nICZDHI3xsc8bOcMkm1
         APqh7/MN4RMBzG32zQbY1fSFoufU+RvVbikwORK7h/VOkwNYo90Ac4MsCFE0EQD/qXmd
         qJHjBIgHuG6lK5PCaIWJFxwLYZf7Waz8GxuSjfuyau6fqxhnWEkp/ib0fEBrHDSqtxnD
         2ifw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723026698; x=1723631498;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=y3z8dSnYx2yxPW1ozVVfs80KPPaM2PHOiBX/9DnWjF4=;
        b=cMQ9iHb+KctjBw+PN79TQCPFZZb35gl1HCis2PNG1s+4V/u2grRt0sUUNI9rArX+Y6
         JlCOM8Wz3VTlUH3VE7KUFmm27PVaBwM2YNUfy20LslcUOp3b8Gr/pS3dVuiEyXd0tsb+
         PvfOVOszdXTTfK6MOIjJWYjQhV5uww6xnnvM0wsXiEAoLEa8d96Dv68WOI8PZRE2FLMq
         6c7W4pAcXe7QxJTXP4E5qCfe4soUEMSw6Qa4nW6zlFdj68oesJkmHevGSEVo1RcZfqAc
         OnmY73Vxa3+eHotv/znVOZJF8mvuxhtMGPXo51SYwC8DAI6d6WhK6sVak9k9ZP8e7qg9
         priQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXfrUQfshDEWX+A7eo08pwbwP6fNExbElfx+KuqbUpj5gaAMLkt/RUKkL7YMwdsgueA/mffOPrT7wHwfzXVrOsOr4LTmY8vyA==
X-Gm-Message-State: AOJu0YyrOW72WhVPvalUqI/+tTcvjhfbiEVYYnqJ5oFDVw0Zi4xD6eBy
	snOUsbt9PssHmeNE2FtmwqrdKRSjSsfnMIdGtS802/ZQ7G0hbnnw
X-Google-Smtp-Source: AGHT+IGHvubGkKj/nbLmIdOA9aEiMEaRo4AoUORX0dkuGqPRS+zardDdf71cqnyAoXG561plmQoA3w==
X-Received: by 2002:a2e:8794:0:b0:2ef:1784:a20 with SMTP id 38308e7fff4ca-2f15ab0c2b7mr128820111fa.38.1723026697750;
        Wed, 07 Aug 2024 03:31:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:2a06:0:b0:2ef:2eec:5036 with SMTP id 38308e7fff4ca-2f16a6028a3ls10144571fa.1.-pod-prod-09-eu;
 Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUfKSnZcTYejc3fBKtk/9obzjwHEhwUt0hANhPgbhxvKqE06VkOpSjRjRPxPFz4jj8IgwGVy8d/rB5in65Ko6kFYSGovii8RgvHng==
X-Received: by 2002:a2e:9203:0:b0:2ef:2c6b:818 with SMTP id 38308e7fff4ca-2f15aab2649mr117866481fa.24.1723026695530;
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723026695; cv=none;
        d=google.com; s=arc-20160816;
        b=V/maoHIqz9k1YTBKSv+DsK3Qw/zwjBELErQKKMzAC1PDClS7dnf6zjH99uZMn3Sq/V
         6XQID9l8RRYvNSNAPQPgNDyzLOlj22haIoygxRoGXqUL5M6QTvdYNp/Y3NCQLw2h4VDF
         bUDuiTyl5BaG4WpTKyQJFsTROhSZsWsJy19PiRq5Ma8dSTMVzcLAop7Y6yj33oCr3srg
         BCuVvhUwxDnVyLSR7d37tuu3v3mGA4hzdxq+f8QZrmml/2/W7WeSAxGiqWCmqnhFQW1S
         k20gy8ycU1/YSgsYN2cPwaChnQhh8iaWBcBIwezkZGXo0T54zpabyQi/6XRNJWPtRhhY
         ZGKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature
         :dkim-signature:dkim-signature;
        bh=Upn+l7aIdIa1NYqSvgAPp2lNr0Z+34OGHoqNziNBnOM=;
        fh=IkE9nfmJjqF0Gh4XK//npeGH2HkSHIqCgOhfhWJ/CPU=;
        b=Ei90T4ma8OiVouFsAwnbnUHMzKTUOwqZXgMiGPpHI6wvCSGP05o9biWtywfN30tyPq
         AVkDQFz6yh2FXPecQiiNASaSKvxrjRDG+v1oBcD7YnHrPJDKwbcSD393Wt4ryfY7rIzm
         h5hkcACnKITKPeq4Uvp1Emcry45f6mijDZw8qU9NeXfBl9//fZlrDL0ll9pvfKUXBso+
         2gWq0NTupIywa++L+OTLxePti87qlqWqeAlfFFFcZbdpQWaIUlBPeeRhKuYFfynAoobs
         PbK8A9Rj8V0A+PCoyJw7of11FG4qdyCOcTDI+mPFpTaBRnaR8I9uIGcz5JfNzXzhYi+5
         fQAg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="wJzF/g6n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="wJzF/g6n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2f15e25d3fasi2273191fa.3.2024.08.07.03.31.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Aug 2024 03:31:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 1D32E21CF0;
	Wed,  7 Aug 2024 10:31:34 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id E333F13297;
	Wed,  7 Aug 2024 10:31:33 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id sNEoNwVNs2YsHwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 07 Aug 2024 10:31:33 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Wed, 07 Aug 2024 12:31:16 +0200
Subject: [PATCH v2 3/7] mm, slab: move kfence_shutdown_cache() outside
 slab_mutex
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20240807-b4-slab-kfree_rcu-destroy-v2-3-ea79102f428c@suse.cz>
References: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
In-Reply-To: <20240807-b4-slab-kfree_rcu-destroy-v2-0-ea79102f428c@suse.cz>
To: "Paul E. McKenney" <paulmck@kernel.org>, 
 Joel Fernandes <joel@joelfernandes.org>, 
 Josh Triplett <josh@joshtriplett.org>, Boqun Feng <boqun.feng@gmail.com>, 
 Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>
Cc: Steven Rostedt <rostedt@goodmis.org>, 
 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
 Lai Jiangshan <jiangshanlai@gmail.com>, Zqiang <qiang.zhang1211@gmail.com>, 
 Julia Lawall <Julia.Lawall@inria.fr>, Jakub Kicinski <kuba@kernel.org>, 
 "Jason A. Donenfeld" <Jason@zx2c4.com>, 
 "Uladzislau Rezki (Sony)" <urezki@gmail.com>, 
 Andrew Morton <akpm@linux-foundation.org>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org, 
 linux-kernel@vger.kernel.org, rcu@vger.kernel.org, 
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
 Jann Horn <jannh@google.com>, Mateusz Guzik <mjguzik@gmail.com>, 
 Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.14.1
X-Spam-Level: 
X-Spamd-Result: default: False [0.20 / 50.00];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TAGGED_RCPT(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[27];
	FREEMAIL_TO(0.00)[kernel.org,joelfernandes.org,joshtriplett.org,gmail.com,linux.com,google.com];
	MID_RHS_MATCH_FROM(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[goodmis.org,efficios.com,gmail.com,inria.fr,kernel.org,zx2c4.com,linux-foundation.org,linux.dev,kvack.org,vger.kernel.org,google.com,googlegroups.com,suse.cz];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	TO_DN_SOME(0.00)[]
X-Spam-Flag: NO
X-Spam-Score: 0.20
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="wJzF/g6n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="wJzF/g6n";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

kfence_shutdown_cache() is called under slab_mutex when the cache is
destroyed synchronously, and outside slab_mutex during the delayed
destruction of SLAB_TYPESAFE_BY_RCU caches.

It seems it should always be safe to call it outside of slab_mutex so we
can just move the call to kmem_cache_release(), which is called outside.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/slab_common.c | 8 ++------
 1 file changed, 2 insertions(+), 6 deletions(-)

diff --git a/mm/slab_common.c b/mm/slab_common.c
index db61df3b4282..a079b8540334 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -492,6 +492,7 @@ EXPORT_SYMBOL(kmem_buckets_create);
  */
 static void kmem_cache_release(struct kmem_cache *s)
 {
+	kfence_shutdown_cache(s);
 	if (__is_defined(SLAB_SUPPORTS_SYSFS) && slab_state >= FULL)
 		sysfs_slab_release(s);
 	else
@@ -521,10 +522,8 @@ static void slab_caches_to_rcu_destroy_workfn(struct work_struct *work)
 
 	rcu_barrier();
 
-	list_for_each_entry_safe(s, s2, &to_destroy, list) {
-		kfence_shutdown_cache(s);
+	list_for_each_entry_safe(s, s2, &to_destroy, list)
 		kmem_cache_release(s);
-	}
 }
 
 void slab_kmem_cache_release(struct kmem_cache *s)
@@ -563,9 +562,6 @@ void kmem_cache_destroy(struct kmem_cache *s)
 
 	list_del(&s->list);
 
-	if (!err && !rcu_set)
-		kfence_shutdown_cache(s);
-
 	mutex_unlock(&slab_mutex);
 	cpus_read_unlock();
 

-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240807-b4-slab-kfree_rcu-destroy-v2-3-ea79102f428c%40suse.cz.
