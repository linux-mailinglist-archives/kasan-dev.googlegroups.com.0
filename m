Return-Path: <kasan-dev+bncBDXYDPH3S4OBBBHLZGVAMGQETC5UOEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 6C2997EA363
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 20:14:14 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-2c50257772bsf44431301fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Nov 2023 11:14:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699902854; cv=pass;
        d=google.com; s=arc-20160816;
        b=qZQ0o7G1BlLar1f6DcWfckx/BxB11xvSGAyiaa71uWLkuotPAHJxqc28JqyUlJelLX
         rUApvKqKU6oaEaqoPeWN3JPIcKPmQ/1ikYeI2t6KclST5cMYTUgKzhegQIK5ZdwXXqnW
         GkDlWBwyTYI0cb0LFZo6ICx6N965hVryBJvllkD+Jcq7MyYyqGiSFARiLXejInt/JiHm
         kAJshc77QSzlhPm6+oRhXyrlbrvYD93LdiLB3caVhT9O2eJ24My84DaVZZqsJB6UVbO6
         VW6hnLDb0/bQo3ypa06G8/5U5GyfmReePU8r/t6KawA27vUIf9jMe/ejRxNCIZHZkqcp
         dhjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=mvm5ll8jecCqiqfj3jC/gZjGp5uiw9Qgj0YuITEKh54=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=zwAsnT1NyaALUc/IAtKKsojiILZNNY4qJ3rb4TxFfJN0jWQ2Sy3iJrQAPr/eqiTUcV
         udB3iKDs5QS/DfOWEfSVWSl+luABPNhNrzV1QRchEDQ898SfP035wItz4s4bBfyV2ErZ
         JWukH0rw1hEg4+qYoZ7xfMuOoniqxKGeGo+uF7nhAtfEJAQcmttcdkoXjbq/xHCH9hl6
         a4zYdBa+/rurfPkLytdfILXo/0EPOmOdpq6LRR/MbXMg49ndfMIDMrgqz/fwMX1rdMmW
         QJLsup2flLe8QbXQSD+bTBtCQZvUErZisiRonDRcbi0U317K4f5/pWxDPN9/OdKBcoOB
         bR2A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="EDCJw7/r";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699902854; x=1700507654; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=mvm5ll8jecCqiqfj3jC/gZjGp5uiw9Qgj0YuITEKh54=;
        b=CSwGY2WSZfq/iINnODieNYz7MMpS1eNDllNgtm7jRe7OHovwMIlAzQTdsm0iA1O0hb
         ySQAf6BhOznAGJBbfhJ5JH/PxvCaUVYvwOM7SGmnpjRH5BLUGpF0pIOgZIP691CsbP9s
         Sjvaln2qaFmyDp7JGRYpnn2m7gPRaeEx7mmebpqX85VI9uMXGyw7PAG1/343smeUO3FP
         1QvBt9VTSdNY8Lw46IrQ0ZmTvrXTFFfyZ4OT/RR+4PS6pzqTnhGM4plubbg25cadR5PI
         t2aonQIPx9xFDGOLAKzgvQqFReo/qJtgvMSYqxDaVNxmcmr6QHuVId8nrfpk9NGfk+ch
         kabg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699902854; x=1700507654;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=mvm5ll8jecCqiqfj3jC/gZjGp5uiw9Qgj0YuITEKh54=;
        b=nqV0e4WilWrZaDmmPXY+WzcBfhQdKNFylmqugFlbdXMwR09RZATL9gQ+iHhbP5oRQ0
         2a7BW6MSanp6SSGEstKaavpw1kEgvxfXfXCTE8VnBQqvckbECGXK9MCgvq8ZAo6iwpGx
         q4sKm0y7tfx3ERp7CFwPDs0/rnljOvphSH13gYAkmmHKnQ0hXMcntjRZyhqyIArsT8Ar
         LQndc479UfzKBET4Bpl6wvW+3ziSUBz4m63u8gtITsRg4c0ZKUFSYetqb6IsfPrpRfZZ
         kFx9QM42vGxzeuvSuG+m1fhP0PcukOw2Jet4MQ3XEl9JkvMqDiN1riNNJJT0kcb4KtbO
         zEHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywnmjp1532yZxEbJhIXbR+q121CQjfLqzHihf4TwzkMD5YfAmEl
	T2/IzZ/zzhgGBLeqbt3N5aI=
X-Google-Smtp-Source: AGHT+IF1SyRXkHJejso7DCEMSgsgM0tlpMlcDRrAQJ7bxBzVJD6PksbpV6RwOhhAJxuNQgo35OUy/w==
X-Received: by 2002:a2e:980b:0:b0:2b6:da88:a2d0 with SMTP id a11-20020a2e980b000000b002b6da88a2d0mr136352ljj.47.1699902852662;
        Mon, 13 Nov 2023 11:14:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:538b:b0:404:7d64:bc68 with SMTP id
 hg11-20020a05600c538b00b004047d64bc68ls866121wmb.2.-pod-prod-08-eu; Mon, 13
 Nov 2023 11:14:11 -0800 (PST)
X-Received: by 2002:a1c:7506:0:b0:409:677:31e7 with SMTP id o6-20020a1c7506000000b00409067731e7mr6358087wmc.11.1699902850844;
        Mon, 13 Nov 2023 11:14:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699902850; cv=none;
        d=google.com; s=arc-20160816;
        b=rsGSWpSAmDuOACTpI8z72ez4BssNQy2OTi2LZlvxzaN5f44ZqYs2tVXfIvcTURmdDg
         X1czE0RcnqxsLzPcEG7IkT5qRL+nJgOv9UWlnM9hnNI56NJFzypM51J9RQlDMMkp0ctJ
         mKkM0PRzelFkhNowvBUO66k4kkWagd3wyr9W0pYFd/KOaD+8WBhiUwEI1cAs/kUyV4DV
         7Znr+4gUoeYpmWZyaPpafwIXF05MRUv146JF4pu8GBFm/bVGuFXUwBDdn1gkhC0Nq8QR
         U9rK5O+7nQZiBqOgqJj2aDb20cBFb0k1PuEhoGCye6m5nty5qZi75uspRTQcKy1vgHFD
         xzOg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature:dkim-signature;
        bh=gc35dnOv0z/EAYeff3HVhELHQaD+6wOr4+QtkQBoL1I=;
        fh=RPAmrUlnQQdc1FhCirEqyhGh/OnPyRxUfAdj7ygPMx4=;
        b=Yk0yiXkATcrskMPiGavmJNWuFcf9FRUId66MgxkXnUyKFOF0Ol7DaW6LWgV3HDwJjo
         hjnI0LSa5MP+tLrGFTDOTX5mcB2575l2tzY2ngpXTD7Hdd0ZYPbYOIqvOOFVJeBbQboj
         vyXruFalOtbaHA/XEs0cLxhahTDwSsCR9YarzAhue8cnloTT1YHnb6GLW4u2hdS9Szpv
         gUtFUKUpqWc0GIhIg8efa+NmXLjMvoiE7gZdWqsAWQ5//r4Sdr+ZpVBtvAJ48e7AJ/Gs
         ck8sYZOafrPQereRwp1jD0n2B/Fl97MChSiFHvKAn74ead7zfYrl9O8S5ugMJeK2Qq4z
         LmWQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="EDCJw7/r";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id u22-20020a05600c139600b004047a45b541si179wmf.0.2023.11.13.11.14.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 13 Nov 2023 11:14:10 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 65BE321907;
	Mon, 13 Nov 2023 19:14:10 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 040D313907;
	Mon, 13 Nov 2023 19:14:10 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id eJtLAIJ1UmVFOgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 13 Nov 2023 19:14:10 +0000
From: Vlastimil Babka <vbabka@suse.cz>
To: David Rientjes <rientjes@google.com>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	patches@lists.linux.dev,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Marco Elver <elver@google.com>,
	Johannes Weiner <hannes@cmpxchg.org>,
	Michal Hocko <mhocko@kernel.org>,
	Shakeel Butt <shakeelb@google.com>,
	Muchun Song <muchun.song@linux.dev>,
	Kees Cook <keescook@chromium.org>,
	kasan-dev@googlegroups.com,
	cgroups@vger.kernel.org,
	Vlastimil Babka <vbabka@suse.cz>
Subject: [PATCH 03/20] KFENCE: cleanup kfence_guarded_alloc() after CONFIG_SLAB removal
Date: Mon, 13 Nov 2023 20:13:44 +0100
Message-ID: <20231113191340.17482-25-vbabka@suse.cz>
X-Mailer: git-send-email 2.42.1
In-Reply-To: <20231113191340.17482-22-vbabka@suse.cz>
References: <20231113191340.17482-22-vbabka@suse.cz>
MIME-Version: 1.0
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="EDCJw7/r";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Content-Type: text/plain; charset="UTF-8"
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

Some struct slab fields are initialized differently for SLAB and SLUB so
we can simplify with SLUB being the only remaining allocator.

Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
---
 mm/kfence/core.c | 4 ----
 1 file changed, 4 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 3872528d0963..8350f5c06f2e 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -463,11 +463,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	/* Set required slab fields. */
 	slab = virt_to_slab((void *)meta->addr);
 	slab->slab_cache = cache;
-#if defined(CONFIG_SLUB)
 	slab->objects = 1;
-#elif defined(CONFIG_SLAB)
-	slab->s_mem = addr;
-#endif
 
 	/* Memory initialization. */
 	set_canary(meta);
-- 
2.42.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231113191340.17482-25-vbabka%40suse.cz.
