Return-Path: <kasan-dev+bncBDXYDPH3S4OBBQ6N52VAMGQEGGY4CLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 5951F7F1C79
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 19:34:44 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-2c8767e6074sf20656301fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Nov 2023 10:34:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700505283; cv=pass;
        d=google.com; s=arc-20160816;
        b=q5TKG0ppE7JOf6msCEwE8zfcBkUdbDz19JRv+3zQTzj/5cfToUXH/99XovGPfDTOrJ
         BvYd5m40OPI9rHsMNy/liichVmEv+ZLCn7aLLAmOftMYwfr/9Zs2XcPwrPKnjBROY+zI
         MNAmI6X0RaGrJ/0CEFCGBFTs33rsohnMChI0ovd56o/XNvYqG6j+68yCDTkYy9ccLda4
         ompx42/4H852512curRNKDFiZ5YilG156cASvzjcWbc23eSlfMIu0ivXZvC6gfSmaPPC
         B7dRTjd0ZkfroW4e4VbxTuR0WLXzyTfkM1p/ThZmChmREE/XOhExAActDw5E9AJSt/65
         GO3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=CQPE2T5lcQJZitxHcrnsQksegNn6Wo2Urk7bO0GF9Zk=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=NuQr0fovYW53kQiOUO6OojMIMKVgJbumtmKJD+kZYXuLecC5x1iQYE4ixg+7nStrku
         hWZbialymcIlmwcMvQszyF8EH5I1aJItSAZW1dcTpkUOsJvQtDK9BmblrZQnkdEvGe5m
         O2oXqnfE/E5FMuCCedPDUPoV9Spze44rw6ZUBlXP40iQD+DSQ8QngNTqgFD8kGnTy4Qg
         JhV+c8pJpAG19bxsucwNEMBZKBOqs7GGdC0reddcjgYLMFM6SM/dbO7UmlvIhJXqbtjP
         JSRi9N5Druiz2Iesgnk2nd9ddT8JMeu4GSa3VOnuNo8nuoTXoznFIVZS8TYyQalpEQm4
         AKIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Mc9ZBcq6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700505283; x=1701110083; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CQPE2T5lcQJZitxHcrnsQksegNn6Wo2Urk7bO0GF9Zk=;
        b=VtwSYwRfRTzGm5b1jS4FpAfv1DHvHNARjdp3xzo3kV2Ij1YitkVMjhNmW17236PApP
         3QQ6EljovIj+kKLwANKj7r6zOEVt2fJb5rE3V/ct56uPI8Tb7SOYjZCKT4Tp59+15edx
         6nG3FMgEr6cGCIjeidzhcE/vcIHzulrnMZ4ZMAdOfDYzXsd0CowrKWu+Jj4bFDVe7jcR
         W8p5kbMJ/U+ntjTEDnsuFlU3uT58DkFigeRshOvwYdWkNl/BnTckW8P9UEp8SG6J3Q4L
         sVX/fY92nmHCW1YqV+bmqQz50ZWwd0D6eYEkQ4pvoO+V7MzG58zMbmudK8H3wQN7zmtU
         o4yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700505283; x=1701110083;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=CQPE2T5lcQJZitxHcrnsQksegNn6Wo2Urk7bO0GF9Zk=;
        b=ktWpKieiLtVnePtqyORL++3rHLXUlsROutm4M1RHLdueryFj3vjQPweaj/4TiDk99i
         juUQgsPqIPk57YyW/ePTyyww4BwhaVSrmRDHSAaR0izC4REv+4BYZFUeIGfKOIDjZy3/
         a+Rqv2AOK9Vox7dBWfJ2qn+DUN5DiO7IcS88F3zR3TszAAS4Yy+LsZHZu209RJmHxZ3w
         tc28NisTYbFBV1OltwQ+nBLg08oLGVbp170aZM1p83PE3jfMMfPxYyCI/y8/42eT0Of4
         0TjqMRWIqU/oVVCqGKTipJKc4oM2y+ucvsTaWtgLVy6wqmrZJLWSNcl8bggB+SEbmBl+
         7FXQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw0aM+tmNtbUms/p+4oXdhOgKl7OrSGT52XYME0ewJ037g/5/pa
	ulqJb0rYJgsE+zG3yphXcP8=
X-Google-Smtp-Source: AGHT+IFMn8Kq4okvR8HFaxG8gkM8mNNybc9kH7aBTjNrYISPMaraHxevWv2nzG5Oq8npeImiPPUAkg==
X-Received: by 2002:a2e:9054:0:b0:2c4:f768:c6ee with SMTP id n20-20020a2e9054000000b002c4f768c6eemr5008423ljg.19.1700505283443;
        Mon, 20 Nov 2023 10:34:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1c7:b0:2b9:5450:e122 with SMTP id
 d7-20020a05651c01c700b002b95450e122ls119284ljn.0.-pod-prod-03-eu; Mon, 20 Nov
 2023 10:34:41 -0800 (PST)
X-Received: by 2002:a2e:94d7:0:b0:2c8:71dd:3bab with SMTP id r23-20020a2e94d7000000b002c871dd3babmr5088851ljh.0.1700505281479;
        Mon, 20 Nov 2023 10:34:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700505281; cv=none;
        d=google.com; s=arc-20160816;
        b=L4v8aeX0S5cQd7PGtgPgn518lKAKZTlYCIjCieGbbXTlTRnzMtf6PsD6d/mlRKW0QU
         elhlSRYToST/H6rtFtfu5KD3CxoBIlveRKb6vyDkMzt8Q26uVWHRQ4ZgmwlEc+grOMQz
         nrBg5DggEkYfs7DMPbEx8c4Y6toQY7yRl0tYip2UoNIRIE33xXf+6Ugq+CB5PrcTgWy1
         AIvZJ1RIxVOQHwOM1nxGdCKku2NHk5r9MBcPtfVAxVRp6XMRjySxMEUaPO/fjvh3bb37
         xvVP4roYidSWcU+FwUzyiCfnDUZrOjfgbmVIkVHoUrcySCjLmwJlSIQE6ZaQ4tA5jJV+
         AQPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from:dkim-signature:dkim-signature;
        bh=Ndzzw2LDYk3UJM+5T71hG/B5zzIA5XjvqZzPCmRkAfA=;
        fh=ONqwzSuNvSIo96fWAp0pW54nN9xAdzTfApSlC7LEvRU=;
        b=CTpaiBa+8kTExcq2g3FyJbJnBSyGJQm9i6wgUGqlShEQY4Ej/0Twsb6xGqojfq+bNI
         CDby5S7yOEI/UFqCtibmVY1DapFBUbDHswuJ17vMdeFzvL4zT9zHlC/sOZQ2w3UoKhrh
         Nv7caw9v2htabyY/1Pg1XAEWWZePHuhcoCr7M+TTNDbIDXN0bX+iC0W9tMlbuiA9R9td
         JgiCGih/jD4gPpeSMh1w+cZYQwpsgxb6fe+aX+WZbKAEzxXbypJy5kQnuNjAJ892ebd3
         tfFyJRnlzkQHBdTd3m0MK9I1N6hvsE8vswbx0F0KidaLpQh0elYx2IlCMpl9avp0a2Lq
         OMpQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Mc9ZBcq6;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id x22-20020a05651c105600b002c12145a0cbsi314253ljm.7.2023.11.20.10.34.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Nov 2023 10:34:41 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 80D1221910;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 3D2A713912;
	Mon, 20 Nov 2023 18:34:40 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id IIxyDsCmW2UUMgAAMHmgww
	(envelope-from <vbabka@suse.cz>); Mon, 20 Nov 2023 18:34:40 +0000
From: Vlastimil Babka <vbabka@suse.cz>
Date: Mon, 20 Nov 2023 19:34:15 +0100
Subject: [PATCH v2 04/21] KFENCE: cleanup kfence_guarded_alloc() after
 CONFIG_SLAB removal
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20231120-slab-remove-slab-v2-4-9c9c70177183@suse.cz>
References: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
In-Reply-To: <20231120-slab-remove-slab-v2-0-9c9c70177183@suse.cz>
To: David Rientjes <rientjes@google.com>, Christoph Lameter <cl@linux.com>, 
 Pekka Enberg <penberg@kernel.org>, Joonsoo Kim <iamjoonsoo.kim@lge.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, 
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
 Roman Gushchin <roman.gushchin@linux.dev>, 
 Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
 Alexander Potapenko <glider@google.com>, 
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Vincenzo Frascino <vincenzo.frascino@arm.com>, 
 Marco Elver <elver@google.com>, Johannes Weiner <hannes@cmpxchg.org>, 
 Michal Hocko <mhocko@kernel.org>, Shakeel Butt <shakeelb@google.com>, 
 Muchun Song <muchun.song@linux.dev>, Kees Cook <keescook@chromium.org>, 
 linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, cgroups@vger.kernel.org, 
 linux-hardening@vger.kernel.org, Vlastimil Babka <vbabka@suse.cz>
X-Mailer: b4 0.12.4
X-Spam-Level: 
X-Spam-Score: 0.04
X-Spamd-Result: default: False [0.04 / 50.00];
	 ARC_NA(0.00)[];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 RCVD_TLS_ALL(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 TO_DN_SOME(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 REPLY(-4.00)[];
	 MID_RHS_MATCH_FROM(0.00)[];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 R_RATELIMIT(0.00)[to_ip_from(RL563rtnmcmc9sawm86hmgtctc)];
	 BAYES_SPAM(3.84)[96.50%];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 RCPT_COUNT_TWELVE(0.00)[24];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 FREEMAIL_CC(0.00)[linux-foundation.org,gmail.com,linux.dev,google.com,arm.com,cmpxchg.org,kernel.org,chromium.org,kvack.org,vger.kernel.org,googlegroups.com,suse.cz];
	 RCVD_COUNT_TWO(0.00)[2];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Mc9ZBcq6;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted
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

Some struct slab fields are initialized differently for SLAB and SLUB so
we can simplify with SLUB being the only remaining allocator.

Reviewed-by: Kees Cook <keescook@chromium.org>
Reviewed-by: Marco Elver <elver@google.com>
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231120-slab-remove-slab-v2-4-9c9c70177183%40suse.cz.
