Return-Path: <kasan-dev+bncBDXYDPH3S4OBBLUCSKVQMGQE2A5KVBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5CC787F9EDF
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 12:44:48 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-421acfe16f6sf47039461cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Nov 2023 03:44:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701085487; cv=pass;
        d=google.com; s=arc-20160816;
        b=sYqxepfzXahwkKjYQBPlRWbUV4GRH/S1w5P1Tjovrhwq3Apf1XFxhqFQvTDylzOJH5
         nzpEfdLpmfW6MXLeBAil1uDd3vjv1Xt4tC5T+b7gHTr/GroDh5H9cEIhgpTQ3MGu2gbW
         KndkORe6EncmcnGKf21ggeIk0Bc2ZyMrEXV2VJZqelHMi80IZVhRM9t7IJPsWzP/mu66
         2x3r43myo+AY7g896rZBVzEx3JT7ECxakgW2Vl2NQIPHbdgmtW+omB3+XfRNTLvSgz8H
         4y30H53ty5vfeEHnrdPtrfLRH4O/lExi38U4CcKhDRPGnh8GOXd24cz8+CwsvxBkJXOK
         vFvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=Jm7I4XMCgUIgL9A0DjRp70sOQ2zDQhgXMvImifUdgmA=;
        fh=NQTwOh0E1WLd0hyEorehruAYYuCyJBOiTguAjklSQ5o=;
        b=tamIUdWMejoN5QnDnwZHTWi9lF/ZvaLQ7xqZVFrSfJsfvkrxHKS4miituwe1WQBULj
         rqvvikbFR+jYcBSHwy4C4c7CFmYRi8DzlGux1/pcDXt3+4VnkY65N9kJwb5ePcA3sEwG
         kLRhgXRM07eStW7LWI8lan9JSvpZAewdlJyW+7p6tA5lsHsqUnVij1KEr9L5QD1vo9FM
         vYZgSE70cnbraugRx8awSv3P5uqpNVVrw+mF7jn8AT434CSyFgEW+Fh/tDf98Un2ZxKe
         8SjS4hzTkRLp4gm49f8vJhXj4BDJRjSCWZFCaFGjOFkaEYKs+e0/dI4A+RfOe5M36NV+
         KblA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701085487; x=1701690287; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Jm7I4XMCgUIgL9A0DjRp70sOQ2zDQhgXMvImifUdgmA=;
        b=WLO9aTTuzHSwH56Y7DuNWB0dgIuJlXB6+oSp7d6M3vYLCUe9JLt6FrxllESbOZFqTF
         iOaGjH6keVvO+6467UuYzb1fhd5Tp/CdaYQ4aEC2Q9C4aRNXnJ9eqgcfmNXjX1ieWAt9
         gR6xTi4jdRspYldcz/wk16ei84bqBL8RDcTCJC0w/Osq/XCxq+7oKguY2JjXVT9eqCRA
         A4bBM7W+ECBMaFbxy4IKEmfGXypHkyn2NoHepQLqDYylLs4iy4w6zqNFMO6gAZSxlVNP
         b3OOJ+KtrxkFUwTlKJPvqKH8vHfvs/DlcQs40l8M1cJhtmdoMDTteGWAj4x/cZBL148Q
         z27Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701085487; x=1701690287;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Jm7I4XMCgUIgL9A0DjRp70sOQ2zDQhgXMvImifUdgmA=;
        b=KKSZwsmPGwk9iVPFGjYl/gTdPqeaIai39vLvtOXGX/FthxyO8LJ4hOKwlnpjxa2Nza
         JXH7ELcLNdhcq+46J8K++ixEE4OSY/YCHB5XMAdhyPKectPmRZscFPmyJlqy0o1DOQbm
         k9yOnzAtajsmsjP0IGocUmu9Hw2I8z08cs6KTilgVfkRpBVbjo0mL+T9UwwCgISddWKV
         V4DFoBf7NZAsypOXbMZ6gapSLuFAYwVWd34pH1h+uzdVTy20b7Ai0ncAV6/GTc8j+Beb
         h0fFT4U4/BI2hUrCwgIlL33o4sIW0QzOQtnaAciFUZ6BFDFc2C0AesCHDNNUeK1z1ix1
         qJ/Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yw8XIXhqg8sdlJj9DuXF/Jx0/bo/Tkr8S3BIUmY+9eSfOTBQUXV
	oA/f9RonB5wNA6hOepSHHOk=
X-Google-Smtp-Source: AGHT+IGvyCvJCtWRbpI+2/4cmny2JB5slrwdMuro0lfG1CAQyH7qi9uxkfvQB2J0ul2zRpQp6GrF9g==
X-Received: by 2002:ac8:7d52:0:b0:418:2268:992b with SMTP id h18-20020ac87d52000000b004182268992bmr12304876qtb.14.1701085486955;
        Mon, 27 Nov 2023 03:44:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:58d1:0:b0:41b:5e46:aa61 with SMTP id u17-20020ac858d1000000b0041b5e46aa61ls61379qta.1.-pod-prod-02-us;
 Mon, 27 Nov 2023 03:44:46 -0800 (PST)
X-Received: by 2002:ac8:4dc7:0:b0:423:a2b3:49ba with SMTP id g7-20020ac84dc7000000b00423a2b349bamr8212471qtw.56.1701085485672;
        Mon, 27 Nov 2023 03:44:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701085485; cv=none;
        d=google.com; s=arc-20160816;
        b=uX+gS+OX3DFP51mI9akj2nLQ3NZG7WHE5LYd3G75BzSMaWz6BS6kx8ARun24rQStAR
         OI/6fAsx+LJH20A82bjgyNLmx5gB2CPGvBe59sb6loGCB4P3D+Dg6KM7SFUwZ3KA5DOw
         ahM4DpxFgMjMcuQJmxGW4cHjUVA9Erp9PojSsIyE8D1IIL1WmDzHgI1B88h520HJjEw7
         lLA86vNt4VAaawS04DXtXboYXTYap3m8VE7oY5rnwW8eWjqQ0F5pkJ4g2qn2tsdmZDKA
         PPIB5hhe79ADHnqDYVZXT/XHsynLmKRifV6Gm6iJWnqO7QTsIVBtm6ZyU9dNOcTulAkK
         Q5QQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=u98qmG+0N4uJ94Mrt8Yf0kqM6NEsRwfSj+qTsu6GUro=;
        fh=NQTwOh0E1WLd0hyEorehruAYYuCyJBOiTguAjklSQ5o=;
        b=Pahq+XpjnADz+33w3ah+D4MGlG7xzK4dpungo2w23dGSS5J6q9MYvjR0Q7v1Zbokds
         AzdC37ToZPYjkv5WU46IQOpkK2rrvcqkn0hOTajvJeD/TPHjL+6znbzeDcsXCiQX1y2U
         NQKKq4UlM/y/0o49JFEdoPM7LUl0zw0F5CGN18PHcOX7AAAN7WVKF9j+nQ5bR8tcwbhV
         WCV5OIeTY7WnTxpu2sWbCWXZQ/mPGZNtvM4kXwK5AoTh2RQqJXa86twp6aVV6AMDK5yB
         g7590KJHLqHSW6jcg+8MF5lRzB+cBYyy7TmPyrJZU5mmlX7im9DMwNixGvHlvJUqdt0M
         8pMg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id cd11-20020a05622a418b00b0041790471199si1647636qtb.4.2023.11.27.03.44.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 27 Nov 2023 03:44:45 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id 779451FD85;
	Mon, 27 Nov 2023 11:44:41 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 552381379A;
	Mon, 27 Nov 2023 11:44:41 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id aQluFCmBZGX2bwAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Mon, 27 Nov 2023 11:44:41 +0000
Message-ID: <1f2f5a9f-61aa-094d-f9ed-be97e3671fb1@suse.cz>
Date: Mon, 27 Nov 2023 12:44:41 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101
 Thunderbird/102.15.1
Subject: Re: [PATCH mm] slub, kasan: improve interaction of KASAN and
 slub_debug poisoning
Content-Language: en-US
To: andrey.konovalov@linux.dev, Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>,
 Oscar Salvador <osalvador@suse.de>, Hyeonggon Yoo <42.hyeyoo@gmail.com>,
 Feng Tang <feng.tang@intel.com>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
References: <20231122231202.121277-1-andrey.konovalov@linux.dev>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20231122231202.121277-1-andrey.konovalov@linux.dev>
Content-Type: text/plain; charset="UTF-8"
X-Spamd-Bar: ++++++++++++++
X-Spam-Score: 14.28
X-Rspamd-Server: rspamd1
X-Rspamd-Queue-Id: 779451FD85
X-Spam-Flag: NO
X-Spam-Level: **************
X-Spamd-Result: default: False [14.28 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 BAYES_SPAM(5.09)[99.96%];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_SPF_SOFTFAIL(4.60)[~all];
	 RCVD_COUNT_THREE(0.00)[3];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FROM_EQ_ENVFROM(0.00)[];
	 R_DKIM_NA(2.20)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 ARC_NA(0.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 DMARC_NA(1.20)[suse.cz];
	 RCPT_COUNT_TWELVE(0.00)[14];
	 DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:email,linux.dev:email];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 FREEMAIL_CC(0.00)[gmail.com,google.com,googlegroups.com,suse.de,intel.com,kvack.org,vger.kernel.org];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2
 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/23/23 00:12, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> When both KASAN and slub_debug are enabled, when a free object is being
> prepared in setup_object, slub_debug poisons the object data before KASAN
> initializes its per-object metadata.
> 
> Right now, in setup_object, KASAN only initializes the alloc metadata,
> which is always stored outside of the object. slub_debug is aware of
> this and it skips poisoning and checking that memory area.
> 
> However, with the following patch in this series, KASAN also starts
> initializing its free medata in setup_object. As this metadata might be
> stored within the object, this initialization might overwrite the
> slub_debug poisoning. This leads to slub_debug reports.
> 
> Thus, skip checking slub_debug poisoning of the object data area that
> overlaps with the in-object KASAN free metadata.
> 
> Also make slub_debug poisoning of tail kmalloc redzones more precise when
> KASAN is enabled: slub_debug can still poison and check the tail kmalloc
> allocation area that comes after the KASAN free metadata.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Acked-by: Vlastimil Babka <vbabka@suse.cz>

Thanks.

> ---
> 
> Andrew, please put this patch right before "kasan: use stack_depot_put
> for Generic mode".
> ---
>  mm/slub.c | 41 ++++++++++++++++++++++++++---------------
>  1 file changed, 26 insertions(+), 15 deletions(-)
> 
> diff --git a/mm/slub.c b/mm/slub.c
> index 63d281dfacdb..782bd8a6bd34 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -870,20 +870,20 @@ static inline void set_orig_size(struct kmem_cache *s,
>  				void *object, unsigned int orig_size)
>  {
>  	void *p = kasan_reset_tag(object);
> +	unsigned int kasan_meta_size;
>  
>  	if (!slub_debug_orig_size(s))
>  		return;
>  
> -#ifdef CONFIG_KASAN_GENERIC
>  	/*
> -	 * KASAN could save its free meta data in object's data area at
> -	 * offset 0, if the size is larger than 'orig_size', it will
> -	 * overlap the data redzone in [orig_size+1, object_size], and
> -	 * the check should be skipped.
> +	 * KASAN can save its free meta data inside of the object at offset 0.
> +	 * If this meta data size is larger than 'orig_size', it will overlap
> +	 * the data redzone in [orig_size+1, object_size]. Thus, we adjust
> +	 * 'orig_size' to be as at least as big as KASAN's meta data.
>  	 */
> -	if (kasan_metadata_size(s, true) > orig_size)
> -		orig_size = s->object_size;
> -#endif
> +	kasan_meta_size = kasan_metadata_size(s, true);
> +	if (kasan_meta_size > orig_size)
> +		orig_size = kasan_meta_size;
>  
>  	p += get_info_end(s);
>  	p += sizeof(struct track) * 2;
> @@ -1192,7 +1192,7 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  {
>  	u8 *p = object;
>  	u8 *endobject = object + s->object_size;
> -	unsigned int orig_size;
> +	unsigned int orig_size, kasan_meta_size;
>  
>  	if (s->flags & SLAB_RED_ZONE) {
>  		if (!check_bytes_and_report(s, slab, object, "Left Redzone",
> @@ -1222,12 +1222,23 @@ static int check_object(struct kmem_cache *s, struct slab *slab,
>  	}
>  
>  	if (s->flags & SLAB_POISON) {
> -		if (val != SLUB_RED_ACTIVE && (s->flags & __OBJECT_POISON) &&
> -			(!check_bytes_and_report(s, slab, p, "Poison", p,
> -					POISON_FREE, s->object_size - 1) ||
> -			 !check_bytes_and_report(s, slab, p, "End Poison",
> -				p + s->object_size - 1, POISON_END, 1)))
> -			return 0;
> +		if (val != SLUB_RED_ACTIVE && (s->flags & __OBJECT_POISON)) {
> +			/*
> +			 * KASAN can save its free meta data inside of the
> +			 * object at offset 0. Thus, skip checking the part of
> +			 * the redzone that overlaps with the meta data.
> +			 */
> +			kasan_meta_size = kasan_metadata_size(s, true);
> +			if (kasan_meta_size < s->object_size - 1 &&
> +			    !check_bytes_and_report(s, slab, p, "Poison",
> +					p + kasan_meta_size, POISON_FREE,
> +					s->object_size - kasan_meta_size - 1))
> +				return 0;
> +			if (kasan_meta_size < s->object_size &&
> +			    !check_bytes_and_report(s, slab, p, "End Poison",
> +					p + s->object_size - 1, POISON_END, 1))
> +				return 0;
> +		}
>  		/*
>  		 * check_pad_bytes cleans up on its own.
>  		 */

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1f2f5a9f-61aa-094d-f9ed-be97e3671fb1%40suse.cz.
