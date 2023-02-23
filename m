Return-Path: <kasan-dev+bncBAABBRPQ32PQMGQEIDNR2ZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 360DA6A1001
	for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 20:02:31 +0100 (CET)
Received: by mail-wr1-x43d.google.com with SMTP id m7-20020a056000008700b002c7047ea429sf2241841wrx.21
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Feb 2023 11:02:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677178950; cv=pass;
        d=google.com; s=arc-20160816;
        b=rGskflS6TRFQamReTd+d2n6cF6YHHDJdER9Ghj87kbtU4Hy871sLfrdMEDXGgpQAbu
         LtYAXhgD58F7Zr9lTSXeDcE4fHIvO2xOD0Q0F582/VBG8HTe3Oovk/AgSAN+6yGVCtV+
         3hGU0T+3pQL1TZgXgkQPE5SNwVZRDjjJV1mKjEpasnJrUVmd0g6S1Jh8kqnzg1aJt8zB
         w/HSPEszByfoMfG5x38ahRmQ9WgyH8lmop2UBLbzBwwoSY7Kq/hWTkV94hFXaNIdhcLM
         Q9mijxY7zaWj2x453yU7volTOUgrZmWgFqdxB4/L4tD9IspKc5R1NTUprGMO0TENKLUd
         PXog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :in-reply-to:date:references:subject:cc:to:from:sender
         :dkim-signature;
        bh=ZnLu5EtMGqsf/a3vh3gEf138OuMNG3Sb7Tp6UJR9HbA=;
        b=RLnSclZ/bsP5I2VWYDHOYJyoRCEziWvdHgOiq+JRvPNudcGbUzS0DWGAvmD3ZYE0yf
         MOPVnyuC3kgzz9+2LDUv1W2vaNggjQ4KvfkoB1G3mNiZ2QF1mOZjBzSqND7TiYGA8cPd
         WK97n4HcmeiUtZCxLbg+wdL7IBPRNIIoAkHy49rjMavAK+3LhQLGGGtAEMllwZftQx48
         dZwAVHxgItLDoE+n1eTMcLb366cmReqZAEde9ResHMRkAA+HqhVjRE9MzdsoeJo3cZ4e
         FTBG13oCXInS2TNMWb772uiAs7J9Xw/5KVl7yfB9CDKsfSGGpisWB1hjgW3o2ZpWyNTY
         SobQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=WaukZiuo;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=krisman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:in-reply-to
         :date:references:subject:cc:to:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZnLu5EtMGqsf/a3vh3gEf138OuMNG3Sb7Tp6UJR9HbA=;
        b=mckhofvHFc6c37b9IKS+QqMVFGDdhp2floAqb/axjXw3wS4Fr56aUjpin3T+7s9BS/
         3q5WPHetRObEcpvbOMJhx6dhrvNtOaeFG6j0jJwo7e6HfRM/Mc5UMQpVRKIFgwwBQTQ9
         v/NXSZsVWwLZlvaePOe1g0U0ITJhKEqgDQ8o2LU0IuAqadPrXi68Kg/sfoqNtLTFtewT
         tn04wXq5OUNGYZbV7hEWEOwvQpOg2yaoTa6KHvbek/iuHLaf4CHXgjZn83oV3PnH9Uqo
         MIboz5SOnPBkt354KbfPvq/xSyDni0EETTse5FqlQvcpkT0p/jXnTwyuofHhLJsGC/Ah
         qV4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:in-reply-to:date:references:subject:cc:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ZnLu5EtMGqsf/a3vh3gEf138OuMNG3Sb7Tp6UJR9HbA=;
        b=X4WOTJS8Q6jILG6BOfNbfaomhiso1loOr3UR//GoehMPxCrdU7ZeN9wK0BcmgL6def
         apoVu43+2RkfM+0zmT2G72A4tx7i6PkjYkmXKOhBGyIL0iJqhK7g8iVxR1uhUI9mBLdo
         0ZG9XOytfBYxe/JExtVQxM3jgxD2p7N3R0XPtYOd582Wb+J0t+4aBVXQnxsUJiXno5G3
         DmeLEz8KxzuByDMa4ZQnKWQ1uKqxXNgaxEzgoBMiEyQ655VZ+rNsPbcLO2nIF9NT/KzL
         nXZFgVoPBJQ7fnqyO9p4lGBnja9B07339Su9W+ZYt8YvrQ1Rqo/WDiYAC/DdLDznnUgN
         lxmg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUaQJonuup21dPBLY26Enc0yK0tYjbeVyQKim/KO9mtBp7Eu3nK
	DMhHpwBDvYjCIofs4KR6MSU=
X-Google-Smtp-Source: AK7set+qDNvViQJPX74kjS4NXGsHbUgHnzyLN3DdFdXzQyhQj1ZqHbqIryl/RcRp5gTioSjIs5rWSw==
X-Received: by 2002:a5d:6b8a:0:b0:2c5:4c8e:d661 with SMTP id n10-20020a5d6b8a000000b002c54c8ed661mr802113wrx.10.1677178950162;
        Thu, 23 Feb 2023 11:02:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:a18:b0:2c5:55ca:3a3b with SMTP id
 co24-20020a0560000a1800b002c555ca3a3bls881484wrb.1.-pod-prod-gmail; Thu, 23
 Feb 2023 11:02:28 -0800 (PST)
X-Received: by 2002:a5d:5848:0:b0:2c5:4a22:937c with SMTP id i8-20020a5d5848000000b002c54a22937cmr13423617wrf.27.1677178948794;
        Thu, 23 Feb 2023 11:02:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677178948; cv=none;
        d=google.com; s=arc-20160816;
        b=L+9Mm7sMMEHRAG2RgEqL1V5ZP7TuiYO6yxrcJztJrrz9eKPljLNuNZuU2ECWLTabVI
         nA1/HGmqfEXGc9GlVG8nE+5pmqsBGG/XbvcszMWbn4zYTEO2dG9n37N1omANGruLxMn0
         V7MIvAy5AhJ+exdBcFU975928KTHUbUDtI4vS3rdKeDnkQiZZ/1rNcapDmzA2GJHEq20
         Ttw7bj5oyvPDbA6DChVkx2W6dtdG9ey5JeAb6LUz/iA1CeHOYuHJZvypDuhNJvytawCu
         RAnvMcBZ/dXCBaYAAJqHeqccwcqde7Qo4x+H+eEOSke9eGzyWQYNFCznny2fKh9bS0pM
         pm/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:message-id:in-reply-to:date:references
         :subject:cc:to:from:dkim-signature:dkim-signature;
        bh=P02lDBmsHtB0LY1+D/Fd48m1wsVE8BrW8yUGVQS7FRk=;
        b=fq4/VUv4JszGZqscYTRtTStsOo9zFpYD8z5K4vh09laJhBOZNUdErf3TBNQ6iFnbNa
         LIBEr8doz5rQS/wktFIdPremjNU6YqifTO1cumUEholsaaR2ffQqARIYPMBt+kyjv58O
         Ic8JnN7jED+67sAhHl0Pf91qb+y09JFEXEV6QYklu4Fh0cLGKH3ClB7sLtIkPMVO0Edp
         wpA6ouwg9DCTGZZFnHH9kNNFrGB7+XRpg3GBpqbC0tQBBTn5XaJVZGt7eD6hHFwGcrpm
         gF1sZ4wV86wsAoHitsKAF0YX1JnSMwHKmNVlMzchw4qgCH6WLvlM/kLJNVeaz+J24gOV
         8cCQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.de header.s=susede2_rsa header.b=WaukZiuo;
       dkim=neutral (no key) header.i=@suse.de header.s=susede2_ed25519;
       spf=pass (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender) smtp.mailfrom=krisman@suse.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=suse.de
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2001:67c:2178:6::1c])
        by gmr-mx.google.com with ESMTPS id h5-20020adfa4c5000000b002c685ef5fe8si414688wrb.5.2023.02.23.11.02.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 23 Feb 2023 11:02:28 -0800 (PST)
Received-SPF: pass (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as permitted sender) client-ip=2001:67c:2178:6::1c;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 77F5D339CF;
	Thu, 23 Feb 2023 19:02:28 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 057BA13928;
	Thu, 23 Feb 2023 19:02:27 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id niFGMEO492M8NAAAMHmgww
	(envelope-from <krisman@suse.de>); Thu, 23 Feb 2023 19:02:27 +0000
From: Gabriel Krisman Bertazi <krisman@suse.de>
To: Breno Leitao <leitao@debian.org>
Cc: axboe@kernel.dk,  asml.silence@gmail.com,  io-uring@vger.kernel.org,
  linux-kernel@vger.kernel.org,  gustavold@meta.com,  leit@meta.com,
  kasan-dev@googlegroups.com
Subject: Re: [PATCH v3 1/2] io_uring: Move from hlist to io_wq_work_node
References: <20230223164353.2839177-1-leitao@debian.org>
	<20230223164353.2839177-2-leitao@debian.org>
Date: Thu, 23 Feb 2023 16:02:25 -0300
In-Reply-To: <20230223164353.2839177-2-leitao@debian.org> (Breno Leitao's
	message of "Thu, 23 Feb 2023 08:43:52 -0800")
Message-ID: <87wn48ryri.fsf@suse.de>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/27.2 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: krisman@suse.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.de header.s=susede2_rsa header.b=WaukZiuo;       dkim=neutral
 (no key) header.i=@suse.de header.s=susede2_ed25519;       spf=pass
 (google.com: domain of krisman@suse.de designates 2001:67c:2178:6::1c as
 permitted sender) smtp.mailfrom=krisman@suse.de;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=suse.de
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

Breno Leitao <leitao@debian.org> writes:

> Having cache entries linked using the hlist format brings no benefit, and
> also requires an unnecessary extra pointer address per cache entry.
>
> Use the internal io_wq_work_node single-linked list for the internal
> alloc caches (async_msghdr and async_poll)
>
> This is required to be able to use KASAN on cache entries, since we do
> not need to touch unused (and poisoned) cache entries when adding more
> entries to the list.
>

Looking at this patch, I wonder if it could go in the opposite direction
instead, and drop io_wq_work_node entirely in favor of list_head. :)

Do we gain anything other than avoiding the backpointer with a custom
linked implementation, instead of using the interface available in
list.h, that developers know how to use and has other features like
poisoning and extra debug checks?


>  static inline struct io_cache_entry *io_alloc_cache_get(struct io_alloc_cache *cache)
>  {
> -	if (!hlist_empty(&cache->list)) {
> -		struct hlist_node *node = cache->list.first;
> +	if (cache->list.next) {
> +		struct io_cache_entry *entry;
>  
> -		hlist_del(node);
> -		return container_of(node, struct io_cache_entry, node);
> +		entry = container_of(cache->list.next, struct io_cache_entry, node);
> +		cache->list.next = cache->list.next->next;
> +		return entry;
>  	}

From a quick look, I think you could use wq_stack_extract() here

-- 
Gabriel Krisman Bertazi

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87wn48ryri.fsf%40suse.de.
