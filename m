Return-Path: <kasan-dev+bncBDXYDPH3S4OBBAXO3GXAMGQEZBETSJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 541BF85EBBE
	for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 23:19:48 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-512cc3ea8b8sf1681904e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 21 Feb 2024 14:19:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708553987; cv=pass;
        d=google.com; s=arc-20160816;
        b=Qg2xW73OFO/Z/bjNGB70ZMqqXnhn1NZJ2Zsgrn49vlYpQrrW9BPyUMs1NBUvKhKBZF
         amkHaSwdVb7FreCPhXT5TOKSva8jmW4MrTYoSKFnA/RtwL2zncms4CtYT+MJEfrVGVIw
         lmeBFuL+9SkkMZONfSq6Bn3PNM8TeKVJHsCKZITAahVPO+uwubl/wAiGOGVbyfvnngwH
         ziTTvn/vK/UMsuJ80A7GRlvqQ6Yx4ixt6/s3B/pSb4j6mDkBTaoiHqAKOxUTj+sgc5Oi
         mSw9ePEY1D8NnK0EMyFaTYhGaaiLVo5jiRXxMfDbzDoFExI73D7V229ajVizaf3mDKqA
         NbbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=7E9u0cvMETcV3BauS7uQEt75QhYKiBRdlyBkHkIGCnI=;
        fh=jZoEeDgXifHXAAZilg9YQhHf6zHiG/TWDk1OXt5Vn9M=;
        b=rCAx26oMAaoWWqKe3K0jSPO7uRNqNNNo4KmfNEXRLuzEu2iVjgOVO06o0Y6g5sJjpO
         yL1pN37LSzp+qDZr7+6ZaGwAvN51jMYtKItP20TMxjCjNnVdqgk8/KBsNh5IW9TRJHSq
         +xzK1RwOzPh6Z8tGPRYQ/A0aNt7/R3oho1B8I+db6jGeQTV5+IAYyJZ4DwX0G+bDuj5S
         mjC2JNo7pvF5V1VEgs4AQWQYw+SW5TA2m8X5xN5Id6sMxiIzUbFropmqxxsqcKxtKThm
         4EXcLk7eeYTw4Rq5oPzH6ZNJ9LTzCNaRdvcTe2Pyj5i/md+lvbxxqTvHTmhPrAUXRq37
         hkzg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HNAIyQ+a;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=ylT2uZtA;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HNAIyQ+a;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708553987; x=1709158787; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=7E9u0cvMETcV3BauS7uQEt75QhYKiBRdlyBkHkIGCnI=;
        b=HOnE8R35vPheHm8GvDgK7XesQsOG8MHuY+ZjkX7SdUmRBAfN4mT8lz8FflBYzLk6Hr
         S46KS3f/3+H9BxS0Ii0kH5prCdY7/WG35mU5FnAPYEnaACD1fxDiG0rkIvH+EgppHapj
         xmQq3H06bKL1vBQNMd+pKvkMG9cx/2L4AY9LgQiZOq3nBA22RnZpQE16G3eaaGD+rDWe
         Otu++ViVsAiN8h3qMv9FSs1ZKrJQkD6VzjUxz5HEBnuHUasa+STPL+1B4vg30kUnYG6A
         3RB3f0hvU+VTT30puDH35Xk/yhQlQhx9Zgmh40ECGqV/eTm2P/YWGWU5vkmkpZBZuQwU
         apGg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708553987; x=1709158787;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=7E9u0cvMETcV3BauS7uQEt75QhYKiBRdlyBkHkIGCnI=;
        b=xKm1GDUSqNirwCBg/fWhVH+GmDS+SRLdgC7NwndiOmTXBOHiRtIGD3VHC2WUiCw9oL
         plNCFVW1dMliqANRuRTVM0Sp+F5v0tg9cCY9WwNWcTWJDmvCEMJBo76nItV3N7JK881K
         uanWI0j7azGyvWVZ+pRtD5CKhtXxP/Xa8N79AR8dRpV++rt03uJgBr6l41dkomaM+YRj
         9g2MR1ZX1JhNrx5r7rNRhVlgFemy4PrZsemjmQ8xb4nbjNC0omFSZRz3OUqQekW3jqN8
         CF09xiN211CScH41Irt4692mvmTThr8zFMsrR+3Sbldl57KWEnpFx/pmeO+cVUnnydC7
         Fv7w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0bkqruk00t9eQlRe/CUgyKn+4q5f9goENScuPXPlrakSDjXSoOm91UfhAqyHqTfqevoCpUfIxjc8GxJ3oVeE/mfX/Z1hpag==
X-Gm-Message-State: AOJu0YxQDhDrwLG0poC17Imr78uePmDXZCQ5T5nrBjvHD4KBPFJO5Xnp
	m9nJnPpaUMp3kHndrD/VgyxyhiIIx0xUNV9XwCXR7h+JjBaHZmQJ
X-Google-Smtp-Source: AGHT+IGW1uOuwmk0akSJhQzvUCWcB3DXpZsmZfZqQoRfJpNnYD2dzWMhazF8wVVG0FoBGEwtgVs42w==
X-Received: by 2002:a05:6512:ac3:b0:512:8a87:cbef with SMTP id n3-20020a0565120ac300b005128a87cbefmr14719389lfu.41.1708553987084;
        Wed, 21 Feb 2024 14:19:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:ba7:b0:512:be92:a2df with SMTP id
 b39-20020a0565120ba700b00512be92a2dfls263889lfv.0.-pod-prod-07-eu; Wed, 21
 Feb 2024 14:19:45 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWQov/s2aiA2J5Ib8d+hTbVtd/N5K4J5PfNRsFCRITORSszdR/xNgUjfp7kh9+6VYmDnSccHY8dyGqdz/J+zGqCtW4hJDuSsg0czw==
X-Received: by 2002:ac2:4e0b:0:b0:512:b3f9:6ef3 with SMTP id e11-20020ac24e0b000000b00512b3f96ef3mr7794234lfr.47.1708553984941;
        Wed, 21 Feb 2024 14:19:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708553984; cv=none;
        d=google.com; s=arc-20160816;
        b=c9YUb3xrr/oDtnp22M+8t45SR61ckXlUV2f+w7ye35+NlrlHK9RpTdiHK/sPXe30yw
         kdKrt0KcYVEzn4e5Az+a8CPjdKowllxsvcGON+D2YPiOSCQd2Mt2tGqUM68z9Tb4BLB3
         m9JXX2yDoOpMFcaJlMqSr9tj8ymdlFAHj+nkdd4QvioiQj7iftZa7w85PDu6Ft77xWKS
         IFIXrh8WF81kvh5QPjksJOhdQIbAqKsUgQ5YPaVPD+ZIBwOMrHOjK748NpLv6D9mA9RM
         nnzTARLzJBXFHVlwofe3it5ulNGdZehucSUGERJwpUiWjBKkcyfEzAZFMr8h4yzzfNyA
         Eq7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=vxL/y8ewJsj/ttUnxwt5FKrTF34RqTIXa5SPkRu66jo=;
        fh=1ndklQ0gcP9gqEQhUeyE3KBVvYsXJ7wbFtD3c5sq7Dk=;
        b=TRDE+J79v8h/nA6fuodNQNWFA9wHsopQSQqYJifFqhflfTyoEJxMsikxr2QSE06L0a
         Im8vY1gW0iSSkJh78n3ZNH5vUGEnkL1n7sTnJDEMlVKEG8u21EXgUmXXeUP2+bivhjsS
         EyY6rnEv+r4Ik2iXNSQUSXztG4Dmz8dQN2ibDT0ph/EUnRJ/se5xFuD9+WQ37kIMPQRK
         JT0ovMR/MZrkSPYuO8XjWHDL9H8thKJjvGw8OETEOi7fypFRC/811AJsjJmCoG+/w8RU
         ak3fQW3UDFd4vsc7ctSy0GJAAEHjiWwXncMSO7WYNyUrlb6GFJPbE2jJ6V7Vdx6VbgdS
         Y6aQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HNAIyQ+a;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=ylT2uZtA;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HNAIyQ+a;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [2a07:de40:b251:101:10:150:64:1])
        by gmr-mx.google.com with ESMTPS id dw24-20020a0565122c9800b00512d6c1e526si80562lfb.3.2024.02.21.14.19.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 21 Feb 2024 14:19:44 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:1 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:1;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id B314F22264;
	Wed, 21 Feb 2024 22:19:43 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 8AE6413A69;
	Wed, 21 Feb 2024 22:19:43 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id vOGYIf921mUObgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Wed, 21 Feb 2024 22:19:43 +0000
Message-ID: <e8e9d68d-8bbd-41ea-a627-eed17ba37ebe@suse.cz>
Date: Wed, 21 Feb 2024 23:19:43 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 2/3] mm, slab: use an enum to define SLAB_ cache creation
 flags
Content-Language: en-US
To: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Zheng Yejian <zhengyejian1@huawei.com>,
 Xiongwei Song <xiongwei.song@windriver.com>,
 Chengming Zhou <chengming.zhou@linux.dev>, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com
References: <20240220-slab-cleanup-flags-v1-0-e657e373944a@suse.cz>
 <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20240220-slab-cleanup-flags-v1-2-e657e373944a@suse.cz>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Rspamd-Server: rspamd2.dmz-prg2.suse.org
X-Spamd-Result: default: False [-1.68 / 50.00];
	 RCVD_VIA_SMTP_AUTH(0.00)[];
	 XM_UA_NO_VERSION(0.01)[];
	 SPAMHAUS_XBL(0.00)[2a07:de40:b281:104:10:150:64:97:from];
	 TO_DN_SOME(0.00)[];
	 R_RATELIMIT(0.00)[to_ip_from(RLycmwa99sdzp837p77658kns5)];
	 RCVD_COUNT_THREE(0.00)[3];
	 DKIM_TRACE(0.00)[suse.cz:+];
	 MX_GOOD(-0.01)[];
	 NEURAL_HAM_SHORT(-0.20)[-1.000];
	 FREEMAIL_TO(0.00)[linux.com,kernel.org,google.com,lge.com,linux-foundation.org,linux.dev,gmail.com,arm.com];
	 FROM_EQ_ENVFROM(0.00)[];
	 MIME_TRACE(0.00)[0:+];
	 MID_RHS_MATCH_FROM(0.00)[];
	 BAYES_HAM(-0.18)[70.31%];
	 ARC_NA(0.00)[];
	 R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCVD_DKIM_ARC_DNSWL_HI(-1.00)[];
	 FROM_HAS_DN(0.00)[];
	 FREEMAIL_ENVRCPT(0.00)[gmail.com];
	 TO_MATCH_ENVRCPT_ALL(0.00)[];
	 TAGGED_RCPT(0.00)[];
	 MIME_GOOD(-0.10)[text/plain];
	 NEURAL_HAM_LONG(-1.00)[-1.000];
	 DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	 RCPT_COUNT_TWELVE(0.00)[18];
	 FUZZY_BLOCKED(0.00)[rspamd.com];
	 RCVD_IN_DNSWL_HI(-0.50)[2a07:de40:b281:104:10:150:64:97:from];
	 RCVD_TLS_ALL(0.00)[];
	 SUSPICIOUS_RECIPS(1.50)[]
X-Spam-Score: -1.68
X-Rspamd-Queue-Id: B314F22264
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=HNAIyQ+a;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519 header.b=ylT2uZtA;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=HNAIyQ+a;
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

On 2/20/24 17:58, Vlastimil Babka wrote:
> @@ -156,9 +195,9 @@
>  /* The following flags affect the page allocator grouping pages by mobility */
>  /* Objects are reclaimable */
>  #ifndef CONFIG_SLUB_TINY
> -#define SLAB_RECLAIM_ACCOUNT ((slab_flags_t __force)0x00020000U)
> +#define SLAB_RECLAIM_ACCOUNT __SF_BIT(_SLAB_RECLAIM_ACCOUNT)
>  #else
> -#define SLAB_RECLAIM_ACCOUNT ((slab_flags_t __force)0)
> +#define SLAB_RECLAIM_ACCOUNT 0

lkp/sparse tells me this was the wrong way to unify all noop-due-to-config
flags [1,2]

so in v2 I'll unify all those to
((slab_flags_t __force)0U)

also the deprecated SLAB_MEM_SPREAD in patch 1

[1] https://lore.kernel.org/all/202402212310.KPtSDrRy-lkp@intel.com/
[2] https://lore.kernel.org/all/202402211803.Lmf1ANXx-lkp@intel.com/


>  #endif
>  #define SLAB_TEMPORARY		SLAB_RECLAIM_ACCOUNT	/* Objects are short-lived */


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e8e9d68d-8bbd-41ea-a627-eed17ba37ebe%40suse.cz.
