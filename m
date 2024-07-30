Return-Path: <kasan-dev+bncBDXYDPH3S4OBBK5PUW2QMGQEJI64H3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F29F94220E
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 23:14:21 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id 2adb3069b0e04-52fc54c3f66sf2782e87.0
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2024 14:14:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722374061; cv=pass;
        d=google.com; s=arc-20160816;
        b=lrbx5PPpBZriNdV+tvoZbQpdW6wemNgvGOV9KBpALtv3VPbRGQE9hIlFYbn6EWo0mD
         /tOmRBGdJ6bJHmfshI6J+YNUrP3eSc+tjjuoVykgYTTJ3G6PQJ6qnrQNKQJnLXfI1mPi
         m79ynSsnSBJvmXQZGNd6y+bclH6qDrKGHTo615YmsYWL6uGR1LbVvshKnjgjnEaYEo2j
         qudT4wFoElLAbNWVRvvatckHoJMz7SDmNqw+rjoeTFI7+27j8yiDQFgntP+cvv8sdoHJ
         pKfzGo3OMUqHsWsPc1Dde+BrUk1tnVc8NWnZpKgVhkbMReNkgTNuhmsxAl9d/OLNZmUj
         Z89w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=8LmjZnb4PjZAyU5pJeQs8SoA4ACR4fzGVTNZZMTK2JU=;
        fh=zEgwdC/Qu0c0pfMbdeX/gCrTJxYXSHclo4w2+BLyjDI=;
        b=STRxyIbjlW4GZYEemtm9DzTIV+IwP7vh9xC11vp90x/vw4QPHo167CcDfPdFY+El+F
         mdgHgLPkY5Q84TmKFv6kr24IJodXzuIPgnCu97ENzw3hJVXYrX40qU9rQlkjuT5B2PM8
         RyTnMru8BI9vIn0WXAvhZVzoCWCvc+f5mHI9KQxWLWuhRK69QwfxiFyhxN1OvPSIAw/9
         kZelI1cO8GFFMZcp4/FcZKQraZHoiWG5Bv6p0A9vYEI7jyuWRpNC30L8MroGYcd64lpA
         ai1Bc0hFCZySbfGRg5UHsEhrkd/PljwO4LfZxlFZ/VjNtx1k1rw7ZPFg0u/umqD0QdQl
         1vDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Sf/BCW7t";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Sf/BCW7t";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722374061; x=1722978861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8LmjZnb4PjZAyU5pJeQs8SoA4ACR4fzGVTNZZMTK2JU=;
        b=iasaE2KEnmnqe5pbb+z3SMAzVyRYPdC09BhlvT9N1qiEbPO9AIzYOdrlnUPP3t62YC
         UyoIqh2hIbMo3HzrLULMCtznJLEYz3SQ5lriSfSGlqnwIpq39NNKHglNgki8IVcntm9N
         YMdxsTiSHHmwzrZmiFUZ4XAJjpJi2phXkM6Mo+nYh1pmmFVxnyy8VulQgtMHyPst17yi
         kScVqi3U/96W5rWmI4b7Pf9PAEY0aix2Dx8CJ2v+RAZuX4GrLGeJBWEIDxLghc//4JlR
         3qVDdWMQaIZFPCPqrJ+yTgmepnQM0SkTu/+x4nyTdLM0lvUm2yxBUOZmq1JcNKH3JU1f
         QfMw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722374061; x=1722978861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8LmjZnb4PjZAyU5pJeQs8SoA4ACR4fzGVTNZZMTK2JU=;
        b=gLxlb/ZfX7XqyXo0mcGJ+odSlB6/w22OYFuyI7veUrpwJ5TkjaeubalX9WkZQHQhnO
         CiImWSn/zaM4KIrjpT9UYvZyJIBXj7aWpfuRXGO2vYgzn8PKg4XLo3X2nllrvjeeWpFz
         nRiG2y9z3yiR+dOmIJ8hb8AryviSWoP7uZRhErLu273Y6tEpWWVl1ijJwlie7auZy5Fb
         Znk5n5mVSw7II/wbRGEq/Wl+KEDaC9oVnMtYzN4fc16l5OH9Tig/4EutKfFpCtoX74Mc
         XL6NwfkamViwEvCVTUveZ7JTYFqRFP3yxikQ4viXkalmQZ4dsruHIxzzWG8sulBcVgun
         yeHQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXwuymPMdpoo9ZMKw92dkoKlq1s2RXFYIHIho0hTnDV9OIPHLp+PtVcAwFcTbjScP4YukPdqOjR3J//RDZG1OO85H1Sek3H3w==
X-Gm-Message-State: AOJu0YxFKpr4BJw+tnR06e4T5HiNkG90MhMLzS+cQN3i5hqw4DPwnSoz
	6ni4+1tNIZCKVLFInqiQUo2qRDbG25Z0GAQkzpJPebVF20UlltMI
X-Google-Smtp-Source: AGHT+IESZ4jrAG2gCIR50PzY6m0ylXMOkZkhNUj/1T+X3dwL5cu8rc/YouD7KGrGPJOx9OaUnkIdQw==
X-Received: by 2002:a05:6512:ac3:b0:52e:8a42:f152 with SMTP id 2adb3069b0e04-530b03873efmr6182e87.5.1722374059873;
        Tue, 30 Jul 2024 14:14:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:e88:b0:52e:9b66:4f8 with SMTP id
 2adb3069b0e04-52fd420a24bls2832898e87.2.-pod-prod-05-eu; Tue, 30 Jul 2024
 14:14:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXK5Z+fyVtvsuU/9Q5gAYRvXdZlpiuIodldRtsVA82hVTN8UATkC+wFjz8u/ulQ76ObpQaWH7xlWVMON17779zbQ1NBOMeSkVTdkw==
X-Received: by 2002:ac2:5968:0:b0:52c:9877:71b7 with SMTP id 2adb3069b0e04-5309b2d8bffmr10297711e87.59.1722374057598;
        Tue, 30 Jul 2024 14:14:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722374057; cv=none;
        d=google.com; s=arc-20160816;
        b=dY0dcuPBPkVL3ZUZz6ev/NzdZ31r50ie6L5Ol8pMhDVsUyIt4C9nI0FOnPJsVwoyPA
         2ZFdNHUcYHb9CAIESUCO1wf3Zl3LXShcHgZOuDHwWVyx3dciH4O1brocal6DRzOYXwSS
         DFHzbZOQ1l7cqL6KqCDuYUolRMAAi1K6PkWHYPNW0GMP7V84ahFgphFGsJE5ixVJpcPR
         NaDfs++KyNA9Kemv62bFx3tzsGw4HufeTTr/hJ4BviYBocT2gIg+4Jyi5dh8Z2w1zsOA
         f1XJK+2Ph1xdOMYAaRWpIKM7keh0GIM+Z2Fm08hFcHvyIszpIg3E8/2q1SFQig+fCbit
         rvhg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=XAGax8LVb3jlQZ8uD9QYjv/FlOREfiX45HtE90u8OzI=;
        fh=6RadFs7f0xrlh5isHYBWj7sUCXiElbs6+xouOOPrBxc=;
        b=ghOBXAYZlvjlrwmj0eMDiey8YKCcOCWNCOwvKnAP8Zws+qewKvISwQAzFFIz5iern9
         mMm3qVuxOzI89j99FZ+O4yUnU6joyDrIiRgxqfC9r2K2h2EfJpv6VH+9sWHkhZT3bfvG
         yF0Rujhbqzj1SaWbGY+P15IbfiCe+ggF3rlTT3Zm5hd6SdTR4PsmylGP0ecSoOqleFk1
         RCayoE6V/M9GjGB+ILqDBxYyponEnZQQQfxh8XQ3Cb2YerWE4m2U9SjyHgCytcJBKdsg
         TjDs9ZNMe3jxDnBaiFW5DUA9k3witJ063SomV8suX4/e1U0gCaGFIEVgU/SGEZMLlxB4
         64UA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Sf/BCW7t";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Sf/BCW7t";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-52fd5b28a51si230976e87.0.2024.07.30.14.14.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 30 Jul 2024 14:14:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (imap1.dmz-prg2.suse.org [IPv6:2a07:de40:b281:104:10:150:64:97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 7EC07219C6;
	Tue, 30 Jul 2024 21:14:16 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id 6489513983;
	Tue, 30 Jul 2024 21:14:16 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id oYbpF6hXqWYlWQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Tue, 30 Jul 2024 21:14:16 +0000
Message-ID: <66836dd6-b0c2-4f77-b2a3-c43296aa6c93@suse.cz>
Date: Tue, 30 Jul 2024 23:14:16 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH 1/2] mm: krealloc: consider spare memory for __GFP_ZERO
Content-Language: en-US
To: Danilo Krummrich <dakr@kernel.org>, akpm@linux-foundation.org,
 cl@linux.com, penberg@kernel.org, rientjes@google.com,
 iamjoonsoo.kim@lge.com, roman.gushchin@linux.dev, 42.hyeyoo@gmail.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20240730194214.31483-1-dakr@kernel.org>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20240730194214.31483-1-dakr@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Rspamd-Server: rspamd1.dmz-prg2.suse.org
X-Rspamd-Action: no action
X-Rspamd-Queue-Id: 7EC07219C6
X-Spam-Score: -2.80
X-Spam-Level: 
X-Spam-Flag: NO
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	R_DKIM_ALLOW(-0.20)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	MIME_GOOD(-0.10)[text/plain];
	XM_UA_NO_VERSION(0.01)[];
	MX_GOOD(-0.01)[];
	TAGGED_RCPT(0.00)[];
	FREEMAIL_TO(0.00)[kernel.org,linux-foundation.org,linux.com,google.com,lge.com,linux.dev,gmail.com];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_SEVEN(0.00)[11];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	TO_DN_SOME(0.00)[];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	DKIM_TRACE(0.00)[suse.cz:+]
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b="Sf/BCW7t";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b="Sf/BCW7t";
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates
 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 7/30/24 9:42 PM, Danilo Krummrich wrote:
> As long as krealloc() is called with __GFP_ZERO consistently, starting
> with the initial memory allocation, __GFP_ZERO should be fully honored.
> 
> However, if for an existing allocation krealloc() is called with a
> decreased size, it is not ensured that the spare portion the allocation
> is zeroed. Thus, if krealloc() is subsequently called with a larger size
> again, __GFP_ZERO can't be fully honored, since we don't know the
> previous size, but only the bucket size.
> 
> Example:
> 
> 	buf = kzalloc(64, GFP_KERNEL);
> 	memset(buf, 0xff, 64);
> 
> 	buf = krealloc(buf, 48, GFP_KERNEL | __GFP_ZERO);
> 
> 	/* After this call the last 16 bytes are still 0xff. */
> 	buf = krealloc(buf, 64, GFP_KERNEL | __GFP_ZERO);
> 
> Fix this, by explicitly setting spare memory to zero, when shrinking an
> allocation with __GFP_ZERO flag set or init_on_alloc enabled.
> 
> Signed-off-by: Danilo Krummrich <dakr@kernel.org>
> ---
>  mm/slab_common.c | 7 +++++++
>  1 file changed, 7 insertions(+)
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index 40b582a014b8..cff602cedf8e 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -1273,6 +1273,13 @@ __do_krealloc(const void *p, size_t new_size, gfp_t flags)
>  
>  	/* If the object still fits, repoison it precisely. */
>  	if (ks >= new_size) {
> +		/* Zero out spare memory. */
> +		if (want_init_on_alloc(flags)) {
> +			kasan_disable_current();
> +			memset((void *)p + new_size, 0, ks - new_size);
> +			kasan_enable_current();

If we do kasan_krealloc() first, shouldn't the memset then be legal
afterwards without the disable/enable dance?

> +		}
> +
>  		p = kasan_krealloc((void *)p, new_size, flags);
>  		return (void *)p;
>  	}
> 
> base-commit: 7c3dd6d99f2df6a9d7944ee8505b195ba51c9b68

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66836dd6-b0c2-4f77-b2a3-c43296aa6c93%40suse.cz.
