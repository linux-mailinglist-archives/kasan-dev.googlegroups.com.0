Return-Path: <kasan-dev+bncBDXYDPH3S4OBBSMXZW6AMGQEG6KMY5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 69B80A1B177
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 09:14:03 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5d09962822bsf1874373a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Jan 2025 00:14:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737706443; cv=pass;
        d=google.com; s=arc-20240605;
        b=D51k/RbV+89GLXSu9r7Z0B5/dnOaOYB6utdZ1fPW2K3d+cUY/oe8a1Os8ix8g2yQ3L
         0upz6N/WWdC7mZE9ohSI5SokmODiDeek80t5u/EJM6q8eq+WptVh/dV54MsR+XgqnWYB
         Vz6CtO02qfLJl9yNPF5oSNuvwy46NW/PktlkmkwIXk8/jgqc7z6heaCSF5It8rZNOzzF
         RMS9oVi6aczci5I8rDPTyRE9heA8h5fqOKzidfrtzc+iFJm4Zxpsn5zjrJgF9gN+kLLy
         dDaZU/bygkOJx1ZScDEVQm2nRP4d9IoaLEqB+tDEsNwra8MwJG3NGxpbfdOYYQFcpw6J
         5CwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=1uMly63X3Vlfp8DdOfu7NyJr2Oj69/V1RRhwCnhEjEw=;
        fh=DBACvdSfU0q/eWaGXT00g8S9Szigto4KUzAJBgSEhlw=;
        b=AGtsOnK0r87nVdzHJrTau1wchopauEowWK412zH1NNjWkBuaa7BR7bq9s4QXzMWUa9
         Zw+cLDMkwSdaYVyWkNPC5oTjCuMFo3gSkQQpKAK0s7FlKkArlgG00nj8smZ8Ku28Fmgn
         At9vGXdRWv/ST3UUrTEU8ERYTNP57dOJMjd9kQQczKT5Xsq8nTsb+z1R4sZuXWPBGj28
         fXk7unsREV9R+ffrhUgIZA19Qf3z+XpNUNmNrDPl39ZAXHHbi9HBK2ILYhl97Sub3td3
         s5+CKvs/boZ4UqM9bs91TLQHBF4ENdAhXI0nagfWJyzhhSb0D6zzu8VR4lEVlUL83XKq
         yZJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Z4ra255j;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pw+Mkixc;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737706443; x=1738311243; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=1uMly63X3Vlfp8DdOfu7NyJr2Oj69/V1RRhwCnhEjEw=;
        b=Wx4tusSA9eCap1rFDJABrBtqk2l8otGBwcbxhtYH6jIg8IJyW/F7Pk95Hi9blKCL/e
         Gl6EEsa0kQGo0eaqR/3xEoTKaxXkGxG45WHGWOjw1V5KG2uqzb9My8KEHGQo6XDnAzxz
         S6iXSkcHOyDQfIY5zcvEvV75ONz/zLYMiTopFK6NpQaYbLcBBThhEBbyZadBcLqa+dOE
         IFSZZvTMqoci9iMK0Y8gtOy0lPhB24Jnz+ZIdL3kF3xMZ4FzTOEtbimcsoTCU+tk3bfM
         3Y7MfPrvybAN/MfxVQaP94Equlo5BpGhhCgFIt4DQ2EILQGYeSK5nWOri2vamqcnGz/G
         BM6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737706443; x=1738311243;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=1uMly63X3Vlfp8DdOfu7NyJr2Oj69/V1RRhwCnhEjEw=;
        b=DQ9f4RpgZ0IU6BlpE1UpAWthz9rcMUJrrsYDi0azh1H6RO1G3aWKGAtrOkA/OMgsgU
         W2iS593qcTzP2eRzt5bopUsQC+OLDyx7qG31CKJgP2wZBdXFj35WF85lJ6IGU0Sa7Ivz
         k3g6m3yWvY2sz+GYVjHvZII1oHPWpisRxD8PqZD9n8QrgF8ZlHhlVfsa5bI2fGt0Z1tj
         yVwSqoPbFTKdGmre3amVYgJ1VuS2xDObCTJwZaKMi1wvt3H2PaN8ObvMFPNoXZQVBLpM
         HYrTbN1cvMTpi6ZNW+Hc/w3PuvkOfrBRRJDMHZmYJPBoYJQJpbvZ2X435rftK7RmqLzx
         4Fzg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXQBFpG7CLEO8LfMwO+2XvYP6QlBZGG9YVlzijhKRF2cY74kfAd17Ja01kFm8ppHJdZ9cZKJA==@lfdr.de
X-Gm-Message-State: AOJu0Yy2IYLKeUWR82RNhCU2iw/gDNxYHH7U/84+67QFEIOHP1U+rO+n
	hdobd959hLQNc7U8fgYYBirrvk8aZVeJW/f1z+D5z1K5/JyS0AKc
X-Google-Smtp-Source: AGHT+IHPjfCq5IimU4zLWQf3+1aLV7M7p4p/199jbEQ9a8clhgpZV+bmkxJ0ejBs3D5SpqJBMtBXgg==
X-Received: by 2002:a17:906:f1d2:b0:ab6:5143:6889 with SMTP id a640c23a62f3a-ab6514368b9mr939287066b.16.1737706441911;
        Fri, 24 Jan 2025 00:14:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:c35a:0:b0:5d3:cdb1:60a with SMTP id 4fb4d7f45d1cf-5dc07a290f7ls240470a12.2.-pod-prod-06-eu;
 Fri, 24 Jan 2025 00:14:00 -0800 (PST)
X-Received: by 2002:a05:6402:2744:b0:5d0:bcdd:ff90 with SMTP id 4fb4d7f45d1cf-5db7d2e7e43mr24754505a12.2.1737706439502;
        Fri, 24 Jan 2025 00:13:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737706439; cv=none;
        d=google.com; s=arc-20240605;
        b=hjVLe/2DkY2hhWDbe/kjhzrD7jwzYz1r0EITQKqBO8g2nUUo4PoxGEozSmGgY9Z3Rt
         mc8ShL6Yb7qF1MqtGRaxIrxssT33Hck0cOI5YSSd64QhjjLn8LihDAAfLX9PUY57/p72
         VR12AImAaNk8IZHvVjyuqmjiTRJo2vC6GIs+cAGxXzvX/HRYnqerObrFvserc9k0lem2
         F2Ttb68AKFo6ctPSYeIP5bpskqCO9etEzzjBF85yeguqL5Mz8EXz81pavK22mU/qL7+2
         nChksXdEx3Iaywf5n4FUyOngoCGqxs/wTNT4TSYOFhioJ4+QY0hi5bEBPjGkMdOZnG4W
         tfdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:dkim-signature:dkim-signature:dkim-signature
         :dkim-signature;
        bh=HHsPPvjg96ro625fCHdbmx9NdmMnNcX6YT3MfhhBF4k=;
        fh=c1r6sYHCP3CO9IpcdbcQoM63lc0TpasnNhH/5yyGVSg=;
        b=FXD7sLBmZqdqK2ixVdJV2pPoNgXVR6zwl/cKGR8TKMGVbT+AW27ipRb76rZ4BmfMQC
         iQg2Nsnh/Q/iSvZ12DZ753pMSivjeqBOnA23mCvCdxa9ShOTvciH0vdVUlQvIU6/6hAq
         Kykt6MqhburaNs4ujIeQwPDFrrrlF1gEDaMJqljaBI2+O8QVf8WNqO8kBB7GeLyse8FI
         /adZS9E+AseC8BdsBgcVMJ794yVyAPToKySmzoq3IOparg0HfWTOspdrPunP3IscF+uN
         su2NqibQUWgWSSJ9iKSgheZH9g9HCaznPQ32T0eQfSzvHRZHKAEeJo46ZokgafB6b05b
         PXMg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=Z4ra255j;
       dkim=neutral (no key) header.i=@suse.cz;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=pw+Mkixc;
       dkim=neutral (no key) header.i=@suse.cz;
       spf=pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out2.suse.de (smtp-out2.suse.de. [2a07:de40:b251:101:10:150:64:2])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dc186abbcdsi16184a12.5.2025.01.24.00.13.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 Jan 2025 00:13:59 -0800 (PST)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 2a07:de40:b251:101:10:150:64:2 as permitted sender) client-ip=2a07:de40:b251:101:10:150:64:2;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out2.suse.de (Postfix) with ESMTPS id E27C61F38C;
	Fri, 24 Jan 2025 08:13:58 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id BE783139CB;
	Fri, 24 Jan 2025 08:13:58 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id mihrLMZLk2elTQAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 24 Jan 2025 08:13:58 +0000
Message-ID: <b788d591-4c5f-4c1d-be07-651db699fb7a@suse.cz>
Date: Fri, 24 Jan 2025 09:13:58 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH] KFENCE: Clarify that sample allocations are not following
 NUMA or memory policies
To: cl@gentwo.org, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Jonathan Corbet <corbet@lwn.net>, Andrew Morton <akpm@linux-foundation.org>,
 Yang Shi <shy828301@gmail.com>, Huang Shijie <shijie@os.amperecomputing.com>
Cc: kasan-dev@googlegroups.com, workflows@vger.kernel.org,
 linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
 Christoph Lameter <cl@linux.com>
References: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org>
Content-Language: en-US
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20250123-kfence_doc_update-v1-1-9aa8e94b3d0b@gentwo.org>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Level: 
X-Spamd-Result: default: False [-4.30 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	ARC_NA(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_TO(0.00)[gentwo.org,google.com,lwn.net,linux-foundation.org,gmail.com,os.amperecomputing.com];
	RCPT_COUNT_TWELVE(0.00)[13];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[suse.cz:mid]
X-Spam-Score: -4.30
X-Spam-Flag: NO
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=Z4ra255j;       dkim=neutral
 (no key) header.i=@suse.cz;       dkim=pass header.i=@suse.cz
 header.s=susede2_rsa header.b=pw+Mkixc;       dkim=neutral (no key)
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

On 1/23/25 23:44, Christoph Lameter via B4 Relay wrote:
> From: Christoph Lameter <cl@linux.com>
> 
> KFENCE manages its own pools and redirects regular memory allocations
> to those pools in a sporadic way. The usual memory allocator features
> like NUMA, memory policies and pfmemalloc are not supported.

Can it also violate __GFP_THISNODE constraint? That could be a problem, I
recall a problem in the past where it could have been not honoured by the
page allocator, leading to corruption of slab lists.

> This means that one gets surprising object placement with KFENCE that
> may impact performance on some NUMA systems.
> 
> Update the description and make KFENCE depend on VM debugging
> having been enabled.
> 
> Signed-off-by: Christoph Lameter <cl@linux.com>
> ---
>  Documentation/dev-tools/kfence.rst |  4 +++-
>  lib/Kconfig.kfence                 | 10 ++++++----
>  2 files changed, 9 insertions(+), 5 deletions(-)
> 
> diff --git a/Documentation/dev-tools/kfence.rst b/Documentation/dev-tools/kfence.rst
> index 541899353865..27150780d6f5 100644
> --- a/Documentation/dev-tools/kfence.rst
> +++ b/Documentation/dev-tools/kfence.rst
> @@ -8,7 +8,9 @@ Kernel Electric-Fence (KFENCE) is a low-overhead sampling-based memory safety
>  error detector. KFENCE detects heap out-of-bounds access, use-after-free, and
>  invalid-free errors.
>  
> -KFENCE is designed to be enabled in production kernels, and has near zero
> +KFENCE is designed to be low overhead but does not implememnt the typical
> +memory allocation features for its samples like memory policies, NUMA and
> +management of emergency memory pools. It has near zero
>  performance overhead. Compared to KASAN, KFENCE trades performance for
>  precision. The main motivation behind KFENCE's design, is that with enough
>  total uptime KFENCE will detect bugs in code paths not typically exercised by
> diff --git a/lib/Kconfig.kfence b/lib/Kconfig.kfence
> index 6fbbebec683a..48d2a6a1be08 100644
> --- a/lib/Kconfig.kfence
> +++ b/lib/Kconfig.kfence
> @@ -5,14 +5,14 @@ config HAVE_ARCH_KFENCE
>  
>  menuconfig KFENCE
>  	bool "KFENCE: low-overhead sampling-based memory safety error detector"
> -	depends on HAVE_ARCH_KFENCE
> +	depends on HAVE_ARCH_KFENCE && DEBUG_VM
>  	select STACKTRACE
>  	select IRQ_WORK
>  	help
>  	  KFENCE is a low-overhead sampling-based detector of heap out-of-bounds
>  	  access, use-after-free, and invalid-free errors. KFENCE is designed
> -	  to have negligible cost to permit enabling it in production
> -	  environments.
> +	  to have negligible cost. KFENCE does not support NUMA features
> +	  and other memory allocator features for it sample allocations.
>  
>  	  See <file:Documentation/dev-tools/kfence.rst> for more details.
>  
> @@ -21,7 +21,9 @@ menuconfig KFENCE
>  	  detect, albeit at very different performance profiles. If you can
>  	  afford to use KASAN, continue using KASAN, for example in test
>  	  environments. If your kernel targets production use, and cannot
> -	  enable KASAN due to its cost, consider using KFENCE.
> +	  enable KASAN due to its cost and you are not using NUMA and have
> +	  no use of the memory reserve logic of the memory allocators,
> +	  consider using KFENCE.
>  
>  if KFENCE
>  
> 
> ---
> base-commit: d0d106a2bd21499901299160744e5fe9f4c83ddb
> change-id: 20250123-kfence_doc_update-93b4576c25bb
> 
> Best regards,

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/b788d591-4c5f-4c1d-be07-651db699fb7a%40suse.cz.
