Return-Path: <kasan-dev+bncBDXYDPH3S4OBBOG7ZC4AMGQEPNBLMDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E0E89A3A79
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 11:51:54 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-53a017bc09dsf1320632e87.0
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 02:51:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729245114; cv=pass;
        d=google.com; s=arc-20240605;
        b=KmEkh2hiyl7n1QIscZuEDNx60OlKqdffkBQpnZY0Rmk7G6yWwGu6BjnIcyh+52eHge
         7rlUTNAjvOF6y+B8rYBm/JJqU2fYCq53aqliwIUztSO1GLqZeXBFgPSSh1v5Zd+JGPED
         GTkjfaRdBGzxm3R3iWKrvgemTrE47FaBfXxlyH57p/Be74/+JrwbeykcGGkUOpWkh/Ih
         hcTJVvbeLCKPc6e5wBPhuGynDdWrGcWpsIA/m5PGVm+LStYhAaXi4OngtahAlVdfaTy3
         +BxgE88ANDftSvrl5lBhEJqAms63ktQjLayYic03N+i9dtI75rm5Iulhczjka+JNHwNX
         NgOA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:autocrypt:from
         :references:cc:to:content-language:subject:user-agent:mime-version
         :date:message-id:sender:dkim-signature;
        bh=tnNKDvG4y2jZu+qc8iJMXBCSDVZC+E+cY48NveHu5rI=;
        fh=0xw7XnOf08+K8h42ttb/ArxWa8qpnYWQkGyDmDiCD1E=;
        b=C4nUK4U77PvFqDL17RQIJ7dX6qmju5d4mweZ+YrCgOA2l62wWeSFzC+P9Qf5ZoGPtY
         W+x4lK7hhJrSOqjALfkvnysfqis9czMnsfWgi8oJWPfXhIYEZ1b/efVg6dyGgYmlezC1
         yhjYPFFWf7g357VeO6UH9VL/N7V24S3Cl3RuKe95hIfnGutcq4+CHh84LMhQ0baNDj23
         gvFA9wBbcFMQC9AtMuaPtZacUFRqHeCsKK+rhUvIyl88g/oKbHj9y7GnSRvnvaJ6DlvH
         Qxdp7NoU6CoEgdzjND11vw1k6wtl4r/ELw6GBq2ZRGnq7vgXz2RBSCmGKmnokRdefJ6j
         OKmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jQNn36iu;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jQNn36iu;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729245114; x=1729849914; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:autocrypt:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=tnNKDvG4y2jZu+qc8iJMXBCSDVZC+E+cY48NveHu5rI=;
        b=Oj5zby6kNV4IWcfokHVM+/+ZBy6YuOaXrLW52MZRLRs232q5GU0ubsnA9J1Rg36ABK
         XDrCvikGJbqQs39fm1uHMG+hTSQRK/izfF1GuhQ7+3qd7v0l5Y3DNhTBQim8v/qDsBHk
         0BE8Z2yKp6weq2DLt5v2/h5iCuCuIKkPwaTt7aeSEtY0O3enT+WSsVpRHfFIn0U/mA6b
         1BZkZeKw1Y1w8pkMX9O6xHiVoDgsmtJtGN07oaSMCAxkAORTsbeIZDqa/NPcR4xE7r0m
         wUlVjDXF4PlWhv2Algiy8pPePm8QMeVFoT9k6Lx6tdAvd/MzJIY5MCKNqokuJsNsun3J
         5BgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729245114; x=1729849914;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :autocrypt:from:references:cc:to:content-language:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=tnNKDvG4y2jZu+qc8iJMXBCSDVZC+E+cY48NveHu5rI=;
        b=FXo+7lF+zxvavkkTx3GhKAClHWM5UJZaHA2IjCIh0qyL6Eozk5Zs4MwDnMlr6LvMx3
         nKrINsohM9SWYo+lJJUQyG8UwKCEFCliHGuJktrQy0F51LTPRYTZtLnqnA5eqAPBq2nG
         PZPLhIjaxAtfRh9B0IW5eze5JV3fEmpa7v8K7R3jaoUv4DwKJi8Iy19CJCh7lZn97g5N
         TYRY70Xu+ggQTwVK/XxNjNggZcWRYbpEyQAF5vRnIE8+JxgShDaZXeOTMO2hiVwlfgPX
         dsACDFB6q0ykBOylYmKRdWlTri8pANTV4jmf1jsD5d05HdrRzTWuA/AQ95xwc21g7PEb
         6vQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX2Dmbep4vSoKzlLe+UES6nlbxDYM90zNRHuzlArMa7gQC8zWrNVmjqWEpSLvqCyWlSVYu7rQ==@lfdr.de
X-Gm-Message-State: AOJu0YzPaIshSWVkrjRn9kV8yh42ODjec0qXF9E7IKomzSc7xd3Y801j
	mub9X2AEqQ/NmnEgm1TyCO58ECqv8WCl6hpj4M6sz9k8Mnz2StHM
X-Google-Smtp-Source: AGHT+IGDq3DVz99ibFEa10e9Xf/M9LNtxhTo068QJnIj2/4EUZglx2k3B/Qgj2HLTW9NOZ4o1IJ/Ug==
X-Received: by 2002:a05:6512:31d2:b0:53a:1337:5ff7 with SMTP id 2adb3069b0e04-53a154e79d3mr1025158e87.40.1729245112821;
        Fri, 18 Oct 2024 02:51:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3e27:b0:539:907d:1ec4 with SMTP id
 2adb3069b0e04-53a0c6a31b0ls632792e87.1.-pod-prod-03-eu; Fri, 18 Oct 2024
 02:51:51 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUAjcnW+SisUExpJ5W+/0cLS7uGcm0rykUuYCdhf0r3yAJvIw6XfiabOFesM/azsVl1CLwwgw1NRhQ=@googlegroups.com
X-Received: by 2002:a05:651c:1502:b0:2fb:593c:2bf2 with SMTP id 38308e7fff4ca-2fb82e90cebmr7250251fa.3.1729245110657;
        Fri, 18 Oct 2024 02:51:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729245110; cv=none;
        d=google.com; s=arc-20240605;
        b=HGUJiTTm/TJ+affECG5zMBwxZMzYgflmKD3FebJDOcaSmZniMBW/RbiOgjlBy0LXLq
         1dnZR4rhBcEKuHQreiXzgdgwvXmW+DWmHD8u2yacw8T1yLAi5rIkaK1diEStyYZdw2o2
         zM5QJ9XuzAvP2mmfCTZW+ZRm3/gWsbDCUzwlhqdw+IyKTiRrTS/Y3xy42Oe5UxSQe2SP
         SC611vQAvSpeACM2pQ6hTCJkX/uzfkyECpqWXpYPsp+7lxlWn79eqDE2e5VYsNl7Nt8P
         yhROA29oCr/zxyLgcgPHlQau61fXmH5kNxhkoPrSj0clH1tGgK45AftdN86/igt3XUsz
         hupw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:autocrypt:from:references:cc
         :to:content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature:dkim-signature:dkim-signature;
        bh=FxoA0IWubQTFFZYsZLwFdw69WWfeB5BHrKx5lHw6Xt4=;
        fh=so9kd5qBaNdv/Dvj3u6dOj89M0XZuXwu5KMTS/GZQKE=;
        b=AO10RK3+8TJOUfQFIBFucxDIMkL1Rn3ma+1a9vmA9+B7csKzHFw66F9KeRPZgloxnv
         8nwA9IkWLXh7nXYmyKObopjVw1ZmWvHGleflNuFpN9CC6zTPys70FE0p2BwxlGoiA4DD
         PvA1WfZ0GR1deiPG3VtH0LxFDvOngIzf85MCiC6hAn0OPtNkypxo5TxTlcyglvNqe6Fj
         wrNyJ+9EcgAZiaDCN2g4LtKt05oD/dweGF/i6khE+parelpUfCI75A9mGlASp376KQaL
         ceQ97DdYLyEQmXXtmBhX1YgfYaiyTHcM5qRF7hQyL+NeRIECJSS/uS3iOos2afA6oL8J
         8fPw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jQNn36iu;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=jQNn36iu;
       dkim=neutral (no key) header.i=@suse.cz header.s=susede2_ed25519;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.223.130])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-2fb809fccb6si232931fa.3.2024.10.18.02.51.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 02:51:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted sender) client-ip=195.135.223.130;
Received: from imap1.dmz-prg2.suse.org (unknown [10.150.64.97])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id CFA0C21B5A;
	Fri, 18 Oct 2024 09:51:49 +0000 (UTC)
Received: from imap1.dmz-prg2.suse.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by imap1.dmz-prg2.suse.org (Postfix) with ESMTPS id AD9E013680;
	Fri, 18 Oct 2024 09:51:49 +0000 (UTC)
Received: from dovecot-director2.suse.de ([2a07:de40:b281:106:10:150:64:167])
	by imap1.dmz-prg2.suse.org with ESMTPSA
	id qTMCKrUvEmdHYgAAD6G6ig
	(envelope-from <vbabka@suse.cz>); Fri, 18 Oct 2024 09:51:49 +0000
Message-ID: <c4a55668-dfdf-42f3-89b7-eb9c5ded4c81@suse.cz>
Date: Fri, 18 Oct 2024 11:51:49 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 0/3] mm/slub: Improve data handling of krealloc() when
 orig_size is enabled
Content-Language: en-US
To: Feng Tang <feng.tang@intel.com>, Andrew Morton
 <akpm@linux-foundation.org>, Christoph Lameter <cl@linux.com>,
 Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>,
 Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Roman Gushchin <roman.gushchin@linux.dev>,
 Hyeonggon Yoo <42.hyeyoo@gmail.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Marco Elver <elver@google.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Danilo Krummrich <dakr@kernel.org>, Narasimhan.V@amd.com
Cc: linux-mm@kvack.org, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
References: <20241016154152.1376492-1-feng.tang@intel.com>
From: Vlastimil Babka <vbabka@suse.cz>
Autocrypt: addr=vbabka@suse.cz; keydata=
 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
 EP+ylKVEKb0Q2A==
In-Reply-To: <20241016154152.1376492-1-feng.tang@intel.com>
Content-Type: text/plain; charset="UTF-8"
X-Spam-Score: -2.80
X-Spamd-Result: default: False [-2.80 / 50.00];
	BAYES_HAM(-3.00)[100.00%];
	SUSPICIOUS_RECIPS(1.50)[];
	NEURAL_HAM_LONG(-1.00)[-1.000];
	NEURAL_HAM_SHORT(-0.20)[-1.000];
	MIME_GOOD(-0.10)[text/plain];
	FREEMAIL_TO(0.00)[intel.com,linux-foundation.org,linux.com,kernel.org,google.com,lge.com,linux.dev,gmail.com,amd.com];
	TAGGED_RCPT(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCPT_COUNT_TWELVE(0.00)[17];
	ARC_NA(0.00)[];
	RCVD_VIA_SMTP_AUTH(0.00)[];
	MID_RHS_MATCH_FROM(0.00)[];
	FREEMAIL_ENVRCPT(0.00)[gmail.com];
	DKIM_SIGNED(0.00)[suse.cz:s=susede2_rsa,suse.cz:s=susede2_ed25519];
	FROM_EQ_ENVFROM(0.00)[];
	FROM_HAS_DN(0.00)[];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_ALL(0.00)[];
	RCVD_COUNT_TWO(0.00)[2];
	TO_MATCH_ENVRCPT_ALL(0.00)[];
	FUZZY_BLOCKED(0.00)[rspamd.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[imap1.dmz-prg2.suse.org:helo,suse.cz:mid]
X-Spam-Flag: NO
X-Spam-Level: 
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jQNn36iu;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=jQNn36iu;       dkim=neutral
 (no key) header.i=@suse.cz header.s=susede2_ed25519;       spf=pass
 (google.com: domain of vbabka@suse.cz designates 195.135.223.130 as permitted
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

On 10/16/24 17:41, Feng Tang wrote:
> Danilo Krummrich's patch [1] raised one problem about krealloc() that
> its caller doesn't pass the old request size, say the object is 64
> bytes kmalloc one, but caller originally only requested 48 bytes. Then
> when krealloc() shrinks or grows in the same object, or allocate a new
> bigger object, it lacks this 'original size' information to do accurate
> data preserving or zeroing (when __GFP_ZERO is set).
> 
> Thus with slub debug redzone and object tracking enabled, parts of the
> object after krealloc() might contain redzone data instead of zeroes,
> which is violating the __GFP_ZERO guarantees. Good thing is in this
> case, kmalloc caches do have this 'orig_size' feature, which could be
> used to improve the situation here.
> 
> To make the 'orig_size' accurate, we adjust some kasan/slub meta data
> handling. Also add a slub kunit test case for krealloc().
> 
> Many thanks to syzbot and V, Narasimhan for detecting issues of the
> v2 patches.
> 
> This is again linux-slab tree's 'for-6.13/fixes' branch

Thanks, added there.

Vlastimil

> [1]. https://lore.kernel.org/lkml/20240812223707.32049-1-dakr@kernel.org/
> 
> Thanks,
> Feng
> 
> Changelog:
> 
>   Since v2:
>   * Fix NULL pointer issue related to big kmalloc object which has
>     no associated slab (V, Narasimhan, syzbot)
>   * Fix issue related handling for kfence allocated object (syzbot,
>     Marco Elver)
>   * drop the 0001 and 0003 patch whch have been merged to slab tree
> 
>   Since v1:
>   * Drop the patch changing generic kunit code from this patchset,
>     and will send it separately.
>   * Separate the krealloc moving form slab_common.c to slub.c to a 
>     new patch for better review (Danilo/Vlastimil)
>   * Improve commit log and comments (Vlastimil/Danilo) 
>   * Rework the kunit test case to remove its dependency over
>     slub_debug (which is incomplete in v1) (Vlastimil)
>   * Add ack and review tag from developers.
> 
> 
> 
> Feng Tang (3):
>   mm/slub: Consider kfence case for get_orig_size()
>   mm/slub: Improve redzone check and zeroing for krealloc()
>   mm/slub, kunit: Add testcase for krealloc redzone and zeroing
> 
>  lib/slub_kunit.c | 42 +++++++++++++++++++++++
>  mm/slub.c        | 87 +++++++++++++++++++++++++++++++++++-------------
>  2 files changed, 105 insertions(+), 24 deletions(-)
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c4a55668-dfdf-42f3-89b7-eb9c5ded4c81%40suse.cz.
