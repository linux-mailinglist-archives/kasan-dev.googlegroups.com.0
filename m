Return-Path: <kasan-dev+bncBDWLZXP6ZEPRBD7SRCGAMGQESWTYJLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 36738443DA9
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Nov 2021 08:24:00 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id m11-20020a2e97cb000000b00212f89f3888sf703504ljj.21
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Nov 2021 00:24:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1635924239; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kbt30g8VLgS7S0tPJfzFe10Cj3+OJJf41QgNu2Pn94VOebSp5Qcwf4mtInKS0YAc91
         sCiI5NP0+9lXOK1pk8yVB6ICiec1H3EY8ZZX+ZnB1XxF0Gu7q0MpbBM+DKa/axLrBYVn
         rWh9aPf2K23oyj4/m6bxA7tsIoIQQcbm2f0vSKf+0yXJstN4A8sN1FzsAftC0AhPghdu
         JLIo6nPAYhZjj9ZPS57YeMaV0hAA9lyvF0S1qNbYmK1RON1kxOWxjgaYjLyN/KAjA6WD
         APV2KCjE6nwp/Re4iHeFqcmQoGLYWay0KWC0PFDUerpDDUHMHLR4upp9RvW1d45ypLCB
         pwtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=6v6a1kOwNo+VAdvR0Wpq0IvzG/ULioQFnCEZNeK6ihQ=;
        b=Vm7G4IoLmmiGJ+4mNh5KsVCSVEO3kfRWZ93IsxxF6biusqzmgF5TAJL9Lf49I7G6PX
         5ORvgp4SVWmftxLWSjpjturll6C/rQfyP0dCoTaaMM7QXbNDvFptMe0tvpSQApOEH2ie
         PPsyZqXwvVBY9z5JCssgRAsTKWJSEjK9uiaS4p0Mkiwt2+x/p3I9yWaW4HF3uTvVdf0+
         Z1e2hFNWdSVnpJtSE6UyI5jveW5HuT5pbPCicnJewr5l3glmBBirK7YZgUEYgj8dd6Ia
         /Sms9O0xw9htUtSGMH+imwTxc5gkW8TY9hLNw7f3jlTbD6BW6vVhzhTi+Y7ccDBN0Lxy
         GvDg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YPpVRsyE;
       dkim=neutral (no key) header.i=@suse.cz header.b=Ss3QaDDF;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6v6a1kOwNo+VAdvR0Wpq0IvzG/ULioQFnCEZNeK6ihQ=;
        b=pQY2bWzzATf4uNtNtK+JAUguouoSEeUkYcvfSZsY88EPvqc8UvJce52ska5cL1t0qc
         duZhEiCKHUJF8j3jLztg0k+MLoLyDGw+rOFRDY9c9HYt1aBIOStaUFdZGn5ndAteMy1L
         MUmePK7aXsITxLbH7RdFedHDpRQIEZegFgwD0RNiSzNjD3MQn9/ws8oyDEMWBtGm61PC
         9WBHp3lSOsKkPX6Zj5PdHHmYRgzwxroeu1jk7fvzGXSeWQPHOIglLSett45BxYSCeR73
         nJV3xjtqZX7UJJJpfu/nRhLTjjiycJT5FAS2j4n+b6yl6+athFZjuSbkPN28ZBNioQU0
         idgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6v6a1kOwNo+VAdvR0Wpq0IvzG/ULioQFnCEZNeK6ihQ=;
        b=YbShm7k5f3ngo6YLaYjWCsKwfVEnusF70aAliV0WXTh2QmV6EbFJyO+0sH3pGthJrk
         ySXyN53qjatpdTjP0R0m8J0d+SKZLkg8l8s1qy55ZTXmZ+9+BuITvDpvBLQv3O0xPutt
         TQ1yIvjfhkogocHDHWhHpnucd/cezoy8yfGZGUD9IHuxGkPKv+W2ZUo0RxZKd7mcYBPm
         L8oN+fZzVumY0AW9yd4qpa8EoQ1fAmXf4c29D2kToHPqIcTjsmuYfvAqKikWe7E+7mnq
         hVu9boAoStYSDUcM//+om3RSP8icLPV9Xj8VcVpqUTrKRGc5HHuz2VKMbJL/a19BebXX
         WfhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531ImFZagg5BweAcHTl/LDMNR8k6e9Sx4WL3NAkaRptBhvR+tPeB
	dEbhvkQ+pEDkrbKi0HuC7D4=
X-Google-Smtp-Source: ABdhPJzl8bGp72cxEIvGU5x1eYZ0Vh7UdjfA9CWfJczxl9CgZdoGMZG3x2cy2jB3CiVhQjaQpDebvA==
X-Received: by 2002:a05:6512:22c1:: with SMTP id g1mr39047098lfu.404.1635924239659;
        Wed, 03 Nov 2021 00:23:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1314:: with SMTP id x20ls691536lfu.1.gmail; Wed, 03
 Nov 2021 00:23:58 -0700 (PDT)
X-Received: by 2002:ac2:4104:: with SMTP id b4mr27635601lfi.130.1635924238508;
        Wed, 03 Nov 2021 00:23:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1635924238; cv=none;
        d=google.com; s=arc-20160816;
        b=iksm9RXMF8p3nfdopRqjH3LtvV8paoZ6IuGTa5EMlD2VUv3xWOsFfMHNGLrapqqY+5
         e4V2xBIxQbnyWJupqo/OXzqDIMGDSMWqZkqxPGqMKhf7R1lOfap2FcLDxx9xSy5Ut6pg
         /iOCuf75cHSPREm47AXbeuo94FxgaCJBCNYFOwk5a1xqbdcYmCr3wgkiNY9aswUKoEWt
         VccQus1J0lB4mOzsGC9LtW5zFeYbjYU7XCUqGZoRvOkrdICCrqbW96GtVVpihnh+KxsG
         0MPGcQfjoek+8ucoPkfC4ju3haYvoj40K8Ws/Of7YhUUX2Z5XGLMNS31FwnBtZrTf4MU
         HE/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :dkim-signature:dkim-signature;
        bh=T4u4MEwe36HTs254JfcIvpHngVEczN5pBxWb8/aUgzo=;
        b=OYC9aBamBJFZzlSqmKNKlFQSAx/ochx8AWyWMnT6QFCdRALWDcEOFvBK08D8F5V+vr
         gFjipxNY+70V5J5ZLtjm2h/Eu7SYkptmFBeQ3Rgjrz92a+fHeWoYqaxgCuPfK2ZW36X5
         Ph/satQ5ZGGUnVbXrwI3phlX2bXIixK74aoSB29/vGO2Zel+njYOqptFouVvHmiCsVYO
         Z2bH2dAQ+z4vfqN/VzAQQar1Mvs6ZSYxB7yzvwYpLLsWVq1E33vywRpbPYIxBXIOh3Vg
         BTRXxQ4Uh686C4+nrAYv4pVvM+mF5bWO71JSbYUJuGLgS3oy1QY8a29+Uhnw1xjjkBH9
         LX7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@suse.cz header.s=susede2_rsa header.b=YPpVRsyE;
       dkim=neutral (no key) header.i=@suse.cz header.b=Ss3QaDDF;
       spf=pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
Received: from smtp-out1.suse.de (smtp-out1.suse.de. [195.135.220.28])
        by gmr-mx.google.com with ESMTPS id h4si85168lft.8.2021.11.03.00.23.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 03 Nov 2021 00:23:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) client-ip=195.135.220.28;
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by smtp-out1.suse.de (Postfix) with ESMTPS id 94FDD21155;
	Wed,  3 Nov 2021 07:23:57 +0000 (UTC)
Received: from imap2.suse-dmz.suse.de (imap2.suse-dmz.suse.de [192.168.254.74])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature ECDSA (P-521) server-digest SHA512)
	(No client certificate requested)
	by imap2.suse-dmz.suse.de (Postfix) with ESMTPS id 6B4F913C7E;
	Wed,  3 Nov 2021 07:23:57 +0000 (UTC)
Received: from dovecot-director2.suse.de ([192.168.254.65])
	by imap2.suse-dmz.suse.de with ESMTPSA
	id I5R1GQ05gmHFOQAAMHmgww
	(envelope-from <vbabka@suse.cz>); Wed, 03 Nov 2021 07:23:57 +0000
Message-ID: <af8e043c-9095-7a9a-0c0d-fcc11dec7e74@suse.cz>
Date: Wed, 3 Nov 2021 08:23:57 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.2.1
Subject: Re: [PATCH] mm/slab_common: use WARN() if cache still has objects on
 destroy
Content-Language: en-US
To: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>
Cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 linux-mm@kvack.org, linux-kernel@vger.kernel.org,
 Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>,
 kasan-dev@googlegroups.com, Ingo Molnar <mingo@redhat.com>
References: <20211102170733.648216-1-elver@google.com>
From: Vlastimil Babka <vbabka@suse.cz>
In-Reply-To: <20211102170733.648216-1-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vbabka@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@suse.cz header.s=susede2_rsa header.b=YPpVRsyE;       dkim=neutral
 (no key) header.i=@suse.cz header.b=Ss3QaDDF;       spf=pass (google.com:
 domain of vbabka@suse.cz designates 195.135.220.28 as permitted sender) smtp.mailfrom=vbabka@suse.cz
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

On 11/2/21 18:07, Marco Elver wrote:
> Calling kmem_cache_destroy() while the cache still has objects allocated
> is a kernel bug, and will usually result in the entire cache being
> leaked. While the message in kmem_cache_destroy() resembles a warning,
> it is currently not implemented using a real WARN().
> 
> This is problematic for infrastructure testing the kernel, all of which
> rely on the specific format of WARN()s to pick up on bugs.
> 
> Some 13 years ago this used to be a simple WARN_ON() in slub, but
> d629d8195793 ("slub: improve kmem_cache_destroy() error message")
> changed it into an open-coded warning to avoid confusion with a bug in
> slub itself.
> 
> Instead, turn the open-coded warning into a real WARN() with the message
> preserved, so that test systems can actually identify these issues, and
> we get all the other benefits of using a normal WARN(). The warning
> message is extended with "when called from <caller-ip>" to make it even
> clearer where the fault lies.
> 
> For most configurations this is only a cosmetic change, however, note
> that WARN() here will now also respect panic_on_warn.
> 
> Signed-off-by: Marco Elver <elver@google.com>

Makes sense.

Reviewed-by: Vlastimil Babka <vbabka@suse.cz>

> ---
>  mm/slab_common.c | 11 +++--------
>  1 file changed, 3 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index ec2bb0beed75..0155a3042203 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -497,8 +497,6 @@ void slab_kmem_cache_release(struct kmem_cache *s)
>  
>  void kmem_cache_destroy(struct kmem_cache *s)
>  {
> -	int err;
> -
>  	if (unlikely(!s))
>  		return;
>  
> @@ -509,12 +507,9 @@ void kmem_cache_destroy(struct kmem_cache *s)
>  	if (s->refcount)
>  		goto out_unlock;
>  
> -	err = shutdown_cache(s);
> -	if (err) {
> -		pr_err("%s %s: Slab cache still has objects\n",
> -		       __func__, s->name);
> -		dump_stack();
> -	}
> +	WARN(shutdown_cache(s),
> +	     "%s %s: Slab cache still has objects when called from %pS",
> +	     __func__, s->name, (void *)_RET_IP_);
>  out_unlock:
>  	mutex_unlock(&slab_mutex);
>  	cpus_read_unlock();
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/af8e043c-9095-7a9a-0c0d-fcc11dec7e74%40suse.cz.
