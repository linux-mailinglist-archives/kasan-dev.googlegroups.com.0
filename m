Return-Path: <kasan-dev+bncBDDL3KWR4EBRBQ7VWSTAMGQE43WWQYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id 646D5770753
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Aug 2023 19:52:05 +0200 (CEST)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-268441d0e64sf1973450a91.1
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Aug 2023 10:52:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1691171523; cv=pass;
        d=google.com; s=arc-20160816;
        b=mJWoof6RhWKIf47UEHfFkAlRsK/ixhPBaVJBZoYgkTbvwoq/py4VxYJwrWPPcHScC2
         EewiTjlkWdUwZjCj52dSHy56nPrZFDLKY75QSk6xEzch9UFxWxSW/sDO6/l8ngUeH0tB
         BIia3ECvE0LY74HPsxEO3Xx4BRaEotRYPCszoop35uDn8gF5d7N0pIux/9Yy45LdSLSB
         jtgG8Cc8IPBJhVyuoByCRd8tSJpDqwWOHSli3Ddyt8E9XKkOsV0TpMOGGKU4q0wk4b51
         lWx8M0/LzHIjxoVdN6CJkhpvPJuQow84F0qV7A0HLPr5oc4FOR2S0wBfNKLLwl6eK4x9
         sXhA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QORwQOERxLMLNAudniazjGGbaKZVIHGNndDpYocWewg=;
        fh=qkTuvW9ByiBJkBS+1khXxtkoJOcSwWqbti21sR93Sg8=;
        b=PPaI9ae2rvl2sXcyMhJOV+aP3um8zFEQ3M+/VqSZPqtk2tlUu6I64/bmCkHrCQu3/Q
         G2jQwQS7XqMcLcTolqQeVX82vinU3DMtD/pwuRuJC4jf+WxhG8XPl+cTansq0IqKgGsW
         SyRE6/31QwJJtFleirpIUx9xL/1VkZECenlIH4vpJlFhWPwSEGuWYWu8CX+MJf83nOoF
         uugnHDzgNP1KKKdIwXsayTd/ndfBqatAEGh/kW64o2PqOTHjJ6FQxnLKew1bthkzV5Q5
         BTDc+vRoK16/Yy7LJos0mXvewqmcMTcaehqYOR7gqDbc+86m1SGqZmZhwurh51LoI0bb
         dBOA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1691171523; x=1691776323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QORwQOERxLMLNAudniazjGGbaKZVIHGNndDpYocWewg=;
        b=IjQXaRTKx2clnNlao8A5X4hfZ0g9hi4IA1dBua97V6fxhXJ2FFsGH1maPqQIkFIQIB
         vjjl1J5I/oMorecutrfwE/I5m18kv/ptstZuIew5ThKYM/MWxlXnrnZW9n9lUVolABaF
         G7NWWb7DlrprP/BuWsgRFoBTbjMiDOzlEWz5dSwDWVt0qal+/NI6/cAyDxkyIxiGvSiR
         fwa1wK59lBF8WtY5TwUWCblwjFd5xLt1V7VddRvUnMJmJys8Y363/9q3j3KoysJGi2Me
         8cHQcI2bAQJDqAOxnHkRSbQaZHqTSrlzPDddWqj4KjSNue+mMQddy3U2CyylemWzOgzY
         3y2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1691171523; x=1691776323;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QORwQOERxLMLNAudniazjGGbaKZVIHGNndDpYocWewg=;
        b=ftkednVKlvzOoMJeXHw1crbfRxYaDbMdNsAy6+aMDVrt5Fe81VUuP2vBY1IeH7/anZ
         mqpKXitTi/+2Y9gL7pE+PwZBJC/IBQfOe4ERFWG4I1X2xm33SwIH2WLoNQVJziGJtCHv
         6asdqb4F+4n4X8frNPaPy4uX4QV3LyR9pdkQV76RR0YBNiFDnZ7GKKidt6ylX/Yj/6F+
         jftmsbmmGAqlJ29xos5Upa9VJiRaQH3EXBT/dwRY9KjmZW4NA1HMPqXHwfPx8iz52hci
         mkqfD2WEHUmnoxisZvr/1MUW2wGWWK1DmaXox/guFLK/a7zQd3cWtJqdZ/URgnPG237G
         VI5g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyD+IwVJZNFrHpFeINu7yn+cK9HwFUyzs3cSHuNyJHejWqh51VC
	gWLK75poIv6vybZaj5woHWc=
X-Google-Smtp-Source: AGHT+IFeaqoDuPL7yeW/Ycn8sxauT7m0wRTAfy6LnCbFvpYLv/Sjg6N1WEMg6lHrqaTdJ4Bjkg7dEg==
X-Received: by 2002:a17:90b:4b04:b0:268:dad:2fdc with SMTP id lx4-20020a17090b4b0400b002680dad2fdcmr2458562pjb.21.1691171523549;
        Fri, 04 Aug 2023 10:52:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2397:b0:268:f0b:2429 with SMTP id
 mr23-20020a17090b239700b002680f0b2429ls158880pjb.1.-pod-prod-08-us; Fri, 04
 Aug 2023 10:52:02 -0700 (PDT)
X-Received: by 2002:a17:90a:ce96:b0:268:5bca:3bdf with SMTP id g22-20020a17090ace9600b002685bca3bdfmr2321088pju.40.1691171522437;
        Fri, 04 Aug 2023 10:52:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1691171522; cv=none;
        d=google.com; s=arc-20160816;
        b=lyHjnVbe0Kwog6dj64zXRd/I7wKcr+8F/dWPgAVDbinGB/gOc9dlqiXVN3eCOyO4BY
         pu+BeUQo2YPtARvHlz9wBPODxYkyV39blIIJR3PNbtxZ/WaZIJbycGnSGAsfb+EA35lM
         JuoJO7WweRREoZ5LcOKH203GlB4sa4vDSKHP/hK9OM82ocIr3xz6deOAPMYFe3TxgDye
         k+1JkJuEdYdR/A3nB13t7ZaoD8jgyC7jJclz0DZGjfTPmHp/QjHivazyX2tBJAgLK051
         zTYer7rUb6kZLB9rBiMDwpBY92aL8lb8NUxcJcyGodUPf1KfGOYWCig23GgggIn0bjVY
         anMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=NkmXcWpTmNedE9X1yoYWUbjj2reCnz33pQSc8zmQ/90=;
        fh=qkTuvW9ByiBJkBS+1khXxtkoJOcSwWqbti21sR93Sg8=;
        b=g9qSImRYhAYDeoAc/T3mDbkiRPJyKV/giNyRvubhAlOqZkjSyibHe6aPBzGaeSgF6z
         9gZD3POUCjpd2Du3WPvqnLMVxZYyR5axV3qLsGcGhZAfnQ+cf21pFq+LxUu1rJ4i/Vch
         drHuQIhWbVLb31fS60sd/ZleNg/xpG5rPrN1WmvjPyGPhGuknWV5yqRPwdn2Z2Dkeii0
         aI8YVs3jBiNNQ9sfgxDC+v296KRa80n2ZjCmSJF8w0KoEbV12CvjDGUbmFNxl4S7g6zt
         2WuRwjjyaPvVpZMBnQjkbcPXD4+OcJG4pBJWmmuhTgLcyTj/QAE1FyHqSmtv5Cwb32nN
         Omng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id so3-20020a17090b1f8300b0025c1096a7a4si314010pjb.2.2023.08.04.10.52.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 04 Aug 2023 10:52:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id CF681620B2;
	Fri,  4 Aug 2023 17:52:01 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A652DC433C7;
	Fri,  4 Aug 2023 17:51:59 +0000 (UTC)
Date: Fri, 4 Aug 2023 18:51:57 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Peter Collingbourne <pcc@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>,
	Willem de Bruijn <willemdebruijn.kernel@gmail.com>
Subject: Re: MTE false-positive with shared userspace/kernel mapping
Message-ID: <ZM06vS0JrAVBYv2x@arm.com>
References: <CA+fCnZdeMfx4Y-+tNcnDzNYj6fJ9pFMApLQD93csftCFV7zSow@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CA+fCnZdeMfx4Y-+tNcnDzNYj6fJ9pFMApLQD93csftCFV7zSow@mail.gmail.com>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi Andrey,

On Thu, Jul 20, 2023 at 08:28:12PM +0200, Andrey Konovalov wrote:
> Syzbot reported an issue originating from the packet sockets code [1],
> but it seems to be an MTE false-positive with a shared
> userspace/kernel mapping.
> 
> The problem is that mmap_region calls arch_validate_flags to check
> VM_MTE_ALLOWED only after mapping memory for a non-anonymous mapping
> via call_mmap().

That was on purpose as we can have some specific mmap implementation
that can set VM_MTE_ALLOWED. We only do this currently for shmem_mmap().
But I haven't thought of the vm_insert_page() case.

> What happens in the reproducer [2] is:
> 
> 1. Userspace creates a packet socket and makes the kernel allocate the
> backing memory for a shared mapping via alloc_one_pg_vec_page.
> 2. Userspace calls mmap _with PROT_MTE_ on a packet socket file descriptor.
> 3. mmap code sets VM_MTE via calc_vm_prot_bits(), as PROT_MTE has been provided.
> 3. mmap code calls the packet socket mmap handler packet_mmap via
> call_mmap() (without checking VM_MTE_ALLOWED at this point).
> 4. Packet socket code uses vm_insert_page to map the memory allocated
> in step #1 to the userspace area.
> 5. arm64 code resets memory tags for the backing memory via
> vm_insert_page->...->__set_pte_at->mte_sync_tags(), as the memory is
> MT_NORMAL_TAGGED due to VM_MTE.
> 6. Only now the mmap code checks VM_MTE_ALLOWED via
> arch_validate_flags() and unmaps the area, but the memory tags have
> already been reset.
> 5. The packet socket code accesses the area through its tagged kernel
> address via __packet_get_status(), which leads to a tag mismatch.

Ah, so we end up rejecting the mmap() eventually but the damage was done
by clearing the tags on the kernel page via a brief set_pte_at(). I
assume the problem only triggers with kasan enabled, though even without
kasan, we shouldn't allow a set_pte_at(PROT_MTE) for a vma that does not
allow MTE.

> I'm not sure what would be the best fix here. Moving
> arch_validate_flags() before call_mmap() would be an option, but maybe
> you have a better suggestion.

This would break the shmem case (though not sure who's using that). Also
since many drivers do vm_flags_set() (unrelated to MTE), it makes more
sense for arch_validate_flags() to happen after call_mmap().

Not ideal but an easy fix is calling arch_validate_flags() in those
specific mmap functions that call vm_insert_page(). They create a
mapping before the core code had a chance to validate the flags. Unless
we find a different solution for shmem_mmap() so that we can move the
arch_validate_flags() earlier.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ZM06vS0JrAVBYv2x%40arm.com.
