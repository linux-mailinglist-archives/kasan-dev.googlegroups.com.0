Return-Path: <kasan-dev+bncBC32535MUICBBGXH5T3QKGQE5APWC5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id CE8A220F4E8
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 14:44:12 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id w24sf12017132ply.10
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jun 2020 05:44:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593521051; cv=pass;
        d=google.com; s=arc-20160816;
        b=GGQbf/6/yPmecSs22Cyjr5imHO47+JngcCzM+VVdoWRLFA+51S4FE6v9ZLA1oJtDma
         Dd237ONY6M732QjgZ4CodXH+avccIyoywiM2wxw6lrRalkTvFIgdXXGWMpeVQSTM+EK2
         kavoGYuCHFyiHepCi76sYcmYWHoOggKb/cQCuLSC8doMN6BlLEiLPXLHeiY5VxIytQLo
         xe9TYHMmdrd8UhotTlKBSbRBvFAsHixVT8vCN/fM3wOQ0ewokLfiqa6CiglrNwhcYIua
         F/S8CNaiUuqKhcqj92Ge68y/hFszQiER/NK5J0oR+RVTDu5qQGmCd2WeVdD0gDwHZ+cH
         Rd3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:organization:autocrypt:from
         :references:cc:to:subject:sender:dkim-signature;
        bh=j4JnYR4Tu4mYAcvDx0PkqukRNSMvHeeyVxFfL3Svtd8=;
        b=Vj/fOGrcBtfbQChDHQE5rUQmLkQN/OojzNb7MWr3orjxys7kwz+nr5nzBF1hMxYmct
         yhyTC30I1BqHWHxEiOf/ljY6BE24AMsHLPQh98l6/6YdWAFJYvhBT7WX3OlmCvFCzFJb
         MzxkUbInvsRT5Z9klEQcx5E5W5IlZSTKq/+6y522D03G0vO9pzmyz+9C2uKwwQPHIPuP
         j2shR019GqXWlA9/A+Yv9w5z4OAtKRJuFMnpYRY2Li9a1oIVxvf+Eyqtcr4tqi+oMakD
         +aZJCwP0W0KvnsQ6uaru3uqvZrKGEFo104pWacZH05hha5cxUXID2vL3+JcEEk04k8T6
         nhuQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NGvktcjG;
       spf=pass (google.com: domain of david@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:autocrypt:organization
         :message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=j4JnYR4Tu4mYAcvDx0PkqukRNSMvHeeyVxFfL3Svtd8=;
        b=PY8nVCANF0ustojpkIwD7C6bAnM8z3dJOK6ZZIsKugCsUXJNgUnqCX9gAyXy2ocHBD
         T1UuJNcUq6ydkr5am4rn3IpuKnB9s9ah9WhlW3HQPq49rfsdBA1JtABmYE+Qzfpqmf/G
         Gdgg8gTYibihe3OCwjkuU2f7gizDl7B2ztM2ysG3c0ZvZnMZ0wnk3dAmhyvS/c5oZBnv
         KVsrOTFgFLqQ23mKhOjIwMJPJWPHbl585Q8PSY4JISZ1CgcNbkkw3IDelIROL0GPZVnM
         wHrhvCieO2RETSUfgF/XVsg+v1dGGJX1axV5ymtJXsHjCy6osoee81h7oJRGf/KVflIz
         iHUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:autocrypt
         :organization:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=j4JnYR4Tu4mYAcvDx0PkqukRNSMvHeeyVxFfL3Svtd8=;
        b=jWogUgUzcZ7Ok3kN4Lb01skDd8/1oOZtaveYk3SV+xzUR26MwxGCN7c/1EM/4BxP4G
         jrNrbYp57YN6Yopeoa6SN8zdpqB9Srid07f8HyO05elO+/ss6MKO6x7ALYGCHpKEuPDM
         NPds09X1CfJqxO4X/k+P57JgYJ6n/5erpwG0FER0180a7y/yBvA9o8pMfnV5DNxANFKo
         Cu8Ynr2Ze1jyqBdhmXuVyeUOqYJVDdAFvvu3NZWrlzWOmZZnGxVdeGw5fEeue4is9NIo
         VENHpiBQu89PZTW2IWCRGxYSZzVTAHXLysiN1AVRAuffxzmrEKkPVS0Iu6Noxic7CmGT
         rr3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dINJP8MBxNJERRFVM0xvkdKBAdEG60khke983AIHwk2LDnM9i
	KrwmsaMf238+7AByzV1X0s8=
X-Google-Smtp-Source: ABdhPJzZZKazv9wmn3CcsJkxBdipkORhG8Xs4XNyhyuMPQAEDgNZn/5yVbdXVHHn46Q38A4nFtJolg==
X-Received: by 2002:a17:90a:d3d6:: with SMTP id d22mr21956446pjw.184.1593521051012;
        Tue, 30 Jun 2020 05:44:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:730d:: with SMTP id o13ls5597911pgc.1.gmail; Tue, 30 Jun
 2020 05:44:10 -0700 (PDT)
X-Received: by 2002:a65:6916:: with SMTP id s22mr15183384pgq.128.1593521050575;
        Tue, 30 Jun 2020 05:44:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593521050; cv=none;
        d=google.com; s=arc-20160816;
        b=sk4VNRA6OuAi3w4oZgUe6IK1eworARHqfhReXEo7CdcI/LkeF+fusg9B06qByaxzP2
         4jRunO809sWE0DCp4c76HfumLno7IPXbIWhlWsqUPjdCKT2JCJeJZkdNqSic0mTpx7jR
         upZ2SsbHTRekHYUl+rN05vFqzSm7bpRAbGCCXPIDAuHxbgs+IjF8iVVs0FW4tHn9qdBK
         C7QUHtbg4C0ng71IUWNpTNxQpI25aM2YTmby5gYyxKKY/j+t+hnPZV0efiTbESeucZCw
         BUPgG6zLzLouWnJ13XS2RCHri/Gbib6lRaAtDXxacmIY5hPiPs8eat6WS7h0lRVw+jK9
         70Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:organization:autocrypt:from:references
         :cc:to:subject:dkim-signature;
        bh=eOB4QoPsgdm9AnxQjJI73ATUqfj2VJGa+RxI5dUhe7Q=;
        b=ZFDGPGAMpCt9XeVOfiqT+rI6de/z1ilhzo2Y/nyTBg8Lye+8k1h+hYJs5PxwdFUwVE
         W5krH4LHrU6z9/Z8E7VRtVKAavNpbEw3umlIUN2NnEy85/5K1dYCNCiaRyZ94GEZRaJE
         B57Wmc7hyj0AQvTPOGGtwQ+I7YxcMQNcVtaB0+GjS4L/mV9MkUYw3XWS164YUaeFiOdt
         ja73UQd2ZZ0+9ucoM4AIlTLdpIZswtMH4tbkg1+Ffjmmoupcc/2Xy2X4/MbsJVFpq1CV
         6VNs+OjsMcpfYZ4fztN4a+17wrvjHuQ1NuRMgcKHw4ma2FpXxZtN7CXsFA0o/J9Cnji/
         D4Mg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=NGvktcjG;
       spf=pass (google.com: domain of david@redhat.com designates 207.211.31.120 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-1.mimecast.com (us-smtp-delivery-1.mimecast.com. [207.211.31.120])
        by gmr-mx.google.com with ESMTPS id q85si178623pfq.5.2020.06.30.05.44.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jun 2020 05:44:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 207.211.31.120 as permitted sender) client-ip=207.211.31.120;
Received: from mimecast-mx01.redhat.com (mimecast-mx01.redhat.com
 [209.132.183.4]) (Using TLS) by relay.mimecast.com with ESMTP id
 us-mta-485-Wkccd_yLNXOV5qzUPGNUZA-1; Tue, 30 Jun 2020 08:44:07 -0400
X-MC-Unique: Wkccd_yLNXOV5qzUPGNUZA-1
Received: from smtp.corp.redhat.com (int-mx07.intmail.prod.int.phx2.redhat.com [10.5.11.22])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx01.redhat.com (Postfix) with ESMTPS id 3C2FF1005512;
	Tue, 30 Jun 2020 12:44:04 +0000 (UTC)
Received: from [10.36.114.56] (ovpn-114-56.ams2.redhat.com [10.36.114.56])
	by smtp.corp.redhat.com (Postfix) with ESMTP id 76D6010013C1;
	Tue, 30 Jun 2020 12:44:01 +0000 (UTC)
Subject: Re: [PATCH] mm: define pte_add_end for consistency
To: Wei Yang <richard.weiyang@linux.alibaba.com>,
 dave.hansen@linux.intel.com, luto@kernel.org, peterz@infradead.org,
 tglx@linutronix.de, mingo@redhat.com, bp@alien8.de, akpm@linux-foundation.org
Cc: x86@kernel.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
 linux-mm@kvack.org
References: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
From: David Hildenbrand <david@redhat.com>
Autocrypt: addr=david@redhat.com; prefer-encrypt=mutual; keydata=
 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
Organization: Red Hat GmbH
Message-ID: <40362e99-a354-c44f-8645-e2326a6df680@redhat.com>
Date: Tue, 30 Jun 2020 14:44:00 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
In-Reply-To: <20200630031852.45383-1-richard.weiyang@linux.alibaba.com>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Scanned-By: MIMEDefang 2.84 on 10.5.11.22
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=NGvktcjG;
       spf=pass (google.com: domain of david@redhat.com designates
 207.211.31.120 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On 30.06.20 05:18, Wei Yang wrote:
> When walking page tables, we define several helpers to get the address of
> the next boundary. But we don't have one for pte level.
> 
> Let's define it and consolidate the code in several places.
> 
> Signed-off-by: Wei Yang <richard.weiyang@linux.alibaba.com>
> ---
>  arch/x86/mm/init_64.c   | 6 ++----
>  include/linux/pgtable.h | 7 +++++++
>  mm/kasan/init.c         | 4 +---
>  3 files changed, 10 insertions(+), 7 deletions(-)
> 
> diff --git a/arch/x86/mm/init_64.c b/arch/x86/mm/init_64.c
> index dbae185511cd..f902fbd17f27 100644
> --- a/arch/x86/mm/init_64.c
> +++ b/arch/x86/mm/init_64.c
> @@ -973,9 +973,7 @@ remove_pte_table(pte_t *pte_start, unsigned long addr, unsigned long end,
>  
>  	pte = pte_start + pte_index(addr);
>  	for (; addr < end; addr = next, pte++) {
> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
> -		if (next > end)
> -			next = end;
> +		next = pte_addr_end(addr, end);
>  
>  		if (!pte_present(*pte))
>  			continue;
> @@ -1558,7 +1556,7 @@ void register_page_bootmem_memmap(unsigned long section_nr,
>  		get_page_bootmem(section_nr, pud_page(*pud), MIX_SECTION_INFO);
>  
>  		if (!boot_cpu_has(X86_FEATURE_PSE)) {
> -			next = (addr + PAGE_SIZE) & PAGE_MASK;
> +			next = pte_addr_end(addr, end);
>  			pmd = pmd_offset(pud, addr);
>  			if (pmd_none(*pmd))
>  				continue;
> diff --git a/include/linux/pgtable.h b/include/linux/pgtable.h
> index 32b6c52d41b9..0de09c6c89d2 100644
> --- a/include/linux/pgtable.h
> +++ b/include/linux/pgtable.h
> @@ -706,6 +706,13 @@ static inline pgprot_t pgprot_modify(pgprot_t oldprot, pgprot_t newprot)
>  })
>  #endif
>  
> +#ifndef pte_addr_end
> +#define pte_addr_end(addr, end)						\
> +({	unsigned long __boundary = ((addr) + PAGE_SIZE) & PAGE_MASK;	\
> +	(__boundary - 1 < (end) - 1) ? __boundary : (end);		\
> +})
> +#endif
> +
>  /*
>   * When walking page tables, we usually want to skip any p?d_none entries;
>   * and any p?d_bad entries - reporting the error before resetting to none.
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index fe6be0be1f76..89f748601f74 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -349,9 +349,7 @@ static void kasan_remove_pte_table(pte_t *pte, unsigned long addr,
>  	unsigned long next;
>  
>  	for (; addr < end; addr = next, pte++) {
> -		next = (addr + PAGE_SIZE) & PAGE_MASK;
> -		if (next > end)
> -			next = end;
> +		next = pte_addr_end(addr, end);
>  
>  		if (!pte_present(*pte))
>  			continue;
> 

I'm not really a friend of this I have to say. We're simply iterating
over single pages, not much magic ....

What would definitely make sense is replacing (addr + PAGE_SIZE) &
PAGE_MASK; by PAGE_ALIGN() ...

-- 
Thanks,

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/40362e99-a354-c44f-8645-e2326a6df680%40redhat.com.
