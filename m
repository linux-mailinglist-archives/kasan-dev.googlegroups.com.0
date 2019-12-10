Return-Path: <kasan-dev+bncBCY5VBNX2EDRBIOOXXXQKGQENU6QU3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id B25891183B9
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 10:36:33 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id f1sf3776290ljp.5
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Dec 2019 01:36:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575970593; cv=pass;
        d=google.com; s=arc-20160816;
        b=I3+3Yr75T+Dr0CQ92gV8NJa1gBufjUkpbGgJj9ZWjS8Wn44OKZg5evWCNGWAG2BAZN
         s5kGNBoGkiowQ3ZB7Eu5vMeP2JatsX0rK9WwV36uENmHAKXFPc2pkvwmbqEXYFosorim
         79PcoSxig6fau/QsvxFvTz+OYeEyjTNtJU/60J4IwUgI2zm38v1mxBfzgN8fN1LD4DMH
         0QPLXVxTeAVcO9FkX1CIDww17uLWaULkFyApJrwjV3ZJxKyB1PEp59XGpkDG88rxWyNd
         2IIlHfFbQmN1K27ctAhG9l/hDpxgO9uIUkppIlW491F5dLGQVyZpaZ3tgyacxaSDnAQO
         5NiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:to:subject
         :sender:dkim-signature:dkim-signature;
        bh=4USDX+QVuy14cK9e2+PFHC7GRa/tufPqaWfsMmVxbLE=;
        b=GlTMa1AklO2x9b7EqcFgGMUQN4LDGbFjFEskxrgvaywRSEArAQ1UU7vreBr7w/DEl6
         /CxpczE1d5sJ+XJJZDZChLWyPWMAR9WzAD6zE1nGwhhyCLiPvbe5R4bRcL1/mzLb0828
         sOGtacM7nL3rLn+2BP++8RRNgpIgfoY8AoPNAcpbfSCEgPuHDWo2bPzX+jgJrXdJZ4hK
         0ZIZUcYpGaCvcLxDxY7nucQ3w6lQZhqYuhG0Gjljjgkx0AawFhNt5VCFdKugIGPzSB70
         WUXgA0CNE9lPAPRhAEHOgJJS9wfNsBjW5T/oxqHk6AfX8RTw08wAaCZBAeJxKukgNl64
         i8bQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UBiVzNjP;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4USDX+QVuy14cK9e2+PFHC7GRa/tufPqaWfsMmVxbLE=;
        b=oLOLQNkMB157GWSH6BWIe9pugtYjQTX9gON1iVNSHQZixiH1v8Rea/6mf2W/aQ13FI
         Oeh3V5C933hxF9NXNBj3Jt/zyZlJuaUmt1TgfX0/s27aI6DPylGzdMQoTDLJGkhgSLQJ
         T13h4OEZ7fo3fLEU6jvLsF277BDBvef9tLbOgwwG6A9cWXUTBDXd8RGmO9BxbEjP3u5f
         hwueK7LLvpZFOGg0PkxOT6VrR+mF3It3clLi7tg3SbfuV06TuacuH8nfI6OKhoefla+o
         4OvJVFEY96cUSRg3AiqB+IxQgwU3Rzjilf/6ls8tqj7haBVq8Gy4gG1rhLLVR9gpIluH
         bqhA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=subject:to:references:from:message-id:date:user-agent:mime-version
         :in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4USDX+QVuy14cK9e2+PFHC7GRa/tufPqaWfsMmVxbLE=;
        b=B9V5WO1NgrY+JEYe03cglNpbT3ADQ9jGynqNbUHm4HqUrBwimZCQ14pn5iNZSsRnVi
         FQbjMLs+wEmawQkOF2R0iLN060s/d7oeGo9gQ9DU14BgNrpGeIjjd33XvbGYuZQEg88L
         ctijK6MbFDheYZeQj2HF6xCgbbKJfwAQlsChJMM6oxwqCcQq+1bri276rnq9WrZ8nKxF
         i03c15JlUrliy16XoZxbhJZYt29iZwVwAeLXVQ5KmfAEnfTGVN/gzlEKwrlYDCLmZ6N/
         X3VX2CSv/L0Adrv7fIPHQDAWaaNmqOaPojF/vOfmltuJUAE+rmZZ2uSFbvKNTPL2WhU0
         A1ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4USDX+QVuy14cK9e2+PFHC7GRa/tufPqaWfsMmVxbLE=;
        b=drFtFb02L74BzomfYcLFOp5961fvcZZxF9NTRAiamPp/cKEXtwohGHFUHFltMQL01U
         l+Mca36KwJR2ygL30hJKmOIB+BpcjT5GBbkR48tsKngWzmH5rVcUD0aTIPqMIfp1LlrL
         zfIegxxclgYB9Ar4W1NhKeaEsa9sAj2yzyr6ktfWPnk1kgMNNUKyMHuptuir+T6YnOgi
         MeadHB3rfmSRKBdBu1M/upxnX7bGFqA/d+9HEZhs8yuLtmko7MrEzaT0inaKWXSkomBt
         T+SYUTI/Hk/rQHNninZiZ5AVm7ZhS9KnpD4mTpWlkq93K+4tQwzQYAjzGPVnPT25nqoE
         54xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW87KllnGbO5eT34heonCWUJZczNkxtBogvXHz0inaZjFOV3orT
	nYM2vMI70cKU5Gp0ORuu6p0=
X-Google-Smtp-Source: APXvYqypv87KeS0FgUObzyDyPKgU8rH14yBukIv+nRXxXwNq24ADv6JRYOsItavyng9XQZdlm7Zw4g==
X-Received: by 2002:a2e:9bd9:: with SMTP id w25mr18178375ljj.212.1575970593275;
        Tue, 10 Dec 2019 01:36:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:1051:: with SMTP id x17ls2336596ljm.8.gmail; Tue,
 10 Dec 2019 01:36:32 -0800 (PST)
X-Received: by 2002:a2e:9356:: with SMTP id m22mr20023574ljh.160.1575970592744;
        Tue, 10 Dec 2019 01:36:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575970592; cv=none;
        d=google.com; s=arc-20160816;
        b=nAsEQsd+lkqXkfUs9UyDVstmgVnjoyJ1ZtuPMXDT1gxcPOhLBxQD80TlSxSfcKf/Xf
         vmD/uQFTEE8AK6S8jOlPxizKS8HE+fwqn91yMffClDI18UpzM4zglYVCne1VY10d9FCI
         yK7nqXPFoh5wirqxzemLreNkIdgXAKDSG5aq8xc8ms/v0UOuaAkhrgvr95kdOA6Zkhqo
         NWtbggj7RbouQWkMbxF5BLt0T5xW2RdHOicJ7DdgCjKYFx0uyLwssRw2OAnoaeW6Q61K
         S+1lUbMGleyESmH6zsSp8x3AzYJl/ReFBuV6zO1mQ0s0zvcd+phAsWB3BBWWERA0xyUj
         GnJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:to:subject
         :dkim-signature;
        bh=gXjxkm88DEjZBFBOVgYS/nXq7WpsnAwIahBe1LGrB6M=;
        b=n496Cpzq5tiVONY3+o1arHKdUhfThR5l/ZRfnh1ajU0IgA/eGqe2yqfrfEWuGi8tv5
         Z/YzxC8gZuBAGUE2RHJuLuHdG2dJeYXMczYLo6fvDmvDW55dO+wvd06W5tcfHDh0x0wu
         QneGM15XKA8M5vzyY79sHMnBBWo3du1+kYG1dmtXkxmltJ2sp+eZIFj8qqKFPUEwV+zn
         YQV3ei/x/TStOK+fDIhGFHi6/sB+uMQFGJvwf3P0/Drj/ik/eeCg2M8joa3edpuH56pC
         vJF1aUY4BXTd8qQQ1RKToLIJlFzKwpJllEHMPwvYdVNYAFMatr513VN7p0pLUt1zynjM
         9Nfw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=UBiVzNjP;
       spf=pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::244 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-lj1-x244.google.com (mail-lj1-x244.google.com. [2a00:1450:4864:20::244])
        by gmr-mx.google.com with ESMTPS id f1si72313ljg.2.2019.12.10.01.36.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Dec 2019 01:36:32 -0800 (PST)
Received-SPF: pass (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::244 as permitted sender) client-ip=2a00:1450:4864:20::244;
Received: by mail-lj1-x244.google.com with SMTP id r19so19104412ljg.3
        for <kasan-dev@googlegroups.com>; Tue, 10 Dec 2019 01:36:32 -0800 (PST)
X-Received: by 2002:a2e:9015:: with SMTP id h21mr3537646ljg.69.1575970592330;
        Tue, 10 Dec 2019 01:36:32 -0800 (PST)
Received: from [192.168.68.106] ([193.119.54.228])
        by smtp.gmail.com with ESMTPSA id m21sm1186222lfh.53.2019.12.10.01.36.27
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Dec 2019 01:36:31 -0800 (PST)
Subject: Re: [PATCH v2 2/4] kasan: use MAX_PTRS_PER_* for early shadow
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 linux-s390@vger.kernel.org, linux-xtensa@linux-xtensa.org,
 linux-arch@vger.kernel.org, linux-arm-kernel@lists.infradead.org,
 kasan-dev@googlegroups.com, christophe.leroy@c-s.fr,
 aneesh.kumar@linux.ibm.com
References: <20191210044714.27265-1-dja@axtens.net>
 <20191210044714.27265-3-dja@axtens.net>
From: Balbir Singh <bsingharora@gmail.com>
Message-ID: <a31459ee-2019-2f7b-0dc1-235374579508@gmail.com>
Date: Tue, 10 Dec 2019 20:36:24 +1100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101
 Thunderbird/60.9.0
MIME-Version: 1.0
In-Reply-To: <20191210044714.27265-3-dja@axtens.net>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: bsingharora@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=UBiVzNjP;       spf=pass
 (google.com: domain of bsingharora@gmail.com designates 2a00:1450:4864:20::244
 as permitted sender) smtp.mailfrom=bsingharora@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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



On 10/12/19 3:47 pm, Daniel Axtens wrote:
> This helps with powerpc support, and should have no effect on
> anything else.
> 
> Suggested-by: Christophe Leroy <christophe.leroy@c-s.fr>
> Signed-off-by: Daniel Axtens <dja@axtens.net>

If you follow the recommendations by Christophe and I, you don't need this patch

Balbir Singh.

> ---
>  include/linux/kasan.h | 6 +++---
>  mm/kasan/init.c       | 6 +++---
>  2 files changed, 6 insertions(+), 6 deletions(-)
> 
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index e18fe54969e9..d2f2a4ffcb12 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -15,9 +15,9 @@ struct task_struct;
>  #include <asm/pgtable.h>
>  
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
> -extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
> -extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
> -extern pud_t kasan_early_shadow_pud[PTRS_PER_PUD];
> +extern pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE];
> +extern pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD];
> +extern pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD];
>  extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>  
>  int kasan_populate_early_shadow(const void *shadow_start,
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index ce45c491ebcd..8b54a96d3b3e 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -46,7 +46,7 @@ static inline bool kasan_p4d_table(pgd_t pgd)
>  }
>  #endif
>  #if CONFIG_PGTABLE_LEVELS > 3
> -pud_t kasan_early_shadow_pud[PTRS_PER_PUD] __page_aligned_bss;
> +pud_t kasan_early_shadow_pud[MAX_PTRS_PER_PUD] __page_aligned_bss;
>  static inline bool kasan_pud_table(p4d_t p4d)
>  {
>  	return p4d_page(p4d) == virt_to_page(lm_alias(kasan_early_shadow_pud));
> @@ -58,7 +58,7 @@ static inline bool kasan_pud_table(p4d_t p4d)
>  }
>  #endif
>  #if CONFIG_PGTABLE_LEVELS > 2
> -pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD] __page_aligned_bss;
> +pmd_t kasan_early_shadow_pmd[MAX_PTRS_PER_PMD] __page_aligned_bss;
>  static inline bool kasan_pmd_table(pud_t pud)
>  {
>  	return pud_page(pud) == virt_to_page(lm_alias(kasan_early_shadow_pmd));
> @@ -69,7 +69,7 @@ static inline bool kasan_pmd_table(pud_t pud)
>  	return false;
>  }
>  #endif
> -pte_t kasan_early_shadow_pte[PTRS_PER_PTE] __page_aligned_bss;
> +pte_t kasan_early_shadow_pte[MAX_PTRS_PER_PTE] __page_aligned_bss;
>  
>  static inline bool kasan_pte_table(pmd_t pmd)
>  {
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a31459ee-2019-2f7b-0dc1-235374579508%40gmail.com.
