Return-Path: <kasan-dev+bncBDQ27FVWWUFRBHMEQDVAKGQE5BCBCQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3f.google.com (mail-yw1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 975707A331
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2019 10:38:54 +0200 (CEST)
Received: by mail-yw1-xc3f.google.com with SMTP id r67sf46949779ywg.7
        for <lists+kasan-dev@lfdr.de>; Tue, 30 Jul 2019 01:38:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1564475933; cv=pass;
        d=google.com; s=arc-20160816;
        b=m2McvafHX2NC94ic4nCgHQLlwyQ57P7Xn0CAANFSsmMANQzw3FJZ292V1v6BuQMAvD
         H7tIFM6E1VSlCkHh9yg0KJYmYfcjTMnYFjoQE412i4Tp9XxtEsaLv8nJT4GC5WvDa3zI
         YEGpNKPz3kIszQbRbk/VWI+WdhcL/hVeEMxH895aPeBXKZbUWORLJKhJPH9n4SDPvczN
         UN5W4VNxNDqJ7jvjpG0SPR+RzgKDuwuzXn4I4DL5Eh6ntJwDmMR1anTussCSCF1eAAJz
         AQ7Slp1LYePMkK8cAuH+EDy1lNvgJbo2MqulSgf55rfwhju6WH/kaN8SRs5snj85s/71
         /wWw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=lscEXW43mCnHdK+Pc2Z3xEq0QSsK4vRsMEPAPyvMn1A=;
        b=vCdpA1uWONzZ6EYoVswIlRjzxvSi2FyUd8Tds+pKFeeJf/U9gpY0BePMwGozGgk25Z
         xrmIL2zxdcfF1Imi1p0Gpxs2ATMwp5I7G1jbJlaOL/0danPPeo1rBAeLV0eEo5DWe8VZ
         d5VBXN4WNuuFzAoMLV65zykWpE1yeCclIahdTNu0RGEmUAylNNRE0u/LTf/ep5/gjJ7+
         bda81+4mxZPsYMWpbm8uHwOC0JBkMogzdXGp7yobKOBvo6IROVHND/+eWdHAGChUk4kC
         3avs9OpO0mlxTor1HZCa0ei4OnXEtEY82HFxj0+NYp2Lca4CCVaBJjXZyz2D+apJamzf
         Z9Rg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fBVA+CF5;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lscEXW43mCnHdK+Pc2Z3xEq0QSsK4vRsMEPAPyvMn1A=;
        b=fkm5BEe5vKpz77H4juoGW+Yis6iPRXhXIHr9k/iG12IW7v1doAKgQ6pn5K67ngCEpQ
         Oe+HcggUIAEWMdKlYBqUtKuqYf6wPtJsGjWcjIv7xnQLZ7uoXqkaxOW1Ka5dB3gURsuh
         vuCac+W3JeeX9ijO6MnlHjlqFq6beHpchG3/pBG2hZN+4Y3xinwFPIWDtc7E/lNjV9nK
         VZvrmD8OvAgdvdMEnxxz6Itwo3K3unwsy3Qr3G0S2Q2amTgJiGEQQbCc7B3hIs4kl6yi
         aNsbMRMv616YTTLF6NHgoVLsz5g5aZNDmAvgGLeM8kYAoyVdmK33uoiGgdLCpRA+SFlT
         pRsw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lscEXW43mCnHdK+Pc2Z3xEq0QSsK4vRsMEPAPyvMn1A=;
        b=sfRaWihh1XpGOcdcQcNe1ZK4BEaIFNdTwgQ/OFDlY6W75nDC4uYdyuo7hDHKQT1Zry
         FGj4ApqeCLKW0jgh5I0ToAZ7zja3mFwXZtqoNr7eidDQZdXUmm5e5XtDckRVWiH/fCnr
         l3XZ/MZCOJk2l3PRxX816eQklhtCLSi2eFULdruuVjFriOCUZAcWn+qWv+CdiRu/H8XL
         CZKVjT6IKABv3tvGJ2hpWLw+xAEQZjtVBe/sVgpRpzlo7YVPviwN0QDFyI/7Y/WlAafU
         k2LS86fKV1Qr36ety2bC2ls+OkPrDZPBXFF1WnCgHiatmsyK4jGIAiqKza+8xG9Zzf2R
         jc3A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXBMwPr39GJEU3s3utkmumNPNmLfLwcp39woVeHJVbIZMLpNoqI
	PVJQp7vbNn8yNXhsOOQmIfQ=
X-Google-Smtp-Source: APXvYqyVkr+hNFzq+T9ZOOCG59o9Z4pWLR7tGPsIdd7PKwVtKQuNwjjeDZeUHqZZ1xeXXUAaLbLTZw==
X-Received: by 2002:a81:1a4e:: with SMTP id a75mr68417502ywa.310.1564475933718;
        Tue, 30 Jul 2019 01:38:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:a087:: with SMTP id x129ls9602140ywg.14.gmail; Tue, 30
 Jul 2019 01:38:53 -0700 (PDT)
X-Received: by 2002:a0d:dbc8:: with SMTP id d191mr73572636ywe.483.1564475933417;
        Tue, 30 Jul 2019 01:38:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1564475933; cv=none;
        d=google.com; s=arc-20160816;
        b=Bao1pfbOdNQ6qg7OSbtoOF90Wg7k1xGdRHTAySMkJHaFEEAf9MUshug+DF5r0Cl/k7
         gRAe1uqx0jB5UmS8E2NYRE/kYkRfl/8n1KriPamXpBQCbBIm2ZwTpQR6qsPR+c/ee4/A
         s5pEb1CESMaXf9n/N38YmUaVEkjCcwBfsAqKZQY6kDo8lNhKQbh922ocqKRRK31S9mNm
         YCh40w++Pb+tAkiytpjx6l+RXfQi7tvnwPrM80I9SpIFbdFQv3SS7onS/VyIvtWFSJe3
         m4Nlt0NF3acFG/Bb+BbkF2UI9LM7qeOsi379V0dyWLaxHbfBRhfVMKysex5qJ0FMkCWd
         HJ5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=xAWml8zHr+RR4WtcfJXF5qLyW4vcoY8hdC2IB6AOcOc=;
        b=i3iA7IGYTOIDdWHpc9SFoqWkaoG2blUUuBqgRr+EOUE2RbpBGu+WwAy8sMAeG2mKV5
         WW4WuKJKzD2jjIhGATDN4+dHnoVdHioII3U7T/bn77JPsuf4rUH5hoLDECXnVeTiMXIL
         ajOoHSvqycwF00FHDOu5MoZAH/2nib1j69xXh4+b1M2xreA1B4qej256m0oXRXMgKpyv
         koGbhhBHDZMIY5W6jmyPRQ+wiMvBV4L1nV/HTxUxT19Wv19hwOAFWa8RVd36Z5TRFw4y
         J8LJAE3S3ZD0dD+D55pylcqoRJ5JHRiEsXUlnerjFhn9syc9uZUXPJFambMlh+WbT8Ef
         5TZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=fBVA+CF5;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x444.google.com (mail-pf1-x444.google.com. [2607:f8b0:4864:20::444])
        by gmr-mx.google.com with ESMTPS id x5si1696042ybn.2.2019.07.30.01.38.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 30 Jul 2019 01:38:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as permitted sender) client-ip=2607:f8b0:4864:20::444;
Received: by mail-pf1-x444.google.com with SMTP id p184so29454662pfp.7
        for <kasan-dev@googlegroups.com>; Tue, 30 Jul 2019 01:38:53 -0700 (PDT)
X-Received: by 2002:a17:90a:17c4:: with SMTP id q62mr117904140pja.104.1564475932272;
        Tue, 30 Jul 2019 01:38:52 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id q126sm70680998pfq.123.2019.07.30.01.38.50
        (version=TLS1_3 cipher=AEAD-AES256-GCM-SHA384 bits=256/256);
        Tue, 30 Jul 2019 01:38:51 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Mark Rutland <mark.rutland@arm.com>
Cc: kasan-dev@googlegroups.com, linux-mm@kvack.org, x86@kernel.org, aryabinin@virtuozzo.com, glider@google.com, luto@kernel.org, linux-kernel@vger.kernel.org, dvyukov@google.com
Subject: Re: [PATCH v2 1/3] kasan: support backing vmalloc space with real shadow memory
In-Reply-To: <20190729154426.GA51922@lakrids.cambridge.arm.com>
References: <20190729142108.23343-1-dja@axtens.net> <20190729142108.23343-2-dja@axtens.net> <20190729154426.GA51922@lakrids.cambridge.arm.com>
Date: Tue, 30 Jul 2019 18:38:47 +1000
Message-ID: <877e7zhq7c.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=fBVA+CF5;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::444 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Hi Mark,

Thanks for your email - I'm very new to mm stuff and the feedback is
very helpful.

>> +#ifndef CONFIG_KASAN_VMALLOC
>>  int kasan_module_alloc(void *addr, size_t size)
>>  {
>>  	void *ret;
>> @@ -603,6 +604,7 @@ void kasan_free_shadow(const struct vm_struct *vm)
>>  	if (vm->flags & VM_KASAN)
>>  		vfree(kasan_mem_to_shadow(vm->addr));
>>  }
>> +#endif
>
> IIUC we can drop MODULE_ALIGN back to PAGE_SIZE in this case, too.

Yes, done.

>>  core_initcall(kasan_memhotplug_init);
>>  #endif
>> +
>> +#ifdef CONFIG_KASAN_VMALLOC
>> +void kasan_cover_vmalloc(unsigned long requested_size, struct vm_struct *area)
>
> Nit: I think it would be more consistent to call this
> kasan_populate_vmalloc().
>

Absolutely. I didn't love the name but just didn't 'click' that populate
would be a better verb.

>> +{
>> +	unsigned long shadow_alloc_start, shadow_alloc_end;
>> +	unsigned long addr;
>> +	unsigned long backing;
>> +	pgd_t *pgdp;
>> +	p4d_t *p4dp;
>> +	pud_t *pudp;
>> +	pmd_t *pmdp;
>> +	pte_t *ptep;
>> +	pte_t backing_pte;
>
> Nit: I think it would be preferable to use 'page' rather than 'backing',
> and 'pte' rather than 'backing_pte', since there's no otehr namespace to
> collide with here. Otherwise, using 'shadow' rather than 'backing' would
> be consistent with the existing kasan code.

Not a problem, done.

>> +	addr = shadow_alloc_start;
>> +	do {
>> +		pgdp = pgd_offset_k(addr);
>> +		p4dp = p4d_alloc(&init_mm, pgdp, addr);
>> +		pudp = pud_alloc(&init_mm, p4dp, addr);
>> +		pmdp = pmd_alloc(&init_mm, pudp, addr);
>> +		ptep = pte_alloc_kernel(pmdp, addr);
>> +
>> +		/*
>> +		 * we can validly get here if pte is not none: it means we
>> +		 * allocated this page earlier to use part of it for another
>> +		 * allocation
>> +		 */
>> +		if (pte_none(*ptep)) {
>> +			backing = __get_free_page(GFP_KERNEL);
>> +			backing_pte = pfn_pte(PFN_DOWN(__pa(backing)),
>> +					      PAGE_KERNEL);
>> +			set_pte_at(&init_mm, addr, ptep, backing_pte);
>> +		}
>
> Does anything prevent two threads from racing to allocate the same
> shadow page?
>
> AFAICT it's possible for two threads to get down to the ptep, then both
> see pte_none(*ptep)), then both try to allocate the same page.
>
> I suspect we have to take init_mm::page_table_lock when plumbing this
> in, similarly to __pte_alloc().

Good catch. I think you're right, I'll add the lock.

>> +	} while (addr += PAGE_SIZE, addr != shadow_alloc_end);
>> +
>> +	kasan_unpoison_shadow(area->addr, requested_size);
>> +	requested_size = round_up(requested_size, KASAN_SHADOW_SCALE_SIZE);
>> +	kasan_poison_shadow(area->addr + requested_size,
>> +			    area->size - requested_size,
>> +			    KASAN_VMALLOC_INVALID);
>
> IIUC, this could leave the final portion of an allocated page
> unpoisoned.
>
> I think it might make more sense to poison each page when it's
> allocated, then plumb it into the page tables, then unpoison the object.
>
> That way, we can rely on any shadow allocated by another thread having
> been initialized to KASAN_VMALLOC_INVALID, and only need mutual
> exclusion when allocating the shadow, rather than when poisoning
> objects.

Yes, that makes sense, will do.

Thanks again,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/877e7zhq7c.fsf%40dja-thinkpad.axtens.net.
