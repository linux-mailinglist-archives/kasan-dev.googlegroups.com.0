Return-Path: <kasan-dev+bncBDQ27FVWWUFRBFN4R2DQMGQEPH4IBVQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x337.google.com (mail-ot1-x337.google.com [IPv6:2607:f8b0:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 919C03BC449
	for <lists+kasan-dev@lfdr.de>; Tue,  6 Jul 2021 02:04:38 +0200 (CEST)
Received: by mail-ot1-x337.google.com with SMTP id g72-20020a9d12ce0000b0290464115c5c33sf14210632otg.10
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jul 2021 17:04:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1625529877; cv=pass;
        d=google.com; s=arc-20160816;
        b=uBTOjk16K9ZUXWzmMcP/VdWviT9PvuryrexW73RUvtwjr5+1850NH31uP5a9Ed9fcZ
         o9IMOg1oOPeNGePLmk8KZyVJYafGXS5kxoTXJvMiWIcpCFjVmpovH7piOvzxTbC3qb8t
         iG9GLvo1+k13yetlev8L3jfYMp4I6l4WzbsbD1/RIkfYSRp/m6AEKXh1Sm4347o14/ae
         Qx4x3MfYxyculDXLlRZCfj3ee+PO0aOoMCggg3CpHya2q3k7RX32/9CPachjwoFqSAYE
         oX4x+40fMQWh3ueEdGuPylHhHXHrTZKmOK+4cOJhopQcgz72h4DmIHl+Pw4v+JiItpJD
         USBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=hQmEe0AFaXYRBHoDaGyy42Y2oVFyKJokBmSZj6VdvIU=;
        b=NlhFfsj1QLDL3cEX4AhOpqhhSsRUOdHqGcxMKIbeHSdVz/c0+LKouera2ymFhDJ6hh
         fMoHQPZ7sGCJnryPD3ElFhIicjN5CeY9K7xcmnzyvZ3ZGGA00GRQS897aIbF5uReDC03
         3UfTl+CsY8aj47QMt/BihAU5jS1QtJIw0+SCtBpbEnc7IZ77w08nVjvFdD+dUu7F5BxF
         RYngYqfSSbyiwz8JZ7SxGeFjyJPtdmP2wW8r8YkalgqfkpmoLtmjdFs1OjDzOPXw8QVP
         vd+JjE+fKNE3dV57z8mSFvRhYps8sBjjd7f9ypI44SNgdW2TIx3vKtNf7OMAeBpiiB4R
         nYfw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=rDvuIPBc;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hQmEe0AFaXYRBHoDaGyy42Y2oVFyKJokBmSZj6VdvIU=;
        b=cvYRxA99sDf5hS/GM1ugoaUBSunoTxeDBnNBDyjOcaNO1mUtXD3pq/6wGcZRpzcpal
         f//EM01g3fRsudG4/9FslLAbYIUNk0IMAchpOGh4TLBlSVQhF3wd9T/dCKipNcR6V2U/
         KnBN9svpvqn2OencMs4wuGjpn1m4R0/ZMgHFkRdSdEsnTHSf51HNwwSq1z6Mx9xwi8h3
         WcYFpH/mvgDKtpPc2IpCQlUi4PYSKzpiX5WOA/V5Vss5qlZ5Qmn4nenFiJf9xyPUm1jd
         fbiUZJgR6d6UCfsyRMy1wgAMhqvnSw5XnqGqGTeyKbDGsGMeBwHG4MGqbAXd12IxW78J
         QqVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hQmEe0AFaXYRBHoDaGyy42Y2oVFyKJokBmSZj6VdvIU=;
        b=ZwQJEsfJql94pnxWLSmn+K2RU830cQ7vTFVuPd6yXx9fOCVJ/Z2JbD8ZKRdLryb63v
         jQzYnZsPeUSGh89R751B+cSl2X5EljgfJBsG32YO/OeKV67wKoqpt5Xf+0LK9eoIue1H
         5ULblUZpEPmNAzzJYW4E6aiHzM7yY5YR9rolle0SMNKaxiubkeV0PaJ003YlpGBXD1xq
         AkmbRMtDPviuwSFHTPdvJGjJ/9IcEj2UcB2Vn9RsVnh2CuXhvlHkS1krSdIP100T/ZTG
         Uiyd9xwMLB1QDz9qhV3RcsW/hH7kvQUjpVzNHJw1aQOIPCT3770ZyGy4iIObWHIIo5cV
         UrmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533QUXNHPeLEjFJVRBDrd+SlAnQroaolDXQbwRkdSTod++8vMyAx
	Hv8LuxVzmst5tImrsEhgcE0=
X-Google-Smtp-Source: ABdhPJw8S5QEXlR9OkbdiWymfQ00FsNkvFDLvSxOXK/wJmTo5YG4CDwsYlN17Ftld5M5o5br68mzsQ==
X-Received: by 2002:aca:38c1:: with SMTP id f184mr11908081oia.101.1625529877367;
        Mon, 05 Jul 2021 17:04:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:641:: with SMTP id 62ls7535568oig.0.gmail; Mon, 05 Jul
 2021 17:04:37 -0700 (PDT)
X-Received: by 2002:a54:4797:: with SMTP id o23mr1321499oic.158.1625529877014;
        Mon, 05 Jul 2021 17:04:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1625529877; cv=none;
        d=google.com; s=arc-20160816;
        b=TmOt2kBYXlvWsA/r8An8IVk23EG656IDcX8jdWDX8wCNc8GKBYBM/TmR0Nknwxq0H+
         sVzg6dijvCpogBnWHvAEKumtcLOugnf3Iee8Fwah8vXcu28lpTE3omeaeYmlHE3PR/hs
         AKGnxHAjjVyWuw95CvqV1VK5iSYCsZWqPZSPG6/LD7J5U5QP1tnnuQAolBD/o7gqRvZV
         fm0Mtbkd9dgbIbs6ci4snM7pa8UUtAnJDI/1jq8coc3+AooLXuXTG5G89epeeXfPPrD0
         C0c6tNUrbx4cJl7d6E0zwr/02VUP/lhHp6V94/BxRpsGuoSNFFsYAeFfmHirAxLJHGYe
         hjVw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=B0opPtpn0MNnkL5QbMS6eUOeWPJf+0ldaSgcF59HYA4=;
        b=j/Suw6thkVH/NuiTbbvyWDhG1ok2Nv1PNiJVS3EaA0ArctnbS8l32ZfFlgiUw2RJ6g
         PaDLvVG+NWf2DOugZ7bUFYaMDlhC9yXBfHTIiIwuleVzc85KrJ4pq9g4c7cAMHdQWEDq
         JM5tO6nugJvrwXkwhNIg71PMzY65FDGxNiQQQgsiwrK3xcthk49NyAkkfAZalibATTPb
         Wj7aUzS3I5RKQKrIXlJmEn6kDdXhWrw2Y71WykmRzVpeQ38J99uA9N7IWWrBfcdizP1Y
         A8t75qyHEs/nURwTpKzWoX7snhOIg93QorWtRyF65npPa2/49IJ7Dc9QF17fUaUup9WG
         gZug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=rDvuIPBc;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x534.google.com (mail-pg1-x534.google.com. [2607:f8b0:4864:20::534])
        by gmr-mx.google.com with ESMTPS id b9si2014260ooq.1.2021.07.05.17.04.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jul 2021 17:04:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as permitted sender) client-ip=2607:f8b0:4864:20::534;
Received: by mail-pg1-x534.google.com with SMTP id o18so19112243pgu.10
        for <kasan-dev@googlegroups.com>; Mon, 05 Jul 2021 17:04:36 -0700 (PDT)
X-Received: by 2002:a63:1d42:: with SMTP id d2mr18120359pgm.21.1625529876564;
        Mon, 05 Jul 2021 17:04:36 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id 199sm13077375pfy.203.2021.07.05.17.04.35
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Jul 2021 17:04:35 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Marco Elver <elver@google.com>, Kefeng Wang <wangkefeng.wang@huawei.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon
 <will@kernel.org>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH -next 3/3] kasan: arm64: Fix pcpu_page_first_chunk crash
 with KASAN_VMALLOC
In-Reply-To: <YOMfcE7V7lSE3N/z@elver.google.com>
References: <20210705111453.164230-1-wangkefeng.wang@huawei.com>
 <20210705111453.164230-4-wangkefeng.wang@huawei.com>
 <YOMfcE7V7lSE3N/z@elver.google.com>
Date: Tue, 06 Jul 2021 10:04:31 +1000
Message-ID: <87bl7gxq7k.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=rDvuIPBc;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::534 as
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

Hi,

Marco Elver <elver@google.com> writes:

> On Mon, Jul 05, 2021 at 07:14PM +0800, Kefeng Wang wrote:
> [...]
>> +#ifdef CONFIG_KASAN_VMALLOC
>> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
>> +						       unsigned long size)
>
> This should probably not be __weak, otherwise you now have 2 __weak
> functions.
>
>> +{
>> +	unsigned long shadow_start, shadow_end;
>> +
>> +	if (!is_vmalloc_or_module_addr(start))
>> +		return;
>> +
>> +	shadow_start = (unsigned long)kasan_mem_to_shadow(start);
>> +	shadow_start = ALIGN_DOWN(shadow_start, PAGE_SIZE);
>> +	shadow_end = (unsigned long)kasan_mem_to_shadow(start + size);
>> +	shadow_end = ALIGN(shadow_end, PAGE_SIZE);
>> +	kasan_map_populate(shadow_start, shadow_end,
>> +			   early_pfn_to_nid(virt_to_pfn(start)));
>> +}
>> +#endif
>
> This function looks quite generic -- would any of this also apply to
> other architectures? I see that ppc and sparc at least also define
> CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK.

So I checked with my latest KASAN ppc64 series and my code also breaks
in a very similar way if you boot with percpu_alloc=page. It's not
something I knew about or tested with before!

Unfortunately kasan_map_populate - despite having a very
generic-sounding name - is actually arm64 specific. I don't know if
kasan_populate_early_shadow (which is generic) would be able to fill the
role or not. If we could keep it generic that would be better.

It looks like arm64 does indeed populate the kasan_early_shadow_p{te,md..}
values, but I don't really understand what it's doing - is it possible
to use the generic kasan_populate_early_shadow on arm64?

If so, should we put the call inside of vm_area_register_early?

Kind regards,
Daniel

>
>>  void __init kasan_init(void)
>>  {
>>  	kasan_init_shadow();
>> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
>> index 5310e217bd74..79d3895b0240 100644
>> --- a/include/linux/kasan.h
>> +++ b/include/linux/kasan.h
>> @@ -49,6 +49,8 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
>>  int kasan_populate_early_shadow(const void *shadow_start,
>>  				const void *shadow_end);
>>  
>> +void kasan_populate_early_vm_area_shadow(void *start, unsigned long size);
>> +
>>  static inline void *kasan_mem_to_shadow(const void *addr)
>>  {
>>  	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
>> index cc64ed6858c6..d39577d088a1 100644
>> --- a/mm/kasan/init.c
>> +++ b/mm/kasan/init.c
>> @@ -279,6 +279,11 @@ int __ref kasan_populate_early_shadow(const void *shadow_start,
>>  	return 0;
>>  }
>>  
>> +void __init __weak kasan_populate_early_vm_area_shadow(void *start,
>> +						       unsigned long size)
>> +{
>> +}
>
> I'm just wondering if this could be a generic function, perhaps with an
> appropriate IS_ENABLED() check of a generic Kconfig option
> (CONFIG_NEED_PER_CPU_PAGE_FIRST_CHUNK ?) to short-circuit it, if it's
> not only an arm64 problem.
>
> But I haven't looked much further, so would appeal to you to either
> confirm or reject this idea.
>
> Thanks,
> -- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87bl7gxq7k.fsf%40dja-thinkpad.axtens.net.
