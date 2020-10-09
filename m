Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBFPGQD6AKGQEIXUS6QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 05AD4288663
	for <lists+kasan-dev@lfdr.de>; Fri,  9 Oct 2020 11:53:27 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id s14sf8336224ybl.10
        for <lists+kasan-dev@lfdr.de>; Fri, 09 Oct 2020 02:53:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602237206; cv=pass;
        d=google.com; s=arc-20160816;
        b=EWyjArlR/bvikSToxTnhFren3G4MUiPvkziVhp9YiGlGin0lmMXZDaOgQLY1kftZXj
         HrsD0bcj3FgLMTsRbQOXdDdtD61VHFEVm7hOD9XDLchDA2tZuckOQVP78vwjdIbi1Ere
         bNZBMTsREKoDkdDOtPGq3HP9U78ZIQUuyKCTToDkde13uMcNukFNy5GUbbdIo7s7LbjC
         XUR6zLw5T421lGCIfLfJZC50qYep9DP72dP8pgN1od884m51GvQzdG7iKdUQRekSEQYX
         MX8b8FaYlzMVwytzo4v/GaCX8zeHAT0smwOOcDcttHBX5TMGAbekXUyfaRYKB8bLja6Z
         F9Cg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=mg+ff519x2Qk5H6Q+Z65d59+FRtgS4v1exoATheVuA4=;
        b=vTMSUAXV2Oi4yGh5w2CmdYpmZR4cr5AvOK5IZf8eLdOddZ4DoPeEC+S+WWM4DcHt0c
         TcU1QZDPK4iKARxW2Mv79CrHgKa+JgZ/Y6k3nnDT/+12KIbPePV5lZ1dLIcTKmbSSZYt
         Mp6M/EW8ONTMbBQ3M9pgU6uDa5mmzuFE8IygSBTB8+IZ2RGMpatV7uenMfTXJ1eR5GYt
         B1bZ1/hmXp7doJKBU1n6CyNK/oIuVoaVUhIlHC9IDODPDyF27tmsiKaNApWUJaweq/hX
         DLIBo+b5FnvuhzLMy6R15AUQv3gth+kcq1e9fbWQ8fl5dldTf6fpsk8O3VST8BuID7mx
         pcUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=mg+ff519x2Qk5H6Q+Z65d59+FRtgS4v1exoATheVuA4=;
        b=IeMWb5w0xaiEIQdmreQQLYBHBOI90xrmRSOIEX6odEnLazb9tQVxociU//hq4fa4Ev
         OS566zVPBNNwyS1bo6yAlC1r/HdBKuY2jLoJKNSdfIMnsDSPEOEJ4oELd9Kszcejeyrs
         QJGE88wjYU6ju0Z7EwggiS8YhrJqWtaH5QUNTGSTdGuDKaQ6FEkPjB6YUFI1wRANSUaZ
         LKtLAjfPd/nDlFJJmlw594jsbqzPlWhUB9oonezbldNql0elfdgOMUNdc/2S7VXfOMgt
         BbNogPCuq1H6T53mKDblKHjCFLVkDklCZ1EBMVIhUDn8PvoByo3vXmD0SIF6zyv+5nXN
         Vqjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=mg+ff519x2Qk5H6Q+Z65d59+FRtgS4v1exoATheVuA4=;
        b=qiIKGKOiOCMYZovCXo30Y7xeJdpkj8Wq6vkYhx79D8IxbqnHYLXb3QVUjczWbMTqEC
         RJW5jDX6Ta66lj7OxyzshJMor2r/OrA/xtsxVG7fltZoZcBHzQNp29f03IjT5WDwG/xV
         c+RtgMa4G/CJTVN8Rry/L+ZxTKFNhy5HjzTRqhMrfdHJVgGem5ZrdkC9zxWTr1Ooufo7
         +LaUcZ6seXh+kjT6/45rKmPwEDAER3YXqwfbPTB7cDseV5KOtGhTX/p5ACau+VrJS/O/
         LuP3zRG5i/VeFK1b/SNynWHnnQ5NUY+/eQO3oISbL7FDCAI3hz9eQOyvFnDwgt+hepBm
         voQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ujeBR+SUEYtOlZekeTH9HB1oTxf09Hm74M06weXo8yTx6cMYg
	SplZqUga3camXHeXaV7uNJc=
X-Google-Smtp-Source: ABdhPJwAGVmO6TmmhWADrQzcbXBe5vUJJhc0w+fwEzqNuXttEKwn0Vz4HAxXXkN4dstnNAshqJuwZQ==
X-Received: by 2002:a25:4289:: with SMTP id p131mr17211284yba.257.1602237205753;
        Fri, 09 Oct 2020 02:53:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:2c04:: with SMTP id s4ls563147ybs.0.gmail; Fri, 09 Oct
 2020 02:53:25 -0700 (PDT)
X-Received: by 2002:a5b:ad0:: with SMTP id a16mr17154932ybr.478.1602237205284;
        Fri, 09 Oct 2020 02:53:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602237205; cv=none;
        d=google.com; s=arc-20160816;
        b=Fpt1d4GNgD6aAzXIS9mvhjBTG+1oNXFt1G68Qysk/E3WoWi/qCx7e7Tq6BA9y2yD00
         INSHhw7RYeB9mTpFVAJIQYUwvpaK+zLWf2KcODnyAjCkfnoIkej+adSwseGs7VJ+4mdI
         Z0OUVu9DgHukEGs6zkuYHWngBX3EzWzma4JiccGUj7F34NgRyBgJa/kdt8QeiWssambA
         Sd+UacWvVlevmQgWxQXIdsf78LxZvqVaxUJKeORTigIL//HQthf0HYnvrUzXa1UTWWuW
         T9oFbYu0GLOutxy0r1txIG7Tc3c9CkCz1AIx99mjmbqSOhMg+NWIvHhvjvAQ+kkhmqqB
         LHxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=Rgsagru9ZF8KEs7Qv4Usn2DLSRBsdHxb3aXiglEHlPs=;
        b=h3yQBcLJ7yKhfVKv/3jhukv8MIhsdSccn+aeBmhtRqpex1gHpW3bk1nPE9MV4XJYfQ
         VjKnQ7yfwTLLEuDcJ4WZpwjiFZSI8vCPGooG4YLzvaijuG/gVyZoOq3l+GpT/zf4PYkL
         j57cXntFNRA16a58gyuHm1PI07WBUP7VpLiFksJB42eefsh47TSN8UyzYacTwJByivHc
         9ys7c+ZxKBJAF3oraHHrlBeoMAt8Bj3ogbMvPLTiWg0yp8qtpzwpBtqI4WBfytgxZC+f
         9Tonw5C6f1KQX6vNUoi2Vl4hB6u5ZD0kuT9635sHxpRUhDAqZA/D6CK3rgEgTvkPu6Qb
         ywvw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e17si630925ybp.1.2020.10.09.02.53.25
        for <kasan-dev@googlegroups.com>;
        Fri, 09 Oct 2020 02:53:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id A9CB7D6E;
	Fri,  9 Oct 2020 02:53:24 -0700 (PDT)
Received: from [10.37.12.22] (unknown [10.37.12.22])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 45DAD3F66B;
	Fri,  9 Oct 2020 02:53:21 -0700 (PDT)
Subject: Re: [PATCH v4 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Kevin Brodsky <kevin.brodsky@arm.com>, Will Deacon <will.deacon@arm.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
 linux-kernel@vger.kernel.org
References: <cover.1601593784.git.andreyknvl@google.com>
 <1f2681fdff1aa1096df949cb8634a9be6bf4acc4.1601593784.git.andreyknvl@google.com>
 <20201002140652.GG7034@gaia> <1b2327ee-5f30-e412-7359-32a7a38b4c8d@arm.com>
 <20201009081111.GA23638@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <106f8670-3dd0-70ad-91ac-4f419585df50@arm.com>
Date: Fri, 9 Oct 2020 10:56:02 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201009081111.GA23638@gaia>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 10/9/20 9:11 AM, Catalin Marinas wrote:
> On Thu, Oct 08, 2020 at 07:24:12PM +0100, Vincenzo Frascino wrote:
>> On 10/2/20 3:06 PM, Catalin Marinas wrote:
>>> On Fri, Oct 02, 2020 at 01:10:30AM +0200, Andrey Konovalov wrote:
>>>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>>>> index 7c67ac6f08df..d1847f29f59b 100644
>>>> --- a/arch/arm64/kernel/mte.c
>>>> +++ b/arch/arm64/kernel/mte.c
>>>> @@ -23,6 +23,8 @@
>>>>  #include <asm/ptrace.h>
>>>>  #include <asm/sysreg.h>
>>>>  
>>>> +u64 gcr_kernel_excl __ro_after_init;
>>>> +
>>>>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>>>>  {
>>>>  	pte_t old_pte = READ_ONCE(*ptep);
>>>> @@ -120,6 +122,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>>>  	return ptr;
>>>>  }
>>>>  
>>>> +void mte_init_tags(u64 max_tag)
>>>> +{
>>>> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
>>>
>>> Nitpick: it's not obvious that MTE_TAG_MAX is a mask, so better write
>>> this as GENMASK(min(max_tag, MTE_TAG_MAX), 0).
>>
>> The two things do not seem equivalent because the format of the tags in KASAN is
>> 0xFF and in MTE is 0xF, hence if extract the minimum whatever is the tag passed
>> by KASAN it will always be MTE_TAG_MAX.
>>
>> To make it cleaner I propose: GENMASK(FIELD_GET(MTE_TAG_MAX, max_tag), 0);
> 
> I don't think that's any clearer since FIELD_GET still assumes that
> MTE_TAG_MAX is a mask. I think it's better to add a comment on why this
> is needed, as you explained above that the KASAN tags go to 0xff.
> 
> If you want to get rid of MTE_TAG_MAX altogether, just do a
> 
> 	max_tag &= (1 << MAX_TAG_SIZE) - 1;
> 
> before setting incl (a comment is still useful).
> 

Agree, but still think we should use FIELD_GET here since it is common language
in the kernel.

How about we get rid of MTE_TAG_MAX and we do something like:

GENMASK(FIELD_GET(MTE_TAG_MASK >> MTE_TAG_SHIFT, max_tag), 0);

Obviously with a comment ;)

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/106f8670-3dd0-70ad-91ac-4f419585df50%40arm.com.
