Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBMFR7X5QKGQEE3JJXAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 96972287B92
	for <lists+kasan-dev@lfdr.de>; Thu,  8 Oct 2020 20:21:37 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id q6sf1938266otn.4
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Oct 2020 11:21:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602181296; cv=pass;
        d=google.com; s=arc-20160816;
        b=Y3pwDd1sdarF7AtjZ9Msr+OIWFR506j7Bjutct5LkZpkPAZF6tgQQ4nD0+lflNcDij
         QhfSKugF9P7QQ5zRI+c/iFKJMZYe3tzWmoNd3rxKLa7BteujBuRsIVtcAdiBTOi8a0cC
         1/CZZdwgUWhvSc86c4jmdfapPPLLJl8j0TmnYx20hSIF2ZjPEle3Wm7d5edmROpiSYAe
         1omIGIuJblxs0XBz6Eu2sugJCMDDkdyU7oHxEXFSFdBdJL1QTTzzrj5HVMpZ5aJ1aM/1
         0eWsUu+n4RJ7NUxRztxzT0n6QJp0ljyhJ91ynDwB63prt21FbCvOpjBiWBU50XiEatPH
         tF9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=Lun/Hfa6dNnYQNGSdfZzEwsLg4Abmj8NaDEXd7gA27Q=;
        b=DIeyHVAyRhnPy8iHDYXDA4ZxlF2Ry8n/RjcKjHBErncq7HAov5GmWc1NdBdVR+mu3E
         5Iu+B2fTuNj/KvfFleYqNAU3T5jv+7Nrf7Y97/mmo/OOagpNQ/vQ9uEmqX67CkOd8KF8
         uCKKpmG5m+ZbB7PaVmtwQQGx5U+gtHnugsLmELCiSAAafcq2JVd313Blj1JO/jiG4U99
         aBkdofZSbHPCcnFXtCADgLLwzPeqlmVBfCUCg6z7Yp02hYCDZSDlQF8dAELLxwhKBEqc
         50Gz5UVUUgLCdwWyc3V7KlMyY9icBT8SAm0oH/G1RUjZJAwAPkY1/ZIP07Oj2e32ROYG
         n/Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Lun/Hfa6dNnYQNGSdfZzEwsLg4Abmj8NaDEXd7gA27Q=;
        b=W+Zj9ZsHEcIkyK8G9iV5/EeWbRm3H7+GP3B3hdx4Jxag3G8webTd/aC/T+9ufa6VTx
         gTn8ICReIYGhmDXPUVLMDNtTBDH4Fmy/AijHWU6LTiSPzfRzl/daTtsuFF85zO039lWW
         bRnyK/0T5EWhc5xk96eVLy7KU9iI1R3dRpTD6njka2FD9EmnUV3t7LNywm+ph5f8kwN+
         IZ9MVK7GHQLnvJRX317DZjFtVMWy5A5pFrSxi9VUKEoUOpEIMXiKZ9pEwLAiG8dv3/oc
         MB63MMH4vq60s+C7sgF62rn1Gi0JdJhp+juLlemAbKuzUubdhWUS1ZT7c67sXUqTvFaY
         Hs3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Lun/Hfa6dNnYQNGSdfZzEwsLg4Abmj8NaDEXd7gA27Q=;
        b=qM2hx2Fjpb1lrYpvp2O/cOf1w5yVhQIxOpOQ8n5BYg+QeiWTWIqKM5p8Vt+QgVbMxq
         OqE9Xjaafi/z0tRIrxaj0CBZ8yFmRdPwcVpAzz7Oafv5K4DaSdmm3Qc4NZUOPJLyHsga
         LqtDH+LBnz5PyQ4GXQYqxtxLxyB2/e8ObAfKcLQsmFwIngM6pqAfBMzjV+P3CZSFICGX
         TMvROWhBCV+pEhuP5tKKAC+6gGLfflUSuKK6p//QXZDOpD8JvbnJYRzssDfBuHUBFZ5M
         XpQG25TWrnbFWnt3DJAbSlRfyCCfMv9VGcQbVtxdzMGJWgyyqHf5LDEpjSabCYKM8t62
         vG9A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532SLi04ZQ2myxUX3hMJNyBuUKTnQ+9utNFHAGITpWVphGRDJISi
	IHXd6CVpyD5AKedt/8dKRq0=
X-Google-Smtp-Source: ABdhPJz8F7ZM4JIXZA1euv7zJ3tnyj4zNNslhAfmNiuoHH2KRu5Po6v0cdDpmraifOyw7JYLkVNuuw==
X-Received: by 2002:a9d:6b99:: with SMTP id b25mr2488492otq.60.1602181296247;
        Thu, 08 Oct 2020 11:21:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:85:: with SMTP id a5ls1497597oto.10.gmail; Thu, 08
 Oct 2020 11:21:35 -0700 (PDT)
X-Received: by 2002:a9d:2a8a:: with SMTP id e10mr6077995otb.3.1602181295821;
        Thu, 08 Oct 2020 11:21:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602181295; cv=none;
        d=google.com; s=arc-20160816;
        b=iOxP1w4DmbWJ8RkpWrPZsL2I5sevyNJ4otU+Rwz23mHBHIMuWZvybWizJAjTqHrW8d
         Bl1IKFUc9duy8JPBqN3msM8IYGZ7lSqaCSO/knQU5sLHysvfOPP+A1K4H3eYwktEElQH
         y6kVU0fZuEtRn8+KoD0v1Qjn4mOCQicxqDMg2bhWQp/GMOhRdVECuKcXsIRtyYH9IXwg
         wRXbbdJNmEec/Nxy0VDE7PCWS0mgwZN6KIm5dAszrRem3T/iCrSrHbvJcSxUrvG/kz9f
         uAxVHurVUJas5TcpuyGRWeVZ8U/NuObL9WQQ3TZBb+G141WlQV0rzBh52T3DcJFUp8U8
         vcig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=w88Mrj9r6i2IxyCwM62agi9k8/juhIEjZ9/d1uUi9uk=;
        b=rC0B4CzF4OGDHnTatdoLxy1M+Tr6BdbQl8os+CCsaEqUOD2WND0zlfHOnK7KOzLhE6
         K48ZOUFYUKGMtnbsS/QuT/lbMkA4xJNswwj4EM/64BBV/fxKpLHn1CxmtN5gqjvRwETU
         8S9+rsGdT2aWdvY+KN0HTHt4dX+ZLVPecKhVAhZctiItrzV4+B2W4S96j05hBTDjyULm
         jpvy04OA8fz2pO32Uh+PYhRp28GhGKU/3OVyvHV0KYZH9fDohrgRkB+9vA03NH0Y88zT
         i7UJE8O3AcI6kESGHxP8gYsjQZaxbTxIOKBywbJbAX2zh3Tpl6+ge8f3GxptobaDqwT9
         qh+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id r6si1101325oth.4.2020.10.08.11.21.35
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Oct 2020 11:21:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 91CC4D6E;
	Thu,  8 Oct 2020 11:21:35 -0700 (PDT)
Received: from [10.37.12.22] (unknown [10.37.12.22])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 2D4F63F802;
	Thu,  8 Oct 2020 11:21:31 -0700 (PDT)
Subject: Re: [PATCH v4 29/39] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
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
 <20201002140652.GG7034@gaia>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <1b2327ee-5f30-e412-7359-32a7a38b4c8d@arm.com>
Date: Thu, 8 Oct 2020 19:24:12 +0100
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20201002140652.GG7034@gaia>
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

Hi Catalin,

On 10/2/20 3:06 PM, Catalin Marinas wrote:
> On Fri, Oct 02, 2020 at 01:10:30AM +0200, Andrey Konovalov wrote:
>> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
>> index 7c67ac6f08df..d1847f29f59b 100644
>> --- a/arch/arm64/kernel/mte.c
>> +++ b/arch/arm64/kernel/mte.c
>> @@ -23,6 +23,8 @@
>>  #include <asm/ptrace.h>
>>  #include <asm/sysreg.h>
>>  
>> +u64 gcr_kernel_excl __ro_after_init;
>> +
>>  static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
>>  {
>>  	pte_t old_pte = READ_ONCE(*ptep);
>> @@ -120,6 +122,13 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
>>  	return ptr;
>>  }
>>  
>> +void mte_init_tags(u64 max_tag)
>> +{
>> +	u64 incl = GENMASK(max_tag & MTE_TAG_MAX, 0);
> 
> Nitpick: it's not obvious that MTE_TAG_MAX is a mask, so better write
> this as GENMASK(min(max_tag, MTE_TAG_MAX), 0).
> 

The two things do not seem equivalent because the format of the tags in KASAN is
0xFF and in MTE is 0xF, hence if extract the minimum whatever is the tag passed
by KASAN it will always be MTE_TAG_MAX.

To make it cleaner I propose: GENMASK(FIELD_GET(MTE_TAG_MAX, max_tag), 0);

> Otherwise it looks fine.
> 
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1b2327ee-5f30-e412-7359-32a7a38b4c8d%40arm.com.
