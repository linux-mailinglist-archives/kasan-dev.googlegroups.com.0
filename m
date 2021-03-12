Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIUCV2BAMGQEI5UJPTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 2470E339072
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:56:36 +0100 (CET)
Received: by mail-pj1-x1038.google.com with SMTP id gv10sf9198869pjb.3
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:56:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615560994; cv=pass;
        d=google.com; s=arc-20160816;
        b=uBMd4nESqVAFB3Zd1M24ZtL5rkmmHwv2lKGQoJ+etapMezpUnrS/eoCYYc3Cr3pDgU
         jf1sJEWQYyJ6IZNmQRpHBenSRFHqiWLcLuaZQqZ+WDTTCIat8rlCDII7lLHL3k/D2RXc
         xEodsYvxc3gnmxUhMRPGuo54au31MhWshqjSNYtyVZXYJFyFrBwPR/KboAvPth1DpjtJ
         wFu1PloPBUtSbXRARrMfNR8c1t9qCuen0J9iwOw3SL0JihDOVOjWbWw+EmCxTu85Zvn0
         jD2P0ifu9B4vepNXH/IMLb93uM0epOU4hI/5hbdfhLZ1L03oQiKjmOsOwMZuo55jWr0s
         k4yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=Qk3dWQvf9C51B4Nw1Zox0NHAyfbT0RZrSi6SeXWiSvE=;
        b=h4B/aU7ZuyBjoxrZoIGMoJxYFz3XPy7LvT3sz2XWbOzCd1QvISpWV2RRVOetqq7xv4
         jnk4vKF4RMaRwGWFpx/DgJTIs2C+S9DlccLYxCEon4wWvbSv3uDpAtHzsD8fH7BJEoUR
         TOzYDSz6eTOKBB6bHILMzLP+uu8GfATUqRHhlwr9z6xR4hT/jQ98lna5wHBlVCNh995t
         MCVBVAXUsZHsWCFDrdYgNeK9tq+QlrNRCeI8XCKNdlp4I6SsSiZw9NCBaF5U4qHYyGbP
         reHgeTj/fe7Kdq4C6tA0zJUT/n08KIrRzoljnf5JMG1DrRWmkvmWvukwkke/4Z+NJCDA
         0+BQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Qk3dWQvf9C51B4Nw1Zox0NHAyfbT0RZrSi6SeXWiSvE=;
        b=q2B9IrCzbKMIjxyNOJATmX7IEETEYp0e98ltpeRP0VAkvdHEkjAv83sIPQWT/Ey2j9
         NfXLDUjmwlyCgYefGzjd4mML/Am7kFBDRpZs7GiBHotwdf22P7q7+IGGs/wQGfOeqlqT
         jXfPK6+5wtfbLy2jI+CUn6guaK60uxTTCuFQK8AKG1i9gVbeKJTikzVXtGH+2NTRhvO8
         0YbGoGmcr+sYbygO6yadOfR9fJFJMJt5ydJQ1SGVpiVAVxEG2LaCOYt3QEhYTnhtjhSZ
         pZlSNeRr5lwG00cw87lR/GoVN6K6Ny+imCVFwniZ1ajoFyj2XKYFI6GwOm7wWvkBOvX0
         ArbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Qk3dWQvf9C51B4Nw1Zox0NHAyfbT0RZrSi6SeXWiSvE=;
        b=OBZ6CkLorT/KDiSsM+LjE+hL+XN4XhCYLNC96s86+0UW09J1aPLm1YxIKo8Z7KTHca
         X6UVPN2IPGYcgjbKhKYtADMFxXQgt0YCDZvk4mFPqnVKEMa8Bfb8gzxBCdXtOcA1fFyD
         K9YLYFTqwO5jOrNMkHgOlOYhj5ZSrJiAjc20wD/mFLn3uE1+TBwwwN4reoeYm++CLqFg
         WanXQOvY4ZVwO2wJAFH3J635xtC2JMIhrpYxlAiIH9BsQfCHn8I8oNzdlap1IvQdBwug
         gJOnv8ciRdyv8EJxoBD5A2PJbR4b9qrgECWSlnUswTV4pORYOGE7TbMeFPaPnzOcNb2l
         1ppQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530AKsAF+sOud1zZI8FwcS1uNBbegKeRkSwetVqzTOw2Bx+rqc0i
	bG/lrUEDbQ3dw+2sdfQh9kI=
X-Google-Smtp-Source: ABdhPJyLVhHuK4ZdzypYjH0hMPZrrOrk0qMGlMtV2osREwwlSkeElJGV9kJZ2S3h7LhR1Zd+RkrMjQ==
X-Received: by 2002:a62:7d14:0:b029:1f6:18a1:6b98 with SMTP id y20-20020a627d140000b02901f618a16b98mr12601379pfc.15.1615560994504;
        Fri, 12 Mar 2021 06:56:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls3669982pgu.6.gmail; Fri, 12 Mar
 2021 06:56:34 -0800 (PST)
X-Received: by 2002:a63:1f1e:: with SMTP id f30mr12451628pgf.141.1615560993932;
        Fri, 12 Mar 2021 06:56:33 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615560993; cv=none;
        d=google.com; s=arc-20160816;
        b=D59rnwrajRaoIY/StRo3EwC1y7eiW24N+VCAe7OQy6zHvUtBGO4M+NWcb4LGQtxiBR
         fJyCaNbnlnwVN0BL27CTvO/uFVuZd4G2O8OgwMEaOxGoKq3CteRU0J6XQj8UZbF4Fq8s
         7TMRG17gDw5dq/7pY0rH+z11bkBBd1IRXfN/0REHDC+0XF2h0rx840ZjJHbE4uU8Hf7a
         MDq+PbEvbz5bYLEWcLw4mSvO7LL11wqH0Zt21UOa4D/EqeJTsaM5t1eV/B4WEj4fG9IJ
         NB/rF5E5IzWQ6At4nBYzWyKTf66EL/a7pIWPkdEpX7Y3RAf6RWqv417dtzE3g1oZI8bh
         Q1CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=xVSsqE6gRWa9ApEv2UHvWYPkiYq2b0WVwNt0GXx+h3c=;
        b=LJIA8Yb/f7pfM0RVTCuKlwpWnSnrJBe5l8AlU9lPlI2pMl2plZbP9RlkADk+BVSWiF
         2B+z9Ap8rBl7kJln07aCBXWOWUZdyDzB10E+9zqueBaAZObDjBV6EuGVUaab6ZGvhMFh
         E2zsGKLtNn1GvmEx0s1CKwi8tBqEFnah4311zbAQrYpqcfFl0L1JaYQKPhxuvAz0V55S
         q3SdzSIOsCg4sGtqG8fnSIbVqYGHakImMECQ/jsH7TjtfdefrvIjl+RzPSRi9LdbbHdH
         scMhqvoqFKBiCmPas+dCs/xDyyaTpFA3WVP3tPbt+6MtC5WM1vDBLyBrFvjk5Jc4KVpH
         JJgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id k21si388923pfa.5.2021.03.12.06.56.33
        for <kasan-dev@googlegroups.com>;
        Fri, 12 Mar 2021 06:56:33 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 5A43D1FB;
	Fri, 12 Mar 2021 06:56:33 -0800 (PST)
Received: from [10.37.8.6] (unknown [10.37.8.6])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 5FDBB3F7D7;
	Fri, 12 Mar 2021 06:56:31 -0800 (PST)
Subject: Re: [PATCH v15 0/8] arm64: ARMv8.5-A: MTE: Add async mode support
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20210312142210.21326-1-vincenzo.frascino@arm.com>
 <CAAeHK+wFT7Z5_Jg-8afdu8=mVqTwcnZY65Cgywxbd_0ui+1BEQ@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <7e14b0ae-8aa5-549c-ef77-5f040e0d3813@arm.com>
Date: Fri, 12 Mar 2021 14:56:30 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+wFT7Z5_Jg-8afdu8=mVqTwcnZY65Cgywxbd_0ui+1BEQ@mail.gmail.com>
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



On 3/12/21 2:50 PM, Andrey Konovalov wrote:
> On Fri, Mar 12, 2021 at 3:22 PM Vincenzo Frascino
> <vincenzo.frascino@arm.com> wrote:
>>
>> This patchset implements the asynchronous mode support for ARMv8.5-A
>> Memory Tagging Extension (MTE), which is a debugging feature that allows
>> to detect with the help of the architecture the C and C++ programmatic
>> memory errors like buffer overflow, use-after-free, use-after-return, etc.
>>
>> MTE is built on top of the AArch64 v8.0 virtual address tagging TBI
>> (Top Byte Ignore) feature and allows a task to set a 4 bit tag on any
>> subset of its address space that is multiple of a 16 bytes granule. MTE
>> is based on a lock-key mechanism where the lock is the tag associated to
>> the physical memory and the key is the tag associated to the virtual
>> address.
>> When MTE is enabled and tags are set for ranges of address space of a task,
>> the PE will compare the tag related to the physical memory with the tag
>> related to the virtual address (tag check operation). Access to the memory
>> is granted only if the two tags match. In case of mismatch the PE will raise
>> an exception.
>>
>> The exception can be handled synchronously or asynchronously. When the
>> asynchronous mode is enabled:
>>   - Upon fault the PE updates the TFSR_EL1 register.
>>   - The kernel detects the change during one of the following:
>>     - Context switching
>>     - Return to user/EL0
>>     - Kernel entry from EL1
>>     - Kernel exit to EL1
>>   - If the register has been updated by the PE the kernel clears it and
>>     reports the error.
>>
>> The series is based on linux-next/akpm.
>>
>> To simplify the testing a tree with the new patches on top has been made
>> available at [1].
>>
>> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v13.async.akpm
> 
> Acked-by: Andrey Konovalov <andreyknvl@google.com>
> Tested-by: Andrey Konovalov <andreyknvl@google.com>
> 
> for the series.
> 
> Thank you, Vincenzo!
> 

Thanks to you!

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7e14b0ae-8aa5-549c-ef77-5f040e0d3813%40arm.com.
