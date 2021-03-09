Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBNMRTWBAMGQEC4KERYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 0B387332290
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Mar 2021 11:06:47 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 38sf8909840otx.19
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 02:06:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615284406; cv=pass;
        d=google.com; s=arc-20160816;
        b=FiKUTAdkCCG3IXs18Gj8SZBL26P8bIVMpuiMns93IdmHFBv+oCu6qLElXIjxCDm82c
         DDicedCYLEed+zQTtzo0nFSe5GSGfh0qR/mMLGD0fpu44ZMG4hdZMn7VS6U4+tF3HrgY
         kgs+NLT6xwM9KqOi2057E4oHsDBUjDe/adlWqJEIDjHv3aO8aabSSE3uBibks5xguP8f
         5B7hHWiVXf/h3bfHRIkIDu/rT1BmJ1NN9UY89gNBvvFy9Ma3w2tzKDu2BLxI+nlGFy+Q
         CTt//Ww0aaB3bnx26qClM3iWacNcQAkRwb9B02njNa2r3nSCDvfe4TbHpEBeG3HE+0pZ
         9ipA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=50a66koI9BVSjXIDSeao5Iqw3jE6pSXTAxccuam1RXM=;
        b=hG1o1vXbQRy74nj15iXZ15ZwYIjBg5K3+xthPKHFlVc+Q8Jx7HHX1NEWtxDa6T6zeO
         Aolin1D13WPwVdBNkFjDW1Qj4jaQGhR0rUP15tGIz942GbM1rgBhhB9G8s3BViCKNs7t
         i6ZYEJSPShR+l7vIgB9X5IYpFSAUaGw1aGN0jcEGdTPs2tX8VLds4UWvB2oAen1YBxWL
         nuvhBae78T8gEky+OMgyq8eCdZJnOpZWsw6prcuGnnhREWxArnLEmf4EEm5zMV82k7Fm
         KfKssD7gyyrN0s3eeGYFeqjO7ATnYEDI5b0lcLPIocZaU/0e7/Nz358LgcE95x9TCOWm
         qgwA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=50a66koI9BVSjXIDSeao5Iqw3jE6pSXTAxccuam1RXM=;
        b=KoRzxy9r2gUzQCI2buV+tJlqzGn72XBc09kp+2wB/cxHuGmuZyp92BLinmqiA8qa5w
         feEMygDXZZzZknLIduTp+QMkr5pU5wlbxYU/ze5JHAvo0WOsj4qAbpCAM6sB4qVuRTSX
         dsIgVXpVCSf63n+xnDQPcdtK2pEX9snyF5ooBL/SAr2vOy+Vg2TxowYl1MZ2I+VMd1Fk
         pNNwTe8MCnnUfpi6VVYd6Tv4Kt8pH9jVNEsP7xYapaCMZdB+Lr/tdVppTRZCId8BGPzj
         2JI0jFF+gs6iIIWJQUhDf+qjMLDdCn4xM5jr0DMcIQMRAmqfb//3+csF6Cr1pwX9mb60
         S1DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=50a66koI9BVSjXIDSeao5Iqw3jE6pSXTAxccuam1RXM=;
        b=DR2HnBlvJ/EO/s/GdjrP+ns+ozdjpiBdrKVObVLX2Pt00SsS7vPBvyZ1IQPgKji3s1
         Wwjs9+C/gAuNFnv11VGxHKiXeXHdC4SrkpJ5XbSPVwfI0nwRf00E0pRav/QfBVq1nSf7
         HNsCT5B9C/md0HUfIPUDpkJdra2FPTx6F1I8KmbjONTVLMBb20h9CQ6usyer4nDChjvK
         C0U3FJJke3Kgvr9zZhHMUdbwa2vWZsisS9jqJXfXdWkN4hZlYiIvH2bopnJSdrGLLo2T
         XBcZqmnTc2Myhkqv9fDx8M2WeOg1gx1JpgL26MdRT0bU+f4FSRckppDCd8uzV8ekE0mA
         EU3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM53333fwWfrPgOsc60WAKhOduyhwaaN3D5HBeZcZIhjQtVr38hCCr
	nCSNgQVRNgsD1VXSs92o6lw=
X-Google-Smtp-Source: ABdhPJzNaQXqwnE8HGeJ7NhYIwpBmB/I2COwObN6J+jaTvwX1CpdwoymfwQR6qf9o+4WTE5sppM8WQ==
X-Received: by 2002:aca:3dd7:: with SMTP id k206mr2387382oia.10.1615284405810;
        Tue, 09 Mar 2021 02:06:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:12f2:: with SMTP id g105ls262757otg.6.gmail; Tue, 09 Mar
 2021 02:06:45 -0800 (PST)
X-Received: by 2002:a05:6830:199:: with SMTP id q25mr24007863ota.275.1615284405471;
        Tue, 09 Mar 2021 02:06:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615284405; cv=none;
        d=google.com; s=arc-20160816;
        b=t2JNI0Hajf6HRl+X3656NxKznwXYbTQaoh5wVb4+AWuJgVNZLstLsTV0k9KEkGV0BN
         6Sghr7xYXG55m+/f16429FIdDpTVomDF7D59kZr73HGmWxl4njMGDd6xKf69tpU8aIDO
         0kws5Dy7ShDZCyf6seCmH9Ku4G4VGuc2eWbshPPD8gfFMbOQS4aiSBOqgQF95+enY+5A
         sEvBnuhxedANhyzL5OMOYFGme/jV+Nv4qiWoP6cRz+rI7S55GmG8F+aBI7ZX9iKABOnn
         NsVYjcgB67vDwO5DnVtOPZRDPFUWw6yJF+vt28tGGw5t4XQmQm+6NRgSAZGokv+Ykkn6
         1E6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=sjtstUgGoBd8qn9j1eDf6FKS6VSfnxoU4LFFAAArSVo=;
        b=gyhfEySCB3x7WoKsNVnPCJy/VIZBV2S1xeNYulKSFOSRpln/6b3IUmWjL6WGT8qArU
         OTzIr/T69ZLkdWlIiyDxqP0nbOmHwEvw8dC+5/2lNfplRAmMeSlozDhPJG45KKhwrqb8
         lJeZok9tYDjsBvSuYolGBcyu5IRyOQiyfwbKNJsmpCJxUOgMknYDRI5laBMYCiBKBrWn
         wEf0ou0Gc+PjwZhnynQyyKgRDkjwGCIoV3UqXWqDLVbZB6cuElacVuSaAa+nN1ccBDZl
         5HM+wI4qr5RtkluSs7ocyxtG50mVqQfsrnbBSLzFfsVVzOcslIArUTPZs8GHxi4CKPWM
         Zi+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id f20si490789oiw.1.2021.03.09.02.06.45
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Mar 2021 02:06:45 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 3167B31B;
	Tue,  9 Mar 2021 02:06:45 -0800 (PST)
Received: from [10.37.8.8] (unknown [10.37.8.8])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 9EFC73F71B;
	Tue,  9 Mar 2021 02:06:42 -0800 (PST)
Subject: Re: [PATCH v14 0/8] arm64: ARMv8.5-A: MTE: Add async mode support
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
References: <20210308161434.33424-1-vincenzo.frascino@arm.com>
 <CAAeHK+xEc8spQWh9Mz7z-mVQRavD2y84ufnGx6cm-gK3AkJfAw@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <723ec86a-75be-e0e3-e4a9-b3d40d69e238@arm.com>
Date: Tue, 9 Mar 2021 10:11:07 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xEc8spQWh9Mz7z-mVQRavD2y84ufnGx6cm-gK3AkJfAw@mail.gmail.com>
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

Hi Andrey,

On 3/8/21 9:02 PM, Andrey Konovalov wrote:
> On Mon, Mar 8, 2021 at 5:14 PM Vincenzo Frascino
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
>> [1] https://git.gitlab.arm.com/linux-arm/linux-vf.git mte/v12.async.akpm
> 
> Hi Vincenzo,
> 
> As previously discussed, here's the tree with tests support added to
> this series:
> 
> https://github.com/xairy/linux/tree/vf-v12.async.akpm-tests
> 
> Please take a look at the last two patches. Feel free to include them
> into v15 if they look good.
> 
> Thanks!
> 

Thank you for this. I will definitely have a look and include them.
Based on the review process, I am planning to have another version early next week.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/723ec86a-75be-e0e3-e4a9-b3d40d69e238%40arm.com.
