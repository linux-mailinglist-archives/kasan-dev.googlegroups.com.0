Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBIGMUWAAMGQES44Z7QY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 262BE2FE8CD
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 12:31:47 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id z20sf860340ooe.13
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 03:31:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611228706; cv=pass;
        d=google.com; s=arc-20160816;
        b=F+x22Er7mSfykk8/UJHSv8WNUZqBzXa7YJ5c26qQDW0+7/WVl2k1Varg8jMKQy2Umu
         9SGV0OSUfmhJ4g0Gy6SqsgEnGwa5GWAFb2jrbWyl09HhUcuttMMhJXuxQpCw+zvib7vr
         QCMKYLZ8LEaLSz5Rt2pWsRIy211MEpTO5n+1YIgHk9T1cK2YhCjc2UBiTCIuxqPFsk1Y
         HjaY5zdkgOCi5lxvRpGkZZ4TMFGJ03EGOyQJWH5cQQynZI43M2Shi5fnExy0kHAxCR5e
         Fuknx21dNrGkdop1nf8CS0yNgxg8cPaFeygVOvOD3317tSQukOOSssiLeF/sJJI/Rjv9
         mqtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=/uaZhx1l6RwfeyVPOuXA1+BoBeo7ofSpjeC0iq8Kxao=;
        b=OajEQXOb548pGZ8PwI5/SxgWmGI2zgbZQ2wF39FjWOSu/0qNu47kHG9pax7L7eKWk4
         /DYce7nEGW/OD96S/4xezZ272KMVazDf5wqabMZbWcTVQ2FO/CIl5Btbo/QF4ftWBfzp
         vTLCkn25IOS1JY8GX82DNZAd2cBTv/LH/oN0GdIdd4DPH4pWjZBWjKq2sOdN0r2C78T5
         nB0hIgcbqZu60AkDcS44Mr6he7tQdW2H7ctcI0kYuVtSO6ijsTR62EQIhaGjFjAfbqpP
         n5CwGO1ZyqxvWtyQjlv4YB+xZNZJe2JpKo8j2xOHkeMH9fM0FncIvC6jPnVJDgaZt2zt
         9MPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/uaZhx1l6RwfeyVPOuXA1+BoBeo7ofSpjeC0iq8Kxao=;
        b=CSBSCz7hwSdbpgmui04SYhetI4fMMS3AbhP+Vedvc8HyEntnbvkPcLxRuKkYLmhqha
         npNniAKlhY5AwvLrufRhmq4Rf8SQPX8qHZrBizzXilNQMHCPSgHNzxlPCIcC0cA2cajl
         q4Z+VVD0u7XiqE4bjkLJKR38aDQfJ16jc8G9ntdesXRcGewZealV1mInIG6BEj0sOELe
         ePw+eM3/ecQ4sQc9yF5EXXXIGryfQPZJlsIlCJBvO+hMhFgc57qCTKP2MzsgpPCs3QOW
         CYZV7gPVCUKJeQycm52+EP5VXPv+uVS4+vs29DWv9bQXWCXpgBR5KreN2kw5WnE6ajo+
         F7CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=/uaZhx1l6RwfeyVPOuXA1+BoBeo7ofSpjeC0iq8Kxao=;
        b=YMpIkjxKqEMh3V/UEHvT6NTNnTZXxYXnszKVTN+rqlZXwOGTiX3+WQ7F+31BOk9xFJ
         dYcDRHDSMbVJHFJiu2ZmPCLcMdkie3XVNDpC6VVA0uofDkZAAsN3IzLY29CcOA1QZUaP
         X5D/bD7PoC9Ij2gKvmbIiTcJJtqxquzuY4nJrvi1OIn2uqAeKByATFpPTun/+P4zY8AE
         M9LVBZD2i+4laKR+brKmc/hhGhN1NQtkFG0x992mowHT6z/7G2bv8CGu17WVMpkzYUiP
         v3LiGcK6/6SypRe/XU7+zsNS8fVfaVbl03vgrztKPkb1smREPP08GyP8O/mdAsaA8n31
         7T3w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530BwJPsju8RjPHIdUnfuMdwpCHgPi2O4bWdxBW18b9sII+kGLfa
	rHekfrvoFXsGyP35g0MLF+0=
X-Google-Smtp-Source: ABdhPJxEQWI5/Uxm6Suof6UXsVQWDCAhK7cS9jG9HQsfvrCk2x72pUge9AozUYmqcvp2N5SttsgUFw==
X-Received: by 2002:aca:d80a:: with SMTP id p10mr108909oig.118.1611228705076;
        Thu, 21 Jan 2021 03:31:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e88c:: with SMTP id g12ls120153ooe.1.gmail; Thu, 21 Jan
 2021 03:31:43 -0800 (PST)
X-Received: by 2002:a4a:520f:: with SMTP id d15mr9065462oob.29.1611228703860;
        Thu, 21 Jan 2021 03:31:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611228703; cv=none;
        d=google.com; s=arc-20160816;
        b=spH8KaKfhKpEX5srgZNkYF3RT9CGxbtKw/+YNfJHcG+tRib3phDkkgmx1gfD9FSgJJ
         OjfZJl3Ko9119nGZc+4dviJOS22yKMeJj6nThmbnMDoKDyUdV6oSMrbuUTuLtFd0rCKg
         WM5PRx0Sn8ApycnozwFKQ6D0WGsZWIEF8DzXsbhqVpXLxkb0vhRMiT/wra2oRqlsb7Iz
         ShZUi57C16R8IMEWXoHT03UwmG8RWo5QweEd5u5dmcAg5Q8Anm+FK+M6xTHn2M5cQ8Ba
         BSJrfZSnQx3TpNOx/LcmRRvknPqQMq1dQUoWi8VheiKzGTKIwoYAifnkAyp9wAN2ASJ+
         K/tw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=24bPT1jsqaE9Y6a7TKY6wJ7XXTQbm2roMN4AZZgzagQ=;
        b=AgKsJ5Mty/ENk/aB0hK0QZrWUmLx+iMUOhaFoTQ/aKz4v16n8tr6OGKNtHyzm1gF9S
         kSlsn+AxbqolFZW9XYxzs4zPqGpOXIc3DyI8NpjnMzJNTfM3I8CWClMgcVLG1zym1k3H
         Tr+vBfgh+eIbPe1R0LcxiLFejwxm9O3dSjb4eLJNqfW5DWxY7KrhGz5vDuvG222VSLF4
         SKbah17sligXfinQhPB9ercpEWDyBa9J+ykj7zQqpzsHMCpnGwBPXpS1LgrFaxG3gjyK
         6CVPyuDzg8IO7691g+SVF6amiwwPydsI2sBkzxSesw5v+3SkK4YuC9hDFcYgIgG3xfKm
         9R2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e6si65742oie.2.2021.01.21.03.31.43
        for <kasan-dev@googlegroups.com>;
        Thu, 21 Jan 2021 03:31:43 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 795BD11B3;
	Thu, 21 Jan 2021 03:31:43 -0800 (PST)
Received: from [10.37.8.32] (unknown [10.37.8.32])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8ABC03F719;
	Thu, 21 Jan 2021 03:31:41 -0800 (PST)
Subject: Re: [PATCH v4 0/5] arm64: ARMv8.5-A: MTE: Add async mode support
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <CAAeHK+xmmTs+T9WNagj0_f3yxT-juSiCDH+wjS-4J3vUviTFsQ@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <ed20df73-486d-db11-a1b9-4006a3a638a2@arm.com>
Date: Thu, 21 Jan 2021 11:35:32 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CAAeHK+xmmTs+T9WNagj0_f3yxT-juSiCDH+wjS-4J3vUviTFsQ@mail.gmail.com>
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

On 1/19/21 6:09 PM, Andrey Konovalov wrote:
> Hi Vincenzo,
> 
> This change has multiple conflicts with the KASAN testing patches that
> are currently in the mm tree. If Andrew decides to send all of them
> during RC, then this should be good to go through arm64. Otherwise, I
> guess this will need to go through mm as well. So you probably need to
> rebase this on top of those patches in any case.
> 

Could you please let me know on which tree do you want me to rebase my patches?
I almost completed the requested changes.

Thank you!

> Thanks!

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ed20df73-486d-db11-a1b9-4006a3a638a2%40arm.com.
