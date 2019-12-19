Return-Path: <kasan-dev+bncBCR5PSMFZYORBNV45XXQKGQEB3V3KMY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 986201260C8
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 12:25:43 +0100 (CET)
Received: by mail-yb1-xb37.google.com with SMTP id e11sf3714088ybn.12
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 03:25:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576754742; cv=pass;
        d=google.com; s=arc-20160816;
        b=z0dnMQi+hnW9xzSWK9MPQ0+QTTpwn9LUtX96Pec8zUDA5ZjOyP1sCz565vV/Hmmjfg
         SlRfIxkH8FujLHodkQZ48mIY2fYfj9vIa5Lt9pNT/UVHXAC4PIFf3CaPuM+ZUjanofek
         QkldhJYXVsG6NzZmcqt6A2fQswslOg5+Kj6ov667maj+6z+MuHw6E2ztXXw6dWIMOmmW
         H6yTnx9xfHyMwWI4gmWvQsC28u0ukLpnUR/d1W1oAZKmhtoew68F5GEQk6jPEtObqRDx
         bJK8jEBqlx5yj8GUnWfQkR9IiE97UX41wyO1G3gjfTTp/JVxYArdgxG21LjdxXUmadyw
         HSAg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:to:from:sender:dkim-signature;
        bh=KYUZ23H4g4w4CKyAx48cByE1ayXuekNWEXTwfCpAYIA=;
        b=cPjbtjMV8wGrfO48mH1PUFdQmmw86daKezaCKdFiMvLjKUPt2t8TNrOjtVFMBPeq9M
         wzOBT+gVUwrLw1Khdn8ytYuQqF2iCqQPe1YhI9rvM5G0xx/lU/e8fSpRXkowxvM+Rs8d
         seNtrAH0+Iz6RN9GDoOeEzbJFaMCFSQHtMieygmK3JguhogBXFtNMbPsso8hFKNif7/z
         NyfHCcIpR1OMh0VGVc23ymU9QX6WWaEi+4Cn4d0Zs6zpVL+GEOvkBoKub4obTMu1uLU3
         4cNL3s4IWXoZFEa1E/K5tcEDALZXsox/G7QUwhc5bDUSuW06eWVzqyqwwHP7Bs1HnA8U
         GD0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=P0pIMkw4;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KYUZ23H4g4w4CKyAx48cByE1ayXuekNWEXTwfCpAYIA=;
        b=eI2fgtmZHSlKa8CTgsCTTmnUf72esa1cp+5hiIeVzhScOKkt+0agVUr9jgRzkVq1Wu
         FwzE9EYfirbenExnx1P2Kd9aHN22nHSAXitGlX23zJ6sYUDlAxwjmsVwyNKrw4N62gNT
         LlP40Ap8Kt5vmQwYPCd2FtOWrU/Q8/abICjrDAkQXyF7RcV4Xs39fE9GoDR1ttFOZQs7
         MrkLEGVKk1/aagB3ebOG2UTLWt1gF5XVv+t8qcgBjFNWewuYFYLINxYbWQ1siGRX9CcF
         369QNfJ2HyXqfFt0AtNwI3nbELdkL3QrJWKmJVGh91JOAC6y7nGT+47RU+EWp+3suVtx
         Zevg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=KYUZ23H4g4w4CKyAx48cByE1ayXuekNWEXTwfCpAYIA=;
        b=GXVLh27f7Hz8syFpUzEOEXpCfEouQ6/1PCGWOcgwpuBfHyPrz4YEppZg4q4SSQbX4H
         OrsFfvFcyfOzov2Su+tyE4k198mESnfJs/GSZY2SD+rjaQShM/Fs3Uajy/aTQr8XGNK1
         fCKxBXOFM1g2Ftu5DGWGuXkbjAWBCbZ6c9sDP9OsJ6VAoQoa2mEB+yNnH3V8VzcEi1ED
         rCJDaG0idg+F6AXee4ntzeG1YJAmKE+3Zungvpu5ejGcazHkveiaYxChOpW3sKuTEmcW
         mnFaIny7kakd1w0+uVqgANTnjyAsBpfYPfoJ6s7JZ49YVrq+wZV5t269kWXrG59efpXl
         h2SQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWXk4pnb1VwWSDUB5BeN/TCQyYWFC6r0WYS4CP64W4NRredE/ZF
	EhP737k4TU1UkODm7sa3YdA=
X-Google-Smtp-Source: APXvYqz0P60A5MkvN+JBVeTFyMdCaAh72y06TenBjkD49rLtxF9fjRj4nl4/SYLdr6sbYhzFxyrSow==
X-Received: by 2002:a25:24c5:: with SMTP id k188mr6017073ybk.207.1576754742420;
        Thu, 19 Dec 2019 03:25:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d4d5:: with SMTP id m204ls801372ybf.5.gmail; Thu, 19 Dec
 2019 03:25:41 -0800 (PST)
X-Received: by 2002:a25:310b:: with SMTP id x11mr5637637ybx.467.1576754741097;
        Thu, 19 Dec 2019 03:25:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576754741; cv=none;
        d=google.com; s=arc-20160816;
        b=GShL/iDL0aTNaFAXNQ16M704AC+dj60ON98CwLOAxj715+5rdOgbtEdr7EkyeU/qkG
         I/2EelmkEvW1Mfu4NnDQYhRe4/Icd/GPE9IND2U2SncEz5jWkmL6yPHNzjc193DtfJw9
         P1ZxTi6j2uMWxLkRaUZ2aA7yl3uoYu22PZLaAy3K3lWnX6ZcPqvV8nxzxnpD9qBMA4dV
         HqtjZhveGF+H0wh9hz59/7v/CVftBkQrtyGLD7IqyjeQ9zDRDnuX+CjaJuDEKVJ6vriY
         NveYJDP8R3cVDUIyJz3VsgeT/JyqzIMLFEo4Pm8PvrD+P2iI6u4RZC5WT0U/sbQ1QDq5
         X0Qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=5NL3hw3ZipUm0x7KGXD6mjMXU8mT1W7WQy6jFvhbHQo=;
        b=Fgwc88ZL+s042Ipte4Y+b641DB14y0iASgV6HtQs/JUhR1d1lQMwcpWkM4xEcP/uTQ
         8BXrzVpWUkoUWvu632h+1ro7aSROWSC3Rcm66y3+kr4iF5RzrhCbwzDAucr+mK61iZ/t
         cUuWLL3TWo73Mj2WW9z99FPvJeF6Ikqu1jKOtcDoMi01CzGqTQIERnFGoQeQDVjzpLT/
         rhpLEUSnAt5kzHkW6j06ZpG0cZPzGHPlYkG4krTzk8eQq2YE6wEUwRwCFD46fkRRCLbB
         jKgyU71I+0VSZjB4DkDXIW/R8QMiut5u3MjxC0JHgpzgjclOH6rCHPzpILDiFkdP4IxO
         rZBA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=P0pIMkw4;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from ozlabs.org (bilbo.ozlabs.org. [203.11.71.1])
        by gmr-mx.google.com with ESMTPS id z5si292960ywg.5.2019.12.19.03.25.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 19 Dec 2019 03:25:41 -0800 (PST)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted sender) client-ip=203.11.71.1;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 47dqLP6ntkz9sPn;
	Thu, 19 Dec 2019 22:25:33 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Daniel Axtens <dja@axtens.net>, Christophe Leroy <christophe.leroy@c-s.fr>, linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Subject: Re: [PATCH v4 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
In-Reply-To: <87bls4tzjn.fsf@dja-thinkpad.axtens.net>
References: <20191219003630.31288-1-dja@axtens.net> <20191219003630.31288-5-dja@axtens.net> <c4d37067-829f-cd7d-7e94-0ec2223cce71@c-s.fr> <87bls4tzjn.fsf@dja-thinkpad.axtens.net>
Date: Thu, 19 Dec 2019 22:25:32 +1100
Message-ID: <87fthgmuab.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=P0pIMkw4;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 203.11.71.1 as permitted
 sender) smtp.mailfrom=mpe@ellerman.id.au
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

Daniel Axtens <dja@axtens.net> writes:
> Christophe Leroy <christophe.leroy@c-s.fr> writes:
>> On 12/19/2019 12:36 AM, Daniel Axtens wrote:
>>> KASAN support on Book3S is a bit tricky to get right:
...
>>> diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
>>> index 296e51c2f066..f18268cbdc33 100644
>>> --- a/arch/powerpc/include/asm/kasan.h
>>> +++ b/arch/powerpc/include/asm/kasan.h
>>> @@ -2,6 +2,9 @@
>>>   #ifndef __ASM_KASAN_H
>>>   #define __ASM_KASAN_H
>>>   
>>> +#include <asm/page.h>
>>> +#include <asm/pgtable.h>
>>
>> What do you need asm/pgtable.h for ?
>>
>> Build failure due to circular inclusion of asm/pgtable.h:
>
> I see there's a lot of ppc32 stuff, I clearly need to bite the bullet
> and get a ppc32 toolchain so I can squash these without chewing up any
> more of your time. I'll sort that out and send a new spin.

I think you run Ubuntu, in which case it should just be:

$ apt install gcc-powerpc-linux-gnu

cheers

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87fthgmuab.fsf%40mpe.ellerman.id.au.
