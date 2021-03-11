Return-Path: <kasan-dev+bncBCSPV64IYUKBBQ54VCBAMGQEIE362GQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-f59.google.com (mail-lf1-f59.google.com [209.85.167.59])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E439337439
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 14:42:28 +0100 (CET)
Received: by mail-lf1-f59.google.com with SMTP id j15sf6797862lfe.2
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 05:42:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615470147; cv=pass;
        d=google.com; s=arc-20160816;
        b=iWJNUkOP0XYwH2UqYqX16yv+dfpwOxWmfEr2tGDOiFFg2AYgn+Vfk+XhQe9DDZLnKE
         sgFJKwU8WvOr84cf50C1/W1cuVPYT49L4kNnDZlops6Ur/yJmYqVy0fo81NM80pPeD3B
         P7amb4Ro4wQ9UV9qzkX+J3vAMPL5Qu0Iq9z9svNkd7rVQ3sq2qXtX31alHSBl8Ra1XCz
         HqOG/ZtIAdIUbNc1MMUjHqZpjqN1CykWBvL3Srkxc5KBLp3u2wNLxHJNvOilRQ0RK80o
         m1pAFI4urONQBlAWoj3WCar8N7XppXc4/SPL/gvw6oOKCQFr5ccpL+abttlVC1wEF/tf
         G2Bw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=54+NufqOCavdSdiLxGIQ3PwWe9gSE2t26ESxngWIZ3k=;
        b=KZfJCZTquLfixu5TLPRI3m5vhttH7rPOgTD4kMLQcR5j8SHa3QvC3HHE8dMvsWn0nA
         OCFlIK9JEzRry7k62isJi2heIg/uyycYnsNwmAm8rCBvMLCDCWMv+EdeGRSEXBxQQtYp
         pH695mA1t7s6FTmcQbIwxi0zB1P7vKJXyBDwdr2pX5UYaT6RItz2n9XUCDmpoVgnbZJE
         egCsTdqMNmDvExOhg123Gd/hHNPVJZ4S3ykSWmf1aFnDl0JOt23VFQcAbmrDMiIY2JJ3
         PZF/oSccYymMrMzgwFf60z+m6TTfhqfa/t0vaG5Fu3GJVcDDyATMqHl+Uae77IHbbCDI
         hYow==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=MLs3ACF2;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent:sender
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=54+NufqOCavdSdiLxGIQ3PwWe9gSE2t26ESxngWIZ3k=;
        b=WMtVuIutLYlck8u8mS8rMx+L0y47e5Zcs0fuPNPlB1sRrVmT98Fqo8gmwYHYGHiFGT
         iCGTv7OQVvgAlOO5W7vSRy79zxARDIezAyjnCvxBYKKOySV58PnipaZKdL7VOOIPSW9h
         5NPjFegOjECrpoEHm6892pGgzaa1glxlQdVsvyyFVHU+7HrTuXlvqpqSBG+G1vr7YQ1L
         wsUZAc4Wdb338Bj05w9mAwTrUclZmiG2xBls2/LbrgclfssWBzrnd7jXP2h4lrT3gSLN
         9zQttJdJE69/aqs1IswcFOB4ndSbFZiiNt1rT66FcYzfh2SxSPwKVUdjprm9S8s0d5D3
         zSFQ==
X-Gm-Message-State: AOAM531MsAys3zBJ+RKrnuq1/oI21cavVSinBkw5sWFTx7HGRPNQ1Y2D
	ZfiGOEyu4jIc8lEw5bafoaU=
X-Google-Smtp-Source: ABdhPJwAjbFIxuKUnV1ENI8XQ4G+dRz0/yv1Iue6IxFzstIe/AqmP75bTmy9RDbvCL+xdm83RS9P3A==
X-Received: by 2002:a05:6512:969:: with SMTP id v9mr2394766lft.466.1615470147752;
        Thu, 11 Mar 2021 05:42:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc11:: with SMTP id b17ls1272241ljf.7.gmail; Thu, 11 Mar
 2021 05:42:26 -0800 (PST)
X-Received: by 2002:a05:651c:110a:: with SMTP id d10mr5092366ljo.307.1615470146775;
        Thu, 11 Mar 2021 05:42:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615470146; cv=none;
        d=google.com; s=arc-20160816;
        b=U3s9wqYGKQeRZuJyS6FP3/9nooJOb1eFuhVlW+fSoZySdeW5vlYruHoVj4PplLGIiZ
         +0Y6AhVlmyOOnV1CO2laEm1GJoadyBcmgJ0VvL37C5Bt0URc7IH5YPLeOCBcbj0NgiMl
         Y+TfMvRqL7S5W2ibU6BbQ92p2w5gSmihZhShzwx/LVYm3hEe0vnqi6hrLAyq0SVZymDs
         OKLZYNQyrDBmw0bU866LMCm0a6qgptqMduyng6hsIWZkQW5wJtPoneP6rIukdh5UiDbs
         g2pcRgxiizXprmJeYDotHgtiiApI2ithWAbIje8l8IWwqKmYwRpdNlWrYKa4+pZsyxRr
         j5aQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:user-agent:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:dkim-signature;
        bh=F1xbrVo6JZE4cjC+AqQd5ETB1wPDIYvemAB+1nPv1Z4=;
        b=o5re+xlICerKFKLIZKS8CmINGn20g60ZKbQbKtP9CDwr8Sby7uH5iNk6mGgVJa2brv
         Ww77GQa+uoNPzm0g0fBxtciWNK3kOCJZTCGCxVFTniQ84Y9DG4iM/y5kKHVOLZ/Snbdg
         gSYff9jr39xEeeDKdIctgnzsoRk2rTYHvaDphEuRF+JcImDvzHByD5Jz8sWId4Qr9qBO
         8UnqYRVtspM16MBUAYMKheApsxmHKn+K2ZXw8YaaT1G0qSqveWC17DEiUFyt+osfwCTn
         roSnL9xyELc6Kr3ZBBEJ1PreoMZovbxcqQsth8L79p7aDtY8FN2TQTQwZ9WKBY4vEqpP
         lGKg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass (test mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=MLs3ACF2;
       spf=pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
Received: from pandora.armlinux.org.uk (pandora.armlinux.org.uk. [2001:4d48:ad52:32c8:5054:ff:fe00:142])
        by gmr-mx.google.com with ESMTPS id a17si69483ljq.5.2021.03.11.05.42.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 11 Mar 2021 05:42:25 -0800 (PST)
Received-SPF: pass (google.com: best guess record for domain of linux+kasan-dev=googlegroups.com@armlinux.org.uk designates 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) client-ip=2001:4d48:ad52:32c8:5054:ff:fe00:142;
Received: from shell.armlinux.org.uk ([fd8f:7570:feb6:1:5054:ff:fe00:4ec]:50760)
	by pandora.armlinux.org.uk with esmtpsa (TLS1.3:ECDHE_RSA_AES_256_GCM_SHA384:256)
	(Exim 4.92)
	(envelope-from <linux@armlinux.org.uk>)
	id 1lKLZx-0005bT-AU; Thu, 11 Mar 2021 13:42:17 +0000
Received: from linux by shell.armlinux.org.uk with local (Exim 4.92)
	(envelope-from <linux@shell.armlinux.org.uk>)
	id 1lKLZt-0001gO-FC; Thu, 11 Mar 2021 13:42:13 +0000
Date: Thu, 11 Mar 2021 13:42:13 +0000
From: Russell King - ARM Linux admin <linux@armlinux.org.uk>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Linus Walleij <linus.walleij@linaro.org>, Arnd Bergmann <arnd@arndb.de>,
	Krzysztof Kozlowski <krzk@kernel.org>,
	syzkaller <syzkaller@googlegroups.com>,
	kasan-dev <kasan-dev@googlegroups.com>,
	Hailong Liu <liu.hailong6@zte.com.cn>,
	Linux ARM <linux-arm-kernel@lists.infradead.org>
Subject: Re: Arm + KASAN + syzbot
Message-ID: <20210311134213.GI1463@shell.armlinux.org.uk>
References: <CACT4Y+a1NnA_m3A1-=sAbimTneh8V8jRwd8KG9H1D+8uGrbOzw@mail.gmail.com>
 <20210119123659.GJ1551@shell.armlinux.org.uk>
 <CACT4Y+YwiLTLcAVN7+Jp+D9VXkdTgYNpXiHfJejTANPSOpA3+A@mail.gmail.com>
 <20210119194827.GL1551@shell.armlinux.org.uk>
 <CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com>
 <CACRpkdYtGjkpnoJgOUO-goWFUpLDWaj+xuS67mFAK14T+KO7FQ@mail.gmail.com>
 <CACT4Y+aMn74-DZdDnUWfkTyWfuBeCn_dvzurSorn5ih_YMvXPA@mail.gmail.com>
 <CACRpkdZyfphxWqqLCHtaUqwB0eY18ZvRyUq6XYEMew=HQdzHkw@mail.gmail.com>
 <20210127101911.GL1551@shell.armlinux.org.uk>
 <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+YhTGWNcZxe+W+kY4QP9m=Z8iaR5u6-hkQvjvqN4VD1Sw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
Sender: Russell King - ARM Linux admin <linux@armlinux.org.uk>
X-Original-Sender: linux@armlinux.org.uk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass (test
 mode) header.i=@armlinux.org.uk header.s=pandora-2019 header.b=MLs3ACF2;
       spf=pass (google.com: best guess record for domain of
 linux+kasan-dev=googlegroups.com@armlinux.org.uk designates
 2001:4d48:ad52:32c8:5054:ff:fe00:142 as permitted sender) smtp.mailfrom="linux+kasan-dev=googlegroups.com@armlinux.org.uk";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=armlinux.org.uk
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

On Thu, Mar 11, 2021 at 11:54:22AM +0100, Dmitry Vyukov wrote:
> The instance has KASAN disabled because Go binaries don't run on KASAN kernel:
> https://lore.kernel.org/linux-arm-kernel/CACT4Y+YdJoNTqnBSELcEbcbVsKBtJfYUc7_GSXbUQfAJN3JyRg@mail.gmail.com/

I suspect this is unlikely to change as it hasn't attracted any
interest. Someone using Go and KASAN needs to debug this... I suspect
it may be due to something being KASAN instrumented that shouldn't be.

> It also has KCOV disabled (so no coverage guidance and coverage
> reports for now) because KCOV does not fully work on arm:
> https://lore.kernel.org/linux-arm-kernel/20210119130010.GA2338@C02TD0UTHF1T.local/T/#m78fdfcc41ae831f91c93ad5dabe63f7ccfb482f0

Looking at those, they look a bit weird. First:

PC is at check_kcov_mode kernel/kcov.c:163 [inline]
PC is at __sanitizer_cov_trace_pc+0x40/0x78 kernel/kcov.c:197

Why is this duplicated?

Second:

sp : 8b4e6078  ip : 8b4e6088  fp : 8b4e6084
...
Process   (pid: 0, stack limit = 0x147f9c36)

The stack limit is definitely wrong, and it looks like the thread_info
is likely wrong too. Given the value of "sp" I wonder if the kernel
stack has overflowed and overwritten the thread_info structure at the
bottom of the kernel stack.

I've no idea what effect KCOV would have on the kernel - it's something
I've never looked at, so I don't know what changes it would impose.
At this point, as there's very little commercial interest in arm32,
there's probably little hope in getting this sorted. It may make sense
to force KCOV to be disabled for arm32.

-- 
RMK's Patch system: https://www.armlinux.org.uk/developer/patches/
FTTP is here! 40Mbps down 10Mbps up. Decent connectivity at last!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210311134213.GI1463%40shell.armlinux.org.uk.
