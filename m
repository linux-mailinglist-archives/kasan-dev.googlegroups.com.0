Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBJOCRKAQMGQEBN2LQOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id B7CB83151FF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 15:50:14 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id n2sf3453717plc.3
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 06:50:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612882213; cv=pass;
        d=google.com; s=arc-20160816;
        b=I6wWq+iS5J8UFvKSi83jGk3rm70KZdjpgNRZ4ZxWuE7ZI60PTdv2538LDPEMaIXtIH
         FiZEvHcT5NNSSxI8+1V7rk6/SCs04gtShuHj37yE424Z9ug6+bpOProd+2J8UH1qKPy7
         rC4CPtowYW5x4UyJOeH1wOd0d+ErmjvaVrTsMpBm+dZX++F/IOgdK87im5WhWq/HSdqC
         8a/UFyEw/EzFSwSAaHZZky0RefhBTlhX2czpzhg07DuFwx3I6OpcHMeUcIG3DMmAyjbD
         z4+isGAmCdVkA7LvpbglnBgyKRio57Xm0sSIXCoacSqKmSAw8zLXTLxvLycG97Bn2Liq
         56SQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=SF57UdIeFFCNvDNf1t370pp8R3JEcwCT+lJSZwF6Gtk=;
        b=zPmCdn0EF2rJjiRy8OzGudLy3zsIfPfX0aOOOiR5SFXgWvMSJqqmqgmTx8bUp3bJgq
         YHhPCuDYysgXxy/Iccv92JWPVSzttGFDIZvPfCljTboe0QM8Xf7u0tR8zgbHn1XOVjhR
         e0tnCcADreYBvU1JAUuDK1JKtVnzqzn8cIhnEn/Fsz3a/N3ZXPMwioTaycZRxaVj2jip
         JuCe4pfBEo8CgrMpiwgj5jTIprTFB3bRbuCcLtdehRTJvCbKVf8g0dZ0kyFF4PGjMOwr
         2K2uXuhgMon6J23MSLwTrF1fpqJjrB8TaOTwPSLzuIIt/ZerTvzOUHTgicrXW7L80G20
         zJHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=SF57UdIeFFCNvDNf1t370pp8R3JEcwCT+lJSZwF6Gtk=;
        b=GErMD9jbtLm0KuJ1Bm56x/8LYqLh1irjxFgT0Sv7MhDMSwvaGVkegQVxkvp9Nr4h37
         n9gGrYQWsc55wgl6kpSpbqVlydtb2h3J8cxxH52xRNOPNiVmpd1FBRZnHWyjKPRxljgv
         cHQr2DO7vd6O0BrbkM+TzSpc6Z3tDf30mcom3AhCLesd5Rdn8pDY848X4r1fxceMkbx8
         Pps6pd3sn++xEyDFSDYeZvGWP1oUI2uvuVAr9RiTUnrarvrGrKCNRPtAPE27jk1gKstV
         B37HBqh36sPpGXQfbh/eYaLa2iKXi0J3grXlKL99gNQQp2tE/j/VZKRMnCubzaQvCPo7
         UCOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=SF57UdIeFFCNvDNf1t370pp8R3JEcwCT+lJSZwF6Gtk=;
        b=tfP3PIhE02t3u7Gv75K0Ne1F+p7UyGsJsFuJfAPl+TDkFFLdK2loj6Rd7PfJLlPtsM
         361I/2AKNkRearNnWbehToX7SfE99tnyZvRKjQX6BOM8edDJMDxG9vNGyL5cy6xBr+ui
         dp841aprH34pqkuByC8kD8sn2/OQgS6svWy7rSrhqvZbWStE3BoWGjU/UMByL/FSMcBN
         7dRGv0o7f8iXqUvC2cf1JllZodNWoRU4a7viKGumSc12enEjjslYUDGVKaFEKEeZUXGT
         sRaAZaAMd9OkwEVjA+mOkmvVPZOO4txr56spXiBWmITT9S8UW6NaRXLvPn+nIK5bDENQ
         WgxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532A5+/QtEwccvtB1yfCbq9j0Q0Wxyqt1AodjibLOQtbhXOg/BVN
	l28O+zQgVZlRdf6nBt8cFGs=
X-Google-Smtp-Source: ABdhPJyLtSR6Pk1OE4urQnncvVHmbmmccpxiqJ4WJfDJOOx6qva/6LPagjG3OkRpVM1qsiOfI55NXw==
X-Received: by 2002:a65:4b89:: with SMTP id t9mr22268067pgq.211.1612882213479;
        Tue, 09 Feb 2021 06:50:13 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:a416:: with SMTP id p22ls9727276plq.3.gmail; Tue, 09
 Feb 2021 06:50:12 -0800 (PST)
X-Received: by 2002:a17:90b:4c8e:: with SMTP id my14mr4322385pjb.30.1612882212845;
        Tue, 09 Feb 2021 06:50:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612882212; cv=none;
        d=google.com; s=arc-20160816;
        b=IYRQRzLkvVW/S2ch3NF0hOx0uxzXRcxgt62gUEkHi1UVXBhZveMcMpQspHSY9fKNTF
         akcDQYWsGvbvsdlY0IPkQLi6J5P+FDFHhC8gjRrczMvyn/jEfmeFoIeGGt0GsYTGjFbi
         QWk+cQLTgiGt3PhMkmhZUDuqNO92H80dNvbYSOKs2yuOMhysN3ZdemVztoIn6AQE87hL
         0yoM4oz200RMnf3rjPixeAu95rwM9LbgAO7oEcB1bcyndSnnYWg79uKY6y6b11wJTGRh
         FMTB5Yrl8RtTncUiz1SoknzfbL0E5wGQALtjbjw2CCyKFmji5NWKudpCg4lPLI4zeH8u
         kMmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=1N2vFHFBCa+uDoq33k3f2AwtlfUt0lXYNmusjFFc+Ew=;
        b=pe6w7lylIXXXOezAq0K7b6PbgzXLMSaAgThoAqmdAbVzrw0aGbbngiuhjFcPVe4vxl
         5efRGYLyYGBPgNjyCaPaFJsTVsNf9IQI2ls8Stp56bMddQn6VKj0XL9LXSy+M0mcucQf
         uSLMCebj+GMCy+zVHw3UDAjdEP94V1jisoIjiA5dS8e5R0o4jDAF1k6ieI6eRi5mHkdx
         shzJag232hfp4ygebZGutN/B9UY+d5D4ysmRWMDpf7pZX3g21i88G9IkfGX5XO5KzXKI
         xv/BwwHC0q0PqlGe6q97XsGseOxHlgNMCwgqn6skVzjgC6AkEM/wFMY3wShGHrtA/Izo
         LbVQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id gt23si166022pjb.3.2021.02.09.06.50.12
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Feb 2021 06:50:12 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id B9B54101E;
	Tue,  9 Feb 2021 06:50:11 -0800 (PST)
Received: from [10.37.8.18] (unknown [10.37.8.18])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id C0F223F73D;
	Tue,  9 Feb 2021 06:50:09 -0800 (PST)
Subject: Re: [PATCH v12 6/7] arm64: mte: Save/Restore TFSR_EL1 during suspend
To: Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>,
 Catalin Marinas <catalin.marinas@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, Andrew Morton <akpm@linux-foundation.org>,
 Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Andrey Konovalov <andreyknvl@google.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-7-vincenzo.frascino@arm.com>
 <20210209115533.GE1435@arm.com>
 <20210209143328.GA27791@e121166-lin.cambridge.arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <2a551330-111b-4cb4-51d1-190f2c6d8493@arm.com>
Date: Tue, 9 Feb 2021 14:54:13 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210209143328.GA27791@e121166-lin.cambridge.arm.com>
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



On 2/9/21 2:33 PM, Lorenzo Pieralisi wrote:
>> Do we need a similar fix for TFSRE0_EL1? We get away with this if
>> suspend is only entered on the idle (kernel) thread but I recall we
>> could also enter suspend on behalf of a user process (I may be wrong
>> though).
> Yes, when we suspend the machine to RAM, we execute suspend on behalf
> on a userspace process (but that's only running on 1 cpu, the others
> are hotplugged out).
> 
> IIUC (and that's an if) TFSRE0_EL1 is checked on kernel entry so I don't
> think there is a need to save/restore it (just reset it on suspend
> exit).
> 
> TFSR_EL1, I don't see a point in saving/restoring it (it is a bit
> per-CPU AFAICS) either, IMO we should "check" it on suspend (if it is
> possible in that context) and reset it on resume.
> 
> I don't think though you can "check" with IRQs disabled so I suspect
> that TFSR_EL1 has to be saved/restored (which means that there is a
> black out period where we run kernel code without being able to detect
> faults but there is no solution to that other than delaying saving the
> value to just before calling into PSCI). Likewise on resume from low
> power.
> 

Ok, based on what you are saying it seems that the most viable solution here is
to save and restore TFSR_EL1. I will update my code accordingly.

> Thanks,
> Lorenzo
> 

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2a551330-111b-4cb4-51d1-190f2c6d8493%40arm.com.
