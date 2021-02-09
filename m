Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBK5FROAQMGQET6KYTYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 59D063155BF
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 19:21:32 +0100 (CET)
Received: by mail-pg1-x53c.google.com with SMTP id o20sf13771440pgu.16
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 10:21:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612894891; cv=pass;
        d=google.com; s=arc-20160816;
        b=NZcsG4NDGdI9+0R0Ag8KlXJ7wZfCU4IvUgllXRfrvNliSg86EnhtOtBM8HPqUAHqgf
         h4aKkOaftSLc4DvlmBbH75M34Dsz1HWpZabdcMfmEwVoSfY6M6Fa1hWTPL9dJrAamQJB
         JK8Yv0du9lxG6BuDdQ/izwbA05Q2ogOcJbKYp1MJGXBDVU02sKcqwaFc1xnhSPI9Iby4
         FbHVLS4EpgSiC9Dmvr4rZLEpWPK5c1OyFI4L8tBM0iuPDoZErtykwPeDtERMhNZQbRQR
         0N8bAa5oZ/0VOityiPdPDFW7JY4tX0+3I8gtA9HL0OKeuInnD2W5fyGXORgKfGCB6liR
         /0GA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=WbHj1atqrbUInsCM9hznJc8qAus0KZmGUdDAQv5w5go=;
        b=kJ2Jeg8qXK6/RS+/FkwN+Zn3YqF8brFUMTJYZcVEojjD4dNKtAnwbKiPa2k6GgXFyh
         YbjR09GiQvQJS+5QNQsKG/Y6PP1cJ3nlR7Ikgv3UoNZ+5lFhBDao/l7l/lILVsXa3S6+
         ozSGaMQZrl6iXW2lut+0Db1SnFT/MDehGWdgq9MqxcUua0liLLBr1T00ltOjz/Yukn4e
         c+TvCmoZcctg+2aLozwMOKdCGJ7od4wt4DMqZ8YH31I9N2PheIh4RnHxmsQVZEcRBHmv
         XeZOumAaxEmV19LCUpD39lXS7pGNFBIbSgm2SaCaB5PQL9SG61m+IXLtHDUksIJ4+Ubp
         xhbQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=WbHj1atqrbUInsCM9hznJc8qAus0KZmGUdDAQv5w5go=;
        b=CzgKYX/y8tSpHWPpDFmRJziAkbZYVPCyiTecjc8RMrduz2T+m7+tVCdO6I0BXIG74z
         s1RPykA3ujcGMzbdePlHNozRuObFjrh9bApJ87otCLjM9A6z8n8cmuHzW7u+ZbDOYRdD
         01GvgB2EtCdQ/5O8cydLTnYmiNG2/8/LiZFqySg0Xaj1K00Q6BjR/x+vq1oqoTKyRrui
         lSVI/YYjugty4HaCn8zIQaIWiXmiil7N/N5kCTFFNc9XmcJW0Fp3alvwQDme2l4CTatP
         5L5J40eoxVEpJZgbX/sbaZ6Z+hD4TIugkJtFDcatAqXHj/3Pa0s5Rj0UkReLbmszfFnR
         5t7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=WbHj1atqrbUInsCM9hznJc8qAus0KZmGUdDAQv5w5go=;
        b=J7YH+t3kNCebeQJxdHINsPIlZPGEdrrWVORdr1S92DMFMugfgsJscoT8JxCkxj2C7y
         NBsDbc/AKcqTwzWg3ND1Tv3HEniXvWNg5nJjflTHi0GB49f8dUhyfoVCTCT9QN1Sn6ak
         nxDCC0ACNhe/XBgEkxtnrX1vpkQ1oWVST8M93hL/l31S2SxJ1S+uhuyBWW2WO035A1xc
         Z6qIT+54cbQKUFhF9sGs6nVMc+nh2AcTqozREZXP5zhf7sb5kHhynYqJ/1ANZRd1Mt/s
         +aBiDgy0bsd/H57oKlt/RhXi3RUPiDPbD1fDxu1EwxCatg/qLbhiko58Ma9gxsw1YvzN
         0CHA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530YZBiHMikwhMFIBNcg5xpp1HZN6a9G9S3ay+oi0mcdOdZXwCZi
	19yan2ZphU+n6kld1iq+HtY=
X-Google-Smtp-Source: ABdhPJww8t0TZ0ZpGxgbwpImwcPGbev9oPpqwymp46SfftU1Nh4NkkDuMz1UvyzAx261arvUVmOLCQ==
X-Received: by 2002:a17:90b:1a8b:: with SMTP id ng11mr5493149pjb.160.1612894891168;
        Tue, 09 Feb 2021 10:21:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6a11:: with SMTP id m17ls8483520pgu.6.gmail; Tue, 09 Feb
 2021 10:21:30 -0800 (PST)
X-Received: by 2002:aa7:88cb:0:b029:1e4:370e:614e with SMTP id k11-20020aa788cb0000b02901e4370e614emr1942322pff.35.1612894890585;
        Tue, 09 Feb 2021 10:21:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612894890; cv=none;
        d=google.com; s=arc-20160816;
        b=tX1fMS4t2yKe6p2wrkNBZoivKtp71jlSTTx1G99kQyitlbCxyeH8iZfQbWZo2EQCcJ
         iStF341YqZVHairorLBcYfZT3/AdTaTKnjezGtp/zumS86BOOYn1XXCLMnfyEPTDCRDH
         xBzNdRYOxAuKZQU1Ju61zdqW6/Ws3XyFVcRasSKNbC/SOmDZE8DFAuZ4eYAxs39T4uw4
         pEzJ6Jl+ZEZgmgHCcd5BaMrqKvoIQS8QnVD17nOXQc4cS2G+7mWMcP+ueTXUnHQaX2px
         Jefa7xRKAWNV4dIYsxvIDpecjfw5wFUfAwKkULpesxu7c3BE8YOpg3P4u0H0jz0E6mKK
         FXOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=nfeXmfKOZsFn+6qZpEhgQwILTM90bKspEyt/Zf6dBGI=;
        b=suwSQBjfdphaLUzQLe9NtJFXUOC1pf64cOq+YSirPX3EjXlpx4VIgC0/KvOuU8ozFb
         mvXMiAnarPzZ9FU1sbr5S2rRDlRN32jVvaT/uMr/llonARTifx90UgnzkY+W9XNEETph
         tyKILoMTQzyeqBzZq7cCK3q2Ne7MoPVijKz8hnhjTINFyuVjj8ssQsX5mStkm95mI4BM
         J4yq34UPq6kSNPiktOQcaSyvXKMsogqrijEz62ddY7Sh8EYvrDq9AHAHqVPe2Rcp6E9p
         vzuzij/JUBGv6L0+C8qBvgSJ/XEsAfoPb6QKznqpwRLEh7xy1U4iFyhz/RMi+aP/SQ0O
         BvKA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id t25si641242pfg.2.2021.02.09.10.21.30
        for <kasan-dev@googlegroups.com>;
        Tue, 09 Feb 2021 10:21:30 -0800 (PST)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 8FE53113E;
	Tue,  9 Feb 2021 10:21:29 -0800 (PST)
Received: from [10.37.8.18] (unknown [10.37.8.18])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 94D513F73B;
	Tue,  9 Feb 2021 10:21:27 -0800 (PST)
Subject: Re: [PATCH v12 6/7] arm64: mte: Save/Restore TFSR_EL1 during suspend
To: Catalin Marinas <catalin.marinas@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
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
 <20210209172821.GI1435@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <89c95a1e-cfd2-7840-3175-deaeb336190b@arm.com>
Date: Tue, 9 Feb 2021 18:25:31 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20210209172821.GI1435@arm.com>
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

On 2/9/21 5:28 PM, Catalin Marinas wrote:
>> I don't think though you can "check" with IRQs disabled so I suspect
>> that TFSR_EL1 has to be saved/restored (which means that there is a
>> black out period where we run kernel code without being able to detect
>> faults but there is no solution to that other than delaying saving the
>> value to just before calling into PSCI). Likewise on resume from low
>> power.
> It depends on whether kasan_report can be called with IRQs disabled. I
> don't see why not, so if this works I'd rather just call mte_check_async
> (or whatever it's called) on the suspend path and zero the register on
> resume (mte_suspend_exit). We avoid any saving of the state.

Fine by me, I tried a quick test and can confirm that kasan_report can be
invoked with IRQ disabled.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/89c95a1e-cfd2-7840-3175-deaeb336190b%40arm.com.
