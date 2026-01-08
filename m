Return-Path: <kasan-dev+bncBDDL3KWR4EBRBY47QDFQMGQEWNKPFDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x840.google.com (mail-qt1-x840.google.com [IPv6:2607:f8b0:4864:20::840])
	by mail.lfdr.de (Postfix) with ESMTPS id B66C7D06018
	for <lists+kasan-dev@lfdr.de>; Thu, 08 Jan 2026 21:13:24 +0100 (CET)
Received: by mail-qt1-x840.google.com with SMTP id d75a77b69052e-4ffc5f68516sf16824441cf.2
        for <lists+kasan-dev@lfdr.de>; Thu, 08 Jan 2026 12:13:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767903203; cv=pass;
        d=google.com; s=arc-20240605;
        b=KaKISX/kyeZDHRm3l1a/qHO67ADkIZg3fvkmGzOCeZsQ2V2Jyxl3rqrUxVc+M+Mu+K
         qOiT3QOlScjBr7F7ODO3pwC1Y55Kv6qMzhg/5nMY94Dw7GrVVPk7zG1rUr1UrQerZJzg
         xKtnBrJL7zDJ+rputDG5xqPwanY/nlyQmYNR7PJTJTFopxEmrIsJh/+MY/jzMzsCQE6e
         5dRD2Rcn0zOvMHUqzi9SvgVPNGawPPYKjUSS3pRlK8hYhzpDX02x73REbCXrkNtWF1UP
         a4e2buoViMqFLXKQaNS0ZLgx9uLPwTTuosFgER1KgH526890Dt5ODdsP8pjRGiLRUQi1
         P5Ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=1s3rLsleuxQYkssgXiw+Jrgb2dA7QUoB+Wgb5gDMv98=;
        fh=jiKK2BBRFgHrbXhfzJsmLMxX/3BuFat1HyzZB0MbyRc=;
        b=U4oywF43hqe3i3iNDtchtgRpY42XCJ+BwYC//BmhWz9Xoz2la5IfT085qsOnhti2u0
         ORBRBxdIcq2QLMwbqvWeXmK83o6eNpAljXYYVo4D9r1TNHOwLp2h7o8F+X1wF3Wqjfag
         pfEtiZu97FzcwwK0Q+MquLioamTrTHbrP0lMAGuTWm4IuGy/TQi9nBzVkw3FaK+99hyV
         WkPd9dRc1rX7dxUcObN9CH9F0TB1dcbcstcEKpW9D0AhKljxysQ07yAXFx2sqPjPw7Eo
         icON6onhXyyRT0b6+EJz0DctPGCQtlQhIbJlX4Le+lmvlv0zhqsEaOkF0EeMQCIHvgh3
         YjHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of catalin.marinas@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=catalin.marinas@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767903203; x=1768508003; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1s3rLsleuxQYkssgXiw+Jrgb2dA7QUoB+Wgb5gDMv98=;
        b=j8gmfwsrreacwPW4GMvF+vKnEqz4n0GWLag17fwopItDvDiWZ+Gp1huMx1lUyyWWxB
         WBuZ1gCobMx19kUDs9R7RY6950NqBPJHQeU2y99S7AnxX4ZwmJowqqHbaeT2YrEJmqyQ
         N20oxMgYUEb3o9cAGrvfeEn2gwXFXn5prCYVU57MkdNUHuuLzZ9s35dmDsgfxfo92AMw
         CfFVpPYH7OX58jamhz0UTOcPPjb6vIKvV18GsdvxnYyYH8tTCkAQcb/pgDmSpjMoU+JX
         rjl9POju1XUE2j/kW4DXSGKJVUDZ0YcMeq0Zfd5FErDVBLu+5vIqcSWLsRia5pUq5JRS
         Ny4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767903203; x=1768508003;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1s3rLsleuxQYkssgXiw+Jrgb2dA7QUoB+Wgb5gDMv98=;
        b=XAZs5FH7ixSF1mq8izllxOts/TcjI2cvpHtulnuaAlxVCLmpNTHtBmINKqV5PWu+1S
         9j/w8AHm9+GqK2udAxk7QtGee46gsCbynGdjNQFaTDiNFxXPj+iWnl+AeU/9M028KwTs
         EmrBp+UQdLU2Q0htZ7UbLuuSQyh+pOXjf23ANEGhgTq0xgsXFnsCvheePdtETcxgwPgg
         CpwYKoILINbn56K9m6xRU3DC/aFeT1ajTO8tY4zWyYidbIBDtpfgFRgQJxsxCiAjDhbB
         3CceHWEyAE7V8RtOU5KPZkDn1nDYkKcoK12Q2uKnylZ9N2zuzgG+03IJnplaTM2SyWbn
         UBVQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUEoytJu8lVQBau3h5VbadPOyB7gei7d/xqiyBY3rANGkUrMJ2gPxm01VSe22MnpyoEE8W6pg==@lfdr.de
X-Gm-Message-State: AOJu0YwcJv7wYpIWLl3YvpgGdGg2sgGjBWplpeZEVlaYdRuYr4AW7C0s
	iE8/v81c6F9TWcfqU2LfSA+ORpn8KrHtAobcO+x6drHgzvxXObyeYN/U
X-Google-Smtp-Source: AGHT+IE8dCLIf5Lq8p+wWrDLjL/NUMZUX0AJbs8PMeS4Y7XfOB8GvBCxxwiLgZDzJewBQ0XEwLzSDA==
X-Received: by 2002:a05:622a:14c8:b0:4f1:b714:5864 with SMTP id d75a77b69052e-4ffb457133bmr91208671cf.0.1767903203433;
        Thu, 08 Jan 2026 12:13:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWb8UOTI16GIK63zIAlJHW7Sp4xii2lll7uH5gVLeK95Ww=="
Received: by 2002:ac8:5e0a:0:b0:4ee:217f:a9d9 with SMTP id d75a77b69052e-4ffa70d5428ls57116291cf.0.-pod-prod-03-us;
 Thu, 08 Jan 2026 12:13:22 -0800 (PST)
X-Received: by 2002:a05:620a:2947:b0:8b2:d648:493f with SMTP id af79cd13be357-8c38941dc1amr807853185a.77.1767903202450;
        Thu, 08 Jan 2026 12:13:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767903202; cv=none;
        d=google.com; s=arc-20240605;
        b=GDRX0CgMmxGaQ5HNGRvmDABp3wn1SHvHWZZO/ZHvz1WRrL9DoqsBGOxhL6tL148rRb
         BJZstVJAnng5kTnJZD5x4tbSia3d/FlRI872nCBt/KA3ouTqxGqT5fx6hSfXhiNvkITO
         YeqLqDmZCEL5wFJOZ3PZ5E477XLx9KjdlUrgzTInStlZn8TqrPNDWa8g9Kk3iyciE7vq
         sT62VC2WB1rrsBo/sooQMKQmbNKnjC7xUkAztbeQsE9QykMwz+RjJqXbObhIjGCO0Lij
         6U/akSjnpEH67bPZKbrfcYcY0jMvH7q30k0EsqJmOkkn8vXvDMeaeVzqTnmfjmmNydWk
         l3pw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=f8byXjPG47zjjRA4gisVK79Su6Rh5yAb1mMc6R/e1dg=;
        fh=A2avVsa6UdZ9gzSVWrMLHvKzFkur4Ji19E3yTSKSePs=;
        b=K7pK7PEOzjlO7zJTupcuaNDqSNGiCJpKewdcAYrNAhlCZAJrxlCAtoN3KJzrhghf3A
         kD85jx0iPd+LTYfhcbBPfapEnQhqGkyHtzY7TLjIj2RlrA5DI7wds7r0mA9wLawB5br7
         rItXlyb/e6AVGXt6STOWTzUOugg9apR06ImBI264zN2BXFpZdCH7Up8Cixo+eysShSCL
         8MmYpwxC83QNxOwMckRuoEkxJ1mZ/8yFGFux+jT1pZ0CO6pXrsDcMcEpiLL1VF+6hxup
         iK3j+dRyas9rdOADxOAUfZMspo75hkTUE2LDeVQhVbVOcPyOoT3nG1T1xuu9+GFcm9M4
         qIJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of catalin.marinas@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=catalin.marinas@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id af79cd13be357-8c387cc0980si15861985a.4.2026.01.08.12.13.22
        for <kasan-dev@googlegroups.com>;
        Thu, 08 Jan 2026 12:13:22 -0800 (PST)
Received-SPF: pass (google.com: domain of catalin.marinas@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id EB1A8497;
	Thu,  8 Jan 2026 12:13:14 -0800 (PST)
Received: from arm.com (arrakis.cambridge.arm.com [10.1.197.46])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id DA72A3F5A1;
	Thu,  8 Jan 2026 12:13:15 -0800 (PST)
Date: Thu, 8 Jan 2026 20:13:11 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: kasan-dev@googlegroups.com, andreyknvl@gmail.com,
	Jiayuan Chen <jiayuan.chen@linux.dev>
Cc: dvyukov@google.com, vincenzo.frascino@arm.com, ryabinin.a.a@gmail.com,
	glider@google.com, linux-mm@kvack.org,
	Jiayuan Chen <jiayuan.chen@shopee.com>,
	Will Deacon <will@kernel.org>, Ryan Roberts <ryan.roberts@arm.com>,
	Dev Jain <dev.jain@arm.com>, Yang Shi <yang@os.amperecomputing.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Huang Shijie <shijie@os.amperecomputing.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	bpf@vger.kernel.org
Subject: Re: [PATCH v1] kasan,mm: fix incomplete tag reset in
 change_memory_common()
Message-ID: <176790294571.2289790.2180517635826904022.b4-ty@arm.com>
References: <20260104123532.272627-1-jiayuan.chen@linux.dev>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20260104123532.272627-1-jiayuan.chen@linux.dev>
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of catalin.marinas@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=catalin.marinas@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

(for some reason, I did not get this email, our server dropped it;
thanks to Will for telling me)

On Sun, 04 Jan 2026 20:35:27 +0800, Jiayuan Chen wrote:
> Running KASAN KUnit tests with {HW,SW}_TAGS mode triggers a fault in
> change_memory_common():
> 
>   Call trace:
>    change_memory_common+0x168/0x210 (P)
>    set_memory_ro+0x20/0x48
>    vmalloc_helpers_tags+0xe8/0x338
>    kunit_try_run_case+0x74/0x188
>    kunit_generic_run_threadfn_adapter+0x30/0x70
>    kthread+0x11c/0x200
>    ret_from_fork+0x10/0x20
>   ---[ end trace 0000000000000000 ]---
>       # vmalloc_helpers_tags: try faulted
>       not ok 67 vmalloc_helpers_tags
> 
> [...]

Applied to arm64 (for-next/fixes), thanks!

[1/1] kasan,mm: fix incomplete tag reset in change_memory_common()
      https://git.kernel.org/arm64/c/5fcd5513072b

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/176790294571.2289790.2180517635826904022.b4-ty%40arm.com.
