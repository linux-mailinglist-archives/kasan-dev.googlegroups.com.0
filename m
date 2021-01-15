Return-Path: <kasan-dev+bncBDDL3KWR4EBRBANQQ6AAMGQEPFAH4ZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B3792F8325
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:59:30 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id l22sf6876366pgc.15
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:59:30 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733569; cv=pass;
        d=google.com; s=arc-20160816;
        b=wJMSCqL20O1c7tD0GcuBW5FYBxSRTdzz0Q9vk18PNkKvaHgZv3Hr8zCdNvVU77EUKI
         xXcHIhIEvfDPjvVFJhY7syPWMJ5IBXJmNorxVsgTgrCW9K1NkuojXya9ya4lbnlyep83
         e5hUXHKD3MSoH79XCy4OwuwUZO/xREP1bHvzhESEPL4sQX6/6G1Q96HzLvO4XbuAD8gM
         yeTarbUYRBSOIBumO5PZvN21BzgqEJ3zyi9VYDQ+XulmTRIzYJGbCE5J7u6Rx6ePWzK6
         HbW332/ttul17myj7itWYdmvdNCOC3iF2V1IDI0h2DsvHVjIE4JKpk9qvk/x2Vx3RKUF
         rQyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=r7UuMKF9MkdRhxC1zpRaGf558e+JQcmyumWJmz5J7GU=;
        b=VYbcwsXWsIzYG5aFRcEdvPcb4e85GpuuT8cTGeuGkevOaqoTKQFCIyDtBp8PEGlK1+
         z4uoZe2AO1jtD1QsBWPNCJprJs49YAEeABTsoDZkfDVx86eMtr5yR31BswLEGXfY+AAO
         MSGlkRidJ0QuTXKR3RXGpy3Tc8pvAG0h1le9gW+Z4SW33/q+nk+fgK1qIrxn+s8JOXQy
         7J5PiOR7Tt9DfXKoYlcE1hbCh3fgZg7w2POL+RjXgtXgSpGoFpNdNhlPRfR0XoiLo0Z9
         0yW0QCtLsgz4/i7RSFC3Q1lK7SJvHTRktD84iUKZt4ymRUz40b5V32B7456QJKU+np9D
         pkpA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=r7UuMKF9MkdRhxC1zpRaGf558e+JQcmyumWJmz5J7GU=;
        b=e1RErdAyop310argHnq/mU7VK2Lozt/e8B6MkxbdW++dfQzDoIwESwziQ7A+CjOrVP
         oMTzXx4sxqrXK+T0mXTwoQqus/crGWvvLaM8RyDSR5lRTmP1sd/yHuOwS18N/PAgN6OM
         YsK5djcQVx5h2PUdvK4mKbmfDn4OHfSnK6GN284pHtAZRl3wYUsAtSmOxub8cVfAVnty
         zq2J287oK+HvSQitT0XD+IG4d0GEs42Iju3Bn7E3zqcgjyajLVN37Wn3pyxhkQiq4YtI
         2gHrBX33Z+lCj9Be7NzFIBiB97D5wjpAk18DosiT0Vpb4krYcKGDr0K8QxKJY+WJvutB
         Tn2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=r7UuMKF9MkdRhxC1zpRaGf558e+JQcmyumWJmz5J7GU=;
        b=sSKiOiXSGIP0q1hcO08IC6pGmIrAjGDjyEfYlHcigr5xFVk8/SgekzwJKYjh1e/XrN
         KNkf72vwHHT7UKbqmduFQkmtNaRwLEAsvGlgysI0DvKKY6d4Idy/va7EwbVbjVr9aN2G
         u7CDCy01kem7wEjluIGqZrcApi7447scWJfdCq0zKpGd3Wh+19dzHPLcnCdb9ldNF8Rb
         IN1fOsjevdrqV5PO59YQoROpHfIihJmRR3sGXpodanJkSp5H9WTwy9JXvnnzJX7fuvSx
         bLHcLf5k0xYO8E9fbnweG97qd2oy2K7ujTSrOZxDGcoJevmRpH3YXPaLj+JKYpU1VRdg
         S7/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530J8twY9BJzJai2f60C2qrvaIuwDP6rbib/hHyEXA0RQmfPkcqB
	EQ8oPhUIMKZYeUyLPZzc3LA=
X-Google-Smtp-Source: ABdhPJzCQlH1W2K4rA/L3Aro0cB3wCaGwXtlGuVJ77hSel5cWUvkWgQoAauW6r0hFRrGaXynXqfqCQ==
X-Received: by 2002:a63:101e:: with SMTP id f30mr14087358pgl.95.1610733569203;
        Fri, 15 Jan 2021 09:59:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:6d0e:: with SMTP id i14ls3770304pgc.8.gmail; Fri, 15 Jan
 2021 09:59:28 -0800 (PST)
X-Received: by 2002:a63:752:: with SMTP id 79mr13568022pgh.272.1610733568645;
        Fri, 15 Jan 2021 09:59:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733568; cv=none;
        d=google.com; s=arc-20160816;
        b=JLH3+YYNwo0RPjeGPNacm7C6PqC7xvMXuhx2coTTBhjm1tZVfDX1ANtiQYipn0iqOK
         ehvyqxXoZuHZBDTanpSYORoqZQxOrKFwdOfPjkUP8mGgEtFDRohP9s194U8kW+RY/nml
         eVln3r2QEIFgGzuf9dNGHLPqnbzf9ZQW31Zi29Wj2OM1Up3H/DMpMsg4o7o1q6QB3VPd
         jMIdrH90H4tf8sLGU9y26wdyd/rVmFx1Ml6MwWuXM1ySp2Nf6UejEUttozaeYuPsoGJJ
         dulrVfWqUympDqDGD9ljtCiUVEmpbDI5+mMbr25rRnoL8msj8tTmspQvjiY4BrEWvKJn
         2mkQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=YmoONv3wQpOkoeeyDIZHtWQV/jwkYaia/9bkmSrvRsc=;
        b=uCx94f8SG85XUmUvW0kAN1q7o3ByrJ7EtkOwfWkcmeh4Zzzh4UZEz4sa68GLEF/3DZ
         tcaEiGJWIRif97n13u/cI9BUJH5YLZbOfTkWDgd29RraSUH1VrzE/jgcAxGyV1aIlCpH
         ApG2QxgKeQsLQpRVLdqASHQ+2ht1bRvicP1+e2y6093L4svqCHoIgBfmdHxa3LebNVIQ
         4dP4/wc5OSeYbWHLIUo0iBmMewGV8QGhbwTahtMDZUmP7Us1ktPiJnQjWhtXSjrBmQo1
         71uaKUaRaDPhv+nIT/jbzdWmv+Eddw4a0U98Cmo5C4kfWhJi97PKpUEgs25vFVFqhkX4
         Oqfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id c3si500522pll.0.2021.01.15.09.59.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:59:28 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A10CB23A59;
	Fri, 15 Jan 2021 17:59:25 +0000 (UTC)
Date: Fri, 15 Jan 2021 17:59:23 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Will Deacon <will.deacon@arm.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 2/2] kasan, arm64: fix pointer tags in KASAN reports
Message-ID: <20210115175922.GI16707@gaia>
References: <cover.1610731872.git.andreyknvl@google.com>
 <ff30b0afe6005fd046f9ac72bfb71822aedccd89.1610731872.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ff30b0afe6005fd046f9ac72bfb71822aedccd89.1610731872.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Fri, Jan 15, 2021 at 06:41:53PM +0100, Andrey Konovalov wrote:
> As of the "arm64: expose FAR_EL1 tag bits in siginfo" patch, the address
> that is passed to report_tag_fault has pointer tags in the format of 0x0X,
> while KASAN uses 0xFX format (note the difference in the top 4 bits).
> 
> Fix up the pointer tag for kernel pointers in do_tag_check_fault by
> setting them to the same value as bit 55. Explicitly use __untagged_addr()
> instead of untagged_addr(), as the latter doesn't affect TTBR1 addresses.
> 
> Link: https://linux-review.googlesource.com/id/I9ced973866036d8679e8f4ae325de547eb969649

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

Unless there are other comments, I'll queue this for -rc5 through the
arm64 tree (I already finalised the arm64 for-next/fixes branch for this
week).

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210115175922.GI16707%40gaia.
