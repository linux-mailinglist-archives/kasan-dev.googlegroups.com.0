Return-Path: <kasan-dev+bncBDDL3KWR4EBRBG4KYGAAMGQEKKA5TYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 64EB23043E6
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 17:36:45 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id bc11sf2626102plb.17
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Jan 2021 08:36:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611679004; cv=pass;
        d=google.com; s=arc-20160816;
        b=d1Xv82uWfdLXEDHnkDXqj5XbGawJ+rx9oIa1Hi2JhUX9bgcQOJ3UWQbVrT35ete3GX
         4YVeJAyKBay6Wjq7c+0zta9BN3JhrEegpkCXWZBi4D0mDcnujgjqvdG/w9ITMY2MG/cT
         /hQwXRhzThuBBppQgcsNv0cAX3FilNvhFmapMDk8G8y1MZCEjlMTrAqPznKS5L3OCs1F
         OQbI+0RYCIsfbpPyJOU5av90+eHUJg1CS6PRx7r70sdSEJSDqqPP0wW5/7wPkrj5j+Vc
         JOFSniLm2tMBMMgsTnomjHqsJqZLvXPqMBVklXEStpOnP9lg5XQGgxHkEFmNWC8s627Q
         HMCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=RR5eZL9DJ44xMCVDn9BmO6LcHVif6e6BGqk6e5LfnZs=;
        b=tdhvTHRccrPE1OIyU4dEuQxawxH0BAdI7UcjNPIj61GiGDC8P48UDCzDuM5ipl3El3
         KGeyocWTAoBXnq7qiwcSKkT4jz9sAgo0QKfRlwHUH0zyNfa5i5xlj9q+BN9VqqPSYO15
         tLuMnw0FGEt12pSWUz44FSlElM//mdEURor53Pt2qkOaTvix60wFFQQ4fieFcIf9tgix
         WSJZuVvkSC7ovZc8kv9EnlCv/1I55u+gKrcrLN/fCYgLVcHQfWmQgsNBSlWk+oIlcU6M
         sFfJJmrQWu7XuI8MnHkZ94D7ewW9glFkdhdypEBDaAbqirFMLuqHHaaZB/5luFRbtLk8
         gb/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=RR5eZL9DJ44xMCVDn9BmO6LcHVif6e6BGqk6e5LfnZs=;
        b=j4WuIdiRInEv7m2ayRLPgYVT5XEEJcxsJBtTZuij2dNIKIuYXKe8i5fB5psgW6DF3O
         euvuV6WOQGs7qU+ZHbYfrsRQlYO4ktuMS4nQ3Tk0gpwrLkz5DFizwfGP+//B50fXxdoc
         sXRvXuGqGPdb5vtlkkPDMmdntFNO1jJQNr18wxOB1nlWVq6O169fn7EUdSwslfLYfk10
         fGtQX5F3et5MNXsaz1XQ8WfBp9Cn7K5tKUdN/WVemhV2sW2Lh929n3omPF2nRE7dtifr
         PLHPCxMTE25tVBhIQI9POWaOqffRmkfff6gxD6TGjUnIA4MYcWb36OdWqh8duf+Ru7df
         YiNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=RR5eZL9DJ44xMCVDn9BmO6LcHVif6e6BGqk6e5LfnZs=;
        b=KlEwEjVXonSXnscHdpqgt7n+6kZihmT2Lw/iJAXwZPF+ozvYHxOvjrYNB/qLBNYM7r
         1C8hqVuvjpL8bFnfLK1lnR8//UcPqHb0dk16+nDWlv4bGww5FaXcDjLuQoJXiablcSwW
         6nyYLB8svB/ddPflOTQbu6wZUusT4BMJ+kNrX099JsMGa+RHuEKMF6e1x/pFVwfYNh7s
         7SCziCY2VdmXonfcEi0+UGm1QJZRrrAD6zxlnDPA3t2LTcacfWKkJi8O4ZtnpdiVrS6G
         iYHlcrWxpM3VbSc5Cl0Rm+AG4hWL+/1sQmuFaTtzNm+tZFXvvcu/aLvNZmKKwa+aCfGn
         /RvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532vOesOr0iB7z5QL1osIhLhAMhUjWil9f9iLKDnG6o9Pc3DYVU4
	q93xROkc3W1YbkP9a05CRGw=
X-Google-Smtp-Source: ABdhPJw9q7kofv8fVHqUQ/6oC+23HDKOBDLTeDURU/KE2sFfmqFLRZ34j4GTgFxbY9aURXKGI42yKA==
X-Received: by 2002:a62:1ec1:0:b029:1a8:2c01:13c0 with SMTP id e184-20020a621ec10000b02901a82c0113c0mr5988955pfe.8.1611679003795;
        Tue, 26 Jan 2021 08:36:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:511:: with SMTP id r17ls1868023pjz.1.canary-gmail;
 Tue, 26 Jan 2021 08:36:43 -0800 (PST)
X-Received: by 2002:a17:90b:18a:: with SMTP id t10mr681829pjs.28.1611679003155;
        Tue, 26 Jan 2021 08:36:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611679003; cv=none;
        d=google.com; s=arc-20160816;
        b=N+IvgkSsLCCgJfshShYRy2vb+yos9i5cDcGW3ll2pOSpVvWVrQhwjAR1w297GbzAQT
         boCb8vjy4r+PiA4bwe7JhKMMUoX8gnzxqA45L/KcZety1NC5bwc3NNJyQTVcEyt8BCTs
         v6cbeIqwtSlxwOGwOBE0vIdHj6H+pXbPQ/fvVPe025ROek7sd16Mbu+igFEYwa+4gZsK
         johcxLAC4gS0+X7iAyExLfcrUXP8j4fMXoEtCWGDdia84kHls8ev86ew8EgVcyOZJINw
         QnK6TM/o3IEPfrIUQnGcj97wPKqhkBGeY9NpyLjNpBkPiI8kw0oQ0qNZ2YGlqxUiyI82
         Ccvg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=mbBR6IKku7++ckdkOLaYM/oCACfMAUACy6LTo39T09I=;
        b=iQOhhj6tbhEVJCVnrOzkqSMqDzQ93us7EY219tAT0NsFVuc4RfcPg2F8IIK3o8IrDL
         9TyhBAPT1xzX2WfABCvjdbEDFLvFiHQXZMf3RtiOCLCgJNN2/Z9xGZyGNxCS4emRXQyy
         Dzi9yux3JVx8xzzrsQPAWWmjEjEGjxg+vSaRtc8+mEvVIhP41kl5diRxqTgtBeizTNnt
         w+41dXTQrmabXlW8QHZaTG+lj2g2pLg0jboJnV/PutDDUKOL0wudvFUG3XWfVClFtILx
         CGP6qB8aLiLuLkmj6TRzhiNBdAe410dh8H6ZtGqkOF4vpA3ojY14D5fpycO4pEDVgw1O
         7/4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id mm22si178724pjb.3.2021.01.26.08.36.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 26 Jan 2021 08:36:43 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id A940C22241;
	Tue, 26 Jan 2021 16:36:41 +0000 (UTC)
Date: Tue, 26 Jan 2021 16:36:39 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, stable@vger.kernel.org,
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>
Subject: Re: [PATCH] arm64: Fix kernel address detection of __is_lm_address()
Message-ID: <20210126163638.GA3509@gaia>
References: <20210126134056.45747-1-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210126134056.45747-1-vincenzo.frascino@arm.com>
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

On Tue, Jan 26, 2021 at 01:40:56PM +0000, Vincenzo Frascino wrote:
> Currently, the __is_lm_address() check just masks out the top 12 bits
> of the address, but if they are 0, it still yields a true result.
> This has as a side effect that virt_addr_valid() returns true even for
> invalid virtual addresses (e.g. 0x0).
> 
> Fix the detection checking that it's actually a kernel address starting
> at PAGE_OFFSET.
> 
> Fixes: f4693c2716b35 ("arm64: mm: extend linear region for 52-bit VA configurations")
> Cc: <stable@vger.kernel.org> # 5.4.x

Not sure what happened with the Fixes tag but that's definitely not what
it fixes. The above is a 5.11 commit that preserves the semantics of an
older commit. So it should be:

Fixes: 68dd8ef32162 ("arm64: memory: Fix virt_addr_valid() using __is_lm_address()")

The above also had a fix for another commit but no need to add two
entries, we just fix the original fix: 14c127c957c1 ("arm64: mm: Flip
kernel VA space").

Anyway, no need to repost, I can update the fixes tag myself.

In terms of stable backports, it may be cleaner to backport 7bc1a0f9e176
("arm64: mm: use single quantity to represent the PA to VA translation")
which has a Fixes tag already but never made it to -stable. On top of
this, we can backport Ard's latest f4693c2716b35 ("arm64: mm: extend
linear region for 52-bit VA configurations"). I just tried these locally
and the conflicts were fairly trivial.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210126163638.GA3509%40gaia.
