Return-Path: <kasan-dev+bncBDDL3KWR4EBRBCFCX76QKGQESCQ6QSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E2D592B2D2D
	for <lists+kasan-dev@lfdr.de>; Sat, 14 Nov 2020 13:43:53 +0100 (CET)
Received: by mail-il1-x139.google.com with SMTP id o5sf8536469ilh.15
        for <lists+kasan-dev@lfdr.de>; Sat, 14 Nov 2020 04:43:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605357832; cv=pass;
        d=google.com; s=arc-20160816;
        b=qWPqizejnrSR0gomutDQCklPYdwzu1dozcuELh4UBAdbX88CJpBCE4+nIszo1VYFG+
         z13fBe4uiIlfV71hqRsexymJfBnf9oWhmW+fJGm57DBGXdY7irE2Y817B5BKMW5WWow3
         IeYY4N2NVCZtvTD/pGtbXrjYneah/zrEyrqB4aL+fP+ZYXsqJaS5yZfIZ+v2gp7w/VHW
         Ai5fDk7LXTVmKK/ON5khlUmZw1whZDKoMs005W0KHvnHPN+/BUJX8HFfiFtoJvNsKybM
         U0Kc6W2CYI+nB1qSWB/d8ZIGMGs6/QInEDGU6iflSiifZHWwMDUKJAIQ3PcC+rCw0lj0
         Ezyw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=YoIYIObuFdfrau3worddFeWiKUmtWHe8dnPgWlSk2BQ=;
        b=WKGeDxiIutnRi0wS7p07wcKxTy3ZBghN9ZDQd+7322B36//gurD+7NfKNQ3LJd8DRZ
         2AER4NiA13kW6Y+c26w9ahWtGvVRR8zEPyf8IHgy3n6/+9CcdIEhaUzBBkl8re4GZ2Xt
         +AWVbWKcdP09w6k0mnwgglkbisW82isDDGqqQmoqH57goZvOg/EaRZnRc9v1OQRaWZ1A
         p/Udx1LtxXST6H89PBSxvhKdxpmgrE6TGznSbDZ2NyQavZ2uk59679nAD5GorZ3tNtBI
         vVYyOFS1Xji13GYMjATsWo+a6WJL9ubrLNndzk8UBhVCa3zv+pgG9c+YNu6Oof9xdxwn
         Y3uQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=YoIYIObuFdfrau3worddFeWiKUmtWHe8dnPgWlSk2BQ=;
        b=sC2fux3QRHoCLNtliBej2dx0QDUwGeAP3M8T2R6UODzFJAjHOKIOZtHVlqU2lo/I5k
         wjEN5lCvJbrwSDN7+bFcmnxTYqXq3kVYEwfrlidAtoFIIFBa5EuiXkm3/z6u/577uZKA
         DACH+EBkyN/AKGkXYAfkj0CYTiXe11bNB+Y4dUATFpTju0vgynm8fDugeTnQx34L7USR
         h5D1C0UY8lN8Q7s9yxLOE9AgOrEshWOz9gNNFZ4MGFu67h3j5+EXGel7IDTqS3EkRseb
         azEHf03pLkwWhtXrK7v2Av56dP1lG3PiC8wZSCsBTMCpLNXd5W0Ou73a0dFliwSGgGlb
         qu/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YoIYIObuFdfrau3worddFeWiKUmtWHe8dnPgWlSk2BQ=;
        b=OPjZVXAmzLHVGzzNV8NnASvOGNnjRc+8Bcd2Gyu3Epc1NluoXUatMCXuzGPalzLw6f
         NSFoatTydv52SEGgHLOaF1kDvpzJjhH/MMQMzHDRKC1hNhwulkY+GxvsH9WXrRyCfktM
         whVsX7E9NiGulCBS37GPcRdpVYsYx1ePF9ImaOKXyUF9vWKHHu+tK8WKZUO8mDecce8f
         MM5QVzDeRjR6Eon7b5GIrRQneSsA+yyLbz42nIAkF/Y0JE4zxOwLCO63D65Vrl0QJPtO
         3QqwEyCAqy4/Mcm7Qpj96+p0jnwB76u448R5nUqxG8yxrDH52ouVM+ggwdtwdGyjjHwL
         VkJw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530jtpaO9c7eZsiOVWQTcDr7KuffqSjApzlAT+ntYK3ePyKIRY7A
	ibkZG918gN6eF91b954lB1s=
X-Google-Smtp-Source: ABdhPJy/JfgtGtBnNfcGDL6xd6Mu5lMpGVT0YZZ11xoo8I60YFrR7bk4XTYYAWwFDjgARmDAXS0MAA==
X-Received: by 2002:a92:520b:: with SMTP id g11mr989468ilb.14.1605357832603;
        Sat, 14 Nov 2020 04:43:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1246:: with SMTP id j6ls1779554ilq.10.gmail; Sat,
 14 Nov 2020 04:43:52 -0800 (PST)
X-Received: by 2002:a05:6e02:96b:: with SMTP id q11mr3034309ilt.117.1605357832237;
        Sat, 14 Nov 2020 04:43:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605357832; cv=none;
        d=google.com; s=arc-20160816;
        b=hXLhzBhb7PnsWsrFgk5rivIKX2+u7MG3MU3fdzvxyoGv0sjn2MrCDT3CGDeVTtwn2d
         qNixfB5/XKJOdx7RymcwyKKwIguBFAYocvyVMsFkD08bNnWMgog1rBp3dgv1Wkikts/T
         17XX8oAn1wsHChmQtJklICMcgpPVZ2I1hIGFlVI8e0tWKEHtV1t4rrMjrIPrbmN6xOBj
         j2jj0PetqrcAL7DDeyNr9MqUjG0Zu5WORrSu4/FB++aSO2EKKMXWO7aCrDgM0K23035P
         RItyALy2BnlaSyvrGnmMa6KujbRqZMqaaqDMAy5FrBl0iE1L8EzjdJEBcztKjxNNhad9
         c0CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=9TcHEhhPt8WFSqyJdv7UhW23Nxn3ENvAZaNdkv+kgu4=;
        b=oGGQ8imR1ezw+4ywyf+tKR3YvoycL2IQ+m9GpXl95EvOdbA1P12mFP3CtNmuK2nuSU
         ghtMOwtnRP3j6K/x+ZeNOw/a6GKPUWEa1EDMoq0d4OsVCI4cHSpXeEBlrGB6WLfopKis
         oayGsy/YuqLPL0HV5Kl5RIWf1kmXi6ZXM3AKC15ATYlcAo9xO3NMcUkPxRvlV1J2BVbZ
         0AZ65acVeeTgPGz1m3hmaNowkUnd3BUMMMvCqxXVnOi8EmWpKHjQQ799ufDkPDmR6Ej2
         56y5YMQHli4QiaMw5zKBtkwz8Dl4hxO0WIeIevGd/wDenSgC3GREBI/+8HTOYjEvu/sb
         FXUw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id h8si709791iog.4.2020.11.14.04.43.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 14 Nov 2020 04:43:52 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 1FFF720759;
	Sat, 14 Nov 2020 12:43:48 +0000 (UTC)
Date: Sat, 14 Nov 2020 12:43:46 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH mm v10 26/42] arm64: mte: Reset the page tag in
 page->flags
Message-ID: <20201114124346.GC2837@gaia>
References: <cover.1605305705.git.andreyknvl@google.com>
 <18bca1ff61bf6605289e7213153b3fd5b8f81e27.1605305705.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <18bca1ff61bf6605289e7213153b3fd5b8f81e27.1605305705.git.andreyknvl@google.com>
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

On Fri, Nov 13, 2020 at 11:15:54PM +0100, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> The hardware tag-based KASAN for compatibility with the other modes
> stores the tag associated to a page in page->flags.
> Due to this the kernel faults on access when it allocates a page with an
> initial tag and the user changes the tags.
> 
> Reset the tag associated by the kernel to a page in all the meaningful
> places to prevent kernel faults on access.
> 
> Note: An alternative to this approach could be to modify page_to_virt().
> This though could end up being racy, in fact if a CPU checks the
> PG_mte_tagged bit and decides that the page is not tagged but another
> CPU maps the same with PROT_MTE and becomes tagged the subsequent kernel
> access would fail.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201114124346.GC2837%40gaia.
