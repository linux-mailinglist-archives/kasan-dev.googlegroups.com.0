Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBUPB62FAMGQEDFGK7DI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 078F5423FF4
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 16:21:06 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id r21-20020adfa155000000b001608162e16dsf2176940wrr.15
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 07:21:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633530065; cv=pass;
        d=google.com; s=arc-20160816;
        b=xdyqx9kGBFN+Q8pyA6H7pm29n4P0tp1o/ANP7DY5g4J6WBfvr8zac12jpEqRzvSkYD
         TShuLL70yIXRSd0ij8uLvncQt+oAqFO2JTwfQLPTBPs6OJWN3uF9I2dOucvmZ67VuTGA
         vdg6/xRdDXNK8JsxpxSPMnpXsYM9H/CEO94vSbLBPANgEexuWgf14GAQ2fHq6fSg3c7k
         T3AtcgnNw3yi3D/OGHoo83CGuKCP8NXkVNQtK1UHyopzPdtrrP8OynxVqJrcqcRTXFaP
         or8VBXo+jU9yOCQxijyppzfWFXbv1cPz6LOBPmJLzwFz7MLxJ7f5fBbjgDZw0N89WtxT
         QTZQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=ThiJru5GAfxt5Kcob9RYWjpLTvOhy7+5ubiUwWNkOV4=;
        b=RX6+yttxIV++OE7/k/Wbqa/0iJu35FWDBQz+3rrEHk3CIpozrE8+FjUPaYaCrXePa0
         U/E15s3yOTzWvTyrQFnmoz2rDndOzHzqfCho/V7/dotoEzCWgm0Jz2RmSlF34JWCumiF
         jt2MqBdDuzMeg5ZhztYPvF+o6/Ur+IhSbT67aEU5sxs1jkt+FaBFkmSBLt4YqyyjpG76
         E+IcLAyjtHGUwIEC2OZTW39dGlr/M2Kjt/Wg/c998ux8+lA1aANCRCCP0tXLhsjiGNwg
         s00Tlp15Sie4YP5OdXyE1Gcca8vtKMQln92e/CcZy1SxLOXGq5L6XxvXrMY+D0Gk9JCM
         v1hg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=ThiJru5GAfxt5Kcob9RYWjpLTvOhy7+5ubiUwWNkOV4=;
        b=QCtw/9UWZbKoCp2pW/pARo2jbWDAoAvnSGb8H2txOf0Ox5NcfkO+6W3niBRWuYoroj
         jb8k/Q3ObpQ2FIAPbD51uFxI5V6ZK9vELnd3ZcN15vJWXNbsjVFs7vRCxr6oDqv6pYzl
         LEn2kAWGkimEVotUue8Dh/Sy/2rLx6NAFxTO2DBEIpgIcTwX/MvqQIJn6eLX9kvOYPgn
         XxMuBPIdZfRxGyKgtXfjvBZQ0D4pDD0phanIbi+LsKY3aP4hcFpVTDq1wroxvDIJOWC6
         OP+akki4xdyUfmAmGfoFc9t6bmveT2kIGCeWs0fMrfqejx17cUBnYVfwM6x08aPWTfSk
         Uq3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ThiJru5GAfxt5Kcob9RYWjpLTvOhy7+5ubiUwWNkOV4=;
        b=hpKcFqlOiLbPOC47X5YEMlHs8Qvb7DlyOy0ofOJLa9A7RIJ2ya+9I4mMso2Bl3CESX
         0M3TeGboKf48XTeq/Oyw4dJUyleNReibfyd4mfZbkk+SrRDIRMyqrkxat4panZ0ynUY9
         LEpJq1p7RR4yXZfqrx3ZXTjMsslCl0YSZAPlGTUOZJQ5FyNDxv1t25WDHZfMciNKmSKb
         YXqoxePoYU+KJdyUiblUBwFaO6V5sg/SWXDuU46vs/zl8baM1XQ2E5wknopg4ggKlW+Y
         +3hkbzKpXBkrLB7CkxG3tE/BRmUx9oZuTV36iYVH0ZaXF8c+GfbMhGbyg/iKdaObbWNu
         8o+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OqG2K1KEX2W11qcdsX6TlgTFaCEtap/d+qk6ngmS3VfhZng4Q
	Kudjr5E1I50tvDbbtWWVyv4=
X-Google-Smtp-Source: ABdhPJw+dnrauhQduNzXnOdQArEPtFzGKnU4OO+MkFZTaT8gjGL209J1iQBz+OFspxnin+v379EDoQ==
X-Received: by 2002:adf:fb0a:: with SMTP id c10mr30340810wrr.354.1633530065720;
        Wed, 06 Oct 2021 07:21:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4c3:: with SMTP id g3ls110028wmk.0.gmail; Wed, 06 Oct
 2021 07:21:04 -0700 (PDT)
X-Received: by 2002:a1c:4487:: with SMTP id r129mr10135050wma.127.1633530064911;
        Wed, 06 Oct 2021 07:21:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633530064; cv=none;
        d=google.com; s=arc-20160816;
        b=GtzaKCjM0g/qOLVhalLZSA5GTzYDMfBEuQBwM7oq2bwt/ndv6J/x6bpAJq19UUfiWI
         tpxGMUUBOqHCKzTq6H2wXQGZS0HiMHeEUU/1BrNedVU8I3dym2wX56opQOR1KV7notDB
         x1JABUPiAE8vDIe/ThnnlP7FiadmOGYcFy68tv2rubacL2jpGlvSy6DgYp5GpZeD2Mno
         itpX343ASTqg23ho0ra0x2El0yvHPTHn50C9MTDnhKW7ZDSAr81lXrfj54k7mqJAjQ9p
         bs+bVvKJrCgFrP1BeWE/XCZOTlZy8m8W44D6rIAkbFH0LSnqk9PLroCt0ga8I3zKu/KZ
         2l3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=ohvhA8TkYGwx1WO19Kid1C/JRXXLWrJzCZ7XLi6xYaY=;
        b=TCpjprqNWE17FpEWMJJEN6/jgA7JnTPOPZ4AC7n2kcTCXfzvk7FRpaAfE0QuXC8RpW
         XL+StM3Mj6Q4EkmSZeNNkS3vsWCjB8KsyoY6I1196wBFRDhLfY5H5oNW3yTkMKL9gigp
         K9EUW0hn1OgRJ5xgfY7or5iwH1c7foweM28B0u7uKITo+CsqzpE6TTY/rfbCmUimyqfj
         ocM3x2W3+gBqIXV/UgRc6ZGsWI6T2T4+/HCuSR6hbH3wsNJkcC8DLTRSHu+TEt8QjzK5
         zW5kT+SlXU3tw1XgA2u4svTSZ4CKixqlqV4A93auBA5miVypykBmwqInJMVsstZ3AIrT
         Vz2A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id e2si1245933wrj.4.2021.10.06.07.21.04
        for <kasan-dev@googlegroups.com>;
        Wed, 06 Oct 2021 07:21:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 078996D;
	Wed,  6 Oct 2021 07:21:04 -0700 (PDT)
Received: from [10.57.43.152] (unknown [10.57.43.152])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id E4CFC3F66F;
	Wed,  6 Oct 2021 07:21:00 -0700 (PDT)
Subject: Re: [PATCH v2 4/5] arm64: mte: Add asymmetric mode support
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>,
 LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
 Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin
 <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>,
 Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>,
 Branislav Rankov <Branislav.Rankov@arm.com>,
 Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
 <20211004202253.27857-5-vincenzo.frascino@arm.com>
 <CA+fCnZeL48oLd8bbWgxomc6WnS4e53a7K6SwBpKBJND4f03f7A@mail.gmail.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
Message-ID: <2d03d87b-5ea8-8b2a-eae6-ae70c7e9d855@arm.com>
Date: Wed, 6 Oct 2021 16:21:17 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <CA+fCnZeL48oLd8bbWgxomc6WnS4e53a7K6SwBpKBJND4f03f7A@mail.gmail.com>
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

On 10/6/21 2:19 PM, Andrey Konovalov wrote:
>> +               if (!system_uses_mte_async_mode())
>> +                       static_branch_enable(&mte_async_mode);
> Using this variable and function here still looks confusing. Maybe
> naming the variable mte_async_or_asymm_mode? Or
> mte_async_fault_possible similarly to KASAN?
> 
> 

mte_async_or_asymm_mode works for me. I will modify the code in v3.

Thanks.

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2d03d87b-5ea8-8b2a-eae6-ae70c7e9d855%40arm.com.
