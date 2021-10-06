Return-Path: <kasan-dev+bncBDAZZCVNSYPBBUFR6WFAMGQEWO3B3RA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 90696423960
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Oct 2021 10:05:38 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id q10-20020a056a00084a00b0044c729ea8f2sf158155pfk.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Oct 2021 01:05:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633507537; cv=pass;
        d=google.com; s=arc-20160816;
        b=rTFe/2sGrUi7QqzH/XqqjDkndPkWx7Fzc9Xho+fkxv4fvxJgwszark40cxFeawkZrV
         YHbUDcjZs+yXf+Myz8YL6Ms9vB4X1eB564X2mlVGawHlwFer6jik5Sjo+AMBGhzTIsF5
         otJpnuA8mhdHwuDPTIxatLkPsabWWvypn/GPGLdSMooGSUuM1Sx+2NVs9xiBCMJlLim8
         qJvz4E13rwnV25R95ki68tTR7lNEmm3s2bdkmHvGLVvh401boYXHqcS9HXoaLTQB0q76
         Hf+Frhet/NoNLsWt+3JTjGxPB8uvQScukzKG2rcn04gTHkmc2qnmMmWDiJAet2fDqPEt
         zt9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=8sSFgieo4HWMQKNHlMkInkW0bZkRUlyBq1zSDgNq9iQ=;
        b=vP1pRLfZRpchyopWFxkojHGe7asE82KMaPOuU5HkLQ81Y4ALFNewzTqnGVlCEoccyv
         e2t4i/2hm3C/vRfZbDFekZwHk+9FXjfAjaMzODj/Z1W4Qzk/hc8UmM03udw7gaXkEO97
         p7BorFBZQY4/DaRapHn5dL52BKt6xYTPwyUnlnH0Z5FqGdu7/OltJD8VDHttQYqXTzif
         B0GeKCIUrdq+qcI738PBK4J4GWXUoNUW1SCKVH7sYEATDcPFTNivRQ90r67SiinT3Nha
         zFNRKSe/TCKbUmkCY8qt4eTbRBGLXKn5sUlsbLMxFnTAnJcIKTBD7CdSMzX6YX3+teAf
         pskw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=E4v0iJvP;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=8sSFgieo4HWMQKNHlMkInkW0bZkRUlyBq1zSDgNq9iQ=;
        b=Jke7M7Z1z1ot0a8sJv1QwA0eSL6FaZ8gbf06KBXUFifziJlzsMKZRg0moX0VEVdCYv
         9jUpqaZvRaoiOCK+/gs+kH5A4oYHzoo88tuxX5PnoJwt6iyE70brWbfBI0HwgHR1PYfm
         cya6O0Qq2QQCYubJKSS0Jv2I4RqI2eC8HqLn4LAUnIDF681WeTLmsiu8YeG7y69NZl86
         cvQ3T8FVu0iOcEQYvyitaqFcWxOOu6Aw0fWJh8XvNg4CgsApJuINkogibEfPB8m/P3b+
         Y1eopuLZQje8Ynv5KevvW44RgOS57QcpgRB4fiJd3JAdSZjvTGc5t35jyljnDdQr1VGB
         oR2Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=8sSFgieo4HWMQKNHlMkInkW0bZkRUlyBq1zSDgNq9iQ=;
        b=R4hksntEpm78pbQ1TlwO5iePNir/aa4uQMK+sC85sIIfA6F10Bk7yJKcGP0N/KKQ2f
         Hno+A1MNun9S80YTP2hn9X22FV2eyi4UST1El1KQCQDV5YeS8+gJX6rE9wPUmB6LsPTS
         oqcwDp0k0nVE9r2xBnlwzlOFde8ewJGL58Hx9LxlabZnR+sFwRdkWgMEeXbtRtjWBj3y
         L82M7Wf4G0Z/lFXqAReIVbE6tj7fRddTEa4qzspqbCZ28J19982Az9ODcLt1683NNdpN
         jZOCNdujblenO5I+HvXwipxLJCWTcbthFPpATVuOIh6rnghPlOZO/Fab/Pjr1ctwVlsQ
         KjCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533GBDKpkxqnl8IUmdqQbT+FNllvPLcGidxOTYDwOktm7mpXIBdW
	A+Y6l09SUAD3m21xDiwjmUc=
X-Google-Smtp-Source: ABdhPJyswnUDSaEz56ya9qN2yRkQBWKcPPC/WIZ52DUxCHJHqGmwHkIfCgTHqwHh8ku7hQZlZTOSBw==
X-Received: by 2002:a17:90b:4b48:: with SMTP id mi8mr9051454pjb.26.1633507537017;
        Wed, 06 Oct 2021 01:05:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:e398:: with SMTP id b24ls2759572pjz.2.gmail; Wed, 06
 Oct 2021 01:05:36 -0700 (PDT)
X-Received: by 2002:a17:90b:682:: with SMTP id m2mr9380837pjz.141.1633507536550;
        Wed, 06 Oct 2021 01:05:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633507536; cv=none;
        d=google.com; s=arc-20160816;
        b=K/42y7jYtkJY4yq41HqEySoDm4mUnMqLV/3Jb3PX7uTczwvThJ+gWtnaIWeRRKH7vq
         /Vw4lrktvUasHgZeYufSUEzCRjIXUyC/i+WQRxhg1CKU/NxYCO2qw19x6WD9bcmLKX3c
         n6pKhggAVO3M+DtQW2XublKlDRXMAO1bblW3T1DQcggghd/TDFzW8Nxlk/aaRlbrT3mY
         DQhtb9GQmrrVB2zwew/c6T8Aa9Rw0JgjfJbZjwZmmxNZByCDT7XiSwJ8HDgo7nAibOvm
         b+EYE561ASF4fkxdZ4jQchC/nEj55AeFVdRn/Ct4wqv//tDqkV4yvNUtmbkO5N7OLsck
         Fhyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=YvnMfjhQhHjbnMtwfCxHXAB9Z1MMtRkByUPo/y5YSX0=;
        b=EYS6eN3ZZzW8RjK178UogcJNHSrjBIxnnCuC5qlpjz6ncUbBughepmeoi6CapNkjDZ
         RNx79+vySkjrLlQSQZdW2mDzf0sltbV8iAyDnSbWM9+JRePCOoNdzGnnln2xv4H/M55M
         JqqRv1cvmdDSj2FwQotBfK07cJihzhaRfUqxHD0B+ujnnrsFjurBTIqUEX6BSDHwOY/L
         6NtIb1W4GzAg7u3WBxpaFzaQFnODMRTjnv3v0LXF8CqQECwuC9psGrNEX8xClXBIafwh
         hMsKLNKbLDmvjo5pJTV5d+Cmo4xFhU6cN97qCh5CIiSTzzxKmu6ckEfGkRd9cI0TADfZ
         x8Iw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=E4v0iJvP;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id r14si1931261pgv.3.2021.10.06.01.05.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 06 Oct 2021 01:05:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 190C861040;
	Wed,  6 Oct 2021 08:05:33 +0000 (UTC)
Date: Wed, 6 Oct 2021 09:05:30 +0100
From: Will Deacon <will@kernel.org>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Catalin Marinas <catalin.marinas@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v2 0/5] arm64: ARMv8.7-A: MTE: Add asymm in-kernel support
Message-ID: <20211006080530.GA30214@willie-the-truck>
References: <20211004202253.27857-1-vincenzo.frascino@arm.com>
 <20211005152531.9b1443e659f4200cd4d7182d@linux-foundation.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20211005152531.9b1443e659f4200cd4d7182d@linux-foundation.org>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=E4v0iJvP;       spf=pass
 (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted
 sender) smtp.mailfrom=will@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

Hi Andrew,

On Tue, Oct 05, 2021 at 03:25:31PM -0700, Andrew Morton wrote:
> On Mon,  4 Oct 2021 21:22:48 +0100 Vincenzo Frascino <vincenzo.frascino@arm.com> wrote:
> 
> > This series implements the in-kernel asymmetric mode support for
> > ARMv8.7-A Memory Tagging Extension (MTE), which is a debugging feature
> > that allows to detect with the help of the architecture the C and C++
> > programmatic memory errors like buffer overflow, use-after-free,
> > use-after-return, etc.
> 
> I'm not sure which subsystem tree you were targeting here, so I grabbed
> them.  I'll drop the -mm copy if this material pops up in a linux-next
> via a different tree.

I'll queue 'em via the arm64 tree, as we already have some MTE work over
there and most of this series seems to be arch changes.

Cheers,

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211006080530.GA30214%40willie-the-truck.
