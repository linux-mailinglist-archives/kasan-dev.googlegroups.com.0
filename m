Return-Path: <kasan-dev+bncBDDL3KWR4EBRBO7QRGAQMGQEDUPBO5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id F0D6E314E79
	for <lists+kasan-dev@lfdr.de>; Tue,  9 Feb 2021 12:55:40 +0100 (CET)
Received: by mail-oi1-x23c.google.com with SMTP id x23sf2145538oic.18
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Feb 2021 03:55:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612871739; cv=pass;
        d=google.com; s=arc-20160816;
        b=LZJ19EDbbGs2W+RMuuiQ6QZyOx1uCQLf2tXkVzN1m+FrSn6cr5BbRFZIj2DRKygTvE
         gbA1Ryezw1GFExAryDQmzMDP/roY+r2zX3ShlOICZVsOK7WpSQtvTO6fx0KJCLf10pGl
         sXIJFQ58PXbj3nPC8Ry26NRq1sZGXCMR/pNp973gPeEyV2Pyce41iU3/KQM76tRqm+A3
         vSK8Hrw3HwSIJtHSzR8k1xUB/ehcphgWW1l71al3Tv5AGq0xJH3LFwXaiC8bnBT5cpmH
         VHC9OBM7TIueQrqh9CL6r2UY5dhk50xbS+XFwwFA3WzpqPYg2ktG9TuHbJDo2/WE0VCc
         y39g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=VYmZ/bAsHx8t1CxR99WHmezewmzNRYjCRkd1bVkvlww=;
        b=L7XO9OtNBAqaQP+d0aJJ6ZRAYlEIwKEw6x9yIanWpR6lWXm2H91zM8v5n/zgq7gG+v
         75Q9O7clgbUrX4PMEllfyLjHB1wALd0LXaK+TY8QnFUo6SqhOOAbSiULbeVx6kwe3Rjy
         x+xYNu58h3kwKAba+89v23dnz9+8u7PGmY/NqbF5dQ77nOGwMof4iiz4iFBJhrngsoCv
         3EGZcLad+MZV0g/C7IlcXKReS3zkW9sg9T5XVBgMsXjX5sXDRuSHXWofAqUem7B6G8Fr
         7VX4CpyYE1ETwSkqA3C8+IZmkfCCsEDd1D35ACQu1/rkAKclXZRK+H+/eaINJJnLlnmq
         P+qA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=VYmZ/bAsHx8t1CxR99WHmezewmzNRYjCRkd1bVkvlww=;
        b=eoRFBmeL0hbt27Z3QGmx3ZW0Vpapxm2ppXPUMDqLNJK1MxhnRQ/TWZlzJ/HGO2Fzaf
         bfnIt5Efd1HNsxHQL/33wHPnGQVMeqzY215ZzTwkBbz8fdZgA8OVbsdyDq/b1reEBpEi
         7yo1DvCFboNpjjMbrPTzi2IyRvjReCSX9e5A7hAVErROiUmk6hjdP6zBToLoUIRqPsg2
         RWLtrn8YmlRHcRW67JBggah0aLfCNEFTSVUOZ9I/CXM+fztSwMXoMtIi+Q792p/ccS2t
         DlRtGbATBvNrVxG7T5YuJJu/VHBeeyio1bNdBZlSMnbCGgT5DekS1RgcRrfqY9LukIXc
         Ev7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VYmZ/bAsHx8t1CxR99WHmezewmzNRYjCRkd1bVkvlww=;
        b=E1ZLIwxrs5enaOCcSzw9/lF2g0WzYpFTbsAVC//01yrz46gAVP0PXbesSM8BCoxmRs
         ThJvwA8iFicmav4vWmPV/fZqtM/TLFUpm9TjfU9S2MUvKUMBIKfmHiLP0qpcaG/VR/xI
         14AcjuqkLYOF5cEOoLryiHCUs46zlefEhfJHX8Yot6HNIqXpHGVIAhySNUYpde5727ws
         4/wfj/REB3bHcRD+U5nReN4TXlzc3Sdz2MowPLUsLn2iJL0pgUKlPDvVlKbCHPdLg7Oz
         koIHG3JF0bVhBkOrtXV/Oqv0426296BURA1+sbTlATUEy0o2rtmBIWimA+ItXzsY8w5r
         zsHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531aLtCb8zwk3jCLnEiscrL9jyWYNpDy5smqS7l780lc+3XFnQyt
	PPyztCsXcb4xBGYv18AmaAg=
X-Google-Smtp-Source: ABdhPJzU891fb1KZBXWb6FI+MItxxmhls77iFxV+1ZtqOItz/PgyQe7Hdea1GiIaU2/41ZZVdh0hug==
X-Received: by 2002:aca:5d84:: with SMTP id r126mr2199193oib.76.1612871739656;
        Tue, 09 Feb 2021 03:55:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:923:: with SMTP id v35ls4942619ott.0.gmail; Tue, 09
 Feb 2021 03:55:39 -0800 (PST)
X-Received: by 2002:a9d:5f12:: with SMTP id f18mr15606574oti.282.1612871739259;
        Tue, 09 Feb 2021 03:55:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612871739; cv=none;
        d=google.com; s=arc-20160816;
        b=qvCyRICDNzj5WQcQkSJCclFqobShvsRdvnz3p9dHGbLtnAroTrcUi0ZWsEF6fbuM3c
         +3h6OCm/hPN90jw89qxE2V/ml5waU+7UEfFzraZ3RlZjjVasHBw3X/l0+BHfSYYpdHsB
         lbiVyA4Jye3BOjUI0qjTRWVql6t7JUOo8pcVjHpNc2WtR9FrM01J+RnZugUslrlCWL2d
         CFB8JoJP8I75E9+spZjwNZboG6l/R8+cHidQhJYGaY6oR0P5CqqLHhZwXc8MpK+rmvn5
         TJv+WbzpfOQ4gMBSVBH1Js93mtUEPIvvdhhmcgipdUT+Ls4EhLnnz57+zc5MGCg2dr4Y
         TknQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=mUnFdkhqe/qPdJcfAo6ak44ehFoo34zv3JZN221m6u4=;
        b=wYiXefpzqBrdwzPXXAf9bJeJ9V8mtMK2a4l5Pp1Gb7nHJcEQ0BaP20OS1KqAwNGXrH
         aLqp/Upc/KnCWtHtrk1ae5UROtzoQXRulwacjfZv71o3S6Pli9FRFhs0X7cZ8MVV6dma
         hcoIQLXmfw8iidbHLhz0j2GnR3Jab15SyZeOaPtjVggZEvsTEyl6lKgmIdth50ANjQXI
         75Tn7XoGNrgE6cg5acmRKLtmWD2JZnmVXZpgj+x6jGaoXBrI7S7jU0WOUm155tcXlxz5
         +zhVJ7sflaqWEltn0o2NIeYzOUJZsDpnyFZIHSpOjXHtLXTV8uJvoVZdVmoYFJcodf5P
         WGmw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id e206si1150369oib.3.2021.02.09.03.55.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 09 Feb 2021 03:55:39 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id DB61664E3B;
	Tue,  9 Feb 2021 11:55:35 +0000 (UTC)
Date: Tue, 9 Feb 2021 11:55:33 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	Will Deacon <will@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Lorenzo Pieralisi <lorenzo.pieralisi@arm.com>
Subject: Re: [PATCH v12 6/7] arm64: mte: Save/Restore TFSR_EL1 during suspend
Message-ID: <20210209115533.GE1435@arm.com>
References: <20210208165617.9977-1-vincenzo.frascino@arm.com>
 <20210208165617.9977-7-vincenzo.frascino@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210208165617.9977-7-vincenzo.frascino@arm.com>
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

On Mon, Feb 08, 2021 at 04:56:16PM +0000, Vincenzo Frascino wrote:
> When MTE async mode is enabled TFSR_EL1 contains the accumulative
> asynchronous tag check faults for EL1 and EL0.
> 
> During the suspend/resume operations the firmware might perform some
> operations that could change the state of the register resulting in
> a spurious tag check fault report.
> 
> Save/restore the state of the TFSR_EL1 register during the
> suspend/resume operations to prevent this to happen.

Do we need a similar fix for TFSRE0_EL1? We get away with this if
suspend is only entered on the idle (kernel) thread but I recall we
could also enter suspend on behalf of a user process (I may be wrong
though).

If that's the case, it would make more sense to store the TFSR* regs in
the thread_struct alongside sctlr_tcf0. If we did that, we'd not need
the per-cpu mte_suspend_tfsr_el1 variable.

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210209115533.GE1435%40arm.com.
