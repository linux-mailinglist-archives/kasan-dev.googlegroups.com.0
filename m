Return-Path: <kasan-dev+bncBDDL3KWR4EBRBGHTSD6QKGQEHQ6T2WY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id 543402A852A
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 18:42:49 +0100 (CET)
Received: by mail-qt1-x838.google.com with SMTP id j5sf1254400qtj.11
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 09:42:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604598168; cv=pass;
        d=google.com; s=arc-20160816;
        b=fVee3npkPfBukqRKpGYXxqQFcFiFOfEep2VNZJ49htgC8o4CpQ94unUfaLj5UIybey
         MOSn4TnCgEGZKrB8PYhjzOjOf/M6Ro6VHZyr7Q5uf3HqwMj72ErcmocGTihvoAmbLcT6
         tsJBPVN3nHENXoJ0U7dorR3frbTqMIhfsYG/kGqie3ozo/30WL1bFWTqsY6pkLGcV2Je
         3qNOhrdZtxkZO2Sdmv/YIVaiMs3I0intQ7yFcUozY+CJBui7Uoah5FolwkaKDnazWcvT
         IXKdKiZcsUn0qCbmdjU+5dcc8aNSxbcqX/6aSqtNiVzDQtcC+RuwHywVCJFZ5BQgtYAw
         zuMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=nNX1smRAaSkS4h4BrIHFNNy3xJK86AumuxeA08yl3tE=;
        b=yg1KcemO01vzeVCL64AkjtIyGrKmjGJ2bsVlWbdfMcllf6XjuP5bnz4Nw7I1CmEZ/a
         GqWko5GVgWGMcwOVpkTdLvLHlM/4oiyhzB3rpxaSuQHink++6jhNBfqZ1xO6YmUETwy4
         DNZX3hYep/vJ+i4BTUWRI20/7RcOARnbWr2IbTHClt4UcwbcoEHMH7ADckLvomECiX2L
         P+H7cOYdhNOsCEpL6rThyu5efINKnzakQR6zniAviadxEUP/q+yWc+Xuus00Jf4vYu06
         8IV/kVV2Y0Mc6tHbd3Bd8mg9DTJx5MRO2baIKnucxqjO6AchwRbv0r7FbCBPsqATGyl8
         NXOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=nNX1smRAaSkS4h4BrIHFNNy3xJK86AumuxeA08yl3tE=;
        b=NkezTg1w19nYsCAOZkO+khouy1nXcVnMx8+8TEhk0qUf2dHcyR7dNX+LzBSR4zLORv
         nyh45wBq6awpbcIOfIt5yl9/ecQ/Kei8/R1J8ADPv6Vst/lD7TZSFjUI/JHMtAZ4xn9K
         NOmkjNHCD/WARK6sq/ZBg19I1/y9iFnfSJ0d/FZuRSIGWm83LOSrbQAGMUo7/7+wpnVM
         YGPiH3vEyn9uef7vKFsiW5jNpFdzt4kxSx4M0GZ2UaT2vqpC+nqRjTKxQ8WMajpBvApW
         3WL2pzYVPMpiN7xZ321g/vrle4TWpOCAcz+kc6b7ljf5f2hsQTq3iP4fTWuB5aaYYXnv
         pKIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nNX1smRAaSkS4h4BrIHFNNy3xJK86AumuxeA08yl3tE=;
        b=PFrhNCPUzvrAkq3OkC3W1B/eEhBS2CsIBIUgCPmIjRoSnbAheoipl7dtY8vGn0G5tz
         A4QFc7Wrb5QM9mw5qpSIEf/JJM/WBrLN3azHWEwguaFXy9ibkFKggppEugH25feonBHJ
         zbgFi0YGBBKL7xrJ9MPCccrpDoyglHhCmKUMeH8FPc1Y5lQ0yQjmjaHs7BwDxNnnPJ/z
         FdocU4Z88Zi45TMqGZTfyrLk2sm1dmgQnwI1hBUHymdtdK+vpPW01uy95+bucI/Z3G5d
         paQn4968SteTAVyom0jcibb+H2dDiojQnHFdlV2v8gQmVmX/nlSlmnvmKbzsd+xWuT5D
         j1LA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532bw2AXdd6rpyNLfMHjVwSCqB2Y7aZbokNShmLiQZPtbQLOCVvL
	WuxD7WKdawb3PPtzLapRH0I=
X-Google-Smtp-Source: ABdhPJwfmmDMfiy+0H7UxOQQtD3fwChgWbF7Ij8WC3Onjw6VrzwoABK4qzudsM+seAbbt4V+VNCH+g==
X-Received: by 2002:ae9:ea14:: with SMTP id f20mr3066523qkg.239.1604598168448;
        Thu, 05 Nov 2020 09:42:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4085:: with SMTP id f5ls1104465qko.7.gmail; Thu, 05
 Nov 2020 09:42:48 -0800 (PST)
X-Received: by 2002:a37:4c81:: with SMTP id z123mr3151158qka.249.1604598167939;
        Thu, 05 Nov 2020 09:42:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604598167; cv=none;
        d=google.com; s=arc-20160816;
        b=dC6EeCJh5/3TLWUFvdW6L5NgfdCRWLGdk8BtLpH1cYAT/7aA322Nh43+WslArhjw8p
         RBJE6aHyodH2BAqIr+oyNxfPdndeytEO9n1VHTi2vNaC6IX0VScW+ryYyqYnN0pu7lgR
         0QbaQ93qk3qwXP6gYA0PzGl4wcOXCDtf8fRLF6qortiDqqIkYxgU50GZM6pzEHn5TSIS
         0vaSqsMV3WEu9M8vEC+WZxqtRRl6L/Xjwdur9tpMbF/7k1cbkxqnYoyv2RyJ/s9wG2nm
         vfay1TYZhRncHMl6Hk5LioL4HlOpirNgpyc5eMAv+YZ/+tgoL55EV7YmPjt/y6u+jJJ9
         fTlQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=k0PEOHEdAb4y2PTPOE1KxApVrKZStztANNCCBF33TkQ=;
        b=AXLXz+tqsEfNMIjTrl9R9nfumr7YuI1BtXc0msAR5UZnkI1E9+fnspwm+lcftkORq9
         Qcjqe+7OlZO+XCb0A1Za/x4ef7TZm3N8JVYJmgTa7HCk1dQEPoIlceOOkoaleyawSO2h
         XbH5BumG7+1hBc79JYgF3jS2oVnlS6jgmyF3ZGaBCbJ5VqAZn6ERozZHaecQflDQmKyL
         hu2tF1Ew8iTtghjO1OSqGiZZZRoSqcBedVjMKsEjYQ9qFYfqt68UO4vCIMhCe3Xgd4Qd
         9PvF1vszIKnZLYyeT9CXDdaSDCZTabGRNjIsXLXX/MWq6vmXpb/JenoEtf9+MTioCjhn
         rWcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id x13si103305qka.3.2020.11.05.09.42.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 09:42:47 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 44E29206CA;
	Thu,  5 Nov 2020 17:42:42 +0000 (UTC)
Date: Thu, 5 Nov 2020 17:42:39 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Will Deacon <will.deacon@arm.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v8 32/43] arm64: mte: Switch GCR_EL1 in kernel entry and
 exit
Message-ID: <20201105174239.GI30030@gaia>
References: <cover.1604531793.git.andreyknvl@google.com>
 <5d9ece04df8e9d60e347a2f6f96b8c52316bfe66.1604531793.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <5d9ece04df8e9d60e347a2f6f96b8c52316bfe66.1604531793.git.andreyknvl@google.com>
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

On Thu, Nov 05, 2020 at 12:18:47AM +0100, Andrey Konovalov wrote:
> From: Vincenzo Frascino <vincenzo.frascino@arm.com>
> 
> When MTE is present, the GCR_EL1 register contains the tags mask that
> allows to exclude tags from the random generation via the IRG instruction.
> 
> With the introduction of the new Tag-Based KASAN API that provides a
> mechanism to reserve tags for special reasons, the MTE implementation
> has to make sure that the GCR_EL1 setting for the kernel does not affect
> the userspace processes and viceversa.
> 
> Save and restore the kernel/user mask in GCR_EL1 in kernel entry and exit.
> 
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Co-developed-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105174239.GI30030%40gaia.
