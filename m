Return-Path: <kasan-dev+bncBDDL3KWR4EBRB66CSD6QKGQERQZ7BEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F2442A82DD
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 16:59:56 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id v29sf1391186ilk.16
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Nov 2020 07:59:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604591995; cv=pass;
        d=google.com; s=arc-20160816;
        b=sNT3OOe9FsLSVIpm8c8BT0fqD0yuR4MrcVkvV+lqkhsxFf1do5nLikFb3fSi4LHdSO
         Tn1kgojyCI5ds/ea9PGLel3fm4XVXjyoKJc9CqVdVWr5B7fYj0W5hWkTkHOz6X3Wc34z
         y8QhcVOyZjJ2QaFnZpBmFmDewk17NFOA6H6gQeqvIQ7Z8L5Zke6+ltLK3kW59j7lIQLV
         US5QHZE2Ds4Ig3ZgCTuzhbSRqX9ntnttevm2dxisJiQyBK/l8H6vmaCZNSkwS0/zxVSO
         UJ3tk93OY0POl6299D5JAuw5LNk8j3uu9cVe6GAoR+GHSnQIFjGUmASxZ4TtdMipqmIH
         CKkg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=tnv5/kcAwpz5iGSI/iQWG3gw6TG0quiGM/SxB1dT9BQ=;
        b=G4nWrRC9zBXovif4YJGmeR7yBrk/gAZBAfp8lsGdNO3yoSGadOXiElJhPfYt3BvG/p
         ftbMx+Xtd2UuSKqJruddEdomimIP2exKQZoAPvVWfLKZQ7SwDDMQrjOJIFck4IFO/knD
         h3zGFWl0ZhR8n/RnmxFwDMYSTTCLh32VsqHfmMRkkhDnhBgfhRbdK3INPGFLacEpJDiQ
         kkiOZ3JbHUN8SAv883k2RruYp69eHbzQF41DhqGXoTTnfoZjc7MCSKWSmIB6eqVYzBvw
         UiPdGO1eNFHwISc/A8TxSVe+xxSiADS3r3WjxSPuEhL6nfXXxfTs6HjSfG54fXDse0BI
         VB+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=tnv5/kcAwpz5iGSI/iQWG3gw6TG0quiGM/SxB1dT9BQ=;
        b=KtGnktAN3+UXQnEK+HBKBp2GOYnCuDITiLOS6s0d6HP9NEiBSFTtFTFZ++PFJ5/3xO
         IrwCZERcO82tPAr8rvhTvz42Wi5FPbLaSRkAC5yvxEehD26nkJScQ5V33X43fASl8Sti
         rZcBqL2yJf174bjLaNJFkIvlIRsIjhx+noOP7+7slzrp98WjdtZBgHFkurHuqsSYJ1Kv
         NTPP/C9CvlqvP0o+28GuRtjc6yZ1mZTFoCdqGad66kG/u444KmawBfH/gFKZwWCAVNfX
         /vq8WYAQe1dhvWN1kRXFWXILUSassrYWADLUvzFXzHeiDnnUyrWx8AGUJpK/qmG1BoL5
         ynDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=tnv5/kcAwpz5iGSI/iQWG3gw6TG0quiGM/SxB1dT9BQ=;
        b=eyfSLosxMDh30qPqamRiiR6Ld1ySSJ2B1fOWwJA120IYfA0rvTfuCbxCSNY9W3qPiP
         3QhjZv5WRXcQAyiIDOsd9CLIhBj+CZWVtqS/qvISyjlYHI8EZxo6tBDWz3ng76w3FuFf
         U0ETTBHR7rvb1rEqz3888DH44zxqJSq3qCqiBun/Z+ABVbfITRY0vruPoBS1fBO5bkll
         8jPMYQEH043m3/mRs/qwR8dQsRP9pdo6sYeQG7KfzpxfM6ukMv9P8dE27GxRT4r4ZG2w
         2eEr/3FOzbVHnX5VEa8ftD++p0E/fLlr//kEZXty3IidLjXl3RLxiHKRMnUD8CCSN3nh
         LOyQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533KSfa/SBthlOdw4uP1TSk/XXlCRCyA0j2nEbbZZGNdi9Bgr9hs
	DmY6O6m3CSc1TxQ/hd6TDwc=
X-Google-Smtp-Source: ABdhPJxWE2NBRQMqVr80ULKgOiASwTJJ3i6t91RGFw6EgMZIiDzvQ2c0T/wZxYIaNQ0uVUzrtpxzsg==
X-Received: by 2002:a6b:bbc6:: with SMTP id l189mr2183210iof.145.1604591995295;
        Thu, 05 Nov 2020 07:59:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9a07:: with SMTP id t7ls383571ili.8.gmail; Thu, 05 Nov
 2020 07:59:54 -0800 (PST)
X-Received: by 2002:a92:3554:: with SMTP id c81mr2410938ila.265.1604591994770;
        Thu, 05 Nov 2020 07:59:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604591994; cv=none;
        d=google.com; s=arc-20160816;
        b=VGl3f2IUG+rJyHeYMe4aSxoisSNWaia55neAeC+ghFAO7myMnF4Lhsi/nN1tv9/ReX
         y7RoHAXi6B0MCw3DxaWGijWqRfoihX0PwMQMgQpxDcsNbllgDLcQFQ4oauS1QdJV1nL1
         Wwl1bqPfiv4adyBpAIueMeQGZbuf4M8i39sKH950IxgyEgX6xTjGxfr5bKTlw88DmQjv
         0kOvh9rlV0QTxQCxhb1bdetKHFKkC1/mqHJ5/7Z19EZ6yjTBJKKUzCO6Hpt6bJcV3eAy
         9qE6MndFVyWGPyblWdEqgUOgzhvDeAAjQIFfGV7aewKbjb0myY8zTdRSkXmgWhjXYRHH
         SqYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=JVs7kFKb9HsFwSxuMl7/vjGXderbTidoBJvKSDkOZKs=;
        b=QIrRlY5jbsZFEYSEhNv0ytFKUldUOXZJbGJuzHBZb/qDIkncUzVqdX0mSASyNVMNuD
         d96BqUDR06V4ipNQtmKONjQp7klf9vXGLl17Ece5YZbd7KhAOUIQpG3lP6YkKzNFHml/
         7MwFFReJC6g8QS3QnTKk2m9U3UsiYat8+0y1F2WeoP7H3vXzyEGicEkrIxITLtsdLOR4
         hnrOqoHfWwUpx5eYM7zpg+RPfzMTgVpYk9m43MpgWhLkqee9vMbHRNRmizGjj5JYgXiz
         1Ui3tBWHaMM1ELI/Y8DnGyvp9+x2UE40DXFE/rORypgajYbKdbJ5FmMLr1hGi5AsgY3M
         4nsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id l1si122362ili.0.2020.11.05.07.59.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 05 Nov 2020 07:59:54 -0800 (PST)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [2.26.170.190])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id BB4492087D;
	Thu,  5 Nov 2020 15:59:49 +0000 (UTC)
Date: Thu, 5 Nov 2020 15:59:46 +0000
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
Subject: Re: [PATCH v8 17/43] kasan, arm64: move initialization message
Message-ID: <20201105155946.GB30030@gaia>
References: <cover.1604531793.git.andreyknvl@google.com>
 <eb6ecc9ca7d4dfa653fce0012bd1651e157638e8.1604531793.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <eb6ecc9ca7d4dfa653fce0012bd1651e157638e8.1604531793.git.andreyknvl@google.com>
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

On Thu, Nov 05, 2020 at 12:18:32AM +0100, Andrey Konovalov wrote:
> Software tag-based KASAN mode is fully initialized with kasan_init_tags(),
> while the generic mode only requires kasan_init(). Move the
> initialization message for tag-based mode into kasan_init_tags().
> 
> Also fix pr_fmt() usage for KASAN code: generic.c doesn't need it as it
> doesn't use any printing functions; tag-based mode should use "kasan:"
> instead of KBUILD_MODNAME (which stands for file name).
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201105155946.GB30030%40gaia.
