Return-Path: <kasan-dev+bncBDDL3KWR4EBRBTFOR35QKGQEW7PRYXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 21F0926E1B1
	for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 19:05:18 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id 135sf1828209pfu.9
        for <lists+kasan-dev@lfdr.de>; Thu, 17 Sep 2020 10:05:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600362317; cv=pass;
        d=google.com; s=arc-20160816;
        b=QXEakEp5cQmkT9WFwBRPwS9neAFttNMoArPj/HTzYiwGXymzOziSN/zasJ2oEFiC/w
         LK7RCWsycZVVhcUmq0xnC1zECUGiRW4OVEHBFyHgUm6R1D8pzlG9DLoLKjTAPzA3DpZs
         n+35jHjIj1blskHzXMh91p2QDcvNWfsY7MPFK81A6D6hhgRgPpzy0Z8y2IVpI3zIlIgC
         PF06AGGC+Wsr7hhE3DuXTVBpoGlkqjVTAd+RK9pA0j179z6wXTrV6GCOeea1CJfXdC/s
         tSaGcGzMBsxuJbOdJ2yMv6170NmKPeeJhD0+wF+XeK1ndWKzwLywOKgh70ha0BG887o2
         27qg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=4Q4+56glJ8UzFmkB8VQTbeDURXixme1sttJrFeMfwv0=;
        b=UnWeenPSwylKz+Z9rlvFiy1m4BuIZ/n2iADhpC3z4g7ptm+IQ2ak1/pMWoomyPUZgB
         +mOtf86mmI0XwFjbuU6A+e1sge47RfWIHElCAi3YwDYxMRhhkpuJ0iC9xXVsnNdKwtYr
         Ug1kggE6imFvCQv+3mPSp3nvum2R97VHIGhyJYd9OjNcJvP94iJqoF9HH2I0ZxbTXh7v
         MLj2bA2TkQNZ5dp3hmySg6HgXtwJB0ZG1TT5Wj/dzfALVVQY33cZjXN8tUrdEAemKi53
         szr80KYvsAhf/9O78/BIL1S/Tt+mf+Ov8JpDk+J0CXPan1xCvmi9HR3TncFq2tS/REwC
         zZMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4Q4+56glJ8UzFmkB8VQTbeDURXixme1sttJrFeMfwv0=;
        b=Mbsvr0EKVnOasSwZwZFhoRiZV/nrWzpMPRV2EdVBcFFQHwEiq5s+ChBfWzMzDfpqLf
         eXnUBTp7BBCFTFM6x7Vdp9joqpoCDZqvsTsT63bRRJuKJJnAQuYkJQCKnHcYoCzG/CbI
         LOGPufLRhrzvId2ItnF/tJ+aJ675FaqkEJeXkronurNaB1Z4/Sft4W1MXOaepfFlkNwF
         L0c9NMZP7bpB+WIbvhfu3fwFr+4Pg4foQ6OWnfKw1PoJzeN+t6CLD4HD8vfVpVdmQvYz
         3/HdCQl9orlvOnd9GumBSpsUCWrx7IAFeurnzZECoM0gmKGGFcBuQ5smINmcupGMv5Sc
         HGJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4Q4+56glJ8UzFmkB8VQTbeDURXixme1sttJrFeMfwv0=;
        b=Tz3FcDd9WT0sMX4IuJj52V+rmA/P5k/kX6j/JWDOTtqZlUWtggzo9rJlAGYW4nO/vu
         QZRqHm5mAfHvi4iv0Xnzq+VVIOgyzJDWZMMMaq0ulf5vYM1ERHKaK9oRLNEGO2EAu4j1
         GaVXev/GwkXRDLVRCjFI+519+YavHF7OZ+GFYmUFNwhOSi9CwYqWmL3V5jZ3jDRZZwlC
         i54WrlhJ8tNjXcSru5aHyYqWWDQBVdMwWrgGTeyp7+XmJvn96IfNuoTGrAy++mzcpq12
         VKQUB6QLEew3qpoolrbNWpLNe1WupB5QH9PNkE4Iv6T1fhIWXUswFpc7z5DL+8YcQxZ5
         /ppw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532TcRaaTcG6rZPPxERGGoihFj3oGlexpLmvBJhIvFhuf+ijxROm
	E+GfjCHCQVZZjRZ6175g6qI=
X-Google-Smtp-Source: ABdhPJzVPcCrCrc4QrXPZ1YdzhViq+A9L92lGUBw37tXX9HWDnUgH7gk9MP/i/8K4udnd1WEz709Xw==
X-Received: by 2002:a63:5726:: with SMTP id l38mr23317113pgb.79.1600362316845;
        Thu, 17 Sep 2020 10:05:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7c90:: with SMTP id y16ls1355206pll.6.gmail; Thu, 17
 Sep 2020 10:05:16 -0700 (PDT)
X-Received: by 2002:a17:902:161:b029:d1:9bc8:15f1 with SMTP id 88-20020a1709020161b02900d19bc815f1mr29325599plb.39.1600362316186;
        Thu, 17 Sep 2020 10:05:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600362316; cv=none;
        d=google.com; s=arc-20160816;
        b=FxWmYhpBC6n1CAdVbdyqUVEU3dKXpHpcR5wko4DYKJ85tobrPAVzhaB4N0RKc3aYHx
         lJjNCOGaXCKF/RJhloIWXeAHP9yVP32Hr83LTnExTS4PWK90SDLD/tSGyFIZpO4cS0Cv
         58BbSVF7vKYf94pjo6Q9de0qPDU22bR0hXe57NUqaIneLo8v+l/H9nr/oxqEep5cUE4R
         XHsiRrjzFKFd1thhrD95jTiyA0khmzR9vVFMLJ9cP+jUR0+2ZD9n394iH1Svv6A/KC7e
         Ov2wbeA3CYRv1yX1DTGE3NzPJ49kvTqCb+Oq4Za3+VMCF4xiyBYrpsF4f3g5weBwzTuW
         d0ow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=txIhjbaoaRqs3rUEcTvadaQMQedKZT+sycqDXXj7oAo=;
        b=xvDHg9dyEGXZvKR5vFn+YskfptPVac8/rUMyzUCoAQ1Vaqf+xrQB9I5UH7trFSbZ55
         wNOGkqv7KmsA9jmFCAPwBrYw9TJgAVEYpVEB/gyKgo8nJGTg9WkP5931hWK1ySIZC619
         n93ReWrXKR526klhVvqR+554sXU154ASRUm/BXF+64FNbBIQqQJqtbNBAPFQgKyxxFaF
         3iWu+NeUm1/EZ7LdfUQopZtIfjxRTdLIa/HzD1B1YNrNVvuk+bk37IcXfWqkyqjUsj9e
         QhRA6tBf2Apdca3REUehtlEyGW+SLKnvUVwpB1mdc+AfpHlF7mriYzGF5kzsA/NXnd3R
         R3oQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id p15si19747plr.5.2020.09.17.10.05.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 17 Sep 2020 10:05:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from gaia (unknown [31.124.44.166])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id 727E4206CA;
	Thu, 17 Sep 2020 17:05:13 +0000 (UTC)
Date: Thu, 17 Sep 2020 18:05:11 +0100
From: Catalin Marinas <catalin.marinas@arm.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v2 13/37] kasan, arm64: only use kasan_depth for software
 modes
Message-ID: <20200917170510.GL10662@gaia>
References: <cover.1600204505.git.andreyknvl@google.com>
 <b83ab742bda81114249ef81870a6f30023192cf3.1600204505.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <b83ab742bda81114249ef81870a6f30023192cf3.1600204505.git.andreyknvl@google.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org
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

On Tue, Sep 15, 2020 at 11:15:55PM +0200, Andrey Konovalov wrote:
> This is a preparatory commit for the upcoming addition of a new hardware
> tag-based (MTE-based) KASAN mode.
> 
> Hardware tag-based KASAN won't use kasan_depth. Only define and use it
> when one of the software KASAN modes are enabled.
> 
> No functional changes for software modes.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200917170510.GL10662%40gaia.
