Return-Path: <kasan-dev+bncBDAZZCVNSYPBBH7U6WAAMGQEVRCZLPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id 5AE4E310E43
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:02:24 +0100 (CET)
Received: by mail-pl1-x638.google.com with SMTP id o9sf4773690plg.17
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:02:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612544543; cv=pass;
        d=google.com; s=arc-20160816;
        b=R4bY5mqgPBX2LZ00N77sMYw3ZhJO1wE5+xE/8ZVLvjYJXMJFuoKQZi+kMHTFlmlrS3
         FtUJZiRCthidtedIJ0iUhsAesSTtcc+fU8tMlCqXMMaaKmPWZGF1xeunky4IaBbi17Np
         v2cLdK84/Ai6CzSYjyTJf6fW+3NyHBEZ/0PZqQgfoYTJ0upzm0iWFUwwSgZ8WBi3bGvB
         jgm5aUb47ZXXGbw4OJPm1DkC+lNidIZRKANPdv8aqCwI7upL3QZA0e0tebh9weYCxJBf
         OKrmQSYm7ern72uLPQnIPdJ0gHJGZODucgyVWdJszIjOhg9RTOIIthHRt6AB9y6sH6K6
         NJ8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=zuZcAxeqrfYeu2CRLGgHxjnRG6SOYtujV1k/b+xbd8w=;
        b=PK790Ojv9dwEtVYymB2oZ3nOslHIRCXeUyT63gEB0JYf3081j/2lOQJa/1SkxKuVGU
         HHmUHynOmWEvEeNH8be94vUoppQBdGCVlgrYcraZBhvnXF6+dCsp89Exrc22MOP/rhJe
         rk6YHz3wkgesp9c+uJPlexhr9m1TMtobD9st3BOubPAhvRkgAgw7nVlV+kgs7nxIMEoR
         NJLK83yU2X1D9mC3mAG3eOiS1q2NC+nXOzHvVugteRj54RD/PjVbDdLHSQQ+m4pucOOh
         DZck7ncMWHNo8Vi/6tzCD5MvvyLmnpLizo7n8vP9m2x9ylEdaFdA0z7eDUkrDv0mon39
         dfZg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k3+Grm3B;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=zuZcAxeqrfYeu2CRLGgHxjnRG6SOYtujV1k/b+xbd8w=;
        b=QuHDFf7oAhPpIqpj2yPeZ3dYlY9Q6nZCxhkzSNiBTXQkGUKPWFXWo50YaIsh1HrR/0
         0CgiOOMYXQljVWUf8BSZ7Rj9kYqrjqtxPGqeC60g5Qh9f6s23hDMq9Mvk8/ELVPcqVO2
         x95V2Zh+UsKkSTM4X3LYn41+Y19473uif4IdJ3bdB9IZZgEQJRKMOuwkPUC48KJZw2de
         9RKLPoeh6Vm+/aAVZl0bhL2KoCPDkBtRgrayV/7sKN4/BbQSDzG6JAWzYhIZ+TuaLA4B
         +yWlmhYnKRrUtw3jRFT+efbR963YUDpT3i6thDoWrIIEg2zApFM8xOfsq4FPueSryBrE
         Yerg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=zuZcAxeqrfYeu2CRLGgHxjnRG6SOYtujV1k/b+xbd8w=;
        b=nD/Wv4n2jjad4KOiRnbqyfUQHQ+l+lMLXT52M3Mm1W96WoxxrCEgFVB0sf8AgWZOI5
         ap9QfHl6iTLn5sI3JtczzpSUOlmNG99NpJ0toxN95c1iBPVwf0ZWUDoSRHtJ+iVz5hyl
         s6J0M1teaL/OGre6HNmVtNmgr6cI7ntwsb0FjWV4fI6YNfw440Uc9qqkVFsM7tAfVsIs
         doduFA3JqN70X33yibBAyN0YGkVvpr8Tjrkgc48K3GMnApdxEoWKe+moSuMYQ55NfZkT
         3lr9rC+MEyn0CpDoktbdjuQwiI2K5DXsHpHfuxex7+yJ3tQjIKCRBBd9BssyQCaxZFVd
         bGHQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531RN8ARuMH44PLGtFp0t3PEUkUhZSoyjQSgbXBUXkjSYRYGvwQk
	yvSnu/vC4rfd38oO0+jf1MY=
X-Google-Smtp-Source: ABdhPJxlDJ5EBhQBoxjOEzSdMcCbkLncjsdx06EVB/6xTEcBeQvfYmLdsZ/RSaQZsfn6Fu+JBBzTHA==
X-Received: by 2002:a17:902:b40b:b029:df:cf31:2849 with SMTP id x11-20020a170902b40bb02900dfcf312849mr4980530plr.33.1612544543125;
        Fri, 05 Feb 2021 09:02:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:c401:: with SMTP id k1ls4066298plk.1.gmail; Fri, 05
 Feb 2021 09:02:22 -0800 (PST)
X-Received: by 2002:a17:90a:eb13:: with SMTP id j19mr4955514pjz.219.1612544542539;
        Fri, 05 Feb 2021 09:02:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612544542; cv=none;
        d=google.com; s=arc-20160816;
        b=EtA72oSpI7kf7sXhn7W9f1uhVnT1d7n7XnzCx6Lnk6oGvoY1Qb+MaNVkUFc0Kmliob
         V+zTDQVhvhSYl9sOv1UKGHP8Hi9L0F+0aoKbGjCOKg1tmdm2+Y4/g7C84r+YMjERjP/i
         DE/+0X/Ec3TB4LgvPdAc/CPXrc3cLXsi4ORSV8Jbmmzz/RweMAng6FbgxXFaRP4J/e4s
         1SfAm+vg6UXsKJZvmN027Ul+KABW+Op+ou5DAY03clqtK2yMIBClJC9gPpRR+rBq+BLH
         7fC2qkv7dFrdGztPEMO3/TlDQMwaiL2aBEjjY/61+sqY003rVzbWgLCVe6drV2vEYvas
         JkWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=h8s4Zg9CSEtlDm0zTLqyfUpI7kAi/vtDZXbyDIPvLM4=;
        b=mYDXZ4vYz2zjHHW6EcLEPShCOCYE1NJCjVoum/INAfSJxmCmDZG3uCjrU0DbuuIdnj
         QA65BzMOIqpSLrLnLrZc1C7e4yCo2utwpDJiOFPknZ/S8QQbZyg9vCZnggt79bWnJZTw
         l7/4ia5h4okhXJYV2Yi+FqMqlrAx4vUexM29OxrE/imOrjSn0whUH/WKpeXxMDwrGon4
         aryHcnSPc4jJQm6YaAtA1numMGzB2UTfnEa9nUEA1QCX7EHSarIB52KrKqKRRwGq6Bpx
         IsVQhqrfxVwThdU0ocKmnSZlZuGuAITPXnhB4IaiNoE4z0WIXAGV0krQ0vnjaWUPMChq
         ix4g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=k3+Grm3B;
       spf=pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=will@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id kk5si214009pjb.1.2021.02.05.09.02.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:02:22 -0800 (PST)
Received-SPF: pass (google.com: domain of will@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 1F82864E37;
	Fri,  5 Feb 2021 17:02:17 +0000 (UTC)
Date: Fri, 5 Feb 2021 17:02:14 +0000
From: Will Deacon <will@kernel.org>
To: Lecopzer Chen <lecopzer@gmail.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Andrey Konovalov <andreyknvl@google.com>, ardb@kernel.org,
	aryabinin@virtuozzo.com, broonie@kernel.org,
	Catalin Marinas <catalin.marinas@arm.com>, dan.j.williams@intel.com,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>, gustavoars@kernel.org,
	kasan-dev@googlegroups.com,
	Jian-Lin Chen <lecopzer.chen@mediatek.com>,
	linux-arm-kernel <linux-arm-kernel@lists.infradead.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	linux-mediatek@lists.infradead.org, linux-mm@kvack.org,
	linux@roeck-us.net, robin.murphy@arm.com, rppt@kernel.org,
	tyhicks@linux.microsoft.com, vincenzo.frascino@arm.com,
	yj.chiang@mediatek.com
Subject: Re: [PATCH v2 2/4] arm64: kasan: abstract _text and _end to
 KERNEL_START/END
Message-ID: <20210205170214.GD22665@willie-the-truck>
References: <20210204124658.GB20468@willie-the-truck>
 <20210204145127.75856-1-lecopzer@gmail.com>
 <20210204145547.GD20815@willie-the-truck>
 <CANr2M1-=ONun5fLNoODftmfcuWw49hj9yXsrxkqrfCEtELX1hw@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANr2M1-=ONun5fLNoODftmfcuWw49hj9yXsrxkqrfCEtELX1hw@mail.gmail.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: will@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=k3+Grm3B;       spf=pass
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

On Fri, Feb 05, 2021 at 12:06:10AM +0800, Lecopzer Chen wrote:
> I think it would be better to leave this for you since I'm not
> familiar with the relationship
> between vmemmap() and NUMA_NO_NODE.
> 
> So I would just keep this patch in next version, is this fine with you?

Yes, ok.

Will

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210205170214.GD22665%40willie-the-truck.
