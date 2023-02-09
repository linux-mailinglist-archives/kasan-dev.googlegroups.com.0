Return-Path: <kasan-dev+bncBAABBXMRSWPQMGQEK6ITZTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 7E37869114B
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Feb 2023 20:26:23 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id z2-20020a626502000000b0059085684b50sf1476924pfb.16
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Feb 2023 11:26:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675970782; cv=pass;
        d=google.com; s=arc-20160816;
        b=lka6NDKtoHBQpBFOQCN5xCd8XtAWzPj471L8c/JpMs6eSC6lUj8gq3LrhYHv3Mq7MW
         rt+krC3vqQ8dRUqUDvPScKi3A6dtBFbiuWwEFqHztOwBnbnS+mR7WxpNl3oHXfVUh/99
         AM2+cN9ICxr7VGoT858nR2nVvi5FOP0hlA/gRIU4Dxiw+yvLxP1sFFNdMYRsdn7Mi/pC
         CExtM7a2hg7cXyMboDXY+1kW2DzAusHl/9oXsJIwqYYDH1BXCwOhSNPYGrDogJCaMPmk
         H+Iq/oHWSdIzlc3hXagXupRQorZGpF+q+0UI4fEZ52brbMelds6zzcHCcZegKptMdQgf
         DLhg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KOKRq6CFJh4MLl0wlNvoV2L/1qrJJpX+ZYeV1op3bQE=;
        b=Pl1h7of0kbXjntT1Ls+KrKJRufMHiL17S4AUCTbCtMo+kS6df66WcX6WV+camazNVS
         sQwuoVUMzl0G7O6ZRsKMQt4ze7bB9mpw5CC8EqBZH00tFlARfQgJG2pMNsTuPvdNfb0r
         65s/LAcdJPU0nBbadzStih2v89YSmtYcM4dwpoaCuNhCgkqf8J8lPjB4rE7QdCIK5coy
         uVNRU5HEZFn5SB8ORYmWyne2p9rQrvnR21w+12l0UYu48yGjY8+4MvicB8JukO6xvPUu
         1BBmeWN34BaXv4SyAdkwtsE2uzhDzq/RLLslpVWziRml/25q5SGtTGeVR9fGp4uJTf3R
         bF0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XmESZp7G;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KOKRq6CFJh4MLl0wlNvoV2L/1qrJJpX+ZYeV1op3bQE=;
        b=DVEuUTKPLPP0M/Oh25uSq5suDs5/qSS36drizHGLDVvMV9eBJ6OORtlRxcmOKZNPG/
         AefDwLk1WnlKPPd7sWZ81rI0Ko7QVz827H13O7h81HYDr3vxx8bv6xHtAMYJwGsPNRlg
         E3UAr0swKuEfNKAeG8eh7o4ez2hBRPz5whUx5d71UHNmEB4Bury1xS8JqPcgljzA6RXa
         lZUb1uir7LjHP9SdiSnlX8fJjSVS0H4ZX66IWwWK/XTAnicYrRBHf9ZY9ZpLGwRY7Ljx
         YMibZhAiK5+cJJicqiwxmaJf2nsoCoO/3x+MsFVg9UurKMfpQywwGOiuV78zm9g0sAt7
         szlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=KOKRq6CFJh4MLl0wlNvoV2L/1qrJJpX+ZYeV1op3bQE=;
        b=ohg6Sw/6xv9T94U+i/PEX0KrYrGsa5fKxmWm7VdieQnrqco9GJ78FtB4CqFOH1B2Kv
         Wh3DOxjw8FOVYtJep/3blTi/m5BXsg0DY00iGFtiOAL5qzPoPTkJXYghhS6UQPuu45b6
         9dHuP8DEo2HILYWbyqKdY3MovZuXv6+6RgfVxYgSfTsxVdQh1StkugzjNc/nOYC+s630
         PEBDr1okr4qmrdluOZWLh5Q4k1Apew+g1L+q0/aM8yF2Wq/T9QtoXvqhsjiFKlGuvD5S
         7+/b+7wIdp7snMtRlmUK2DSp3VZ07oqe/MdWGiDhj//xLrzHBMIJFMsOYsVX/dDGX0Ox
         L9xQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUDuEyb8fnkQ0lDTIpqeQvRxLJ6KEjGZ0OJ+2ZgjoFeGuFSmUDR
	dtsueJI3KzzLxQuKPd0c9wU=
X-Google-Smtp-Source: AK7set9BBOajsCNsLCCEkKMmvBYUtxywMJLlriK+xAkHIbeRqC4WrzmIxL7djsgtI2zjk/VMjcucQA==
X-Received: by 2002:a17:90a:600d:b0:22c:5fb0:e36a with SMTP id y13-20020a17090a600d00b0022c5fb0e36amr1819456pji.29.1675970781826;
        Thu, 09 Feb 2023 11:26:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:10c:0:b0:4f1:7806:2186 with SMTP id 12-20020a63010c000000b004f178062186ls632249pgb.10.-pod-prod-gmail;
 Thu, 09 Feb 2023 11:26:21 -0800 (PST)
X-Received: by 2002:a62:1ac6:0:b0:592:501c:8968 with SMTP id a189-20020a621ac6000000b00592501c8968mr11351538pfa.24.1675970781244;
        Thu, 09 Feb 2023 11:26:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675970781; cv=none;
        d=google.com; s=arc-20160816;
        b=qzxKn6Uf5YGzO2Ue+akrO6LhhDkh019dSfMhOf1uzAyx2g1cbwW7VO+P4zZdiRa9/x
         ZHb0g7k7G9rY8cBdN5HH4UB0EMHMC7TqRhXzAUMtRo0CEJOSyAl0/F9lPDgigRhecQKE
         FBSoN9MLIL24AUF6mqZFr3zGfim6Fnq955lmiVOfwxXnL+PEDBX9ZIxh601q00d7FwPX
         bwbJ4ZDQwgLtYsUM+HumwILfj4I7qk9FEJPpHXcLDYwh8YXCzOnzfvH739zyaJTmNSCV
         96nKW9VUvctjz6GiFK+WcdZE1lgUqXtkKBFs9lhmIAzHPjEZz0GBjUwIGiDK2elFyP68
         FJZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=gvBaG09Lu+oeMJl2pMFlzuYKwehTo6C72FhtY5iKsOs=;
        b=m7ypWVXOUd4cr1c1uGuqCgPE7sat/02eZdTe6jPtAgEXYqoI3t7l7KGUb/RI1Yol7B
         r3Z8IYpwBSOVngxoXscNTwQKKiPk2pjjvwC3dGNSDHvD9QNMac/J+RCZ5CKNzc9ovnoZ
         oTyOcbeHt/zl1I+oXe0G2h/0Gr9lLns5pkxQGLkfzs7m/QTcv2v/lmW7tz2qYAf5/3G1
         s3k12C4/VdeuC9ww16Bfc48bJ45mM57oRubsfOtaa3SV20DI4sfa9wCQlp6nZztap5uc
         JXpYU/W+4KRfpWvQJautuiUTiKIsYW2dtQKonfwTywNsX8UYcr5wucsv8io1+jqmItRv
         Nv7A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=XmESZp7G;
       spf=pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id o12-20020a056a00214c00b00593910fa1d3si177516pfk.6.2023.02.09.11.26.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Feb 2023 11:26:21 -0800 (PST)
Received-SPF: pass (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9861061BA0;
	Thu,  9 Feb 2023 19:26:20 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 83EF2C433EF;
	Thu,  9 Feb 2023 19:26:19 +0000 (UTC)
Date: Thu, 9 Feb 2023 11:26:17 -0800
From: Josh Poimboeuf <jpoimboe@kernel.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Arnd Bergmann <arnd@arndb.de>,
	Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH 1/4] kasan: mark addr_has_metadata __always_inline
Message-ID: <20230209192617.mc4fvwe3ryyzdhve@treble>
References: <20230208164011.2287122-1-arnd@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230208164011.2287122-1-arnd@kernel.org>
X-Original-Sender: jpoimboe@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=XmESZp7G;       spf=pass
 (google.com: domain of jpoimboe@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=jpoimboe@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Wed, Feb 08, 2023 at 05:39:55PM +0100, Arnd Bergmann wrote:
> From: Arnd Bergmann <arnd@arndb.de>
> 
> When the compiler decides not to inline this function, objdump

"objdump" -> "objtool" here and in patch subject.

-- 
Josh

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230209192617.mc4fvwe3ryyzdhve%40treble.
