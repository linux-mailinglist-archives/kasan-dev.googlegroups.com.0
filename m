Return-Path: <kasan-dev+bncBDH7RNXZVMORBXHHZL7AKGQE35FGV2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id C772E2D6C00
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Dec 2020 00:48:45 +0100 (CET)
Received: by mail-pg1-x539.google.com with SMTP id q4sf5156886pgn.0
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Dec 2020 15:48:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1607644124; cv=pass;
        d=google.com; s=arc-20160816;
        b=tzxHvcvS7y/vIK/1NZuxedN3mRQn3GSVYYdFHBajQ3uCTTFdD/sYdvTfv/VulXAM3U
         ek2XxxGssr9kZC+YK79Hq3b5iETECrXf0CxfoQWmlSMKUgxa3F9/OYMF3NbAyvM24UmF
         snLwO4fciPh72Gk4YPZqTJ9CfVg6PRJ2uLDmPi2mA2IP6pPQzOD6pW5I8KQUIGKJRhc2
         QQdlO0XqpQpzmBq4oJnfUoZzQbaGrI+SBDGI6avY+m0TMrXsel1pBpL3D8IXBeTWyxsJ
         6zZU1iyozLprBD5pVxRipYhzLtZJwHbYUDTJbM5sPIuAyX6G+5fLEDZgUxbkxYjWAitb
         g40Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :message-id:in-reply-to:subject:cc:to:from:date:dkim-signature;
        bh=S2GkkPFsl+Ofzs2iR2N7/pAHiVSh9SXohUHqQHtTc6s=;
        b=CVG3F3vkXFYzjO+PPUlifdahUMpG4f0/nMgusJ4YN4JYfnAabZgol6ObzBJ66kzTxA
         jD7bsiuA1qcgmyTLCZiOtBkLuCpjeTAZScjYS+YE0H479myHAHrm0HFBikcYqNkGFSwS
         yBqkefPXNdTIrz7uPK9U0D26cJ5OY+d+x+kTcqMLotRCc3hjQp13bHfbCMnIl0YYMWSJ
         xDa+sQ6ZOhffQIDJOPgyxJGq6neE/V6YZJp9wu10nsnC9F/YQSJFy3Koi2NrRO0Rx6zV
         uC3OKJBGBekBpG1ft01Oc+efVGc94MzVycjGRPZmC42WBhAsPtB73oP0KHzDln0Pg30u
         EjGw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FayvgMRl;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:in-reply-to:message-id:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=S2GkkPFsl+Ofzs2iR2N7/pAHiVSh9SXohUHqQHtTc6s=;
        b=GBhSe3r8YSovAdCvxfHbroJJaUaNUspzhZr8UoW/UtILiWOS2FPHSC43TbCaouiF4b
         E/qSF64uPBFNTi2cS20VDSRUqdeVvwEvAeRALiPRAsvnV4oHOxbepytXXx8HcSlCR5t/
         N7B+o1RvKGgmO+AlVKwscdBuqwhzI+xobgJEaGSSZb/BagX1V0xRf25+qEf0GxbIhJkX
         uDfxhDUkh/0XoPYwiSuA9SlQ1KT7SGISQWhHZUyMQkvd+1mOySzkhBmWN9gSNZCRJ4jc
         4+SIuJ9vd8tLlkdjhqcTVp5MfuP3/6npYMckf6nfuDS9V7lekvPirspyoM8hoaX/V5Ot
         QG8A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:in-reply-to:message-id
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S2GkkPFsl+Ofzs2iR2N7/pAHiVSh9SXohUHqQHtTc6s=;
        b=fM6eFIw5PMe6FRzR0JbqSTGNiv//W4914Rdbz32qtaVWi3MM7ypi1t9ypJg3XxBDdz
         jw9ph9cHFJgDQuv+0d+UxqVV2YyTOuxro+KB9vw03vEhVeLGEdgXDYoF/1nDqJhSU/7k
         Q+c5wsDXvFYjisZ60oVok0NOdfr4uWclsf/KcxviptIqVXySJA+4ejEfO7ja2ylvvme0
         i8r2zoy5pCtlcw0Tlk/pGjf9oPKTIVZ/yXGkeL06Jtv4jGzUaFhVGHNhFEf0bP3J2yqj
         1oxyiHeQ20cpvMZFZPp0yufI1QnR+QBnpT/GcJBlRSuyfqOnFLwORSbvaFLvR/X6Z5ur
         6kFQ==
X-Gm-Message-State: AOAM532pS+Y9xVAM5WRanjLMhWurFsXNRhchXeO91+i0LXrCkzFlY0d0
	EvaeJA40uO8q9hLAaQu1dpU=
X-Google-Smtp-Source: ABdhPJzU+rZxznpWJZfIHsz4l8MI7MpAdpU6cTgkauKSTKamdUdUm1RjiochGRoI1EXuPcu5flznHg==
X-Received: by 2002:a62:19ca:0:b029:19d:cd0d:af83 with SMTP id 193-20020a6219ca0000b029019dcd0daf83mr9066879pfz.51.1607644124470;
        Thu, 10 Dec 2020 15:48:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:5612:: with SMTP id k18ls2632293pgb.7.gmail; Thu, 10 Dec
 2020 15:48:43 -0800 (PST)
X-Received: by 2002:aa7:9706:0:b029:19d:a2c6:aeb with SMTP id a6-20020aa797060000b029019da2c60aebmr8957849pfg.36.1607644123822;
        Thu, 10 Dec 2020 15:48:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1607644123; cv=none;
        d=google.com; s=arc-20160816;
        b=t8aXVYzER4s9J5hJu8oZi2vfTvmJLOKGeiJDyn8kJc+ivhO+lw77p6YuLVFzAkNcsr
         qYHpjlFb13fEMMDPoOKrflLTdWrGdo9Gd7OZybRRapYSx6056FQHVpQIuJSJSggUB0tc
         PfZEPJ5vATbv0H6koFSKkDuFCC4iTpjgF/vd3eccbQ2tW1c27F9kLYHOAwRpg//fYm5y
         XAfqhuTuBfgQ0q2AoI5VZONHVCa38fd37J0Vlf+1o4WIarjGUqQOz0WB4t4VBbOzG83r
         Ap3OghX/HfXLrd97OSCBRehLdTXTYdO9/4N8GDanebj+2/STZ5sBBb33zB/FxiNETYl8
         vcJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:message-id:in-reply-to:subject:cc:to:from
         :date:dkim-signature;
        bh=AG5j6KdzOrOIZlpP/G9Y3cE+K8n2ovOPbsXUJ+7wxSo=;
        b=PBMq/oxTkmRx/MWde0IQy4X5rky9UB3nCaiue70jp5FjWzlo6PIYvzgXIxGDimHB1s
         H454FRwvrMlosmqbczeJ7MTCW1ktFoWKr+iuziFJNwKWkc8Qd5XAzeGf4eiWTUa3ktVr
         mkEPTdaoMOtbvHK7iLMB5kY3XNV7qHSakBG5GOZvM6voCGFbnzua/WZnR7VaBEjDoKuv
         YOPMlKo5xacVTEgxZw6MALYx+XMCJcqYMDxpEUmzVz1Rq4Io5mEGFrcrENlgOyxtnThP
         +hf6Vn0jozoIR1LvGJoWLVd5lkwIRl1HLH2pZtv5IrfI6gPZ7NB8+bXiaEF1DEImewsh
         cR6Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=FayvgMRl;
       spf=pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::643 as permitted sender) smtp.mailfrom=rientjes@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x643.google.com (mail-pl1-x643.google.com. [2607:f8b0:4864:20::643])
        by gmr-mx.google.com with ESMTPS id r2si446551pls.2.2020.12.10.15.48.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Dec 2020 15:48:43 -0800 (PST)
Received-SPF: pass (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::643 as permitted sender) client-ip=2607:f8b0:4864:20::643;
Received: by mail-pl1-x643.google.com with SMTP id x12so3186796plr.10
        for <kasan-dev@googlegroups.com>; Thu, 10 Dec 2020 15:48:43 -0800 (PST)
X-Received: by 2002:a17:902:6903:b029:da:f458:798c with SMTP id j3-20020a1709026903b02900daf458798cmr8325001plk.68.1607644123398;
        Thu, 10 Dec 2020 15:48:43 -0800 (PST)
Received: from [2620:15c:17:3:4a0f:cfff:fe51:6667] ([2620:15c:17:3:4a0f:cfff:fe51:6667])
        by smtp.gmail.com with ESMTPSA id e5sm7184975pfc.76.2020.12.10.15.48.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Dec 2020 15:48:42 -0800 (PST)
Date: Thu, 10 Dec 2020 15:48:41 -0800 (PST)
From: "'David Rientjes' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Popov <alex.popov@linux.com>
cc: Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
    Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
    Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
    linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
    Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
    notify@kernel.org
Subject: Re: [PATCH] mm/slab: Perform init_on_free earlier
In-Reply-To: <20201210183729.1261524-1-alex.popov@linux.com>
Message-ID: <9c37ff7f-813d-3313-ea8a-fd65484e476a@google.com>
References: <20201210183729.1261524-1-alex.popov@linux.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: rientjes@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=FayvgMRl;       spf=pass
 (google.com: domain of rientjes@google.com designates 2607:f8b0:4864:20::643
 as permitted sender) smtp.mailfrom=rientjes@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Rientjes <rientjes@google.com>
Reply-To: David Rientjes <rientjes@google.com>
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

On Thu, 10 Dec 2020, Alexander Popov wrote:

> Currently in CONFIG_SLAB init_on_free happens too late, and heap
> objects go to the heap quarantine not being erased.
> 
> Lets move init_on_free clearing before calling kasan_slab_free().
> In that case heap quarantine will store erased objects, similarly
> to CONFIG_SLUB=y behavior.
> 
> Signed-off-by: Alexander Popov <alex.popov@linux.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>

Acked-by: David Rientjes <rientjes@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/9c37ff7f-813d-3313-ea8a-fd65484e476a%40google.com.
