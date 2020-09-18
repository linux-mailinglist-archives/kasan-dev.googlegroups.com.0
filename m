Return-Path: <kasan-dev+bncBDX4HWEMTEBRBPVMSP5QKGQEZVUEOXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 27378270147
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 17:46:09 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id m1sf4932604ilg.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Sep 2020 08:46:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600443967; cv=pass;
        d=google.com; s=arc-20160816;
        b=BqATelBwV4jfARmXV8ZW4ZYf/f6pOg7y4G0gRaZL2sdvUI4J47ed6HZCCVdcvMaSd6
         v5tneogAq4TpuG/gIILdkCkm4uTITKGcEAeQfituEOFE1J4kMuF79GKCAtJm0ZrKirC2
         FxRGV75pFxR3A2N7DW+nBdx//G15QyoImsd6C8sKXjd613uHhXbf/GaUt963WGEzyG35
         pED/eJvI0mp2gWBY2xH8cZKUT1fARubPfL0Ub7LdWC0uLUjl0BApM1f/omvF85CAiDt7
         CsZ5owKgAUVOqODLXRgScJclX2frCWJdLuXkAdtO3zncSMxbxDgerdj+/xkV6DBPK2UG
         z7iQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OaK1RM+sb9vm5Z6uU9Zf/3Up4xQPS7YatDLL0JNXtok=;
        b=VSJvJPBqXAFRPRtBEElsW7kmHBXf4XMhHJqQWvg2omEaFep+fW5sfKKFMfopKs8NNf
         xESVc5nare00NRNLk7iHA0odm163caiy/Lz2aaHOivfOtW4wDsRHh/v7EEY/40KtJ4j5
         Z6uuEPs/MebnrOaM33oBW21pgLTUeh3DLFaGDOQg6VX8vCEnsQOwTRfAOQgDuDxXDxxD
         IRi16HmflwOvDr9c8JfaW6mxr0LeuyrHKEczVXL3OnmEfKASmgBrG5baNvYgXJLix9Y+
         Fl2N8dwhgDFXA/Yyg3UKprcHDu1G7Nvx3HvxXa4kAwSBGO4/9hhif6W/NdA/HXygZnru
         irQA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DuSddiKU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OaK1RM+sb9vm5Z6uU9Zf/3Up4xQPS7YatDLL0JNXtok=;
        b=X7fruV+Tmhj+DBhue2cjFSfzHpa/1QRdYos2N2DrxhLAJIZAOOx1V4F/Yoo/gfl1ZU
         FvH18QyI43k+IjcP+baS5k6KFDc877vR30PXjMwqVhF/POkLtE2M+l/eZpIfg2RGaWld
         UNBObujJqzdK8cHWXlSdd0XmMIdJf6aeMrfLtps+8xoCo6MEfRSL5zlt/XPCKPAzFkhP
         lBIKWpTDKZYkw2Vt9bAHt1VAnSqSZKzOFSVZPwnbA+zQLSfPEFFFyZwrjq5zPELQYHVJ
         dTUUs9d93u6G3dVDQkJBqDo40HfysdGu7s6niExVJIibWPSPhN+oofNQb18Q7ZALsyKI
         JJgQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OaK1RM+sb9vm5Z6uU9Zf/3Up4xQPS7YatDLL0JNXtok=;
        b=nrvGJ9JYrrqKcDtXfrerahTIgShMYkWQA9Y+EX9MR2Q9MNBE+9+CvPeFP0iKeiwAhz
         l2tahgIUXhpmRyYLhTmf9amTgjmZd5ouWZI5C2O0eAQ3Ad1j83+ndsTcJwqRgRNZNBfC
         qoC87du/+Om94gdP0LKvWm7uWZclmxtFpOSVRmsgkoJVinvf81VgOscTUYHNKNvPwbXR
         Ah0lgOKY9CSLtaJCIBrK+QjPS1Xmg4alnkMITnVK7VlDnhIwR9w1G5S031O1uAy45S02
         Qk3UCK+5Tw1ggMzTiCQwkSeWuKwi6QOGQxn2bkA7198KFvCdoSZVsBf1BaaFM5VBZnhX
         KbLg==
X-Gm-Message-State: AOAM533pe6W8VLL4NyoZmdTfGOhUAoBKY7vO1Ww4PmyYH9P3oWurlMMC
	XoTe9oxG0MeFgr8xXzqP1QE=
X-Google-Smtp-Source: ABdhPJwcAXm8yQ++KlNjIJPN5aUF7N+GeKfawl0aKb+ASSBrORRS2yj1IXtoertznv9t4bC78DxMBw==
X-Received: by 2002:a02:c045:: with SMTP id u5mr32131623jam.125.1600443966759;
        Fri, 18 Sep 2020 08:46:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2ac2:: with SMTP id m2ls1017270iov.7.gmail; Fri, 18
 Sep 2020 08:46:06 -0700 (PDT)
X-Received: by 2002:a6b:b48c:: with SMTP id d134mr28057876iof.115.1600443966320;
        Fri, 18 Sep 2020 08:46:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600443966; cv=none;
        d=google.com; s=arc-20160816;
        b=PUMMnVYAboEshuWHgwG3HOmPBbqqCufUV69Sh41A3Ss0JVJSaAgMKTOlM5CSdW+nOp
         wE8LF46Ay4MaZMS4erw2jX8pHjLnLSgOUyJ93iwMuDNnoEcEJ+5B3y0zrwRG1UgBMo0l
         NFmBPw0ZiGngEubpndu/AsnzcAItjliUxJozza0qdqMsG7LW9Zqw/ZJ+N5vml7MjM6+Z
         rp8tEfIuEErWkHfgdhe1e4sO5zmXdCyHazyPuaZXuzIui7ydjsXlVMikaoeG7WRTZ/6k
         CVY7ASJeyq5A7J4K4jLRP4TakKwIxuacD9YjvJUuLPpiCs5NyzJjuaOGoY7pMYZMaytj
         cSHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hkgDDbxZ0ilYITjWl8C63+E3bk69jBdfnUZGv0u3+yE=;
        b=D/yxZ16oDfkYz6ZWBsyv16Fbck7z4K8ffUrDDIkh1x9/zJv3X9K19HQo+kvQIi3llc
         tpFzFMT/SFiLAK0unySCTJWtRHhedzzUmdiTf7pXF0nbXm/ElAfb1Ow0m9ngXtrFDYyP
         9E/1qeX8oO1cIkAwSgDp3GjBid9KNlcDc7wd3rK6g+RGsmr6g94p96TQzR1ecJZOvH0b
         GyJrTP9NQ9tMfnDcTdHmPwX7LzzF5Ln7dK2WcrCWl/Of2fKuMIJwANgjPZSAAbb8qayB
         GBPqp3uCWCjHUZ+azsmrzkdNVzii/woJ1EKKRvGBkeZ7A7hf1wNY1AIlArd8hcawpyrM
         7Kcg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=DuSddiKU;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id f80si255535ilf.3.2020.09.18.08.46.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Sep 2020 08:46:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id f1so3170920plo.13
        for <kasan-dev@googlegroups.com>; Fri, 18 Sep 2020 08:46:06 -0700 (PDT)
X-Received: by 2002:a17:90a:cc0e:: with SMTP id b14mr12978124pju.166.1600443965540;
 Fri, 18 Sep 2020 08:46:05 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1600204505.git.andreyknvl@google.com> <329ece34759c5208ae32a126dc5c978695ab1776.1600204505.git.andreyknvl@google.com>
 <20200918123249.GC2384246@elver.google.com> <CAAeHK+wF_tkBqHd7ESSa5jOy50AW1WfzSAM-qNf_+iMkLwptTQ@mail.gmail.com>
 <CANpmjNNrBX624GJWY3GK6YR9xoYX8BwstXaRYXJT1QgSFORSaQ@mail.gmail.com>
In-Reply-To: <CANpmjNNrBX624GJWY3GK6YR9xoYX8BwstXaRYXJT1QgSFORSaQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 18 Sep 2020 17:45:54 +0200
Message-ID: <CAAeHK+z5pqSYJifvpLoHNe83UaJSsuR8WdBS8-JOwgCeHTi8ow@mail.gmail.com>
Subject: Re: [PATCH v2 21/37] kasan: introduce CONFIG_KASAN_HW_TAGS
To: Marco Elver <elver@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Will Deacon <will.deacon@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=DuSddiKU;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::642
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Fri, Sep 18, 2020 at 5:36 PM Marco Elver <elver@google.com> wrote:
>
> > > How about something like the below change (introduce KASAN_INSTRUMENTED
> > > Kconfig var) to avoid the repeated "KASAN_GENERIC || KASAN_SW_TAGS".
> > > This could then also be used in the various .c/.h files (and make some
> > > of the code more readable hopefully).
> >
> > I tried doing that initially, but it didn't really look good. The
> > reason is that we actually have two properties that are currently
> > common for the software modes, but aren't actually tied to each other:
> > instrumentation and shadow memory. Therefore we will end up with two
> > new configs: KASAN_INSTRUMENTED and KASAN_USES_SHADOW (or something),
> > and things get quite confusing. I think it's better to keep
> > KASAN_GENERIC || KASAN_SW_TAGS everywhere.
>
> Ah, I see. So in some cases the reason the #ifdef exists is because of
> instrumentation, in other cases because there is some shadow memory
> (right?).

Correct.

> The only other option I see is to call it what it is ("KASAN_SW" or
> "KASAN_SOFTWARE"), but other than that, I don't mind if it stays
> as-is.

Let's leave it as is then. I don't think the code will get much better
in terms of readability if we add KASAN_SOFTWARE, but we'll get
another "indirect" config option, which makes things a bit more
confusing.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2Bz5pqSYJifvpLoHNe83UaJSsuR8WdBS8-JOwgCeHTi8ow%40mail.gmail.com.
