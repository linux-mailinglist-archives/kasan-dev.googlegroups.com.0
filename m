Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUXFUWAAMGQEYW2XYJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DA862FE9EE
	for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 13:25:56 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id n8sf1153692pfa.8
        for <lists+kasan-dev@lfdr.de>; Thu, 21 Jan 2021 04:25:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611231954; cv=pass;
        d=google.com; s=arc-20160816;
        b=vlkfTBQNnhWkOSLaxMbIykGqNTTlNkyluMwdczCFP0Wdn+z5wnLAYwjnqRe/RVqIqS
         tus8Ddb3/RXESGcbswbXJfv7y6RCVEk+mrEPR7w4pnLnm5XXJ0IctI5fTE3nzM9Vq/HY
         gbzeOft4aUoZE+cutFc3LTb7n0XXC4EEkFeA9weN74LBQCm3FR4OT3UEwOuhBBpHE6Dn
         RpYV7CILodCdi8SSTAPy6SHOyo8F77R8Z1YSsM2rTFBbg0KMrRmRXG1+XKlK3BCFLvXb
         H9GoWcuQtAmavXhxAAth0k7jgZ4gahesKYh/DPKl1p9d6Y5D8hEh/mQWFklrf1Ro3UPQ
         Eubg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=8Ir27CumuKI/s3dOAAytr/HCbqRPaFhFkC+mJfhTTdg=;
        b=vWmuikkviO1RAMKUMnrhpDtUVFuv5VgbkON9/MlJWbsMtZarlMF/+oinuClHpIGLx6
         0wqa0LWel7QF+NOb2KVBk7Rqw4img3/447lC8HHB6uYi9aIm+mJeHjcXbFOpF2rxIDD+
         PWIbg0CEa5pTA0195RwGlTiRvSKS0HmLhVMH9UTkXtbQKjiEanNvnH1kcWRkvsFgNfnI
         bwLVxzTQwE18EzL4P2AdJH4ekz0RmwxumOAJ5VA96N0j0Xfsvmy9Xn2rxpfqQlM9Oqe8
         5qhUWR6GlAWesu79USaxHwkFsGdl4TjnmpwURhzl7keYEcTUVGNDEEwHtpCc5CkxcH0k
         SJYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vxEAz+Kk;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Ir27CumuKI/s3dOAAytr/HCbqRPaFhFkC+mJfhTTdg=;
        b=oBRppKpQJc1kOgzqgCIY8fA8mX+5xaglAUYBvi64pVVc0S3/Q22EybcjRN0WAJPTCb
         9OaV4UHFfSZoFFjUoM1PFawDQplH9QaS6stVA5q/GHHSUMWXOAgQi0302W1+rCEjMYCY
         vU89ea8vbiMluq0dU2Kvdqu5uPIx1lDsMxbVjBPqBMw1pUogne9AdHXHmXBNKRbKlAko
         nY8PxYQLBEbeTzL4AI716A6RwF/tuZzmGIOMT9xtZsFFq4BVkAMiorW2In3KgWWmF/Pn
         0wXwneggleg0yCSDScea25VJOC569R0t6iwUzZgKojXg7Iuylse+BAnt5FYjvY2VWBou
         xUUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8Ir27CumuKI/s3dOAAytr/HCbqRPaFhFkC+mJfhTTdg=;
        b=bA4STD2Yyffn6vRWzwyNsBy8kjuqHs7qV75oUJ/uSI1Fk1oBbU5U+VC1OV4qwWhFnX
         kl+zfU2RNTjrwhi1BOD/kxgDDdsYsjP+GwO6AK6ZkEUMXDLICA+TNC/vQN/4ewCzni4v
         s9D8Pm5GDArjFb7aiH3vY3bOKRJM3L78/imDLlROQ/Tjc96KVwvc8PxGCWi6N9aPrxoV
         KS1bBVn8M0XkktayHxn7GjhvkWBeoufO1/mByPjTXXqpm7wF8Vo5g+hxnVykQm78gUsl
         qS8HvUlaQqemb2kMq4cM21/DqI44jRw5rZQhq+hq7Dub3+iVQcb2mVlNaNaIKi9q/X55
         FHig==
X-Gm-Message-State: AOAM531naMRxFErEKmrvPkM/ppWeVmmDrlsjDwL3h4W7oFODl6u1t7t2
	PHjSVTPocKL1MeSuB8MYbkU=
X-Google-Smtp-Source: ABdhPJwkDuEBNT2tqPfFW1uLuF8bVxj7fG35dvH05vThXY1tXiTCV1HWEPzi2Seoh3J3lFdErYHiEQ==
X-Received: by 2002:a17:90a:e549:: with SMTP id ei9mr11462289pjb.43.1611231954645;
        Thu, 21 Jan 2021 04:25:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d149:: with SMTP id c9ls838411pgj.1.gmail; Thu, 21 Jan
 2021 04:25:54 -0800 (PST)
X-Received: by 2002:aa7:8bce:0:b029:1b8:f395:87a with SMTP id s14-20020aa78bce0000b02901b8f395087amr13835143pfd.36.1611231954045;
        Thu, 21 Jan 2021 04:25:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611231954; cv=none;
        d=google.com; s=arc-20160816;
        b=AaeqzBaE4Y87Ru6BQHk125wx/1Aksv70TqmBNx9k9JPJWEkggyQQb9O3LO9njHT/ql
         K/q5lfnD+/WgX75s0QjVYesY2GhdfjFTl4Cyz85mbe1ZLhYnscC3qpp72RzO78wazCI2
         GMhQB/F6b+546/xYwGLgDO/dljt46x78PNYUZHILXG1Jo8N2CrGTMbiASz5FLa0MCDxS
         gyY2Y9Y9r4n4LpK7lE3TatqnSeQY5kilzI75kLAZ2LzB2rMtEttrwHkufaycgEsG0liI
         mXdTq23BP9otunNQ5+OIqVBhC99iFe5BGhh1wrNiCYijdXJWtfRGIDByOY+6jWpD61Ah
         CgNw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=oOyrg08vtxiHPYZkedOlgXvEt/7RDWD4URVSIByL7Fc=;
        b=oSvv+3mcMnr6LvL4EgWBOLdj24HiN2CdDgr/gmh8j+Wl9HsekrhpFXNdyXiY6B6wGq
         uHFvqisIrse1A24zmeh9zfJSn9uOmLN9IamKfNGJbYGKNS+Q8a4Cq22QAkDhz86ElHjW
         GNpoHn6TvQENj9HDQHvmKMX7vfQ2lSlI77N7i/TI9YgKuf8hv6IuwOiHq6Jcy3Ove2IW
         4GdK94xS2YroYenMqXt3DQXjpzOnaUcjIWU667/EFjW0okBYyuOPobng5c963vCoTKN7
         6zfur9hjpolp63L6ACnjQE7tpBwwimgtdOSb6IgjkO1opsdAhaOjbNq83dteAuKYwrMl
         sTow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vxEAz+Kk;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x433.google.com (mail-pf1-x433.google.com. [2607:f8b0:4864:20::433])
        by gmr-mx.google.com with ESMTPS id t9si899853pjv.2.2021.01.21.04.25.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 21 Jan 2021 04:25:54 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433 as permitted sender) client-ip=2607:f8b0:4864:20::433;
Received: by mail-pf1-x433.google.com with SMTP id i63so1394066pfg.7
        for <kasan-dev@googlegroups.com>; Thu, 21 Jan 2021 04:25:54 -0800 (PST)
X-Received: by 2002:a62:5c4:0:b029:1ba:9b0a:3166 with SMTP id
 187-20020a6205c40000b02901ba9b0a3166mr8574872pff.55.1611231952154; Thu, 21
 Jan 2021 04:25:52 -0800 (PST)
MIME-Version: 1.0
References: <20210118183033.41764-1-vincenzo.frascino@arm.com>
 <CAAeHK+xmmTs+T9WNagj0_f3yxT-juSiCDH+wjS-4J3vUviTFsQ@mail.gmail.com> <ed20df73-486d-db11-a1b9-4006a3a638a2@arm.com>
In-Reply-To: <ed20df73-486d-db11-a1b9-4006a3a638a2@arm.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 21 Jan 2021 13:25:39 +0100
Message-ID: <CAAeHK+xOcxNNNWosLZqTC1mOQZLScfDNwtTA0vCYTb8kc=UJ_g@mail.gmail.com>
Subject: Re: [PATCH v4 0/5] arm64: ARMv8.5-A: MTE: Add async mode support
To: Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vxEAz+Kk;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::433
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

On Thu, Jan 21, 2021 at 12:31 PM Vincenzo Frascino
<vincenzo.frascino@arm.com> wrote:
>
> Hi Andrey,
>
> On 1/19/21 6:09 PM, Andrey Konovalov wrote:
> > Hi Vincenzo,
> >
> > This change has multiple conflicts with the KASAN testing patches that
> > are currently in the mm tree. If Andrew decides to send all of them
> > during RC, then this should be good to go through arm64. Otherwise, I
> > guess this will need to go through mm as well. So you probably need to
> > rebase this on top of those patches in any case.
> >
>
> Could you please let me know on which tree do you want me to rebase my patches?
> I almost completed the requested changes.

linux-next/akpm should work. Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxOcxNNNWosLZqTC1mOQZLScfDNwtTA0vCYTb8kc%3DUJ_g%40mail.gmail.com.
