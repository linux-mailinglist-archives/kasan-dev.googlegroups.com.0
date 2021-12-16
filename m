Return-Path: <kasan-dev+bncBCCMH5WKTMGRBX5V5SGQMGQEFYIKHZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 31C50476F39
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 11:54:25 +0100 (CET)
Received: by mail-io1-xd37.google.com with SMTP id o11-20020a0566022e0b00b005e95edf792dsf22944063iow.14
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 02:54:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639652064; cv=pass;
        d=google.com; s=arc-20160816;
        b=v90wFJTGG8Zfq0AWpo7u3RHco7pLJIpV1AvG/++Qhg5/3irFgncD3kPYPaw7NrUg5K
         Srvz7TyVAYt11PwH8TO7dWyBL4Yi0czS0cMxB6lmv3Wb9J7NORETFf9Ul9pw2nhGfBWx
         gvM/uLaMPrfzNdOIw0XhlfnbBMWqSFytN30xOVLKAJ/+n9VXFoKxzKySxujyFw8utckn
         AZ0lnKGTmfTXo2gPiB2xme935kqyNTDP6iyxhNo2dA1lwAyJSnsWqm4+wIm/dfFDsy2Y
         Q6FPzZWYPCuZ2PkK3tCwbnrxKyJcugPVa30iHWY3vmxVFiqeqKsVBXA2ev2+XmMzHUry
         pd8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=izd7Z+08AQ8zSNPne24vX5vgAvPmiWcG3aI5Li1mm9k=;
        b=0gG8WK7MBlUUENRpoj15TwcfrUICTm+0LzllE3IAG3ozTDBFbF7m069uYqsY/t8gjf
         +waVjlfpvMMaYZg3CbqxzFNF5MM1kFkLcsGOiMq8Ds2bZk0IlfDLK5pjWifB1wtmypsv
         cMwM6y/da54nALfH139mdh8OOdC8T2pxQaSyJAOLTIO0QGCEDaM/F4G2O3k4olPVBwnp
         2aIFsgVoqbz6bauJxSt3Vo+LLFfUBiZAtASfja/0Y0OYpSPWKG+tZEfDBabelJsHYz3T
         eOygtOgL0DGwAaL8MDetb7eygtE229lj3eq5jc9OupGRXLBM+jDJ+snh354FTDQGEw/W
         cQdQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lGKx4K34;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=izd7Z+08AQ8zSNPne24vX5vgAvPmiWcG3aI5Li1mm9k=;
        b=WIC4ESOuG29Wk31nrU7v1aqTadNcx0n0TjO1W/CI2JxzvAG6Sr+zxaF3l1FA6wPyjy
         WzBZjJZCc4fAqhO7lVzmjerU2UdyAaocJxJAN/CeEzehOd6AjrYUaQHrMUynZ0IzKmoS
         sPJ/h6BBh3wuv3E7Jtb5FRIVw2tvH4VZtXf8pqcPpju+BjDRUup5hM/Q4ssClyBbOsyq
         i99GsCa6M9vcEazcv2cBEOyIGvpkd7OJM0K/y3Ryb4mUftgxnRRBGbUawz0h/s2GXmls
         FNoGBIrbTTZGmlRuW0nhKAHNj6d76xIhbDQByUEtuHSLI4oAmLC3xAmXKmAMBoQDkf5l
         fLuw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=izd7Z+08AQ8zSNPne24vX5vgAvPmiWcG3aI5Li1mm9k=;
        b=58CvXjFPo10a/NsfH0tr8E9wOSzSWs/H3Ek4jpCZiJVxHopVF5G7MKiyUniDU0DaEl
         h2X0pFOTYIxfAAHu8PJwYRc7l8YyERdDjLEvtPO8XNzOvjzCr4dNizjcwyNoXkHODuc0
         XjbPCnhExJ6cgsRYkvjB8Xobee1hjAJwIpigEzsuyEd8JpsYMq1EWPtkyB3gjrEj00bC
         psN1QkBeEi6MOVxieCdlooSgZCFnDXKu2hWJ2AkKngOZNn9wvuvvMmEZ9+rADi0dsBLy
         la1GSalhxBIzEV1jBcRTbS+gcVkWoQI79UmEvLJFvAS5U6dAASWgRX8GHWMWaqlr8uII
         tsXg==
X-Gm-Message-State: AOAM531gVY0Gz4PgFbjqGQmUapj4kgHUwkI0le+kHKEOc6T1tev0+UGu
	WNpBDrPAEiG58SOSrsS0tx4=
X-Google-Smtp-Source: ABdhPJzaiTb8CalczJ1rQzMOTZazuVFqXldmSed2If7K7xTGSBgdDOdqMXe5nH1pFuUVHjVZ6lJziA==
X-Received: by 2002:a05:6638:3294:: with SMTP id f20mr8773966jav.222.1639652063996;
        Thu, 16 Dec 2021 02:54:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d085:: with SMTP id h5ls772715ilh.9.gmail; Thu, 16 Dec
 2021 02:54:23 -0800 (PST)
X-Received: by 2002:a05:6e02:1806:: with SMTP id a6mr8281931ilv.125.1639652063672;
        Thu, 16 Dec 2021 02:54:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639652063; cv=none;
        d=google.com; s=arc-20160816;
        b=mmNTbdPkk5KJNlWTe1DtT36ZeMUWjLzjS3ym5xvz5AxK2WH+1Wig2oIbkBMkIOmkvW
         IA8dZvvQkmmWtH/AGUDb1KucszPiPfcOo2CzV5N+0ZbmsF1taKbgHlLe6woQvrDzuwR+
         Gf4yPWxHmHY37VIyyFDO+Do0h7w/r6yHHHpzR3DrUoi9Uc2ABTUC2ZLxQNpCui1/ZK6g
         TBqvvsF3BhSkMdJmNrCW6nGvNbuKosL0Egu2tLZ2uhGVDrKATKmeoBJprDndsf786uEz
         0eIYGkgK9LaepWrqyaCWU61k0GdVYG/egkPWy4vSnmc2V9uOgvD+GVXcXoqNO0eP68R1
         lctA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qaq4AYvHrkraOXjSh4Dxq1xnyiNdkNmydNNcRNrMS9I=;
        b=KTg8C/J2fXBToIALsCeX2np9+6VFwYomEIu0ewGWdDGnpzwdWS7/B8J5WKl2to7OG7
         svgqESuOWsDiV2roj1ox1F97nznLyKI0dhCMu+MQqKfQh4pscwYxSyOuLzEexTqfudGf
         oEsL5TNXBFGg/Wz52jgNMpwXfFRfyfriEMlKquDg9LIrUYO0v6c+JmC7glcO9XwreKDV
         foDAGjW4OoSFp2MRQUKR23g7YdNnuN7mk6P3UM4UJ4ke4CWmPBEv/VNlWMB6Ot/6oTlb
         lYNSjQ6otY/P1G9BJrMvFJfYntaCgmcl8pWRrfO99qqo8gUVKBIG/ZEF5r4XJKfhJBts
         tiEA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=lGKx4K34;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id a15si283325ilv.2.2021.12.16.02.54.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 02:54:23 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id m186so22911066qkb.4
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 02:54:23 -0800 (PST)
X-Received: by 2002:a05:620a:28d2:: with SMTP id l18mr6008731qkp.355.1639652063228;
 Thu, 16 Dec 2021 02:54:23 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <678a2184509f5622d4a068f762691eb3ef5897af.1639432170.git.andreyknvl@google.com>
In-Reply-To: <678a2184509f5622d4a068f762691eb3ef5897af.1639432170.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Dec 2021 11:53:47 +0100
Message-ID: <CAG_fn=XFFF16r0irayKp=CnrJsnL_uGR-uz2sa2G12=zrSGO1Q@mail.gmail.com>
Subject: Re: [PATCH mm v3 18/38] kasan, vmalloc: drop outdated VM_KASAN comment
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=lGKx4K34;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Dec 13, 2021 at 10:53 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> The comment about VM_KASAN in include/linux/vmalloc.c is outdated.
> VM_KASAN is currently only used to mark vm_areas allocated for
> kernel modules when CONFIG_KASAN_VMALLOC is disabled.
>
> Drop the comment.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DXFFF16r0irayKp%3DCnrJsnL_uGR-uz2sa2G12%3DzrSGO1Q%40mail.gmail.com.
