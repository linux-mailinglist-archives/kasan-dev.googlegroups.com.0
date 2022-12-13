Return-Path: <kasan-dev+bncBC2JFQ6TUUPRBCFN4GOAMGQEEWDMNPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 626F764B35A
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 11:40:09 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id o18-20020a05651c051200b0027a0ee63d4asf790123ljp.21
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Dec 2022 02:40:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1670928008; cv=pass;
        d=google.com; s=arc-20160816;
        b=KNZDHNF/dNVmN8T2KHAmYhdUy7LpaZ6/6ZYRgq5bAG4cqp0oZRkzxTRrC+B4q5XZbz
         E6bytK1DzVMxqB7MCCCS7DVUkZ/jqgU+psylPCjSogDg4rJFJZsXabjcupNJ9xxtQqnR
         3TeGzCOZQ8G1xlb/RlaQMcwTkY+IWi4MStnPt9mkdwDAoKwhciMddp1ZSRnI2+dpelHR
         CwzvMCrXJ/vlJ+afd34C+oR9AnTqCBa/QPiNMnmqBmFMCr6kjmClKnyRrgSUiUYCWeb7
         2TvRW13HbdyYVWeoEopIv0Kd3dcHhi13hXMqzVmZU+mxcXA7fULOE5Af0LkjJ23AmvBf
         eWng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=pxdNJlWQJp7VhsPGoUG9QUx7lAzRq10ZNkXPTthPeT0=;
        b=Viay50K2jE0AzLQJBtHvGp7jtLM5vGJhfMrQbXAniWGW3+wBn29dPR5vbp79wXvXoi
         E9eW3gjYoNpiTVKkk4Ql9W9iaHMNAxOygBWW09/UD6PWdajFsYgwpfKcRpxqZHyZ3T0M
         J067lmzUN4y93vW6qljTt7cvBUlszCVc+1EjVL+9UVMfFBlZqaVcXnNwO30BJ/RRproi
         dlwjA5/ZYqGEjkPjCR3EvXVX8nGhwmOgtUNY3PmpQdum+P7sVqWuj78/t5aNRK0dxoKb
         Isah9ev58VzXWCgaHETVj+AsMKJpBZnDb2HzGPfQCaWbCloQIyE2rZMI+p/5zfYKdEYd
         EQng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qyPBF6YT;
       spf=pass (google.com: domain of sudipm.mukherjee@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=sudipm.mukherjee@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pxdNJlWQJp7VhsPGoUG9QUx7lAzRq10ZNkXPTthPeT0=;
        b=oswQTTDVSDKT7P4hjpJnzDf46GURoolJF2dhJyZS0nm4s1KfODzJJ9/b4tmMPcE1BF
         V9MEXOlG3B4n/Vf8uDdC+zopxFOcYjm/9+wg8gvy3Qpc/sjXMJ7eFaD2kilKh1/1RFeF
         K1WM9COAlmWvCJ2TGRJu1sSx5kxIB5rP1NIYTGIvOEud3rAru6WX3plWIdOg/Hz9AlTI
         r7d2qqrjEO+t1XmjnhhX2BelcvOf/wjyHVsa7xGdlmLOcb0+78uqr3pFEBoy1HBBYEoR
         wBK34kKI0aFE/IT9IFVme1FKefdpK1GMSwb+A2dd3R2zlhhHk4UVOldAg1IQe+kpiTVs
         fMig==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=pxdNJlWQJp7VhsPGoUG9QUx7lAzRq10ZNkXPTthPeT0=;
        b=eewIX415L51dO8aSayxyNXCGRYiXkQmxhQOrC4KX/jsVzO5E8TqoG5p35p+twQu/JF
         WbR7wOyXJeUduEpUIS8zcXul8kQDyX6DgL93/iQkuuKR09muzVxbdtCtRBxfonxlE28g
         pcDt6zpx/ors22UOaiUEOUuYZCjXX+dtQ61NI8CKdQxmZZmHPlTdhu+ycA4/KfVXPuvB
         ahxFNSSwVXeTTh7BV2U7Fw54tivlj7tHXpi/uTXSPgy4shcPEcVoIHr1fpwLrNcB0lqD
         eNftdTGmyHHNck5yKABwyFn7Z9mgw0BJZT2wc1n++NPFXHz0aBsGh9tc2v7SDvzO7iS5
         yjGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pxdNJlWQJp7VhsPGoUG9QUx7lAzRq10ZNkXPTthPeT0=;
        b=pot6F70MfdBYiTa9S9hTJOL2IdoamrNs9aW9zL13DwpCbXGjP8lMU+MvFi3odKnQx2
         AA6CdC6DEXnTXg8HXRzSnAclkETac/kDmy607K2WG7suWWf8yBQ5bfmHJin2NdoN4qrq
         5OEnPxwuiioFvr7bS2y+hnkokBRg8e/cIqa0RsttNGJSPpjxokFI7i3OfBfb80bMO55K
         kKF+2na1gdhKlQJ9dRv4qo3swRn3pqzAz4YhpAFjVtDDYiwXCvVm4dOA1d/64OLgEpzk
         8lRb70XIFBNYWUzeYaksYatSn3MgpyJuhbPmbAI9sakebdlVzP5TCkgGCrLRHIf31FWx
         ciHg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ANoB5pnBcervTbWuFHSygYv92DVgvfaTUlswZDY5yRtX9BX4z5knOLwy
	SEKL+W4tsjkD76/jUD9JvWU=
X-Google-Smtp-Source: AA0mqf5xK2YzYrfawZm7ylaESLXjNJ2sz7izjz0V3K7QQ96m1aLktc1EowFimdl8SqxQcxSpS8bALw==
X-Received: by 2002:a05:6512:c01:b0:4b1:ebdb:be45 with SMTP id z1-20020a0565120c0100b004b1ebdbbe45mr37929697lfu.618.1670928008475;
        Tue, 13 Dec 2022 02:40:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9050:0:b0:277:fa1:cf3a with SMTP id n16-20020a2e9050000000b002770fa1cf3als2611303ljg.10.-pod-prod-gmail;
 Tue, 13 Dec 2022 02:40:06 -0800 (PST)
X-Received: by 2002:a05:651c:200d:b0:277:e58:1814 with SMTP id s13-20020a05651c200d00b002770e581814mr4424459ljo.43.1670928006842;
        Tue, 13 Dec 2022 02:40:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1670928006; cv=none;
        d=google.com; s=arc-20160816;
        b=cYiHvSzbSaYK2y+6N+N59CduUZJweCBnH+mv4ac6rYEm934Zre0enqUjAyXGWy6zdV
         rcxeTP73pPbglNtmSHcJe1KKYlvAVCdzR0BbGXw/VCpX34j11cr5CBqdjuryjZR8p2/i
         zx2vzmcEB8JdOll2up9O27Cc/T8pcbEvJ2a8Df5R+e+6Va53R82FjxQDnK/9zFH06D0b
         V8UbL+nQk/MTlIq40K9uE8okx9kO0k1lOZ/qDP5E8syRbhw/oz13kYTgfx8pPqUpDoiU
         0NKRbrVptWYFY3Iim7bVhqodBO1Bbcm2NaWJWtU3g/nOQ+qo2hyA4QkfXMCwyZZq37qo
         Jwmw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=b6QgqvSEkJ40dC/g0yqPFcNIxsg/4vW/2+57F7Oid/Y=;
        b=n4AiOvQMxYOE7mSI7CsqxPK+YXf9H1D+iXhlMwUkrT/8NLsS4UugDegHHt1oHquN1Q
         lmrg88OD2g+olgK4pksVc+xwn+5+xC/SNxy6VeavkrSe8ws0OCKHkLtrwYBQOkOUWT8k
         hstSZOonzq4KctcuVvhAxklG8fBJInBlRPRtpZSlj+4KH2PR7cLhib0zFbKA+VVFwYZR
         NpF6hZivpNZoc7F5BVPw1cAbNwLlgDyp7U25q07rl+rXmQ2Glx4EOyVFV8UxF3uqwL51
         TltmPhLcUvny53PUu6FoZxyt3CIxFoDxbYYhoq9eZEWkRlQoXiJAka5iSPmaeOlsyIUG
         2LDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=qyPBF6YT;
       spf=pass (google.com: domain of sudipm.mukherjee@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=sudipm.mukherjee@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id bf40-20020a2eaa28000000b002797e79499csi112349ljb.8.2022.12.13.02.40.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Dec 2022 02:40:06 -0800 (PST)
Received-SPF: pass (google.com: domain of sudipm.mukherjee@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id z92so17098425ede.1
        for <kasan-dev@googlegroups.com>; Tue, 13 Dec 2022 02:40:06 -0800 (PST)
X-Received: by 2002:aa7:d841:0:b0:46d:692e:8572 with SMTP id
 f1-20020aa7d841000000b0046d692e8572mr7011724eds.25.1670928006558; Tue, 13 Dec
 2022 02:40:06 -0800 (PST)
MIME-Version: 1.0
References: <Y5hTTGf/RA2kpqOF@debian>
In-Reply-To: <Y5hTTGf/RA2kpqOF@debian>
From: Sudip Mukherjee <sudipm.mukherjee@gmail.com>
Date: Tue, 13 Dec 2022 10:39:30 +0000
Message-ID: <CADVatmM4Xr7gKqkeNX90KjmhB-E6H8rSfsK_E+42wp8OmALbDw@mail.gmail.com>
Subject: Re: mainline build failure due to e240e53ae0ab ("mm, slub: add CONFIG_SLUB_TINY")
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	Linus Torvalds <torvalds@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: sudipm.mukherjee@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=qyPBF6YT;       spf=pass
 (google.com: domain of sudipm.mukherjee@gmail.com designates
 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=sudipm.mukherjee@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, 13 Dec 2022 at 10:26, Sudip Mukherjee (Codethink)
<sudipm.mukherjee@gmail.com> wrote:
>
> Hi All,
>
> The latest mainline kernel branch fails to build xtensa allmodconfig
> with gcc-11 with the error:

And, also powerpc allmodconfig with the error:

fs/f2fs/inline.c: In function 'f2fs_move_inline_dirents':
./include/linux/fortify-string.h:59:33: error: '__builtin_memset'
pointer overflow between offset [28, 898293814] and size [-898293787,
-1] [-Werror=array-bounds]
   59 | #define __underlying_memset     __builtin_memset
      |                                 ^
./include/linux/fortify-string.h:337:9: note: in expansion of macro
'__underlying_memset'
  337 |         __underlying_memset(p, c, __fortify_size);
         \
      |         ^~~~~~~~~~~~~~~~~~~
./include/linux/fortify-string.h:345:25: note: in expansion of macro
'__fortify_memset_chk'
  345 | #define memset(p, c, s) __fortify_memset_chk(p, c, s,
         \
      |                         ^~~~~~~~~~~~~~~~~~~~
fs/f2fs/inline.c:430:9: note: in expansion of macro 'memset'
  430 |         memset(dst.bitmap + src.nr_bitmap, 0, dst.nr_bitmap -
src.nr_bitmap);
      |         ^~~~~~

Note: the powerpc failure is also with gcc-11 only. gcc-12 builds fine.


-- 
Regards
Sudip

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CADVatmM4Xr7gKqkeNX90KjmhB-E6H8rSfsK_E%2B42wp8OmALbDw%40mail.gmail.com.
