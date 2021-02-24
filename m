Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6FE3GAQMGQESL6CT4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id C8D5C323DBA
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 14:19:53 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id w2sf1942568pjk.4
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Feb 2021 05:19:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1614172792; cv=pass;
        d=google.com; s=arc-20160816;
        b=LAqKlGCPvxUXHTik/QUcUjDCQtPSg7yX2HErJ4HKng+fMzWlUND+at1SOW6Tx0J83P
         1cTodoygB02w5oe8HBeFiWwsBUQlaPCRrbGO796OqFDC5LrQQmox0WJFAPJFctDa4YMy
         A1gQ8Xcb+0iZBr9pwR+VYMNMPaHZzl3piFWKj3wWP/XYlqpjT1cFMg/YJnm622t851gK
         LDjsEJF1WAUjgU9F1gzRD3eLTYkosYRg8yGT8yxxNiv5uv3xum1WxIUUDZur4/3PW/qf
         Oapq/a/8TUTAJNW2X0y5KkRgGKFT19sgwQfk2GefxinOthUNbKxEPQcEg89oiZSI+2eE
         A5QA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=zs5ZFmvBvaPge/biPwDvubnqUbgBJbk05+Vjwtl26S4=;
        b=dX9AICgh50stpAY5ifuOApgJfnx2w7brj2y90t4ecnc5OXr9xd7oy6VdAZN3nMsNiX
         z5qb/9/CL0VKna4kPa8BwHO3xTxkI1cPrl3n+LgGEDmtZbfYraaEYCuYXcztF/Vz9uuP
         jdgc25mGqRQRpf5Vhqy2XnVsIMaxi1L9UKuCnL0lImjwoXbqlJi9XyzqgStnbk52vlSB
         6SvbfB8K748zhH1Lcu40DwUGmc6O7oGjgsn4zdbepDlKouQmFvJRrgRDeWm+0NopZJVP
         H8iK1vczNTWghr7UEI64ClsN2oU4PkfIUH4PPfHAI+UZ+xXK8Zk1IgYBZLKdIMsQWEfE
         vebQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rYx0yajl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zs5ZFmvBvaPge/biPwDvubnqUbgBJbk05+Vjwtl26S4=;
        b=CSbpq3RToq1pl38r+gvucYWBXJkI5cDJlml+Nqq7fHIFL/tzotPHsg0DqHyEiRfoRS
         ut1Gv4GFsmApd+IhKPxrZlBC/gN7L95nZhgntyg4ZAaLg+Ka/9+9I0RNp+6YKNJ9Qy5Y
         mIiGHE7ZU6dba+lf01ogMtkXbcxlmF4rArcu44AaSxItaTwD7zVJv2tbkftj+2o/030g
         w0rhpNFHQyHzmZHkmteIqQHWIr3+GJFOyrPXTjllajf3otJAnZyJ/9qDkLEuoh3jzjYX
         ZBepQsCoLxRSmw+AjviecP6bjGed7dMDJQ/Qvw/hi3BwD/AhpJ2qIN2/nDZZ87nUr+uJ
         I1MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zs5ZFmvBvaPge/biPwDvubnqUbgBJbk05+Vjwtl26S4=;
        b=WV1uOGRpO/i2wQKcXWI7xhMS1kKISidn2mfAMkLyxBjOGbZHP159EePZURqiSiNv+B
         puOCTKtWfcpH2q/57gjJz3b37yDDp+UR9i/u5oiHO+V78ezi5Ym8bzHv+C/9kxl3iU4U
         +s8vopE32jZ4f2A/mFNwLNO18VF1MS/UmxEJ4kt2a/s50A31AuzPEhdeHi7Xonh/17so
         4d1LgrFz2w00N0c9PBJRxWCU/3Ves4bzlOezQLJC2lVMawqGVAR3qz/vN1le1nmhCdHb
         +CxwBxQolIuKAIbQ22Uzkq2fr6MdL9uhpaxHoC1TMUblJpt8S5La9Ihu7TqYhfJriZS4
         C/dA==
X-Gm-Message-State: AOAM530s01Ucp1v2dlx4JjOti808VOMGyFjkmhf4NE8tAOFemB+0q7a7
	MbzJf5KW9g4JJN78AuTGs7w=
X-Google-Smtp-Source: ABdhPJwDcfTTizgwPbQTJy1RNhBXj/jQQAbdOI1TEE5g8Us3IqCVqAebUUDmlLSQZNan9az1lldvDA==
X-Received: by 2002:a17:90a:b26:: with SMTP id 35mr4565533pjq.104.1614172792590;
        Wed, 24 Feb 2021 05:19:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:2311:: with SMTP id d17ls1352051plh.6.gmail; Wed, 24
 Feb 2021 05:19:52 -0800 (PST)
X-Received: by 2002:a17:90a:72c4:: with SMTP id l4mr4623429pjk.52.1614172792065;
        Wed, 24 Feb 2021 05:19:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1614172792; cv=none;
        d=google.com; s=arc-20160816;
        b=Hkg9zIs06aFS81fAZsAJl4SRxsnk1SCLVVdgwcV6/EpQ2x4fLwnhdfm8KQHEuEl+i1
         xvTDVsaVo0I3RKQD611EUVMrcrCPMBD0BJHT3LD9zgRMDf1WgYIpP0wRPDe675vSdkIT
         9v9WXl28KCWn7ueHbcxzoXtsqotrFdWFKzL1N/M0QWMU8SrPAWt6dgVLUsUakrGbxHCW
         pKdEvjVeIhEBhYpKTRxgLJnDNhh4lRzh/c4AT9p4YN6h5PJyV+yLnNGnnWtcE6YEIZIp
         8+fwS7T1WniKwNVgibmAtF5Rw/26AgolyvdvXRIckqphcwZOYWY+F8MdpJNWP+n+K//V
         buXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mg3v0aUVSI5MYJQxBhrJwHedPmnwI46w03DSMoRs/ys=;
        b=vQ8TORkc/TJTl68g/hQttD5HHqAwCtJh262s5Rv73lMqRKVX7sVeYA2wFaD0jR3SCS
         ntyoMbsZaWOuh6esx+IN05AnbfiSnfBJ3rshFQGoRZ/AaoDbbJQ2pndMoF5iE+nPdGxA
         7JyH51hyeabE6G48SHUkgmi7z+7zAaw3pvBurWv6A62zNl7wixuXy0f7VsdtbdZOr06S
         TSqSapy4AoyKG05ahKVa9TI+ORqk9LDTdr02IFQXebin+V6XhNqy/GxxGODGpZFerxNm
         ZEzzDLVXamerZwNvwBYSq+UgiL5MLn0DKO/1Zmtx0XvSvkSamEYQM0nZvI5wXL32J4rk
         jzvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=rYx0yajl;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x329.google.com (mail-ot1-x329.google.com. [2607:f8b0:4864:20::329])
        by gmr-mx.google.com with ESMTPS id n2si114815pjp.2.2021.02.24.05.19.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 24 Feb 2021 05:19:52 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as permitted sender) client-ip=2607:f8b0:4864:20::329;
Received: by mail-ot1-x329.google.com with SMTP id h22so2084279otr.6
        for <kasan-dev@googlegroups.com>; Wed, 24 Feb 2021 05:19:52 -0800 (PST)
X-Received: by 2002:a9d:5a05:: with SMTP id v5mr24708971oth.17.1614172791279;
 Wed, 24 Feb 2021 05:19:51 -0800 (PST)
MIME-Version: 1.0
References: <20201218140046.497484741326828e5b5d46ec@linux-foundation.org>
 <20201218220233.pgX0nYYVt%akpm@linux-foundation.org> <X91JLZhrXYaLzoB8@elver.google.com>
 <20201218171327.180140338d183b41a962742d@linux-foundation.org>
In-Reply-To: <20201218171327.180140338d183b41a962742d@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 24 Feb 2021 14:19:38 +0100
Message-ID: <CANpmjNO0ODGVfH2Vbeu-gY=6CuAGSE=O3MKe96QX_-N0qZ+G-Q@mail.gmail.com>
Subject: Re: [patch 21/78] kasan: split out shadow.c from common.c
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=rYx0yajl;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::329 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Hi Andrew,

On Sat, 19 Dec 2020 at 02:13, Andrew Morton <akpm@linux-foundation.org> wrote:
[...]
> Yes, kfence came in fairly late and seems a bit fresh.  I was planning
> on holding it off until next cycle.

We were wondering if KFENCE will be sent for 5.12. If there is
anything we can help with, or help clarify, please do let us know.

Many thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNO0ODGVfH2Vbeu-gY%3D6CuAGSE%3DO3MKe96QX_-N0qZ%2BG-Q%40mail.gmail.com.
