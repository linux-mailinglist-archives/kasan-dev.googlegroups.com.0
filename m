Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCHEVWBAMGQENEIQYPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 95917338F26
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 14:52:09 +0100 (CET)
Received: by mail-pl1-x640.google.com with SMTP id l19sf13298342plc.14
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 05:52:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615557128; cv=pass;
        d=google.com; s=arc-20160816;
        b=g7Pi1FbkQqP/gH5tAdRj1VkfFxrtIVmAxIvlhA/fYksLpKiK87kTNCM43GVVeSuKWK
         VrJOZ+0+nEZK0+m9VjQlCnP4RTnrmDYE4sHdGp1jUg5/NEz7kObLqvCBxnr6hQouYgqs
         Fw46iiZiHfE/Rw+ZdK6Lz9Ds6Nd5SWQ5ObgyVs+O/3xDlEBRM6fTVsq5BYoJKqgOLkaX
         KJEQZn2sn7mMk8pBqCQOOMvYIKryc6mrTIzDus6WyPEsbzreRMeQlt0ikyIilGY7QWNV
         RhYRC93tHMc1dmvk8yTFwvPmYid8dtwkk6HmgaG/FJnC1OcaJU+WOM/osVZPw6jttaRR
         LcBA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=aw8ykQEdcfJyYHtBf9AK1JjgEiavs32DnUmx2b3pdjc=;
        b=WlZY0PNa+6iK0/HBhcXvEdTGIUd5lFF4Vn0O7ZHbH5xfr1jJZs9nhvP5QbRgYRgpDR
         Mj+W0n+0CKT1LNQaA9jU3ryT5SPy3Yrq4xklC8zeYWKo4vjNM42AUy56T+76vBnPedvQ
         AliZdUoWyvjsLtScCgCxSKWZoiKWu5XsVDPJDz1euk0k/PnFEiuBXPcXgtckJdOhcFmZ
         swjQz8FQ8di/gHkx11HJw5EBENPE8fHx0uZELH14qGkQ7VKTBCtXpomoZrSLXSs7iTgq
         SpuENXR5TNwHsFEOUg2OZWNxdEpV8ycCy5zKdyCpbqxjJ/OXQLvQa3RWRbbrI2F6yeA/
         LkUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RwVBkPff;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aw8ykQEdcfJyYHtBf9AK1JjgEiavs32DnUmx2b3pdjc=;
        b=bhiLkEb7mH3/CPBUWNPDpNdkvFpydNEozmgl5ohxUFI726ib9VDaQOs4jS3vjYSG21
         ZkOfDMd9Wo8GKSYsJUlh5/a5NK9VDr7F/PjqOgMOxA1zAidUU82RzWAzTpNIlGuE3CIL
         EtBP9nf9ivoZKAJnEi2yKIGPUULUsHbO9hBOFTLr4weDWRjZGVnlRwx/O8kJZ2wypdhK
         ZyOatWrGvf2bnkJqvVIYGhCjgiBXzZ7DCS4akehVlFZPKpSTxwWBoIk5WdqMo7v6povs
         +eizt2zSbOXByUxJAtkoyarJKNSfUcM9VDWLeNld9tjbeOJ20nZaRUraQfdAXVpkwT3i
         bKLA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aw8ykQEdcfJyYHtBf9AK1JjgEiavs32DnUmx2b3pdjc=;
        b=NIRueSJ4iDF4Aki9L7DX9o1d3PHtPAFPs5pzcTNUoAQKJoInk2d3U+T+tD/QvBW7Nn
         SWYxvTkq7D98+kdpQQ5opd40W2ERFa9hJFc2NAKMZBGS3C4lrgKOJ+QhIZSdDGwhGdJR
         9Ys5VrmtffyCvJcXrMrbZP0Wz9lPsQBXT1XJN1HLN5HIFntpCPT7CxNt1WEOA+wfOxVM
         7A95d7wQPLMA2009o+nRGsMqBUI9UnMw2rPGrKkYzYYynyd7+f24PERShiIESzUQdCEF
         eSCCMMKdm4SRQEoYMHWvRR4jWGo/dEX7hPT4zAHNqBPpI90n0AjNk0poCEvV5bWwkM9e
         L4Sw==
X-Gm-Message-State: AOAM530pCBnefRjhoaWe2FEVK45v4SlM5xgooyHqDoBW/E9Fyay4CEW2
	2GJ4k7J/aJfuxNhBYKrUURw=
X-Google-Smtp-Source: ABdhPJyD8xS0ciLTq/IF5rDwUvUjI2qkYt9iIBZc8xwS67jLcyzV2yctgghn5KAWcNgkybBF0ewATA==
X-Received: by 2002:a63:231d:: with SMTP id j29mr11652647pgj.75.1615557128180;
        Fri, 12 Mar 2021 05:52:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:1914:: with SMTP id z20ls3614709pgl.0.gmail; Fri, 12 Mar
 2021 05:52:07 -0800 (PST)
X-Received: by 2002:a62:2e83:0:b029:1db:8bd9:b8ad with SMTP id u125-20020a622e830000b02901db8bd9b8admr12609305pfu.74.1615557127639;
        Fri, 12 Mar 2021 05:52:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615557127; cv=none;
        d=google.com; s=arc-20160816;
        b=UW+1HR79U5iP+PL58eM24Jcy5m00YIQGetFV7JW8zsIi46kpfwWEG1UcppUtsDW8hk
         XyvMOde2DEZl80K/+OZqJB78iuUInt00yYnCvE0l/GyQez7jNXecbOyIBSy0pVAhQdXW
         ObCxazIysuOs0+H506JLgqTj49S0nXgXFwmRSU6+DL1V4+QtVZuaQymE0Sc7eSVjYGZd
         +h/2RbaHvzrqHU/W8K+FkZM5ZaKCTvkN6LKvn59RiOJx6M4v2+1IHAUwwOxflTAZjrrN
         6guNv5h2pILZc8NhjVkmsJhYgvweBdup/799fK3SH6cMFkdq5D7uV8WELhBA2bNfZNSG
         PzDw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qaH9KU2KwFKsLqRjuU6mMbuIQ6s+6udeN62Nf4zmSB4=;
        b=sQ8+IjZDfuUNWKq3ZfVEoefm9ziQN5z3Rcw4E1J4xDN6hAdo8xFEmRgGWkzawsIi6K
         qRVtGjIlRqXlFK0I932OGqg+OUFnPX/B94Tt1vwnRUVdL5h9Q66lR/nSvB2BB5fw4aJI
         nzWjf3vuwiy3yFOSZ5nTYIJ2cvx8zp42N0Tw5YrpZH5ZsEoibpY6HeLud3q9HDetyJq2
         ZOfnpZYn/iBY7i6Qv1EQKyxt6hmoU1+hxuU7pR1+9ruBzV6uf6jKCE3cXHaKSRikOx+p
         ERCkqVgZ1ZWAu84tw/RHUqL0faqLwe2g8lP0Ccf8nTWolzQyQuaqjaFKYecPSBhE+LOJ
         Ff+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=RwVBkPff;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id k21si375271pfa.5.2021.03.12.05.52.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 05:52:07 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id t37so5113879pga.11
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 05:52:07 -0800 (PST)
X-Received: by 2002:a62:cd49:0:b029:1f3:3697:90d4 with SMTP id
 o70-20020a62cd490000b02901f3369790d4mr12569341pfg.24.1615557127049; Fri, 12
 Mar 2021 05:52:07 -0800 (PST)
MIME-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
 <da296c4fe645f724922b691019e9e578e1834557.1615498565.git.andreyknvl@google.com>
 <CANpmjNP3bHe2h1=-W7r-64Vg9vr9vREzY0M97uh_QRDr3tVEYQ@mail.gmail.com>
In-Reply-To: <CANpmjNP3bHe2h1=-W7r-64Vg9vr9vREzY0M97uh_QRDr3tVEYQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 12 Mar 2021 14:51:56 +0100
Message-ID: <CAAeHK+xHeGQ8FSddfFpLrq+5YHoRZ+5KZr2zB+fzCssSbE_=bg@mail.gmail.com>
Subject: Re: [PATCH 02/11] kasan: docs: update overview section
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=RwVBkPff;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::52b
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

On Fri, Mar 12, 2021 at 11:18 AM Marco Elver <elver@google.com> wrote:
>
> > -Currently generic KASAN is supported for the x86_64, arm, arm64, xtensa, s390
> > +The hardware KASAN mode (#3) relies on hardware to perform the checks but
> > +still requires a compiler version that supports memory tagging instructions.
> > +This mode is supported in Clang 11+.
>
> Doesn't HW_TAGS mode work with GCC as well? While the sentence doesn't
> say "exclusively", the mention of Clang 11+ makes me think it's only
> Clang.

I never tried it with GCC until just now. But looks like it works.
Will add GCC here, thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BxHeGQ8FSddfFpLrq%2B5YHoRZ%2B5KZr2zB%2BfzCssSbE_%3Dbg%40mail.gmail.com.
