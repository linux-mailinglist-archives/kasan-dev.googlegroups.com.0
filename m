Return-Path: <kasan-dev+bncBDQ27FVWWUFRB7P3ZODAMGQEYJJDKDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id B45913B16CA
	for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 11:25:18 +0200 (CEST)
Received: by mail-qt1-x839.google.com with SMTP id t6-20020ac80dc60000b029024e988e8277sf2022704qti.23
        for <lists+kasan-dev@lfdr.de>; Wed, 23 Jun 2021 02:25:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624440318; cv=pass;
        d=google.com; s=arc-20160816;
        b=OjbyO7sTXT6KbKiXzHm2ESk1NfVbibhS8LFNarm7pY78N72YqM5ueQdKKK9sKYLH1L
         2DAyHa2gYmZ4qRzH4kzKF54jnrEEKpFIsrIe1cePhey+EB1LuiGi66zmn3sQaHvA21HR
         okYznCnuT0LKEYKIGI8r8FHSJwujrMz51XLQz+etCrZcBAd9JyFnvUcrvwSGbHPBeTZX
         no8UNSAEPhkqts7ZYraJy6Unq/EmQC6IelwbjwS4aS13y2ImyihSDsbmiNZb8arBn/RG
         UKqhazSCI3LvGgX7euWZIn8C0chdw+CXP6oR5RtspkjiztiF9HmKEOgNCxk9/W1DQa6N
         N2ew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=1HXhYBriTWtJWd4UftZhn+6MmDCMUzIIzmCPQ4GtlRg=;
        b=S9871+N++yZYhxhbRHYDAef0CX6I02qE4hbN+a5A4HZ2eMokwC1N7B6Zzp7Ok9arGm
         l08NBtmtWH37CD2ua9T27gYh573ypWH5eOSalt5OIDH6BqK1VnZXBxXC9YuScmCcxDO/
         FNiDFdVwz6bYNoQLRBLJbdP/BzT+urhkxUZcoJ/w8bcd+BOhf+Ko0gDyliQydkfNGB8R
         z6MEhqjoO6LFp1dkn2YB1wmBU5hq0boA8iGm0kyhFUDILkDIMz1e5921bg/fx1KObFbc
         /PS/5TptaNVFOvEThTVTpoYg+1zA10GGtuVL8Jh2lpT8K8yWlBLGRca5l/sR20maxFC2
         Ge4A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="jT/xShcV";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1HXhYBriTWtJWd4UftZhn+6MmDCMUzIIzmCPQ4GtlRg=;
        b=I5I2AzxBAfpVqn2ZDXPxnkSq/ZgUvdgB1T2RpukDNbtTa6VcFcoBj4QgNXFvwUooKl
         UmcwgxOP4GeTVIFE3uI56ADV4D8HDrCVJHzaU0T1Jy0weVYKPw6qKPEGr9K1Q1wMzu07
         5kn7mu/9FaGW3T9/b21NQ05wSKQwWSNQRAwvuDi6Xt2r01kFhdfDwmGHFBR7tB7Pnaaj
         LZsgARA9z64RoMvAA9YwwKRuUruLWLNJAK5KaApW38yhSVaZ7ZPO6Pz6ylAWpRp1yHAR
         mWfUpXHs5Yff+jfujrR9ey+MJbI7kx8CZ2zOP0pUsSkrbAhjHrmZc5v98YLnq8yQMYi/
         xbXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1HXhYBriTWtJWd4UftZhn+6MmDCMUzIIzmCPQ4GtlRg=;
        b=p8ip//PFfyhqIGmPLKnlPz6m+UiiJM+Lx5Ljtw//Ct6A2OUN2HuiMcZ3b+dk0Qs73O
         /gU1+6fGUBsjBlb2LQySB9fxaHMa+c7UkgGGcOWcw5OQM+knZ9Lqy2F3zQSyzcKYBnnz
         xXAphOY9YBgRc3Bv2E+chcval8xPvMh6a1sYssoxgTnxeHRT4gic5UJfmLo1MOEx2HLR
         Sfp9wXGVEPgi2k99xoRjGf92rRMYEuYWE7fZ2VDz7lCj+6m2FmfuAwAtL/lTzFeBL2AQ
         0lUvXEWs+ECJU5gUtqIGvkZLObAbEnV5cXsGNxqMNkEG1/kuHPHHJf/tieuVSkI6+gHa
         aoOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532hC5QF2NiQK8wYMRXw+wCc2iRh5uwOC//jQPtnnagNoZH56rsR
	WFx198EqdN/TzwWDEDdtSPE=
X-Google-Smtp-Source: ABdhPJxX/q8Vm/ImOkTxVCzq0vdfv2RwQIHN+Mfk5WNCjBu99pS/2lHaPi9VKGMq10rKXts2Ackv3Q==
X-Received: by 2002:a37:620f:: with SMTP id w15mr9260611qkb.99.1624440317792;
        Wed, 23 Jun 2021 02:25:17 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:f84b:: with SMTP id g11ls650500qvo.5.gmail; Wed, 23 Jun
 2021 02:25:17 -0700 (PDT)
X-Received: by 2002:ad4:41ce:: with SMTP id a14mr1079564qvq.56.1624440317382;
        Wed, 23 Jun 2021 02:25:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624440317; cv=none;
        d=google.com; s=arc-20160816;
        b=t49dTLPNSS9k9J1AsoQP95gQxehnGi/lz1FXXH65Gt0BM8InsowMQTp+2SOWybOiL2
         z3i0EdrM/10QeIrPCgFYxw8Fxy7A6BZjyKPYaHMKuipafVRa7RFvQqfJcEzz6M1G9QB7
         htaYMZ8AqN4n+FBoh0xx+eogD+rXw8OejAlbH/qpsvtA4/fHmjED6DPeJN6D6ydm2Rdn
         Phg+Ltn7UNRPfjtD0txiSRmTiTR0JLIxTNkrWWkjq99ZM7dlVKTIR6AYrIzsLVP8O8ls
         bN9kunVXQkROB9W7YnTs3oQohRKRq2sddfinRb6U5CSOaAxp34aC96wqqmrTNV2V4hqR
         Gp6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=ZT/7Ux0bhzXpS+rf3sIBrRKhCNZmq/T8COWEpsyT4vY=;
        b=fV60tKAg5nZcCpC+zxuUl8P7oRsChIIvo7z0TJf7fOpFGvCKm9VJGLJ/DZSMkHrqt5
         rfzVGt7F9mr0wU5PXXhNc9u67jg8SiT3BOfTBw2YaUIahuMEQKlJMDayhEHxEJqEF/KJ
         cGVAvRQUy5gj36LYLm4Dni/6/sA6nEV5nPtFeNOFx1uYkjUVC5mTjufWgw6Pl1zmW4Eo
         jydNw/yGIlOj8uzU9+KFnnCv84etFxPcflM8AhevjkmakILb4IrJcWtjvRVgB976e7nH
         gkwPhGUeXmf4ZHim/z3bNbQPiCwJtlu94Q3IogvYCV3xMPAMieYMrVGYaSde5AMiWi+A
         Zy4w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="jT/xShcV";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pj1-x102c.google.com (mail-pj1-x102c.google.com. [2607:f8b0:4864:20::102c])
        by gmr-mx.google.com with ESMTPS id t8si485341qkp.6.2021.06.23.02.25.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 23 Jun 2021 02:25:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as permitted sender) client-ip=2607:f8b0:4864:20::102c;
Received: by mail-pj1-x102c.google.com with SMTP id bv7-20020a17090af187b029016fb18e04cfso3358229pjb.0
        for <kasan-dev@googlegroups.com>; Wed, 23 Jun 2021 02:25:17 -0700 (PDT)
X-Received: by 2002:a17:90a:ee88:: with SMTP id i8mr8603384pjz.71.1624440316495;
        Wed, 23 Jun 2021 02:25:16 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id u10sm1860501pfh.123.2021.06.23.02.25.14
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 23 Jun 2021 02:25:15 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux Memory Management List
 <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>, Marco Elver
 <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>,
 linuxppc-dev@lists.ozlabs.org, christophe.leroy@csgroup.eu,
 aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
Subject: Re: [PATCH v15 2/4] kasan: allow architectures to provide an
 outline readiness check
In-Reply-To: <CA+fCnZdJ=HHn1Y=UDiYJ2NagNF9d-bJfjQa0jmiDaLiqneB_rA@mail.gmail.com>
References: <20210617093032.103097-1-dja@axtens.net>
 <20210617093032.103097-3-dja@axtens.net>
 <CA+fCnZdJ=HHn1Y=UDiYJ2NagNF9d-bJfjQa0jmiDaLiqneB_rA@mail.gmail.com>
Date: Wed, 23 Jun 2021 19:25:12 +1000
Message-ID: <878s31hr0n.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="jT/xShcV";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::102c as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

>> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
>> index 10177cc26d06..0ad615f3801d 100644
>> --- a/mm/kasan/common.c
>> +++ b/mm/kasan/common.c
>> @@ -331,6 +331,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>>         u8 tag;
>>         void *tagged_object;
>>
>> +       /* Bail if the arch isn't ready */
>
> This comment brings no value. The fact that we bail is clear from the
> following line. The comment should explain why we bail.
>
>> +       if (!kasan_arch_is_ready())
>> +               return false;

Fair enough, I've just dropped the comments as I don't think there's
really a lot of scope for the generic/core comment to explain why a
particular architecture might not be ready.

> Have you considered including these checks into the high-level
> wrappers in include/linux/kasan.h? Would that work?

I don't think those wrappers will catch the outline check functions
like __asan_load*, which also need guarding.

Kind regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/878s31hr0n.fsf%40dja-thinkpad.axtens.net.
