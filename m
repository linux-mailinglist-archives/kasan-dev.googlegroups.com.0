Return-Path: <kasan-dev+bncBDQ27FVWWUFRBWH4QTXQKGQEVPZUFCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id 65C1610D817
	for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 16:50:49 +0100 (CET)
Received: by mail-qk1-x73a.google.com with SMTP id 143sf663123qkg.12
        for <lists+kasan-dev@lfdr.de>; Fri, 29 Nov 2019 07:50:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575042648; cv=pass;
        d=google.com; s=arc-20160816;
        b=HBRjEzhSlenLehNczXxCgaemxWDBWJ2/HzuAgeayUjTvEtgXddukN56I4xHW3loybJ
         8vRRSLBdqOItO/yrcE1o+rYuLnSKwm+IFIxwED6TqJUmwqWJ2tJIBlYaUVpJeCk2ApRg
         2Vs6EtjBdJ1JO3MM1QZWu76Ou4eQp7kvQf7tn+2TG/hXUQXsiYgu6X0R90dHJBYj6inQ
         FE8JLm5X5etqQOyqYcnjhF3SSp0ZCsyFunm5T+/nUzegVVnDOAiw/k2pPHQ3XPlw8cbv
         I2py3upEwrRygP45f77k6TRkRk3k9b6R4Heb7UIW0H+Kh4JfMOJjYNpksgOHwVpMc6KB
         xbBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=zJK/ktB5R3Y700CCJQYYvneolL3RrUZypyYkVV8SJWw=;
        b=VAPbyWtkRZxqCy1JIL/BJZYtPLaEHKggekbywGuKhq2Svm3KecWD9MQ0vVuRvFsoR5
         WUuSN0n/51u0daItUiGpfvz2Sg68ibiE8KEeKgR1Kd06DyDscu52cN52aevYYMHZSEm7
         VYv3K4xN7o7AQj9vQnBBt6NKj9oCCveaBiBi6HHT/8eVJ9fPaOkssPiC6a2jenPJZ6HN
         t3p558UhR2tE+q69IUKGW7bh0WGGytQEeQQsZcL5Vpv2PIPcrSYmdbfX10ieOPPeUEDd
         NWZlp+k9uVljhbIQXB9JHAJAqWVNbl3dPTj9SapaFI9LZxCEIXFpebVKwObTYQSW/ZFK
         8xMQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lUT1A0bJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zJK/ktB5R3Y700CCJQYYvneolL3RrUZypyYkVV8SJWw=;
        b=PHhL4/5TPqyoQcwOUi5/4w9duKu0aiGScr7rcuLt33YIrZhMU6bre2K2fuJgcZZEad
         8+pYEigjn5TOevZig7MXsHjmFGvWgah8DajNOJiXu5iqR7OWdkgjIRhNSL1ja4ql64vj
         Mzej9l3l6W8SbRLCQfSEdP/xKb6rUDpUJTh4wcQSZXQvU/6gZpNeVOnFWK+FBTW2EXTt
         Fq44rfXmNFfPl7IX0IZeKXpvguQfNGmqXO/Yw+ugi2vCDMrwsaM1GD4YUjs/PrytISL8
         YLhsCH/+Y8hU/Df5Q6VX4xOhb8sGvD5GxWPxGKNBHhN3oXufugc6B7fMdyAF/8pGwuQC
         HKaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=zJK/ktB5R3Y700CCJQYYvneolL3RrUZypyYkVV8SJWw=;
        b=lGyijcMc6WZTqpTfjctzoYlb4tIndzAc2cHdkk1fVnTOhM6KMtzi07IkiZ9HxzFna8
         04reNDn2tU+nDxNsbjTzMKyj50/BDj2UzS1G+BMw+5/tmzl8B2KyfcJFhdAcflz5g8jD
         oAMzjVtTVijIX8/Zs64EDZ5q9u4SRm+PX7FBbBnD4U/18e7VGiYOx9pNs8QbA6ydjmmx
         A2+5mGyZy089+uA/M9VccHKCG5jryVRM8RVYjHTIvCBZM2i+C0AMbsIssyid1WW9uo7g
         TozhlPIa7jugiD2JFi6OoIfUtQZ0gBU/SgB55WT4mHH/DtnrQJwzwHuzMXUYn9iXVuVb
         K9xA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWmK4/Pr6JI1egxRQijaD6ycOa93AjprEZsEb6Pw28oC6DdA7S7
	AlyCDj5BCEK5nu7nsiNGKsA=
X-Google-Smtp-Source: APXvYqxV6iL/48I08aJHn8s+I//4s3hoW2sjHv3qh529LqcwWACbko8jVCbNJR6bg9hCmBhVKig5Ig==
X-Received: by 2002:ac8:6a0b:: with SMTP id t11mr17157969qtr.104.1575042648361;
        Fri, 29 Nov 2019 07:50:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:85c1:: with SMTP id h184ls924171qkd.3.gmail; Fri, 29 Nov
 2019 07:50:48 -0800 (PST)
X-Received: by 2002:a37:b81:: with SMTP id 123mr17030092qkl.378.1575042647996;
        Fri, 29 Nov 2019 07:50:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575042647; cv=none;
        d=google.com; s=arc-20160816;
        b=TZNQkeyjRBXJBEB9QUy1Wg2dGYXLp6+0FJrogzGZ1c+XDZb+DU5V3M/Yuo6p/PNSVo
         PTkj03WtrjfLEp9IBcK4macMYSgUWpp1kilFJigka0JAASk8hSspDRMGLF7Pw2nXJU43
         lo222vCbp35IDnkqRD0Veqove/EduZbGk9CYHWlWXAk5RCm8xXmigu+pu0vuNVmGgG5A
         x157X2Che59jV593PV/4INiQin0ZtRpKyOOwRNonbWuRmvpIz0cUAQYYGpqjK4oX0+YC
         7of7NnO1WGbeyEph3uQMS2BngrNMFdvEs3lRvJwkb5M6JlLaShJxKor/6W9XX02ahdyb
         1uqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=zqzmkmsTqqNqAEU6sqwGU4uvEVY7myANFxGbhNa8Thk=;
        b=l9gO56XIjgVTHifZ/W7baIKeVEyHUt2XyHppigwLlI7J7HHQ5Gh1chT9Vl0qFEZb9E
         M14FwUjYW2+lGdiBqk9qjweiAAeL4W2OG6qXkT8DRMDFkdxbwJETt/3OyhlyE3peTru4
         4+2Fer0BWKrD0mBlcBxEb5sByV0L0k+HZdVyzm5w/lY1zHzaWnEPM9slPsX1BaXsbVqH
         PvXJg7W9bo2s94Y6gBpCCZnPvIJ+qz4lkVB7HvttmBiIQh33UCFn1J+E1pWuflLDQ2xe
         zyt3hemYUAIdDlkTYaI6IjDstrkB6OGkCzyujR30iEjTvlnq5jUUkncVvEMljIYs4W7b
         WgCg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=lUT1A0bJ;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id q1si1172318qti.2.2019.11.29.07.50.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 29 Nov 2019 07:50:47 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id z188so14552491pgb.1
        for <kasan-dev@googlegroups.com>; Fri, 29 Nov 2019 07:50:47 -0800 (PST)
X-Received: by 2002:aa7:93a7:: with SMTP id x7mr57797282pff.36.1575042647113;
        Fri, 29 Nov 2019 07:50:47 -0800 (PST)
Received: from localhost (2001-44b8-111e-5c00-4092-39f5-bb9d-b59a.static.ipv6.internode.on.net. [2001:44b8:111e:5c00:4092:39f5:bb9d:b59a])
        by smtp.gmail.com with ESMTPSA id a22sm1465829pfk.108.2019.11.29.07.50.45
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 29 Nov 2019 07:50:46 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: Qian Cai <cai@lca.pw>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>, the arch/x86 maintainers <x86@kernel.org>, Alexander Potapenko <glider@google.com>, Andy Lutomirski <luto@kernel.org>, LKML <linux-kernel@vger.kernel.org>, Mark Rutland <mark.rutland@arm.com>, Christophe Leroy <christophe.leroy@c-s.fr>, linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, Vasily Gorbik <gor@linux.ibm.com>, linux-xfs@vger.kernel.org, "Darrick J. Wong" <darrick.wong@oracle.com>
Subject: Re: XFS check crash (WAS Re: [PATCH v11 1/4] kasan: support backing vmalloc space with real shadow memory)
In-Reply-To: <27B18BF6-757C-4CA3-A852-1EE20D4D10A9@lca.pw>
References: <20191031093909.9228-1-dja@axtens.net> <20191031093909.9228-2-dja@axtens.net> <1573835765.5937.130.camel@lca.pw> <871ru5hnfh.fsf@dja-thinkpad.axtens.net> <952ec26a-9492-6f71-bab1-c1def887e528@virtuozzo.com> <CACT4Y+ZGO8b88fUyFe-WtV3Ubr11ChLY2mqk8YKWN9o0meNtXA@mail.gmail.com> <CACT4Y+Z+VhfVpkfg-WFq_kFMY=DE+9b_DCi-mCSPK-udaf_Arg@mail.gmail.com> <CACT4Y+Yog=PHF1SsLuoehr2rcbmfvLUW+dv7Vo+1RfdTOx7AUA@mail.gmail.com> <2297c356-0863-69ce-85b6-8608081295ed@virtuozzo.com> <CACT4Y+ZNAfkrE0M=eCHcmy2LhPG_kKbg4mOh54YN6Bgb4b3F5w@mail.gmail.com> <56cf8aab-c61b-156c-f681-d2354aed22bb@virtuozzo.com> <871rtqg91q.fsf@dja-thinkpad.axtens.net> <27B18BF6-757C-4CA3-A852-1EE20D4D10A9@lca.pw>
Date: Sat, 30 Nov 2019 02:50:43 +1100
Message-ID: <87y2vyel64.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=lUT1A0bJ;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::542 as
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

>>>>> 
>>>>> Nope, it's vm_map_ram() not being handled
>>>> 
>>>> 
>>>> Another suspicious one. Related to kasan/vmalloc?
>>> 
>>> Very likely the same as with ion:
>>> 
>>> # git grep vm_map_ram|grep xfs
>>> fs/xfs/xfs_buf.c:                * vm_map_ram() will allocate auxiliary structures (e.g.
>>> fs/xfs/xfs_buf.c:                       bp->b_addr = vm_map_ram(bp->b_pages, bp->b_page_count,
>> 
>> Aaargh, that's an embarassing miss.
>> 
>> It's a bit intricate because kasan_vmalloc_populate function is
>> currently set up to take a vm_struct not a vmap_area, but I'll see if I
>> can get something simple out this evening - I'm away for the first part
>> of next week.

For crashes in XFS, binder etc that implicate vm_map_ram, see:
https://lore.kernel.org/linux-mm/20191129154519.30964-1-dja@axtens.net/

The easiest way I found to repro the bug is
sudo modprobe i915 mock_selftest=-1

For lock warns, one that goes through the percpu alloc path, the patch
is already queued in mmots.

For Dmitry's latest one where there's an allocation in the
purge_vmap_area_lazy path that triggers a locking warning, you'll have
to wait until next week, sorry.

Regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87y2vyel64.fsf%40dja-thinkpad.axtens.net.
