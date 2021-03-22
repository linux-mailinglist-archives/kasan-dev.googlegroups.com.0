Return-Path: <kasan-dev+bncBDQ27FVWWUFRBBPB4CBAMGQEPSN5JZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F2C63438CA
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Mar 2021 06:52:07 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id g6sf24828194pfo.2
        for <lists+kasan-dev@lfdr.de>; Sun, 21 Mar 2021 22:52:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616392325; cv=pass;
        d=google.com; s=arc-20160816;
        b=vUzAvGlxXHf1vpczu3LRUAGjYayA45yGYETU9t3Msd46YDap5s2FaejMBn1r0Bfi2a
         UU57TXy20yaW8nrFBFMMx1OFdTg3Z7OkqLBcdxyMLRFPjsS0GDYgP3OyFfi2kpiKxgTU
         lGpkX2Vrk62Scq3wP1hG/ZIVojbb7IMD8EDeQ8dBQ5H6RrNcHGKuQlyqzvYJxS5xVbV/
         VZXmDqElK0igKRKezF+1h52Kkn7zJ2Cty0laG8QSn5/CemWHhtEquqp15p1FRiDnjBQU
         bNrQ65cNaMaNtBdKkUS11Dni/S2ZeFkLdrFLst/fz9CK3T23i9AJB63DuMBWXHKSA5is
         Sm3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=d6sXO/FdGIag+9+yacM1tQfMbOADuh+bShhy0TT0zgU=;
        b=MEmXA6/ad/qnorJnykt+nXTcItSWyNMok8Jrjhl/4hYmkCpA9GYDZN6MC75F8rArOT
         YCqjMPhH+svrrICfo9xNQSNi1Xdxz3dvm9Ox7DL4KV7fRTBZohr1WVvs9SbImaQWspyC
         sRphg56m9qnX8/GU+oJeWDbkenaEKeNzhHM22GeZhP3Z4I1fRRZKcG94tZgpXDUnCJeu
         of/RuxQVwTAxMTjJCEff1x3HtSoz985xQ6H1P6Gs8XITjz5fsVBMdub2UBhAYs3BP8dp
         NYSj3AhpF6rgphXFk0Lvub3RIZfZ8bdwuX4IQPcHRNirLS3w4UKUThv4J+IIbthTxOSU
         YwUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YAeNiVm0;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d6sXO/FdGIag+9+yacM1tQfMbOADuh+bShhy0TT0zgU=;
        b=HTMatweJXXGpwENsG8nbKEAWB2oSA5wGPwvVEPdHvHY+2Hwb9nJli92qbsbN5cONU4
         XBDKsP7t3bad/cYlS8Thd+pYgptjt3AdBczfygmwrWegmsaq0LEOZlZcxBvLm/6KkC12
         wjUcmaAuHlZY5K6eiZ4nsIOhe7roiJcqimc+b/JxeM+B9m7IhEM8AO+bvMKoJdQMXH88
         f0zh27pQwoKefjE53pi91nsNwYxmksizf01iU27EomPXNmlJbvL/LaemiBjEMl2x5aAt
         VVpxTvD77/nCcHqX21bHehHznRNLwKpzq6ApC+T2MbjWTatTF2dVJUMP5wNZ9q0/Bfo1
         07Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=d6sXO/FdGIag+9+yacM1tQfMbOADuh+bShhy0TT0zgU=;
        b=WVShpkgcQYa7v+lvnOD/vSdiywStonD3PI74kRFtlTWBmaS+GfjMyxXkd+eujp+8pe
         mpuN8A4LIOyvz/HL6BfK6dVWf3TtBu8VPWnIaSJd/lCQhvvO587+V/zTRBwNQxQN4Rme
         Jkh+0CwCg3NGsofSRYocltSIRz1lr+AObTeaIgfN0a+P6IKl1RT7fzXeVfRFlUiM13et
         YY+HwSyMiGEkBADOIrtQ19SfF0Oz4wGqpNHAMKH7nSUZFusHqjDSvwyKIwlW5jkZetis
         xg+OLco0iA8Beb2KsHmNQmGrAsmXcjdTW1fXLDG9xVR1xYMShTene3nPCOfrNGa8RW1B
         Zk6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5338z5yLNt321x/sdAtGoY0FuCHMi0jd2DzhTxRJDOu6b7jKRgS0
	C/gi+buQOKbGGXv6uHVViHM=
X-Google-Smtp-Source: ABdhPJxmIztIIVdWbrucldm356beXYvKuFFVS3rNAeIcSQimdW75SuH4ZQ4Ja0n54cv0qN6BMpxpmw==
X-Received: by 2002:a17:90a:1a59:: with SMTP id 25mr11634383pjl.54.1616392325358;
        Sun, 21 Mar 2021 22:52:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:1057:: with SMTP id gq23ls6979568pjb.0.gmail; Sun,
 21 Mar 2021 22:52:04 -0700 (PDT)
X-Received: by 2002:a17:90a:bb81:: with SMTP id v1mr11776573pjr.123.1616392324897;
        Sun, 21 Mar 2021 22:52:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616392324; cv=none;
        d=google.com; s=arc-20160816;
        b=gQHbJoWsAR6pHT0QWtU9OwZONNn/rQtyr0mV6I1hwljO6zDOA+KSmMOeNX8xLiLZvq
         DVrxjGxpcvqLUGiGQfMDGlk2Ndk0/TrrYK+nf6l+3jXnujxhLSDDpfejFL98kwT6N9dn
         jg44emBXnwSOsltE+qtBh7brjeEPQq6a9gbY2JDGFNqp2dYQ4MTchTUkNgkArC/Bwc7I
         2bivVIrgadbXLV403zGUHmWH+o0wpb3dul8ZKB4Nhn0CHMkOKWXvVPWbCxGTFJQAYrh1
         K9voJH7qIFVvtSeHxWsmHVqPy/zBRLiaVotvGurrt/pG1TljnU4NTr2xALAq3CRqBZby
         fIvA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=jrTlyfiRQP0Jt7kq8QZFoM4VuMzt11eSTk3pvqVA7QY=;
        b=q1i3hX5LXuwz6bFkhGIEIlmd//E0s4+voLFEejNwUh5KLLG8bD69dbq8Vn9AUmP4ul
         talCDUCeKvcV6kzVcQW+5yphbIB8MwRNv0B3TzOynoAEF9vhU3/2pQCgruAhQ4sECDZM
         y/RkMrLLC39wzSpCDH8elGCNLylMOFwRH07bdtH0fvppx+uVfa2+H1sfg6Da8n7c8buY
         MPBTWv8Y5TgnZmGTFc5BYBRp4IsCk1ze3jMvyNZKcV0OJRl9oGYAD+Wnb955blfuLeew
         rXlQFXZ335Ge4UQjcD4V9Zcmn/+fTy2AdRTeMrhK/c3MeNKQjUwS+LDEG2O8gfkLZb0/
         kkHA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=YAeNiVm0;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pg1-x52d.google.com (mail-pg1-x52d.google.com. [2607:f8b0:4864:20::52d])
        by gmr-mx.google.com with ESMTPS id m9si785354pgr.3.2021.03.21.22.52.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 21 Mar 2021 22:52:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as permitted sender) client-ip=2607:f8b0:4864:20::52d;
Received: by mail-pg1-x52d.google.com with SMTP id m7so7905120pgj.8
        for <kasan-dev@googlegroups.com>; Sun, 21 Mar 2021 22:52:04 -0700 (PDT)
X-Received: by 2002:aa7:9852:0:b029:211:6824:6c7d with SMTP id n18-20020aa798520000b029021168246c7dmr17530016pfq.19.1616392324492;
        Sun, 21 Mar 2021 22:52:04 -0700 (PDT)
Received: from localhost (2001-44b8-1113-6700-b3b5-fa56-fd12-3c5a.static.ipv6.internode.on.net. [2001:44b8:1113:6700:b3b5:fa56:fd12:3c5a])
        by smtp.gmail.com with ESMTPSA id nk3sm12514893pjb.17.2021.03.21.22.52.03
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 21 Mar 2021 22:52:04 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Balbir Singh <bsingharora@gmail.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, christophe.leroy@csgroup.eu, aneesh.kumar@linux.ibm.com
Subject: Re: [PATCH v11 6/6] powerpc: Book3S 64-bit outline-only KASAN support
In-Reply-To: <20210322025934.GG77072@balbir-desktop>
References: <20210319144058.772525-1-dja@axtens.net> <20210319144058.772525-7-dja@axtens.net> <20210320060259.GF77072@balbir-desktop> <87o8fcatxv.fsf@dja-thinkpad.axtens.net> <20210322025934.GG77072@balbir-desktop>
Date: Mon, 22 Mar 2021 16:52:00 +1100
Message-ID: <87lfafburj.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=YAeNiVm0;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::52d as
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

Balbir Singh <bsingharora@gmail.com> writes:

> On Mon, Mar 22, 2021 at 11:55:08AM +1100, Daniel Axtens wrote:
>> Hi Balbir,
>> 
>> > Could you highlight the changes from
>> > https://patchwork.ozlabs.org/project/linuxppc-dev/patch/20170729140901.5887-1-bsingharora@gmail.com/?
>> >
>> > Feel free to use my signed-off-by if you need to and add/update copyright
>> > headers if appropriate.
>> 
>> There's not really anything in common any more:
>> 
>>  - ppc32 KASAN landed, so there was already a kasan.h for powerpc, the
>>    explicit memcpy changes, the support for non-instrumented files,
>>    prom_check.sh, etc. all already landed.
>> 
>>  - I locate the shadow region differently and don't resize any virtual
>>    memory areas.
>> 
>>  - The ARCH_DEFINES_KASAN_ZERO_PTE handling changed upstream and our
>>    handling for that is now handled more by patch 3.
>> 
>>  - The outline hook is now an inline function rather than a #define.
>> 
>>  - The init function has been totally rewritten as it's gone from
>>    supporting real mode to not supporting real mode and back.
>> 
>>  - The list of non-instrumented files has grown a lot.
>> 
>>  - There's new stuff: stack walking is now safe, KASAN vmalloc support
>>    means modules are better supported now, ptdump works, and there's
>>    documentation.
>> 
>> It's been a while now, but I don't think when I started this process 2
>> years ago that I directly reused much of your code. So I'm not sure that
>> a signed-off-by makes sense here? Would a different tag (Originally-by?)
>> make more sense?
>>
>
> Sure

Will do.

>  
>> >> + * The shadow ends before the highest accessible address
>> >> + * because we don't need a shadow for the shadow. Instead:
>> >> + * c00e000000000000 << 3 + a80e 0000 0000 0000 000 = c00fc00000000000
>> >
>> > The comment has one extra 0 in a80e.., I did the math and had to use
>> > the data from the defines :)
>> 
>> 3 extra 0s, even! Fixed.
>> 
>> >> +void __init kasan_init(void)
>> >> +{
>> >> +	/*
>> >> +	 * We want to do the following things:
>> >> +	 *  1) Map real memory into the shadow for all physical memblocks
>> >> +	 *     This takes us from c000... to c008...
>> >> +	 *  2) Leave a hole over the shadow of vmalloc space. KASAN_VMALLOC
>> >> +	 *     will manage this for us.
>> >> +	 *     This takes us from c008... to c00a...
>> >> +	 *  3) Map the 'early shadow'/zero page over iomap and vmemmap space.
>> >> +	 *     This takes us up to where we start at c00e...
>> >> +	 */
>> >> +
>> >
>> > assuming we have
>> > #define VMEMMAP_END R_VMEMMAP_END
>> > and ditto for hash we probably need
>> >
>> > 	BUILD_BUG_ON(VMEMMAP_END + KASAN_SHADOW_OFFSET != KASAN_SHADOW_END);
>> 
>> Sorry, I'm not sure what this is supposed to be testing? In what
>> situation would this trigger?
>>
>
> I am bit concerned that we have hard coded (IIR) 0xa80e... in the
> config, any changes to VMEMMAP_END, KASAN_SHADOW_OFFSET/END
> should be guarded.
>

Ah that makes sense. I'll come up with some test that should catch any
unsynchronised changes to VMEMMAP_END, KASAN_SHADOW_OFFSET or
KASAN_SHADOW_END.

Kind regards,
Daniel Axtens

> Balbir Singh.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87lfafburj.fsf%40dja-thinkpad.axtens.net.
