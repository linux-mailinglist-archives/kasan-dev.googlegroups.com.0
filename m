Return-Path: <kasan-dev+bncBDQ27FVWWUFRBEEBU2DAMGQE3MOE6IA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 689BF3A90AC
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jun 2021 06:39:46 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id h1-20020a63df410000b0290222939c0dd7sf732994pgj.4
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 21:39:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623818385; cv=pass;
        d=google.com; s=arc-20160816;
        b=tkdltvAI1Pe++IsdFM8wWeNBzYzUXJzD5sLYm96QrBwlYtzYqjdHJgMF9BnoopVJ0y
         u5fdUX7v5vyCnqp7pQpyXTaEgZkTe+YqGcQfaXZZAdLW7KIzHWhKTEW9MauwW6VjUgh9
         ZyMASgLdqY7EsVBJw1crN4y3fjxyUbSKBiQJFyIr/zyx6G8+JoH8jEQAFYGXOHkX/VAd
         sQjQXprYeZuZ0nzDXpb0VPW4j0f1ifcDDQJyl9pWh5k8bbscYmlYng87Rx0DEakuN8V8
         uxowoqah6I/W9unv45LBRFgh1374NiQHlBEZ4mkEsKodheToVO8KGsaUEmpvzwn+cTTM
         U/0A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=q4/OQSTiIeyspgzQIeepUgiCZNBtSpr2wNtFq5uMKRk=;
        b=flviUZvRhMKrMGQ7BqGAmTUJg0mt/VVKmw5O/3DI3lkutypdww6ikIa3epiNLmomZJ
         ofvXm09MZ2WCB78URd3VuH2WnrXoeBHlImQxR3OcSOGNke3rd2291Se/NkZKpwSealae
         /LxE38diSnsHeXLQ+HolOrLxzjjPvzD9RvlOF3kaySCBEsK09/PlwkYZ7OrP1AaGnIrg
         2yjzfdrDNx/neQ5M/P7mpR3sQ/0v0AniPu2OyRwfZLzc32Wh4XD2OxZMBBA/uWsMjGJi
         XWtGANGQCIKTzStWB0UpD8RppMdZ208P6G/sIPjwawc4OalKHuWZrI4v2XZ2H+z4smfx
         DXkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BhoZH0Nr;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q4/OQSTiIeyspgzQIeepUgiCZNBtSpr2wNtFq5uMKRk=;
        b=RgqgfbMswnXMfTKUa0sv2IQVXuSHEOF3Jp5M+KyV/s6tylJ/K0jFIsk79MOo156X1X
         DpOuP1bKTCQFDpkESWok55zMmnZ+IE2pW6/b4gGm/dGc7aIW8X0fk9Bot7TEpUm9rQDZ
         3QW8X0r1mqe9UuSYevi2pMLXHKAy2HCgho5ZkRwpOAy2bP96FeyWJZFd5p93yRdj1PPB
         rdz3Ebgl9XAm0EWURU9AedDcF61kDKN/oPzk7kMtN+bwjoWzVyyjMiHZ2u1i+xdhVpBB
         cye2HfuC/cttIaD2Mv9ldE8hMMRAv5xa+f2SxesrW6PFv9QHGAmHOeoER1Y+20oOkk9/
         yx4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=q4/OQSTiIeyspgzQIeepUgiCZNBtSpr2wNtFq5uMKRk=;
        b=NeJ1K5D9DvyNWWO5Hr7wXsXkeM3NdH8IhLk2ds/Ejabvjqac7QfPP8PImkbwtb9l6c
         6jiLB8rdX6qDGFZrbo7xmodNTwvehT2qSaj9/tZfhp3sglpqc1DDMnPr0BqoJVq/k2n7
         B8sxKCbtkoJJswGnI1Hy+GEUvB1w6kwEppthdaCmK24QJutkJwWJl8gdYEPMPZ0nUAL9
         dm63He+ywLAog4QKBmKt/GqROxeaAgh3NM6ipEij9fwE9rqTJFvnlk8wxNq3V1VxyFzw
         F5ERGSYKcIFJkgSCbBHxEo/cFZmxeaxWa7DbMeD7qCL8//RURhmzToZzrjnjV4yRc3ss
         DKTA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532i8p60d8txlmV8/3kISylhcOpe9lqVD/r4YHddNfeC075Z2Pww
	PW1gGF3fo09jIR4pfV+pV3o=
X-Google-Smtp-Source: ABdhPJwfGY5yYIlfr83wwdWNxQxPzrXHME3ChY/TbayvC+QUOihzllCUYpyf//2Oq899OGCJox0q4g==
X-Received: by 2002:a17:90b:517:: with SMTP id r23mr2882315pjz.209.1623818384814;
        Tue, 15 Jun 2021 21:39:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:d4b:: with SMTP id 11ls591093pgn.5.gmail; Tue, 15 Jun
 2021 21:39:44 -0700 (PDT)
X-Received: by 2002:a63:485a:: with SMTP id x26mr3056957pgk.159.1623818384115;
        Tue, 15 Jun 2021 21:39:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623818384; cv=none;
        d=google.com; s=arc-20160816;
        b=bEo9QIu46Ifcit8uY8gPm/rQYhI8QM4hUaqfCA3JIVec5C9nIbvEcGpNdR29aqzmHa
         tFDlyLFRObVQB9fshKMJ71WNHaCgny+bnTXfqpS3sFS7Gl3Z4wcsVsTFm7v72s39wtWC
         Tua3tixfha6ssu4guGsPjnI6Ce15iOtlTfNMbJU/2FJ9X/W8Fvv9cHCVDOeXTSceMWxN
         VDD00WOR9Z8gEQE5V0nFHidHraUEa/nQSqz/qMmXrPiJAbhTY0MFScfhob+UdhMBE3Nu
         cibNCuuWgaGv1IzOtgMBX9TPbLMiZvP78Mk5O2YHGYSeZAdqr13adH17IoZuZ4w5Vn4H
         k8Cg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:dkim-signature;
        bh=5w3M3t3Z4U9itzhliFyQ9k6bBdvkeu8fXdsAtgl3rqo=;
        b=bbvReDHgh11lpxBx0RIn2NMjdOXl4g7dhUhghXb5bVopMNXq8kBQcmhbg+hJMRM/QG
         yTxfn9PiTFBTLGbJ/IRlfkjSzF6DxBcK7Pqtf+EkmYNkZMUoVFa8DgqHL71O/2v/yBG0
         St2dt21lxHuudBz+CWe0Fzda4hSt5LW22k2OKWfVtT0i4hDs9xWfYHbSJsYHtFvSZJ6z
         k+x62QDNB8AQr/tY17pNI73+Nezdyfox/StwbXZeyN0lNtApQ3JVMXuIWfblvWSoA6N4
         0lH3woZy/UnhDv13rKmIBucbhrmJ19Qq+uH95zoIhmfNDu7Odo8a1yWAcdGMDnKAJNEj
         zXNg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=BhoZH0Nr;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id y205si95524pfc.6.2021.06.15.21.39.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 21:39:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id h1so487408plt.1
        for <kasan-dev@googlegroups.com>; Tue, 15 Jun 2021 21:39:43 -0700 (PDT)
X-Received: by 2002:a17:90b:1805:: with SMTP id lw5mr2950044pjb.120.1623818383687;
        Tue, 15 Jun 2021 21:39:43 -0700 (PDT)
Received: from localhost ([203.206.29.204])
        by smtp.gmail.com with ESMTPSA id f28sm732424pgb.12.2021.06.15.21.39.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jun 2021 21:39:43 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: Marco Elver <elver@google.com>
Cc: LKML <linux-kernel@vger.kernel.org>, Linux Memory Management List
 <linux-mm@kvack.org>, linuxppc-dev@lists.ozlabs.org, kasan-dev
 <kasan-dev@googlegroups.com>, Christophe Leroy
 <christophe.leroy@csgroup.eu>, aneesh.kumar@linux.ibm.com, Balbir Singh
 <bsingharora@gmail.com>
Subject: Re: [PATCH v12 1/6] kasan: allow an architecture to disable inline
 instrumentation
In-Reply-To: <CANpmjNOa-a=M-EgdkneiWDD0eCF-DELjMFxAeJzGQz6AgCdNWg@mail.gmail.com>
References: <20210615014705.2234866-1-dja@axtens.net>
 <20210615014705.2234866-2-dja@axtens.net>
 <CANpmjNOa-a=M-EgdkneiWDD0eCF-DELjMFxAeJzGQz6AgCdNWg@mail.gmail.com>
Date: Wed, 16 Jun 2021 14:39:38 +1000
Message-ID: <87im2ev2wl.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=BhoZH0Nr;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::62b as
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

Hi Marco,

@@ -12,6 +12,15 @@ config HAVE_ARCH_KASAN_HW_TAGS
>>  config HAVE_ARCH_KASAN_VMALLOC
>>         bool
>>
>> +# Sometimes an architecture might not be able to support inline instrumentation
>> +# but might be able to support outline instrumentation. This option allows an
>> +# arch to prevent inline and stack instrumentation from being enabled.
>
> This comment could be moved into 'help' of this new config option.

It could. I did wonder if that made sense given that this is not a user
selectable option so I'm not sure if the help will ever be visible, but
I see that we do this sort of thing in Kconfig.kcsan and Kconfig.kgdb.
I've changed it over.

>> +# ppc64 turns on virtual memory late in boot, after calling into generic code
>> +# like the device-tree parser, so it uses this in conjuntion with a hook in
>> +# outline mode to avoid invalid access early in boot.
>
> I think the ppc64-related comment isn't necessary and can be moved to
> arch/ppc64 somewhere, if there isn't one already.

Fair enough. I'll pull it out of this file and look for a good place to
put the information in arch/powerpc in a later patch/series.

Kind regards,
Daniel

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87im2ev2wl.fsf%40dja-thinkpad.axtens.net.
