Return-Path: <kasan-dev+bncBCRKNY4WZECBBGM4Y2BAMGQEZKK3IIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id F198233E8B7
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Mar 2021 06:05:30 +0100 (CET)
Received: by mail-qk1-x737.google.com with SMTP id g62sf5175157qkf.18
        for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 22:05:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615957529; cv=pass;
        d=google.com; s=arc-20160816;
        b=j62GcGK2alH9Dzwd9d8SyTSZqCETTxqdJmCFb0VICNPA9OcmpU1JKmCFeDdKEMvFu3
         TQ+TYNW+pGyEYeM/5B9WZHZERxvIhsZtKU65RuLMFH0Iqp3CzceJpOyVvWiPhPDNV0bm
         VTXqFm1tc/zgz7+SWZA7OhGbjGGOMD5OZDV+L7TiBGUIrrEMtjgPl2P6umm+UWY/qukc
         iTyRZ+eIXPmJqv8kuoJn6CUmHUTaV9YfzxOuwBZX9Utl4JMoLiVg45jMCmc/053QFMHR
         4W2zs/SijvwWbHE7wiFB78D58C9ZkDNWiviYC7p9bkaijhNn7Vk58/FrJ6KtUHjAmrgZ
         fiMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:to:from:cc:in-reply-to:subject:date:sender
         :dkim-signature;
        bh=QrHuP1W7JCYNI13OMDCAX84j3bj/eWWemAJyQF54p5w=;
        b=wUyi40fGyKBDfcNYc2V1TvAhCGsKZPpQZNzZdJIuuol/LF3wYmXrNmVxndpWTIKOpW
         MQ8HvKeJS8BYYaz/V1YUJ1a0JLcVpD4pNMlJeLZU8G5EhcoDda6lZ+t/WDX3XEPfZwhE
         bNt5oKRU7xmufRnJPVbi2Hrmftldxp6ek6uuu0lAqYdFrwnEVsLqFZlUBhsYlYWVY5sQ
         mxHpeAv3WNGdmPLz5jqElf55IQ+TDDQeclcsoaGxft57uEu5IHIWKqYV3bJkYgFKSs+t
         huoHqRM7lpwoBH7XtWunDuaYs9GaP1MMcR32haOKM92+mB8Sz5ewipyPR51jyg6Z1sgZ
         HJlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=fU9xwamV;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QrHuP1W7JCYNI13OMDCAX84j3bj/eWWemAJyQF54p5w=;
        b=ZJm1ypySSyY+GIc4P1Hh5Y2M+SFNSfUcl06iMMJlR3Nhymb4mAzRnqK53vg3BJNkfB
         n2X7K55dCih5bSEBfope8XS8FZHR6Y455sBjWhwhzvVy5T5//xlkqFaX7kX5J9tjjCwv
         X2iVNDYq1pvfLIjPp5co7BlF5Qg3pSEDE0ZyWESbz8cKU49PHY8jtrOPIEb0bKsPmxfC
         R2NmaZ+cihGwE2p6/vJV1/7cD5fwN95qAaIrEO7Ovf06o7fXk13FNgCjuiYRq7A157Oz
         Y8HUUjBICoBUn4ogQji523eqERPdlfTTAnqKo7rHPdxz1YyKwvQOacSKuoxpi3EpUtXr
         NQ2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QrHuP1W7JCYNI13OMDCAX84j3bj/eWWemAJyQF54p5w=;
        b=I9kD0V9gHvgSV2e32VhRuF6j/PIkkffc6+6DjPg5yOGlpsaOSBIM8WMsl43SxIHAbV
         gulI3lFWsNcitvYvrfj88Wp5eXomJZkXjKnea6scfU9KarLT69Xklgb5QRrzmoLSmxlm
         3C0RIMExccRPCsVObvNck1lt7kCutFOJDz+KiUKLLMQ+kH6KgB28E41QCf8ex102SLOT
         GOm9M+zIkDgTHPXMQMz0fq/3/Uv1qyEzKSq98Khe9vTGxXuLxC7KOYdt3eKCqlA/ghoR
         NGyu5+kDFjW4i6/Vl9OXV/EX7HZxLQkrikd9CND8yoDe+WE2asEIFTGB01h583VgTyEh
         /f1w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530sUVLK6duks2YdEOIG0+vxH8Gz6cxySV7QZuJcQeg7ylAHA1Qh
	22fgp/SIoXngHWV7ibTpm2c=
X-Google-Smtp-Source: ABdhPJwSwTypsCYjhitl0IeS2PQFwv/6mDK575lCZF+UdOhtYRYq/SIcuUbWvfaz1g6WMBJQaoXtuw==
X-Received: by 2002:a0c:a692:: with SMTP id t18mr3316774qva.18.1615957529784;
        Tue, 16 Mar 2021 22:05:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4096:: with SMTP id f22ls6485141qko.7.gmail; Tue,
 16 Mar 2021 22:05:29 -0700 (PDT)
X-Received: by 2002:a05:620a:38f:: with SMTP id q15mr2781194qkm.379.1615957529332;
        Tue, 16 Mar 2021 22:05:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615957529; cv=none;
        d=google.com; s=arc-20160816;
        b=nUi5oPr2O83K2AifFPfcFxb83OD8B+h/LQ8FCwOFTh8Ge1IRlb4hQuFIB6oxgbZ/xf
         x8WRG307U3S015b4L4zhKPCur3sKHdSUPDe1MGUzNV+0ASElpJvJr00heXxaDJw3YFx/
         JsI6TvtlgeUopSsdqMbajAVbMU0bIa8sLCxRpTLV1JEsyGZJJIprKC1HLm0lE3/1B9iA
         bZ28b1l22BjIdWoKlGs6IgOA1bzZ/4Tr0ulNQ5Ufi7b9kJct3jG7auLw++wbG3PKMw9e
         yLJLfYR2nk62ZXICSbvCBVz8ORHbQTTHTNY5LfomE6LIDyO5c2y/0FjiuIOYfr5A2X4T
         TerA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=MIc7mavbJhN4OuOMILSSjW63cQv0oc3j9t7W7Zfvn3k=;
        b=O6HBZHxrO3pQ1BiSdfgilst43pS5Ok3rCc8HolOAduM/lOPaLVvfGy36Cw1+45bhhB
         Gjq9Mbb7dpVlzLpgcnWaMyHkaxlBlCVczuhBSIq5SQ0Plb5hHLLdJY0bkre2m+YuS3Pz
         feqcDxj/Ls8Sxtn2p4DjwxTgwhgqCsYH4vLpEdLGEmo483fLQQiegFOPp84cv5oMBjOz
         1KqGGIUktIuX/mrwWGL2aNGAsjLF5jrrzW0nOo+oVCec7p/X4osUNUHmqkN6g1XPt39+
         Zqxsqmcildyuq8DkLNlonSe/SEJJVVN1x/NcXBcH02qMTPJZ7Q7IpKP3AAcyg/9Z7sX/
         6SqA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=fU9xwamV;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pg1-x52c.google.com (mail-pg1-x52c.google.com. [2607:f8b0:4864:20::52c])
        by gmr-mx.google.com with ESMTPS id w19si1003713qto.4.2021.03.16.22.05.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 16 Mar 2021 22:05:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::52c as permitted sender) client-ip=2607:f8b0:4864:20::52c;
Received: by mail-pg1-x52c.google.com with SMTP id o10so24087920pgg.4
        for <kasan-dev@googlegroups.com>; Tue, 16 Mar 2021 22:05:29 -0700 (PDT)
X-Received: by 2002:a62:e708:0:b029:1f8:c092:ff93 with SMTP id s8-20020a62e7080000b02901f8c092ff93mr2675554pfh.21.1615957528395;
        Tue, 16 Mar 2021 22:05:28 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id i17sm19789935pfq.135.2021.03.16.22.05.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 16 Mar 2021 22:05:27 -0700 (PDT)
Date: Tue, 16 Mar 2021 22:05:27 -0700 (PDT)
Subject: Re: [PATCH 0/3] Move kernel mapping outside the linear mapping
In-Reply-To: <0bb85388-c4e1-523a-9bf3-0ccec6c4041e@ghiti.fr>
CC: corbet@lwn.net, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  Arnd Bergmann <arnd@arndb.de>, aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com,
  linux-doc@vger.kernel.org, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, linux-arch@vger.kernel.org, linux-mm@kvack.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-08cda2bf-fcd9-4848-b549-632d015e1acd@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=fU9xwamV;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::52c as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Sat, 13 Mar 2021 01:26:47 PST (-0800), alex@ghiti.fr wrote:
> Hi Palmer,
>
> Le 3/9/21 =C3=A0 9:54 PM, Palmer Dabbelt a =C3=A9crit=C2=A0:
>> On Thu, 25 Feb 2021 00:04:50 PST (-0800), alex@ghiti.fr wrote:
>>> I decided to split sv48 support in small series to ease the review.
>>>
>>> This patchset pushes the kernel mapping (modules and BPF too) to the la=
st
>>> 4GB of the 64bit address space, this allows to:
>>> - implement relocatable kernel (that will come later in another
>>> =C2=A0 patchset) that requires to move the kernel mapping out of the li=
near
>>> =C2=A0 mapping to avoid to copy the kernel at a different physical addr=
ess.
>>> - have a single kernel that is not relocatable (and then that avoids th=
e
>>> =C2=A0 performance penalty imposed by PIC kernel) for both sv39 and sv4=
8.
>>>
>>> The first patch implements this behaviour, the second patch introduces =
a
>>> documentation that describes the virtual address space layout of the
>>> 64bit
>>> kernel and the last patch is taken from my sv48 series where I simply
>>> added
>>> the dump of the modules/kernel/BPF mapping.
>>>
>>> I removed the Reviewed-by on the first patch since it changed enough fr=
om
>>> last time and deserves a second look.
>>>
>>> Alexandre Ghiti (3):
>>> =C2=A0 riscv: Move kernel mapping outside of linear mapping
>>> =C2=A0 Documentation: riscv: Add documentation that describes the VM la=
yout
>>> =C2=A0 riscv: Prepare ptdump for vm layout dynamic addresses
>>>
>>> =C2=A0Documentation/riscv/index.rst=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 |=C2=A0 1 +
>>> =C2=A0Documentation/riscv/vm-layout.rst=C2=A0=C2=A0 | 61 ++++++++++++++=
++++++++
>>> =C2=A0arch/riscv/boot/loader.lds.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0 |=C2=A0 3 +-
>>> =C2=A0arch/riscv/include/asm/page.h=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
 | 18 ++++++-
>>> =C2=A0arch/riscv/include/asm/pgtable.h=C2=A0=C2=A0=C2=A0 | 37 +++++++++=
----
>>> =C2=A0arch/riscv/include/asm/set_memory.h |=C2=A0 1 +
>>> =C2=A0arch/riscv/kernel/head.S=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3 +-
>>> =C2=A0arch/riscv/kernel/module.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 |=C2=A0 6 +--
>>> =C2=A0arch/riscv/kernel/setup.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3 ++
>>> =C2=A0arch/riscv/kernel/vmlinux.lds.S=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 3=
 +-
>>> =C2=A0arch/riscv/mm/fault.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 13 +++++
>>> =C2=A0arch/riscv/mm/init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 81 +++++++++++++++++++++++-=
-----
>>> =C2=A0arch/riscv/mm/kasan_init.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0 |=C2=A0 9 ++++
>>> =C2=A0arch/riscv/mm/physaddr.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 2 +-
>>> =C2=A0arch/riscv/mm/ptdump.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 67 +++++++++++++++++++-----
>>> =C2=A015 files changed, 258 insertions(+), 50 deletions(-)
>>> =C2=A0create mode 100644 Documentation/riscv/vm-layout.rst
>>
>> This generally looks good, but I'm getting a bunch of checkpatch
>> warnings and some conflicts, do you mind fixing those up (and including
>> your other kasan patch, as that's likely to conflict)?
>
>
> I fixed a few checkpatch warnings and rebased on top of for-next but had
> not conflicts.
>
> I have just sent the v2.

Thanks.  These (and the second patch of the one I just put on fixes) are
for-next things, so I'm not going to get a look at them tonight because I w=
ant
to make sure we don't have any more fixes outstanding.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/mhng-08cda2bf-fcd9-4848-b549-632d015e1acd%40palmerdabbelt-glaptop=
.
