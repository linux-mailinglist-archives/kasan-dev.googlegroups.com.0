Return-Path: <kasan-dev+bncBCXLBLOA7IGBB74X5XXQKGQE4MSFO2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id 65250125E86
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 11:08:00 +0100 (CET)
Received: by mail-lj1-x238.google.com with SMTP id l10sf1736994ljb.15
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Dec 2019 02:08:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576750080; cv=pass;
        d=google.com; s=arc-20160816;
        b=A5YAZO8ZkCJhB6naA3UotqM4RryUyC8ykje0Oz/unVa7nhYuKrhF/5LfIT8DIg04W6
         NSQqaf1vAqGjJmmw1GxdSh8baXLHIR88mJnU/PBB31SDK4qcwBEquxyGq4jLHtQIUqSt
         JNLCI6JT4FFYJmSdaWGkkeitrPCdn5kUBOmPxsJepjjtjUJLV55Wcuoh6dLDe2YbFrub
         pNnNxiNmjiNXv+kuNRW70/b1+hRIYqULcbNyBxK6bMfJCmRrZmWy8xQWNSp6gc3Zt08L
         Hq1GYK9G1wMRAoijKX+yrQUW+3dLzf15tykkOsw3rYPLMItZa3D9BztoJ6bxLyw/spn9
         YITw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:to:from:subject:sender:dkim-signature;
        bh=a5FiT8FfAdx8Jul3KiLkpggS/KPmeTIfqBMDrlm2FTc=;
        b=cl1uY7lBR+udpwMkZEweApr5lswCw3HLjpBnz3JKLZle9INlyDtsms+JjQXYqdKb+x
         mTAcLAIAgDrnYA95lltrM/sMLgu+DtlR2n6XywCOE9+uPe0NmnNJAZbKrCpQw0aqe7Zc
         Y3u/m6H+KaEAxjYhKoNhhCBRwQHNbKUEwLsaypzS4GP0A0zR+oLWc2TC8zrE+Olz/M/J
         x7UQM2vmrDK+8CUnZgIfiNjRzpRNp/fNAG2ZdroVHcig9R+uoN+0zYOHV+0DipmxfLKo
         mQgYxTMAeYxsRXWWbRbjc7Wmc5flKWDG2Y5Tc37Zq0Q7c4IeEgw3XnUdzpBbZvRfLqjU
         XAnw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=AmDlgp2G;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:from:to:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a5FiT8FfAdx8Jul3KiLkpggS/KPmeTIfqBMDrlm2FTc=;
        b=CCcNo7B449rh4FxlyMGIK15Fo7zdPLo4sZbgZ1EqUz0n0JNwJgKyIAHxqsPBZFtL52
         o4rDcLnCAx8/ynGePfoHM9Q9aWeWnYIpD94KcyNPLyAMQxNjSxCkwrUf/XQ6zFJdjoop
         vDBVGxt5I3H1qm+Kixysz1vmXRqj1q7GyHu+0bDxYf3IK9n7XNHgtIjHXFqoZUOojEjh
         TovGLr2g8ycX7V0BngA+RIq58GszcqAA7dLDwu/VPFp5xzb1PAOq9xl0QhzKNgjBG3kQ
         BQBzkl1/AOCpmuJkuid52lF77Ov+7Ziyl2KMeYl6LR9XV/LQomaX91lJD/GIGdVl7VA6
         I3tA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:from:to:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=a5FiT8FfAdx8Jul3KiLkpggS/KPmeTIfqBMDrlm2FTc=;
        b=YHdb5MBgOUaBHIlZ1iuD7pIimeT8w3pcaxA8qSXkxFzXhgklUW5KajAUvqNSyEj31V
         AqUWI9H+q8E3h7eCWs94yrEOS4SYmpypFqv+39ZXa6iFpCGzFU3Z5wqXimKs5Y4v0qO9
         4hDMRh9rVkERsXWRy7LmF/5LdMmp44RedV4f5Adr5i+d98J9Kbil+qGbgfOsQoTNQB6o
         jzkAYk9TI08VX9wgdBo4uqr9m20FrSPYjTFI+K98GTqoTzwKGmKjUY2JT/ADxPdM2i0y
         g3T76NEaCCkUzfUdqSEnyT6bPmO04JclLR06mu7GMGJD4EBpq8wmbSvc6CvdymZlgpNX
         0+mw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXHEh7MGBClDd8E+oMgSNvLDwleN41GxRMgl85IyBfG0/ZF7gNX
	11GMq6+sJ+P0gxqohCBasBM=
X-Google-Smtp-Source: APXvYqxQqkssoRQ/w/oMvaVmvFExYHr8vUU1QVilXs2w9bmqV8XZzT8ugHE3tP6YMTKKaFbl5namQQ==
X-Received: by 2002:a2e:83cc:: with SMTP id s12mr5249990ljh.11.1576750079875;
        Thu, 19 Dec 2019 02:07:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a49c:: with SMTP id h28ls716438lji.11.gmail; Thu, 19 Dec
 2019 02:07:59 -0800 (PST)
X-Received: by 2002:a2e:8946:: with SMTP id b6mr3263379ljk.1.1576750079085;
        Thu, 19 Dec 2019 02:07:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576750079; cv=none;
        d=google.com; s=arc-20160816;
        b=muyPnizai2BJHDsq9JPGQhqP89W8jNdb1iQyxgdfgtm6QIfQYNhukVep9EP8HHdtnS
         iK4vmk/3kCByUALLYa02RBI0e84o1/vRFOBRTB8ytP/0y+vR778U0f+Qwa2n3aRDTbXv
         2nrns6Bme6jiS5WdHnIG8v4Is+hykBUAQbEG6LlGrjcLxR6DtB4jc+KxsvzC71TiT+Q6
         wsxwVUccY3sMbVjMpfvO3gR23V+6dwvJ3Ghh6VFU/OZF/GFTO4Q46Wkf2CpoRx39vN16
         1l5I0jPmZfAk8g/Ej1NTsrwvTK8+2iHXkZRj551e1ePBAH+0oUzrOkhaD2KzHOA9jDfq
         BUSQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:references:to:from:subject
         :dkim-signature;
        bh=/4zEamhLSd+OmHEjHewPY8apoChkej0LywPcTIUtggs=;
        b=zpIDPYslwcT2xopUtNjNgfWJzjev/0GGghvNUcKquW9EFSAbO4kXUoWEusmCddDN09
         NgyjrPPaaNiIVmQwxLUbn21MutnDIDzU8kkDrYy4AU6A7Q3IaH2dbG8XC+knfvcoQiAV
         +tNdKKvwZYuFZpUPhfLF7fptnqGvAKhlDsfYX5UvOV2nRullueXz+XA/hj5bLNAvFoxl
         AbWSW2kqs55ShOv+hk9/kcIt7aRKUdeaTsm8NX6USx0nnGx7jgtiIVWwhiTLliKNtKYy
         0np/6ft0b6cvQpPS0o4VHmezK72E/+CMmHc769qyl3eDHdO/pfZxVwtLnpeMceag9qX0
         m/kw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=AmDlgp2G;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id x5si226226ljh.5.2019.12.19.02.07.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 19 Dec 2019 02:07:59 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47dncs1fSZz9txdZ;
	Thu, 19 Dec 2019 11:07:57 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id FMPZ0PcMguUF; Thu, 19 Dec 2019 11:07:57 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47dncs0W1Mz9txdX;
	Thu, 19 Dec 2019 11:07:57 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 2ACE68B7AD;
	Thu, 19 Dec 2019 11:07:58 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id C_K90wc5tv2M; Thu, 19 Dec 2019 11:07:58 +0100 (CET)
Received: from po16098vm.idsi0.si.c-s.fr (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 6F0CB8B787;
	Thu, 19 Dec 2019 11:07:57 +0100 (CET)
Subject: Re: [PATCH v4 4/4] powerpc: Book3S 64-bit "heavyweight" KASAN support
From: Christophe Leroy <christophe.leroy@c-s.fr>
To: Daniel Axtens <dja@axtens.net>, linux-kernel@vger.kernel.org,
 linux-mm@kvack.org, linuxppc-dev@lists.ozlabs.org,
 kasan-dev@googlegroups.com, aneesh.kumar@linux.ibm.com, bsingharora@gmail.com
References: <20191219003630.31288-1-dja@axtens.net>
 <20191219003630.31288-5-dja@axtens.net>
 <c4d37067-829f-cd7d-7e94-0ec2223cce71@c-s.fr>
 <87bls4tzjn.fsf@dja-thinkpad.axtens.net>
 <4f2fffb3-5fb6-b5ea-a951-a7910f2439b8@c-s.fr>
Message-ID: <76c5aa20-7993-9501-514d-10e0b6d882d1@c-s.fr>
Date: Thu, 19 Dec 2019 10:07:57 +0000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:52.0) Gecko/20100101
 Thunderbird/52.7.0
MIME-Version: 1.0
In-Reply-To: <4f2fffb3-5fb6-b5ea-a951-a7910f2439b8@c-s.fr>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=AmDlgp2G;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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



On 12/19/2019 10:05 AM, Christophe Leroy wrote:
>=20
>=20
> Le 19/12/2019 =C3=A0 10:50, Daniel Axtens a =C3=A9crit=C2=A0:
>> Christophe Leroy <christophe.leroy@c-s.fr> writes:
>>
>>> On 12/19/2019 12:36 AM, Daniel Axtens wrote:
>>>> KASAN support on Book3S is a bit tricky to get right:
>>>>
>>>> =C2=A0=C2=A0 - It would be good to support inline instrumentation so a=
s to be=20
>>>> able to
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 catch stack issues that cannot be caught with=
 outline mode.
>>>>
>>>> =C2=A0=C2=A0 - Inline instrumentation requires a fixed offset.
>>>>
>>>> =C2=A0=C2=A0 - Book3S runs code in real mode after booting. Most notab=
ly a lot=20
>>>> of KVM
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 runs in real mode, and it would be good to be=
 able to=20
>>>> instrument it.
>>>>
>>>> =C2=A0=C2=A0 - Because code runs in real mode after boot, the offset h=
as to=20
>>>> point to
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 valid memory both in and out of real mode.
>>>>
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 [ppc64 mm note: The kernel installs a l=
inear mapping at effective
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 address c000... onward. This is a one-t=
o-one mapping with=20
>>>> physical
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 memory from 0000... onward. Because of =
how memory accesses=20
>>>> work on
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 powerpc 64-bit Book3S, a kernel pointer=
 in the linear map=20
>>>> accesses the
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 same memory both with translations on (=
accessing as an 'effective
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 address'), and with translations off (a=
ccessing as a 'real
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 address'). This works in both guests an=
d the hypervisor. For more
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 details, see s5.7 of Book III of versio=
n 3 of the ISA, in=20
>>>> particular
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 the Storage Control Overview, s5.7.3, a=
nd s5.7.5 - noting that=20
>>>> this
>>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 KASAN implementation currently only sup=
ports Radix.]
>>>>
>>>> One approach is just to give up on inline instrumentation. This way al=
l
>>>> checks can be delayed until after everything set is up correctly,=20
>>>> and the
>>>> address-to-shadow calculations can be overridden. However, the=20
>>>> features and
>>>> speed boost provided by inline instrumentation are worth trying to do
>>>> better.
>>>>
>>>> If _at compile time_ it is known how much contiguous physical memory a
>>>> system has, the top 1/8th of the first block of physical memory can=20
>>>> be set
>>>> aside for the shadow. This is a big hammer and comes with 3 big
>>>> consequences:
>>>>
>>>> =C2=A0=C2=A0 - there's no nice way to handle physically discontiguous =
memory,=20
>>>> so only
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 the first physical memory block can be used.
>>>>
>>>> =C2=A0=C2=A0 - kernels will simply fail to boot on machines with less =
memory than
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 specified when compiling.
>>>>
>>>> =C2=A0=C2=A0 - kernels running on machines with more memory than speci=
fied when
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 compiling will simply ignore the extra memory=
.
>>>>
>>>> Implement and document KASAN this way. The current implementation is=
=20
>>>> Radix
>>>> only.
>>>>
>>>> Despite the limitations, it can still find bugs,
>>>> e.g. http://patchwork.ozlabs.org/patch/1103775/
>>>>
>>>> At the moment, this physical memory limit must be set _even for outlin=
e
>>>> mode_. This may be changed in a later series - a different=20
>>>> implementation
>>>> could be added for outline mode that dynamically allocates shadow at a
>>>> fixed offset. For example, see=20
>>>> https://patchwork.ozlabs.org/patch/795211/
>>>>
>>>> Suggested-by: Michael Ellerman <mpe@ellerman.id.au>
>>>> Cc: Balbir Singh <bsingharora@gmail.com> # ppc64 out-of-line radix=20
>>>> version
>>>> Cc: Christophe Leroy <christophe.leroy@c-s.fr> # ppc32 version
>>>> Signed-off-by: Daniel Axtens <dja@axtens.net>
>>>>
>>>> ---
>>>> Changes since v3:
>>>> =C2=A0=C2=A0 - Address further feedback from Christophe.
>>>> =C2=A0=C2=A0 - Drop changes to stack walking, it looks like the issue =
I=20
>>>> observed is
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 related to that particular stack, not stack-w=
alking generally.
>>>>
>>>> Changes since v2:
>>>>
>>>> =C2=A0=C2=A0 - Address feedback from Christophe around cleanups and do=
cs.
>>>> =C2=A0=C2=A0 - Address feedback from Balbir: at this point I don't hav=
e a good=20
>>>> solution
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 for the issues you identify around the limita=
tions of the=20
>>>> inline implementation
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 but I think that it's worth trying to get the=
 stack=20
>>>> instrumentation support.
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 I'm happy to have an alternative and more fle=
xible outline mode=20
>>>> - I had
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 envisoned this would be called 'lightweight' =
mode as it imposes=20
>>>> fewer restrictions.
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 I've linked to your implementation. I think i=
t's best to add it=20
>>>> in a follow-up series.
>>>> =C2=A0=C2=A0 - Made the default PHYS_MEM_SIZE_FOR_KASAN value 1024MB. =
I think=20
>>>> most people have
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 guests with at least that much memory in the =
Radix 64s case so=20
>>>> it's a much
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 saner default - it means that if you just tur=
n on KASAN without=20
>>>> reading the
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 docs you're much more likely to have a bootab=
le kernel, which=20
>>>> you will never
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 have if the value is set to zero! I'm happy t=
o bikeshed the=20
>>>> value if we want.
>>>>
>>>> Changes since v1:
>>>> =C2=A0=C2=A0 - Landed kasan vmalloc support upstream
>>>> =C2=A0=C2=A0 - Lots of feedback from Christophe.
>>>>
>>>> Changes since the rfc:
>>>>
>>>> =C2=A0=C2=A0 - Boots real and virtual hardware, kvm works.
>>>>
>>>> =C2=A0=C2=A0 - disabled reporting when we're checking the stack for ex=
ception
>>>> =C2=A0=C2=A0=C2=A0=C2=A0 frames. The behaviour isn't wrong, just incom=
patible with KASAN.
>>>>
>>>> =C2=A0=C2=A0 - Documentation!
>>>>
>>>> =C2=A0=C2=A0 - Dropped old module stuff in favour of KASAN_VMALLOC.
>>>>
>>>> The bugs with ftrace and kuap were due to kernel bloat pushing
>>>> prom_init calls to be done via the plt. Because we did not have
>>>> a relocatable kernel, and they are done very early, this caused
>>>> everything to explode. Compile with CONFIG_RELOCATABLE!
>>>> ---
>>>> =C2=A0=C2=A0 Documentation/dev-tools/kasan.rst=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 8 +-
>>>> =C2=A0=C2=A0 Documentation/powerpc/kasan.txt=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 | 112=20
>>>> ++++++++++++++++++-
>>>> =C2=A0=C2=A0 arch/powerpc/Kconfig=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 2 +
>>>> =C2=A0=C2=A0 arch/powerpc/Kconfig.debug=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 21 ++++
>>>> =C2=A0=C2=A0 arch/powerpc/Makefile=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 11 ++
>>>> =C2=A0=C2=A0 arch/powerpc/include/asm/book3s/64/hash.h=C2=A0=C2=A0=C2=
=A0 |=C2=A0=C2=A0 4 +
>>>> =C2=A0=C2=A0 arch/powerpc/include/asm/book3s/64/pgtable.h |=C2=A0=C2=
=A0 7 ++
>>>> =C2=A0=C2=A0 arch/powerpc/include/asm/book3s/64/radix.h=C2=A0=C2=A0 |=
=C2=A0=C2=A0 5 +
>>>> =C2=A0=C2=A0 arch/powerpc/include/asm/kasan.h=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0 21 +++-
>>>> =C2=A0=C2=A0 arch/powerpc/kernel/prom.c=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0 |=C2=A0 61 +++++++++-
>>>> =C2=A0=C2=A0 arch/powerpc/mm/kasan/Makefile=C2=A0=C2=A0=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 1 +
>>>> =C2=A0=C2=A0 arch/powerpc/mm/kasan/init_book3s_64.c=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 |=C2=A0 70 ++++++++++++
>>>> =C2=A0=C2=A0 arch/powerpc/platforms/Kconfig.cputype=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 |=C2=A0=C2=A0 1 +
>>>> =C2=A0=C2=A0 13 files changed, 316 insertions(+), 8 deletions(-)
>>>> =C2=A0=C2=A0 create mode 100644 arch/powerpc/mm/kasan/init_book3s_64.c
>>>>
>>>> diff --git a/arch/powerpc/include/asm/kasan.h=20
>>>> b/arch/powerpc/include/asm/kasan.h
>>>> index 296e51c2f066..f18268cbdc33 100644
>>>> --- a/arch/powerpc/include/asm/kasan.h
>>>> +++ b/arch/powerpc/include/asm/kasan.h
>>>> @@ -2,6 +2,9 @@
>>>> =C2=A0=C2=A0 #ifndef __ASM_KASAN_H
>>>> =C2=A0=C2=A0 #define __ASM_KASAN_H
>>>> +#include <asm/page.h>
>>>> +#include <asm/pgtable.h>
>>>
>>> What do you need asm/pgtable.h for ?
>>>
>>> Build failure due to circular inclusion of asm/pgtable.h:
>>
>> I see there's a lot of ppc32 stuff, I clearly need to bite the bullet
>> and get a ppc32 toolchain so I can squash these without chewing up any
>> more of your time. I'll sort that out and send a new spin.
>>
>=20
> I'm using a powerpc64 toolchain to build both ppc32 and ppc64 kernels=20
> (from https://mirrors.edge.kernel.org/pub/tools/crosstool/ )
>=20
>=20
> Another thing, did you test PTDUMP stuff with KASAN ? It looks like=20
> KASAN address markers don't depend on PPC32, but are only initialised by=
=20
> populate_markers() for PPC32.
>=20
> Regarding kasan.h, I think we should be able to end up with something=20
> where the definition of KASAN_SHADOW_OFFSET should only depend on the=20
> existence of CONFIG_KASAN_SHADOW_OFFSET, and where only=20
> KASAN_SHADOW_SIZE should depend on the target (ie PPC32 or BOOK3S64)
> Everything else should be common. KASAN_END should be START+SIZE.
>=20
> It looks like what you have called KASAN_SHADOW_SIZE is not similar to=20
> what is called KASAN_SHADOW_SIZE for PPC32, as yours only covers the=20
> SHADOW_SIZE for linear mem while PPC32 one covers the full space.
>=20

More or less something like that:

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_KASAN_H
#define __ASM_KASAN_H

#include <asm/page.h>

#ifdef CONFIG_KASAN
#define _GLOBAL_KASAN(fn)	_GLOBAL(__##fn)
#define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(__##fn)
#define EXPORT_SYMBOL_KASAN(fn)	EXPORT_SYMBOL(__##fn)
#else
#define _GLOBAL_KASAN(fn)	_GLOBAL(fn)
#define _GLOBAL_TOC_KASAN(fn)	_GLOBAL_TOC(fn)
#define EXPORT_SYMBOL_KASAN(fn)
#endif

#ifndef __ASSEMBLY__

#define KASAN_SHADOW_SCALE_SHIFT	3

#define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))

#define KASAN_SHADOW_END	(KASAN_SHADOW_START + KASAN_SHADOW_SIZE)


#ifdef CONFIG_KASAN_SHADOW_OFFSET
#define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
#endif

#ifdef CONFIG_PPC32
#define KASAN_SHADOW_SIZE	((-PAGE_OFFSET) >> KASAN_SHADOW_SCALE_SHIFT)
#endif

#ifdef CONFIG_PPC_BOOK3S_64
#define KASAN_SHADOW_SIZE (ASM_CONST(CONFIG_PHYS_MEM_SIZE_FOR_KASAN) *=20
SZ_1G) >> \
			   KASAN_SHADOW_SCALE_SHIFT)
#endif


#ifdef CONFIG_KASAN
void kasan_early_init(void);
void kasan_mmu_init(void);
void kasan_init(void);
#else
static inline void kasan_init(void) { }
static inline void kasan_mmu_init(void) { }
#endif

#endif /* __ASSEMBLY */
#endif



Christophe

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/76c5aa20-7993-9501-514d-10e0b6d882d1%40c-s.fr.
