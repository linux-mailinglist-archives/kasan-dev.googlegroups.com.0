Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBZ7VXT2AKGQEKFOKBZQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2389F1A36A1
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Apr 2020 17:10:34 +0200 (CEST)
Received: by mail-pf1-x43f.google.com with SMTP id e18sf8749754pfl.17
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Apr 2020 08:10:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586445032; cv=pass;
        d=google.com; s=arc-20160816;
        b=X/aajDN8EUBq+er6SOeMu3OtFjpwIVBUYlI1iKgGBPjrQVRjxToYTWm8eqkP529yfo
         NNWIok+nyv8+O1y3JQNFrsiJsIYqLyIRyOy5bZLKeBgkmmYGGDau/khSrnyCnsjAPM7N
         SjuFbgLoTSlGyRUlO0D5GAFpsQl8Bng5VqijpqAoZFkswQJth1yHD2bcaZybiw2Gi+KI
         9qghGFeuRQ7aediA1yOknZXHh37L/S2Rf/AY7QjnF7raOlQkVB7QYH626o5tSq2hCV/9
         yXrCDVZAjw5MdlRJnxKfEpzfquC8nnzXe3Y4OByOmLc0UULGZhkBwoa3EPSMbry69Kgz
         aIJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=jFkmtDJW8Et1IPBSc0ikmtZOFGr/czdooYchoA8E4X8=;
        b=bVPXVungOw39Sas6gpgmI6mFDo4K/pHKbQI3BTWoi+hRGnTPV5YFnb2NHWAta2dxc1
         DRNSgTO6Npda/6R5XlsIadhN/Gm5XelNLuNUba3vetETsXkCjvQwgeWcb+lbaRPqyrWl
         mcL8OIEDD3ny231wd373/rEfmJnrLwybNuGNoqV4XHMtaXCsSdw/IR2rYhu/elWjtWOh
         3g5zrye4m/phOoQU2gglJkHZuEQNgjhQzQm8k/o3PuCGtAK5ZnY9X/2ryHUxf8EuiIbP
         xz9aiWURZpL5WIPqsVjM47tGAMRGa5UpcaWU949CrFFAdhYCstmHfyrpwG2PLWThjLuJ
         DKIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=rropwxWi;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=jFkmtDJW8Et1IPBSc0ikmtZOFGr/czdooYchoA8E4X8=;
        b=fIrST9sVQ6jy35VAblk3RjpepOme433kqBdDq/ghlbV+VREwIkD6AzVCe/oCTPIyq0
         qaSBK8FK5oxR2HQMs46bcV6nY1fWnomw28sabaNObm4ocPBahz5XJajhvt4IPHm+xvjd
         sw9Azaibh6To25Px869DGQHPCraopmpHTFdOnL6FuJG9AEwEE/ewrJHGyUyT1iA60QFk
         3Dl9f22JkpOSb6HES3+eCTgkCaWiAoaE098UjdOVkOQrG8+LkrSWYtvS5Lwav/ZVS8/A
         CS717dTabwEfzcLGVEq9nMMdI3uxAtqHMK7Ri9Tz4XIrjsZJUEiDT14R4JSzng2osGT8
         Uqrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=jFkmtDJW8Et1IPBSc0ikmtZOFGr/czdooYchoA8E4X8=;
        b=SkvOPUKUqEOpPy5vIEAkUitRRXElJ5VX/PR+yBRAJxNn/OtxRiL+hpuW34h7H9EqEm
         5V0bo7wS3cLpWaSeEwpZHQtbo0S+14M0Ta26hyiLhDGhjcMM0dCYz507k1SSF1TE9skA
         q3w/+MOYUOd9By+PG1xQBdOo4b4VJWvZ6H7OHwJ1ISLucf1onNlkTCY99SP5ztOE6TvJ
         FNNcyayrgrBop5oeBoXASJ0r9rDXhRF2ckYC2iHdgbdVCzMmsiWEE87OGSlOqaZ6onz1
         +U8BS1EYvfP5reorJ3Rv6BIJSXK/4E0RF+b9VIDrFrSA0r9FnYgsRPQei2XhjnqHEuf4
         LFpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0Pub8AfdS2lBb+gNjOXNkkS4zjogwY3ecPztNS1D2JdsIvArHzwKb
	yhrmrjBpmTSvcMnyKj2aSAg=
X-Google-Smtp-Source: APiQypLwkqnQ5ckUmGE5o1rd5cJCsEeL68FMqGEl7gJqJa6b4fgAJ0qPfGvvE0t4T3ymGroTOucugA==
X-Received: by 2002:a65:6403:: with SMTP id a3mr323147pgv.222.1586445031945;
        Thu, 09 Apr 2020 08:10:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:98de:: with SMTP id e30ls6842785pfm.0.gmail; Thu, 09 Apr
 2020 08:10:31 -0700 (PDT)
X-Received: by 2002:a63:4463:: with SMTP id t35mr12534430pgk.412.1586445031394;
        Thu, 09 Apr 2020 08:10:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586445031; cv=none;
        d=google.com; s=arc-20160816;
        b=U209Is7N8K6z3NgBqOMbMmT7nBjoLrmK6gHsHgs8SUFaKBRkgMH7QHOlJjn1ol1dpW
         SE/863Yt6/+OTOA7/RkwFQ2BIqyEFY8xsnYrSReptSRG49VyeqFrfjxVF4k2Ifd6T4rQ
         TEINtGI3k3d546ciP1N4GS2S2C/zRuzsh9dDJ4aYhSdxfV6CyKyKKzJWIqKwDJPv7dDo
         GW7lMVLTVFPW/m5+t3b0Dqcc5t5pobDF3aFgkZ7IVEx+cmgBJ8QRMeih076A/mjgMPyU
         c3TUbJfT/qqc5gPFwsGhvHQaCN9N4H80Skof42Eas+JQWBZ5SwiQD0QxFfYXPEgqOywp
         KE3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=DIocbXZ/GrySYJM2qjlB0aVfLDG/I+8RC+5beeuDqKQ=;
        b=VfE0pfhq1NmmUNUGtGsSOdpmALYSnRixwsBd/cZs5m7tBdW/7e8znN3MaNM5JIL4uj
         9IAx8lpV7dIIRjeraL6duo7EUWHIXPGz5VQRHpBHe+Latt49mrwlMLUsnRBVJiio72IL
         QmpN8WN8Ye+SCgOQRiPvYmo2LtbHjjZhAXLYiikSc5oFqaNJ4QfNqtGxnl2evUtEQDFO
         dvCswMX/pGXUSFNVErhYFTTzu+qzqsGfHslh4fDoRJPkcJDGLKL1lqg0UhUQxgefLj+W
         8yXyWrbyJ9MrAKsKyV8+6mmGQzULblL72ZAovc8JNCAsuEI/nCP8zLtcS0TldI4w8rdH
         i1aA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=rropwxWi;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id e17si161141pjt.2.2020.04.09.08.10.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Apr 2020 08:10:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id v7so4286283qkc.0
        for <kasan-dev@googlegroups.com>; Thu, 09 Apr 2020 08:10:31 -0700 (PDT)
X-Received: by 2002:a05:620a:12fa:: with SMTP id f26mr282331qkl.374.1586445030295;
        Thu, 09 Apr 2020 08:10:30 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id y21sm21347011qka.37.2020.04.09.08.10.29
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Apr 2020 08:10:29 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: KCSAN + KVM = host reset
From: Qian Cai <cai@lca.pw>
In-Reply-To: <CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA@mail.gmail.com>
Date: Thu, 9 Apr 2020 11:10:28 -0400
Cc: Paolo Bonzini <pbonzini@redhat.com>,
 "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <B7F7F73E-EE27-48F4-A5D0-EBB29292913E@lca.pw>
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw>
 <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
 <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw>
 <CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=rropwxWi;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 9, 2020, at 3:03 AM, Marco Elver <elver@google.com> wrote:
>=20
> On Wed, 8 Apr 2020 at 23:29, Qian Cai <cai@lca.pw> wrote:
>>=20
>>=20
>>=20
>>> On Apr 8, 2020, at 5:25 PM, Paolo Bonzini <pbonzini@redhat.com> wrote:
>>>=20
>>> On 08/04/20 22:59, Qian Cai wrote:
>>>> Running a simple thing on this AMD host would trigger a reset right aw=
ay.
>>>> Unselect KCSAN kconfig makes everything work fine (the host would also
>>>> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before runn=
ing qemu-kvm).
>>>=20
>>> Is this a regression or something you've just started to play with?  (I=
f
>>> anything, the assembly language conversion of the AMD world switch that
>>> is in linux-next could have reduced the likelihood of such a failure,
>>> not increased it).
>>=20
>> I don=E2=80=99t remember I had tried this combination before, so don=E2=
=80=99t know if it is a
>> regression or not.
>=20
> What happens with KASAN? My guess is that, since it also happens with
> "off", something that should not be instrumented is being
> instrumented.

No, KASAN + KVM works fine.

>=20
> What happens if you put a 'KCSAN_SANITIZE :=3D n' into
> arch/x86/kvm/Makefile? Since it's hard for me to reproduce on this

Yes, that works, but this below alone does not work,

KCSAN_SANITIZE_kvm-amd.o :=3D n

I have been able to reproduce this on a few AMD hosts.

> exact system, I'd ask you to narrow it down by placing 'KCSAN_SANITIZE
> :=3D n' into suspect subsystems' Makefiles. Once you get it to work with
> that, we can refine the solution.
>=20
> Thanks,
> -- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/B7F7F73E-EE27-48F4-A5D0-EBB29292913E%40lca.pw.
