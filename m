Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBEFHX32AKGQEHZED77Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3e.google.com (mail-yb1-xb3e.google.com [IPv6:2607:f8b0:4864:20::b3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2BC3F1A3BE9
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Apr 2020 23:28:49 +0200 (CEST)
Received: by mail-yb1-xb3e.google.com with SMTP id 5sf425855ybx.13
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Apr 2020 14:28:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586467728; cv=pass;
        d=google.com; s=arc-20160816;
        b=b9Lu9rmCrGtp7qn3FrVo+MCBAMoC/qhJsRSS0gn7C3wigIJLcWmujrGQPOiABKmX4E
         0FBoxrBmM2GfRVM5CwMFZnqV2owRiYAI5UVbigbkZwqwV45vqolslEovTs2IrWMx1KX3
         sRAsKHKMiAkfuW9CY4xC3x+0mgnhny6KE8/GFVF/ag+teKfnJGAaJeKhW3CSyByB0rS2
         v39CcInM5H/ZkFGqiDpGimQqDS9Z1OjYCuqd+no1VCOOXMCQrOCHu5s3+qGnN7RCU0bx
         qNBROCp47Cgo801/K1fHgWxzS26VTu6XcN+nTu/4OXGbzgJNS2Lq9Pt0OvKxP8wa0GM3
         MIXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=gbdpA5A8hOFcbFcvMDG37xq3t+16LrwZNitPONm83r8=;
        b=ncOYJRkfLPGeLrcW4Vu2wCArnGO4Zhkb6eyAyQIiLktOa3rXk+irMG2OpB7buK5flc
         uYf/snUXQKaEPrUxGfkroE+IINZ0PqGqpxAqpsxEbHcjk7CX3wbyh94Yc3gjEdjAkJCC
         AG1yfhNJTxrVXO2L3TZyxysJcnceKn6JIjHUZoQ0wF9zvvYJlgPDmAL+i4SuQZtzsZ39
         pvkNnhkASsOIHIYAr70OX59FAokKbltXDF56hMVSsLk/0oDpJeIuC7ld1z9+ZcQndp2+
         v0axuA3KP4kGu8yCzEzLVCr6KNWF+c2ivmaVAqM13fnSVnWDMEFjCV6bd0W3TZRoqTFa
         DJVw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=L3VCXeGZ;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gbdpA5A8hOFcbFcvMDG37xq3t+16LrwZNitPONm83r8=;
        b=cO05mgiy41y/u75a6kI4v3OQepL2nfi4hyrJIo6f1h1VHJfQwMdsMJSMRF9thRHvfl
         jh99P4UzX2nK9+f54ZFtO68cmRZK76So/H0kAe20Y9AHhYibOBo2YW4GG+PSpXUodFja
         8pcjF7YuoLVUsodCMV0l7QGl+OcHxhIaZmT3paLLh/+Qr13yXjChOXRX7jb7XmeqOjyb
         0XPK8oF3/vkGs8x0JNextxr2HLfMsQ3bDpM4l+TSkTGZVA8tOyhjhZ1U6vGZYMKEkWQy
         Guh0V6BopfBdcR2xUVb8GRXH17FGaLv6W0EmgXTjEreU6Tnrzzh/H+l1fjXU7Eddk0od
         PXzA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=gbdpA5A8hOFcbFcvMDG37xq3t+16LrwZNitPONm83r8=;
        b=dZ7upxqPajavyBh4pTm+/ScYciFufsK0sNHzuSCfs045P8Fj2lDWSC4DHxIjZu79Vi
         oCWfq6A6V6i0gcU45770lbGITgVaD8hWDoY3OJcAAMuLkUvkyDD+gppdBSODUmpR42MF
         bCqu5eas1oSm585SV4EA1w9yT4/UnRlEwGMhOpoIX7HvwTn/9MfnVoAe9lKlMEkxOEUZ
         LZnUW0AcJJBnjvCupsaf6kC5qVPCRWhTbwnlIbF3MczAgBh8FGV5gqKR7GMTyFYQNtBk
         ZWnnLpEAFARLOOwtldCx9qjXfNXmNAwv4pHYBh8CuIE3/aeGayf5aDFaVN9kBQabWxnZ
         WGog==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZPVd1U83wA/NzpkHRau441vzbfZh4sR1lrRLOZ7j9HDpl9fR83
	+JwpvxXDBE+bl/vmqjLCjRw=
X-Google-Smtp-Source: APiQypLXnItzawaOyt7A7L0zXfwJprQbP7TUKlOYEK4rGeds/u0NlDW6YPUyIyXNLwws1SGoh5Gq7g==
X-Received: by 2002:a25:8883:: with SMTP id d3mr3057162ybl.217.1586467728166;
        Thu, 09 Apr 2020 14:28:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d6c8:: with SMTP id n191ls4755990ybg.4.gmail; Thu, 09
 Apr 2020 14:28:47 -0700 (PDT)
X-Received: by 2002:a25:2c43:: with SMTP id s64mr3077976ybs.21.1586467727639;
        Thu, 09 Apr 2020 14:28:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586467727; cv=none;
        d=google.com; s=arc-20160816;
        b=muwKdJJDqjxX62po5pkoMKPVAEE6u2UmQwXX/KZpITwtUjg5rO6V5w+//e7ejy+I11
         +dybfz54c3kacADprbYD6Xg3qq7/lkuR1qXRHebgBJljZ4WGY7hWJDg0LXQWBBqK995a
         tgM1OAiyyaY5bi4u/R0v4L9vImK03iNRmvr0jYNmvWV/v7Ki7qH7Qz1iU9KHPOux2SSR
         qVaCB2qQ+2iWK+M1AC9Y9nx0cxnBvxva2cMVBN2YEsNaw/YZ6GhbBT0xk93BbAo12oYW
         REoGDK6XsgEO6DKe0sv3JUr1oSv8R5u8IlvggmnzRcOv+jcl3VkFVihlRMr9MhBa88O1
         cRUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=KzqITVc/bBuEyLxzGIUIGtxALz12p2/0ce0mFYQIrPw=;
        b=OfWVf6HS9m5i+zBJqb73sAhP9kLKrYZE3Tvc6j5bFdjNtMJVm9TVxQr24vLktdVn9C
         LMgTr2/QNLLCX6CfRlhN+e499yyDufNdcUhtj8W3HDLkLl0L5Kw0bg7HYMbsusdzSWP7
         9tYDr/1FTUqg4/NG/06G9m73OaqzB0PUn63UVPXwIXWtneMq94Q4tmpItf/wkgcjOwOH
         L26vPdng7BNTZwrNqVfbqct9FGwQuSEn+Vp7gTwHIidFVAhWj8Hx/wpQP2qWZd0z/2yR
         bqnesFgDW/KeuoSmyxTTu5g6dLz791Kmcw9XUTUcrQDT8sB0lP2ECmyz9NTlZENpig6T
         dhLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=L3VCXeGZ;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x743.google.com (mail-qk1-x743.google.com. [2607:f8b0:4864:20::743])
        by gmr-mx.google.com with ESMTPS id s10si12321ybk.0.2020.04.09.14.28.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Apr 2020 14:28:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::743 as permitted sender) client-ip=2607:f8b0:4864:20::743;
Received: by mail-qk1-x743.google.com with SMTP id x66so272260qkd.9
        for <kasan-dev@googlegroups.com>; Thu, 09 Apr 2020 14:28:47 -0700 (PDT)
X-Received: by 2002:a37:a84f:: with SMTP id r76mr1035709qke.370.1586467727251;
        Thu, 09 Apr 2020 14:28:47 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id x68sm50341qka.129.2020.04.09.14.28.46
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Apr 2020 14:28:46 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: KCSAN + KVM = host reset
From: Qian Cai <cai@lca.pw>
In-Reply-To: <CANpmjNNUn9_Q30CSeqbU_TNvaYrMqwXkKCA23xO4ZLr2zO0w9Q@mail.gmail.com>
Date: Thu, 9 Apr 2020 17:28:45 -0400
Cc: Paolo Bonzini <pbonzini@redhat.com>,
 "paul E. McKenney" <paulmck@kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>,
 LKML <linux-kernel@vger.kernel.org>,
 kvm@vger.kernel.org
Content-Transfer-Encoding: quoted-printable
Message-Id: <B5F0F530-911E-4B75-886A-9D8C54FF49C8@lca.pw>
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw>
 <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
 <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw>
 <CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA@mail.gmail.com>
 <B7F7F73E-EE27-48F4-A5D0-EBB29292913E@lca.pw>
 <CANpmjNMEgc=+bLU472jy37hYPYo5_c+Kbyti8-mubPsEGBrm3A@mail.gmail.com>
 <2730C0CC-B8B5-4A65-A4ED-9DFAAE158AA6@lca.pw>
 <CANpmjNNUn9_Q30CSeqbU_TNvaYrMqwXkKCA23xO4ZLr2zO0w9Q@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=L3VCXeGZ;       spf=pass
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



> On Apr 9, 2020, at 12:03 PM, Marco Elver <elver@google.com> wrote:
>=20
> On Thu, 9 Apr 2020 at 17:30, Qian Cai <cai@lca.pw> wrote:
>>=20
>>=20
>>=20
>>> On Apr 9, 2020, at 11:22 AM, Marco Elver <elver@google.com> wrote:
>>>=20
>>> On Thu, 9 Apr 2020 at 17:10, Qian Cai <cai@lca.pw> wrote:
>>>>=20
>>>>=20
>>>>=20
>>>>> On Apr 9, 2020, at 3:03 AM, Marco Elver <elver@google.com> wrote:
>>>>>=20
>>>>> On Wed, 8 Apr 2020 at 23:29, Qian Cai <cai@lca.pw> wrote:
>>>>>>=20
>>>>>>=20
>>>>>>=20
>>>>>>> On Apr 8, 2020, at 5:25 PM, Paolo Bonzini <pbonzini@redhat.com> wro=
te:
>>>>>>>=20
>>>>>>> On 08/04/20 22:59, Qian Cai wrote:
>>>>>>>> Running a simple thing on this AMD host would trigger a reset righ=
t away.
>>>>>>>> Unselect KCSAN kconfig makes everything work fine (the host would =
also
>>>>>>>> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before =
running qemu-kvm).
>>>>>>>=20
>>>>>>> Is this a regression or something you've just started to play with?=
  (If
>>>>>>> anything, the assembly language conversion of the AMD world switch =
that
>>>>>>> is in linux-next could have reduced the likelihood of such a failur=
e,
>>>>>>> not increased it).
>>>>>>=20
>>>>>> I don=E2=80=99t remember I had tried this combination before, so don=
=E2=80=99t know if it is a
>>>>>> regression or not.
>>>>>=20
>>>>> What happens with KASAN? My guess is that, since it also happens with
>>>>> "off", something that should not be instrumented is being
>>>>> instrumented.
>>>>=20
>>>> No, KASAN + KVM works fine.
>>>>=20
>>>>>=20
>>>>> What happens if you put a 'KCSAN_SANITIZE :=3D n' into
>>>>> arch/x86/kvm/Makefile? Since it's hard for me to reproduce on this
>>>>=20
>>>> Yes, that works, but this below alone does not work,
>>>>=20
>>>> KCSAN_SANITIZE_kvm-amd.o :=3D n
>>>=20
>>> There are some other files as well, that you could try until you hit
>>> the right one.
>>>=20
>>> But since this is in arch, 'KCSAN_SANITIZE :=3D n' wouldn't be too bad
>>> for now. If you can't narrow it down further, do you want to send a
>>> patch?
>>=20
>> No, that would be pretty bad because it will disable KCSAN for Intel
>> KVM as well which is working perfectly fine right now. It is only AMD
>> is broken.
>=20
> Interesting. Unfortunately I don't have access to an AMD machine right no=
w.
>=20
> Actually I think it should be:
>=20
>  KCSAN_SANITIZE_svm.o :=3D n
>  KCSAN_SANITIZE_pmu_amd.o :=3D n
>=20
> If you want to disable KCSAN for kvm-amd.

KCSAN_SANITIZE_svm.o :=3D n

That alone works fine. I am wondering which functions there could trigger
perhaps some kind of recursing with KCSAN?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/B5F0F530-911E-4B75-886A-9D8C54FF49C8%40lca.pw.
