Return-Path: <kasan-dev+bncBCG6FGHT7ALRB6XYST3AKGQE4JYHKQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 35E811DB61A
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 16:19:39 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id q6sf951059wme.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 07:19:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589984379; cv=pass;
        d=google.com; s=arc-20160816;
        b=cJaACd+Qa66El9WrN3DvC7jNXvnEZzVqyF95tcQAoBIZQBx2P2RwTMCGQgJemT6os2
         9z4XNrpYqmtzXo+Ju0fCtqTmAHyiDP//ApCme/jXax2GoF/uBLv7nI5d8ja4CglRQR8g
         CIbq5wU3uCvf46FcGtVGAJDr/Or4VfxxQlYJaXx7cqIlAt3taQoWfxes6KIGVtoJgoLE
         BBHZL+yLS+DrSitztS8y/cebFn86/qP9Rp3dE2E3BijBJnVF9Ru0tHUD8Msa3cyBvOTZ
         LWqqUcH3z+jucpt/Vl4FivuWcvKc+fovl+zlmzqSKM71v1RA/biYmzroNTMbLFDb2zt1
         rNSA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:sender:dkim-signature;
        bh=SSQLfohwJAvX7neO15aH5eCHQHcGx9h9aQg0iw4fJZ0=;
        b=ccLywltFAuaWBmcqUf1QTcTuP9HSpjx2YACRmSDZmpzsMFioLohfs2C7Rf7Hp/u4Eo
         rrqrOFrEGdi4G5E83veq8sPPQ5qVv77wWm3iQg4Y5nr9hCVdkw14Ixhe3uEtzRagMmx1
         M2b+4f4dJX4moOf5sCkq+jVPbM2XX81P1M+5aou5uGrfb+X0kP2ZaFL9gs67ZM+wt0nK
         tGESnxA6JpELkgwdAt7fguTwX0rAJ2RJRLiQf0F98loQ3SH5Vvf7tJozx1wC/7Qd4Yy6
         rYLgPvqrfO8oZfGv5HKU1LnqaCVOercKHrk4BpGtpVtbsgbcsRPvdjFxu2yhT53ARgGk
         Fkpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SSQLfohwJAvX7neO15aH5eCHQHcGx9h9aQg0iw4fJZ0=;
        b=TrOUbtOeqWXHSDF8rkEjiszye+U5Zr4gkT0nHAQZaV5GpHpvjRN9GShbLGXoPS85II
         oERrS5OsTpQtNC/75NKaKDRLGZQ2j0yEInHOXqqvd9/S0C7u8GiX/78Ds0wE1xPwHqAq
         4+0QS9t3H1nUDFOIte64cpobmfoScdPij+hKo9hIQRTUAS5O1kS+6XI8YdhDAYG/Gvtr
         N644+voFutNfI8LWWm3aRO2xUgqAlZHFKC+Fw0waAvQ9TEq6pLPjPutgx7ZHbC+yY6YU
         EcWPJaTxjjZM/ngz+Fh0Lool2H5SZYm3uxdAGoJDLOjavtYvQdQqnz3l8fK99LbA03Sf
         cbFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=SSQLfohwJAvX7neO15aH5eCHQHcGx9h9aQg0iw4fJZ0=;
        b=Wz8jwY/220owObQT0zpzJoq4RlaiwpExrCCSJfPJs3LZvl5kzB53cEqUrEKDrWLrVh
         /hz+4BKBHgFUDkQNO5/uNRstg+QVIUejfR5b4KuLrAwVIa/j7OTQyEhUSXT++PgQXblI
         sf6Y+MSXb0PtVtAzUb3p1VsDq8dCQtsTrNY0mEm1Hbe+Plb9e46tdFL8rpZqiBI+kZ0M
         G2sOoHhL/wOFLfk9RiPFrFuWhdyoStZ7tDRoFvV2QRkXqu6Q8oa1f2jATl9q5N0Vy4VZ
         ItE7WGYudmS/r6ZRbp9ikfbLzHNoNrHBRBZBQecHqscsDGA5On3XdCpoCQy9IUg1KqsB
         XsVQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531V9EkpejogujKflD6dRXNS1pXbidsQNDtrmO+g3THlfoMW7zeI
	8e4XitqR0sUIln+BpU0KBuU=
X-Google-Smtp-Source: ABdhPJyjIRTgYmaBXCb4Hqio2td3Ja3Lbmf+4zV1ii+V4nMsS6qzejUe49iYWkN6R0s/Q10bWwyeaQ==
X-Received: by 2002:a5d:530c:: with SMTP id e12mr4715630wrv.271.1589984378912;
        Wed, 20 May 2020 07:19:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:5224:: with SMTP id i4ls4492235wra.0.gmail; Wed, 20 May
 2020 07:19:38 -0700 (PDT)
X-Received: by 2002:a5d:6846:: with SMTP id o6mr4314996wrw.384.1589984378432;
        Wed, 20 May 2020 07:19:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589984378; cv=none;
        d=google.com; s=arc-20160816;
        b=krpujoFLa9K20YEq1b1O9yIQ9XCdiWfATMmjFDAdXxyks+pQsVbGvkhYYj5e3mp6rt
         9kVA0VZaaAMTYjyod30hcAk2khYaUl0fBV4IVQ9S/NSJiJ1tqsoblpJWTVnnGs6/OXQm
         yIRDx4RH1VPLdfjKT1F5w4Egqfbt4rIe0WbeAa+I9RPpdTUCg+BpWL2UH3Di6hY2tcZ+
         vlkOWAzJ9Gcm+/2ukCu3PjdUp+bvWRZ6oIrKZmv9151sgsMqaHbc5U8OL9B/LuoWkkKr
         xpTIWal/vwJl8vhQ36l9ZbBgyBjXa5Fgc/V31Jakhc1qeCtyt7YKM34fveB6mqP1tkHA
         xx/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:from:references:cc:to:subject;
        bh=6/Pa+YbngPGreJ1GwBtfUJ/OxfcF/5q81yDRwBIsfEs=;
        b=MLJUaxNLm2vC4iaIqHJpM5anQSSBzAzCURKnJHqqE7hRjPUTexHdAaNSWa+hIFxDSt
         Zw5zILubGOgyaytpxQVwYwn5SkCrRu648lUxDEYhJz4ad5OTc3r8akhzdLOrZJlq4uI3
         G2/cmHo44Bjwvhhf6aqPH7I5B900kh7WAOdszF4EeNnXkkGuBjw2mOdy57pqtjyMs5QU
         /I3TI6xMFCLCEgD1DkkrwXfuQvX2cgNhNuMw189JNSMtvFRpbRMBY3Yj3R6JbUou5CEm
         6VXl5QVVzcybMDFgnf5xDaI5jgr34ETaSzpbEMEd8+YkU2MqgZUrPyxaClmbebpLRZPk
         4Mlw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) smtp.mailfrom=mliska@suse.cz
Received: from mx2.suse.de (mx2.suse.de. [195.135.220.15])
        by gmr-mx.google.com with ESMTPS id a22si395800wmd.4.2020.05.20.07.19.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 20 May 2020 07:19:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted sender) client-ip=195.135.220.15;
X-Virus-Scanned: by amavisd-new at test-mx.suse.de
Received: from relay2.suse.de (unknown [195.135.220.254])
	by mx2.suse.de (Postfix) with ESMTP id 9FA42AF19;
	Wed, 20 May 2020 14:19:40 +0000 (UTC)
Subject: Re: [PATCH] tsan: Add optional support for distinguishing volatiles
To: Marco Elver <elver@google.com>
Cc: GCC Patches <gcc-patches@gcc.gnu.org>, Jakub Jelinek <jakub@redhat.com>,
 kasan-dev <kasan-dev@googlegroups.com>
References: <20200423154250.10973-1-elver@google.com>
 <0e79d50f-163d-0878-709b-4d5ab06ff8eb@suse.cz>
 <CANpmjNNH6Sfo7t8Vp13fXfqg0AWYS3v07xveihgZgtPfR9b9wQ@mail.gmail.com>
From: =?UTF-8?Q?Martin_Li=c5=a1ka?= <mliska@suse.cz>
Message-ID: <bb41da10-1ed9-5467-d1be-a7dfda2d10ab@suse.cz>
Date: Wed, 20 May 2020 16:19:36 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.8.0
MIME-Version: 1.0
In-Reply-To: <CANpmjNNH6Sfo7t8Vp13fXfqg0AWYS3v07xveihgZgtPfR9b9wQ@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Language: en-US
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mliska@suse.cz
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of mliska@suse.cz designates 195.135.220.15 as permitted
 sender) smtp.mailfrom=mliska@suse.cz
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

On 5/20/20 4:04 PM, Marco Elver wrote:
> On Wed, 20 May 2020 at 15:30, Martin Li=C5=A1ka <mliska@suse.cz> wrote:
>>
>> On 4/23/20 5:42 PM, Marco Elver via Gcc-patches wrote:
>>
>> Hello.
>>
>> Not being a maintainer of libsanitizer but I can provide a feedback:
>=20
> Thank you for the review!
>=20
> Note, this is not touching libsanitizer or user-space TSAN runtime,
> only the compiler. Alternative runtimes may enable the option where
> required (particularly, kernel space runtimes).

You are right ;) Anyway, a maintainer will be needed, but Jakub promised
to make a review once I'm done.

>=20
>>> Add support to optionally emit different instrumentation for accesses t=
o
>>> volatile variables. While the default TSAN runtime likely will never
>>> require this feature, other runtimes for different environments that
>>> have subtly different memory models or assumptions may require
>>> distinguishing volatiles.
>>>
>>> One such environment are OS kernels, where volatile is still used in
>>> various places for various reasons, and often declare volatile to be
>>> "safe enough" even in multi-threaded contexts. One such example is the
>>> Linux kernel, which implements various synchronization primitives using
>>> volatile (READ_ONCE(), WRITE_ONCE()). Here the Kernel Concurrency
>>> Sanitizer (KCSAN) [1], is a runtime that uses TSAN instrumentation but
>>> otherwise implements a very different approach to race detection from
>>> TSAN.
>>>
>>> While in the Linux kernel it is generally discouraged to use volatiles
>>> explicitly, the topic will likely come up again, and we will eventually
>>> need to distinguish volatile accesses [2]. The other use-case is
>>> ignoring data races on specially marked variables in the kernel, for
>>> example bit-flags (here we may hide 'volatile' behind a different name
>>> such as 'no_data_race').
>>
>> Do you have a follow up patch that will introduce such an attribute? Doe=
s clang
>> already have the attribute?
>=20
> Ah, sorry I wasn't clear enough here. As far as the compiler is aware,
> no extra attribute, so no patch for the compilers for that. It's an
> extra use-case, but not the main reason we need this. Re attribute, we
> may do:
>=20
> #ifdef __SANITIZE_THREAD__
> #define no_data_race volatile
> #else
> #define no_data_race
> #endif
>=20
> in the kernel. It's something that was expressed by kernel
> maintainers, as some people want to just have a blanket annotation to
> make the data race detector ignore or treat certain variables as if
> they were atomic, even though they're not. But for all intents and
> purposes, please ignore the 'no_data_race' comment.

That's a reasonable approach for now!

>=20
> The main use-case, of actually distinguishing volatile accesses is now
> required for KCSAN in the kernel, as without it the race detector
> won't work anymore after some {READ,WRITE}_ONCE() rework. Right now,
> KCSAN in the kernel is therefore Clang only:
> https://lore.kernel.org/lkml/20200515150338.190344-1-elver@google.com/
>=20
> Getting this patch into GCC gets us one step closer to being able to
> re-enable KCSAN for GCC in the kernel, but there are some other loose
> ends that I don't know how to resolve (independent of this patch).

Ok.

>=20
> [...]
>>> +-param=3Dtsan-distinguish-volatile=3D
>>> +Common Joined UInteger Var(param_tsan_distinguish_volatile) IntegerRan=
ge(0, 1) Param
>>> +Emit special instrumentation for accesses to volatiles.
>>
>> You want to add 'Optimization' keyword as the parameter can be different
>> per-TU (in LTO mode).
>=20
> Will add in v2.
>=20
>>> +
>>>    -param=3Duninit-control-dep-attempts=3D
>>>    Common Joined UInteger Var(param_uninit_control_dep_attempts) Init(1=
000) IntegerRange(1, 65536) Param Optimization
>>>    Maximum number of nested calls to search for control dependencies du=
ring uninitialized variable analysis.
>>> diff --git a/gcc/sanitizer.def b/gcc/sanitizer.def
>>> index 11eb6467eba..a32715ddb92 100644
>>> --- a/gcc/sanitizer.def
>>> +++ b/gcc/sanitizer.def
>>> @@ -214,6 +214,27 @@ DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_READ_RANGE, "_=
_tsan_read_range",
>>>    DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_WRITE_RANGE, "__tsan_write_range=
",
>>>                      BT_FN_VOID_PTR_PTRMODE, ATTR_NOTHROW_LEAF_LIST)
>>>
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ1, "__tsan_volatile_r=
ead1",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ2, "__tsan_volatile_r=
ead2",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ4, "__tsan_volatile_r=
ead4",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ8, "__tsan_volatile_r=
ead8",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_READ16, "__tsan_volatile_=
read16",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE1, "__tsan_volatile_=
write1",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE2, "__tsan_volatile_=
write2",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE4, "__tsan_volatile_=
write4",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE8, "__tsan_volatile_=
write8",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_VOLATILE_WRITE16, "__tsan_volatile=
_write16",
>>> +                   BT_FN_VOID_PTR, ATTR_NOTHROW_LEAF_LIST)
>>> +
>>>    DEF_SANITIZER_BUILTIN(BUILT_IN_TSAN_ATOMIC8_LOAD,
>>>                      "__tsan_atomic8_load",
>>>                      BT_FN_I1_CONST_VPTR_INT, ATTR_NOTHROW_LEAF_LIST)
>>> diff --git a/gcc/testsuite/ChangeLog b/gcc/testsuite/ChangeLog
>>> index 245c1512c76..f1d3e236b86 100644
>>> --- a/gcc/testsuite/ChangeLog
>>> +++ b/gcc/testsuite/ChangeLog
>>> @@ -1,3 +1,7 @@
>>> +2020-04-23  Marco Elver  <elver@google.com>
>>> +
>>> +     * c-c++-common/tsan/volatile.c: New test.
>>> +
>>>    2020-04-23  Jakub Jelinek  <jakub@redhat.com>
>>>
>>>        PR target/94707
>>> diff --git a/gcc/testsuite/c-c++-common/tsan/volatile.c b/gcc/testsuite=
/c-c++-common/tsan/volatile.c
>>> new file mode 100644
>>> index 00000000000..d51d1e3ce8d
>>> --- /dev/null
>>> +++ b/gcc/testsuite/c-c++-common/tsan/volatile.c
>>
>> Can you please add a run-time test-case that will check gd-output for TS=
AN
>> error messages?
>=20
> What do you mean? The user-space TSAN runtime itself does not make use
> of the option, and therefore will and should never implement
> __tsan_volatile*.

I've got it. So at least please add scanning of assembly or a tree dump
for the expected __tsan_* calls.

Martin

>=20
> As stated in the commit message, it's an option for alternative
> runtimes. Recently, the KCSAN runtime in the Linux kernel (there are
> also "CSAN" ports to NetBSD and FreeBSD kernels, which also had the
> same problem that default TSAN instrumentation doesn't distinguish
> volatiles). Note, we chose "CSAN" instead of "TSAN" for naming the
> different runtime, to avoid confusion since the runtimes function very
> very differently, just use the same instrumentation. (There was also a
> KTSAN for the kernel, but it turned out to be too complex in kernel
> space -- still, very little in common with the user-space runtime,
> just similar algorithm.)
>=20
> FWIW we have a test in the Linux kernel that checks the runtime, since
> that's where the runtime is implemented.
>=20
>>> @@ -0,0 +1,62 @@
>>> +/* { dg-additional-options "--param=3Dtsan-distinguish-volatile=3D1" }=
 */
>>> +
>>> +#include <assert.h>
>>> +#include <stdint.h>
>>> +#include <stdio.h>
>>> +
>>> +int32_t Global4;
>>> +volatile int32_t VolatileGlobal4;
>>> +volatile int64_t VolatileGlobal8;
> [...]
>>>      else if (rhs =3D=3D NULL)
>>> -    g =3D gimple_build_call (get_memory_access_decl (is_write, size),
>>> -                        1, expr_ptr);
>>> +    {
>>> +      builtin_decl =3D get_memory_access_decl (is_write, size,
>>> +                                             TREE_THIS_VOLATILE(expr))=
;
>>> +      g =3D gimple_build_call (builtin_decl, 1, expr_ptr);
>>> +    }
>>>      else
>>>        {
>>>          builtin_decl =3D builtin_decl_implicit (BUILT_IN_TSAN_VPTR_UPD=
ATE);
>>>
>>
>> And please check coding style, 8 spares are not expanded with a tab.
>=20
> Will fix for v2.
>=20
> Thanks,
> -- Marco
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bb41da10-1ed9-5467-d1be-a7dfda2d10ab%40suse.cz.
