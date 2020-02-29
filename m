Return-Path: <kasan-dev+bncBDK3TPOVRULBBPHK43ZAKGQEYZLCC2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53f.google.com (mail-ed1-x53f.google.com [IPv6:2a00:1450:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id F2C2A1743EF
	for <lists+kasan-dev@lfdr.de>; Sat, 29 Feb 2020 01:50:04 +0100 (CET)
Received: by mail-ed1-x53f.google.com with SMTP id d12sf1600726edq.16
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 16:50:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582937404; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ye0A8ePtQwKmB0Adxbpwye7O3hfeHVKaCn27w317DPA4HH2Rn/BQvfAyL+U3CmD3Lx
         Y0ScHoXo/VHBPE4FlMVtGEEVzoGXjpFGvyVPtStRlU/p3N8xGlBYR9iuZlAdmmvGMKr4
         wtM2acilWLwIJdenOtoMnzNTzZt64/lcsymH6MvmKe4oSOnQRwiJC6cgQPSrYEcihjjb
         nxpd6n7TMPaD4J0CcK8JxNDboolgyB60C+d7vYWd12iT78cNbz7BdavVNhAq2hPMmNss
         AA8ksL3ElWKrnbU2P6L0JxmmrYcM1rcncGI/KG1My1dPqh6HHMnLoPH/RoZ7WRjAMdZl
         JbGA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3n+sXRFXzOXz24PnZvZ0ZmIP0yUtCyUWuJfkzCICJBM=;
        b=JhpO7Y27T+4HfY8TD93DopQTdC5nomZRclwLjnWkE0nu4ADLcpGdOtgPQXTzJRRR6L
         Jj6a1tRxHOmCZp1DaL1CmuSo6GhtqtKzqQr2+86rQbgJOXCfGcHW5OPEcyrP2UBb5Ar5
         0toj+IHKo5LQAaXCrpJEcNtPXg9E7b3Moav7SrDlQsYoBXBmAh52c6EqwWv6kJU/wtep
         v0fa7+etQ+sa6PgBsTVwCoGgReULIKGj5GBhAyyQBgKe3dFHXFUW9ada/6tGjEAcW9jE
         2jJ82i8yKZU0mkvc/bPg4c/55ta4Zi8MN5IXwpKEYqaRqUHT1B21OmtwRA9+R2744v07
         GutQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pim9Ezl7;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=3n+sXRFXzOXz24PnZvZ0ZmIP0yUtCyUWuJfkzCICJBM=;
        b=c/g03Co2iizqz7/mNcTTM+PucHHw10vwyb3YujVmInfVeg0v3Kw4Sz2hapA8WphhtZ
         Esxtav4O8mlS0AsTwIDYpeqY+Fl03n84+Qsun0rVPb2m9ZUBQ0ONbYGKGeI5CtqLtOpK
         PxFk75m4oURd3XfHXtc+uAyBJtiYIIbI9j7w/BNg6VqLvqNPaP9CzbbDKS14brq835T4
         +TryhdLkXjkTuIRmMX+DWwTXHgoY15CP5e+72rwWUhULfrb+xcXcea5X2LTyIlV7tYtu
         JUi3pVLyytpyQAUVHrsIAhw3s04SLbDn3p/50WvL8og2vyQjWPCJx3lbnogOFbSs20cH
         LwJA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=3n+sXRFXzOXz24PnZvZ0ZmIP0yUtCyUWuJfkzCICJBM=;
        b=lyYt/+UIyb+fIzcVfwPbKWHAZDhcW7DIBnvAJsl4V4eCRSasdR+kF3EVSxPUufGZ+/
         QeLYU4u+E38sJl5cd2FbdCrtiFxRSSgKlnoYRd4GIC5lZMPdRsnyLmQwvsBznBU0N01x
         kpatuE+96wCywqeBEfdflCvk+8dF+82CgUAIQ/RyFQQyjtZbTXrnSnsmHZ3ZF9DyE5b+
         EWnTP2IarQ+8SEn41fdV4A7dzLqe8kmHbH3p+jKbds5y1oVuBNBLz5uKzrrbsSUv5DHE
         lKAwYkVdqIIcfoa2qRk406Y7wkcbkE+iF3ldbS/HP/wE2EXszXM972ehDImzFDbObUCk
         frzA==
X-Gm-Message-State: APjAAAXYekNQL75h/S9JGqzUU/uPGkDmioD3rCeafKVsxKXmujhG346g
	AA6GDdDqWbw4oSj38I8VsIo=
X-Google-Smtp-Source: APXvYqxHmDMaPGaVTI9X5GejE/1SnHzjrtLzdzlE2CFVCw9AY6JTMcZ7vK+qC8Ooo6woJL+1s3ohkg==
X-Received: by 2002:a17:906:4a12:: with SMTP id w18mr6492297eju.321.1582937404688;
        Fri, 28 Feb 2020 16:50:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:bfe7:: with SMTP id vr7ls660630ejb.1.gmail; Fri, 28
 Feb 2020 16:50:04 -0800 (PST)
X-Received: by 2002:a17:906:4d43:: with SMTP id b3mr6438948ejv.109.1582937404167;
        Fri, 28 Feb 2020 16:50:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582937404; cv=none;
        d=google.com; s=arc-20160816;
        b=qGcd53wogM5LtemjopsZvudpoEP/HSdPXTJBp1eYk48UEZehBA3/jEKhzEeHeE4EKT
         sTqo9dcUp+C9I4h2S2fawxbu8Qsk9cyBlM0mRiGX2Evk0/h5VT/I3vGB7WLU9m7ceY5k
         0gNiw68wpwxPtiPnrnEYUSgQIBQTOgy+eeYHtfQMRwOooqXFN/gwVc/Dp+xUP37xSNgK
         Blwka6jB3scq65b54kjoZdL6wnnHYwb9782heqM/VSOGBXcCfBFyW6VKC3o78R2Iwd6t
         fYR93BTyDZZ1hstNNbQfO4VsaoCDr+u/rsq1J3D3wmkO6Oggf2UT5JhtdwF14TihBAYN
         110A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=0fc83ZqAA6+83fPnMS4lxXssttTpf+l85Fw1w82L0QU=;
        b=ppNFxCb42dTfJPc7n0iJV1VFLh8T76/JcGVFCq/WU2xpSjOR7CrIU+lHJhn1lXIvSi
         oHoyQlRrptfLF+Ny08m1rgG0hFpMEVdTxTxzHRbik0V+fmLlkHBrZV+d8CyObPqh901d
         WH748Ns9jBo2utV05O1yUD7OSHJxmVavrJ47xmxbx2vfkgIRwlsmhBDVcWgPSEP0SmEI
         bhtN/Ny2favTapq7yr9xVsz3MjhtNoN/wU9q7khxdXdUEt+85GUtqNrpTaJpxrobJGTq
         kyqdWBfSeMoY5yYcGVnTyA6gmFH4JAK4e1rPEcJazY4GFRrCiR+7DWILJlaDJRUFDPyx
         APQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Pim9Ezl7;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x443.google.com (mail-wr1-x443.google.com. [2a00:1450:4864:20::443])
        by gmr-mx.google.com with ESMTPS id s16si351559edy.3.2020.02.28.16.50.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 16:50:04 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443 as permitted sender) client-ip=2a00:1450:4864:20::443;
Received: by mail-wr1-x443.google.com with SMTP id e8so5260692wrm.5
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 16:50:04 -0800 (PST)
X-Received: by 2002:adf:e38d:: with SMTP id e13mr6955293wrm.133.1582937403580;
 Fri, 28 Feb 2020 16:50:03 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <CACT4Y+b0LHp15GNchK_TPxaqX8zscqgBw-Jm2Y3yq8Bn=dRbeQ@mail.gmail.com>
In-Reply-To: <CACT4Y+b0LHp15GNchK_TPxaqX8zscqgBw-Jm2Y3yq8Bn=dRbeQ@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Feb 2020 16:49:52 -0800
Message-ID: <CAKFsvUJhbk6cOXKgQ1+9=eDRDES1AB0rSTM+zid-yfk2U-qhYw@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, vincent.guittot@linaro.org, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Pim9Ezl7;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::443
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Thu, Feb 27, 2020 at 6:45 AM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > Integrate KASAN into KUnit testing framework.
> >  - Fail tests when KASAN reports an error that is not expected
> >  - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
> >  - KUnit struct added to current task to keep track of the current test
> > from KASAN code
> >  - Booleans representing if a KASAN report is expected and if a KASAN
> >  report is found added to kunit struct
> >  - This prints "line# has passed" or "line# has failed"
> >
> > Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
>
> This does not build for me:
>
> $ make
> scripts/kconfig/conf  --syncconfig Kconfig
>   CC      arch/x86/kernel/asm-offsets.s
>   UPD     include/generated/asm-offsets.h
>   CALL    scripts/checksyscalls.sh
>   CALL    scripts/atomic/check-atomics.sh
>   DESCEND  objtool
>   CC      init/main.o
> In file included from ./include/linux/uaccess.h:11,
>                  from ./arch/x86/include/asm/fpu/xstate.h:5,
>                  from ./arch/x86/include/asm/pgtable.h:26,
>                  from ./include/linux/kasan.h:15,
>                  from ./include/linux/slab.h:136,
>                  from ./include/kunit/test.h:16,
>                  from ./include/linux/sched.h:35,
>                  from ./include/linux/ioprio.h:5,
>                  from ./include/linux/fs.h:39,
>                  from ./include/linux/proc_fs.h:9,
>                  from init/main.c:18:
> ./arch/x86/include/asm/uaccess.h: In function =E2=80=98set_fs=E2=80=99:
> ./arch/x86/include/asm/uaccess.h:31:9: error: dereferencing pointer to
> incomplete type =E2=80=98struct task_struct=E2=80=99
>    31 |  current->thread.addr_limit =3D fs;
>       |         ^~
> make[1]: *** [scripts/Makefile.build:268: init/main.o] Error 1
> make: *** [Makefile:1681: init] Error 2
>
>
> On bfdc6d91a25f4545bcd1b12e3219af4838142ef1 config:
> https://pastebin.com/raw/nwnL2N9w

I'm sorry. It seems I only ever tested locally on UML. As Alan
suggested, removing "#include <kunit/test.h>" from
include/linux/sched.h seems to fix this problem.

--=20
Best,
Patricia Alfonso

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAKFsvUJhbk6cOXKgQ1%2B9%3DeDRDES1AB0rSTM%2Bzid-yfk2U-qhYw%40mail.=
gmail.com.
