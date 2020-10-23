Return-Path: <kasan-dev+bncBCT6537ZTEKRBJ4YZT6AKGQENNLDGUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3b.google.com (mail-vs1-xe3b.google.com [IPv6:2607:f8b0:4864:20::e3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2840129756E
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 19:00:25 +0200 (CEST)
Received: by mail-vs1-xe3b.google.com with SMTP id s7sf397749vso.19
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 10:00:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603472424; cv=pass;
        d=google.com; s=arc-20160816;
        b=exEQDR1Lf8k/oOXJxFFg6xWPptHIw592D34DEMKP/TNEnGZm4mFJd7hDP3jzApZzEd
         MZ9hk+4odjaIq3TqucwL4IgrWOIgxGXvgvzOXjyuVYu5WW7LUkmDesQyvEZnOnGusY89
         ie/S8BmebRDpw/Q5YcRmOLNFxmCxKSGcZzueRP7PLlfBt7XxRFH3o0qLtZwrv/ob/SdN
         7FrxRtiF8ruLECUiYpKIbf8rlAHDbIRIp2vsx6Db+UTlpT+DosIRbiYUykmqWHd8lWTS
         yOktvttGSp2WS4jpFaZ9xuxZRIuIbY4zsLWyCQykgkEvMGOO0gYy/Cuii8VvtXzlgYm5
         jStw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=+CEMBvXyJJd4hZ6TBbx4pjmHEGMY2nZW+uVUT6KguGg=;
        b=Ra/wUIQufMBGKEx5XB5y5vIhwjuK7cNoSaprULr7c5S2Z1CmtkuunCn4NoULdWHNQI
         K7KUELl6OhMNkF26mbWO/u0V++5i6yn6zmTyuFiSDaS0qqmC598p0HroGTzNf9fFULne
         YZaClT7Ji4/y9vNgbmk411KNAd0KctdjZ1CmBWnQ5i/RFcr8305W3I0EtUeF/AJn31y3
         7JbWE7sxwYBn+a25vi+4JH1LNaRxh2nuw1GghqdvMeH7O12L3w2G9a97Rr+zhfnTHNBL
         g6tzSPQcME8Lg0LCnRybFqsaSm77F2W3tEgxhayhYs6b2i3BvSiJEn1+XoU0fQnyBoAt
         KePQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=V+Gg9uIC;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::141 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=+CEMBvXyJJd4hZ6TBbx4pjmHEGMY2nZW+uVUT6KguGg=;
        b=spk1hOWyFi9TVmDSFW69xWlmdAPsctNF3yS2a+F3yZq9MdrJIIvCTqnzF5i0o6aZnO
         +jETGJtWIh1ZwqH3lX9oiYLcqAzDCxGUbCe/XD4YGvqIu6efBQF30vTq+JhSEZ4vdzAm
         Xn7k4qV3Iyn5tQkoaPwgt7qk8Bv0bF7WPWJ6qK0ovV9wzYAVhH2rQJ2k8eTk+I3r5L3Z
         vMt7/d6KXZyxFVCnUeDAsKyLi9YIDWe09jLeJQRuQgarBOyeBxbRHy8PEVQLNDEy12E+
         pkoxW+ecpiRE6GXRMbb/FPsPfE28r61F7IUrZbPJhvXQO8nBLEO/+usXymiGPpWP3edn
         TOwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=+CEMBvXyJJd4hZ6TBbx4pjmHEGMY2nZW+uVUT6KguGg=;
        b=qbSfiiuF4ex1xVQaObiCNLmlcHNW4rq6fMV9JrZB8EpwkyZMK48cfajvM5NCLp/ErQ
         DB4W+IHj2iISgSsE+CcHvqJem3XqEmQJ0OqRjYCRHCA1pubWo5BIAn+sGPNpmQfuGF3t
         5vCxqUZG9DtG/xR7PvZRwra7cjloI0C+jx5UKR8Urlmz2wyIyyRKyfreoZuoRvAQwj+e
         fyjp+yY9ZRC2XsGFFTVJnc7QDmt+/WVMZ06KMu27oKaZiLDLxHR+GZtgrJaE9aoU61MK
         t5k4wqMV2Phwx0puxftN8llzzSk2kd06ucJMZuE7Ge5mGIIt1wGk7bx/OPj1om/EExuX
         VekQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ybfUUI5Wz8Tzqm8QNraM0k5RLtsdYhjMOUn75vooT1MICzUNp
	NYgJsvd5vQgZ+sJd9HTdIi8=
X-Google-Smtp-Source: ABdhPJxvffeEYbEtqYj5dXkCU7wWOO59q/hWVr1UkrOyNU521Hx7HB9ypSPA/FcQRPKsPqq3DsGp4g==
X-Received: by 2002:ab0:2a8c:: with SMTP id h12mr2108131uar.26.1603472423999;
        Fri, 23 Oct 2020 10:00:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:30c5:: with SMTP id k5ls88026uab.3.gmail; Fri, 23 Oct
 2020 10:00:23 -0700 (PDT)
X-Received: by 2002:ab0:314b:: with SMTP id e11mr2082378uam.117.1603472423475;
        Fri, 23 Oct 2020 10:00:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603472423; cv=none;
        d=google.com; s=arc-20160816;
        b=isLVkqvmqL+tVHgRUWIV8aZsVzyqSB2ENlW2CJOmzE9eL4M5IwQJjRw8WSfm7iYZV6
         0Uo9y7uTjrcNOlPuzbPukTNq1Iy1JlMC3bKCU3ik9YurA0nAPFsX/16ZAM6Yyh7iUFQn
         BgHmAnKqNJwCloUG9A5LB2qF1w7VTB6lRCa+D95DhBVHUVYkv1M1klzwSTFEJRf3Z6Va
         VNCqI3CqQXJKI7OnS3j7iopY+f4HogVgw2L+v7ygfDeAj8JfnUKDNWFVPzDgmixe0Hx0
         L3RCFgM4pHLYGpa5dHHy8ZmO3bLheItHFEDrobfK9JBj0YrwGrUOi5j56d1ep8l/+fpJ
         5Cwg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=o1VEizSN6TM+raklNtIXpsapMZWxETouBV0mamAPQo0=;
        b=Vqi0kijM0yXONk1ahW6js2vYm0SXIfVq3m2J5TYuOvl12mih1L3266nimsBqIuctZF
         eR172bO09THuKtF2Q9suVc0eyVKA+KLgH3XyMQfA5Xt6qZ05/5KRzPOzAuAac4z8wlE4
         u9UoildBpvYI4h9yEbeBU1l1nWLwyyoT/E774InRBUFJLp5KTJuR4bGjXxclqgxvUtde
         fEjbo+b8ypkJE8hNWxs4sR+J3J3wRFFboVY+L7QkXxRGpQMQS+aJPpgKF4Klupn6ia4+
         W5cKK8om+B4Qwd88it8CbOEGA+6YYJPBdG7NbJDcfYDE/cdLDo+JeBzuDscS356Eli67
         PWmg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linaro.org header.s=google header.b=V+Gg9uIC;
       spf=pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::141 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
Received: from mail-il1-x141.google.com (mail-il1-x141.google.com. [2607:f8b0:4864:20::141])
        by gmr-mx.google.com with ESMTPS id j77si116671vkj.1.2020.10.23.10.00.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 10:00:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of naresh.kamboju@linaro.org designates 2607:f8b0:4864:20::141 as permitted sender) client-ip=2607:f8b0:4864:20::141;
Received: by mail-il1-x141.google.com with SMTP id y17so2036950ilg.4
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 10:00:23 -0700 (PDT)
X-Received: by 2002:a92:b6d2:: with SMTP id m79mr1190406ill.216.1603472422474;
 Fri, 23 Oct 2020 10:00:22 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
 <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com> <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
In-Reply-To: <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
From: Naresh Kamboju <naresh.kamboju@linaro.org>
Date: Fri, 23 Oct 2020 22:30:11 +0530
Message-ID: <CA+G9fYu5aGbMHaR1tewV9dPwXrUR5cbGHJC1BT=GSLsYYwN6Nw@mail.gmail.com>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: =?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>, 
	Stephen Rothwell <sfr@canb.auug.org.au>, "Matthew Wilcox (Oracle)" <willy@infradead.org>, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Christian Brauner <christian.brauner@ubuntu.com>, 
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: naresh.kamboju@linaro.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linaro.org header.s=google header.b=V+Gg9uIC;       spf=pass
 (google.com: domain of naresh.kamboju@linaro.org designates
 2607:f8b0:4864:20::141 as permitted sender) smtp.mailfrom=naresh.kamboju@linaro.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linaro.org
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

On Fri, 23 Oct 2020 at 08:35, Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Thu, Oct 22, 2020 at 6:36 PM Daniel D=C3=ADaz <daniel.diaz@linaro.org>=
 wrote:
> >
> > The kernel Naresh originally referred to is here:
> >   https://builds.tuxbuild.com/SCI7Xyjb7V2NbfQ2lbKBZw/
>
> is unnecessary (because the 8-byte case is still just a single
> register, no %eax:%edx games needed), it would be interesting to hear
> if the attached patch fixes it. That would confirm that the problem
> really is due to some register allocation issue interaction (or,
> alternatively, it would tell me that there's something else going on).

[Old patch from yesterday]

After applying your patch on top on linux next tag 20201015
there are two observations,
  1) i386 build failed. please find build error build
  2) x86_64 kasan test PASS and the reported error not found.


i386 build failure,
----------------------
make -sk KBUILD_BUILD_USER=3DTuxBuild -C/linux -j16 ARCH=3Di386 HOSTCC=3Dgc=
c
CC=3D"sccache gcc" O=3Dbuild
#
In file included from ../include/linux/uaccess.h:11,
                 from ../arch/x86/include/asm/fpu/xstate.h:5,
                 from ../arch/x86/include/asm/pgtable.h:26,
                 from ../include/linux/pgtable.h:6,
                 from ../include/linux/mm.h:33,
                 from ../include/linux/memblock.h:13,
                 from ../fs/proc/page.c:2:
../fs/proc/page.c: In function =E2=80=98kpagecgroup_read=E2=80=99:
../arch/x86/include/asm/uaccess.h:217:2: error: inconsistent operand
constraints in an =E2=80=98asm=E2=80=99
  217 |  asm volatile("call __" #fn "_%P[size]"    \
      |  ^~~
../arch/x86/include/asm/uaccess.h:244:44: note: in expansion of macro
=E2=80=98do_put_user_call=E2=80=99
  244 | #define put_user(x, ptr) ({ might_fault();
do_put_user_call(put_user,x,ptr); })
      |                                            ^~~~~~~~~~~~~~~~
../fs/proc/page.c:307:7: note: in expansion of macro =E2=80=98put_user=E2=
=80=99
  307 |   if (put_user(ino, out)) {
      |       ^~~~~~~~
make[3]: *** [../scripts/Makefile.build:283: fs/proc/page.o] Error 1
make[3]: Target '__build' not remade because of errors.
make[2]: *** [../scripts/Makefile.build:500: fs/proc] Error 2
In file included from ../include/linux/uaccess.h:11,
                 from ../include/linux/sched/task.h:11,
                 from ../include/linux/sched/signal.h:9,
                 from ../include/linux/rcuwait.h:6,
                 from ../include/linux/percpu-rwsem.h:7,
                 from ../include/linux/fs.h:33,
                 from ../include/linux/cgroup.h:17,
                 from ../include/linux/memcontrol.h:13,
                 from ../include/linux/swap.h:9,
                 from ../include/linux/suspend.h:5,
                 from ../kernel/power/user.c:10:
../kernel/power/user.c: In function =E2=80=98snapshot_ioctl=E2=80=99:
../arch/x86/include/asm/uaccess.h:217:2: error: inconsistent operand
constraints in an =E2=80=98asm=E2=80=99
  217 |  asm volatile("call __" #fn "_%P[size]"    \
      |  ^~~
../arch/x86/include/asm/uaccess.h:244:44: note: in expansion of macro
=E2=80=98do_put_user_call=E2=80=99
  244 | #define put_user(x, ptr) ({ might_fault();
do_put_user_call(put_user,x,ptr); })
      |                                            ^~~~~~~~~~~~~~~~
../kernel/power/user.c:340:11: note: in expansion of macro =E2=80=98put_use=
r=E2=80=99
  340 |   error =3D put_user(size, (loff_t __user *)arg);
      |           ^~~~~~~~
../arch/x86/include/asm/uaccess.h:217:2: error: inconsistent operand
constraints in an =E2=80=98asm=E2=80=99
  217 |  asm volatile("call __" #fn "_%P[size]"    \
      |  ^~~
../arch/x86/include/asm/uaccess.h:244:44: note: in expansion of macro
=E2=80=98do_put_user_call=E2=80=99
  244 | #define put_user(x, ptr) ({ might_fault();
do_put_user_call(put_user,x,ptr); })
      |                                            ^~~~~~~~~~~~~~~~
../kernel/power/user.c:346:11: note: in expansion of macro =E2=80=98put_use=
r=E2=80=99
  346 |   error =3D put_user(size, (loff_t __user *)arg);
      |           ^~~~~~~~
../arch/x86/include/asm/uaccess.h:217:2: error: inconsistent operand
constraints in an =E2=80=98asm=E2=80=99
  217 |  asm volatile("call __" #fn "_%P[size]"    \
      |  ^~~
../arch/x86/include/asm/uaccess.h:244:44: note: in expansion of macro
=E2=80=98do_put_user_call=E2=80=99
  244 | #define put_user(x, ptr) ({ might_fault();
do_put_user_call(put_user,x,ptr); })
      |                                            ^~~~~~~~~~~~~~~~
../kernel/power/user.c:357:12: note: in expansion of macro =E2=80=98put_use=
r=E2=80=99
  357 |    error =3D put_user(offset, (loff_t __user *)arg);
      |            ^~~~~~~~


x86_64 Kasan tested and the reported issue not found.
https://lkft.validation.linaro.org/scheduler/job/1868029#L2374

- Naresh

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BG9fYu5aGbMHaR1tewV9dPwXrUR5cbGHJC1BT%3DGSLsYYwN6Nw%40mail.gm=
ail.com.
