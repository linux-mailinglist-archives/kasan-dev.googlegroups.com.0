Return-Path: <kasan-dev+bncBCRY3K6ZWAFRBYELZDXQKGQEIRRLJFI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 78BEC11C8FB
	for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 10:18:26 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id z7sf345590otm.10
        for <lists+kasan-dev@lfdr.de>; Thu, 12 Dec 2019 01:18:26 -0800 (PST)
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:message-id:in-reply-to:references:subject
         :mime-version:x-original-sender:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1mRE8eMVaUHkxocYULGXsVg1m+Om0FheX/Nqje1w5TE=;
        b=JwRioyUf0Vwa5y4JPuU6KTmTafvXhGeZYG8Ggd3BgdHPEAxVutUJ5C0kJuBfm6OP1k
         l0zjfXdfuoR0zNCi8unil18nAhE/GHcBnaEm6sQqfTotwlZkSl0oO0jwFa+/V07VmGgw
         njoRQmLJxpmPTlJ2qyJIP+rw45DAKb5CwTbX2aJG/PPrCCdEfXB+qnEpzr4yZx3l+LZ0
         HESAj2VFLGTCX9CmJRq4UfWaG0DhQG7kgIrQIuvkiaL+330y68HEvQrb6QH1AJ4ukoY+
         MJwwbe9C+GXthW6sib43LK6j8L4lnD7gZ+mAuHc2cFWyj3HXzVDPKpqOEyqeRBFAoYnq
         8eIw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=date:from:to:message-id:in-reply-to:references:subject:mime-version
         :x-original-sender:precedence:mailing-list:list-id:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=1mRE8eMVaUHkxocYULGXsVg1m+Om0FheX/Nqje1w5TE=;
        b=WBwAQNgqi0XGrUnFLcjwd+BYbz649uvnT1ceYytQ0BBiOCNN/iKBnM0OBhq4fPqXG3
         H0p6f4KKhVi14gCKAuWvTUKlJCf3F52JLS6X+Jd9bwclhhg6w5CrWROAW5JSgOGqOEPp
         qbT71OCEH6OdYttcXAa1phDU1iJmC+dgP+scQ+4JRMZKU2ixwRfdBcV7jZUe5KWle6UQ
         guZO/5lcrex0Sw6aR8lR48oauOIWTh2ANox3VDQeLHmgXfe5+iGEJboOlMYqx9Pa3CDz
         y2ct4xVRbK909nU3zYGTLtKxs6upWfgeGGPujRg4EiUoIR5ncw6s3XugJHbYuivvlz7h
         o7tw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:message-id:in-reply-to
         :references:subject:mime-version:x-original-sender:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=1mRE8eMVaUHkxocYULGXsVg1m+Om0FheX/Nqje1w5TE=;
        b=Tzla1uSXQxQocQh6U7vTF63Ri1Asi4Ovxmnw/SYXXcVeCSvLHjkImtAvAwc5A+98Ph
         SrpSmJaza01vECuoMGckmi6lvNnKAgpCIn1G8VRH2FLKsJ2NTKuU2KeQfzl/Xnb6gXuf
         QF/AMoBmaIOngtSlHEZI8zPC87H9wHVz1ybuJX0Xwv7UuVwf3DaFAyNz1d6kyinKWTwn
         jv41dZ1D1qd4DPaa5gc5u9WoWbv4x61UXbbiqOBq+SZDUOkGf4hOOoDIWgrNO5UVce2A
         ikEI88f64NZJ2CG/CVlN7eQ2advtflDOLfye0weHpGOrRNWgjZljIdB03Vz7faeyIYru
         tSYQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXfz6ZJYtMb4v6Ubfsu9aTfzZgtqaTk9xxFlTPCvP19YoNx75c5
	XZIn89EIWdpDszM9/tKa8Lc=
X-Google-Smtp-Source: APXvYqzFnkYFwL2SkLrF4Is3cDW8YVP7U4aWJx+6IIJ55k1aDpTiXVZNc0cF1hqc1/MJOOk1GqYkiA==
X-Received: by 2002:aca:3012:: with SMTP id w18mr4915225oiw.33.1576142304690;
        Thu, 12 Dec 2019 01:18:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:460d:: with SMTP id y13ls1147026ote.15.gmail; Thu, 12
 Dec 2019 01:18:24 -0800 (PST)
X-Received: by 2002:a05:6830:1e2d:: with SMTP id t13mr7298363otr.128.1576142303691;
        Thu, 12 Dec 2019 01:18:23 -0800 (PST)
Date: Thu, 12 Dec 2019 01:18:22 -0800 (PST)
From: Walter Wu <truhuan@gmail.com>
To: kasan-dev <kasan-dev@googlegroups.com>
Message-Id: <ef99291d-83b9-464e-b7a1-ad7122ed1ea1@googlegroups.com>
In-Reply-To: <20191016083959.186860-1-elver@google.com>
References: <20191016083959.186860-1-elver@google.com>
Subject: Re: [PATCH 0/8] Add Kernel Concurrency Sanitizer (KCSAN)
MIME-Version: 1.0
Content-Type: multipart/mixed; 
	boundary="----=_Part_5479_243328792.1576142303148"
X-Original-Sender: truhuan@gmail.com
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

------=_Part_5479_243328792.1576142303148
Content-Type: multipart/alternative; 
	boundary="----=_Part_5480_11805987.1576142303149"

------=_Part_5480_11805987.1576142303149
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

Marco Elver=E6=96=BC 2019=E5=B9=B410=E6=9C=8816=E6=97=A5=E6=98=9F=E6=9C=9F=
=E4=B8=89 UTC+8=E4=B8=8B=E5=8D=884=E6=99=8241=E5=88=8609=E7=A7=92=E5=AF=AB=
=E9=81=93=EF=BC=9A
>
> This is the patch-series for the Kernel Concurrency Sanitizer (KCSAN).=20
> KCSAN is a sampling watchpoint-based data-race detector. More details=20
> are included in Documentation/dev-tools/kcsan.rst. This patch-series=20
> only enables KCSAN for x86, but we expect adding support for other=20
> architectures is relatively straightforward (we are aware of=20
> experimental ARM64 and POWER support).=20
>
>
Hi Marco,

Data racing issues always bothers us, we are happy to use this debug tool t=
o
detect the root cause. So, we need to understand this tool implementation,
we try to trace your code and have some questions, would you take the free=
=20
time
to answer the question.=20
Thanks.

Question:
We assume they access the same variable when use read() and write()
Below two Scenario are false negative?

=3D=3D=3D
Scenario 1:

CPU 0:                                                                     =
=20
               CPU 1:
tsan_read()                                                               =
=20
               tsan_write()
  check_access()                                                           =
=20
             check_access()
     watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL                   =
=20
 watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL
     kcsan_setup_watchpoint()                                             =
=20
            kcsan_setup_watchpoint()
        watchpoint =3D insert_watchpoint                                   =
  =20
              watchpoint =3D insert_watchpoint
        if (!remove_watchpoint(watchpoint)) // no enter, no report         =
=20
 if (!remove_watchpoint(watchpoint)) // no enter, no report

=3D=3D=3D
Scenario 2:

CPU 0:                                                                     =
=20
              CPU 1:
tsan_read()
  check_access()
    watchpoint=3Dfind_watchpoint() // watchpoint=3DNULL
    kcsan_setup_watchpoint()
      watchpoint =3D insert_watchpoint()=20

tsan_read()                                                               =
=20
              tsan_write() =20
  check_access()                                                           =
=20
            check_access()
    find_watchpoint()                                            =20
      if(expect_write && !is_write)
        continue
      return NULL                                                         =
=20
 =20
    kcsan_setup_watchpoint()
      watchpoint =3D insert_watchpoint()                                   =
  =20
        =20
      remove_watchpoint(watchpoint)
        watchpoint =3D INVALID_WATCHPOINT                                  =
 =20
                           =20
                                                                           =
=20
                     watchpoint =3D find_watchpoint()                      =
 =20
                                                             =20
                                                                           =
=20
                     kcsan_found_watchpoint()
                                                                           =
=20
                        consumed =3D try_consume_watchpoint() //=20
consumed=3Dfalse, no report




To gather early feedback, we announced KCSAN back in September, and=20
> have integrated the feedback where possible:=20
>
> http://lkml.kernel.org/r/CANpmjNPJ_bHjfLZCAPV23AXFfiPiyXXqqu72n6TgWzb2Gnu=
1eA@mail.gmail.com=20
>
> We want to point out and acknowledge the work surrounding the LKMM,=20
> including several articles that motivate why data-races are dangerous=20
> [1, 2], justifying a data-race detector such as KCSAN.=20
> [1] https://lwn.net/Articles/793253/=20
> [2] https://lwn.net/Articles/799218/=20
>
> The current list of known upstream fixes for data-races found by KCSAN=20
> can be found here:=20
>
> https://github.com/google/ktsan/wiki/KCSAN#upstream-fixes-of-data-races-f=
ound-by-kcsan=20
>
> Marco Elver (8):=20
>   kcsan: Add Kernel Concurrency Sanitizer infrastructure=20
>   objtool, kcsan: Add KCSAN runtime functions to whitelist=20
>   build, kcsan: Add KCSAN build exceptions=20
>   seqlock, kcsan: Add annotations for KCSAN=20
>   seqlock: Require WRITE_ONCE surrounding raw_seqcount_barrier=20
>   asm-generic, kcsan: Add KCSAN instrumentation for bitops=20
>   locking/atomics, kcsan: Add KCSAN instrumentation=20
>   x86, kcsan: Enable KCSAN for x86=20
>
>  Documentation/dev-tools/kcsan.rst         | 202 ++++++++++=20
>  MAINTAINERS                               |  11 +=20
>  Makefile                                  |   3 +-=20
>  arch/x86/Kconfig                          |   1 +=20
>  arch/x86/boot/Makefile                    |   1 +=20
>  arch/x86/boot/compressed/Makefile         |   1 +=20
>  arch/x86/entry/vdso/Makefile              |   1 +=20
>  arch/x86/include/asm/bitops.h             |   2 +-=20
>  arch/x86/kernel/Makefile                  |   6 +=20
>  arch/x86/kernel/cpu/Makefile              |   3 +=20
>  arch/x86/lib/Makefile                     |   2 +=20
>  arch/x86/mm/Makefile                      |   3 +=20
>  arch/x86/purgatory/Makefile               |   1 +=20
>  arch/x86/realmode/Makefile                |   1 +=20
>  arch/x86/realmode/rm/Makefile             |   1 +=20
>  drivers/firmware/efi/libstub/Makefile     |   1 +=20
>  include/asm-generic/atomic-instrumented.h | 192 ++++++++-=20
>  include/asm-generic/bitops-instrumented.h |  18 +=20
>  include/linux/compiler-clang.h            |   9 +=20
>  include/linux/compiler-gcc.h              |   7 +=20
>  include/linux/compiler.h                  |  35 +-=20
>  include/linux/kcsan-checks.h              | 116 ++++++=20
>  include/linux/kcsan.h                     |  85 ++++=20
>  include/linux/sched.h                     |   7 +=20
>  include/linux/seqlock.h                   |  51 ++-=20
>  init/init_task.c                          |   6 +=20
>  init/main.c                               |   2 +=20
>  kernel/Makefile                           |   6 +=20
>  kernel/kcsan/Makefile                     |  14 +=20
>  kernel/kcsan/atomic.c                     |  21 +=20
>  kernel/kcsan/core.c                       | 458 ++++++++++++++++++++++=
=20
>  kernel/kcsan/debugfs.c                    | 225 +++++++++++=20
>  kernel/kcsan/encoding.h                   |  94 +++++=20
>  kernel/kcsan/kcsan.c                      |  81 ++++=20
>  kernel/kcsan/kcsan.h                      | 140 +++++++=20
>  kernel/kcsan/report.c                     | 307 +++++++++++++++=20
>  kernel/kcsan/test.c                       | 117 ++++++=20
>  kernel/sched/Makefile                     |   6 +=20
>  lib/Kconfig.debug                         |   2 +=20
>  lib/Kconfig.kcsan                         |  88 +++++=20
>  lib/Makefile                              |   3 +=20
>  mm/Makefile                               |   8 +=20
>  scripts/Makefile.kcsan                    |   6 +=20
>  scripts/Makefile.lib                      |  10 +=20
>  scripts/atomic/gen-atomic-instrumented.sh |   9 +-=20
>  tools/objtool/check.c                     |  17 +=20
>  46 files changed, 2364 insertions(+), 16 deletions(-)=20
>  create mode 100644 Documentation/dev-tools/kcsan.rst=20
>  create mode 100644 include/linux/kcsan-checks.h=20
>  create mode 100644 include/linux/kcsan.h=20
>  create mode 100644 kernel/kcsan/Makefile=20
>  create mode 100644 kernel/kcsan/atomic.c=20
>  create mode 100644 kernel/kcsan/core.c=20
>  create mode 100644 kernel/kcsan/debugfs.c=20
>  create mode 100644 kernel/kcsan/encoding.h=20
>  create mode 100644 kernel/kcsan/kcsan.c=20
>  create mode 100644 kernel/kcsan/kcsan.h=20
>  create mode 100644 kernel/kcsan/report.c=20
>  create mode 100644 kernel/kcsan/test.c=20
>  create mode 100644 lib/Kconfig.kcsan=20
>  create mode 100644 scripts/Makefile.kcsan=20
>
> --=20
> 2.23.0.700.g56cf767bdb-goog=20
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ef99291d-83b9-464e-b7a1-ad7122ed1ea1%40googlegroups.com.

------=_Part_5480_11805987.1576142303149
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: base64

PGRpdiBkaXI9Imx0ciI+TWFyY28gRWx2ZXLmlrwgMjAxOeW5tDEw5pyIMTbml6XmmJ/mnJ/kuIkg
VVRDKzjkuIvljYg05pmCNDHliIYwOeenkuWvq+mBk++8mjxibG9ja3F1b3RlIGNsYXNzPSJnbWFp
bF9xdW90ZSIgc3R5bGU9Im1hcmdpbjogMDttYXJnaW4tbGVmdDogMC44ZXg7Ym9yZGVyLWxlZnQ6
IDFweCAjY2NjIHNvbGlkO3BhZGRpbmctbGVmdDogMWV4OyI+VGhpcyBpcyB0aGUgcGF0Y2gtc2Vy
aWVzIGZvciB0aGUgS2VybmVsIENvbmN1cnJlbmN5IFNhbml0aXplciAoS0NTQU4pLg0KPGJyPktD
U0FOIGlzIGEgc2FtcGxpbmcgd2F0Y2hwb2ludC1iYXNlZCBkYXRhLXJhY2UgZGV0ZWN0b3IuIE1v
cmUgZGV0YWlscw0KPGJyPmFyZSBpbmNsdWRlZCBpbiBEb2N1bWVudGF0aW9uL2Rldi10b29scy9r
Y3Nhbi48d2JyPnJzdC4gVGhpcyBwYXRjaC1zZXJpZXMNCjxicj5vbmx5IGVuYWJsZXMgS0NTQU4g
Zm9yIHg4NiwgYnV0IHdlIGV4cGVjdCBhZGRpbmcgc3VwcG9ydCBmb3Igb3RoZXINCjxicj5hcmNo
aXRlY3R1cmVzIGlzIHJlbGF0aXZlbHkgc3RyYWlnaHRmb3J3YXJkICh3ZSBhcmUgYXdhcmUgb2YN
Cjxicj5leHBlcmltZW50YWwgQVJNNjQgYW5kIFBPV0VSIHN1cHBvcnQpLg0KPGJyPg0KPGJyPjwv
YmxvY2txdW90ZT48ZGl2Pjxicj48L2Rpdj48ZGl2PkhpIE1hcmNvLDwvZGl2PjxkaXY+PGJyPjwv
ZGl2PjxkaXY+RGF0YSByYWNpbmcgaXNzdWVzIGFsd2F5cyBib3RoZXJzIHVzLCB3ZSBhcmUgaGFw
cHkgdG8gdXNlIHRoaXMgZGVidWcgdG9vbCB0bzwvZGl2PjxkaXY+ZGV0ZWN0IHRoZSByb290IGNh
dXNlLiBTbywgd2UgbmVlZCB0byB1bmRlcnN0YW5kIHRoaXMgdG9vbCBpbXBsZW1lbnRhdGlvbiw8
L2Rpdj48ZGl2PndlIHRyeSB0byB0cmFjZSB5b3VyIGNvZGUgYW5kIGhhdmUgc29tZSBxdWVzdGlv
bnMsIHdvdWxkIHlvdSB0YWtlIHRoZSBmcmVlIHRpbWU8L2Rpdj48ZGl2PnRvIGFuc3dlciB0aGUg
cXVlc3Rpb24uwqA8L2Rpdj48ZGl2PlRoYW5rcy48L2Rpdj48ZGl2Pjxicj48L2Rpdj48ZGl2PlF1
ZXN0aW9uOjwvZGl2PjxkaXY+V2UgYXNzdW1lIHRoZXkgYWNjZXNzIHRoZSBzYW1lIHZhcmlhYmxl
IHdoZW4gdXNlIHJlYWQoKSBhbmQgd3JpdGUoKTwvZGl2PjxkaXY+QmVsb3cgdHdvwqBTY2VuYXJp
byBhcmUgZmFsc2UgbmVnYXRpdmU/PC9kaXY+PGRpdj48YnI+PC9kaXY+PGRpdj49PT08L2Rpdj48
ZGl2PlNjZW5hcmlvIDE6PGJyPjwvZGl2PjxkaXY+PGRpdj48YnI+PC9kaXY+PGRpdj5DUFUgMDrC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoENQVSAxOjwvZGl2PjxkaXY+dHNhbl9yZWFkKCnCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoHRzYW5fd3JpdGUo
KTwvZGl2PjxkaXY+wqAgY2hlY2tfYWNjZXNzKCnCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoGNoZWNrX2FjY2VzcygpPC9kaXY+PGRpdj7CoCDCoCDC
oHdhdGNocG9pbnQ9ZmluZF93YXRjaHBvaW50KCkgLy8gd2F0Y2hwb2ludD1OVUxMwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqB3YXRjaHBvaW50PWZpbmRfd2F0Y2hwb2ludCgpIC8vIHdh
dGNocG9pbnQ9TlVMTDwvZGl2PjxkaXY+wqAgwqAgwqBrY3Nhbl9zZXR1cF93YXRjaHBvaW50KCnC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCBrY3Nhbl9zZXR1cF93YXRjaHBvaW50KCk8L2Rp
dj48ZGl2PsKgIMKgIMKgIMKgIHdhdGNocG9pbnQgPSBpbnNlcnRfd2F0Y2hwb2ludMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIHdhdGNocG9pbnQgPSBpbnNlcnRfd2F0Y2hwb2ludDwvZGl2PjxkaXY+wqAg
wqAgwqAgwqAgaWYgKCFyZW1vdmVfd2F0Y2hwb2ludCh3YXRjaHBvaW50KSkgLy8gbm8gZW50ZXIs
IG5vIHJlcG9ydMKgIMKgIMKgIMKgIMKgIMKgaWYgKCFyZW1vdmVfd2F0Y2hwb2ludCh3YXRjaHBv
aW50KSkgLy8gbm8gZW50ZXIsIG5vIHJlcG9ydDwvZGl2PjxkaXY+PGJyPjwvZGl2PjxkaXY+PT09
PGJyPjwvZGl2PjxkaXY+U2NlbmFyaW8gMjo8L2Rpdj48ZGl2Pjxicj48L2Rpdj48ZGl2PkNQVSAw
OsKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIENQVSAxOjwvZGl2PjxkaXY+dHNhbl9yZWFkKCk8L2Rpdj48ZGl2PsKgIGNo
ZWNrX2FjY2VzcygpPC9kaXY+PGRpdj7CoCDCoCB3YXRjaHBvaW50PWZpbmRfd2F0Y2hwb2ludCgp
IC8vIHdhdGNocG9pbnQ9TlVMTDwvZGl2PjxkaXY+wqAgwqAga2NzYW5fc2V0dXBfd2F0Y2hwb2lu
dCgpPC9kaXY+PGRpdj7CoCDCoCDCoCB3YXRjaHBvaW50ID0gaW5zZXJ0X3dhdGNocG9pbnQoKcKg
PC9kaXY+PGRpdj48YnI+PC9kaXY+PGRpdj50c2FuX3JlYWQoKcKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIHRzYW5fd3JpdGUoKcKgwqA8
L2Rpdj48ZGl2PsKgIGNoZWNrX2FjY2VzcygpwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgY2hlY2tfYWNjZXNzKCk8L2Rpdj48ZGl2PsKgIMKgIGZpbmRf
d2F0Y2hwb2ludCgpwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqA8L2Rpdj48ZGl2PsKgIMKgIMKgIGlmKGV4cGVjdF93cml0
ZSAmYW1wOyZhbXA7ICFpc193cml0ZSk8L2Rpdj48ZGl2PsKgIMKgIMKgIMKgIGNvbnRpbnVlPC9k
aXY+PGRpdj7CoCDCoCDCoCByZXR1cm4gTlVMTMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgwqA8L2Rpdj48ZGl2PsKgIMKgIGtjc2FuX3NldHVwX3dhdGNocG9pbnQoKTwvZGl2PjxkaXY+
wqAgwqAgwqAgd2F0Y2hwb2ludCA9IGluc2VydF93YXRjaHBvaW50KCnCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoDwv
ZGl2PjxkaXY+wqAgwqAgwqAgcmVtb3ZlX3dhdGNocG9pbnQod2F0Y2hwb2ludCk8L2Rpdj48ZGl2
PsKgIMKgIMKgIMKgIHdhdGNocG9pbnQgPSBJTlZBTElEX1dBVENIUE9JTlTCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoMKgPC9kaXY+PGRpdj7CoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoHdhdGNocG9pbnQgPSBmaW5kX3dhdGNocG9pbnQoKcKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
wqA8L2Rpdj48ZGl2PsKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKga2NzYW5fZm91bmRf
d2F0Y2hwb2ludCgpPC9kaXY+PGRpdj7CoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCBjb25zdW1lZCA9IHRyeV9jb25zdW1lX3dhdGNocG9pbnQoKSAvLyBjb25zdW1lZD1mYWxzZSwg
bm8gcmVwb3J0PC9kaXY+PC9kaXY+PGRpdj48YnI+PC9kaXY+PGRpdj48YnI+PC9kaXY+PGRpdj48
YnI+PC9kaXY+PGRpdj48YnI+PC9kaXY+PGJsb2NrcXVvdGUgY2xhc3M9ImdtYWlsX3F1b3RlIiBz
dHlsZT0ibWFyZ2luOiAwO21hcmdpbi1sZWZ0OiAwLjhleDtib3JkZXItbGVmdDogMXB4ICNjY2Mg
c29saWQ7cGFkZGluZy1sZWZ0OiAxZXg7Ij5UbyBnYXRoZXIgZWFybHkgZmVlZGJhY2ssIHdlIGFu
bm91bmNlZCBLQ1NBTiBiYWNrIGluIFNlcHRlbWJlciwgYW5kDQo8YnI+aGF2ZSBpbnRlZ3JhdGVk
IHRoZSBmZWVkYmFjayB3aGVyZSBwb3NzaWJsZToNCjxicj48YSBocmVmPSJodHRwOi8vbGttbC5r
ZXJuZWwub3JnL3IvQ0FOcG1qTlBKX2JIamZMWkNBUFYyM0FYRmZpUGl5WFhxcXU3Mm42VGdXemIy
R251MWVBQG1haWwuZ21haWwuY29tIiB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub2ZvbGxvdyIgb25t
b3VzZWRvd249InRoaXMuaHJlZj0mIzM5O2h0dHA6Ly93d3cuZ29vZ2xlLmNvbS91cmw/cVx4M2Ro
dHRwJTNBJTJGJTJGbGttbC5rZXJuZWwub3JnJTJGciUyRkNBTnBtak5QSl9iSGpmTFpDQVBWMjNB
WEZmaVBpeVhYcXF1NzJuNlRnV3piMkdudTFlQSU0MG1haWwuZ21haWwuY29tXHgyNnNhXHgzZERc
eDI2c250elx4M2QxXHgyNnVzZ1x4M2RBRlFqQ05HN2VCS0xSblFqbVJUS3VmR25aTDZ2WUV6dXNn
JiMzOTs7cmV0dXJuIHRydWU7IiBvbmNsaWNrPSJ0aGlzLmhyZWY9JiMzOTtodHRwOi8vd3d3Lmdv
b2dsZS5jb20vdXJsP3FceDNkaHR0cCUzQSUyRiUyRmxrbWwua2VybmVsLm9yZyUyRnIlMkZDQU5w
bWpOUEpfYkhqZkxaQ0FQVjIzQVhGZmlQaXlYWHFxdTcybjZUZ1d6YjJHbnUxZUElNDBtYWlsLmdt
YWlsLmNvbVx4MjZzYVx4M2REXHgyNnNudHpceDNkMVx4MjZ1c2dceDNkQUZRakNORzdlQktMUm5R
am1SVEt1ZkduWkw2dllFenVzZyYjMzk7O3JldHVybiB0cnVlOyI+aHR0cDovL2xrbWwua2VybmVs
Lm9yZy9yLzx3YnI+Q0FOcG1qTlBKXzx3YnI+YkhqZkxaQ0FQVjIzQVhGZmlQaXlYWHFxdTcybjZU
PHdicj5nV3piMkdudTFlQUBtYWlsLmdtYWlsLmNvbTwvYT4NCjxicj4NCjxicj5XZSB3YW50IHRv
IHBvaW50IG91dCBhbmQgYWNrbm93bGVkZ2UgdGhlIHdvcmsgc3Vycm91bmRpbmcgdGhlIExLTU0s
DQo8YnI+aW5jbHVkaW5nIHNldmVyYWwgYXJ0aWNsZXMgdGhhdCBtb3RpdmF0ZSB3aHkgZGF0YS1y
YWNlcyBhcmUgZGFuZ2Vyb3VzDQo8YnI+WzEsIDJdLCBqdXN0aWZ5aW5nIGEgZGF0YS1yYWNlIGRl
dGVjdG9yIHN1Y2ggYXMgS0NTQU4uDQo8YnI+WzFdIDxhIGhyZWY9Imh0dHBzOi8vbHduLm5ldC9B
cnRpY2xlcy83OTMyNTMvIiB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub2ZvbGxvdyIgb25tb3VzZWRv
d249InRoaXMuaHJlZj0mIzM5O2h0dHBzOi8vd3d3Lmdvb2dsZS5jb20vdXJsP3FceDNkaHR0cHMl
M0ElMkYlMkZsd24ubmV0JTJGQXJ0aWNsZXMlMkY3OTMyNTMlMkZceDI2c2FceDNkRFx4MjZzbnR6
XHgzZDFceDI2dXNnXHgzZEFGUWpDTkhaVGFBTlVlR1UzRk5sbE5UNVFPZ2JlUDZBakEmIzM5Ozty
ZXR1cm4gdHJ1ZTsiIG9uY2xpY2s9InRoaXMuaHJlZj0mIzM5O2h0dHBzOi8vd3d3Lmdvb2dsZS5j
b20vdXJsP3FceDNkaHR0cHMlM0ElMkYlMkZsd24ubmV0JTJGQXJ0aWNsZXMlMkY3OTMyNTMlMkZc
eDI2c2FceDNkRFx4MjZzbnR6XHgzZDFceDI2dXNnXHgzZEFGUWpDTkhaVGFBTlVlR1UzRk5sbE5U
NVFPZ2JlUDZBakEmIzM5OztyZXR1cm4gdHJ1ZTsiPmh0dHBzOi8vbHduLm5ldC9BcnRpY2xlcy88
d2JyPjc5MzI1My88L2E+DQo8YnI+WzJdIDxhIGhyZWY9Imh0dHBzOi8vbHduLm5ldC9BcnRpY2xl
cy83OTkyMTgvIiB0YXJnZXQ9Il9ibGFuayIgcmVsPSJub2ZvbGxvdyIgb25tb3VzZWRvd249InRo
aXMuaHJlZj0mIzM5O2h0dHBzOi8vd3d3Lmdvb2dsZS5jb20vdXJsP3FceDNkaHR0cHMlM0ElMkYl
MkZsd24ubmV0JTJGQXJ0aWNsZXMlMkY3OTkyMTglMkZceDI2c2FceDNkRFx4MjZzbnR6XHgzZDFc
eDI2dXNnXHgzZEFGUWpDTkgyaHNrRkNhWlFMRUlSTkQwU2E2MEtHeGxhNUEmIzM5OztyZXR1cm4g
dHJ1ZTsiIG9uY2xpY2s9InRoaXMuaHJlZj0mIzM5O2h0dHBzOi8vd3d3Lmdvb2dsZS5jb20vdXJs
P3FceDNkaHR0cHMlM0ElMkYlMkZsd24ubmV0JTJGQXJ0aWNsZXMlMkY3OTkyMTglMkZceDI2c2Fc
eDNkRFx4MjZzbnR6XHgzZDFceDI2dXNnXHgzZEFGUWpDTkgyaHNrRkNhWlFMRUlSTkQwU2E2MEtH
eGxhNUEmIzM5OztyZXR1cm4gdHJ1ZTsiPmh0dHBzOi8vbHduLm5ldC9BcnRpY2xlcy88d2JyPjc5
OTIxOC88L2E+DQo8YnI+DQo8YnI+VGhlIGN1cnJlbnQgbGlzdCBvZiBrbm93biB1cHN0cmVhbSBm
aXhlcyBmb3IgZGF0YS1yYWNlcyBmb3VuZCBieSBLQ1NBTg0KPGJyPmNhbiBiZSBmb3VuZCBoZXJl
Og0KPGJyPjxhIGhyZWY9Imh0dHBzOi8vZ2l0aHViLmNvbS9nb29nbGUva3RzYW4vd2lraS9LQ1NB
TiN1cHN0cmVhbS1maXhlcy1vZi1kYXRhLXJhY2VzLWZvdW5kLWJ5LWtjc2FuIiB0YXJnZXQ9Il9i
bGFuayIgcmVsPSJub2ZvbGxvdyIgb25tb3VzZWRvd249InRoaXMuaHJlZj0mIzM5O2h0dHBzOi8v
d3d3Lmdvb2dsZS5jb20vdXJsP3FceDNkaHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGZ29vZ2xl
JTJGa3RzYW4lMkZ3aWtpJTJGS0NTQU4lMjN1cHN0cmVhbS1maXhlcy1vZi1kYXRhLXJhY2VzLWZv
dW5kLWJ5LWtjc2FuXHgyNnNhXHgzZERceDI2c250elx4M2QxXHgyNnVzZ1x4M2RBRlFqQ05IRzRQ
cG5EVkhhZjJBUUtaOHVRMjhYZ25pYzBnJiMzOTs7cmV0dXJuIHRydWU7IiBvbmNsaWNrPSJ0aGlz
LmhyZWY9JiMzOTtodHRwczovL3d3dy5nb29nbGUuY29tL3VybD9xXHgzZGh0dHBzJTNBJTJGJTJG
Z2l0aHViLmNvbSUyRmdvb2dsZSUyRmt0c2FuJTJGd2lraSUyRktDU0FOJTIzdXBzdHJlYW0tZml4
ZXMtb2YtZGF0YS1yYWNlcy1mb3VuZC1ieS1rY3Nhblx4MjZzYVx4M2REXHgyNnNudHpceDNkMVx4
MjZ1c2dceDNkQUZRakNOSEc0UHBuRFZIYWYyQVFLWjh1UTI4WGduaWMwZyYjMzk7O3JldHVybiB0
cnVlOyI+aHR0cHM6Ly9naXRodWIuY29tL2dvb2dsZS88d2JyPmt0c2FuL3dpa2kvS0NTQU4jdXBz
dHJlYW0tPHdicj5maXhlcy1vZi1kYXRhLXJhY2VzLWZvdW5kLWJ5LTx3YnI+a2NzYW48L2E+DQo8
YnI+DQo8YnI+TWFyY28gRWx2ZXIgKDgpOg0KPGJyPsKgIGtjc2FuOiBBZGQgS2VybmVsIENvbmN1
cnJlbmN5IFNhbml0aXplciBpbmZyYXN0cnVjdHVyZQ0KPGJyPsKgIG9ianRvb2wsIGtjc2FuOiBB
ZGQgS0NTQU4gcnVudGltZSBmdW5jdGlvbnMgdG8gd2hpdGVsaXN0DQo8YnI+wqAgYnVpbGQsIGtj
c2FuOiBBZGQgS0NTQU4gYnVpbGQgZXhjZXB0aW9ucw0KPGJyPsKgIHNlcWxvY2ssIGtjc2FuOiBB
ZGQgYW5ub3RhdGlvbnMgZm9yIEtDU0FODQo8YnI+wqAgc2VxbG9jazogUmVxdWlyZSBXUklURV9P
TkNFIHN1cnJvdW5kaW5nIHJhd19zZXFjb3VudF9iYXJyaWVyDQo8YnI+wqAgYXNtLWdlbmVyaWMs
IGtjc2FuOiBBZGQgS0NTQU4gaW5zdHJ1bWVudGF0aW9uIGZvciBiaXRvcHMNCjxicj7CoCBsb2Nr
aW5nL2F0b21pY3MsIGtjc2FuOiBBZGQgS0NTQU4gaW5zdHJ1bWVudGF0aW9uDQo8YnI+wqAgeDg2
LCBrY3NhbjogRW5hYmxlIEtDU0FOIGZvciB4ODYNCjxicj4NCjxicj7CoERvY3VtZW50YXRpb24v
ZGV2LXRvb2xzLzx3YnI+a2NzYW4ucnN0IMKgIMKgIMKgIMKgIHwgMjAyICsrKysrKysrKysNCjxi
cj7CoE1BSU5UQUlORVJTIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIHwgwqAxMSArDQo8YnI+wqBNYWtlZmlsZSDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoHwgwqAgMyArLQ0KPGJyPsKgYXJjaC94ODYvS2NvbmZpZyDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoHwgwqAgMSArDQo8YnI+wqBhcmNo
L3g4Ni9ib290L01ha2VmaWxlIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgfCDCoCAxICsN
Cjxicj7CoGFyY2gveDg2L2Jvb3QvY29tcHJlc3NlZC88d2JyPk1ha2VmaWxlIMKgIMKgIMKgIMKg
IHwgwqAgMSArDQo8YnI+wqBhcmNoL3g4Ni9lbnRyeS92ZHNvL01ha2VmaWxlIMKgIMKgIMKgIMKg
IMKgIMKgIMKgfCDCoCAxICsNCjxicj7CoGFyY2gveDg2L2luY2x1ZGUvYXNtL2JpdG9wcy5oIMKg
IMKgIMKgIMKgIMKgIMKgIHwgwqAgMiArLQ0KPGJyPsKgYXJjaC94ODYva2VybmVsL01ha2VmaWxl
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgfCDCoCA2ICsNCjxicj7CoGFyY2gveDg2L2tlcm5l
bC9jcHUvTWFrZWZpbGUgwqAgwqAgwqAgwqAgwqAgwqAgwqB8IMKgIDMgKw0KPGJyPsKgYXJjaC94
ODYvbGliL01ha2VmaWxlIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIHwgwqAgMiArDQo8
YnI+wqBhcmNoL3g4Ni9tbS9NYWtlZmlsZSDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oHwgwqAgMyArDQo8YnI+wqBhcmNoL3g4Ni9wdXJnYXRvcnkvTWFrZWZpbGUgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgfCDCoCAxICsNCjxicj7CoGFyY2gveDg2L3JlYWxtb2RlL01ha2VmaWxlIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgfCDCoCAxICsNCjxicj7CoGFyY2gveDg2L3JlYWxtb2RlL3JtL01h
a2VmaWxlIMKgIMKgIMKgIMKgIMKgIMKgIHwgwqAgMSArDQo8YnI+wqBkcml2ZXJzL2Zpcm13YXJl
L2VmaS9saWJzdHViLzx3YnI+TWFrZWZpbGUgwqAgwqAgfCDCoCAxICsNCjxicj7CoGluY2x1ZGUv
YXNtLWdlbmVyaWMvYXRvbWljLTx3YnI+aW5zdHJ1bWVudGVkLmggfCAxOTIgKysrKysrKystDQo8
YnI+wqBpbmNsdWRlL2FzbS1nZW5lcmljL2JpdG9wcy08d2JyPmluc3RydW1lbnRlZC5oIHwgwqAx
OCArDQo8YnI+wqBpbmNsdWRlL2xpbnV4L2NvbXBpbGVyLWNsYW5nLjx3YnI+aCDCoCDCoCDCoCDC
oCDCoCDCoHwgwqAgOSArDQo8YnI+wqBpbmNsdWRlL2xpbnV4L2NvbXBpbGVyLWdjYy5oIMKgIMKg
IMKgIMKgIMKgIMKgIMKgfCDCoCA3ICsNCjxicj7CoGluY2x1ZGUvbGludXgvY29tcGlsZXIuaCDC
oCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoHwgwqAzNSArLQ0KPGJyPsKgaW5jbHVkZS9saW51eC9r
Y3Nhbi1jaGVja3MuaCDCoCDCoCDCoCDCoCDCoCDCoCDCoHwgMTE2ICsrKysrKw0KPGJyPsKgaW5j
bHVkZS9saW51eC9rY3Nhbi5oIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIHwgwqA4NSAr
KysrDQo8YnI+wqBpbmNsdWRlL2xpbnV4L3NjaGVkLmggwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgfCDCoCA3ICsNCjxicj7CoGluY2x1ZGUvbGludXgvc2VxbG9jay5oIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIHwgwqA1MSArKy0NCjxicj7CoGluaXQvaW5pdF90YXNrLmMgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqB8IMKgIDYgKw0KPGJyPsKgaW5pdC9tYWlu
LmMgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgfCDCoCAyICsN
Cjxicj7CoGtlcm5lbC9NYWtlZmlsZSDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCB8IMKgIDYgKw0KPGJyPsKga2VybmVsL2tjc2FuL01ha2VmaWxlIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIHwgwqAxNCArDQo8YnI+wqBrZXJuZWwva2NzYW4vYXRvbWljLmMgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgfCDCoDIxICsNCjxicj7CoGtlcm5lbC9rY3Nhbi9j
b3JlLmMgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgfCA0NTggKysrKysrKysrKysr
KysrKysrKysrKw0KPGJyPsKga2VybmVsL2tjc2FuL2RlYnVnZnMuYyDCoCDCoCDCoCDCoCDCoCDC
oCDCoCDCoCDCoCDCoHwgMjI1ICsrKysrKysrKysrDQo8YnI+wqBrZXJuZWwva2NzYW4vZW5jb2Rp
bmcuaCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCB8IMKgOTQgKysrKysNCjxicj7CoGtlcm5l
bC9rY3Nhbi9rY3Nhbi5jIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgfCDCoDgxICsr
KysNCjxicj7CoGtlcm5lbC9rY3Nhbi9rY3Nhbi5oIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgfCAxNDAgKysrKysrKw0KPGJyPsKga2VybmVsL2tjc2FuL3JlcG9ydC5jIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIHwgMzA3ICsrKysrKysrKysrKysrKw0KPGJyPsKga2VybmVs
L2tjc2FuL3Rlc3QuYyDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCB8IDExNyArKysr
KysNCjxicj7CoGtlcm5lbC9zY2hlZC9NYWtlZmlsZSDCoCDCoCDCoCDCoCDCoCDCoCDCoCDCoCDC
oCDCoCB8IMKgIDYgKw0KPGJyPsKgbGliL0tjb25maWcuZGVidWcgwqAgwqAgwqAgwqAgwqAgwqAg
wqAgwqAgwqAgwqAgwqAgwqAgfCDCoCAyICsNCjxicj7CoGxpYi9LY29uZmlnLmtjc2FuIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIHwgwqA4OCArKysrKw0KPGJyPsKgbGliL01h
a2VmaWxlIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgfCDCoCAz
ICsNCjxicj7CoG1tL01ha2VmaWxlIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKg
IMKgIMKgIMKgIHwgwqAgOCArDQo8YnI+wqBzY3JpcHRzL01ha2VmaWxlLmtjc2FuIMKgIMKgIMKg
IMKgIMKgIMKgIMKgIMKgIMKgIMKgfCDCoCA2ICsNCjxicj7CoHNjcmlwdHMvTWFrZWZpbGUubGli
IMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgIMKgfCDCoDEwICsNCjxicj7CoHNjcmlwdHMv
YXRvbWljL2dlbi1hdG9taWMtPHdicj5pbnN0cnVtZW50ZWQuc2ggfCDCoCA5ICstDQo8YnI+wqB0
b29scy9vYmp0b29sL2NoZWNrLmMgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgwqAgfCDCoDE3
ICsNCjxicj7CoDQ2IGZpbGVzIGNoYW5nZWQsIDIzNjQgaW5zZXJ0aW9ucygrKSwgMTYgZGVsZXRp
b25zKC0pDQo8YnI+wqBjcmVhdGUgbW9kZSAxMDA2NDQgRG9jdW1lbnRhdGlvbi9kZXYtdG9vbHMv
a2NzYW4uPHdicj5yc3QNCjxicj7CoGNyZWF0ZSBtb2RlIDEwMDY0NCBpbmNsdWRlL2xpbnV4L2tj
c2FuLWNoZWNrcy5oDQo8YnI+wqBjcmVhdGUgbW9kZSAxMDA2NDQgaW5jbHVkZS9saW51eC9rY3Nh
bi5oDQo8YnI+wqBjcmVhdGUgbW9kZSAxMDA2NDQga2VybmVsL2tjc2FuL01ha2VmaWxlDQo8YnI+
wqBjcmVhdGUgbW9kZSAxMDA2NDQga2VybmVsL2tjc2FuL2F0b21pYy5jDQo8YnI+wqBjcmVhdGUg
bW9kZSAxMDA2NDQga2VybmVsL2tjc2FuL2NvcmUuYw0KPGJyPsKgY3JlYXRlIG1vZGUgMTAwNjQ0
IGtlcm5lbC9rY3Nhbi9kZWJ1Z2ZzLmMNCjxicj7CoGNyZWF0ZSBtb2RlIDEwMDY0NCBrZXJuZWwv
a2NzYW4vZW5jb2RpbmcuaA0KPGJyPsKgY3JlYXRlIG1vZGUgMTAwNjQ0IGtlcm5lbC9rY3Nhbi9r
Y3Nhbi5jDQo8YnI+wqBjcmVhdGUgbW9kZSAxMDA2NDQga2VybmVsL2tjc2FuL2tjc2FuLmgNCjxi
cj7CoGNyZWF0ZSBtb2RlIDEwMDY0NCBrZXJuZWwva2NzYW4vcmVwb3J0LmMNCjxicj7CoGNyZWF0
ZSBtb2RlIDEwMDY0NCBrZXJuZWwva2NzYW4vdGVzdC5jDQo8YnI+wqBjcmVhdGUgbW9kZSAxMDA2
NDQgbGliL0tjb25maWcua2NzYW4NCjxicj7CoGNyZWF0ZSBtb2RlIDEwMDY0NCBzY3JpcHRzL01h
a2VmaWxlLmtjc2FuDQo8YnI+DQo8YnI+LS0gDQo8YnI+Mi4yMy4wLjcwMC5nNTZjZjc2N2JkYi1n
b29nDQo8YnI+DQo8YnI+PC9ibG9ja3F1b3RlPjwvZGl2Pg0KDQo8cD48L3A+CgotLSA8YnIgLz4K
WW91IHJlY2VpdmVkIHRoaXMgbWVzc2FnZSBiZWNhdXNlIHlvdSBhcmUgc3Vic2NyaWJlZCB0byB0
aGUgR29vZ2xlIEdyb3VwcyAmcXVvdDtrYXNhbi1kZXYmcXVvdDsgZ3JvdXAuPGJyIC8+ClRvIHVu
c3Vic2NyaWJlIGZyb20gdGhpcyBncm91cCBhbmQgc3RvcCByZWNlaXZpbmcgZW1haWxzIGZyb20g
aXQsIHNlbmQgYW4gZW1haWwgdG8gPGEgaHJlZj0ibWFpbHRvOmthc2FuLWRldit1bnN1YnNjcmli
ZUBnb29nbGVncm91cHMuY29tIj5rYXNhbi1kZXYrdW5zdWJzY3JpYmVAZ29vZ2xlZ3JvdXBzLmNv
bTwvYT4uPGJyIC8+ClRvIHZpZXcgdGhpcyBkaXNjdXNzaW9uIG9uIHRoZSB3ZWIgdmlzaXQgPGEg
aHJlZj0iaHR0cHM6Ly9ncm91cHMuZ29vZ2xlLmNvbS9kL21zZ2lkL2thc2FuLWRldi9lZjk5Mjkx
ZC04M2I5LTQ2NGUtYjdhMS1hZDcxMjJlZDFlYTElNDBnb29nbGVncm91cHMuY29tP3V0bV9tZWRp
dW09ZW1haWwmdXRtX3NvdXJjZT1mb290ZXIiPmh0dHBzOi8vZ3JvdXBzLmdvb2dsZS5jb20vZC9t
c2dpZC9rYXNhbi1kZXYvZWY5OTI5MWQtODNiOS00NjRlLWI3YTEtYWQ3MTIyZWQxZWExJTQwZ29v
Z2xlZ3JvdXBzLmNvbTwvYT4uPGJyIC8+Cg==
------=_Part_5480_11805987.1576142303149--

------=_Part_5479_243328792.1576142303148--
