Return-Path: <kasan-dev+bncBCBJ5VHVTUFBBCU3Y2QQMGQEIRHCNAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 63EB36DBC02
	for <lists+kasan-dev@lfdr.de>; Sat,  8 Apr 2023 17:51:40 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id gt19-20020a17090af2d300b002465835c3d0sf1067028pjb.1
        for <lists+kasan-dev@lfdr.de>; Sat, 08 Apr 2023 08:51:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680969099; cv=pass;
        d=google.com; s=arc-20160816;
        b=cT/B7k4cL8m6y6iVH1tjV77FG99tI3tnOqp7RUedKJOzHmk5SEZlMfzox5dmCLkcrs
         xolskX4tLaKs29XNhY+lBWyryenxuNtm8BcQCG9OscUY4dPo8ybCPTNNTm1zLifES+be
         XBxU0nLpKWNFvMZjrE7FhXz3CrpV6lgflriQFYC+nam8moBCg1QWNNBscwoZcNcuZDFl
         VrcCc1nKkftZKKG9bgIC1ssCfHJJfCP5IosVOSDqhucpjluco3mscB4lHxfhR0TjjUS6
         UDSz7MKYelMlacYxNb/17oisN6ooSo4D2etMecUYgyN/Se91VOAp8KTpGrquJbXoOEWw
         UpLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=+NQKQJmEXhxSb1hMszl3F78azMXr/beAC75E5HxyyMI=;
        b=ZmWb95bLt2zyQ5l8DwdVuw4IIVUD+CRnkoYMb8rvpt2Ksg18/k2nQXxpQ6uRvt8+17
         aCjCyzOdKY7G7aRKqkX9aa9pGbFtJbV7jXnbQ+NXYf4y8nKgdc9dnrxkefZ+NozCYrzK
         d9kIcgkIXJ47xoVAwljgrtsYuiBOZEvlXCNOinOP/3jo3ZY/i6FeiF8U5SBJzz+KvBBy
         I34mEiCb4q77VoLCIXN5N+NePz39tj9KvumqIiHYAdCItVXNomf0Vuj84N6ve0OywHq3
         h2LeXuiSG0gR0DRgN2mmGe4ccAJp4lJ98z70medr94BmDY4FaDknzWHddfJIFQi9J8ut
         +W0A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=f47is1vb;
       spf=pass (google.com: domain of mail.dipanjan.das@gmail.com designates 2001:4860:4864:20::2e as permitted sender) smtp.mailfrom=mail.dipanjan.das@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1680969099;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:mime-version:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+NQKQJmEXhxSb1hMszl3F78azMXr/beAC75E5HxyyMI=;
        b=smB503B4fbmir7pPaJRSP86ZMMjRNXSaWaPQLBTCuSroEpLM3JKBdXIP0NjsBOy9rd
         wT8abLK8gjqi//jWJ7ZNthossMzz+AbSLPG50K3KbLcFV6m5AJXM8btAxWudgDA19ieG
         Ixqygk4cWLcwwwcMDvsDOtFd0TeEHH2T4Ln7ERlZyrFjmUDWuQC31hneq58dqun16r+f
         S/VdLiFVAnACb/zRc1GXBrN/YcItLW5zNofVhOWMeMpp86XA4XMAejLHM5XaWTADRT0E
         Scb/I3YAwVE2EVz66u0YPe7wVBov4I0JH3wWeUeg9AkKc5acgZX0eDZGV3hdsyA9Qhv4
         4wyQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680969099;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+NQKQJmEXhxSb1hMszl3F78azMXr/beAC75E5HxyyMI=;
        b=fDvAvn5DgaT0yMa6A+VmojNFdPCuQZMnlnpbFC9UobBOwVorGU28BRD6fAZxW6P3lE
         Hbx4CN0vEKFJHFP1Q0aN4YtVvloiq/ZsYj9LPYyOEcvGNCQCqCByHjmhddbZtUxK7h2V
         nDxXkJMrTHxeVrxHRCw0rcx4Tlbxom+nExk+YZWAY71X6ir5vDr2hIlA2ZCgauJSP6+n
         FZJYaZG/vPxRoCK3qwUC6EXUFEzHFf6avcu3/OmCOX0j7wXXTAqKbHpEftuuYZSGAMnH
         hxktjf9FpBijuu8H/WpyKx6B5UHEwXvM1jpGUJOjdklOdq42Dv8qlhx1YHiavdvvqI9/
         eokg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680969099;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :mime-version:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+NQKQJmEXhxSb1hMszl3F78azMXr/beAC75E5HxyyMI=;
        b=JWWDkR4XCNYoMNN8agPAgxF8DRsyU2buog4nFcEAGnAZ0giFTNZljY5w8pKTPPvt2j
         Hpq/0bX03m8czblgrpehM/fb7ulCHya2QjE1fLZGFtkCJYpGo53CaVSiYEEi01ftEJ++
         GtQAXEXAQhsPIERj3cVyUdKe9o2sKOr/uimG3eam+gZFIQLnsnvkDEi85DVUACgfNA7D
         A9uJDNEWVEYHqLG+okjI9pb0KOCyAcyTDsuqHd7f39/7o8Ejy2lhFYHhJlzxYt33pJTh
         OrfpD2YoILi3f+Zgxg3/2/SzrxbHnf04sI1bkZYnhra/Pxg9EtX0F/aei5CuHsAXYw3/
         pj9w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AAQBX9e/9Zo4y08pGpuFhEycJ8WoXbdH1qy8FCOsBKqZBEGizQlsZv4O
	14qwdbbUjVh/E3slLsn5IiA=
X-Google-Smtp-Source: AKy350b/JmzPgns10yKCmFwTOMamxMRK9KM0YxZJiaeniOYeLJH1TJML4DUwotsT//eOTIIE4nytSg==
X-Received: by 2002:a17:902:e550:b0:1a2:1674:3902 with SMTP id n16-20020a170902e55000b001a216743902mr1945015plf.10.1680969098695;
        Sat, 08 Apr 2023 08:51:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b084:b0:19c:b3c9:49d5 with SMTP id
 p4-20020a170902b08400b0019cb3c949d5ls24517651plr.6.-pod-prod-gmail; Sat, 08
 Apr 2023 08:51:37 -0700 (PDT)
X-Received: by 2002:a17:90a:d258:b0:246:7582:b76f with SMTP id o24-20020a17090ad25800b002467582b76fmr2703810pjw.0.1680969097458;
        Sat, 08 Apr 2023 08:51:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680969097; cv=none;
        d=google.com; s=arc-20160816;
        b=klAWotAg0/YeBvrr2UfS9gGJ+8MCDnj3HO6QGZwh0tyARfgZ4OeVfpR0Mp0m1SsdXk
         rqX6RDTOYovSptEjgkSQZf33yWknp2KssXRsspXI7v/z/HTUfJnTdkMa3OUdHEdI+d+q
         clJ0L5M7dwKgST6ZnfL6hP8SCYCUdNFCN3eLn4Oem3TfY/jI6W2mn2kcu7ivqpdFCZe3
         bQC5wvX8sA+P/aoP1kkst07LzCvBWyjK2KDUxFh9Sp87Nb4xHxr8rXU3PshSfnrg35SY
         OMrLJZO8WC97Do4TFyDh0a8zJn4AIEczxEKMX1QUd8EFdJ3F3lZEGxCCXyA6p7u+2A2t
         pBbA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :mime-version:dkim-signature;
        bh=xbMqxWkswZ+j8vnTKs/LDwFFKDpT5yB5iqVFJaXrdK0=;
        b=CHV+LacAE+lUvT5gy3WpXAsNAxMs0SIP0l/DthJDlaO0I9HwiHYNS+nb1Ql9lb7i5D
         VI8UstUT4pEt7vkhdCd/CPzLTUZHNjdkct/GXmmVQ905iwfbQkfMO6vNcu4Oq6GzUp/f
         6lVCjdIaEX87aCtuRQMknxzsSntn1eUFr0qczxadGOSOpx++A/Q+IO0dxf4saDJEvsbx
         Yu/Xxk5y6pVJCIULO61uHEZWWN3NeSeaBiI2ex8WPeK2XVjJWSPmLDqt0I2wc3ZyoTan
         xr1qhBBter4eHxGM0qt4iiyfcbIZ9UvSbWAOLcqy9TF414CXa9npWafaWuzZUbWDNgni
         owXA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=f47is1vb;
       spf=pass (google.com: domain of mail.dipanjan.das@gmail.com designates 2001:4860:4864:20::2e as permitted sender) smtp.mailfrom=mail.dipanjan.das@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-oa1-x2e.google.com (mail-oa1-x2e.google.com. [2001:4860:4864:20::2e])
        by gmr-mx.google.com with ESMTPS id pv3-20020a17090b3c8300b0024681ac109asi89513pjb.3.2023.04.08.08.51.37
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 08 Apr 2023 08:51:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of mail.dipanjan.das@gmail.com designates 2001:4860:4864:20::2e as permitted sender) client-ip=2001:4860:4864:20::2e;
Received: by mail-oa1-x2e.google.com with SMTP id 586e51a60fabf-1842d8976d9so1578399fac.9;
        Sat, 08 Apr 2023 08:51:37 -0700 (PDT)
X-Received: by 2002:a05:6870:4184:b0:184:1a2c:83df with SMTP id
 y4-20020a056870418400b001841a2c83dfmr2001463oac.4.1680969096727; Sat, 08 Apr
 2023 08:51:36 -0700 (PDT)
MIME-Version: 1.0
From: Dipanjan Das <mail.dipanjan.das@gmail.com>
Date: Sat, 8 Apr 2023 08:51:26 -0700
Message-ID: <CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com>
Subject: Possible incorrect handling of fault injection inside KMSAN instrumentation
To: Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Cc: syzkaller <syzkaller@googlegroups.com>, 
	Marius Fleischer <fleischermarius@googlemail.com>, 
	Priyanka Bose <its.priyanka.bose@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mail.dipanjan.das@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=f47is1vb;       spf=pass
 (google.com: domain of mail.dipanjan.das@gmail.com designates
 2001:4860:4864:20::2e as permitted sender) smtp.mailfrom=mail.dipanjan.das@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Hi,

We would like to report a =E2=80=9Cpotential=E2=80=9D bug in the KMSAN inst=
rumentation
which has been found during the root-cause analysis of another bug
discovered by our modified version of syzkaller.

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
description: Possible incorrect handling of fault injection inside
KMSAN instrumentation
affected file: mm/kmsan/shadow.c
kernel version: 6.2.0-rc5
kernel commit: 41c66f47061608dc1fd493eebce198f0e74cc2d7
git tree: kmsan
kernel config: https://syzkaller.appspot.com/text?tag=3DKernelConfig&x=3Da9=
a22da1efde3af6.
The config has Fault Injection (FI) turned on, which is important in
this case.
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
We reported the =E2=80=9Csupposed=E2=80=9D bug discovered by our fuzzer her=
e:
https://groups.google.com/u/1/g/syzkaller/c/_83qwErVKlA. Initially, we
presumed that the vzalloc() call (refer to Jiri Slaby=E2=80=99s comment on
that thread) fails due to fault injection (refer to the reproducer
attached). However, we were confused to see that the allocation
failure triggers a crash, though clearly the driver code checks for
allocation failures. Nonetheless, we reported the crash to the
developers. Following Jiri=E2=80=99s comments, who evidently had the same
impression as ours, we started investigating. Below is our
observation.
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
TL;DR:

kmsan's allocation of shadow or origin memory in
kmsan_vmap_pages_range_noflush() fails silently due to fault injection
(FI). KMSAN sort of =E2=80=9Cswallows=E2=80=9D the allocation failure, and =
moves on.
When either of them is later accessed while updating the metadata,
there are no checks to test the validity of the respective pointers,
which results in a page fault.
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
Detail explanation:

- In drivers/tty/n_tty.c:1879 (n_tty_open) , the driver calls vzalloc
to allocate memory for ldata.

- This triggers the KMSAN instrumentation to allocate the
corresponding shadow and origin memory in mm/kmsan/shadow.c:236
(kmsan_vmap_pages_range_noflush) .

- This allocation of the shadow memory fails (through fault
injection). KMSAN checks for failure, frees the allocated memory and
returns. Note: There is no return value signaling the error.
Additionally, the pages for shadow and origin memory are not mapped at
the addresses where KMSAN expects them to be (in fact, there are no
pages that could be mapped at all since the allocation failed).

- The allocation of the actual memory for the driver is successful.
Therefore, vzalloc (from 1.) returns a valid pointer (not NULL).

- After checking that the allocation succeeded
(drivers/tty/n_tty.c:1880), the driver tries to dereference ldata and
write to one of the fields at drivers/tty/n_tty.c:1883 (n_tty_open).

- This triggers the KMSAN instrumentation to update the shadow/origin
memory according to the write by calling
__msan_metadata_ptr_for_store_8  which subsequently calls
mm/kmsan/shadow.c:81 (kmsan_get_shadow_origin_ptr).

- Since the address that the driver is trying to access is with the
vmalloc range, this function will only calculate the offset of this
pointer from the base of the vmalloc range and add this to the base of
the shadow/origin memory range to retrieve the pointer for the
corresponding shadow/origin memory. Note: there are no checks ensuring
that this memory is actually mapped.

- Next, after the return of __msan_metadata_ptr_for_store_8 , the
instrumentation will try to update the shadow memory (or origin, we
are not entirely confident which of the two. We think it is the
shadow, but it also does not really change anything). Since this
memory is not mapped, it leads to the crash.
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D
Our conclusions/Questions:

- Should KMSAN fail silently? Probably not. Otherwise, the
instrumentation always needs to check whether shadow/origin memory
exists.

- Should KMSAN even be tested using fault injection? We are not sure.
On one hand, the primary purpose of FI should be testing the
application code. But also, inducing faults inside instrumentation
clearly helps to find mistakes in that, too.

- What is a fix for this? Should a failure in the KMSAN
instrumentation be propagated up so that the kernel allocator
(vzalloc() in this case) can =E2=80=9Cpretend=E2=80=9D to fail, too?

--=20
Thanks and Regards,

Dipanjan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ%3DcAw%40mail.gmai=
l.com.
