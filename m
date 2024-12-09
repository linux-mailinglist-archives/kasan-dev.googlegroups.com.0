Return-Path: <kasan-dev+bncBAABB2VS3G5AMGQEUCMEJEA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43a.google.com (mail-pf1-x43a.google.com [IPv6:2607:f8b0:4864:20::43a])
	by mail.lfdr.de (Postfix) with ESMTPS id 5594F9E8949
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Dec 2024 03:43:56 +0100 (CET)
Received: by mail-pf1-x43a.google.com with SMTP id d2e1a72fcca58-725c36cdc5csf2177846b3a.0
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Dec 2024 18:43:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1733712234; cv=pass;
        d=google.com; s=arc-20240605;
        b=efiqYKyDBKUnGCS2ACuMTvQiYi3hqjT+yhWobmPxKxmnWpNeDhvvo/3Ag+MkSTpP4D
         Hi7elJhGEg2aTnaD0bAlsundNdhAuzS484X1IUmIYeYVoGIq+5osz3dSekPjYqDOlu6u
         v18Yzluv06t1e6rjPuR2+ctviIWrg3owaa7jNeBVtgdWKDUb//Yl1N/udt3JEWH4OfeD
         vwuA4RC3XI4lScvl8uApGcISHGkc1D5QmK4V468AEfZqh/C1lKwlboHlI8Hdv3ZheNg5
         ZHDWXldNzGEpn3aP0KhZCLaIexBkEpoBWhnCxGVvmlrJxaVSD2N8Vmdt1kwRRp13UnkC
         pR+g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=qe95rK95/C2kdAZe+e3vbOHoOeDipweo4QutyYDqpfU=;
        fh=N+9PrQQECDNMvR6hG5vz41pvJMMqhPoM98Jn76fyK2o=;
        b=ddBX3YP3OP3VPEfsdR3eo+uIBIw8171VVrGAtGyQIeMv0A4tf2QhubWUrqMUKyPhzM
         jjTzcBQcSJHHlKUzvVwySKuoiG35NO2NZ5IxWriRwRIUbd+CvaqEIarw71mJHot8eNXd
         1uLnQUa+VI7jK+eiLsPDxJtTTGNSwuN1nMSGFQErzZsS79Z8bW/i0MUUKugSDtxd6AQ1
         8bExQIaTOHiVyJbncZd60ctuVE0nwTlQjm/RTZJC/vbBAjP6kBEbeJXjMLHKfdd3QWDM
         hqWsGvPowEbnjkqQPsn/eKc/y75Qo+jgjX1JklvgSV0c9FgLL3S1DlZ3VX58V+hCZwbG
         VOdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1733712234; x=1734317034; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=qe95rK95/C2kdAZe+e3vbOHoOeDipweo4QutyYDqpfU=;
        b=ZukmQ3oaQzhS94dY+ynb/2s+rXgGRYLbuhUWAm/1bBiM1W/vIpWtw5eaSCmjuWcES1
         bkexmdZAqbacj4oZ0N7O9xI6u01kc66nj7IdL6fzmVbGTgn9lzTV9OGkn+4pa6uBShE7
         ivREJcAZ21QMCCkIz1iCoJipiw2MEB6NJgN5ATGRucJvcA3XvWRVZ3HuzfQszdSsPYtV
         ngFs2zdiKeXWKu84tsFI0ecOqfZE9JWWuE+4z+43jno5ExfD4lLDgrWdiR+73ieF0cLO
         B7wmmu3qkwcjoVz/wmrHs/1B1f+31LjwXfxz+bz9sJ9+oVU+pJCECSmUhx7Y874Afkrt
         CPEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1733712234; x=1734317034;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=qe95rK95/C2kdAZe+e3vbOHoOeDipweo4QutyYDqpfU=;
        b=F91pVgyPop16sKCn9XPkep9rMXC130umDUGx3jHWHTU8nwnu+8A4LezmEQFiO++/7X
         VeFta22QPndJzLnyyIvGlBlw8ckckLX8/sPITtvtVCVmxIwSm74C2/42sZKrfLq+qtDw
         53QrVqzlnG1V6n6IszC5DR7Ih4hKP9NdgCszXkUrnSeC3KWY3Z8b3qwN+5jFLIDei27o
         +IMqFMEkktnjhix4/nTuyL6E/OVpSoqYoxHSIG1oYwVHL+iyfXJy7lZi036IXh7ij+xY
         DpfX+EwfC8j0XZO9zt9bdtWhD5ZK6YwzV4CIvuSyTSde0zqnPY+MHLxTCeDinwzwDTv8
         Hjtg==
X-Forwarded-Encrypted: i=2; AJvYcCW1cNKfZgqgugmfNw5FlQCVJ37fqhgAX1gEny0Ko5+2kVDKVRiCG02gfSY5AGxYNRnBStxRZQ==@lfdr.de
X-Gm-Message-State: AOJu0YzgTi+BGcLyqrUKVUbM4HihM3g6KeR+ArViqpuuW/eVDEVpGOX8
	R2SsGfa43/lDukQ/93C2TjM1UvRnr/mJox+zMhr7t/wlONOenasj
X-Google-Smtp-Source: AGHT+IFyb7fnXPCbcF9Ixntj12fabwTPsbo5xjlJ86Shai3FM60SJQQavp5SEtDnVAX3aoyWyxYDLA==
X-Received: by 2002:a05:6a00:148d:b0:71e:722b:ae1d with SMTP id d2e1a72fcca58-725b81be3fdmr15856167b3a.25.1733712234274;
        Sun, 08 Dec 2024 18:43:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1814:b0:725:9248:d60e with SMTP id
 d2e1a72fcca58-7259d61c8ecls2217203b3a.0.-pod-prod-07-us; Sun, 08 Dec 2024
 18:43:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW/PHnRdW4uM2PRIFPL2/Tt3Whe0ZCplzFo0QUFvhFLsoRwi05Gz9gQb34xNFGwqGWQItSHI/3TlCM=@googlegroups.com
X-Received: by 2002:a05:6a00:148d:b0:71e:722b:ae1d with SMTP id d2e1a72fcca58-725b81be3fdmr15856112b3a.25.1733712233109;
        Sun, 08 Dec 2024 18:43:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1733712233; cv=none;
        d=google.com; s=arc-20240605;
        b=U8Mrb6kYwZP8QIvRndc170YNB+hK8b2htO6ATc68IVZUKwSTnIzKzTQyf4MDuROcLb
         gZWnNG8yRkWlaJcLQvHWi0Y1U6dj9p1tnWsEreAflgKAcuZcnd34w9Fi5QmYZlP5BDrv
         7QWDGlwzi5IrcNyqtYgGTjUoeabau5l9KvCOm4QnpyEcNilbJOMUlYt5TScxtlPUdGS0
         fPI41t4Qqge780Ajk0V4RbJVO3zeg6YE+MpnPQXMiE4tKV4RnYDU00YQJewlS07sEekX
         nsUfooMJjLI7KANUnAZ9oKJd5Sghm0h7x8IAztG6mcJKZ0PBh9KtAgcSklJuJ5u87WaV
         i7lg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=20OY5Wca9v29+l5BtvCY5fuiV4sFMquFAGouScos9WA=;
        fh=zBWha3m7j9g4fOlI2Dk54gN6qyAThRjo4Lp4VAY4w1U=;
        b=AJf/lbUelv/PwHfY2Pp4jQub9aQif2J7sERWPWUlHc8FwnNhKKcXYxxkH1NpMjT5nA
         kyy+3qiQAbXQSDzOI4YN4IEDRoUMaUfwUa7H9OMV9K2k186r/F8xtRfBeKIJ9mhOvFI6
         4dnKnNIvtDtBMF9pGGlKNv0YOHc5qRqSpvoN8T62zgMIi7DGqzNv++xvJm1X6bmrUXVc
         iImfhgPv+XT+8BkFbHwdaJjVUX0oLManun2/p2kqSeC/QI+pfkoZHfXXnARC3cRq6q1u
         TqesCMySrxHAgNrOB9WCtm6h0e1t/0sjrstkoniz321jjydb4fI8sCfhamBVvcF5oh7t
         FYqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga04-in.huawei.com (szxga04-in.huawei.com. [45.249.212.190])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-7fd4275e39fsi131231a12.3.2024.12.08.18.43.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Dec 2024 18:43:53 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as permitted sender) client-ip=45.249.212.190;
Received: from mail.maildlp.com (unknown [172.19.88.214])
	by szxga04-in.huawei.com (SkyGuard) with ESMTP id 4Y65hS4kNBz2DhQD;
	Mon,  9 Dec 2024 10:40:56 +0800 (CST)
Received: from kwepemk500005.china.huawei.com (unknown [7.202.194.90])
	by mail.maildlp.com (Postfix) with ESMTPS id 732081A016C;
	Mon,  9 Dec 2024 10:43:19 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemk500005.china.huawei.com (7.202.194.90) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.11; Mon, 9 Dec 2024 10:43:17 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Mark Rutland <mark.rutland@arm.com>, Jonathan Cameron
	<Jonathan.Cameron@Huawei.com>, Mauro Carvalho Chehab
	<mchehab+huawei@kernel.org>, Catalin Marinas <catalin.marinas@arm.com>, Will
 Deacon <will@kernel.org>, Andrew Morton <akpm@linux-foundation.org>, James
 Morse <james.morse@arm.com>, Robin Murphy <robin.murphy@arm.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Andrey Ryabinin
	<ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Christophe
 Leroy <christophe.leroy@csgroup.eu>, Aneesh Kumar K.V
	<aneesh.kumar@kernel.org>, "Naveen N. Rao" <naveen.n.rao@linux.ibm.com>,
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
	Borislav Petkov <bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>,
	<x86@kernel.org>, "H. Peter Anvin" <hpa@zytor.com>, Madhavan Srinivasan
	<maddy@linux.ibm.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v13 0/5]arm64: add ARCH_HAS_COPY_MC support
Date: Mon, 9 Dec 2024 10:42:52 +0800
Message-ID: <20241209024257.3618492-1-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 kwepemk500005.china.huawei.com (7.202.194.90)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.190 as
 permitted sender) smtp.mailfrom=tongtiangen@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Tong Tiangen <tongtiangen@huawei.com>
Reply-To: Tong Tiangen <tongtiangen@huawei.com>
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

Problem
=3D=3D=3D=3D=3D=3D=3D=3D=3D
With the increase of memory capacity and density, the probability of memory
error also increases. The increasing size and density of server RAM in data
centers and clouds have shown increased uncorrectable memory errors.

Currently, more and more scenarios that can tolerate memory errors=EF=BC=8C=
such as
COW[1,2], KSM copy[3], coredump copy[4], khugepaged[5,6], uaccess copy[7],
etc.

Solution
=3D=3D=3D=3D=3D=3D=3D=3D=3D

This patchset introduces a new processing framework on ARM64, which enables
ARM64 to support error recovery in the above scenarios, and more scenarios
can be expanded based on this in the future.

In arm64, memory error handling in do_sea(), which is divided into two case=
s:
 1. If the user state consumed the memory errors, the solution is to kill
    the user process and isolate the error page.
 2. If the kernel state consumed the memory errors, the solution is to
    panic.

For case 2, Undifferentiated panic may not be the optimal choice, as it can
be handled better. In some scenarios, we can avoid panic, such as uaccess,
if the uaccess fails due to memory error, only the user process will be
affected, killing the user process and isolating the user page with
hardware memory errors is a better choice.

[1] commit d302c2398ba2 ("mm, hwpoison: when copy-on-write hits poison, tak=
e page offline")
[2] commit 1cb9dc4b475c ("mm: hwpoison: support recovery from HugePage copy=
-on-write faults")
[3] commit 6b970599e807 ("mm: hwpoison: support recovery from ksm_might_nee=
d_to_copy()")
[4] commit 245f09226893 ("mm: hwpoison: coredump: support recovery from dum=
p_user_range()")
[5] commit 98c76c9f1ef7 ("mm/khugepaged: recover from poisoned anonymous me=
mory")
[6] commit 12904d953364 ("mm/khugepaged: recover from poisoned file-backed =
memory")
[7] commit 278b917f8cb9 ("x86/mce: Add _ASM_EXTABLE_CPY for copy user acces=
s")

------------------
Test result:

1. copy_page(), copy_mc_page() basic function test pass, and the disassembl=
y
   contents remains the same before and after refactor.

2. copy_to/from_user() access kernel NULL pointer raise translation fault
   and dump error message then die(), test pass.

3. Test following scenarios: copy_from_user(), get_user(), COW.

   Before patched: trigger a hardware memory error then panic.
   After  patched: trigger a hardware memory error without panic.

   Testing step:
   step1. start an user-process.
   step2. poison(einj) the user-process's page.
   step3: user-process access the poison page in kernel mode, then trigger =
SEA.
   step4: the kernel will not panic, only the user process is killed, the p=
oison
          page is isolated. (before patched, the kernel will panic in do_se=
a())

------------------

Benefits
=3D=3D=3D=3D=3D=3D=3D=3D=3D
According to the statistics of our storage product, the memory errors trigg=
ered
in kernel-mode by COW and page cache read (uaccess) scenarios account for m=
ore
than 50%, with this patchset deployed, all the kernel panic caused by COW a=
nd
page cache memory errors are eliminated, in addition, other scenarios that
account for a small proportion will also benefit.

Since v12:
Thanks to the suggestions of Jonathan, Mark, and Mauro, the following modif=
ications
are made:
1. Rebase to latest kernel version.
2. Patch1, add Jonathan's and Mauro's review-by.
3. Patch2, modified do_apei_claim_sea() according to Mark's and Jonathan's =
suggestions,
   and optimized the commit message according to Mark's suggestions(Added d=
escription of
   the impact on regular copy_to_user()).
4. Patch3, optimized the commit message according to Mauro's suggestions an=
d add Jonathan's
   review-by.
5. Patch4, modified copy_mc_user_highpage() and Optimized the commit messag=
e according to
   Jonathan's suggestions(no functional changes).
6. Patch5, optimized the commit message according to Mauro's suggestions.
7. Patch4/5, FEAT_MOPS is added to the code logic. Currently, the fixup is =
not performed
   on the MOPS instruction.=20
8. Remove patch6 in v12 according to Jonathan's suggestions.

Since v11:
1. Rebase to latest kernel version 6.9-rc1.
2. Add patch 5, Since the problem described in "Since V10 Besides 3" has
   been solved in a50026bdb867 ('iov_iter: get rid of 'copy_mc' flag').
3. Add the benefit of applying the patch set to our company to the descript=
ion of patch0.

Since V10:
 Accroding Mark's suggestion:
 1. Merge V10's patch2 and patch3 to V11's patch2.
 2. Patch2(V11): use new fixup_type for ld* in copy_to_user(), fix fatal
    issues (NULL kernel pointeraccess) been fixup incorrectly.
 3. Patch2(V11): refactoring the logic of do_sea().
 4. Patch4(V11): Remove duplicate assembly logic and remove do_mte().

 Besides:
 1. Patch2(V11): remove st* insn's fixup, st* generally not trigger memory =
error.
 2. Split a part of the logic of patch2(V11) to patch5(V11), for detail,
    see patch5(V11)'s commit msg.
 3. Remove patch6(v10) =E2=80=9Carm64: introduce copy_mc_to_kernel() implem=
entation=E2=80=9D.
    During modification, some problems that cannot be solved in a short
    period are found. The patch will be released after the problems are
    solved.
 4. Add test result in this patch.
 5. Modify patchset title, do not use machine check and remove "-next".

Since V9:
 1. Rebase to latest kernel version 6.8-rc2.
 2. Add patch 6/6 to support copy_mc_to_kernel().

Since V8:
 1. Rebase to latest kernel version and fix topo in some of the patches.
 2. According to the suggestion of Catalin, I attempted to modify the
    return value of function copy_mc_[user]_highpage() to bytes not copied.
    During the modification process, I found that it would be more
    reasonable to return -EFAULT when copy error occurs (referring to the
    newly added patch 4).=20

    For ARM64, the implementation of copy_mc_[user]_highpage() needs to
    consider MTE. Considering the scenario where data copying is successful
    but the MTE tag copying fails, it is also not reasonable to return
    bytes not copied.
 3. Considering the recent addition of machine check safe support for
    multiple scenarios, modify commit message for patch 5 (patch 4 for V8).

Since V7:
 Currently, there are patches supporting recover from poison
 consumption for the cow scenario[1]. Therefore, Supporting cow
 scenario under the arm64 architecture only needs to modify the relevant
 code under the arch/.
 [1]https://lore.kernel.org/lkml/20221031201029.102123-1-tony.luck@intel.co=
m/

Since V6:
 Resend patches that are not merged into the mainline in V6.

Since V5:
 1. Add patch2/3 to add uaccess assembly helpers.
 2. Optimize the implementation logic of arm64_do_kernel_sea() in patch8.
 3. Remove kernel access fixup in patch9.
 All suggestion are from Mark.=20

Since V4:
 1. According Michael's suggestion, add patch5.
 2. According Mark's suggestiog, do some restructuring to arm64
 extable, then a new adaptation of machine check safe support is made based
 on this.
 3. According Mark's suggestion, support machine check safe in do_mte() in
 cow scene.
 4. In V4, two patches have been merged into -next, so V5 not send these
 two patches.

Since V3:
 1. According to Robin's suggestion, direct modify user_ldst and
 user_ldp in asm-uaccess.h and modify mte.S.
 2. Add new macro USER_MC in asm-uaccess.h, used in copy_from_user.S
 and copy_to_user.S.
 3. According to Robin's suggestion, using micro in copy_page_mc.S to
 simplify code.
 4. According to KeFeng's suggestion, modify powerpc code in patch1.
 5. According to KeFeng's suggestion, modify mm/extable.c and some code
 optimization.

Since V2:
 1. According to Mark's suggestion, all uaccess can be recovered due to
    memory error.
 2. Scenario pagecache reading is also supported as part of uaccess
    (copy_to_user()) and duplication code problem is also solved.=20
    Thanks for Robin's suggestion.
 3. According Mark's suggestion, update commit message of patch 2/5.
 4. According Borisllav's suggestion, update commit message of patch 1/5.

Since V1:
 1.Consistent with PPC/x86, Using CONFIG_ARCH_HAS_COPY_MC instead of
   ARM64_UCE_KERNEL_RECOVERY.
 2.Add two new scenes, cow and pagecache reading.
 3.Fix two small bug(the first two patch).

V1 in here:
https://lore.kernel.org/lkml/20220323033705.3966643-1-tongtiangen@huawei.co=
m/

Tong Tiangen (5):
  uaccess: add generic fallback version of copy_mc_to_user()
  arm64: add support for ARCH_HAS_COPY_MC
  mm/hwpoison: return -EFAULT when copy fail in
    copy_mc_[user]_highpage()
  arm64: support copy_mc_[user]_highpage()
  arm64: introduce copy_mc_to_kernel() implementation

 arch/arm64/Kconfig                   |  1 +
 arch/arm64/include/asm/asm-extable.h | 31 +++++++--
 arch/arm64/include/asm/asm-uaccess.h |  4 ++
 arch/arm64/include/asm/extable.h     |  1 +
 arch/arm64/include/asm/mte.h         |  9 +++
 arch/arm64/include/asm/page.h        | 10 +++
 arch/arm64/include/asm/string.h      |  5 ++
 arch/arm64/include/asm/uaccess.h     | 18 +++++
 arch/arm64/lib/Makefile              |  2 +
 arch/arm64/lib/copy_mc_page.S        | 37 +++++++++++
 arch/arm64/lib/copy_page.S           | 62 ++----------------
 arch/arm64/lib/copy_page_template.S  | 70 ++++++++++++++++++++
 arch/arm64/lib/copy_to_user.S        | 10 +--
 arch/arm64/lib/memcpy_mc.S           | 98 ++++++++++++++++++++++++++++
 arch/arm64/lib/mte.S                 | 29 ++++++++
 arch/arm64/mm/copypage.c             | 75 +++++++++++++++++++++
 arch/arm64/mm/extable.c              | 19 ++++++
 arch/arm64/mm/fault.c                | 30 ++++++---
 arch/powerpc/include/asm/uaccess.h   |  1 +
 arch/x86/include/asm/uaccess.h       |  1 +
 include/linux/highmem.h              | 16 +++--
 include/linux/uaccess.h              |  8 +++
 mm/kasan/shadow.c                    | 12 ++++
 mm/khugepaged.c                      |  4 +-
 24 files changed, 472 insertions(+), 81 deletions(-)
 create mode 100644 arch/arm64/lib/copy_mc_page.S
 create mode 100644 arch/arm64/lib/copy_page_template.S
 create mode 100644 arch/arm64/lib/memcpy_mc.S

--=20
2.25.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2=
0241209024257.3618492-1-tongtiangen%40huawei.com.
