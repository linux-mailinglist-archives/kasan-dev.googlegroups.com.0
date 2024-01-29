Return-Path: <kasan-dev+bncBAABBVGY32WQMGQEWZ47GQI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F72B84074E
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 14:47:01 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-42a9d572204sf482121cf.0
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Jan 2024 05:47:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706536020; cv=pass;
        d=google.com; s=arc-20160816;
        b=TqAAdn4G13upCD/1cwcn9011VgqSfhYXOv5KbDB/jtLTWkyyl8YiswrAga/qPMkgsQ
         FNYgGvKirJcLY1uvh2rcH22LEvNVuCynguf9orrZJtJqHMpMu8SN74cYL8vdLufIihBS
         syy8YFReojYmC+udeoasqd1j5WTn/es45SjOPfVJq6Th2tfhc9yRyKneu7KBRDxKO/SR
         FKrH8EL1StZDm19ibKNGmGBNqQVA1pV0rUOkJcu8VcW+WNv2JsvwmI0A+3nXQq/wr4Gd
         k5We/rEYQJ7AONs5mOyvPyBYorqEvQ1mQrwF4rrj+4d4rxwNAW2UMYK332xjHGdUCbmy
         Asnw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :mime-version:message-id:date:subject:cc:to:from:dkim-signature;
        bh=vtPOZA/aUhvsxgPkH5khQdfinnr5mTm/lBgezJ5m/70=;
        fh=6GjCATS3Av3R5n22cmUNjR8BqFdQaYql1tTTlSbWUeM=;
        b=HrWC03ifA5/tyia25w6Z6ZFXi93xK307b2GSX1VHVsbKCWtY6H5wLn9MxuE7ZRwrAJ
         EeHTRizrhn5OYDzGID8AjUHYJ1u2FsH7M6pWXNEn8mb8fy/BlRE3bsipcHZyUO9Ufvgf
         he66gBoICvgipO4II1BUYcZk8NbxPGCC5eG2XYdsTvom+VbNAyooQFdGRQjbbdFi3u8l
         24kS0At51oDFegOP6t8qdqOBo77GEGIeqMvZ63+NmfKTzlY1IRI9s+klqDp5pEy9VCLp
         QM/RB/oAEnCoSIcvq7jZDlG9lQDbAhD+9CZzjbVFZzV4yxP9JWiw6q/MUcBDroX9lmPt
         E6Gg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706536020; x=1707140820; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=vtPOZA/aUhvsxgPkH5khQdfinnr5mTm/lBgezJ5m/70=;
        b=CsTnE+12yx7jVUoBtDc/4RfLhLEMrnNlTmmfD/HrUvAvghCetkd1aVCZhBldt33ca0
         LPs9wymDA+rpLeg2iYyxcSDJrABz3bTNaZLiCgGbYwpaxiMANZUppVzyryRefK3OOfPC
         N57JF0enGS02OY/X+bAosIYiyps4TyqtnVad3obIzckhdY6oJjdP3wpWqdOIgk/iMS8O
         kdiiqrRWXcMhoeAdMO+w1omf1ASa+5xmQ+dXFRmIRBldy6kBGSEfAraSQ+2J43zWPKug
         zc/UyWDbbLHO+UQhH6IBHVgJkCP+WqFWYyy8NFHRiBnoXvCYaBxONZ8VeZ0jHVoNJYnY
         6brg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706536020; x=1707140820;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vtPOZA/aUhvsxgPkH5khQdfinnr5mTm/lBgezJ5m/70=;
        b=VedZsLe42jxrpcgZ0+LVsgzj9/pP3ipy/mblZC+KjUBMI4TPObf6YEH/w5ZP3uOnSB
         L3RB6OrXyX1J/pzWxtucCFEd958VcuzJz5LW9XpmT5JiTEBuGUabPRsBB/dE4XKwWAt1
         WyW/6zPpWL0R+8j7MB0Hc24JTizCs2WlYy/bbOQHtoNvQ1013Xl9R7wGCjKb79htHsSE
         6o5xomzBZrs/k/lw2cmNeE+f+l2ZFDpezFiWZ20UUJfIyYpDLwaJmCY3Bq8onbsNSVCp
         3NeyrxncBHx21U8PWQV+mdQ9cNXg0PyttsU8MUfdqJT8Zl6X7ABcU62IhIeXHzltsifd
         ZLkw==
X-Gm-Message-State: AOJu0Yx9Pt4MhzIMOZ2OrhhpYBBOtHtRSAYMZc7RjKzSR1ziBRbe27Ph
	v9KoeNwSCfhEisOK7Sf6tQbih3NzgGxaYZM3MVK3kRWji098w2Bf
X-Google-Smtp-Source: AGHT+IHJQVMbBIPqaO0KDz7LANww0mW7HwsaaTCa7CXixxG3gmK+dYLdDRZSxma7SeymCJbZJ3v/PA==
X-Received: by 2002:a05:622a:1c0b:b0:42a:b00a:da7b with SMTP id bq11-20020a05622a1c0b00b0042ab00ada7bmr28570qtb.8.1706536020142;
        Mon, 29 Jan 2024 05:47:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2486:b0:68c:45f7:b89e with SMTP id
 gi6-20020a056214248600b0068c45f7b89els3393650qvb.2.-pod-prod-08-us; Mon, 29
 Jan 2024 05:46:59 -0800 (PST)
X-Received: by 2002:a1f:f44f:0:b0:4bd:1677:9458 with SMTP id s76-20020a1ff44f000000b004bd16779458mr1031496vkh.32.1706536019505;
        Mon, 29 Jan 2024 05:46:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706536019; cv=none;
        d=google.com; s=arc-20160816;
        b=QBsvaR0aZ78HFr3POWAHtkVFcq5vduCTqP02p6TwNACR3ak8boRGp34mE9BsfwcNyU
         mpuXPvbHRwQwlb7H8qQHakGAvJ4Oyv4CeBXzAHxIrsHsEY0QJ/DvALmSOVK5uf1APpjk
         eogcTzU+AY2246BYn8uuikIzbl13sYsPWQdSC40E7fZkLNbtsBVMmXb9ADNI55Hpgw8r
         iY6g18Marga+UAy9yGHgGiQqD8/MVNvrAM9q6oFih1gu7fi3QakP4dWid7UKEm/IGT2w
         2sFi51dqqujte4FEgXMxpKjA85qsBEtAXXUVMxH7Dp+ur/6de3R6fFB4M4RCVxS2/iW/
         xwsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=y/3o5nZg1DX5U/JlCqiqLwRlXv2UIiSBkhikFVhybmk=;
        fh=6GjCATS3Av3R5n22cmUNjR8BqFdQaYql1tTTlSbWUeM=;
        b=DNvRE6l2qoOHdZYmYQaWe/eGcUAW/hfAOKHaBRg80lLpH8aCfeNnDOPIgxVVlvB3rF
         dNYP/Kc9LU31+MQ5l6BX4/JLwuDdxEIdkCgkNl1XSt7p7JP9tsHsHae2rsFoXavlFrKq
         Gh4nBZJmbIGgzxzfx/mgZBMDdf0r5m1Mn6T/3Iy6q0C3cmdhzWXvLxAUSg9w7kgK0wnk
         Cslf1S6u/F+RpyHdlCvFUVPYAWW7+PVXvRk2uB3BxXS02ElRjaPBIeUzUNNe3Cybw9PY
         lSdtdvU246xVbrhqnDD3eObDUjwhh9rxJFPRQozc0SkqzSXI16AmNu9cwCT1dfdKwoue
         rXfw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as permitted sender) smtp.mailfrom=tongtiangen@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Forwarded-Encrypted: i=0; AJvYcCVPVHPT/iNWwlnHqk6I/JfsbME0jh0d9gKk+m/GAAQRjraWcw1w4Dgg1IWCXSYQyMjyBq2Nox2t5VDZcCNtqdVIoqZY4Ly4BPAzNQ==
Received: from szxga07-in.huawei.com (szxga07-in.huawei.com. [45.249.212.35])
        by gmr-mx.google.com with ESMTPS id z6-20020a056122104600b004b6cfa3a59esi427963vkn.5.2024.01.29.05.46.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 29 Jan 2024 05:46:59 -0800 (PST)
Received-SPF: pass (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as permitted sender) client-ip=45.249.212.35;
Received: from mail.maildlp.com (unknown [172.19.88.214])
	by szxga07-in.huawei.com (SkyGuard) with ESMTP id 4TNqLC0Jb8z1Q89j;
	Mon, 29 Jan 2024 21:45:07 +0800 (CST)
Received: from kwepemm600017.china.huawei.com (unknown [7.193.23.234])
	by mail.maildlp.com (Postfix) with ESMTPS id 26EE01A016B;
	Mon, 29 Jan 2024 21:46:56 +0800 (CST)
Received: from localhost.localdomain (10.175.112.125) by
 kwepemm600017.china.huawei.com (7.193.23.234) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2507.35; Mon, 29 Jan 2024 21:46:54 +0800
From: "'Tong Tiangen' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>, James Morse <james.morse@arm.com>, Robin
 Murphy <robin.murphy@arm.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>, Alexander Viro
	<viro@zeniv.linux.org.uk>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry
 Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>, Michael Ellerman
	<mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Christophe Leroy
	<christophe.leroy@csgroup.eu>, Aneesh Kumar K.V <aneesh.kumar@kernel.org>,
	"Naveen N. Rao" <naveen.n.rao@linux.ibm.com>, Thomas Gleixner
	<tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov
	<bp@alien8.de>, Dave Hansen <dave.hansen@linux.intel.com>, <x86@kernel.org>,
	"H. Peter Anvin" <hpa@zytor.com>
CC: <linux-arm-kernel@lists.infradead.org>, <linux-mm@kvack.org>,
	<linuxppc-dev@lists.ozlabs.org>, <linux-kernel@vger.kernel.org>,
	<kasan-dev@googlegroups.com>, Tong Tiangen <tongtiangen@huawei.com>,
	<wangkefeng.wang@huawei.com>, Guohanjun <guohanjun@huawei.com>
Subject: [PATCH v10 0/6]arm64: add machine check safe support
Date: Mon, 29 Jan 2024 21:46:46 +0800
Message-ID: <20240129134652.4004931-1-tongtiangen@huawei.com>
X-Mailer: git-send-email 2.25.1
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Originating-IP: [10.175.112.125]
X-ClientProxiedBy: dggems701-chm.china.huawei.com (10.3.19.178) To
 kwepemm600017.china.huawei.com (7.193.23.234)
X-Original-Sender: tongtiangen@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of tongtiangen@huawei.com designates 45.249.212.35 as
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

With the increase of memory capacity and density, the probability of memory
error also increases. The increasing size and density of server RAM in data
centers and clouds have shown increased uncorrectable memory errors.

Currently, more and more scenarios that can tolerate memory errors=EF=BC=8C=
such as
CoW[1,2], KSM copy[3], coredump copy[4], khugepaged[5,6], uaccess copy[7],
etc.

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

Tong Tiangen (6):
  uaccess: add generic fallback version of copy_mc_to_user()
  arm64: add support for machine check error safe
  arm64: add uaccess to machine check safe
  mm/hwpoison: return -EFAULT when copy fail in
    copy_mc_[user]_highpage()
  arm64: support copy_mc_[user]_highpage()
  arm64: introduce copy_mc_to_kernel() implementation

 arch/arm64/Kconfig                   |   1 +
 arch/arm64/include/asm/asm-extable.h |  15 ++
 arch/arm64/include/asm/assembler.h   |   4 +
 arch/arm64/include/asm/extable.h     |   1 +
 arch/arm64/include/asm/mte.h         |   5 +
 arch/arm64/include/asm/page.h        |  10 ++
 arch/arm64/include/asm/string.h      |   5 +
 arch/arm64/include/asm/uaccess.h     |  21 +++
 arch/arm64/lib/Makefile              |   4 +-
 arch/arm64/lib/copy_from_user.S      |  10 +-
 arch/arm64/lib/copy_mc_page.S        |  78 ++++++++
 arch/arm64/lib/copy_to_user.S        |  10 +-
 arch/arm64/lib/memcpy_mc.S           | 257 +++++++++++++++++++++++++++
 arch/arm64/lib/mte.S                 |  27 +++
 arch/arm64/mm/copypage.c             |  66 ++++++-
 arch/arm64/mm/extable.c              |  21 ++-
 arch/arm64/mm/fault.c                |  29 ++-
 arch/powerpc/include/asm/uaccess.h   |   1 +
 arch/x86/include/asm/uaccess.h       |   1 +
 include/linux/highmem.h              |  16 +-
 include/linux/uaccess.h              |   9 +
 mm/kasan/shadow.c                    |  12 ++
 mm/khugepaged.c                      |   4 +-
 23 files changed, 581 insertions(+), 26 deletions(-)
 create mode 100644 arch/arm64/lib/copy_mc_page.S
 create mode 100644 arch/arm64/lib/memcpy_mc.S

--=20
2.25.1

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20240129134652.4004931-1-tongtiangen%40huawei.com.
