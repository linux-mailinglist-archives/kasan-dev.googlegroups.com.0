Return-Path: <kasan-dev+bncBDFJHU6GRMBBBEOD36KQMGQECBNLWLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F7D555AEDA
	for <lists+kasan-dev@lfdr.de>; Sun, 26 Jun 2022 06:33:22 +0200 (CEST)
Received: by mail-lf1-x137.google.com with SMTP id q22-20020a0565123a9600b0047f6b8e1babsf3229885lfu.21
        for <lists+kasan-dev@lfdr.de>; Sat, 25 Jun 2022 21:33:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656218001; cv=pass;
        d=google.com; s=arc-20160816;
        b=mtE/J/v86Q8htH5JwigIzQApXHMt6zH1kvG+kafK8WpoFweAagE7r96TSPE/uPNLAs
         xTFV4QXm3hvlcqZWLpHgJQUZdUhtF1Lpoq9kEuXTnsPBsUKdrtQfd2YTFRwtlmWCbrqj
         EsN3u1FYQh/27nneIWjM/w60z+GFXA40/41N2dHxU77uvsZwbesagutUt57qKHVdZFpr
         B+VaXFMkLSLl8fCtAD+eUjVm85BkdiO8SKvMaTOztrckBST62Qt3/iexj8eVnXPvLRJP
         7wGkmMCUNw+FAYoo1zWn+0wpJrEziGhGUAmKK/fHFLx60VcsjofTGmzRa2806FJ4fBy/
         gbNQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=utXmqNxoFVEV/qW3a6HMWuo83Ni8V/ueLwozNsY/Xd8=;
        b=J1zl5Y9CmFhr7f51vz3RtGYEh9Jdk23J0xc05HQY0XzXfn/Fy9bNkjmteCvW93ab0x
         wpHnITcm5tKpnLbhXETDQBWMtwI2WryOClsR70jh8L2PQggikfO37Q42kKCRvurdugz0
         yjyqzsT0GNbtvlGB3f5P3NGqQ+MCPhRzvreF5ECIuktZCyWL65MTfLBel70JBF49iANZ
         6iXIu5dukI21t/Cq3KQDo0vthVAU5Ns/Fl4I47EmmvaL7x5tIElE2gVETeOtobaRUAim
         /6foNdpba82uY8pvjj3keXOfd+R5/x8xDcxyGY2Wg5YIZ831oUqj4qfX7j844h6FC6gt
         3G/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=FrZZoDyu;
       spf=neutral (google.com: 2a00:1450:4864:20::336 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=utXmqNxoFVEV/qW3a6HMWuo83Ni8V/ueLwozNsY/Xd8=;
        b=CVRPyxWlu1KeHFp8n/xnskYD/qU8m8MbqE+58ligvSnB3lAZi01DT4BI7MMoxsAPG/
         qY4OJIVuxTSDqq542tr9P+b6k90N7K5h91wj3CLPoU3tqUuv6Sp9T1d4S0dF06jyxcRx
         RRqNCbP3QevQraTGOsgDQoW7n3SLYjV7nbmujn+YhUfifHwZ1UoyUafjL4hIaIUNnWPO
         mhXtmaCftnAdxAyfhNjRHqc9IOC7FJy27oGugN5aYqb7EUKBX6RayoL5oG1dR/nZ7lYe
         rpO6pRO17luZ2cD6HlX3BVc6lxNEt0WMXkOABXbsNyOKgL60ZhE3yAgolEz71euSOlXy
         pOzg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=utXmqNxoFVEV/qW3a6HMWuo83Ni8V/ueLwozNsY/Xd8=;
        b=G/X24qJIS1N4UfGqHuQ8uqSKi0qJdCTOWDQBGS2foCVtdS+5V544PyCnXu05or4YQh
         PkmDODn8UJsq9dv8DMrQO39FZh3rnjuVIGzQIwOkt1OwMJz1K6wgSWVKloTF1HCRmHZ2
         +j/fWygUpnDiG5MEuBwcZnGWEjDGDbMOsQbcHVKFrCX49/Nq2+cnGcDHVUGhqX+1RffI
         D7ktTzB6bmjAFYtREu1aehvA+og1MIwdau5YsvhYtiPGbQD3/CYKzpHyMBYrpoqiEytP
         c5W31yJDQGpT7SeTRGfgcVyAPDSDtAgbFZtztUNhyCtO2O5noX6FAnl3PirPqXX8dbv2
         whhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9k1jeI/nz1d4OP838I5W3XMGK2KDqEMQKGvQA19qhF0HrDJs3I
	2VfpH+CNZIBIBIC1RL8RVf8=
X-Google-Smtp-Source: AGRyM1sy/P/FRXRU2/cBn9HrReMwhfeFrHxoN9iiyPx9FIWeycX3Xz5giRuyUqGlgbKOac6L7f98xA==
X-Received: by 2002:a2e:8754:0:b0:25a:9b99:328f with SMTP id q20-20020a2e8754000000b0025a9b99328fmr3602400ljj.396.1656218001485;
        Sat, 25 Jun 2022 21:33:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:98c5:0:b0:255:9299:b0e1 with SMTP id s5-20020a2e98c5000000b002559299b0e1ls4251600ljj.5.gmail;
 Sat, 25 Jun 2022 21:33:20 -0700 (PDT)
X-Received: by 2002:a05:651c:1721:b0:25a:737d:4cb0 with SMTP id be33-20020a05651c172100b0025a737d4cb0mr3291151ljb.175.1656218000201;
        Sat, 25 Jun 2022 21:33:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656218000; cv=none;
        d=google.com; s=arc-20160816;
        b=EIYEWSTcbXJy+eQoJr5eKRjJLM8/I5ngNf//e0e1VU1OoGYRsvv741IFsAldtGOm9n
         T8kbaQHMv8I4/XO6ES832zMSLJv3Tp3uq2Ois4iQfIghx4SVKRuRNmkxWl8JKmrP4Bk/
         gMCVw/kgmIDC/EMe5rHoPeflHYEU/KOh6d8RNGeH/OZiypWfe9MWOfrb6oFpBlT4HDTU
         YoQhiD8LcQQK7TNMK73AXNREIxRn9Zb+sniyt9iCLTiWoY/IDyovBAeRLcu8etsa/K1h
         BFMYZtBeGpQnRWm8xv5rKME7w1HIrdngBnEid6Z3gLLFZA9dQQNkO7xMyOP762gu1Jog
         kifQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2kWtI1K8FBljQi8An/wyVTdiQqFYwSP32gsF9BQJ03c=;
        b=OyUNeB/8jdrqSu3surkpo60lz3wknkD4U3C4dQkSHIGK7KqECQbz8iJrXdBES+4t3U
         CeIW3eb+zQXF3wM5zrfpzKIaMRTU2VpRwOaTUrgQZxFvcd99NJd35l7DQXfQI7kUd/Ut
         rz4cWK3W4lRoVhq3q6GNu6TZRj9v2rcGy/yKUbE5oT7FPbMj5ALcU7uXeoeKqQbplE33
         h96ojm7bBkoJNR2vf4JQdIfIJXlCjT1gqEKxBXbcbEFlHh5vjqDAlKYcwEJELm5vlwod
         CS4fM/hcHYp26A+u4LSvVEJsK0VE6zbajkB9hKsNJbQL/TsH3uisDA2s2OeMFdbbsV2P
         pDPQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112 header.b=FrZZoDyu;
       spf=neutral (google.com: 2a00:1450:4864:20::336 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id o19-20020ac24c53000000b004810d3e125csi66469lfk.11.2022.06.25.21.33.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 25 Jun 2022 21:33:20 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::336 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id l2-20020a05600c4f0200b0039c55c50482so5490560wmq.0
        for <kasan-dev@googlegroups.com>; Sat, 25 Jun 2022 21:33:20 -0700 (PDT)
X-Received: by 2002:a05:600c:1d0b:b0:3a0:3ab8:924 with SMTP id
 l11-20020a05600c1d0b00b003a03ab80924mr7671319wms.137.1656217999456; Sat, 25
 Jun 2022 21:33:19 -0700 (PDT)
MIME-Version: 1.0
References: <20220521143456.2759-1-jszhang@kernel.org>
In-Reply-To: <20220521143456.2759-1-jszhang@kernel.org>
From: Anup Patel <anup@brainfault.org>
Date: Sun, 26 Jun 2022 10:03:07 +0530
Message-ID: <CAAhSdy0mkwacNMVa_jFZmZ+NRPBa1TpKUQGpzr6Z9_wfoq1R4g@mail.gmail.com>
Subject: Re: [PATCH v4 0/2] use static key to optimize pgtable_l4_enabled
To: Jisheng Zhang <jszhang@kernel.org>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexandre Ghiti <alexandre.ghiti@canonical.com>, Atish Patra <atishp@rivosinc.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20210112.gappssmtp.com header.s=20210112
 header.b=FrZZoDyu;       spf=neutral (google.com: 2a00:1450:4864:20::336 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Sat, May 21, 2022 at 8:13 PM Jisheng Zhang <jszhang@kernel.org> wrote:
>
> The pgtable_l4|[l5]_enabled check sits at hot code path, performance
> is impacted a lot. Since pgtable_l4|[l5]_enabled isn't changed after
> boot, so static key can be used to solve the performance issue[1].
>
> An unified way static key was introduced in [2], but it only targets
> riscv isa extension. We dunno whether SV48 and SV57 will be considered
> as isa extension, so the unified solution isn't used for
> pgtable_l4[l5]_enabled now.
>
> patch1 fixes a NULL pointer deference if static key is used a bit earlier.
> patch2 uses the static key to optimize pgtable_l4|[l5]_enabled.
>
> [1] http://lists.infradead.org/pipermail/linux-riscv/2021-December/011164.html
> [2] https://lore.kernel.org/linux-riscv/20220517184453.3558-1-jszhang@kernel.org/T/#t
>
> Since v3:
>  - fix W=1 call to undeclared function 'static_branch_likely' error
>
> Since v2:
>  - move the W=1 warning fix to a separate patch
>  - move the unified way to use static key to a new patch series.
>
> Since v1:
>  - Add a W=1 warning fix
>  - Fix W=1 error
>  - Based on v5.18-rcN, since SV57 support is added, so convert
>    pgtable_l5_enabled as well.
>
>
>
> Jisheng Zhang (2):
>   riscv: move sbi_init() earlier before jump_label_init()
>   riscv: turn pgtable_l4|[l5]_enabled to static key for RV64

I have tested both these patches on QEMU RV64 and RV32.

Tested-by: Anup Patel <anup@brainfault.org>

Thanks,
Anup

>
>  arch/riscv/include/asm/pgalloc.h    | 16 ++++----
>  arch/riscv/include/asm/pgtable-32.h |  3 ++
>  arch/riscv/include/asm/pgtable-64.h | 60 ++++++++++++++++++---------
>  arch/riscv/include/asm/pgtable.h    |  5 +--
>  arch/riscv/kernel/cpu.c             |  4 +-
>  arch/riscv/kernel/setup.c           |  2 +-
>  arch/riscv/mm/init.c                | 64 ++++++++++++++++++-----------
>  arch/riscv/mm/kasan_init.c          | 16 ++++----
>  8 files changed, 104 insertions(+), 66 deletions(-)
>
> --
> 2.34.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy0mkwacNMVa_jFZmZ%2BNRPBa1TpKUQGpzr6Z9_wfoq1R4g%40mail.gmail.com.
