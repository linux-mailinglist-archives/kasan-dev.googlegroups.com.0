Return-Path: <kasan-dev+bncBDW2JDUY5AORBFUORWUAMGQEED7QQRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8278E7A0BF4
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 19:47:04 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id 46e09a7af769-6bdb30c45f6sf1581716a34.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Sep 2023 10:47:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694713623; cv=pass;
        d=google.com; s=arc-20160816;
        b=C/LRRP//FIZz9gOy2/f5AdoH3mIX6euo3dyiGpHy6PdyQawAkb96tzQ+8/VDugbA+b
         2ZouazUgGtC8MQ8WE6+gX8O6+qQBVV7x7OdVXhHrfzVcybqTjCF+RCgnvsFIxZUpttgY
         Cq+4iIkYyFRLtGWY7DAzX9QAjWUnMzn74B22m1WLHLDgbxvAQXwxSyyVT6eTJ/5ulRnE
         1ZTebuZ/lKiCsxV9Z1bMMZYpTX6iiCQOcqcMc/EOVjMjnFIaUwPRVbyd/jS+rZEzZ+iR
         3JCieiMdis3tzSZ1s1l2v1l5FstcwFRXidVNjeO2LfMAnbWFlo//b4udTWAT6qbvMosv
         4r4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=Y8Fe8LNIE/O7C/ZbnVuwgz8qur3H5Mmnh60+BcMo2x0=;
        fh=mOFVByfsJNle5OoL3xMTOfgYLnLvVWdorHp2SYW++nc=;
        b=ItrwkTfTHAfXQh67lhlSGExiPuGmF2TzKOXVmYp4BqYdsoRT3Y/80JsQn9oISlObNt
         ZpalpqnqEXEiQDl69MxX4bJuqiuHTrBX3BU/egtDtjvQ4Zam/pYMeiADAAdM9Owi2XOd
         a9grM5KWgp8eUH2O8U219HBPWsdD0klshjHad9p2Tw7KJk/zCFOJeetCYw3Y22R+OisI
         mwy3JsZl65It+Jp/wu5C6HGgc/TdQ6yqWCV1mUqaY0Mmq3AmOO0l7zKHPhUa+LGVtUTY
         jKo3mFHU9gUUAhlINAf41F7nFX4U+4Z4yDYMGS1uLfnChK+H8qHGDGH7bEV2SmVM7HYl
         0+mg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Ffhl6wdC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694713623; x=1695318423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Y8Fe8LNIE/O7C/ZbnVuwgz8qur3H5Mmnh60+BcMo2x0=;
        b=K1c7EDRJZGtGVYp1o7DkB4gfxyenAMuXwn/IiT3nHvqL6v0AteL8/UdXEcy7D6ZpwZ
         00npLwadWtia5aF5QafJKY9+zLxS2DPlZv3atCVkNdkUqz45/bgXARMx7V4Nn29hGSFs
         HXeSrr8Twc06cl036KORn5ALRoi+ySAcAlldKOdBQZw8Hui+qeU6ohDY1tZABFRPWhHK
         o9YSDlzPlQO8xHRcgTZOVe6fEMVEuzSiN76ZVHt9GhaF+qOoKZhs02p+RbY27OAZzVO+
         neIh2ukXSJriMR/P/TJzDuLjO85b8jQ0jfPhqBi7wpIlK9wyKQr45SPBpXBOxO2Mnajf
         PzzA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694713623; x=1695318423; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Y8Fe8LNIE/O7C/ZbnVuwgz8qur3H5Mmnh60+BcMo2x0=;
        b=lT05hmzpMukxiGM0bMoYB/PebILEekq7L+9IoABSB7CTpc5lg6ercyiTbQ71MtY+bj
         eoc8aiO874Lj6QFO0c+z9FLWmsk46o/CVcq/3Uzhu0+i6vSlZhO3jyaFiEYVUKjZqWAW
         krlCJvBUfDp/Q0zWTqyBbrSIGqTl7Nk6RqnY+IO4B4YuQ02zLrgVzX13dZxdZXWziMsa
         WyJIhdZqXqqsjloBA9dmSKLh+l/nbkAZUP5vnw+FFaY51FUifQd3nsFJO6I9r3PsOUaH
         tMu3UUlbhTToeUmXMeoxoEnUvE/9zKlhH6BHj88vA+ZdSTRyDQ1/RzWOWk8ThA1v1hyP
         HMfQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694713623; x=1695318423;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Y8Fe8LNIE/O7C/ZbnVuwgz8qur3H5Mmnh60+BcMo2x0=;
        b=TmUAP2qHZvWHtBkdqiTU1WT9l2f8F24BaeU+SF0e/w0/iNFDUrXyxruEXn8qupoJxK
         i3Eu/dMq+VCQxSDxgRiX0Cq0ah3wMvgL8clOtyoMXWMRzn8ZOBF4feZe7CNc4S9j2grO
         Pi4XLVhWHt1ZjrSuLqse1yigllcxpnAs/kolpIKU5KylWFo0+kuggU72MAb2a4mEB81F
         ooi7ip97lfbA6zJeUWsKJea5km9aIOwkEPembmelfsNkGWNOxv0YuQAoi8YBCbZV1IEp
         DMlGcYgYzMSDu4Z4kFLrtdNws7VU9abwGVGeelh9jRbRTODs+QKrPnZcq5tBWMSSD56H
         Dnlw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yz4Nh73Q6DpxPFXx8Bsdh8VJP12KQbIcId8aJJZxWH8VJqfo6MO
	ZKycpD/mtya8f1Z2E9yfuUA=
X-Google-Smtp-Source: AGHT+IHYCvEXsYL7dY61H+eID+Ht3PEpWr7yW9JTq0226riFa5hwGHWFn4e6DEOURsycTSd+c1GJbA==
X-Received: by 2002:a9d:6f04:0:b0:6b8:dcd2:8b9e with SMTP id n4-20020a9d6f04000000b006b8dcd28b9emr6981974otq.7.1694713623020;
        Thu, 14 Sep 2023 10:47:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:4f8c:0:b0:576:22ef:e4a4 with SMTP id c134-20020a4a4f8c000000b0057622efe4a4ls762084oob.2.-pod-prod-07-us;
 Thu, 14 Sep 2023 10:47:02 -0700 (PDT)
X-Received: by 2002:a9d:7642:0:b0:6b9:1917:b2f3 with SMTP id o2-20020a9d7642000000b006b91917b2f3mr6074820otl.33.1694713622137;
        Thu, 14 Sep 2023 10:47:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694713622; cv=none;
        d=google.com; s=arc-20160816;
        b=dZkLuf1PPFEE0J/9lgnQGDJsDU5n9rBH/npb8EtY2uj4Mm9dW5lQ787EEKa1R/VQtS
         UziJneBAo50JDUtqvrB5W3C+JQiseN/O2G2swvhTDkSeRoUqLXNtOyVHSihMZ3nYxGnG
         0ciSgcvjVt3VWRi9+AG/JfgTIi/dupU6FuKoNJk9XFkefKl3lABdeEHQSB6b+hkUP9Re
         9dGKIQz6DaSPbIjQFWb2AE8LvywxHL/5FYUqMKnjTjnJYAVmQxeFn1qsi35Sh7GxyVJp
         SoICvWMVXa4tbAFuIictTGVUYYjip6+ZNvjQKt5itt/cMu77F3t2UqGWvtwRZRHqlWEF
         xeCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=J3P8BZDl5uXhLdi7mCkkSTzXwn0E2WaaQT91SGIepdI=;
        fh=mOFVByfsJNle5OoL3xMTOfgYLnLvVWdorHp2SYW++nc=;
        b=U1SmyxaIhKEMp0aJK50IiziN0wxZQQYKnFdNAL8euK3ust8CfolTWvf4s5N4pFU9Jt
         jpr164q3gRL+FI3BETmUIjXIl6IymzIV/7JcaK9yIdlE0IBtnluTqPXVBTRkbLLoP0uo
         9bGolazN66oX4H8f+pXs0qSRUJhjlnqIHeyeXWtDIUaQVIPt78BgEyk0oB3r7BDS4+xI
         x9lHrqmLzWVzI8834XpJ7Ocv9Xky/yrMomhb7/N743+K5A2RbAieeSJjG/AtpMDnoVjN
         oqFUSsxcflfGcjlVAW7n4aXrJoxslNkmV8767CGndzMfH+yUkvUm/9baoSInbLIPNaz2
         IUMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Ffhl6wdC;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1035.google.com (mail-pj1-x1035.google.com. [2607:f8b0:4864:20::1035])
        by gmr-mx.google.com with ESMTPS id c14-20020a056830348e00b006b9f166fa6asi200558otu.4.2023.09.14.10.47.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Sep 2023 10:47:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035 as permitted sender) client-ip=2607:f8b0:4864:20::1035;
Received: by mail-pj1-x1035.google.com with SMTP id 98e67ed59e1d1-27474c64b0bso581720a91.3
        for <kasan-dev@googlegroups.com>; Thu, 14 Sep 2023 10:47:02 -0700 (PDT)
X-Received: by 2002:a17:90b:1d87:b0:268:5bed:708e with SMTP id
 pf7-20020a17090b1d8700b002685bed708emr5548210pjb.24.1694713621533; Thu, 14
 Sep 2023 10:47:01 -0700 (PDT)
MIME-Version: 1.0
References: <20230914080833.50026-1-haibo.li@mediatek.com>
In-Reply-To: <20230914080833.50026-1-haibo.li@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 14 Sep 2023 19:46:50 +0200
Message-ID: <CA+fCnZeHNoccoiUy11pmCG9LWHAxyB+6C7+GTc3ixj8iBnbi0w@mail.gmail.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
To: Haibo Li <haibo.li@mediatek.com>
Cc: linux-kernel@vger.kernel.org, xiaoming.yu@mediatek.com, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Matthias Brugger <matthias.bgg@gmail.com>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=Ffhl6wdC;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1035
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Thu, Sep 14, 2023 at 10:08=E2=80=AFAM 'Haibo Li' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> when the input address is illegal,the corresponding shadow address
> from kasan_mem_to_shadow may have no mapping in mmu table.
> Access such shadow address causes kernel oops.
> Here is a sample about oops on arm64(VA 39bit) with KASAN_SW_TAGS on:
>
> [ffffffb80aaaaaaa] pgd=3D000000005d3ce003, p4d=3D000000005d3ce003,
>     pud=3D000000005d3ce003, pmd=3D0000000000000000
> Internal error: Oops: 0000000096000006 [#1] PREEMPT SMP
> Modules linked in:
> CPU: 3 PID: 100 Comm: sh Not tainted 6.6.0-rc1-dirty #43
> Hardware name: linux,dummy-virt (DT)
> pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=3D--)
> pc : __hwasan_load8_noabort+0x5c/0x90
> lr : do_ib_ob+0xf4/0x110
> ffffffb80aaaaaaa is the shadow address for efffff80aaaaaaaa.
> The problem is reading invalid shadow in kasan_check_range.
>
> The generic kasan also has similar oops.
>
> To fix it,check shadow address by reading it with no fault.
>
> After this patch,KASAN is able to report invalid memory access
> for this case.

Hi Haibo,

I thought this should be covered by the kasan_non_canonical_hook
handler, which prints some additional information about how the GPF
could be caused by accessing shadow memory.

Does it not work in your case? It might be that we need to add
kasan_non_canonical_hook to some other arm64 internal fault handler
functions then.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZeHNoccoiUy11pmCG9LWHAxyB%2B6C7%2BGTc3ixj8iBnbi0w%40mail.=
gmail.com.
