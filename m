Return-Path: <kasan-dev+bncBDW2JDUY5AORBZVD6CPQMGQEK5KMX7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id B90786A3801
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Feb 2023 03:13:59 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id t2-20020a4ad0a2000000b00517879b32dfsf850102oor.22
        for <lists+kasan-dev@lfdr.de>; Sun, 26 Feb 2023 18:13:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1677464038; cv=pass;
        d=google.com; s=arc-20160816;
        b=0/7t873YW3x0AB/eKVw6OQqod3Cnp29q+8nNFENjyDOgCLvapU0rFegSDYjmKmrWPp
         ZBHEIkJNC+TuH12/cBWDh7OKA8n15tTRi8xE0/XCwQ6yKAvhji/ayMYJkHbA+9UIlAWD
         JUUjEu1KMr0olZJcUAoSGejq+QndqmLF+Lf/cXTWGrJXB7CEHgVJYEQKV/Spn1x8RwWj
         C5QvtiBHdmZDdcsBywOn7tcy7KcUh/Q6nmYC0zixhOVmqJr74u5J63jiUeZ9+iyBCYCp
         PehTHFgb0prGcvLzPheebGea4erJnEmAT1P5tW/6fY5JkG5GG1IHUAZTPL1bebS+F5i/
         5P5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=M/naIVP7VTbGgoG/GaBzfbjO0xMjsV89ckWAXpXleeE=;
        b=rNsL5apsvQta0AicIjExBjliknBO7tMRgmfGOidOakUNMbCG06QsQMSbnrhHfz4rVh
         6xrUqqme1QPY4jFlk9CKZ0m9rXhn0HDFM6t5vAwbTMKuziI+ZebopxtYocTtjOT+N2Rk
         yliFmqPc1L3LTlUpZ+S3RgqXly9TBsyPRTeuJuYxWtuexRKHgkrAW4v0v0E1wRiQPP+K
         +ntfXOUq0If8/q44Pn/J44VSqvbJx5qZTk0SyUy02j1DLCUaSzqCJSGgeK7lSopYg5PB
         iwWLIvKSn3PeOh1mXHR8qzZ3wlNM3LgntV4gkE0khCo6XJZdQUDxWkmIWhlIJAkT3xS6
         CqbA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QaqU4DEa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=M/naIVP7VTbGgoG/GaBzfbjO0xMjsV89ckWAXpXleeE=;
        b=oWtQjqO1/YZRPFoFV6z0bdmgysNqtT+iY9hA3d+ThXqY3A3/V8dtGswCZgeygqw017
         CW1zBQMocU8lHTWhdXaAUnilxifud8DS7BlJ3U3rdwDwkIYYmqUPt2V4uuoLVlkir3Lb
         sQSdM1M0Q/G3cgUPyLAZUShxkz1fUgZRCWFR9U54VUHluevHYwciiyhXy54cN7C8VFbW
         PxqQd+wzNvtJUeJYalAzcZk6tDI3vX5wln4X4IMQ/RaD96Vb2r5u8FTDPlZoOk6aq7SO
         KtkG1bae9a47dmwoWSlE50jQM4BXk6jx8o2wQcVFcTFMo+7mcyYBZy82jjq88DF5aXw+
         vmMw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=M/naIVP7VTbGgoG/GaBzfbjO0xMjsV89ckWAXpXleeE=;
        b=qEW7V/HGH8XqfrCtGcAdGp7Jk+3SEsk6Yf1n8GB5wTtcE/ivb10X/o9gYfxFmN/o9r
         57ryumlvSgP+V+rvgTmK54RSfvisLarDz5nyaQiv3ElzTncm5dFXxvL+nMkB2lbnIChJ
         +yjH54ovX5tbTU6tlwCObSxpzx1NshTFsE20DgV4OzbKKCvNvUlysHi9b8+xwv4M9cgP
         gwtCAs3WJ5lXXCx04qVWuzERZ5g4LMmzNfPBKlaAWfTZ8bb95VRhAt6sVoWsM+UyWVZQ
         uRnKVbT72d2+TRNfyuUU6i4Qhf6X9FtvaFdsL98NMM4LQ1H0fTtbExdrvkbTzsHXhWn1
         Rrow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=M/naIVP7VTbGgoG/GaBzfbjO0xMjsV89ckWAXpXleeE=;
        b=HDh0jR9O4EtJgTG6uzw27RVj6hy7VZdRF1yocInJC814SfCOV68ZzPfyYiFGcSD28Z
         B4QNohDoBEeVVEBALEue7k3zap6VDvY2JI+Y7rbX38mbftgQ8ZWbyBn0n0yCzxsV7DL5
         exQlpYdqlUNoLULctpeQcZJa3g4JKWXjl9UZKUOBCT1pki7l1NpOwkR9bUTFzBb2VIH3
         obJdkOw3CPHpVboxaYBYJYOww0X5w65ssfV1cMUdJODP8y/o8HfVYP6JYMxY4Fqagwq1
         NYE8L4nw2JAMWwgiNOHxptl4vQArWCBCk0kY3UKxThH5RLrHihZJSDXY9zK1+b5fjVTZ
         c44A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXE7YctwM9PwFMVOMM/6tfniQng2I9CsmyUe8yw5REwGy3KQ09c
	Dke4ww20aj9KnpDbrvVeCy0=
X-Google-Smtp-Source: AK7set+vOBQgVZOB1Jx1oASJQT6zK410BwqGymh2F0+XAsqx6NHnvW63Q76lCjS0G6kAOVxZDneH6A==
X-Received: by 2002:a05:6830:26c9:b0:68b:dc77:a1dc with SMTP id m9-20020a05683026c900b0068bdc77a1dcmr3837113otu.0.1677464038095;
        Sun, 26 Feb 2023 18:13:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:6255:0:b0:37a:fb5a:bdce with SMTP id w82-20020aca6255000000b0037afb5abdcels2650105oib.3.-pod-prod-gmail;
 Sun, 26 Feb 2023 18:13:57 -0800 (PST)
X-Received: by 2002:a05:6808:2c2:b0:384:94a:ab4e with SMTP id a2-20020a05680802c200b00384094aab4emr4316083oid.54.1677464037653;
        Sun, 26 Feb 2023 18:13:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1677464037; cv=none;
        d=google.com; s=arc-20160816;
        b=gCLEchPFwWPaSlL/IrZgbHFkOTC86jfLSiKcK3py5yHoOQG7PPSMPYME1MjcaBUh4k
         eVMFRGvBkSbwx2Wl0I5gQZDfOGHRPlQJKlPKS5mxPcxjDoeSvCE806SmoKAdnPTeTII4
         nbewPVwowYMyVb/vUv+AJBLYIG5B1lcBvVqZCGxFO2Mh7N8HQvMvKwLjMnvMmZzCnqpF
         7LZils51Dluslg6L9Z0M8XQbE00EjyPJkZzI+WnLXOOm6WX+YTO1PpQUF7ElGfe6wYjO
         ct9TQ2TZjgbeETjS1p6FvCV4XN9BL9ShsQIHtxX9el8v4yzGFYrzr71IdjViGbAvV2kP
         lP/A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=EL7MuJSDTGevv/5NshB4YJDYr1z5Pg/OiTSz3dYlut0=;
        b=b1RplXAwhvHb0NAnZVbaPVp9fqEctoCpIsBD50+3/3ILtaaTrPnBi4tFWsF3QhyOiJ
         iZAuaLqRRWLZGFK/5txO1taT7pTTGfK5ptygOuCGPb+N7b3rDZLC1rmXDQPWgw3TDQY7
         x0MpihG9nteICZnNJbLyB7ISuypAXsOdS8u2JWYBSUveud1nJw0+lBvPOr0eiPefnBhj
         sgQdIRbMQ7+8NiN79/bV8tD5tdmRzlLWZYOnOsKi8kPoHwmtOJLxw0NIPL81BIfJS1+8
         I4LpTW68LrEll7Dny0gtMcsUNm6RBK3DnAIdxxkjDDI34R26ojY+3JgNgPHnXQjMMk5p
         YdLg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=QaqU4DEa;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id bh4-20020a056808180400b0037fa46467c0si297141oib.0.2023.02.26.18.13.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 26 Feb 2023 18:13:57 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id nw10-20020a17090b254a00b00233d7314c1cso8524083pjb.5
        for <kasan-dev@googlegroups.com>; Sun, 26 Feb 2023 18:13:57 -0800 (PST)
X-Received: by 2002:a17:90a:17ec:b0:237:30ef:e252 with SMTP id
 q99-20020a17090a17ec00b0023730efe252mr4002230pja.9.1677464036839; Sun, 26 Feb
 2023 18:13:56 -0800 (PST)
MIME-Version: 1.0
References: <20230209031159.2337445-1-ouyangweizhao@zeku.com>
 <CACT4Y+Zrz4KOU82jjEperYOM0sEp6TCmgse4XVMPkwAkS+dXrA@mail.gmail.com>
 <93b94f59016145adbb1e01311a1103f8@zeku.com> <CACT4Y+a=BaMNUf=_suQ5or9=ZksX2ht9gX8=XBSDEgHogyy3mg@mail.gmail.com>
 <CA+fCnZf3k-rsaOeti0Q7rqkmvsqDb2XxgxOq6V5Gqp6FGLH7Yg@mail.gmail.com>
 <b058a424e46d4f94a1f2fdc61292606b@zeku.com> <2b57491a9fab4ce9a643bd0922e03e73@zeku.com>
In-Reply-To: <2b57491a9fab4ce9a643bd0922e03e73@zeku.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 27 Feb 2023 03:13:45 +0100
Message-ID: <CA+fCnZcirNwdA=oaLLiDN+NxBPNcA75agPV1sRsKuZ0Wz6w_hQ@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: fix deadlock in start_report()
To: =?UTF-8?B?6KKB5biFKFNodWFpIFl1YW4p?= <yuanshuai@zeku.com>, 
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, 
	=?UTF-8?B?5qyn6Ziz54Kc6ZKKKFdlaXpoYW8gT3V5YW5nKQ==?= <ouyangweizhao@zeku.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, Weizhao Ouyang <o451686892@gmail.com>, 
	=?UTF-8?B?5Lu756uL6bmPKFBlbmcgUmVuKQ==?= <renlipeng@zeku.com>, 
	Peter Collingbourne <pcc@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=QaqU4DEa;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036
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

On Wed, Feb 15, 2023 at 2:22 PM =E8=A2=81=E5=B8=85(Shuai Yuan) <yuanshuai@z=
eku.com> wrote:
>
> I have got valid information to clarify the problem and solutions. I made
> a few changes to the code to do this.
>
> a) I was testing on a device that had hardware issues with MTE,
>     and the memory tag sometimes changed randomly.

Ah, I see. Faulty hardware explains the problem. Thank you!

> f) From the above log, you can see that the system tried to call kasan_re=
port() twice,
>    because we visit tag address by kmem_cache and this tag have change..
>    Normally this doesn't happen easily. So I think we can add kasan_reset=
_tag() to handle
>    the kmem_cache address.
>
>    For example, the following changes are used for the latest kernel vers=
ion.
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -412,7 +412,7 @@ static void complete_report_info(struct kasan_report_=
info *info)
>         slab =3D kasan_addr_to_slab(addr);
>         if (slab) {
> -               info->cache =3D slab->slab_cache;
> +               info->cache =3D kasan_reset_tag(slab->slab_cache);

This fixes the problem for accesses to slab_cache, but KASAN reporting
code also accesses stack depot memory and calls other routines that
might access (faulty) tagged memory. And the accessed addresses aren't
exposed to KASAN code, so we can't use kasan_reset_tag for those.

I wonder what would be a good solution here. I really don't want to
use kasan_depth or some other global/per-cpu flag here, as it would be
too good of a target for attackers wishing to bypass MTE. Perhaps,
disabling MTE once reporting started would be a better option: calling
the disabling routine would arguably be a harder task for an attacker
than overwriting a flag.

+Catalin, would it be acceptable to implement a routine that disables
in-kernel MTE tag checking (until the next
mte_enable_kernel_sync/async/asymm call)? In a similar way an MTE
fault does this, but without the fault itself. I.e., expose the part
of do_tag_recovery functionality without report_tag_fault?

TL;DR on the problem: Besides relying on CPU tag checks, KASAN also
does explicit tag checks to detect double-frees and similar problems,
see the calls to kasan_report_invalid_free. Thus, when e.g. a
double-free report is printed, MTE checking is still on. This results
in a deadlock in case invalid memory is accessed during KASAN
reporting.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcirNwdA%3DoaLLiDN%2BNxBPNcA75agPV1sRsKuZ0Wz6w_hQ%40mail.=
gmail.com.
