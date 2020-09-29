Return-Path: <kasan-dev+bncBCV5TUXXRUIBBT5ZZP5QKGQEYTC5DCQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x940.google.com (mail-ua1-x940.google.com [IPv6:2607:f8b0:4864:20::940])
	by mail.lfdr.de (Postfix) with ESMTPS id 00F9F27BD8A
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 09:05:53 +0200 (CEST)
Received: by mail-ua1-x940.google.com with SMTP id p65sf456912uap.22
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Sep 2020 00:05:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601363152; cv=pass;
        d=google.com; s=arc-20160816;
        b=D67g/URloWJK2XkkM6TKNi1cH5ITZZtU1o1x0sDAOUl1Svk79w7yzAD1Mhmgnj7xl5
         ZO5zUGQSE1oYbZAYseweF716PArpYE8smr74lWFCYMwMIh81PEVTaTwpt1maeZu3IO2/
         Fjm36MNkky2C6xUqa6xFoPWvW7BvYedgiaZPtMS0KCutosgNsPUYEBDurt5Jm946Jrwg
         ufUwj7KCBHWEVsMqtbaJ96gao2NS62XqqH52rdACs3NilWb4BcJJYgne+KK5lNrul0x9
         ivMfdNndgY5f5CNzLDE0pGKKThQu591Mj4P3cwkvghv93PKYR7SCaloNGMR++5p2bPu1
         0pEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=Qh4/TdC332PoSD2rMXFs3inWBhGfDtwmDoY31UCQiEw=;
        b=smOiX9kn0jlllavd2w0r3c1ZaYmPbvjb+jZGh6gRG19jSqS1lCLsucgJW1/C4sRIfT
         DjX3Vodi0GKB0z21rk6vawxzuYDDQ3bN//y6R9UCik2Z1KtbOsVkek14z3CDPs5ikAZ9
         iEOnX5Rfc9mu1NdWXK5GkUzA2aQoSXtf8JM5LZ1VUKHqJxqJFk5eG7O+9ZxWsqQClZ4u
         2oPbYlrV3OrNvmdmr0eI8nFSrlzuc8+hS+B/13SS0PqjNG6E9gz0ozSXEfLqu301UkST
         6tbSaH7/ThXi192xEM3R+j9bwJ+uL0LwbQxMXCFSErp7s18k3YaRtluhWCOJpVeZRV63
         91mQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=qxjLXffF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qh4/TdC332PoSD2rMXFs3inWBhGfDtwmDoY31UCQiEw=;
        b=jmbb7TaYxY9+j9jAxiM5k1uM/qE06PiuxUjoGo9FX3h4crnUX28ND8mFs8PMpW1Uar
         2W5rq4H3YqFI01IrQXfBD4oKWsbEZcUIYkKYcGu/lvmZLT++cHPRaCmD18lAx3FIa1Vo
         sUyKlj0Dy7s1XAQjiyuSaa2DJH9Bgarvu6qtJA1JEm1TuoU//fmMIDsuRVw4KB9WsmaR
         aqaHIswtEp3jGGtELMG7BouWGUp1qydGdU+/j6CuZTtq9Gv/u2CeJIzShi9PDAgwYN/d
         dVr7usvCCK5YiowCa/tXNUjkluPjexaXc30gLaMS5Aamop6Szi5N9DJe9/rw3JDcYua0
         g0kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Qh4/TdC332PoSD2rMXFs3inWBhGfDtwmDoY31UCQiEw=;
        b=PSDHQT0VFw91/vAR7jtP2R9m/j4F69YwAKXtazCCobgMVpMKssn3HVLanAmIM2cvWX
         bTMPUpKOSLGb6P1LPSalv62hQ/sX+G8oHjRkGRgZKp+Nx7CTjSZGJy2t3eKwlw4NSoTr
         Cxne0+QzhojO5cM2Z/+/86RDbnMOpvl39bUC/BmM9l6hoA6oIilibzI61sdpwucAKP7y
         uxCuiuht9qknj2QvtTYl/KJba7MpPyjNR5U/M5A946ochoSxk2d34J6CW7gPYeFMU4P4
         Rpwm0vEzTATttIzQUq2VO57u7Dd/qcWwv283hf+ZZXJQ69cr5GsQ3FTmscOuH6J2pa4L
         WrrQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Xu+Gqs9fMWF5H6Pe42fXdNR66efGMkbJUcUvmTeE4EauExkSO
	xXfHL4py8Fywn81p6gqIg9U=
X-Google-Smtp-Source: ABdhPJxHITk7OIfWKccJBLXn/vLjxaT7tYXUsUWnOxlZGnOItxNkI3Ms+itKlSV/sVAv6RBZHsE+RQ==
X-Received: by 2002:a05:6102:10c2:: with SMTP id t2mr2062128vsr.10.1601363151936;
        Tue, 29 Sep 2020 00:05:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:5b04:: with SMTP id u4ls303965uae.7.gmail; Tue, 29 Sep
 2020 00:05:51 -0700 (PDT)
X-Received: by 2002:ab0:2c:: with SMTP id 41mr2903017uai.58.1601363151404;
        Tue, 29 Sep 2020 00:05:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601363151; cv=none;
        d=google.com; s=arc-20160816;
        b=PXqQVxelmwFjLcQJ25iV36y1PWv20CQ3eDnHmI8Wz9ZUHE1CuqEISvQ8gjeXRjtAWn
         xi6lRt66SGRRnTcP9dALqNfO86vrJlnWpjNSzwuKOxZGUJ8SDy4E82Ybu116CmWXS2OA
         9/56mJnI+qrYPpiQjPT5i6SwRrBphjEOj7kTTkimmeRAlLbioxI+A94KVTGK5CZmrBNq
         DcYA98bC6BCSGEGRwE5ZVPwmyWuVaLR9d1ekQ6waTbVcH1NRfA6QI03qn44Ey56FiwF7
         Yf36GDkEOoh2Dwl4GhRvqfS804XBnV99IYdc3uwUy27LTBsubNa7K3+QKoFQMGDPpq9n
         SLhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=9kawJvAFm/r2cBtZDaKI8NZRqczi1W/P4nsVgilq4Ss=;
        b=Ei6SGLCfXkBbmVt6p8RW6sRuNFHFsNaNPAiDb0Rbzo7bx/QAgLzjWghaKfuzfe3sxi
         aL2fX1qtLjdozL4rd+xyB4YarkDmhw1GXlgXfhhu/ade2oycjj5GawT/BNAYCNoYdEE2
         qEtaX7QhChWuUy+pl4kBaKINnb93GIT2RMeSOfuYpegGn460rPItmmdSyhRC8InB38gO
         lEYPTB1layuDRQNS2W9h6ZE+dfZwO6pTBO8WEcyZeBTLXFQ0MV4LtexuLDbTuyxRNOqM
         2BuWvNvF1AIkpme2rqG/4wKSPyXjU1HgK4igtgRg2CxJbTiuiOxmOVwxNm6BTgZHfW96
         V6aQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=merlin.20170209 header.b=qxjLXffF;
       spf=pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
Received: from merlin.infradead.org (merlin.infradead.org. [2001:8b0:10b:1231::1])
        by gmr-mx.google.com with ESMTPS id 134si175332vkx.0.2020.09.29.00.05.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 29 Sep 2020 00:05:50 -0700 (PDT)
Received-SPF: pass (google.com: best guess record for domain of peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) client-ip=2001:8b0:10b:1231::1;
Received: from j217100.upc-j.chello.nl ([24.132.217.100] helo=noisy.programming.kicks-ass.net)
	by merlin.infradead.org with esmtpsa (Exim 4.92.3 #3 (Red Hat Linux))
	id 1kN9hq-0008JL-9M; Tue, 29 Sep 2020 07:05:46 +0000
Received: from hirez.programming.kicks-ass.net (hirez.programming.kicks-ass.net [192.168.1.225])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(Client did not present a certificate)
	by noisy.programming.kicks-ass.net (Postfix) with ESMTPS id 7F65B302753;
	Tue, 29 Sep 2020 09:05:44 +0200 (CEST)
Received: by hirez.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5B5D7200D4C43; Tue, 29 Sep 2020 09:05:44 +0200 (CEST)
Date: Tue, 29 Sep 2020 09:05:44 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Jann Horn <jannh@google.com>
Cc: Josh Poimboeuf <jpoimboe@redhat.com>, linux-kernel@vger.kernel.org,
	x86@kernel.org, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
	Dan Williams <dan.j.williams@intel.com>,
	Tony Luck <tony.luck@intel.com>,
	Vishal Verma <vishal.l.verma@intel.com>
Subject: Re: [PATCH] objtool: Permit __kasan_check_{read,write} under UACCESS
Message-ID: <20200929070544.GI2628@hirez.programming.kicks-ass.net>
References: <20200928224916.2101563-1-jannh@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <20200928224916.2101563-1-jannh@google.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=merlin.20170209 header.b=qxjLXffF;
       spf=pass (google.com: best guess record for domain of
 peterz@infradead.org designates 2001:8b0:10b:1231::1 as permitted sender) smtp.mailfrom=peterz@infradead.org
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

On Tue, Sep 29, 2020 at 12:49:16AM +0200, Jann Horn wrote:
> Building linux-next with JUMP_LABEL=3Dn and KASAN=3Dy, I got this objtool
> warning:
>=20
> arch/x86/lib/copy_mc.o: warning: objtool: copy_mc_to_user()+0x22: call to
> __kasan_check_read() with UACCESS enabled
>=20
> What happens here is that copy_mc_to_user() branches on a static key in a
> UACCESS region:
>=20
> =C2=A0 =C2=A0 =C2=A0 =C2=A0 __uaccess_begin();
> =C2=A0 =C2=A0 =C2=A0 =C2=A0 if (static_branch_unlikely(&copy_mc_fragile_k=
ey))
> =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ret =3D copy_mc_f=
ragile(to, from, len);
> =C2=A0 =C2=A0 =C2=A0 =C2=A0 ret =3D copy_mc_generic(to, from, len);
> =C2=A0 =C2=A0 =C2=A0 =C2=A0 __uaccess_end();
>=20
> and the !CONFIG_JUMP_LABEL version of static_branch_unlikely() uses
> static_key_enabled(), which uses static_key_count(), which uses
> atomic_read(), which calls instrument_atomic_read(), which uses
> kasan_check_read(), which is __kasan_check_read().
>=20
> Let's permit these KASAN helpers in UACCESS regions - static keys should
> probably work under UACCESS, I think.

It's not a matter of permitting, it's a matter of being safe and
correct. In this case it is, because it's a thin wrapper around
check_memory_region() which was already marked safe.

check_memory_region() is correct because the only thing it ends up
calling is kasa_report() and that is also marked safe because that is
annotated with user_access_save/restore() before it does anything else.

On top of that, all of KASAN is noinstr, so nothing in here will end up
in tracing and/or call schedule() before the user_access_save().

> Signed-off-by: Jann Horn <jannh@google.com>

Acked-by: Peter Zijlstra (Intel) <peterz@infradead.org>

> ---
> Calling atomic_read() on a global under UACCESS should probably be fine,
> right?

Yes, per the above.

>  tools/objtool/check.c | 2 ++
>  1 file changed, 2 insertions(+)
>=20
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index a88fb05242d5..1141a8e26c1e 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -583,6 +583,8 @@ static const char *uaccess_safe_builtin[] =3D {
>  	"__asan_store4_noabort",
>  	"__asan_store8_noabort",
>  	"__asan_store16_noabort",
> +	"__kasan_check_read",
> +	"__kasan_check_write",
>  	/* KASAN in-line */
>  	"__asan_report_load_n_noabort",
>  	"__asan_report_load1_noabort",
>=20
> base-commit: 0248dedd12d43035bf53c326633f0610a49d7134
> --=20
> 2.28.0.709.gb0816b6eb0-goog
>=20

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200929070544.GI2628%40hirez.programming.kicks-ass.net.
