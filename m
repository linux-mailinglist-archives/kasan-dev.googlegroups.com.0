Return-Path: <kasan-dev+bncBDW2JDUY5AORBSHXRTCQMGQEUQMBMAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id DF7B3B2AB1A
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 16:42:28 +0200 (CEST)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-333f8f1d00asf17231011fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 07:42:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755528137; cv=pass;
        d=google.com; s=arc-20240605;
        b=aNRwqHEPu6zEX3DMbjzNFM55Q/LsrUPW2w/kwRG1INXFPR8oHDq6ZGFRFRK3Vuvdwi
         zL7WKVbcrD8MY4MVLQ4xc+f7ecOYFfpP/4R8fVYdn0SarL3UTc3VD27mVlSwlo681IAd
         sYA84tAGLJwlumF7041305DJsjXuwEqrY4G1ob9BGlIxdiFKrAR+8MfOZWsT/gKCq7EL
         116Vr9aVcyijmsUjUhHNFwmaaV4ivwmpmdhFDYDLguccpCfk+Ih+7SJSGMY1HrRsDO1e
         RGJ7ZL/Ig8FH+3NQzOHRMxQxDcAwm0kZlg6eD4DtOEkhG7ecRHECN45wpiFQuT0RXFfN
         7b9A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=cHt4EfT9JM8A71qmU8DNxP6Nl4P+Ql0ApY63Ddrb9e0=;
        fh=+F8K7XbKSqrmT3MwFjCxVZUOn0wSrncpaOrtRyCH4fU=;
        b=Vwk8PdX2meaFV1nfnsy/awuXIoGL2n+bsZb4Hb2yNQBHQWeu3rIGFwMGkzCx903cnP
         LIGRv/EeP0uRT005lLAHMfO4/3BAGorIAK3FruecnxPstJLDjjXq0UFKwQn1/XQDV4y4
         A6GNbbrATmYwLxCimHXlTmO1GlcprmIBqGlGviUUsseXFhwFadeRcpbJVNDQmxaJkj0A
         0/9H/dJoWv7A+tvbYQF/56tLT6stlSaj8acDznKA1ErCSS4bQJkx/NNACowzUGzrRGHY
         5veOM4EBz/W56GzV4HPCS9xlCoehMyLS5iWYkM3HfknNVQVSqnI+b5Z3guUlU13l2fHA
         veJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="HPpEr3k/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755528137; x=1756132937; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=cHt4EfT9JM8A71qmU8DNxP6Nl4P+Ql0ApY63Ddrb9e0=;
        b=vKKkGNsUOyo8Lnh5Tcy2NIU3KqTzThqU/0HqQ2U3CI0ouCJnUlKrsgeJv7BWcPRIvK
         XaZSUjwh/SufTyu8oWlJ8jTt3yEM+iDp2UD+zmSO1xmfxUdMIwajWO14pVoQGEt1QTX8
         NO2HaLPtYveac3jfBoVgsxuEcQoezgFZomFUtu5ddRtae9p/lOKbR+sBWeUvcOis9c6n
         MFiJQ7qEz18fe6+CKtW2y5VpdTDGqx6yX1CRz9tTSwtqQshhKRCNvzrPO4mfVoFTk59L
         WNZuwWHOhgzraCCdB3OPyTf0/ntWTX/oXykx88e0dJyMYMj7f36mBSuRQH5YerLkjfwH
         abyA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755528137; x=1756132937; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=cHt4EfT9JM8A71qmU8DNxP6Nl4P+Ql0ApY63Ddrb9e0=;
        b=aBK/4eHerYxMoFM6Jj8NYhKnqoWfaBJTi7RuuGBJyN+RIV0oS12ZsH8rwbU8oXHBtS
         2S7TgbYdlJ4D9IgqhDXsccIw1HLBQERyjcHBSrNcgxObbrexmkmfZG0FQ0iBfJRNNppN
         nEx6oBFoBSCT9wf/apmcBMGL3j/EZUnYNUccUezOGxxNO6TxwGUkYQKmK2YTnl/g8wlH
         k77l6HsEj932yptSQ5sKQF9MoTrAsE87F9tn23FZPVeqkgWpYOIYPoZLTzgvqaFQGKiT
         VnF1SDIpff/od6jGpy603wwWoAJ+5eQpFa4RxIB5wluyfF3R5WrQy4tJ3gUsmgrcQmVI
         DW5g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755528137; x=1756132937;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=cHt4EfT9JM8A71qmU8DNxP6Nl4P+Ql0ApY63Ddrb9e0=;
        b=K1N7KOanCQiBA1yHBNmxfJ+Cv22vV9M3KivMazVirYH6CJ6Z8Ahu+gB2iHCvOjvwzG
         SPmBoYmnirjpPC/hKtQjtPdnFLXyo52Dl8gADX1xS6eCGnBR0EPh49NxpYrWIcvaGnZq
         5mKa8CS0nLHqUnl7twlWs1ezy0c+EIIPPMuAilsTIUOyPqzthNxWIjdm60iHSrJPM+Qz
         BgkaC0FgItDbIot+TCBqQ68qldrQlhzvUBIczmPY9DQ11fZTy2NAqAkJtgoMwlVqtgRw
         FlQ+DPyM0dJHqZn87jvP4H/Kz2Dpc4oUziiCJfsARhVewUZ7RaEi8uRc+Yw/QazHT5jD
         5RUA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUSc2F5atlJIBl5ozjvbEGqHKZo+Vzs1S8+Rvew/hwoUYy63ZOAkE0c+yirgFJ0zOYIkYXz5Q==@lfdr.de
X-Gm-Message-State: AOJu0YyXd4uLn1kwuG8VvULkwaNoobTYEAL/I1i4MA2H/JjbU5ufSyjG
	2KFr/vX0wvwAKY1S6qOWtUmpMYwUnT0W7//2rGgcG6mgKCuKy+OQQewZ
X-Google-Smtp-Source: AGHT+IGv7REAI5Zkx2u79lyV8xajCqdks8QQ37rtLPYFSEGJihZ1jyhg8lk5gZTK6PNivFlsMecwpg==
X-Received: by 2002:a05:6512:e83:b0:55b:8e2e:8cea with SMTP id 2adb3069b0e04-55ceeaaa9demr2690161e87.9.1755528136813;
        Mon, 18 Aug 2025 07:42:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcHMEy0mQzy6La1ZKiVq0/Ety1hLUv8Lb4OVIpKxg3aiw==
Received: by 2002:a05:6512:281:b0:55a:2758:43e9 with SMTP id
 2adb3069b0e04-55ce4b277f6ls934410e87.1.-pod-prod-03-eu; Mon, 18 Aug 2025
 07:42:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX3sn99gq78zF3TyfT0iD5tcGReDjXI8deallAYj3PyE48GfWEGxWdiCQ0chMcwoc9Ot59e+N6cCws=@googlegroups.com
X-Received: by 2002:a05:6512:3090:b0:55c:c971:227a with SMTP id 2adb3069b0e04-55ceeacc7d5mr3110860e87.13.1755528133841;
        Mon, 18 Aug 2025 07:42:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755528133; cv=none;
        d=google.com; s=arc-20240605;
        b=PgqFnsl4YIRzl/Uo6RdXepu3mWWvK+vIPZcs2YZ9ZEASlrOEz0ZArf1DyCj8vtJYDx
         UigXkbUI4Ho6fmSfy6oGBgmyRsT+mvumro7u9gUK/i577GDjSBKtUJuhquHS20dCynH6
         rrZzpIhGwQfWS/D7B6rH7TTbU9z0x8QmakXimBGDfOcPjeZhe+BZiArxtbVguS0bZ6BS
         +7De9Aendw/hqKBvluR6tfa+Dk8nsYGxFkbaYaNUuM3keqX8D2OI+as3lfxofF3INbkf
         eEnb+Qv9xnt9NgkWbDqbkK6fvKduEqy6+9aIP2+wQnijxkvHnqQQirbl6utIQH/bF15F
         41Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=2VylDR1oWkJ0EiX1c8eLC+dJ8zDkBar7+OrlY7elEsc=;
        fh=NeK+p9cJx3wFYjA9gm/x9Q/fi9Gc0PqWJC+24ZBqG24=;
        b=Pt2K8tv6hhSz7T1/biJ4dEkhUy/xPBrPvNBs3ziY6HF/U3NYW4Q1kerkolotZvnr6w
         kfbGhvD/HHXfStVZDmrVkj2DpNTITchs6ip5wZjGYEOlnqVWn9saV0Dcwh7hor17AxS5
         1e5QAqz94VsEfqQXMzw2Muvs1zWjggDavVpwygLbnkixj7KFBBCBjv1v6RLrp/caB6Ey
         34MOnbGm06ZYlRDc7GwzgeASPzkwG5isrIqREn/GNXv59VMeB5bUVoo0JM1kTXZ5hP+O
         TTlzD/Xe4rRYflseSOQseT/68k4Nwg3Ih1+dCGYP8SoN6q5NcnL9qXtFC4cZIknjOWRo
         fkcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="HPpEr3k/";
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-55cef3bebd4si186064e87.8.2025.08.18.07.42.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 18 Aug 2025 07:42:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-3b9e4148134so2071258f8f.2
        for <kasan-dev@googlegroups.com>; Mon, 18 Aug 2025 07:42:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVCt8XwyEm4pFSY3W1nJRKO43NH8MjFSZjVXtExI2YBBpPTSsK9yYBMhc1GDrgz0B8/BWTarUF1hfk=@googlegroups.com
X-Gm-Gg: ASbGncvwoQlt7S4kgAc7VK2XZQrGZbO1oRgHoqdDzxLMpuUbxPHX/KewKu9rWcB7iI4
	tOdAjoGymX+m3DVBIoyI14cxVGqx026CpmJ5EedIsTs0LORTPeM4S8o7YdQHZOF50f9t0MsaOGA
	0YMdRwDohY8blx1BPi7IxHplVJ2h3RqufjloUrs1wCHdnP2CMvkt874Edumc7gAbRoje/znAl1/
	BQb/gCYEQ==
X-Received: by 2002:a05:6000:24c5:b0:3a4:f50b:ca2 with SMTP id
 ffacd0b85a97d-3bb6636cb19mr9221513f8f.8.1755528132931; Mon, 18 Aug 2025
 07:42:12 -0700 (PDT)
MIME-Version: 1.0
References: <20250818075051.996764-1-yeoreum.yun@arm.com> <20250818075051.996764-2-yeoreum.yun@arm.com>
 <CA+fCnZcce88Sj=oAe-cwydu7Ums=wk2Ps=JZkz0RwO-M_DjfVQ@mail.gmail.com> <aKMmcPR8ordnn1AG@e129823.arm.com>
In-Reply-To: <aKMmcPR8ordnn1AG@e129823.arm.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 18 Aug 2025 16:42:02 +0200
X-Gm-Features: Ac12FXwekbsyapeljRABB8AE1hyjZDIfFB0HZbnsKW56XSmgXNqVbJdHAoiUZKU
Message-ID: <CA+fCnZd9m3WBPimikuxSMNar-xbDaNFNQEJ9Bn=8uCMe-uYHeQ@mail.gmail.com>
Subject: Re: [PATCH v4 1/2] kasan/hw-tags: introduce kasan.write_only option
To: Yeoreum Yun <yeoreum.yun@arm.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, corbet@lwn.net, catalin.marinas@arm.com, 
	will@kernel.org, akpm@linux-foundation.org, scott@os.amperecomputing.com, 
	jhubbard@nvidia.com, pankaj.gupta@amd.com, leitao@debian.org, 
	kaleshsingh@google.com, maz@kernel.org, broonie@kernel.org, 
	oliver.upton@linux.dev, james.morse@arm.com, ardb@kernel.org, 
	hardevsinh.palaniya@siliconsignals.io, david@redhat.com, 
	yang@os.amperecomputing.com, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="HPpEr3k/";       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Aug 18, 2025 at 3:11=E2=80=AFPM Yeoreum Yun <yeoreum.yun@arm.com> w=
rote:
>
> > > +           hw_enable_tag_checks_write_only()) {
> > > +               kasan_arg_write_only =3D=3D KASAN_ARG_WRITE_ONLY_OFF;
> >
> > Typo in =3D=3D in the line above. But also I think we can just drop the
> > line: kasan_arg_write_only is KASAN_ARG_WRITE_ONLY_ON after all, it's
> > just not supported and thus kasan_flag_write_only is set to false to
> > reflect that.
>
> Sorry :\ I've missed this fix from patch 3... this should be =3D=3D to =
=3D.
>
> However, we couldn't remove kasan_arg_write_only check in condition.
> If one of cpu get failed to hw_enable_tag_checks_write_only() then
> By changing this with KASAN_ARG_WRITE_ONLY_OFF, It prevent to call
> hw_eanble_tag_checks_write_only() in other cpu.

Is it possible that the write-only mode will fail to be enabled on one
CPU but then get enabled successfully for another?

What would happen with the current code if the first CPU succeeds in
enabling the write-only mode, and the second one fails?

> As you said, kasan_flag_write_only reflects the state.
> But like other option, I keep the condition to call the hw_enable_xxx()
> by checking the "argments" and keep the "hw enable state" with
> kasan_flag_write_only.

Assuming we keep this behavior, please add a comment explaining all this.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd9m3WBPimikuxSMNar-xbDaNFNQEJ9Bn%3D8uCMe-uYHeQ%40mail.gmail.com.
