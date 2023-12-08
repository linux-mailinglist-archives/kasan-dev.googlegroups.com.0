Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYUVZWVQMGQEK2HB2ZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id B335E80A9DE
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 17:57:07 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-35da0415ab1sf20379175ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 08:57:07 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702054626; cv=pass;
        d=google.com; s=arc-20160816;
        b=XlPda5X8qmcUmrMa+JoAop6KVietCCDx4TW3XU/+aBNOP0LMzDEhbIfmjX+95O7Kt4
         dNJc2tPKgbUm5Sc0pBtIdw0QpprxnXs5TBzd2YEF6IEUdo5fQuzM2X6l7/6ZvpJy+qxt
         3xq9SkMsM1Yd6k1Y9tQDKElG1uexr8rMSw5iSia9M5azctua8eulgynF2+IFa25uCBpF
         gZWddYbXqz6/ZH2Zav8wtIDiB1s6NWyYrve1Pm/1G2N8DGAuQJLLThjYcOdsmlUrtWMr
         aB/5t2gdSOX8hGftUNXwvD0UlJIdCHF+7tIxsyHIeehxYyx1z1ZJx9ojRhEnLmb2pEJ5
         Xn1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XfUSCA/DbOkYRXXsIV/z553QkUO1fhx9hTMEz/Y/QfY=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=P4ANvk76INcPkgtISOBiCDRaoZG3eUtHKGO883aaWySUioqYJi64BxMesyqa976UmP
         sP9J65KXbyHUIbpoQoPxvkR/nE/lmZiJ0WRfAi84mW8YCvi6zQwZ7AKMtErDd9FI7B6o
         ojsC97Yw0ukEvxNU2YTAT9ZWmxkeJWeOBoGP+Lzw5hUROlgspPegOKs32cXhbNREeAiQ
         zAww5JiFxlYVE7XkV6Fe/adcteVsdyEELK3Dv91y4cFFX0nWEIuPIvtyWXATY3xcNXKW
         L5ECnoQGMhUX73Kel9tBvqiarLmMt/LX9M4okUmaYYqOhlJ0OoknSja58kVxQq0Z4zdC
         mRHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vOz4U7z1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702054626; x=1702659426; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XfUSCA/DbOkYRXXsIV/z553QkUO1fhx9hTMEz/Y/QfY=;
        b=Pkr0aW6wNe+iBhhuLrC0lfoUGkbjGM4JMInpS6ZI9RDP8gymIO1KfIp4vWdh7ecyuU
         y7DjFaFPeRAdj0/NTNg6dpMnIYCYhV74+ZJdb8Hrez0ElDnlNKQ4EnzAEhwa2OkbM6P5
         9TJeh697rMc+PSn8mar9F/fqFGdMerd/1qur962W2H6yo2zSpX0O2wN6HBlhBspxvZtS
         kd93ZQUez/av8O2h5jwx0kfXU2WE6sNs/LWmu6Kia7JIypSJ5AYSh0mp86jwUG/gAzH8
         arkzWkU3PAEMIa6RH7JVRckFHL+J/GVmQY8MKn1WNnOeRYednSVj5uHHRsPah7POQ7rv
         TT0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702054626; x=1702659426;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XfUSCA/DbOkYRXXsIV/z553QkUO1fhx9hTMEz/Y/QfY=;
        b=mA3yeNzS5DvD8WzV0KaHq393zSyDUCvF2rvWYLXhZ0oz6hwbXlOJPDENqern56nyku
         QPuM7cCWGUu5XOsMY0BWeIpCkEbc/0q44/r1rxAyQevlpRR6718vx52f4LO0VWrI1BPp
         0eLnjbc17vMh61/OmpnMgfW23XjMeyGM/rN9ZIDAewd2+P0e9qoVY8DFUb2vpuih1lYD
         7b93W4PioSEt6piKxrnnSPthtxWQ+1RNDA6gICReHUtYIynAd4MNgdlEQUP168nzgrzH
         Oa6u5wjIAWt4CILFL6vcAEIgeiOVFLxw8zSnfY63ZeF51TSSAu19Zo5H7fYDXm0pmxA4
         2tcQ==
X-Gm-Message-State: AOJu0Ywg0RqM5HNrS1aF3ZdSGbxebbNquinazrqz5kBGhoofZXAJ8EzX
	+eysDLCBHdxZvHLJdW9k+7s=
X-Google-Smtp-Source: AGHT+IHvofWeNYYn50qCfG3O2Wg8n4/0EX6PCBnNLdHnc+p8hA5BZv1ok7ZqD8AENox6u2xlTNpq1g==
X-Received: by 2002:a05:6e02:1c49:b0:35d:66a0:5432 with SMTP id d9-20020a056e021c4900b0035d66a05432mr614991ilg.13.1702054626498;
        Fri, 08 Dec 2023 08:57:06 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca0e:0:b0:35d:1a8:864 with SMTP id j14-20020a92ca0e000000b0035d01a80864ls1330917ils.1.-pod-prod-04-us;
 Fri, 08 Dec 2023 08:57:05 -0800 (PST)
X-Received: by 2002:a5e:9413:0:b0:7b7:19d2:b53a with SMTP id q19-20020a5e9413000000b007b719d2b53amr401039ioj.28.1702054625677;
        Fri, 08 Dec 2023 08:57:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702054625; cv=none;
        d=google.com; s=arc-20160816;
        b=MoCGEXxbc1qz9xwsU0YC7x4o2fyEpNpZx3Wn06KppBRpK7bNj1lMuCB9HoroXx9TuD
         A5ZBkl8iNOI2xLmHekxT3fpgpXSYc1Z0w1IUnYDL5tD5qKxPgLzZGCdVoepVofYtpm15
         +PEI+iPH6+teVevOad+0FHzhZ5C4064wJUAaAoCPIHfVSAcWSASjL2/5j6P+BvE4oMcO
         3L41gjdfJ4PQByrVjda8MUNGH/0XcD/vVzgfBThVY5+TyFMVDy4m54qNZtoWpcN2Vbcl
         9wDEcJN3clymirscgAI714sBBDZs8sY8J+jKyu+Wm+zUEL43NI7nK3ak04ewYLf7w294
         INew==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=p7eBdMYz2oO1gCYv2gO3b03vyzDyBixdRfjwy6xmbYk=;
        fh=kmKVJfn1Y9YZhlVPpqCDHuVVZsVgm/oqvGOUm8JK+fE=;
        b=DWhNdxI3pYNLFP2Xs6GOacjzQFvTfARCb8J3/9VGGoXDomS8Dwa8qosI+3YLACiCTT
         QZ3K6FFHyVDq6OX26pmPA0ZizSBM9VQgVE2CWUuVdMs8T7/7J+eM36MFUUqWK/J/G1xZ
         PrYan4g8ho88Y8GwpwepXc/9NVng/SfBoYRfX3S/CNl1sW0Pld8JStAM/5gZVDIChgen
         dlVIq7QQIX4PdpnlvQQN+GHqT/ILLbkCsdJDEFHV5dORGMrANtBHwmYpHLzEvPiD1fVA
         5zu3SPZl6uKC5/uXVaArxn16BzKdQsmDPTCDKgNracIl/63yeKEeTwKb9qfV1KRt00nm
         A6iA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vOz4U7z1;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id v18-20020a056638251200b0046922e192a1si170542jat.3.2023.12.08.08.57.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 08:57:05 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-67ac8e5566cso14264236d6.3
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 08:57:05 -0800 (PST)
X-Received: by 2002:a05:6214:d0:b0:67a:49c5:8cc3 with SMTP id
 f16-20020a05621400d000b0067a49c58cc3mr269853qvs.32.1702054625028; Fri, 08 Dec
 2023 08:57:05 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-24-iii@linux.ibm.com>
In-Reply-To: <20231121220155.1217090-24-iii@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 17:56:29 +0100
Message-ID: <CAG_fn=UBt2A75bOgZmh7q_dS08d0PD8wJRHpoJyUDXRPRk_exA@mail.gmail.com>
Subject: Re: [PATCH v2 23/33] s390/boot: Add the KMSAN runtime stub
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vOz4U7z1;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Nov 21, 2023 at 11:02=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> It should be possible to have inline functions in the s390 header
> files, which call kmsan_unpoison_memory(). The problem is that these
> header files might be included by the decompressor, which does not
> contain KMSAN runtime, causing linker errors.
>
> Not compiling these calls if __SANITIZE_MEMORY__ is not defined -
> either by changing kmsan-checks.h or at the call sites - may cause
> unintended side effects, since calling these functions from an
> uninstrumented code that is linked into the kernel is valid use case.
>
> One might want to explicitly distinguish between the kernel and the
> decompressor. Checking for a decompressor-specific #define is quite
> heavy-handed, and will have to be done at all call sites.
>
> A more generic approach is to provide a dummy kmsan_unpoison_memory()
> definition. This produces some runtime overhead, but only when building
> with CONFIG_KMSAN. The benefit is that it does not disturb the existing
> KMSAN build logic and call sites don't need to be changed.
>
> Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUBt2A75bOgZmh7q_dS08d0PD8wJRHpoJyUDXRPRk_exA%40mail.gmai=
l.com.
