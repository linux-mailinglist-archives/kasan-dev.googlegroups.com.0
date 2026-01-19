Return-Path: <kasan-dev+bncBCSL7B6LWYHBB57LXHFQMGQENLT2I4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B8328D3B56F
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 19:20:40 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-4801d21c280sf26814975e9.1
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Jan 2026 10:20:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768846840; cv=pass;
        d=google.com; s=arc-20240605;
        b=SL43KMnmBNgSo+Zbfa2z4fKCWD7auTbpQdiLabHLGRANAqazwZNvlUUN+6PywKvux/
         vMOrx5RfwQd1kLMdhL9awWd+rOTLw8VvR7vQwPBlN4VE15V5ZoQOq6cC/3NHZiFQuQbw
         bHiM+Gxaz5wRAbrj/JH0bSNshIVJUcaUHc1jXXrY/u6hbeU8OFmSdpwp4OL5SjA3d6gF
         NbH0ev3krK5szApj+T0t04A/1eXsgitQ+2MuE2zu487FloRzJBao9JDEgHQwIeUEwiPg
         IVIxq7VSMhFA0dPDGMFbu1Sc51oNN7Ub7w6fghqkIt8UILIPwIU2Q6PB6LoMm+6vuj03
         Ak6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:from:content-language:references:cc:to:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature
         :dkim-signature;
        bh=Vb3RDH3teuPqesK87MnlceVt5biJrg9dHia+fsj3rAw=;
        fh=y3ukZ57m2llAJT/57Um116V9d67iUZWRnyChToKzh5M=;
        b=OEIHuc2tSo1tfgTRDl+l/fL1Fr5+0Tn60FrtjNve09rfFGCh3cwUSs0Z1tgLLvKvHr
         X3bAEwwJFk0r4VIW7Ougr5FyAwkYO6gVnTT8rqEGdDWLhLhWrc4XP5jhgi7ONNwJGiVI
         nLv9F7LufbDdMF8aaaRLJWynElrswcvGGLBRoaVhoBvoLH71/u6Hyg047gbPpC+n27Qb
         G45xOicFJgj30/rbujIMi0qNrGJmjApUVRfKVX+4j3oyWeViBh1XBtipUMpxl0Z8w0xS
         vSZ1lYgBX1h40dxev11mV/Hwif8ExCxv2qpaXVCJjKv3eEgXf0uzZ5OW1IK0RZmtKALa
         oXJQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mEwowLfI;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768846840; x=1769451640; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Vb3RDH3teuPqesK87MnlceVt5biJrg9dHia+fsj3rAw=;
        b=lmsVUJqIkYuP3z2BK+kNa7uI4+5CbPUzLogKki9ZKwnh6LqywK1CtEtklwfpeLf8We
         be3FXCEuBWVk6ItCcWIfLJkyGCPiCuoHYjbfXZhR56MCx3c1FwDTav+JitKmwNL8hxan
         k82a1TZEYsA0uDTIAwewbEh64Taun0Lj/7f28Zfop/VFjI/qlpQwcE3RAUGS+ZFDOzke
         +Sj6HcBRASfIaBD6sijYTcuBD+V3wj054NnveG7iu9Lkob3f+t308r8VTjUd/yizTETx
         w3b4cVfPluDoc0TA1B98tJKKLvisHwMpdn30M0n6Fa3MqvpQyw5d75+yCaDRAUMn22sW
         fClA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768846840; x=1769451640; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to:from
         :content-language:references:cc:to:subject:user-agent:mime-version
         :date:message-id:from:to:cc:subject:date:message-id:reply-to;
        bh=Vb3RDH3teuPqesK87MnlceVt5biJrg9dHia+fsj3rAw=;
        b=DVTYC8739LfLftFBTeTbIBgYIa82e++RYqwGwHCZWBHkIdqMOLg2mbAnH0BxXv32Om
         P2BmxdPDgoKnwCdu0moQGXQvVFAnyEvH2bnVI5lPs/qBRagXxxwf1MPnIUTc6VbyUuaQ
         asUZhkILbipOUkP2xAnpk7RLIjFokYk+GtHblJsKHtjW+EAoKnHlfOSOmA+2gsvpQPLj
         T1TbpoIajSPDgjYgJOFc3mxRnjVadCCK57Iocv78qmJXESy4TanmVGLklIoCzHtALuLw
         5sQB4PsBSz8+M4ReNDUzzyQV1a8vmrqtqNJf1zEH1zW4SrU/NbMlUcfH5Q+tQhV5ADje
         pyVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768846840; x=1769451640;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :x-gm-gg:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=Vb3RDH3teuPqesK87MnlceVt5biJrg9dHia+fsj3rAw=;
        b=hecSWKowiLytyJrhNoc5Hcr51ZiDVg3OrodZXNg7C4hiYE9kG7GrGyErrGHTobFh+T
         /2Js/iAhV78H3jPOYa1JiZimAod96+QeSfFuuUpTipaGhncRKKm6EW0TcApdX3pefrLN
         9v8CJCoPBF4Jsic2DxOtNMbAl4rndNtV9wIyS7wHF0aaSnRk/xeQaSaHMrRjMgb4K4MR
         Qu3LB/52zKWPHUSw2gyeF9/0bEurbuXP/X8q/RDLXOBE1dNPkSKXaa96bGF3BgiNKtya
         79QFe1f0xiIGmawLtosdbtrriVjBZkHnQDYXyKoz2W15eGuEVJ+BsshZsGaEKDpHhXtD
         K9xA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCU7bXraTMWJHxKtE6Y/H/5Hggj4SDSkxfJP5H/luHJCUaDZFqbSK8qlbQhO35npxwTq0Ks6Cg==@lfdr.de
X-Gm-Message-State: AOJu0YyZwDOyH58vkxP/jWjg22vfcPgrjbbYrcaOUR7OtJIeJNmvNmCW
	zfApKXpZkPMR7J03vuOAaV+FX6c4dHw7VBo8A/6Md4NnMPyRQpweKnIW
X-Received: by 2002:a05:600c:8286:b0:480:259b:3705 with SMTP id 5b1f17b1804b1-480259b3772mr107411445e9.13.1768846839964;
        Mon, 19 Jan 2026 10:20:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gno2QWNol+uugpUwpyWuQwNgKFeGqsdbNmpRx1kS0wLg=="
Received: by 2002:a05:600c:8b16:b0:47e:ddf0:fd35 with SMTP id
 5b1f17b1804b1-47f3b7a574cls28585975e9.1.-pod-prod-01-eu; Mon, 19 Jan 2026
 10:20:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUFzAEDxOQcZ+kMVwBJgAgqsti+5foUtQqUlAjjiMAmD0R/41kH2Xb5zTI1dIZoR6T8TGwdkzaGFBc=@googlegroups.com
X-Received: by 2002:a05:600c:3e07:b0:480:3ad0:93bf with SMTP id 5b1f17b1804b1-4803ad094b1mr28821285e9.24.1768846837438;
        Mon, 19 Jan 2026 10:20:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768846837; cv=none;
        d=google.com; s=arc-20240605;
        b=XLrZmKWY7dzBWrijjcLu9day1qY37/jApnSdkj6SeM1qNY0JydsVAetPptAh9mfASR
         dyKJNoIAR40nYdt3L3NXuXWnXe470cDIyptesf5eRLajDtvQvRGO0hkFSVe/OndQ1Sak
         BQr3J7/7HN9u3WF/ghQLTJoKUZWr+pNOuZ/PiujXqmz49G8q+O5HTYiRhAnn+JTeoPik
         1WPDRGYvguzHPZ7wM2D5/gbxRKPRnLY9i7S1dJlK3sZX5S1B4kipgqeAwqkr0S8rXaUL
         3FMJvzDJWyncS2pQU/nibeNfonvBhmjYvTNPb0JrvV1f1ZBddnN2XXUDQf7+Bp7tOQLK
         oPBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=vSQyY/sbw+WW+mdZ495+fmp7dM6Z9X4lGB7EkpPTED8=;
        fh=aNrUdA5vaAW13WYl3oE6dLF1UOy9ATUw5M6ec4MPuO8=;
        b=hRn+w4pdGgxB/7ZCVlgzpN8S2jU7z0jSn2roFn+7W2oamSkA6JGUg2e97Tsfgg5WtC
         20toX14+OndkuCa50YECuitJNZ1M3atlIg25CPoCKKaQhVEsWuj5BEE1dKSvJxLasSk1
         K1ymY4g/YYbiAAMEp7n6ajGXgDTW2CR/20219aOW/xwp6hs8C/qHCP9zBIPFd9KaxcJg
         +9XK0ZpnkMWP8p3umC799BlBRihz50b0P2TWAj/icoiOIgB8VrcwuxuAe/qEWT+xOAgO
         IE+WeH7sCgQCw6sZPh6aMAXR7CrB2AkoiCorUFyQRAwSnlJqQCmVbklUJjmFE4lTWa9j
         84rg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=mEwowLfI;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x332.google.com (mail-wm1-x332.google.com. [2a00:1450:4864:20::332])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-435699214e2si183580f8f.1.2026.01.19.10.20.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 10:20:37 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::332 as permitted sender) client-ip=2a00:1450:4864:20::332;
Received: by mail-wm1-x332.google.com with SMTP id 5b1f17b1804b1-47ee47ff24aso2700085e9.1
        for <kasan-dev@googlegroups.com>; Mon, 19 Jan 2026 10:20:37 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV3aY4YNWHZb+YHAnSjZ66aYB71HS1psrNI5Po6u3JPoLEeP+267kgDar7e+a6nv7cl+3ty03k1UOc=@googlegroups.com
X-Gm-Gg: AZuq6aJoGGF6viRGFcPnac/jFmDOWVAOXS97vrgqOmgyIUY6gSmjM1l3eHhc61isZHR
	kBhB9zJ7XOzd0c9CU7amVm3bkZcK7eVe0pmR8VtHtpyCQOr6P3PqDpxqOEfzZ/mhI57QS4GxcCo
	Lt7o3iJLqnv7yXFLkk+NtqkEzcQ0IHcuu/ikpt3gkVFEuxDS/nLppxTqKUcODwv5XtYbOpMeH/f
	0z/4np+TLbRCnPWpHsug4llJu13NkNpmQ7UVIaw23cWhyOdkJtdKIYiRdJHgOOJrOMvWe2jwm6M
	bU6cnHZg8fb7xR459sXBfPqprsrwxN/muU5EEZidO0gIzY7OZDXzQbkCuvia1j8iHb8IiElNVqy
	tcgkpApSF2lYNd9jOmZLc09JWDksJYaXKe44k6+Dgj5yyaLl63bHiZ+IYGIsCxv7KSbCzBdJfwo
	tD8FdZuo+vla+24lbTzQ==
X-Received: by 2002:a05:6512:340e:b0:59d:c490:3ab9 with SMTP id 2adb3069b0e04-59dc4903b42mr330960e87.0.1768840488602;
        Mon, 19 Jan 2026 08:34:48 -0800 (PST)
Received: from [10.214.35.248] ([80.93.240.68])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-59baf3a6ff6sm3432421e87.102.2026.01.19.08.34.44
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Jan 2026 08:34:47 -0800 (PST)
Message-ID: <e273571e-ab8f-46d6-a44e-c1d0d06d3cbf@gmail.com>
Date: Mon, 19 Jan 2026 17:33:35 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>, corbet@lwn.net,
 morbo@google.com, rppt@kernel.org, lorenzo.stoakes@oracle.com,
 ubizjak@gmail.com, mingo@redhat.com, vincenzo.frascino@arm.com,
 maciej.wieczor-retman@intel.com, maz@kernel.org, catalin.marinas@arm.com,
 yeoreum.yun@arm.com, will@kernel.org, jackmanb@google.com,
 samuel.holland@sifive.com, glider@google.com, osandov@fb.com,
 nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org,
 akpm@linux-foundation.org, Liam.Howlett@oracle.com, kees@kernel.org,
 jan.kiszka@siemens.com, thomas.lendacky@amd.com, jeremy.linton@arm.com,
 dvyukov@google.com, axelrasmussen@google.com, leitao@debian.org,
 bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com,
 urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com,
 andreyknvl@gmail.com, weixugc@google.com, kbingham@kernel.org,
 vbabka@suse.cz, nathan@kernel.org, trintaeoitogc@gmail.com,
 samitolvanen@google.com, tglx@kernel.org, thuth@redhat.com,
 surenb@google.com, anshuman.khandual@arm.com, smostafa@google.com,
 yuanchu@google.com, ada.coupriediaz@arm.com, dave.hansen@linux.intel.com,
 kas@kernel.org, nick.desaulniers+lkml@gmail.com, david@kernel.org,
 bp@alien8.de, ardb@kernel.org, justinstitt@google.com
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, llvm@lists.linux.dev,
 linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org,
 linux-kbuild@vger.kernel.org, x86@kernel.org
References: <cover.1768233085.git.m.wieczorretman@pm.me>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=mEwowLfI;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::332
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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



On 1/12/26 6:26 PM, Maciej Wieczor-Retman wrote:

> =3D=3D=3D=3D=3D=3D=3D Compilation
> Clang was used to compile the series (make LLVM=3D1) since gcc doesn't
> seem to have support for KASAN tag-based compiler instrumentation on
> x86.
>=20


It appears that GCC nominally supports this, but in practice it does not wo=
rk.
Here is a minimal reproducer: https://godbolt.org/z/s85e11T5r

As far as I understand, calling a function through a tagged pointer is not
supported by the hardware, so GCC attempts to clear the tag before the call=
.
This behavior seems to be inherited from the userspace implementation of HW=
ASan (-fsanitize=3Dhwaddress).

I have filed a GCC bug report: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=
=3D123696

For the kernel, we probably do not want this masking at all, as effectively=
 99.9=E2=80=93100%
of function pointer calls are expected to be untagged anyway.

Clang does not appear to do this, not even for userspace.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/e=
273571e-ab8f-46d6-a44e-c1d0d06d3cbf%40gmail.com.
