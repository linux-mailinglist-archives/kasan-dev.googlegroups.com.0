Return-Path: <kasan-dev+bncBAABBC5EROQQMGQEUDL3JLQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 598C96CBDF8
	for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 13:39:57 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id c2-20020a62f842000000b0062d93664ad5sf1702617pfm.19
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Mar 2023 04:39:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680003596; cv=pass;
        d=google.com; s=arc-20160816;
        b=tfH9TBZsz/KQmRNYtc3yZgTqtH7RYaZfLGOR1KURUWQfGHUhP8ABTDhbUOPvycOp3O
         rx/jdIxSbM+Y7xV1PUpckStnPU1jePLT8YnWuA8b/uNOOXFo1pfEn6YXHGyAF35qq1Uc
         tLMD1MC6Bw42ZVRaTahFTVajk3yU/p6I4ZZqwzVKInn//s9WOFvdLbcZQGq1Pj23nQu3
         z5dY9gKlHTatHa68KagJpqqyAO9WBp3Fw9DCdxN6Njwez98Slq+dQPVfmXUtPKnb3sgK
         2hl6Rb3IJO5M1iCaFA6C7Q2paMEg5ijCS1bwSntOjH58zbe2zXRYcq0RlM2XBeudJ+Gk
         zInA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :content-transfer-encoding:references:in-reply-to:date:cc:to:from
         :subject:message-id:dkim-signature;
        bh=vjsX/nPGRw+HprnncHCapDg5eCgX2yknVPwIQmdVhXA=;
        b=mCthClPVyVYmxd1BUc18xeg0ZM0Xh8FUvuUc/A2qLGzkhmvptSywSjOQN0nkcFQgrd
         OXFZctu/vpN59Gdmx180SDn3s+hKlFF23HDIlyqrklWBFmr7BfKThBGJabNTSqg+JLyU
         8uJKQ+QwlijYDG0eAmxDTTkBUwdRgWYUvffY2p7gaobOAG6bx1MX2CbtGxult1ZA+AZx
         KdgziMxsQ+IZAX/zscQOCl07DNYL1rx51cygAWYm78YS/FA1NnkWdWn+Zpop0A+LRYWH
         zefrIlWEpDYuoztStgfUg1vDmiWszmY/m3hwMm6Bc7eS9MLUF7zatrSWRmPThm4LFDFK
         o3gQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=LCrSQT3N;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680003596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:from:to:cc:subject:date:message-id
         :reply-to;
        bh=vjsX/nPGRw+HprnncHCapDg5eCgX2yknVPwIQmdVhXA=;
        b=m2NFuvikX4U+XM8WLozvBoXI+anH2z84gdXsvs/kdOtq92hfVMet/u1nKijAYMJhgC
         cGQO++7Kc2AW14XikeSaoiqwwWMrj/YV6vmWugSYfUBYYPnH6Jdfjx6iI+l9F8BWT3t8
         e2ffDVL7iiWur/srb9Z8fIXnhoHRKQuhDNrPlgcLZH6qe9itvMY/l39U5TPNiTwp3hO9
         6ZO2t8EIZg0CBnuy1I/Ks4zvatsi+FymdYIvGaZ9LzN9wbXowoamSVdnUoWYdcnfX5RJ
         b8UMYktM6m3cLrD77lLOcADci+2UBaIUGSCPSpw6bSZuMBq4YZpSlPJfZMdLb2F1nl8T
         FX2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680003596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:content-transfer-encoding:references:in-reply-to:date:cc
         :to:from:subject:message-id:x-gm-message-state:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vjsX/nPGRw+HprnncHCapDg5eCgX2yknVPwIQmdVhXA=;
        b=Ujei0lCLcPtF2lN8iG8g+nFR+ZRzYGGXhyijQ8fduXRKlvm5QuYznur4vvuIgX2lFe
         UcgqbFuk0gpm55lEmOXV/OJS88dvfXHaSCmdA12ufAwnzx9gevjAmmQFN3egGNYueIr6
         6OrwPOea7R+RECsf33UlRi2p06b8FBZpgylzMPavImPUimxTlEeBU72KhAjAPQWoZD1i
         aK+DJh4tyOQ72PsSjnMc2dAghurwJTfezbQy/m7xbGy2HYVz/m20593+FbZ/DiDaq570
         cIsUpKj2g32teOn9flztiztniW2DYCFBA0WpfjsUOVr+8V/NVOBEeraawFHHlEskeej6
         G3yA==
X-Gm-Message-State: AAQBX9cStzei+KtY3rOeZQG6KfVfMcPsjbgOLws50eAt6b7QcfJ/Bund
	pFCYfzJqdUoO8+RzYbcyCNw=
X-Google-Smtp-Source: AKy350aS6UQPZ+kotU/rbzUu39vIsNSFjFc0kbN21R6eZa1kTmZbq4PL9zC96+xOPanoyhd/3sdaug==
X-Received: by 2002:a17:902:ba94:b0:19e:f660:81ee with SMTP id k20-20020a170902ba9400b0019ef66081eemr5251056pls.2.1680003595791;
        Tue, 28 Mar 2023 04:39:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:62c3:b0:236:6df7:76b0 with SMTP id
 k3-20020a17090a62c300b002366df776b0ls10454233pjs.2.-pod-canary-gmail; Tue, 28
 Mar 2023 04:39:55 -0700 (PDT)
X-Received: by 2002:a17:90a:1947:b0:23f:962e:825d with SMTP id 7-20020a17090a194700b0023f962e825dmr14292319pjh.1.1680003595172;
        Tue, 28 Mar 2023 04:39:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680003595; cv=none;
        d=google.com; s=arc-20160816;
        b=u9jAwG4VYgm4h486QfRXEZaOpexsPeg7XskXCQ1XdSxmW+bTfySw2oTIONnsMom2HK
         VTVmPQ0o86sEd5EyKebUqHlbZYyBHQaTU8Kf8vKTttFQMK5zK3cNyY4tKKQZS9Db1Zp7
         YbOj7euJdvfQSsL5UnHeVaZJFBCMmLJgLRTM5nwpr39hnEz3eBy62dXgurcuXMF15O7C
         bSQevFP523rLe1rL9fVpBydWOFD6B5rNniF989PEfkz+Fc4Z0VHIAqaze2rdR98CsZ8d
         24WVVcYbRcTyL9zHjQTYI5XfMTah2H0DC0a8wgJwCh8zFOHPr/phSrcDzdzUAc4z1yWu
         IQ5A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=SzulNji4opou7lgojxtUyQ4UHhhPqbMH3w+G5a9zDiw=;
        b=zxCAFBlwXOnjF1zfOx5InwsAwemzvOLodjcIRlH2oImyC1LcmHcufnsy58JakaUmB4
         XFkzv9/kgW/vQgmVRGd4EQqDV36LAhzsvbJa7qY6iZSpgrZhO10fKhno9lWj9kx1c20V
         upMI4fpGkAfFmoYUnXac0j4p8kXb764itForxQOeA/a9UuYnNmqUi9fcSOjB/bjlBwF5
         TqVYP+lf3ZxLTo00ey6j3IQrdLzWyeCag+ucdnhuoAU3xOXLM6xpmkScb6I6c7F0t67b
         ljYgZUPTWAGvViXHaQ4D59sisHIiTSTPS6cbcQCc5/fBkQDTnUEVp+eeJGXGKfkIgflw
         yFhw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@xry111.site header.s=default header.b=LCrSQT3N;
       spf=pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) smtp.mailfrom=xry111@xry111.site;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
Received: from xry111.site (xry111.site. [89.208.246.23])
        by gmr-mx.google.com with ESMTPS id x23-20020a17090aca1700b00229ee755cffsi98216pjt.2.2023.03.28.04.39.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 28 Mar 2023 04:39:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of xry111@xry111.site designates 89.208.246.23 as permitted sender) client-ip=89.208.246.23;
Received: from localhost.localdomain (xry111.site [IPv6:2001:470:683e::1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature ECDSA (P-384) server-digest SHA384)
	(Client did not present a certificate)
	(Authenticated sender: xry111@xry111.site)
	by xry111.site (Postfix) with ESMTPSA id 6E7A365BFC;
	Tue, 28 Mar 2023 07:39:45 -0400 (EDT)
Message-ID: <9817aaa043e9f0ed964bd523773447bd64f6e2c0.camel@xry111.site>
Subject: Re: [PATCH] LoongArch: Add kernel address sanitizer support
From: "'Xi Ruoyao' via kasan-dev" <kasan-dev@googlegroups.com>
To: Qing Zhang <zhangqing@loongson.cn>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>,  Jonathan Corbet <corbet@lwn.net>, Huacai Chen
 <chenhuacai@kernel.org>, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Andrey Konovalov
 <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo
 Frascino <vincenzo.frascino@arm.com>, WANG Xuerui <kernel@xen0n.name>,
 Jiaxun Yang <jiaxun.yang@flygoat.com>, kasan-dev@googlegroups.com, 
 linux-doc@vger.kernel.org, linux-mm@kvack.org, loongarch@lists.linux.dev, 
 linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Date: Tue, 28 Mar 2023 19:39:42 +0800
In-Reply-To: <20230328111714.2056-1-zhangqing@loongson.cn>
References: <20230328111714.2056-1-zhangqing@loongson.cn>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
User-Agent: Evolution 3.48.0
MIME-Version: 1.0
X-Original-Sender: xry111@xry111.site
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@xry111.site header.s=default header.b=LCrSQT3N;       spf=pass
 (google.com: domain of xry111@xry111.site designates 89.208.246.23 as
 permitted sender) smtp.mailfrom=xry111@xry111.site;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=xry111.site
X-Original-From: Xi Ruoyao <xry111@xry111.site>
Reply-To: Xi Ruoyao <xry111@xry111.site>
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

On Tue, 2023-03-28 at 19:17 +0800, Qing Zhang wrote:

/* snip */


> -void * __init relocate_kernel(void)
> +unsigned long __init relocate_kernel(void)

Why we must modify relocate_kernel for KASAN?

> =C2=A0{
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unsigned long kernel_leng=
th;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0unsigned long random_offs=
et =3D 0;
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0void *location_new =3D _t=
ext; /* Default to original kernel start */
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0void *kernel_entry =3D start_k=
ernel; /* Default to original kernel entry point */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0char *cmdline =3D early_i=
oremap(fw_arg1, COMMAND_LINE_SIZE); /* Boot command line is passed in fw_ar=
g1 */
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0strscpy(boot_command_line=
, cmdline, COMMAND_LINE_SIZE);
> @@ -190,9 +189,6 @@ void * __init relocate_kernel(void)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0reloc_offset +=3D random_offset;
> =C2=A0
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0/* Return the new kernel's entry point */
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0kernel_entry =3D RELOCATED_KASLR(start_kernel);
> -
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0/* The current thread is now within the relocated k=
ernel */
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0__current_thread_info =3D RELOCATED_KASLR(__current=
_thread_info);
> =C2=A0
> @@ -204,7 +200,7 @@ void * __init relocate_kernel(void)
> =C2=A0
> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0relocate_absolute(random_=
offset);
> =C2=A0
> -=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return kernel_entry;
> +=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0return random_offset;

--=20
Xi Ruoyao <xry111@xry111.site>
School of Aerospace Science and Technology, Xidian University

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9817aaa043e9f0ed964bd523773447bd64f6e2c0.camel%40xry111.site.
