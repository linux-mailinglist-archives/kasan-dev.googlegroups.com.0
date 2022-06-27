Return-Path: <kasan-dev+bncBDPYNU65Q4NRBZ7Q46KQMGQEYJYAJXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id E39EA55BB9F
	for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 20:35:20 +0200 (CEST)
Received: by mail-oo1-xc3e.google.com with SMTP id p17-20020a4aa251000000b00422e3b5627bsf622942ool.19
        for <lists+kasan-dev@lfdr.de>; Mon, 27 Jun 2022 11:35:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656354919; cv=pass;
        d=google.com; s=arc-20160816;
        b=fvIs4spxATFuXD9e8J5PrF3o0Gt2BmCxe3FXrbJc14PI2WBH3nYoRqMwZbm2jvk7Rt
         zn2R1wjCx4Ijc0c0W8S9FV6x9REh2KBtvV/AV5t8evBEV1CDq8nx9fWvNbZsugoYgXSk
         xGdeEHYcz+35ZHGuUiqUIl8ep51kiNBQ2HMDrbWGFBcqKtcTQqTovhVIdiuWzk+7jU5G
         0iUUZLu4RGn88fGqQKzvVyV6V9J0SilPU0O5pRde4ydDQbFsXfuB76Q0ofjim1gCL69N
         Fkoapip//806RNF0xZy+6VNtGCdmueiuuN6GgZ8DddmK0aJyb03GC3SQRu06KJcjock4
         zBag==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=8+2VOeHsaStLM/3m7UyoWSHn7a0sPTXIfKd4ZgVV5X0=;
        b=0IUYTD5n48kjYM6oTcf/cy9szCf93RSc69inxU3ab1xv+D7WRx3fSzlaf/k6b8x9AU
         b7zjR4SqGLcBkU+0ol7j/z/85vetExiaaRC6w9j89BBb1BA8yeGbwpFC7NCsiCxfitUM
         7zoPW5St0RTNx+FYnyyzG+5QyCMJgx3OuxY6dx3YgjNmVMTouxxTCdMxLpuzSGKRx3ZF
         Dfokh95LdZ1J3OApQ3IKvZ5UHB67i7JZeSbjtupvifxPoRhjjNi7d4+CUR+HGJSKSKne
         ubHKlRlVglG3Fs1DKqbbS/z8FUyYcCRMw1R6cUgZ93sPDD4kBQNIdT7oiD9GwXcVCM5U
         KNOw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V1wgnhWI;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:content-transfer-encoding:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8+2VOeHsaStLM/3m7UyoWSHn7a0sPTXIfKd4ZgVV5X0=;
        b=pNJwdzSywG2CdNSCUauc+NtcoX8EJm6VvIkTKkZw9SzG0GKq17bWT7JybJTWTIEbB/
         /AY5wyFkTjq1U3j6CrbVfR2/DaSi55ofm2FbcGp1kCi8lNhjiQ4apygxva93weQthwcH
         gMn5x4Z+G4GbA0u1kTr+WXXmRm/MKvNcQKcTKT3PzLWXo5odpyFxqAPo6HzMFBIWiKOd
         FF76RYnEA6jhZa8ZilaqJUTRatfKPYXRv8E1WkDTy0HIZ1GFssXONtE986W3kkD1Cp38
         JYC9FzwZZQZsw4BiXISZAbRE32j+ZaBF6ZD9YWpJAJajtYpv4KM3qPooMNi3tPh2CnHA
         ixyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=8+2VOeHsaStLM/3m7UyoWSHn7a0sPTXIfKd4ZgVV5X0=;
        b=yh8A3SQciIxW7JrCNVuZiwMuk/xIyphKXp4oxMKI82B9xdz3UXBZZ9+Vt7v4G1vYIb
         jkVQHwIXJaoA4iqZWvtpti5vcSeaLdvmtFbgU+Ec4d3DX0SFVTduQkkE7JC7uNDfuctw
         DjoJLGdoiclTsj7T/86OKOl1UBbMlqZicO5D6TRxW30cG3Co7+IVqqP41Y0qOvGFhHy6
         jMUp4HTcUHQ0sumfHSiiGgkiF4HlHDFPQ2PNCmQvYhMRPa0QXRdCyOCQu8yWxj3jaTPx
         eDJqasmkyf7oHRrqdms0yFwGOxoX8L9hD2KDeqbFky8wxHTVIkYSHvx+ltKJBkiOBnGv
         Fg+w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora8FNVp8EpOKgXegGtQ5whGbLrwyD6fyP3+9Zj0BxVa5aWx+ZbJi
	7hXWc7hwOqXo8yDBg3Gwx7U=
X-Google-Smtp-Source: AGRyM1t60WAmvFtE1WQhjW8uqKammLEqGONNl/eOrid3lX3tbL6Wu9jm93cp0AoIxxWUr0DN/GiTgA==
X-Received: by 2002:a05:6830:2647:b0:60c:6678:d7cc with SMTP id f7-20020a056830264700b0060c6678d7ccmr6519900otu.237.1656354919269;
        Mon, 27 Jun 2022 11:35:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:2af:0:b0:616:92a6:cdff with SMTP id 44-20020a9d02af000000b0061692a6cdffls2609052otl.3.gmail;
 Mon, 27 Jun 2022 11:35:18 -0700 (PDT)
X-Received: by 2002:a05:6830:3154:b0:60c:54e8:f684 with SMTP id c20-20020a056830315400b0060c54e8f684mr6364692ots.346.1656354918878;
        Mon, 27 Jun 2022 11:35:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656354918; cv=none;
        d=google.com; s=arc-20160816;
        b=JQ8Ivj5au2DqTjzTG/jFs+2hWW9ft9b1V6CH4J68QxZ1xuztTFivktMzwIT41iYvYa
         BOdN5tok8WsV0HkhAGkT78Q7K1ND7SljfQ83i0FgG7YNzpccmjcHuU27aauzBKjibTH/
         WBoSGF3ANd7vqoy0tud84YmmhzHoMROvXYlh3zy5mKHSgwRJ/rK8E1D0TK+Pu3sw8wgg
         P8SuMIVaV1K+CmCK5qvqW9+A6E7CX9Un3Suzk48slzz6wsqSlR3li80X18Od8py2DnMO
         RBzK/02vNwT0fsiAKbaAq8RN/Gek2dO1Prjre1huCFlK62r2bzyor01C9zNBPc5QHeYn
         SN6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=+8s8ewhW/lWJnywycRJQsKuRMfCGUDUhBfo6IQpyJww=;
        b=LLMhHWNJto4UgMELO3inLBQn3o9S0zn+A46V9QtO7dM7Vwv1kYTHwTBE7pMLmuC/3D
         PgGeYLo/R2m2FOhQ1h6Qld9iBpfpoXdEf51TqKKrrmMqIZqXf3u+ssE4gHuRINu6vJ3w
         BC6KlR5MNbLGD8Jmi8mLxPT1+JsbKGHiz2Gcw2rw8Mhpl1RzMhwAXvUy4jZiUAKOB2vc
         zU/XQDFCaiOsuvFL05OgMkVdMx1P0PdS1pu8j6vGsKQAUJXZmmRTRRjp43fc5qVRPaHf
         lFyfxvMkLGtnteCy5RTHdzzaxd0Wp5KfP1gnSVY8gxwXpJIUaDpndLkMKs7Wcr4KlJUa
         q2ag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=V1wgnhWI;
       spf=pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e19-20020a544f13000000b0032f7d36c37esi696514oiy.2.2022.06.27.11.35.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 27 Jun 2022 11:35:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 9EA6C61578;
	Mon, 27 Jun 2022 18:35:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 43D52C3411D;
	Mon, 27 Jun 2022 18:35:15 +0000 (UTC)
Date: Mon, 27 Jun 2022 20:35:13 +0200
From: "Gustavo A. R. Silva" <gustavoars@kernel.org>
To: Daniel Borkmann <daniel@iogearbox.net>
Cc: Kees Cook <keescook@chromium.org>, linux-kernel@vger.kernel.org,
	x86@kernel.org, dm-devel@redhat.com,
	linux-m68k@lists.linux-m68k.org, linux-mips@vger.kernel.org,
	linux-s390@vger.kernel.org, kvm@vger.kernel.org,
	intel-gfx@lists.freedesktop.org, dri-devel@lists.freedesktop.org,
	netdev@vger.kernel.org, bpf@vger.kernel.org,
	linux-btrfs@vger.kernel.org, linux-can@vger.kernel.org,
	linux-fsdevel@vger.kernel.org,
	linux1394-devel@lists.sourceforge.net, io-uring@vger.kernel.org,
	lvs-devel@vger.kernel.org, linux-mtd@lists.infradead.org,
	kasan-dev@googlegroups.com, linux-mmc@vger.kernel.org,
	nvdimm@lists.linux.dev, netfilter-devel@vger.kernel.org,
	coreteam@netfilter.org, linux-perf-users@vger.kernel.org,
	linux-raid@vger.kernel.org, linux-sctp@vger.kernel.org,
	linux-stm32@st-md-mailman.stormreply.com,
	linux-arm-kernel@lists.infradead.org, linux-scsi@vger.kernel.org,
	target-devel@vger.kernel.org, linux-usb@vger.kernel.org,
	virtualization@lists.linux-foundation.org,
	v9fs-developer@lists.sourceforge.net, linux-rdma@vger.kernel.org,
	alsa-devel@alsa-project.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH][next] treewide: uapi: Replace zero-length arrays with
 flexible-array members
Message-ID: <20220627183513.GA137875@embeddedor>
References: <20220627180432.GA136081@embeddedor>
 <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <6bc1e94c-ce1d-a074-7d0c-8dbe6ce22637@iogearbox.net>
X-Original-Sender: gustavoars@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=V1wgnhWI;       spf=pass
 (google.com: domain of gustavoars@kernel.org designates 2604:1380:4641:c500::1
 as permitted sender) smtp.mailfrom=gustavoars@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Mon, Jun 27, 2022 at 08:27:37PM +0200, Daniel Borkmann wrote:
> On 6/27/22 8:04 PM, Gustavo A. R. Silva wrote:
> > There is a regular need in the kernel to provide a way to declare
> > having a dynamically sized set of trailing elements in a structure.
> > Kernel code should always use =E2=80=9Cflexible array members=E2=80=9D[=
1] for these
> > cases. The older style of one-element or zero-length arrays should
> > no longer be used[2].
> >=20
> > This code was transformed with the help of Coccinelle:
> > (linux-5.19-rc2$ spatch --jobs $(getconf _NPROCESSORS_ONLN) --sp-file s=
cript.cocci --include-headers --dir . > output.patch)
> >=20
> > @@
> > identifier S, member, array;
> > type T1, T2;
> > @@
> >=20
> > struct S {
> >    ...
> >    T1 member;
> >    T2 array[
> > - 0
> >    ];
> > };
> >=20
> > -fstrict-flex-arrays=3D3 is coming and we need to land these changes
> > to prevent issues like these in the short future:
> >=20
> > ../fs/minix/dir.c:337:3: warning: 'strcpy' will always overflow; destin=
ation buffer has size 0,
> > but the source string has length 2 (including NUL byte) [-Wfortify-sour=
ce]
> > 		strcpy(de3->name, ".");
> > 		^
> >=20
> > Since these are all [0] to [] changes, the risk to UAPI is nearly zero.=
 If
> > this breaks anything, we can use a union with a new member name.
> >=20
> > [1] https://en.wikipedia.org/wiki/Flexible_array_member
> > [2] https://www.kernel.org/doc/html/v5.16/process/deprecated.html#zero-=
length-and-one-element-arrays
> >=20
> > Link: https://github.com/KSPP/linux/issues/78
> > Build-tested-by: https://lore.kernel.org/lkml/62b675ec.wKX6AOZ6cbE71vtF=
%25lkp@intel.com/
> > Signed-off-by: Gustavo A. R. Silva <gustavoars@kernel.org>
> > ---
> > Hi all!
> >=20
> > JFYI: I'm adding this to my -next tree. :)
>=20
> Fyi, this breaks BPF CI:

Thanks for the report! It seems the 0-day robot didn't catch that one.
I'll fix it up right away. :)

--
Gustavo

>=20
> https://github.com/kernel-patches/bpf/runs/7078719372?check_suite_focus=
=3Dtrue
>=20
>   [...]
>   progs/map_ptr_kern.c:314:26: error: field 'trie_key' with variable size=
d type 'struct bpf_lpm_trie_key' not at the end of a struct or class is a G=
NU extension [-Werror,-Wgnu-variable-sized-type-not-at-end]
>           struct bpf_lpm_trie_key trie_key;
>                                   ^
>   1 error generated.
>   make: *** [Makefile:519: /tmp/runner/work/bpf/bpf/tools/testing/selftes=
ts/bpf/map_ptr_kern.o] Error 1
>   make: *** Waiting for unfinished jobs....
>   Error: Process completed with exit code 2.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20220627183513.GA137875%40embeddedor.
