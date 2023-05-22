Return-Path: <kasan-dev+bncBD52JJ7JXILRBC75V6RQMGQEM3LWTXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x740.google.com (mail-qk1-x740.google.com [IPv6:2607:f8b0:4864:20::740])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D1FA70CEBD
	for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 01:45:17 +0200 (CEST)
Received: by mail-qk1-x740.google.com with SMTP id af79cd13be357-75b17aa340fsf195911685a.3
        for <lists+kasan-dev@lfdr.de>; Mon, 22 May 2023 16:45:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684799116; cv=pass;
        d=google.com; s=arc-20160816;
        b=r4QYXxqvj/gLaQrydYEl2Oz3VQn7S1zOXPZPCiHfyCOQyYdt3MhK5TjY7rzvZemwdS
         tXqccSZ33F2+9dFQnQb1GQ7wd1rroO5LCEp6F/fMyBnOi23j/cIEznfb30ulBKLpjD/t
         Peg6GIild3DLKWp3AyEZAShoktlTRymd+rKuFdwDI3fRbHGsDyi8xI/QsfCqXePlUNLl
         Na5XP02NOEtSAmGnB3urIfho2Jc4UfVD+Er8bcwC7XqI3QeO76PSKR1skLF23MhKF7OY
         fjIswa4PnD8Y0V6lS55JduftLzkBh065q8ChnUB2eTASIaYst/aMM+gqcEUN3coaPThX
         VjnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=vU3IcVQh+KV9BhgKgu633X0JXQ6/9uNZ+c3990//W4Q=;
        b=nm+sLlvSjKYrNtktb6j0kHDWybD4qYHVoFK915BoNVS0+2PgeVpaEsIo71E5E5dqL5
         miWTcgpleeRR83Gt5ybFzeKYcsf7po2ANoB8keEGXp0LWQl+AMC4CI4rJsSJdY/YZJn+
         hgIiYZQxXN2TR311oOYTXcXzKgQIgWxdi10yJlUPFem5nkYPeTc8J0r8RATDogKYeja+
         daCXRysqxELiqciJBEoTUtfup72IzqX8+B2krZCZNNT1eJKF2NQ6p9g5rTDFHnENe5Bu
         Sx6I/4XtUs5hJJyYBy3eBpkL7MHUsoH6NxJoM4YCr5s4t/KmXdfsjJnJ214iBB8I16NZ
         AWuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1RihYSk6;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684799116; x=1687391116;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=vU3IcVQh+KV9BhgKgu633X0JXQ6/9uNZ+c3990//W4Q=;
        b=kaQrsUEQvym6ThpC4iOTWtRPY0klNvelKX5wc/runYPZp4ncM3gcCSLv/y1mVrbWtA
         hT8mVPF7uU3R8f0BqT2EUubtPzZ4l8en3tDKWo533UejMUvnwt8tlkeaH007hEK6maTI
         pe5ERkUo5gvssig5guKbO9wtBTraRGhPDNpIhW4+LAa74cUn2279jYFgWmRmMaaL3sx4
         If+NDkNKkdW8/vuR+ICIJDgxMTwbWFOcifRPMzxPTVWvz53Rc72naeVhOwiywaXAzjfA
         hP5xyk08qaQbWPmH+usY6EWL97IF6oEkNdaSjIbjuuRvaJsH91Ro9DHhAjGIOWJuEXKB
         AcXA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684799116; x=1687391116;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vU3IcVQh+KV9BhgKgu633X0JXQ6/9uNZ+c3990//W4Q=;
        b=A6BiSFpmzgUaBEEF/lL5A4TFaBsCpHVdNdh+2ovmM4Gt1cj/W69vVR6pZedvblGK/9
         X5w9pDdxFidSvQzGKvbbJ1Ft8fqcqwAtRwOAS4ToGr27EQn87Nh91ZxM50/NiKrCrI5/
         XWAyiWFM9RtrQ5P5qWmN52LJby7XB8ShYjqhg5mZZMa/Hrt56CNLFhD/CkLU7SUH6MV/
         aJOA2hxW21rD5PUWuwoE+wu9X0cNsfUASU2BcmBSu3Lo89T958jnE11pKXGSOmbYCBjX
         HTDwxNqkINsrBOdoL+1k4VJ9D4zr/73n3ynwxkcJrn0mgILrBqaWeGItaPaQ/M6MoMdW
         GpiQ==
X-Gm-Message-State: AC+VfDziiq8Xzyi/UDt/bDCTOCRtyp1PS2T2/evxjdM7wxmQ/tUREF+V
	+r6WXbEiGWW9WGgAXWNFkOM=
X-Google-Smtp-Source: ACHHUZ74s/CUlLKC+tx4Cl+TSDA9vBS0MLjz3PQPb6ssbkhvsgAY+YYJy+G3+CykuX+pYduEYKBitw==
X-Received: by 2002:a05:620a:2450:b0:759:4381:d767 with SMTP id h16-20020a05620a245000b007594381d767mr4100426qkn.11.1684799116032;
        Mon, 22 May 2023 16:45:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:59c8:0:b0:625:84a2:1d97 with SMTP id el8-20020ad459c8000000b0062584a21d97ls2250514qvb.1.-pod-prod-09-us;
 Mon, 22 May 2023 16:45:15 -0700 (PDT)
X-Received: by 2002:a05:6214:20e2:b0:622:199c:c4d0 with SMTP id 2-20020a05621420e200b00622199cc4d0mr16212598qvk.15.1684799115552;
        Mon, 22 May 2023 16:45:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684799115; cv=none;
        d=google.com; s=arc-20160816;
        b=Y8ijgtPVHasvq6xhAqx8PUIHhW88uHV7IcLRwgAOF1Ne9TXxHbbRD/Ro+ZDoPuGy/y
         9/nMPW7RLiPzlfsbSiwHSbSfUVNiBTJH2vDlghxwH/hoIFWPFhajXvxfUt9+5q1n3yJt
         aGuEFG4O/wz0Fo5pdfXkq7ekG450gulevcQI9xMIAkxCy6tpmzfL4tQ28gN05wh9ZX1j
         eUrbdGXiPdkpZlmXhxuhb5ZnYsXT/4GA0qvm+kao+NhLtp9d3uvxf6MtJFeABfLCkrUA
         khwBddlabVm396fA5weC+gNT+xhTMo8S0vi2/i0ph6SVUogBVGAtMA59fa4U1/Dg32pt
         Q1kA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=krhUajFGwK9L4o6aKxZVhfmKxVJjexnutJuCxQxG8Gg=;
        b=h0ipedhjjYeZgy4WyuMNvnELMeF64GcQ5JcEiZDic54yOrb53rnktyxWOdOks4vpET
         6EdlFb3incQ96RzxILMQ5FcDN/cN4sfTkrEecFQc3zvobAhjcyyeBLrE5+YR4wkOXQPo
         2Lu0MwPH4ngnsojnD4gSQMocRnM4jMfHwPjI4m1Eku7l8+ZcbADTakwTK8wcXre+T2RL
         +gA9yXk4P7gtiJdsR0gZTX2+o+KUZsJ0uGxssXpfd8FeG644KRV/s2kVGRiQAMa0r+4M
         bC4hdkFgF0NXaJp/Mdat+m+XJ7Y3aRO/ov16tQm/N0vT/1yHJVSTgePawEDVnbnWCsXx
         3BlQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=1RihYSk6;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id k4-20020a0cd684000000b006238adde012si514617qvi.0.2023.05.22.16.45.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 May 2023 16:45:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id d75a77b69052e-3f6a6e9d90dso89731cf.0
        for <kasan-dev@googlegroups.com>; Mon, 22 May 2023 16:45:15 -0700 (PDT)
X-Received: by 2002:ac8:598e:0:b0:3ed:86f6:6eab with SMTP id
 e14-20020ac8598e000000b003ed86f66eabmr104822qte.14.1684799115109; Mon, 22 May
 2023 16:45:15 -0700 (PDT)
MIME-Version: 1.0
References: <20230517022115.3033604-1-pcc@google.com> <20230517022115.3033604-4-pcc@google.com>
 <ZGepsWDEfG+gk/t3@arm.com>
In-Reply-To: <ZGepsWDEfG+gk/t3@arm.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 22 May 2023 16:45:03 -0700
Message-ID: <CAMn1gO4pWpcu_F_vbfeURQX85hp9aRLWTwDyDRB=eZEKM_hb9A@mail.gmail.com>
Subject: Re: [PATCH v3 3/3] arm64: mte: Simplify swap tag restoration logic
To: Catalin Marinas <catalin.marinas@arm.com>
Cc: =?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>, 
	"david@redhat.com" <david@redhat.com>, =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	=?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?= <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=1RihYSk6;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::836 as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

Hi Catalin,

On Fri, May 19, 2023 at 9:54=E2=80=AFAM Catalin Marinas <catalin.marinas@ar=
m.com> wrote:
>
> On Tue, May 16, 2023 at 07:21:13PM -0700, Peter Collingbourne wrote:
> > As a result of the previous two patches, there are no circumstances
> > in which a swapped-in page is installed in a page table without first
> > having arch_swap_restore() called on it. Therefore, we no longer need
> > the logic in set_pte_at() that restores the tags, so remove it.
> >
> > Because we can now rely on the page being locked, we no longer need to
> > handle the case where a page is having its tags restored by multiple ta=
sks
> > concurrently, so we can slightly simplify the logic in mte_restore_tags=
().
> [...]
> > diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
> > index cd508ba80ab1..3a78bf1b1364 100644
> > --- a/arch/arm64/mm/mteswap.c
> > +++ b/arch/arm64/mm/mteswap.c
> > @@ -53,10 +53,9 @@ void mte_restore_tags(swp_entry_t entry, struct page=
 *page)
> >       if (!tags)
> >               return;
> >
> > -     if (try_page_mte_tagging(page)) {
> > -             mte_restore_page_tags(page_address(page), tags);
> > -             set_page_mte_tagged(page);
> > -     }
> > +     WARN_ON_ONCE(!try_page_mte_tagging(page));
> > +     mte_restore_page_tags(page_address(page), tags);
> > +     set_page_mte_tagged(page);
> >  }
>
> Can we have a situation where two processes share the same swap pte
> (CoW) and they both enter the do_swap_page() or the unuse_pte() paths
> triggering this warning?

Having examined the code more closely, I realized that this is
possible with two do_swap_page() calls on CoW shared pages (or
do_swap_page() followed by unuse_pte()), because the swapcache page
will be shared between the tasks and so they will both call
arch_swap_restore() on the same page. I was able to provoke the
warning with the following program:

#include <sys/mman.h>
#include <unistd.h>

int main() {
  char *p =3D mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_MTE,
MAP_ANON|MAP_PRIVATE, -1, 0);
  p[0] =3D 1;
  madvise(p, 4096, MADV_PAGEOUT);
  fork();
  return p[0];
}

I will send a v4 with this hunk removed.

> Other than that, the looks nice, it simplifies the logic and probably
> saves a few cycles as well on the set_pte_at() path.
>
> Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>

Thanks for the review!

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO4pWpcu_F_vbfeURQX85hp9aRLWTwDyDRB%3DeZEKM_hb9A%40mail.gmai=
l.com.
