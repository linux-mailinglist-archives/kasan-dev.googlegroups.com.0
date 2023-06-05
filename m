Return-Path: <kasan-dev+bncBD52JJ7JXILRBRN47CRQMGQE4QR6VHA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x638.google.com (mail-pl1-x638.google.com [IPv6:2607:f8b0:4864:20::638])
	by mail.lfdr.de (Postfix) with ESMTPS id F31DD722DC4
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Jun 2023 19:41:26 +0200 (CEST)
Received: by mail-pl1-x638.google.com with SMTP id d9443c01a7336-1b04aec3428sf19551905ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Jun 2023 10:41:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1685986885; cv=pass;
        d=google.com; s=arc-20160816;
        b=NsejGj/xO3TszyDSRMM61QZP0oDLcDnatZTWCuiYs8Txse91pI3GVEsOd17SzULzK4
         UrsoEK2oggr+QyTIEMmGL3dg0iePjumi2gVwRZVCXEYF/avSJ5Aq11orkuAYvGCe70jg
         NAqUZ1Aq2R9aqfVrS0RYhHLhD9Ox/W+DL5tQUOhj0jGnTcp79yIBTemtSDD3mdl6S3py
         +L7vxJUMOlcOQg9cl18IY3sQHOpMfSarfcGhags8lv8wYyuT1OImW0cNz5bBD2g4e1Oz
         TVsRxRE0k+nwOyrYsx+HetdCHXPvA1T4k59xaxL0SLo3Wd8/ODCM63pBI5iKcMyRoN1E
         ihDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Av8KRslr9mnWtBRVDqbWL2877/xkJGilda0MvNFSwlc=;
        b=yRddzBHZzXtjvGfSPm6SeusiM5ldcRaeaAGHUI4uX3B2x9XUxxNMDTcrKQ1xzjnkJG
         gGF2Zl41rcdakwxYMDw6W4FQZvC7x0ZTqiWBVM5F1/P4CDS6fGNB1lmOnZsvkszJPwU1
         8i3lIv80UNXwzizpR8Lv3Nm8dH63uHjmxkeeUcN5Sv+nwnTQR1JW3HOSG/P3jNXuhwkh
         LobFyVB7pqvLYYe0T6sPky23VvllhfNPqejOL2eiUB6rslGOYSXghy470TQigI4xQFAo
         y8DtqYVZ38SbcepGT7hMkpfZ9OHnAOeDDgqRZ7DXLfsShwym8p99/VlMupkzyjOJ1mh4
         AJSg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=M6gD9hlJ;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1685986885; x=1688578885;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Av8KRslr9mnWtBRVDqbWL2877/xkJGilda0MvNFSwlc=;
        b=gevRViMdWI4V6qN3gJMOIKUSVGZ/Abw+s6om8gvNZoT1V0m927lHSKnX4GufCStJZI
         hv9eg3QDzN/H71SwZ314B9bYxj1uP1SojrhpHxi+fzHl6TKxv/8LpJkGemL/3Y8blKT5
         goi/1uUqAQhSwPgDdLLHdl9guuxYf9ig6scAZOY0U/I8WPz2maJq6rJGeYYb5PVVA5ta
         jL65U6VeByD+swCxjybqhTYQmx/70lMNWcVlEet6UzHDAgw4Uhm/PsfuV77xAOz4zHIb
         oJxF7QIlkVjRe6dBkvXcFB3u+QhLuVdA7XIb4K6gJpHIy5rsfFgevllkv10K87ByOG5j
         CnHw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1685986885; x=1688578885;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Av8KRslr9mnWtBRVDqbWL2877/xkJGilda0MvNFSwlc=;
        b=YJXD8Pz0bKDSiUVYCl3U92DuxBvwhEHyf8IrVnGl8RTMFc2LgvZZO/oBv6rLf5W0Ad
         AoGZmhE4uOSI4Lk22/1WXd4eFcQcCK2kNvSAKsg1yAzu0tG2VFZW3nI7GiLHfm6goqUP
         3HBZ+BTT8ZZONCCxjNTwNhMpTuJPuLu68TIDJ6Bj5Ybc08ACZmeJXNV5KHmwylxu26sn
         KlKMRkVLw92fXy4qYQvTWvDcp1zZ6HapoMIJP+2nSO6bcxAcwgzOb9UMVA91GR9nhYkX
         4tLists73PBg6L6yreg1qHOipKRmeIsmnv8J4e6QV8vWhONJyHffYWfXmpGD8bqcV1pi
         YI+Q==
X-Gm-Message-State: AC+VfDwgjwqhq3aYzQy3ON8O1u0sWySAZBxzoOS/U+/H5lLAYZG87diY
	XlVCGCCSm/ehrvkczP/fkMw=
X-Google-Smtp-Source: ACHHUZ4Jihzqnu701ti7YXVR+sdspahVdk5S/pfshDvvpUScTyuticK80gQnloAalijS/xi233WKCA==
X-Received: by 2002:a17:903:244a:b0:1b0:5e0f:16a5 with SMTP id l10-20020a170903244a00b001b05e0f16a5mr4245353pls.11.1685986885279;
        Mon, 05 Jun 2023 10:41:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:33c5:b0:1b0:36bf:b725 with SMTP id
 kc5-20020a17090333c500b001b036bfb725ls781396plb.1.-pod-prod-05-us; Mon, 05
 Jun 2023 10:41:24 -0700 (PDT)
X-Received: by 2002:a17:903:2302:b0:1b0:4a2:590f with SMTP id d2-20020a170903230200b001b004a2590fmr4148085plh.28.1685986884481;
        Mon, 05 Jun 2023 10:41:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1685986884; cv=none;
        d=google.com; s=arc-20160816;
        b=MkDzD3zsQe5KSSSaMFJsH5/trCrQ7FFDM6MsBqI6cP0N/qUvqlnSgFnn1ZAEOQxCUQ
         ropYjJAeN42QbZy16x8Q8BK7G6jmbVTPUakqBl8ETafkM8RmdrqrqwQhMuK44xl/turl
         5wWRSOfPjjI3t2juiiF8Sw32yI9UEhh7A3ggX38LP5ZXsXUBzLTIea1x/MAAwaLxaa+n
         xEhzS5qc0z1z6K/5BTu4IdO9jpaIgBCEojFJ3n+2HPtfPbdLCT/Llzh7e0XQwDlMU7eb
         em2YwYJj/v+ggaUBuDHzolbMvJ2OKZh5N2JF4XAY4Cr7v/WW5xo3VWteBhy/ysL34IMv
         hDYA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=yUlwMMqaluEB3AWNinGyHM3bHJ/UF1t/FsSOYIiiPMM=;
        b=orTWCjIKSzkirza2tizp3rfHlTkwZQdAMhqhsP+2Kr4Fa625qgeTCCkZbRphWB6gUC
         +wp/wGXidMw38jswkjFyvVUafZXu7mwf3Nlp7iYAm8/c6zYVPsaAR2NFA4yGqia1jm4k
         Fu9duVOs3xUH8lpueCToEE6UHHoxMo7NgcgD6xy0VP7g4tvKSiwdpHBE3oRdu0TzyBj/
         C59Nh5MK17igLFxMId9M2/mzJuuuNc9ZafjKi8lkHE4s/x0EAr25QWWCGdWlG+msMz8s
         hV5ggYHZBrDgIO4OqigW1ALQeGW/hhTJ+ScARKn1xft8H/w1MH270311KnEllPRS4j+g
         VaMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=M6gD9hlJ;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12a as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12a.google.com (mail-il1-x12a.google.com. [2607:f8b0:4864:20::12a])
        by gmr-mx.google.com with ESMTPS id m18-20020a170902d19200b001b049988297si692719plb.13.2023.06.05.10.41.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 05 Jun 2023 10:41:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12a as permitted sender) client-ip=2607:f8b0:4864:20::12a;
Received: by mail-il1-x12a.google.com with SMTP id e9e14a558f8ab-33dea7d5424so13265ab.1
        for <kasan-dev@googlegroups.com>; Mon, 05 Jun 2023 10:41:24 -0700 (PDT)
X-Received: by 2002:a05:6e02:20e4:b0:33d:4e7a:3dac with SMTP id
 q4-20020a056e0220e400b0033d4e7a3dacmr19385ilv.3.1685986883754; Mon, 05 Jun
 2023 10:41:23 -0700 (PDT)
MIME-Version: 1.0
References: <20230523004312.1807357-1-pcc@google.com> <20230523004312.1807357-2-pcc@google.com>
 <20230605140554.GC21212@willie-the-truck>
In-Reply-To: <20230605140554.GC21212@willie-the-truck>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Jun 2023 10:41:12 -0700
Message-ID: <CAMn1gO4k=rg96GVsPW6Aaz12c7hS0TYcgVR7y38x7pUsbfwg5A@mail.gmail.com>
Subject: Re: [PATCH v4 1/3] mm: Call arch_swap_restore() from do_swap_page()
To: Will Deacon <will@kernel.org>
Cc: akpm@linux-foundation.org, Catalin Marinas <catalin.marinas@arm.com>, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>, 
	"david@redhat.com" <david@redhat.com>, =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	=?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?= <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, eugenis@google.com, 
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=M6gD9hlJ;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12a as
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

On Mon, Jun 5, 2023 at 7:06=E2=80=AFAM Will Deacon <will@kernel.org> wrote:
>
> Hi Peter,
>
> On Mon, May 22, 2023 at 05:43:08PM -0700, Peter Collingbourne wrote:
> > Commit c145e0b47c77 ("mm: streamline COW logic in do_swap_page()") move=
d
> > the call to swap_free() before the call to set_pte_at(), which meant th=
at
> > the MTE tags could end up being freed before set_pte_at() had a chance
> > to restore them. Fix it by adding a call to the arch_swap_restore() hoo=
k
> > before the call to swap_free().
> >
> > Signed-off-by: Peter Collingbourne <pcc@google.com>
> > Link: https://linux-review.googlesource.com/id/I6470efa669e8bd2f841049b=
8c61020c510678965
> > Cc: <stable@vger.kernel.org> # 6.1
> > Fixes: c145e0b47c77 ("mm: streamline COW logic in do_swap_page()")
> > Reported-by: Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=B4=B4) <Qun-wei.Lin@med=
iatek.com>
> > Closes: https://lore.kernel.org/all/5050805753ac469e8d727c797c2218a9d78=
0d434.camel@mediatek.com/
> > Acked-by: David Hildenbrand <david@redhat.com>
> > Acked-by: "Huang, Ying" <ying.huang@intel.com>
> > Reviewed-by: Steven Price <steven.price@arm.com>
> > Acked-by: Catalin Marinas <catalin.marinas@arm.com>
> > ---
> > v2:
> > - Call arch_swap_restore() directly instead of via arch_do_swap_page()
> >
> >  mm/memory.c | 7 +++++++
> >  1 file changed, 7 insertions(+)
> >
> > diff --git a/mm/memory.c b/mm/memory.c
> > index f69fbc251198..fc25764016b3 100644
> > --- a/mm/memory.c
> > +++ b/mm/memory.c
> > @@ -3932,6 +3932,13 @@ vm_fault_t do_swap_page(struct vm_fault *vmf)
> >               }
> >       }
> >
> > +     /*
> > +      * Some architectures may have to restore extra metadata to the p=
age
> > +      * when reading from swap. This metadata may be indexed by swap e=
ntry
> > +      * so this must be called before swap_free().
> > +      */
> > +     arch_swap_restore(entry, folio);
> > +
> >       /*
> >        * Remove the swap entry and conditionally try to free up the swa=
pcache.
> >        * We're already holding a reference on the page but haven't mapp=
ed it
>
> It looks like the intention is for this patch to land in 6.4, whereas the
> other two in the series could go in later, right? If so, I was expecting
> Andrew to pick this one up but he's not actually on CC. I've added him no=
w,
> but you may want to send this as a separate fix so it's obvious what need=
s
> picking up for this cycle.

I was expecting that this whole series could be picked up in mm. There
was a previous attempt to apply v3 of this series to mm, but that
failed because a dependent patch (commit c4c597f1b367 ("arm64: mte: Do
not set PG_mte_tagged if tags were not initialized")) hadn't been
merged into Linus's master branch yet. The series should be good to go
in now that that patch has been merged.

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO4k%3Drg96GVsPW6Aaz12c7hS0TYcgVR7y38x7pUsbfwg5A%40mail.gmai=
l.com.
