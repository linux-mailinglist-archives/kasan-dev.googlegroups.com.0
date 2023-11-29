Return-Path: <kasan-dev+bncBDW2JDUY5AORBKGTTKVQMGQE5PPNLQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id EDFE67FCD22
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Nov 2023 04:02:01 +0100 (CET)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-67a36efeab4sf38398036d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 28 Nov 2023 19:02:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701226920; cv=pass;
        d=google.com; s=arc-20160816;
        b=lSzplrRWVYkvOBECsDO4q7ts0pxY1n8HEkf78d1k7I9QY3a/w6b2K5TdX6IWhwLbd5
         j1UT0u8dLxbofTVKtcq8+U5nFhsTnthJVi3eld+B0LHwjHoM+SbhJ0g6bRG1Ywdrq2Ri
         64jH+JbH/8ojn4ntMVZDZrewg7VMPt8VzHlDVQP+lb+Xa+ODzx3pRl4VsxEFxC9Y8NN2
         lXlolqhO533hgf/NoGni4gU7+VQkR8uwpxb32UXC/cv/Nw34XL64pKWvrD0YOugAEfMZ
         X9/9Eznk2PVxcpsiSrjJg/J9vR7DD2M+h9REdH424yf0az4p/UnEwJFgxwsjRIgmlgC3
         9eEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=apO3coxJPXMX7Sjpmoa8GznFCgI99pBxQARPF+duhTs=;
        fh=kr4SrwCPpjd/itQqfxbAHnjRgjjSCQqDqYIShluYXBk=;
        b=p0tPsaXSxVdY+0yzifMaKqKp54EOUgkqx6fJSyxZvGzq6c+5Yn2iwApFfp2pytVlRR
         NIrB6ls6x5mf0/ebsiH7lofd232XkH7YWLRvgx7qQQ7y6rEPBXn8x6Wj3wt5J+7s3srY
         nRQw3TKfl+Iqfle0ff6dwyCMxnk+B3TM1ZhScAzCJ4wOGbAWN6fR+kGbdIoHKBzVMLFg
         VbOcvRWQxbjVSvzYZu4dQ1/IqO6E5fuQkFywWA5VRp+CZHELdKtHzBBOfOgbMx7ZOpKn
         fuuVXVqsk7Li6OGSyUEhWC3perLQ4AZak/WxuhKF/+Biy1i6gEbpVbrQmXoef8UuPCl/
         fZWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B4rP+SCn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701226920; x=1701831720; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=apO3coxJPXMX7Sjpmoa8GznFCgI99pBxQARPF+duhTs=;
        b=GmRD8NyNBUa9C1uWiKXduPAZvKMdxRHMvrYyooP6JJA0eS8Ulb889NWTbHNWqDJ3uh
         eh7BDG/TXpru4AQXKbCbTooRmSQyzUcw2r22XK3CJG0mnh9DoEr88yuMQEG2TsYI/HEc
         piNTHjdauOOBbKmPkJWctPJog1yrPCxQZ7md2rBlaUL/tpiN9pO8rpvibTX5pDRi7uj7
         XUxH216WJ1PfJjo7oTOH7AE2opIVLr4Zw/qlMT1TSkRvdn+gFhX0naq92GOw8YAHH4Gh
         kvTLJPV7Oly2JXqVr4B4iva16w50mnc6lf0gLNv7W+8KznnCTJlHoDzb64Bfn/JNNJYI
         QvNA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1701226920; x=1701831720; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=apO3coxJPXMX7Sjpmoa8GznFCgI99pBxQARPF+duhTs=;
        b=c/pCip+Fk03OYnae/tH5XOyfmgV85C/KdX7oXZS5l4jYZ67TEhE9JQGtMk1aYOOtx3
         IxV+CTsadyJsN3lCIpX9CPfV+QCoyAhjVVVH/f9BzDpZ2xoy8oQ8Xq/rylPTMe8I8Zk8
         WT54OwMSrB/y0JDs+MMuE3e+lWj305X48hJY2rfvbLdXsFaQhk5kHsfXVlLu7LOUExae
         Nve3rWSRz2bcOYm1Sqd6YwxE/Qsp5dtSOqx+IUG1gNFbOsUsafsE8NFvCmWHglZFop9u
         dWcdEj7h5wJjzfrG4/NUl1A73SLrEnoxkLumn70Q1oVYE40ssGgnqxgNa5YgJ4feszee
         SR6Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701226920; x=1701831720;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=apO3coxJPXMX7Sjpmoa8GznFCgI99pBxQARPF+duhTs=;
        b=G/fmJhBcmp+WY4jIP3AJa4wtE3VMgdnVi3BmkyJFt0QzvBMNeFVLcba1Enzo98Fb5w
         o5GQ7nm0OeneG8giek8PwmaRU3W11I2Rm0wmECpXuswaQvqRdFombXvGb1EX7RLixgrk
         x0V/dWd6NawLokXDef6H5ZK2Ihf125g/HVc0J3TpME6f2NA1SLJT+3jJlkT1O/Jg0MFy
         MqiwsKe8kQKOY8N4k4VdjJpq0C/BnBVQVgDIb7RNayk4TPHgZE0Pi6usLAeToYwMNttl
         OmK0naiW3dFRZMyh8wkCuC4vRYgkV3M3RjvWXp4gxQ9tzn7T4PuCym1JlFxgVmjq782j
         LneA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwvcbbEHHVSC1bfhg0S5JC9j3qTDSPO9YcAOEd0BS1EfNZIKJn1
	0i+b49+v70I5UjwBa2Vn9zE=
X-Google-Smtp-Source: AGHT+IH26WCDiwvFOu+EIur06/CBvGefRiUw7b3QsrgjUxkYHMtyQffoyhybXC8aGK2X5wBjxjjEMg==
X-Received: by 2002:a05:6214:303:b0:67a:360a:daa7 with SMTP id i3-20020a056214030300b0067a360adaa7mr9885243qvu.63.1701226920668;
        Tue, 28 Nov 2023 19:02:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:548e:0:b0:677:f602:655f with SMTP id pv14-20020ad4548e000000b00677f602655fls1077467qvb.0.-pod-prod-08-us;
 Tue, 28 Nov 2023 19:01:59 -0800 (PST)
X-Received: by 2002:a05:6214:1928:b0:67a:6e6c:c79e with SMTP id es8-20020a056214192800b0067a6e6cc79emr10263qvb.12.1701226919646;
        Tue, 28 Nov 2023 19:01:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701226919; cv=none;
        d=google.com; s=arc-20160816;
        b=v5qb086AWQnVeW8kjpxuzO19CArXtCD657BiYvaJLkYvQQ/0dAYhE9w08GElbM8wDh
         bap2+lburm55NY9/8b9iK3WJIgPqCrv/Pmz8DCk2MOK3XEezEFvw5oJ0/yGUNEIMpGmN
         QpRFWv+yALCxet1dWicPdV0UhQDEaowTux1F/FezfWoDvElJWsc67Y5E3VkA2pX1+r11
         GhcVgrIWxAi8MjXBPIEQ7oQ7qP5P+Q5Ad8nTUBFpTVLFpPXBd/923D/k1mvz/BQC/XWZ
         GBj4f31jV6sW9qlUmwrUw68yAXN9yCMbA740hX6eMNtY32mSa6DTeZyCQBjet/e/Esn2
         jGFQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=YmmZdnMG5cx1ucOkJTYJz9C0ueulBI91QAmZKkzSQnk=;
        fh=kr4SrwCPpjd/itQqfxbAHnjRgjjSCQqDqYIShluYXBk=;
        b=NZwNmOqd56M30M022Ne7WQScb8asjkbBWxFOEf6pJQPJ3VyNG71RRfuF1ZHOgYHxSL
         +ItBgzLkrlnaoVO4uDTHfO2UiTFtveiO4f7URNWVVJzNwQVfOG6ktYvXR7eaiSz70trG
         PLBGkNWqmeH4ayeiGUGVhb5iavAN5TWGT4UTuQQeykzmxKKtp1iGa/jcwtd2W+mNSNom
         /aUwVprwiB3qiTbXJCUS/HZgf8Hs4siUEFJdhwpOvKU07ufQPVdYoI4BJCkxAm0GAKrt
         TQcmU0OrxV2PZK5A/0gLKvVk052zMEZmTIhFtKtf7iVb8DUdmNIygIH11uInf+4Lcrkh
         spsA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=B4rP+SCn;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id l6-20020a0ce6c6000000b0067a51a92287si479803qvn.8.2023.11.28.19.01.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 28 Nov 2023 19:01:59 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id 98e67ed59e1d1-285b926e5deso3236261a91.0
        for <kasan-dev@googlegroups.com>; Tue, 28 Nov 2023 19:01:59 -0800 (PST)
X-Received: by 2002:a17:90b:4c02:b0:285:dbbe:1178 with SMTP id
 na2-20020a17090b4c0200b00285dbbe1178mr7726571pjb.39.1701226918871; Tue, 28
 Nov 2023 19:01:58 -0800 (PST)
MIME-Version: 1.0
References: <20231128075532.110251-1-haibo.li@mediatek.com> <20231128172238.f80ed8dd74ab2a13eba33091@linux-foundation.org>
In-Reply-To: <20231128172238.f80ed8dd74ab2a13eba33091@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 29 Nov 2023 04:01:47 +0100
Message-ID: <CA+fCnZcLwXn6crGF1E1cY3TknMaUN=H8-_hp0-cC+s8-wj95PQ@mail.gmail.com>
Subject: Re: [PATCH] fix comparison of unsigned expression < 0
To: Andrew Morton <akpm@linux-foundation.org>, kernel test robot <lkp@intel.com>, 
	Haibo Li <haibo.li@mediatek.com>
Cc: linux-kernel@vger.kernel.org, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Matthias Brugger <matthias.bgg@gmail.com>, 
	AngeloGioacchino Del Regno <angelogioacchino.delregno@collabora.com>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-arm-kernel@lists.infradead.org, 
	linux-mediatek@lists.infradead.org, xiaoming.yu@mediatek.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=B4rP+SCn;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1033
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

On Wed, Nov 29, 2023 at 2:22=E2=80=AFAM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Tue, 28 Nov 2023 15:55:32 +0800 Haibo Li <haibo.li@mediatek.com> wrote=
:
>
> > Kernel test robot reported:
> >
> > '''
> > mm/kasan/report.c:637 kasan_non_canonical_hook() warn:
> > unsigned 'addr' is never less than zero.
> > '''
> > The KASAN_SHADOW_OFFSET is 0 on loongarch64.
> >
> > To fix it,check the KASAN_SHADOW_OFFSET before do comparison.
> >
> > --- a/mm/kasan/report.c
> > +++ b/mm/kasan/report.c
> > @@ -634,10 +634,10 @@ void kasan_non_canonical_hook(unsigned long addr)
> >  {
> >       unsigned long orig_addr;
> >       const char *bug_type;
> > -
> > +#if KASAN_SHADOW_OFFSET > 0
> >       if (addr < KASAN_SHADOW_OFFSET)
> >               return;
> > -
> > +#endif
>
> We'd rather not add ugly ifdefs for a simple test like this.  If we
> replace "<" with "<=3D", does it fix?  I suspect that's wrong.

Changing the comparison into "<=3D" would be wrong.

But I actually don't think we need to fix anything here.

This issue looks quite close to a similar comparison with 0 issue
Linus shared his opinion on here:

https://lore.kernel.org/all/Pine.LNX.4.58.0411230958260.20993@ppc970.osdl.o=
rg/

I don't know if the common consensus with the regard to issues like
that changed since then. But if not, perhaps we can treat this kernel
test robot report as a false positive.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZcLwXn6crGF1E1cY3TknMaUN%3DH8-_hp0-cC%2Bs8-wj95PQ%40mail.=
gmail.com.
