Return-Path: <kasan-dev+bncBDW2JDUY5AORBLW2Q6UAMGQEHXA5KBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x37.google.com (mail-oa1-x37.google.com [IPv6:2001:4860:4864:20::37])
	by mail.lfdr.de (Postfix) with ESMTPS id 2026A79EFF4
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 19:11:12 +0200 (CEST)
Received: by mail-oa1-x37.google.com with SMTP id 586e51a60fabf-1c8e1617d96sf102890fac.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Sep 2023 10:11:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694625070; cv=pass;
        d=google.com; s=arc-20160816;
        b=hib4/cp+BOK11CWQtf4mGP5QncJW756yvLtOB1IAkKACEnvuP67L+IyQVoteN8wx+D
         wkraTsb5+96pPUrhjfc+IB8nQ8gJujcf9nvkVaLfYwL4aPImFW6Qa3Jwgx3KC6y53F5F
         t3B5KSSy2ADYeDOlA6MO4cNr938tDetdLZZcAxPIg7+BNMa6Kxy+RZWt3JPk8uLz5kYw
         AnBl7TQEZwNW9S4PO8Y54tCCATPuOL/NuGHKI/FOrCHGZt9QLzsjbA0C6T2ldsUxPYwu
         HpfBrb17i25f1AxLGVzujHEWRinsVOvDvcu0YUM8Ws3tcP58IzfhBAbSw50oEAQGWLB0
         9oeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=t8qbCtNA9Zz9JkhUCCT3qzOhlH1hRiOwWnaStppVkz8=;
        fh=VtO2r39L1Pkw23epfrjaznU6dpfwWvgnPAe8vOMgzxU=;
        b=UqqqUv3rNME4fGjqPLjuAvc/YPsY9Xb/3jEZoOdj9z1W9uOvxvjB87f/r6IzMXIdh9
         tbAcGvcnj2Zuu32fgjO8KOqUDBPvuqOw1g+trAwtZsa6nSJx8HYsyNepwyqi0YyxL2Wn
         eUID9YC8h9X0XKlynLYdAi7JBmZWUULcyhyC2XXPk/ecLsXCt2/IFLZ76hB5znLIaanR
         aep7wNTmuv5Dbur5AZP+dSI9TuajsZ0H5ZQAmj93cEEK5UwMbC9pDEgavSmXWufL9s82
         6z21z5o5c3Me3xOOfqR5VYNQ1PsqjzeP1Ocz/WYHrQc4LGc3hEoqhzWtxt3j0S6qTNEG
         l4SQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Im7Zdb3K;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694625070; x=1695229870; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=t8qbCtNA9Zz9JkhUCCT3qzOhlH1hRiOwWnaStppVkz8=;
        b=fPAQbLngG59BqFJWBttqiZW1UHQu/OqPYwwW1eerIzxhpbQLW3kobo66J/Ms4xB3+M
         1IpxYXmnNfwQ8TqX5NobXxumxqaCzi74UHaK3Bga62M8uDwgjTwHiW/ctlHqsjLkt5lY
         LI1AZZGwP+ww7iKmkrQqN6efixVLvpeH95Ge8bjvvN8ZVsJKTb9y7SD6eQaxQOKul5zU
         Do9FMVXQevMnyaaEl9fhnZw+tYjQBxZEOZb1OYtIoCWHek2ssjeWZ2UP3XPkwSyB+4yf
         57yKmTpf+GE9IzXazgGtQMWNinYcsmYlwT3EQpPf9xj/OnWlt7BwPUaBQwY7sp4ea6Wk
         QscQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1694625070; x=1695229870; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=t8qbCtNA9Zz9JkhUCCT3qzOhlH1hRiOwWnaStppVkz8=;
        b=eT2wjrC58x52FkqRamSH/dfq/RSGYGf8EEoH7Bm5gwl2c+MSKICXSs7oEhaYw1rzPE
         chVPKel4IivFe7NGL1RJrn3SlaJoHec/rVknJZd5V7cQWXUXH/qfdy2pwqw2yVgPNrik
         WjI5Y3i5LteezRMNsKhCTzGknRWyh5Yfm8NzvscjBoD094ukxJE++e/AgCHBROFkdrd8
         vo0XlkK6JfOI7Kn0rk8isjefmoybDMCnBHi5T/eGTgeZI3S3gGMqJUlXm97AtJhEFRom
         PBLl3J9lAYugX3ZTd2ejSbtzbnfWHgBZQ+fFyQRMNQaBQPCF52rFubeLY0EHVCR9Y8ks
         +0fQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694625070; x=1695229870;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=t8qbCtNA9Zz9JkhUCCT3qzOhlH1hRiOwWnaStppVkz8=;
        b=NrTUPEBqftw5ppeG0WZ3xdOWzgo8Ko9Vx04EvE7qbK5wnV15rhMtXkjSitJQCI0ts9
         MRdzWsshdt3/AMuwyHMbrhtcWBM5Vu9jYd2+1WMtedR3TJXBYEO+e4raNdTruI2nOmLK
         XcFqHGrzkG6c+Hd3DKUct9N5MAXQi3lCe2bw+63Ymzep6yZisg/dvRg98muhQEFD8u53
         aJ6fxeWigZlailjizJtK33hVqNdS+C+Aq8n8ospTFVCJgl3JUf3wm8h35koMK2XMjFlx
         aSPfF8GMRl1vqoKrThAJPgJlZ0cSV5NYbPnEhEpgJQKRY4eJ9RFJt0jGY81liq2H/cni
         AZag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyCVRFJiuWoWSQjdY8gtMiDdaeRFmToNcQDarWas5VEq2QW9aUu
	965COLsl6qIRdYfaPFBsP5Q=
X-Google-Smtp-Source: AGHT+IH04lgAoIPn9rBXJEawSz+tTPb/VqLl/02cVCssUtYhX2sCvfpn6XEo4nX7tuBK1byC5T58Fg==
X-Received: by 2002:a05:6870:ec92:b0:1d5:a1da:69b with SMTP id eo18-20020a056870ec9200b001d5a1da069bmr3700251oab.44.1694625070562;
        Wed, 13 Sep 2023 10:11:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:a706:b0:1bb:933b:e6a7 with SMTP id
 g6-20020a056870a70600b001bb933be6a7ls1010011oam.0.-pod-prod-04-us; Wed, 13
 Sep 2023 10:11:10 -0700 (PDT)
X-Received: by 2002:a05:6870:708c:b0:1bf:1c49:7455 with SMTP id v12-20020a056870708c00b001bf1c497455mr3724462oae.6.1694625069981;
        Wed, 13 Sep 2023 10:11:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694625069; cv=none;
        d=google.com; s=arc-20160816;
        b=XthtIgZgRXZPpXZh2vKKgnjrtnEE+b5Ucs/oRGHztpVOPHxXeZNRon6W2eQPb7/sSF
         DcRnOqPdJKBI7GAQSLMQa3Sihb0aIkJ4m51L7LFzb55YVMszQv2MuO34qb3w1StL5lED
         cJqtx2/C5Gk+Yh52K7MWUL3eCli3g27gt7BLfBpxcGY0uiHeeR2rMfPc0QHAe4IQXsc8
         1QCxgSWc5cLW7PlhlYuL/Tuz1DSEN26iEAjPkx61JxftymaVaMula7O/z/IWeDeRRvJw
         qtaNplx15EBwtZ+O/bVT2d9I+hte2Ai0Ut1aYFDN4vri3+hdS0D4kXTC+Lskfno2Tvg+
         Z3Nw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=D31NnAlVX5Nwr4SVKiIWrR2mdDlx525lDafc4aXdb/s=;
        fh=VtO2r39L1Pkw23epfrjaznU6dpfwWvgnPAe8vOMgzxU=;
        b=IHwNrMCuHVl+7EPNs5bOXmphNZ2ReayIVMtNxnMIa/G4rJn/h/3+WmBklLu6d8k3Kj
         9suP/plLEzsATcsvtluS4DjmNUSoBoJjjccVOwZGL4TfRXYpar+mnfAd0JcEt/Fe3AX0
         eLr97GM1wjm/+9V4F7j4SdF/RVTOkIjrYC8YRMITr3w3s9lMYWmFL28goP6n/dGYif2j
         QjXFKeJDvcsPHSdJ5+RIVLWawmLw0SI3bg6Oiuj45KLpWkEkg4EDBUben3zTW2kj4mOx
         xboQ5F4mS7fJGgue1C2m7LZCQUMKFp6ZmZO//tcM2Os4gF8WqXFsrGqv+euESWCw2Bqo
         nGGQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b=Im7Zdb3K;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id wx23-20020a0568707e1700b001d5a1fac22dsi1515611oab.2.2023.09.13.10.11.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Sep 2023 10:11:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-26f9521de4cso65854a91.0
        for <kasan-dev@googlegroups.com>; Wed, 13 Sep 2023 10:11:09 -0700 (PDT)
X-Received: by 2002:a17:90b:f17:b0:268:2d92:55d3 with SMTP id
 br23-20020a17090b0f1700b002682d9255d3mr2851674pjb.39.1694625069172; Wed, 13
 Sep 2023 10:11:09 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <3948766e-5ebd-5e13-3c0d-f5e30c3ed724@suse.cz>
 <CA+fCnZdRkJTG0Z1t00YGuzH4AFAicGUVyxFc63djewRz0vj=pQ@mail.gmail.com> <3a372d658246c5dd1ab1d95f4b601267b0fb154e.camel@mediatek.com>
In-Reply-To: <3a372d658246c5dd1ab1d95f4b601267b0fb154e.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Sep 2023 19:10:57 +0200
Message-ID: <CA+fCnZf7eHV3Mb27x6HnNyS9RoS2AYQTtYxxLrv5QXKhMKEqcg@mail.gmail.com>
Subject: Re: [PATCH 00/15] stackdepot: allow evicting stack traces
To: =?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>
Cc: "vbabka@suse.cz" <vbabka@suse.cz>, "andreyknvl@google.com" <andreyknvl@google.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, "linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, "dvyukov@google.com" <dvyukov@google.com>, 
	"akpm@linux-foundation.org" <akpm@linux-foundation.org>, "elver@google.com" <elver@google.com>, 
	"eugenis@google.com" <eugenis@google.com>, 
	"andrey.konovalov@linux.dev" <andrey.konovalov@linux.dev>, "glider@google.com" <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b=Im7Zdb3K;       spf=pass
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

On Tue, Sep 5, 2023 at 4:48=E2=80=AFAM 'Kuan-Ying Lee (=E6=9D=8E=E5=86=A0=
=E7=A9=8E)' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> > > 3. With the number of stackdepot users increasing, each having
> > > their
> > > distinct set of stacks from others, would it make sense to create
> > > separate
> > > "storage instance" for each user instead of putting everything in a
> > > single
> > > shared one?
> >
> > This shouldn't be hard to implement. However, do you see any
> > particular use cases for this?
> >
> > One thing that comes to mind is that the users will then be able to
> > create/destroy stack depot instances when required. But I don't know
> > if any of the users need this: so far they all seem to require stack
> > depot throughout the whole lifetime of the system.
> >
> Maybe we can use evition in page_owner and slub_debug
> (SLAB_STORE_USER).
>
> After we update page_owner->handle, we could evict the previous
> handle?

We can definitely adapt more users to the new API. My comment was
related to the suggestion of splitting stack depot storages for
different users.

But actually I have a response to my question about the split: if each
user has a separate stack depot storage instance, they can set the
maximum stack trace size as they desire, and thus save up on memory.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf7eHV3Mb27x6HnNyS9RoS2AYQTtYxxLrv5QXKhMKEqcg%40mail.gmai=
l.com.
