Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4PHSCUAMGQETXL5NFY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 163C77A1C67
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 12:37:39 +0200 (CEST)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-41213943314sf20583841cf.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 03:37:39 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694774258; cv=pass;
        d=google.com; s=arc-20160816;
        b=d05A7Cjh/aHGYN/073Ym/pk54d+eZlsH2E1Cn8GXN8IaE0Bf+Tr+tXyDpYA4QNjkF/
         HY8BdmFKa/d8HNvCSYHaOLNXp8vnugO7jzag/gtT1Ef6+kdIkvo8ZPkktDtFo6unHvI+
         XMygvZaQ7t0dSlHRAJO0B3a/GpTBbO8u5OEcxqjvPJuCWSd+GwBdfbR58VhJimD0Unb6
         Cijq0kqVXuHeYJRpqkq0InU0RZSRlvmOSDexRyLisQQTNJw8DHr2WUgsZLTRIUNK5dq+
         7nW07By9VkZYXJy4TYTjv44sL+b8HtDC1rkMuG8bjZxH0Im4AINMveccibqk8r3dMf2T
         K4Aw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=O019rgBXJ1KT8pb2MYosvd5uSB4dPaJ36NKb9IHyHt4=;
        fh=B91nIZwDiUKkFKpA1FtmLDDi3vH/t+wG+WJxA3DrOes=;
        b=irv9vRoePMvgKBq/Nsx78KVD0BVX9eSDHGyBVWfvtFKTsvbrfBgWdh1rtFKCLLVszW
         OugE57suHQPArT5oyuViIODdyC/BQwgxmzLime2SQSBl/CNQ0V2e7R6FDE7JLyZhFT2z
         7jwukS2boJsJWWmH3mFNWn2owdvD2knY+uQIT5Q/XQYiGWHrSBEzW18PG6P249oaL9EA
         Q5lzJye/k0a/rAfrcc8/XSQcu30sL1jVT/nMXilEc9VxlgFpD1s6LYXDLtKZe6nJNiYc
         ZQ1kyloRlC4R3B6pFcJyeDyWdLI65oi9WG1UIk5pWye0o6zSGYsAYrCemecJnRjZIy0K
         eikg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nyp0L+xg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694774258; x=1695379058; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=O019rgBXJ1KT8pb2MYosvd5uSB4dPaJ36NKb9IHyHt4=;
        b=wENE21fxq43WbPFxlmkrWvQYy0yoX7zGd9Op5Y7t7e8lZiWbvGDyIlQijsBHnxjs1X
         FVFq/vrv4pm48T8taGHOQqkXPm5bLqVNR1wM0VEbEAZUiLZV7jTm8CC9lBibQhstNu6S
         6n8G/FbCr9AuldX4/N2e2c7cmj6gKY+yurZb8FesfsUqTVBsRZMnGJUxflzBYqTwTpQZ
         GtlLv16jslfLnlDPFyacramlzC4fNCwcvDI1OSv/Dl3Hftd2keV8K60UMMo4k9gU6jf5
         6rxf0GDgRCqbZ/jf6wy1wbS0OiEQ7a+NJWRkla3tql6GaEBdoaCHhuUHGmkuc4f3lZN8
         bcgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694774258; x=1695379058;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O019rgBXJ1KT8pb2MYosvd5uSB4dPaJ36NKb9IHyHt4=;
        b=jrnuUKAYhJMjW313dpEhspB78McRxnOMhnEegpzagY3wrAejRIVMjTvxbHcfNnCCE9
         g3l1AYps1dVm+ky1faZmY0vaBl7DTiLmjE6Fk24cJ0Ro3nfIcBoLrw3o8jDlGN2qqPMz
         W9RfZS2wag6pq9cGG3rhuAK+OBL7g9M5H4rZ8VwrHTkhCVfv/Y4tUQLhwTMxyk7cXq14
         pbuaDjT9cqAb7w6m9CQLVqqTjcFD+REQH6rXMSK5vdHEgJFpX+rTtIRFaIoyeAK22oUn
         6vXI+kEkg54JjWQMQcaM7dmmmRmblSatFA101SUq2SqTpGcmBIz2hOl/RIGQIAa7Rsy0
         FgRg==
X-Gm-Message-State: AOJu0YzP+/sSS0NNAFhD2g1OSgkdnqyZRx0MoKaDA8glefGivxoTPiwl
	hv3HHITmYVZ+rw236zgBMFE=
X-Google-Smtp-Source: AGHT+IEVcLD00gHUgvxuwLCRi0Wd6xSPS6Fhi1IPLd7akoZetxG6/aEdopoWK47bGlMV9Dngq1ULTw==
X-Received: by 2002:a05:622a:130c:b0:417:931c:4b63 with SMTP id v12-20020a05622a130c00b00417931c4b63mr1442819qtk.30.1694774257903;
        Fri, 15 Sep 2023 03:37:37 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:4706:0:b0:415:1684:8eed with SMTP id f6-20020ac84706000000b0041516848eedls1691267qtp.2.-pod-prod-03-us;
 Fri, 15 Sep 2023 03:37:37 -0700 (PDT)
X-Received: by 2002:a05:620a:4483:b0:76f:10ea:e92a with SMTP id x3-20020a05620a448300b0076f10eae92amr1372458qkp.0.1694774257164;
        Fri, 15 Sep 2023 03:37:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694774257; cv=none;
        d=google.com; s=arc-20160816;
        b=wFy70FZF1DvZo8pM1N545zqrRHVugQtWKjtGQKYDn609oK5mohYVQ58yXh6mAoWqtl
         0shTlpFyZ0sp2XUx27X7lrtBd+5lVW927xQFL5RLv0VmHwEir5UlvNBGCRQIPG5u8a/7
         15aNNbTCdaqFsXAK5NU4m0V87WymBYjLBfm/fto9JFz900ymlMQ0JRyvlHgNNlAyxllc
         7/Ib8LP2NdXzm4mdiqWQMdQ5rZx6iRuagMHV09/kTAGVyq88bnyRPyt7GDtL/x/GQZEl
         vto9e4nC09MoUuIzfM2ulhWSzK/eWwathuJCGjBpu8UoMhzIURaGywYfNdXMzKUIf+7p
         3QHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=L1M0/0ecR5D/JjO5eCZw5wQnSPeaMytczG5hNDeARmM=;
        fh=B91nIZwDiUKkFKpA1FtmLDDi3vH/t+wG+WJxA3DrOes=;
        b=wUmZ7cwFMu1oPde9HBo8zGk2WTNEnRJ5j9nVelJU52qf9fP3oIBxVDiQkDFspjO+EZ
         O7uMgndFhwtQPoikgYfVdLbzPTLixdLO9gnz/2E1Tb5JBbRD/TKW24r7ihyxtOXW5sCu
         UEXFYoFQOWYfCDgrGUNEqdQ5thCjPWU1bO/60784pO/NA5vF30L9tf8JRpuJJ5ZE/nSK
         e7EmDlzXEZ3Fldul15xs9FF45Drh553+CAeamH4X5pRcxi3k3dr4IehKS7Zy6eU/JnVZ
         ABCPrn+q2pkYwf75X0oQ2QRRpVjny9wfzI4J1PUaaoReOW7kG9YnFYIcYm0wdBWUUAIB
         EKeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=nyp0L+xg;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd33.google.com (mail-io1-xd33.google.com. [2607:f8b0:4864:20::d33])
        by gmr-mx.google.com with ESMTPS id c3-20020a05620a0ce300b0076daf89f666si301962qkj.3.2023.09.15.03.37.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Sep 2023 03:37:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d33 as permitted sender) client-ip=2607:f8b0:4864:20::d33;
Received: by mail-io1-xd33.google.com with SMTP id ca18e2360f4ac-79565370aa3so74538539f.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Sep 2023 03:37:37 -0700 (PDT)
X-Received: by 2002:a6b:d918:0:b0:795:1a7c:486f with SMTP id
 r24-20020a6bd918000000b007951a7c486fmr1140189ioc.14.1694774256505; Fri, 15
 Sep 2023 03:37:36 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1693328501.git.andreyknvl@google.com> <89c2f64120a7dd6b2255a9a281603359a50cf6f7.1693328501.git.andreyknvl@google.com>
 <CAG_fn=WsYH8iwHCGsoBRL9BRM-uzKJ3+RDgrB5DEGVJKLPagVw@mail.gmail.com> <CA+fCnZftKPJ7zDWmPRjxYXQK91DX2eEw0nDNtYW856399v__Hg@mail.gmail.com>
In-Reply-To: <CA+fCnZftKPJ7zDWmPRjxYXQK91DX2eEw0nDNtYW856399v__Hg@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Sep 2023 12:36:56 +0200
Message-ID: <CAG_fn=USVp-HtC=K=BwaNQVCVVeHDRcGSCpF8dS6f9C1Vd8wjg@mail.gmail.com>
Subject: Re: [PATCH 05/15] stackdepot: use fixed-sized slots for stack records
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=nyp0L+xg;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d33 as
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

> > As a side note, kmsan_internal_chain_origin()
> > (https://elixir.bootlin.com/linux/latest/source/mm/kmsan/core.c#L214)
> > creates small 3-frame records in the stack depot to link two stacks
> > together, which will add unnecessary stackdepot pressure.
> > But this can be fixed by storing both the new stack trace and the link
> > to the old stack trace in the same record.
>
> Do you mean this can be fixed in KMSAN? Or do you mean some kind of an
> extension to the stack depot interface?

Yes, I'll just fix this on the KMSAN side.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUSVp-HtC%3DK%3DBwaNQVCVVeHDRcGSCpF8dS6f9C1Vd8wjg%40mail.gmail.com.
