Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2W6R6UQMGQEIA2FPXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x38.google.com (mail-oa1-x38.google.com [IPv6:2001:4860:4864:20::38])
	by mail.lfdr.de (Postfix) with ESMTPS id 160787BDB5A
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Oct 2023 14:17:48 +0200 (CEST)
Received: by mail-oa1-x38.google.com with SMTP id 586e51a60fabf-1dd053fb4f0sf6925690fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 09 Oct 2023 05:17:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1696853867; cv=pass;
        d=google.com; s=arc-20160816;
        b=m6fC5q2gSudrMk3/1Hiq2wIM5VMb5cbk0pxGEl0S6RfIHhO2lBUe1zAyHzNU1goGe7
         3BGtSoQAFbPyO4hZIAasX6UkJDoAsup1uJmWQ+lmmVBjpjRt21hBBNWeNe7Gj96nBfDT
         oKJ9LVnuf7HF2Ef3BIea3d+gvUUS+6OCUt5sQmHc1HWqcuw1+3bJv+luVJ+4Nn+HdcOt
         Eo6+fxIKo0o41OsZg2Eb8x1XTh4VHzTn6KWqaE3Wp1S/hRl8dyK+RnQNtbFNsLP8geK7
         3fgJ58nbDMem92MPlZqgmsL8kZpnBKTKCLSJH2Gn6FP1bBCKbbRkW+o86+nOmeAi/v+5
         +y1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=sp0atk29g/UXlqmSKRjfYee7CXFwzzaWonz96uaMqTs=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=c1wuMHvXVIP1B2e9ywXRtNAbd7BEg8vJfXI1t+RdoySAjrv06+izvQfjn/J9ABqAXe
         HWoDGcaDrmO8DUKPtqjTvGP5TJcJiGWqkMNVy4XKINVirX2puyypGrc9DRyqyG+lYTzB
         3fyd2eRV6d8BIVXz+J5mwf8Tkzhuvhdj82tOmGY6ZCZEgvLI3W0kdqiX5Mf6Rzjns96p
         TSYY5Gi5lhq7JrO7XLvXqeqWlOlKhrOWyy4tT2Ec5wvajSHGkyXElDcuNSLWjjxHqrjO
         LZPwZ7oPemZUYKFM4jv1jMQh9zl8FtbwjCQreIUJ6l5+Tr0ezuTLRid0IIWS9brXGGG1
         CW+A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=taaR4Q4D;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1696853867; x=1697458667; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=sp0atk29g/UXlqmSKRjfYee7CXFwzzaWonz96uaMqTs=;
        b=HEXz3c+DaLT14bXyeLD1rwqMjDzoLwbQvItVOJXgGoB9u6vxmZHCkciiDy043oMXKE
         aGFogEWL0rHz6t0sdcol//ZUKIFxV0taafqzI+nLJxbumOJZjhVzP8SCiCdUEhqrbZh/
         xpaDXFKYqz9SHum83Cv5MEgAR6+UzD+jRUSY0eE0aokBYSs+HeGHSba9V8EMP9VFdnbX
         WG8KTxJ2lWO280EnlmndHwS6R+rBnVn5cTbPjbXBnp0fXuZsjj9aSF/ZtlZthL8tBYNQ
         gZAcLf9dBp13cmEzSKUdloeI0hrwqYsxfvpTc36xiuKvHGvydMQNKUEfNSuWLqBjBDS+
         jk2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1696853867; x=1697458667;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=sp0atk29g/UXlqmSKRjfYee7CXFwzzaWonz96uaMqTs=;
        b=HMsDn63mQSLfJmBGa+FIRc3TMJNc6bLavxK/qmnsDkW00g9kiBuTCy9zTMuUAt+t/D
         wIQ1x1ijAC9Avq+2GcZ1j72KKjqF0ZmZMGN4M8UHaIGu7gYmgGaTzivjJm20YQQMkrbg
         GHFFvJqQBaF6+jOmmahyo4+icCXZy7Yoweyi8V1i9//i6t/KcCb7fRqyEZby0P1mG/TH
         j11ir+ao0vnsjP9V3iT6lcSRP6nm8tidLR4vZiQotY2/hsFAsMExWc+vpSwhWM8TentE
         OZVQ0es3BBEKoZxNMXcZol8R6+WA1GwzX7ta6ulxPg/U9W9+/RjoHKC9ingy9FIoTUfl
         yLmA==
X-Gm-Message-State: AOJu0YyKCV9YlLPWGMvvJReZLoOzEF/nhLqCUFRaBmi9nwH/iSMM2gQT
	gheFlYXD3ku2Clml602ZTaM=
X-Google-Smtp-Source: AGHT+IGzbvzyYbSx6n/UtmwkMU302B33pPWEuoI0P5OmEowBz+v/PxMibspOF8f3HPbhvIRAKkX2Cg==
X-Received: by 2002:a05:6870:9120:b0:1d4:de5e:9b8b with SMTP id o32-20020a056870912000b001d4de5e9b8bmr17646020oae.51.1696853866888;
        Mon, 09 Oct 2023 05:17:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:71d3:b0:1d6:cbc7:fb45 with SMTP id
 p19-20020a05687071d300b001d6cbc7fb45ls374611oag.0.-pod-prod-05-us; Mon, 09
 Oct 2023 05:17:46 -0700 (PDT)
X-Received: by 2002:a05:6870:588c:b0:1d0:f5bd:6d2 with SMTP id be12-20020a056870588c00b001d0f5bd06d2mr18369707oab.38.1696853866214;
        Mon, 09 Oct 2023 05:17:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1696853866; cv=none;
        d=google.com; s=arc-20160816;
        b=N8WlhQJrEUJ+Fp5QoNujoNHOWuHe/IIEtVT8U7iWW58jwXZVwIvUfBeciCYPknU5wj
         78Kim/Og4bYpLdSPQANTOefcubU0dwTb5Ttc2KClXDR1iMsRl3PudQ1gisIlHqT73glD
         i8ie1vpGPTSNJe3nBqc5jbQ1YgZZRdif/SGy1PIq7j7SXdKQkCfsJ2Yd1hVO9NmSByT4
         nzXPv6vODTkknGgk1a3wtnwsETvIPunoUsnReL/NeYsUQo84L+HAMpI3wzB0biJpxhRe
         g/uhbjLVpFoHlEvcGm4J0fOhnCBbxJrQFfJpe4zkZtqhrSiFdUkb7r4RMbK5LJkPygy5
         MSUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=m6/vE8g+hycoIkP+nnT3t3DO9SbrtMni1szfWJaCTpw=;
        fh=D7uhrQnmQG6xf11gbvfi3iQ1A4p/6GZN4OQA8frEvwo=;
        b=NEKSr7LHdmBfvgVz0TDIkI46DqAsACDiZ6ZTRQh+HbWNvcIJh7UX6sDl/5Q1TMimvH
         CDeF5Iq0fK81GsezppB3IzmxP57ksV1CVa+WWTLZyv56lABnnY/VU8YLdywmVMoRrqxg
         sKWGkcfxKw7GbGNqbAMwt4HJdVP6D45qYQmTWT9fDj5O/3cBBHJ/+0Vt6KsjmF1LYcKh
         IQylooWqFmh5sL7DgqScgGBTBu1FWxy+JemIPoi+0CKs0S8txTMYtoQwpd35aR+UDnRo
         LqytjIg4oTtg8JGqc2DHrgC7erLQqQsHhymun+j8SqjdgfVlhM6c0PTIhQfiMDN24AvC
         nfLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=taaR4Q4D;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2f.google.com (mail-qv1-xf2f.google.com. [2607:f8b0:4864:20::f2f])
        by gmr-mx.google.com with ESMTPS id lh8-20020a0568700b0800b001d6edf0fa0esi594149oab.2.2023.10.09.05.17.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 09 Oct 2023 05:17:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as permitted sender) client-ip=2607:f8b0:4864:20::f2f;
Received: by mail-qv1-xf2f.google.com with SMTP id 6a1803df08f44-65b0e623189so25640096d6.1
        for <kasan-dev@googlegroups.com>; Mon, 09 Oct 2023 05:17:46 -0700 (PDT)
X-Received: by 2002:a0c:c409:0:b0:64f:3699:90cd with SMTP id
 r9-20020a0cc409000000b0064f369990cdmr15621669qvi.42.1696853865508; Mon, 09
 Oct 2023 05:17:45 -0700 (PDT)
MIME-Version: 1.0
References: <cover.1694625260.git.andreyknvl@google.com> <293d73bcd89932bc026263d3df8ee281ad3f621f.1694625260.git.andreyknvl@google.com>
In-Reply-To: <293d73bcd89932bc026263d3df8ee281ad3f621f.1694625260.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 9 Oct 2023 14:17:09 +0200
Message-ID: <CAG_fn=WXiE1=NjE-NHsXwttJuMmqu1nQURH5ZeTknK0yT0cpoQ@mail.gmail.com>
Subject: Re: [PATCH v2 18/19] kasan: check object_size in kasan_complete_mode_report_info
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Oscar Salvador <osalvador@suse.de>, 
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=taaR4Q4D;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2f as
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

On Wed, Sep 13, 2023 at 7:18=E2=80=AFPM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Check the object size when looking up entries in the stack ring.
>
> If the size of the object for which a report is being printed does not
> match the size of the object for which a stack trace has been saved in
> the stack ring, the saved stack trace is irrelevant.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWXiE1%3DNjE-NHsXwttJuMmqu1nQURH5ZeTknK0yT0cpoQ%40mail.gm=
ail.com.
