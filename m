Return-Path: <kasan-dev+bncBCCMH5WKTMGRBD4536QQMGQEDALPRCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F97A6E0A69
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 11:42:42 +0200 (CEST)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-54ee1fd7876sf150545587b3.23
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 02:42:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681378959; cv=pass;
        d=google.com; s=arc-20160816;
        b=h46z3Ffvge1bfq4bJh8JZk8/WNScpmfoWyEmj9aSf1/EXdPhNgszSE6dEgBdvXJrtW
         ilzlhL8dtrUz0u6c0aN/K/rVWY7LJFa+zqMdiisytHdSBONPCdw/XUtlbNEYgIPlYAxU
         z6nTgdxadqVx4OM3MUHKo6F+tgBi5LVb7GVzVKpA7mgdc96SAEQDmr5CG1fuALOH3O7r
         jSEJJJDJJJcNuvObJC80l7D1LyAc2X4iP0WZ43AXERBYRQGyOBXzg5GyGwdfu5YR6zbB
         gRejHfce46Alt8e39JksGO/ScfEHGl5aX5n+SQK+hHIEHX3kxQWJ/LmJE7jz/4xHeaVV
         +OMw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lgECyAsIZ8sdQKI1ONlKpcoNJ49K1ifjqhFLeY7oCV4=;
        b=zkivRRvFgv/UVRocDy6VfImoiyfuW08SgQcpMHSr/K14jUO4T5VEWQcsF/IR6PyzYZ
         ycAt/Szcl3ygZxY1UgV1Zu5OXggNLvK5D5rpOTzqRyk4kKw8RwHRQZs0sJLeFwsLg/Jv
         26y3YUQUo9XrQM22a4YYPbeU9UWJTzYk68+lolxUlHnZWhEO1h2PKAZj0SluCLLuSKQo
         T3z9EJMEJnRnK60c1dA7/AD2Sp+ObiL72YA2Gjqt+xTrvvnZPTy3jUA4/B3nNKVMLHMl
         TCHZ3HNC0dsn+DRbA6/AT7B3+2OG7doTbWpBderL0yByXUfjb/Uj0IlHGp8LLD2hH7+I
         svEQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=p5qruo+v;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681378959; x=1683970959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=lgECyAsIZ8sdQKI1ONlKpcoNJ49K1ifjqhFLeY7oCV4=;
        b=c+eVkGqwaT8Err+5CbItZ9LQb6lF5HQK/8sqaml2Y61tsEdGKn9SJbjqccRY+PovEq
         QvBmxaryyzdTqvgQD6mCkJdnDbGpKPyabNr+LuF/ps2IWMPfHecv/CQRu9ovjpNEYnwq
         t8KtGG9anq8LCIWJGCg3skwte7llWIve1Z7caHf9f57PTKQ1E1ah/Bo/vl5j+avg549K
         RboyAQjdXGbJASOiqhKLufgGidxd80E3VmjnvyCimKx3Lbk6Kap+vDeBdv9aUn0kLOlL
         ScntElxlsdzeB82Jd0/JKj4p7yT4jiFbb+USx6NkWVV/S4LTCrT9mRexJiYwm1r0thay
         JzGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681378959; x=1683970959;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=lgECyAsIZ8sdQKI1ONlKpcoNJ49K1ifjqhFLeY7oCV4=;
        b=MF4L434DXjZGKU9kXaatHGlBf2Cll9juyYuzm/RPiVZzC9JeLPZnldGwDsXpRYeAiw
         s3kWA9hxMUXGq0TP6GD3s6j3mspQHeO5UeLKy1gCpP/xc92nD6/0RUUVziOgsUtHJiAY
         KulWPZcnXeflxc/yCSEgW/J6WfRktKXf3yiT419hDjG5AijkKKgIUhVJNqBUmHSrzcY9
         nZ/0a9Wy8Zr78Kc17TnkBsOcTbxe8AsNudpW62GXGUi8SCBmazuq79/aZ3owZ8Ri9cdW
         48pPQf6v6T2nHrKNFxJJXAm7EchN1lrknebkdtR31w4dN6yTwBqYMdXZf8mpfdD+unrf
         bIEg==
X-Gm-Message-State: AAQBX9fvq/pd6A2dGkpqhprXYJsQf9ckf/KoBCKmo75Nq5JSq/VWVtGz
	fsvcqxNIBVItAwUpuS+1rVE=
X-Google-Smtp-Source: AKy350bjmgY4xbcm1boW250b9vfNOAlMfEq23AZhDV+AyFMDm3s7WyniyjOOZVmejD1Y3fr9PRO0CQ==
X-Received: by 2002:a25:d647:0:b0:b8f:54b0:fd3b with SMTP id n68-20020a25d647000000b00b8f54b0fd3bmr987366ybg.10.1681378959487;
        Thu, 13 Apr 2023 02:42:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:814d:0:b0:b32:32f7:8ee7 with SMTP id j13-20020a25814d000000b00b3232f78ee7ls1760108ybm.2.-pod-prod-gmail;
 Thu, 13 Apr 2023 02:42:38 -0700 (PDT)
X-Received: by 2002:a25:2692:0:b0:b8e:d6f8:53ce with SMTP id m140-20020a252692000000b00b8ed6f853cemr1328547ybm.63.1681378958819;
        Thu, 13 Apr 2023 02:42:38 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681378958; cv=none;
        d=google.com; s=arc-20160816;
        b=Ssfs94bbur+/w7G0jjx2b2FwlQJy6M+4Xi9yJR2vFSeomTO5VcdGw8xoE3clHPPNT5
         FQuyVs3dlFNnIW3dy0kAb3FPVc4zfxTZCKfqnAVg4215zuLyMhsf0Ts6L9tOB2gaHZM0
         AfNeaSTcO2qMBzf7zR2in+RaumN0N+wtZ5OEvQkXRPS0jjwMRpT7YIhHSXWDaPcBSg7S
         vsxKB/rQWFsUDSokbTHjaxuPE/HjGdcWrqLiqhkofMnhGxi2vqnmDjDv2gtJkSf74C6d
         sNRDZ03cGHSFjCe+sZPjsf6vI341pJACErBP+sZt018K6k6sY8l/IP+NtAzeYApvlwSw
         HrWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=FXuvR6IorGk+vc4Sbx2+ljSRa/GREptQBSmjgKoDNBQ=;
        b=fsM9O9vYFnWvmazBw2Dt/F1uI7i/EIVqDmsjK7IbQkL7orw9pRChgi1h2PK1KEKyT2
         REDhFoaN21zGtisNzTsi553YA5VTRZKTj9vxiCVolrHpQs5f3jlbYsSZZytKlqqmC8im
         9ZOxkPa9TdrDwIOyVc5ejj6BGjjAcnQ7mjwM28fGBINZEjfcZdOIi6l6zbRENXPntXYf
         KTVQKyUetoq0ZTPPHIADXf4wSlu7Si6oC0vAO1YHEWLpzCw0K5wNrXiY9z9ULMLnckvy
         4VHZZ4GkyPIqnQ/H1LvBjvyJlFJhq4sok9IhNSBTwkNNp6O7flRv76/DmhBD+Zj0UY7X
         lPhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=p5qruo+v;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb36.google.com (mail-yb1-xb36.google.com. [2607:f8b0:4864:20::b36])
        by gmr-mx.google.com with ESMTPS id n11-20020a25400b000000b00b8f158a4ecesi50621yba.2.2023.04.13.02.42.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Apr 2023 02:42:38 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b36 as permitted sender) client-ip=2607:f8b0:4864:20::b36;
Received: by mail-yb1-xb36.google.com with SMTP id y69so21563565ybe.2
        for <kasan-dev@googlegroups.com>; Thu, 13 Apr 2023 02:42:38 -0700 (PDT)
X-Received: by 2002:a25:ae45:0:b0:b8f:62b7:e03c with SMTP id
 g5-20020a25ae45000000b00b8f62b7e03cmr190745ybe.1.1681378958351; Thu, 13 Apr
 2023 02:42:38 -0700 (PDT)
MIME-Version: 1.0
References: <CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com>
 <CAG_fn=V57m0om5HUHHFOQr9R9TWHtfm4+jO96Smf+Q+XjRkxtQ@mail.gmail.com> <CANX2M5bWPMDJGgD=xq33A3p96ii3wBOuy9UKYAstX4psdAGrrA@mail.gmail.com>
In-Reply-To: <CANX2M5bWPMDJGgD=xq33A3p96ii3wBOuy9UKYAstX4psdAGrrA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 13 Apr 2023 11:42:01 +0200
Message-ID: <CAG_fn=WOZ2RTyTYrgV3JhsqESf-YCmj_FmbzJZdJogpZk8SnOw@mail.gmail.com>
Subject: Re: Possible incorrect handling of fault injection inside KMSAN instrumentation
To: Dipanjan Das <mail.dipanjan.das@gmail.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, syzkaller <syzkaller@googlegroups.com>, 
	Marius Fleischer <fleischermarius@googlemail.com>, 
	Priyanka Bose <its.priyanka.bose@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=p5qruo+v;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::b36 as
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

On Wed, Apr 12, 2023 at 8:24=E2=80=AFPM Dipanjan Das
<mail.dipanjan.das@gmail.com> wrote:
>
> On Wed, Apr 12, 2023 at 7:39=E2=80=AFAM Alexander Potapenko <glider@googl=
e.com> wrote:
>
> > Here are two patches that fix the problem:
> >  - https://github.com/google/kmsan/commit/b793a6d5a1c1258326b0f53d6e3ac=
8aa3eeb3499
> > - for kmsan_vmap_pages_range_noflush();
> >  - https://github.com/google/kmsan/commit/cb9e33e0cd7ff735bc302ff69c022=
74f24060cff
> > - for kmsan_ioremap_page_range()
> >
> > Can you please try them out?
>
> The second patch needs a small modification.
>
> The return value of `__vmap_pages_range_noflush` at Line 181
> (https://github.com/google/kmsan/commit/cb9e33e0cd7ff735bc302ff69c02274f2=
4060cff#diff-6c23520766ef70571c16b74ed93474716645c7ba81dc07028c076b6fd5ad27=
31R181)
> should also be assigned to `mapped`. With this modification, the patch
> works.

Good catch, thanks!
I'll send an updated version.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWOZ2RTyTYrgV3JhsqESf-YCmj_FmbzJZdJogpZk8SnOw%40mail.gmai=
l.com.
