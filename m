Return-Path: <kasan-dev+bncBCCMH5WKTMGRBZF5SDTQKGQE6EXGWHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id DF62225485
	for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2019 17:53:09 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id o98sf8653518ota.11
        for <lists+kasan-dev@lfdr.de>; Tue, 21 May 2019 08:53:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558453988; cv=pass;
        d=google.com; s=arc-20160816;
        b=lppUqcEFyjPYr1eW6y+/DvyhjB+yMwIIoHzHneN3Szy6SgvaFEXK6A3t3qB3TVwYsB
         NCl++fppTycKqc6JplW8iY7IrrzCDGUWJqAk12FOYlmms5+1ip8PGokch2RPaeDkRCJB
         KVTR3CPfTAVHbphyUJI8y7AWof1if3qyPQKWThuUbY5yNue2Ji3aYM2K9kCldqsvCjgw
         xRrcGmOMxwlBEk7ba8XoIpS28jtEuh/SVetv8JkYv+RM0NTNlGpFmn0+yuqPqpmXmqNW
         ejqm2LBTapCKZOSkWdQ/fiKMR2h2R6je/aIl93BMhkfGQ/HP7ylDFB0XQHT3QNKUuD3l
         XIiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=BF0yp6dvZp2xDySbHjxof3N9Dnb5VxSevc6FDcdPtnM=;
        b=D2ZI0zIygT0ZNWXqH53BSGSWfZybeqN/6uES5boCJTlUulqDhttvzMoYgrH48pABYE
         KQLaCAT+ahztuQk0yv0IV9GR21Dr7cBfyTrABDbkTt/nEsmXa3eT71NeCeo+5eqIMdRZ
         g3nXkOrug1MXdk488nuZFj0FQ6R8ZtPTi19CAGFxtng6cW1m8KG2n55Jwm5ZkOagG6sZ
         46OX0ZATWR8Zxc+HkqHbkeA8HPLKm/REtx9tunDkEWHZD+UF4VQDzStUkqFeQ/n2a23+
         dT90TnfXbbx2nXuRlFB8lvMVQhlhTumlruifhy0XcjPp0b0U9Ne3coA6uNhTNYSMdaG6
         yclA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SCWW9XLd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=BF0yp6dvZp2xDySbHjxof3N9Dnb5VxSevc6FDcdPtnM=;
        b=YPrmP/mjgsILT5u8JOdLr3UusWN+UrsTIKHH/e0HDnY97YO+MI+4OpfKnnZNuJ2uul
         EoEOOCZ5CvYVn0iPBpMiiBgzjiZqB6+qRK0o7CttOIxKmcLuILWXfef9qTlumqJiCH77
         0SC0Rfg9Ba7qtn+kR1UrCMDue4Owa4w/+wMVIRdrRv5JFwIEd6pTHkGkiK0RvIDT4IY9
         7MFn37Xc0uNdONGnIQmzDTY2zJojdzlRBH6oUG4hJWYbO1/PTVS/57csRilPkU1nh3fu
         n8BmCC720wVBXLabOH7AhSm9M9Z1r8MWGyIdM5L+wwskr3nEYuNGavGVH7n1ca6v71oF
         ebvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=BF0yp6dvZp2xDySbHjxof3N9Dnb5VxSevc6FDcdPtnM=;
        b=Pt3YoBA2cfLDIuZcgAOjHC3FSDfZpNjbqh5MgU/4WOfMKaokiUY4e7cPo4BLVBHKjs
         qFmirFaikROosfXNtWQbkGQ5Sw9ZSosQkcCFbZ8MkvqM95fc9IHmaAQUjGBIS6Y/JF7m
         6pN+MxRUwmF5qwGpiwVLF/af44KsY/yqXodj1IwW1LJxUoheCPaCgqi6kq0z9m0WU3sx
         FP+h8GXG/wbwWltJQi0xXbG1FST/o/GXI6re9egfs3/JJwSAJfGZVlyeaEPqBM8woh8X
         gg1xQMG7Kwn2tcDSqCe/eObx4s/r8eqeWNAG37BTTBVmZ6mNHynzH9U92eBkx5TSTMs2
         rQNQ==
X-Gm-Message-State: APjAAAX5D4w4LU12+sSVEPPp+Uq4RPa3VT7/aRCm0siZfpuQHWmZMXYW
	krW9Te21X7fBpFtGCsNlNaM=
X-Google-Smtp-Source: APXvYqwXUIRqTGGLzbZsHFfRvFvb/IuZSPw4EmdfbEn0ln6AuS/nx8S4YztBdB9bBzrpag7oEwCCpA==
X-Received: by 2002:aca:4509:: with SMTP id s9mr3942739oia.158.1558453988390;
        Tue, 21 May 2019 08:53:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:df02:: with SMTP id w2ls3143831oig.6.gmail; Tue, 21 May
 2019 08:53:08 -0700 (PDT)
X-Received: by 2002:aca:f007:: with SMTP id o7mr3920701oih.59.1558453988115;
        Tue, 21 May 2019 08:53:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558453988; cv=none;
        d=google.com; s=arc-20160816;
        b=m9ZMOeE2VXDvlWAeNJNWL2HdkV7l9sqm5XgKtuF4e0mb9xuLrs+nm4i/xoOALcl5aZ
         7KPQMS3j4VtPF7zLfOOeB2u7+FAwsa/7OAulu5IJqeY2Ju0VgDKBUbLAEWeub4YkzB5y
         i44eUpTf2KSmFr4j5Dg2QalaUGxH/hCHY7Uc7LRVnEOXs/MtLm8iVn7j6LvAEJ2OG9KK
         O1mNUCO0LusmXE7dQoNozoIcqk75ZKw7X7bKiyFP6ch+b6HENHOeqvSwsHK+Wz4nyDaA
         71rvrhuD9qHjvBYPzrzH6SdGZEnpKqDXeUYIUFVF2kPC2uiUB6n1o7tyZ5trxZ26d9Tk
         Bg3g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=M+Fy+Dv7IAvIp9wM9LD81KQdUDxns6+Ve3Y3gCcA6+w=;
        b=RUhUsLCgXzkJgQksPiPWLrnmKLp9E9qFTkeC7DYqc39oufbJB10DYFWNubq5w4X8pm
         wAdvAo1I8S44SqffI/L4wH93LRAY1SuNyWobnNf4JSPlNXZCCIx/SLm/omefxeWG/FEz
         VEExGvwHPJELUD7tpTv37IkwU38t5DwPgTNrbi/et8WeQMPLY8MJM0/8OAebzlPiCYMm
         q51NOmPV07cf/zkwuaJnkCoENG5s/bSQ1M21DeTxnflW7AUJJe0wEC0H5Ju50LDReq8T
         9iedQW6PEupnZzsUEpMW8uIg/IHpFbxhGjI95diWXoHEtj2JacrUI+rrar00FXMMzSq0
         dugQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SCWW9XLd;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e44 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe44.google.com (mail-vs1-xe44.google.com. [2607:f8b0:4864:20::e44])
        by gmr-mx.google.com with ESMTPS id d5si757259oib.5.2019.05.21.08.53.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=AEAD-AES128-GCM-SHA256 bits=128/128);
        Tue, 21 May 2019 08:53:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e44 as permitted sender) client-ip=2607:f8b0:4864:20::e44;
Received: by mail-vs1-xe44.google.com with SMTP id z11so11423650vsq.9
        for <kasan-dev@googlegroups.com>; Tue, 21 May 2019 08:53:08 -0700 (PDT)
X-Received: by 2002:a67:d615:: with SMTP id n21mr26515680vsj.39.1558453987203;
 Tue, 21 May 2019 08:53:07 -0700 (PDT)
MIME-Version: 1.0
References: <20190520154751.84763-1-elver@google.com> <ebec4325-f91b-b392-55ed-95dbd36bbb8e@virtuozzo.com>
In-Reply-To: <ebec4325-f91b-b392-55ed-95dbd36bbb8e@virtuozzo.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 21 May 2019 17:52:55 +0200
Message-ID: <CAG_fn=W+_Ft=g06wtOBgKnpD4UswE_XMXd61jw5ekOH_zeUVOQ@mail.gmail.com>
Subject: Re: [PATCH v2] mm/kasan: Print frame description for stack bugs
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
Cc: Marco Elver <elver@google.com>, Dmitriy Vyukov <dvyukov@google.com>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Linux Memory Management List <linux-mm@kvack.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SCWW9XLd;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e44 as
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

On Tue, May 21, 2019 at 5:43 PM Andrey Ryabinin <aryabinin@virtuozzo.com> w=
rote:
>
>
>
> On 5/20/19 6:47 PM, Marco Elver wrote:
>
> > +static void print_decoded_frame_descr(const char *frame_descr)
> > +{
> > +     /*
> > +      * We need to parse the following string:
> > +      *    "n alloc_1 alloc_2 ... alloc_n"
> > +      * where alloc_i looks like
> > +      *    "offset size len name"
> > +      * or "offset size len name:line".
> > +      */
> > +
> > +     char token[64];
> > +     unsigned long num_objects;
> > +
> > +     if (!tokenize_frame_descr(&frame_descr, token, sizeof(token),
> > +                               &num_objects))
> > +             return;
> > +
> > +     pr_err("\n");
> > +     pr_err("this frame has %lu %s:\n", num_objects,
> > +            num_objects =3D=3D 1 ? "object" : "objects");
> > +
> > +     while (num_objects--) {
> > +             unsigned long offset;
> > +             unsigned long size;
> > +
> > +             /* access offset */
> > +             if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> > +                                       &offset))
> > +                     return;
> > +             /* access size */
> > +             if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> > +                                       &size))
> > +                     return;
> > +             /* name length (unused) */
> > +             if (!tokenize_frame_descr(&frame_descr, NULL, 0, NULL))
> > +                     return;
> > +             /* object name */
> > +             if (!tokenize_frame_descr(&frame_descr, token, sizeof(tok=
en),
> > +                                       NULL))
> > +                     return;
> > +
> > +             /* Strip line number, if it exists. */
>
>    Why?
>
> > +             strreplace(token, ':', '\0');
> > +
>
> ...
>
> > +
> > +     aligned_addr =3D round_down((unsigned long)addr, sizeof(long));
> > +     mem_ptr =3D round_down(aligned_addr, KASAN_SHADOW_SCALE_SIZE);
> > +     shadow_ptr =3D kasan_mem_to_shadow((void *)aligned_addr);
> > +     shadow_bottom =3D kasan_mem_to_shadow(end_of_stack(current));
> > +
> > +     while (shadow_ptr >=3D shadow_bottom && *shadow_ptr !=3D KASAN_ST=
ACK_LEFT) {
> > +             shadow_ptr--;
> > +             mem_ptr -=3D KASAN_SHADOW_SCALE_SIZE;
> > +     }
> > +
> > +     while (shadow_ptr >=3D shadow_bottom && *shadow_ptr =3D=3D KASAN_=
STACK_LEFT) {
> > +             shadow_ptr--;
> > +             mem_ptr -=3D KASAN_SHADOW_SCALE_SIZE;
> > +     }
> > +
>
> I suppose this won't work if stack grows up, which is fine because it gro=
ws up only on parisc arch.
> But "BUILD_BUG_ON(IS_ENABLED(CONFIG_STACK_GROUWSUP))" somewhere wouldn't =
hurt.
Note that KASAN was broken on parisc from day 1 because of other
assumptions on the stack growth direction hardcoded into KASAN
(e.g. __kasan_unpoison_stack() and __asan_allocas_unpoison()).
So maybe this BUILD_BUG_ON can be added in a separate patch as it's
not specific to what Marco is doing here?
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To post to this group, send email to kasan-dev@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/ebec4325-f91b-b392-55ed-95dbd36bbb8e%40virtuozzo.com.
> For more options, visit https://groups.google.com/d/optout.



--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DW%2B_Ft%3Dg06wtOBgKnpD4UswE_XMXd61jw5ekOH_zeUVOQ%40mail.=
gmail.com.
For more options, visit https://groups.google.com/d/optout.
