Return-Path: <kasan-dev+bncBCCMH5WKTMGRB2VRYWZQMGQEX4D75SI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 75A4D90C5A5
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 11:52:44 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id 98e67ed59e1d1-2c78c2b7f4bsf235167a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Jun 2024 02:52:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718704363; cv=pass;
        d=google.com; s=arc-20160816;
        b=HNZVaNQ3s6lvkYrxO8d59ixAMyD/116wrnSHt1FA/9a/dfLLKWFhiEn670A6i9wrwS
         kYkR4wvGOPHU0GWZxHDgHqh/FaN6XZQtCZAUON0CbHHtevbxk4evabF0gJQxDSm6W2r8
         Tt0TtV8hZLy+XZ1reTKMjLs46oa5y9KqfXugA8TT+M5P9cjhLERO/aa5Qbsjqe30bbaN
         UwfaeX5lQ7rkw5RHePlxiZMTYH52aL/QU1wK3ir6KW4gGPXymXuJTL8rbkfMyVt7QJ1M
         Tc+N4ZnNGTqbZHTaVKMhy3t/azlfYDBbQzgOQmMRf8Gh/Cx4E9uxr2CeuBI3Oh13arEK
         Cy5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H9GPe51bqQqlHlLMoHhJBiZr6cFG2sXlFXMn+YStvXo=;
        fh=QOSgTWhW9bQmps6fsnUO4e2iGgGL/V/l/xPiBC+Ckjw=;
        b=CD/V5wlDCQoBgBvFOi5Sj1w55xOUh3X5UMv7sbXRE6H4JYYkBfERFNyg2TcheQlUQw
         UI6VxO+Tk/tmrDL4+3VkWus5J4DM4ZLwhV5JfKshv00ZBN4PAhE8uji9H3dxw1QPRKLN
         eiD/z8yfF2D1RZ6KDs0Sq3wZzQjbG1xQcAEnHmlmtkfbSqswaTpnMyaBkrfe5WL/5HBt
         J4fRVHlp1w+TMm7SJbn6QJHdnTfxMWg6ugt9wh+hGSobmQ6D03yS3w3V69HXKBknBdof
         dFZg/zdckm6YpEieaJ0utXLUT12Hv6O10lpbWR5KiibhWJuobSMEm/ufvFP7dslJjLyS
         vqTA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=psTKW4iy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718704363; x=1719309163; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=H9GPe51bqQqlHlLMoHhJBiZr6cFG2sXlFXMn+YStvXo=;
        b=JJlYE2C4eeIWQnWtVuvksE66Ut1BX5QJ0fM7FVBK8xZqiUMp5AvNCE5ekUz1CHxw/h
         Sc4Q71yDoXGpRCgtXY2giEQFzGf4u2XFiXR/9wLnaRq2tkXBX8L9sBOP0P5/+ezSzZCb
         /VIBqmSTBHD22I2pazTtOudbVZ3vnX7KKdaEhBFG28dIrjcWdYQqT+inzC+B5cxaBwRg
         xk5tY3ITo3llm2L037Upj4LS5H48BKEv0X8XowJdq1FufcVj7YGQ1wyIPHrMlAqDVVBn
         ndI64bTKCnQKgYAAo/MtAnFEXSOKiHshkk1btC4NoSkNzuU+4zSBqS8Tkxtn64y6b00S
         bKAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718704363; x=1719309163;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=H9GPe51bqQqlHlLMoHhJBiZr6cFG2sXlFXMn+YStvXo=;
        b=hH/EyxwBcvQ+Xe+nSXvYmAqqUnm3+8sf1wAnpuiYgJpXJmcAjnOuv7KmxtjxMtW7Sr
         Xq5K46ufP2YJpWhppMJW/DGfuYxqQQpU5b7G0E1gnlvcyWcnJsD5mIhxIT33x52Lammy
         BdHKwlnW6D87dwoSBZNCBYHAY48dYca/mnv72Mm1qFj56zYLe7Y2sYAPdROVe6enoHGb
         CmmrItDgS6KVJRll8eHKYK0BOOprpYLHaAKNAMjEaFsP7c9TzQl/agjyIWHGk1YUfMs6
         3CKxT/MQVJ6OZ/lQKxm+xztbjHOU7QzMF3NZXpkylySiBWeqGPL219NJW4HwZL5FIP1H
         AqJA==
X-Forwarded-Encrypted: i=2; AJvYcCVWBNsTt2WOjyfIaybNe3ve2t5qoEL8Dvl1scVSBgGe8/cFuTFLtpJTH1Qn2X7ddUC6dWZILzoXK+xXhU+ElahHcGXK9xYCIg==
X-Gm-Message-State: AOJu0Yyf62bn1KdfDqTUqYOywDMHD2aSnX+mfkyDDTR5bDZXktqnRCVA
	97dj637XiiXu1Z89v3I6ZYiPgftC6MRzM0aQpxZaVhIo3swBU2ik
X-Google-Smtp-Source: AGHT+IHYBq5FdtrVKD2tV0yW4LwyzyTjPUVvaQzHVkNx5wq60wO95FBb67H9NhVOuHCgqqzJt2TOiA==
X-Received: by 2002:a17:90a:a389:b0:2c5:2acb:1acd with SMTP id 98e67ed59e1d1-2c52acb1bf8mr4965133a91.10.1718704362607;
        Tue, 18 Jun 2024 02:52:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:3508:b0:2c5:128e:23d with SMTP id
 98e67ed59e1d1-2c5128e043els1516410a91.2.-pod-prod-08-us; Tue, 18 Jun 2024
 02:52:41 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWKvgAmg3oWpGYkhkduIZNDjYPIToUao0x1gjqIMh4dw+cRAPGBIOJkjJ1yDtP8KdjyUfndGBeXCspHrgvZd6KcrY/uzWVUgXqfNQ==
X-Received: by 2002:a05:6a21:33a7:b0:1af:a475:e043 with SMTP id adf61e73a8af0-1bae7e9362emr16575428637.32.1718704361504;
        Tue, 18 Jun 2024 02:52:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718704361; cv=none;
        d=google.com; s=arc-20160816;
        b=dgfZpjipFeHqrU+hFPV3fSSRqbwD1bMD548Bt3LBEVMDGmXlsDN9ZuJ87XL2NJmiBH
         5nfva22WQE8Czpk5ouetwtt9N7nveMNWZ1ggaSJ6gR0JbI2xDVOXLnHLOgQlGZYkwXCk
         D3S83JrjoO8ryBCILJtFBbyALfHAwPeWI7SB5pcxAG07DVV7Hd0FIWm3PE3u76EWUUC7
         UfVIfHEBrS+KSEdHEHcx1eo3XLOzoT06xGHtMX2XI41YNvI+0HotwdQeFCRLgGAampoA
         FUYoRsFTq54MhjzWtbFx1OfQ95AGj2uLS9jlwjT2yha57T0q8zzKBYMOLC+JozLNP0p2
         C+FA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=/lD+4/1pW5cDhxFei3+MLKsCC6iwlHSFD/OS/9oOq0k=;
        fh=jrj84tHEYIaVxT1dDTqi5MHm3EI7NCjAjCD396kik3o=;
        b=I0bx8Rtc7Gh/IRZT6uhNzJG5IlMfQa13Z9PWC6bzSuwcqweGiIRFt19dT5XovneyPm
         htToYowrAfrnMhJb+GBR7/VnPQGZdwEt/8gXe625CdtIV3Q4iPBwu2vTpjtxZih4zhmI
         CRWcM2cue9DVsc7vLCubnZQUlePi/u4Yexl/EfzxbB0hZPgaQ8tybuyYenOxMrB5aXEo
         y+yMjl9Yspm1uuGLwdrGTPe3AflJ2sFpfwICfbHL8ixdu7TtHNPgN+u8HmFm0lAQAqft
         e3jprvOqCq2mm2o2kAk7mOM8zc9tqXC+xo2UMR0UOqfDr8cPVRGDjZ2DP5K/EN1/LeFu
         PKYQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=psTKW4iy;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1134.google.com (mail-yw1-x1134.google.com. [2607:f8b0:4864:20::1134])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2c738c1998asi69039a91.1.2024.06.18.02.52.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 18 Jun 2024 02:52:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1134 as permitted sender) client-ip=2607:f8b0:4864:20::1134;
Received: by mail-yw1-x1134.google.com with SMTP id 00721157ae682-632597a42b8so37600877b3.3
        for <kasan-dev@googlegroups.com>; Tue, 18 Jun 2024 02:52:41 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUcJbcXBwtW0WIIlj8rji0C9ptYKZUi3yjLtw6dFhyEhRXFOF5CSceS+dYCtfCrHcQRZtsYFTRMgqP9PMJsTvTgp5AuTcxacSv2LA==
X-Received: by 2002:a0d:d456:0:b0:632:c442:2316 with SMTP id
 00721157ae682-632c44224b4mr101739057b3.3.1718704360687; Tue, 18 Jun 2024
 02:52:40 -0700 (PDT)
MIME-Version: 1.0
References: <20240613153924.961511-1-iii@linux.ibm.com> <20240613153924.961511-33-iii@linux.ibm.com>
 <CAG_fn=X6wHfmGsVgdqwms_Hk1CQAZ6M5623WyatjVp=Uk-z9pQ@mail.gmail.com> <e91768f518876ec9b53ffa8069b798107434d0dd.camel@linux.ibm.com>
In-Reply-To: <e91768f518876ec9b53ffa8069b798107434d0dd.camel@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 18 Jun 2024 11:52:03 +0200
Message-ID: <CAG_fn=XhWpLKbMO6ZHpnxQDh+PXrTxBnL9X-1zZtBj-CoVk0=g@mail.gmail.com>
Subject: Re: [PATCH v4 32/35] s390/uaccess: Add KMSAN support to put_user()
 and get_user()
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Heiko Carstens <hca@linux.ibm.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Marco Elver <elver@google.com>, 
	Masami Hiramatsu <mhiramat@kernel.org>, Pekka Enberg <penberg@kernel.org>, 
	Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik <gor@linux.ibm.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Christian Borntraeger <borntraeger@linux.ibm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=psTKW4iy;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1134
 as permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Tue, Jun 18, 2024 at 11:40=E2=80=AFAM Ilya Leoshkevich <iii@linux.ibm.co=
m> wrote:
>
> On Tue, 2024-06-18 at 11:24 +0200, Alexander Potapenko wrote:
> > On Thu, Jun 13, 2024 at 5:39=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm=
.com>
> > wrote:
> > >
> > > put_user() uses inline assembly with precise constraints, so Clang
> > > is
> > > in principle capable of instrumenting it automatically.
> > > Unfortunately,
> > > one of the constraints contains a dereferenced user pointer, and
> > > Clang
> > > does not currently distinguish user and kernel pointers. Therefore
> > > KMSAN attempts to access shadow for user pointers, which is not a
> > > right
> > > thing to do.
> > >
> > > An obvious fix to add __no_sanitize_memory to __put_user_fn() does
> > > not
> > > work, since it's __always_inline. And __always_inline cannot be
> > > removed
> > > due to the __put_user_bad() trick.
> > >
> > > A different obvious fix of using the "a" instead of the "+Q"
> > > constraint
> > > degrades the code quality, which is very important here, since it's
> > > a
> > > hot path.
> > >
> > > Instead, repurpose the __put_user_asm() macro to define
> > > __put_user_{char,short,int,long}_noinstr() functions and mark them
> > > with
> > > __no_sanitize_memory. For the non-KMSAN builds make them
> > > __always_inline in order to keep the generated code quality. Also
> > > define __put_user_{char,short,int,long}() functions, which call the
> > > aforementioned ones and which *are* instrumented, because they call
> > > KMSAN hooks, which may be implemented as macros.
> >
> > I am not really familiar with s390 assembly, but I think you still
> > need to call kmsan_copy_to_user() and kmsan_copy_from_user() to
> > properly initialize the copied data and report infoleaks.
> > Would it be possible to insert calls to linux/instrumented.h hooks
> > into uaccess functions?
>
> Aren't the existing instrument_get_user() / instrument_put_user() calls
> sufficient?

Oh, sorry, I overlooked them. Yes, those should be sufficient.
But you don't include linux/instrumented.h, do you?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXhWpLKbMO6ZHpnxQDh%2BPXrTxBnL9X-1zZtBj-CoVk0%3Dg%40mail.=
gmail.com.
