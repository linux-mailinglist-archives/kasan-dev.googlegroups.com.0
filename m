Return-Path: <kasan-dev+bncBCCMH5WKTMGRB35W26VAMGQE4PKKK3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id E76677EDD58
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 10:05:52 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-41cbc7d2e58sf7856651cf.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Nov 2023 01:05:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1700125552; cv=pass;
        d=google.com; s=arc-20160816;
        b=Of93nRIeyOnfnnu0zknVaJ6wTyJQWWXLy8yIzu993DehMCtFIdtFOTHqJKd3VhhkRQ
         vwtLkkmeOR1M3nU+75U6WKLryKK+OP1dFLu3IS1dM2+yJrLDlefF4oDBg0ltoouN0HVn
         TOHiquoDtKDkUwhvc3t4gzVlt8EsRgVOX02KBdOqYyVjkzifX36C7N3aWQvGv1ddS75k
         UZzf8p3+PHvLGyYsHC/c6x45P0wQdYIiAhs6V2Zcy0iIIwNVNwa0J7WLOInJaZeDn/ay
         UOhoiO7B+Q1t/k65gHXDh6lSDKPM37fDU8R4VvFJzCq0HouD9o9pUmvn+1ShlvwiwNKp
         MjRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RK4cdBTbaZNK3mwmQcgZ8wCyVdf4G8pmuHNn1ZYoAXA=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=C1hHxXQh06A+eatlCooStRYPNLJ6SbfspbvF9dlJDOH00qF1kSyWPayvt2zDrKVGF3
         Zpt7t2x8ERUkunX8sPol0R76nukfQSeeynC2q5AFUF6+1E0bF47Btx7h8TX6hnZhVqJx
         CFO9GgMsBsImzNhQfeGw5o1bqqHD0vT3jAxLSR8XwIbiseDo2RVqsTuxV6UtYGyZtCTZ
         cscdDhkTom9tI6PAM6uDzLw5WQhl+8ZWkx52m1dIZpylUB4bPamwJTx++gk2w7gfaVbT
         x1XftZLqsKLYTnDjWII/IwjqHHY6VB0I+3uuGzMEds2CBpVBczU53Hj2fy/hxQuNNn1G
         B+GA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Xk5b3+dz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1700125552; x=1700730352; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RK4cdBTbaZNK3mwmQcgZ8wCyVdf4G8pmuHNn1ZYoAXA=;
        b=HA1TmcFa1/Di52OoYzsFE0NQgkNIW3/c2Zrcxq63SioXV/HjZJxKXnOUfH3SSuLCi7
         A9QJGLn+VUa5cbKJy7ByZKhfoucbx3SfcJn2qRPsChecH/sXrgAhn3daqU3xbOtp5x6d
         KsCMVA4NlufX7BOnKfx4i+740x94wKNpN9XIwfvWIy9w7YZ91mG55eiI4vM20RnaSG8d
         e9epiet0hJjvtPlbKxvJYN05GDfN4i6Q/RUZvD7vLCu072Jj/Q/D4BSfwKTv9U3ONy3c
         /twmrm8dCc3zO7SKKNq5hJlENtMawZN8RTWN2/0EsWDWVET8vnEsoyI93Vj+DJLmrLu2
         jWlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1700125552; x=1700730352;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RK4cdBTbaZNK3mwmQcgZ8wCyVdf4G8pmuHNn1ZYoAXA=;
        b=t1gGaTZJZNTfF/zS5kARb0mwXFR6U2qWHwFg/cYSFE6oVYKqIq/ydkngGBD8MsybgO
         NRtygHDuUUxD6tTbgwudaQRuwkL76wzGsdW/NgYsYwW2bK+6+iVUuz5W1T/csJMp9F4b
         wYYzxnzcmdFnuuYoXwwifoiz3y3OWXAj+GdkKBGcTh0kbo8WXN7xVosTIHGkHKSsxU3X
         1PEs6sk6nYOOmO63EbjLXGxWEMete2yxK+eF/I6yR7dt90MKy190qkBv1m407TLOVPwU
         gIHnGjHM0Rl/5UQblWgUm5rvvY6DZhZAQb4N7P6x6JADwm+04IAPwJ3+uK/0NfYKqCvq
         iIEw==
X-Gm-Message-State: AOJu0YxC0LFuyiOqQf4sLSJ/B4KKMYKg9IbK8oKHqpHbas2s2auPEDeX
	acuEpDIZb3Sc38QBb4G8H+8=
X-Google-Smtp-Source: AGHT+IE/KrB97iiP1DZqX7DNXz+YrWhRun4hA2pkBhQ5sp3GzVfBxYPSiuWoWprfErsgexGlgkvRgg==
X-Received: by 2002:a05:622a:1448:b0:418:737:87fc with SMTP id v8-20020a05622a144800b00418073787fcmr9784594qtx.18.1700125551946;
        Thu, 16 Nov 2023 01:05:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:19a5:b0:41c:d1a7:9109 with SMTP id
 u37-20020a05622a19a500b0041cd1a79109ls162752qtc.0.-pod-prod-04-us; Thu, 16
 Nov 2023 01:05:51 -0800 (PST)
X-Received: by 2002:ac8:4e56:0:b0:421:c9a0:3e9b with SMTP id e22-20020ac84e56000000b00421c9a03e9bmr9647550qtw.3.1700125551230;
        Thu, 16 Nov 2023 01:05:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1700125551; cv=none;
        d=google.com; s=arc-20160816;
        b=Eo2pv6unvYcDxG7OBdvzamB9iTc6JLsciFX0LgTvvBqjycEvERR634xi7E0P+2Yp+8
         //8rqwWU94F1P20sgXPwyFftiHfReQ2kGdBrwwi4VVEUnQ4zEkc2UKzHOXymzkdEldMW
         5sUbf7/1PE5h+W9Dz5wTTlwsM+FnE9tSBvG/Tn4RWuBgMCHjTDD1f7j1sxeWH6Q47nWJ
         SVOvVCfZKFnHKz5jaQJPBi5mOW1veMkF+rTYM8uTdbMGXZUY4fPopzZXIJ0HsES6JFBB
         PMPcdS3OlupzOnV8bO9x5HN3XW35p+hkLx8Wt/ENX/WhhfGjK5RUPq2pv2SMtl1APeOa
         ByPA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=CJvcy5OQThQMBzLC/CmhcyXSfL+uAyptQQ2e5phxAM4=;
        fh=YZa8vkdUz4pzRj6QFVU/SyYW+LsIH/Wz0o5e5dUhKFo=;
        b=W8E+1EPMawuQIF/z1y8Yu9u7lx1sdPSq/dWlD0UmOOd139owwDg8zKy26I8U3ou0RI
         xUy+MOJctFJM852MYQbIdWA3PsinAO3w0NnG+Ca8rDPvOG4Pfvp5aWihJVJyjeO4jyd3
         yQioy2dBgWe2mhAkTA+9QFAR1US1ZKL3Nl41CYIQlawfyFwutgKzV5dY2kwgYY3CyQW7
         WRwXAiOX2g/0+rhjFDGt2Ns2Y1wtxPMrI5bi75Rs9lKzSohPJpPCjCFpcexkc6gBSEaq
         ToiZpvPfci8rCVSjcUZ9Lgiax9cgvW4EU1BuM6sqAITLLfi6C+2ZzxtP8c5ZXPosFRhm
         Ruig==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Xk5b3+dz;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1131.google.com (mail-yw1-x1131.google.com. [2607:f8b0:4864:20::1131])
        by gmr-mx.google.com with ESMTPS id ga23-20020a05622a591700b00421e709bf9bsi896550qtb.5.2023.11.16.01.05.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Nov 2023 01:05:51 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131 as permitted sender) client-ip=2607:f8b0:4864:20::1131;
Received: by mail-yw1-x1131.google.com with SMTP id 00721157ae682-5a8ee23f043so5884727b3.3
        for <kasan-dev@googlegroups.com>; Thu, 16 Nov 2023 01:05:51 -0800 (PST)
X-Received: by 2002:a81:8a41:0:b0:5a8:3f0a:618e with SMTP id
 a62-20020a818a41000000b005a83f0a618emr16007472ywg.37.1700125550745; Thu, 16
 Nov 2023 01:05:50 -0800 (PST)
MIME-Version: 1.0
References: <20231115203401.2495875-1-iii@linux.ibm.com> <20231115203401.2495875-31-iii@linux.ibm.com>
 <CAG_fn=WW1BUehMSsbjtPb4gKpakLGi3bF2KFEPxE4dV7n1ToSQ@mail.gmail.com>
In-Reply-To: <CAG_fn=WW1BUehMSsbjtPb4gKpakLGi3bF2KFEPxE4dV7n1ToSQ@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Nov 2023 10:05:14 +0100
Message-ID: <CAG_fn=XftAnT0=kxkjGrtn9QEye1Xayg_jw3Fk_cy6SforMTpg@mail.gmail.com>
Subject: Re: [PATCH 30/32] s390/unwind: Disable KMSAN checks
To: Ilya Leoshkevich <iii@linux.ibm.com>
Cc: Alexander Gordeev <agordeev@linux.ibm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Marco Elver <elver@google.com>, Masami Hiramatsu <mhiramat@kernel.org>, 
	Pekka Enberg <penberg@kernel.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Vasily Gorbik <gor@linux.ibm.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Christian Borntraeger <borntraeger@linux.ibm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, linux-s390@vger.kernel.org, 
	linux-trace-kernel@vger.kernel.org, Mark Rutland <mark.rutland@arm.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Xk5b3+dz;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::1131
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

On Thu, Nov 16, 2023 at 10:04=E2=80=AFAM Alexander Potapenko <glider@google=
.com> wrote:
>
> On Wed, Nov 15, 2023 at 9:35=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.c=
om> wrote:
> >
> > The unwind code can read uninitialized frames. Furthermore, even in
> > the good case, KMSAN does not emit shadow for backchains. Therefore
> > disable it for the unwinding functions.
> >
> > Signed-off-by: Ilya Leoshkevich <iii@linux.ibm.com>
> > ---
> >  arch/s390/kernel/unwind_bc.c | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/arch/s390/kernel/unwind_bc.c b/arch/s390/kernel/unwind_bc.=
c
> > index 0ece156fdd7c..7ecaab24783f 100644
> > --- a/arch/s390/kernel/unwind_bc.c
> > +++ b/arch/s390/kernel/unwind_bc.c
> > @@ -49,6 +49,7 @@ static inline bool is_final_pt_regs(struct unwind_sta=
te *state,
> >                READ_ONCE_NOCHECK(regs->psw.mask) & PSW_MASK_PSTATE;
> >  }
> >
> > +__no_kmsan_checks
>
> Please add some comments to the source file to back this annotation,
> so that the intent is not lost in git history.

Apart from that,

Reviewed-by: Alexander Potapenko <glider@google.com>


--=20
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Liana Sebastian
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXftAnT0%3DkxkjGrtn9QEye1Xayg_jw3Fk_cy6SforMTpg%40mail.gm=
ail.com.
