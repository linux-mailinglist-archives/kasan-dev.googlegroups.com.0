Return-Path: <kasan-dev+bncBC7OD3FKWUERB7XC4OXAMGQEKKS35SQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 89A03861C6C
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 20:26:56 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-6e4c85a1437sf750438b3a.0
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 11:26:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708716415; cv=pass;
        d=google.com; s=arc-20160816;
        b=xHy2tsHrH/cQxKcD8zZorF/EIE+QcgDipHrs/UoLVFlq8EH2JYdtj1Ve3O4arRd11y
         XNhT2YQmOsy06OYl9M/nKquLKXM+amOF6dBW/q6VJ/Tq+55HjoFyT1HGjKim8X0fbr1P
         hO67LZBgF2/V6FnYHn7j/1rJXFF9gh70CJMuyYW/VQYg7cugcPijqTnllsJLRrP2SZDv
         OxhAek79+pUBtDLrlCcVMkxdxWhcgP1Fxbsj0lTuK+OejF4lVgXLREh/+JpBPvuECRDt
         OvAa/K9N3Zj/iOPB5GUkvhr4YEyEJPmFLcnZ3l1jZwTOkw/uFIGCUmvW+yr1aTULT9zU
         k9Tw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=URjm9DB0jkkAun2gg1Z6npSMbg/91ggRryhJToo7lLw=;
        fh=UzmWSyFS/MV0vwM2iuZEjeqZWWsEG4ry7QEq9nBX4c4=;
        b=TRQFPVgtj6XihrlgHS7IraGFFDuUPr+P5SN+k/f2ULChOjSYarx5p4vEtjUTrfhXFW
         C2ZahNsSw+U/ZzC3rTJSpaa/vJ/Yl+ojJDVT4r8j1xm8kfQuVVs3ly2ZuQeyUv+WNoY3
         P9xSRYL38N+912Yxw7aFUn4woiVM6QlsLFMc15lQP6uOt2t8h+4MZLQZhL27Fncd0psV
         uNDf8OtGNxHLqksMTA9gM4YWsTfB7BESavVT/qJK4629wiWRCePjZFLfMy3dah5oqDs8
         fWwt+Dsg1Uh2E/3nLn34FHJJGIxIj5giDWnVtT9kwYrhPOdvFo89oO/Wcz8Vrl1XQZZZ
         PL3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FIPZyoht;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708716415; x=1709321215; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=URjm9DB0jkkAun2gg1Z6npSMbg/91ggRryhJToo7lLw=;
        b=OIf+lHWf4EOaX61JUOhO7Dh20M61QaqEG61Re56f7dLVWfaF5/WK1w8RUo/wFofz7Y
         LI0u9kBlsRZAZFJwUxfr1L32kvBWKz0uQelFvpvVqsmN0LWfDy5pzt4OncxBSdT8cZjn
         B8M9HIbV9g7ywgXlPebnAqOOzWMcHq57Q2k2pNJ2pkifO+bLkQ388gRiEBPQfHTQxzfG
         /Dl9RAY7rf0+dAxU0JIiJhWbMJ0vEJ+P+CN7bA9S3G5JDKkZeprjeD/tIoYHdPyqZaKS
         2t6qT7YxSc7Jk6pJsrYN6nSXX/1HnkohPNezcvfw2Zi5ci5+1aNu45T3/3U1Ti1hHabt
         u3AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708716415; x=1709321215;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=URjm9DB0jkkAun2gg1Z6npSMbg/91ggRryhJToo7lLw=;
        b=ck35n1abIsDh9usJOMZtNJoav3G3xxZKUIbYCpFmGMax4fRKnKb22Lr5FosP/xs6G1
         l9pig+nN+l0QrCHUgIAQbFrLlUpHW5iTcZo7oNlS+pP6oWCduJThOKLzWvw8i/emKBEs
         EDIkA//jPqWULMz9TQyxrQtNNE9bzGwClnXWD+dI+d2JNsQhIK0uaapNwKrAeUTnLOxi
         +SqsBm8uS3r1PaRo8bPfbXXm/VCvC9oHv9dR2cnHFsUWclERummbtMOcxoxG+jbeiGp0
         Q8ffJnICYzBuORZVv8/4Zz44bWTtjhB4yiuPoAyRNR2nVV5xIs3ieJZ6CsD0FXxltB6E
         gN9w==
X-Forwarded-Encrypted: i=2; AJvYcCWsoWMgiiVjMRi0AcxWh0KDYwMQsTIIjFiQWKi/6/p6W6caigCktVm/SxtTEVDDpO65PMY22paeT3tO7g42qJZNTnUWbKzdWQ==
X-Gm-Message-State: AOJu0Yxc4Xw84NWxRCHVNvDbGXl78MHHjxjnGg1pkEKdTnY49fqNUjOo
	y6Ws8pchT/ntwuKxhI7f48O47jgLNG6hJHGNz5X1D6MnQFDqDp7N
X-Google-Smtp-Source: AGHT+IFyeA7f//1gYU6XaVeTCUvmB/IabBffftCw4bHuyuomfCLjmdKhobJyvL4MWOuy3WVnJdRheA==
X-Received: by 2002:a05:6a00:1ac7:b0:6e4:d198:6d66 with SMTP id f7-20020a056a001ac700b006e4d1986d66mr947578pfv.7.1708716414708;
        Fri, 23 Feb 2024 11:26:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1d23:b0:6e0:f00b:3ffe with SMTP id
 a35-20020a056a001d2300b006e0f00b3ffels761154pfx.0.-pod-prod-01-us; Fri, 23
 Feb 2024 11:26:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVyAlfmO5+ddkgFMEe2/Wykrp9pRGurBA+JCkgB1FO8wrsJ9suq2Jj4vMbufJ6jUMlJ1rsKBMajQ1VJJU7boPVVHmQ2kcU22qc0pw==
X-Received: by 2002:a62:5ec7:0:b0:6e4:aca:ce0d with SMTP id s190-20020a625ec7000000b006e40acace0dmr790430pfb.31.1708716412948;
        Fri, 23 Feb 2024 11:26:52 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708716412; cv=none;
        d=google.com; s=arc-20160816;
        b=sRECwtrZqQI3IS3DEVeJ8M4D8XL0HK0akEMvQ9GB6qMQAFYaLd2F79KNfszrkJYgY7
         tN1RDO89KQkxZRkw22P5CiDg4+RQKAl6+l/lvfDUdGgka33ES7EcgS8hUCAJIllPdCxI
         WlVC3jz8WDAW7pqxbUNlfCjBmgXihgxQbVLaQaJ6nr3mQj8VoiI87tFDas083ZEZWK6G
         F8szZBNAXVsPgm2xb4uaaA0fY261xJsRdCLLMoJpGuJHHNJZXhNfgjFvnQnGEHpG8zCw
         CuHEYK6Mbdsgt+CQ1g3hOIzomNqSRdurzxA1Nz85Pbnkuy5rxoc7Lgd6u2I/dRUcNM3V
         FK4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=R6zUV9LQ644WPBwU2nAdaKkCRupl6ITF2pP4ziWZMV0=;
        fh=wqg9droly7KTTnoG2gqx2P630YXZjlqJtekcCz2sGvw=;
        b=vJEz/Tdvt5FplrQzqULqU3tquYgdpHTXyb+9GzvBjeFGM4FIcMZeAQ5rOW80+py+x4
         1rpeeOO5fbfKmg1eZqxEVvICE0ahspvfNQ6NYGKiLvJmdW8mxbfXz10czmKunQ/APne9
         ZnBgJdhh3zhHSSaWT3ZNYf01yfGM4b7/7aRbZf5tFFjvd3aX2dlyiJUcJ06hGVLntQdR
         MLsNLyBDYh3YtuZI3gjxBK4jTLVWyFVYbG1/q7MuBv0bA0CbLfsBe2LLj+JvFU8QTpyV
         SRifnTbduHJDD67R5gQfys+M++Vho+feuGEinfRp9GAZbDJ/DyZn9HeEfW+c5h4J65Db
         YrKA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FIPZyoht;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id f12-20020a056a0022cc00b006e4eef1a4e8si84459pfj.1.2024.02.23.11.26.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Feb 2024 11:26:52 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 3f1490d57ef6-dcdb210cb6aso1353631276.2
        for <kasan-dev@googlegroups.com>; Fri, 23 Feb 2024 11:26:52 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUZ9qlpar2UCuFpSalRxUDhX6Dk6mjcDd+mRyPN44HY+J6fAnEI51EeyUM6a0sJBoO9J/Y0ln5QJXd3zWw1bBfstTOX5FhNHJheZg==
X-Received: by 2002:a25:2653:0:b0:dc6:b088:e742 with SMTP id
 m80-20020a252653000000b00dc6b088e742mr843579ybm.8.1708716411749; Fri, 23 Feb
 2024 11:26:51 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-7-surenb@google.com>
 <Zdc6LUWnPOBRmtZH@tiehlicka> <20240222132410.6e1a2599@meshulam.tesarici.cz>
In-Reply-To: <20240222132410.6e1a2599@meshulam.tesarici.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 23 Feb 2024 11:26:40 -0800
Message-ID: <CAJuCfpGNoMa4G3o_us+Pn2wvAKxA2L=7WEif2xHT7tR76Mbw5g@mail.gmail.com>
Subject: Re: [PATCH v4 06/36] mm: enumerate all gfp flags
To: =?UTF-8?B?UGV0ciBUZXNhxZnDrWs=?= <petr@tesarici.cz>
Cc: Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, kent.overstreet@linux.dev, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, rientjes@google.com, 
	minchan@google.com, kaleshsingh@google.com, kernel-team@android.com, 
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, 
	iommu@lists.linux.dev, linux-arch@vger.kernel.org, 
	linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FIPZyoht;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Suren Baghdasaryan <surenb@google.com>
Reply-To: Suren Baghdasaryan <surenb@google.com>
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

On Thu, Feb 22, 2024 at 4:24=E2=80=AFAM 'Petr Tesa=C5=99=C3=ADk' via kernel=
-team
<kernel-team@android.com> wrote:
>
> On Thu, 22 Feb 2024 13:12:29 +0100
> Michal Hocko <mhocko@suse.com> wrote:
>
> > On Wed 21-02-24 11:40:19, Suren Baghdasaryan wrote:
> > > Introduce GFP bits enumeration to let compiler track the number of us=
ed
> > > bits (which depends on the config options) instead of hardcoding them=
.
> > > That simplifies __GFP_BITS_SHIFT calculation.
> > >
> > > Suggested-by: Petr Tesa=C5=99=C3=ADk <petr@tesarici.cz>
> > > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > > Reviewed-by: Kees Cook <keescook@chromium.org>
> >
> > I thought I have responded to this patch but obviously not the case.
> > I like this change. Makes sense even without the rest of the series.
> > Acked-by: Michal Hocko <mhocko@suse.com>
>
> Thank you, Michal. I also hope it can be merged without waiting for the
> rest of the series.

Thanks Michal! I can post it separately. With the Ack I don't think it
will delay the rest of the series.
Thanks,
Suren.

>
> Petr T
>
> --
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kernel-team+unsubscribe@android.com.
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGNoMa4G3o_us%2BPn2wvAKxA2L%3D7WEif2xHT7tR76Mbw5g%40mail.gm=
ail.com.
