Return-Path: <kasan-dev+bncBCCMH5WKTMGRB5WOZSVQMGQEPX5EXUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 28C9C80A560
	for <lists+kasan-dev@lfdr.de>; Fri,  8 Dec 2023 15:26:00 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-59085a47037sf1154217eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 08 Dec 2023 06:26:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702045559; cv=pass;
        d=google.com; s=arc-20160816;
        b=AaG6asqNlJ7pXuLNiRDgc4drFxsxj1PjTlZk8hyqXccVPEXRm5fhvDcjSMlcqd0w2c
         7Xl7vfVMj0QmE7+KFGQimQckL50hQ1Ax8rw5/YigjOsTQ0Uhz9OtH8IzrQS+ujlYakrM
         W3VUstgQ2V+3f4UAWYeDrd+jik7ubFGB8ZK3sDVHJThjAHek4RyvCFaSPh3tXugHHdfa
         sb33nXTe7y/8No/lPpj8P71iqYY9T+yVrYqH4jkO6+VlmAEH+7v7kBAHmdUCEiG2kdkS
         9ekHocDnNAsNKyNpktBnir64wdSw/fIukqs+/IuXOWGZmzL4aEpVP1fmE0GocULe5Mb0
         qjTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=AWY9ABjWueOsAjR9NQSuACT7HbQCIel93Es/HzUVZeA=;
        fh=4F7/7GXXxyuo8X/UbjieRU7LMIhIis3FKkbV38g4Hg0=;
        b=oZq37haisDvfzzzB0rhXk0KQI+JQnsUlkl5TGI7ELKT6fX3l7Euk4IUICCbDqmq9xT
         8Jcw4d/CoRhZWKeFxECz8lsvUbgUcy2tCwzYlBI37oAhU1IPe0ItUtdGZwOFv9b4/15u
         5L7J0OIiijJx9DiBkYYE+B2be8VOI67QKKlYb468F6Y/h36u5+vh6HbiT07xvfvdReZ1
         LVv5vsCdDKkTT/EDmWaFFuYVM9FP9ayxVO2JY1S94VuiFCNd5UrnXfX85tngfnmWmmg1
         tLlVQm1HBxQMPnpJiMVqIG4LdX+7S7+mK91L9yXqGEHD9Wi1VWToZ3I+y2twHtImyufN
         uZ9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QMcqBwqx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702045559; x=1702650359; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=AWY9ABjWueOsAjR9NQSuACT7HbQCIel93Es/HzUVZeA=;
        b=dpe/QFqZtVcWnGZjlx34KEHNwoTtmfyBn1kFmWF17kW1+vUkE1uMeAtQWSRVCe3LVK
         xnng4ehRvpDk8aiBoA73RCfDtDY6hc9RuW45rqmPLZDKmCVkK1E2gGrpkZEJjf0nlhTN
         NdEWDb/CHrOrjrKZtMs5YenHHvg8soiqtFqLJdmAZL7n8Ie4MNApybpAmRHs3fjNtmOV
         n3xDbqYx3++Xe8D64c/Xr3Vva5SIqZ6KZ3vKTF8h/UeFIvRE+RQXAb850KT5bP16KoNH
         A7izk+bLHYQsr7t2BhnjeI8KZszUf2oW39AdX5UCQZp3t+SdB276PW5M1qElIndncMAr
         uYGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702045559; x=1702650359;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=AWY9ABjWueOsAjR9NQSuACT7HbQCIel93Es/HzUVZeA=;
        b=g/ZSwIzrTxE/z8Llr+gSMqfSI+t60iIAfj50PaOt/BR470bnonNHBdCrNn55EE1I+B
         4Me/O70WKzSh4mXcj5pd5Ov8eaYuZGECMslJyHi64UZ8Gf75m7Tf6iL+FkA1i0n7ubG2
         Aj5HBBnxTJc+CsEOergndIZRBi7Ih1dH6ylpOjH2+XMJJQbSS8QcK3VDoybvJxfRKsVS
         H23Jp7WEw70qDznmhQ/IQkXmfyEqf5tDtISKT4mf9Kxc7qd+4gOGiBSVkDXbnR17hyyr
         wKhMVKHfsdczb0zYbqi1/VN7r+dB7MFfLD6TaasOMXSnSVeKGcI86tszRqTpFjsSHk/m
         Im7g==
X-Gm-Message-State: AOJu0Yx815hF1UgrLZ+oTweK21psrLfVm1/SdR/TL7gofWzaDHdwymmF
	N+vutm6GeMUTK1rsF82/HVo=
X-Google-Smtp-Source: AGHT+IEqOZU7NjOzwil5GK1hgc5scrRXrt0inbvacdwOhnZ4l+XtQ8blUeDSzTTu2yLNua0pzW6K7A==
X-Received: by 2002:a4a:d28f:0:b0:590:e85:199c with SMTP id h15-20020a4ad28f000000b005900e85199cmr149859oos.6.1702045558932;
        Fri, 08 Dec 2023 06:25:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:161e:b0:58d:be41:d2a3 with SMTP id
 bb30-20020a056820161e00b0058dbe41d2a3ls664605oob.2.-pod-prod-01-us; Fri, 08
 Dec 2023 06:25:58 -0800 (PST)
X-Received: by 2002:a05:6820:2218:b0:58e:2e05:d99e with SMTP id cj24-20020a056820221800b0058e2e05d99emr191490oob.9.1702045558166;
        Fri, 08 Dec 2023 06:25:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702045558; cv=none;
        d=google.com; s=arc-20160816;
        b=SEdo1ufdBRUOQz3+FMTDq9yUKYg+T81kmJGIMgCStPcdtBVlwVyuN69XYnaEJDgUn5
         hj9s79jvjmLi/PcOF4E/9Md2JYyl/WMw5dLvJ/bksFdLH+f2gVkHSoAMl5KpDElubNDU
         gkL+owH/qU98yphHzYKYct1Rkq412POiVA2y4Ne+o2L0LH+Cvx5X6NFULazAlUL0gZhr
         5nPRigB40A5ENsJMC1ARDSCnfUjytpOjjn2ndRVfH1zZA5BcP3g0mFUaus0VANmHwOYL
         4VzdoJ6oMsIjzic2PQWHU70rDvfp6xQFexu2CoAhpVf9KPR50S6WN7Ih1GTitcbXegr4
         P+fQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gMzKOjsadOdlzFzBDSAqUHFYwgT1E5TMaJuAbqx/ofA=;
        fh=4F7/7GXXxyuo8X/UbjieRU7LMIhIis3FKkbV38g4Hg0=;
        b=vLjMO/O1fZLOwueJEPLtReXu5HCcOpjATTOb7svjs2VNu7HoqAtyUJq+8MQvTElIko
         GKmG774zu0rX6dZMvvDHpJBQdTB3ZU4pijae/F1fv6KeChUTzyB/+Avi4VfM4qquuHQ6
         DP4BioBHcVAKTlyJ7lqHxuPtv6Zl8Ebu3T9YvPrSDlyNv/HORBHs50TU5D9Tngzes3Z9
         z6ugLHzvQgMwE0vUvdptthdvHUn71pztegnu0OLl6slBjLHcZdDCIBkK9wBmTntMUkaK
         q67kMu2PrxLz4UIDjMhw2rlIkqO3fnOu1Jo0UnX61p7Fm84G5L47+9qsoZqQKrV5tP5a
         ZQZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=QMcqBwqx;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc29.google.com (mail-oo1-xc29.google.com. [2607:f8b0:4864:20::c29])
        by gmr-mx.google.com with ESMTPS id e84-20020a4a5557000000b0058ddf7336a4si319237oob.2.2023.12.08.06.25.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 08 Dec 2023 06:25:58 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c29 as permitted sender) client-ip=2607:f8b0:4864:20::c29;
Received: by mail-oo1-xc29.google.com with SMTP id 006d021491bc7-58d956c8c38so1048814eaf.2
        for <kasan-dev@googlegroups.com>; Fri, 08 Dec 2023 06:25:58 -0800 (PST)
X-Received: by 2002:a05:6358:10c:b0:170:4403:83a6 with SMTP id
 f12-20020a056358010c00b00170440383a6mr3947511rwa.52.1702045557641; Fri, 08
 Dec 2023 06:25:57 -0800 (PST)
MIME-Version: 1.0
References: <20231121220155.1217090-1-iii@linux.ibm.com> <20231121220155.1217090-20-iii@linux.ibm.com>
 <CAG_fn=WiT7C2QMCwq_nBg9FXZrJ2-mSyJuM1uVz_3Mag8xBHJg@mail.gmail.com> <4f0eb4b4d4f6830f39555dc8a35f6ff88d6f8e63.camel@linux.ibm.com>
In-Reply-To: <4f0eb4b4d4f6830f39555dc8a35f6ff88d6f8e63.camel@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 8 Dec 2023 15:25:21 +0100
Message-ID: <CAG_fn=XUSfppyVMZO5K2kaii+OSLxV_UbHcn3cuH3zBt9J3g1g@mail.gmail.com>
Subject: Re: [PATCH v2 19/33] lib/zlib: Unpoison DFLTCC output buffers
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
	Roman Gushchin <roman.gushchin@linux.dev>, Sven Schnelle <svens@linux.ibm.com>, 
	Mikhail Zaslonko <zaslonko@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=QMcqBwqx;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::c29 as
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

On Fri, Dec 8, 2023 at 3:14=E2=80=AFPM Ilya Leoshkevich <iii@linux.ibm.com>=
 wrote:
>
> On Fri, 2023-12-08 at 14:32 +0100, Alexander Potapenko wrote:
> > On Tue, Nov 21, 2023 at 11:07=E2=80=AFPM Ilya Leoshkevich <iii@linux.ib=
m.com>
> > wrote:
> > >
> > > The constraints of the DFLTCC inline assembly are not precise: they
> > > do not communicate the size of the output buffers to the compiler,
> > > so
> > > it cannot automatically instrument it.
> >
> > KMSAN usually does a poor job instrumenting inline assembly.
> > Wouldn't be it better to switch to pure C ZLIB implementation, making
> > ZLIB_DFLTCC depend on !KMSAN?
>
> Normally I would agree, but the kernel DFLTCC code base is synced with
> the zlib-ng code base to the extent that it uses the zlib-ng code style
> instead of the kernel code style, and MSAN annotations are already a
> part of the zlib-ng code base. So I would prefer to keep them for
> consistency.

Hm, I didn't realize this code is being taken from elsewhere.
If so, maybe we should come up with an annotation that can be
contributed to zlib-ng, so that it doesn't cause merge conflicts every
time Mikhail is doing an update?
(leaving this up to you to decide).

If you decide to go with the current solution, please consider adding
an #include for kmsan-checks.h, which introduces
kmsan_unpoison_memory().

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DXUSfppyVMZO5K2kaii%2BOSLxV_UbHcn3cuH3zBt9J3g1g%40mail.gm=
ail.com.
