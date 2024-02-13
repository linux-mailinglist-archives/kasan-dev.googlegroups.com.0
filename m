Return-Path: <kasan-dev+bncBC7OD3FKWUERBHHJVKXAMGQEH7DDGBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id E67868522FF
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 01:15:25 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id d75a77b69052e-42c4346a56dsf49528721cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Feb 2024 16:15:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707783325; cv=pass;
        d=google.com; s=arc-20160816;
        b=uKR+DCI0uYonqOvuFpqToRJGiJ+edIBCV27Vm8L5A+DdxBwEcv5331RoEv6E7QDxEg
         gJGPNgQA+Qcg888MX1dSNi9QCe1xEDHoWxnDBOVcTD0OSTgSqEkIfqh7/+U+f/2RB1TS
         tc8fXTfdmFLC5HafCVht/THl6Ty2yyPJOFW+m0MOo2XC9QO96sllKj0eZxs90+7GuHnj
         uITwhW6iQglWI2291kThNEW/mEtkOTiQObgGFbz6xE2GyNPApdqLDDm3shCLPTLPbnku
         e5DzV1uSMXLFhy8UUM3hjoHIYmvrPeA9V9tN9XXeWHthysiiHb8fOf1nqqhzCl/y+b0U
         0kAw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=UBfK+VE7uKNl3JG9TfgOEUUblTjKAZwms7q2IbVxY6w=;
        fh=eXLMPAI8MU2jFWSIu9yWik+Y7E7EZghYBV7i9niMpgI=;
        b=BDQEQ3MPS+MXmwvbq3o9egE4juW1JjsKlYDRhUTuymh154iimm56gpHT37vMcol/7d
         Scx/4RtEJodiqhQlRtzEobphpSmYrJGD420/rPmttQm31pTqP0xhamCf0a2vv2BeZxY9
         GOenos0pajLQwlrO2JEdl3/bUQOR/GGidwfaY26RQR5oDTq2RpxdJnEHX4H9z/H725pm
         XmQbO29cR1ooyQeUn143tS6vsH81U4WF7rjhd2t5jvGII7+9hR0iwet9Y9h1NjFOLOeR
         Org/dqb8kHQCypxY7EbyXEDm31kps5Qp4oCI/4UvjtaoIDe2wvDPLuQ+TJ8n1M0h23gC
         gKGg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y+qCdWmX;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707783325; x=1708388125; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=UBfK+VE7uKNl3JG9TfgOEUUblTjKAZwms7q2IbVxY6w=;
        b=cCrIRp6XzJwzkyi51SqIk37ZWfE3OEBt4e3f7gHi2sm1OJtF+D0yfthP/h4P1p3ZKs
         sjQNiyCnpiO5TNR2ZqQ5UVJDul3aFAyq1qPJOMmBctNClWqWddnVqr3TC19FwDeHCm4r
         Pgr9NpZ76rJHmEAzw7JhWsalZDLJrdHkkVQKcJwC2sA0HqkcVSdzmtF0U6PSXOZ6jXWM
         fngA0537nztdtsL//p75Eode4X8PUK4hG2v+LaT6YBcoytwKJIlfA74XdU+GMY4gcZWv
         EGK8WLOLb1nYxso+8wN+f+dYPLjkeQIWhciryYqxhf0s+PFhhjzG6hbAmgdTiuXQcU5M
         WNcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707783325; x=1708388125;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=UBfK+VE7uKNl3JG9TfgOEUUblTjKAZwms7q2IbVxY6w=;
        b=M39obPBBBDpYQp91tNBWdAIHyyGvokLAS1F4om0ixIJAEjs5hzTrTHSvLgdvCUHO0f
         wvK7QnBrGlMtkuk+XIqdZUe3MxAHAOisx/NuHJUlM0Wk+noWWqZdykrtqAuwq7W+5K1I
         1OV+mn0mBgwqpPZGfGdJdBDrReEaK+qRogErCTfZ5C/WcB8HyYRP/fDV/0MZL9v/MlQ5
         XBtzmAGGwCq1aUJnuNiSAmG5RFiZ9xoneiawei2D+tzmBUFoZNhzsP7qz7imqSMsCkG4
         MkER8uLOlSDZMYIT7WTDfjSMoJrSZ44KUIdfjs7sdxHGY4dt5QO7biXXVGBRtfFejq94
         mRKQ==
X-Forwarded-Encrypted: i=2; AJvYcCXGUmmK45lp/lz8d+yKbQXLRyJALa4La+V3Q9vc2/6YOyJADgFUepOoO3h/eX0isNCDEZ/2wHq9PgByvpPJ7x3okPC9mpfAQg==
X-Gm-Message-State: AOJu0YyzMKq56YtgsSZXnqhbMnjIkM0YwfCMlT+LRw5DpE1C4/c9hS9c
	L6XB9RoSD0B5a1j70HM0H1P6C3DlGJM91/ZrmNYP6V+vnNLFTl3c
X-Google-Smtp-Source: AGHT+IHbU7jJG9SjLve/ELI3L+DxvDvlmJwmDo6PH1w/lrLZXzLhDZSp+ysM7sDokXMJ3wNubK9qRg==
X-Received: by 2002:ac8:5d93:0:b0:42a:9a3c:d8f2 with SMTP id d19-20020ac85d93000000b0042a9a3cd8f2mr11381598qtx.42.1707783324805;
        Mon, 12 Feb 2024 16:15:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:3d4:b0:42d:aa3f:7c25 with SMTP id
 k20-20020a05622a03d400b0042daa3f7c25ls540318qtx.1.-pod-prod-09-us; Mon, 12
 Feb 2024 16:15:24 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU7TdRgPNQNSCZMHhzlX6l+XRJ4KrARf92ucEr2SPwyj4uICt0mKsImuDlvAYsrZB+vmEvFT71ZbwnYIulpQHDkZXhHO4szoUmTBQ==
X-Received: by 2002:a05:620a:146e:b0:784:93d:c905 with SMTP id j14-20020a05620a146e00b00784093dc905mr9258448qkl.25.1707783324235;
        Mon, 12 Feb 2024 16:15:24 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707783324; cv=none;
        d=google.com; s=arc-20160816;
        b=gMJMwPAnxA4T/MljzqA1j0AtmCu5PeKu6yu3P52/yry91nvQCCiVWcktIdzi46iBQR
         sWsE32G0WePMwqXXjs68+b3ooBXfKN+xa3o/bJw5DaM6+NnGUDPa0Qrkuia/jJotZ99d
         X+7W5HkfPZvTol4C+/1bbA5RBpf8ziMeMBNKyliFe/V0/E6ItFKUOeg6K/GSXVTN3KKo
         8i9tNXe3u/NiqQv1ss7ilqHHpj9d6ld3CzdlBQ/DeVbfdNmYeP8hLPc/2WGO0XgcD+/+
         sxsHBF1/4iBJOZzWH2S2z6xeQ1DEQWEy7EyKuQySStnJswBvEVfHsvxTO1wD8t5Lad81
         Jt8g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7Wwz+pVnHJ9jIYCJ6OslYOBAl9//CS1GWKGLZ0scfs8=;
        fh=3YG5sjLL/kT4m0BGjY2oDpOEHJ5KkBN26V5ApLpmuvc=;
        b=V84awkZiR9iutSAgsYQVyET/J8Iqp4MI1/3lGnM54VMP0YTXDnZm18vY1t61uZ70+/
         7v95c6p/SXnVJ3q7Yrw2ZqpA657DF+QRGgrgobTEZAmk/2mGZnZH9sEs98xEi1Zjzetj
         aUw7IJhuIsGAMghkh/ULAU2dn1pN6ndjHE2MGZDDS+XFAJBo9b23i6BllClQHr9J/wfp
         51j0BVbPGgAO8GWmf+JrpYDRYZ+AzwdHY57vBedKRyjhQAKC5Ay4uKY/AKZVofa7JoPB
         l+jjSUhFggJy3H1DYa3l6MiZqyOpsCBRltpoJxde2XcBVd9Kv0PK2CR4hp1tBITLk9T9
         sDgw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=y+qCdWmX;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Forwarded-Encrypted: i=1; AJvYcCXrFenKCV7MZBVQL9yTJRY2B88G4ygx1HHSEB57qOU1OzO5TON1/XBOATl1hZ+TFWA/u5F98PT6r8tMlZSkHLnDOLIz+lPs8Is7OQ==
Received: from mail-yb1-xb30.google.com (mail-yb1-xb30.google.com. [2607:f8b0:4864:20::b30])
        by gmr-mx.google.com with ESMTPS id sn18-20020a05620a949200b007858b8cfc14si577675qkn.4.2024.02.12.16.15.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Feb 2024 16:15:24 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as permitted sender) client-ip=2607:f8b0:4864:20::b30;
Received: by mail-yb1-xb30.google.com with SMTP id 3f1490d57ef6-dc6d9a8815fso3886024276.3
        for <kasan-dev@googlegroups.com>; Mon, 12 Feb 2024 16:15:24 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVgIf5hqnmdemD1sBbG8WwVQ1/FDgpAx5gsXmoFxYlVrpOUlqUfDLDL7ZdgsOkf2Rw1eVTYrQt3dRNnnFMMBbdJ1zjIOHpd/F1WCw==
X-Received: by 2002:a25:ac68:0:b0:dc6:d158:98f0 with SMTP id
 r40-20020a25ac68000000b00dc6d15898f0mr6974706ybd.52.1707783323411; Mon, 12
 Feb 2024 16:15:23 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-34-surenb@google.com>
 <202402121445.B6EDB95@keescook>
In-Reply-To: <202402121445.B6EDB95@keescook>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 12 Feb 2024 16:15:12 -0800
Message-ID: <CAJuCfpEoS=ea90EHHc-Kwg3G3_ZWsVgKvhRiZ4SVuGARBe=vnA@mail.gmail.com>
Subject: Re: [PATCH v3 33/35] codetag: debug: mark codetags for reserved pages
 as empty
To: Kees Cook <keescook@chromium.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, ndesaulniers@google.com, 
	vvvvvv@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	rostedt@goodmis.org, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, cl@linux.com, penberg@kernel.org, iamjoonsoo.kim@lge.com, 
	42.hyeyoo@gmail.com, glider@google.com, elver@google.com, dvyukov@google.com, 
	shakeelb@google.com, songmuchun@bytedance.com, jbaron@akamai.com, 
	rientjes@google.com, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, iommu@lists.linux.dev, 
	linux-arch@vger.kernel.org, linux-fsdevel@vger.kernel.org, linux-mm@kvack.org, 
	linux-modules@vger.kernel.org, kasan-dev@googlegroups.com, 
	cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=y+qCdWmX;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b30 as
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

On Mon, Feb 12, 2024 at 2:45=E2=80=AFPM Kees Cook <keescook@chromium.org> w=
rote:
>
> On Mon, Feb 12, 2024 at 01:39:19PM -0800, Suren Baghdasaryan wrote:
> > To avoid debug warnings while freeing reserved pages which were not
> > allocated with usual allocators, mark their codetags as empty before
> > freeing.
>
> How do these get their codetags to begin with?

The space for the codetag reference is inside the page_ext and that
reference is set to NULL. So, unless we set the reference as empty
(set it to CODETAG_EMPTY), the free routine will detect that we are
freeing an allocation that has never been accounted for and will issue
a warning. To prevent this warning we use this CODETAG_EMPTY to denote
that this codetag reference is expected to be empty because it was not
allocated in a usual way.

> Regardless:
>
> Reviewed-by: Kees Cook <keescook@chromium.org>
>
> --
> Kees Cook

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpEoS%3Dea90EHHc-Kwg3G3_ZWsVgKvhRiZ4SVuGARBe%3DvnA%40mail.gm=
ail.com.
