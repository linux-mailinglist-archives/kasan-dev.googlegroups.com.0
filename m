Return-Path: <kasan-dev+bncBC7OD3FKWUERB7WDZKRAMGQEBKADP5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13d.google.com (mail-il1-x13d.google.com [IPv6:2607:f8b0:4864:20::13d])
	by mail.lfdr.de (Postfix) with ESMTPS id D341F6F5D6D
	for <lists+kasan-dev@lfdr.de>; Wed,  3 May 2023 20:03:43 +0200 (CEST)
Received: by mail-il1-x13d.google.com with SMTP id e9e14a558f8ab-3314bf49057sf9405775ab.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 May 2023 11:03:43 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683137022; cv=pass;
        d=google.com; s=arc-20160816;
        b=R+LPA4Vc3zJ18QGS6DfBiygsVGVfyxV/YG8fD6u32rZUUZ0/6LtEp84Pk9bp+n/GRO
         iZ1H1irKSoXvxMzH8h+XsJiESgeFc2SqTp3dXsaBJDXkaSmd0A1H0bFI4dcMCt3LIA66
         uJ1vIOasqhpoGXl7VyxRK8N7KtB7h+5LoR4innvRny2wPU3pw47D0+fzDsu2j0VdFUmC
         /C4hfvqegsa6fyOpHnHvIo+XBqeaYVFQLC7FH9OGG2A5oDq73p78fsZakG98x+56RzBN
         LFJ3c6JWEZG34mia/zCRowt4PCa5XVOeW3yM4LsTwKUOZULoxlnc+xf9iDJyrM1sc4oH
         cNWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=xml5/4wGzUjpt0+Eqpt6eX2Qf5bJmiNJsXaUImH46eU=;
        b=JJhhsl0KW7r5/uivLZZTVcPNvxwG7tJEDiueZkalkZBEt7vbIsM93jda5PcZS6m4S+
         Ulvi6L2zw7DRGyF+l+JDJpRcdOkbbySki2DG3UXvfWlUMV4j76yoAom0T4AjgBX5QB1e
         KDwafaoE+eQx3y6YQ5g7A8Z1UAod7+LsxmodP2uQ1A1OQ61AGYP1YnzNM0cN7WkG/z/q
         ZHBh+4mdyexO4cy3zPpdMBdRYnwv8PDqldVODCB/cnObBcNThiXvKIICKrY4v7kmxbXs
         mdrUbfnnHY46VsACAmDDFD7yTq62GMyehdZ/RY1c+H8NjwZOLDOa5WZ4cnMPFIhf84xy
         9KTA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=L5MD7LDE;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683137022; x=1685729022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xml5/4wGzUjpt0+Eqpt6eX2Qf5bJmiNJsXaUImH46eU=;
        b=IY9hnZUSSoNYtHNJ9eOg9/OdldhLDHGFBJRemFOtzXdm7DXKMra3aHRt1IgXEvK+94
         u5v8zdUsLU0kZduBsa7NQDXcgYmIu4cyTaLcgaN3jG16wStKXIFBlDQddvncGYOQeO7E
         THxWdxuU0Zf83kMDrxv6MOmrdzu+Z010+gjIqfb8fYq0b7Tel4mV1Q0vrA6qUynvN2RF
         DSwQK/J0ysjXnpIIIbj1Fb03JpS5y0GG1HK5i9k5U7czwF1f7TDPpcq7Lvc1HCI7D0JS
         TQ/QYE0oacsSlfUtboRgCmkvtIoWrH9PciQa8dfeGamykhv0o6qvt3y6NV8VmNbHIgXa
         Z+Bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683137022; x=1685729022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=xml5/4wGzUjpt0+Eqpt6eX2Qf5bJmiNJsXaUImH46eU=;
        b=RdgtvXfv+rXi+BTFwnhQQMgVs8HsbTPP7GasSQ66KCpYOlE2WmW6U+Cf4Te/z9GwF3
         /ZorOLoF8RN+hmJbP8ow9NBCBQt+N0AgcvyxlQwa5vUetSzTsdLQoMLtW0HofTWRL4fh
         L4oYKn/i70cbFFIokFQ77bog677sKJSgnHO53/KICiKrW4+FC3RtDcokVbvh08DCjFPx
         x1w+XElSgaM6aE8SSSgcY109QtGpzNF4g/HIR9vqi+Y+hnDG+jZ5q+qsKAWGby1chx9X
         iivrrYCzujC2BjIX/q7USVFN1z4BAwctjvH5ymVgIsGta9F47VwlbkACj+N/I+Hd3/H2
         +X1g==
X-Gm-Message-State: AC+VfDxscqUzLkmky7XCl+58yKJHNsQn8Hv6xSsRAgYx51xIyBQ+d0mD
	s2jExB7Z/nRRKL/LIk2Oj3I=
X-Google-Smtp-Source: ACHHUZ5gX5AYxOQOMKNFbYYxMXtxO2/2TqynWUbtAL4l20vC/fdIG3czYXiItk912n1EXLOaNVue4w==
X-Received: by 2002:a92:4b0b:0:b0:32b:a8bd:50f7 with SMTP id m11-20020a924b0b000000b0032ba8bd50f7mr12028819ilg.2.1683137022652;
        Wed, 03 May 2023 11:03:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:11a9:b0:325:d4ba:8214 with SMTP id
 9-20020a056e0211a900b00325d4ba8214ls5236125ilj.3.-pod-prod-gmail; Wed, 03 May
 2023 11:03:42 -0700 (PDT)
X-Received: by 2002:a92:cd09:0:b0:32b:cc5b:debe with SMTP id z9-20020a92cd09000000b0032bcc5bdebemr14480178iln.11.1683137022112;
        Wed, 03 May 2023 11:03:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683137022; cv=none;
        d=google.com; s=arc-20160816;
        b=vzc3xd8HGIFsK4dLCGEadbmqNys30xC+2ScwEJLaSfHDGQh5RFzW+O+tbY8XAWRx3V
         FbEs+FgjbmyxFHrtq+DPlsWzHm6iwgq2Qyr4eR+pbbLemdUqW+Yv0nYXGROhlcqSO3gW
         D+PZ1wGUHuu7S9RZjA4J+kADl8eS1pgue32MiBTTzghowFXIASdjMyUO+swkHKAFBTuI
         sBzuMZVqJfVETFOBuNt7MEqt5THY9wh00CguUoe99wWyOeTx2U1vq+jTcbcRWCiwuDlt
         W98r0n9IHju+oeVr7BSA7HFnVIfUt1xjB1Va4JYlwMsTufkHBQRb8rkRLlReaI4HdaEN
         NPdw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=v9bphnAMm9U7G1bEITi+0ZLO/l3WQ/XqMzpkJeT7kyk=;
        b=LDLUOrmyxj/YOvk9nKL0h7K4FufFT9KqI0cPc+gQ+qSsifgwUTA5OCZsJgpkQ94xiB
         9blRfqSO+ej6R8NoQ7ygc7FByTR93DOjKpfxTfkPtcFlOsOB0qbeeIplEvf/IT2aLJN3
         Qq4MXDegKXATeY23ytHpSjxFMlB6z5HD1Lh7oK1jGzBxNRJMkKshpqpPTiF2s1BjfE/7
         smgeUr35MaSSiL+2E0NOhwrtqIZUHWVY8OIkAFjTNXXh801t6LvsqMwB5IJNcgxX8fLp
         SAFZnxxr60vK2s2aCTpFEo0722k3A+LGSasA4nvVCSPt3K//u2We4KkB4sinpBGMaSp7
         ij1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=L5MD7LDE;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id c7-20020a0566022d0700b00760fac3ba91si1825906iow.2.2023.05.03.11.03.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 May 2023 11:03:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id 3f1490d57ef6-b9a6d9dcbebso4597888276.2
        for <kasan-dev@googlegroups.com>; Wed, 03 May 2023 11:03:42 -0700 (PDT)
X-Received: by 2002:a25:b18e:0:b0:b9d:b774:3aa2 with SMTP id
 h14-20020a25b18e000000b00b9db7743aa2mr16215719ybj.9.1683137021290; Wed, 03
 May 2023 11:03:41 -0700 (PDT)
MIME-Version: 1.0
References: <20230501165450.15352-1-surenb@google.com> <20230501165450.15352-20-surenb@google.com>
 <20230503122529.44ef2d56@gandalf.local.home>
In-Reply-To: <20230503122529.44ef2d56@gandalf.local.home>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 May 2023 11:03:30 -0700
Message-ID: <CAJuCfpGPVWQ1RYVSZOiXe2xDVbgMFAxVf2x=2xbgor=YqpntzQ@mail.gmail.com>
Subject: Re: [PATCH 19/40] change alloc_pages name in dma_map_ops to avoid
 name conflicts
To: Steven Rostedt <rostedt@goodmis.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, ldufour@linux.ibm.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, gregkh@linuxfoundation.org, ebiggers@google.com, 
	ytcoode@gmail.com, vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20221208 header.b=L5MD7LDE;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b2f as
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

On Wed, May 3, 2023 at 9:25=E2=80=AFAM Steven Rostedt <rostedt@goodmis.org>=
 wrote:
>
> On Mon,  1 May 2023 09:54:29 -0700
> Suren Baghdasaryan <surenb@google.com> wrote:
>
> > After redefining alloc_pages, all uses of that name are being replaced.
> > Change the conflicting names to prevent preprocessor from replacing the=
m
> > when it's not intended.
>
> Note, every change log should have enough information in it to know why i=
t
> is being done. This says what the patch does, but does not fully explain
> "why". It should never be assumed that one must read other patches to get
> the context. A year from now, investigating git history, this may be the
> only thing someone sees for why this change occurred.
>
> The "why" above is simply "prevent preprocessor from replacing them
> when it's not intended". What does that mean?

Thanks for the feedback, Steve. I'll make appropriate modifications to
the description.

>
> -- Steve
>
>
> >
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
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
kasan-dev/CAJuCfpGPVWQ1RYVSZOiXe2xDVbgMFAxVf2x%3D2xbgor%3DYqpntzQ%40mail.gm=
ail.com.
