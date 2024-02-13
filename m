Return-Path: <kasan-dev+bncBCC2HSMW4ECBBSECWCXAMGQE2UCLG5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 97704854061
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Feb 2024 00:54:49 +0100 (CET)
Received: by mail-oo1-xc3f.google.com with SMTP id 006d021491bc7-5993598d215sf5329000eaf.1
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Feb 2024 15:54:49 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1707868488; cv=pass;
        d=google.com; s=arc-20160816;
        b=UYKqO1UD5WAMzpQPHLVj71g2LDEPzqcA/EWOp4+C9yFGV+TnRiq2QDqfPTM63WzZta
         lq+u/GedjW6nL4HCNcme0sJKR7afEhjbe2ljStq7uFocIrt+/Eys2Q3KPSS8Xys8BZJc
         y49N+mZodAFgUmkdpUNgNvwWBKhYOKUSpL/RTd1OHj7y9Zv3f75bBG5OG6+ircG1U8dv
         xGH1MJh2HNSn6tm+DXNAAfXdBY0Yq/siOcZAWQ+Ap+kUCIARztI+J8vfZP1VrWKJzpsC
         TlEOsD46fYJUyATJWx5hGppJ3a+/wddw5cbXs9FTU7F4/vcyrgaTsmfRTAZh6tFPVIw5
         MZUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=fGyj5dVaB1yZNpH1nAY3ODY+/DVHQf+WkS4Zywnd9mI=;
        fh=NfZ+ZWEp2McR2mTSpmh1PH80KmA4cucByas97mwQXvI=;
        b=zkvDQBQihUnGSLHAjIspgUKNTX3G6d14Eaxo+srlssYRw3xc9VXrkO7uUJ519fJRae
         Y3ZjugR00nQN1ivoueCn0UFRJfBboMNXXETIUhAVWBVr0xsZp6/Ydoa5FFaODXaiieOt
         tg3puoolcqvu6JqGxu0QaRnErPATHGLYgclbNuI5Q6J1Li4aLSI+GEJ5B8TYpXLmqccf
         Pc01MfrSDXYcD1k4GOHvatArFIHkiL86iaPgQP+Zcltm0fsMpKLkLY/CCHOQz/ZxdbFM
         EnDnnwyZZ7C+fOQDxoHgR6eKQJhNaHY3Z626I+UXt/XXxkM/oApGQJmOrEHLG6ghcmHD
         mr2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=ZVd46MmA;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1707868488; x=1708473288; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fGyj5dVaB1yZNpH1nAY3ODY+/DVHQf+WkS4Zywnd9mI=;
        b=XdHH9g1gTBLcoVcixs/+ctUjC0B+fF78vIxRcbUtAjRsFbiwdhoS2Q6gclJ+cy9plA
         fxaWKUdIxgBN25MbNrdeHLhSQ2UPe9Z3jraqgdf8qpQMQg39FCh6pnHI+rW+jqi1iTAL
         lc6hatZkMJlIRKl3qqkSihOqdfiYT0HIFY9C82bj8oxTeCW+2/nxzosOdgApwqGvgvg4
         VOUeAe7deAL9kia3XPEn8IOAT/VzhE+XDTNzbFpp/9Wpw65VB2dlty/joJcekQYOtLun
         mcGftOEW2Qvx1q+goV/GsgZgfncpoZ/pCVJVM/IW1F5g60415T0Dj/z0Khn5j/XfUtVx
         Bn3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1707868488; x=1708473288;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fGyj5dVaB1yZNpH1nAY3ODY+/DVHQf+WkS4Zywnd9mI=;
        b=M+UEx88XUYJUUJA8RFNRCSsZF5Dxy165wf2OhXbrUOVyxi9UlRddR4kmWTH2qCje/H
         JVld5atixsplKrnBvNGTpIVxRUp8joElVzQMYBTncr07ThFSawjkK0DvIZD0zjHz2V3Q
         3n12j1FHA+PmXlCernKGeXf1OFXFWqAA6gbB5QyeOrbATdu2LQ9XXqYuJ301Nx6uekow
         z9QMtuwxxSwocW/ceNXpm0yMTtghUAHnlycfzPZhbUq8DijxaI/Q20ALdFbaLj9DLYkz
         78ZxFLQcT1Ckdb96DZze5vIu+5sNwTriJbFrrbU0z+inTHI/FVg7zoDlNiA/xUCNEM6e
         16zA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvyGc3NDFchk6r7ZFsShz6PnmW49HLyEhm+W0pALd7eOgzkISpE0YMYQyUjpxRlmy6tcv15QohtbxTC2dMkTI7+wG6HqeLxw==
X-Gm-Message-State: AOJu0YyykBQBf6siDLHXIOfE0dRLTIe/R/kH/6vsCx0jfEZA7xsAozcX
	AL4zkXzC+WYoF9HBwRSKV0xciEJj6vEaNnNlVRDojiHJaqpfc3bb
X-Google-Smtp-Source: AGHT+IEKrR/E1PddVSjAJS3lLPmCsTnOkHCGuEeEVU1Y7nbQyUIE1RlUQdQ+niZIVxJrKYoLqyTJTQ==
X-Received: by 2002:a4a:e04a:0:b0:59d:d349:daab with SMTP id v10-20020a4ae04a000000b0059dd349daabmr1061587oos.0.1707868488325;
        Tue, 13 Feb 2024 15:54:48 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:58c6:0:b0:598:74b6:da43 with SMTP id f189-20020a4a58c6000000b0059874b6da43ls4608113oob.1.-pod-prod-04-us;
 Tue, 13 Feb 2024 15:54:47 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWM/QIBJenGMkNuQWPs0qZkgb2fEfvAHlykqaBWPN3gAJPOhRv6OT6iX3+780iE9cXPahDsL3JDZQPYd2A57ZEK5mRBx5GLODrPFw==
X-Received: by 2002:a05:6830:3490:b0:6e2:dfae:3ef8 with SMTP id c16-20020a056830349000b006e2dfae3ef8mr1346414otu.37.1707868487352;
        Tue, 13 Feb 2024 15:54:47 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1707868487; cv=none;
        d=google.com; s=arc-20160816;
        b=W0nLnOFhAFlb/3IjMlvSdcn+F6FNlkrEUvBEGVdAbYdfkIuiwz1V+JlNg6aLDG7QS0
         YATiq65w0oApSm2yLOBSYssvx+vjGQZbcyLs3yv1WBlhIkl3yQPjSuAEQEHvlX8fnRBa
         bjkmP4stbISTdE95jnTmKEG2l6Y5spbXajSccrU6OFNwElMw/fDujTQvMH7SrgcclTlW
         PSrchJDHK3WOuIbiqwjDImla4QvuRNeTAmKWTzMwThnapwX3FVQyoij/JNbCi8ZvN4Ju
         YnvZw3/UD3EnXR0/8mbGE3JPW730atDodRddBxJM9Jh8OhJUvOkdBTjQOArJdhA0fIcT
         USMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=azZvqzbTFipUnuC8HX9TaKZdjTIk9iGcAhgBe6cJRrA=;
        fh=VvN0IK/yKuW5feH5zdkgTkvbHuiOKyyd8pprtr2cWdw=;
        b=Ng1spbVt6Uov/Qcfd4XUZpvZsfBRGATpWVeTqiz/OlHtvvD4VMmYmUQ4SHWOEKnY9u
         x5e2sk73IS5oyukphcpcpm+r/bO19+/bS260j4HwOaiBWTRp6loVY2OShae35cTy7+cg
         WuE0khhTwD7XLk71aXOukzkd1WjgM57m2nPkiPv0zWkzwVUeQx8hqvzh5OFG4VYqY2th
         lSVItvvmIqsPFLMXk7XOS5QMr/P9qC2zdTRUpOJ3VrfdfJkZt91lE/uaMgE2SOfg5Mif
         eGcojbJ2Td0d5TN32Ir7UTYCYOeU0gIrmP+6mXyPXIrt2MnO7Fn2y66J029rhfo8sgHr
         kncQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b=ZVd46MmA;
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
X-Forwarded-Encrypted: i=1; AJvYcCVLSWSx65WPYHYnKaHU6LnJBNfTbi8IkWmsY8IxRUevQoL6mwYZt4ox+b13gqGFKMuZn6VVB7jn0GeZiob99x5QVLbkZoOp2f9itg==
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id x55-20020a056830247700b006e2f6d29a61si192503otr.4.2024.02.13.15.54.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Feb 2024 15:54:47 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id d75a77b69052e-42c6b6ec76eso31603161cf.1
        for <kasan-dev@googlegroups.com>; Tue, 13 Feb 2024 15:54:47 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWZws8/+cuMMFkI1HRGuhToJ+0ZGZHyrwy+6WnWsLi2ZSFAGtFA49Nv2nhN/+VAM8+g63FWGiVVczIM0joS4MXojSRr5SKVYoWnYw==
X-Received: by 2002:a05:622a:41:b0:42c:6fb6:8d2b with SMTP id
 y1-20020a05622a004100b0042c6fb68d2bmr1159462qtw.46.1707868486727; Tue, 13 Feb
 2024 15:54:46 -0800 (PST)
MIME-Version: 1.0
References: <Zctfa2DvmlTYSfe8@tiehlicka> <CAJuCfpEsWfZnpL1vUB2C=cxRi_WxhxyvgGhUg7WdAxLEqy6oSw@mail.gmail.com>
 <9e14adec-2842-458d-8a58-af6a2d18d823@redhat.com> <2hphuyx2dnqsj3hnzyifp5yqn2hpgfjuhfu635dzgofr5mst27@4a5dixtcuxyi>
 <6a0f5d8b-9c67-43f6-b25e-2240171265be@redhat.com> <CAJuCfpEtOhzL65eMDk2W5SchcquN9hMCcbfD50a-FgtPgxh4Fw@mail.gmail.com>
 <adbb77ee-1662-4d24-bcbf-d74c29bc5083@redhat.com> <r6cmbcmalryodbnlkmuj2fjnausbcysmolikjguqvdwkngeztq@45lbvxjavwb3>
 <CAJuCfpF4g1jeEwHVHjQWwi5kqS-3UqjMt7GnG0Kdz5VJGyhK3Q@mail.gmail.com>
 <a9b0440b-844e-4e45-a546-315d53322aad@redhat.com> <xbehqbtjp5wi4z2ppzrbmlj6vfazd2w5flz3tgjbo37tlisexa@caq633gciggt>
 <c842347d-5794-4925-9b95-e9966795b7e1@redhat.com> <CAJuCfpFB-WimQoC1s-ZoiAx+t31KRu1Hd9HgH3JTMssnskdvNw@mail.gmail.com>
In-Reply-To: <CAJuCfpFB-WimQoC1s-ZoiAx+t31KRu1Hd9HgH3JTMssnskdvNw@mail.gmail.com>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Tue, 13 Feb 2024 18:54:09 -0500
Message-ID: <CA+CK2bCvaoSRUjBZXFbyZi-1mPedNL3sZmUA9fHwcBB00eDygw@mail.gmail.com>
Subject: Re: [PATCH v3 00/35] Memory allocation profiling
To: Suren Baghdasaryan <surenb@google.com>
Cc: David Hildenbrand <david@redhat.com>, Kent Overstreet <kent.overstreet@linux.dev>, 
	Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, rppt@kernel.org, 
	paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
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
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b=ZVd46MmA;       spf=pass (google.com: domain of pasha.tatashin@soleen.com
 designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
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

> > I tried to be helpful, finding ways *not having to* bypass the MM
> > community to get MM stuff merged.
> >
> > The reply I got is mostly negative energy.
> >
> > So you don't need my help here, understood.
> >
> > But I will fight against any attempts to bypass the MM community.
>
> Well, I'm definitely not trying to bypass the MM community, that's why
> this patchset is posted. Not sure why people can't voice their opinion
> on the benefit/cost balance of the patchset over the email... But if a
> meeting would be more productive I'm happy to set it up.

Discussing these concerns during the next available MM Alignment
session makes sense. At a minimum, Suren and Kent can present their
reasons for believing the current approach is superior to the
previously proposed alternatives.

However, delaying the discussion and feature merge until after LSF/MM
seems unnecessary. As I mentioned earlier in this thread, we've
already leveraged the concepts within this feature to debug
unexplained memory overhead, saving us many terabytes of memory. This
was just the initial benefit; we haven't even explored its full
potential to track every allocation path.

Pasha

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BCK2bCvaoSRUjBZXFbyZi-1mPedNL3sZmUA9fHwcBB00eDygw%40mail.gmail.com.
