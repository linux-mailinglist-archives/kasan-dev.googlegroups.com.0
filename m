Return-Path: <kasan-dev+bncBC7OD3FKWUERBTMAXGXAMGQEKXWJ2RI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x837.google.com (mail-qt1-x837.google.com [IPv6:2607:f8b0:4864:20::837])
	by mail.lfdr.de (Postfix) with ESMTPS id 732208569E7
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 17:48:15 +0100 (CET)
Received: by mail-qt1-x837.google.com with SMTP id d75a77b69052e-42c709698f8sf37437151cf.1
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 08:48:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708015694; cv=pass;
        d=google.com; s=arc-20160816;
        b=X92WfocsSJwODVqifHJH2CJJOYghJtk2dzja9/He2O8DXnew/6hXg6+sidwMQ5oYqs
         J+QgUD/L/IzWb1iBrY3+VqWVN78qHrLVIlFkhSMkptmPsJne3wz7PeS09CHrLx67I/QI
         4A2F8DJPge+6NSJe99rw8pEtf5VIYJmq4OKIMZm8P12l/6ESbuQbyCBHKTxv0IhQJ+LX
         IZZhc6O7uHrCVkZaQsEicrkxa7rezPP0e5jmsE1TJ1HIq7Z2IGrKwVBRgFPxFGrMu5YC
         SaQOwuPWts9zvMaTPcTJ5JsQEADH/c+jfU2d9O+Bc42q8xrbLT7TRNxdLHuemA5pviR8
         PESQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=MRSpI57+KoEXDwZWYe0M0CS1yOFJZLDIshWDtLoylvE=;
        fh=CVI1zYb0r4KWTIsS4MerGMDqNJwWNFPNWhhVtf9NeBE=;
        b=KdEAcICPUO/AZWi3G0t8labMauPmd2018Vbx7MtutNL2sMqCWurCqhVB7k50yBN3hD
         vVux4rfT2gShnZxo79h/JG/MSIJLL3Zh7D0KEYc3eEdU+paFwJ+I1oW66ynotOH7kTCq
         PRQAfj/hFAj+hLFt+kqMb0zQkbzpUcEiaHtwOmsKuwpiMOGy55qQVxxMglr8svJNSNa1
         qSH9d5iYzpz8vnM+RlXmmxfinLNY26CbrW09vFhfe8cHGYAR8pDdNeDMZ1a2e9lJqEcn
         Yai5A9Aap4DNpGGNh9I4jaZo7ZMeIBmCAkfXdSt53HU87uKcH4OU+SRvjLdzh4xBliCa
         F5kQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=f8nHrLKm;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708015694; x=1708620494; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=MRSpI57+KoEXDwZWYe0M0CS1yOFJZLDIshWDtLoylvE=;
        b=W0Ee5yH+mB9q4FElq5MXvCJrHbFF+WnsYYyXRxJ+f2WYTmC8kJ0bpPvnULesDmp6v6
         63vV+rwGzjzlHsh2tWrFIpBkp5owp1etrHWA1Np8iN7ERY+2naGbricfbhG3NoWo8S7g
         icuu9G7wzTpi+R+/K6wvQnrf6yLzlxy4uhNcUojinQHTZrv3SxWa/ViFsYXNmI6K3K/T
         cOl9GKsTxb2cwBqjb8zA1ENAg0rbQeRt7FP5rQdAzZRAWPNYQMojkaNvDZGF8pfWx8TR
         XBvnZgrPuHkfOI0w0gTRANwVqK0OEEHBjmNQT4l/+LqUQiibICg7cabNTEGia4GLZQgZ
         FcSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708015694; x=1708620494;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=MRSpI57+KoEXDwZWYe0M0CS1yOFJZLDIshWDtLoylvE=;
        b=djBfVBSdIl/LAExMS7f44Jcp9f/UqOcdUByKKve/2k/IfIwuegWN2GWkoCy4918H9y
         bh/BZ/laytOpzbL68mEM545/Wg4LXTckzf9pd23i7dVnaeiBo4CSb5ukzaL6xaXLr0g/
         n1FqiKKznW4MfXXoZsvOd9MMk71FoeSHh1e42X9xt5fH1WRDGDR1bX2q9C22pNkmZV4b
         FVlg0lo8E5I5aZExo46DTwG42+685jFPHq+CEvnWYnumgJwobuWK/1K6Gge1fxz7QevX
         X1Ww08/MLQEBSt2EZDpxKl5QZGxH+ER7E69AW5EmcqMIPBnZJbCh0wBv0J61zUA9J8CX
         0FAg==
X-Forwarded-Encrypted: i=2; AJvYcCWFPBvmM8W/HH4AE0ugK4baPyb4kcg70IsY0eBsX3/3NHVv8kX++vwxyEtd+RUvGaSjLV2GQzgUO2zwzvP0UafZQqtH1m9wfg==
X-Gm-Message-State: AOJu0YzxLdvcROigj1TZ4mNNbOvyixefPoDY53A7Toc4JSi23ebebtoa
	eeDK6zivymHUPD117x54fwjHRfJXRhWxt1Bomxy2QLsqSRdgpIiO
X-Google-Smtp-Source: AGHT+IGUU0InJxCPv2zy2UFh89kWHsudaFKW4gBiYdTaX/hOtWXHVnRX+pkXkavWK504qJoxwtAZ8w==
X-Received: by 2002:a05:622a:64c:b0:42c:2dd4:3ef6 with SMTP id a12-20020a05622a064c00b0042c2dd43ef6mr3238570qtb.12.1708015694054;
        Thu, 15 Feb 2024 08:48:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:59c9:0:b0:42d:a963:7ef8 with SMTP id f9-20020ac859c9000000b0042da9637ef8ls761653qtf.0.-pod-prod-00-us;
 Thu, 15 Feb 2024 08:48:13 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWiXMX0VEvOQ10kPVxrKCYCxRn5KMMbNomMeRaLy1IWhW5/oghu87+e8EgacLpOAJS3slipDJIRPtZYVJQ1MMYDbt4ogc8isJV4Ag==
X-Received: by 2002:a67:e44b:0:b0:46e:dcb1:77a1 with SMTP id n11-20020a67e44b000000b0046edcb177a1mr1891731vsm.0.1708015693330;
        Thu, 15 Feb 2024 08:48:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708015693; cv=none;
        d=google.com; s=arc-20160816;
        b=yvluRtbNwYmxhi5n+kDRN5s7FGw5xq9WHX9pRj7WZtwjzHLnDqzE4JCxgNyInhlvIQ
         +azwHlZ3JjFj0OL78LvGNNZ2woW4Aa1tq6Oge92scIHJXcBZ7ePrbnruhu1T/2Fx3NE+
         tB+kWmnZ4qqdGgu/1c+yqOjH3uxkt/+XLp1RfdcPc2aleYn1i7R/koUCMIUwBmpZ0+KZ
         CmKP6PfRAiALSs9M8NobflEf6Qpa92y+W9yVzQcKhy1g3LfmROOxnGepNZ+eOUU2HJvR
         NNV+bOwRjFwuIvxcK/XhgrMLbqKqFWZl8Zb6tevZqp9MMgHIU+cG6rqUpL6+VfZ1XtdY
         ICwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=1tI+hCE30y1jp9jG4DD8d4tpJXQ3JxVVysbuWcCVNic=;
        fh=plNqv0l0gQze/tyW45SFvPmQmg89gT3oPn5axXQ37F4=;
        b=sbkLE2nKu805G4loc7Xl8VYGNBJazkamwDaTwW/ufIrKDNod9+ykAp3u51lJM3CN3B
         ng49emwAjLuM5Y8QWLD/n9+gyYyIP+Uvg6xe7Iy0opgGG1gf9XfGSO8VXXE2jx5URgSS
         7yJoLP/mS+5cl+QKIfQ7/FUuKXp6584CtQrQ7PfS69Wiwu7h1oUeHKR6N1BCSmuRW6DJ
         7VIJfhkmusZrMDU4u2KBAxofGOe7CO3X60m9MHdnACbPQXfYYmWMpsmPz4ga4FDOhK9Q
         Tp0CdK8Tr8uwdvGVosvLuh656uz7iQtpjeHH12My8lLpN9RfhNTlNZ653b9nPkStB/BD
         KGrg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=f8nHrLKm;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112c.google.com (mail-yw1-x112c.google.com. [2607:f8b0:4864:20::112c])
        by gmr-mx.google.com with ESMTPS id ib25-20020a0561022b9900b0046d3986403esi250349vsb.0.2024.02.15.08.48.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 08:48:13 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c as permitted sender) client-ip=2607:f8b0:4864:20::112c;
Received: by mail-yw1-x112c.google.com with SMTP id 00721157ae682-603fd31f5c2so18578467b3.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 08:48:13 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWvTP9q0UjUPXUy/wg/jH/gZrTy2ZXdagV2+If8zkSLukciwiecPs5Zw08LCOh0qVZbkZXdbX4PaUfmimrzuqG73f7K9I/gcowj2g==
X-Received: by 2002:a0d:e284:0:b0:607:77bd:711 with SMTP id
 l126-20020a0de284000000b0060777bd0711mr1808635ywe.11.1708015692595; Thu, 15
 Feb 2024 08:48:12 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka> <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka>
In-Reply-To: <Zc4_i_ED6qjGDmhR@tiehlicka>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Feb 2024 08:47:59 -0800
Message-ID: <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Michal Hocko <mhocko@suse.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, vbabka@suse.cz, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	corbet@lwn.net, void@manifault.com, peterz@infradead.org, 
	juri.lelli@redhat.com, catalin.marinas@arm.com, will@kernel.org, 
	arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=f8nHrLKm;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112c
 as permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Feb 15, 2024 at 8:45=E2=80=AFAM Michal Hocko <mhocko@suse.com> wrot=
e:
>
> On Thu 15-02-24 06:58:42, Suren Baghdasaryan wrote:
> > On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@suse.com> =
wrote:
> > >
> > > On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
> > > [...]
> > > > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodemask_=
t *nodemask, int max_zone_idx)
> > > >  #ifdef CONFIG_MEMORY_FAILURE
> > > >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_poison=
ed_pages));
> > > >  #endif
> > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > > +     {
> > > > +             struct seq_buf s;
> > > > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
> > > > +
> > > > +             if (buf) {
> > > > +                     printk("Memory allocations:\n");
> > > > +                     seq_buf_init(&s, buf, 4096);
> > > > +                     alloc_tags_show_mem_report(&s);
> > > > +                     printk("%s", buf);
> > > > +                     kfree(buf);
> > > > +             }
> > > > +     }
> > > > +#endif
> > >
> > > I am pretty sure I have already objected to this. Memory allocations =
in
> > > the oom path are simply no go unless there is absolutely no other way
> > > around that. In this case the buffer could be preallocated.
> >
> > Good point. We will change this to a smaller buffer allocated on the
> > stack and will print records one-by-one. Thanks!
>
> __show_mem could be called with a very deep call chains. A single
> pre-allocated buffer should just do ok.

Ack. Will do.

>
> --
> Michal Hocko
> SUSE Labs

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHq3N0h6dGieHxD6Au%2Bqs%3DiKAifFrHAMxTsHTcDrOwSQA%40mail.gm=
ail.com.
