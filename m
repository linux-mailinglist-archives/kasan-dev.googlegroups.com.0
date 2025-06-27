Return-Path: <kasan-dev+bncBCCMH5WKTMGRBMNH7LBAMGQEX7OFE2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1672AAEB823
	for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 14:51:05 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id 3f1490d57ef6-e87a485af5dsf1732436276.3
        for <lists+kasan-dev@lfdr.de>; Fri, 27 Jun 2025 05:51:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751028657; cv=pass;
        d=google.com; s=arc-20240605;
        b=hdVAEDzM9ySVsTH8hY7zpZ3Hke8hTj6TjbBFGwDekTtBc33hdVUa4k4wSt+Cs2Lyaj
         up0sxZ0APyJdTZDBZ7cE1kthKy/0037tGQCPPOnsUHQMjpDExSrdw+MqNz1GxQ8ozZcc
         9mI156YiVCIWAplqyxCmC3q6ipK876FN35jMy7fmfGGD7tJTU5NaCPv0ajMdJ6BuSnf/
         LJ0u+UN4hFyfDxfjADMWZxIdnezQgmVzJ1lLMGwZzZXbT3mXosNYdmtIhlFJ4oFtQ5zJ
         PbFPIga7vSytiw4M1PZPNYPV3FBm+7bo1xqV+47TqF2HH8fdMhIIiqnedYq2IULKlGi/
         A4vw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ABAFtexRrQeTJbgcFb/kvIHtyx0+AaD8w6BpN1mGCfk=;
        fh=2Onr8d/TbfF+oK8g6+CslcZsNpoifcZLKFHSAnanZCE=;
        b=Yc5aI1m3QET1sMqAqnbtqXe/KCqQl9sldZzUeETPpLxGBbER2qrjPBYlfrWcZCv5Ze
         LOkO1BqN8UX9ucUybAWxGW56IRsO7V6F2nhhjABJTTLwZ5Q2S/Xs6EwUao23volpv+aE
         FcgJV/03h+oAwEpoQN2fzA7ObpiXdIaxioO+J/1yI9zaIh4s9Di975G0aZ7QHBjT5V+p
         rmraziFPzA+KBSqM9mfVCpF5OeskY5yL0i+tauVc4+73d86NILJMtI3blmtwLsnGkeye
         KXsqEbXQN2fa/1WWPVllXKrtaV3i6vbaeuuQswYpGRvg0m1hAubgHm+rDF6GGIV37XfU
         AOCg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wuf9dzPk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751028657; x=1751633457; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ABAFtexRrQeTJbgcFb/kvIHtyx0+AaD8w6BpN1mGCfk=;
        b=URAmSuVZlrm0wpY+LjjZKYsbOwAwcC8DDe5zQcgHYzdMO2VPKLrveIHL7/z4NwXZXf
         i4Q/OkY2nXB3HePTmEWWy4hVAGpGEqKp7ERx2j1w+xII75xzTE6EbXmdESnGBJwGOByp
         5mQXcyjJDssLK8TqFnPrwI6PPLG6SMQGN8r18cSsc4g8HFWCqtSratBvXaW/q48VVf6m
         RIaQOSeQw2LPkcISHjpQ5oU5OwwydZwDBQqORlMLEysCAMHz8Mr2r9Eebxbia9YckvGy
         oWi86P6aKxuzZVf4YXPFAVDK/j5BZK7VANbPRPjvOuIt5orbR8ZXzP9Hrq0maSKtOlNU
         MiLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751028657; x=1751633457;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ABAFtexRrQeTJbgcFb/kvIHtyx0+AaD8w6BpN1mGCfk=;
        b=mZxit2PZcTheobmxSTgqlYYBXtnm8ehFEfl/UrTLMGvM8OTObSMOZ1rt4sWrd84s20
         ak811LRgaCBYVWkJdJw/owBiVE3ELH4VCLcEBY0XAXpHhnFXtjm8aIk07qRQQ/jxI05q
         V3S3EA5IwGpkIQp4O6y/UxbAoFgNwk9ZtWiezj7SrQgQomr1/F5zrUkb4VgdTPsyxoZ8
         VT+T/f/ZDSoLf937gpxlffyiD0NnTvqJ1k7dHRQ9qS1Dd2hyxP/OwnaaGSXjGh5PyjGk
         EsHIObg3nNYLE+yvGVOl5bYaTpaJU02VKHsLscIsXpx2odkt79YeT/jjCYcCT5FWx/ps
         vy/A==
X-Forwarded-Encrypted: i=2; AJvYcCW9AgJnNIUNdltVcP2RCV3JGSz0xMADstxmeuYFHxxrmeBVMRNvpVBmzuHG/2tPGS4cSUf0YA==@lfdr.de
X-Gm-Message-State: AOJu0YwkholRZr5C16/2JL9VQzLxuNNfz7u6ZF/RH4L57jjEbFhSK1Nf
	dTiIdwfZUrfhl171vVM9f/JtNeZkXJiyiQ2TVQn8Ew39lxsAKrXJkLs+
X-Google-Smtp-Source: AGHT+IHoj0JWdgZXHz/vvsWMISlUgd7bVgevHnBORt049UjtiE8670mnI05/3cUMv5+yle1BltVeog==
X-Received: by 2002:a05:6902:a07:b0:e87:a6b3:ee41 with SMTP id 3f1490d57ef6-e87a7af77ebmr3920725276.16.1751028657537;
        Fri, 27 Jun 2025 05:50:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeb3biYS+Wacf+B+cfVhjSiPEdbkYVH69K+okTsb3IBUQ==
Received: by 2002:a5b:d0d:0:b0:e7d:cd4c:80a6 with SMTP id 3f1490d57ef6-e879c40c14dls2547387276.2.-pod-prod-09-us;
 Fri, 27 Jun 2025 05:50:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUMKx0vpNPtNKixmIdSI7ijN+nXy0J3NjUCkkwtPC13l3bySy7wDVrVM7O5KnYluGz5He/72aUrlrI=@googlegroups.com
X-Received: by 2002:a05:690c:a0a4:10b0:70f:8884:a5fc with SMTP id 00721157ae682-715171382c6mr29069497b3.4.1751028656314;
        Fri, 27 Jun 2025 05:50:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751028656; cv=none;
        d=google.com; s=arc-20240605;
        b=DZe+p99pi01fHSE+UQfazfHJHmQtMk0wAgKtTiq48jWfAsrFFLZyssXPFqCczI8vte
         8CIV6YDR0d4sLaJoa1m/FeRoBUNfcLR6efwNpy0xn3/P1gxiIsAfvmhWH/iDt0LrF8tR
         hZQOi/tzPjclCHjjby6Ormb0AhdXVMQZgMKHdrWGqyCIoruCe82ccHdmzyTUN8I+jBIX
         U3WCRzpJOuMajxdKQwkEKLOjKWGXDWIfOHTOaAHvV67jBdIKPtXcytPb1EoDrPW+2Ql0
         K/j51DVqI/qj0z1v8RhjC3euTcLD1orEDXqAbinjFfYwFGna5t/ND6C5wZoNQpxbOcV5
         BlkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=idturYgqav2RqhmzofSv+DJRMZDL8II+nd4+G+NHC8w=;
        fh=sx0pAqTzZ6mKAAYvfXGQw5mwpm9J3EjB9L3XYF2GeOs=;
        b=d9OuXqeHedG8g1DnUY28PAr29hhebsJh5zWZwPLb+q4QyFrKLchK9Ocm4AYJUW8ktr
         igpg1o0Jq9MlBvncpOs2aUTC0Glao1zhQC5RcmzYPsp8o9C38PdsiyGX4IEahvMGCGUC
         7V7RLxNYNQlPf/h5SbbH7TI7MM8zi4UOt5GsoFYwYnZXyJv0rhgB/btobCckawtDpNA5
         6bzHNkietcUN9YSIGSC2fA82feoKVfFem1MfCY/TWQhIVCROvO15Qo9zgD7P53nofHEi
         adf+NAVoxD0KDFYRdvv6kQeqgBNjbs10ioDvAh27ubvqogK6Y3OyLXgI9U2LPJoTGgVs
         noJA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wuf9dzPk;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2b.google.com (mail-qv1-xf2b.google.com. [2607:f8b0:4864:20::f2b])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71515be7850si1499717b3.1.2025.06.27.05.50.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 27 Jun 2025 05:50:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as permitted sender) client-ip=2607:f8b0:4864:20::f2b;
Received: by mail-qv1-xf2b.google.com with SMTP id 6a1803df08f44-6faf66905baso31020236d6.2
        for <kasan-dev@googlegroups.com>; Fri, 27 Jun 2025 05:50:56 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVYGYicJA03RXc5DOOMwONOcWnAe6zG1D/xGCkD2u7RXf2Zslsr1EZdRmnBLmdk7D/bfp6En76y3vE=@googlegroups.com
X-Gm-Gg: ASbGncv0E8Tz+5E7qh10N2pSeBnn8onvRJ2YKXzCbsrQ656xPlWwgZ630sgK2nyCmCz
	q+SrW6ltheobjdhNafua4uCYNxH1dknITtut9I+5uRh4oCQHrwmQk3OS9JcbYPFCOu8Wl19Y/dI
	1jWtxvczRInpX6TkxE7GYvaTACoH9u6Jkc/3+Skbx6R7H2G5IcDPIVzmUvfubFxfC7Q1JoRWZ+m
	73vPtqPtBaU
X-Received: by 2002:a05:6214:459a:b0:6fd:a382:f86f with SMTP id
 6a1803df08f44-7001413116cmr59746306d6.34.1751028655727; Fri, 27 Jun 2025
 05:50:55 -0700 (PDT)
MIME-Version: 1.0
References: <20250626134158.3385080-1-glider@google.com> <20250626134158.3385080-3-glider@google.com>
 <20250627080248.GQ1613200@noisy.programming.kicks-ass.net>
In-Reply-To: <20250627080248.GQ1613200@noisy.programming.kicks-ass.net>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 27 Jun 2025 14:50:18 +0200
X-Gm-Features: Ac12FXwxKj33euY6ZH-yL0eZIHyMTugesDF-zJKSuw4473Kt_nozRUjRKba6tvg
Message-ID: <CAG_fn=XCEHppY3Fn+x_JagxTjHYyi6C=qt-xgGmHq7xENVy4Jw@mail.gmail.com>
Subject: Re: [PATCH v2 02/11] kcov: apply clang-format to kcov code
To: Peter Zijlstra <peterz@infradead.org>, Miguel Ojeda <ojeda@kernel.org>
Cc: quic_jiangenj@quicinc.com, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, Aleksandr Nogikh <nogikh@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Ingo Molnar <mingo@redhat.com>, Josh Poimboeuf <jpoimboe@kernel.org>, Marco Elver <elver@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Wuf9dzPk;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2b as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Fri, Jun 27, 2025 at 10:02=E2=80=AFAM Peter Zijlstra <peterz@infradead.o=
rg> wrote:
>
> On Thu, Jun 26, 2025 at 03:41:49PM +0200, Alexander Potapenko wrote:
> > kcov used to obey clang-format style, but somehow diverged over time.
> > This patch applies clang-format to kernel/kcov.c and
> > include/linux/kcov.h, no functional change.
>
> I'm not sure I agree this is in fact a good thing. Very questionable
> style choices made.

Adding Miguel, who maintains clang-format.

> I had to kill clang-format hard in my nvim-lsp-clangd setup, because
> clang-format is such a piece of shit.

Random fact that I didn't know before: 1788 out of 35503 kernel .c
files are already formatted according to the clang-format style.
(I expected the number to be much lower)

>
> > -static inline void kcov_task_init(struct task_struct *t) {}
> > -static inline void kcov_task_exit(struct task_struct *t) {}
> > -static inline void kcov_prepare_switch(struct task_struct *t) {}
> > -static inline void kcov_finish_switch(struct task_struct *t) {}
> > -static inline void kcov_remote_start(u64 handle) {}
> > -static inline void kcov_remote_stop(void) {}
> > +static inline void kcov_task_init(struct task_struct *t)
> > +{
> > +}
> > +static inline void kcov_task_exit(struct task_struct *t)
> > +{
> > +}
> > +static inline void kcov_prepare_switch(struct task_struct *t)
> > +{
> > +}
> > +static inline void kcov_finish_switch(struct task_struct *t)
> > +{
> > +}
> > +static inline void kcov_remote_start(u64 handle)
> > +{
> > +}
> > +static inline void kcov_remote_stop(void)
> > +{
> > +}
>
> This is not an improvement.

Fair enough.
I think we can fix this by setting AllowShortFunctionsOnASingleLine:
Empty, SplitEmptyFunction: false in .clang-format

Miguel, do you think this is a reasonable change?


> >
> >  struct kcov_percpu_data {
> > -     void                    *irq_area;
> > -     local_lock_t            lock;
> > -
> > -     unsigned int            saved_mode;
> > -     unsigned int            saved_size;
> > -     void                    *saved_area;
> > -     struct kcov             *saved_kcov;
> > -     int                     saved_sequence;
> > +     void *irq_area;
> > +     local_lock_t lock;
> > +
> > +     unsigned int saved_mode;
> > +     unsigned int saved_size;
> > +     void *saved_area;
> > +     struct kcov *saved_kcov;
> > +     int saved_sequence;
> >  };
> >
> >  static DEFINE_PER_CPU(struct kcov_percpu_data, kcov_percpu_data) =3D {
>
> This is just plain wrong. Making something that was readable into a
> trainwreck.

Setting AlignConsecutiveDeclarations: AcrossEmptyLinesAndComments will
replace the above with the following diff:

 struct kcov_percpu_data {
-       void                    *irq_area;
-       local_lock_t            lock;
-
-       unsigned int            saved_mode;
-       unsigned int            saved_size;
-       void                    *saved_area;
-       struct kcov             *saved_kcov;
-       int                     saved_sequence;
+       void        *irq_area;
+       local_lock_t lock;
+
+       unsigned int saved_mode;
+       unsigned int saved_size;
+       void        *saved_area;
+       struct kcov *saved_kcov;
+       int          saved_sequence;
 };

(a bit denser, plus it aligns the variable names, not the pointer signs)
Does this look better?

>
> Please either teach clang-format sensible style choices, or refrain from
> using it.



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
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXCEHppY3Fn%2Bx_JagxTjHYyi6C%3Dqt-xgGmHq7xENVy4Jw%40mail.gmail.com.
