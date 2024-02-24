Return-Path: <kasan-dev+bncBC7OD3FKWUERBPM44WXAMGQEM3FTJEQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3a.google.com (mail-oo1-xc3a.google.com [IPv6:2607:f8b0:4864:20::c3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 78B7D862227
	for <lists+kasan-dev@lfdr.de>; Sat, 24 Feb 2024 03:02:38 +0100 (CET)
Received: by mail-oo1-xc3a.google.com with SMTP id 006d021491bc7-5a032e40f41sf1255838eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Feb 2024 18:02:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708740157; cv=pass;
        d=google.com; s=arc-20160816;
        b=RusEO29qlNlT1spVfaz00sCY6dk0S6Yj5Yxso9Y7WDLzZSmy1IlTKOFBqgZRH+WYey
         JSNCL049oPANUSZDuvoCOdAP6qjXoxPnzry44GWZ6Z9AMm5uoA04cxASgeJq2H0diUTi
         irRTbz+pNpGlFqXOosplarhd/gMY9Ztw9McL2g0HZ+o4WmfY0STfAiCV2u8ht6rBGPAK
         t2iBHPZFf+uIBwaEVSIGNB+3ugkTZbt/hkDxaDZghBVa4IqRZHqCNV0mPBS7FWniHt1k
         cZAnXk8xElPzf+l+nNbqZ7BrX+UUWw0pv7vYUYPKLMyH0BMc9LL37aJWefO/GzJZGS3g
         JKXQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=3DUWVdqOd4+zmjszUpVmnHd1wo8uJzQkw784ivDsOFk=;
        fh=QtsYu9ZPTIJJ3rTIIqeHJYbYmNrftJb5DF0VBq/GuSo=;
        b=k5FHCBQ7eN580BSpPq8RWrYQnoLytFMfMe2oge1m46UUChidd36puqZVWD5RgX4mt1
         +3BJtbNBVPoBiTjEJXrDKMvBUomTPXryGLno8zWjzboSOHFOs5qDLT9zJYxVAU5IHfaW
         JI5UFvj2odApacANm5VU42LH0Kaeoo09Ptey+rr0dVy+bD7RQVtgBJ5tL3dpBcCASNY+
         cQ8/ybZLy2nrNQVYx0BiBgp76o/UcCszUcxczn6CnfetgRI6U6VzcW3f3BiYORyw11Zw
         Bbt0Sa4PHWAET/JC/F2BQYmHevIuaalW9Y8T/yUoE+Xhd5D07Lgdp+kZ897T82C7r4Qv
         Q8cg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jtnWmDJU;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708740157; x=1709344957; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3DUWVdqOd4+zmjszUpVmnHd1wo8uJzQkw784ivDsOFk=;
        b=nR5TZwgHw9FnKNdADJA+ViwzjAnLcDqmZtOvA1+CgFxZWjZpLi/SyPFcA5YRoLKhgd
         8F4WsSdnGVfIEyho9Y+61zi8PciAdr3ZNx+Nakof18twp2A9knRcANSCq9Hd90plliCS
         dapp30Xsz8p+6sGJHjGPanMQvGstx92gC4EeFiSygI5xxd5qZKsvG1Ek8OQsq1Y/76Fe
         xQb7z4Zjpcp6AvjGfUONGEx8uupkUzE83iZT7ahNZJKgoESbrJY4sHUjPpSTIjl+un9w
         ZrXOwoGAELdnuniBDzcFuPgITP4niAoWEVHbPonrIXe6ZdpcDRFW1a/0lGf7RzMXbGc2
         +Cvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708740157; x=1709344957;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=3DUWVdqOd4+zmjszUpVmnHd1wo8uJzQkw784ivDsOFk=;
        b=ai6uzHyWjVrOrWYrxgoGzUDUWzLy+FpNhmRpHhySPIndf5CmRYADN+3OMCabpiZfa2
         1XMfmPtIrpNt9KCW4CvMYXYtYLiwdxz/OG4v6JHpoGJUNpHGQB5qLCakdyFVz5AjYkz5
         oQHt4vQN84+5lC4LEOQTaUkIeOkonpTXF8g92yfWd8+jFMhbPqldzX2XoFtgj6EqDuzi
         tkLEX/2cIPgatcpeBBZXP6vWfhwwP5bqhI7Yl4Vj6EpGdeazfyCoOAFiHDWxYqRxKPwp
         1SPA5yqsu0MekgytrocYp8ZmJcSf62XzTMKVBb44VBywnVYfYt1fIIlBoamvCvj7Bgvw
         fBoA==
X-Forwarded-Encrypted: i=2; AJvYcCVuQlDfPUAahNtT9IS92LNnqoIufIK1W2ZzkpufXw7qpJRbXltc5VBK6GD9T1YgOET0Gcq6TJJZ/1LOPBLBcdv2mlJjW9tQnw==
X-Gm-Message-State: AOJu0YwSAuuexurWC80gWXK0SPoglPMYK0lPWMFBUVQYpA7OkeYSG4bt
	hrGatJc36P8cBYXl3mUYJ+Fo/mbupvRIM9K1AGkrWxysRxy11jMT2xU=
X-Google-Smtp-Source: AGHT+IFxtSguaUXnbg8pjxSSevF8o0HGOMDYEpL4PzRuMNnTfRPYIuXaIlqRvfuAQ9EKRhfKbEUOVg==
X-Received: by 2002:a4a:2453:0:b0:5a0:4598:7a90 with SMTP id v19-20020a4a2453000000b005a045987a90mr1529191oov.5.1708740157240;
        Fri, 23 Feb 2024 18:02:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:5886:0:b0:59a:6de0:e6f5 with SMTP id f128-20020a4a5886000000b0059a6de0e6f5ls986964oob.0.-pod-prod-02-us;
 Fri, 23 Feb 2024 18:02:36 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVVNILm+rhXD/Vf8eHEq5idHyWRBrPAT1xNhg334ZMYBY4GnoDpS5rdT+IQywsIy4dAbJ+dSV5cvVhvijpvqv/aYFpsi+aajwxSkA==
X-Received: by 2002:a05:6808:1784:b0:3c1:4b14:f684 with SMTP id bg4-20020a056808178400b003c14b14f684mr1941228oib.1.1708740156543;
        Fri, 23 Feb 2024 18:02:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708740156; cv=none;
        d=google.com; s=arc-20160816;
        b=RBxxE6OVNRDJyYxas94EOgWUEgoVXR+dEwqp9FQbB56R9cL25fI0iq1/c54pSvTg+r
         /JAr4qPxW+9Ca5f4N7+WLmLoCmgNoxv/q95e1NWld+eqN6hTPl8huKi5GCiTBN4H+EPe
         ebAsEVUWg0gjQM8WNcMyhCERyP/DcZLLtlEA+iyO3ZnDfzl7vtJdHnatJkfrGd8/BOoJ
         U1CjXN4Mk4X6VyRNQumjOuHidexnQ5+/JDFaOw6lScZuJcrc7rg4N/uQ3x0QOvF6fOxm
         n35pRq18NZJNGoNVa7r/piz5DKKNhre6xSqEzjbp9UvLq0446ae6cOzzlcYsV5SJ2AcL
         e41A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=9PYgxetUjHOrEBE3OyfXnw/V4oH+FzaVrAptzS8yqHg=;
        fh=rGsx5nn9P6y5j8fipYcl3RmXZRVDiug6Wc3dKekvqOs=;
        b=Ughqc1hW4WAGwShPpJHaHeBhxfBXVqltVrMliY2gdGSjnvpR4lTZfPvDkRfdBstc2F
         mHrUxrEwRq5z3HEjxmCTwInZl/OO/SYftDOMCVLtYv98bq+U6LRPZ0Opa7o9SsiBHGX1
         lCylDTwLyanI/asXTz0xhQiqKpOjUKlWKRGlMOG6YovloZwIlh+sU3jID4q39zMRWiVf
         oGqaze7Y7ppjtktMtXduG02VXPu7ZIz35rZpLFD7iGBHy4cXlJeX/YncTqWxF/75gSnk
         S0M4w5+AU3l5Bro1RBt01p2l/fNCgfMylw8+4L3Ex4doYQW+K/HbhxW2Z1HP1aoC1jXf
         e7Yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=jtnWmDJU;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x1130.google.com (mail-yw1-x1130.google.com. [2607:f8b0:4864:20::1130])
        by gmr-mx.google.com with ESMTPS id ec8-20020a056808638800b003c184672227si15462oib.4.2024.02.23.18.02.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Feb 2024 18:02:36 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130 as permitted sender) client-ip=2607:f8b0:4864:20::1130;
Received: by mail-yw1-x1130.google.com with SMTP id 00721157ae682-608c73f03a9so9035917b3.0
        for <kasan-dev@googlegroups.com>; Fri, 23 Feb 2024 18:02:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUHWMRJ44wf2jNqovuEUibut650Klu9EwNI2mllE9uTWcd5H59vP5/a4m5l+neD1ElHP4ljtWjZ3AI99NC5/kERt8s+AC9dlW7t0g==
X-Received: by 2002:a25:9986:0:b0:dc7:4758:7802 with SMTP id
 p6-20020a259986000000b00dc747587802mr1258940ybo.48.1708740155772; Fri, 23 Feb
 2024 18:02:35 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-4-surenb@google.com>
 <CA+CK2bD8Cr1V2=PWAsf6CwDnakZ54Qaf_q5t4aVYV-jXQPtPbg@mail.gmail.com>
In-Reply-To: <CA+CK2bD8Cr1V2=PWAsf6CwDnakZ54Qaf_q5t4aVYV-jXQPtPbg@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 23 Feb 2024 18:02:24 -0800
Message-ID: <CAJuCfpHBgZeJN_O1ZQg_oLbAXc-Y+jmUpB02jznkEySpd4rzvw@mail.gmail.com>
Subject: Re: [PATCH v4 03/36] mm/slub: Mark slab_free_freelist_hook() __always_inline
To: Pasha Tatashin <pasha.tatashin@soleen.com>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, yosryahmed@google.com, yuzhao@google.com, 
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
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=jtnWmDJU;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::1130
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

On Wed, Feb 21, 2024 at 1:16=E2=80=AFPM Pasha Tatashin
<pasha.tatashin@soleen.com> wrote:
>
> On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan <surenb@google=
.com> wrote:
> >
> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >
> > It seems we need to be more forceful with the compiler on this one.
> > This is done for performance reasons only.
> >
> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > Reviewed-by: Kees Cook <keescook@chromium.org>
> > ---
> >  mm/slub.c | 2 +-
> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >
> > diff --git a/mm/slub.c b/mm/slub.c
> > index 2ef88bbf56a3..d31b03a8d9d5 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -2121,7 +2121,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x=
, bool init)
> >         return !kasan_slab_free(s, x, init);
> >  }
> >
> > -static inline bool slab_free_freelist_hook(struct kmem_cache *s,
> > +static __always_inline bool slab_free_freelist_hook(struct kmem_cache =
*s,
>
> __fastpath_inline seems to me more appropriate here. It prioritizes
> memory vs performance.

Hmm. AFAIKT this function is used only in one place and we do not add
any additional users, so I don't think changing to __fastpath_inline
here would gain us anything.

>
> >                                            void **head, void **tail,
> >                                            int *cnt)
> >  {
> > --
> > 2.44.0.rc0.258.g7320e95886-goog
> >

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpHBgZeJN_O1ZQg_oLbAXc-Y%2BjmUpB02jznkEySpd4rzvw%40mail.gmai=
l.com.
