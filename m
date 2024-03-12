Return-Path: <kasan-dev+bncBC7OD3FKWUERBZ6DYKXQMGQE7LKTCSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A8D15879BB9
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 19:41:45 +0100 (CET)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3663d0b8615sf10330165ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Mar 2024 11:41:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710268904; cv=pass;
        d=google.com; s=arc-20160816;
        b=jQUI0jWpRsmj2q/QZnWYZZ/oYB+Qb+Xt8/Krg4FUNgdLa4bVxZECJlb9zBXBQI2m82
         UgIVZaahhniVJwj7VyGwtsa6zSI/iFxhL8pstwvXh2fDIFA/0OmkCCfWw23lQvu4AG3N
         7l0UD2n9KUijJLGOGk8vtESg3S470XHELE7WA8OOI1xyV1ixwQOn1ANfknz8torJTGTJ
         iY4F3QlTzhBZEePAiQjrK8MRoS9CQMRr4bARUUwLM28+EN9XhMKRYnfdhcsmW0Ps4g++
         PlgL49pf3tUpxTLQxiXCmmKEXhWf6dqDZyNqOCeAKk84J7olOp0sIcpzbSqU33pzKwj1
         BReg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bMDTISuaQaP/jG4Aa40cGMIUJilXE92G3xJwsOZ/Wis=;
        fh=5acnaPbV3J5HTn35ysN5APQWbrL27yBxdhF1GOiuCxM=;
        b=gMOjivWhSGoqcuj2h8A8ZghTbHKNgNSJZ2NZT4dA2FX3ugNpGh+myQ6geKZ6dQguQZ
         8jsGwXekLce29Hwf5x0k0QemjznjmrH7YQmGHt98rYF8VN7Q3RwqTztg0dGTeL6q5vLz
         4RpLccGYTqKp9BKdIJ+vjO9d5sH9u76uHF1LqiqPbJUdOP8Hjx7/AWA+Nx5govO/yTxW
         QTsmb2hj4MjsEB2ixynf+O3+5i3eQno6s3zcwSKLyIMxXFfb91mtGkfLuUiELM86BbDF
         odK+xGIxYRlsim3tZy8OW8lnZMtJYto5WsXm0C6UjB7FL5ux+z+fUkJGPy+aSW73H2FB
         Hhyw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="n3//WXx1";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710268904; x=1710873704; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=bMDTISuaQaP/jG4Aa40cGMIUJilXE92G3xJwsOZ/Wis=;
        b=YgXA50Z3UHuCFt8/t0/5NVhXcpX7ev3No1O1gVnOk7Mr422oEE6pmvTsTagAX4vfyD
         sX/OOUtNaJV/FTCGELwYohM2KuOc51eFRhkyONHCusbAyuPpLANrTTEwkpvVJbh90Snw
         REkpm9zbZK8RMcnFtWVAQagLP5N0q4h1pbhS8WliyLNh31jkgSzMGTBgw2E++sh2r4w1
         EBwpEkWmKXopQCReYMNGDstM5u7Yz9KNlwPxOD8rql4K2t2KQxZH/wXT+qVefLIXbf5U
         pYTlyp2g1XA0GKKHD3oKIrStIJtmCQNh3Qfd1pzqFNMLgcfk2QBx3b3JayPHIUIu4qDQ
         quOA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710268904; x=1710873704;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=bMDTISuaQaP/jG4Aa40cGMIUJilXE92G3xJwsOZ/Wis=;
        b=nthrBuBCIKFW8mvkl+xv5qFf7WhZ/Q1mlfUomSjGwuPnEuA2e9b5T7vrpBEzldzzAu
         LJ/hQUbBm0ZSkHUrqlCHqwvvIS6trSqEEyEzVvXV9NdpAL/n8+U70meauaE5k/ONHD0q
         E6HAQB4E0W4tDlaVynZKcUpHQBZyOzKAfLcdNsEZOJg7IxG9t6DHPsr6FbrrLqiICJar
         hZAGP65qq96ma8Z/Bk/iL+fPPVzdD3PtQ82pKsfmv6TsEebCXPk1RoBWkh3KUIG58i6p
         oHrn80T4jBDtt/gAHewLGgBfbWDXSHHhfN+8T4e1B9fDuAuzz65gKfYh9R3EIG2hh1+Q
         /D5A==
X-Forwarded-Encrypted: i=2; AJvYcCVoPfiauG21dZceGOKuxIfC0YkebdhUF2fd7tBNG78OXODaNcNzR5m9oGvyqYt4yIXdziYoSsqwXIM5f2H3hU+esDqYdn5iUg==
X-Gm-Message-State: AOJu0YxiEJ/mh3LbGE1exrrkbFN+grceF4Bl0BozmPii90w5ZNx2nzCz
	c9UO5poHSyMojP3kfiqB1uh0PonMXCpi4adt/O6p7MGKsrfYVV7F
X-Google-Smtp-Source: AGHT+IGG64SVp69pNDsxsVJjIqWpdk8PkSaShEJbq5yIt3eQ42wwQR7Sdqx+y/jxF+c5BqQAURHH0A==
X-Received: by 2002:a05:6e02:20c8:b0:365:4e45:78cb with SMTP id 8-20020a056e0220c800b003654e4578cbmr10546205ilq.2.1710268904112;
        Tue, 12 Mar 2024 11:41:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:1d12:b0:366:70d:8658 with SMTP id
 i18-20020a056e021d1200b00366070d8658ls365109ila.1.-pod-prod-00-us; Tue, 12
 Mar 2024 11:41:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXlF/hZcWZOt1KSbb6sDva2uDY8iwG8i8Bb0Nqk/1Nxo1Y+Q8acYws0fx+TY5qj5WF1lYse23TTIGiHFn5bvxlLrybcFvWYm6QoZA==
X-Received: by 2002:a92:cda3:0:b0:365:6:b56b with SMTP id g3-20020a92cda3000000b003650006b56bmr399682ild.8.1710268903346;
        Tue, 12 Mar 2024 11:41:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710268903; cv=none;
        d=google.com; s=arc-20160816;
        b=fiFkH4uPXYGcVi8vd0b953UrwKCksstcXxCpw7PRD+ETgQFoBBbwvbijrWeViOSwTZ
         D1P82n88xEgUuBKx8Swnk0Df7nkyBHERjtJdlWTCmKWUkXBXqPbdGEjYX5EKlLkUy6XV
         7LpPgZTXLFJaZSu8V678Cjxa7xYPffkkn3FZud6NCGr/mqCX132aeA66zQ6Lrm8SOkUb
         IhwglQ9gP+z5Ov5+34leRdSYfABVYA8N3iAiLOx+o4OXIgVbi6Peve+F8Cxz3qipWJ7g
         KPh8iB1qYQJcUajfI3A/AmgVEy1ONOnAnK7MPgMtZkj8hYqZ/Whufb2toGejLpqlR1bS
         u0cw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=k2MYgtHOHaU2CXGG9+oDczn4RM3zU0YZuyP5JPwAa+g=;
        fh=Wx4wTK5WMnFsRJvbWAMR9i1kSvQG3KyyXdodJ2pN4I4=;
        b=AmUJQ43N+5hBLzwbi4mJ8F12zWYoaKrAnS0CnGQM6NKGe73RMYimi9xOMtRjuusD0X
         l6tnjkLHDREZ9sWzmGd85R4ODUfuzbYPopFS7Smk9aje7AyUQRUDDKBW+2WVlUsN8vOx
         EqIad1Vaj/SfWxUYMbSKmzbisqlgREXOLDiie36QbE2Vabna/Ck7sZCA2hrG7iw1H31P
         KsoYPIGfl9YN8b2PwtmrOJ0JOWEw8PWVivVKJNWDBM6F2R8neGaQzZREOj2tbXGhRQjn
         EOdR3mt26P4zbbKEEKyNayjwoyVJ8LbWK5jvWjDp2BC1gvheC6viqedp7vfQLwNxsDJS
         q/FQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="n3//WXx1";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112a.google.com (mail-yw1-x112a.google.com. [2607:f8b0:4864:20::112a])
        by gmr-mx.google.com with ESMTPS id h6-20020a056e02052600b0036503a50b98si685260ils.4.2024.03.12.11.41.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 12 Mar 2024 11:41:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a as permitted sender) client-ip=2607:f8b0:4864:20::112a;
Received: by mail-yw1-x112a.google.com with SMTP id 00721157ae682-609eb87a847so1325937b3.0
        for <kasan-dev@googlegroups.com>; Tue, 12 Mar 2024 11:41:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXt2/6/Kzvkosu5HS0AWyqK53ydbx3mXIYX4tUdJBOcOyEbX4wjnTVWqUWppEdQoh5gNHIOuCQ2WygtRIIaCn7tp/YXRigm06Xbzw==
X-Received: by 2002:a81:e546:0:b0:609:c64a:f34b with SMTP id
 c6-20020a81e546000000b00609c64af34bmr292571ywm.22.1710268902597; Tue, 12 Mar
 2024 11:41:42 -0700 (PDT)
MIME-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com> <20240306182440.2003814-13-surenb@google.com>
 <ZfCdVI464EqeI9YP@bombadil.infradead.org>
In-Reply-To: <ZfCdVI464EqeI9YP@bombadil.infradead.org>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 12 Mar 2024 11:41:28 -0700
Message-ID: <CAJuCfpFDY=+gmVytYY6iCYds5OW0gVfwrXguWWq0B0G1qq7hYQ@mail.gmail.com>
Subject: Re: [PATCH v5 12/37] lib: prevent module unloading if memory is not freed
To: Luis Chamberlain <mcgrof@kernel.org>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	vbabka@suse.cz, hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, masahiroy@kernel.org, nathan@kernel.org, 
	dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, muchun.song@linux.dev, 
	rppt@kernel.org, paulmck@kernel.org, pasha.tatashin@soleen.com, 
	yosryahmed@google.com, yuzhao@google.com, dhowells@redhat.com, 
	hughd@google.com, andreyknvl@gmail.com, keescook@chromium.org, 
	ndesaulniers@google.com, vvvvvv@google.com, gregkh@linuxfoundation.org, 
	ebiggers@google.com, ytcoode@gmail.com, vincent.guittot@linaro.org, 
	dietmar.eggemann@arm.com, rostedt@goodmis.org, bsegall@google.com, 
	bristot@redhat.com, vschneid@redhat.com, cl@linux.com, penberg@kernel.org, 
	iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, glider@google.com, 
	elver@google.com, dvyukov@google.com, shakeelb@google.com, 
	songmuchun@bytedance.com, jbaron@akamai.com, aliceryhl@google.com, 
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
 header.i=@google.com header.s=20230601 header.b="n3//WXx1";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112a
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

On Tue, Mar 12, 2024 at 11:22=E2=80=AFAM Luis Chamberlain <mcgrof@kernel.or=
g> wrote:
>
> On Wed, Mar 06, 2024 at 10:24:10AM -0800, Suren Baghdasaryan wrote:
> > Skip freeing module's data section if there are non-zero allocation tag=
s
> > because otherwise, once these allocations are freed, the access to thei=
r
> > code tag would cause UAF.
>
> So you just let them linger?

Well, I think this is not a normal situation when a module allocated
some memory and then is being unloaded without freeing that memory,
no?

>
> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>
>
> >  /* Free a module, remove from lists, etc. */
> >  static void free_module(struct module *mod)
> >  {
> > +     bool unload_codetags;
> > +
> >       trace_module_free(mod);
> >
> > -     codetag_unload_module(mod);
> > +     unload_codetags =3D codetag_unload_module(mod);
> > +     if (!unload_codetags)
> > +             pr_warn("%s: memory allocation(s) from the module still a=
live, cannot unload cleanly\n",
> > +                     mod->name);
> > +
>
> Because this is not unwinding anything. Should'd we check if we can
> free all tags first, if we can't then we can't free the module. If we
> can then ensure we don't enter a state where we can't later?

unload_codetags already indicates that someone has a live reference to
one or more tags of that module, so we can't free them. Maybe I
misunderstood your suggestion?

>
>   Luis

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFDY%3D%2BgmVytYY6iCYds5OW0gVfwrXguWWq0B0G1qq7hYQ%40mail.gm=
ail.com.
