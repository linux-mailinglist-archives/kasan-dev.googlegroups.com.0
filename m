Return-Path: <kasan-dev+bncBC7OD3FKWUERBIFSXGXAMGQEGVXEWKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 60D1C856CB2
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 19:34:09 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-680b7da38bcsf17651936d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 10:34:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708022048; cv=pass;
        d=google.com; s=arc-20160816;
        b=MicazNDYYABMh7xOU/h+tokZ9utCBU6QAKReg/cN+O33juzETe+Au36BJbs0CdA4Tv
         CSTgtCUnvIZzfQja2G18/LUeDMyopVeQ7CZITZwo0AbpDVa67DinGkmcKuF5yrzMvu9I
         +icxj7hRdw6lNUJnO+Nc75TpECYZ+bjtxZImkhfICEAmZwxmoIsyMhm+Sg/G4FusIhVs
         QAmoP7m6Ifpdhg33h/Ut19eA7VCp4f+5kJZ84rVMnXUkLeqyJh2arhhIki7U5+JrhERt
         z9wGWzHHAcWxAXavu/hdb4g8/eMPDToiIeNsbpWQS8CLi0OXCY4RWfO0v5ct2QGVRMjr
         4Uvw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=olGJq+dOsBXglJgm53rCP6RQP5adZZg1xIZdABgobII=;
        fh=LmYRVHw05QuZgu2r0VcJzHF1v0DZFUPg2D/IrtUuEkw=;
        b=C13r/JeDUPuEuo5sov+svrUFVoixNYGZjQyHe86np8wERN/UD0anLQ/VyhKay37svD
         hKPqvEzXn7GB9qYxotcSHQT4228s9imXtr5WjCEQDOVCY/UNgXmtB/x4pYbETQVcXNQF
         ekYXjBUpg4uUY7xHZKWOUnkJontN7nBslqzl2A1me0YG0Xu7enzdvbyX3YDARbhcbFOH
         J5oT8UodK0Rgj17RqC3cj4ib6zAaOato1XD5JESz3372gvMzahX/myUijocnuxbsKYX/
         IcUrC4wf5H49OxWx+AigPCbTQX+HTSoV6wEUKYdq1fBKZFiqyY3RQLAPEpZPF+jrLJYo
         pPSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=E0WLO0YR;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708022048; x=1708626848; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=olGJq+dOsBXglJgm53rCP6RQP5adZZg1xIZdABgobII=;
        b=YxYunSuMUJQ9RJ/ScZWLVWYtKK+KdX+r7idOb6UhOhC1pEZM8WpgBeC1MOUuSJhv4A
         lXUaDyyOF8iq9knH4ywWMmEC7chZTF+Mae5/O3Z9bBaoWu2vnJM3n4kRoiDTh3CqNYMa
         +2oFVcbWC7WHb022p8HaKLaTV3XvsIHzyDFn6TbLiPylzf4lm+I2u7vD9+04yOvDJln+
         HuvISmvklc0sDwcKcSxFWdDEelbDdn8+QIYJOL6sZLfg3/Uq3dONTZqWoA6Odg5JHP1I
         qXAYIqxkUTdPE2qz4LHnPCor+0wpews0LzgIKd5AfJkjEn2V5/EZbLSQgK+vGOy21gRj
         vyAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708022048; x=1708626848;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=olGJq+dOsBXglJgm53rCP6RQP5adZZg1xIZdABgobII=;
        b=cgN3yNckHu5am3wRK3fTgDQ/02Lx2lvDYcKGM4++G4OVTMAzT7KU5jO/ZLgMHaHhYu
         oOiccZMtLUuoiwu5mjZxXDgdNhB9qKK1UIz+ZYx5/ExihSmiXEf60JvN996sdLK3eg61
         +FGO/H8lwfjkTVMhc8DHoTI1gMMVDCiHfApze2eLflQweK6h00NJM4MBu+w+7O6fR+fz
         v7l3y5ubII39G6p1DNl5QX3qMt9/EPrfLtUo7qSolnTMsZPQngYHeTtOLMLMkVXBRR2m
         VW10pz5LTMABgMpF4E+JKvxj7zuxnHqMhVZHdz48Zs7OcOF/9JGc+qVkQic4zZFhVVtw
         C4xw==
X-Forwarded-Encrypted: i=2; AJvYcCWgLRZZxoX+dIGNve5ZhNWvuCBgjGPOyeanoehQMFdO+PG4AfOFqYEp8BfwVQTElPl1BYxdymA7/tL2VY6bWeMjtFWmHHVMrA==
X-Gm-Message-State: AOJu0YzVBdccT8mEY3l66XRyjbbPt949ollcknhrKnxjfNtFlVM87Cli
	DyPG5StFrDnHsgBLsJevxdr0UDGRsbEOeHnbdclJljV+5dXSoDCH
X-Google-Smtp-Source: AGHT+IEp7GvuK4uuPj9vjuMO5EUSYLWvY0hbjYVP2z4NPX2M1HJVKp8vj32mkz3DindpmyeglSaf9w==
X-Received: by 2002:a0c:f54b:0:b0:68c:95a3:5a3 with SMTP id p11-20020a0cf54b000000b0068c95a305a3mr2432544qvm.1.1708022048205;
        Thu, 15 Feb 2024 10:34:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:242b:b0:68c:d848:72ac with SMTP id
 gy11-20020a056214242b00b0068cd84872acls26091qvb.2.-pod-prod-04-us; Thu, 15
 Feb 2024 10:34:07 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWu0V5E1dZ1x+oxGBLpzV1MadewP8Ud7RnvKVlB55M7kyK5uwOzbrH7NGe+kQSZHeJs5OgUsf84DsXTosnhKxE2K9KMY+Jr0G0bog==
X-Received: by 2002:a67:e2d4:0:b0:46d:49ac:6ec4 with SMTP id i20-20020a67e2d4000000b0046d49ac6ec4mr2761088vsm.19.1708022047533;
        Thu, 15 Feb 2024 10:34:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708022047; cv=none;
        d=google.com; s=arc-20160816;
        b=gxQ6VJPkT8AAHOavMneWrfbJxDwT18BCqK6taf1lcblMfI9P/pH3q1ZquIBCr+/QZs
         dnRk7SW5m5caLZ5ulBgd/B2y/kWqJzBeFMEYVAJKt1F8J/qitxm2EdvAxkd96plKt1m2
         DrW5XK1OjjyU8JU9yj9gh2aRQHCwtD6Q0mYh0Du8kqNct7lgivx8YvIQeysjtv/JnwIV
         jZV+XZV7QJwBGAbGFr2Th8MKI9BYbEMCdvq3Pix2hvvoKzaIfIqjpwyiScYg5H82c/oi
         X0TytioMpRKncp+pX9iqsCVBiqUYM9jMPwfkq2/lbCZfzcGgr+GjYCuStr15xUGN8b5n
         nw2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=c/zbyo2KXw6JhtuTeO6vuT3ARKuU8XObNaLi3n/GNPQ=;
        fh=ngRtfjIci6goa+rBfcGw44UcP9Q3hw2eKwCJ+BAqwVI=;
        b=VuekJ65A+ToulaMZWuygUGa7LNgW1oFqVS2ZKQZIjHMBwjeGM2gZFEWUiAVuQvVFvX
         +dvO+N4YQMghNd9nqjdDoBrbuj58l9SnTuCuuOfKXsRtBzySNH0BNDmSneiLudwJqhK/
         Os6BjyIbvMS6HcrcRjP8gjN5FhmojDS6K83hlK5Jj1TaN+jY2D9re7ifYBABmcGsIXw4
         p3fkiuLcdMwI5pBgR76HoixWPnz1TKdCQ54qBoecwJeXnuUdmvhtUeZh/A1G8UIHI1wk
         HP7vmyRSyqS3JY19t27m/FM/0Mc218NFNENocqaMNw1lq3UwANkoAWFh5/QtMg5EY3pM
         LnQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=E0WLO0YR;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb33.google.com (mail-yb1-xb33.google.com. [2607:f8b0:4864:20::b33])
        by gmr-mx.google.com with ESMTPS id v28-20020ab036bc000000b007d914ea8a2csi128410uat.0.2024.02.15.10.34.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 10:34:07 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as permitted sender) client-ip=2607:f8b0:4864:20::b33;
Received: by mail-yb1-xb33.google.com with SMTP id 3f1490d57ef6-dcc71031680so1118045276.2
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 10:34:07 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVZPe32I+0xuq3vAjyNIuhQ7y/QmbHJ20WY43vgpwGpj2n2eFp1jRpJ763ehwrk1jlPxfcBaQbRxzOUjgSPYLuK37wJpaIbmmNKLw==
X-Received: by 2002:a25:bac5:0:b0:dc6:a223:bb3b with SMTP id
 a5-20020a25bac5000000b00dc6a223bb3bmr2333936ybk.46.1708022046848; Thu, 15 Feb
 2024 10:34:06 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-32-surenb@google.com>
 <Zc3X8XlnrZmh2mgN@tiehlicka> <CAJuCfpHc2ee_V6SGAc_31O_ikjGGNivhdSG+2XNcc9vVmzO-9g@mail.gmail.com>
 <Zc4_i_ED6qjGDmhR@tiehlicka> <CAJuCfpHq3N0h6dGieHxD6Au+qs=iKAifFrHAMxTsHTcDrOwSQA@mail.gmail.com>
 <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
In-Reply-To: <ruxvgrm3scv7zfjzbq22on7tj2fjouydzk33k7m2kukm2n6uuw@meusbsciwuut>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Feb 2024 10:33:53 -0800
Message-ID: <CAJuCfpFCu73eCMo-hd=vvvMhGjEuOwvkcGb2DuDssHC5soNFGw@mail.gmail.com>
Subject: Re: [PATCH v3 31/35] lib: add memory allocations report in show_mem()
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Michal Hocko <mhocko@suse.com>, akpm@linux-foundation.org, vbabka@suse.cz, 
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
 header.i=@google.com header.s=20230601 header.b=E0WLO0YR;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b33 as
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

On Thu, Feb 15, 2024 at 10:29=E2=80=AFAM Kent Overstreet
<kent.overstreet@linux.dev> wrote:
>
> On Thu, Feb 15, 2024 at 08:47:59AM -0800, Suren Baghdasaryan wrote:
> > On Thu, Feb 15, 2024 at 8:45=E2=80=AFAM Michal Hocko <mhocko@suse.com> =
wrote:
> > >
> > > On Thu 15-02-24 06:58:42, Suren Baghdasaryan wrote:
> > > > On Thu, Feb 15, 2024 at 1:22=E2=80=AFAM Michal Hocko <mhocko@suse.c=
om> wrote:
> > > > >
> > > > > On Mon 12-02-24 13:39:17, Suren Baghdasaryan wrote:
> > > > > [...]
> > > > > > @@ -423,4 +424,18 @@ void __show_mem(unsigned int filter, nodem=
ask_t *nodemask, int max_zone_idx)
> > > > > >  #ifdef CONFIG_MEMORY_FAILURE
> > > > > >       printk("%lu pages hwpoisoned\n", atomic_long_read(&num_po=
isoned_pages));
> > > > > >  #endif
> > > > > > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> > > > > > +     {
> > > > > > +             struct seq_buf s;
> > > > > > +             char *buf =3D kmalloc(4096, GFP_ATOMIC);
> > > > > > +
> > > > > > +             if (buf) {
> > > > > > +                     printk("Memory allocations:\n");
> > > > > > +                     seq_buf_init(&s, buf, 4096);
> > > > > > +                     alloc_tags_show_mem_report(&s);
> > > > > > +                     printk("%s", buf);
> > > > > > +                     kfree(buf);
> > > > > > +             }
> > > > > > +     }
> > > > > > +#endif
> > > > >
> > > > > I am pretty sure I have already objected to this. Memory allocati=
ons in
> > > > > the oom path are simply no go unless there is absolutely no other=
 way
> > > > > around that. In this case the buffer could be preallocated.
> > > >
> > > > Good point. We will change this to a smaller buffer allocated on th=
e
> > > > stack and will print records one-by-one. Thanks!
> > >
> > > __show_mem could be called with a very deep call chains. A single
> > > pre-allocated buffer should just do ok.
> >
> > Ack. Will do.
>
> No, we're not going to permanently burn 4k here.

We don't need 4K here. Just enough to store one line and then print
these 10 highest allocations one line at a time. This way we can also
change that 10 to any higher number we like without any side effects.

>
> It's completely fine if the allocation fails, there's nothing "unsafe"
> about doing a GFP_ATOMIC allocation here.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpFCu73eCMo-hd%3DvvvMhGjEuOwvkcGb2DuDssHC5soNFGw%40mail.gmai=
l.com.
