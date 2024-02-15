Return-Path: <kasan-dev+bncBC7OD3FKWUERBUEXXKXAMGQEOLO6FIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id B7B46856FF8
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 23:10:25 +0100 (CET)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-21e585ffee7sf521352fac.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Feb 2024 14:10:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708035024; cv=pass;
        d=google.com; s=arc-20160816;
        b=07nBmt0cRdNovOuhsqLhQZc/1SAc4K44CD4XtywzoSnbwO+mg3kaK9VVh9HKzfyDOp
         pLcdwXCEhJ0VxiYDhKnoi6sXAk5wYlZJa86gRet/fb09z5Urz4xyXS1sAg0Qp55zdZfY
         y1g/8HUt75rebrLrn2HVjvbXTQFgL7Us3FvxeDMjLeyKAsQyigytfEf4qRnJnwvtGHuW
         ler/9urU/Dm5E3c+VvqC4qg3qz5f7Pwsf9KFmJqHotjez/VDzIiynujIfvKQXF16E1U0
         x8zRI0gp9NiLBfRz40wMFuiodnjl0tkGiV61sDOTz56MmcA7MQZVwQXFlH6Eee/8cQVk
         1t9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+M2KZh5N5FYh6MpAf9XdRP1kMLjaUquTc0fBUsPLl84=;
        fh=CKq78sLtRZGDWPUXfeEnZTd6yagZj0qR7jD3pWB4TnY=;
        b=Vim1cScV31kw+Rwr8Igob66Au4IOnjz6OuzlbROfg0XCImA1sjdjsYf0+/CDzcy1dF
         jYKmYVamzUV5J1dFoQB7XZgOqFPMNfU3KK4yMht4iys+hEHtYjsWlGegkH8x86mriKyE
         bue4QlTkm2VhpyEvF8vDW9AF9LV7gzwl2amYgSuTNXYO83Fo1gNTvP+1PqQ+/W5jx7lW
         kqigs9E9FGUZmoAluhNkUXzeSx4Vu8EPLhzdwdUbn/yGetZF+GDp3K5QIHKptbT+CpS+
         UeydIFj5Nmuwfdu3YGhg6UgkIBxXy1I10eyAyx8dlcvfyb/Y9lW21SvzxwMwrzLaVkp2
         BQiw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HTynbo3w;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708035024; x=1708639824; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+M2KZh5N5FYh6MpAf9XdRP1kMLjaUquTc0fBUsPLl84=;
        b=ANJ9C7SoaZ731iHyaDvPCzrEgcSPz/R6XPv1ldQm2xAo27Rf4nWjuJUOiDCgP+OYPL
         Cp60pouzFXMUik+lQ8W0yaGSrg7grI1ZOh7RzZj9GfrKAJ6fl9fVdsdhwi4pTKx7FMF3
         9P8i0r1mqlxH1qy2rqI7CvI3HouMuRC4Vwhy0CvDSbUc5XhfFx34O3huY07JOPpBptLD
         1rlZ8dtMHhXq52q/KZie2DL9nfavHDSAwK2uaAy6CC2nfxPSyvn2yXh3gfTxav3o43xv
         7c1cMPs0gjoDGKeM/gZl2koVw2vcqc0nFdgyk24Nii1B3iGw7jWue1qFdWEa4I7siwZh
         /usg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708035024; x=1708639824;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+M2KZh5N5FYh6MpAf9XdRP1kMLjaUquTc0fBUsPLl84=;
        b=KHq2c5y/PiyrGT7iYmReWA3u3A91bbowJCGdE12xF1a6igGDnRsB0yZUy/rpvueZsD
         2RVblFg3hTELZ/KOW8o4fEovoar966cnR218hW1ZCvHj2vWC2UrLFH2h2XVJEB+g1SuS
         gidlLDYksp2K8KamTyq2BeQWr0fVoOKE5nSClVLdW3ppELuXxl0cpvqJfv1szqcBTBZ+
         hVxKLtGiNgj0KCcZqj6c5mHe+xwXqDdJYoxFG6ede2yGe3ekLCxr9hkPM6t6gk+R9iJC
         2/cPLjWTGN+bfTe4HuEASjBDRdxxpINzTjyj72ay/QkZQMFzRF6NbhfTXRMLebEM+ZMk
         W+yA==
X-Forwarded-Encrypted: i=2; AJvYcCVrcOfqjgrO3/JNfmNkrI+JlZ+ICW5oTpkVnEWRcH7Y8T1Id054QZEfykHiDqRa6fQ9AfMoAP4dH1q1Js1Yw4RRYXmjBFH6Iw==
X-Gm-Message-State: AOJu0YztTYSDWOnBEMZYXeRuCbPxuEqcsIyphNi25LZ/v6Q9mRwDecfT
	h3WmhD4F23QSmRN+ekqgs0cQbHCa0ABuO50Lrdw3wFOsqvcvf4lk
X-Google-Smtp-Source: AGHT+IFYz7O0s+m0x8mNG4+VBCnTXBNZKHZosLc6CTGcfSfOubwNtG8KkVL7AJIneGVrJp3YIe8Dyg==
X-Received: by 2002:a05:6870:5688:b0:218:cdce:478e with SMTP id p8-20020a056870568800b00218cdce478emr3895407oao.19.1708035024260;
        Thu, 15 Feb 2024 14:10:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6870:316:b0:21e:4aab:bcf4 with SMTP id
 m22-20020a056870031600b0021e4aabbcf4ls223557oaf.2.-pod-prod-09-us; Thu, 15
 Feb 2024 14:10:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWcPSvor9nhoq2qP6CNr2RIUAw26HuuIx/AECyCBgm/A0clX4TRI5dQlgpGO64DloN8fvJs+mitZNL7tKUJzsji1ZDRC5Ea6exThQ==
X-Received: by 2002:a05:6358:885:b0:176:5d73:34ef with SMTP id m5-20020a056358088500b001765d7334efmr3328081rwj.24.1708035022984;
        Thu, 15 Feb 2024 14:10:22 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708035022; cv=none;
        d=google.com; s=arc-20160816;
        b=unS8iW4x2a5MO4bzBgDm6x/bXMtK6+uA2sBu7sYYiQPcQJew1AOYpa6LF7kI3soQ2h
         9Dx62QsUfiLhljsuoU82JOtqVjzHeLND9v2XKwvO7Oy2W6zS5/pz/3ZGQPxtWHxSP67d
         KfFtN4ktFtxRXxQkT8ETRFHX62Tkp9JHEmGAY7fTck91gmWllamqB1v7/7ux3Z5oj30H
         o0PcaI9P1klQsdNQjZvkd0/oM94EYHmBnzcdZm9E3lp+5QAJdyc78J4eI8cIkLh90WYL
         dDuCrDRl+Erz39ym5mzBLI/LMdfNglMuoAzNqK+fj+sj+MittOaWkZeeIK4kpvwCALmw
         Kenw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=DLHIWZhrv84d6KmPP8BZW5HG3tmTNG2nCmARo35gkoM=;
        fh=k++6N9fWjSHj8A2ZJaQrPpFYh9i61l9V4Qm6ESmsBpg=;
        b=cGJ1l/peaiQ/f0u7e39I1RO0G0jeb2zO8mLIrlYmhgyDPZ+SO6+9cQPkdXN3vbXN8H
         0aTwD3y/U4AQU49wH0wYcKDiZEI6V2HSpLTFHwDHufsAWBNEDcntgPOvnatrtO58D6JE
         2u7JR7dWtTDtwOqYX8YKLXnEoNZmnJjJgNd7dcZ5c1mCW/8UpIx3Q+9fOrYbzhJLXt0H
         E4VCKPbRm5T3tuZVEMHs89Ub6+rNkVSzU7LXEfHcJjzBxSBzNKJQthi+uK60wbWUBeXP
         A9Y8u3FoRZtYTJlIw4tPfiCjYt5agA+bX6EW5FTnaS4LNlHRoh7fl2JqzvvrzA7sdgE4
         tUjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HTynbo3w;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112d as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112d.google.com (mail-yw1-x112d.google.com. [2607:f8b0:4864:20::112d])
        by gmr-mx.google.com with ESMTPS id ic12-20020a056a008a0c00b006e0542545eesi166002pfb.2.2024.02.15.14.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Feb 2024 14:10:22 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112d as permitted sender) client-ip=2607:f8b0:4864:20::112d;
Received: by mail-yw1-x112d.google.com with SMTP id 00721157ae682-607d590aeb5so10042637b3.0
        for <kasan-dev@googlegroups.com>; Thu, 15 Feb 2024 14:10:22 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCV0ehMkjURHznn3mVUUkqKylimfdz2P3L2XsON4WibKAP1TYQU9xEkzdDNbuFdt8+8Zc8T8wPVgqa34THRp0AbnDyPug8qenal2iQ==
X-Received: by 2002:a0d:cc81:0:b0:5ff:956a:1a05 with SMTP id
 o123-20020a0dcc81000000b005ff956a1a05mr3845012ywd.14.1708035021851; Thu, 15
 Feb 2024 14:10:21 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-8-surenb@google.com>
 <fbfab72f-413d-4fc1-b10b-3373cfc6c8e9@suse.cz> <tbqg7sowftykfj3rptpcbewoiy632fbgbkzemgwnntme4wxhut@5dlfmdniaksr>
 <ab4b1789-910a-4cd6-802c-5012bf9d8984@suse.cz>
In-Reply-To: <ab4b1789-910a-4cd6-802c-5012bf9d8984@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 15 Feb 2024 14:10:09 -0800
Message-ID: <CAJuCfpH=tr1faWnn0CZ=V_Gg-0ysEsGPOje5U-DDy5x2V83pxA@mail.gmail.com>
Subject: Re: [PATCH v3 07/35] mm/slab: introduce SLAB_NO_OBJ_EXT to avoid
 obj_ext creation
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Kent Overstreet <kent.overstreet@linux.dev>, akpm@linux-foundation.org, mhocko@suse.com, 
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
 header.i=@google.com header.s=20230601 header.b=HTynbo3w;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112d
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

On Thu, Feb 15, 2024 at 1:50=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 2/15/24 22:37, Kent Overstreet wrote:
> > On Thu, Feb 15, 2024 at 10:31:06PM +0100, Vlastimil Babka wrote:
> >> On 2/12/24 22:38, Suren Baghdasaryan wrote:
> >> > Slab extension objects can't be allocated before slab infrastructure=
 is
> >> > initialized. Some caches, like kmem_cache and kmem_cache_node, are c=
reated
> >> > before slab infrastructure is initialized. Objects from these caches=
 can't
> >> > have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mark =
these
> >> > caches and avoid creating extensions for objects allocated from thes=
e
> >> > slabs.
> >> >
> >> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> >> > ---
> >> >  include/linux/slab.h | 7 +++++++
> >> >  mm/slub.c            | 5 +++--
> >> >  2 files changed, 10 insertions(+), 2 deletions(-)
> >> >
> >> > diff --git a/include/linux/slab.h b/include/linux/slab.h
> >> > index b5f5ee8308d0..3ac2fc830f0f 100644
> >> > --- a/include/linux/slab.h
> >> > +++ b/include/linux/slab.h
> >> > @@ -164,6 +164,13 @@
> >> >  #endif
> >> >  #define SLAB_TEMPORARY            SLAB_RECLAIM_ACCOUNT    /* Object=
s are short-lived */
> >> >
> >> > +#ifdef CONFIG_SLAB_OBJ_EXT
> >> > +/* Slab created using create_boot_cache */
> >> > +#define SLAB_NO_OBJ_EXT         ((slab_flags_t __force)0x20000000U)
> >>
> >> There's
> >>    #define SLAB_SKIP_KFENCE        ((slab_flags_t __force)0x20000000U)
> >> already, so need some other one?

Indeed. I somehow missed it. Thanks for noticing, will fix this in the
next version.

> >
> > What's up with the order of flags in that file? They don't seem to
> > follow any particular ordering.
>
> Seems mostly in increasing order, except commit 4fd0b46e89879 broke it fo=
r
> SLAB_RECLAIM_ACCOUNT?
>
> > Seems like some cleanup is in order, but any history/context we should
> > know first?
>
> Yeah noted, but no need to sidetrack you.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpH%3Dtr1faWnn0CZ%3DV_Gg-0ysEsGPOje5U-DDy5x2V83pxA%40mail.gm=
ail.com.
