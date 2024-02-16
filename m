Return-Path: <kasan-dev+bncBC7OD3FKWUERB6OYX2XAMGQEHGURWXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63a.google.com (mail-pl1-x63a.google.com [IPv6:2607:f8b0:4864:20::63a])
	by mail.lfdr.de (Postfix) with ESMTPS id 48FC2858570
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 19:42:03 +0100 (CET)
Received: by mail-pl1-x63a.google.com with SMTP id d9443c01a7336-1dbbd6112d1sf112905ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Feb 2024 10:42:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708108922; cv=pass;
        d=google.com; s=arc-20160816;
        b=QFSjSP2Ad6uvy0cKwAGfnpBh8Tx2Dm5WvoSHdTRGEUumb0z09symFBfoHdIp6ADT+4
         0hIgqbilFi6GySvxLj0Y+onPvi3JOSb+RUioHuCSVfpQ1ExXRut5VGGNWfTjXf2GRRQf
         LT29ZsgKdLzJnhoyXbtKCrlsQo70AMBcKmYIUnyoe8CSRqpMwwZaP5fNxoH9g8tmpO2s
         NR+7cHGCV0Pm47xnSO6w26KBh5ce/LVJm/20/Ny6ppAP8Hwmo9FGdpfPLWL4JfkZnU9Z
         bItvBTUiQ8JRXX0GTS1JXROLbShniXcQ8Sx7te0H24WWyZht/YLDhZt0dE7QBglveaGh
         Ge2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kzbjQi/x6dS6utyZPdWD4q3c0diSn0cAp4RY/iCwrrc=;
        fh=4/1N4DN92YZ+E/x1V2rF0Ev/O9E4PJVFf0eDJ7wrzdk=;
        b=lCsZpShQ9mdU4bz7Na7pntVmt86loRSgAWapM9a1Hexnu367cCXRIO2098T9sEHlPy
         KuhJ4YDguAr9q86uF9cRbwgOxANLrVi65xe9CgI4Cz8ocx04jHkq8LLQuK44IxAiDrtP
         stBs22b9IRb9f6i+K7HsTyX7XtiqfreLBxg++NW9rfIrfgpVYh7y6SPvkruxOZMnZz8a
         8mFYOALzDVa2QsYCf//5pHQIeoqMcuGBNaZ4UA7sRSpeSzNTLwbVq8d7XQdOqxfaynix
         7BEd7jg+vKRCORpu3WGvUZVbaaDEk4TT3UUIbqLxDcrRe4bF9R1zldnZ3fWAGvuZeH/Z
         lKEg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="kG6m8K/e";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708108922; x=1708713722; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=kzbjQi/x6dS6utyZPdWD4q3c0diSn0cAp4RY/iCwrrc=;
        b=RzwyAzJ7Jz6zE8oY3VMKx76WTqj5Fy/Cf4k/5H39IUGDFRDf5vMGrDm2Y1titdkk96
         lfcFSHrnoM41aE7MSgnSjIovdJ2Suds9PJD76a75Zhug99GtdJKafdM0PL6QmdoYouDC
         K3/qSSKQaDyIkId/1uEc9LBN405ASuHlgBb/73fWkmYsqlB0llZmjbMRcl9Ze1lLY10b
         O5hFExvpk2l6eO7lBF2tEvG/mrHqj0hrUbWMi0ltW1neTXk7tUM22Padf0hSBz700Lj4
         tvQ/zJlxV1SXqTK+t2TWIoxdqLVwn4qr+thT/e3BH1tgyhNDXh75vynyAbuwko8/CV+/
         jcgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708108922; x=1708713722;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=kzbjQi/x6dS6utyZPdWD4q3c0diSn0cAp4RY/iCwrrc=;
        b=M62u6Fe/QI+I5Go0L08uC5Xm846KDnoN1BjToLP3rPHmkRO32O0yYCG6Zyi49Mq7p+
         JUlmTXQCrbs3GL3hrYBHZYmwko9mMDD8EDmpaxkskesVtHQKFiK9ryTtocnAszl3JvMh
         txp8yBufbdPrG/qL1Qh+yhbAVqEmQh2RaQrZVOE4jq1hFe+7WXL5737Ksg/GpTi0A30U
         bjQEb2W3JZLT9fYdU2kgun7yU5EDamiaqwg6g5mA4YcjtE3cZ9GFvQxel+pAQrSNR0wq
         FG5QZnZ9JOGSMPoKJ7i+HG8AlU0FdyFRpKe7Gx2fNHkAXsXneKZ/zkkxwW24HS+5B6xY
         aFwg==
X-Forwarded-Encrypted: i=2; AJvYcCXDarL/n0zGtfFiKUTGH9h67eWZVGGvC2Z3nt+KVWyqPBuprR49AefvlwzNngEABttxsHmw8skWhcXBQxGPVr7JUE2HmD145g==
X-Gm-Message-State: AOJu0YyHe1sBUc7XoA55fftDNcUz3cfnZIgLQ8u9uimrpW2p1sqWG1dm
	vBfZZMi1KTmtaFPxDk91FIekKB2xjFQrfw9IbpVwHrvKv7T7f0Qf
X-Google-Smtp-Source: AGHT+IGo4F9/NA0ZdBdH0AIJBCTDWg1lkR/xNUEYdKZTbHP5ju1A6e+BW46JSeZEJghPQqkhxysVCg==
X-Received: by 2002:a17:902:d2d2:b0:1db:640f:cb43 with SMTP id n18-20020a170902d2d200b001db640fcb43mr21462plc.8.1708108921608;
        Fri, 16 Feb 2024 10:42:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:4c4d:b0:299:34de:8849 with SMTP id
 np13-20020a17090b4c4d00b0029934de8849ls501832pjb.0.-pod-prod-00-us-canary;
 Fri, 16 Feb 2024 10:42:00 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWV+F9fr7bJS31aRI230b6hhY2vowIBgqTwmT33CeI2WZoVoUpl/5DQNFWddbhGzKKxGC61Fw17hTrJOqyymtC4jOrv7PzewoU2Xg==
X-Received: by 2002:a17:902:bb0f:b0:1db:c056:8b2f with SMTP id im15-20020a170902bb0f00b001dbc0568b2fmr420688plb.16.1708108920471;
        Fri, 16 Feb 2024 10:42:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708108920; cv=none;
        d=google.com; s=arc-20160816;
        b=tvSyTl3fGdRh0xQ9xP51tStpBqfcSbPmqqga9QJmR2n69q6/EZoO8FNllYwaQroG/l
         6dX2EpkIM08weNjbVOIMySlpGtfhpzj7xkJ1aYqDHGPD4LM6ADbooQm0XcVn2JmppHRY
         0eczZswluC+JbcEfjjgWxHZJ6nJcWdkvMbdaPJylBVegdXUQl3QHioSchPHIilsIkUnB
         F4i8DkKzhx+6JsQ7vD1njf1lc5e3+NYVWckXcrQEw/GkcmVXisDAwgs5r0OwxmtMCuRP
         7uaLbkXOik0dIO3JAlu+pVFkG+EnkPNpK4q9EzylypG82yr4OAiboHCBt3moCV3y9wXW
         OILQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=faKyGS2bCJ2px0ud+d+mBkv9JBZNScCq7HyfBnLgGJM=;
        fh=ZyUtoAE6l9zfWRjUneTcsxOwMVt5AxilvBLTfAp8ndw=;
        b=hGn1oGJlW3OhTm94FHV71WA/OX4JiwTcR8RfJTDuQK+th1P57OIZSj31J7brVOD7FJ
         8n/IWuJMU3FprUJ+UpWb+KMRyYDlyilMv+qk9vAHHVdSbbPZHxdTlFWA7Boeb8ig0EJp
         nphjyU/E2odWZIaOJfPHW5I2MxJjj7Us0v8LVul3GVln17E9U3yCMTo4HZ2wAMu1pCxl
         An68A4KLlbQ8o36KY4Qiyjv8tV9os73/xr/su+4D84vt+NrHaipMdHXEAh/HSDwfGMyF
         hzCjfpRJu4m+9yuVIxfxeZmReRvqyAY5YNiI1Qi7ccbJPRpNlXBuxseEjWgHb8NyqwqD
         fHJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="kG6m8K/e";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112f.google.com (mail-yw1-x112f.google.com. [2607:f8b0:4864:20::112f])
        by gmr-mx.google.com with ESMTPS id s3-20020a170902c64300b001db3eb95007si22090pls.5.2024.02.16.10.42.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Feb 2024 10:42:00 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f as permitted sender) client-ip=2607:f8b0:4864:20::112f;
Received: by mail-yw1-x112f.google.com with SMTP id 00721157ae682-6077444cb51so25297487b3.1
        for <kasan-dev@googlegroups.com>; Fri, 16 Feb 2024 10:42:00 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVZvic48rHDOCFXnYMhvZmPMNT1qPSQsD64ZqWG7bAyFFWtd1r7Utfeb2mzFoHYIHrWGjPoqb9EkFym2MPGq50DB52u9R1NJM9Z/w==
X-Received: by 2002:a25:fc23:0:b0:dc2:3a05:489 with SMTP id
 v35-20020a25fc23000000b00dc23a050489mr4194145ybd.14.1708108919211; Fri, 16
 Feb 2024 10:41:59 -0800 (PST)
MIME-Version: 1.0
References: <20240212213922.783301-1-surenb@google.com> <20240212213922.783301-8-surenb@google.com>
 <fbfab72f-413d-4fc1-b10b-3373cfc6c8e9@suse.cz> <tbqg7sowftykfj3rptpcbewoiy632fbgbkzemgwnntme4wxhut@5dlfmdniaksr>
 <ab4b1789-910a-4cd6-802c-5012bf9d8984@suse.cz> <CAJuCfpH=tr1faWnn0CZ=V_Gg-0ysEsGPOje5U-DDy5x2V83pxA@mail.gmail.com>
In-Reply-To: <CAJuCfpH=tr1faWnn0CZ=V_Gg-0ysEsGPOje5U-DDy5x2V83pxA@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Feb 2024 18:41:46 +0000
Message-ID: <CAJuCfpGBCNsvK35Bq8666cJeZ3Hwfwj6mDJ6M5Wjg7oZi8xd0g@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b="kG6m8K/e";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112f
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

On Thu, Feb 15, 2024 at 10:10=E2=80=AFPM Suren Baghdasaryan <surenb@google.=
com> wrote:
>
> On Thu, Feb 15, 2024 at 1:50=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> =
wrote:
> >
> > On 2/15/24 22:37, Kent Overstreet wrote:
> > > On Thu, Feb 15, 2024 at 10:31:06PM +0100, Vlastimil Babka wrote:
> > >> On 2/12/24 22:38, Suren Baghdasaryan wrote:
> > >> > Slab extension objects can't be allocated before slab infrastructu=
re is
> > >> > initialized. Some caches, like kmem_cache and kmem_cache_node, are=
 created
> > >> > before slab infrastructure is initialized. Objects from these cach=
es can't
> > >> > have extension objects. Introduce SLAB_NO_OBJ_EXT slab flag to mar=
k these
> > >> > caches and avoid creating extensions for objects allocated from th=
ese
> > >> > slabs.
> > >> >
> > >> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> > >> > ---
> > >> >  include/linux/slab.h | 7 +++++++
> > >> >  mm/slub.c            | 5 +++--
> > >> >  2 files changed, 10 insertions(+), 2 deletions(-)
> > >> >
> > >> > diff --git a/include/linux/slab.h b/include/linux/slab.h
> > >> > index b5f5ee8308d0..3ac2fc830f0f 100644
> > >> > --- a/include/linux/slab.h
> > >> > +++ b/include/linux/slab.h
> > >> > @@ -164,6 +164,13 @@
> > >> >  #endif
> > >> >  #define SLAB_TEMPORARY            SLAB_RECLAIM_ACCOUNT    /* Obje=
cts are short-lived */
> > >> >
> > >> > +#ifdef CONFIG_SLAB_OBJ_EXT
> > >> > +/* Slab created using create_boot_cache */
> > >> > +#define SLAB_NO_OBJ_EXT         ((slab_flags_t __force)0x20000000=
U)
> > >>
> > >> There's
> > >>    #define SLAB_SKIP_KFENCE        ((slab_flags_t __force)0x20000000=
U)
> > >> already, so need some other one?
>
> Indeed. I somehow missed it. Thanks for noticing, will fix this in the
> next version.

Apparently the only unused slab flag is 0x00000200U, all others seem
to be taken. I'll use it if there are no objections.

>
> > >
> > > What's up with the order of flags in that file? They don't seem to
> > > follow any particular ordering.
> >
> > Seems mostly in increasing order, except commit 4fd0b46e89879 broke it =
for
> > SLAB_RECLAIM_ACCOUNT?
> >
> > > Seems like some cleanup is in order, but any history/context we shoul=
d
> > > know first?
> >
> > Yeah noted, but no need to sidetrack you.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpGBCNsvK35Bq8666cJeZ3Hwfwj6mDJ6M5Wjg7oZi8xd0g%40mail.gmail.=
com.
