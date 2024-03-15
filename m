Return-Path: <kasan-dev+bncBC7OD3FKWUERBJ4A2KXQMGQEAGA7TQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B6B4687D24F
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 18:06:48 +0100 (CET)
Received: by mail-oi1-x23d.google.com with SMTP id 5614622812f47-3c24221f4efsf2056550b6e.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Mar 2024 10:06:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710522407; cv=pass;
        d=google.com; s=arc-20160816;
        b=FavsmF0Ob4f5iuQzhNvw1Vo8wjVkrg2dXhkFUSx/54O9E3aMjhwZtol3Zjrw/Id0QE
         paVqjvSiev1kGuN788Rvx+UkRzeqsPtMpqMoYuOfmzq8xk3qBtyzddkF67GLStHUtA4L
         qhsfMDIRahhhddx2f6kI/Z16ZzdCDC1PVrZk0Jw9wlN/LtjBYMmJG8gmKC9DCeG1U5RI
         OufesQe7rTXbA365KI7Dr2VldiEpG9YBKwWF4mZ42oZC79Z6gNFQpDjlO2yi6W/H5KG/
         jGBdG/evftEPHeVBpp1Jcxbxh5hqpegsUcTfqTBFF+jjcUEu9sctMCi0nHne97JiJh5j
         SndA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XQnQcM2w3Mg32sGYcpI7YEOcVwEXHJJ3PEKDeO0bgsQ=;
        fh=JIfiXj2+x7L4juiK07YApiJoLuNazaBwNHTL6Yt1upI=;
        b=VAIzedZFBxQQz0rn3b+JvO4yEmeKusN9vk2QMVqqhaUmw5OKlgyRjOrXT2QY9zLmkb
         PEMmtTldsuKdj8B8nGN4tQ0qwGymk6Szch5nxusaMHf2efF4ZV1lRaFCqCgth2k+DvXY
         B19LYBgoKW3fjqiaHXj9pc5vP/dfXJ8IyzCzNy7sUoQm/Tv8M7q7Z/k8Flb+f+nDWWLJ
         YTYVCE9P5jjDxP6SQh6IFBZLD4MgM44Id4aBvkm6/3WDYtMadE7qA68410z/zVD6v8AE
         ItyzBUt7yvUiH/dk4Vc2bzj1xZ7xQMDQ8zf8iZbLNm2UkCpsQm3pY+E1RuwavJcMHttr
         kQ8g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="kB/76sSP";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710522407; x=1711127207; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XQnQcM2w3Mg32sGYcpI7YEOcVwEXHJJ3PEKDeO0bgsQ=;
        b=fd32BGv1tcvK00WhYmgegxUOm4hx9L+X41tkwbHyRpiLfcc1xsJtZlHvnPXlgrzrH9
         5GPEN3glDyjt5Yy0C3ufPMmV9hiyVLeDDusXXyQ4S+KFgEiWTzHr+EbUDoA5yg7Y3jJZ
         Bc/+xq1q5a2iNjg1Q7UZ1F4eAz0dCpKCrtvfFV9r1NLe8BarFHDhC4U0y0QWIm30mLEk
         NNkcpSDivp3HTMZufzMXI0glWskhBDBvKfmNW4TQARr2fqb1jAEp2OGljbATT3QUaWvq
         ZiyRytViOVrqVPWCxKJo3BiVPS+jwxtEHUp+o/OkTOQBXBejhMxemBq8DkDGop9FcK87
         bn4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710522407; x=1711127207;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XQnQcM2w3Mg32sGYcpI7YEOcVwEXHJJ3PEKDeO0bgsQ=;
        b=FImE27S9joHnmbHkvWgexwGT3Szpibt1kTNisiT6yk7WilpV+xztRu4q1ifzH7MzVV
         GTb7HFwT5wqmSycnHSjYUqlzRNg1DaE3DBez5fSuaOoA8g84nzYTaQ7fS/7/Q1qjRPXC
         6e0hLtjjbLJj5A/W2/fo1YEeoIoprAVB9/jffZ2r0/0RRBUhkRGN77ehnWxOKU6v1t88
         ZDix+snM6SnZ7yzejWBo1xSrkeJ9Zn8x+2KRbfKRYMPQkhDK4MYk+YjpfGyCIcZcw3Zd
         ltGKwjZNbXQWvylaRXawLU8dMPXS387GyrLVl6Jnxp+s6vVkTZmEPcANGS/ZATem5tfO
         o3JQ==
X-Forwarded-Encrypted: i=2; AJvYcCWhz+gFs6MRMOEOun4qfHx5XKMTupywuWRwUsl4y+xyGe6gPJHFQaHIjPdEd0AtaSMYXL1GRjPY2f8hoEvESO1cde3fqxQf9Q==
X-Gm-Message-State: AOJu0YzmDjlH45OA598qhQjC7NSMvlTWhwknOmvx9LD/gCWzCrGCHm9C
	nPoLTF+hH+x/sF2q6InDC7qmbTnFyjphbSW3tETW1aZ+nVLNwHHWj1U=
X-Google-Smtp-Source: AGHT+IHqAKLLtNy53dW7JUIolCxauXKr55KKXDifrTWyMRrYvgoMTFLlCk0QGx+Fbxpe/+7mX0N9AQ==
X-Received: by 2002:a05:6808:2f19:b0:3c2:16d5:3d53 with SMTP id gu25-20020a0568082f1900b003c216d53d53mr7521172oib.51.1710522407407;
        Fri, 15 Mar 2024 10:06:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:ac2:b0:690:ee1f:cfe3 with SMTP id
 g2-20020a0562140ac200b00690ee1fcfe3ls3396265qvi.0.-pod-prod-01-us; Fri, 15
 Mar 2024 10:06:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV3SkeZI8JbxkROYj30es5HQgStsk6/9TyOP8/Tf1ZK3UDGPkvprZFHIDuQNMqB3NMGpy3XPjt1K/7kqvWWlNG0KfRiUSnsNG4OpA==
X-Received: by 2002:a05:620a:4594:b0:788:1a86:5428 with SMTP id bp20-20020a05620a459400b007881a865428mr7072827qkb.58.1710522406633;
        Fri, 15 Mar 2024 10:06:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710522406; cv=none;
        d=google.com; s=arc-20160816;
        b=OV7kH/LFXzWvLzNp6AaONEQRaWJl/oDVDkadjUwHmTgliFRlW3z9xzEhmas5DKFE7x
         6l/7lwF7qSb13YwfkrQPbN4AsxkNmv148kyf8EdRJwHcImPRvkoQ+LZTD95ghva3O/q7
         GKl/iVgnOXvyCZmhq+BQnh1VobzcWbBsJ8/3ifR66v6H1l7PytLOSTEY0glGo3ChIzuz
         a6QaWDYyzPCs1bu7zxUyjQ6fafenXzT6Cm00aeUmloSVuNPEkSXcchWpS4r53UaThV0t
         8wOHYJUfnhw5vCXxKOLbdeqKsndj5gwUXFZuX85Ka2Dl9UyWWh2m+f+lKJeItDBsRacp
         U2EQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rC572A3yia7X47ZYtWd+ymj431bX9Z5tiP3vPmrWrg8=;
        fh=GdUrimyw0evPmXXDYTD7MRO+0sysnvXLd3TrgLOFlXc=;
        b=OCOybi6xm1BKxSSpDNWh4e09KVGn/rqCf0XlVqZi/0+UlUzR5N/DiWC/MBP83Q05/K
         0FORc1WlOHTCEnPw+mvhCIe4KEkh7/uUwK41K+nTp3fKiuf3pH9FTOOMTjKFNWCfVgH/
         L2ekqXd7I4yEgHI/owYG4IiCKr4g+7A/f6TvI1GNK8tyxSc4t2TV6Di3LdPwwpo/zFTP
         GIqV8KUwbDAOnfrfJPHY4biu2QJRAkGqvmIc5fWBe+71mIGZPab8ZBrdQCdpdNJDidRh
         wnnGZLtnga0GplNnBjlJOfjbwOWodth+QFIUx4Mn0EA3B4p6EUMQ8ehNVsfSluW0K6wl
         6+6Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="kB/76sSP";
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb31.google.com (mail-yb1-xb31.google.com. [2607:f8b0:4864:20::b31])
        by gmr-mx.google.com with ESMTPS id w6-20020a05620a444600b0078874854642si327288qkp.4.2024.03.15.10.06.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Mar 2024 10:06:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as permitted sender) client-ip=2607:f8b0:4864:20::b31;
Received: by mail-yb1-xb31.google.com with SMTP id 3f1490d57ef6-dc6d8bd618eso2129963276.3
        for <kasan-dev@googlegroups.com>; Fri, 15 Mar 2024 10:06:46 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVi1/cVroPjm1DJcvCzJRhjzjLSGR/tuCYFy/n1Swpy8advMDyd896TKR/n+4CcAfwoNwWd91JnU21uKpYXNBT62Gy/tR7WJnumDg==
X-Received: by 2002:a25:dbca:0:b0:dcc:273e:1613 with SMTP id
 g193-20020a25dbca000000b00dcc273e1613mr5471648ybf.40.1710522405619; Fri, 15
 Mar 2024 10:06:45 -0700 (PDT)
MIME-Version: 1.0
References: <20240306182440.2003814-1-surenb@google.com> <20240306182440.2003814-24-surenb@google.com>
 <1f51ffe8-e5b9-460f-815e-50e3a81c57bf@suse.cz> <CAJuCfpE5mCXiGLHTm1a8PwLXrokexx9=QrrRF4fWVosTh5Q7BA@mail.gmail.com>
 <e6e96b64-01b1-4e23-bb0b-45438f9a6cc4@suse.cz>
In-Reply-To: <e6e96b64-01b1-4e23-bb0b-45438f9a6cc4@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Mar 2024 17:06:32 +0000
Message-ID: <CAJuCfpEsAHSAUP_EFP4yZdyZ1hfVPbQSWn9j-eZQdiRLy5MGYg@mail.gmail.com>
Subject: Re: [PATCH v5 23/37] mm/slab: add allocation accounting into slab
 allocation and free paths
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
	dave.hansen@linux.intel.com, x86@kernel.org, peterx@redhat.com, 
	david@redhat.com, axboe@kernel.dk, mcgrof@kernel.org, masahiroy@kernel.org, 
	nathan@kernel.org, dennis@kernel.org, jhubbard@nvidia.com, tj@kernel.org, 
	muchun.song@linux.dev, rppt@kernel.org, paulmck@kernel.org, 
	pasha.tatashin@soleen.com, yosryahmed@google.com, yuzhao@google.com, 
	dhowells@redhat.com, hughd@google.com, andreyknvl@gmail.com, 
	keescook@chromium.org, ndesaulniers@google.com, vvvvvv@google.com, 
	gregkh@linuxfoundation.org, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, rostedt@goodmis.org, 
	bsegall@google.com, bristot@redhat.com, vschneid@redhat.com, cl@linux.com, 
	penberg@kernel.org, iamjoonsoo.kim@lge.com, 42.hyeyoo@gmail.com, 
	glider@google.com, elver@google.com, dvyukov@google.com, shakeelb@google.com, 
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
 header.i=@google.com header.s=20230601 header.b="kB/76sSP";       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b31 as
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

On Fri, Mar 15, 2024 at 4:52=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 3/15/24 16:43, Suren Baghdasaryan wrote:
> > On Fri, Mar 15, 2024 at 3:58=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> On 3/6/24 19:24, Suren Baghdasaryan wrote:
> >> > Account slab allocations using codetag reference embedded into slabo=
bj_ext.
> >> >
> >> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> >> > Co-developed-by: Kent Overstreet <kent.overstreet@linux.dev>
> >> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> >> > Reviewed-by: Kees Cook <keescook@chromium.org>
> >>
> >> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
> >>
> >> Nit below:
> >>
> >> > @@ -3833,6 +3913,7 @@ void slab_post_alloc_hook(struct kmem_cache *s=
, struct obj_cgroup *objcg,
> >> >                         unsigned int orig_size)
> >> >  {
> >> >       unsigned int zero_size =3D s->object_size;
> >> > +     struct slabobj_ext *obj_exts;
> >> >       bool kasan_init =3D init;
> >> >       size_t i;
> >> >       gfp_t init_flags =3D flags & gfp_allowed_mask;
> >> > @@ -3875,6 +3956,12 @@ void slab_post_alloc_hook(struct kmem_cache *=
s,        struct obj_cgroup *objcg,
> >> >               kmemleak_alloc_recursive(p[i], s->object_size, 1,
> >> >                                        s->flags, init_flags);
> >> >               kmsan_slab_alloc(s, p[i], init_flags);
> >> > +             obj_exts =3D prepare_slab_obj_exts_hook(s, flags, p[i]=
);
> >> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> >> > +             /* obj_exts can be allocated for other reasons */
> >> > +             if (likely(obj_exts) && mem_alloc_profiling_enabled())
>
> Could you at least flip these two checks then so the static key one goes =
first?

Yes, definitely. I was thinking about removing need_slab_obj_ext()
from prepare_slab_obj_exts_hook() and adding this instead of the above
code:

+        if (need_slab_obj_ext()) {
+                obj_exts =3D prepare_slab_obj_exts_hook(s, flags, p[i]);
+#ifdef CONFIG_MEM_ALLOC_PROFILING
+                /*
+                 * Currently obj_exts is used only for allocation
profiling. If other users appear
+                 * then mem_alloc_profiling_enabled() check should be
added here.
+                 */
+                if (likely(obj_exts))
+                        alloc_tag_add(&obj_exts->ref,
current->alloc_tag, s->size);
+#endif
+        }

Does that look good?

> >> > +#ifdef CONFIG_MEM_ALLOC_PROFILING
> >> > +             /* obj_exts can be allocated for other reasons */
> >> > +             if (likely(obj_exts) && mem_alloc_profiling_enabled())
>
> >> > +                     alloc_tag_add(&obj_exts->ref, current->alloc_t=
ag, s->size);
> >> > +#endif
> >>
> >> I think you could still do this a bit better:
> >>
> >> Check mem_alloc_profiling_enabled() once before the whole block callin=
g
> >> prepare_slab_obj_exts_hook() and alloc_tag_add()
> >> Remove need_slab_obj_ext() check from prepare_slab_obj_exts_hook()
> >
> > Agree about checking mem_alloc_profiling_enabled() early and one time,
> > except I would like to use need_slab_obj_ext() instead of
> > mem_alloc_profiling_enabled() for that check. Currently they are
> > equivalent but if there are more slab_obj_ext users in the future then
> > there will be cases when we need to prepare_slab_obj_exts_hook() even
> > when mem_alloc_profiling_enabled()=3D=3Dfalse. need_slab_obj_ext() will=
 be
> > easy to extend for such cases.
>
> I thought we don't generally future-proof internal implementation details
> like this until it's actually needed. But at least what I suggested above
> would help, thanks.
>
> > Thanks,
> > Suren.
> >
> >>
> >> >       }
> >> >
> >> >       memcg_slab_post_alloc_hook(s, objcg, flags, size, p);
> >> > @@ -4353,6 +4440,7 @@ void slab_free(struct kmem_cache *s, struct sl=
ab *slab, void *object,
> >> >              unsigned long addr)
> >> >  {
> >> >       memcg_slab_free_hook(s, slab, &object, 1);
> >> > +     alloc_tagging_slab_free_hook(s, slab, &object, 1);
> >> >
> >> >       if (likely(slab_free_hook(s, object, slab_want_init_on_free(s)=
)))
> >> >               do_slab_free(s, slab, object, object, 1, addr);
> >> > @@ -4363,6 +4451,7 @@ void slab_free_bulk(struct kmem_cache *s, stru=
ct slab *slab, void *head,
> >> >                   void *tail, void **p, int cnt, unsigned long addr)
> >> >  {
> >> >       memcg_slab_free_hook(s, slab, p, cnt);
> >> > +     alloc_tagging_slab_free_hook(s, slab, p, cnt);
> >> >       /*
> >> >        * With KASAN enabled slab_free_freelist_hook modifies the fre=
elist
> >> >        * to remove objects, whose reuse must be delayed.
> >>
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
kasan-dev/CAJuCfpEsAHSAUP_EFP4yZdyZ1hfVPbQSWn9j-eZQdiRLy5MGYg%40mail.gmail.=
com.
