Return-Path: <kasan-dev+bncBC7OD3FKWUERBU7P6KXAMGQEKNVDNIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id AD447867B33
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 17:09:57 +0100 (CET)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-7bad62322f0sf338354739f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 08:09:57 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708963796; cv=pass;
        d=google.com; s=arc-20160816;
        b=cCV0yS2AvAu7EtXMHzc20I7LcT0q7P6FgC9ZOMvL4mk2/aOArlZZOsYVpmX/2nmc+Q
         fXDsFJE7WvGD4nFZ8xNzyLKnsNZnymdCKCW1zSNaTYf76YBSuwyKoqrZXoNROFL9j5rv
         i4ERsGclVmbcmZ420RbL2GcxM4+nJpQY1dwtZT7s30Qaep/C/gIBftBap1tM9+A8nZ0K
         vEXmPUt1bluW3PUDBJC4UxSjhr6R10gKMaxBM5FcLUd8vlPGZaInjJh0IhlrZrvGdqWS
         443VU+tr7euRFx6A6MJ3bT9fzsfe/Ay2k0er2drXuS1g2HJYNwgQNL4sjPTWa0tSgmes
         2+oA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=k1yilIT/CF3uHTaeFiV9Y21XvX7npQ8IJ9P+eiUarC4=;
        fh=eDjbMxNMnJWmhaoe/2auscL3JvsDH9jSIYGVJEzBPqg=;
        b=xiEEfKout+rf4nWeY7P3O/suZC5+YU+WLtsr0AdVUgnRJw5CTbVgr1vQZ318b38KFa
         7UvZ6rmOChx1+TwRteV+GCb4JBfvb5Be9KPaxw+wG4XEM3ZtDW17WNYl6zF25qW/dY6j
         vPj0djf/eXl3wsC/UtARsikxYPOKB2aUVCKmUMD28wK0GpxOlIESUe6gXjty4avrdYuC
         rC7/Q7cf0+bBepxu6jdk5mh3Z0R2m/tG1l92jOdq0BRpLrJtPzeii/B+1DCH3QfGwdET
         gKsHpWDPqQyNZwCym9++P5/Y/ApmzL7ajM6AfdjJK246nXZqXzBZMAMFlJ+QuJx3j561
         HNfQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=N3WJI0Az;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708963796; x=1709568596; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=k1yilIT/CF3uHTaeFiV9Y21XvX7npQ8IJ9P+eiUarC4=;
        b=Qm7O4b9yUuurp/suVnTjcpb7ztNVJdnW6/2r/pE9BAinEMyv4fJ+YsooPWAoGHBZvQ
         2Zq9H5pxyPouFABO3qaZGmRcERsN/SfDG7aeHKQMw5rtiZ0Kd87cwuMYztFelS4b9FXQ
         1p3w6OUGCaeKcv+nBWOAwCxA91/B3B0kN1fLN+gN6jc9ke9HI5U3P6pTPMkYgNy1Abu8
         5brnFUpJR5shejNoYhnbPL3xK57jloaMpGzpcnnBZFQvssBNGOvAdnHwm0ALzWhVLwnG
         URK4Fs7ybNVXS8CRCHNwUEETKk1TJT7+pAa3firspMmAzjO86WGf9fd8ytsLBGf7F2QN
         nj0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708963796; x=1709568596;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=k1yilIT/CF3uHTaeFiV9Y21XvX7npQ8IJ9P+eiUarC4=;
        b=hAxR7Wb7f/Rc3nznJu9e/DrvApTgO/1abAvA2/sKuAdJDA/Ee+Db0Bqz5DLqfn6yFv
         tmaAwPywxwT5MNPOFu8yQ1idW2C2Q36M3tHrU6LIg2XK/DWYasf9oHr7tTlNcEFN0q9J
         +7vTZGTXZDkRhn26/E1YOuuvWcQUD/kjL5iWcelEM4qvkJB6gVoEJEA6cRmp0JbDUH/U
         JNLNo4kmFq/M30VzQsGEZLbYj4h/EgehgiOHHx63xXVcjCk9LqDjfC6vd+1Qw5nw9ctX
         RucTGPlnqhatx6E8xTtemfJgcWgjk6yjr39eejV7QC9885x4G6MyRRMz36O+Fo7zUgas
         Of0A==
X-Forwarded-Encrypted: i=2; AJvYcCWJWLKpiC9Go2JeKTYDWHPFHMkvFnS1e+0xwA61w15ceSB9gfgDMFBqBkyEjhtBxH59JfZvfoe0KQY88Xa5hSj/RRud1qn9+w==
X-Gm-Message-State: AOJu0YwBNb+5Geqz7qFKIihPq6Cj/+o77AwraM+DbCps5ptvW4AeZYU4
	LUELKjrkoTnZ/9addQVFXid9QN3yUqr3ZFsKm72Pk4DxzXDvstSk
X-Google-Smtp-Source: AGHT+IG8JubXMdC+Hq2XPsYXazCm50Z9unM3EDhYzyP3j58oHPoW4KifG/e97QFhyzxKIu06ZOzFCw==
X-Received: by 2002:a05:6e02:e10:b0:365:1b7c:670 with SMTP id a16-20020a056e020e1000b003651b7c0670mr6097923ilk.8.1708963795948;
        Mon, 26 Feb 2024 08:09:55 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:c14c:0:b0:363:d634:895a with SMTP id b12-20020a92c14c000000b00363d634895als1731312ilh.2.-pod-prod-03-us;
 Mon, 26 Feb 2024 08:09:54 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCX36ypRpnF6yaGc/Ii1tqLl+D/FlV82E5Kn/dxsdzwWbLDpwyDkcV4jk1McTav+x63QaH4xhULF0CCiJBfwl8u93xFPxWf4M1V6+A==
X-Received: by 2002:a05:6e02:92e:b0:365:24c1:c996 with SMTP id o14-20020a056e02092e00b0036524c1c996mr6589423ilt.19.1708963794701;
        Mon, 26 Feb 2024 08:09:54 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708963794; cv=none;
        d=google.com; s=arc-20160816;
        b=eDwUZ9iwVVfBOvj6eB8RpHFihcq33IZ9cw3e1OUbm/q8uQkCNFT0O5gC4mFO+0C/Cw
         F8G8O8eVyeoQivX05u/+resAwBKPo2m0mZIJlnJdd59EZUVwEl4xjQuwD5dCXXDK3HlW
         WV9uDFaAAdL6Mf/wrvqoHX3RAtbtSpOADveJiLH3AC7K9CF7ffXHMvLbJzlW7Nzsido1
         D8IcvBGtlW4cy9ghlrTfqkiGDRmRmMRL/t+las7VNcDjsvH62h2XyA+9IE2shazfgZG9
         4qPIxczSsdast0YJ7MpfgqJXFxbwoe5+SwvPu0ZghCMMD5tSXRXTfauDaAm4Dd/vmHrW
         7QtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Q2i9nu0Yj7jZAbH4EMUTPvr2EXed0SrW18ZEoR5sBFQ=;
        fh=pmkzW1jQp3y9gXfKZmvjfaA8WisqbJKVQjTROQOg4fY=;
        b=UvN0T3Rx98q1J5KDvvFxW9Uvm1ovflT8lnW2dwdju5fMp9UvfcVLR2e4VKnaI4R15Q
         w0WLBQoHUDeBacpC/6r4wFirHa9yfpfYmcOK/SqRpJLtMXi/u3nVlySdl2c85AYuZTix
         phiNMp2NU/JXi80+rZF+kpvbK9U3lCrf3TnJ2PXIddPcuymHnjm8/E+1CXWMc0uR/DgV
         SPeKUuYp0r+XSAPphkGh1DzJq7QPZQsVvPownR5Lpi4ODBOrcA9qNvcFGhvcytmYYVh9
         qyU7q0Eik1smzRR65sD1HAcdviOkteT1dHTgIglx3eHSvdXy7CZyjACTQkQgZe/pOfEd
         7/tg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=N3WJI0Az;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb32.google.com (mail-yb1-xb32.google.com. [2607:f8b0:4864:20::b32])
        by gmr-mx.google.com with ESMTPS id c14-20020a92b74e000000b0036427ee7bbcsi453875ilm.2.2024.02.26.08.09.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Feb 2024 08:09:54 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as permitted sender) client-ip=2607:f8b0:4864:20::b32;
Received: by mail-yb1-xb32.google.com with SMTP id 3f1490d57ef6-d9b9adaf291so3025655276.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Feb 2024 08:09:54 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVJipf3T+4lpWj4w2DSYjaL7frkSYzKb++j/lg0hrww2WTnIjzYZq4qOYxycoIatf9WD1xcjYWLqFZ0Po0taioH9VdCBq3NhyBKHg==
X-Received: by 2002:a25:ef4a:0:b0:dcd:3575:db79 with SMTP id
 w10-20020a25ef4a000000b00dcd3575db79mr4289171ybm.6.1708963793723; Mon, 26 Feb
 2024 08:09:53 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-4-surenb@google.com>
 <CA+CK2bD8Cr1V2=PWAsf6CwDnakZ54Qaf_q5t4aVYV-jXQPtPbg@mail.gmail.com>
 <CAJuCfpHBgZeJN_O1ZQg_oLbAXc-Y+jmUpB02jznkEySpd4rzvw@mail.gmail.com>
 <d8a7ed49-f7d1-44bf-b0e5-64969e816057@suse.cz> <CA+CK2bBggtq6M96Pu49BmG_j01Sv6p_84Go++9APuvVPXHMwvQ@mail.gmail.com>
In-Reply-To: <CA+CK2bBggtq6M96Pu49BmG_j01Sv6p_84Go++9APuvVPXHMwvQ@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Feb 2024 08:09:40 -0800
Message-ID: <CAJuCfpE_=A3H+FKwHeu-XLX5rDCqrV8dUT40=EVm4w_q8A=EwQ@mail.gmail.com>
Subject: Re: [PATCH v4 03/36] mm/slub: Mark slab_free_freelist_hook() __always_inline
To: Pasha Tatashin <pasha.tatashin@soleen.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, Andrew Morton <akpm@linux-foundation.org>, 
	Kent Overstreet <kent.overstreet@linux.dev>, Michal Hocko <mhocko@suse.com>, 
	Johannes Weiner <hannes@cmpxchg.org>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Mel Gorman <mgorman@suse.de>, dave@stgolabs.net, Matthew Wilcox <willy@infradead.org>, 
	"Liam R. Howlett" <liam.howlett@oracle.com>, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	Jonathan Corbet <corbet@lwn.net>, void@manifault.com, Peter Zijlstra <peterz@infradead.org>, 
	Juri Lelli <juri.lelli@redhat.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Thomas Gleixner <tglx@linutronix.de>, 
	Ingo Molnar <mingo@redhat.com>, Dave Hansen <dave.hansen@linux.intel.com>, 
	"maintainer:X86 ARCHITECTURE (32-BIT AND 64-BIT)" <x86@kernel.org>, Peter Xu <peterx@redhat.com>, David Hildenbrand <david@redhat.com>, 
	Jens Axboe <axboe@kernel.dk>, mcgrof@kernel.org, Masahiro Yamada <masahiroy@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, dennis@kernel.org, Tejun Heo <tj@kernel.org>, 
	Muchun Song <muchun.song@linux.dev>, Mike Rapoport <rppt@kernel.org>, paulmck@kernel.org, 
	Yosry Ahmed <yosryahmed@google.com>, Yu Zhao <yuzhao@google.com>, dhowells@redhat.com, 
	Hugh Dickins <hughd@google.com>, andreyknvl@gmail.com, Kees Cook <keescook@chromium.org>, 
	ndesaulniers@google.com, vvvvvv@google.com, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, ebiggers@google.com, ytcoode@gmail.com, 
	vincent.guittot@linaro.org, dietmar.eggemann@arm.com, 
	Steven Rostedt <rostedt@goodmis.org>, bsegall@google.com, bristot@redhat.com, 
	vschneid@redhat.com, Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	Alexander Potapenko <glider@google.com>, elver@google.com, dvyukov@google.com, 
	Shakeel Butt <shakeelb@google.com>, Muchun Song <songmuchun@bytedance.com>, jbaron@akamai.com, 
	David Rientjes <rientjes@google.com>, minchan@google.com, kaleshsingh@google.com, 
	kernel-team@android.com, Linux Doc Mailing List <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, iommu@lists.linux.dev, 
	"open list:GENERIC INCLUDE/ASM HEADER FILES" <linux-arch@vger.kernel.org>, linux-fsdevel <linux-fsdevel@vger.kernel.org>, 
	linux-mm <linux-mm@kvack.org>, linux-modules@vger.kernel.org, 
	kasan-dev@googlegroups.com, cgroups@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=N3WJI0Az;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::b32 as
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

On Mon, Feb 26, 2024 at 7:21=E2=80=AFAM Pasha Tatashin
<pasha.tatashin@soleen.com> wrote:
>
>
>
> On Mon, Feb 26, 2024, 9:31=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>>
>> On 2/24/24 03:02, Suren Baghdasaryan wrote:
>> > On Wed, Feb 21, 2024 at 1:16=E2=80=AFPM Pasha Tatashin
>> > <pasha.tatashin@soleen.com> wrote:
>> >>
>> >> On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan <surenb@go=
ogle.com> wrote:
>> >> >
>> >> > From: Kent Overstreet <kent.overstreet@linux.dev>
>> >> >
>> >> > It seems we need to be more forceful with the compiler on this one.
>> >> > This is done for performance reasons only.
>> >> >
>> >> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
>> >> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
>> >> > Reviewed-by: Kees Cook <keescook@chromium.org>
>> >> > ---
>> >> >  mm/slub.c | 2 +-
>> >> >  1 file changed, 1 insertion(+), 1 deletion(-)
>> >> >
>> >> > diff --git a/mm/slub.c b/mm/slub.c
>> >> > index 2ef88bbf56a3..d31b03a8d9d5 100644
>> >> > --- a/mm/slub.c
>> >> > +++ b/mm/slub.c
>> >> > @@ -2121,7 +2121,7 @@ bool slab_free_hook(struct kmem_cache *s, voi=
d *x, bool init)
>> >> >         return !kasan_slab_free(s, x, init);
>> >> >  }
>> >> >
>> >> > -static inline bool slab_free_freelist_hook(struct kmem_cache *s,
>> >> > +static __always_inline bool slab_free_freelist_hook(struct kmem_ca=
che *s,
>> >>
>> >> __fastpath_inline seems to me more appropriate here. It prioritizes
>> >> memory vs performance.
>> >
>> > Hmm. AFAIKT this function is used only in one place and we do not add
>> > any additional users, so I don't think changing to __fastpath_inline
>> > here would gain us anything.
>
>
> For consistency __fastpath_inline makes more sense, but I am ok with or w=
ithout this change.

Ok, I'll update in the next revision. Thanks!

>
> Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>
>
>>
>> It would have been more future-proof and self-documenting. But I don't i=
nsist.
>>
>> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
>>
>> >>
>> >> >                                            void **head, void **tail=
,
>> >> >                                            int *cnt)
>> >> >  {
>> >> > --
>> >> > 2.44.0.rc0.258.g7320e95886-goog
>> >> >
>>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAJuCfpE_%3DA3H%2BFKwHeu-XLX5rDCqrV8dUT40%3DEVm4w_q8A%3DEwQ%40mai=
l.gmail.com.
