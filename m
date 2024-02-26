Return-Path: <kasan-dev+bncBCC2HSMW4ECBBGGZ6KXAMGQEGXZUYIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id B99C0867A0C
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 16:22:01 +0100 (CET)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3652d6907a1sf30272905ab.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 07:22:01 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708960920; cv=pass;
        d=google.com; s=arc-20160816;
        b=Lm53ZPVspJjGpgYiQW1OJ96ldAV++CczriDC91xar5hXKvGcfNEGnXessgB5tTfO8E
         +L33xMWIFUTVL3zJkIjEm1lsbtblK2Ek6EeHVFyHdCI27/1VC0sqC+QTCoJaf0UTURue
         lwbV1OQ9F5EcV7ZaS+rXsuOkScFEX9Nk+QQIyrxNlHYD2XVXl30wilZ1DmrNFsU2RVd0
         ZuK7Td9phdnINikKzxJY7q63wI+kLK0TCUyW5hmO9S9KcJt5OrKJrgcZomzbvPwSkr5T
         qaKxVB/dcc1SyVhnCQsnVnJD82tTRCwVc59ZBDVFjCjUCqkRvPleD+oXX3YQoPs+RcWu
         rg6w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=tXUTw+8K/wkeL5JjagnbMvkv4lq/BCiIEmHPMUaI3Xo=;
        fh=7UaBboWGPmdoYs6eq0OGJcEWOBMfRYpDR4mdlxvjRrs=;
        b=SYyCXR6b7+vrm1GY5nnSUjiYq4XkQ6oNW4bN++rJQ9TQd7UkFv/ifaY7eABcCjjwNy
         DbfIEDhaFc+QMMCmE2NPMr1C0ZWzdhk9I6HGVG8ubEEilfjn9UKmXHYdgfWUlxTCF+KS
         o4KZlrz7+IPOrY1y8rHg4EgFNrDv0TeQtXP+cl4wV57EgzGomXejNNgt4bClZ2UsyE+G
         /Y6CWrTun7mDFZf5qmOZYsIt+dqpum/jx9UY3ZTyQ+RcsGsy8PODqRDEPhFUaCGVpIue
         SXBgIMAKTwTzTVtkOZqXWbgALRMK7Zx81vO2ZRQbAJgmC9uUAP7eVWy6BOmAi7WmzBV0
         p4mw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b="ll/pdzRo";
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708960920; x=1709565720; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=tXUTw+8K/wkeL5JjagnbMvkv4lq/BCiIEmHPMUaI3Xo=;
        b=Mj0OU4njgW9xxvl9rXm5vq8L8YpSjrlRi8mKTwFFLc4NlpGWAclH1Ii8c8hF9ZHmUc
         Ora5MLrAcyyGh24HTBQe48Ua6p9KZ6gLDsTLPvklFWJjGrtTO7jdBFh5aU7y3GEeYIzr
         aSdImCZ+wuDC+kTa2NIwCHA2LfiHgRC0JnP1midndK0LUeqsaoHackp5wqhTT/7qQCPE
         eMAwIqeJI8vduEJhSotefNnL7R/VVsaWU729HmZuz4QKQEg1pUwCb1y6UgQC1jy4tfAc
         uU5xmlVeVB8wsG9JGE+RJ0IbR7cCe0TorZx9TBRBlYOPWj4ChhMmeO/nMCClffLtvkra
         XeeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708960920; x=1709565720;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=tXUTw+8K/wkeL5JjagnbMvkv4lq/BCiIEmHPMUaI3Xo=;
        b=v49SSMNk8Di3eNj2TuKLr8xGaRxDeLFVluvCeMLEwNnsjzCVqOYtPbGgySp2JPAU87
         C+nRsljawCifPbXlRwkxyV9iESGjBIKo1WaMmQBhhkU42z9PVWDp8fz5B5BU3h0CNFNG
         nf+zJhL9/S0rggE+AN0mEWUXgH5qEJc7dU0ldrAT9wjfvWdwgfzJahj0xF4PSadpANJv
         Y8Mx/XF25IkuuS8OfvuPL0QYXgd3rlhnwwhhaGZdl9xo/BqMwxFEQpYlA8/ZeDIDPDpB
         XBuIIipN1vrmZbcb0Xi76VKAzGVrKx3PUan8cFkwyG68/0MTukrlOEB7WYanFOWm1ing
         WQQA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUmg2RMhN4fN3bYnHlipVyq6Ph/2mMDSTYQRJoafQ/d2pE8Ewqo7erVR6sPNtO07OxaRqXq+yTrctJkYgZetftWiqvXwaM4aA==
X-Gm-Message-State: AOJu0YzfNcZhQfd+AfPFwwC6YQgzhYvyYuo2hI//S4LjCJ95jZatSmUc
	zeyieRUvtBMrGapnE9MIl/eBCiW0rkXt/optNiJp4NdNZR8g3Isb
X-Google-Smtp-Source: AGHT+IESe3XLRjU7QlijTsd/KN15NAbx6QJaAQDP4xZjdtTZXM2g/8tNAcAZekEMealJU6nAUxDyug==
X-Received: by 2002:a05:6e02:b28:b0:365:55fb:9944 with SMTP id e8-20020a056e020b2800b0036555fb9944mr8244111ilu.4.1708960920361;
        Mon, 26 Feb 2024 07:22:00 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:d192:0:b0:363:d865:fa3 with SMTP id z18-20020a92d192000000b00363d8650fa3ls1980283ilz.2.-pod-prod-01-us;
 Mon, 26 Feb 2024 07:21:59 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWXpyUZTYghtwZzmYk/E2Zx58gcXv5/48MSlA+Op76LuvdJ896WSyfw2WLYr72pPfuGaIs4I/j8emUxhElAoKkqm6Cl8ucJVJ6PRw==
X-Received: by 2002:a5e:aa10:0:b0:7c7:97e5:463d with SMTP id s16-20020a5eaa10000000b007c797e5463dmr8983258ioe.18.1708960919337;
        Mon, 26 Feb 2024 07:21:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708960919; cv=none;
        d=google.com; s=arc-20160816;
        b=AB1rD9eFVaUFaA2L2diji3gqXCg5KvuOBMA460eqysfiyCerKi8D5pm1UtmISbA4QU
         mgfm5zcV6nh/euUBsvTRhc4OnOlds885b4VxDFcdShaVV6bwxK8RUPCIL5xSYVHqxVXv
         Xf5QKz4W7Y+h6L/zesIdkOM5lBwFwlSbAZo9ZywKz9MlYlwl4yMxcBQ9ZOvzSAbG6LcO
         I1Cqus71mQbA76Z+/VoHVobb4eL4SV+Mb1+1Q6OKfrS5JogKTtrj+/LEiLOLripdmKoh
         5gWMzy88pp8TGx/WqcdkFql1bOl5MIIddl3jFjaDQvZPzuybSSdQGLnbFK95do0pn2JU
         tq9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=+YAsFvK90oUcyunlKypP0cgUIeYQWof3rSlBEnKwPsU=;
        fh=wu6H0Ly3lPD2woTYW7UYn7fFrSomIlCXqLn0uXZw2qU=;
        b=b6LlDOwmUBlR9JmuxqnAQD3YXGwLJOA+L7UyYUCVOxFrs867kWZDAXfZ0xvBD/GTDF
         KEgAd0U3KypjUI5P58Ibk0BZL6h+Xq8KtosnCx0DJgJS9+dS4UNDcVDiB8c5hYVY58sw
         G92I8SpFiRtBQcfoO62KO27r283s/tBOOJqsRjlFMTqih/uU/t2+mJ+pHPLvsf3JpLhO
         2t8JLf3sK5FtasEpj+MZrKfjK+udnh3w/dM2yFgYzQZna1FIt8v9BWMwQuDIerFZzS5X
         D5sJnqzUX6uOAYFlqKNAIc+ii6r+P5WF0U6A1A0tQdXiHWYHnuz65Wpz4USBHpZ8vni0
         PwFw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601 header.b="ll/pdzRo";
       spf=pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::833 as permitted sender) smtp.mailfrom=pasha.tatashin@soleen.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=soleen.com
Received: from mail-qt1-x833.google.com (mail-qt1-x833.google.com. [2607:f8b0:4864:20::833])
        by gmr-mx.google.com with ESMTPS id y138-20020a6bc890000000b007c7588a9f61si633102iof.4.2024.02.26.07.21.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Feb 2024 07:21:59 -0800 (PST)
Received-SPF: pass (google.com: domain of pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::833 as permitted sender) client-ip=2607:f8b0:4864:20::833;
Received: by mail-qt1-x833.google.com with SMTP id d75a77b69052e-42a029c8e76so25377791cf.2
        for <kasan-dev@googlegroups.com>; Mon, 26 Feb 2024 07:21:59 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVFQI94PoQZJ7xvOwM9OGE4dsVjsCZxHDbD3NPj/mFnMklu0fV2ySEDOvqz+31Y6gO9Ot2tH60tsNNgTDdonz7w0FzW/0EVqVzFsA==
X-Received: by 2002:a05:622a:1354:b0:42e:8b5c:fd01 with SMTP id
 w20-20020a05622a135400b0042e8b5cfd01mr1779068qtk.54.1708960918671; Mon, 26
 Feb 2024 07:21:58 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-4-surenb@google.com>
 <CA+CK2bD8Cr1V2=PWAsf6CwDnakZ54Qaf_q5t4aVYV-jXQPtPbg@mail.gmail.com>
 <CAJuCfpHBgZeJN_O1ZQg_oLbAXc-Y+jmUpB02jznkEySpd4rzvw@mail.gmail.com> <d8a7ed49-f7d1-44bf-b0e5-64969e816057@suse.cz>
In-Reply-To: <d8a7ed49-f7d1-44bf-b0e5-64969e816057@suse.cz>
From: Pasha Tatashin <pasha.tatashin@soleen.com>
Date: Mon, 26 Feb 2024 10:21:47 -0500
Message-ID: <CA+CK2bBggtq6M96Pu49BmG_j01Sv6p_84Go++9APuvVPXHMwvQ@mail.gmail.com>
Subject: Re: [PATCH v4 03/36] mm/slub: Mark slab_free_freelist_hook() __always_inline
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Suren Baghdasaryan <surenb@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
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
Content-Type: multipart/alternative; boundary="0000000000007e237a06124a7861"
X-Original-Sender: pasha.tatashin@soleen.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@soleen-com.20230601.gappssmtp.com header.s=20230601
 header.b="ll/pdzRo";       spf=pass (google.com: domain of
 pasha.tatashin@soleen.com designates 2607:f8b0:4864:20::833 as permitted
 sender) smtp.mailfrom=pasha.tatashin@soleen.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=soleen.com
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

--0000000000007e237a06124a7861
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Mon, Feb 26, 2024, 9:31=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wrot=
e:

> On 2/24/24 03:02, Suren Baghdasaryan wrote:
> > On Wed, Feb 21, 2024 at 1:16=E2=80=AFPM Pasha Tatashin
> > <pasha.tatashin@soleen.com> wrote:
> >>
> >> On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan <surenb@goo=
gle.com>
> wrote:
> >> >
> >> > From: Kent Overstreet <kent.overstreet@linux.dev>
> >> >
> >> > It seems we need to be more forceful with the compiler on this one.
> >> > This is done for performance reasons only.
> >> >
> >> > Signed-off-by: Kent Overstreet <kent.overstreet@linux.dev>
> >> > Signed-off-by: Suren Baghdasaryan <surenb@google.com>
> >> > Reviewed-by: Kees Cook <keescook@chromium.org>
> >> > ---
> >> >  mm/slub.c | 2 +-
> >> >  1 file changed, 1 insertion(+), 1 deletion(-)
> >> >
> >> > diff --git a/mm/slub.c b/mm/slub.c
> >> > index 2ef88bbf56a3..d31b03a8d9d5 100644
> >> > --- a/mm/slub.c
> >> > +++ b/mm/slub.c
> >> > @@ -2121,7 +2121,7 @@ bool slab_free_hook(struct kmem_cache *s, void
> *x, bool init)
> >> >         return !kasan_slab_free(s, x, init);
> >> >  }
> >> >
> >> > -static inline bool slab_free_freelist_hook(struct kmem_cache *s,
> >> > +static __always_inline bool slab_free_freelist_hook(struct
> kmem_cache *s,
> >>
> >> __fastpath_inline seems to me more appropriate here. It prioritizes
> >> memory vs performance.
> >
> > Hmm. AFAIKT this function is used only in one place and we do not add
> > any additional users, so I don't think changing to __fastpath_inline
> > here would gain us anything.
>

For consistency __fastpath_inline makes more sense, but I am ok with or
without this change.

Reviewed-by: Pasha Tatashin <pasha.tatashin@soleen.com>


> It would have been more future-proof and self-documenting. But I don't
> insist.
>
> Reviewed-by: Vlastimil Babka <vbabka@suse.cz>
>
> >>
> >> >                                            void **head, void **tail,
> >> >                                            int *cnt)
> >> >  {
> >> > --
> >> > 2.44.0.rc0.258.g7320e95886-goog
> >> >
>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BCK2bBggtq6M96Pu49BmG_j01Sv6p_84Go%2B%2B9APuvVPXHMwvQ%40mail.=
gmail.com.

--0000000000007e237a06124a7861
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"><div><br><br><div class=3D"gmail_quote"><div dir=3D"ltr" =
class=3D"gmail_attr">On Mon, Feb 26, 2024, 9:31=E2=80=AFAM Vlastimil Babka =
&lt;<a href=3D"mailto:vbabka@suse.cz">vbabka@suse.cz</a>&gt; wrote:<br></di=
v><blockquote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-left:=
1px #ccc solid;padding-left:1ex">On 2/24/24 03:02, Suren Baghdasaryan wrote=
:<br>
&gt; On Wed, Feb 21, 2024 at 1:16=E2=80=AFPM Pasha Tatashin<br>
&gt; &lt;<a href=3D"mailto:pasha.tatashin@soleen.com" target=3D"_blank" rel=
=3D"noreferrer">pasha.tatashin@soleen.com</a>&gt; wrote:<br>
&gt;&gt;<br>
&gt;&gt; On Wed, Feb 21, 2024 at 2:41=E2=80=AFPM Suren Baghdasaryan &lt;<a =
href=3D"mailto:surenb@google.com" target=3D"_blank" rel=3D"noreferrer">sure=
nb@google.com</a>&gt; wrote:<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; From: Kent Overstreet &lt;<a href=3D"mailto:kent.overstreet@l=
inux.dev" target=3D"_blank" rel=3D"noreferrer">kent.overstreet@linux.dev</a=
>&gt;<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; It seems we need to be more forceful with the compiler on thi=
s one.<br>
&gt;&gt; &gt; This is done for performance reasons only.<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; Signed-off-by: Kent Overstreet &lt;<a href=3D"mailto:kent.ove=
rstreet@linux.dev" target=3D"_blank" rel=3D"noreferrer">kent.overstreet@lin=
ux.dev</a>&gt;<br>
&gt;&gt; &gt; Signed-off-by: Suren Baghdasaryan &lt;<a href=3D"mailto:suren=
b@google.com" target=3D"_blank" rel=3D"noreferrer">surenb@google.com</a>&gt=
;<br>
&gt;&gt; &gt; Reviewed-by: Kees Cook &lt;<a href=3D"mailto:keescook@chromiu=
m.org" target=3D"_blank" rel=3D"noreferrer">keescook@chromium.org</a>&gt;<b=
r>
&gt;&gt; &gt; ---<br>
&gt;&gt; &gt;=C2=A0 mm/slub.c | 2 +-<br>
&gt;&gt; &gt;=C2=A0 1 file changed, 1 insertion(+), 1 deletion(-)<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; diff --git a/mm/slub.c b/mm/slub.c<br>
&gt;&gt; &gt; index 2ef88bbf56a3..d31b03a8d9d5 100644<br>
&gt;&gt; &gt; --- a/mm/slub.c<br>
&gt;&gt; &gt; +++ b/mm/slub.c<br>
&gt;&gt; &gt; @@ -2121,7 +2121,7 @@ bool slab_free_hook(struct kmem_cache *=
s, void *x, bool init)<br>
&gt;&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0return !kasan_slab_free(s, x=
, init);<br>
&gt;&gt; &gt;=C2=A0 }<br>
&gt;&gt; &gt;<br>
&gt;&gt; &gt; -static inline bool slab_free_freelist_hook(struct kmem_cache=
 *s,<br>
&gt;&gt; &gt; +static __always_inline bool slab_free_freelist_hook(struct k=
mem_cache *s,<br>
&gt;&gt;<br>
&gt;&gt; __fastpath_inline seems to me more appropriate here. It prioritize=
s<br>
&gt;&gt; memory vs performance.<br>
&gt; <br>
&gt; Hmm. AFAIKT this function is used only in one place and we do not add<=
br>
&gt; any additional users, so I don&#39;t think changing to __fastpath_inli=
ne<br>
&gt; here would gain us anything.<br></blockquote></div></div><div dir=3D"a=
uto"><br></div><div dir=3D"auto">For consistency __fastpath_inline makes mo=
re sense, but I am ok with or without this change.</div><div dir=3D"auto"><=
br></div><div dir=3D"auto">Reviewed-by: Pasha Tatashin &lt;<a href=3D"mailt=
o:pasha.tatashin@soleen.com">pasha.tatashin@soleen.com</a>&gt;<br></div><di=
v dir=3D"auto"><br></div><div dir=3D"auto"><div class=3D"gmail_quote"><bloc=
kquote class=3D"gmail_quote" style=3D"margin:0 0 0 .8ex;border-left:1px #cc=
c solid;padding-left:1ex">
<br>
It would have been more future-proof and self-documenting. But I don&#39;t =
insist.<br>
<br>
Reviewed-by: Vlastimil Babka &lt;<a href=3D"mailto:vbabka@suse.cz" target=
=3D"_blank" rel=3D"noreferrer">vbabka@suse.cz</a>&gt;<br>
<br>
&gt;&gt;<br>
&gt;&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 void **head, void **tail,<br>
&gt;&gt; &gt;=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0=
 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=
=A0 =C2=A0 =C2=A0 int *cnt)<br>
&gt;&gt; &gt;=C2=A0 {<br>
&gt;&gt; &gt; --<br>
&gt;&gt; &gt; 2.44.0.rc0.258.g7320e95886-goog<br>
&gt;&gt; &gt;<br>
<br>
</blockquote></div></div></div>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion on the web visit <a href=3D"https://groups.google.c=
om/d/msgid/kasan-dev/CA%2BCK2bBggtq6M96Pu49BmG_j01Sv6p_84Go%2B%2B9APuvVPXHM=
wvQ%40mail.gmail.com?utm_medium=3Demail&utm_source=3Dfooter">https://groups=
.google.com/d/msgid/kasan-dev/CA%2BCK2bBggtq6M96Pu49BmG_j01Sv6p_84Go%2B%2B9=
APuvVPXHMwvQ%40mail.gmail.com</a>.<br />

--0000000000007e237a06124a7861--
