Return-Path: <kasan-dev+bncBC7OD3FKWUERBSP37WXAMGQEVJRGV6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 18D0686B745
	for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 19:39:08 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id 006d021491bc7-5a0312e60fbsf41172eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 28 Feb 2024 10:39:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1709145547; cv=pass;
        d=google.com; s=arc-20160816;
        b=qMLKYrhcPvChs2ME0Q/obEjTrZ/7nesViOGeQy8yD7mhCCXaHurDt3nZgEwpmaQluQ
         EfIwOnZu6JxeMlxgV1LzAM1KrOxC7ynOMxBTymeID1+jxGmL2/fE8ZW9qNS8TNDl9Cj/
         YMYoBz5fkaf45CI68kB3gmC7aDg5D798kW5x7iFN0rakfF5dBve4fI5RAaiIEdC4eRE6
         0EszhYh1tn1Bmnoyv3x8qhv7SzGPN1m/vwljFaJcUUddLVXIDNqEpi6yZEHoE9nS5T+b
         fG4QL1kUJIeTWv4LiX0V3f5owQbVI1oF4CRLo7mNiDBEnAepZF+3/ZcGPzBYI9VBHW7v
         kq8A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=b3YCl9rn+KBZBIOAMbO7LvHOcthmE8HfiOB+lIBiGb8=;
        fh=TIspwpqq56IBiiib/cJUrXDGu/cxTs3rzUiPmwAIqI0=;
        b=ylfgsLCvLcsjCtp0AU4byofVet7tzs1tN6F/UmjsB/C1fF0zUnOJJ25+wGUvGX6Lpa
         MjSc8FCKsskIySBRVcTVTMASfG7LuDa2gtCnSknpia3uwiiMUZtHkGfznzG+xPd5/9yq
         qe983wUyCHNWUuHwrNW3BuWgrtSQLA6wdcAqszPXl5ykYrK/OIEn9YPw0ZzFrbBJeO2/
         M1jQyo/adDbjllW5lIklpgzSNhiQ5VDNSz6SY7IyGVWiy4HISgasE8/l3jJI5I8Srb8z
         gvkxhU+nOqVAILWV5Mb2G23H5TTNh4/pWxMbr+iIDqVnJlqeM5J2mO6Ah7Hyr53BqvvZ
         oNMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HoGNwYyz;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1709145547; x=1709750347; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=b3YCl9rn+KBZBIOAMbO7LvHOcthmE8HfiOB+lIBiGb8=;
        b=FJ5UCbZf7DkD4K4JdAD/M//Jlk+wWbMz37d2j82rbTt0qnp01l30UduxQIjJchYGBb
         I8mXP4Vb45Ll2SWTSkdTtO3TnWtJJGU8Kzl2nqZRF3rwdxH7g80vM0Dgf2PhqgiYLHnP
         uoj5FfTvX0Nhg9KLXW+xNpsTrGxbq3ZnAmJ/75s+nzFYqvuWZyctdkUcQ07otE3rtsKK
         Fi9+7fJ0KGBbxVSWTKkeYDFIMmoHlESSKrN68dDCvBQ0sQhmTKIGHv283/Yn+OqjcwbT
         Ipl7jls9+s/T/mrnFYZGv8dekCoQtlBuglFImv+eOWPo/o/Rm34gLeRlz7CJp7lXBHDZ
         G3FQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1709145547; x=1709750347;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=b3YCl9rn+KBZBIOAMbO7LvHOcthmE8HfiOB+lIBiGb8=;
        b=PvyfmHOceOKNf44Vh9dw1q5BkBUik+Pa/mO2ZiZjtZ8DkpiLyWV5prNw2WH2y4aN0J
         gxH89drXNDxP9+g4NZwx8TQ6xOVSvGN/LA4+zCoGC1CjKf/su32+dxdFLAS3DX/qVqS1
         vuCIYAV4Jqoi5nNcCFITT3zy+Q32WSFFjMdNBrWeORtEjs0OtkRrbCr+nbHRV3WvjC4p
         VF/ekiggCf2xCK3A8gagCu7jSSd25/Ax+R6y7ufMQlXzcHP0KwK+ZGQPQfR6kX0p8DGL
         EmAh6GO+lBQnaBH/Pgn81wc8y9dQRebydWYUykJhVYD3aHrneaw6NL8MFuzv3/s40p4p
         hk2g==
X-Forwarded-Encrypted: i=2; AJvYcCUwDn5Yk+OrpBQkmUuaRD1ZrNKPWzAhVcuH1KXmsRZFhYqzBpGldY/I4mjxnXfSfBnxfLqRn+5T9nnJrb/XoswBliyjpsPjOA==
X-Gm-Message-State: AOJu0YwfkSirrZF1ySQmiM3BISG2aUwAEVMvniQq68RYoJmfL2e9MdDz
	VDfVPAGt1dzRuQMzlhmyiqnJcVLHfou2e0BzpeAVi+Ci/29UHjV6
X-Google-Smtp-Source: AGHT+IF7mOYmA9/boewQvftlyh3jXBNzt+GBuq4cZPXcDwlPB2rDJ1490KGsE5q4/Vj3r8pH9JjNnw==
X-Received: by 2002:a4a:351c:0:b0:5a0:539:7c98 with SMTP id l28-20020a4a351c000000b005a005397c98mr487706ooa.1.1709145545371;
        Wed, 28 Feb 2024 10:39:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:55d4:0:b0:5a0:3850:af20 with SMTP id e203-20020a4a55d4000000b005a03850af20ls123544oob.2.-pod-prod-03-us;
 Wed, 28 Feb 2024 10:39:04 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXGLNU1xKp3L5V0kn77bIzKt/man9IXPFfEjEmLmOi9XDm0wg+XbWIH9ke2UnQjODHf5tJX9mWftCtYMaD1a6c1rvFhbtpFo6G/PQ==
X-Received: by 2002:a4a:300b:0:b0:5a0:5fe8:e45f with SMTP id q11-20020a4a300b000000b005a05fe8e45fmr419264oof.9.1709145544505;
        Wed, 28 Feb 2024 10:39:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1709145544; cv=none;
        d=google.com; s=arc-20160816;
        b=NRwLFXdFBUQVfoLxS5zwmrMyy/dAgaXhtR70M+mnvhs0PYhrFlO77UwNPyP1zd3cDZ
         YdiT1bXXMH4pZoMdKMPu1jlufEeiOqU5bQLcGy2+ZNdPF90SL2PttOroodt6KqiTl/DT
         +Ljqf6J/tW/BEAeK7gJBGmk4LYRvMqM83d7Fo8P0RIe6TNvP3AikrqawlyKrhQo23ubQ
         0Rw26g6qaYzH1BlvQBKJSel1xHAvpz6CI6JUYocaDGFSvqa9+9F3QHpPrkNkUJdJnXm2
         WWv8FPlmMws3Sy852NX3znSSj1KSSwmeaVgHdSTiqjQ96PJ1ZzBGkOmN3KR8n2ejUUXf
         nbQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=7iqFBA+LWwnU3gwgoROsymeSLKp/pJPiwqlUMLON2K8=;
        fh=u1pJOaJaL3+b/GxZ8qZmkmw0luz/xUGjOumgm6URaAo=;
        b=hceTJHdwLI1OScAq2327zRWAUSPvHwUx77OxDtUdo92KaeLutnx24dzfe+gsEYHomz
         NrTg/xjU0bhR5RzRtRu+WymVcij9GDj/l138Pyv79EttCqTg4I5KFPzR+ntxBz7BNDRU
         0RwG8s6UjtymkHrOCmmSl2oKJlMx4ydru06DMU4wqO+62fyon6O31l42yzZBTtz18/vW
         6qvCO44QLspo7Gmkt7WJ9ocZ81gbxmPu0sTcBIlU9ulKekOfhlbFlrNyXvWvwfeZ/iky
         MORE8kKSr1IcaUVax8srkikJDzqRR2dEjMy1oCWVTIK3HmyFcUS2xY2dnsNW9awzcY9U
         NTWQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HoGNwYyz;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id m5-20020a4a2405000000b005a03384a96fsi13460oof.0.2024.02.28.10.39.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 28 Feb 2024 10:39:04 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-60938adfed8so787267b3.0
        for <kasan-dev@googlegroups.com>; Wed, 28 Feb 2024 10:39:04 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU+eRxVjTP0+grgRY//DjN8LldMPmkR17wx+58ioKw5NtlTrYPL3B6XFhn2rmXqRN94asMtw6KvuL3GULgVQkDLGbwH4KlNxV8hrQ==
X-Received: by 2002:a5b:f45:0:b0:dc6:e75d:d828 with SMTP id
 y5-20020a5b0f45000000b00dc6e75dd828mr48009ybr.18.1709145543730; Wed, 28 Feb
 2024 10:39:03 -0800 (PST)
MIME-Version: 1.0
References: <20240221194052.927623-1-surenb@google.com> <20240221194052.927623-20-surenb@google.com>
 <2daf5f5a-401a-4ef7-8193-6dca4c064ea0@suse.cz> <CAJuCfpGt+zfFzfLSXEjeTo79gw2Be-UWBcJq=eL1qAnPf9PaiA@mail.gmail.com>
 <6db0f0c8-81cb-4d04-9560-ba73d63db4b8@suse.cz> <CAJuCfpEgh1OiYNE_uKG-BqW2x97sOL9+AaTX4Jct3=WHzAv+kg@mail.gmail.com>
 <f494b8e5-f1ca-4b95-a8aa-01b9c4395523@suse.cz>
In-Reply-To: <f494b8e5-f1ca-4b95-a8aa-01b9c4395523@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 28 Feb 2024 10:38:49 -0800
Message-ID: <CAJuCfpHJoPa_pQNPrcWNZyU7V7=UA4deGFMxh9_aZPyiP0bFSw@mail.gmail.com>
Subject: Re: [PATCH v4 19/36] mm: create new codetag references during page splitting
To: Vlastimil Babka <vbabka@suse.cz>
Cc: akpm@linux-foundation.org, kent.overstreet@linux.dev, mhocko@suse.com, 
	hannes@cmpxchg.org, roman.gushchin@linux.dev, mgorman@suse.de, 
	dave@stgolabs.net, willy@infradead.org, liam.howlett@oracle.com, 
	penguin-kernel@i-love.sakura.ne.jp, corbet@lwn.net, void@manifault.com, 
	peterz@infradead.org, juri.lelli@redhat.com, catalin.marinas@arm.com, 
	will@kernel.org, arnd@arndb.de, tglx@linutronix.de, mingo@redhat.com, 
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
 header.i=@google.com header.s=20230601 header.b=HoGNwYyz;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::112b
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

On Wed, Feb 28, 2024 at 10:28=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> On 2/28/24 18:50, Suren Baghdasaryan wrote:
> > On Wed, Feb 28, 2024 at 12:47=E2=80=AFAM Vlastimil Babka <vbabka@suse.c=
z> wrote:
> >
> >>
> >> Now this might be rare enough that it's not worth fixing if that would=
 be
> >> too complicated, just FYI.
> >
> > Yeah. We can fix this by subtracting the "bytes" counter of the "head"
> > page for all free_the_page(page + (1 << order), order) calls we do
> > inside __free_pages(). But we can't simply use pgalloc_tag_sub()
> > because the "calls" counter will get over-decremented (we allocated
> > all of these pages with one call). I'll need to introduce a new
> > pgalloc_tag_sub_bytes() API and use it here. I feel it's too targeted
> > of a solution but OTOH this is a special situation, so maybe it's
> > acceptable. WDYT?
>
> Hmm I think there's a problem that once you fail put_page_testzero() and
> detect you need to do this, the page might be already gone or reallocated=
 so
> you can't get to the tag for decrementing bytes. You'd have to get it
> upfront (I guess for "head && order > 0" cases) just in case it happens.
> Maybe it's not worth the trouble for such a rare case.

Yes, that hit me when I tried to implement it but there is a simple
solution around that. I can obtain alloc_tag before doing
put_page_testzero() and then decrement bytes counter directly as
needed.
Not sure if it is a rare enough case that we can ignore it but if the
fix is simple enough then might as well do it?

>
> >>
> >>
> >> > Every time
> >> > one of these pages are freed that codetag's "bytes" and "calls"
> >> > counters will be decremented. I think accounting will work correctly
> >> > irrespective of where these pages are freed, in __free_pages() or by
> >> > put_page().
> >> >
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
kasan-dev/CAJuCfpHJoPa_pQNPrcWNZyU7V7%3DUA4deGFMxh9_aZPyiP0bFSw%40mail.gmai=
l.com.
