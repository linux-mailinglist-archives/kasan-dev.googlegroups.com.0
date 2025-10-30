Return-Path: <kasan-dev+bncBCUY5FXDWACRBYMWR3EAMGQEQFOBRNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D44EC21120
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 16:59:31 +0100 (CET)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-4711899ab0asf10512645e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 08:59:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761839971; cv=pass;
        d=google.com; s=arc-20240605;
        b=VzvwwmsGpD0VN5UF5N89+mdC2WOzuWIp/cEQT0r002RHajT7orqwPRuHJ0aGvvsyJj
         ZPWIM0/T0UOaH8YQBH7pbb20rZWLbSWkAAp/ux0HV1Mv5ZeWVWHP5LLDJeMdIlSQIokv
         zSJNWHSjQ2jI7CEMTHbxxVrKY6Ud+f57E4VnRMUI96Pzf9azPjePZ2yHPdnkOb8KVbmG
         imhaU7b4c944NPOosIYaWesK0scah40j93//3lNAenrz78xeoon7BET0d+TdG/zgYeqk
         RnKq2s+F1imSBtw+5kMSdDsD2fw3zHDR2bHLsGsCoD1ZVo+PhRqdBw0K3mdebrfE59gn
         UV8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=8BiaIFZMMWDPFhoyAw3WSi/gIvptXRFHNBrS7gwlRdE=;
        fh=CIEiHfRTlewWaaiECHb1ojWYTtjmU9B5nZlCBu6K7l0=;
        b=a5xmv3wWfDC5zh6dBAV4doQzjOdz2e38mxksyTyXEMkbr2DltOkdreXTAFQ0QD4Ebo
         huTVm3CCf7Ang0tAN3Jvc85h6yDal+vYPpvS4DbmanSH2KLBjO5wB0ugzyA5z5LCPfsL
         gziUDyuG7kA4DFyBm1OjROtPEE7JYi6DyjxCgvjpLMNkEulhL0Hu/Mp4J1p0nLa2fNZa
         OU7LUtwym6/q9ug7GgJPohhC6qAVab/5RTl2h+jcR74LXTo9vUUY5nIQD4YWYFmyBwXo
         hElIxSc13rU7zJV7tjE8JvOVyNqTngKCESXdTmJGPLFl8ADhgC9YVt4shpexBWQQfuIC
         EVnw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eBAPH6EI;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761839971; x=1762444771; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=8BiaIFZMMWDPFhoyAw3WSi/gIvptXRFHNBrS7gwlRdE=;
        b=CbJmB2CELqX58bu11VQjKzwQtxeUAOUMwQWeIthgYpJw0ukrijoI6Xm9r8oOuQFb2I
         MylPULQk379HovtuPicdy1j+zT1Asr0IvxwNX8OgtjqXkHNYNO6pkEKmU+PJw8k/2kfb
         WHdXGb0ytFa8B9SSb7jWhqaNKx89KRs5Yg6bmEH+ruPKqIFYQsDQnyG+n9K+oHyk7yCL
         uRgqn1+YbMxGcm8QIM2ae/qfoYlRhA8/rQ5mUpGb/3iCQfU8QfxH3I8rc7GgjBrYlsq8
         zs6xylo3zM8cy0Kwhshc1Fv8x6zPHoyGdINDaL87F4xjc13yJkbmPOrQgd01Pp0g6/x2
         C5Uw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761839971; x=1762444771; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=8BiaIFZMMWDPFhoyAw3WSi/gIvptXRFHNBrS7gwlRdE=;
        b=ObYI5SMcpkeL30WCMFjavhLFeI2/Eibd/D9DCDKG2WqzXRuo6mb8B/KC+Z5GIqgJZj
         2ADBPiATWc2OjxwBVfiB2rYhCd0Fe5OO1QYwUPFUV3i29bswjWrHpEqkwB8Pl+ZEt50H
         HH4yAm5McJxokmheb8nOI++yE+aW3taAB2gCBdoYj/AbKTbgeUitZ4BoCZnx50QQ5VBZ
         KYuCkwR0FsNrLQUKLlwjSg2HL0Kaw/7wo+EYqqBMIepsKvYMJNYM1cr/Bk1zfQ/24tie
         VGSDDzQ/bXGqY0C3GcAObAWj5DtzAz1HFKPBZ1Xi135JoMSo8PbBH99Gkhuf0vLS4mtC
         1oxQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761839971; x=1762444771;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=8BiaIFZMMWDPFhoyAw3WSi/gIvptXRFHNBrS7gwlRdE=;
        b=Hc+Q99XyVZf7iHIVcmSDZee2e6gvG2cystCmde3d1WK3dpYgdDPl99vZ7LP+SmQ5n7
         sSOBgV68NaSHLaLp50mRv3GXNFGfL7pEZzD9E6m/b9RGNrwjL3g6c9HMde2ApiGbiiDY
         sMOKCo4hXZtevuj46ihkfeS9VpcgtpN7LC/ClGTpWZ1Pej7avAO+NRCUYQyfjJrttIl+
         dZLd6oSqmmglpTJQerNU+BAlKrD9jPXAKUffpyY5H+tiiWwNAl8SRqG8ew+QPFwAkNR4
         rF3nw2She5av9OJgIGHi03slilmajY4OF4MLJjpNS6JDUkikD8wjSrtzYPdZOFK/Gf3L
         Ftug==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWM7xNv9ZqlIMqSfQtIgjt6QS7in6i9enbDS9/gVvZsfnMaXMYAjstxD2bDaak57a9t3iKVgA==@lfdr.de
X-Gm-Message-State: AOJu0YwbvaprgsQzzQDGAfWVKoPAFaVuiv0Q59jh25LIs5VewFqoOrBu
	WtcfjGpdiU1oSHdO1PPKydHpGBn0JwKFNYIaW25Pe47eT3J/Fmqw6TuR
X-Google-Smtp-Source: AGHT+IErbjG4c9hBxV/7TLkptfiDKyv8thoNI+cdnwTr2SuEdQcp8c0m+3cVplrIzf+9gU3Snsisdg==
X-Received: by 2002:a05:600c:1553:b0:471:15bb:ad7b with SMTP id 5b1f17b1804b1-477307b5f7cmr2419505e9.6.1761839970496;
        Thu, 30 Oct 2025 08:59:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+boCZ9OX8O+/7U+IgNE3U76O5pXfIq7CHrFtYwViNh5Kg=="
Received: by 2002:a05:600c:1c28:b0:471:80e:c5fe with SMTP id
 5b1f17b1804b1-477276e93e6ls8385145e9.0.-pod-prod-08-eu; Thu, 30 Oct 2025
 08:59:26 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVJ0e6AKuZZxQFj95JcsfGEmcLmbc2BhGwl2mq8U7Ov/3h00vgUF8MbWtQ8DDnG1hPaS9D31wm2/IU=@googlegroups.com
X-Received: by 2002:a05:600c:3489:b0:477:58:7d04 with SMTP id 5b1f17b1804b1-477307e214dmr2072385e9.9.1761839966583;
        Thu, 30 Oct 2025 08:59:26 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761839966; cv=none;
        d=google.com; s=arc-20240605;
        b=i3s0tGOAYxH8xhhXYDofL0FWjNnNQ8uM31XH68WgoBW8rb8DrdbU8fep+z+pK3ARYz
         xz2zHr6HtVX+BjLP4dGYd3vAqv1aQxsEfSq3OFSJ8A1QYZlpmJDLDvgpdvMf2t/r4cuy
         +0tb2JJ4Ygzxi89DZTeICxGTv9sb9lU7Npq7jrkmn0ZlW6U3tJSsSlPZseAnbNQq771t
         K3owW+drhyebZbQAqBtisW82sq4c7T04dBi6U3BUZIBJRuPnwYcEjgizCpg61d6k/C9C
         ddlfZIss5m4DHjIFEjDzTWgTdYTygREpl0vl9WRqbFDYedxRj8URubWqzXVQWKwGXsBU
         kJNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=dtYLD87/tbnWpFhxZoXLkwutGQwHC9HiwVV2d797j9U=;
        fh=Ua99mqrrSGr9RzsQnDEsi/6u29ZzqoPLLBokzsyESUY=;
        b=IXSKm+N4+AyohEHjbXrtN1YOYosU7tlbfu9F0J0k0KO1rukF0PI+fss0A5P0cA1BRf
         PvXwCxepUQEyQtNYH+AII9L87GPnJxxv5Fa6QyWA9tIlu4QuptdjNsGc8GSLEHaWXi75
         oPX8y6wDE2z9Fjy8TxbYciR0EKvjUlYaBTpedYbdT1yMMvFLcTb0AZO3WqQiI8iCgski
         3nGBS3SOvDNgR8kKzeEd/xqxzWYMzIabdh+z6Shztwa7wrIPSz9sxvE7tIoG3CtZqOGC
         FZxQxrtqV2TQBLhhYVWPf9Pb2C0j89HMGBPoPEUxGMzR9SKYgnXMEc14/H57N1kWhNHx
         QMKQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eBAPH6EI;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-47727fc5ebasi56365e9.0.2025.10.30.08.59.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Oct 2025 08:59:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id a640c23a62f3a-b4736e043f9so213226866b.0
        for <kasan-dev@googlegroups.com>; Thu, 30 Oct 2025 08:59:26 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUKr/QJis05rL9CIpGJUaARulAQsYDhtTS9kN9Cf9CdmSP4tb1/UY6qwEZPaJQwbFu6AD1ZclZpqvI=@googlegroups.com
X-Gm-Gg: ASbGncvUN9E64/UtTvjuzNWEyeDhgBXb/OBL21mrl6xeQGPk5ySiHjcinmYQOH72qwX
	UhXvPP6LhJJn3wjzdoknRiKMQ85eweZ9VhvRprgz31Ml075agqPYLvHklmQ8/SaX3KUWl9rPmdW
	tRnV0FxcZt9MroQwmdeOakDq8Wcc4Wa0+BTNGcnaoPw5s2+WyL1b7tvIp2Xvyu33Kb2P2kycWMP
	26dk40VgLVmkmw+AaWV3Kj9T89cmw7if7JrVlMe7lnGs2j/AkPzRyHzqR3NiFt1t9q+4jd3PoM3
	2sF4OcTT/9U=
X-Received: by 2002:a17:907:7f22:b0:b0c:b51b:81f6 with SMTP id
 a640c23a62f3a-b7053e45459mr371911866b.43.1761839965702; Thu, 30 Oct 2025
 08:59:25 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-10-6ffa2c9941c0@suse.cz> <aQLqZjjq1SPD3Fml@hyeyoo>
 <06241684-e056-40bd-88cc-0eb2d9d062bd@suse.cz> <CAADnVQ+K-gWm6KKzKZ0vVwfT2H1UXSoaD=eA1aRUHpA5MCLAvA@mail.gmail.com>
 <5e8e6e92-ba8f-4fee-bd01-39aacdd30dbe@suse.cz>
In-Reply-To: <5e8e6e92-ba8f-4fee-bd01-39aacdd30dbe@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Thu, 30 Oct 2025 08:59:14 -0700
X-Gm-Features: AWmQ_bkWAOmvQoKcQyr_zcqHDGMRrBlm9dDGveiPgB0Mj-QwDfGlE8jGMTlojF0
Message-ID: <CAADnVQJ_yzOGAT__EG=eBTHbWeiFgEZ--fHFQNprsX9o0vEQkA@mail.gmail.com>
Subject: Re: [PATCH RFC 10/19] slab: remove cpu (partial) slabs usage from
 allocation paths
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev, 
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=eBAPH6EI;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Oct 30, 2025 at 8:35=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 10/30/25 16:27, Alexei Starovoitov wrote:
> > On Thu, Oct 30, 2025 at 6:09=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> On 10/30/25 05:32, Harry Yoo wrote:
> >> > On Thu, Oct 23, 2025 at 03:52:32PM +0200, Vlastimil Babka wrote:
> >> >> diff --git a/mm/slub.c b/mm/slub.c
> >> >> index e2b052657d11..bd67336e7c1f 100644
> >> >> --- a/mm/slub.c
> >> >> +++ b/mm/slub.c
> >> >> @@ -4790,66 +4509,15 @@ static void *___slab_alloc(struct kmem_cach=
e *s, gfp_t gfpflags, int node,
> >> >>
> >> >>      stat(s, ALLOC_SLAB);
> >> >>
> >> >> -    if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
> >> >> -            freelist =3D alloc_single_from_new_slab(s, slab, orig_=
size, gfpflags);
> >> >> -
> >> >> -            if (unlikely(!freelist))
> >> >> -                    goto new_objects;
> >> >> -
> >> >> -            if (s->flags & SLAB_STORE_USER)
> >> >> -                    set_track(s, freelist, TRACK_ALLOC, addr,
> >> >> -                              gfpflags & ~(__GFP_DIRECT_RECLAIM));
> >> >> -
> >> >> -            return freelist;
> >> >> -    }
> >> >> -
> >> >> -    /*
> >> >> -     * No other reference to the slab yet so we can
> >> >> -     * muck around with it freely without cmpxchg
> >> >> -     */
> >> >> -    freelist =3D slab->freelist;
> >> >> -    slab->freelist =3D NULL;
> >> >> -    slab->inuse =3D slab->objects;
> >> >> -    slab->frozen =3D 1;
> >> >> -
> >> >> -    inc_slabs_node(s, slab_nid(slab), slab->objects);
> >> >> +    freelist =3D alloc_single_from_new_slab(s, slab, orig_size, gf=
pflags);
> >> >>
> >> >> -    if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin))=
 {
> >> >> -            /*
> >> >> -             * For !pfmemalloc_match() case we don't load freelist=
 so that
> >> >> -             * we don't make further mismatched allocations easier=
.
> >> >> -             */
> >> >> -            deactivate_slab(s, slab, get_freepointer(s, freelist))=
;
> >> >> -            return freelist;
> >> >> -    }
> >> >> +    if (unlikely(!freelist))
> >> >> +            goto new_objects;
> >> >
> >> > We may end up in an endless loop in !allow_spin case?
> >> > (e.g., kmalloc_nolock() is called in NMI context and n->list_lock is
> >> > held in the process context on the same CPU)
> >> >
> >> > Allocate a new slab, but somebody is holding n->list_lock, so tryloc=
k fails,
> >> > free the slab, goto new_objects, and repeat.
> >>
> >> Ugh, yeah. However, AFAICS this possibility already exists prior to th=
is
> >> patch, only it's limited to SLUB_TINY/kmem_cache_debug(s). But we shou=
ld fix
> >> it in 6.18 then.
> >> How? Grab the single object and defer deactivation of the slab minus o=
ne
> >> object? Would work except for kmem_cache_debug(s) we open again a race=
 for
> >> inconsistency check failure, and we have to undo the simple slab freei=
ng fix
> >>  and handle the accounting issue differently again.
> >> Fail the allocation for the debug case to avoid the consistency check
> >> issues? Would it be acceptable for kmalloc_nolock() users?
> >
> > You mean something like:
> > diff --git a/mm/slub.c b/mm/slub.c
> > index a8fcc7e6f25a..e9a8b75f31d7 100644
> > --- a/mm/slub.c
> > +++ b/mm/slub.c
> > @@ -4658,8 +4658,11 @@ static void *___slab_alloc(struct kmem_cache
> > *s, gfp_t gfpflags, int node,
> >         if (kmem_cache_debug(s)) {
> >                 freelist =3D alloc_single_from_new_slab(s, slab,
> > orig_size, gfpflags);
> >
> > -               if (unlikely(!freelist))
> > +               if (unlikely(!freelist)) {
> > +                       if (!allow_spin)
> > +                               return NULL;
> >                         goto new_objects;
> > +               }
> >
> > or I misunderstood the issue?
>
> Yeah that would be the easiest solution, if you can accept the occasional
> allocation failures.

yeah. not worried about the slub debug case.
Let's reassess when sheav conversion is over.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQJ_yzOGAT__EG%3DeBTHbWeiFgEZ--fHFQNprsX9o0vEQkA%40mail.gmail.com.
