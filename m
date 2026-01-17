Return-Path: <kasan-dev+bncBC7OD3FKWUERBQW7VPFQMGQEN3IRGBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x839.google.com (mail-qt1-x839.google.com [IPv6:2607:f8b0:4864:20::839])
	by mail.lfdr.de (Postfix) with ESMTPS id 79A54D38B7A
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Jan 2026 03:11:16 +0100 (CET)
Received: by mail-qt1-x839.google.com with SMTP id d75a77b69052e-5013d63b3f1sf73442461cf.1
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 18:11:16 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768615875; cv=pass;
        d=google.com; s=arc-20240605;
        b=GrImBHK82CQM997c3q5NId3aZcJSHAvjmx7sMr2jsP3JEbwtXMeWNpoTNc2bE1CnAg
         rUrDOKw00QbleU4xVvo5prw+/7l4p0pcsG5kbztbU1xiFklCARRKOWXYMM7Cz4/1nO+d
         kAyBaneYRVePvNjmVdyeYCa4eGMQ9lhHyUh1v67988K7Bm4rDJCf4W3G0nYFXe3a/VxC
         KZkKUewI5p0TPF7UWbOuU+E/Kxhcnjx2IlEZFBsBTX9amQ6wG2D9nz9ypaImNW4iurFX
         RR0CZ50X9kXBUm/CvncSCcc7s3wjSrN6d0Ov0c8J+siOMbJ0BpFHx7dFn6NOy26V4pJx
         4yBQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ntEPM+fqUn2yQcbNK0eLmAgimyZMqfo7jkvJaWLJDUY=;
        fh=gPrVZoKB/jnaRwVUYtfVIqJsVqOjOllawWVkcv64yuM=;
        b=DG/OgSDXS3tIpotlFI3ci1wn6BUdLITOT9O1ZRrrAQE9aM6yqW/mKO0DJHcN01fH05
         TYZrnLA0ndjTSJ125jeGofdgtAR2oQt2Jtf1ufgRmqx2ZNiOuIzxuTpf30Cfrl7Y3ugL
         XwPT5Wq4b+UFIUD58y1OrGdvWQEzNB6nkeft3pCwWdt895hNJI6sokAYTK0fWEiQu8/2
         9dj3s0kqYXZ9D4JQDfeK+YOoiQB9+nVGf4BNHvZvvHNOWqOUYbFN3oNnX/7LAQPIyj+w
         fiAz/YjPKwahf1U/ibSxYnEv7e44co+kgnfp6+XBOpiLcmTA1E1xYBLpD1GyVdQySLQf
         PFBQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cpK5lFFW;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768615875; x=1769220675; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ntEPM+fqUn2yQcbNK0eLmAgimyZMqfo7jkvJaWLJDUY=;
        b=DovfneOiebd65Rm+ZlgwPB33+Ws1oLxWyj0sH6p6S0RNqIVUXjDFOTXjLTJlbJNEZR
         nEnluy7vAqJcCQh0Qs6vZj5pen/YGGBYqniMvuTILMn7kh+hk0yllKn1L237DCxCvSOe
         OycFdYyqv5jv2toLJSGjq8iQrqBWsMA5fN+5LY5lAKbqZufreUsZWK5lOb0oFFeyrzx5
         vTi5l8XVHwLt/wHs79apI2DDPGTy6sYCAecorqoLnDGjZTEWVkCzi3C/2n1Uu9LO5lKW
         3Qlk8YivRLADvWMdXeSNUe4XFFzAiTQEXFcAN6RWhJjfrfPaKHgoJjGftGfd+n2s/SHc
         mO2g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768615875; x=1769220675;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=ntEPM+fqUn2yQcbNK0eLmAgimyZMqfo7jkvJaWLJDUY=;
        b=NMmDZrhLOVn4iPuc5fU8ud08o18hlInGy6M6JXDKWVmdzXsP9iaWqOESQ0NLNMYFiC
         ECLonNpspapgbpJeDIdHGAfhyGCpmCYuZzfgZ7oz3+MK2oNW+GTXRk9CxyNRT6CVguUd
         2DRE3TTWECYOf5WCMbXR21XRNjAhL2zZW6Mh2KsdUCIT4sBTM3vElCHPGKlmUym7J51z
         1Ao/YariJmQSZGYMAMyZ0SVw+J4Vgp7uds6dJK8dF+vbVY5x6ZxAmzky1YJkjNzxWDuc
         7TMoeiPpFbfWxhr4QWn1ZbUrkTl/JHdIlOBU4Dgobhxoi2GGlWeIWLgs6wqs5KSjhlo5
         jH0Q==
X-Forwarded-Encrypted: i=3; AJvYcCVsDjP9L6Bx9B0Bc4tcfocdOLPOqdCAgfy38xPdFQPWhhzXuK+1/ebpGgtuTA1kBkfUq9EpQQ==@lfdr.de
X-Gm-Message-State: AOJu0YxVAC7z2AZolLmwXrLPxvdLX/WDEMrmNQ17OLPdxEHoq9hu6U7a
	K2bqw8UtArXZshz5TPAJVB8UO8qzcqGCnoYUMKO2gXQOcDzK9ErjyZ8y
X-Received: by 2002:ac8:5d8e:0:b0:4ff:ca75:70ec with SMTP id d75a77b69052e-502a15747d7mr73330461cf.13.1768615874943;
        Fri, 16 Jan 2026 18:11:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HT2/k26/zA9Lfa27hH9dZlD+VVxHl85KCzxaNjDgywtw=="
Received: by 2002:ac8:6c9:0:b0:4f3:4bef:4924 with SMTP id d75a77b69052e-50147ce0f1fls23971231cf.0.-pod-prod-00-us-canary;
 Fri, 16 Jan 2026 18:11:14 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWQWw7/CUbGrOI16nNqnA0i4ZUVD6eoythPIX/8z2YiZUQzRKCFTkIKoK9F86MGAdcQTfKMX2Rk3Tc=@googlegroups.com
X-Received: by 2002:a05:620a:1707:b0:8bb:7886:7e1f with SMTP id af79cd13be357-8c6a650e2e4mr746424385a.36.1768615874025;
        Fri, 16 Jan 2026 18:11:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768615874; cv=pass;
        d=google.com; s=arc-20240605;
        b=STg2uVZMZ/dEUENw/xOs3Q8Ulvu3J45KRSJ+Yw8AnOLA4dAyFk5vO8jwik++4+i/fK
         70m7kvGVUY6e7xhWwcL8+3aEKvfCPvdoWj/k6dkBBvuiiv29GLSI/1b+ZZRCGkf4S7vN
         MzkbYH2DVCYJ0uYRTLyYnTxzaMDJYlG3Lp4mOAmhif6ef7ifPBYATB6MyNrsxlcX1IJf
         a77958+fB34mYs43H84AOTez38lYg2JNOAINtQ11yQQ5eyQI4VbeWn+5ep71JNMHrGLl
         9UcHdg/T1T317DhiHez4H6WErrnkq+Oi1ZsGNAFxAHSI9xboLCtPpuRUH/l371nADiKk
         1tUg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z8XfzdTcYbKXbttOZYCkhexZVaSChWM1LNoqV+hh1gE=;
        fh=Vglgy7ak3fw9lWqJML3IHVFI8LNgn7YsDbrVHtuuqWk=;
        b=jmrIi9X/kCl3aQI9novYma3K3WXzLbgDiz9FdORa2HtdsD6Jndbm9+foMmhjPRNIc3
         poUYZFpqQVofctcs8MGHHwa2hx8s1GxZTYn33FMMgycRA3/LySThc3C9Fk8txo/uRBEb
         b4pu9OTIACLvOPYnJCozSeo7gqBeI360pg5wy6dxRWKyhvDZjG74ifFfdH2fAE93iTcR
         j35yCFiiZbhFnBsHxGcj1ko9VywucDRVKr1f//+XlfELTH0oFtZGi32RA4VeufU8PDg5
         AFmaKYHJCMNzdl3d7ff6+2TsSsnzV6lm2jjsAGN1Z2w9od2lJjB1xn20a2Dcc+uGT6Ly
         JMww==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=cpK5lFFW;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-8c6a72419besi13752085a.6.2026.01.16.18.11.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 18:11:14 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id d75a77b69052e-5014b5d8551so157291cf.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 18:11:13 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768615873; cv=none;
        d=google.com; s=arc-20240605;
        b=GdimHFCbtvuyV4dM18iwqBdt6NTLtHsF/W2nnCN46xFXpfRVqYJALylqnpqZ/T2Ciq
         OibIEyf3Po2DJfhCG1Q1/beREyyIDv//805qNdZkXhaXFtCc+YOAEoA7+ci6C5XVLIZg
         tvmWUBzBWyLaBheq40bMghaCetf3izcs5FebzmLUzTKHPV86ee+ZWATotCA/7nPzmp4b
         ESQfKsR6B1q67SFyntwcWRGslFiJSee2VzsjQdOW/lk0jo3yxCe3pmJXqvVOZyCAO+v2
         p8k91XnQgYUt6coDOt2x0/f7S+gsb3wy4t5cZZ9Rqt50RCaUX4NfgaXIcC1hX4EDRc2t
         zD4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Z8XfzdTcYbKXbttOZYCkhexZVaSChWM1LNoqV+hh1gE=;
        fh=Vglgy7ak3fw9lWqJML3IHVFI8LNgn7YsDbrVHtuuqWk=;
        b=arS/wF5vq/ksafFFtgwoWH21LmnR/FCa4XFX7iLZeWo/Vp//CvLEJVwK9fX8lXrl69
         ji4oAm3jmxorN1LfH4iq78k2b+TwOsOlXv7Twh47t5UrOiDDLEuIF+sHB+oRrC23ezBJ
         wu7AsvRPFF+bUBSq2k+rzSMmgDToP5qN1yS+VSyCMSY0oHy/FkS4CNuVNW7EGm8F5QTu
         3hADN0rxTidkaMRnHSMSoKkFPxTKrtWmj0qjWtvpn+T1EJ9ZsZ4T5wNSZ8ML5/u8kuAN
         IqXVwDZFBSuHzOm/ausY11ftL6eS7Uv7yy2fZj8q0EE6PTR8GgeU/uIaJj7G6qlU1bWO
         fFTg==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWWeBFrksIkZClj53Ad0DJwkfJQYR1eG/kQOmONTdLLC/vwaJc19VVZaKMfx8C49RSmET36Mj8hvWo=@googlegroups.com
X-Gm-Gg: AY/fxX4rh2rj+/6R2ZYWnoQni2rPICxKaX43ve3dJ30b0SSX9AXm2fcFpNW8Dk2Dhm+
	RHwsThhtg3mDqToXRVf0LlfKiOX34WLQjWBIOVP9U2T24g/F0gOBMDu2p0jW8PD+3NRByXCodON
	a6tL1sHDPf3fQNdYh6e1cbcYgKr9Weu92mDo5B2rvq5kXCOGvhRzBTK4ZdlNvgE96MHbaSTXxQW
	3/IxDH2ZpZUP+AV7n7NMNOSoGVo06+x9yo9HFV3FFyqOpbtz2BJSjhm7SfXorWTMzfTSt1UpRLH
	zYbZ22JkVS1AStv93BQsC3/oVhrsQuhv4g==
X-Received: by 2002:a05:622a:607:b0:4ff:cb25:998b with SMTP id
 d75a77b69052e-502afa038cbmr4649721cf.12.1768615873084; Fri, 16 Jan 2026
 18:11:13 -0800 (PST)
MIME-Version: 1.0
References: <20260116-sheaves-for-all-v3-0-5595cb000772@suse.cz> <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
In-Reply-To: <20260116-sheaves-for-all-v3-6-5595cb000772@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Sat, 17 Jan 2026 02:11:02 +0000
X-Gm-Features: AZwV_QgrFpJPgQWV97FWxIc0ZsJ8CltGCxNFZv_PPGY8cU_AH1jVOdq1pMTHKpM
Message-ID: <CAJuCfpERcCzBysPVh63g7d0FpUBNQeq9nCL+ycem1iR08gDmaQ@mail.gmail.com>
Subject: Re: [PATCH v3 06/21] slab: introduce percpu sheaves bootstrap
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Harry Yoo <harry.yoo@oracle.com>, Petr Tesarik <ptesarik@suse.com>, 
	Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hao Li <hao.li@linux.dev>, 
	Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Sebastian Andrzej Siewior <bigeasy@linutronix.de>, 
	Alexei Starovoitov <ast@kernel.org>, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	linux-rt-devel@lists.linux.dev, bpf@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=cpK5lFFW;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

On Fri, Jan 16, 2026 at 2:40=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> Until now, kmem_cache->cpu_sheaves was !NULL only for caches with
> sheaves enabled. Since we want to enable them for almost all caches,
> it's suboptimal to test the pointer in the fast paths, so instead
> allocate it for all caches in do_kmem_cache_create(). Instead of testing
> the cpu_sheaves pointer to recognize caches (yet) without sheaves, test
> kmem_cache->sheaf_capacity for being 0, where needed, using a new
> cache_has_sheaves() helper.
>
> However, for the fast paths sake we also assume that the main sheaf
> always exists (pcs->main is !NULL), and during bootstrap we cannot
> allocate sheaves yet.
>
> Solve this by introducing a single static bootstrap_sheaf that's
> assigned as pcs->main during bootstrap. It has a size of 0, so during
> allocations, the fast path will find it's empty. Since the size of 0
> matches sheaf_capacity of 0, the freeing fast paths will find it's
> "full". In the slow path handlers, we use cache_has_sheaves() to
> recognize that the cache doesn't (yet) have real sheaves, and fall back.

I don't think kmem_cache_prefill_sheaf() handles this case, does it?
Or do you rely on the caller to never try prefilling a bootstrapped
sheaf?
kmem_cache_refill_sheaf() and kmem_cache_return_sheaf() operate on a
sheaf obtained by calling kmem_cache_prefill_sheaf(), so if
kmem_cache_prefill_sheaf() never returns a bootstrapped sheaf we don't
need special handling there.

> Thus sharing the single bootstrap sheaf like this for multiple caches
> and cpus is safe.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 119 ++++++++++++++++++++++++++++++++++++++++++--------------=
------
>  1 file changed, 81 insertions(+), 38 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index edf341c87e20..706cb6398f05 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -501,6 +501,18 @@ struct kmem_cache_node {
>         struct node_barn *barn;
>  };
>
> +/*
> + * Every cache has !NULL s->cpu_sheaves but they may point to the
> + * bootstrap_sheaf temporarily during init, or permanently for the boot =
caches
> + * and caches with debugging enabled, or all caches with CONFIG_SLUB_TIN=
Y. This
> + * helper distinguishes whether cache has real non-bootstrap sheaves.
> + */
> +static inline bool cache_has_sheaves(struct kmem_cache *s)
> +{
> +       /* Test CONFIG_SLUB_TINY for code elimination purposes */
> +       return !IS_ENABLED(CONFIG_SLUB_TINY) && s->sheaf_capacity;
> +}
> +
>  static inline struct kmem_cache_node *get_node(struct kmem_cache *s, int=
 node)
>  {
>         return s->node[node];
> @@ -2855,6 +2867,10 @@ static void pcs_destroy(struct kmem_cache *s)
>                 if (!pcs->main)
>                         continue;
>
> +               /* bootstrap or debug caches, it's the bootstrap_sheaf */
> +               if (!pcs->main->cache)
> +                       continue;

I wonder why we can't simply check cache_has_sheaves(s) at the
beginning and skip the loop altogether.
I realize that __kmem_cache_release()->pcs_destroy() is called in the
failure path of do_kmem_cache_create() and s->cpu_sheaves might be
partially initialized if alloc_empty_sheaf() fails somewhere in the
middle of the loop inside init_percpu_sheaves(). But for that,
s->sheaf_capacity should still be non-zero, so checking
cache_has_sheaves() at the beginning of pcs_destroy() should still
work, no?

BTW, I see one last check for s->cpu_sheaves that you didn't replace
with cache_has_sheaves() inside __kmem_cache_release(). I think that's
because it's also in the failure path of do_kmem_cache_create() and
it's possible that s->sheaf_capacity > 0 while s->cpu_sheaves =3D=3D NULL
(if alloc_percpu(struct slub_percpu_sheaves) fails). It might be
helpful to add a comment inside __kmem_cache_release() to explain why
cache_has_sheaves() can't be used there.

> +
>                 /*
>                  * We have already passed __kmem_cache_shutdown() so ever=
ything
>                  * was flushed and there should be no objects allocated f=
rom
> @@ -4030,7 +4046,7 @@ static bool has_pcs_used(int cpu, struct kmem_cache=
 *s)
>  {
>         struct slub_percpu_sheaves *pcs;
>
> -       if (!s->cpu_sheaves)
> +       if (!cache_has_sheaves(s))
>                 return false;
>
>         pcs =3D per_cpu_ptr(s->cpu_sheaves, cpu);
> @@ -4052,7 +4068,7 @@ static void flush_cpu_slab(struct work_struct *w)
>
>         s =3D sfw->s;
>
> -       if (s->cpu_sheaves)
> +       if (cache_has_sheaves(s))
>                 pcs_flush_all(s);
>
>         flush_this_cpu_slab(s);
> @@ -4157,7 +4173,7 @@ void flush_all_rcu_sheaves(void)
>         mutex_lock(&slab_mutex);
>
>         list_for_each_entry(s, &slab_caches, list) {
> -               if (!s->cpu_sheaves)
> +               if (!cache_has_sheaves(s))
>                         continue;
>                 flush_rcu_sheaves_on_cache(s);
>         }
> @@ -4179,7 +4195,7 @@ static int slub_cpu_dead(unsigned int cpu)
>         mutex_lock(&slab_mutex);
>         list_for_each_entry(s, &slab_caches, list) {
>                 __flush_cpu_slab(s, cpu);
> -               if (s->cpu_sheaves)
> +               if (cache_has_sheaves(s))
>                         __pcs_flush_all_cpu(s, cpu);
>         }
>         mutex_unlock(&slab_mutex);
> @@ -4979,6 +4995,12 @@ __pcs_replace_empty_main(struct kmem_cache *s, str=
uct slub_percpu_sheaves *pcs,
>
>         lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
>
> +       /* Bootstrap or debug cache, back off */
> +       if (unlikely(!cache_has_sheaves(s))) {
> +               local_unlock(&s->cpu_sheaves->lock);
> +               return NULL;
> +       }
> +
>         if (pcs->spare && pcs->spare->size > 0) {
>                 swap(pcs->main, pcs->spare);
>                 return pcs;
> @@ -5165,6 +5187,11 @@ unsigned int alloc_from_pcs_bulk(struct kmem_cache=
 *s, size_t size, void **p)
>                 struct slab_sheaf *full;
>                 struct node_barn *barn;
>
> +               if (unlikely(!cache_has_sheaves(s))) {
> +                       local_unlock(&s->cpu_sheaves->lock);
> +                       return allocated;
> +               }
> +
>                 if (pcs->spare && pcs->spare->size > 0) {
>                         swap(pcs->main, pcs->spare);
>                         goto do_alloc;
> @@ -5244,8 +5271,7 @@ static __fastpath_inline void *slab_alloc_node(stru=
ct kmem_cache *s, struct list
>         if (unlikely(object))
>                 goto out;
>
> -       if (s->cpu_sheaves)
> -               object =3D alloc_from_pcs(s, gfpflags, node);
> +       object =3D alloc_from_pcs(s, gfpflags, node);
>
>         if (!object)
>                 object =3D __slab_alloc_node(s, gfpflags, node, addr, ori=
g_size);
> @@ -5355,17 +5381,6 @@ kmem_cache_prefill_sheaf(struct kmem_cache *s, gfp=
_t gfp, unsigned int size)
>
>         if (unlikely(size > s->sheaf_capacity)) {
>
> -               /*
> -                * slab_debug disables cpu sheaves intentionally so all
> -                * prefilled sheaves become "oversize" and we give up on
> -                * performance for the debugging. Same with SLUB_TINY.
> -                * Creating a cache without sheaves and then requesting a
> -                * prefilled sheaf is however not expected, so warn.
> -                */
> -               WARN_ON_ONCE(s->sheaf_capacity =3D=3D 0 &&
> -                            !IS_ENABLED(CONFIG_SLUB_TINY) &&
> -                            !(s->flags & SLAB_DEBUG_FLAGS));
> -
>                 sheaf =3D kzalloc(struct_size(sheaf, objects, size), gfp)=
;
>                 if (!sheaf)
>                         return NULL;
> @@ -6082,6 +6097,12 @@ __pcs_replace_full_main(struct kmem_cache *s, stru=
ct slub_percpu_sheaves *pcs)
>  restart:
>         lockdep_assert_held(this_cpu_ptr(&s->cpu_sheaves->lock));
>
> +       /* Bootstrap or debug cache, back off */
> +       if (unlikely(!cache_has_sheaves(s))) {
> +               local_unlock(&s->cpu_sheaves->lock);
> +               return NULL;
> +       }
> +
>         barn =3D get_barn(s);
>         if (!barn) {
>                 local_unlock(&s->cpu_sheaves->lock);
> @@ -6280,6 +6301,12 @@ bool __kfree_rcu_sheaf(struct kmem_cache *s, void =
*obj)
>                 struct slab_sheaf *empty;
>                 struct node_barn *barn;
>
> +               /* Bootstrap or debug cache, fall back */
> +               if (unlikely(!cache_has_sheaves(s))) {
> +                       local_unlock(&s->cpu_sheaves->lock);
> +                       goto fail;
> +               }
> +
>                 if (pcs->spare && pcs->spare->size =3D=3D 0) {
>                         pcs->rcu_free =3D pcs->spare;
>                         pcs->spare =3D NULL;
> @@ -6674,9 +6701,8 @@ void slab_free(struct kmem_cache *s, struct slab *s=
lab, void *object,
>         if (unlikely(!slab_free_hook(s, object, slab_want_init_on_free(s)=
, false)))
>                 return;
>
> -       if (s->cpu_sheaves && likely(!IS_ENABLED(CONFIG_NUMA) ||
> -                                    slab_nid(slab) =3D=3D numa_mem_id())
> -                          && likely(!slab_test_pfmemalloc(slab))) {
> +       if (likely(!IS_ENABLED(CONFIG_NUMA) || slab_nid(slab) =3D=3D numa=
_mem_id())
> +           && likely(!slab_test_pfmemalloc(slab))) {
>                 if (likely(free_to_pcs(s, object)))
>                         return;
>         }
> @@ -7379,7 +7405,7 @@ void kmem_cache_free_bulk(struct kmem_cache *s, siz=
e_t size, void **p)
>          * freeing to sheaves is so incompatible with the detached freeli=
st so
>          * once we go that way, we have to do everything differently
>          */
> -       if (s && s->cpu_sheaves) {
> +       if (s && cache_has_sheaves(s)) {
>                 free_to_pcs_bulk(s, size, p);
>                 return;
>         }
> @@ -7490,8 +7516,7 @@ int kmem_cache_alloc_bulk_noprof(struct kmem_cache =
*s, gfp_t flags, size_t size,
>                 size--;
>         }
>
> -       if (s->cpu_sheaves)
> -               i =3D alloc_from_pcs_bulk(s, size, p);
> +       i =3D alloc_from_pcs_bulk(s, size, p);

Doesn't the above change make this fastpath a bit longer? IIUC,
instead of bailing out right here we call alloc_from_pcs_bulk() and
bail out from there because pcs->main->size is 0.

>
>         if (i < size) {
>                 /*
> @@ -7702,6 +7727,7 @@ static inline int alloc_kmem_cache_cpus(struct kmem=
_cache *s)
>
>  static int init_percpu_sheaves(struct kmem_cache *s)
>  {
> +       static struct slab_sheaf bootstrap_sheaf =3D {};
>         int cpu;
>
>         for_each_possible_cpu(cpu) {
> @@ -7711,7 +7737,28 @@ static int init_percpu_sheaves(struct kmem_cache *=
s)
>
>                 local_trylock_init(&pcs->lock);
>
> -               pcs->main =3D alloc_empty_sheaf(s, GFP_KERNEL);
> +               /*
> +                * Bootstrap sheaf has zero size so fast-path allocation =
fails.
> +                * It has also size =3D=3D s->sheaf_capacity, so fast-pat=
h free
> +                * fails. In the slow paths we recognize the situation by
> +                * checking s->sheaf_capacity. This allows fast paths to =
assume
> +                * s->cpu_sheaves and pcs->main always exists and is vali=
d.

s/is/are

> +                * It's also safe to share the single static bootstrap_sh=
eaf
> +                * with zero-sized objects array as it's never modified.
> +                *
> +                * bootstrap_sheaf also has NULL pointer to kmem_cache so=
 we
> +                * recognize it and not attempt to free it when destroyin=
g the
> +                * cache

missing a period at the end of the above sentence.

> +                *
> +                * We keep bootstrap_sheaf for kmem_cache and kmem_cache_=
node,
> +                * caches with debug enabled, and all caches with SLUB_TI=
NY.
> +                * For kmalloc caches it's used temporarily during the in=
itial
> +                * bootstrap.
> +                */
> +               if (!s->sheaf_capacity)
> +                       pcs->main =3D &bootstrap_sheaf;
> +               else
> +                       pcs->main =3D alloc_empty_sheaf(s, GFP_KERNEL);
>
>                 if (!pcs->main)
>                         return -ENOMEM;
> @@ -7809,7 +7856,7 @@ static int init_kmem_cache_nodes(struct kmem_cache =
*s)
>                         continue;
>                 }
>
> -               if (s->cpu_sheaves) {
> +               if (cache_has_sheaves(s)) {
>                         barn =3D kmalloc_node(sizeof(*barn), GFP_KERNEL, =
node);
>
>                         if (!barn)
> @@ -8127,7 +8174,7 @@ int __kmem_cache_shutdown(struct kmem_cache *s)
>         flush_all_cpus_locked(s);
>
>         /* we might have rcu sheaves in flight */
> -       if (s->cpu_sheaves)
> +       if (cache_has_sheaves(s))
>                 rcu_barrier();
>
>         /* Attempt to free all objects */
> @@ -8439,7 +8486,7 @@ static int slab_mem_going_online_callback(int nid)
>                 if (get_node(s, nid))
>                         continue;
>
> -               if (s->cpu_sheaves) {
> +               if (cache_has_sheaves(s)) {
>                         barn =3D kmalloc_node(sizeof(*barn), GFP_KERNEL, =
nid);
>
>                         if (!barn) {
> @@ -8647,12 +8694,10 @@ int do_kmem_cache_create(struct kmem_cache *s, co=
nst char *name,
>
>         set_cpu_partial(s);
>
> -       if (s->sheaf_capacity) {
> -               s->cpu_sheaves =3D alloc_percpu(struct slub_percpu_sheave=
s);
> -               if (!s->cpu_sheaves) {
> -                       err =3D -ENOMEM;
> -                       goto out;
> -               }
> +       s->cpu_sheaves =3D alloc_percpu(struct slub_percpu_sheaves);
> +       if (!s->cpu_sheaves) {
> +               err =3D -ENOMEM;
> +               goto out;
>         }
>
>  #ifdef CONFIG_NUMA
> @@ -8671,11 +8716,9 @@ int do_kmem_cache_create(struct kmem_cache *s, con=
st char *name,
>         if (!alloc_kmem_cache_cpus(s))
>                 goto out;
>
> -       if (s->cpu_sheaves) {
> -               err =3D init_percpu_sheaves(s);
> -               if (err)
> -                       goto out;
> -       }
> +       err =3D init_percpu_sheaves(s);
> +       if (err)
> +               goto out;
>
>         err =3D 0;
>
>
> --
> 2.52.0
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpERcCzBysPVh63g7d0FpUBNQeq9nCL%2Bycem1iR08gDmaQ%40mail.gmail.com.
