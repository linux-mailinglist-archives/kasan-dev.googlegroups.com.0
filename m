Return-Path: <kasan-dev+bncBCUY5FXDWACRBB4IR3EAMGQE4UTZSWA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 57CA8C20EC5
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 16:28:09 +0100 (CET)
Received: by mail-lf1-x139.google.com with SMTP id 2adb3069b0e04-592f9f4d60dsf155257e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 08:28:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761838088; cv=pass;
        d=google.com; s=arc-20240605;
        b=XisN+HdaOfl3IpqS/csfbuDdLDWlaAiqnqkytVFFD+XkFuPGhDu2TU7RJEnInM3ukT
         rVanpQOik+y82poO4SI2zQ8uTaU/DJcLYENh/gUvZLO6hv6poLFK+wY11HVfNGypQjEt
         EPYDEi4Nk0vyHiLpfVzrij1jA7exVbYlksLGcfm/qZbHQsQR59V2a+qnc72CN0Pbcjz5
         FZiTP2GDa0QtaLxOw7sGYuMPFGDADCIK5C8lXf0twISdxkJNazDzTe+Fh1HEakoVlI85
         TaxtxdJthfPGJpoNcLxaazBWKhsIrIfjjb6uVrGkain2DMRLAvrL43td7RREn1oW5v41
         2tJw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=vYIGbLF9CPXu4GVM6XDoLSICkpUtAAu9IhY5ZCp/7JM=;
        fh=SI8tH11juKcIlorL+SAXKb7HP4T4m8YXXZmcJGFPpTU=;
        b=ahFQnXXWKiqtJbvWLuqcqoxQEQ9lkNeIbpgrRPSYih4Su6o8g4NZ/f/CSay0jW9P85
         VSWk9sQhts68qHe20O8B3XZl+EIwSXcjnJS68Q1Nugtj9h4+MRwV+K0BRVrN4ukOZv7d
         LULE9yR+6KxljSGUw92XqR9KTklPXrkBNj7JS1l7LiGYROVjPNG/Kt4SuMDOTMiBK3i9
         gLMNqA99hM4xZx+lRcZWusROX6K38lVIhlYC2aWxYHFGOqT8oKkm3qfotTUYKk6946z+
         ziVkUP+O5XD3uA3XIsGRac5iaxtQMYOExDy3cbCXQ/6lvaZ//imhWIzZ1AZWtkJJQJz/
         zouw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Znu5k311;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761838088; x=1762442888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=vYIGbLF9CPXu4GVM6XDoLSICkpUtAAu9IhY5ZCp/7JM=;
        b=OGwDxsKsx+yZyQkeiM3O95lXrNoLrr+sDsnbbysmPa/uTugt1taeeRR1wtEi0S4N9+
         tcCOcTF/eIn4DyYkq6Qy1GiRLiSsTTcTN2hWxQ3kPOq368NNPbKonFfCp+bBUV8SUNpq
         6xY8ofo9bO1w8vvM2BeH6jovK9GN/50ccftoxXhnHYADpoH0bu2mcuk/jXD6kAfj3DO3
         TBMOhjlAiEbyMLksY+IVrQGJPbt+MiyP4VDZFTj12hnSGG/bKMr1JALEd3knAhcm4Q1C
         DFGv+YtUh1bbOwnhkBlDinsiLzhNR9lUNlzfNRS6a1chrwRYCKGsFzJ+qiYVVCPN7mFc
         uoGA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761838088; x=1762442888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vYIGbLF9CPXu4GVM6XDoLSICkpUtAAu9IhY5ZCp/7JM=;
        b=UaDo6wAmNhCSH235wUbmDFjbAewfx4oTP4Q3okHIc2avyHRLrdonIAK4Z1w6xOESmR
         UmkOQGYZck/GCP9Be1a/aNvzcb49vu+9P0GviQ6Y+0aShwrF4QSYg+KefRMoXf8o/BfQ
         t6SJt6umKOP18BetL3ROSldr5c3BKZiOdfWsdAZ2MWSiZ2K55E0g0G+prJ5g4k5B1FQP
         l+lvB8TCSblLzVAGMeH8BoeCwi9ecU8YGxeanYqvBc61EE81+lgv5xXKeG79827JKkG6
         kUpTBpFXqlVP10b9Ne/CSzedrPe9U+9VA2LsKNNwzL6XWeqChdMpXVFYrSpcckAT5L4N
         rWVg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761838088; x=1762442888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vYIGbLF9CPXu4GVM6XDoLSICkpUtAAu9IhY5ZCp/7JM=;
        b=qSSCq3+upWl2kpP8VF5lJDUP728VTXkcmkzlotVsTISeOZtTOBOOInPZXj5bYJfbGt
         6j4VdaY4pL2VLwlYboHCBmut7Sb7s7cLGBwxdSIn5g0mJ1dB9EEFY9OEH/I5wGCYHa9E
         bsR8WcQJIFHymtOAHLUQyfjhu3i/r5CkfZTCOWpJr2YypLE4miii4uGo8u5gwi6Er4sl
         TdpLkL7i/oejSYUvV/Z6kdUN3fiMMxQZLSPXyFNb5DST7fFCauK4zRLWqooIY3Aid67P
         eO23F6tid+iqyNxedAmfuNprhi6HCBhHVa0HTY5OxXz4WNnRb3V5ROKAn/8qsFND/98q
         SfNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWQpeNO3ppkCZsZ5smmkDZtu5wmj0j6LYqA06/7rXMWgWwg/nyMA147qLIwrqEpZQ+4hBID3g==@lfdr.de
X-Gm-Message-State: AOJu0Yw1ksO3yDiqZE6EdQ2t8FOVG1/iAmrOc/0IbBC6S6oiRdf+C5I8
	qNByqrxUJiWLzPhwLOxM9+FbCG5pQweTh/88fn6x9b6dfMx++b/fu4oM
X-Google-Smtp-Source: AGHT+IGmdEemWhFCqGp0bjlQ3jmv4VnKIUCHNRCVKPHyirH/PqtGNbztvPAGd2s5JMqfRynm8Wykrg==
X-Received: by 2002:a05:651c:3259:b0:337:e43b:655b with SMTP id 38308e7fff4ca-37a18db90efmr379891fa.2.1761838088299;
        Thu, 30 Oct 2025 08:28:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+ZQwDMrIQlRJ1eRG1VQwmzUnPx6117XZovJvCvO0WIYKw=="
Received: by 2002:a05:651c:91:b0:376:34ae:d65e with SMTP id
 38308e7fff4ca-37a109d38a4ls3418941fa.0.-pod-prod-09-eu; Thu, 30 Oct 2025
 08:28:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU1gJL6QGuxnbpwCKHGGjNMk7pf5jBkB4hj39BvEqTJV/w8lfDitvy0ozQSZzhAjT/oxSJs+N2TnWA=@googlegroups.com
X-Received: by 2002:a2e:3010:0:b0:378:e3e1:c2f2 with SMTP id 38308e7fff4ca-37a18dc758dmr566381fa.27.1761838083890;
        Thu, 30 Oct 2025 08:28:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761838083; cv=none;
        d=google.com; s=arc-20240605;
        b=gZVnGAfe9evraVawfk4s6qGMOp9Pf0F9eYVLjTA9UnuNsWpB2Uej0C+NtqnAZLGROv
         HjGYnKs8R9LWsEXWDWh4clUVhhkYg9VWz068Ua/DozXy85mUEg7gGKgvZKyBn5555dY+
         9fYkY86iGSZRVH4Chjs1mN2tBXoIwWR5bFykxVdlkaoT79kj8YNvT7PGT+1lW478zsTW
         nHKQFni+neXH536yJGSOffEkOtRVrcqf/lEZCQ2FhL7ljOKXO7kjlbuFwrot7D45ci6m
         GBz90q6Xvo2N/fGNLjR1A7bS86jHHyJuF81tlKpLhFy0JryfYQuvyhUHv+nULfy0hDdH
         GRQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=17s53pVmMkcMZT8ne5HIpndSpVg+pfPjrs/QsaSS0o4=;
        fh=zRjOVfczMIiKTwMCptg9dYBm68zhQZGiRboyFca/ZTU=;
        b=goaIpLzEUlN9EaS83YaTR+7gj57wwhrL8uaWyXJfJQCs0C+K7RTRHK6/DW1zHW4Qty
         LC2819IhLAGr8tAI9cu91Jtkpt6eeD6BJOKy1fUOpu6gyDDRbqYbkiuMiR/nsfTgLqyN
         NdHWO5zdfKOaXX1rpZdXij2nBvpi39Clcpo+mRnGPnKbjC+uGP9ia+CD0PKOwsDVsjZh
         PxxGSzUU9JWJoiBLluf0p+7iHJPQRPuYY5+LQX6ASjrKXi8l1XTCfYpmuQOReYBircUJ
         U2TzYVDeBbsPQal9t8+2szgbx/dgeVTkIkhksWZ++2sHmR/FCYmsMItPfYUlo9kTIDI7
         Pq1Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Znu5k311;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378eef28281si2654211fa.5.2025.10.30.08.28.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Oct 2025 08:28:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-4270a3464bcso921837f8f.2
        for <kasan-dev@googlegroups.com>; Thu, 30 Oct 2025 08:28:03 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXByZtq6ftsecK8Is3irLrYd38tNd2MBl0EqDssla2qfYt5SlqQjzWF0/RpLnR0WxL0CylPzDleGqc=@googlegroups.com
X-Gm-Gg: ASbGncuPJIL7javwT6gONNDqZEU9rPxBH2RLrxPQk4VaR/ITKwzWUxuQTQmDS7eYEbY
	+6AXft7pnIqsjyTgs7irBg2XATHW6ePFAyxsNnuH7IXXhKhL6bWKitcHEhzpa5UY4WoKtnFcsAY
	TNhnOr03ZxJ2HZboOwFTumKKaZgZaGgtYfM2f+wdKSENaJfxKZ+bjUa22W2N2r0j4cIEoyctRX2
	LaSkJQbxPTbroUm9YC5CHGxpqTHG5nMBViuOXCA88yP9fEX+aaX2l7iQEtn427FiGm1xGPs2TdN
X-Received: by 2002:a05:6000:2006:b0:427:847:9d59 with SMTP id
 ffacd0b85a97d-429b4c9ee68mr3815611f8f.45.1761838083095; Thu, 30 Oct 2025
 08:28:03 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-10-6ffa2c9941c0@suse.cz> <aQLqZjjq1SPD3Fml@hyeyoo>
 <06241684-e056-40bd-88cc-0eb2d9d062bd@suse.cz>
In-Reply-To: <06241684-e056-40bd-88cc-0eb2d9d062bd@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Thu, 30 Oct 2025 08:27:51 -0700
X-Gm-Features: AWmQ_bnX5zwf36gXg3U_L6nD0Y-OhNsAUiH1Wv4xcOqbTsg1lnruV_RapPX3X1o
Message-ID: <CAADnVQ+K-gWm6KKzKZ0vVwfT2H1UXSoaD=eA1aRUHpA5MCLAvA@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=Znu5k311;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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

On Thu, Oct 30, 2025 at 6:09=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 10/30/25 05:32, Harry Yoo wrote:
> > On Thu, Oct 23, 2025 at 03:52:32PM +0200, Vlastimil Babka wrote:
> >> diff --git a/mm/slub.c b/mm/slub.c
> >> index e2b052657d11..bd67336e7c1f 100644
> >> --- a/mm/slub.c
> >> +++ b/mm/slub.c
> >> @@ -4790,66 +4509,15 @@ static void *___slab_alloc(struct kmem_cache *=
s, gfp_t gfpflags, int node,
> >>
> >>      stat(s, ALLOC_SLAB);
> >>
> >> -    if (IS_ENABLED(CONFIG_SLUB_TINY) || kmem_cache_debug(s)) {
> >> -            freelist =3D alloc_single_from_new_slab(s, slab, orig_siz=
e, gfpflags);
> >> -
> >> -            if (unlikely(!freelist))
> >> -                    goto new_objects;
> >> -
> >> -            if (s->flags & SLAB_STORE_USER)
> >> -                    set_track(s, freelist, TRACK_ALLOC, addr,
> >> -                              gfpflags & ~(__GFP_DIRECT_RECLAIM));
> >> -
> >> -            return freelist;
> >> -    }
> >> -
> >> -    /*
> >> -     * No other reference to the slab yet so we can
> >> -     * muck around with it freely without cmpxchg
> >> -     */
> >> -    freelist =3D slab->freelist;
> >> -    slab->freelist =3D NULL;
> >> -    slab->inuse =3D slab->objects;
> >> -    slab->frozen =3D 1;
> >> -
> >> -    inc_slabs_node(s, slab_nid(slab), slab->objects);
> >> +    freelist =3D alloc_single_from_new_slab(s, slab, orig_size, gfpfl=
ags);
> >>
> >> -    if (unlikely(!pfmemalloc_match(slab, gfpflags) && allow_spin)) {
> >> -            /*
> >> -             * For !pfmemalloc_match() case we don't load freelist so=
 that
> >> -             * we don't make further mismatched allocations easier.
> >> -             */
> >> -            deactivate_slab(s, slab, get_freepointer(s, freelist));
> >> -            return freelist;
> >> -    }
> >> +    if (unlikely(!freelist))
> >> +            goto new_objects;
> >
> > We may end up in an endless loop in !allow_spin case?
> > (e.g., kmalloc_nolock() is called in NMI context and n->list_lock is
> > held in the process context on the same CPU)
> >
> > Allocate a new slab, but somebody is holding n->list_lock, so trylock f=
ails,
> > free the slab, goto new_objects, and repeat.
>
> Ugh, yeah. However, AFAICS this possibility already exists prior to this
> patch, only it's limited to SLUB_TINY/kmem_cache_debug(s). But we should =
fix
> it in 6.18 then.
> How? Grab the single object and defer deactivation of the slab minus one
> object? Would work except for kmem_cache_debug(s) we open again a race fo=
r
> inconsistency check failure, and we have to undo the simple slab freeing =
fix
>  and handle the accounting issue differently again.
> Fail the allocation for the debug case to avoid the consistency check
> issues? Would it be acceptable for kmalloc_nolock() users?

You mean something like:
diff --git a/mm/slub.c b/mm/slub.c
index a8fcc7e6f25a..e9a8b75f31d7 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4658,8 +4658,11 @@ static void *___slab_alloc(struct kmem_cache
*s, gfp_t gfpflags, int node,
        if (kmem_cache_debug(s)) {
                freelist =3D alloc_single_from_new_slab(s, slab,
orig_size, gfpflags);

-               if (unlikely(!freelist))
+               if (unlikely(!freelist)) {
+                       if (!allow_spin)
+                               return NULL;
                        goto new_objects;
+               }

or I misunderstood the issue?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQ%2BK-gWm6KKzKZ0vVwfT2H1UXSoaD%3DeA1aRUHpA5MCLAvA%40mail.gmail.com.
