Return-Path: <kasan-dev+bncBCUY5FXDWACRBW4UWDEAMGQEP4OJMOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EA04C38E20
	for <lists+kasan-dev@lfdr.de>; Thu, 06 Nov 2025 03:39:25 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-585b3594d16sf582369e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Nov 2025 18:39:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1762396765; cv=pass;
        d=google.com; s=arc-20240605;
        b=iun5XejEtNgDGjcPmtrNBXZ6KsNgpVnmXPqpIumkpCRxBZ9Mj0Rlr6ANQfhbrp9Jrf
         NZ432MfcEsoSelBahQZc/4X85st3ebb7u8AdeDLczIYas36oqeE4wKq2UHbTNQs9gLNB
         0LJ1kGsldwx0UWLG1aRCrGupNpRrHIxEzYNn+5kH6gO57MEFa7o3Nfjd0V5q9F2eulMj
         ysFodrbwJBvjmY3+9iwyzdSKqA2CpG6Kidtab0xsPe3auo4u14Uzv6LlR8FL7wampKHb
         y1wf11vq4xQVrz5gLxbexVq915iLuAnX5QA+4kpbyxz3svUYNq3Z6pOrmHFOBhLP6G4j
         X7sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=zLjehf69wVjFBe5GVThD4GXmQeOoM6ZDPjES6dwN2Lk=;
        fh=uBurwQgEiHDyBGyih6HkaeNTnyoisImfdZlezUBWX/Y=;
        b=kc7iRwizZVyXQrkoExD3jt7KM6qWY0Nn1aiENbgP1gnSZXM/6gNLLuyXHY9hldpS+R
         6wpCs1Lfb6VorqcruWD4br5nbKyWroU5ZrVBRsnrtqRPnNJd7wqjO9UpiF40GsumLaaD
         W12ugLGTJE4kfnGK+M4e/2gasaqWQLa5OR6y8zxDU7PktD07sloYoYTi4pe8mx7Nhiof
         LJxw0+ouCOAn64bFR+hyiS4xWoqeQH3PZAun8bhR559zDIPfZSovicXNGh9sUHHbwmA6
         B42hnTpLGZonSmDCUIJGd3Ah/d1Ii7NKnUP9s8/y+Xshf/krypxC2IKEXgJdLhvmQfxf
         UaSQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZMcg03MY;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1762396765; x=1763001565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=zLjehf69wVjFBe5GVThD4GXmQeOoM6ZDPjES6dwN2Lk=;
        b=c4C2QiU07wbakEV1Z46frwCgCcaJBvweGiVS21LuROl0VR6XLXw/lRl5i0A8XhjRiT
         2UFtyNAAbF2LUFOqCtkANTh0+8ikC0c9+0aCcaaXfgfFypUHUDpxhAxIXItWl4sgrWqI
         lxJ0e56QGo3mV3Hb4egkwtdCVD9nNgB1QQPjRZUij/dGFQiOn7pJPCX1LoPm+kIweq7L
         kkvKCuPirrisyhWCR9Ou1f5MZC9Zjqsfrfj1adX6UV9j6jQ4PjDrIoVtgExQQi03kvQ5
         cQKTBWNRVgIaMJM7xcOXNaCIob+QnP5ZiKkOLSMCQVMY0uN14KyXru/5PtfYGFaIrFfj
         IG+A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1762396765; x=1763001565; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zLjehf69wVjFBe5GVThD4GXmQeOoM6ZDPjES6dwN2Lk=;
        b=OHQPDNpGWNMK29iabDI0E0Stcp7pzjuuR1D7UG9L0Tqtx0OgXSWPsJIyg2U4Fiyp3u
         uBZTFERJy979YriXPOXZwqNsEtwSSq1meTxQ3UY+TzK1JBTVweOjrCsLLg176gQ5hqVn
         +G2XeedTeCXDPhTxJaALfeydsuGGeM2qPvSzhvdPCf92dPVmBDZ7r6D5fojVI5S2y/CI
         v/MrGwB6Sz93HaLL0D285ZZb/tdreFKiJjErS5QY8avgh5Al3v33a+4nsRf5gI2rszwo
         j+u41ItagSHtIAB7QGM0tDLbFsAWZNKmTUoIS+tnPJUkBLc/tkaa+gorI6ZrtmJgCeWF
         rF0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1762396765; x=1763001565;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=zLjehf69wVjFBe5GVThD4GXmQeOoM6ZDPjES6dwN2Lk=;
        b=VTGRxMVHxblDNohLYhxA06oeVxDRAX6TMMnrtvsLdmubRQK0lFm5rM4xwKzTMKl5y6
         kntOiZTF2xYenrB4dbzK4d2XfC5D0HoNBS3jB08P1fp50Eh3miKDb78I4qEXZAekXK1S
         qGH8RwfA2REzuoSHWDPtRe4HmDqEgF8A21z3+kApNYUsloI/o+5UoU2oWEZct3Ukzdsx
         p9NtRzSfSMDlGqG+QG04/wNixtfKoyQCL8jxFkPF4+9IMw0tDJznwo1y3c42OjXw7Fzd
         lGngZojDK1cuoHSZnvocltxa4/uDTpGBFjaRPFILlHxFoh/THHYe1/EBTBhTlS6JW4Qu
         TvxQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVi7rg/C/72o4gOOeAugu9VVVnfasarN3azrMEfmPAtK6/eWXrFe5PrdLzQ6BLtlswFbGz9GA==@lfdr.de
X-Gm-Message-State: AOJu0YyxjhCLD2XtxoLTLeQkvHrRL8f9EX05M41FbQgCm+7sChuXC+Aa
	Tqo7lZr9hM1oYbMnX13ZYBZiMlCwo6b0OY/+EHGDdzKvBpaYcVCBjWMz
X-Google-Smtp-Source: AGHT+IHRDeiRK3eO7r+lC8OJZ5K3mBfodaVlcaCw5IrkmHOhbIKiKh+NMGwlWD9pMWHmlY+mPEeEoQ==
X-Received: by 2002:a05:6512:e89:b0:594:27ac:f39c with SMTP id 2adb3069b0e04-5943d7e6c26mr1828861e87.51.1762396764299;
        Wed, 05 Nov 2025 18:39:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+a/5npEML57Vt6x94GxbTU2LxOnxncAM92jBWfuOwEFjQ=="
Received: by 2002:ac2:568e:0:b0:594:3627:89c8 with SMTP id 2adb3069b0e04-59449c8016als283499e87.1.-pod-prod-08-eu;
 Wed, 05 Nov 2025 18:39:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUiKBfog7IzgjDyrLykLIefyeckG8mXGgSpn1FdkZPt74mwX5otmLM9JyeCFCrwIAMSQGvDAau5R20=@googlegroups.com
X-Received: by 2002:a05:6512:2390:b0:594:2d64:bcef with SMTP id 2adb3069b0e04-5943d55dbeemr2038051e87.3.1762396758150;
        Wed, 05 Nov 2025 18:39:18 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1762396758; cv=none;
        d=google.com; s=arc-20240605;
        b=a4SM9ZcxsBbiZLmL7H4h6zilXWXC+tjbvLgBJP2yP9lYb8iNry+oyiP+nJBCDcgjHd
         CMD4di9NseAdmYC8yEARnYoRFIJHQqQ6EyRwJdalDFRvyDtF+Tt8hNF1eG1sVqXBajbQ
         5GANsQUBZmOVBvXAKFQK5bhlhnBjjAhu852+8LHeyORNAD+9dIEr7OP1scmZtv+4JdJZ
         tsndLq/WZSfEgX/7ybtBAOp47s+4M9SxsbjfRLhDYXjfoP4hGqc/YdcDMw4A5XRT5/ml
         yQUkiO42XKPVa4tyBhB+3FIJ7BA20YFGFgyVVDYrpvkqmBW/9zloxzOQZOX9Zdbew/l7
         b5oA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ewoAJCSF8NH/dTxpovl4STEPgaBdVGC9xI+etM7pZH8=;
        fh=KLuhKB2Ax7yI1+IP8Ad7AjeDYtiiZnI/S5A3taB4AQA=;
        b=djgBdJcnR+tJ+podHKeuEQgTmnwEr9SPzA1OH8xZZ+jjnyyxyC6qnrwFNnf1b/5B6C
         OgZTwzar1dLCrDZChhsGAws2hUJCD7C9cEoEJsVue4qOsIF0aSFz0M265VyTZdgBvLzJ
         Vt4WuqCBhsi+OzjZtjZWuN0OE5zfWfZjQH9GAdrhfBNUx5J7EMiK4Sa6ub44y3ywaSEz
         fU5DI2KjwjS3UKhXLbcgjehkCqLT2Yd4ico2G48inzBQfe5hcT1a0uhS7GN7qq/UnS4C
         DiYR1MtI+idR0izBoXfIRQOZ+0RSh1viD0G/CpLUgHjiE4X81lpREEbWi7qz9EF+dcDq
         nyzg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=ZMcg03MY;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59449ff86bcsi12101e87.1.2025.11.05.18.39.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 05 Nov 2025 18:39:18 -0800 (PST)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-429b7ba208eso285542f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 05 Nov 2025 18:39:18 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCW8yrhTgV4CAReVoRjKgjtXczmYjxY2M8FvkyaXkqxP3MyX7dEsheAUMe+4IOGNWPUI/QKV7IT4aTY=@googlegroups.com
X-Gm-Gg: ASbGnctT2co/IMoPzRNdPNjepZwSliUwf1HKh8D2nrOwNrJwL9wcFGhx7PfPy1O3cr+
	0LxBVaNPgmzJeZ5yFWs7ISlhYFSNCOEnUhkxUdWV9tdqUUTVE5eF4vdVLghOzaFD6hMhHUnWJtC
	Eibh4yLiDegmSqfa53pQ1Malr7WwJDog3340w1i4t7crU3bFbawH2PHcy8M9rGUBhVWn3f2Y7GZ
	U91W8REZuWNPJm/EJIp5qdmhOFi+/6WH9xXu5wVjBT51gtfS6vsNcQqYahiMngIssYhTJiKTvOH
	oqJ4DLeKpYj3hX9nfUarRf9mRmSx
X-Received: by 2002:a05:6000:2dca:b0:425:75c6:7125 with SMTP id
 ffacd0b85a97d-429e32e36eamr4631215f8f.16.1762396757374; Wed, 05 Nov 2025
 18:39:17 -0800 (PST)
MIME-Version: 1.0
References: <20251105-sheaves-cleanups-v1-0-b8218e1ac7ef@suse.cz> <20251105-sheaves-cleanups-v1-2-b8218e1ac7ef@suse.cz>
In-Reply-To: <20251105-sheaves-cleanups-v1-2-b8218e1ac7ef@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Wed, 5 Nov 2025 18:39:06 -0800
X-Gm-Features: AWmQ_bnDlj12yke_m0UY9rM9to7dPxs3SzBTZ6_PfSj5mhKDDRMWfaCanTzBLeU
Message-ID: <CAADnVQJY_iZ5a1_GbZ7HUot7tMwpxFyABEdrRU3tcMWPnVyGjg@mail.gmail.com>
Subject: Re: [PATCH 2/5] slab: move kfence_alloc() out of internal bulk alloc
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Harry Yoo <harry.yoo@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Suren Baghdasaryan <surenb@google.com>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, bpf <bpf@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=ZMcg03MY;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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

On Wed, Nov 5, 2025 at 1:05=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wro=
te:
>
> SLUB's internal bulk allocation __kmem_cache_alloc_bulk() can currently
> allocate some objects from KFENCE, i.e. when refilling a sheaf. It works
> but it's conceptually the wrong layer, as KFENCE allocations should only
> happen when objects are actually handed out from slab to its users.
>
> Currently for sheaf-enabled caches, slab_alloc_node() can return KFENCE
> object via kfence_alloc(), but also via alloc_from_pcs() when a sheaf
> was refilled with KFENCE objects. Continuing like this would also
> complicate the upcoming sheaf refill changes.
>
> Thus remove KFENCE allocation from __kmem_cache_alloc_bulk() and move it
> to the places that return slab objects to users. slab_alloc_node() is
> already covered (see above). Add kfence_alloc() to
> kmem_cache_alloc_from_sheaf() to handle KFENCE allocations from
> prefilled sheafs, with a comment that the caller should not expect the
> sheaf size to decrease after every allocation because of this
> possibility.
>
> For kmem_cache_alloc_bulk() implement a different strategy to handle
> KFENCE upfront and rely on internal batched operations afterwards.
> Assume there will be at most once KFENCE allocation per bulk allocation
> and then assign its index in the array of objects randomly.
>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> ---
>  mm/slub.c | 44 ++++++++++++++++++++++++++++++++++++--------
>  1 file changed, 36 insertions(+), 8 deletions(-)
>
> diff --git a/mm/slub.c b/mm/slub.c
> index 074abe8e79f8..0237a329d4e5 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -5540,6 +5540,9 @@ int kmem_cache_refill_sheaf(struct kmem_cache *s, g=
fp_t gfp,
>   *
>   * The gfp parameter is meant only to specify __GFP_ZERO or __GFP_ACCOUN=
T
>   * memcg charging is forced over limit if necessary, to avoid failure.
> + *
> + * It is possible that the allocation comes from kfence and then the she=
af
> + * size is not decreased.
>   */
>  void *
>  kmem_cache_alloc_from_sheaf_noprof(struct kmem_cache *s, gfp_t gfp,
> @@ -5551,7 +5554,10 @@ kmem_cache_alloc_from_sheaf_noprof(struct kmem_cac=
he *s, gfp_t gfp,
>         if (sheaf->size =3D=3D 0)
>                 goto out;
>
> -       ret =3D sheaf->objects[--sheaf->size];
> +       ret =3D kfence_alloc(s, s->object_size, gfp);
> +
> +       if (likely(!ret))
> +               ret =3D sheaf->objects[--sheaf->size];

Judging by this direction you plan to add it to kmalloc/alloc_from_pcs too?
If so it will break sheaves+kmalloc_nolock approach in
your prior patch set, since kfence_alloc() is not trylock-ed.
Or this will stay kmem_cache specific?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQJY_iZ5a1_GbZ7HUot7tMwpxFyABEdrRU3tcMWPnVyGjg%40mail.gmail.com.
