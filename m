Return-Path: <kasan-dev+bncBCUY5FXDWACRB7P457DQMGQEJSWN25A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id D02A1C083ED
	for <lists+kasan-dev@lfdr.de>; Sat, 25 Oct 2025 00:32:31 +0200 (CEST)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-37773b477c6sf18642421fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 24 Oct 2025 15:32:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761345151; cv=pass;
        d=google.com; s=arc-20240605;
        b=iVLl8H0N+nOWhUBcDhrvdplkZ+HZoNcLUWjjC5eKPzp2a5TOUYOJgJ64mSB1B4iefn
         f7qVU1J3Ut5mmMzgbd1EE7HsJLzwWBZXoTNpbtycjJjf6sPsfgGq18RUTlPNRSsbgKK5
         HZLionu4e+gcCSraWLYuxs3Lp6GsE7L+QxqdGUloehDiKDgy5r5jaZI0IpQ+Tg4Vmy3Y
         EGTbch7arUOO1ups0C1J08GFXI5xo/YQGNyqHtRAcHJE6UkbLkl0nYEjd8lmoQcY9dKC
         Lba9Ep6tisfK4iU5NmW1Rfkh4IJST5zHHKNch4te9oUZx41o0+aMN+y/rzDFRa3dTDZI
         tB3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=XiCKLyfcFT8rEr0OWWw98PLtuxiAKbUhOp1ZQYvvwoA=;
        fh=3GVi2WrWKkO5lhXOetCKyU819yXeUdl/XETO0DBO1rA=;
        b=iHoqQFI/Y7klMs0osV9HHYpc4OtSNsWL4NMJR8HjEMsc2OkoWOXBUvDCPnWFKtHtkt
         rSJ7veS/hnvucFmNH3/EWxXpRHWFQnjO7VJut80yc45CY45ac8ByhRG8TO7xxpqf1xOR
         +jinW6oLcxiYxqe+x1dnagZEMTmF8VTOGmLYQBW3WyPa22ErhtHRKHHD5LrzyOgRPRkL
         W+Ig7S5vS0TlE2VvN98BesZve0H1iRXoLd4f3t5SUYSFYpsMmb7UbisS4PA7E4rrEg5z
         2z8bn+7mRaFNFw66Mz8pcrv7YJaIX23PA3d4pbL04MrLI1Act1pjiCzm4ngeHfWVJPA7
         M+GA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GVXdUAOI;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761345151; x=1761949951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XiCKLyfcFT8rEr0OWWw98PLtuxiAKbUhOp1ZQYvvwoA=;
        b=J/KaPh246DtYWJzQYoF7bRsbTDZqPZ/6NX20sKyJpL2kz7o6nDJMBDggSqi3u+1xtn
         edpLa30nlCtHJWIfJGkYK1XOQT6dMWP/Qbm0ANuDQA6RcFNLjYpjGdfmzdAv3cnPjBxp
         run6HNn8qLHi6nWFq1rNovmOh6AbsZJzm96ube5pXUQYlIaZRaVUV4QO0jMBPjUmcemS
         uKBS7gM6AnruhCxbp1qDvImVzp4/1r8vY1wcgfZllfX/M0HNxgryHzom+8Caw8bsSJkU
         FHhiZ//BC2/5M5x/BK90TL+LfnhSnipN3nMmh6X3vNilGENACpE5p6DPllHCdtxIwf09
         Pi+Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761345151; x=1761949951; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XiCKLyfcFT8rEr0OWWw98PLtuxiAKbUhOp1ZQYvvwoA=;
        b=EDB/UEKe5u7vNgjPoSS99ewsJdBb76wqTHU9YjcPicq2AM0n83tZoLCoulmD+ESCo6
         C35LwGXf+vStYwQIx59oxyw77aEJchAghbgG8b3buFb/uo2RnpVZJU2o2iUkY6K2gVvz
         ZLFLc/H3Ths4LHX9OzGojMvMjUfFvyc6mhs0TCWDPJdotLbfGDOF84N/k1hqcZzp1yIX
         spUzV2QXGUbgH14AmzCy2Ao+uzFEY9Np+HkPxDDnQqweX5v7mM9lKi3EVumrSokc1mhz
         G43/vUjNMAlAE/IJQf9ia94fYS+yNastqWdW5OoYNK/T2xygmD6lZuPgr/GG2lHoEoqU
         TYsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761345151; x=1761949951;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=XiCKLyfcFT8rEr0OWWw98PLtuxiAKbUhOp1ZQYvvwoA=;
        b=Zh0b0OroaEpNdFQFXeF3TxVaRnJ6sUOChEZKvO5O9WBaNfFZ0Rzhdmk2j3uaTX9mgR
         V311nz9iTtoPoeNb1Veqm7Xq31mDPBp5o+OaiowATKzckbDAbX3qbFDQcwpA2pSBT7J2
         FUFukX1xEDuVGgejyVigoT8a3ljkyKeZtcGwN8od0yZWl3boHVx7O13gR6ijVYVzc5pe
         SCYW+X1qptqKow+gur7o/y/70it+2PumQ7RVCgSMKVFTuXnS3QW9mEfW0mq3Oc0yDeDd
         RcIl1ba6aeeQE/1dlUQXg/WhHgo4ffT77nZNPtiQkhiUnbmU6bOI23mblxi2tu+/qSIK
         Nt/Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVr069TpE9CmfYRryFRvMEZXVE+H9fxQ9y72OgkHIa0qsE2LIkcnhVn5nzn6B1+gQCXQ+W0rQ==@lfdr.de
X-Gm-Message-State: AOJu0YxqC584o9qBM8IYHjTGYW+0kpNOKT4eTbl5UKKIM6n/lpd/kasi
	xZ6sjM/GAp7PrVKowo47ot2ovbtj1yJlStRPIbuIeROmCMMHFmmoL/6I
X-Google-Smtp-Source: AGHT+IG1xiOgAXTnF+rfdkMeglhtahABUc5zE+7BDFEVJpJ9TJYbvtFntsuhf3OsRCiGYJHPQYpJ0g==
X-Received: by 2002:a2e:bc01:0:b0:378:e8d1:117 with SMTP id 38308e7fff4ca-378e8d10503mr7920231fa.11.1761345150643;
        Fri, 24 Oct 2025 15:32:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+bAxfVCRQ/FWkX++tqxkRqV/ziN029IdmuZn5YhD7lF2Q=="
Received: by 2002:a2e:330f:0:b0:378:cdf7:278d with SMTP id 38308e7fff4ca-378d64ec97bls8133941fa.2.-pod-prod-04-eu;
 Fri, 24 Oct 2025 15:32:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWmdaZVZzlKdvpouhD0e31A1o6t3sqBgnkRE7QifRbffBvFNyfXotteEoeoS7jSrS2xKU2rHt8Nhng=@googlegroups.com
X-Received: by 2002:a05:651c:1612:b0:365:d56c:bfb with SMTP id 38308e7fff4ca-377978f4288mr98301551fa.21.1761345147263;
        Fri, 24 Oct 2025 15:32:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761345147; cv=none;
        d=google.com; s=arc-20240605;
        b=SwvMcbh+Jsng6ICNLEKQdWXte0zRCeydWhBI4uBk9qFya6QU7knUzv3V87ctTKCLiK
         KvHg0XLUvA4utDRXo6Nc6aPKMT1YGi2T+KVe5VloKnHUB8ZT4bGzIbTxTTrGqViSJ5wA
         yECoqWpT8CSiRop5OtRuQbjP8AQx89S/Y6UCll3e0wKtDRslN+ZXM26CX2mi8ZI5EojA
         t7Yty+ObmVNHgmJDAvnn6XJWb3BB5E3Hjb/C389Yv+Dta1wQWRTYCB34tlj36NGpDu0q
         KAh8Yya2gH451lB5v1E7TgChCc39lGfw832au0EJu4EuGYAfoSp9XkP7e6zYStg0iqvv
         lw1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=HUfYp53fu94dUtqrZRLYGe5gVG2u++6KcY9W1vIJxhk=;
        fh=oeE202bFvyg6UfhsLlJR1aOQpDdUagVKeBTm6j1lfSU=;
        b=diLUlyytBvapX1dK97Cr3BbDNM+wlsXG4G6eX7xgImFjdw2fPNnfI1zJoxeGnHSDVh
         +czFrmEfuVj02vNFPn7PZHC4F6/Q6QivOEl32TFbrDxAA7AbVT+Pzi9wloQL8TI62ewO
         3A4i20XwKo00w9iPFTMSUja64Key2muXYyPqmUJw6QiH57RTwOqJ/oa1EB3wGR8EoD6s
         U7lt55K7ZFbp4W0cPmWjCO5K7WyMUAXc/7VoF4JX2TeS/HY540z4LOippK2oDjxiT0sH
         luIfMAFPiifeRuN6r7Z1wLqVHnZBTXnqUPq5rWeFMBD6O2/zZpdWEvaRjmUTmUBgSDoI
         l79g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=GVXdUAOI;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x433.google.com (mail-wr1-x433.google.com. [2a00:1450:4864:20::433])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378eee33722si15821fa.2.2025.10.24.15.32.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 24 Oct 2025 15:32:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::433 as permitted sender) client-ip=2a00:1450:4864:20::433;
Received: by mail-wr1-x433.google.com with SMTP id ffacd0b85a97d-42557c5cedcso1818752f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 24 Oct 2025 15:32:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWbLa9lZd0f1YFFPeLRicF1xM3/wMPoA9OEYji3cJ2dP2z17r1kcxZGK+dfmo4nsGEFuq/u4Zhv4KU=@googlegroups.com
X-Gm-Gg: ASbGncv2s7nHzz2Ug8z+V1oxmrJOKxsIserQG4Ghrl5eNPqDS9UKVkZIHM/Tu0fJad3
	uw/4ygKViEtAL+7rndlxwf/eIywAj4weS5uFLYVX0zOgXie0CAWTSDjl1Z7sGdyMUhFQE3UBWZ0
	PXnipPEEoddGDiBozmj/bE86E868iBhZqhIkLISQjRCCyoz1ynh17tm5hNWsmDUbChuyfu30Gfl
	Oh2wZOtH49Y05RjkH8OtIvQgmJzPBq3G/An7ltNoR3UgGSINqP7VrMu7g5lTetajp0NaFA39AJL
	7wxbkF52uLBcoh1//Q==
X-Received: by 2002:a05:6000:200c:b0:428:3ef4:9a10 with SMTP id
 ffacd0b85a97d-4283ef49ddamr18538286f8f.54.1761345146453; Fri, 24 Oct 2025
 15:32:26 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz> <20251023-sheaves-for-all-v1-12-6ffa2c9941c0@suse.cz>
In-Reply-To: <20251023-sheaves-for-all-v1-12-6ffa2c9941c0@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 24 Oct 2025 15:32:14 -0700
X-Gm-Features: AWmQ_bmYxy3mKLZGuaPpnI1v7zjS22cZzV3kwSBj_coWNlSrdgc_1YOXiQjgS1Y
Message-ID: <CAADnVQ+nAA5OeCbjskbrtgYbPR4Mp-MtOfeXoQE5LUgcZOawEQ@mail.gmail.com>
Subject: Re: [PATCH RFC 12/19] slab: remove the do_slab_free() fastpath
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev, 
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=GVXdUAOI;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::433 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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

On Thu, Oct 23, 2025 at 6:53=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
> @@ -6444,8 +6316,13 @@ void kfree_nolock(const void *object)
>          * since kasan quarantine takes locks and not supported from NMI.
>          */
>         kasan_slab_free(s, x, false, false, /* skip quarantine */true);
> +       /*
> +        * __slab_free() can locklessly cmpxchg16 into a slab, but then i=
t might
> +        * need to take spin_lock for further processing.
> +        * Avoid the complexity and simply add to a deferred list.
> +        */
>         if (!free_to_pcs(s, x, false))
> -               do_slab_free(s, slab, x, x, 0, _RET_IP_);
> +               defer_free(s, x);

That should be rare, right?
free_to_pcs() should have good chances to succeed,
and pcs->spare should be there for kmalloc sheaves?
So trylock failure due to contention in barn_get_empty_sheaf()
and in barn_replace_full_sheaf() should be rare.

But needs to be benchmarked, of course.
The current fast path cmpxchg16 in !RT is very reliable
in my tests. Hopefully this doesn't regress.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQ%2BnAA5OeCbjskbrtgYbPR4Mp-MtOfeXoQE5LUgcZOawEQ%40mail.gmail.com.
