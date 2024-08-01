Return-Path: <kasan-dev+bncBDW2JDUY5AORB6UKV22QMGQE5HUG5MQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id C2F01944BC3
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Aug 2024 14:54:19 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3687eca5980sf3085051f8f.0
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Aug 2024 05:54:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722516859; cv=pass;
        d=google.com; s=arc-20160816;
        b=x36+XZDaYNPzbxVxMsWV2gBtFv3FoQey5jBletrXTY9/pzPAGppTqhgphPkeUAg2ie
         uNqok7SziPeR+6gA/GQuKFHO02kSkxGExlDMsIPYlQNmKnupDzfcX4W+K110fQFrt2pT
         UW1NU8k2gAuJ+dHn16l88KQGKoexuMk48SlmBbbPatjyDsYSzfOw5gu+Tc7KLNRAV/Xl
         0BmqXl4nt4UaB0lKBertP+EY+BbOKPeR3kJd8FoJDoKoWJ6XcgL/ldUU9lkVQtW++uyV
         OC2TYnkOXEr3qGwBmBu5Q7NwkIanxu72cANZKjRA8yOpQgEso6Eh8CCM+FyILTasYvqB
         xGjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=6826b42oZByLh2Scb4H7E4HhnJJ1vPmHiv/3eV4IO6Q=;
        fh=JtYjsXfP8t/4nW1kGG/VnYmWL51VUzATj7jCJxLz2TI=;
        b=Tzojmr4hYOn1dGjKmWMq1+ohFMp7C7h+5mID65IYiP694ri79dqOdZR2WwW0S+andW
         mbf6V83ySVWfCftLP2PuDSmpw1tuK5N7CiKDn+g96y4jRgdBRkssXSFMb7Wp+FTIa6xy
         5A9sqooZBCBZKvv8c42WFPW+PRzPbov6IvSRY7ClpbT0nmgD2Ux82ugnb0UfurKtFo46
         7uAFO+RUfoInpNTAUWZmlQds6IGDbh1J843kcvcTUhT59/NO3zuSdiUMcausyeanWMnL
         VLFarHgTWW4lonpe9UjCyFmPpsqYA5W+KOcnNgPQjmWNOkTvGPLYXJvawQ4FMG8SHwgc
         YaCw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S2ieaJjV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722516859; x=1723121659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6826b42oZByLh2Scb4H7E4HhnJJ1vPmHiv/3eV4IO6Q=;
        b=aiB9FexyieJicZfAu0ZtX6TMVV3Uaovzx0wSJkJfP48PhdgzPmTkU/z92fTyOhmgx2
         Mp1nVd1o18F2PEM0uNYzc5kpdRNmdooi+2d3DNeN420tDWgPUmQyA4htJS+a8uY++kMy
         XZiM6b5zyE0Ml7OFXpI9dm09ojsxG6OEc4Ig+rDO4vQ3qmVGhRjmomhVQWBCmj2+u3jw
         NPV8tvxX3incoKmlw+4o6QIOzkSseXt9n2X78Pv1mEXZt+AGyM17zbwj4WOm5zOaExTZ
         CCBTNp7den4O8A5RiwvS+AtWIC+/V04CN808rm4laP537OXuAUgnHKSlFsp4vUP9ApB5
         tqzg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722516859; x=1723121659; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6826b42oZByLh2Scb4H7E4HhnJJ1vPmHiv/3eV4IO6Q=;
        b=S8lw6P2uLKqdE+t12a1tC6w3Bola1Z9Yzln0w7x1kMD1fW3WXaMKT0PDYzZCxg85MI
         2MP2EFq+99v64yUtC45cswSo+ydAkoLA4njWK+4djEhMS3cvG6wyhQFW/wbdKv/AfBi1
         f2cxvEYUrq1Q0Zu0i1pxFZizoesXNmNYiQEuiQLk1YBhDQEPaon6Z5+0UiX/FxAnXIBt
         NKSpG+lRJtfJ1p8ajEvXQNnPmhkQo/M+cEuzJnDWvjpgYNBy6PRHr3DBpEKaAhO7HqRP
         +8af+D72m/7WVmWVswzPuKK/QnlFi+jigbg81G2BnDcBj1kQCIuZtAK3Cr/MIo7AfurC
         FAKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722516859; x=1723121659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=6826b42oZByLh2Scb4H7E4HhnJJ1vPmHiv/3eV4IO6Q=;
        b=Gf82KzQghQQSZJ3BY5iM4w4WyBAUwBb38FFBkdI1mVoK958xHndLse3t0advTkK5ml
         lzzxwGv8G87vfcoMgpkFkx8XGSgQ+/iJHLkuDHgx67OWPRvsbYiAyareqEDA59YRq3D0
         UhPQ1zyDS9YZaSa8IdJgtWLtJbaa7PTpT5KeN7AO+ySaBAsr6PCU9RxydfSqmzWWRz5p
         pMWeehLXXD86/euQBu2qd+kX3hgSr/LPeJFvUCOr5wLnGMQLok4cqbgyuldVE2cNtjsF
         2pFZFcJjojcyWHU9yz0PahfAdbNrE+5keyZkcj5iXFAMWu8Spv2pWqQRKwQ8a7D2UoVc
         VojQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWcGQpTz1n/5blaNkb1LiFTfEswXrSXjLFnTZ2otH8O37x/mbBgTqoe7gXeU/FgUWKKB4anC1NrpWtkaN+pR0wlXYarlLRlkA==
X-Gm-Message-State: AOJu0Yzkl4BjHEfZlDwCBpuOwYUAIJeSk3Hcw6asf0+h4LcwI5dorz2x
	6xTt4JgEjEmWztS6begM83ZS31ZqppIt5agntkTMWmzMEkhBeIdw
X-Google-Smtp-Source: AGHT+IE4L+U+OxD0aih6Hs4GJ4CdCtRboPfj/HwERzdzH2ljRe07m/U0IWndyrBYaN+4hApXMN2aug==
X-Received: by 2002:a5d:42d0:0:b0:366:e9f3:c242 with SMTP id ffacd0b85a97d-36baac9e3e3mr1494940f8f.12.1722516858454;
        Thu, 01 Aug 2024 05:54:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:eed0:0:b0:368:35eb:ada3 with SMTP id ffacd0b85a97d-36b3195cf3fls2296481f8f.0.-pod-prod-03-eu;
 Thu, 01 Aug 2024 05:54:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXxgXtwcAmvQ8b7c+A6X5RmVuxQyZaHW7XxvO/moOIolACkcNygZcF9M5Q+IfuChhenKeldBfUx1/fNCOQ1v3ChA2RMEVyh+U5cxw==
X-Received: by 2002:adf:e286:0:b0:367:9614:fb99 with SMTP id ffacd0b85a97d-36baac9e4a3mr1740111f8f.10.1722516856228;
        Thu, 01 Aug 2024 05:54:16 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722516856; cv=none;
        d=google.com; s=arc-20160816;
        b=Nx+9RCG+EnLi1N9imPp8c2MzJ2X5bu0NywjIsYDZ1wZck95J2EUMAPW9LaGPYBcVU3
         zQFDLR8Wp2XSUqII7znHd22uUVO2i4qto49XpEB0v6LxKlyHZENZAQo1Eh6c5+L7rz6T
         Zym6QYNeF014S3sT2+5sNiJkf/2MbaweMhyzREJS7VQafoFxx6J255PZpsAHOl8XCzB+
         6NrfXgVy7qGfwGOZk+2eZcriZZyzbrzSPi+BYbo7+bzprLO/lZueRa2OXcsJRmxrbaDS
         QFHOoTLyQrHO6h8M7c3D0m1i2JJ5LCdngmiulcyH2B5jM/xMFuUrdOx5q7wTgyWoFBCc
         0XMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oJM7ZW7Cx4ewZwlyf9TpDzuVdkBNUpK6wYJDwO0sS4w=;
        fh=41zXq2oQX7qzlXN0NCOTIbNf29U031gNmneLf+0tHt0=;
        b=e/rTAu8ZBQP1rGD1po2oBKcLEwT3wD8UQLKebGcvQXGVVLCHOJRB/UhcGGQUEy2YUz
         BqrO9T6gWcYId5W+CzNvPCl50UDPXzN2uoQpPTK7jDD6MMqeC4+GKkMwu0ozOX29NrW8
         Br+/o1Isq/3hhQ+D1mzmFxoYvjJ/Pu+DlmWeZbckpqicvGjfwV1ZG8klMLJ/d0obkrvV
         mR5kMQtejdohFNECcnR1NvRB7C2lqeVaODviDLDEW9wh9LQVtRzEFHjhTJtKqvzGWDjJ
         /I4FuY6VKbBMFOCv4ag/vYr4i26powc1HqeP0/xADEGV4GpO4mXH/QPq9I2QsyUVc9Jk
         ENjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=S2ieaJjV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-36b8f5e65e1si107574f8f.0.2024.08.01.05.54.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Aug 2024 05:54:16 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-3685a5e7d3cso3975486f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 01 Aug 2024 05:54:16 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWDuhxDn+rPelBr5RzoPPmqtN0A+VtzkPLCwrJIRR0VjfmBsYB8PX+Vs6QnmE8gNb/2AcdPvprRoOZqQ8izOL30bUKH3OjSTzOVWQ==
X-Received: by 2002:a5d:62c5:0:b0:368:3b21:6643 with SMTP id
 ffacd0b85a97d-36baaf237a1mr1484941f8f.48.1722516855454; Thu, 01 Aug 2024
 05:54:15 -0700 (PDT)
MIME-Version: 1.0
References: <20240730-kasan-tsbrcu-v5-0-48d3cbdfccc5@google.com>
 <20240730-kasan-tsbrcu-v5-1-48d3cbdfccc5@google.com> <CA+fCnZfURBYNM+o6omuTJyCtL4GpeudpErEd26qde296ciVYuQ@mail.gmail.com>
 <CAG48ez12CMh2wM90EjF45+qvtRB41eq0Nms9ykRuf5-n7iBevg@mail.gmail.com>
In-Reply-To: <CAG48ez12CMh2wM90EjF45+qvtRB41eq0Nms9ykRuf5-n7iBevg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Thu, 1 Aug 2024 14:54:04 +0200
Message-ID: <CA+fCnZf++VKo-VKYTJsuiYeP9LJoxHdd3nk1DL+tZP1TOQ9xrw@mail.gmail.com>
Subject: Re: [PATCH v5 1/2] kasan: catch invalid free before SLUB
 reinitializes the object
To: Jann Horn <jannh@google.com>
Cc: Marco Elver <elver@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>, David Rientjes <rientjes@google.com>, 
	Joonsoo Kim <iamjoonsoo.kim@lge.com>, Vlastimil Babka <vbabka@suse.cz>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Hyeonggon Yoo <42.hyeyoo@gmail.com>, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=S2ieaJjV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Aug 1, 2024 at 6:01=E2=80=AFAM Jann Horn <jannh@google.com> wrote:
>
> > > @@ -503,15 +509,22 @@ bool __kasan_mempool_poison_object(void *ptr, u=
nsigned long ip)
> > >                 kasan_poison(ptr, folio_size(folio), KASAN_PAGE_FREE,=
 false);
> > >                 return true;
> > >         }
> > >
> > >         if (is_kfence_address(ptr))
> > >                 return false;
> > > +       if (!kasan_arch_is_ready())
> > > +               return true;
> >
> > Hm, I think we had a bug here: the function should return true in both
> > cases. This seems reasonable: if KASAN is not checking the object, the
> > caller can do whatever they want with it.
>
> But if the object is a kfence allocation, we maybe do want the caller
> to free it quickly so that kfence can catch potential UAF access? So
> "return false" in that case seems appropriate.

Return false would mean: allocation is buggy, do not use it and do not
free it (note that the return value meaning here is inverse compared
to the newly added check_slab_allocation()). And this doesn't seem
like something we want for KFENCE-managed objects. But regardless of
the return value here, the callers tend not to free these allocations
to the slab allocator, that's the point of mempools. So KFENCE won't
catch a UAF either way.

> Or maybe we don't
> because that makes the probability of catching an OOB access much
> lower if the mempool is going to always return non-kfence allocations
> as long as the pool isn't empty? Also I guess whether kfence vetoes
> reuse of kfence objects probably shouldn't depend on whether the
> kernel is built with KASAN... so I guess it would be more consistent
> to either put "return true" there or change the !KASAN stub of this to
> check for kfence objects or something like that? Honestly I think the
> latter would be most appropriate, though then maybe the hook shouldn't
> have "kasan" in its name...

Yeah, we could add some custom handling of mempool to KFENCE as well.
But that would be a separate effort.

> Either way, I agree that the current situation wrt mempools and kfence
> is inconsistent, but I think I should probably leave that as-is in my
> series for now, and the kfence mempool issue can be addressed
> separately afterwards? I also would like to avoid changing kfence
> behavior as part of this patch.

Sure, sounds good to me.

> If you want, I can add a comment above the "if (is_kfence_address())"
> that notes the inconsistency?

Up to you, I'll likely add a note to the bug tracker to fix this once
the patch lands anyway.

Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf%2B%2BVKo-VKYTJsuiYeP9LJoxHdd3nk1DL%2BtZP1TOQ9xrw%40mai=
l.gmail.com.
