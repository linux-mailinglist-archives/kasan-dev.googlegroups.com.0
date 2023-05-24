Return-Path: <kasan-dev+bncBCKJJ7XLVUBBBC6NW2RQMGQESFFEHZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x340.google.com (mail-ot1-x340.google.com [IPv6:2607:f8b0:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 1F24970ED64
	for <lists+kasan-dev@lfdr.de>; Wed, 24 May 2023 07:54:21 +0200 (CEST)
Received: by mail-ot1-x340.google.com with SMTP id 46e09a7af769-6af6fcdd0dfsf362006a34.3
        for <lists+kasan-dev@lfdr.de>; Tue, 23 May 2023 22:54:21 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684907660; cv=pass;
        d=google.com; s=arc-20160816;
        b=o8dWdPCsjqFaji2AYIcbiBjlUgPwCoUBz+5hBJSVrJI2Q4YgJNYHrf7V8k4YsViDP7
         KKQeQWRP1P3k6wd0F4vdLrllz++tZgVjhPwvzyDO5Gn2bpzpooPG2x6QC5D6L+B0WddJ
         Rak8RIziGEb3liyVGMSZsLXBRx+x1d4vzSOfz/+OpLWmxfapFrO8f02JCnnxg38NuGgM
         0yEXRygvZTjg0quuiJ7R02Hn/hG6c77G1rE6PuXjRDueO1sTbtrDXbTyph30YpbYjWLM
         zPyXYYif/OMiytH47u0nPuuf/ELg0cvNzpYTE+D3G5PAwMT1ff72haMXJpN9+VGAkAYt
         9msw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature
         :dkim-signature;
        bh=Tf29r6g1Ynbti4xJlR8W/I9h863y9mNHSZ4q1qkW+sg=;
        b=U8fULINZHAZgUwZiFD1iiOlrfkGMtNYQfeKtgT5cZP8paa69TYqLe6l2Fb2eBq+cby
         Sx1NbtTeQgwBZHl35zIkMceX6SR8YfjT22OtAVTKzsSg2+wLCLz9VCPJ3oo9z56r5G+F
         77YRpOxhiEShX3xd8TbCU+NQXUVWau7ZI1Y+Cl+Ip0hVYDRZ0JQ9AgdR4ZS9LhyKAsaK
         lszITYA+KXldPHoaTILRy0iN/eioAOdciDKP2vkQv7abrg/JY8MhbWVrehNc13BUZMgU
         SfVxYxEuXreg0n/0Yp1CUiH2AOXRvhsk4S2kje8U/Zk28l8qTheyG0H19u0RhxZIwfPL
         zyzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="Ll/kZY4z";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684907659; x=1687499659;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Tf29r6g1Ynbti4xJlR8W/I9h863y9mNHSZ4q1qkW+sg=;
        b=A1tFJTe+bf8C6xFPN8VPNMWn+hNj0qWegsLtzHy5nDVWTPRDVWOvdCb/lnGJ2CH+1/
         v60HaJBWeXDXs8R8dlVZqflmi0pN3YZR0yvlB60gbiAoeu6hemlATucXg5/zgmN6kzOb
         G1OEnZZf4jPviwqnsackXSv61QR0/lkhZYNt5VpIQxa0E/ntbL3rs+mMpVLgRWA452Ps
         MfZ3M0BXOiNi1m1jD4k1sOyYhRVHY9NJr7H4STRRZ6Pfyb2IvrT8cYVu/sqClMXhNCSi
         MSkaQJeC2J7KQIdyz/QC1Wna9lJi6GoPxWwEEyNxxGIkExklLPqG+4Ppv51EsbUIrW1S
         kGdg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20221208; t=1684907660; x=1687499660;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=Tf29r6g1Ynbti4xJlR8W/I9h863y9mNHSZ4q1qkW+sg=;
        b=GX0vqZET78iS2vXD6DlALy0gaqfFJ3ckdpDwQ0kc7WjbR4WsLs32UZbfsR3zYa1mEy
         ZpIJVs1sSD/2hUjrhNoCnmxqYm7jKmnpUa+jqM6qJZt6UL5jOrVpXZPzF+HgVLMf8uu9
         OLxBSIbCFeLzr0QMxPOYF/xOrIMXAiI+olTeYzoseGm0Y+fvgHiiGz0sAj/JcRnmrVk4
         2I323IWHXrGsCt1lMsOlQWZ1xm7YufWEsQ+nVhv2gpBgjf8AtaTROamtEHu5+2v9tvXZ
         tI9QOx1CVqHkvgCyj6ZX83NpGFqMYUHajpEIzt7HAno4tNABU3ZBian2yRphn9t26tlE
         L5hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684907660; x=1687499660;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Tf29r6g1Ynbti4xJlR8W/I9h863y9mNHSZ4q1qkW+sg=;
        b=hhLdZFECNkjb4xhBEbj1crekXt3g90Y6UklY5Yvajo93WUVFifuCElB3n1UkIQFPuk
         /V5+BCoX22hF9eDn0Xyf2BUo85xiVYITGXaVobgeRLACXfMjh1aPJ13UTORb6shwkffR
         qF+YK2Qp7iFS66/lSbAyZrpZW5HLuwgFhzR8xlnKmbKuabe21lRbFvpnDyyWO5QEvn3Y
         mrr2dxWhNBL4dqJa9NrthYVYMYw+XMb32G2d7BNDcs4B8WpL3ZX+CFqXSlEcaZlEX7/6
         Tt5fkVSJIETwqbUsIHRLldvEk/LEZtOu+f0NyKf6ndr7NCgh1llMkuAciUte5z56/f2r
         oWEA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDwNntcsNDoUMjEpt9qc96FEkxwxafLYfpBUW7+bar8zEiR2CGfJ
	phibq3ZmY5Cbw5aVdoACkVM=
X-Google-Smtp-Source: ACHHUZ6neJRrGo0NuHKZI9jB8l8YGpMm+lhcrPrp5eTzojKk78hCrpw29ohO8vFz5xZmQtdC9M+20g==
X-Received: by 2002:a9d:7a56:0:b0:6aa:ff62:546f with SMTP id z22-20020a9d7a56000000b006aaff62546fmr4700757otm.5.1684907659702;
        Tue, 23 May 2023 22:54:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:316:b0:555:458b:d30d with SMTP id
 l22-20020a056820031600b00555458bd30dls694611ooe.0.-pod-prod-05-us; Tue, 23
 May 2023 22:54:19 -0700 (PDT)
X-Received: by 2002:a05:6808:64b:b0:398:2f06:329 with SMTP id z11-20020a056808064b00b003982f060329mr2076104oih.9.1684907658978;
        Tue, 23 May 2023 22:54:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684907658; cv=none;
        d=google.com; s=arc-20160816;
        b=kEAKo0YMEqMCxDRtSIZAxHyVm5UycGk7J62QVwXAyRnSYewNKCNqJoo/tolgU72DZl
         dQOa1gjqNBymBlGzCYRN+NhcAG4nDJGl9+JX55Bo5rTqr1pGeb8iWzteUpJU/N1xWTok
         tdz47HCDO6lWSQEtsVhqwVYCXOfdimh0SaYokkU/mKhHMrZFCYgah7cxtKfOHsTUPJsq
         mU5J+HDt2ymAn+LftBA8vQQogNT1Lp6Q367amGbhuNwWvpOoelBCaFIgwlLAtSMYHqKK
         lFFzKkktwqs1D/wbc8cZoT5dgbOiBmN1XqC9u/JsL2m+Pu1la/UInXpbAuAkL6xS684c
         /nJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=qmpQ8CZWBqNpjBXlf/vqm5PoXrDI3CUBIg7+r/yPqX4=;
        b=TG+LXEby4lsTfg1OWQb6QHjjs2h3s3DC8cM9Vjc6kGY2xK56Bp3RTv/HBv0PsgPmAD
         5x1IxlsesOzCgjn/TC9rcdNo6fv1Y7GThe3Jzyr79mArnXUnBXDzOG2AVhOofArcX81E
         3X0Mq7cIFsFVe9OhrG3Q78+qYx+rerwiXNDzpxvOyn4D9LdO40HlLPAX2qYbN1QU3mIb
         JbxbBgrJ4WRW9iKV7xVk5gaevPk6y7H8RARAQ/J3Wy/zyUq04crsleekRaPZ3+0dqyAi
         +G+gmVl5PHwj5gdgGcF4150kq2zi9UKA8J3DoVt351e1NNASyT3u3zWs5M72QWA1zALX
         xWJw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20221208 header.b="Ll/kZY4z";
       spf=pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52b.google.com (mail-pg1-x52b.google.com. [2607:f8b0:4864:20::52b])
        by gmr-mx.google.com with ESMTPS id 126-20020aca0584000000b003925998258asi1246152oif.5.2023.05.23.22.54.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 23 May 2023 22:54:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52b as permitted sender) client-ip=2607:f8b0:4864:20::52b;
Received: by mail-pg1-x52b.google.com with SMTP id 41be03b00d2f7-53f158ecfe1so1830a12.0
        for <kasan-dev@googlegroups.com>; Tue, 23 May 2023 22:54:18 -0700 (PDT)
X-Received: by 2002:a17:903:188:b0:1ae:600d:3d07 with SMTP id z8-20020a170903018800b001ae600d3d07mr18751108plg.4.1684907658072;
        Tue, 23 May 2023 22:54:18 -0700 (PDT)
Received: from debian-BULLSEYE-live-builder-AMD64 ([211.216.218.61])
        by smtp.gmail.com with ESMTPSA id m10-20020a170902bb8a00b001aaeeeebaf1sm7723002pls.201.2023.05.23.22.54.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 23 May 2023 22:54:17 -0700 (PDT)
Date: Wed, 24 May 2023 14:54:33 +0900
From: Hyeonggon Yoo <42.hyeyoo@gmail.com>
To: "GONG, Ruiqi" <gongruiqi@huaweicloud.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org,
	linux-hardening@vger.kernel.org,
	Alexander Lobakin <aleksander.lobakin@intel.com>,
	kasan-dev@googlegroups.com, Wang Weiyang <wangweiyang2@huawei.com>,
	Xiu Jianfeng <xiujianfeng@huawei.com>,
	Vlastimil Babka <vbabka@suse.cz>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Pekka Enberg <penberg@kernel.org>,
	Kees Cook <keescook@chromium.org>, Paul Moore <paul@paul-moore.com>,
	James Morris <jmorris@namei.org>,
	"Serge E. Hallyn" <serge@hallyn.com>,
	"Gustavo A. R. Silva" <gustavoars@kernel.org>,
	Gong Ruiqi <gongruiqi1@huawei.com>
Subject: Re: [PATCH RFC v2] Randomized slab caches for kmalloc()
Message-ID: <ZG2mmWT5dxfMC3DW@debian-BULLSEYE-live-builder-AMD64>
References: <20230508075507.1720950-1-gongruiqi1@huawei.com>
 <CAB=+i9QxWL6ENDz_r1jPbiZsTUj1EE3u-j0uP6y_MxFSM9RerQ@mail.gmail.com>
 <5f5a858a-7017-5424-0fa0-db3b79e5d95e@huawei.com>
 <CAB=+i9R0GZiau7PKDSGdCOijPH1TVqA3rJ5tQLejJpoR55h6dg@mail.gmail.com>
 <19707cc6-fa5e-9835-f709-bc8568e4c9cd@huawei.com>
 <CAB=+i9T-iqtMZw8y7SxkaFBtiXA93YwFFEtQyGynBsorud1+_Q@mail.gmail.com>
 <1cec95d5-5cd4-fbf9-754b-e6a1229d45c3@huaweicloud.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <1cec95d5-5cd4-fbf9-754b-e6a1229d45c3@huaweicloud.com>
X-Original-Sender: 42.hyeyoo@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20221208 header.b="Ll/kZY4z";       spf=pass
 (google.com: domain of 42.hyeyoo@gmail.com designates 2607:f8b0:4864:20::52b
 as permitted sender) smtp.mailfrom=42.hyeyoo@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, May 22, 2023 at 04:58:25PM +0800, GONG, Ruiqi wrote:
>=20
>=20
> On 2023/05/22 16:03, Hyeonggon Yoo wrote:
> > On Mon, May 22, 2023 at 4:35=E2=80=AFPM Gong Ruiqi <gongruiqi1@huawei.c=
om> wrote:
> >> On 2023/05/17 6:35, Hyeonggon Yoo wrote:
> > [...]
> >>>>>> +#ifdef CONFIG_RANDOM_KMALLOC_CACHES
> >>>>>> +# define SLAB_RANDOMSLAB       ((slab_flags_t __force)0x01000000U=
)
> >>>>>> +#else
> >>>>>> +# define SLAB_RANDOMSLAB       0
> >>>>>> +#endif
> >>>
> >>> There is already the SLAB_KMALLOC flag that indicates if a cache is a
> >>> kmalloc cache. I think that would be enough for preventing merging
> >>> kmalloc caches?
> >>
> >> After digging into the code of slab merging (e.g. slab_unmergeable(),
> >> find_mergeable(), SLAB_NEVER_MERGE, SLAB_MERGE_SAME etc), I haven't
> >> found an existing mechanism that prevents normal kmalloc caches with
> >> SLAB_KMALLOC from being merged with other slab caches. Maybe I missed
> >> something?
> >>
> >> While SLAB_RANDOMSLAB, unlike SLAB_KMALLOC, is added into
> >> SLAB_NEVER_MERGE, which explicitly indicates the no-merge policy.
> >=20
> > I mean, why not make slab_unmergable()/find_mergeable() not to merge km=
alloc
> > caches when CONFIG_RANDOM_KMALLOC_CACHES is enabled, instead of a new f=
lag?
> >=20
> > Something like this:
> >=20
> > diff --git a/mm/slab_common.c b/mm/slab_common.c
> > index 607249785c07..13ac08e3e6a0 100644
> > --- a/mm/slab_common.c
> > +++ b/mm/slab_common.c
> > @@ -140,6 +140,9 @@ int slab_unmergeable(struct kmem_cache *s)
> >   if (slab_nomerge || (s->flags & SLAB_NEVER_MERGE))
> >   return 1;
> >=20
> > + if (IS_ENALBED(CONFIG_RANDOM_KMALLOC_CACHES) && (flags & SLAB_KMALLOC=
))
> > + return 1;
> > +
> >   if (s->ctor)
> >   return 1;
> >=20
> > @@ -176,6 +179,9 @@ struct kmem_cache *find_mergeable(unsigned int
> > size, unsigned int align,
> >   if (flags & SLAB_NEVER_MERGE)
> >   return NULL;
> >=20
> > + if (IS_ENALBED(CONFIG_RANDOM_KMALLOC_CACHES) && (flags & SLAB_KMALLOC=
))
> > + return NULL;
> > +
> >   list_for_each_entry_reverse(s, &slab_caches, list) {
> >   if (slab_unmergeable(s))
> >   continue;
>=20
> Ah I see. My concern is that it would affect not only normal kmalloc
> caches, but kmalloc_{dma,cgroup,rcl} as well: since they were all marked
> with SLAB_KMALLOC when being created, this code could potentially change
> their mergeablity. I think it's better not to influence those irrelevant
> caches.

I see. no problem at all as we're not running out of cache flags.

By the way, is there any reason to only randomize normal caches
and not dma/cgroup/rcl caches?

Thanks,

--=20
Hyeonggon Yoo

Doing kernel stuff as a hobby
Undergraduate | Chungnam National University
Dept. Computer Science & Engineering

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/ZG2mmWT5dxfMC3DW%40debian-BULLSEYE-live-builder-AMD64.
