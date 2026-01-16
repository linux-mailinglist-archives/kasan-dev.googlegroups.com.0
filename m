Return-Path: <kasan-dev+bncBC7OD3FKWUERB5G4VHFQMGQE43A7J7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8CB56D339C9
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 17:59:34 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2a07fa318fdsf18148055ad.0
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 08:59:34 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768582773; cv=pass;
        d=google.com; s=arc-20240605;
        b=JTVI2Z56PQ4266YjzMjc3bv5Cg9zuWm5n8VSbvlsMn3i5V0mNbSW2O8OeZ64QQJfd5
         yQklNAvoi1jUpJEVMTqEv30fAcGkJIbLLRDooxrkdBwdGrP0kAF7KN+t4/1Xg0Ni9f3k
         hlNh9pcf9lb4Bw9wNKYwWKt9jqIIkm43C8ljOAn2r+XU3ekSlnQA1tduN8rp6nxRPK7H
         FMN4fS6/nmH6nw/KEJKvZL8tHrBw8TccOUvW0nVatuELH7qqshKckaH3Pc7j7GVcWWkK
         fU6aQ5VTwh8q7FYTrdqqF1/bTqM5iNvBPNoEfCGPstN+05FvBHT68fcgOzScaGTpySPJ
         21+A==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=WXFak1BJWpIXTB+kNbLTcFhRGIlctoUlrdkSCuSYLTU=;
        fh=kiCrFwaTSIskSfuIO+eqewx0S2qJSpts68Ui4Es3vrE=;
        b=WttF89q4noAVyYU4DPLR9lL858XJp3lXeBrrZrWnOzWN5lnPX1qZOm/aiv7Tibi4sa
         /oD+Sln19UukZGqcuftcAJnF2d9b5fKxqhTu393kKzgIbmZNI3aauhLmaWP7BOz5DuI2
         rx2FBf2KykOkXeRWoLnolLkZlsIPnRdlk4OBSMBkiBRr3UFRH7lipwZjtJpZRizh3Rgp
         k4LhmlmKNmTJ62SHIfIKt3Y20g1EDKF9hBbHICc9UPAwzRhnIY3d7AV3xfGyjzimmlWu
         XsFJrxMl59mOmBUGv+hgW842Fqeb8pAPfw8P4cqVm914syIu7RyF8u4IpKOMm/XUnHTY
         5NFA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Kumt09QY;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768582773; x=1769187573; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WXFak1BJWpIXTB+kNbLTcFhRGIlctoUlrdkSCuSYLTU=;
        b=kdDck6/F0q/YAVi6mSZpZj0GZrz0F9Jy0LHgCqAUsQUWzV+DnU/rtstEvCbNg91Xef
         y+U1fYs1gMbngJOBjis95UVF0Sy6uvgb1zR2NfvQcg7TLGOW0vLGDHmtvK9+pwlSodKG
         GpjD0eyVipizT78KWh2UTKXhowNkDeA9Cx7ahJal7Rgq3MI234XoiRkBcUz0e8rJOop9
         x1BYlWmR2atBs4GtTP1cmDQFHh6VWdL/ZzddMd2Je5FDaKI8hHTjlmDoS5GorhikTGxc
         2y3R0u/peo+lDlw8lZJV0Sm2hfGYMysgLbhESo1fhnJ4pszNB/LG8Aw4pGdTY2rmiJuB
         hfKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768582773; x=1769187573;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=WXFak1BJWpIXTB+kNbLTcFhRGIlctoUlrdkSCuSYLTU=;
        b=D65eushivNo3fGqs09jeyGi10I/WgQB12bToUVrAnGoK71xwrgcIoZzdU+7pJIKk1g
         jCKPfK/DLZy5eBcrkQrGydWaec2+tTZovwZToR9UScXR1vagZF64oncHtWg6zygYd17A
         ROf6A9L8tMKlcx5aDr1yCiRbPkTCMxd//bhHCVYVYD9H2ZFlu/IEImjiMIfhTOaP6AF4
         9i4H9Ckbt+vD1eiGeIcmoUhk0XGpvXGkniwNOOzKip9syFRyoYEJuyfppfbDpjLi9g3D
         L0U/RnD1/c2WigG+JVdn6TGZt2PsFOfji/jbcJIR2nfCXl2Yi9DmkdSU1WBbllqJz4nN
         gl3A==
X-Forwarded-Encrypted: i=3; AJvYcCWvB0xKZPWKsdZ/iqAIfxu58mJCCgGa3oQRIkxbVfTX7wJl08aELVtB5pMqXQDQ2dlijzI0ww==@lfdr.de
X-Gm-Message-State: AOJu0YzcBGobJRWWTSUjBvn5ti2GK+mhGp0hgHZSJFKO5a+s4b9DPZrs
	88Kqi/+lOWgSOSv6BZjh8kPrpVuajzDE0ezDgn3eT8+5HD21nacpVted
X-Received: by 2002:a17:902:da8c:b0:2a0:bb0a:a5dd with SMTP id d9443c01a7336-2a7177e99eamr30682685ad.57.1768582772599;
        Fri, 16 Jan 2026 08:59:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FOw6R2jIBEgyZWHaFTLwU9r3uPZEkTevm1kJzQ/vVNJg=="
Received: by 2002:a17:902:a50d:b0:295:68e4:74d5 with SMTP id
 d9443c01a7336-2a70331ad01ls15631595ad.1.-pod-prod-01-us; Fri, 16 Jan 2026
 08:59:31 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUQSB6vPpdiA5Xl4mT3T7nybFhMNiu/XqeyYC6g5e+uyPLe1KVqfmq0mUfrt6KG9739FgjPq7598f0=@googlegroups.com
X-Received: by 2002:a17:903:2ed0:b0:2a0:e80e:b118 with SMTP id d9443c01a7336-2a717517031mr32112575ad.7.1768582771216;
        Fri, 16 Jan 2026 08:59:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768582771; cv=pass;
        d=google.com; s=arc-20240605;
        b=e7GXr8LrNou/NnF62IEji08FVAuQW+H6WrBT3gcu1rKrl1epAOZja77FR8za3qerlX
         tDldeLseq10CA0JFuq32qO3QuaETkz8efCmb3Lz63u0Or+8HW2kdRiWdGBvaZGYVXLiV
         maC/VmIbHNjW678owx3b9DqMGsY78oJz7uPYFc5vvpEzRmCqLg0Nfs3F73nkDWkmbYjD
         jfeq0hbw0eiNOehfOFTgszI1axKSJ3/JMrj7Qhh2sp+oQJblstfsJcIOKNMvWohXX5xX
         DALLoqSvJNv2xFOKXJ6LAYv1Ysuawr4SDhKaGNG0DepAGKy3Fn6LSl8VdC6+p1fd8RSa
         z9mA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=s1BTvLdErVOVTXbojE/mp4bn56MJT1unyCMZ/1mKqI8=;
        fh=gDRl2G3njCaciLcvpfv3+sRdlzyJ3xAro0h17JtYncQ=;
        b=Hf1u1uff1zD0xXid0LcTVVzGQMnuA3c1qX0sOpFTeFb3p6WCVQT1/IpuH+PACMm61N
         l0I9JmJVjoIxNIjN+YYP6Icza1zk7vv0TBEZRjdD4T6RdOvoPlyuv+MQJ5OkqxJNGPVL
         4B3C13IuAQz9xEUMmY7bouy1puvoWLCdwfjPxzl2BFRedosaJyRdIfTeuLiFXj1QBe6+
         mDtnlQlHHzK/CQkynRhbd33szJbHFauXG76jrtX3KE8/wnjBWwMpPIy6VPViVUCwEdYf
         8k6V+Ab1KsjJHKm7BE47/YXdgzW9/luouEkSrmyWPnfANs4TXARIl4zNKWRGMljscKPW
         gRQA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Kumt09QY;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x829.google.com (mail-qt1-x829.google.com. [2607:f8b0:4864:20::829])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2a7190b674csi902435ad.4.2026.01.16.08.59.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Jan 2026 08:59:31 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::829 as permitted sender) client-ip=2607:f8b0:4864:20::829;
Received: by mail-qt1-x829.google.com with SMTP id d75a77b69052e-5014b5d8551so534671cf.0
        for <kasan-dev@googlegroups.com>; Fri, 16 Jan 2026 08:59:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768582770; cv=none;
        d=google.com; s=arc-20240605;
        b=PuPJbmPgVcL47Cuj1uE0xqvg2GFsh2Km4izXpcFpnMr14xZLFytxZquSqXMMN9iHSb
         It/C8hiHAQcDUWHeqKnRF8D5XIxtr+yCxJ1BNLW7i68APrtKkGXnHU/7EOmwuLYsSW6m
         0ztZSU5bZGD0ZV1HbFnoaGdWdie6yAI+zEy7eTMHzdUvKdHnw3YtrSaTLL6NLj8/a3+v
         dEANcHnq1AeKtfF2ahLJqkBpWH0sWXVyTvT+wTGBp/wsD905fKpvoB7f+4pXQ1QVDNfr
         MZgcqMIhVz3v2VzYj/vZvpSETmaGMagNQq+IatYehytx69KM7M6J6xPKzHWAsOnPRqs+
         zJCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=s1BTvLdErVOVTXbojE/mp4bn56MJT1unyCMZ/1mKqI8=;
        fh=gDRl2G3njCaciLcvpfv3+sRdlzyJ3xAro0h17JtYncQ=;
        b=hnrSLZguIL5pigpJOn6wVkgz32cY+qv/u/NBD+se652rB/07tfqpmM8I8Bf9Lf7wMd
         z/o99tNMZYJPuC6fMi9LXlUuK5ZD78lYKyUDMnKLbJ+sFjslnkk3eAvhonarg8ptLKr8
         72wWz1PowiWQmrB9usvGwxO+p0M5gIYOlw3art6weVxExBipcPqye7/KsDuGyV/DSYh3
         WYpHY0YEJ2rowxBMcto3+o5XgLH4D3ufM3UN5RhSdzNpvlgIxbHiQxEl9sSsWwUBpq8L
         syskENQlOaf1354W4vyOQAZJczr/L34zpD65cdrKqS4rQk7U+iFrxKaJGb0pf8ZySZTv
         H76Q==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXkCW8RZ3iNw3yOYOnMp25anVCJicOgB7SmXGZadv5KUiDV/Qf8Xybgskr/whZeiq/JZUFrbiqsWk8=@googlegroups.com
X-Gm-Gg: AY/fxX5MNRaqcHux8zPWagY37zvByPyczP2bhLjEC2IHHy8LWKC/iC+RAfbwpxz11hO
	s9/2xmlrA3w5lm4+OI6bSz0Uuw+votKIETiUePm1dFSSIdg/1cOwXptLElxRQVm/kCSEZ855tAI
	pBnKVxn+aP347dVl6XXQ28FrdG+sl4a4hYujCiMkhOFVbRLFSVHGknteIVNFIX0tiDjEkKaFBse
	1xEioV18NSu1wv447ogKxLA2uFF6+e3GmSnjJwSCR3woo/RxP/Zuq2+wNqJFXqLDgNdhA==
X-Received: by 2002:a05:622a:4c:b0:4f3:7b37:81b with SMTP id
 d75a77b69052e-502a23a54c0mr4530661cf.18.1768582769172; Fri, 16 Jan 2026
 08:59:29 -0800 (PST)
MIME-Version: 1.0
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz>
 <20260112-sheaves-for-all-v2-4-98225cfb50cf@suse.cz> <CAJuCfpFKKtxB2mREuOSa4oQu=MBGkbQRQNYSSnubAAgPENcO-Q@mail.gmail.com>
 <d310d788-b6df-47dc-9557-643813351838@suse.cz>
In-Reply-To: <d310d788-b6df-47dc-9557-643813351838@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jan 2026 08:59:18 -0800
X-Gm-Features: AZwV_QgPp527tGrUgX7CIcyuFqzTixlPtSEyPVxRBLdI9BmrU9Axe1wzPof38j0
Message-ID: <CAJuCfpEqZwgB65y3zbm0Pwb_sVLjMbmHbTmJY6SdiVvvOPq+2A@mail.gmail.com>
Subject: Re: [PATCH RFC v2 04/20] slab: add sheaves to most caches
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
 header.i=@google.com header.s=20230601 header.b=Kumt09QY;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::829 as permitted sender) smtp.mailfrom=surenb@google.com;
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

On Fri, Jan 16, 2026 at 3:24=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 1/16/26 06:45, Suren Baghdasaryan wrote:
> > On Mon, Jan 12, 2026 at 3:17=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> In the first step to replace cpu (partial) slabs with sheaves, enable
> >> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum=
,
> >> and calculate sheaf capacity with a formula that roughly follows the
> >> formula for number of objects in cpu partial slabs in set_cpu_partial(=
).
> >>
> >> This should achieve roughly similar contention on the barn spin lock a=
s
> >> there's currently for node list_lock without sheaves, to make
> >> benchmarking results comparable. It can be further tuned later.
> >>
> >> Don't enable sheaves for bootstrap caches as that wouldn't work. In
> >> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
> >> even for !CONFIG_SLAB_OBJ_EXT.
> >>
> >> This limitation will be lifted for kmalloc caches after the necessary
> >> bootstrapping changes.
> >>
> >> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>
> >
> > One nit but otherwise LGTM.
> >
> > Reviewed-by: Suren Baghdasaryan <surenb@google.com>
>
> Thanks.
>
> >> ---
> >>  include/linux/slab.h |  6 ------
> >>  mm/slub.c            | 51 +++++++++++++++++++++++++++++++++++++++++++=
++++----
> >>  2 files changed, 47 insertions(+), 10 deletions(-)
> >>
> >> diff --git a/include/linux/slab.h b/include/linux/slab.h
> >> index 2482992248dc..2682ee57ec90 100644
> >> --- a/include/linux/slab.h
> >> +++ b/include/linux/slab.h
> >> @@ -57,9 +57,7 @@ enum _slab_flag_bits {
> >>  #endif
> >>         _SLAB_OBJECT_POISON,
> >>         _SLAB_CMPXCHG_DOUBLE,
> >> -#ifdef CONFIG_SLAB_OBJ_EXT
> >>         _SLAB_NO_OBJ_EXT,
> >> -#endif
> >>         _SLAB_FLAGS_LAST_BIT
> >>  };
> >>
> >> @@ -238,11 +236,7 @@ enum _slab_flag_bits {
> >>  #define SLAB_TEMPORARY         SLAB_RECLAIM_ACCOUNT    /* Objects are=
 short-lived */
> >>
> >>  /* Slab created using create_boot_cache */
> >> -#ifdef CONFIG_SLAB_OBJ_EXT
> >>  #define SLAB_NO_OBJ_EXT                __SLAB_FLAG_BIT(_SLAB_NO_OBJ_E=
XT)
> >> -#else
> >> -#define SLAB_NO_OBJ_EXT                __SLAB_FLAG_UNUSED
> >> -#endif
> >>
> >>  /*
> >>   * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
> >> diff --git a/mm/slub.c b/mm/slub.c
> >> index 8ffeb3ab3228..6e05e3cc5c49 100644
> >> --- a/mm/slub.c
> >> +++ b/mm/slub.c
> >> @@ -7857,6 +7857,48 @@ static void set_cpu_partial(struct kmem_cache *=
s)
> >>  #endif
> >>  }
> >>
> >> +static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
> >> +                                            struct kmem_cache_args *a=
rgs)
> >> +
> >> +{
> >> +       unsigned int capacity;
> >> +       size_t size;
> >> +
> >> +
> >> +       if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAG=
S)
> >> +               return 0;
> >> +
> >> +       /* bootstrap caches can't have sheaves for now */
> >> +       if (s->flags & SLAB_NO_OBJ_EXT)
> >> +               return 0;
> >> +
> >> +       /*
> >> +        * For now we use roughly similar formula (divided by two as t=
here are
> >> +        * two percpu sheaves) as what was used for percpu partial sla=
bs, which
> >> +        * should result in similar lock contention (barn or list_lock=
)
> >> +        */
> >> +       if (s->size >=3D PAGE_SIZE)
> >> +               capacity =3D 4;
> >> +       else if (s->size >=3D 1024)
> >> +               capacity =3D 12;
> >> +       else if (s->size >=3D 256)
> >> +               capacity =3D 26;
> >> +       else
> >> +               capacity =3D 60;
> >> +
> >> +       /* Increment capacity to make sheaf exactly a kmalloc size buc=
ket */
> >> +       size =3D struct_size_t(struct slab_sheaf, objects, capacity);
> >> +       size =3D kmalloc_size_roundup(size);
> >> +       capacity =3D (size - struct_size_t(struct slab_sheaf, objects,=
 0)) / sizeof(void *);
> >> +
> >> +       /*
> >> +        * Respect an explicit request for capacity that's typically m=
otivated by
> >> +        * expected maximum size of kmem_cache_prefill_sheaf() to not =
end up
> >> +        * using low-performance oversize sheaves
> >> +        */
> >> +       return max(capacity, args->sheaf_capacity);
> >> +}
> >> +
> >>  /*
> >>   * calculate_sizes() determines the order and the distribution of dat=
a within
> >>   * a slab object.
> >> @@ -7991,6 +8033,10 @@ static int calculate_sizes(struct kmem_cache_ar=
gs *args, struct kmem_cache *s)
> >>         if (s->flags & SLAB_RECLAIM_ACCOUNT)
> >>                 s->allocflags |=3D __GFP_RECLAIMABLE;
> >>
> >> +       /* kmalloc caches need extra care to support sheaves */
> >> +       if (!is_kmalloc_cache(s))
> >
> > nit: All the checks for the cases when sheaves should not be used
> > (like SLAB_DEBUG_FLAGS and SLAB_NO_OBJ_EXT) are done inside
> > calculate_sheaf_capacity(). Only this is_kmalloc_cache() one is here.
> > It would be nice to have all of them in the same place but maybe you
> > have a reason for keeping it here?
>
> Yeah, in "slab: handle kmalloc sheaves bootstrap" we call
> calculate_sheaf_capacity() from another place for kmalloc normal caches s=
o
> the check has to be outside.

Ok, I suspected the answer will be in the later patches. Thanks!

>
> >> +               s->sheaf_capacity =3D calculate_sheaf_capacity(s, args=
);
> >> +
> >>         /*
> >>          * Determine the number of objects per slab
> >>          */
> >> @@ -8595,15 +8641,12 @@ int do_kmem_cache_create(struct kmem_cache *s,=
 const char *name,
> >>
> >>         set_cpu_partial(s);
> >>
> >> -       if (args->sheaf_capacity && !IS_ENABLED(CONFIG_SLUB_TINY)
> >> -                                       && !(s->flags & SLAB_DEBUG_FLA=
GS)) {
> >> +       if (s->sheaf_capacity) {
> >>                 s->cpu_sheaves =3D alloc_percpu(struct slub_percpu_she=
aves);
> >>                 if (!s->cpu_sheaves) {
> >>                         err =3D -ENOMEM;
> >>                         goto out;
> >>                 }
> >> -               // TODO: increase capacity to grow slab_sheaf up to ne=
xt kmalloc size?
> >> -               s->sheaf_capacity =3D args->sheaf_capacity;
> >>         }
> >>
> >>  #ifdef CONFIG_NUMA
> >>
> >> --
> >> 2.52.0
> >>
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpEqZwgB65y3zbm0Pwb_sVLjMbmHbTmJY6SdiVvvOPq%2B2A%40mail.gmail.com.
