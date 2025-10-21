Return-Path: <kasan-dev+bncBDW2JDUY5AORBVVE4DDQMGQETQJ3MMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x437.google.com (mail-wr1-x437.google.com [IPv6:2a00:1450:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id B0AB8BF92E6
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 01:08:08 +0200 (CEST)
Received: by mail-wr1-x437.google.com with SMTP id ffacd0b85a97d-3ece0fd841csf2685160f8f.0
        for <lists+kasan-dev@lfdr.de>; Tue, 21 Oct 2025 16:08:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761088088; cv=pass;
        d=google.com; s=arc-20240605;
        b=RjOY1+eKfIp41rIRKNzxESG6Nlyk4AG85edCXugYD7bgJa4+QQLeoIAlSNy7k98mrC
         dd3aDpUP1PWvQieWX6ECOf4J8dxbDXYg5TA1VNZ5N/ajKA7GcyMu529c/puoEhyyCrsn
         AwvijavCQnUI8Kbp1U07IbSbcNZPBP9ckvZn/uQwOE1/P3Df6nZEhTsVpDWrArIrqvyh
         Yr6wlmKScoH1ylVol4syCx8eiefnlr1mnKkOXTPKaVZ0PGETvlUTFIRaaE2VxopAyk5g
         xxl4v60yWTgwBs5bMHgLdqnxuH1SQyH41ex+yPY0my+oZAdyXSo1OtYtvLPXqK2M0/8O
         fFaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=G6SrCap31zguRiSOLgCvveuljyqU1eV5344ZjLBJUfA=;
        fh=lf4KmxVwUAHkYd9badrXXdl7DhxHSV1BN1KIeK/HOH8=;
        b=OQDCUaFQTrIlNjV0T4G+ysRu6mUHHSziSI9wfzhpuYngaHBTKRlgK1nrxzJrKVYilr
         oShbqXZqs5h4/bTYjx7Do2X2kOinlT13FWuKnHidKStCAv1QhjQvGWus2U8Jg9dDurBN
         NXSnLZDnzOhopbikSFFWZucbNaV06gpSgX/hdhaPsLIlxqQrFOVI3dfjRQBWupnoB+q1
         pGnZodZFxIeOyzuqgo8jFqm9FQ+OgRLeAfTYPJzEdPBfIgOjRY3s/3HcP++Fp88mes0W
         9Fh/t0w/UuK4sRyxwuqKO3TTFFWhEgGDEymHYesI66iIly8c+cfTQAJODpEbN2xHSN2b
         g1zA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dT5BDsUZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761088088; x=1761692888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G6SrCap31zguRiSOLgCvveuljyqU1eV5344ZjLBJUfA=;
        b=KfT/607T4S34g+iXs4CEglKghib0W+anPqFMJm4R+tdXk9HPzPTMo5+t9SmiyxuBFs
         FleIZw3OKtcKFUZcNcm8R23ZgDRNVda1A9sxL6LRcgkKmk/vFf3fCeIr02yHQkZzRK/m
         L605FOz1+djWzj11qkK2i8aMTrnMrSzTm/oRJhZqzy96mo8OeFs+Q2Nj8lUleeHV1Bi7
         VwwkOnpDQWsYH1b1dG8+1RzNuiXndW24WD12qErUyJli6hbL0wP1sgkacrfQ94CVJrZi
         5ILK3zerWBob3kjkO+Mc+X+SK0aZ6gZ2FH+FG9HK6CSpR2BAY1+qtpDdvigPYCW5VVvx
         rbvw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761088088; x=1761692888; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=G6SrCap31zguRiSOLgCvveuljyqU1eV5344ZjLBJUfA=;
        b=dd/n2RIDtu/Xgrzui+btZrpQZgKuO9f+XL3+zW8uD9Uthknag0tfCA7g4vMNUILK9K
         V3iXDckxQa7SzwnASmgmcfXyheuz2BRyOa+1z37Vcv3TlUuRjyERXEpxAxlkrQefrW8b
         zKkcHSbnsZmzkZoB6OUF/poFkJeT1htX5EkfbpShIqpUKd4+fUS/QiDf8rYaXo26dlPg
         GvA65ob+UIqJ1jE4Q8ptxcGH5L5FtvX9pcl1sp63L2WLt/JZws1ktqvbAEauUlTcqV1e
         zbWslJA2KsR7o7JQb3zQCeEPWnyfnMYJYX+1dIJFEEbGkEoK5P72derhTM5kqiNYllwi
         jCiw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761088088; x=1761692888;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=G6SrCap31zguRiSOLgCvveuljyqU1eV5344ZjLBJUfA=;
        b=QAfsFgDrufYHcII7nDmbCmS6/F31La7EU7qFq+2R6XdQIYEbEy3DtXlg5ILm+Kd7NS
         LVUTDx7TL3Ee4r+6k7ZyxcNhOL/jkC/vXWwkVKAqwlTZjsOMT7sPkew7+q8xUApIGqB3
         1i7ybifvgefQv6FWA0UPbj6EgFIAVUk/8vbETl5hn2dDCNg49ssWedZ9sRcC056NN9r9
         RLMzhMrN4kvZcHj2yTXEONRwEg2FpiyM8D2c9dfimkdTXi0tNvZLSQrI332pDJRe50I5
         7p7Xh6W2P2rMo83e6hJZkkUc3IQYGtrAo8WnXZc9lzfPEIJws/yEylbi3UR/zIN9KZJV
         1cpw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWiz2NadgsypYGaPuES3ubnDFtAsJwCa1QTE8isQIMuAgGfgnww0ciHpH1wgfuE5MaVDc3mJg==@lfdr.de
X-Gm-Message-State: AOJu0YzBtLFSpc/rWShch6OzwqbnGD26L5aahcW8cP7XMATg4p2dVv4z
	iPC8A4T4eWZFGmVVL5/icuYFFYWR6b9/o2pHEXEjZTs/Fe5Gvr20DsI1
X-Google-Smtp-Source: AGHT+IFJLXZavZ2uX2d5ceG+8iLYpGMd931Houm2rGg6Ow5jUe6gvO9ji+utJFcjwbGV3VNBHF90NA==
X-Received: by 2002:a5d:5f82:0:b0:425:8133:8a89 with SMTP id ffacd0b85a97d-42704d75729mr13580455f8f.22.1761088087363;
        Tue, 21 Oct 2025 16:08:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd4XINByjW6gQV2ER4drxun3kUKUafSnn4ee7ia5K03X0w=="
Received: by 2002:a05:6000:2808:b0:426:cb20:6c35 with SMTP id
 ffacd0b85a97d-426ff4983eals2216983f8f.0.-pod-prod-06-eu; Tue, 21 Oct 2025
 16:08:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU9+/pvKaMqdPSSYeoMx4l6QC9Z5QYYy7N6hT8UrznCZPADC6SEq31vo+8GuE3VHkK3HYeQy7HTjuk=@googlegroups.com
X-Received: by 2002:a05:6000:2586:b0:3eb:d906:e553 with SMTP id ffacd0b85a97d-42704dab707mr11710296f8f.55.1761088084837;
        Tue, 21 Oct 2025 16:08:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761088084; cv=none;
        d=google.com; s=arc-20240605;
        b=Lv/KnvDL1ExicMq0La6I/EkmIXTcH07uRkeUf7ppxmNX13ulAW3IksGLk0GCdeqVKU
         pAP0hYAfSIsRpwFHlfIPhj2Yf5GK7lzWvgl/kJjETIIff16l91Q2EErRypN+iWSZzNIb
         hJMKskBPnMi/ilywEU37bcOaSeuUx3/qxvag++mvn7abeAspNidBeh992UK2sIhtFnQc
         O0wjC2T5xEm37VhTm8oBh81OmJbEQmbOkaDkggcW511c0hXx7enex5kknusR+louXrlV
         w7Uw+dZHuWFaT7L/jzS8mVFmBDe8zslFCg5rWe8ViUIeifzzTUjoymh2XMwAq6CIx9Hr
         HWTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=H37xO2Fy8H7/W951P5nhrd9q2BRvh9lu87ubrZUHMGY=;
        fh=k6WlBwI7fxp/HjTW9qK1lwyTUDfyr2OVX40fQpAfAKM=;
        b=HouSSBguQiOwS87+AfsAYwbvsgPmnDBnWFj/V03+xhc3eljr77kTOymJ99NrjHR0Jt
         A6YVUE6Q2hSD1EvOT0U4RtGzomfFkHLAAlJLmwJZbwRnumR88lh9HuIjhC4U3DIY2QI7
         6eprSs4fs92tVB4MYCasgdB4IRnox4ZGhRH0dp/i98kQrSaO2sTAto1UFeSUb+2CutF5
         GxzTU0YdnR+UHXbU6HTyci/+AqzqRGxVBaGSoP72VWOpEF6zBt2mUE9Sj46HO1K2AWbx
         GxqpZcpeDaPH6RFbkX3bL7c1SieE1hZ0aWx7SzIXDtdMWy0AN7zj21PHvAOYlplzvTA9
         s+eA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=dT5BDsUZ;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42e.google.com (mail-wr1-x42e.google.com. [2a00:1450:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-4284fa9ae86si157253f8f.6.2025.10.21.16.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 21 Oct 2025 16:08:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e as permitted sender) client-ip=2a00:1450:4864:20::42e;
Received: by mail-wr1-x42e.google.com with SMTP id ffacd0b85a97d-4285169c005so522303f8f.0
        for <kasan-dev@googlegroups.com>; Tue, 21 Oct 2025 16:08:04 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWbASntpUXBRLYXWGqQ4PwuolziqEb1RWU4PZUORD9ghtMv0QzPBWWQXdWmwrov4K52V3Lu4vTN+D8=@googlegroups.com
X-Gm-Gg: ASbGncvc9KcYWy4uUBw2jg2loeRCHg+ICMadI8KgCJWcCeOghMYMqOK4+Yc6sU2w29D
	4wWjJlLCULW1e8bpcXTvCxvNRqeH+aY3FXxvu5Wm87CCNnJ9nX0o3rnCwMS5eRn5mpB95SimG5X
	6vqs93wd9h2eH8ZRKVAA2fU8twPceokVjXp4N6RbOjXw1oKdwCfYB/i93Ku4uaDSAnPHZLiW4Mq
	NT4CmG9vD9awHx6Z2CbladrIEOaWPA1bTPz7zByDGhtx8x1xVfj5TpGe0OOCEZpsgGA9npgfk7N
	UsbIz7zTCBgDFQpBQMk=
X-Received: by 2002:a05:6000:22c6:b0:405:3028:1bf0 with SMTP id
 ffacd0b85a97d-42704d49805mr12349472f8f.10.1761088084218; Tue, 21 Oct 2025
 16:08:04 -0700 (PDT)
MIME-Version: 1.0
References: <20251009155403.1379150-1-snovitoll@gmail.com> <20251009155403.1379150-3-snovitoll@gmail.com>
In-Reply-To: <20251009155403.1379150-3-snovitoll@gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 22 Oct 2025 01:07:52 +0200
X-Gm-Features: AS18NWA2pgO8GYU1ySDNiDCWOQnFDbtDo8I_YJWXlOsSYh4kVXxVQK2mbQ2GsTM
Message-ID: <CA+fCnZeqtp2jqa7YTzDSbCkhso3dAaMGSEcmVtzU+Mrobark8w@mail.gmail.com>
Subject: Re: [PATCH 2/2] kasan: cleanup of kasan_enabled() checks
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, dvyukov@google.com, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, bhe@redhat.com, 
	christophe.leroy@csgroup.eu, ritesh.list@gmail.com, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=dT5BDsUZ;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42e
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

On Thu, Oct 9, 2025 at 5:54=E2=80=AFPM Sabyrzhan Tasbolatov <snovitoll@gmai=
l.com> wrote:
>
> Deduplication of kasan_enabled() checks which are already used by callers=
.
>
> * Altered functions:
>
> check_page_allocation
>         Delete the check because callers have it already in __wrappers in
>         include/linux/kasan.h:
>                 __kasan_kfree_large
>                 __kasan_mempool_poison_pages
>                 __kasan_mempool_poison_object
>
> kasan_populate_vmalloc, kasan_release_vmalloc
>         Add __wrappers in include/linux/kasan.h.
>         They are called externally in mm/vmalloc.c.
>
> __kasan_unpoison_vmalloc, __kasan_poison_vmalloc
>         Delete checks because there're already kasan_enabled() checks
>         in respective __wrappers in include/linux/kasan.h.
>
> release_free_meta -- Delete the check because the higher caller path
>         has it already. See the stack trace:
>
>         __kasan_slab_free -- has the check already
>         __kasan_mempool_poison_object -- has the check already
>                 poison_slab_object
>                         kasan_save_free_info
>                                 release_free_meta
>                                         kasan_enabled() -- Delete here
>
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  include/linux/kasan.h | 20 ++++++++++++++++++--
>  mm/kasan/common.c     |  3 ---
>  mm/kasan/generic.c    |  3 ---
>  mm/kasan/shadow.c     | 20 ++++----------------
>  4 files changed, 22 insertions(+), 24 deletions(-)
>
> diff --git a/include/linux/kasan.h b/include/linux/kasan.h
> index d12e1a5f5a9..f335c1d7b61 100644
> --- a/include/linux/kasan.h
> +++ b/include/linux/kasan.h
> @@ -571,11 +571,27 @@ static inline void kasan_init_hw_tags(void) { }
>  #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
>
>  void kasan_populate_early_vm_area_shadow(void *start, unsigned long size=
);
> -int kasan_populate_vmalloc(unsigned long addr, unsigned long size, gfp_t=
 gfp_mask);
> -void kasan_release_vmalloc(unsigned long start, unsigned long end,
> +int __kasan_populate_vmalloc(unsigned long addr, unsigned long size, gfp=
_t gfp_mask);
> +static inline int kasan_populate_vmalloc(unsigned long addr,
> +                                        unsigned long size, gfp_t gfp_ma=
sk)
> +{
> +       if (kasan_enabled())
> +               return __kasan_populate_vmalloc(addr, size, gfp_mask);
> +       return 0;
> +}
> +void __kasan_release_vmalloc(unsigned long start, unsigned long end,
>                            unsigned long free_region_start,
>                            unsigned long free_region_end,
>                            unsigned long flags);
> +static inline void kasan_release_vmalloc(unsigned long start, unsigned l=
ong end,
> +                          unsigned long free_region_start,
> +                          unsigned long free_region_end,
> +                          unsigned long flags)
> +{
> +       if (kasan_enabled())
> +               return __kasan_release_vmalloc(start, end, free_region_st=
art,
> +                                        free_region_end, flags);
> +}
>
>  #else /* CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS */
>
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index d4c14359fea..22e5d67ff06 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -305,9 +305,6 @@ bool __kasan_slab_free(struct kmem_cache *cache, void=
 *object, bool init,
>
>  static inline bool check_page_allocation(void *ptr, unsigned long ip)
>  {
> -       if (!kasan_enabled())
> -               return false;
> -
>         if (ptr !=3D page_address(virt_to_head_page(ptr))) {
>                 kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_F=
REE);
>                 return true;
> diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
> index 516b49accc4..2b8e73f5f6a 100644
> --- a/mm/kasan/generic.c
> +++ b/mm/kasan/generic.c
> @@ -506,9 +506,6 @@ static void release_alloc_meta(struct kasan_alloc_met=
a *meta)
>
>  static void release_free_meta(const void *object, struct kasan_free_meta=
 *meta)
>  {
> -       if (!kasan_enabled())
> -               return;
> -
>         /* Check if free meta is valid. */
>         if (*(u8 *)kasan_mem_to_shadow(object) !=3D KASAN_SLAB_FREE_META)
>                 return;
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index 5d2a876035d..cf842b620a2 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -354,7 +354,7 @@ static int ___alloc_pages_bulk(struct page **pages, i=
nt nr_pages, gfp_t gfp_mask
>         return 0;
>  }
>
> -static int __kasan_populate_vmalloc(unsigned long start, unsigned long e=
nd, gfp_t gfp_mask)
> +static int __kasan_populate_vmalloc_do(unsigned long start, unsigned lon=
g end, gfp_t gfp_mask)
>  {
>         unsigned long nr_pages, nr_total =3D PFN_UP(end - start);
>         struct vmalloc_populate_data data;
> @@ -403,14 +403,11 @@ static int __kasan_populate_vmalloc(unsigned long s=
tart, unsigned long end, gfp_
>         return ret;
>  }
>
> -int kasan_populate_vmalloc(unsigned long addr, unsigned long size, gfp_t=
 gfp_mask)
> +int __kasan_populate_vmalloc(unsigned long addr, unsigned long size, gfp=
_t gfp_mask)
>  {
>         unsigned long shadow_start, shadow_end;
>         int ret;
>
> -       if (!kasan_enabled())
> -               return 0;
> -
>         if (!is_vmalloc_or_module_addr((void *)addr))
>                 return 0;
>
> @@ -432,7 +429,7 @@ int kasan_populate_vmalloc(unsigned long addr, unsign=
ed long size, gfp_t gfp_mas
>         shadow_start =3D PAGE_ALIGN_DOWN(shadow_start);
>         shadow_end =3D PAGE_ALIGN(shadow_end);
>
> -       ret =3D __kasan_populate_vmalloc(shadow_start, shadow_end, gfp_ma=
sk);
> +       ret =3D __kasan_populate_vmalloc_do(shadow_start, shadow_end, gfp=
_mask);
>         if (ret)
>                 return ret;
>
> @@ -574,7 +571,7 @@ static int kasan_depopulate_vmalloc_pte(pte_t *ptep, =
unsigned long addr,
>   * pages entirely covered by the free region, we will not run in to any
>   * trouble - any simultaneous allocations will be for disjoint regions.
>   */
> -void kasan_release_vmalloc(unsigned long start, unsigned long end,
> +void __kasan_release_vmalloc(unsigned long start, unsigned long end,
>                            unsigned long free_region_start,
>                            unsigned long free_region_end,
>                            unsigned long flags)
> @@ -583,9 +580,6 @@ void kasan_release_vmalloc(unsigned long start, unsig=
ned long end,
>         unsigned long region_start, region_end;
>         unsigned long size;
>
> -       if (!kasan_enabled())
> -               return;
> -
>         region_start =3D ALIGN(start, KASAN_MEMORY_PER_SHADOW_PAGE);
>         region_end =3D ALIGN_DOWN(end, KASAN_MEMORY_PER_SHADOW_PAGE);
>
> @@ -634,9 +628,6 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>          * with setting memory tags, so the KASAN_VMALLOC_INIT flag is ig=
nored.
>          */
>
> -       if (!kasan_enabled())
> -               return (void *)start;
> -
>         if (!is_vmalloc_or_module_addr(start))
>                 return (void *)start;
>
> @@ -659,9 +650,6 @@ void *__kasan_unpoison_vmalloc(const void *start, uns=
igned long size,
>   */
>  void __kasan_poison_vmalloc(const void *start, unsigned long size)
>  {
> -       if (!kasan_enabled())
> -               return;
> -
>         if (!is_vmalloc_or_module_addr(start))
>                 return;
>
> --
> 2.34.1
>

Reviewed-by: Andrey Konovalov <andreyknvl@gmail.com>

Awesome, thank you!

I believe the check in kasan_byte_accessible() can be just removed as
well? If you do, please run the tests to be sure.

As for the other three (check_inline_region(), kasan_poison(), and
kasan_poison_last_granule()) - perhaps, we can leave them be.
Otherwise, we would need to duplicate the kasan_enabled() checks in a
lot of compiler-inserted functions.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZeqtp2jqa7YTzDSbCkhso3dAaMGSEcmVtzU%2BMrobark8w%40mail.gmail.com.
