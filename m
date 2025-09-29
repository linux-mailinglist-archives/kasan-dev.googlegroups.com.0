Return-Path: <kasan-dev+bncBC76POFLYULBBSM25PDAMGQEBOKNWOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id BF494BAA44D
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 20:17:48 +0200 (CEST)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-78104c8c8ddsf4134241b3a.2
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Sep 2025 11:17:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1759169866; cv=pass;
        d=google.com; s=arc-20240605;
        b=MJyV6LjHVAsSJ6rJl7j4f4FoegDNpQKpkaOBul/WHw7oOhxfCWFAPlo9yuUukE0A5A
         zOv8MTudb5OtD0DyMCma79rMBqMIqK3rEhRZ5rqKoNymtRvqKOjaPXFkBnN/4F7UKzow
         zrE3CbDPpO4m0KK+qdRvTUjoa1hwfcYfgpG1BBUymHvVvwOjmXGME1Qw147dEu3vV8+W
         DfT+mc2zqbx5hNDWcZRBHXeL5Mq7B5xoHF+f5iJ/OL+eEE9DWBkE/n3InFu0GRcQSh7u
         vuYJvX3s5CSginvS4rD1ORQVpD2ITqFnCfqqtYBDkbsqUnrOvkVO3SaGd+8JPaitXj59
         XbXw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6quh/obVwV4f9vaH7GFDZ4JSsEIdc9ZfPXuAFRLORDk=;
        fh=r7zhd+Dwq4Y2tstrfc8VHtsVNSZV4MmQ5T4VBy16M0o=;
        b=DKT93WNU+k834OUOmZqNQdIw3TTBleyWNzFOjT93jPGW1Hq2W2ufB0YO5WWp+msASH
         S6Zn1CdmHG1gVkKff9g2XHvj6NvZikoyU3g/dXY0Y4v0e7rDV3oC/hdoKfTKK72WQV7T
         7Vpcz/mLb56qHCw/FwhEVCLPkW+SkQOtSkxHJ0MFZrt2kHTghYRb2rUUk8SRAumRxWEc
         BiHoiFfeNuoW/UV/TOJOe7aAOHvczV/ImGAFyXofxP9kamuxIkTN8QxSLaq3l+ivFhEm
         yn61BDINSB+1mPshHGWGXZ9Ohd0tKmbumFlEY2zS4mr0fmbVGamtSzxfOI28Pn1xDIlI
         Rw+A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="iSHp/qgY";
       spf=pass (google.com: domain of chrisl@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=chrisl@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1759169866; x=1759774666; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6quh/obVwV4f9vaH7GFDZ4JSsEIdc9ZfPXuAFRLORDk=;
        b=DYNkCM9hf3u87HRPIjDWWMLhz/CMNBF9Km/KCtDWUXGSTQjtEpkebGePsOolbPTuDZ
         qq1LtcSlKGYCqrILi924TaEMAIpYM02gXQXjOJoQEVaIC2C2a/vyHnJ6faEGvjWBME9P
         RuKFED9SZ09/lizdRPQn/a5Kkr+flhzDizSLtIftkDyj9jdsMqYjxOkN3KwuUhr1p6tJ
         PJIeM5Z+fc8zGbqyIRMHaJJ9lTvOlqCz3CbC4yw3SEZ/nrB8T4WjlhFpQ7pc3A4YfNJw
         7d8s/7vLEFkNSfS4BqAa5PYOpLgGx9yTdoWMrdlu1YSTylTtUDTj+AA/zfUhZ2jQFxGp
         3cHg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1759169866; x=1759774666;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=6quh/obVwV4f9vaH7GFDZ4JSsEIdc9ZfPXuAFRLORDk=;
        b=f/Ms1Z3kkt+tPAefCLzvYspbxMbrvbHHOrzxcqNj5Ctp/yytJ4kzdjcpEBFbMRqlsU
         xasIPX4B5I3xlgZUQRze2JekpmApzrFL2EmJ+fEwH3ay597nTCmtU5Cj1mgxtMR3DrKX
         hlnueA1yi6p61VtglKaOzvLNFJNfU+mMif/N5VkxKka/Cd+jDiKthXKa9Hr3UPfroYyE
         IpuoVinzS9iv+dEuvRheYfwkTysABk9no4hY2Yxix5Nb2+Rpf3hXsQ+BD7xxbDpcm9qX
         eRyflcg8vYyBtWTIUZK7qQS6ArTXVjLNDrv9pAcqf0lyJ85rL09I7J/ZI31+XQBhvWxH
         LzVw==
X-Forwarded-Encrypted: i=2; AJvYcCXUz4lgpoHXC78h9+suegBZsdSSYv2or/SXwP+n/KxvrbNOJNs4K9yscCN8nbO4d2NbsCFTLw==@lfdr.de
X-Gm-Message-State: AOJu0Yy+iVtc2nj258xcae52PhEu+mY1gwOX3JoFGcSCLJ1/YAGABAtA
	azGbq2bAGtTF+C5gojhEgfMIpN8SDGvDwzdStj1inY1KJ5opOCurBTXr
X-Google-Smtp-Source: AGHT+IGL07Hf75ZY57amMKpyRq+szCtAQwcfEXQ0BQtAppQmfzkbwgmUkaIbn4LLSrU/HjGnbzZ7Nw==
X-Received: by 2002:a05:6a21:3b8a:b0:2f4:a8f:728f with SMTP id adf61e73a8af0-2f40a8f74c7mr15074479637.29.1759169866153;
        Mon, 29 Sep 2025 11:17:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd77KXF2pMKLKVlaJ5V3k+QHhWuUkB5ANHIQpAeSxudeVg=="
Received: by 2002:aa7:9d1a:0:b0:77e:ce3:c5cf with SMTP id d2e1a72fcca58-780fee348e6ls3584444b3a.2.-pod-prod-07-us;
 Mon, 29 Sep 2025 11:17:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXUljJCPCNCOVIGbm81RLvjlt4+noMnnyhqrGW4bovAXPJ2gX+c/yMflBLL8WFR1FLWxcQKMde63gA=@googlegroups.com
X-Received: by 2002:a05:6a00:2342:b0:781:171c:54cf with SMTP id d2e1a72fcca58-781171c58demr11978029b3a.1.1759169864719;
        Mon, 29 Sep 2025 11:17:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1759169864; cv=none;
        d=google.com; s=arc-20240605;
        b=RTH4KzFMY64ES+tR5sRRo9g6LiaC2VNPGej59oquYv3qz2t7VxM2GQL+WwFz8AhF5N
         zsoTGNuuhwM/o61z6X3rVdU9xgcwD61RicBDpiqz/duE2LdXoYGHJEq2FH7nzf5xQU7N
         SyBgRwD8ai3BD9JTUTcoDCS0SM6ga0QSPAL90ywtFvs5KVw1lcwwkE0qKE3rfuXIAwxT
         wbwZaWCQ4JC7VEvzuBqCoPfs1+GvBKplUudufBJXWhO2k2cNI5/nDmvcGRLaUoFlk9bQ
         4+cOp/uLB6aD8VWR2rsVlQSkREmi4lcDLr3AEvn6iMhwexB39LdtEuICl+Vw2QVpKa8G
         u3wg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=rbR40gIwz1eWno2qORrORtHBF7WKzEwOSgZS9A7bK9A=;
        fh=gXhaYtjcy0+GATm9FJ+WwhxG0byq9UeCM+m56AVcRfw=;
        b=ihGWofM22d8rw5jAosVbafXP0O8Rjj89STQxJLNqC7yopnwjaMs8SW5UCMPaKu8FJi
         uAOXbl9kmSWHlzPe9rT/8b7tpm8tXj4aubAB4E3+z/C0y7PxJFD/ZUpHkb4foStfzvPS
         TY50QryHocrUgzDVrLUtkcNChcD1ZuRGPh+ahHVJKi98ZS3/F8AQNaq2YwOejYJWObOh
         0gHkwv9YwHCuNytEfAu13pUhOZ2Sol/R5RbS0o4yybq2HwEnV6ioCorkRKyiHjNybvps
         L5LIHKSUjuCBzuZNZ2BG3oYftvfF6va7NCUaRrhgpSZsTgsaE9dlSv8KLVlFJ5uKTIpx
         Rg0g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="iSHp/qgY";
       spf=pass (google.com: domain of chrisl@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=chrisl@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-781028a7830si534684b3a.3.2025.09.29.11.17.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Sep 2025 11:17:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of chrisl@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 98D3E626AF
	for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 18:17:43 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 3D9D1C19423
	for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 18:17:43 +0000 (UTC)
Received: by mail-yw1-f176.google.com with SMTP id 00721157ae682-72e565bf2feso52818277b3.3
        for <kasan-dev@googlegroups.com>; Mon, 29 Sep 2025 11:17:43 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUmMb0DZpDGRsx/LlCh1B+dA33U5/kzP+FmFBxt4WGuAQzcIM15YRM2ZcM8yO1w1xc69I9o9a+aKOM=@googlegroups.com
X-Received: by 2002:a53:ea42:0:b0:63a:183:ffda with SMTP id
 956f58d0204a3-63a01a28749mr3923965d50.26.1759169862055; Mon, 29 Sep 2025
 11:17:42 -0700 (PDT)
MIME-Version: 1.0
References: <20250927080635.1502997-1-jianyungao89@gmail.com>
In-Reply-To: <20250927080635.1502997-1-jianyungao89@gmail.com>
From: "'Chris Li' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 29 Sep 2025 11:17:31 -0700
X-Gmail-Original-Message-ID: <CACePvbWkr79j-ogkp+-Eehx=pssTmb2Cb4npKGd0ehZE-qudcg@mail.gmail.com>
X-Gm-Features: AS18NWDO3sHve2jnUkOqUEozfH6mTV1MNP6z6MOxPopzdQLUYhEQ7K_wVAWGfWA
Message-ID: <CACePvbWkr79j-ogkp+-Eehx=pssTmb2Cb4npKGd0ehZE-qudcg@mail.gmail.com>
Subject: Re: [PATCH] mm: Fix some typos in mm module
To: "jianyun.gao" <jianyungao89@gmail.com>
Cc: linux-mm@kvack.org, SeongJae Park <sj@kernel.org>, 
	Andrew Morton <akpm@linux-foundation.org>, David Hildenbrand <david@redhat.com>, 
	Jason Gunthorpe <jgg@ziepe.ca>, John Hubbard <jhubbard@nvidia.com>, Peter Xu <peterx@redhat.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Xu Xin <xu.xin16@zte.com.cn>, Chengming Zhou <chengming.zhou@linux.dev>, 
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, "Liam R. Howlett" <Liam.Howlett@oracle.com>, 
	Vlastimil Babka <vbabka@suse.cz>, Mike Rapoport <rppt@kernel.org>, Suren Baghdasaryan <surenb@google.com>, 
	Michal Hocko <mhocko@suse.com>, Christoph Lameter <cl@gentwo.org>, David Rientjes <rientjes@google.com>, 
	Roman Gushchin <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, 
	Kemeng Shi <shikemeng@huaweicloud.com>, Kairui Song <kasong@tencent.com>, 
	Nhat Pham <nphamcs@gmail.com>, Baoquan He <bhe@redhat.com>, Barry Song <baohua@kernel.org>, 
	Jann Horn <jannh@google.com>, Pedro Falcato <pfalcato@suse.de>, 
	"open list:DATA ACCESS MONITOR" <damon@lists.linux.dev>, open list <linux-kernel@vger.kernel.org>, 
	"open list:KMSAN" <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: chrisl@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="iSHp/qgY";       spf=pass
 (google.com: domain of chrisl@kernel.org designates 172.105.4.254 as
 permitted sender) smtp.mailfrom=chrisl@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Chris Li <chrisl@kernel.org>
Reply-To: Chris Li <chrisl@kernel.org>
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

Acked-by: Chris Li <chrisl@kernel.org>

Chris

On Sat, Sep 27, 2025 at 1:07=E2=80=AFAM jianyun.gao <jianyungao89@gmail.com=
> wrote:
>
> Below are some typos in the code comments:
>
>   intevals =3D=3D> intervals
>   addesses =3D=3D> addresses
>   unavaliable =3D=3D> unavailable
>   facor =3D=3D> factor
>   droping =3D=3D> dropping
>   exlusive =3D=3D> exclusive
>   decription =3D=3D> description
>   confict =3D=3D> conflict
>   desriptions =3D=3D> descriptions
>   otherwize =3D=3D> otherwise
>   vlaue =3D=3D> value
>   cheching =3D=3D> checking
>   exisitng =3D=3D> existing
>   modifed =3D=3D> modified
>
> Just fix it.
>
> Signed-off-by: jianyun.gao <jianyungao89@gmail.com>
> ---
>  mm/damon/sysfs.c  | 2 +-
>  mm/gup.c          | 2 +-
>  mm/kmsan/core.c   | 2 +-
>  mm/ksm.c          | 2 +-
>  mm/memory-tiers.c | 2 +-
>  mm/memory.c       | 4 ++--
>  mm/secretmem.c    | 2 +-
>  mm/slab_common.c  | 2 +-
>  mm/slub.c         | 2 +-
>  mm/swapfile.c     | 2 +-
>  mm/userfaultfd.c  | 2 +-
>  mm/vma.c          | 4 ++--
>  12 files changed, 14 insertions(+), 14 deletions(-)
>
> diff --git a/mm/damon/sysfs.c b/mm/damon/sysfs.c
> index c96c2154128f..25ff8bd17e9c 100644
> --- a/mm/damon/sysfs.c
> +++ b/mm/damon/sysfs.c
> @@ -1232,7 +1232,7 @@ enum damon_sysfs_cmd {
>         DAMON_SYSFS_CMD_UPDATE_SCHEMES_EFFECTIVE_QUOTAS,
>         /*
>          * @DAMON_SYSFS_CMD_UPDATE_TUNED_INTERVALS: Update the tuned moni=
toring
> -        * intevals.
> +        * intervals.
>          */
>         DAMON_SYSFS_CMD_UPDATE_TUNED_INTERVALS,
>         /*
> diff --git a/mm/gup.c b/mm/gup.c
> index 0bc4d140fc07..6ed50811da8f 100644
> --- a/mm/gup.c
> +++ b/mm/gup.c
> @@ -2730,7 +2730,7 @@ EXPORT_SYMBOL(get_user_pages_unlocked);
>   *
>   *  *) ptes can be read atomically by the architecture.
>   *
> - *  *) valid user addesses are below TASK_MAX_SIZE
> + *  *) valid user addresses are below TASK_MAX_SIZE
>   *
>   * The last two assumptions can be relaxed by the addition of helper fun=
ctions.
>   *
> diff --git a/mm/kmsan/core.c b/mm/kmsan/core.c
> index 1ea711786c52..1bb0e741936b 100644
> --- a/mm/kmsan/core.c
> +++ b/mm/kmsan/core.c
> @@ -33,7 +33,7 @@ bool kmsan_enabled __read_mostly;
>
>  /*
>   * Per-CPU KMSAN context to be used in interrupts, where current->kmsan =
is
> - * unavaliable.
> + * unavailable.
>   */
>  DEFINE_PER_CPU(struct kmsan_ctx, kmsan_percpu_ctx);
>
> diff --git a/mm/ksm.c b/mm/ksm.c
> index 160787bb121c..edd6484577d7 100644
> --- a/mm/ksm.c
> +++ b/mm/ksm.c
> @@ -389,7 +389,7 @@ static unsigned long ewma(unsigned long prev, unsigne=
d long curr)
>   * exponentially weighted moving average. The new pages_to_scan value is
>   * multiplied with that change factor:
>   *
> - *      new_pages_to_scan *=3D change facor
> + *      new_pages_to_scan *=3D change factor
>   *
>   * The new_pages_to_scan value is limited by the cpu min and max values.=
 It
>   * calculates the cpu percent for the last scan and calculates the new
> diff --git a/mm/memory-tiers.c b/mm/memory-tiers.c
> index 0382b6942b8b..f97aa5497040 100644
> --- a/mm/memory-tiers.c
> +++ b/mm/memory-tiers.c
> @@ -519,7 +519,7 @@ static inline void __init_node_memory_type(int node, =
struct memory_dev_type *mem
>          * for each device getting added in the same NUMA node
>          * with this specific memtype, bump the map count. We
>          * Only take memtype device reference once, so that
> -        * changing a node memtype can be done by droping the
> +        * changing a node memtype can be done by dropping the
>          * only reference count taken here.
>          */
>
> diff --git a/mm/memory.c b/mm/memory.c
> index 0ba4f6b71847..d6b0318df951 100644
> --- a/mm/memory.c
> +++ b/mm/memory.c
> @@ -4200,7 +4200,7 @@ static inline bool should_try_to_free_swap(struct f=
olio *folio,
>          * If we want to map a page that's in the swapcache writable, we
>          * have to detect via the refcount if we're really the exclusive
>          * user. Try freeing the swapcache to get rid of the swapcache
> -        * reference only in case it's likely that we'll be the exlusive =
user.
> +        * reference only in case it's likely that we'll be the exclusive=
 user.
>          */
>         return (fault_flags & FAULT_FLAG_WRITE) && !folio_test_ksm(folio)=
 &&
>                 folio_ref_count(folio) =3D=3D (1 + folio_nr_pages(folio))=
;
> @@ -5274,7 +5274,7 @@ vm_fault_t do_set_pmd(struct vm_fault *vmf, struct =
folio *folio, struct page *pa
>
>  /**
>   * set_pte_range - Set a range of PTEs to point to pages in a folio.
> - * @vmf: Fault decription.
> + * @vmf: Fault description.
>   * @folio: The folio that contains @page.
>   * @page: The first page to create a PTE for.
>   * @nr: The number of PTEs to create.
> diff --git a/mm/secretmem.c b/mm/secretmem.c
> index 60137305bc20..a350ca20ca56 100644
> --- a/mm/secretmem.c
> +++ b/mm/secretmem.c
> @@ -227,7 +227,7 @@ SYSCALL_DEFINE1(memfd_secret, unsigned int, flags)
>         struct file *file;
>         int fd, err;
>
> -       /* make sure local flags do not confict with global fcntl.h */
> +       /* make sure local flags do not conflict with global fcntl.h */
>         BUILD_BUG_ON(SECRETMEM_FLAGS_MASK & O_CLOEXEC);
>
>         if (!secretmem_enable || !can_set_direct_map())
> diff --git a/mm/slab_common.c b/mm/slab_common.c
> index bfe7c40eeee1..9ab116156444 100644
> --- a/mm/slab_common.c
> +++ b/mm/slab_common.c
> @@ -256,7 +256,7 @@ static struct kmem_cache *create_cache(const char *na=
me,
>   * @object_size: The size of objects to be created in this cache.
>   * @args: Additional arguments for the cache creation (see
>   *        &struct kmem_cache_args).
> - * @flags: See the desriptions of individual flags. The common ones are =
listed
> + * @flags: See the descriptions of individual flags. The common ones are=
 listed
>   *         in the description below.
>   *
>   * Not to be called directly, use the kmem_cache_create() wrapper with t=
he same
> diff --git a/mm/slub.c b/mm/slub.c
> index d257141896c9..5f2622c370cc 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -2412,7 +2412,7 @@ bool slab_free_hook(struct kmem_cache *s, void *x, =
bool init,
>                 memset((char *)kasan_reset_tag(x) + inuse, 0,
>                        s->size - inuse - rsize);
>                 /*
> -                * Restore orig_size, otherwize kmalloc redzone overwritt=
en
> +                * Restore orig_size, otherwise kmalloc redzone overwritt=
en
>                  * would be reported
>                  */
>                 set_orig_size(s, x, orig_size);
> diff --git a/mm/swapfile.c b/mm/swapfile.c
> index b4f3cc712580..b55f10ec1f3f 100644
> --- a/mm/swapfile.c
> +++ b/mm/swapfile.c
> @@ -1545,7 +1545,7 @@ static bool swap_entries_put_map_nr(struct swap_inf=
o_struct *si,
>
>  /*
>   * Check if it's the last ref of swap entry in the freeing path.
> - * Qualified vlaue includes 1, SWAP_HAS_CACHE or SWAP_MAP_SHMEM.
> + * Qualified value includes 1, SWAP_HAS_CACHE or SWAP_MAP_SHMEM.
>   */
>  static inline bool __maybe_unused swap_is_last_ref(unsigned char count)
>  {
> diff --git a/mm/userfaultfd.c b/mm/userfaultfd.c
> index aefdf3a812a1..333f4b8bc810 100644
> --- a/mm/userfaultfd.c
> +++ b/mm/userfaultfd.c
> @@ -1508,7 +1508,7 @@ static int validate_move_areas(struct userfaultfd_c=
tx *ctx,
>
>         /*
>          * For now, we keep it simple and only move between writable VMAs=
.
> -        * Access flags are equal, therefore cheching only the source is =
enough.
> +        * Access flags are equal, therefore checking only the source is =
enough.
>          */
>         if (!(src_vma->vm_flags & VM_WRITE))
>                 return -EINVAL;
> diff --git a/mm/vma.c b/mm/vma.c
> index 3b12c7579831..2e127fa97475 100644
> --- a/mm/vma.c
> +++ b/mm/vma.c
> @@ -109,7 +109,7 @@ static inline bool is_mergeable_vma(struct vma_merge_=
struct *vmg, bool merge_nex
>  static bool is_mergeable_anon_vma(struct vma_merge_struct *vmg, bool mer=
ge_next)
>  {
>         struct vm_area_struct *tgt =3D merge_next ? vmg->next : vmg->prev=
;
> -       struct vm_area_struct *src =3D vmg->middle; /* exisitng merge cas=
e. */
> +       struct vm_area_struct *src =3D vmg->middle; /* existing merge cas=
e. */
>         struct anon_vma *tgt_anon =3D tgt->anon_vma;
>         struct anon_vma *src_anon =3D vmg->anon_vma;
>
> @@ -798,7 +798,7 @@ static bool can_merge_remove_vma(struct vm_area_struc=
t *vma)
>   * Returns: The merged VMA if merge succeeds, or NULL otherwise.
>   *
>   * ASSUMPTIONS:
> - * - The caller must assign the VMA to be modifed to @vmg->middle.
> + * - The caller must assign the VMA to be modified to @vmg->middle.
>   * - The caller must have set @vmg->prev to the previous VMA, if there i=
s one.
>   * - The caller must not set @vmg->next, as we determine this.
>   * - The caller must hold a WRITE lock on the mm_struct->mmap_lock.
> --
> 2.34.1
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ACePvbWkr79j-ogkp%2B-Eehx%3DpssTmb2Cb4npKGd0ehZE-qudcg%40mail.gmail.com.
