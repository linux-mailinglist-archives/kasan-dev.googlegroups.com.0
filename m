Return-Path: <kasan-dev+bncBC7OD3FKWUERBAVBU7FQMGQEAXALKJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id E6862D2C1F1
	for <lists+kasan-dev@lfdr.de>; Fri, 16 Jan 2026 06:45:39 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-888825e6423sf28865106d6.3
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jan 2026 21:45:39 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1768542338; cv=pass;
        d=google.com; s=arc-20240605;
        b=JcYdzHwo4KEy7jwRXGULECVK1Zf0EPzGIYpKTTnssJxYbOqrnSv433hiTs6ee/hvpr
         QC87vTSD5D8/EOF74ibWr4iESvOu+w0DaubGDAu3JMpYASg+lY3I1W7BbkOA2SfbbJS6
         GH+9VB4xuYHtGfkXxOiczxwjNNkeFs8XsZ6hjiud4L1UJoyoOaW4dW6IEFyDBFXUxIF6
         iija+zJovZptOB++ZQv6gsfzeUmBGITKvtk4SWbYn3b0WizOsRYiu965jvMVz34e7pAw
         kSAg7HrQdz6ib00soaB3dgNCqO2Y8y4zl7PwB6HYw3+Gjp2p/Fu07jGzIVIGGA0ZcHyK
         HFQg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LCX8edHFpnblveBHBRiVruUMlz7AxGX3zbDYetx9k6Q=;
        fh=7US9BdqGtwG3pEDZ8LhdF7xZNkh0doM4N9pf/xg8k1A=;
        b=XiB1prIeNU+Tllg7L2MAwf6nMxZ35n4tW2ZbVDH3DTnV2sWdL9j8yS9csRqy6+wrPg
         Yk2DLm7XRIYabxKHB5nXdttiDWmSMBh4749YlTE+AwPxYLyLofwlfS5umzhomx3O+g0h
         /TCJvKcB1v/T3WsrqshTHnco5HR/TILmFmddcuCX/ZkUzgE+BYN4WOquecRWZ7wC2GfL
         lCdEkUGkssMDWC2Ex2IFB5w/pPxY94Za+rR59piwzx/ERhWvMp/lqT5nHBztWB1QoQL5
         6xvvfcOqFUI2gbpZ4MwLT18f5Newhkk/R7PJj+clvU0sM+LlCekYJ+F9PDarqtE80/0q
         9sFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g3UWQK3C;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768542338; x=1769147138; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LCX8edHFpnblveBHBRiVruUMlz7AxGX3zbDYetx9k6Q=;
        b=eG3tUr80WCdfdLeZ2jZjq7b/+zRe2UBz3YxTgxkmp6NBcsZYkZQJ8M7TiWdieWMvuY
         4Pt9Uhd9zZzwdFS0Ulo3CXPaoRZ8ujKQxh1tw1m+xctlpD0iPjUBWQcsYja7kzGc3MPr
         LAeyRD93fZ/IrATe8j00o5kZr2MJwJ/c8fRGgd+VK08UX2rh2wxtn1gWdYPRQ26yANUZ
         VC1gVagZcxxqxY2VnQ7mw2Nzg2C8TFzUhYtRGf4MCzcBIGoDmW+0n4qnnXiNCjI1pTmA
         vv0RN8a/ClOQ+UVGFKfDxXFJMWWr2Kp4mxf0YJQ0lPp8KNVb8l/aYyaYREcRwyq5InXz
         YVSg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768542338; x=1769147138;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=LCX8edHFpnblveBHBRiVruUMlz7AxGX3zbDYetx9k6Q=;
        b=HUlV8zBAEFsGAUHFuUZX14P7uIPoUBQQiqHjhScNDEYjNT2wwLt0jxakUKz+vBj3B2
         lgXYtKfYyvUPD8jPv2I5fIrnQrkeT+Q0/rxmjjikIEHdKBPZ5QEeYcm8BFd9dauXUV3E
         Brk44Wf07TaeDof9GP2HZiUhKBGJXeY6qGF4n3jRWgPjEhM5WCdcCtJpvvS408d9fKy3
         Ic4NL9Iz2jtZF0ezEjK7OwNPsGO/rbIe+0vwK1YjJacI9O+NOcd+IbIzull+R/AOwna+
         pJIGxuJ3OENqKw149Cuw3rGfIJ566NU4VYKK1uFvLuxGNYAS8tAbhA7AvPfc/r7yKfdp
         1A6w==
X-Forwarded-Encrypted: i=3; AJvYcCVwsmhXUt061UbERG+RfIQEVZiweCkKInuegocHo5VhTHuuJ4WWFlMyP2r2BxM05M3smp/PMw==@lfdr.de
X-Gm-Message-State: AOJu0YznPhPwnxCzJsHOeh/jk9SVzHRbqWlswk0wg02GuW2C3gYVaD7X
	ZbmyvcI9AA/A8MiT0CgLBgQPfDHA0K3W6xZyFGiWZTC72QsomeL0WCLC
X-Received: by 2002:ad4:5b8f:0:b0:88a:3113:3ac3 with SMTP id 6a1803df08f44-8942dcf87d0mr24726326d6.10.1768542338419;
        Thu, 15 Jan 2026 21:45:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Hh3y7rbUYh3r2M9k5lZBRFnUTPCWf40HQReuKhHZFkIw=="
Received: by 2002:a05:6214:1c09:b0:880:57b3:cd12 with SMTP id
 6a1803df08f44-894222e7986ls25558026d6.1.-pod-prod-03-us; Thu, 15 Jan 2026
 21:45:37 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCX/64fTZ3ifVsJv+G+3OEXJkB8nEjoj4kWSXgnwrr4TYSfChOj4L9EvqelDLYUXIpo+7DYSjVPvEek=@googlegroups.com
X-Received: by 2002:a05:6122:7c8:b0:54a:1e96:e958 with SMTP id 71dfb90a1353d-563b5a79b75mr839449e0c.0.1768542337623;
        Thu, 15 Jan 2026 21:45:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768542337; cv=pass;
        d=google.com; s=arc-20240605;
        b=lniZd080GxNE+54Vv1V+f9NIck4ldWSQE6VFlh5Ec3tYioXi18Y3ZGfl8oO2B6yiUX
         KfQpxbqc9V/acj5yfqnfQ7IFQFwa4M9sOLB2wH6fJwcebe7BSlXf6QfZusrYNQX1swgW
         o2bH/75NpS+9yP8YET6hIK0q7gOQlLb4hxPTDMqRT1EB6KT1TlWbo8relG9DNTW2is19
         1n0/szSmKz2shpO3TQWgEHje9aJmv/BFCltBvzM691oARauF0vmnhwJ4VPsAnlGZbKVR
         TLBQDlOhE27qZjwiFOViT2TNsCxKmSlXkRQGZEVIgDBoKiFaRs8L3Ptipma7L5l5cG0h
         wbUw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oD4lKTyPruUjM+2ZGAjFWRV4Lq8q1KPCB1ITiVRP8FE=;
        fh=Q2P18sM6E341nE/H1ur9zB+XlKvSnbWAGKlI7BwspFw=;
        b=LKtIjhiumSrr2h73IBucxNvQqeF0lUZYlHzu7QVbvhhefj4vGQzCX3RrVlWHYfAdtT
         QFob29esAalCvnPyQ8FscN44bXlIWrH3Ful5Up1PS1JFba+fnEywdV2TnF+AGn7AZzg1
         lQvq97TCpewWTXOHhTDl4OMOf7sWP2naIfMnPr+P3T6nypJkVMBgflhvkHWmdDbRUa0B
         YwhF67CLOdnElcHT4aq2Iyap7Qh9MS3xPMLZ0mqbnRZwFmEPN/PX4VYBU5qgfqe9ZNzr
         xNI1mVNa9lHZYrSb7cmwb5gxxm51LJgV4tESBVnE9kBJGDr6o6kAT4UcS5aJiUOWpyA7
         TpcA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=g3UWQK3C;
       arc=pass (i=1);
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-563b713daecsi48482e0c.7.2026.01.15.21.45.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 15 Jan 2026 21:45:37 -0800 (PST)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id d75a77b69052e-5014acad6f2so227861cf.1
        for <kasan-dev@googlegroups.com>; Thu, 15 Jan 2026 21:45:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768542337; cv=none;
        d=google.com; s=arc-20240605;
        b=SdkOvwiUV0pLOf5aCrwIOf+ACVuay17+0cjq4FBfImABaehTTh3PQykBqtl5pJ2ZYX
         +5lC2LDTBnLGwmELmxnc963WS2dTxcv1YwQvg+DYa4lTalzg6PI9YjX+SHo3D/CA/GqM
         1Zqd6CBwNM6q+TyXwnSJ6zZSSDov1yH2mxxNt00qxzYm2YnVR11adkNFlP5h0jBqVpMk
         DZA/2cmAJMk27J8jM6FWeN6RhH++HNOcdqFvyLjbjRgM7TE1zlcrDykoiCRIvungg09G
         2xCI45y2ziiIKA9OgCNbNTtsbCYSQIAAcsLgMPjlCl6bD27KrYHCYBR8CsVKcKnaqGG2
         XXPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=oD4lKTyPruUjM+2ZGAjFWRV4Lq8q1KPCB1ITiVRP8FE=;
        fh=Q2P18sM6E341nE/H1ur9zB+XlKvSnbWAGKlI7BwspFw=;
        b=C0+IdStSHtovvX/TGLUJgWH1pWbAspisG7mcyy1qtzWAhUMbv6uxb/knAQVTALfpEk
         8fIrgI+zZAAEhiLuGECvMZ/2FSfXLLOCDv/7Kj3KZmPCXf3c7UgrCK07PP/0mVwadY+H
         BHeLrXlQWm6pOftHaj7ZkCkXx8D5eeD3RPrjWosU7t04wMNUak1TVhxmbdvOHCZLRbYH
         mANTzZvMPcZwHQ1HexhtzxkuzU8l/DyOkFuXnzPCVin5Qj1wsiNcbXRoWUDPtdImktAy
         rj2eizFtb4hGi38ilURrLDhgKmiqgM3DhFttbSfiRECoX+DN3h2S47L5OtbM3O1tjMcz
         vjug==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUw9ovHp54xcDr1fMyci5sRBHTZCUiAdFaJ7R08uZs1oQG4ClJgHr0yhsp//5PuRx/g3br8KRE0Zxo=@googlegroups.com
X-Gm-Gg: AY/fxX7mzYGKBpSP1/IWTxZQ5hS8f0MizxDAbElkZ5a/uFm+QKrwwDP07K7ZqM9rkef
	7QXFTs0uFuZJYKjPphuhldJlD0f4XvOa6bGyg3z3yPOBGOVqDl3OBdeFP4EWrAzz7Po/hj3uNij
	5EvX6ijWTk3iXlWKPiy+vme3LUehz+RGLR8t7hVe0OCn0czvkTPABpGERBnJFMyB36m8aV/flCA
	BI5XeTerB+ADNWaIkgIb1N71OERv5EyJDBjnPndriiRYMTMyRIEnNa/PGq6SpXHtPG1UqlKBig3
	MxEog8S5yJK6sPFINhsULJyxfe44dw+wHg==
X-Received: by 2002:ac8:5a93:0:b0:4ed:8103:8c37 with SMTP id
 d75a77b69052e-502a23ba0bemr6815851cf.12.1768542336851; Thu, 15 Jan 2026
 21:45:36 -0800 (PST)
MIME-Version: 1.0
References: <20260112-sheaves-for-all-v2-0-98225cfb50cf@suse.cz> <20260112-sheaves-for-all-v2-4-98225cfb50cf@suse.cz>
In-Reply-To: <20260112-sheaves-for-all-v2-4-98225cfb50cf@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 16 Jan 2026 05:45:26 +0000
X-Gm-Features: AZwV_Qj313U65TQKJGcZKomalyp4G4s3S9dwtw3N-deAJ8pCUFL8HFCSglYguDc
Message-ID: <CAJuCfpFKKtxB2mREuOSa4oQu=MBGkbQRQNYSSnubAAgPENcO-Q@mail.gmail.com>
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
 header.i=@google.com header.s=20230601 header.b=g3UWQK3C;       arc=pass
 (i=1);       spf=pass (google.com: domain of surenb@google.com designates
 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=surenb@google.com;
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

On Mon, Jan 12, 2026 at 3:17=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> In the first step to replace cpu (partial) slabs with sheaves, enable
> sheaves for almost all caches. Treat args->sheaf_capacity as a minimum,
> and calculate sheaf capacity with a formula that roughly follows the
> formula for number of objects in cpu partial slabs in set_cpu_partial().
>
> This should achieve roughly similar contention on the barn spin lock as
> there's currently for node list_lock without sheaves, to make
> benchmarking results comparable. It can be further tuned later.
>
> Don't enable sheaves for bootstrap caches as that wouldn't work. In
> order to recognize them by SLAB_NO_OBJ_EXT, make sure the flag exists
> even for !CONFIG_SLAB_OBJ_EXT.
>
> This limitation will be lifted for kmalloc caches after the necessary
> bootstrapping changes.
>
> Signed-off-by: Vlastimil Babka <vbabka@suse.cz>

One nit but otherwise LGTM.

Reviewed-by: Suren Baghdasaryan <surenb@google.com>

> ---
>  include/linux/slab.h |  6 ------
>  mm/slub.c            | 51 ++++++++++++++++++++++++++++++++++++++++++++++=
+----
>  2 files changed, 47 insertions(+), 10 deletions(-)
>
> diff --git a/include/linux/slab.h b/include/linux/slab.h
> index 2482992248dc..2682ee57ec90 100644
> --- a/include/linux/slab.h
> +++ b/include/linux/slab.h
> @@ -57,9 +57,7 @@ enum _slab_flag_bits {
>  #endif
>         _SLAB_OBJECT_POISON,
>         _SLAB_CMPXCHG_DOUBLE,
> -#ifdef CONFIG_SLAB_OBJ_EXT
>         _SLAB_NO_OBJ_EXT,
> -#endif
>         _SLAB_FLAGS_LAST_BIT
>  };
>
> @@ -238,11 +236,7 @@ enum _slab_flag_bits {
>  #define SLAB_TEMPORARY         SLAB_RECLAIM_ACCOUNT    /* Objects are sh=
ort-lived */
>
>  /* Slab created using create_boot_cache */
> -#ifdef CONFIG_SLAB_OBJ_EXT
>  #define SLAB_NO_OBJ_EXT                __SLAB_FLAG_BIT(_SLAB_NO_OBJ_EXT)
> -#else
> -#define SLAB_NO_OBJ_EXT                __SLAB_FLAG_UNUSED
> -#endif
>
>  /*
>   * ZERO_SIZE_PTR will be returned for zero sized kmalloc requests.
> diff --git a/mm/slub.c b/mm/slub.c
> index 8ffeb3ab3228..6e05e3cc5c49 100644
> --- a/mm/slub.c
> +++ b/mm/slub.c
> @@ -7857,6 +7857,48 @@ static void set_cpu_partial(struct kmem_cache *s)
>  #endif
>  }
>
> +static unsigned int calculate_sheaf_capacity(struct kmem_cache *s,
> +                                            struct kmem_cache_args *args=
)
> +
> +{
> +       unsigned int capacity;
> +       size_t size;
> +
> +
> +       if (IS_ENABLED(CONFIG_SLUB_TINY) || s->flags & SLAB_DEBUG_FLAGS)
> +               return 0;
> +
> +       /* bootstrap caches can't have sheaves for now */
> +       if (s->flags & SLAB_NO_OBJ_EXT)
> +               return 0;
> +
> +       /*
> +        * For now we use roughly similar formula (divided by two as ther=
e are
> +        * two percpu sheaves) as what was used for percpu partial slabs,=
 which
> +        * should result in similar lock contention (barn or list_lock)
> +        */
> +       if (s->size >=3D PAGE_SIZE)
> +               capacity =3D 4;
> +       else if (s->size >=3D 1024)
> +               capacity =3D 12;
> +       else if (s->size >=3D 256)
> +               capacity =3D 26;
> +       else
> +               capacity =3D 60;
> +
> +       /* Increment capacity to make sheaf exactly a kmalloc size bucket=
 */
> +       size =3D struct_size_t(struct slab_sheaf, objects, capacity);
> +       size =3D kmalloc_size_roundup(size);
> +       capacity =3D (size - struct_size_t(struct slab_sheaf, objects, 0)=
) / sizeof(void *);
> +
> +       /*
> +        * Respect an explicit request for capacity that's typically moti=
vated by
> +        * expected maximum size of kmem_cache_prefill_sheaf() to not end=
 up
> +        * using low-performance oversize sheaves
> +        */
> +       return max(capacity, args->sheaf_capacity);
> +}
> +
>  /*
>   * calculate_sizes() determines the order and the distribution of data w=
ithin
>   * a slab object.
> @@ -7991,6 +8033,10 @@ static int calculate_sizes(struct kmem_cache_args =
*args, struct kmem_cache *s)
>         if (s->flags & SLAB_RECLAIM_ACCOUNT)
>                 s->allocflags |=3D __GFP_RECLAIMABLE;
>
> +       /* kmalloc caches need extra care to support sheaves */
> +       if (!is_kmalloc_cache(s))

nit: All the checks for the cases when sheaves should not be used
(like SLAB_DEBUG_FLAGS and SLAB_NO_OBJ_EXT) are done inside
calculate_sheaf_capacity(). Only this is_kmalloc_cache() one is here.
It would be nice to have all of them in the same place but maybe you
have a reason for keeping it here?

> +               s->sheaf_capacity =3D calculate_sheaf_capacity(s, args);
> +
>         /*
>          * Determine the number of objects per slab
>          */
> @@ -8595,15 +8641,12 @@ int do_kmem_cache_create(struct kmem_cache *s, co=
nst char *name,
>
>         set_cpu_partial(s);
>
> -       if (args->sheaf_capacity && !IS_ENABLED(CONFIG_SLUB_TINY)
> -                                       && !(s->flags & SLAB_DEBUG_FLAGS)=
) {
> +       if (s->sheaf_capacity) {
>                 s->cpu_sheaves =3D alloc_percpu(struct slub_percpu_sheave=
s);
>                 if (!s->cpu_sheaves) {
>                         err =3D -ENOMEM;
>                         goto out;
>                 }
> -               // TODO: increase capacity to grow slab_sheaf up to next =
kmalloc size?
> -               s->sheaf_capacity =3D args->sheaf_capacity;
>         }
>
>  #ifdef CONFIG_NUMA
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
AJuCfpFKKtxB2mREuOSa4oQu%3DMBGkbQRQNYSSnubAAgPENcO-Q%40mail.gmail.com.
