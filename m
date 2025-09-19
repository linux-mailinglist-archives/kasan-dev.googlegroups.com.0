Return-Path: <kasan-dev+bncBCUY5FXDWACRB3XIWLDAMGQENTD3UZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 60452B879F0
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 03:39:59 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id 5b1f17b1804b1-45ddbdb92dfsf6822385e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 18:39:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758245999; cv=pass;
        d=google.com; s=arc-20240605;
        b=RilczmuYczoDCE3Sl2TdkNivIgZiPKHv15eo3EsqPnR5bpXO0yonxqzKhzreklAgM/
         F6YZVdmP5rV7NAjosp70T5Sx4cGpfP3mLHr6XeJKacjaJwdIZjI4SuUegyezapG5yJ6N
         AlZvcIGHGMMLtCJSBI2emzBpnR+gDmjrCKYFpcn9PRNerd6V1HF8uTwAyyPEMyK+by6b
         ZfBKdacBZapfaomDh4zfE4tA9WjFTbmwlBDA8Qvfj96E+r5/bxykwvgqbce9yok75iNy
         KpANdTeipmgCOszKHdUYacBn0rBdEXhcTRrXZSOjHOYCeMO4Ar/hpki9TSQ5QVy4cjmP
         740A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=LRXU5sdCcHnZHB0niNSma0gSJ6f4hHe5oFnXF9OTdJQ=;
        fh=9zgLyyv5I6chCnaoQzD2tAR7xxD+Lkaf+pxwwYsbuWY=;
        b=Yq/xGuPRQQqnWarNLy1XH2tIT36fRwe38z84imYLAjG0ul1cGFgwYa7UHwuDoYo5X1
         2fDho9PbbRsk31kpE4o5HgrpW0/Ft2Ow4EZLY34UGF2sjYJc70xqiuvLv+oft25PYagS
         FnqBRUoYIMqwba76uoeN20gVO9ZZrAsvIQgGS+fIBfUm4E3Mo4KC9EPgSsvKolrYCQjC
         SaYbXJLGVeGK3DdgE+Uv9UcWxhpw2v1PzjOa484Rb0r8H4OJKQAluFaXxlmPtX0P+OSm
         lMiB/LgaNqkrWnIg7Ooq+sAS0z+jFLgjOM5meGiAOf7dFJJ/2umFqNz2QqQQHTcFEEmg
         bXRQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WjfSVpl1;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758245999; x=1758850799; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LRXU5sdCcHnZHB0niNSma0gSJ6f4hHe5oFnXF9OTdJQ=;
        b=aZRH80kEoFl/rZmwPIWTF1pKI+9bwz04bMeeRVb0Y/gv2fEKb2mjBUqVIBEgRAApDj
         muY7KvlF+Dkvvo+auaT3gH39BGQ2Ttm2biLxahkuVEwswhDk/STjpEnGjt4PBh/f5QPA
         7v/Zs25/qkF03RdxMVORvlWbaUC7f9i78gVJwZrNZSabCt8A3/uI4VL76tO0Bjt14oxd
         3JSoYFlc2P3V+LNNblakshiO2hJFtyLaN8qbCxsIhDA2JrPCEznGqFrcjIwmHb7H8/Sy
         ywDsIXjL6/Chw4CdBaaksqN9QoYBZ+zwv4xUbQE6WiZ/8prmQoVBDOst/jEJhg779goW
         9EyA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758245999; x=1758850799; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=LRXU5sdCcHnZHB0niNSma0gSJ6f4hHe5oFnXF9OTdJQ=;
        b=W2aTfPNfCCWDawTabShDRhR3q+iBjR9eNuZFydRKijyyZfbDbpOwSYTQQl0MjxPPf8
         iKtZwYp2wmAEMtOziwTpR/q/1AXC7hAEAD9qcHDLNYwYIRKAQG8miAR45Q5TVxebZp+R
         NoEheHnI9AwOQFAqVGrS2PShEdA9myRBRje9rIxZDYiDqa6t/hFSkhTGCQ6ltJye5HR0
         cPs0KvCjKzMcZzz7+4UTLHr7JAAHdLKcGbICgSxnqMCrwQFJ6PJQ/S5niveNcQ/ikhR6
         sd6SmLYoF6FGWpxD8L/R9Y1iZnrh45V5AzsOIB1RPldcDmrvsXHC1yinz9j39JOYS2v0
         dSkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758245999; x=1758850799;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LRXU5sdCcHnZHB0niNSma0gSJ6f4hHe5oFnXF9OTdJQ=;
        b=UF33j1VKEX8Kfxh0AmCytjCW6POA0ti8yZub66eYOpV5Zq4Bl/qmL/nZ5bAsDxsw1b
         75ZSkCHRUy4lX/SN3haBSskFFIy5B/nPG7K301AOVvFBiv6o3oXjKOkt2p3sypjR2hiV
         pBJJWcjbn/0giMrAcMl6vdoQNe+rkSTPphHc72y+jS+a5pBEXb1Y83L8xL2qn3i9+po8
         wXJo+QRBoMMOJg77nyjqwyQZ+fHPuxEmDiM5IeC9k5ZoULAenWze1J9bRJXqGPaj4OQv
         vdoMKfJq772k6tnoQtM+F+hEvGuwz9DLjbb9Y4WzfRvEPNsHRMpQH0wQ3v8ue9jGEKjf
         iCeg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVIaPtL4EPEJnPXANj2aMBiqx6QK5iVfkKp0QVv78vPn3Fiogzv8eUrh/Ezl7m+wsEfFQrGOw==@lfdr.de
X-Gm-Message-State: AOJu0YyiaIFBz8zG8ZQ0IkQPCwRrIxm9GSqkutGOz+7ZFuDd6W8rgx13
	suR9laY+7cYAqWHZDoOweMXK2mtEhsc4rgllCX2eWTenkIkKBHoio63s
X-Google-Smtp-Source: AGHT+IGduBWjb2tcLiF/doYbkysDxmiYPz7lSIlkjPRp7OieAdprbDWb4RIfSIpIAmMo7gU+1YuxMg==
X-Received: by 2002:a05:600c:1c01:b0:468:9798:1b4c with SMTP id 5b1f17b1804b1-4689798319dmr2222015e9.25.1758245998698;
        Thu, 18 Sep 2025 18:39:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5OCOOrUj+zvBBldItOWM/ov7ifM3f34iJEaIHGqcgG/A==
Received: by 2002:a05:600c:4ed4:b0:456:241d:50bd with SMTP id
 5b1f17b1804b1-46543cea6d3ls7312805e9.2.-pod-prod-04-eu; Thu, 18 Sep 2025
 18:39:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUS6VNsrKIkMEgJVsVtNj9PSEktkX6q6XWnoP2cuk9FCEOEw4pIdLX3c04wV9iT9HhBdOj3YDWJ2v4=@googlegroups.com
X-Received: by 2002:a05:600c:4fcb:b0:45c:4470:271c with SMTP id 5b1f17b1804b1-467f205a428mr8662195e9.18.1758245995545;
        Thu, 18 Sep 2025 18:39:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758245995; cv=none;
        d=google.com; s=arc-20240605;
        b=TF+Z3ajFgFIMHoKEbfntiuuXtIjEi+wMrbik8B5QMHsRbRLjuMDsFZt+yl+FnvP1dM
         jh6U87wUPVlXg5nR0dZQTDvUQKgOZhrJgmzI4ezPx6WJUuoEUVH6aaWZKZenVhnGiz9R
         0XpC93FnBNLSyNAXCBEpQCuuJMJlNpms1/6XlrjEeCOUH1qGTuq3LQ3bUs1JQHjqvMOK
         qlIU3Y4SYjVxlxMcFmPvfNC19TxN7JB80csyYhmFbxxyH4TWcbVo7y3K3EsWZL+6ZIVl
         RyBhbgZYEfZyVyuFHrhILUudzqoWlhHbRwkf6BUoBKc1fIvZnk3Ptv7e9P5rI8o4HEN5
         yuBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=TLWwqggp3K/TaMuP/qh+3dUHM74KL5ZFGLTQM4YRlUo=;
        fh=qepemk6vmcSeC0fFuX6BN/DDFaHdG4t9uNcbqMdDtYE=;
        b=I3PFpFkuEz1hxzp07aGw6WBfJd2CqNcemIP6feMKIDMQr+MIr1ag38eB75px8VdEm+
         05rtBLE3zNkOM0Q6IqOIfpNd1kh/WYM0MjkZQfMcdW3w8Fe/FWskQ+8Yj97Ekc5jJ4E8
         qM5Nf0lcCfCqAOAlFb2ZFoov7PdN35EQKDgM6xpZc98CdBDFEp77ixTZsD0w9xHMeTnv
         YfaVqjJJ5+eDfLkG5+E2udS/56B70xKWBrRjqLjzZb9oRBOThgZ+3Ed9veqUATJIE8b2
         xu5YI3EUdbGtUXfLaOmEeEU6aMV2CLqIyEhSOwyNH4g12FkJuOwe82KJge0A2UdYuTPH
         /6UA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=WjfSVpl1;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4607aaf8226si1402585e9.1.2025.09.18.18.39.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 18:39:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id 5b1f17b1804b1-45dde353b47so7884695e9.3
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 18:39:55 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV2Tc2z3gQcIMWzu3WP+aC3DzabVTvnNnZylDscpYGugjMwmuO0VJSbd47estcPcdi4mhSNZWY7vsw=@googlegroups.com
X-Gm-Gg: ASbGncuYygpDBhj42nBHcaUAdNg/Lw9K3fsjYVbBbbipiBMtk0Tvx/UFiduvPQzXoyF
	VKTajbT6Xx6Syity+JsK1ANcuB+IHGQLuhDVerx7G/8yD4HWTx8qZPNGWPNG72yNu71e+0/yXwu
	XAqXq/LJN6Xbj7ymCJASYzrLQsT3NBion+GeVuODExcSt6W9XknbG3uQ1x6mt+x5g9YaBulsZ2k
	Dwtj0nZgXYNIY3Qp1fSCYmu4WzMKDT+l8DK
X-Received: by 2002:a05:600c:4fc3:b0:45d:ddc6:74a9 with SMTP id
 5b1f17b1804b1-467eed8f915mr8129025e9.12.1758245994492; Thu, 18 Sep 2025
 18:39:54 -0700 (PDT)
MIME-Version: 1.0
References: <202509171214.912d5ac-lkp@intel.com> <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
 <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz> <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
 <ce3be467-4ff3-4165-a024-d6a3ed33ad0e@suse.cz> <CAJuCfpGLhJtO02V-Y+qmvzOqO2tH5+u7EzrCOA1K-57vPXhb+g@mail.gmail.com>
In-Reply-To: <CAJuCfpGLhJtO02V-Y+qmvzOqO2tH5+u7EzrCOA1K-57vPXhb+g@mail.gmail.com>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Thu, 18 Sep 2025 18:39:43 -0700
X-Gm-Features: AS18NWBlUth1kJvWS5JXtLwteu2b8Preo5gOd_kEK4OqVju9jJmrGXsODrzjcRM
Message-ID: <CAADnVQLPq=puz04wNCnUeSUeF2s1SwTUoQvzMWsHCVhjFcyBeg@mail.gmail.com>
Subject: Re: [linux-next:master] [slab] db93cdd664: BUG:kernel_NULL_pointer_dereference,address
To: Suren Baghdasaryan <surenb@google.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, kernel test robot <oliver.sang@intel.com>, 
	Alexei Starovoitov <ast@kernel.org>, Harry Yoo <harry.yoo@oracle.com>, oe-lkp@lists.linux.dev, 
	kbuild test robot <lkp@intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:CONTROL GROUP (CGROUP)" <cgroups@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=WjfSVpl1;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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

On Thu, Sep 18, 2025 at 7:49=E2=80=AFAM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> On Thu, Sep 18, 2025 at 12:06=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz>=
 wrote:
> >
> > On 9/17/25 20:38, Alexei Starovoitov wrote:
> > > On Wed, Sep 17, 2025 at 2:18=E2=80=AFAM Vlastimil Babka <vbabka@suse.=
cz> wrote:
> > >>
> > >> Also I was curious to find out which path is triggered so I've put a
> > >> dump_stack() before the kmalloc_nolock call:
> > >>
> > >> [    0.731812][    T0] Call Trace:
> > >> [    0.732406][    T0]  __dump_stack+0x18/0x30
> > >> [    0.733200][    T0]  dump_stack_lvl+0x32/0x90
> > >> [    0.734037][    T0]  dump_stack+0xd/0x20
> > >> [    0.734780][    T0]  alloc_slab_obj_exts+0x181/0x1f0
> > >> [    0.735862][    T0]  __alloc_tagging_slab_alloc_hook+0xd1/0x330
> > >> [    0.736988][    T0]  ? __slab_alloc+0x4e/0x70
> > >> [    0.737858][    T0]  ? __set_page_owner+0x167/0x280
> > >> [    0.738774][    T0]  __kmalloc_cache_noprof+0x379/0x460
> > >> [    0.739756][    T0]  ? depot_fetch_stack+0x164/0x180
> > >> [    0.740687][    T0]  ? __set_page_owner+0x167/0x280
> > >> [    0.741604][    T0]  __set_page_owner+0x167/0x280
> > >> [    0.742503][    T0]  post_alloc_hook+0x17a/0x200
> > >> [    0.743404][    T0]  get_page_from_freelist+0x13b3/0x16b0
> > >> [    0.744427][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > >> [    0.745358][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > >> [    0.746290][    T0]  ? __next_zones_zonelist+0x26/0x60
> > >> [    0.747265][    T0]  __alloc_frozen_pages_noprof+0x143/0x1080
> > >> [    0.748358][    T0]  ? lock_acquire+0x8b/0x180
> > >> [    0.749209][    T0]  ? pcpu_alloc_noprof+0x181/0x800
> > >> [    0.750198][    T0]  ? sched_clock_noinstr+0x8/0x10
> > >> [    0.751119][    T0]  ? local_clock_noinstr+0x137/0x140
> > >> [    0.752089][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > >> [    0.753023][    T0]  alloc_slab_page+0xda/0x150
> > >> [    0.753879][    T0]  new_slab+0xe1/0x500
> > >> [    0.754615][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > >> [    0.755577][    T0]  ___slab_alloc+0xd79/0x1680
> > >> [    0.756469][    T0]  ? pcpu_alloc_noprof+0x538/0x800
> > >> [    0.757408][    T0]  ? __mutex_unlock_slowpath+0x195/0x3e0
> > >> [    0.758446][    T0]  __slab_alloc+0x4e/0x70
> > >> [    0.759237][    T0]  ? mm_alloc+0x38/0x80
> > >> [    0.759993][    T0]  kmem_cache_alloc_noprof+0x1db/0x470
> > >> [    0.760993][    T0]  ? mm_alloc+0x38/0x80
> > >> [    0.761745][    T0]  ? mm_alloc+0x38/0x80
> > >> [    0.762506][    T0]  mm_alloc+0x38/0x80
> > >> [    0.763260][    T0]  poking_init+0xe/0x80
> > >> [    0.764032][    T0]  start_kernel+0x16b/0x470
> > >> [    0.764858][    T0]  i386_start_kernel+0xce/0xf0
> > >> [    0.765723][    T0]  startup_32_smp+0x151/0x160
> > >>
> > >> And the reason is we still have restricted gfp_allowed_mask at this =
point:
> > >> /* The GFP flags allowed during early boot */
> > >> #define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM|__GFP_IO|__=
GFP_FS))
> > >>
> > >> It's only lifted to a full allowed mask later in the boot.
> > >
> > > Ohh. That's interesting.
> > >
> > >> That means due to "kmalloc_nolock() is not supported on architecture=
s that
> > >> don't implement cmpxchg16b" such architectures will no longer get ob=
jexts
> > >> allocated in early boot. I guess that's not a big deal.
> > >>
> > >> Also any later allocation having its flags screwed for some reason t=
o not
> > >> have __GFP_RECLAIM will also lose its objexts. Hope that's also acce=
ptable.
> > >> I don't know if we can distinguish a real kmalloc_nolock() scope in
> > >> alloc_slab_obj_exts() without inventing new gfp flags or passing an =
extra
> > >> argument through several layers of functions.
> > >
> > > I think it's ok-ish.
> > > Can we add a check to alloc_slab_obj_exts() that sets allow_spin=3Dtr=
ue
> > > if we're in the boot phase? Like:
> > > if (gfp_allowed_mask !=3D __GFP_BITS_MASK)
> > >    allow_spin =3D true;
> > > or some cleaner way to detect boot time by checking slab_state ?
> > > bpf is not active during the boot and nothing should be
> > > calling kmalloc_nolock.
> >
> > Checking the gfp_allowed_mask should work. Slab state is already UP so =
won't
> > help, and this is not really about slab state anyway.
> > But whether worth it... Suren what do you think?
>
> Vlastimil's fix is correct. We definitely need __GFP_NO_OBJ_EXT when
> allocating an obj_exts vector, otherwise it will try to recursively
> allocate an obj_exts vector for obj_exts allocation.
>
> For the additional __GFP_BITS_MASK check, that sounds good to me as
> long as we add a comment on why that is there. Or maybe such a check
> deserves to be placed in a separate function similar to
> gfpflags_allow_{spinning | blocking}?

I would not. I think adding 'boot or not' logic to these two
will muddy the waters and will make the whole slab/page_alloc/memcg
logic and dependencies between them much harder to follow.
I'd either add a comment to alloc_slab_obj_exts() explaining
what may happen or add 'boot or not' check only there.
imo this is a niche, rare and special.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQLPq%3Dpuz04wNCnUeSUeF2s1SwTUoQvzMWsHCVhjFcyBeg%40mail.gmail.com.
