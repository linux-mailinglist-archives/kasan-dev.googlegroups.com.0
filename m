Return-Path: <kasan-dev+bncBCUY5FXDWACRBLWDW3DAMGQE3HWXN6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 88665B8AEC6
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 20:32:17 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-469e82ad756sf3145005e9.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 11:32:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758306737; cv=pass;
        d=google.com; s=arc-20240605;
        b=KGxzX+2Wz6lQWMBacn1+sLuBLdPdNwxVhvCrYu0S9m4hLe2MRwLkfHx5EZZi/wKSC9
         80co9+pU8DreuJcIBSeMwQdfh9ou0qLZJm5RfN3fywcNz62oVv2yZr50URSVB8AuUf/S
         XLLv1mito0XpR7+HsbPPmjExXPMPgaI5Ph1rcyB5t08+dZ+3n3YBToAx8NVzUbTFAJtY
         NNNsSTAeGdMQeJvqrh2H/q23GQ5uY6hAvipE7dwpkPBLz3ysUO8QnROZKyk4l3ufYJrL
         KnWgPEkGzGUb2H6D9VRpbj7Z0tTyUEIfM0pNFtv37BARwc78X8DX0g3Ftq/lzH+F+V5+
         /UDQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=fWSNAx/ATAOEuSJ7h5PHuZUJrkb61jL6EOPJkG7QO9o=;
        fh=3G7MUCPrZdhgiU7FfeGKhLtGvS5QrA3QhFOa76xREyk=;
        b=U+eHKaLs9NyGynE+pVMN9/jFyV4lXwTvzVBMNFHYigLDgVN+LQ2ChQJseEnwaIzqtP
         17Lyc31zj1HS78MVlEJGZOohbv/D00GUg+W176hBPpYIaY8IA9L9mxLyJuab7/g5gvWA
         mOLhMo/xBAcuL3fTTOeizA1BeK/EWBOQ3g9DF5oTgLPgzETtGqg9EeGlv8NDOfaj4H14
         Wx/YT+bjY+50Qv6LH85tI70U+UB+f9ryrpGoLGWyeeVpJFbscn0RfIE8986GwGmwsKNY
         rR86hybkc0F7W0/a/BqeAJS83qVxGjKghA7fndTQmD1nwgPNV26G4o7a6I/s+4x5Sp4K
         BZ6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eHRkOLBf;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758306737; x=1758911537; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=fWSNAx/ATAOEuSJ7h5PHuZUJrkb61jL6EOPJkG7QO9o=;
        b=jbVlQAkEjmCEgzyOc10RxKfyo6xgjb6IHpNtWdysdWtvWx0FzRcf8biOYZvhLIsN1I
         U4Q3c+eATmqTD8LdgAqr0fGIChvvbI2n3B0eqwS3YmUYw5R9s0FLdVdiYpNv3ncilmcq
         Rz3nY7FzkJsBYQj5KtaDbNCVd21vZTp30EkS06ZzI7zhjQXEuQO5IND51aQjELANZBrl
         vqUcWcZzaqPYaOLTRnfbhoz/AIXBL/719MfAAr/jQ7bXkc2ueQIZvPXwSYevrJJ2fyFT
         V49FmFmQcEro7XJ3F2fbJyzfsZioZiNyfho2pRhq4+ub9L0xpI5N/raXfy4FEXYeJlgC
         w/KA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758306737; x=1758911537; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=fWSNAx/ATAOEuSJ7h5PHuZUJrkb61jL6EOPJkG7QO9o=;
        b=g1+jiebhYNAOxMtwOCmrIIXVop1H2HAuxJMzMHGNj6FLDgurzcTXnPcBUapRU1TPDC
         Hl4spWuE1WXZosHQYfub0bff1NoOB0seo2641gzxLnACB+cVt2VzTl8kjs/ymjC4gM3/
         DvsuWGaCJCah70RWnl1M+6fAC6LAFqeAHqwe/rln48jj1kkQ+rAZr+91cYhkieOPy8SA
         gbloDIJcXyh5QVXMhUYfAuQYdi/ZJNql7SpxW7Go0/QwU7cg/Go3gywdBDbmtdjTAUsM
         cgjIrzkwI8FhGQhUdkZACPiui+3r1XFHFviGcUhKN09vzFHtTEO48wmTbRR7As93lU/E
         LPZQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758306737; x=1758911537;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=fWSNAx/ATAOEuSJ7h5PHuZUJrkb61jL6EOPJkG7QO9o=;
        b=Dt/LVTj5C2uIdjYFtrlVcX7l/nfzhxH00lgqvLnglvBcDDO54qGWQ5uamBOKwlNspm
         mFToeeGizF59xluoeKi0OFR9fy1qZQilt7bG0yoNCZf+VdlEx0qbzZ7MTawLhx3FoFjm
         eabhuTOmH4lzdkU3v2huY8QAcMSobfKa5l+1zu6Xm6NHUevOEPHUGeYd6soSjjNDqye9
         3Lngg3rOCtiEwwNT9ojT/77ZEvRVnOKOSlaUkhLK6tbm2QE1juy9nEQtBQQWvD9yXL40
         JQX7ip0+RMkhVCz5kgFvbO0wpv3y5y0UBbGedSNnwjZpF0nuxqeJauK5+/Y9UgiV6acU
         C1/A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqxsMj4KhS9Rqj6vimsoD1b/c5C9ZXHe/nj+lJRT3T1pNVkkER+MlJv0oRwSER+oUS6jDL6g==@lfdr.de
X-Gm-Message-State: AOJu0YwkJEiVD5JcNhOBk54h3lzGeYtVCmvhKZjuSd6w9AiA62qtgx9+
	TOp9U4TRi1kAjBkRiEj0uSKk1/qu4j7ru6bLUCGicOoT53L9DnNhDhmT
X-Google-Smtp-Source: AGHT+IH58h674mD/4rCMtMl6JzaYULgpcp8bkbJ7Yzj+vz4TTCkMdyTah1xV64bBDdm+rm/aEKxpag==
X-Received: by 2002:a05:600c:3b09:b0:45b:9afe:ad48 with SMTP id 5b1f17b1804b1-467e82608c5mr48942435e9.16.1758306735135;
        Fri, 19 Sep 2025 11:32:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7y+S9NQAbMLTpjxMitjSjNJneTFAo3h2b/uJFREWNAdw==
Received: by 2002:a05:600c:4690:b0:45d:d27e:8ca8 with SMTP id
 5b1f17b1804b1-46543b01aaals12790905e9.2.-pod-prod-03-eu; Fri, 19 Sep 2025
 11:32:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWoXjvqTvXiRvyYNG9ANp8JEeh4eKkCDzasjLcziukULGYNXcyXcdsWrcKbIIuJUbQpbxue1FohLas=@googlegroups.com
X-Received: by 2002:a05:600c:4f51:b0:468:7ad5:b91c with SMTP id 5b1f17b1804b1-4687ad5c393mr42042085e9.5.1758306731512;
        Fri, 19 Sep 2025 11:32:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758306731; cv=none;
        d=google.com; s=arc-20240605;
        b=ScjXHQbuLy9qDVBOkNDi857NO6G6pI0zm88JWjLW4IF2MXDX9/KK/+6rcTRQoVXebF
         lO0s1dCE2BHnwAsd3RWBhQC43TycE/HPGx8NGiXSvvbQVEUZBHsOGVg2XeVeE0cu3ZXM
         SFvx7Jc7gUnaUUu/GEQRV/fhDIstfOuxwjGGFrtsy2LVx5ND22OW6uYoBrY/LnML29xL
         KBaFrL3TwZ5Ggh0JP8MesjCmO6flvWaaB3Khq2EOQ+b+0sMtkwMbYb1DK6K1szm+kdiB
         41pGuXhjx0DC7nBwldlFL6MTBN/iUxYHicjViQsOZSDJh6X0qp2AxwR8ib9AgL7XA2Hi
         zc+A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=NNz2rvWdWurkAjYnYhECzBshCI3+0s6yD1fA4kNT29Q=;
        fh=eZA5lYVRs2l97JgX1twKSr9vkLjV4NYVZtFFEHfgG1U=;
        b=Sb/FhAZt7BAg/AV1MqzVpTV2Xc2zXxDnA3/6gLaFbPvwHotTJ5stISmB3AyQRp+GCB
         WRjItAsjujzfGl3V/5p2YgqgvpFVAPJsiHPvVr6kNiPZRZlTjheHMBQVobVJytmD6UL/
         V9uvsz9R4JDjiXubxkg39sTgoNdoyfHApG3pP91VMOeDZyeD0oyI0Eo8u7tbSZRsMhRN
         1NZTAQE3mGyMQ9/KZJZnVawYQ6kvh+Vdjdyi5C6QgM1smf+r9FzIDmCdgyiDGaMkNU/v
         5ZVuC9z8bExd7U7g/oXFeZbLn+Ge+4Py1iGRZ+MYUVP8yWLsutAqojoI4FrDkXv8VA82
         aN4Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=eHRkOLBf;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f3208575dsi3296215e9.0.2025.09.19.11.32.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 11:32:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-3ee130237a8so1195944f8f.0
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 11:32:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVRzvopvnQTmGVGG8NQ2EjtKCBJeu7UglAmYRvaGnsLOvl6e7Zt+EdEuKK0x7kyY+xQ8HPB0bVipT8=@googlegroups.com
X-Gm-Gg: ASbGncuc3bfDjlas32NPLJWVbTCQRAIXJ5FEs3XdPVlD91wMBtSlVA3QMSiSYm6mhQV
	s6SwpJfBLj3+UfKRoXESX6JvRIK3T7/cNDWeNMzdbcUD+SKHzHRXL5JPCedtWbzOZfgK7iJhEcm
	FuiduV/OgOpQnA+e0fk5DarbYIN5WpS8baD3WgbA7zVrZkjyHwMz/SvXcLLo+QoHyOoys/dL4zi
	GRSYzCawSyLbUG7zUmQe88=
X-Received: by 2002:a05:6000:2486:b0:3ed:f690:a390 with SMTP id
 ffacd0b85a97d-3ee8481fdffmr3766244f8f.40.1758306730884; Fri, 19 Sep 2025
 11:32:10 -0700 (PDT)
MIME-Version: 1.0
References: <202509171214.912d5ac-lkp@intel.com> <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
 <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz> <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
 <ce3be467-4ff3-4165-a024-d6a3ed33ad0e@suse.cz> <CAJuCfpGLhJtO02V-Y+qmvzOqO2tH5+u7EzrCOA1K-57vPXhb+g@mail.gmail.com>
 <CAADnVQLPq=puz04wNCnUeSUeF2s1SwTUoQvzMWsHCVhjFcyBeg@mail.gmail.com> <CAJuCfpGA_YKuzHu0TM718LFHr92PyyKdD27yJVbtvfF=ZzNOfQ@mail.gmail.com>
In-Reply-To: <CAJuCfpGA_YKuzHu0TM718LFHr92PyyKdD27yJVbtvfF=ZzNOfQ@mail.gmail.com>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Fri, 19 Sep 2025 11:31:57 -0700
X-Gm-Features: AS18NWDr8VuH5ucHYn2ibLVBASY5zct8WHDo7Mc0mqgDvlFRZ593jDOgzN6t5y4
Message-ID: <CAADnVQKt5YVKiVHmoB7fZsuMuD=1+bMYvCNcO0+P3+5rq9JXVw@mail.gmail.com>
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
 header.i=@gmail.com header.s=20230601 header.b=eHRkOLBf;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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

On Fri, Sep 19, 2025 at 8:01=E2=80=AFAM Suren Baghdasaryan <surenb@google.c=
om> wrote:
>
> On Thu, Sep 18, 2025 at 6:39=E2=80=AFPM Alexei Starovoitov
> <alexei.starovoitov@gmail.com> wrote:
> >
> > On Thu, Sep 18, 2025 at 7:49=E2=80=AFAM Suren Baghdasaryan <surenb@goog=
le.com> wrote:
> > >
> > > On Thu, Sep 18, 2025 at 12:06=E2=80=AFAM Vlastimil Babka <vbabka@suse=
.cz> wrote:
> > > >
> > > > On 9/17/25 20:38, Alexei Starovoitov wrote:
> > > > > On Wed, Sep 17, 2025 at 2:18=E2=80=AFAM Vlastimil Babka <vbabka@s=
use.cz> wrote:
> > > > >>
> > > > >> Also I was curious to find out which path is triggered so I've p=
ut a
> > > > >> dump_stack() before the kmalloc_nolock call:
> > > > >>
> > > > >> [    0.731812][    T0] Call Trace:
> > > > >> [    0.732406][    T0]  __dump_stack+0x18/0x30
> > > > >> [    0.733200][    T0]  dump_stack_lvl+0x32/0x90
> > > > >> [    0.734037][    T0]  dump_stack+0xd/0x20
> > > > >> [    0.734780][    T0]  alloc_slab_obj_exts+0x181/0x1f0
> > > > >> [    0.735862][    T0]  __alloc_tagging_slab_alloc_hook+0xd1/0x3=
30
> > > > >> [    0.736988][    T0]  ? __slab_alloc+0x4e/0x70
> > > > >> [    0.737858][    T0]  ? __set_page_owner+0x167/0x280
> > > > >> [    0.738774][    T0]  __kmalloc_cache_noprof+0x379/0x460
> > > > >> [    0.739756][    T0]  ? depot_fetch_stack+0x164/0x180
> > > > >> [    0.740687][    T0]  ? __set_page_owner+0x167/0x280
> > > > >> [    0.741604][    T0]  __set_page_owner+0x167/0x280
> > > > >> [    0.742503][    T0]  post_alloc_hook+0x17a/0x200
> > > > >> [    0.743404][    T0]  get_page_from_freelist+0x13b3/0x16b0
> > > > >> [    0.744427][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > > > >> [    0.745358][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > > > >> [    0.746290][    T0]  ? __next_zones_zonelist+0x26/0x60
> > > > >> [    0.747265][    T0]  __alloc_frozen_pages_noprof+0x143/0x1080
> > > > >> [    0.748358][    T0]  ? lock_acquire+0x8b/0x180
> > > > >> [    0.749209][    T0]  ? pcpu_alloc_noprof+0x181/0x800
> > > > >> [    0.750198][    T0]  ? sched_clock_noinstr+0x8/0x10
> > > > >> [    0.751119][    T0]  ? local_clock_noinstr+0x137/0x140
> > > > >> [    0.752089][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > > > >> [    0.753023][    T0]  alloc_slab_page+0xda/0x150
> > > > >> [    0.753879][    T0]  new_slab+0xe1/0x500
> > > > >> [    0.754615][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > > > >> [    0.755577][    T0]  ___slab_alloc+0xd79/0x1680
> > > > >> [    0.756469][    T0]  ? pcpu_alloc_noprof+0x538/0x800
> > > > >> [    0.757408][    T0]  ? __mutex_unlock_slowpath+0x195/0x3e0
> > > > >> [    0.758446][    T0]  __slab_alloc+0x4e/0x70
> > > > >> [    0.759237][    T0]  ? mm_alloc+0x38/0x80
> > > > >> [    0.759993][    T0]  kmem_cache_alloc_noprof+0x1db/0x470
> > > > >> [    0.760993][    T0]  ? mm_alloc+0x38/0x80
> > > > >> [    0.761745][    T0]  ? mm_alloc+0x38/0x80
> > > > >> [    0.762506][    T0]  mm_alloc+0x38/0x80
> > > > >> [    0.763260][    T0]  poking_init+0xe/0x80
> > > > >> [    0.764032][    T0]  start_kernel+0x16b/0x470
> > > > >> [    0.764858][    T0]  i386_start_kernel+0xce/0xf0
> > > > >> [    0.765723][    T0]  startup_32_smp+0x151/0x160
> > > > >>
> > > > >> And the reason is we still have restricted gfp_allowed_mask at t=
his point:
> > > > >> /* The GFP flags allowed during early boot */
> > > > >> #define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM|__GFP_I=
O|__GFP_FS))
> > > > >>
> > > > >> It's only lifted to a full allowed mask later in the boot.
> > > > >
> > > > > Ohh. That's interesting.
> > > > >
> > > > >> That means due to "kmalloc_nolock() is not supported on architec=
tures that
> > > > >> don't implement cmpxchg16b" such architectures will no longer ge=
t objexts
> > > > >> allocated in early boot. I guess that's not a big deal.
> > > > >>
> > > > >> Also any later allocation having its flags screwed for some reas=
on to not
> > > > >> have __GFP_RECLAIM will also lose its objexts. Hope that's also =
acceptable.
> > > > >> I don't know if we can distinguish a real kmalloc_nolock() scope=
 in
> > > > >> alloc_slab_obj_exts() without inventing new gfp flags or passing=
 an extra
> > > > >> argument through several layers of functions.
> > > > >
> > > > > I think it's ok-ish.
> > > > > Can we add a check to alloc_slab_obj_exts() that sets allow_spin=
=3Dtrue
> > > > > if we're in the boot phase? Like:
> > > > > if (gfp_allowed_mask !=3D __GFP_BITS_MASK)
> > > > >    allow_spin =3D true;
> > > > > or some cleaner way to detect boot time by checking slab_state ?
> > > > > bpf is not active during the boot and nothing should be
> > > > > calling kmalloc_nolock.
> > > >
> > > > Checking the gfp_allowed_mask should work. Slab state is already UP=
 so won't
> > > > help, and this is not really about slab state anyway.
> > > > But whether worth it... Suren what do you think?
> > >
> > > Vlastimil's fix is correct. We definitely need __GFP_NO_OBJ_EXT when
> > > allocating an obj_exts vector, otherwise it will try to recursively
> > > allocate an obj_exts vector for obj_exts allocation.
> > >
> > > For the additional __GFP_BITS_MASK check, that sounds good to me as
> > > long as we add a comment on why that is there. Or maybe such a check
> > > deserves to be placed in a separate function similar to
> > > gfpflags_allow_{spinning | blocking}?
> >
> > I would not. I think adding 'boot or not' logic to these two
> > will muddy the waters and will make the whole slab/page_alloc/memcg
> > logic and dependencies between them much harder to follow.
> > I'd either add a comment to alloc_slab_obj_exts() explaining
> > what may happen or add 'boot or not' check only there.
> > imo this is a niche, rare and special.
>
> Ok, comment it is then.
> Will you be sending a new version or Vlastimil will be including that
> in his fixup?

Whichever way. I can, but so far Vlastimil phrasing of comments
were much better than mine :) So I think he can fold what he prefers.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQKt5YVKiVHmoB7fZsuMuD%3D1%2BbMYvCNcO0%2BP3%2B5rq9JXVw%40mail.gmail.com=
.
