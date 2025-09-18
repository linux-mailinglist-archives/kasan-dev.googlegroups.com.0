Return-Path: <kasan-dev+bncBC7OD3FKWUERBA5YWDDAMGQE5YHJDTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id 2815FB85572
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:49:41 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id d2e1a72fcca58-77ca5b8387asf1195174b3a.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:49:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758206979; cv=pass;
        d=google.com; s=arc-20240605;
        b=icvWBFyNwByIrOoq+fpiW8q3LIGEPQWu8oV1B8HjP+CQs9tHYqGMv1kxPAz7P0W5gq
         653bpXKgb9/hXX6VmajOclKURvN1MQydpSehXO3+F1cTBwm4/AYUYGvG5Ei4P/8CT/J8
         /bPP7TTlBp0y9St8szSQfMYsBi59PM/mm6LpDdh/lg41rS+hiF+6Ekbyr/CEKMezkKWv
         aT/yT2xoSN04QxPCM51Nv74WOTiUemtPiU2lrz0VqwMJ/rk38dh+5byR4SUm7XR/c+rH
         klH4u15n3lgUjDUU8PctOSccrx9A/qtKiBO4nVTEVfIseqqEYEREjqXkIcdrXrnklYpA
         ufDw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XvfZa48X95Q1NCnzNs+NL+ifrlU2pPYPmShQJPjy1Po=;
        fh=XsJl/qHw5qJkWwjEUbh9DXlaIwt5VllsK2KxnsK7reU=;
        b=SLCFJrsW4/qaWJ9czv23xQxm7p5N8QQcbx/QjtZvhJE4SwwNVxP40Fs8Nh1WKbwc3z
         CFH7Jqz76YnSxFX2Ed1VCS31FBH/HAM1qFpWei0eA2qMOXhaGcLBGEb/VlPCbsjbIlHV
         eIQBflhx1utGjASgAVsmDihTzrQjPjrMm9rniGXk8kCzyXPCMFHY0BSkcHqxcix9+Kua
         hcQUFjI9Is1Fbj6VG16AEmKJLK3cCC6IEHUrDtaHrrkwp52WmWsVRY7LyvzgD9wd8HyE
         CKrxfsaq0KbA09pt/DN69eeYRsK9A8bKgW307YtCp3XTo0ZYGrX9QM4NnKUtzP3bQoHo
         lOIQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OctF5PY5;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758206979; x=1758811779; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XvfZa48X95Q1NCnzNs+NL+ifrlU2pPYPmShQJPjy1Po=;
        b=jmVkNELv8StWTsD0ByXcRYQItYlZFbKzlvshf2tIPsg4A66JcXv007hcJzXG53YaoR
         IVUdhc03xHLguUAPdMVfi4DCqQLNrd8BMqq/+wnEQgDuSO3fQu1H+ofhNG65T19/m4Z3
         NMY7CbpaEcBc2Xtr3pyXNTClfLEH0R9POojIHYnWhyuAFnsWjBFosJBzT9RdL6N7fDHk
         i5FydsOVG1+tvUH3ZyuOIiLWJv52qmYtfV8Oq1Hd0xmdFfdgJ4KIWt8JezMo8EmR3le1
         qsG22RIsEIjAEvpwO4MQraxamytCHH+IGQZAmHy2QUaE3ECbeGjblarvNkVXKoLSgVnS
         oEPg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758206979; x=1758811779;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=XvfZa48X95Q1NCnzNs+NL+ifrlU2pPYPmShQJPjy1Po=;
        b=jqQM1SwCeMIU1Gg8LfumPO5upGDXCCpuuFPfDuZKFXPY4BuspuhpYkrx4GG9R01uFG
         QtnaZgXQ+9+HXhYRWJLYxm4gbqgwMqFndx6k9kDvRN6PzVrpiAuzm/eHqlbyfcHfOKcy
         VlUqM5U/odW0pQSa2H5pWYBBL8EUts6kDQsHMQlgvx1erbgjcdcvfkiS0z7uqsk5o8Qy
         XMb32KGxP9CulIcD51oHYszpd5HVseSduJdmLkFg5TZqHuaCnkFSV6PaJhy20RomePxE
         Gg8IsZVao+7+9T8Dr7pNZl8o0khLfC9/NGFnvvcUfKV62czSfU0DmkF3RKsHexOvhAN5
         n/7A==
X-Forwarded-Encrypted: i=2; AJvYcCUwNvWGInDOmmnGC4z8pVvR3llwBrr/OWAPQ2Vi+Oh6KHQKCvyA7aS+eNj5W1TIvW5ZXmMDWg==@lfdr.de
X-Gm-Message-State: AOJu0YwTSrrtdW9xOXaqO47CXTlgB3ErXxCYG/9SZrFHeFNsMdh6KAcp
	zh6x+Q+YOv7NOmsPqZA7zKTaxoJvsy7RIqrht1MMngJGW+RbEHgMdlU6
X-Google-Smtp-Source: AGHT+IHboX0wH7o5vIlxX2O+nJFFHOSnYJ3zJoTuY5hy5jezOGoxlypmRyhVZDq/GG552BMhe5JI0Q==
X-Received: by 2002:a05:6a00:18a2:b0:772:6235:7038 with SMTP id d2e1a72fcca58-77bf72cbc6emr6914646b3a.10.1758206979364;
        Thu, 18 Sep 2025 07:49:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd7rXDxC+i3N/Wus0vglzJxC3owPXoUA5EzAE1a/GomgRQ==
Received: by 2002:a05:6a00:815:b0:736:57a0:c48f with SMTP id
 d2e1a72fcca58-77e02b31c06ls219097b3a.2.-pod-prod-09-us; Thu, 18 Sep 2025
 07:49:38 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU79Ti2pXCRr4HD76xBry2wh0UZV1zSItPn/plfjHKyvQmaobJhaiXa+HMfO5TZBIcQRWvikkyQaFc=@googlegroups.com
X-Received: by 2002:a05:6a20:394b:b0:263:28c2:c8f7 with SMTP id adf61e73a8af0-27a8dfaecdemr7777768637.9.1758206977802;
        Thu, 18 Sep 2025 07:49:37 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758206977; cv=none;
        d=google.com; s=arc-20240605;
        b=huGWZwsS3ru93QXrqn+IbIftiNtXNPTq19NbxXqq1+BiIFtt9hoD/r+gYf+Z8VMHOK
         vq2di5mYOzemeu8FhIdUADifL+16tt1yELEeUmX3pwhlv6wh5chEhEptl2Nb7YoqoKbR
         i/b7b3oV9/TnP6oUHzPXDjLAKlyEwmOQV2tFTS6Ug0+8P/D1rjcUN96YipcwkxFHiqCQ
         ihS1lu9cH1jUeX3hLwxtgky67phA8uZtl1V7+GvGDgITnC3PRHQffFYTXdfXxWdmNCG9
         +QlB49wVsVZzmKZsnOmDa4u6DEsHErr8w0pSov0KqaYvABJbZlskfBFliNS4n8y6xfw4
         XR7g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KvgqQMIRazqhTNds4nMPQal7ZSlIJweSzO/oPA+Hs2c=;
        fh=/FikcAsapytfbksSYO8+v+S2FPEnHxohvOemXffvsZs=;
        b=XAaBCB2rNqg4L9b9oMv48EivIv8GS/UaNnm2JT3Xu6oEumnGr/aqGYze6f1QunU8FJ
         gvYI/gNJSGJlWcTYgJW8XT0YLwnj634KEfBtVScVGpp6KHq7Zsm2zQS2lrmFFJrpoZbD
         ICDCEv4UGwaFMmkQiThzD+eXdXwV96ipqrPcbmc7N1JhTX8NlwglFlORCOEmGf2k4B6X
         l0SB38q0Ybo6LKF24KxaDQA8RmXpO147hCdSlkY438VDiysH3BuSDW0+WcO7Nw+rl7gk
         P5dVpcIrZ75pefUkhAnApbzzrdUkqc8yaOP/9Y+pt//QcPpfawj8cI7pcx9+xqGo0yJV
         XNYA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OctF5PY5;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::830 as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x830.google.com (mail-qt1-x830.google.com. [2607:f8b0:4864:20::830])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b5515666145si16034a12.1.2025.09.18.07.49.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:49:37 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::830 as permitted sender) client-ip=2607:f8b0:4864:20::830;
Received: by mail-qt1-x830.google.com with SMTP id d75a77b69052e-4b4bcb9638aso434551cf.0
        for <kasan-dev@googlegroups.com>; Thu, 18 Sep 2025 07:49:37 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXH3JG5x7ornMQLfmy8/ULB6D2WTIMCUm8b2J+Obup0Sg2cf/REdlWzKH4LdZG0knRxAjNAx2ER/No=@googlegroups.com
X-Gm-Gg: ASbGncu4dqRnZC+uPSvTNro8qajEFarMncLwE5pEQYb7MQdYi3uHpLs+eFPw6r64Z5a
	YzQrK7ySBoapHLTjTZoLLiReOBSjsIla9hn6epQcbgDvx0PQ+V4ingJ1W4IWPK7yFaU93xsj/IG
	pZkmTqT+OeMWQxzGdtcAYY0tHpQyWDYhMWPsWGlGhNUww4SOGISgMs/vWOFS0ERpiyTmUO1h9U8
	IW9rSA1Gkka/eQ+ykBq2S8tDs0nj4kMq6EgKLSbOR1DJ64jTFCG22e9KZ7SC+Y=
X-Received: by 2002:a05:622a:118c:b0:4b3:50ee:579e with SMTP id
 d75a77b69052e-4ba2dbd8d7amr13425281cf.11.1758206976508; Thu, 18 Sep 2025
 07:49:36 -0700 (PDT)
MIME-Version: 1.0
References: <202509171214.912d5ac-lkp@intel.com> <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
 <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz> <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
 <ce3be467-4ff3-4165-a024-d6a3ed33ad0e@suse.cz>
In-Reply-To: <ce3be467-4ff3-4165-a024-d6a3ed33ad0e@suse.cz>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 Sep 2025 07:49:25 -0700
X-Gm-Features: AS18NWBKqEKLWVuQ980Fh7DdopBdRtw6yIZtBXo-Y59z15HRkGH_vRxj6TN4pFk
Message-ID: <CAJuCfpGLhJtO02V-Y+qmvzOqO2tH5+u7EzrCOA1K-57vPXhb+g@mail.gmail.com>
Subject: Re: [linux-next:master] [slab] db93cdd664: BUG:kernel_NULL_pointer_dereference,address
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Alexei Starovoitov <alexei.starovoitov@gmail.com>, kernel test robot <oliver.sang@intel.com>, 
	Alexei Starovoitov <ast@kernel.org>, Harry Yoo <harry.yoo@oracle.com>, oe-lkp@lists.linux.dev, 
	kbuild test robot <lkp@intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:CONTROL GROUP (CGROUP)" <cgroups@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OctF5PY5;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::830 as
 permitted sender) smtp.mailfrom=surenb@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Thu, Sep 18, 2025 at 12:06=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> w=
rote:
>
> On 9/17/25 20:38, Alexei Starovoitov wrote:
> > On Wed, Sep 17, 2025 at 2:18=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz=
> wrote:
> >>
> >> Also I was curious to find out which path is triggered so I've put a
> >> dump_stack() before the kmalloc_nolock call:
> >>
> >> [    0.731812][    T0] Call Trace:
> >> [    0.732406][    T0]  __dump_stack+0x18/0x30
> >> [    0.733200][    T0]  dump_stack_lvl+0x32/0x90
> >> [    0.734037][    T0]  dump_stack+0xd/0x20
> >> [    0.734780][    T0]  alloc_slab_obj_exts+0x181/0x1f0
> >> [    0.735862][    T0]  __alloc_tagging_slab_alloc_hook+0xd1/0x330
> >> [    0.736988][    T0]  ? __slab_alloc+0x4e/0x70
> >> [    0.737858][    T0]  ? __set_page_owner+0x167/0x280
> >> [    0.738774][    T0]  __kmalloc_cache_noprof+0x379/0x460
> >> [    0.739756][    T0]  ? depot_fetch_stack+0x164/0x180
> >> [    0.740687][    T0]  ? __set_page_owner+0x167/0x280
> >> [    0.741604][    T0]  __set_page_owner+0x167/0x280
> >> [    0.742503][    T0]  post_alloc_hook+0x17a/0x200
> >> [    0.743404][    T0]  get_page_from_freelist+0x13b3/0x16b0
> >> [    0.744427][    T0]  ? kvm_sched_clock_read+0xd/0x20
> >> [    0.745358][    T0]  ? kvm_sched_clock_read+0xd/0x20
> >> [    0.746290][    T0]  ? __next_zones_zonelist+0x26/0x60
> >> [    0.747265][    T0]  __alloc_frozen_pages_noprof+0x143/0x1080
> >> [    0.748358][    T0]  ? lock_acquire+0x8b/0x180
> >> [    0.749209][    T0]  ? pcpu_alloc_noprof+0x181/0x800
> >> [    0.750198][    T0]  ? sched_clock_noinstr+0x8/0x10
> >> [    0.751119][    T0]  ? local_clock_noinstr+0x137/0x140
> >> [    0.752089][    T0]  ? kvm_sched_clock_read+0xd/0x20
> >> [    0.753023][    T0]  alloc_slab_page+0xda/0x150
> >> [    0.753879][    T0]  new_slab+0xe1/0x500
> >> [    0.754615][    T0]  ? kvm_sched_clock_read+0xd/0x20
> >> [    0.755577][    T0]  ___slab_alloc+0xd79/0x1680
> >> [    0.756469][    T0]  ? pcpu_alloc_noprof+0x538/0x800
> >> [    0.757408][    T0]  ? __mutex_unlock_slowpath+0x195/0x3e0
> >> [    0.758446][    T0]  __slab_alloc+0x4e/0x70
> >> [    0.759237][    T0]  ? mm_alloc+0x38/0x80
> >> [    0.759993][    T0]  kmem_cache_alloc_noprof+0x1db/0x470
> >> [    0.760993][    T0]  ? mm_alloc+0x38/0x80
> >> [    0.761745][    T0]  ? mm_alloc+0x38/0x80
> >> [    0.762506][    T0]  mm_alloc+0x38/0x80
> >> [    0.763260][    T0]  poking_init+0xe/0x80
> >> [    0.764032][    T0]  start_kernel+0x16b/0x470
> >> [    0.764858][    T0]  i386_start_kernel+0xce/0xf0
> >> [    0.765723][    T0]  startup_32_smp+0x151/0x160
> >>
> >> And the reason is we still have restricted gfp_allowed_mask at this po=
int:
> >> /* The GFP flags allowed during early boot */
> >> #define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM|__GFP_IO|__GF=
P_FS))
> >>
> >> It's only lifted to a full allowed mask later in the boot.
> >
> > Ohh. That's interesting.
> >
> >> That means due to "kmalloc_nolock() is not supported on architectures =
that
> >> don't implement cmpxchg16b" such architectures will no longer get obje=
xts
> >> allocated in early boot. I guess that's not a big deal.
> >>
> >> Also any later allocation having its flags screwed for some reason to =
not
> >> have __GFP_RECLAIM will also lose its objexts. Hope that's also accept=
able.
> >> I don't know if we can distinguish a real kmalloc_nolock() scope in
> >> alloc_slab_obj_exts() without inventing new gfp flags or passing an ex=
tra
> >> argument through several layers of functions.
> >
> > I think it's ok-ish.
> > Can we add a check to alloc_slab_obj_exts() that sets allow_spin=3Dtrue
> > if we're in the boot phase? Like:
> > if (gfp_allowed_mask !=3D __GFP_BITS_MASK)
> >    allow_spin =3D true;
> > or some cleaner way to detect boot time by checking slab_state ?
> > bpf is not active during the boot and nothing should be
> > calling kmalloc_nolock.
>
> Checking the gfp_allowed_mask should work. Slab state is already UP so wo=
n't
> help, and this is not really about slab state anyway.
> But whether worth it... Suren what do you think?

Vlastimil's fix is correct. We definitely need __GFP_NO_OBJ_EXT when
allocating an obj_exts vector, otherwise it will try to recursively
allocate an obj_exts vector for obj_exts allocation.

For the additional __GFP_BITS_MASK check, that sounds good to me as
long as we add a comment on why that is there. Or maybe such a check
deserves to be placed in a separate function similar to
gfpflags_allow_{spinning | blocking}?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpGLhJtO02V-Y%2BqmvzOqO2tH5%2Bu7EzrCOA1K-57vPXhb%2Bg%40mail.gmail.com.
