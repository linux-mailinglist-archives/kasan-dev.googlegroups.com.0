Return-Path: <kasan-dev+bncBCUY5FXDWACRBQEAVTDAMGQEITNQBQY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 88660B815CE
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 20:38:57 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3e8c4aa37bbsf12183f8f.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 11:38:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758134337; cv=pass;
        d=google.com; s=arc-20240605;
        b=XaQKJhMbG0HSJc2+Z9DWo3e94FGYGqLk+Up6hUIGlJkyFSmsOIxka10HRlA7kMNMeh
         bUrLaE+s6t9V30r2xQAptnEvf8cBGv7HWigblqN+Tw76a3ReIU/O0OWwmPCBEFomzREA
         JhvJiRGuVXv0mgyL1Zuc5Tntz05RTGWmj2p5UF5qfhewlQXbGdU3EodkZRSJ9JLpueqP
         qs1IIAKVzsYItpMxmHcFwlTN1Gcnb4PhprCaW8PaFizGwv0gfpyO+Y/GtLst34VQ8kZK
         wC8aXZL9ZBF2PPeMpb41SG6gJ83J2j/dTd7PeZx0GUE1jB+PLilDTDLRV43ZaSbkXHOy
         HYSw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=c5Z9BiQW67WFsjvNmlzOY+92h+XM0OQauBfgDeimbm4=;
        fh=NWehMDkQ0ZccabIAsVrBKmg17/vLNHkzb4Kz3arhTqE=;
        b=WIP07mP3uC6GszD3GTuYqWNuDKxLRavEC1a3twwcDYi2PripNFE4y7MK4bosV3pRa8
         nVadLqVIzz4ZmRppgWROaE2nGCawwOVkSRYeIIeSnnvW3wSo+GwyY8a5eF+qyizRGKpc
         evfqy1kor2gl8g75u6Ondz+o6PyyeM1kk6VtiLAp5N5ksgF45Bj8g20ap9IoS1CYv2BK
         xIwRu8H/oKAoMsjVYGZdzEOxed+3o73Qwk/xns2FnEnwJ5QYlpcJ//HUh90Hqquso2kX
         TB0XbpvZijP9LI2qvjcRo6f5grbxjxCYfyh8YDYAzrPhmvSNlJ3aGzfR4i41q/0tAuuN
         gv4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bnTt2oK3;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758134337; x=1758739137; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=c5Z9BiQW67WFsjvNmlzOY+92h+XM0OQauBfgDeimbm4=;
        b=nH1MNo6IYvs+zzO7IA2kVkULZldMVmZbULLCb0WKlJHRXp1gz/2iXXru7cpNVzrwCo
         6G/5ed0EgI934dyH2btY8JCd//11EEDEIOpCbhY2ESeBO5QHl3M6y7MJwg4BvlgeocmX
         NKJBSitDCoy5AStO3kkXVBX2COroc1C+dsBw82WAmE2Vok+30NEi71Q0RzD85F1Yv7ao
         kyiDI1fDwC/yc+iG2AFzu19PsxyF7wxGM97CFAnJjyiLujDD+Vu1ZneguVaJRUEjp6t4
         GjJeW6oJKYNU8wjZxaqALASlN4U1bJv6iKoEICF82Hx2c19v/Pz8Q+UePHhlgZnBVz70
         xLJw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1758134337; x=1758739137; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=c5Z9BiQW67WFsjvNmlzOY+92h+XM0OQauBfgDeimbm4=;
        b=A90LUDOp9FViFF+F1IMfxXGFaIiyElnxS6/nmamBkTUL0TKkieuvCSqPZZCeU0uWHK
         91i9HBXlnEt4ByY7qNJzVHrNkXlkb2eLLYFojdA7SowNLa5j9kBI4DICSsnjPFN9GEUa
         1sRnIeliAaSU3+RaQ6ysL/a9pgfPY7PGN1H+VnUgNWnnbmMe8o13Oq5i+XGUheckQNTT
         rQie2qN3ja7ExPi8AE//26AzA5/EQ2LXyw/L4tmO6NR5ji/ZnRHGtswCHoZ8nlWLX4iq
         8k+28Lw13sr5reV38v7W6JmGlJVSt85W/mQu3wqxzAxWCQ8/D3uCVFsZQkXWGw3yjHzx
         3Ekg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758134337; x=1758739137;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=c5Z9BiQW67WFsjvNmlzOY+92h+XM0OQauBfgDeimbm4=;
        b=fhNpdK0Dn1LNH2Srg/Rs9ODz9Z5wcUH/RqzKuXHYaiNkYUiHzRlHSa9eMoOiwTOC9b
         a5x830kGn2Eu7D8dPpcPDWrt/wzXEMTZ38S+tk+vGsKmKfjP81qTLgF84owRIsQ+K+CX
         NtK9SOJPwyZ8WhIgaNxL0lnKbiS85ZD9CeSxy0n7hRpMxsf6pJGZdM3leI6SnAgRJwap
         Fz8zmwR4VMmhEQ+lXvUnz0VTYYtf2kZmgTCzNcSeAQCHRx8GhC1JofZsibfNInzMV7n9
         g36AmnNuOlEXi2KqkXjJkxQvYKR4J+e3U9XkvLtXrkZeMD+tpyyWlZ2+Sj8cstJBhGiF
         izsg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX52FwcuLtEUjNAmJoyIAzmdr/OzMvdrlnIxjiYBGqWmIQtJ/QhHT+Aj9MNuA6GDYMSwTshGg==@lfdr.de
X-Gm-Message-State: AOJu0Yz1oLcl+CvMeWwIZrcpXMamankvylsVXwLhi1lIvz5v4utdafG1
	jrvxYSGyDRhiCpGmvmJcAIhXA+qpvqYhqpZKvcfawmE9HlEycAFPhJ+z
X-Google-Smtp-Source: AGHT+IFk4C7/TsY9P3vfNV1DyCcPkoU21WtkmrdL/AQzV46u918kTqrEcZws7VmtTJ8HFaVMZAKHXA==
X-Received: by 2002:a05:6000:178e:b0:3e0:2a95:dc9e with SMTP id ffacd0b85a97d-3ecdfa3b817mr2865973f8f.57.1758134336648;
        Wed, 17 Sep 2025 11:38:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd655qmPzzVPrzO5KsKehGVSqzURUdcNHklYF21uuoXCbg==
Received: by 2002:a05:6000:4013:b0:3e1:7964:2c28 with SMTP id
 ffacd0b85a97d-3ee106a1761ls16542f8f.1.-pod-prod-01-eu; Wed, 17 Sep 2025
 11:38:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXx/C0ataZTbAZBrrYF+38iVaa/6gJ2eUbTvVBJpbmPrb5Ri0gUt9z7Ws3gYpZakB33nglArrnuMUs=@googlegroups.com
X-Received: by 2002:a05:6000:1863:b0:3e7:6474:1b63 with SMTP id ffacd0b85a97d-3ecdfa3d20fmr2767131f8f.63.1758134333672;
        Wed, 17 Sep 2025 11:38:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758134333; cv=none;
        d=google.com; s=arc-20240605;
        b=F39YLpVfoNomv1IrcAxpNT/XMWJnJfa1SPFVHaD/CUeFofjMTz/C4dgHoU/888gjxA
         5uTGxZ3+0I3S2v5goocL/Aub7QqC2KBjc953jvatlAUE0lxGVm0r/aA66KPMY/gq7fSf
         XDZIMYSFgEq8+nvclf9siHeOEnaM2mH7g94bjAkvQHSFyJyYksl/t11kQDveeNjCz9n9
         nETHmuaMWqgiHjUhGR/7W9tDKYn763ZgfXuK37Jnae3YGohEOcCj0TIBue3QWvRfFJQA
         6yL3CKHTNEe/8BnsC+9As0RiCAlwKV55nhn+YueJ3pfomosAfpb2LQy2/6aQo3N6MBLq
         R1SA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=WSe+/0Ppv6md7i7Zvl8mHAv4aY3npVBA8JoXdsiKzcU=;
        fh=4SHeHqjtSwBs2IDaZRPd5n7Xa9kRsSi4EpYhep1mnFw=;
        b=GX1uDA/aHSYExiOrx0kk11NFioTTC2+ttoc+iJp2jgYhWcMSPb3Ff4fkTeHs7if1Td
         uR3KVrl3+YzCSvsNVVxk4HrGKTWlFgRy32JQbGGe9WGpik8qVHbBb4FvG7DjJOVQJMMW
         X1UPez6E1OjDrInYdJ9aPn35ZfAtcANURoAGkNSDGXFqolFB/HZyjgtZC+3sZMTWF6fm
         Y1WCzg2NGfsu7lsEIBbV577Z7MI8nZTFfaMl/5npnWFlJ+kT/cy3K5OKoOpzvgrz/vLc
         HjeSazVqWW4fm0t6VmqRlLwHOfOOvRt+eaiawZZQmoN8AIE4w4PkxY1QUb0hIUdfHYJH
         IUeA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=bnTt2oK3;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45f80f7944dsi1125585e9.0.2025.09.17.11.38.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 17 Sep 2025 11:38:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-3ebc706eb7bso23040f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 17 Sep 2025 11:38:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCURz2J+zrerRlXkG34HK1Dzm9J61gd8pM8G+RMjI5GHZoN5QEb3lcGMC+dBNyBfi6S79Mi7AlRWe08=@googlegroups.com
X-Gm-Gg: ASbGncsvOUZxFE/u5LJZQ2OjASdp7uvVtI5DSdO/Jer+64qX7haEM+VQrIEOzSkaq7Z
	xf7w2Gh3TU6EgM0UWSyj+WyVqm/tCxtwssknjzhbVtqi0Bj5NATbbkrmOF/Q9ltYgWWUKNtcsnR
	lcE9lQG2Qtb78NnBZEZSc/bvThoUPNUp4cMVFIL1ftrB6qD4+DSiuKq9rEw7CCFYuC0gc5HunRF
	mmhUBhKhPCdYP3trLGcg0ucDkOaZ6EXHVKawpkF26WLSpQ=
X-Received: by 2002:a5d:5d83:0:b0:3e8:f67:894a with SMTP id
 ffacd0b85a97d-3ecdf9b19b2mr3358067f8f.5.1758134332921; Wed, 17 Sep 2025
 11:38:52 -0700 (PDT)
MIME-Version: 1.0
References: <202509171214.912d5ac-lkp@intel.com> <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
 <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz>
In-Reply-To: <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Wed, 17 Sep 2025 11:38:41 -0700
X-Gm-Features: AS18NWCa5a8ExJYAmvo8581Fjoj9FqLlIlKIfMzQMBKR4Zv-pgzwhyjut6uI-zc
Message-ID: <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
Subject: Re: [linux-next:master] [slab] db93cdd664: BUG:kernel_NULL_pointer_dereference,address
To: Vlastimil Babka <vbabka@suse.cz>
Cc: kernel test robot <oliver.sang@intel.com>, Alexei Starovoitov <ast@kernel.org>, 
	Harry Yoo <harry.yoo@oracle.com>, Suren Baghdasaryan <surenb@google.com>, oe-lkp@lists.linux.dev, 
	kbuild test robot <lkp@intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:CONTROL GROUP (CGROUP)" <cgroups@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=bnTt2oK3;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
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

On Wed, Sep 17, 2025 at 2:18=E2=80=AFAM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
> On 9/17/25 10:03, Vlastimil Babka wrote:
> > On 9/17/25 07:01, kernel test robot wrote:
> >>
> >>
> >> Hello,
> >>
> >> kernel test robot noticed "BUG:kernel_NULL_pointer_dereference,address=
" on:
> >>
> >> commit: db93cdd664fa02de9be883dd29343b21d8fc790f ("slab: Introduce kma=
lloc_nolock() and kfree_nolock().")
> >> https://git.kernel.org/cgit/linux/kernel/git/next/linux-next.git maste=
r
> >>
> >> in testcase: boot
> >>
> >> config: i386-randconfig-062-20250913
> >> compiler: clang-20
> >> test machine: qemu-system-x86_64 -enable-kvm -cpu SandyBridge -smp 2 -=
m 16G
> >>
> >> (please refer to attached dmesg/kmsg for entire log/backtrace)
>
> Managed to reproduce locally and my suggested fix works so I'm going to f=
old
> it unless there's objections or better suggestions.

Thanks for the fix. Not sure what I was thinking. __GFP_NO_OBJ_EXT
is obviously needed there.

> Also I was curious to find out which path is triggered so I've put a
> dump_stack() before the kmalloc_nolock call:
>
> [    0.731812][    T0] Call Trace:
> [    0.732406][    T0]  __dump_stack+0x18/0x30
> [    0.733200][    T0]  dump_stack_lvl+0x32/0x90
> [    0.734037][    T0]  dump_stack+0xd/0x20
> [    0.734780][    T0]  alloc_slab_obj_exts+0x181/0x1f0
> [    0.735862][    T0]  __alloc_tagging_slab_alloc_hook+0xd1/0x330
> [    0.736988][    T0]  ? __slab_alloc+0x4e/0x70
> [    0.737858][    T0]  ? __set_page_owner+0x167/0x280
> [    0.738774][    T0]  __kmalloc_cache_noprof+0x379/0x460
> [    0.739756][    T0]  ? depot_fetch_stack+0x164/0x180
> [    0.740687][    T0]  ? __set_page_owner+0x167/0x280
> [    0.741604][    T0]  __set_page_owner+0x167/0x280
> [    0.742503][    T0]  post_alloc_hook+0x17a/0x200
> [    0.743404][    T0]  get_page_from_freelist+0x13b3/0x16b0
> [    0.744427][    T0]  ? kvm_sched_clock_read+0xd/0x20
> [    0.745358][    T0]  ? kvm_sched_clock_read+0xd/0x20
> [    0.746290][    T0]  ? __next_zones_zonelist+0x26/0x60
> [    0.747265][    T0]  __alloc_frozen_pages_noprof+0x143/0x1080
> [    0.748358][    T0]  ? lock_acquire+0x8b/0x180
> [    0.749209][    T0]  ? pcpu_alloc_noprof+0x181/0x800
> [    0.750198][    T0]  ? sched_clock_noinstr+0x8/0x10
> [    0.751119][    T0]  ? local_clock_noinstr+0x137/0x140
> [    0.752089][    T0]  ? kvm_sched_clock_read+0xd/0x20
> [    0.753023][    T0]  alloc_slab_page+0xda/0x150
> [    0.753879][    T0]  new_slab+0xe1/0x500
> [    0.754615][    T0]  ? kvm_sched_clock_read+0xd/0x20
> [    0.755577][    T0]  ___slab_alloc+0xd79/0x1680
> [    0.756469][    T0]  ? pcpu_alloc_noprof+0x538/0x800
> [    0.757408][    T0]  ? __mutex_unlock_slowpath+0x195/0x3e0
> [    0.758446][    T0]  __slab_alloc+0x4e/0x70
> [    0.759237][    T0]  ? mm_alloc+0x38/0x80
> [    0.759993][    T0]  kmem_cache_alloc_noprof+0x1db/0x470
> [    0.760993][    T0]  ? mm_alloc+0x38/0x80
> [    0.761745][    T0]  ? mm_alloc+0x38/0x80
> [    0.762506][    T0]  mm_alloc+0x38/0x80
> [    0.763260][    T0]  poking_init+0xe/0x80
> [    0.764032][    T0]  start_kernel+0x16b/0x470
> [    0.764858][    T0]  i386_start_kernel+0xce/0xf0
> [    0.765723][    T0]  startup_32_smp+0x151/0x160
>
> And the reason is we still have restricted gfp_allowed_mask at this point=
:
> /* The GFP flags allowed during early boot */
> #define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM|__GFP_IO|__GFP_F=
S))
>
> It's only lifted to a full allowed mask later in the boot.

Ohh. That's interesting.

> That means due to "kmalloc_nolock() is not supported on architectures tha=
t
> don't implement cmpxchg16b" such architectures will no longer get objexts
> allocated in early boot. I guess that's not a big deal.
>
> Also any later allocation having its flags screwed for some reason to not
> have __GFP_RECLAIM will also lose its objexts. Hope that's also acceptabl=
e.
> I don't know if we can distinguish a real kmalloc_nolock() scope in
> alloc_slab_obj_exts() without inventing new gfp flags or passing an extra
> argument through several layers of functions.

I think it's ok-ish.
Can we add a check to alloc_slab_obj_exts() that sets allow_spin=3Dtrue
if we're in the boot phase? Like:
if (gfp_allowed_mask !=3D __GFP_BITS_MASK)
   allow_spin =3D true;
or some cleaner way to detect boot time by checking slab_state ?
bpf is not active during the boot and nothing should be
calling kmalloc_nolock.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQJYn9%3DGBZifobKzME-bJgrvbn%3DOtQJLbU%2B9xoyO69L8OA%40mail.gmail.com.
