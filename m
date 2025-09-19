Return-Path: <kasan-dev+bncBC7OD3FKWUERBXXAWXDAMGQEKE3NG4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id B0D0FB8A253
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 17:01:53 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-269a2b255aasf29160605ad.3
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Sep 2025 08:01:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758294112; cv=pass;
        d=google.com; s=arc-20240605;
        b=aV4niYBOusUBsJDGWWjftJTCOoRAnGi6odL94VsoBoVq+CNOKTK1xMXkhhl2eZ+gKN
         In/p9xGluNWWQTj/5kEwoK+gRLCENjH+/i9x7vrXKLw7/rmoc0uUYCjEV/HRccZ0GjVb
         9wwJXjbtvnrZu0DxPusye1xyllW9u+uDLysnhJIcUFzV8Wo3zHYVT+rdp6WAybn/pWVk
         XghRCYat1xjluN8o3C5swBgoaE91H2AbJzWmlAQU3agkOl6Hw1LwhaUtx7DbPDJs5bjG
         mbLO3H21GUn2S2RWCofiVHEaxnSAucRz/COKTvSTtx6OiSEwEnON7wSl1HubUQ5/T4ax
         9RjA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Fwsxv1wGzLduhiN/5yFfl19AiwrhrpkU/G/mMfbij6M=;
        fh=BOIjFRVj+uHMNA3vq+v6j9coOzyDv4ttxd98EhKE5HU=;
        b=Y1OFidFgW/7c8LckE6qtee8+wtGq7J/eNV3rrGRPbBXNOpQYS33jby8uXy4uQLazRJ
         qM92iuwTnuUbpQ4z2EplUkS1hwfvDNkmXr8zeYeIm5JnpRKozZi+pBz+QJnPktmavcJP
         UA1xqlh2DS/8qKI1da81VUK+GTOvvbuPHeO/rEY2lcB3/xK7cZu43P1z2p918wosZDlK
         j7XkckfTFMfcyPr1lXdZldu0Pe7I6tz78mB++sm4cQncEu/2XHJHa6ilYy/osHVeyxcu
         AtAosNPAXixScj+ULjomDlp/vMDAuqP+Zkm2UvtL9dlLwbcqJnGvVZVRRhBLLxPK05Nb
         1oQA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FosMqbn4;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758294111; x=1758898911; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Fwsxv1wGzLduhiN/5yFfl19AiwrhrpkU/G/mMfbij6M=;
        b=gCUy9r8ql33ediHd3cbJfR++i0dn/5MQcywk+8MRSydw6slW6TLv+r6qDXBXmtInvp
         iYTqc4iQ/e+N0DKmP9NM+s7HzpeK/IuG2846pratuOldRvf6JN3YbkB5shU79HyWBotU
         ZrCP3ve1a431OWdjZrIhIbGNMTnfFo3mn8DjVFIqeAwSpkTeMuw0JmsT8XvaJgDWtSjk
         5NhyjrrbO+BzOyBp/yljqJoXbtiEZXUvtOmL2XDBye+xl8f7BHyTmvWm7h7ArgZyKe7P
         ybHjrBOZS9wCQ6dY91rgxTQRx2C+TAjNvqJm0tfodRfpVSkfwtyfy/MQysurv0tHm4al
         +SBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758294112; x=1758898912;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Fwsxv1wGzLduhiN/5yFfl19AiwrhrpkU/G/mMfbij6M=;
        b=uWLkgK1LD6XP9TFSXbLDMMZqnY1B8M4obAICPxw6utu06j37RyJTvTH+8IvaarBGfw
         aw+Abh6pd3zy4PxNVr4w2HIocT2knhK0BhXUBW6oE571K479YWMIFBtq662OC8g+Mi2g
         NNffB/yg0KK7SbXIDHRejcwUclzw+ZdCErZ4ZRTCsKXxHlnEZdE6LzjFQegu3YlpbQ9K
         TY/soJhdpfeBIzamP3BAT3jOD3xW0xhHOyCDuv9t4mpXvTmNXnCkkn8GQ/I8bfmKK2U8
         89ZbsGeK/RET0cqG6QB8E64/2bE7uvJvD1Zu7bSItC6waenvlNAqta82tLGhwg6HtaGP
         NA2w==
X-Forwarded-Encrypted: i=2; AJvYcCV8spvZ+ETkJz3BgUXsEa8eiMrJJQ6d3P8SwQE5AI14+K2JjoE4MgBXDWTdsoK7/Y5ETLyP3Q==@lfdr.de
X-Gm-Message-State: AOJu0YxcVoThtLhP9KNUVcZvoAhbhytKjUdV2cci+2DCJjIs/ZndlJ4Z
	1onPR8lKM397xD+KwFoGWMhj/m1LKw5klf/ymSvsAciIj4J69zbrkGUr
X-Google-Smtp-Source: AGHT+IF4Ot3pyHJcSGd1sRokRG/GQ4Y2KKjYrLEul6eEQZuzQWNVN+KWSnaJd71B1vldFgtZaZErFQ==
X-Received: by 2002:a17:902:ccd2:b0:262:9c4:5470 with SMTP id d9443c01a7336-269ba4ffe78mr47518885ad.28.1758294111277;
        Fri, 19 Sep 2025 08:01:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd6mULm3HmjvXuuX0Bi3kY4TbEvCf8cGDmyADrrkWXO0eg==
Received: by 2002:a17:903:42c3:b0:269:63c2:108a with SMTP id
 d9443c01a7336-269840e3698ls15222775ad.1.-pod-prod-06-us; Fri, 19 Sep 2025
 08:01:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuUtbisPb5rz7X+/EqlUAi3CQuBdfON2VnSkSMpr9P+0A8Yd9W5mL3ahPWWvt/vcWfjNQm7rEe2Ug=@googlegroups.com
X-Received: by 2002:a17:903:22cc:b0:26d:353c:75d4 with SMTP id d9443c01a7336-26d353c78dfmr19759895ad.0.1758294109532;
        Fri, 19 Sep 2025 08:01:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758294109; cv=none;
        d=google.com; s=arc-20240605;
        b=kTVNtGaUra2gq58pRjbSz/rdwpxFQ22yZSiiurvuC5C6tFgHKBvFaDqcr6FbL4El4u
         t+SzPT+SEHbjGBT0It8b+L4mbB1hcyKFGTGQ1dm61pPOL49KG/1qZKYTPdildB97FvpK
         VxyWVBfQhj/PWoLkl9WfNA9dRBf6eOv+S5IjK4msSxVGM39iEj3hcPfxaMv+sqEohLm+
         xMPgcoQqIoKqNtNqqiuin9BZ3pZTGzoPaYUOlmivHcTN/ctAdqV4WUPVKbx8n5DFX4oS
         JtvKmN0VqHA9YZb57n+vreSz1Dei1SyhEfcJFXZOz+a0DmO0HSWcW5GK7GUWkQCZ3ERa
         ZgMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=xd49/q/5YBCJxAFGP/L8ktabS8R9TywHti0W/ntbZ14=;
        fh=p5IH7/wgHymy4X3eYT2tNK9+b0MUl5ay0gXM03qZhxM=;
        b=V4kkPnc6RyFGUupsKoyPdpaHywhvktr9KlFvKkY7Aj/4KwsbQrKtnhAND07Pkw8IKW
         dbmEAYAPZpTp/CP3tcsdu7XQOp/u21HvS945d69iMaXGVUqSfakrQ+bV+vUF5L7KxnXb
         LHvXvaiyoiekw/kFh9OY02vEgEjwL1+CljTc4haszy47pIbqO2L63vPGH1Gys6D5166b
         oZPNDQ2ONAUDm3CF5eGmIlrqdlmrJTm4hSkkie/Ety2gYURn1XLwiRhGIUikIBwr5X52
         woTwqf9JTxiSVFtAAxQwUOZ74KayoRGnc3SQyPdwgaS/7hdZ/gaEP1APBwk11F2/dT9w
         1qig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FosMqbn4;
       spf=pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82c as permitted sender) smtp.mailfrom=surenb@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x82c.google.com (mail-qt1-x82c.google.com. [2607:f8b0:4864:20::82c])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32ed26fc0cdsi383442a91.2.2025.09.19.08.01.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Sep 2025 08:01:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82c as permitted sender) client-ip=2607:f8b0:4864:20::82c;
Received: by mail-qt1-x82c.google.com with SMTP id d75a77b69052e-4bb7209ec97so301321cf.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Sep 2025 08:01:49 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVj+xlCpETEdZGmW+HVSJmVV3JUJRvpeEYv/Fr5BC5+gCJdwFqS0Ha+XL6gETbqwIrLYLu5krY/ojY=@googlegroups.com
X-Gm-Gg: ASbGncvuTkna/MEeP0d1nZsj/q+S/j+/cxVmx6CLvKZUAOXFDylMz+xnoemHp89PXvU
	SfWnpMIeOP36/9C6WpmOqN7TB4n8M2e06GzwAHY7mUfcgCizaMknC6JRmYLSfywLYfPQ7r6AXrW
	zfxcB551mXa7y3Yvgglv1qz1OCCjENZCGkLCi/BZHkm6RSMFd5CaA5xiCnC7PvzRR/KBHLqy5QB
	WxhAA==
X-Received: by 2002:ac8:5f84:0:b0:4b7:94d7:8b4c with SMTP id
 d75a77b69052e-4b9d33b6432mr19618551cf.0.1758294107407; Fri, 19 Sep 2025
 08:01:47 -0700 (PDT)
MIME-Version: 1.0
References: <202509171214.912d5ac-lkp@intel.com> <b7d4cf85-5c81-41e0-9b22-baa9a7e5a0c4@suse.cz>
 <ead41e07-c476-4769-aeb6-5a9950737b98@suse.cz> <CAADnVQJYn9=GBZifobKzME-bJgrvbn=OtQJLbU+9xoyO69L8OA@mail.gmail.com>
 <ce3be467-4ff3-4165-a024-d6a3ed33ad0e@suse.cz> <CAJuCfpGLhJtO02V-Y+qmvzOqO2tH5+u7EzrCOA1K-57vPXhb+g@mail.gmail.com>
 <CAADnVQLPq=puz04wNCnUeSUeF2s1SwTUoQvzMWsHCVhjFcyBeg@mail.gmail.com>
In-Reply-To: <CAADnVQLPq=puz04wNCnUeSUeF2s1SwTUoQvzMWsHCVhjFcyBeg@mail.gmail.com>
From: "'Suren Baghdasaryan' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Sep 2025 08:01:36 -0700
X-Gm-Features: AS18NWD12crNOmM4aEy96ofaHX5zWtBB8_S_SE5RNjFC2qJWezk2NctkV6nki6A
Message-ID: <CAJuCfpGA_YKuzHu0TM718LFHr92PyyKdD27yJVbtvfF=ZzNOfQ@mail.gmail.com>
Subject: Re: [linux-next:master] [slab] db93cdd664: BUG:kernel_NULL_pointer_dereference,address
To: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Cc: Vlastimil Babka <vbabka@suse.cz>, kernel test robot <oliver.sang@intel.com>, 
	Alexei Starovoitov <ast@kernel.org>, Harry Yoo <harry.yoo@oracle.com>, oe-lkp@lists.linux.dev, 
	kbuild test robot <lkp@intel.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:CONTROL GROUP (CGROUP)" <cgroups@vger.kernel.org>, linux-mm <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: surenb@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FosMqbn4;       spf=pass
 (google.com: domain of surenb@google.com designates 2607:f8b0:4864:20::82c as
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

On Thu, Sep 18, 2025 at 6:39=E2=80=AFPM Alexei Starovoitov
<alexei.starovoitov@gmail.com> wrote:
>
> On Thu, Sep 18, 2025 at 7:49=E2=80=AFAM Suren Baghdasaryan <surenb@google=
.com> wrote:
> >
> > On Thu, Sep 18, 2025 at 12:06=E2=80=AFAM Vlastimil Babka <vbabka@suse.c=
z> wrote:
> > >
> > > On 9/17/25 20:38, Alexei Starovoitov wrote:
> > > > On Wed, Sep 17, 2025 at 2:18=E2=80=AFAM Vlastimil Babka <vbabka@sus=
e.cz> wrote:
> > > >>
> > > >> Also I was curious to find out which path is triggered so I've put=
 a
> > > >> dump_stack() before the kmalloc_nolock call:
> > > >>
> > > >> [    0.731812][    T0] Call Trace:
> > > >> [    0.732406][    T0]  __dump_stack+0x18/0x30
> > > >> [    0.733200][    T0]  dump_stack_lvl+0x32/0x90
> > > >> [    0.734037][    T0]  dump_stack+0xd/0x20
> > > >> [    0.734780][    T0]  alloc_slab_obj_exts+0x181/0x1f0
> > > >> [    0.735862][    T0]  __alloc_tagging_slab_alloc_hook+0xd1/0x330
> > > >> [    0.736988][    T0]  ? __slab_alloc+0x4e/0x70
> > > >> [    0.737858][    T0]  ? __set_page_owner+0x167/0x280
> > > >> [    0.738774][    T0]  __kmalloc_cache_noprof+0x379/0x460
> > > >> [    0.739756][    T0]  ? depot_fetch_stack+0x164/0x180
> > > >> [    0.740687][    T0]  ? __set_page_owner+0x167/0x280
> > > >> [    0.741604][    T0]  __set_page_owner+0x167/0x280
> > > >> [    0.742503][    T0]  post_alloc_hook+0x17a/0x200
> > > >> [    0.743404][    T0]  get_page_from_freelist+0x13b3/0x16b0
> > > >> [    0.744427][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > > >> [    0.745358][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > > >> [    0.746290][    T0]  ? __next_zones_zonelist+0x26/0x60
> > > >> [    0.747265][    T0]  __alloc_frozen_pages_noprof+0x143/0x1080
> > > >> [    0.748358][    T0]  ? lock_acquire+0x8b/0x180
> > > >> [    0.749209][    T0]  ? pcpu_alloc_noprof+0x181/0x800
> > > >> [    0.750198][    T0]  ? sched_clock_noinstr+0x8/0x10
> > > >> [    0.751119][    T0]  ? local_clock_noinstr+0x137/0x140
> > > >> [    0.752089][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > > >> [    0.753023][    T0]  alloc_slab_page+0xda/0x150
> > > >> [    0.753879][    T0]  new_slab+0xe1/0x500
> > > >> [    0.754615][    T0]  ? kvm_sched_clock_read+0xd/0x20
> > > >> [    0.755577][    T0]  ___slab_alloc+0xd79/0x1680
> > > >> [    0.756469][    T0]  ? pcpu_alloc_noprof+0x538/0x800
> > > >> [    0.757408][    T0]  ? __mutex_unlock_slowpath+0x195/0x3e0
> > > >> [    0.758446][    T0]  __slab_alloc+0x4e/0x70
> > > >> [    0.759237][    T0]  ? mm_alloc+0x38/0x80
> > > >> [    0.759993][    T0]  kmem_cache_alloc_noprof+0x1db/0x470
> > > >> [    0.760993][    T0]  ? mm_alloc+0x38/0x80
> > > >> [    0.761745][    T0]  ? mm_alloc+0x38/0x80
> > > >> [    0.762506][    T0]  mm_alloc+0x38/0x80
> > > >> [    0.763260][    T0]  poking_init+0xe/0x80
> > > >> [    0.764032][    T0]  start_kernel+0x16b/0x470
> > > >> [    0.764858][    T0]  i386_start_kernel+0xce/0xf0
> > > >> [    0.765723][    T0]  startup_32_smp+0x151/0x160
> > > >>
> > > >> And the reason is we still have restricted gfp_allowed_mask at thi=
s point:
> > > >> /* The GFP flags allowed during early boot */
> > > >> #define GFP_BOOT_MASK (__GFP_BITS_MASK & ~(__GFP_RECLAIM|__GFP_IO|=
__GFP_FS))
> > > >>
> > > >> It's only lifted to a full allowed mask later in the boot.
> > > >
> > > > Ohh. That's interesting.
> > > >
> > > >> That means due to "kmalloc_nolock() is not supported on architectu=
res that
> > > >> don't implement cmpxchg16b" such architectures will no longer get =
objexts
> > > >> allocated in early boot. I guess that's not a big deal.
> > > >>
> > > >> Also any later allocation having its flags screwed for some reason=
 to not
> > > >> have __GFP_RECLAIM will also lose its objexts. Hope that's also ac=
ceptable.
> > > >> I don't know if we can distinguish a real kmalloc_nolock() scope i=
n
> > > >> alloc_slab_obj_exts() without inventing new gfp flags or passing a=
n extra
> > > >> argument through several layers of functions.
> > > >
> > > > I think it's ok-ish.
> > > > Can we add a check to alloc_slab_obj_exts() that sets allow_spin=3D=
true
> > > > if we're in the boot phase? Like:
> > > > if (gfp_allowed_mask !=3D __GFP_BITS_MASK)
> > > >    allow_spin =3D true;
> > > > or some cleaner way to detect boot time by checking slab_state ?
> > > > bpf is not active during the boot and nothing should be
> > > > calling kmalloc_nolock.
> > >
> > > Checking the gfp_allowed_mask should work. Slab state is already UP s=
o won't
> > > help, and this is not really about slab state anyway.
> > > But whether worth it... Suren what do you think?
> >
> > Vlastimil's fix is correct. We definitely need __GFP_NO_OBJ_EXT when
> > allocating an obj_exts vector, otherwise it will try to recursively
> > allocate an obj_exts vector for obj_exts allocation.
> >
> > For the additional __GFP_BITS_MASK check, that sounds good to me as
> > long as we add a comment on why that is there. Or maybe such a check
> > deserves to be placed in a separate function similar to
> > gfpflags_allow_{spinning | blocking}?
>
> I would not. I think adding 'boot or not' logic to these two
> will muddy the waters and will make the whole slab/page_alloc/memcg
> logic and dependencies between them much harder to follow.
> I'd either add a comment to alloc_slab_obj_exts() explaining
> what may happen or add 'boot or not' check only there.
> imo this is a niche, rare and special.

Ok, comment it is then.
Will you be sending a new version or Vlastimil will be including that
in his fixup?

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AJuCfpGA_YKuzHu0TM718LFHr92PyyKdD27yJVbtvfF%3DZzNOfQ%40mail.gmail.com.
