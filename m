Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBLH2TPFQMGQETLCAQKQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23b.google.com (mail-lj1-x23b.google.com [IPv6:2a00:1450:4864:20::23b])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F555D1C1D0
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 03:19:26 +0100 (CET)
Received: by mail-lj1-x23b.google.com with SMTP id 38308e7fff4ca-3831426aeb1sf24920791fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 18:19:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768357165; cv=pass;
        d=google.com; s=arc-20240605;
        b=I7R3tJpyFIheT3LXZVQoAwxGvJPjmkdU81o1CrtvQtVN/6HkLrL6lTEembrV1nmn3+
         uCe+JIBOQFGv+LKxARXuS9iohjHfWQX6ANii6EGDEMk1oBuXXGrF/DvBwD+EfuyXShT9
         rThUq/pqvFGSeFpyjZzuWp3gDn9stvHrb3hqzZYfgFS23M6iSp9Xhxr6d4iPYUxbd6IG
         o7DP7O9P7QPAJH6vMJMYfG0883+uD/b6vau4nOUKlwrISA3bL+Vg88qBnZabFmWTFa0a
         +7nu6HjG08o5MQGYKZXfILVdUCQWpoWEfETKMtW3+9Plp4f/DzbIHyIlP64FNHCr2ZNO
         Q2ng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=F2rusyBwV34kkojejdAbJ4NZ+1ctPoPxjB0BoAQnzKA=;
        fh=wqwVCwD35GlVHoN7O7vY6AabD3Fcyxy7LpN6hd0HXtw=;
        b=BRwwf6fgqEJjEfmKbMesk94GNyl672mXRTp80icjAijszBT14mug/P7eZOgTkfJhcM
         e1nOZh2OLmruPVCrGUXnphIYmaxS0jfDkWxRa3HqWKXKy89ZVLksF+nHSfwgL6smU7Ut
         GYsj7aMTzLn+idyCZPy8zk7KN8HihzBWwkRMD3qTjs7RwJKEnIrsz71wIS7yJsWvF8l+
         bTNhKtGZmjN8/7oo69EO9j+ySwiiZEP7oUg3hFnlCl8UQ1lE3uXcabPeFkZwLypehcUO
         8oR0tZDlSgN6mbd5n1ZAHe+qw6loUPJvoJxNZXLIQUShXArDz0cL2/B6y+0V7swI33Au
         qiKg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JxefPSE0;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768357165; x=1768961965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=F2rusyBwV34kkojejdAbJ4NZ+1ctPoPxjB0BoAQnzKA=;
        b=h1MzLVvkwRgEE4I/Hnnai+bzfu6ycGXA1l+pVtja+m1ZJjcPiPSRGvk7uaZ8Q3g+H1
         kMKyY8MjAu1k6Kq8Gw7lygbIMryyIDYD3YojyY3Sf6a0HafqnG+/YjQj+Y+UFbwABZPV
         c6gepU6tKaINu4E29d5pG5YPoXmCiaKz5pRsHydPOe8A1DzsMs5h6i0WPiZmQj/L1i9d
         RCT43Y9+C9RQ/InusUfPQNXiVkb03qqvbPXAIxpHiiIYEfknw0NA1cLD4D5ToQbaSk4z
         0YiDPeyOif9JeSQCnx27Kqt6oVWPpSgUcPN82CQgnI1VJ/h5ifODMwArlixRYh3MT8YZ
         3ocQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768357165; x=1768961965; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=F2rusyBwV34kkojejdAbJ4NZ+1ctPoPxjB0BoAQnzKA=;
        b=XgDTx12BOe9alU225RQMkbTVggl49apKXJUdhgmFi/cXinBaBtYQsWm813dhrhB01R
         kdG5yGegl2mMVOKFtELy/MJWHsARUvezplRrMrU/coLOFQA9hcpoH8SA2sfca942ErY0
         fY55NfbFIEIrJd3tTNjfp6MUBcOyCQ4Q5U7ysYd/UQTTbOwwvARhe/IXnIjtXhPBv8JU
         zlWzg+2U1bFuHw/ZEmmKPIv7uSO3GLMIu9ggdL2GZSMpSCVmbb/5+Znbi70oYM3cFZ4V
         DykR91HrzCr1CEtmI5beGi8YeFkqj0s/yYv2YqTPY7Gv79tkpLrqzBWnLLecoMp23bZ2
         3pUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768357165; x=1768961965;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F2rusyBwV34kkojejdAbJ4NZ+1ctPoPxjB0BoAQnzKA=;
        b=pVKyA7UK0Q1P7NC02Kk1b+R6umvW3zKVhHvW6fQeFw9nJ6Z+tfiI4lWKpXiiEhG/kw
         CWtWNLlulVjwzofW8Mzj9p83UqF5pfnLYwQTd8TUMwF9f8Ry4azTO9Qwa3ntROG5Yap5
         Os+RtTQ7VHNhpugo63lC2xRnmPfPK5vdB55MV4Fu8Keu6ofPt2SLzaYojfglwEKxa+tN
         XVGjrvJJzkUghw9nM0rqnPbdR+VqCHmiPZ/VoKeZ7QBLK96dvtzIxSBh28mzxlWzSMCZ
         nUyQAwTujTa93zeEmtVcQTSRNqk04krporWqTU6Ry+EdDmABF3ljH52r3WpLyGblV8Df
         o3Tg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJ0B1aI53hv1AUlX0mfNHsuF/MvHGUf88+8yRPzuj3YklQvZLI/nF61JgkMYmBMqDoCaeRZw==@lfdr.de
X-Gm-Message-State: AOJu0Yw17jrhmFMnGv9ouYz6rOFlP5Dx2zWxnzW4iFK6OCvZsu+dO7xd
	QoMO+rzjChEFkzaujDYtP45pkhbSsvAekFh0/WGgckLowheWYewIeQUQ
X-Received: by 2002:a05:651c:1443:b0:37b:a519:cc95 with SMTP id 38308e7fff4ca-383607942fbmr3082941fa.21.1768357165209;
        Tue, 13 Jan 2026 18:19:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FoEg0ZoI7cv40FPwPz9D9UjTz4y/NQTak2sz4iervNAQ=="
Received: by 2002:a05:651c:4397:20b0:383:19ea:6a50 with SMTP id
 38308e7fff4ca-38319ea6ff9ls8248491fa.1.-pod-prod-04-eu; Tue, 13 Jan 2026
 18:19:22 -0800 (PST)
X-Received: by 2002:a2e:a99e:0:b0:37f:cc09:3197 with SMTP id 38308e7fff4ca-383607942camr3245281fa.23.1768357161739;
        Tue, 13 Jan 2026 18:19:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768357161; cv=none;
        d=google.com; s=arc-20240605;
        b=jR1ynCPH79nvuVc2L9dfSVkUXEglkQzpVk0cbFf/ZKOOajoj5XfrAnxgsQN2lOIo01
         Rg0dIplV170/9909PbsqlfkM5Da/8t7lfFj048Fxx6TcJ49Bj98Wby0QA4IQVLeRsU/k
         WKqdUM/cA96NBdrt+FBESn7HFwtqDEufruuinxWxU6l82+Pp8KuXXVTVgLYNor1Nmc0e
         OJSMPBUd3h5twRauqu9jKY8/2XIRl+yIfB/duUqe9kW+HtlJTuirufaXCn1fqMI5YUMO
         ndWAuJxgsDvJzSVeGzuh35n92HyJOQgf8rEi2hr9JeVDC48p9F7bzGNM9axWUcQmFnC2
         iEOQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lsH74FQB6GsAZvPhgwCpffF+cdvm1p5xuyklZ/Ubd1M=;
        fh=rI8A+zAE2Kpfv5bB8f7P7UeUqalJFuEpSq7dz3ZOEJc=;
        b=UUoVXef39S8wC/wiVQFfHXZCPI5xAzNnDRitOZIUzVT/zOEXTibIBeUYf31cgzdHjw
         isvkzJl3s/dFz1dXs9/Wm2W035DPH5C+/HJng8ojo58Hn1Rkhi27i5o82MGXqUa5HfDV
         Fl7vQ4IEFxKJJ3diVY0I2oymDZpZlR7wCvQrh0Kgz9HnPHDm0WyvBAApfmAyc8WWhPx1
         lnsHbVz/GLW9mDb+WP9rlXyQwpz0VSL9Z2UqN7oqtjl8w2hr0/Rl4Pt82/I6nzM2VAeS
         Pk0ettFoj1psQMJ1ZatgDDuYSeo/T8olPrk5WVU7d1T6e1qd6h5W0ujsQPLlHZa5YHtf
         5jig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=JxefPSE0;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x534.google.com (mail-ed1-x534.google.com. [2a00:1450:4864:20::534])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-3831850a898si3294691fa.8.2026.01.13.18.19.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 18:19:21 -0800 (PST)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2a00:1450:4864:20::534 as permitted sender) client-ip=2a00:1450:4864:20::534;
Received: by mail-ed1-x534.google.com with SMTP id 4fb4d7f45d1cf-64b9b0b4d5dso17292279a12.1
        for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 18:19:21 -0800 (PST)
X-Gm-Gg: AY/fxX6SmnAdre3ahAzhBIXChaVJAGn47IkDByK4lJ3VwZo5xOl8PnIgwRiPqyNJwZW
	xj8CIVzDt9kMvuBPZxRo2A5/j0R5kd3beOYg8BxwYZYgWoHNoh5x5a7XL3tZnCnfi1oXV0tTSQ7
	SSzgxHfLO2b2UxajS7hW6veaPNjdyLQUWzpI+Y+iwIvUOZA2F7ZtVlgDAlgU9qO+AaP4U9CN75+
	vZzKFOw6wQ89FgkYZfzuk2lc165mffJVg+mJH0E732hBhA4zCRyMX4f5cAU5hbDPu/RuPk1N1a0
	7AloxXhdODF2qndZ42yxjdXsvbiQPQ==
X-Received: by 2002:a05:6402:13cf:b0:641:2cf3:ec3e with SMTP id
 4fb4d7f45d1cf-653ec116812mr724609a12.11.1768357160865; Tue, 13 Jan 2026
 18:19:20 -0800 (PST)
MIME-Version: 1.0
References: <b8976a5d5fcbe8bf919dfa5d8ffbf22be8167eba.1767797480.git.ritesh.list@gmail.com>
 <3013f5eb-dcec-4311-bcac-e2e786172ec8@gmail.com>
In-Reply-To: <3013f5eb-dcec-4311-bcac-e2e786172ec8@gmail.com>
From: Ritesh Harjani <ritesh.list@gmail.com>
Date: Wed, 14 Jan 2026 07:49:08 +0530
X-Gm-Features: AZwV_QjIiVXj1nXf2VdxOqy2XCfQ1ZOrh_ba1_aahhewjGGOITf9ZjmXgSu6LZs
Message-ID: <CALk7dXrseLOzMFpWgxfzafMQe1hJRS0nywBaiN7qkU1HQ-fS_w@mail.gmail.com>
Subject: Re: [RFC] mm/kasan: Fix double free for kasan pXds
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Cc: kasan-dev@googlegroups.com, Alexander Potapenko <glider@google.com>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Content-Type: multipart/alternative; boundary="00000000000068d2e706484fbcd5"
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=JxefPSE0;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2a00:1450:4864:20::534
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
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

--00000000000068d2e706484fbcd5
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

On Wed, 14 Jan, 2026, 4:51=E2=80=AFam Andrey Ryabinin, <ryabinin.a.a@gmail.=
com>
wrote:

>
> On 1/13/26 2:43 PM, Ritesh Harjani (IBM) wrote:
> > kasan_free_pxd() assumes the page table is always struct page aligned.
> > But that's not always the case for all architectures. E.g. In case of
> > powerpc with 64K pagesize, PUD table (of size 4096) comes from slab
> > cache named pgtable-2^9. Hence instead of page_to_virt(pxd_page()) let'=
s
> > just directly pass the start of the pxd table which is anyway present i=
n
> these
> > functions as it's 1st argument.
> >
> > This fixes the below double free kasan issue which is sometimes seen
> with PMEM:
> >
> > radix-mmu: Mapped 0x0000047d10000000-0x0000047f90000000 with 2.00 MiB
> pages
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > BUG: KASAN: double-free in kasan_remove_zero_shadow+0x9c4/0xa20
> > Free of addr c0000003c38e0000 by task ndctl/2164
> >
> > CPU: 34 UID: 0 PID: 2164 Comm: ndctl Not tainted
> 6.19.0-rc1-00048-gea1013c15392 #157 VOLUNTARY
> > Hardware name: IBM,9080-HEX POWER10 (architected) 0x800200 0xf000006
> of:IBM,FW1060.00 (NH1060_012) hv:phyp pSeries
> > Call Trace:
> >  dump_stack_lvl+0x88/0xc4 (unreliable)
> >  print_report+0x214/0x63c
> >  kasan_report_invalid_free+0xe4/0x110
> >  check_slab_allocation+0x100/0x150
> >  kmem_cache_free+0x128/0x6e0
> >  kasan_remove_zero_shadow+0x9c4/0xa20
> >  memunmap_pages+0x2b8/0x5c0
> >  devm_action_release+0x54/0x70
> >  release_nodes+0xc8/0x1a0
> >  devres_release_all+0xe0/0x140
> >  device_unbind_cleanup+0x30/0x120
> >  device_release_driver_internal+0x3e4/0x450
> >  unbind_store+0xfc/0x110
> >  drv_attr_store+0x78/0xb0
> >  sysfs_kf_write+0x114/0x140
> >  kernfs_fop_write_iter+0x264/0x3f0
> >  vfs_write+0x3bc/0x7d0
> >  ksys_write+0xa4/0x190
> >  system_call_exception+0x190/0x480
> >  system_call_vectored_common+0x15c/0x2ec
> > ---- interrupt: 3000 at 0x7fff93b3d3f4
> > NIP:  00007fff93b3d3f4 LR: 00007fff93b3d3f4 CTR: 0000000000000000
> > REGS: c0000003f1b07e80 TRAP: 3000   Not tainted
> (6.19.0-rc1-00048-gea1013c15392)
> > MSR:  800000000280f033 <SF,VEC,VSX,EE,PR,FP,ME,IR,DR,RI,LE>  CR:
> 48888208  XER: 00000000
> > <...>
> > NIP [00007fff93b3d3f4] 0x7fff93b3d3f4
> > LR [00007fff93b3d3f4] 0x7fff93b3d3f4
> > ---- interrupt: 3000
> >
> >  The buggy address belongs to the object at c0000003c38e0000
> >   which belongs to the cache pgtable-2^9 of size 4096
> >  The buggy address is located 0 bytes inside of
> >   4096-byte region [c0000003c38e0000, c0000003c38e1000)
> >
> >  The buggy address belongs to the physical page:
> >  page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0
> pfn:0x3c38c
> >  head: order:2 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:=
0
> >  memcg:c0000003bfd63e01
> >  flags: 0x63ffff800000040(head|node=3D6|zone=3D0|lastcpupid=3D0x7ffff)
> >  page_type: f5(slab)
> >  raw: 063ffff800000040 c000000140058980 5deadbeef0000122 00000000000000=
00
> >  raw: 0000000000000000 0000000080200020 00000000f5000000 c0000003bfd63e=
01
> >  head: 063ffff800000040 c000000140058980 5deadbeef0000122
> 0000000000000000
> >  head: 0000000000000000 0000000080200020 00000000f5000000
> c0000003bfd63e01
> >  head: 063ffff800000002 c00c000000f0e301 00000000ffffffff
> 00000000ffffffff
> >  head: ffffffffffffffff 0000000000000000 00000000ffffffff
> 0000000000000004
> >  page dumped because: kasan: bad access detected
> >
> > [  138.953636] [   T2164] Memory state around the buggy address:
> > [  138.953643] [   T2164]  c0000003c38dff00: fc fc fc fc fc fc fc fc fc
> fc fc fc fc fc fc fc
> > [  138.953652] [   T2164]  c0000003c38dff80: fc fc fc fc fc fc fc fc fc
> fc fc fc fc fc fc fc
> > [  138.953661] [   T2164] >c0000003c38e0000: fc fc fc fc fc fc fc fc fc
> fc fc fc fc fc fc fc
> > [  138.953669] [   T2164]                    ^
> > [  138.953675] [   T2164]  c0000003c38e0080: fc fc fc fc fc fc fc fc fc
> fc fc fc fc fc fc fc
> > [  138.953684] [   T2164]  c0000003c38e0100: fc fc fc fc fc fc fc fc fc
> fc fc fc fc fc fc fc
> > [  138.953692] [   T2164]
> =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > [  138.953701] [   T2164] Disabling lock debugging due to kernel taint
> >
> > Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
>
> I suppose this deserves cc stable and fixes tag:
>
> Fixes: 0207df4fa1a8 ("kernel/memremap, kasan: make ZONE_DEVICE with work
> with KASAN")
> Cc: stable@vger.kernel.org
>
> > ---
> >
> > It will be very helpful if one can review this path more thoroughly as =
I
> am not
> > much aware of this code paths of page table freeing in kasan. But it
> logically
> > looked ok to me to free all PXDs in the same fashion.
> >
>
> I can't find a reason why this code was written in such odd way.


I guess you meant s/code/msg.

Your patch makes total sense to me.
>

Thanks Andrey. That helps.


> Please add Andrew Morton <akpm@linux-foundation.org>  and  <
> linux-kernel@vger.kernel.org> to recipients
> and resend the patch.


Yes, in v2 will do that and will add fixes & stable tag too.
I am on travel from today , so I will send v2 once I am back.

Thanks for the review!
-ritesh

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
ALk7dXrseLOzMFpWgxfzafMQe1hJRS0nywBaiN7qkU1HQ-fS_w%40mail.gmail.com.

--00000000000068d2e706484fbcd5
Content-Type: text/html; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable

<div dir=3D"auto"><div><br><br><div class=3D"gmail_quote gmail_quote_contai=
ner"><div dir=3D"ltr" class=3D"gmail_attr">On Wed, 14 Jan, 2026, 4:51=E2=80=
=AFam Andrey Ryabinin, &lt;<a href=3D"mailto:ryabinin.a.a@gmail.com">ryabin=
in.a.a@gmail.com</a>&gt; wrote:<br></div><blockquote class=3D"gmail_quote" =
style=3D"margin:0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex"><br=
>
On 1/13/26 2:43 PM, Ritesh Harjani (IBM) wrote:<br>
&gt; kasan_free_pxd() assumes the page table is always struct page aligned.=
<br>
&gt; But that&#39;s not always the case for all architectures. E.g. In case=
 of<br>
&gt; powerpc with 64K pagesize, PUD table (of size 4096) comes from slab<br=
>
&gt; cache named pgtable-2^9. Hence instead of page_to_virt(pxd_page()) let=
&#39;s<br>
&gt; just directly pass the start of the pxd table which is anyway present =
in these<br>
&gt; functions as it&#39;s 1st argument.<br>
&gt; <br>
&gt; This fixes the below double free kasan issue which is sometimes seen w=
ith PMEM:<br>
&gt; <br>
&gt; radix-mmu: Mapped 0x0000047d10000000-0x0000047f90000000 with 2.00 MiB =
pages<br>
&gt; =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D<br>
&gt; BUG: KASAN: double-free in kasan_remove_zero_shadow+0x9c4/0xa20<br>
&gt; Free of addr c0000003c38e0000 by task ndctl/2164<br>
&gt; <br>
&gt; CPU: 34 UID: 0 PID: 2164 Comm: ndctl Not tainted 6.19.0-rc1-00048-gea1=
013c15392 #157 VOLUNTARY<br>
&gt; Hardware name: IBM,9080-HEX POWER10 (architected) 0x800200 0xf000006 o=
f:IBM,FW1060.00 (NH1060_012) hv:phyp pSeries<br>
&gt; Call Trace:<br>
&gt;=C2=A0 dump_stack_lvl+0x88/0xc4 (unreliable)<br>
&gt;=C2=A0 print_report+0x214/0x63c<br>
&gt;=C2=A0 kasan_report_invalid_free+0xe4/0x110<br>
&gt;=C2=A0 check_slab_allocation+0x100/0x150<br>
&gt;=C2=A0 kmem_cache_free+0x128/0x6e0<br>
&gt;=C2=A0 kasan_remove_zero_shadow+0x9c4/0xa20<br>
&gt;=C2=A0 memunmap_pages+0x2b8/0x5c0<br>
&gt;=C2=A0 devm_action_release+0x54/0x70<br>
&gt;=C2=A0 release_nodes+0xc8/0x1a0<br>
&gt;=C2=A0 devres_release_all+0xe0/0x140<br>
&gt;=C2=A0 device_unbind_cleanup+0x30/0x120<br>
&gt;=C2=A0 device_release_driver_internal+0x3e4/0x450<br>
&gt;=C2=A0 unbind_store+0xfc/0x110<br>
&gt;=C2=A0 drv_attr_store+0x78/0xb0<br>
&gt;=C2=A0 sysfs_kf_write+0x114/0x140<br>
&gt;=C2=A0 kernfs_fop_write_iter+0x264/0x3f0<br>
&gt;=C2=A0 vfs_write+0x3bc/0x7d0<br>
&gt;=C2=A0 ksys_write+0xa4/0x190<br>
&gt;=C2=A0 system_call_exception+0x190/0x480<br>
&gt;=C2=A0 system_call_vectored_common+0x15c/0x2ec<br>
&gt; ---- interrupt: 3000 at 0x7fff93b3d3f4<br>
&gt; NIP:=C2=A0 00007fff93b3d3f4 LR: 00007fff93b3d3f4 CTR: 0000000000000000=
<br>
&gt; REGS: c0000003f1b07e80 TRAP: 3000=C2=A0 =C2=A0Not tainted=C2=A0 (6.19.=
0-rc1-00048-gea1013c15392)<br>
&gt; MSR:=C2=A0 800000000280f033 &lt;SF,VEC,VSX,EE,PR,FP,ME,IR,DR,RI,LE&gt;=
=C2=A0 CR: 48888208=C2=A0 XER: 00000000<br>
&gt; &lt;...&gt;<br>
&gt; NIP [00007fff93b3d3f4] 0x7fff93b3d3f4<br>
&gt; LR [00007fff93b3d3f4] 0x7fff93b3d3f4<br>
&gt; ---- interrupt: 3000<br>
&gt; <br>
&gt;=C2=A0 The buggy address belongs to the object at c0000003c38e0000<br>
&gt;=C2=A0 =C2=A0which belongs to the cache pgtable-2^9 of size 4096<br>
&gt;=C2=A0 The buggy address is located 0 bytes inside of<br>
&gt;=C2=A0 =C2=A04096-byte region [c0000003c38e0000, c0000003c38e1000)<br>
&gt; <br>
&gt;=C2=A0 The buggy address belongs to the physical page:<br>
&gt;=C2=A0 page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 p=
fn:0x3c38c<br>
&gt;=C2=A0 head: order:2 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pin=
count:0<br>
&gt;=C2=A0 memcg:c0000003bfd63e01<br>
&gt;=C2=A0 flags: 0x63ffff800000040(head|node=3D6|zone=3D0|lastcpupid=3D0x7=
ffff)<br>
&gt;=C2=A0 page_type: f5(slab)<br>
&gt;=C2=A0 raw: 063ffff800000040 c000000140058980 5deadbeef0000122 00000000=
00000000<br>
&gt;=C2=A0 raw: 0000000000000000 0000000080200020 00000000f5000000 c0000003=
bfd63e01<br>
&gt;=C2=A0 head: 063ffff800000040 c000000140058980 5deadbeef0000122 0000000=
000000000<br>
&gt;=C2=A0 head: 0000000000000000 0000000080200020 00000000f5000000 c000000=
3bfd63e01<br>
&gt;=C2=A0 head: 063ffff800000002 c00c000000f0e301 00000000ffffffff 0000000=
0ffffffff<br>
&gt;=C2=A0 head: ffffffffffffffff 0000000000000000 00000000ffffffff 0000000=
000000004<br>
&gt;=C2=A0 page dumped because: kasan: bad access detected<br>
&gt; <br>
&gt; [=C2=A0 138.953636] [=C2=A0 =C2=A0T2164] Memory state around the buggy=
 address:<br>
&gt; [=C2=A0 138.953643] [=C2=A0 =C2=A0T2164]=C2=A0 c0000003c38dff00: fc fc=
 fc fc fc fc fc fc fc fc fc fc fc fc fc fc<br>
&gt; [=C2=A0 138.953652] [=C2=A0 =C2=A0T2164]=C2=A0 c0000003c38dff80: fc fc=
 fc fc fc fc fc fc fc fc fc fc fc fc fc fc<br>
&gt; [=C2=A0 138.953661] [=C2=A0 =C2=A0T2164] &gt;c0000003c38e0000: fc fc f=
c fc fc fc fc fc fc fc fc fc fc fc fc fc<br>
&gt; [=C2=A0 138.953669] [=C2=A0 =C2=A0T2164]=C2=A0 =C2=A0 =C2=A0 =C2=A0 =
=C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 =C2=A0 ^<br>
&gt; [=C2=A0 138.953675] [=C2=A0 =C2=A0T2164]=C2=A0 c0000003c38e0080: fc fc=
 fc fc fc fc fc fc fc fc fc fc fc fc fc fc<br>
&gt; [=C2=A0 138.953684] [=C2=A0 =C2=A0T2164]=C2=A0 c0000003c38e0100: fc fc=
 fc fc fc fc fc fc fc fc fc fc fc fc fc fc<br>
&gt; [=C2=A0 138.953692] [=C2=A0 =C2=A0T2164] =3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D<br>
&gt; [=C2=A0 138.953701] [=C2=A0 =C2=A0T2164] Disabling lock debugging due =
to kernel taint<br>
&gt; <br>
&gt; Signed-off-by: Ritesh Harjani (IBM) &lt;<a href=3D"mailto:ritesh.list@=
gmail.com" target=3D"_blank" rel=3D"noreferrer">ritesh.list@gmail.com</a>&g=
t;<br>
<br>
I suppose this deserves cc stable and fixes tag:<br>
<br>
Fixes: 0207df4fa1a8 (&quot;kernel/memremap, kasan: make ZONE_DEVICE with wo=
rk with KASAN&quot;)<br>
Cc: <a href=3D"mailto:stable@vger.kernel.org" target=3D"_blank" rel=3D"nore=
ferrer">stable@vger.kernel.org</a><br><br>
&gt; ---<br>
&gt; <br>
&gt; It will be very helpful if one can review this path more thoroughly as=
 I am not<br>
&gt; much aware of this code paths of page table freeing in kasan. But it l=
ogically<br>
&gt; looked ok to me to free all PXDs in the same fashion.<br>
&gt; <br>
<br>
I can&#39;t find a reason why this code was written in such odd way. </bloc=
kquote></div></div><div dir=3D"auto"><br></div><div dir=3D"auto">I guess yo=
u meant s/code/msg.=C2=A0</div><div dir=3D"auto"><br></div><div dir=3D"auto=
"><div class=3D"gmail_quote gmail_quote_container"><blockquote class=3D"gma=
il_quote" style=3D"margin:0 0 0 .8ex;border-left:1px #ccc solid;padding-lef=
t:1ex">Your patch makes total sense to me.<br></blockquote></div></div><div=
 dir=3D"auto"><br></div><div dir=3D"auto">Thanks Andrey. That helps.=C2=A0<=
/div><div dir=3D"auto"><br></div><div dir=3D"auto"><div class=3D"gmail_quot=
e gmail_quote_container"><blockquote class=3D"gmail_quote" style=3D"margin:=
0 0 0 .8ex;border-left:1px #ccc solid;padding-left:1ex">
<br>
Please add Andrew Morton &lt;<a href=3D"mailto:akpm@linux-foundation.org" t=
arget=3D"_blank" rel=3D"noreferrer">akpm@linux-foundation.org</a>&gt;=C2=A0=
 and=C2=A0 &lt;<a href=3D"mailto:linux-kernel@vger.kernel.org" target=3D"_b=
lank" rel=3D"noreferrer">linux-kernel@vger.kernel.org</a>&gt; to recipients=
<br>
and resend the patch.</blockquote></div></div><div dir=3D"auto"><br></div><=
div dir=3D"auto">Yes, in v2 will do that and will add fixes &amp; stable ta=
g too.=C2=A0</div><div dir=3D"auto">I am on travel from today , so I will s=
end v2 once I am back.=C2=A0</div><div dir=3D"auto"><br></div><div dir=3D"a=
uto">Thanks for the review!=C2=A0</div><div dir=3D"auto">-ritesh</div></div=
>

<p></p>

-- <br />
You received this message because you are subscribed to the Google Groups &=
quot;kasan-dev&quot; group.<br />
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to <a href=3D"mailto:kasan-dev+unsubscribe@googlegroups.com">kasan-dev=
+unsubscribe@googlegroups.com</a>.<br />
To view this discussion visit <a href=3D"https://groups.google.com/d/msgid/=
kasan-dev/CALk7dXrseLOzMFpWgxfzafMQe1hJRS0nywBaiN7qkU1HQ-fS_w%40mail.gmail.=
com?utm_medium=3Demail&utm_source=3Dfooter">https://groups.google.com/d/msg=
id/kasan-dev/CALk7dXrseLOzMFpWgxfzafMQe1hJRS0nywBaiN7qkU1HQ-fS_w%40mail.gma=
il.com</a>.<br />

--00000000000068d2e706484fbcd5--
