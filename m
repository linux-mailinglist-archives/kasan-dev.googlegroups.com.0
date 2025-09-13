Return-Path: <kasan-dev+bncBCKPFB7SXUERB4WRSTDAMGQE7GEXBII@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id F32F1B55F60
	for <lists+kasan-dev@lfdr.de>; Sat, 13 Sep 2025 10:19:08 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4b5ee6cd9a3sf57281311cf.2
        for <lists+kasan-dev@lfdr.de>; Sat, 13 Sep 2025 01:19:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757751538; cv=pass;
        d=google.com; s=arc-20240605;
        b=GniQ36a8oaxnb2YoZWdAGrbeDnubE1YL0AuuF3DqhZdM+pQU23aVt56aItFBBhIdjr
         35k6HM4xa1+mPtQUqpVrx7gXtQMWdzgDj9WWcZivYBzDGqDypKCYrJQxwnWOFAyjn4yv
         XKaujV9+OdZqwvnI012C8dSN3YbDocXRueBRCSE3LUGEAmmr26a1otl+dQ/2ix6bh7cg
         EQcYmAhAHo+q+mJjOkr6yB68BwYo9L+tbOTZpOBZs+8KlAevUI7HUpCnuqG7b5XsTl3D
         g51Ma0YT5zncr5CnpMMU/xN+rzBiCv+Wf8v8WncrrJafWVyjYq2TywSZGxHPcX//WRJU
         CiSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :content-disposition:in-reply-to:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=LdFv1jxJaJWATZhdSdbci5qwcDeFAKgDmuwTLBDXAyw=;
        fh=KltR+hUe3zHZ6zQVuHFKgfAMoYJ7q+WF010JdaWO9aM=;
        b=PgstfsSyIT+2Wxb7fh5KV9rwUiaO5f08Ns7D+Tb/ux2ytRO1Z4jYDphT+E0Z3CM6Jx
         d9/2LIzUCS/6kgE7Mp83Ippv/Zve5wS9nMO1d0zyS5hoEjCn3c3cAMvkNvdBRWDMPE91
         xGZ280AUKSClJysVJq013df8YrEU6ADabeIVNGyqKpf5pKBZ+WaxkwFS2yuGR7ANLyYM
         muhfzZeBqNNNeCwBlixIwSMIXZBI5Z18HG70NgwT4hS4FgXNfXvvrWSo6ULuSiG1hTNR
         dg2YXb82rV9MxsGw5OxDLb644uQxItsWTI+qqo+sHlOZIKOMZn5guIw8bpzVHkE9Pxcg
         sE/A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KtpoM3bE;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757751538; x=1758356338; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LdFv1jxJaJWATZhdSdbci5qwcDeFAKgDmuwTLBDXAyw=;
        b=i2sk5SXrIHSdgZoF6aa7dt6Q54Zo3YU6JRFgZD3IybHuAfE3LyObmghVUdHC52WTtC
         /oDxDDxXKyudIxw3/zvZkKw7TcVZVEaqojF6jBszGCb+4pPhjmE8rzt9Nxam/aoxG53N
         LMcNzmUFFBWoPR53t+JWqj5jsgMUlkon7J8H5eAaLxztABxKRAeWqbxkwPDXQTGaTdYq
         Lor4IRCRi4LGXm4ezVwL+UqowVslhd2KYHASjyD78IS+75p0aQ57h9m4vRxmo/aPk+7J
         sSBOWN6pTWwAwZBJqCDdimn4MBnfy2AFKIgC0W4Jzr98zBghlXq9x1vMKixHc6M0QmZn
         nDkg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757751538; x=1758356338;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LdFv1jxJaJWATZhdSdbci5qwcDeFAKgDmuwTLBDXAyw=;
        b=MGmQz8m55o4JP9sL9/9IwX+krLwS7d/VIIMjhjyTH+DupZhAXW1mj6k/5YMrGY6MJ0
         hkK9MmHN6BEXFUA3vU/NDMgQyAZ4FJT1OM88PjF+YiZOoZXIq2YFvw+xFHKEucV6jbE+
         /bYh2/Qeq4iukRRersUq8E7TuzIhwRGSG/+EeBjtk/w1NI7HU6eCph7myF0VPUfjGkOm
         H6bpLsdSPXMBY0IsG9yJzxgbP2xnOrkysK84OesI96uCUteYh14/vnPDaeZJWjhjkjzy
         wLdRlSN64p3iJnOy21k7d2IIRNA7TII096QJB/AA/jSQR31SpwbHBHkp/NHfKZff9VR0
         104g==
X-Forwarded-Encrypted: i=2; AJvYcCW4mhMB72yP+HE4PoI53oWXUBBGiHs+RhqBM5mG264m6+s50Xxs+gJ+KPoDQK2WlqdKmEKnRA==@lfdr.de
X-Gm-Message-State: AOJu0Yzk3UJrapl915AFx8VLSUU7ZpQ9LsQJTmQb+Uxnavxj4f/qz1H7
	fIYppS09Brbq+/UytGpeFHqsMLYAYUDjmO4mdRHZ1AKvz52cRaIYOTWl
X-Google-Smtp-Source: AGHT+IGthd1Q4gsgdLiJrgKdxdYaU99ktPgZwVkX3ufCx/8SdNTeFJfiZJCn/OS00zl7dogb8bJFKQ==
X-Received: by 2002:a05:622a:d4:b0:4b4:9773:5854 with SMTP id d75a77b69052e-4b77d05e9e9mr72934681cf.2.1757751538490;
        Sat, 13 Sep 2025 01:18:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZefhbuSDV+yUV8R/LgfOVnYPaU8td5VI2xXFCKEjXkS5A==
Received: by 2002:ac8:5781:0:b0:4b5:dc6e:c1df with SMTP id d75a77b69052e-4b636cc9f57ls46948741cf.2.-pod-prod-07-us;
 Sat, 13 Sep 2025 01:18:57 -0700 (PDT)
X-Received: by 2002:a05:620a:1729:b0:824:63df:561f with SMTP id af79cd13be357-82463df567bmr675869385a.28.1757751537549;
        Sat, 13 Sep 2025 01:18:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757751537; cv=none;
        d=google.com; s=arc-20240605;
        b=EloXlMAkHRf3L3qpUQvtuCrWOFExmmamYw4+s7/IArgCpu5sgjd5+fkM7Y+erACWG6
         TwBOiXQ+3anuPN1UX9ggVnF7p6Mv9ILYXmpUt0RKWjSn2pQbV7G00lSa3c3b+mG6IT+t
         UxDRZcjRj+YKsjjBWolrlfpOU4i+6pnzdghCpPokUFnlqJbhELE8xBs99YKn39ELbSV+
         zSuF/1Y96jvutcddHcMxtqk2dYxLksgkNWVCcMBQ6C8HaTTKiZpZp8Tq2joV2SC2yzRf
         sTBUWSkVpNna9MPRTySynLCzlur1kKSaoUGTjaMt8ts4TO17BMO9YWX0TE50KLhUpEeo
         16zA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-disposition:in-reply-to
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=Spp/Jz1qXl5SUzfrVjS1ofed61ZjUSO+C5UH/+1pmIs=;
        fh=dADbQc5g/FOuikCCrc1uxfeOxMCGQvdZvdId9lWimvk=;
        b=XQzCe4/5EVbiv7M9GleqXQjrh0Fe5Vk00MBa97Y7FvuksK/jQyY1unzf7r83LPMNEV
         ZfrLTRzDntJmJEyJZLSTRxEAyoE+FF1e9RxNzT0wQcV5HcK8xgkOYHkYV6IsWrFOMhng
         YL+NVntrFW4QPbnM2ihOWmr26p56sJrZ2rzHdCCd33h+TAT+7iQFtRIB/6pVVuz6QiXp
         eLI0CiqtOfWeYX9tvnGwb9KQfwPLEGRQz6ZlkEWTigSWeT6vbVPoODfwmYTTNkm3ad1I
         wGpF5XS8KfZ+QKZXizjH4sy1vlGFINmI8Q/UC6V40p9fd6GYZupr2y89WD9TGOWPMX+j
         Wr4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=KtpoM3bE;
       spf=pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.129.124])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4b639de813asi2761201cf.5.2025.09.13.01.18.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sat, 13 Sep 2025 01:18:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of bhe@redhat.com designates 170.10.129.124 as permitted sender) client-ip=170.10.129.124;
Received: from mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com
 (ec2-54-186-198-63.us-west-2.compute.amazonaws.com [54.186.198.63]) by
 relay.mimecast.com with ESMTP with STARTTLS (version=TLSv1.3,
 cipher=TLS_AES_256_GCM_SHA384) id us-mta-501-cbEIzo6iN9yUuPu2mhHx7A-1; Sat,
 13 Sep 2025 04:18:53 -0400
X-MC-Unique: cbEIzo6iN9yUuPu2mhHx7A-1
X-Mimecast-MFC-AGG-ID: cbEIzo6iN9yUuPu2mhHx7A_1757751532
Received: from mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com [10.30.177.12])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange X25519 server-signature RSA-PSS (2048 bits) server-digest SHA256)
	(No client certificate requested)
	by mx-prod-mc-04.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 0A99319560B3;
	Sat, 13 Sep 2025 08:18:52 +0000 (UTC)
Received: from localhost (unknown [10.72.112.45])
	by mx-prod-int-03.mail-002.prod.us-west-2.aws.redhat.com (Postfix) with ESMTPS id 5D19019560B9;
	Sat, 13 Sep 2025 08:18:49 +0000 (UTC)
Date: Sat, 13 Sep 2025 16:18:46 +0800
From: "'Baoquan He' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: kasan-dev@googlegroups.com, ryabinin.a.a@gmail.com, glider@google.com,
	dvyukov@google.com, vincenzo.frascino@arm.com, linux-mm@kvack.org,
	Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Subject: Re: System is broken in KASAN sw_tags mode during bootup
Message-ID: <aMUo5rXaXOU2nNh4@MiWiFi-R3L-srv>
References: <aKMLgHdTOEf9B92E@MiWiFi-R3L-srv>
 <CA+fCnZebyMgWWEOW_ZxiGwnkiXqXX6XK5NJv-uWXAxdN+JxsSw@mail.gmail.com>
MIME-Version: 1.0
In-Reply-To: <CA+fCnZebyMgWWEOW_ZxiGwnkiXqXX6XK5NJv-uWXAxdN+JxsSw@mail.gmail.com>
X-Scanned-By: MIMEDefang 3.0 on 10.30.177.12
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: Y1TQurL4dEBDcxvIh54NGf3acbhyLwNjEea9-i_Y8dQ_1757751532
X-Mimecast-Originator: redhat.com
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: bhe@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=KtpoM3bE;
       spf=pass (google.com: domain of bhe@redhat.com designates
 170.10.129.124 as permitted sender) smtp.mailfrom=bhe@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: Baoquan He <bhe@redhat.com>
Reply-To: Baoquan He <bhe@redhat.com>
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

On 09/06/25 at 07:23pm, Andrey Konovalov wrote:
> On Mon, Aug 18, 2025 at 1:16=E2=80=AFPM Baoquan He <bhe@redhat.com> wrote=
:
> >
> > Hi,
> >
> > This can be reproduced stably on hpe-apollo arm64 system with the lates=
t
> > upstream kernel. I have this system at hand now, the boot log and kerne=
l
> > config are attached for reference.
> >
> > [   89.257633] =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D
> > [   89.257646] BUG: KASAN: invalid-access in pcpu_alloc_noprof+0x42c/0x=
9a8
> > [   89.257672] Write of size 528 at addr ddfffd7fbdc00000 by task syste=
md/1
> > [   89.257685] Pointer tag: [dd], memory tag: [ca]
> > [   89.257692]
> > [   89.257703] CPU: 108 UID: 0 PID: 1 Comm: systemd Not tainted 6.17.0-=
rc2 #1 PREEMPT(voluntary)
> > [   89.257719] Hardware name: HPE Apollo 70             /C01_APACHE_MB =
        , BIOS L50_5.13_1.16 07/29/2020
> > [   89.257726] Call trace:
> > [   89.257731]  show_stack+0x30/0x90 (C)
> > [   89.257753]  dump_stack_lvl+0x7c/0xa0
> > [   89.257769]  print_address_description.isra.0+0x90/0x2b8
> > [   89.257789]  print_report+0x120/0x208
> > [   89.257804]  kasan_report+0xc8/0x110
> > [   89.257823]  kasan_check_range+0x7c/0xa0
> > [   89.257835]  __asan_memset+0x30/0x68
> > [   89.257847]  pcpu_alloc_noprof+0x42c/0x9a8
> > [   89.257859]  mem_cgroup_alloc+0x2bc/0x560
> > [   89.257873]  mem_cgroup_css_alloc+0x78/0x780
> > [   89.257893]  cgroup_apply_control_enable+0x230/0x578
> > [   89.257914]  cgroup_mkdir+0xf0/0x330
> > [   89.257928]  kernfs_iop_mkdir+0xb0/0x120
> > [   89.257947]  vfs_mkdir+0x250/0x380
> > [   89.257965]  do_mkdirat+0x254/0x298
> > [   89.257979]  __arm64_sys_mkdirat+0x80/0xc0
> > [   89.257994]  invoke_syscall.constprop.0+0x88/0x148
> > [   89.258011]  el0_svc_common.constprop.0+0x78/0x148
> > [   89.258025]  do_el0_svc+0x38/0x50
> > [   89.258037]  el0_svc+0x3c/0x168
> > [   89.258050]  el0t_64_sync_handler+0xa0/0xf0
> > [   89.258063]  el0t_64_sync+0x1b0/0x1b8
> > [   89.258076]
> > [   89.258080] The buggy address belongs to a 0-page vmalloc region sta=
rting at 0xcafffd7fbdc00000 allocated at pcpu_get_vm_areas+0x0/0x1da0
> > [   89.258111] The buggy address belongs to the physical page:
> > [   89.258117] page: refcount:1 mapcount:0 mapping:0000000000000000 ind=
ex:0x0 pfn:0x881ddac
> > [   89.258129] flags: 0xa5c00000000000(node=3D1|zone=3D2|kasantag=3D0x5=
c)
> > [   89.258148] raw: 00a5c00000000000 0000000000000000 dead000000000122 =
0000000000000000
> > [   89.258160] raw: 0000000000000000 f3ff000813efa600 00000001ffffffff =
0000000000000000
> > [   89.258168] raw: 00000000000fffff 0000000000000000
> > [   89.258173] page dumped because: kasan: bad access detected
> > [   89.258178]
> > [   89.258181] Memory state around the buggy address:
> > [   89.258192] Unable to handle kernel paging request at virtual addres=
s ffff7fd7fbdbffe0
> > [   89.258199] KASAN: probably wild-memory-access in range [0xfffffd7fb=
dbffe00-0xfffffd7fbdbffe0f]
> > [   89.258207] Mem abort info:
> > [   89.258211]   ESR =3D 0x0000000096000007
> > [   89.258216]   EC =3D 0x25: DABT (current EL), IL =3D 32 bits
> > [   89.258223]   SET =3D 0, FnV =3D 0
> > [   89.258228]   EA =3D 0, S1PTW =3D 0
> > [   89.258232]   FSC =3D 0x07: level 3 translation fault
> > [   89.258238] Data abort info:
> > [   89.258241]   ISV =3D 0, ISS =3D 0x00000007, ISS2 =3D 0x00000000
> > [   89.258246]   CM =3D 0, WnR =3D 0, TnD =3D 0, TagAccess =3D 0
> > [   89.258252]   GCS =3D 0, Overlay =3D 0, DirtyBit =3D 0, Xs =3D 0
> > [   89.258260] swapper pgtable: 4k pages, 48-bit VAs, pgdp=3D0000008ff8=
b8f000
> > [   89.258267] [ffff7fd7fbdbffe0] pgd=3D1000008ff0275403, p4d=3D1000008=
ff0275403, pud=3D1000008ff0274403, pmd=3D1000000899079403, pte=3D0000000000=
000000
> > [   89.258296] Internal error: Oops: 0000000096000007 [#1]  SMP
> > [   89.540859] Modules linked in: i2c_dev
> > [   89.544619] CPU: 108 UID: 0 PID: 1 Comm: systemd Not tainted 6.17.0-=
rc2 #1 PREEMPT(voluntary)
> > [   89.553234] Hardware name: HPE Apollo 70             /C01_APACHE_MB =
        , BIOS L50_5.13_1.16 07/29/2020
> > [   89.562970] pstate: 604000c9 (nZCv daIF +PAN -UAO -TCO -DIT -SSBS BT=
YPE=3D--)
> > [   89.569933] pc : __pi_memcpy_generic+0x24/0x230
> > [   89.574472] lr : kasan_metadata_fetch_row+0x20/0x30
> > [   89.579350] sp : ffff8000859d76c0
> > [   89.582660] x29: ffff8000859d76c0 x28: 0000000000000100 x27: ffff008=
ec626d800
> > [   89.589807] x26: 0000000000000210 x25: 0000000000000000 x24: fffffd7=
fbdbfff00
> > [   89.596952] x23: ffff8000826cbeb8 x22: fffffd7fbdc00000 x21: 0000000=
0fffffffe
> > [   89.604097] x20: ffff800082682ee0 x19: fffffd7fbdbffe00 x18: 0000000=
0049016ff
> > [   89.611242] x17: 3030303030303030 x16: 2066666666666666 x15: 6631303=
030303030
> > [   89.618386] x14: 0000000000000001 x13: 0000000000000001 x12: 0000000=
000000001
> > [   89.625530] x11: 687420646e756f72 x10: 0000000000000020 x9 : 0000000=
000000000
> > [   89.632674] x8 : ffff78000859d766 x7 : 0000000000000000 x6 : 0000000=
00000003a
> > [   89.639818] x5 : ffff8000859d7728 x4 : ffff7fd7fbdbfff0 x3 : efff800=
000000000
> > [   89.646963] x2 : 0000000000000010 x1 : ffff7fd7fbdbffe0 x0 : ffff800=
0859d7718
> > [   89.654107] Call trace:
> > [   89.656549]  __pi_memcpy_generic+0x24/0x230 (P)
> > [   89.661086]  print_report+0x180/0x208
> > [   89.664753]  kasan_report+0xc8/0x110
> > [   89.668333]  kasan_check_range+0x7c/0xa0
> > [   89.672258]  __asan_memset+0x30/0x68
> > [   89.675836]  pcpu_alloc_noprof+0x42c/0x9a8
> > [   89.679935]  mem_cgroup_alloc+0x2bc/0x560
> > [   89.683947]  mem_cgroup_css_alloc+0x78/0x780
> > [   89.688222]  cgroup_apply_control_enable+0x230/0x578
> > [   89.693191]  cgroup_mkdir+0xf0/0x330
> > [   89.696771]  kernfs_iop_mkdir+0xb0/0x120
> > [   89.700697]  vfs_mkdir+0x250/0x380
> > [   89.704103]  do_mkdirat+0x254/0x298
> > [   89.707596]  __arm64_sys_mkdirat+0x80/0xc0
> > [   89.711697]  invoke_syscall.constprop.0+0x88/0x148
> > [   89.716491]  el0_svc_common.constprop.0+0x78/0x148
> > [   89.721286]  do_el0_svc+0x38/0x50
> > [   89.724602]  el0_svc+0x3c/0x168
> > [   89.727746]  el0t_64_sync_handler+0xa0/0xf0
> > [   89.731933]  el0t_64_sync+0x1b0/0x1b8
> > [   89.735603] Code: f100805f 540003c8 f100405f 540000c3 (a9401c26)
> > [   89.741695] ---[ end trace 0000000000000000 ]---
> > [   89.746308] note: systemd[1] exi
> > =3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D
>=20
> Might be the same issue as the one being fixed by Maciej here:
>=20
> https://lore.kernel.org/all/bcf18f220ef3b40e02f489fdb90fc7a5a153a383.1756=
151769.git.maciej.wieczor-retman@intel.com/
> https://lore.kernel.org/all/3339d11e69c9127108fe8ef80a069b7b3bb07175.1756=
151769.git.maciej.wieczor-retman@intel.com/
>=20
> Perhaps it makes sense to split that fix out of the series and submit
> separately.

Thanks for the information. I finally got a machine to reproduce the
issue and testing the patches. It's weird it firstly can't be reproduced
in the latest 6.17.0-rc5+, not sure if I made anything wrong on steps.
Later, I started it over and can stably reproduce the problem, I can
confirm Maciej's two patches can fix the problem very well.

Will reply to Maciej's patches to add my Tested-by.

Thanks
Baoquan

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/a=
MUo5rXaXOU2nNh4%40MiWiFi-R3L-srv.
