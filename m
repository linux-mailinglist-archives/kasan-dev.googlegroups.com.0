Return-Path: <kasan-dev+bncBCSL7B6LWYHBBS7PYO6AMGQEM5POMWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53e.google.com (mail-ed1-x53e.google.com [IPv6:2a00:1450:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 049B0A192F2
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2025 14:51:10 +0100 (CET)
Received: by mail-ed1-x53e.google.com with SMTP id 4fb4d7f45d1cf-5dbaaed8aeesf5113496a12.1
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Jan 2025 05:51:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1737553869; cv=pass;
        d=google.com; s=arc-20240605;
        b=lfq8rGsOhFAwZNTsoi6Ih2OT5vph4yDOXuPXDl/tYPTNHyAXfLccUvKj/ZH8o2y8aL
         Jbxa8G3/cICqrsfaaKaL9EDK4xaMeD1WpoiU9Zql4ydJ+ix9G1BVjrYedFjFG2oWx0qf
         THotxJD18hEV8AVLt5z5/2c46hUP9ukQ7XrWxU3f77kdTDiwQzFgbryc5RzM0iYvbYtm
         jPv3cSUOYoq8o9ZOIiYpgKJBQSJlul7V06hIFEsKVyUkYLIsEO/Oms5agjlKYGBSBdBA
         H+JFErJAlZSEpEra7J3ok8DV9NBy5nU0j9Rs6hz8jShpmY1br9gXGm6e2GigE31FgP1d
         5lUA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=hCVdhUs9RJeO3LrdwPXuER619hHb4Aw8pvgc9sHmzz4=;
        fh=QzWS7fTack3IIVj3UaoM1cxv89jyRokK3Emt5gQS73c=;
        b=J2+K9IkLSInjMVpMyaf5x6M+oBVipTxSuDnzlNNA/Zrge2+mhl8f0TRDgKycxpolti
         Oe+VL0M8lQDKXT0pDiw04gBWxcVBLVcckq99o11DoY44OsHoEzuZ9JbHDQbonCH5jbj5
         da7KuX3sTZVTzYPI9E+adQ+vRJoduaUTIYfoXRGhRyF3JusNY6fydSs4LIki1Tj7J4CN
         Kp8p0X3QOM5wgZfM8/5JMWk4BlR2qQ2RzD9sxIfQLYc56veHPtn9MaH7E23/AiSfpK+E
         xu5Xx2fWfciA8sGuhyu+yZ9L+EVN2gEOrReRB1vcRrdIkAAx8oS7y95WTPKadPPNEPyh
         fcVQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gjMDs9G5;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1737553869; x=1738158669; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=hCVdhUs9RJeO3LrdwPXuER619hHb4Aw8pvgc9sHmzz4=;
        b=nNb0QJLzpabnQQfUxQepllLw+jpHT9k4X/yBYXBj91uMkksE3wBXv5/ZcDAyLELSTJ
         q0puBUZOfHDQ1tfVFgZ/fIxE7AqxDyUnQ6xX3+0rWVsQXC3ccpUveyXUKRd5J5iopZbE
         lpOxwv1iubur6Gtsv0i9pdqjEV8IyXycFipIjo8IJKLjqFAKZMJ3DgCF6pHvNSsOvfP/
         5xu7vxloDPe49qDOM1SCir80LTalTsCU1gxJ2Tmhp7Dxawtc0CWRPM9H5vHkj5EN6pIO
         UJOGTTSw+gtR7JhvSm5FnGstMlkOtxJCkhQKImtNLzbl0vS7f9BNYtAyoCtk6VvpCLh1
         gmHg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1737553869; x=1738158669; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=hCVdhUs9RJeO3LrdwPXuER619hHb4Aw8pvgc9sHmzz4=;
        b=K1VBv3kgDBuFSpRcBa5reft7B5bpVY/l1rNsC0UD9U5rmNazVu+JAGitQGNsdwasPW
         ZROdn5aEVEifwpSTRx5qkGA0kLgTnQ5BaLuYZRlEkA7E3Fi/E6QUiAagLPtiE2mVaw3R
         ffRHDLydzh7f7uPUNT7FBd1ghxDMpnf8MruVbfLx/pDNldzGRVTpwVrjnZR62wDROgfN
         agww7K2JPN3NUMlFc+KAPPyewA23aVkOWPhahHIA3i6eyN7Dxy44uOUFUMgsBrTl5YqP
         zyUlJMsfLYEFpQf3tF9huvkkMpRJiskV70QqYdbgZkIElXT1ZAfgvCeP4F5HgkmK18Rr
         fBbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1737553869; x=1738158669;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=hCVdhUs9RJeO3LrdwPXuER619hHb4Aw8pvgc9sHmzz4=;
        b=nkdJpM2DVBrcQzlmYSM4LRSyeMmZrHaJWKRNTMoaMTJYwfurZ4ePyScP/luVU+aRz5
         T8zb5oz4STLg+g5c6ZqmCFu3GJjkB68L0Ne22olul94zIPK04FoAdWh3JcDDe5Gj/Bn5
         YfL9A3vIbf8BQ/8169a+N1Wu9XFFfrvUwe0tmKJGGCRTib95Noa8S5M1JEuJ6Jrb9NdC
         sqx4p2qdrtuU7+ztzWRDTN5KSNrlhmIA7Zg8ceganofQil0TJ+fokOPlMTN0G5LJtoSX
         WBjV8U7TS95LDAHbGjrjVczuUGLP4uaxFmh1eoCZ/KNdr1PxBgqgVvOAp0To1XeFAgAD
         jLaw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWGDIyk2uQ9vBprakPvLX5tKtHa6+NYt783WgW+AIbcRdO9ANPHw61lmb1TSAb6mGi8jatsCA==@lfdr.de
X-Gm-Message-State: AOJu0YwfROSXaJ1+UQ5nQSgQF3eS13KE/DSSOjiglz+RljANTF+ng3c1
	13mXhVb0JmmI/9Zvzgg0yN7A83FtdN1Yg/P687F2YT9ZFMxpWvYY
X-Google-Smtp-Source: AGHT+IGbU8hgouU3VKvOHpPZzBQITG4CUxMnpgfiyOEq3YfUy1HopiJVa/izuFglzgyeSyku00Emyw==
X-Received: by 2002:a05:6402:2110:b0:5da:c38:b1cf with SMTP id 4fb4d7f45d1cf-5db7d2dc135mr20256176a12.3.1737553868069;
        Wed, 22 Jan 2025 05:51:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:9ea8:0:b0:5d3:e99c:a4c8 with SMTP id 4fb4d7f45d1cf-5dbe09b1e77ls65836a12.2.-pod-prod-03-eu;
 Wed, 22 Jan 2025 05:51:05 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVFT6+CjnbMLloSyC/DFdWMqwCRZggzi9vGBQFjRS9gUke2sYohGMKjU4EPjWCxUG1ZIzMcOzGaQUI=@googlegroups.com
X-Received: by 2002:a05:6402:40cd:b0:5d4:5e4:1555 with SMTP id 4fb4d7f45d1cf-5db7d300482mr19117731a12.19.1737553865480;
        Wed, 22 Jan 2025 05:51:05 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1737553865; cv=none;
        d=google.com; s=arc-20240605;
        b=IR/mYoS4aaWrdg+z8TAwIn1DgMbIesBeBCIw2jP2noVzNKr3DkjunQ8XEGCb0kL+Uf
         Kd10BlMXfv0i4TfLbTe/5bQ2sV2S2XqGfrPI0ybkfh/hzcVzGTWwfe2o5PsffnqPnSJd
         D33bo3VhlaHCu1kM798nJQhhFAbb036OighMA+CjeSygv7pF+yfEtep9CuM66heyP8y4
         4QeIblY4ETt5et31QoQWtbkZeeaEzjGB19uh7VRRGIhfmFgchhaN5QNoeXI0ESe8CUSW
         7qG8jV3Y90RVLqcOAfJl4mnuSSoiCbIpLkzdy+cKjbnwQQLWsFYNftRyMF/Q0mF49s4F
         hIIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=zVX2FJ2hCr5swG6CFbz13/hPQt22h2FbZGX8nYTRstg=;
        fh=yBUH7F/agBaP5JRIbVomCHVksWyUIpJl66JALe7Scz0=;
        b=j8VQ+6ST1SMc7giZ5fmmSjOmigIhYhEloR3K0sycpp43iBnvEOIqiubqq1XOi8aC4D
         MGE6VNvGA6+fTaEkkyy0odV079l2/+k04Jpk7jCrh9VspxAziW3/CJAzkxx6f0213CiX
         jiPpJrPzsVru1E21VpO6rq7pWfiT08lmYJgdC5GURNWKUq+B7aGaNxNymawhfLVGo96W
         qGtI9IVtq/FdQy9PSHSbZKJ2vETU8WGy+FzVcUDQMh61Z/Itfnm1KG6ykBmWoWmweWfS
         WbiGupnDPwszodArDkOmmEYUQu73zryYbGoSL5iJr/pzU5xvH3wPkVxdbVyqZ4/fFoBp
         O/rg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=gjMDs9G5;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42c.google.com (mail-wr1-x42c.google.com. [2a00:1450:4864:20::42c])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5db73e9d349si198962a12.3.2025.01.22.05.51.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Jan 2025 05:51:05 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::42c as permitted sender) client-ip=2a00:1450:4864:20::42c;
Received: by mail-wr1-x42c.google.com with SMTP id ffacd0b85a97d-385d851e7c3so350868f8f.3
        for <kasan-dev@googlegroups.com>; Wed, 22 Jan 2025 05:51:05 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCUmYHMM7/JryYCSZNF1B3MKe6p82Lm/AnQ9Sz1B31AtvdWplepv05t7qpv6tUBGkimDn4g3ehZtmfk=@googlegroups.com
X-Gm-Gg: ASbGncs4m8cS6wuLvsj/MfJY4pm5vNThGsDQGdN6lfoxbHhQErUos7zQpZWuy3YJUPL
	QUIQ7jiWvxmFgWdguff1VAWPB7tvWlCe08fvEv4mcwafdY5TwLxQZDZI78Jxy9TQa0G9G0qedMH
	dbMuQaXT4gDYea/3DD
X-Received: by 2002:a5d:47c5:0:b0:38a:8784:9137 with SMTP id
 ffacd0b85a97d-38bf57a8f56mr7575141f8f.9.1737553864742; Wed, 22 Jan 2025
 05:51:04 -0800 (PST)
MIME-Version: 1.0
References: <ec2a6ca08c614c10853fbb1270296ac4@huawei.com> <98125b67-7b63-427f-b822-a12779d50a13@kernel.dk>
 <c14929fc328f43baa7ac2ad8f85a8f2b@huawei.com>
In-Reply-To: <c14929fc328f43baa7ac2ad8f85a8f2b@huawei.com>
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
Date: Wed, 22 Jan 2025 14:49:51 +0100
X-Gm-Features: AWEUYZmZpJb_nJXGrc0VFB4A-A68-6fMudm0dEEboziQ_Zudc-pl8fDXoa4w9hg
Message-ID: <CAPAsAGwzBeGXbVtWtZKhbUDbD4b4PtgAS9MJYU2kkiNHgyKpfQ@mail.gmail.com>
Subject: Re: KASAN reported an error while executing accept-reust.t testcase
To: lizetao <lizetao1@huawei.com>
Cc: Jens Axboe <axboe@kernel.dk>, io-uring <io-uring@vger.kernel.org>, 
	Pavel Begunkov <asml.silence@gmail.com>, 
	"juntong.deng@outlook.com" <juntong.deng@outlook.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, Andrey Konovalov <andreyknvl@gmail.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=gjMDs9G5;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::42c
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
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

On Sun, Jan 12, 2025 at 7:45=E2=80=AFAM lizetao <lizetao1@huawei.com> wrote=
:
>
> Hi,
>
> > -----Original Message-----
> > From: Jens Axboe <axboe@kernel.dk>
> > Sent: Sunday, January 12, 2025 1:13 AM
> > To: lizetao <lizetao1@huawei.com>; io-uring <io-uring@vger.kernel.org>
> > Cc: Pavel Begunkov <asml.silence@gmail.com>
> > Subject: Re: KASAN reported an error while executing accept-reust.t tes=
tcase
> >
> > On 1/11/25 7:07 AM, lizetao wrote:
> > > Hi all,
> > >
> > > When I run the testcase liburing/accept-reust.t with CONFIG_KASAN=3Dy
> > > and CONFIG_KASAN_EXTRA_INFO=3Dy, I got a error reported by KASAN:
> >
> > Looks more like you get KASAN crashing...
> >
> > > Unable to handle kernel paging request at virtual address
> > > 00000c6455008008 Mem abort info:
> > >   ESR =3D 0x0000000096000004
> > >   EC =3D 0x25: DABT (current EL), IL =3D 32 bits
> > >   SET =3D 0, FnV =3D 0
> > >   EA =3D 0, S1PTW =3D 0
> > >   FSC =3D 0x04: level 0 translation fault Data abort info:
> > >   ISV =3D 0, ISS =3D 0x00000004, ISS2 =3D 0x00000000
> > >   CM =3D 0, WnR =3D 0, TnD =3D 0, TagAccess =3D 0
> > >   GCS =3D 0, Overlay =3D 0, DirtyBit =3D 0, Xs =3D 0 user pgtable: 4k=
 pages,
> > > 48-bit VAs, pgdp=3D00000001104c5000 [00000c6455008008]
> > > pgd=3D0000000000000000, p4d=3D0000000000000000 Internal error: Oops:
> > > 0000000096000004 [#1] PREEMPT SMP Modules linked in:
> > > CPU: 6 UID: 0 PID: 352 Comm: kworker/u128:5 Not tainted
> > > 6.13.0-rc6-g0a2cb793507d #5 Hardware name: linux,dummy-virt (DT)
> > > Workqueue: iou_exit io_ring_exit_work
> > > pstate: 10000005 (nzcV daif -PAN -UAO -TCO -DIT -SSBS BTYPE=3D--) pc =
:
> > > __kasan_mempool_unpoison_object+0x38/0x170
> > > lr : io_netmsg_cache_free+0x8c/0x180
> > > sp : ffff800083297a90
> > > x29: ffff800083297a90 x28: ffffd4d7f67e88e4 x27: 0000000000000003
> > > x26: 1fffe5958011502e x25: ffff2cabff976c18 x24: 1fffe5957ff2ed83
> > > x23: ffff2cabff976c10 x22: 00000c6455008000 x21: 0002992540200001
> > > x20: 0000000000000000 x19: 00000c6455008000 x18: 00000000489683f8
> > > x17: ffffd4d7f68006ac x16: ffffd4d7f67eb3e0 x15: ffffd4d7f67e88e4
> > > x14: ffffd4d7f766deac x13: ffffd4d7f6619030 x12: ffff7a9b012e3e26
> > > x11: 1ffffa9b012e3e25 x10: ffff7a9b012e3e25 x9 : ffffd4d7f766debc
> > > x8 : ffffd4d80971f128 x7 : 0000000000000001 x6 : 00008564fed1c1db
> > > x5 : ffffd4d80971f128 x4 : ffff7a9b012e3e26 x3 : ffff2cabff976c00
> > > x2 : ffffc1ffc0000000 x1 : 0000000000000000 x0 : 0002992540200001 Cal=
l
> > > trace:
> > >  __kasan_mempool_unpoison_object+0x38/0x170 (P)
> > >  io_netmsg_cache_free+0x8c/0x180
> > >  io_ring_exit_work+0xd4c/0x13a0
> > >  process_one_work+0x52c/0x1000
> > >  worker_thread+0x830/0xdc0
> > >  kthread+0x2bc/0x348
> > >  ret_from_fork+0x10/0x20
> > > Code: aa0003f5 aa0103f4 8b131853 aa1303f6 (f9400662) ---[ end trace
> > > 0000000000000000 ]---
> > >
> > >
> > > I preliminary analyzed the accept and connect code logic. In the
> > > accept-reuse.t testcase, kmsg->free_iov is not used, so when calling
> > > io_netmsg_cache_free(), the
> > > kasan_mempool_unpoison_object(kmsg->free_iov...) path should not be
> > > executed.
> > >
> > >
> > > I used the hardware watchpoint to capture the first scene of modifyin=
g kmsg-
> > >free_iov:
> > >
> > > Thread 3 hit Hardware watchpoint 7: *0xffff0000ebfc5410 Old value =3D=
 0
> > > New value =3D -211812350 kasan_set_track (stack=3D<optimized out>,
> > > track=3D<optimized out>) at ./arch/arm64/include/asm/current.h:21
> > > 21          return (struct task_struct *)sp_el0;
> > >
> > > # bt
> > > kasan_set_track
> > > kasan_save_track
> > > kasan_save_free_info
> > > poison_slab_object
> > > __kasan_mempool_poison_object
> > > kasan_mempool_poison_object
> > > io_alloc_cache_put
> > > io_netmsg_recycle
> > > io_req_msg_cleanup
> > > io_connect
> > > io_issue_sqe
> > > io_queue_sqe
> > > io_req_task_submit
> > > ...
> > >
> > >
> > > It's a bit strange. It was modified by KASAN. I can't understand this=
.
> > > Maybe I missed something? Please let me know. Thanks.
> >
> > Looks like KASAN with the extra info ends up writing to io_async_msghdr=
-
> > >free_iov somehow. No idea... For the test case in question, ->free_iov=
 should
> > be NULL when initially allocated, and the io_uring code isn't storing t=
o it. Yet
> > it's non-NULL when you later go and free it, after calling
> > kasan_mempool_poison_object().
>
> I also think so and would Juntong and Ryabinin or others KASAN developers=
 be interested
> In this problem?
>

Hi, thanks for reporting.
KASAN stores some info about freed slab object in the object itself
until it is reallocated or the slab page is released.
And since the  b556a462eb8d ("kasan: save free stack traces for slab
mempools") we do the same thing in kasan_mempool_poison_object().
In the most use cases this wasn't the problem, because callers expect
uninitialized objects from mempool.

However, this isn't the case for io_alloc_cache. AFAICS io_uring code
expects that io_alloc_cache_put/get leaves objects unmodified.
So I'm thinking we'd need to add some parameter to the
kasan_mempool_poison_object() to avoid modifying objects.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
APAsAGwzBeGXbVtWtZKhbUDbD4b4PtgAS9MJYU2kkiNHgyKpfQ%40mail.gmail.com.
