Return-Path: <kasan-dev+bncBDW2JDUY5AORBAOBSGQQMGQECCQ6QJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3e.google.com (mail-io1-xd3e.google.com [IPv6:2607:f8b0:4864:20::d3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 84F8A6CEE44
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 18:00:02 +0200 (CEST)
Received: by mail-io1-xd3e.google.com with SMTP id i2-20020a5d9e42000000b0074cfcc4ed07sf10108933ioi.22
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 09:00:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680105601; cv=pass;
        d=google.com; s=arc-20160816;
        b=0Wge7K7NCGHQoAFBm6/RaoihTT+c4Q3Q04ub3C6Dti5rdhCdedscF2i5Q4iy9Zsg6m
         eFlh3Gh2/EVWZi0DVjyTSsB6JgvEH+erawG2PUlcKJmU4PQh+agX8bOEuclSqL9Y9wxV
         cjJpMKtiUUO7Ybe0jHngFyM4iHrNPz0FpSwuesijv66wi2oGe9r8kzcGskVe5mUhkbSh
         WoW6JVoC3GMqctpunlSrHCStmAzuGnXPaXacBt6kOr+I1VkAlCh9DxxQR2tKcFrqDADH
         ImxcpVt+KQ/3rXmB/jrNnoCAoFY1hzR5Zd2f/zC/0fmTNnmgIdWaybpYU1r7jVkKOUzm
         loPQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=WjpzNpj+xmyrQKqkakl/YvPAAdwMtZQIzF0v+ehGKmY=;
        b=W4xfQ/HAEyE/FLUWG8FpfXzI9zBHEqGilZy7q9UaCZocDWE3fNNaq8u6wEU7SlCkpr
         MTwSM+2B93OwnFdWQ6kt6hlBSAOk03ZCREffa4JjJnHGHPp3G0bAirZhHGaN3CXT8fUA
         ny71OAhAV53To1tQOS2SY2JFGWliAclznL74j46I9Cxl2eeUrbSI+7FRyU2zfE1EfWbs
         QgNPT1ymK6yHHHX+ZGUqzVHhyaosBZriAsdofEJx9qkif0gLpR/4zbmEu6TuVMZ27ZyX
         5VJsflNdxGDi18wcfhSqKNsTLdATj2yXZ9fQDzywvBZuX0kZoriJIi4ecZjW5MpkWItb
         4yfA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IoeJ2hRh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680105601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WjpzNpj+xmyrQKqkakl/YvPAAdwMtZQIzF0v+ehGKmY=;
        b=d09KPxDKW8WvQRWI2UPptcST/0XUzB2fFx+BSSOfEjxjfPqYEOlxEjueOEGfX1JEMr
         LvCWbHdV+ts32/cOwCrH2PLfUjP75wI2elZwuEPTVbj4beaBgZSdAApDu7azAxGRg9gv
         lMYPW8qZg3xJ0RNF1WoMqQdm0Zybkfzgnq1aTWg1MsNPpdC3exTrebH+SRU8WtXL/VA7
         aR9GMOmGC/j9MFbOFdccqOGNUQFohjXslwcqT4eZNvNC/vW2E8vk8at9Lgwsqu3n5dCl
         QJ6sA1RxwlM+8zx9tpi1A0AroXH+WkwBsBoSYUO26RqYluShQ3awfBl/DHDFYfXdfH+v
         pZcQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112; t=1680105601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WjpzNpj+xmyrQKqkakl/YvPAAdwMtZQIzF0v+ehGKmY=;
        b=BZ1TGOea9WpbSZWW47PiasBRD8H+D7ZRJUSxDxSwa3N+y/xuc691IfgRffv3PBcbUt
         6zUZFabAWKzsA3IixkW3y9+nS8Yx8UC88BeaH0+ba1TKW48j7sOckMIVqX5LojWP9ViT
         PnV0dOp+c3afKSJEXknT2/54a+SepfNfwtkO8TO0X3SN0z8AH1MsgBOZ4eqPqPGFw6mJ
         Ry5FfgudpaCiTUmWGArOGXHcqUkQRKG6xZ31YdeBVnUyjPlqju3h74plJb0vE1d/jgw3
         AA+nmQ893GNcp5oesCiDSw9YBAuu6CxyT7lB67m0n3JwvhVZkS+sXVdUpWtYw6ZZOhSH
         Y6XA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680105601;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=WjpzNpj+xmyrQKqkakl/YvPAAdwMtZQIzF0v+ehGKmY=;
        b=h5M/lLkTh/ZXmgH6b5EiSYD11vPVhkklsvufhI+MvAgowcOdl7WkvVKjn+DDT3lUk8
         IA3KsfHWNC326lFm5oS09Y8xKx3IzM3WlPLR2MpJ4HjJsJSRvg2HVRcypkC75WFZczUa
         MHUTuR4F/bFiucr54Mv8ahmdwNK+VOqyNjuJ2jFHAhIt2EDhta7VMKvtZ/fzitgK0e2D
         3+v9sU8mGF0CUkbpzSiimXg7d7lmtYXwr0KX4eBQTGJR7ixQNKaFFe0BHY/MSMa9uUFl
         JeQk321P07jmqBR3MwCOXJV9Ouepj6bo6V0oWcnIv4J6bo8BjnupCMMsj9AXJRpCczsS
         2Y5w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKU5tnrAEovMlW438gBRB5qXHPsgR+tCtuR1fxCXHpoipbO9LQHD
	wPfVhM+GDJ8FDSyZ+Gnu4/U=
X-Google-Smtp-Source: AK7set8CdHgLvXLU3LUoQ/FNX+06GKXeYmQwYLw8GOpZFFohRDFILiMRV3iiszrvV0VltWIfZaZM2g==
X-Received: by 2002:a02:95c3:0:b0:406:2cd0:a668 with SMTP id b61-20020a0295c3000000b004062cd0a668mr8231948jai.2.1680105601109;
        Wed, 29 Mar 2023 09:00:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:15c2:b0:317:9a9f:53a5 with SMTP id
 q2-20020a056e0215c200b003179a9f53a5ls4505058ilu.8.-pod-prod-gmail; Wed, 29
 Mar 2023 09:00:00 -0700 (PDT)
X-Received: by 2002:a92:dc91:0:b0:325:c8ee:96e2 with SMTP id c17-20020a92dc91000000b00325c8ee96e2mr14240933iln.7.1680105600608;
        Wed, 29 Mar 2023 09:00:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680105600; cv=none;
        d=google.com; s=arc-20160816;
        b=c55qFArgOmkMOvDyy5Y7qca6dybTK0UVDEPjp6/02wQrNWd3Dy4wdm9YagEyqmwyLF
         9brazl2sGe18HTU1OZmNArjgZZ4wKscTIlE1wyLbniLtlpdiH55RY0vMHVmUqDNXZ8DP
         q1xeA6cwQYiuOdLnYRY0LW1oOntVA1/yZ1JAFKF/h/z8tgqqt5FNS10Jt69WjjmcCSTD
         lLVZCZHSpjlxqxCQG2kZi8rCFSQ3qKzbbd8yAlk1fs45gBdkg1Z7O2QYb/AY5HFyQ9rU
         vuunuIGVR3nViIcs9DeKv/vvTA3bwtg5eqZkxjzShAx0K64IAkGul4B0purdgHy41CfG
         UlkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=w4mfqXcQDMgEMpQCXMX8Y+2J6yDMso+bxawxRo1V7AM=;
        b=o+oMA67riGiD8HGYfDx4Aa4+fhi3fCC4thxlKAxCwfMakzOLrAZ1JcBrMEZPQ2yC1O
         ow3uqc+ohMdxBMeJcPIwCZhrgmU7DM2V0EY0rxs+PoA70xejZdnfbXI7MJrmx2gQ6QvY
         /XdlbeECQcM4THNS2C93zSQ6/QqDA0W8sDlRHe8RfnhrEXPjip3jtVcTqi6V3+y7BN8e
         lZpicsCRgCzHJU+EvZvrCttub1hj793dhRl+I90qOGG4v+HX2LGSb6Ia0wR9S/KGj3BA
         EYcBOraQ43tmDpgwrgVYKHvqIhsW+2+LEyV3IjnYnfpQddOQLPbLw9gn9/jGCP8e9njj
         uo8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=IoeJ2hRh;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id s12-20020a056638218c00b00409125e3b19si800898jaj.2.2023.03.29.09.00.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Mar 2023 09:00:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id cm5so4762761pfb.0
        for <kasan-dev@googlegroups.com>; Wed, 29 Mar 2023 09:00:00 -0700 (PDT)
X-Received: by 2002:a05:6a00:1a8b:b0:627:d4fa:6a9c with SMTP id
 e11-20020a056a001a8b00b00627d4fa6a9cmr10678222pfv.6.1680105599791; Wed, 29
 Mar 2023 08:59:59 -0700 (PDT)
MIME-Version: 1.0
References: <5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com>
In-Reply-To: <5050805753ac469e8d727c797c2218a9d780d434.camel@mediatek.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 29 Mar 2023 17:59:48 +0200
Message-ID: <CA+fCnZfVs44zQs1Sg_MXvyGcTHc=aNhx+5R+ku8Nh3yDBb45qg@mail.gmail.com>
Subject: Re: [BUG] Usersapce MTE error with allocation tag 0 when low on memory
To: Peter Collingbourne <pcc@google.com>
Cc: "linux-arm-kernel@lists.infradead.org" <linux-arm-kernel@lists.infradead.org>, 
	"linux-mm@kvack.org" <linux-mm@kvack.org>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>, "surenb@google.com" <surenb@google.com>, 
	"david@redhat.com" <david@redhat.com>, =?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	=?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?= <casper.li@mediatek.com>, 
	"catalin.marinas@arm.com" <catalin.marinas@arm.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <qun-wei.lin@mediatek.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=IoeJ2hRh;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Wed, Mar 29, 2023 at 4:56=E2=80=AFAM 'Qun-wei Lin (=E6=9E=97=E7=BE=A4=E5=
=B4=B4)' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> Hi,
>
> We meet the mass MTE errors happened in Android T with kernel-6.1.
>
> When the system is under memory pressure, the MTE often triggers some
> error reporting in userspace.
>
> Like the tombstone below, there are many reports with the acllocation
> tags of 0:
>
> Build fingerprint:
> 'alps/vext_k6897v1_64/k6897v1_64:13/TP1A.220624.014/mp2ofp23:userdebug/
> dev-keys'
> Revision: '0'
> ABI: 'arm64'
> Timestamp: 2023-03-14 06:39:40.344251744+0800
> Process uptime: 0s
> Cmdline: /vendor/bin/hw/camerahalserver
> pid: 988, tid: 1395, name: binder:988_3  >>>
> /vendor/bin/hw/camerahalserver <<<
> uid: 1047
> tagged_addr_ctrl: 000000000007fff3 (PR_TAGGED_ADDR_ENABLE,
> PR_MTE_TCF_SYNC, mask 0xfffe)
> signal 11 (SIGSEGV), code 9 (SEGV_MTESERR), fault addr
> 0x0d000075f1d8d7f0
>     x0  00000075018d3fb0  x1  00000000c0306201  x2  00000075018d3ae8  x
> 3  000000000000720c
>     x4  0000000000000000  x5  0000000000000000  x6  00000642000004fe  x
> 7  0000054600000630
>     x8  00000000fffffff2  x9  b34a1094e7e33c3f  x10
> 00000075018d3a80  x11 00000075018d3a50
>     x12 ffffff80ffffffd0  x13 0000061e0000072c  x14
> 0000000000000004  x15 0000000000000000
>     x16 00000077f2dfcd78  x17 00000077da3a8ff0  x18
> 00000075011bc000  x19 0d000075f1d8d898
>     x20 0d000075f1d8d7f0  x21 0d000075f1d8d910  x22
> 0000000000000000  x23 00000000fffffff7
>     x24 00000075018d4000  x25 0000000000000000  x26
> 00000075018d3ff8  x27 00000000000fc000
>     x28 00000000000fe000  x29 00000075018d3b20
>     lr  00000077f2d9f164  sp  00000075018d3ad0  pc  00000077f2d9f134  p
> st 0000000080001000
>
> backtrace:
>       #00 pc 000000000005d134  /system/lib64/libbinder.so
> (android::IPCThreadState::talkWithDriver(bool)+244) (BuildId:
> 8b5612259e4a42521c430456ec5939c7)
>       #01 pc 000000000005d448  /system/lib64/libbinder.so
> (android::IPCThreadState::getAndExecuteCommand()+24) (BuildId:
> 8b5612259e4a42521c430456ec5939c7)
>       #02 pc 000000000005dd64  /system/lib64/libbinder.so
> (android::IPCThreadState::joinThreadPool(bool)+68) (BuildId:
> 8b5612259e4a42521c430456ec5939c7)
>       #03 pc 000000000008dba8  /system/lib64/libbinder.so
> (android::PoolThread::threadLoop()+24) (BuildId:
> 8b5612259e4a42521c430456ec5939c7)
>       #04 pc 0000000000013440  /system/lib64/libutils.so
> (android::Thread::_threadLoop(void*)+416) (BuildId:
> 10aac5d4a671e4110bc00c9b69d83d8a)
>       #05 pc
> 00000000000c14cc  /apex/com.android.runtime/lib64/bionic/libc.so
> (__pthread_start(void*)+204) (BuildId:
> 718ecc04753b519b0f6289a7a2fcf117)
>       #06 pc
> 0000000000054930  /apex/com.android.runtime/lib64/bionic/libc.so
> (__start_thread+64) (BuildId: 718ecc04753b519b0f6289a7a2fcf117)
>
> Memory tags around the fault address (0xd000075f1d8d7f0), one tag per
> 16 bytes:
>       0x75f1d8cf00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d000: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d100: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d200: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d300: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d400: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d500: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d600: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>     =3D>0x75f1d8d700: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0 [0]
>       0x75f1d8d800: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8d900: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8da00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8db00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8dc00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8dd00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>       0x75f1d8de00: 0  0  0  0  0  0  0  0  0  0  0  0  0  0  0  0
>
> Also happens in coredump.
>
> This problem only occurs when ZRAM is enabled, so we think there are
> some issues regarding swap in/out.
>
> Having compared the differences between Kernel-5.15 and Kernel-6.1,
> We found the order of swap_free() and set_pte_at() is changed in
> do_swap_page().
>
> When fault in, do_swap_page() will call swap_free() first:
> do_swap_page() -> swap_free() -> __swap_entry_free() ->
> free_swap_slot() -> swapcache_free_entries() -> swap_entry_free() ->
> swap_range_free() -> arch_swap_invalidate_page() ->
> mte_invalidate_tags_area() ->  mte_invalidate_tags() -> xa_erase()
>
> and then call set_pte_at():
> do_swap_page() -> set_pte_at() -> __set_pte_at() -> mte_sync_tags() ->
> mte_sync_page_tags() -> mte_restore_tags() -> xa_load()
>
> This means that the swap slot is invalidated before pte mapping, and
> this will cause the mte tag in XArray to be released before tag
> restore.
>
> After I moved swap_free() to the next line of set_pte_at(), the problem
> is disappeared.
>
> We suspect that the following patches, which have changed the order, do
> not consider the mte tag restoring in page fault flow:
> https://lore.kernel.org/all/20220131162940.210846-5-david@redhat.com/
>
> Any suggestion is appreciated.
>
> Thank you.

+Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZfVs44zQs1Sg_MXvyGcTHc%3DaNhx%2B5R%2Bku8Nh3yDBb45qg%40mai=
l.gmail.com.
