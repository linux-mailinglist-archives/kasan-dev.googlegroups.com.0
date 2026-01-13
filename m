Return-Path: <kasan-dev+bncBCSL7B6LWYHBB5FGTPFQMGQE7UOI6EI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13a.google.com (mail-yx1-xb13a.google.com [IPv6:2607:f8b0:4864:20::b13a])
	by mail.lfdr.de (Postfix) with ESMTPS id AFD39D1BAFC
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Jan 2026 00:21:26 +0100 (CET)
Received: by mail-yx1-xb13a.google.com with SMTP id 956f58d0204a3-63e32e1737asf12202481d50.0
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 15:21:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768346485; cv=pass;
        d=google.com; s=arc-20240605;
        b=EutMvzqYsvCyhh9deV8HB2oiY0zDV1rKBDaVQXfO0R2HcKs5QtvaQ0/qGn9EDievYH
         5KdNnDGdUpwi7lmYOy06VtudSPwtdeqbzT/8SdFxpG1Re0UUfrqRrEwQa3XxKhy+M+MW
         /cWCWu8Ad/CddkwAo5m7EKJBcyFoZHYwNrVF62+aa3rx1reiyYLeed9/1g4SXe8BOsVg
         OEvJUW+BoQ5344WO+bmpmKx03TCNq1nQ8EKBwrGllC/er5/3EdzgkH3bulUvf+0folCY
         RbpEjOmKafrkrkFD26EXQfyvfqrFK9GpfIAf0RHhV1ZZ6obJeaSkiUvf7NReiUrfMG9L
         tq8Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=Zjes7/QVax0VGuGn/wWD5WjulMhkANmtRbFPrF14Otk=;
        fh=LnOU8G519rEhqm49ujEuUFob9vPEuUbaXD5AhT1GPAs=;
        b=HqVdjwhvNOpfYpJHjxsQtf5xjokUnRgfVFYm7YyRqDhC9CrRqaqnvHbLI6PvgGICWu
         jt/CcDgnb9xXXftT2ibJtuoijSf2S0xYTZp6uM1PR/ILwcm5NBdMkD3MxTwAI61Ac8NJ
         VbL2E73tY3+nYsIxiFOBQl8w5481UJ7CSmE5ejTZSc0lJ4ZfOz2Vg814qsLabRpVkF2c
         bNHdG6MmdCXkvBjtJAYOF70YggnJ88OooEHZcajrFvrfFuYRRb+MokW4eNspqIyW1E4V
         a8EK6BpV3fRi1gqqayS3w7oDpq0sx5yoHR0wo/joK/svszZYwxxE5UARK7Zb5keMIh/U
         18BA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Thwq/GsY";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768346485; x=1768951285; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Zjes7/QVax0VGuGn/wWD5WjulMhkANmtRbFPrF14Otk=;
        b=SrRzhe4Ca3gjMnqP/ZddLIke2QacjyQyaGYtDL0oLKh3B7pfuXpuGx5q396Ywu7ifd
         YTCAsd5oYY8Z80q+qMG7/piwSNvbYX7Hm0PBqkobVy2IxKl8k6G3CVqk0E6ZKXUIaKjr
         sb+c6auorofhj4vi+zvPrm1kDZxGOCzAq3tnDl8J/5lAGkRef3DubKTOl2LHXvJ5wIYd
         9YTW8v6Wdq+RYklZqiDUmIo/Hika8eKXHERRAeJGC1KGc745fCfv8sFVYwvpF062NOmF
         o7r8a5kfwM2t37qbSbEpmbV3ENm/gdPoQK0aVFjB1ptB4/54OM8azw1e1pjyJqcGaDSD
         uvNw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768346485; x=1768951285; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Zjes7/QVax0VGuGn/wWD5WjulMhkANmtRbFPrF14Otk=;
        b=I8cqwP9Wbc1QSRrEztCJCqV3VtbvOwAJBpV4zrZbIEFS+knC3RkmWyTXKIMxmTv8cb
         dtHuYToOncvelZU2YLwcEG3lvIZKmPcxWYoZs2f8pAVQlGDSbC/EAuxNIgAPXEiOSFfQ
         QOKxKaM3H5WReZL0Aij1EhxtIjE2Z32gnj6Fg6MWMlho7oPq+5jDiBMDDjtE5a2b4mM2
         xj3JbkP6lVEkvD2q2KyCpoKorYutMWCgkltdZPMwaNaWX2Mgovzrh2aYxdXiewcbDKb8
         fNXo9quywmPHicn6Qx8KhpgZyT30CPUgv3cGc8AVcGTlzhETG7k9jH+3a4rSLxc0+GI9
         Rv4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768346485; x=1768951285;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-gm-gg:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Zjes7/QVax0VGuGn/wWD5WjulMhkANmtRbFPrF14Otk=;
        b=k5b4Im9X0mkuSoJsoxWwnM9eu+CWhx61tLKgNKamGewpQ1m44/EmqnJLgSFw3LQlDz
         zR6juwGpXWmsiQu6avTr6ODXIt3jmBwgtiD8eS53HXGueDVpMoFBKca4Rb5rHuCsglDh
         9aKrDFQyv46wlwHix29n0NaPjSQlxXjoNNxd6SFOBvnN5X5gQpdoihMPB3FwCDcHXn3m
         rh7WzU8ZyiqtNPYHRPUn6ymUfskl+BOdM9XLc6PenyNRGeJTUDHoHZwDo7B5WNLfpyVh
         kqvQjSKX6nH+9RfNJhZ4ZdWlR71ahcORebAK19nyLKjI+a4fBWfXisK6NsKxDpWFTblQ
         h7jg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUyIAtV8f/1irFqOUMU3ta0qg6QkGu+w7YZfnwbO7VawdvGRGKovEwhatcXDLsqzxfIi9ssww==@lfdr.de
X-Gm-Message-State: AOJu0YysdWIBht9zXvi4WK6518RH0+s+h+4qMKgUBXiFONC/5M64ztTs
	bxrWlz5Kf+Gz+znJK6LpDZVPx9geUCgfeS2c62EueKaM4p/XsKLA5itf
X-Received: by 2002:a53:d00a:0:b0:641:f5bc:695f with SMTP id 956f58d0204a3-64903b5179emr156942d50.75.1768346485211;
        Tue, 13 Jan 2026 15:21:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H4iUDk+uJICQkSyROsSowcq6UzlILHN1tvq10SATOSbg=="
Received: by 2002:a53:5a03:0:b0:647:27b0:1aa2 with SMTP id 956f58d0204a3-64727b01c12ls3956007d50.3.-pod-prod-02-us;
 Tue, 13 Jan 2026 15:21:23 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW63C5HpYSVyThH6y/4hCLrgMVRDPCKiL6kuWPXlxYSiMC07tErihh5hV5188gI9jo/WIAB46TwMDc=@googlegroups.com
X-Received: by 2002:a05:690c:e08:b0:792:7463:c980 with SMTP id 00721157ae682-793a3a49ceamr803697b3.43.1768346483738;
        Tue, 13 Jan 2026 15:21:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768346483; cv=none;
        d=google.com; s=arc-20240605;
        b=k6T0D460Vxe3YkM2cxiHWRt4Jf3G1srkkpt3Tgs9WRzXU+o2bu5mcsUARHX4hq4OrL
         rVBKfl82EQRBAVUTP0oVMYFct5LZHd4UBUaKYxxTq2UiyG9SOBtaliwFpdiRR8zKqmWk
         1VaGIpbX15930/5bqpVuQSikQ3ob43qbHkDG/j1Zfcbm1XBWKPdi33nAYHrLdTKgj8sF
         3nGe1Vd45Kwflch4sdKYfshLB4UulgxhS7oP6wDvndpBb3iaakVyMQEpEe8E7AVfK1z+
         pMRSiRQKyTAQ+b6J9g+xWSF3F1kiUn+jvXODXoDCz6PucPZwiMk+GYxf/z21Fd7MGeYx
         jTeA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=gyRbCnsYYYz53lB5KG77Dcoajjjdn1wotNrV5Ps1VLw=;
        fh=Oje6S2y/RgmRb06peXfqb3feyrBBR7VsAlKR/ElMOWM=;
        b=bdsbiOaxaniX1wrgCSPg/0u4B1eyIy95oHC06vTvNcLecfg1trpjG5svRE5+kPPBaI
         v0Jc1R+81fDVmwhaSJ5gtZTbdZcC8NW26CrUzaR+/2FjekyN9Ubz2HasGptfP+DiPakX
         2RshXeQHFl8fONplTdU6DMpkzE+Eejiab9HF2uhYo2Q6kd6YZe++t+9TuQRyiGbtbCIc
         GG+j/Fx/VwrFcXChExP4LPaBAl9KVxyVCzAYrvSpp38G2ted+6YMRX0bzACY9+gKC+WL
         dXPCLxv6jRbSM0VPvbk/8FKZKko9/12+5hdsVLo5+CdV1ypSx1vgkG6hW14VlAKX+VXe
         p6GA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Thwq/GsY";
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-790aab4f0e5si6025997b3.3.2026.01.13.15.21.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 15:21:23 -0800 (PST)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-29f08b909aeso16531565ad.2
        for <kasan-dev@googlegroups.com>; Tue, 13 Jan 2026 15:21:23 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCU+wVP/9sftDWfmvXqtLyCSqxW80681vfYK6oyuY2vgM/C5/Tb3H6Op5hFs3dslfs1cn/1fdC5FpTc=@googlegroups.com
X-Gm-Gg: AY/fxX7Hpn5bnSm6F2KqM/gSUQkQCYvPGejq1B6zzz2C4jbv3X/Cj8mZRJQjDUXwW3O
	4zP8OPhpXpr9qmZSIU/gjASqGIqVLR+bj6Q4jNsZUpt8giCx4lccjO+hbpm2LWgbkBMeCpvafuc
	8zqLvlT49O8dJI/srVOPdofDAPjhAFEvLjSu7OiRKnmEE9yPmORq704ceCp8+UsEt5kjtdVkMFs
	3SsD7eAKFOTY+fx72FF9NWMb4axtRcIa09WPs617bM8S2karQ7lUT/W10HjWlyaGDhMwSBw39j4
	9PuqC0jk5Gr6uIsI99TdlJdFLQFITdUemNwVraGE6MFAR89CCCPuaKr1qxd5YxULwt+ecdZnDuy
	Nq0uxurI0Lg6KMVLvZlZfbRx1gXHxduJxkqDwx5/noBDchnjHR8GQ4P/0QFp5mVR3YdQMxQKRsL
	bPuNfW2+0CQgwCnj40Jko=
X-Received: by 2002:a17:903:1205:b0:2a0:990e:effd with SMTP id d9443c01a7336-2a599e94b45mr4018235ad.7.1768346482755;
        Tue, 13 Jan 2026 15:21:22 -0800 (PST)
Received: from [192.168.0.18] ([87.116.166.242])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-2a3e3cc8dd2sm208571835ad.82.2026.01.13.15.21.17
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 13 Jan 2026 15:21:22 -0800 (PST)
Message-ID: <3013f5eb-dcec-4311-bcac-e2e786172ec8@gmail.com>
Date: Wed, 14 Jan 2026 00:20:36 +0100
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [RFC] mm/kasan: Fix double free for kasan pXds
To: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>, kasan-dev@googlegroups.com
Cc: Alexander Potapenko <glider@google.com>,
 Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>,
 Vincenzo Frascino <vincenzo.frascino@arm.com>
References: <b8976a5d5fcbe8bf919dfa5d8ffbf22be8167eba.1767797480.git.ritesh.list@gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <b8976a5d5fcbe8bf919dfa5d8ffbf22be8167eba.1767797480.git.ritesh.list@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Thwq/GsY";       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2607:f8b0:4864:20::631
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


On 1/13/26 2:43 PM, Ritesh Harjani (IBM) wrote:
> kasan_free_pxd() assumes the page table is always struct page aligned.
> But that's not always the case for all architectures. E.g. In case of
> powerpc with 64K pagesize, PUD table (of size 4096) comes from slab
> cache named pgtable-2^9. Hence instead of page_to_virt(pxd_page()) let's
> just directly pass the start of the pxd table which is anyway present in these
> functions as it's 1st argument.
> 
> This fixes the below double free kasan issue which is sometimes seen with PMEM:
> 
> radix-mmu: Mapped 0x0000047d10000000-0x0000047f90000000 with 2.00 MiB pages
> ==================================================================
> BUG: KASAN: double-free in kasan_remove_zero_shadow+0x9c4/0xa20
> Free of addr c0000003c38e0000 by task ndctl/2164
> 
> CPU: 34 UID: 0 PID: 2164 Comm: ndctl Not tainted 6.19.0-rc1-00048-gea1013c15392 #157 VOLUNTARY
> Hardware name: IBM,9080-HEX POWER10 (architected) 0x800200 0xf000006 of:IBM,FW1060.00 (NH1060_012) hv:phyp pSeries
> Call Trace:
>  dump_stack_lvl+0x88/0xc4 (unreliable)
>  print_report+0x214/0x63c
>  kasan_report_invalid_free+0xe4/0x110
>  check_slab_allocation+0x100/0x150
>  kmem_cache_free+0x128/0x6e0
>  kasan_remove_zero_shadow+0x9c4/0xa20
>  memunmap_pages+0x2b8/0x5c0
>  devm_action_release+0x54/0x70
>  release_nodes+0xc8/0x1a0
>  devres_release_all+0xe0/0x140
>  device_unbind_cleanup+0x30/0x120
>  device_release_driver_internal+0x3e4/0x450
>  unbind_store+0xfc/0x110
>  drv_attr_store+0x78/0xb0
>  sysfs_kf_write+0x114/0x140
>  kernfs_fop_write_iter+0x264/0x3f0
>  vfs_write+0x3bc/0x7d0
>  ksys_write+0xa4/0x190
>  system_call_exception+0x190/0x480
>  system_call_vectored_common+0x15c/0x2ec
> ---- interrupt: 3000 at 0x7fff93b3d3f4
> NIP:  00007fff93b3d3f4 LR: 00007fff93b3d3f4 CTR: 0000000000000000
> REGS: c0000003f1b07e80 TRAP: 3000   Not tainted  (6.19.0-rc1-00048-gea1013c15392)
> MSR:  800000000280f033 <SF,VEC,VSX,EE,PR,FP,ME,IR,DR,RI,LE>  CR: 48888208  XER: 00000000
> <...>
> NIP [00007fff93b3d3f4] 0x7fff93b3d3f4
> LR [00007fff93b3d3f4] 0x7fff93b3d3f4
> ---- interrupt: 3000
> 
>  The buggy address belongs to the object at c0000003c38e0000
>   which belongs to the cache pgtable-2^9 of size 4096
>  The buggy address is located 0 bytes inside of
>   4096-byte region [c0000003c38e0000, c0000003c38e1000)
> 
>  The buggy address belongs to the physical page:
>  page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x3c38c
>  head: order:2 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0
>  memcg:c0000003bfd63e01
>  flags: 0x63ffff800000040(head|node=6|zone=0|lastcpupid=0x7ffff)
>  page_type: f5(slab)
>  raw: 063ffff800000040 c000000140058980 5deadbeef0000122 0000000000000000
>  raw: 0000000000000000 0000000080200020 00000000f5000000 c0000003bfd63e01
>  head: 063ffff800000040 c000000140058980 5deadbeef0000122 0000000000000000
>  head: 0000000000000000 0000000080200020 00000000f5000000 c0000003bfd63e01
>  head: 063ffff800000002 c00c000000f0e301 00000000ffffffff 00000000ffffffff
>  head: ffffffffffffffff 0000000000000000 00000000ffffffff 0000000000000004
>  page dumped because: kasan: bad access detected
> 
> [  138.953636] [   T2164] Memory state around the buggy address:
> [  138.953643] [   T2164]  c0000003c38dff00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> [  138.953652] [   T2164]  c0000003c38dff80: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> [  138.953661] [   T2164] >c0000003c38e0000: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> [  138.953669] [   T2164]                    ^
> [  138.953675] [   T2164]  c0000003c38e0080: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> [  138.953684] [   T2164]  c0000003c38e0100: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
> [  138.953692] [   T2164] ==================================================================
> [  138.953701] [   T2164] Disabling lock debugging due to kernel taint
> 
> Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>

I suppose this deserves cc stable and fixes tag:

Fixes: 0207df4fa1a8 ("kernel/memremap, kasan: make ZONE_DEVICE with work with KASAN")
Cc: stable@vger.kernel.org

> ---
> 
> It will be very helpful if one can review this path more thoroughly as I am not
> much aware of this code paths of page table freeing in kasan. But it logically
> looked ok to me to free all PXDs in the same fashion.
> 

I can't find a reason why this code was written in such odd way. Your patch makes total sense to me.

Please add Andrew Morton <akpm@linux-foundation.org>  and  <linux-kernel@vger.kernel.org> to recipients
and resend the patch. 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3013f5eb-dcec-4311-bcac-e2e786172ec8%40gmail.com.
