Return-Path: <kasan-dev+bncBCIN3AMT7YNBBUWKRW6AMGQER6DYADA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 89700A0A761
	for <lists+kasan-dev@lfdr.de>; Sun, 12 Jan 2025 07:46:43 +0100 (CET)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6d89154adabsf58799576d6.0
        for <lists+kasan-dev@lfdr.de>; Sat, 11 Jan 2025 22:46:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736664402; cv=pass;
        d=google.com; s=arc-20240605;
        b=h59iY3gQYzMm6a+ENvrUrrreFrUrZCrGO/TuJ8XoHagRlloYcguIW+P5y+b4lWmEOi
         9nz37hIoS1lSWXPkHuYyUT3C6GP9q+QTNYlVxNWjU+3xX0d6Ls6V7VQRRDjCA870T3Z2
         5V8QqhhRyQuBQqzKE3kHN59ueAnOPrm4QjFOfhgPDwi8IOmyFs+k12hHoztNnUmi1tdp
         jqjVmNo549v1YDdQHsHpe68DCPJI5YHVcdFH/e6rO88XHX/vl+piSLKyEdKUSKy0E3Uy
         IpbIm/nJnqokOPbmZAsDYH086hfV0FHuRO9Jgh0KNlMAtebLMgB23lygs2hlmT1l3neG
         rE2w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:dkim-signature;
        bh=j7qXNxvjkA17HhguaSV9iVuZfb8bh+10/p+GpxcoBe0=;
        fh=GQ+kfBlMe+Nua0kXK45MAO6klmIr3dk6l+wttC41VEI=;
        b=STiV+wIcPPs3fLE01LvAq9DOrxtunSiqIlhdiTgXyfoG66j0FY00ShnEkDilmlwehu
         jC37qKX6w4plV9UAb6ds1DWV+EOie45EoXELQXwogIjM5S9ISukUlhuLBZzzuT2Fd2iM
         2CAP6fgy4zGjXRpw/uoX2xlSBQiK0BpjJXqDfszqPlUPSrR8JpWQgk4J1c6CoYdyVV6h
         6C5ABcZEiy410Zh8AsFRv7b6vsP+IRH8HSc3W1uTJdlbUYU5Z6rJpDUzB+QnPp0P86Fy
         kchfYWrDIIIXSs4z59AHkh4KspXCJ2Mouws1ZV4FlLVRra/z8tPkdMiJ2tTx6wZ9OVEi
         4iDw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of lizetao1@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=lizetao1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736664402; x=1737269202; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:from:to:cc
         :subject:date:message-id:reply-to;
        bh=j7qXNxvjkA17HhguaSV9iVuZfb8bh+10/p+GpxcoBe0=;
        b=XIkgFdbZFEoejT+wvSaQwAUGQhNk7ZuyTrQK4OgY1+YZJorcWH9pFwZ3CKmMX2oEf0
         d6bzNHneMZd7GTiDNW91cl9QOtII1cjjwHgN74y4FavQrL0gzQZ8IpVMpKP1/4xDv1fb
         siFl097WgDWSySxr9ZClewc7RzL2v7EnKQFRWW/W0CemyLBnNlTEizCQKJCV49JU2AZ0
         NgNoNcJDDc5+RYrFzl2FzHx1Sh5MPXa2t+eO7BofxdGslyFL54IUr0zcecHLs91GZb8L
         koa7Mee/BxZr0hiTKUs29Kv92U4uK8nGGlbR2v0CHtxW+ss4Zf76PVOalI/LuMpIpiNz
         pjxA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736664402; x=1737269202;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :content-language:accept-language:in-reply-to:references:message-id
         :date:thread-index:thread-topic:subject:cc:to:from:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=j7qXNxvjkA17HhguaSV9iVuZfb8bh+10/p+GpxcoBe0=;
        b=fz3Hmarumde9LXaWLfLtJuRsgKTLOZBhjhfRMTe4hdjVa36C72/iDLK/Not2GsYnr/
         zjKj7EoZ3tIzmvAVwmqAM44rqRNbew++P11zIAyonf65wp6/DIJ2wZIZXlU6a++1JVF6
         vCRZQxpQaPVYtjxy0Hzd08sJjYIh2QjLJ5bqrToW1cf/MA2LAj3XTCeEUDe/Pkuv+LKN
         Fte4Md3n89w+INwbovfBGW+mfoa8USR5i6oKaOlZmhA2SYZNoGobNtdJUudryQEfPrZI
         SWn+T/yxat6IWiWflXLbt2aORBl44j8JtCdwFR/NQwLkPyau7QCqEa4OQsn+TqAzZvYE
         ZGdw==
X-Forwarded-Encrypted: i=2; AJvYcCVgXW4x6h47Rz629uVpdxLJphrmlLtEHVr+CNckh6ZNNIy02B+WMNwbRiC7OE/QIP7UeAEDIg==@lfdr.de
X-Gm-Message-State: AOJu0YxV+EQhFjVFnkYIC/egnO1nK/qmPZNPJK2nCy/q6uB9eKFUTtUR
	VqRnaF1y2UchBuS5L9YQBFRTR1vU8XkqGrH5Q1y79maYjGxNdwIz
X-Google-Smtp-Source: AGHT+IGK1+HJYYlgGMRbcErrgkV1hwKG+6otcubmoHTzSf5KCXXpkoUk2DQJ8CPIakxfZuZL1hZG/A==
X-Received: by 2002:a05:6214:2f8e:b0:6df:ba24:2af2 with SMTP id 6a1803df08f44-6dfba242b5bmr84239316d6.25.1736664402238;
        Sat, 11 Jan 2025 22:46:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5788:b0:6d4:18b4:dc77 with SMTP id
 6a1803df08f44-6dfa36d23edls9210136d6.0.-pod-prod-09-us; Sat, 11 Jan 2025
 22:46:41 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWd5nODcb7M2+467ynDpAaHi0PfP9ZsCg1cBjDmieoowI/NgPfK90wXiUM+oe3yniHqPy+bwJbH4ZE=@googlegroups.com
X-Received: by 2002:a05:620a:2947:b0:7b6:da21:752e with SMTP id af79cd13be357-7bcd96e55a6mr2805818685a.8.1736664401611;
        Sat, 11 Jan 2025 22:46:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736664401; cv=none;
        d=google.com; s=arc-20240605;
        b=dsUJ5spC/C4NObvRrU1jId9GPqmK9YbiFlKcLZ/AmzxY90dfAElgBKY6qWRpPQ5MOC
         0NZxfqy+rl51MnM/ZrWWD6r4N/GsvNt5+0KwJy1CXkHsAk2VL/267GJ0HzviqttApulV
         MfekATi4vCxO6jARMmKmJm70UOMEr/iKHmbRtAKlqYWQo82jk0LGjEHA7nMSuYbIYmOT
         jWB48FLOgApzel+Fdf96dZlEHqlVe4kh9b/yZPMk71DRygKDrMiUnRlbkcxPQbStZwEt
         FKA3yk+QEOzbIyYdj0ocmpt+6q5BxI9xCjWB0J1ztipel3hKXtfpWmpbFARPrL9CZYiv
         wuKA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:content-transfer-encoding:content-language
         :accept-language:in-reply-to:references:message-id:date:thread-index
         :thread-topic:subject:cc:to:from;
        bh=5O5GrY2DL3HmVqMBs1zEvv0fX+L0ULWNILdSDuIXxW0=;
        fh=BWZBf5Qzbqj2IlXl3IkghbVHjonFE4s++6F4umi76W0=;
        b=WdLBANFPbmB027PNN4LhpZeG1eTdRWKoT8cK24AzoWaA/UZ8rzpaIHHfe8omhIAiaf
         Y6B0YHtb57hcbaP1LORnU3sXXC1LHS5YGIoo2VXnIVup/zIwgOB0ASUeUN58dtduNd7B
         Tf5gArU6kSLbm/nS974u9W4IOO8T7UQ4dlh1etRDKqwVdoVGrRaMc73OJnxXKuLdX8XP
         p4I1h4UOsv8GadOaTQhMfK1BwagSiI6gqoFtNrJPsg/FeyS4EfL8cckkSGVKB5KXA74B
         M0kuw96LDoRuTpMHfLcBFA1i75HJHK84ViyfianfcvaDR29tOCAMNizzfLLbhmlcNTBf
         9BWg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of lizetao1@huawei.com designates 45.249.212.191 as permitted sender) smtp.mailfrom=lizetao1@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga05-in.huawei.com (szxga05-in.huawei.com. [45.249.212.191])
        by gmr-mx.google.com with ESMTP id af79cd13be357-7bce32eca02si26747885a.4.2025.01.11.22.46.40
        for <kasan-dev@googlegroups.com>;
        Sat, 11 Jan 2025 22:46:41 -0800 (PST)
Received-SPF: pass (google.com: domain of lizetao1@huawei.com designates 45.249.212.191 as permitted sender) client-ip=45.249.212.191;
Received: from mail.maildlp.com (unknown [172.19.162.112])
	by szxga05-in.huawei.com (SkyGuard) with ESMTP id 4YW5VC0WRWz1JGd2;
	Sun, 12 Jan 2025 14:44:51 +0800 (CST)
Received: from kwepemd100011.china.huawei.com (unknown [7.221.188.204])
	by mail.maildlp.com (Postfix) with ESMTPS id 83299140114;
	Sun, 12 Jan 2025 14:45:40 +0800 (CST)
Received: from kwepemd500012.china.huawei.com (7.221.188.25) by
 kwepemd100011.china.huawei.com (7.221.188.204) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1258.34; Sun, 12 Jan 2025 14:45:40 +0800
Received: from kwepemd500012.china.huawei.com ([7.221.188.25]) by
 kwepemd500012.china.huawei.com ([7.221.188.25]) with mapi id 15.02.1258.034;
 Sun, 12 Jan 2025 14:45:40 +0800
From: "'lizetao' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jens Axboe <axboe@kernel.dk>, io-uring <io-uring@vger.kernel.org>
CC: Pavel Begunkov <asml.silence@gmail.com>, "juntong.deng@outlook.com"
	<juntong.deng@outlook.com>, "ryabinin.a.a@gmail.com"
	<ryabinin.a.a@gmail.com>, "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: RE: KASAN reported an error while executing accept-reust.t testcase
Thread-Topic: KASAN reported an error while executing accept-reust.t testcase
Thread-Index: AdtkMiVyVeZvS0/xQj+24imZgOjMRP//rdsA//6ZQvA=
Date: Sun, 12 Jan 2025 06:45:40 +0000
Message-ID: <c14929fc328f43baa7ac2ad8f85a8f2b@huawei.com>
References: <ec2a6ca08c614c10853fbb1270296ac4@huawei.com>
 <98125b67-7b63-427f-b822-a12779d50a13@kernel.dk>
In-Reply-To: <98125b67-7b63-427f-b822-a12779d50a13@kernel.dk>
Accept-Language: en-US
Content-Language: zh-CN
X-MS-Has-Attach: 
X-MS-TNEF-Correlator: 
x-originating-ip: [10.82.162.72]
Content-Type: text/plain; charset="UTF-8"
MIME-Version: 1.0
X-Original-Sender: lizetao1@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of lizetao1@huawei.com designates 45.249.212.191 as
 permitted sender) smtp.mailfrom=lizetao1@huawei.com;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: lizetao <lizetao1@huawei.com>
Reply-To: lizetao <lizetao1@huawei.com>
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

Hi,

> -----Original Message-----
> From: Jens Axboe <axboe@kernel.dk>
> Sent: Sunday, January 12, 2025 1:13 AM
> To: lizetao <lizetao1@huawei.com>; io-uring <io-uring@vger.kernel.org>
> Cc: Pavel Begunkov <asml.silence@gmail.com>
> Subject: Re: KASAN reported an error while executing accept-reust.t testcase
> 
> On 1/11/25 7:07 AM, lizetao wrote:
> > Hi all,
> >
> > When I run the testcase liburing/accept-reust.t with CONFIG_KASAN=y
> > and CONFIG_KASAN_EXTRA_INFO=y, I got a error reported by KASAN:
> 
> Looks more like you get KASAN crashing...
> 
> > Unable to handle kernel paging request at virtual address
> > 00000c6455008008 Mem abort info:
> >   ESR = 0x0000000096000004
> >   EC = 0x25: DABT (current EL), IL = 32 bits
> >   SET = 0, FnV = 0
> >   EA = 0, S1PTW = 0
> >   FSC = 0x04: level 0 translation fault Data abort info:
> >   ISV = 0, ISS = 0x00000004, ISS2 = 0x00000000
> >   CM = 0, WnR = 0, TnD = 0, TagAccess = 0
> >   GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 user pgtable: 4k pages,
> > 48-bit VAs, pgdp=00000001104c5000 [00000c6455008008]
> > pgd=0000000000000000, p4d=0000000000000000 Internal error: Oops:
> > 0000000096000004 [#1] PREEMPT SMP Modules linked in:
> > CPU: 6 UID: 0 PID: 352 Comm: kworker/u128:5 Not tainted
> > 6.13.0-rc6-g0a2cb793507d #5 Hardware name: linux,dummy-virt (DT)
> > Workqueue: iou_exit io_ring_exit_work
> > pstate: 10000005 (nzcV daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc :
> > __kasan_mempool_unpoison_object+0x38/0x170
> > lr : io_netmsg_cache_free+0x8c/0x180
> > sp : ffff800083297a90
> > x29: ffff800083297a90 x28: ffffd4d7f67e88e4 x27: 0000000000000003
> > x26: 1fffe5958011502e x25: ffff2cabff976c18 x24: 1fffe5957ff2ed83
> > x23: ffff2cabff976c10 x22: 00000c6455008000 x21: 0002992540200001
> > x20: 0000000000000000 x19: 00000c6455008000 x18: 00000000489683f8
> > x17: ffffd4d7f68006ac x16: ffffd4d7f67eb3e0 x15: ffffd4d7f67e88e4
> > x14: ffffd4d7f766deac x13: ffffd4d7f6619030 x12: ffff7a9b012e3e26
> > x11: 1ffffa9b012e3e25 x10: ffff7a9b012e3e25 x9 : ffffd4d7f766debc
> > x8 : ffffd4d80971f128 x7 : 0000000000000001 x6 : 00008564fed1c1db
> > x5 : ffffd4d80971f128 x4 : ffff7a9b012e3e26 x3 : ffff2cabff976c00
> > x2 : ffffc1ffc0000000 x1 : 0000000000000000 x0 : 0002992540200001 Call
> > trace:
> >  __kasan_mempool_unpoison_object+0x38/0x170 (P)
> >  io_netmsg_cache_free+0x8c/0x180
> >  io_ring_exit_work+0xd4c/0x13a0
> >  process_one_work+0x52c/0x1000
> >  worker_thread+0x830/0xdc0
> >  kthread+0x2bc/0x348
> >  ret_from_fork+0x10/0x20
> > Code: aa0003f5 aa0103f4 8b131853 aa1303f6 (f9400662) ---[ end trace
> > 0000000000000000 ]---
> >
> >
> > I preliminary analyzed the accept and connect code logic. In the
> > accept-reuse.t testcase, kmsg->free_iov is not used, so when calling
> > io_netmsg_cache_free(), the
> > kasan_mempool_unpoison_object(kmsg->free_iov...) path should not be
> > executed.
> >
> >
> > I used the hardware watchpoint to capture the first scene of modifying kmsg-
> >free_iov:
> >
> > Thread 3 hit Hardware watchpoint 7: *0xffff0000ebfc5410 Old value = 0
> > New value = -211812350 kasan_set_track (stack=<optimized out>,
> > track=<optimized out>) at ./arch/arm64/include/asm/current.h:21
> > 21		return (struct task_struct *)sp_el0;
> >
> > # bt
> > kasan_set_track
> > kasan_save_track
> > kasan_save_free_info
> > poison_slab_object
> > __kasan_mempool_poison_object
> > kasan_mempool_poison_object
> > io_alloc_cache_put
> > io_netmsg_recycle
> > io_req_msg_cleanup
> > io_connect
> > io_issue_sqe
> > io_queue_sqe
> > io_req_task_submit
> > ...
> >
> >
> > It's a bit strange. It was modified by KASAN. I can't understand this.
> > Maybe I missed something? Please let me know. Thanks.
> 
> Looks like KASAN with the extra info ends up writing to io_async_msghdr-
> >free_iov somehow. No idea... For the test case in question, ->free_iov should
> be NULL when initially allocated, and the io_uring code isn't storing to it. Yet
> it's non-NULL when you later go and free it, after calling
> kasan_mempool_poison_object().

I also think so and would Juntong and Ryabinin or others KASAN developers be interested
In this problem?

+CC juntong.deng@outlook.com, ryabinin.a.a@gmail.com and kasan-dev@googlegroups.com

Thank you so mush.
> 
> --
> Jens Axboe

---
Li Zetao

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c14929fc328f43baa7ac2ad8f85a8f2b%40huawei.com.
