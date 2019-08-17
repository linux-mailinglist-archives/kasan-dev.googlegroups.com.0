Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBXHL3XVAKGQEDUC4VRQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 1AC2590C72
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Aug 2019 05:34:55 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id j12sf4253392pll.14
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 20:34:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566012893; cv=pass;
        d=google.com; s=arc-20160816;
        b=SorHJiNHZsZcbV5Dmg5LDnEvFWldgr2ZAX9Ht/s08DVXvLoSlusafuFBFvy93l1Lbb
         5ZW6SDUL+afsxfZfzfhHkjNH1lMmuhgDwAt3agZkojZuwGpna0fwFuLra88ezvlDYd+U
         WJpFYeWOLor8nsGzHkVNYKlkwmJlxikuTn/nFWsXGRNLmUBSHws0Zm8iaPCVCuGR8/g8
         kA997RWoMLVv5Hu3800aAIqETJdon/k+hEKWLH3bFH+z+2VFhVe1o09ACgFCVpCRE+BS
         AaYhj0JUqP8WA9AHwMrKl1Wn3o4RFTGlhGLOn1/gFE+/jCcchUiiPyNZ6fLcIRuiNcAM
         hJvg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=Vt7w808xZUVayDhm2XoF+vXz0PxDikk9fet3bw9t1To=;
        b=f4qgDPoPSSvPkXVFSPx0aH8bwdGyMMkY2N897LfymXDpbgsFg3jLNSx1UJcE817Q83
         o2e87eJgmMaB8qzAv0FqUxj/7MUzpULnZRD1++o9vzrRZ0/5h8yB5ycLHb3J2fIfJpA6
         BZm8DNDJ7NRKkBoiQrGiEWXP1f8k7ZGbnhkvE1v5dRc5RLYkIC6rgZ4Gfzhg9JQreyCc
         QhlPIUcA8huOByL+a30M4tCYQ+5cJKOX8TWrqb+PCYCaHJXMouHZBZYn4ZmUB6SM5ktE
         xa9uq3UvRUPEIe+SuheibzbjIvqFEAgA8hOVhvXiFkC1iwanvQaa+nETCtDEEbsSj966
         bkWw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=RrOWVqtA;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc:message-id
         :references:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vt7w808xZUVayDhm2XoF+vXz0PxDikk9fet3bw9t1To=;
        b=M554cH8LdZn/Tu0CdzRV0I5aBtF/p2LrqbzaiU+lPozy82OSFWAWl9+I+4IOIjS06x
         XQnrb8hy/FwPEOsj5qFxZFxAW2WM6vKAKukDUCHvt/pmQf+yz0G4Rlui+ajx+acNgMCe
         q3wvPz4ir3ysYH9k8qzEsUIJKjVzlvX0cZA8fUTNcVXAJlMjDJB9MeGu2J8uDHcm+WJV
         cvcqB/C1kkj4mBJlNShV+NDvp+gpNou2u1vlQf/EeJZIVWQD6PhlitGN8Be83mGhJ99S
         Qdq1AiIJkwvhOM53I38FV1FhfNXKLJfFUjCKFnKCwsQREak0FA1IYRIP3YYNVYG2zj6F
         9iLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:message-id:references:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Vt7w808xZUVayDhm2XoF+vXz0PxDikk9fet3bw9t1To=;
        b=hQuOhI8g2R61DHRwgF8Jkw1KGXKsuV++vhvda93Z05p29FeaHB12XFDtxwGgKUu846
         UiL/+HsWL0GoWLwQm4csaSz5UmGaYK6Q5COIoIhBkfalTS/onWYIsCy+NkPQ/MI32VSF
         NCZFbWewwIPFSdwE9Uob+lUz75SHvPjIioWD1KsEZMrLKF8VeiIR4vms8o8zb9jvHbfF
         u2KSDk5eK7cMLtkZfVWtiYDxPK/N/36H+EWkL/7wxkHqf8vV4szZEh1SU1Vmfjw9Kh6h
         fqabH0TDpu8tZ+phoWw/4/AdqUFJdou4zm0IbWDNilNkhjqBYyCBasOgMz1xTo7AKe4r
         HBhA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUfZvfUAvNTSN4Kh8i+ifzvQz+80mEvRRl8CynusXf/w/eIg+7W
	tZy2cxcziUuU84BS5dEIwTE=
X-Google-Smtp-Source: APXvYqzF0l5QwIdNQ4Mr6/sdTjAHv8w+rCPoVdFDK4Mq0SW1iumcJ33WTU2DLMCDvB2oHFcv58Nkkw==
X-Received: by 2002:a17:90a:80ca:: with SMTP id k10mr10442915pjw.59.1566012893341;
        Fri, 16 Aug 2019 20:34:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:20c8:: with SMTP id v8ls2484895plg.11.gmail; Fri, 16
 Aug 2019 20:34:52 -0700 (PDT)
X-Received: by 2002:a17:902:1107:: with SMTP id d7mr12101467pla.184.1566012892702;
        Fri, 16 Aug 2019 20:34:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566012892; cv=none;
        d=google.com; s=arc-20160816;
        b=zft+RmRpJfSX858bZcGMxoNJJC51LeaefHckaBmAOpHXHDAoQp1EXoqK6I/6WBAHad
         zGTLGhA8cWb/uJW2jXpvI3vWiNwLS+KrD+8wNV2sZpAa9v4nJAUEk6mkERJxO/AtxvdM
         75fXSX3iPfzoyY+wqLqkV6xzcu2wrP9U/kq8agRPjiNkoduR13c3QCY5ej9VEW4uMNDB
         FvmdgEUwXqgkzhQN57xzTyhRoxtYy6YuWJNFE1cYjU+/CgDCaZOJR2KjAmEFOyLg86IK
         y7ioiEPWg5AWncOuhpUbQOnaGDg9LSQgT2B1UjZtcMrCC8L+rO5zW1vkTi22v0/bqljf
         iB9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=H0x/tH5aSizx2cH/6tkCkmxwDmqvYIh10OUi2/vlP6A=;
        b=rGKH6q0ZxWb1O0Lmij3iuFzxtU7HZK9MWniM11KJ2AeCvJ8yyvaSfvmyHVbKid9ifB
         tNuA85mSzyRcvGJGxKqkhmKlhZxk7FlPsM7bPwocDr2RtPvmxQ80R/3w+1db+1/c+DVn
         ra+r61zgbM1DANyUUHPUo6/TmwwTI+YKxJGW2dPe3w1vRLTmOWQVuyresR4T7c2FR9lX
         yPjpFN3u6hNgGrAy1xUepCX6ogdC1kkdHtC5H1h28n1/gUGXC8cMiA34cc8RE10DMD30
         LtNW76IkS4Vbjzpnibw0bcQMXO2bSAppuV4LKLmW1r8ur8MfBQKsZ91l9mXAcpJYSnet
         sYww==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=RrOWVqtA;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x844.google.com (mail-qt1-x844.google.com. [2607:f8b0:4864:20::844])
        by gmr-mx.google.com with ESMTPS id y6si213511pjv.2.2019.08.16.20.34.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Aug 2019 20:34:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as permitted sender) client-ip=2607:f8b0:4864:20::844;
Received: by mail-qt1-x844.google.com with SMTP id 44so8261670qtg.11
        for <kasan-dev@googlegroups.com>; Fri, 16 Aug 2019 20:34:52 -0700 (PDT)
X-Received: by 2002:ad4:4301:: with SMTP id c1mr996111qvs.138.1566012891520;
        Fri, 16 Aug 2019 20:34:51 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id f20sm5430480qtf.68.2019.08.16.20.34.50
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 16 Aug 2019 20:34:51 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 12.4 \(3445.104.11\))
Subject: Re: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
From: Qian Cai <cai@lca.pw>
In-Reply-To: <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
Date: Fri, 16 Aug 2019 23:34:49 -0400
Cc: Linux MM <linux-mm@kvack.org>,
 linux-nvdimm <linux-nvdimm@lists.01.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Andrey Ryabinin <aryabinin@virtuozzo.com>,
 kasan-dev@googlegroups.com
Message-Id: <0FB85A78-C2EE-4135-9E0F-D5623CE6EA47@lca.pw>
References: <1565991345.8572.28.camel@lca.pw>
 <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
To: Dan Williams <dan.j.williams@intel.com>
X-Mailer: Apple Mail (2.3445.104.11)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=RrOWVqtA;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::844 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Aug 16, 2019, at 5:48 PM, Dan Williams <dan.j.williams@intel.com> wrote:
> 
> On Fri, Aug 16, 2019 at 2:36 PM Qian Cai <cai@lca.pw> wrote:
>> 
>> Every so often recently, booting Intel CPU server on linux-next triggers this
>> warning. Trying to figure out if  the commit 7cc7867fb061
>> ("mm/devm_memremap_pages: enable sub-section remap") is the culprit here.
>> 
>> # ./scripts/faddr2line vmlinux devm_memremap_pages+0x894/0xc70
>> devm_memremap_pages+0x894/0xc70:
>> devm_memremap_pages at mm/memremap.c:307
> 
> Previously the forced section alignment in devm_memremap_pages() would
> cause the implementation to never violate the KASAN_SHADOW_SCALE_SIZE
> (12K on x86) constraint.
> 
> Can you provide a dump of /proc/iomem? I'm curious what resource is
> triggering such a small alignment granularity.

This is with memmap=4G!4G ,

# cat /proc/iomem 
00000000-00000fff : Reserved
00001000-00093fff : System RAM
00094000-0009ffff : Reserved
000a0000-000bffff : PCI Bus 0000:00
000c0000-000c7fff : Video ROM
000c8000-000cbfff : Adapter ROM
000cc000-000ccfff : Adapter ROM
000e0000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-5a7a0fff : System RAM
5a7a1000-5b5e0fff : Reserved
5b5e1000-790fefff : System RAM
  69000000-78ffffff : Crash kernel
790ff000-791fefff : Reserved
791ff000-7b5fefff : ACPI Non-volatile Storage
7b5ff000-7b7fefff : ACPI Tables
7b7ff000-7b7fffff : System RAM
7b800000-8fffffff : Reserved
  80000000-8fffffff : PCI MMCONFIG 0000 [bus 00-ff]
90000000-c7ffbfff : PCI Bus 0000:00
  90000000-92afffff : PCI Bus 0000:01
    90000000-9000ffff : 0000:01:00.2
    91000000-91ffffff : 0000:01:00.1
    92000000-927fffff : 0000:01:00.1
    92800000-928fffff : 0000:01:00.2
    92900000-929fffff : 0000:01:00.2
    92a00000-92a7ffff : 0000:01:00.2
    92a80000-92a87fff : 0000:01:00.2
    92a88000-92a8bfff : 0000:01:00.1
    92a8c000-92a8c0ff : 0000:01:00.2
    92a8d000-92a8d1ff : 0000:01:00.0
  92b00000-92dfffff : PCI Bus 0000:02
    92b00000-92bfffff : 0000:02:00.1
      92b00000-92bfffff : igb
    92c00000-92cfffff : 0000:02:00.0
      92c00000-92cfffff : igb
    92d00000-92d03fff : 0000:02:00.1
      92d00000-92d03fff : igb
    92d04000-92d07fff : 0000:02:00.0
      92d04000-92d07fff : igb
    92d80000-92dfffff : 0000:02:00.0
  92e00000-92ffffff : PCI Bus 0000:03
    92e00000-92efffff : 0000:03:00.0
      92e00000-92efffff : hpsa
    92f00000-92f003ff : 0000:03:00.0
      92f00000-92f003ff : hpsa
    92f80000-92ffffff : 0000:03:00.0
  93000000-930003ff : 0000:00:1d.0
  93001000-930013ff : 0000:00:1a.0
  93003000-93003fff : 0000:00:05.4
c7ffc000-c7ffcfff : dmar1
c8000000-fbffbfff : PCI Bus 0000:80
  c8000000-c8000fff : 0000:80:05.4
fbffc000-fbffcfff : dmar0
fec00000-fecfffff : PNP0003:00
  fec00000-fec003ff : IOAPIC 0
  fec01000-fec013ff : IOAPIC 1
  fec40000-fec403ff : IOAPIC 2
fed00000-fed003ff : HPET 0
  fed00000-fed003ff : PNP0103:00
fed12000-fed1200f : pnp 00:01
fed12010-fed1201f : pnp 00:01
fed1b000-fed1bfff : pnp 00:01
fed1c000-fed3ffff : pnp 00:01
fed45000-fed8bfff : pnp 00:01
fee00000-feefffff : pnp 00:01
  fee00000-fee00fff : Local APIC
ff800000-ffffffff : Reserved
100000000-155dfffff : Persistent Memory (legacy)
  100000000-155dfffff : namespace0.0
155e00000-15982bfff : System RAM
  155e00000-156a00fa0 : Kernel code
  156a00fa1-15765d67f : Kernel data
  157837000-1597fffff : Kernel bss
15982c000-1ffffffff : Persistent Memory (legacy)
200000000-87fffffff : System RAM
  858000000-877ffffff : Crash kernel
38000000000-39fffffffff : PCI Bus 0000:00
  39fffe00000-39fffefffff : PCI Bus 0000:02
  39ffff00000-39ffff0ffff : 0000:00:14.0
  39ffff10000-39ffff13fff : 0000:00:04.7
  39ffff14000-39ffff17fff : 0000:00:04.6
  39ffff18000-39ffff1bfff : 0000:00:04.5
  39ffff1c000-39ffff1ffff : 0000:00:04.4
  39ffff20000-39ffff23fff : 0000:00:04.3
  39ffff24000-39ffff27fff : 0000:00:04.2
  39ffff28000-39ffff2bfff : 0000:00:04.1
  39ffff2c000-39ffff2ffff : 0000:00:04.0
  39ffff31000-39ffff310ff : 0000:00:1f.3
3a000000000-3bfffffffff : PCI Bus 0000:80
  3bffff00000-3bffff03fff : 0000:80:04.7
  3bffff04000-3bffff07fff : 0000:80:04.6
  3bffff08000-3bffff0bfff : 0000:80:04.5
  3bffff0c000-3bffff0ffff : 0000:80:04.4
  3bffff10000-3bffff13fff : 0000:80:04.3
  3bffff14000-3bffff17fff : 0000:80:04.2
  3bffff18000-3bffff1bfff : 0000:80:04.1
  3bffff1c000-3bffff1ffff : 0000:80:04.0

> 
> Is it truly only linux-next or does latest mainline have this issue as well?

No idea. I have not had a chance to test it on the mainline yet.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0FB85A78-C2EE-4135-9E0F-D5623CE6EA47%40lca.pw.
