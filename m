Return-Path: <kasan-dev+bncBDZYPUPHYEJBBQ7W3XVAKGQEDO6PJZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E3C390C9B
	for <lists+kasan-dev@lfdr.de>; Sat, 17 Aug 2019 05:57:57 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id k70sf5119287otk.6
        for <lists+kasan-dev@lfdr.de>; Fri, 16 Aug 2019 20:57:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566014276; cv=pass;
        d=google.com; s=arc-20160816;
        b=z7taZfUw5bE8b9hJG5y45CFryC9zXpSWlb3ucH5kYwK/gIom1HI3Pf+ztpelZVFNUj
         QpK0oXB/Ep6rTMHgDGVn00QyGHDyncyYZDf3IkDZWQJik1zafpCJ6qmmlrqWdRgyjWJe
         pTgyWTGTAbOkjJ7TZOlZR2MMPXV2ymReBdKqWjhgDcAQYGQOJs3VtJO81ZfUFxy/ozVi
         6a1tji/Llt1mRZflTrud56qC6SMkk6UVzPX0mWPB8EzPVw+nmGyAptpqK2+i9jNwu7+H
         H2PnT5gj/6rSRzJxxOO94uGtN0wiyq/xaFKwMndZ+6KcHZPKDUm25fOyadfTdzQKhx9V
         bXyg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=2LDAxA6IuVb6Wat4awaMLeBPC228iz72YtW6Km525pM=;
        b=r17MM2LJTHGpPKT68KQuNhWjfyjW3qpaxCP3jEd80giiEoetr0Sc2HWUeArMkrEGXK
         mJq41gs8eG3RWW2PISS3z+UYAwbTmOLV8UxI+msfgmoBCzkGmJhQKedppfBWREQr10Y3
         4E/410jD28onXHqG8JrXkoQZfWOENdFBWAGdg9B1im3C2iS60lK7lelTN/T4rHdkxp7U
         0dUggq893iUH9xs7Ys3ZVg36t2Gag0mOLNbHHCHa3V/JiEJERgrljYiIGLNoHsWkxJDj
         mGS38dTmNmZHMea65izShbmzyAyULwNfYM4ozuvuF4vUMucRcrjmCZKj5yyvUHVl28ap
         5hAw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel-com.20150623.gappssmtp.com header.s=20150623 header.b=PLgTwvnO;
       spf=pass (google.com: domain of dan.j.williams@intel.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2LDAxA6IuVb6Wat4awaMLeBPC228iz72YtW6Km525pM=;
        b=RyEvnUCHGTK8CjWqEIpfrvO0VWVPo8fPgm661xb0zIWHC22/gzvsNOudSolYbHmKPf
         GxFQy8GNAuHezh9l/9gFn3p3hen2zyKYRFN70NNO7IBhlKS5aMG1GHJvhBuG2f1CWctz
         lhYRMzIVP63nAoyh89LqnyPoZJVNgecSZcjM9v51IxmA1lHZa0fvU4D7y2ZXZbFmA+0b
         l71iWv52vg0gd+ZfNqHBMPCGnksT13xFypMA3j69tFg+yykei7c3oXia8LmornyH4WzL
         Km8E9dYIZ3inkQXbTLkgyvUs6bYspDQ1V5INH8zGCRZRhkQUncBAR22RImvuYkV+vs3z
         ejBg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2LDAxA6IuVb6Wat4awaMLeBPC228iz72YtW6Km525pM=;
        b=WU0CjflropkOmbmPH8AWP8B9lkQpjlXIzxtgyjy45lZXKmg9Jz3Sx3/FTDWCIfoela
         TDa0bkZqkvx+lnHw7BtrKxWpS571+ID9Smo8LbbI3PF5gjAtekogjP8ss4/av/DVEd7+
         fsmmfbOZMyH11rN5Xq3h6D6uaoSTn+hE1x8q1V7QEdteZcHveL7Gpmeb0Mkw5eopGkdD
         lvh46H4OCqo2A1kQKyU9PoVngFUIDx4/OWrTVc97JV/xWCfgfEMghE29ZMnrQMLAEmsu
         p1bptKaURI4kVRjZTBD8op6pC2X+M7NcxVGiMcmVC0WM3u0CNwSXVlw9Vw3yQgor0QAd
         6reA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXzA07yKNEPsPJCNHTl7/rcvC7OoGevuenHqSGpB7PbwYr8JFcl
	4CcRJBelac7JvvtuE0iv0qc=
X-Google-Smtp-Source: APXvYqw7UmYT7nt6nZFWmgn6wAD0HVClj80fXlrYwYc4FdquEU7LqIE6C8c9J5Y+VIh6E+MKE15yVw==
X-Received: by 2002:aca:b303:: with SMTP id c3mr1697168oif.95.1566014275828;
        Fri, 16 Aug 2019 20:57:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:fc93:: with SMTP id a141ls1028137oii.10.gmail; Fri, 16
 Aug 2019 20:57:55 -0700 (PDT)
X-Received: by 2002:aca:d449:: with SMTP id l70mr7281740oig.88.1566014275467;
        Fri, 16 Aug 2019 20:57:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566014275; cv=none;
        d=google.com; s=arc-20160816;
        b=qlJZ+vBAZUrYPqUjaml1OH1Eif0vKBhyLUrjOUyMewDpgH6pdg5H4YbKt32A17BaGx
         e0f64n4O47CxfA7fIwffpH15Rmtb6G3SvmLZ/w3bu0mypVSTiKQIETekx94+cRoBPvzE
         V7VAIeTSlm5RBEVGBOqOxxCRt3V/rbCE0b2RthcSnJanoy2SS11SNlUNl8LLQTq4P8Nt
         NIrvSIVuz1sZjBs2COGpGzgTUNXHiJ62N+Lu8nplZ4UCFVE2NuacuDOTmL0MFbvH7DAz
         YhfLs6ov9y69XdcdDX2yr4nKbprS/SlMRJ0uNMIN5GCObUdqfHUE8RdJTIAuJspO9R9o
         YfKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5JkAhLV4VoRnu2crZGL/J2yHThD4/hsSp7D/mpQ+b1s=;
        b=tsazUL8YSbAlwE5uLC2/bInPzwSB+zX/wVBskAH51w8jJ10UUPTMfDWfRuRKU75QdC
         jN3HnfnKpiF/l0WG5wo9K1qrv+ScWSQsW+a5bn1aAbO9xg7mZTemH9SL3rH3Lrm/0F9e
         9CrMPV3etNaOIUwDMBzXf03ea9lUbqUUoxB+06ENPduFR6rKnV3r2athplF9FQYZ+PZ4
         CoiinchOA+G5YkQvEnGqN7gxiilYhdI2t0p2BeIBcSFDDKbSGb64gk70U5Xa4wi7PkMp
         23/cQt5aKrpPxmGoLssMaG/+mLLXpmcbFsahNX/4izwjUMRA/4h/QTYreNi1r9KqMaVM
         CSZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel-com.20150623.gappssmtp.com header.s=20150623 header.b=PLgTwvnO;
       spf=pass (google.com: domain of dan.j.williams@intel.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id u18si261035oie.4.2019.08.16.20.57.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 16 Aug 2019 20:57:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of dan.j.williams@intel.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id e12so11363712otp.10
        for <kasan-dev@googlegroups.com>; Fri, 16 Aug 2019 20:57:55 -0700 (PDT)
X-Received: by 2002:a05:6830:1e05:: with SMTP id s5mr9263489otr.247.1566014275232;
 Fri, 16 Aug 2019 20:57:55 -0700 (PDT)
MIME-Version: 1.0
References: <1565991345.8572.28.camel@lca.pw> <CAPcyv4i9VFLSrU75U0gQH6K2sz8AZttqvYidPdDcS7sU2SFaCA@mail.gmail.com>
 <0FB85A78-C2EE-4135-9E0F-D5623CE6EA47@lca.pw>
In-Reply-To: <0FB85A78-C2EE-4135-9E0F-D5623CE6EA47@lca.pw>
From: Dan Williams <dan.j.williams@intel.com>
Date: Fri, 16 Aug 2019 20:57:40 -0700
Message-ID: <CAPcyv4h9Y7wSdF+jnNzLDRobnjzLfkGLpJsML2XYLUZZZUPsQA@mail.gmail.com>
Subject: Re: devm_memremap_pages() triggers a kasan_add_zero_shadow() warning
To: Qian Cai <cai@lca.pw>
Cc: Linux MM <linux-mm@kvack.org>, linux-nvdimm <linux-nvdimm@lists.01.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dan.j.williams@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel-com.20150623.gappssmtp.com header.s=20150623
 header.b=PLgTwvnO;       spf=pass (google.com: domain of dan.j.williams@intel.com
 designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=dan.j.williams@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
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

On Fri, Aug 16, 2019 at 8:34 PM Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Aug 16, 2019, at 5:48 PM, Dan Williams <dan.j.williams@intel.com> wrote:
> >
> > On Fri, Aug 16, 2019 at 2:36 PM Qian Cai <cai@lca.pw> wrote:
> >>
> >> Every so often recently, booting Intel CPU server on linux-next triggers this
> >> warning. Trying to figure out if  the commit 7cc7867fb061
> >> ("mm/devm_memremap_pages: enable sub-section remap") is the culprit here.
> >>
> >> # ./scripts/faddr2line vmlinux devm_memremap_pages+0x894/0xc70
> >> devm_memremap_pages+0x894/0xc70:
> >> devm_memremap_pages at mm/memremap.c:307
> >
> > Previously the forced section alignment in devm_memremap_pages() would
> > cause the implementation to never violate the KASAN_SHADOW_SCALE_SIZE
> > (12K on x86) constraint.
> >
> > Can you provide a dump of /proc/iomem? I'm curious what resource is
> > triggering such a small alignment granularity.
>
> This is with memmap=4G!4G ,
>
> # cat /proc/iomem
[..]
> 100000000-155dfffff : Persistent Memory (legacy)
>   100000000-155dfffff : namespace0.0
> 155e00000-15982bfff : System RAM
>   155e00000-156a00fa0 : Kernel code
>   156a00fa1-15765d67f : Kernel data
>   157837000-1597fffff : Kernel bss
> 15982c000-1ffffffff : Persistent Memory (legacy)
> 200000000-87fffffff : System RAM

Ok, looks like 4G is bad choice to land the pmem emulation on this
system because it collides with where the kernel is deployed and gets
broken into tiny pieces that violate kasan's. This is a known problem
with memmap=. You need to pick an memory range that does not collide
with anything else. See:

    https://nvdimm.wiki.kernel.org/how_to_choose_the_correct_memmap_kernel_parameter_for_pmem_on_your_system

...for more info.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAPcyv4h9Y7wSdF%2BjnNzLDRobnjzLfkGLpJsML2XYLUZZZUPsQA%40mail.gmail.com.
