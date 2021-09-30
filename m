Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBNOU3CFAMGQEKFQYZZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E37A41E330
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 23:20:54 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id x16-20020a25b910000000b005b6b7f2f91csf10584313ybj.1
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Sep 2021 14:20:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1633036853; cv=pass;
        d=google.com; s=arc-20160816;
        b=bASISvZ9xND9QdnhkGjg5TkUgBAVQk0TYzQn/nzjafE69sxoAhMdIOm1NGX4vpA1WT
         57SAXuQw4orqou188D29qcufd6mofxINLHRGkEW9QlwHaHANr0Lr6xg4LK/itRen85sf
         MpAhk/F3vxY+CgMablJRdKvSDDVtwtCD91c0IEWaGLOr+Qna5vZtAnriXurpyQ23EXy1
         tU/4qpSxq7tio0RWqt4hphrIi84RPxUeVnJZfLZdx4ZGSpgsszEH9Ey4Mb7bkw8rLYV1
         0RuwKoycf3g3WXjStic2BCU8OBKffpbXd2+rI9d8AMHxn6Z6ly65xY6Kd0IMZLnSyae5
         IP6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=w/sWP3icaoF+XEK6f0GaAJeBiLDMnbjXq0MJchDYGEI=;
        b=xo4IT+Yv2FvtzJiMLkURFdyfC6JWb+CBiYsXzYq/VXCqQUNpyTKN30L6DWnBgAZ3nA
         DMf5r4B7quB4HClYLL/R8AGxQAOvnqUKqMRAFcXO8kqmnXQMCYHcHqSrNSkNOxhF5NQd
         uNAZK/7LAwz3qfP1fGnYwEWe0R8lcpIlqrhaXFYxUeLBnBT87IJjlRwUuHPN4eDhNDkQ
         r+arepWzHdf7cefoP+fO7vSXRecEwE0B2HJ1BwKsIysORr5Hni06Z2oOMoozycTwyRGo
         /IFRTg4t/KSCSXj2oYr0AAICFX4IupXMziNh5tpl6YyoygLvSUaXXGjj8aDmtv8QQVwh
         VIRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="BlxMYaM/";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w/sWP3icaoF+XEK6f0GaAJeBiLDMnbjXq0MJchDYGEI=;
        b=gSNf7wghFKaIrzPJYYRShkopKXXD7N93xV3iw2BPmTfI/3rG2zRdT/nmEm3WsVwr4g
         Xvcb3K/FqlHR81Ehx+9ZfQvSK73feIb/f8l8WGSxVGCRZUet/QemMmpFfDb+ha40+NJW
         VMnW53uCsalc9peBghyV+QUV1vjB4PuLHDh5b0nhxi3kj20qw1VBVgYahismpiz+sIg2
         mhh871lJYxqVyjdt3O/N3tNWWY63rRLs5uhryStx3Lgc62tdtJMeP9QlsvVjMIE0n8D0
         bsKHDuq+vnQZINSiPCqFnOVinegmMcRToTTo58mljLQfmowSPSOjN9zxg/3JbnvTu3k5
         TYrw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w/sWP3icaoF+XEK6f0GaAJeBiLDMnbjXq0MJchDYGEI=;
        b=JpDvJaeUWcoCbUmwda86xMtdPSjshHznMmC9TcnIWk5rOOivupVChXltu620O54TRN
         87yKT4ITNmuqevN2P1mi54ZeV5qOwBrO2F5/BSU+CZEaJIaT2EMjXsIcnLsn1GzhNT/j
         +tlF2M8GoRorShofAt9jsOirvMie/Ekcc4hOenrlnxvqSq4L9/X7ooIfh59vmuZUzIKb
         upfT8K1wKyEcisnEk5r6h4aNYx52vPZhRncx0jrVGuyx2Xlr6zAU5kt6ZDH5pAFet3lW
         Gy01ciHLA3FooSYdDgKrmQLXf1NDfEwzovrGHboyJi3h3M1Q/iivE/yrrUkgN0+iXsMz
         AGgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5327QAV8QZ6ydVEr7VWcy9hwlXysaixlEnKhAnqoKs8uoCYJX9D1
	SBwDmUpoJAJOQA2bnDA5Jig=
X-Google-Smtp-Source: ABdhPJxRCGJ1cjAhx1T7zmGb8RLjWvu7lFzTFvjp0/X6oT+udt5+mpTnWpYzwQ8wsGtb5tlcmKkbZA==
X-Received: by 2002:a25:d846:: with SMTP id p67mr1971912ybg.386.1633036853364;
        Thu, 30 Sep 2021 14:20:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b981:: with SMTP id r1ls1050870ybg.8.gmail; Thu, 30 Sep
 2021 14:20:52 -0700 (PDT)
X-Received: by 2002:a25:e906:: with SMTP id n6mr1576820ybd.248.1633036852759;
        Thu, 30 Sep 2021 14:20:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1633036852; cv=none;
        d=google.com; s=arc-20160816;
        b=sMsJd9880Z149Z2zL4/TpE4qX8gp1OZ3feAj/WQTO+XePnGH1JjjMatQNVTFMj9nZJ
         jB8TCwAs1hlWwXLQDhuOIcO0YGb7R1uvbEEVSLkndsyCEyue9/7VM7MiKGjnGZJXau5Y
         8f4JlJlhI441sfn6v3hYgkaW766tRtIUTBwNUHQZZhj0VrcdbcpG6wxR6Ax1buvUHJkx
         tGOqso9bdjyMxENRwNPQF3ZK0gvl+9Bqp5AlqDTYU9ydorCi4WWG0uAbQep5aWA5UTb5
         eV1nSqY+iu1PtumfJPDLybgl1KS5ET0Is+9zZIZWrRJUEKc0wMuWRvKEU4Hp1PU92VRC
         l+OQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=h/TBKn03dF9IntMFcuDE9WlvX4rnNMcxTnYaxfj4f3M=;
        b=nJlHAoA4iF6mXG2t0chUaBF+7JOT19InZlxhGTy2InV6yhxBCSbp6+35hOwuyT+Nlv
         keCvqkCE+5he4fA+hzUotwBcSqYbDKB5t4gn8lkqU/miZNE5GvbDU8jp2mVo0Aq0lACM
         VNRjapdV3YOPRtt5nBwiWQusggN244Yixpimnf89mPdqD/fleykWYhEFPXcJCMDGDq5I
         GPzIoe+h8uqkC4W7ZYaCV7rArBjjOAN1FE4Q9Es6vtGT969skmOlwzUNd6jyig+5AOwQ
         vheT5PVorEtmRFcftyP9o1LcRA2/BABrLxQSUAownI0RpRwubbyFBPb2BAN6KvV1IfVS
         WhBg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b="BlxMYaM/";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-qt1-x831.google.com (mail-qt1-x831.google.com. [2607:f8b0:4864:20::831])
        by gmr-mx.google.com with ESMTPS id k1si254030ybp.1.2021.09.30.14.20.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Sep 2021 14:20:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2607:f8b0:4864:20::831 as permitted sender) client-ip=2607:f8b0:4864:20::831;
Received: by mail-qt1-x831.google.com with SMTP id j13so7112431qtq.6
        for <kasan-dev@googlegroups.com>; Thu, 30 Sep 2021 14:20:52 -0700 (PDT)
X-Received: by 2002:aed:2791:: with SMTP id a17mr8658769qtd.193.1633036851603;
        Thu, 30 Sep 2021 14:20:51 -0700 (PDT)
Received: from mail-yb1-f172.google.com (mail-yb1-f172.google.com. [209.85.219.172])
        by smtp.gmail.com with ESMTPSA id w9sm2021010qki.80.2021.09.30.14.20.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Sep 2021 14:20:50 -0700 (PDT)
Received: by mail-yb1-f172.google.com with SMTP id s64so13196677yba.11
        for <kasan-dev@googlegroups.com>; Thu, 30 Sep 2021 14:20:50 -0700 (PDT)
X-Received: by 2002:a25:df06:: with SMTP id w6mr1562849ybg.459.1633036849801;
 Thu, 30 Sep 2021 14:20:49 -0700 (PDT)
MIME-Version: 1.0
References: <20210930185031.18648-1-rppt@kernel.org>
In-Reply-To: <20210930185031.18648-1-rppt@kernel.org>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Thu, 30 Sep 2021 14:20:33 -0700
X-Gmail-Original-Message-ID: <CAHk-=wjS76My8aJLWJAHd-5GnMEVC1D+kV7DgtV9GjcbtqZdig@mail.gmail.com>
Message-ID: <CAHk-=wjS76My8aJLWJAHd-5GnMEVC1D+kV7DgtV9GjcbtqZdig@mail.gmail.com>
Subject: Re: [PATCH v2 0/6] memblock: cleanup memblock_free interface
To: Mike Rapoport <rppt@kernel.org>
Cc: Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Andrew Morton <akpm@linux-foundation.org>, 
	Christophe Leroy <christophe.leroy@csgroup.eu>, Juergen Gross <jgross@suse.com>, 
	Mike Rapoport <rppt@linux.ibm.com>, Shahab Vahedi <Shahab.Vahedi@synopsys.com>, 
	devicetree <devicetree@vger.kernel.org>, iommu <iommu@lists.linux-foundation.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>, 
	alpha <linux-alpha@vger.kernel.org>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	linux-efi <linux-efi@vger.kernel.org>, 
	"open list:BROADCOM NVRAM DRIVER" <linux-mips@vger.kernel.org>, Linux-MM <linux-mm@kvack.org>, 
	linux-riscv <linux-riscv@lists.infradead.org>, linux-s390 <linux-s390@vger.kernel.org>, 
	Linux-sh list <linux-sh@vger.kernel.org>, 
	"open list:SYNOPSYS ARC ARCHITECTURE" <linux-snps-arc@lists.infradead.org>, 
	linux-um <linux-um@lists.infradead.org>, linux-usb@vger.kernel.org, 
	linuxppc-dev <linuxppc-dev@lists.ozlabs.org>, linux-sparc <sparclinux@vger.kernel.org>, 
	xen-devel@lists.xenproject.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b="BlxMYaM/";
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2607:f8b0:4864:20::831 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Thu, Sep 30, 2021 at 11:50 AM Mike Rapoport <rppt@kernel.org> wrote:
>
> The first patch is a cleanup of numa_distance allocation in arch_numa I've
> spotted during the conversion.
> The second patch is a fix for Xen memory freeing on some of the error
> paths.

Well, at least patch 2 looks like something that should go into 5.15
and be marked for stable.

Patch 1 looks like a trivial local cleanup, and could go in
immediately. Patch 4 might be in that same category.

The rest look like "next merge window" to me, since they are spread
out and neither bugfixes nor tiny localized cleanups (iow renaming
functions, global resulting search-and-replace things).

So my gut feel is that two (maybe three) of these patches should go in
asap, with three (maybe four) be left for 5.16.

IOW, not trat this as a single series.

Hmm?

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwjS76My8aJLWJAHd-5GnMEVC1D%2BkV7DgtV9GjcbtqZdig%40mail.gmail.com.
