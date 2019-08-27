Return-Path: <kasan-dev+bncBAABB6XFSPVQKGQEL236WYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id 594399E3A8
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Aug 2019 11:08:11 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id f71sf14969218ybg.6
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Aug 2019 02:08:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1566896890; cv=pass;
        d=google.com; s=arc-20160816;
        b=QHZZ1+norCzal/0VK/vAKFzowzwPJCZYc8VMycGmg65Y8BXdLPkTwqQweWHNLaC/5l
         6OxI6vYwch82oQ+sr7Ckhx6m+r7NOG+TUIT23+HRsWLvN5FzD2cRj1+0xK9FrPojkpt0
         n3tyt7zyU2SsthD9YODTdmgQmJ4M+O/Xqksfy7vX0EgAsl4T9Yj6bpWkjflyCrSbVkBl
         vBX8O4G4BzZ9DexkhBpA6Pv8xb1yvCNIIxNSZlbjzfDLzLae3yFfaN9x5jzVvQ6qgayU
         JxmXN00TiExZwmajz/1+xi5rOn9izuMLPNArLnuPe2ZH8JD/forYfnlk3hUM/jdB55g+
         sCew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=AGOYqcdH4dzWuIOXu1LSpb9VrHexvcZellHbL4wrDTU=;
        b=wcg7b5dzbDbmJ/6KsWVw7DApj7Q3sWIQEiXuj75N/hld1gVOpR+IGILf9GB+HaQN93
         fcQAVD1CtCqxoTSKBWVJdWyvlyyXQLY/1MJGsoZjvmO7hZ8ZGl46oJ3AhX753KfKXpMs
         R6VkSAoJFJDAj7eslAysNcX8aw33kN96oU2Ib7Z1pOCTlQhgOSwxR88+Zv3Ls0t8DIHW
         FjlVCD9LVpO33hXCZQ/foVLaTaAsLdX+i25kU28liOvQJ63zqiptoFIt+Q2eNcpZv6So
         8zsBc4JSJfSNkHg1JRBOgR4cjy61sd/ElzGQigJqg3+FdHuoIFrBn6N/OQrr1oaQ0bx+
         0tUQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=AGOYqcdH4dzWuIOXu1LSpb9VrHexvcZellHbL4wrDTU=;
        b=Ef87akp4Et3b6jCKraHU3cUadErrebPyI20qetMK8/msvz0laDkw31dHaOY2j2WkDr
         7NdRkPcXT3krbl1aTOTGUR2l0jHk3SuARqSa/9zGqKz8jr/ni8AB7wE5lIo4t0Rip/9i
         PjFsyETfSwHsH8lIcts50NukJXyWqPBh8w7ompjNyCKZ9Vc9sWO1Zy8BNKYPI16yAHB8
         U7Any5l4oC8AVe2lM4cDG51fZsMydoZag7MwBb8URZgeCxb0egTIw7nXgeKzPQsjAUmA
         5L5cWjVNQPUS6ijUzQMJMNbPAkbV2orgVY11rtsxq2fr5udzc1+0k7kdkIVfI+I0DoWB
         FDsQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=AGOYqcdH4dzWuIOXu1LSpb9VrHexvcZellHbL4wrDTU=;
        b=aj5b+1J4bJkj2oZA79xUBl2Jbr2GYnnn3u29wS09EIUhMl6K4cBgac7SOuzXUXYmOv
         nv1xONstgFd1wyLNhmt6hLOQOUqfUowsoJ/5+m57xI/t3RaDGi/PTJN8jGcayEUm9VkC
         RvyynCEqWCHix1u1moGDU7eQPPKSLbQTyWK4NX+DD7glmcLNsyMxc1MXLaDmds4H0VRI
         mdBSJzarg/9PxB6COoOcb+Ty006RDSndft8ANlyM0CXXUg0gEviT08FVI1sRFfN0xjAR
         kWCCBv5K6aGEJokApDoNwpVmRytLI/uomihTHiMLCpWWeQGYX3ZoxF2IfT7l+YH/zq7Y
         PIEw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWcMTZASPOHnlqWw+HcYsPjeDlDRwQ1Ykb6A3kS1NB3HrcNsIN/
	VqmcnkO65a9CjWHwBgIbx3s=
X-Google-Smtp-Source: APXvYqx/pzi/CfHcwB5hX5mQ7p6mZohjPmiahTAcvzoZHC9LfFncakH0xPmJeQSecKxMmw9fa63H9Q==
X-Received: by 2002:a81:3795:: with SMTP id e143mr16549609ywa.508.1566896890193;
        Tue, 27 Aug 2019 02:08:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:23d6:: with SMTP id j205ls5076193ybj.0.gmail; Tue, 27
 Aug 2019 02:08:09 -0700 (PDT)
X-Received: by 2002:a25:2692:: with SMTP id m140mr16857495ybm.74.1566896889944;
        Tue, 27 Aug 2019 02:08:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1566896889; cv=none;
        d=google.com; s=arc-20160816;
        b=W0Gi3DkIN3eoDmMHVi4/Dsf+c/rIRtnGQdBnb/IHz3owmOeHBgUqd2XcAuQM11tfUC
         qj2qL1A5HYm5NY36oTVakO7z2BcXnMBA2J7fR8mx3IEdnadeH/wbldG4TK2zqt3QkL8x
         pv0NdTP2CY7Lcu7F8gHWfO6Q1L7j5+/Te+MWkeO9HBcW2AhEtfBgDIZRCdsCev38AnL9
         HJHWU7Ad6oiBlj2wBKwZ6tnVk2bAHImnK4fz2+TJn8thptw52AxK58KAh7phU4zobR0e
         QzRFhB1IyCJIq3jpVVBw5xPb9pCN5BwHeXvnmI1rwxcr+DbX95Hq43RlGKxpQnHNhiw7
         Kl/g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=2u323hoz23rzmSW/OPwOW559Sh/TfGsEjIpq1hvDbHg=;
        b=qPCF6f1ZKjBGlGHyvF3WwBYHFht/GTKrok0fKB9C08CofLJgdNWnzeysxNQw5AUbOS
         mJbUY/AvxdpsE9SjTaobIzsgjXkyjQgEAsrDqTdoFwA1uc1O8ENH1KO6wKhrLY7V3KeZ
         jkUhfijTYAujPcabhTdNKwFM27AdPzJa2xp3iE5qOMSCpHcGq8qYIQUnWFge4/bXhwfo
         MmTg7DoXkVkgoMMRV1xR3R6s2Amx/4IeyUDUeWNVCtEb0pXhbm++8yWNAR2qtVUUMfUJ
         57oJK79DFtvaFTyulal1dp4pywdd4gpZeU2aHet4CQsdvBpEuJeQFOKhaA+CXMqB+r7x
         Fv1A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id r6si711564ybb.1.2019.08.27.02.08.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 27 Aug 2019 02:08:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x7R8t2G4072298;
	Tue, 27 Aug 2019 16:55:02 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Tue, 27 Aug 2019
 17:07:37 +0800
Date: Tue, 27 Aug 2019 17:07:38 +0800
From: Nick Hu <nickhu@andestech.com>
To: Andrey Ryabinin <aryabinin@virtuozzo.com>
CC: Alan Quey-Liang =?utf-8?B?S2FvKOmrmOmtgeiJryk=?= <alankao@andestech.com>,
        "paul.walmsley@sifive.com" <paul.walmsley@sifive.com>,
        "palmer@sifive.com"
	<palmer@sifive.com>,
        "aou@eecs.berkeley.edu" <aou@eecs.berkeley.edu>,
        "green.hu@gmail.com" <green.hu@gmail.com>,
        "deanbo422@gmail.com"
	<deanbo422@gmail.com>,
        "tglx@linutronix.de" <tglx@linutronix.de>,
        "linux-riscv@lists.infradead.org" <linux-riscv@lists.infradead.org>,
        "linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>,
        "glider@google.com" <glider@google.com>,
        "dvyukov@google.com"
	<dvyukov@google.com>,
        "Anup.Patel@wdc.com" <Anup.Patel@wdc.com>,
        "gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>,
        "alexios.zavras@intel.com" <alexios.zavras@intel.com>,
        "atish.patra@wdc.com"
	<atish.patra@wdc.com>,
        =?utf-8?B?6Zui6IG3Wm9uZyBab25nLVhpYW4gTGko5p2O5a6X5oayKQ==?=
	<zong@andestech.com>,
        "kasan-dev@googlegroups.com"
	<kasan-dev@googlegroups.com>
Subject: Re: [PATCH 1/2] riscv: Add memmove string operation.
Message-ID: <20190827090738.GA22972@andestech.com>
References: <cover.1565161957.git.nickhu@andestech.com>
 <a6c24ce01dc40da10d58fdd30bc3e1316035c832.1565161957.git.nickhu@andestech.com>
 <09d5108e-f0ba-13d3-be9e-119f49f6bd85@virtuozzo.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <09d5108e-f0ba-13d3-be9e-119f49f6bd85@virtuozzo.com>
User-Agent: Mutt/1.5.24 (2015-08-30)
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x7R8t2G4072298
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

Hi Andrey

On Thu, Aug 22, 2019 at 11:59:02PM +0800, Andrey Ryabinin wrote:
> On 8/7/19 10:19 AM, Nick Hu wrote:
> > There are some features which need this string operation for compilation,
> > like KASAN. So the purpose of this porting is for the features like KASAN
> > which cannot be compiled without it.
> > 
> 
> Compilation error can be fixed by diff bellow (I didn't test it).
> If you don't need memmove very early (before kasan_early_init()) than arch-specific not-instrumented memmove()
> isn't necessary to have.
> 
> ---
>  mm/kasan/common.c | 2 ++
>  1 file changed, 2 insertions(+)
> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index 6814d6d6a023..897f9520bab3 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -107,6 +107,7 @@ void *memset(void *addr, int c, size_t len)
>  	return __memset(addr, c, len);
>  }
>  
> +#ifdef __HAVE_ARCH_MEMMOVE
>  #undef memmove
>  void *memmove(void *dest, const void *src, size_t len)
>  {
> @@ -115,6 +116,7 @@ void *memmove(void *dest, const void *src, size_t len)
>  
>  	return __memmove(dest, src, len);
>  }
> +#endif
>  
>  #undef memcpy
>  void *memcpy(void *dest, const void *src, size_t len)
> -- 
> 2.21.0
> 
> 
> 
I have confirmed that the string operations are not used before kasan_early_init().
But I can't make sure whether other ARCHs would need it before kasan_early_init().
Do you have any idea to check that? Should I cc all other ARCH maintainers?

Nick

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190827090738.GA22972%40andestech.com.
