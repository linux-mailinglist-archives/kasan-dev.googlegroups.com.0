Return-Path: <kasan-dev+bncBCD3PVFVQENBBSNVVXWAKGQEMPIEGYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5909CBDDFB
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 14:17:15 +0200 (CEST)
Received: by mail-ot1-x33d.google.com with SMTP id z24sf3089487otq.6
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2019 05:17:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1569413834; cv=pass;
        d=google.com; s=arc-20160816;
        b=hI8/rcGuuB3M9UEb/37Rb+TcKO4YYCFpNtDAhfxC93JjxDq6+Tf+JITlsLEEXk/6dX
         NkMLpUHOcY3ODpeyjP833/8VFe3XSxP0dZs8cGrNKGjF1lUehneKr4HoqGj5UwgF5Jw6
         FL40ylYnU2oB+rV0Gy0O9298dIhXK1Z0Fc2kjpse0tvRcWHTrqHNMkZcOf74YLA0rKh7
         voLp3Sq4GQryehGFiw5kb5RzIYhOdO2TyD7XX9oMv3pHwuEqpGqeW+lct8KGxUqinQM0
         ysMTWiu+GL1AHnlLNL/10a9sJqfqQomsvYzywlmDbgR68y6MBh23eCNwSdOcnbxZNl8P
         n2ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=EHF09cBxnHLfF3kSh8/7rdk0S7hjW1wLhBKtAIOgvd8=;
        b=xcEhrWtqbSo8e5tto/YbMwKP64/FYyNWcVkfO59tyzp7xgfLXtLmNXm5BL/zWHaAP7
         n2wEVo2SEUXG9g44O1elL/6exfBgGaHiNMmvD5Zz/+p27hjMuHPJD7XsNDeQgN1iRWB0
         sqAVi5bsqU3dkhpYREfUBbDsRoWEgYDjZQB2M470o99ETlNn3vnq+7CwHbQuP4au0CV5
         SUTkQUWcRZTSbJC3CMe1cZVxLjrS6gV0+mh7UtvpYSVe3gE0zX6gIQ5lRK0X6cKERW4d
         RIoyGmZ+TfEPZKuYDVcLz2UoQ9D6h1jVS6xjr69aQl/vkbYaa6b7siuyrhJPoxf6k8pc
         LDiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=iUVK92GE;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EHF09cBxnHLfF3kSh8/7rdk0S7hjW1wLhBKtAIOgvd8=;
        b=LZ2kcj65XqhfEN7CZ7MFG+krqciVnk+yh180mGSSGId7GJ7O8K7eqByUkP+eRqp1fs
         7vZKHUNnQWcZLUe0zAYRmeT7K5aGZMCZ2/i+6tKVkPPOD0cvM/95K02JQpR1ng+wbGZd
         OFENvVM3RbanQho/tMk+tWRagZJoJfcj35ZaTGyPkVPFE64Fgfr/L1ArzE97wEWaaQ0J
         xlnOQiVSb0MytxlAi5MWLsizLeOQlsAQMXVfMF/B7oGHvCkZ7hHhBWzDQbll2jQLGGQp
         P9aW3r+OHwMMnygT7HOylg+UIqquZR174MdDKDTnTyjoO8hZxpkD8fVSn+8JE7cgX/mN
         21wQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EHF09cBxnHLfF3kSh8/7rdk0S7hjW1wLhBKtAIOgvd8=;
        b=Dl3036qHp3BSFy1QWm9CVQVSr7pb2tmBhOVhcxyYHPg6OccQOiyD2vMjoSq3lgfZpw
         jc4CbyEfAXMp81pk03QfFF62hNM/SXiHguKkw/XSkyL/7HmZkmH/r9ih6GzG4WG/g0PB
         EoCN5zTleDql2Puo5mRvHrpA78fGUfbpda60SkR9g53jV/rvNXeukzO/fp9UKBH6n9sb
         bwloYKFv213k1wLjBgteQNXT5dGZIQ9DHhsXGe6IsZq3D6urI8wS5OdhWeUyQFFgSfv9
         3toS0s25g0+Fei3WxJ1mSTK6oz+EcfQdRpKewGU8iz4kSyH1p1RnuVJ3NkWOhWSqBEai
         ZPBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EHF09cBxnHLfF3kSh8/7rdk0S7hjW1wLhBKtAIOgvd8=;
        b=cFS/s9uI2GMrNOGq+u5wfHdg1sVmkAepUrcP7pwsUS12m9izkjkLxFAeQoXeQkkIli
         hros3SuI2lxodIyn9f+cjR2l9AlY7GGhD/oGjejMSfRNFKoPXPAKxJCOVXHBQRPXA3Sp
         DzgvJKo/vo1BVo7v5m4WTx/QeWWRqa7M0yIJE8Va66QQczfAq4W4780zK9rt8FS7FRub
         W1PLe+bIDTaJlv2fPMYELgpT2eAe0wJxExaFSj4TEry5HYQlYZmZ/2jIU6NIy4pBzrwF
         AGVz7Qq4kSoarDeth9/UBvaXIDqkC2K+2NGFButJEqswSvAg1YfZ4v2C5fLktveHlzyV
         QjkQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWDytLq9s+O/Pwj+U5Zl/TE2qpBjFP5skjlEm2Zw4Hn4ZkC2XHm
	NshJz+x8xiNl7jIgq7242oo=
X-Google-Smtp-Source: APXvYqxw5jPXIzf90WbyvElM7q7oUGYTn58hiU/Taf2RgGf96mMidVFshVajXfwqmBNS6J3yB+KUyQ==
X-Received: by 2002:a9d:4b13:: with SMTP id q19mr5892667otf.202.1569413833959;
        Wed, 25 Sep 2019 05:17:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a54:4f98:: with SMTP id g24ls303878oiy.12.gmail; Wed, 25 Sep
 2019 05:17:13 -0700 (PDT)
X-Received: by 2002:aca:f50b:: with SMTP id t11mr4467020oih.1.1569413833665;
        Wed, 25 Sep 2019 05:17:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1569413833; cv=none;
        d=google.com; s=arc-20160816;
        b=pcKKg9sV19coHlrEUu6Y8h1AQvMlQT0CSbfhGJuGPsYo6x04qA7jSXMepJ2t8j3Fgt
         rN3UXY/GKk60QHeuhqULS7cmlvVYDDX6xR4+wiORyzGIuok88NNlXyifAtGybW+NgKqQ
         mgNqa0ZAd+trPjMMs2uRPL4Wyhm6gcJLdIYPHQ8c/SRJI9Wjhpqhbo9vRpuzneYJcFT7
         EmNIvBXcTIVwUrtupnt7g0gAVMEsCCRu+MmOVL0B0rmL4fACh+h1b/NOeuLIRbdHSDIj
         zC+VGsDjLma1Hzcwa/mEx2mjQiW2Y/0MoFkFdWex+aO3XRpBqtNQAfHm8kHko3aS2xTY
         hzaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Y4RvotBfrNK4XtLNNLx8Pazo7kMyOm8WMNbLFH6FEEU=;
        b=qubIg6MamGcofD5V3g8QKTIKTteWc5LsUufa59rk0t/qq7OxQZaB4X5Vv3W7d97+FU
         Ef8sGHuUVaqsknIR3rY69t4BlRkXstBxw5VTbVPpyau6s43BDZwukdQxXcplzqc4YlJt
         KL+q05oAfx8p3BaI8tXxCUgDjwi9yK0gcXBAppctJfp6bu5jmczQiVM2mvUGyDahirA8
         MSbIEW/bQDKBritHT0T0d0tVwTU9ZJUfqXEWwqcy7uqTlpA1ZS3Ay+wF6O4Zep+3hakl
         OzbJowAql1lefZm66L4qoM8fTMJintqx7L3dzm6420iJ+Qi6ZDnh00pg6GMmz9Y9h9Hc
         xGdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=iUVK92GE;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d44 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd44.google.com (mail-io1-xd44.google.com. [2607:f8b0:4864:20::d44])
        by gmr-mx.google.com with ESMTPS id m23si371097otl.4.2019.09.25.05.17.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Sep 2019 05:17:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d44 as permitted sender) client-ip=2607:f8b0:4864:20::d44;
Received: by mail-io1-xd44.google.com with SMTP id a1so13217025ioc.6
        for <kasan-dev@googlegroups.com>; Wed, 25 Sep 2019 05:17:13 -0700 (PDT)
X-Received: by 2002:a02:65cd:: with SMTP id u196mr4900191jab.3.1569413832794;
 Wed, 25 Sep 2019 05:17:12 -0700 (PDT)
MIME-Version: 1.0
References: <1548057848-15136-1-git-send-email-rppt@linux.ibm.com>
 <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com> <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
In-Reply-To: <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
From: Adam Ford <aford173@gmail.com>
Date: Wed, 25 Sep 2019 07:17:02 -0500
Message-ID: <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com>
Subject: Re: [PATCH v2 00/21] Refine memblock API
To: Fabio Estevam <festevam@gmail.com>
Cc: Mike Rapoport <rppt@linux.ibm.com>, Rich Felker <dalias@libc.org>, linux-ia64@vger.kernel.org, 
	Petr Mladek <pmladek@suse.com>, linux-sh@vger.kernel.org, 
	Catalin Marinas <catalin.marinas@arm.com>, Heiko Carstens <heiko.carstens@de.ibm.com>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>, Max Filippov <jcmvbkbc@gmail.com>, 
	Guo Ren <guoren@kernel.org>, Michael Ellerman <mpe@ellerman.id.au>, sparclinux@vger.kernel.org, 
	Christoph Hellwig <hch@lst.de>, linux-s390@vger.kernel.org, linux-c6x-dev@linux-c6x.org, 
	Yoshinori Sato <ysato@users.sourceforge.jp>, Richard Weinberger <richard@nod.at>, x86@kernel.org, 
	Russell King <linux@armlinux.org.uk>, kasan-dev <kasan-dev@googlegroups.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Mark Salter <msalter@redhat.com>, 
	Dennis Zhou <dennis@kernel.org>, Matt Turner <mattst88@gmail.com>, 
	linux-snps-arc@lists.infradead.org, uclinux-h8-devel@lists.sourceforge.jp, 
	devicetree <devicetree@vger.kernel.org>, linux-xtensa@linux-xtensa.org, 
	linux-um@lists.infradead.org, 
	The etnaviv authors <etnaviv@lists.freedesktop.org>, linux-m68k@lists.linux-m68k.org, 
	Rob Herring <robh+dt@kernel.org>, Greentime Hu <green.hu@gmail.com>, xen-devel@lists.xenproject.org, 
	Stafford Horne <shorne@gmail.com>, Guan Xuetao <gxt@pku.edu.cn>, 
	arm-soc <linux-arm-kernel@lists.infradead.org>, Michal Simek <monstr@monstr.eu>, 
	Tony Luck <tony.luck@intel.com>, Linux Memory Management List <linux-mm@kvack.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, USB list <linux-usb@vger.kernel.org>, 
	linux-mips@vger.kernel.org, Paul Burton <paul.burton@mips.com>, 
	Vineet Gupta <vgupta@synopsys.com>, linux-alpha@vger.kernel.org, 
	Andrew Morton <akpm@linux-foundation.org>, linuxppc-dev@lists.ozlabs.org, 
	"David S. Miller" <davem@davemloft.net>, openrisc@lists.librecores.org, 
	Chris Healy <cphealy@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: aford173@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=iUVK92GE;       spf=pass
 (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d44
 as permitted sender) smtp.mailfrom=aford173@gmail.com;       dmarc=pass
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

On Wed, Sep 25, 2019 at 7:12 AM Fabio Estevam <festevam@gmail.com> wrote:
>
> Hi Adam,
>
> On Wed, Sep 25, 2019 at 6:38 AM Adam Ford <aford173@gmail.com> wrote:
>
> > I know it's rather late, but this patch broke the Etnaviv 3D graphics
> > in my i.MX6Q.
> >
> > When I try to use the 3D, it returns some errors and the dmesg log
> > shows some memory allocation errors too:
> > [    3.682347] etnaviv etnaviv: bound 130000.gpu (ops gpu_ops)
> > [    3.688669] etnaviv etnaviv: bound 134000.gpu (ops gpu_ops)
> > [    3.695099] etnaviv etnaviv: bound 2204000.gpu (ops gpu_ops)
> > [    3.700800] etnaviv-gpu 130000.gpu: model: GC2000, revision: 5108
> > [    3.723013] etnaviv-gpu 130000.gpu: command buffer outside valid
> > memory window
> > [    3.731308] etnaviv-gpu 134000.gpu: model: GC320, revision: 5007
> > [    3.752437] etnaviv-gpu 134000.gpu: command buffer outside valid
> > memory window
>
> This looks similar to what was reported at:
> https://bugs.freedesktop.org/show_bug.cgi?id=111789
>
> Does it help if you use the same suggestion and pass cma=256M in your
> kernel command line?

I tried cma=256M and noticed the cma dump at the beginning didn't
change.  Do we need to setup a reserved-memory node like
imx6ul-ccimx6ulsom.dtsi did?

adam

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v%3DCfS08xzSi59Z2uw%40mail.gmail.com.
