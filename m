Return-Path: <kasan-dev+bncBCD3PVFVQENBBEEN2LWAKGQEBZCTC2Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id 56EE3C8708
	for <lists+kasan-dev@lfdr.de>; Wed,  2 Oct 2019 13:14:25 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id 11sf17907440qkh.15
        for <lists+kasan-dev@lfdr.de>; Wed, 02 Oct 2019 04:14:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570014864; cv=pass;
        d=google.com; s=arc-20160816;
        b=UTztV1D63M+h3v0FME/2GRdTCY6KjOF7OJxxyej8c1SYp9JwvVhNjLXGKqXxCB60J6
         xEEO1j2TNH+i64WbgynQpZA88JsIRvylWTj+QOf6IUcleDPswCZ47S3rYxoaGhffqmk7
         hM+84raDGzhp/XRVF6/5AxexaCN7Nxp6XymHwtL7jYzmkldZPTcS528mxCd9U5633oJo
         5BzVfxMtTui/AJfly5zNcWoqzuAZd3LyiUL0uj4QwGbjsKKUk5bynkcgVLms9beQ5Edb
         tTAVw/HlXgpLokGNjf72XrW9ba8TaUsN7szjHU3ttGcPSnQqq0zAPzxPYgIymWvvHqXR
         L7FA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=hTeGA97hpNgDvy8m5+gzuu0y2wNlbhzASrPNFxpt0MQ=;
        b=oD03coU5l0rAJ3OLHkGEc7C2GWNovt9rXm4nFlqY7kVlbAU+/Qv9It5iaa+/AKVGVb
         HJSLfA8fT1O+MeUUs4xQ2SRYFI5wTrvhav7Ov7b8OqXCh4vxkyNseKQ8/0hIGIrhqO2E
         y2/7WPDbEA3ROCxmuzzMDi8Uz+x+l35FaqnU8DVLsSrwqtnPUtarxGH/JxAK/JPLZHOH
         MjXPXl6bng1qIJQv5gnlHy2If9cHB71fUFSkGKVb9K7zPKG1dhZLUntP1A+wvWtqt+bp
         ACKLnQe6JylQD1J0qXV/d7Le2mGKHTD9AQaxSKs5ARTDcIsxMdSR8EwpEbyvJ7V4rCYr
         ZXiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vHy1Q0oW;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hTeGA97hpNgDvy8m5+gzuu0y2wNlbhzASrPNFxpt0MQ=;
        b=MzvwlOsgDrcDAQEoLs/qK3P6TlPOjq8FdAgHLaz2HEFQQEHKj7yMTH/I51c1IgCF/V
         rET+i8DNW5YAovLi2sXxOAx1QDnb8XJ6oZWprShvi5d0eaBI/veDAw8+btRocY/1tvc4
         AT2V3Yp8l4gP4bx/SydC1XJUmjZTVIpDAWGGFKObqCr18+rTaey8690cSFI8OYHbuq8W
         yPLXwGvv/S0IovVqasmxGNd2x0kLnkdUiaOxfOmrgK/G9J12PIMtpvW8K6spvISqw7ko
         7KAsZc0OhuKMQZU/sR7q4teoeL3nXLrL0jmqEBU29gvA82DSGPXIJ+3PZRSqbHCw00rm
         4kwg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hTeGA97hpNgDvy8m5+gzuu0y2wNlbhzASrPNFxpt0MQ=;
        b=sH2lwbnE9TdwqLeQKDYUyJjHRdn5GOBnHyfTDA2mOezHnzNhLLTtCChR75jD1W6jPa
         E1kO37W8fyl+7+a/3E3F17ZKrb1fMLzOzHqFUqt+4MkA4jkxAJcLJJPfoNRvxn6eHd+7
         6oPvypWtA/kFfH/g9c+VOskNoktrj4PcZrFwqc5RtWt+EKbpZfdIw6ZMJEBfVb9drn0x
         9+kA252SOOGqf8dq7mMVN+qv0YxgtCfYGOiML1aakCvRS5wA6Vbzm1Lh7CrvGh6aBq7I
         9vZiQoMpESEIQWl0QA7YhQ7M8UVvzLqN99n5udvIxZa+pja1JhqzaTzTNlMgKyBjnHI8
         y2mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hTeGA97hpNgDvy8m5+gzuu0y2wNlbhzASrPNFxpt0MQ=;
        b=NNg2DH7C1Y7tFavNG2SkvFvdOtcwXlC3oJ/i5iJ+mqgxjVbyQN6++o55TCFhotJN4J
         NbI+5pRA5mBBkht383lv3Z/tdt6d48giak1OWtDa7V6IMV0K6CYNRiQyy0G0knMPytrZ
         CCV07+k78aR6dDhCmPlJkIaJxHMtk82EKcEkTaYeOXNprecV7bMgyF2Is8plPfry5t7N
         7HRQmlZyr1L/bIV+/sNKjS9ti+l0fnJboHrzgU1xMziCvcYfOepbEtP0eWOa9nbkjzTc
         hfyv+WuQHOQF3Mhh1Nn9Eq+8fKn+xaVKMMNRLtayH0VIUpVGowGaYWqbexbasLbSujUr
         kkQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVGyB0Cpt6Wn0q0mbgmt90Btdg061DcfUZBsGQiddS/8mnWfB5M
	Pwoz3od82gK8k+pP4E+kz+4=
X-Google-Smtp-Source: APXvYqw5PqrQMBfGVT9vj7c6DH751aM7OPB1TlmuUuX2TLceExzo1RA2gMbCFXX3YBn9D4lUfdHyPQ==
X-Received: by 2002:ac8:5181:: with SMTP id c1mr3454944qtn.29.1570014864271;
        Wed, 02 Oct 2019 04:14:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aed:3f5a:: with SMTP id q26ls532735qtf.13.gmail; Wed, 02 Oct
 2019 04:14:23 -0700 (PDT)
X-Received: by 2002:ac8:45da:: with SMTP id e26mr3291035qto.75.1570014863892;
        Wed, 02 Oct 2019 04:14:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570014863; cv=none;
        d=google.com; s=arc-20160816;
        b=XAhdxh9xXGx0SdD8SEixJhIkb+s1+oKVqaI7x5o3Fsi4uiO8VFPzb1Xb0rdSqFdxhl
         Vc/mNuZhmF31nIT9GVSb+jncUrGiBzxkVnoPP1OJYJbVVCFQCfrZpl+YbqQL3W4VPdPS
         rhfQPZh2NkbkGa+flJTkGgomCC9mx7iP0jWVFPyOgIXsn7Z6j1HWtwNc+RKriZfTBNea
         9Mmf4miGc1vc9aF0BiNJFt77I7IBQSajdI9INqk99uXdTlRO/73NmNQMKkCa157dAe6q
         KdsN/L0lrSmSfJ3wyrLoQbwyn8WTQNz4yUTwnl5pekXWSZzAYbBiEB3FmQD8zbe2wqrB
         E3pA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=ZB4/wBe40ScWLOPnOnO2A5CCUN+N+AU8kGY9PrjNkCo=;
        b=Io/A0wQFSkViJbwrNdTtSCqgUxAihfAyUsiSxjTDrwBuYCSNghDJ8Tu8ycDO7US3zQ
         hSvs8ffQMDWXtDrMGDsWgvU/UT9kJOs91WfzcA4JliM3FU4YFZY9iUF4n9QTQeNG20t8
         GW9CJwhQgPqnQpTY0TSvSJcloX1RWneustO7+wgOSSrLm2GF7j11k11mhZ/L9bl8Ixcr
         QJ04O6A4bbx1CGIpQHE0xLsXd0lNzb5HjjhAhAW0s2uE9c3AzqjWkFLgZPxjvmfbMoRT
         v9H4RmhRjHGutdTJs07m6D0Frz/fjqc/LMRhE6JPqzSt/fEf0+mXVxj4rCjiSMsTvEl8
         ye5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=vHy1Q0oW;
       spf=pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d42 as permitted sender) smtp.mailfrom=aford173@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-io1-xd42.google.com (mail-io1-xd42.google.com. [2607:f8b0:4864:20::d42])
        by gmr-mx.google.com with ESMTPS id t187si693343qkd.0.2019.10.02.04.14.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 02 Oct 2019 04:14:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d42 as permitted sender) client-ip=2607:f8b0:4864:20::d42;
Received: by mail-io1-xd42.google.com with SMTP id w12so27804505iol.11
        for <kasan-dev@googlegroups.com>; Wed, 02 Oct 2019 04:14:23 -0700 (PDT)
X-Received: by 2002:a6b:d601:: with SMTP id w1mr2668972ioa.158.1570014862922;
 Wed, 02 Oct 2019 04:14:22 -0700 (PDT)
MIME-Version: 1.0
References: <CAHCN7x+Jv7yGPoB0Gm=TJ30ObLJduw2XomHkd++KqFEURYQcGg@mail.gmail.com>
 <CAOMZO5A_U4aYC4XZXK1r9JaLg-eRdXy8m6z4GatQp62rK4HZ6A@mail.gmail.com>
 <CAHCN7xJdzEppn8-74SvzACsA25bUHGdV7v=CfS08xzSi59Z2uw@mail.gmail.com>
 <CAOMZO5D2uzR6Sz1QnX3G-Ce_juxU-0PO_vBZX+nR1mpQB8s8-w@mail.gmail.com>
 <CAHCN7xJ32BYZu-DVTVLSzv222U50JDb8F0A_tLDERbb8kPdRxg@mail.gmail.com>
 <20190926160433.GD32311@linux.ibm.com> <CAHCN7xL1sFXDhKUpj04d3eDZNgLA1yGAOqwEeCxedy1Qm-JOfQ@mail.gmail.com>
 <20190928073331.GA5269@linux.ibm.com> <CAHCN7xJEvS2Si=M+BYtz+kY0M4NxmqDjiX9Nwq6_3GGBh3yg=w@mail.gmail.com>
 <CAHCN7xKLhWw4P9-sZKXQcfSfh2r3J_+rLxuxACW0UVgimCzyVw@mail.gmail.com> <20191002073605.GA30433@linux.ibm.com>
In-Reply-To: <20191002073605.GA30433@linux.ibm.com>
From: Adam Ford <aford173@gmail.com>
Date: Wed, 2 Oct 2019 06:14:11 -0500
Message-ID: <CAHCN7xL1MkJh44N3W_1+08DHmX__SqnfH6dqUzYzr2Wpg0kQyQ@mail.gmail.com>
Subject: Re: [PATCH v2 00/21] Refine memblock API
To: Mike Rapoport <rppt@linux.ibm.com>
Cc: Fabio Estevam <festevam@gmail.com>, Rich Felker <dalias@libc.org>, linux-ia64@vger.kernel.org, 
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
 header.i=@gmail.com header.s=20161025 header.b=vHy1Q0oW;       spf=pass
 (google.com: domain of aford173@gmail.com designates 2607:f8b0:4864:20::d42
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

On Wed, Oct 2, 2019 at 2:36 AM Mike Rapoport <rppt@linux.ibm.com> wrote:
>
> Hi Adam,
>
> On Tue, Oct 01, 2019 at 07:14:13PM -0500, Adam Ford wrote:
> > On Sun, Sep 29, 2019 at 8:33 AM Adam Ford <aford173@gmail.com> wrote:
> > >
> > > I am attaching two logs.  I now the mailing lists will be unhappy, but
> > >  don't want to try and spam a bunch of log through the mailing liast.
> > > The two logs show the differences between the working and non-working
> > > imx6q 3D accelerator when trying to run a simple glmark2-es2-drm demo.
> > >
> > > The only change between them is the 2 line code change you suggested.
> > >
> > > In both cases, I have cma=128M set in my bootargs.  Historically this
> > > has been sufficient, but cma=256M has not made a difference.
> > >
> >
> > Mike any suggestions on how to move forward?
> > I was hoping to get the fixes tested and pushed before 5.4 is released
> > if at all possible
>
> I have a fix (below) that kinda restores the original behaviour, but I
> still would like to double check to make sure it's not a band aid and I
> haven't missed the actual root cause.
>
> Can you please send me your device tree definition and the output of
>
> cat /sys/kernel/debug/memblock/memory
>
> and
>
> cat /sys/kernel/debug/memblock/reserved
>
> Thanks!
>

Before the patch:

# cat /sys/kernel/debug/memblock/memory
   0: 0x10000000..0x8fffffff
# cat /sys/kernel/debug/memblock/reserved
   0: 0x10004000..0x10007fff
   1: 0x10100000..0x11ab141f
   2: 0x1fff1000..0x1fffcfff
   3: 0x2ee40000..0x2ef53fff
   4: 0x2ef56940..0x2ef56c43
   5: 0x2ef56c48..0x2fffefff
   6: 0x2ffff0c0..0x2ffff4d8
   7: 0x2ffff500..0x2ffff55f
   8: 0x2ffff580..0x2ffff703
   9: 0x2ffff740..0x2ffff918
  10: 0x2ffff940..0x2ffff9cf
  11: 0x2ffffa00..0x2ffffa0f
  12: 0x2ffffa40..0x2ffffa43
  13: 0x2ffffa80..0x2ffffad5
  14: 0x2ffffb00..0x2ffffb55
  15: 0x2ffffb80..0x2ffffbd5
  16: 0x2ffffc00..0x2ffffc4e
  17: 0x2ffffc50..0x2ffffc6a
  18: 0x2ffffc6c..0x2ffffce6
  19: 0x2ffffce8..0x2ffffd02
  20: 0x2ffffd04..0x2ffffd1e
  21: 0x2ffffd20..0x2ffffd3a
  22: 0x2ffffd3c..0x2ffffd56
  23: 0x2ffffd58..0x2ffffe30
  24: 0x2ffffe34..0x2ffffe4c
  25: 0x2ffffe50..0x2ffffe68
  26: 0x2ffffe6c..0x2ffffe84
  27: 0x2ffffe88..0x2ffffea0
  28: 0x2ffffea4..0x2ffffebc
  29: 0x2ffffec0..0x2ffffedf
  30: 0x2ffffee4..0x2ffffefc
  31: 0x2fffff00..0x2fffff13
  32: 0x2fffff28..0x2fffff4b
  33: 0x2fffff50..0x2fffff84
  34: 0x2fffff88..0x3fffffff


After the patch:
# cat /sys/kernel/debug/memblock/memory
   0: 0x10000000..0x8fffffff
# cat /sys/kernel/debug/memblock/reserved
   0: 0x10004000..0x10007fff
   1: 0x10100000..0x11ab141f
   2: 0x1fff1000..0x1fffcfff
   3: 0x3eec0000..0x3efd3fff
   4: 0x3efd6940..0x3efd6c43
   5: 0x3efd6c48..0x3fffbfff
   6: 0x3fffc0c0..0x3fffc4d8
   7: 0x3fffc500..0x3fffc55f
   8: 0x3fffc580..0x3fffc703
   9: 0x3fffc740..0x3fffc918
  10: 0x3fffc940..0x3fffc9cf
  11: 0x3fffca00..0x3fffca0f
  12: 0x3fffca40..0x3fffca43
  13: 0x3fffca80..0x3fffca83
  14: 0x3fffcac0..0x3fffcb15
  15: 0x3fffcb40..0x3fffcb95
  16: 0x3fffcbc0..0x3fffcc15
  17: 0x3fffcc28..0x3fffcc72
  18: 0x3fffcc74..0x3fffcc8e
  19: 0x3fffcc90..0x3fffcd0a
  20: 0x3fffcd0c..0x3fffcd26
  21: 0x3fffcd28..0x3fffcd42
  22: 0x3fffcd44..0x3fffcd5e
  23: 0x3fffcd60..0x3fffcd7a
  24: 0x3fffcd7c..0x3fffce54
  25: 0x3fffce58..0x3fffce70
  26: 0x3fffce74..0x3fffce8c
  27: 0x3fffce90..0x3fffcea8
  28: 0x3fffceac..0x3fffcec4
  29: 0x3fffcec8..0x3fffcee0
  30: 0x3fffcee4..0x3fffcefc
  31: 0x3fffcf00..0x3fffcf1f
  32: 0x3fffcf28..0x3fffcf53
  33: 0x3fffcf68..0x3fffcf8b
  34: 0x3fffcf90..0x3fffcfac
  35: 0x3fffcfb0..0x3fffffff
  36: 0x80000000..0x8fffffff

> From 06529f861772b7dea2912fc2245debe4690139b8 Mon Sep 17 00:00:00 2001
> From: Mike Rapoport <rppt@linux.ibm.com>
> Date: Wed, 2 Oct 2019 10:14:17 +0300
> Subject: [PATCH] mm: memblock: do not enforce current limit for memblock_phys*
>  family
>
> Until commit 92d12f9544b7 ("memblock: refactor internal allocation
> functions") the maximal address for memblock allocations was forced to
> memblock.current_limit only for the allocation functions returning virtual
> address. The changes introduced by that commit moved the limit enforcement
> into the allocation core and as a result the allocation functions returning
> physical address also started to limit allocations to
> memblock.current_limit.
>
> This caused breakage of etnaviv GPU driver:
>
> [    3.682347] etnaviv etnaviv: bound 130000.gpu (ops gpu_ops)
> [    3.688669] etnaviv etnaviv: bound 134000.gpu (ops gpu_ops)
> [    3.695099] etnaviv etnaviv: bound 2204000.gpu (ops gpu_ops)
> [    3.700800] etnaviv-gpu 130000.gpu: model: GC2000, revision: 5108
> [    3.723013] etnaviv-gpu 130000.gpu: command buffer outside valid
> memory window
> [    3.731308] etnaviv-gpu 134000.gpu: model: GC320, revision: 5007
> [    3.752437] etnaviv-gpu 134000.gpu: command buffer outside valid
> memory window
> [    3.760583] etnaviv-gpu 2204000.gpu: model: GC355, revision: 1215
> [    3.766766] etnaviv-gpu 2204000.gpu: Ignoring GPU with VG and FE2.0
>
> Restore the behaviour of memblock_phys* family so that these functions will
> not enforce memblock.current_limit.
>

This fixed the issue.  Thank you

Tested-by: Adam Ford <aford173@gmail.com> #imx6q-logicpd

> Fixes: 92d12f9544b7 ("memblock: refactor internal allocation functions")
> Reported-by: Adam Ford <aford173@gmail.com>
> Signed-off-by: Mike Rapoport <rppt@linux.ibm.com>
> ---
>  mm/memblock.c | 6 +++---
>  1 file changed, 3 insertions(+), 3 deletions(-)
>
> diff --git a/mm/memblock.c b/mm/memblock.c
> index 7d4f61a..c4b16ca 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -1356,9 +1356,6 @@ static phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
>                 align = SMP_CACHE_BYTES;
>         }
>
> -       if (end > memblock.current_limit)
> -               end = memblock.current_limit;
> -
>  again:
>         found = memblock_find_in_range_node(size, align, start, end, nid,
>                                             flags);
> @@ -1469,6 +1466,9 @@ static void * __init memblock_alloc_internal(
>         if (WARN_ON_ONCE(slab_is_available()))
>                 return kzalloc_node(size, GFP_NOWAIT, nid);
>
> +       if (max_addr > memblock.current_limit)
> +               max_addr = memblock.current_limit;
> +
>         alloc = memblock_alloc_range_nid(size, align, min_addr, max_addr, nid);
>
>         /* retry allocation without lower limit */
> --
> 2.7.4
>
>
> > > adam
> > >
> > > On Sat, Sep 28, 2019 at 2:33 AM Mike Rapoport <rppt@linux.ibm.com> wrote:
> > > >
> > > > On Thu, Sep 26, 2019 at 02:35:53PM -0500, Adam Ford wrote:
> > > > > On Thu, Sep 26, 2019 at 11:04 AM Mike Rapoport <rppt@linux.ibm.com> wrote:
> > > > > >
> > > > > > Hi,
> > > > > >
> > > > > > On Thu, Sep 26, 2019 at 08:09:52AM -0500, Adam Ford wrote:
> > > > > > > On Wed, Sep 25, 2019 at 10:17 AM Fabio Estevam <festevam@gmail.com> wrote:
> > > > > > > >
> > > > > > > > On Wed, Sep 25, 2019 at 9:17 AM Adam Ford <aford173@gmail.com> wrote:
> > > > > > > >
> > > > > > > > > I tried cma=256M and noticed the cma dump at the beginning didn't
> > > > > > > > > change.  Do we need to setup a reserved-memory node like
> > > > > > > > > imx6ul-ccimx6ulsom.dtsi did?
> > > > > > > >
> > > > > > > > I don't think so.
> > > > > > > >
> > > > > > > > Were you able to identify what was the exact commit that caused such regression?
> > > > > > >
> > > > > > > I was able to narrow it down the 92d12f9544b7 ("memblock: refactor
> > > > > > > internal allocation functions") that caused the regression with
> > > > > > > Etnaviv.
> > > > > >
> > > > > >
> > > > > > Can you please test with this change:
> > > > > >
> > > > >
> > > > > That appears to have fixed my issue.  I am not sure what the impact
> > > > > is, but is this a safe option?
> > > >
> > > > It's not really a fix, I just wanted to see how exactly 92d12f9544b7 ("memblock:
> > > > refactor internal allocation functions") broke your setup.
> > > >
> > > > Can you share the dts you are using and the full kernel log?
> > > >
> > > > > adam
> > > > >
> > > > > > diff --git a/mm/memblock.c b/mm/memblock.c
> > > > > > index 7d4f61a..1f5a0eb 100644
> > > > > > --- a/mm/memblock.c
> > > > > > +++ b/mm/memblock.c
> > > > > > @@ -1356,9 +1356,6 @@ static phys_addr_t __init memblock_alloc_range_nid(phys_addr_t size,
> > > > > >                 align = SMP_CACHE_BYTES;
> > > > > >         }
> > > > > >
> > > > > > -       if (end > memblock.current_limit)
> > > > > > -               end = memblock.current_limit;
> > > > > > -
> > > > > >  again:
> > > > > >         found = memblock_find_in_range_node(size, align, start, end, nid,
> > > > > >                                             flags);
> > > > > >
> > > > > > > I also noticed that if I create a reserved memory node as was done one
> > > > > > > imx6ul-ccimx6ulsom.dtsi the 3D seems to work again, but without it, I
> > > > > > > was getting errors regardless of the 'cma=256M' or not.
> > > > > > > I don't have a problem using the reserved memory, but I guess I am not
> > > > > > > sure what the amount should be.  I know for the video decoding 1080p,
> > > > > > > I have historically used cma=128M, but with the 3D also needing some
> > > > > > > memory allocation, is that enough or should I use 256M?
> > > > > > >
> > > > > > > adam
> > > > > >
> > > > > > --
> > > > > > Sincerely yours,
> > > > > > Mike.
> > > > > >
> > > >
> > > > --
> > > > Sincerely yours,
> > > > Mike.
> > > >
>
> --
> Sincerely yours,
> Mike.
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHCN7xL1MkJh44N3W_1%2B08DHmX__SqnfH6dqUzYzr2Wpg0kQyQ%40mail.gmail.com.
