Return-Path: <kasan-dev+bncBD4LX4523YGBBYHDRSLAMGQESMPNWBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id BF029565D7F
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 20:30:58 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id t24-20020a170902b21800b00168e27c3c2asf5494124plr.18
        for <lists+kasan-dev@lfdr.de>; Mon, 04 Jul 2022 11:30:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656959457; cv=pass;
        d=google.com; s=arc-20160816;
        b=VZysBFWtHNQabDmr7ywuLoA611msTY1Q8ck4kDVZ0AOgabRR3eTTHP83jj15g4ZYmk
         o5EB5PVO+26GaWLDInqHBvd5nUdcfZ3StoZ9JtuvDxhWrfm1ggjC+uwMHGhqkEU8K2eC
         znVQLLV4gjgww5JXh50ZtJlEGQhnuAKB7ya+iF6fOVrwUhmNcT8R68d4cOqQOtThYioe
         dvGRyQDAyE7nkHVOqxQtSa7ifvjiy6Lq4hK0qsH7pXiHblBPr75Vlc/s3+nMtmwPr6CY
         gYebsqrIco9l+q0FKlkJMc61d+jtALcs2SI4KsA4jdgjlR46MQhl0mqoVm2k7dwRCQWR
         BtnA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=fk5eZCY11M7jDNIfSSow666gphCXsyDq664u42NyXrE=;
        b=zC+wpSRJ4ssgbx/cWyzs28cYUTulRmZrCrU9M9IVyeSe16+UPOiHwycals4cLCmokr
         BmFITwoC5bzHqOOUYS2T+6L+uR9MqjDMwuQzMKcdHhyCnuA/FMx3oO9xstrDeGlScDzf
         8XJoDmDszQvmSUf22RMZUx6Gag+2ECCERY1oZBkWUEXMRCDUVejbsYGP+yzfx5r9Dk3P
         emWSf/nzI9KdW1UzAGqdZczlX08y5m0bJqITGZCUbje+MhCWvxj/JKfEJYmexlpsphqS
         5wlFKc4u0afP1XaM7yoje7amVGJz9Ut4+ETQGmC7ImyrXIUkA6aqU9CTBBNIBV1Mm3Zv
         rXIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=fk5eZCY11M7jDNIfSSow666gphCXsyDq664u42NyXrE=;
        b=C2WWpHrJQC/x/z6ssLbuLi/PbIjc6a7CvUyQwHvBpSuejbT+0ZdJP28Nnel1d3vV1U
         dqGDumzykcP7cKITYi1EL2o1FInn09HNQsHkbShSVAA3bK9m9QaTOYPPngyequThSEdU
         /V/58OO5B0d/FSZ2DjdMS6s9uEM1wLiH4qqIpLuB4htuXEjHULvw+1EkbatL6ReGgvYz
         zWsoWqEi2zUVw+B5MywTpWQ184JmtV9OAKkmxxk/CbtCAuPKsLT+GwSvYvBpZ9M9SmoO
         AFOLBnizdtjSWGCSd6idiWpi67/j+F8KnJoZRts9OVTNK+3iaGP8O1RiJsfOydrSi/Fr
         IRgA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=fk5eZCY11M7jDNIfSSow666gphCXsyDq664u42NyXrE=;
        b=WuL039eEf4VS/bkvEs6FH5mhcWNUDzxZ9ictctZle1JFieuWmsXQB6rP2EiGNn27AO
         4BzFf7rmsy5O8QKU2kjPMJbqTxNZ5MMznR5ciuE8yhQJpZ0tcFy6UdDe4XJBUiueiQdg
         tjvJmMiAJChdBTdyQl0nIbFYsdt/6KG5SBLfHcfyj7yKUB1nz5LIZj0jGic0WHQUgB3c
         THuxsKl6l182IG1fAUwglkNDQwHGt3JDhW0W+OYm/3W5uUEZ59CV7FcmLPT4HgmNoyZv
         oFKLbKmtUJzmzmqhr+s/TCoZZcPWRc3Hz5/UZ063Nb4j6JVwTHu4XHLw0c4/y0J5dSUN
         VSGA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora++tuDXQBTbZLtvGTmtM4/cD4G7n78/mik51flHcr3YsoU3QgO+
	M5AwWUslcVCLG8Dfowo+TxI=
X-Google-Smtp-Source: AGRyM1tEorbu0KmwpvVKRHuOVfcyg4O9hq4SEWKlYLgaKDEflet3QM0PvchyH6QYy5JntJY7A1ed9w==
X-Received: by 2002:a17:902:e889:b0:16a:6c64:aa50 with SMTP id w9-20020a170902e88900b0016a6c64aa50mr37021607plg.142.1656959457092;
        Mon, 04 Jul 2022 11:30:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:18c:b0:16a:2c14:1ccd with SMTP id
 z12-20020a170903018c00b0016a2c141ccdls20711093plg.10.gmail; Mon, 04 Jul 2022
 11:30:56 -0700 (PDT)
X-Received: by 2002:a17:90b:1a8b:b0:1ed:1202:32fb with SMTP id ng11-20020a17090b1a8b00b001ed120232fbmr38746374pjb.9.1656959456382;
        Mon, 04 Jul 2022 11:30:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656959456; cv=none;
        d=google.com; s=arc-20160816;
        b=LrN4TLyCfuRjXKx5FjWhKSIIjL/eTfLAE6E1f2ycbdtuXnJt+K9cQ5QkzCS1l03qcB
         IVAfb2raDcf8LJrA3HLPblu5si1LnioQauAfVLafuS/9ysEAl2J/ymDl7e+vCP2jV61X
         u+eS2PabxQq1l76Zr/xYarRehhH1U5X+jUaJipV2yWOEirp9Yc32TgRtYCxsCnz65KSs
         k4INeIaqPEmfr/C5/02LG25gkzyApCRWntjKIKK5nPHG8vrmbpbSWao1z/WUTr2vP4Bs
         deMPIQ1YFQMxjv2uTi/mslGp0DPrMCuBVCuNmsmwRfIfnl1F8D7Ld6+i12Tx5REbJmhh
         EtXg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=HZ+YeuujyK+kpO/HzleJC9YagcK0WT15I3KDnR/ZJ+U=;
        b=wZdMnQ7Ies+4KQjmWVoWu21HVFQweD1100N/MsAf/R/1t3g32Qio8OYqqPkZmk/aKl
         qHUYZUZpTNJUfhJJLvbwqUecbnYvx6AC4f8NCcgSHQ8xfHYvhBgK1RC4m5oMmvgeFGiS
         5NLcJLcxrIlMg1qmxVvPhJa3rhUSDOdRz628CmI7fXMhaop1w/0eHBVBKr+OYO19bRvl
         VV0O6p+xzfDJJA4Ar/O4NBbNOS4OTZaqW7m/kuBq3gooEDQ9Tc0O3hWRgU5y9RPuePZN
         /cE6vVLlFCuObZdX7huzfn5Lvb/IKEbfDcD4SzRWgvU/1yrQz8JldS5xue6BreT58ZQt
         RawQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) smtp.mailfrom=segher@kernel.crashing.org
Received: from gate.crashing.org (gate.crashing.org. [63.228.1.57])
        by gmr-mx.google.com with ESMTP id rv21-20020a17090b2c1500b001ef8b809176si121037pjb.2.2022.07.04.11.30.55
        for <kasan-dev@googlegroups.com>;
        Mon, 04 Jul 2022 11:30:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as permitted sender) client-ip=63.228.1.57;
Received: from gate.crashing.org (localhost.localdomain [127.0.0.1])
	by gate.crashing.org (8.14.1/8.14.1) with ESMTP id 264INElF019868;
	Mon, 4 Jul 2022 13:23:14 -0500
Received: (from segher@localhost)
	by gate.crashing.org (8.14.1/8.14.1/Submit) id 264INAKN019865;
	Mon, 4 Jul 2022 13:23:10 -0500
X-Authentication-Warning: gate.crashing.org: segher set sender to segher@kernel.crashing.org using -f
Date: Mon, 4 Jul 2022 13:23:10 -0500
From: Segher Boessenkool <segher@kernel.crashing.org>
To: Alexander Potapenko <glider@google.com>
Cc: Al Viro <viro@zeniv.linux.org.uk>,
        Linus Torvalds <torvalds@linux-foundation.org>,
        Alexei Starovoitov <ast@kernel.org>,
        Andrew Morton <akpm@linux-foundation.org>,
        Andrey Konovalov <andreyknvl@google.com>,
        Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>,
        Borislav Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>,
        Christoph Lameter <cl@linux.com>, David Rientjes <rientjes@google.com>,
        Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Herbert Xu <herbert@gondor.apana.org.au>,
        Ilya Leoshkevich <iii@linux.ibm.com>, Ingo Molnar <mingo@redhat.com>,
        Jens Axboe <axboe@kernel.dk>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
        Kees Cook <keescook@chromium.org>, Marco Elver <elver@google.com>,
        Mark Rutland <mark.rutland@arm.com>,
        Matthew Wilcox <willy@infradead.org>,
        "Michael S. Tsirkin" <mst@redhat.com>,
        Pekka Enberg <penberg@kernel.org>,
        Peter Zijlstra <peterz@infradead.org>, Petr Mladek <pmladek@suse.com>,
        Steven Rostedt <rostedt@goodmis.org>,
        Thomas Gleixner <tglx@linutronix.de>,
        Vasily Gorbik <gor@linux.ibm.com>,
        Vegard Nossum <vegard.nossum@oracle.com>,
        Vlastimil Babka <vbabka@suse.cz>,
        kasan-dev <kasan-dev@googlegroups.com>, Linux-MM <linux-mm@kvack.org>,
        linux-arch <linux-arch@vger.kernel.org>,
        Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
        Evgenii Stepanov <eugenis@google.com>,
        Nathan Chancellor <nathan@kernel.org>,
        Nick Desaulniers <ndesaulniers@google.com>,
        Vitaly Buka <vitalybuka@google.com>,
        linux-toolchains <linux-toolchains@vger.kernel.org>
Subject: Re: [PATCH v4 43/45] namei: initialize parameters passed to step_into()
Message-ID: <20220704182310.GQ25951@gate.crashing.org>
References: <20220701142310.2188015-1-glider@google.com> <20220701142310.2188015-44-glider@google.com> <CAHk-=wgbpot7nt966qvnSR25iea3ueO90RwC2DwHH=7ZyeZzvQ@mail.gmail.com> <YsJWCREA5xMfmmqx@ZenIV> <CAG_fn=V_vDVFNSJTOErNhzk7n=GRjZ_6U6Z=M-Jdmi=ekbS5+g@mail.gmail.com> <YsLuoFtki01gbmYB@ZenIV> <CAG_fn=VTihJSzQ106WPaQNxwTuuB8iPQpZR4306v8KmXxQT_GQ@mail.gmail.com>
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CAG_fn=VTihJSzQ106WPaQNxwTuuB8iPQpZR4306v8KmXxQT_GQ@mail.gmail.com>
User-Agent: Mutt/1.4.2.3i
X-Original-Sender: segher@kernel.crashing.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of segher@kernel.crashing.org designates 63.228.1.57 as
 permitted sender) smtp.mailfrom=segher@kernel.crashing.org
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

On Mon, Jul 04, 2022 at 05:49:13PM +0200, Alexander Potapenko wrote:
> One of the reasons to do so is standard compliance - passing an
> uninitialized value to a function is UB in C11, as Segher pointed out
> here: https://lore.kernel.org/linux-toolchains/20220614214039.GA25951@gate.crashing.org/
> The compilers may not be smart enough to take advantage of this _yet_,
> but I wouldn't underestimate their ability to evolve (especially that
> of Clang).

GCC doesn't currently detect this UB, and doesn't even warn or error for
this, although that shouldn't be hard to do: it is all completely local.
An error is warranted here, and you won't get UB ever either then.

> I also believe it's fragile to rely on the callee to ignore certain
> parameters: it may be doing so today, but if someone changes
> step_into() tomorrow we may miss it.

There isn't any choice usually, this is C, do you want varargs?  :-)

But yes, you always should only pass "safe" values; callers should do
their part, and not assume the callee will do in the future as it does
now.  Defensive programming is mostly about defending your own sanity!


Segher

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220704182310.GQ25951%40gate.crashing.org.
