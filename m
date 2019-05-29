Return-Path: <kasan-dev+bncBCMIZB7QWENRB3URXHTQKGQECKG3WDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa40.google.com (mail-vk1-xa40.google.com [IPv6:2607:f8b0:4864:20::a40])
	by mail.lfdr.de (Postfix) with ESMTPS id E95752D842
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 10:55:11 +0200 (CEST)
Received: by mail-vk1-xa40.google.com with SMTP id x196sf685368vkx.19
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 01:55:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559120110; cv=pass;
        d=google.com; s=arc-20160816;
        b=Q1HdvC1RzeJg+DjaQkMfB/HQy8Ms3hR39ngXYPrLytIxIFdVIh0EfEyDIqgUUmpRwg
         ow9C08BsgOKY4Np2SNrB6z1p0C3Ig9DdQ9MrWxVbi+OV4coYMo5ddPk/rOQymh/c071p
         9QO3JjYo5FTVQ2hgDSxi76plFT9XB9E6+Y5mIJx10BuXimOY4vuA7dujXrRXql/ULiXP
         ub7rQwCHD3c/3yFijIHw3yY05WrCHP+jVkCH7LiSHwcp460UNnEMmwBdNe+bcaaH96/n
         LLZE5ZJPxbvliaLVaMe6ybHUGc+z5GxA3CX/2fAC0xiehpA745X586TnRnn9B863q4ZV
         URpQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=gAj34fRqb/PQhzWFzQfsUVsKNyw3k5cfE2RqBiJ4V1I=;
        b=q79odlBAd7zs/bhwM8PM/DXWpfhfuDQn7IbbsW/JPkq57DgxpcXirKaaGiI77wJ58X
         ppbHx/cVEpfmPxa6HIA24tkmlGFwpcvNbrhz75b5Mk+nVv7XPXFY3U31sSdTeMe6NM1c
         F1B9FXpd/oT6USInIhS8rHwVMirgcjusA5ESndMRMA5KmKKRAWWL7wbuGCfX2t19p4pD
         n6RCMcRGPsqycWKpst9LZVQu90JeFmUYf69bDjAlVJw4hPMesfnjZ7aJOcD7fVtgA++m
         98WxJy3K+y8lKys0IkRTZ9/UK3jXv4v5j83tvW4kb9OlBKr+FzXyGZG5BvFgRJzpHFxT
         9tDw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PNQZe4nw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gAj34fRqb/PQhzWFzQfsUVsKNyw3k5cfE2RqBiJ4V1I=;
        b=M00Td3g+Y5s3MwZ0EhsG9q5BmPx989H8czUS91k78Z74lTqGUGIQgLnlURuJkxO03P
         5PbwZcT/GU3xoIBcRBEdibgiY5kRJwmVpqs7pYs4PZviqM245Br6NRRHEazwWt+S2VY2
         zbPiPIod14c+KWVmMvHx5Mb1V0heMtmEDdMjIdYDbp00BdJZeozJmzqpWXAKUmW8QZ7l
         BNHl17Rmc0cpGgxY6xwgnm7CTly2PYaYVh43w9ct4AiJJTsWu7h+GHZmkenHkVTnvXFw
         vkgBD02saab1W6T4RNu5JRwD+mNYArNeq22SAwc9VsyRf6JPwvayp5jUkOe0XQajbLn7
         GBkQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gAj34fRqb/PQhzWFzQfsUVsKNyw3k5cfE2RqBiJ4V1I=;
        b=LqNK4mN1rQGWbLqJJzz3ZmyinNtaEWfn/Sd3iBHZ73DLfnWt5+hD6wy35DyKfG6wV0
         v0cjq/CBm8ypnMoEF1Vcf/nLvBz+io7UXqoVYOE3KOLHG5tAV/GSXxFuM55l4RLHHx1S
         E1aNJdeajEYjk0PuBhWTy94TbcvQwnpG4Nr1T9/XzoiHxEGgBR14IG5CXfonvAxUJ8l1
         NZUe7bKOs2OEeonT1clAcWNcGdZMWSb8CZamZFAeUyyXsKJQkjJthU8QfhCHLYdcFlB0
         3zLBIz3qsvqCgduGj2eDEJFq6ciCIwXHMyr8F8G3XzD8/AYbBSEPNvyrDRZl5SRsvLHc
         t0ZA==
X-Gm-Message-State: APjAAAXwNU4lIoKMTE7HUOAXqSpX7OxhnRIec3XqUhSYzJXWaPNMw7U+
	HPdfYb/V7HRegcmU7m4ari0=
X-Google-Smtp-Source: APXvYqz9/Re/CfEj7mAgo2MiAkE2/+Qbl8C5k5Mx+3j4elunPQavAuwebKkCofUXp3rpn88BtIi1+Q==
X-Received: by 2002:a67:e9cd:: with SMTP id q13mr7846611vso.129.1559120110693;
        Wed, 29 May 2019 01:55:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:d59e:: with SMTP id m30ls228835vsj.12.gmail; Wed, 29 May
 2019 01:55:10 -0700 (PDT)
X-Received: by 2002:a67:dc01:: with SMTP id x1mr41002868vsj.153.1559120110487;
        Wed, 29 May 2019 01:55:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559120110; cv=none;
        d=google.com; s=arc-20160816;
        b=N9JcTpBbS877XJxhiS7gyDyvEA2YMtac9z0DXJI+jMsimPV2cmX6DN/G+f5/WNfyzK
         48kcM+oQ+UPb0TlDd1RS3u7CoLL+R6P0oe5YEw4x0Fpu1l36ldkpO6JnHjZAqqYjycUI
         iimQrJkZsXG+XgNRLBJrCDTSxTmyM7MlVwhS3cV32Fg/JkA4McVq87sln7sBfjvjFl7F
         Y2TMLfmBQCq/hvsJi7tc+310aIAp3gvzj6OyU9udQI3h/z7BSsJYLDu4DcZdCZnZ0Hj2
         2GlLd2CHZfcZAxtvxkDCzettnp/1++hZ6AnNs//f4hT2LAutsYFRHeTStAnvAS6gK9jn
         iEyw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=7KeoID3DEJVvd72x+oB2aXFD3P3WMkCRwLmanrhFSes=;
        b=NYd9m581k8GNIRdVe4XY3NiQAZV9Wzc6Wk37snACnwMsJLtnYWoW7RL6KPMpd8exRj
         4hWH53ns4MyWxca/F+zg/dX3H4uPv3uM8PJh5VV+NCgPzhCbsG7JgLmPOfQNn43TKxC/
         VQt5vjAd7Yc4JSAZPCQYeE8IkmFdWeklVukOT9gQJwIx5b6KBFQpf+FUhKEDUdEk55rW
         LdyxkSFlr/R8HS6/YzSxCEZVja4EK38rPzH9ULK95r+BMW9KU5gOzeQqrJH2tipFgUFf
         R4nnrkbxY4RIUU26AbFOZ0FfgpeGj5GiLR3AWrD3Xyj2cMVjPjLyPHbISDy3hYuP1m5J
         bVPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PNQZe4nw;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd2a.google.com (mail-io1-xd2a.google.com. [2607:f8b0:4864:20::d2a])
        by gmr-mx.google.com with ESMTPS id b63si858938vka.2.2019.05.29.01.55.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 01:55:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d2a as permitted sender) client-ip=2607:f8b0:4864:20::d2a;
Received: by mail-io1-xd2a.google.com with SMTP id e3so1115066ioc.12
        for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 01:55:10 -0700 (PDT)
X-Received: by 2002:a6b:e711:: with SMTP id b17mr12474897ioh.3.1559120109961;
 Wed, 29 May 2019 01:55:09 -0700 (PDT)
MIME-Version: 1.0
References: <20190528163258.260144-1-elver@google.com> <20190528163258.260144-2-elver@google.com>
 <20190528171942.GV2623@hirez.programming.kicks-ass.net>
In-Reply-To: <20190528171942.GV2623@hirez.programming.kicks-ass.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 29 May 2019 10:54:58 +0200
Message-ID: <CACT4Y+ZK5i0r0GSZUOBGGOE0bzumNor1d89W8fvphF6EDqKqHg@mail.gmail.com>
Subject: Re: [PATCH 2/3] tools/objtool: add kasan_check_* to uaccess whitelist
To: Peter Zijlstra <peterz@infradead.org>
Cc: Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Borislav Petkov <bp@alien8.de>, "H. Peter Anvin" <hpa@zytor.com>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Arnd Bergmann <arnd@arndb.de>, Josh Poimboeuf <jpoimboe@redhat.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-arch <linux-arch@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=PNQZe4nw;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::d2a
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Tue, May 28, 2019 at 7:19 PM Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Tue, May 28, 2019 at 06:32:57PM +0200, Marco Elver wrote:
> > This is a pre-requisite for enabling bitops instrumentation. Some bitops
> > may safely be used with instrumentation in uaccess regions.
> >
> > For example, on x86, `test_bit` is used to test a CPU-feature in a
> > uaccess region:   arch/x86/ia32/ia32_signal.c:361
>
> That one can easily be moved out of the uaccess region. Any else?

Marco, try to update config with "make allyesconfig" and then build
the kernel without this change.

>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  tools/objtool/check.c | 2 ++
> >  1 file changed, 2 insertions(+)
> >
> > diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> > index 172f99195726..eff0e5209402 100644
> > --- a/tools/objtool/check.c
> > +++ b/tools/objtool/check.c
> > @@ -443,6 +443,8 @@ static void add_ignores(struct objtool_file *file)
> >  static const char *uaccess_safe_builtin[] = {
> >       /* KASAN */
> >       "kasan_report",
> > +     "kasan_check_read",
> > +     "kasan_check_write",
> >       "check_memory_region",
> >       /* KASAN out-of-line */
> >       "__asan_loadN_noabort",
> > --
> > 2.22.0.rc1.257.g3120a18244-goog
> >

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BZK5i0r0GSZUOBGGOE0bzumNor1d89W8fvphF6EDqKqHg%40mail.gmail.com.
For more options, visit https://groups.google.com/d/optout.
