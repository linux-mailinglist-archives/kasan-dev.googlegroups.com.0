Return-Path: <kasan-dev+bncBCMIZB7QWENRBBGXQDYQKGQESPV7GCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93f.google.com (mail-ua1-x93f.google.com [IPv6:2607:f8b0:4864:20::93f])
	by mail.lfdr.de (Postfix) with ESMTPS id 7B16013D6BA
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 10:23:17 +0100 (CET)
Received: by mail-ua1-x93f.google.com with SMTP id i12sf3101728uak.21
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2020 01:23:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579166596; cv=pass;
        d=google.com; s=arc-20160816;
        b=loGEuOu1UjNXmKLoD2wC+iw4AX30gHkHK8B5yUEUfv02TxBI02169PA7WCEwkG3PJR
         M8pUCQbBMElOWNtcDEkYrCbkgAntil43EW7gAdQyrKVqI+Pd3N1MWPLJF7X3+S4CEDiB
         ZzCmzR+Sii/dpZo6PiSygL6oPvwjr72jSwboI3Vq01SlNFnj7umHmSxcnkx1vLJ4RYoL
         Lh/HBPmZXgxbcz0sPP3Adw3AOGewJbvU1Nn+tO9SFlBj6KjjnCiY/ejkowIH+pHzXhMi
         /kKsR1vVg3rUQXaVrwMg4jDQsVOY4sfapLq9RPaEwo2n3WXV75SNTcuuBV67DyQ24VJn
         ce2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lzF9fo1e7kbj5qGD5k782e28aKLDGqy2vmY12cZCHqc=;
        b=DfkGH+qW6mSdi2H67NwrQFPg+ELuJovVC/Bh7ARZkr1TTKrncncbSAqL1n+2BG9bQj
         1022+mRftSLEPpPVaYOpxEJpQnZWOLqU/aKZDzVvHjsRKTK6xYKsBj4+DGqv6p9pR+wR
         0S4MmAFswDwHsMxUn2Y8tBr+LMIcN0ELycK5Pf3N/Whq1Q7YfBihLEcBJnVWRI2em4Ep
         vEsczcu2dJYESih5rB/b+XfGT/NsaBgL8P9PpeVC9X9lfnCSTxxhLnN76tb4rdf60HVd
         /4hZXeTmPbhhK55TfYyVgm7MFFkO10Ko2PPqi+tAeRNQIomIYkNBP91F1cT+NFnvVFnY
         2SHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HpLbf4ux;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lzF9fo1e7kbj5qGD5k782e28aKLDGqy2vmY12cZCHqc=;
        b=puAYo3NwyY5WDTmfYvSd6dR96fLp3XXABupeL1lzS8AucglAR5+YfdvsW8MkF2UKmn
         NlKIaErS/Hhs9ZuZ2aI24PqNSEOQmNrQftVClTO47BtsDTbcE9MZS92q9BInJyW61err
         hKDy0Dec47CTKUVj5eNtMjJpKsIZUwniuSQNPGU1UNFMJOL/pde0MlsMLaLmDW0EvLYB
         saLroeGLvdVGOtt0FTQCQxxPkuYpHDjIXIUU3VPtyyvin78ush21vWbWDRBRp7NzJGVf
         Kv9j1PKqLdoTR/lxQ/z7aaYMhnpJEhlcrNSfwBlf5JhZZ6MK9ZGO/iBqpx3RL5N4Lq4K
         l0Vw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lzF9fo1e7kbj5qGD5k782e28aKLDGqy2vmY12cZCHqc=;
        b=dpWfePGP9rAlqpUhkepB5fm8h/C41thNYGxZ7uZHKXZ+aJ7Bn24NBob1sPqgY5t/sy
         MAd94Jj5EdpcTULIEr5hoo9H/E45+MoqvIA0TFOGsOWd6M+S25slRFdQMQ0jRIpGHSdR
         Uq/87KnGnFTXYGOc+3ShoxpOBUE2qckv2nvS7jO7vdk/bMxv84S9ynWbSY88bjmhSEAo
         W4pkWs3tChpKyPRPOmYuk1quQoerTkdYhC+NCmhab99ZplS0BRjVeSYZ+7zSyEGRfWCN
         GEGvAHroTHKXeGvGKoSL9bfNMTTcLJgXGPgk1qVeWhEg6NnDUpANXYlFUBhcc4h2iEBY
         y+XQ==
X-Gm-Message-State: APjAAAXKJ9KvHn+nYn4+Et+rbseY+cR643yqDnXzqoNxNBJNKlM3Aw7K
	SGBX+laIDre3rlxmm+F5/Vk=
X-Google-Smtp-Source: APXvYqyiVy4lePsrUUhI1s6b+dXp6ua5LUmEuB4+pgKkNInfLJVFXus9HHy1l9dCEIF4Ah1hdxPngA==
X-Received: by 2002:a1f:c686:: with SMTP id w128mr17070837vkf.34.1579166596453;
        Thu, 16 Jan 2020 01:23:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:2885:: with SMTP id s5ls1251599uap.10.gmail; Thu, 16 Jan
 2020 01:23:16 -0800 (PST)
X-Received: by 2002:ab0:3773:: with SMTP id o19mr16336045uat.30.1579166596106;
        Thu, 16 Jan 2020 01:23:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579166596; cv=none;
        d=google.com; s=arc-20160816;
        b=w3F6MMpli0iy5zwtW6qy/Zmhi7pd9Vw2sCPHmwsU5e8jyl4ZXvfA6O+hr5YHVtZBR7
         B6oKwirWP3YMZgjPM+MaIgYBp1Cv0xoAT/67kQvPR8J6NbZo9tz4d3bb/VVP8AuI9j/i
         JmvREmZUSsE2y5sRM1WP71PxC0yXXp6S/uhNobslsFUZ74Z2x4aGtdsZoj6x2E/Ttovg
         4a3Dg7gwTSx01spr4xAiN7wFr66H0FZwnUstIE46PzAQDCZakCqdJbOR3mQ8SJEkbecg
         i8dOCtqK7CnD7K0Yuv7U1XPyP07UgjTOdbohgsmU+P3WzU4ndqT3z7Cn2hyjrpEClH0Q
         VqCQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RqTHK7EsHlkxZxI0RjfjnnG8P6WuHcl1Hv4xLIayM+k=;
        b=RNBL7LXeDKkZqxBgs8XRobUIdWmFsXidbPBy86Nxp0xsAuqqoYp3p0HwtUyb+HothT
         Gy6mRRjLL1hH4cCF/nCAlElSvO9MFK7m8DJflr0jr7YmASrigiJlIwiiZqcdouf98TbG
         2a1ycNU2PBVcEhC8RIZDa1tFIJNTHdyUpkk/lCpkYYJII036lFugy3flehm7CNtnODeG
         i73+Ib2OxWVobbFpTBYLoMCd9wQ8gmMJz33CK4gS9fhPPYknthy2Mol3xzgYArElevDH
         H6cGf7vGewmkQ+7/z9YkOEUdpRNPcEhCZ5hHMDUyig8KGNKTEQOtFJ9lidK62ANh6e+9
         OTcQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HpLbf4ux;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id w4si935149vse.2.2020.01.16.01.23.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Jan 2020 01:23:16 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id x1so18429073qkl.12
        for <kasan-dev@googlegroups.com>; Thu, 16 Jan 2020 01:23:16 -0800 (PST)
X-Received: by 2002:ae9:eb48:: with SMTP id b69mr31201094qkg.43.1579166595511;
 Thu, 16 Jan 2020 01:23:15 -0800 (PST)
MIME-Version: 1.0
References: <20200115182816.33892-1-trishalfonso@google.com>
 <dce24e66d89940c8998ccc2916e57877ccc9f6ae.camel@sipsolutions.net>
 <CAKFsvU+sUdGC9TXK6vkg5ZM9=f7ePe7+rh29DO+kHDzFXacx2w@mail.gmail.com>
 <4f382794416c023b6711ed2ca645abe4fb17d6da.camel@sipsolutions.net>
 <b55720804de8e56febf48c7c3c11b578d06a8c9f.camel@sipsolutions.net>
 <CACT4Y+brqD-o-u3Vt=C-PBiS2Wz+wXN3Q3RqBhf3XyRYaRoZJw@mail.gmail.com> <2092169e6dd1f8d15f1db4b3787cc9fe596097b7.camel@sipsolutions.net>
In-Reply-To: <2092169e6dd1f8d15f1db4b3787cc9fe596097b7.camel@sipsolutions.net>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Jan 2020 10:23:04 +0100
Message-ID: <CACT4Y+b6C+y9sDfMYPDy-nh=WTt5+u2kLcWx2LQmHc1A5L7y0A@mail.gmail.com>
Subject: Re: [RFC PATCH] UML: add support for KASAN under x86_64
To: Johannes Berg <johannes@sipsolutions.net>
Cc: Patricia Alfonso <trishalfonso@google.com>, Richard Weinberger <richard@nod.at>, 
	Jeff Dike <jdike@addtoit.com>, Brendan Higgins <brendanhiggins@google.com>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	linux-um@lists.infradead.org, David Gow <davidgow@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, anton.ivanov@cambridgegreys.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HpLbf4ux;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::744
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

On Thu, Jan 16, 2020 at 10:20 AM Johannes Berg
<johannes@sipsolutions.net> wrote:
>
> On Thu, 2020-01-16 at 10:18 +0100, Dmitry Vyukov wrote:
> >
> > Looking at this problem and at the number of KASAN_SANITIZE := n in
> > Makefiles (some of which are pretty sad, e.g. ignoring string.c,
> > kstrtox.c, vsprintf.c -- that's where the bugs are!), I think we
> > initialize KASAN too late. I think we need to do roughly what we do in
> > user-space asan (because it is user-space asan!). Constructors run
> > before main and it's really good, we need to initialize KASAN from
> > these constructors. Or if that's not enough in all cases, also add own
> > constructor/.preinit array entry to initialize as early as possible.
>
> We even control the linker in this case, so we can put something into
> the .preinit array *first*.

Even better! If we can reliably put something before constructors, we
don't even need lazy init in constructors.

> > All we need to do is to call mmap syscall, there is really no
> > dependencies on anything kernel-related.
>
> OK. I wasn't really familiar with those details.
>
> > This should resolve the problem with constructors (after they
> > initialize KASAN, they can proceed to do anything they need) and it
> > should get rid of most KASAN_SANITIZE (in particular, all of
> > lib/Makefile and kernel/Makefile) and should fix stack instrumentation
> > (in case it does not work now). The only tiny bit we should not
> > instrument is the path from constructor up to mmap call.
>
> That'd be great :)
>
> johannes
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2092169e6dd1f8d15f1db4b3787cc9fe596097b7.camel%40sipsolutions.net.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb6C%2By9sDfMYPDy-nh%3DWTt5%2Bu2kLcWx2LQmHc1A5L7y0A%40mail.gmail.com.
