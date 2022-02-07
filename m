Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB75HQ2IAMGQE2BYXB5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 1FE2A4ACB98
	for <lists+kasan-dev@lfdr.de>; Mon,  7 Feb 2022 22:49:53 +0100 (CET)
Received: by mail-io1-xd3b.google.com with SMTP id n20-20020a6bed14000000b0060faa0aefd3sf10018199iog.20
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Feb 2022 13:49:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1644270592; cv=pass;
        d=google.com; s=arc-20160816;
        b=JmaW1FWDU3TC/Bc1TUpfMqt82+4PabS6vqXZtUIA0xKL56VCH+th0QvUmyluQzcqHU
         Xd/TD9PRbj/3uXKAZAoSMsq6a0s2FNE8l7m4kwDBF1YOdO4ez32DUx0ieCW9JaENapcb
         KSFZLSTT/I/sFw/QbjXEGe1Kos3iR2eyEpJoy6mtkZYE4hkneWDEzJ/rGxpuUtVsWHj+
         XKZseXQPoPZxqBMGJsmN4/kpJcEiLRmi5fCIzWTfMd/5FvwGNQyiRZHTGA9fYXVLCJu+
         oOQ1s3pdr01/hh7Vh4jRFy6DgTdnQPADg2Uq3n/kckWoOtv8dU3qi+HY61e+25/iMN50
         66Jw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=FSqzrWkEj0rkLzDttaJEnKAeJsve43UMSfb5eM3yxno=;
        b=KWT+rX6HtguNEvSGJDcKtTt/HnUQWeWzPBanMo1qBE6UXhBbDt6so4RRIMcqbe+pLw
         czhDsbK5lfuEBuV7bAawxAXAqbXuJTaN8GMAo7v2i3ziASegrJH9MM+LgROWs5wTy8ow
         a/pSEpE3g19Sj2+89gf+WtcdY+4gVBb/Y3lpakNQe0jS7HDUHHY9DTUKa1jyleI4L6nT
         WYHLZqbBF2D4+18W6OOb7TZRRyPTcRsZVpe9AUv5NKi0IlkbvFgDoM3+lrgyvXSDsM0f
         osgplQFW3udzHua/fyyHsUJfeW4nh842x4kqGiJR4+JWxSeavsT24NmRrA32Kl9pZzRH
         /+aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FiK4f6J1;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FSqzrWkEj0rkLzDttaJEnKAeJsve43UMSfb5eM3yxno=;
        b=Wz6CQa2MPwyZnhU/n1pLubVCQDFoFl+mhx+YeFKrCy5Vf33jmfEuwfccqEftgc45Bc
         kWpeD+pIE78hvUhWXBDsFdBCWBlRYFYt8pq2l5/Opi4bnGHaZiA93QEQapU3QTewZGNu
         PVZ5nxhwvR7q8jFYozXUmocHR7JSMaa4QuwSbENynw3RiWlLEN1NH07OlxZAZrxgeGLl
         QArQrT6MfVQWjD9A3LlIyGqDpORThZEqBLc0jUL06fhOZ7WFO9yc70ZZdkgoaL7zDjxO
         Fho9wXKJXDFHHMyMnvMtEpOtcG+JJ67VNa2BnWXP25CsBAVYJxDH5c71/EdiWQYz/yEh
         BMnA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=FSqzrWkEj0rkLzDttaJEnKAeJsve43UMSfb5eM3yxno=;
        b=tDlNfhOE7+UK/jsBPW92spxuRkC+KS3ro/MzT5OL+ROj8CTpFCXmGOaOEboSErDOOR
         XHzq1Sf2qhXGiHM9L1jKvZ+NuNplSzuH024oSeLE1mbQSVATxVwmI2TzLsLLBgmDWjKj
         BGSudLd2kkzoERoIPBOjnx6Kxzg+YQA3DlHrhr0iZkje0GdVxEJXZU6KTLdDt2PEsAwp
         x7tzinf/g3WZ+2mSXGaz5JHFc4DFomA9n+J4974AkzmwERLC+iijSFYd6WrJ1fSSFkXF
         JVqXdJVi0dAIUX3OYEOZfarMsShcyzGlAyF/Xq4pkxMJ46z2KepW87JBsiFfZ7Q4qj7k
         j0uA==
X-Gm-Message-State: AOAM532cDZ22pC3otljh1FB8YtLKy445SbqcR+0+i5oEyJbj0Hto+nz0
	/qZAmAyAB6d7mFq4kKOOlCI=
X-Google-Smtp-Source: ABdhPJydmEOKB2oFfy+PZO2Php+KT5Hu2If9nDfNArinpdH5CtKPGSj+ekEpLU6BthjAxba2h7uuIQ==
X-Received: by 2002:a92:a053:: with SMTP id b19mr768669ilm.234.1644270591725;
        Mon, 07 Feb 2022 13:49:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:ce3b:: with SMTP id v27ls1751083jar.2.gmail; Mon, 07 Feb
 2022 13:49:51 -0800 (PST)
X-Received: by 2002:a05:6638:1384:: with SMTP id w4mr793963jad.200.1644270591264;
        Mon, 07 Feb 2022 13:49:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1644270591; cv=none;
        d=google.com; s=arc-20160816;
        b=BtZVPKDXuT32Nzv6pjccaP/sfDlT28yjkdaorRVT1qQQrYqJ3+73sVtusKGE+dlv/a
         Gl7j6HB49gYNx0c6M+8ZxXztN5N8ZMfzR7jRTOpU37B1nviDJ6ZJeMgZUztm8tXYCaM7
         Tm4BPw32OnZUUzCylNe9rIQvbLvQVeWuLzRSBYVlq74K05xTH4Le2djVaqdmU+m3qbNX
         CvnHUxZu+fPBZ99nkTv1X/9ASFcHBJZyvQbStl+enFw//9lGuc9MFJ8etFaj8rNGRhBB
         h56lARd0myBmJ57tJmV/icfZPbDiT6enbIyfGmDdxEr4L+EqCTeinxAOi3Vgiz2aqgnj
         Xd9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=yOK7ZFbX6M/yFlHUYZwVYyYTn3CE2+Syg/ppv2ftUNA=;
        b=YInswZX0IgisJfOd5+Ok8ybWPu6NgFvCnUaBEa2JHYsNI/IzS7BqcZNj2SOHBsWPr3
         wkTl+vIG9+xLxWlzww7u52dCx/s3O9kUiYhIPv6V/mMKaJ1kZvbgfb422hXqBubswBnm
         LmNaVyYUguncfIGNTng5OzHtK7gFn9ujvQmZ1EinBh8QQPP3mshIida5Gq5g6yg76ExS
         2z8HGKFyJzJg8HlgC4yBldTZ70ca6l8fRir4xNz8W+IKEgYc/1h7MKK3zJKQxEMKx5fi
         mhypFy6qQssLD2IcTqwZ4NAsGAwbWIAGBSXdbfG/3Ap3wo24qLNkGJk98debuBwx+TdQ
         1KZw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=FiK4f6J1;
       spf=pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::92d as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92d.google.com (mail-ua1-x92d.google.com. [2607:f8b0:4864:20::92d])
        by gmr-mx.google.com with ESMTPS id f2si344683ilu.4.2022.02.07.13.49.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Feb 2022 13:49:51 -0800 (PST)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::92d as permitted sender) client-ip=2607:f8b0:4864:20::92d;
Received: by mail-ua1-x92d.google.com with SMTP id r8so24157468uaj.0
        for <kasan-dev@googlegroups.com>; Mon, 07 Feb 2022 13:49:51 -0800 (PST)
X-Received: by 2002:ab0:43a6:: with SMTP id l35mr29540ual.12.1644270590671;
 Mon, 07 Feb 2022 13:49:50 -0800 (PST)
MIME-Version: 1.0
References: <e10b79cf-d6d5-ffcc-bce4-edd92b7cb6b9@molgen.mpg.de> <CAHmME9pktmNpcBS_DJhJ5Z+6xO9P1wroQ9_gwx8KZMBxk1FBeQ@mail.gmail.com>
In-Reply-To: <CAHmME9pktmNpcBS_DJhJ5Z+6xO9P1wroQ9_gwx8KZMBxk1FBeQ@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 7 Feb 2022 22:49:24 +0100
Message-ID: <CAG48ez17i5ObZ62BtDFF5UguO-n_0qvcvrsqVp4auvq2R4NPTA@mail.gmail.com>
Subject: Re: BUG: KCSAN: data-race in add_device_randomness+0x20d/0x290
To: "Jason A. Donenfeld" <Jason@zx2c4.com>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>
Cc: pmenzel@molgen.mpg.de, "Theodore Y. Ts'o" <tytso@mit.edu>, 
	LKML <linux-kernel@vger.kernel.org>, 
	Dominik Brodowski <linux@dominikbrodowski.net>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=FiK4f6J1;       spf=pass
 (google.com: domain of jannh@google.com designates 2607:f8b0:4864:20::92d as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

+KCSAN people

On Mon, Feb 7, 2022 at 7:42 PM Jason A. Donenfeld <Jason@zx2c4.com> wrote:
> Thanks for the report. I assume that this is actually an old bug. Do
> you have a vmlinux or a random.o from this kernel you could send me to
> double check? Without that, my best guess, which I'd say I have
> relatively high confidence about,

Maybe KCSAN should go through the same instruction-bytes-dumping thing
as normal BUG() does? That might be helpful for cases like this...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez17i5ObZ62BtDFF5UguO-n_0qvcvrsqVp4auvq2R4NPTA%40mail.gmail.com.
