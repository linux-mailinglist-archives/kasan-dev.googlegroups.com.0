Return-Path: <kasan-dev+bncBD42DY67RYARBQPFYTXQKGQEEGCET7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 4010011BB82
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 19:17:38 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id l2sf4618657lja.18
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Dec 2019 10:17:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576088257; cv=pass;
        d=google.com; s=arc-20160816;
        b=Zf/xPdUuBS7wNX41YRaSEYZHURZomBIvhF+eiC4dpeqx61slSKEiVTyoEdU5WwJANp
         SRyTte/WcXLGFS8doQBXCBSbjyDdqmh4aJKK2uQf//3oeEhdYRa+xsHlRqQbaLJUQi2j
         7E8Vdv1G23CZy/QN6EUwZ5WaARsvpJ1UkwL/NXnTATL2HWPtwTL20kTg6a8d/qBdacn8
         7guxEWRJvAD54B7Xe0eiwgXbRkZXfT97W5YX2E5Socihq1UCYOCHNtCjVTDFiOnQqcqf
         V/4YJgn3nwmPkO77LJ2/oEErUQemWgLsjbC6CaZpWcs0XQMgEFamMeHXUyiwoRbHPiYw
         1G0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature;
        bh=DgNMArSA00gCkMDHOtZXpt2aebOBhJ8X8THQyNAHjCk=;
        b=GfwBLd2QN5nOylJtvekFW1JcR2rqMS55YgoIalb3de4eKAKso3+vcDbjqRa5RilVD8
         /1/ez4GiajdPXOQecoMYZXeXwqw+ppEOR+SR2j6LFM0AQJ1WKRWGYNZlFQFL1T3S26IP
         Iif9mCcOV8dZCyWQrw+QFzrGKDC9SjKehlusIaTDg4il84VXHNKqJuZA3KrMjgQ7FDbu
         kX2ikcbPmdfLEzBJT8Hn+hdfPitIl0Vb135pmxBloScZ8kfd0Mr0LnhKmYW4Yf9D4kAo
         1BIJk1ygCC9ldn/NftPo/4nqhk4kqWuLCHmLEM6XvdrEJLpJ89w17HU9C3daVZeJ96NW
         /1aw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=g44yxhTp;
       spf=pass (google.com: domain of luto@amacapital.net designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=luto@amacapital.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DgNMArSA00gCkMDHOtZXpt2aebOBhJ8X8THQyNAHjCk=;
        b=sVoVdgTwok0fusZa8r86kWmcvubAobjdbEefwV5CFQF+bwkpP2Bgc5bihQkBrKcVeH
         YUSB8LbzTxVznACSdXfutJ3bcoj8FS8JpUcAoVtyf+yR++Ti8upq2V925fIjfuP0wu72
         tDrYTWyH+rDh+DNa67RrJZ+Knp6jkkKTzEZ/GDDhqchaYPga7JnNx5VkygLTvXt2oka1
         peuXo/M88t2P1LugU0JAzshvCHy/1+njvEmsQvacn3R9fX3C+4gXnLUvnaIpt9exf0SS
         V6zq08KoCqt2Lli5Kcy5AaIH4qjf6pJzhnNnnCRP519KROA1JXItklvdFlniD/LMJMOZ
         IpVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=DgNMArSA00gCkMDHOtZXpt2aebOBhJ8X8THQyNAHjCk=;
        b=dEwvAzptLUCS0SJkPmSsMYyRcCSy753He/A4/LJsYz6FZUTxHzoT+6zPOZuVbUYjB6
         fW3BA/sgvKtr80hNfCVfDk9v9kfxb7CdLRvp5CZ/uoDUv8EGmKGo8txPAPpGC6tgeE4e
         SbP99Hf2w8cCdHI73b7FgsFxSru5C7PeCRqynALIMU6qiNuQptYXHl59ptAOUGD2bMYo
         UL9z5LWCQJ/Zdxj4mOjHmJhMRqOvCG1OmsHgvCKRpbRQ6woSVEMpdSyzpqkRE3e48Msx
         fKovKvtel79rJthst8OHShvmCCergOLQDbrTA9j5uTlJoMPzKjuHVD4dh16hAGXSHSrS
         Rc3g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAW5DVkcfI3CE+Ma1xFeuZAEHaP1w774quogRkNa65HCn0lmh5Q6
	z2KtiGTRbQI4kZ+S9gyF4XU=
X-Google-Smtp-Source: APXvYqw0v+udj0F6jZ4chJS4NgUsSdrkLNKVxTaPbzVHg4EeHQPB9ixyhLyUoedbsOHmhecr/kAGAA==
X-Received: by 2002:a2e:8646:: with SMTP id i6mr3130915ljj.122.1576088257868;
        Wed, 11 Dec 2019 10:17:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9e01:: with SMTP id e1ls434997ljk.15.gmail; Wed, 11 Dec
 2019 10:17:37 -0800 (PST)
X-Received: by 2002:a05:651c:204f:: with SMTP id t15mr3256234ljo.240.1576088257246;
        Wed, 11 Dec 2019 10:17:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576088257; cv=none;
        d=google.com; s=arc-20160816;
        b=pVXSbZ9E6yNEr0L9j/LmiPF5TMj9kIJYqBj2Iut5mlvNu4rWom7JHgnK2XDWQlhhEM
         wNcLNYVSCbkbIwRcIUeQs9TXCiO7VhVyyrv9GBTDT/pn3IAYgNZE3VDT7TK6Gp70zkOa
         9CfXTb7Sid2hMdTaZisa72cX9g3/84LICFpVK731jKe6OaJl1fqBPj+RXXiaNALxlSCO
         4JXY6UxTATlfR/QfF+Ai1GseyyALIiHNDf/h76iK+jbxc3y09JNPTvv5upn1QnKZ84QF
         DZIeqnTdihdxYO+OfYaf5tfK0LqM015eN2jPm9SaqG87GPFszgkRYnIWWeB8YHl37e1e
         oUGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=gdbdOJGDr6s2TB3vkGkLojy6hKiZ0+eS72V/GX35qQM=;
        b=xsG9u7Ac3Dn3REMfrvLmIiQrqeJBWz4VfyJNRT5ow9lezdSCRvVXuLBbA6zQLKd4sS
         MlK0UfG+//rWmSz4kEWJYJPBTg2JyNX7s7urSinPzlImRVx9ATKcSFyLprDqmo1hQnzg
         7Q7vMNC3jY84OY8Kan3bS4jZbJvySbl1u8R6n6nKLXdiK+r5FkVoJ0/Gr+ySyMxltgP5
         nODWyxSeVh7EK0/iEEY7LLgie7n0RD1rr6kxdlYHRxE1Ry8FdkZg/U/xb4HiIIslGYHD
         BxulzXkJdZjewEoyGsTZG2j8TnnKCC68y1xaqMnX5LizXQ0pNuE7PgPSCMQqCuo0II/B
         36+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=g44yxhTp;
       spf=pass (google.com: domain of luto@amacapital.net designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=luto@amacapital.net
Received: from mail-wm1-x341.google.com (mail-wm1-x341.google.com. [2a00:1450:4864:20::341])
        by gmr-mx.google.com with ESMTPS id x5si124816ljh.5.2019.12.11.10.17.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 11 Dec 2019 10:17:37 -0800 (PST)
Received-SPF: pass (google.com: domain of luto@amacapital.net designates 2a00:1450:4864:20::341 as permitted sender) client-ip=2a00:1450:4864:20::341;
Received: by mail-wm1-x341.google.com with SMTP id q9so8245181wmj.5
        for <kasan-dev@googlegroups.com>; Wed, 11 Dec 2019 10:17:37 -0800 (PST)
X-Received: by 2002:a1c:2083:: with SMTP id g125mr1260281wmg.89.1576088256672;
 Wed, 11 Dec 2019 10:17:36 -0800 (PST)
MIME-Version: 1.0
References: <20191211170632.GD14821@zn.tnic> <BC48F4AD-8330-4ED6-8BE8-254C835506A5@amacapital.net>
 <20191211172945.GE14821@zn.tnic>
In-Reply-To: <20191211172945.GE14821@zn.tnic>
From: Andy Lutomirski <luto@amacapital.net>
Date: Wed, 11 Dec 2019 10:17:25 -0800
Message-ID: <CALCETrXuJMBawUy3DTQfE4qLb822d9491er9-hd971BtBsPFNw@mail.gmail.com>
Subject: Re: [PATCH v6 2/4] x86/traps: Print address on #GP
To: Borislav Petkov <bp@alien8.de>
Cc: Jann Horn <jannh@google.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	"H. Peter Anvin" <hpa@zytor.com>, X86 ML <x86@kernel.org>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, Andrey Konovalov <andreyknvl@google.com>, 
	Andy Lutomirski <luto@kernel.org>, Sean Christopherson <sean.j.christopherson@intel.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: luto@amacapital.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623
 header.b=g44yxhTp;       spf=pass (google.com: domain of luto@amacapital.net
 designates 2a00:1450:4864:20::341 as permitted sender) smtp.mailfrom=luto@amacapital.net
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

On Wed, Dec 11, 2019 at 9:29 AM Borislav Petkov <bp@alien8.de> wrote:
>
> On Wed, Dec 11, 2019 at 09:22:30AM -0800, Andy Lutomirski wrote:
> > Could we spare a few extra bytes to make this more readable?  I can nev=
er keep track of which number is the oops count, which is the cpu, and whic=
h is the error code.  How about:
> >
> > OOPS 1: general protection blah blah blah (CPU 0)
> >
> > and put in the next couple lines =E2=80=9C#GP(0)=E2=80=9D.
>
> Well, right now it is:
>
> [    2.470492] general protection fault, probably for non-canonical addre=
ss 0xdfff000000000001: 0000 [#1] PREEMPT SMP
> [    2.471615] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1+ #6
>
> and the CPU is on the second line, the error code is before the number -
> [#1] - in that case.
>
> If we pull the number in front, we can do:
>
> [    2.470492] [#1] general protection fault, probably for non-canonical =
address 0xdfff000000000001: 0000 PREEMPT SMP
> [    2.471615] [#1] CPU: 0 PID: 1 Comm: swapper/0 Not tainted 5.5.0-rc1+ =
#6
>
> and this way you know that the error code is there, after the first
> line's description.

Hmm, I like that.

>
> I guess we can do:
>
> [    2.470492] [#1] general protection fault, probably for non-canonical =
address 0xdfff000000000001 Error Code: 0000 PREEMPT SMP
>
> to make it even more explicit...

I like this too.

>
> --
> Regards/Gruss,
>     Boris.
>
> https://people.kernel.org/tglx/notes-about-netiquette



--=20
Andy Lutomirski
AMA Capital Management, LLC

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CALCETrXuJMBawUy3DTQfE4qLb822d9491er9-hd971BtBsPFNw%40mail.gmail.=
com.
