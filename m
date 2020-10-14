Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4MUTT6AKGQEAZUP54I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 375EA28E220
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 16:25:55 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id 139sf3245981ybe.15
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 07:25:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602685554; cv=pass;
        d=google.com; s=arc-20160816;
        b=OMVATzNG+09ZeJVoeu3+yN+8OwcmGzntvOMrVd5A5rXCqNbJ4DNf+XHT+6s7B4PFQa
         MT35yE0WOPGksbbraEgMzlkhgJkyUbQ2QnYE1Mky12Uf/P3a+TgrDsOm2xP6YcF/zDIA
         LiFAlLhEXBSnnPJB64c8s4xjhgZ6xymGr/ct0J7Vuj2Que9a2AR3h37KbqJYFtK/UHcY
         l/WjVToQj5JvHy/SM4+Lsbrp9Gi1xiFMirmfPzTkpNOWkXgBcPmrJjxTCm9+BKnlx9HZ
         bHJTyRLitCKLO0zXyQVkIIUFD5vyHrb0lQt2dge+k6DSWCrO5xUrxEtQDq1eLszVO8VZ
         tesA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=/Mw9XkM9mkpuEDQu8/Fe+P7mgFeFS30fX3u8KRzWPLw=;
        b=YHtSuS31oKEX9WNuziaaM1+vATg6QxfUZRBcJ/H/NbuUATv+ylH6El/mB6Xf39IGpZ
         imuv5iFsiqod7Z3zp8EYpxiflrrdSDBTCWBywhRsNrG6vnM7F1Gkg3k9RjIBCYP2d/V2
         32mUGa9uYRQEOEr1KfI0i7f4inE6svPyqmXOQz5z5iu32qzYOwqEx4wKGydJV3kCdmfS
         anLzevGuXWSaIVVYZ4dlQ4GtE5LfGHQGHo3G2kn9X9j40vx8XfRt2nwwMlrGtYzJ6NMk
         iEGn0cgaKe2QhikScIAM89Bs6DTm+0JPlFYJryQjNyCnZtEiOggEtKwdKGSQAXQ4uWZq
         Anjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VuJzhEHf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/Mw9XkM9mkpuEDQu8/Fe+P7mgFeFS30fX3u8KRzWPLw=;
        b=DOyvlNbbm9YPlArDPOjJJ0boQ5/mQhab6hHB6Y6fbLKY0U0J6NNhS1EBn/k7AtOmJL
         4PQvcgGDOoXntpylsZvTyc1LEAlj18P6EGLv9FqOshi6vPPDxvqP/6uOxgdwybhDLt5V
         sB7RI2mYgcjT9BApj7YqU442gbCDp4WJhX0/iW2vb2q8gBux08gaFr2RgApUXCsW13hO
         CJPxoMLlHuamOmVTBCWZiT2poa22KoDwex6hAus/LzWXeUVekAoe6RShp6RUrG6x0MMc
         2DS0833pb7g/jZITVqvH5v41N6vwdrXu5ZG3PhgDt4/mXDwHRFtEWaEQwucjLKcbo5Se
         QT4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/Mw9XkM9mkpuEDQu8/Fe+P7mgFeFS30fX3u8KRzWPLw=;
        b=NypI2+fm2TcyrkQAQMKAQJWMhgOrFr+OQtPCbCqLIrYZzVxK7s6B878JqjTGDxs4Py
         2kZNIQXhxT/VC24Di2xVmuxxOXow2RO4DrIOfNKxVpuUjHLl8aP7rGiT2SD7nxp5pq2W
         qUbKdpGuEt24yraQSF9VVnpoTsNoxLy+c/GJoxITP6Wvte4v7IPQ8YaqJTSpQNWQIR1Q
         fOMvhQ4noQUPYP51KdL11iO+yxgutJVKO+Kj9bHUao/U4ykKNU9D4K4k+saMxjXlRuxj
         omwUjCOLqeOtIR0PAM2FTHm5Cs3ZVkwMNx+kiRJU1AgGBsQXTkfhm4LvBtDRNgBpZ9e6
         ndxA==
X-Gm-Message-State: AOAM530NAPw2yxsUt2OyRcO4hfD1gZHv69YmwUpP6g6VQrTEizTWW1Za
	6j8xyGNhbBhh7+OYuY5a0jc=
X-Google-Smtp-Source: ABdhPJwtY7D4DKnbRJLMGRNB7y0EeWYcczzmhZIAzQmdLzS2FYYlt2Wm0GDo8A9dtjdeOnop6j4Siw==
X-Received: by 2002:a25:d197:: with SMTP id i145mr460277ybg.82.1602685554052;
        Wed, 14 Oct 2020 07:25:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:511:: with SMTP id x17ls1771327ybs.11.gmail; Wed,
 14 Oct 2020 07:25:53 -0700 (PDT)
X-Received: by 2002:a25:d988:: with SMTP id q130mr7492855ybg.9.1602685553485;
        Wed, 14 Oct 2020 07:25:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602685553; cv=none;
        d=google.com; s=arc-20160816;
        b=nTKj/R5jSWHWpmXgPvgKF8DAQxVy9HPfDlO40Vuoebjd46P1NkRZ048OHTWHwTnMqM
         EGO/EslO6Z25XES8kcYHXs1cU8Tk+GNkZyDSFLFH5wwZhZQjo5TWDbJ1MgtuE6Lt+Ba9
         6qtuo84IjoocShuCaUaFufuHn0+V2OiQU0DHkty4P9PKXsnnobS8LQnlG18qGO4GO83l
         bPUxMFeEi2whYldEYm/TulQx+YvAQ54jnq62jmRXILNdvcWFxkqTYpxkpXd5T7OrIVw5
         kK5Qix6A+L0hbWK5XLjQjBOK24zqGNpnI3UXbAMidC8i3t8UHJjXlcyoPA2fD4vth0z/
         TR9w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=fAErjWw182zCAd+MdZBoOK+YTDWK+8XzTFr8GhJmh38=;
        b=vB4MGQzoWjZLcFxpDvuapc2jmFRGb+amyahwBvxaqR+NheGZujDVQQW9dzpUiLLX+j
         L/qq3InyYU56otHH2sSAsVBrSJrtCtNUTlgRpGySYnY00YNq/Q9emekExvsXeNFIqISC
         zw+1Aw2wS2f8F9gi++NGI9yQ27OKs9+Qvwewuf+BUiNASi56C/7ooh2cCe5TlRi4MnKm
         H9x+fsBzfWIGsm9r6uSM1Wtzii966G1TNs8U/GkRYwMMhtbXcPZeGRZAZeDhHN5a865c
         BD2Jo8wyZLb2EORFFCTLFy6NpsLGkJ145IZbmPcfheS3IEoyHQqL7IljiHtaLJa1e9fS
         1/FQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VuJzhEHf;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oo1-xc2b.google.com (mail-oo1-xc2b.google.com. [2607:f8b0:4864:20::c2b])
        by gmr-mx.google.com with ESMTPS id s7si295598ybk.3.2020.10.14.07.25.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 07:25:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as permitted sender) client-ip=2607:f8b0:4864:20::c2b;
Received: by mail-oo1-xc2b.google.com with SMTP id r7so832452ool.0
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 07:25:53 -0700 (PDT)
X-Received: by 2002:a4a:751a:: with SMTP id j26mr3762201ooc.14.1602685552796;
 Wed, 14 Oct 2020 07:25:52 -0700 (PDT)
MIME-Version: 1.0
References: <20201014113724.GD3567119@cork> <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com> <20201014134905.GG3567119@cork>
In-Reply-To: <20201014134905.GG3567119@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Oct 2020 16:25:41 +0200
Message-ID: <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
Subject: Re: GWP-ASAN
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VuJzhEHf;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::c2b as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 14 Oct 2020 at 15:49, 'J=C3=B6rn Engel' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Wed, Oct 14, 2020 at 02:03:54PM +0200, Marco Elver wrote:
> >
> > The (hopefully final) v5 will be sent the week after the merge window
> > for 5.10 closes, so probably in ~2 weeks (will add you to Cc). If all
> > goes well, KFENCE might make it into 5.11.
>
> Random thoughts:
>
> One thing that could be improved is the regular pattern of guard pages.
> Accesses that are off by 4k get caught, but off by 8k do not.  I suppose
> consistent off-by-8k will eventually get caught when the neighboring
> object is freed and the address is unmapped.  Fair enough.
>
> On 64bit systems it might be nice to grow the address space for guard
> pages anyway, as long as address space is relatively cheap.  That
> improves the odds of hitting a guard page when the pointer is off by a
> lot.

While I can see that it'd be nice to catch larger and larger OOB
strides, I'm not sure where we should draw the limit.

Experience with syzkaller+KASAN has shown that such large OOBs are
rare. We also have the redzones, which means that large OOB writes
will likely be caught (if not scribbling over another object),
although the generated report will certainly be confusing because
it'll assume that the closest object is at fault.

> Unmap could be made cheaper by doing it lazily.  It is expensive,
> particularly on large systems, because it involved TLB shootdown across
> many CPUs.  It can also amplify latency problems when you keep waiting
> for the slowest CPU.

It already is done lazily. We only invalidate the local CPU's TLB (on
x86) and no IPIs are involved.

> If you do something similar to RCU where pages are queued up for TLB
> shootdown, but without sending IPIs, the operation becomes significantly
> cheaper.  Complication is that, as with RCU, the address space range
> cannot be reused until all CPUs have done the corresponding work.
>
> Getting all the details right is probably a lot of work.  But it would
> allow a higher sampling rate for KFENCE - if CPU is the bottleneck.
> Such infrastructure would also help userspace munmap operations, which
> can be a performance bottleneck.

We have found that a sample interval as low as 10ms is still not
noticeable. Since the tool is not meant as a substitute for KASAN, but
a complementary tool, we think sample intervals for a large enough
fleet will be closer to 1sec. But here our current guidance is to
monitor /sys/kernel/debug/kfence/stats across that fleet to decide on
a suitable sample interval.

> None of the above is an argument against the existing patches.  Feel
> free to ignore.

Thank you for your comments.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA%40mail.gmail.=
com.
