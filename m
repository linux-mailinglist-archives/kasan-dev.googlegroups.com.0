Return-Path: <kasan-dev+bncBC7OBJGL2MHBB7VFTT6AKGQEY6Q642I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x539.google.com (mail-pg1-x539.google.com [IPv6:2607:f8b0:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F32D28E2BB
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 17:02:24 +0200 (CEST)
Received: by mail-pg1-x539.google.com with SMTP id j16sf2035228pgi.3
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 08:02:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602687743; cv=pass;
        d=google.com; s=arc-20160816;
        b=dpousIl+84NTGbEi+xMlDi6Du81be4pmDlFfO6AACVqCvPklcjAFc8xXTWtV0yUyHa
         ZaG+5Gajn/lAONxvKfd6RjtAedMl2YnNywUt0pU1sbOYoyCPlnkhxI/H/a7ILR7m74kC
         1u/7a8ayxRdUmI7OUnyQDHqPbLVsFq9Iu2PCvOE5TXxktodw1IRrt2GYKvzfTokG/2jP
         Y1xEwjz/xG2l9+yF8t/1GR4dXYORob2l92fCdvcuOjVrP3Md6f3uVAbTaMld4R8UvBAt
         T4PJyrHNWiuh6pTkgbIEINYcWpT1fje7nL4VRkUn9nDOt7g0X3FivfSsUXTY7uDJJGei
         nx5Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=2j12mhgtqlTyh7ll8PGfn6Axb9gF63oKMKdlfZYy2Tk=;
        b=EQScvcGdDCGX4eU1iSJLoIV+BR8maLB/BHNzRfVeQAVxcQkxw8ubvEzQjvsZ6SP2bU
         /jReCNB5gCevjZLDHwFhvHp235C2rnW/5/nt+20zvSBNaWJP7nZGAsFGkQRXEx7fD5TJ
         F0eV0d1XiFq8nnyJm8opZBk9NPFNK5zVLNlj2e/QUBKgPNGiDOffIP2HOD3NNeC61Df2
         fCEiflyqmfSI0P9tMn9++FQNI6V73HOc4D8v4u/r8n416H8TopQQSdJe3rfQVXL88mpH
         45VGgWXsyZ+2gjEYfx19SjkIR8LU/Tgt5Ovbfp7QlMih0aoUpPevxOSMXOZuTRmEFr9r
         j4TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="aun/Hmxd";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=2j12mhgtqlTyh7ll8PGfn6Axb9gF63oKMKdlfZYy2Tk=;
        b=NSRQImUwIBkF8hB7tqvDiZUbP8MAqEWky5aSz5kLI/Zqx0UNKeiiuHVAsAYjJhGHoo
         zrktWTXb3993jsGvbj+PcY+/hRXHg3mW8QrcHnDlE6wdcIvGsDcLbsT2AkjkOuRQXVtL
         lMgq/unje8Y319o6DotpsR63BLpg/+0hkmH8/XF7hgMKpENN1pvIxm8e5Z3bAyA8X4l7
         ZtwP9Xali7coTDWxrr98p8vOTBnTLQRzo73epvyyTFa5NWRlaTaqYmBoIRIPyalIpRcT
         QgBUAmPon5oa65WG0Qwlc50DVcHLJHO9uODyV1kWygSiHu1nrk/ZyFv7zJz54OgDgxAd
         X2Nw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=2j12mhgtqlTyh7ll8PGfn6Axb9gF63oKMKdlfZYy2Tk=;
        b=eJs3QhM/tD36S3UvfOCWs/fNiSQynxwYAdvFSHaZA6rhv4tI0hsq+wN1kmenmp8fKL
         cEu0kRqdweL3qr9ZRYUxXmdbj025r38eGOW5ZLAaWlyV1xpHXS6P+p5eO92qZwbvKfXl
         rkTfjrIVt19kqMISO6y1h9taOrvjr80Y2ZSlUo65QY89dgbWkJA6ig8a389nL0rnjriZ
         dnc6oUQK4vlkNzCeBaNU1F6CkeA1uthxkfbjYuVKgq4cxSuldiPspJkfxdMivf54iFkq
         S9iaXfTn+sogGgGgy7rAiiZSVGx9jEDa6Qd/lh7cwkswBxxzqLD7TGyvQMxFpmxI+vpz
         dm2g==
X-Gm-Message-State: AOAM530Wae+Apo1+CMj15Nnt7pgHhzMBwSXwvB1wyXhVM8ErhKwGrNW3
	tZMtpNbjhCEikRMeCF7Rrp0=
X-Google-Smtp-Source: ABdhPJysy2e9JuSbcpBdoimtzNLh6nMsQIZRQoUUPH5D3tcPPCH6FDSIqVwHvE8tFquvZFX9ByPFaw==
X-Received: by 2002:a17:90b:891:: with SMTP id bj17mr3886758pjb.44.1602687742587;
        Wed, 14 Oct 2020 08:02:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:8810:: with SMTP id c16ls1248062pfo.10.gmail; Wed, 14
 Oct 2020 08:02:21 -0700 (PDT)
X-Received: by 2002:a65:5ace:: with SMTP id d14mr4228976pgt.323.1602687741845;
        Wed, 14 Oct 2020 08:02:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602687741; cv=none;
        d=google.com; s=arc-20160816;
        b=rekXL91Izx8t958RM/kqQ4svCjJjVrHiOd5puuovcdEPIslxV86fQWk2MOOA1gjGQ1
         wMEjs7cd4b6LAIeXgiYMJT+5sRCsi037b2EGyu8JiXQDx6BGQlM80nLoZhZaMKrG5kw4
         dcYABRrRhR0ytm91ZiZUyWAxFYm+tb85smNmwGnaYyZiebCN84NH+eSFmaG3fnUzMeFF
         9CwU6Jd9sYcKqLKj+tJiA/l7SRMFoXqlfQoiwsjKN1ak0VcwcGKbfa/jMJi+H+x23O/T
         azmkqY0PtpcV83UFbTze7KrRYN1RM5aQ+m4eApVAnO+bU/4BjezGIb2sQWecPYRlnU90
         kP2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=09LatxZ6o5ArwjuwWODaAe6sSQN5/f4DyqZPSm72U5k=;
        b=H8DVKCjxH9MPU61jhkPxZDUhn+UnohM2BXvlY+EFHD3j534dlmbWImZ0cu/UXZgWlB
         G6H0rJXr2apWN72CEUSZYYZkmDahErmnzXo4mTiAE8Bry01WxcdHvCJzXjIZKXVjCS+i
         Qe2XW1VWJ4FMdi8VJQ604Ss8EEX63Fn7+mM47GqAC0i6X/t3NR47PYbPnGn+s4XPhiUe
         b+d61JnVadn4kWj74cwJjhcDYcdcRJfk0GW86BGh13JoLfb9AXHGM+1tGUVDaw2vQuWc
         CTlMPL6ivr7nvtm9hP81Kf9mKJbvVFh0NULU6PGTGHAFODH2dhZypXgbyad8jgUCGm/1
         RZDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="aun/Hmxd";
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x32a.google.com (mail-ot1-x32a.google.com. [2607:f8b0:4864:20::32a])
        by gmr-mx.google.com with ESMTPS id d2si271798pfr.4.2020.10.14.08.02.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 08:02:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as permitted sender) client-ip=2607:f8b0:4864:20::32a;
Received: by mail-ot1-x32a.google.com with SMTP id m11so3669803otk.13
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 08:02:21 -0700 (PDT)
X-Received: by 2002:a9d:649:: with SMTP id 67mr816844otn.233.1602687740074;
 Wed, 14 Oct 2020 08:02:20 -0700 (PDT)
MIME-Version: 1.0
References: <20201014113724.GD3567119@cork> <CACT4Y+Z=zNsJ6uOTiLr6Vpwq-ARewwptvyWUEkBgC1UOdt=EnA@mail.gmail.com>
 <CANpmjNPy3aJak_XqYeGq11gkTLFTQyuXTGR8q8cYuHA-tHSDRg@mail.gmail.com>
 <20201014134905.GG3567119@cork> <CANpmjNPGd5GUZ0O0NuqTMBgBbv3J1irxm16ATxuhYJJWKvoUTA@mail.gmail.com>
 <20201014145149.GH3567119@cork>
In-Reply-To: <20201014145149.GH3567119@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 14 Oct 2020 17:02:08 +0200
Message-ID: <CANpmjNPuuCsbV5CwQ5evcxaWd-p=vc4ZGmR0gOdbxdJvL2M8aQ@mail.gmail.com>
Subject: Re: GWP-ASAN
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Alexander Potapenko <glider@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="aun/Hmxd";       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::32a as
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

On Wed, 14 Oct 2020 at 16:51, J=C3=B6rn Engel <joern@purestorage.com> wrote=
:
>
> On Wed, Oct 14, 2020 at 04:25:41PM +0200, Marco Elver wrote:
> >
> > While I can see that it'd be nice to catch larger and larger OOB
> > strides, I'm not sure where we should draw the limit.
>
> Ideally you wouldn't.  An alternative design would reserve a virtual
> memory chunk, maybe 1GB to pick a round number.  If you add a bitmap of
> free pages, you need 1GB/32kB or 32kB worth of bitmap.  On allocation
> you search for a free range large enough for the allocation and guard
> pages.  Notice that this works for larger allocations as well, you're
> not limited to 4k.
>
> Scanning 32k from the beginning is clearly horrible, so you remember the
> last position you scanned in a per-CPU variable.  Different CPUs have
> different cursors, reducing the odds of stepping on each other's toes.
> You should also limit how much you are willing to scan.  A 64B cacheline
> worth of bitmap would cover 2MB, so maybe 1-2 cachelines.  If you don't
> find a good spot, fall back to regular memory allocation and move your
> cursor to a random location for the next allocation.

Interesting. It's certainly more general, but adds a lot of complexity
to address 1% or less of cases. Maybe there's a middle-ground
somewhere that I'm not yet seeing. But this is something for the
future...

> Anyway, this is bordering on a bikeshed discussion.  You should get the
> existing patches in first, then we can consider possible improvements.
> No point blocking a 98% solution just because it could be a 99% one.

Fair point. And we do hope it'll get into 5.11. :-)

> > > Unmap could be made cheaper by doing it lazily.  It is expensive,
> > > particularly on large systems, because it involved TLB shootdown acro=
ss
> > > many CPUs.  It can also amplify latency problems when you keep waitin=
g
> > > for the slowest CPU.
> >
> > It already is done lazily. We only invalidate the local CPU's TLB (on
> > x86) and no IPIs are involved.
>
> Nice!  I haven't read that far yet, but clearly should!
>
> > We have found that a sample interval as low as 10ms is still not
> > noticeable. Since the tool is not meant as a substitute for KASAN, but
> > a complementary tool, we think sample intervals for a large enough
> > fleet will be closer to 1sec. But here our current guidance is to
> > monitor /sys/kernel/debug/kfence/stats across that fleet to decide on
> > a suitable sample interval.
>
> I'm leaning towards being more aggressive, but I also tend to receive
> all those impossible-to-debug memory corruptions and would like to get
> rid of them. :)

;-)

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPuuCsbV5CwQ5evcxaWd-p%3Dvc4ZGmR0gOdbxdJvL2M8aQ%40mail.gmai=
l.com.
