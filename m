Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS4OXX2AKGQECBKKJBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x93b.google.com (mail-ua1-x93b.google.com [IPv6:2607:f8b0:4864:20::93b])
	by mail.lfdr.de (Postfix) with ESMTPS id 726A51A37AD
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Apr 2020 18:03:24 +0200 (CEST)
Received: by mail-ua1-x93b.google.com with SMTP id i35sf101944uai.14
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Apr 2020 09:03:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586448203; cv=pass;
        d=google.com; s=arc-20160816;
        b=bilgaLYzZWge02RRkO7+F0VhfnFbHlv3cBXdJgqh8SGaI+qgJkhGZFmJi8qoE5Vcxf
         QcEMrFqmADnafj7D/gd0h9Vw645MzWCpV+Zdg0uyaC7GOiK/xKMTQS+tKzd7A3J939eV
         mtUC41au5PMwhZ9ndQYRqBIkQfhm8lg3keTFcjkWznLGFdbQdblpQaSGgHdwmFCx1MEo
         JsMRk96dTB6eYyjhrs0QuuhVl3Izj+j5AeT5rditmtUWGIF8HIYnfgxyFYsfmlX50huG
         TWOWx75Arp1zwo9Uyu/KKQaKtlNc62anEYY3e6V+dUbUc7f2hTHWUggT6BhfgMBDSH7t
         +hdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=lO05qkAfnVYq6JIBcImwMR+6WDSI7hO610P3S4uIiyU=;
        b=R//DKacXte4ed2VsUO7XVG/jXsbEzN/HsdpnWJsnVIC+lJU2y8WB9uprgD6Bsod0VP
         jObH+xvGb5MY+JvOPFrjNnQee6YIpzcrZX5D4MAWU1Ma5I1tL4b6wGfsGtSupeAEKZ/X
         DDumKRIgT8G0KTV6tBk5w6TM+pI0XAsuVXYQ/Cu3363CgCz6v3RGdzMigdNzoB4ayhiY
         SJkZ4rXuQAut7iEJBLqmJM6VHSR4/7UEvZm4hxkbxgOAQfWxHRCpy9uwARBiCwjDzoGY
         IXxD8q5otrKslPj9TdIVyNlFsGBSpmv5U2P25jatNmC3BQ2x5F3xN9DvwLV8J74Hj9GF
         EEKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hTXModHk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=lO05qkAfnVYq6JIBcImwMR+6WDSI7hO610P3S4uIiyU=;
        b=j61MNCVC6CiCFswYr6ocJkWtVpAu+oXbJFb+9zFtluQVOJ8zK5MYUt1WpBrJunnImf
         nVDJ4r6anGSR6oA7TD4c3Xt6fWxjU09KPV6mjyXiyauP3AiuJwfagQ1dysEoVAm5NC3b
         qrAf9SArklJa8i8wsd4wGfR05/51cp0O6GBePAjOY5jnoAx5huDFjx8j6EQNXmdgRxT/
         M/NexpezcfnK7A2bgfZwJ7L9omV1JUC34E1LrrwoCHjWy8oVUkhw7o6hx1MAC2bCfNdF
         4uhuCcrB1qU5M+Dp/w0prSD+3a7W3a8aUHNDojjeigo8o95rBpr6eL4F4L27IiSHgQE9
         9Isw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=lO05qkAfnVYq6JIBcImwMR+6WDSI7hO610P3S4uIiyU=;
        b=dpYs/Y1v06uGqGXFYpxwX74FeFrdX7ZD6T3sy6amokTWDrYGm8iXtBdORa3LG8nv+d
         dITNgWnu28W4aOclFguKN7vgPXL7i/M0qBui/NzgbwIx6xKB7kuS3H3kqTP+H2QbkLjG
         M/2sbknXJIae3w4PUcZ8I7GFOEkdZCyqWa0Fjw+uh0x0F49XK4NXp34v3+8yr2EFj/fz
         crQXWal8V8lrv1LqeCVfj/fT0o2ngc7SQwAgIR2q25N1ctqp5tlNkZIX8MLa2rBClY/v
         u3ND5jJ0lKLnGJC6oRWXU6qUr5ANL14Pf8UlCg8E1ywjmA+Z/ESyV11fv/cwu1WyYx9z
         EXPA==
X-Gm-Message-State: AGi0PubRCNPwCKTsyPaTfj2BS6UOiXWWuaWyuhkeUZffIZtwffMzrHHt
	orvS032hKZm9t9CV8IKQ1aA=
X-Google-Smtp-Source: APiQypKcYgZVFW15UwRAbCLKcfMoi905nKyaQi2jSeWXBc3VOHMsLQAzt0H1vMMIdnajHJRy2VJ3nw==
X-Received: by 2002:a1f:3649:: with SMTP id d70mr326247vka.12.1586448203334;
        Thu, 09 Apr 2020 09:03:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:29c5:: with SMTP id p188ls1622230vsp.10.gmail; Thu, 09
 Apr 2020 09:03:22 -0700 (PDT)
X-Received: by 2002:a05:6102:3224:: with SMTP id x4mr600924vsf.32.1586448202913;
        Thu, 09 Apr 2020 09:03:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586448202; cv=none;
        d=google.com; s=arc-20160816;
        b=idSJqxV8npbSjrJZ1X1bgEk321q/wWI9lDo2c4S5oDXwF+ZpqNr2qCzg0bcF/vL/zL
         77TUchRjJC2EpOwEygTFLkpsbEWQCAAfyxH8Mi35agIAN/rj9FMBcXc21YVhn2qCnaDs
         puttpmUA2MYNR0YMZD1rtc1BLiUEFQlPnBPp1xij1zvlBZl59xoOyddqGhZS4yo+tec6
         tXWx5zQ0awYrPExttP8d+sIUC8wcacFLQ9V6DVcnix+o3ghZT6sl6g7nZjyPK5DSkfcu
         R96Bynj6w63O+v+fJAnL5WRpWQ0DpH3Qp+tbblfjy1TyqZxcXAyOYSk1KReEvpYwzSEu
         +zHA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=tjHIQBCBSrHwNHPc99hMBF0pIDG2KesjmgOXuqoKDMM=;
        b=yOfDqyCyB0WEle75+5hyNvXhQ2a3NHtx41NAqOeEpejnS0sRSA8I7z/3e2C5OamKfQ
         tdQUtaeVu2uOaLNy3oMzHkGDwNOqVj2dOh8KuimFW+sjzRmY3uT7j1pEtil75EVrQZY4
         hxiX+j4KoteMCZk5qNAcU22eb4N6ZuV1YvidTjm/wp8pTb89boHU4xnyhaGNgie3/P8Y
         rmRA6/fgrjFrGwCn32Rw2hpQ6vya+Fp95BB9biL82kNBlG3uKK5QfEPlhCk4UO2CrbG5
         QMyKs77V2IGTJYkZhddDJjwYKb0wfSLItoSWy+9hrBp6grLwqTW+dNUzOCalUpIWIFCi
         l57Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hTXModHk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x241.google.com (mail-oi1-x241.google.com. [2607:f8b0:4864:20::241])
        by gmr-mx.google.com with ESMTPS id g6si707509uab.1.2020.04.09.09.03.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Apr 2020 09:03:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as permitted sender) client-ip=2607:f8b0:4864:20::241;
Received: by mail-oi1-x241.google.com with SMTP id d63so299716oig.6
        for <kasan-dev@googlegroups.com>; Thu, 09 Apr 2020 09:03:22 -0700 (PDT)
X-Received: by 2002:aca:620a:: with SMTP id w10mr1792454oib.121.1586448202131;
 Thu, 09 Apr 2020 09:03:22 -0700 (PDT)
MIME-Version: 1.0
References: <E180B225-BF1E-4153-B399-1DBF8C577A82@lca.pw> <fb39d3d2-063e-b828-af1c-01f91d9be31c@redhat.com>
 <017E692B-4791-46AD-B9ED-25B887ECB56B@lca.pw> <CANpmjNMiHNVh3BVxZUqNo4jW3DPjoQPrn-KEmAJRtSYORuryEA@mail.gmail.com>
 <B7F7F73E-EE27-48F4-A5D0-EBB29292913E@lca.pw> <CANpmjNMEgc=+bLU472jy37hYPYo5_c+Kbyti8-mubPsEGBrm3A@mail.gmail.com>
 <2730C0CC-B8B5-4A65-A4ED-9DFAAE158AA6@lca.pw>
In-Reply-To: <2730C0CC-B8B5-4A65-A4ED-9DFAAE158AA6@lca.pw>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Apr 2020 18:03:10 +0200
Message-ID: <CANpmjNNUn9_Q30CSeqbU_TNvaYrMqwXkKCA23xO4ZLr2zO0w9Q@mail.gmail.com>
Subject: Re: KCSAN + KVM = host reset
To: Qian Cai <cai@lca.pw>
Cc: Paolo Bonzini <pbonzini@redhat.com>, "paul E. McKenney" <paulmck@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	kvm@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=hTXModHk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::241 as
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

On Thu, 9 Apr 2020 at 17:30, Qian Cai <cai@lca.pw> wrote:
>
>
>
> > On Apr 9, 2020, at 11:22 AM, Marco Elver <elver@google.com> wrote:
> >
> > On Thu, 9 Apr 2020 at 17:10, Qian Cai <cai@lca.pw> wrote:
> >>
> >>
> >>
> >>> On Apr 9, 2020, at 3:03 AM, Marco Elver <elver@google.com> wrote:
> >>>
> >>> On Wed, 8 Apr 2020 at 23:29, Qian Cai <cai@lca.pw> wrote:
> >>>>
> >>>>
> >>>>
> >>>>> On Apr 8, 2020, at 5:25 PM, Paolo Bonzini <pbonzini@redhat.com> wro=
te:
> >>>>>
> >>>>> On 08/04/20 22:59, Qian Cai wrote:
> >>>>>> Running a simple thing on this AMD host would trigger a reset righ=
t away.
> >>>>>> Unselect KCSAN kconfig makes everything work fine (the host would =
also
> >>>>>> reset If only "echo off > /sys/kernel/debug/kcsan=E2=80=9D before =
running qemu-kvm).
> >>>>>
> >>>>> Is this a regression or something you've just started to play with?=
  (If
> >>>>> anything, the assembly language conversion of the AMD world switch =
that
> >>>>> is in linux-next could have reduced the likelihood of such a failur=
e,
> >>>>> not increased it).
> >>>>
> >>>> I don=E2=80=99t remember I had tried this combination before, so don=
=E2=80=99t know if it is a
> >>>> regression or not.
> >>>
> >>> What happens with KASAN? My guess is that, since it also happens with
> >>> "off", something that should not be instrumented is being
> >>> instrumented.
> >>
> >> No, KASAN + KVM works fine.
> >>
> >>>
> >>> What happens if you put a 'KCSAN_SANITIZE :=3D n' into
> >>> arch/x86/kvm/Makefile? Since it's hard for me to reproduce on this
> >>
> >> Yes, that works, but this below alone does not work,
> >>
> >> KCSAN_SANITIZE_kvm-amd.o :=3D n
> >
> > There are some other files as well, that you could try until you hit
> > the right one.
> >
> > But since this is in arch, 'KCSAN_SANITIZE :=3D n' wouldn't be too bad
> > for now. If you can't narrow it down further, do you want to send a
> > patch?
>
> No, that would be pretty bad because it will disable KCSAN for Intel
> KVM as well which is working perfectly fine right now. It is only AMD
> is broken.

Interesting. Unfortunately I don't have access to an AMD machine right now.

Actually I think it should be:

  KCSAN_SANITIZE_svm.o :=3D n
  KCSAN_SANITIZE_pmu_amd.o :=3D n

If you want to disable KCSAN for kvm-amd.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNNUn9_Q30CSeqbU_TNvaYrMqwXkKCA23xO4ZLr2zO0w9Q%40mail.gmail.=
com.
