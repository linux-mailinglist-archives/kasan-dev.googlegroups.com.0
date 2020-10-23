Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBSULZT6AKGQE2HUNDYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 66AC52973F1
	for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 18:33:15 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id 2sf777753wrd.14
        for <lists+kasan-dev@lfdr.de>; Fri, 23 Oct 2020 09:33:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603470795; cv=pass;
        d=google.com; s=arc-20160816;
        b=FCgA/zKP0xZAYVquGSUZYQ6nmaNyOrwARMrXEMVt3eBWhXwbqFBl6z2+dbTKyE3i+a
         cyy1fohjEYoBkLWXIpsiZRcpyuQsxvTlfmS/2l3Iu8fiorgMng5DXHhbhd+lM+AlKCU8
         OtvaEEnYtFshmmWbMro5tHaA+FTRFc7zIp9t2I0omCzj83aEOjmT8thZMv+dFflIL0k+
         oKSOZBf76qolpfZF6BH7ZXC6peyqOizCO6OVOn2penIDx0dI+6eNWYhyM5YyefvKjWh1
         RG6KCdN8omSfbLhA0jklK5YB9dBdldlX3FbOXsdEILFvKi0OiqunI6WkOcrGy3lTGb66
         UO4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=+mn52CePD+r6k4IshmMsbPjoZAliUhu/M/JoVpPpkio=;
        b=tpDRYOOP9GnhL9sX31lmxhzrQabjR7FUp3qlOEdB8kexB/0DTZ6nH9ATsAC8oT0zB2
         RHdCm+p6bIjuuHlB0RRcbLw0AHpQLG4CW98882+vvuz5WCfaDXggILxXz/OORqPaS7Kd
         ucv2+rOvI7cDQ5lss+laIdyfjAcS7gqjscz8Q7zWe4v4yKmKHq1cHX++3Fn5zU96fF7J
         lJOSU46V30oF9xj4RInoTTSOefJEpQ7TEhDrnCJy7jaKOnYQl3llt8B1fLo+nq4IJRTq
         uhK2EO2M7Sr5AC/WPB0haJE9fCeg4XmKhdmTiXWDI+CaISJUwRtaP62P4TjQUGyQtgP6
         11/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=bKJlp5Zi;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+mn52CePD+r6k4IshmMsbPjoZAliUhu/M/JoVpPpkio=;
        b=Xx4qzBeSGHLm28dRUGT2Wd8ICDICO2ZxbrJNHFTJFCO53RZNf6fVhU+kJ1mu0osrXt
         lg39DH/95jbNS4NhcU+umDmCrpYAXgrMkQy2nO2TYAIOiYoMxYCXYNQr2vPhOPL62pfL
         ToVs6sLjlRcZkXsfRbGJPyOG8DHGjExBj5JH37Pqoa92zbw2im4R7BzransKaOQkGUCh
         yZmLFStSWp1lX4049yzVjcQ0o1ZOOdF/Ok4XGTvBY1Ytf+zItz4ZCnAIjlO6eZU7Wx5N
         yvTGw/VTkEgpPDViToW+VFUKXF8shL8d3J7AR4m70wDmKTxE7j6g1Y5/uwBgx4IQnX7V
         xB/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+mn52CePD+r6k4IshmMsbPjoZAliUhu/M/JoVpPpkio=;
        b=g/zqVNyoqzWBLCs5QmpuKandAqVhPcnro5HvMlDcRB+L40mi7tECByWqnEurarQ/ds
         YxQPkcMObjyfyfDT0U7hqiKSS067/yRwfYFecDxWgxQWfUDr6kULRAawxwfMHVByjYzu
         EoNerYLM24IZwmuLFGvxosHQ/jtSYe6uOWUpgVzANLFJMwAeZlvEoc/zCM9+SgQtCB8k
         nUP+uNdlQj6vzKi1DIMa/oe7MB7bp/124aAaQxz+brrcT0UnWZZe59zRbaF9w6KKjkUX
         8OTd8MuXJPLJITM7uYfGWRo/L+LsDKstXmsJuVb//16R0e5FKunM/73+Gwf1yKjhj9Kr
         04Pg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531OngMngex5hYETxku8HxYIjVin4Icmzy2FK5oScNXUnxuDJH2/
	+1rCR5YTxdmp+TzQP2euj1E=
X-Google-Smtp-Source: ABdhPJzmWCVUpKcJEB3XCwWmJThXE7WmUgeY24x+sQ0WGTSnMC/OBqsEO92ogSmc3FOkWsBZBSZ+NA==
X-Received: by 2002:a1c:750b:: with SMTP id o11mr3319928wmc.32.1603470795147;
        Fri, 23 Oct 2020 09:33:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:2506:: with SMTP id l6ls1164120wml.3.canary-gmail; Fri,
 23 Oct 2020 09:33:14 -0700 (PDT)
X-Received: by 2002:a7b:c7c9:: with SMTP id z9mr3326784wmk.91.1603470794080;
        Fri, 23 Oct 2020 09:33:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603470794; cv=none;
        d=google.com; s=arc-20160816;
        b=TrRRHl00DzXhr58PfGVQTxfdE0YabgEy1N1+WT8ziWK/n+erQ9iGREKB3fuKSdzpw9
         kph/Bn4Hf4r6epBnLtx4xStg3X7apQoVZxaKA2zFrqINxbjGuPn2I5SCW4lrswqHWzln
         +CgGVIhN2/TaHucuEm9WqhEMP4XUvSUrDiRL80OSZ0OWKDtU+u5N6lJovQWlFzKaB1ey
         fVSKgHpCW1E1iTblLxdq5YZVWWaX1+9hexaPlF83NSnq8IUmPioCKvrXGxC2WfUDtaUI
         9e4v3d6ZY9m7eC9SCrdnblWvfspgF6+CmmcCINlfG4HGCbo/sHCGp9ypnopG/k0Ikle0
         VucQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=5/+Z2DTY0X3UNE1zOAnDc3GMvU3/neAbYyAwV9Uv1sQ=;
        b=gcdLkBK2MRSgLozKm2AAFxb7Otuz3ARp5A1MOL+g55mwOXK7TitToP1bjeznxC09Hd
         uP2nR625hGnVdxzi3FtVGeWraFSRzEWGqEFwotZDt11kXEP2oGAkb14fpr6OYDIxiaF0
         1xifJ+FKzlYQBjcVQnMwFadMB1hunTOaB/wfVYf6X4ycRvHtP9rqHdLikoU62UI7P8+6
         WVZrQumD7ohYRQ5cQrdbnChXOL/xLecWd/usdCdoCCupXgkscdLwyQt+Mwp0eiLgGb0W
         ltYTCqP0PWu8dXzFUJrkICA8cA3sPnhSdjShIhs8meJK7OIkl4M6PlG+52PZW4rIw46Q
         Qzfg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=bKJlp5Zi;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-lf1-x141.google.com (mail-lf1-x141.google.com. [2a00:1450:4864:20::141])
        by gmr-mx.google.com with ESMTPS id j5si66522wro.2.2020.10.23.09.33.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 09:33:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::141 as permitted sender) client-ip=2a00:1450:4864:20::141;
Received: by mail-lf1-x141.google.com with SMTP id l2so2842924lfk.0
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 09:33:14 -0700 (PDT)
X-Received: by 2002:a19:8c07:: with SMTP id o7mr1011408lfd.525.1603470793340;
        Fri, 23 Oct 2020 09:33:13 -0700 (PDT)
Received: from mail-lf1-f49.google.com (mail-lf1-f49.google.com. [209.85.167.49])
        by smtp.gmail.com with ESMTPSA id k13sm209752ljh.136.2020.10.23.09.33.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 23 Oct 2020 09:33:11 -0700 (PDT)
Received: by mail-lf1-f49.google.com with SMTP id b1so2802177lfp.11
        for <kasan-dev@googlegroups.com>; Fri, 23 Oct 2020 09:33:11 -0700 (PDT)
X-Received: by 2002:a19:c703:: with SMTP id x3mr971141lff.105.1603470790607;
 Fri, 23 Oct 2020 09:33:10 -0700 (PDT)
MIME-Version: 1.0
References: <CA+G9fYvHze+hKROmiB0uL90S8h9ppO9S9Xe7RWwv808QwOd_Yw@mail.gmail.com>
 <CAHk-=wg5-P79Hr4iaC_disKR2P+7cRVqBA9Dsria9jdVwHo0+A@mail.gmail.com>
 <CA+G9fYv=DUanNfL2yza=y9kM7Y9bFpVv22Wd4L9NP28i0y7OzA@mail.gmail.com>
 <CA+G9fYudry0cXOuSfRTqHKkFKW-sMrA6Z9BdQFmtXsnzqaOgPg@mail.gmail.com>
 <CAHk-=who8WmkWuuOJeGKa-7QCtZHqp3PsOSJY0hadyywucPMcQ@mail.gmail.com>
 <CAHk-=wi=sf4WtmZXgGh=nAp4iQKftCKbdQqn56gjifxWNpnkxw@mail.gmail.com>
 <CAEUSe78A4fhsyF6+jWKVjd4isaUeuFWLiWqnhic87BF6cecN3w@mail.gmail.com>
 <CAHk-=wgqAp5B46SWzgBt6UkheVGFPs2rrE6H4aqLExXE1TXRfQ@mail.gmail.com>
 <20201023050214.GG23681@linux.intel.com> <356811ab-cb08-7685-ca01-fe58b5654953@rasmusvillemoes.dk>
 <CAHk-=whFb3wk0ff8jb3BCyoNvNJ1TSZxoYRKaAoW=Y43iQFNkw@mail.gmail.com>
In-Reply-To: <CAHk-=whFb3wk0ff8jb3BCyoNvNJ1TSZxoYRKaAoW=Y43iQFNkw@mail.gmail.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Fri, 23 Oct 2020 09:32:54 -0700
X-Gmail-Original-Message-ID: <CAHk-=whGbM1E0BbSVvxGRj5nBaNRXXD-oKcgrM40s4gvYV_C+w@mail.gmail.com>
Message-ID: <CAHk-=whGbM1E0BbSVvxGRj5nBaNRXXD-oKcgrM40s4gvYV_C+w@mail.gmail.com>
Subject: Re: [LTP] mmstress[1309]: segfault at 7f3d71a36ee8 ip
 00007f3d77132bdf sp 00007f3d71a36ee8 error 4 in libc-2.27.so[7f3d77058000+1aa000]
To: Rasmus Villemoes <linux@rasmusvillemoes.dk>
Cc: Sean Christopherson <sean.j.christopherson@intel.com>, 
	=?UTF-8?B?RGFuaWVsIETDrWF6?= <daniel.diaz@linaro.org>, 
	Naresh Kamboju <naresh.kamboju@linaro.org>, Stephen Rothwell <sfr@canb.auug.org.au>, 
	"Matthew Wilcox (Oracle)" <willy@infradead.org>, zenglg.jy@cn.fujitsu.com, 
	"Peter Zijlstra (Intel)" <peterz@infradead.org>, Viresh Kumar <viresh.kumar@linaro.org>, X86 ML <x86@kernel.org>, 
	open list <linux-kernel@vger.kernel.org>, lkft-triage@lists.linaro.org, 
	"Eric W. Biederman" <ebiederm@xmission.com>, linux-mm <linux-mm@kvack.org>, 
	linux-m68k <linux-m68k@lists.linux-m68k.org>, 
	Linux-Next Mailing List <linux-next@vger.kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev <kasan-dev@googlegroups.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Geert Uytterhoeven <geert@linux-m68k.org>, Christian Brauner <christian.brauner@ubuntu.com>, 
	Ingo Molnar <mingo@redhat.com>, LTP List <ltp@lists.linux.it>, Al Viro <viro@zeniv.linux.org.uk>
Content-Type: multipart/mixed; boundary="000000000000e2112705b259227d"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=bKJlp5Zi;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::141 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

--000000000000e2112705b259227d
Content-Type: text/plain; charset="UTF-8"

On Fri, Oct 23, 2020 at 8:54 AM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Fri, Oct 23, 2020 at 12:14 AM Rasmus Villemoes
> <linux@rasmusvillemoes.dk> wrote:
> >
> > That's certainly garbage. Now, I don't know if it's a sufficient fix (or
> > could break something else), but the obvious first step of rearranging
> > so that the ptr argument is evaluated before the assignment to __val_pu
>
> Ack. We could do that.
>
> I'm more inclined to just bite the bullet and go back to the ugly
> conditional on the size that I had hoped to avoid, but if that turns
> out too ugly, mind signing off on your patch and I'll have that as a
> fallback?

Actually, looking at that code, and the fact that we've used the
"register asm()" format forever for the get_user() side, I think your
approach is the right one.

I'd rename the internal ptr variable to "__ptr_pu", and make sure the
assignments happen just before the asm call (with the __val_pu
assignment being the final thing).

lso, it needs to be

        void __user *__ptr_pu;

instead of

        __typeof__(ptr) __ptr = (ptr);

because "ptr" may actually be an array, and we need to have the usual
C "array to pointer" conversions happen, rather than try to make
__ptr_pu be an array too.

So the patch would become something like the appended instead, but I'd
still like your sign-off (and I'd put you as author of the fix).

Narest, can you confirm that this patch fixes the issue for you?

                  Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3DwhGbM1E0BbSVvxGRj5nBaNRXXD-oKcgrM40s4gvYV_C%2Bw%40mail.gmail.com.

--000000000000e2112705b259227d
Content-Type: application/octet-stream; name=patch
Content-Disposition: attachment; filename=patch
Content-Transfer-Encoding: base64
Content-ID: <f_kgmh3alt0>
X-Attachment-Id: f_kgmh3alt0

IGFyY2gveDg2L2luY2x1ZGUvYXNtL3VhY2Nlc3MuaCB8IDQgKysrLQogMSBmaWxlIGNoYW5nZWQs
IDMgaW5zZXJ0aW9ucygrKSwgMSBkZWxldGlvbigtKQoKZGlmZiAtLWdpdCBhL2FyY2gveDg2L2lu
Y2x1ZGUvYXNtL3VhY2Nlc3MuaCBiL2FyY2gveDg2L2luY2x1ZGUvYXNtL3VhY2Nlc3MuaAppbmRl
eCBmMTM2NTk1MjMxMDguLmQwMDZhZjkxNWQ0YSAxMDA2NDQKLS0tIGEvYXJjaC94ODYvaW5jbHVk
ZS9hc20vdWFjY2Vzcy5oCisrKyBiL2FyY2gveDg2L2luY2x1ZGUvYXNtL3VhY2Nlc3MuaApAQCAt
MjExLDEzICsyMTEsMTUgQEAgZXh0ZXJuIHZvaWQgX19wdXRfdXNlcl9ub2NoZWNrXzgodm9pZCk7
CiAjZGVmaW5lIGRvX3B1dF91c2VyX2NhbGwoZm4seCxwdHIpCQkJCQlcCiAoewkJCQkJCQkJCVwK
IAlpbnQgX19yZXRfcHU7CQkJCQkJCVwKKwl2b2lkIF9fdXNlciAqX19wdHJfcHU7CQkJCQkJXAog
CXJlZ2lzdGVyIF9fdHlwZW9mX18oKihwdHIpKSBfX3ZhbF9wdSBhc20oIiUiX0FTTV9BWCk7CQlc
CiAJX19jaGtfdXNlcl9wdHIocHRyKTsJCQkJCQlcCisJX19wdHJfcHUgPSAocHRyKTsJCQkJCQlc
CiAJX192YWxfcHUgPSAoeCk7CQkJCQkJCVwKIAlhc20gdm9sYXRpbGUoImNhbGwgX18iICNmbiAi
XyVQW3NpemVdIgkJCQlcCiAJCSAgICAgOiAiPWMiIChfX3JldF9wdSksCQkJCQlcCiAJCQlBU01f
Q0FMTF9DT05TVFJBSU5UCQkJCVwKLQkJICAgICA6ICIwIiAocHRyKSwJCQkJCVwKKwkJICAgICA6
ICIwIiAoX19wdHJfcHUpLAkJCQkJXAogCQkgICAgICAgInIiIChfX3ZhbF9wdSksCQkJCQlcCiAJ
CSAgICAgICBbc2l6ZV0gImkiIChzaXplb2YoKihwdHIpKSkJCQlcCiAJCSAgICAgOiJlYngiKTsJ
CQkJCQlcCg==
--000000000000e2112705b259227d--
