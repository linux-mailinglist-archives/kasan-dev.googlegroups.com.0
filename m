Return-Path: <kasan-dev+bncBCCMH5WKTMGRBFH7UL5QKGQE5JAWMDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x640.google.com (mail-ej1-x640.google.com [IPv6:2a00:1450:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 5C9F8272941
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 16:58:29 +0200 (CEST)
Received: by mail-ej1-x640.google.com with SMTP id w10sf4941994ejq.11
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Sep 2020 07:58:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1600700309; cv=pass;
        d=google.com; s=arc-20160816;
        b=yTiyvyqFphe32XMgJlZmlLe8OsMaCLfdHjXCLfFWPhp2YikgZoywAxYa5Yie6BWZx1
         w7l0r/JmR996eUgU9OB0NcDD+XIvAoQ3by8D8DTFB8Zc/Ngup+GyedoN9rddjtdIOxzU
         uPZXzkxvpnZvrAHHePvTmSXPrlmciOIaqkimre2wmJ6N1WrfHBHVdThbfsSH8Z7wkUnf
         V56RxQFIqdpZzHj6JV6qLnrUIWPjyKiEGjinCNF1vdFcptoCNrfRmEY8e6DKbczVb+g2
         8ngcLcv68PY03rdFCe0ZWTALihN2qOfN2JvJtz2EHjUCffVjxcPKsoVsemOv/znDLlB1
         jnpw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H35FBIIUjF5GIehK9CzTIb7aZLU/nPkY8nk1h3qNvGc=;
        b=kqhy0abbaR3b/FH32PKpe/ejKafOrnYtpQYmYgyp/0gb0/Muj8xjPq3QIZxpzQ4yY7
         40RXHcM3gpgvwVI1jd8K8DSwsm/aIuRVCTPlzDBHOJO5DtDxMagjSWpGjVW2iOAeM+EE
         B4ZULWQcjOybU/RlJboz6AyWr1UjEACdaAi76JTyB4f/aq86JAiOoqXSkUtlI2QNmxPD
         YkHTA3ism4GqWgEIKG/I+q+BYLpE4TcQEXRG6drCSOlbqbbB0TRZfRd8yfEAyNxAsy9/
         ITKfuCC7o80SwToodqFoJmVR/UoQ0IW1MAkJTCR5fgG6/oQmukRM34m9WkIdq3jx+ilF
         ExFA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pihm+3yZ;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=H35FBIIUjF5GIehK9CzTIb7aZLU/nPkY8nk1h3qNvGc=;
        b=IXkDnPqFxhTvjpYU1lgOhLocpMdTGt7EtVEp2JkHVbmeOTg3h7nqg4MJ7wWRCzUJ7w
         /sOujnzbDw5ixpiJECD+nlvf6sqfqSyfpgckALxWPbnWM97QnRhAKNbQaSxOW/vFprFT
         isdYVSDAS/KaCoo5rbxS+TYT841HW1l8pYjP0ojMM1l+1YrH+ES9wfvRG4TPs93SEkkr
         o2TFj9phiLaFcWsBTrS66wiDdGG5j0I5rcQF3c5mqoP4y0wqIjCWvWEI0eCeDIPKRpRd
         musgAgOqX/9y9LfDGlrsBlnBIBZO1HjBq1xELDr6EEgNqTNqQbIi1D+3itpFfTNnPnlW
         l1ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H35FBIIUjF5GIehK9CzTIb7aZLU/nPkY8nk1h3qNvGc=;
        b=WaiN1s276gW6alPo941FZEXhu1bJku08oQL/OmJE4ORndnR9pwlmd0vHIvFV9g1oYL
         JhVtks/tqgCPuvdhS9sVj2zC9Xn0d4DArTNjaBNSXFS6ePLeQsc0NjbO9CTnh9pXtU8q
         cZzLl00+klywh7BqQil58argI0jjcOKCriYNQ6HA9peDR+9Q/RHxNpcxieh00IOT1LQz
         cht3ZeHEFhjoNwGjYjv69zAdyL//pMJL3nLveqDtFmjsR/41pQuDUnfnTGTQYpzfQ1jB
         lL0ZXwsntvwzfeKgHbEXAjvNd5qa1Fag75JueXq4f1FfmSgMrFyhyN0+9Tt36Guch8j3
         R+4A==
X-Gm-Message-State: AOAM533dhoIaYXhctzRgEdYDL/MZkgNfzTz+8oyqGo8O920T2YHR0Yyn
	3dK0sicDQwPoOTQKEMjdv8E=
X-Google-Smtp-Source: ABdhPJz9np3ZtX1Zft1zhmpELfJTyiGFWnjZNqpDoZv/B/A0Qwag5pgFi9ERFACMAkPA4uZBFtcUeA==
X-Received: by 2002:a17:906:1787:: with SMTP id t7mr52086053eje.173.1600700309076;
        Mon, 21 Sep 2020 07:58:29 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:bf49:: with SMTP id g9ls7928854edk.1.gmail; Mon, 21 Sep
 2020 07:58:28 -0700 (PDT)
X-Received: by 2002:a05:6402:209:: with SMTP id t9mr63627edv.208.1600700308151;
        Mon, 21 Sep 2020 07:58:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1600700308; cv=none;
        d=google.com; s=arc-20160816;
        b=qq+y/NIkXn8x90vQ1oT64fA5z2bYSGV9WsLG7hjNleE2KhLGCofRrCdgoBhkx5Ctp6
         mFrZMkcAHOinJFn7vWrWLx09SSWyxiFzsNlQwk5Ikj2dAbQn97s+DVJ9Rj96hX1J0ieQ
         FVvM6bfkRXp2ygdgQrh1XRKuqoCa0soByaPVnQdU4UBQlMBytaIZXeOR+aT1TXX1/cnI
         UTvfuMQY8rxSrGh/u3b63sGsxWYCp5SbaNKz7Ex8tyrcPDyj7MzbchDCGbYyCLDfC1Hx
         R2+AWGmG1kt15KOZkX50RKSVgdG+wSlEaFfcUnB1MCG0UscPinHbKa1V6SvR2JrNnEYw
         Fj/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=J02fUfHHsGOzjhQyl/tGfPUtfr9BJPAQxULq+u6ZRXM=;
        b=zVelX4IC+EcAfWnlLdcdPnEsqg9DN7pYD5eDydt/gY0hgY+qvDkoRcGrboj2ezHmC/
         J6Wwv0pl3tWrD53GCtNGFlRR6MFl16xG1R4OdkbZ9qbZxrb8mX5yd9dIjsxs7hZv9CMW
         5lu201131IWNgO4AZXLBCLe5FXeUADLE+Wy8Cs+p8+RKR0YCPlLLrlCACfPwzknfjxX+
         EObEE5gOBRvF5FxZUDRBIcpiXv90r2bdA02Q6w3LLjutj40znacAYmNFuW+zfh9wnVuU
         nqf6XGDQkVdw8GQe4jthMM5+NWTijHl5MXaJNaPKqUTGrh5HLS7AF9g7wVpKqyDGcG8l
         miCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pihm+3yZ;
       spf=pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x343.google.com (mail-wm1-x343.google.com. [2a00:1450:4864:20::343])
        by gmr-mx.google.com with ESMTPS id k6si265770eds.3.2020.09.21.07.58.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Sep 2020 07:58:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as permitted sender) client-ip=2a00:1450:4864:20::343;
Received: by mail-wm1-x343.google.com with SMTP id d4so12446609wmd.5
        for <kasan-dev@googlegroups.com>; Mon, 21 Sep 2020 07:58:28 -0700 (PDT)
X-Received: by 2002:a7b:c210:: with SMTP id x16mr47411wmi.37.1600700307697;
 Mon, 21 Sep 2020 07:58:27 -0700 (PDT)
MIME-Version: 1.0
References: <20200921132611.1700350-1-elver@google.com> <20200921132611.1700350-4-elver@google.com>
 <20200921143059.GO2139@willie-the-truck>
In-Reply-To: <20200921143059.GO2139@willie-the-truck>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 21 Sep 2020 16:58:16 +0200
Message-ID: <CAG_fn=WKaY9MVmbpkgoN4vaJYD_T_A3z2Lgqn+2o8-irmCKywg@mail.gmail.com>
Subject: Re: [PATCH v3 03/10] arm64, kfence: enable KFENCE for ARM64
To: Will Deacon <will@kernel.org>
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitriy Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jann Horn <jannh@google.com>, Jonathan.Cameron@huawei.com, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, sjpark@amazon.com, 
	Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	"the arch/x86 maintainers" <x86@kernel.org>, "open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, 
	LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Linux Memory Management List <linux-mm@kvack.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pihm+3yZ;       spf=pass
 (google.com: domain of glider@google.com designates 2a00:1450:4864:20::343 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Mon, Sep 21, 2020 at 4:31 PM Will Deacon <will@kernel.org> wrote:
>
> On Mon, Sep 21, 2020 at 03:26:04PM +0200, Marco Elver wrote:
> > Add architecture specific implementation details for KFENCE and enable
> > KFENCE for the arm64 architecture. In particular, this implements the
> > required interface in <asm/kfence.h>. Currently, the arm64 version does
> > not yet use a statically allocated memory pool, at the cost of a pointe=
r
> > load for each is_kfence_address().
> >
> > Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> > Co-developed-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Alexander Potapenko <glider@google.com>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> > For ARM64, we would like to solicit feedback on what the best option is
> > to obtain a constant address for __kfence_pool. One option is to declar=
e
> > a memory range in the memory layout to be dedicated to KFENCE (like is
> > done for KASAN), however, it is unclear if this is the best available
> > option. We would like to avoid touching the memory layout.
>
> Sorry for the delay on this.

NP, thanks for looking!

> Given that the pool is relatively small (i.e. when compared with our virt=
ual
> address space), dedicating an area of virtual space sounds like it makes
> the most sense here. How early do you need it to be available?

Yes, having a dedicated address sounds good.
We're inserting kfence_init() into start_kernel() after timekeeping_init().
So way after mm_init(), if that matters.

> An alternative approach would be to patch in the address at runtime, with
> something like a static key to swizzle off the direct __kfence_pool load
> once we're up and running.

IIUC there's no such thing as address patching in the kernel at the
moment, at least static keys work differently?
I am not sure how much we need to randomize this address range (we
don't on x86 anyway).

> Will
>
> --
> You received this message because you are subscribed to the Google Groups=
 "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an=
 email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgi=
d/kasan-dev/20200921143059.GO2139%40willie-the-truck.



--
Alexander Potapenko
Software Engineer

Google Germany GmbH
Erika-Mann-Stra=C3=9Fe, 33
80636 M=C3=BCnchen

Gesch=C3=A4ftsf=C3=BChrer: Paul Manicle, Halimah DeLaine Prado
Registergericht und -nummer: Hamburg, HRB 86891
Sitz der Gesellschaft: Hamburg

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DWKaY9MVmbpkgoN4vaJYD_T_A3z2Lgqn%2B2o8-irmCKywg%40mail.gm=
ail.com.
