Return-Path: <kasan-dev+bncBDW2JDUY5AORBL6IS3FQMGQEKULFCZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53d.google.com (mail-ed1-x53d.google.com [IPv6:2a00:1450:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id DD954D1633D
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Jan 2026 02:47:28 +0100 (CET)
Received: by mail-ed1-x53d.google.com with SMTP id 4fb4d7f45d1cf-64b98593517sf8419122a12.3
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 17:47:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768268848; cv=pass;
        d=google.com; s=arc-20240605;
        b=g9QtUbrWNBeT53VxsBNtkVsR9j6ssgsOhwGZw7GD/sOt0Dq75IFpihjGD7U1FJ3ryU
         Te9MMMqUMf4dlQzrAyorWCDc9uecwcHwXKPO/pB1/ai3c9KgFtzuDkb5J39+EpsJaUiz
         awTTxEvW4hW4izf6s2gRnlsmC3Q6TPtApeix3txnylAUGTr21tSQRDHtTS5A4Wv/doas
         XuHBrwGO2OGgg4h3ar+zdZqAHvkEXhsywJnU98CxPPH7CbB6V9O8KA1PL+CiYZV/VKqx
         4emrZ6chiNE53wCU92JYmnzRpqvT3Ob0uljiUVVxYYH5hQNarL4DFAooxlXXC6r5wrrT
         3D0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=K32J4MvquA/TzRqFVszn65ZtMCNbNPh29N8pf+jISck=;
        fh=+Bhm0kQpTcWjp/tYJ80VlMSDTzegqkeKIcZcXvDmBVQ=;
        b=GZJM8zCem3UvOZr/hD1lOPo5ZsUgXT/TPcExmZ0et2qn8CqulXPGYWlbBQEZZjMAyD
         wfU0qYS++ajvy48mRaBcd6LRb+/uNQr4bfQIAsyUT6/iEcFp/E+bvG5/fc24fARMsEtX
         0tfUmVKwziwGiJyIwCdoNKjy8OFnSIqizUbtPys2f00NgCGcWAxpwcexT+hG4ACG9YZc
         qwzZVA23mYcQeXuceYIwWDv7WjJu3V+oj978UzliDX2b9eT3bZFMWB015QJJb45jcY9r
         bV8Z7xOzdFJEX9ptGIYU1u18EpeInoexMjRmyg6uTQi+YhKaaJaondnnrQZJtwayecBW
         Mv2w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BPeyWnpP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768268848; x=1768873648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=K32J4MvquA/TzRqFVszn65ZtMCNbNPh29N8pf+jISck=;
        b=qThPsmUGQYsuCbtBuUXY9JRnuFW8uuMyliCJr+td67yahagK7xb6gVYNjZd4/RqVdl
         hA1amB6oo8LJ1H7LB+oKck5dPCQU2tHGsedXRl0te4/ZUjngtCNH83jCcifAuUpP6JBm
         xbIzNnLhWYc/KJuuSwsWZjDp8jIs75fdRKUFqVEGcF77+WJZd4s59swl403UipksYJiL
         KdMJkASrD2xdBsYzvpxhJ11kp4itpRVQ9oSNKX0IPA7nAA/YI3noMlzmNf3/pa9uAPjv
         vEU590+uWJ5J4jUSkEFsVHrcPc5qyOLXjdLi74jJ1xuAfWFE2R7ZdFJBkoUPvZEII+LA
         BdDg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1768268848; x=1768873648; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=K32J4MvquA/TzRqFVszn65ZtMCNbNPh29N8pf+jISck=;
        b=eDgq5FxTCS13IDSO3GWWvZUwY3YTRdD69tHwCYsf68QP8S7SxkQgq2zYUaqDI4mQE0
         Lv9kcz3jIRXFKXKLY4eIME+oBMWsQA5wksLiZDVcNylMLMDgc0jFDIAZ2pM5PHH+D+jq
         XRQ9BRMP5yBuYB21JbRj7jnA15JshgrJCizq/+xV7b1aIcFQkWxNsKNtgo0J/Qpe87/Q
         4dAvI9Fh3oTdkBmcU3gNX5c/4pdbgS4Bb1G0gD5jycSnJnRaiXkviVy+eupB54Uye4Wm
         ZE5hciXkUdO/YNKi+YoNwmIB+86EfrEO7TH3F09fPQaN95EB3Dki9oAHbdbArCg8okSU
         tbUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768268848; x=1768873648;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=K32J4MvquA/TzRqFVszn65ZtMCNbNPh29N8pf+jISck=;
        b=ZpgCc6C74ldOvOdXfO8iy8YcCjz9p3vm+yoS9gV8otm5qh1rWRQJNvn+eiTAhwBc9l
         502iEn3XeCw8K9csV+mzQnyTug/qXh5OCfYDl/MHp4NAsxt92O9n9EJIANkTXuAD1FJH
         uWHKbqAj4iAtLDu5qBJ2S7IXlupsclK0ugbfDcCRbCoe1g5pZGwNaNZXjyeosLYe+EX9
         zg1Zv28f71pISHzQw2HDPSmtUxsCdyn6X1r+fbLYwcpl5X+Ekc6rrCbqcgFnh0AJ6rt1
         GpyjllZl7OpSrqZ4aeGFCa2wSWJ9Wk7Fp4hzHa74FI+UwOcx01iBzi6XqvxJyJrC3PV6
         5AKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXj/XHeT8ltaUUy9jmr8+PT2HOnX0dDdeuMQQmJq6iHLshvKGAPnYmJJXGo/yCwA2fhTfJuBw==@lfdr.de
X-Gm-Message-State: AOJu0YwLnheAcbhXcF5DLmwo7EpNyyoWxCvaftRGnW5ghW0rBhc/3zw9
	NuPYUwp5uyotuI7gfOGGlgeOubUC2avCzvglVXW7CZXUJedtWlnYk+wD
X-Google-Smtp-Source: AGHT+IFF1GDLvS0vjOzoUupptBBWgonFOxINitTQ0kv1820nk9bwpmJ1xuJGTnbHDly8KXbhFghN3w==
X-Received: by 2002:a05:6402:34c2:b0:64d:2769:8460 with SMTP id 4fb4d7f45d1cf-65097dd1197mr18986076a12.6.1768268848367;
        Mon, 12 Jan 2026 17:47:28 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FgoRAunIquRZCkE84tw44WBM1VIBy7SLv2TCUKhkn+FQ=="
Received: by 2002:aa7:dd06:0:b0:64c:7925:f275 with SMTP id 4fb4d7f45d1cf-650748d4084ls7203404a12.1.-pod-prod-09-eu;
 Mon, 12 Jan 2026 17:47:25 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVp4blc1Dpm2NH2179zIR+FvA+xKj8sxdid6JdrOPH3Oa4HADw9l2Hn3Dn64aFNzFQaD5OwfDXjxC0=@googlegroups.com
X-Received: by 2002:a05:6402:34c2:b0:64d:2769:8460 with SMTP id 4fb4d7f45d1cf-65097dd1197mr18985974a12.6.1768268845089;
        Mon, 12 Jan 2026 17:47:25 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768268845; cv=none;
        d=google.com; s=arc-20240605;
        b=U1oxzl8YLhCRGA6P8zdLxm/Vm4id4vrPtBF26dwP418Ghmm5+NvEj6aiejQ24Kd4a3
         GgeQYVtJcm4kdeHAaXcD8wHbBB99UGtk98muhxswIjuhIsAt4fmUi4wzmDOIxWzJ+vLQ
         Rt8puMsY1pSVQKJxNjSChbjZkCPheUpyYl5xy4QUE8Pnq3YKEOqdswLlbN0UJXtWRFyC
         OzQ7ruHNph9mw3PGdctnFUe4r7JbDCoqNasNWVoBvE9lB9vTbuC/gQ+OWXbarLEFIFmL
         u5yeS0JEAV06o1wHYmYZUsNXzhn57CAR2OiweQ5iNH1rU1iVxEfUyrPSpt+9gy1CdtOi
         FJZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=r5Zya1QiiH1g15sa03C60PMdmscKG1ONGxgStc03n5E=;
        fh=CCAFkKsfqbf7Q1gSm04N7C/uWD/wqLB1ZXeDsZnKwh0=;
        b=Y5jHv+EuEN9QGinNL6vbQU9F/rpIn/5SDfIQIyUn3++Li9dcC/ENM/q2BBCjFN+Ify
         sCv2+riiTP7kDNUtZFfx2yrdWF2poeu8ny6/OxknDoUpImp2DvvgP08AGunHTe0qRTMU
         AdHkxl8UypBdU2ZvE4Oqs8efxNa6FvCFMYEfIlKUuRqz9rAQ17JpFaPER8poh5L1FwuR
         KWvq01g8Y6qd3PAjKnuZR7RTY9Tiic4mAjQ4EQI8UBdrSNRvn7fOrkkzM43sFwDF2q1O
         dOoQdh1LJCn+/jAFiHflj8+dkFvq8xK+q89WDEIQY/+GOv9qV1jJ5/9vU8jwLPierlg1
         UnRA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BPeyWnpP;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42b.google.com (mail-wr1-x42b.google.com. [2a00:1450:4864:20::42b])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-6508d723064si409146a12.7.2026.01.12.17.47.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 12 Jan 2026 17:47:25 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b as permitted sender) client-ip=2a00:1450:4864:20::42b;
Received: by mail-wr1-x42b.google.com with SMTP id ffacd0b85a97d-42fbc305914so4987859f8f.0
        for <kasan-dev@googlegroups.com>; Mon, 12 Jan 2026 17:47:25 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCULfG0/A0lKGr9N7GeZUgzd5kH7ktQQUTC3EgK7wo5PUyDYq/A+7TFMiOCVttAgcbGpFNzTaUM3yxk=@googlegroups.com
X-Gm-Gg: AY/fxX4KZK4s1EpoKFS7u8X5puIcD6cy+9FuPPslB84Dg02EPR2K3mz1QWoPWkWbgW4
	wyznk8YE+H3WXxSgSbvTQGWJHqy3WcN1RuuS+ZqTfx4ubOqHtg8hr4Mhj7V9tmMRMivaD08aE9H
	LeuRMs5cC1AB4KH/Jibp7azq66j0qRLy+yXPjn2jktcjk70kdo69ubml7bO20MDEUBkBbuif3D0
	R2piEtZD9zorefKJ6ujs90IQlZlv3RLgJwSB+YTI9XPd86LL1tbnDWZ/K+bEwRDB9VbPg9FYMt/
	2fA49FTezw9QPXdJhDulZEwTKZq1Mg==
X-Received: by 2002:a05:6000:1a89:b0:431:342:ad4e with SMTP id
 ffacd0b85a97d-432c37a9b5emr27240018f8f.62.1768268844511; Mon, 12 Jan 2026
 17:47:24 -0800 (PST)
MIME-Version: 1.0
References: <cover.1768233085.git.m.wieczorretman@pm.me> <20260112102957.359c8de904b11dc23cffd575@linux-foundation.org>
 <aWU-oL8oYS_PTwzc@maciej> <20260112125348.124d201ef2baf762561a43af@linux-foundation.org>
In-Reply-To: <20260112125348.124d201ef2baf762561a43af@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Tue, 13 Jan 2026 02:47:13 +0100
X-Gm-Features: AZwV_QjCQ1fbtNH6MxAuTA9Y-OoKsLsk_NAIZlsBpLK13R0P_Z1v4NHXaV8E6rI
Message-ID: <CA+fCnZci8YK04PPMT7gkMrrNHbMB3Ks+D4xG-5XkEOaywyrGhw@mail.gmail.com>
Subject: Re: [PATCH v8 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
To: Andrew Morton <akpm@linux-foundation.org>, 
	=?UTF-8?Q?Maciej_Wiecz=C3=B3r=2DRetman?= <m.wieczorretman@pm.me>
Cc: corbet@lwn.net, morbo@google.com, rppt@kernel.org, 
	lorenzo.stoakes@oracle.com, ubizjak@gmail.com, mingo@redhat.com, 
	vincenzo.frascino@arm.com, maciej.wieczor-retman@intel.com, maz@kernel.org, 
	catalin.marinas@arm.com, yeoreum.yun@arm.com, will@kernel.org, 
	jackmanb@google.com, samuel.holland@sifive.com, glider@google.com, 
	osandov@fb.com, nsc@kernel.org, luto@kernel.org, jpoimboe@kernel.org, 
	Liam.Howlett@oracle.com, kees@kernel.org, jan.kiszka@siemens.com, 
	thomas.lendacky@amd.com, jeremy.linton@arm.com, dvyukov@google.com, 
	axelrasmussen@google.com, leitao@debian.org, ryabinin.a.a@gmail.com, 
	bigeasy@linutronix.de, peterz@infradead.org, mark.rutland@arm.com, 
	urezki@gmail.com, brgerst@gmail.com, hpa@zytor.com, mhocko@suse.com, 
	weixugc@google.com, kbingham@kernel.org, vbabka@suse.cz, nathan@kernel.org, 
	trintaeoitogc@gmail.com, samitolvanen@google.com, tglx@kernel.org, 
	thuth@redhat.com, surenb@google.com, anshuman.khandual@arm.com, 
	smostafa@google.com, yuanchu@google.com, ada.coupriediaz@arm.com, 
	dave.hansen@linux.intel.com, kas@kernel.org, nick.desaulniers+lkml@gmail.com, 
	david@kernel.org, bp@alien8.de, ardb@kernel.org, justinstitt@google.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, kasan-dev@googlegroups.com, 
	llvm@lists.linux.dev, linux-arm-kernel@lists.infradead.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, x86@kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BPeyWnpP;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42b
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Jan 12, 2026 at 9:53=E2=80=AFPM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Mon, 12 Jan 2026 20:08:23 +0000 Maciej Wiecz=C3=B3r-Retman <m.wieczorr=
etman@pm.me> wrote:
>
> > >OK, known issues and they are understandable.  With this patchset is
> > >there any way in which our testers can encounter these things?  If so
> > >can we make changes to protect them from hitting known issues?
> >
> > The gcc documentation states that the -fsanitize=3Dkernel-hwaddress is
> > similar to -fsanitize=3Dhwaddress, which only works on AArch64. So that
> > hints that it shouldn't work.
> >
> > But while with KASAN sw_tags enabled the kernel compiles fine with gcc,
> > at least in my patched qemu it doesn't run. I remember Ada Couprie Diaz
> > mention that passing -march=3Darrowlake might help since the tag suppor=
t
> > seems to be based on arch.

FYI, there are some known GCC issues with arm64 SW_TAGS mode as well:
https://bugzilla.kernel.org/show_bug.cgi?id=3D218043#c3.

> >
> > I'll check if there's a non-hacky way to have gcc work too, but perhaps
> > to minimize hitting known issue, for now HAVE_ARCH_KASAN_SW_TAGS should
> > be locked behind both ADDRESS_MASKING and CC_IS_CLANG in the Kconfig?
>
> Yes please - my main concern is that we avoid causing any disruption to
> testers/buildbots/fuzzers/etc.

I left some comments, but from my/KASAN point of view, the series is
ready for linux-next (but this could wait for a week and maybe the
next version of the series).

I wouldn't think there would be disruption issues: one would need to
deliberately enable the SW_TAGS mode for x86 (as GENERIC is the
default mode when just enabling KASAN). But I don't mind locking down
x86 SW_TAGS to be Clang-only for now if GCC is known not to work at
all.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZci8YK04PPMT7gkMrrNHbMB3Ks%2BD4xG-5XkEOaywyrGhw%40mail.gmail.com.
