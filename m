Return-Path: <kasan-dev+bncBD42DY67RYARBNGERGBQMGQEYK7KI3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id 0665D34DC6F
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 01:26:45 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id dz17sf11954579qvb.14
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 16:26:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617060404; cv=pass;
        d=google.com; s=arc-20160816;
        b=RPIXkZdJRvH6+wWRg6G2U8v28toJrfl36vxjBpkGae6+ju/iO4h83uRRn9jswbCuNK
         12OZpi3M6iUnkw+Hslz0ei0uL/3z2WvIhUImVlUZGMsDcdFLtHWJBFov15N6sTPvaUSS
         OWn1LfOr+rgHK239qwdyqI8HBTVHeAfzOi4eW7PiuXOIuItC02SGWTDR4rddek+NHWof
         XcFWB6ah/fCJKRyv0SBRPkb+8u+Ou58NSXEAv5o1YbbB4eiA1UMa8aXlwsELWQmPcjnn
         vBjY50p4OYMB7zpWWtaeLAsndfiylQvZ74ZfLCHpGByFGwCxE9y73vxeYgmyMEePcPME
         ld0w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=GNprBS8mZwBAbEuH71H9QKBDEzalm06e62UnY1vT+pU=;
        b=QxiDfkpYSIMr/i5Bp2QnNulDAwJsGuyhaMveb+7OrsW4/5b7e+AZiaJ4mntvhpJlqW
         4B09s0KpfDlhy9zCky1r1tJJoox38SHlla8I0kCiL/0DCoUHtfwKJoEV1bMExFRSUc05
         1KAD1KriYek4R7n5EPvcyIEfH207GXJusrG8EP+Iu+4tyhkFk6UAmPTWoxB6L8eQ2Lll
         1IMy3wWlCur3Vi+q7av83csBHNVznnaGahdunuxK62lb19bGWqUMncK+l6n6gLHPfzh4
         atQ9uDX6UGkVkwUJth+WiRjkfSZBD0DMlS5aW088q1dLx5eK8eJkjSKfjxEA+2gUnZgc
         fm2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=DuUgS+zB;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=luto@amacapital.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=GNprBS8mZwBAbEuH71H9QKBDEzalm06e62UnY1vT+pU=;
        b=PEVdxC/+m27PM692eJbcXxxrBdo0Ps54jsYyR8MxAICV6n9Zb+WDwsUfybGDAQTVts
         HMZbkSd9182IeO3vYmGZ5Ax8fmijjIZitfya+aly6mUgJrGZaGihgl9GKclafDgpLlBR
         Q3b+gUEL6Rv40StVx496NO49RLnHSur0+VtFYG2Uedtfr5/sAYKEqMfzlP/xzjP6jMOR
         jsW2umU8TtbYT5kelCSeJjPTpD4RahplVi9SEv4j89opdOq22czBEsP2WsAKkZSmAhQC
         cu6z7uhBdu7F7joRxnWgcBq6PU8A1QVONq2eaCE+dyxc34GKJMZ9rqVdlAzyqivIGJ7z
         5pAA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=GNprBS8mZwBAbEuH71H9QKBDEzalm06e62UnY1vT+pU=;
        b=Ah3UFFmlJ0qikVEW8zOX6JJPqZhR55PxJspgrcOTshZ+mTUQm5J55eX6G+J3hQQC4d
         S6hWeS/EkZco4tO/umDBunwvfyzaY13y0IgzYuU4xOaJ/HJxr9LcWQFccG1pp/m0hxqo
         XouYE3zCwIEYq0VD0fs/8MeJSSQ5ndrNXII3KKACS4bUnDWmeEnajLFQs/kDDrAVONPI
         LIcwoLHc/cl6QdAE/gNsfhjFuiYM3yHzRRXxGUkDGUZmL3lMZmCA40sa38DSr2eNrTkn
         b+wecGHSqE4Vy12NjKp8IJVbB2R9K6Gl2/NWhXvnJsch9abUXEx/8xxlLO0PPJgYqkJG
         3NfA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530c81B4s6BzmaBEjVGXrAvVtLchPSNuBF6+ihGKcUquzBY4gQ+f
	ERlA1LCTMW/Hwp48UWLLOS8=
X-Google-Smtp-Source: ABdhPJyIOZWISOUAwZ8YidabfbfwJ3zOFGkQEpjHpldWB+QT5UwA589wg0nhEvdHh9+sFlLlvEsiVw==
X-Received: by 2002:ac8:6606:: with SMTP id c6mr25682128qtp.76.1617060404127;
        Mon, 29 Mar 2021 16:26:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:620a:4455:: with SMTP id w21ls9400018qkp.7.gmail; Mon,
 29 Mar 2021 16:26:43 -0700 (PDT)
X-Received: by 2002:a37:688f:: with SMTP id d137mr27821635qkc.246.1617060403704;
        Mon, 29 Mar 2021 16:26:43 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617060403; cv=none;
        d=google.com; s=arc-20160816;
        b=MtVKiTh+lcfFfVl8xTJ1qLk4bnJv0PxrLZaSWV+kr+M+k9ztGWyxGLLBuWoLBAWz2Z
         pixojxKrHTuZDO8kuena1Su2Ptv7arW9+NL4nQSe1OGmaKWrFg1as7OwNKqUmkD0zcff
         ASNjpsnfq10oh3Q5Z/mINA+7PvUXZjeFh6UbC8MJElCg5fES5LxpcAyPzN5znu32Oly6
         T+oVAMHuyPTR27/TmnB30lnGXlDtMASHbJSKCRp/q17EO3iYCEY5DyiQihuaWEBfhtwJ
         e3VaaC9AfCo0KoB1MJbuAq18ie8TQgvRmL3N8BKwYUpTYv8/XP4KlkiIUfV89iCUMI2E
         /xIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=waSXWCTE99vHc7CuELi75wqDgOVkGsht2MlSvB7uCsw=;
        b=qYe0/79EEuYzevE6DEDicTnnNJIVxhDKfFEiIGWHxzrygXIvcTRi4Y3tXL4JsXl4sv
         fWRMk5VOq/0Jxm0V29M5JoHy3QaoIsLRf+YT0eLf4nXiRL3aONKPgqYVkDKQe8nnIihe
         kCrSw1t78GRqWOC8X8vyqW+U7k7KODY1G+h2zPg9v1znMJZLLTIpQ8mAUgAOpcm0qEE+
         EViLm6JMTc+ULoapFm/6TDCLbxTRAFB5Vo40RVpepXlVSGjV2vek0ZQoGzyFEUUybhP4
         rKP4xTcfamMJl7qDqpVhkKvd93UaeNialdkXeDw7LF9euE29PDkLQObzndyaX2fVO+Ah
         W0MQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623 header.b=DuUgS+zB;
       spf=pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=luto@amacapital.net
Received: from mail-pj1-x1033.google.com (mail-pj1-x1033.google.com. [2607:f8b0:4864:20::1033])
        by gmr-mx.google.com with ESMTPS id b201si1315717qkg.6.2021.03.29.16.26.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 16:26:43 -0700 (PDT)
Received-SPF: pass (google.com: domain of luto@amacapital.net designates 2607:f8b0:4864:20::1033 as permitted sender) client-ip=2607:f8b0:4864:20::1033;
Received: by mail-pj1-x1033.google.com with SMTP id x7-20020a17090a2b07b02900c0ea793940so8480018pjc.2
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 16:26:43 -0700 (PDT)
X-Received: by 2002:a17:902:f68c:b029:e5:ca30:8657 with SMTP id l12-20020a170902f68cb02900e5ca308657mr30950976plg.78.1617060402851;
        Mon, 29 Mar 2021 16:26:42 -0700 (PDT)
Received: from ?IPv6:2601:646:c200:1ef2:e17c:78f7:dc94:55dd? ([2601:646:c200:1ef2:e17c:78f7:dc94:55dd])
        by smtp.gmail.com with ESMTPSA id e3sm6214707pfm.43.2021.03.29.16.26.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 16:26:42 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Andy Lutomirski <luto@amacapital.net>
Mime-Version: 1.0 (1.0)
Subject: Re: I915 CI-run with kfence enabled, issues found
Date: Mon, 29 Mar 2021 16:26:41 -0700
Message-Id: <2F989294-F0D4-4F1C-86A6-E657F60EF2A8@amacapital.net>
References: <CANpmjNO+_4C0dYs6K8Ofy-xVSYxO8OtXSRbW6vCXBYdjJSjqbQ@mail.gmail.com>
Cc: Dave Hansen <dave.hansen@intel.com>,
 "Sarvela, Tomi P" <tomi.p.sarvela@intel.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 Dave Hansen <dave.hansen@linux.intel.com>,
 Andy Lutomirski <luto@kernel.org>, Peter Zijlstra <peterz@infradead.org>,
 Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>,
 Borislav Petkov <bp@alien8.de>, the arch/x86 maintainers <x86@kernel.org>,
 "H. Peter Anvin" <hpa@zytor.com>, LKML <linux-kernel@vger.kernel.org>
In-Reply-To: <CANpmjNO+_4C0dYs6K8Ofy-xVSYxO8OtXSRbW6vCXBYdjJSjqbQ@mail.gmail.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (18D61)
X-Original-Sender: luto@amacapital.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@amacapital-net.20150623.gappssmtp.com header.s=20150623
 header.b=DuUgS+zB;       spf=pass (google.com: domain of luto@amacapital.net
 designates 2607:f8b0:4864:20::1033 as permitted sender) smtp.mailfrom=luto@amacapital.net
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


> On Mar 29, 2021, at 2:55 PM, Marco Elver <elver@google.com> wrote:
>=20
> =EF=BB=BFOn Mon, 29 Mar 2021 at 23:47, Andy Lutomirski <luto@amacapital.n=
et> wrote:
>>=20
>>=20
>>>> On Mar 29, 2021, at 2:34 PM, Marco Elver <elver@google.com> wrote:
>>>=20
>>> =EF=BB=BFOn Mon, 29 Mar 2021 at 23:03, Dave Hansen <dave.hansen@intel.c=
om> wrote:
>>>>> On 3/29/21 10:45 AM, Marco Elver wrote:
>>>>>> On Mon, 29 Mar 2021 at 19:32, Dave Hansen <dave.hansen@intel.com> wr=
ote:
>>>>> Doing it to all CPUs is too expensive, and we can tolerate this being
>>>>> approximate (nothing bad will happen, KFENCE might just miss a bug an=
d
>>>>> that's ok).
>>>> ...
>>>>>> BTW, the preempt checks in flush_tlb_one_kernel() are dependent on K=
PTI
>>>>>> being enabled.  That's probably why you don't see this everywhere.  =
We
>>>>>> should probably have unconditional preempt checks in there.
>>>>>=20
>>>>> In which case I'll add a preempt_disable/enable() pair to
>>>>> kfence_protect_page() in arch/x86/include/asm/kfence.h.
>>>>=20
>>>> That sounds sane to me.  I'd just plead that the special situation (no=
t
>>>> needing deterministic TLB flushes) is obvious.  We don't want any folk=
s
>>>> copying this code.
>>>>=20
>>>> BTW, I know you want to avoid the cost of IPIs, but have you considere=
d
>>>> any other low-cost ways to get quicker TLB flushes?  For instance, you
>>>> could loop over all CPUs and set cpu_tlbstate.invalidate_other=3D1.  T=
hat
>>>> would induce a context switch at the next context switch without needi=
ng
>>>> an IPI.
>>>=20
>>> This is interesting. And it seems like it would work well for our
>>> usecase. Ideally we should only flush entries related to the page we
>>> changed. But it seems invalidate_other would flush the entire TLB.
>>>=20
>>> With PTI, flush_tlb_one_kernel() already does that for the current
>>> CPU, but now we'd flush entire TLBs for all CPUs and even if PTI is
>>> off.
>>>=20
>>> Do you have an intuition for how much this would affect large
>>> multi-socket systems? I currently can't quite say, and would err on
>>> the side of caution.
>>=20
>> Flushing the kernel TLB for all addresses
>> Is rather pricy. ISTR 600 cycles on Skylake, not to mention the cost of =
losing the TLB.  How common is this?
>=20
> AFAIK, invalidate_other resets the asid, so it's not explicit and
> perhaps cheaper?
>=20
> In any case, if we were to do this, it'd be based on the sample
> interval of KFENCE, which can be as low as 1ms. But this is a
> production debugging feature, so the target machines are not test
> machines. For those production deployments we'd be looking at every
> ~500ms. But I know of other deployments that use <100ms.
>=20
> Doesn't sound like much, but as you say, I also worry a bit about
> losing the TLB across >100 CPUs even if it's every 500ms.

On non-PTI, the only way to zap kernel mappings is to do a global flush, ei=
ther via INVPCID (expensive) or CR4 (extra expensive). In PTI mode, it=E2=
=80=99s plausible that the implicit flush is good enough, and I=E2=80=99d b=
e happy to review the patch, but it=E2=80=99s a PTI only thing.  Much less =
expensive in PTI mode, too, because it only needs to flush kernel mappings.

If this is best-effort, it might be better to have some work in the exit to=
 usermode path or a thread or similar that periodically does targeting sing=
le-page zaps.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/2F989294-F0D4-4F1C-86A6-E657F60EF2A8%40amacapital.net.
