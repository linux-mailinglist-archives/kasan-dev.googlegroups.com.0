Return-Path: <kasan-dev+bncBC7OBJGL2MHBBNEFU6VQMGQEMQP65JY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id B2F1C8009E0
	for <lists+kasan-dev@lfdr.de>; Fri,  1 Dec 2023 12:25:41 +0100 (CET)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-db402e6f61dsf618882276.3
        for <lists+kasan-dev@lfdr.de>; Fri, 01 Dec 2023 03:25:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1701429940; cv=pass;
        d=google.com; s=arc-20160816;
        b=DefkWQBoFeb2O3Mu+hATEvVEAL747NERGMaMEcTeqio4gylni9HAUHxAlZL/9j53+q
         wVnUdhu3AAEWVl1PE+CebEWooUzwjugB4FhRBUtLLNV6LlCeIP5ZpWGFD9mRHjqP7jjM
         Z20F7REtVmrHZ3iUTAZhpIyCjuTEhu1OSuLpVCKV9+55oMm+UT4rUJNkT4Vtlp5V6Vjx
         X9Nlk3O9wp+32ywa44Y7go05loESxIqjVSyqR19Z+rCPzwqO6GlY70siblTWTH3KV9YW
         SQG9TFr6CgvM8/3ddyKcovzB1H2/zGaGe5nZnDI6LL97zH7yVdk6jGCF9ZSinq7NUT/r
         6A3g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=InKH6rnHI/utN0OhgNlGE5qTXT9ng6LYT/QmSARiBkE=;
        fh=fwWJ42K6w6cdbJRbPUk/A0m9E3CoA/JFe3Wn1sPWXJk=;
        b=hKChMsNyvZNs0P0kfz0HvGWfmVsxGZT4CUbRRbGIJpQI6tJyYlJQJraI1D37QDY7zY
         XvTix8krzcnd4xfS4n1PDBETBjfxmKpRamG4+iS5/YYAgyIkhOhamgh3Cwd+wS6YZHBB
         XeDSVUMzsx8Ad97R/81izcEZdTK793sdhrka0ObevQ1/ptvu+4l8oR5/bv7WGz00edFk
         m3t0gUO/Bk7lVHoT49iAmNIfx44iwvtMY3k0mnSVwf0X2sZ0hN1LLfZk4T8CgKMZo5aO
         tTo4nINcpRFsVyVfEfmvNpOV6DKR9m7WIWV8sme5YqERGOpSwpWSpKQASWKv1OS+RbcP
         Mb9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pLrJ5tX6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1701429940; x=1702034740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=InKH6rnHI/utN0OhgNlGE5qTXT9ng6LYT/QmSARiBkE=;
        b=wl6Rzg2VylJdeixXpa7TgbgLhq2v59xc8w/iLAg6JaAPxsBoCXM8LVKEHHchiG9OtB
         rDPoDXcaEEg010sTpZmDto+0sdHQGWD3LZAp2CFJ9EZXkg2Lwlm3YSlA08r5d2x6WrzN
         guGGOxw3I995NX20ISP9jW+ibG6uosAq9FaKUmDUiXIzwSUQ2kAe87Yay6hWKZ8Eb1tW
         BdmpfS2uwggDgcvczmGMyV9hKFOeVXeoTW/82Bw40Ro54ACB/kj+rUB5zAWokFo7OC3v
         u2ZxjCZLGRrIyJTmKjDrLqZa9sWXKJomSwfG2UAd0MukoHVtbRaprc/spxZozK8oQIrb
         emdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1701429940; x=1702034740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=InKH6rnHI/utN0OhgNlGE5qTXT9ng6LYT/QmSARiBkE=;
        b=JPnw1YkwlLOEeyVp2KMIxMaRaw75eem0gw5WoqBXoQwMD38zDgOZADGIpdHX6+vNrW
         2Oe3TrIKR0XqE+j0w2iGzxmy04aJMj1vkuSEvo2P0U5dii/xE3qDkQL8EQQKopo3URpR
         V8oHb+neVEPn4N77D2/Qa9rcStabXSwTiKg1CcD1YDoQqGZJppuCQGYeEHbO17SDVkN/
         4rFXxuCY5RB9VlMGxT+q0PgoZ8RZBSmoUU/NRLkePC3hBVdJf/0m4EfceiBCvlS9zGht
         /pz6FHE8ydV2SxsydN91piJdz1Y+CLTjAfueITfHqwanXQ0kmRAyKySqnulSLX6GpOty
         d4bg==
X-Gm-Message-State: AOJu0YzTM388kWH/7cFPdrq+3PJ5/u5K4XE/OxmjASkMEP/v1NlNCfYS
	HtX20OTA1WQNiMw3YAAtT6g=
X-Google-Smtp-Source: AGHT+IHFMmFfzm49E2TRIyY1lYwFr9mYQ1MEQg31r6In1MbP5EfB1PU32Yn0DuFhG8HZ70gsn16vUA==
X-Received: by 2002:a05:6902:52:b0:da0:d148:391b with SMTP id m18-20020a056902005200b00da0d148391bmr23735534ybh.50.1701429940439;
        Fri, 01 Dec 2023 03:25:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d094:0:b0:da0:33b3:b1b5 with SMTP id h142-20020a25d094000000b00da033b3b1b5ls296173ybg.0.-pod-prod-08-us;
 Fri, 01 Dec 2023 03:25:39 -0800 (PST)
X-Received: by 2002:a25:50d0:0:b0:db5:43a6:3cfc with SMTP id e199-20020a2550d0000000b00db543a63cfcmr3556808ybb.35.1701429939567;
        Fri, 01 Dec 2023 03:25:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1701429939; cv=none;
        d=google.com; s=arc-20160816;
        b=K9ZZbBpV+BBh8O3MpU15i0DVwtWTy3RoPL7L6Op4vFLBShMckRXGO1qhKiuX3cvLJd
         H/rsntjPLHSw2aHLHAsmaUMCTQIDAUijmqLv5l1vEuy23fj8nU6B2QQYmZWLUC2Rwhgk
         zp2fg49kpiZwYmXJadPKqPZ/+wTKgWaj1z7MEJdxT7EvB9fIKkgl9865pQ9IN0exVtIb
         46O3HZtK9SxFKXsgGijzjq5weIDixciSEfOKQLoKk9xd8DP5A4DFSDd+THvVyiQzOggs
         oZCgFoty7dHsDC+p2Y1Obi7jkcHWiN2B2/XmjKjUXS+35qPK3qKMv1jq4g/LPRTK/vXX
         g+Yg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=jUitSoQwv0jzQMmozURzuu9CTgSmq2KcdlMAKLhzaq4=;
        fh=fwWJ42K6w6cdbJRbPUk/A0m9E3CoA/JFe3Wn1sPWXJk=;
        b=OggYDdVncEwWgPsBbiebesjFoTZLQc4ZEZESYuCsWesm7PH9a06CEqpNK5Q0pE1Yad
         U7aqivhkWP3B/f41qmLMQm73Py5/iS1sUv+OiOQGi++UGSRw3RIehzIa+tk2E3fDMhTr
         tYurV7/MgFfmPVgXnQrSd+YPdefG1GZF6DW9aQt9eX2mFQN3KsrEmR4eGMGnavEbM8D4
         v0zsSvgvcQLXTonzPqeZ1I8oye0rBvbX9Wvt9TioHyq0xikVmryBKEcJQkUccg8bt9am
         U0hnO/XSEC2NDFThnUMcYGwQMEpvoPzrzBYMlKiY7Y7BbGX6Y7RBxtK9XkTs/DQp6RuV
         jLsg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=pLrJ5tX6;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ua1-x92f.google.com (mail-ua1-x92f.google.com. [2607:f8b0:4864:20::92f])
        by gmr-mx.google.com with ESMTPS id x28-20020a25ac9c000000b00da06a7c4983si138894ybi.2.2023.12.01.03.25.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 01 Dec 2023 03:25:39 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as permitted sender) client-ip=2607:f8b0:4864:20::92f;
Received: by mail-ua1-x92f.google.com with SMTP id a1e0cc1a2514c-7c4ed6740c7so623367241.1
        for <kasan-dev@googlegroups.com>; Fri, 01 Dec 2023 03:25:39 -0800 (PST)
X-Received: by 2002:a67:eb52:0:b0:464:4f42:c195 with SMTP id
 x18-20020a67eb52000000b004644f42c195mr6922668vso.8.1701429939054; Fri, 01 Dec
 2023 03:25:39 -0800 (PST)
MIME-Version: 1.0
References: <ZWgml3PCpk1kWcEg@cork> <CANpmjNMpty5+g76RLy5uZARZAfx+Uzr+z5uAKMp-om9__2O77Q@mail.gmail.com>
 <ZWjMC9FXSEXZjNw9@cork>
In-Reply-To: <ZWjMC9FXSEXZjNw9@cork>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 1 Dec 2023 12:25:01 +0100
Message-ID: <CANpmjNMQMzsPan_1MB98h7M8c5qXeum35MEhohtuCA6OqC4LSg@mail.gmail.com>
Subject: Re: dynamic kfence scaling
To: =?UTF-8?Q?J=C3=B6rn_Engel?= <joern@purestorage.com>
Cc: dvyukov@google.com, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=pLrJ5tX6;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92f as
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

On Thu, 30 Nov 2023 at 18:53, 'J=C3=B6rn Engel' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> On Thu, Nov 30, 2023 at 12:09:14PM +0100, Marco Elver wrote:
> > On Thu, 30 Nov 2023 at 07:07, J=C3=B6rn Engel <joern@purestorage.com> w=
rote:
> > >
> > > That works for the instrumentation frequency.  But it doesn't work fo=
r
> > > the amount of memory reserved for kfence.  We should be able to scale
> > > that dynamically as well.
> >
> > Yeah, that's been requested before. The main problem is that it'd add
> > a few more instructions to the allocator fast path (in the simplest
> > version). Discussed previously here:
> >
> > https://lore.kernel.org/lkml/Ye5hKItk3j7arjaI@elver.google.com/
> >
> > Maybe it's possible to add a config option and if you can live with a
> > few more instructions in the allocator fast path, then maybe that
> > could work.
>
> Ah!  I think my scheme wouldn't add instructions to the fast path.
> Let's say we grab 1TB of virtual memory for our pool.  But we only use a
> small fraction of that range.  Then the fast path would be
>
>
>         static __always_inline bool is_kfence_address(const void *addr)
>         {
>                 /*
>                  * The __kfence_pool !=3D NULL check is required to deal =
with the case
>                  * where __kfence_pool =3D=3D NULL && addr < KFENCE_POOL_=
SIZE. Keep it in
>                  * the slow-path after the range-check!
>                  */
>                 return unlikely((unsigned long)((char *)addr - __kfence_p=
ool) < KFENCE_VIRTUAL_POOL_SIZE && __kfence_pool);
>         }
>
> Notice that we check for KFENCE_VIRTUAL_POOL_SIZE, not KFENCE_POOL_SIZE.
> Any address inside the 1TB range would return true.  Once that happens
> we can check whether the address is within the much smaller range backed
> by physical pages.
>
> We probably want to avoid having a single contiguous range, as it makes
> shrinking problematic.  But whatever we do, the more interesting check
> can happen in the slow path.

It'd be nice if that would work, but see below.

> > From this I infer you mean an effectively unbounded pool, or just
> > having a soft upper limit, right? That looks rather tricky.
>
> There would still be a bound, but something like 1TB will appear
> unbounded to most people while still easily fitting inside a 64bit
> address space.  Even if we only get 47bit effective address space.
>
> The tricky bit is that you currently seem to allocate physical memory
> ahead of time (contiguous physical memory?  I should check).  Then you
> mark pages PROT_NONE or PROT_RW.  There are two states for any page.  In
> my scheme there would be three states, with UNMAPPED being the dominant
> state.  Supporting lots of unmapped pages requires a hashmap or
> something similar.  So yeah, 98% of the work is building infrastructure.

The problem is we can't "just" hand out virtual addresses slab
allocations: https://lore.kernel.org/lkml/CANpmjNO8g_MB-5T9YxLKHOe=3DMo8AWT=
mSFGh5jmr479s=3Dj-v0Pg@mail.gmail.com/

I still think that "immediate patching" is the way to go, or just
accept the perf cost (if any).

Another alternative is "poor man's immediate patching": allow N fixed
pool sizes (e.g. 8, 64, 512, and 1024 MB .. smaller N is better), and
have 4 static branches for each size. Then is_kfence_address() will
check 4 static branches, but only 1 will ever be active. Not sure
that's better or worse than just loading the current pool size from
some variable.

Thanks,
-- Marco

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNMQMzsPan_1MB98h7M8c5qXeum35MEhohtuCA6OqC4LSg%40mail.gmail.=
com.
