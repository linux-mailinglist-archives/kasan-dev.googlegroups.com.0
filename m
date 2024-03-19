Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7UO42XQMGQEG23XRYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id ABFAC87FDAC
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 13:39:28 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-6e71495a60dsf2712176b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 05:39:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710851967; cv=pass;
        d=google.com; s=arc-20160816;
        b=kvNRm25jrAM+tpelgVc0pfwX6W2M54/c/xbzHJHO3IIO/fyfkgOQh9hK5G4LlPjiwp
         q3NEePzignMCfmq3VXZG0ZGmfMjLhG9upiqE7hcSejiK1j3cQ0rtEQc2J3103TrKVGUo
         QW+oLdVgaDnbIwV5mGeJBqym6boav80hLtQ+piT6QX3IIUEkl8xOV1+WyrhnVOk+3Z9F
         yB/grqlXYz2E/C7QcwQAkKCYi0dmpQDYG7jFwZ0ZQWIKVH7CbYKjmCXgv59ZIFdMMLRN
         tEb+Ihk+A4lTdnHD08jLVFfrcbIY849Tb2HWaaRYxmBixNLbaadk9ZCIMFYkVFhHf37d
         ZLHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=LZDR2bKwuyP8xCjPNvZ1fmx6BhT5+0mzv4SprxJbe3o=;
        fh=+tWRLF16HxuRUkcgjAYutNqsrCvrLPrC2EESxUSL7oE=;
        b=RyBmkwnzP9znIwaBF3Ju6mxue5q/hsUGG14qG9lRsqzzFjlDtid3B5cpOqe+H9jK/L
         MNLvCT2uTHguAQEHQp+rRpERPMIKwtXHRqjgORk3gysiDVol3vxZ7hzSJRYS6uW/9MF3
         xlDUoRt1y+WRZWdyBsUmybL+KyQj3/34BEaztb2JkjP0DpGx61VJpS9Y4yYpyt5fbxhp
         BG8Ixau5NakUILABSUAPwIqEMURDgPDMaufG97/ezBZcU/OvjlCr7iEcCutjRc+YqQ45
         /E5hHrMzrV7qBta6Q0MbExMDPkzK7D0/C4SX0Uxwh7VU0oWtzxiBphEmg0RDBpW4r17e
         BZTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="pZ+/vDes";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710851967; x=1711456767; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LZDR2bKwuyP8xCjPNvZ1fmx6BhT5+0mzv4SprxJbe3o=;
        b=B7FOhfxEAQjmvzxnx5q2b1u3irFzTEkP6USoO4xKXtk13iv4EBK2v8sNhXIGRNbDZa
         Wet42bNGNNtZBEF2QG7rAk+MmvIggCkCLcgifu8E1HkOqDxymnu+5RjtDTqoUtiTLwIS
         N717yK9GCiSf8rFHWuFrVJnjSbTwpQfjIdLxPjpu+ZBNDP7Rz/XW0ex+ZUIfFzBpkr+b
         8AL3GAR2X35M/bF7EbVUQQI693hlcCoc2tlbOss7rxeNMiYXUeyTaMTvkLgES7zJIXu8
         64WHTa5PBX5cm3h03fWMpO6tMkQV45e0f2qWA7+eP/rNU1o1qxWMn5Y99iWMIO69GUHw
         subA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710851967; x=1711456767;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=LZDR2bKwuyP8xCjPNvZ1fmx6BhT5+0mzv4SprxJbe3o=;
        b=fGb6mnliSflOuQuBKPT4AogEwjjsUk9S7r1h/Yaa5GutOcqskNz+/EkGx5lNIY7Mhp
         PvZoTF7a4KzFnmuO8dn+c31EQugcdKgq6gYeG11pzmsPOWKlXIsA9uPnU4IJuCLYFQ8n
         c7Micn2q5xu+x6Fm4e1bFhxeohWBNgLbl12My3+5kHl7+IED/rE2728njygtHy76qEGk
         XgQZxgzTGC7Qz5gKATUaETOui2rf02Txikgou11DfcNhKOKhx9tRpPvF8XE+D2/1LNC4
         N5tkuhBKc6PGPUVvfM9LkZVDPY/Z/K14qjY9g5NCe+rAu8Ga+3+3amzv2ze19NXys7qq
         LGmA==
X-Forwarded-Encrypted: i=2; AJvYcCXu96sW4h/QNvFvumSwn+OZxgDaaJgbz1/cxRcwLLU4XYx75idG0OpWPkQHFQmC3Aq8g5EApJy0Nj80Pp9JwKyBGUz2oB9jTA==
X-Gm-Message-State: AOJu0YxAHoU/YPO2XXgy72qddLjDo3nViib3Pq+bmBxgC4IZTPlrQjNJ
	20RXtjXMOfrjRXa2a5c5JnB/FWOpD+0CSyCxi9LV3KWpBvj1Ihce
X-Google-Smtp-Source: AGHT+IHPaeIv1a+dr4aI7tNY7P8y5gn64vrSSP84YpAQ6rrfILlT3OEOG5f0l4mc2uXhTrOITN6TRg==
X-Received: by 2002:a05:6a20:b90a:b0:1a3:15e8:7e93 with SMTP id fe10-20020a056a20b90a00b001a315e87e93mr12612192pzb.56.1710851966560;
        Tue, 19 Mar 2024 05:39:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:1610:b0:29c:5a19:1c32 with SMTP id
 n16-20020a17090a161000b0029c5a191c32ls3525656pja.1.-pod-prod-06-us; Tue, 19
 Mar 2024 05:39:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWTWeNFZG4aqPaJQ9jfGA35HT6yPv1bBk5PcvhuPLh7PdYiwCEvn3FQnRnYkKkXdR2Gv6A491snCFX2s/FhQdVUSxtV9H2J25fvuA==
X-Received: by 2002:a17:902:ec8d:b0:1dd:8c28:8a97 with SMTP id x13-20020a170902ec8d00b001dd8c288a97mr17191488plg.6.1710851965354;
        Tue, 19 Mar 2024 05:39:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710851965; cv=none;
        d=google.com; s=arc-20160816;
        b=e13L4wZy8BfO1cET2xfYkiRGfT4mdXxIWkXsBhgVknchomr2ciLxZvIzNM2VvTnNsv
         hFr0YSJ08Dws6NsJgTuomGhf/0in+0RCvopdM+JQZlTJjgbrbIIDm4XImiQOtZ8Z/3sY
         KsEBMUgFW+gSiCc6cIyjFptsbP+YhEvtsepYl5FJxUL4UWmsiNZvAEakEB1HVJt209J9
         a68/CxvZGM5TjnPbzvOEwxdsgaQajX9kGb17YvbS2I0NEnjGsEfhITogvGKEwsDVdhGx
         cjDoJsc/k4BZtEoprytNSvF/nGe6nR3vFPz0GNQGbKLFVRJi6Um8EOs8+jsjcVQYy89Q
         QEag==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=JB+hqT6GbC7x8e7B3kg2ZXAusMKqsBrFmJKSr64voZA=;
        fh=zsADesgcsyTsy3qELRqZe/qSljXnMXV6ybK2aaB7Z7U=;
        b=TGK5tJhxO1z2ozmByQotC7/IV2KmS+iytHILGUt7FZvCWNTxsnOsWsw0z0w7jCqRzq
         9cy4HQprtT+UWwqVyOVcAXaldUea8CyrhTBYvPsJp1cnTldHSTErM8YPDjoBUqHx8ypw
         KDF6FAXnJEhIwOSIH3fy6/1Jfu+/OIvF/u75/uG89uLNzIsu809sn2fDYaBXYX3H87/K
         botZOFLYaoKGT71UJNwCceARZFO/xcbuAgQWgynga3iVhtr9adbcKPyXOjNeiv3mMO/g
         fXSiPE9uizRmXUQ+2pb8iDZXbjaZW5d9MYl344rIOl3TwChFKU8efKB/9juZHei9I8lL
         6dXA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="pZ+/vDes";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::233 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x233.google.com (mail-oi1-x233.google.com. [2607:f8b0:4864:20::233])
        by gmr-mx.google.com with ESMTPS id lh8-20020a170903290800b001dddd207d97si842261plb.10.2024.03.19.05.39.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 05:39:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::233 as permitted sender) client-ip=2607:f8b0:4864:20::233;
Received: by mail-oi1-x233.google.com with SMTP id 5614622812f47-3c38d76384cso867298b6e.2
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 05:39:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX3ngvIsHXrHfo7L25TseE0Rjvm/4AjlzMlSJB1jtA3IaxElnJY/+OyccOlLmohAlY4zzjz010LeYXITpOa2iwECYC4uKNA+KkE2g==
X-Received: by 2002:a05:6808:1284:b0:3c2:aaa4:a6f7 with SMTP id
 a4-20020a056808128400b003c2aaa4a6f7mr19008575oiw.24.1710851964392; Tue, 19
 Mar 2024 05:39:24 -0700 (PDT)
MIME-Version: 1.0
References: <3b7dbd88-0861-4638-b2d2-911c97a4cadf@I-love.SAKURA.ne.jp>
 <06c11112-db64-40ed-bb96-fa02b590a432@I-love.SAKURA.ne.jp>
 <CAHk-=whGn2hDpHDrgHEzGdicXLZMTgFq8iaH8p+HnZVWj32_VQ@mail.gmail.com>
 <9692c93d-1482-4750-a8fc-0ff060028675@I-love.SAKURA.ne.jp> <CAHk-=wgA1N72WfT9knweT=p1jhHGV3N0C2Z+7zvGL+LgG-AwXA@mail.gmail.com>
In-Reply-To: <CAHk-=wgA1N72WfT9knweT=p1jhHGV3N0C2Z+7zvGL+LgG-AwXA@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 19 Mar 2024 13:38:45 +0100
Message-ID: <CAG_fn=X71NCOnqNrtU9rJ4eeGZsxLCxKT=Cq9J9dq9q+Re9syA@mail.gmail.com>
Subject: Re: [PATCH v2] x86: disable non-instrumented version of copy_mc when
 KMSAN is enabled
To: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Marco Elver <elver@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, 
	Dave Hansen <dave.hansen@linux.intel.com>, "H. Peter Anvin" <hpa@zytor.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="pZ+/vDes";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::233 as
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

On Thu, Mar 7, 2024 at 1:09=E2=80=AFAM Linus Torvalds
<torvalds@linux-foundation.org> wrote:
>
> On Wed, 6 Mar 2024 at 14:08, Tetsuo Handa
> <penguin-kernel@i-love.sakura.ne.jp> wrote:
> >
> > Something like below one?
>
> I'd rather leave the regular fallbacks (to memcpy and copy_to_user())
> alone, and I'd just put the
>
>         kmsan_memmove(dst, src, len - ret);
>
> etc in the places that currently just call the MC copy functions.

(sorry for being late to the party)

We should probably use <linux/instrumented.h> here, as other tools
(KASAN and KCSAN) do not instrument copy_mc_to_kernel() either, and
might benefit from the same checks.

Something along the lines of:

=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D
static __always_inline void
instrument_memcpy_before(const void *to, const void *from, unsigned long n)
{
        kasan_check_write(to, n);
        kasan_check_read(from, n);
        kcsan_check_write(to, n);
        kcsan_check_read(from, n);
}

static __always_inline void instrument_memcpy_after(const void *to,
                                                    const void *from,
                                                    unsigned long n,
                                                    unsigned long left)
{
        kmsan_memcpy(to, n - left);
}
=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=3D=
=3D=3D=3D=3D=3D=3D=3D

(with kmsan_memcpy() working as Tetsuo described).

We can also update copy_mc_fragile_handle_tail() and copy_mc_to_user()
to call the instrumentation hooks.
Let me send the patches.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DX71NCOnqNrtU9rJ4eeGZsxLCxKT%3DCq9J9dq9q%2BRe9syA%40mail.=
gmail.com.
