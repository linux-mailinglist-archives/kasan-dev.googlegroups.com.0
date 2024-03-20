Return-Path: <kasan-dev+bncBCCMH5WKTMGRBCOZ5KXQMGQEECPK2OY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 956B7880E91
	for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 10:29:46 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-430e4afb01asf22167581cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 20 Mar 2024 02:29:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710926985; cv=pass;
        d=google.com; s=arc-20160816;
        b=ufvSVwEsuBif/rPVdLin9njq3HCaXcW2NWGPgeYkhQFs340b9fy0+iPT1GB7rHzTjg
         KWbKc9nmmuRTCgeGaPsWgnIxmn0IWt1s6P6KyQ23geM1rjfOn99Zs2Sf0JvEbcsTlAqa
         oPjEIsr6g16KTIf4XBvfGbMLZ8uhbdZdvMrqGRUZ3J4fSa1iUacARRzu9LjD+8v65QVb
         N0KZDxurdRNsX7+k99JV+METrV2MNt/mfTgeb4eRweA8L+UkvWLF3USxnoAOQqYemZyt
         qwn3Mj82Uh9MW3oIBWRbvYplzrEBbp+V3A8+ZsJs4FIoiSZDlni1bFq1aXasEj/sVMuh
         WX3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=TKzKZtAp42gCrf3cWuf2RDstxna5xYV5ChV4mqxxQ6w=;
        fh=ifH4t60aihOWRNsm3/c0ZHt345ACK0b3mwFxMCRc3xc=;
        b=rQ3ld/N13HXXX+3JcHobbBtdBjTbjuv3U8foWbjc1AibhyVa7FENd+n0lG99uSOYUu
         zj17nQF1PLnAEh8nnUfMTs/X0qu+pZptihYxOKWRDY4lsxb3RBoxu0qG48HQDltk84Oy
         avrVX4cOyNC93s4LjgXibiMUialX/HcrQ41ssT1epkvolBjrHb+e8q0nLkydBPP7ah3b
         sd7Zb1UPHabn0ebol5hIcmxpEIIclXYIB8/TJazyXjSMouQWoyT4/3uVIivdcA3daFmA
         sxVO2PeMt5DbMvVDh9FvuyYX8jReH1fCMkPjzXpl7HvoqTVkZhSduQNCW8NvJTipugBj
         dkuQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FMquJtIr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710926985; x=1711531785; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=TKzKZtAp42gCrf3cWuf2RDstxna5xYV5ChV4mqxxQ6w=;
        b=kNgyaL8PLTlX5s5/B4hXUzjCWS9B+g+cjFncXJ24Rd0NNLwRn/TLaYGx62G95L6v+Q
         BrzNnJWjo+OMXtG6/HZmqKjUW3uSX8a5j3mWRBHlnBRp5sbnrsZcEurZ24cZhM2TT4dN
         KJnZZpKLVSHF2iI6Ej9O3MKgCw31VHXV8qvEIY0Mt3dYN57dXp7AD5P+gsbyCXCSZnPs
         zFjcKuvppyKIhRa6A7sGONS9R1poDDOIAV9IafFFejXQXYOEx9o9ksTB1jEo6++bGNyw
         AohHfkqMcnF1WkPlbK3HAf2IxNAF3kHzTM4OS8tfm1RSZ9WJsjgc8JKyuhMktE1aKSfh
         KjaQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710926985; x=1711531785;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=TKzKZtAp42gCrf3cWuf2RDstxna5xYV5ChV4mqxxQ6w=;
        b=lWPxPGUX9q2i95DmqrBX2heZzgvzxNvcma32IgOvAmil3w4piz5QWf1pAoFh8RvS1E
         leEcPcnDik8pjdQEiI18KxH4T9LvWbIVVv8HXWkxekjdbWxQ3XMNcEYfcEk5H5Nw5SWe
         r7OCJzhmG2JnxlwScdu+xvYe/Is9WCfHUWdUJqMosbtITJuH07DMdoe054iqyllmy9Sr
         ti5NIXjhZtWKQERrkZNmVfN/cHLzMpJ47TLFU/CVsSVvz5XRMYxYgaA7DBbqmHSG2E38
         /IvX2+nEqeRZ38ZkoDeZ6/Oh5Dcp5NTXOxOvM/DgHzf2JVyY2ZaGPU3c8H9UXwR+Yf33
         ynyA==
X-Forwarded-Encrypted: i=2; AJvYcCXAZ8VjBnr9x8JC2QJKbtH8bk9vwDFCK1C0ThJ9fGm9LzuhZrXoAif8p+mWoxUyf2XpACQDsPs41dt/FVEcqw//WU7/PYEiXw==
X-Gm-Message-State: AOJu0Yy1qHlBO9ZUIkLqsixTvWbxzGcwch16MDH8Q/W1iZ9XWt/YdqqI
	32RNZO20o9+CpQROKmvFDGmRncEeIpTXuewopFX9G6qRux0kk2VY
X-Google-Smtp-Source: AGHT+IHycY3nD4RW2qMfsZ2iNNApvSBcNRXzRGgsUsXvmHSh5JALx2mjLWwDVEPcak3otajbeQi7Vg==
X-Received: by 2002:a05:622a:11c2:b0:430:e567:ee0a with SMTP id n2-20020a05622a11c200b00430e567ee0amr5085357qtk.68.1710926985244;
        Wed, 20 Mar 2024 02:29:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d02:0:b0:430:c273:680e with SMTP id f2-20020ac85d02000000b00430c273680els3459983qtx.1.-pod-prod-04-us;
 Wed, 20 Mar 2024 02:29:44 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVXeINP3lO4e5DYabsRCqYsxVrije6rzHS6p+aJe6m6ZLelzrPDS0d1ul6RqTDHzkmvGNqdFrSY19MKPPDb0np4pwDHhrcOpGkIIw==
X-Received: by 2002:a05:620a:3707:b0:789:dae2:1086 with SMTP id de7-20020a05620a370700b00789dae21086mr22357435qkb.50.1710926984522;
        Wed, 20 Mar 2024 02:29:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710926984; cv=none;
        d=google.com; s=arc-20160816;
        b=LDw/Z95MF58avSRKRa1QYrhw2aqsw/FRrYmyMap6NLobDxTz3XYD45tudi0FwA8sS+
         ZkLjnyvkxhogMEE78UVrEX1EwtCkAKeEFV2LFQI4ckOcmsHZBDW8kHNORymKT1/r1Iil
         W8tnI1l73Q/5C/P0Uxp0IMA+d5nqFxtHig+ryVr0qdUlBkRIp4I463T22xMnCWA1gUDx
         rJr0aMPfapnIEscjBYJNCTV36f3h9+t7NvpRMIb1JeFBlOwTAb3J3WhTn7+LaMedj2TF
         OdPjKnfDdHqHwpYvqnVtRFq/qAc/pMjmL1iG8Ahfi6Nc0lTspe/YlTMPrImEZMIv9g4l
         ZVTQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=bLyoCiqbHiSdNZKr0m0tptqhq/5sVBW4PAT9ynMrYdw=;
        fh=8cBmryd0rU2x9/CC/Zp8/5XL24K/h90NPoy0ILIRQ0M=;
        b=UvbEJaWCQ2v3UPTo6wdrhfWfD4DshfdF9YlUxIkK9zcCJU8Vm8oGXnYeQJ1H2fqNj5
         uJ3oekp482PcQJk6FxW7moE1qX1xHeT+28rCfDJ14JBKu6KTl+Z1KIdr10HFPb14M1wO
         AKB9S0T8gJYPmue9/YwYY519C+r1J/xQX/D++H3dBnYPMT9lwR3Sl+sq+jHbqdtxjTw4
         UTe277MpsE1EQUJX9kb8haBa9ZP81uEI5LVVjJFZ3M8kdyl4bTkV2kuCt/flVHRWDkUX
         0enJI6IcVeOgGxHlznDFaGjKWn/7N0BOrpn/Cifms5nrSFaLr9P6gQY+aXZaPuaBXYz+
         ub4g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=FMquJtIr;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id a13-20020a05620a102d00b00789d43b16b3si1100845qkk.6.2024.03.20.02.29.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 20 Mar 2024 02:29:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-690cffa8a0bso38030906d6.0
        for <kasan-dev@googlegroups.com>; Wed, 20 Mar 2024 02:29:44 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVCQGRNotwkRsQI2UcnL3z8uChEa50KzAAtsB8q7JZ+TaCyp5AfhHPOkSvlBy1h5AlGZdjV0qMKm+HkGnMrSrNM/elub35kGQXkXg==
X-Received: by 2002:ad4:5bef:0:b0:691:641a:7bbb with SMTP id
 k15-20020ad45bef000000b00691641a7bbbmr22395757qvc.28.1710926984060; Wed, 20
 Mar 2024 02:29:44 -0700 (PDT)
MIME-Version: 1.0
References: <20240319163656.2100766-1-glider@google.com> <20240319163656.2100766-3-glider@google.com>
 <f9a8a442-0ff2-4da9-af4d-3d0e2805c4a7@I-love.SAKURA.ne.jp>
In-Reply-To: <f9a8a442-0ff2-4da9-af4d-3d0e2805c4a7@I-love.SAKURA.ne.jp>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 20 Mar 2024 10:29:03 +0100
Message-ID: <CAG_fn=UAsTnuZb+p17X+_LN+wY7Anh3OzjHxMEw9Z-A=sJV0UQ@mail.gmail.com>
Subject: Re: [PATCH v1 3/3] x86: call instrumentation hooks from copy_mc.c
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Linus Torvalds <torvalds@linux-foundation.org>, 
	Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=FMquJtIr;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
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

On Wed, Mar 20, 2024 at 4:54=E2=80=AFAM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2024/03/20 1:36, Alexander Potapenko wrote:
> > @@ -61,10 +62,20 @@ unsigned long copy_mc_enhanced_fast_string(void *ds=
t, const void *src, unsigned
> >   */
> >  unsigned long __must_check copy_mc_to_kernel(void *dst, const void *sr=
c, unsigned len)
> >  {
> > -     if (copy_mc_fragile_enabled)
> > -             return copy_mc_fragile(dst, src, len);
> > -     if (static_cpu_has(X86_FEATURE_ERMS))
> > -             return copy_mc_enhanced_fast_string(dst, src, len);
> > +     unsigned long ret;
> > +
> > +     if (copy_mc_fragile_enabled) {
> > +             instrument_memcpy_before(dst, src, len);
>
> I feel that instrument_memcpy_before() needs to be called *after*
> copy_mc_fragile() etc. , for we can't predict how many bytes will
> copy_mc_fragile() etc. actually copy.

That's why we have both _before() and _after(). We can discuss what
checks need to be done before and after the memcpy call, but calling
instrument_memcpy_before() after copy_mc_fragile() is
counterintuitive.

For KMSAN it is indeed important to only handle `len-ret` bytes that
were actually copied. We want the instrumentation to update the
metadata without triggering an immediate error report, so the update
better be consistent with what the kernel actually did with the
memory.

But for KASAN/KCSAN we can afford more aggressive checks.
First, if we postpone them after the actual memory accesses happen,
the kernel may panic on the invalid access without a decent error
report.
Second, even if in a particular case only `len-ret` bytes were copied,
the caller probably expected both `src` and `dst` to have `len`
addressable bytes.
Checking for the whole length in this case is more likely to detect a
real error than produce a false positive.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DUAsTnuZb%2Bp17X%2B_LN%2BwY7Anh3OzjHxMEw9Z-A%3DsJV0UQ%40m=
ail.gmail.com.
