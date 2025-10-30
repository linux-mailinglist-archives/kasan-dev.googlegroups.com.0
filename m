Return-Path: <kasan-dev+bncBCUY5FXDWACRBPXARLEAMGQEBZGBDNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 362DEC1DE56
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Oct 2025 01:24:32 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id 2adb3069b0e04-5941857e6a5sf66406e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 17:24:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761783871; cv=pass;
        d=google.com; s=arc-20240605;
        b=JQVniZ/7492o3xgCg69TCKtD3ychn/cc4yGtLeSY47Y7B22DFfewn6WvPsCI5gq7DJ
         XY4TFOIHk2pQuXG94OMbcEFHYnIPNDofg51tIR9Bj5Af3t3y7re5x6pgYWcX6mooom29
         pmZpq7T4Ysnae5H2StbL3I0srALo5z5ABs40IqAn58rDQrMg0Ki38d2xjUn2larf51gt
         jLkM2h52tTwZbBKTu+pkWFB9vq033QIVrPNPp+SFMk7Lw9B2tcOKOKhFl8LpaPAVTtV3
         lu83LZCxF1oJoV5ePZkLXY+KkJjXqR0xKkp9dR2HML9VuEvHuDsIBQnbCUMosQZ+tnOl
         w8gQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=i0zhM/LADAP4rhq0I0ie+fBNXoYDyyTWsQr5rear5mg=;
        fh=qulwBw37Cy5AlzRI28LkT3z7LzyxWbUPGMdL9PdQnRk=;
        b=Xw7xJyq7JP2BH0syb1gBnd2juC5XQ84E0A5+upVSh7m75zkCh4ixmxlLDz9ne1FRdN
         rPEF9K1x6Lpc/nAPGWFWVKQD3k0sJwcvr7Qf49A3SnyzHCczyMXHRNcKZVA30270K8r6
         o77HthhqHCfKgrOLrHf7faFylAMpvkf88I9S82MJEu2+mMjpWcR11u1W0u1+ecPd8lNJ
         XAWnM89iww9IJyt+PwQ5XZ+bZejpBy9Eo/zGlOP1cvvYEOBb8DZy5EhwuPWV8SO1QPW0
         zUP+JzW+OLQdoA5NYTrxudz1ESvZXr2uK4jMTdPpdMe+pkaqgCaipsIkyOikjM/+ONmo
         aEmw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EYKoQWno;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761783871; x=1762388671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=i0zhM/LADAP4rhq0I0ie+fBNXoYDyyTWsQr5rear5mg=;
        b=gtX1ObupaF0sy4Mfh4aYY1AbB+sHXgJE6SmeWGA6HW/rTgGax7fSoW0SUd2uCYzhcI
         hxERRxGIbh8QQ/XpZt4sQ2PHFudqmp9ILZHfZx8aFxkUfztbe3269UFfp8bRqpcSkBFb
         eg8qe0YSJdgAcIzNQ9lSpLgiPZv28//RYTLknwAsmHP1UK008Vh/hl+FxM6Cwwm+85SS
         UWAhuh0KzR8f3ZgWF6/SDPm/h73ahJngA52twhXJxDQiXTHuFsEGmYI47tkgSzlJX1jJ
         2fpNx48GbWaSQkby4seWHNrdOZbbBcb6RrNbR/eQl0fIZUUlUObVL7NP2ibK2F43bLyD
         JDPQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1761783871; x=1762388671; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=i0zhM/LADAP4rhq0I0ie+fBNXoYDyyTWsQr5rear5mg=;
        b=VlNQ9VFMvAhaszuw0my1e7kAjUFUTi0+kNVRc71VgMLR+LN3n/t4bJPlWKyUoi3s/5
         wRhOLOsyqujzbf1GOycuRxVox1sU6oBd9BrR1djDuGg+0gfRuGHBFF2smAs0qTj4u44i
         ZRPHvOSCcWxKwGziA5DhY0Iejqa5HHAJdXbVeSGpr+6VvGrl5h/II2DuDT5oop1kGrX5
         7PKiXD9S5edriR8t2Vbt4UcA6q2OgFNqeJccwog45VM92ArlZ7SMXBRZE/vvkG60XZMT
         hW7muU9V5wK9t1DQ12h5xtEJkctqGgSGKGDzLBi3smdgppoW/o2hLwy23gkel+6ggWHU
         +KZA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761783871; x=1762388671;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=i0zhM/LADAP4rhq0I0ie+fBNXoYDyyTWsQr5rear5mg=;
        b=biPFqBse/QlTib6wBFEjQPmdshNDZxVrR8lNwc1qgTKKYnilBTEB8BBDABavbJpPgw
         UmcKOK7wTmrj9vZ89i5cGLKwp/zGrOLpzpFsLbO0U9PDCYAi0zKkNjbYR8ncZJcnFE6u
         yGQWqylSZoDcasb5EmoaEZB3In5iMRMSsj57GPDMJemF59k/oYcgenhiKKs0aeU8iq1j
         ghThGtNFYC5gc9PDiY6qM+ozmfkz535X3ADxA/5qHnsBwGRz3FYyKR0brMFF+CyOqJD/
         YnYP7zwTVyDLTJTF/gCMTPlKEBQiwlweNOARMVjTLEtvTImLG+JX81FfFT6kFwgBIorL
         wR7Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXU8OB00Uk46IVAoAO+ZDjAY6vVxvyo1EZ8qtZBpTRfwVfyQ8hf+x06Ppj6om8YWYPYf/bqfA==@lfdr.de
X-Gm-Message-State: AOJu0YwzmiozmFIXEZ9crWUlXx/RU262iZeOJIaB3V+Pbm7V4vR0psDk
	8QolA49MZwEzNrwG1fPtlgZKnwgUZXZP9jhHl2D/VEZL/ZxelzShMwCZ
X-Google-Smtp-Source: AGHT+IGBwnOFhVLIbYrbzGQW3Z3kAEdq3RAdn57sROixTVh3pVseAcZWGY5DueQP2taS4jkvjEuclg==
X-Received: by 2002:a05:6512:6186:b0:55f:552c:f731 with SMTP id 2adb3069b0e04-59416d0cb54mr413819e87.7.1761783871266;
        Wed, 29 Oct 2025 17:24:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aXJZILBc3hQZkhKbY1C/sXg23sBrHGbnucF6qPxIL3Wg=="
Received: by 2002:a05:6512:3b0d:b0:592:f31d:6fa2 with SMTP id
 2adb3069b0e04-59415542620ls66106e87.1.-pod-prod-00-eu-canary; Wed, 29 Oct
 2025 17:24:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW/4wAGbbf8TvbuSiJYewyCtvPMgv2XjD/OwEw0qQtaYOq340BGgIAalsJ1qEie1TISQ6VwGcqzN4Q=@googlegroups.com
X-Received: by 2002:a2e:be8f:0:b0:36b:2fab:fa6f with SMTP id 38308e7fff4ca-37a1067f9a0mr4431011fa.3.1761783867376;
        Wed, 29 Oct 2025 17:24:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761783867; cv=none;
        d=google.com; s=arc-20240605;
        b=EGXlqexd7u3GtfNuHZBIyV5eNjDp3REm8b1g03uWoP8LEqmLH9XULDonP1LNCnxGlI
         RwhL3Q0hQ8o6QlmiAzKsrUIJCDZG4avvs7LCUU6rLA50IshZKBAYRKEV7++HGJaqHkmI
         JlhKva4BMPRZtLtQ/iCBKqo9DSv1iBF1wc6nUKKvDerwbj/zPMEtNzmFgA9HTkplms1b
         3JULGoUNs84TUw+uSmJxhSD1CWSCH0PAGp3vIpzQrjOBP+aRk1uvMoKIhFJojWSvsWNg
         oJTPK3nv4fhrtf/IveAerG0kqzRleaaRRM+dB51bvsBT4qvRdjGmA6Gp+DTPqkjlm3E4
         HbQg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=epzPhO8vgI37OQJ5YBJFLRek4SKDfV+z2knwPznfnng=;
        fh=LtA0sVTLyob5g8MN2j5sCOxJCBQTcR3igorc8fUn7V0=;
        b=dVqSZr+YW7hwurQ/jjf2XhtbBx40juebh8NyP1bOhsXEwNj2IlTAMUFAfkQ+8o90gE
         EopBj4E4i/GSvulXsJ8aY1i+RemdE4Ab9grHvy4c2ZDbQWuwyEJ6IEPRPYWPlP58PcB6
         I3wgf9mX47yLeLviso52/v2wp39At57ZmNCnwYvQ/shTkIJXSi4UtPAwjZU0HvpDnooG
         NDY4bRPE7dkquB2ABMiTRPLNG4B8CbsPBFc9bjlqbFL4p/uCrrPoP+EtHSJiS+uY2Dsb
         Dp/4Cwa1JymoOpnBAyzDEdXVMKvxJugXsSmu7xWJbPceTqmFJKTr6RgPaV1mhNY8Wxt2
         zKQQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=EYKoQWno;
       spf=pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42f.google.com (mail-wr1-x42f.google.com. [2a00:1450:4864:20::42f])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-378eee336fcsi2784921fa.1.2025.10.29.17.24.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 29 Oct 2025 17:24:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexei.starovoitov@gmail.com designates 2a00:1450:4864:20::42f as permitted sender) client-ip=2a00:1450:4864:20::42f;
Received: by mail-wr1-x42f.google.com with SMTP id ffacd0b85a97d-429a0d1c31aso262966f8f.1
        for <kasan-dev@googlegroups.com>; Wed, 29 Oct 2025 17:24:27 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWa5urCfjoXRwJseGyimLnumheaxlznd2hcvOUaZPVm9l+PG8lXUbm/C37SwX9bDLGNqZ6ZMx6qbvY=@googlegroups.com
X-Gm-Gg: ASbGncuE0CCDXkQrRQi/wFOL4RFlRwKTM1xbyaOid4kFXksnBQ87R6EWBAhx2PvoVua
	Boyv6pIS62rNz/FR3WVAO8xND4v4uJDNeIdcKS0l7ZDrJQZSISnMAQ5ksmb2mec65btyonR6vBe
	uGUnQyj7ZodzwAKIxDRthwt6WcHMJ8Cwmc/7FPmtl0/aIfT7d+I4U4Ud9MJgWwRL0k7bNEFIqYK
	AognNwbHWHc/OHuMDys7IwxfGr6ZpeY1OUZpNd4nMp7Tv2uZ4jQc87/r+QjS96VHOjMQPFG9xJX
	EoFdypPwvedv27DZHA==
X-Received: by 2002:a05:6000:2584:b0:401:2cbf:ccad with SMTP id
 ffacd0b85a97d-429b4c56bbbmr1308255f8f.17.1761783866576; Wed, 29 Oct 2025
 17:24:26 -0700 (PDT)
MIME-Version: 1.0
References: <20251023-sheaves-for-all-v1-0-6ffa2c9941c0@suse.cz>
 <20251023-sheaves-for-all-v1-12-6ffa2c9941c0@suse.cz> <CAADnVQ+nAA5OeCbjskbrtgYbPR4Mp-MtOfeXoQE5LUgcZOawEQ@mail.gmail.com>
 <a110ffdb-1e87-4a5a-b01b-2e7b0658ae33@suse.cz>
In-Reply-To: <a110ffdb-1e87-4a5a-b01b-2e7b0658ae33@suse.cz>
From: Alexei Starovoitov <alexei.starovoitov@gmail.com>
Date: Wed, 29 Oct 2025 17:24:15 -0700
X-Gm-Features: AWmQ_bm8V8LdP4A-G3QXinsd8ut065vtjAkDQw3A14j7is_ar0KxcjD8kryVmlU
Message-ID: <CAADnVQ+8x2b5qddRxU50xeq69XMY5RNi8ZfvTbERidKwTYrzqA@mail.gmail.com>
Subject: Re: [PATCH RFC 12/19] slab: remove the do_slab_free() fastpath
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Andrew Morton <akpm@linux-foundation.org>, Christoph Lameter <cl@gentwo.org>, 
	David Rientjes <rientjes@google.com>, Roman Gushchin <roman.gushchin@linux.dev>, 
	Harry Yoo <harry.yoo@oracle.com>, Uladzislau Rezki <urezki@gmail.com>, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Suren Baghdasaryan <surenb@google.com>, 
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>, Alexei Starovoitov <ast@kernel.org>, linux-mm <linux-mm@kvack.org>, 
	LKML <linux-kernel@vger.kernel.org>, linux-rt-devel@lists.linux.dev, 
	bpf <bpf@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: alexei.starovoitov@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=EYKoQWno;       spf=pass
 (google.com: domain of alexei.starovoitov@gmail.com designates
 2a00:1450:4864:20::42f as permitted sender) smtp.mailfrom=alexei.starovoitov@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Wed, Oct 29, 2025 at 3:44=E2=80=AFPM Vlastimil Babka <vbabka@suse.cz> wr=
ote:
>
>
> You mean the one that doesn't go the "if (unlikely(slab !=3D c->slab))" w=
ay?
> Well that unlikely() there might be quite misleading. It will be true whe=
n
> free follows shortly after alloc. If not, c->slab can be exhausted and
> replaced with a new one. Or the process is migrated to another cpu before
> freeing. The probability of slab =3D=3D c->slab staying true drops quickl=
y.
>
> So if your tests were doing frees shortly after alloc, you would be indee=
d
> hitting it reliably, but is it representative?
> However sheaves should work reliably as well too with such a pattern, so =
if
> some real code really does that significantly, it will not regress.

I see. The typical usage of bpf map on the tracing side is
to attach two bpf progs to begin/end of something (like function entry/exit=
),
then map_update() on entry that allocates an element, populate
with data, then consume this data in 2nd bpf prog on exit
that deletes the element.
So alloc/free happen in a quick succession on the same cpu.
This is, of course, just one of use cases, but it was the dominant
one during early days.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AADnVQ%2B8x2b5qddRxU50xeq69XMY5RNi8ZfvTbERidKwTYrzqA%40mail.gmail.com.
