Return-Path: <kasan-dev+bncBCT5RTF4TEMBB7E63K4AMGQEO5U4YWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id C1A509A7111
	for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 19:29:35 +0200 (CEST)
Received: by mail-qv1-xf3e.google.com with SMTP id 6a1803df08f44-6cbe77eeeadsf68773266d6.0
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 10:29:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729531774; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qpj8xqOGVWASRcsGhnyfOsfNNkfl+YHHBohOpyUW9WOTLsMTu6MZ6oJcB311aH0HdR
         lCu0ZfVjyLGdKQdxmVuLaxN+zEs9B5PseLO+/4EQEJflSs03OjNHjl89zscg+uOmVgxx
         20U5ohyiSIoqv5pVWUPWi+EPIT++QojXvSi+8Yyx+sDNNkbEI0qdsHi6j6Qc5eU0zrR+
         C21KA3gzdAhb3aCpuDfNy1hRO9jf0PFNDzph1QHJ1tzVJgRwUtE65Xuug9dSLBUWfOMS
         dLpNL+xpH9A5ldmhKVSyjb4rsNgdeuLuE4blbIid3cKI/I64avJeZV0abSXrk8m0IWYS
         ZT2Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=HpzftZ3tdH8b/zz0BiAObYnW0YOpkGRqWWfjKdOs01o=;
        fh=dq2VVQlqe6VlVakk+kpqI56LFxAlyZ1TLXiK6FVUakw=;
        b=MZKPsOSvNRyARxyPmPdX2Yc0ZUaUoowrpmXg67b8mJo5XCCL0YwUW+I+NPZVZbKBDy
         LDPrmGW8vY+oqZRScZvuMMawxwcy9A7KQF2zy/qNlrUIyKI5ad3q6TJlHG7MH/3U8PI/
         WUfIxULM3DpOoHzE9DMcbjt0dTXVyRhOVkDAU45THAkenbGsU89I9mjRS7Em90bnsPfD
         sfjt5WzAWPDOnnnFyP1q6MWRUFykbKO/7lqe7Pk8ylPQAHxn0cOZzvsPDQSkkj3hxYqK
         o+YrOYHavDxzXBDRSt3R2FAwFLM8bMf3ImA4C7TlEileJdwyTlYn5gsmiIPJKGQRrB/6
         PvrQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BLSWL6YD;
       spf=pass (google.com: domain of pinskia@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=pinskia@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729531774; x=1730136574; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=HpzftZ3tdH8b/zz0BiAObYnW0YOpkGRqWWfjKdOs01o=;
        b=A5xOw7YA5HWFi8/Np19KnpQBKk73wdE4d0Gz7SZTJpV8cAApRnGD+uNOAjJGeybmZ5
         gbcpPcL6H+4NbYorAAycDQC6Rc5ZEzv4M6RmmAc3l7SHsC3GJVlzZ19LiZfw+rOZMIG0
         e1DnItclpek8YvTk8usOVdF0hWbF9k0jc7l3AZxgqozcWIcZUrMcyTtR4WQMQ+5JYOFl
         F1JsrDbNkPV1w2OcvgY4A0nx3IhX905InqQMBbIMs8uFovHYO7sY6dBVAfBQ/hOmik/u
         OZ1hnZB+P/4qRVJtgt6YxGX1cqRaiPlv781e9UVSmG83GsqDC4Jy+269qp8vdF6r33FF
         tCOQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729531774; x=1730136574; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HpzftZ3tdH8b/zz0BiAObYnW0YOpkGRqWWfjKdOs01o=;
        b=H+AvwbWLH23xmlRhZdXOj4Ca3uIGcM7rrz1Mj0On4stPgS8uZRSGiKVALvOMLJW9gH
         WFrOh429HMnVR4U88KdmLRyhHVrFlDZrnT0YNcDjYEsj146uTAv36tzyWVCjwjsZfzKV
         Zpdk3e/SsECrvRKpR4LU6y4dqJugtTZ9xBSuj0kCUteMTk4+Uxi/KefS1wTO+e4bohoX
         2rRLj7rdCJbQIH7TgpEBX5gjrP89yRSO/wmjTMY9zEfMTTLPcR5aiD16XbRY3YYQvFNt
         hbfAiaRDrS0ypQeCO11WM1ogd86gzHLqEtLCl36380kGSxENqTnxy+JiBNcX2WWTgVmj
         CNDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729531774; x=1730136574;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=HpzftZ3tdH8b/zz0BiAObYnW0YOpkGRqWWfjKdOs01o=;
        b=vqLj+5eM9lvHgusnUbvSoRpV6jubJdcfcVob6GdOLPgXFkn1dc8BukZ8YbPimQs1Qa
         SlR7+TwYID27Ky1Y8X8ksYS0zqbEGmVOopBnAqK5YIyDUpUs0WkqgqbvP8MzQ9VsTN3U
         UOim+EeUoUrFajQN/yNZIu13HfqPf3uhDYDWO72n3bWWjLszplBu7nM+OjZ8CdEAxtkd
         gEJXzk2OSH6zO3PnhhDDceiluRL41MyH3nhL83tOm1L18OwiBrxPmQEejbbD08uqMqtB
         PgPoIYliyNKJGm+2tAxWgn2dCkHfj+lAoEhFS/RXZ1HrHs84QKOagmPdpo22FJ6Mx4qi
         8+eA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXATrJ2up84sUPXWIsgYr8vzsm8YfIIG24l/wcd4nR7e3CXDsBvwrxS72XSkkeACClnByCCEg==@lfdr.de
X-Gm-Message-State: AOJu0Yy/UEVw46nUX+rklx1jLvPmyo3emLT/n5oTWKdfdPJhm5LK6KMU
	oU4XvjsoIqh6O+M8ud3TMzqFW3WSbRxD7uNGNEUbsrhdIitbVRC/
X-Google-Smtp-Source: AGHT+IEoKdO+2sSdoGDsraNan2b2o4PIcEHIw3QxyaGvws+0TFRkSPWVg7EYBxWMH6fA0KzBmv269w==
X-Received: by 2002:a05:6214:468d:b0:6cb:e3ea:f07e with SMTP id 6a1803df08f44-6cde155eae3mr238742786d6.26.1729531772884;
        Mon, 21 Oct 2024 10:29:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:2628:b0:6cb:be88:c825 with SMTP id
 6a1803df08f44-6cc36d93bb8ls84923346d6.0.-pod-prod-05-us; Mon, 21 Oct 2024
 10:29:32 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDLik/8SH5yMrhkUaqL91y2AR+MRFxeT+ktR0ulVJNDVH33pP79dV1azSDxCnUC2N9p7SlVJUcmXM=@googlegroups.com
X-Received: by 2002:a05:6122:3c42:b0:50c:99da:4f70 with SMTP id 71dfb90a1353d-50dda02922bmr8839594e0c.2.1729531772235;
        Mon, 21 Oct 2024 10:29:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729531772; cv=none;
        d=google.com; s=arc-20240605;
        b=hWnlGGcGg664qJYsH6/mJQDrkTtVz7g70hisCSsCY8sJrg9zLFbB2MxpihRCFfzZVr
         Cb1EexvigMbjeIkpU6CmXT327Ki6xAFflGLmfT73XDSJOd9dJVtCBqXrVqnf5N4JFRUR
         0bPT4NLLt++oQfsx7nBf4klDliEP8jQZAso7VKiMGyzWbLXm9PO94s1hzd6X2widvGZT
         1Y8KWrCX0SMGRg4h5BR2a+tOJFhBAMH6qhR0zlTgwE5MnkXaNhN+Gk+pNlLkIlXA/UXy
         MfzzD1MhuafmoVqm0Q4yF5MtDHCMzkbgXg0V3r7uix7e44sX2NQqj+fA1TY5y8M0a62V
         NVMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=KBMMpOhM7o/sGaQ+IgPO+fXmm5Xj7pn8re9uxcPeOlc=;
        fh=HAMnFBtBsCCobqNO3A3p2OUBaNNcr3avyZnS8o8XWaA=;
        b=kReAbjg0Rq+MAftBujZnLU2dN96B7ASbwpY4bRlTWo9q4XUbeQDT1LRK4ve+8OXKfQ
         rV6xy/hOewZvsK1igBa4eNTA0ZEERne51x6ij2cH3xzwKhIaEimjS1L7ocjNm/SIGZRN
         wmE2miQQHP6FTA3NdTD7hgk3tDsMHwKS8M8gp80mZ8rVLPMFloXUfuSECQp0NAqG0llz
         J5E5PYrwi6LIiuKzThn4UhlMDhvgWPVyIImqfPWXzuSSC5Etm1EohNxAlLlALBndmu8+
         t++ESko2wUx2BPfPFOGPeRegahI8U+CHBg1NzHzr/5AA+A5yqPqUCqNDneyUDgicCkM4
         wLvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=BLSWL6YD;
       spf=pass (google.com: domain of pinskia@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) smtp.mailfrom=pinskia@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52f.google.com (mail-pg1-x52f.google.com. [2607:f8b0:4864:20::52f])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-50e19fc3975si155542e0c.4.2024.10.21.10.29.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 10:29:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of pinskia@gmail.com designates 2607:f8b0:4864:20::52f as permitted sender) client-ip=2607:f8b0:4864:20::52f;
Received: by mail-pg1-x52f.google.com with SMTP id 41be03b00d2f7-656d8b346d2so3076502a12.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 10:29:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWXE1kyOI6sjgidjbI9d6c8lTchFeUXUEst9ukIx7Gk2+fPZ9XKm97hhWq/hnNxqFqRmD7lRHpVrNc=@googlegroups.com
X-Received: by 2002:a05:6a21:118e:b0:1d2:f124:a1cb with SMTP id
 adf61e73a8af0-1d92c4a5373mr17184971637.9.1729531771096; Mon, 21 Oct 2024
 10:29:31 -0700 (PDT)
MIME-Version: 1.0
References: <20241021120013.3209481-1-elver@google.com> <20241021172058.GB26179@willie-the-truck>
In-Reply-To: <20241021172058.GB26179@willie-the-truck>
From: Andrew Pinski <pinskia@gmail.com>
Date: Mon, 21 Oct 2024 10:29:18 -0700
Message-ID: <CA+=Sn1m7KYkJHL3gis6+7M2-o9fuuzDtyUmycKnHK9KKEr2LtA@mail.gmail.com>
Subject: Re: [PATCH 1/2] kasan: Fix Software Tag-Based KASAN with GCC
To: Will Deacon <will@kernel.org>
Cc: Marco Elver <elver@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Mark Rutland <mark.rutland@arm.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, llvm@lists.linux.dev, 
	syzbot+908886656a02769af987@syzkaller.appspotmail.com, 
	"Andrew Pinski (QUIC)" <quic_apinski@quicinc.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pinskia@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=BLSWL6YD;       spf=pass
 (google.com: domain of pinskia@gmail.com designates 2607:f8b0:4864:20::52f as
 permitted sender) smtp.mailfrom=pinskia@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Mon, Oct 21, 2024 at 10:21=E2=80=AFAM Will Deacon <will@kernel.org> wrot=
e:
>
> On Mon, Oct 21, 2024 at 02:00:10PM +0200, Marco Elver wrote:
> > Per [1], -fsanitize=3Dkernel-hwaddress with GCC currently does not disa=
ble
> > instrumentation in functions with __attribute__((no_sanitize_address)).
> >
> > However, __attribute__((no_sanitize("hwaddress"))) does correctly
> > disable instrumentation. Use it instead.
> >
> > Link: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=3D117196 [1]
> > Link: https://lore.kernel.org/r/000000000000f362e80620e27859@google.com
> > Link: https://lore.kernel.org/r/ZvFGwKfoC4yVjN_X@J2N7QTR9R3
> > Link: https://bugzilla.kernel.org/show_bug.cgi?id=3D218854
> > Reported-by: syzbot+908886656a02769af987@syzkaller.appspotmail.com
> > Tested-by: Andrey Konovalov <andreyknvl@gmail.com>
> > Cc: Andrew Pinski <pinskia@gmail.com>
> > Cc: Mark Rutland <mark.rutland@arm.com>
> > Cc: Will Deacon <will@kernel.org>
> > Signed-off-by: Marco Elver <elver@google.com>
> > ---
> >  include/linux/compiler-gcc.h | 4 ++++
> >  1 file changed, 4 insertions(+)
> >
> > diff --git a/include/linux/compiler-gcc.h b/include/linux/compiler-gcc.=
h
> > index f805adaa316e..cd6f9aae311f 100644
> > --- a/include/linux/compiler-gcc.h
> > +++ b/include/linux/compiler-gcc.h
> > @@ -80,7 +80,11 @@
> >  #define __noscs __attribute__((__no_sanitize__("shadow-call-stack")))
> >  #endif
> >
> > +#ifdef __SANITIZE_HWADDRESS__
> > +#define __no_sanitize_address __attribute__((__no_sanitize__("hwaddres=
s")))
> > +#else
> >  #define __no_sanitize_address __attribute__((__no_sanitize_address__))
> > +#endif
>
> Does this work correctly for all versions of GCC that support
> -fsanitize=3Dkernel-hwaddress?

Yes, tested from GCC 11+, kernel-hwaddress was added in GCC 11.
Also tested from clang 9.0+ and it works there too.

Thanks,
Andrew Pinski

>
> Will

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2B%3DSn1m7KYkJHL3gis6%2B7M2-o9fuuzDtyUmycKnHK9KKEr2LtA%40mail.=
gmail.com.
