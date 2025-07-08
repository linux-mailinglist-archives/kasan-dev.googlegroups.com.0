Return-Path: <kasan-dev+bncBD7I3CGX5IPRBM74WLBQMGQE647XQRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 2FFCCAFC303
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Jul 2025 08:44:05 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-4532ff43376sf31531635e9.3
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Jul 2025 23:44:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1751957044; cv=pass;
        d=google.com; s=arc-20240605;
        b=GdFOrcJWOMGEhpNs4k6reHQTkWaAdNcEnJgjUANOW4G1eXuLHc+/X/j5Em8h9wrTNq
         INdYPNhwIN2y6g+KV5++/7yL0kepu1CNpKW9ILZ1otqFh33QNzw72dmU9owQDgEJJ2q8
         2TpIBwVdzRqLItjWMSkxh6NuMR4k7GDR3YeCc2hGAEEID+3REGHGqJCu0wXAB4EriH8F
         dEYNmUiblLLHU1Yfz42q35DvH5UqSpzAY6hwlsg1h3uBilJcwkN4+84xWEz61+G3dV+K
         +asnmJ6+IWY0c4/e7ldSKW064pqwURPmw3KclvB5d15qJTtFq4kzFLXipiJ3SDsIqYY6
         6GfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender
         :dkim-signature;
        bh=hyzkDCFdAUBsIZQOIE+a4kRRY1D9RGfihLN8UeWW7o0=;
        fh=nxqlPs3RPJzeSTHx2k5O0Ac6/Q/vTk1i9GaEoSymd9w=;
        b=H2/iASD4ZA11kCw6p5KhaKEO3pv+v6Rym8+/EAvgqc9OIRRn/vu6i52cIEmIlXsl/x
         m5zPy4kkrGaZJbJ18rqoUgF8MSS+pC9OfYhDyqvc2rACvoF0L8K+g//FhnNeGZ8pmxzj
         CGqN1/0K9wFK8oDcdW7dhbVgbqJGnmJEm7ozZNy+PjXRaboqahsB4fcomaa+zNGvmdus
         gIWLbi9yDXw5eO0PxcdyvsyMYehaBr6tljBZGwMa2jmr29DVkTYyAkea8UwTkKcrtTR0
         cvB3lKzrqJljhcOP2XSw77Yw7FLidjM8I3zVlABaRMFMd48JiPy0pLMU/7oX750iyQBr
         haDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=NoLwhtDD;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1751957044; x=1752561844; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=hyzkDCFdAUBsIZQOIE+a4kRRY1D9RGfihLN8UeWW7o0=;
        b=A3RBung8BSLz7yURP1n/u/QPoRRRcBNiRDiCQADGz/+JJHQW53chs3iqtGtDePgQQt
         YauyLGJ9Ips3Un95ndXd4OJHZGUtzBi7n+EfWroEG5gIjNJc6albcv0xSMnzLjVknWOx
         PL3KLBCzbGVAvX0rOzZNLSnxSBiuR3IQujp+slwnEQYUWUgU8uO12K3xNRlLZwvqrDQN
         5gCestA7H9XlQbvfj9epWmLooHVMjCiwz1EMdNHDidJnn0+K5KwJWu3l48ALzxLXgDVM
         WK5+DfR/C96VehhyeGOGW7FYZzlNQ8b7hm9yjT0BHgob1jmggVBeSayNpGgG4dv0Rc3v
         XzLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1751957044; x=1752561844;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:message-id:date:references:in-reply-to:subject:cc:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=hyzkDCFdAUBsIZQOIE+a4kRRY1D9RGfihLN8UeWW7o0=;
        b=l65CneFmh52ZycQCR5Gsos8o/ojSPOrWJ1OrBwlhM0KRmrpFltBmnWnC50JG56FPEv
         Nqkb1OfE5XAOL0uXry/pc+kTYWLUWh9mJpGR8d7i36LGRjZWdaHvUOWRoF/OiQ+UJA8g
         pDNEGS8RMwgaqKrcngUn4pjI7uY4GWWo+5jUf3LauIgxEynyJREb4aST+gfchHNfTqPn
         LB0mH9IcDZODubslVtrFM8AmGPj/XM9ik84TMvvFXiIENvtHrviRwErEl+kDiXOzF78U
         VN6uYQFYPWBrRs5906hv+bRV5iuVXvJuyxsa7JWxnXvPedIgK/npUcv0Td32tEzcuLvt
         1gKA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWefvjX30WvHcb5EHEURsjS2a+JjlfXb5Gq0BrLAx9tqqeKM6ft94uP8t6xjPTghVGDiufQAw==@lfdr.de
X-Gm-Message-State: AOJu0YwJGHOtaR2BB4UpDh77ki2c9cOvPVJWIiIpPw/1rgI/0j0t9Kq5
	ft6WV62fH/5lYgn0SrH4zWseZaJp76GOpTTntbp4XKTwtyhYOPeW3MYG
X-Google-Smtp-Source: AGHT+IEsHtmXEVkC3qQKgTDO6eG8qgpXRm6HEaatAX15udZGH9zKu6HtA/E058PFpaim775OEdYYhA==
X-Received: by 2002:a05:600c:540c:b0:43d:45a:8fbb with SMTP id 5b1f17b1804b1-454b4ead7f5mr114359415e9.22.1751957043993;
        Mon, 07 Jul 2025 23:44:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeJJZipZ6Xq7V9f4eFkIZGdKHmM2tu9sbKCaGlh8nAx/A==
Received: by 2002:a05:600c:5252:b0:43c:eb7b:1403 with SMTP id
 5b1f17b1804b1-454bbea90cdls15309705e9.1.-pod-prod-09-eu; Mon, 07 Jul 2025
 23:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVZwcxdUmKCcUt8TML/x4siaocDRJbOUqH2Nrp5u4gF84D+i3TdRRcshh7l5mth18q9wdd1yJS2Qto=@googlegroups.com
X-Received: by 2002:a05:600c:3b25:b0:43c:ee3f:2c3 with SMTP id 5b1f17b1804b1-454b4e6e3aemr127733405e9.7.1751957041379;
        Mon, 07 Jul 2025 23:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1751957041; cv=none;
        d=google.com; s=arc-20240605;
        b=bpwd7BV+koREX0KSe/U4WcNbrg2aN9b+HO+Q2c7f4GoNkmQuKLtj7E7v4f/2L12lXf
         4hyj8TuWRNAkomdipBjKI4Q9BLdHk9Eq4qf44U1q+WzvojT9XnMACipKGlzxwzHl1IKU
         oi/RYbQ3FgiGdMGhX42qFD3T4NB/qBXyEtOnmDWRh8oHg2XrQ53EtZd2i3DVIJt3omaj
         zdDoWVHRFE9qqBz+6RLV0GVw09t1JVmmd+D/YeAvmh5SUyRpQDg3gSfpYqENEzO5kxQc
         6rhXfZaziNux4wVPRQ3gsZj+PJ8HaWc4YRHk3+MP5UQRrqlW7//9TMuacvJxQnxhyKH3
         k/gw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:message-id:date:references:in-reply-to
         :subject:cc:to:from:dkim-signature;
        bh=VwcmJ/ZhvGTQZtfzPShfeClIbetsIVYAmTNQ+zOrI/Q=;
        fh=Ezb2KwQdr6Jb7GLZPlJjeLogfHv50yuZFCWy3wpv2gI=;
        b=M/vFGBaQ8Vda0Q0FVn6xw4soLWWGVMU4DxPD6eoNWkJ8lspYVn/INgLgpCJxvnkunG
         rbWQ4wP+VYqi2tLON3dHHo97RgOKh13ibLS/Y9KcfTntpnbERbv71xEXCI4ZWDyGjPqf
         oigypsZtb3mjVQBYS8Ezt/BVs7pqhAyW4qGq4SkiYFwmS2bUMhnX5wn+H+DmFT02oFR5
         K/KDdsORMBne5Orqwc02VaLiNjMsC35j2OD1vlwMqCSt2S64MvB5iAsj7YfnqLwAngvH
         mY5RlKFqti+Sc/nfJVJxW30HQcxnJsQdfHkZbpa0WcFD6Vbjw+mESDJSUbUYKjafGgpu
         yZnQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@rasmusvillemoes.dk header.s=google header.b=NoLwhtDD;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x12e.google.com (mail-lf1-x12e.google.com. [2a00:1450:4864:20::12e])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-454cd498c64si108925e9.0.2025.07.07.23.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 07 Jul 2025 23:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of linux@rasmusvillemoes.dk designates 2a00:1450:4864:20::12e as permitted sender) client-ip=2a00:1450:4864:20::12e;
Received: by mail-lf1-x12e.google.com with SMTP id 2adb3069b0e04-555024588b1so3902959e87.1
        for <kasan-dev@googlegroups.com>; Mon, 07 Jul 2025 23:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVeo3m126WtyvswI2j8LjyVAJx+ujTpkMDAfsO8pbzgkuDK5ivl0aiHELF6a/pqujMzE5K5fpMEucc=@googlegroups.com
X-Gm-Gg: ASbGncuemIeMqPkBesbgJV74QHQiXpLzKUmy1IHBz2x3ESCOSDpJhH4iLO5OW9EFPLO
	2ek8WNhpXXaeCogl7Rw7oQZ+nG5TGsAe7e+g5fLprh7mXB4xZ0mwAreYApXHEhxx8bgcSrErWeB
	ghTK71P3kpWUsJEVW5IuBx/4ifHbITwPb4vkOD9SpsujSpqxKGCDAHG2574zY2dyUceWu4run7D
	MuPrBORZufQR6mtZLH9RfSU5zFarPNlx4iSPxDIkRGw2LhIgWHpwQklNlhSx8Qz7tR/HkB4wjf3
	86kJyErJRKmxLVYNJeNld6W7pRWoK/MFHqiNC2EcccIlEtzJyXBI1M2hEOBwzfZ8
X-Received: by 2002:a05:6512:230f:b0:553:388a:e794 with SMTP id 2adb3069b0e04-557a19df4f8mr5244040e87.17.1751957040069;
        Mon, 07 Jul 2025 23:44:00 -0700 (PDT)
Received: from localhost ([81.216.59.226])
        by smtp.gmail.com with UTF8SMTPSA id 38308e7fff4ca-32e1af83038sm14820851fa.14.2025.07.07.23.43.59
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 07 Jul 2025 23:43:59 -0700 (PDT)
From: Rasmus Villemoes <linux@rasmusvillemoes.dk>
To: Alejandro Colomar <alx@kernel.org>
Cc: linux-mm@kvack.org,  linux-hardening@vger.kernel.org,  Kees Cook
 <kees@kernel.org>,  Christopher Bazley <chris.bazley.wg14@gmail.com>,
  shadow <~hallyn/shadow@lists.sr.ht>,  linux-kernel@vger.kernel.org,
  Andrew Morton <akpm@linux-foundation.org>,  kasan-dev@googlegroups.com,
  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko
 <glider@google.com>,  Marco Elver <elver@google.com>,  Christoph Lameter
 <cl@linux.com>,  David Rientjes <rientjes@google.com>,  Vlastimil Babka
 <vbabka@suse.cz>,  Roman Gushchin <roman.gushchin@linux.dev>,  Harry Yoo
 <harry.yoo@oracle.com>
Subject: Re: [RFC v1 0/3] Add and use seprintf() instead of less ergonomic APIs
In-Reply-To: <cover.1751747518.git.alx@kernel.org> (Alejandro Colomar's
	message of "Sat, 5 Jul 2025 22:33:47 +0200")
References: <cover.1751747518.git.alx@kernel.org>
Date: Tue, 08 Jul 2025 08:43:57 +0200
Message-ID: <87a55fw5aq.fsf@prevas.dk>
User-Agent: Gnus/5.13 (Gnus v5.13)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: linux@rasmusvillemoes.dk
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@rasmusvillemoes.dk header.s=google header.b=NoLwhtDD;
       spf=pass (google.com: domain of linux@rasmusvillemoes.dk designates
 2a00:1450:4864:20::12e as permitted sender) smtp.mailfrom=linux@rasmusvillemoes.dk;
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

On Sat, Jul 05 2025, Alejandro Colomar <alx@kernel.org> wrote:

> On top of that, I have a question about the functions I'm adding,
> and the existing kernel snprintf(3): The standard snprintf(3)
> can fail (return -1), but the kernel one doesn't seem to return <0 ever.
> Should I assume that snprintf(3) doesn't fail here?

Yes. Just because the standard says it may return an error, as a QoI
thing the kernel's implementation never fails. That also means that we
do not ever do memory allocation or similar in the guts of vsnsprintf
(that would anyway be a mine field of locking bugs).

If we hit some invalid or unsupported format specifier (i.e. a bug in
the caller), we return early, but still report what we wrote until
hitting that.

Rasmus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/87a55fw5aq.fsf%40prevas.dk.
