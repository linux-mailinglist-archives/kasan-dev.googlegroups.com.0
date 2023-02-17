Return-Path: <kasan-dev+bncBDW2JDUY5AORBBM2XWPQMGQEO7TXZCA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A28969A88C
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 10:46:47 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id g200-20020a6252d1000000b0059395f5a701sf157714pfb.13
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Feb 2023 01:46:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676627206; cv=pass;
        d=google.com; s=arc-20160816;
        b=jv+w1vlfS5mwcLdKCn0Q8n309c1pAnkrx4ypAqCrtlv1K5+IKeX/vMP+cdMMVQq4fg
         kIapyg1XP4v2Rzfzpkz4ZK6ySnZNc2EHoMbBUyz+gyfBKwaOtCMcCowzJoHk7b8SV8im
         ixDy1gJNZx9lPE04V0ySYXhyoXXHOjf+8PnP720Y3QAEAf21B4JEeyrC/jaMYdU2d/8G
         q5MjHy6HSCwM64wydHz2id/78ApKitzMNuvpdwEUWdx9H9X53BaWVJMNuEKpQ5Melj8/
         QdTNdFALFSOVGc42mVmTbX+OSQmp8CwA7UenU+RUtgsT5m44rSJGskZrQyyQ2l41lq0P
         q3ZA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=4vizlDPxqJ/cqmegw0B/hL87V6o/uc9ARFdwp6n8Mvw=;
        b=P2XQ5tbjfERiNLCTQODR3FXC9qYSttF8uaTJBKvFxEEkEC/szF0MdX9aBfmvmNTvFw
         Te/hQH0pnM85ni18qVwlJjlIflyhA8mrBuQ2kye/lBF4eAlwjCdXzTjmAbImXpxb0I1C
         xqzXIVzp9zCB7NFHqehF2jtMSvPzMueDxeYMYH4tsYaXv6yJlkH+HKCOf8sanTJUoMKf
         yuXMoapCS7yuO5b/x5IWoZ6wFb9X+fYn4drhIeQ2CeGI68iluqb1GjWxWwoZsRlvkBH/
         cJKkNGV00dRmKaO6dJtlwe9FMKWBNsgW6uS8eDuqeLRM6SebDuywK3wpWo9lYhjvhs30
         ldKQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I16dYVnV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4vizlDPxqJ/cqmegw0B/hL87V6o/uc9ARFdwp6n8Mvw=;
        b=D+uvUlEE0YRSFE1uN+GZYmdg5kBMkOH+RT+ykL0DVkf+dTue4zSMefDowkDwQz8omU
         JLmdQSpTu4uJhvKqXfPg8ktsRbqVJhDTeGpcFnfkL5c22Y4625v0T7eAjsqqOHRVZG4j
         0khqhEI6BIvqp4VMwrZAvo6fh15TpElBT/9ro/kiD+04vBEvshb41zASt2FTBJWZFzNe
         Xx5UHO1t4eY1uLNM9+Kw0X8VZsAFmUmSP8pTjAOx7/b+Q34vRy1DPjrEtZX3cRFgEoPK
         GeejXUbKCQsOOzc2hq0BNaBjwTO9cN4frbUqYOvawNXoeZJjqRDdTEvWhpatM+U+wyif
         K/Iw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:from:to:cc:subject:date:message-id:reply-to;
        bh=4vizlDPxqJ/cqmegw0B/hL87V6o/uc9ARFdwp6n8Mvw=;
        b=dminLyotMeyRPchGvF9maPruP/PptFBwyOlQ3F3E549Qxc0LbXXSedbqvKoJ1muc6n
         X7yBBvQgn3hvbneYTUogIwrI+G0a7z0kMgCnxJw/xKTwGzkK/c5ey2dCfTWgnteXdkrT
         iOeE7FUuqIsVH9rRA+KfadJJB4MsKy5GmAS69Q5DOuMpXGWdAixe1Sp6McXo9HGq5Wm3
         2vW9lfvHzXNYAGrYKChddASPX2qqYbl4XLTrDxUlbI6dGj5AdibrXcSj35egW33ostFL
         1O0BnT6fgy7xUgqqClDG8YQJ8c91/7ukLSObv9mVddjyjk9O7ihCkmMLdWoBVqjxxg9A
         lfRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4vizlDPxqJ/cqmegw0B/hL87V6o/uc9ARFdwp6n8Mvw=;
        b=Ht6Gd0WrkMsjmVn3735YIoC9TYWaT6LQo+sbkkQqT7XpoV0llKkKzXOottCAE14LJ5
         aqj0mKIm+KRUAudqxoA71MPo0HlPFOuQcthIOQ16jqfiOjgFFmQM8iXpcWXKbO++BUsg
         8Im3n9oSRSS7M6dZ7n4azPCv/MZuGphcoAXQBAIcKMwQyZikXMdsl2n6ywqjo+LFlquE
         BkfpgtYjVsXZSkDWKvEHWQ06LsYqLKVSg3mYUIahV23SL77OIOVmoeKhRznY3luk6FHv
         j0gYEi6L8qW6OYoFqjamudHC0eVnr3sXp0Ny0Vcfep8uzhQ0P1diPpQRVEuwmxr+Fquj
         uYjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUC7SYsso1m6S4BSVZhnQpxFheCoVsZ4n35NCKkJf52tMkymq7q
	R3jfHu47/kbm9CaqVKOZXwM=
X-Google-Smtp-Source: AK7set8rKt8i5axS50P7+TZOqkibhG1HE+qVL7TUP4EBtUoAc1akcUHJhPiibo6YMFdy3J3kB2a3iA==
X-Received: by 2002:a17:90b:3d01:b0:233:a5e3:825f with SMTP id pt1-20020a17090b3d0100b00233a5e3825fmr1367396pjb.15.1676627205740;
        Fri, 17 Feb 2023 01:46:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:d54c:b0:199:50f5:6729 with SMTP id
 z12-20020a170902d54c00b0019950f56729ls1962991plf.11.-pod-prod-gmail; Fri, 17
 Feb 2023 01:46:45 -0800 (PST)
X-Received: by 2002:a17:902:e18b:b0:19b:c6a:6bbf with SMTP id y11-20020a170902e18b00b0019b0c6a6bbfmr2645199pla.8.1676627205016;
        Fri, 17 Feb 2023 01:46:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676627205; cv=none;
        d=google.com; s=arc-20160816;
        b=C8xbNqPofYYJ7BN+kDDuLczbPIYeoEWmZVIwEMj/BmxHw/rZDKuMwVsHecrFpJ/7oH
         dMqA99OZoMCLWjA/LwjqUjKOlz4Pnceu6XzEjMmh/zdcWpD/AV8Xw8yqQ8mNq2bFie2S
         edGa68E6VjfwG31iLZZPyCvlz2LhTOEb5mjJaTGfoOJp6RGneDYRtHXsm+yytgMKpcQy
         l+r7bwdHFJ7Az8un+Usp/OZ/NVTx2DyB8mlZ0wAxjR5WVChmKjytSzZ+8ft/Vap/Kog9
         Ujl/ZMXyeaC98vVjkYYkWjGWT+p2hDnlVqanKBjbOty2Sv+YTz755HzRh0MeZiUMcV9W
         DnEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9SH8M+iqgIr8G+65VlZ0io44yWlIQXBEHAm0eyAdZpw=;
        b=WzE1lH7lNRacyeeEjIF+jFFRYGqVftAYdcLi7RQGRXtmvAJsJ0k/4LL0nI69nRN2DL
         ZRgWSj/df9G9364AqOw3jTdw2PxKqfIKOUqzuAXHGm668rrNzI9EnTaNvbBGkUDgm3kp
         2jRXrqvv2FGJHCxZH9qRXZXLf5nYSV/oRJut22C3IcXeTNta33H+1M0ljC7DjXxZPi7+
         ib0lhYrPhwIgalopmTDwY4G18WWUuypGaA1cJ8WxbLJdipa70PlTIZ4JPoxaW8aJwcUa
         GquElnIfk4xmboGOjc3YIWB0lXR++499cUf+rZ7uF5hHyDA18GbF1LlJKLhQWedNWRL8
         Rvuw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=I16dYVnV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id e3-20020a170902e0c300b0019929ea3979si237459pla.8.2023.02.17.01.46.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Feb 2023 01:46:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id jk12so1012588plb.5
        for <kasan-dev@googlegroups.com>; Fri, 17 Feb 2023 01:46:44 -0800 (PST)
X-Received: by 2002:a17:902:d4d2:b0:199:6e3:187a with SMTP id
 o18-20020a170902d4d200b0019906e3187amr263451plg.6.1676627204614; Fri, 17 Feb
 2023 01:46:44 -0800 (PST)
MIME-Version: 1.0
References: <cover.1676063693.git.andreyknvl@google.com> <5836231b7954355e2311fc9b5870f697ea8e1f7d.1676063693.git.andreyknvl@google.com>
 <CAG_fn=VM34NfOhir_3y86=SKxZ=PqbC3DFuFVAmLEYp8Z9Ax3A@mail.gmail.com>
In-Reply-To: <CAG_fn=VM34NfOhir_3y86=SKxZ=PqbC3DFuFVAmLEYp8Z9Ax3A@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 17 Feb 2023 10:46:33 +0100
Message-ID: <CA+fCnZfVy6=ZKKvUWtCzMwstBjPCp7airuG9L1DSWxkKyyAAVQ@mail.gmail.com>
Subject: Re: [PATCH v2 17/18] lib/stackdepot: various comments clean-ups
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=I16dYVnV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::62e
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Feb 13, 2023 at 2:26 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Fri, Feb 10, 2023 at 10:18 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Clean up comments in include/linux/stackdepot.h and lib/stackdepot.c:
> >
> > 1. Rework the initialization comment in stackdepot.h.
> > 2. Rework the header comment in stackdepot.c.
> > 3. Various clean-ups for other comments.
> >
> > Also adjust whitespaces for find_stack and depot_alloc_stack call sites.
> >
> > No functional changes.
> >
> > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Reviewed-by: Alexander Potapenko <glider@google.com>
>
> > - * Instead, stack depot maintains a hashtable of unique stacktraces. Since alloc
> > - * and free stacks repeat a lot, we save about 100x space.
> > - * Stacks are never removed from depot, so we store them contiguously one after
> > - * another in a contiguous memory allocation.
> > + * For example, KASAN needs to save allocation and free stack traces for each
>
> s/free/deallocation, maybe? (Here and below)

Either way looks good to me.

The patches are in mm-stable now though, so lets save this change for
another potential set of clean-ups.

Thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfVy6%3DZKKvUWtCzMwstBjPCp7airuG9L1DSWxkKyyAAVQ%40mail.gmail.com.
