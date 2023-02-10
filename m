Return-Path: <kasan-dev+bncBCVJB37EUYFBBHFUTKPQMGQELODVKNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x538.google.com (mail-ed1-x538.google.com [IPv6:2a00:1450:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 523C869263D
	for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 20:25:17 +0100 (CET)
Received: by mail-ed1-x538.google.com with SMTP id b12-20020a056402278c00b004aad86c5723sf4135079ede.5
        for <lists+kasan-dev@lfdr.de>; Fri, 10 Feb 2023 11:25:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676057117; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ai+/cGTWJk6rQ2aO7zLTVXwblOzJ7MucnEeUTMW+fHej4GArJ2BIhTHxlOCG4X9rVL
         xH7vZkceH3bEE7pMorXRxZ4njGdPXdQGBbEkJuuqt5Zjy2X0pB/A34qvstsVVkxoDGun
         0lQxQYpySKPMmhZn46T50gXZvldpfyNkj9G4TH1TMuQ9WlCcwFHC9K4fNnH0ZmLearVK
         aNz9v0/BN06O+D6NmD6MuWIhCiXxGAzeL0Gd+RyTI/k+h65LG4291O+Vi26HREbm//ho
         p7i6RzaFJjNWAiD/0UIIxK9JQ/OfNEtK1MXXKQcuPu+f8TNNfMuKKRJ+bkPYwmH8M7cQ
         yCBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:dkim-signature;
        bh=gsNkbSGj9bDEAcrxIHKLjqkHXNfiPRpR34e5Kgd6VPM=;
        b=uB8aEickZ7s6gL2UtIcPMPjTeieT2xezrNPBe3b/zce8AOs7hcQxrH35Go0pm9rPtp
         kq6N+x8u+UG8BmAHpkQ1hC4XGS3QNIMrrpmC7FBq3/h/k8Q1rfdB1+dvoJlfkyzsNz3Z
         +gWMie4YYKRkeFUUFXLsDBv/Y9kh7eB+j3/y6AdlY/0YzCO6WyYANMN5SkRKzHZcm2zI
         /aeo+8B26Az7Ws/tKeF4s6jf1vHgETulGhTwksPebp2z0vk8uckBwrvU8LmLeL9ucoz7
         fmcr7S8KGgpPu2C3stTgoEkT7HDv3yOo9qHYW7lWJnMo9+JFya43RHXQEneAKbS73czo
         nKVA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dK77Ndiv;
       spf=pass (google.com: domain of jakub@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=gsNkbSGj9bDEAcrxIHKLjqkHXNfiPRpR34e5Kgd6VPM=;
        b=Le0Xiw63ZSIyq8+LzQBFcek5etCnxW0sxauNj13j1m1y/G+UXmgUkeECX+QA+g8kDE
         6/HT0Fi0r+edyqkfmIUtQt2T4kyE2NdKVW7nWkjvGf5ccnNtW3y9eZ18ZOeeBIl6OUgp
         lBzd1/5u4hFI0ghdb4MUCt9Y0Zb73hm5sdLdXm7iI1EZuNTeTRGg3OK5P4Pk6xHCRgia
         AG8/QlV+aRYIq6ivOGW3sE1WUW3dyeVK+oWMRoMRVLVWgRaDshOCTRVzqJCmznCoF9kJ
         diybDbEkS/lj+8vfPQh85QthMOZG7CwliVjCJaPLoTlpvGnD3VlTRuV36KYSAzmpx5Wc
         sLXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gsNkbSGj9bDEAcrxIHKLjqkHXNfiPRpR34e5Kgd6VPM=;
        b=5P8gM3JufhQbgVnEsdz1rdQyBa4AsSMxXj6Kg1rZnYobSADWf6iwqsjiLIy0MMU/aY
         ytLKzmOnTs6D9TrE0MWjtUwOiQSBFQWRbT4roWDL00q09BZdEABYOK5/h1x9ybRXDsOO
         +eupEmUQbx/cjeAitOm9WnYgLzzWPKKl2GAEyBC7+R7Uroj8z46IH637N84Mb63CtU59
         LUEnkQn02Tqvwcrc/d3R+RSi7avMMoNPE2x82zZ+WyuzCsxjiPkUwwAZsM8n5m4gkeco
         rHElMAneOfgeIN+rlvSr1sno2+07Wrd2Hik/W/bCZCzuNiGH590qgV1p4Fhd55PBVYKZ
         q5ag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUSMnZUF7J+el4Bg55d+mOoF50/Uik1DD7AWi6oEC8FF4uNoPh1
	nnxKoX1zNm/P78fN6MISvAE=
X-Google-Smtp-Source: AK7set84ToEaVp9+PH6FQjc4p3Q0jyp3aacvHbN3RWV/WNKJq0ig6ZpRhyaSWkdOGVi3ySjiuxOWyQ==
X-Received: by 2002:a17:906:4b05:b0:8af:38c9:d52d with SMTP id y5-20020a1709064b0500b008af38c9d52dmr1415781eju.2.1676057116694;
        Fri, 10 Feb 2023 11:25:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:d0cf:b0:887:1b8f:423c with SMTP id
 bq15-20020a170906d0cf00b008871b8f423cls4464608ejb.4.-pod-prod-gmail; Fri, 10
 Feb 2023 11:25:15 -0800 (PST)
X-Received: by 2002:a17:906:4c98:b0:878:4bc1:dd19 with SMTP id q24-20020a1709064c9800b008784bc1dd19mr18545863eju.52.1676057115261;
        Fri, 10 Feb 2023 11:25:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676057115; cv=none;
        d=google.com; s=arc-20160816;
        b=J8E9UJCuaB7hioZcoBZBP/r5dPg3dgjkxty9Al/pFJMSf+Vv5g7qFBTE56tIBg0zCo
         nIkTLpJDdmsMPcENdExRkM7os9V1JHdNmqUZlakbr2YviBWlYcUaruXg9CNZlzqnHToA
         +aZNieECPycCVjv++80z/IgyLhpmcTVcdVqKflNvd69zblI7kck4zbMh4EWAb3HrKEJg
         wO/kAVw+hL14KmIcIxE5TNNWAlwq/jqwh3FCCm0qZltjYXRzUzSiQ1SYgSPpn4Rfjszc
         Q6TRIlhsNGiogjPfsWzwEaWt4Li+shiEwfJBfeuyrKh1519mz4tKNKTzZ819LNGlZK0w
         vqfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=xmO9YKHMKKTJQMjPUu1RtooVQTRNP/W/wxyjD2+hujQ=;
        b=RrY+STho/2Pjdch8M2frv9HlcDNMMy54Wf+mZqWYPZgkKWp9wpoavWGxDTmyaj2fYM
         11+KJbvrPbO/oE8H3P4Qs71VG5qKgth+3uSHw6PUlsWhtVAXVshBWhAYiltc3axCYx1R
         g+oDqHEtUUv1cwIm8BpKGPvsaCv46H0pzyGETsKUh010p6MMU5MYnEuCC9t6w63gdkmN
         7SNg0We8GJBLPSh+/frLrM/naJrAffGDmWU4ojSqjQVfaroy6aWlfJfa3R1YlL9uNbKm
         R1WrpDIc4mdydUvGYOzfp0ag6qWvpeSkvkI7PcYzALGpv4bmumj7d6UVYukwP3sAzjqW
         Vvqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=dK77Ndiv;
       spf=pass (google.com: domain of jakub@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id t21-20020a1709064f1500b0088d43b316aasi253860eju.0.2023.02.10.11.25.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 10 Feb 2023 11:25:15 -0800 (PST)
Received-SPF: pass (google.com: domain of jakub@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mimecast-mx02.redhat.com (mimecast-mx02.redhat.com
 [66.187.233.88]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 us-mta-564-R_x943JFOkGWZaQUcdRCzA-1; Fri, 10 Feb 2023 14:25:10 -0500
X-MC-Unique: R_x943JFOkGWZaQUcdRCzA-1
Received: from smtp.corp.redhat.com (int-mx09.intmail.prod.int.rdu2.redhat.com [10.11.54.9])
	(using TLSv1.2 with cipher AECDH-AES256-SHA (256/256 bits))
	(No client certificate requested)
	by mimecast-mx02.redhat.com (Postfix) with ESMTPS id BDA48971084;
	Fri, 10 Feb 2023 19:25:09 +0000 (UTC)
Received: from tucnak.zalov.cz (unknown [10.39.192.223])
	by smtp.corp.redhat.com (Postfix) with ESMTPS id 34406492C3F;
	Fri, 10 Feb 2023 19:25:08 +0000 (UTC)
Received: from tucnak.zalov.cz (localhost [127.0.0.1])
	by tucnak.zalov.cz (8.17.1/8.17.1) with ESMTPS id 31AJP41Q1777405
	(version=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 bits=256 verify=NOT);
	Fri, 10 Feb 2023 20:25:04 +0100
Received: (from jakub@localhost)
	by tucnak.zalov.cz (8.17.1/8.17.1/Submit) id 31AJP1BB1777404;
	Fri, 10 Feb 2023 20:25:01 +0100
Date: Fri, 10 Feb 2023 20:25:00 +0100
From: Jakub Jelinek <jakub@redhat.com>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
        Masahiro Yamada <masahiroy@kernel.org>,
        Nathan Chancellor <nathan@kernel.org>,
        Nick Desaulniers <ndesaulniers@google.com>,
        Nicolas Schier <nicolas@fjasle.eu>,
        Andrey Ryabinin <ryabinin.a.a@gmail.com>,
        Alexander Potapenko <glider@google.com>,
        Andrey Konovalov <andreyknvl@gmail.com>,
        Dmitry Vyukov <dvyukov@google.com>,
        Vincenzo Frascino <vincenzo.frascino@arm.com>,
        linux-kbuild@vger.kernel.org, kasan-dev@googlegroups.com,
        linux-kernel@vger.kernel.org, Ingo Molnar <mingo@kernel.org>,
        Tony Lindgren <tony@atomide.com>, Ulf Hansson <ulf.hansson@linaro.org>,
        linux-toolchains@vger.kernel.org
Subject: Re: [PATCH -tip] kasan: Emit different calls for instrumentable
 memintrinsics
Message-ID: <Y+aaDP32wrsd8GZq@tucnak>
Reply-To: Jakub Jelinek <jakub@redhat.com>
References: <20230208184203.2260394-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20230208184203.2260394-1-elver@google.com>
X-Scanned-By: MIMEDefang 3.1 on 10.11.54.9
X-Original-Sender: jakub@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=dK77Ndiv;
       spf=pass (google.com: domain of jakub@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=jakub@redhat.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=redhat.com
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

On Wed, Feb 08, 2023 at 07:42:03PM +0100, Marco Elver wrote:
> Clang 15 will provide an option to prefix calls to memcpy/memset/memmove
> with __asan_ in instrumented functions: https://reviews.llvm.org/D122724
> 
> GCC does not yet have similar support.

GCC has support to rename memcpy/memset etc. for years, say on
following compiled with
-fsanitize=kernel-address -O2 -mstringop-strategy=libcall
(the last option just to make sure the compiler doesn't prefer to emit
rep mov*/stos* or loop or something similar, of course kernel can keep
whatever it uses) you'll get just __asan_memcpy/__asan_memset calls,
no memcpy/memset, while without -fsanitize=kernel-address you get
normally memcpy/memset.
Or do you need the __asan_* functions only in asan instrumented functions
and normal ones in non-instrumented functions in the same TU?

#ifdef __SANITIZE_ADDRESS__
extern __typeof (__builtin_memcpy) memcpy __asm ("__asan_memcpy");
extern __typeof (__builtin_memset) memset __asm ("__asan_memset");
#endif
struct S { char a[2048]; } a, b;

void
foo (void)
{
  a = b;
  b = (struct S) {};
}

void
bar (void *p, void *q, int s)
{
  memcpy (p, q, s);
}

void
baz (void *p, int c, int s)
{
  memset (p, c, s);
}

void
qux (void *p, void *q, int s)
{
  __builtin_memcpy (p, q, s);
}

void
quux (void *p, int c, int s)
{
  __builtin_memset (p, c, s);
}

	Jakub

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y%2BaaDP32wrsd8GZq%40tucnak.
