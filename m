Return-Path: <kasan-dev+bncBCJYX6FNZ4PBBOOTYLBQMGQEGKMPEAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id AD67FB01349
	for <lists+kasan-dev@lfdr.de>; Fri, 11 Jul 2025 08:05:46 +0200 (CEST)
Received: by mail-wm1-x339.google.com with SMTP id 5b1f17b1804b1-451d3f03b74sf9287225e9.3
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Jul 2025 23:05:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752213946; cv=pass;
        d=google.com; s=arc-20240605;
        b=jZEH2biw3zelT0LaadrPggWPVG0vaar0sN4oLJ4InvNggcIp0FvIlY2v1Su2aE86sc
         LadL+d4PmD/Yb6uKCxcIxZEQ7LihS6CDWkn4TMXnAqLxnXVayO6BChmDGLA7gBeCIwjc
         zh6Gvzi2cJDUZnpuOltEWPZO5UzYWBUw+eTj60Qy1aIKYljcJFYIYZFzNQsSR4ioC02c
         Opv1C2NyfTi7PY4mlCq6AKXwYSV/N5I4yJ9EQuAzBQ68uj/jh2fO8/NE+YU2kyNcK7a5
         /IXIAGr3hDv6s0Ig17zO5d1wp2gU2EpQdHTIV8H9fPBuWm28XCuYlU6VVbNhoe86MFrg
         gCeg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:user-agent:references
         :in-reply-to:date:cc:to:from:subject:message-id:sender
         :dkim-signature:dkim-signature;
        bh=5EVGCE0LY37yrUsT+Hz2yOWwzBaawEvP3HoyzdT6QEg=;
        fh=CX0igdGZZOn24PBEQ3G+BwKRgd4ta+YSEl5DKKerBAI=;
        b=gbEyfjCH6RrFLap8Trd6a30KXH/F9NFKUp+1lZzWpKXBD1av0ZWCf9WfwKt+M1I09b
         dzQRdZBsVC0AhhRBJVZAnjD75wivGF49yz4oUpNrwP3BIuYqhdhe2JT7ku6gWxD0QCK7
         l9cVI2vXqPXlcC1+w7c+tUlJUBcAbU6pfAPyWD/5psfcmOzII2n3IMLQ4S/2K7cWs85j
         s8p7PEgGU/xhN5LXVSUrw2SHc++cwv9dZSbotJL5Xlq7FM5N8J3WAly7wW9e7sWBNnE7
         IDfxzF/gpInIuy6QaYFnuUnM/LnYhOG9Wo8KgYPVmr+RnpZowYQhfLBtT2aCV92IXxSL
         j5tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aPbBAAmK;
       spf=pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752213946; x=1752818746; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5EVGCE0LY37yrUsT+Hz2yOWwzBaawEvP3HoyzdT6QEg=;
        b=WFHDPn378KLgu2ywJsVW9bPPvr3RsWUJQHhk1bLeH33WRRLxWKy0rFbYLwQpNFgRuQ
         /gEEUJmYTu3gWQ5tghEBTWfl1pSIeWXBzd6t1cqn/Lgrpmhd1okq+v0Aj90OEDO/IeNj
         xB55yX9Nu0CHZFg7bBHkCagFZ/vnRejN+SgikXlOdpyhQApYgOyLP67JA9ZZxKY5jIhF
         WA01mh/qTPxYAthsBAqL9g3IjLtk3u/rymS24Pf+fhK9dXS6buu04/QzK+ChyJX25uRZ
         T37HgKhOrN0lVWkpMevNf7051MU6IfdmBABNcTjDWIovR5PXMlBN1ywaKsvJp/p/UE0h
         eOuA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752213946; x=1752818746; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:user-agent:references:in-reply-to
         :date:cc:to:from:subject:message-id:from:to:cc:subject:date
         :message-id:reply-to;
        bh=5EVGCE0LY37yrUsT+Hz2yOWwzBaawEvP3HoyzdT6QEg=;
        b=IDrahtfRH+sOkXHuLx1UfAFBDE4juOhog6rNXvWs2K+72vxvEMmGZkFw4DibnQzWcg
         ICa6KV3tKwcfGlSltcL/wwBJhlfUd0GHyDLhvb/25+wg0QkyMVG1BQa1yremCev5O2rb
         pqYCLGVriJHIygfwYFn7bZtseovx2zUmSuJKQv3fIdIfqwjr/QFqfHeJIqTc1r6BBgg3
         MOQUADr4YH8vAP+4acCs0YbXuLBJgsH/2dn17wHnI6ajqyZsDhrMtfW2nEyvisTL6Fkm
         x/XPy0KpajWydagxDyNMXaAoINtbxOex9GVQ1J+G4rFbQsc5mk4A2zt3BH1LIEI049db
         5Shg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752213946; x=1752818746;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:date:cc:to:from:subject
         :message-id:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=5EVGCE0LY37yrUsT+Hz2yOWwzBaawEvP3HoyzdT6QEg=;
        b=PZyLWhZtYs/QfG3/MGsRy9lcWO813b4toUNPIIIMYuwd+i7XD8C4c8VIKDtM5x96s3
         E/loMbgAj2R5FtX0Dxm8bWBhXHfSoeThgpF9b+Yz4s8h+MlA9zdV9/jg+B5TUX2S1E33
         CvLGw+K1qaPuupWf97JtUADEtz7m2ECgpyQ94zpka7AZ30benGuhK6mpD+grpZObmh0X
         UNkoAbCrZGW3cRQ7/kEInFOyrg+3bsfKMEdb+6f5yO2y790gBz+DgK9sZFWCgdVjDXCx
         9kEx2RWRTv7Xdm/1ZWaT5EQGrNgy/RyQ9l5pDJRP7vFH4pWKN3t84gf0acuL9/T1mAMT
         3reg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXWOLrs7BhOex4hEiNvfcsB9iBpPEX7dyjmTasEBiBsFK46ueAoLve31XEQi2dY1edwE3uR8A==@lfdr.de
X-Gm-Message-State: AOJu0Yw2zqgmgrahJxW6pBzqL+pbbpu8P6xQLxzipJGgVFbU5ae9Dcxh
	mt2826+ctwe23+ubHzEAIBCJNkBgY7kWhHv8ZWhQZU0HnsmIVUyC8/av
X-Google-Smtp-Source: AGHT+IGOO2qJQlC9dWLrJ282U0QcMy/8NYDk1aKs+UXeOSCrswzxBNHNOQhWd5HD9VnrlcgW8fFwGQ==
X-Received: by 2002:a05:600c:8b84:b0:450:cabd:160 with SMTP id 5b1f17b1804b1-454f42722a5mr14888115e9.3.1752213945797;
        Thu, 10 Jul 2025 23:05:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf/3PKTCtt7t5YwmDfOVqGk0E7YdffjrNoCRDiBcU0w6A==
Received: by 2002:a05:600c:35ca:b0:453:5a2:ef4b with SMTP id
 5b1f17b1804b1-454db5f65edls9469925e9.0.-pod-prod-03-eu; Thu, 10 Jul 2025
 23:05:43 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDyTQoVzSXrxPeFf+IFFQJSTSR2QP9tuh20YMT24DCoUNfElZOJfpE2YOS7WRBVGOidZhhDmV0t6M=@googlegroups.com
X-Received: by 2002:a05:600c:8b84:b0:450:cabd:160 with SMTP id 5b1f17b1804b1-454f42722a5mr14886525e9.3.1752213942996;
        Thu, 10 Jul 2025 23:05:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752213942; cv=none;
        d=google.com; s=arc-20240605;
        b=D8xNRIQsQsgveGmzfhnTRxTveErSe3t21S6rfrEXk7zkzuAls3Rb12Oc2KXeoSuz0B
         xb1PSBDI7HXH2Vu0KWvBy6fSh/Mh5fFfEsT9Y0Owm+QpH0qZQb4n7Ad5m+4xXuR98sQ5
         AFDHNjRh5QjgWG3ctgQHbcZ9ju+K5fgb/c9JgTQSorgjx0nQ6jERljp6HYB+P3oZX8aX
         ntf9s2+EBcAduNUo6ZSZglHEi/7XSPwr1irEFBWDK2CAygZrJa652fS8D808rsiCIA3h
         uuBiHasS4HgBN95SxB/xxw10xAcn4tdX+LHxis+sZ4cx8GphyQGdPCZby+d13Jkvs38y
         pUhA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:content-transfer-encoding:references
         :in-reply-to:date:cc:to:from:subject:message-id:dkim-signature;
        bh=E7DKDfxJvck0LHqqh3ys40NEXmDsPAV+8zsSFbCeAIw=;
        fh=6kpNzh4JILx0DOr6WUNOWHUxCjkyHb+rmC2rhT0DZrE=;
        b=fUW/yHXZxF+r5iyktDqx5+G6ANn2v6YPmpzVrP0NvBc1XQzRJCHQj6yafRq3/WfXr7
         PIzVkN30CXNs2u1mu5YyLhibEld8LtTr03M29cYFkmeD8RXcY731+nQsFVq8HyN2RNHj
         ezdtXzMMwNg7RA5CSVNvAp00+OVKMC3w4g5hkyFSE24EylCwgEJBOUMjOrFzs1RIEUro
         gML6He8xvF2vEiXUrSMleR0PNeq8HgVZUeHaILGn1fjMV84Y7ZDBru6AyWtnuVwRQyns
         0sfQnHl22BysQq31r8ST3JEdejpliQQn3d4BcOdJDyJMQufyL5+4u555lAYA1sUGlHAJ
         SXMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=aPbBAAmK;
       spf=pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x430.google.com (mail-wr1-x430.google.com. [2a00:1450:4864:20::430])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3b5e8e020ffsi84273f8f.5.2025.07.10.23.05.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Jul 2025 23:05:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::430 as permitted sender) client-ip=2a00:1450:4864:20::430;
Received: by mail-wr1-x430.google.com with SMTP id ffacd0b85a97d-3a54700a46eso1103936f8f.1
        for <kasan-dev@googlegroups.com>; Thu, 10 Jul 2025 23:05:42 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXYpH1n3JtQf80IOYmeC6gktRwlmF+gCvob6h8DGx2rxQzt5VXi7CBUn9VGjjPaUKZkXjXFdJOjYN8=@googlegroups.com
X-Gm-Gg: ASbGncsFWPqk0zaFhM28oJUN+qJiq5UWNNGmx5Z79RUZWozkfkHPCWvheNqju5zd4zI
	GDwNkbcgamOMbKupCQT4qYrUNz6XoMkeIwY/v5RioBthxFO1o3GKx171U8l+kG18a6vwUJMW62/
	HFhMqFRqxN8zV/1v2Dewml1C+4eQwZI0UHaFMKxAlRa9aHDLNdchu13jkEC0972x7lgx3SInZmZ
	N/uXSun8UKG+GXga9t8LJNRVbfrtXmFPhoFezwvvu1QqJ9sl0K1zn+4Buy/4q0Iyffb6DHe8HBY
	EkfWkR/VrN98Dl7e9GV65lt8IgMfVF0QhpYAXo0tJCDvbZKMuD9dmQU5Cs/uhd7/WT2cAQADtmm
	G8Z09K3tlWh0kvyl4gWFCo/4Mi+1n30sGvjXTGmjU+H1zLbhtbjBJtm7cCzKemSKCkmCWTEScXk
	dbPmLK90MrPtAyFVjlhjJ6jpgPT2pFYqsvfpEJ0yKsrP4d8IuAhpTsEdxkcfLkQYCiPs5j+H2g+
	BHmuLWkxAx7IhrctsFF+/wILckJHxk=
X-Received: by 2002:a05:6000:42c4:b0:3a3:7ba5:93a5 with SMTP id ffacd0b85a97d-3b5f188e76amr1361043f8f.26.1752213941380;
        Thu, 10 Jul 2025 23:05:41 -0700 (PDT)
Received: from 2a02-8388-e6bb-e300-2ae5-f1e1-5796-cbba.cable.dynamic.v6.surfer.at (2a02-8388-e6bb-e300-2ae5-f1e1-5796-cbba.cable.dynamic.v6.surfer.at. [2a02:8388:e6bb:e300:2ae5:f1e1:5796:cbba])
        by smtp.gmail.com with ESMTPSA id ffacd0b85a97d-3b5e8dc21e7sm3597085f8f.36.2025.07.10.23.05.39
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 10 Jul 2025 23:05:40 -0700 (PDT)
Message-ID: <28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel@gmail.com>
Subject: Re: [RFC v5 6/7] sprintf: Add [v]sprintf_array()
From: Martin Uecker <ma.uecker@gmail.com>
To: Linus Torvalds <torvalds@linux-foundation.org>, Alejandro Colomar
	 <alx@kernel.org>
Cc: linux-mm@kvack.org, linux-hardening@vger.kernel.org, Kees Cook
 <kees@kernel.org>, Christopher Bazley <chris.bazley.wg14@gmail.com>, shadow
 <~hallyn/shadow@lists.sr.ht>, linux-kernel@vger.kernel.org, Andrew Morton
 <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, Dmitry Vyukov
 <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver
 <elver@google.com>, Christoph Lameter <cl@linux.com>, David Rientjes
 <rientjes@google.com>, Vlastimil Babka <vbabka@suse.cz>, Roman Gushchin
 <roman.gushchin@linux.dev>, Harry Yoo <harry.yoo@oracle.com>, Andrew
 Clayton <andrew@digital-domain.net>, Rasmus Villemoes
 <linux@rasmusvillemoes.dk>,  Michal Hocko <mhocko@suse.com>, Al Viro
 <viro@zeniv.linux.org.uk>, Sam James <sam@gentoo.org>, Andrew Pinski
 <pinskia@gmail.com>
Date: Fri, 11 Jul 2025 08:05:38 +0200
In-Reply-To: <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
References: <cover.1751823326.git.alx@kernel.org>
	 <cover.1752182685.git.alx@kernel.org>
	 <04c1e026a67f1609167e834471d0f2fe977d9cb0.1752182685.git.alx@kernel.org>
	 <CAHk-=wiNJQ6dVU8t7oM0sFpSqxyK8JZQXV5NGx7h+AE0PY4kag@mail.gmail.com>
Content-Type: text/plain; charset="UTF-8"
User-Agent: Evolution 3.46.4-2
MIME-Version: 1.0
X-Original-Sender: ma.uecker@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=aPbBAAmK;       spf=pass
 (google.com: domain of ma.uecker@gmail.com designates 2a00:1450:4864:20::430
 as permitted sender) smtp.mailfrom=ma.uecker@gmail.com;       dmarc=pass
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

Am Donnerstag, dem 10.07.2025 um 14:58 -0700 schrieb Linus Torvalds:
> On Thu, 10 Jul 2025 at 14:31, Alejandro Colomar <alx@kernel.org> wrote:
> > 
> > These macros are essentially the same as the 2-argument version of
> > strscpy(), but with a formatted string, and returning a pointer to the
> > terminating '\0' (or NULL, on error).
> 
> No.
> 
> Stop this garbage.
> 
> You took my suggestion, and then you messed it up.
> 
> Your version of sprintf_array() is broken. It evaluates 'a' twice.
> Because unlike ARRAY_SIZE(), your broken ENDOF() macro evaluates the
> argument.
> 
> And you did it for no reason I can see. You said that you wanted to
> return the end of the resulting string, but the fact is, not a single
> user seems to care, and honestly, I think it would be wrong to care.
> The size of the result is likely the more useful thing, or you could
> even make these 'void' or something.
> 
> But instead you made the macro be dangerous to use.
> 
> This kind of churn is WRONG. It _looks_ like a cleanup that doesn't
> change anything, but then it has subtle bugs that will come and bite
> us later because you did things wrong.
> 
> I'm NAK'ing all of this. This is BAD. Cleanup patches had better be
> fundamentally correct, not introduce broken "helpers" that will make
> for really subtle bugs.
> 
> Maybe nobody ever ends up having that first argument with a side
> effect. MAYBE. It's still very very wrong.
> 
>                 Linus

What I am puzzled about is that - if you revise your string APIs -,
you do not directly go for a safe abstraction that combines length
and pointer and instead keep using these fragile 80s-style string
functions and open-coded pointer and size computations that everybody
gets wrong all the time.

String handling could also look like this:


https://godbolt.org/z/dqGz9b4sM

and be completely bounds safe.

(Note that those function abort() on allocation failure, but this
is an unfinished demo and also not for kernel use. Also I need to
rewrite this using string views.)


Martin



-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/28c8689c7976b4755c0b5c2937326b0a3627ebf6.camel%40gmail.com.
